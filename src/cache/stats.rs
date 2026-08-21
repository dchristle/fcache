//! Concurrent cache statistics.

use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use thiserror::Error;

const SHARDS: u64 = 16;
const JOURNAL_PREFIX: &[u8] = b"FCS1 ";
const CHECKSUM_HEX_BYTES: usize = 64;
const MAX_RECORD_BYTES: usize = 256 * 1024;
const MAX_FRAME_BYTES: usize = JOURNAL_PREFIX.len() + CHECKSUM_HEX_BYTES + 1 + MAX_RECORD_BYTES + 1;
const MAX_LEGACY_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REASON_ENTRIES: usize = 256;
const MAX_REASON_BYTES: usize = 256;
pub const STATS_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LookupResults {
    pub hits: u64,
    pub misses: u64,
    pub not_attempted: u64,
}

impl LookupResults {
    fn merge(&mut self, other: &Self) {
        add(&mut self.hits, other.hits);
        add(&mut self.misses, other.misses);
        add(&mut self.not_attempted, other.not_attempted);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ObservedOutcomes {
    pub cache_hit_success: u64,
    pub compiler_success: u64,
    pub compiler_failure: u64,
    pub launcher_failure: u64,
}

impl ObservedOutcomes {
    fn merge(&mut self, other: &Self) {
        add(&mut self.cache_hit_success, other.cache_hit_success);
        add(&mut self.compiler_success, other.compiler_success);
        add(&mut self.compiler_failure, other.compiler_failure);
        add(&mut self.launcher_failure, other.launcher_failure);
    }
}

/// Compiler subprocesses launched while handling cache requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProcessCounts {
    pub fingerprint_queries: u64,
    pub preprocessing_probes: u64,
    pub dependency_probes: u64,
    pub real_compilations: u64,
    pub pass_through_executions: u64,
}

impl ProcessCounts {
    fn merge(&mut self, other: &Self) {
        add(&mut self.fingerprint_queries, other.fingerprint_queries);
        add(&mut self.preprocessing_probes, other.preprocessing_probes);
        add(&mut self.dependency_probes, other.dependency_probes);
        add(&mut self.real_compilations, other.real_compilations);
        add(&mut self.pass_through_executions, other.pass_through_executions);
    }
}

/// Outcomes from attempting the compiler-free direct path.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DirectPathStats {
    pub candidates_found: u64,
    pub validated_hits: u64,
    pub validated_compile_plans: u64,
    pub stale_records: u64,
    pub corrupt_records: u64,
    pub missing_result_manifests: u64,
    pub validation_fallback_reasons: BTreeMap<String, u64>,
}

/// Miss-observation strategy selections, attempts, and successful validations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MissObservationStats {
    pub validated_precompile_selections: u64,
    pub real_md_validation_successes: u64,
    pub post_compile_probe_attempts: u64,
}

impl MissObservationStats {
    fn merge(&mut self, other: &Self) {
        add(&mut self.validated_precompile_selections, other.validated_precompile_selections);
        add(&mut self.real_md_validation_successes, other.real_md_validation_successes);
        add(&mut self.post_compile_probe_attempts, other.post_compile_probe_attempts);
    }
}

impl DirectPathStats {
    fn merge(&mut self, other: &Self) {
        add(&mut self.candidates_found, other.candidates_found);
        add(&mut self.validated_hits, other.validated_hits);
        add(&mut self.validated_compile_plans, other.validated_compile_plans);
        add(&mut self.stale_records, other.stale_records);
        add(&mut self.corrupt_records, other.corrupt_records);
        add(&mut self.missing_result_manifests, other.missing_result_manifests);
        merge_reasons(&mut self.validation_fallback_reasons, &other.validation_fallback_reasons);
    }
}

/// Cumulative monotonic time spent in launcher phases, in nanoseconds.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PhaseTimingsNs {
    pub parsing: u64,
    pub compiler_identity: u64,
    pub direct_validation: u64,
    pub preprocessing_qualification: u64,
    pub dependency_probing: u64,
    pub cache_lookup_staging: u64,
    pub real_compilation: u64,
    pub post_compile_validation: u64,
    pub publication: u64,
    pub lock_waiting: u64,
    pub maintenance: u64,
}

impl PhaseTimingsNs {
    fn merge(&mut self, other: &Self) {
        add(&mut self.parsing, other.parsing);
        add(&mut self.compiler_identity, other.compiler_identity);
        add(&mut self.direct_validation, other.direct_validation);
        add(&mut self.preprocessing_qualification, other.preprocessing_qualification);
        add(&mut self.dependency_probing, other.dependency_probing);
        add(&mut self.cache_lookup_staging, other.cache_lookup_staging);
        add(&mut self.real_compilation, other.real_compilation);
        add(&mut self.post_compile_validation, other.post_compile_validation);
        add(&mut self.publication, other.publication);
        add(&mut self.lock_waiting, other.lock_waiting);
        add(&mut self.maintenance, other.maintenance);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Stats {
    pub schema_version: u32,
    pub requests: u64,
    pub hits: u64,
    pub misses: u64,
    pub lookup_results: LookupResults,
    pub observed_outcomes: ObservedOutcomes,
    pub process_counts: ProcessCounts,
    pub direct_path: DirectPathStats,
    pub miss_observation: MissObservationStats,
    pub phase_timings_ns: PhaseTimingsNs,
    pub bypass_reasons: BTreeMap<String, u64>,
    pub compiler_failures: u64,
    pub cache_read_failures: u64,
    pub cache_write_failures: u64,
    pub corruption: u64,
    /// Logical payload bytes published in cache bundles, including artifacts and diagnostics.
    ///
    /// This counts payload sizes for every publication, independently of deduplication,
    /// compression, metadata, or physical storage writes.
    pub bytes_stored: u64,
    /// Logical payload bytes delivered from cache bundles, including artifacts and diagnostics.
    ///
    /// This uses the same payload definition as [`Stats::bytes_stored`], independently of
    /// deduplication, compression, metadata, or physical storage reads.
    pub bytes_restored: u64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            schema_version: STATS_SCHEMA_VERSION,
            requests: 0,
            hits: 0,
            misses: 0,
            lookup_results: LookupResults::default(),
            observed_outcomes: ObservedOutcomes::default(),
            process_counts: ProcessCounts::default(),
            direct_path: DirectPathStats::default(),
            miss_observation: MissObservationStats::default(),
            phase_timings_ns: PhaseTimingsNs::default(),
            bypass_reasons: BTreeMap::new(),
            compiler_failures: 0,
            cache_read_failures: 0,
            cache_write_failures: 0,
            corruption: 0,
            bytes_stored: 0,
            bytes_restored: 0,
        }
    }
}

impl Stats {
    pub fn merge(&mut self, other: &Self) {
        self.schema_version = STATS_SCHEMA_VERSION;
        add(&mut self.requests, other.requests);
        add(&mut self.hits, other.hits);
        add(&mut self.misses, other.misses);
        self.lookup_results.merge(&other.lookup_results);
        self.observed_outcomes.merge(&other.observed_outcomes);
        self.process_counts.merge(&other.process_counts);
        self.direct_path.merge(&other.direct_path);
        self.miss_observation.merge(&other.miss_observation);
        self.phase_timings_ns.merge(&other.phase_timings_ns);
        add(&mut self.compiler_failures, other.compiler_failures);
        add(&mut self.cache_read_failures, other.cache_read_failures);
        add(&mut self.cache_write_failures, other.cache_write_failures);
        add(&mut self.corruption, other.corruption);
        add(&mut self.bytes_stored, other.bytes_stored);
        add(&mut self.bytes_restored, other.bytes_restored);
        merge_reasons(&mut self.bypass_reasons, &other.bypass_reasons);
    }
}

fn add(value: &mut u64, increment: u64) {
    *value = value.saturating_add(increment);
}

fn merge_reasons(output: &mut BTreeMap<String, u64>, input: &BTreeMap<String, u64>) {
    for (reason, count) in input {
        let value = output.entry(reason.clone()).or_default();
        add(value, *count);
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "stats", rename_all = "snake_case")]
enum JournalEntry {
    Delta(Stats),
    Snapshot(Stats),
}

#[derive(Debug, Error)]
pub enum StatsError {
    #[error("stats I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("stats JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported stats schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid stats path: {0}")]
    InvalidPath(PathBuf),
    #[error("stats record exceeds its size limit")]
    RecordTooLarge,
    #[error("stats journal is corrupt: {0}")]
    CorruptJournal(PathBuf),
    #[error("stats reason map exceeds its bounds")]
    InvalidReasons,
}

#[derive(Debug, Clone)]
pub struct StatsStore {
    root: PathBuf,
}

impl StatsStore {
    pub fn new(cache_dir: impl AsRef<Path>) -> Result<Self, StatsError> {
        let cache_dir = cache_dir.as_ref();
        create_real_directory(cache_dir)?;
        let version = cache_dir.join("v1");
        create_real_directory(&version)?;
        let root = version.join("stats");
        create_real_directory(&root)?;
        Ok(Self { root })
    }

    fn shard_number(&self, key: Option<&str>) -> u64 {
        key.map(|key| {
            let hash = blake3::hash(key.as_bytes());
            u64::from_le_bytes(hash.as_bytes()[..8].try_into().expect("eight hash bytes")) % SHARDS
        })
        .unwrap_or_else(|| u64::from(std::process::id()) % SHARDS)
    }

    fn legacy_path(&self, shard: u64) -> PathBuf {
        self.root.join(format!("{shard:02}.json"))
    }

    fn journal_path(&self, shard: u64) -> PathBuf {
        self.root.join(format!("{shard:02}.journal"))
    }

    fn lock_path(&self, shard: u64) -> PathBuf {
        self.root.join(format!("{shard:02}.lock"))
    }

    /// Append one additive statistics delta.
    ///
    /// The update is applied to an empty delta, not to the current aggregate. Callers should
    /// only add counters and reason entries.
    pub fn record(
        &self,
        key: Option<&str>,
        update: impl FnOnce(&mut Stats),
    ) -> Result<(), StatsError> {
        let mut delta = Stats::default();
        update(&mut delta);
        self.record_delta(key, &delta)
    }

    /// Append a pre-aggregated additive delta without reading existing statistics.
    pub fn record_delta(&self, key: Option<&str>, delta: &Stats) -> Result<(), StatsError> {
        validate_stats(delta)?;
        let entry = JournalEntry::Delta(delta.clone());
        let frame = encode_entry(&entry)?;
        let shard = self.shard_number(key);
        let lock = self.lock_shard(shard, false)?;
        append_frame(&self.journal_path(shard), &frame)?;
        FileExt::unlock(&lock)?;
        Ok(())
    }

    pub fn aggregate(&self) -> Result<Stats, StatsError> {
        let mut output = Stats::default();
        for shard in 0..SHARDS {
            let lock = self.lock_shard(shard, true)?;
            output.merge(&self.read_shard(shard)?);
            FileExt::unlock(&lock)?;
        }
        Ok(output)
    }

    /// Replace every shard with an empty snapshot.
    pub fn reset(&self) -> Result<(), StatsError> {
        for shard in 0..SHARDS {
            let lock = self.lock_shard(shard, false)?;
            replace_journal(&self.root, &self.journal_path(shard), &Stats::default())?;
            FileExt::unlock(&lock)?;
        }
        Ok(())
    }

    /// Compact every journal to one checksummed snapshot.
    pub fn compact(&self) -> Result<(), StatsError> {
        for shard in 0..SHARDS {
            let lock = self.lock_shard(shard, false)?;
            let stats = self.read_shard(shard)?;
            replace_journal(&self.root, &self.journal_path(shard), &stats)?;
            FileExt::unlock(&lock)?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    fn lock_shard(&self, shard: u64, shared: bool) -> Result<File, StatsError> {
        require_real_directory(&self.root)?;
        let lock = open_regular(&self.lock_path(shard), true, false)?;
        if shared {
            FileExt::lock_shared(&lock)?;
        } else {
            FileExt::lock(&lock)?;
        }
        Ok(lock)
    }

    fn read_shard(&self, shard: u64) -> Result<Stats, StatsError> {
        let mut stats = read_legacy(&self.legacy_path(shard))?;
        let path = self.journal_path(shard);
        let Some(file) = open_existing_regular(&path)? else {
            return Ok(stats);
        };
        read_journal(file, &path, &mut stats)?;
        Ok(stats)
    }
}

fn create_real_directory(path: &Path) -> Result<(), StatsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => return Ok(()),
        Ok(_) => return Err(StatsError::InvalidPath(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    require_real_directory(path)
}

fn require_real_directory(path: &Path) -> Result<(), StatsError> {
    if fs::symlink_metadata(path)?.file_type().is_dir() {
        Ok(())
    } else {
        Err(StatsError::InvalidPath(path.to_path_buf()))
    }
}

fn open_regular(path: &Path, create: bool, append: bool) -> Result<File, StatsError> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
        return Err(StatsError::InvalidPath(path.to_path_buf()));
    }
    let file = OpenOptions::new()
        .create(create)
        .read(true)
        .write(true)
        .append(append)
        .truncate(false)
        .open(path)?;
    let path_metadata = fs::symlink_metadata(path)?;
    let file_metadata = file.metadata()?;
    if !path_metadata.file_type().is_file()
        || !file_metadata.is_file()
        || !same_regular_file(&path_metadata, &file_metadata)
    {
        return Err(StatsError::InvalidPath(path.to_path_buf()));
    }
    Ok(file)
}

#[cfg(unix)]
fn same_regular_file(path_metadata: &fs::Metadata, file_metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    path_metadata.dev() == file_metadata.dev()
        && path_metadata.ino() == file_metadata.ino()
        && path_metadata.nlink() == 1
}

#[cfg(not(unix))]
fn same_regular_file(_path_metadata: &fs::Metadata, _file_metadata: &fs::Metadata) -> bool {
    true
}

fn open_existing_regular(path: &Path) -> Result<Option<File>, StatsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            open_regular(path, false, false).map(Some)
        }
        Ok(_) => Err(StatsError::InvalidPath(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_legacy(path: &Path) -> Result<Stats, StatsError> {
    let Some(mut file) = open_existing_regular(path)? else {
        return Ok(Stats::default());
    };
    if file.metadata()?.len() > MAX_LEGACY_BYTES {
        return Err(StatsError::RecordTooLarge);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Stats::default());
    }
    let stats: Stats = serde_json::from_slice(&bytes)?;
    validate_stats(&stats)?;
    Ok(stats)
}

fn validate_stats(stats: &Stats) -> Result<(), StatsError> {
    if stats.schema_version != 0
        && stats.schema_version != 1
        && stats.schema_version != 2
        && stats.schema_version != STATS_SCHEMA_VERSION
    {
        return Err(StatsError::UnsupportedSchema(stats.schema_version));
    }
    validate_reasons(&stats.bypass_reasons)?;
    validate_reasons(&stats.direct_path.validation_fallback_reasons)
}

fn validate_reasons(reasons: &BTreeMap<String, u64>) -> Result<(), StatsError> {
    if reasons.len() > MAX_REASON_ENTRIES
        || reasons.keys().any(|reason| reason.len() > MAX_REASON_BYTES)
    {
        return Err(StatsError::InvalidReasons);
    }
    Ok(())
}

fn encode_entry(entry: &JournalEntry) -> Result<Vec<u8>, StatsError> {
    let payload = serde_json::to_vec(entry)?;
    if payload.len() > MAX_RECORD_BYTES {
        return Err(StatsError::RecordTooLarge);
    }
    let checksum = blake3::hash(&payload).to_hex();
    let mut frame = Vec::with_capacity(JOURNAL_PREFIX.len() + checksum.len() + payload.len() + 2);
    frame.extend_from_slice(JOURNAL_PREFIX);
    frame.extend_from_slice(checksum.as_bytes());
    frame.push(b' ');
    frame.extend_from_slice(&payload);
    frame.push(b'\n');
    Ok(frame)
}

fn append_frame(path: &Path, frame: &[u8]) -> Result<(), StatsError> {
    let mut file = open_regular(path, true, true)?;
    repair_truncated_tail(&mut file)?;
    if file.metadata()?.len().saturating_add(frame.len() as u64) > MAX_JOURNAL_BYTES {
        return Err(StatsError::RecordTooLarge);
    }
    file.write_all(frame)?;
    Ok(())
}

fn repair_truncated_tail(file: &mut File) -> Result<(), StatsError> {
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    let inspected = length.min(MAX_FRAME_BYTES as u64);
    file.seek(SeekFrom::Start(length - inspected))?;
    let mut tail = vec![0; inspected as usize];
    file.read_exact(&mut tail)?;
    let valid_length = tail
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|position| length - inspected + position as u64 + 1)
        .unwrap_or(0);
    if valid_length == 0 && length > MAX_FRAME_BYTES as u64 {
        return Err(StatsError::RecordTooLarge);
    }
    file.set_len(valid_length)?;
    Ok(())
}

fn read_journal(file: File, path: &Path, stats: &mut Stats) -> Result<(), StatsError> {
    if file.metadata()?.len() > MAX_JOURNAL_BYTES {
        return Err(StatsError::RecordTooLarge);
    }
    let mut reader = BufReader::new(file);
    loop {
        let Some((line, terminated)) = read_bounded_line(&mut reader)? else {
            return Ok(());
        };
        if !terminated {
            return Ok(());
        }
        let entry =
            decode_entry(&line).map_err(|_| StatsError::CorruptJournal(path.to_path_buf()))?;
        match entry {
            JournalEntry::Delta(delta) => stats.merge(&delta),
            JournalEntry::Snapshot(snapshot) => *stats = snapshot,
        }
    }
}

fn read_bounded_line(reader: &mut impl BufRead) -> Result<Option<(Vec<u8>, bool)>, StatsError> {
    let mut output = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if output.is_empty() { Ok(None) } else { Ok(Some((output, false))) };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        if output.len().saturating_add(consumed) > MAX_FRAME_BYTES {
            return Err(StatsError::RecordTooLarge);
        }
        output.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            output.pop();
            return Ok(Some((output, true)));
        }
    }
}

fn decode_entry(line: &[u8]) -> Result<JournalEntry, ()> {
    let checksum_end = JOURNAL_PREFIX.len() + CHECKSUM_HEX_BYTES;
    if line.len() <= checksum_end + 1
        || !line.starts_with(JOURNAL_PREFIX)
        || line.get(checksum_end) != Some(&b' ')
    {
        return Err(());
    }
    let expected = blake3::hash(&line[checksum_end + 1..]).to_hex();
    if expected.as_bytes() != &line[JOURNAL_PREFIX.len()..checksum_end] {
        return Err(());
    }
    let entry: JournalEntry = serde_json::from_slice(&line[checksum_end + 1..]).map_err(|_| ())?;
    match &entry {
        JournalEntry::Delta(stats) | JournalEntry::Snapshot(stats) => {
            validate_stats(stats).map_err(|_| ())?;
        }
    }
    Ok(entry)
}

fn replace_journal(root: &Path, path: &Path, stats: &Stats) -> Result<(), StatsError> {
    validate_stats(stats)?;
    let frame = encode_entry(&JournalEntry::Snapshot(stats.clone()))?;
    let mut temporary = NamedTempFile::new_in(root)?;
    temporary.write_all(&frame)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| StatsError::Io(error.error))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

pub fn aggregate(cache_dir: impl AsRef<Path>) -> Result<Stats, StatsError> {
    StatsStore::new(cache_dir)?.aggregate()
}

pub fn reset(cache_dir: impl AsRef<Path>) -> Result<(), StatsError> {
    StatsStore::new(cache_dir)?.reset()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn populated_stats() -> Stats {
        let mut stats = Stats {
            requests: 7,
            hits: 2,
            misses: 3,
            lookup_results: LookupResults { hits: 2, misses: 3, not_attempted: 2 },
            observed_outcomes: ObservedOutcomes {
                cache_hit_success: 2,
                compiler_success: 2,
                compiler_failure: 1,
                launcher_failure: 1,
            },
            process_counts: ProcessCounts {
                fingerprint_queries: 6,
                preprocessing_probes: 1,
                dependency_probes: 1,
                real_compilations: 3,
                pass_through_executions: 1,
            },
            direct_path: DirectPathStats {
                candidates_found: 3,
                validated_hits: 2,
                validated_compile_plans: 1,
                stale_records: 1,
                corrupt_records: 0,
                missing_result_manifests: 1,
                validation_fallback_reasons: BTreeMap::from([("input-changed".into(), 1)]),
            },
            miss_observation: MissObservationStats {
                validated_precompile_selections: 1,
                real_md_validation_successes: 2,
                post_compile_probe_attempts: 3,
            },
            phase_timings_ns: PhaseTimingsNs {
                parsing: 1,
                compiler_identity: 2,
                direct_validation: 3,
                preprocessing_qualification: 4,
                dependency_probing: 5,
                cache_lookup_staging: 6,
                real_compilation: 7,
                post_compile_validation: 8,
                publication: 9,
                lock_waiting: 10,
                maintenance: 11,
            },
            compiler_failures: 1,
            cache_read_failures: 2,
            cache_write_failures: 1,
            corruption: 1,
            bytes_stored: 128,
            bytes_restored: 64,
            ..Stats::default()
        };
        stats.bypass_reasons.insert("flag".into(), 2);
        stats
    }

    #[test]
    fn round_trip_reset_and_compact() {
        let directory = tempfile::tempdir().unwrap();
        let store = StatsStore::new(directory.path()).unwrap();
        let expected = populated_stats();

        store.record_delta(Some("x"), &expected).unwrap();
        assert_eq!(store.aggregate().unwrap(), expected);
        store.compact().unwrap();
        assert_eq!(store.aggregate().unwrap(), expected);
        store.reset().unwrap();
        assert_eq!(store.aggregate().unwrap(), Stats::default());
    }

    #[test]
    fn reads_legacy_schema_shards() {
        for schema in [None, Some(1), Some(2)] {
            let directory = tempfile::tempdir().unwrap();
            let store = StatsStore::new(directory.path()).unwrap();
            let shard = store.root.join("00.json");
            let version =
                schema.map_or(String::new(), |value| format!("\"schema_version\":{value},"));
            fs::write(
                shard,
                format!(
                    "{{{version}\"requests\":4,\"hits\":1,\"misses\":2,\"bypass_reasons\":{{\"unsupported-compiler\":1}}}}"
                ),
            )
            .unwrap();

            let stats = store.aggregate().unwrap();
            assert_eq!(stats.schema_version, STATS_SCHEMA_VERSION);
            assert_eq!(stats.requests, 4);
            assert_eq!(stats.hits, 1);
            assert_eq!(stats.misses, 2);
            assert_eq!(stats.process_counts, ProcessCounts::default());
            assert_eq!(stats.direct_path, DirectPathStats::default());
            assert_eq!(stats.phase_timings_ns, PhaseTimingsNs::default());
        }
    }

    #[test]
    fn reads_and_compacts_schema_two_journal_frames() {
        let directory = tempfile::tempdir().unwrap();
        let store = StatsStore::new(directory.path()).unwrap();
        let encode = |payload: &[u8]| {
            let checksum = blake3::hash(payload).to_hex();
            let mut frame = Vec::new();
            frame.extend_from_slice(JOURNAL_PREFIX);
            frame.extend_from_slice(checksum.as_bytes());
            frame.push(b' ');
            frame.extend_from_slice(payload);
            frame.push(b'\n');
            frame
        };
        let snapshot = br#"{"kind":"snapshot","stats":{"schema_version":2,"requests":3,"hits":1}}"#;
        let delta = br#"{"kind":"delta","stats":{"schema_version":2,"requests":1,"misses":2,"direct_path":{"validated_hits":1}}}"#;
        let mut journal = encode(snapshot);
        journal.extend(encode(delta));
        fs::write(store.journal_path(0), journal).unwrap();

        let stats = store.aggregate().unwrap();
        assert_eq!(stats.schema_version, STATS_SCHEMA_VERSION);
        assert_eq!(stats.requests, 4);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.direct_path.validated_hits, 1);
        assert_eq!(stats.miss_observation, MissObservationStats::default());

        store.compact().unwrap();
        assert_eq!(store.aggregate().unwrap(), stats);
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = StatsStore::new(directory.path()).unwrap();
        let shard = store.root.join("00.json");
        let stats = Stats { schema_version: STATS_SCHEMA_VERSION + 1, ..Stats::default() };
        fs::write(shard, serde_json::to_vec(&stats).unwrap()).unwrap();

        assert!(matches!(
            store.aggregate(),
            Err(StatsError::UnsupportedSchema(version)) if version == STATS_SCHEMA_VERSION + 1
        ));
    }

    #[test]
    fn truncated_tail_is_ignored_and_repaired_before_append() {
        let directory = tempfile::tempdir().unwrap();
        let store = StatsStore::new(directory.path()).unwrap();
        store.record(Some("x"), |stats| stats.requests = 1).unwrap();
        let path = store.journal_path(store.shard_number(Some("x")));
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"FCS1 torn").unwrap();

        assert_eq!(store.aggregate().unwrap().requests, 1);
        store.record(Some("x"), |stats| stats.requests = 2).unwrap();
        assert_eq!(store.aggregate().unwrap().requests, 3);
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let store = StatsStore::new(directory.path()).unwrap();
        store.record(Some("x"), |stats| stats.requests = 1).unwrap();
        let path = store.journal_path(store.shard_number(Some("x")));
        let mut bytes = fs::read(&path).unwrap();
        let payload = bytes.iter().position(|byte| *byte == b'{').unwrap();
        bytes[payload] = b'[';
        fs::write(&path, bytes).unwrap();

        assert!(
            matches!(store.aggregate(), Err(StatsError::CorruptJournal(found)) if found == path)
        );
    }

    #[test]
    fn serializes_reason_maps_in_key_order() {
        let mut stats = Stats::default();
        stats.bypass_reasons.insert("zeta".into(), 1);
        stats.bypass_reasons.insert("alpha".into(), 2);
        stats.direct_path.validation_fallback_reasons.insert("zeta".into(), 1);
        stats.direct_path.validation_fallback_reasons.insert("alpha".into(), 2);

        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.find("alpha").unwrap() < json.find("zeta").unwrap());
    }

    #[test]
    fn concurrent_records_do_not_lose_updates() {
        const THREADS: usize = 8;
        const UPDATES_PER_THREAD: usize = 25;

        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(StatsStore::new(directory.path()).unwrap());
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for _ in 0..UPDATES_PER_THREAD {
                        store
                            .record(Some("shared-key"), |stats| {
                                stats.requests += 1;
                                stats.lookup_results.misses += 1;
                                stats.observed_outcomes.compiler_success += 1;
                                stats.process_counts.real_compilations += 1;
                                stats.phase_timings_ns.real_compilation += 10;
                            })
                            .unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        let stats = store.aggregate().unwrap();
        let expected = (THREADS * UPDATES_PER_THREAD) as u64;
        assert_eq!(stats.requests, expected);
        assert_eq!(stats.lookup_results.misses, expected);
        assert_eq!(stats.observed_outcomes.compiler_success, expected);
        assert_eq!(stats.process_counts.real_compilations, expected);
        assert_eq!(stats.phase_timings_ns.real_compilation, expected * 10);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_stats_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let store = StatsStore::new(directory.path()).unwrap();
        let outside = directory.path().join("outside");
        fs::write(&outside, b"unchanged").unwrap();
        let path = store.journal_path(store.shard_number(Some("x")));
        symlink(&outside, &path).unwrap();

        assert!(matches!(
            store.record(Some("x"), |stats| stats.requests = 1),
            Err(StatsError::InvalidPath(found)) if found == path
        ));
        assert_eq!(fs::read(outside).unwrap(), b"unchanged");
    }
}
