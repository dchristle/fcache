//! Persistent, locally validated compiler identity records.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use fs4::FileExt;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::fingerprint::{
    CompilerFingerprint, FingerprintContext, FingerprintError, FingerprintObservation,
    ResolutionObservation, encoded, observe_gfortran, path_bytes, path_from_bytes,
};

const IDENTITY_SCHEMA: u32 = 2;
const MAX_RECORD_SIZE: u64 = 8 * 1024 * 1024;
const MAX_WITNESS_NODES: usize = 256;

/// Controls whether persistent compiler identity observations may be reused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IdentityMode {
    /// Reuse an identity only when local filesystem witnesses remain authoritative.
    #[default]
    Auto,
    /// Execute the complete compiler fingerprint operation every time.
    Strict,
}

/// Persistent compiler identity storage rooted in an fcache cache directory.
#[derive(Clone, Debug)]
pub struct CompilerIdentityCache {
    root: PathBuf,
    read_only: bool,
}

impl CompilerIdentityCache {
    pub fn new(cache_root: impl Into<PathBuf>, read_only: bool) -> Self {
        Self { root: cache_root.into().join("v1/compiler-identities"), read_only }
    }

    /// Return a validated identity, falling back to a complete fingerprint on any cache doubt.
    pub fn lookup(
        &self,
        context: &FingerprintContext,
        mode: IdentityMode,
    ) -> Result<ValidatedCompilerIdentity, FingerprintError> {
        let key = context_key(context);
        if mode == IdentityMode::Auto {
            if let Some(identity) = self.try_load(&key) {
                return Ok(identity);
            }
        }
        if self.read_only {
            return self.full_fingerprint(context, false);
        }

        if self.prepare_directories().is_err() {
            return self.full_fingerprint(context, false);
        }
        let lock = match IdentityLock::acquire(&self.lock_path(&key)) {
            Ok(lock) => lock,
            Err(_) => return self.full_fingerprint(context, false),
        };
        if mode == IdentityMode::Auto {
            if let Some(identity) = self.try_load(&key) {
                return Ok(identity);
            }
        }
        let identity = self.full_fingerprint(context, true)?;
        drop(lock);
        Ok(identity)
    }

    fn full_fingerprint(
        &self,
        context: &FingerprintContext,
        publish: bool,
    ) -> Result<ValidatedCompilerIdentity, FingerprintError> {
        let observation = observe_gfortran(context)?;
        let key = context_key(context);
        let record = IdentityRecord::from_observation(key.clone(), observation)?;
        let identity = ValidatedCompilerIdentity {
            fingerprint: record.fingerprint(),
            record: record.clone(),
            reused: false,
        };
        if publish {
            let _ = self.publish(&key, &record);
        }
        Ok(identity)
    }

    fn try_load(&self, key: &str) -> Option<ValidatedCompilerIdentity> {
        let path = self.record_path(key);
        let metadata = fs::symlink_metadata(&path).ok()?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_SIZE {
            return None;
        }
        let file = File::open(path).ok()?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_RECORD_SIZE + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > MAX_RECORD_SIZE {
            return None;
        }
        let record: IdentityRecord = serde_json::from_slice(&bytes).ok()?;
        if record.schema != IDENTITY_SCHEMA || record.context_key != key || !record.is_bounded() {
            return None;
        }
        if record.validate(true).is_err() {
            return None;
        }
        Some(ValidatedCompilerIdentity { fingerprint: record.fingerprint(), record, reused: true })
    }

    fn publish(&self, key: &str, record: &IdentityRecord) -> io::Result<()> {
        let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_RECORD_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "identity record is too large"));
        }
        let records = self.root.join("records");
        create_real_directory(&records)?;
        let destination = self.record_path(key);
        if fs::symlink_metadata(&destination)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "identity record is a symlink"));
        }
        let mut temporary = NamedTempFile::new_in(&records)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&destination).map_err(|error| error.error)?;
        File::open(records)?.sync_all()
    }

    fn prepare_directories(&self) -> io::Result<()> {
        create_real_directory(&self.root)?;
        create_real_directory(&self.root.join("records"))?;
        create_real_directory(&self.root.join("locks"))
    }

    fn record_path(&self, key: &str) -> PathBuf {
        self.root.join("records").join(format!("{key}.json"))
    }

    fn lock_path(&self, key: &str) -> PathBuf {
        self.root.join("locks").join(format!("{key}.lock"))
    }
}

/// A compiler identity whose tool resolution and filesystem witnesses were validated.
#[derive(Clone, Debug)]
pub struct ValidatedCompilerIdentity {
    fingerprint: CompilerFingerprint,
    record: IdentityRecord,
    reused: bool,
}

impl ValidatedCompilerIdentity {
    pub fn fingerprint(&self) -> &CompilerFingerprint {
        &self.fingerprint
    }

    pub fn into_fingerprint(self) -> CompilerFingerprint {
        self.fingerprint
    }

    pub fn was_reused(&self) -> bool {
        self.reused
    }

    /// Digest of the exact driver, working-directory, and environment lookup context.
    pub fn context_digest(&self) -> [u8; 32] {
        *blake3::hash(self.record.context_key.as_bytes()).as_bytes()
    }

    /// Revalidate immediately before committing outputs to close the toolchain TOCTOU window.
    pub fn revalidate(&self) -> Result<(), FingerprintError> {
        self.record.validate(self.reused).map_err(FingerprintError::InvalidRecord)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IdentityRecord {
    schema: u32,
    checksum: [u8; 32],
    context_key: String,
    digest: [u8; 32],
    major_version: u32,
    driver: Vec<u8>,
    f951: Vec<u8>,
    assembler: Vec<u8>,
    driver_resolution: ResolutionObservation,
    f951_resolution: ResolutionObservation,
    assembler_resolution: ResolutionObservation,
    specs_path: Option<Vec<u8>>,
    specs_absent: Vec<Vec<u8>>,
    specs_resolution_complete: bool,
    query_outputs: super::fingerprint::QueryOutputs,
    tools: Vec<ToolWitness>,
}

impl IdentityRecord {
    fn from_observation(
        context_key: String,
        observation: FingerprintObservation,
    ) -> Result<Self, FingerprintError> {
        let mut tools = Vec::with_capacity(observation.tool_content_digests.len());
        for (path, digest) in &observation.tool_content_digests {
            tools.push(ToolWitness::capture(&path_from_bytes(path), *digest)?);
        }
        let mut record = Self {
            schema: IDENTITY_SCHEMA,
            checksum: [0; 32],
            context_key,
            digest: observation.fingerprint.digest,
            major_version: observation.fingerprint.major_version,
            driver: path_bytes(&observation.fingerprint.driver),
            f951: path_bytes(&observation.fingerprint.f951),
            assembler: path_bytes(&observation.fingerprint.assembler),
            driver_resolution: observation.driver_resolution,
            f951_resolution: observation.f951_resolution,
            assembler_resolution: observation.assembler_resolution,
            specs_path: observation.specs_path,
            specs_absent: observation.specs_absent,
            specs_resolution_complete: observation.specs_resolution_complete,
            query_outputs: observation.query_outputs,
            tools,
        };
        record.checksum = record
            .computed_checksum()
            .map_err(|error| FingerprintError::InvalidRecord(error.to_string()))?;
        Ok(record)
    }

    fn fingerprint(&self) -> CompilerFingerprint {
        CompilerFingerprint {
            digest: self.digest,
            driver: path_from_bytes(&self.driver),
            f951: path_from_bytes(&self.f951),
            assembler: path_from_bytes(&self.assembler),
            major_version: self.major_version,
        }
    }

    fn validate(&self, require_trustworthy_filesystem: bool) -> Result<(), String> {
        if self.schema != IDENTITY_SCHEMA || !self.is_bounded() {
            return Err("unsupported or unbounded compiler identity record".into());
        }
        if self.computed_checksum().map_err(|error| error.to_string())? != self.checksum {
            return Err("compiler identity record checksum does not match".into());
        }
        validate_resolution(&self.driver_resolution)?;
        validate_resolution(&self.f951_resolution)?;
        validate_resolution(&self.assembler_resolution)?;
        let paths = self.tools.iter().map(|tool| path_from_bytes(&tool.path)).collect::<Vec<_>>();
        let trustworthy = filesystems_are_trustworthy(&paths);
        if require_trustworthy_filesystem && !trustworthy {
            return Err("compiler tool is not on a trustworthy local filesystem".into());
        }
        for tool in &self.tools {
            tool.validate(!trustworthy)?;
        }
        let witnessed = self.tools.iter().map(|tool| tool.path.as_slice()).collect::<BTreeSet<_>>();
        for required in [&self.driver, &self.f951, &self.assembler] {
            if !witnessed.contains(required.as_slice()) {
                return Err("compiler identity is missing a tool witness".into());
            }
        }
        if let Some(specs) = &self.specs_path {
            if !witnessed.contains(specs.as_slice()) {
                return Err("compiler identity is missing its external specs witness".into());
            }
        }
        if require_trustworthy_filesystem && !self.specs_resolution_complete {
            return Err("external specs resolution cannot be witnessed completely".into());
        }
        for candidate in &self.specs_absent {
            match path_from_bytes(candidate).try_exists() {
                Ok(false) => {}
                Ok(true) => return Err("an earlier external specs candidate appeared".into()),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    fn is_bounded(&self) -> bool {
        self.tools.len() <= 4
            && self.tools.iter().all(|tool| tool.nodes.len() <= MAX_WITNESS_NODES)
            && self.driver_resolution.earlier_absent.len() <= MAX_WITNESS_NODES
            && self.f951_resolution.earlier_absent.len() <= MAX_WITNESS_NODES
            && self.assembler_resolution.earlier_absent.len() <= MAX_WITNESS_NODES
            && self.specs_absent.len() <= MAX_WITNESS_NODES
    }

    fn computed_checksum(&self) -> Result<[u8; 32], serde_json::Error> {
        let mut canonical = self.clone();
        canonical.checksum = [0; 32];
        Ok(*blake3::hash(&serde_json::to_vec(&canonical)?).as_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ToolWitness {
    path: Vec<u8>,
    canonical_path: Vec<u8>,
    metadata: MetadataWitness,
    nodes: Vec<PathNodeWitness>,
    content_digest: [u8; 32],
}

impl ToolWitness {
    fn capture(path: &Path, content_digest: [u8; 32]) -> Result<Self, FingerprintError> {
        let canonical = fs::canonicalize(path)
            .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
        let before = fs::metadata(path)
            .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
        if !before.is_file() {
            return Err(FingerprintError::InvalidRecord(
                "compiler tool is not a regular file".into(),
            ));
        }
        let nodes = capture_path_nodes(path).map_err(FingerprintError::CacheIo)?;
        let observed_digest = digest_file(path)
            .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
        let after = fs::metadata(path)
            .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
        if MetadataWitness::capture(&before) != MetadataWitness::capture(&after)
            || observed_digest != content_digest
        {
            return Err(FingerprintError::InvalidRecord(
                "compiler tool changed while its identity was captured".into(),
            ));
        }
        Ok(Self {
            path: path_bytes(path),
            canonical_path: path_bytes(&canonical),
            metadata: MetadataWitness::capture(&after),
            nodes,
            content_digest,
        })
    }

    fn validate(&self, verify_content: bool) -> Result<(), String> {
        let path = path_from_bytes(&self.path);
        let canonical = fs::canonicalize(&path).map_err(|error| error.to_string())?;
        if path_bytes(&canonical) != self.canonical_path {
            return Err("compiler tool canonical path changed".into());
        }
        let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
        if !metadata.is_file() || MetadataWitness::capture(&metadata) != self.metadata {
            return Err("compiler tool metadata changed".into());
        }
        validate_path_nodes(&self.nodes)?;
        if verify_content
            && digest_file(&path).map_err(|error| error.to_string())? != self.content_digest
        {
            return Err("compiler tool contents changed".into());
        }
        Ok(())
    }
}

fn digest_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let expected = file.metadata()?.len();
    let mut hasher = blake3::Hasher::new();
    let mut actual = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        actual = actual.saturating_add(count as u64);
        hasher.update(&buffer[..count]);
    }
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compiler tool changed while hashing",
        ));
    }
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MetadataWitness {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl MetadataWitness {
    #[cfg(unix)]
    fn capture(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    #[cfg(not(unix))]
    fn capture(metadata: &fs::Metadata) -> Self {
        let modified = metadata.modified().ok();
        let duration = modified.and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
        Self {
            device: 0,
            inode: 0,
            mode: 0,
            size: metadata.len(),
            modified_seconds: duration.map_or(0, |value| value.as_secs() as i64),
            modified_nanoseconds: duration.map_or(0, |value| value.subsec_nanos() as i64),
            changed_seconds: 0,
            changed_nanoseconds: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PathNodeWitness {
    path: Vec<u8>,
    metadata: MetadataWitness,
    symlink_target: Option<Vec<u8>>,
}

fn capture_path_nodes(path: &Path) -> io::Result<Vec<PathNodeWitness>> {
    let absolute = if path.is_absolute() { path.to_path_buf() } else { fs::canonicalize(path)? };
    let mut current = PathBuf::new();
    let mut nodes = Vec::new();
    let components = absolute.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                current.push(component.as_os_str());
            }
        }
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.file_type().is_symlink() && index + 1 != components.len() {
            continue;
        }
        let symlink_target = if metadata.file_type().is_symlink() {
            Some(path_bytes(&fs::read_link(&current)?))
        } else {
            None
        };
        nodes.push(PathNodeWitness {
            path: path_bytes(&current),
            metadata: MetadataWitness::capture(&metadata),
            symlink_target,
        });
        if nodes.len() > MAX_WITNESS_NODES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tool path is too deep"));
        }
    }
    Ok(nodes)
}

fn validate_path_nodes(nodes: &[PathNodeWitness]) -> Result<(), String> {
    if nodes.is_empty() || nodes.len() > MAX_WITNESS_NODES {
        return Err("invalid compiler path witness".into());
    }
    for node in nodes {
        let path = path_from_bytes(&node.path);
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if MetadataWitness::capture(&metadata) != node.metadata {
            return Err("compiler path component changed".into());
        }
        let target = if metadata.file_type().is_symlink() {
            Some(path_bytes(&fs::read_link(path).map_err(|error| error.to_string())?))
        } else {
            None
        };
        if target != node.symlink_target {
            return Err("compiler path symlink changed".into());
        }
    }
    Ok(())
}

fn validate_resolution(resolution: &ResolutionObservation) -> Result<(), String> {
    if resolution.earlier_absent.len() > MAX_WITNESS_NODES {
        return Err("compiler resolution witness is too large".into());
    }
    for path in &resolution.earlier_absent {
        match path_from_bytes(path).try_exists() {
            Ok(false) => {}
            Ok(true) => return Err("an earlier compiler tool candidate appeared".into()),
            Err(error) => return Err(error.to_string()),
        }
    }
    let selected = path_from_bytes(&resolution.selected);
    if !selected.is_file() {
        return Err("selected compiler tool disappeared".into());
    }
    Ok(())
}

fn context_key(context: &FingerprintContext) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_key_field(&mut hasher, b"fcache-compiler-identity-context-v1");
    hash_key_field(&mut hasher, &encoded(&context.driver));
    hash_key_field(&mut hasher, &path_bytes(&context.cwd));
    hasher.update(&(context.environment.len() as u64).to_le_bytes());
    for (name, value) in &context.environment {
        hash_key_field(&mut hasher, &encoded(name));
        hash_key_field(&mut hasher, &encoded(value));
    }
    hasher.finalize().to_hex().to_string()
}

fn hash_key_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn create_real_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity cache path is not a directory",
        ));
    }
    Ok(())
}

struct IdentityLock {
    _file: File,
}

impl IdentityLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "identity lock is a symlink"));
        }
        let file =
            OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path)?;
        FileExt::lock(&file)?;
        Ok(Self { _file: file })
    }
}

#[cfg(target_os = "linux")]
fn filesystems_are_trustworthy(paths: &[PathBuf]) -> bool {
    use std::os::unix::fs::MetadataExt;

    let devices = paths
        .iter()
        .map(|path| fs::metadata(path).map(|metadata| metadata.dev()))
        .collect::<Result<BTreeSet<_>, _>>();
    let Ok(devices) = devices else { return false };
    let Ok(mountinfo) = fs::read("/proc/self/mountinfo") else {
        return false;
    };
    let mut trusted = BTreeSet::new();
    for line in mountinfo.split(|byte| *byte == b'\n') {
        let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            continue;
        };
        if separator < 6 || separator + 1 >= fields.len() {
            continue;
        }
        let filesystem = fields[separator + 1];
        if !matches!(filesystem, b"ext4" | b"xfs" | b"btrfs" | b"apfs") {
            continue;
        }
        let mountpoint = path_from_bytes(&decode_mount_path(fields[4]));
        if let Ok(metadata) = fs::metadata(mountpoint) {
            trusted.insert(metadata.dev());
        }
    }
    !devices.is_empty() && devices.is_subset(&trusted)
}

#[cfg(target_os = "linux")]
fn decode_mount_path(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'\\' && index + 3 < value.len() {
            let octal = &value[index + 1..index + 4];
            if octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
                index += 4;
                continue;
            }
        }
        decoded.push(value[index]);
        index += 1;
    }
    decoded
}

#[cfg(target_os = "macos")]
fn filesystems_are_trustworthy(paths: &[PathBuf]) -> bool {
    const MNT_LOCAL: u64 = 0x0000_1000;

    !paths.is_empty()
        && paths.iter().all(|path| {
            let Ok(stat) = rustix::fs::statfs(path) else {
                return false;
            };
            let filesystem = stat
                .f_fstypename
                .iter()
                .take_while(|byte| **byte != 0)
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>();
            filesystem == b"apfs" && (stat.f_flags as u64 & MNT_LOCAL) != 0
        })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn filesystems_are_trustworthy(_paths: &[PathBuf]) -> bool {
    false
}

#[cfg(test)]
fn filesystem_is_trustworthy(path: &Path) -> bool {
    filesystems_are_trustworthy(&[path.to_path_buf()])
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    struct FakeToolchain {
        directory: tempfile::TempDir,
        driver: PathBuf,
        count: PathBuf,
    }

    impl FakeToolchain {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let driver = directory.path().join("gfortran");
            let f951 = directory.path().join("f951");
            let assembler = directory.path().join("as");
            let count = directory.path().join("count");
            fs::write(&f951, b"f951 tool").unwrap();
            fs::write(&assembler, b"assembler tool").unwrap();
            let script = format!(
                "#!/bin/sh\nprintf x >> '{}'\ncase \"$1\" in\n  -print-search-dirs) printf 'programs: ={}\\n' ;;\n  -print-prog-name=f951) printf '{}\\n' ;;\n  -print-prog-name=as) printf '{}\\n' ;;\n  --version) printf 'GNU Fortran 16.1\\n' ;;\n  -dumpfullversion) printf '16.1.0\\n' ;;\n  -dumpmachine) printf 'test-target\\n' ;;\n  -print-file-name=specs) printf 'specs\\n' ;;\n  -dumpspecs) printf '*test specs\\n' ;;\nesac\n",
                count.display(),
                directory.path().display(),
                f951.display(),
                assembler.display(),
            );
            fs::write(&driver, script).unwrap();
            let mut permissions = fs::metadata(&driver).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&driver, permissions).unwrap();
            Self { directory, driver, count }
        }

        fn context(&self) -> FingerprintContext {
            FingerprintContext::new(
                OsString::from("gfortran"),
                self.directory.path(),
                [(OsString::from("PATH"), self.directory.path().as_os_str().to_os_string())],
            )
        }

        fn calls(&self) -> usize {
            fs::read(&self.count).map_or(0, |bytes| bytes.len())
        }
    }

    #[test]
    fn context_key_preserves_environment_order_and_bytes() {
        let first = FingerprintContext::new("gfortran", "/tmp", [("A", "1"), ("B", "2")]);
        let second = FingerprintContext::new("gfortran", "/tmp", [("B", "2"), ("A", "1")]);
        assert_ne!(context_key(&first), context_key(&second));
    }

    #[test]
    fn auto_reuses_a_valid_record_without_compiler_queries_on_supported_filesystems() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        let first = identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        assert!(!first.was_reused());
        let initial_calls = fake.calls();
        assert_eq!(initial_calls, 8);

        let second = identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        if filesystem_is_trustworthy(&fake.driver) {
            assert!(second.was_reused());
            assert_eq!(fake.calls(), initial_calls);
        } else {
            assert!(!second.was_reused());
            assert_eq!(fake.calls(), initial_calls * 2);
        }
    }

    #[test]
    fn strict_always_executes_the_full_fingerprint() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        identities.lookup(&fake.context(), IdentityMode::Strict).unwrap();
        let initial_calls = fake.calls();
        identities.lookup(&fake.context(), IdentityMode::Strict).unwrap();
        assert_eq!(fake.calls(), initial_calls * 2);
    }

    #[test]
    fn changed_tool_metadata_invalidates_auto_reuse() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        let initial_calls = fake.calls();
        fs::write(fake.directory.path().join("f951"), b"changed f951 tool").unwrap();
        let identity = identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        assert!(!identity.was_reused());
        assert_eq!(fake.calls(), initial_calls * 2);
    }

    #[test]
    fn newly_appearing_external_specs_candidate_invalidates_auto_reuse() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        let initial_calls = fake.calls();
        fs::write(fake.directory.path().join("specs"), b"*cc1:\n-fchanged-semantics\n").unwrap();

        let identity = identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        assert!(!identity.was_reused());
        assert_eq!(fake.calls(), initial_calls * 2);
    }

    #[test]
    fn same_size_rewrite_with_restored_mtime_still_invalidates_reuse() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        let f951 = fake.directory.path().join("f951");
        let old_mtime =
            filetime::FileTime::from_last_modification_time(&fs::metadata(&f951).unwrap());
        fs::write(&f951, b"evil tool").unwrap();
        filetime::set_file_mtime(&f951, old_mtime).unwrap();

        let identity = identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        assert!(!identity.was_reused());
    }

    #[test]
    fn newly_appearing_earlier_path_candidate_invalidates_reuse() {
        let fake = FakeToolchain::new();
        let earlier = tempfile::tempdir().unwrap();
        let path = env::join_paths([earlier.path(), fake.directory.path()]).unwrap();
        let context = FingerprintContext::new(
            "gfortran",
            fake.directory.path(),
            [(OsString::from("PATH"), path)],
        );
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        identities.lookup(&context, IdentityMode::Auto).unwrap();
        fs::copy(&fake.driver, earlier.path().join("gfortran")).unwrap();

        let identity = identities.lookup(&context, IdentityMode::Auto).unwrap();
        assert!(!identity.was_reused());
    }

    #[test]
    fn read_only_consumes_records_but_does_not_publish() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let read_only = CompilerIdentityCache::new(cache.path(), true);
        read_only.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        assert!(!cache.path().join("v1/compiler-identities").exists());

        let writable = CompilerIdentityCache::new(cache.path(), false);
        writable.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        let calls = fake.calls();
        let identity = read_only.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        if filesystem_is_trustworthy(&fake.driver) {
            assert!(identity.was_reused());
            assert_eq!(fake.calls(), calls);
        }
    }

    #[test]
    fn corrupt_and_oversized_records_fall_back_to_full_fingerprint() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        let key = context_key(&fake.context());
        fs::write(identities.record_path(&key), b"not json").unwrap();
        identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        let calls_after_corruption = fake.calls();

        let file = File::create(identities.record_path(&key)).unwrap();
        file.set_len(MAX_RECORD_SIZE + 1).unwrap();
        identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        assert_eq!(fake.calls(), calls_after_corruption + 8);
    }

    #[test]
    fn checksum_rejects_a_structurally_valid_modified_record() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        let key = context_key(&fake.context());
        let path = identities.record_path(&key);
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json["major_version"] = serde_json::Value::from(99);
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();

        let identity = identities.lookup(&fake.context(), IdentityMode::Auto).unwrap();
        assert!(!identity.was_reused());
        assert_eq!(identity.fingerprint().major_version, 16);
    }

    #[test]
    fn context_lock_coalesces_concurrent_initial_fingerprints() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identities = CompilerIdentityCache::new(cache.path(), false);
        let context = fake.context();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let identities = identities.clone();
                let context = context.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    identities.lookup(&context, IdentityMode::Auto).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let results = handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>();
        if filesystem_is_trustworthy(&fake.driver) {
            assert_eq!(fake.calls(), 8);
            assert_eq!(results.iter().filter(|identity| identity.was_reused()).count(), 1);
        }
    }

    #[test]
    fn revalidation_detects_tool_mutation() {
        let fake = FakeToolchain::new();
        let cache = tempfile::tempdir().unwrap();
        let identity = CompilerIdentityCache::new(cache.path(), false)
            .lookup(&fake.context(), IdentityMode::Auto)
            .unwrap();
        fs::write(fake.directory.path().join("as"), b"mutated assembler").unwrap();
        assert!(identity.revalidate().is_err());
    }
}
