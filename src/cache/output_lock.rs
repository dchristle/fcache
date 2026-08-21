//! Advisory serialization and observation for compiler output paths.

use fs4::FileExt;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Describes how an action will use its final module output directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleDirectoryAccess {
    /// A compiler miss whose probe predicted no generated modules.
    CompilerMissWithoutModules,
    /// A compiler miss whose probe predicted generated modules.
    CompilerModuleProducer,
    /// A cache restoration that installs generated modules.
    ModuleRestore,
}

impl ModuleDirectoryAccess {
    fn lock_mode(self) -> LockMode {
        match self {
            Self::CompilerMissWithoutModules => LockMode::Shared,
            Self::CompilerModuleProducer | Self::ModuleRestore => LockMode::Exclusive,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Debug)]
struct PlannedLock {
    path: PathBuf,
    mode: LockMode,
}

/// Collects every output and module-directory lock required by an action.
#[derive(Debug, Default)]
pub struct OutputLockPlan {
    requested: Vec<PlannedLock>,
}

impl OutputLockPlan {
    /// Create an empty lock plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a compiler output, which always requires exclusive access.
    pub fn add_output(&mut self, path: impl Into<PathBuf>) {
        self.requested.push(PlannedLock { path: path.into(), mode: LockMode::Exclusive });
    }

    /// Add the final module directory with the mode required by the action kind.
    pub fn add_module_directory(
        &mut self,
        path: impl Into<PathBuf>,
        access: ModuleDirectoryAccess,
    ) {
        self.requested.push(PlannedLock { path: path.into(), mode: access.lock_mode() });
    }
}

/// Holds locks for compiler output paths and module directories.
#[derive(Debug)]
pub struct OutputLocks {
    _files: Vec<File>,
}

impl OutputLocks {
    /// Acquire exclusive locks for output paths in deterministic order.
    pub fn acquire(
        cache_root: &Path,
        outputs: impl IntoIterator<Item = PathBuf>,
    ) -> io::Result<Self> {
        let mut plan = OutputLockPlan::new();
        for output in outputs {
            plan.add_output(output);
        }
        Self::acquire_plan(cache_root, plan)
    }

    /// Acquire a unified lock plan in digest order so overlapping actions cannot deadlock.
    pub fn acquire_plan(cache_root: &Path, plan: OutputLockPlan) -> io::Result<Self> {
        let root = cache_root.join("locks").join("outputs");
        create_real_directory(cache_root)?;
        create_real_directory(&cache_root.join("locks"))?;
        create_real_directory(&root)?;

        let mut targets = BTreeMap::<String, LockMode>::new();
        for requested in plan.requested {
            if requested.path.as_os_str().is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty lock target"));
            }
            let normalized = normalize_target(&requested.path);
            let name = blake3::hash(&path_bytes(&normalized)).to_hex().to_string();
            targets
                .entry(name)
                .and_modify(|mode| *mode = (*mode).max(requested.mode))
                .or_insert(requested.mode);
        }

        let mut files = Vec::with_capacity(targets.len());
        for (name, mode) in targets {
            let path = root.join(name);
            reject_symlink(&path)?;
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)?;
            validate_open_lock_file(&path, &file)?;
            match mode {
                LockMode::Shared => FileExt::lock_shared(&file)?,
                LockMode::Exclusive => FileExt::lock(&file)?,
            }
            files.push(file);
        }
        Ok(Self { _files: files })
    }
}

fn create_real_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("output lock path is not a real directory: {}", path.display()),
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("output lock is a symlink: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_open_lock_file(path: &Path, file: &File) -> io::Result<()> {
    let opened = file.metadata()?;
    let destination = fs::symlink_metadata(path)?;
    if !opened.is_file()
        || !destination.is_file()
        || file_identity(&opened) != file_identity(&destination)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("output lock is not a stable regular file: {}", path.display()),
        ));
    }
    Ok(())
}

fn normalize_target(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(parent) = fs::canonicalize(parent) {
            return parent.join(name);
        }
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

/// The filesystem identity of one directory entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

/// The non-following file type observed for a direct directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntryKind {
    RegularFile,
    Directory,
    Symlink,
    Other,
}

/// A byte-preserving observation of one direct directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntrySnapshot {
    pub kind: DirectoryEntryKind,
    pub identity: Option<FileIdentity>,
    pub mode: u32,
    pub size: u64,
    pub modified: FileTimestamp,
    pub changed: FileTimestamp,
    pub digest: Option<[u8; 32]>,
    pub symlink_target: Option<Vec<u8>>,
}

/// A filesystem timestamp with its native nanosecond component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileTimestamp {
    pub seconds: i64,
    pub nanoseconds: i64,
}

/// A complete, byte-preserving observation of a directory's direct entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectorySnapshot {
    directory: PathBuf,
    directory_identity: FileIdentity,
    entries: BTreeMap<Vec<u8>, DirectoryEntrySnapshot>,
}

impl DirectorySnapshot {
    /// Observe every direct entry without following symlinks.
    pub fn read(directory: &Path) -> io::Result<Self> {
        Self::read_for_outputs(directory, &BTreeSet::new())
    }

    /// Observe every direct entry and hash only predicted outputs.
    pub fn read_for_outputs(
        directory: &Path,
        predicted_raw_names: &BTreeSet<Vec<u8>>,
    ) -> io::Result<Self> {
        ensure_snapshot_supported()?;
        if predicted_raw_names.iter().any(|name| !is_direct_name(name)) {
            return Err(invalid_snapshot("predicted output is not a direct filename"));
        }
        let directory_before = fs::symlink_metadata(directory)?;
        if !directory_before.file_type().is_dir() {
            return Err(invalid_snapshot(format!(
                "module output path is not a real directory: {}",
                directory.display()
            )));
        }
        let directory_identity = file_identity(&directory_before).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "directory snapshots require stable filesystem identities",
            )
        })?;
        let canonical_directory = fs::canonicalize(directory)?;
        let directory_witness = stability_witness(&directory_before);
        let mut entries = BTreeMap::new();
        let mut witnesses = BTreeMap::new();

        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = os_bytes(&entry.file_name());
            if name.is_empty() || entries.contains_key(&name) {
                return Err(invalid_snapshot("invalid or duplicate directory entry name"));
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let hash_contents = predicted_raw_names.contains(&name);
            let (snapshot, witness) = snapshot_entry(&path, &metadata, hash_contents)?;
            entries.insert(name.clone(), snapshot);
            witnesses.insert(name, witness);
        }

        let directory_after = fs::symlink_metadata(directory)?;
        if stability_witness(&directory_after) != directory_witness {
            return Err(invalid_snapshot(format!(
                "module output directory changed while observing: {}",
                directory.display()
            )));
        }
        for (name, witness) in &witnesses {
            let path = directory.join(os_string(name));
            let current = fs::symlink_metadata(&path)?;
            if stability_witness(&current) != *witness {
                return Err(invalid_snapshot(format!(
                    "module output entry changed while observing: {}",
                    path.display()
                )));
            }
        }

        Ok(Self { directory: canonical_directory, directory_identity, entries })
    }

    /// Return all entries keyed by their raw filename bytes.
    pub fn entries(&self) -> &BTreeMap<Vec<u8>, DirectoryEntrySnapshot> {
        &self.entries
    }

    /// Validate that all directory changes are predicted regular output files.
    pub fn validate_changes(
        &self,
        after: &Self,
        predicted_raw_names: &BTreeSet<Vec<u8>>,
    ) -> io::Result<BTreeSet<Vec<u8>>> {
        if self.directory != after.directory || self.directory_identity != after.directory_identity
        {
            return Err(invalid_snapshot("directory snapshots refer to different paths"));
        }
        for name in predicted_raw_names {
            if !is_direct_name(name) {
                return Err(invalid_snapshot("predicted output is not a direct filename"));
            }
            match after.entries.get(name) {
                Some(entry)
                    if entry.kind == DirectoryEntryKind::RegularFile && entry.digest.is_some() => {}
                Some(_) => return Err(invalid_snapshot("predicted output is not a regular file")),
                None => return Err(invalid_snapshot("predicted output is absent")),
            }
        }

        let changed: BTreeSet<_> = self
            .entries
            .keys()
            .chain(after.entries.keys())
            .filter(|name| self.entries.get(*name) != after.entries.get(*name))
            .cloned()
            .collect();
        let relevant_changes = changed
            .iter()
            .filter(|name| predicted_raw_names.contains(*name) || is_module_name(name))
            .cloned()
            .collect::<BTreeSet<_>>();
        if !relevant_changes.is_subset(predicted_raw_names) {
            return Err(invalid_snapshot("compiler changed an unpredicted module output"));
        }

        let mut identities = BTreeMap::new();
        for (name, entry) in &after.entries {
            if let Some(identity) = entry.identity {
                if let Some(previous) = identities.insert(identity, name) {
                    if predicted_raw_names.contains(name) || predicted_raw_names.contains(previous)
                    {
                        return Err(invalid_snapshot(
                            "predicted output aliases another directory entry",
                        ));
                    }
                }
            }
        }
        Ok(relevant_changes)
    }
}

fn snapshot_entry(
    path: &Path,
    metadata: &Metadata,
    hash_contents: bool,
) -> io::Result<(DirectoryEntrySnapshot, MetadataStability)> {
    let kind = entry_kind(metadata);
    let witness = stability_witness(metadata);
    let (digest, symlink_target) = match kind {
        DirectoryEntryKind::RegularFile if hash_contents => {
            (Some(hash_regular_file(path, &witness)?), None)
        }
        DirectoryEntryKind::RegularFile => (None, None),
        DirectoryEntryKind::Symlink => (None, Some(path_bytes(&fs::read_link(path)?))),
        DirectoryEntryKind::Directory | DirectoryEntryKind::Other => (None, None),
    };
    Ok((
        DirectoryEntrySnapshot {
            kind,
            identity: file_identity(metadata),
            mode: file_mode(metadata),
            size: metadata.len(),
            modified: witness.modified,
            changed: witness.changed,
            digest,
            symlink_target,
        },
        witness,
    ))
}

fn hash_regular_file(path: &Path, expected: &MetadataStability) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || stability_witness(&before) != *expected {
        return Err(invalid_snapshot(format!(
            "module output entry changed before hashing: {}",
            path.display()
        )));
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| invalid_snapshot("module output size overflow"))?;
    }
    let after = file.metadata()?;
    if stability_witness(&after) != *expected || size != after.len() {
        return Err(invalid_snapshot(format!(
            "module output entry changed while hashing: {}",
            path.display()
        )));
    }
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MetadataStability {
    kind: DirectoryEntryKind,
    identity: Option<FileIdentity>,
    mode: u32,
    size: u64,
    modified: FileTimestamp,
    changed: FileTimestamp,
}

fn stability_witness(metadata: &Metadata) -> MetadataStability {
    let (modified, changed) = metadata_times(metadata);
    MetadataStability {
        kind: entry_kind(metadata),
        identity: file_identity(metadata),
        mode: file_mode(metadata),
        size: metadata.len(),
        modified,
        changed,
    }
}

fn entry_kind(metadata: &Metadata) -> DirectoryEntryKind {
    let kind = metadata.file_type();
    if kind.is_symlink() {
        DirectoryEntryKind::Symlink
    } else if kind.is_file() {
        DirectoryEntryKind::RegularFile
    } else if kind.is_dir() {
        DirectoryEntryKind::Directory
    } else {
        DirectoryEntryKind::Other
    }
}

fn is_direct_name(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

fn is_module_name(name: &[u8]) -> bool {
    name.ends_with(b".mod") || name.ends_with(b".smod")
}

fn invalid_snapshot(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(unix)]
fn ensure_snapshot_supported() -> io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_snapshot_supported() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory snapshots require nanosecond modification and change times",
    ))
}

fn path_bytes(path: &Path) -> Vec<u8> {
    os_bytes(path.as_os_str())
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn os_string(value: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(value.to_vec())
}

#[cfg(not(unix))]
fn os_string(value: &[u8]) -> std::ffi::OsString {
    String::from_utf8_lossy(value).into_owned().into()
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity { device: metadata.dev(), inode: metadata.ino() })
}

#[cfg(not(unix))]
fn file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(unix)]
fn file_mode(metadata: &Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn file_mode(metadata: &Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

#[cfg(unix)]
fn metadata_times(metadata: &Metadata) -> (FileTimestamp, FileTimestamp) {
    use std::os::unix::fs::MetadataExt;
    (
        FileTimestamp { seconds: metadata.mtime(), nanoseconds: metadata.mtime_nsec() },
        FileTimestamp { seconds: metadata.ctime(), nanoseconds: metadata.ctime_nsec() },
    )
}

#[cfg(not(unix))]
fn metadata_times(_metadata: &Metadata) -> (FileTimestamp, FileTimestamp) {
    // Direct observation is currently supported only where native change times are available.
    (FileTimestamp { seconds: 0, nanoseconds: 0 }, FileTimestamp { seconds: 0, nanoseconds: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_of_the_same_parent_share_one_lock_file() {
        let root = tempfile::tempdir().unwrap();
        let output_parent = tempfile::tempdir().unwrap();
        let first = output_parent.path().join("nested").join("..").join("result.o");
        let second = output_parent.path().join("result.o");
        fs::create_dir(output_parent.path().join("nested")).unwrap();

        let locks = OutputLocks::acquire(root.path(), [first, second]).unwrap();
        assert_eq!(locks._files.len(), 1);
    }

    #[test]
    fn duplicate_shared_and_exclusive_targets_are_promoted() {
        let root = tempfile::tempdir().unwrap();
        let output_parent = tempfile::tempdir().unwrap();
        let target = output_parent.path().join("result.o");
        let mut plan = OutputLockPlan::new();
        plan.add_module_directory(&target, ModuleDirectoryAccess::CompilerMissWithoutModules);
        plan.add_output(&target);

        let locks = OutputLocks::acquire_plan(root.path(), plan).unwrap();
        assert_eq!(locks._files.len(), 1);
        let lock_path = fs::read_dir(root.path().join("locks/outputs"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let contender = OpenOptions::new().read(true).write(true).open(lock_path).unwrap();
        assert!(FileExt::try_lock_shared(&contender).is_err());
    }

    #[test]
    fn shared_module_directory_locks_can_coexist() {
        let root = tempfile::tempdir().unwrap();
        let output_parent = tempfile::tempdir().unwrap();
        let mut first = OutputLockPlan::new();
        first.add_module_directory(
            output_parent.path(),
            ModuleDirectoryAccess::CompilerMissWithoutModules,
        );
        let first = OutputLocks::acquire_plan(root.path(), first).unwrap();

        let mut second = OutputLockPlan::new();
        second.add_module_directory(
            output_parent.path(),
            ModuleDirectoryAccess::CompilerMissWithoutModules,
        );
        let second = OutputLocks::acquire_plan(root.path(), second).unwrap();

        assert_eq!(first._files.len(), 1);
        assert_eq!(second._files.len(), 1);
    }

    #[test]
    fn snapshot_preserves_non_utf8_names_and_entry_details() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let name = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(b"module-\xff.mod".to_vec())
        };
        #[cfg(not(unix))]
        let name = std::ffi::OsString::from("module.mod");
        if let Err(error) = fs::write(directory.path().join(&name), b"module bytes") {
            if matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput)
                || error.raw_os_error() == Some(92)
            {
                return;
            }
            panic!("cannot create non-UTF-8 test entry: {error}");
        }

        let name = os_bytes(&name);
        let snapshot =
            DirectorySnapshot::read_for_outputs(directory.path(), &BTreeSet::from([name.clone()]))
                .unwrap();
        let entry = snapshot.entries().get(&name).unwrap();
        assert_eq!(entry.kind, DirectoryEntryKind::RegularFile);
        assert!(entry.identity.is_some() || cfg!(not(unix)));
        assert_eq!(entry.size, 12);
        assert_eq!(entry.digest, Some(*blake3::hash(b"module bytes").as_bytes()));
    }

    #[test]
    fn snapshot_does_not_hash_unrelated_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("large-object.o"), b"object bytes").unwrap();

        let snapshot = DirectorySnapshot::read(directory.path()).unwrap();
        assert_eq!(snapshot.entries()[b"large-object.o".as_slice()].digest, None);
    }

    #[test]
    fn snapshot_hashes_explicitly_predicted_non_module_outputs() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("generated.interface"), b"interface").unwrap();
        let predicted = BTreeSet::from([b"generated.interface".to_vec()]);

        let snapshot = DirectorySnapshot::read_for_outputs(directory.path(), &predicted).unwrap();
        assert_eq!(
            snapshot.entries()[b"generated.interface".as_slice()].digest,
            Some(*blake3::hash(b"interface").as_bytes())
        );
    }

    #[test]
    fn validation_rejects_unpredicted_changes() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("existing.mod"), b"before").unwrap();
        let before = DirectorySnapshot::read(directory.path()).unwrap();
        fs::write(directory.path().join("unexpected.mod"), b"created").unwrap();
        let after = DirectorySnapshot::read(directory.path()).unwrap();

        let error = before.validate_changes(&after, &BTreeSet::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn validation_ignores_concurrent_non_module_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let before = DirectorySnapshot::read(directory.path()).unwrap();
        fs::write(directory.path().join("other-job.o"), b"object").unwrap();
        let after = DirectorySnapshot::read(directory.path()).unwrap();

        assert!(before.validate_changes(&after, &BTreeSet::new()).unwrap().is_empty());
    }

    #[test]
    fn validation_accepts_only_predicted_regular_changes() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("existing.txt"), b"unchanged").unwrap();
        let before = DirectorySnapshot::read(directory.path()).unwrap();
        fs::write(directory.path().join("generated.mod"), b"generated").unwrap();
        let predicted = BTreeSet::from([b"generated.mod".to_vec()]);
        let after = DirectorySnapshot::read_for_outputs(directory.path(), &predicted).unwrap();

        let changed = before.validate_changes(&after, &predicted).unwrap();
        assert_eq!(changed, predicted);
    }

    #[cfg(unix)]
    #[test]
    fn validation_rejects_predicted_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("target"), b"target").unwrap();
        let before = DirectorySnapshot::read(directory.path()).unwrap();
        symlink("target", directory.path().join("generated.mod")).unwrap();
        let predicted = BTreeSet::from([b"generated.mod".to_vec()]);
        let after = DirectorySnapshot::read_for_outputs(directory.path(), &predicted).unwrap();

        assert!(before.validate_changes(&after, &predicted).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn validation_rejects_hard_link_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("existing.mod");
        fs::write(&existing, b"module").unwrap();
        let before = DirectorySnapshot::read(directory.path()).unwrap();
        fs::hard_link(existing, directory.path().join("generated.mod")).unwrap();
        let predicted = BTreeSet::from([b"generated.mod".to_vec()]);
        let after = DirectorySnapshot::read_for_outputs(directory.path(), &predicted).unwrap();

        assert!(before.validate_changes(&after, &predicted).is_err());
    }
}
