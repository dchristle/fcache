//! Content-addressable local storage.

use crate::cache::key::ActionKey;
use crate::cache::manifest::{ArtifactKind, BlobRef, DestinationRole, Manifest, ManifestError};
use fs4::FileExt;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use tempfile::NamedTempFile;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache miss")]
    Miss,
    #[error("cache entry is corrupt: {0}")]
    Corrupt(String),
    #[error("cache entry conflicts with an existing result")]
    Conflict,
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("destination is a symlink: {0}")]
    SymlinkDestination(PathBuf),
    #[error("missing destination for artifact {0}")]
    MissingDestination(String),
    #[error("unexpected destination for artifact {0}")]
    UnexpectedDestination(String),
    #[error("destination role does not match artifact {0}")]
    DestinationRoleMismatch(String),
    #[error("restore destination is used by more than one artifact: {0}")]
    DuplicateDestination(PathBuf),
    #[error("destination paths must be regular files or absent: {0}")]
    InvalidDestination(PathBuf),
    #[error("cache-owned path is not a real directory: {0}")]
    InvalidCacheDirectory(PathBuf),
    #[error("cache-owned file is a symlink: {0}")]
    SymlinkCacheFile(PathBuf),
}

#[derive(Clone, Debug)]
pub struct CacheStore {
    root: PathBuf,
}

#[derive(Clone, Debug)]
struct RestoreDestination {
    path: PathBuf,
    role: Option<DestinationRole>,
}

#[derive(Clone, Debug, Default)]
pub struct RestoreDestinations(HashMap<String, RestoreDestination>);

impl RestoreDestinations {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, logical_name: impl Into<String>, destination: impl Into<PathBuf>) {
        self.0.insert(
            logical_name.into(),
            RestoreDestination { path: destination.into(), role: None },
        );
    }

    pub fn insert_with_role(
        &mut self,
        logical_name: impl Into<String>,
        role: DestinationRole,
        destination: impl Into<PathBuf>,
    ) {
        self.0.insert(
            logical_name.into(),
            RestoreDestination { path: destination.into(), role: Some(role) },
        );
    }
}

impl From<HashMap<String, PathBuf>> for RestoreDestinations {
    fn from(value: HashMap<String, PathBuf>) -> Self {
        Self(
            value
                .into_iter()
                .map(|(name, path)| (name, RestoreDestination { path, role: None }))
                .collect(),
        )
    }
}

#[derive(Debug)]
pub struct PreparedRestore {
    manifest: Manifest,
    artifacts: Vec<PreparedArtifact>,
}

#[derive(Debug)]
struct PreparedArtifact {
    destination: PathBuf,
    temporary: NamedTempFile,
    mode: u32,
    role: DestinationRole,
    preserve_if_unchanged: bool,
}

impl PreparedRestore {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn commit(mut self) -> Result<Manifest, CacheError> {
        for artifact in &self.artifacts {
            check_destination(&artifact.destination)?;
        }
        let mut replacements = Vec::with_capacity(self.artifacts.len());
        for artifact in self.artifacts {
            if artifact.preserve_if_unchanged {
                let staged = fs::read(artifact.temporary.path())?;
                if same_file(&artifact.destination, &staged)? {
                    continue;
                }
            }
            replacements.push(artifact);
        }
        self.artifacts = replacements;

        self.artifacts.sort_by_key(|artifact| restore_role_order(&artifact.role));
        let artifact_count = self.artifacts.len();
        let mut object = None;
        let mut remaining = Vec::with_capacity(artifact_count);
        for artifact in self.artifacts {
            if artifact.role == DestinationRole::Object {
                object = Some(artifact);
            } else {
                remaining.push(artifact);
            }
        }
        let mut committed = Vec::with_capacity(artifact_count);
        let mut object_backup = None;

        if let Some(object) = &object {
            let backup = backup_destination(&object.destination)?;
            if let Err(error) = remove_completion_marker(&object.destination) {
                rollback_artifact(&object.destination, backup);
                return Err(error);
            }
            object_backup = Some((object.destination.clone(), backup));
        }

        for artifact in remaining {
            let backup = match backup_destination(&artifact.destination) {
                Ok(backup) => backup,
                Err(error) => {
                    rollback_all(&mut committed, object_backup.take());
                    return Err(error);
                }
            };
            let destination = artifact.destination;
            let installed = install_replace(artifact.temporary, &destination, artifact.mode);
            if let Err(error) = installed {
                rollback_artifact(&destination, backup);
                rollback_all(&mut committed, object_backup.take());
                return Err(error);
            }
            committed.push((destination, backup));
        }

        if let Some(artifact) = object {
            let (_, backup) = object_backup.take().expect("object backup was prepared");
            let destination = artifact.destination;
            let installed = install_replace(artifact.temporary, &destination, artifact.mode);
            if let Err(error) = installed {
                rollback_artifact(&destination, backup);
                rollback_all(&mut committed, None);
                return Err(error);
            }
        }

        Ok(self.manifest)
    }
}

impl CacheStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let root = root.into();
        create_cache_directory(&root)?;
        create_cache_directory(&root.join("v1"))?;
        create_cache_directory(&root.join("v1/blobs"))?;
        create_cache_directory(&root.join("v1/results"))?;
        create_cache_directory(&root.join("v1/conflicts"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blob_path(&self, digest: &str) -> PathBuf {
        self.root.join("v1/blobs").join(&digest[..2.min(digest.len())]).join(digest)
    }
    pub fn result_path(&self, action: &ActionKey) -> PathBuf {
        self.root.join("v1/results").join(&action.to_string()[..2]).join(format!("{action}.json"))
    }
    pub fn conflict_path(&self, action: &ActionKey) -> PathBuf {
        self.root.join("v1/conflicts").join(action.to_string())
    }

    pub fn put_blob(&self, bytes: &[u8], mode: u32) -> Result<BlobRef, CacheError> {
        self.validate_area("blobs")?;
        let digest = blake3::hash(bytes).to_hex().to_string();
        let reference = BlobRef::new(digest, bytes.len() as u64, mode);
        let destination = self.blob_path(&reference.digest);
        create_cache_directory(destination.parent().expect("blob parent"))?;
        if destination.exists() {
            self.verify_blob(&reference)?;
            return Ok(reference);
        }
        let mut temporary = NamedTempFile::new_in(destination.parent().expect("blob parent"))?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        install_noclobber(temporary, &destination)?;
        self.verify_blob(&reference)?;
        Ok(reference)
    }

    pub fn read_blob(&self, reference: &BlobRef) -> Result<Vec<u8>, CacheError> {
        self.validate_area("blobs")?;
        reference.validate().map_err(CacheError::Manifest)?;
        let path = self.blob_path(&reference.digest);
        if !validate_existing_cache_directory(path.parent().expect("blob shard"))? {
            return Err(CacheError::Miss);
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound { CacheError::Miss } else { error.into() }
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(CacheError::Corrupt(reference.digest.clone()));
        }
        let bytes = fs::read(path)?;
        if bytes.len() as u64 != reference.size
            || blake3::hash(&bytes).to_hex().as_str() != reference.digest
        {
            return Err(CacheError::Corrupt(reference.digest.clone()));
        }
        Ok(bytes)
    }

    pub fn verify_blob(&self, reference: &BlobRef) -> Result<(), CacheError> {
        self.read_blob(reference).map(|_| ())
    }

    /// Publishes a validated manifest after its referenced blobs have been installed.
    pub fn publish_manifest(&self, manifest: &Manifest) -> Result<(), CacheError> {
        let _maintenance = self.maintenance_lock(false)?;
        self.validate_area("results")?;
        self.validate_area("conflicts")?;
        manifest.validate()?;
        for artifact in &manifest.artifacts {
            self.verify_blob(&artifact.blob)?;
        }
        self.verify_blob(&manifest.stdout)?;
        self.verify_blob(&manifest.stderr)?;
        let action = &manifest.action_key;
        if fs::symlink_metadata(self.conflict_path(action)).is_ok() {
            return Err(CacheError::Conflict);
        }
        let path = self.result_path(action);
        create_cache_directory(path.parent().expect("result parent"))?;
        let bytes = manifest.to_json()?;
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() {
                return Err(CacheError::SymlinkCacheFile(path));
            }
            let current = fs::read(&path)?;
            let existing = Manifest::from_json(&current)
                .map_err(|error| CacheError::Corrupt(error.to_string()))?;
            if existing == *manifest {
                return Ok(());
            }
            self.write_tombstone(action)?;
            return Err(CacheError::Conflict);
        }
        let mut temporary = NamedTempFile::new_in(path.parent().expect("result parent"))?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        install_noclobber(temporary, &path)?;
        if let Ok(current) = fs::read(&path) {
            if current != bytes {
                self.write_tombstone(action)?;
                return Err(CacheError::Conflict);
            }
        }
        Ok(())
    }

    pub fn publish(&self, manifest: &Manifest) -> Result<(), CacheError> {
        self.publish_manifest(manifest)
    }

    pub fn load(&self, action: &ActionKey) -> Result<Option<Manifest>, CacheError> {
        let Some(manifest) = self.load_manifest_metadata(action)? else {
            return Ok(None);
        };
        self.verify_manifest_blobs(&manifest)?;
        Ok(Some(manifest))
    }

    pub(crate) fn load_manifest_metadata(
        &self,
        action: &ActionKey,
    ) -> Result<Option<Manifest>, CacheError> {
        self.validate_area("results")?;
        self.validate_area("conflicts")?;
        if fs::symlink_metadata(self.conflict_path(action)).is_ok() {
            return Ok(None);
        }
        let path = self.result_path(action);
        if !validate_existing_cache_directory(path.parent().expect("result shard"))? {
            return Ok(None);
        }
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() {
                return Err(CacheError::SymlinkCacheFile(path));
            }
        }
        let bytes = match fs::read(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let manifest =
            Manifest::from_json(&bytes).map_err(|error| CacheError::Corrupt(error.to_string()))?;
        if manifest.action_key != *action {
            return Err(CacheError::Corrupt("action key does not match result path".into()));
        }
        Ok(Some(manifest))
    }

    fn verify_manifest_blobs(&self, manifest: &Manifest) -> Result<(), CacheError> {
        let mut verified = HashSet::new();
        for blob in manifest
            .artifacts
            .iter()
            .map(|artifact| &artifact.blob)
            .chain([&manifest.stdout, &manifest.stderr])
        {
            if verified.insert((&blob.digest, blob.size)) {
                self.verify_blob(blob)?;
            }
        }
        Ok(())
    }

    pub fn get(&self, action: &ActionKey) -> Result<Option<Manifest>, CacheError> {
        self.load(action)
    }

    pub fn restore(
        &self,
        action: &ActionKey,
        destinations: &RestoreDestinations,
    ) -> Result<Manifest, CacheError> {
        self.prepare_restore_impl(action, destinations, false)?.commit()
    }

    pub fn prepare_restore(
        &self,
        action: &ActionKey,
        destinations: &RestoreDestinations,
    ) -> Result<PreparedRestore, CacheError> {
        self.prepare_restore_impl(action, destinations, true)
    }

    fn prepare_restore_impl(
        &self,
        action: &ActionKey,
        destinations: &RestoreDestinations,
        require_roles: bool,
    ) -> Result<PreparedRestore, CacheError> {
        let manifest = self.load_manifest_metadata(action)?.ok_or(CacheError::Miss)?;
        validate_restore_contract(&manifest, destinations, require_roles)?;
        let mut artifacts = Vec::new();
        let mut verified = HashSet::new();
        for artifact in &manifest.artifacts {
            let destination = destinations
                .0
                .get(&artifact.logical_name)
                .expect("restore contract has a destination");
            check_destination(&destination.path)?;
            let bytes = self.read_blob(&artifact.blob)?;
            verified.insert((&artifact.blob.digest, artifact.blob.size));
            let parent = destination.path.parent().unwrap_or_else(|| Path::new("."));
            let mut temporary = NamedTempFile::new_in(parent)?;
            temporary.write_all(&bytes)?;
            artifacts.push(PreparedArtifact {
                destination: destination.path.clone(),
                temporary,
                mode: artifact.blob.mode,
                role: artifact.destination_role,
                preserve_if_unchanged: matches!(
                    artifact.kind,
                    ArtifactKind::Module | ArtifactKind::Submodule
                ),
            });
        }
        for diagnostic in [&manifest.stdout, &manifest.stderr] {
            if verified.insert((&diagnostic.digest, diagnostic.size)) {
                self.verify_blob(diagnostic)?;
            }
        }
        Ok(PreparedRestore { manifest, artifacts })
    }

    pub fn trim(&self, keep_recent: usize) -> Result<usize, CacheError> {
        let _maintenance = self.maintenance_lock(true)?;
        self.trim_with_grace_locked(keep_recent, std::time::Duration::from_secs(60 * 60))
    }

    pub fn trim_to_size(&self, max_bytes: u64) -> Result<usize, CacheError> {
        let _maintenance = self.maintenance_lock(true)?;
        let mut entries = self.result_entries()?;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        let mut retained_bytes = 0_u64;
        let mut retained_blobs = std::collections::HashSet::new();
        let mut keep = 0;
        for (_, path) in &entries {
            let manifest_bytes = fs::read(path)?;
            let manifest = match Manifest::from_json(&manifest_bytes) {
                Ok(value) => value,
                Err(_) => break,
            };
            let mut added = manifest_bytes.len() as u64;
            for blob in manifest
                .artifacts
                .iter()
                .map(|artifact| &artifact.blob)
                .chain([&manifest.stdout, &manifest.stderr])
            {
                if retained_blobs.insert(blob.digest.clone()) {
                    added = added.saturating_add(blob.size);
                }
            }
            if retained_bytes.saturating_add(added) > max_bytes {
                break;
            }
            retained_bytes = retained_bytes.saturating_add(added);
            keep += 1;
        }
        self.trim_with_grace_locked(keep, std::time::Duration::from_secs(60 * 60))
    }

    pub fn trim_with_grace(
        &self,
        keep_recent: usize,
        orphan_grace: std::time::Duration,
    ) -> Result<usize, CacheError> {
        let _maintenance = self.maintenance_lock(true)?;
        self.trim_with_grace_locked(keep_recent, orphan_grace)
    }

    fn trim_with_grace_locked(
        &self,
        keep_recent: usize,
        orphan_grace: std::time::Duration,
    ) -> Result<usize, CacheError> {
        self.validate_area("results")?;
        self.validate_area("blobs")?;
        let mut entries = self.result_entries()?;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        let marked = entries
            .iter()
            .take(keep_recent)
            .filter_map(|(_, path)| fs::read(path).ok())
            .filter_map(|bytes| Manifest::from_json(&bytes).ok())
            .flat_map(|manifest| {
                manifest
                    .artifacts
                    .into_iter()
                    .map(|artifact| artifact.blob.digest)
                    .chain([manifest.stdout.digest, manifest.stderr.digest])
            })
            .collect::<std::collections::HashSet<_>>();
        let mut removed = 0;
        for (_, path) in entries.iter().skip(keep_recent) {
            if fs::remove_file(path).is_ok() {
                removed += 1;
            }
        }
        let cutoff = std::time::SystemTime::now()
            .checked_sub(orphan_grace)
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let blobs = self.root.join("v1/blobs");
        for shard in fs::read_dir(&blobs)? {
            let shard = shard?.path();
            if !is_real_directory(&shard)? {
                continue;
            }
            for item in fs::read_dir(shard)? {
                let item = item?;
                let path = item.path();
                let digest = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
                if marked.contains(digest)
                    || item.metadata()?.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                        > cutoff
                {
                    continue;
                }
                if fs::remove_file(path).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    fn result_entries(&self) -> Result<Vec<(std::time::SystemTime, PathBuf)>, CacheError> {
        let results = self.root.join("v1/results");
        let mut entries = Vec::new();
        for shard in fs::read_dir(&results)? {
            let shard = shard?.path();
            if !is_real_directory(&shard)? {
                continue;
            }
            for item in fs::read_dir(shard)? {
                let item = item?;
                if item.path().extension().and_then(|extension| extension.to_str()) == Some("json")
                {
                    entries.push((
                        item.metadata()?.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                        item.path(),
                    ));
                }
            }
        }
        Ok(entries)
    }

    pub fn clear(&self) -> Result<(), CacheError> {
        let _maintenance = self.maintenance_lock(true)?;
        require_real_directory(&self.root)?;
        let version = self.root.join("v1");
        if version.exists() {
            if !is_real_directory(&version)? {
                return Err(CacheError::InvalidCacheDirectory(version));
            }
            fs::remove_dir_all(version)?;
        }
        create_cache_directory(&self.root.join("v1"))?;
        create_cache_directory(&self.root.join("v1/blobs"))?;
        create_cache_directory(&self.root.join("v1/results"))?;
        create_cache_directory(&self.root.join("v1/conflicts"))?;
        Ok(())
    }

    fn write_tombstone(&self, action: &ActionKey) -> Result<(), CacheError> {
        let path = self.conflict_path(action);
        if fs::symlink_metadata(&path).is_ok() {
            return Ok(());
        }
        let mut temporary = NamedTempFile::new_in(path.parent().expect("conflict parent"))?;
        temporary.write_all(b"conflict\n")?;
        temporary.as_file().sync_all()?;
        install_noclobber(temporary, &path)
    }

    fn maintenance_lock(&self, exclusive: bool) -> Result<File, CacheError> {
        require_real_directory(&self.root)?;
        let path = self.root.join(".fcache-maintenance.lock");
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(CacheError::SymlinkCacheFile(path));
        }
        let lock =
            OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&path)?;
        if exclusive {
            FileExt::lock(&lock)?;
        } else {
            FileExt::lock_shared(&lock)?;
        }
        Ok(lock)
    }

    fn validate_area(&self, area: &str) -> Result<(), CacheError> {
        require_real_directory(&self.root)?;
        require_real_directory(&self.root.join("v1"))?;
        require_real_directory(&self.root.join("v1").join(area))
    }
}

fn create_cache_directory(path: &Path) -> Result<(), CacheError> {
    fs::create_dir_all(path)?;
    require_real_directory(path)
}

fn is_real_directory(path: &Path) -> Result<bool, CacheError> {
    Ok(fs::symlink_metadata(path)?.file_type().is_dir())
}

fn require_real_directory(path: &Path) -> Result<(), CacheError> {
    if is_real_directory(path)? {
        Ok(())
    } else {
        Err(CacheError::InvalidCacheDirectory(path.to_path_buf()))
    }
}

fn validate_existing_cache_directory(path: &Path) -> Result<bool, CacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(CacheError::InvalidCacheDirectory(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn restore_role_order(role: &DestinationRole) -> u8 {
    match role {
        DestinationRole::Dependency => 0,
        DestinationRole::Module => 1,
        DestinationRole::Submodule => 1,
        DestinationRole::Object => 2,
    }
}

fn validate_restore_contract(
    manifest: &Manifest,
    destinations: &RestoreDestinations,
    require_roles: bool,
) -> Result<(), CacheError> {
    for logical_name in destinations.0.keys() {
        if !manifest.artifacts.iter().any(|artifact| artifact.logical_name == *logical_name) {
            return Err(CacheError::UnexpectedDestination(logical_name.clone()));
        }
    }

    let mut paths = HashSet::new();
    for artifact in &manifest.artifacts {
        let destination = destinations
            .0
            .get(&artifact.logical_name)
            .ok_or_else(|| CacheError::MissingDestination(artifact.logical_name.clone()))?;
        if require_roles && destination.role.as_ref() != Some(&artifact.destination_role) {
            return Err(CacheError::DestinationRoleMismatch(artifact.logical_name.clone()));
        }
        if destination.role.as_ref().is_some_and(|role| role != &artifact.destination_role) {
            return Err(CacheError::DestinationRoleMismatch(artifact.logical_name.clone()));
        }
        let identity = normalized_destination(&destination.path)?;
        if !paths.insert(identity) {
            return Err(CacheError::DuplicateDestination(destination.path.clone()));
        }
    }
    Ok(())
}

fn normalized_destination(path: &Path) -> Result<PathBuf, CacheError> {
    let absolute =
        if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    if let Ok(canonical) = fs::canonicalize(&absolute) {
        return Ok(canonical);
    }
    if let (Some(parent), Some(file_name)) = (absolute.parent(), absolute.file_name()) {
        if let Ok(canonical_parent) = fs::canonicalize(parent) {
            return Ok(canonical_parent.join(file_name));
        }
    }
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    Ok(normalized)
}

#[derive(Debug)]
struct DestinationBackup {
    temporary: NamedTempFile,
    mode: u32,
}

fn backup_destination(path: &Path) -> Result<Option<DestinationBackup>, CacheError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(CacheError::SymlinkDestination(path.to_path_buf()));
    }
    if !metadata.file_type().is_file() {
        return Err(CacheError::InvalidDestination(path.to_path_buf()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = NamedTempFile::new_in(parent)?;
    fs::copy(path, temporary.path())?;
    Ok(Some(DestinationBackup { temporary, mode: file_mode(&metadata) }))
}

fn remove_completion_marker(path: &Path) -> Result<(), CacheError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn rollback_all(
    committed: &mut Vec<(PathBuf, Option<DestinationBackup>)>,
    completion_marker: Option<(PathBuf, Option<DestinationBackup>)>,
) {
    for (destination, backup) in committed.drain(..).rev() {
        rollback_artifact(&destination, backup);
    }
    if let Some((destination, backup)) = completion_marker {
        rollback_artifact(&destination, backup);
    }
}

fn rollback_artifact(destination: &Path, backup: Option<DestinationBackup>) {
    if let Some(backup) = backup {
        let _ = install_replace(backup.temporary, destination, backup.mode);
    } else if fs::symlink_metadata(destination).is_ok_and(|metadata| metadata.file_type().is_file())
    {
        let _ = fs::remove_file(destination);
    }
}

fn file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0o644
    }
}

fn check_destination(path: &Path) -> Result<(), CacheError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(CacheError::SymlinkDestination(path.to_path_buf()));
        }
        if !metadata.file_type().is_file() {
            return Err(CacheError::InvalidDestination(path.to_path_buf()));
        }
    }
    Ok(())
}

fn same_file(path: &Path, bytes: &[u8]) -> Result<bool, CacheError> {
    match fs::read(path) {
        Ok(existing) => Ok(existing == bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn install_noclobber(temporary: NamedTempFile, destination: &Path) -> Result<(), CacheError> {
    match fs::hard_link(temporary.path(), destination) {
        Ok(()) => {
            temporary.close()?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            temporary.close()?;
            Ok(())
        }
        Err(_) => {
            temporary.persist_noclobber(destination).map(|_| ()).map_err(|error| error.error.into())
        }
    }
}

fn install_replace(
    temporary: NamedTempFile,
    destination: &Path,
    mode: u32,
) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary.as_file().set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
    }
    temporary.persist(destination).map(|_| ()).map_err(|error| error.error.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::key::ActionKeyBuilder;
    use crate::cache::manifest::{Artifact, ArtifactKind};

    fn artifact(
        store: &CacheStore,
        kind: ArtifactKind,
        logical_name: &str,
        role: DestinationRole,
        bytes: &[u8],
    ) -> Artifact {
        Artifact::new(kind, logical_name, role, store.put_blob(bytes, 0o644).unwrap())
    }

    fn publish_bundle(store: &CacheStore, artifacts: Vec<Artifact>) -> ActionKey {
        let key = ActionKeyBuilder::new().bytes("x", b"y").finish().unwrap();
        let diagnostics = store.put_blob(b"", 0o644).unwrap();
        store
            .publish(&Manifest::new(
                key,
                "a".repeat(64),
                artifacts,
                diagnostics.clone(),
                diagnostics,
            ))
            .unwrap();
        key
    }

    #[test]
    fn corrupted_blob_is_reported() {
        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path()).unwrap();
        let reference = store.put_blob(b"good", 0o644).unwrap();
        fs::write(store.blob_path(&reference.digest), b"bad").unwrap();
        assert!(matches!(store.read_blob(&reference), Err(CacheError::Corrupt(_))));
    }
    #[test]
    fn identical_modules_are_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path()).unwrap();
        let blob = store.put_blob(b"module", 0o644).unwrap();
        let stdout = store.put_blob(b"", 0o644).unwrap();
        let key = ActionKeyBuilder::new().bytes("x", b"y").finish().unwrap();
        let manifest = Manifest::new(
            key,
            "a".repeat(64),
            vec![Artifact::new(ArtifactKind::Module, "x.mod", DestinationRole::Module, blob)],
            stdout.clone(),
            stdout,
        );
        store.publish(&manifest).unwrap();
        let destination = directory.path().join("x.mod");
        fs::write(&destination, b"module").unwrap();
        let before = fs::metadata(&destination).unwrap().modified().unwrap();
        let mut destinations = RestoreDestinations::new();
        destinations.insert("x.mod", &destination);
        store.restore(&key, &destinations).unwrap();
        assert_eq!(before, fs::metadata(destination).unwrap().modified().unwrap());
    }

    #[test]
    fn preparation_failure_does_not_mutate_any_destination() {
        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path().join("cache")).unwrap();
        let key = publish_bundle(
            &store,
            vec![
                artifact(
                    &store,
                    ArtifactKind::Object,
                    "object",
                    DestinationRole::Object,
                    b"new object",
                ),
                artifact(
                    &store,
                    ArtifactKind::Module,
                    "module:x.mod",
                    DestinationRole::Module,
                    b"new module",
                ),
            ],
        );
        let object = directory.path().join("x.o");
        fs::write(&object, b"old object").unwrap();
        let mut destinations = RestoreDestinations::new();
        destinations.insert_with_role("object", DestinationRole::Object, &object);
        destinations.insert_with_role(
            "module:x.mod",
            DestinationRole::Module,
            directory.path().join("missing/x.mod"),
        );

        assert!(matches!(store.prepare_restore(&key, &destinations), Err(CacheError::Io(_))));
        assert_eq!(fs::read(object).unwrap(), b"old object");
    }

    #[test]
    fn corrupted_artifact_prevents_any_destination_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path().join("cache")).unwrap();
        let object_artifact = artifact(
            &store,
            ArtifactKind::Object,
            "object",
            DestinationRole::Object,
            b"new object",
        );
        let module_artifact = artifact(
            &store,
            ArtifactKind::Module,
            "module:x.mod",
            DestinationRole::Module,
            b"new module",
        );
        let corrupt_path = store.blob_path(&module_artifact.blob.digest);
        let key = publish_bundle(&store, vec![object_artifact, module_artifact]);
        fs::write(corrupt_path, b"corrupt").unwrap();

        let object = directory.path().join("x.o");
        let module = directory.path().join("x.mod");
        fs::write(&object, b"old object").unwrap();
        fs::write(&module, b"old module").unwrap();
        let mut destinations = RestoreDestinations::new();
        destinations.insert_with_role("object", DestinationRole::Object, &object);
        destinations.insert_with_role("module:x.mod", DestinationRole::Module, &module);

        assert!(matches!(store.prepare_restore(&key, &destinations), Err(CacheError::Corrupt(_))));
        assert_eq!(fs::read(object).unwrap(), b"old object");
        assert_eq!(fs::read(module).unwrap(), b"old module");
    }

    #[test]
    fn corrupted_diagnostics_prevent_destination_commit() {
        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path().join("cache")).unwrap();
        let key = ActionKeyBuilder::new().bytes("x", b"y").finish().unwrap();
        let object = artifact(
            &store,
            ArtifactKind::Object,
            "object",
            DestinationRole::Object,
            b"new object",
        );
        let stdout = store.put_blob(b"compiler output", 0o644).unwrap();
        let stderr = store.put_blob(b"", 0o644).unwrap();
        store
            .publish(&Manifest::new(key, "a".repeat(64), vec![object], stdout.clone(), stderr))
            .unwrap();
        fs::write(store.blob_path(&stdout.digest), b"corrupt").unwrap();

        let destination = directory.path().join("x.o");
        fs::write(&destination, b"old object").unwrap();
        let mut destinations = RestoreDestinations::new();
        destinations.insert_with_role("object", DestinationRole::Object, &destination);

        assert!(matches!(store.prepare_restore(&key, &destinations), Err(CacheError::Corrupt(_))));
        assert_eq!(fs::read(destination).unwrap(), b"old object");
    }

    #[test]
    fn preparation_rejects_duplicate_destinations_and_role_mismatches() {
        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path().join("cache")).unwrap();
        let key = publish_bundle(
            &store,
            vec![
                artifact(
                    &store,
                    ArtifactKind::Object,
                    "object",
                    DestinationRole::Object,
                    b"object",
                ),
                artifact(
                    &store,
                    ArtifactKind::Module,
                    "module:x.mod",
                    DestinationRole::Module,
                    b"module",
                ),
            ],
        );
        let shared = directory.path().join("shared");
        let mut destinations = RestoreDestinations::new();
        destinations.insert_with_role("object", DestinationRole::Object, &shared);
        destinations.insert_with_role("module:x.mod", DestinationRole::Module, &shared);
        assert!(matches!(
            store.prepare_restore(&key, &destinations),
            Err(CacheError::DuplicateDestination(_))
        ));

        destinations.insert_with_role(
            "module:x.mod",
            DestinationRole::Dependency,
            directory.path().join("x.mod"),
        );
        assert!(matches!(
            store.prepare_restore(&key, &destinations),
            Err(CacheError::DestinationRoleMismatch(name)) if name == "module:x.mod"
        ));
    }

    #[test]
    fn failed_object_commit_rolls_back_earlier_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path().join("cache")).unwrap();
        let key = publish_bundle(
            &store,
            vec![
                artifact(
                    &store,
                    ArtifactKind::Object,
                    "object",
                    DestinationRole::Object,
                    b"new object",
                ),
                artifact(
                    &store,
                    ArtifactKind::Dependency,
                    "dependency",
                    DestinationRole::Dependency,
                    b"new dependency",
                ),
                artifact(
                    &store,
                    ArtifactKind::Module,
                    "module:x.mod",
                    DestinationRole::Module,
                    b"new module",
                ),
            ],
        );
        let object = directory.path().join("x.o");
        let dependency = directory.path().join("x.d");
        let module = directory.path().join("x.mod");
        fs::write(&object, b"old object").unwrap();
        fs::write(&dependency, b"old dependency").unwrap();
        fs::write(&module, b"old module").unwrap();
        let mut destinations = RestoreDestinations::new();
        destinations.insert_with_role("object", DestinationRole::Object, &object);
        destinations.insert_with_role("dependency", DestinationRole::Dependency, &dependency);
        destinations.insert_with_role("module:x.mod", DestinationRole::Module, &module);

        let prepared = store.prepare_restore(&key, &destinations).unwrap();
        let object_temporary = prepared
            .artifacts
            .iter()
            .find(|artifact| artifact.role == DestinationRole::Object)
            .unwrap()
            .temporary
            .path()
            .to_path_buf();
        fs::remove_file(object_temporary).unwrap();
        assert!(matches!(prepared.commit(), Err(CacheError::Io(_))));
        assert_eq!(fs::read(object).unwrap(), b"old object");
        assert_eq!(fs::read(dependency).unwrap(), b"old dependency");
        assert_eq!(fs::read(module).unwrap(), b"old module");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_directories() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let external = directory.path().join("external");
        fs::create_dir(&external).unwrap();
        let cache = directory.path().join("cache");
        symlink(&external, &cache).unwrap();
        assert!(matches!(
            CacheStore::new(&cache),
            Err(CacheError::InvalidCacheDirectory(path)) if path == cache
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_shards_on_read() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let store = CacheStore::new(directory.path().join("cache")).unwrap();
        let external = directory.path().join("external");
        fs::create_dir(&external).unwrap();

        let key = ActionKey::from_bytes([0xab; 32]);
        let result_shard = store.result_path(&key).parent().unwrap().to_path_buf();
        symlink(&external, &result_shard).unwrap();
        assert!(
            matches!(store.load(&key), Err(CacheError::InvalidCacheDirectory(path)) if path == result_shard)
        );

        let blob = BlobRef::new(format!("cd{}", "0".repeat(62)), 0, 0o644);
        let blob_shard = store.blob_path(&blob.digest).parent().unwrap().to_path_buf();
        symlink(&external, &blob_shard).unwrap();
        assert!(
            matches!(store.read_blob(&blob), Err(CacheError::InvalidCacheDirectory(path)) if path == blob_shard)
        );
    }
}
