//! Persistent observations used to prove compiler-free direct cache hits.

use crate::cache::key::ActionKey;
use crate::cache::manifest::{ArtifactKind, validate_logical_name};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use tempfile::NamedTempFile;

pub const DIRECT_RECORD_SCHEMA_VERSION: u32 = 2;
pub const DIRECT_INDEX_SCHEMA_VERSION: u32 = 2;
pub const DIRECT_REQUEST_KEY_VERSION: u8 = 1;
pub const MAX_DIRECT_CANDIDATES: usize = 4;
pub const MAX_DIRECT_INDEX_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_DIRECT_INPUTS: usize = 4096;
pub const MAX_SEARCH_ROOTS: usize = 1024;
pub const MAX_RESOLUTION_WITNESSES: usize = 16_384;
pub const MAX_EXPECTED_ARTIFACTS: usize = 256;
pub const MAX_PATH_BYTES: usize = 64 * 1024;
pub const MAX_OBSERVATION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SYMLINKS_PER_PATH: usize = 256;

/// A byte-preserving operating-system string stored in direct-index metadata.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EncodedOsString(Vec<u8>);

impl EncodedOsString {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_os_str(value: &OsStr) -> Self {
        Self(os_bytes(value))
    }

    pub fn from_path(value: &Path) -> Self {
        Self::from_os_str(value.as_os_str())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_os_string(&self) -> OsString {
        os_string(&self.0)
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(self.to_os_string())
    }

    fn validate(&self) -> Result<(), DirectRecordError> {
        if self.0.len() > MAX_PATH_BYTES {
            return Err(DirectRecordError::PathTooLong);
        }
        if self.0.contains(&0) {
            return Err(DirectRecordError::NulPath);
        }
        Ok(())
    }
}

impl fmt::Debug for EncodedOsString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("EncodedOsString").field(&self.to_os_string()).finish()
    }
}

impl Serialize for EncodedOsString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for EncodedOsString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        hex_decode(&value).map(Self).map_err(serde::de::Error::custom)
    }
}

/// A BLAKE3 digest used by direct observations.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectDigest([u8; 32]);

impl DirectDigest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn hash(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, DirectRecordError> {
        let decoded = hex_decode(value).map_err(|_| DirectRecordError::InvalidDigest)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| DirectRecordError::InvalidDigest)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for DirectDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex_encode(&self.0))
    }
}

impl fmt::Debug for DirectDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DirectDigest").field(&self.to_string()).finish()
    }
}

impl Serialize for DirectDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DirectDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// A request identity available before compiler fingerprinting or dependency probes.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectRequestKey([u8; 32]);

impl DirectRequestKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, DirectRecordError> {
        let digest = DirectDigest::parse(value)?;
        Ok(Self(*digest.as_bytes()))
    }

    /// Hashes exact request bytes while preserving argument, environment, and semantic ordering.
    pub fn compute(
        compiler: &OsStr,
        cwd: &Path,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
        source_path: &Path,
        source_digest: DirectDigest,
        semantics: &[(Vec<u8>, Vec<u8>)],
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fcache.direct-request-key\0");
        hasher.update(&[DIRECT_REQUEST_KEY_VERSION]);
        hash_frame(&mut hasher, 1, &os_bytes(compiler));
        hash_frame(&mut hasher, 2, &os_bytes(cwd.as_os_str()));
        for argument in arguments {
            hash_frame(&mut hasher, 3, &os_bytes(argument));
        }
        for (name, value) in environment {
            hash_frame(&mut hasher, 4, &os_bytes(name));
            hash_frame(&mut hasher, 5, &os_bytes(value));
        }
        hash_frame(&mut hasher, 6, &os_bytes(source_path.as_os_str()));
        hash_frame(&mut hasher, 7, source_digest.as_bytes());
        for (name, value) in semantics {
            hash_frame(&mut hasher, 8, name);
            hash_frame(&mut hasher, 9, value);
        }
        Self(*hasher.finalize().as_bytes())
    }
}

impl fmt::Display for DirectRequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex_encode(&self.0))
    }
}

impl fmt::Debug for DirectRequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DirectRequestKey").field(&self.to_string()).finish()
    }
}

impl Serialize for DirectRequestKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DirectRequestKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WitnessFileType {
    Regular,
    Directory,
    Symlink,
}

/// Metadata fields used to detect replacement or mutation of a witnessed path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataWitness {
    pub file_type: WitnessFileType,
    pub size: u64,
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

impl MetadataWitness {
    fn capture(metadata: &fs::Metadata, file_type: WitnessFileType) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                file_type,
                size: metadata.len(),
                mode: metadata.mode(),
                device: metadata.dev(),
                inode: metadata.ino(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            use std::time::UNIX_EPOCH;
            let modified =
                metadata.modified().ok().and_then(|value| value.duration_since(UNIX_EPOCH).ok());
            Self {
                file_type,
                size: metadata.len(),
                mode: u32::from(metadata.permissions().readonly()),
                device: 0,
                inode: 0,
                modified_seconds: modified.map_or(0, |value| value.as_secs() as i64),
                modified_nanoseconds: modified.map_or(0, |value| i64::from(value.subsec_nanos())),
                changed_seconds: 0,
                changed_nanoseconds: 0,
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymlinkWitness {
    pub path: EncodedOsString,
    pub target: EncodedOsString,
    pub metadata: MetadataWitness,
}

/// Canonical and symlink identity for a resolved filesystem path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathWitness {
    pub resolved_path: EncodedOsString,
    pub canonical_path: EncodedOsString,
    pub metadata: MetadataWitness,
    pub symlinks: Vec<SymlinkWitness>,
}

impl PathWitness {
    pub fn capture(path: &Path, expected_type: WitnessFileType) -> io::Result<Self> {
        let absolute = absolute_path(path)?;
        let canonical = fs::canonicalize(&absolute)?;
        let metadata = fs::metadata(&absolute)?;
        ensure_file_type(&metadata, expected_type, &absolute)?;
        Ok(Self {
            resolved_path: EncodedOsString::from_path(&absolute),
            canonical_path: EncodedOsString::from_path(&canonical),
            metadata: MetadataWitness::capture(&metadata, expected_type),
            symlinks: capture_symlinks(&absolute)?,
        })
    }

    pub fn validate(&self, expected_type: WitnessFileType) -> Result<(), DirectValidationError> {
        self.validate_schema()?;
        let current =
            Self::capture(&self.resolved_path.to_path_buf(), expected_type).map_err(|source| {
                DirectValidationError::PathChanged {
                    path: self.resolved_path.to_path_buf(),
                    source,
                }
            })?;
        if !self.same_identity(&current, expected_type) {
            return Err(DirectValidationError::WitnessChanged(self.resolved_path.to_path_buf()));
        }
        Ok(())
    }

    fn same_identity(&self, current: &Self, expected_type: WitnessFileType) -> bool {
        if self.resolved_path != current.resolved_path
            || self.canonical_path != current.canonical_path
            || self.symlinks != current.symlinks
        {
            return false;
        }
        match expected_type {
            WitnessFileType::Regular => self.metadata.file_type == current.metadata.file_type,
            WitnessFileType::Directory => self.metadata.file_type == current.metadata.file_type,
            WitnessFileType::Symlink => self.metadata == current.metadata,
        }
    }

    fn validate_schema(&self) -> Result<(), DirectRecordError> {
        self.resolved_path.validate()?;
        self.canonical_path.validate()?;
        if !self.resolved_path.to_path_buf().is_absolute()
            || !self.canonical_path.to_path_buf().is_absolute()
        {
            return Err(DirectRecordError::NonAbsoluteResolvedPath);
        }
        if self.symlinks.len() > MAX_SYMLINKS_PER_PATH {
            return Err(DirectRecordError::TooManySymlinks);
        }
        for symlink in &self.symlinks {
            symlink.path.validate()?;
            symlink.target.validate()?;
            if symlink.metadata.file_type != WitnessFileType::Symlink {
                return Err(DirectRecordError::InvalidWitnessType);
            }
        }
        Ok(())
    }
}

/// A compiler-reported input and the exact regular file that satisfied it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectInput {
    pub raw_path: EncodedOsString,
    pub path: PathWitness,
    pub digest: DirectDigest,
    pub size: u64,
}

impl DirectInput {
    pub fn capture(raw_path: &OsStr, resolved_path: &Path) -> io::Result<Self> {
        let path = PathWitness::capture(resolved_path, WitnessFileType::Regular)?;
        let (digest, size) = hash_stable_regular_file(&path)?;
        Ok(Self { raw_path: EncodedOsString::from_os_str(raw_path), path, digest, size })
    }

    pub fn validate_contents(&self) -> Result<(), DirectValidationError> {
        self.validate_schema()?;
        self.path.validate(WitnessFileType::Regular)?;
        let (digest, size) = hash_stable_regular_file(&self.path).map_err(|source| {
            DirectValidationError::PathChanged {
                path: self.path.resolved_path.to_path_buf(),
                source,
            }
        })?;
        if digest != self.digest || size != self.size {
            return Err(DirectValidationError::ContentChanged(
                self.path.resolved_path.to_path_buf(),
            ));
        }
        self.path.validate(WitnessFileType::Regular)
    }

    fn validate_schema(&self) -> Result<(), DirectRecordError> {
        self.raw_path.validate()?;
        self.path.validate_schema()?;
        if self.path.metadata.file_type != WitnessFileType::Regular
            || self.path.metadata.size != self.size
        {
            return Err(DirectRecordError::InvalidInput);
        }
        Ok(())
    }
}

/// Proof that an exact earlier search candidate did not exist.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsentPathWitness {
    pub path: EncodedOsString,
    pub nearest_existing_ancestor: PathWitness,
}

impl AbsentPathWitness {
    pub fn capture(path: &Path) -> io::Result<Self> {
        let absolute = absolute_path(path)?;
        require_absent(&absolute)?;
        let ancestor = nearest_existing_ancestor(&absolute)?;
        Ok(Self {
            path: EncodedOsString::from_path(&absolute),
            nearest_existing_ancestor: PathWitness::capture(&ancestor, WitnessFileType::Directory)?,
        })
    }

    pub fn validate(&self) -> Result<(), DirectValidationError> {
        self.validate_schema()?;
        self.nearest_existing_ancestor.validate(WitnessFileType::Directory)?;
        require_absent(&self.path.to_path_buf()).map_err(|source| {
            DirectValidationError::NegativeCandidateChanged {
                path: self.path.to_path_buf(),
                source,
            }
        })
    }

    fn validate_schema(&self) -> Result<(), DirectRecordError> {
        self.path.validate()?;
        if !self.path.to_path_buf().is_absolute() {
            return Err(DirectRecordError::NonAbsoluteResolvedPath);
        }
        self.nearest_existing_ancestor.validate_schema()?;
        if self.nearest_existing_ancestor.metadata.file_type != WitnessFileType::Directory {
            return Err(DirectRecordError::InvalidWitnessType);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionKind {
    Source,
    Include,
    ForcedInput,
    Module,
    Submodule,
    IntrinsicModule,
    ModuleOrInclude,
}

/// A selected input together with every earlier candidate that could shadow it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PositiveResolutionWitness {
    pub kind: ResolutionKind,
    pub requested_name: EncodedOsString,
    pub selected_input: usize,
    pub selected_path: PathWitness,
    pub earlier_candidates: Vec<AbsentPathWitness>,
}

/// An exact candidate that must remain absent even when no positive input was selected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeResolutionWitness {
    pub kind: ResolutionKind,
    pub requested_name: EncodedOsString,
    pub candidate: AbsentPathWitness,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResolutionWitnesses {
    pub roots: Vec<PathWitness>,
    pub positive: Vec<PositiveResolutionWitness>,
    pub negative: Vec<NegativeResolutionWitness>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerWitnessRef {
    pub context_key: DirectDigest,
    pub compiler_digest: DirectDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyMode {
    None,
    Md,
    Mmd,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepfileTargetShape {
    pub kind: DepfileTargetKind,
    pub bytes: EncodedOsString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepfileTargetKind {
    Ordinary,
    GeneratedModule,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepfilePrerequisiteShape {
    pub kind: DepfilePrerequisiteKind,
    pub bytes: EncodedOsString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepfilePrerequisiteKind {
    Ordinary,
    GeneratedModule,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepfileRuleShape {
    pub targets: Vec<DepfileTargetShape>,
    pub prerequisites: Vec<DepfilePrerequisiteShape>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepfileShape {
    pub mode: DependencyMode,
    pub destination: EncodedOsString,
    pub target_modifiers: Vec<EncodedOsString>,
    pub rules: Vec<DepfileRuleShape>,
    pub digest: DirectDigest,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PreprocessorShape {
    Inactive,
    CompilerObserved {
        stdout_digest: DirectDigest,
        stdout_size: u64,
        stderr_digest: DirectDigest,
        stderr_size: u64,
        automatic_lowercase_source: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedArtifact {
    pub kind: ArtifactKind,
    pub logical_name: String,
    pub destination: EncodedOsString,
    pub digest: DirectDigest,
    pub size: u64,
    pub mode: u32,
}

/// A complete compiler-authoritative observation associated with one action result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectRecord {
    pub schema_version: u32,
    pub compiler: CompilerWitnessRef,
    pub inputs: Vec<DirectInput>,
    pub resolution: SearchResolutionWitnesses,
    pub expected_artifacts: Vec<ExpectedArtifact>,
    pub probe_rules: Vec<DepfileRuleShape>,
    pub depfile: Option<DepfileShape>,
    pub preprocessor: PreprocessorShape,
    pub action_key: ActionKey,
}

impl DirectRecord {
    pub fn validate_schema(&self) -> Result<(), DirectRecordError> {
        if self.schema_version != DIRECT_RECORD_SCHEMA_VERSION {
            return Err(DirectRecordError::UnsupportedRecordSchema(self.schema_version));
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_DIRECT_INPUTS {
            return Err(DirectRecordError::InvalidInputCount);
        }
        if self.resolution.roots.len() > MAX_SEARCH_ROOTS {
            return Err(DirectRecordError::TooManySearchRoots);
        }
        let resolution_count = self
            .resolution
            .positive
            .iter()
            .try_fold(self.resolution.negative.len(), |count, witness| {
                count.checked_add(witness.earlier_candidates.len())
            })
            .ok_or(DirectRecordError::TooManyResolutionWitnesses)?;
        if resolution_count > MAX_RESOLUTION_WITNESSES {
            return Err(DirectRecordError::TooManyResolutionWitnesses);
        }
        if self.expected_artifacts.is_empty()
            || self.expected_artifacts.len() > MAX_EXPECTED_ARTIFACTS
        {
            return Err(DirectRecordError::InvalidArtifactCount);
        }
        for input in &self.inputs {
            input.validate_schema()?;
        }
        for root in &self.resolution.roots {
            root.validate_schema()?;
            if root.metadata.file_type != WitnessFileType::Directory {
                return Err(DirectRecordError::InvalidWitnessType);
            }
        }
        for positive in &self.resolution.positive {
            positive.requested_name.validate()?;
            if positive.selected_input >= self.inputs.len() {
                return Err(DirectRecordError::InvalidSelectedInput);
            }
            positive.selected_path.validate_schema()?;
            if positive.selected_path.metadata.file_type != WitnessFileType::Regular {
                return Err(DirectRecordError::InvalidWitnessType);
            }
            if positive.selected_path.canonical_path
                != self.inputs[positive.selected_input].path.canonical_path
            {
                return Err(DirectRecordError::InvalidSelectedInput);
            }
            for candidate in &positive.earlier_candidates {
                candidate.validate_schema()?;
            }
        }
        for negative in &self.resolution.negative {
            negative.requested_name.validate()?;
            negative.candidate.validate_schema()?;
        }
        self.validate_artifacts()?;
        validate_rule_shapes(&self.probe_rules)?;
        self.validate_resolution_coverage()?;
        self.validate_depfile()?;
        Ok(())
    }

    fn validate_resolution_coverage(&self) -> Result<(), DirectRecordError> {
        let mut positive_counts = HashMap::<&[u8], usize>::new();
        for witness in &self.resolution.positive {
            *positive_counts.entry(witness.requested_name.as_bytes()).or_default() += 1;
        }
        for prerequisite in self
            .probe_rules
            .iter()
            .flat_map(|rule| &rule.prerequisites)
            .filter(|prerequisite| prerequisite.kind == DepfilePrerequisiteKind::Ordinary)
        {
            let Some(count) = positive_counts.get_mut(prerequisite.bytes.as_bytes()) else {
                return Err(DirectRecordError::IncompleteResolutionProof);
            };
            if *count == 0 {
                return Err(DirectRecordError::IncompleteResolutionProof);
            }
            *count -= 1;
        }
        Ok(())
    }

    /// Validates all recorded inputs and namespace witnesses without executing a compiler.
    pub fn validate_filesystem(&self) -> Result<ValidatedDirectRecord<'_>, DirectValidationError> {
        self.validate_schema()?;
        self.validate_filesystem_once()?;
        Ok(ValidatedDirectRecord { record: self })
    }

    fn validate_filesystem_once(&self) -> Result<(), DirectValidationError> {
        for root in &self.resolution.roots {
            root.validate(WitnessFileType::Directory)?;
        }
        for input in &self.inputs {
            input.validate_contents()?;
        }
        for positive in &self.resolution.positive {
            positive.selected_path.validate(WitnessFileType::Regular)?;
            for candidate in &positive.earlier_candidates {
                candidate.validate()?;
            }
        }
        for negative in &self.resolution.negative {
            negative.candidate.validate()?;
        }
        Ok(())
    }

    fn validate_artifacts(&self) -> Result<(), DirectRecordError> {
        let mut names = HashSet::new();
        let mut destinations = HashSet::new();
        let mut object_count = 0;
        let mut dependency = None;
        for artifact in &self.expected_artifacts {
            if artifact.logical_name.len() > MAX_PATH_BYTES
                || validate_logical_name(&artifact.logical_name).is_err()
                || !names.insert(&artifact.logical_name)
            {
                return Err(DirectRecordError::InvalidArtifact);
            }
            artifact.destination.validate()?;
            let destination = artifact.destination.to_path_buf();
            if !destination.is_absolute() || !destinations.insert(destination) {
                return Err(DirectRecordError::InvalidArtifact);
            }
            match artifact.kind {
                ArtifactKind::Object => object_count += 1,
                ArtifactKind::Dependency => {
                    if dependency.replace(artifact).is_some() {
                        return Err(DirectRecordError::InvalidArtifact);
                    }
                }
                ArtifactKind::Module | ArtifactKind::Submodule => {}
            }
        }
        if object_count != 1 {
            return Err(DirectRecordError::InvalidArtifact);
        }
        match (&self.depfile, dependency) {
            (Some(depfile), Some(artifact))
                if depfile.mode != DependencyMode::None
                    && depfile.destination == artifact.destination
                    && depfile.digest == artifact.digest
                    && depfile.size == artifact.size =>
            {
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err(DirectRecordError::InvalidDepfile),
        }
    }

    fn validate_depfile(&self) -> Result<(), DirectRecordError> {
        if let PreprocessorShape::CompilerObserved { stdout_size, stderr_size, .. } =
            &self.preprocessor
        {
            if *stdout_size > MAX_OBSERVATION_BYTES as u64
                || *stderr_size > MAX_OBSERVATION_BYTES as u64
            {
                return Err(DirectRecordError::InvalidPreprocessor);
            }
        }
        let Some(depfile) = &self.depfile else {
            return Ok(());
        };
        depfile.destination.validate()?;
        if depfile.destination.as_bytes().is_empty() || depfile.size > MAX_OBSERVATION_BYTES as u64
        {
            return Err(DirectRecordError::InvalidDepfile);
        }
        let mut count = depfile.target_modifiers.len();
        for modifier in &depfile.target_modifiers {
            modifier.validate()?;
        }
        for rule in &depfile.rules {
            if rule.targets.is_empty() {
                return Err(DirectRecordError::InvalidDepfile);
            }
            count = count
                .checked_add(rule.targets.len())
                .and_then(|value| value.checked_add(rule.prerequisites.len()))
                .ok_or(DirectRecordError::InvalidDepfile)?;
            for target in &rule.targets {
                target.bytes.validate()?;
            }
            for prerequisite in &rule.prerequisites {
                prerequisite.bytes.validate()?;
            }
        }
        if count > MAX_RESOLUTION_WITNESSES {
            return Err(DirectRecordError::InvalidDepfile);
        }
        Ok(())
    }
}

fn validate_rule_shapes(rules: &[DepfileRuleShape]) -> Result<(), DirectRecordError> {
    let mut count = 0usize;
    for rule in rules {
        if rule.targets.is_empty() {
            return Err(DirectRecordError::InvalidDepfile);
        }
        count = count
            .checked_add(rule.targets.len())
            .and_then(|value| value.checked_add(rule.prerequisites.len()))
            .ok_or(DirectRecordError::InvalidDepfile)?;
        for target in &rule.targets {
            target.bytes.validate()?;
        }
        for prerequisite in &rule.prerequisites {
            prerequisite.bytes.validate()?;
        }
    }
    if count > MAX_RESOLUTION_WITNESSES {
        return Err(DirectRecordError::InvalidDepfile);
    }
    Ok(())
}

/// Proof token retained across staging so callers can close the validation TOCTOU window.
#[derive(Debug)]
pub struct ValidatedDirectRecord<'a> {
    record: &'a DirectRecord,
}

impl ValidatedDirectRecord<'_> {
    pub fn record(&self) -> &DirectRecord {
        self.record
    }

    /// Repeats all filesystem checks immediately before committing restored outputs.
    pub fn revalidate(&self) -> Result<(), DirectValidationError> {
        self.record.validate_filesystem_once()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirectRecordError {
    #[error("unsupported direct record schema version {0}")]
    UnsupportedRecordSchema(u32),
    #[error("direct path exceeds the size limit")]
    PathTooLong,
    #[error("direct path contains a NUL byte")]
    NulPath,
    #[error("resolved and canonical witness paths must be absolute")]
    NonAbsoluteResolvedPath,
    #[error("path witness has too many symlinks")]
    TooManySymlinks,
    #[error("path witness has an inconsistent file type")]
    InvalidWitnessType,
    #[error("direct record has an invalid input count")]
    InvalidInputCount,
    #[error("direct input is inconsistent with its path witness")]
    InvalidInput,
    #[error("direct record has too many search roots")]
    TooManySearchRoots,
    #[error("direct record has too many resolution witnesses")]
    TooManyResolutionWitnesses,
    #[error("positive resolution refers to an unknown input")]
    InvalidSelectedInput,
    #[error("direct record does not prove every compiler-observed prerequisite")]
    IncompleteResolutionProof,
    #[error("direct record has an invalid artifact count")]
    InvalidArtifactCount,
    #[error("direct record has a duplicate or invalid artifact")]
    InvalidArtifact,
    #[error("direct record has an invalid dependency-file shape")]
    InvalidDepfile,
    #[error("direct record has an invalid preprocessor observation")]
    InvalidPreprocessor,
    #[error("invalid hexadecimal digest")]
    InvalidDigest,
}

#[derive(Debug, thiserror::Error)]
pub enum DirectValidationError {
    #[error("invalid direct record: {0}")]
    Record(#[from] DirectRecordError),
    #[error("witnessed path changed: {0}")]
    WitnessChanged(PathBuf),
    #[error("witnessed input contents changed: {0}")]
    ContentChanged(PathBuf),
    #[error("could not validate witnessed path {path}: {source}")]
    PathChanged { path: PathBuf, source: io::Error },
    #[error("negative resolution candidate changed at {path}: {source}")]
    NegativeCandidateChanged { path: PathBuf, source: io::Error },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectMissReason {
    Missing,
    Oversized,
    Corrupt,
    UnsupportedSchema(u32),
    RequestKeyMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectLookup {
    pub candidates: Vec<DirectRecord>,
    pub missing_result_candidates: Vec<DirectRecord>,
    pub miss_reason: Option<DirectMissReason>,
}

impl DirectLookup {
    fn miss(reason: DirectMissReason) -> Self {
        Self {
            candidates: Vec::new(),
            missing_result_candidates: Vec::new(),
            miss_reason: Some(reason),
        }
    }

    pub fn is_miss(&self) -> bool {
        self.candidates.is_empty() && self.missing_result_candidates.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct DirectIndex {
    cache_root: PathBuf,
}

impl DirectIndex {
    /// Opens an index handle without creating or modifying cache state.
    pub fn open(cache_root: impl Into<PathBuf>) -> Self {
        Self { cache_root: cache_root.into() }
    }

    pub fn index_path(&self, request_key: &DirectRequestKey) -> PathBuf {
        let key = request_key.to_string();
        self.index_root().join(&key[..2]).join(format!("{key}.json"))
    }

    /// Loads candidates without creating directories, touching timestamps, or pruning entries.
    pub fn lookup(&self, request_key: &DirectRequestKey) -> io::Result<DirectLookup> {
        self.lookup_with_manifest_check(request_key, |_| true)
    }

    /// Separates candidates whose result manifest is absent without discarding their observation.
    pub fn lookup_with_manifest_check<F>(
        &self,
        request_key: &DirectRequestKey,
        mut manifest_exists: F,
    ) -> io::Result<DirectLookup>
    where
        F: FnMut(&ActionKey) -> bool,
    {
        let loaded = self.load_file(request_key)?;
        let mut file = match loaded {
            LoadedIndex::File(file) => file,
            LoadedIndex::Miss(reason) => return Ok(DirectLookup::miss(reason)),
        };
        let mut missing_result_candidates = Vec::new();
        file.candidates.retain(|candidate| {
            if manifest_exists(&candidate.action_key) {
                true
            } else {
                missing_result_candidates.push(candidate.clone());
                false
            }
        });
        Ok(DirectLookup {
            candidates: file.candidates,
            missing_result_candidates,
            miss_reason: None,
        })
    }

    /// Atomically adds the most recent observation while retaining at most four candidates.
    pub fn publish(
        &self,
        request_key: DirectRequestKey,
        record: DirectRecord,
    ) -> Result<(), DirectIndexError> {
        self.publish_with_manifest_check(request_key, record, |_| true)
    }

    /// Lazily drops candidates whose result manifests disappeared during a later publication.
    pub fn publish_with_manifest_check<F>(
        &self,
        request_key: DirectRequestKey,
        record: DirectRecord,
        mut manifest_exists: F,
    ) -> Result<(), DirectIndexError>
    where
        F: FnMut(&ActionKey) -> bool,
    {
        record.validate_schema()?;
        self.create_directories()?;
        let _lock = self.lock(&request_key)?;
        let mut candidates = match self.load_file(&request_key)? {
            LoadedIndex::File(file) => file.candidates,
            LoadedIndex::Miss(_) => Vec::new(),
        };
        candidates.retain(|candidate| {
            candidate.action_key != record.action_key && manifest_exists(&candidate.action_key)
        });
        candidates.insert(0, record);
        candidates.truncate(MAX_DIRECT_CANDIDATES);
        let mut file = DirectIndexFile {
            schema_version: DIRECT_INDEX_SCHEMA_VERSION,
            request_key,
            candidates,
            checksum: DirectDigest::from_bytes([0; 32]),
        };
        file.checksum = file.calculate_checksum()?;
        let bytes = file.to_json()?;
        let destination = self.index_path(&request_key);
        let parent = destination.parent().expect("direct index shard");
        create_real_directory(parent)?;
        reject_symlink_file(&destination)?;
        let mut temporary = NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&destination).map_err(|error| error.error)?;
        sync_directory(parent)?;
        Ok(())
    }

    fn load_file(&self, request_key: &DirectRequestKey) -> io::Result<LoadedIndex> {
        if !self.validate_existing_directories(request_key)? {
            return Ok(LoadedIndex::Miss(DirectMissReason::Missing));
        }
        let path = self.index_path(request_key);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(LoadedIndex::Miss(DirectMissReason::Missing));
            }
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Ok(LoadedIndex::Miss(DirectMissReason::Corrupt));
        }
        if metadata.len() > MAX_DIRECT_INDEX_SIZE as u64 {
            return Ok(LoadedIndex::Miss(DirectMissReason::Oversized));
        }
        let bytes = fs::read(path)?;
        match DirectIndexFile::from_json(&bytes, request_key) {
            Ok(file) => Ok(LoadedIndex::File(file)),
            Err(DirectIndexDecodeError::UnsupportedSchema(version)) => {
                Ok(LoadedIndex::Miss(DirectMissReason::UnsupportedSchema(version)))
            }
            Err(DirectIndexDecodeError::RequestKeyMismatch) => {
                Ok(LoadedIndex::Miss(DirectMissReason::RequestKeyMismatch))
            }
            Err(DirectIndexDecodeError::Oversized) => {
                Ok(LoadedIndex::Miss(DirectMissReason::Oversized))
            }
            Err(DirectIndexDecodeError::Corrupt) => {
                Ok(LoadedIndex::Miss(DirectMissReason::Corrupt))
            }
        }
    }

    fn create_directories(&self) -> io::Result<()> {
        create_real_directory(&self.cache_root)?;
        create_real_directory(&self.cache_root.join("v1"))?;
        create_real_directory(&self.direct_root())?;
        create_real_directory(&self.index_root())?;
        create_real_directory(&self.lock_root())
    }

    fn validate_existing_directories(&self, request_key: &DirectRequestKey) -> io::Result<bool> {
        for path in [
            self.cache_root.clone(),
            self.cache_root.join("v1"),
            self.direct_root(),
            self.index_root(),
            self.index_path(request_key).parent().expect("direct index shard").to_path_buf(),
        ] {
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("direct cache path is not a real directory: {}", path.display()),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    fn lock(&self, request_key: &DirectRequestKey) -> io::Result<File> {
        let path = self.lock_root().join(request_key.to_string());
        reject_symlink_file(&path)?;
        let file =
            OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path)?;
        FileExt::lock(&file)?;
        Ok(file)
    }

    fn direct_root(&self) -> PathBuf {
        self.cache_root.join("v1/direct")
    }

    fn index_root(&self) -> PathBuf {
        self.direct_root().join("index")
    }

    fn lock_root(&self) -> PathBuf {
        self.direct_root().join("locks")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirectIndexError {
    #[error("invalid direct record: {0}")]
    Record(#[from] DirectRecordError),
    #[error("direct index I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("direct index serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("direct index exceeds the size limit")]
    TooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectIndexFile {
    schema_version: u32,
    request_key: DirectRequestKey,
    candidates: Vec<DirectRecord>,
    checksum: DirectDigest,
}

impl DirectIndexFile {
    fn to_json(&self) -> Result<Vec<u8>, DirectIndexError> {
        self.validate(self.request_key).map_err(|_| DirectIndexError::TooLarge)?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_DIRECT_INDEX_SIZE {
            return Err(DirectIndexError::TooLarge);
        }
        Ok(bytes)
    }

    fn from_json(
        bytes: &[u8],
        expected_key: &DirectRequestKey,
    ) -> Result<Self, DirectIndexDecodeError> {
        if bytes.len() > MAX_DIRECT_INDEX_SIZE {
            return Err(DirectIndexDecodeError::Oversized);
        }
        let envelope: IndexEnvelope =
            serde_json::from_slice(bytes).map_err(|_| DirectIndexDecodeError::Corrupt)?;
        if envelope.schema_version != DIRECT_INDEX_SCHEMA_VERSION {
            return Err(DirectIndexDecodeError::UnsupportedSchema(envelope.schema_version));
        }
        let file: Self =
            serde_json::from_slice(bytes).map_err(|_| DirectIndexDecodeError::Corrupt)?;
        file.validate(*expected_key)?;
        Ok(file)
    }

    fn validate(&self, expected_key: DirectRequestKey) -> Result<(), DirectIndexDecodeError> {
        if self.schema_version != DIRECT_INDEX_SCHEMA_VERSION {
            return Err(DirectIndexDecodeError::UnsupportedSchema(self.schema_version));
        }
        if self.request_key != expected_key {
            return Err(DirectIndexDecodeError::RequestKeyMismatch);
        }
        let checksum = self.calculate_checksum().map_err(|_| DirectIndexDecodeError::Corrupt)?;
        if checksum != self.checksum {
            return Err(DirectIndexDecodeError::Corrupt);
        }
        if self.candidates.is_empty() || self.candidates.len() > MAX_DIRECT_CANDIDATES {
            return Err(DirectIndexDecodeError::Corrupt);
        }
        let mut actions = HashSet::new();
        for candidate in &self.candidates {
            candidate.validate_schema().map_err(|_| DirectIndexDecodeError::Corrupt)?;
            if !actions.insert(candidate.action_key) {
                return Err(DirectIndexDecodeError::Corrupt);
            }
        }
        Ok(())
    }

    fn calculate_checksum(&self) -> Result<DirectDigest, serde_json::Error> {
        #[derive(Serialize)]
        struct IntegrityPayload<'a> {
            schema_version: u32,
            request_key: DirectRequestKey,
            candidates: &'a [DirectRecord],
        }

        let payload = IntegrityPayload {
            schema_version: self.schema_version,
            request_key: self.request_key,
            candidates: &self.candidates,
        };
        serde_json::to_vec(&payload).map(|bytes| DirectDigest::hash(&bytes))
    }
}

#[derive(Deserialize)]
struct IndexEnvelope {
    schema_version: u32,
}

enum LoadedIndex {
    File(DirectIndexFile),
    Miss(DirectMissReason),
}

#[derive(Debug)]
enum DirectIndexDecodeError {
    UnsupportedSchema(u32),
    RequestKeyMismatch,
    Oversized,
    Corrupt,
}

fn hash_stable_regular_file(path: &PathWitness) -> io::Result<(DirectDigest, u64)> {
    let resolved = path.resolved_path.to_path_buf();
    let mut file = File::open(&resolved)?;
    let before = file.metadata()?;
    ensure_file_type(&before, WitnessFileType::Regular, &resolved)?;
    let before_witness = MetadataWitness::capture(&before, WitnessFileType::Regular);
    let mut hasher = blake3::Hasher::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "input is too large"))?;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    let named_after = fs::metadata(&resolved)?;
    if MetadataWitness::capture(&after, WitnessFileType::Regular) != before_witness
        || MetadataWitness::capture(&named_after, WitnessFileType::Regular) != before_witness
        || size != before.len()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "input changed while it was read"));
    }
    Ok((DirectDigest::from_bytes(*hasher.finalize().as_bytes()), size))
}

fn capture_symlinks(path: &Path) -> io::Result<Vec<SymlinkWitness>> {
    let mut current = PathBuf::new();
    let mut symlinks = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {
                current.push(component.as_os_str());
            }
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            symlinks.push(SymlinkWitness {
                path: EncodedOsString::from_path(&current),
                target: EncodedOsString::from_path(&fs::read_link(&current)?),
                metadata: MetadataWitness::capture(&metadata, WitnessFileType::Symlink),
            });
        }
    }
    if symlinks.len() > MAX_SYMLINKS_PER_PATH {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too many symlinks in path"));
    }
    Ok(symlinks)
}

fn nearest_existing_ancestor(path: &Path) -> io::Result<PathBuf> {
    let mut candidate = path.parent();
    while let Some(value) = candidate {
        match fs::metadata(value) {
            Ok(metadata) if metadata.file_type().is_dir() => return Ok(value.to_path_buf()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        candidate = value.parent();
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no existing ancestor"))
}

fn require_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "negative resolution candidate now exists",
        )),
    }
}

fn ensure_file_type(
    metadata: &fs::Metadata,
    expected: WitnessFileType,
    path: &Path,
) -> io::Result<()> {
    let matches = match expected {
        WitnessFileType::Regular => metadata.file_type().is_file(),
        WitnessFileType::Directory => metadata.file_type().is_dir(),
        WitnessFileType::Symlink => metadata.file_type().is_symlink(),
    };
    if matches {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected file type for {}", path.display()),
        ))
    }
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn create_real_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    if fs::symlink_metadata(path)?.file_type().is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("direct cache path is not a real directory: {}", path.display()),
        ))
    }
}

fn reject_symlink_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("direct cache file is a symlink: {}", path.display()),
        )),
        Ok(metadata) if !metadata.file_type().is_file() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("direct cache path is not a file: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    Ok(())
}

fn hash_frame(hasher: &mut blake3::Hasher, tag: u8, bytes: &[u8]) {
    hasher.update(&[tag]);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, &'static str> {
    if value.len() % 2 != 0 {
        return Err("hexadecimal value has an odd length");
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("hexadecimal value must use lowercase ASCII digits"),
    }
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
fn os_string(value: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(value.to_vec())
}

#[cfg(not(unix))]
fn os_string(value: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(value).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::key::ActionKeyBuilder;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn action(number: u8) -> ActionKey {
        ActionKeyBuilder::new().bytes("action", [number]).finish().unwrap()
    }

    fn record(root: &Path, number: u8) -> DirectRecord {
        let source = root.join(format!("source-{number}.f90"));
        fs::write(&source, format!("program p{number}\nend\n")).unwrap();
        let input = DirectInput::capture(source.as_os_str(), &source).unwrap();
        DirectRecord {
            schema_version: DIRECT_RECORD_SCHEMA_VERSION,
            compiler: CompilerWitnessRef {
                context_key: DirectDigest::hash(b"context"),
                compiler_digest: DirectDigest::hash(b"compiler"),
            },
            inputs: vec![input],
            resolution: SearchResolutionWitnesses {
                roots: vec![PathWitness::capture(root, WitnessFileType::Directory).unwrap()],
                positive: Vec::new(),
                negative: Vec::new(),
            },
            expected_artifacts: vec![ExpectedArtifact {
                kind: ArtifactKind::Object,
                logical_name: "object".into(),
                destination: EncodedOsString::from_path(&root.join(format!("result-{number}.o"))),
                digest: DirectDigest::hash(&[number]),
                size: 1,
                mode: 0o644,
            }],
            probe_rules: Vec::new(),
            depfile: None,
            preprocessor: PreprocessorShape::Inactive,
            action_key: action(number),
        }
    }

    fn request(number: u8) -> DirectRequestKey {
        DirectRequestKey::compute(
            OsStr::new("gfortran"),
            Path::new("/build"),
            &[OsString::from("-c"), OsString::from(format!("source-{number}.f90"))],
            &[(OsString::from("PATH"), OsString::from("/usr/bin"))],
            Path::new("/build/source.f90"),
            DirectDigest::hash(&[number]),
            &[(b"module-dir".to_vec(), b"/build/modules".to_vec())],
        )
    }

    #[test]
    fn request_key_preserves_argument_and_environment_order() {
        let source = DirectDigest::hash(b"source");
        let first = DirectRequestKey::compute(
            OsStr::new("gfortran"),
            Path::new("/build"),
            &[OsString::from("-O2"), OsString::from("-g")],
            &[(OsString::from("A"), OsString::from("1"))],
            Path::new("/build/x.f90"),
            source,
            &[],
        );
        let reordered = DirectRequestKey::compute(
            OsStr::new("gfortran"),
            Path::new("/build"),
            &[OsString::from("-g"), OsString::from("-O2")],
            &[(OsString::from("A"), OsString::from("1"))],
            Path::new("/build/x.f90"),
            source,
            &[],
        );
        assert_ne!(first, reordered);
    }

    #[cfg(unix)]
    #[test]
    fn encoded_paths_round_trip_non_utf8_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let original = OsString::from_vec(b"source-\xff.f90".to_vec());
        let encoded = EncodedOsString::from_os_str(&original);
        let json = serde_json::to_vec(&encoded).unwrap();
        let decoded: EncodedOsString = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.to_os_string().as_bytes(), original.as_bytes());
    }

    #[test]
    fn lookup_does_not_create_cache_directories() {
        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join("missing");
        let lookup = DirectIndex::open(&cache).lookup(&request(1)).unwrap();
        assert_eq!(lookup.miss_reason, Some(DirectMissReason::Missing));
        assert!(!cache.exists());
    }

    #[test]
    fn publication_retains_only_four_recent_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let sources = tempfile::tempdir().unwrap();
        let index = DirectIndex::open(directory.path());
        let key = request(1);
        for number in 0..6 {
            index.publish(key, record(sources.path(), number)).unwrap();
        }
        let lookup = index.lookup(&key).unwrap();
        assert_eq!(lookup.candidates.len(), MAX_DIRECT_CANDIDATES);
        assert_eq!(
            lookup.candidates.iter().map(|value| value.action_key).collect::<Vec<_>>(),
            vec![action(5), action(4), action(3), action(2)]
        );
    }

    #[test]
    fn corrupt_and_stale_indexes_are_misses() {
        let directory = tempfile::tempdir().unwrap();
        let sources = tempfile::tempdir().unwrap();
        let index = DirectIndex::open(directory.path());
        let key = request(1);
        index.publish(key, record(sources.path(), 1)).unwrap();
        let path = index.index_path(&key);
        fs::write(&path, b"not json").unwrap();
        assert_eq!(index.lookup(&key).unwrap().miss_reason, Some(DirectMissReason::Corrupt));
        fs::write(&path, br#"{"schema_version":999}"#).unwrap();
        assert_eq!(
            index.lookup(&key).unwrap().miss_reason,
            Some(DirectMissReason::UnsupportedSchema(999))
        );
    }

    #[test]
    fn checksum_rejects_structurally_valid_direct_record_modification() {
        let directory = tempfile::tempdir().unwrap();
        let sources = tempfile::tempdir().unwrap();
        let index = DirectIndex::open(directory.path());
        let key = request(1);
        index.publish(key, record(sources.path(), 1)).unwrap();
        let path = index.index_path(&key);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["candidates"][0]["expected_artifacts"][0]["mode"] = 0o600.into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(index.lookup(&key).unwrap().miss_reason, Some(DirectMissReason::Corrupt));
    }

    #[test]
    fn missing_result_candidates_are_preserved_without_writing() {
        let directory = tempfile::tempdir().unwrap();
        let sources = tempfile::tempdir().unwrap();
        let index = DirectIndex::open(directory.path());
        let key = request(1);
        index.publish(key, record(sources.path(), 1)).unwrap();
        index.publish(key, record(sources.path(), 2)).unwrap();
        let before = fs::read(index.index_path(&key)).unwrap();
        let lookup =
            index.lookup_with_manifest_check(&key, |action_key| *action_key == action(2)).unwrap();
        assert_eq!(lookup.candidates.len(), 1);
        assert_eq!(lookup.missing_result_candidates.len(), 1);
        assert_eq!(lookup.missing_result_candidates[0].action_key, action(1));
        assert_eq!(fs::read(index.index_path(&key)).unwrap(), before);
    }

    #[test]
    fn concurrent_publication_does_not_lose_candidates() {
        let directory = tempfile::tempdir().unwrap();
        let sources = tempfile::tempdir().unwrap();
        let index = Arc::new(DirectIndex::open(directory.path()));
        let barrier = Arc::new(Barrier::new(4));
        let key = request(1);
        let mut threads = Vec::new();
        for number in 0..4 {
            let index = Arc::clone(&index);
            let barrier = Arc::clone(&barrier);
            let value = record(sources.path(), number);
            threads.push(thread::spawn(move || {
                barrier.wait();
                index.publish(key, value).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let actions = index
            .lookup(&key)
            .unwrap()
            .candidates
            .into_iter()
            .map(|value| value.action_key)
            .collect::<HashSet<_>>();
        assert_eq!(actions, (0..4).map(action).collect());
    }

    #[test]
    fn content_and_negative_witness_changes_fail_validation() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.f90");
        fs::write(&source, b"program p\nend\n").unwrap();
        let input = DirectInput::capture(source.as_os_str(), &source).unwrap();
        input.validate_contents().unwrap();
        fs::write(&source, b"program changed\nend\n").unwrap();
        assert!(input.validate_contents().is_err());

        let candidate = directory.path().join("shadow.mod");
        let absent = AbsentPathWitness::capture(&candidate).unwrap();
        absent.validate().unwrap();
        fs::write(&candidate, b"module").unwrap();
        assert!(absent.validate().is_err());
    }

    #[test]
    fn unrelated_directory_entries_do_not_invalidate_search_root_identity() {
        let directory = tempfile::tempdir().unwrap();
        let witness = PathWitness::capture(directory.path(), WitnessFileType::Directory).unwrap();
        let absent = AbsentPathWitness::capture(&directory.path().join("wanted.mod")).unwrap();
        fs::write(directory.path().join("unrelated.mod"), b"module").unwrap();
        witness.validate(WitnessFileType::Directory).unwrap();
        absent.validate().unwrap();
    }

    #[test]
    fn recreated_search_root_keeps_exact_absence_witness_valid() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("modules");
        fs::create_dir(&root).unwrap();
        let witness = PathWitness::capture(&root, WitnessFileType::Directory).unwrap();
        let candidate = root.join("wanted.mod");
        let absent = AbsentPathWitness::capture(&candidate).unwrap();

        fs::remove_dir(&root).unwrap();
        fs::create_dir(&root).unwrap();

        witness.validate(WitnessFileType::Directory).unwrap();
        absent.validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn same_content_atomic_input_replacement_remains_valid() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.f90");
        fs::write(&source, b"program p\nend\n").unwrap();
        let input = DirectInput::capture(source.as_os_str(), &source).unwrap();
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"program p\nend\n").unwrap();
        fs::rename(replacement, &source).unwrap();
        input.validate_contents().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_retargeting_fails_revalidation() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::write(&first, b"same").unwrap();
        fs::write(&second, b"same").unwrap();
        let link = directory.path().join("source");
        symlink(&first, &link).unwrap();
        let input = DirectInput::capture(link.as_os_str(), &link).unwrap();
        input.validate_contents().unwrap();
        fs::remove_file(&link).unwrap();
        symlink(&second, &link).unwrap();
        assert!(input.validate_contents().is_err());
    }

    #[test]
    fn validation_token_rechecks_after_staging_window() {
        let directory = tempfile::tempdir().unwrap();
        let value = record(directory.path(), 1);
        let validated = value.validate_filesystem().unwrap();
        fs::write(directory.path().join("source-1.f90"), b"changed").unwrap();
        assert!(validated.revalidate().is_err());
    }
}
