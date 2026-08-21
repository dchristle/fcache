//! Versioned cache result manifests.

use crate::cache::key::ActionKey;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_ARTIFACTS: usize = 256;
pub const MAX_BLOB_SIZE: u64 = 1 << 30;
pub const MAX_TOTAL_BLOB_SIZE: u64 = 2 << 30;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("unsupported manifest schema version {0}")]
    UnsupportedSchema(u32),
    #[error("manifest JSON is too large")]
    TooLarge,
    #[error("manifest has too many artifacts")]
    TooManyArtifacts,
    #[error("manifest contains duplicate artifact {0}")]
    DuplicateArtifact(String),
    #[error("unsafe logical destination {0}")]
    UnsafeName(String),
    #[error("invalid blob digest")]
    InvalidDigest,
    #[error("blob size exceeds the manifest limit")]
    BlobTooLarge,
    #[error("manifest total blob size exceeds the limit")]
    TotalBlobTooLarge,
    #[error("manifest must describe a successful compilation")]
    NonZeroExit,
    #[error("artifact kind and destination role do not agree for {0}")]
    InconsistentArtifact(String),
    #[error("manifest contains more than one object artifact")]
    MultipleObjectArtifacts,
    #[error("manifest contains more than one dependency artifact")]
    MultipleDependencyArtifacts,
    #[error("invalid manifest JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    Object,
    Module,
    Submodule,
    Dependency,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DestinationRole {
    Object,
    Module,
    Submodule,
    Dependency,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    pub digest: String,
    pub size: u64,
    #[serde(default = "default_mode")]
    pub mode: u32,
}

impl BlobRef {
    pub fn new(digest: impl Into<String>, size: u64, mode: u32) -> Self {
        Self { digest: digest.into(), size, mode }
    }
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.digest.len() != 64
            || self.digest.bytes().any(|b| !b.is_ascii_hexdigit())
            || self.digest != self.digest.to_ascii_lowercase()
        {
            return Err(ManifestError::InvalidDigest);
        }
        if self.size > MAX_BLOB_SIZE {
            return Err(ManifestError::BlobTooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub logical_name: String,
    pub destination_role: DestinationRole,
    pub blob: BlobRef,
}

impl Artifact {
    pub fn new(
        kind: ArtifactKind,
        logical_name: impl Into<String>,
        destination_role: DestinationRole,
        blob: BlobRef,
    ) -> Self {
        Self { kind, logical_name: logical_name.into(), destination_role, blob }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub action_key: ActionKey,
    pub compiler_digest: String,
    pub artifacts: Vec<Artifact>,
    pub stdout: BlobRef,
    pub stderr: BlobRef,
    pub exit_code: i32,
}

impl Manifest {
    pub fn new(
        action_key: ActionKey,
        compiler_digest: impl Into<String>,
        artifacts: Vec<Artifact>,
        stdout: BlobRef,
        stderr: BlobRef,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            action_key,
            compiler_digest: compiler_digest.into(),
            artifacts,
            stdout,
            stderr,
            exit_code: 0,
        }
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchema(self.schema_version));
        }
        if self.exit_code != 0 {
            return Err(ManifestError::NonZeroExit);
        }
        if self.compiler_digest.len() != 64
            || self.compiler_digest.bytes().any(|b| !b.is_ascii_hexdigit())
            || self.compiler_digest != self.compiler_digest.to_ascii_lowercase()
        {
            return Err(ManifestError::InvalidDigest);
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(ManifestError::TooManyArtifacts);
        }
        let mut total = self.stdout.size.saturating_add(self.stderr.size);
        self.stdout.validate()?;
        self.stderr.validate()?;
        let mut seen = std::collections::HashSet::new();
        let mut object_count = 0;
        let mut dependency_count = 0;
        for artifact in &self.artifacts {
            validate_logical_name(&artifact.logical_name)?;
            if !seen.insert(&artifact.logical_name) {
                return Err(ManifestError::DuplicateArtifact(artifact.logical_name.clone()));
            }
            if !artifact_kind_matches_role(&artifact.kind, &artifact.destination_role) {
                return Err(ManifestError::InconsistentArtifact(artifact.logical_name.clone()));
            }
            match &artifact.destination_role {
                DestinationRole::Object => object_count += 1,
                DestinationRole::Dependency => dependency_count += 1,
                DestinationRole::Module | DestinationRole::Submodule => {}
            }
            artifact.blob.validate()?;
            total = total.saturating_add(artifact.blob.size);
        }
        if object_count > 1 {
            return Err(ManifestError::MultipleObjectArtifacts);
        }
        if dependency_count > 1 {
            return Err(ManifestError::MultipleDependencyArtifacts);
        }
        if total > MAX_TOTAL_BLOB_SIZE {
            return Err(ManifestError::TotalBlobTooLarge);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ManifestError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(ManifestError::TooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

fn artifact_kind_matches_role(kind: &ArtifactKind, role: &DestinationRole) -> bool {
    matches!(
        (kind, role),
        (ArtifactKind::Object, DestinationRole::Object)
            | (ArtifactKind::Module, DestinationRole::Module)
            | (ArtifactKind::Submodule, DestinationRole::Submodule)
            | (ArtifactKind::Dependency, DestinationRole::Dependency)
    )
}

pub fn validate_logical_name(name: &str) -> Result<(), ManifestError> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains('\0')
        || name.contains('/')
        || name.contains('\\')
        || path.is_absolute()
        || name.starts_with("\\\\")
    {
        return Err(ManifestError::UnsafeName(name.to_owned()));
    }
    if path.components().any(|component| {
        matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_))
    }) || name == "."
        || name == ".."
    {
        return Err(ManifestError::UnsafeName(name.to_owned()));
    }
    Ok(())
}

fn default_mode() -> u32 {
    0o644
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::key::ActionKeyBuilder;
    fn manifest() -> Manifest {
        Manifest::new(
            ActionKeyBuilder::new().bytes("x", b"y").finish().unwrap(),
            "a".repeat(64),
            vec![],
            BlobRef::new("b".repeat(64), 0, 0o644),
            BlobRef::new("c".repeat(64), 0, 0o644),
        )
    }
    #[test]
    fn rejects_traversal() {
        assert!(validate_logical_name("../x").is_err());
        assert!(validate_logical_name("/tmp/x").is_err());
    }
    #[test]
    fn round_trips_versioned_json() {
        let value = manifest();
        assert_eq!(Manifest::from_json(&value.to_json().unwrap()).unwrap(), value);
    }

    #[test]
    fn rejects_inconsistent_artifact_roles() {
        let mut value = manifest();
        value.artifacts.push(Artifact::new(
            ArtifactKind::Object,
            "object",
            DestinationRole::Module,
            BlobRef::new("d".repeat(64), 1, 0o644),
        ));
        assert!(matches!(value.validate(), Err(ManifestError::InconsistentArtifact(_))));
    }

    #[test]
    fn permits_artifact_bundles_without_an_object() {
        let mut value = manifest();
        value.artifacts.push(Artifact::new(
            ArtifactKind::Module,
            "module:x.mod",
            DestinationRole::Module,
            BlobRef::new("d".repeat(64), 1, 0o644),
        ));
        assert!(value.validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_singleton_roles() {
        let mut value = manifest();
        value.artifacts.extend([
            Artifact::new(
                ArtifactKind::Object,
                "object:first",
                DestinationRole::Object,
                BlobRef::new("d".repeat(64), 1, 0o644),
            ),
            Artifact::new(
                ArtifactKind::Object,
                "object:second",
                DestinationRole::Object,
                BlobRef::new("e".repeat(64), 1, 0o644),
            ),
        ]);
        assert!(matches!(value.validate(), Err(ManifestError::MultipleObjectArtifacts)));
    }
}
