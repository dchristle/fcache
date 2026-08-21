//! Cache action-key construction.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;

/// The version of the wire format used by [`ActionKeyBuilder`].
pub const ACTION_KEY_VERSION: u8 = 1;

/// A hexadecimal BLAKE3 action key.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionKey([u8; 32]);

impl ActionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.to_string()
    }

    pub fn parse(value: &str) -> Result<Self, KeyError> {
        if value.len() != 64 {
            return Err(KeyError::InvalidHex);
        }
        let mut out = [0; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            out[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for ActionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ActionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ActionKey").field(&self.to_string()).finish()
    }
}

impl AsRef<[u8]> for ActionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for ActionKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for ActionKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum KeyError {
    #[error("action key must contain 64 hexadecimal characters")]
    InvalidHex,
    #[error("action key field names must not be empty")]
    EmptyName,
}

/// Constructs an action key from typed, length-framed named fields.
///
/// Fields are hashed in insertion order so repeated arguments and search paths retain
/// their compiler-visible ordering.
#[derive(Clone, Debug, Default)]
pub struct ActionKeyBuilder {
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ActionKeyBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field<N: AsRef<[u8]>, V: AsRef<[u8]>>(mut self, name: N, value: V) -> Self {
        self.fields.push((name.as_ref().to_vec(), value.as_ref().to_vec()));
        self
    }

    pub fn add_field<N: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, name: N, value: V) -> &mut Self {
        self.fields.push((name.as_ref().to_vec(), value.as_ref().to_vec()));
        self
    }

    pub fn bytes<V: AsRef<[u8]>>(self, name: &str, value: V) -> Self {
        self.field(name.as_bytes(), value)
    }
    pub fn add_bytes<V: AsRef<[u8]>>(&mut self, name: &str, value: V) -> &mut Self {
        self.add_field(name.as_bytes(), value)
    }

    pub fn os_str(self, name: &str, value: &OsStr) -> Self {
        self.field(name.as_bytes(), os_bytes(value))
    }
    pub fn add_os_str(&mut self, name: &str, value: &OsStr) -> &mut Self {
        self.add_field(name.as_bytes(), os_bytes(value))
    }
    pub fn path(self, name: &str, value: &Path) -> Self {
        self.field(name.as_bytes(), os_bytes(value.as_os_str()))
    }
    pub fn add_path(&mut self, name: &str, value: &Path) -> &mut Self {
        self.add_field(name.as_bytes(), os_bytes(value.as_os_str()))
    }

    pub fn finish(self) -> Result<ActionKey, KeyError> {
        if self.fields.iter().any(|(name, _)| name.is_empty()) {
            return Err(KeyError::EmptyName);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fcache.action-key\0");
        hasher.update(&[ACTION_KEY_VERSION]);
        for (name, value) in self.fields {
            frame(&mut hasher, 0x01, &name);
            frame(&mut hasher, 0x02, &value);
        }
        Ok(ActionKey(*hasher.finalize().as_bytes()))
    }

    pub fn build(self) -> Result<ActionKey, KeyError> {
        self.finish()
    }
}

fn frame(hasher: &mut blake3::Hasher, tag: u8, bytes: &[u8]) {
    hasher.update(&[tag]);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_nibble(value: u8) -> Result<u8, KeyError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(KeyError::InvalidHex),
    }
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    std::os::unix::ffi::OsStrExt::as_bytes(value).to_vec()
}
#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

impl From<ActionKey> for OsString {
    fn from(value: ActionKey) -> Self {
        OsString::from(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_prevents_delimiter_collisions() {
        let a = ActionKeyBuilder::new().bytes("a", b"bc").bytes("ab", b"c").finish().unwrap();
        let b = ActionKeyBuilder::new().bytes("a", b"b").bytes("cab", b"").finish().unwrap();
        assert_ne!(a, b);
        assert_ne!(
            ActionKeyBuilder::new().bytes("x", b"1").bytes("y", b"2").finish().unwrap(),
            ActionKeyBuilder::new().bytes("y", b"2").bytes("x", b"1").finish().unwrap()
        );
    }
}
