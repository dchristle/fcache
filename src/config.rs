//! Configuration loading and validation.

use directories::BaseDirs;
use serde::Deserialize;
use std::{env, ffi::OsString, fs, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub cache_dir: PathBuf,
    pub max_size: u64,
    pub enabled: bool,
    pub read_only: bool,
    pub direct: bool,
    pub compiler_identity: CompilerIdentityPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerIdentityPolicy {
    Auto,
    Strict,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot determine platform cache directory")]
    NoCacheDirectory,
    #[error("cannot read config file {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("invalid config file {path}: {source}")]
    Toml { path: PathBuf, source: toml::de::Error },
    #[error("invalid {0}: {1}")]
    Value(String, String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    dir: Option<PathBuf>,
    max_size: Option<String>,
    enabled: Option<bool>,
    read_only: Option<bool>,
    direct: Option<bool>,
    compiler_identity: Option<String>,
}

impl Config {
    pub fn defaults() -> Result<Self, ConfigError> {
        let cache_dir = BaseDirs::new()
            .map(|b| b.cache_dir().join("fcache"))
            .ok_or(ConfigError::NoCacheDirectory)?;
        Ok(Self {
            cache_dir,
            max_size: 10 * 1024 * 1024 * 1024,
            enabled: true,
            read_only: false,
            direct: true,
            compiler_identity: CompilerIdentityPolicy::Auto,
        })
    }

    pub fn load() -> Result<Self, ConfigError> {
        Self::load_with(
            |name| env::var_os(name),
            Self::config_path().unwrap_or_else(|| PathBuf::from("fcache.toml")),
        )
    }

    fn load_with<F>(get_env: F, default_config_path: PathBuf) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let mut c = Self::defaults()?;
        let selected_path = get_env("FCACHE_CONFIG").map(PathBuf::from);
        let path = selected_path.clone().unwrap_or(default_config_path);
        if selected_path.is_some() || path.exists() {
            let text = fs::read_to_string(&path)
                .map_err(|source| ConfigError::Read { path: path.clone(), source })?;
            let f: FileConfig = toml::from_str(&text)
                .map_err(|source| ConfigError::Toml { path: path.clone(), source })?;
            if let Some(v) = f.dir {
                c.cache_dir = v;
            }
            if let Some(v) = f.max_size {
                c.max_size = parse_size(&v, "max_size")?;
            }
            if let Some(v) = f.enabled {
                c.enabled = v;
            }
            if let Some(v) = f.read_only {
                c.read_only = v;
            }
            if let Some(v) = f.direct {
                c.direct = v;
            }
            if let Some(v) = f.compiler_identity {
                c.compiler_identity = parse_compiler_identity(&v, "compiler_identity")?;
            }
        }
        if let Some(v) = get_env("FCACHE_DIR") {
            c.cache_dir = PathBuf::from(v);
        }
        if let Some(v) = get_env("FCACHE_MAX_SIZE") {
            c.max_size = parse_size_os(v, "FCACHE_MAX_SIZE")?;
        }
        if let Some(disabled) = parse_bool_value("FCACHE_DISABLE", get_env("FCACHE_DISABLE"))? {
            c.enabled = !disabled;
        }
        if let Some(read_only) = parse_bool_value("FCACHE_READ_ONLY", get_env("FCACHE_READ_ONLY"))?
        {
            c.read_only = read_only;
        }
        if let Some(direct) = parse_bool_value("FCACHE_DIRECT", get_env("FCACHE_DIRECT"))? {
            c.direct = direct;
        }
        if let Some(value) = get_env("FCACHE_COMPILER_IDENTITY") {
            let text = value.to_str().ok_or_else(|| {
                ConfigError::Value("FCACHE_COMPILER_IDENTITY".into(), "must be valid UTF-8".into())
            })?;
            c.compiler_identity = parse_compiler_identity(text, "FCACHE_COMPILER_IDENTITY")?;
        }
        Ok(c)
    }
    pub fn config_path() -> Option<PathBuf> {
        BaseDirs::new().map(|b| b.config_dir().join("fcache/config.toml"))
    }
}

fn parse_compiler_identity(value: &str, name: &str) -> Result<CompilerIdentityPolicy, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(CompilerIdentityPolicy::Auto),
        "strict" => Ok(CompilerIdentityPolicy::Strict),
        other => Err(ConfigError::Value(
            name.into(),
            format!("expected 'auto' or 'strict', got '{other}'"),
        )),
    }
}

/// Reports an `FCACHE_DISABLE` emergency bypass without loading the configuration file.
pub fn disabled_by_env() -> Result<bool, ConfigError> {
    Ok(parse_bool_value("FCACHE_DISABLE", env::var_os("FCACHE_DISABLE"))?.unwrap_or(false))
}

fn parse_bool_value(name: &str, value: Option<OsString>) -> Result<Option<bool>, ConfigError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text = value
        .to_str()
        .ok_or_else(|| ConfigError::Value(name.into(), "must be valid UTF-8".into()))?
        .trim()
        .to_ascii_lowercase();
    match text.as_str() {
        "" | "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => {
            Err(ConfigError::Value(name.into(), format!("expected a boolean value, got '{text}'")))
        }
    }
}

fn parse_size_os(value: OsString, name: &str) -> Result<u64, ConfigError> {
    parse_size(
        value
            .to_str()
            .ok_or_else(|| ConfigError::Value(name.into(), "must be valid UTF-8".into()))?,
        name,
    )
}
pub fn parse_size(value: &str, name: &str) -> Result<u64, ConfigError> {
    let normalized = value.trim().to_ascii_lowercase().replace(' ', "");
    let s = normalized.as_str();
    let (num, mult) = [
        ("kib", 1u64 << 10),
        ("mib", 1u64 << 20),
        ("gib", 1u64 << 30),
        ("tib", 1u64 << 40),
        ("kb", 1u64 << 10),
        ("mb", 1u64 << 20),
        ("gb", 1u64 << 30),
        ("tb", 1u64 << 40),
    ]
    .iter()
    .find_map(|(suffix, m)| s.strip_suffix(suffix).map(|n| (n, *m)))
    .unwrap_or((s, 1));
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| ConfigError::Value(name.into(), format!("invalid size '{value}'")))?;
    n.checked_mul(mult).ok_or_else(|| ConfigError::Value(name.into(), "size is too large".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_with_values(
        values: &[(&str, OsString)],
        default_config_path: PathBuf,
    ) -> Result<Config, ConfigError> {
        Config::load_with(
            |name| values.iter().find(|(key, _)| *key == name).map(|(_, value)| value.clone()),
            default_config_path,
        )
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("10 GiB", "x").unwrap(), 10 << 30);
        assert_eq!(parse_size("2mb", "x").unwrap(), 2 << 20);
        assert_eq!(parse_size("42", "x").unwrap(), 42);
    }

    #[test]
    fn invalid_and_overflowing_sizes_are_rejected() {
        assert!(matches!(parse_size("many", "x"), Err(ConfigError::Value(_, _))));
        assert!(matches!(
            parse_size("18446744073709551615 KiB", "x"),
            Err(ConfigError::Value(_, _))
        ));
    }

    #[test]
    fn unknown_file_fields_are_rejected() {
        let error = toml::from_str::<FileConfig>("enabled = true\ntyop = false\n").unwrap_err();
        assert!(error.to_string().contains("unknown field `tyop`"));
    }

    #[test]
    fn explicitly_selected_missing_config_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.toml");
        let error = load_with_values(
            &[("FCACHE_CONFIG", missing.clone().into_os_string())],
            directory.path().join("default.toml"),
        )
        .unwrap_err();

        match error {
            ConfigError::Read { path, source } => {
                assert_eq!(path, missing);
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected a read error, got {other:?}"),
        }
    }

    #[test]
    fn absent_default_config_is_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let config = load_with_values(&[], directory.path().join("missing.toml")).unwrap();
        assert!(config.enabled);
        assert!(!config.read_only);
        assert!(config.direct);
        assert_eq!(config.compiler_identity, CompilerIdentityPolicy::Auto);
    }

    #[test]
    fn file_values_load_and_environment_values_override_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "dir = '/from-file'\nmax_size = '2 MiB'\nenabled = true\nread_only = false\ndirect = true\ncompiler_identity = 'strict'\n",
        )
        .unwrap();

        let config = load_with_values(
            &[
                ("FCACHE_CONFIG", path.into_os_string()),
                ("FCACHE_DIR", OsString::from("/from-environment")),
                ("FCACHE_MAX_SIZE", OsString::from("3 MiB")),
                ("FCACHE_DISABLE", OsString::from("yes")),
                ("FCACHE_READ_ONLY", OsString::from("on")),
                ("FCACHE_DIRECT", OsString::from("off")),
                ("FCACHE_COMPILER_IDENTITY", OsString::from("auto")),
            ],
            directory.path().join("default.toml"),
        )
        .unwrap();

        assert_eq!(config.cache_dir, PathBuf::from("/from-environment"));
        assert_eq!(config.max_size, 3 << 20);
        assert!(!config.enabled);
        assert!(config.read_only);
        assert!(!config.direct);
        assert_eq!(config.compiler_identity, CompilerIdentityPolicy::Auto);
    }

    #[test]
    fn compiler_identity_policy_is_validated() {
        let error = load_with_values(
            &[("FCACHE_COMPILER_IDENTITY", OsString::from("fastest"))],
            PathBuf::from("missing.toml"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("expected 'auto' or 'strict'"));
    }

    #[test]
    fn disable_value_can_be_checked_without_loading_config() {
        for value in ["", "1", "true", "YES", "on"] {
            assert_eq!(parse_bool_value("FCACHE_DISABLE", Some(value.into())).unwrap(), Some(true));
        }
        for value in ["0", "false", "NO", "off"] {
            assert_eq!(
                parse_bool_value("FCACHE_DISABLE", Some(value.into())).unwrap(),
                Some(false)
            );
        }
        assert_eq!(parse_bool_value("FCACHE_DISABLE", None).unwrap(), None);
    }

    #[test]
    fn invalid_boolean_value_is_rejected() {
        let error = parse_bool_value("FCACHE_DISABLE", Some("sometimes".into())).unwrap_err();
        assert!(error.to_string().contains("expected a boolean value"));
    }
}
