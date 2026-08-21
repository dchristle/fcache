//! GNU compiler toolchain fingerprinting.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_QUERY_OUTPUT: usize = 4 * 1024 * 1024;

/// The exact process context used to resolve and query a compiler driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintContext {
    pub driver: OsString,
    pub cwd: PathBuf,
    pub environment: Vec<(OsString, OsString)>,
}

impl FingerprintContext {
    pub fn new<I, K, V>(
        driver: impl Into<OsString>,
        cwd: impl Into<PathBuf>,
        environment: I,
    ) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            driver: driver.into(),
            cwd: cwd.into(),
            environment: environment
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        }
    }
}

/// Content-addressed identity of a gfortran driver and its backend tools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerFingerprint {
    /// BLAKE3 digest of the serialized bytes.
    pub digest: [u8; 32],
    pub driver: PathBuf,
    pub f951: PathBuf,
    pub assembler: PathBuf,
    pub major_version: u32,
}

impl CompilerFingerprint {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn digest_hex(&self) -> String {
        self.digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("compiler driver {0:?} was not found")]
    DriverNotFound(OsString),
    #[error("failed to read compiler tool {path:?}: {source}")]
    ReadTool { path: PathBuf, source: std::io::Error },
    #[error("failed to execute {program:?}: {source}")]
    Execute { program: OsString, source: std::io::Error },
    #[error("compiler command {program:?} exited with {status}")]
    CommandFailed { program: OsString, status: String },
    #[error("compiler command {program:?} did not print a tool path")]
    MissingToolPath { program: OsString },
    #[error("compiler command {program:?} produced more than {limit} bytes")]
    QueryOutputTooLarge { program: OsString, limit: usize },
    #[error("compiler identity cache I/O failed: {0}")]
    CacheIo(#[source] std::io::Error),
    #[error("compiler identity cache record is invalid: {0}")]
    InvalidRecord(String),
}

#[derive(Clone, Debug)]
pub(crate) struct FingerprintObservation {
    pub fingerprint: CompilerFingerprint,
    pub driver_resolution: ResolutionObservation,
    pub f951_resolution: ResolutionObservation,
    pub assembler_resolution: ResolutionObservation,
    pub specs_path: Option<Vec<u8>>,
    pub specs_absent: Vec<Vec<u8>>,
    pub specs_resolution_complete: bool,
    pub tool_content_digests: Vec<(Vec<u8>, [u8; 32])>,
    pub query_outputs: QueryOutputs,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ResolutionObservation {
    pub selected: Vec<u8>,
    pub earlier_absent: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct QueryOutputs {
    pub f951: Vec<u8>,
    pub assembler: Vec<u8>,
    pub version: Vec<u8>,
    pub numeric_version: Vec<u8>,
    pub target: Vec<u8>,
    pub search_dirs: Vec<u8>,
    pub specs_name: Vec<u8>,
    pub specs: Vec<u8>,
}

/// Fingerprint a gfortran driver using the current process context.
pub fn fingerprint_gfortran(driver: &OsStr) -> Result<CompilerFingerprint, FingerprintError> {
    let cwd = env::current_dir().map_err(FingerprintError::CacheIo)?;
    let context = FingerprintContext::new(driver, cwd, env::vars_os());
    fingerprint_gfortran_in(&context)
}

/// Fingerprint a gfortran driver using an explicit compiler process context.
pub fn fingerprint_gfortran_in(
    context: &FingerprintContext,
) -> Result<CompilerFingerprint, FingerprintError> {
    Ok(observe_gfortran(context)?.fingerprint)
}

/// Alias for callers that use the shorter operation name.
pub fn fingerprint(driver: &OsStr) -> Result<CompilerFingerprint, FingerprintError> {
    fingerprint_gfortran(driver)
}

pub(crate) fn observe_gfortran(
    context: &FingerprintContext,
) -> Result<FingerprintObservation, FingerprintError> {
    if !context.cwd.is_absolute() || !context.cwd.is_dir() {
        return Err(FingerprintError::InvalidRecord(
            "compiler working directory must be an absolute existing directory".into(),
        ));
    }
    let driver_resolution = resolve_program(
        &context.driver,
        &context.cwd,
        path_from_environment(&context.environment),
        &[],
    )
    .ok_or_else(|| FingerprintError::DriverNotFound(context.driver.clone()))?;
    let resolved_driver = path_from_bytes(&driver_resolution.selected);

    let search_dirs = run(context, &resolved_driver, &[b"-print-search-dirs"])?;
    let program_roots = parse_program_search_dirs(&search_dirs, &context.cwd);
    let (f951_resolution, f951_output) =
        tool_path(context, &resolved_driver, b"-print-prog-name=f951", &program_roots)?;
    let (assembler_resolution, assembler_output) =
        tool_path(context, &resolved_driver, b"-print-prog-name=as", &program_roots)?;
    let f951 = path_from_bytes(&f951_resolution.selected);
    let assembler = path_from_bytes(&assembler_resolution.selected);
    let version = run(context, &resolved_driver, &[b"--version"])?;
    let numeric_version = run(context, &resolved_driver, &[b"-dumpfullversion", b"-dumpversion"])?;
    let major_version =
        parse_major_version(&numeric_version).ok_or_else(|| FingerprintError::CommandFailed {
            program: resolved_driver.as_os_str().to_os_string(),
            status: "compiler did not report a numeric major version".into(),
        })?;
    let target = run(context, &resolved_driver, &[b"-dumpmachine"])?;
    let specs_name = run(context, &resolved_driver, &[b"-print-file-name=specs"])?;
    let specs = run(context, &resolved_driver, &[b"-dumpspecs"])?;
    let specs_path =
        resolve_specs_path(&specs_name, &context.cwd, &program_roots).ok_or_else(|| {
            FingerprintError::MissingToolPath { program: os_string(trim_ascii(&specs_name)) }
        })?;
    let (specs_absent, specs_resolution_complete) =
        specs_resolution_witnesses(specs_path.as_deref(), &program_roots);

    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, b"fcache-gfortran-fingerprint-v2");
    hash_field(&mut hasher, &driver_resolution.selected);
    let driver_digest = hash_tool_field_with_digest(&mut hasher, &resolved_driver)?;
    hash_field(&mut hasher, &f951_output);
    hash_field(&mut hasher, &f951_resolution.selected);
    let f951_digest = hash_tool_field_with_digest(&mut hasher, &f951)?;
    hash_field(&mut hasher, &assembler_output);
    hash_field(&mut hasher, &assembler_resolution.selected);
    let assembler_digest = hash_tool_field_with_digest(&mut hasher, &assembler)?;
    hash_field(&mut hasher, &version);
    hash_field(&mut hasher, &numeric_version);
    hash_field(&mut hasher, &target);
    hash_field(&mut hasher, &search_dirs);
    hash_field(&mut hasher, &specs_name);
    let specs_digest = if let Some(path) = &specs_path {
        hash_field(&mut hasher, b"external-specs");
        hash_field(&mut hasher, &path_bytes(path));
        Some(hash_tool_field_with_digest(&mut hasher, path)?)
    } else {
        hash_field(&mut hasher, b"built-in-specs");
        None
    };
    hash_field(&mut hasher, &specs);
    let digest = *hasher.finalize().as_bytes();
    let tool_content_digests = [
        Some((path_bytes(&resolved_driver), driver_digest)),
        Some((path_bytes(&f951), f951_digest)),
        Some((path_bytes(&assembler), assembler_digest)),
        specs_path.as_ref().zip(specs_digest).map(|(path, digest)| (path_bytes(path), digest)),
    ]
    .into_iter()
    .flatten()
    .collect();
    let fingerprint =
        CompilerFingerprint { digest, driver: resolved_driver, f951, assembler, major_version };
    Ok(FingerprintObservation {
        fingerprint,
        driver_resolution,
        f951_resolution,
        assembler_resolution,
        specs_path: specs_path.as_ref().map(|path| path_bytes(path)),
        specs_absent,
        specs_resolution_complete,
        tool_content_digests,
        query_outputs: QueryOutputs {
            f951: f951_output,
            assembler: assembler_output,
            version,
            numeric_version,
            target,
            search_dirs,
            specs_name,
            specs,
        },
    })
}

fn specs_resolution_witnesses(
    selected: Option<&Path>,
    program_roots: &[PathBuf],
) -> (Vec<Vec<u8>>, bool) {
    let selected = selected.and_then(|path| fs::canonicalize(path).ok());
    let mut absent = Vec::new();
    let mut selected_found = selected.is_none();
    let mut complete = true;
    for root in program_roots {
        let candidate = root.join("specs");
        match fs::canonicalize(&candidate) {
            Ok(canonical) if selected.as_ref() == Some(&canonical) => {
                selected_found = true;
                break;
            }
            Ok(_) => complete = false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                absent.push(path_bytes(&candidate));
            }
            Err(_) => complete = false,
        }
    }
    (absent, complete && selected_found)
}

fn tool_path(
    context: &FingerprintContext,
    driver: &Path,
    option: &[u8],
    program_roots: &[PathBuf],
) -> Result<(ResolutionObservation, Vec<u8>), FingerprintError> {
    let output = run(context, driver, &[option])?;
    let path = trim_ascii(&output);
    if path.is_empty() {
        return Err(FingerprintError::MissingToolPath {
            program: driver.as_os_str().to_os_string(),
        });
    }
    let path = os_string(path);
    let resolved = resolve_program(
        &path,
        &context.cwd,
        path_from_environment(&context.environment),
        program_roots,
    )
    .ok_or(FingerprintError::MissingToolPath { program: path })?;
    Ok((resolved, output))
}

fn run(
    context: &FingerprintContext,
    program: &Path,
    args: &[&[u8]],
) -> Result<Vec<u8>, FingerprintError> {
    let mut command = Command::new(program);
    command.current_dir(&context.cwd).env_clear().envs(context.environment.iter().cloned());
    for arg in args {
        command.arg(os_string(arg));
    }
    let output = command.output().map_err(|source| FingerprintError::Execute {
        program: program.as_os_str().to_os_string(),
        source,
    })?;
    if !output.status.success() {
        return Err(FingerprintError::CommandFailed {
            program: program.as_os_str().to_os_string(),
            status: output.status.to_string(),
        });
    }
    let total = output.stdout.len().saturating_add(output.stderr.len()).saturating_add(8);
    if total > MAX_QUERY_OUTPUT {
        return Err(FingerprintError::QueryOutputTooLarge {
            program: program.as_os_str().to_os_string(),
            limit: MAX_QUERY_OUTPUT,
        });
    }
    let mut combined = output.stdout;
    if !output.stderr.is_empty() {
        combined.extend_from_slice(b"\0stderr\0");
        combined.extend_from_slice(&output.stderr);
    }
    Ok(combined)
}

#[cfg(test)]
fn hash_tool_field(hasher: &mut blake3::Hasher, path: &Path) -> Result<(), FingerprintError> {
    hash_tool_field_with_digest(hasher, path).map(|_| ())
}

fn hash_tool_field_with_digest(
    hasher: &mut blake3::Hasher,
    path: &Path,
) -> Result<[u8; 32], FingerprintError> {
    let mut file = File::open(path)
        .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
    let initial_metadata = file
        .metadata()
        .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
    let expected_len = initial_metadata.len();
    hasher.update(&expected_len.to_le_bytes());

    let mut actual_len = 0_u64;
    let mut content_hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
        if count == 0 {
            break;
        }
        actual_len = actual_len.saturating_add(count as u64);
        hasher.update(&buffer[..count]);
        content_hasher.update(&buffer[..count]);
    }
    let final_metadata = file
        .metadata()
        .map_err(|source| FingerprintError::ReadTool { path: path.to_path_buf(), source })?;
    if actual_len != expected_len || !same_tool_metadata(&initial_metadata, &final_metadata) {
        return Err(FingerprintError::ReadTool {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "compiler tool changed while being fingerprinted",
            ),
        });
    }
    Ok(*content_hasher.finalize().as_bytes())
}

#[cfg(unix)]
fn same_tool_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_tool_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn resolve_program(
    program: &OsStr,
    cwd: &Path,
    path: Option<&OsStr>,
    prefix_roots: &[PathBuf],
) -> Option<ResolutionObservation> {
    let program_path = Path::new(program);
    if program_path.components().count() > 1 {
        let candidate = if program_path.is_absolute() {
            program_path.to_path_buf()
        } else {
            cwd.join(program_path)
        };
        return candidate.is_file().then(|| ResolutionObservation {
            selected: path_bytes(&candidate),
            earlier_absent: Vec::new(),
        });
    }
    let mut candidates = prefix_roots.iter().map(|root| root.join(program)).collect::<Vec<_>>();
    if let Some(path) = path {
        candidates.extend(env::split_paths(path).map(|directory| {
            if directory.as_os_str().is_empty() {
                cwd.join(program)
            } else if directory.is_absolute() {
                directory.join(program)
            } else {
                cwd.join(directory).join(program)
            }
        }));
    }
    let mut earlier_absent = Vec::new();
    for candidate in candidates {
        match candidate.try_exists() {
            Ok(true) if candidate.is_file() => {
                return Some(ResolutionObservation {
                    selected: path_bytes(&candidate),
                    earlier_absent,
                });
            }
            Ok(false) => earlier_absent.push(path_bytes(&candidate)),
            Ok(true) | Err(_) => return None,
        }
    }
    None
}

fn resolve_specs_path(
    raw: &[u8],
    cwd: &Path,
    program_roots: &[PathBuf],
) -> Option<Option<PathBuf>> {
    let name = os_string(trim_ascii(raw));
    if name.is_empty() || name == OsStr::new("specs") {
        return Some(None);
    }
    let path = Path::new(&name);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if path.components().count() > 1 {
        cwd.join(path)
    } else {
        program_roots.iter().map(|root| root.join(path)).find(|path| path.is_file())?
    };
    candidate.is_file().then_some(Some(candidate))
}

fn parse_program_search_dirs(value: &[u8], cwd: &Path) -> Vec<PathBuf> {
    let stdout = value.split(|byte| *byte == 0).next().unwrap_or(value);
    let Some(line) =
        stdout.split(|byte| *byte == b'\n').find(|line| line.starts_with(b"programs: ="))
    else {
        return Vec::new();
    };
    let paths = os_string(&line[b"programs: =".len()..]);
    env::split_paths(&paths)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| if path.is_absolute() { path } else { cwd.join(path) })
        .collect()
}

fn path_from_environment(environment: &[(OsString, OsString)]) -> Option<&OsStr> {
    environment
        .iter()
        .rev()
        .find(|(name, _)| name == OsStr::new("PATH"))
        .map(|(_, value)| value.as_os_str())
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn parse_major_version(value: &[u8]) -> Option<u32> {
    let value = trim_ascii(value);
    let digits = value.iter().copied().take_while(u8::is_ascii_digit).collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

pub(crate) fn path_bytes(path: &Path) -> Vec<u8> {
    encoded(path.as_os_str())
}

pub(crate) fn path_from_bytes(value: &[u8]) -> PathBuf {
    PathBuf::from(os_string(value))
}

pub(crate) fn encoded(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn os_string(value: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(value.to_vec())
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(value).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{hash_field, hash_tool_field, parse_major_version, trim_ascii};

    fn append_field(buffer: &mut Vec<u8>, value: &[u8]) {
        buffer.extend_from_slice(&(value.len() as u64).to_le_bytes());
        buffer.extend_from_slice(value);
    }

    #[test]
    fn serialization_is_length_delimited() {
        let mut bytes = Vec::new();
        append_field(&mut bytes, b"a");
        append_field(&mut bytes, b"bc");
        assert_eq!(&bytes[..8], &1u64.to_le_bytes());
        assert_eq!(&bytes[9..17], &2u64.to_le_bytes());
    }

    #[test]
    fn streaming_digest_matches_canonical_serialization() {
        let directory = tempfile::tempdir().unwrap();
        let tool_path = directory.path().join("tool");
        let mut tool = std::fs::File::create(&tool_path).unwrap();
        tool.write_all(&vec![0x5a; 128 * 1024 + 17]).unwrap();
        drop(tool);

        let fields: [&[u8]; 3] = [b"fcache-gfortran-fingerprint-v2", b"path", b"output"];
        let mut canonical = Vec::new();
        append_field(&mut canonical, fields[0]);
        append_field(&mut canonical, fields[1]);
        append_field(&mut canonical, &std::fs::read(&tool_path).unwrap());
        append_field(&mut canonical, fields[2]);

        let mut streaming = blake3::Hasher::new();
        hash_field(&mut streaming, fields[0]);
        hash_field(&mut streaming, fields[1]);
        hash_tool_field(&mut streaming, &tool_path).unwrap();
        hash_field(&mut streaming, fields[2]);

        assert_eq!(streaming.finalize(), blake3::hash(&canonical));
    }

    #[test]
    fn trims_non_utf8_output_without_loss() {
        assert_eq!(trim_ascii(b" \ttool\n"), b"tool");
    }

    #[test]
    fn parses_numeric_compiler_major() {
        assert_eq!(parse_major_version(b"16.1.0\n"), Some(16));
        assert_eq!(parse_major_version(b"not-a-version"), None);
    }
}
