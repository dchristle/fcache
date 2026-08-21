//! Compiler launcher orchestration.

use crate::cache::direct::{
    AbsentPathWitness, CompilerWitnessRef, DIRECT_RECORD_SCHEMA_VERSION,
    DepfilePrerequisiteKind as DirectDepfilePrerequisiteKind,
    DepfilePrerequisiteShape as DirectDepfilePrerequisiteShape,
    DepfileRuleShape as DirectDepfileRuleShape, DepfileShape as DirectDepfileShape,
    DepfileTargetKind as DirectDepfileTargetKind, DepfileTargetShape as DirectDepfileTargetShape,
    DirectDigest, DirectIndex, DirectInput, DirectMissReason, DirectRecord, DirectRequestKey,
    EncodedOsString, ExpectedArtifact as DirectExpectedArtifact, PathWitness,
    PositiveResolutionWitness, PreprocessorShape, ResolutionKind, SearchResolutionWitnesses,
    WitnessFileType,
};
use crate::cache::key::{ActionKey, ActionKeyBuilder};
use crate::cache::manifest::{Artifact, ArtifactKind, DestinationRole, Manifest};
use crate::cache::output_lock::{
    DirectorySnapshot, ModuleDirectoryAccess, OutputLockPlan, OutputLocks,
};
use crate::cache::stats::{Stats, StatsStore};
use crate::cache::store::{CacheError, CacheStore, RestoreDestinations};
use crate::cli::Command;
use crate::compiler::depfile::{Depfile, parse_depfile};
use crate::compiler::fingerprint::{CompilerFingerprint, FingerprintContext, fingerprint_gfortran};
use crate::compiler::gfortran::resolution::{
    DependencyObservation, DependencyResolutionKind, EnvironmentSearchPaths,
    ObservedSearchFeatures, ResolutionContext,
};
use crate::compiler::gfortran::{
    BypassReason, Cacheability, DependencyMode, GfortranInvocation, Preprocessing,
    parse_gfortran_args,
};
use crate::compiler::identity::{CompilerIdentityCache, IdentityMode, ValidatedCompilerIdentity};
use crate::config::{CompilerIdentityPolicy, Config};
use crate::process::{CompilerCommand, CompilerOutput, exec_compiler};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(serde::Serialize)]
struct ExplainInput {
    path: String,
    digest: String,
    size: u64,
}

#[derive(serde::Serialize)]
struct ExplainOutput {
    logical_name: String,
    kind: String,
    destination_role: String,
    path: String,
    probe_digest: Option<String>,
}

#[derive(serde::Serialize)]
struct ExplainReport {
    decision: &'static str,
    reason: Option<String>,
    compiler_major: Option<u32>,
    compiler_digest: Option<String>,
    action_key: Option<String>,
    inputs: Vec<ExplainInput>,
    outputs: Vec<ExplainOutput>,
}

const KEY_SCHEMA: &[u8] = b"fcache-gfortran-action-v10";
const MIN_GFORTRAN_MAJOR: u32 = 11;
const MAX_GFORTRAN_MAJOR: u32 = 16;

fn supported_gfortran_major(major: u32) -> bool {
    (MIN_GFORTRAN_MAJOR..=MAX_GFORTRAN_MAJOR).contains(&major)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputFile {
    raw_path: Vec<u8>,
    observed_path: PathBuf,
    path: PathBuf,
    digest: [u8; 32],
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedDependency {
    raw_path: Vec<u8>,
    observed_path: PathBuf,
    path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedArtifact {
    logical_name: String,
    kind: ArtifactKind,
    role: DestinationRole,
    path: PathBuf,
    probe_digest: Option<[u8; 32]>,
    probe_size: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct Observation {
    inputs: Vec<InputFile>,
    dependencies: Vec<ObservedDependency>,
    outputs: Vec<ExpectedArtifact>,
    depfile_shape: DepfileShape,
    preprocessor: Option<PreprocessorObservation>,
}

#[derive(Debug, Eq, PartialEq)]
struct PreprocessorObservation {
    stdout_digest: [u8; 32],
    stdout_size: u64,
    stderr_digest: [u8; 32],
    stderr_size: u64,
    automatic_lowercase_source: bool,
}

enum DirectAttempt {
    Hit(Manifest),
    Compile(Box<DirectCompilePlan>),
    Miss,
}

struct DirectCompilePlan {
    record: DirectRecord,
    observation: Observation,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DepfileTarget {
    Ordinary(Vec<u8>),
    GeneratedModule(Vec<u8>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DepfilePrerequisite {
    Ordinary(Vec<u8>),
    GeneratedModule(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedDepfileRule {
    targets: Vec<DepfileTarget>,
    prerequisites: Vec<DepfilePrerequisite>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DepfileShape {
    primary_rules: Vec<ObservedDepfileRule>,
    dummy_targets: Vec<DepfileTarget>,
}

#[derive(Debug)]
struct ProbeModule {
    name: String,
    name_bytes: Vec<u8>,
    private_path: PathBuf,
    contents: InputFile,
}

#[derive(Debug)]
struct ProbeModules {
    modules: Vec<ProbeModule>,
    generated_targets: BTreeMap<(usize, usize), Vec<u8>>,
    canonical_paths: BTreeSet<PathBuf>,
}

#[derive(Debug)]
struct CapturedArtifact<'a> {
    expected: &'a ExpectedArtifact,
    bytes: Vec<u8>,
    mode: u32,
    digest: [u8; 32],
}

struct PendingStats {
    store: Option<StatsStore>,
    key: Option<String>,
    delta: Stats,
    dirty: bool,
}

impl PendingStats {
    fn new(store: Option<StatsStore>) -> Self {
        Self { store, key: None, delta: Stats::default(), dirty: false }
    }

    fn record(&mut self, key: Option<&str>, update: impl FnOnce(&mut Stats)) {
        if let Some(key) = key {
            self.key = Some(key.to_owned());
        }
        update(&mut self.delta);
        self.dirty = true;
    }

    fn flush(&mut self) {
        if !self.dirty {
            return;
        }
        if let Some(store) = &self.store {
            let delta = &self.delta;
            let _ = store.record(self.key.as_deref(), |stats| stats.merge(delta));
        }
        self.delta = Stats::default();
        self.dirty = false;
    }
}

impl Drop for PendingStats {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Run fcache using the current process arguments and environment.
pub fn run() -> i32 {
    match run_inner() {
        Ok(code) => code,
        Err(message) => {
            let _ = writeln!(io::stderr(), "fcache: {message}");
            2
        }
    }
}

fn run_inner() -> Result<i32, String> {
    let command = crate::cli::parse_env().map_err(|error| error.to_string())?;
    match &command {
        Command::Version => {
            println!("fcache {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        Command::Help => {
            print_help();
            return Ok(0);
        }
        Command::Explain { arguments, json } => return explain(arguments, *json),
        Command::Compiler(arguments)
            if crate::config::disabled_by_env().map_err(|e| e.to_string())? =>
        {
            let Some((compiler, compiler_args)) = arguments.split_first() else {
                print_help();
                return Ok(2);
            };
            return pass_through(compiler, compiler_args, &compiler_environment());
        }
        _ => {}
    }
    let config = Config::load().map_err(|error| error.to_string())?;
    match command {
        Command::Compiler(arguments) => run_compiler(arguments, &config),
        Command::Explain { .. } => unreachable!("explain handled before configuration loading"),
        Command::ShowStats { json } => show_stats(&config, json),
        Command::ZeroStats => {
            StatsStore::new(&config.cache_dir)
                .and_then(|store| store.reset())
                .map_err(|error| error.to_string())?;
            Ok(0)
        }
        Command::ShowConfig => {
            println!("cache_dir = {}", config.cache_dir.display());
            println!("max_size = {}", config.max_size);
            println!("enabled = {}", config.enabled);
            println!("read_only = {}", config.read_only);
            println!("direct = {}", config.direct);
            println!(
                "compiler_identity = {}",
                match config.compiler_identity {
                    crate::config::CompilerIdentityPolicy::Auto => "auto",
                    crate::config::CompilerIdentityPolicy::Strict => "strict",
                }
            );
            Ok(0)
        }
        Command::Trim => {
            let removed = CacheStore::new(&config.cache_dir)
                .and_then(|store| store.trim_to_size(config.max_size))
                .map_err(|error| error.to_string())?;
            println!("removed {removed} cache files");
            Ok(0)
        }
        Command::Clear => {
            CacheStore::new(&config.cache_dir)
                .and_then(|store| store.clear())
                .map_err(|error| error.to_string())?;
            Ok(0)
        }
        Command::Version | Command::Help => unreachable!("handled before configuration loading"),
    }
}

fn explain(arguments: &[OsString], json: bool) -> Result<i32, String> {
    let Some((compiler, compiler_args)) = arguments.split_first() else {
        return Err("--explain requires a compiler command".into());
    };
    let environment = compiler_environment();
    if !is_gfortran(compiler) {
        return emit_explain(
            ExplainReport {
                decision: "bypass",
                reason: Some("unsupported-compiler".into()),
                compiler_major: None,
                compiler_digest: None,
                action_key: None,
                inputs: Vec::new(),
                outputs: Vec::new(),
            },
            json,
            1,
        );
    }
    let invocation = parse_gfortran_args(compiler_args).map_err(|error| error.to_string())?;
    if let Cacheability::Bypass(reason) = &invocation.cacheability {
        return emit_explain(
            ExplainReport {
                decision: "bypass",
                reason: Some(format!("{}: {reason:?}", bypass_name(reason))),
                compiler_major: None,
                compiler_digest: None,
                action_key: None,
                inputs: Vec::new(),
                outputs: Vec::new(),
            },
            json,
            1,
        );
    }
    if !invocation.preprocessing.permits_probe() {
        return emit_explain(
            ExplainReport {
                decision: "bypass",
                reason: Some("dependency-probe-preprocessing".into()),
                compiler_major: None,
                compiler_digest: None,
                action_key: None,
                inputs: Vec::new(),
                outputs: Vec::new(),
            },
            json,
            1,
        );
    }
    let fingerprint = fingerprint_gfortran(compiler).map_err(|error| error.to_string())?;
    if !supported_gfortran_major(fingerprint.major_version) {
        return emit_explain(
            ExplainReport {
                decision: "bypass",
                reason: Some("unsupported-compiler-version".into()),
                compiler_major: Some(fingerprint.major_version),
                compiler_digest: Some(fingerprint.digest_hex()),
                action_key: None,
                inputs: Vec::new(),
                outputs: Vec::new(),
            },
            json,
            1,
        );
    }
    let cwd = env::current_dir().map_err(|error| error.to_string())?;
    let mut probe_telemetry = ProbeTelemetry::default();
    let observation = match observe(
        compiler,
        &invocation,
        &cwd,
        &environment,
        fingerprint.major_version,
        &mut probe_telemetry,
    ) {
        Ok(observation) => observation,
        Err(error) if error == "dependency probe failed" => {
            return emit_explain(
                ExplainReport {
                    decision: "bypass",
                    reason: Some(format!("dependency-probe: {error}")),
                    compiler_major: Some(fingerprint.major_version),
                    compiler_digest: Some(fingerprint.digest_hex()),
                    action_key: None,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                },
                json,
                1,
            );
        }
        Err(error) => return Err(error),
    };
    if invocation.syntax_only
        && observation
            .outputs
            .iter()
            .any(|output| matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule))
    {
        return emit_explain(
            explain_report(
                "bypass",
                Some("syntax-only-module-outputs".into()),
                &fingerprint,
                None,
                &observation,
            ),
            json,
            1,
        );
    }
    let action =
        build_action_key(compiler, &invocation, &fingerprint, &cwd, &environment, &observation)
            .map_err(|error| error.to_string())?;
    emit_explain(
        explain_report("cacheable", None, &fingerprint, Some(action.to_string()), &observation),
        json,
        0,
    )
}

fn explain_report(
    decision: &'static str,
    reason: Option<String>,
    fingerprint: &CompilerFingerprint,
    action_key: Option<String>,
    observation: &Observation,
) -> ExplainReport {
    ExplainReport {
        decision,
        reason,
        compiler_major: Some(fingerprint.major_version),
        compiler_digest: Some(fingerprint.digest_hex()),
        action_key,
        inputs: observation
            .inputs
            .iter()
            .map(|input| ExplainInput {
                path: input.path.display().to_string(),
                digest: hex_digest(input.digest),
                size: input.size,
            })
            .collect(),
        outputs: observation
            .outputs
            .iter()
            .map(|output| ExplainOutput {
                logical_name: output.logical_name.clone(),
                kind: format!("{:?}", output.kind).to_ascii_lowercase(),
                destination_role: format!("{:?}", output.role).to_ascii_lowercase(),
                path: output.path.display().to_string(),
                probe_digest: output.probe_digest.map(hex_digest),
            })
            .collect(),
    }
}

fn emit_explain(report: ExplainReport, json: bool, exit_code: i32) -> Result<i32, String> {
    if json {
        serde_json::to_writer_pretty(io::stdout(), &report).map_err(|error| error.to_string())?;
        println!();
    } else {
        println!("decision: {}", report.decision);
        if let Some(reason) = &report.reason {
            println!("reason: {reason}");
        }
        if let Some(major) = report.compiler_major {
            println!("compiler major: {major}");
        }
        if let Some(digest) = &report.compiler_digest {
            println!("compiler digest: {digest}");
        }
        if let Some(action) = &report.action_key {
            println!("action key: {action}");
        }
        for input in &report.inputs {
            println!("input: {} {} {}", input.digest, input.size, input.path);
        }
        for output in &report.outputs {
            println!(
                "output: {} {} {} {}",
                output.destination_role, output.kind, output.logical_name, output.path
            );
        }
    }
    Ok(exit_code)
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn run_compiler(arguments: Vec<OsString>, config: &Config) -> Result<i32, String> {
    let Some((compiler, compiler_args)) = arguments.split_first() else {
        print_help();
        return Ok(2);
    };
    let environment = compiler_environment();
    if !config.enabled || io::stdout().is_terminal() || io::stderr().is_terminal() {
        return pass_through(compiler, compiler_args, &environment);
    }
    let mut stats = PendingStats::new(StatsStore::new(&config.cache_dir).ok());
    if !is_gfortran(compiler) {
        record_bypass(&mut stats, "unsupported-compiler");
        return pass_through(compiler, compiler_args, &environment);
    }
    let invocation = match parse_gfortran_args(compiler_args) {
        Ok(value) => value,
        Err(_) => {
            record_bypass(&mut stats, "argument-parse");
            return pass_through(compiler, compiler_args, &environment);
        }
    };
    if let Cacheability::Bypass(reason) = &invocation.cacheability {
        record_bypass(&mut stats, bypass_name(reason));
        return pass_through(compiler, compiler_args, &environment);
    }
    if !invocation.preprocessing.permits_probe() {
        record_bypass(&mut stats, "dependency-probe-preprocessing");
        return pass_through(compiler, compiler_args, &environment);
    }
    record(&mut stats, None, |value| value.requests += 1);
    let cwd = env::current_dir().map_err(|error| error.to_string())?;
    let store = match CacheStore::new(&config.cache_dir) {
        Ok(value) => value,
        Err(_) => {
            record(&mut stats, None, |value| {
                value.cache_read_failures += 1;
                value.process_counts.pass_through_executions += 1;
            });
            stats.flush();
            return pass_through(compiler, compiler_args, &environment);
        }
    };
    let identity_context =
        FingerprintContext::new(compiler, &cwd, relevant_environment(&environment));
    let identity_started = Instant::now();
    let identity = match CompilerIdentityCache::new(&config.cache_dir, config.read_only).lookup(
        &identity_context,
        match config.compiler_identity {
            CompilerIdentityPolicy::Auto => IdentityMode::Auto,
            CompilerIdentityPolicy::Strict => IdentityMode::Strict,
        },
    ) {
        Ok(value) => value,
        Err(_) => {
            record_attempted_bypass(&mut stats, "compiler-fingerprint");
            return pass_through(compiler, compiler_args, &environment);
        }
    };
    record(&mut stats, None, |value| {
        value.phase_timings_ns.compiler_identity =
            value.phase_timings_ns.compiler_identity.saturating_add(elapsed_ns(identity_started));
        if !identity.was_reused() {
            value.process_counts.fingerprint_queries += 8;
        }
    });
    let fingerprint = identity.fingerprint();
    if !supported_gfortran_major(fingerprint.major_version) {
        record_attempted_bypass(&mut stats, "unsupported-compiler-version");
        return pass_through(compiler, compiler_args, &environment);
    }
    let legacy_cpp_requires_observation =
        fingerprint.major_version <= 12 && invocation.preprocessing == Preprocessing::Cpp;
    let direct_request = if config.direct
        && invocation.compile_only
        && !invocation.syntax_only
        && !legacy_cpp_requires_observation
    {
        direct_request_key(compiler, compiler_args, &invocation, &cwd, &environment).ok()
    } else {
        None
    };
    let mut direct_compile_plan = None;
    if let Some(request_key) = &direct_request {
        match try_direct_restore(
            &DirectIndex::open(&config.cache_dir),
            request_key,
            &store,
            compiler,
            &invocation,
            &cwd,
            &environment,
            &identity,
            &mut stats,
        ) {
            Ok(DirectAttempt::Hit(manifest)) => {
                if let Err(error) = replay(&store, &manifest) {
                    record(&mut stats, Some(&manifest.action_key.to_string()), |value| {
                        value.observed_outcomes.launcher_failure += 1;
                    });
                    return Err(error.to_string());
                }
                record(&mut stats, Some(&manifest.action_key.to_string()), |value| {
                    value.hits += 1;
                    value.lookup_results.hits += 1;
                    value.observed_outcomes.cache_hit_success += 1;
                    value.direct_path.validated_hits += 1;
                    value.bytes_restored += manifest_payload_size(&manifest);
                });
                return Ok(0);
            }
            Ok(DirectAttempt::Compile(plan)) => {
                record(&mut stats, None, |value| {
                    value.direct_path.validated_compile_plans += 1;
                    value.miss_observation.validated_precompile_selections += 1;
                });
                direct_compile_plan = Some(plan);
            }
            Ok(DirectAttempt::Miss) => {}
            Err(reason) => record_direct_fallback(&mut stats, &reason),
        }
    }
    let (observation, direct_compile_record) = if let Some(plan) = direct_compile_plan {
        (plan.observation, Some(plan.record))
    } else {
        let probe_started = Instant::now();
        let mut probe_telemetry = ProbeTelemetry::default();
        let observation = match observe(
            compiler,
            &invocation,
            &cwd,
            &environment,
            fingerprint.major_version,
            &mut probe_telemetry,
        ) {
            Ok(value) => value,
            Err(_) => {
                record_probe_telemetry(&mut stats, probe_telemetry, probe_started);
                record_attempted_bypass(&mut stats, "dependency-probe");
                return pass_through(compiler, compiler_args, &environment);
            }
        };
        record_probe_telemetry(&mut stats, probe_telemetry, probe_started);
        (observation, None)
    };
    if invocation.syntax_only
        && observation
            .outputs
            .iter()
            .any(|output| matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule))
    {
        record_attempted_bypass(&mut stats, "syntax-only-module-outputs");
        return pass_through(compiler, compiler_args, &environment);
    }
    let action = direct_compile_record
        .as_ref()
        .map_or_else(
            || {
                build_action_key(
                    compiler,
                    &invocation,
                    fingerprint,
                    &cwd,
                    &environment,
                    &observation,
                )
            },
            |record| Ok(record.action_key),
        )
        .map_err(|error| error.to_string())?;
    let produces_modules = observation
        .outputs
        .iter()
        .any(|output| matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule));
    let module_dir = final_module_dir(&invocation, &cwd);
    let mut lock_plan = OutputLockPlan::new();
    for output in &observation.outputs {
        lock_plan.add_output(output.path.clone());
    }
    lock_plan.add_module_directory(
        module_dir.clone(),
        if produces_modules {
            ModuleDirectoryAccess::CompilerModuleProducer
        } else {
            ModuleDirectoryAccess::CompilerMissWithoutModules
        },
    );
    let output_locks = match OutputLocks::acquire_plan(store.root(), lock_plan) {
        Ok(locks) => locks,
        Err(_) => {
            record_attempted_bypass(&mut stats, "output-lock");
            return pass_through(compiler, compiler_args, &environment);
        }
    };
    if direct_compile_record.is_none() {
        match try_restore(&store, &action, fingerprint, &identity, &observation) {
            Ok(Some(manifest)) => {
                drop(output_locks);
                if let Some(request_key) = direct_request {
                    publish_direct_observation(
                        &config.cache_dir,
                        request_key,
                        &store,
                        compiler,
                        &invocation,
                        &cwd,
                        &environment,
                        &identity,
                        &observation,
                        &manifest,
                        &mut stats,
                    );
                }
                if let Err(error) = replay(&store, &manifest) {
                    record(&mut stats, Some(&action.to_string()), |value| {
                        value.observed_outcomes.launcher_failure += 1;
                    });
                    return Err(error.to_string());
                }
                record(&mut stats, Some(&action.to_string()), |value| {
                    value.hits += 1;
                    value.lookup_results.hits += 1;
                    value.observed_outcomes.cache_hit_success += 1;
                    value.bytes_restored += manifest_payload_size(&manifest);
                });
                return Ok(0);
            }
            Ok(None) | Err(CacheError::Miss) => {}
            Err(CacheError::Corrupt(_)) | Err(CacheError::Manifest(_)) => {
                record(&mut stats, Some(&action.to_string()), |value| {
                    value.corruption += 1;
                    value.cache_read_failures += 1;
                });
            }
            Err(_) => {
                record(&mut stats, Some(&action.to_string()), |value| {
                    value.cache_read_failures += 1;
                });
            }
        }
    }
    record(&mut stats, Some(&action.to_string()), |value| {
        value.misses += 1;
        value.lookup_results.misses += 1;
    });
    if direct_compile_record.as_ref().is_some_and(|record| {
        record.validate_filesystem().is_err() || identity.revalidate().is_err()
    }) {
        record_direct_fallback(&mut stats, "precompile-revalidation");
        drop(output_locks);
        return pass_through(compiler, compiler_args, &environment);
    }
    let predicted_module_names = predicted_module_names(&observation);
    let module_snapshot = if config.read_only {
        None
    } else {
        DirectorySnapshot::read_for_outputs(&module_dir, &predicted_module_names).ok()
    };
    let compile_started = Instant::now();
    let output = CompilerCommand::new(compiler)
        .args(compiler_args.iter().cloned())
        .current_dir(&cwd)
        .environment(environment.clone())
        .tee_output(true)
        .run()
        .map_err(|error| error.to_string())?;
    record(&mut stats, None, |value| {
        value.process_counts.real_compilations += 1;
        value.phase_timings_ns.real_compilation =
            value.phase_timings_ns.real_compilation.saturating_add(elapsed_ns(compile_started));
    });
    let exit_code = status_code(&output);
    if !output.status.success() {
        record(&mut stats, Some(&action.to_string()), |value| {
            value.compiler_failures += 1;
            value.observed_outcomes.compiler_failure += 1;
        });
        return Ok(exit_code);
    }
    record(&mut stats, Some(&action.to_string()), |value| {
        value.observed_outcomes.compiler_success += 1;
    });
    if config.read_only {
        return Ok(exit_code);
    }
    let Some(module_snapshot) = module_snapshot else {
        record_nonpublication(&mut stats, "module-output-snapshot");
        return Ok(exit_code);
    };
    let current_modules =
        match DirectorySnapshot::read_for_outputs(&module_dir, &predicted_module_names) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                record_nonpublication(&mut stats, "module-output-snapshot");
                return Ok(exit_code);
            }
        };
    if module_snapshot.validate_changes(&current_modules, &predicted_module_names).is_err() {
        record_nonpublication(&mut stats, "real-module-output-mismatch");
        return Ok(exit_code);
    }
    let validation_started = Instant::now();
    if validate_real_depfile_targets(&invocation, &observation, &cwd).is_err() {
        record_nonpublication(&mut stats, "real-depfile-mismatch");
        return Ok(exit_code);
    }
    if invocation.dependency_mode == Some(DependencyMode::Md) {
        if !inputs_unchanged(&observation.inputs) {
            record_nonpublication(&mut stats, "inputs-changed-during-compilation");
            return Ok(exit_code);
        }
        if observation.preprocessor.is_some() {
            let preprocessing_started = Instant::now();
            record(&mut stats, None, |value| value.process_counts.preprocessing_probes += 1);
            let post_preprocessor = match observe_preprocessing_only(
                compiler,
                &invocation,
                &cwd,
                &environment,
                fingerprint.major_version,
            ) {
                Ok(value) => value,
                Err(_) => {
                    record_nonpublication(&mut stats, "preprocessor-validation-failed");
                    return Ok(exit_code);
                }
            };
            record(&mut stats, None, |value| {
                value.phase_timings_ns.preprocessing_qualification = value
                    .phase_timings_ns
                    .preprocessing_qualification
                    .saturating_add(elapsed_ns(preprocessing_started));
            });
            if post_preprocessor.as_ref() != observation.preprocessor.as_ref() {
                record_nonpublication(&mut stats, "preprocessor-changed-during-compilation");
                return Ok(exit_code);
            }
        }
        record(&mut stats, None, |value| {
            value.miss_observation.real_md_validation_successes += 1;
        });
    } else {
        record(&mut stats, None, |value| {
            value.miss_observation.post_compile_probe_attempts += 1;
        });
        let post_probe_started = Instant::now();
        let mut post_probe_telemetry = ProbeTelemetry::default();
        let post_observation = match observe(
            compiler,
            &invocation,
            &cwd,
            &environment,
            fingerprint.major_version,
            &mut post_probe_telemetry,
        ) {
            Ok(value) => value,
            Err(_) => {
                record_probe_telemetry(&mut stats, post_probe_telemetry, post_probe_started);
                return Ok(exit_code);
            }
        };
        record_probe_telemetry(&mut stats, post_probe_telemetry, post_probe_started);
        if observation != post_observation {
            record_nonpublication(&mut stats, "inputs-changed-during-compilation");
            return Ok(exit_code);
        }
    }
    if direct_compile_record.as_ref().is_some_and(|record| record.validate_filesystem().is_err()) {
        record_nonpublication(&mut stats, "direct-observation-changed");
        return Ok(exit_code);
    }
    if identity.revalidate().is_err() {
        record_nonpublication(&mut stats, "compiler-identity-changed");
        return Ok(exit_code);
    }
    record(&mut stats, None, |value| {
        value.phase_timings_ns.post_compile_validation = value
            .phase_timings_ns
            .post_compile_validation
            .saturating_add(elapsed_ns(validation_started));
    });
    let publication_started = Instant::now();
    match store_result(&store, action, fingerprint, &observation, &output) {
        Ok((bytes, manifest)) => {
            record(&mut stats, Some(&action.to_string()), |value| value.bytes_stored += bytes);
            if let Some(request_key) = direct_request {
                publish_direct_observation(
                    &config.cache_dir,
                    request_key,
                    &store,
                    compiler,
                    &invocation,
                    &cwd,
                    &environment,
                    &identity,
                    &observation,
                    &manifest,
                    &mut stats,
                );
            }
            record(&mut stats, None, |value| {
                value.phase_timings_ns.publication = value
                    .phase_timings_ns
                    .publication
                    .saturating_add(elapsed_ns(publication_started));
            });
        }
        Err(_) => {
            record(&mut stats, Some(&action.to_string()), |value| {
                value.cache_write_failures += 1;
            });
            record_nonpublication(&mut stats, "cache-publication");
        }
    }
    Ok(exit_code)
}

#[allow(clippy::too_many_arguments)]
fn publish_direct_observation(
    cache_dir: &Path,
    request_key: DirectRequestKey,
    store: &CacheStore,
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    identity: &ValidatedCompilerIdentity,
    observation: &Observation,
    manifest: &Manifest,
    stats: &mut PendingStats,
) {
    let record_value = match build_direct_record(
        compiler,
        invocation,
        cwd,
        environment,
        identity,
        observation,
        manifest,
    ) {
        Ok(value) => value,
        Err(_) => {
            record_direct_fallback(stats, "record-publication");
            return;
        }
    };
    if DirectIndex::open(cache_dir)
        .publish_with_manifest_check(request_key, record_value, |candidate| {
            store.load_manifest_metadata(candidate).ok().flatten().is_some()
        })
        .is_err()
    {
        record_direct_fallback(stats, "index-publication");
    }
}

fn direct_request_key(
    compiler: &OsStr,
    compiler_args: &[OsString],
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> Result<DirectRequestKey, String> {
    let source = invocation.source.as_ref().ok_or_else(|| "missing source input".to_owned())?;
    let source_path = absolute_output(cwd, PathBuf::from(source));
    let source_input = read_stable(&source_path)?;
    let relevant_environment = relevant_environment(environment);
    let semantics = vec![
        (b"action-schema".to_vec(), KEY_SCHEMA.to_vec()),
        (b"preprocessing".to_vec(), format!("{:?}", invocation.preprocessing).into_bytes()),
        (b"dependency-mode".to_vec(), format!("{:?}", invocation.dependency_mode).into_bytes()),
        (b"umask".to_vec(), effective_umask().to_le_bytes().to_vec()),
    ];
    Ok(DirectRequestKey::compute(
        compiler,
        cwd,
        compiler_args,
        &relevant_environment,
        &source_path,
        DirectDigest::from_bytes(source_input.digest),
        &semantics,
    ))
}

#[allow(clippy::too_many_arguments)]
fn try_direct_restore(
    index: &DirectIndex,
    request_key: &DirectRequestKey,
    store: &CacheStore,
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    identity: &ValidatedCompilerIdentity,
    stats: &mut PendingStats,
) -> Result<DirectAttempt, String> {
    let started = Instant::now();
    let lookup = index
        .lookup_with_manifest_check(request_key, |action| {
            store.load_manifest_metadata(action).ok().flatten().is_some()
        })
        .map_err(|_| "direct-index-read".to_owned())?;
    record(stats, None, |value| {
        value.direct_path.candidates_found = value.direct_path.candidates_found.saturating_add(
            lookup.candidates.len().saturating_add(lookup.missing_result_candidates.len()) as u64,
        );
        value.direct_path.missing_result_manifests = value
            .direct_path
            .missing_result_manifests
            .saturating_add(lookup.missing_result_candidates.len() as u64);
        if matches!(
            lookup.miss_reason,
            Some(
                DirectMissReason::Corrupt
                    | DirectMissReason::Oversized
                    | DirectMissReason::UnsupportedSchema(_)
                    | DirectMissReason::RequestKeyMismatch
            )
        ) {
            value.direct_path.corrupt_records += 1;
        }
    });
    if lookup.is_miss() {
        record(stats, None, |value| {
            value.phase_timings_ns.direct_validation =
                value.phase_timings_ns.direct_validation.saturating_add(elapsed_ns(started));
        });
        return Ok(DirectAttempt::Miss);
    }

    let compiler_context = DirectDigest::from_bytes(identity.context_digest());
    let compiler_digest = DirectDigest::from_bytes(*identity.fingerprint().digest());
    let mut compile_plan = None;
    for candidate in &lookup.candidates {
        let (observation, validated) = match validate_direct_candidate(
            candidate,
            compiler_context,
            compiler_digest,
            compiler,
            invocation,
            cwd,
            environment,
            identity,
        ) {
            Ok(value) => value,
            Err(reason) => {
                record_direct_fallback(stats, reason);
                continue;
            }
        };

        let mut lock_plan = OutputLockPlan::new();
        for output in &observation.outputs {
            lock_plan.add_output(output.path.clone());
        }
        let restores_modules = observation
            .outputs
            .iter()
            .any(|output| matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule));
        lock_plan.add_module_directory(
            final_module_dir(invocation, cwd),
            if restores_modules {
                ModuleDirectoryAccess::ModuleRestore
            } else {
                ModuleDirectoryAccess::CompilerMissWithoutModules
            },
        );
        let _locks = OutputLocks::acquire_plan(store.root(), lock_plan)
            .map_err(|_| "direct-output-lock".to_owned())?;
        if validate_restore_output_contract(&observation).is_err() {
            record_direct_fallback(stats, "output-contract");
            continue;
        }
        let mut destinations = RestoreDestinations::new();
        for output in &observation.outputs {
            destinations.insert_with_role(&output.logical_name, output.role, &output.path);
        }
        let prepared = match store.prepare_restore(&candidate.action_key, &destinations) {
            Ok(value) => value,
            Err(_) => {
                record_direct_fallback(stats, "result-staging");
                compile_plan.get_or_insert_with(|| DirectCompilePlan {
                    record: candidate.clone(),
                    observation,
                });
                continue;
            }
        };
        if prepared.manifest().compiler_digest != identity.fingerprint().digest_hex()
            || !direct_manifest_matches(candidate, prepared.manifest())
            || validated.revalidate().is_err()
            || identity.revalidate().is_err()
            || validate_restore_output_contract(&observation).is_err()
        {
            record_direct_fallback(stats, "precommit-revalidation");
            continue;
        }
        let manifest = prepared.commit().map_err(|_| "direct-commit".to_owned())?;
        record(stats, None, |value| {
            value.phase_timings_ns.direct_validation =
                value.phase_timings_ns.direct_validation.saturating_add(elapsed_ns(started));
        });
        return Ok(DirectAttempt::Hit(manifest));
    }
    for candidate in &lookup.missing_result_candidates {
        let (observation, _) = match validate_direct_candidate(
            candidate,
            compiler_context,
            compiler_digest,
            compiler,
            invocation,
            cwd,
            environment,
            identity,
        ) {
            Ok(value) => value,
            Err(reason) => {
                record_direct_fallback(stats, reason);
                continue;
            }
        };
        compile_plan
            .get_or_insert_with(|| DirectCompilePlan { record: candidate.clone(), observation });
    }
    record(stats, None, |value| {
        value.phase_timings_ns.direct_validation =
            value.phase_timings_ns.direct_validation.saturating_add(elapsed_ns(started));
    });
    Ok(compile_plan.map_or(DirectAttempt::Miss, |plan| DirectAttempt::Compile(Box::new(plan))))
}

#[allow(clippy::too_many_arguments)]
fn validate_direct_candidate<'a>(
    candidate: &'a DirectRecord,
    compiler_context: DirectDigest,
    compiler_digest: DirectDigest,
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    identity: &ValidatedCompilerIdentity,
) -> Result<(Observation, crate::cache::direct::ValidatedDirectRecord<'a>), &'static str> {
    if candidate.compiler.context_key != compiler_context
        || candidate.compiler.compiler_digest != compiler_digest
    {
        return Err("compiler-witness");
    }
    let validated = candidate.validate_filesystem().map_err(|_| "filesystem-witness")?;
    let observation = observation_from_direct(candidate).map_err(|_| "record-conversion")?;
    let reconstructed = build_action_key(
        compiler,
        invocation,
        identity.fingerprint(),
        cwd,
        environment,
        &observation,
    )
    .map_err(|_| "action-key")?;
    if reconstructed != candidate.action_key {
        return Err("action-key");
    }
    if validate_restore_output_contract(&observation).is_err() {
        return Err("output-contract");
    }
    Ok((observation, validated))
}

fn direct_manifest_matches(record: &DirectRecord, manifest: &Manifest) -> bool {
    if record.expected_artifacts.len() != manifest.artifacts.len() {
        return false;
    }
    record.expected_artifacts.iter().all(|expected| {
        manifest.artifacts.iter().any(|artifact| {
            artifact.kind == expected.kind
                && artifact.logical_name == expected.logical_name
                && artifact.blob.digest == expected.digest.to_string()
                && artifact.blob.size == expected.size
                && artifact.blob.mode == expected.mode
        })
    })
}

fn observation_from_direct(record: &DirectRecord) -> Result<Observation, String> {
    let inputs = record
        .inputs
        .iter()
        .map(|input| InputFile {
            raw_path: input.raw_path.as_bytes().to_vec(),
            observed_path: input.path.resolved_path.to_path_buf(),
            path: input.path.canonical_path.to_path_buf(),
            digest: *input.digest.as_bytes(),
            size: input.size,
        })
        .collect();
    let dependencies = record
        .resolution
        .positive
        .iter()
        .map(|witness| {
            let input = record
                .inputs
                .get(witness.selected_input)
                .ok_or_else(|| "direct resolution selected an unknown input".to_owned())?;
            Ok(ObservedDependency {
                raw_path: witness.requested_name.as_bytes().to_vec(),
                observed_path: witness.selected_path.resolved_path.to_path_buf(),
                path: input.path.canonical_path.to_path_buf(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let outputs = record
        .expected_artifacts
        .iter()
        .map(|artifact| {
            let role = match artifact.kind {
                ArtifactKind::Object => DestinationRole::Object,
                ArtifactKind::Module => DestinationRole::Module,
                ArtifactKind::Submodule => DestinationRole::Submodule,
                ArtifactKind::Dependency => DestinationRole::Dependency,
            };
            let module = matches!(artifact.kind, ArtifactKind::Module | ArtifactKind::Submodule);
            Ok(ExpectedArtifact {
                logical_name: artifact.logical_name.clone(),
                kind: artifact.kind,
                role,
                path: artifact.destination.to_path_buf(),
                probe_digest: module.then_some(*artifact.digest.as_bytes()),
                probe_size: module.then_some(artifact.size),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut depfile_shape = DepfileShape::default();
    for rule in &record.probe_rules {
        let targets = rule
            .targets
            .iter()
            .map(|target| match target.kind {
                DirectDepfileTargetKind::Ordinary => {
                    DepfileTarget::Ordinary(target.bytes.as_bytes().to_vec())
                }
                DirectDepfileTargetKind::GeneratedModule => {
                    DepfileTarget::GeneratedModule(target.bytes.as_bytes().to_vec())
                }
            })
            .collect::<Vec<_>>();
        if rule.prerequisites.is_empty() {
            depfile_shape.dummy_targets.extend(targets);
        } else {
            let prerequisites = rule
                .prerequisites
                .iter()
                .map(|prerequisite| match prerequisite.kind {
                    DirectDepfilePrerequisiteKind::Ordinary => {
                        DepfilePrerequisite::Ordinary(prerequisite.bytes.as_bytes().to_vec())
                    }
                    DirectDepfilePrerequisiteKind::GeneratedModule => {
                        DepfilePrerequisite::GeneratedModule(prerequisite.bytes.as_bytes().to_vec())
                    }
                })
                .collect();
            depfile_shape.primary_rules.push(ObservedDepfileRule { targets, prerequisites });
        }
    }
    let preprocessor = match &record.preprocessor {
        PreprocessorShape::Inactive => None,
        PreprocessorShape::CompilerObserved {
            stdout_digest,
            stdout_size,
            stderr_digest,
            stderr_size,
            automatic_lowercase_source,
        } => Some(PreprocessorObservation {
            stdout_digest: *stdout_digest.as_bytes(),
            stdout_size: *stdout_size,
            stderr_digest: *stderr_digest.as_bytes(),
            stderr_size: *stderr_size,
            automatic_lowercase_source: *automatic_lowercase_source,
        }),
    };
    Ok(Observation { inputs, dependencies, outputs, depfile_shape, preprocessor })
}

#[allow(clippy::too_many_arguments)]
fn build_direct_record(
    _compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    identity: &ValidatedCompilerIdentity,
    observation: &Observation,
    manifest: &Manifest,
) -> Result<DirectRecord, String> {
    if !invocation.forced_inputs.is_empty() || direct_search_environment_is_unmodeled(environment) {
        return Err("direct search semantics are incomplete".into());
    }
    let source = invocation.source.as_ref().ok_or_else(|| "missing source input".to_owned())?;
    let source_path = fs::canonicalize(absolute_output(cwd, PathBuf::from(source)))
        .map_err(|error| error.to_string())?;
    let input_bytes = observation
        .inputs
        .iter()
        .map(|input| fs::read(&input.path).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let features = ObservedSearchFeatures::scan(input_bytes.iter().map(Vec::as_slice));
    let mut include_parents = observation
        .dependencies
        .iter()
        .filter(|dependency| dependency.path != source_path)
        .flat_map(|dependency| {
            [dependency.observed_path.parent(), dependency.path.parent()]
                .into_iter()
                .flatten()
                .map(Path::to_path_buf)
        })
        .collect::<Vec<_>>();
    include_parents.sort();
    include_parents.dedup();
    let search_environment = EnvironmentSearchPaths::complete_empty();
    let model = invocation
        .search_resolution_model(ResolutionContext {
            cwd,
            include_parents: &include_parents,
            environment: &search_environment,
            observed_features: &features,
        })
        .map_err(|error| error.to_string())?;
    let dependencies = observation
        .dependencies
        .iter()
        .map(|dependency| DependencyObservation {
            prerequisite: dependency.raw_path.clone(),
            resolved_path: dependency.observed_path.clone(),
            kind: if dependency.path == source_path {
                DependencyResolutionKind::Source
            } else if is_module_path(&dependency.path) {
                DependencyResolutionKind::ModuleOrInclude
            } else {
                DependencyResolutionKind::Include
            },
        })
        .collect::<Vec<_>>();
    let proof = model.prove(&dependencies).map_err(|error| error.to_string())?;

    let inputs = observation
        .inputs
        .iter()
        .map(|input| {
            DirectInput::capture(path_from_bytes(&input.raw_path).as_os_str(), &input.observed_path)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut roots = Vec::new();
    let mut root_paths = BTreeSet::new();
    for selected in &proof.selected {
        for root in &selected.possible_roots {
            if root.path.is_dir() && root_paths.insert(root.path.clone()) {
                roots.push(
                    PathWitness::capture(&root.path, WitnessFileType::Directory)
                        .map_err(|error| error.to_string())?,
                );
            }
        }
    }
    let mut positive = Vec::new();
    for selected in &proof.selected {
        let canonical =
            fs::canonicalize(&selected.selected_path).map_err(|error| error.to_string())?;
        let selected_input = observation
            .inputs
            .iter()
            .position(|input| input.path == canonical || input.path == selected.selected_path)
            .ok_or_else(|| "resolution proof selected an unknown input".to_owned())?;
        let earlier_candidates = proof
            .negative_candidates
            .iter()
            .filter(|negative| negative.prerequisite == selected.prerequisite)
            .map(|negative| {
                AbsentPathWitness::capture(&negative.path).map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        positive.push(PositiveResolutionWitness {
            kind: direct_resolution_kind(selected.kind),
            requested_name: EncodedOsString::new(selected.prerequisite.clone()),
            selected_input,
            selected_path: PathWitness::capture(&selected.selected_path, WitnessFileType::Regular)
                .map_err(|error| error.to_string())?,
            earlier_candidates,
        });
    }

    let expected_artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            let observed = observation
                .outputs
                .iter()
                .find(|output| output.logical_name == artifact.logical_name)
                .ok_or_else(|| "manifest contains an unobserved artifact".to_owned())?;
            Ok(DirectExpectedArtifact {
                kind: artifact.kind,
                logical_name: artifact.logical_name.clone(),
                destination: EncodedOsString::from_path(&observed.path),
                digest: DirectDigest::parse(&artifact.blob.digest).map_err(|e| e.to_string())?,
                size: artifact.blob.size,
                mode: artifact.blob.mode,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let probe_rules = direct_probe_rules(observation);
    let depfile = build_direct_depfile(invocation, observation, manifest, &probe_rules)?;
    let preprocessor =
        observation.preprocessor.as_ref().map_or(PreprocessorShape::Inactive, |value| {
            PreprocessorShape::CompilerObserved {
                stdout_digest: DirectDigest::from_bytes(value.stdout_digest),
                stdout_size: value.stdout_size,
                stderr_digest: DirectDigest::from_bytes(value.stderr_digest),
                stderr_size: value.stderr_size,
                automatic_lowercase_source: value.automatic_lowercase_source,
            }
        });
    Ok(DirectRecord {
        schema_version: DIRECT_RECORD_SCHEMA_VERSION,
        compiler: CompilerWitnessRef {
            context_key: DirectDigest::from_bytes(identity.context_digest()),
            compiler_digest: DirectDigest::from_bytes(*identity.fingerprint().digest()),
        },
        inputs,
        resolution: SearchResolutionWitnesses { roots, positive, negative: Vec::new() },
        expected_artifacts,
        probe_rules,
        depfile,
        preprocessor,
        action_key: manifest.action_key,
    })
}

fn build_direct_depfile(
    invocation: &GfortranInvocation,
    observation: &Observation,
    manifest: &Manifest,
    probe_rules: &[DirectDepfileRuleShape],
) -> Result<Option<DirectDepfileShape>, String> {
    let Some(mode) = invocation.dependency_mode else {
        return Ok(None);
    };
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == ArtifactKind::Dependency)
        .ok_or_else(|| "dependency mode is missing a cached depfile".to_owned())?;
    let destination = observation
        .outputs
        .iter()
        .find(|output| output.kind == ArtifactKind::Dependency)
        .ok_or_else(|| "dependency mode is missing an observed depfile".to_owned())?;
    Ok(Some(DirectDepfileShape {
        mode: match mode {
            DependencyMode::Md => crate::cache::direct::DependencyMode::Md,
            DependencyMode::Mmd => crate::cache::direct::DependencyMode::Mmd,
        },
        destination: EncodedOsString::from_path(&destination.path),
        target_modifiers: invocation
            .dependency_target_modifiers
            .iter()
            .map(|value| EncodedOsString::from_os_str(value))
            .collect(),
        rules: probe_rules.to_vec(),
        digest: DirectDigest::parse(&artifact.blob.digest).map_err(|e| e.to_string())?,
        size: artifact.blob.size,
    }))
}

fn direct_probe_rules(observation: &Observation) -> Vec<DirectDepfileRuleShape> {
    let mut rules = observation
        .depfile_shape
        .primary_rules
        .iter()
        .map(|rule| DirectDepfileRuleShape {
            targets: rule.targets.iter().map(direct_depfile_target).collect(),
            prerequisites: rule.prerequisites.iter().map(direct_depfile_prerequisite).collect(),
        })
        .collect::<Vec<_>>();
    rules.extend(observation.depfile_shape.dummy_targets.iter().map(|target| {
        DirectDepfileRuleShape {
            targets: vec![direct_depfile_target(target)],
            prerequisites: Vec::new(),
        }
    }));
    rules
}

fn direct_depfile_prerequisite(
    prerequisite: &DepfilePrerequisite,
) -> DirectDepfilePrerequisiteShape {
    match prerequisite {
        DepfilePrerequisite::Ordinary(bytes) => DirectDepfilePrerequisiteShape {
            kind: DirectDepfilePrerequisiteKind::Ordinary,
            bytes: EncodedOsString::new(bytes.clone()),
        },
        DepfilePrerequisite::GeneratedModule(bytes) => DirectDepfilePrerequisiteShape {
            kind: DirectDepfilePrerequisiteKind::GeneratedModule,
            bytes: EncodedOsString::new(bytes.clone()),
        },
    }
}

fn direct_depfile_target(target: &DepfileTarget) -> DirectDepfileTargetShape {
    match target {
        DepfileTarget::Ordinary(bytes) => DirectDepfileTargetShape {
            kind: DirectDepfileTargetKind::Ordinary,
            bytes: EncodedOsString::new(bytes.clone()),
        },
        DepfileTarget::GeneratedModule(bytes) => DirectDepfileTargetShape {
            kind: DirectDepfileTargetKind::GeneratedModule,
            bytes: EncodedOsString::new(bytes.clone()),
        },
    }
}

fn direct_resolution_kind(kind: DependencyResolutionKind) -> ResolutionKind {
    match kind {
        DependencyResolutionKind::Source => ResolutionKind::Source,
        DependencyResolutionKind::Include => ResolutionKind::Include,
        DependencyResolutionKind::ForcedInput(_) => ResolutionKind::ForcedInput,
        DependencyResolutionKind::Module => ResolutionKind::Module,
        DependencyResolutionKind::Submodule => ResolutionKind::Submodule,
        DependencyResolutionKind::IntrinsicModule => ResolutionKind::IntrinsicModule,
        DependencyResolutionKind::ModuleOrInclude => ResolutionKind::ModuleOrInclude,
    }
}

fn direct_search_environment_is_unmodeled(environment: &[(OsString, OsString)]) -> bool {
    const NAMES: &[&[u8]] = &[
        b"CPATH",
        b"C_INCLUDE_PATH",
        b"CPLUS_INCLUDE_PATH",
        b"OBJC_INCLUDE_PATH",
        b"GFORTRAN_INCLUDE_PATH",
        b"GCC_EXEC_PREFIX",
        b"DEPENDENCIES_OUTPUT",
        b"SUNPRO_DEPENDENCIES",
    ];
    environment.iter().any(|(name, value)| {
        !value.is_empty() && NAMES.iter().any(|candidate| encoded_os(name) == *candidate)
    })
}

fn relevant_environment(environment: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    environment
        .iter()
        .filter(|(name, _)| environment_affects_compiler_output(name))
        .cloned()
        .collect()
}

fn is_module_path(path: &Path) -> bool {
    extension_is(path, b"mod") || extension_is(path, b"smod")
}

fn extension_is(path: &Path, expected: &[u8]) -> bool {
    path.extension().is_some_and(|extension| encoded_os(extension).eq_ignore_ascii_case(expected))
}

fn final_module_dir(invocation: &GfortranInvocation, cwd: &Path) -> PathBuf {
    invocation
        .module_dir
        .as_ref()
        .map(PathBuf::from)
        .map_or_else(|| cwd.to_path_buf(), |path| absolute_output(cwd, path))
}

fn predicted_module_names(observation: &Observation) -> BTreeSet<Vec<u8>> {
    observation
        .outputs
        .iter()
        .filter(|output| matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule))
        .filter_map(|output| output.path.file_name())
        .map(encoded_os)
        .collect()
}

fn observe(
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    compiler_major: u32,
    telemetry: &mut ProbeTelemetry,
) -> Result<Observation, String> {
    let temporary = tempfile::tempdir().map_err(|error| error.to_string())?;
    let preprocessor = match invocation.preprocessing {
        Preprocessing::Auto => {
            telemetry.preprocessing_probes += 1;
            Some(qualify_automatic_preprocessing(compiler, invocation, cwd, environment)?)
        }
        Preprocessing::Cpp if compiler_major <= 12 => {
            telemetry.preprocessing_probes += 1;
            Some(observe_legacy_preprocessing(compiler, invocation, cwd, environment)?)
        }
        _ => None,
    };
    let module_dir = temporary.path().join("modules");
    fs::create_dir(&module_dir).map_err(|error| error.to_string())?;
    let depfile_path = temporary.path().join("dependencies.d");
    let probe_args = invocation
        .dependency_probe_argv(depfile_path.as_os_str(), module_dir.as_os_str())
        .map_err(|error| error.to_string())?;
    telemetry.dependency_probes += 1;
    let probe = CompilerCommand::new(compiler)
        .args(probe_args)
        .current_dir(cwd)
        .environment(environment.iter().cloned())
        .run()
        .map_err(|error| error.to_string())?;
    if !probe.status.success() {
        return Err("dependency probe failed".into());
    }
    let depfile_bytes = fs::read(&depfile_path).map_err(|error| error.to_string())?;
    let depfile = parse_depfile(&depfile_bytes).map_err(|error| error.to_string())?;
    let probe_modules = discover_probe_modules(&depfile, cwd, &module_dir)?;
    let outputs = expected_outputs(invocation, &probe_modules.modules, cwd)?;
    let (inputs, dependencies) =
        read_inputs(&depfile, invocation, cwd, &probe_modules.canonical_paths, &outputs)?;
    let input_bytes = inputs
        .iter()
        .map(|input| fs::read(&input.path).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let search_features = ObservedSearchFeatures::scan(input_bytes.iter().map(Vec::as_slice));
    if !invocation.permits_complete_depfile_observation(&search_features) {
        return Err(
            "preprocessor filesystem queries are not completely represented by depfiles".into()
        );
    }
    let depfile_shape = depfile_shape(
        &depfile,
        &probe_modules.generated_targets,
        &probe_modules.canonical_paths,
        cwd,
        &outputs,
    )?;
    Ok(Observation { inputs, dependencies, outputs, depfile_shape, preprocessor })
}

fn observe_preprocessing_only(
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    compiler_major: u32,
) -> Result<Option<PreprocessorObservation>, String> {
    match invocation.preprocessing {
        Preprocessing::Auto => {
            qualify_automatic_preprocessing(compiler, invocation, cwd, environment).map(Some)
        }
        Preprocessing::Cpp if compiler_major <= 12 => {
            observe_legacy_preprocessing(compiler, invocation, cwd, environment).map(Some)
        }
        _ => Ok(None),
    }
}

fn observe_legacy_preprocessing(
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> Result<PreprocessorObservation, String> {
    let arguments =
        invocation.preprocessor_observation_argv().map_err(|error| error.to_string())?;
    let output = CompilerCommand::new(compiler)
        .args(arguments)
        .current_dir(cwd)
        .environment(environment.iter().cloned())
        .run()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("preprocessor observation failed".into());
    }
    Ok(PreprocessorObservation {
        stdout_digest: *blake3::hash(&output.stdout).as_bytes(),
        stdout_size: output.stdout.len() as u64,
        stderr_digest: *blake3::hash(&output.stderr).as_bytes(),
        stderr_size: output.stderr.len() as u64,
        automatic_lowercase_source: false,
    })
}

fn qualify_automatic_preprocessing(
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> Result<PreprocessorObservation, String> {
    let source = invocation.source.as_ref().ok_or_else(|| "missing source input".to_owned())?;
    let source_path = absolute_output(cwd, PathBuf::from(source));
    let source_bytes = fs::read(&source_path)
        .map_err(|error| format!("cannot read source input {}: {error}", source_path.display()))?;
    let arguments = invocation.preprocessor_identity_argv().map_err(|error| error.to_string())?;
    let output = CompilerCommand::new(compiler)
        .args(arguments)
        .current_dir(cwd)
        .environment(environment.iter().cloned())
        .run()
        .map_err(|error| error.to_string())?;
    if !output.status.success() || !preprocessor_output_is_identity(&output.stdout, &source_bytes) {
        return Err("automatic preprocessing is not byte-identical".into());
    }
    Ok(PreprocessorObservation {
        stdout_digest: *blake3::hash(&output.stdout).as_bytes(),
        stdout_size: output.stdout.len() as u64,
        stderr_digest: *blake3::hash(&output.stderr).as_bytes(),
        stderr_size: output.stderr.len() as u64,
        automatic_lowercase_source: true,
    })
}

fn preprocessor_output_is_identity(output: &[u8], source: &[u8]) -> bool {
    if output_matches_source_with_newline_prefix(output, source) {
        return true;
    }
    !source.ends_with(b"\n")
        && output
            .strip_suffix(b"\n")
            .is_some_and(|trimmed| output_matches_source_with_newline_prefix(trimmed, source))
}

fn output_matches_source_with_newline_prefix(output: &[u8], source: &[u8]) -> bool {
    let Some(prefix_length) = output.len().checked_sub(source.len()) else {
        return false;
    };
    output[..prefix_length].iter().all(|byte| *byte == b'\n') && output[prefix_length..] == *source
}

fn read_inputs(
    depfile: &Depfile,
    invocation: &GfortranInvocation,
    cwd: &Path,
    generated_modules: &BTreeSet<PathBuf>,
    outputs: &[ExpectedArtifact],
) -> Result<(Vec<InputFile>, Vec<ObservedDependency>), String> {
    let projected = ProjectedOutputs::resolve(outputs)?;
    let mut unique = BTreeMap::new();
    let source = invocation.source.as_ref().ok_or_else(|| "missing source input".to_owned())?;
    let source_observed = absolute_output(cwd, PathBuf::from(source));
    let source_canonical = resolve_observed_input(&source_observed, generated_modules, &projected)?;
    unique.insert(source_canonical.clone(), (encoded_os(source), source_observed));
    let mut dependencies = vec![ObservedDependency {
        raw_path: encoded_os(source),
        observed_path: absolute_output(cwd, PathBuf::from(source)),
        path: source_canonical,
    }];
    for rule in &depfile.rules {
        if rule.is_dummy() {
            continue;
        }
        for encoded in &rule.prerequisites {
            let path = path_from_bytes(encoded);
            let path = if path.is_absolute() { path } else { cwd.join(path) };
            if let Some(canonical) = resolve_optional_input(&path, generated_modules, &projected)? {
                dependencies.push(ObservedDependency {
                    raw_path: encoded.clone(),
                    observed_path: path.clone(),
                    path: canonical.clone(),
                });
                unique.entry(canonical).or_insert_with(|| (encoded.clone(), path));
            }
        }
    }
    let mut inputs = Vec::with_capacity(unique.len());
    for (path, (raw_path, observed_path)) in unique {
        inputs.push(read_stable_with_paths(&path, raw_path, observed_path)?);
    }
    Ok((inputs, dependencies))
}

fn resolve_observed_input(
    path: &Path,
    generated_modules: &BTreeSet<PathBuf>,
    projected: &ProjectedOutputs,
) -> Result<PathBuf, String> {
    resolve_optional_input(path, generated_modules, projected)?
        .ok_or_else(|| format!("source input collides with a compiler output: {}", path.display()))
}

fn resolve_optional_input(
    path: &Path,
    generated_modules: &BTreeSet<PathBuf>,
    projected: &ProjectedOutputs,
) -> Result<Option<PathBuf>, String> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        format!("cannot resolve compiler dependency {}: {error}", path.display())
    })?;
    if generated_modules.contains(&canonical) {
        return Ok(None);
    }
    if let Some((expected_digest, expected_size)) = projected.modules.get(&canonical) {
        let current = read_stable(&canonical)?;
        if current.digest == *expected_digest && current.size == *expected_size {
            return Ok(None);
        }
        return Err(format!(
            "compiler dependency collides with a different projected module output: {}",
            path.display()
        ));
    }
    if projected.collisions.contains(&canonical) {
        return Err(format!(
            "compiler dependency collides with a projected output: {}",
            path.display()
        ));
    }
    let metadata = fs::metadata(&canonical).map_err(|error| {
        format!("cannot inspect compiler dependency {}: {error}", path.display())
    })?;
    if file_identity(&metadata).is_some_and(|identity| projected.identities.contains_key(&identity))
    {
        return Err(format!("compiler dependency aliases a projected output: {}", path.display()));
    }
    Ok(Some(canonical))
}

struct ProjectedOutputs {
    modules: BTreeMap<PathBuf, ([u8; 32], u64)>,
    collisions: BTreeSet<PathBuf>,
    identities: BTreeMap<FileIdentity, PathBuf>,
}

impl ProjectedOutputs {
    fn resolve(outputs: &[ExpectedArtifact]) -> Result<Self, String> {
        let mut modules = BTreeMap::new();
        let mut collisions = BTreeSet::new();
        let mut identities = BTreeMap::new();
        let mut destinations = BTreeSet::new();
        for output in outputs {
            let destination = normalize_output_path(&output.path);
            if !destinations.insert(destination.clone()) {
                return Err(format!(
                    "projected outputs resolve to the same destination: {}",
                    destination.display()
                ));
            }
            let metadata = match fs::symlink_metadata(&output.path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "cannot inspect projected output {}: {error}",
                        output.path.display()
                    ));
                }
            };
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(format!(
                    "projected output is not a regular file: {}",
                    output.path.display()
                ));
            }
            if link_count(&metadata) > 1 {
                return Err(format!(
                    "projected output has multiple hard links: {}",
                    output.path.display()
                ));
            }
            let canonical = fs::canonicalize(&output.path).map_err(|error| {
                format!("cannot resolve projected output {}: {error}", output.path.display())
            })?;
            if !collisions.insert(canonical.clone()) {
                return Err(format!(
                    "projected outputs resolve to the same path: {}",
                    canonical.display()
                ));
            }
            if let Some(identity) = file_identity(&metadata) {
                if let Some(previous) = identities.insert(identity, canonical.clone()) {
                    return Err(format!(
                        "projected outputs share a filesystem identity: {} and {}",
                        previous.display(),
                        canonical.display()
                    ));
                }
            }
            if matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule) {
                let digest = output
                    .probe_digest
                    .ok_or_else(|| "module output is missing its probe digest".to_owned())?;
                let size = output
                    .probe_size
                    .ok_or_else(|| "module output is missing its probe size".to_owned())?;
                modules.insert(canonical, (digest, size));
            }
        }
        Ok(Self { modules, collisions, identities })
    }
}

fn normalize_output_path(path: &Path) -> PathBuf {
    let parent = path.parent().and_then(|parent| fs::canonicalize(parent).ok());
    if let (Some(parent), Some(name)) = (parent, path.file_name()) {
        return parent.join(name);
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn read_stable(path: &Path) -> Result<InputFile, String> {
    read_stable_with_paths(path, encoded_os(path.as_os_str()), path.to_path_buf())
}

fn read_stable_with_paths(
    path: &Path,
    raw_path: Vec<u8>,
    observed_path: PathBuf,
) -> Result<InputFile, String> {
    let before = fs::metadata(path).map_err(|error| error.to_string())?;
    if !before.is_file() {
        return Err(format!("dependency is not a regular file: {}", path.display()));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let after = fs::metadata(path).map_err(|error| error.to_string())?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || file_identity(&before) != file_identity(&after)
        || before.len() != bytes.len() as u64
    {
        return Err(format!("dependency changed while hashing: {}", path.display()));
    }
    Ok(InputFile {
        raw_path,
        observed_path,
        path: path.to_path_buf(),
        digest: *blake3::hash(&bytes).as_bytes(),
        size: bytes.len() as u64,
    })
}

fn expected_outputs(
    invocation: &GfortranInvocation,
    modules: &[ProbeModule],
    cwd: &Path,
) -> Result<Vec<ExpectedArtifact>, String> {
    let mut outputs = Vec::new();
    if invocation.compile_only && !invocation.syntax_only {
        let object = invocation
            .object
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| default_object(invocation))
            .ok_or_else(|| "cannot derive object output".to_owned())?;
        outputs.push(ExpectedArtifact {
            logical_name: "object".into(),
            kind: ArtifactKind::Object,
            role: DestinationRole::Object,
            path: absolute_output(cwd, object),
            probe_digest: None,
            probe_size: None,
        });
    }
    let final_module_dir = invocation
        .module_dir
        .as_ref()
        .map(PathBuf::from)
        .map_or_else(|| cwd.to_path_buf(), |path| absolute_output(cwd, path));
    for module in modules {
        let submodule = module.name.ends_with(".smod");
        outputs.push(ExpectedArtifact {
            logical_name: format!(
                "{}:{}",
                if submodule { "submodule" } else { "module" },
                module.name
            ),
            kind: if submodule { ArtifactKind::Submodule } else { ArtifactKind::Module },
            role: if submodule { DestinationRole::Submodule } else { DestinationRole::Module },
            path: final_module_dir.join(&module.name),
            probe_digest: Some(module.contents.digest),
            probe_size: Some(module.contents.size),
        });
    }
    if invocation.dependency_mode.is_some() {
        if let Some(depfile) = &invocation.user_depfile {
            outputs.push(ExpectedArtifact {
                logical_name: "dependency".into(),
                kind: ArtifactKind::Dependency,
                role: DestinationRole::Dependency,
                path: absolute_output(cwd, PathBuf::from(depfile)),
                probe_digest: None,
                probe_size: None,
            });
        }
    }
    outputs.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    Ok(outputs)
}

fn discover_probe_modules(
    depfile: &Depfile,
    cwd: &Path,
    directory: &Path,
) -> Result<ProbeModules, String> {
    let mut modules = Vec::new();
    let mut by_path = BTreeMap::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot inspect probe module directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect probe module entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect probe module entry type: {error}"))?;
        let path = entry.path();
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(format!("unexpected probe module output: {}", path.display()));
        }
        let os_name = entry.file_name();
        let name = os_name
            .clone()
            .into_string()
            .map_err(|_| "probe module output name is not valid UTF-8".to_owned())?;
        if !name.ends_with(".mod") && !name.ends_with(".smod") {
            return Err(format!("unexpected probe output in module directory: {name}"));
        }
        let private_path = fs::canonicalize(&path)
            .map_err(|error| format!("cannot resolve probe module {}: {error}", path.display()))?;
        let contents = read_stable(&private_path)
            .map_err(|error| format!("cannot read probe module {name}: {error}"))?;
        let index = modules.len();
        if by_path.insert(private_path.clone(), index).is_some() {
            return Err(format!("duplicate probe module output: {}", private_path.display()));
        }
        modules.push(ProbeModule {
            name,
            name_bytes: encoded_os(&os_name),
            private_path,
            contents,
        });
    }
    modules.sort_by(|left, right| left.name_bytes.cmp(&right.name_bytes));
    by_path.clear();
    for (index, module) in modules.iter().enumerate() {
        by_path.insert(module.private_path.clone(), index);
    }

    let mut generated_targets = BTreeMap::new();
    let mut matches = vec![0_u8; modules.len()];
    for (rule_index, rule) in depfile.rules.iter().enumerate() {
        if rule.is_dummy() {
            continue;
        }
        for (target_index, encoded) in rule.targets.iter().enumerate() {
            let path = path_from_bytes(encoded);
            let path = if path.is_absolute() { path } else { cwd.join(path) };
            let Ok(canonical) = fs::canonicalize(path) else {
                continue;
            };
            let Some(module_index) = by_path.get(&canonical).copied() else {
                continue;
            };
            matches[module_index] = matches[module_index].saturating_add(1);
            generated_targets
                .insert((rule_index, target_index), modules[module_index].name_bytes.clone());
        }
    }
    for (module, count) in modules.iter().zip(matches) {
        if count != 1 {
            return Err(format!(
                "probe module {} has {count} dependency targets instead of one",
                module.name
            ));
        }
    }
    let canonical_paths = modules.iter().map(|module| module.private_path.clone()).collect();
    Ok(ProbeModules { modules, generated_targets, canonical_paths })
}

fn depfile_shape(
    depfile: &Depfile,
    generated_targets: &BTreeMap<(usize, usize), Vec<u8>>,
    generated_modules: &BTreeSet<PathBuf>,
    cwd: &Path,
    outputs: &[ExpectedArtifact],
) -> Result<DepfileShape, String> {
    let projected = ProjectedOutputs::resolve(outputs)?;
    let mut primary_rules = Vec::new();
    let mut dummy_targets = Vec::new();
    for (rule_index, rule) in depfile.rules.iter().enumerate() {
        if rule.is_dummy() {
            dummy_targets.extend(rule.targets.iter().cloned().map(DepfileTarget::Ordinary));
        } else {
            let targets = rule
                .targets
                .iter()
                .enumerate()
                .map(|(target_index, target)| {
                    generated_targets.get(&(rule_index, target_index)).cloned().map_or_else(
                        || DepfileTarget::Ordinary(target.clone()),
                        DepfileTarget::GeneratedModule,
                    )
                })
                .collect();
            let prerequisites = rule
                .prerequisites
                .iter()
                .map(|prerequisite| {
                    let path = path_from_bytes(prerequisite);
                    let path = if path.is_absolute() { path } else { cwd.join(path) };
                    match fs::canonicalize(&path) {
                        Ok(canonical)
                            if generated_modules.contains(&canonical)
                                || projected_module_matches(&canonical, &projected)? =>
                        {
                            let name = canonical.file_name().ok_or_else(|| {
                                "generated module prerequisite has no file name".to_owned()
                            })?;
                            Ok(DepfilePrerequisite::GeneratedModule(encoded_os(name)))
                        }
                        _ => Ok(DepfilePrerequisite::Ordinary(prerequisite.clone())),
                    }
                })
                .collect::<Result<Vec<_>, String>>()?;
            primary_rules.push(ObservedDepfileRule { targets, prerequisites });
        }
    }
    Ok(DepfileShape { primary_rules, dummy_targets })
}

fn projected_module_matches(
    canonical: &Path,
    projected: &ProjectedOutputs,
) -> Result<bool, String> {
    let Some((expected_digest, expected_size)) = projected.modules.get(canonical) else {
        return Ok(false);
    };
    let current = read_stable(canonical)?;
    Ok(current.digest == *expected_digest && current.size == *expected_size)
}

fn validate_real_depfile_targets(
    invocation: &GfortranInvocation,
    observation: &Observation,
    cwd: &Path,
) -> Result<(), String> {
    let Some(mode) = invocation.dependency_mode else {
        return Ok(());
    };
    let Some(path) = &invocation.user_depfile else {
        return Err("dependency output was requested without a depfile path".into());
    };
    let path = absolute_output(cwd, PathBuf::from(path));
    let bytes = fs::read(&path).map_err(|error| {
        format!("cannot read real compiler depfile {}: {error}", path.display())
    })?;
    let depfile = parse_depfile(&bytes).map_err(|error| error.to_string())?;
    let generated_targets = real_generated_targets(&depfile, cwd, &observation.outputs)?;
    let generated_modules = observation
        .outputs
        .iter()
        .filter(|output| matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule))
        .map(|output| {
            fs::canonicalize(&output.path).map_err(|error| {
                format!("cannot resolve real module output {}: {error}", output.path.display())
            })
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    let actual_shape =
        depfile_shape(&depfile, &generated_targets, &generated_modules, cwd, &observation.outputs)?;
    let primary_targets_match = actual_shape.primary_rules.len()
        == observation.depfile_shape.primary_rules.len()
        && actual_shape
            .primary_rules
            .iter()
            .zip(&observation.depfile_shape.primary_rules)
            .all(|(actual, expected)| actual.targets == expected.targets);
    if !primary_targets_match {
        return Err(format!(
            "real compiler depfile primary targets differ from probe: expected {:?}, got {:?}",
            observation.depfile_shape.primary_rules, actual_shape.primary_rules
        ));
    }
    let actual_prerequisites =
        resolved_depfile_prerequisites(&depfile, cwd, &BTreeSet::new(), &observation.outputs)?;
    let expected_prerequisites: BTreeSet<_> =
        observation.inputs.iter().map(|input| input.path.clone()).collect();
    match mode {
        DependencyMode::Md => {
            if actual_shape != observation.depfile_shape {
                return Err(format!(
                    "real compiler depfile target shape differs from probe: expected {:?}, got {:?}",
                    observation.depfile_shape, actual_shape
                ));
            }
            if actual_prerequisites != expected_prerequisites {
                return Err(format!(
                    "real compiler depfile prerequisites differ from probe: expected {expected_prerequisites:?}, got {actual_prerequisites:?}"
                ));
            }
        }
        DependencyMode::Mmd => {
            let probe_dummy: BTreeSet<_> =
                observation.depfile_shape.dummy_targets.iter().cloned().collect();
            let real_dummy: BTreeSet<_> = actual_shape.dummy_targets.iter().cloned().collect();
            if !real_dummy.is_subset(&probe_dummy) {
                return Err("real -MMD depfile contains targets absent from the full probe".into());
            }
            if !actual_prerequisites.is_subset(&expected_prerequisites) {
                return Err(
                    "real -MMD depfile contains prerequisites absent from the full probe".into()
                );
            }
            let source =
                invocation.source.as_ref().ok_or_else(|| "missing source input".to_owned())?;
            let source = fs::canonicalize(absolute_output(cwd, PathBuf::from(source)))
                .map_err(|error| format!("cannot resolve source input: {error}"))?;
            if !actual_prerequisites.contains(&source) {
                return Err("real -MMD depfile omits the source input".into());
            }
        }
    }
    Ok(())
}

fn real_generated_targets(
    depfile: &Depfile,
    cwd: &Path,
    outputs: &[ExpectedArtifact],
) -> Result<BTreeMap<(usize, usize), Vec<u8>>, String> {
    let modules: Vec<_> = outputs
        .iter()
        .filter(|output| matches!(output.kind, ArtifactKind::Module | ArtifactKind::Submodule))
        .map(|output| {
            let canonical = fs::canonicalize(&output.path).map_err(|error| {
                format!("cannot resolve real module output {}: {error}", output.path.display())
            })?;
            let name = output
                .path
                .file_name()
                .ok_or_else(|| "real module output has no file name".to_owned())?;
            Ok((canonical, encoded_os(name)))
        })
        .collect::<Result<_, String>>()?;
    let by_path: BTreeMap<_, _> =
        modules.iter().enumerate().map(|(index, (path, _))| (path.clone(), index)).collect();
    let mut matches = vec![0_u8; modules.len()];
    let mut generated = BTreeMap::new();
    for (rule_index, rule) in depfile.rules.iter().enumerate() {
        if rule.is_dummy() {
            continue;
        }
        for (target_index, target) in rule.targets.iter().enumerate() {
            let path = path_from_bytes(target);
            let path = if path.is_absolute() { path } else { cwd.join(path) };
            let Ok(canonical) = fs::canonicalize(path) else {
                continue;
            };
            let Some(index) = by_path.get(&canonical).copied() else {
                continue;
            };
            matches[index] = matches[index].saturating_add(1);
            generated.insert((rule_index, target_index), modules[index].1.clone());
        }
    }
    for ((path, _), count) in modules.iter().zip(matches) {
        if count != 1 {
            return Err(format!(
                "real module {} has {count} dependency targets instead of one",
                path.display()
            ));
        }
    }
    Ok(generated)
}

fn resolved_depfile_prerequisites(
    depfile: &Depfile,
    cwd: &Path,
    generated_modules: &BTreeSet<PathBuf>,
    outputs: &[ExpectedArtifact],
) -> Result<BTreeSet<PathBuf>, String> {
    let projected = ProjectedOutputs::resolve(outputs)?;
    let mut resolved = BTreeSet::new();
    for rule in &depfile.rules {
        if rule.is_dummy() {
            continue;
        }
        for encoded in &rule.prerequisites {
            let path = path_from_bytes(encoded);
            let path = if path.is_absolute() { path } else { cwd.join(path) };
            if let Some(canonical) = resolve_optional_input(&path, generated_modules, &projected)? {
                resolved.insert(canonical);
            }
        }
    }
    Ok(resolved)
}

fn build_action_key(
    compiler: &OsStr,
    invocation: &GfortranInvocation,
    fingerprint: &CompilerFingerprint,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    observation: &Observation,
) -> Result<ActionKey, crate::cache::key::KeyError> {
    let mut builder = ActionKeyBuilder::new();
    builder.add_bytes("schema", KEY_SCHEMA);
    builder.add_bytes("umask", effective_umask().to_le_bytes());
    builder.add_bytes("compiler-digest", fingerprint.digest());
    builder.add_os_str("compiler-argument", compiler);
    builder.add_path("cwd", cwd);
    for (index, argument) in invocation.original_args.iter().enumerate() {
        builder.add_os_str(&format!("argument-{index:08}"), argument);
    }
    for (index, (name, value)) in
        environment.iter().filter(|(name, _)| environment_affects_compiler_output(name)).enumerate()
    {
        builder.add_os_str(&format!("environment-name-{index:08}"), name);
        builder.add_os_str(&format!("environment-value-{index:08}"), value);
    }
    for (index, directory) in invocation.include_dirs.iter().enumerate() {
        builder.add_path(
            &format!("include-directory-{index:08}"),
            &absolute_output(cwd, PathBuf::from(directory)),
        );
    }
    if let Some(directory) = &invocation.module_dir {
        builder.add_path("module-directory", &absolute_output(cwd, PathBuf::from(directory)));
    }
    for (index, input) in observation.inputs.iter().enumerate() {
        builder.add_path(&format!("input-path-{index:08}"), &input.path);
        builder.add_bytes(&format!("input-digest-{index:08}"), input.digest);
        builder.add_bytes(&format!("input-size-{index:08}"), input.size.to_le_bytes());
    }
    for (index, output) in observation.outputs.iter().enumerate() {
        builder.add_bytes(&format!("output-name-{index:08}"), output.logical_name.as_bytes());
        builder.add_path(&format!("output-path-{index:08}"), &output.path);
        if let Some(digest) = output.probe_digest {
            builder.add_bytes(&format!("output-probe-digest-{index:08}"), digest);
        }
        if let Some(size) = output.probe_size {
            builder.add_bytes(&format!("output-probe-size-{index:08}"), size.to_le_bytes());
        }
    }
    for (rule_index, rule) in observation.depfile_shape.primary_rules.iter().enumerate() {
        builder.add_bytes(
            &format!("depfile-primary-target-count-{rule_index:08}"),
            (rule.targets.len() as u64).to_le_bytes(),
        );
        for (target_index, target) in rule.targets.iter().enumerate() {
            add_depfile_target_to_key(
                &mut builder,
                &format!("depfile-primary-{rule_index:08}-{target_index:08}"),
                target,
            );
        }
        builder.add_bytes(
            &format!("depfile-primary-prerequisite-count-{rule_index:08}"),
            (rule.prerequisites.len() as u64).to_le_bytes(),
        );
        for (prerequisite_index, prerequisite) in rule.prerequisites.iter().enumerate() {
            add_depfile_prerequisite_to_key(
                &mut builder,
                &format!("depfile-primary-prerequisite-{rule_index:08}-{prerequisite_index:08}"),
                prerequisite,
            );
        }
    }
    for (index, target) in observation.depfile_shape.dummy_targets.iter().enumerate() {
        add_depfile_target_to_key(&mut builder, &format!("depfile-dummy-{index:08}"), target);
    }
    if let Some(preprocessor) = &observation.preprocessor {
        builder.add_bytes("preprocessor-stdout-digest", preprocessor.stdout_digest);
        builder.add_bytes("preprocessor-stdout-size", preprocessor.stdout_size.to_le_bytes());
        builder.add_bytes("preprocessor-stderr-digest", preprocessor.stderr_digest);
        builder.add_bytes("preprocessor-stderr-size", preprocessor.stderr_size.to_le_bytes());
        builder.add_bytes(
            "preprocessor-automatic-lowercase",
            [u8::from(preprocessor.automatic_lowercase_source)],
        );
    }
    builder.finish()
}

#[cfg(unix)]
fn effective_umask() -> u32 {
    let previous = rustix::process::umask(rustix::fs::Mode::empty());
    rustix::process::umask(previous);
    #[allow(
        clippy::useless_conversion,
        reason = "mode_t widths differ across supported Unix targets"
    )]
    u32::from(previous.bits())
}

#[cfg(not(unix))]
fn effective_umask() -> u32 {
    0
}

fn add_depfile_prerequisite_to_key(
    builder: &mut ActionKeyBuilder,
    name: &str,
    prerequisite: &DepfilePrerequisite,
) {
    match prerequisite {
        DepfilePrerequisite::Ordinary(bytes) => {
            builder.add_bytes(&format!("{name}-kind"), b"ordinary");
            builder.add_bytes(name, bytes);
        }
        DepfilePrerequisite::GeneratedModule(bytes) => {
            builder.add_bytes(&format!("{name}-kind"), b"generated-module");
            builder.add_bytes(name, bytes);
        }
    }
}

fn add_depfile_target_to_key(builder: &mut ActionKeyBuilder, name: &str, target: &DepfileTarget) {
    match target {
        DepfileTarget::Ordinary(bytes) => {
            builder.add_bytes(&format!("{name}-kind"), b"ordinary");
            builder.add_bytes(name, bytes);
        }
        DepfileTarget::GeneratedModule(bytes) => {
            builder.add_bytes(&format!("{name}-kind"), b"generated-module");
            builder.add_bytes(name, bytes);
        }
    }
}

fn try_restore(
    store: &CacheStore,
    action: &ActionKey,
    fingerprint: &CompilerFingerprint,
    identity: &ValidatedCompilerIdentity,
    observation: &Observation,
) -> Result<Option<Manifest>, CacheError> {
    if !inputs_unchanged(&observation.inputs)
        || validate_restore_output_contract(observation).is_err()
        || identity.revalidate().is_err()
    {
        return Ok(None);
    }
    let Some(manifest) = store.load_manifest_metadata(action)? else {
        return Ok(None);
    };
    if manifest.compiler_digest != fingerprint.digest_hex() {
        return Ok(None);
    }
    let mut destinations = RestoreDestinations::new();
    for output in &observation.outputs {
        destinations.insert_with_role(&output.logical_name, output.role, &output.path);
    }
    let prepared = store.prepare_restore(action, &destinations)?;
    if !inputs_unchanged(&observation.inputs)
        || validate_restore_output_contract(observation).is_err()
    {
        return Ok(None);
    }
    let restored = prepared.commit()?;
    Ok(Some(restored))
}

fn inputs_unchanged(inputs: &[InputFile]) -> bool {
    inputs.iter().all(|expected| {
        read_stable(&expected.path).is_ok_and(|current| {
            current.path == expected.path
                && current.digest == expected.digest
                && current.size == expected.size
        })
    })
}

fn validate_restore_output_contract(observation: &Observation) -> Result<(), String> {
    let projected = ProjectedOutputs::resolve(&observation.outputs)?;
    for (path, (digest, size)) in &projected.modules {
        let current = read_stable(path)?;
        if current.digest != *digest || current.size != *size {
            return Err(format!(
                "existing module output differs from the dependency probe: {}",
                path.display()
            ));
        }
    }
    for input in &observation.inputs {
        let metadata = fs::metadata(&input.path)
            .map_err(|error| format!("cannot inspect input {}: {error}", input.path.display()))?;
        if file_identity(&metadata)
            .is_some_and(|identity| projected.identities.contains_key(&identity))
        {
            return Err(format!(
                "compiler input aliases a projected output: {}",
                input.path.display()
            ));
        }
    }
    Ok(())
}

fn store_result(
    store: &CacheStore,
    action: ActionKey,
    fingerprint: &CompilerFingerprint,
    observation: &Observation,
    output: &CompilerOutput,
) -> Result<(u64, Manifest), String> {
    if !inputs_unchanged(&observation.inputs)
        || validate_restore_output_contract(observation).is_err()
    {
        return Err("inputs changed before compiler outputs were captured".into());
    }
    let captured =
        observation.outputs.iter().map(capture_artifact).collect::<Result<Vec<_>, _>>()?;
    for artifact in &captured {
        if artifact.expected.probe_digest.is_some_and(|expected| expected != artifact.digest) {
            return Err(format!(
                "real compiler module differs from dependency probe: {}",
                artifact.expected.path.display()
            ));
        }
        let current = read_stable(&artifact.expected.path)?;
        if current.digest != artifact.digest || current.size != artifact.bytes.len() as u64 {
            return Err(format!(
                "compiler output changed while capturing the result: {}",
                artifact.expected.path.display()
            ));
        }
    }
    if !inputs_unchanged(&observation.inputs) {
        return Err("inputs changed while compiler outputs were captured".into());
    }

    let mut artifacts = Vec::with_capacity(observation.outputs.len());
    let mut bytes_stored = 0;
    for captured in captured {
        let expected = captured.expected;
        let blob =
            store.put_blob(&captured.bytes, captured.mode).map_err(|error| error.to_string())?;
        bytes_stored += blob.size;
        artifacts.push(Artifact::new(expected.kind, &expected.logical_name, expected.role, blob));
    }
    let stdout = store.put_blob(&output.stdout, 0o644).map_err(|error| error.to_string())?;
    let stderr = store.put_blob(&output.stderr, 0o644).map_err(|error| error.to_string())?;
    bytes_stored += stdout.size + stderr.size;
    let manifest = Manifest::new(action, fingerprint.digest_hex(), artifacts, stdout, stderr);
    store.publish(&manifest).map_err(|error| error.to_string())?;
    Ok((bytes_stored, manifest))
}

fn capture_artifact(expected: &ExpectedArtifact) -> Result<CapturedArtifact<'_>, String> {
    let before = fs::symlink_metadata(&expected.path).map_err(|error| error.to_string())?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        return Err(format!("compiler output is not a regular file: {}", expected.path.display()));
    }
    if link_count(&before) > 1 {
        return Err(format!(
            "compiler output has multiple hard links: {}",
            expected.path.display()
        ));
    }
    let bytes = fs::read(&expected.path).map_err(|error| error.to_string())?;
    let after = fs::symlink_metadata(&expected.path).map_err(|error| error.to_string())?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || file_identity(&before) != file_identity(&after)
        || before.len() != bytes.len() as u64
    {
        return Err(format!("compiler output changed while reading: {}", expected.path.display()));
    }
    let digest = *blake3::hash(&bytes).as_bytes();
    Ok(CapturedArtifact { expected, bytes, mode: file_mode(&after), digest })
}

fn replay(store: &CacheStore, manifest: &Manifest) -> Result<(), CacheError> {
    let stdout = store.read_blob(&manifest.stdout)?;
    let stderr = store.read_blob(&manifest.stderr)?;
    io::stdout().write_all(&stdout)?;
    io::stderr().write_all(&stderr)?;
    Ok(())
}

fn show_stats(config: &Config, json: bool) -> Result<i32, String> {
    let stats = StatsStore::new(&config.cache_dir)
        .and_then(|store| store.aggregate())
        .map_err(|error| error.to_string())?;
    if json {
        serde_json::to_writer_pretty(io::stdout(), &stats).map_err(|error| error.to_string())?;
        println!();
    } else {
        println!("stats schema: {}", stats.schema_version);
        println!("requests: {}", stats.requests);
        println!("hits: {}", stats.hits);
        println!("misses: {}", stats.misses);
        println!("lookups not attempted: {}", stats.lookup_results.not_attempted);
        println!("observed cache hit successes: {}", stats.observed_outcomes.cache_hit_success);
        println!("observed compiler successes: {}", stats.observed_outcomes.compiler_success);
        println!("observed compiler failures: {}", stats.observed_outcomes.compiler_failure);
        println!("observed launcher failures: {}", stats.observed_outcomes.launcher_failure);
        println!("compiler failures (legacy): {}", stats.compiler_failures);
        println!("cache read failures: {}", stats.cache_read_failures);
        println!("cache write failures: {}", stats.cache_write_failures);
        println!("corruption: {}", stats.corruption);
        println!("bytes stored: {}", stats.bytes_stored);
        println!("bytes restored: {}", stats.bytes_restored);
        println!("fingerprint queries: {}", stats.process_counts.fingerprint_queries);
        println!("preprocessing probes: {}", stats.process_counts.preprocessing_probes);
        println!("dependency probes: {}", stats.process_counts.dependency_probes);
        println!("real compilations: {}", stats.process_counts.real_compilations);
        println!("pass-through executions: {}", stats.process_counts.pass_through_executions);
        println!("direct candidates found: {}", stats.direct_path.candidates_found);
        println!("direct validated hits: {}", stats.direct_path.validated_hits);
        println!("direct validated compile plans: {}", stats.direct_path.validated_compile_plans);
        println!("direct stale records: {}", stats.direct_path.stale_records);
        println!("direct corrupt records: {}", stats.direct_path.corrupt_records);
        println!("direct missing manifests: {}", stats.direct_path.missing_result_manifests);
        println!(
            "validated precompile selections: {}",
            stats.miss_observation.validated_precompile_selections
        );
        println!(
            "real MD validation successes: {}",
            stats.miss_observation.real_md_validation_successes
        );
        println!(
            "post-compile probe attempts: {}",
            stats.miss_observation.post_compile_probe_attempts
        );
        for (reason, count) in stats.direct_path.validation_fallback_reasons {
            println!("direct fallback {reason}: {count}");
        }
        for (reason, count) in stats.bypass_reasons {
            println!("bypass {reason}: {count}");
        }
    }
    Ok(0)
}

fn pass_through(
    compiler: &OsStr,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<i32, String> {
    let command = CompilerCommand::new(compiler)
        .args(arguments.iter().cloned())
        .environment(environment.iter().cloned());
    match exec_compiler(command) {
        Ok(status) => Ok(status.code().unwrap_or(1)),
        Err(error) => Err(error.to_string()),
    }
}

fn compiler_environment() -> Vec<(OsString, OsString)> {
    filter_compiler_environment(env::vars_os())
}

fn filter_compiler_environment(
    values: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let mut environment: Vec<_> =
        values.into_iter().filter(|(name, _)| !encoded_os(name).starts_with(b"FCACHE_")).collect();
    environment.sort_by(|left, right| {
        encoded_os(&left.0)
            .cmp(&encoded_os(&right.0))
            .then(encoded_os(&left.1).cmp(&encoded_os(&right.1)))
    });
    environment
}

fn environment_affects_compiler_output(name: &OsStr) -> bool {
    !matches!(encoded_os(name).as_slice(), b"MAKEFLAGS" | b"MFLAGS")
}

fn record(stats: &mut PendingStats, key: Option<&str>, update: impl FnOnce(&mut Stats)) {
    stats.record(key, update);
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn manifest_payload_size(manifest: &Manifest) -> u64 {
    manifest.artifacts.iter().map(|artifact| artifact.blob.size).sum::<u64>()
        + manifest.stdout.size
        + manifest.stderr.size
}

#[derive(Clone, Copy, Default)]
struct ProbeTelemetry {
    preprocessing_probes: u64,
    dependency_probes: u64,
}

fn record_probe_telemetry(stats: &mut PendingStats, telemetry: ProbeTelemetry, started: Instant) {
    record(stats, None, |value| {
        value.process_counts.dependency_probes =
            value.process_counts.dependency_probes.saturating_add(telemetry.dependency_probes);
        value.process_counts.preprocessing_probes = value
            .process_counts
            .preprocessing_probes
            .saturating_add(telemetry.preprocessing_probes);
        value.phase_timings_ns.dependency_probing =
            value.phase_timings_ns.dependency_probing.saturating_add(elapsed_ns(started));
    });
}

fn record_direct_fallback(pending: &mut PendingStats, reason: &str) {
    record(pending, None, |stats| {
        stats.direct_path.stale_records += 1;
        *stats.direct_path.validation_fallback_reasons.entry(reason.to_owned()).or_default() += 1;
    });
}

fn record_bypass(pending: &mut PendingStats, reason: &str) {
    record(pending, None, |stats| {
        stats.requests += 1;
        stats.lookup_results.not_attempted += 1;
        stats.process_counts.pass_through_executions += 1;
        *stats.bypass_reasons.entry(reason.to_owned()).or_default() += 1;
    });
    pending.flush();
}

fn record_attempted_bypass(pending: &mut PendingStats, reason: &str) {
    record(pending, None, |stats| {
        stats.lookup_results.not_attempted += 1;
        stats.process_counts.pass_through_executions += 1;
        *stats.bypass_reasons.entry(reason.to_owned()).or_default() += 1;
    });
    pending.flush();
}

fn record_nonpublication(pending: &mut PendingStats, reason: &str) {
    record(pending, None, |stats| {
        *stats.bypass_reasons.entry(reason.to_owned()).or_default() += 1;
    });
}

fn bypass_name(reason: &BypassReason) -> &'static str {
    match reason {
        BypassReason::EmptyInvocation => "empty-invocation",
        BypassReason::ResponseFile(_) => "response-file",
        BypassReason::StdinSource => "stdin-source",
        BypassReason::MissingSource => "missing-source",
        BypassReason::MultipleSources => "multiple-sources",
        BypassReason::NonFortranInput(_) => "non-fortran-input",
        BypassReason::LinkAction => "link-action",
        BypassReason::PreprocessOnly => "preprocess-only",
        BypassReason::AssemblyOutput => "assembly-output",
        BypassReason::SaveTemps => "save-temps",
        BypassReason::DumpOutput => "dump-output",
        BypassReason::CoverageOrProfile => "coverage-or-profile",
        BypassReason::PluginOrSpecs => "plugin-or-specs",
        BypassReason::StdoutDepfile => "depfile-stdout",
        BypassReason::OptimizationRecord => "optimization-record",
        BypassReason::FileDiagnostic => "file-diagnostic",
        BypassReason::AutoFdo => "autofdo",
        BypassReason::LanguageOverride => "language-override",
        BypassReason::ArgumentCarrier => "argument-carrier",
        BypassReason::UnknownOption(_) => "unknown-option",
        BypassReason::MissingDependencyProbePreprocessing => "dependency-probe-preprocessing",
        BypassReason::DuplicateModuleDirectory => "duplicate-module-directory",
    }
}

fn default_object(invocation: &GfortranInvocation) -> Option<PathBuf> {
    let source = invocation.source.as_ref()?;
    let name = Path::new(source).file_name()?;
    Some(Path::new(name).with_extension("o"))
}

fn absolute_output(cwd: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() { path } else { cwd.join(path) }
}

fn is_gfortran(program: &OsStr) -> bool {
    Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name == "gfortran" || name.starts_with("gfortran-"))
}

fn status_code(output: &CompilerOutput) -> i32 {
    if let Some(code) = output.status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        output.status.signal().map_or(1, |signal| 128 + signal)
    }
    #[cfg(not(unix))]
    1
}

fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(OsString::from_vec(bytes.to_vec()))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn encoded_os(value: &OsStr) -> Vec<u8> {
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

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity { device: metadata.dev(), inode: metadata.ino() })
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(unix)]
fn link_count(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink()
}

#[cfg(not(unix))]
fn link_count(_metadata: &fs::Metadata) -> u64 {
    1
}

fn file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    0o644
}

fn print_help() {
    println!(
        "fcache {version}\n\nUsage:\n  fcache <compiler> <arguments...>\n  fcache --explain [--json] -- <compiler> <arguments...>\n  fcache --show-stats [--json]\n  fcache --zero-stats\n  fcache --show-config\n  fcache --trim\n  fcache --clear\n  fcache --version\n  fcache --help",
        version = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_reserved_environment() {
        let values = filter_compiler_environment([
            (OsString::from("FCACHE_TEST_RESERVED"), OsString::from("value")),
            (OsString::from("PATH"), OsString::from("/bin")),
        ]);
        assert!(!values.iter().any(|(name, _)| name == "FCACHE_TEST_RESERVED"));
        assert!(values.iter().any(|(name, _)| name == "PATH"));
    }

    #[test]
    fn excludes_make_jobserver_metadata_only_from_action_keys() {
        let values = filter_compiler_environment([
            (OsString::from("MAKEFLAGS"), OsString::from("-j12 --jobserver-auth=fifo:/tmp/one")),
            (OsString::from("MFLAGS"), OsString::from("-j12 --jobserver-auth=fifo:/tmp/one")),
            (OsString::from("PATH"), OsString::from("/bin")),
        ]);

        assert!(values.iter().any(|(name, _)| name == "MAKEFLAGS"));
        assert!(values.iter().any(|(name, _)| name == "MFLAGS"));
        assert!(!environment_affects_compiler_output(OsStr::new("MAKEFLAGS")));
        assert!(!environment_affects_compiler_output(OsStr::new("MFLAGS")));
        assert!(environment_affects_compiler_output(OsStr::new("PATH")));
    }

    #[test]
    fn derives_default_object_in_working_directory() {
        let invocation =
            parse_gfortran_args(&[OsString::from("-c"), OsString::from("source/example.F90")])
                .unwrap();
        assert_eq!(default_object(&invocation), Some(PathBuf::from("example.o")));
    }

    #[test]
    fn detects_input_changes_after_observation() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.F90");
        fs::write(&input, b"program first\nend\n").unwrap();
        let observed = read_stable(&input).unwrap();
        assert!(inputs_unchanged(std::slice::from_ref(&observed)));

        fs::write(&input, b"program second\nend\n").unwrap();
        assert!(!inputs_unchanged(&[observed]));
    }

    #[test]
    fn source_is_hashed_even_when_the_depfile_has_no_prerequisites() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("source.F90"), b"program source\nend\n").unwrap();
        let invocation = parse_gfortran_args(&[
            OsString::from("-cpp"),
            OsString::from("-c"),
            OsString::from("source.F90"),
        ])
        .unwrap();

        let (inputs, _) =
            read_inputs(&Depfile::default(), &invocation, directory.path(), &BTreeSet::new(), &[])
                .unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, fs::canonicalize(directory.path().join("source.F90")).unwrap());
    }

    #[test]
    fn automatic_preprocessing_requires_byte_identity() {
        let source = b"program source\nend program source\n";
        let mut prefixed = b"\n\n".to_vec();
        prefixed.extend_from_slice(source);
        assert!(preprocessor_output_is_identity(&prefixed, source));
        assert!(preprocessor_output_is_identity(source, source));
        assert!(preprocessor_output_is_identity(
            b"\n\nprogram source\nend program source\n",
            b"program source\nend program source"
        ));
        assert!(!preprocessor_output_is_identity(b"\n\nprogram changed\n", b"program source"));
        assert!(!preprocessor_output_is_identity(b"\nprogram changed\n", source));
        assert!(!preprocessor_output_is_identity(b"# 1 source.f90\n", source));
    }

    #[test]
    fn reports_predicted_module_names_as_raw_bytes() {
        let observation = Observation {
            inputs: Vec::new(),
            dependencies: Vec::new(),
            outputs: vec![ExpectedArtifact {
                logical_name: "module:expected.mod".into(),
                kind: ArtifactKind::Module,
                role: DestinationRole::Module,
                path: PathBuf::from("expected.mod"),
                probe_digest: Some([2; 32]),
                probe_size: Some(1),
            }],
            depfile_shape: DepfileShape::default(),
            preprocessor: None,
        };
        assert_eq!(
            predicted_module_names(&observation),
            BTreeSet::from([b"expected.mod".to_vec()])
        );
    }

    #[test]
    fn skips_same_compilation_module_used_as_a_later_prerequisite() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("multi.F90");
        let generated = directory.path().join("first.mod");
        fs::write(&source, b"module first\nend module first\n").unwrap();
        fs::write(&generated, b"module").unwrap();
        let invocation = parse_gfortran_args(&[
            OsString::from("-cpp"),
            OsString::from("-c"),
            OsString::from("-J"),
            OsString::from("."),
            OsString::from("multi.F90"),
            OsString::from("-o"),
            OsString::from("multi.o"),
        ])
        .unwrap();
        let depfile = Depfile {
            rules: vec![crate::compiler::depfile::DepfileRule {
                targets: vec![b"first.mod".to_vec(), b"multi.o".to_vec()],
                prerequisites: vec![b"multi.F90".to_vec(), b"first.mod".to_vec()],
            }],
        };
        let module = read_stable(&generated).unwrap();
        let outputs = [ExpectedArtifact {
            logical_name: "module:first.mod".into(),
            kind: ArtifactKind::Module,
            role: DestinationRole::Module,
            path: generated,
            probe_digest: Some(module.digest),
            probe_size: Some(module.size),
        }];
        let (inputs, _) =
            read_inputs(&depfile, &invocation, directory.path(), &BTreeSet::new(), &outputs)
                .unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, fs::canonicalize(source).unwrap());
    }

    #[test]
    fn rejects_dependency_that_collides_with_a_projected_output() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.F90");
        let object = directory.path().join("source.o");
        fs::write(&source, b"program source\nend\n").unwrap();
        fs::write(&object, b"not-an-object").unwrap();
        let invocation = parse_gfortran_args(&[
            OsString::from("-cpp"),
            OsString::from("-c"),
            OsString::from("source.F90"),
            OsString::from("-o"),
            OsString::from("source.o"),
        ])
        .unwrap();
        let depfile = Depfile {
            rules: vec![crate::compiler::depfile::DepfileRule {
                targets: vec![b"source.o".to_vec()],
                prerequisites: vec![b"source.F90".to_vec(), b"source.o".to_vec()],
            }],
        };
        let outputs = [ExpectedArtifact {
            logical_name: "object".into(),
            kind: ArtifactKind::Object,
            role: DestinationRole::Object,
            path: object,
            probe_digest: None,
            probe_size: None,
        }];
        let error =
            read_inputs(&depfile, &invocation, directory.path(), &BTreeSet::new(), &outputs)
                .unwrap_err();
        assert!(error.contains("collides with a projected output"), "unexpected error: {error}");
    }

    #[test]
    fn real_depfile_comparison_requires_matching_targets_and_prerequisites() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.F90");
        let include = directory.path().join("value.inc");
        let consumed = directory.path().join("used.mod");
        fs::write(&source, b"program source\nend\n").unwrap();
        fs::write(&include, b"integer :: x\n").unwrap();
        fs::write(&consumed, b"module").unwrap();
        let source = fs::canonicalize(source).unwrap();
        let include = fs::canonicalize(include).unwrap();
        let consumed = fs::canonicalize(consumed).unwrap();
        let observation = Observation {
            inputs: vec![
                InputFile {
                    raw_path: encoded_os(source.as_os_str()),
                    observed_path: source.clone(),
                    path: source.clone(),
                    digest: [1; 32],
                    size: 1,
                },
                InputFile {
                    raw_path: encoded_os(include.as_os_str()),
                    observed_path: include.clone(),
                    path: include.clone(),
                    digest: [2; 32],
                    size: 1,
                },
                InputFile {
                    raw_path: encoded_os(consumed.as_os_str()),
                    observed_path: consumed.clone(),
                    path: consumed.clone(),
                    digest: [3; 32],
                    size: 1,
                },
            ],
            dependencies: Vec::new(),
            outputs: vec![ExpectedArtifact {
                logical_name: "object".into(),
                kind: ArtifactKind::Object,
                role: DestinationRole::Object,
                path: directory.path().join("source.o"),
                probe_digest: None,
                probe_size: None,
            }],
            depfile_shape: DepfileShape {
                primary_rules: vec![ObservedDepfileRule {
                    targets: vec![DepfileTarget::Ordinary(b"source.o".to_vec())],
                    prerequisites: vec![
                        DepfilePrerequisite::Ordinary(b"source.F90".to_vec()),
                        DepfilePrerequisite::Ordinary(b"value.inc".to_vec()),
                        DepfilePrerequisite::Ordinary(b"used.mod".to_vec()),
                    ],
                }],
                ..DepfileShape::default()
            },
            preprocessor: None,
        };
        let matching = Depfile {
            rules: vec![crate::compiler::depfile::DepfileRule {
                targets: vec![b"source.o".to_vec()],
                prerequisites: vec![
                    b"source.F90".to_vec(),
                    b"value.inc".to_vec(),
                    b"used.mod".to_vec(),
                ],
            }],
        };
        assert_eq!(
            resolved_depfile_prerequisites(
                &matching,
                directory.path(),
                &BTreeSet::new(),
                &observation.outputs,
            )
            .unwrap(),
            BTreeSet::from([source, include, consumed])
        );
        let mismatched = Depfile {
            rules: vec![crate::compiler::depfile::DepfileRule {
                targets: vec![b"source.o".to_vec()],
                prerequisites: vec![b"source.F90".to_vec(), b"value.inc".to_vec()],
            }],
        };
        let actual = resolved_depfile_prerequisites(
            &mismatched,
            directory.path(),
            &BTreeSet::new(),
            &observation.outputs,
        )
        .unwrap();
        let expected: BTreeSet<_> =
            observation.inputs.iter().map(|input| input.path.clone()).collect();
        assert_ne!(actual, expected);
    }

    #[test]
    fn supports_declared_gfortran_versions_and_driver_names() {
        assert!(!supported_gfortran_major(10));
        assert!(supported_gfortran_major(11));
        assert!(supported_gfortran_major(12));
        assert!(supported_gfortran_major(16));
        assert!(!supported_gfortran_major(17));
        assert!(is_gfortran(OsStr::new("gfortran")));
        assert!(is_gfortran(OsStr::new("/opt/gcc-11/bin/gfortran-11")));
        assert!(!is_gfortran(OsStr::new("vendor-gfortran")));
    }
}
