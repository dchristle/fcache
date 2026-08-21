use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
};

use serde::Deserialize;
use tempfile::TempDir;

use fcache::compiler::depfile::parse_depfile;
use filetime::{FileTime, set_file_mtime};

#[derive(Debug, Deserialize)]
struct Stats {
    requests: u64,
    hits: u64,
    misses: u64,
    #[serde(default)]
    lookup_results: LookupResults,
    #[serde(default)]
    observed_outcomes: ObservedOutcomes,
    #[serde(default)]
    process_counts: ProcessCounts,
    #[serde(default)]
    direct_path: DirectPathStats,
    #[serde(default)]
    miss_observation: MissObservationStats,
    #[serde(default)]
    bypass_reasons: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Deserialize)]
struct LookupResults {
    hits: u64,
    misses: u64,
    not_attempted: u64,
}

#[derive(Debug, Default, Deserialize)]
struct ObservedOutcomes {
    cache_hit_success: u64,
    compiler_success: u64,
}

#[derive(Debug, Default, Deserialize)]
struct ProcessCounts {
    fingerprint_queries: u64,
    preprocessing_probes: u64,
    dependency_probes: u64,
    real_compilations: u64,
}

#[derive(Debug, Default, Deserialize)]
struct DirectPathStats {
    validated_hits: u64,
    validated_compile_plans: u64,
}

#[derive(Debug, Default, Deserialize)]
struct MissObservationStats {
    validated_precompile_selections: u64,
    real_md_validation_successes: u64,
    post_compile_probe_attempts: u64,
}

struct Fixture {
    root: TempDir,
    cache: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create isolated integration directory");
        let cache = root.path().join("cache");
        fs::create_dir(&cache).expect("create isolated cache directory");
        Self { root, cache }
    }

    fn path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.root.path().join(relative)
    }

    fn copy_fixture(&self, name: &str) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
        let destination = self.path(name);
        fs::copy(&source, &destination).unwrap_or_else(|error| {
            panic!("copy fixture {} to {}: {error}", source.display(), destination.display())
        });
        destination
    }

    fn modules(&self) -> PathBuf {
        let path = self.path("modules");
        fs::create_dir_all(&path).expect("create module output directory");
        path
    }

    fn remove_outputs(&self, relative_paths: &[&str]) {
        for relative in relative_paths {
            let path = self.path(relative);
            if path.exists() {
                fs::remove_file(&path)
                    .unwrap_or_else(|error| panic!("remove {}: {error}", path.display()));
            }
        }
    }
}

fn gfortran_available() -> bool {
    required_tool_available("gfortran")
}

fn gfortran_supports_compiler_free_cpp() -> bool {
    Command::new("gfortran")
        .arg("-dumpfullversion")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .split('.')
                .next()
                .and_then(|major| major.parse::<u32>().ok())
        })
        .is_some_and(|major| major >= 13)
}

fn required_tool_available(tool: &str) -> bool {
    if Command::new(tool).arg("--version").output().is_ok_and(|output| output.status.success()) {
        return true;
    }
    assert!(
        env::var_os("CI").is_none(),
        "required integration-test tool {tool} is unavailable in CI"
    );
    eprintln!("skipping integration test: required tool {tool} is unavailable");
    false
}

fn fcache_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fcache"))
}

fn compiler_output(compiler: &str, fixture: &Fixture, arguments: &[&str]) -> Output {
    Command::new(compiler)
        .args(arguments)
        .current_dir(fixture.root.path())
        .output()
        .expect("run compiler")
}

fn cached_output(fixture: &Fixture, arguments: &[&str]) -> Output {
    Command::new(fcache_path())
        .arg("gfortran")
        .args(arguments)
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("run fcache")
}

fn cached_output_with_env(
    fixture: &Fixture,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> Output {
    Command::new(fcache_path())
        .arg("gfortran")
        .args(arguments)
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .envs(environment.iter().copied())
        .output()
        .expect("run fcache with controlled environment")
}

#[cfg(unix)]
fn cached_output_with_umask(fixture: &Fixture, arguments: &[&str], mask: &str) -> Output {
    Command::new("sh")
        .args(["-c", "umask \"$1\"; shift; exec \"$@\"", "fcache-umask", mask])
        .arg(fcache_path())
        .arg("gfortran")
        .args(arguments)
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("run fcache with controlled umask")
}

fn stats(fixture: &Fixture) -> Stats {
    let output = Command::new(fcache_path())
        .args(["--show-stats", "--json"])
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("read fcache statistics");
    assert!(
        output.status.success(),
        "stats command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse fcache statistics JSON")
}

fn regular_files_beneath(directory: &Path) -> Vec<PathBuf> {
    fn visit(directory: &Path, files: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("read cache entry");
            let path = entry.path();
            let file_type = entry.file_type().expect("inspect cache entry");
            if file_type.is_dir() {
                visit(&path, files);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    visit(directory, &mut files);
    files
}

fn evict_only_result_manifest(fixture: &Fixture) {
    let manifests = regular_files_beneath(&fixture.cache.join("v1/results"));
    assert_eq!(manifests.len(), 1, "expected one result manifest");
    fs::remove_file(&manifests[0]).expect("evict result manifest");
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn depfile_has_primary_target(depfile: &[u8], target: &[u8]) -> bool {
    parse_depfile(depfile).expect("parse dependency file").rules.iter().any(|rule| {
        !rule.prerequisites.is_empty() && rule.targets.iter().any(|candidate| candidate == target)
    })
}

fn snapshot(fixture: &Fixture, relative_paths: &[&str]) -> BTreeMap<String, Vec<u8>> {
    relative_paths
        .iter()
        .map(|relative| {
            let path = fixture.path(relative);
            (
                (*relative).to_owned(),
                fs::read(&path).unwrap_or_else(|error| {
                    panic!("read expected artifact {}: {error}", path.display())
                }),
            )
        })
        .collect()
}

fn tree_snapshot(fixture: &Fixture) -> BTreeMap<String, Vec<u8>> {
    fn visit(fixture: &Fixture, directory: &Path, entries: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("read output tree {}: {error}", directory.display()))
        {
            let entry = entry.expect("read output tree entry");
            let path = entry.path();
            if path == fixture.cache {
                continue;
            }
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("inspect output tree {}: {error}", path.display()));
            if file_type.is_dir() {
                visit(fixture, &path, entries);
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(fixture.root.path())
                    .expect("output tree entry is beneath fixture root")
                    .to_string_lossy()
                    .into_owned();
                entries.insert(
                    relative,
                    fs::read(&path).unwrap_or_else(|error| {
                        panic!("read output tree file {}: {error}", path.display())
                    }),
                );
            }
        }
    }

    let mut entries = BTreeMap::new();
    visit(fixture, fixture.root.path(), &mut entries);
    entries
}

fn tree_delta(
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
) -> BTreeMap<String, Option<Vec<u8>>> {
    before
        .keys()
        .chain(after.keys())
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|path| before.get(*path) != after.get(*path))
        .map(|path| (path.to_owned(), after.get(path).cloned()))
        .collect()
}

fn restore_tree(fixture: &Fixture, baseline: &BTreeMap<String, Vec<u8>>) {
    let current = tree_snapshot(fixture);
    for relative in current.keys().filter(|relative| !baseline.contains_key(*relative)) {
        let path = fixture.path(relative);
        fs::remove_file(&path)
            .unwrap_or_else(|error| panic!("remove output tree file {}: {error}", path.display()));
    }
    for (relative, bytes) in baseline {
        let path = fixture.path(relative);
        if fs::read(&path).ok().as_ref() != Some(bytes) {
            fs::write(&path, bytes).unwrap_or_else(|error| {
                panic!("restore output tree file {}: {error}", path.display())
            });
        }
    }
}

fn assert_tree_delta(
    actual: &BTreeMap<String, Option<Vec<u8>>>,
    expected: &BTreeMap<String, Option<Vec<u8>>>,
    context: &str,
) {
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "{context}: output paths differ"
    );
    for (relative, expected_bytes) in expected {
        assert!(
            actual.get(relative) == Some(expected_bytes),
            "{context}: output {relative} differs"
        );
    }
}

fn assert_snapshot(fixture: &Fixture, expected: &BTreeMap<String, Vec<u8>>, context: &str) {
    for (relative, bytes) in expected {
        let actual = fs::read(fixture.path(relative))
            .unwrap_or_else(|error| panic!("{context}: read {relative}: {error}"));
        assert_eq!(actual, *bytes, "{context}: artifact {relative} differs");
    }
}

fn differential_action(compiler: &str, fixture: &Fixture, arguments: &[&str]) {
    let baseline = tree_snapshot(fixture);
    let direct = compiler_output(compiler, fixture, arguments);
    assert_success(&direct, "direct compiler invocation");
    let oracle = tree_delta(&baseline, &tree_snapshot(fixture));
    assert!(!oracle.is_empty(), "direct compiler invocation produced no output-tree delta");

    restore_tree(fixture, &baseline);
    let cold = cached_output(fixture, arguments);
    assert_success(&cold, "cold fcache invocation");
    assert_eq!(cold.stdout, direct.stdout, "cold stdout differs from direct compiler");
    assert_eq!(cold.stderr, direct.stderr, "cold stderr differs from direct compiler");
    assert_tree_delta(
        &tree_delta(&baseline, &tree_snapshot(fixture)),
        &oracle,
        "cold fcache invocation",
    );
    let cold_stats = stats(fixture);
    assert_eq!(cold_stats.requests, 1, "cold invocation request count");
    assert_eq!(cold_stats.misses, 1, "cold invocation miss count");
    assert_eq!(cold_stats.hits, 0, "cold invocation hit count");
    assert_eq!(cold_stats.lookup_results.misses, 1);
    assert_eq!(cold_stats.observed_outcomes.compiler_success, 1);

    restore_tree(fixture, &baseline);
    let warm = cached_output(fixture, arguments);
    assert_success(&warm, "warm fcache invocation");
    assert_eq!(warm.stdout, direct.stdout, "warm stdout differs from direct compiler");
    assert_eq!(warm.stderr, direct.stderr, "warm stderr differs from direct compiler");
    assert_tree_delta(
        &tree_delta(&baseline, &tree_snapshot(fixture)),
        &oracle,
        "warm fcache invocation",
    );
    let warm_stats = stats(fixture);
    assert_eq!(warm_stats.requests, 2, "warm invocation request count");
    assert_eq!(warm_stats.misses, 1, "warm invocation miss count: {warm_stats:?}");
    assert_eq!(warm_stats.hits, 1, "warm invocation hit count");
    assert_eq!(warm_stats.lookup_results.hits, 1);
    assert_eq!(warm_stats.observed_outcomes.cache_hit_success, 1);
}

#[test]
fn direct_cold_warm_object_outputs_match() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    if !gfortran_supports_compiler_free_cpp() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    fixture.modules();
    let arguments =
        ["-cpp", "-MD", "-MF", "basic.d", "-J", "modules", "-c", "basic.F90", "-o", "basic.o"];
    differential_action("gfortran", &fixture, &arguments);
    let result = stats(&fixture);
    assert_eq!(result.direct_path.validated_hits, 1);
    assert!(
        matches!(result.process_counts.fingerprint_queries, 8 | 16),
        "auto identity should either reuse a trusted local witness or fingerprint both requests"
    );
    assert!(result.process_counts.preprocessing_probes <= 2);
    assert_eq!(result.process_counts.dependency_probes, 1);
    assert_eq!(result.process_counts.real_compilations, 1);
    assert_eq!(result.miss_observation.real_md_validation_successes, 1);
    assert_eq!(result.miss_observation.post_compile_probe_attempts, 0);
}

#[test]
fn orphaned_direct_observation_recompiles_from_real_md_without_probes() {
    if !gfortran_available() {
        return;
    }
    if !gfortran_supports_compiler_free_cpp() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    fixture.modules();
    let arguments =
        ["-cpp", "-MD", "-MF", "basic.d", "-J", "modules", "-c", "basic.F90", "-o", "basic.o"];

    let cold = cached_output(&fixture, &arguments);
    assert_success(&cold, "populate cache and direct observation");
    let expected = snapshot(&fixture, &["basic.o", "basic.d"]);
    evict_only_result_manifest(&fixture);
    fixture.remove_outputs(&["basic.o", "basic.d"]);

    let recovered = cached_output(&fixture, &arguments);
    assert_success(&recovered, "compile from orphaned direct observation");
    assert_snapshot(&fixture, &expected, "recompiled orphaned direct observation");
    let recovered_stats = stats(&fixture);
    assert_eq!(recovered_stats.process_counts.real_compilations, 2);
    assert_eq!(recovered_stats.process_counts.dependency_probes, 1);
    assert_eq!(recovered_stats.direct_path.validated_hits, 0);
    assert_eq!(recovered_stats.direct_path.validated_compile_plans, 1);
    assert_eq!(recovered_stats.miss_observation.validated_precompile_selections, 1);
    assert_eq!(recovered_stats.miss_observation.real_md_validation_successes, 2);

    fixture.remove_outputs(&["basic.o", "basic.d"]);
    let warm = cached_output(&fixture, &arguments);
    assert_success(&warm, "restore republished result");
    assert_snapshot(&fixture, &expected, "warm result after orphan recovery");
    let warm_stats = stats(&fixture);
    assert_eq!(warm_stats.process_counts.real_compilations, 2);
    assert_eq!(warm_stats.process_counts.dependency_probes, 1);
    assert_eq!(warm_stats.direct_path.validated_hits, 1);
}

#[test]
fn orphaned_observation_without_real_md_uses_one_post_probe() {
    if !gfortran_available() {
        return;
    }
    if !gfortran_supports_compiler_free_cpp() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let arguments = ["-cpp", "-c", "basic.F90", "-o", "basic.o"];

    assert_success(&cached_output(&fixture, &arguments), "populate result without depfile");
    let expected = snapshot(&fixture, &["basic.o"]);
    evict_only_result_manifest(&fixture);
    fixture.remove_outputs(&["basic.o"]);

    assert_success(
        &cached_output(&fixture, &arguments),
        "compile orphaned observation without real depfile",
    );
    assert_snapshot(&fixture, &expected, "post-probe validated orphan result");
    let result = stats(&fixture);
    assert_eq!(result.process_counts.real_compilations, 2);
    assert_eq!(result.process_counts.dependency_probes, 3);
    assert_eq!(result.direct_path.validated_compile_plans, 1);
    assert_eq!(result.miss_observation.validated_precompile_selections, 1);
    assert_eq!(result.miss_observation.real_md_validation_successes, 0);
    assert_eq!(result.miss_observation.post_compile_probe_attempts, 2);
}

#[test]
fn compiler_assisted_hit_backfills_direct_observation() {
    if !gfortran_available() {
        return;
    }
    if !gfortran_supports_compiler_free_cpp() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    fixture.modules();
    let arguments =
        ["-cpp", "-MD", "-MF", "basic.d", "-J", "modules", "-c", "basic.F90", "-o", "basic.o"];

    assert_success(
        &cached_output_with_env(&fixture, &arguments, &[("FCACHE_DIRECT", "0")]),
        "populate result without direct metadata",
    );
    let expected = snapshot(&fixture, &["basic.o", "basic.d"]);
    fixture.remove_outputs(&["basic.o", "basic.d"]);

    assert_success(
        &cached_output(&fixture, &arguments),
        "compiler-assisted hit that backfills direct metadata",
    );
    assert_snapshot(&fixture, &expected, "compiler-assisted restored result");
    let assisted_stats = stats(&fixture);
    assert_eq!(assisted_stats.process_counts.real_compilations, 1);
    assert_eq!(assisted_stats.process_counts.dependency_probes, 2);
    assert_eq!(assisted_stats.hits, 1);
    assert_eq!(assisted_stats.direct_path.validated_hits, 0);

    fixture.remove_outputs(&["basic.o", "basic.d"]);
    assert_success(&cached_output(&fixture, &arguments), "backfilled direct hit");
    assert_snapshot(&fixture, &expected, "direct restore after backfill");
    let direct_stats = stats(&fixture);
    assert_eq!(direct_stats.process_counts.real_compilations, 1);
    assert_eq!(direct_stats.process_counts.dependency_probes, 2);
    assert_eq!(direct_stats.hits, 2);
    assert_eq!(direct_stats.direct_path.validated_hits, 1);
}

#[cfg(unix)]
#[test]
fn real_md_does_not_publish_when_an_input_changes_after_compilation() {
    use std::os::unix::fs::PermissionsExt;

    if !gfortran_available() {
        return;
    }
    if !gfortran_supports_compiler_free_cpp() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    fixture.modules();
    fs::write(
        fixture.path("replacement.F90"),
        "subroutine increment(value)\n  implicit none\n  integer, intent(inout) :: value\n  value = value + 2\nend subroutine increment\n",
    )
    .expect("write replacement source");
    let real_compiler = env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("gfortran"))
        .find(|candidate| candidate.is_file())
        .expect("resolve real gfortran");
    let wrapper = fixture.path("gfortran");
    fs::write(
        &wrapper,
        r#"#!/bin/sh
real_compile=0
for argument in "$@"; do
  if [ "$argument" = "-c" ]; then
    real_compile=1
  fi
done
"$REAL_GFORTRAN" "$@"
status=$?
if [ "$status" -eq 0 ] && [ "$real_compile" -eq 1 ] && [ -f mutation.trigger ]; then
  cp replacement.F90 basic.F90
fi
exit "$status"
"#,
    )
    .expect("write mutation compiler wrapper");
    let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&wrapper, permissions).expect("make mutation wrapper executable");
    let arguments =
        ["-cpp", "-MD", "-MF", "basic.d", "-J", "modules", "-c", "basic.F90", "-o", "basic.o"];
    let run = || {
        Command::new(fcache_path())
            .arg(&wrapper)
            .args(arguments)
            .current_dir(fixture.root.path())
            .env("FCACHE_DIR", &fixture.cache)
            .env("REAL_GFORTRAN", &real_compiler)
            .output()
            .expect("run through mutation compiler wrapper")
    };

    assert_success(&run(), "populate result and direct observation");
    evict_only_result_manifest(&fixture);
    fixture.remove_outputs(&["basic.o", "basic.d"]);
    fs::write(fixture.path("mutation.trigger"), b"").expect("arm source mutation");

    assert_success(&run(), "compiler result whose input changes before validation");
    assert!(
        regular_files_beneath(&fixture.cache.join("v1/results")).is_empty(),
        "changed input must prevent result publication"
    );
    let result = stats(&fixture);
    assert_eq!(result.direct_path.validated_compile_plans, 1);
    assert_eq!(result.miss_observation.real_md_validation_successes, 1);
    assert_eq!(result.bypass_reasons.get("inputs-changed-during-compilation"), Some(&1));
}

#[cfg(unix)]
#[test]
fn trusted_auto_identity_makes_warm_direct_hits_driver_free() {
    use std::os::unix::fs::PermissionsExt;

    if !gfortran_available() {
        return;
    }
    if !gfortran_supports_compiler_free_cpp() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let real_compiler = env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("gfortran"))
        .find(|candidate| candidate.is_file())
        .expect("resolve real gfortran");
    let wrapper_dir = fixture.path("wrapper");
    fs::create_dir(&wrapper_dir).expect("create compiler wrapper directory");
    let wrapper = wrapper_dir.join("gfortran");
    let trace = fixture.path("driver.trace");
    fs::write(&wrapper, "#!/bin/sh\nprintf x >> \"$TRACE_PATH\"\nexec \"$REAL_GFORTRAN\" \"$@\"\n")
        .expect("write compiler wrapper");
    let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&wrapper, permissions).expect("make compiler wrapper executable");
    let arguments = ["-cpp", "-c", "basic.F90", "-o", "basic.o"];
    let run = || {
        Command::new(fcache_path())
            .arg(&wrapper)
            .args(arguments)
            .current_dir(fixture.root.path())
            .env("FCACHE_DIR", &fixture.cache)
            .env("TRACE_PATH", &trace)
            .env("REAL_GFORTRAN", &real_compiler)
            .output()
            .expect("run fcache through tracing compiler wrapper")
    };
    assert_success(&run(), "cold traced compiler invocation");
    fixture.remove_outputs(&["basic.o"]);
    fs::write(&trace, b"").expect("reset compiler trace");
    assert_success(&run(), "warm traced compiler invocation");

    let result = stats(&fixture);
    assert_eq!(result.direct_path.validated_hits, 1);
    if result.process_counts.fingerprint_queries == 8 {
        assert!(fs::read(&trace).unwrap().is_empty(), "trusted warm hit executed the driver");
    } else {
        assert_eq!(result.process_counts.fingerprint_queries, 16);
    }
}

#[cfg(unix)]
#[test]
fn output_creation_umask_participates_in_cache_identity() {
    use std::os::unix::fs::PermissionsExt;

    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let arguments = ["-cpp", "-c", "basic.F90", "-o", "basic.o"];
    assert_success(
        &cached_output_with_umask(&fixture, &arguments, "022"),
        "compile with permissive umask",
    );
    assert_eq!(fs::metadata(fixture.path("basic.o")).unwrap().permissions().mode() & 0o777, 0o644);
    fixture.remove_outputs(&["basic.o"]);
    assert_success(
        &cached_output_with_umask(&fixture, &arguments, "077"),
        "compile with restrictive umask",
    );
    assert_eq!(fs::metadata(fixture.path("basic.o")).unwrap().permissions().mode() & 0o777, 0o600);
    let result = stats(&fixture);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 2, "different creation modes require distinct cache actions");
}

#[test]
fn direct_cold_warm_multiple_modules_match() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("multi_modules.F90");
    fixture.modules();
    let arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "multi.d",
        "-J",
        "modules",
        "-c",
        "multi_modules.F90",
        "-o",
        "multi_modules.o",
    ];
    differential_action("gfortran", &fixture, &arguments);

    fixture.remove_outputs(&["multi_modules.o", "multi.d"]);
    let retained_modules = cached_output(&fixture, &arguments);
    assert_success(&retained_modules, "warm invocation with retained module outputs");
    let retained_stats = stats(&fixture);
    assert_eq!(retained_stats.requests, 3);
    assert_eq!(retained_stats.misses, 1);
    assert_eq!(retained_stats.hits, 2);
}

#[test]
fn orphaned_module_observation_recompiles_complete_bundle() {
    if !gfortran_available() {
        return;
    }
    if !gfortran_supports_compiler_free_cpp() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("multi_modules.F90");
    fixture.modules();
    let arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "multi.d",
        "-J",
        "modules",
        "-c",
        "multi_modules.F90",
        "-o",
        "multi_modules.o",
    ];

    assert_success(&cached_output(&fixture, &arguments), "populate module bundle");
    let outputs =
        ["multi_modules.o", "multi.d", "modules/first_module.mod", "modules/second_module.mod"];
    let expected = snapshot(&fixture, &outputs);
    evict_only_result_manifest(&fixture);
    fixture.remove_outputs(&outputs);

    assert_success(
        &cached_output(&fixture, &arguments),
        "compile module bundle from orphaned observation",
    );
    assert_snapshot(&fixture, &expected, "recompiled complete module bundle");
    let result = stats(&fixture);
    assert_eq!(result.process_counts.real_compilations, 2);
    assert_eq!(result.process_counts.dependency_probes, 1);
    assert_eq!(result.direct_path.validated_compile_plans, 1);
}

#[test]
fn retained_modules_warm_hit_in_cwd_and_shared_search_output_directory() {
    if !gfortran_available() {
        return;
    }
    for (case, module_arguments, retained_modules) in [
        ("cwd", Vec::new(), vec!["first_module.mod", "second_module.mod"]),
        (
            "shared-search-output",
            vec!["-I", "modules", "-J", "modules"],
            vec!["modules/first_module.mod", "modules/second_module.mod"],
        ),
    ] {
        let fixture = Fixture::new();
        fixture.copy_fixture("multi_modules.F90");
        if case == "shared-search-output" {
            fixture.modules();
        }
        let mut arguments = vec!["-cpp", "-MD", "-MF", "multi.d"];
        arguments.extend(module_arguments);
        arguments.extend(["-c", "multi_modules.F90", "-o", "multi_modules.o"]);

        differential_action("gfortran", &fixture, &arguments);
        for module in &retained_modules {
            assert!(fixture.path(module).is_file(), "{case}: missing retained module {module}");
        }

        fixture.remove_outputs(&["multi_modules.o", "multi.d"]);
        assert_success(
            &cached_output(&fixture, &arguments),
            &format!("{case}: warm invocation with retained modules"),
        );
        let result = stats(&fixture);
        assert_eq!(result.requests, 3, "{case}: request count");
        assert_eq!(result.misses, 1, "{case}: miss count");
        assert_eq!(result.hits, 2, "{case}: retained modules must preserve a hit");
    }
}

#[test]
fn differing_retained_module_passes_through_instead_of_restoring_stale_outputs() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("multi_modules.F90");
    fixture.modules();
    let arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "multi.d",
        "-I",
        "modules",
        "-J",
        "modules",
        "-c",
        "multi_modules.F90",
        "-o",
        "multi_modules.o",
    ];
    assert_success(&cached_output(&fixture, &arguments), "populate module-producing cache entry");
    let expected_module =
        fs::read(fixture.path("modules/first_module.mod")).expect("read expected retained module");

    fs::create_dir(fixture.path("alternate")).expect("create alternate module directory");
    fs::write(
        fixture.path("alternate/first_module.F90"),
        "module first_module\n  implicit none\n  integer, parameter :: first_value = 99\nend module first_module\n",
    )
    .expect("write alternate module provider");
    assert_success(
        &compiler_output(
            "gfortran",
            &fixture,
            &[
                "-J",
                "alternate",
                "-c",
                "alternate/first_module.F90",
                "-o",
                "alternate/first_module.o",
            ],
        ),
        "compile alternate retained module",
    );
    let differing_module = fs::read(fixture.path("alternate/first_module.mod"))
        .expect("read alternate retained module");
    assert_ne!(differing_module, expected_module, "alternate interface must differ");
    fs::write(fixture.path("modules/first_module.mod"), &differing_module)
        .expect("replace retained module with different valid interface");
    fixture.remove_outputs(&["multi_modules.o", "multi.d"]);

    let baseline = tree_snapshot(&fixture);
    let direct = compiler_output("gfortran", &fixture, &arguments);
    assert_success(&direct, "direct compile with differing retained module");
    let oracle = tree_delta(&baseline, &tree_snapshot(&fixture));
    assert!(!oracle.is_empty(), "direct compile produced no output-tree delta");

    restore_tree(&fixture, &baseline);
    let cached = cached_output(&fixture, &arguments);
    assert_success(&cached, "fcache compile with differing retained module");
    assert_eq!(cached.stdout, direct.stdout);
    assert_eq!(cached.stderr, direct.stderr);
    assert_tree_delta(
        &tree_delta(&baseline, &tree_snapshot(&fixture)),
        &oracle,
        "fcache compile with differing retained module",
    );
    assert_eq!(
        fs::read(fixture.path("modules/first_module.mod")).expect("read regenerated module"),
        expected_module,
        "real compiler must replace the differing retained module",
    );
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0, "differing retained module must not restore a stale object");
    assert_eq!(result.misses, 1, "unsafe observation must pass through before lookup");
    assert_eq!(result.lookup_results.not_attempted, 1);
}

#[test]
fn dependency_target_options_preserve_warm_depfiles() {
    if !gfortran_available() {
        return;
    }
    for (case, target_arguments) in [
        ("mt", vec!["-MT", "custom-target"]),
        ("mq", vec!["-MQ", "target $ with # space"]),
        ("repeated-mt", vec!["-MT", "first-target", "-MT", "second-target"]),
    ] {
        let fixture = Fixture::new();
        fixture.copy_fixture("basic.F90");
        let mut arguments = vec!["-cpp", "-MD", "-MF", "basic.d"];
        arguments.extend(target_arguments);
        arguments.extend(["-c", "basic.F90", "-o", "basic.o"]);

        differential_action("gfortran", &fixture, &arguments);
        let depfile = fs::read(fixture.path("basic.d")).expect("read target-option depfile");
        match case {
            "mt" => assert!(depfile_has_primary_target(&depfile, b"custom-target")),
            "mq" => assert!(depfile_has_primary_target(&depfile, b"target $ with # space")),
            "repeated-mt" => assert!(depfile_has_primary_target(&depfile, b"second-target")),
            _ => unreachable!(),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn wsjtx_linux_flags_preserve_complete_warm_results() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    fixture.modules();
    differential_action(
        "gfortran",
        &fixture,
        &[
            "-cpp",
            "-MD",
            "-MF",
            "basic.d",
            "-J",
            "modules",
            "-fbounds-check",
            "-funroll-all-loops",
            "-fbacktrace",
            "-Wmaybe-uninitialized",
            "-Wa,--noexecstack",
            "-fdata-sections",
            "-ffunction-sections",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-c",
            "basic.F90",
            "-o",
            "basic.o",
        ],
    );
}

#[cfg(target_os = "macos")]
#[test]
fn wsjtx_macos_flags_preserve_complete_warm_results() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    fixture.modules();
    fs::create_dir(fixture.path("frameworks")).expect("create framework search directory");
    differential_action(
        "gfortran",
        &fixture,
        &[
            "-cpp",
            "-MD",
            "-MF",
            "basic.d",
            "-J",
            "modules",
            "-iframework",
            "frameworks",
            "-Fframeworks",
            "-fbounds-check",
            "-funroll-all-loops",
            "-fbacktrace",
            "-Wmaybe-uninitialized",
            "-c",
            "basic.F90",
            "-o",
            "basic.o",
        ],
    );
}

#[test]
fn literal_phony_target_keeps_includes_in_the_action_key() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("phony.F90"),
        "program phony\n#include \"value.inc\"\n  print *, value\nend program phony\n",
    )
    .expect("write phony-target source");
    fs::write(fixture.path("value.inc"), "integer, parameter :: value = 1\n")
        .expect("write phony-target include");
    let arguments =
        ["-cpp", "-MD", "-MF", "phony.d", "-MT", ".PHONY", "-c", "phony.F90", "-o", "phony.o"];

    differential_action("gfortran", &fixture, &arguments);
    assert!(depfile_has_primary_target(&fs::read(fixture.path("phony.d")).unwrap(), b".PHONY"));

    fs::write(fixture.path("value.inc"), "integer, parameter :: value = 2\n")
        .expect("change phony-target include");
    fixture.remove_outputs(&["phony.o", "phony.d"]);
    assert_success(&cached_output(&fixture, &arguments), "changed include with .PHONY target");
    let result = stats(&fixture);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "changed include must invalidate the cached object");
}

#[test]
fn module_consumer_mp_dummy_rule_is_preserved_on_warm_hit() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    compile_shadow_provider(&fixture, "mods", 4);
    fs::write(
        fixture.path("consumer.F90"),
        "subroutine consume(value)\n  use shadow\n  implicit none\n  integer, intent(out) :: value\n  value = which\nend subroutine consume\n",
    )
    .expect("write module consumer");
    let arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "consumer.d",
        "-MP",
        "-I",
        "mods",
        "-c",
        "consumer.F90",
        "-o",
        "consumer.o",
    ];

    differential_action("gfortran", &fixture, &arguments);
    let depfile = fs::read(fixture.path("consumer.d")).expect("read MP depfile");
    assert!(
        depfile.windows(b"mods/shadow.mod:\n".len()).any(|bytes| bytes == b"mods/shadow.mod:\n"),
        "depfile must retain the consumed-module dummy rule: {}",
        String::from_utf8_lossy(&depfile),
    );
}

#[test]
fn syntax_only_depfile_uses_requested_object_target_and_warm_hits() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let arguments =
        ["-cpp", "-MD", "-MF", "syntax.d", "-fsyntax-only", "-o", "named.o", "basic.F90"];

    differential_action("gfortran", &fixture, &arguments);
    assert!(!fixture.path("named.o").exists(), "syntax-only invocation created an object");
    let depfile = fs::read(fixture.path("syntax.d")).expect("read syntax-only depfile");
    assert!(depfile_has_primary_target(&depfile, b"named.o"));
}

#[test]
fn mmd_openmp_depfile_warm_hits_with_full_probe_inputs() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("openmp.F90"),
        "subroutine use_openmp(value)\n  use omp_lib\n  implicit none\n  integer, intent(out) :: value\n  value = omp_get_num_threads()\nend subroutine use_openmp\n",
    )
    .expect("write OpenMP intrinsic-module consumer");
    let arguments =
        ["-cpp", "-MMD", "-MF", "openmp.d", "-fopenmp", "-c", "openmp.F90", "-o", "openmp.o"];

    differential_action("gfortran", &fixture, &arguments);
    let depfile = fs::read_to_string(fixture.path("openmp.d")).expect("read MMD depfile");
    assert!(depfile.contains("openmp.F90"));
    assert!(!depfile.contains("omp_lib.mod"), "MMD depfile unexpectedly includes system module");

    let report = explain_json(&fixture, &arguments);
    assert_eq!(report["decision"], "cacheable");
    assert!(
        report["inputs"]
            .as_array()
            .expect("explain inputs")
            .iter()
            .any(|input| input["path"].as_str().is_some_and(|path| path.ends_with("omp_lib.mod"))),
        "full private probe must hash the file-backed OpenMP module: {report}",
    );
}

#[test]
fn generated_fpreprocessed_source_passes_through_with_complete_outputs() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("generated.f90");
    fixture.modules();
    let arguments = ["-fpreprocessed", "-J", "modules", "-c", "generated.f90", "-o", "generated.o"];
    let baseline = tree_snapshot(&fixture);
    let direct = compiler_output("gfortran", &fixture, &arguments);
    assert_success(&direct, "direct fpreprocessed invocation");
    let oracle = tree_delta(&baseline, &tree_snapshot(&fixture));

    for invocation in 1..=2 {
        restore_tree(&fixture, &baseline);
        let cached = cached_output(&fixture, &arguments);
        assert_success(&cached, "fcache fpreprocessed pass-through");
        assert_eq!(cached.stdout, direct.stdout);
        assert_eq!(cached.stderr, direct.stderr);
        assert_tree_delta(
            &tree_delta(&baseline, &tree_snapshot(&fixture)),
            &oracle,
            &format!("fpreprocessed pass-through invocation {invocation}"),
        );
    }
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.lookup_results.not_attempted, 2);
    assert_eq!(result.bypass_reasons.get("dependency-probe-preprocessing"), Some(&2));
}

#[test]
fn explain_is_a_dry_run_with_stable_exit_semantics() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    fixture.modules();
    let baseline = tree_snapshot(&fixture);

    let cacheable = Command::new(fcache_path())
        .args([
            "--explain",
            "--json",
            "--",
            "gfortran",
            "-cpp",
            "-J",
            "modules",
            "-c",
            "basic.F90",
            "-o",
            "basic.o",
        ])
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("explain cacheable action");
    assert_success(&cacheable, "explain cacheable action");
    let report: serde_json::Value =
        serde_json::from_slice(&cacheable.stdout).expect("parse explain JSON");
    assert_eq!(report["decision"], "cacheable");
    assert!(report["action_key"].as_str().is_some());
    assert_eq!(tree_snapshot(&fixture), baseline, "explain modified the build tree");
    assert!(!fixture.cache.join("v1/stats").exists(), "explain updated statistics");

    let bypass = Command::new(fcache_path())
        .args([
            "--explain",
            "--json",
            "--",
            "gfortran",
            "-x",
            "f95",
            "-c",
            "basic.F90",
            "-o",
            "basic.o",
        ])
        .current_dir(fixture.root.path())
        .output()
        .expect("explain bypassed action");
    assert_eq!(bypass.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&bypass.stdout).expect("parse bypass explain JSON");
    assert_eq!(report["decision"], "bypass");
    assert!(report["reason"].as_str().is_some_and(|reason| reason.contains("language-override")));

    let missing_compiler = fixture.path("missing/gfortran");
    let tool_failure = Command::new(fcache_path())
        .arg("--explain")
        .arg("--")
        .arg(&missing_compiler)
        .args(["-cpp", "-c", "basic.F90", "-o", "basic.o"])
        .current_dir(fixture.root.path())
        .output()
        .expect("explain missing compiler");
    assert_eq!(tool_failure.status.code(), Some(2));
}

#[test]
fn disable_environment_bypasses_an_invalid_config() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let output = Command::new(fcache_path())
        .args(["gfortran", "-cpp", "-c", "basic.F90", "-o", "basic.o"])
        .current_dir(fixture.root.path())
        .env("FCACHE_DISABLE", "1")
        .env("FCACHE_CONFIG", fixture.path("missing.toml"))
        .output()
        .expect("run disabled launcher with invalid config");
    assert_success(&output, "disabled launcher with invalid config");
    assert!(fixture.path("basic.o").is_file());
    assert!(!fixture.cache.join("v1").exists());
}

#[test]
fn direct_cold_warm_parent_and_child_submodule_match() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("parent.F90");
    fixture.copy_fixture("child.F90");
    fixture.modules();
    let parent_arguments =
        ["-cpp", "-MD", "-MF", "parent.d", "-J", "modules", "-c", "parent.F90", "-o", "parent.o"];
    let child_arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "child.d",
        "-J",
        "modules",
        "-I",
        "modules",
        "-c",
        "child.F90",
        "-o",
        "child.o",
    ];

    let direct_parent = compiler_output("gfortran", &fixture, &parent_arguments);
    assert_success(&direct_parent, "direct parent compiler invocation");
    let parent_oracle = snapshot(
        &fixture,
        &["parent.o", "parent.d", "modules/parent_module.mod", "modules/parent_module.smod"],
    );
    let direct_child = compiler_output("gfortran", &fixture, &child_arguments);
    assert_success(&direct_child, "direct child compiler invocation");
    let child_oracle =
        snapshot(&fixture, &["child.o", "child.d", "modules/parent_module@child_module.smod"]);

    fixture.remove_outputs(&[
        "parent.o",
        "parent.d",
        "modules/parent_module.mod",
        "modules/parent_module.smod",
        "child.o",
        "child.d",
        "modules/parent_module@child_module.smod",
    ]);
    let cold_parent = cached_output(&fixture, &parent_arguments);
    assert_success(&cold_parent, "cold parent fcache invocation");
    assert_snapshot(&fixture, &parent_oracle, "cold parent fcache invocation");
    let cold_child = cached_output(&fixture, &child_arguments);
    assert_success(&cold_child, "cold child fcache invocation");
    assert_snapshot(&fixture, &child_oracle, "cold child fcache invocation");
    let cold_stats = stats(&fixture);
    assert_eq!(cold_stats.requests, 2);
    assert_eq!(cold_stats.misses, 2);
    assert_eq!(cold_stats.hits, 0);

    fixture.remove_outputs(&["child.o", "child.d", "modules/parent_module@child_module.smod"]);
    let warm_child = cached_output(&fixture, &child_arguments);
    assert_success(&warm_child, "warm child fcache invocation");
    assert_eq!(warm_child.stdout, direct_child.stdout);
    assert_eq!(warm_child.stderr, direct_child.stderr);
    assert_snapshot(&fixture, &child_oracle, "warm child fcache invocation");
    let warm_stats = stats(&fixture);
    assert_eq!(warm_stats.requests, 3);
    assert_eq!(warm_stats.misses, 2);
    assert_eq!(warm_stats.hits, 1);
}

#[test]
fn module_content_change_invalidates_cached_consumer() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    let parent = fixture.copy_fixture("parent.F90");
    fixture.copy_fixture("consumer.F90");
    fixture.modules();
    let parent_arguments =
        ["-cpp", "-MD", "-MF", "parent.d", "-J", "modules", "-c", "parent.F90", "-o", "parent.o"];
    let consumer_arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "consumer.d",
        "-J",
        "modules",
        "-I",
        "modules",
        "-c",
        "consumer.F90",
        "-o",
        "consumer.o",
    ];
    assert_success(&cached_output(&fixture, &parent_arguments), "initial parent fcache invocation");
    assert_success(
        &cached_output(&fixture, &consumer_arguments),
        "initial consumer fcache invocation",
    );
    let before = stats(&fixture);
    assert_eq!(before.requests, 2);
    assert_eq!(before.misses, 2);
    assert_eq!(before.hits, 0);

    let mut parent_source = fs::read_to_string(&parent).expect("read parent source");
    parent_source = parent_source.replace(
        "  end interface\nend module parent_module",
        "  end interface\n  integer, parameter :: changed_value = 7\nend module parent_module",
    );
    fs::write(&parent, parent_source).expect("change parent module content");
    assert_success(&cached_output(&fixture, &parent_arguments), "changed parent fcache invocation");
    fixture.remove_outputs(&[
        "consumer.o",
        "consumer.d",
        "modules/consumer_module.mod",
        "modules/consumer_module.smod",
    ]);
    let changed_consumer = cached_output(&fixture, &consumer_arguments);
    assert_success(&changed_consumer, "consumer after module content change");
    let after = stats(&fixture);
    assert_eq!(after.requests, 4);
    assert_eq!(after.misses, 4, "consumer must miss after dependency content changes");
    assert_eq!(after.hits, 0);
}

#[test]
fn implementation_only_module_change_preserves_downstream_hit() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    let provider = fixture.copy_fixture("implementation_module.F90");
    fixture.copy_fixture("implementation_consumer.F90");
    fixture.modules();
    let provider_arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "implementation_module.d",
        "-J",
        "modules",
        "-c",
        "implementation_module.F90",
        "-o",
        "implementation_module.o",
    ];
    let consumer_arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "implementation_consumer.d",
        "-J",
        "modules",
        "-I",
        "modules",
        "-c",
        "implementation_consumer.F90",
        "-o",
        "implementation_consumer.o",
    ];
    assert_success(
        &cached_output(&fixture, &provider_arguments),
        "initial implementation provider compile",
    );
    assert_success(
        &cached_output(&fixture, &consumer_arguments),
        "initial implementation consumer compile",
    );
    let module_before = fs::read(fixture.path("modules/implementation_module.mod"))
        .expect("read initial implementation module");
    let object_before = fs::read(fixture.path("implementation_module.o"))
        .expect("read initial implementation object");

    let changed_source = fs::read_to_string(&provider)
        .expect("read implementation provider")
        .replace("computed_value = input + 1", "computed_value = input + 2");
    fs::write(&provider, changed_source).expect("change module implementation");
    assert_success(
        &cached_output(&fixture, &provider_arguments),
        "changed implementation provider compile",
    );
    let module_after = fs::read(fixture.path("modules/implementation_module.mod"))
        .expect("read changed implementation module");
    let object_after = fs::read(fixture.path("implementation_module.o"))
        .expect("read changed implementation object");
    assert_eq!(
        module_after, module_before,
        "implementation-only edit changed the compiler module interface"
    );
    assert_ne!(object_after, object_before, "implementation edit did not change provider object");

    fixture.remove_outputs(&[
        "implementation_consumer.o",
        "implementation_consumer.d",
        "modules/implementation_consumer.mod",
    ]);
    assert_success(
        &cached_output(&fixture, &consumer_arguments),
        "consumer after implementation-only provider change",
    );
    let result = stats(&fixture);
    assert_eq!(result.requests, 4);
    assert_eq!(result.misses, 3);
    assert_eq!(result.hits, 1, "unchanged module bytes must preserve the downstream consumer hit");
}

#[test]
fn same_named_external_input_is_not_mistaken_for_generated_module() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    fixture.modules();
    fs::create_dir(fixture.path("external")).expect("create external input directory");
    fs::write(
        fixture.path("foo.F90"),
        "module foo\n#include \"external/foo.mod\"\n  implicit none\n  integer, parameter :: value = EXTERNAL_VALUE\nend module foo\n",
    )
    .expect("write collision source");
    fs::write(fixture.path("external/foo.mod"), "#define EXTERNAL_VALUE 1\n")
        .expect("write same-named external input");
    let arguments =
        ["-cpp", "-MD", "-MF", "foo.d", "-J", "modules", "-c", "foo.F90", "-o", "foo.o"];
    assert_success(&cached_output(&fixture, &arguments), "initial collision compile");
    assert_success(&cached_output(&fixture, &arguments), "warm collision compile");

    fs::write(fixture.path("external/foo.mod"), "#define EXTERNAL_VALUE 2\n")
        .expect("change same-named external input");
    let changed = cached_output(&fixture, &arguments);
    assert_success(&changed, "collision compile after external input change");
    let result = stats(&fixture);
    assert_eq!(result.requests, 3);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "same-named external input must remain in the cache key");
}

#[test]
fn included_source_content_change_invalidates_result() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("include_module.F90");
    let include = fixture.copy_fixture("included_value.inc");
    fixture.modules();
    let arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "include_module.d",
        "-J",
        "modules",
        "-c",
        "include_module.F90",
        "-o",
        "include_module.o",
    ];
    assert_success(&cached_output(&fixture, &arguments), "initial include compile");
    assert_success(&cached_output(&fixture, &arguments), "warm include compile");

    fs::write(&include, "integer, parameter :: included_value = 8\n")
        .expect("change included source");
    assert_success(&cached_output(&fixture, &arguments), "include compile after dependency change");
    let result = stats(&fixture);
    assert_eq!(result.requests, 3);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "included source content must remain in the cache key");
}

#[cfg(unix)]
#[test]
fn distinct_include_spellings_that_share_an_inode_remain_independent_dependencies() {
    if !gfortran_available() {
        return;
    }
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    fs::write(
        fixture.path("source.F90"),
        "subroutine values(first, second)\n  implicit none\n  integer, intent(out) :: first, second\n#include \"a.inc\"\n  first = VALUE\n#undef VALUE\n#include \"b.inc\"\n  second = VALUE\nend subroutine values\n",
    )
    .expect("write include consumer");
    fs::write(fixture.path("shared.inc"), "#define VALUE 1\n").expect("write shared include");
    symlink("shared.inc", fixture.path("a.inc")).expect("link first include spelling");
    symlink("shared.inc", fixture.path("b.inc")).expect("link second include spelling");
    let arguments = ["-cpp", "-MD", "-MF", "source.d", "-c", "source.F90", "-o", "source.o"];
    assert_success(&cached_output(&fixture, &arguments), "cold aliased-include compile");
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(&cached_output(&fixture, &arguments), "warm aliased-include compile");

    fs::remove_file(fixture.path("b.inc")).expect("remove second include symlink");
    fs::write(fixture.path("b.inc"), "#define VALUE 2\n").expect("replace second include");
    fixture.remove_outputs(&["source.o", "source.d"]);
    let oracle = compiler_output("gfortran", &fixture, &arguments);
    assert_success(&oracle, "direct compile after replacing one alias");
    let expected = snapshot(&fixture, &["source.o", "source.d"]);
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(
        &cached_output(&fixture, &arguments),
        "cached compile after replacing one alias",
    );
    assert_snapshot(&fixture, &expected, "changed aliased include");

    let result = stats(&fixture);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "each compiler-emitted include spelling must be witnessed");
}

#[cfg(unix)]
#[test]
fn earlier_symlink_alias_changes_raw_dependency_identity() {
    if !gfortran_available() {
        return;
    }
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    fs::create_dir_all(fixture.path("first")).expect("create first include directory");
    fs::create_dir_all(fixture.path("second")).expect("create second include directory");
    fs::write(
        fixture.path("source.F90"),
        "subroutine include_path(value)\n  implicit none\n  integer, intent(out) :: value\n#include <value.inc>\n  value = len(INCLUDED_PATH)\nend subroutine include_path\n",
    )
    .expect("write path-sensitive include consumer");
    fs::write(
        fixture.path("shared.inc"),
        "character(len=*), parameter :: INCLUDED_PATH = __FILE__\n",
    )
    .expect("write path-sensitive include");
    symlink("../shared.inc", fixture.path("second/value.inc"))
        .expect("link later include candidate");
    let arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "source.d",
        "-I",
        "first",
        "-I",
        "second",
        "-c",
        "source.F90",
        "-o",
        "source.o",
    ];
    assert_success(&cached_output(&fixture, &arguments), "cold path-sensitive include compile");
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(&cached_output(&fixture, &arguments), "warm path-sensitive include compile");

    symlink("../shared.inc", fixture.path("first/value.inc"))
        .expect("add earlier include candidate");
    fixture.remove_outputs(&["source.o", "source.d"]);
    let oracle = compiler_output("gfortran", &fixture, &arguments);
    assert_success(&oracle, "direct compile with earlier include candidate");
    let expected = snapshot(&fixture, &["source.o", "source.d"]);
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(&cached_output(&fixture, &arguments), "cached compile with earlier candidate");
    assert_snapshot(&fixture, &expected, "earlier include candidate");

    let result = stats(&fixture);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "raw dependency spelling must participate in the action key");
}

#[test]
fn mod_named_include_uses_both_include_and_module_resolution_witnesses() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.path("src")).expect("create source directory");
    fs::create_dir_all(fixture.path("includes")).expect("create include directory");
    fs::write(
        fixture.path("src/source.F90"),
        "subroutine mod_include(value)\n  implicit none\n  integer, intent(out) :: value\n#include \"foo.mod\"\n  value = INCLUDED_VALUE\nend subroutine mod_include\n",
    )
    .expect("write mod-named include consumer");
    fs::write(fixture.path("includes/foo.mod"), "#define INCLUDED_VALUE 1\n")
        .expect("write fallback mod-named include");
    let arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "source.d",
        "-I",
        "includes",
        "-c",
        "src/source.F90",
        "-o",
        "source.o",
    ];
    assert_success(&cached_output(&fixture, &arguments), "cold mod-named include compile");
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(&cached_output(&fixture, &arguments), "warm mod-named include compile");

    fs::write(fixture.path("src/foo.mod"), "#define INCLUDED_VALUE 2\n")
        .expect("write source-adjacent mod-named include");
    fixture.remove_outputs(&["source.o", "source.d"]);
    let oracle = compiler_output("gfortran", &fixture, &arguments);
    assert_success(&oracle, "direct compile with source-adjacent mod-named include");
    let expected = snapshot(&fixture, &["source.o", "source.d"]);
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(
        &cached_output(&fixture, &arguments),
        "cached compile with source-adjacent mod-named include",
    );
    assert_snapshot(&fixture, &expected, "source-adjacent mod-named include");

    let result = stats(&fixture);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "a .mod suffix cannot imply module-only search semantics");
}

#[cfg(unix)]
#[test]
fn nested_include_witnesses_the_lexical_symlink_parent() {
    if !gfortran_available() {
        return;
    }
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    fs::create_dir_all(fixture.path("links")).expect("create lexical include directory");
    fs::create_dir_all(fixture.path("real")).expect("create real include directory");
    fs::create_dir_all(fixture.path("fallback")).expect("create fallback include directory");
    fs::write(fixture.path("real/parent.inc"), "#include \"child.inc\"\n")
        .expect("write parent include");
    fs::write(fixture.path("fallback/child.inc"), "#define INCLUDED_VALUE 1\n")
        .expect("write fallback child include");
    symlink("../real/parent.inc", fixture.path("links/parent.inc")).expect("link parent include");
    let parent = fixture.path("links/parent.inc");
    fs::write(
        fixture.path("source.F90"),
        format!(
            "subroutine nested_include(value)\n  implicit none\n  integer, intent(out) :: value\n#include \"{}\"\n  value = INCLUDED_VALUE\nend subroutine nested_include\n",
            parent.display()
        ),
    )
    .expect("write nested include consumer");
    let arguments =
        ["-cpp", "-MD", "-MF", "source.d", "-I", "fallback", "-c", "source.F90", "-o", "source.o"];
    assert_success(&cached_output(&fixture, &arguments), "cold nested include compile");
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(&cached_output(&fixture, &arguments), "warm nested include compile");

    fs::write(fixture.path("links/child.inc"), "#define INCLUDED_VALUE 2\n")
        .expect("write lexical-parent child include");
    fixture.remove_outputs(&["source.o", "source.d"]);
    let oracle = compiler_output("gfortran", &fixture, &arguments);
    assert_success(&oracle, "direct compile with lexical-parent child");
    let expected = snapshot(&fixture, &["source.o", "source.d"]);
    fixture.remove_outputs(&["source.o", "source.d"]);
    assert_success(&cached_output(&fixture, &arguments), "cached compile with lexical child");
    assert_snapshot(&fixture, &expected, "lexical-parent nested include");

    let result = stats(&fixture);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "lexical include parents must be witnessed");
}

#[test]
fn missing_required_module_does_not_restore_cached_consumer() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("parent.F90");
    fixture.copy_fixture("consumer.F90");
    fixture.modules();
    let parent_arguments =
        ["-cpp", "-MD", "-MF", "parent.d", "-J", "modules", "-c", "parent.F90", "-o", "parent.o"];
    let consumer_arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "consumer.d",
        "-J",
        "modules",
        "-I",
        "modules",
        "-c",
        "consumer.F90",
        "-o",
        "consumer.o",
    ];
    assert_success(&cached_output(&fixture, &parent_arguments), "parent fcache invocation");
    assert_success(&cached_output(&fixture, &consumer_arguments), "consumer fcache invocation");
    fixture.remove_outputs(&[
        "consumer.o",
        "consumer.d",
        "modules/consumer_module.mod",
        "modules/consumer_module.smod",
        "modules/parent_module.mod",
        "modules/parent_module.smod",
    ]);
    let missing = cached_output(&fixture, &consumer_arguments);
    assert!(!missing.status.success(), "missing module must fail through to gfortran");
    assert!(!fixture.path("consumer.o").exists(), "failed compile created an object");
    assert!(!fixture.path("modules/consumer_module.mod").exists());
    assert!(!fixture.path("modules/consumer_module.smod").exists());
    let result = stats(&fixture);
    assert_eq!(result.requests, 3);
    assert_eq!(result.hits, 0, "missing module must not restore a cached consumer");
    assert_eq!(result.misses, 2);
    assert_eq!(result.bypass_reasons.get("dependency-probe"), Some(&1));
}

#[test]
fn warnings_are_replayed_on_warm_hit() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    let source = fixture.path("warning.F90");
    fs::write(
        &source,
        "subroutine warning(value)\n  implicit none\n  integer, intent(in) :: value\n  integer :: unused\nend subroutine warning\n",
    )
    .expect("write warning fixture");
    fixture.modules();
    let arguments = [
        "-cpp",
        "-Wall",
        "-MD",
        "-MF",
        "warning.d",
        "-J",
        "modules",
        "-c",
        "warning.F90",
        "-o",
        "warning.o",
    ];
    let direct = compiler_output("gfortran", &fixture, &arguments);
    assert_success(&direct, "direct warning compiler invocation");
    assert!(!direct.stderr.is_empty(), "warning fixture did not emit a warning");
    let oracle = snapshot(&fixture, &["warning.o", "warning.d"]);
    fixture.remove_outputs(&["warning.o", "warning.d"]);

    let cold = cached_output(&fixture, &arguments);
    assert_success(&cold, "cold warning fcache invocation");
    assert_eq!(cold.stderr, direct.stderr, "cold invocation did not replay compiler warning");
    assert_snapshot(&fixture, &oracle, "cold warning fcache invocation");
    fixture.remove_outputs(&["warning.o", "warning.d"]);
    let warm = cached_output(&fixture, &arguments);
    assert_success(&warm, "warm warning fcache invocation");
    assert_eq!(warm.stderr, direct.stderr, "warm hit did not replay compiler warning");
    assert_snapshot(&fixture, &oracle, "warm warning fcache invocation");
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.misses, 1);
    assert_eq!(result.hits, 1);
}

#[test]
fn failed_compile_is_not_cached() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    let source = fixture.path("broken.F90");
    fs::write(
        &source,
        "module broken_module\n  implicit none\n  this is not valid Fortran\nend module broken_module\n",
    )
    .expect("write failed-compile fixture");
    fixture.modules();
    let arguments =
        ["-cpp", "-MD", "-MF", "broken.d", "-J", "modules", "-c", "broken.F90", "-o", "broken.o"];
    let first = cached_output(&fixture, &arguments);
    assert!(!first.status.success(), "invalid source unexpectedly compiled");
    assert!(!fixture.path("broken.o").exists());
    let second = cached_output(&fixture, &arguments);
    assert!(!second.status.success(), "invalid source unexpectedly compiled on retry");
    assert!(!fixture.path("broken.o").exists());
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0, "failed compile must never become a cache hit");
    assert_eq!(result.bypass_reasons.get("dependency-probe"), Some(&2));
}

#[test]
fn lowercase_non_cpp_command_caches_after_identity_qualification() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    let fixture = Fixture::new();
    let source = fixture.path("lowercase.f90");
    fs::write(
        &source,
        "subroutine lowercase(value)\n  implicit none\n  integer, intent(inout) :: value\n  value = value + 1\nend subroutine lowercase\n",
    )
    .expect("write lowercase fixture");
    let arguments = ["-c", "lowercase.f90", "-o", "lowercase.o"];
    differential_action("gfortran", &fixture, &arguments);
}

#[test]
fn lowercase_source_without_final_newline_caches_after_identity_qualification() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("no_final_newline.f90"),
        b"subroutine no_final_newline(value)\n  implicit none\n  integer, intent(inout) :: value\n  value = value + 1\nend subroutine no_final_newline",
    )
    .expect("write lowercase fixture without final newline");
    let arguments = ["-c", "no_final_newline.f90", "-o", "no_final_newline.o"];
    differential_action("gfortran", &fixture, &arguments);
}

#[test]
fn lowercase_nested_include_change_invalidates_cache() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("nested.f90"),
        "subroutine nested(value)\n  implicit none\n  integer, intent(out) :: value\n  include 'outer.inc'\n  value = nested_value\nend subroutine nested\n",
    )
    .expect("write lowercase include source");
    fs::write(fixture.path("outer.inc"), "include 'inner.inc'\n").expect("write outer include");
    fs::write(fixture.path("inner.inc"), "integer, parameter :: nested_value = 1\n")
        .expect("write inner include");
    let arguments = ["-c", "nested.f90", "-o", "nested.o"];

    assert_success(&cached_output(&fixture, &arguments), "cold lowercase include compile");
    fixture.remove_outputs(&["nested.o"]);
    assert_success(&cached_output(&fixture, &arguments), "warm lowercase include compile");
    let warm = fs::read(fixture.path("nested.o")).expect("read warm object");

    fs::write(fixture.path("inner.inc"), "integer, parameter :: nested_value = 2\n")
        .expect("change nested include");
    fixture.remove_outputs(&["nested.o"]);
    assert_success(&cached_output(&fixture, &arguments), "changed lowercase include compile");
    let changed = fs::read(fixture.path("nested.o")).expect("read changed object");
    assert_ne!(warm, changed, "nested include change did not affect the object");
    let result = stats(&fixture);
    assert_eq!(result.requests, 3);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2);
}

#[test]
fn lowercase_module_content_change_invalidates_consumer() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.modules();
    fs::write(
        fixture.path("lower_provider.f90"),
        "module lower_provider\n  implicit none\n  integer, parameter :: value = 1\nend module lower_provider\n",
    )
    .expect("write lowercase provider");
    fs::write(
        fixture.path("lower_consumer.f90"),
        "subroutine lower_consumer(result)\n  use lower_provider\n  integer, intent(out) :: result\n  result = value\nend subroutine lower_consumer\n",
    )
    .expect("write lowercase consumer");
    let provider = ["-J", "modules", "-c", "lower_provider.f90", "-o", "lower_provider.o"];
    let consumer =
        ["-I", "modules", "-J", "modules", "-c", "lower_consumer.f90", "-o", "lower_consumer.o"];

    assert_success(&cached_output(&fixture, &provider), "cold lowercase provider compile");
    assert_success(&cached_output(&fixture, &consumer), "cold lowercase consumer compile");
    fixture.remove_outputs(&["lower_consumer.o"]);
    assert_success(&cached_output(&fixture, &consumer), "warm lowercase consumer compile");

    fs::write(
        fixture.path("lower_provider.f90"),
        "module lower_provider\n  implicit none\n  integer, parameter :: value = 2\nend module lower_provider\n",
    )
    .expect("change lowercase provider interface");
    assert_success(&cached_output(&fixture, &provider), "changed lowercase provider compile");
    fixture.remove_outputs(&["lower_consumer.o"]);
    assert_success(&cached_output(&fixture, &consumer), "invalidated lowercase consumer compile");

    let result = stats(&fixture);
    assert_eq!(result.requests, 5);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 4);
}

#[test]
fn lowercase_preprocessor_directive_fails_identity_qualification() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("directive.f90"),
        "#define FCACHE_DIRECTIVE 1\nsubroutine directive\nend subroutine directive\n",
    )
    .expect("write lowercase directive source");
    let arguments = ["-c", "directive.f90", "-o", "directive.o"];
    for _ in 0..2 {
        assert_success(&cached_output(&fixture, &arguments), "lowercase directive pass-through");
        fixture.remove_outputs(&["directive.o"]);
    }
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.bypass_reasons.get("dependency-probe"), Some(&2));
}

#[test]
fn explicit_f95_language_on_uppercase_source_bypasses_and_regenerates_module() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("language_override.F90"),
        "module language_override\n  implicit none\n  integer, parameter :: value = 1\nend module language_override\n",
    )
    .expect("write language-override source");
    fixture.modules();
    let arguments =
        ["-x", "f95", "-J", "modules", "-c", "language_override.F90", "-o", "language_override.o"];
    assert_success(&cached_output(&fixture, &arguments), "first language-override compile");
    fixture.remove_outputs(&["language_override.o", "modules/language_override.mod"]);
    assert_success(&cached_output(&fixture, &arguments), "second language-override compile");
    assert!(fixture.path("language_override.o").is_file());
    assert!(fixture.path("modules/language_override.mod").is_file());
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.bypass_reasons.get("language-override"), Some(&2));
}

#[test]
fn stack_usage_sidecar_option_bypasses_before_dependency_probe() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("sidecar.F90"),
        "subroutine sidecar(value)\n  integer, intent(inout) :: value\n  value = value + 1\nend subroutine sidecar\n",
    )
    .expect("write sidecar source");
    let arguments = ["-cpp", "-fstack-usage", "-c", "sidecar.F90", "-o", "sidecar.o"];
    assert_success(&cached_output(&fixture, &arguments), "first sidecar compile");
    assert!(fixture.path("sidecar.su").is_file(), "compiler did not create stack-usage sidecar");
    fixture.remove_outputs(&["sidecar.o", "sidecar.su"]);
    assert_success(&cached_output(&fixture, &arguments), "second sidecar compile");
    assert!(fixture.path("sidecar.o").is_file());
    assert!(fixture.path("sidecar.su").is_file());
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.bypass_reasons.get("dump-output"), Some(&2));
    assert_eq!(result.bypass_reasons.get("dependency-probe"), None);
}

#[test]
fn volatile_preprocessor_builtins_bypass_caching() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("volatile.F90"),
        "subroutine volatile_stamp(value)\n  implicit none\n  integer, intent(out) :: value\n  character(len=*), parameter :: stamp = __TIMESTAMP__\n  value = iachar(stamp(1:1))\nend subroutine volatile_stamp\n",
    )
    .expect("write volatile preprocessor fixture");
    let arguments = ["-cpp", "-MD", "-MF", "volatile.d", "-c", "volatile.F90", "-o", "volatile.o"];
    set_file_mtime(fixture.path("volatile.F90"), FileTime::from_unix_time(946_684_800, 0))
        .expect("set first volatile source timestamp");
    let first = cached_output(&fixture, &arguments);
    assert_success(&first, "first volatile preprocessor compile");
    let first_object = fs::read(fixture.path("volatile.o")).expect("read first volatile object");

    fixture.remove_outputs(&["volatile.o", "volatile.d"]);
    set_file_mtime(fixture.path("volatile.F90"), FileTime::from_unix_time(978_307_200, 0))
        .expect("set second volatile source timestamp");
    let second = cached_output(&fixture, &arguments);
    assert_success(&second, "second volatile preprocessor compile");
    let second_object = fs::read(fixture.path("volatile.o")).expect("read second volatile object");
    assert_ne!(first_object, second_object, "volatile expansion restored a stale object");

    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0);
    assert_eq!(result.lookup_results.misses + result.lookup_results.not_attempted, 2);
}

#[test]
fn preprocessor_filesystem_queries_bypass_caching() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    let optional = fixture.path("optional.inc");
    fs::write(&optional, "optional input\n").expect("create optional include");
    fs::write(
        fixture.path("has_include.F90"),
        format!(
            "#if __has_include(\"{}\")\n#endif\nsubroutine optional(value)\n  implicit none\n  integer, intent(out) :: value\n  value = 1\nend subroutine optional\n",
            optional.display()
        ),
    )
    .expect("write filesystem-query source");
    let arguments = ["-cpp", "-c", "has_include.F90", "-o", "has_include.o"];

    assert_success(&cached_output(&fixture, &arguments), "compile filesystem query source");
    fixture.remove_outputs(&["has_include.o"]);
    assert_success(&cached_output(&fixture, &arguments), "repeat filesystem query compile");

    let result = stats(&fixture);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.lookup_results.not_attempted, 2);
    assert_eq!(result.bypass_reasons.get("dependency-probe"), Some(&2));
}

#[test]
fn command_line_preprocessor_filesystem_queries_bypass_caching() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    let optional = fixture.path("optional.inc");
    fs::write(&optional, "optional input\n").expect("create optional include");
    fs::write(
        fixture.path("argument_query.F90"),
        format!(
            "#if QUERY(\"{}\")\n#endif\nsubroutine optional(value)\n  implicit none\n  integer, intent(out) :: value\n  value = 1\nend subroutine optional\n",
            optional.display()
        ),
    )
    .expect("write argument-query source");
    let arguments =
        ["-DQUERY=__has_include", "-cpp", "-c", "argument_query.F90", "-o", "argument_query.o"];

    assert_success(&cached_output(&fixture, &arguments), "compile argument filesystem query");
    fixture.remove_outputs(&["argument_query.o"]);
    assert_success(&cached_output(&fixture, &arguments), "repeat argument filesystem query");

    let result = stats(&fixture);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.lookup_results.not_attempted, 2);
    assert_eq!(result.bypass_reasons.get("dependency-probe"), Some(&2));
}

#[test]
fn make_jobserver_metadata_does_not_change_the_action_key() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let arguments = ["-c", "basic.F90", "-o", "basic.o"];
    let first_environment = [
        ("MAKEFLAGS", "-j12 --jobserver-auth=fifo:/tmp/GMfifo100"),
        ("MFLAGS", "-j12 --jobserver-auth=fifo:/tmp/GMfifo100"),
    ];
    let second_environment = [
        ("MAKEFLAGS", "-j12 --jobserver-auth=fifo:/tmp/GMfifo200"),
        ("MFLAGS", "-j12 --jobserver-auth=fifo:/tmp/GMfifo200"),
    ];

    let first = cached_output_with_env(&fixture, &arguments, &first_environment);
    assert_success(&first, "cold compile with GNU Make jobserver metadata");
    let expected = fs::read(fixture.path("basic.o")).expect("read cold object");
    fixture.remove_outputs(&["basic.o"]);

    let second = cached_output_with_env(&fixture, &arguments, &second_environment);
    assert_success(&second, "warm compile with changed GNU Make jobserver metadata");
    assert_eq!(fs::read(fixture.path("basic.o")).expect("read warm object"), expected);

    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 1);
}

#[test]
fn specs_hidden_input_option_bypasses_before_dependency_probe() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("hidden_input.F90"),
        "subroutine hidden_input\nend subroutine hidden_input\n",
    )
    .expect("write hidden-input source");
    fs::write(fixture.path("compiler.specs"), "").expect("write compiler specs file");
    let arguments =
        ["-cpp", "-specs=compiler.specs", "-c", "hidden_input.F90", "-o", "hidden_input.o"];
    assert_success(&cached_output(&fixture, &arguments), "first hidden-input compile");
    fixture.remove_outputs(&["hidden_input.o"]);
    assert_success(&cached_output(&fixture, &arguments), "second hidden-input compile");
    assert!(fixture.path("hidden_input.o").is_file());
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.bypass_reasons.get("plugin-or-specs"), Some(&2));
    assert_eq!(result.bypass_reasons.get("dependency-probe"), None);
}

#[test]
fn cmake_ninja_launcher_smoke() {
    if !gfortran_available() {
        return;
    }
    if !required_tool_available("cmake") || !required_tool_available("ninja") {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("CMakeLists.txt"),
        "cmake_minimum_required(VERSION 3.18)\nproject(fcache_smoke LANGUAGES Fortran)\nadd_library(smoke OBJECT smoke.F90)\n",
    )
    .expect("write CMake project");
    fs::write(
        fixture.path("smoke.F90"),
        "module smoke_module\n  implicit none\n  integer, parameter :: smoke_value = 1\nend module smoke_module\n",
    )
    .expect("write CMake Fortran source");
    let build = fixture.path("build");
    let configure = Command::new("cmake")
        .args([
            "-S",
            ".",
            "-B",
            "build",
            "-G",
            "Ninja",
            &format!("-DCMAKE_Fortran_COMPILER={}", gfortran_path()),
            &format!("-DCMAKE_Fortran_COMPILER_LAUNCHER={}", fcache_path().display()),
            "-DCMAKE_Fortran_FLAGS=-cpp",
        ])
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("configure CMake project");
    assert_success(&configure, "CMake configure");
    let first = Command::new("cmake")
        .args(["--build", "build"])
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("build CMake project");
    assert_success(&first, "first CMake build");
    let clean = Command::new("ninja")
        .args(["-C", build.to_str().expect("UTF-8 build path"), "clean"])
        .current_dir(fixture.root.path())
        .output()
        .expect("clean Ninja build");
    assert_success(&clean, "Ninja clean");
    let second = Command::new("cmake")
        .args(["--build", "build"])
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("rebuild CMake project");
    assert_success(&second, "second CMake build");
    let result = stats(&fixture);
    assert!(result.requests >= 2, "launcher did not receive Fortran compilations: {result:?}");
    assert_eq!(
        result.hits
            + result.misses
            + result.bypass_reasons.get("dependency-probe-preprocessing").copied().unwrap_or(0),
        result.requests,
        "launcher requests were not fully classified: {result:?}"
    );
    assert!(
        result.hits >= 1 || result.bypass_reasons.contains_key("dependency-probe-preprocessing"),
        "Ninja rebuild was neither cached nor safely bypassed: {result:?}"
    );
}

#[test]
fn parallel_jobs_share_cache_safely() {
    if !gfortran_available() {
        eprintln!("skipping gfortran integration test: gfortran is unavailable");
        return;
    }
    const JOBS: usize = 8;
    let fixture = Fixture::new();
    let source_fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_modules.F90");
    let mut job_directories = Vec::new();
    for index in 0..JOBS {
        let directory = fixture.path(format!("job-{index}"));
        fs::create_dir(&directory).expect("create parallel job directory");
        fs::create_dir(directory.join("modules")).expect("create parallel module directory");
        fs::copy(&source_fixture, directory.join("multi_modules.F90"))
            .expect("copy parallel source fixture");
        job_directories.push(directory);
    }

    run_parallel_jobs(&job_directories, &fixture.cache);
    let cold = stats(&fixture);
    assert_eq!(cold.requests, JOBS as u64);
    assert_eq!(cold.misses, JOBS as u64);
    assert_eq!(cold.hits, 0);

    for directory in &job_directories {
        for relative in
            ["multi_modules.o", "multi.d", "modules/first_module.mod", "modules/second_module.mod"]
        {
            fs::remove_file(directory.join(relative)).expect("remove parallel output");
        }
    }
    run_parallel_jobs(&job_directories, &fixture.cache);
    let warm = stats(&fixture);
    assert_eq!(warm.requests, (JOBS * 2) as u64);
    assert_eq!(warm.misses, JOBS as u64);
    assert_eq!(warm.hits, JOBS as u64);
}

#[test]
fn same_named_modules_follow_gfortran_search_order_for_both_argv_orders() {
    if !gfortran_available() {
        return;
    }
    for arguments in [
        [
            "-cpp", "-MD", "-MF", "user.d", "-J", "jmods", "-I", "explicit", "-c", "user.F90",
            "-o", "user.o",
        ],
        [
            "-cpp", "-MD", "-MF", "user.d", "-I", "explicit", "-J", "jmods", "-c", "user.F90",
            "-o", "user.o",
        ],
    ] {
        let fixture = Fixture::new();
        compile_shadow_provider(&fixture, "jmods", 1);
        compile_shadow_provider(&fixture, "explicit", 2);
        fs::write(
            fixture.path("user.F90"),
            "subroutine user(value)\n  use shadow\n  implicit none\n  integer, intent(out) :: value\n  value = which\nend subroutine user\n",
        )
        .expect("write shadow consumer");

        differential_action("gfortran", &fixture, &arguments);
        assert_eq!(
            read_shadow_result(&fixture, &arguments),
            2,
            "gfortran must prefer the explicit -I module for {arguments:?}"
        );

        compile_shadow_provider(&fixture, "jmods", 9);
        fixture.remove_outputs(&["user.o", "user.d"]);
        assert_success(
            &cached_output(&fixture, &arguments),
            "consumer after shadowed module change",
        );
        assert_eq!(read_shadow_result(&fixture, &arguments), 2);
        let after_shadowed = stats(&fixture);
        assert_eq!(after_shadowed.hits, 2, "shadowed -J module must not be in the key");

        compile_shadow_provider(&fixture, "explicit", 7);
        fixture.remove_outputs(&["user.o", "user.d"]);
        assert_success(
            &cached_output(&fixture, &arguments),
            "consumer after winning module change",
        );
        assert_eq!(read_shadow_result(&fixture, &arguments), 7);
        let after_winning = stats(&fixture);
        assert_eq!(after_winning.hits, 2, "winning -I module change must miss");
        assert_eq!(after_winning.misses, 2);
    }
}

#[test]
fn nested_grandchild_submodule_depends_on_child_smod() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("parent.F90");
    fixture.copy_fixture("child.F90");
    fixture.copy_fixture("grand.F90");
    fixture.modules();
    let parent_arguments =
        ["-cpp", "-MD", "-MF", "parent.d", "-J", "modules", "-c", "parent.F90", "-o", "parent.o"];
    let child_arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "child.d",
        "-J",
        "modules",
        "-I",
        "modules",
        "-c",
        "child.F90",
        "-o",
        "child.o",
    ];
    let grand_arguments = [
        "-cpp",
        "-MD",
        "-MF",
        "grand.d",
        "-J",
        "modules",
        "-I",
        "modules",
        "-c",
        "grand.F90",
        "-o",
        "grand.o",
    ];
    assert_success(&cached_output(&fixture, &parent_arguments), "parent compile");
    assert_success(&cached_output(&fixture, &child_arguments), "child compile");
    assert_success(&cached_output(&fixture, &grand_arguments), "cold grandchild compile");
    fixture.remove_outputs(&["grand.o", "grand.d", "modules/parent_module@grand_module.smod"]);
    assert_success(&cached_output(&fixture, &grand_arguments), "warm grandchild compile");

    fs::write(
        fixture.path("child.F90"),
        "submodule (parent_module) child_module\n  integer, parameter :: marker = 1\ncontains\n  module procedure child_procedure\n    value = 42\n  end procedure child_procedure\nend submodule child_module\n",
    )
    .expect("change child submodule interface");
    assert_success(&cached_output(&fixture, &child_arguments), "changed child compile");
    fixture.remove_outputs(&["grand.o", "grand.d", "modules/parent_module@grand_module.smod"]);
    assert_success(&cached_output(&fixture, &grand_arguments), "grandchild after child change");
    let result = stats(&fixture);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 5, "grandchild must miss after its parent smod changes");
}

#[test]
fn intrinsic_module_use_is_cacheable_and_hashes_file_backed_intrinsics() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.path("intrinsic.F90"),
        "subroutine use_intrinsic(value)\n  use, intrinsic :: iso_c_binding\n  implicit none\n  integer, intent(out) :: value\n  value = c_int\nend subroutine use_intrinsic\n",
    )
    .expect("write intrinsic source");
    let arguments =
        ["-cpp", "-MD", "-MF", "intrinsic.d", "-c", "intrinsic.F90", "-o", "intrinsic.o"];
    differential_action("gfortran", &fixture, &arguments);

    let report = explain_json(&fixture, &arguments);
    assert_eq!(report["decision"], "cacheable");
    let inputs = report["inputs"].as_array().expect("explain inputs");
    assert!(inputs.iter().any(|input| {
        input["path"].as_str().is_some_and(|path| path.ends_with("intrinsic.F90"))
    }));
    for input in inputs {
        let path = input["path"].as_str().expect("input path");
        if path.ends_with(".mod") {
            assert!(
                Path::new(path).is_file(),
                "file-backed intrinsic must exist as a hashed input: {path}"
            );
        }
    }
}

#[test]
fn symlink_module_retarget_invalidates_consumer() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    compile_shadow_provider(&fixture, "real1", 1);
    compile_shadow_provider(&fixture, "real2", 2);
    fs::create_dir_all(fixture.path("mods")).expect("create symlink module directory");
    std::os::unix::fs::symlink(fixture.path("real1/shadow.mod"), fixture.path("mods/shadow.mod"))
        .expect("link first shadow module");
    fs::write(
        fixture.path("user.F90"),
        "subroutine user(value)\n  use shadow\n  implicit none\n  integer, intent(out) :: value\n  value = which\nend subroutine user\n",
    )
    .expect("write symlink consumer");
    let arguments =
        ["-cpp", "-MD", "-MF", "user.d", "-I", "mods", "-c", "user.F90", "-o", "user.o"];
    assert_success(&cached_output(&fixture, &arguments), "cold symlink consumer");
    fixture.remove_outputs(&["user.o", "user.d"]);
    assert_success(&cached_output(&fixture, &arguments), "warm symlink consumer");
    assert_eq!(read_shadow_result(&fixture, &arguments), 1);

    fs::remove_file(fixture.path("mods/shadow.mod")).expect("remove module symlink");
    std::os::unix::fs::symlink(fixture.path("real2/shadow.mod"), fixture.path("mods/shadow.mod"))
        .expect("retarget shadow module");
    fixture.remove_outputs(&["user.o", "user.d"]);
    assert_success(&cached_output(&fixture, &arguments), "consumer after symlink retarget");
    assert_eq!(read_shadow_result(&fixture, &arguments), 2);
    let result = stats(&fixture);
    assert_eq!(result.hits, 1);
    assert_eq!(result.misses, 2, "retargeted module symlink must miss");
}

#[test]
fn duplicate_module_directory_bypasses() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let arguments = ["-cpp", "-J", "one", "-J", "two", "-c", "basic.F90", "-o", "basic.o"];
    let output = cached_output(&fixture, &arguments);
    assert!(!output.status.success(), "duplicate -J should fail in gfortran");
    let result = stats(&fixture);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.bypass_reasons.get("duplicate-module-directory"), Some(&1));
}

#[test]
fn colliding_input_and_object_output_bypasses() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    compile_shadow_provider(&fixture, "mods", 1);
    fs::write(
        fixture.path("user.F90"),
        "subroutine user(value)\n  use shadow\n  implicit none\n  integer, intent(out) :: value\n  value = which\nend subroutine user\n",
    )
    .expect("write colliding consumer");
    let arguments = ["-cpp", "-I", "mods", "-c", "user.F90", "-o", "mods/shadow.mod"];
    let first = cached_output(&fixture, &arguments);
    assert_success(&first, "first colliding compile pass-through");
    fixture.remove_outputs(&["mods/shadow.mod"]);
    compile_shadow_provider(&fixture, "mods", 1);
    let second = cached_output(&fixture, &arguments);
    assert_success(&second, "second colliding compile pass-through");
    let result = stats(&fixture);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.bypass_reasons.get("dependency-probe"), Some(&2));
}

#[cfg(unix)]
#[test]
fn hard_linked_projected_object_alias_passes_through() {
    use std::os::unix::fs::MetadataExt;

    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let arguments = ["-cpp", "-c", "basic.F90", "-o", "basic.o"];

    for invocation in 1..=2 {
        for relative in ["basic.o", "object-alias"] {
            if fixture.path(relative).exists() {
                fs::remove_file(fixture.path(relative)).expect("remove previous output");
            }
        }
        fs::write(fixture.path("basic.o"), b"preexisting object")
            .expect("seed direct projected object output");
        fs::hard_link(fixture.path("basic.o"), fixture.path("object-alias"))
            .expect("create direct hard-link alias");
        let direct = compiler_output("gfortran", &fixture, &arguments);
        assert_success(&direct, &format!("direct hard-linked output invocation {invocation}"));
        let direct_object = fs::read(fixture.path("basic.o")).expect("read direct object");
        let direct_alias = fs::read(fixture.path("object-alias")).expect("read direct alias");
        let direct_links =
            fs::metadata(fixture.path("basic.o")).expect("inspect direct object").nlink();

        fs::remove_file(fixture.path("basic.o")).expect("remove direct object");
        fs::remove_file(fixture.path("object-alias")).expect("remove direct alias");
        fs::write(fixture.path("basic.o"), b"preexisting object")
            .expect("seed cached projected object output");
        fs::hard_link(fixture.path("basic.o"), fixture.path("object-alias"))
            .expect("create cached hard-link alias");
        let output = cached_output(&fixture, &arguments);
        assert_success(&output, &format!("hard-linked output invocation {invocation}"));
        assert_eq!(
            fs::read(fixture.path("basic.o")).expect("read projected object"),
            direct_object,
            "wrapper object differs from the direct compiler",
        );
        assert_eq!(
            fs::read(fixture.path("object-alias")).expect("read hard-link alias"),
            direct_alias,
            "wrapper alias differs from the direct compiler",
        );
        assert_eq!(
            fs::metadata(fixture.path("basic.o")).expect("inspect projected object").nlink(),
            direct_links,
            "wrapper hard-link behavior differs from the direct compiler",
        );
    }

    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.hits, 0);
    assert_eq!(result.misses, 0);
    assert_eq!(result.lookup_results.not_attempted, 2);
}

#[cfg(unix)]
#[test]
fn hard_link_aliases_between_inputs_and_projected_outputs_pass_through() {
    use std::os::unix::fs::MetadataExt;

    fn assert_pass_through(fixture: &Fixture, arguments: &[&str], context: &str) {
        let output = cached_output(fixture, arguments);
        assert_success(&output, context);
        let result = stats(fixture);
        assert_eq!(result.requests, 1, "{context}: request count");
        assert_eq!(result.hits, 0, "{context}: hit count");
        assert_eq!(result.misses, 0, "{context}: miss count");
        assert_eq!(result.lookup_results.not_attempted, 1, "{context}: lookup count");
    }

    if !gfortran_available() {
        return;
    }

    let object_input = Fixture::new();
    compile_shadow_provider(&object_input, "mods", 1);
    fs::write(
        object_input.path("user.F90"),
        "subroutine user(value)\n  use shadow\n  implicit none\n  integer, intent(out) :: value\n  value = which\nend subroutine user\n",
    )
    .expect("write object/input hard-link consumer");
    fs::hard_link(object_input.path("mods/shadow.mod"), object_input.path("user.o"))
        .expect("hard-link object output to module input");
    assert_pass_through(
        &object_input,
        &["-cpp", "-I", "mods", "-c", "user.F90", "-o", "user.o"],
        "object/input hard-link collision",
    );

    let depfile_input = Fixture::new();
    fs::write(depfile_input.path("value.inc"), "integer, parameter :: included_value = 7\n")
        .expect("write depfile/input include");
    fs::write(
        depfile_input.path("user.F90"),
        "subroutine user(value)\n  implicit none\n  integer, intent(out) :: value\n  include 'value.inc'\n  value = included_value\nend subroutine user\n",
    )
    .expect("write depfile/input consumer");
    fs::hard_link(depfile_input.path("value.inc"), depfile_input.path("user.d"))
        .expect("hard-link depfile output to included input");
    assert_pass_through(
        &depfile_input,
        &["-cpp", "-MD", "-MF", "user.d", "-c", "user.F90", "-o", "user.o"],
        "depfile/input hard-link collision",
    );

    let module_input = Fixture::new();
    compile_shadow_provider(&module_input, "mods", 1);
    fs::write(
        module_input.path("generated.F90"),
        "module generated\n  use shadow\n  implicit none\n  integer, parameter :: generated_value = which\nend module generated\n",
    )
    .expect("write module/input collision source");
    fs::hard_link(module_input.path("mods/shadow.mod"), module_input.path("mods/generated.mod"))
        .expect("hard-link module output to module input");
    assert_pass_through(
        &module_input,
        &["-cpp", "-I", "mods", "-J", "mods", "-c", "generated.F90", "-o", "generated.o"],
        "module/input hard-link collision",
    );

    let output_output = Fixture::new();
    output_output.copy_fixture("basic.F90");
    let output_arguments = ["-cpp", "-MD", "-MF", "basic.d", "-c", "basic.F90", "-o", "basic.o"];
    fs::write(output_output.path("basic.o"), b"preexisting output")
        .expect("seed direct output/output collision");
    fs::hard_link(output_output.path("basic.o"), output_output.path("basic.d"))
        .expect("hard-link direct projected outputs");
    let direct = compiler_output("gfortran", &output_output, &output_arguments);
    assert_success(&direct, "direct output/output hard-link collision");
    let direct_object = fs::read(output_output.path("basic.o")).expect("read direct object");
    let direct_depfile = fs::read(output_output.path("basic.d")).expect("read direct depfile");
    let direct_links =
        fs::metadata(output_output.path("basic.o")).expect("inspect direct object").nlink();

    fs::remove_file(output_output.path("basic.o")).expect("remove direct object");
    fs::remove_file(output_output.path("basic.d")).expect("remove direct depfile");
    fs::write(output_output.path("basic.o"), b"preexisting output")
        .expect("seed cached output/output collision");
    fs::hard_link(output_output.path("basic.o"), output_output.path("basic.d"))
        .expect("hard-link cached projected outputs");
    assert_pass_through(&output_output, &output_arguments, "output/output hard-link collision");
    assert_eq!(
        fs::read(output_output.path("basic.o")).expect("read object output"),
        direct_object,
        "wrapper object differs from the direct compiler",
    );
    assert_eq!(
        fs::read(output_output.path("basic.d")).expect("read depfile output"),
        direct_depfile,
        "wrapper depfile differs from the direct compiler",
    );
    assert_eq!(
        fs::metadata(output_output.path("basic.o")).expect("inspect object output").nlink(),
        direct_links,
        "wrapper hard-link behavior differs from the direct compiler",
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_mq_target_is_preserved_byte_for_byte_on_warm_hit() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.copy_fixture("basic.F90");
    let target = OsString::from_vec(b"target-\xff $ with space".to_vec());
    let arguments = vec![
        OsString::from("-cpp"),
        OsString::from("-MD"),
        OsString::from("-MF"),
        OsString::from("basic.d"),
        OsString::from("-MQ"),
        target,
        OsString::from("-c"),
        OsString::from("basic.F90"),
        OsString::from("-o"),
        OsString::from("basic.o"),
    ];
    let baseline = tree_snapshot(&fixture);
    let direct = Command::new("gfortran")
        .args(&arguments)
        .current_dir(fixture.root.path())
        .output()
        .expect("run direct compiler with non-UTF-8 target");
    assert_success(&direct, "direct compiler with non-UTF-8 target");
    let oracle = tree_delta(&baseline, &tree_snapshot(&fixture));
    let direct_depfile = fs::read(fixture.path("basic.d")).expect("read direct non-UTF-8 depfile");
    assert!(direct_depfile.contains(&0xff), "direct depfile lost the non-UTF-8 target byte");

    restore_tree(&fixture, &baseline);
    let cold = Command::new(fcache_path())
        .arg("gfortran")
        .args(&arguments)
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("run cold fcache with non-UTF-8 target");
    assert_success(&cold, "cold fcache with non-UTF-8 target");
    assert_eq!(cold.stdout, direct.stdout);
    assert_eq!(cold.stderr, direct.stderr);
    assert_tree_delta(
        &tree_delta(&baseline, &tree_snapshot(&fixture)),
        &oracle,
        "cold fcache with non-UTF-8 target",
    );
    assert_eq!(
        fs::read(fixture.path("basic.d")).expect("read cold non-UTF-8 depfile"),
        direct_depfile,
    );

    restore_tree(&fixture, &baseline);
    let warm = Command::new(fcache_path())
        .arg("gfortran")
        .args(&arguments)
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("run warm fcache with non-UTF-8 target");
    assert_success(&warm, "warm fcache with non-UTF-8 target");
    assert_eq!(warm.stdout, direct.stdout);
    assert_eq!(warm.stderr, direct.stderr);
    assert_tree_delta(
        &tree_delta(&baseline, &tree_snapshot(&fixture)),
        &oracle,
        "warm fcache with non-UTF-8 target",
    );
    assert_eq!(
        fs::read(fixture.path("basic.d")).expect("read warm non-UTF-8 depfile"),
        direct_depfile,
    );
    let result = stats(&fixture);
    assert_eq!(result.requests, 2);
    assert_eq!(result.misses, 1);
    assert_eq!(result.hits, 1);
}

#[test]
fn requested_depfile_records_includes_and_consumed_modules() {
    if !gfortran_available() {
        return;
    }
    let fixture = Fixture::new();
    compile_shadow_provider(&fixture, "mods", 4);
    fs::write(fixture.path("value.inc"), "integer, parameter :: extra = 3\n")
        .expect("write fortran include");
    fs::write(
        fixture.path("combo.F90"),
        "subroutine combo(value)\n  use shadow\n  implicit none\n  integer, intent(out) :: value\n  include 'value.inc'\n  value = which + extra\nend subroutine combo\n",
    )
    .expect("write combined dependency source");
    let arguments =
        ["-cpp", "-MD", "-MF", "combo.d", "-I", "mods", "-c", "combo.F90", "-o", "combo.o"];
    differential_action("gfortran", &fixture, &arguments);
    let depfile = fs::read_to_string(fixture.path("combo.d")).expect("read combo depfile");
    assert!(depfile.contains("combo.F90"), "depfile missing source: {depfile}");
    assert!(depfile.contains("value.inc"), "depfile missing include: {depfile}");
    assert!(depfile.contains("shadow.mod"), "depfile missing consumed module: {depfile}");
}

fn compile_shadow_provider(fixture: &Fixture, directory: &str, value: i32) {
    fs::create_dir_all(fixture.path(directory)).expect("create shadow provider directory");
    let source = format!("{directory}/shadow.F90");
    let object = format!("{directory}/shadow.o");
    fs::write(
        fixture.path(&source),
        format!(
            "module shadow\n  implicit none\n  integer, parameter :: which = {value}\nend module shadow\n"
        ),
    )
    .expect("write shadow provider");
    assert_success(
        &compiler_output("gfortran", fixture, &["-J", directory, "-c", &source, "-o", &object]),
        "compile shadow provider",
    );
}

fn read_shadow_result(fixture: &Fixture, arguments: &[&str]) -> i32 {
    let program = fixture.path("read_shadow.F90");
    fs::write(
        &program,
        "program read_shadow\n  implicit none\n  integer :: value\n  call user(value)\n  write(*,'(I0)') value\nend program read_shadow\n",
    )
    .expect("write shadow reader");
    let object = fixture.path("user.o");
    let binary = fixture.path("read_shadow");
    let output = Command::new("gfortran")
        .arg(&program)
        .arg(&object)
        .arg("-o")
        .arg(&binary)
        .current_dir(fixture.root.path())
        .output()
        .expect("link shadow reader");
    assert_success(&output, "link shadow reader");
    let output = Command::new(&binary).output().expect("run shadow reader");
    assert_success(&output, "run shadow reader");
    let _ = arguments;
    String::from_utf8_lossy(&output.stdout).trim().parse().expect("parse shadow result")
}

fn explain_json(fixture: &Fixture, arguments: &[&str]) -> serde_json::Value {
    let output = Command::new(fcache_path())
        .args(["--explain", "--json", "--", "gfortran"])
        .args(arguments)
        .current_dir(fixture.root.path())
        .env("FCACHE_DIR", &fixture.cache)
        .output()
        .expect("explain action");
    assert_success(&output, "explain action");
    serde_json::from_slice(&output.stdout).expect("parse explain JSON")
}

fn run_parallel_jobs(job_directories: &[PathBuf], cache: &Path) {
    let handles: Vec<_> = job_directories
        .iter()
        .cloned()
        .map(|directory| {
            let cache = cache.to_path_buf();
            thread::spawn(move || {
                Command::new(fcache_path())
                    .arg("gfortran")
                    .args([
                        "-cpp",
                        "-MD",
                        "-MF",
                        "multi.d",
                        "-J",
                        "modules",
                        "-c",
                        "multi_modules.F90",
                        "-o",
                        "multi_modules.o",
                    ])
                    .current_dir(directory)
                    .env("FCACHE_DIR", cache)
                    .output()
                    .expect("run parallel fcache job")
            })
        })
        .collect();
    for output in handles.into_iter().map(|handle| handle.join().expect("join parallel job")) {
        assert_success(&output, "parallel fcache job");
    }
}

fn gfortran_path() -> String {
    let output =
        Command::new("sh").args(["-c", "command -v gfortran"]).output().expect("locate gfortran");
    assert!(output.status.success(), "gfortran was not found");
    String::from_utf8(output.stdout).expect("gfortran path is UTF-8").trim().to_owned()
}
