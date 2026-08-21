#!/usr/bin/env python3
"""Run the repeatable fcache performance and artifact-identity acceptance workload."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import shlex
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


MARKER_NAME = ".fcache-benchmark-root"
MARKER_CONTENT = "fcache benchmark workspace v1\n"
ARTIFACT_SUFFIXES = {".d", ".mod", ".o", ".smod"}
PROCESS_FIELDS = (
    "fingerprint_queries",
    "preprocessing_probes",
    "dependency_probes",
    "real_compilations",
    "pass_through_executions",
)
MISS_OBSERVATION_FIELDS = (
    "validated_precompile_selections",
    "real_md_validation_successes",
    "post_compile_probe_attempts",
)


class BenchmarkError(RuntimeError):
    """A benchmark setup, build, or acceptance failure."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare repeated direct, cold-cache, and warm-cache CMake builds while "
            "checking all discovered Fortran-related build artifacts byte for byte."
        )
    )
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument(
        "--work-dir",
        required=True,
        type=Path,
        help="isolated benchmark workspace; a nonempty unmarked directory is refused",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        help="stable build path inside --work-dir (default: build)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="cache root inside --work-dir (default: cache)",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        help="result root inside --work-dir (default: results)",
    )
    parser.add_argument("--fcache", required=True, type=Path)
    parser.add_argument("--compiler", default="gfortran")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--generator", default="Unix Makefiles")
    parser.add_argument("--fortran-target", required=True)
    parser.add_argument(
        "--mixed-target",
        help="optional full mixed-language target, reported with a separate denominator",
    )
    parser.add_argument("--build-type", default="Release")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    parser.add_argument(
        "--configure-arg",
        action="append",
        default=[],
        help="extra CMake configure argument; repeat and use --configure-arg=-DNAME=VALUE",
    )
    parser.add_argument(
        "--build-arg", action="append", default=[], help="extra CMake build argument; repeat"
    )
    parser.add_argument(
        "--compiler-identity", choices=("auto", "strict"), default="auto"
    )
    parser.add_argument("--max-cache-size", default="100 GiB")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--correctness-only",
        action="store_true",
        help=(
            "run direct A, direct B, cold-cache, and warm-cache builds without "
            "performance thresholds"
        ),
    )
    mode.add_argument(
        "--report-only",
        action="store_true",
        help="write results without returning failure when an acceptance threshold is missed",
    )
    args = parser.parse_args()
    if not args.correctness_only and args.samples < 5:
        parser.error("--samples must be at least 5")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if "ninja" in args.generator.casefold():
        parser.error(
            "Ninja Fortran rules commonly use -fpreprocessed and are pass-through; "
            "use a generator that presents original Fortran source invocations"
        )
    return args


def executable(value: str | Path, label: str) -> Path:
    text = os.fspath(value)
    candidate = shutil.which(text) if len(Path(text).parts) == 1 else text
    if candidate is None:
        raise BenchmarkError(f"{label} was not found: {text}")
    path = Path(candidate).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise BenchmarkError(f"{label} is not an executable file: {path}")
    return path


def prepare_workspace(path: Path) -> Path:
    root = path.expanduser().resolve()
    home = Path.home().resolve()
    if root == Path(root.anchor) or root == home:
        raise BenchmarkError(f"refusing unsafe benchmark workspace: {root}")
    root.mkdir(parents=True, exist_ok=True)
    marker = root / MARKER_NAME
    if marker.exists():
        if not marker.is_file() or marker.read_text(encoding="utf-8") != MARKER_CONTENT:
            raise BenchmarkError(f"invalid benchmark workspace marker: {marker}")
    else:
        entries = list(root.iterdir())
        if entries:
            raise BenchmarkError(
                f"refusing nonempty unmarked benchmark workspace: {root}; "
                "choose an empty directory"
            )
        marker.write_text(MARKER_CONTENT, encoding="utf-8")
    return root


def inside_workspace(root: Path, value: Path | None, default: str, label: str) -> Path:
    candidate = Path(default) if value is None else value.expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        common = Path(os.path.commonpath((os.fspath(root), os.fspath(resolved))))
    except ValueError as error:
        raise BenchmarkError(f"{label} must be inside {root}") from error
    if common != root or resolved == root:
        raise BenchmarkError(f"{label} must be a strict descendant of {root}: {resolved}")
    return resolved


def reject_overlaps(named_paths: dict[str, Path]) -> None:
    items = list(named_paths.items())
    for index, (left_name, left) in enumerate(items):
        for right_name, right in items[index + 1 :]:
            common = Path(os.path.commonpath((os.fspath(left), os.fspath(right))))
            if common == left or common == right:
                raise BenchmarkError(
                    f"{left_name} and {right_name} must not overlap: {left}, {right}"
                )


def clear_managed_directory(root: Path, path: Path) -> None:
    marker = root / MARKER_NAME
    if marker.read_text(encoding="utf-8") != MARKER_CONTENT:
        raise BenchmarkError(f"benchmark workspace is no longer validated: {root}")
    common = Path(os.path.commonpath((os.fspath(root), os.fspath(path))))
    if common != root or path == root:
        raise BenchmarkError(f"refusing to clear path outside benchmark workspace: {path}")
    if path.is_symlink():
        raise BenchmarkError(f"refusing to clear a symlinked benchmark directory: {path}")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def write_compiler_wrapper(directory: Path, compiler: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=False)
    wrapper_name = compiler.name if compiler.name.startswith("gfortran") else "gfortran"
    wrapper = directory / wrapper_name
    quoted_compiler = shlex.quote(os.fspath(compiler))
    wrapper.write_text(
        "#!/bin/sh\n"
        "kind=compiler\n"
        "has_syntax_only=0\n"
        "has_md=0\n"
        "for argument do\n"
        "  case \"$argument\" in\n"
        "    -print-prog-name=*|-print-search-dirs|-print-file-name=specs|--version|"
        "-dumpfullversion|-dumpversion|-dumpmachine|-dumpspecs) kind=fingerprint-query ;;\n"
        "    -E) kind=preprocessing-probe ;;\n"
        "    -fsyntax-only) has_syntax_only=1 ;;\n"
        "    -MD) has_md=1 ;;\n"
        "  esac\n"
        "done\n"
        "if [ \"$has_syntax_only\" -eq 1 ] && [ \"$has_md\" -eq 1 ]; then\n"
        "  kind=dependency-probe\n"
        "fi\n"
        "if [ -n \"${FORTRAN_BENCH_TRACE:-}\" ]; then\n"
        "  printf '%s\\n' \"$kind\" >> \"$FORTRAN_BENCH_TRACE\"\n"
        "fi\n"
        f"exec {quoted_compiler} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper


def run_command(
    command: list[str], env: dict[str, str], stdout_path: Path, stderr_path: Path
) -> None:
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(command, env=env, stdout=stdout, stderr=stderr, check=False)
    if result.returncode != 0:
        raise BenchmarkError(
            f"command failed with exit status {result.returncode}: {shlex.join(command)}; "
            f"see {stdout_path} and {stderr_path}"
        )


def load_stats(fcache: Path, env: dict[str, str], destination: Path) -> dict[str, Any]:
    result = subprocess.run(
        [os.fspath(fcache), "--show-stats", "--json"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise BenchmarkError(
            f"fcache --show-stats failed: {result.stderr.decode('utf-8', 'replace')}"
        )
    destination.write_bytes(result.stdout)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BenchmarkError("fcache --show-stats did not produce valid JSON") from error
    if not isinstance(value, dict):
        raise BenchmarkError("fcache --show-stats JSON must be an object")
    validate_stats_telemetry(value)
    return value


def reset_stats(fcache: Path, env: dict[str, str]) -> None:
    result = subprocess.run(
        [os.fspath(fcache), "--zero-stats"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise BenchmarkError(
            f"fcache --zero-stats failed: {result.stderr.decode('utf-8', 'replace')}"
        )


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def discover_artifacts(build_dir: Path) -> list[Path]:
    artifacts = []
    for path in build_dir.rglob("*"):
        if path.suffix.casefold() not in ARTIFACT_SUFFIXES:
            continue
        if path.is_symlink():
            raise BenchmarkError(f"artifact comparison does not accept symlinks: {path}")
        if path.is_file():
            artifacts.append(path)
    artifacts.sort(key=lambda path: path.relative_to(build_dir).as_posix())
    if not artifacts:
        raise BenchmarkError(f"no .o, .mod, .smod, or .d artifacts found under {build_dir}")
    return artifacts


def artifact_manifest(build_dir: Path, artifacts: Iterable[Path]) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(build_dir).as_posix(),
            "size": path.stat().st_size,
            "sha256": hash_file(path),
        }
        for path in artifacts
    ]


def copy_baseline(build_dir: Path, artifacts: list[Path], baseline: Path) -> None:
    baseline.mkdir(parents=True, exist_ok=False)
    for source in artifacts:
        destination = baseline / source.relative_to(build_dir)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def files_equal(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as left_file, right.open("rb") as right_file:
        while True:
            left_chunk = left_file.read(1024 * 1024)
            right_chunk = right_file.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def artifact_comparison(
    build_dir: Path, artifacts: list[Path], baseline: Path
) -> dict[str, Any]:
    actual = {path.relative_to(build_dir).as_posix(): path for path in artifacts}
    expected = {
        path.relative_to(baseline).as_posix(): path
        for path in baseline.rglob("*")
        if path.is_file()
    }
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = [
        relative
        for relative in sorted(actual.keys() & expected.keys())
        if not files_equal(actual[relative], expected[relative])
    ]
    return {
        "identical": not missing and not extra and not changed,
        "missing": missing,
        "extra": extra,
        "changed": changed,
    }


def comparison_error(comparison: dict[str, Any]) -> BenchmarkError:
    if comparison["missing"] or comparison["extra"]:
        return BenchmarkError(
            "artifact tree differs; "
            f"missing={comparison['missing']}, extra={comparison['extra']}"
        )
    return BenchmarkError(f"artifact bytes differ: {comparison['changed']}")


def compare_baseline(build_dir: Path, artifacts: list[Path], baseline: Path) -> None:
    comparison = artifact_comparison(build_dir, artifacts, baseline)
    if not comparison["identical"]:
        raise comparison_error(comparison)


def copy_artifact_differences(
    build_dir: Path, baseline: Path, comparison: dict[str, Any], destination: Path
) -> None:
    expected_paths = sorted(set(comparison["missing"]) | set(comparison["changed"]))
    actual_paths = sorted(set(comparison["extra"]) | set(comparison["changed"]))
    for label, root, relative_paths in (
        ("baseline", baseline, expected_paths),
        ("actual", build_dir, actual_paths),
    ):
        for relative in relative_paths:
            target = destination / label / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target)


def trace_counts(trace: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not trace.exists():
        return counts
    for line in trace.read_text(encoding="utf-8").splitlines():
        counts[line] = counts.get(line, 0) + 1
    return counts


def numeric(stats: dict[str, Any], *path: str) -> int:
    value: Any = stats
    for component in path:
        if not isinstance(value, dict):
            return 0
        value = value.get(component, 0)
    return int(value) if isinstance(value, (int, float)) else 0


def validate_stats_telemetry(stats: dict[str, Any]) -> None:
    schema = stats.get("schema_version")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema < 3:
        raise BenchmarkError("fcache statistics schema 3 or newer is required")
    observation = stats.get("miss_observation")
    if not isinstance(observation, dict):
        raise BenchmarkError("fcache statistics omit miss_observation telemetry")
    for field in MISS_OBSERVATION_FIELDS:
        value = observation.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BenchmarkError(f"fcache statistics omit integer miss_observation.{field}")


def nearest_rank_p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def aggregate_run_stats(runs: list[dict[str, Any]]) -> dict[str, Any]:
    hits = sum(numeric(run["stats"], "lookup_results", "hits") for run in runs)
    misses = sum(numeric(run["stats"], "lookup_results", "misses") for run in runs)
    direct_hits = sum(
        numeric(run["stats"], "direct_path", "validated_hits") for run in runs
    )
    process_counts = {
        field: sum(numeric(run["stats"], "process_counts", field) for run in runs)
        for field in PROCESS_FIELDS
    }
    miss_observation = {
        field: sum(numeric(run["stats"], "miss_observation", field) for run in runs)
        for field in MISS_OBSERVATION_FIELDS
    }
    trace: dict[str, int] = {}
    for run in runs:
        for name, count in run["trace_counts"].items():
            trace[name] = trace.get(name, 0) + count
    eligible = hits + misses
    return {
        "eligible_hits": hits,
        "eligible_misses": misses,
        "eligible_hit_rate": hits / eligible if eligible else None,
        "validated_direct_hits": direct_hits,
        "validated_direct_hit_rate": direct_hits / hits if hits else None,
        "process_counts": process_counts,
        "miss_observation": miss_observation,
        "trace_counts": trace,
    }


def phase_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    durations = [float(run["wall_seconds"]) for run in runs]
    comparisons = [
        bool(run["artifact_bytes_identical"])
        for run in runs
        if run["artifact_bytes_identical"] is not None
    ]
    return {
        "samples": len(runs),
        "wall_seconds": durations,
        "median_wall_seconds": statistics.median(durations),
        "p95_wall_seconds": nearest_rank_p95(durations),
        "all_artifacts_byte_identical": all(comparisons) if comparisons else None,
        **aggregate_run_stats(runs),
    }


def trace_matches_reported_processes(summary: dict[str, Any]) -> bool:
    processes = summary["process_counts"]
    trace = summary["trace_counts"]
    expected_trace = {
        "compiler": processes["real_compilations"]
        + processes["pass_through_executions"],
        "dependency-probe": processes["dependency_probes"],
        "fingerprint-query": processes["fingerprint_queries"],
        "preprocessing-probe": processes["preprocessing_probes"],
    }
    return set(trace).issubset(expected_trace) and all(
        trace.get(kind, 0) == count for kind, count in expected_trace.items()
    )


def acceptance_results(summaries: dict[str, dict[str, Any]]) -> dict[str, bool]:
    direct_median = summaries["direct"]["median_wall_seconds"]
    cold_median = summaries["cold"]["median_wall_seconds"]
    warm_median = summaries["warm"]["median_wall_seconds"]
    trace_matches = trace_matches_reported_processes(summaries["warm"])
    direct_hit_rate = summaries["warm"]["validated_direct_hit_rate"]
    return {
        "warm_wall_more_than_50_percent_lower": warm_median < direct_median * 0.5,
        "eligible_warm_hit_rate_at_least_95_percent": (
            summaries["warm"]["eligible_hit_rate"] is not None
            and summaries["warm"]["eligible_hit_rate"] >= 0.95
        ),
        "validated_direct_hit_rate_at_least_95_percent": (
            direct_hit_rate is not None and direct_hit_rate >= 0.95
        ),
        "validated_direct_hits_launch_no_unaccounted_processes": (
            summaries["warm"]["validated_direct_hits"] > 0
            and trace_matches
        ),
        "compiler_trace_matches_reported_processes": trace_matches,
        "cold_median_overhead_at_most_10_percent": cold_median <= direct_median * 1.10,
        "all_artifacts_byte_identical": all(
            summary["all_artifacts_byte_identical"] for summary in summaries.values()
        ),
    }


def correctness_results(summaries: dict[str, dict[str, Any]]) -> dict[str, bool]:
    return {
        "direct_builds_byte_identical": summaries["direct-b"][
            "all_artifacts_byte_identical"
        ],
        "cold_build_byte_identical": summaries["cold"]["all_artifacts_byte_identical"],
        "warm_build_byte_identical": summaries["warm"]["all_artifacts_byte_identical"],
        "cold_cache_population_observed": summaries["cold"]["eligible_misses"] > 0,
        "warm_cache_hit_observed": summaries["warm"]["eligible_hits"] > 0,
        "cold_compiler_trace_matches_reported_processes": trace_matches_reported_processes(
            summaries["cold"]
        ),
        "warm_compiler_trace_matches_reported_processes": trace_matches_reported_processes(
            summaries["warm"]
        ),
    }


def base_environment(args: argparse.Namespace, cache_dir: Path, trace: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "FCACHE_DIR": os.fspath(cache_dir),
            "FCACHE_DIRECT": "1",
            "FCACHE_COMPILER_IDENTITY": args.compiler_identity,
            "FCACHE_DISABLE": "0",
            "FCACHE_READ_ONLY": "0",
            "FCACHE_MAX_SIZE": args.max_cache_size,
            "FORTRAN_BENCH_TRACE": os.fspath(trace),
        }
    )
    return env


def configure_build(
    args: argparse.Namespace,
    cmake: Path,
    fcache: Path,
    wrapper: Path,
    source: Path,
    build_dir: Path,
    env: dict[str, str],
    log_dir: Path,
    use_fcache: bool,
) -> None:
    command = [
        os.fspath(cmake),
        "-S",
        os.fspath(source),
        "-B",
        os.fspath(build_dir),
        "-G",
        args.generator,
        f"-DCMAKE_BUILD_TYPE={args.build_type}",
        f"-DCMAKE_Fortran_COMPILER={wrapper}",
    ]
    if use_fcache:
        command.append(f"-DCMAKE_Fortran_COMPILER_LAUNCHER={fcache}")
    command.extend(args.configure_arg)
    configure_env = dict(env)
    configure_env["FCACHE_DISABLE"] = "1"
    run_command(
        command,
        configure_env,
        log_dir / "configure.stdout.log",
        log_dir / "configure.stderr.log",
    )


def write_phase_error(
    log_dir: Path, phase: str, sample: int, error: BenchmarkError
) -> None:
    (log_dir / "error.json").write_text(
        json.dumps(
            {"phase": phase, "sample": sample, "error": str(error)},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def run_sample(
    args: argparse.Namespace,
    root: Path,
    cmake: Path,
    fcache: Path,
    wrapper: Path,
    source: Path,
    build_dir: Path,
    cache_dir: Path,
    result_dir: Path,
    workload: str,
    target: str,
    phase: str,
    sample: int,
    baseline: Path | None,
    use_fcache: bool,
    preserve_differences: bool = False,
) -> tuple[dict[str, Any], Path]:
    label = "warmup" if sample == 0 else f"{sample:02d}"
    log_dir = result_dir / workload / phase / label
    log_dir.mkdir(parents=True, exist_ok=False)
    trace = result_dir / "toolchain" / "compiler-processes.log"
    trace.write_text("", encoding="utf-8")
    env = base_environment(args, cache_dir, trace)
    recorded_trace = log_dir / "compiler-processes.log"
    stats_path = log_dir / "stats.json"
    try:
        clear_managed_directory(root, build_dir)
        configure_build(
            args, cmake, fcache, wrapper, source, build_dir, env, log_dir, use_fcache
        )
        trace.write_text("", encoding="utf-8")
        if use_fcache:
            reset_stats(fcache, env)

        command = [
            os.fspath(cmake),
            "--build",
            os.fspath(build_dir),
            "--target",
            target,
            "--parallel",
            str(args.jobs),
        ]
        command.extend(args.build_arg)
        start = time.perf_counter()
        run_command(
            command, env, log_dir / "build.stdout.log", log_dir / "build.stderr.log"
        )
        elapsed = time.perf_counter() - start

        if use_fcache:
            stats = load_stats(fcache, env, stats_path)
        else:
            stats = {}
            stats_path.write_text("{}\n", encoding="utf-8")
    except BenchmarkError as error:
        write_phase_error(log_dir, phase, sample, error)
        if use_fcache and not stats_path.exists():
            try:
                load_stats(fcache, env, stats_path)
            except BenchmarkError as stats_error:
                (log_dir / "stats-capture-error.txt").write_text(
                    f"{stats_error}\n", encoding="utf-8"
                )
        if not stats_path.exists():
            stats_path.write_text("{}\n", encoding="utf-8")
        raise
    finally:
        if trace.exists():
            shutil.copyfile(trace, recorded_trace)

    try:
        artifacts = discover_artifacts(build_dir)
        manifest = artifact_manifest(build_dir, artifacts)
    except BenchmarkError as error:
        write_phase_error(log_dir, phase, sample, error)
        raise
    (log_dir / "artifacts.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    comparison: dict[str, Any]
    if baseline is None:
        baseline = result_dir / workload / "artifact-baseline"
        copy_baseline(build_dir, artifacts, baseline)
        comparison = {
            "status": "baseline",
            "compared_to": None,
            "identical": None,
            "missing": [],
            "extra": [],
            "changed": [],
        }
    else:
        comparison = artifact_comparison(build_dir, artifacts, baseline)
        comparison["status"] = "compared"
        comparison["compared_to"] = os.fspath(baseline.relative_to(result_dir))
        if not comparison["identical"]:
            copy_artifact_differences(
                build_dir, baseline, comparison, log_dir / "artifact-differences"
            )
    (log_dir / "artifact-comparison.json").write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    result = {
        "phase": phase,
        "sample": sample,
        "wall_seconds": elapsed,
        "artifact_count": len(artifacts),
        "artifact_bytes_identical": comparison["identical"],
        "artifact_comparison": comparison,
        "trace_counts": trace_counts(recorded_trace),
        "stats": stats,
        "logs": os.fspath(log_dir.relative_to(result_dir)),
    }
    if comparison["identical"] is False and not preserve_differences:
        raise comparison_error(comparison)
    return result, baseline


def benchmark_workload(
    args: argparse.Namespace,
    root: Path,
    cmake: Path,
    fcache: Path,
    wrapper: Path,
    source: Path,
    build_dir: Path,
    cache_run_root: Path,
    result_dir: Path,
    workload: str,
    target: str,
) -> dict[str, Any]:
    print(f"benchmarking {workload} target {target!r}", flush=True)
    phases: dict[str, list[dict[str, Any]]] = {"direct": [], "cold": [], "warm": []}
    baseline: Path | None = None

    direct_cache = cache_run_root / workload / "direct"
    direct_cache.mkdir(parents=True)
    for sample in range(1, args.samples + 1):
        print(f"  direct {sample}/{args.samples}", flush=True)
        run, baseline = run_sample(
            args,
            root,
            cmake,
            fcache,
            wrapper,
            source,
            build_dir,
            direct_cache,
            result_dir,
            workload,
            target,
            "direct",
            sample,
            baseline,
            False,
        )
        phases["direct"].append(run)

    for sample in range(1, args.samples + 1):
        print(f"  cold {sample}/{args.samples}", flush=True)
        cold_cache = cache_run_root / workload / "cold" / f"{sample:02d}"
        cold_cache.mkdir(parents=True)
        run, baseline = run_sample(
            args,
            root,
            cmake,
            fcache,
            wrapper,
            source,
            build_dir,
            cold_cache,
            result_dir,
            workload,
            target,
            "cold",
            sample,
            baseline,
            True,
        )
        phases["cold"].append(run)

    warm_cache = cache_run_root / workload / "warm"
    warm_cache.mkdir(parents=True)
    print("  populating warm cache", flush=True)
    warmup, baseline = run_sample(
        args,
        root,
        cmake,
        fcache,
        wrapper,
        source,
        build_dir,
        warm_cache,
        result_dir,
        workload,
        target,
        "warmup",
        0,
        baseline,
        True,
    )
    for sample in range(1, args.samples + 1):
        print(f"  warm {sample}/{args.samples}", flush=True)
        run, baseline = run_sample(
            args,
            root,
            cmake,
            fcache,
            wrapper,
            source,
            build_dir,
            warm_cache,
            result_dir,
            workload,
            target,
            "warm",
            sample,
            baseline,
            True,
        )
        phases["warm"].append(run)

    summaries = {name: phase_summary(runs) for name, runs in phases.items()}
    direct_median = summaries["direct"]["median_wall_seconds"]
    cold_median = summaries["cold"]["median_wall_seconds"]
    warm_median = summaries["warm"]["median_wall_seconds"]
    acceptance = acceptance_results(summaries)
    return {
        "mode": "performance",
        "status": "completed",
        "target": target,
        "warmup": warmup,
        "phases": phases,
        "summary": summaries,
        "metrics": {
            "warm_wall_savings_fraction": (direct_median - warm_median) / direct_median,
            "cold_overhead_fraction": (cold_median - direct_median) / direct_median,
        },
        "acceptance": acceptance,
    }


def correctness_workload(
    args: argparse.Namespace,
    root: Path,
    cmake: Path,
    fcache: Path,
    wrapper: Path,
    source: Path,
    build_dir: Path,
    cache_run_root: Path,
    result_dir: Path,
    workload: str,
    target: str,
) -> dict[str, Any]:
    print(f"validating {workload} target {target!r}", flush=True)
    phases: dict[str, list[dict[str, Any]]] = {
        "direct-a": [],
        "direct-b": [],
        "cold": [],
        "warm": [],
    }
    direct_cache = cache_run_root / workload / "direct"
    shared_cache = cache_run_root / workload / "cached"
    direct_cache.mkdir(parents=True)
    shared_cache.mkdir(parents=True)
    baseline: Path | None = None

    phase_specs = (
        ("direct-a", direct_cache, False),
        ("direct-b", direct_cache, False),
        ("cold", shared_cache, True),
        ("warm", shared_cache, True),
    )
    failure: dict[str, Any] | None = None
    for phase, cache_dir, use_fcache in phase_specs:
        print(f"  {phase}", flush=True)
        try:
            run, baseline = run_sample(
                args,
                root,
                cmake,
                fcache,
                wrapper,
                source,
                build_dir,
                cache_dir,
                result_dir,
                workload,
                target,
                phase,
                1,
                baseline,
                use_fcache,
                preserve_differences=True,
            )
        except BenchmarkError as error:
            failure = {
                "phase": phase,
                "sample": 1,
                "error": str(error),
                "logs": f"{workload}/{phase}/01",
            }
            phases[phase].append({"status": "failed", **failure})
            break
        phases[phase].append(run)

    summaries = {
        name: phase_summary(runs)
        for name, runs in phases.items()
        if runs and runs[0].get("status") != "failed"
    }
    acceptance = (
        correctness_results(summaries)
        if failure is None
        else {"workload_completed": False}
    )
    return {
        "mode": "correctness",
        "status": "completed" if failure is None else "failed",
        "target": target,
        "phases": phases,
        "summary": summaries,
        "acceptance": acceptance,
        "error": failure,
    }


def failed_report_checks(
    workloads: dict[str, dict[str, Any]], correctness_only: bool
) -> list[str]:
    selected = (
        workloads.items()
        if correctness_only
        else [("fortran", workloads["fortran"])]
    )
    return [
        f"{workload_name}.{criterion}"
        for workload_name, workload in selected
        for criterion, accepted in workload["acceptance"].items()
        if not accepted
    ]


def main() -> int:
    args = parse_args()
    source = args.source_dir.expanduser().resolve()
    if not source.is_dir() or not (source / "CMakeLists.txt").is_file():
        raise BenchmarkError(f"source directory does not contain CMakeLists.txt: {source}")
    root = prepare_workspace(args.work_dir)
    build_dir = inside_workspace(root, args.build_dir, "build", "build directory")
    cache_root = inside_workspace(root, args.cache_dir, "cache", "cache directory")
    results_root = inside_workspace(root, args.results_dir, "results", "results directory")
    reject_overlaps(
        {"build directory": build_dir, "cache directory": cache_root, "results directory": results_root}
    )
    cache_root.mkdir(parents=True, exist_ok=True)
    results_root.mkdir(parents=True, exist_ok=True)

    fcache = executable(args.fcache, "fcache")
    compiler = executable(args.compiler, "Fortran compiler")
    cmake = executable(args.cmake, "CMake")
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    result_dir = results_root / run_id
    cache_run_root = cache_root / run_id
    result_dir.mkdir()
    cache_run_root.mkdir()
    wrapper = write_compiler_wrapper(result_dir / "toolchain", compiler)

    workloads = [("fortran", args.fortran_target)]
    if args.mixed_target:
        workloads.append(("mixed", args.mixed_target))
    report: dict[str, Any] = {
        "schema_version": 3,
        "run_id": run_id,
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "configuration": {
            "mode": "correctness" if args.correctness_only else "performance",
            "source_dir": os.fspath(source),
            "stable_build_dir": os.fspath(build_dir),
            "fcache": os.fspath(fcache),
            "compiler": os.fspath(compiler),
            "cmake": os.fspath(cmake),
            "generator": args.generator,
            "build_type": args.build_type,
            "samples": None if args.correctness_only else args.samples,
            "jobs": args.jobs,
            "compiler_identity": args.compiler_identity,
            "configure_args": args.configure_arg,
            "build_args": args.build_arg,
        },
        "workloads": {},
    }
    report_path = result_dir / "report.json"
    try:
        for name, target in workloads:
            workload_runner = (
                correctness_workload if args.correctness_only else benchmark_workload
            )
            report["workloads"][name] = workload_runner(
                args,
                root,
                cmake,
                fcache,
                wrapper,
                source,
                build_dir,
                cache_run_root,
                result_dir,
                name,
                target,
            )
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
    finally:
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    for name, workload in report["workloads"].items():
        summary = workload["summary"]
        if workload["status"] == "failed":
            print(
                f"{name}: failed during {workload['error']['phase']}; "
                f"logs={workload['error']['logs']}",
                flush=True,
            )
        elif args.correctness_only:
            print(
                f"{name}: direct-a={summary['direct-a']['median_wall_seconds']:.3f}s, "
                f"direct-b={summary['direct-b']['median_wall_seconds']:.3f}s, "
                f"cold={summary['cold']['median_wall_seconds']:.3f}s, "
                f"warm={summary['warm']['median_wall_seconds']:.3f}s, "
                f"warm_hits={summary['warm']['eligible_hits']}",
                flush=True,
            )
        else:
            print(
                f"{name}: direct={summary['direct']['median_wall_seconds']:.3f}s, "
                f"cold={summary['cold']['median_wall_seconds']:.3f}s, "
                f"warm={summary['warm']['median_wall_seconds']:.3f}s, "
                f"warm_hit_rate={summary['warm']['eligible_hit_rate']!r}",
                flush=True,
            )
    print(f"report: {report_path}", flush=True)

    failed = failed_report_checks(report["workloads"], args.correctness_only)
    if failed and (args.correctness_only or not args.report_only):
        mode = "correctness" if args.correctness_only else "acceptance"
        print(f"failed Fortran {mode} criteria: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BenchmarkError, OSError) as error:
        print(f"benchmark error: {error}", file=sys.stderr)
        sys.exit(2)
