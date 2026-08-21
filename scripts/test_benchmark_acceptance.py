import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).with_name("benchmark_acceptance.py")
SPEC = importlib.util.spec_from_file_location("benchmark_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class WorkspaceSafetyTests(unittest.TestCase):
    def test_correctness_mode_accepts_single_sample_and_excludes_report_only(self) -> None:
        required = [
            "benchmark_acceptance.py",
            "--source-dir",
            ".",
            "--work-dir",
            "workspace",
            "--fcache",
            "fcache",
            "--fortran-target",
            "fortran",
        ]
        with mock.patch.object(
            sys, "argv", [*required, "--correctness-only", "--samples", "1"]
        ):
            self.assertTrue(benchmark.parse_args().correctness_only)
        with mock.patch.object(sys, "argv", [*required, "--samples", "1"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    benchmark.parse_args()
        with mock.patch.object(
            sys, "argv", [*required, "--correctness-only", "--report-only"]
        ):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    benchmark.parse_args()

    def test_workspace_requires_an_empty_or_marked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            workspace = parent / "workspace"
            workspace.mkdir()
            (workspace / "unrelated").write_text("keep", encoding="utf-8")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.prepare_workspace(workspace)

            workspace = parent / "empty"
            root = benchmark.prepare_workspace(workspace)
            self.assertEqual(root, workspace.resolve())
            self.assertEqual(
                (root / benchmark.MARKER_NAME).read_text(encoding="utf-8"),
                benchmark.MARKER_CONTENT,
            )
            self.assertEqual(benchmark.prepare_workspace(workspace), root)

    def test_managed_paths_must_be_strict_nonoverlapping_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = benchmark.prepare_workspace(Path(temporary) / "workspace")
            build = benchmark.inside_workspace(root, None, "build", "build")
            cache = benchmark.inside_workspace(root, Path("cache"), "cache", "cache")
            benchmark.reject_overlaps({"build": build, "cache": cache})
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.inside_workspace(root, root, "build", "build")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.reject_overlaps({"build": build, "nested": build / "nested"})


class ArtifactComparisonTests(unittest.TestCase):
    def test_comparison_rejects_byte_or_tree_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            build.mkdir()
            (build / "unit.o").write_bytes(b"object")
            (build / "module.mod").write_bytes(b"module")
            artifacts = benchmark.discover_artifacts(build)
            baseline = root / "baseline"
            benchmark.copy_baseline(build, artifacts, baseline)
            benchmark.compare_baseline(build, artifacts, baseline)

            (build / "unit.o").write_bytes(b"changed")
            comparison = benchmark.artifact_comparison(
                build, benchmark.discover_artifacts(build), baseline
            )
            self.assertEqual(comparison["changed"], ["unit.o"])
            evidence = root / "evidence"
            benchmark.copy_artifact_differences(build, baseline, comparison, evidence)
            self.assertEqual((evidence / "baseline/unit.o").read_bytes(), b"object")
            self.assertEqual((evidence / "actual/unit.o").read_bytes(), b"changed")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.compare_baseline(build, benchmark.discover_artifacts(build), baseline)

            (build / "unit.o").write_bytes(b"object")
            (build / "extra.d").write_bytes(b"dependency")
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.compare_baseline(build, benchmark.discover_artifacts(build), baseline)

    def test_phase_summary_does_not_treat_baseline_as_a_comparison(self) -> None:
        run = {
            "wall_seconds": 1.0,
            "artifact_bytes_identical": None,
            "stats": {},
            "trace_counts": {},
        }
        self.assertIsNone(benchmark.phase_summary([run])["all_artifacts_byte_identical"])


class AcceptanceTests(unittest.TestCase):
    def test_observation_telemetry_requires_schema_three_and_integer_fields(self) -> None:
        valid = {
            "schema_version": 3,
            "miss_observation": {
                "validated_precompile_selections": 0,
                "real_md_validation_successes": 0,
                "post_compile_probe_attempts": 0,
            },
        }
        benchmark.validate_stats_telemetry(valid)
        for invalid in [
            {},
            {"schema_version": 2, "miss_observation": valid["miss_observation"]},
            {"schema_version": 3, "miss_observation": {}},
        ]:
            with self.assertRaises(benchmark.BenchmarkError):
                benchmark.validate_stats_telemetry(invalid)

    def test_aggregation_reports_miss_observation_strategies(self) -> None:
        run = {
            "stats": {
                "lookup_results": {"hits": 0, "misses": 1},
                "direct_path": {"validated_hits": 0},
                "process_counts": {"real_compilations": 1},
                "miss_observation": {
                    "validated_precompile_selections": 1,
                    "real_md_validation_successes": 1,
                    "post_compile_probe_attempts": 0,
                },
            },
            "trace_counts": {"compiler": 1},
        }
        result = benchmark.aggregate_run_stats([run])
        self.assertEqual(
            result["miss_observation"],
            {
                "validated_precompile_selections": 1,
                "real_md_validation_successes": 1,
                "post_compile_probe_attempts": 0,
            },
        )

    def test_acceptance_distinguishes_direct_hits_from_fallback_work(self) -> None:
        process_counts = {
            "fingerprint_queries": 0,
            "preprocessing_probes": 1,
            "dependency_probes": 1,
            "real_compilations": 0,
            "pass_through_executions": 2,
        }
        summaries = {
            "direct": {
                "median_wall_seconds": 20.0,
                "all_artifacts_byte_identical": True,
            },
            "cold": {
                "median_wall_seconds": 21.0,
                "all_artifacts_byte_identical": True,
            },
            "warm": {
                "median_wall_seconds": 4.0,
                "all_artifacts_byte_identical": True,
                "eligible_hit_rate": 1.0,
                "validated_direct_hit_rate": 0.99,
                "validated_direct_hits": 99,
                "process_counts": process_counts,
                "trace_counts": {
                    "compiler": 2,
                    "dependency-probe": 1,
                    "preprocessing-probe": 1,
                },
            },
        }
        result = benchmark.acceptance_results(summaries)
        self.assertTrue(all(result.values()))

        summaries["warm"]["trace_counts"]["compiler"] = 3
        result = benchmark.acceptance_results(summaries)
        self.assertFalse(result["compiler_trace_matches_reported_processes"])
        self.assertFalse(result["validated_direct_hits_launch_no_unaccounted_processes"])

    def test_correctness_requires_cold_population_warm_hits_and_matching_traces(self) -> None:
        empty_processes = {field: 0 for field in benchmark.PROCESS_FIELDS}
        cold_processes = dict(empty_processes)
        cold_processes["real_compilations"] = 1
        summaries = {
            "direct-a": {"all_artifacts_byte_identical": True},
            "direct-b": {"all_artifacts_byte_identical": True},
            "cold": {
                "all_artifacts_byte_identical": True,
                "eligible_misses": 1,
                "process_counts": cold_processes,
                "trace_counts": {"compiler": 1},
            },
            "warm": {
                "all_artifacts_byte_identical": True,
                "eligible_hits": 1,
                "process_counts": empty_processes,
                "trace_counts": {},
            },
        }
        self.assertTrue(all(benchmark.correctness_results(summaries).values()))

        summaries["warm"]["eligible_hits"] = 0
        result = benchmark.correctness_results(summaries)
        self.assertFalse(result["warm_cache_hit_observed"])

        summaries["warm"]["eligible_hits"] = 1
        summaries["warm"]["trace_counts"] = {"compiler": 1}
        result = benchmark.correctness_results(summaries)
        self.assertFalse(result["warm_compiler_trace_matches_reported_processes"])

    def test_correctness_checks_include_every_requested_workload(self) -> None:
        workloads = {
            "fortran": {"acceptance": {"matches": True}},
            "mixed": {"acceptance": {"matches": False}},
        }
        self.assertEqual(
            benchmark.failed_report_checks(workloads, correctness_only=True),
            ["mixed.matches"],
        )
        self.assertEqual(
            benchmark.failed_report_checks(workloads, correctness_only=False), []
        )

    def test_failed_sample_preserves_trace_stats_and_error(self) -> None:
        args = SimpleNamespace(
            compiler_identity="auto", max_cache_size="1 GiB", jobs=1, build_arg=[]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            result_dir = root / "results"
            (result_dir / "toolchain").mkdir(parents=True)

            def fail_build(
                command: list[str],
                env: dict[str, str],
                stdout_path: Path,
                stderr_path: Path,
            ) -> None:
                del command, stdout_path, stderr_path
                Path(env["FORTRAN_BENCH_TRACE"]).write_text(
                    "compiler\n", encoding="utf-8"
                )
                raise benchmark.BenchmarkError("build failed")

            with (
                mock.patch.object(benchmark, "clear_managed_directory"),
                mock.patch.object(benchmark, "configure_build"),
                mock.patch.object(benchmark, "reset_stats"),
                mock.patch.object(benchmark, "run_command", side_effect=fail_build),
                mock.patch.object(benchmark, "load_stats", return_value={}),
            ):
                with self.assertRaises(benchmark.BenchmarkError):
                    benchmark.run_sample(
                        args,
                        root,
                        Path("cmake"),
                        Path("fcache"),
                        Path("gfortran"),
                        Path("source"),
                        build,
                        root / "cache",
                        result_dir,
                        "fortran",
                        "wsjt_fort",
                        "cold",
                        1,
                        None,
                        True,
                    )

            log_dir = result_dir / "fortran/cold/01"
            self.assertEqual(
                (log_dir / "compiler-processes.log").read_text(encoding="utf-8"),
                "compiler\n",
            )
            self.assertTrue((log_dir / "stats.json").is_file())
            self.assertEqual(
                json.loads((log_dir / "error.json").read_text(encoding="utf-8"))[
                    "phase"
                ],
                "cold",
            )

    def test_correctness_preserves_mismatch_and_finishes_all_phases(self) -> None:
        args = SimpleNamespace(
            compiler_identity="auto", max_cache_size="1 GiB", jobs=1, build_arg=[]
        )
        outputs = iter(
            [
                ("direct-a", b"baseline"),
                ("direct-b", b"different"),
                ("cold", b"baseline"),
                ("warm", b"baseline"),
            ]
        )
        current_phase = ""

        def fake_build(
            command: list[str],
            env: dict[str, str],
            stdout_path: Path,
            stderr_path: Path,
        ) -> None:
            nonlocal current_phase
            del command, stdout_path, stderr_path
            current_phase, contents = next(outputs)
            build.mkdir(parents=True, exist_ok=True)
            (build / "unit.o").write_bytes(contents)
            trace = "compiler\n" if current_phase == "cold" else ""
            Path(env["FORTRAN_BENCH_TRACE"]).write_text(trace, encoding="utf-8")

        def fake_stats(
            fcache: Path, env: dict[str, str], destination: Path
        ) -> dict[str, object]:
            del fcache, env
            process_counts = {field: 0 for field in benchmark.PROCESS_FIELDS}
            if current_phase == "cold":
                process_counts["real_compilations"] = 1
                stats = {
                    "lookup_results": {"hits": 0, "misses": 1},
                    "process_counts": process_counts,
                }
            else:
                stats = {
                    "lookup_results": {"hits": 1, "misses": 0},
                    "process_counts": process_counts,
                }
            destination.write_text("{}\n", encoding="utf-8")
            return stats

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            result_dir = root / "results"
            (result_dir / "toolchain").mkdir(parents=True)
            with (
                mock.patch.object(benchmark, "clear_managed_directory"),
                mock.patch.object(benchmark, "configure_build"),
                mock.patch.object(benchmark, "reset_stats"),
                mock.patch.object(benchmark, "run_command", side_effect=fake_build),
                mock.patch.object(benchmark, "load_stats", side_effect=fake_stats),
            ):
                result = benchmark.correctness_workload(
                    args,
                    root,
                    Path("cmake"),
                    Path("fcache"),
                    Path("gfortran"),
                    Path("source"),
                    build,
                    root / "cache",
                    result_dir,
                    "fortran",
                    "wsjt_fort",
                )

            comparison = result["phases"]["direct-a"][0]["artifact_comparison"]
            self.assertEqual(comparison["status"], "baseline")
            self.assertIsNone(comparison["identical"])
            self.assertFalse(result["acceptance"]["direct_builds_byte_identical"])
            evidence = result_dir / "fortran/direct-b/01/artifact-differences"
            self.assertEqual(
                (evidence / "baseline/unit.o").read_bytes(), b"baseline"
            )
            self.assertEqual(
                (evidence / "actual/unit.o").read_bytes(), b"different"
            )

    def test_correctness_workload_runs_four_phases_with_one_shared_cache(self) -> None:
        calls: list[tuple[str, Path, bool, bool]] = []

        def fake_run_sample(*args: object, **kwargs: object):
            cache_dir = args[7]
            phase = args[11]
            baseline = args[13]
            use_fcache = args[14]
            self.assertIsInstance(cache_dir, Path)
            self.assertIsInstance(phase, str)
            self.assertIsInstance(use_fcache, bool)
            calls.append(
                (
                    phase,
                    cache_dir,
                    use_fcache,
                    bool(kwargs.get("preserve_differences")),
                )
            )
            if baseline is None:
                baseline = Path("baseline")
            process_counts = {field: 0 for field in benchmark.PROCESS_FIELDS}
            stats: dict[str, object] = {}
            trace: dict[str, int] = {}
            if phase == "cold":
                process_counts["real_compilations"] = 1
                stats = {
                    "lookup_results": {"hits": 0, "misses": 1},
                    "process_counts": process_counts,
                }
                trace = {"compiler": 1}
            elif phase == "warm":
                stats = {
                    "lookup_results": {"hits": 1, "misses": 0},
                    "direct_path": {"validated_hits": 1},
                    "process_counts": process_counts,
                }
            return (
                {
                    "wall_seconds": 1.0,
                    "artifact_bytes_identical": True,
                    "stats": stats,
                    "trace_counts": trace,
                },
                baseline,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(benchmark, "run_sample", side_effect=fake_run_sample):
                result = benchmark.correctness_workload(
                    SimpleNamespace(),
                    root,
                    Path("cmake"),
                    Path("fcache"),
                    Path("gfortran"),
                    Path("source"),
                    root / "build",
                    root / "cache",
                    root / "results",
                    "fortran",
                    "wsjt_fort",
                )

        self.assertEqual(
            [call[0] for call in calls], ["direct-a", "direct-b", "cold", "warm"]
        )
        self.assertFalse(calls[0][2])
        self.assertFalse(calls[1][2])
        self.assertTrue(calls[2][2])
        self.assertTrue(calls[3][2])
        self.assertEqual(calls[2][1], calls[3][1])
        self.assertTrue(all(call[3] for call in calls))
        self.assertEqual(result["status"], "completed")
        self.assertTrue(all(result["acceptance"].values()))

    def test_correctness_workload_reports_failed_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                benchmark,
                "run_sample",
                side_effect=benchmark.BenchmarkError("build failed"),
            ):
                result = benchmark.correctness_workload(
                    SimpleNamespace(),
                    root,
                    Path("cmake"),
                    Path("fcache"),
                    Path("gfortran"),
                    Path("source"),
                    root / "build",
                    root / "cache",
                    root / "results",
                    "fortran",
                    "wsjt_fort",
                )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["phase"], "direct-a")
        self.assertFalse(result["acceptance"]["workload_completed"])


if __name__ == "__main__":
    unittest.main()
