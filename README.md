# fcache

`fcache` is a correctness-first local compiler cache for modern Fortran projects that use `gfortran`. It is designed to be a transparent compiler launcher: a cache miss invokes the real compiler, and a cache hit restores the complete compiler result.

The project is alpha software. It supports macOS and Linux, single-source compilation and syntax-only checks, and a local content-addressable store. It has no daemon, remote cache, distributed coordination, or compatibility guarantee for pre-1.0 cache data.

## Installation

fcache requires a working `gfortran` installation. The tested support matrix covers GNU Fortran 11 through 16 on Linux and the current Homebrew GNU Fortran toolchain on macOS. The compiler is not bundled with fcache and must be available to the build system that invokes it.

The first GitHub release is planned to provide these prebuilt archives:

| Host | Release target |
| --- | --- |
| macOS on Apple silicon | `aarch64-apple-darwin` |
| macOS on Intel | `x86_64-apple-darwin` |
| Linux on x86-64 | `x86_64-unknown-linux-musl` |

When a release is available, download the archive for the host and its matching `.sha256` file from the release page. Verify it before extracting:

```sh
archive="fcache-VERSION-TARGET.tar.gz"

# Linux
sha256sum --check "$archive.sha256"

# macOS
shasum -a 256 --check "$archive.sha256"
```

Extract the archive and place `fcache` in a directory on `PATH`. Planned release archives will not initially be code-signed or notarized. They will not include Windows or Linux ARM binaries, and Windows is not a supported platform.

To build from source instead, install Rust 1.85 or newer and run:

```sh
cargo build --locked --release
install -m 755 target/release/fcache /usr/local/bin/fcache
```

Choose a different destination if `/usr/local/bin` is not writable. The Cargo package is named `fortran-fcache` while its executable and library remain `fcache`. It is not currently published to crates.io, so `cargo install fortran-fcache` is not yet an installation path.

## Quick start

Point a CMake build at the launcher by setting the compiler before configuring:

```sh
cmake -S . -B build \
  -DCMAKE_Fortran_COMPILER=gfortran \
  -DCMAKE_Fortran_COMPILER_LAUNCHER=/absolute/path/to/fcache
cmake --build build
```

The launcher receives the real compiler as its first argument. For direct use, run commands such as `fcache gfortran -cpp -c source.F90 -o source.o`. fcache forwards unsupported or uncertain invocations to that compiler; it never claims a cache hit unless every input needed for correctness is known and unchanged. The CMake example is the supported launcher shape, not a claim that every CMake generator or project layout has dedicated integration coverage.

The cache directory follows the platform's user cache directory convention. `FCACHE_DIR` can override it for tests and isolated builds. The local administrative and analysis interface includes:

```text
fcache --show-stats [--json]
fcache --zero-stats
fcache --show-config
fcache --explain [--json] -- gfortran <arguments...>
fcache --trim
fcache --clear
fcache --version
```

Run `fcache --help` for the installed command syntax. `--clear` is destructive to cached artifacts but does not touch source or build files.

`--explain` performs the same fail-closed eligibility analysis used by the launcher. It may run private compiler fingerprint and dependency probes, but it never runs the requested compilation, writes user outputs, updates statistics, or publishes a cache entry. Its exit status is 0 for cacheable, 1 for a safe bypass, and 2 for invalid input or a tool failure.

Direct lookup is enabled by default. Set `FCACHE_DIRECT=0` (or `direct = false` in `fcache/config.toml`) to retain compiler-assisted cache lookup while disabling compiler-free hits. Compiler identity defaults to `FCACHE_COMPILER_IDENTITY=auto` (or `compiler_identity = "auto"`), which reuses a persisted identity only when complete metadata and path-resolution witnesses validate on a trusted local filesystem. Set it to `strict` to recompute the complete compiler identity for every request; unsupported or insufficiently trustworthy filesystems automatically use the strict behavior.

## MVP behavior

- Supported platforms: macOS and Linux.
- Supported compiler: GNU Fortran (`gfortran`) major versions 11 through 16 on Linux and the current Homebrew toolchain on macOS, supplied as the launcher compiler command.
- Supported actions: one source file per invocation for compilation or syntax-only checking. Syntax-only actions that generate module interfaces pass through. Uppercase preprocessing suffixes and explicit `-cpp` may be eligible. Lowercase sources without an explicit preprocessing mode are eligible only when a private `-cpp -E -P` qualification reproduces the source apart from gfortran's leading newline prefix and an optional final newline for a final record ending at EOF; `-nocpp` and `-fpreprocessed` actions pass through.
- Eligible invocations use a compiler-generated `-MD` depfile as the conservative transitive input set, including consumed modules and file-backed intrinsic modules. Requested `-MMD` output may omit system inputs, but the cache key does not.
- A cache bundle contains the object file, generated module files (`.mod`/`.smod`), and depfile when requested.
- Storage is local and content-addressable; blobs are installed before an atomically published, versioned manifest makes a complete bundle visible.
- Compiler failures are not cached. Any ambiguity, unsupported flag, missing dependency observation, or unsafe output situation passes through to the real compiler.

Interactive terminal invocations pass through so native compiler diagnostics and signals are preserved; build-system launcher invocations are the primary cached path. The MVP does not provide a daemon, remote storage, cache sharing, multi-source linking, compiler wrappers for non-gfortran compilers, or a promise of stable cache format compatibility before a 1.0 release.

Modern CMake/Ninja Fortran rules commonly preprocess sources outside the compiler launcher and then invoke the launcher with `-fpreprocessed`. Those actions currently use the correct pass-through path. CMake's Makefile generators present original source invocations and can cache eligible actions.

## Design and correctness

After computing or safely reusing the compiler identity, the launcher attempts a versioned direct observation for the exact request. With `compiler_identity = "auto"`, a reusable identity on a trusted local filesystem makes this path compiler-process-free for supported actions; strict mode and untrusted filesystems intentionally recompute it. Explicitly preprocessed GCC 11/12 actions retain compiler-assisted observation because those versions cannot reliably reject volatile preprocessor built-ins. A direct hit requires unchanged compiler identity witnesses, dependency contents, path and symlink identities, ordered search roots, and every negative lookup witness that proves an earlier include or module candidate has not appeared. It then reconstructs the full action key and revalidates the observation while output locks are held.

Missing, stale, corrupt, incomplete, or unsupported evidence falls back to the compiler-authoritative path. A genuinely unseen request is observed before compilation with an isolated compiler probe; generated interfaces are identified by matching its dependency targets to files that actually exist in the private module directory, never by filename suffixes or source parsing. If a complete validated direct observation survives after its result manifest is evicted or unreadable, fcache can instead compile immediately from that pre-compile witness. After a successful real compilation, a requested full `-MD` depfile is the authoritative dependency-name and rule channel, while every pre-observed input is rehashed and the module output set and bytes are checked exactly. Actions without a complete real `-MD` channel retain the post-compile probe. Any mismatch returns the real compiler's successful result without publishing it. On an ordinary compiler-assisted hit, fcache backfills the direct observation so the following request can be compiler-free.

Processes using the same cache root coordinate declared outputs and module directories with advisory locks. Object-only misses take shared module-directory access; module producers and restores take exclusive access. This prevents one invocation from attributing another invocation's `.mod` or `.smod` changes to itself without serializing unrelated object-only compilations. Processes using different cache roots are not coordinated and remain subject to the build system's output ownership rules.

Atomic publication applies to the cache entry, not to restoring several output paths as one filesystem transaction. A hit prepares each output privately and installs depfiles and module interfaces before the object file. If an install fails, fcache reports failure and attempts to roll back earlier replacements; placing the object last prevents it from advertising a completed compilation before its interfaces are available.

The key invariants are:

1. A hit is valid only when the compiler identity, relevant arguments, source identity, observed preprocessing, and all dependency contents match.
2. A hit restores the same observable output set as the corresponding successful compiler invocation.
3. Failed, partial, ambiguous, or unsupported operations are never turned into cache entries.
4. Cache publication is atomic; readers see either a complete valid bundle or no entry. Restoring that bundle is ordered and fail-fast rather than globally atomic.
5. Cache data is an optimization. Deleting it cannot alter source, build, or compiler behavior.

The next miss-path performance milestone is a version-qualified compiler adapter that can obtain a complete private dependency sidecar from the real invocation without changing user-visible artifacts or diagnostics. Until that equivalence is proven across the supported gfortran matrix, true cold requests without an earlier observation remain probe-first. A post-compilation depfile alone is insufficient because it names files but cannot prove which bytes the compiler consumed before a concurrent change.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Install a real `gfortran` when running launcher integration tests. CI requires `gfortran`, CMake, and Ninja to be present, exercises Rust stable and MSRV 1.85 on Ubuntu and macOS, runs the differential suite with GNU Fortran 11 through 16 on Linux, and includes an Arch Linux container smoke job. The current suite includes one CMake/Ninja launcher smoke project plus differential fixtures for selected object, depfile, module, submodule, diagnostics, invalidation, and pass-through cases; it is not an exhaustive compatibility suite for every compiler version or build-system layout.

### Performance acceptance benchmark

`scripts/benchmark_acceptance.py` runs at least five direct, cold-cache, and warm-cache builds at one stable build path. It saves every `--show-stats --json` snapshot, reports validated pre-compile observations, real `-MD` validations, and post-compile probes, independently traces compiler-driver launches, and compares the complete discovered `.o`, `.mod`, `.smod`, and `.d` tree byte for byte against the direct-build baseline.

```sh
cargo build --locked --release
python3 scripts/benchmark_acceptance.py \
  --source-dir /path/to/project \
  --work-dir /path/to/empty/fcache-benchmark \
  --fcache target/release/fcache \
  --compiler /path/to/gfortran \
  --generator "Unix Makefiles" \
  --fortran-target fortran-target \
  --mixed-target all \
  --samples 5
```

The workspace must initially be empty or contain the marker created by an earlier run. Build, cache, and results paths must be strict, non-overlapping descendants of that workspace; only the validated build directory is cleared. Repeat `--configure-arg=-DNAME=VALUE` or `--build-arg=VALUE` for project-specific options. `--report-only` records a measurement without enforcing thresholds.

For a faster correctness gate without performance thresholds, add `--correctness-only`. This mode performs exactly four builds at the same stable path: direct A establishes the oracle, direct B checks that the compiler and project are reproducible, a cold cached build populates one fresh cache, and a warm build reuses that cache. It requires a cold miss, a warm hit, compiler-trace agreement with fcache statistics, and byte-identical artifacts in every comparison. `--samples` is ignored in this mode, and correctness failures always return a nonzero status.

Every completed phase records `artifacts.json`, `artifact-comparison.json`, compiler output, statistics, and the independent compiler-process trace beneath the results directory. A failed phase retains its logs, `error.json`, compiler trace, and best-effort statistics. When artifacts differ, the results also retain baseline and actual copies under `artifact-differences/` so a CI artifact upload contains the bytes needed to diagnose the failure.

```sh
python3 scripts/benchmark_acceptance.py \
  --source-dir /path/to/project \
  --work-dir /path/to/empty/fcache-correctness \
  --fcache target/release/fcache \
  --compiler /path/to/gfortran \
  --generator "Unix Makefiles" \
  --fortran-target fortran-target \
  --compiler-identity strict \
  --correctness-only
```

The Fortran acceptance denominator must show more than 50% lower warm median wall time than direct compilation, at least a 95% eligible hit rate, at least 95% validated-direct coverage among hits, no compiler processes unaccounted for by measured fallback work, no more than 10% cold median overhead, and byte-identical artifacts. A validated direct hit returns before any preprocessing, dependency, or real-compilation process is launched; a conservative direct-ineligible hit may still use the compiler-assisted lookup. Median and nearest-rank p95 are reported separately for the Fortran target and the optional complete mixed-language target; mixed-language timing must not be used as the Fortran denominator. Performance thresholds belong in this repeatable workload rather than ordinary CI. Ninja's common `-fpreprocessed` Fortran actions remain intentional pass-throughs and are outside this benchmark, so the harness rejects Ninja generators.

This project is dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Notable user-facing changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Releases

The release workflow uses `vX.Y.Z` tags whose version exactly matches `Cargo.toml`. A tag push will build the three archives listed above, publish an individual SHA-256 file for each archive plus a combined `SHA256SUMS`, and create the GitHub release. A build or version mismatch prevents publication. Release binaries will use the Rust version pinned in `rust-toolchain.toml`.

Because fcache is pre-1.0, command behavior, configuration, and cache formats may still change between minor versions. Upgrade notes belong in the changelog. Existing cache entries may be discarded after an incompatible change; source and build outputs must remain unaffected.

## Roadmap

Near-term work includes reducing cold-miss dependency-observation cost, expanding gfortran flag coverage, and adding richer public differential workloads. Private output staging, relocation-friendly key trimming, and independently keyed interface/object results remain deferred because each can change compiler-observable behavior or weaken the current correctness argument. Later work may add multi-source/build-system scenarios, a daemon, and authenticated remote caches. Each feature must preserve the pass-through and complete-bundle invariants before it is enabled by default.
