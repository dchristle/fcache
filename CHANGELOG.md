# Changelog

Notable user-facing changes to fcache are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) while retaining normal pre-1.0 compatibility latitude.

## [Unreleased]

The first public release is planned as `0.1.0-alpha.1`.

### Added

- A correctness-first local cache for eligible single-source `gfortran` compilations and syntax-only checks on macOS and Linux.
- Complete cache bundles for objects, module and submodule interfaces, depfiles, and compiler diagnostics.
- Administrative commands for configuration, eligibility explanations, statistics, trimming, and clearing the cache.
- Validated direct lookup capable of compiler-process-free warm hits, with `auto` and fully recomputed `strict` compiler-identity modes.
- Tested support for GNU Fortran 11 through 16 on Linux, the current Homebrew GNU Fortran toolchain on macOS, and the flags exercised by real WSJT-X builds.
- A portable CMake acceptance harness for direct, cold, and warm builds, plus four-build correctness validation with byte-identical artifact comparison.
- A tag-driven release workflow for macOS and Linux archives, SHA-256 checksums, and build provenance attestations.
- The Cargo package name `fortran-fcache`, with the executable and Rust library named `fcache`.

### Correctness and safety

- Unsupported, partial, or ambiguous actions pass through to the real compiler instead of being cached.
- Cache hits require validated compiler identity, relevant arguments, source and preprocessing identity, dependency contents, and output observations.
- Compiler-produced dependency rules remain authoritative while preserving `-MT`, `-MQ`, `-MP`, and `-MMD` behavior.
- Generated modules are discovered from compiler output and dependency targets rather than inferred from source text or filename suffixes.
- Existing projected modules are treated as inputs unless their bytes match the private probe output; path and filesystem aliases with projected outputs are rejected.
- Direct observations are invalidated when compiler tools, external specifications, search resolution, missing candidates, process umask, or output identities change.
- Volatile preprocessing is hashed or kept on the compiler-assisted path when the compiler cannot prove deterministic expansion.
- Cache publication is atomic, and manifests, blobs, paths, and dependencies are validated before restoration.
