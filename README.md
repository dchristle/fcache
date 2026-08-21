# fcache

`fcache` is a local compiler cache for modern Fortran projects that use
`gfortran`. It runs as a compiler launcher: misses invoke the real compiler,
and hits restore the complete compiler result.

fcache is alpha software. It supports macOS and Linux, single-source
compilation and syntax-only checks, and a local content-addressable store.
There is no daemon, remote cache, or pre-1.0 cache-format compatibility
guarantee.

## Installation

fcache requires a working `gfortran` installation. The tested compiler matrix
covers GNU Fortran 11 through 16 on Linux and the current Homebrew GNU Fortran
toolchain on macOS.

Tagged releases provide these archives:

| Host | Release target |
| --- | --- |
| macOS 11 or newer on Apple silicon | `aarch64-apple-darwin` |
| macOS 11 or newer on Intel | `x86_64-apple-darwin` |
| Linux x86-64 with glibc 2.28 or newer | `x86_64-unknown-linux-gnu` |
| Linux x86-64, statically linked with musl | `x86_64-unknown-linux-musl` |

Download the archive and matching `.sha256` file from the
[release page](https://github.com/dchristle/fcache/releases), then verify it:

```sh
# Linux
sha256sum --check fcache-VERSION-TARGET.tar.gz.sha256

# macOS
shasum -a 256 --check fcache-VERSION-TARGET.tar.gz.sha256
```

Extract the archive and place `fcache` on `PATH`. The compiler is not included.
Release archives are not currently code-signed or notarized. Windows and Linux
ARM are not supported.

To build from source, install Rust 1.85 or newer and run:

```sh
cargo build --locked --release
install -m 755 target/release/fcache /usr/local/bin/fcache
```

The Cargo package is named `fortran-fcache`; the executable and library are
named `fcache`. The package is not currently published to crates.io.

## Usage

Configure fcache as the CMake Fortran compiler launcher:

```sh
cmake -S . -B build \
  -DCMAKE_Fortran_COMPILER=gfortran \
  -DCMAKE_Fortran_COMPILER_LAUNCHER=/absolute/path/to/fcache
cmake --build build
```

For direct use, pass the real compiler as the first argument:

```sh
fcache gfortran -cpp -c source.F90 -o source.o
```

Unsupported or uncertain invocations run through the real compiler without
being cached.

Common administrative commands are:

```text
fcache --show-stats [--json]
fcache --zero-stats
fcache --show-config
fcache --explain [--json] -- gfortran <arguments...>
fcache --trim
fcache --clear
```

`--explain` reports whether an invocation is cacheable without running the
requested compilation or writing its outputs. `--clear` removes only fcache
data. See [configuration and administration](docs/configuration.md) for the
configuration file, environment variables, and command semantics.

## Supported scope

- macOS and Linux.
- GNU Fortran 11 through 16 on Linux and the current Homebrew toolchain on
  macOS.
- One source file per compilation or syntax-only invocation.
- Objects, generated `.mod` and `.smod` files, depfiles, and compiler
  diagnostics.
- Local storage only.

Explicit preprocessing with `-cpp` and uppercase preprocessing suffixes may be
cached. `-nocpp`, `-fpreprocessed`, linking, multi-source actions, unknown
side-effecting options, and non-gfortran compilers pass through. CMake's common
Ninja Fortran rules use `-fpreprocessed`; Unix Makefiles present the original
source invocation and are the supported cacheable CMake path.

See [limitations](docs/limitations.md) for the complete boundary. Near-term
work is focused on broader compiler-option coverage and additional real-world
validation. Daemon and remote-cache operation are outside the initial scope.

## Correctness model

fcache fails closed. It accepts a hit only when it can validate the compiler,
arguments, source, dependencies, and complete output set. Compiler-generated
depfiles are authoritative for transitive inputs, and generated modules are
identified from compiler output rather than source parsing.

The core rules are:

1. Uncertain or unsupported actions pass through.
2. Compiler failures and partial results are not cached.
3. A cache entry contains every output required by the successful action.
4. Cache publication is atomic.
5. Deleting the cache cannot affect source or build semantics.

The detailed policy is documented in [correctness](docs/correctness.md) and
[architecture](docs/architecture.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Install `gfortran`, CMake, and Ninja to run the compiler-backed integration
tests. CI covers Rust stable and MSRV 1.85 on Ubuntu and macOS, GNU Fortran 11
through 16 on Linux, and Arch Linux. See [testing](docs/testing.md) for test
scope and differential-validation requirements.

## Releases

Tags use `vX.Y.Z` and must match the version in `Cargo.toml`. The release
workflow builds the four archives listed above, verifies their platform floors
and packaged compiler-cache behavior, publishes SHA-256 checksums and build
provenance attestations, and creates the GitHub release. Manual workflow runs
perform the same build and validation without publishing.

## License

fcache is available under either the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE). User-facing changes are recorded in the
[changelog](CHANGELOG.md).
