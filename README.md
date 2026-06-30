# rars

A Rust implementation of RAR.

* [🏠 home](https://bitplane.net/dev/rust/rars)
  * [🪵 blog](https://bitplane.net/log/2026/05/rars/)
* [🦀 crate](https://crates.io/crates/rars)
* [🐱 source](https://github.com/bitplane/rars)
* [📃 spec](https://github.com/bitplane/rar-research)

## Current Status

`rars` covers the RAR lineage from early `RE~^` archives through RAR 7,
compression and decompression. It's not fast, but it works. ish.

## Rust API

Use the `rars` crate for Rust applications and libraries. Since 0.4, the
lower-level `rars-format`, `rars-codec`, `rars-crypto`, `rars-crc32`, and
`rars-recovery` crates are folded into `rars`; those standalone crates ended at
0.3.x. Applications should depend on `rars`, and command-line installs should
use `rars-cli`.

## CLI

Inspect, test, and extract archives:

```sh
rars info archive.rar
rars test archive.rar
rars x archive.rar out/
```

Create archives with specific RAR generation:

```sh
rars a --format rar29 archive.rar files...
rars a --format rar50 --solid --auto-filter archive.rar files...
rars a --format rar70 --store --volume-size 10m archive.part1.rar files...
```

The writer supports stored and compressed members, split volumes, passwords,
header encryption where implemented, comments, RARVM filters, RAR5 quick-open
records, and supported recovery records. Run `rars --help` for the exact option
set.

## Fast Builds

The optional `fast` feature enables safe portable SIMD paths for selected hot
compression and decompression helpers, including LZ match scanning, x86 filter
scanning, and CRC-32 updates. It uses Rust's experimental `std::simd` API, so it
requires a nightly toolchain. Default builds do not enable this feature and
remain stable-compatible.

Build or run the CLI with the fast path:

```sh
cargo +nightly run -p rars-cli --features fast -- info archive.rar
cargo +nightly build --workspace --features fast
```

Run the fast test and benchmark paths:

```sh
cargo +nightly test --workspace --features fast
cargo +nightly bench -p rars --bench chunk_sizes --features fast
```

## Parallel Builds

The optional `parallel` feature enables Rayon worker threads for independent
archive members. It parallelizes non-solid compression planning for supported
writers and buffered extraction of non-solid, non-split single archives while
preserving archive order for output. Solid archives and multivolume extraction
fall back to the existing sequential stream because their codec state depends on
member order.

Build or run the CLI with parallel workers:

```sh
cargo run -p rars-cli --features parallel -- --threads 4 a --format rar50 archive.rar files...
cargo run -p rars-cli --features parallel -- x --threads 4 archive.rar out/
cargo test --workspace --features parallel
```

Measure parallel archive-member work with Criterion:

```sh
cargo bench -p rars --bench parallel --features parallel
cargo +nightly bench -p rars --bench parallel --features fast,parallel
```

The parallel benchmark reports `1_thread` and `all_threads_N` cases for RAR5
multi-member compression and extraction.

When `--threads` is omitted, `rars` uses all available cores. Passing
`--threads` to a CLI built without `parallel` is rejected.

## Python bindings

The workspace includes PyO3 bindings packaged as the `rars` Python module for
Python 3.10 and newer. The default Python build enables the Rust `parallel`
feature; the optional `fast` feature is available for nightly Rust builds only
because it relies on `std::simd`.

```sh
maturin develop
RUSTUP_TOOLCHAIN=nightly maturin develop --features fast
```

The Python API exposes a `rarfile`-style `RarFile` for listing, reading,
testing, and extracting archives, plus `RarBuilder` for creating or rewriting
archives. Rewrites are staged into a new archive; existing RAR files are not
edited in place.

## Development

Run the test suite:

```sh
cargo test --workspace --all-targets
```

Generate a local coverage report:

```sh
rustup component add llvm-tools-preview
./scripts/coverage.py
```

The script prints a line-coverage summary, saves it to
`target/coverage/summary.txt`, and writes HTML output to
`target/coverage/html/library/index.html` and `target/coverage/html/cli/index.html`.
