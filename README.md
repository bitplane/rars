# rars

A Rust implementation of RAR.

* [🏠 home](https://bitplane.net/dev/rust/rars)
  * [🪵 blog](https://bitplane.net/log/2026/05/rars/)
* [🦀 crate](https://crates.io/crates/rars)
* [🐱 source](https://github.com/bitplane/rars)
* [📃 spec](https://github.com/bitplane/rar-research)

## Current Status

`rars` covers the RAR lineage from early `RE~^` archives through RAR 7,
compression and decompression. It's getting faster, and kinda works.

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

Non-solid RAR 5 and RAR 7 creation streams path inputs through bounded codec
windows and disk-backed payload spools. The global compression workspace limit
defaults to 256 MiB and is shared by Rayon jobs; a dictionary that cannot fit is
rejected before compression starts. Temporary payloads are created beside the
output archive by default.

```sh
rars a --memory-limit 128m --temp-dir /path/with/space archive.rar files...
```

## Parallel work

Rayon worker threads process independent archive members. This parallelizes
non-solid compression planning for supported
writers and buffered extraction of non-solid, non-split single archives while
preserving archive order for output. Solid archives and multivolume extraction
fall back to the existing sequential stream because their codec state depends on
member order.

Control the number of workers with `--threads`:

```sh
cargo run -p rars-cli -- --threads 4 a --format rar50 archive.rar files...
cargo run -p rars-cli -- x --threads 4 archive.rar out/
```

Measure parallel archive-member work with Criterion:

```sh
cargo bench -p rars --bench parallel
```

The parallel benchmark reports `1_thread` and `all_threads_N` cases for RAR5
multi-member compression and extraction.

When `--threads` is omitted, `rars` uses all available cores. Pass
`--threads 1` to run member work serially.

## Python bindings

The workspace includes PyO3 bindings packaged as the `rars` Python module for
Python 3.10 and newer. Independent archive members are processed in parallel.

```sh
maturin develop
```

The Python API exposes a `rarfile`-style `RarFile` for listing, reading,
testing, and extracting archives, plus `RarBuilder` for creating or rewriting
archives. Rewrites are staged into a new archive; existing RAR files are not
edited in place. `RarBuilder.add()` keeps path inputs lazy, and the common
non-solid RAR 5/7 `write()` path writes directly instead of first constructing
the complete archive in memory. `add_bytes()` and `to_bytes()` remain available
as convenience wrappers.

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
