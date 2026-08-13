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
records, and supported recovery records. Run `rars --help` for more info.

RAR 5 and RAR 7 archives are written in a single pass without being held in
memory, so the peak stays flat whatever the inputs weigh. Members compress into
temporary files under `--temp-dir`, and `--memory-limit` (256MB by default)
bounds the working set: raise it to compress more blocks at once, which on a
machine with many cores is what limits throughput. The number of `--threads`
defaults to your core count.

Two things still need a whole member in memory, and fall back to streaming
without it when the budget is too small to allow it: choosing a data filter,
and comparing candidate settings at `--level 5`. Per-file comments, PPMd and
the RAR 1.3-4.x formats still assemble archives in memory; the CLI warns
before doing that with a large input.


## Python bindings

Python bindings are published to [pypi](https://pypi.org/project/rars/), so you
can `pip install rars`. To build locally, it's `maturin develop`.

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
