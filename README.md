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

Archives are written straight to their output rather than assembled in memory,
whatever the format. `--memory-limit` (256MB by default) bounds the working set,
and the number of `--threads` defaults to your core count.

RAR 5 and RAR 7 go furthest with this: members compress into temporary files
under `--temp-dir`, so the peak stays flat whatever the inputs weigh, and
raising the limit compresses more blocks at once, which on a machine with many
cores is what limits throughput.

RAR 5 and RAR 7 look for a data filter by default, which is worth around 6% on
executables and costs compression time rather than memory; `--no-filter` turns
it off, and solid archives do not use one because they share a dictionary
across members. Choosing a filter, and comparing candidate settings at
`--level 5`, both need a whole member in memory, and fall back to streaming
without them when the budget is too small to allow it.

RAR 2.9 and later look for a filter the same way. Candidates are screened on a
sample of the member before anything is compressed in full, so filters that were
never going to help cost a fraction of a member rather than one whole encode
each.

RAR 1.3 to 4.x compress a member as a unit, so one member has to fit in memory
even though the archive does not. There the limit decides how many members are
compressed at once, and a member too big for the whole budget is compressed on
its own rather than refused. Stored members are copied straight from disk and
never land in memory at all.

Volume sets are the exception: below RAR 5 the split has to see the whole packed
payload before it can decide where the parts break, so those are still built in
memory. The CLI warns before starting a large one and points at RAR 5, which
splits as it goes.

Every option either works for the format you chose or is refused before any
input is read, naming the flag and a format that would have worked:

```
$ rars a --format rar15 --encrypt-headers --password pw archive.rar files...
error: --encrypt-headers is not supported by --format rar15; use --format rar30,
--format rar40, --format rar50 or --format rar70
```


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
