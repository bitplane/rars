# rars

A Rust implementation of RAR.

* 🏠 [home](https://bitplane.net/dev/rust/rars)
* 📦 [downloads](https://github.com/bitplane/rars/releases)
  * 🦀 [crates](https://crates.io/crates/rars)
  * 🐍 [pypi](https://pypi.org/project/rars)
  * 📜 [npm](https://www.npmjs.com/package/@bitplane/rars)
* 🐱 [source](https://github.com/bitplane/rars)
  * 📃 [spec](https://github.com/bitplane/rar-research)

`rars` is free software for compression, decompression and recovery of RAR
archives. It supports all the archive types I could find - from the early `RE~^`
ones from the DOS days all the way through to RAR 7. It comes with a Rust
library, a CLI, Python and TypeScript bindings.

It started as an
[agentic development experiment](https://bitplane.net/log/2026/05/rars/), and
has since matured as it gained some users. It's still a bit slower than WinRAR,
uses more memory and has slightly worse compression. It could use more testing
at volume, too. Other than that it's in pretty good shape.

## Usage

The API is in the `rars` crate, which is used by the Python and TypeScript
bindings. For the CLI, run:

`cargo install rars-cli`.

To inspect, test, and extract archives:

```sh
rars info archive.rar
rars test archive.rar
rars x archive.rar out/
```

These commands accept parsing and decoding limits; see
[CLI reader controls](CLI_READING.md).

To create archives with a specific RAR generation:

```sh
rars a --format rar29 archive.rar files...
rars a --format rar29 --solid --auto-filter archive.rar files...
rars a --format rar70 --store --volume-size 10m archive.part1.rar files...
```

The writer supports stored and compressed members, split volumes, passwords,
comments, RARVM filters, RAR5 quick-open records, recovery records and header
encryption. There are a lot of things I won't list here, so run `rars --help`
for more details.

On Unix, native filenames and legacy archive names can contain non-UTF-8 bytes.
The CLI, Python extraction and Rust path adapters preserve those bytes. RAR5/7
filesystem inputs use the format's reversible Unix byte mapping; member metadata
and lookup keys retain the encoded archive identity. Use byte names (or Python
`RarInfo` objects) for exact lookup, rather than lossy display names.

Legacy code pages are not guessed. Windows supports Unicode names; extracting
non-Unicode legacy byte names there still requires caller-selected decoding.
Use `--legacy-name-encoding cp850` or the corresponding binding option; see
[legacy filename decoding](FILENAME_ENCODINGS.md) for supported encodings and
preservation semantics.

## Writer execution

For writer execution modes, workspace estimates and retained storage, see
[WRITER_EXECUTION.md](WRITER_EXECUTION.md).

RAR5/7 writers accept an optional aggregate managed-memory ceiling: Rust
`WriterResources::with_max_memory_bytes`, CLI `rars a --max-memory 256m`,
Python `RarBuilder(max_memory_bytes=256 << 20)`, and npm
`new RarWriter({ maxMemoryBytes: 256 * 1024 * 1024 })`.
The default is unlimited. This counts writer execution allocations and retained
output, including binding copy peaks; caller inputs, sinks, runtime and allocator
overhead are excluded. Legacy writers refuse the policy. Reader and rewrite
staging limits are separate. See [the resource contract](WRITER_RESOURCE_CONTRACT.md)
for ownership boundaries and the separate estimated-workspace policy.

## Bindings

Python bindings are published to [pypi](https://pypi.org/project/rars/), so you
can `pip install rars`. To build locally, it's `just python`.

`RarBuilder.from_archive` preserves supported RAR5/7 metadata and archive settings
by default, plus a limited subset of ordinary RAR2.9–4.x archives. Unsupported
preservation is rejected. Pass `preserve=False` explicitly
to convert to unencrypted RAR5, including from older archives. This default change
is intended for the next minor release; see the [rewrite contract](python/REWRITING.md).

`RarBuilder` writes accept `cancellation=rars.CancellationToken()` for
cooperative cancellation from another Python thread, with or without progress
callbacks. Reader operations accept `options=rars.ReadOptions(...)` for
cancellation, output ceilings and RAR5/7 decoder limits. See the
[reader controls](python/READING.md) and [rewrite contract](python/REWRITING.md).
Repair operations also accept `cancellation=`; see [repair cancellation](python/REPAIRING.md).

For JS it's built to WebAssembly and published to
[npm](https://www.npmjs.com/package/@bitplane/rars);
`npm install @bitplane/rars`. It reads and writes in the browser and in Node,
with no native module. To build locally, type `just npm`.

Licensed under the [Apache License, Version 2.0](COPYING).
