# rars

A Rust implementation of RAR.

* 🏠 [home](https://bitplane.net/dev/rust/rars)
  * 🪵 [blog](https://bitplane.net/log/2026/05/rars/)
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

It's a bit slower than WinRAR, it uses more memory and has slightly worse
compression. It could probably use more testing, too. Other than that it's in
pretty good shape.

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

## Bindings

Python bindings are published to [pypi](https://pypi.org/project/rars/), so you
can `pip install rars`. To build locally, it's `just python`.

`RarBuilder.from_archive` currently converts to unencrypted RAR5 and does not
preserve all metadata. See the [rewrite contract](python/REWRITING.md) before
using it to edit existing archives.

For JS it's built to WebAssembly and published to
[npm](https://www.npmjs.com/package/@bitplane/rars);
`npm install @bitplane/rars`. It reads and writes in the browser and in Node,
with no native module. To build locally, type `just npm`.
