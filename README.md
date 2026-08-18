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

## Status

`rars` covers RAR compression and decompression from early `RE~^` archives
through to RAR 7. It comes with Python and TypeScript bindings

## Usage

The `rars` crate is the API, which is what the Python package uses. For the CLI
run `cargo install rars-cli`.

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
records, and supported recovery records. There are a lot of args, run
`rars --help` for more info.

## Bindings

Python bindings are published to [pypi](https://pypi.org/project/rars/), so you
can `pip install rars`. To build locally, it's `maturin develop`.

For JS it's WebAssembly, published to
[npm](https://www.npmjs.com/package/@bitplane/rars), so
`npm install @bitplane/rars`. It reads and writes in the browser and in Node,
with no native module. To build locally, `just npm`.
