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

`rars` is free software and covers compression and decompression of archives
from the early `RE~^` ones all the way through to RAR 7. It comes with a Rust
library, a CLI, Python and TypeScript bindings.

It's a bit slower than WinRAR, uses more memory, compresses a little bit
worse and CLI isn't compatible with unrar. It could probably use more testing,
too.

## Usage

The `rars` crate is the API, as used by the Python and TypeScript packages.
For the CLI run `cargo install rars-cli`.

To inspect, test, and extract archives:

```sh
rars info archive.rar
rars test archive.rar
rars x archive.rar out/
```

To create archives with a specific RAR generation:

```sh
rars a --format rar29 archive.rar files...
rars a --format rar50 --solid --auto-filter archive.rar files...
rars a --format rar70 --store --volume-size 10m archive.part1.rar files...
```

The writer supports stored and compressed members, split volumes, passwords,
comments, RARVM filters, RAR5 quick-open records, and some support for recovery
records and header encryption. There are a lot of args, run `rars --help` for
more info.

## Bindings

Python bindings are published to [pypi](https://pypi.org/project/rars/), so you
can `pip install rars`. To build locally, it's `just python`.

For JS it's built to WebAssembly and published to
[npm](https://www.npmjs.com/package/@bitplane/rars);
`npm install @bitplane/rars`. It reads and writes in the browser and in Node,
with no native module. To build locally, run `just npm`.
