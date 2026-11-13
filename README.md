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

## Install

```sh
cargo install rars-cli       # the CLI
cargo add rars               # the Rust library
pip install rars             # Python
npm install @bitplane/rars   # JavaScript, as WebAssembly for Node or the browser
```

Then `rars --help`. For example:

```sh
rars x archive.rar out/
rars a --format rar29 --solid archive.rar files...
rars a --format rar70 --volume-size 10m archive.part1.rar files...
```

For programs that run the `unrar` command, rars-cli also installs `unrars`,
which takes unrar's commands, switches and exit codes. For programs that link
against libunrar, bgermann's [unrars](https://crates.io/crates/unrars) crate
wraps rars in the same C ABI.

Licensed under the [Apache License, Version 2.0](COPYING).
