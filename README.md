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

New RAR 1.4, 1.5, 2.0, 2.9, 3, 4, 5 and 7 archives include a `RARS` record identifying the
producing rars library version. RAR 1.4 uses a main-header extension; later
formats use a service record. It is separate from files and user comments,
and appears in every volume. The producer/version text remains readable even
when archive headers are encrypted. It is advisory metadata, not authentication;
other archivers may remove it when updating an archive. The record layout and
compatibility results are documented in the
[RAR 5/7 producer-marker report](scripts/producer-marker/README.md),
[RAR 3/4 compatibility report](scripts/producer-marker/rar34/README.md),
[RAR 2.9 compatibility report](scripts/producer-marker/rar29/README.md),
[RAR 2.0 compatibility report](scripts/producer-marker/rar20/README.md),
[RAR 1.5 compatibility report](scripts/producer-marker/rar15/README.md) and
[RAR 1.3/1.4 compatibility report](scripts/producer-marker/rar14/README.md).

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

The opt-in [hybrid encoder](HYBRID_ENCODER.md) has a separate
[candidate runner](scripts/hybrid/README.md). It freezes 64 configurations per
profile, resumes bounded screening and confirmation, and verifies native/rars
extraction before ranking candidates. It requires prebuilt binaries.

Licensed under the [Apache License, Version 2.0](COPYING).
