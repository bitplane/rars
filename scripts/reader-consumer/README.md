# Independent reader build

A minimal program that depends on `rars` with default features off. It parses
an archive and decodes every member to a sink, checking integrity. It has its
own workspace so the CLI, Python and WebAssembly packages can't switch the
library's default features back on.

```sh
CARGO_BUILD_JOBS=1 cargo build --manifest-path scripts/reader-consumer/Cargo.toml \
  --release --target-dir target/reader-consumer
target/reader-consumer/release/rars-reader-consumer \
  crates/rars/tests/fixtures/golden/stored_rar50.rar
```

Its `full` feature turns the library defaults back on, for comparing build
time and binary size. Use a fresh target directory per build and the same
compiler for both.

## Library features

| Feature | Adds |
| --- | --- |
| none | Parsing and decoding every format, metadata, checksums, solid and split members, comments, cancellation and resource limits |
| `write` | Encoders, builders, writing and rewriting |
| `recovery` | Recovery record generation and repair (reading record metadata needs no feature) |
| `encryption` | Encrypted headers and payloads |
| `parallel` | Rayon; without it, fan-out runs sequentially |

The defaults turn all of them on. Writing encrypted archives needs both `write`
and `encryption`. Without a feature, rars still recognises what it can't
process and returns an explicit error, rather than treating ciphertext as data.

`scripts/check-reader-features.py` runs Clippy, the reader fixtures and a
dependency check for all 16 combinations, logging under `target/reader-features/`:

```sh
cargo fetch --locked
cargo fetch --locked --manifest-path scripts/reader-consumer/Cargo.toml
nice -n 10 python3 scripts/check-reader-features.py
python3 scripts/check-reader-features.py --features write,encryption   # one combination
```

`scripts/check-unit-features.py` does the same for the library's unit tests,
with warnings denied.
