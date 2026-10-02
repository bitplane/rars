# Independent reader build

This package has its own workspace to prevent the CLI, Python and WebAssembly
packages from enabling the library's default features during feature checks.
It parses an archive and decodes every member to a sink, checking integrity.
The executable uses reader APIs only. Its tests also exercise optional capabilities
when those features are selected.

From the repository root:

```sh
CARGO_BUILD_JOBS=1 cargo build --manifest-path scripts/reader-consumer/Cargo.toml \
  --release --target-dir target/reader-consumer
target/reader-consumer/release/rars-reader-consumer \
  crates/rars/tests/fixtures/golden/stored_rar50.rar
cargo tree --manifest-path scripts/reader-consumer/Cargo.toml
```

The `full` feature enables the library defaults for comparison. Record dependency
trees, clean build times and executable sizes under ignored `target/` directories.
Compare identical compiler versions, profiles and consumer code; executable size
includes only linked code and does not measure all compilation savings.

## Feature checks

The library preserves the complete feature set by default:

| Feature | Responsibility |
| --- | --- |
| No defaults | Sequential parsing and decoding of every supported format, metadata, checksums, solid/split members, comments, cancellation and resource policies |
| `write` | Encoders, builders, writing and rewriting; writer entropy |
| `recovery` | Recovery generation and repair; record metadata stays in the reader |
| `encryption` | Encrypted header and payload reading and crypto dependencies |
| `parallel` | Rayon execution; without it, fan-out operations run sequentially |

Each feature works independently and in combination. Writing encrypted
archives requires both `write` and `encryption`. Unsupported encrypted operations
return an explicit error rather than treating ciphertext as plain data.
Recovery does not pull in the full writer to publish repaired bytes. Disabling
features preserves format recognition and metadata wherever those can be
read without the omitted implementation.

Run the complete 16-combination matrix, with sequential Cargo invocations and
resource limits, after fetching the locked dependencies:

```sh
cargo fetch --locked
cargo fetch --locked --manifest-path scripts/reader-consumer/Cargo.toml
nice -n 10 python3 scripts/check-reader-features.py
# Or one focused combination:
python3 scripts/check-reader-features.py --features write,encryption
```

The script checks library and consumer Clippy, runs historical and modern reader
fixtures, and verifies excluded dependencies. It includes encrypted archives,
recovery metadata and repair, disabled operations, writer round trips and
buffered extraction with sequential fallback. The library's comprehensive
self-generated fixture suite runs with defaults enabled; the independent
consumer checks the optional feature configurations. Logs and dependency trees
are generated under ignored `target/reader-features/`, never tracked in Git.

For a clean release measurement, use a new ignored target directory per build:

```sh
CARGO_BUILD_JOBS=1 /usr/bin/time -p cargo build --offline --locked \
  --manifest-path scripts/reader-consumer/Cargo.toml --release \
  --target-dir target/reader-measurement
wc -c target/reader-measurement/release/rars-reader-consumer
```

Repeat with `--features full` and a different empty target directory. Record the
compiler version and use identical consumer code and release profiles. The
release profile strips symbols. Compile times depend on the machine and cache;
executable size excludes unused library code removed by the linker.
