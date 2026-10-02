# Independent reader build

This package has its own workspace to prevent the CLI, Python and WebAssembly
packages from enabling the library's default features during feature checks.
It parses an archive and decodes every member to a sink, checking integrity.
Use existing fixture archives; this consumer must not depend on writer APIs.

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

## Feature contract for issue #45

The implementation will preserve the complete feature set by default. The
independent consumer is also the baseline before these boundaries are introduced:

| Feature | Responsibility |
| --- | --- |
| No defaults | Sequential parsing and decoding of every supported format, metadata, checksums, solid/split members, comments, cancellation and resource policies |
| `write` | Encoders, builders, writing and rewriting; writer entropy |
| `recovery` | Recovery generation and repair; record metadata stays in the reader |
| `encryption` | Encrypted header and payload reading and crypto dependencies |
| `parallel` | Rayon execution; without it, fan-out operations run sequentially |

Each feature must work independently and in combination. Writing encrypted
archives requires both `write` and `encryption`. Unsupported encrypted operations
must return an explicit error rather than treating ciphertext as plain data.
Recovery must not pull in the full writer to publish repaired bytes. Disabling
features must preserve format recognition and metadata wherever those can be
read without the omitted implementation.
