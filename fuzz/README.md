# Local fuzzing

This is a separate Cargo workspace, so normal workspace checks don't build
these targets and CI doesn't run them.

From the repository root, install the tooling once:

```sh
mkdir -p target/fuzz-tmp
TMPDIR="$PWD/target/fuzz-tmp" CARGO_TARGET_DIR="$PWD/target/fuzz-tools" cargo install cargo-fuzz --locked
rustup toolchain install nightly --profile minimal
cargo +nightly fuzz list
cargo +nightly fuzz build
```

Builds, corpora and artifacts stay under the repository, not in a possibly
RAM-backed `/tmp`. After a rars version or dependency change, refresh
`fuzz/Cargo.lock` with
`RUSTFLAGS="--cfg fuzzing" cargo check --manifest-path fuzz/Cargo.toml --bins`.
`--cfg fuzzing`, which `cargo fuzz` sets itself, exposes the RAR 3 VM to
`rarvm_parse_execute`.

## Targets

- `archive_parse`: archive dispatch and parsing.
- `archive_extract`: parse a single archive and extract sequentially to a discard
  sink, including solid members. It caps input at 1 MiB, headers at 256/256 KiB,
  individual output at 1 MiB, total output at 4 MiB, and RAR5 declared dictionaries
  at 8 MiB. Filtered buffering is capped at 1 MiB. Errors are expected; panics and
  sanitizer failures are not. Passwords and multi-volume assembly are not covered.
- `unpack29_decode`, `ppmd_decode`, `unpack50_decode`: decoder primitives.
- `rarvm_parse_execute`: VM parsing and execution. Small programs can still loop.
  The decoder and archive targets enable non-standard RAR 3 VM programs, which
  readers refuse by default.
- `unpack15_round_trip`: encoder/decoder agreement across encoding options.
- `rar3_recovery`, `rar5_recovery`: recovery records and reconstruction.
- `rar30_crypto`, `rar50_crypto`: crypto primitives. The RAR5 target limits KDF
  rounds to keep individual cases useful for fuzzing throughput.

## Smoke checks and longer runs

Build first. Replay a known valid archive without random mutation:

```sh
cargo +nightly fuzz run archive_extract crates/rars/tests/fixtures/golden/stored_rar50.rar -- -timeout=10 -rss_limit_mb=1024
```

For a time-bounded local campaign, copy small representative fixtures into a
working corpus; do not let libFuzzer write into the regression-fixture directory:

```sh
mkdir -p fuzz/corpus/archive_extract
cp crates/rars/tests/fixtures/golden/stored_rar50.rar fuzz/corpus/archive_extract/
cp crates/rars/tests/fixtures/rar15_40/ppmd/ppmd_solid_rar300.rar fuzz/corpus/archive_extract/
cp crates/rars/tests/fixtures/rar50/filter_e8e9.rar fuzz/corpus/archive_extract/
timeout --kill-after=5s 70s cargo +nightly fuzz run archive_extract -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024 -max_len=1048576
```

Other targets take the same flags. `-rss_limit_mb` is sampled, not a hard
ceiling; use a cgroup when you need one.

Crashes and timeouts land in `fuzz/artifacts/<target>/`. Turn confirmed bugs
into small deterministic regression tests.
