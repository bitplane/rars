# Local fuzzing

This is a separate Cargo workspace; normal workspace checks do not build these
targets. Run fuzzing locally or in explicitly scheduled jobs. PR checks run the
ordinary deterministic tests, not random fuzz campaigns.

From the repository root, install the tooling once:

```sh
mkdir -p target/fuzz-tmp
TMPDIR="$PWD/target/fuzz-tmp" CARGO_TARGET_DIR="$PWD/target/fuzz-tools" cargo install cargo-fuzz --locked
rustup toolchain install nightly --profile minimal
cargo +nightly fuzz list
cargo +nightly fuzz build
```

Builds, corpora and artifacts stay on disk under the repository, rather than
putting large working data in a potentially RAM-backed `/tmp`. After a rars
version/dependency change, refresh this workspace's lockfile with
`cargo check --manifest-path fuzz/Cargo.toml --bins`, then commit `fuzz/Cargo.lock`.

## Targets

- `archive_parse`: archive dispatch and parsing.
- `archive_extract`: parse a single archive and extract sequentially to a discard
  sink, including solid members. It caps input at 1 MiB, headers at 256/256 KiB,
  individual output at 1 MiB, total output at 4 MiB, and RAR5 declared dictionaries
  at 8 MiB. Filtered buffering is capped at 1 MiB. Errors are expected; panics and
  sanitizer failures are not. Passwords and multi-volume assembly are not covered.
- `unpack29_decode`, `ppmd_decode`, `unpack50_decode`: decoder primitives.
- `rarvm_parse_execute`: VM parsing and execution. Small programs can still loop.
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

The outer `timeout` command is available on Linux. It covers the whole command,
so build first. Adjust durations explicitly for longer runs. Other targets use
the same runner flags, with input sizes suited to their individual harnesses.

Logical output and dictionary admission are not an aggregate RAM/CPU budget.
Keep the per-input timeout and process RSS guard even with reader limits;
libFuzzer's RSS guard is sampled, not a strict OS memory ceiling. Use a dedicated
container/cgroup when a hard machine-wide resource ceiling is required. Reader
cancellation cannot preempt blocked I/O, allocations or every library primitive.

Crashes/timeouts are saved under `fuzz/artifacts/<target>/`. Triage them locally
and turn confirmed bugs into small deterministic regression tests. A successful
smoke replay verifies the harness, not the robustness of the parser or codecs.
