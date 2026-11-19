# RAR 5/7 encoder memory

## Managed-allocation regression test

`crates/rars/tests/encoder_memory_regression.rs` writes RAR 5 and RAR 7 archives
through `Builder::write_to` and the streaming writer, under fixed
`WriterResources` ceilings: 96 MiB for ordinary writes (160 KiB members,
dictionaries from 128 KiB to 1 MiB, levels 1/3/5) and 448 MiB for solid writes
with a full 1 MiB history. Each case must produce the same archive at one and
two threads and decompress byte for byte. Refused and cancelled writes must
leave the destination alone, release all managed capacity and leave no spool
files. CI runs it with default features, `write`, and `write,parallel`:

```sh
cargo test -p rars --locked --test encoder_memory_regression
cargo test -p rars --locked --no-default-features --features write,parallel --test encoder_memory_regression
```

The ceilings bound the managed ledger, not process RSS. Caller buffers,
stacks and allocator overhead are outside it.

## RSS comparison

`compare.py` measured peak process RSS before and after the encoder change in
PR #83 (`51addb73` against merge `4298f18e`), using the wait4 worker from
`../exact-encoder/vendor/worker.py`. It needs Python 3.9+, Git, Cargo and a
native `unrar`. `prepare` checks out and builds both revisions; `run` builds
nothing, so give it a quiet machine:

```sh
python3 benchmarks/encoder-memory/compare.py prepare \
  --repository /absolute/rars --native-unrar /absolute/unrar \
  --output /absolute/encoder-memory-run
python3 /absolute/encoder-memory-run/compare.py run \
  --output /absolute/encoder-memory-run
```

Inputs are two 1 MiB members, either SHAKE256 noise or a repeated pattern,
with filters and solid off and 1 GiB memory limits. Every archive is checked by
`unrar` and by the encoder that wrote it. Median peak RSS in MiB over three
pairs, from `observed-local.json` (arm64 macOS, 2026-10-22):

| Data | Configuration | Before | After |
| --- | --- | ---: | ---: |
| Noise | RAR 5, 1 MiB dictionary, level 1, one thread | 18.0 | 16.4 |
| Noise | RAR 7, 3 MiB dictionary, level 3, two threads | 40.5 | 33.3 |
| Repetitive | RAR 5, 1 MiB dictionary, level 1, one thread | 10.4 | 10.0 |
| Repetitive | RAR 7, 3 MiB dictionary, level 3, two threads | 89.5 | 43.4 |

Three samples on one machine; treat it as a sanity check, not a bound.
