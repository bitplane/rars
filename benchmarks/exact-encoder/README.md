# Exact encoder comparison

This package benchmarks the `experimental-ring-state` encoder against three
frozen controls (current, wide and cyclic) on seven inputs, with native RAR
checking every archive. The latest numbers are in [RESULTS.md](RESULTS.md).
It is standard-library Python; bring your own native `rar`. POSIX hosts only.

`vendor/worker.py` is the measurement worker, pinned at SHA256
`866235a7…0771d`, and `analysis.py` does the paired-median bootstrap (5,000
resamples). Don't edit either; `selfcheck.py` verifies them.

## Build inputs and controls

Start from a clone that contains revision `d4664689`. The corpus is generated
from that revision and must match `corpus.json` byte for byte. The controls are
d466 plus `references/wide.patch` and `references/cyclic.patch`. Keep both
outside the repository:

```sh
B=/absolute/rars/benchmarks/exact-encoder
R=/absolute/rars
python3 "$B/corpus.py" --repository "$R" --output /absolute/corpus
python3 "$B/build_controls.py" --repository "$R" --output /absolute/controls
```

`build_controls.py --check-only` verifies the patches apply without compiling.
Build the candidate from a clean commit:

```sh
cargo build --release --locked -p rars-cli --features experimental-ring-state
```

## Run

```sh
python3 "$B/benchmark.py" freeze --repository "$R" \
  --candidate /absolute/candidate --current /absolute/controls/current \
  --wide /absolute/controls/wide --cyclic /absolute/controls/cyclic \
  --native-rar /absolute/native/rar --corpus /absolute/corpus/manifest.json \
  --control-provenance /absolute/controls/controls.json \
  --label exact-final --output /absolute/run
python3 /absolute/run/benchmark.py screen --output /absolute/run
python3 /absolute/run/benchmark.py qualify --output /absolute/run
python3 /absolute/run/assess.py /absolute/run/qualification.json > /absolute/run/assessment.json
python3 /absolute/run/benchmark.py smoke --output /absolute/run
python3 /absolute/run/benchmark.py export --output /absolute/run --destination /absolute/public-results.json
```

`screen` checks the candidate's archives are byte-identical to the current
control's. `qualify` runs one warmup and 15 measured pairs per workload
against each control, serially; don't run anything else on the machine.
`smoke` runs twelve RAR 5/7 settings through both decoders. The export strips
local paths.

`assess.py` exits 0 only if all five upper 95% bounds are at most 1:
dictionary-distance CPU and pressure CPU against current, 2 MiB source wall
and CPU against wide, and 2 MiB source RSS against cyclic. Exit 2 is a fail.
Rerunning unchanged code until an interval passes defeats the test.
