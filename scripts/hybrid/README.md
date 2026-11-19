# Frozen encoder comparison runner

`scripts/hybrid_candidates.py` compares a built `rars` against native RAR
(and optionally a `--baseline` rars, such as the previous release) on a fixed
corpus. Each run directory gets frozen copies of the binaries, inputs, plan and
the runner itself. Run results come from those copies, and you can stop a run
and resume it later. Python 3.9+, macOS, Linux or FreeBSD.

Modes:

- default (controls): rars against native RAR, one configuration per profile.
- `--experiment smoke`: rars only, create/test/extract. No native RAR needed.
- `--experiment hybrid`: the old 64-variant matrix, for an experimental rars
  build with the hybrid switches. That build is not in this repository.

## Run

Generate the small synthetic fixtures, optionally on top of an existing corpus,
then freeze and run from a clean committed checkout. Keep generated data out of
the source tree:

```sh
python3 scripts/hybrid_fixtures.py work/hybrid-corpus \
  --base-corpus /absolute/path/to/existing/manifest.json
python3 scripts/hybrid_candidates.py init --output work/hybrid-run \
  --rars /absolute/path/to/rars \
  --native-rar /absolute/path/to/rar \
  --corpus work/hybrid-corpus/manifest.json \
  --profile desktop --profile server
python3 work/hybrid-run/frozen/hybrid_candidates.py run work/hybrid-run
python3 work/hybrid-run/frozen/hybrid_candidates.py status work/hybrid-run
```

`run --max-tasks N` stops at a task boundary and the same `run` resumes. A
different experiment needs a new directory.

The corpus manifest is
`{"files":[{"path":"relative/file","sha256":"..."}],"workloads":[{"id":"case","files":["relative/file"],"solid":false}]}`.
Empty directories can be listed as `{"path":"empty","type":"directory"}`.

## What it measures

All encoders run at level 3 with one thread by default. rars writes `rar50`,
native RAR `-ma5`. Both get the same dictionary: the next power of two above
the largest member (or the solid total), at least 128 KiB, capped at 4 MiB for
the desktop profile and 64 MiB for server. rars also gets a 256 MiB (desktop)
or 8 GiB (server) memory limit.

Every archive is tested and extracted by both native RAR and rars. Extraction
must reproduce paths, sizes, SHA-256s, permission bits and whole-second mtimes.
Wall time, child CPU and peak RSS are recorded per process.

Screening runs each configuration once per workload, within a four host-hour
budget and a 300-second task limit by default. Up to three Pareto-optimal
configurations per profile then go to confirmation: one warmup and 15 paired
repetitions per workload, within twelve host-hours. A failed control stops the
run; a failed candidate is dropped. Archives, receipts and logs are kept;
extracted trees are deleted once verified.

## Plan options

`init --plan plan.json` accepts:

```json
{
  "fixed_dictionary_bytes": 4194304,
  "worker_options": {"rars_add": ["--no-filter"], "native_add": ["-mc-"]},
  "task_timeout_seconds": 300,
  "budgets": {"screen": 3600, "confirm": 7200},
  "execution": {"parallel_screening": false, "screen_threads": 1, "confirm_threads": 1},
  "cold_prepare": ["/absolute/path/cache-helper", "{archive}"]
}
```

`fixed_dictionary_bytes` (controls mode only) overrides the fitted dictionary
for every encoder. `worker_options` also takes `rars_read` and `native_read`;
it can't override dictionary, thread or memory switches. Budgets can only be
lowered. `parallel_screening` runs `screening_slots` jobs per host (set in the
inventory, with optional `logical_cpus` and `memory_budget_bytes` checks);
confirmation always runs one job per host. `cold_prepare` runs a helper before
timing a selective extraction of the last regular file; `{archive}` becomes the
archive path. The runner does not evict caches itself.

## Remote workers

Without `--inventory` the runner uses only this host. To spread work:

```json
[
  {"id":"local","kind":"local","hostname":"desktop.example"},
  {"id":"worker1","kind":"ssh","hostname":"worker1.example",
   "ssh_target":"user@worker1.example","port":22,
   "remote_directory":"/work/rars-hybrid"}
]
```

`hostname` must match `socket.gethostname()` on the worker. SSH runs in
BatchMode and won't accept unknown host keys. `dispatch work/hybrid-run` runs
every listed worker and imports their receipts. For an offline worker, use
`"kind":"export"`:

```sh
python3 scripts/hybrid_candidates.py export-worker work/hybrid-run \
  --host worker1 --output worker1.tar.gz
# on the worker, after extracting:
python3 hybrid-run/frozen/hybrid_candidates.py run hybrid-run --host worker1
# back on the controller:
python3 scripts/hybrid_candidates.py import-results work/hybrid-run \
  --from-directory /absolute/path/to/returned/hybrid-run
```

Export again after screening to hand out the confirmation list.

## Tests

```sh
python3 -m unittest discover -s scripts/hybrid -v
```

The unit tests use fake archivers. To include the real-binary smoke test, build
rars and point at it; set `RARS_NATIVE_RAR` too, or put `rar` on `PATH`, for the
native half (it skips without one):

```sh
cargo build -p rars-cli --locked
RARS_SMOKE_BINARY="$PWD/target/debug/rars" \
  python3 -m unittest discover -s scripts/hybrid -v
```
