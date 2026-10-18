# Frozen hybrid candidate runner

This POSIX Python 3.9+ runner executes a finite experiment without building or
changing source, calling an AI service, or discovering remote hosts. It requires
an already-built experimental `rars`, an ordinary-rars control, and a licensed
native RAR executable. It reports measurements and verified Pareto candidates;
it does not assert native parity or apply a size-percentage or archive-byte
identity acceptance rule.

Local and SSH workers support macOS, Linux and FreeBSD with compatible frozen
executables. Peak RSS uses macOS byte units and converts Linux/FreeBSD KiB units
to bytes; unknown platforms retain an unavailable RSS measurement.

Generate the related-release, distance, shifted and unrelated fixtures alongside the existing corpus:

```sh
python3 scripts/hybrid_fixtures.py work/hybrid-corpus \
  --base-corpus /absolute/path/to/existing/manifest.json
```

Use an ignored working directory or a location outside the source checkout for generated data. From a **clean committed checkout**, freeze the binaries, full corpus and plan:

```sh
python3 scripts/hybrid_candidates.py init --output work/hybrid-run \
  --rars /absolute/path/to/experimental-rars \
  --baseline /absolute/path/to/ordinary-rars \
  --native-rar /absolute/path/to/rar \
  --corpus work/hybrid-corpus/manifest.json \
  --profile desktop --profile server
python3 work/hybrid-run/frozen/hybrid_candidates.py run work/hybrid-run
python3 work/hybrid-run/frozen/hybrid_candidates.py status work/hybrid-run
```

Omit `--baseline` to use the experimental executable **without hybrid flags** as
the explicit ordinary-rars control. Profiles may be selected independently; the
default is desktop. Do not modify binaries, frozen inputs, manifests or frozen
worker source after initialization. A different experiment needs a new directory.
`run --max-tasks N` pauses at a task boundary; the same `run` resumes automatically.

Each profile has exactly 64 immutable variants. Bit 0 enables deeper search,
bit 1 multiple states, bit 2 full partitions, bit 3 automatic filters, bit 4
member ordering, and bit 5 adaptive rather than existing automatic dictionary
selection. Every combined-hybrid variant explicitly requests relationship
analysis; bit 4 changes ordering alone. Hybrid, relationships and streams omit
an explicit dictionary request. The filter bit explicitly requests `--auto-filter` when on and `--no-filter` when off; a separately requested mandatory filter remains authoritative. Solid/filter combinations unsupported by the CLI are frozen as pre-dispatch exclusions with no child launch; all 64 configurations remain represented. Eligibility and confirmation require every applicable valid workload, at least one valid workload, and report omitted coverage explicitly. Configurations covering different applicable subsets are not evidence of a universal winner.

All encoders use level 3 and one thread. Ordinary rars/native controls request
the same mechanically fitted dictionary: the next power of two reaching the
largest regular member (the sum for solid workloads), at least 128 KiB, clipped
to 4 MiB for desktop or 64 MiB for server. These settings are recorded per
workload/profile in the frozen manifest and actual command. All rars encoder
roles explicitly set both estimated-workspace and hard managed-memory limits
to 256 MiB desktop or 8 GiB server. Worker options cannot override the matrix's
dictionary, thread or memory switches. Native process RSS is measured independently.
Rars requests `rar50`; native RAR requests `-ma5`.
Actual native archive metadata is retained verbatim: these flags do not establish
an identical compression-algorithm version. Corpus workloads control solid mode.

Every paired sample also runs relationship-only and stream-only architecture
controls. Relationships explicitly requests whole-archive analysis and permits
ordering only when bit 4 is set; streams masks bits 4/5, preserves the original
order and uses existing automatic dictionary selection, enabling only the stream-encoder choices. The
five unassisted roles (ordinary native, ordinary rars, hybrid, relationships,
streams) have seeded random order. A sixth **ordering-assisted native** role
runs afterward with `-ds`, using the candidate archive's member sequence. Its
actual member sequence must also match; it is reported separately from ordinary
native. Bare listings supply ordering only, after the candidate archive has
already passed actual two-decoder extraction verification. Corpus names with
newlines are refused rather than ambiguously parsed.

The corpus schema is `{"files":[{"path":"relative/file","sha256":"..."}],
"workloads":[{"id":"case","files":["relative/file"],"solid":false}]}`.
The existing parity corpus manifest is supported directly. Explicit empty
directories may appear as `{"path":"empty","type":"directory"}`. Each
workload gets an isolated frozen tree with exactly its files and parent/empty
directories. Only explicitly requested paths are passed to archivers. Implicit
parents are checked for existence/path/type, without inventing a request to
preserve their modes or timestamps. Explicit directories retain strict metadata
checks, including empty ones; a native extractor that changes a requested
folder timestamp while creating children fails that check and is recorded as a
control limitation.

Screening has a maximum **four aggregate host-hours**, confirmation twelve.
Multiple hosts receive fixed equal shares, so disconnected/exported workers
cannot multiply the total allowance. Each task reserves at most 300 seconds
including encoding, decoding and correctness work. The process group is killed
when its task reservation expires; normal scheduler/termination overhead is
recorded, not hidden. Task deadlines precede validation and are checked while hashing and verifying
extractions. Active phase wall time includes scheduling, journals, selection and
correctness work. OS I/O blocking and process-termination latency cannot be
preempted, so this is a cooperative budget, not a hard real-time guarantee.
Interrupted tasks conservatively consume their full reservation. Failed or interrupted samples are not automatically retried.
Control failure stops the run; candidate failure excludes that configuration.

Screening visits seeded whole-configuration workload blocks, keeping each configuration on one explicitly assigned host so a budget cutoff can yield complete candidates. It uses one sample for every configuration/workload it reaches. Only configurations
with all applicable workloads verified can enter selection. Four-dimensional non-dominance
uses within-task candidate/native ratios for compression wall time, archive size, compression peak RSS and rars extraction wall time, with equal workload weights. Absolute per-workload/host frontiers remain in the report; unlike hosts are not ranked by raw seconds or RSS. Up to three frontier configurations per
profile advance using a deterministic sum-log compromise rank. Configurations
with different applicable workloads are ranked in separate coverage groups;
promotion visits those groups round-robin, with broader coverage first. Confirmation
uses one warm-up followed by exactly 15 paired repetitions per workload, with
all unassisted command order frozen by task seed. Incomplete
confirmation is reported as incomplete, not qualified. Raw per-process results
and paired control ratios remain available for independent analysis.

Every archive is integrity-tested and **actually extracted by both native RAR
and rars**. Verification checks every file/directory path (including empty dirs),
file size and SHA256, POSIX permission bits and whole-second modification times of explicitly requested
archive members; implicit parent directories require path/type only;
symlinks are never followed. Owner/group, ACLs, xattrs and subsecond timestamps
are outside the supported comparison. No listing-only verification is used.
Wall time, child CPU and per-process peak RSS are recorded. Kernel filesystem
block counters and materialized temporary-output bytes have explicit scopes;
I/O byte totals and cold-cache claims are unavailable by default. Successful extracted trees are removed only after durable, hash-bound member and verification receipts are saved. Archives, receipts and logs remain; failed extraction trees are preserved. Provide disk space for the retained archives. A nonzero exit, content/metadata mismatch, resource refusal or timeout
retains its diagnostic files and excludes the affected candidate.

Optional `--plan plan.json` accepts `worker_options` arrays (`rars_add`,
`native_add`, `rars_read`, `native_read`), a positive
`task_timeout_seconds`, and reduced `budgets.screen`/`budgets.confirm` in seconds.
Budgets cannot exceed the declared maxima. The six matrix switches cannot be
injected through worker options.

For optional cold selective extraction, supply a direct executable helper in the
same plan:

```json
{"cold_prepare":["/absolute/path/cache-helper","{archive}"]}
```

Initialization copies and hashes this executable; workers run only that frozen
copy with literal argument arrays, without a shell. An argument equal to
`{archive}` becomes the measured archive's absolute path. Other arguments remain
literal. Shell/privilege wrappers are refused; no purge or sudo is implicit.
For each role, after the mandatory full extraction by both decoders, the runner
invokes this helper and measures native extraction of the lexicographically last
requested regular file. It verifies that selected file's bytes, path, supported
metadata and implicit parent paths, and checks the archive stayed unchanged.
Helper and extraction commands, wall time, CPU and RSS are recorded within the
same task budget. Successful selective trees are removed after durable proof;
failed trees remain. The scope is **operator-supplied cache preparation**:
system/global cache eviction is not verified. Without this option, or for a
workload containing no requested regular file, the measurement is unavailable.

## Explicit workers

No inventory means this host only; the runner does not search for SSH hosts.
An optional `--inventory hosts.json` freezes an explicit array:

```json
[
  {"id":"local","kind":"local","hostname":"desktop.example"},
  {"id":"worker1","kind":"ssh","hostname":"worker1.example",
   "ssh_target":"user@worker1.example","port":22,
   "remote_directory":"/work/rars-hybrid"}
]
```

The declared `hostname` must equal Python's `socket.gethostname()` on that
worker. Supply compatible frozen executable architectures. SSH uses BatchMode
and a connection timeout; it does not change SSH trust/credentials or accept
unknown keys automatically. Run `dispatch work/hybrid-run` to execute only the
listed local/SSH workers, import their hash-bound receipts and advance the two
phases mechanically. Hosts dispatch concurrently within each phase; returned
receipts retain inventory order and selection waits for the whole phase.
Local subprocesses use argument arrays; remote paths and
commands are validated/quoted. No actual SSH is exercised by the unit tests.

For an offline worker, declare `kind:"export"` and use:

```sh
python3 scripts/hybrid_candidates.py export-worker work/hybrid-run \
  --host worker1 --output worker1.tar.gz
# On the explicitly selected worker: extract the generated bundle, then
python3 hybrid-run/frozen/hybrid_candidates.py run hybrid-run --host worker1
# Return that directory (or a newly exported result bundle), then on controller:
python3 scripts/hybrid_candidates.py import-results work/hybrid-run \
  --from-directory /absolute/path/to/returned/hybrid-run
```

Only metadata/command receipts need returning alongside the frozen manifest and
inputs; exported bundles retain these. Do not merge an active worker's directory.
The controller waits for every worker's screen-phase boundary before selecting
finalists. Re-export after selection to supply the immutable confirmation list.
Transport failures retain remote state; task IDs and receipts prevent silently
rerunning completed samples. Conflicting receipts, changed hashes and torn
journal lines fail closed and preserve evidence for repair.

Run the mechanical tests, including fake executable smoke, with:

```sh
python3 -m unittest discover -s scripts/hybrid -v
```

Run the untimed native correctness harness separately with supplied executables
and a fresh output location:

```sh
python3 scripts/hybrid/native_smoke.py --candidate /absolute/path/rars \
  --native /absolute/path/rar --out /absolute/path/fresh-smoke.json
```

It records exact commands and extracted-content checks; it makes no speed claim.
