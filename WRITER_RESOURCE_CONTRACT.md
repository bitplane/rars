# Writer resource accounting

This contract separates enforceable storage quotas from estimated compression
workspace. It is not a process-RSS guarantee. The allocation inventory and
current scheduling behaviour are in [WRITER_EXECUTION.md](WRITER_EXECUTION.md).

## Available quota: logical spool storage

```rust
let resources = rars::WriterResources::default()
    .with_temp_dir("scratch")
    .with_max_spool_bytes(64 * 1024 * 1024);
builder.write_to(&mut output, &resources, None)?;
```

`max_spool_bytes` caps the sum of logical lengths of spools created using this
resource group, plus reserved growth that has not yet completed. It covers
packed-member spools, volume bodies, encryption copies, recovery prefix mirrors,
recovery payloads and striped recovery scratch using that group. All coexistence
counts: preparing a ciphertext spool does not release the plaintext spool's
charge until the plaintext storage is dropped.

On native targets these are file lengths, including holes. On bare WASM they
are in-memory spool lengths. Neither interpretation counts filesystem block
allocation, allocator overhead or spare `Vec` capacity. The option is therefore
a hard logical-storage quota, not a hard disk-allocation or RAM ceiling.

The default is unlimited. Zero permits empty spools but no growth. Existing
workspace estimates, dictionary selection and compression decisions are
unchanged. Legacy in-memory materialization and codecs do not become bounded
merely because a spool quota is supplied.

### Reservation and ownership

- Configure the quota before dispatching work. Configuring it creates a fresh
  group; cloning the configured `WriterResources` shares its ledger. Simultaneous
  writes using those clones compete for the same capacity. Separately configured
  resources are separate groups, not a machine-wide limit.
- Reserve the complete possible increase in logical length before a backing
  write. The invariant is `live bytes + outstanding growth <= limit`.
- An overwrite within an existing extent has no additional charge. Seeking
  alone does not allocate storage; a later extending write charges the hole too.
- After a short or failed write, release only the unwritten allowance. Existing
  contents remain charged. Arithmetic overflow cannot grant capacity.
- Parking, finishing compression, or returning from a writer does not release
  a live spool. Sources and readers retain ownership and its charge.
- Drop closes storage before releasing its charge. If native removal fails,
  the group conservatively retains the charge for possible orphaned storage.
  External cleanup does not automatically reconcile that debt. Process crashes
  and external changes to spool files are outside the quota's enforcement.

Growth that cannot fit fails immediately with `WriterSpoolLimitExceeded`, using
the `RESOURCE_LIMIT` category and carrying `limit`, `required` and `used` byte
counts. It must survive entry context and recovery I/O adapters. There is no
implicit wait: the writer may need to retain every existing spool until the
current preparation phase finishes, so waiting for that same storage would
deadlock. Concurrent callers are not promised which request wins admission.

Failure may leave a prefix in a caller-provided output sink. The quota does not
change publication guarantees. Empty-file counts and filesystem metadata are
not bounded by a byte quota.

This first control is available through Rust `WriterResources` entry points.
CLI, Python and npm writer-resource options remain separate integration work;
their default writer entry points do not acquire a spool limit automatically.
Rewrite staging and reader scratch created with their own resource policies
remain outside this group.

## Contract for a future managed-memory ceiling

A memory ceiling must cover the sum of active workspace and retained execution
allocations. Adding the current estimates together would not enforce it.

| Storage class | Required accounting |
| --- | --- |
| Active jobs | Input/history, match finders, tokens, candidate/filter copies, and encryption/recovery workspace |
| Retained memory | Packed buffers, bare-WASM spool capacity, prepared headers/services, quick-open records and coordinator state |
| Temporary files | Separate logical-storage ledger; memory and file copies count simultaneously during transfers |
| Output collectors | Writer-owned archive/volume buffer capacity until ownership transfers to the caller |
| Input already owned by the caller or builder | Explicitly outside an execution-memory quota; fresh copies made during execution count |

The guarantee must name managed allocation capacity, excluding allocator
overhead, stacks, external sinks and process-global state. It cannot be called
a total process-memory cap. Every covered growth needs a known charge reserved
before allocation; an allocation path without that accounting cannot silently
run under the hard policy. A platform or execution mode that cannot enforce the
requested policy must refuse it explicitly.

Coordinator admission must reserve both a job's peak working allowance and its
retained-result allowance before dispatch. Workers operate within that allowance.
Unexpected growth requires coordinator approval; workers must not race for the
last shared bytes and make progress dependent on scheduling order. A mutex or
atomic total by itself is not this admission policy.

When a job finishes, transfer the result's charge to its retained owner before
releasing unused workspace. Copies remain separately charged until freed. On
failure, stop dispatching new jobs, join admitted jobs and release charges as
their owners drop. Keep charging successful siblings whose output is still
retained. Cancellation must not reset the ledger while work remains alive.

A hard policy must refuse an individually oversized legacy job. The existing
oversized-member-runs-alone behaviour remains an explicitly estimated-workspace
policy for calls without that hard limit. Neither policy may silently change
archive version, dictionary, filters, encryption or preservation semantics.

## Remaining implementation boundaries

Next, account retained memory by capacity and connect workspace allocation
allowances to coordinator admission. Then integrate output collectors and expose
the enforceable policies consistently through the high-level entry points and
bindings. Reader resource accounting is a separate follow-up.

For changes to planning or execution selection, check byte output, compression
ratio, CPU and peak RAM across stored, compressed, solid, filtered, encrypted and
recovery cases. Storage-ledger changes must additionally test exact limits,
concurrency, retained ownership, partial I/O, cancellation and cleanup failures.
