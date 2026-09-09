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
recovery payloads, quick-open indexes and striped recovery scratch using that
group. All coexistence counts: preparing a ciphertext spool does not release the plaintext spool's
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

These controls are available through Rust `WriterResources` entry points.
CLI, Python and npm writer-resource options remain separate integration work;
their default writer entry points do not acquire a spool limit automatically.
Rewrite staging and reader scratch created with their own resource policies
remain outside this group.

## Available quota: memory-spool allocation capacity

`WriterResources::with_max_spool_memory_bytes(limit)` separately caps the shared
payload and index allocation capacity of bare-WASM spools. Native file-backed
spools have no charge against this memory quota. Its default is unlimited and
retains the existing `Cursor<Vec<u8>>` backend.

When configured, a memory spool uses fixed 4096-byte boxed payload blocks and
an index with a power-of-two slot count. The index charges every slot, including
unused ones, at `size_of::<Option<Box<[u8; 4096]>>>()` bytes per slot (4 on bare
WASM). A one-byte spool therefore consumes 4100 bytes on bare WASM. Padding in
payload blocks and zero-filled seek holes also count.

Before growth, admission reserves the resulting payload capacity and index,
plus the old index if it needs replacement. The old index is freed before its
charge is released. Payloads stay in place during index replacement. This
conservative growth reservation can exceed the final retained capacity, so a
limit that fits the result alone can still refuse growth.

Allocator overhead, inline spool state, codec workspace, services, headers and
output collectors are outside this quota. It bounds spool heap allocation
capacity, not aggregate managed memory or process RAM.

Resource clones share the capacity ledger. Parking, rewinding and overwriting
do not free blocks or their charge. Payload blocks and indexes are freed before
their charge is released on drop. A failed capacity admission leaves existing
contents and capacity unchanged. Zero allows empty memory spools only. An insufficient limit
returns `WriterSpoolMemoryLimitExceeded` with `RESOURCE_LIMIT` and the same
`limit`, `required` and `used` fields as the logical-storage error.

Logical length and payload capacity remain independent limits. If logical
growth is admitted but capacity growth is refused, the outer spool releases
the unwritten logical reservation. Neither limit changes compression settings.
The block representation is selected only when a memory quota is configured.
Quick-open indexes are prepared in spools without whole-index or per-header
payload copies. Their preparation can refuse a storage quota before emission;
native output with quick-open enabled now needs temporary spool storage.

RAR5/7 prepared services borrow input payloads instead of retaining additional
plaintext or ciphertext copies. Encryption uses the existing chunked emission
workspace. This removes a retained allocation class; it does not bound upstream
input construction, prepared headers, key state or aggregate execution memory.

## Available quota: retained prepared header images

`WriterResources::with_max_prepared_header_bytes(limit)` caps the shared final
member and service header images retained by RAR5/7 single-archive preparation,
including comment and quick-open service headers. Both native and bare-WASM
writers enforce it. The default is unlimited; zero refuses any nonempty image.

Serialization computes the exact image length and reserves it before allocating
the image. Encrypted headers include the 16-byte IV and cipher padding in this
charge and encrypt in place. Images are immutable, so their allocation capacity
cannot grow after admission. Clones share the ledger; configuring a quota makes
a fresh group. Images retain charges through preparation and emission and free
their allocation before releasing the charge. Failure and unwinding follow the
same ownership rule. Admission fails immediately with
`WriterPreparedHeaderLimitExceeded` (`RESOURCE_LIMIT`, with `limit`, `required`
and `used` byte counts).

This is a quota for a specific retained allocation class, not all header memory.
Variable-length serializer scratch (including type-specific and extra records),
main/end and recovery headers, volume fragment headers, legacy headers, block descriptors,
key state and allocator overhead remain outside it. The option imposes no limit
on those other paths. It is independent of spool and estimated workspace quotas.

Fixed-size framing and common hash, encryption, timestamp and locator records
use bounded stack scratch. Extra-record payloads append directly to the output
without an intermediate body copy; plain header framing likewise fills its
final image directly. Filename and archive-metadata records allocate their exact
final size without intermediate payload copies. Plain, encrypted and prepared
headers share framing logic; encrypted headers compute their final layout and
encrypt in place without a separate plaintext or padded ciphertext buffer.
Only prepared images currently carry a quota charge. Variable-length record
allocations and the other output images still need separate accounting.

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

Next, extend capacity accounting to other retained allocations and connect
workspace allocation allowances to coordinator admission. Then
integrate output collectors and expose the enforceable policies consistently
through the high-level entry points and bindings. Reader resource accounting is
a separate follow-up.

For changes to planning or execution selection, check byte output, compression
ratio, CPU and peak RAM across stored, compressed, solid, filtered, encrypted and
recovery cases. Storage-ledger changes must additionally test exact limits,
concurrency, retained ownership, partial I/O, cancellation and cleanup failures.
