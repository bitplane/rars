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
The image-only quota remains independently available. The broader preparation
policy below also accounts for scratch records and transient header images.

## Available quota: RAR5/7 engine preparation memory

`WriterResources::with_max_preparation_bytes(limit)` bounds the live allocation
capacity of the RAR5/7 engine's header and preparation owners. Clones share one
ledger; configuring the option creates a fresh group. The default is unlimited.
This is one preparation policy covering both retained and temporary owners,
not a separate user setting for each internal buffer type.

| Allocation or path | Treatment |
| --- | --- |
| Header scratch | Filename/type-specific fields, extras, mapped link records, archive metadata, layout iterations and recovery subdata use charged byte buffers. Fixed framing and extended timestamp records use stack storage. |
| Final header images | Member/service/comment/quick-open images, main/end/encryption headers, recovery headers and volume fragment images reserve capacity before allocation. IV and cipher padding count. The image-only quota can also apply independently. |
| Retained descriptors | Source arrays, prepared block arrays and volume-member arrays reserve their complete backing allocation before filling. Service counts are included in block admission. A consuming iterator retains the array's charge until its backing allocation is freed. |
| Boxed preparation state | Nested payload owners and volume integrity state carry their own charges. Inline state in descriptor arrays is included in the array allocation. |
| Borrowed payload and names | Plain service payloads and volume filenames borrow engine input. Source handles clone existing shared ownership rather than cloning payloads. Mapped link lengths are measured without allocating decoded names. |
| Legacy writers | RAR1.3–4.0 header/comment construction remains intertwined with unaccounted legacy materialization. Supplying this hard policy is explicitly refused, including the high-level builder fallback, before emission. Calls without this policy retain existing legacy support. |
| Compression coordinator descriptors | Integrity arrays, per-member execution plans, stream/history descriptors, block/job boundaries, worker slots and retained result arrays use the preparation ledger. Boundary growth reserves old plus replacement capacity. Worker slots, boundary images and coordinator result arrays are admitted before dispatch. The arrays retain their charges through joining and consumption. |
| Active workspace and payload buffers | Input/history and pushback bytes, codec/filter allocations (including codec-owned packed arrays), candidate settings, KDF/encryption/recovery workspace and source-reader internals remain outside the preparation quota. Coordinator descriptor admission does not bound the buffers those descriptors point to. |
| Adapters, sinks and diagnostics | Caller/adapter-created `ArchiveEntry` inputs, high-level input conversion, external source/sink callbacks, output collectors, error/context allocations and allocator overhead are outside this engine quota. High-level policy integration and output ownership remain later passes. Recovery repair APIs without `WriterResources` are a separate workflow. |

Growing a charged byte buffer reserves the old allocation plus the replacement
before allocating or copying. Spare capacity remains charged. Refused growth
leaves existing contents and capacity unchanged. Fixed-capacity descriptor
arrays cannot silently grow beyond their admitted count. Dynamic block-boundary
arrays use explicit growth with replacement-peak admission. Each owner frees its
storage before releasing its charge, including error, cancellation and unwind
paths. Charges follow the owner through preparation and emission. There is no
waiting for retained storage that the writer itself needs to finish.

Failures return `WriterPreparationLimitExceeded` in the `RESOURCE_LIMIT`
category with `limit`, `required` and `used` counts. A refusal before emission
leaves the sink untouched; a later refusal in main, recovery or volume framing
can leave a prefix. This does not introduce transactional publication. Zero
allows empty containers but refuses the first nonempty covered allocation.

This scope covers the header/preparation pass for the RAR5/7 engine, including
its supported volume and recovery paths. It is not yet an aggregate managed
writer-memory ceiling. The inventory above names the exclusions and explicit
legacy refusal rather than treating them as covered by this quota.

## Current coordinator admission

RAR5/7 whole-member waves reserve the sum of their estimated workspaces on the
coordinator before dispatch. Waves stop at the worker count, the configured
workspace limit or a streaming-fallback boundary. An oversized first member
fails admission before its source is opened. Block waves also reserve their
workspace before constructing and dispatching jobs. The reservation remains
live while workers join and their outputs are appended to spools or transferred
to the retained member array.

Preallocated worker slots retain successful siblings until the wave joins.
A failure stops queued callbacks and running codecs observe batch-local
cancellation. Error selection prefers a source/codec failure over the resulting
cancellation. Returning joins admitted callbacks before releasing their owners;
reusing the resources after an ordinary failure does not inherit cancellation.

These reservations still use workspace estimates. Raw and filtered members,
adjacent streaming blocks and persistent codec history have an internal
fallible allowance path covering history-window copies, chain/tree
match-finder tables, collected match runs and offsets, parse arrays, candidate
reaches, competing token buffers, Huffman construction and code tables, table
serialization, bit output, block framing and retained outputs. Filter copies,
delta scratch, normalized filter specifications and per-block descriptors use
the same allowance. Consuming a descriptor container keeps its allocation
charged until the iterator drops; extracted output owners keep their own charges.
History growth is admitted before mutation and copies only the retained tail.
An encode refusal or callback failure preserves the previous persistent history.
The production streaming writer carries these owners through admitted source
chunks, block lookahead, assembled jobs and rolling dictionaries for both
independent and solid members. A job takes ownership of its first block instead
of copying it. Packed block owners remain charged through parallel result slots
and ordered spool writes; source failures and cancellation release the wave.
Whole-member source loading and automatic filter search use the same internal
allowance through the winning payload's spool write. Screen baselines, retained
measurements, transformed samples, scanner clusters and ranges, table grafts,
finalist descriptors and competing encoder settings keep their allocation owners.
Scanner ranking and table ordering use explicit tie-breaks to preserve stable
selection without hidden sorting workspace. The progress estimate counts filter
kinds without allocating a candidate list. Legacy search uses an unlimited
adapter; this does not add a hard policy to older-format encoding.
Coordinator descriptors still use preparation accounting and spools retain their
separate storage policy. This does not yet combine those ledgers.
Covered owners reserve before growth, include replacement peaks and retain
charges through moves and token selection. Unlimited and bounded buffers use
separate compile-time policies; the unlimited owner retains Vec's layout.
Allocation-failure details are boxed to keep successful codec Results compact.
A refused parse is abandoned; its partially updated finder is not resumed with
extra bytes. An allowance cannot borrow capacity from another worker.

This is migration infrastructure, not an available writer limit. Production
codec entry points currently use unlimited handles; bounded construction is
internal test coverage, including its refusal diagnostics. The codec reader
adapter also has bounded read-ahead and input-buffer tests; it is not the
production writer's source-loading path. Encryption/KDF and recovery workspace
still need migration. Only after those paths are covered can the coordinator
supply reserved allowances and connect them to preparation and spool memory. There is no public worker allowance or extension API yet.
The workspace/admission pass remains open until those guarantees are enforceable.

The optimal parser keeps match-pricing helpers available for inlining across
generic codegen units. The numeric-sample workload in
`cargo bench -p rars --bench parallel -- rar50_candidate_pricing` exercises
the per-candidate pricing cost during filter search; keep it in performance
comparisons when changing allocation owners or parser boundaries.

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

## Remaining implementation passes

Complete these as outcome-based passes, including implementation and validation.
A pass is not complete merely because one buffer type has been converted.
The existing per-class quotas are building blocks for the aggregate policy.

| Pass | Scope | Completion evidence |
| --- | --- | --- |
| 2. Workspace and coordinator admission | Enforceable codec/filter/encryption/recovery workspace and retained payload allowances, joined to coordinator admission. | Coordinator admission reserves peak workspace and retained-result allowances before dispatch. Workers have enforceable allowances and an extension policy. No race for shared spare bytes determines success. Oversized jobs, sibling failure, cancellation and retained results are tested. |
| 3. Output ownership | Writer-owned archive/volume collectors, staging, transfers and copies. | Capacity remains charged until ownership transfers or storage is freed; copies and replacement peaks count simultaneously. Active and retained allocations compose under one managed-memory ledger. Caller-owned input and external sink exclusions are explicit. |
| 4. Public integration and validation | High-level Rust, CLI, Python and npm controls, errors and documentation. | One coherent hard-policy contract across entry points, with explicit refusal of unsupported modes; byte compatibility, ratio, CPU and peak-memory checks cover the writer matrix. Existing estimated-workspace behaviour remains available separately. |

The preparation policy and its inventory are defined above. Compression
coordinator records belong in pass 2 because their capacity and lifetime depend
on job admission. Avoid creating a public setting for every internal buffer class; consolidate the
policy as the common accounting and ownership model becomes enforceable.

Reader resource accounting and reader API extensions remain separate follow-ups.
The writer work is complete only when the covered active and retained allocation
classes compose under the aggregate contract above, not when their independent
limits merely exist.

For changes to planning or execution selection, check byte output, compression
ratio, CPU and peak RAM across stored, compressed, solid, filtered, encrypted and
recovery cases. Storage-ledger changes must additionally test exact limits,
concurrency, retained ownership, partial I/O, cancellation and cleanup failures.
