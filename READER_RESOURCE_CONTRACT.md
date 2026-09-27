# Reader workspace limits

`ArchiveReadOptions::with_max_reader_workspace_bytes(bytes)` sets an inclusive
capacity ceiling for one extraction call or options-aware archive-comment call.
The default is unlimited. Supply the policy again for subsequent calls; parsing
does not retain it. One extraction budget covers all members, solid predecessors
and volume fragments. Selected reads and archive testing use the same extraction
paths. A comment call starts a separate budget.

This is a limit on owned reader workspace allocations, not process RAM or logical
output. Use `max_member_output_bytes` and `max_total_output_bytes` to limit decoded
output separately. A declared RAR5 dictionary ceiling remains an independent
format admission check.

| Charged workspace | Outside this ceiling |
| --- | --- |
| Decoder dictionaries, history, Huffman tables and PPMd model containers | Parsed archive headers, metadata and source storage |
| Packed-input buffers and heap cipher state/staging | Caller inputs, output writers and collected final output |
| Checkpoints, VM programs/memory/results, filter records and scratch filter buffers | Allocator bookkeeping, thread stacks, executor and fixed operation control storage |
| Split-fragment descriptors and source-cursor arrays | Scratch disk bytes, which have their own policy |
| Parallel job slots, reservations and queued decoded payloads | Direct codec calls, password-only default wrappers and recovery/repair helpers |

Capacity counts even when a buffer is empty or retains capacity after truncation.
Admission precedes allocation. Growing a container charges its old allocation and
replacement while both exist; it releases the old charge after replacement. A
small logical member can therefore need more workspace than its decoded length.
Streaming reduces retained output but still needs input, codec state, history,
filter workspace and sometimes a checkpoint. Stored sequential extraction avoids
creating an unused decoder dictionary.

## Parallel admission and lifetime

Independent RAR1.5–4.x and RAR5/7 members can run in parallel. The coordinator
allocates charged job slots and reserves each worker's allowance before dispatch.
Declared packed/unpacked lengths and codec startup hints select the batch width;
they are scheduling estimates, not trusted upper bounds on physical allocations.
The remaining capacity is divided among admitted workers before they start.
Workers have fixed allowances and cannot extend them or compete for sibling spare
capacity. Understated lengths or unexpectedly large model/filter growth produce a
typed workspace refusal. Increase the ceiling or select sequential extraction if
one job needs a larger share. There is no automatic retry after publication begins.

Charged plus reserved bytes never exceed the call's ceiling. After decoding, only
unused reservation capacity returns immediately. Queued payloads retain their
charges until publication or cleanup. Publication happens in archive order after
all callbacks in the batch have joined. A batch failure discards successful
siblings; a sink failure drops unpublished results. Both retain charges until the
associated storage is freed. No later batch starts after either failure; callbacks
that have not started decoding skip it after observing a sibling failure.

Existing sequential fallbacks remain: solid/split archives, configured total
logical output ceilings, scratch-backed decoding and RAR5 streaming-sized members.
RAR1.3/1.4 extraction is sequential. These fallbacks use the same aggregate ledger.

## Refusals and publication

Workspace refusals have `ErrorKind::ResourceLimit` and a codec
`WorkspaceLimitExceeded` root cause with `limit`, `required` and `used` values.
For a parallel worker, `limit` is its local allowance. Refusals remain resource
errors through encrypted decoding, I/O adapters and split-volume diagnostics.
Cancellation and source/sink failures retain their own meaning.

A failure may leave earlier members and a streaming member's prefix in the output.
This policy does not provide verified publication for every extraction path.
Scratch-backed decoding retains its existing verification-before-publication
behavior and separate disk/filter ceilings; its in-memory payload workspace also
counts against the aggregate reader limit.
