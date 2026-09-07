# RAR5/7 writer execution and allocations

This describes the current implementation, before planning is consolidated.
`WriterResources::memory_limit` admits estimated active workspace. It is not a
hard ceiling on process RAM, retained archive data or temporary disk use.

## Entry points and planning

The single-archive and volume entry points in
[`write/mod.rs`](crates/rars/src/rar50/write/mod.rs) validate options, build a
`CompressPlan`, then attach the filter policy and encoder candidates inside an
`EnginePlan`. `streaming_compress_plan` initially chooses the dictionary and
estimates streaming workspace before the eventual execution mode is known.
The default dictionary is fitted to content and reduced to fit that estimate;
an explicit dictionary is validated without silently reducing it.

For independent members, dictionary reach uses the largest input. For solid
archives it uses the sum of member sizes. This header dictionary choice is
distinct from the actual buffers and match-finder workspace used during coding.

## Compression modes

[`compress.rs`](crates/rars/src/rar50/write/compress.rs) chooses among these paths:

| Trigger | Execution | Retained data and fallback |
| --- | --- | --- |
| Method zero | Read sources to compute integrity, then reopen them during emission | Source descriptors and integrity values persist. Emission checks the reread bytes against the prepared size and integrity. |
| Non-solid compression with a filter policy other than `None`, or multiple candidates | Admit and encode a whole member | Input, transformed data, competing compressed results and codec workspace can coexist. Successful packed output is copied into a spool. |
| Whole-member estimate exceeds the budget and filter policy is `Auto` | Recursively call compression with `None` and one candidate | Drops automatic filter search and candidate trials, keeps the selected dictionary and base encoder options, and attempts streaming admission. That attempt can also fail. |
| Whole-member admission fails with an explicit filter, or with `None` and multiple candidates | Return `MemoryLimitExceeded` | There is no equivalent fallback in this branch. Cancellation and I/O errors are propagated too. |
| Other non-solid compression | Interleave independent members in batches of block jobs | Each job retains input and history; packed results are appended to member spools in order. |
| Solid compression | Read one history chain across members and encode batches of block jobs | Whole-member filter search is not selected. Source order and solid continuation state govern the chain. |

Whole-member batches contain at most the worker count. Workers acquire their
workspace permits before loading input. Members requiring streaming fallback
run outside those worker batches because fallback can itself schedule parallel
work. Streaming batch capacity is the smaller of the worker count and the
budget divided by the per-job estimate. A job that cannot fit is refused.

Store fallback is a separate decision from execution fallback: an independent
member may use its original bytes when compression does not pay. An explicit
filter is retained even when its output is larger. Solid history constrains
which members can be stored; it is not safe to change these decisions solely to
meet a memory target.

## Workspace estimates

`streaming_lz_workspace` currently estimates a job using the dictionary rounded
up to a power of two, the maximum LZ block size and whether any candidate uses
optimal parsing:

- Non-optimal: `13 * rounded_dictionary + 64 * block_size + 3 MiB`.
- Optimal: `17 * rounded_dictionary + 160 * block_size + 3 MiB`.

These charges cover the anticipated input/history/search buffers, finder links,
token streams and parse workspace. They are estimates, not allocator tracking.
`whole_member_workspace` adds four times the input size and a codec workspace
estimate with reach and block size fitted to that input.

RAR5/7 admission refuses an estimate larger than the configured limit. The
legacy writer policy is different: an oversized member reserves the entire
budget and runs alone. Neither policy constitutes a total RAM quota.

## Allocation lifetimes outside active compression

| Allocation | Lifetime and accounting |
| --- | --- |
| Caller input buffers and queued source descriptors | Owned by the caller or builder; not charged as compression workspace. |
| Packed member spools | Retained through preparation and emission. Native builds use temporary files; parked spools release file handles. Disk usage has no aggregate quota here. |
| Bare-WASM spools | In-memory cursors retain packed bytes beyond active-job permits. This can grow with the archive. |
| Prepared headers, member/service records and inline payloads | Retained for archive construction. Comment and service data can be allocated in memory. |
| Quick-open payload | Built in a `Vec` from cached headers, separately from codec workspace. Its size grows with the indexed headers. |
| Encryption | Single-archive member data is encrypted during emission in chunks. Volume preparation writes ciphertext into an additional spool before splitting. Keys, cipher state, padded headers and inline encrypted services also allocate storage. |
| Recovery | Emitted prefix bytes are mirrored to a spool. Recovery chooses resident or striped workspace and acquires a permit; striped mode adds scratch storage, and the recovery payload has its own spool. |
| Output collectors | `to_bytes` retains the final archive. `CollectedVolumes` retains all volume buffers; a caller-provided `VolumeSink` can release parts independently. |
| Volume body | Each part's body is spooled before its layout and optional recovery are emitted. This storage is separate from packed-member spools. |

The engine prepares compressed members before emitting the archive. Native
output can therefore stream without holding all packed bytes in RAM, but that
does not mean it consumes and publishes each member immediately. Volume output
also retains prepared member payloads before splitting them.

Layout resolution computes offsets using prepared block lengths and a fixed
point over variable-length main-header fields. It does not repeatedly emit the
archive or rebuild recovery data. Layout arithmetic overflow is an invalid size;
failure to resolve the layout is a `WRITE_FAILED` construction error.

Direct output sinks may contain a prefix on failure. `Builder::write_to_path`
publishes a single archive only after successful writing and syncing. Multiple
volume files do not have a collective atomic-publication guarantee.

## Next planning change

Choose whole-member versus streaming execution before estimating its workspace,
then construct one final plan containing the dictionary, filter policy, encoder
candidates and an explicit fallback mode and reason. Keep filter selection
data-dependent. Replace recursive fallback coordination without changing the
conditions that currently select filters, store fallback or solid continuation.

Any hard quota proposal must separately account for active workspace, retained
payloads, caller buffers, headers/services, recovery scratch, output collectors
and disk. Renaming the current workspace limit would not supply that accounting.

Before accepting a planning change, compare output bytes and external-decoder
compatibility, compression ratio, CPU time and peak RAM for stored, independent,
solid, filtered, encrypted and recovery output. Cover default and explicit
dictionaries, budgets around admission boundaries, automatic fallback and
explicit-filter refusal. Include native and bare-WASM retention behavior.
