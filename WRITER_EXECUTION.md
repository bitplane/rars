# RAR5/7 writer execution and allocations

This describes the current RAR5/7 planning and execution model.
`WriterResources::memory_limit` admits estimated active workspace. It is not a
hard ceiling on process RAM, retained archive data or temporary disk use.
`WriterResources::with_max_spool_bytes` separately limits live logical spool
contents. Its scope and the next accounting steps are defined in the
[resource contract](WRITER_RESOURCE_CONTRACT.md).
`with_max_spool_memory_bytes` additionally bounds bare-WASM spool payload
and index capacity using fixed allocations; it excludes other writer memory.

## Entry points and planning

The single-archive and volume entry points in
[`write/mod.rs`](crates/rars/src/rar50/write/mod.rs) validate options, build a
complete `CompressPlan` with the dictionary, method, filter policy and encoder
candidates, and pass it to the engine without further mutation. The dictionary
selection policy fits the default dictionary to content and a streaming baseline
estimate; an explicit dictionary is validated without silently reducing it.
This policy remains separate from execution admission so the same options keep
their dictionary and encoded output.

After source sizes are available, [`plan.rs`](crates/rars/src/rar50/write/plan.rs)
resolves an `ExecutionPlan`: stored, block streaming, or independent members with
individual execution decisions. Each decision selects a mode and estimates its
active workspace. Automatic-filter fallback records the rejected whole-member
estimate and limit, then estimates the base streaming candidate. The scheduler
consumes these decisions and charges without rebuilding the codec plan or
recursively entering compression. Actual filter selection remains data-dependent.

For independent members, dictionary reach uses the largest input. For solid
archives it uses the sum of member sizes. This header dictionary choice is
distinct from the actual buffers and match-finder workspace used during coding.

## Compression modes

[`compress.rs`](crates/rars/src/rar50/write/compress.rs) executes the planned paths:

| Trigger | Execution | Retained data and fallback |
| --- | --- | --- |
| Method zero | Read sources to compute integrity, then reopen them during emission | Source descriptors and integrity values persist. Emission checks the reread bytes against the prepared size and integrity. |
| Non-solid compression with a filter policy other than `None`, or multiple candidates | Admit and encode a whole member | Input, transformed data, competing compressed results and codec workspace can coexist. Successful packed output is copied into a spool. |
| Whole-member estimate exceeds the budget and filter policy is `Auto` | Directly execute block streaming with the base candidate | Drops automatic filter search and candidate trials, keeps the selected dictionary and base encoder options, and attempts streaming admission. That attempt can also fail. |
| Whole-member estimate exceeds the budget with an explicit filter, or with `None` and multiple candidates | Return `MemoryLimitExceeded` | There is no equivalent fallback in this branch. Cancellation and I/O errors are propagated too. |
| Other non-solid compression | Interleave independent members in batches of block jobs | Each job retains input and history; packed results are appended to member spools in order. |
| Solid compression | Read one history chain across members and encode batches of block jobs | Whole-member filter search is not selected. Source order and solid continuation state govern the chain. |

Whole-member batches contain at most the worker count and fit the sum of their
workspace estimates. The coordinator acquires one permit for the complete wave
before dispatch; workers do not wait for workspace. That permit remains live
until the wave joins and its results have been consumed. Members requiring streaming fallback
run outside those worker batches because fallback can itself schedule parallel
work. Streaming batch capacity is the smaller of the worker count and the
budget divided by the per-job estimate. A job that cannot fit is refused. Empty
whole members have no codec workspace charge.

Both whole-member and block waves allocate charged coordinator slots before
worker dispatch. A sibling failure stops queued jobs, signals running codecs
through progress cancellation, joins admitted work and then drops retained
results. The reported error prefers the original failure over consequential
cancellation. Batch cancellation does not mutate the caller's reusable token.
These are scheduling guarantees; codec allocations still use workspace estimates.

Store fallback is a separate decision from execution fallback: an independent
member may use its original bytes when compression does not pay. An explicit
filter is retained even when its output is larger. Solid history constrains
which members can be stored; it is not safe to change these decisions solely to
meet a memory target.

## Workspace estimates

`streaming_lz_workspace` currently estimates a job using the dictionary rounded
up to a power of two, the maximum LZ block size and whether any candidate uses
optimal parsing (automatic fallback considers only the base candidate):

- Non-optimal: `13 * rounded_dictionary + 64 * block_size + 3 MiB`.
- Optimal: `17 * rounded_dictionary + 160 * block_size + 3 MiB`.

These charges cover the anticipated input/history/search buffers, finder links,
token streams and parse workspace. They are estimates, not allocator tracking.
The RAR5 parser's match finders, match cache, parse arrays and token owners now
support fallible internal allocation allowances, but production codec entry
points still use unlimited handles. Framing/filter/payload migration and
coordinator integration must precede an enforceable writer policy.
`whole_member_workspace` adds four times the input size and a codec workspace
estimate with reach and block size fitted to that input.

RAR5/7 admission refuses an estimate larger than the configured limit. The
legacy writer policy is different: an oversized member reserves the entire
budget and runs alone. Neither policy constitutes a total RAM quota.

## Allocation lifetimes outside active compression

Rewrite session sources are decoded on demand in one archive-order traversal.
Only verified payloads become readable. Compression releases a session source
when its packed result will be emitted; stored fallback retains it for the
checked emission reread. Legacy materialization releases each staged source after
loading it but retains the resulting payload in RAM. The staging disk quota
counts live plaintext payloads separately from these writer allocations.


| Allocation | Lifetime and accounting |
| --- | --- |
| Caller input buffers and queued source descriptors | Owned by the caller or builder; not charged as compression workspace. |
| Packed member spools | Retained through preparation and emission. Native builds use temporary files; parked spools release file handles. An optional shared spool quota counts live logical file lengths. |
| Bare-WASM spools | Default cursors retain packed bytes beyond active-job permits. The logical spool quota bounds lengths. An optional memory quota selects fixed blocks and charges payload and index capacity, including padding and index replacement peaks; other RAM remains separate. |
| Prepared headers and member/service records | Final RAR5/7 member and service images retained for single-archive output have an optional shared `with_max_prepared_header_bytes` capacity quota. The broader `with_max_preparation_bytes` engine quota also covers variable-length record buffers, transient main/end/recovery/volume headers, descriptor arrays and boxed preparation state. Fixed-size framing uses stack scratch. RAR5/7 service payloads borrow writer input; preparation makes no additional plaintext or ciphertext payload copy. Upstream input construction may still allocate. |
| Quick-open payload | Built in a spool from borrowed cached headers, with stack framing and incremental checksums. Logical spool limits cover it on all targets; the memory spool quota also covers its payload and index capacity on bare WASM. |
| Encryption | Single-archive member and service data is encrypted during emission in chunks. Volume preparation writes ciphertext into an additional spool before splitting. Keys, cipher state, final encrypted header images and the bounded encryption buffer also allocate storage. Header encryption fills one final image and encrypts it in place. |
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

## Limits and future accounting

An aggregate managed-memory ceiling still needs accounting for active workspace,
retained payload capacity, headers/services, recovery scratch and output
collectors, with explicit boundaries for caller buffers and disk. Renaming the
current workspace limit would not supply that accounting.
The planning model does not change native spool or bare-WASM retention lifetimes.

Planning changes must preserve output bytes and external-decoder compatibility,
and compare compression ratio, CPU time and peak RAM for stored, independent,
solid, filtered, encrypted and recovery output. Cover default and explicit
dictionaries, budgets around admission boundaries, automatic fallback and
explicit-filter refusal.
