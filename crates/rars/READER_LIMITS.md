# Total logical output quota

Status: implemented alongside declared RAR5 dictionary admission and the all-family
per-member output ceiling. This documents the contract and its regression coverage.
Parallel reservation scheduling remains future work. These features are partial
progress on #42, not completion of the whole reader-resource issue.

## Public contract

`ArchiveReadOptions::max_total_output_bytes: Option<u64>` and
`with_max_total_output_bytes(u64)` configure an inclusive ceiling on logical member
output across **one extraction invocation**, including the entire volume set
passed to that invocation. Reusing options for another extraction starts a fresh
counter. A caller extracting nested archives in separate calls must manage its
own overall budget; this option does not create a process-wide limit.

`None` preserves current extraction and scheduling. Zero permits empty members
and metadata-only directories/redirections. Apply the option consistently to
common and family-specific option-bearing extraction APIs, including RAR5
redirection callbacks and all volume paths. Preserve the existing treatment of
unsupported entry types; a zero quota does not enable a new redirection or
directory-payload capability.

Parsing does not retain this policy. Password-only helpers, including current
`read_member`, `read_member_at`, `test`, and low-level member `write_to` methods,
continue using defaults. Direct codec calls and internal comment/recovery
decoding remain outside this scope. New helper variants and CLI/Python/npm option
exposure are separate API work. Callers can already discard callback output to
test an archive through the option-bearing extraction API.

## What is counted

Count bytes accepted at the member's logical output boundary: the guarded caller
writer in streaming extraction, or a guarded final result collector if parallel
extraction is subsequently supported under this policy. A short write charges
only the returned count. Failed writes charge no additional bytes. A discarded
member still counts because its sink accepts bytes, whether it is needed for
solid history or simply unwanted by the caller.

Count each logical member once. Split fragments share one member guard and the
operation counter survives across volumes. Packed bytes, encryption padding,
history copies, filter retries and checksum rereads do not add charges. Replaying
an already charged result to its destination must not charge it again.

This is a logical-output quota, **not a counter of every byte produced internally
by a decoder**. For example, RAR5 buffered decoding and integrity verification
precede the final `write_all`; a failed candidate can consume CPU and memory
without reaching the guard. Declared-size admission prevents starting a member
whose known output does not fit, but this feature does not establish a hard CPU
or RAM bound for malformed input. Keep dictionary/workspace admission, parser
limits and cancellation separate. Do not advertise it as sufficient by itself
for bounded extraction fuzzing.

## Admission and runtime enforcement

Create one private operation budget at each family extraction entry point, and
thread it through ordinary and completed-split extraction. Extend the existing
[output guard](src/output_limit.rs), rather than duplicating quota/error handling
inside each codec. Keep `ArchiveReadOptions` a configuration value, not shared
mutable accounting state.

Before output opens or payload decoding starts:

1. Preserve existing structural and dictionary checks. Determine the logical
   size for a non-directory, non-redirection member.
2. If either output ceiling is set, use RAR5 `known_unpacked_size()`. Reject an
   unknown-size logical member with the existing contextual unsupported-feature
   error. Do not trust its numeric placeholder. A configured zero is still a
   configured ceiling. No limits means existing unknown-size behaviour remains.
3. Check the per-member ceiling first, then check `declared_size > limit - used`
   for the total ceiling. Do not sum unchecked integers. Refuse before `open`,
   decryption, decoder dispatch or output allocation on that member's path.
4. For a completed split member, use its final logical size after structural
   validation, before opening its output or constructing payload decryption.
   Early fragment sizes/placeholders are not separately reserved or charged.

Header parsing, validation and collection of split references can already have
occurred; this is not a parser or packed-input admission limit.

Admission does not charge the declaration. Run the member with the existing
per-member guard plus the remaining total allowance, charging actual accepted
bytes. On successful completion, that actual count is the starting point for
the next member. Even when a declaration overstates the eventual output,
admission must conservatively require it to fit. Do not relax existing size or
integrity validation to accommodate a quota.

At runtime, check the entire offered chunk before forwarding it. Rejecting a
chunk can leave some allowance unused; there is no guarantee of filling the
quota. If both member and total checks reject the same chunk, report the member
error first. Keep refusal latched out of band so legacy password/checksum/I/O
adapters cannot replace it, as the member guard does today. Preserve unrelated
sink or decode errors when no quota refusal has occurred.

Never refund bytes already accepted, even if later integrity verification or
publication fails. Abort that extraction call; do not continue after an error
or expose a resumable budget in this increment. Earlier output and a failing
member's prefix may remain. A new invocation has a new budget and may decode the
same bytes again.

## Parallel entry points: deliberately staged implementation

**First implementation: use the sequential extractor whenever the total quota
is configured**, including `Some(u64::MAX)`. Apply the fallback in both typed
parallel entry points, so direct family callers cannot bypass it. RAR1.3/1.4 and
volume extraction already use sequential execution. Solid archives already
require sequential decoding.

This gives archive-order admission, deterministic quota attribution and simple
per-operation ownership without locks or a new worker protocol. No total quota
means no scheduling change and no additional total-counter work. Document the
tradeoff publicly: opting in can reduce throughput for independent compressed
members. The parallel API already falls back for several archive properties,
but this new condition must be explicit and tested.

Evidence for staging this:

- [RAR5](src/rar50/extract.rs) builds bounded batches, but currently checks member
  admission **inside** each worker. A total check needs coordination before work
  is launched.
- [RAR1.5–4.0](src/rar15_40.rs) collects all headers and all decoded results. Its
  result-retention bound needs a separate focused change.
- [The parallel helper](src/parallel.rs) collects a `Result<Vec<_>>`. One error
  can discard results while other workers have already performed work. Charging
  only published or successfully returned batches would undercount it.

A future parallel implementation must reserve allowance in archive order before
dispatch, maintain `charged + reserved <= limit`, and prevent workers consuming
one another's reservations. Actual accepted bytes convert reservations into
charges; only unconsumed reservations may be released. Successful decoded output
still counts if a later sink fails or a sibling's error discards the batch.
Running workers retain bounded allowances after the first failure; stop launching
new work and join them before returning. RAII cleanup alone is not enough if it
refunds output already produced.

Declared sizes are not trusted runtime bounds. A member that needs more than its
reservation requires an explicit coordinator protocol or a deliberately stricter
policy for malformed sizes; workers must not race to claim spare bytes. Do not
introduce that complexity in this increment, silently reject legitimate output
within the sequential policy's allowance, or call a shared atomic counter alone
pre-decode admission. Parallel publication/error ordering also needs its own
tests before enabling this route.

## Errors

Add `TotalOutputLimitExceeded { limit: u64, required: u64, used: u64 }`, classified
as `ErrorKind::ResourceLimit`, with the offending member's entry context and the
operation `limiting output`.

- `limit` is the configured total.
- `used` is total accepted output immediately before the refused admission/write.
- `required` is the total that would be needed: `used + declared_size` at
  admission, or `used + offered_chunk_len` at runtime. It is a minimum attempted
  total, not the current member's size or a promised final archive size.

Use subtraction to decide refusal. Saturate only the diagnostic `required` sum
at `u64::MAX`; document that it is a lower bound if the sum cannot be represented.
For example, after 60 accepted bytes, a 50-byte member under a 100-byte total
reports `{ limit: 100, used: 60, required: 110 }` before its output opens.

Retain generic Python/CLI resource classification. Add the variant to exhaustive
core/error-adapter matches, including legacy encrypted error preservation. WASM
details carry `limitBytes`, `requiredBytes` and `usedBytes` as decimal strings,
following existing byte-count transport. This does not expose a new binding knob.

## Regression coverage and validation

Use [the output-limit tests](tests/reader_output_limit.rs) and real archive
builders/fixtures; keep accounting arithmetic and short-write cases as small
guard unit tests. Cover:

- Two individually admissible members whose sum is exactly the total, and one
  byte over it. The failing member never opens; earlier accepted output remains.
  For example, two 32-byte members under member=32 succeed with total=64 and
  reject the second with total=63. Reusing options starts a fresh operation.
- `None`, zero, empty archives/members, directories/redirections, and totals
  near `u64::MAX`, including arithmetic overflow and error-field meanings.
- Stored and compressed legacy/RAR5/7 members, solid discarded history,
  buffered/streaming RAR5, and typed as well as common extraction entry points.
- Ordinary members and encrypted split logical members in the same volume set:
  no reset on fragment, volume or split completion. Early unknown placeholders
  with a known final size work; an unknown logical size is refused with a total
  ceiling alone. Default unknown-size behaviour remains characterized.
- Understated stored sizes reaching the runtime guard after earlier output;
  partial writes, sticky refusal, genuine sink errors and integrity-error
  precedence. Accepted prefixes remain charged after failure in guard tests.
- Both ceilings together: member error precedence at admission and on a chunk
  rejected by both; total-only failure after previous members have consumed it.
- Both typed parallel entry points with a total ceiling exercise archive-order
  sequential fallback. Without a total ceiling, existing parallel regressions
  still pass. Test actual callback/error behaviour, not just a fallback boolean.
- Filtered fixture output remains byte-identical when admitted; retries do not
  double-charge and the buffered-decode-limit error remains distinct. A buffer
  failure before final output does not invent accepted bytes.
- Structured error classification, entry/volume context and exact WASM byte-count
  serialization; preserve existing error-transport coverage.

Run focused core/integration tests, workspace formatting and strict Clippy, and
bare-WASM compilation. Broaden regression checks when results warrant it. Reader
cancellation tests belong to its later implementation, not an acceptance gate for
a capability that does not yet exist. No compression-format or writer change is
part of this implementation.
