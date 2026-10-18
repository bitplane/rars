# Experimental hybrid RAR encoder

The hybrid encoder is an opt-in experiment that writes ordinary RAR5 and RAR7
archives. Existing writer defaults and explicitly requested dictionaries stay
unchanged. This implementation does not establish performance parity with RAR.

```sh
rars a --experimental-hybrid desktop --analyze-relationships \
  --optimize-member-order output.rar input-directory
```

Use `--experimental-hybrid server` for the larger resource envelope. Explicit
`--memory-limit`, `--max-memory`, and `--dict-size` requests remain authoritative.
`--hybrid-dictionary-ceiling` bounds automatic selection without requesting an
exact size. It also caps the existing automatic choice when adaptive selection
is off. Archive-wide analysis and reordering require their separate flags.

Rust callers can pass `HybridOptions` through
`rar50::WriterOptions::with_hybrid`, or
`Builder::experimental_hybrid`. A default `HybridOptions` preserves member order
and performs no archive-wide relationship analysis.

## Capture and complete repeat indexing

Each original source is opened once. The reader captures its bytes in private
temporary storage and extends a generalized suffix tree as data arrives.
File terminators prevent false matches spanning unrelated members; ordinary
read boundaries introduce no terminators. Edges refer to captured bytes.

The tree represents all exact repeated substrings, including overlaps and
matches longer than a RAR token. It does not enumerate every occurrence pair.
`RepeatIndex::occurrences` and `for_each_occurrence` query complete results;
`occurrences_limited` reports when its returned list is truncated. Index
construction never silently substitutes sampling after a resource refusal.

The node/member stores are disk-backed and use bounded, write-through caches.
Temporary directories and files use Unix permissions 0700 and 0600. Captured
member sources retain storage ownership until their last reader is dropped.
Logical storage limits include index records and captured bytes; filesystem
allocation overhead is outside that measure.

Dictionary summaries update during discovery. Their statistics describe
observed repeat witnesses, not exhaustive coverage or every matching pair.
The shortlist retains the existing automatic size and the smallest legal size
covering 95% of reachable witness weights; the server profile can also try its
ceiling. Encoding pilots read the snapshot, never the original sources again.
Pilots follow a bounded prefix of the proposed stream (up to 4 MiB desktop or
16 MiB server per dictionary), including actual solid joins, resets and filters.
Selection minimizes the worst relative sampled size/work/memory cost, with
smaller-dictionary ties. No runtime clock decides archive bytes.

The global raw-byte index guides legal ordering and dictionary choices. It does
not authorize arbitrary cross-file references. Actual matches must reach
preceding bytes in the selected stream and dictionary. Filters change that
byte domain and require their own match collection. Automatic file-copy
redirections are not emitted.

## Stateful decision windows

A decision covers at most 256 KiB, with complete candidate partitions and all
block headers, Huffman tables, padding and filter records counted. The encoder
preserves exact recent-distance, repeat-length and dictionary-domain state.
Fresh tables do not reset recent distances.

The desktop profile keeps two finalists and the server profile four. Each sees
the same next 256 KiB through a fixed cheap continuation policy. Only the
current decision is committed. Lookahead stops at a member boundary.

Match graphs have explicit collection provenance, visit/retention limits and
truncation metadata. Pricing passes may reuse compatible fresh matches;
recent-distance matches are derived separately from each arriving parse state.
Rejecting a candidate does not alter committed history or completed progress.
Independent members are admitted in bounded parallel waves. Solid successors
parse from their actual predecessor state.

## Initial envelopes

| Limit | Desktop | Server |
| --- | ---: | ---: |
| Working memory | 256 MiB | 8 GiB |
| Automatic dictionary ceiling | 4 MiB | 64 MiB |
| Repeat-index RAM cache | 16 MiB | 256 MiB |
| Logical temporary storage | 8 GiB | 256 GiB |
| Maximum parse states | 2 | 8 |
| Pricing passes | 2 | 3 |

Controlled allocations and estimated execution workspace are separate from
process RSS. Complete indexing can require much more retained storage than
the original input, and disk-backed updates can be expensive. These are
experimental limits, not tuned performance recommendations.

## Mechanical candidate testing

The six bits of `--hybrid-variant 0..63` select deeper search, multiple parse
states, the full partition portfolio, automatic filters, optimized ordering and
adaptive dictionary selection, respectively. The filter bit controls the CLI
default; explicit mandatory filters remain authoritative. Solid archives retain
the existing refusal for filters, so that matrix combination is ineligible.
Reordering still requires both
explicit archive-analysis and ordering flags. Explicit filters are preserved.

`--hybrid-architecture relationships` retains capture/planning and the existing
stream encoder. `--hybrid-architecture streams` uses the new stream encoder
without analysis, adaptive dictionaries or reordering (use a variant in 0..15).
These are frozen controls alongside the combined default architecture.

See [the runner instructions](scripts/hybrid/README.md) for immutable candidate
manifests, frozen controls, native extraction verification, resumable journals,
phase budgets and explicit SSH/exported workers. Trials do not change source
or ask an AI to choose their next configuration. Archive bytes may differ;
extracted member contents, paths and supported metadata must agree.
