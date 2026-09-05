# Archive rewriting

## Current API

`RarBuilder.from_archive(source, password=None)` creates a **conversion builder**:
RAR5, compression level 3, non-solid, unencrypted, with no recovery or volume
configuration. It is not yet a metadata-preserving editor. Even a rename rebuilds
the archive with these settings.

`source` accepts the same inputs as `RarFile`, or an existing `RarFile`. The
password unlocks the input; it never enables output encryption. When given an
existing `RarFile`, the method uses that object's configured password, ignoring
the separate password argument.

| Property | Current behaviour | Intended preservation behaviour |
| --- | --- | --- |
| File contents, raw names, order | Copied; builder name validation applies | Preserve retained members and order |
| Duplicate names | Rejected by the builder | Reject explicitly until editing by member identity is supported |
| Directories | Skipped, including empty directories | Preserve explicit directory entries |
| Timestamps | RAR5 whole-second modification time retained (base header or HTIME, including explicit epoch); legacy times and subsecond precision still dropped | Preserve supported timestamp fields and precision using the established local-zone interpretation for legacy DOS times |
| Attributes and host OS | Unix permission/special bits and DOS file flags retained using source host rules; unknown hosts use default DOS archive attributes | Preserve supported attributes with their source meaning; reject unsupported host semantics |
| Archive comment | Copied as decoded comment bytes | Preserve comment content |
| File comments, links and other metadata | No faithful preservation contract | Preserve supported records; reject unsupported preservation |
| Archive format | Always writes RAR5 | Preserve supported format semantics; exact creating release may be unknowable |
| Data/header encryption | Removed | Preserve both, using an available input password unless explicitly changed |
| Solid layout and compression | Fresh non-solid level-3 compression | Preserve supported solid semantics; compressed bytes and original encoder tuning are not guaranteed |
| Volumes and recovery | Configuration not copied | Detect these features; preserve supported semantics or reject; volume boundaries are not guaranteed |
| SFX executable prefix | Not copied | Reject preservation unless explicitly supported |
| Unknown records | No preservation guarantee | Reject when their preservation cannot be established |

File contents are read lazily during output. Keep a file-backed source available
and unchanged until writing completes. Each retained member currently invokes
an archive read separately; rewriting large or solid archives can be expensive.

## Agreed direction for the next minor release

Preservation will become the default **after it is implemented and tested**.
Unsupported preservation must produce an actionable error identifying the
property before output is written. That includes metadata the reader currently
discards: absence from the public member model is not evidence of absence in the
archive. Failed preflight must leave existing destinations intact.

Conversion will be explicit. It must let callers deliberately select a target
format and remove encryption or metadata, and retain a documented route to the
current RAR5 conversion settings. These options are planned, not available in
the current `from_archive` signature. The former DOS-to-Unix permission
reinterpretation was a bug; conversion no longer performs it.

Preservation means preserving supported archive semantics, not identical bytes,
compression ratio, encoder version, dictionary choices or volume boundaries.
If a format cannot represent retained metadata, preservation must fail instead
of silently degrading it. Reading and recompression can still fail after a
successful metadata preflight; preflight is not a substitute for staged output.

Implement this in small steps:

1. Add format-aware metadata adapters and tests for timestamps and attributes.
2. Represent directories and archive settings, including separate data/header
   encryption, and detect unsupported records and features before emission.
3. Add explicit preservation/conversion policy and round-trip tests, then switch
   the default in the minor release. Cover encrypted, solid, legacy and empty
   archives, rejection paths and external extraction of emitted metadata.
4. Replace repeated name-based extraction with stable member indices and a
   single-pass rewrite session, with bounded temporary storage. Compressed-data
   reuse can follow once solid dependencies and encryption are handled.
