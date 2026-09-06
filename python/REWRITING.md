# Archive rewriting

## Current API

`RarBuilder.from_archive(source, password=None, *, preserve=False)` creates a **conversion builder**:
RAR5, compression level 3, non-solid, unencrypted, with no recovery or volume
configuration. It is not yet a metadata-preserving editor. Even a rename rebuilds
the archive with these settings.

Use `RarFile.rewrite_preservation_issues()` to inspect settings and metadata the
current builder cannot preserve. `from_archive(..., preserve=True)` rejects those
issues before creating an output builder. This opt-in currently accepts a
conservative subset of unencrypted, non-solid RAR5 archives. Legacy/RAR7 format
conversion, encryption, solid/volume/recovery settings, main-header extras,
unsupported services, and unknown, duplicate or incomplete file extras fail
preflight. Unknown metadata remains tolerated during ordinary reading.

This check is about supported metadata semantics. It does not verify payload
integrity, promise identical compressed bytes, or replace staged publication.
Its diagnostic strings are explanatory text, not stable machine-readable codes.

`source` accepts the same inputs as `RarFile`, or an existing `RarFile`. The
password unlocks the input; it never enables output encryption. When given an
existing `RarFile`, the method uses that object's configured password, ignoring
the separate password argument.

| Property | Current behaviour | Intended preservation behaviour |
| --- | --- | --- |
| File contents, raw names, order | Copied; builder name validation applies | Preserve retained members and order |
| Duplicate names | Rejected explicitly before constructing the rewrite builder | Reject until editing duplicate names by identity is supported |
| Directories | Explicit entries retained, including empty directories and supported modification time/attributes | Preserve explicit directory entries |
| Timestamps | Modification, creation and access times retained, including legacy odd seconds/fractions and complete RAR5 Unix/FILETIME values | Preserve supported timestamp kinds using the established local-zone interpretation for legacy DOS times |
| Attributes and host OS | Unix permission/special bits and DOS file flags retained using source host rules; unknown hosts use default DOS archive attributes | Preserve supported attributes with their source meaning; reject unsupported host semantics |
| Archive comment | Copied as decoded comment bytes | Preserve comment content |
| Links and special entries | RAR5 Unix/Windows symbolic links, junctions, hard links and file-copy records retained; legacy links and other special entries rejected before writing | Preserve supported types; reject unsupported preservation |
| File comments | Decoded comments copied, including explicit empty comments; supported RAR5 CMT records pass preflight | Preserve supported comment content |
| Other metadata | No faithful preservation contract | Preserve supported records; reject unsupported preservation |
| Archive format | Always writes RAR5 | Preserve supported format semantics; exact creating release may be unknowable |
| Data/header encryption | Removed | Preserve both, using an available input password unless explicitly changed |
| Solid layout and compression | Fresh non-solid level-3 compression | Preserve supported solid semantics; compressed bytes and original encoder tuning are not guaranteed |
| Volumes and recovery | Configuration not copied | Detect these features; preserve supported semantics or reject; volume boundaries are not guaranteed |
| SFX executable prefix | Not copied | Reject preservation unless explicitly supported |
| Unknown records | No preservation guarantee | Reject when their preservation cannot be established |

File contents are read lazily during output. Keep a file-backed source available
and unchanged until writing completes. Each retained member currently invokes
an archive read separately; rewriting large or solid archives can be expensive.
Lazy reads use original member indices, including directory positions, so edits
to the queued names and order do not change source identity.

File comments are decoded eagerly in one metadata pass when creating the rewrite
builder. RAR5 comment payloads are integrity-checked; duplicate member comment
records are rejected. Comments remain attached through renames and removals.
`RarFile.getcomment(member, pwd=None)` returns decoded bytes or `None` when absent.
`RarBuilder.set_file_comment(member, comment=None)` sets or removes a queued
comment; `b""` retains an explicit empty comment. RAR3/4 and volume output do not
support setting file comments. Legacy comments exposed by the reader are retained
when converting to RAR5; legacy format preservation still fails preflight.

`RarFile.gettimes(member)` returns present `modified`, `created` and `accessed`
times as exact integer Unix nanoseconds. `RarBuilder.set_times(member, *,
modified_ns=None, created_ns=None, accessed_ns=None)` sets the extended record.
An omitted modification time retains the base-header modification time, if any.
RAR5 FILETIME values retain their full range, including dates before 1970.
Combining such dates with Unix nanosecond timestamps requires every value to fit
FILETIME's 100-nanosecond precision; otherwise the setter fails without changes.
Legacy creation/access fields use the same local-zone policy as modification
time. Malformed legacy extended records and legacy archival time (which has no
supported RAR5 counterpart) are rejected during conversion.

`RarBuilder.add_directory(arcname, mtime=None, mode=None)` adds an explicit
directory to RAR5/7 output. It also allows empty directories without an input
archive. `mode` supplies Unix permissions; the default uses DOS directory flags.
Recursive `add(path)` still only queues files; explicit directory creation does
not change that existing traversal policy.

`RarBuilder.add_unix_symlink(arcname, target, *, target_is_directory=False,
mtime=None, mode=None)` queues a RAR5/7 Unix symbolic link. The target is stored
as metadata without being followed, so dangling links are supported. `mode`
defaults to `0o777`; link type bits are retained separately from permissions.
`RarFile.readlink(member)` returns the raw target bytes of a supported RAR5 redirection.
Targets use the [RAR5 wire encoding](https://www.rarlab.com/technote.htm), including
its Unix byte mapping, and must be nonempty and contain no NUL. Relative targets
are retained verbatim: renaming a link or its target does not retarget the link.
Hard-link and file-copy targets follow member renames. Writing rejects missing,
forward or size-inconsistent archive targets, including targets removed by edits.
Windows symbolic links and junctions retain their original target bytes and flags.
Link volume output is currently rejected. Rewriting does not change extraction's
existing policy for creating filesystem links.

## Agreed direction for the next minor release

Preservation will become the default **after it is implemented and tested**.
Unsupported preservation must produce an actionable error identifying the
property before output is written. That includes metadata the reader currently
discards: absence from the public member model is not evidence of absence in the
archive. Failed preflight must leave existing destinations intact.

Conversion will be explicit. It must let callers deliberately select a target
format and remove encryption or metadata, and retain a documented route to the
current RAR5 conversion settings. The `preserve` opt-in and existing conversion
are available; configurable target-format/encryption preservation is still planned.
The former DOS-to-Unix permission
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
3. Extend the opt-in preservation preflight and round-trip tests, then switch
   the default in the minor release. Cover encrypted, solid, legacy and empty
   archives, rejection paths and external extraction of emitted metadata.
4. Replace repeated name-based extraction with stable member indices and a
   single-pass rewrite session, with bounded temporary storage. Compressed-data
   reuse can follow once solid dependencies and encryption are handled.
