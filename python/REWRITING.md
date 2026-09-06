# Archive rewriting

## Current API

`RarBuilder.from_archive(source, password=None, *, preserve=True)` creates a
**preserving rewrite builder**. It retains supported RAR5/7 format requirements,
solid mode, per-member data and comment encryption, header and archive-comment
encryption, lock flags, archive name/creation metadata, and regenerated
quick-open/recovery services. Plaintext members and comments remain plaintext.
Unsupported preservation raises `UnsupportedRarFeature`; there is no automatic
fallback to conversion. `RarFile.rewrite_preservation_issues()` lists the gaps.

Use `from_archive(..., preserve=False)` to explicitly convert to RAR5,
compression level 3, non-solid and unencrypted, without recovery or volume
configuration. This also remains the route for editing older archives: their
contents and supported member metadata are converted to RAR5. Legacy RAR format
preservation is not implemented.

Preservation rejects legacy formats, volume layouts, SFX prefixes, unknown
compression algorithms, unsupported services and unknown, duplicate or incomplete
metadata. Quick-open indexes combined with header encryption remain an
unsupported writer combination. Unknown
metadata remains tolerated during ordinary reading.

This check is about supported metadata semantics. It does not verify payload
integrity, promise identical compressed bytes, or replace staged publication.
Its diagnostic strings are explanatory text, not stable machine-readable codes.

`source` accepts the same inputs as `RarFile`, or an existing `RarFile`. The
password unlocks the input. Preservation reuses it for encrypted output;
conversion does not enable output encryption. When given an
existing `RarFile`, the method uses that object's configured password, ignoring
the separate password argument.

| Property | Rewrite behaviour | Preservation contract |
| --- | --- | --- |
| File contents, raw names, order | Copied; builder name validation applies | Preserve retained members and order |
| Duplicate names | Rejected explicitly before constructing the rewrite builder | Reject until editing duplicate names by identity is supported |
| Directories | Explicit entries retained, including empty directories and supported modification time/attributes | Preserve explicit directory entries |
| Timestamps | Modification, creation and access times retained, including legacy odd seconds/fractions and complete RAR5 Unix/FILETIME values | Preserve supported timestamp kinds using the established local-zone interpretation for legacy DOS times |
| Attributes and host OS | Unix permission/special bits and DOS file flags retained using source host rules; unknown hosts use default DOS archive attributes | Preserve supported attributes with their source meaning; reject unsupported host semantics |
| Archive comment | Copied as decoded bytes; preservation retains its encryption | Preserve comment content |
| Links and special entries | RAR5 Unix/Windows symbolic links, junctions, hard links and file-copy records retained; legacy Unix links converted to RAR5; other special entries rejected | Preserve supported types; reject unsupported preservation |
| File comments | Decoded comments copied, including explicit empty comments; supported RAR5 CMT records pass preflight | Preserve supported comment content |
| Other metadata | Supported archive name/creation time and lock flag retained in preservation; indexes regenerated | Preserve supported records; reject unsupported preservation |
| Archive format | Conversion writes RAR5; preservation selects the RAR5/7 writer required by the source | Preserve supported format semantics; exact creating release may be unknowable |
| Data/header encryption | Removed in conversion; retained separately in preservation, including mixed plaintext/encrypted members and comments | Preserve both, using an available input password unless explicitly changed |
| Solid layout and compression | Fresh level-3 compression; preservation retains solid mode | Preserve supported solid semantics; compressed bytes and original encoder tuning are not guaranteed |
| Volumes and recovery | Conversion removes configuration; preservation regenerates recognized recovery records at the retained percentage and rejects volumes | Detect these features; preserve supported semantics or reject; volume boundaries are not guaranteed |
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
`RarFile.readlink(member)` returns the raw target bytes of a supported RAR5
redirection or legacy Unix symbolic link. Legacy link payloads are decoded and
integrity-checked without following the target. Conversion maps legacy Unix
member names and targets into the RAR5 Unix byte encoding without replacement;
it does not guess a DOS code page. Legacy-format preservation remains unsupported.
Targets use the [RAR5 wire encoding](https://www.rarlab.com/technote.htm), including
its Unix byte mapping, and must be nonempty and contain no NUL. Relative targets
are retained verbatim: renaming a link or its target does not retarget the link.
Hard-link and file-copy targets follow member renames. Writing rejects missing,
forward or size-inconsistent archive targets, including targets removed by edits.
Windows symbolic links and junctions retain their original target bytes and flags.
Link volume output is currently rejected. Rewriting does not change extraction's
existing policy for creating filesystem links.

## Compatibility change for the next minor release

The default changes from `preserve=False` to `preserve=True`. Callers that need
the previous conversion behaviour must pass `preserve=False` explicitly:

```python
# Preserve supported source settings, or raise before emitting output.
editor = RarBuilder.from_archive(source, password="secret")

# Explicitly convert, including older archives, to unencrypted RAR5.
converter = RarBuilder.from_archive(source, password="secret", preserve=False)
```

Existing calls can now require a password for retained encryption or reject
unsupported source properties. Successful rewrites retain encryption, solid mode
and supported recovery settings instead of resetting them. This is a minor
release compatibility change, not a patch release change.

Empty single-file RAR5/7 archives are supported, including removing the last
member and retaining archive comments and encrypted headers. An empty archive
has no member compression algorithm from which to infer a RAR7 requirement;
the output uses the compatible RAR5 container. Empty legacy/volume output remains
unsupported.

Preflight checks metadata support; payload reads, password verification and
recompression can still fail during writing. `write(path)` stages the complete
archive beside the destination and replaces it only after successful writing.
An existing destination survives preflight, decoding and write failures. The
source path can be the destination when it remains unchanged until publication.
Caller-owned output streams do not have this rollback guarantee.

Preservation means supported archive semantics, not identical bytes, compression
ratio, encoder release, dictionary choices or original solid group boundaries.
Legacy format preservation, volume-set rewriting, explicit conversion target
settings and header-encrypted quick-open output remain separate work. A bounded
single-pass rewrite session is also pending; current lazy member reads can repeat
extraction work for solid archives.
