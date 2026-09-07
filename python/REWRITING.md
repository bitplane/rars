# Archive rewriting

## Current API

`RarBuilder.from_archive(source, password=None, *, preserve=True,
staging_dir=None, max_staged_bytes=None)` creates a
**preserving rewrite builder**. It retains supported RAR5/7 format requirements,
solid mode, per-member data and comment encryption, header and archive-comment
encryption, lock flags, archive name/creation metadata, and regenerated
quick-open/recovery services. Plaintext members and comments remain plaintext.
Unsupported preservation raises `UnsupportedRarFeature`; there is no automatic
fallback to conversion. `RarFile.rewrite_preservation_issues()` lists the gaps.

Use `from_archive(..., preserve=False)` to explicitly convert to RAR5,
compression level 3, non-solid and unencrypted, without recovery or volume
configuration. This also remains the route for editing older archives: their
contents and supported member metadata are converted to RAR5. Native legacy
preservation supports the limited subset described below.

Preservation rejects unsupported legacy properties, volume layouts, SFX prefixes, unknown
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
| Links and special entries | RAR5 Unix/Windows symbolic links, junctions, hard links and file-copy records retained; legacy Unix links retained natively or converted to RAR5; other special entries rejected | Preserve supported types; reject unsupported preservation |
| File comments | Decoded comments copied, including explicit empty comments; supported RAR5 CMT records pass preflight | Preserve supported comment content |
| Other metadata | Supported archive name/creation time and lock flag retained in preservation; indexes regenerated | Preserve supported records; reject unsupported preservation |
| Archive format | Conversion writes RAR5; preservation selects a compatible supported legacy or RAR5/7 writer | Preserve supported format semantics; exact creating release may be unknowable |
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
when converting to RAR5. Native preservation also retains supported legacy
archive comments and embedded file comments, as described below.

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
directory to single-archive RAR1.3–4.x or RAR5/7 output. It also allows empty
directories without an input archive. `mode` supplies Unix permissions for RAR2
and later; RAR1.x requires DOS attributes. The default uses DOS directory flags.
Recursive `add(path)` still only queues files; explicit directory creation does
not change that existing traversal policy.

`RarBuilder.add_unix_symlink(arcname, target, *, target_is_directory=False,
mtime=None, mode=None)` queues a Unix symbolic link for RAR2.0–4.x or RAR5/7.
The target is retained without being followed, so dangling links are supported. `mode`
defaults to `0o777`; link type bits are retained separately from permissions.
`RarFile.readlink(member)` returns the raw target bytes of a supported RAR5
redirection or legacy Unix symbolic link. Legacy link payloads are decoded and
integrity-checked without following the target. Conversion maps legacy Unix
member names and targets into the RAR5 Unix byte encoding without replacement;
it does not guess a DOS code page. Native preservation keeps the original legacy
target bytes. RAR5/7 targets use the [RAR5 wire encoding](https://www.rarlab.com/technote.htm),
including its Unix byte mapping; legacy targets use native bytes. Targets must be
nonempty and contain no NUL. Relative targets
are retained verbatim: renaming a link or its target does not retarget the link.
Hard-link and file-copy targets follow member renames. Writing rejects missing,
forward or size-inconsistent archive targets, including targets removed by edits.
Windows symbolic links and junctions retain their original target bytes and flags.
Link volume output is currently rejected. Rewriting does not change extraction's
existing policy for creating filesystem links.

## Native legacy preservation

The supported subset includes single-volume RAR 1.3–4.x archives containing ordinary
files, including solid archives, RAR1.x/RAR2 data encryption and RAR2.9–4.x salted AES
data encryption. RAR3/4 header encryption is retained separately; mixed encrypted/plain members keep their individual status.
Names retain their original bytes; base DOS timestamps and validated extended records retain their raw values without
a timezone conversion. This includes modification, creation, access and archival
time, odd seconds and each record’s original fractional precision. Unix
permissions/type bits and DOS attributes retain their source meaning. DOS, OS/2
and Windows host IDs are normalised to the DOS host with the same attributes.
Renames and removals retain original member identity and order.

Legacy sources can mix supported unpacker versions. The output retains the
highest format requirement present before editing, even if that member is later
removed. Unpacker 15 uses RAR1.5, 20/26 use the RAR2 codec, and 29 uses RAR2.9;
header encryption or NewSub archive comments require the compatible RAR3 writer.
Recompression can increase an individual older member's unpacker requirement
within that retained archive format, including its corresponding encryption
cipher; passwords and each member's encryption status are retained.
RAR1.5 output supports DOS attributes; Unix metadata that its compatible writer
would normalise is rejected. Extended timestamps require RAR2.9 or later output.

Modern UnRAR reports three comment-header errors on the original WinRAR 2.02
comment fixtures and their rewrites, while validating both members successfully.
Comment contents are checked independently through the library.

RAR2.9, 3.x and 4.x share unpacker version 29. Preservation retains the compatible
format requirement without claiming to reproduce the creating release. File data
is recompressed.

Specific preflight errors currently reject unsupported encryption settings,
malformed extended timestamps, unsupported comment forms and special entries,
malformed legacy Unicode filename records, unsupported host metadata, recovery
and other service records. Unknown header
flags, extra header bytes, unsupported end headers and trailing bytes are also
rejected. Empty legacy output remains unsupported; removing the final member fails writing without replacing the destination.
Use explicit `preserve=False` conversion when these properties need conversion
rather than retention. Legacy writers materialize retained payloads in memory.

Native directories retain explicit entries, attributes and base/extended timestamps,
including empty directories. Their headers do not advance or reset solid compression.
Unix symbolic links retain their native target bytes, attributes, comments and times
without following the target; dangling links remain valid. Targets must be nonempty
and contain no NUL. Renaming a link or another member leaves symbolic targets unchanged.
Legacy link payloads are stored, restarting the solid stream before later file data
for reference-reader compatibility. Legacy link/directory volume output is rejected,
as are directories with payload data, unsupported compression or solid dependencies.
The legacy format has no separate symbolic-link target-directory flag; requesting
that flag through `add_unix_symlink` is rejected for legacy output. Other special
entry types remain unsupported.

Legacy Unicode entries retain their original wire name, including the fallback
bytes, when unchanged. Renames encode UTF-16 commands with an ASCII fallback;
renaming such an entry requires valid UTF-8, while ordinary legacy byte names
keep accepting arbitrary bytes. Invalid names fail before modifying builder state.
Non-BMP names round-trip through the library. Linux UnRAR currently mishandles
surrogate pairs in the legacy compact encoding, so its filename extraction checks
cover BMP names; this does not change the retained Unicode data.

The input password is required for retained data, header or archive-comment
encryption and is reused for encrypted output. Plaintext members stay plaintext. Removing encrypted members
does not disable retained header encryption. Missing/wrong passwords and decode
failures leave an existing destination intact. Unexpected salt settings and
explicit encryption-version records still fail preflight. Per-member encryption
overrides are not supported for volume output. The legacy reader can currently
require the password even when selecting a plaintext member of a mixed archive;
this does not mean its payload is encrypted.

Archive comments are retained in their old-style or RAR3/4 `CMT` form. Nested
old-style comments may be emitted as standalone archive-comment blocks. RAR3/4
comment records retain their DOS timestamp and host ID as well as decoded content.
Embedded file comments follow renames/removals; explicit empty comments remain
distinct from absent comments. Comments are decoded and integrity-checked before
output. Duplicate archive comments, unknown comment metadata and ambiguous service
locations fail preflight. Archive comments can accompany encrypted headers and
retain independently encrypted CMT payloads, even when every file is plaintext.
Embedded file comments can accompany a RAR3/4 archive CMT record with visible
headers. Modern UnRAR reports old-comment header diagnostics on these embedded
records, while the library retains and verifies their contents. Embedded file
comments with encrypted headers remain explicitly rejected: reference UnRAR
refuses the whole archive for that combination. File data encryption with visible
comments is supported. RAR1.3/1.4 comments are retained as decoded bytes;
compressed archive comments may be emitted uncompressed. Unknown extra metadata and authenticity records
are rejected. The compatible RAR1.4 writer retains the shared unpacker-2 format,
raw DOS names, timestamps, attributes, solid mode and per-member encryption.

Native rewriting preserves archival time even though `gettimes()` and RAR5
conversion cannot represent it. Those conversion APIs retain their existing
explicit rejection. `Builder::set_legacy_extended_times` in Rust accepts or removes
a validated raw record for single-archive RAR2.9–4.x output; invalid changes leave
the queued record unchanged. Volume output with retained records is rejected.

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

## Rewrite execution and staging

Each `to_bytes()`, `write(path)` or `write_volumes(first_path)` call verifies and
stages retained file payloads in one archive-order extraction pass before
encoding output. Renames retain original source identity; removed independent
files are skipped. Solid predecessors are decoded and verified when needed,
even if removed. Payloads after the last retained source file are not decoded.
Comments and legacy symbolic-link targets use the eager metadata path in
`from_archive()`. Legacy link targets are collected and verified in one traversal,
including required solid predecessors. Independent ordinary files and the suffix
after the last link are not decoded by that metadata traversal. Archives without
legacy links require no link-payload traversal. This metadata pass is separate
from the per-write payload staging pass.

Staging files are private plaintext files, including when the archive is
encrypted. `staging_dir` selects an existing trusted directory; it defaults to
the output directory for path writes and the current directory for `to_bytes()`.
The system temporary directory is not used by default. Files are reopened by
path, so other users must not be able to replace entries in that directory.

`max_staged_bytes` limits the combined uncompressed payload bytes retained on
disk. Its default is the sum of the retained source files' declared sizes,
recomputed after edits on each write. Both admission and actual writes enforce
the limit. A refusal raises `MemoryError`, the binding's resource-limit exception;
filesystem failures raise `OSError`. For example:

```python
editor = RarBuilder.from_archive(
    source, staging_dir="/path/to/private/staging", max_staged_bytes=2 * 1024**3
)
editor.write("edited.rar")
```

Staging lasts only for one write and is removed on success or failure; a retry
stages afresh. Cleanup is best effort, not secure erasure, and process termination
may leave plaintext files. The limit excludes filesystem overhead, discarded
solid dependencies, archive input, comments, link targets, decoder workspace,
added files and writer output spools. Legacy encoding still materializes payloads
in memory; this is not an aggregate RAM limit.

The existing `progress` callback reports a `staging` phase before compression.
Its byte total includes decoded solid predecessors, including removed files;
it is therefore distinct from the retained-byte quota. Entry indices count
decoded payloads in traversal order and names refer to the source archive.
Byte progress counts output before checksum verification and is not a success
signal. Raising from the callback cooperatively cancels staging, cleans up its
files and re-raises the original exception. Decoder work checks the cancellation
token too; blocked I/O and indivisible library work cannot be preempted.

The complete retained payload set is staged before encoding. Incremental
consumption and reuse of original compressed payloads remain future work.

Preservation means supported archive semantics, not identical bytes, compression
ratio, encoder release, dictionary choices or original solid group boundaries.
Volume-set rewriting, explicit conversion target settings, unsupported legacy
metadata/services and header-encrypted quick-open output remain separate work.
Rust callers can use
`Archive::stage_rewrite_sources` with an explicit `RewriteStaging` directory and
payload byte limit, then pass the verified sources to `Builder::add_source`.
This stages the selected payloads in one traversal, including necessary solid
predecessors, before writing; decoder and writer workspace have separate limits.
