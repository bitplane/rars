# Legacy filename decoding

Legacy RAR names may contain bytes without a recorded code page. An archive's
DOS/Windows host identifier does not identify its language. rars never guesses
the encoding from the current locale or from whether the bytes happen to be
valid UTF-8.

An explicit legacy name encoding supplies a Unicode view for names that lack
a format-provided Unicode representation. Legacy Unicode names and RAR5/7 names
keep their existing interpretation. The archive's name identity and original
Unicode header representation remain unchanged for reading and rewriting.

Supported names are `cp437`, `cp850`, `cp852`, `cp866`, `windows-1251`,
`windows-1252` and `utf-8`. Names are case insensitive; `cp1251`, `cp1252` and
`utf8` are aliases. All bindings use the same locale-independent tables.
Undefined code-page bytes, invalid explicitly selected UTF-8 and unsupported
encodings fail. There is no replacement-character fallback under an explicit
encoding. East Asian multibyte encodings are not yet supported.

## CLI

```sh
rars info --legacy-name-encoding cp850 old.rar
rars x --legacy-name-encoding cp850 old.rar output/
```

The selection applies to both ordinary and verbose filename listings and to
extraction, including volume sets. Converted paths go through the normal
destination checks. Conflicting output paths are refused. Earlier extracted
output can remain when a later entry fails.

## Python

```python
options = rars.ReadOptions(legacy_name_encoding="cp850")
archive = rars.RarFile("old.rar", options=options)
info = archive.getinfo("café.txt")
data = archive.read(info)
archive.extractall("output")
```

The opened archive retains its name interpretation for listing, string lookup
and extraction. This does not retain resource limits or cancellation tokens.
Extraction can override the encoding through its own `ReadOptions`; an omitted
encoding inherits the opened archive's choice. Open a new archive without a
name encoding to return to the default byte-preserving behaviour.

`RarInfo.orig_filename_bytes` retains the existing identity bytes. Byte lookups
and `RarInfo` selections use that identity. A decoded string matching several
entries is refused; use the original bytes or entry objects to distinguish
different original names. Existing limitations on entries with identical
original names are unchanged. Selecting another encoding for extraction does
not change the opened listing or its string lookup policy.

An encoding may also be supplied to `extract_volumes(..., options=options)`.
Converted output path collisions are refused even with `overwrite=True`.

## JavaScript

```js
const archive = await RarArchive.open(input, { legacyNameEncoding: "cp850" });
const entry = archive.get("café.txt");
const bytes = await entry.bytes();
```

`entry.name` is the decoded view; `entry.nameBytes` retains the existing identity
bytes. Entries remain indexed in archive order. If a decoded string matches
several entries, `get()` throws `AMBIGUOUS_ENTRY`; `getAll()` returns the entries
so callers can choose explicitly. Open the archive again to change its name
view. JavaScript returns payload bytes; callers choose filesystem destinations.

## Rust

Use `ArchiveMember::decoded_name(Some(LegacyNameEncoding::Cp850))` for a view.
Core parsing, lookup and extraction callbacks retain their existing name bytes.
Extraction metadata includes `name_is_unicode`; path adapters can use
`filename::decoded_name(&meta.name, meta.name_is_unicode, encoding)` and then
validate the converted destination. `ArchiveReadOptions::legacy_name_encoding`
is an application-adapter policy, not a request to mutate
core callback metadata.

## Defaults and scope

Without a choice, native Unix extraction preserves legacy bytes. Non-Unix
destinations retain the existing Unicode requirement. The RAR5 Unix byte mapping
is independent of this option and keeps its existing behaviour.

This option does not reinterpret comments, passwords or payloads, transcode
names while rewriting, create new legacy code-page names, normalize Unicode,
or choose replacement filenames. These require separate policies.
