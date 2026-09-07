# Reader cancellation and resource limits

`RarFile.read`, `open`, `extract`, `extractall`, `testrar` and `read_comment` accept a keyword-only
`options=rars.ReadOptions(...)` argument. Options apply to that call, not to the
archive object. Omitting them retains the existing defaults and password handling.

```python
import rars

archive = rars.RarFile("input.rar")
token = rars.CancellationToken()
options = rars.ReadOptions(
    cancellation=token,
    max_member_output_bytes=16 * 1024**2,
    max_total_output_bytes=64 * 1024**2,
    rar50_dictionary_size_limit=32 * 1024**2,
)
payload = archive.read("document.txt", options=options)
archive.extractall("output", options=options)
archive.testrar(options=options)
comment = archive.read_comment(options=options)
```

`ReadOptions` is immutable and reusable. Its limits and cancellation token are
readable properties. Every call starts fresh output budgets; sharing an options
object does not share a cumulative budget. Limits accept nonnegative integers
through `2**64 - 1`; `None` retains the default policy.

| Option | Meaning |
| --- | --- |
| `cancellation` | A `CancellationToken` shared with the caller. Another Python thread may call `cancel()` while decoding runs with the GIL released. |
| `max_member_output_bytes` | Inclusive logical output ceiling per decoded member, across all archive families. Zero permits empty output. |
| `max_total_output_bytes` | Inclusive logical output ceiling for the call. Counts all decoded members, including discarded solid predecessors. Configuring it selects sequential extraction. |
| `rar50_dictionary_size_limit` | Inclusive declared dictionary-size admission limit for compressed RAR5/7 members; not a total RAM quota. |
| `rar50_buffered_decode_limit` | Threshold above which RAR5/7 uses streaming decoding where supported. Filtered members can require scratch-backed decoding; scratch policy is not exposed by this Python API yet. |

Selecting a member can require decoding earlier solid members. Their output
counts against both limits even when discarded. Unrelated independent members
are skipped by selected operations. `testrar` discards every member's decoded
bytes, but those bytes still count against the limits. Unknown-size RAR5 members
are rejected under an output-limit policy; these options do not enable a new
decode-to-end mode.

A declared-size refusal happens before opening the failing output file, including
when `overwrite=True`. Runtime limit, cancellation, integrity or I/O failures may
leave earlier extracted files and the failing file's prefix. Extraction does not
have the staged-publication guarantee of builder path writes. Successful empty
files and explicit directories are still created.

`read` returns a complete byte buffer or raises; it never returns a partial
buffer. `open` also decodes the complete member before returning `BytesIO`; it is
not a streaming archive reader. Output limits do not account for all decoder
workspace, retained input, copies or concurrent jobs.

Cancellation raises `InterruptedError` when observed. It is cooperative: blocked
I/O and indivisible codec work cannot be interrupted midway. Cancelled tokens
cannot be reset; use a new token for later work. Resource refusals raise
`MemoryError`; unsupported decoding modes retain their feature exception.

`read_comment(pwd=None, *, options=None)` returns the complete archive comment as
bytes, or `None` if absent; an empty comment is `b""`. Both output ceilings apply
to the single comment, with fresh budgets and admission before payload decoding.
Cancellation is checked even when no comment exists. RAR5/7 dictionary and
buffering policies apply to compressed comments; the default comment path stays
buffered unless a threshold is supplied. Filtered comments above that threshold
raise `MemoryError` because Python does not yet expose scratch policy. No partial
comment is returned on failure. The `comment` property keeps its default policy;
`getcomment(member)` reads a member comment and does not accept these options.

These options do not apply to initial archive parsing, member-comment or link
helpers, repair, or the module-level volume helpers. Passwords remain supplied
through `pwd=` or the archive's configured password. A per-call password does not
change the archive's configured password.
