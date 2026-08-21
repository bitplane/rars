# Crafted RAR 5 headers a reader must handle

Hand-built, since no encoder emits these. Each was checked against RAR 7.12 and
UnRAR 7.20 so the expected verdict is the reference's, not ours. All three are
patched copies of `-qo-` archives: an archive carrying a quick-open cache holds
a verbatim second copy of the header, and the reference reader silently
extracts from that instead, so an edit to the live header measures nothing.

| Fixture | Edit | Reference verdict |
|---|---|---|
| `algorithm_version_2.rar` | CompInfo algorithm version 0 → 2 on a compressed member | `Unknown method in mid.txt` |
| `algorithm_version_2_stored.rar` | the same edit on a **stored** member | extracts cleanly |
| `first_block_without_tables.rar` | `table_present` cleared on the first block, block header XOR checksum fixed | member fails |

The stored one is the interesting pair to the first: with nothing to
decompress, the algorithm version never comes up, so the refusal belongs on the
decompressor rather than at header parse time.

Version 1 was measured too and is not kept as a fixture: it dispatches to
Unpack70 and then fails a checksum, because the stream is really v0. That the
version picks the decoder is what makes an unassigned value have none to pick.

## Volume substitution

`plaintext_stored_multivol.part2.rar` is a plaintext RAR 5 volume with the same
layout as `header_encrypted_stored_multivol.part2.rar`, for splicing into that
set. RAR 7.12 and UnRAR 7.20 abort with `ERROR: Bad archive` rather than
extract; rars refuses with "split entry encryption flag changed".

Header encryption hides the file names, so an attacker who can replace one
volume of a set the user believes is protected throughout would otherwise
inject entries into the extraction. The set is the unit of trust, not the
volume.
