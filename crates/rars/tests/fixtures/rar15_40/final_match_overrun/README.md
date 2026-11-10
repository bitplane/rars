# final_match_overrun

The same two members as `rar50/final_match_overrun.rar`, archived in solid mode
by `rars add --format rar15|rar20|rar29`, with `first.bin`'s declared size then
cut from 2,000 to 1,990 bytes and its CRC32 and header CRC rewritten.

UnRAR 7.23 extracts `second.bin` from all three. For `rar29.rar` it truncates
`first.bin` at 1,990 bytes. For `rar15.rar` and `rar20.rar` it writes all
2,000 bytes and reports a checksum error. rars truncates in every case. The
rars RAR 1.5 encoder never matches across members, so only `rar20.rar` and
`rar29.rar` test that the overrun stays in the window.
