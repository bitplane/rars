# Zero padding after the last code (issue #489)

`rar29.rar` holds two non-solid RAR 2.9 LZ members:

- `first.bin`: bytes 0 to 255 six times, then
  `b"RAR 2.9 member without an end-of-block code\n"` four times;
- `second.txt`: bytes 32 to 126 thirty times.

`rars add --format rar29` wrote it. Each member's packed data then had its
end-of-block code and the two flag bits after it removed, so the stream stops
on its last literal or match, followed by the zero bits that pad its last
byte. `first.bin` then got one whole zero byte of padding and `second.txt`
five, with the packed sizes and header CRCs rewritten. Every member's CRC32
is the writer's.

UnRAR 7.20 tests both members OK. rars before #489 refused both with "RAR 2.9
LZ member has trailing data", because it took no more than seven bits of zero
padding.
