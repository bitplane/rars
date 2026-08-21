# zero_fill_out_of_window.rar

One 240-byte member, `zerofill.bin`: eight `0x00` bytes followed by
`b"zero-fill regression payload "` repeated eight times.

The leading eight bytes are stored as a match of length 8 at distance 4096,
emitted at output position 0, so the distance reaches past the start of the
stream. WinRAR fills such a region with zeroes rather than failing, which makes
this a valid archive whose BLAKE2sp hash matches only if the reader does the
same.

Produced by `rars` with the encoder temporarily patched to splice that match
over the leading literals, then verified against UnRAR 7.20 and RAR 7.12.
