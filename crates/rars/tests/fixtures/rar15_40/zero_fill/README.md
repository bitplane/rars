# Out-of-window match fixtures (RAR 2.0 and RAR 2.9)

Each archive holds one 240-byte member, `zerofill.bin`: eight `0x00` bytes
followed by `b"zero-fill regression payload "` repeated eight times.

The first eight bytes are not stored as literals. They are a match of length 8
at distance 4096, emitted at output position 0, where nothing has been written
yet and the distance reaches past the start of the stream. A reader that treats
that as an error cannot extract these files; a reader that fills the region with
zeroes reproduces the member exactly and its CRC32 matches.

Both archives were produced by `rars` with the encoder temporarily patched to
splice that match over the leading literals, then verified against UnRAR 7.20
and RAR 7.12, which extract them without complaint.
