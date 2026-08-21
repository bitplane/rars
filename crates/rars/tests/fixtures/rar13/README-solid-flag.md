# solid_flag_cleared.rar

A solid two-member RAR 1.4 archive written by rars, with `LHD_SOLID` (file
entry flag `0x10`, at offset +17) cleared on the second member. RAR 1.4 headers
carry no checksum, so the byte is simply flipped.

Both members still extract under RAR 7.12, UnRAR 7.20 and rars. Below `UnpVer`
20 the per-file flag is written but never read back: solid continuation follows
the archive-level `MHD_SOLID` flag and position alone.

The second member is 44 packed bytes standing for 2700 unpacked, so decoding it
correctly is only possible with the window carried over from the first.
