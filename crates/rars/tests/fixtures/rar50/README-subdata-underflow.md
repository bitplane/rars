# subdata_size_underflow.rar

`with_recovery.rar` with one byte changed: the `RR` service header's
`FHEXTRA_SUBDATA` record declares size 1 instead of 2, so its type vint fills
the record and the payload byte `0x0a` (10% recovery) dangles past the end. The
header CRC32 was recomputed over `[crc + 4, header_end)`.

WinRAR 5.21 and earlier wrote this shape for real: they stored the `SUBDATA`
size one less than the payload they emitted. Because `SUBDATA` is the last
record in a service header, the shortfall always shows up as exactly one
leftover byte, which is how a reader recognises it.

RAR 7.12 and UnRAR 7.20 both extract this archive and report the recovery
record. Neither prints the recovery percent, so what the fixture pins is that
the shape is readable, not that the reference readers keep the byte.

Hand-crafted rather than produced by a WinRAR 5.21 build.
