# crc32_wrong_beside_blake2sp.rar

`stored_blake2.rar` with a `Data CRC32` field grafted onto the file header: the
`FHFL_CRC32` flag (0x0004) is set, four bytes holding `0x83b27226` are inserted
after `Attributes`, `HeadSize` grows by four, and the header CRC32 is
recomputed. The payload's real CRC32 is `0x83b27227`, so the stored value is
wrong by one bit while the BLAKE2sp record is untouched and correct.

RAR 7.12 and UnRAR 7.20 both test this archive clean. Corrupting the BLAKE2sp
digest instead, and leaving the CRC32 correct, makes both reject it. So when a
header carries both, BLAKE2sp is the authoritative check and the CRC32 is never
evaluated.

WinRAR writes one field or the other, never both, so this shape only turns up
in archives from elsewhere. Hand-crafted for that reason.
