# Crafted RAR 1.5-4.x headers

Hand-built edge cases that ordinary encoder operation does not emit.
Compatibility observations are recorded with each fixture.

## empty_compressed_payload_rar30.rar

A 61-byte RAR 3.0 archive containing `empty.bin`. Its file header declares
RAR29 compression method `0x33`, zero packed bytes, zero unpacked bytes, and
the CRC-32 of an empty file. It was made from a stored empty archive emitted by
rars by changing method `0x30` to `0x33` and recomputing the file-header CRC.

On 2026-09-12, rars, UnRAR 7.20, and bsdtar/libarchive 3.8.5 all accepted it
and extracted a zero-byte file. 7-Zip 26.00 recognized the archive but reported
the member as an unsupported method. No historical WinRAR or RAR.EXE result is
claimed: none was installed in the test environment.

## zero_head_size.rar

A RAR 1.5 file header with `HEAD_SIZE = 0` and the long-block flag cleared, so
the block extent is exactly zero and the next position equals the current one.
A reader that seeks and repeats spins on that offset forever.

RAR 7.12, UnRAR 7.20 and rars all reject it, and none hang. rars gets there by
refusing any header below the 7-byte minimum rather than by comparing
positions; either route works as long as the walk cannot stand still.

## solid_flag_cleared_rar15.rar

A solid two-member RAR 1.5 archive with `FHD_SOLID` cleared on the second
member and the header CRC recomputed. Both members still extract, because
below `UnpVer` 20 the per-file flag is not consulted: continuation follows the
archive-level `MHD_SOLID` and position.

The second member is 46 packed bytes standing for 2700 unpacked, so extraction
can only succeed by carrying the window across. The same edit to a RAR 2.0
archive breaks it, which is where the flag starts being read.
