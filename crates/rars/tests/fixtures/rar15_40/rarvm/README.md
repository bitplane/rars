# RARVM Regression Fixtures

Archive-level fixtures for Unpack29 filters and generic RARVM bytecode.

| Fixture | Purpose |
|---|---|
| `generic_delta_padding_mutation.rar` | Generic VM fallback path for a non-standard filter program. |
| `vm_encoded_u32_filter.rar` | VM filter control stream with 32-bit encoded integers. |
| `ppmd_embedded_vm_filter.rar` | RARVM filter record embedded in a PPMd stream. |
| `solid_e8_filter_member_offset.rar` | Solid E8 filter offset handling across members. |
| `filter_bsdcat_exe.rar` | Real executable filter archive; focused coverage for x86/E8-style filtered PE data. |

The `solid_e8_filter_*.txt` / `.exe` files are expected payloads for the solid
filter regression tests.

## delta_64_channels.rar

One member, `delta64.bin`, 25,600 bytes: 400 rows of 64 interleaved channels
where byte `[row][channel]` is `(channel * 7 + row * 3) & 0xff`. It carries a
RAR 2.9 VM delta filter with `R[0] = 64`.

RAR 5 caps delta channels at 32 because its filter record stores `channels - 1`
in five bits. The RAR 2.9 VM has no such field, taking the count from a
register, and the reference decoder accepts up to 1024. UnRAR 7.20 and RAR 7.12
both extract this archive; rars refused it until the decode bound was raised to
match.

Written by rars with the writer's own 32-channel limit temporarily lifted. That
limit is a choice about what to emit and stays in place.
