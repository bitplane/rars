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
