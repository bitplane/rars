# RAR 2.50 Unpack20 Fixtures

Copied from the spec repository's `fixtures/2.50/` directory plus selected
external corpus samples promoted as regression fixtures.

| Fixture | Purpose |
|---|---|
| `AUDIO.RAR` | RAR 2.50 `-mm` multimedia-switch fixture. Despite the name, the first table-read peek is `0x0040`, so bit 15 is clear and the member decodes through normal Unpack20 LZ. |
| `AUTOREJ.RAR` | Same `-mm` path on text input where the encoder rejects audio mode and emits normal Unpack20 LZ. |
| `BIGLZ.RAR` | Longer Unpack20 LZ history/table-stress stream. |
| `SOLID.RAR` | Solid Unpack20 state carry-over across two members. |
| `unpack20_audio_text.rar` | External `junrar` corpus archive with a WAV-named payload and stored text member. The first compressed member's table-read peek is `0x2221`, so it also exercises normal Unpack20 LZ rather than audio mode. |
| `unpack20_keep_tables.rar` | Unpack20 keep-table coverage. |
| `unpack20_multiblock.rar` | Explicit multiblock Unpack20 stream from the local corpus. |

Known remaining gap: no vintage-encoder fixture currently proves a true
Unpack20 audio block. The test suite has synthetic one-channel audio coverage
at codec level and synthetic in-memory RAR 2.0 archive coverage for channel
counts 1, 2, 3, and 4, but RAR 2.50 `-mm[f]` probes with
mono/3-channel/4-channel WAV-shaped data and the historical `AUDIO.RAR`
fixture all selected normal LZ blocks. A useful future fixture must have bit
15 set in the first table-read peek word and should pin the selected channel
count.

The spec repo's `scripts/find-rar20-audio-candidates.py` scans the local
external corpus, spec fixtures, promoted crate fixtures, and old numbered
volumes. Current result: 538 archive/volume files scanned, 37 raw bit-15
candidates, 0 clean candidates. The candidates are stored, encrypted,
split-continuation, or solid-continuation false positives. `SOLID.RAR` member
2 intentionally pins one trap: raw data-start peek `0xdfbe`, but `LHD_SOLID`
means it is not a fresh table-read boundary.
