# RAR 1.54 Unpack15 Fixtures

Copied from the spec repository's `fixtures/1.54/` directory.
`expected/README.md` is the byte-for-byte payload expected from the
single-file README fixtures.

| Fixture | Purpose |
|---|---|
| `readme_154_normal.rar` | Single-file compressed `README.md`, method `0x33`, `UNP_VER = 15`. |
| `readme_154_password.rar` | Same payload patched to set `FHD_PASSWORD` and encrypt the packed stream with CRYPT_RAR15, password `password`; validated by RAR 3.93. |
| `readme_154_store_solid.rar` | Single-file solid-archive flag variant; same payload. |
| `doc_154_best.rar` | Multi-file compressed text corpus, 17 entries. |
| `audio_win_names_unpack15.rar` | Audio-shaped WAV payload with Windows long names. |
| `audio_dos_names_unpack15.rar` | Same audio-shaped payload with DOS 8.3 names. |
| `random.rar` + `.r00` + `.r01` | Old-numbered multi-volume archive. |

Expected `README.md` CRC32 is `0x509e5e3c`.
