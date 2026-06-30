# RAR 2.9/3.x PPMd Fixtures

PPMd-mode fixtures for the RAR 1.5-4.x container. These are copied from the
spec repository's `fixtures/ppmd/` set plus small regression fixtures.

| Fixture | Purpose |
|---|---|
| `ppmd_lorem_rar300.rar` | Normal RAR 3.00 PPMd text member. |
| `ppmd_escape_rar300.rar` | Literal escape-byte handling. |
| `ppmd_mixed_rar300.rar` | Mixed text/binary PPMd archive. |
| `ppmd_solid_rar300.rar` | Solid PPMd model reuse across members. |
| `ppmd_lz_repeat_rar3.cbr` | PPMd stream with embedded one-byte LZ repeats. |
| `ppmd_lz_match_rar300.rar` | PPMd stream with embedded LZ distance matches. |
| `farmanager170.rar` | Wild solid PPMd archive whose model reaches large-context allocator territory before `Addons\Shell\FARHere.inf`. |

The `.txt` and `.bin` files in this directory are expected plaintext payloads
used by tests.
