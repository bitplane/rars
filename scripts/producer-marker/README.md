# Producer marker

Every archive and volume rars writes carries a small stored record named `RARS`
whose payload is:

```text
rars/<library version>
marker-schema=1
```

The version is the rars library's, not the embedding application's. The record
is advisory: anyone can strip or forge it, and its CRC detects damage, not
tampering. The payload stays plaintext even when headers are encrypted, so it
names the producer without the password but exposes no file names or data.
RARLAB has not allocated `RARS`; we picked it.

Preserving rewrites replace a recognised record with the current version.
Unknown, duplicate, misplaced or damaged records are refused rather than
dropped. RAR's own updates discard the record, as its flags ask, so it marks
the original writer, not the last one.

## Framing

| Format | Container | Overhead per volume at 0.10.2 |
| --- | --- | --- |
| RAR 5/7 | Service header (type 3) after the main header, before any comment or file. Flags `0x0006`, file flags `0x0004` (CRC32), stored, zero attributes and host OS, no extras or quick-open entry | 50 bytes, 76 with encrypted headers |
| RAR 1.5-4 | `NEWSUB_HEAD` (`0x7a`), flags `0xc000`, 36-byte header, method `0x30`, zero host/attributes/time. Placed after any old-style archive comment, before files | 64 bytes, 84 with encrypted headers |
| RAR 1.3/1.4 | Appended to the `RE~^` main header after any comment, with `HeadSize` raised: `RARS`, 2-byte payload length, payload, 4-byte payload CRC32 | 38 bytes |

The `NEWSUB_HEAD` unpacker version follows the target: 15 for `rar15`, 20 for
`rar20`, 29 for `rar29` to `rar40`. A marker alone therefore needs RAR 2.9, not
3.0, and rewrites infer the lowest format the members and producer allow.
The record must follow an old-style comment: RAR 3.93 reports a corrupt comment
when it comes first.

## Compatibility evidence

Each family was tested by writing pairs of archives, one unmarked control and
one marked, and checking that every reader produced the same verified output
for both. A pair passes when test/list and extraction succeed and the extracted
names and SHA-256s match the input exactly. Readers included UnRAR 7.20, RAR
7.12, RAR 3.93, official 7-Zip 26.04, libarchive 3.8.5, The Unarchiver 1.10.8,
Bandizip 7.47, RAR and WinRAR consoles and GUIs from 2.90 to 7.21b1 under Wine,
DOS RAR 1.402/1.55/2.50 under DOSBox-X, and WinRAR 1.54 driven through its GUI.

| Family | Pairs | Pass | Control failures | Marker regressions |
| --- | ---: | ---: | ---: | ---: |
| RAR 5/7 | 168 | 156 | 12 | 0 |
| RAR 3/4 (production rerun) | 540 | 500 | 40 | 0 |
| RAR 2.9 | 220 | 208 | 12 | 0 |
| RAR 2.0 | 242 | 232 | 10 | 0 |
| RAR 1.5 (+11 WinRAR 1.54 GUI pairs, all pass) | 242 | 227 | 15 | 0 |
| RAR 1.3/1.4 (+10 WinRAR 1.54 GUI pairs, all pass) | 250 | 202 | 48 | 0 |

Control failures are readers that already fail the unmarked archive:
libarchive on most compressed, solid, encrypted or multivolume cases; The
Unarchiver on solid and encrypted cases; Bandizip on multivolume RAR 5 and
encrypted-header volumes; 7-Zip, libarchive, The Unarchiver and Bandizip on
anything before RAR 1.5; RAR 5.00 dropping the last byte of an old-style
comment. Corruption controls (a flipped member byte) returned exit code 3 from
every RAR and WinRAR build tested, so silent GUI testing does not hide CRC
errors. RAR 3/4 recovery repair restores a marked archive byte for byte.

`results.json` in each directory holds the case definitions, outcomes and
executable fingerprints. These cover Wine, not native Windows, and say nothing
about readers not listed above (WinZip, Explorer, SharpCompress, Go rardecode).

## Rerunning

The scripts never patch source or install software. Build an unmarked control
CLI and the current CLI, then describe the readers in an engine list:

```json
[
  {"name": "unrar", "family": "rar", "command": ["/usr/bin/unrar"]},
  {"name": "7zip", "family": "7zip", "command": ["/path/to/7zz"]}
]
```

Families are `rar`, `winrar`, `7zip`, `libarchive`, `unar` (also needs a
`list_command` for `lsar`), `rars` and `bandizip`. Windows engines take
`windows: true`, a `wine` command prefix and a `WINEPREFIX` in `env`. Run
`WinRAR.exe` engines under `xvfb-run -a`, one Wine job at a time per prefix.

```sh
python3 scripts/producer-marker/rar34/probe.py \
  --control /path/to/rars-control --marked /path/to/rars \
  --engines engines.json --output target/producer-marker/rar34
```

The top-level scripts cover RAR 5/7; `rar14/`, `rar15/`, `rar20/`, `rar29/` and
`rar34/` cover the older families with the same `probe.py`, `negative.py`
(corruption controls) and `maintenance.py` (RAR update checks). `dos.py` and
`winrar154.py` drive the DOS and WinRAR 1.54 readers, and
`rar34/protected_marker.py` builds recovery-protected marked archives. Use a
fresh output directory, or `--resume` with unchanged binaries and engines. Exit
status only fails on a marker regression, so read the report for coverage.
Keep output and Wine prefixes on disk, not in a RAM-backed `/tmp`.
