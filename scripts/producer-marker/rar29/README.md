# RAR 2.9 producer marker

The `rar29` writer emits the same `RARS` new-subblock as RAR 3/4: type `0x7a`,
flags `0xc000`, a 36-byte header, stored method `0x30`, unpacker version 29,
zero host/attributes/time, and the shared `rars/<version>\nmarker-schema=1\n`
payload. At version 0.10.2 this adds 64 bytes to each archive or volume.

An old-style archive comment must immediately follow the main header. The
producer follows that comment, before members; without a comment it follows
the main header. The initial prototype put the producer before the comment:
member extraction passed, but RAR 3.93 reported a corrupt comment. That layout
was rejected. The final probe checks comment export explicitly, in addition to
file tests and extraction hashes.

The `rar29` writer has since moved its archive comment to a `CMT` new-subblock,
as every RAR build that writes 2.9-format members does. The producer still
follows the comment, so the framing below holds for either comment form.

Preserving rewrites recognize and replace the producer using the existing
bounded, CRC-checked schema validation. The marker requires at least `rar29`,
not `rar30`. A `CMT` comment or encrypted headers rewrite as `rar30`, which
`rar29` output also reads as.
Otherwise identical RAR 2.9/3/4 archives cannot reveal the original target
selection. Rewriting uses the lowest supported format implied by their records.
The subsequent [RAR 2.0 backfit](../rar20/README.md) uses unpacker version 20
for its producer; RAR 1.5 now uses unpacker version 15; see the
[RAR 1.5 report](../rar15/README.md). RAR 1.4 output remains unmarked.

## Evidence

**220 comparisons across 20 executable builds: 208 pass, 12 baseline failures,
zero marker regressions.** RAR and WinRAR 2.90 both pass all 11 cases. All 14
corruption controls pass. Independent framing checks cover 38 archive/volume
files. All four update checks pass: RAR 2.90 and 3.93 preserve the comment and
members, and discard the unknown producer record as requested by its flags.

`results.json` records paired control/marked runs against the pre-change writer
at `c3a382f`, reader and writer fingerprints, explicit comments, corruption
controls and reference updates. The native corpus includes a Unicode filename;
the Windows corpus uses its ASCII spelling, as in the RAR 3/4 investigation.
Every successful extraction requires exact filenames and content SHA256 hashes.

The 11 archive shapes are stored, compressed, solid, archive comment, stored and
compressed password protection, stored/compressed/solid/password volumes, and
an empty file. Header encryption is not supported by the `rar29` target.
Both the RAR 2.90 console and the actual WinRAR 2.90 GUI executable are tested
under Wine/Xvfb, alongside the established RAR 3/4 reader matrix.

The old 2.90 distribution's `TechNote.txt` documents the common `0x4000`
(discard unknown records on update) and `0x8000` (additional data size) flags,
although its declared block list stops at `0x79`. Thus the framing is skippable
without understanding the new subblock name. The local reference document is
fingerprinted in the evidence. Compatibility conclusions come from executable
tests, not from assuming a decoder's behavior based on its version label.

Baseline failures are retained, not treated as evidence of compatibility:
libarchive fails old-style comments, solid data, passwords and multivolume
extraction; The Unarchiver fails password cases. RAR 5.00 exports the comment
with its final character missing in both variants. UnRAR has no `cw` command,
so its comment check inspects the text displayed by `t` instead.

Negative controls flip a stored member byte and require CRC-error exit 3 from
RAR/WinRAR. Reference update checks require the archive comment and all
member contents to survive adding a member. Raw framing checks validate header
CRCs, producer payload CRCs, exact framing and one producer in every volume.

Recovery generation is still unsupported for this writer. The unchanged
producer framing's recovery-protected behavior was tested in the
[RAR 3/4 investigation](../rar34/README.md); this report does not claim an
additional RAR 2.90 recovery-protection matrix. Likewise, Wine command-driven
GUI executable tests do not establish native Windows or manual GUI behavior.
The marker is advisory, removable and forgeable.

## Reproduce

Build `rars-cli` at `c3a382f` and retain that binary as the control. Build the
current source as the marked writer. Supply engine JSON lists as described in
the [parent report](../README.md), using the reader paths recorded in the
results. The scripts do not modify source or install software.

```sh
python3 scripts/producer-marker/rar29/probe.py --jobs 4 \
  --control /path/to/control --marked /path/to/marked \
  --engines /path/to/native.json --output target/rar29-native

xvfb-run -a python3 scripts/producer-marker/rar29/probe.py --ascii --jobs 6 \
  --control /path/to/control --marked /path/to/marked \
  --engines /path/to/windows.json --output target/rar29-windows

xvfb-run -a python3 scripts/producer-marker/rar29/maintenance.py \
  --matrix target/rar29-windows --engines /path/to/rar-update-engines.json \
  --output target/rar29-maintenance

xvfb-run -a python3 scripts/producer-marker/rar29/negative.py --jobs 5 \
  --matrix target/rar29-windows --engines /path/to/rar-winrar-engines.json \
  --output target/rar29-negative
```

Run the Wine invocations sequentially: sharing a Wine prefix across separate
concurrent Xvfb sessions can produce X display errors. Such infrastructure
failures must be rerun, not counted as reader baseline failures. `--resume`
resumes an interrupted main matrix with unchanged binaries and engine config.
Local archives and logs are under `target/producer-marker-rar29/`; the reference
WinRAR application directory was copied without modifying the user's prefix.

## Validation

The workspace/all-targets suite passes with external decoders required. The
final preserving-version adjustment and comment assertions also pass the focused
producer/rewrite tests. Clippy with warnings denied, formatting, minimal-write
marker tests and the reader-only build pass.
