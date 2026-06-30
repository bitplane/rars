# RAR Format & Implementation Docs

Clean-room specifications and implementation notes for building a complete
RAR reader + writer across every format generation. Written for the `rars`
(RAR in Rust) project.

Scope: RAR 1.3/1.4 (undocumented legacy), RAR 1.5–4.x (technote.txt era),
RAR 5.0/7.0 (current). "RAR 6" was a software release; "RAR 7" is RAR 5.0
with a larger-dictionary algorithm revision.

## Reading order

Skim **§ Format specs** for the version you care about, then dive into
**§ Algorithms** and **§ Write-side** for the pieces referenced by the spec.
**§ Implementation** is the cross-cutting reader/writer companion material
that doesn't belong inside any single version spec.

## Format specs (wire format, read + write)

| Doc | Covers |
|-----|--------|
| [`RAR13_FORMAT_SPECIFICATION.md`](RAR13_FORMAT_SPECIFICATION.md) | RAR 1.3/1.4. `RE~^` signature, adaptive Huffman, full encoder + decoder. |
| [`RAR15_40_FORMAT_SPECIFICATION.md`](RAR15_40_FORMAT_SPECIFICATION.md) | RAR 1.5, 2.0, 2.9/3.x, 4.x. `Rar!` 7-byte signature, block/subblock formats, Unpack15/20/29 compression, RARVM filters, AV, recovery records. |
| [`RAR5_FORMAT_SPECIFICATION.md`](RAR5_FORMAT_SPECIFICATION.md) | RAR 5.0/7.0. 8-byte signature, vint encoding, extra-area records, service headers, Unpack50/70, hardcoded filter enum. |

## Algorithms (version-agnostic primitives)

| Doc | Covers |
|-----|--------|
| [`HUFFMAN_CONSTRUCTION.md`](HUFFMAN_CONSTRUCTION.md) | Length-limited canonical Huffman build; per-version wire packing. |
| [`LZ_MATCH_FINDING.md`](LZ_MATCH_FINDING.md) | HC4/BT4 match finders, greedy/lazy/optimal parsing, cost functions. |
| [`PPMD_ALGORITHM_SPECIFICATION.md`](PPMD_ALGORITHM_SPECIFICATION.md) | PPMd variant H: model, SEE, range coder, 7-Zip vs RAR variants. Used by RAR 3.x/4.x. |
| [`FILTER_TRANSFORMS.md`](FILTER_TRANSFORMS.md) | E8/E8E9/DELTA/ARM/ITANIUM/RGB/AUDIO forward transforms; RAR 3.x VM vs RAR 5.0 hardcoded dispatch. |
| [`RARVM_SPECIFICATION.md`](RARVM_SPECIFICATION.md) | Generic RAR 3.x/4.x VM bytecode, operands, instruction semantics, invocation globals, and safety limits for non-standard filters. |
| [`CRC32_SPECIFICATION.md`](CRC32_SPECIFICATION.md) | IEEE 802.3 CRC32 — parameters, table, test vectors. |

## Write-side (encoder-specific decisions)

The format specs cover the wire layout the decoder must accept. These docs
cover the choices an **encoder** must make that the format alone doesn't pin
down — emit order, flag selection, salt/IV policy, padding, streaming.

| Doc | Covers |
|-----|--------|
| [`ARCHIVE_LEVEL_WRITE_SIDE.md`](ARCHIVE_LEVEL_WRITE_SIDE.md) | Block emit order, cross-reference graph, solid mode, multi-volume split, service headers, Quick Open cache, filesystem metadata, SFX stub. |
| [`ENCRYPTION_WRITE_SIDE.md`](ENCRYPTION_WRITE_SIDE.md) | All five encryption variants (RAR 1.3 through 5.0), key derivation, IV/salt rules, HMAC hashing, header encryption. |
| [`INTEGRITY_WRITE_SIDE.md`](INTEGRITY_WRITE_SIDE.md) | BLAKE2sp, 8-bit and 16-bit Reed–Solomon (`RSCoder`/`RSCoder16`), recovery-record layout, `.rev` files, per-block CRC ranges. |

## Implementation (reader-side + cross-cutting)

*To be written — see `IMPLEMENTATION_GAPS.md` for status.*

| Doc | Covers |
|-----|--------|
| [`READ_SIDE_OVERVIEW.md`](READ_SIDE_OVERVIEW.md) | End-to-end parser walkthrough: type detection, SFX scan, version dispatch, block iteration, streaming, error handling. |
| [`PATH_SANITIZATION.md`](PATH_SANITIZATION.md) | Extraction-side security: traversal guards, drive letters, reserved names, symlink target validation. |
| [`TEST_VECTORS.md`](TEST_VECTORS.md) | Consolidated known-good samples for every primitive and each version's micro-archives. |
| [`IMPLEMENTATION_GAPS.md`](IMPLEMENTATION_GAPS.md) | Open items, including the few that genuinely need ghidra (filter heuristics, `-m0..-m5` tables, IV policy). |

## Source references

All source-level citations point into `_refs/` (gitignored):

- `_refs/7zip/` — 7-Zip 25.01. Independent PPMd/Huffman/LzFind encoders and decoders.
- `_refs/XADMaster/` — The Unarchiver. Obj-C handlers for RAR 1.3–4.x, valuable for the undocumented 1.3 era.
