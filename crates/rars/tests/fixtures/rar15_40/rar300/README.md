# RAR 3.00 Container Fixtures

RAR 3.00 fixtures for the RAR 1.5-4.x container. Most files are copied from the
spec repository's `fixtures/1.5-4.x/rar300/` and `fixtures/rarvm/archives-rar300/`
sets; several compact multivolume and solid fixtures are local regression
cases.

| Fixture group | Purpose |
|---|---|
| `with_comment_rar300.rar` | Stored `hello.txt` plus RAR 3.x archive comment subblock. |
| `header_encrypted_multivol_rar300*`, `header_encrypted_newnaming_rar300*` | Header-encrypted old/new-numbered multi-volume extraction. |
| `compressed_text_rar300.rar` | Basic Unpack29 LZ compressed text member. |
| `solid_rar300.rar`, `solid_simple_rar300.rar` | Solid Unpack29 state and table reuse. |
| `multivol_*_rar300*` | Old/new RAR 3 volume naming flags and split-file extraction. |
| `stored_multivol_rar300*`, `compressed_multivol_prng_rar300*`, `encrypted_multivol_rar300*`, `encrypted_newnaming_rar300*` | Streaming stored, compressed, and AES-encrypted split-volume extraction. |
| `rev_oldstyle.*`, `rev_newstyle.*` | RAR 3.00 old-style and RAR 4.20 new-style `.rev` recovery-volume repair. |
| `rarvm_*_rar300.rar` | Standard RARVM filters: E8, E8E9, DELTA, ITANIUM, RGB, AUDIO. |
| `with_compressed_recovery_rar300.rar` | Derived from `with_recovery_rar300.rar` by recompressing the `RR` NewSub recovery payload with the local RAR29 literal encoder, setting method `0x33`, and recomputing the header CRC. |
| `with_compressed_recovery_header_synthetic.rar` | Derived from `with_recovery_rar300.rar` with the `RR` NewSub method byte changed from store (`0x30`) to compressed (`0x33`) and the header CRC recomputed, but with the stored payload left unchanged. It pins corrupt compressed-RR error handling. |

Expected payloads and CRCs are asserted directly in
`rar15_40_fixtures.rs`.
