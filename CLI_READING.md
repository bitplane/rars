# CLI reader controls

`info`, `test` and `extract` (`x`) accept the same optional limits:

| Flag | Scope |
| --- | --- |
| `--max-header-count COUNT` | Number of parsed headers per archive/volume |
| `--max-header-bytes SIZE` | Parsed header bytes per archive/volume |
| `--max-member-output-bytes SIZE` | Logical output of one member or archive comment |
| `--max-total-output-bytes SIZE` | Logical output across a decoding call, including a volume set |
| `--rar50-dictionary-size-limit SIZE` | Declared RAR5/7 dictionary size |
| `--rar50-buffered-decode-limit SIZE` | RAR5/7 buffered decoding allowance |

Sizes accept bytes or binary suffixes such as `64m`. Zero is a real limit;
omitting a flag retains the library default. Header limits also apply during
password retries. Output limits apply to archive comments displayed by `info`;
legacy embedded member comments use their existing decoding path.

```sh
rars test --max-header-count 10000 --max-member-output-bytes 256m archive.rar
rars x --max-total-output-bytes 1g archive.rar out/
```

For RAR5/7 filtered decoding, `--rar50-scratch-dir PATH` and
`--rar50-scratch-bytes SIZE` enable bounded scratch storage together.
`--rar50-filter-memory-limit SIZE` optionally sets the in-memory filter allowance
and requires scratch storage. Scratch files are cleaned up when decoding ends.
These controls do not set an aggregate process-memory ceiling. Dictionary,
packed input, concurrent jobs and other retained state have separate costs.

A limit failure can leave earlier extracted members or a failing member's
prefix. An unknown-size logical RAR5 member is refused when a member-output
limit is configured; this does not add decode-to-end support.
