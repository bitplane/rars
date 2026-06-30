# RAR 2.02 Fixtures

Copied from the spec repository's `fixtures/2.02/` directory.

These archives pin two RAR 2.x behaviors:

- old-format main-header comments: the embedded comment subblock is included in
  `HEAD_SIZE` but not in the main-header `HEAD_CRC`;
- RAR 2.0 `CRYPT_RAR20` encrypted compressed members (`comment_psw.rar`,
  password `password`).

Payloads:

- `FILE1.TXT` = `file1\r\n`, CRC32 `0x7a197dba`
- `FILE2.TXT` = `file2\r\n`, CRC32 `0x785fc3e3`
