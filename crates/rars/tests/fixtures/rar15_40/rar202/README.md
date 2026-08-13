# RAR 2.02 Fixtures

Copied from the spec repository's `fixtures/2.02/` directory.

These archives pin three RAR 2.x behaviors:

- old-format main-header comments: the embedded comment subblock is included in
  `HEAD_SIZE` but not in the main-header `HEAD_CRC`;
- old-format file comments: the same comment subblock, embedded in a file
  header, with `HEAD_CRC` again covering only the fields the reader parses;
- RAR 2.0 `CRYPT_RAR20` encrypted compressed members (`comment_psw.rar`,
  password `password`).

unrar 7.20 counts one silent error per comment-bearing header in these files
and exits 3, because its second header CRC check (`arcread.cpp`, the
`GetCRC15(false)` one after the block switch) has no exemption for the comment
the first check skips. Members still test and extract correctly. Any archive
written this way, by us or by WinRAR, gets the same treatment, so a non-zero
unrar exit code on a file-comment archive is expected and not a sign the writer
has broken.

Payloads:

- `FILE1.TXT` = `file1\r\n`, CRC32 `0x7a197dba`
- `FILE2.TXT` = `file2\r\n`, CRC32 `0x785fc3e3`
