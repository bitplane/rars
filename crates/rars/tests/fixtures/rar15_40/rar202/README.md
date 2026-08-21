# RAR 2.02 Fixtures

Copied from the spec repository's `fixtures/2.02/` directory.

These archives pin three RAR 2.x behaviors:

- old-format main-header comments: the embedded comment subblock is included in
  `HEAD_SIZE` but not in the main-header `HEAD_CRC`;
- old-format file comments: the same comment subblock, embedded in a file
  header, with `HEAD_CRC` again covering only the fields the reader parses;
- RAR 2.0 `CRYPT_RAR20` encrypted compressed members (`comment_psw.rar`,
  password `password`).

unrar 7.20 counts one silent error per comment-bearing header in these files.
Both archives hold three such headers, the main-header comment and one per
file, and both report `Total errors: 3` and exit 3 while every member still
tests OK. So unrar checks the header CRC a second time somewhere past the
point that skips the comment bytes, and that second check has no matching
exemption.

These are WinRAR 2.02's own archives, so a non-zero unrar exit code on a
comment-bearing RAR 2.x file is expected and not a sign our writer has
broken.

Payloads:

- `FILE1.TXT` = `file1\r\n`, CRC32 `0x7a197dba`
- `FILE2.TXT` = `file2\r\n`, CRC32 `0x785fc3e3`
