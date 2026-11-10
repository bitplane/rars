# Fixture licensing

Every file under `tests/fixtures/` is covered by this list.

## Files made for this project

Everything not listed under the other headings below was made for rars. The
payloads are synthetic: generated text, byte patterns, noise, a speech-shaped
signal, or files this project wrote. They are archived either by rars or by a
RAR encoder run on those payloads, and are released under the project's
Apache-2.0 licence (see `COPYING`).

`scripts/generate-clean-fixtures.py` in the repository regenerates the
fixtures that replaced third-party content in issue #118: the RAR 1.402
`README` set, the solid PPMd, Unpack20 keep-tables and audio archives, the
RAR 1.5 audio archives, the RAR 4 encryption fixtures, and the 64 KiB E8E9
filter archive.

## Format output kept for interoperability

| File | What it is |
|---|---|
| `rar13/SFXSRC.EXE` | Made by running the DOS RAR 1.402 `s` command on `HELLO.TXT`, a 33-byte line this project wrote. The first 6.4 KiB are the self-extractor module that RAR 1.402 prepends to the archive; that module is RAR's own code, not this project's. It is kept because the format uses it to signal a self-extracting archive: readers must recognise the `RSFX` marker at offset 28 to tell a real RAR 1.4 self-extractor from an executable that only contains the archive signature. |

## Third-party fixtures

These are copied unmodified from other projects' test suites, under the
licences below.

| File | Upstream | Licence |
|---|---|---|
| `rar15_40/encrypted/per_file_rar4_libarchive_mixed.rar` | libarchive `libarchive/test/test_read_format_rar4_encrypted.rar.uu`, uudecoded | BSD-2-Clause (libarchive) |
| `rar50/wild/hardlink.rar` | libarchive `libarchive/test/test_read_format_rar5_hardlink.rar.uu`, uudecoded | BSD-2-Clause (libarchive) |
| `rar50/wild/symlink.rar` | libarchive `libarchive/test/test_read_format_rar5_symlink.rar.uu`, uudecoded | BSD-2-Clause (libarchive) |
| `rar50/wild/invalid_hash_valid_htime_exfld.rar` | libarchive `libarchive/test/test_read_format_rar5_invalid_hash_valid_htime_exfld.rar.uu`, uudecoded | BSD-2-Clause (libarchive) |
| `rar50/wild/libarchive_loop_bug.rar` | libarchive `libarchive/test/test_read_format_rar5_loop_bug.rar.uu`, uudecoded | BSD-2-Clause (libarchive) |
| `rar50/wild/libarchive_multiple_files_solid.rar` | libarchive `libarchive/test/test_read_format_rar5_multiple_files_solid.rar.uu`, uudecoded | BSD-2-Clause (libarchive) |
| `rar50/wild/libarchive_solid.rar` | libarchive `libarchive/test/test_read_format_rar5_solid.rar.uu`, uudecoded | BSD-2-Clause (libarchive) |
| `rar15_40/rar202/comment_nopsw.rar` | rarfile `test/files/rar202-comment-nopsw.rar` | ISC (rarfile) |
| `rar15_40/rar202/comment_psw.rar` | rarfile `test/files/rar202-comment-psw.rar` | ISC (rarfile) |
| `rar15_40/wild/rarfile_unix_owner.rar` | rarfile `test/files/rar2-unix-owner.rar` | ISC (rarfile) |
| `rar50/wild/rarfile_hlink.rar` | rarfile `test/files/rar5-hlink.rar` | ISC (rarfile) |
| `rar50/wild/rarfile_solid.rar` | rarfile `test/files/rar5-solid.rar` | ISC (rarfile) |
| `rar50/wild/rarfile_solid_qo.rar` | rarfile `test/files/rar5-solid-qo.rar` | ISC (rarfile) |
| `rar15_40/node_unrar_js/with_comment.rar` | node-unrar-js `testFiles/WithComment.rar` | MIT (node-unrar-js) |
| `rar15_40/encrypted/header_enc_1234.rar` | node-unrar-js `testFiles/HeaderEnc1234.rar` | MIT (node-unrar-js) |
| `rar15_40/ppmd/ppmd_lz_repeat_rar3.cbr` | ssokolow/rar-test-files `build/testfile.rar3.cbr` | CC0-1.0 |
| `tz/*` | Compiled zones from the IANA time zone database | Public domain |

Upstream projects:

- libarchive: <https://github.com/libarchive/libarchive>
- rarfile: <https://github.com/markokr/rarfile>
- node-unrar-js: <https://github.com/YuJianrong/node-unrar.js>
- rar-test-files: <https://github.com/ssokolow/rar-test-files>
- tz database: <https://www.iana.org/time-zones>

### libarchive (BSD-2-Clause)

```text
Copyright (c) 2003-2018 <author(s)>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer
   in this position and unchanged.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### rarfile (ISC)

```text
Copyright (c) 2005-2026 Marko Kreen <markokr@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

### node-unrar-js (MIT)

```text
Copyright (c) 2017 Jianrong Yu.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### rar-test-files (CC0-1.0)

Stephan Sokolow has waived all copyright and related or neighbouring rights
to RAR Test Files under the Creative Commons CC0 1.0 Universal public domain
dedication: <https://creativecommons.org/publicdomain/zero/1.0/>.
