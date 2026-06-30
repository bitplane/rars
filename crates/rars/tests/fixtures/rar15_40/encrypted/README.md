# RAR 1.5-4.x Encryption Fixtures

Focused encryption fixtures for `rar15_40_fixtures.rs`.

| Fixture | Password | Source | Purpose |
|---|---|---|---|
| `header_enc_1234.rar` | `1234` | `node-unrar-js/HeaderEnc1234.rar` | Minimal third-party `MHD_PASSWORD` fixture. Used only to verify parsing without a password returns `NeedPassword`. |
| `header_rar300_password.rar` | `password` | spec repo `fixtures/1.5-4.x/rar300/header_encrypted_rar300.rar` | RAR 3.00 `-hp` header encryption. Decrypted `hello.txt` payload CRC32 is `0xa538535e`. |
| `header_rar420_password.rar` | `password` | spec repo `fixtures/1.5-4.x/rar420/header_encrypted_rar420.rar` | RAR 4.20 `-hp` cross-version header encryption. Same plaintext oracle as the RAR 3.00 fixture. |
| `per_file_rar300_password.rar` | `password` | spec repo `fixtures/1.5-4.x/rar300/encrypted_per_file_rar300.rar` | RAR 3.00 per-file AES-128 encryption. Decrypted `hello.txt` payload CRC32 is `0xa538535e`. |
| `per_file_rar4_libarchive_mixed.rar` | `password` | spec repo `fixtures/1.5-4.x/third_party/libarchive_rar4_mixed_encrypted.rar` | Focused RAR4 encrypted-compressed member oracle. Use member `b.txt` only; historical RAR 3.93 validates it as `This is from b.txt` with CRC32 `0xa9fa1485`, but rejects later member `d.txt` with a CRC/password error. |
| `rar4_junrar_password.rar` | `junrar` | spec repo `fixtures/1.5-4.x/third_party/junrar/rar4-password-junrar.rar` | Tiny RAR4 encrypted compressed member. Payload is `file1\n`, CRC32 `0xe229f704`; RAR 3.93 tests it OK. |
| `rar4_junrar_header_encrypted.rar` | `junrar` | spec repo `fixtures/1.5-4.x/third_party/junrar/rar4-encrypted-junrar.rar` | Tiny RAR4 header-encrypted archive with the same `file1.txt` payload. |
| `rar4_junrar_file_content_encrypted_unicode.rar` | `test` | spec repo `fixtures/1.5-4.x/third_party/junrar/rar4-only-file-content-encrypted.rar` | RAR4 per-file encrypted member with compact Unicode filename `新建文本文档.txt`; payload is `aaaaaaaaaa`, CRC32 `0x4c11cdf0`. |
| `rar4_sharpcompress_files_only.rar` | `test` | spec repo `fixtures/1.5-4.x/third_party/sharpcompress_rar4_encrypted_files_only.rar` | Whole-archive RAR4 per-file encryption fixture with three encrypted compressed files, three directories, and compact Unicode filename `тест.txt`; RAR 3.93 tests it OK. |
| `rar4_mixed_visible_names_password.rar` | `known-pass` | generated with WinRAR 4.20 under Wine | Mixed RAR4 fixture with visible names, one unencrypted stored member (`1File.txt`), one encrypted compressed compact-Unicode member (`2中文.txt`), and one encrypted compressed ASCII member (`3Sec.txt`). Replaces the old `node-unrar-js/FileEncByName.rar` partial oracle whose member passwords were unknown. |
