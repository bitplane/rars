# header_encrypted_stored_multivol.part{1,2,3}.rar

WinRAR 7.12, `rar a -ma5 -v2k -m0 -hppassword`. One 4096-byte member,
`stored_4k.bin`, CRC32 `0xa087a9af`, split across three volumes. Password
`password`.

Stored and header-encrypted and split, which is the combination that reaches
the stored-split verification path. rars used to apply the encrypted-checksum
transform there for any encrypted file rather than only when the crypt record
asks for it, so this archive failed with a checksum mismatch while extracting
the correct bytes. Compressed volume sets took a different path and were
unaffected, which is why the existing `encrypted_multivol` fixtures did not
catch it.
