# encrypted_members_multivol.part{1,2,3,4}.rar

RAR 7.23, `rar a -ma5 -m0 -v2k -tsm -ppassword`. Four 1500-byte members,
`m1.bin` to `m4.bin`, each split across two volumes, with CRC32s `0x2d62b28b`,
`0x9ac9e626`, `0xe8045ecc` and `0x64c8dbc2`. Password `password`.

The headers are plain and the data is encrypted, so the set parses without a
password and needs one only to extract. rar salts every member with the same
salt, so extracting the set should derive the key once rather than once per
member.
