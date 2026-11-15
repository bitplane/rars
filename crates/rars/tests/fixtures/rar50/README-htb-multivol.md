# htb_multivol.part{1,2,3}.rar

RAR 7.30 beta 2, `rar a -ma5 -m0 -htb -v2k -tsm -tsc- -tsa-`. One stored
5000-byte member, `payload.bin`, CRC32 `0x796034e6`, split across three
volumes. The bytes are the high byte of an LCG
(`x = x * 1103515245 + 12345`, seed `0x12345678`).

No fragment carries a CRC32. Each non-final fragment's BLAKE2sp hash record
covers the bytes that volume stores; the final fragment's covers the whole
member.

## htb_multivol_p.part{1,2,3}.rar, htb_multivol_hp.part{1,2,3,4}.rar

The same member and switches, plus `-ppassword` and `-hppassword`
respectively. The password is `password`.

Every fragment is encrypted, but only the final one sets the hash-MAC flag.
Each non-final fragment's hash record is unkeyed BLAKE2sp over the ciphertext
that volume stores, so it can be checked without the password.
