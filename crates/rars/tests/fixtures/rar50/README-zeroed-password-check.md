# zeroed_password_check.rar

A WinRAR 7.12 archive (`rar a -ma5 -m0 -psecret`, one member `s.txt`) with the
file header's 8-byte `PswCheck` field overwritten with zeros, its trailing
4-byte checksum recomputed over those zeros, and the header CRC32 recomputed.
Password `secret`.

WinRAR 5.21 and earlier wrote this shape for real: they set
`FHEXTRA_CRYPT_PSWCHECK` and then left the field zero. A reader that verifies
it rejects the correct password, so those archives cannot be opened at all.

RAR 7.12 treats an all-zero field as no check. Measured on this archive and its
unmodified original:

| `PswCheck` | Correct password | Wrong password |
|---|---|---|
| genuine | `All OK` | `Incorrect password for s.txt` |
| all zeros | `All OK` | `Checksum error in the encrypted file s.txt` |

The changed wrong-password message is the evidence that the explicit check
stopped running and detection fell through to the data checksum. A wrong
password is still refused, just later and by a different mechanism.

Hand-crafted, since WinRAR 7.12 does not emit this shape.
