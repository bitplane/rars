# renamed_continuation.part01.rar, renamed_continuation.part02.rar

A two-volume set holding one member, `payload.txt`: 600 generated lines of the
form `line {i}: split continuation fixture payload {i*i % 977}`, 29,217 bytes.

Made with RAR 7.30 (`rar a -ma5 -m3 -v1500b`), then the continuation header in
the second volume was renamed to `PAYLOAD.TXT` and its header CRC rewritten.
UnRAR 7.23 extracts the member as `payload.txt` with a valid checksum.
