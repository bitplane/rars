# final_match_overrun.rar

A solid archive of two members. `first.bin` is 1,000 noise bytes written twice;
`second.bin` is the first 500 of those bytes, 50 new noise bytes, then the last
500.

Made with RAR 7.23 (`rar a -ma5 -s -m3`), then `first.bin`'s declared size was
cut from 2,000 to 1,990 bytes and its CRC32 and header CRC rewritten. Its last
match now runs 10 bytes past the declared end. `second.bin` matches into those
10 bytes, so it decodes only if the reader keeps them in the window without
writing them out. UnRAR 7.23 extracts both members with valid checksums.
