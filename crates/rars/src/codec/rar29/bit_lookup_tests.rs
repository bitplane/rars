use super::*;

#[test]
fn padded_peek_matches_individual_bits_at_every_byte_boundary() {
    for size in 0..=4 {
        for pattern in 0..=255u8 {
            let input: Vec<_> = (0..size)
                .map(|i| pattern.rotate_left(i as u32 * 3))
                .collect();
            let mut bits =
                BitReader::from_bytes_with_allowance(&input, &Allowance::default()).unwrap();
            for position in 0..=size * 8 + 8 {
                bits.bit_pos = position;
                let available = (size * 8).saturating_sub(position).min(15);
                let expected = (0..15).fold(0, |value, i| {
                    let pos = position + i;
                    let bit = input.get(pos / 8).map_or(0, |b| (b >> (7 - pos % 8)) & 1);
                    (value << 1) | u32::from(bit)
                });
                assert_eq!(bits.peek15(), (expected, available));
                assert_eq!(bits.bit_pos, position);
            }
        }
    }
}

#[test]
fn short_and_long_codes_require_real_bits_and_consume_exact_lengths() {
    for len in [1, 10, 11, 15] {
        let table =
            Huffman::from_lengths_with_allowance(&[len as u8], &Allowance::default()).unwrap();
        for available in 0..=16 {
            let input = [0u8; 2];
            let mut bits =
                BitReader::from_bytes_with_allowance(&input, &Allowance::default()).unwrap();
            bits.bit_pos = 16 - available;
            if available < len {
                assert_eq!(table.decode(&mut bits), Err(Error::NeedMoreInput));
                assert_eq!(bits.bit_pos, 16 - available);
            } else {
                assert_eq!(table.decode(&mut bits), Ok(0));
                assert_eq!(bits.bit_pos, 16 - available + len);
            }
        }
    }
}

#[test]
fn wide_peeks_match_bitwise_reads_for_every_width_and_offset() {
    for size in 0..=4 {
        let input = [0xa5, 0x3c, 0x96, 0x7e][..size].to_vec();
        let mut bits = BitReader::from_bytes_with_allowance(&input, &Allowance::default()).unwrap();
        for position in 0..=size * 8 + 8 {
            bits.bit_pos = position;
            for count in 0..=24 {
                let expected = if count > 0 && position + count > size * 8 {
                    Err(Error::NeedMoreInput)
                } else {
                    Ok((0..count).fold(0u32, |value, i| {
                        let pos = position + i;
                        (value << 1) | u32::from((input[pos / 8] >> (7 - pos % 8)) & 1)
                    }))
                };
                assert_eq!(
                    bits.peek_bits(count as u8),
                    expected,
                    "size={size} position={position} count={count}"
                );
                assert_eq!(bits.bit_pos, position);
            }
            assert_eq!(
                bits.peek_bits(25),
                Err(Error::InvalidData("RAR 2.9 bit read is too wide"))
            );
        }
    }
}
