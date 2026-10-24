use super::*;

#[test]
fn padded_peek_matches_individual_bits_at_every_byte_boundary() {
    for size in 0..=4 {
        for pattern in 0..=255u8 {
            let input: Vec<_> = (0..size)
                .map(|i| pattern.rotate_left(i as u32 * 3))
                .collect();
            let mut bits = BitReader::new(&input);
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
        let table = HuffmanState::from_lengths(&[len as u8], &Allowance::default()).unwrap();
        for available in 0..=16 {
            let input = [0u8; 2];
            let mut bits = BitReader::new(&input);
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
fn empty_rar50_table_needs_no_workspace() {
    let budget = Allowance::limited(0);
    let table = HuffmanState::from_lengths(&[0; 16], &budget).unwrap();
    assert!(table.is_empty());
    assert_eq!(budget.used(), 0);
    assert_eq!(
        table.decode(&mut BitReader::new(&[])),
        Err(Error::InvalidData("RAR 5 empty Huffman table"))
    );
}
