use super::*;

fn original_peek(input: &[u8], position: usize, count: u8) -> Result<u32> {
    if count > 24 {
        return Err(Error::InvalidData("RAR 2.0 bit read is too wide"));
    }
    let mut value = 0;
    for i in 0..usize::from(count) {
        let pos = position + i;
        let byte = *input.get(pos / 8).ok_or(Error::NeedMoreInput)?;
        value = (value << 1) | u32::from((byte >> (7 - pos % 8)) & 1);
    }
    Ok(value)
}

#[test]
fn word_reads_preserve_values_errors_and_positions_at_every_alignment_and_tail() {
    fn check<B: Budget>(budget: &B) {
        for size in 0..=5 {
            for pattern in 0..=255u8 {
                let input: Vec<_> = (0..size)
                    .map(|i| pattern.rotate_left(i as u32 * 3))
                    .collect();
                let mut bits = BitReader::with_allowance(budget);
                bits.append(&input).unwrap();
                for position in 0..=size * 8 + 8 {
                    bits.bit_pos = position;
                    let expected = original_peek(&input, position, 1).map(|bit| bit as u16);
                    assert_eq!(bits.read_bit(), expected);
                    assert_eq!(bits.bit_pos, position + usize::from(expected.is_ok()));
                    for count in 0..=25 {
                        bits.bit_pos = position;
                        let expected = original_peek(&input, position, count);
                        assert_eq!(bits.peek_bits(count), expected);
                        assert_eq!(bits.bit_pos, position);
                        assert_eq!(bits.read_bits(count), expected);
                        assert_eq!(
                            bits.bit_pos,
                            position
                                + if expected.is_ok() {
                                    usize::from(count)
                                } else {
                                    0
                                }
                        );
                    }
                }
            }
        }
    }
    check(&Allowance::default());
    let budget = Allowance::limited(1024);
    check(&budget);
    assert_eq!(budget.used(), 0);
}

#[test]
fn huffman_lookup_preserves_results_and_consumption_for_every_prefix_and_tail() {
    fn check<B: Budget, const LOOKUP: bool>(budget: &B) {
        for lengths in [
            vec![],
            vec![0; 19],
            vec![1, 1],
            (1..=15).chain([15]).collect(),
            vec![0, 2, 2, 10, 11, 15],
            vec![15],
        ] {
            let original = Huffman::<B, LOOKUP>::with_lengths(&lengths, budget).unwrap();
            let table = original.try_clone().unwrap();
            drop(original);
            let mut bits = BitReader::with_allowance(budget);
            bits.append(&[0; 2]).unwrap();
            for prefix in 0..1u32 << 15 {
                for available in 0..=15 {
                    let word = (prefix >> (15 - available)) as u16;
                    bits.input.copy_from_slice(&word.to_be_bytes());
                    let start = 16 - available;
                    bits.bit_pos = start;
                    let mut position = start;
                    let expected = table.state.decode(
                        || {
                            let bit = original_peek(&bits.input, position, 1)?;
                            position += 1;
                            Ok(bit as u16)
                        },
                        "RAR 2.0 empty Huffman table",
                        "RAR 2.0 invalid Huffman code",
                    );
                    assert_eq!(
                        table.decode(&mut bits),
                        expected,
                        "prefix={prefix:#x}, available={available}, lengths={lengths:?}"
                    );
                    assert_eq!(
                        bits.bit_pos, position,
                        "prefix={prefix:#x}, available={available}, lengths={lengths:?}"
                    );
                }
            }
        }
    }
    check::<_, true>(&Allowance::default());
    check::<_, false>(&Allowance::default());
    let budget = Allowance::limited(64 * 1024);
    check::<_, true>(&budget);
    check::<_, false>(&budget);
    assert_eq!(budget.used(), 0);
}

#[test]
fn cloned_partial_byte_readers_compact_and_append_without_changing_bits() {
    fn check<B: Budget>(budget: &B) {
        let first = [0xa5, 0x3c, 0x96];
        let more = [0x7e, 0xe1, 0x09];
        let full = [first, more].concat();
        for position in 0..=24 {
            let mut original = BitReader::with_allowance(budget);
            original.append(&first).unwrap();
            original.bit_pos = position;
            let mut cloned = original.try_clone().unwrap();
            for bits in [&mut original, &mut cloned] {
                bits.append(&more).unwrap();
                assert_eq!(bits.bit_pos, position % 8);
                for count in 0..=24 {
                    assert_eq!(bits.peek_bits(count), original_peek(&full, position, count));
                }
            }
        }
    }
    check(&Allowance::default());
    let budget = Allowance::limited(1024);
    check(&budget);
    assert_eq!(budget.used(), 0);
}

#[test]
fn padded_peek_matches_individual_bits_at_every_byte_boundary() {
    for size in 0..=4 {
        for pattern in 0..=255u8 {
            let input: Vec<_> = (0..size)
                .map(|i| pattern.rotate_left(i as u32 * 3))
                .collect();
            let mut bits = BitReader::with_allowance(&Allowance::default());
            bits.append(&input).unwrap();
            for position in 0..=size * 8 + 8 {
                bits.bit_pos = position;
                let available = (size * 8).saturating_sub(position).min(15);
                let expected = (0..15).fold(0, |value, i| {
                    (value << 1) | original_peek(&input, position + i, 1).unwrap_or(0)
                });
                assert_eq!(bits.peek15(), (expected, available));
                assert_eq!(bits.bit_pos, position);
            }
        }
    }
}
