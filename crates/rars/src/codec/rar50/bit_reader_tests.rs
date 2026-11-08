use super::{Allowance, BitReader, Error, HuffmanState, Result};

fn bitwise_read(input: &[u8], cursor: &mut usize, count: u8) -> Result<u32> {
    let count = usize::from(count);
    let byte = *cursor / 8;
    let span = (*cursor % 8 + count).div_ceil(8);
    if span > input.len().saturating_sub(byte) {
        return Err(Error::NeedMoreInput);
    }
    let mut value = 0u32;
    for _ in 0..count {
        value = (value << 1) | u32::from((input[*cursor / 8] >> (7 - *cursor % 8)) & 1);
        *cursor += 1;
    }
    Ok(value)
}

fn bitwise_peek15(input: &[u8], cursor: usize) -> (u32, usize) {
    let peek = (0..15).fold(0, |value, i| {
        let pos = cursor + i;
        let bit = input.get(pos / 8).map_or(0, |b| (b >> (7 - pos % 8)) & 1);
        (value << 1) | u32::from(bit)
    });
    (peek, (input.len() * 8).saturating_sub(cursor).min(15))
}

#[test]
fn word_reads_match_independent_bits_at_every_alignment_and_physical_tail() {
    for input in [
        [0; 40],
        [0xff; 40],
        std::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(11)),
    ] {
        for size in 0..=input.len() {
            for start in 0..=size * 8 {
                for count in 0..=40 {
                    let mut expected_cursor = start;
                    let expected = bitwise_read(&input[..size], &mut expected_cursor, count);
                    let mut actual = BitReader::at(&input[..size], start);
                    assert_eq!(
                        actual.read_bits(count),
                        expected,
                        "size={size}, start={start}, count={count}"
                    );
                    assert_eq!(actual.position(), expected_cursor);
                }
            }
        }
    }
}

#[test]
fn word_reads_preserve_mixed_sequences_and_wider_low_word_results() {
    let input: Vec<_> = (0..4096usize)
        .map(|index| (index as u8).wrapping_mul(71).wrapping_add(29))
        .collect();
    let mut actual = BitReader::new(&input);
    let mut expected_cursor = 0;
    for count in [1, 4, 0, 8, 15, 26, 32, 33, 64, 127, 255]
        .into_iter()
        .cycle()
        .take(500)
    {
        let expected = bitwise_read(&input, &mut expected_cursor, count);
        assert_eq!(actual.read_bits(count), expected);
        assert_eq!(actual.position(), expected_cursor);
    }
}

#[test]
fn refused_wide_read_consumes_nothing() {
    let input = [0xa5u8; 5];
    for start in 0..=40 {
        for count in [33, 40, 64, 255] {
            let mut expected_cursor = start;
            let expected = bitwise_read(&input, &mut expected_cursor, count);
            let mut actual = BitReader::at(&input, start);
            assert_eq!(actual.read_bits(count), expected);
            assert_eq!(
                actual.position(),
                expected_cursor,
                "start={start}, count={count}"
            );
        }
    }
}

#[test]
fn peeks_skips_and_reads_interleave_across_refills_and_tails() {
    let source: Vec<_> = (0..64usize)
        .map(|index| (index as u8).wrapping_mul(53).wrapping_add(7))
        .collect();
    for size in 0..=source.len() {
        let input = &source[..size];
        for start in 0..8.min(size * 8 + 1) {
            let mut actual = BitReader::at(input, start);
            let mut cursor = start;
            for step in 0usize.. {
                let (peek, available) = bitwise_peek15(input, cursor);
                assert_eq!(
                    actual.peek15(),
                    (peek, available),
                    "size={size}, cursor={cursor}"
                );
                if available == 0 {
                    break;
                }
                if step % 3 == 2 {
                    let count = (step % 29) as u8;
                    let expected = bitwise_read(input, &mut cursor, count);
                    assert_eq!(actual.read_bits(count), expected);
                } else {
                    let count = (step % 15 + 1).min(available);
                    actual.skip(count);
                    cursor += count;
                }
                assert_eq!(actual.position(), cursor);
            }
        }
    }
}

fn literal_table() -> HuffmanState<Allowance> {
    let mut lengths = vec![0u8; 306];
    lengths[..254].fill(8);
    lengths[254] = 9;
    lengths[262] = 9;
    lengths[255..=261].fill(11);
    lengths[263] = 11;
    HuffmanState::from_lengths(&lengths, &Allowance::default()).unwrap()
}

fn generic_literals(
    table: &HuffmanState<Allowance>,
    input: &[u8],
    start: usize,
    end: usize,
    room: usize,
) -> (Vec<u8>, usize) {
    let mut bits = BitReader::at(input, start);
    let mut out = Vec::new();
    while out.len() < room && bits.position() < end {
        let before = bits.position();
        match table.decode(&mut bits) {
            Ok(symbol @ 0..=255) => out.push(symbol as u8),
            _ => return (out, before),
        }
    }
    (out, bits.position())
}

#[test]
fn literal_burst_matches_generic_decode_and_stops_where_it_must() {
    let table = literal_table();
    let input: Vec<_> = (0..96usize)
        .map(|index| (index as u8).wrapping_mul(97).wrapping_add(3))
        .collect();
    for size in [0, 1, 2, 7, 8, 9, 40, 96] {
        let input = &input[..size];
        for start in [0, 3, 7] {
            if start > size * 8 {
                continue;
            }
            for end in [0, 5, 64, 300, size * 8, usize::MAX] {
                for room in [0, 1, 3, 40, 256] {
                    let (expected, position) = generic_literals(&table, input, start, end, room);
                    let mut bits = BitReader::at(input, start);
                    let mut out = [0u8; 256];
                    let count = bits.literal_burst(&table, end, &mut out[..room]);
                    assert!(count <= expected.len());
                    assert_eq!(
                        &out[..count],
                        &expected[..count],
                        "size={size}, start={start}"
                    );
                    if count == expected.len() {
                        assert_eq!(bits.position(), position);
                    } else {
                        assert_eq!(
                            expected[count], 255,
                            "only long-code literals end a burst early"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn literal_burst_leaves_codes_past_the_input_end_to_the_generic_decoder() {
    let table = literal_table();
    let input = [0u8];
    let mut bits = BitReader::at(&input, 1);
    let mut out = [0u8; 4];
    assert_eq!(bits.literal_burst(&table, usize::MAX, &mut out), 0);
    assert_eq!(bits.position(), 1);
    assert_eq!(table.decode(&mut bits), Err(Error::NeedMoreInput));
    assert_eq!(bits.position(), 1);
}
