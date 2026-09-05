/// Append the low `count` bits most-significant first. Complete bytes are
/// extracted from a word; only the two edge bytes need masking. The final
/// partial byte stays zero-padded so callers can inspect or resume the buffer.
#[inline]
pub(crate) fn write_msb_bits(
    bytes: &mut Vec<u8>,
    bit_pos: &mut usize,
    value: u64,
    mut count: usize,
) {
    debug_assert!(count <= 64);
    debug_assert_eq!(bytes.len(), (*bit_pos).div_ceil(8));
    if count == 0 {
        return;
    }
    let used = *bit_pos % 8;
    *bit_pos += count;
    if used != 0 {
        let take = count.min(8 - used);
        count -= take;
        let mask = ((1u16 << take) - 1) as u8;
        *bytes.last_mut().unwrap() |= (((value >> count) as u8) & mask) << (8 - used - take);
    }
    if count == 0 {
        return;
    }
    let whole = count / 8;
    if whole != 0 {
        let aligned = (value << (64 - count)).to_be_bytes();
        bytes.extend_from_slice(&aligned[..whole]);
    }
    let tail = count % 8;
    if tail != 0 {
        bytes.push((value as u8) << (8 - tail));
    }
}

pub(crate) fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    if distance == 0 || distance > pos {
        return 0;
    }

    let max_length = max_length.min(input.len().saturating_sub(pos));
    match_length_scalar(input, pos, distance, max_length, 0)
}

fn match_length_scalar(
    input: &[u8],
    pos: usize,
    distance: usize,
    max_length: usize,
    mut length: usize,
) -> usize {
    while length + 32 <= max_length {
        for offset in [0, 8, 16, 24] {
            let current = u64::from_le_bytes(
                input[pos + length + offset..pos + length + offset + 8]
                    .try_into()
                    .unwrap(),
            );
            let previous = u64::from_le_bytes(
                input[pos + length + offset - distance..pos + length + offset - distance + 8]
                    .try_into()
                    .unwrap(),
            );
            let difference = current ^ previous;
            if difference != 0 {
                return length + offset + (difference.trailing_zeros() / 8) as usize;
            }
        }
        length += 32;
    }
    while length + 8 <= max_length {
        let current = u64::from_le_bytes(input[pos + length..pos + length + 8].try_into().unwrap());
        let previous = u64::from_le_bytes(
            input[pos + length - distance..pos + length - distance + 8]
                .try_into()
                .unwrap(),
        );
        let difference = current ^ previous;
        if difference != 0 {
            return length + (difference.trailing_zeros() / 8) as usize;
        }
        length += 8;
    }
    while length < max_length && input[pos + length] == input[pos + length - distance] {
        length += 1;
    }
    length
}

pub(crate) fn next_x86_opcode(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    let end = end_exclusive.min(data.len());
    if start >= end {
        return None;
    }

    next_x86_opcode_scalar(data, start, end_exclusive, cmp_mask)
}

fn next_x86_opcode_scalar(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    data[start..end_exclusive]
        .iter()
        .position(|&byte| byte & cmp_mask == 0xe8)
        .map(|offset| start + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_match_length(
        input: &[u8],
        pos: usize,
        distance: usize,
        max_length: usize,
    ) -> usize {
        let mut length = 0usize;
        while length < max_length && input[pos + length] == input[pos + length - distance] {
            length += 1;
        }
        length
    }

    #[test]
    fn match_length_matches_scalar_around_chunk_boundaries() {
        let mut input = Vec::new();
        input.extend((0..192).map(|index| (index % 251) as u8));
        input.extend_from_within(64..192);

        for distance in 1..=64 {
            let pos = 192usize;
            let max = (input.len() - pos).min(96);
            let expected = reference_match_length(&input, pos, distance, max);
            assert_eq!(match_length(&input, pos, distance, max), expected);
        }
    }

    #[test]
    fn match_length_stops_at_first_mismatch_in_chunk_tail() {
        let mut input = b"abcdefghijklmnopqrstuvwxyz012345".repeat(4);
        let pos = 64;
        input[pos + 37] ^= 0x55;

        assert_eq!(
            match_length(&input, pos, 32, 64),
            reference_match_length(&input, pos, 32, 64)
        );
    }

    #[test]
    fn x86_opcode_scan_matches_scalar_for_e8_and_e8e9() {
        let mut data = vec![0x41u8; 96];
        for pos in [0, 31, 32, 33, 63, 64, 91] {
            data[pos] = 0xe8;
        }
        data[47] = 0xe9;

        for &include_e9 in &[false, true] {
            let cmp_mask = if include_e9 { 0xfe } else { 0xff };
            let mut pos = 0usize;
            let mut found = Vec::new();
            while let Some(next) = next_x86_opcode(&data, pos, data.len() - 4, cmp_mask) {
                found.push(next);
                pos = next + 1;
            }

            let expected: Vec<_> = data
                .iter()
                .take(data.len() - 4)
                .enumerate()
                .filter_map(|(pos, &byte)| (byte & cmp_mask == 0xe8).then_some(pos))
                .collect();
            assert_eq!(found, expected);
        }
    }
}

#[cfg(test)]
mod bit_output_tests {
    use super::write_msb_bits;

    #[test]
    fn word_output_matches_bit_reference_at_every_alignment_and_width() {
        for offset in 0..8 {
            for width in 0..=64 {
                for value in [0, u64::MAX, 0x0123456789abcdef, 0xfedcba9876543210] {
                    let mut actual = Vec::new();
                    let mut at = 0;
                    let mut expected = Vec::new();
                    let mut bits = 0usize;
                    for (value, count) in [(0x55, offset), (value, width), (0x1234, 13)] {
                        write_msb_bits(&mut actual, &mut at, value, count);
                        for bit in (0..count).rev() {
                            if bits.is_multiple_of(8) {
                                expected.push(0);
                            }
                            *expected.last_mut().unwrap() |=
                                (((value >> bit) & 1) as u8) << (7 - bits % 8);
                            bits += 1;
                        }
                        assert_eq!(actual, expected, "offset={offset} width={width}");
                        assert_eq!(at, bits);
                    }
                }
            }
        }
    }
}
