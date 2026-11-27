/// Append the low `count` bits most-significant first. Complete bytes are
/// extracted from a word; only the two edge bytes need masking. The final
/// partial byte stays zero-padded so callers can inspect or resume the buffer.
#[inline]
#[cfg(any(test, feature = "write"))]
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

/// How many bytes at `pos` repeat those `distance` back, up to `max_length`
/// and the end of `input`.
///
/// Compares a word at a time and finds the first differing byte from the
/// lowest set bit of the XOR. Small enough to inline into the match finders,
/// where most calls end inside the first word.
#[cfg(any(test, feature = "write"))]
#[inline]
pub(crate) fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    // Encoders supply older match-finder candidates or remembered distances
    // already admitted at an earlier position in this forward-moving parse.
    debug_assert!(distance != 0 && distance <= pos);

    let Some(current) = input.get(pos..) else {
        return 0;
    };
    let max_length = max_length.min(current.len());
    let current = &current[..max_length];
    let previous = &input[pos - distance..][..max_length];
    let mut length = 0;
    let (current_words, _) = current.as_chunks::<8>();
    let (previous_words, _) = previous.as_chunks::<8>();
    for (current, previous) in current_words.iter().zip(previous_words) {
        let difference = u64::from_le_bytes(*current) ^ u64::from_le_bytes(*previous);
        if difference != 0 {
            return length + (difference.trailing_zeros() / 8) as usize;
        }
        length += 8;
    }
    if length < max_length && max_length >= 8 {
        // The last word overlaps bytes already proven equal, so its first
        // difference is still the first one past `length`.
        let last = max_length - 8;
        let difference = u64::from_le_bytes(current[last..].try_into().unwrap())
            ^ u64::from_le_bytes(previous[last..].try_into().unwrap());
        return if difference == 0 {
            max_length
        } else {
            last + (difference.trailing_zeros() / 8) as usize
        };
    }
    while length < max_length && current[length] == previous[length] {
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

    let haystack = &data[start..end];
    let offset = if cmp_mask == 0xff {
        memchr::memchr(0xe8, haystack)
    } else {
        debug_assert_eq!(cmp_mask, 0xfe);
        memchr::memchr2(0xe8, 0xe9, haystack)
    };
    offset.map(|found| start + found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_scan_clamps_the_end_and_handles_empty_extents() {
        assert_eq!(next_x86_opcode(b"a\xe8b", 0, usize::MAX, 0xff), Some(1));
        assert_eq!(next_x86_opcode(b"a\xe8b", 2, usize::MAX, 0xff), None);
        assert_eq!(
            next_x86_opcode(b"a\xe8b", usize::MAX, usize::MAX, 0xff),
            None
        );
        assert_eq!(next_x86_opcode(b"a\xe8b", 1, 1, 0xff), None);
        assert_eq!(next_x86_opcode(b"", 0, usize::MAX, 0xff), None);
        assert_eq!(next_x86_opcode(b"", 0, usize::MAX, 0xfe), None);
    }

    fn all_x86_opcodes(data: &[u8], cmp_mask: u8) -> Vec<usize> {
        let mut found = Vec::new();
        let mut pos = 0;
        while let Some(next) = next_x86_opcode(data, pos, data.len(), cmp_mask) {
            found.push(next);
            pos = next + 1;
        }
        found
    }

    #[test]
    fn opcode_scan_finds_opcodes_at_the_first_and_last_byte() {
        let data = b"\xe8a\xe9\xe8cd\xe8";
        assert_eq!(all_x86_opcodes(data, 0xff), [0, 3, 6]);
        assert_eq!(all_x86_opcodes(data, 0xfe), [0, 2, 3, 6]);
        assert!(all_x86_opcodes(b"\xe9", 0xff).is_empty());
        assert_eq!(all_x86_opcodes(b"\xe9", 0xfe), [0]);
        assert_eq!(next_x86_opcode(data, 4, 6, 0xff), None);
        assert_eq!(next_x86_opcode(data, 4, 7, 0xff), Some(6));
    }

    #[test]
    fn opcode_scan_visits_every_opcode_in_sparse_and_dense_data() {
        let mut state = 0x9e37_79b9u32;
        let mut sparse = vec![0u8; 1 << 16];
        for byte in &mut sparse {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        // Calls and jumps every few bytes, as in compiled code.
        let dense: Vec<u8> = (0..1 << 16)
            .map(|index| match index % 7 {
                0 => 0xe8,
                3 if index % 2 == 0 => 0xe9,
                _ => (index * 31) as u8 & 0x7f,
            })
            .collect();

        for data in [&sparse, &dense] {
            for (cmp_mask, opcodes) in [(0xff, &[0xe8][..]), (0xfe, &[0xe8, 0xe9][..])] {
                let expected: Vec<_> = (0..data.len())
                    .filter(|&pos| opcodes.contains(&data[pos]))
                    .collect();
                assert!(!expected.is_empty());
                assert_eq!(all_x86_opcodes(data, cmp_mask), expected);
            }
        }
    }

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
    fn match_length_clamps_the_requested_extent_at_input_end() {
        let input = b"abcdabcdabcdabcd";
        for pos in 1..=input.len() {
            for distance in 1..=pos {
                for requested in [0, 1, 3, 8, 32, usize::MAX] {
                    let available = requested.min(input.len() - pos);
                    assert_eq!(
                        match_length(input, pos, distance, requested),
                        reference_match_length(input, pos, distance, available),
                        "pos={pos}, distance={distance}, requested={requested}"
                    );
                }
            }
        }
        // The public RAR13 match finder also permits positions past EOF.
        // There are no bytes to compare, so no indexing is attempted.
        assert_eq!(match_length(input, input.len() + 1, 1, usize::MAX), 0);
        assert_eq!(match_length(input, usize::MAX, usize::MAX, usize::MAX), 0);
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
    fn match_length_finds_every_mismatch_offset_at_every_extent() {
        let base: Vec<u8> = (0..40u8).collect();
        let mut input = base.clone();
        input.extend_from_slice(&base);
        let pos = base.len();
        for mismatch in 0..=base.len() {
            let mut input = input.clone();
            if mismatch < base.len() {
                input[pos + mismatch] ^= 0x80;
            }
            for max in 0..=base.len() {
                assert_eq!(
                    match_length(&input, pos, pos, max),
                    reference_match_length(&input, pos, pos, max),
                    "mismatch={mismatch}, max={max}"
                );
            }
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
