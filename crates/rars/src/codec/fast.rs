#[cfg(feature = "fast")]
use std::simd::{cmp::SimdPartialEq, Simd};

#[cfg(feature = "fast")]
const LANES: usize = 32;

pub(crate) fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    if distance == 0 || distance > pos {
        return 0;
    }

    let max_length = max_length.min(input.len().saturating_sub(pos));
    match_length_impl(input, pos, distance, max_length)
}

#[cfg(feature = "fast")]
fn match_length_impl(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    let mut length = 0usize;
    while length + LANES <= max_length {
        let current = Simd::<u8, LANES>::from_slice(&input[pos + length..pos + length + LANES]);
        let previous = Simd::<u8, LANES>::from_slice(
            &input[pos + length - distance..pos + length - distance + LANES],
        );
        if let Some(mismatch) = current.simd_ne(previous).first_set() {
            return length + mismatch;
        }
        length += LANES;
    }

    match_length_scalar(input, pos, distance, max_length, length)
}

#[cfg(not(feature = "fast"))]
fn match_length_impl(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    match_length_scalar(input, pos, distance, max_length, 0)
}

fn match_length_scalar(
    input: &[u8],
    pos: usize,
    distance: usize,
    max_length: usize,
    mut length: usize,
) -> usize {
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

    next_x86_opcode_impl(data, start, end, cmp_mask)
}

#[cfg(feature = "fast")]
fn next_x86_opcode_impl(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    let mask = Simd::<u8, LANES>::splat(cmp_mask);
    let needle = Simd::<u8, LANES>::splat(0xe8);
    let mut pos = start;
    while pos + LANES <= end_exclusive {
        let bytes = Simd::<u8, LANES>::from_slice(&data[pos..pos + LANES]);
        if let Some(lane) = (bytes & mask).simd_eq(needle).first_set() {
            return Some(pos + lane);
        }
        pos += LANES;
    }

    next_x86_opcode_scalar(data, pos, end_exclusive, cmp_mask)
}

#[cfg(not(feature = "fast"))]
fn next_x86_opcode_impl(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
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
    fn match_length_matches_scalar_around_lane_boundaries() {
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
    fn match_length_stops_at_first_mismatch_in_vector_tail() {
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
