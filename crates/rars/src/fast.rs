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

    #[test]
    fn x86_opcode_scan_matches_reference_at_chunk_boundaries() {
        let mut data = vec![0x90u8; 128];
        for pos in [0, 1, 31, 32, 33, 63, 64, 95, 123] {
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
