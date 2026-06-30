use std::ops::Range;

const AUTO_X86_CLUSTER_GAP: usize = 4096;
const AUTO_X86_TIGHT_CLUSTER_GAP: usize = 512;
const AUTO_X86_SPAN_CLUSTER_GAP: usize = 32768;
const AUTO_X86_RANGE_PADDING: usize = 16;
const AUTO_X86_MAX_RANGES: usize = 8;
const AUTO_X86_MAX_SPAN_RANGES: usize = 4;
const AUTO_X86_MIN_SPAN_OPCODES: usize = 4;

pub(crate) fn auto_x86_filter_ranges(data: &[u8], include_e9: bool) -> Vec<Range<usize>> {
    let mut ranges =
        auto_x86_filter_ranges_with_cluster_gap(data, include_e9, AUTO_X86_CLUSTER_GAP);
    for range in
        auto_x86_filter_ranges_with_cluster_gap(data, include_e9, AUTO_X86_TIGHT_CLUSTER_GAP)
    {
        if !ranges.contains(&range) {
            ranges.push(range);
        }
    }
    ranges
}

fn auto_x86_filter_ranges_with_cluster_gap(
    data: &[u8],
    include_e9: bool,
    cluster_gap: usize,
) -> Vec<Range<usize>> {
    if data.len() <= 5 {
        return Vec::new();
    }

    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let mut clusters = Vec::new();
    let mut current: Option<(usize, usize, usize)> = None;
    let mut scan_pos = 0usize;
    while let Some(pos) = crate::fast::next_x86_opcode(data, scan_pos, data.len() - 4, cmp_mask) {
        match current {
            Some((start, last, count)) if pos - last <= cluster_gap => {
                current = Some((start, pos, count + 1));
            }
            Some(cluster) => {
                clusters.push(cluster);
                current = Some((pos, pos, 1));
            }
            None => current = Some((pos, pos, 1)),
        }
        scan_pos = pos + 1;
    }
    if let Some(cluster) = current {
        clusters.push(cluster);
    }

    clusters.retain(|&(_, _, count)| count >= 2);
    let mut ranges = Vec::new();
    let mut span_count = 0;
    let mut span: Option<(usize, usize, usize)> = None;
    for &(start, last, count) in &clusters {
        match span {
            Some((span_start, span_last, span_opcodes))
                if start.saturating_sub(span_last) <= AUTO_X86_SPAN_CLUSTER_GAP =>
            {
                span = Some((span_start, last, span_opcodes + count));
            }
            Some((span_start, span_last, span_opcodes)) => {
                if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES
                    && span_count < AUTO_X86_MAX_SPAN_RANGES
                {
                    push_x86_filter_range(&mut ranges, data.len(), span_start, span_last);
                    span_count += 1;
                }
                span = Some((start, last, count));
            }
            None => span = Some((start, last, count)),
        }
    }
    if let Some((span_start, span_last, span_opcodes)) = span {
        if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES && span_count < AUTO_X86_MAX_SPAN_RANGES {
            push_x86_filter_range(&mut ranges, data.len(), span_start, span_last);
        }
    }

    clusters.sort_by(|a, b| {
        let a_len = a.1 - a.0 + 5;
        let b_len = b.1 - b.0 + 5;
        b.2.cmp(&a.2).then_with(|| a_len.cmp(&b_len))
    });
    clusters.truncate(AUTO_X86_MAX_RANGES);

    for (start, last, _) in clusters {
        push_x86_filter_range(&mut ranges, data.len(), start, last);
    }
    ranges
}

fn push_x86_filter_range(
    ranges: &mut Vec<Range<usize>>,
    data_len: usize,
    start: usize,
    last: usize,
) {
    let range_start = start.saturating_sub(AUTO_X86_RANGE_PADDING);
    let range_end = (last + 5 + AUTO_X86_RANGE_PADDING).min(data_len);
    let range = range_start..range_end;
    if range.start < range.end && !ranges.contains(&range) {
        ranges.push(range);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_auto_x86_filter_ranges(data: &[u8], include_e9: bool) -> Vec<Range<usize>> {
        let mut ranges =
            scalar_auto_x86_filter_ranges_with_cluster_gap(data, include_e9, AUTO_X86_CLUSTER_GAP);
        for range in scalar_auto_x86_filter_ranges_with_cluster_gap(
            data,
            include_e9,
            AUTO_X86_TIGHT_CLUSTER_GAP,
        ) {
            if !ranges.contains(&range) {
                ranges.push(range);
            }
        }
        ranges
    }

    fn scalar_auto_x86_filter_ranges_with_cluster_gap(
        data: &[u8],
        include_e9: bool,
        cluster_gap: usize,
    ) -> Vec<Range<usize>> {
        if data.len() <= 5 {
            return Vec::new();
        }

        let cmp_mask = if include_e9 { 0xfe } else { 0xff };
        let mut clusters = Vec::new();
        let mut current: Option<(usize, usize, usize)> = None;
        for (pos, &byte) in data.iter().take(data.len() - 4).enumerate() {
            if byte & cmp_mask != 0xe8 {
                continue;
            }

            match current {
                Some((start, last, count)) if pos - last <= cluster_gap => {
                    current = Some((start, pos, count + 1));
                }
                Some(cluster) => {
                    clusters.push(cluster);
                    current = Some((pos, pos, 1));
                }
                None => current = Some((pos, pos, 1)),
            }
        }
        if let Some(cluster) = current {
            clusters.push(cluster);
        }

        clusters.retain(|&(_, _, count)| count >= 2);
        let mut ranges = Vec::new();
        let mut span_count = 0;
        let mut span: Option<(usize, usize, usize)> = None;
        for &(start, last, count) in &clusters {
            match span {
                Some((span_start, span_last, span_opcodes))
                    if start.saturating_sub(span_last) <= AUTO_X86_SPAN_CLUSTER_GAP =>
                {
                    span = Some((span_start, last, span_opcodes + count));
                }
                Some((span_start, span_last, span_opcodes)) => {
                    if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES
                        && span_count < AUTO_X86_MAX_SPAN_RANGES
                    {
                        push_x86_filter_range(&mut ranges, data.len(), span_start, span_last);
                        span_count += 1;
                    }
                    span = Some((start, last, count));
                }
                None => span = Some((start, last, count)),
            }
        }
        if let Some((span_start, span_last, span_opcodes)) = span {
            if span_opcodes >= AUTO_X86_MIN_SPAN_OPCODES && span_count < AUTO_X86_MAX_SPAN_RANGES {
                push_x86_filter_range(&mut ranges, data.len(), span_start, span_last);
            }
        }

        clusters.sort_by(|a, b| {
            let a_len = a.1 - a.0 + 5;
            let b_len = b.1 - b.0 + 5;
            b.2.cmp(&a.2).then_with(|| a_len.cmp(&b_len))
        });
        clusters.truncate(AUTO_X86_MAX_RANGES);

        for (start, last, _) in clusters {
            push_x86_filter_range(&mut ranges, data.len(), start, last);
        }
        ranges
    }

    #[test]
    fn returns_no_ranges_for_inputs_too_short_to_contain_a_call() {
        for len in 0..=5 {
            let data = vec![0xe8; len];
            assert!(auto_x86_filter_ranges(&data, false).is_empty());
            assert!(auto_x86_filter_ranges(&data, true).is_empty());
        }
    }

    #[test]
    fn auto_x86_filter_ranges_match_scalar_scanner_at_lane_boundaries() {
        let mut data = vec![0x41u8; 150_000];
        for pos in [
            31usize, 32, 33, 1024, 1088, 4096, 4160, 80_000, 80_032, 80_064,
        ] {
            data[pos] = 0xe8;
        }
        data[80_096] = 0xe9;

        assert_eq!(
            auto_x86_filter_ranges(&data, false),
            scalar_auto_x86_filter_ranges(&data, false)
        );
        assert_eq!(
            auto_x86_filter_ranges(&data, true),
            scalar_auto_x86_filter_ranges(&data, true)
        );
    }

    #[test]
    fn drops_isolated_opcodes_that_never_form_a_cluster() {
        let mut data = vec![0x41; 20_000];
        data[100] = 0xe8;
        data[10_000] = 0xe8;
        assert!(auto_x86_filter_ranges(&data, false).is_empty());
    }

    #[test]
    fn clamps_padded_range_to_buffer_bounds_at_both_ends() {
        let mut data = vec![0x41u8; 30];
        for pos in [0, 4, 8, 12] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert_eq!(ranges, vec![0..30]);
    }

    #[test]
    fn does_not_duplicate_a_span_range_already_emitted_for_a_cluster() {
        let mut data = vec![0x41u8; 20_000];
        for pos in [1024, 1050, 1090, 1130] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 1008..1151);
    }

    #[test]
    fn includes_tighter_ranges_inside_sparse_code_spans() {
        let mut data = vec![0x41u8; 8_000];
        for pos in [1024, 1088, 3600, 3664] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert!(
            ranges
                .iter()
                .any(|range| range.start <= 1024 && range.end > 3664 && range.len() > 2000),
            "missing broad sparse-code span: {ranges:?}"
        );
        assert!(
            ranges.iter().any(|range| range.contains(&1024)
                && range.contains(&1088)
                && !range.contains(&3600)),
            "missing first tight code cluster: {ranges:?}"
        );
        assert!(
            ranges.iter().any(|range| range.contains(&3600)
                && range.contains(&3664)
                && !range.contains(&1088)),
            "missing second tight code cluster: {ranges:?}"
        );
    }

    #[test]
    fn keeps_more_disjoint_code_section_candidates() {
        let mut data = vec![0x41u8; 700_000];
        for section in 0..8 {
            let start = 16_384 + section * 80_000;
            for index in 0..6 {
                data[start + index * 64] = 0xe8;
            }
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        for section in 0..8 {
            let start = 16_384 + section * 80_000;
            assert!(
                ranges.iter().any(|range| range.contains(&start)),
                "missing x86 section at {start}"
            );
        }
    }
}
