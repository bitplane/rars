use super::*;
use crate::codec::workspace::RefusingBudget;
fn small() -> HybridCodecOptions {
    HybridCodecOptions {
        max_match_candidates: 8,
        max_endpoints_per_run: 4,
        pricing_passes: 1,
        full_partitions: false,
        ..HybridCodecOptions::default()
    }
}
fn unpack(bytes: &[u8], data: &[u8], version: u8, dictionary: usize) {
    let mut reader = Unpack50Decoder::new();
    assert_eq!(
        reader
            .decode_member_with_dictionary(
                bytes,
                version,
                data.len(),
                dictionary,
                false,
                DecodeMode::Lz
            )
            .unwrap(),
        data
    );
}

#[test]
fn stateful_tables_and_packing_carry_last_repeat_across_fresh_blocks() {
    let budget = Allowance::default();
    for version in [0, 1] {
        let size = distance_size(version).unwrap();
        let mut tokens: Vec<_> = b"ABCDEFGH"
            .iter()
            .copied()
            .map(EncodeToken::Literal)
            .collect();
        tokens.push(EncodeToken::Match {
            length: 32,
            distance: 8,
        });
        let (first, state) = encode_token_block_with_state(
            &tokens,
            version,
            size,
            false,
            &budget,
            EncoderMatchState::default(),
        )
        .unwrap();
        let next = [EncodeToken::Match {
            length: 32,
            distance: 8,
        }];
        let lengths = table_lengths_with_state(&next, &[], size, &budget, state).unwrap();
        assert_ne!(lengths.main[257], 0);
        assert!(lengths.main[258..].iter().all(|&code| code == 0));
        let (second, end) =
            encode_token_block_with_state(&next, version, size, true, &budget, state).unwrap();
        assert_eq!(end.reps, state.reps);
        assert_eq!(end.last_length, 32);
        assert!(parse_compressed_block(&first).unwrap().header.has_tables);
        assert!(parse_compressed_block(&second).unwrap().header.has_tables);
        let joined = [&*first, &*second].concat();
        unpack(&joined, &b"ABCDEFGH".repeat(9), version, 65536);
    }
}

#[test]
fn hybrid_small_beams_versions_and_mandatory_filters_round_trip() {
    let budget = Allowance::default();
    let data: Vec<u8> = (0..2048)
        .map(|at| ((at / 4) as u8).wrapping_add((at % 4) as u8))
        .collect();
    for version in [0, 1] {
        for beam_width in [1, 2, 8] {
            for kind in [
                None,
                Some(crate::FilterKind::E8),
                Some(crate::FilterKind::E8E9),
                Some(crate::FilterKind::Arm),
                Some(crate::FilterKind::Delta { channels: 4 }),
            ] {
                let state = HybridCodecState::new(&[], 65536, version, &budget).unwrap();
                let filters: Vec<_> = kind.into_iter().map(crate::FilterSpec::whole).collect();
                let config = HybridCodecOptions {
                    beam_width,
                    ..small()
                };
                let output = encode_partition(
                    &data,
                    &[],
                    &state,
                    config,
                    &filters,
                    true,
                    &budget,
                    &ReadControl::default(),
                    &|| false,
                    None,
                )
                .unwrap();
                unpack(&output.bytes, &data, version, 65536);
                assert_eq!(output.end_state.member_offset, data.len() as u64);
                assert_eq!(output.end_state.history(), &*output.history_append);
                assert_eq!(state.member_offset, 0);
                assert!(state.history().is_empty());
                assert!(output.work.price_passes > 0);
            }
        }
    }
}

#[test]
fn complete_partition_portfolio_tail_clips_without_missing_bytes() {
    for length in [0, 1, 65535, 65536, 65537, 131072, 196609, HYBRID_WINDOW] {
        for id in 0..4 {
            let (ends, n) = boundaries(length, id);
            assert!(n > 0);
            assert_eq!(ends[n - 1], length);
            assert!(ends[..n].windows(2).all(|pair| pair[0] < pair[1]));
        }
    }
    let budget = Allowance::default();
    let data: Vec<_> = (0..65537).map(|x| x as u8).collect();
    let state = HybridCodecState::new(&[], 65536, 0, &budget).unwrap();
    for id in 0..4 {
        let domain = make_domain(
            &data,
            0,
            &[],
            None,
            &budget,
            &ReadControl::default(),
            &|| false,
        )
        .unwrap();
        let mut work = HybridWork::default();
        let encoded = encode_domain(
            &domain,
            &[],
            state.matches(),
            0,
            65536,
            id,
            small(),
            true,
            true,
            &budget,
            &ReadControl::default(),
            &|| false,
            &mut work,
        )
        .unwrap();
        unpack(&encoded.bytes, &data, 0, 65536);
        assert_eq!(work.blocks, boundaries(data.len(), id).1 as u64);
    }
}

#[test]
fn next_window_is_scored_but_not_committed_or_returned() {
    let budget = Allowance::default();
    let first = vec![b'A'; HYBRID_WINDOW];
    let next = vec![b'Z'; 257];
    let state = HybridCodecState::new(&[], 4096, 0, &budget).unwrap();
    let config = HybridCodecOptions {
        beam_width: 1,
        max_match_candidates: 0,
        max_endpoints_per_run: 1,
        pricing_passes: 1,
        full_partitions: false,
        ..small()
    };
    let output = encode_partition(
        &first,
        &next,
        &state,
        config,
        &[],
        false,
        &budget,
        &ReadControl::default(),
        &|| false,
        None,
    )
    .unwrap();
    assert_eq!(output.work.lookahead_bytes, next.len() as u64);
    assert!(output.next_cost > 0);
    assert_eq!(output.end_state.member_offset, HYBRID_WINDOW as u64);
    assert_eq!(output.history_append.len(), HYBRID_WINDOW);
    assert_eq!(output.end_state.history(), &first[first.len() - 4096..]);
    assert!(
        !parse_compressed_block(&output.bytes)
            .unwrap()
            .header
            .is_last
    );
    let second = encode_partition(
        &next,
        &[],
        &output.end_state,
        config,
        &[],
        true,
        &budget,
        &ReadControl::default(),
        &|| false,
        None,
    )
    .unwrap();
    let bytes = [&*output.bytes, &*second.bytes].concat();
    let all = [first, next].concat();
    unpack(&bytes, &all, 0, 4096);
}

#[test]
fn mandatory_filter_representation_is_independent_of_partition_cuts() {
    let budget = Allowance::default();
    let input: Vec<_> = (0..131077).map(|at| (at / 4) as u8).collect();
    let filters = [crate::FilterSpec::range(
        crate::FilterKind::Delta { channels: 4 },
        3..131075,
    )];
    let domain = make_domain(
        &input,
        0,
        &filters,
        None,
        &budget,
        &ReadControl::default(),
        &|| false,
    )
    .unwrap();
    assert_ne!(&*domain.bytes, &input);
    let mut original: Option<Vec<u8>> = None;
    for id in 0..4 {
        let mut work = HybridWork::default();
        let encoded = encode_domain(
            &domain,
            &[],
            EncoderMatchState::default(),
            0,
            65536,
            id,
            small(),
            true,
            true,
            &budget,
            &ReadControl::default(),
            &|| false,
            &mut work,
        )
        .unwrap();
        unpack(&encoded.bytes, &input, 0, 65536);
        if let Some(history) = &original {
            assert_eq!(&*encoded.history, history);
        } else {
            original = Some(encoded.history.to_vec());
        }
    }
}

#[test]
fn limits_cancellation_and_progress_failure_leave_start_unchanged() {
    let data = b"an independent bounded speculative path".repeat(3);
    let budget = RefusingBudget::new(usize::MAX);
    let state = HybridCodecState::new(&[], 4096, 0, &budget).unwrap();
    let result = encode_partition(
        &data,
        &[],
        &state,
        small(),
        &[],
        true,
        &budget,
        &ReadControl::default(),
        &|| false,
        None,
    )
    .unwrap();
    let attempts = budget.attempts();
    drop(result);
    assert_eq!(budget.used(), 0);
    assert!(attempts > 0);
    for fail in 0..attempts {
        let budget = RefusingBudget::new(fail);
        let state = HybridCodecState::new(&[], 4096, 0, &budget).unwrap();
        assert!(
            matches!(
                encode_partition(
                    &data,
                    &[],
                    &state,
                    small(),
                    &[],
                    true,
                    &budget,
                    &ReadControl::default(),
                    &|| false,
                    None
                ),
                Err(Error::Cancelled)
            ),
            "admission {fail}"
        );
        assert_eq!(budget.used(), 0);
        assert_eq!(state.reps, [0; 4]);
    }
    let budget = Allowance::default();
    let state = HybridCodecState::new(&[], 4096, 0, &budget).unwrap();
    let token = crate::ReadCancellation::new();
    token.cancel();
    let control = ReadControl::new(Some(&token));
    assert!(matches!(
        encode_partition(
            &[],
            &[],
            &state,
            small(),
            &[],
            true,
            &budget,
            &control,
            &|| false,
            None
        ),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        encode_partition(
            &data,
            &[],
            &state,
            small(),
            &[],
            true,
            &budget,
            &ReadControl::default(),
            &|| false,
            Some(&mut |_| false)
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(state.member_offset, 0);
    assert!(state.history().is_empty());
    assert!(matches!(
        encode_partition(
            &data,
            &[],
            &state,
            small(),
            &[],
            false,
            &budget,
            &ReadControl::default(),
            &|| false,
            None
        ),
        Err(Error::InvalidData("hybrid decision window is incomplete"))
    ));
}

#[test]
fn cache_projection_is_explicit_and_retains_nearest_prefix_and_longest() {
    let budget = Allowance::default();
    let start = 43 * 256;
    let span = 100;
    let payload: Vec<_> = (1..=span).map(|x| x as u8).collect();
    let mut data = vec![0; start + span];
    data[start..].copy_from_slice(&payload);
    for index in 0..40 {
        let length = 4 + index;
        let at = start - (index + 1) * 256;
        data[at..at + length].copy_from_slice(&payload[..length]);
    }
    let options = EncodeOptions::new(64).with_max_match_distance(start);
    let control = ReadControl::default();
    let mut work = HybridWork::default();
    let mut collector = collector_with_control(
        &data,
        start,
        options,
        &budget,
        &control,
        &|| false,
        &mut work,
    )
    .unwrap();
    let (matches, truncated) = collector
        .collect_hybrid(
            &data,
            start..start + span,
            options,
            &control,
            &|| false,
            16,
            &mut work,
        )
        .unwrap();
    assert!(truncated);
    let first = &matches.runs[matches.starts[0] as usize..matches.starts[1] as usize];
    assert_eq!(first.len(), 16);
    assert_eq!(first[0], (4, 256));
    assert_eq!(first.last().unwrap().0, 43);
    assert!(first
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0 && pair[0].1 < pair[1].1));
    assert!(work.chain_candidates >= 40);
    assert_eq!(work.seeded_positions, start as u64);
}

#[test]
fn committed_solid_successor_uses_true_repeat_state() {
    let budget = Allowance::default();
    let control = ReadControl::default();
    let data = b"ABCDEFGHABCDEFGHABCDEFGH repeated solid history".repeat(12);
    for version in [0, 1] {
        let state = HybridCodecState::new(&[], 4096, version, &budget).unwrap();
        let first = encode_partition(
            &data,
            &[],
            &state,
            small(),
            &[],
            true,
            &budget,
            &control,
            &|| false,
            None,
        )
        .unwrap();
        assert_ne!(first.end_state.reps, [0; 4]);
        let mut state = first.end_state;
        state.begin_member();
        let second = encode_partition(
            &data,
            &[],
            &state,
            small(),
            &[],
            true,
            &budget,
            &control,
            &|| false,
            None,
        )
        .unwrap();
        assert_eq!(second.end_state.member_offset, data.len() as u64);
        assert_eq!(second.end_state.stream_offset, (data.len() * 2) as u64);
        let mut reader = Unpack50Decoder::new();
        assert_eq!(
            reader
                .decode_member_with_dictionary(
                    &first.bytes,
                    version,
                    data.len(),
                    4096,
                    false,
                    DecodeMode::Lz
                )
                .unwrap(),
            data
        );
        assert_eq!(
            reader
                .decode_member_with_dictionary(
                    &second.bytes,
                    version,
                    data.len(),
                    4096,
                    true,
                    DecodeMode::Lz
                )
                .unwrap(),
            data
        );
        assert_eq!(reader.state.reps, second.end_state.reps);
        assert_eq!(reader.state.last_length, second.end_state.last_length);
        assert_eq!(&*reader.state.history, second.end_state.history());
    }
}

#[test]
fn writer_cancellation_is_polled_inside_speculation_without_progress() {
    let budget = Allowance::default();
    let history = b"prefix dictionary".repeat(2048);
    let state = HybridCodecState::new(&history, 65536, 0, &budget).unwrap();
    let data = b"a cancellable speculative member".repeat(64);
    let calls = std::cell::Cell::new(0usize);
    let cancelled = || {
        let n = calls.get();
        calls.set(n + 1);
        n >= 8
    };
    let mut reports = 0;
    assert!(matches!(
        encode_partition(
            &data,
            &[],
            &state,
            small(),
            &[],
            true,
            &budget,
            &ReadControl::default(),
            &cancelled,
            Some(&mut |_| {
                reports += 1;
                true
            })
        ),
        Err(Error::Cancelled)
    ));
    assert!(calls.get() > 8);
    assert_eq!(reports, 0);
    assert_eq!(state.history(), history);
    assert_eq!(state.member_offset, 0);
    assert_eq!(state.reps, [0; 4]);
}

#[test]
fn server_tail_partition_dedup_includes_nonadjacent_shapes() {
    let budget = Allowance::default();
    let data = vec![b'x'; 70 * 1024];
    let state = HybridCodecState::new(&[], 4096, 0, &budget).unwrap();
    let config = HybridCodecOptions {
        beam_width: 1,
        finalists: 4,
        full_partitions: true,
        max_match_candidates: 0,
        max_endpoints_per_run: 1,
        pricing_passes: 1,
        ..small()
    };
    let output = encode_partition(
        &data,
        &[],
        &state,
        config,
        &[],
        true,
        &budget,
        &ReadControl::default(),
        &|| false,
        None,
    )
    .unwrap();
    assert_eq!(output.work.screened, 2);
    assert_eq!(output.work.finalists, 2);
    assert!(output.partition_id < 4);
    assert_eq!(output.representation_id, 0);
    assert!(output
        .cache_quality
        .iter()
        .all(|q| q.run_cap == 64 && q.nearest_prefix_then_longest && !q.every_position));
    unpack(&output.bytes, &data, 0, 4096);
}

#[test]
fn overlapping_mandatory_filters_preserve_decoder_command_order() {
    let budget = Allowance::default();
    let data: Vec<_> = (0..8192)
        .map(|at| ((at / 4) as u8).wrapping_add((at % 4) as u8))
        .collect();
    let filters = [
        crate::FilterSpec::whole(crate::FilterKind::Delta { channels: 4 }),
        crate::FilterSpec::range(crate::FilterKind::Delta { channels: 1 }, 13..data.len() - 7),
    ];
    let state = HybridCodecState::new(&[], 16384, 0, &budget).unwrap();
    let result = encode_partition(
        &data,
        &[],
        &state,
        small(),
        &filters,
        true,
        &budget,
        &ReadControl::default(),
        &|| false,
        None,
    )
    .unwrap();
    unpack(&result.bytes, &data, 0, 16384);
}

#[test]
fn filter_scratch_and_record_failures_release_all_charges() {
    let input = b"bounded mandatory delta scratch".repeat(3);
    let filters = [crate::FilterSpec::whole(crate::FilterKind::Delta {
        channels: 4,
    })];
    let budget = RefusingBudget::new(usize::MAX);
    let state = HybridCodecState::new(&[], 4096, 0, &budget).unwrap();
    let result = encode_partition(
        &input,
        &[],
        &state,
        small(),
        &filters,
        true,
        &budget,
        &ReadControl::default(),
        &|| false,
        None,
    )
    .unwrap();
    let count = budget.attempts();
    drop(result);
    assert_eq!(budget.used(), 0);
    for fail in 0..count {
        let budget = RefusingBudget::new(fail);
        let state = HybridCodecState::new(&[], 4096, 0, &budget).unwrap();
        assert!(
            matches!(
                encode_partition(
                    &input,
                    &[],
                    &state,
                    small(),
                    &filters,
                    true,
                    &budget,
                    &ReadControl::default(),
                    &|| false,
                    None
                ),
                Err(Error::Cancelled)
            ),
            "filter admission {fail}"
        );
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn empty_decision_has_a_complete_fresh_table_block_and_empty_state() {
    let budget = Allowance::default();
    for version in [0, 1] {
        let state = HybridCodecState::new(&[], 4096, version, &budget).unwrap();
        let output = encode_partition(
            &[],
            &[],
            &state,
            small(),
            &[],
            true,
            &budget,
            &ReadControl::default(),
            &|| false,
            None,
        )
        .unwrap();
        let block = parse_compressed_block(&output.bytes).unwrap();
        assert!(block.header.has_tables && block.header.is_last);
        assert_eq!(output.end_state.member_offset, 0);
        assert!(output.end_state.history().is_empty());
        unpack(&output.bytes, &[], version, 4096);
    }
}
