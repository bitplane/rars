use crate::codec::Error;

#[test]
fn normal_encoder_round_trips_terminal_literal_flag_groups() {
    for length in [23, 24, 25] {
        let input: Vec<u8> = (0..length).collect();
        let packed = super::unpack15_encode(&input).unwrap();
        assert_eq!(super::unpack15_decode(&packed, input.len()).unwrap(), input);
    }
}

#[test]
fn final_literal_flag_crosses_into_a_terminal_flags_group() {
    let first = match_heavy_payload(176, 8000);
    let mut encoder =
        super::Unpack15Encoder::with_options(super::EncodeOptions::new().with_lazy_matching(false));
    let first_packed = encoder.encode_member(&first).unwrap();
    let mut decoder = super::Unpack15::new();
    assert_eq!(
        decoder
            .decode_member(&first_packed, first.len(), false)
            .unwrap(),
        first
    );
    let input: Vec<u8> = [b'A'; 24].into_iter().chain(*b"XYZ").collect();
    let mut planned = encoder.clone_for_planning();
    planned.emit_literal(b'A');
    let buckets = long_lz_buckets(&input);
    assert_eq!(
        planned.choose_lz_token(&input, 1, &buckets, planned.lz_plan_state()),
        Some(MatchToken::LongLz(LongLz {
            distance: 1,
            length: 23
        }))
    );
    let packed = encoder.encode_member(&input).unwrap();
    let mut partial = decoder.clone();
    assert_eq!(
        decoder.decode_member(&packed, input.len(), true).unwrap(),
        input
    );
    assert_eq!(
        partial
            .decode_member(&packed, input.len() - 1, true)
            .unwrap(),
        input[..input.len() - 1]
    );
    assert_eq!(
        partial.state.flags_cnt, 1,
        "one flag bit remains before the terminal literal"
    );
    partial.state.target = input.len();
    let mut tail = Vec::new();
    partial.state.decode_step(&mut tail).unwrap();
    assert_eq!(tail, b"Z");
    assert_eq!(
        partial.state.flags_cnt, 7,
        "the second flag bit comes from the terminal flags group"
    );
}

#[test]
fn empty_encoder_fast_paths_skip_progress_and_nonempty_work_can_cancel() {
    assert!(
        super::unpack15_encode_with_options(&[], super::EncodeOptions::default())
            .unwrap()
            .is_empty()
    );
    assert!(super::unpack15_encode_with_options_and_progress(
        &[],
        super::EncodeOptions::default(),
        &mut |_| panic!("empty input has no codec work")
    )
    .unwrap()
    .is_empty());
    let mut checkpoints = Vec::new();
    assert_eq!(
        super::unpack15_encode_with_options_and_progress(
            b"abc",
            super::EncodeOptions::default(),
            &mut |position| {
                checkpoints.push(position);
                false
            }
        ),
        Err(Error::Cancelled)
    );
    assert_eq!(checkpoints, [3]);
}

#[test]
fn public_decoder_renormalizes_repeated_flags_without_losing_the_alphabet() {
    let mut encoder = super::Unpack15Encoder::new();
    let first = encoder.encode_member(&[0]).unwrap();
    let mut decoder = super::Unpack15::new();
    assert_eq!(decoder.decode_member(&first, 1, false).unwrap(), [0]);
    for _ in 0..300 {
        encoder.emit_flags_byte(0);
        for _ in 0..4 {
            encoder.emit_short_lz(super::ShortLz {
                distance: 1,
                length: 2,
            });
        }
    }
    let packed = std::mem::take(&mut encoder.bits).finish();
    assert_eq!(
        decoder.decode_member(&packed, 2400, true).unwrap(),
        vec![0; 2400]
    );
    assert_eq!(decoder.state.ch_set_c, encoder.ch_set_c);
    let frequency = decoder
        .state
        .ch_set_c
        .iter()
        .find(|&&entry| entry >> 8 == 0)
        .unwrap()
        & 0xff;
    assert_eq!(
        frequency, 52,
        "256th update renormalizes the hot entry to 7, then increments it"
    );
}

#[test]
fn invalid_flag_rank_preserves_the_table_and_match_overrun_writes_nothing() {
    let mut bits = super::BitWriter::new();
    super::emit_decode_num(&mut bits, 256, 5, super::DEC_HF2, super::POS_HF2);
    let packed = bits.finish();
    let mut decoder = super::Unpack15::new();
    let alphabet = decoder.state.ch_set_c;
    assert_eq!(decoder.decode_member(&packed, 2, false).unwrap(), [0; 2]);
    assert_eq!(decoder.state.ch_set_c, alphabet);
    let mut streaming = super::Unpack15::new();
    let mut output = Vec::new();
    streaming
        .decode_member_from_reader(&mut packed.as_slice(), 2, false, &mut output)
        .unwrap();
    assert_eq!(output, [0; 2]);
    assert_eq!(streaming.state.ch_set_c, alphabet);
    assert_eq!(
        super::Unpack15::new().decode_member(&[], 1, false),
        Err(Error::InvalidData("RAR 1.3 match exceeds output size"))
    );
    output.clear();
    assert_eq!(
        super::Unpack15::new().decode_member_from_reader(&mut &[][..], 1, false, &mut output),
        Err(Error::InvalidData("RAR 1.3 match exceeds output size"))
    );
    assert!(output.is_empty());
}

#[test]
fn consecutive_minimum_long_matches_cross_the_distance_threshold() {
    let mut encoder = super::Unpack15Encoder::new();
    let first = encoder.encode_literals_only_member(&[0; 256]);
    let mut decoder = super::Unpack15::new();
    assert_eq!(decoder.decode_member(&first, 256, false).unwrap(), [0; 256]);
    assert!(decoder.state.avr_plc < 0x2a00);
    for _ in 0..178 {
        encoder.emit_long_lz(super::LongLz {
            distance: 1,
            length: 11,
        });
    }
    let payload = std::mem::take(&mut encoder.bits).finish();
    decoder.state.init_member(178 * 11, true);
    decoder.state.bits =
        super::ReaderBits::with_allowance(&payload, &decoder.state.window.allowance()).unwrap();
    let mut output = Vec::new();
    for index in 0..178 {
        decoder.state.long_lz(&mut output).unwrap();
        if index < 177 {
            assert_eq!(decoder.state.max_dist3, 0x2001);
        }
    }
    assert_eq!(output, vec![0; 178 * 11]);
    assert_eq!(decoder.state.avr_ln3, 178);
    assert_eq!(decoder.state.max_dist3, 0x7f00);
    assert_eq!(decoder.state.ch_set_b, encoder.ch_set_b);
}

#[test]
fn maximum_far_distance_zero_fills_then_reads_wrapped_solid_history() {
    fn far_member(encoder: &mut super::Unpack15Encoder) -> Vec<u8> {
        encoder.emit_flags_byte(0);
        // Code 14 is distinct from code 1 only after the Buf60 toggle.
        encoder.emit_short_lz_code(10);
        super::emit_decode_num(&mut encoder.bits, 255, 2, super::DEC_L1, super::POS_L1);
        encoder.emit_short_lz_code(14);
        super::emit_decode_num(&mut encoder.bits, 0, 3, super::DEC_L2, super::POS_L2);
        encoder.bits.write_bits(0x7fff, 15);
        std::mem::take(&mut encoder.bits).finish()
    }
    let mut encoder = super::Unpack15Encoder::new();
    let packed = far_member(&mut encoder);
    let mut decoder = super::Unpack15::new();
    assert_eq!(decoder.decode_member(&packed, 5, false).unwrap(), [0; 5]);
    assert_eq!(decoder.state.last_dist, 0xffff);

    let mut first = vec![0; 0x10000];
    first[1..6].copy_from_slice(b"abcde");
    let mut encoder = super::Unpack15Encoder::new();
    let packed_first = encoder.encode_literals_only_member(&first);
    let mut decoder = super::Unpack15::new();
    assert_eq!(
        decoder
            .decode_member(&packed_first, first.len(), false)
            .unwrap(),
        first
    );
    assert_eq!(decoder.state.unp_ptr, 0);
    assert_eq!(decoder.state.old_dist, [u32::MAX; 4]);
    // The next decoding step observes the wrap before reading a match.
    let mut unused_history = decoder.clone();
    let mut unused_streaming = decoder.clone();
    let mut old_encoder = encoder.clone_for_planning();
    old_encoder.emit_flags_byte(0);
    old_encoder.emit_short_lz_code(10);
    super::emit_decode_num(&mut old_encoder.bits, 0, 2, super::DEC_L1, super::POS_L1);
    let old_packed = std::mem::take(&mut old_encoder.bits).finish();
    assert_eq!(
        unused_history.decode_member(&old_packed, 4, true).unwrap(),
        [0; 4]
    );
    assert!(unused_history.state.first_win_done);
    assert_eq!(unused_history.state.last_dist, u32::MAX);
    let mut zeros = Vec::new();
    unused_streaming
        .decode_member_from_reader(&mut old_packed.as_slice(), 4, true, &mut zeros)
        .unwrap();
    assert_eq!(zeros, [0; 4]);
    let packed = far_member(&mut encoder);
    let mut streaming = decoder.clone();
    assert_eq!(decoder.decode_member(&packed, 5, true).unwrap(), b"abcde");
    assert_eq!(decoder.state.last_dist, 0xffff);
    assert!(decoder.state.first_win_done);
    let mut output = Vec::new();
    streaming
        .decode_member_from_reader(&mut packed.as_slice(), 5, true, &mut output)
        .unwrap();
    assert_eq!(output, b"abcde");
}

#[test]
fn old_distance_finder_keeps_recent_entry_when_match_lengths_tie() {
    let mut encoder = super::Unpack15Encoder::new();
    for distance in 1..=4 {
        encoder.remember_match(distance, 3);
    }
    let token = super::find_old_dist_lz(
        &[0; 16],
        8,
        encoder.old_dist,
        encoder.old_dist_ptr,
        encoder.max_dist3,
    )
    .unwrap();
    assert_eq!(
        token,
        super::OldDistLz {
            distance: 4,
            length: 8,
            short_code: 10
        }
    );
    for _ in 0..4 {
        encoder.remember_match(4, 3);
    }
    assert_eq!(
        super::find_old_dist_lz(
            &[0; 16],
            8,
            encoder.old_dist,
            encoder.old_dist_ptr,
            encoder.max_dist3
        ),
        Some(token)
    );
}

#[test]
fn repeat_and_old_finders_refuse_history_before_the_member_prefix() {
    assert_eq!(super::find_repeat_last_lz(&[0; 8], 4, u32::MAX, 0), None);
    assert_eq!(super::find_repeat_last_lz(&[0; 8], 4, 5, 3), None);
    assert_eq!(super::find_repeat_last_lz(&[0; 8], 4, 4, 5), None);
    assert_eq!(super::find_repeat_last_lz(b"abcdabce", 4, 4, 4), None);
    assert_eq!(
        super::find_repeat_last_lz(b"abcdabcd", 4, 4, 4),
        Some(super::RepeatLastLz {
            distance: 4,
            length: 4
        })
    );
    assert_eq!(
        super::find_old_dist_lz(&[0; 8], 4, [u32::MAX; 4], 0, 0x2001),
        None
    );
    assert_eq!(super::find_old_dist_lz(&[0; 8], 4, [5; 4], 0, 0x2001), None);
}

#[test]
fn long_distance_updates_preserve_every_high_byte_through_counter_wraps() {
    let mut encoder = super::Unpack15Encoder::new();
    let mut wraps = 0;
    for distance in std::iter::repeat_n(128, 768).chain((0..256).map(|high| (high * 128).max(1))) {
        let before = encoder.ch_set_b.iter().find(|&&v| v >> 8 == 1).unwrap() & 0xff;
        let token = super::LongLz {
            distance,
            length: 11,
        };
        assert!(encoder
            .token_bit_cost(super::MatchToken::LongLz(token), encoder.lz_plan_state())
            .is_some());
        encoder.emit_long_lz(token);
        let after = encoder.ch_set_b.iter().find(|&&v| v >> 8 == 1).unwrap() & 0xff;
        wraps += usize::from(distance == 128 && after < before);
        let mut counts = [0u16; 256];
        for &entry in &encoder.ch_set_b {
            counts[(entry >> 8) as usize] += 1;
        }
        assert_eq!(counts, [1; 256]);
    }
    assert!(wraps >= 2);
}

#[test]
fn long_length_cost_matches_emitted_bits_and_decoder_at_every_mode_boundary() {
    for average in [0, 63, 64, 121, 122, 1000] {
        let mut encoder = super::Unpack15Encoder::new();
        encoder.avr_ln2 = average;
        for code in 0..=255 {
            let length = encoder.long_lz_length_bit_cost(code);
            let mut bits = super::BitWriter::new();
            super::emit_long_lz_length(&mut bits, average, code);
            assert_eq!(bits.bit_pos, length);
            let field = (u32::from(bits.output[0]) << 8)
                | u32::from(bits.output.get(1).copied().unwrap_or(0));
            if average >= 64 {
                let (start, thresholds, ranks) = if average >= 122 {
                    (3, DEC_L2, POS_L2)
                } else {
                    (2, DEC_L1, POS_L1)
                };
                for suffix in 0..(1u32 << (16 - length)) {
                    assert_eq!(
                        simulate_decode_num(field | suffix, start, thresholds, ranks),
                        (code, length)
                    );
                }
            } else if code <= 7 {
                assert_eq!(field, 1 << (15 - code));
            } else {
                assert_eq!(field, code);
            }
        }
    }
}

#[test]
fn planned_old_distance_and_repeat_tokens_replay_after_flag_updates() {
    fn state(encoder: &super::Unpack15Encoder) -> (u32, u32, [u32; 4], usize, u32, u32, u32, u32) {
        let s = encoder.lz_plan_state();
        (
            s.last_dist,
            s.last_length,
            s.old_dist,
            s.old_dist_ptr,
            s.max_dist3,
            s.nlzb,
            s.nhfb,
            s.l_count,
        )
    }
    for maximum in [0x2001, 0x7f00] {
        let mut encoder = super::Unpack15Encoder::new();
        encoder.max_dist3 = maximum;
        for distance in 1..=4 {
            encoder.emit_short_lz(super::ShortLz {
                distance,
                length: 3,
            });
        }
        for code in 10..=13 {
            for length in [3, 4, 256] {
                let distance =
                    encoder.old_dist[(encoder.old_dist_ptr.wrapping_sub((code - 9) as usize)) & 3];
                let token = super::OldDistLz {
                    distance,
                    length,
                    short_code: code,
                };
                assert!(encoder
                    .token_bit_cost(
                        super::MatchToken::OldDist(super::OldDistLz {
                            length: 258,
                            ..token
                        }),
                        encoder.lz_plan_state(),
                    )
                    .is_none());
                assert!(encoder
                    .token_bit_cost(super::MatchToken::OldDist(token), encoder.lz_plan_state())
                    .is_some());
                let mut planned = encoder.clone_for_planning();
                planned.emit_old_dist_lz(token);
                // Real emission writes the flags table before replaying payloads.
                // Wrap its adaptive counter to check that this remains independent.
                for _ in 0..512 {
                    encoder.emit_flags_byte(255);
                }
                encoder.emit_old_dist_lz(token);
                assert_eq!(state(&encoder), state(&planned));
                for _ in 0..3 {
                    let repeat = super::find_repeat_last_lz(
                        &[0; 1024],
                        512,
                        encoder.last_dist,
                        encoder.last_length,
                    )
                    .unwrap();
                    planned.emit_repeat_last(repeat);
                    encoder.emit_flags_byte(0);
                    encoder.emit_repeat_last(repeat);
                    assert_eq!(state(&encoder), state(&planned));
                }
            }
        }
    }
}

#[test]
fn flags_and_short_distance_updates_preserve_complete_alphabets() {
    let mut encoder = super::Unpack15Encoder::new();
    let mut renormalizations = 0;
    for flags in std::iter::repeat_n(255, 768).chain(0..=255) {
        let before = encoder.ch_set_c.iter().find(|&&v| v >> 8 == 255).unwrap() & 0xff;
        encoder.emit_flags_byte(flags);
        let after = encoder.ch_set_c.iter().find(|&&v| v >> 8 == 255).unwrap() & 0xff;
        renormalizations += usize::from(flags == 255 && after < before);
        let mut counts = [0u16; 256];
        for &entry in &encoder.ch_set_c {
            counts[(entry >> 8) as usize] += 1;
        }
        assert_eq!(counts, [1; 256]);
    }
    assert!(renormalizations >= 2);
    for length in 2..=10 {
        for distance in (1..=256).rev() {
            encoder.emit_short_lz(super::ShortLz { distance, length });
            let mut counts = [0u16; 256];
            for &entry in &encoder.ch_set_a {
                counts[entry as usize] += 1;
            }
            assert_eq!(counts, [1; 256]);
        }
    }
    let mut input: Vec<u8> = (0..=255).collect();
    input.extend_from_slice(&[0, 1]);
    assert_eq!(
        super::find_short_lz(&input, 256),
        Some(super::ShortLz {
            distance: 256,
            length: 2
        })
    );
}

#[test]
fn adaptive_literal_updates_preserve_every_byte_through_renormalization() {
    fn assert_alphabet(encoder: &super::Unpack15Encoder) {
        let mut counts = [0u16; 256];
        for &entry in &encoder.ch_set {
            counts[(entry >> 8) as usize] += 1;
            assert!(entry & 0xff <= 0xa1);
        }
        assert_eq!(counts, [1; 256]);
    }
    for stmode in [false, true] {
        for average in [0, 0x0e00, 0x3600, 0x5e00, 0x7600] {
            let mut encoder = super::Unpack15Encoder::new();
            encoder.avr_plc = average;
            let mut renormalizations = 0;
            for byte in std::iter::repeat_n(0, 512).chain(0..=255) {
                let before = encoder
                    .ch_set
                    .iter()
                    .find(|&&entry| entry >> 8 == 0)
                    .unwrap()
                    & 0xff;
                if stmode {
                    encoder.emit_stmode_literal(byte);
                } else {
                    encoder.emit_literal(byte);
                }
                let after = encoder
                    .ch_set
                    .iter()
                    .find(|&&entry| entry >> 8 == 0)
                    .unwrap()
                    & 0xff;
                renormalizations += usize::from(byte == 0 && after < before);
                assert_alphabet(&encoder);
            }
            assert!(renormalizations >= 2);
        }
    }
}

#[test]
fn public_decoder_clone_keeps_independent_solid_history_and_tables() {
    let first = b"legacy adaptive solid history ".repeat(32);
    let second = b"legacy adaptive solid history ".repeat(8);
    let mut encoder = super::Unpack15Encoder::new();
    let packed_first = encoder.encode_member(&first).unwrap();
    let packed_second = encoder.encode_member(&second).unwrap();
    let mut original = super::Unpack15::new();
    assert_eq!(
        original
            .decode_member(&packed_first, first.len(), false)
            .unwrap(),
        first
    );
    let mut copied = original.clone();
    let other = b"a different non-solid member";
    assert_eq!(
        original
            .decode_member(&super::unpack15_encode(other).unwrap(), other.len(), false)
            .unwrap(),
        other
    );
    drop(original);
    assert_eq!(
        copied
            .decode_member(&packed_second, second.len(), true)
            .unwrap(),
        second
    );
}

#[test]
fn reader15_workspace_refusals_release_window_input_output_and_checkpoint() {
    use crate::codec::workspace::{Allowance, RefusingBudget};
    let data = b"legacy reader owned capacity\n".repeat(32);
    let packed = unpack15_encode(&data).unwrap();
    for streaming in [false, true] {
        let run = |budget: &RefusingBudget| -> super::Result<()> {
            let mut decoder = super::Reader15State::with_allowance(budget)?;
            if streaming {
                let mut output = super::Buffer::new(budget);
                decoder.decode_member_from_reader(
                    &mut packed.as_slice(),
                    data.len(),
                    false,
                    &mut output,
                )?;
                assert_eq!(&*output, &data);
            } else {
                let output = decoder.decode_member(&packed, data.len(), false)?;
                assert_eq!(&*output, &data);
            }
            let checkpoint = decoder.try_clone()?;
            assert_eq!(checkpoint.window, decoder.window);
            Ok(())
        };
        let baseline = RefusingBudget::new(usize::MAX);
        run(&baseline).unwrap();
        let attempts = baseline.attempts();
        assert!(attempts >= 5);
        assert_eq!(baseline.used(), 0);
        for index in 0..attempts {
            let budget = RefusingBudget::new(index);
            assert!(
                matches!(run(&budget), Err(Error::Cancelled)),
                "allocation {index}, streaming={streaming}"
            );
            assert_eq!(budget.used(), 0);
        }
    }
    let limit = Allowance::limited(0xffff);
    assert!(matches!(
        super::Reader15State::with_allowance(&limit),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(limit.used(), 0);
}

#[test]
fn reader15_workspace_releases_input_and_chunk_on_sink_failure() {
    use crate::codec::workspace::Allowance;
    struct FailingSink;
    impl std::io::Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "sink denied",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let data = b"legacy output failure".repeat(10);
    let packed = unpack15_encode(&data).unwrap();
    let ledger = Allowance::limited(128 * 1024);
    let mut decoder = super::Reader15State::with_allowance(&ledger).unwrap();
    assert!(matches!(
        decoder.decode_member_from_reader(
            &mut packed.as_slice(),
            data.len(),
            false,
            &mut FailingSink
        ),
        Err(Error::Io(_))
    ));
    assert_eq!(
        ledger.used(),
        0x10000 + decoder.bits.input.capacity() as u64
    );
    drop(decoder);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn cancellation_interrupts_buffered_symbol_work() {
    let data = b"cancellable legacy symbols ".repeat(16384);
    let packed = unpack15_encode(&data).unwrap();
    let token = crate::ReadCancellation::new();
    let mut decoder = Unpack15::new();
    decoder.read_control = crate::read_control::ReadControl::new(Some(&token));
    decoder.read_control.cancel_after_checks(3);
    assert_eq!(
        decoder
            .decode_member(&packed, data.len(), false)
            .unwrap_err(),
        Error::Cancelled
    );
    assert!(decoder.state.output_written > 0 && decoder.state.output_written < data.len());
}
use super::{
    decode_num_bit_cost, find_long_lz, find_long_lz_with_buckets, find_lz_token, find_old_dist_lz,
    find_short_lz, flag_fits, long_lz_buckets, should_lazy_emit_literal, unpack15_decode,
    unpack15_encode, unpack15_encode_with_options, EncodeOptions, LongLz, LzPlanState, MatchToken,
    OldDistLz, Rar13MatchFinder, ShortLz, Unpack15, Unpack15Encoder, DEC_HF0, DEC_HF1, DEC_HF2,
    DEC_HF3, DEC_HF4, DEC_L1, DEC_L2, POS_HF0, POS_HF1, POS_HF2, POS_HF3, POS_HF4, POS_L1, POS_L2,
};

fn decode_num_prefix_is_stable(
    code: u32,
    len: usize,
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> bool {
    let relevant_tail_bits = 16usize.saturating_sub(len + 4);
    for tail in 0..(1u32 << relevant_tail_bits) {
        let bit_field = (code << (16 - len)) | (tail << 4);
        let (decoded, consumed) = simulate_decode_num(bit_field, start_pos, dec_tab, pos_tab);
        if decoded != target || consumed != len {
            return false;
        }
    }
    true
}

fn simulate_decode_num(
    bit_field: u32,
    mut start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> (u32, usize) {
    let num = bit_field & 0xfff0;
    let mut i = 0usize;
    while dec_tab[i] as u32 <= num {
        start_pos += 1;
        i += 1;
    }
    (
        ((num - if i > 0 { dec_tab[i - 1] as u32 } else { 0 }) >> (16 - start_pos))
            + pos_tab[start_pos as usize] as u32,
        start_pos as usize,
    )
}

#[test]
fn probe_rar15_solid() {
    let Ok(dir) = std::env::var("RARS_PROBE_DIR") else {
        return;
    };
    let options = EncodeOptions::new().with_lazy_matching(false);
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    let mut enc = Unpack15Encoder::with_options(options);
    let mut dec = Unpack15::new();
    for path in &names {
        let data = std::fs::read(path).unwrap();
        let packed = enc.encode_member(&data).unwrap();
        match dec.decode_member(&packed, data.len(), true) {
            Ok(out) if out == data => println!("{:?} solid OK", path.file_name().unwrap()),
            Ok(out) => println!(
                "{:?} solid WRONG at {:?}",
                path.file_name().unwrap(),
                out.iter().zip(data.iter()).position(|(a, b)| a != b)
            ),
            Err(e) => println!("{:?} solid ERROR {e:?}", path.file_name().unwrap()),
        }
    }
}

fn brute_decode_num_bit_cost(
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> Option<usize> {
    for len in start_pos as usize..=16 {
        for code in 0..(1u32 << len) {
            if decode_num_prefix_is_stable(code, len, target, start_pos, dec_tab, pos_tab) {
                return Some(len);
            }
        }
    }
    None
}

#[test]
fn decode_member_from_reader_accepts_incremental_input() {
    struct TinyReader<'a> {
        input: &'a [u8],
    }

    impl std::io::Read for TinyReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.input.is_empty() {
                return Ok(0);
            }
            let len = self.input.len().min(out.len()).min(2);
            out[..len].copy_from_slice(&self.input[..len]);
            self.input = &self.input[len..];
            Ok(len)
        }
    }

    let expected = b"RAR 1.4 incremental input fixture\n".repeat(32);
    let packed = unpack15_encode(&expected).unwrap();
    assert_eq!(unpack15_decode(&packed, expected.len()).unwrap(), expected);

    let mut reader = TinyReader { input: &packed };
    let mut decoder = Unpack15::new();
    let mut output = Vec::new();
    decoder
        .decode_member_from_reader(&mut reader, expected.len(), false, &mut output)
        .unwrap();

    assert_eq!(output, expected);
}

#[test]
fn literal_only_encoder_round_trips_flag_and_mode_boundaries() {
    for length in 0..=96 {
        let input: Vec<u8> = (0..length)
            .map(|index| (index * 73 + length * 17) as u8)
            .collect();
        let packed = Unpack15Encoder::new().encode_literals_only(&input).unwrap();
        let decoded = unpack15_decode(&packed, input.len()).unwrap();
        assert_eq!(decoded, input, "literal-only length {length}");
    }
}

#[test]
fn literal_only_encoder_follows_match_heavy_solid_history() {
    let second: Vec<u8> = (0..96).map(|index| (index * 73 + 17) as u8).collect();
    let first = match_heavy_payload(176, 8000);
    let mut encoder = Unpack15Encoder::with_options(EncodeOptions::new().with_lazy_matching(false));
    let first_packed = encoder.encode_member(&first).unwrap();
    assert!(
        encoder.nlzb > encoder.nhfb,
        "nlzb={} nhfb={}",
        encoder.nlzb,
        encoder.nhfb
    );
    let second_packed = encoder.encode_literals_only(&second).unwrap();

    let mut decoder = Unpack15::new();
    assert_eq!(
        decoder
            .decode_member(&first_packed, first.len(), false)
            .unwrap(),
        first
    );
    assert_eq!(
        decoder
            .decode_member(&second_packed, second.len(), true)
            .unwrap(),
        second
    );
}

#[test]
fn final_input_zero_pads_missing_bits_in_both_decode_paths() {
    let mut decoder = Unpack15::new();
    let direct = decoder.decode_member(&[], 8, false).unwrap();
    assert_eq!(direct.len(), 8);

    let mut decoder = Unpack15::new();
    let mut from_reader = Vec::new();
    decoder
        .decode_member_from_reader(&mut &[][..], 8, false, &mut from_reader)
        .unwrap();
    assert_eq!(from_reader, direct);
}

#[test]
fn fixed_number_tables_reencode_every_decoder_prefix() {
    for (start, thresholds, ranks, maximum) in [
        (4, DEC_HF0, POS_HF0, 256),
        (5, DEC_HF1, POS_HF1, 256),
        (5, DEC_HF2, POS_HF2, 256),
        (6, DEC_HF3, POS_HF3, 256),
        (8, DEC_HF4, POS_HF4, 256),
        (2, DEC_L1, POS_L1, 255),
        (3, DEC_L2, POS_L2, 255),
    ] {
        assert!(ranks.len() <= 17);
        assert!(ranks.len() > start as usize);
        assert!(thresholds.len() >= ranks.len() - start as usize);
        assert!(thresholds.iter().all(|&threshold| threshold != 0));
        assert!(thresholds.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(thresholds.last(), Some(&u16::MAX));
        let mut intervals = [None::<(u32, u32)>; 17];
        for field in 0..=u16::MAX {
            let (target, consumed) =
                simulate_decode_num(u32::from(field), start, thresholds, ranks);
            assert!(target <= maximum);
            let span = intervals[consumed].get_or_insert((target, target));
            span.0 = span.0.min(target);
            span.1 = span.1.max(target);
            let (prefix, length) =
                super::encode_decode_num_prefix(target, start, thresholds, ranks).unwrap();
            assert_eq!(length, consumed);
            assert_eq!(prefix, u32::from(field) >> (16 - length));
        }
        let mut next = 0;
        for (minimum, maximum) in intervals.into_iter().flatten() {
            assert_eq!(
                minimum, next,
                "nonempty intervals are contiguous in bit-length order"
            );
            next = maximum + 1;
        }
        assert_eq!(next, maximum + 1);
    }
}

#[test]
fn literal_codebooks_decode_every_rank_independently_of_following_bits() {
    for (start, thresholds, ranks) in [
        (4, DEC_HF0, POS_HF0),
        (5, DEC_HF1, POS_HF1),
        (5, DEC_HF2, POS_HF2),
        (6, DEC_HF3, POS_HF3),
        (8, DEC_HF4, POS_HF4),
    ] {
        for rank in 0..=256 {
            let (prefix, length) =
                super::encode_decode_num_prefix(rank, start, thresholds, ranks).unwrap();
            for suffix in 0..(1u32 << (16 - length)) {
                let field = (prefix << (16 - length)) | suffix;
                assert_eq!(
                    simulate_decode_num(field, start, thresholds, ranks),
                    (rank, length),
                    "start={start}, rank={rank}, suffix={suffix}"
                );
            }
        }
    }
}

#[test]
fn decode_num_bit_cost_matches_prefix_search_at_table_boundaries() {
    let tables = [
        (4, DEC_HF0, POS_HF0),
        (5, DEC_HF1, POS_HF1),
        (5, DEC_HF2, POS_HF2),
        (6, DEC_HF3, POS_HF3),
        (8, DEC_HF4, POS_HF4),
        (2, DEC_L1, POS_L1),
        (3, DEC_L2, POS_L2),
    ];
    let targets = [0, 1, 2, 3, 7, 8, 16, 24, 32, 33, 53, 117, 233, 255, 256];

    for (start_pos, dec_tab, pos_tab) in tables {
        for target in targets {
            assert_eq!(
                decode_num_bit_cost(target, start_pos, dec_tab, pos_tab),
                brute_decode_num_bit_cost(target, start_pos, dec_tab, pos_tab),
                "target {target}, start_pos {start_pos}"
            );
        }
    }
}

#[test]
fn encoder_emits_rar15_very_long_lz_matches() {
    let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
    input.extend_from_within(..258);

    assert_eq!(
        find_long_lz(&input, 300, 0x8000),
        Some(LongLz {
            distance: 300,
            length: 258
        })
    );
    let packed = unpack15_encode(&input).unwrap();

    assert!(
        packed.len() < 330,
        "very-long LongLZ should encode a 258-byte repeat compactly, got {} bytes",
        packed.len()
    );
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn short_lz_accepts_the_two_byte_wire_minimum() {
    let input = b"abXabY";

    assert_eq!(
        find_short_lz(input, 3),
        Some(ShortLz {
            distance: 3,
            length: 2,
        })
    );
    let packed = unpack15_encode(input).unwrap();
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn one_bit_match_flags_fit_at_every_open_position() {
    for used in 0..8 {
        assert!(flag_fits(used, &[true]), "flag bit {used}");
    }
    assert!(!flag_fits(8, &[true]));
}

#[test]
fn long_lz_search_accepts_near_distance_boundaries() {
    let distance_one = vec![b'A'; 64];
    assert_eq!(
        find_long_lz(&distance_one, 1, 0x8000),
        Some(LongLz {
            distance: 1,
            length: 63,
        })
    );

    let distance_sixteen = b"abcdefghijklmnop".repeat(4);
    assert_eq!(
        find_long_lz(&distance_sixteen, 16, 0x8000),
        Some(LongLz {
            distance: 16,
            length: 48,
        })
    );

    let distance_256: Vec<_> = (0u8..=255).cycle().take(512).collect();
    assert_eq!(
        find_long_lz(&distance_256, 256, 0x8000),
        Some(LongLz {
            distance: 256,
            length: 256,
        })
    );
}

#[test]
fn near_long_lz_requires_the_eleven_byte_wire_minimum() {
    let input = b"abcdefghijXabcdefghijY";

    assert_eq!(find_long_lz(input, 11, 0x8000), None);
}

#[test]
fn distance_257_remains_a_far_long_lz_match() {
    let mut state = 0x1234_5678u32;
    let mut input: Vec<_> = (0..257)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let repeated = input[..32].to_vec();
    input.extend_from_slice(&repeated);

    assert_eq!(
        find_long_lz(&input, 257, 0x8000),
        Some(LongLz {
            distance: 257,
            length: 32,
        })
    );
}

#[test]
fn near_candidates_do_not_spend_the_far_match_budget() {
    let pos = 2048;
    let mut state = 0x9e37_79b9u32;
    let mut input: Vec<_> = (0..pos + 32)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let pattern = b"ABCDEFGHIJKLMNOPQRST";
    input[128..128 + pattern.len()].copy_from_slice(pattern);
    input[pos..pos + pattern.len()].copy_from_slice(pattern);

    let far_distractors: Vec<_> = (0..63).map(|index| 512 + index * 4).collect();
    let near_distractors: Vec<_> = (0..64).map(|index| pos - 256 + index * 4).collect();
    for &candidate in far_distractors.iter().chain(&near_distractors) {
        input[candidate..candidate + 4].copy_from_slice(b"ABC!");
    }

    let mut positions = vec![128];
    positions.extend(far_distractors);
    positions.extend(near_distractors);
    let mut buckets = vec![Vec::new(); 1 << super::LONG_LZ_HASH_BITS];
    buckets[Rar13MatchFinder::hash(&input, pos)] = positions;
    let finder = Rar13MatchFinder { buckets };

    assert_eq!(
        find_long_lz_with_buckets(&input, pos, 0x8000, &finder, 64),
        Some(LongLz {
            distance: (pos - 128) as u32,
            length: pattern.len() as u32,
        })
    );
}

#[test]
fn encoder_selects_and_round_trips_a_near_long_lz_match() {
    let input = b"abcdefghijklmnop".repeat(64);
    let buckets = long_lz_buckets(&input);
    let encoder = Unpack15Encoder::new();

    assert!(matches!(
        encoder.choose_lz_token(&input, 16, &buckets, encoder.lz_plan_state()),
        Some(MatchToken::LongLz(LongLz {
            distance: 16,
            length: 258,
        }))
    ));

    let packed = unpack15_encode(&input).unwrap();
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

/// Ad-hoc token census for comparing equivalent RAR 1.4 archives.
///
/// Run with a platform-path-separated list of archive paths in
/// `RARS_RAR14_TOKEN_ARCHIVES` and `--ignored --nocapture`.
#[test]
#[ignore = "requires RARS_RAR14_TOKEN_ARCHIVES"]
fn report_rar14_token_census() {
    let paths =
        std::env::var_os("RARS_RAR14_TOKEN_ARCHIVES").expect("set RARS_RAR14_TOKEN_ARCHIVES");
    for path in std::env::split_paths(&paths) {
        let bytes = std::fs::read(&path).unwrap();
        let archive = crate::rar13::Archive::parse(&bytes).unwrap();
        let mut decoder = Unpack15::new();
        println!("{}", path.display());
        for entry in &archive.entries {
            if entry.is_stored() || entry.is_directory() {
                continue;
            }
            decoder.state.token_stats = super::DecodeTokenStats::default();
            decoder.state.old_distance_events.clear();
            decoder
                .decode_member(
                    entry.packed_data(&archive).unwrap(),
                    entry.header.unp_size as usize,
                    entry.header.flags & 0x10 != 0,
                )
                .unwrap();
            if decoder.state.token_stats.old_distance_matches != 0 {
                println!(
                    "  {}: {:?}",
                    String::from_utf8_lossy(&entry.name),
                    decoder.state.token_stats
                );
                if let Ok(from) = std::env::var("RARS_RAR14_EVENT_FROM") {
                    let from: usize = from.parse().unwrap();
                    for event in decoder.state.old_distance_events.iter().filter(|event| {
                        event.output_position >= from
                            && event.output_position < from.saturating_add(500)
                    }) {
                        println!(
                            "    pos={} code={} distance={} length={} max_dist3={}",
                            event.output_position,
                            event.short_code,
                            event.distance,
                            event.length,
                            event.max_dist3
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn encoder_adjusts_rar15_long_lz_length_for_far_distance_bonus() {
    let mut input: Vec<_> = (0..9000).map(|index| (index * 73 + 19) as u8).collect();
    input.extend_from_within(..10);

    let packed = unpack15_encode(&input).unwrap();

    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_reuses_rar15_repeat_last_token() {
    let input = b"abcdefghijklmnop".repeat(64);
    let packed = unpack15_encode(&input).unwrap();

    assert!(
        packed.len() < 100,
        "repeat-last tokens should keep a simple repeated pattern compact, got {} bytes",
        packed.len()
    );
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn old_distance_finder_maps_ring_entries_to_short_lz_codes() {
    let mut input: Vec<_> = (0..80).map(|index| (index * 37 + 11) as u8).collect();
    let pos = input.len();
    input.extend_from_within(pos - 33..pos - 13);

    assert_eq!(
        find_old_dist_lz(&input, pos, [11, 22, 33, 44], 0, 0x2001),
        Some(OldDistLz {
            distance: 33,
            length: 20,
            short_code: 11,
        })
    );
}

#[test]
fn old_distance_finder_rejects_dos_incompatible_maximum_length() {
    let mut input = b"abcd".repeat(128);
    let pos = input.len();
    input.extend((0..257).map(|index| b"abcd"[index % 4]));

    assert_eq!(
        find_old_dist_lz(&input, pos, [u32::MAX, 4, u32::MAX, u32::MAX], 2, 0x2001),
        None,
        "the unsafe old-distance candidate should fall back to another token kind"
    );
}

#[test]
fn old_distance_length_rejects_all_ones_symbol_for_every_short_code() {
    for short_code in 10..=13 {
        assert_eq!(
            super::old_dist_lz_length_code(257, 4, 0x2001, short_code),
            None,
            "near old-distance code {short_code}"
        );
        assert_eq!(
            super::old_dist_lz_length_code(258, 330, 0x2001, short_code),
            None,
            "far old-distance code {short_code}"
        );
        assert_eq!(
            super::old_dist_lz_length_code(256, 4, 0x2001, short_code),
            Some(254)
        );
        assert_eq!(
            super::old_dist_lz_length_code(257, 330, 0x2001, short_code),
            Some(254)
        );
    }
}

#[test]
fn planner_emits_safe_old_distance_token() {
    let mut input: Vec<_> = (0..80).map(|index| (index * 37 + 11) as u8).collect();
    let pos = input.len();
    input.extend_from_within(pos - 33..pos - 13);

    let encoder = Unpack15Encoder::new();
    let buckets = long_lz_buckets(&input);
    let token = encoder
        .choose_lz_token(
            &input,
            pos,
            &buckets,
            LzPlanState {
                last_dist: u32::MAX,
                last_length: 0,
                old_dist: [11, 22, 33, 44],
                old_dist_ptr: 0,
                max_dist3: 0x2001,
                nlzb: encoder.nlzb,
                nhfb: encoder.nhfb,
                l_count: encoder.l_count,
            },
        )
        .expect("old-distance candidate should be selected");

    assert_eq!(
        token,
        MatchToken::OldDist(OldDistLz {
            distance: 33,
            length: 20,
            short_code: 11,
        })
    );
}

#[test]
fn encoder_exits_stmode_when_literal_runs_trigger_decoder_mode() {
    let input: Vec<_> = (0..96).map(|index| (index * 73 + 19) as u8).collect();
    let packed = unpack15_encode(&input).unwrap();

    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_stmode_literals_for_long_literal_runs() {
    let input: Vec<_> = (0..128).map(|index| (index * 73 + 19) as u8).collect();
    let mut encoder = Unpack15Encoder::new();
    let packed = encoder.encode_member(&input).unwrap();

    assert!(
        encoder.stmode_literal_count > 0,
        "long literal runs should use stmode literals before exiting stmode"
    );
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_options_can_disable_stmode_literal_runs() {
    let input: Vec<_> = (0..128).map(|index| (index * 73 + 19) as u8).collect();
    let mut encoder =
        Unpack15Encoder::with_options(EncodeOptions::new().with_stmode_literal_runs(false));
    let packed = encoder.encode_member(&input).unwrap();

    assert_eq!(encoder.stmode_literal_count, 0);
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_options_bound_long_lz_search_distance() {
    let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
    input.extend_from_within(..64);

    assert_eq!(
        find_long_lz(&input, 300, 256),
        Some(LongLz {
            distance: 44,
            length: 44,
        })
    );
    assert_eq!(
        find_long_lz(&input, 300, 0x8000),
        Some(LongLz {
            distance: 300,
            length: 64
        })
    );
}

#[test]
fn long_lz_search_rejects_unencodable_32k_distance() {
    let mut input = Vec::with_capacity(0x8000 + 64);
    let mut state = 0x1234_5678u32;
    for _ in 0..0x8000 + 64 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 24) as u8);
    }
    let repeated = input[..64].to_vec();
    input[0x8000..0x8000 + 64].copy_from_slice(&repeated);

    let token = find_long_lz(&input, 0x8000, 0x8000);

    assert_ne!(token.map(|token| token.distance), Some(0x8000));
}

#[test]
fn lazy_match_prefers_longer_next_position_match() {
    let input = b"abcXbcQRSTabcQRSTUV";
    let buckets = long_lz_buckets(input);
    let token = find_lz_token(
        input,
        10,
        &buckets,
        LzPlanState {
            last_dist: u32::MAX,
            last_length: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            max_dist3: 0x2001,
            nlzb: 0,
            nhfb: 0,
            l_count: 0,
        },
        EncodeOptions::default(),
    )
    .unwrap();

    assert!(matches!(
        token,
        MatchToken::ShortLz(super::ShortLz { length: 3, .. })
    ));
    assert!(should_lazy_emit_literal(
        input,
        10,
        &buckets,
        token,
        0x2001,
        EncodeOptions::default()
    ));

    let packed = unpack15_encode(input).unwrap();
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn cost_aware_selection_prefers_better_bits_per_byte_token() {
    let mut input = vec![b'Z'; 40];
    input[7] = b'A';
    input[8] = b'A';
    input[9] = b'A';
    input[10] = b'B';
    input[39] = b'A';
    let pos = input.len();
    input.extend_from_slice(b"AAAAAAAAAA");

    let mut encoder = Unpack15Encoder::new();
    encoder.old_dist = [u32::MAX, u32::MAX, u32::MAX, 33];
    let buckets = long_lz_buckets(&input);
    let token = encoder
        .choose_lz_token(
            &input,
            pos,
            &buckets,
            LzPlanState {
                last_dist: u32::MAX,
                last_length: 0,
                old_dist: encoder.old_dist,
                old_dist_ptr: encoder.old_dist_ptr,
                max_dist3: encoder.max_dist3,
                nlzb: encoder.nlzb,
                nhfb: encoder.nhfb,
                l_count: encoder.l_count,
            },
        )
        .unwrap();

    assert_eq!(
        token,
        MatchToken::ShortLz(ShortLz {
            distance: 1,
            length: 10,
        })
    );
}

#[test]
fn planner_uses_simulated_max_dist3_for_old_distance_candidates() {
    let mut state = 0x1234_5678u32;
    let mut input = Vec::with_capacity(9004);
    for _ in 0..9004 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        input.push(state as u8);
    }
    let pos = 9000;
    let prefix = [input[0], input[1], input[2]];
    input[pos..pos + 3].copy_from_slice(&prefix);
    input[pos + 3] = input[3].wrapping_add(1);

    let mut encoder = Unpack15Encoder::new();
    encoder.max_dist3 = 0x7f00;
    let buckets = long_lz_buckets(&input);
    let token = encoder.choose_lz_token(
        &input,
        pos,
        &buckets,
        LzPlanState {
            last_dist: u32::MAX,
            last_length: 0,
            old_dist: [u32::MAX, u32::MAX, u32::MAX, 9000],
            old_dist_ptr: 0,
            max_dist3: 0x2001,
            nlzb: encoder.nlzb,
            nhfb: encoder.nhfb,
            l_count: encoder.l_count,
        },
    );

    assert_eq!(token, None);
}

#[test]
fn encoder_round_trips_source_shaped_payload() {
    let source = concat!(include_str!("../rar13.rs"), include_str!("encoder.rs")).as_bytes();
    let input = &source[..source.len().min(50_902)];

    let packed = unpack15_encode(input).unwrap();
    let decoded = unpack15_decode(&packed, input.len()).unwrap();

    let first_diff = decoded
        .iter()
        .zip(input)
        .position(|(actual, expected)| actual != expected);
    assert_eq!(first_diff, None, "first differing byte in decoded payload");
    assert_eq!(decoded, input);
}

/// Match-heavy input drives `nlzb` above `nhfb`, which widens the literal
/// flag to two bits, which is what lets a flag reach the last bit of a
/// flags byte with a bit still to place. The encoder used to pad the byte
/// and start the next group cleanly; the decoder read that padding as a
/// flag and everything after it decoded to the wrong bytes.
#[test]
fn a_flag_straddling_two_flags_bytes_round_trips() {
    let input = match_heavy_payload(176, 8000);

    let packed =
        unpack15_encode_with_options(&input, EncodeOptions::new().with_lazy_matching(false))
            .unwrap();
    let decoded = unpack15_decode(&packed, input.len()).unwrap();

    let first_diff = decoded
        .iter()
        .zip(&input)
        .position(|(actual, expected)| actual != expected);
    assert_eq!(first_diff, None, "first differing byte in decoded payload");
}

fn match_heavy_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let value = next();
        if out.len() > 4096 && value % 3 != 0 {
            let distance = 64 + (value >> 8) as usize % (out.len() - 64);
            let length = 3 + (value >> 40) as usize % 24;
            let start = out.len() - distance;
            for index in 0..length {
                let byte = out[start + index % distance];
                out.push(byte);
            }
        } else {
            out.push((value >> 24) as u8);
        }
    }
    out.truncate(len);
    out
}
