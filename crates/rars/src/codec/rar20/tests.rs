#[test]
fn reader20_workspace_refusals_release_lz_audio_input_and_checkpoints() {
    use crate::codec::workspace::RefusingBudget;
    let data = b"resource accounting for legacy audio and LZ\n".repeat(24);
    let streams = [
        super::unpack20_encode_literals(&data).unwrap(),
        super::encode_audio_member(&data, 4).unwrap(),
    ];
    for packed in streams {
        for streaming in [false, true] {
            let run = |budget: &RefusingBudget| -> super::Result<()> {
                let mut decoder = super::Reader20State::with_allowance(budget);
                if streaming {
                    let mut output = super::Buffer::new(budget);
                    decoder.decode_member_from_reader(
                        &mut packed.as_slice(),
                        data.len(),
                        &mut output,
                    )?;
                    assert_eq!(&*output, &data);
                } else {
                    let output = decoder.decode_member_owned(&packed, data.len())?;
                    assert_eq!(&*output, &data);
                }
                let checkpoint = decoder.try_clone()?;
                assert_eq!(checkpoint.output, decoder.output);
                Ok(())
            };
            let baseline = RefusingBudget::new(usize::MAX);
            run(&baseline).unwrap();
            let attempts = baseline.attempts();
            assert!(attempts > 10);
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
    }
}

#[test]
fn reader20_workspace_keeps_returned_data_charged_after_decoder_drop() {
    let data = b"owned legacy result".repeat(32);
    let packed = unpack20_encode_literals(&data).unwrap();
    let ledger = super::Allowance::limited(256 * 1024);
    let mut decoder = super::Reader20State::with_allowance(&ledger);
    let output = decoder.decode_member_owned(&packed, data.len()).unwrap();
    assert!(ledger.used() > output.capacity() as u64);
    drop(decoder);
    assert_eq!(ledger.used(), output.capacity() as u64);
    assert_eq!(&*output, &data);
    drop(output);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn cancellation_interrupts_buffered_symbol_work() {
    let data = b"cancellable legacy symbols ".repeat(16384);
    let packed = unpack20_encode_literals(&data).unwrap();
    let token = crate::ReadCancellation::new();
    let mut decoder = Unpack20::new();
    decoder.read_control = crate::read_control::ReadControl::new(Some(&token));
    decoder.read_control.cancel_after_checks(3);
    assert_eq!(
        decoder.decode_member(&packed, data.len()).unwrap_err(),
        Error::Cancelled
    );
    assert!(decoder.current_pos() > 0 && decoder.current_pos() < data.len());
}
type Unpack20 = super::Reader20State<super::Allowance>;
use super::{
    encode_tokens_with_progress, level_code_lengths_for_used_symbols, unpack20_decode,
    unpack20_encode_literals, BitWriter, CostModel, EncodeOptions, EncodeToken, Error, Huffman,
    Unpack20Encoder, LEVEL_COUNT,
};

/// 7-Zip builds the RAR pre-table with `k_BuildMode_Full` and refuses a
/// code that leaves part of the code space unassigned, where unrar takes
/// it. Giving every used symbol the same length only fills the space when
/// the count is a power of two, so the flat table we used to emit was
/// under-full for 3, 5, 6, 7, 9 symbols and so on, and 7-Zip rejected the
/// archive before decoding a byte.
#[test]
fn the_pre_table_fills_its_code_space_for_every_symbol_count() {
    for count in 1..=LEVEL_COUNT {
        let mut used = [false; LEVEL_COUNT];
        for slot in used.iter_mut().take(count) {
            *slot = true;
        }
        let lengths = level_code_lengths_for_used_symbols(used);

        let longest = lengths.iter().copied().max().unwrap();
        let kraft: u32 = lengths
            .iter()
            .filter(|&&len| len != 0)
            .map(|&len| 1u32 << (longest - len))
            .sum();
        assert_eq!(
            kraft,
            1 << longest,
            "{count} symbols gave the incomplete code {lengths:?}"
        );
    }
}

fn encode_tokens(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    cost_model: Option<&CostModel>,
) -> Vec<EncodeToken> {
    encode_tokens_with_progress(input, history, options, cost_model, None)
        .expect("encoding without cancellation cannot be cancelled")
}

const AUTOREJ_PACKED: &[u8] = &[
    0x09, 0x14, 0x0c, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0xce, 0xf8, 0x1f, 0xc1, 0xe6, 0x05, 0xfc,
    0x39, 0xc3, 0x50, 0x65, 0x08, 0x41, 0x94, 0xc4, 0x1d, 0xf3, 0xcd, 0x0d, 0x8e, 0x20, 0xf5, 0x9d,
    0x8e, 0x76, 0x1d, 0xc5, 0x19, 0xde, 0x16, 0x5b, 0x52, 0xb8, 0x8e, 0x75, 0xcd, 0xaf, 0x1f, 0xfc,
    0x9e, 0xf7, 0x00, 0x01, 0xbe, 0x90,
];

#[test]
fn decodes_rar20_lz_member() {
    assert_eq!(
        unpack20_decode(AUTOREJ_PACKED, expected_text().len()).unwrap(),
        expected_text()
    );
}

#[test]
fn rejects_oversubscribed_rar20_huffman_tables() {
    assert!(matches!(
        Huffman::from_lengths(&[1, 1, 1]),
        Err(Error::InvalidData("RAR 2.0 oversubscribed Huffman table"))
    ));
}

#[test]
fn rejects_an_empty_main_huffman_table() {
    let mut bits = BitWriter::default();
    bits.write_bits(0, 2); // LZ block with fresh tables.
    for symbol in 0..LEVEL_COUNT {
        bits.write_bits(u32::from(symbol == 0 || symbol == 18), 4);
    }
    for run in [138u32, 138, 98] {
        bits.write_bit(true); // Pre-table symbol 18.
        bits.write_bits(run - 11, 7);
    }

    assert_eq!(
        Unpack20::new()
            .decode_member(&bits.finish(), 1)
            .unwrap_err(),
        Error::InvalidData("RAR 2.0 empty Huffman table")
    );
}

#[test]
fn internal_bit_and_huffman_helpers_reject_out_of_range_requests() {
    assert!(matches!(
        Huffman::from_lengths(&[16]),
        Err(Error::InvalidData("RAR 2.0 Huffman length is too large"))
    ));
    assert!(matches!(
        super::canonical_codes(&[16]),
        Err(Error::InvalidData("RAR 2.0 Huffman length is too large"))
    ));
    assert_eq!(
        super::BitReader::new().peek_bits(25).unwrap_err(),
        Error::InvalidData("RAR 2.0 bit read is too wide")
    );
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
            let len = self.input.len().min(out.len()).min(3);
            out[..len].copy_from_slice(&self.input[..len]);
            self.input = &self.input[len..];
            Ok(len)
        }
    }

    let mut decoder = Unpack20::new();
    let mut reader = TinyReader {
        input: AUTOREJ_PACKED,
    };
    let mut output = Vec::new();
    decoder
        .decode_member_from_reader(&mut reader, expected_text().len(), &mut output)
        .unwrap();

    assert_eq!(output, expected_text());
}

#[test]
fn decode_member_from_reader_rejects_a_truncated_payload() {
    for end in [AUTOREJ_PACKED.len() / 2, AUTOREJ_PACKED.len() - 1] {
        let mut decoder = Unpack20::new();
        let mut packed = &AUTOREJ_PACKED[..end];
        assert_eq!(
            decoder
                .decode_member_from_reader(&mut packed, expected_text().len(), &mut Vec::new())
                .unwrap_err(),
            Error::InvalidData("RAR 2.0 bitstream is truncated")
        );
    }
}

#[test]
fn decode_member_from_reader_accepts_an_empty_member() {
    let mut decoder = Unpack20::new();
    let mut input = &[][..];
    let mut output = Vec::new();
    decoder
        .decode_member_from_reader(&mut input, 0, &mut output)
        .unwrap();
    assert!(output.is_empty());
}

#[test]
fn decoder_reports_truncated_tables_and_member_payloads() {
    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&[0], 1).unwrap_err(),
        Error::InvalidData("RAR 2.0 bitstream is truncated")
    );

    let input = expected_text();
    for packed in [
        &AUTOREJ_PACKED[..1],
        &AUTOREJ_PACKED[..AUTOREJ_PACKED.len() / 2],
    ] {
        let mut decoder = Unpack20::new();
        assert_eq!(
            decoder.decode_member(packed, input.len()).unwrap_err(),
            Error::InvalidData("RAR 2.0 bitstream is truncated")
        );
    }
}

#[test]
fn rejects_a_table_repeat_without_a_previous_level() {
    let mut bits = BitWriter::default();
    bits.write_bits(0, 2); // LZ, new tables.
    for symbol in 0..LEVEL_COUNT {
        bits.write_bits(u32::from(symbol == 0 || symbol == 16), 4);
    }
    bits.write_bit(true); // Pre-table symbol 16 at position zero.
    assert_eq!(
        Unpack20::new()
            .decode_member(&bits.finish(), 1)
            .unwrap_err(),
        Error::InvalidData("RAR 2.0 table repeat at start")
    );
}

#[test]
fn empty_member_does_not_try_to_decode_an_absent_main_table() {
    let mut decoder = Unpack20::new();
    assert_eq!(decoder.decode_member(&[0; 5], 0).unwrap(), b"");

    decoder.audio_block = true;
    assert_eq!(decoder.decode_member(&[0; 5], 0).unwrap(), b"");
}

#[test]
fn audio_table_resets_the_channel_when_channel_count_shrinks() {
    let mut decoder = Unpack20::new();
    decoder.channels = 4;
    decoder.cur_channel = 3;
    assert_eq!(
        decoder.decode_member(&synthetic_audio_block(1), 1).unwrap(),
        b"\0"
    );
    assert_eq!(decoder.cur_channel, 0);
}

#[test]
fn audio_lookahead_keeps_a_block_without_an_end_marker() {
    let mut packed = synthetic_audio_block(4);
    packed.extend_from_slice(&[0; 5]);
    let mut decoder = Unpack20::new();
    assert_eq!(decoder.decode_member(&packed, 4).unwrap(), vec![0; 4]);
    assert!(decoder.in_block);
}

#[test]
fn audio_predictor_coefficients_stop_at_their_format_limits() {
    for winning_difference in 1..=10 {
        let mut decoder = Unpack20::new();
        let state = &mut decoder.audio[0];
        state.byte_count = 31;
        state.dif = [u32::MAX / 4; 11];
        state.dif[winning_difference] = 0;
        let coefficient = (winning_difference - 1) / 2;
        state.k[coefficient] = if winning_difference % 2 == 1 { -17 } else { 16 };
        let before = state.k;

        decoder.decode_audio(0);
        assert_eq!(
            decoder.audio[0].k, before,
            "difference {winning_difference}"
        );
    }
}

#[test]
fn copy_match_zero_fills_an_offset_that_reaches_past_the_stream() {
    let mut decoder = Unpack20::new();
    decoder.output.extend_from_slice(b"AB").unwrap();

    decoder.copy_match(4, 9, 6).unwrap();

    assert_eq!(&*decoder.output, b"AB\0\0\0\0");
}

#[test]
fn repeat_last_without_a_previous_match_is_a_no_op() {
    let mut lengths = [0u8; super::MAIN_COUNT];
    lengths[0] = 1;
    lengths[256] = 1;
    let mut decoder = Unpack20::new();
    decoder.main = Huffman::from_lengths(&lengths).unwrap();
    decoder.in_block = true;
    decoder.bits.append(&[0b1000_0000]).unwrap(); // Repeat last, then literal zero.

    decoder.decode_until(1).unwrap();
    assert_eq!(&*decoder.output, b"\0");
    assert_eq!(decoder.last_length, 0);
}

#[test]
fn old_offset_match_applies_the_long_distance_length_adjustment() {
    let mut main_lengths = [0u8; super::MAIN_COUNT];
    main_lengths[0] = 1;
    main_lengths[257] = 1;
    let mut length_lengths = [0u8; super::LENGTH_COUNT];
    length_lengths[0] = 1;
    let mut decoder = Unpack20::new();
    decoder.main = Huffman::from_lengths(&main_lengths).unwrap();
    decoder.lengths = Huffman::from_lengths(&length_lengths).unwrap();
    decoder.old_offsets[0] = 0x40000;
    decoder.in_block = true;
    decoder.bits.append(&[0b1000_0000]).unwrap(); // Old offset 0, length slot 0.

    decoder.decode_until(1).unwrap();
    assert_eq!(&*decoder.output, b"\0");
    assert_eq!(decoder.last_length, 5); // 2 + three distance adjustments.
    assert_eq!(decoder.pending_match, Some((4, 0x40000)));
}

#[test]
fn unset_old_offset_match_uses_the_first_dictionary_byte() {
    let mut main_lengths = [0u8; super::MAIN_COUNT];
    main_lengths[0] = 1;
    main_lengths[257] = 1;
    let mut length_lengths = [0u8; super::LENGTH_COUNT];
    length_lengths[0] = 1;
    let mut decoder = Unpack20::new();
    decoder.main = Huffman::from_lengths(&main_lengths).unwrap();
    decoder.lengths = Huffman::from_lengths(&length_lengths).unwrap();
    decoder.in_block = true;
    decoder.bits.append(&[0b1000_0000]).unwrap();

    decoder.decode_until(2).unwrap();
    assert_eq!(&*decoder.output, b"\0\0");
    assert_eq!(decoder.last_offset, 0);
}

#[test]
fn offset_slot_without_extra_bits_decodes_the_first_distance() {
    let mut decoder = Unpack20::new();
    decoder.offsets = Huffman::from_lengths(&[1, 1]).unwrap();
    decoder.bits.append(&[0]).unwrap();
    assert_eq!(decoder.read_offset().unwrap(), 1);
}

#[test]
fn encoder_slot_tables_cover_their_entire_format_ranges() {
    for length in 3..=super::MAX_ENCODER_MATCH_LENGTH {
        let (slot, extra) = super::length_slot_for_match(length).unwrap();
        assert_eq!(super::LENGTH_BASES[slot] + extra + 3, length);
        assert!(extra < 1usize << super::LENGTH_BITS[slot]);
    }
    for offset in 1..=256 {
        let (slot, extra) = super::short_slot_for_match(offset).unwrap();
        assert_eq!(super::SHORT_BASES[slot] + extra + 1, offset);
        assert!(extra < 1usize << super::SHORT_BITS[slot]);
    }
    for slot in 0..super::OFFSET_COUNT {
        for extra in [0, (1usize << super::OFFSET_BITS[slot]) - 1] {
            let offset = super::OFFSET_BASES[slot] + extra + 1;
            let (actual_slot, actual_extra) = super::offset_slot_for_match(offset).unwrap();
            assert_eq!((actual_slot, actual_extra), (slot, extra));
        }
    }
    assert_eq!(
        super::OFFSET_BASES[super::OFFSET_COUNT - 1] + 65536,
        super::MAX_HISTORY
    );

    assert!(super::length_slot_for_match(2).is_err());
    assert!(super::length_slot_for_match(259).is_err());
    assert!(super::offset_slot_for_match(0).is_err());
    assert!(super::offset_slot_for_match(super::MAX_HISTORY + 1).is_err());
    assert!(super::short_slot_for_match(0).is_err());
    assert!(super::short_slot_for_match(257).is_err());

    for offset in [1, 0x40000] {
        let adjustment = super::old_length_adjustment(offset);
        for adjusted in 0..=255 {
            let length = adjusted + 2 + adjustment;
            let (slot, extra) = super::old_length_slot_for_match(length, offset).unwrap();
            assert_eq!(super::LENGTH_BASES[slot] + extra, adjusted);
        }
        assert!(super::old_length_slot_for_match(258 + adjustment, offset).is_err());
    }
}

#[test]
fn generated_huffman_lengths_are_canonical_for_rar20_table_sizes() {
    fn check<const N: usize>() {
        let mut seed = 0x9e37_79b9u32;
        for round in 0..128 {
            let mut frequencies = [0usize; N];
            for frequency in &mut frequencies {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                if !seed.is_multiple_of(5) {
                    *frequency = 1 + (seed as usize % (1 + round * round));
                }
            }
            if round % 2 == 0 {
                frequencies[0] = 1 << 24;
            }
            let lengths = super::huffman::lengths_for_frequency_array(&frequencies, 15);
            assert!(
                super::canonical_codes(&lengths).is_ok(),
                "size {N}, round {round}"
            );
        }
    }
    check::<{ super::MAIN_COUNT }>();
    check::<{ super::OFFSET_COUNT }>();
    check::<{ super::LENGTH_COUNT }>();
}

#[test]
fn decodes_synthetic_audio_block() {
    let packed = synthetic_audio_block(8);
    let mut decoder = Unpack20::new();

    assert_eq!(decoder.decode_member(&packed, 8).unwrap(), vec![0; 8]);
}

#[test]
fn audio_encoder_round_trips_interleaved_pcm_like_payload() {
    let input = interleaved_pcm_like_payload();
    let packed = super::encode_audio_member(&input, 4).unwrap();
    let decoded = unpack20_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn auto_encoder_uses_audio_when_it_beats_lz() {
    let input = interleaved_pcm_like_payload();
    let lz = unpack20_encode_literals(&input).unwrap();
    let auto = super::unpack20_encode_auto(&input).unwrap();
    let decoded = unpack20_decode(&auto, input.len()).unwrap();

    assert!(auto.len() < lz.len());
    assert_eq!(decoded, input);
}

#[test]
fn short_auto_encoded_members_skip_audio_candidates() {
    let input = b"short";
    let packed = super::unpack20_encode_auto(input).unwrap();
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);

    let packed = super::unpack20_encode_auto_with_options(
        input,
        EncodeOptions::default().with_try_audio(false),
    )
    .unwrap();
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);

    let mut always_continue = |_| true;
    let packed = super::unpack20_encode_auto_with_options_and_progress(
        input,
        EncodeOptions::default(),
        &mut always_continue,
    )
    .unwrap();
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_checks_cancellation_after_the_last_symbol() {
    let mut calls = 0;
    let mut cancel_at_end = |_| {
        calls += 1;
        calls == 1
    };
    assert_eq!(
        super::unpack20_encode_auto_with_options_and_progress(
            b"end",
            EncodeOptions::new(0).with_try_audio(false),
            &mut cancel_at_end,
        )
        .unwrap_err(),
        Error::Cancelled
    );
    assert_eq!(calls, 2);
}

#[test]
fn encoder_checks_cancellation_during_refinement() {
    let mut calls = 0;
    let mut cancel_during_refinement = |_| {
        calls += 1;
        calls <= 2
    };
    assert_eq!(
        super::unpack20_encode_auto_with_options_and_progress(
            b"ABCDABCDABCD",
            EncodeOptions::default().with_try_audio(false),
            &mut cancel_during_refinement,
        )
        .unwrap_err(),
        Error::Cancelled
    );
    assert_eq!(calls, 3);
}

#[test]
fn encoder_rejects_matches_beyond_the_configured_distance() {
    let input = b"abcXYabc";
    let mut finder = super::Rar20MatchFinder::new(input.len());
    finder.insert(input, 0);
    assert_eq!(
        super::best_match(
            input,
            5,
            input.len(),
            &finder,
            EncodeOptions::default().with_max_match_distance(2),
            None,
        ),
        None
    );
}

#[test]
fn missing_literal_code_has_a_nonzero_refinement_cost() {
    let lengths = [0u8; super::TABLE_COUNT];
    let prices = CostModel::new(&lengths);
    assert_eq!(prices.literal_bits(b"x", 0, 1), super::ABSENT_LITERAL_BITS);
}

#[test]
fn old_offset_ties_prefer_the_shorter_distance() {
    let lengths = [0u8; super::TABLE_COUNT];
    let prices = CostModel::new(&lengths);
    assert!(super::is_better_old_offset_match(
        Some(&prices),
        b"aaa",
        0,
        1,
        3,
        1,
        Some((0, 3, 2)),
    ));
    assert!(!super::is_better_old_offset_match(
        Some(&prices),
        b"aaa",
        0,
        1,
        3,
        3,
        Some((0, 3, 2)),
    ));

    // One extra bit for a longer match can exactly cancel the extra
    // literal it saves. On that score tie, prefer the longer match.
    let mut lengths = [0u8; super::TABLE_COUNT];
    lengths[b'a' as usize] = 1;
    lengths[super::MAIN_COUNT + super::OFFSET_COUNT + 2] = 1;
    let prices = CostModel::new(&lengths);
    let short = super::SelectedMatch::OldOffset {
        index: 0,
        length: 3,
        offset: 1,
    };
    let long = super::SelectedMatch::OldOffset {
        index: 1,
        length: 4,
        offset: 1,
    };
    assert_eq!(
        prices.selected_score(short, b"aaaa", 0),
        prices.selected_score(long, b"aaaa", 0)
    );
    assert!(super::is_better_old_offset_match(
        Some(&prices),
        b"aaaa",
        0,
        1,
        4,
        1,
        Some((0, 3, 1)),
    ));
    assert!(!super::is_better_old_offset_match(
        Some(&prices),
        b"aaaa",
        0,
        0,
        3,
        1,
        Some((1, 4, 1)),
    ));
}

#[test]
fn audio_encoder_rejects_channel_counts_outside_the_format() {
    for channels in [0, 5] {
        assert_eq!(
            super::encode_audio_member(b"audio", channels).unwrap_err(),
            Error::InvalidData("RAR 2.0 audio channel count is invalid")
        );
    }
}

#[test]
fn default_encode_options_match_legacy_entry_points() {
    let input = b"rar20 option plumbing preserves default output ".repeat(128);
    assert_eq!(
        unpack20_encode_literals(&input).unwrap(),
        super::unpack20_encode_literals_with_options(&input, EncodeOptions::default()).unwrap()
    );
    assert_eq!(
        super::unpack20_encode_auto(&input).unwrap(),
        super::unpack20_encode_auto_with_options(&input, EncodeOptions::default()).unwrap()
    );

    let first = b"solid rar20 option seed ".repeat(64);
    let second = b"solid rar20 option seed with suffix ".repeat(32);
    let mut legacy = Unpack20Encoder::new();
    let mut explicit = Unpack20Encoder::with_options(EncodeOptions::default());
    assert_eq!(
        legacy.encode_member(&first).unwrap(),
        explicit.encode_member(&first).unwrap()
    );
    assert_eq!(
        legacy.encode_member(&second).unwrap(),
        explicit.encode_member(&second).unwrap()
    );
}

#[test]
fn direct_option_field_assignment_cannot_exceed_rar20_distance_limit() {
    let mut options = EncodeOptions::new(1);
    options.max_match_distance = super::MAX_ENCODER_MATCH_OFFSET + 1;
    assert_eq!(
        options.constrained().max_match_distance,
        super::MAX_ENCODER_MATCH_OFFSET
    );
    assert_eq!(
        Unpack20Encoder::with_options(options)
            .options
            .max_match_distance,
        super::MAX_ENCODER_MATCH_OFFSET
    );
}

#[test]
fn optimal_parser_skips_an_out_of_format_fresh_match() {
    let start = super::MAX_ENCODER_MATCH_OFFSET + 1;
    let end = start + 5;
    let mut input = vec![b'X'; end];
    input[..5].copy_from_slice(b"abcde");
    input[start..].copy_from_slice(b"abcde");
    let mut finder = super::Rar20MatchFinder::new(input.len());
    finder.insert(&input, 0);
    let mut options = EncodeOptions::new(1).with_optimal_parse(true);
    options.max_match_distance = start;
    let lengths = [0u8; super::TABLE_COUNT];
    let prices = CostModel::new(&lengths);

    let tokens = super::encode_tokens_optimal(&input, start, end, &mut finder, options, &prices);
    assert_eq!(tokens.len(), 5);
    assert!(tokens
        .iter()
        .all(|token| matches!(token, EncodeToken::Literal(_))));
}

#[test]
fn encode_options_can_disable_fresh_lz_matches() {
    let input = b"abcdefabcdefabcdefabcdef";
    let default_tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
    let literalish_tokens = encode_tokens(input, &[], EncodeOptions::new(0), None);

    assert!(default_tokens
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { .. })));
    assert!(!literalish_tokens
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { .. })));
}

#[test]
fn table_level_encoder_uses_rar20_run_symbols() {
    let lengths = [0, 0, 0, 0, 5, 5, 5, 5, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let tokens = super::encode_level_tokens(&lengths);

    assert_eq!(
        tokens,
        vec![
            super::LevelToken::zero_run_short(4),
            super::LevelToken::plain(5),
            super::LevelToken::repeat_previous(3),
            super::LevelToken::plain(7),
            super::LevelToken::zero_run_short(10),
            super::LevelToken::plain(2),
        ]
    );
}

#[test]
fn decodes_back_to_back_fresh_audio_blocks() {
    // No real RAR 2.x encoder we tested emits a mid-stream `audio_block,
    // !keep_tables` transition; reference encoders always either keep the
    // existing audio tables across boundaries or switch out to LZ. The
    // decoder branch that rebuilds `audio_tables` from a freshly-read level
    // table inside an audio sequence is therefore only reachable via a
    // hand-crafted fixture.
    let mut bits = BitWriter::default();
    write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ true);
    write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ false);
    let packed = bits.finish();

    let mut decoder = Unpack20::new();

    assert_eq!(decoder.decode_member(&packed, 8).unwrap(), vec![0; 8]);
}

#[test]
fn audio_member_reads_trailing_table_for_next_solid_member() {
    let mut bits = BitWriter::default();
    write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ true);
    write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ false);
    let packed = bits.finish();

    let mut decoder = Unpack20::new();
    assert_eq!(decoder.decode_member(&packed, 4).unwrap(), vec![0; 4]);
    assert_eq!(decoder.decode_member(&[], 4).unwrap(), vec![0; 4]);
}

#[test]
fn lz_member_reads_trailing_table_for_next_solid_member() {
    let mut bits = BitWriter::default();
    write_fresh_lz_zero_block(&mut bits, 4, true);
    write_fresh_lz_zero_block(&mut bits, 4, false);
    let packed = bits.finish();

    let mut decoder = Unpack20::new();
    assert_eq!(decoder.decode_member(&packed, 4).unwrap(), vec![0; 4]);
    assert_eq!(decoder.decode_member(&[], 4).unwrap(), vec![0; 4]);
}

fn write_fresh_lz_zero_block(bits: &mut BitWriter, count: usize, end: bool) {
    let mut table = [0u8; super::TABLE_COUNT];
    table[0] = 1;
    table[269] = 1;
    let level_tokens = super::encode_table_level_tokens(&table);
    let level_lengths = super::level_code_lengths_for_tokens(&level_tokens);
    let level_codes = super::canonical_codes(&level_lengths).unwrap();
    let main_codes = super::canonical_codes(&table[..super::MAIN_COUNT]).unwrap();

    bits.write_bits(0, 2);
    for &len in &level_lengths {
        bits.write_bits(len as u32, 4);
    }
    for token in level_tokens {
        let code = level_codes[token.symbol].unwrap();
        bits.write_bits(code.code as u32, code.len);
        bits.write_bits(token.extra_value as u32, token.extra_bits);
    }
    let zero = main_codes[0].unwrap();
    for _ in 0..count {
        bits.write_bits(zero.code as u32, zero.len);
    }
    if end {
        let end_code = main_codes[269].unwrap();
        bits.write_bits(end_code.code as u32, end_code.len);
    }
}

#[test]
fn decoder_and_encoder_retain_only_the_last_window_of_solid_history() {
    let first = vec![b'A'; super::MAX_HISTORY / 2 + 64];
    let second = vec![b'B'; super::MAX_HISTORY / 2 + 64];
    let mut encoder = Unpack20Encoder::with_options(EncodeOptions::new(0));
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();
    assert_eq!(encoder.history.len(), super::MAX_HISTORY);

    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert_eq!(
        decoder.decode_member(&second_packed, second.len()).unwrap(),
        second
    );
    assert_eq!(decoder.output.len(), super::MAX_HISTORY);
    assert_eq!(decoder.base_offset, 128);
}

#[test]
fn decode_member_carries_a_match_across_output_boundary() {
    let input = b"ABCD".repeat(20);
    let packed = unpack20_encode_literals(&input).unwrap();
    let mut decoder = Unpack20::new();

    let first = decoder.decode_member(&packed, 6).unwrap();
    assert!(decoder.pending_match.is_some());
    let second = decoder
        .decode_member(&[], input.len() - first.len())
        .unwrap();

    assert_eq!([first, second].concat(), input);
    assert!(decoder.pending_match.is_none());
}

fn expected_text() -> Vec<u8> {
    b"Hello text not audio.\r\n".repeat(100)
}

fn interleaved_pcm_like_payload() -> Vec<u8> {
    let mut input = Vec::new();
    for sample in 0..8192i16 {
        let left = sample.wrapping_mul(3).wrapping_add(200);
        let right = sample.wrapping_mul(3).wrapping_sub(200);
        input.extend_from_slice(&left.to_le_bytes());
        input.extend_from_slice(&right.to_le_bytes());
    }
    input
}

fn synthetic_audio_block(samples: usize) -> Vec<u8> {
    let mut bits = BitWriter::default();

    bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
    bits.write_bits(0, 2); // one channel.

    for symbol in 0..19 {
        let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
        bits.write_bits(len, 4);
    }

    bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
    bits.write_bit(true); // level symbol 18: 138 zeros.
    bits.write_bits(127, 7);
    bits.write_bit(true); // level symbol 18: 118 zeros.
    bits.write_bits(107, 7);

    for _ in 0..samples {
        bits.write_bit(false); // audio delta 0.
    }

    bits.finish()
}

fn write_fresh_audio_block(bits: &mut BitWriter, samples: usize, emit_end_sentinel: bool) {
    bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
    bits.write_bits(0, 2); // one channel.

    for symbol in 0..19 {
        let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
        bits.write_bits(len, 4);
    }

    // Audio table: symbol 0 (delta 0) = "0", symbol 256 (block end) = "1".
    bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
    bits.write_bit(true); // level symbol 18: 138 zeros (audio symbols 1..=138).
    bits.write_bits(127, 7);
    bits.write_bit(true); // level symbol 18: 117 zeros (audio symbols 139..=255).
    bits.write_bits(106, 7);
    bits.write_bit(false); // level symbol 1: block-end (256) has code length 1.

    for _ in 0..samples {
        bits.write_bit(false); // audio delta 0.
    }
    if emit_end_sentinel {
        bits.write_bit(true); // audio symbol 256: end of audio block.
    }
}

#[test]
fn literal_encoder_round_trips_rar20_lz_blocks() {
    let input = b"literal-only RAR 2.0 baseline\nwith repeated text literal-only\n";
    let packed = unpack20_encode_literals(input).unwrap();

    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar20_offset_one_matches_for_repeated_bytes() {
    let input = b"A".repeat(1024);
    let packed = unpack20_encode_literals(&input).unwrap();

    assert!(packed.len() < input.len() / 4);
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar20_dictionary_matches_for_repeated_sequences() {
    let input = b"abc123xyz-".repeat(128);
    let packed = unpack20_encode_literals(&input).unwrap();

    assert!(packed.len() < input.len() / 2);
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar20_repeat_last_matches_for_regular_streams() {
    let input = b"\x00\x01\x02\x03".repeat(4096);
    let tokens = encode_tokens(&input, &[], EncodeOptions::default(), None);
    let packed = unpack20_encode_literals(&input).unwrap();

    assert!(tokens
        .iter()
        .any(|token| matches!(token, EncodeToken::RepeatLast)));
    assert!(packed.len() < input.len() / 8);
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar20_minimum_length_fresh_matches() {
    let input = b"abcabc";
    let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
    let packed = unpack20_encode_literals(input).unwrap();

    assert!(matches!(
        tokens.as_slice(),
        [
            EncodeToken::Literal(b'a'),
            EncodeToken::Literal(b'b'),
            EncodeToken::Literal(b'c'),
            EncodeToken::Match {
                length: 3,
                offset: 3
            }
        ]
    ));
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar20_short_offset_matches() {
    let input = b"abab";
    let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
    let packed = unpack20_encode_literals(input).unwrap();

    assert!(matches!(
        tokens.as_slice(),
        [
            EncodeToken::Literal(b'a'),
            EncodeToken::Literal(b'b'),
            EncodeToken::ShortOffset { offset: 2 }
        ]
    ));
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar20_old_offset_matches() {
    let input = b"abcdabcdXYZXYZwxyzwxyz";
    let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
    let packed = unpack20_encode_literals(input).unwrap();

    assert!(tokens
        .iter()
        .any(|token| matches!(token, EncodeToken::OldOffset { .. })));
    assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_finds_rar20_matches_beyond_near_offsets() {
    let phrase = b"long-distance repeated phrase for rar20 match finder.";
    let mut input = Vec::new();
    input.extend_from_slice(phrase);
    input.extend(std::iter::repeat_n(0, 300 * 1024));
    input.extend_from_slice(phrase);
    input.extend_from_slice(phrase);
    let tokens = encode_tokens(&input, &[], EncodeOptions::default(), None);
    let packed = unpack20_encode_literals(&input).unwrap();

    assert!(tokens.iter().any(|token| matches!(
        token,
        EncodeToken::Match { offset, .. } if *offset > 0x40000
    )));
    assert!(packed.len() < input.len());
    let decoded = unpack20_decode(&packed, input.len()).unwrap();
    assert!(
        decoded == input,
        "RAR 2.0 long-distance match round-trip failed"
    );
}

#[test]
fn solid_encoder_emits_rar20_matches_against_previous_member_history() {
    let first = b"solid rar20 shared phrase alpha beta gamma ".repeat(4);
    let second = b"solid rar20 shared phrase alpha beta gamma ".repeat(2);
    let independent = unpack20_encode_literals(&second).unwrap();
    let mut encoder = Unpack20Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();

    assert!(second_packed.len() < independent.len());
    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert_eq!(
        decoder.decode_member(&second_packed, second.len()).unwrap(),
        second
    );
}

#[test]
fn the_optimal_parse_never_loses_to_the_greedy_one() {
    // Repeated phrases at varying distances with literal noise between
    // them, which is where committing to the first match found costs
    // something: the greedy parse takes a short match that a later, longer
    // one would have covered for free.
    let mut input = Vec::new();
    for round in 0..64u8 {
        input.extend_from_slice(b"the quick brown fox jumps over the lazy dog");
        input.extend_from_slice(&[round, round ^ 0x5a, round.wrapping_mul(31)]);
        input.extend_from_slice(b"over the lazy dog and the quick brown fox");
        input.push(round ^ 0xa5);
    }

    let greedy_options = EncodeOptions::new(256)
        .with_lazy_matching(true)
        .with_lazy_lookahead(2);
    let greedy = super::unpack20_encode_literals_with_options(&input, greedy_options).unwrap();
    let optimal = super::unpack20_encode_literals_with_options(
        &input,
        greedy_options.with_optimal_parse(true),
    )
    .unwrap();

    assert!(
        optimal.len() <= greedy.len(),
        "optimal {} greedy {}",
        optimal.len(),
        greedy.len()
    );
    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&optimal, input.len()).unwrap(),
        input,
        "the optimal parse produced something the decoder disagrees with"
    );
}

#[test]
fn the_optimal_parse_decodes_whatever_it_is_given() {
    // Shapes that stress different corners of the parse: nothing to match,
    // one long run, matches that reach back exactly to the rep offsets, and
    // bytes with no structure at all.
    let mut noise = Vec::new();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..8192 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        noise.push(seed as u8);
    }
    let cases: Vec<Vec<u8>> = vec![
        b"a".to_vec(),
        b"abc".to_vec(),
        vec![0u8; 5000],
        (0u8..=255).cycle().take(4096).collect(),
        b"xyzzy".repeat(700),
        noise,
    ];

    for input in cases {
        let options = EncodeOptions::new(256)
            .with_lazy_matching(true)
            .with_lazy_lookahead(2)
            .with_optimal_parse(true);
        let packed = super::unpack20_encode_literals_with_options(&input, options).unwrap();
        let mut decoder = Unpack20::new();
        assert_eq!(
            decoder.decode_member(&packed, input.len()).unwrap(),
            input,
            "round trip failed for a {} byte member",
            input.len()
        );
    }
}

#[test]
fn solid_encoder_reuses_rar20_tables_at_member_boundary() {
    let first: Vec<_> = (0u8..=255).cycle().take(4096).collect();
    let second = b"short literal member after reused rar20 table boundary\n";
    let independent = unpack20_encode_literals(second).unwrap();
    let mut encoder = Unpack20Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(second).unwrap();

    assert!(second_packed.len() < independent.len());
    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert_eq!(
        decoder.decode_member(&second_packed, second.len()).unwrap(),
        second
    );
}

#[test]
fn solid_encoder_matches_immediately_after_rar20_table_boundary() {
    let phrase = b"rar20 table boundary match phrase with enough bytes ";
    let first = phrase.repeat(128);
    let second = phrase.repeat(8);
    let independent = unpack20_encode_literals(&second).unwrap();
    let mut encoder = Unpack20Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();
    let tokens = encode_tokens(&second, &first, EncodeOptions::default(), None);

    assert!(matches!(tokens.first(), Some(EncodeToken::Match { .. })));
    assert!(second_packed.len() < independent.len());
    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert_eq!(
        decoder.decode_member(&second_packed, second.len()).unwrap(),
        second
    );
}

#[test]
fn solid_encoder_carries_rar20_history_across_multiple_members() {
    let first = b"rar20 multi member solid seed ".repeat(512);
    let second = b"rar20 multi member solid seed with middle tail ".repeat(128);
    let third = b"with middle tail ".repeat(64);
    let independent = unpack20_encode_literals(&third).unwrap();
    let mut encoder = Unpack20Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();
    let third_packed = encoder.encode_member(&third).unwrap();

    assert!(third_packed.len() < independent.len());
    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert_eq!(
        decoder.decode_member(&second_packed, second.len()).unwrap(),
        second
    );
    assert_eq!(
        decoder.decode_member(&third_packed, third.len()).unwrap(),
        third
    );
}

#[test]
fn decode_member_to_streams_decoded_payload_through_writer_sink() {
    let input = b"abcabcabcabcabcabcabcabcabcabcabcabc";
    let packed = unpack20_encode_literals(input).unwrap();

    let mut decoder = Unpack20::new();
    let mut sink = Vec::new();
    decoder
        .decode_member_to(&packed, input.len(), &mut sink)
        .unwrap();
    assert_eq!(sink, input);

    // The error-mapping closure inside decode_member_to fires when the
    // sink's write_all returns Err — feed it a writer that always fails.
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut decoder = Unpack20::new();
    let err = decoder
        .decode_member_to(&packed, input.len(), &mut FailingWriter)
        .unwrap_err();
    assert_eq!(err, Error::from(std::io::Error::other("disk full")));
}
