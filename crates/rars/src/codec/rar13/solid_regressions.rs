
use super::*;
type Unpack15 = Reader15State<Allowance>;
type BitReader = ReaderBits<Allowance>;

/// The options the RAR 1.3 writer uses at its default level.
fn rar13_options() -> EncodeOptions {
    EncodeOptions::new()
        .with_old_distance_tokens(false)
        .with_lazy_matching(false)
}

fn encode_solid_run(members: &[&[u8]], options: EncodeOptions) -> Vec<Vec<u8>> {
    let mut encoder = Unpack15Encoder::with_options(options);
    members
        .iter()
        .map(|member| encoder.encode_member(member).unwrap())
        .collect()
}

fn decode_solid_run(packed: &[Vec<u8>], members: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut decoder = Unpack15::new();
    packed
        .iter()
        .zip(members)
        .map(|(packed, member)| {
            decoder
                .decode_member(packed, member.len(), true)
                .unwrap()
                .into_vec()
        })
        .collect()
}

/// The short-LZ literal run does not survive a member boundary: the decoder
/// clears it for every member, solid or not. The encoder kept it, so where
/// a member happened to end mid-run the next one opened with a break bit
/// nothing would read, and every symbol after it was a bit out of step.
///
/// This pair is the smallest one that ends a member with the run at two.
#[test]
fn a_member_boundary_clears_the_short_lz_literal_run() {
    let first: Vec<u8> = b"abcdefgh".iter().cycle().take(128).copied().collect();
    let second = vec![0u8; 16];
    let members: Vec<&[u8]> = vec![&first, &second];

    let packed = encode_solid_run(&members, rar13_options());
    let decoded = decode_solid_run(&packed, &members);

    assert_eq!(decoded[0], first);
    assert_eq!(
        decoded[1], second,
        "the second member decoded a bit out of step"
    );
}

/// A decoder handed a solid member first skips the non-solid reset, so
/// whatever it was constructed with is what decodes the member. It used to
/// be constructed with the Huffman tables left at zero.
#[test]
fn a_first_member_marked_solid_decodes_against_real_tables() {
    let member = b"the quick brown fox jumps over the lazy dog\n".repeat(40);
    let members: Vec<&[u8]> = vec![&member];
    let packed = encode_solid_run(&members, rar13_options());

    let mut fresh = Unpack15::new();
    let solid = fresh.decode_member(&packed[0], member.len(), true).unwrap();
    assert_eq!(solid, member);

    // And it agrees with the same member read as a fresh one.
    let mut other = Unpack15::new();
    let plain = other
        .decode_member(&packed[0], member.len(), false)
        .unwrap();
    assert_eq!(plain, member);
}

/// Several members in a row, with the shapes that move the adaptive state
/// around: a long run, incompressible bytes, a short member and an empty
/// one.
#[test]
fn a_long_solid_run_round_trips() {
    let repetitive = b"solid chain payload ".repeat(500);
    let counted: Vec<u8> = (0..30_000u32)
        .map(|index| (index * 7 % 251) as u8)
        .collect();
    let short = b"tail".to_vec();
    let empty = Vec::new();
    let members: Vec<&[u8]> = vec![&repetitive, &counted, &short, &empty, &repetitive];

    for options in [
        rar13_options(),
        EncodeOptions::new().with_lazy_matching(false),
    ] {
        let packed = encode_solid_run(&members, options);
        let decoded = decode_solid_run(&packed, &members);
        for (index, (got, want)) in decoded.iter().zip(&members).enumerate() {
            assert_eq!(got, want, "member {index} did not survive the solid run");
        }
    }
}

#[test]
fn final_encoder_progress_report_can_cancel() {
    let mut encoder = Unpack15Encoder::new();
    let mut reports = Vec::new();
    let error = encoder
        .encode_member_with_progress(b"nonempty", &mut |position| {
            reports.push(position);
            reports.len() == 1
        })
        .unwrap_err();
    assert_eq!(error, Error::Cancelled);
    assert_eq!(reports, [8, 8]);
}

#[test]
fn literal_only_encoder_exits_stmode_without_literal_runs() {
    let input: Vec<_> = (0..128).map(|index| (index * 73 + 19) as u8).collect();
    let mut encoder =
        Unpack15Encoder::with_options(EncodeOptions::new().with_stmode_literal_runs(false));
    let packed = encoder.encode_literals_only_member(&input);
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn default_encoder_round_trips_low_rank_literal_history() {
    let input = vec![b'x'; 4096];
    let mut encoder = Unpack15Encoder::default();
    let packed = encoder.encode_literals_only_member(&input);
    assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    assert!(encoder.avr_plc <= 0x0dff);
}

#[test]
fn long_match_search_rejects_zero_history_or_distance_budget() {
    let input = b"repeated repeated";
    assert_eq!(find_long_lz(input, 0, 16), None);
    assert_eq!(find_long_lz(input, 9, 0), None);
    let buckets = long_lz_buckets(input);
    assert_eq!(find_long_lz_with_buckets(input, 9, 0, &buckets, 8), None);
}

#[test]
fn equal_length_match_candidates_keep_nearest_distance() {
    assert_eq!(
        super::find_long_lz(&[0; 24], 11, 11),
        Some(super::LongLz {
            distance: 1,
            length: 13
        })
    );
    let short = b"abcXabcYabcZ";
    assert_eq!(
        find_short_lz(short, 8),
        Some(ShortLz {
            distance: 4,
            length: 3,
        })
    );

    let prefix = b"abcdefghijkl";
    let mut long = Vec::new();
    for suffix in *b"XYZ" {
        long.extend_from_slice(prefix);
        long.push(suffix);
    }
    let buckets = long_lz_buckets(&long);
    assert_eq!(
        find_long_lz_with_buckets(&long, 26, 0x7fff, &buckets, 64),
        Some(LongLz {
            distance: 13,
            length: 12,
        })
    );
}

#[test]
fn decoder_refuses_literal_past_declared_output_size() {
    let mut decoder = Unpack15::new();
    decoder.target = 0;
    assert_eq!(
        decoder.put_byte(b'x', &mut Vec::new()),
        Err(Error::InvalidData("RAR 1.3 literal exceeds output size"))
    );
}

#[test]
fn number_prefix_search_rejects_unrepresentable_candidates() {
    assert_eq!(
        super::encode_decode_num_prefix(u32::MAX, 4, super::DEC_HF0, super::POS_HF0),
        None
    );
    assert_eq!(
        super::decode_num_bit_cost(256, 2, super::DEC_L1, super::POS_L1),
        None
    );
    assert_eq!(
        super::decode_num_bit_cost(256, 3, super::DEC_L2, super::POS_L2),
        None
    );
}

#[test]
fn decoder_reads_far_short_match_token() {
    let mut encoder = Unpack15Encoder::new();
    encoder.emit_short_lz_code(10);
    emit_decode_num(&mut encoder.bits, 0xff, 2, DEC_L1, POS_L1);
    encoder.emit_short_lz_code(14);
    emit_decode_num(&mut encoder.bits, 0, 3, DEC_L2, POS_L2);
    encoder.bits.write_bits(0, 15);

    let mut decoder = Unpack15::new();
    decoder.bits = BitReader::new(&encoder.bits.finish());
    decoder.target = 0x8000 + 5;
    decoder.output_written = 0x8000;
    decoder.unp_ptr = 0x8000;
    decoder.window[..5].copy_from_slice(b"abcde");
    let mut output = Vec::new();
    decoder.short_lz(&mut output).unwrap();
    assert_eq!(decoder.buf60, 1);
    assert!(output.is_empty(), "Buf60 toggle emits no match");
    decoder.short_lz(&mut output).unwrap();
    assert_eq!(output, b"abcde");
    assert_eq!(decoder.token_stats.short_matches, 1);
}

#[test]
fn short_lz_prefix_tables_cover_every_byte_with_each_buf60_state() {
    // RAR13_FORMAT_SPECIFICATION.md §6.13: Buf60 changes one prefix in
    // each table. Completeness must hold for both wire states.
    for (lengths, prefixes, adjusted) in [
        (&super::SHORT_LEN1, &super::SHORT_XOR1, 1),
        (&super::SHORT_LEN2, &super::SHORT_XOR2, 3),
    ] {
        for buf60 in 0..=1 {
            for byte in 0..=u8::MAX {
                assert!(
                    prefixes.iter().enumerate().any(|(index, &prefix)| {
                        let len = if index == adjusted {
                            buf60 + 3
                        } else {
                            lengths[index]
                        };
                        (byte ^ prefix) & (!(0xffu16 >> len) as u8) == 0
                    }),
                    "byte {byte:#04x}, Buf60={buf60}, adjusted prefix={adjusted}"
                );
            }
        }
    }
}

#[test]
fn old_distance_all_ones_length_does_not_toggle_buf60_for_other_codes() {
    // The historical decoder reserves length 257 only for code 10.
    // Current encoders avoid this symbol, but old/crafted streams can
    // carry it with the other old-distance codes (§6.13).
    for code in 11..=13 {
        let mut encoder = Unpack15Encoder::new();
        encoder.emit_short_lz_code(code);
        emit_decode_num(&mut encoder.bits, 0xff, 2, DEC_L1, POS_L1);
        let mut decoder = Unpack15::new();
        decoder.bits = BitReader::new(&encoder.bits.finish());
        decoder.target = 257;
        decoder.unp_ptr = 1;
        decoder.window[0] = b'a';
        decoder.old_dist[(0usize.wrapping_sub(code - 9)) & 3] = 1;
        let mut output = Vec::new();
        decoder.short_lz(&mut output).unwrap();
        assert_eq!(output, vec![b'a'; 257]);
        assert_eq!(decoder.buf60, 0);
    }
}

#[test]
fn zero_distance_after_window_wrap_retains_historical_zero_fill() {
    let mut decoder = Unpack15::new();
    decoder.first_win_done = true;
    decoder.target = 3;
    let mut output = Vec::new();
    decoder.copy_string(0, 3, &mut output).unwrap();
    assert_eq!(output, [0; 3]);
}

#[test]
fn decoder_reads_stmode_short_match_token() {
    for length in [3, 4] {
        let mut bits = BitWriter::new();
        emit_decode_num(&mut bits, 0, 5, DEC_HF1, POS_HF1);
        bits.write_bits(0, 1); // ST-mode match rather than exit.
        bits.write_bits(u32::from(length == 4), 1); // Three- or four-byte match.
        emit_decode_num(&mut bits, 0, 5, DEC_HF2, POS_HF2);
        bits.write_bits(1, 5); // Distance one.

        let mut decoder = Unpack15::new();
        decoder.bits = BitReader::new(&bits.finish());
        decoder.st_mode = true;
        decoder.target = 1 + length;
        decoder.output_written = 1;
        decoder.unp_ptr = 1;
        decoder.window[0] = b'A';
        let mut output = Vec::new();
        decoder.huff_decode(&mut output).unwrap();
        assert_eq!(output, vec![b'A'; length]);
        assert_eq!(decoder.token_stats.st_matches, 1);
    }
}
