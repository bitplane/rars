use rars::codec::rar50::*;
use rars::codec::{Error, Result};

fn checksum(flags: u8, size_bytes: &[u8]) -> u8 {
    size_bytes
        .iter()
        .fold(0x5a ^ flags, |acc, &byte| acc ^ byte)
}

#[test]
fn parses_one_byte_size_block_header() {
    let flags = 0xc7;
    let size = [3];
    let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb, 0xcc];

    let block = parse_compressed_block(&input).unwrap();
    assert_eq!(block.header_len, 3);
    assert_eq!(block.payload, 3..6);
    assert_eq!(block.header.flags, flags);
    assert!(block.header.is_last);
    assert!(block.header.has_tables);
    assert_eq!(block.header.final_byte_bits, 8);
    assert_eq!(block.header.payload_size, 3);
    assert_eq!(block.header.payload_bits, 24);
}

#[test]
fn parses_three_byte_size_block_header_with_partial_final_byte() {
    let flags = 0x94;
    let size = [0x34, 0x12, 0x00];
    let mut input = vec![flags, checksum(flags, &size), size[0], size[1], size[2]];
    input.resize(0x1234 + 5, 0);

    let block = parse_compressed_block(&input).unwrap();
    assert_eq!(block.header_len, 5);
    assert_eq!(block.payload, 5..0x1239);
    assert!(!block.header.is_last);
    assert!(block.header.has_tables);
    assert_eq!(block.header.final_byte_bits, 5);
    assert_eq!(block.header.payload_size, 0x1234);
    assert_eq!(block.header.payload_bits, (0x1234 - 1) * 8 + 5);
}

#[test]
fn rejects_reserved_size_length_selector() {
    let input = [0x18, 0x42, 0x00];

    assert_eq!(
        parse_compressed_block(&input),
        Err(Error::InvalidData("RAR 5 block size length is invalid"))
    );
}

#[test]
fn rejects_bad_block_header_checksum() {
    let input = [0xc7, 0x00, 0x03, 0xaa, 0xbb, 0xcc];

    assert_eq!(
        parse_compressed_block(&input),
        Err(Error::InvalidData("RAR 5 block header checksum mismatch"))
    );
}

#[test]
fn rejects_truncated_block_payload() {
    let flags = 0xc7;
    let size = [3];
    let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb];

    assert_eq!(parse_compressed_block(&input), Err(Error::NeedMoreInput));
}

#[test]
fn reads_level_lengths_with_literal_fifteen() {
    let mut nibbles = vec![1, 2, 15, 0, 3, 4];
    nibbles.resize(LEVEL_TABLE_SIZE + 1, 0);

    let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

    assert_eq!(&lengths[..6], &[1, 2, 15, 3, 4, 0]);
    assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4);
}

#[test]
fn reads_level_lengths_with_zero_run_at_current_position() {
    let mut nibbles = vec![7, 15, 3, 2];
    nibbles.resize(LEVEL_TABLE_SIZE - 3, 0);

    let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

    assert_eq!(lengths[0], 7);
    assert_eq!(&lengths[1..6], &[0, 0, 0, 0, 0]);
    assert_eq!(lengths[6], 2);
    assert_eq!(bits, (LEVEL_TABLE_SIZE - 3) * 4);
}

#[test]
fn level_zero_run_stops_at_level_table_boundary() {
    let mut nibbles = vec![0; LEVEL_TABLE_SIZE - 1];
    nibbles.extend([15, 15]); // a seventeen-entry zero run at the last slot
    let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();
    assert_eq!(lengths, [0; LEVEL_TABLE_SIZE]);
    assert_eq!(bits, (LEVEL_TABLE_SIZE + 1) * 4);
}

fn pack_nibbles(nibbles: &[u8]) -> Vec<u8> {
    nibbles
        .chunks(2)
        .map(|chunk| {
            let high = chunk[0] & 0x0f;
            let low = chunk.get(1).copied().unwrap_or(0) & 0x0f;
            (high << 4) | low
        })
        .collect()
}

#[test]
fn truncated_level_escape_needs_its_count_nibble() {
    // The low nibble is an escape; its following count nibble is absent.
    assert_eq!(read_level_lengths(&[0x0f]), Err(Error::NeedMoreInput));
}

#[test]
fn reads_rar70_table_length_count() {
    assert_eq!(
        table_length_count(1).unwrap(),
        MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
    );
}

#[test]
fn table_reader_rejects_unknown_algorithm_before_decoding() {
    let expected = Error::InvalidData("RAR 5 unknown compression algorithm version");
    assert_eq!(table_length_count(2).unwrap_err(), expected);
    assert_eq!(read_table_lengths(&[], 2).unwrap_err(), expected);
}

#[test]
fn encoded_table_lengths_round_trip_with_bit_count() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[b'B' as usize] = 3;
    lengths.main[262] = 3;
    lengths.distance[1] = 1;
    lengths.align[0] = 4;
    lengths.length[0] = 1;

    let (encoded, bit_count) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let (decoded, decoded_bits) = read_table_lengths(&encoded, 0).unwrap();

    assert_eq!(decoded, lengths);
    assert_eq!(decoded_bits, bit_count);
}

#[test]
fn table_encoder_validates_public_inputs() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[b'B' as usize] = 1;
    let encoded = encode_table_lengths(&lengths, 0).unwrap();
    assert_eq!(read_table_lengths(&encoded, 0).unwrap().0, lengths);

    assert_eq!(
        encode_table_lengths(&lengths, 2),
        Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version"
        ))
    );
    lengths.distance.pop();
    assert_eq!(
        encode_table_lengths(&lengths, 0),
        Err(Error::InvalidData("RAR 5 table length count mismatch"))
    );
    lengths.distance.push(0);
    lengths.main[0] = 16;
    assert_eq!(
        encode_table_lengths(&lengths, 0),
        Err(Error::InvalidData("RAR 5 Huffman length is too large"))
    );
}

#[test]
fn member_encoders_reject_unknown_algorithm_version() {
    let expected = Error::InvalidData("RAR 5 unknown compression algorithm version");
    assert_eq!(encode_literal_only(b"AB", 2).unwrap_err(), expected);
    assert_eq!(encode_lz_member(b"ABABABAB", 2).unwrap_err(), expected);
}

#[test]
fn encoded_compressed_block_round_trips_header_fields() {
    let payload = [0xaa, 0xbb, 0xc0];
    let block = encode_compressed_block(&payload, 18, true, true).unwrap();

    let parsed = parse_compressed_block(&block).unwrap();

    assert_eq!(parsed.payload, 3..6);
    assert!(parsed.header.has_tables);
    assert!(parsed.header.is_last);
    assert_eq!(parsed.header.final_byte_bits, 2);
    assert_eq!(parsed.header.payload_bits, 18);
    assert_eq!(&block[parsed.payload], payload);
}

#[test]
fn rejects_invalid_encoded_block_bit_counts() {
    assert_eq!(
        encode_compressed_block(&[0], 0, true, true),
        Err(Error::InvalidData("RAR 5 block has unused payload bytes"))
    );
    assert_eq!(
        encode_compressed_block(&[], 1, true, true),
        Err(Error::InvalidData("RAR 5 block bit count exceeds payload"))
    );
    let oversized = vec![0; 0x0100_0000];
    assert_eq!(
        encode_compressed_block(&oversized, oversized.len() * 8, false, true),
        Err(Error::InvalidData("RAR 5 block payload is too large"))
    );
}

#[test]
fn rejects_oversubscribed_rar50_huffman_tables() {
    assert!(matches!(
        HuffmanTable::from_lengths(&[1, 1, 1]),
        Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
    ));
    assert!(matches!(
        HuffmanTable::from_lengths(&[16]),
        Err(Error::InvalidData("RAR 5 Huffman length is too large"))
    ));
}

#[test]
fn detects_rar50_align_mode_when_align_lengths_are_not_uniform_four() {
    let mut align = vec![4; ALIGN_TABLE_SIZE];
    align[0] = 0;
    align[3] = 3;
    let lengths = TableLengths {
        main: vec![1, 1],
        distance: vec![1, 1],
        align,
        length: vec![1, 1],
    };

    let tables = DecodeTables::from_lengths(&lengths).unwrap();

    assert!(tables.align_mode);
}

#[test]
fn encodes_literal_only_member_that_decoder_reads() {
    let data = b"literal-only RAR5 codec stream\nwith repeated words words words";
    let input = encode_literal_only(data, 0).unwrap();

    let output = decode_literal_only(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
}

#[test]
fn encodes_literal_only_rar70_table_shape_that_decoder_reads() {
    let data = b"small RAR7-compatible literal block";
    let input = encode_literal_only(data, 1).unwrap();

    let output = decode_literal_only(&input, 1, data.len()).unwrap();

    assert_eq!(output, data);
}

#[test]
fn encodes_empty_literal_only_member() {
    let input = encode_literal_only(b"", 0).unwrap();

    let output = decode_literal_only(&input, 0, 0).unwrap();

    assert!(output.is_empty());
}

#[test]
fn lz_encoder_uses_frequency_weighted_huffman_lengths() {
    let mut data = vec![b'a'; 200];
    data.extend_from_slice(b"bcdefghijklmnopqrstuvwxyz");
    let input = encode_lz_member_with_options(&data, 0, EncodeOptions::new(0)).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert!(lengths.main[b'a' as usize] < lengths.main[b'z' as usize]);
}

fn code_is_complete(lengths: &[u8]) -> bool {
    let max_len = lengths.iter().copied().max().unwrap_or(0);
    if max_len == 0 {
        return true;
    }
    let sum: u64 = lengths
        .iter()
        .filter(|&&len| len != 0)
        .map(|&len| 1u64 << (max_len - len))
        .sum();
    sum == (1u64 << max_len)
}

#[test]
fn degenerate_inputs_emit_complete_huffman_tables() {
    // Highly repetitive data collapses the distance/length/align tables to a
    // single symbol. Those tables must still be transmitted as *complete*
    // prefix codes, or strict RAR 5 decoders (7-Zip / WinRAR, which build
    // with `Full_or_Empty`) reject the archive with a spurious data error.
    // See issue #19.
    let inputs: &[Vec<u8>] = &[
        vec![b'a'; 4000],
        b"ab".repeat(4000),
        (0u8..16).cycle().take(50_000).collect(),
        b"lorem ipsum dolor sit amet ".repeat(2000),
    ];
    for data in inputs {
        let input = encode_lz_member_with_options(data, 0, EncodeOptions::new(0)).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        assert!(code_is_complete(&lengths.main), "main table incomplete");
        assert!(
            code_is_complete(&lengths.distance),
            "distance table incomplete"
        );
        assert!(code_is_complete(&lengths.length), "length table incomplete");
        assert!(code_is_complete(&lengths.align), "align table incomplete");

        assert_eq!(&decode_lz(&input, 0, data.len()).unwrap(), data);
    }
}

fn encode_lz_member_with_filter(data: &[u8], kind: rars::FilterKind) -> Result<Vec<u8>> {
    Unpack50Encoder::new().encode_member_with_filter(data, 0, rars::FilterSpec::whole(kind))
}

#[test]
fn encodes_lz_member_with_delta_filter_record() {
    let data: Vec<u8> = (0..96).map(|index| (index * 7 + index / 3) as u8).collect();
    let input =
        encode_lz_member_with_filter(&data, rars::FilterKind::Delta { channels: 3 }).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn rejects_invalid_delta_filter_channel_count() {
    assert_eq!(
        encode_lz_member_with_filter(b"abc", rars::FilterKind::Delta { channels: 0 }),
        Err(Error::InvalidData(
            "RAR 5 DELTA filter channel count is invalid"
        ))
    );
    assert_eq!(
        encode_lz_member_with_filter(b"abc", rars::FilterKind::Delta { channels: 33 }),
        Err(Error::InvalidData(
            "RAR 5 DELTA filter channel count is invalid"
        ))
    );
}

#[test]
fn encodes_lz_member_with_e8_filter_record() {
    let mut data = b"\xe8\0\0\0\0plain text after call".to_vec();
    data.extend_from_slice(&[0xe8, 3, 0, 0, 0, b'X']);
    let input = encode_lz_member_with_filter(&data, rars::FilterKind::E8).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn short_e8_filter_range_round_trips_without_rewriting_bytes() {
    let data = [0xe8, 0, 0, 0];
    let packed = encode_lz_member_with_filter(&data, rars::FilterKind::E8).unwrap();
    assert_eq!(decode_lz(&packed, 0, data.len()).unwrap(), data);
}

#[test]
fn encodes_lz_member_with_e8e9_filter_record() {
    let data = b"\xe9\0\0\0\0jump target through e9".to_vec();
    let input = encode_lz_member_with_filter(&data, rars::FilterKind::E8E9).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn encodes_lz_member_with_ranged_e8e9_filter_record() {
    let mut data = b"\xe8\0\0\0\0plain prefix outside filter range".to_vec();
    let range_start = data.len();
    for _ in 0..16 {
        let operand_pos = data.len() + 1;
        data.push(0xe8);
        let relative = 0x7000u32.wrapping_sub(operand_pos as u32);
        data.extend_from_slice(&relative.to_le_bytes());
        data.extend_from_slice(b" code ");
    }
    let range = range_start..data.len();
    data.extend_from_slice(b"\xe9\0\0\0\0plain suffix outside filter range");

    let input = Unpack50Encoder::new()
        .encode_member_with_filter(
            &data,
            0,
            rars::FilterSpec::range(rars::FilterKind::E8E9, range),
        )
        .unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn encodes_lz_member_with_arm_filter_record() {
    let data = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
    let input = encode_lz_member_with_filter(&data, rars::FilterKind::Arm).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn solid_encoder_emits_rar50_matches_against_previous_member_history() {
    let first = b"RAR5 solid shared phrase alpha beta gamma\n".repeat(16);
    let second = b"RAR5 solid shared phrase alpha beta gamma\nsecond\n".repeat(4);
    let solid = encode_lz_member_with_history(&second, &first, 0).unwrap();
    let standalone = encode_lz_member(&second, 0).unwrap();
    let mut decoder = Unpack50Decoder::new();

    assert_eq!(
        decoder
            .decode_member(
                &encode_lz_member(&first, 0).unwrap(),
                0,
                first.len(),
                false,
                DecodeMode::Lz
            )
            .unwrap(),
        first
    );
    assert_eq!(
        decoder
            .decode_member(&solid, 0, second.len(), true, DecodeMode::Lz)
            .unwrap(),
        second
    );
    assert!(solid.len() < standalone.len());
}

#[test]
fn public_decoder_clone_keeps_independent_solid_history_and_tables() {
    let first = b"RAR5 independent decoder history ".repeat(32);
    let second = b"RAR5 independent decoder history ".repeat(8);
    let packed_first = encode_lz_member(&first, 0).unwrap();
    let packed_second = encode_lz_member_with_history(&second, &first, 0).unwrap();
    let mut original = Unpack50Decoder::new();
    assert_eq!(
        original
            .decode_member(&packed_first, 0, first.len(), false, DecodeMode::Lz)
            .unwrap(),
        first
    );
    let mut copied = original.clone();
    let other = b"a different non-solid member";
    assert_eq!(
        original
            .decode_member(
                &encode_lz_member(other, 0).unwrap(),
                0,
                other.len(),
                false,
                DecodeMode::Lz
            )
            .unwrap(),
        other
    );
    drop(original);
    assert_eq!(
        copied
            .decode_member(&packed_second, 0, second.len(), true, DecodeMode::Lz)
            .unwrap(),
        second
    );
}

/// Words drawn from a small vocabulary in a repeating-but-not-periodic
/// order. Every position has several matches at different distances and
/// lengths, which is the case where taking the longest one and checking
/// two bytes ahead leaves bits on the floor.
fn wordy_text(len: usize) -> Vec<u8> {
    const WORDS: [&str; 12] = [
        "the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog ", "and ", "then ",
        "runs ", "away ",
    ];
    let mut out = Vec::with_capacity(len + 16);
    let mut noise = 0x2545_f491_4f6c_dd1du64;
    while out.len() < len {
        noise ^= noise << 13;
        noise ^= noise >> 7;
        noise ^= noise << 17;
        out.extend_from_slice(WORDS[(noise >> 40) as usize % WORDS.len()].as_bytes());
        if (noise >> 20).is_multiple_of(11) {
            out.push(b'\n');
        }
    }
    out.truncate(len);
    out
}

#[test]
fn the_optimal_parse_beats_lazy_matching_at_the_same_depth() {
    let data = wordy_text(256 * 1024);
    let base = EncodeOptions::new(64);
    let lazy = encode_lz_member_with_options(
        &data,
        0,
        base.with_lazy_matching(true).with_lazy_lookahead(2),
    )
    .unwrap();
    let optimal = encode_lz_member_with_options(&data, 0, base.with_optimal_parse(true)).unwrap();

    assert!(
        optimal.len() < lazy.len(),
        "optimal parse packed {} against lazy matching's {}",
        optimal.len(),
        lazy.len(),
    );
}

/// One chunk, copied once per round with fresh literals in between, so
/// every match after the first sits at the same distance and every one of
/// them is separated from the last by literals.
fn strided_repeats(gap: usize, rounds: usize) -> Vec<u8> {
    let mut noise = 0x1234_5678u32;
    let mut byte = move || {
        noise = noise.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (noise >> 24) as u8
    };
    let chunk: Vec<u8> = (0..48).map(|_| byte()).collect();
    let mut data = chunk.clone();
    for _ in 0..rounds {
        data.extend((0..gap).map(|_| byte()));
        data.extend_from_slice(&chunk);
    }
    data
}

#[test]
fn reusing_a_remembered_distance_packs_strided_data_smaller() {
    let data = strided_repeats(8, 3000);
    let options = EncodeOptions::new(64).with_optimal_parse(true);
    let packed = encode_lz_member_with_options(&data, 0, options).unwrap();

    // 26,178 bytes when the path carries its remembered distances, 28,447
    // when it does not. The bound sits between the two.
    assert!(
        packed.len() < 27_000,
        "{} bytes packed from {}",
        packed.len(),
        data.len(),
    );
    let decoded = decode_lz(&packed, 0, data.len()).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn encodes_lz_member_with_last_length_repeat_symbols() {
    let data = b"abcdXabcdYabcdZabcd";
    let input = encode_lz_member(data, 0).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[257], 0);
}

#[test]
fn encodes_lz_member_using_rar70_distance_table_shape() {
    let data = b"RAR7-compatible repeated phrase repeated phrase repeated phrase";
    let input = encode_lz_member(data, 1).unwrap();

    let output = decode_lz(&input, 1, data.len()).unwrap();

    assert_eq!(output, data);
}

#[test]
fn rejects_literal_only_block_without_tables() {
    let input = encode_compressed_block(&[0], 8, false, true).unwrap();

    assert_eq!(
        decode_literal_only(&input, 0, 1),
        Err(Error::InvalidData("RAR 5 block reuses missing tables"))
    );
}

#[test]
fn rejects_out_of_range_length_slots_and_extras() {
    assert!(slot_to_length(103, (1 << 24) - 1).is_ok());
    assert_eq!(
        slot_to_length(8, 2),
        Err(Error::InvalidData("RAR 5 length extra bits exceed slot"))
    );
    assert_eq!(
        slot_to_length(104, 0),
        Err(Error::InvalidData("RAR 5 length slot is too large"))
    );
}

#[test]
fn decodes_distance_slots() {
    assert_eq!(slot_to_distance(0, 0).unwrap(), 1);
    assert_eq!(slot_to_distance(3, 0).unwrap(), 4);
    assert_eq!(distance_slot_bit_count(4).unwrap(), 1);
    assert_eq!(slot_to_distance(4, 0).unwrap(), 5);
    assert_eq!(slot_to_distance(4, 1).unwrap(), 6);
    assert_eq!(distance_slot_bit_count(10).unwrap(), 4);
    assert_eq!(slot_to_distance(10, 15).unwrap(), 48);
}

#[test]
fn distance_slots_beyond_native_address_width_use_out_of_window_sentinel() {
    for (slot, extra, distance) in [
        (63, (1u64 << 30) - 1, 1u64 << 32),
        (65, (1u64 << 31) - 1, 1u64 << 33),
    ] {
        assert_eq!(
            slot_to_distance(slot, extra).unwrap(),
            usize::try_from(distance).unwrap_or(usize::MAX)
        );
    }
}

#[test]
fn distance_slots_reach_the_end_of_the_rar7_alphabet_and_no_further() {
    for (slot, extra, distance) in [
        (66, 0, 0x2_0000_0001u64),
        (67, 0xffff_ffff, 0x4_0000_0000),
        (79, 0x3f_ffff_ffff, 0x100_0000_0000),
    ] {
        let expected = usize::try_from(distance).unwrap_or(usize::MAX);
        assert_eq!(slot_to_distance(slot, extra), Ok(expected));
    }
    assert_eq!(
        slot_to_distance(4, 2),
        Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"))
    );
    assert_eq!(
        slot_to_distance(79, 1 << 38),
        Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"))
    );
    assert_eq!(
        slot_to_distance(DISTANCE_TABLE_SIZE_70, 0),
        Err(Error::InvalidData("RAR 5 distance slot is too large"))
    );
}

#[test]
fn parser_handles_largest_declared_block_size_without_overflow() {
    let flags = 0b10 << 3; // three size bytes
    let checksum = 0x5a ^ flags ^ 0xff ^ 0xff ^ 0xff;
    let header = [flags, checksum, 0xff, 0xff, 0xff];
    assert_eq!(parse_compressed_block(&header), Err(Error::NeedMoreInput));
}

#[test]
fn parser_rejects_truncated_block_header_and_payload() {
    // A two-byte size field requires a fourth header byte.
    assert_eq!(
        parse_compressed_block(&[1 << 3, 0, 0]),
        Err(Error::NeedMoreInput)
    );
    let block = encode_compressed_block(&[0xaa, 0xbb], 16, false, true).unwrap();
    for length in 0..block.len() {
        assert_eq!(
            parse_compressed_block(&block[..length]),
            Err(Error::NeedMoreInput),
            "truncated at byte {length}"
        );
    }
    assert_eq!(
        parse_compressed_block(&block).unwrap().payload,
        3..block.len()
    );
}

#[test]
fn streaming_decoder_rejects_missing_tables_and_invalid_dictionary() {
    let input = encode_compressed_block(&[0], 8, false, true).unwrap();
    assert_eq!(
        Unpack50Decoder::new().decode_member_with_dictionary(
            &input,
            0,
            1,
            0,
            false,
            DecodeMode::LiteralOnly,
        ),
        Err(Error::InvalidData("RAR 5 dictionary size is zero"))
    );
    let decode = |dictionary_size| {
        Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            1,
            dictionary_size,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        )
    };
    assert!(matches!(
        decode(1),
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 block reuses missing tables"
        )))
    ));
    assert!(matches!(
        decode(0),
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 dictionary size is zero"
        )))
    ));
}
