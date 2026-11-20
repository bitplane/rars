use rars::codec::rar29::*;
use rars::codec::{Error, Result};
use std::ops::Range;

/// The reader carries its table across the members of a solid chain, so
/// members that look alike stop paying to describe the same table again.
#[test]
fn a_solid_chain_stops_repaying_for_the_same_table() {
    let mut member = Vec::new();
    for index in 0..400u32 {
        member.extend_from_slice(format!("field_{index:04} = value {index:04}\n").as_bytes());
    }

    let mut chained = Unpack29Encoder::with_options(EncodeOptions::default());
    let first = chained.encode_member(&member).unwrap();
    let second = chained.encode_member(&member).unwrap();

    let mut alone = Unpack29Encoder::with_options(EncodeOptions::default());
    alone.encode_member(&member).unwrap();
    let restated = Unpack29Encoder::with_options(EncodeOptions::default())
        .encode_member(&member)
        .unwrap();

    assert_eq!(first.len(), restated.len());
    assert!(
        second.len() < restated.len(),
        "the second member of the chain cost {} bytes against {} on its own",
        second.len(),
        restated.len()
    );
}

const COMPRESSED_TEXT: &[u8] = &[
    0x09, 0x10, 0x10, 0x93, 0xe4, 0xce, 0x7f, 0xa2, 0xba, 0x80, 0x46, 0x16, 0x82, 0x63, 0xe9, 0x9a,
    0x19, 0xe4, 0x10, 0xe0, 0x41, 0x3d, 0x16, 0xfc, 0x4d, 0xfa, 0x6f, 0xf2, 0x5c, 0xae, 0x32, 0x86,
    0xc9, 0x95, 0x9d, 0xf1, 0x04, 0xa4, 0xe8, 0x92, 0x8f, 0x12, 0xd7, 0xe7, 0xba, 0xcb, 0x26, 0xf1,
    0x97, 0xac, 0x7c, 0x5f, 0xfd, 0xa0, 0x00, 0x1f, 0x77, 0x50,
];

#[test]
fn decodes_rar29_lz_member() {
    assert_eq!(
        unpack29_decode(COMPRESSED_TEXT, 2400).unwrap(),
        expected_text()
    );
}

#[test]
fn literal_encoder_round_trips_rar29_lz_blocks() {
    let input = b"literal-only RAR 2.9 baseline\nwith repeated text literal-only\n";
    let packed = unpack29_encode_literals(input).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn an_lz_member_ends_with_a_new_file_marker() {
    let input = b"RAR 2.9 terminator check, with repeated text to force a match: \
RAR 2.9 terminator check\n";
    let packed = unpack29_encode_literals(input).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn rejects_a_final_lz_marker_that_promises_a_missing_table() {
    let input = b"RAR 2.9 missing final table check\n".repeat(8);
    let mut packed = unpack29_encode_literals(&input).unwrap();
    let last_nonzero = packed.iter().rposition(|&byte| byte != 0).unwrap();
    let final_one = 1 << packed[last_nonzero].trailing_zeros();
    let preceding_bit = final_one << 1;
    assert_eq!(packed[last_nonzero] & preceding_bit, 0);
    packed[last_nonzero] ^= final_one | preceding_bit;

    assert!(matches!(
        unpack29_decode(&packed, input.len()),
        Err(Error::InvalidData("RAR 2.9 bitstream is truncated"))
    ));
}

#[test]
fn rejects_an_lz_literal_after_the_declared_member_size() {
    let input = b"literal-only RAR 2.9 member";
    let packed = unpack29_encode_literals(input).unwrap();

    assert!(matches!(
        unpack29_decode(&packed, input.len() - 1),
        Err(Error::InvalidData("RAR 2.9 LZ member has trailing data"))
    ));
}

#[test]
fn public_encoders_handle_zero_match_distance_and_one_byte_blocks() {
    let input = b"small RAR29 blocks";
    let options = EncodeOptions::default()
        .with_max_match_distance(0)
        .with_block_size(1);
    let packed = Unpack29Encoder::with_options(options)
        .encode_member(input)
        .unwrap();
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);

    let packed = Unpack29Encoder::with_options(options)
        .encode_member_with_filter(input, rars::FilterSpec::whole(rars::FilterKind::E8))
        .unwrap();
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn solid_member_rejects_declared_output_beyond_native_range() {
    let mut decoder = rars::codec::rar29::Unpack29::new();
    decoder
        .decode_non_solid_member(COMPRESSED_TEXT, 2400)
        .unwrap();
    assert_eq!(
        decoder.decode_member(&[], usize::MAX),
        Err(Error::InvalidData("RAR 2.9 output size overflows"))
    );
}

#[test]
fn ppmd_literal_encoder_round_trips_rar29_ppmd_blocks() {
    let mut input = b"rar29 ppmd literal text payload alpha beta gamma\n".repeat(64);
    input.extend_from_slice(&[2, 2, 2, b'e', b's', b'c']);
    let packed = unpack29_encode_ppmd_literals(&input).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    assert_ne!(packed.first().copied(), Some(0));
}

#[test]
fn rejects_ppmd_eof_before_the_declared_member_size() {
    let input = b"PPMd member with an inflated declared size";
    let packed = unpack29_encode_ppmd_literals(input).unwrap();

    assert!(matches!(
        unpack29_decode(&packed, input.len() + 1),
        Err(Error::InvalidData(
            "RAR 2.9 member ended before its declared size"
        ))
    ));
}

#[test]
fn rejects_ppmd_output_after_the_declared_member_size() {
    let input = b"PPMd member with a shortened declared size";
    let packed = unpack29_encode_ppmd_literals(input).unwrap();

    assert!(matches!(
        unpack29_decode(&packed, input.len() - 1),
        Err(Error::InvalidData("RAR 2.9 PPMd member has trailing data"))
    ));
}

#[test]
fn rejects_a_truncated_ppmd_end_marker() {
    let input = b"PPMd member whose final range-coder byte is missing";
    let mut packed = unpack29_encode_ppmd_literals(input).unwrap();
    packed.pop();

    assert!(matches!(
        unpack29_decode(&packed, input.len()),
        Err(Error::InvalidData("RAR 2.9 bitstream is truncated"))
    ));
}

#[test]
fn same_block_filters_chain_in_wire_order() {
    let mut input = Vec::new();
    for index in 0..256u32 {
        input.push(0xe8);
        input.extend_from_slice(&index.wrapping_mul(97).to_le_bytes());
        input.extend_from_slice(b"chained-filter-payload");
    }
    let filters = [
        rars::FilterSpec::whole(rars::FilterKind::Delta { channels: 1 }),
        rars::FilterSpec::whole(rars::FilterKind::E8),
    ];
    let packed = Unpack29Encoder::new()
        .encode_member_with_filters(&input, &filters)
        .unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn writer_rejects_partially_overlapping_filters() {
    let input = vec![b'Z'; 96];
    for second_range in [32..96, 0..63] {
        let filters = [
            rars::FilterSpec::range(rars::FilterKind::Delta { channels: 1 }, 0..64),
            rars::FilterSpec::range(rars::FilterKind::E8, second_range),
        ];

        assert_eq!(
            Unpack29Encoder::new()
                .encode_member_with_filters(&input, &filters)
                .unwrap_err(),
            Error::InvalidData("RAR 2.9 VM filters partially overlap")
        );
    }
}

#[test]
fn filtered_entry_point_accepts_empty_input_without_filters() {
    let packed = Unpack29Encoder::new()
        .encode_member_with_filters(b"", &[])
        .unwrap();

    assert!(unpack29_decode(&packed, 0).unwrap().is_empty());
}

fn encode_with_filter(input: &[u8], kind: rars::FilterKind) -> Result<Vec<u8>> {
    Unpack29Encoder::new().encode_member_with_filter(input, rars::FilterSpec::whole(kind))
}

fn encode_with_filter_range(
    input: &[u8],
    kind: rars::FilterKind,
    range: Range<usize>,
) -> Result<Vec<u8>> {
    Unpack29Encoder::new().encode_member_with_filter(input, rars::FilterSpec::range(kind, range))
}

fn encode_with_filter_ranges(
    input: &[u8],
    kind: rars::FilterKind,
    ranges: Vec<Range<usize>>,
) -> Result<Vec<u8>> {
    let filters: Vec<_> = ranges
        .into_iter()
        .map(|range| rars::FilterSpec::range(kind, range))
        .collect();
    Unpack29Encoder::new().encode_member_with_filters(input, &filters)
}

#[test]
fn encoder_emits_rar29_offset_one_matches_for_repeated_bytes() {
    let input = b"Z".repeat(1024);
    let packed = unpack29_encode_literals(&input).unwrap();

    assert!(packed.len() < input.len() / 4);
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar29_dictionary_matches_for_repeated_sequences() {
    let input = b"abc123xyz-".repeat(128);
    let packed = unpack29_encode_literals(&input).unwrap();

    assert!(packed.len() < input.len() / 2);
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar29_e8_vm_filter_record() {
    let input = b"\xe8\0\0\0\0rar29 e8 filter writer payload\n".repeat(8);
    let packed = encode_with_filter(&input, rars::FilterKind::E8).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert!(
        decoded == input,
        "RAR 2.9 multi-filter E8 round-trip failed"
    );
}

#[test]
fn encoder_emits_rar29_e8e9_vm_filter_record() {
    let input = b"\xe9\0\0\0\0rar29 e8e9 filter writer payload\n".repeat(8);
    let packed = encode_with_filter(&input, rars::FilterKind::E8E9).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_e8_vm_filter_record() {
    let mut input = b"prefix data that should not be x86 filtered ".to_vec();
    let start = input.len();
    input.extend_from_slice(b"\xe8\0\0\0\0segmented e8 filtered payload\n");
    let end = input.len();
    input.extend_from_slice(b" suffix data that should also remain raw");
    let packed = encode_with_filter_range(&input, rars::FilterKind::E8, start..end).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_multiple_e8_vm_filter_records() {
    let mut input = vec![0x41u8; 80_000];
    for cluster_start in [8_000, 60_000] {
        for index in 0..8 {
            let pos = cluster_start + index * 64;
            input[pos] = 0xe8;
            input[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
        }
    }

    let packed = encode_with_filter_ranges(
        &input,
        rars::FilterKind::E8,
        vec![8_000..8_512, 60_000..60_512],
    )
    .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_e8e9_vm_filter_record() {
    let mut input = b"prefix data that should not be x86 filtered ".to_vec();
    let start = input.len();
    input.extend_from_slice(b"\xe9\0\0\0\0segmented e8e9 filtered payload\n");
    let end = input.len();
    input.extend_from_slice(b" suffix data that should also remain raw");
    let packed = encode_with_filter_range(&input, rars::FilterKind::E8E9, start..end).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_delta_vm_filter_record() {
    let input: Vec<u8> = (0..192).map(|index| (index * 13 + 7) as u8).collect();
    let packed = encode_with_filter(&input, rars::FilterKind::Delta { channels: 3 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_delta_vm_filter_record() {
    let mut input = b"prefix bytes before delta segment ".to_vec();
    let start = input.len();
    input.extend((0..192).map(|index| (index * 13 + 7) as u8));
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after delta segment");
    let packed =
        encode_with_filter_range(&input, rars::FilterKind::Delta { channels: 3 }, start..end)
            .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_itanium_vm_filter_record() {
    let mut input = vec![0u8; 48];
    input[16] = 22;
    input[21] = 20;
    input.extend_from_slice(b"rar29 itanium filter writer payload\n");
    let packed = encode_with_filter(&input, rars::FilterKind::Itanium).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_itanium_vm_filter_record() {
    let mut input = b"prefix bytes before itanium segment ".to_vec();
    let start = input.len();
    input.extend_from_slice(&[0; 48]);
    input[start + 16] = 22;
    input[start + 21] = 20;
    input.extend_from_slice(b"rar29 segmented itanium filter writer payload\n");
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after itanium segment");
    let packed = encode_with_filter_range(&input, rars::FilterKind::Itanium, start..end).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_rgb_vm_filter_record() {
    let width = 12;
    let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
    let packed = encode_with_filter(&input, rars::FilterKind::Rgb { width, pos_r: 0 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_rgb_filter_with_nonzero_red_position() {
    let width = 12;
    let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
    let packed = encode_with_filter(&input, rars::FilterKind::Rgb { width, pos_r: 2 }).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar29_segmented_rgb_vm_filter_record() {
    let width = 12;
    let mut input = b"prefix bytes before rgb segment ".to_vec();
    let start = input.len();
    input.extend((0..96).map(|index| (index * 29 + 11) as u8));
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after rgb segment");
    let packed = encode_with_filter_range(
        &input,
        rars::FilterKind::Rgb { width, pos_r: 0 },
        start..end,
    )
    .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_rejects_rar29_rgb_filter_with_unaligned_scanline_width() {
    let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
    assert!(encode_with_filter(&input, rars::FilterKind::Rgb { width: 8, pos_r: 0 }).is_err());
}

#[test]
fn encoder_rejects_rgb_ranges_shorter_than_a_pixel_or_scanline() {
    for (input, width) in [(b"ab".as_slice(), 3), (b"abc".as_slice(), 6)] {
        assert_eq!(
            Unpack29Encoder::new().encode_member_with_filter(
                input,
                rars::FilterSpec::whole(rars::FilterKind::Rgb { width, pos_r: 0 }),
            ),
            Err(Error::InvalidData(
                "RAR 2.9 RGB filter parameters are invalid"
            )),
        );
    }
}

#[test]
fn encoder_emits_rar29_audio_vm_filter_record() {
    let input: Vec<u8> = (0..160)
        .map(|index| (index * 7 + index / 3) as u8)
        .collect();
    let packed = encode_with_filter(&input, rars::FilterKind::Audio { channels: 2 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_audio_vm_filter_record() {
    let mut input = b"prefix bytes before audio segment ".to_vec();
    let start = input.len();
    input.extend((0..160).map(|index| (index * 7 + index / 3) as u8));
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after audio segment");
    let packed =
        encode_with_filter_range(&input, rars::FilterKind::Audio { channels: 2 }, start..end)
            .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn short_itanium_filter_encoding_is_a_defined_noop() {
    for len in 4..=21 {
        let input: Vec<u8> = (0..len).map(|index| (index * 17 + 3) as u8).collect();
        let packed = encode_with_filter(&input, rars::FilterKind::Itanium).unwrap();
        assert_eq!(
            unpack29_decode(&packed, input.len()).unwrap(),
            input,
            "changed a {len}-byte block"
        );
    }
}

fn expected_text() -> Vec<u8> {
    "Hello, RAR 3.x fixture world.\n".repeat(80).into_bytes()
}

fn mixed_member(len: usize) -> Vec<u8> {
    let words = [
        &b"alpha "[..],
        b"bravo ",
        b"charlie ",
        b"delta ",
        b"echo\n",
        b"foxtrot ",
    ];
    let mut state = 0x2545_f491_u32;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        if state.is_multiple_of(7) {
            out.extend_from_slice(&state.to_le_bytes());
        } else {
            out.extend_from_slice(words[state as usize % words.len()]);
        }
    }
    out.truncate(len);
    out
}

fn packed_fingerprint(packed: &[u8]) -> (usize, u32) {
    (packed.len(), rars::crc32::crc32(packed))
}

#[test]
fn block_parsed_members_code_to_the_serial_parse_bytes() {
    let input = mixed_member(600 * 1024);
    let options = EncodeOptions::new(64)
        .with_lazy_matching(true)
        .with_max_match_distance(256 * 1024)
        .with_block_size(4096);

    let plain = Unpack29Encoder::with_options(options)
        .encode_member(&input)
        .unwrap();
    assert_eq!(
        rars::codec::rar29::unpack29_decode(&plain, input.len()).unwrap(),
        input
    );

    let mut chain = Unpack29Encoder::with_options(options);
    chain.encode_member(&input[..300 * 1024]).unwrap();
    let continued = chain.encode_member(&input[300 * 1024..]).unwrap();

    let filtered = Unpack29Encoder::with_options(options)
        .encode_member_with_filter(
            &input,
            rars::FilterSpec::whole(rars::FilterKind::Delta { channels: 2 }),
        )
        .unwrap();
    assert_eq!(
        rars::codec::rar29::unpack29_decode(&filtered, input.len()).unwrap(),
        input
    );

    let ppmd = rars::codec::rar29::unpack29_encode_ppmd(&input, 256 * 1024).unwrap();
    assert_eq!(
        rars::codec::rar29::unpack29_decode(&ppmd, input.len()).unwrap(),
        input
    );

    // Captured from the serial parse, one block after another on one finder.
    assert_eq!(packed_fingerprint(&plain), (148_381, 3_735_200_713));
    assert_eq!(packed_fingerprint(&continued), (74_257, 1_312_368_026));
    assert_eq!(packed_fingerprint(&filtered), (239_799, 1_353_944_033));
    // The PPMd search keys on whole matches now; it must not lose to the
    // four-byte key it replaced, which packed this member to 109,636 bytes.
    assert!(ppmd.len() <= 109_636, "{}", ppmd.len());
}
