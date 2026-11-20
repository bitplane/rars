use rars::codec::rar20::*;

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
fn auto_encoder_uses_audio_when_it_beats_lz() {
    let input = interleaved_pcm_like_payload();
    let lz = unpack20_encode_literals(&input).unwrap();
    let auto = rars::codec::rar20::unpack20_encode_auto(&input).unwrap();
    let decoded = unpack20_decode(&auto, input.len()).unwrap();

    assert!(auto.len() < lz.len());
    assert_eq!(decoded, input);
}

#[test]
fn default_encode_options_match_legacy_entry_points() {
    let input = b"rar20 option plumbing preserves default output ".repeat(128);
    assert_eq!(
        unpack20_encode_literals(&input).unwrap(),
        rars::codec::rar20::unpack20_encode_literals_with_options(&input, EncodeOptions::default())
            .unwrap()
    );
    assert_eq!(
        rars::codec::rar20::unpack20_encode_auto(&input).unwrap(),
        rars::codec::rar20::unpack20_encode_auto_with_options(&input, EncodeOptions::default())
            .unwrap()
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

fn windowed_payload(len: usize) -> Vec<u8> {
    let sources: [&[u8]; 3] = [
        include_bytes!("../fixtures/rar15_40/ppmd/binary_64k.bin"),
        include_bytes!("../fixtures/rar15_40/ppmd/escape_64k.bin"),
        include_bytes!("../fixtures/rar15_40/ppmd/lorem_127k.txt"),
    ];
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::with_capacity(len);
    let mut round = 0usize;
    while out.len() < len {
        let source = sources[round % sources.len()];
        let offset = (next() % (source.len() - 4096) as u64) as usize;
        out.extend_from_slice(&source[offset..offset + 4096]);
        out.extend((0..1024).map(|_| next() as u8));
        round += 1;
    }
    out.truncate(len);
    out
}

#[test]
fn priced_parses_code_to_the_unpruned_search_bytes() {
    let windowed = windowed_payload(64 * 1024);
    let text = &include_bytes!("../fixtures/rar15_40/ppmd/lorem_127k.txt")[..32 * 1024];
    let level = |candidates, optimal| {
        EncodeOptions::new(candidates)
            .with_lazy_matching(true)
            .with_lazy_lookahead(2)
            .with_optimal_parse(optimal)
            .with_try_audio(false)
    };
    let cases = [
        (&windowed[..], level(1024, true)),
        (text, level(1024, true)),
        (&windowed[..], level(256, false)),
        (text, level(256, false)),
    ];
    let fingerprints: Vec<_> = cases
        .iter()
        .map(|&(input, options)| {
            let packed =
                rars::codec::rar20::unpack20_encode_literals_with_options(input, options).unwrap();
            assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
            (packed.len(), rars::crc32::crc32(&packed))
        })
        .collect();

    // Captured from the encoder that priced every candidate in full, then again
    // once the pre-table was weighted and absent symbols priced (all smaller).
    assert_eq!(
        fingerprints,
        [
            (32_358, 1_534_072_347),
            (5_515, 1_502_738_075),
            (32_572, 3_375_507_439),
            (5_945, 2_977_992_424),
        ]
    );
}

#[test]
fn shortest_path_levels_code_to_known_bytes() {
    let text = include_bytes!("../fixtures/rar15_40/ppmd/lorem_127k.txt");
    let windowed = windowed_payload(192 * 1024);
    let mut fingerprints = Vec::new();
    for extra in [0, 2] {
        let options = EncodeOptions::new(512)
            .with_lazy_matching(true)
            .with_lazy_lookahead(2)
            .with_optimal_parse(true)
            .with_extra_priced_passes(extra)
            .with_try_audio(false);
        for input in [&text[..], &windowed[..]] {
            let packed =
                rars::codec::rar20::unpack20_encode_literals_with_options(input, options).unwrap();
            assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
            fingerprints.push((packed.len(), rars::crc32::crc32(&packed)));
        }
    }

    // Levels 4 and 5 as the writer sets them, text then windowed. Captured
    // from master f223f8e0, then moved once the greedy seed read the match
    // lists instead of searching, which gives the first priced pass new tables.
    assert_eq!(
        fingerprints,
        [
            (20_087, 2_779_185_340),
            (88_635, 3_316_369_193),
            (20_040, 4_210_419_601),
            (88_626, 59_302_239),
        ]
    );
}
