use super::*;

fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state >> 8
}

/// Code-shaped bytes: short opcodes, small immediates and a call table that
/// repeats at a spread of distances, so matches of every length compete.
fn binary_like(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        match lcg(&mut state) % 6 {
            0 if out.len() > 64 => {
                let back = 1 + (lcg(&mut state) as usize % out.len().min(40_000));
                let take = 3 + lcg(&mut state) as usize % 40;
                let from = out.len() - back;
                for index in 0..take {
                    out.push(out[from + index]);
                }
            }
            1 => out.extend_from_slice(&[0x48, 0x8b, (lcg(&mut state) & 0xff) as u8]),
            2 => out.extend_from_slice(&[0xe8, 0, 0, (lcg(&mut state) & 0x0f) as u8]),
            3 => out.extend_from_slice(&[0, 0, 0, 0]),
            _ => out.push((lcg(&mut state) & 0xff) as u8),
        }
    }
    out.truncate(len);
    out
}

fn words(len: usize, seed: u32) -> Vec<u8> {
    let vocabulary: [&[u8]; 10] = [
        b"the ",
        b"parse ",
        b"prices ",
        b"each ",
        b"match ",
        b"against ",
        b"tables ",
        b"of ",
        b"block ",
        b"route\n",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(vocabulary[lcg(&mut state) as usize % vocabulary.len()]);
    }
    out.truncate(len);
    out
}

/// Runs of zeroes between a phrase repeating at an offset no block aligns to.
fn runs_and_a_phrase(len: usize) -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    for _ in 0..91 {
        block.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
    }
    block.iter().copied().cycle().take(len).collect()
}

fn lazy() -> EncodeOptions {
    EncodeOptions::new(64)
        .with_lazy_matching(true)
        .with_block_size(64 * 1024)
        .with_max_match_distance(1 << 20)
}

#[test]
fn the_shortest_path_round_trips_and_never_codes_larger_than_the_lazy_parse() {
    let samples = [
        ("binary", binary_like(150_000, 7)),
        ("text", words(150_000, 11)),
        ("runs", runs_and_a_phrase(150_000)),
        ("tiny", b"abcabcabcabd".to_vec()),
    ];
    for (name, data) in samples {
        let plain = unpack29_encode_literals_with_options(&data, lazy()).unwrap();
        let parsed =
            unpack29_encode_literals_with_options(&data, lazy().with_optimal_parse_passes(2))
                .unwrap();
        assert_eq!(
            unpack29_decode(&parsed, data.len()).unwrap(),
            data,
            "{name} did not round trip"
        );
        assert!(
            parsed.len() <= plain.len(),
            "{name}: shortest path {} bytes, lazy {}",
            parsed.len(),
            plain.len()
        );
    }
}

#[test]
fn the_shortest_path_wins_on_code_shaped_bytes() {
    let data = binary_like(200_000, 3);
    let plain = unpack29_encode_literals_with_options(&data, lazy()).unwrap();
    let parsed =
        unpack29_encode_literals_with_options(&data, lazy().with_optimal_parse_passes(2)).unwrap();
    assert!(
        parsed.len() * 100 < plain.len() * 99,
        "shortest path {} bytes, lazy {}",
        parsed.len(),
        plain.len()
    );
}

/// A block wider than one parse is priced keeps its lazy tokens rather than
/// holding a node per byte of it.
#[test]
fn a_block_wider_than_one_parse_keeps_the_lazy_parse() {
    let data = binary_like(OPTIMAL_SPAN + 4096, 5);
    let unblocked = EncodeOptions::new(64)
        .with_lazy_matching(true)
        .with_max_match_distance(1 << 20);
    let plain = unpack29_encode_literals_with_options(&data, unblocked).unwrap();
    let parsed =
        unpack29_encode_literals_with_options(&data, unblocked.with_optimal_parse_passes(2))
            .unwrap();
    assert_eq!(parsed, plain);
}

#[test]
fn a_solid_chain_parsed_by_shortest_path_round_trips() {
    let first = words(90_000, 1);
    let second = binary_like(90_000, 2);
    let mut encoder = Unpack29Encoder::with_options(lazy().with_optimal_parse_passes(2));
    let mut decoder = Unpack29::new();
    for member in [&first, &second, &first] {
        let packed = encoder.encode_member(member).unwrap();
        assert_eq!(
            &decoder.decode_member(&packed, member.len()).unwrap(),
            member
        );
    }
}

#[test]
fn two_byte_matches_reach_back_256_bytes_and_no_further() {
    let state = EncoderMatchState::default();
    assert_eq!(
        state.encode_match(2, 1).unwrap(),
        EncodedMatch::Short { slot: 0, extra: 0 }
    );
    assert_eq!(
        state.encode_match(2, 256).unwrap(),
        EncodedMatch::Short { slot: 7, extra: 63 }
    );
    assert!(state.encode_match(2, 257).is_err());

    // A remembered offset is still cheaper as a repeat, and the decoder pushes
    // a two-byte match's offset like any fresh one.
    let mut state = EncoderMatchState::default();
    state.remember(40, 300);
    assert!(matches!(
        state.encode_match(2, 300).unwrap(),
        EncodedMatch::RepeatOffset { index: 0, .. }
    ));
    state.remember(2, 9);
    assert_eq!(state.old_offsets[..2], [9, 300]);
    assert_eq!((state.last_offset, state.last_length), (9, 2));
}

#[test]
fn a_block_of_two_byte_matches_decodes() {
    let mut data = Vec::new();
    let mut tokens = Vec::new();
    for (index, offset) in [1usize, 3, 7, 100, 256, 2, 256].into_iter().enumerate() {
        while data.len() < offset {
            let byte = (data.len() * 37 + index) as u8;
            data.push(byte);
            tokens.push(EncodeToken::Literal(byte));
        }
        for _ in 0..2 {
            data.push(data[data.len() - offset]);
        }
        tokens.push(EncodeToken::Match {
            length: 2,
            offset: offset as u32,
        });
    }
    let packed = code_block(
        &tokens,
        EncoderMatchState::default(),
        &[],
        false,
        &mut [0; TABLE_COUNT],
    )
    .unwrap();
    assert_eq!(unpack29_decode(&packed, data.len()).unwrap(), data);
}

/// The parse prices each match from tables built once a pass. Every length at
/// every kind of offset must cost what the coder's own encoding of it does.
#[test]
fn offset_prices_agree_with_pricing_the_encoded_match() {
    let mut table = [0u8; TABLE_COUNT];
    for (index, length) in table.iter_mut().enumerate() {
        *length = (index * 7 % 16) as u8;
    }
    let prices = Prices::new(&table);
    let mut remembered = EncoderMatchState::default();
    for (length, offset) in [(5, 0x40000), (9, 0x2000), (3, 300), (7, 5)] {
        remembered.remember(length, offset);
    }
    let mut repeated = EncoderMatchState::default();
    for (length, offset) in [(4, 70_000), (2, 9), (258, 9)] {
        repeated.remember(length, offset);
    }
    let mut states = vec![EncoderMatchState::default(), remembered, repeated];
    let mut two = remembered;
    two.remember(2, 12);
    states.push(two);
    let mut offsets: Vec<usize> = (1..=300).collect();
    offsets.extend([
        0x1fff,
        0x2000,
        0x2001,
        0x3ffff,
        0x40000,
        0x40001,
        70_000,
        MAX_HISTORY,
        MAX_HISTORY + 1,
    ]);
    for state in &states {
        for &offset in &offsets {
            let at = OffsetPrices::new(&prices, state, offset);
            for length in 2..=MAX_ENCODER_MATCH_LENGTH {
                let encoded = state.encode_match(length, offset).ok();
                assert_eq!(
                    at.of(length),
                    encoded.map(|encoded| prices.of(encoded)),
                    "length {length} at offset {offset} from {state:?}"
                );
            }
        }
    }
}

#[test]
fn slot_ends_are_the_widest_length_each_slot_codes() {
    for base in [2, 3, 4, 5] {
        let mut offered = Vec::new();
        candidate_lengths(1, MAX_ENCODER_MATCH_LENGTH, base, |length| {
            offered.push(length)
        });
        for pair in offered.windows(2) {
            assert!(pair[0] <= pair[1], "{offered:?}");
        }
        let slot = |length: usize| match base {
            2 => length_slot_for_repeat_match(length).map(|(slot, _)| slot),
            _ => length_slot_for_match(length - (base - 3)).map(|(slot, _)| slot),
        };
        for &length in &offered[..offered.len() - 1] {
            if length < MAX_ENCODER_MATCH_LENGTH {
                assert_ne!(slot(length), slot(length + 1), "base {base}, {length}");
            }
        }
    }
}
