use super::*;

fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state >> 8
}

/// Short opcodes, small immediates and copies from a spread of distances.
fn code_like(len: usize, seed: u32) -> Vec<u8> {
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

fn prose(len: usize, seed: u32) -> Vec<u8> {
    let vocabulary: [&[u8]; 12] = [
        b"the ",
        b"cut ",
        b"tables ",
        b"each ",
        b"block ",
        b"prices ",
        b"of ",
        b"its ",
        b"own ",
        b"symbols ",
        b"where ",
        b"change.\n",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(vocabulary[lcg(&mut state) as usize % vocabulary.len()]);
    }
    out.truncate(len);
    out
}

/// Prose, then code, then prose again, each a third of a block or more.
fn changing(len: usize) -> Vec<u8> {
    let third = len / 3;
    let mut data = prose(third, 1);
    data.extend(code_like(third, 2));
    data.extend(prose(len - 2 * third, 3));
    data
}

fn lazy() -> EncodeOptions {
    EncodeOptions::new(64)
        .with_lazy_matching(true)
        .with_block_size(64 * 1024)
        .with_max_match_distance(1 << 20)
}

/// What `tokens` code from no repeat offsets, counted.
fn counted(tokens: &[EncodeToken]) -> Box<Counted> {
    Box::new(Counted {
        frequencies: SymbolCounts::of_tokens(tokens, EncoderMatchState::default())
            .unwrap()
            .frequencies,
        table: None,
    })
}

/// Each piece carries its own symbols, so coding it builds the same table
/// counting them again would, and the counted bits are what pricing every
/// token says.
#[test]
fn cut_pieces_carry_the_symbols_they_code() {
    let mut cut = prose(32 * 1024, 1);
    cut.extend(code_like(32 * 1024, 2));
    for (block, pieces_at_least) in [(cut, 2), (prose(64 * 1024, 5), 1)] {
        let tokens = encode_tokens_with_progress(&block, &[], lazy(), None).unwrap();
        let fresh = EncoderMatchState::default();
        let counts = SymbolCounts::of_tokens(&tokens, fresh).unwrap();
        let (bits, table) = counts.priced();
        assert_eq!(bits, optimal_parse::priced_bits(&tokens, fresh).unwrap());
        assert_eq!(table, table_lengths_for_tokens(&tokens, fresh, 0).unwrap());
        assert!(counts.shannon_bits() >= bits);
        let pieces = split(0, block.len(), tokens.clone(), counted(&tokens)).unwrap();
        assert!(pieces.len() >= pieces_at_least, "{} pieces", pieces.len());
        for piece in &pieces {
            let mine = SymbolCounts::of_tokens(&piece.tokens, piece.state).unwrap();
            let counted = piece.counted.as_deref().expect("a cut piece is counted");
            assert_eq!(
                counted.frequencies, mine.frequencies,
                "piece ending at {}",
                piece.end
            );
            for filters in [0, 2] {
                assert_eq!(
                    counted.table(filters),
                    table_lengths_for_tokens(&piece.tokens, piece.state, filters).unwrap()
                );
            }
        }
    }
}

#[test]
fn a_block_is_cut_near_where_its_statistics_change() {
    let mut data = prose(32 * 1024, 1);
    data.extend(code_like(32 * 1024, 2));
    let tokens = encode_tokens_with_progress(&data, &[], lazy(), None).unwrap();
    let pieces = split(0, data.len(), tokens.clone(), counted(&tokens)).unwrap();

    assert!(pieces.len() >= 2, "{} pieces", pieces.len());
    assert!(
        pieces
            .iter()
            .any(|piece| piece.end.abs_diff(32 * 1024) <= UNIT),
        "no cut near the change: {:?}",
        pieces.iter().map(|piece| piece.end).collect::<Vec<_>>()
    );
    // The pieces are the parse, in order, ending where it does.
    assert_eq!(pieces.last().unwrap().end, data.len());
    let joined: Vec<EncodeToken> = pieces.into_iter().flat_map(|piece| piece.tokens).collect();
    assert_eq!(format!("{joined:?}"), format!("{tokens:?}"));
}

#[test]
fn a_block_with_one_kind_of_content_or_too_short_to_cut_stays_whole() {
    // After history, so the block does not start on the literals a member
    // with nothing to match against opens with.
    let history = prose(64 * 1024, 4);
    for data in [prose(64 * 1024, 5), prose(2 * UNIT - 1, 6)] {
        let tokens = encode_tokens_with_progress(&data, &history, lazy(), None).unwrap();
        let pieces = split(0, data.len(), tokens.clone(), counted(&tokens)).unwrap();
        assert_eq!(pieces.len(), 1, "{} bytes", data.len());
    }
}

#[test]
fn cut_blocks_round_trip_and_never_code_larger() {
    let samples = [
        ("changing", changing(200_000)),
        ("code", code_like(150_000, 7)),
        ("prose", prose(150_000, 11)),
        ("short", changing(20_000)),
        ("tiny", b"abcabcabcabd".to_vec()),
    ];
    for (name, data) in samples {
        for passes in [0, 2] {
            let options = lazy().with_optimal_parse_passes(passes);
            let whole = unpack29_encode_literals_with_options(&data, options).unwrap();
            let cut = unpack29_encode_literals_with_options(&data, options.with_split_blocks(true))
                .unwrap();
            assert_eq!(
                unpack29_decode(&cut, data.len()).unwrap(),
                data,
                "{name} at {passes} passes did not round trip"
            );
            assert!(
                cut.len() <= whole.len(),
                "{name} at {passes} passes: cut {} bytes, whole {}",
                cut.len(),
                whole.len()
            );
        }
    }
    let data = changing(200_000);
    let whole = unpack29_encode_literals_with_options(&data, lazy()).unwrap();
    let cut = unpack29_encode_literals_with_options(&data, lazy().with_split_blocks(true)).unwrap();
    assert!(cut.len() < whole.len());
}

#[test]
fn a_member_read_in_segments_is_cut_as_it_is_in_memory() {
    let data = changing(300_000);
    let options = lazy().with_split_blocks(true).with_optimal_parse_passes(1);
    let mut streamed = Vec::new();
    let flow = unpack29_encode_literals_streamed(
        &mut &data[..],
        data.len(),
        options,
        None,
        &mut |_| true,
        &mut |block, _| {
            streamed.extend_from_slice(block);
            Ok(ControlFlow::Continue(()))
        },
    )
    .unwrap();
    assert_eq!(flow, ControlFlow::Continue(()));
    assert_eq!(
        streamed,
        unpack29_encode_literals_with_options(&data, options).unwrap()
    );
}

#[test]
fn a_solid_chain_of_cut_blocks_round_trips() {
    let mut encoder =
        Unpack29Encoder::with_options(lazy().with_split_blocks(true).with_optimal_parse_passes(1));
    let mut decoder = Unpack29::new();
    for member in [changing(90_000), code_like(70_000, 9), changing(130_000)] {
        let packed = encoder.encode_member(&member).unwrap();
        assert_eq!(
            decoder.decode_member(&packed, member.len()).unwrap(),
            member
        );
    }
}
