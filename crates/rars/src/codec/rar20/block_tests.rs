use super::*;
use crate::codec::rar20::Unpack20;

// Small blocks, so short inputs cross many of them.
const BLOCK: usize = 16 * 1024;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn text(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&[u8]; 10] = [
        b"blocks ",
        b"carry ",
        b"their ",
        b"offsets ",
        b"across ",
        b"the ",
        b"table ",
        b"switch, ",
        b"and ",
        b"audio.\n",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(WORDS[xorshift(&mut state) as usize % WORDS.len()]);
    }
    out.truncate(len);
    out
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len).map(|_| xorshift(&mut state) as u8).collect()
}

// Interleaved 8-bit samples of slow waves, which the audio predictor codes
// far smaller than LZ does.
fn tone(len: usize, channels: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let (t, channel) = ((i / channels) as f64, (i % channels) as f64);
            (128.0 + 90.0 * ((t + 7.0 * channel) / (13.0 + channel)).sin()) as u8
        })
        .collect()
}

fn decode(packed: &[u8], len: usize) -> Vec<u8> {
    Unpack20::new().decode_member(packed, len).unwrap()
}

fn levels() -> [EncodeOptions; 3] {
    [
        EncodeOptions::new(8),
        EncodeOptions::default().with_lazy_matching(true),
        EncodeOptions::default().with_optimal_parse(true),
    ]
}

#[test]
fn a_member_of_many_blocks_round_trips_at_every_parse() {
    let data = [text(90_000, 1), noise(20_000, 2), text(50_001, 3)].concat();
    for options in levels() {
        let packed =
            encode_member_in_blocks(&data, &[], None, options, false, None, BLOCK).unwrap();
        assert_eq!(decode(&packed, data.len()), data, "{options:?}");
    }
}

#[test]
fn blocks_switch_between_audio_and_lz_and_keep_both_states() {
    // A block size that does not divide into whole frames moves the channel
    // the next audio block starts on.
    let block = BLOCK + 1;
    let data = [
        tone(40_000, 2),
        text(40_000, 4),
        tone(40_000, 2),
        tone(30_000, 3),
        text(20_000, 5),
    ]
    .concat();
    let options = EncodeOptions::default();
    let mixed = encode_member_in_blocks(&data, &[], None, options, true, None, block).unwrap();
    assert_eq!(decode(&mixed, data.len()), data);
    let lz_only = encode_member_in_blocks(&data, &[], None, options, false, None, block).unwrap();
    let audio_only =
        encode_member_in_blocks(&tone(170_000, 2), &[], None, options, true, None, block).unwrap();
    // Both kinds were chosen: audio where it packs smaller, LZ for the text.
    assert!(mixed.len() < lz_only.len());
    assert!(mixed.len() > audio_only.len());
}

#[test]
fn a_member_of_one_block_codes_as_it_did_whole() {
    // One block is the whole member, with no table switch to announce.
    let data = text(BLOCK, 6);
    for options in levels() {
        let one = encode_member_in_blocks(&data, &[], None, options, true, None, BLOCK).unwrap();
        let two =
            encode_member_in_blocks(&data, &[], None, options, true, None, BLOCK / 2).unwrap();
        assert_eq!(
            one,
            encode_member(&data, &[], None, options, true, None).unwrap()
        );
        assert_ne!(one, two);
        assert_eq!(decode(&two, data.len()), data);
    }
}

fn streamed(
    data: &[u8],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    options: EncodeOptions,
    try_audio: bool,
) -> (Vec<u8>, usize, Vec<u8>) {
    let mut out = Vec::new();
    let mut chunks = 0;
    let (flow, kept) = encode_streamed(
        &mut &data[..],
        data.len(),
        history,
        fixed_table,
        options,
        try_audio,
        &mut |_| true,
        &mut |bytes| {
            out.extend_from_slice(bytes);
            chunks += 1;
            Ok(ControlFlow::Continue(()))
        },
        BLOCK,
    )
    .unwrap();
    assert!(flow.is_continue());
    (out, chunks, kept)
}

#[test]
fn streaming_a_member_writes_what_coding_it_in_memory_does() {
    let data = [text(70_000, 7), tone(30_000, 2), noise(9_999, 8)].concat();
    for options in levels() {
        for try_audio in [false, true] {
            let whole =
                encode_member_in_blocks(&data, &[], None, options, try_audio, None, BLOCK).unwrap();
            let (out, chunks, _) = streamed(&data, &[], None, options, try_audio);
            assert_eq!(out, whole, "{options:?}");
            assert!(chunks > 5, "the packed bytes leave a block at a time");
        }
    }
}

#[test]
fn a_streamed_solid_member_continues_the_chain_as_an_in_memory_one_does() {
    let first = text(30_000, 9);
    let second = [text(40_000, 9), first[..5_000].to_vec()].concat();
    let options = EncodeOptions::default().with_max_match_distance(64 * 1024);
    let table = FixedEncodeTable::new().unwrap();
    let mut chain = Unpack20Encoder::with_options(options);
    let packed_first = chain.encode_member(&first).unwrap();

    let whole = encode_member_in_blocks(
        &second,
        &chain.history,
        Some(table),
        chain.options,
        false,
        None,
        BLOCK,
    )
    .unwrap();
    let (out, _, kept) = streamed(&second, &chain.history, Some(table), chain.options, false);
    assert_eq!(out, whole);
    let mut joined = [chain.history.clone(), second.clone()].concat();
    joined.drain(..joined.len() - 64 * 1024);
    assert_eq!(kept, joined);

    let mut decoder = Unpack20::new();
    assert_eq!(
        decoder.decode_member(&packed_first, first.len()).unwrap(),
        first
    );
    assert_eq!(decoder.decode_member(&out, second.len()).unwrap(), second);
}

#[test]
fn a_streamed_chain_moves_on_only_when_every_byte_is_taken() {
    let data = text(3 * BLOCK_SIZE / 2, 10);
    let mut chain = Unpack20Encoder::new();
    chain.encode_member(b"the chain starts here").unwrap();
    let before = chain.history.clone();
    let mut taken = 0;
    let flow = chain
        .encode_member_streamed(&mut &data[..], data.len(), &mut |_| true, &mut |bytes| {
            taken += bytes.len();
            Ok(ControlFlow::Break(()))
        })
        .unwrap();
    assert!(flow.is_break());
    assert!(taken > 0);
    assert_eq!(chain.history, before);

    let flow = chain
        .encode_member_streamed(&mut &data[..], data.len(), &mut |_| true, &mut |_| {
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();
    assert!(flow.is_continue());
    // The chain keeps one dictionary of what it has coded.
    let joined = [&before[..], &data[..]].concat();
    assert!(chain.history == joined[joined.len() - chain.options.max_match_distance..]);
}

#[test]
fn streaming_reports_progress_through_the_member_and_can_be_cancelled() {
    let data = text(5 * BLOCK, 11);
    let mut furthest = 0;
    let mut out = Vec::new();
    let (flow, _) = encode_streamed(
        &mut &data[..],
        data.len(),
        &[],
        None,
        EncodeOptions::default(),
        false,
        &mut |at| {
            furthest = furthest.max(at);
            true
        },
        &mut |bytes| {
            out.extend_from_slice(bytes);
            Ok(ControlFlow::Continue(()))
        },
        BLOCK,
    )
    .unwrap();
    assert!(flow.is_continue());
    assert_eq!(furthest, data.len());

    let cancelled = encode_streamed(
        &mut &data[..],
        data.len(),
        &[],
        None,
        EncodeOptions::default(),
        false,
        &mut |at| at < 2 * BLOCK,
        &mut |_| Ok(ControlFlow::Continue(())),
        BLOCK,
    );
    assert!(matches!(cancelled, Err(Error::Cancelled)));
}

#[test]
fn an_audio_block_with_fewer_channels_starts_again_at_the_first() {
    // Ends with the third channel next, which a two-channel block lacks.
    let first = tone(3 * 1000 + 2, 3);
    let second = tone(2000, 2);
    let (a, coder) = code_audio_block(&first, 3, AudioCoder::default(), true).unwrap();
    assert_eq!(coder.channel, 2);
    let (b, _) = code_audio_block(&second, 2, coder, false).unwrap();
    let mut bits = BitWriter::default();
    bits.append(&a);
    bits.append(&b);
    let data = [first, second].concat();
    assert_eq!(decode(&bits.finish(), data.len()), data);
}

#[test]
fn a_block_parse_starts_from_the_offsets_the_reader_carries() {
    // The block opens by repeating bytes 4321 back, the newest offset carried in.
    let mut window = noise(8_000, 12);
    let start = window.len();
    window.extend_from_within(start - 4321..start - 4321 + 200);
    let state = LzState {
        old_offsets: [4321, 77, 0, 0],
        last_match: None,
    };
    let opens_with_old_offset = |tokens: &[EncodeToken]| {
        matches!(
            tokens[0],
            EncodeToken::OldOffset {
                index: 0,
                offset: 4321,
                ..
            }
        )
    };
    let options = EncodeOptions::default();
    let greedy =
        encode_tokens_with_progress(&window, start, options, None, None, state, None).unwrap();
    assert!(opens_with_old_offset(&greedy), "{:?}", &greedy[..2]);

    let options = options.with_optimal_parse(true);
    let matches = collect_match_lists(&window, start, window.len(), options);
    let tables = [0u8; TABLE_COUNT];
    let prices = CostModel::new(&tables);
    let optimal = encode_tokens_optimal(
        &window,
        start,
        window.len(),
        &matches,
        &prices,
        state.old_offsets,
    );
    assert!(opens_with_old_offset(&optimal), "{:?}", &optimal[..2]);
}
