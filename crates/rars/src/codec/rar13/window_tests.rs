use super::*;
use crate::codec::rar13::Unpack15;
use std::ops::ControlFlow;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn text(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&[u8]; 10] = [
        b"windows ",
        b"carry ",
        b"their ",
        b"flags ",
        b"across ",
        b"the ",
        b"chunk ",
        b"boundary, ",
        b"and ",
        b"stmode.\n",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 16);
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

/// Text, noise long enough for stmode literal runs to cross a window end,
/// zeros for the longest matches, and text again that repeats the first.
fn mixed(len: usize) -> Vec<u8> {
    let quarter = len / 4;
    let mut out = text(quarter, 1);
    out.extend(noise(quarter, 2));
    out.extend(vec![0; quarter]);
    // The same words again, so matches reach back past the noise.
    out.extend(text(len - out.len(), 1));
    out
}

fn options() -> [EncodeOptions; 3] {
    [
        EncodeOptions::new(),
        EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(16 * 1024),
        EncodeOptions::new()
            .with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(4 * 1024),
    ]
}

fn streamed(encoder: &mut Unpack15Encoder, input: &[u8], chunk: usize) -> Vec<u8> {
    let mut packed = Vec::new();
    let mut reached = 0;
    let flow = encoder
        .encode_member_streamed_in(
            &mut &input[..],
            input.len(),
            &mut |_| true,
            &mut |bytes, coded| {
                assert!(coded >= reached && coded <= input.len());
                reached = coded;
                packed.extend_from_slice(bytes);
                Ok(ControlFlow::Continue(()))
            },
            chunk,
        )
        .unwrap();
    assert!(flow.is_continue());
    packed
}

#[test]
fn a_member_coded_a_window_at_a_time_packs_as_it_does_whole() {
    // Longer than the 64 KiB the window keeps, so it slides.
    let data = mixed(160 * 1024 + 7);
    for options in options() {
        let whole = Unpack15Encoder::with_options(options)
            .encode_member(&data)
            .unwrap();
        for chunk in [LOOKAHEAD + 1, 10_000, HISTORY + 3] {
            let packed = streamed(&mut Unpack15Encoder::with_options(options), &data, chunk);
            assert!(packed == whole, "{options:?}, {chunk}-byte windows");
        }
        assert_eq!(
            Unpack15::new()
                .decode_member(&whole, data.len(), false)
                .unwrap(),
            data
        );
    }
}

#[test]
fn a_solid_chain_codes_the_same_streamed_or_whole() {
    let members = [text(90_000, 3), noise(70_000, 4), mixed(100_000)];
    let mut whole = Unpack15Encoder::new();
    let mut windowed = Unpack15Encoder::new();
    let mut decoder = Unpack15::new();
    for (index, member) in members.iter().enumerate() {
        let expected = whole.encode_member(member).unwrap();
        assert!(
            streamed(&mut windowed, member, 9_000) == expected,
            "member {index}"
        );
        assert_eq!(
            decoder
                .decode_member(&expected, member.len(), index > 0)
                .unwrap(),
            *member
        );
    }
}

#[test]
fn the_window_index_lists_every_earlier_position_with_the_same_hash() {
    // Few distinct trigrams, so chains are long and run past the 64 KiB ring.
    let mut state = 5;
    let data: Vec<u8> = (0..3 * HISTORY)
        .map(|_| b"ab"[xorshift(&mut state) as usize % 2])
        .collect();
    let mut finder = Rar13MatchFinder::new();
    for pos in (1..data.len() - 2).step_by(997) {
        let reach = pos.min(MAX_LONG_LZ_DISTANCE);
        let hash = Rar13MatchFinder::hash(&data, pos);
        let expected: Vec<_> = (pos - reach..pos)
            .rev()
            .filter(|&candidate| Rar13MatchFinder::hash(&data, candidate) == hash)
            .collect();
        let listed: Vec<_> = finder
            .candidates_before(&data, pos)
            .take_while(|&candidate| pos - candidate <= reach)
            .collect();
        assert_eq!(listed, expected, "at {pos}");
    }
}

#[test]
fn a_break_from_the_output_stops_the_coding() {
    let data = noise(200_000, 6);
    let mut calls = 0;
    let flow = Unpack15Encoder::new()
        .encode_member_streamed_in(
            &mut &data[..],
            data.len(),
            &mut |_| true,
            &mut |_, _| {
                calls += 1;
                Ok(ControlFlow::Break(()))
            },
            10_000,
        )
        .unwrap();
    assert!(flow.is_break());
    assert_eq!(calls, 1);
}
