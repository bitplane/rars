use super::super::encoder::streaming_blocks_with_allowance;
use super::super::{
    encode_compressed_block, encode_table_lengths_with_bit_count, Allowance, DecodeMode,
    EncodeOptions, HistoryRetention, TableLengths, Unpack50Encoder, ALIGN_TABLE_SIZE,
    DISTANCE_TABLE_SIZE_50, LENGTH_TABLE_SIZE, MAIN_TABLE_SIZE,
};
use super::*;
use crate::{FilterKind, FilterSpec};

const DICTIONARY: usize = 1 << 20;

#[derive(Clone)]
struct Member {
    stream: Vec<u8>,
    size: usize,
    solid: bool,
}

#[derive(Debug, PartialEq)]
struct Outcome {
    output: std::result::Result<Vec<u8>, String>,
    reps: [usize; 4],
    last_length: usize,
    has_tables: bool,
    history: Vec<u8>,
    ended_early: Option<usize>,
}

struct Chain {
    outcomes: Vec<Outcome>,
    claimed: Vec<usize>,
}

fn run_chain(members: &[Member], workers: Option<usize>) -> Chain {
    let mut state = ReaderState::new(&Allowance::default());
    let mut stage =
        workers.map(|workers| MembersAhead::new(workers, &Allowance::default()).unwrap());
    let mut next = 0;
    let mut chain = Chain {
        outcomes: Vec::new(),
        claimed: Vec::new(),
    };
    for (index, member) in members.iter().enumerate() {
        if let Some(stage) = &mut stage {
            if next < index {
                next = index;
                stage.break_run();
            }
            while let Some(ahead) = members.get(next) {
                let key = next as u64;
                if stage.offer(key, &ahead.stream, ahead.size as u64, 0, ahead.solid)
                    == Offered::Full
                {
                    break;
                }
                next += 1;
            }
            if let Some(claimed) = stage.claim(index as u64) {
                chain.claimed.push(index);
                state.set_claimed(claimed);
            }
        }
        let output = state.decode_member_with_dictionary_and_history(
            &member.stream,
            0,
            member.size,
            DICTIONARY,
            member.solid,
            DecodeMode::Lz,
            HistoryRetention::Retain,
        );
        let whole = state.settle_claim();
        if let Some(stage) = &mut stage {
            match &output {
                Err(_) => stage.clear(),
                Ok(_) if whole => stage.replayed(index as u64),
                Ok(_) => {}
            }
        }
        chain.outcomes.push(Outcome {
            output: output
                .map(|output| output.to_vec())
                .map_err(|error| format!("{error:?}")),
            reps: state.reps,
            last_length: state.last_length,
            has_tables: state.tables.is_some(),
            history: state.history_bytes(),
            ended_early: state.ended_early(),
        });
    }
    chain
}

fn assert_ahead_matches_serial(members: &[Member]) -> (Vec<Outcome>, Vec<usize>) {
    let serial = run_chain(members, None);
    let mut claimed = Vec::new();
    for workers in [1, 4] {
        let ahead = run_chain(members, Some(workers));
        assert_eq!(ahead.outcomes, serial.outcomes, "workers={workers}");
        claimed = ahead.claimed;
    }
    (serial.outcomes, claimed)
}

fn prose(len: usize, seed: u32) -> Vec<u8> {
    let words: [&[u8]; 6] = [
        b"member ", b"chain ", b"solid ", b"tables ", b"the ", b"of ",
    ];
    let mut state = seed;
    let mut data = Vec::with_capacity(len + 8);
    while data.len() < len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        if state >> 28 == 0 {
            data.push((state >> 8) as u8);
        } else {
            data.extend_from_slice(words[(state >> 20) as usize % words.len()]);
        }
    }
    data.truncate(len);
    data
}

fn lz_stream(data: &[u8], history: &[u8], block_len: usize) -> Vec<u8> {
    let mut blocks = Vec::new();
    let mut end = 0;
    while end < data.len() {
        end = (end + block_len).min(data.len());
        blocks.push((end, end == data.len()));
    }
    streaming_blocks_with_allowance(
        data,
        history,
        &blocks,
        0,
        EncodeOptions::new(16),
        None,
        &Allowance::default(),
    )
    .unwrap()
    .iter()
    .flat_map(|block| block.to_vec())
    .collect()
}

fn letters(first: u8, packed: &[u8]) -> Vec<u8> {
    packed
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |bit| first + ((byte >> bit) & 1)))
        .collect()
}

// Tables that give one-bit codes to `first` and the letter after it.
fn table_block(first: u8, packed: &[u8], is_last: bool) -> (Vec<u8>, Vec<u8>) {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[first as usize] = 1;
    lengths.main[first as usize + 1] = 1;
    let (mut payload, table_bits) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let pad = payload.len() * 8 - table_bits;
    payload.extend_from_slice(packed);
    let text = letters(first, &payload[payload.len() - packed.len() - 1..])[8 - pad..].to_vec();
    let stream = encode_compressed_block(&payload, payload.len() * 8, true, is_last).unwrap();
    (stream, text)
}

fn plain_block(first: u8, packed: &[u8], is_last: bool) -> (Vec<u8>, Vec<u8>) {
    let stream = encode_compressed_block(packed, packed.len() * 8, false, is_last).unwrap();
    (stream, letters(first, packed))
}

fn member(blocks: &[(Vec<u8>, Vec<u8>)]) -> (Member, Vec<u8>) {
    let text: Vec<u8> = blocks.iter().flat_map(|block| block.1.clone()).collect();
    let member = Member {
        stream: blocks.iter().flat_map(|block| block.0.clone()).collect(),
        size: text.len(),
        solid: true,
    };
    (member, text)
}

#[test]
fn members_that_reuse_earlier_tables_decode_ahead_as_the_serial_decoder_does() {
    let mut members = Vec::new();
    let mut texts = Vec::new();
    let mut push = |blocks: &[(Vec<u8>, Vec<u8>)]| {
        let (member, text) = member(blocks);
        members.push(member);
        texts.push(text);
    };
    push(&[table_block(b'A', &[0b0110_1001], true)]);
    push(&[plain_block(b'A', &[0x5a; 7], true)]);
    push(&[
        plain_block(b'A', &[0x33; 3], false),
        table_block(b'C', &[0x0f], true),
    ]);
    push(&[plain_block(b'C', &[0xa5; 4], true)]);
    push(&[plain_block(b'C', &[0x96; 2], true)]);
    let (outcomes, claimed) = assert_ahead_matches_serial(&members);
    for (outcome, text) in outcomes.iter().zip(&texts) {
        assert_eq!(outcome.output.as_ref(), Ok(text));
    }
    assert_eq!(claimed, [0, 1, 2, 3, 4]);
}

#[test]
fn a_member_that_stops_before_its_last_tables_leaves_its_successor_to_the_serial_decoder() {
    let (first, _) = member(&[table_block(b'A', &[0b0110_1001], true)]);
    let (mut stopping, _) = member(&[
        plain_block(b'A', &[0x5a; 7], false),
        table_block(b'C', &[0x0f], true),
    ]);
    stopping.size = 56;
    let (next, text) = member(&[plain_block(b'A', &[0x3c; 5], true)]);
    let (outcomes, claimed) = assert_ahead_matches_serial(&[first, stopping, next]);
    assert_eq!(outcomes[2].output.as_ref(), Ok(&text));
    assert_eq!(claimed, [0, 1]);
}

#[test]
fn solid_and_filtered_members_decode_ahead_as_the_serial_decoder_does() {
    let first = prose(9_000, 3);
    let second = [&first[4_000..], &prose(5_000, 5)[..]].concat();
    let mut third = prose(6_000, 7);
    for at in (0..third.len() - 5).step_by(97) {
        third[at] = 0xe8;
    }
    let filters = [
        FilterSpec::range(FilterKind::E8, 0..3_000),
        FilterSpec::range(FilterKind::Delta { channels: 3 }, 3_000..6_000),
    ];
    let members = [
        Member {
            stream: lz_stream(&first, &[], 800),
            size: first.len(),
            solid: false,
        },
        Member {
            stream: lz_stream(&second, &first, 800),
            size: second.len(),
            solid: true,
        },
        Member {
            stream: Unpack50Encoder::new()
                .encode_member_with_filters(&third, 0, &filters)
                .unwrap(),
            size: third.len(),
            solid: true,
        },
    ];
    let (outcomes, claimed) = assert_ahead_matches_serial(&members);
    assert_eq!(outcomes[1].output.as_ref(), Ok(&second));
    assert_eq!(outcomes[2].output.as_ref(), Ok(&third));
    assert_eq!(claimed, [0, 1, 2]);
}

#[test]
fn long_members_matching_into_history_decode_ahead_as_the_serial_decoder_does() {
    let first = prose(20_000, 29);
    let second = [
        &first[5_000..15_000],
        &[b'z'; 3_000][..],
        &prose(4_000, 31),
        &first[..8_000],
    ]
    .concat();
    // Encoded against a longer history than the chain holds, so its
    // matches into the missing part reach past the window.
    let missing = prose(4_000, 37);
    let third = [&prose(3_000, 41)[..], &missing[..2_000]].concat();
    let members = [
        Member {
            stream: lz_stream(&first, &[], 6_000),
            size: first.len(),
            solid: false,
        },
        Member {
            stream: lz_stream(&second, &first, 6_000),
            size: second.len(),
            solid: true,
        },
        Member {
            stream: lz_stream(&third, &[&missing[..], &first, &second].concat(), 6_000),
            size: third.len(),
            solid: true,
        },
    ];
    let (outcomes, claimed) = assert_ahead_matches_serial(&members);
    assert_eq!(outcomes[1].output.as_ref(), Ok(&second));
    assert_ne!(outcomes[2].output.as_ref(), Ok(&third));
    assert_eq!(claimed, [0, 1, 2]);
}

#[test]
fn members_after_the_declared_size_decode_ahead_as_the_serial_decoder_does() {
    let data = prose(2_100, 11);
    let stream = lz_stream(&data, &[], 700);
    let tail = prose(1_500, 13);
    for size in 0..=data.len() + 1 {
        let members = [
            Member {
                stream: stream.clone(),
                size,
                solid: false,
            },
            Member {
                stream: lz_stream(&tail, &data, 500),
                size: tail.len(),
                solid: true,
            },
        ];
        assert_ahead_matches_serial(&members);
    }
}

#[test]
fn a_damaged_member_mid_chain_fails_as_the_serial_decoder_does() {
    let first = prose(3_000, 17);
    let second = prose(3_000, 19);
    let third = prose(2_000, 23);
    let streams = [
        lz_stream(&first, &[], 600),
        lz_stream(&second, &first, 600),
        lz_stream(&third, &[&first[..], &second[..]].concat(), 600),
    ];
    for at in (0..streams[1].len()).step_by(7) {
        let mut damaged = streams[1].clone();
        damaged[at] ^= 1 << (at % 8);
        let members = [
            Member {
                stream: streams[0].clone(),
                size: first.len(),
                solid: false,
            },
            Member {
                stream: damaged,
                size: second.len(),
                solid: true,
            },
            Member {
                stream: streams[2].clone(),
                size: third.len(),
                solid: true,
            },
        ];
        assert_ahead_matches_serial(&members);
    }
}

#[test]
fn claims_follow_the_order_members_were_offered_in() {
    let (head, _) = member(&[table_block(b'A', &[0x12], true)]);
    let (reusing, _) = member(&[plain_block(b'A', &[0x34], true)]);
    let mut stage = MembersAhead::new(2, &Allowance::default()).unwrap();
    for (key, member) in [&head, &head, &reusing].into_iter().enumerate() {
        let offered = stage.offer(key as u64, &member.stream, member.size as u64, 0, true);
        assert_eq!(offered, Offered::Taken);
    }
    assert!(stage.claim(7).is_none(), "never offered");
    assert!(stage.claim(1).is_some(), "passes over the first");
    assert!(stage.claim(0).is_none(), "passed over for good");
    assert!(
        stage.claim(2).is_none(),
        "the member before was not replayed"
    );

    let (unsolid, _) = member(&[plain_block(b'A', &[0x56], true)]);
    assert_eq!(
        stage.offer(8, &unsolid.stream, 8, 0, false),
        Offered::Refused
    );
    assert_eq!(
        stage.offer(9, &reusing.stream, 8, 0, true),
        Offered::Refused
    );
}

#[test]
fn literal_runs_cut_by_the_declared_size_are_judged_as_the_serial_decoder_does() {
    let (whole, text) = member(&[
        table_block(b'A', &[0x5a, 0x3c], false),
        plain_block(b'A', &[0x96; 3], true),
    ]);
    let mut refused = 0;
    for size in 1..=text.len() {
        let cut = Member {
            size,
            ..whole.clone()
        };
        let (outcomes, _) = assert_ahead_matches_serial(&[cut]);
        refused += usize::from(outcomes[0].output.is_err());
    }
    assert!(refused > 0);
    let (outcomes, _) = assert_ahead_matches_serial(&[whole]);
    assert_eq!(outcomes[0].output.as_ref(), Ok(&text));
}

#[test]
fn members_passed_over_unclaimed_make_room_for_the_next() {
    let (head, _) = member(&[table_block(b'A', &[0x12], true)]);
    let mut stage = MembersAhead::new(1, &Allowance::default()).unwrap();
    let mut key = 0;
    while stage.offer(key, &head.stream, head.size as u64, 0, true) == Offered::Taken {
        key += 1;
    }
    assert!(stage.full());
    stage.pass_before(key);
    assert!(!stage.full());
    assert_eq!(
        stage.offer(key, &head.stream, head.size as u64, 0, true),
        Offered::Taken
    );
    assert!(stage.claim(key).is_some());
}

#[test]
fn a_claim_a_failure_left_unused_is_not_replayed_for_the_next_member() {
    let (first, _) = member(&[table_block(b'A', &[0x12], true)]);
    let (second, text) = member(&[table_block(b'C', &[0x34], true)]);
    let mut stage = MembersAhead::new(1, &Allowance::default()).unwrap();
    assert_eq!(
        stage.offer(0, &first.stream, first.size as u64, 0, false),
        Offered::Taken
    );
    let mut state = ReaderState::new(&Allowance::default());
    state.set_claimed(stage.claim(0).unwrap());
    let failed = state.decode_member_with_dictionary_and_history(
        &first.stream,
        0,
        first.size,
        0,
        false,
        DecodeMode::Lz,
        HistoryRetention::Retain,
    );
    assert!(failed.is_err());
    assert!(!state.settle_claim());
    let decoded = state
        .decode_member_with_dictionary_and_history(
            &second.stream,
            0,
            second.size,
            DICTIONARY,
            false,
            DecodeMode::Lz,
            HistoryRetention::Retain,
        )
        .unwrap();
    assert_eq!(decoded.to_vec(), text);
}
