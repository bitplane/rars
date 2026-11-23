use super::super::{
    Allowance, DecodedChunk, Error, FilterStage, FilterType, PendingFilter, ReaderState,
    StreamDecodeError, Unpack50Encoder,
};
use super::Piece;
use crate::read_control::ReadControl;
use crate::{ArchiveReadOptions, FilterKind, FilterSpec};

const DICTIONARY: usize = 1 << 20;

#[derive(Debug, PartialEq)]
struct Run {
    bytes: Vec<u8>,
    error: Option<String>,
    reps: [usize; 4],
    last_length: usize,
    has_tables: bool,
    ended_early: Option<usize>,
}

fn decoder(workers: Option<usize>) -> ReaderState<Allowance> {
    let mut state = ReaderState::new(&Allowance::default());
    if let Some(workers) = workers {
        state.read_control =
            ReadControl::for_options(&ArchiveReadOptions::new().with_rar50_decode_workers(workers));
    }
    state
}

fn run(
    state: &mut ReaderState<Allowance>,
    stream: &[u8],
    output_size: usize,
    solid: bool,
    aside: bool,
) -> Run {
    let mut bytes = Vec::new();
    let sink = |chunk: DecodedChunk<'_>| {
        match chunk {
            DecodedChunk::Bytes(chunk) => bytes.extend_from_slice(chunk),
            DecodedChunk::Repeated { byte, len } => bytes.resize(bytes.len() + len, byte),
        }
        Ok::<(), &'static str>(())
    };
    let input = &mut &*stream;
    let result = if aside {
        state.decode_member_filtering_aside(input, 0, output_size, DICTIONARY, solid, sink)
    } else {
        state.decode_member_from_reader_with_dictionary_to_sink(
            input,
            0,
            output_size,
            DICTIONARY,
            solid,
            sink,
        )
    };
    Run {
        bytes,
        error: result.err().map(|error| format!("{error:?}")),
        reps: state.reps,
        last_length: state.last_length,
        has_tables: state.tables.is_some(),
        ended_early: state.ended_early(),
    }
}

/// The decoder's own filter stage, then the filter thread over serial and worker decoding.
fn assert_aside_matches_serial(stream: &[u8], output_size: usize) -> Run {
    let serial = run(&mut decoder(None), stream, output_size, false, false);
    for workers in [None, Some(1), Some(4)] {
        let aside = run(&mut decoder(workers), stream, output_size, false, true);
        assert_eq!(
            aside, serial,
            "workers={workers:?}, output_size={output_size}"
        );
    }
    serial
}

fn prose(len: usize, seed: u32) -> Vec<u8> {
    let words: [&[u8]; 6] = [
        b"call ",
        b"jump ",
        b"\xe8near ",
        b"filter ",
        b"\xe9the ",
        b"of ",
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

/// Filters that start and end inside pieces, across them, and back to back.
fn filtered(data: &[u8], filters: &[FilterSpec]) -> Vec<u8> {
    Unpack50Encoder::new()
        .encode_member_with_filters(data, 0, filters)
        .unwrap()
}

fn mixed_filters() -> [FilterSpec; 4] {
    [
        FilterSpec::range(FilterKind::E8, 100..9_000),
        FilterSpec::range(FilterKind::Delta { channels: 3 }, 9_000..20_001),
        FilterSpec::range(FilterKind::E8E9, 26_000..26_005),
        FilterSpec::range(FilterKind::Delta { channels: 2 }, 30_000..40_000),
    ]
}

#[test]
fn the_filter_thread_applies_filters_as_the_decoders_own_stage_does() {
    let data = prose(40_000, 3);
    let stream = filtered(&data, &mixed_filters());
    let serial = assert_aside_matches_serial(&stream, data.len());
    assert_eq!(serial.error, None);
    assert!(serial.bytes == data, "the filtered bytes differ");
    // A declared size inside a filter leaves it incomplete.
    for output_size in [0, 1, 8_999, 9_000, 15_000, 39_999] {
        assert_aside_matches_serial(&stream, output_size);
    }
}

#[test]
fn the_filter_thread_starts_where_the_bytes_sent_straight_through_end() {
    // The first record arrives blocks into the member, after whole flushes.
    let data = prose(300_000, 23);
    let stream = filtered(
        &data,
        &[
            FilterSpec::range(FilterKind::E8E9, 200_003..230_000),
            FilterSpec::range(FilterKind::Delta { channels: 4 }, 250_000..260_000),
        ],
    );
    let serial = assert_aside_matches_serial(&stream, data.len());
    assert_eq!(serial.error, None);
    assert!(serial.bytes == data, "the filtered bytes differ");
}

#[test]
fn the_filter_thread_reports_a_truncated_member_as_the_decoders_own_stage_does() {
    let data = prose(40_000, 5);
    let stream = filtered(&data, &mixed_filters());
    for len in (0..stream.len()).step_by(37) {
        let serial = assert_aside_matches_serial(&stream[..len], data.len());
        assert!(serial.error.is_some(), "len={len}");
    }
}

#[test]
fn the_filter_thread_reports_a_damaged_member_as_the_decoders_own_stage_does() {
    let data = prose(40_000, 7);
    let stream = filtered(&data, &mixed_filters());
    for at in (0..stream.len()).step_by(29) {
        let mut damaged = stream.clone();
        damaged[at] ^= 1 << (at % 8);
        assert_aside_matches_serial(&damaged, data.len());
    }
}

#[test]
fn a_filter_the_stage_refuses_wins_over_a_later_decode_failure() {
    // Blocks enough that a cut can fall after the refused record.
    let data = prose(200_000, 11);
    // The second filter overlaps the first, which the streaming stage refuses.
    let stream = filtered(
        &data,
        &[
            FilterSpec::range(FilterKind::E8, 1_000..5_000),
            FilterSpec::range(FilterKind::E8, 4_000..6_000),
        ],
    );
    let whole = assert_aside_matches_serial(&stream, data.len());
    assert_eq!(whole.error.as_deref(), Some("FilteredMember"));
    // Cut short after the refused record, the decoder still reports the filter.
    let refused = (0..stream.len())
        .step_by(997)
        .filter(|&len| {
            let run = assert_aside_matches_serial(&stream[..len], data.len());
            run.error.as_deref() == Some("FilteredMember")
        })
        .count();
    assert_ne!(refused, 0);
}

#[test]
fn the_filter_thread_continues_a_solid_member_as_the_decoders_own_stage_does() {
    // The encoder remembers its input, so the member it continues has no filters.
    let first = prose(30_000, 13);
    let second = [&first[10_000..], &prose(12_000, 17)[..]].concat();
    let mut encoder = Unpack50Encoder::new();
    let streams = [
        encoder.encode_member_with_filters(&first, 0, &[]).unwrap(),
        encoder
            .encode_member_with_filters(
                &second,
                0,
                &[
                    FilterSpec::range(FilterKind::E8E9, 6_000..26_005),
                    FilterSpec::range(FilterKind::Delta { channels: 2 }, 27_000..31_000),
                ],
            )
            .unwrap(),
    ];
    let mut serial = decoder(None);
    let expected = [
        run(&mut serial, &streams[0], first.len(), false, false),
        run(&mut serial, &streams[1], second.len(), true, false),
    ];
    assert_eq!(expected[1].error, None);
    assert!(expected[1].bytes == second, "the solid member differs");
    for workers in [None, Some(4)] {
        let mut aside = decoder(workers);
        assert_eq!(
            run(&mut aside, &streams[0], first.len(), false, true),
            expected[0]
        );
        assert_eq!(
            run(&mut aside, &streams[1], second.len(), true, true),
            expected[1]
        );
    }
}

#[test]
fn the_filter_thread_stops_at_a_sink_failure() {
    let data = prose(40_000, 19);
    let stream = filtered(&data, &mixed_filters());
    for workers in [None, Some(4)] {
        let mut calls = 0;
        let result = decoder(workers).decode_member_filtering_aside(
            &mut stream.as_slice(),
            0,
            data.len(),
            DICTIONARY,
            false,
            |_| {
                calls += 1;
                if calls == 3 {
                    Err("sink")
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(
            format!("{:?}", result.unwrap_err()),
            "Sink(\"sink\")",
            "workers={workers:?}"
        );
        assert_eq!(calls, 3, "workers={workers:?}");
    }
}

#[test]
fn a_whole_stream_shorter_than_declared_ends_early_as_in_the_decoder() {
    let data = prose(40_000, 11);
    // Every filter inside the stream: the member is whole, only shorter than declared.
    let stream = filtered(&data, &mixed_filters());
    let short = assert_aside_matches_serial(&stream, data.len() + 5_000);
    assert_eq!(short.error, None);
    assert_eq!(short.ended_early, Some(data.len()));
    assert!(short.bytes == data, "the filtered bytes differ");
}

/// A filter reaching past the last byte leaves a member whose stream ended
/// early truncated, and is invalid in one that ran to its declared size, as
/// the decoder's own stage judges them. An encoder never writes one.
#[test]
fn a_filter_past_an_early_end_leaves_the_member_truncated() {
    for ended_early in [true, false] {
        let allowance = Allowance::default();
        let mut stage = FilterStage::new(&allowance);
        let (send, pieces) = std::sync::mpsc::sync_channel(4);
        let (spare, _spare) = std::sync::mpsc::sync_channel(4);
        let filter = PendingFilter {
            start: 10,
            length: 100,
            filter_type: FilterType::Delta,
            channels: 2,
        };
        send.send(Piece::Filter(filter)).unwrap();
        send.send(Piece::Bytes(vec![7; 50])).unwrap();
        send.send(Piece::Done { ended_early }).unwrap();
        drop(send);
        let mut sink = |_: DecodedChunk<'_>| Ok::<(), ()>(());
        let result = super::run_filters(&mut stage, pieces, spare, &mut sink);
        if ended_early {
            assert!(matches!(
                result,
                Err(StreamDecodeError::Decode(Error::NeedMoreInput))
            ));
        } else {
            assert!(matches!(
                result,
                Err(StreamDecodeError::Decode(Error::InvalidData(_)))
            ));
        }
    }
}
