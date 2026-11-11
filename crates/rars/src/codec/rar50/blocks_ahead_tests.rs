use super::super::{
    encode_compressed_block, encode_table_lengths_with_bit_count, streaming_blocks_with_allowance,
    Allowance, EncodeOptions, TableLengths, Unpack50Encoder, ALIGN_TABLE_SIZE,
    DISTANCE_TABLE_SIZE_50, LENGTH_TABLE_SIZE, MAIN_TABLE_SIZE,
};
use super::*;
use crate::read_control::ReadControl;
use crate::{ArchiveReadOptions, FilterKind, FilterSpec};

const DICTIONARY: usize = 1 << 20;

#[derive(Debug, PartialEq)]
struct Run {
    chunks: Vec<Vec<u8>>,
    error: Option<String>,
    reps: [usize; 4],
    last_length: usize,
    has_tables: bool,
}

impl Run {
    fn bytes(&self) -> Vec<u8> {
        self.chunks.concat()
    }
}

fn decoder(workers: Option<usize>) -> ReaderState<Allowance> {
    let mut state = ReaderState::new(&Allowance::default());
    if let Some(workers) = workers {
        state.read_control =
            ReadControl::for_options(&ArchiveReadOptions::new().with_rar50_decode_workers(workers));
    }
    state
}

fn decode(
    state: &mut ReaderState<Allowance>,
    stream: &[u8],
    output_size: usize,
    solid: bool,
) -> Run {
    decode_with(state, stream, output_size, solid, |_| Ok(()))
}

fn decode_with(
    state: &mut ReaderState<Allowance>,
    stream: &[u8],
    output_size: usize,
    solid: bool,
    mut accept: impl FnMut(usize) -> std::result::Result<(), &'static str>,
) -> Run {
    let mut chunks = Vec::new();
    let result = state.decode_member_from_reader_with_dictionary_to_sink(
        &mut &*stream,
        0,
        output_size,
        DICTIONARY,
        solid,
        |chunk| {
            accept(chunks.len())?;
            chunks.push(match chunk {
                DecodedChunk::Bytes(bytes) => bytes.to_vec(),
                DecodedChunk::Repeated { byte, len } => vec![byte; len],
            });
            Ok::<(), &'static str>(())
        },
    );
    Run {
        chunks,
        error: result.err().map(|error| format!("{error:?}")),
        reps: state.reps,
        last_length: state.last_length,
        has_tables: state.tables.is_some(),
    }
}

fn assert_workers_match_serial(stream: &[u8], output_size: usize) -> Run {
    let serial = decode(&mut decoder(None), stream, output_size, false);
    for workers in [1, 4] {
        let ahead = decode(&mut decoder(Some(workers)), stream, output_size, false);
        assert_eq!(
            ahead, serial,
            "workers={workers}, output_size={output_size}"
        );
    }
    serial
}

fn prose(len: usize, seed: u32) -> Vec<u8> {
    let words: [&[u8]; 8] = [
        b"block ", b"table ", b"window ", b"repeat ", b"match ", b"filter ", b"the ", b"of ",
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

fn ab_tables() -> (Vec<u8>, usize) {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[b'B' as usize] = 1;
    encode_table_lengths_with_bit_count(&lengths, 0).unwrap()
}

fn ab_text(packed: &[u8]) -> Vec<u8> {
    packed
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |bit| b'A' + ((byte >> bit) & 1)))
        .collect()
}

#[test]
fn workers_decode_a_multi_block_member_as_the_serial_decoder_does() {
    let data = prose(60_000, 7);
    let stream = lz_stream(&data, &[], 1_500);
    let serial = assert_workers_match_serial(&stream, data.len());
    assert_eq!(serial.error, None);
    assert_eq!(serial.bytes(), data);
}

#[test]
fn workers_stop_at_the_declared_size_as_the_serial_decoder_does() {
    let data = prose(12_000, 11);
    let stream = lz_stream(&data, &[], 700);
    for output_size in [0, 1, 699, 700, 701, 6_000, 11_999] {
        let serial = assert_workers_match_serial(&stream, output_size);
        assert_eq!(serial.error, None);
        assert_eq!(serial.bytes(), data[..output_size]);
    }
    let serial = assert_workers_match_serial(&stream, data.len() + 1);
    assert_eq!(serial.error.as_deref(), Some("Decode(NeedMoreInput)"));
}

#[test]
fn workers_report_a_truncated_member_as_the_serial_decoder_does() {
    let data = prose(6_000, 13);
    let stream = lz_stream(&data, &[], 500);
    for len in 0..stream.len() {
        let serial = assert_workers_match_serial(&stream[..len], data.len());
        assert!(serial.error.is_some(), "len={len}");
    }
}

#[test]
fn workers_report_a_damaged_member_as_the_serial_decoder_does() {
    let data = prose(6_000, 17);
    let stream = lz_stream(&data, &[], 500);
    for at in (0..stream.len()).step_by(5) {
        let mut damaged = stream.clone();
        damaged[at] ^= 1 << (at % 8);
        assert_workers_match_serial(&damaged, data.len());
    }
}

#[test]
fn workers_continue_a_solid_member_as_the_serial_decoder_does() {
    let first = prose(9_000, 19);
    let second = [&first[4_000..], &prose(5_000, 23)[..]].concat();
    let streams = [lz_stream(&first, &[], 800), lz_stream(&second, &first, 800)];
    let mut serial = decoder(None);
    let expected = [
        decode(&mut serial, &streams[0], first.len(), false),
        decode(&mut serial, &streams[1], second.len(), true),
    ];
    assert_eq!(expected[1].error, None);
    assert_eq!(expected[1].bytes(), second);
    for workers in [1, 4] {
        let mut ahead = decoder(Some(workers));
        assert_eq!(
            decode(&mut ahead, &streams[0], first.len(), false),
            expected[0]
        );
        assert_eq!(
            decode(&mut ahead, &streams[1], second.len(), true),
            expected[1]
        );
    }
}

#[test]
fn workers_apply_filters_as_the_serial_decoder_does() {
    let mut data = prose(40_000, 29);
    for at in (0..data.len() - 5).step_by(97) {
        data[at] = 0xe8;
    }
    let filters = [
        FilterSpec::range(FilterKind::E8, 0..20_000),
        FilterSpec::range(FilterKind::Delta { channels: 3 }, 20_000..40_000),
    ];
    let stream = Unpack50Encoder::new()
        .encode_member_with_filters(&data, 0, &filters)
        .unwrap();
    let serial = assert_workers_match_serial(&stream, data.len());
    assert_eq!(serial.error, None);
    assert_eq!(serial.bytes(), data);
}

#[test]
fn workers_reuse_tables_across_blocks_as_the_serial_decoder_does() {
    let (mut first, table_bits) = ab_tables();
    let pad = first.len() * 8 - table_bits;
    first.push(0b0110_1001);
    let mut stream = encode_compressed_block(&first, first.len() * 8, true, false).unwrap();
    let mut expected = ab_text(&first[first.len() - 2..])[8 - pad..].to_vec();
    for block in 0..400u32 {
        let packed: Vec<u8> = (0..7).map(|n| (block * 31 + n * 7) as u8).collect();
        if block % 10 == 0 {
            stream.extend(encode_compressed_block(&[], 0, false, false).unwrap());
        }
        stream.extend(encode_compressed_block(&packed, 56, false, block == 399).unwrap());
        expected.extend(ab_text(&packed));
    }
    let serial = assert_workers_match_serial(&stream, expected.len());
    assert_eq!(serial.error, None);
    assert_eq!(serial.bytes(), expected);

    let solid: Vec<u8> = (0..300u32)
        .flat_map(|block| {
            encode_compressed_block(&[block as u8; 5], 40, false, block == 299).unwrap()
        })
        .collect();
    let mut serial_state = decoder(None);
    decode(&mut serial_state, &stream, expected.len(), false);
    let inherited = decode(&mut serial_state, &solid, 300 * 40, true);
    assert_eq!(inherited.error, None);
    for workers in [1, 4] {
        let mut ahead = decoder(Some(workers));
        decode(&mut ahead, &stream, expected.len(), false);
        assert_eq!(decode(&mut ahead, &solid, 300 * 40, true), inherited);
    }

    let empty = encode_compressed_block(&[], 0, false, false)
        .unwrap()
        .repeat(5_000);
    assert_workers_match_serial(&empty, 8);
    let orphan = encode_compressed_block(&[0x5a; 7], 56, false, true).unwrap();
    let serial = assert_workers_match_serial(&orphan, 56);
    assert_eq!(
        serial.error.as_deref(),
        Some("Decode(InvalidData(\"RAR 5 block reuses missing tables\"))")
    );
}

#[test]
fn workers_report_an_unset_repeat_distance_before_its_truncated_length() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[258] = 1;
    lengths.length[0] = 1;
    lengths.length[1] = 1;
    let (mut payload, table_bits) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    // Zero bits are literals; they put the repeat symbol on a byte's last bit.
    let repeat_bit = table_bits | 7;
    payload.resize(repeat_bit / 8 + 1, 0);
    payload[repeat_bit / 8] |= 1;
    let stream = encode_compressed_block(&payload, repeat_bit + 1, true, true).unwrap();
    let serial = assert_workers_match_serial(&stream, 10);
    assert_eq!(
        serial.error.as_deref(),
        Some("Decode(InvalidData(\"RAR 5 repeat distance is not initialized\"))")
    );
}

#[test]
fn workers_stop_at_a_sink_failure_as_the_serial_decoder_does() {
    let data = prose(200_000, 31);
    let stream = lz_stream(&data, &[], 20_000);
    let fail = |chunk| if chunk == 1 { Err("sink") } else { Ok(()) };
    let serial = decode_with(&mut decoder(None), &stream, data.len(), false, fail);
    assert_eq!(serial.error.as_deref(), Some("Sink(\"sink\")"));
    assert_eq!(serial.chunks.len(), 1);
    for workers in [1, 4] {
        let ahead = decode_with(
            &mut decoder(Some(workers)),
            &stream,
            data.len(),
            false,
            fail,
        );
        assert_eq!(ahead, serial, "workers={workers}");
    }
}

#[test]
fn workers_observe_cancellation_between_chunks() {
    let data = prose(200_000, 37);
    let stream = lz_stream(&data, &[], 20_000);
    let token = crate::ReadCancellation::new();
    let mut state = ReaderState::new(&Allowance::default());
    state.read_control = ReadControl::for_options(
        &ArchiveReadOptions::new()
            .with_cancellation(&token)
            .with_rar50_decode_workers(2),
    );
    let run = decode_with(&mut state, &stream, data.len(), false, |_| {
        token.cancel();
        Ok(())
    });
    assert_eq!(run.error.as_deref(), Some("Decode(Cancelled)"));
    assert_eq!(run.chunks.len(), 1);
}

#[test]
fn workers_hand_filters_to_a_recorder_as_the_serial_decoder_does() {
    let mut data = prose(40_000, 41);
    for at in (0..data.len() - 5).step_by(89) {
        data[at] = 0xe8;
    }
    let filters = [
        FilterSpec::range(FilterKind::E8, 0..15_000),
        FilterSpec::range(FilterKind::Delta { channels: 2 }, 15_000..40_000),
    ];
    let stream = Unpack50Encoder::new()
        .encode_member_with_filters(&data, 0, &filters)
        .unwrap();
    let record = |workers| {
        let mut bytes = Vec::new();
        let mut recorded = Vec::new();
        let result = decoder(workers).decode_to_sink_with_filters(
            &mut stream.as_slice(),
            0,
            data.len(),
            DICTIONARY,
            false,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(chunk) => bytes.extend_from_slice(chunk),
                    DecodedChunk::Repeated { byte, len } => bytes.resize(bytes.len() + len, byte),
                }
                Ok::<(), &'static str>(())
            },
            Some(&mut |filter| {
                recorded.push(filter);
                Ok(())
            }),
        );
        (bytes, recorded, result.is_ok())
    };
    let serial = record(None);
    assert!(serial.2);
    assert_eq!(serial.1.len(), 2);
    for workers in [1, 4] {
        assert_eq!(record(Some(workers)), serial, "workers={workers}");
    }
}

#[test]
fn concurrent_members_share_the_workers_and_decode_as_the_serial_decoder_does() {
    let members: Vec<(Vec<u8>, Vec<u8>)> = (0..4)
        .map(|seed| {
            let data = prose(40_000, seed);
            let stream = lz_stream(&data, &[], 1_000);
            (data, stream)
        })
        .collect();
    std::thread::scope(|scope| {
        for (data, stream) in &members {
            scope.spawn(move || {
                for workers in [2, 2, 3] {
                    let run = decode(&mut decoder(Some(workers)), stream, data.len(), false);
                    assert_eq!(run.error, None);
                    assert_eq!(run.bytes(), *data);
                }
            });
        }
    });
}
