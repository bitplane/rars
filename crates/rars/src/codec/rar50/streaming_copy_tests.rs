use super::*;
use std::convert::Infallible;

fn append_chunk(decoded: &mut Vec<u8>, chunk: DecodedChunk<'_>) {
    match chunk {
        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
        DecodedChunk::Repeated { byte, len } => decoded.resize(decoded.len() + len, byte),
    }
}

fn reference_match(history: &[u8], pending: &[u8], distance: usize, length: usize) -> Vec<u8> {
    let mut bytes = [history, pending].concat();
    let missing = distance == 0 || distance > bytes.len();
    for _ in 0..length {
        let byte = if missing {
            0
        } else {
            bytes[bytes.len() - distance]
        };
        bytes.push(byte);
    }
    bytes[history.len()..].to_vec()
}

#[test]
fn buffered_matches_equal_scalar_with_history_pending_overlap_and_missing_history() {
    for history_len in 0..=6 {
        let history: Vec<_> = (0..history_len).map(|n| n as u8 + 11).collect();
        let decoder = ReaderState::with_history(Buffer::from_vec(history.clone()));
        for pending_len in 0..=6 {
            let pending: Vec<_> = (0..pending_len).map(|n| n as u8 + 31).collect();
            for distance in 0..=history_len + pending_len + 2 {
                for length in [0, 1, 2, 3, 7, 32, 129] {
                    let mut output = Buffer::from_vec(pending.clone());
                    decoder
                        .copy_match(&mut output, distance, length, pending_len + length, 32)
                        .unwrap();
                    assert_eq!(
                        &*output,
                        reference_match(&history, &pending, distance, length),
                        "history={history_len}, pending={pending_len}, distance={distance}, length={length}"
                    );
                }
            }
        }
    }
}

#[test]
fn buffered_overlap_preserves_output_limit_and_workspace_refusal() {
    let budget = Allowance::limited(128);
    let decoder = ReaderState::new(&budget);
    let mut output = Buffer::with_capacity(128, &budget).unwrap();
    output.extend_from_slice(b"ab").unwrap();
    decoder.copy_match(&mut output, 2, 126, 128, 128).unwrap();
    assert_eq!(&*output, b"ab".repeat(64));
    assert_eq!(budget.used(), 128);
    assert!(matches!(
        decoder.copy_match(&mut output, 2, 1, 128, 128),
        Err(Error::InvalidData("RAR 5 match exceeds output limit"))
    ));
    assert!(matches!(
        decoder.copy_match(&mut output, 2, 1, 129, 128),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(&*output, b"ab".repeat(64));
    assert_eq!(budget.used(), 128);
    drop(output);
    drop(decoder);
    assert_eq!(budget.used(), 0);
}

#[test]
fn streaming_matches_equal_scalar_with_history_pending_overlap_and_missing_history() {
    for history_len in 0..=6 {
        let history: Vec<_> = (0..history_len).map(|n| n as u8 + 11).collect();
        for pending_len in 0..=6 {
            let pending: Vec<_> = (0..pending_len).map(|n| n as u8 + 31).collect();
            for distance in 1..=history_len + pending_len + 2 {
                for length in [0, 1, 2, 3, 7, 32, 129] {
                    let mut output = StreamingOutput::new(
                        Buffer::from_vec(history.clone()),
                        pending_len + length,
                        32,
                        32,
                    )
                    .unwrap();
                    let mut decoded = Vec::new();
                    let mut sink = |chunk: DecodedChunk<'_>| {
                        append_chunk(&mut decoded, chunk);
                        Ok::<(), Infallible>(())
                    };
                    for &byte in &pending {
                        output.push(byte, &mut sink).unwrap();
                    }
                    output.copy_match(distance, length, &mut sink).unwrap();
                    output.finish(&mut sink).unwrap();
                    assert_eq!(
                        decoded,
                        reference_match(&history, &pending, distance, length),
                        "history={history_len}, pending={pending_len}, distance={distance}, length={length}"
                    );
                }
            }
        }
    }
}

#[test]
fn streaming_match_crosses_both_wrapped_history_slices_and_multiple_flushes() {
    let count = 2 * STREAM_FLUSH_THRESHOLD + 37;
    let mut ring: Vec<u8> = (31..39).collect();
    ring.extend([0, 0, 0, 0, 9, 10, 11, 12]);
    let ring = StreamedHistory {
        bytes: Buffer::from_vec(ring),
        end: 8,
        len: 12,
    };
    assert!(!ring.as_slices().1.is_empty());
    let history = ring.to_vec();
    let mut output = StreamingOutput::new(ring, count + 3, 16, 16).unwrap();
    let pending = [91, 92, 93];
    let mut decoded = Vec::new();
    let mut chunks = Vec::new();
    let mut sink = |chunk: DecodedChunk<'_>| {
        chunks.push(match chunk {
            DecodedChunk::Bytes(bytes) => bytes.len(),
            DecodedChunk::Repeated { len, .. } => len,
        });
        append_chunk(&mut decoded, chunk);
        Ok::<(), Infallible>(())
    };
    for byte in pending {
        output.push(byte, &mut sink).unwrap();
    }
    output.copy_match(12, count, &mut sink).unwrap();
    output.finish(&mut sink).unwrap();
    assert_eq!(decoded, reference_match(&history, &pending, 12, count));
    assert!(chunks.len() >= 3);
    assert!(chunks.iter().all(|&len| len <= STREAM_FLUSH_THRESHOLD));
    assert_eq!(output.written(), decoded.len());
    assert_eq!(
        output.into_history().to_vec(),
        decoded[decoded.len() - 16..]
    );
}

#[test]
fn streaming_match_stops_on_the_first_failed_flush() {
    let mut output = StreamingOutput::new(
        Buffer::from_vec(b"abc".to_vec()),
        STREAM_FLUSH_THRESHOLD + 7,
        3,
        3,
    )
    .unwrap();
    let mut calls = 0;
    assert!(matches!(
        output.copy_match(3, STREAM_FLUSH_THRESHOLD + 7, &mut |_chunk| {
            calls += 1;
            Err("failed sink")
        }),
        Err(StreamDecodeError::Sink("failed sink"))
    ));
    assert_eq!(calls, 1);
    assert_eq!(output.written(), STREAM_FLUSH_THRESHOLD);
    assert_eq!(output.pending, STREAM_FLUSH_THRESHOLD);
    assert_eq!(output.ring.len, 3 + STREAM_FLUSH_THRESHOLD);
}

#[test]
fn streaming_match_uses_only_its_admitted_pending_and_history_storage() {
    // Growing the ring holds the old window and the new ring at once.
    let budget = Allowance::limited((STREAM_SLACK + 32) as u64);
    let mut history = Buffer::with_capacity(16, &budget).unwrap();
    history.extend_from_slice(b"abcdefghijklmnop").unwrap();
    let count = 2 * STREAM_FLUSH_THRESHOLD + 5;
    let mut output = StreamingOutput::new(history, count, 16, 16).unwrap();
    let mut observed = 0;
    let mut sink = |chunk: DecodedChunk<'_>| {
        observed += match chunk {
            DecodedChunk::Bytes(bytes) => bytes.len(),
            DecodedChunk::Repeated { len, .. } => len,
        };
        Ok::<(), Infallible>(())
    };
    output.copy_match(7, count, &mut sink).unwrap();
    output.finish(&mut sink).unwrap();
    assert_eq!(observed, count);
    assert_eq!(budget.used(), (STREAM_SLACK + 16) as u64);
    drop(output);
    assert_eq!(budget.used(), 0);
}

#[cfg(feature = "write")]
#[test]
fn streaming_match_flush_preserves_decoder_cancellation() {
    let data: Vec<_> = b"abc"
        .iter()
        .copied()
        .cycle()
        .take(3 * STREAM_FLUSH_THRESHOLD)
        .collect();
    let input = Unpack50Encoder::new().encode_member(&data, 0).unwrap();
    let token = crate::ReadCancellation::new();
    let mut decoder = Unpack50Decoder::new();
    decoder.read_control = crate::read_control::ReadControl::new(Some(&token));
    let mut calls = 0;
    let result = decoder.decode_member_from_reader_with_dictionary_to_sink(
        &mut input.as_slice(),
        0,
        data.len(),
        DEFAULT_DICTIONARY_SIZE,
        false,
        |_chunk| {
            calls += 1;
            token.cancel();
            Ok::<(), Infallible>(())
        },
    );
    assert!(matches!(
        result,
        Err(StreamDecodeError::Decode(Error::Cancelled))
    ));
    assert_eq!(calls, 1);
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }
}

fn stream_against_model(
    rng: &mut Rng,
    model: &mut Vec<u8>,
    history: StreamedHistory,
    output_size: usize,
    dictionary: usize,
) -> StreamedHistory {
    let start = model.len();
    let mut output = StreamingOutput::new(history, output_size, dictionary, dictionary).unwrap();
    let mut decoded = Vec::new();
    let mut sink = |chunk: DecodedChunk<'_>| {
        append_chunk(&mut decoded, chunk);
        Ok::<(), Infallible>(())
    };
    while output.written() < output_size {
        let left = output_size - output.written();
        let reach = model.len().min(dictionary);
        if reach == 0 || rng.below(3) == 0 {
            let byte = rng.below(4) as u8 + b'a';
            output.push(byte, &mut sink).unwrap();
            model.push(byte);
            let room = output.literal_room().min(rng.below(64));
            let literals: Vec<u8> = (0..room).map(|_| rng.below(256) as u8).collect();
            output.push_literals(&literals, &mut sink).unwrap();
            model.extend_from_slice(&literals);
            continue;
        }
        let distance = match rng.below(4) {
            0 => 1 + rng.below(reach.min(4)),
            1 => 1 + rng.below(reach.min(40)),
            _ => 1 + rng.below(reach),
        };
        let length = match rng.below(8) {
            0 => 1 + rng.below(3 * STREAM_FLUSH_THRESHOLD),
            1..=3 => 2 + rng.below(31),
            _ => 2 + rng.below(300),
        }
        .min(left);
        output.copy_match(distance, length, &mut sink).unwrap();
        for _ in 0..length {
            model.push(model[model.len() - distance]);
        }
    }
    output.finish(&mut sink).unwrap();
    assert_eq!(decoded, model[start..]);
    output.into_history()
}

#[test]
fn streamed_output_matches_byte_model_across_wraps_growth_and_chained_members() {
    for (seed, dictionary) in [(1, 64), (2, 4096), (3, 1 << 20), (4, 100_003)] {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
        let mut model = Vec::new();
        let mut history = StreamedHistory::from(Buffer::new(&Allowance::default()));
        for size in [1, 300_000, 17, 250_000] {
            history = stream_against_model(&mut rng, &mut model, history, size, dictionary);
            let kept = model.len().min(dictionary);
            assert_eq!(
                history.to_vec(),
                model[model.len() - kept..],
                "seed={seed}, dictionary={dictionary}"
            );
        }
    }
}
