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
    let mut history = Buffer::with_capacity(16, &Allowance::default()).unwrap();
    history
        .extend_from_slice(&(1..=12).collect::<Vec<u8>>())
        .unwrap();
    let mut output = StreamingOutput::new(history, count + 3, 16, 16).unwrap();
    output.history.discard_prefix(8);
    output.history.extend_admitted(31..39);
    assert!(!output.history.as_slices().1.is_empty());
    let history: Vec<_> = output.history.iter().copied().collect();
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
    assert_eq!(chunks, [STREAM_FLUSH_THRESHOLD, STREAM_FLUSH_THRESHOLD, 40]);
    assert_eq!(output.written(), decoded.len());
    assert_eq!(
        output.into_history().into_vec(),
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
    assert_eq!(output.pending.len(), STREAM_FLUSH_THRESHOLD);
    assert_eq!(
        &*output.history,
        &std::collections::VecDeque::from(b"abc".to_vec())
    );
}

#[test]
fn streaming_match_uses_only_its_admitted_pending_and_history_storage() {
    let budget = Allowance::limited((STREAM_FLUSH_THRESHOLD + 16) as u64);
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
    assert_eq!(budget.used(), (STREAM_FLUSH_THRESHOLD + 16) as u64);
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
