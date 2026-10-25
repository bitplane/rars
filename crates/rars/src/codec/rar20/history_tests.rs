use super::*;
use crate::codec::workspace::RefusingBudget;

// Original eager policy, independent of the new batching helpers.
fn eager<B: Budget>(state: &mut Reader20State<B>) {
    let drain = state.output.len().saturating_sub(MAX_HISTORY);
    state.output.discard_prefix(drain);
    state.base_offset += drain;
}

fn assert_window<B: Budget>(actual: &Reader20State<B>, expected: &Reader20State<B>) {
    let end = expected.current_pos();
    let start = end.saturating_sub(MAX_HISTORY);
    assert_eq!(actual.current_pos(), end);
    assert_eq!(actual.raw_range(start, end), expected.raw_range(start, end));
    assert_eq!(actual.pending_match, expected.pending_match);
    assert!(actual.output.len() - (end - start) < HISTORY_TRIM_BATCH);
}

fn seeded<B: Budget>(budget: &B) -> Reader20State<B> {
    let mut state = Reader20State::with_allowance(budget);
    let seed: Vec<_> = (0..MAX_HISTORY).map(|i| ((i >> 8) ^ i) as u8).collect();
    state
        .output
        .extend_from_slice(&seed)
        .map_err(Into::<Error>::into)
        .unwrap();
    state
}

#[test]
fn small_members_batch_moves_without_growing_the_buffer() {
    let mut actual = seeded(&Allowance::default());
    let mut expected = actual.try_clone().unwrap();
    let mut moves = 0;
    for _ in 0..512 {
        let before = actual.base_offset;
        actual.prepare_history(1024);
        let start = actual.current_pos();
        for state in [&mut actual, &mut expected] {
            // A full-distance copy must work even while obsolete bytes remain.
            state.copy_match(1024, MAX_HISTORY, start + 1024).unwrap();
        }
        assert_eq!(
            actual.raw_range(start, start + 1024),
            expected.raw_range(start, start + 1024)
        );
        actual.finish_history();
        eager(&mut expected);
        moves += usize::from(actual.base_offset != before);
        assert_window(&actual, &expected);
        assert_eq!(actual.output.capacity(), expected.output.capacity());
    }
    assert_eq!(moves, 512 * 1024 / HISTORY_TRIM_BATCH);
}

#[test]
fn trim_and_spare_capacity_boundaries_preserve_absolute_positions() {
    let mut state = seeded(&Allowance::default());
    state
        .output
        .resize(MAX_HISTORY + HISTORY_TRIM_BATCH - 1, 7)
        .unwrap();
    let current = state.current_pos();
    state.finish_history();
    assert_eq!(state.base_offset, 0);
    let spare = state.output.capacity() - state.output.len();
    state.prepare_history(spare);
    assert_eq!(state.base_offset, 0, "an exact fit must not compact");
    state.prepare_history(spare + 1);
    assert_eq!(state.current_pos(), current);
    assert_eq!(state.output.len(), MAX_HISTORY);
    state
        .output
        .resize(MAX_HISTORY + HISTORY_TRIM_BATCH, 9)
        .unwrap();
    let current = state.current_pos();
    state.finish_history();
    assert_eq!(state.current_pos(), current);
    assert_eq!(state.output.len(), MAX_HISTORY);
}

#[test]
fn pending_matches_and_irregular_members_agree_with_eager_history() {
    fn check<B: Budget>(budget: &B) {
        let mut actual = seeded(budget);
        let mut expected = actual.try_clone().unwrap();
        for size in [
            0,
            1,
            4093,
            HISTORY_TRIM_BATCH - 1,
            HISTORY_TRIM_BATCH,
            MAX_HISTORY + 17,
        ] {
            actual.prepare_history(size);
            let begin = actual.current_pos();
            let data: Vec<_> = (begin..begin + size)
                .map(|i| ((i >> 7) ^ i) as u8)
                .collect();
            for state in [&mut actual, &mut expected] {
                state
                    .output
                    .extend_from_slice(&data)
                    .map_err(Into::<Error>::into)
                    .unwrap();
            }
            actual.finish_history();
            eager(&mut expected);
            assert_window(&actual, &expected);
            assert_eq!(actual.output.capacity(), expected.output.capacity());
            for distance in [0, 1, 3, MAX_HISTORY] {
                let mut actual = actual.try_clone().unwrap();
                let mut expected = expected.try_clone().unwrap();
                let begin = actual.current_pos();
                actual.prepare_history(67);
                for state in [&mut actual, &mut expected] {
                    state.copy_match(260, distance, begin + 67).unwrap();
                }
                actual.finish_history();
                eager(&mut expected);
                assert_window(&actual, &expected);
                let mut actual = actual.try_clone().unwrap();
                actual.prepare_history(193);
                actual.drain_pending_match(begin + 260).unwrap();
                expected.drain_pending_match(begin + 260).unwrap();
                actual.finish_history();
                eager(&mut expected);
                assert_window(&actual, &expected);
                assert!(actual.pending_match.is_none());
                let start = actual.current_pos();
                actual.prepare_history(23);
                for state in [&mut actual, &mut expected] {
                    state.copy_match(23, distance, start + 23).unwrap();
                }
                actual.finish_history();
                eager(&mut expected);
                assert_window(&actual, &expected);
            }
        }
    }
    check(&Allowance::default());
    let budget = Allowance::limited(32 * MAX_HISTORY as u64);
    check(&budget);
    assert_eq!(budget.used(), 0);
}

#[test]
fn checkpoints_drop_obsolete_bytes_before_restoration_and_growth() {
    let mut state = seeded(&Allowance::default());
    state
        .output
        .resize(MAX_HISTORY + HISTORY_TRIM_BATCH - 1, 7)
        .unwrap();
    state.finish_history();
    let original_position = state.current_pos();
    let original_len = state.output.len();
    let original_base = state.base_offset;
    let mut restored = state.try_clone().unwrap();
    assert_eq!(state.output.len(), original_len);
    assert_eq!(state.base_offset, original_base);
    assert_eq!(restored.current_pos(), original_position);
    assert_eq!(restored.output.len(), MAX_HISTORY);
    assert!(restored.output.capacity() <= state.output.capacity());
    let mut expected = state;
    eager(&mut expected);
    let mut expected = expected.try_clone().unwrap();
    assert_window(&restored, &expected);
    for size in [
        HISTORY_TRIM_BATCH + 1,
        MAX_HISTORY + 17,
        2 * MAX_HISTORY + 129,
        4093,
    ] {
        restored.prepare_history(size);
        for state in [&mut restored, &mut expected] {
            state.output.resize(state.output.len() + size, 9).unwrap();
        }
        restored.finish_history();
        eager(&mut expected);
        assert_window(&restored, &expected);
        assert_eq!(restored.output.capacity(), expected.output.capacity());
    }
}

#[derive(Debug, PartialEq)]
struct Outcome {
    result: Result<()>,
    output: Vec<u8>,
    capacity: usize,
    base_offset: usize,
}

fn bounded_run<B: Budget>(old: bool, budget: &B) -> Outcome {
    let mut state = Reader20State::with_allowance(budget);
    let result = (|| {
        state.output.resize(MAX_HISTORY, 1)?;
        for size in [1024, HISTORY_TRIM_BATCH - 1, HISTORY_TRIM_BATCH + 1] {
            if !old {
                state.prepare_history(size);
            }
            for _ in 0..size {
                state.output.try_push(3)?;
            }
            if old {
                eager(&mut state);
            } else {
                state.finish_history();
            }
            let _copy = state.try_clone()?;
        }
        Ok(())
    })();
    Outcome {
        result,
        output: state.output.to_vec(),
        capacity: state.output.capacity(),
        base_offset: state.base_offset,
    }
}

#[test]
fn bounded_growth_refusals_and_failure_prefixes_are_unchanged() {
    for limit in [
        0,
        MAX_HISTORY - 1,
        MAX_HISTORY,
        2 * MAX_HISTORY - 1,
        2 * MAX_HISTORY,
        3 * MAX_HISTORY - 1,
        3 * MAX_HISTORY,
        6 * MAX_HISTORY,
    ] {
        let budget = Allowance::limited(limit as u64);
        let expected = bounded_run(true, &budget);
        assert_eq!(budget.used(), 0);
        assert_eq!(bounded_run(false, &budget), expected, "limit={limit}");
        assert_eq!(budget.used(), 0);
    }
    let baseline = RefusingBudget::new(usize::MAX);
    assert!(bounded_run(true, &baseline).result.is_ok());
    assert_eq!(baseline.used(), 0);
    for failure in 0..=baseline.attempts() {
        let old = RefusingBudget::new(failure);
        let new = RefusingBudget::new(failure);
        assert_eq!(
            bounded_run(false, &new),
            bounded_run(true, &old),
            "failure={failure}"
        );
        assert_eq!(new.attempts(), old.attempts());
        assert_eq!(new.used(), 0);
        assert_eq!(old.used(), 0);
    }
}

#[cfg(feature = "write")]
#[test]
fn solid_members_survive_deferred_history_checkpoints_and_sink_failure() {
    struct Fail;
    impl Write for Fail {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink refused"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut encoder = Unpack20Encoder::with_options(EncodeOptions::new(16).with_try_audio(false));
    let frames: Vec<_> = [
        MAX_HISTORY + 17,
        1024,
        4093,
        HISTORY_TRIM_BATCH + 1,
        2 * MAX_HISTORY + 31,
        2 * MAX_HISTORY + 7,
        4093,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, size)| {
        let data: Vec<_> = (0..size).map(|i| ((i + index * 13) % 251) as u8).collect();
        let packed = encoder.encode_member(&data).unwrap();
        (data, packed)
    })
    .collect();
    fn check<B: Budget>(frames: &[(Vec<u8>, Vec<u8>)], budget: &B) {
        for streaming in [false, true] {
            let mut actual = Reader20State::with_allowance(budget);
            let mut expected = Reader20State::with_allowance(budget);
            for (index, (data, packed)) in frames.iter().enumerate() {
                for state in [&mut actual, &mut expected] {
                    if streaming && index == 4 {
                        let before = state.current_pos();
                        assert!(state
                            .decode_member_from_reader(
                                &mut packed.as_slice(),
                                data.len(),
                                &mut Fail
                            )
                            .is_err());
                        assert_eq!(state.current_pos(), before + data.len());
                    } else if streaming {
                        let mut out = Vec::new();
                        state
                            .decode_member_from_reader(&mut packed.as_slice(), data.len(), &mut out)
                            .unwrap();
                        assert_eq!(&out, data);
                    } else {
                        assert_eq!(
                            &*state.decode_member_owned(packed, data.len()).unwrap(),
                            data
                        );
                    }
                }
                if streaming && index == 4 {
                    actual = actual.try_clone().unwrap();
                    if !B::LIMITED {
                        assert_eq!(actual.output.len(), MAX_HISTORY);
                    }
                    continue;
                }
                eager(&mut expected);
                assert_window(&actual, &expected);
                if index == 2 {
                    actual = actual.try_clone().unwrap();
                    expected = expected.try_clone().unwrap();
                }
            }
        }
    }
    check(&frames, &Allowance::default());
    let budget = Allowance::limited(64 * MAX_HISTORY as u64);
    check(&frames, &budget);
    assert_eq!(budget.used(), 0);
}

#[cfg(feature = "write")]
#[test]
fn a_clone_after_cancellation_keeps_the_required_history_and_bit_position() {
    let data: Vec<_> = (0..2 * MAX_HISTORY + 127)
        .map(|i| (i % 251) as u8)
        .collect();
    let packed = Unpack20Encoder::with_options(EncodeOptions::new(16).with_try_audio(false))
        .encode_member(&data)
        .unwrap();
    let token = crate::ReadCancellation::new();
    let mut original = Reader20State::with_allowance(&Allowance::default());
    original.read_control = crate::read_control::ReadControl::new(Some(&token));
    original.read_control.cancel_after_checks(24);
    assert_eq!(
        original
            .decode_member_owned(&packed, data.len())
            .unwrap_err(),
        Error::Cancelled
    );
    let stopped = original.current_pos();
    assert!(stopped > MAX_HISTORY + HISTORY_TRIM_BATCH && stopped < data.len());
    let mut checkpoint = original.try_clone().unwrap();
    assert_eq!(checkpoint.current_pos(), stopped);
    assert_eq!(checkpoint.output.len(), MAX_HISTORY);
    assert!(original.output.len() > MAX_HISTORY + HISTORY_TRIM_BATCH);
    // Exercise the private codec state with a fresh control; this is not a
    // promise that archive extraction can resume after cancellation.
    for state in [&mut original, &mut checkpoint] {
        state.read_control = crate::read_control::ReadControl::default();
        let remaining = state
            .decode_member_owned(&[], data.len() - stopped)
            .unwrap();
        assert_eq!(&*remaining, &data[stopped..]);
    }
}
