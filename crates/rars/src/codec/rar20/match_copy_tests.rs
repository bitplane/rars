use super::*;
use crate::codec::workspace::Allowance;

// Original byte loop: an independent oracle for output and failure state.
fn scalar_copy(
    state: &mut Reader20State,
    length: usize,
    offset: usize,
    target: usize,
    zero: bool,
) -> Result<()> {
    for index in 0..length {
        if state.current_pos() >= target {
            state.pending_match = Some((length - index, offset, zero));
            break;
        }
        let byte = if zero {
            0
        } else {
            state.raw_byte(state.current_pos() - offset)
        };
        state.output.try_push(byte)?;
    }
    Ok(())
}
fn start(
    old: bool,
    state: &mut Reader20State,
    length: usize,
    offset: usize,
    target: usize,
) -> Result<()> {
    if old {
        let offset = offset.max(1);
        scalar_copy(state, length, offset, target, offset > state.current_pos())
    } else {
        state.copy_match(length, offset, target)
    }
}
fn drain(old: bool, state: &mut Reader20State, target: usize) -> Result<()> {
    if old {
        if let Some((length, offset, zero)) = state.pending_match.take() {
            scalar_copy(state, length, offset, target, zero)?;
        }
        Ok(())
    } else {
        state.drain_pending_match(target)
    }
}
fn assert_same(actual: &Reader20State, expected: &Reader20State) {
    assert_eq!(actual.output, expected.output);
    assert_eq!(actual.pending_match, expected.pending_match);
    assert_eq!(actual.base_offset, expected.base_offset);
}

#[test]
fn match_lengths_distances_and_checkpoints_agree_with_scalar_copy() {
    fn check(budget: &Allowance) {
        let seed: Vec<_> = (0..256).map(|i| (i % 23) as u8).collect();
        for base in [0, MAX_HISTORY] {
            for length in [0, 1, 2, 8, 9, 63, 64, 65, 128, 255, 258, 259, 260] {
                for offset in [0, 1, 2, 3, 31, 128, 256, 257] {
                    if base != 0 && offset > seed.len() {
                        continue;
                    }
                    for chunk in [0, 1, 63, 64, 65, 260] {
                        let mut expected = Reader20State::with_allowance(budget);
                        expected.base_offset = base;
                        expected.output.extend_from_slice(&seed).unwrap();
                        let mut actual = expected.try_clone().unwrap();
                        let end = actual.current_pos() + length;
                        let target = if chunk == 0 {
                            actual.current_pos() - 1
                        } else {
                            (actual.current_pos() + chunk).min(end)
                        };
                        start(true, &mut expected, length, offset, target).unwrap();
                        start(false, &mut actual, length, offset, target).unwrap();
                        assert_same(&actual, &expected);
                        // Cloning and draining without progress must retain the
                        // original zero-fill decision, even after crossing it.
                        let mut expected = expected.try_clone().unwrap();
                        let mut actual = actual.try_clone().unwrap();
                        drain(true, &mut expected, target).unwrap();
                        drain(false, &mut actual, target).unwrap();
                        assert_same(&actual, &expected);
                        while expected.pending_match.is_some() {
                            let next = (expected.current_pos() + chunk.max(1)).min(end);
                            drain(true, &mut expected, next).unwrap();
                            drain(false, &mut actual, next).unwrap();
                            assert_same(&actual, &expected);
                        }
                    }
                }
            }
        }
    }
    check(&Allowance::default());
    let budget = Allowance::limited(1024 * 1024);
    check(&budget);
    assert_eq!(budget.used(), 0);
}

#[test]
fn pending_long_matches_survive_history_trimming() {
    fn check(budget: &Allowance) {
        let seed: Vec<_> = (0..MAX_HISTORY + 127).map(|i| (i % 23) as u8).collect();
        for offset in [1, 3, 64, MAX_HISTORY] {
            let mut expected = Reader20State::with_allowance(budget);
            expected.output.extend_from_slice(&seed).unwrap();
            // Start with identical physical histories: unlimited checkpoints
            // may omit obsolete bytes before the forced trim exercised here.
            let mut actual = Reader20State::with_allowance(budget);
            actual.output.extend_from_slice(&seed).unwrap();
            let begin = actual.current_pos();
            start(true, &mut expected, 260, offset, begin + 67).unwrap();
            start(false, &mut actual, 260, offset, begin + 67).unwrap();
            assert_same(&actual, &expected);
            for state in [&mut actual, &mut expected] {
                let current = state.current_pos();
                state.trim_history(current, current);
                assert!(state.base_offset > 0);
                assert_eq!(state.output.len(), MAX_HISTORY);
            }
            drain(true, &mut expected, begin + 260).unwrap();
            drain(false, &mut actual, begin + 260).unwrap();
            assert_same(&actual, &expected);
            assert!(actual.pending_match.is_none());
        }
    }
    check(&Allowance::default());
    let budget = Allowance::limited(16 * 1024 * 1024);
    check(&budget);
    assert_eq!(budget.used(), 0);
}

struct Outcome {
    result: Result<()>,
    output: Vec<u8>,
}
fn limited_run(old: bool, budget: &Allowance, offset: usize) -> Outcome {
    let mut state = Reader20State::with_allowance(budget);
    let result = (|| {
        state.output.extend_from_slice(b"ABC")?;
        start(old, &mut state, 260, offset, 73)?;
        drain(old, &mut state, 263)
    })();
    Outcome {
        result,
        output: state.output.to_vec(),
    }
}

#[test]
fn refusals_during_a_long_match_leave_a_prefix_and_release_everything() {
    for offset in [0, 1, 3, 4] {
        let full = limited_run(true, &Allowance::default(), offset);
        assert!(full.result.is_ok());
        let check = |actual: Outcome, at: &str| {
            if actual.result.is_ok() {
                assert_eq!(actual.output, full.output, "{at}, offset={offset}");
            } else {
                assert!(
                    full.output.starts_with(&actual.output),
                    "{at}, offset={offset}"
                );
            }
        };
        for limit in 0..=800 {
            let budget = Allowance::limited(limit);
            check(
                limited_run(false, &budget, offset),
                &format!("limit={limit}"),
            );
            assert_eq!(budget.used(), 0);
        }
        let baseline = Allowance::refusing(usize::MAX);
        assert!(limited_run(false, &baseline, offset).result.is_ok());
        for failure in 0..=baseline.attempts() {
            let budget = Allowance::refusing(failure);
            check(
                limited_run(false, &budget, offset),
                &format!("failure={failure}"),
            );
            assert_eq!(budget.used(), 0);
        }
    }
}

#[cfg(feature = "write")]
#[test]
fn encoded_long_matches_preserve_member_splits_and_streaming_solid_history() {
    fn check(budget: &Allowance, data: &[u8], packed: &[u8], next: &[u8], packed_next: &[u8]) {
        // A declared size inside the match truncates the output; the window
        // keeps the rest of that match.
        let mut decoder = Reader20State::with_allowance(budget);
        let first = decoder.decode_member_owned(packed, 100).unwrap();
        assert_eq!(&*first, &data[..100]);
        assert!(decoder.pending_match.is_none());
        let window = decoder.raw_range(0, decoder.current_pos());
        assert!(window.len() > 100 && data.starts_with(window));

        let mut decoder = Reader20State::with_allowance(budget);
        let mut checkpoint = decoder.try_clone().unwrap();
        for state in [&mut decoder, &mut checkpoint] {
            let whole = state.decode_member_owned(packed, data.len()).unwrap();
            assert_eq!(&*whole, data);
            let mut out = Vec::new();
            let mut input = packed_next;
            state
                .decode_member_from_reader(&mut input, next.len(), &mut out)
                .unwrap();
            assert_eq!(out, next);
        }
        let mut decoder = Reader20State::with_allowance(budget);
        let mut output = Vec::new();
        let mut input = packed;
        decoder
            .decode_member_from_reader(&mut input, data.len(), &mut output)
            .unwrap();
        assert_eq!(output, data);
    }
    // One long encoded match can straddle a declared member boundary.
    let data = b"ABC".repeat(80);
    let next = data[37..234].to_vec();
    let mut encoder = Unpack20Encoder::with_options(EncodeOptions::new(16).with_try_audio(false));
    let packed = encoder.encode_member(&data).unwrap();
    let packed_next = encoder.encode_member(&next).unwrap();
    assert!(packed.len() < data.len() / 2);
    check(&Allowance::default(), &data, &packed, &next, &packed_next);
    let budget = Allowance::limited(1024 * 1024);
    check(&budget, &data, &packed, &next, &packed_next);
    assert_eq!(budget.used(), 0);
}
