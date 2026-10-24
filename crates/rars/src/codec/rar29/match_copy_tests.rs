use super::*;

#[test]
fn split_zero_fill_keeps_its_decision_across_chunks_and_checkpoints() {
    for (base, offset) in [(0, 3), (MAX_HISTORY, MAX_HISTORY + 4)] {
        let mut whole = Reader29State::with_allowance(&Allowance::default());
        whole.base_offset = base;
        whole.output.extend_from_slice(b"AB").unwrap();
        let mut split = whole.clone();
        let end = base + 12;
        whole.copy_match(10, offset, end).unwrap();
        split.copy_match(10, offset, base + 3).unwrap();
        let checkpoint = split.clone();
        for mut resumed in [split, checkpoint] {
            while resumed.pending_match.is_some() {
                resumed
                    .drain_pending_match((resumed.current_pos() + 3).min(end))
                    .unwrap();
            }
            assert_eq!(&resumed.output[..], b"AB\0\0\0\0\0\0\0\0\0\0");
            assert_eq!(&resumed.output[..], &whole.output[..]);
        }
    }
}

#[test]
fn short_long_and_split_matches_agree_with_bytewise_copying() {
    let seed: Vec<_> = (0..256).map(|i| (i % 23) as u8).collect();
    for length in [0, 1, 64, 65, 200] {
        for offset in [1, 3, 256] {
            let mut expected = seed.clone();
            for _ in 0..length {
                expected.push(expected[expected.len() - offset]);
            }
            for chunk in [1, 63, 64, 65, 200] {
                let mut decoder = Reader29State::with_allowance(&Allowance::default());
                decoder.output.extend_from_slice(&seed).unwrap();
                let end = seed.len() + length;
                decoder
                    .copy_match(length, offset, (seed.len() + chunk).min(end))
                    .unwrap();
                while decoder.pending_match.is_some() {
                    decoder
                        .drain_pending_match((decoder.current_pos() + chunk).min(end))
                        .unwrap();
                }
                assert_eq!(
                    &decoder.output[..],
                    expected,
                    "length={length} offset={offset} chunk={chunk}"
                );
            }
        }
    }
}

#[test]
fn split_long_match_survives_trimming_between_chunks() {
    let mut decoder = Reader29State::with_allowance(&Allowance::default());
    decoder
        .output
        .resize(MAX_HISTORY + MAX_HISTORY / 4 - 70, 0)
        .unwrap();
    decoder.output.extend_from_slice(b"ABC").unwrap();
    let start = decoder.current_pos();
    decoder.copy_match(200, 3, start + 67).unwrap();
    let first = decoder.output[decoder.output.len() - 67..].to_vec();
    let current = decoder.current_pos();
    decoder.trim_history(current, current);
    assert_eq!(decoder.base_offset, MAX_HISTORY / 4);
    decoder.drain_pending_match(start + 200).unwrap();
    let mut actual = first;
    actual.extend_from_slice(&decoder.output[decoder.output.len() - 133..]);
    assert_eq!(
        actual,
        b"ABC".iter().copied().cycle().take(200).collect::<Vec<_>>()
    );
    assert!(decoder.pending_match.is_none());
}

#[test]
fn invalid_distances_are_rejected_even_when_slack_retains_the_bytes() {
    for retained in [0, MAX_HISTORY + 1] {
        let mut decoder = Reader29State::with_allowance(&Allowance::default());
        decoder.output.resize(retained, b'X').unwrap();
        for offset in [0, MAX_HISTORY + 1] {
            if offset > retained {
                continue;
            }
            assert_eq!(
                decoder.copy_match(1, offset, retained + 1),
                Err(Error::InvalidData("RAR 2.9 match distance is out of range"))
            );
            assert_eq!(decoder.output.len(), retained);
        }
    }
}
