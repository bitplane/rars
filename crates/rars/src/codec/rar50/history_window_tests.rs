use super::*;

#[test]
fn buffered_slack_appends_and_compacts_without_reallocating() {
    let mut state = ReaderState::new(&Allowance::default());
    let dictionary = 64;
    let mut expected: Vec<_> = (0..dictionary as u8).collect();
    state.remember_history(&expected, dictionary).unwrap();
    let address = state.history.as_ptr();
    let capacity = state.history.capacity();
    assert_eq!(capacity, dictionary + dictionary / 4);
    for byte in 64..=96 {
        let previous = state.history.to_vec();
        state.remember_history(&[byte], dictionary).unwrap();
        expected.push(byte);
        assert_eq!(state.history.as_ptr(), address);
        assert_eq!(state.history.capacity(), capacity);
        assert_eq!(
            state.reachable_history(),
            &expected[expected.len() - dictionary..]
        );
        if previous.len() < capacity {
            assert!(
                state.history.starts_with(&previous),
                "append moved the retained prefix"
            );
        } else {
            assert_eq!(state.history.len(), dictionary);
        }
    }
}

#[test]
fn dictionary_growth_does_not_make_slack_reachable_in_original_or_clones() {
    let mut state = ReaderState::new(&Allowance::default());
    state.remember_history(b"ABCDEFGH", 8).unwrap();
    state.remember_history(b"x", 8).unwrap();
    assert_eq!(&*state.history, b"ABCDEFGHx");
    assert_eq!(state.reachable_history(), b"BCDEFGHx");
    let public_clone = state.try_clone().unwrap();
    let streaming_clone = state.try_clone_for_stream().unwrap();
    for mut state in [state, public_clone, streaming_clone] {
        let mut output = Buffer::new(&Allowance::default());
        state.copy_match(&mut output, 9, 3, 3, 16).unwrap();
        assert_eq!(&*output, &[0; 3]);
        // An empty member with a larger dictionary cannot resurrect old bytes.
        state.remember_history(&[], 16).unwrap();
        assert_eq!(state.reachable_history(), b"BCDEFGHx");
        state.remember_history(b"y", 16).unwrap();
        output.clear();
        state.copy_match(&mut output, 9, 3, 3, 16).unwrap();
        assert_eq!(&*output, b"BCD");
    }
}

#[test]
fn full_dictionary_output_replaces_discontinuous_old_history() {
    let mut state = ReaderState::new(&Allowance::default());
    state.remember_history(&[b'A'; 96], 128).unwrap();
    state.remember_history(&[b'B'; 256], 128).unwrap();
    assert_eq!(&*state.history, &[b'B'; 128]);
    assert_eq!(state.history_window, 128);
    let address = state.history.as_ptr();
    state.remember_history(&[b'C'; 256], 128).unwrap();
    assert_eq!(state.history.as_ptr(), address);
    assert_eq!(&*state.history, &[b'C'; 128]);
}

#[test]
fn modest_dictionary_shrinks_obey_the_slack_bound() {
    let mut state = ReaderState::new(&Allowance::default());
    let mut expected = vec![b'A'; 1024];
    state.remember_history(&expected, 1024).unwrap();
    for dictionary in [512, 384, 256, 128, 8, 3, 1] {
        state.remember_history(b"x", dictionary).unwrap();
        expected.push(b'x');
        expected.drain(..expected.len().saturating_sub(dictionary));
        assert_eq!(state.reachable_history(), &expected);
        assert_eq!(state.history.capacity(), dictionary + dictionary / 4);
        assert_eq!(state.history_window, dictionary);
    }
}

#[test]
fn refused_history_replacement_preserves_bytes_window_and_charge() {
    let budget = Allowance::limited(1024);
    let mut state = ReaderState::new(&budget);
    state.remember_history(&[b'A'; 1024], 1024).unwrap();
    let address = state.history.as_ptr();
    for (incoming, dictionary) in [(b"x".as_slice(), 512), (&[b'B'; 2048][..], 2048)] {
        assert!(matches!(
            state.remember_history(incoming, dictionary),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
        assert_eq!(state.history.as_ptr(), address);
        assert_eq!(&*state.history, &[b'A'; 1024]);
        assert_eq!(state.history_window, 1024);
        assert_eq!(budget.used(), 1024);
    }
    // The original bounded in-place path still fits its exact budget.
    state.remember_history(b"x", 1024).unwrap();
    assert_eq!(state.history.capacity(), 1024);
    assert_eq!(budget.used(), 1024);
    drop(state);
    assert_eq!(budget.used(), 0);
}

#[cfg(feature = "write")]
#[test]
fn buffered_and_streamed_members_reuse_unlimited_history_in_both_directions() {
    let dictionary = 1024;
    let mut state = ReaderState::new(&Allowance::default());
    state
        .remember_history(&vec![b'A'; dictionary], dictionary)
        .unwrap();
    state.remember_history(b"x", dictionary).unwrap();
    let mut state = state.try_clone_for_stream().unwrap();
    assert_eq!(state.history.len(), dictionary);
    let address = state.history.as_ptr();
    let capacity = state.history.capacity();
    let data = vec![b'B'; STREAM_FLUSH_THRESHOLD + 1];
    let packed = encode_literal_only(&data, 0).unwrap();
    let mut decoded = Vec::new();
    state
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut packed.as_slice(),
            0,
            data.len(),
            dictionary,
            true,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.resize(decoded.len() + len, byte)
                    }
                }
                Ok::<(), std::convert::Infallible>(())
            },
        )
        .unwrap();
    assert_eq!(decoded, data);
    assert_eq!(state.history.as_ptr(), address);
    assert_eq!(state.history.capacity(), capacity);
    assert_eq!(state.history_window, dictionary);
    state.remember_history(b"c", dictionary).unwrap();
    assert_eq!(state.history.as_ptr(), address);
    assert_eq!(state.history.capacity(), capacity);
    assert_eq!(state.reachable_history().last(), Some(&b'c'));
}

#[test]
fn streaming_failure_keeps_the_moved_out_history_window_empty() {
    let mut state = ReaderState::new(&Allowance::default());
    state.remember_history(b"ABCDEFGHx", 8).unwrap();
    let result = state.decode_member_from_reader_with_dictionary_to_sink(
        &mut &[][..],
        0,
        1,
        16,
        true,
        |_| Ok::<(), std::convert::Infallible>(()),
    );
    assert!(result.is_err());
    assert!(state.history.is_empty());
    assert_eq!(state.history_window, 0);
    assert!(state.try_clone().unwrap().reachable_history().is_empty());
}

#[test]
fn dictionary_shrink_after_reset_allocates_only_for_live_history() {
    let mut state = ReaderState::new(&Allowance::default());
    state.remember_history(&[b'A'; 128], 128).unwrap();
    state.reset();
    state.remember_history(b"x", 64).unwrap();
    assert_eq!(state.reachable_history(), b"x");
    assert_eq!(state.history.capacity(), 8);

    // The streaming setup uses the same rule after a non-solid reset.
    let history = Buffer::with_capacity(160, &Allowance::default()).unwrap();
    let output = StreamingOutput::new(history, 1, 64, 64).unwrap();
    assert!(output.history.is_empty());
    assert_eq!(output.history.capacity(), 8);
}
