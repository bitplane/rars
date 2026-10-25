use super::*;

#[test]
fn unlimited_checkpoint_retains_capacity_and_independent_history() {
    let mut history = Buffer::with_capacity(16, &Allowance::default()).unwrap();
    history.extend_from_slice(b"ABCDE").unwrap();
    let mut original = ReaderState::with_history(history);
    original.reps = [1, 2, 3, 4];
    original.last_length = 7;
    let public_copy = original.try_clone().unwrap();
    assert_eq!(public_copy.history.capacity(), 5);
    assert_eq!(&*public_copy.history, b"ABCDE");
    let mut copied = original.try_prepare_for_stream(true, 0).unwrap();
    assert_eq!(copied.history.capacity(), 16);
    assert_eq!(&*copied.history, b"ABCDE");
    assert_ne!(copied.history.as_ptr(), original.history.as_ptr());
    assert_eq!(copied.reps, original.reps);
    assert_eq!(copied.last_length, original.last_length);
    copied.history[0] = b'X';
    assert_eq!(&*original.history, b"ABCDE");
    drop(original);
    assert_eq!(&*copied.history, b"XBCDE");
}

#[test]
fn limited_checkpoint_keeps_its_existing_length_charge_and_refusal() {
    for limit in [20, 21] {
        let budget = Allowance::limited(limit);
        let mut history = Buffer::with_capacity(16, &budget).unwrap();
        history.extend_from_slice(b"ABCDE").unwrap();
        let original = ReaderState::with_history(history);
        assert_eq!(budget.used(), 16);
        match original.try_prepare_for_stream(true, 0) {
            Ok(copied) => {
                assert_eq!(limit, 21);
                assert_eq!(copied.history.capacity(), 5);
                assert_eq!(&*copied.history, b"ABCDE");
                assert_ne!(copied.history.as_ptr(), original.history.as_ptr());
                assert_eq!(budget.used(), 21);
                drop(copied);
            }
            Err(error) => {
                assert_eq!(limit, 20);
                assert!(matches!(error, Error::WorkspaceLimitExceeded(_)));
            }
        }
        assert_eq!(budget.used(), 16);
        assert_eq!(&*original.history, b"ABCDE");
        assert_eq!(original.history.capacity(), 16);
        drop(original);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn refused_checkpoint_preserves_the_previous_history_owner() {
    let budget = super::super::workspace::RefusingBudget::new(1);
    let mut history = Buffer::with_capacity(16, &budget).unwrap();
    history.extend_from_slice(b"ABCDE").unwrap();
    let original = ReaderState::with_history(history);
    let address = original.history.as_ptr();
    assert!(matches!(
        original.try_prepare_for_stream(true, 0),
        Err(Error::Cancelled)
    ));
    assert_eq!(original.history.as_ptr(), address);
    assert_eq!(original.history.capacity(), 16);
    assert_eq!(&*original.history, b"ABCDE");
    assert_eq!(budget.used(), 16);
    drop(original);
    assert_eq!(budget.used(), 0);
}

#[cfg(feature = "write")]
#[test]
fn solid_streaming_checkpoints_keep_geometric_capacity_between_small_members() {
    use std::collections::BTreeSet;
    let dictionary = 16 * 1024;
    let data = b"solid checkpoint history and repeated match bytes\n".repeat(20);
    let mut expected_history = Vec::new();
    let mut capacities = BTreeSet::new();
    let mut decoder = ReaderState::new(&Allowance::default());
    for member in 0..40 {
        let packed = encode_lz_member_with_history(&data, &expected_history, 0).unwrap();
        let mut checkpoint = decoder.try_prepare_for_stream(true, 0).unwrap();
        assert_eq!(checkpoint.history.capacity(), decoder.history.capacity());
        let mut decoded = Vec::new();
        checkpoint
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut packed.as_slice(),
                0,
                data.len(),
                dictionary,
                member != 0,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.extend(std::iter::repeat_n(byte, len));
                        }
                    }
                    Ok::<(), std::convert::Infallible>(())
                },
            )
            .unwrap();
        assert_eq!(decoded, data);
        expected_history.extend_from_slice(&data);
        let discard = expected_history.len().saturating_sub(dictionary);
        expected_history.drain(..discard);
        assert_eq!(&*checkpoint.history, &expected_history);
        assert!(checkpoint.history.capacity() <= dictionary + dictionary / 4);
        capacities.insert(checkpoint.history.capacity());
        decoder = checkpoint;
    }
    // Each checkpoint retains the preceding geometric capacity. Copying only
    // the length creates a fresh capacity on almost every small solid member.
    assert!(capacities.len() <= 6, "capacities: {capacities:?}");
}

#[test]
fn independent_stream_preparation_preserves_control_and_exhausted_budget() {
    let budget = Allowance::limited(1024 * 1024);
    let mut history = Buffer::with_capacity(1024 * 1024, &budget).unwrap();
    history.extend_from_slice(b"previous history").unwrap();
    let mut original = ReaderState::with_history(history);
    original.reps = [1, 2, 3, 4];
    original.last_length = 7;
    let token = crate::ReadCancellation::new();
    original.read_control = crate::read_control::ReadControl::new(Some(&token));
    let mut fresh = original.try_prepare_for_stream(false, 3).unwrap();
    assert_eq!(budget.used(), 1024 * 1024);
    assert_eq!(fresh.history.capacity(), 0);
    assert_eq!(fresh.history_window, 0);
    assert!(fresh.tables.is_none());
    assert_eq!(fresh.reps, [0; 4]);
    assert_eq!(fresh.last_length, 0);
    assert_eq!(&*original.history, b"previous history");
    assert_eq!(original.reps, [1, 2, 3, 4]);
    assert_eq!(original.last_length, 7);
    // The fresh decoder must still charge allocations to the same ledger.
    assert!(fresh.history.try_push(b'X').is_err());
    token.cancel();
    assert!(matches!(
        fresh.read_control.check_codec(),
        Err(Error::Cancelled)
    ));
    drop(original);
    fresh.history.try_push(b'X').unwrap();
    drop(fresh);
    assert_eq!(budget.used(), 0);
}

#[cfg(feature = "write")]
#[test]
fn independent_stream_preparation_does_not_copy_populated_tables_or_history() {
    fn check<B: Budget>(budget: &B) {
        let data = b"old dictionary and Huffman tables";
        let packed = encode_literal_only(data, 0).unwrap();
        let mut original = ReaderState::new(budget);
        original
            .decode_member(&packed, 0, data.len(), false, DecodeMode::Lz)
            .unwrap();
        assert!(original.tables.is_some());
        let address = original.history.as_ptr();
        let fresh = original.try_prepare_for_stream(false, 3).unwrap();
        assert!(fresh.tables.is_none());
        assert!(fresh.history.is_empty());
        assert_eq!(fresh.history.capacity(), if B::LIMITED { 0 } else { 3 });
        assert_eq!(original.history.as_ptr(), address);
        assert_eq!(original.reachable_history(), data);
        let solid = original.try_prepare_for_stream(true, 0).unwrap();
        assert!(solid.tables.is_some());
        assert_eq!(solid.reachable_history(), data);
    }
    check(&Allowance::default());
    check(&Allowance::limited(1024 * 1024));

    let budget = super::super::workspace::RefusingBudget::new(usize::MAX);
    let packed = encode_literal_only(b"old history", 0).unwrap();
    let mut original = ReaderState::new(&budget);
    original
        .decode_member(&packed, 0, 11, false, DecodeMode::Lz)
        .unwrap();
    let before = (budget.attempts(), budget.used());
    let fresh = original.try_prepare_for_stream(false, 3).unwrap();
    assert_eq!((budget.attempts(), budget.used()), before);
    drop(original);
    drop(fresh);
    assert_eq!(budget.used(), 0);
}

#[test]
fn independent_stream_capacity_hint_is_capped_without_copying_history() {
    let mut history = Buffer::with_capacity(16, &Allowance::default()).unwrap();
    history.extend_from_slice(b"ABCDE").unwrap();
    let original = ReaderState::with_history(history);
    for (size, capacity) in [(0, 0), (3, 3), (16, 16), (u64::MAX, 16)] {
        let fresh = original.try_prepare_for_stream(false, size).unwrap();
        assert_eq!(fresh.history.capacity(), capacity);
        assert!(fresh.history.is_empty());
        assert_eq!(fresh.history_window, 0);
        assert_eq!(&*original.history, b"ABCDE");
    }
}
