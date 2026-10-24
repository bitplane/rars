use super::*;
use crate::codec::workspace::RefusingBudget;
use std::io::{Cursor, Read};

#[derive(Debug, PartialEq, Eq)]
struct StateSnapshot {
    tables: String,
    reps: [usize; 4],
    last_length: usize,
    history: Vec<u8>,
    history_capacity: usize,
    history_window: usize,
}

fn snapshot<B: Budget>(state: &ReaderState<B>) -> StateSnapshot {
    StateSnapshot {
        tables: format!("{:?}", state.tables),
        reps: state.reps,
        last_length: state.last_length,
        history: state.history.to_vec(),
        history_capacity: state.history.capacity(),
        history_window: state.history_window,
    }
}

struct TracedReader<'a> {
    input: Cursor<&'a [u8]>,
    calls: Vec<(u64, usize, usize)>,
    fail_at: usize,
}
impl<'a> TracedReader<'a> {
    fn new(input: &'a [u8], fail_at: usize) -> Self {
        Self {
            input: Cursor::new(input),
            calls: Vec::new(),
            fail_at,
        }
    }
}
impl Read for TracedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let at = self.input.position();
        if self.calls.len() == self.fail_at {
            self.calls.push((at, output.len(), usize::MAX));
            return Err(std::io::Error::other("injected packed reader failure"));
        }
        let read = self.input.read(output)?;
        self.calls.push((at, output.len(), read));
        Ok(read)
    }
}

fn source() -> Vec<u8> {
    let mut data: Vec<_> = (0..4096).map(|i| ((i * 73 + i / 17) & 255) as u8).collect();
    for at in (32..data.len() - 8).step_by(64) {
        data[at..at + 5].copy_from_slice(&[0xe8, 0x41, 0, 0, 0]);
        data[at + 5..at + 8].copy_from_slice(&[0, 0, 0xeb]);
    }
    data
}
fn filter_cases() -> [Option<crate::FilterKind>; 5] {
    [
        None,
        Some(crate::FilterKind::Delta { channels: 4 }),
        Some(crate::FilterKind::E8),
        Some(crate::FilterKind::E8E9),
        Some(crate::FilterKind::Arm),
    ]
}
fn packed(data: &[u8], version: u8, filter: Option<crate::FilterKind>) -> Vec<u8> {
    let specs: Vec<_> = filter.into_iter().map(crate::FilterSpec::whole).collect();
    Unpack50Encoder::new()
        .encode_member_with_filters(data, version, &specs)
        .unwrap()
}
fn result(result: Result<Buffer<u8, impl Budget>>) -> std::result::Result<Vec<u8>, String> {
    result
        .map(|buffer| buffer.to_vec())
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn independent_history_unlimited_matches_original_bytes_and_live_decode_state() {
    let data = source();
    for version in [0, 1] {
        for filter in filter_cases() {
            for dictionary in [32, 128, 4096] {
                let specs: Vec<_> = filter.into_iter().map(crate::FilterSpec::whole).collect();
                let packed = Unpack50Encoder::with_options(
                    EncodeOptions::new(64).with_max_match_distance(dictionary),
                )
                .encode_member_with_filters(&data, version, &specs)
                .unwrap();
                for mode in [DecodeMode::Lz, DecodeMode::LzNoFilters] {
                    let mut old = ReaderState::new(&Allowance::default());
                    let mut actual = ReaderState::new(&Allowance::default());
                    let mut old_input = TracedReader::new(&packed, usize::MAX);
                    let mut actual_input = TracedReader::new(&packed, usize::MAX);
                    let expected = result(reference_decode(
                        &mut old,
                        &mut old_input,
                        version,
                        data.len(),
                        dictionary,
                        false,
                        mode,
                    ));
                    let output = result(
                        actual.decode_member_from_reader_with_dictionary_and_history(
                            &mut actual_input,
                            version,
                            data.len(),
                            dictionary,
                            false,
                            mode,
                            HistoryRetention::DiscardIndependent,
                        ),
                    );
                    assert_eq!(output, expected, "version={version}, filter={filter:?}, dictionary={dictionary}, mode={mode:?}");
                    assert_eq!(actual_input.calls, old_input.calls);
                    let mut old_state = snapshot(&old);
                    let actual_state = snapshot(&actual);
                    if let Ok(bytes) = &output {
                        if mode == DecodeMode::Lz {
                            assert_eq!(bytes, &data, "version={version}, filter={filter:?}, dictionary={dictionary}, mode={mode:?}");
                        }
                        assert!(!old_state.history.is_empty());
                        old_state.history.clear();
                        old_state.history_capacity = 0;
                        old_state.history_window = 0;
                        assert!(actual.history.is_empty());
                        assert_eq!(actual.history.capacity(), 0);
                    }
                    assert_eq!(actual_state, old_state);
                }
            }
        }
    }
}

#[test]
fn independent_history_default_and_solid_routes_retain_original_raw_dictionary() {
    let data = source();
    for version in [0, 1] {
        for filter in filter_cases() {
            let packed = packed(&data, version, filter);
            let mut old = ReaderState::new(&Allowance::default());
            let mut actual = ReaderState::new(&Allowance::default());
            let expected = result(reference_decode(
                &mut old,
                &mut Cursor::new(&packed),
                version,
                data.len(),
                4096,
                false,
                DecodeMode::Lz,
            ));
            let output = result(actual.decode_member_with_dictionary(
                &packed,
                version,
                data.len(),
                4096,
                false,
                DecodeMode::Lz,
            ));
            assert_eq!(output, expected);
            assert_eq!(snapshot(&actual), snapshot(&old));
            let specs: Vec<_> = filter.into_iter().map(crate::FilterSpec::whole).collect();
            let (raw, _) = filtered_lz_member(&data, &specs).unwrap();
            assert_eq!(&actual.history[..], raw);
            // The internal discard request must be overridden for solid decoding.
            let next =
                encode_lz_member_with_history(&raw[raw.len() - 128..], &raw, version).unwrap();
            let expected = result(reference_decode(
                &mut old,
                &mut Cursor::new(&next),
                version,
                128,
                4096,
                true,
                DecodeMode::Lz,
            ));
            let output = result(actual.decode_member_with_dictionary_and_history(
                &next,
                version,
                128,
                4096,
                true,
                DecodeMode::Lz,
                HistoryRetention::DiscardIndependent,
            ));
            assert_eq!(output, expected);
            assert_eq!(snapshot(&actual), snapshot(&old));
        }
    }
}

#[test]
fn independent_history_limited_keeps_every_original_growth_refusal_and_charge() {
    let data = source()[..256].to_vec();
    for version in [0, 1] {
        for filter in [None, Some(crate::FilterKind::Delta { channels: 4 })] {
            let packed = packed(&data, version, filter);
            let baseline = RefusingBudget::new(usize::MAX);
            {
                let mut state = ReaderState::new(&baseline);
                reference_decode(
                    &mut state,
                    &mut Cursor::new(&packed),
                    version,
                    data.len(),
                    4096,
                    false,
                    DecodeMode::Lz,
                )
                .unwrap();
            }
            assert_eq!(baseline.used(), 0);
            for fail_at in 0..=baseline.attempts() {
                for cancel_at in [0, 3, 7, usize::MAX] {
                    let old_budget = RefusingBudget::new(fail_at);
                    let actual_budget = RefusingBudget::new(fail_at);
                    let mut old = ReaderState::new(&old_budget);
                    let mut actual = ReaderState::new(&actual_budget);
                    let old_token = crate::ReadCancellation::new();
                    let actual_token = crate::ReadCancellation::new();
                    old.read_control = crate::read_control::ReadControl::new(Some(&old_token));
                    actual.read_control =
                        crate::read_control::ReadControl::new(Some(&actual_token));
                    old.read_control.cancel_after_checks(cancel_at);
                    actual.read_control.cancel_after_checks(cancel_at);
                    let mut old_input = TracedReader::new(&packed, usize::MAX);
                    let mut actual_input = TracedReader::new(&packed, usize::MAX);
                    let expected = result(reference_decode(
                        &mut old,
                        &mut old_input,
                        version,
                        data.len(),
                        4096,
                        false,
                        DecodeMode::Lz,
                    ));
                    let output = result(
                        actual.decode_member_from_reader_with_dictionary_and_history(
                            &mut actual_input,
                            version,
                            data.len(),
                            4096,
                            false,
                            DecodeMode::Lz,
                            HistoryRetention::DiscardIndependent,
                        ),
                    );
                    assert_eq!(
                        output, expected,
                        "version={version}, filter={filter:?}, fail_at={fail_at}"
                    );
                    assert_eq!(actual_input.calls, old_input.calls);
                    assert_eq!(snapshot(&actual), snapshot(&old));
                    assert_eq!(actual_budget.attempts(), old_budget.attempts());
                    assert_eq!(actual_budget.used(), old_budget.used());
                    drop(actual);
                    drop(old);
                    assert_eq!(actual_budget.used(), 0);
                    assert_eq!(old_budget.used(), 0);
                    assert_eq!(actual_token.is_cancelled(), old_token.is_cancelled());
                }
            }
        }
    }
}

#[test]
fn independent_history_preserves_reader_corruption_and_cancellation_order() {
    let data = source()[..256].to_vec();
    for version in [0, 1] {
        for filter in [None, Some(crate::FilterKind::Delta { channels: 4 })] {
            let packed = packed(&data, version, filter);
            for cut in [0, 1, 3, packed.len() / 2, packed.len() - 1, packed.len()] {
                for fail_at in [0, 1, 2, usize::MAX] {
                    for cancel_at in [0, 1, 3, 7, 15, usize::MAX] {
                        let old_token = crate::ReadCancellation::new();
                        let actual_token = crate::ReadCancellation::new();
                        let mut old = ReaderState::new(&Allowance::default());
                        let mut actual = ReaderState::new(&Allowance::default());
                        old.read_control = crate::read_control::ReadControl::new(Some(&old_token));
                        actual.read_control =
                            crate::read_control::ReadControl::new(Some(&actual_token));
                        old.read_control.cancel_after_checks(cancel_at);
                        actual.read_control.cancel_after_checks(cancel_at);
                        let mut old_input = TracedReader::new(&packed[..cut], fail_at);
                        let mut actual_input = TracedReader::new(&packed[..cut], fail_at);
                        let expected = result(reference_decode(
                            &mut old,
                            &mut old_input,
                            version,
                            data.len(),
                            4096,
                            false,
                            DecodeMode::Lz,
                        ));
                        let output = result(
                            actual.decode_member_from_reader_with_dictionary_and_history(
                                &mut actual_input,
                                version,
                                data.len(),
                                4096,
                                false,
                                DecodeMode::Lz,
                                HistoryRetention::DiscardIndependent,
                            ),
                        );
                        assert_eq!(output, expected);
                        assert_eq!(actual_input.calls, old_input.calls);
                        assert_eq!(actual_token.is_cancelled(), old_token.is_cancelled());
                        let mut expected_state = snapshot(&old);
                        if output.is_ok() {
                            expected_state.history.clear();
                            expected_state.history_capacity = 0;
                            expected_state.history_window = 0;
                        }
                        assert_eq!(snapshot(&actual), expected_state);
                    }
                }
            }
        }
    }
}

#[test]
fn independent_history_numeric_limits_keep_original_refusal_values_and_state() {
    let data = source()[..256].to_vec();
    for filter in [None, Some(crate::FilterKind::Delta { channels: 4 })] {
        let packed = packed(&data, 0, filter);
        for limit in [0, 32, 128, 512, 2048, 8192, 65536] {
            let old_budget = Allowance::limited(limit);
            let actual_budget = Allowance::limited(limit);
            let mut old = ReaderState::new(&old_budget);
            let mut actual = ReaderState::new(&actual_budget);
            let expected = result(reference_decode(
                &mut old,
                &mut Cursor::new(&packed),
                0,
                data.len(),
                4096,
                false,
                DecodeMode::Lz,
            ));
            let output = result(
                actual.decode_member_from_reader_with_dictionary_and_history(
                    &mut Cursor::new(&packed),
                    0,
                    data.len(),
                    4096,
                    false,
                    DecodeMode::Lz,
                    HistoryRetention::DiscardIndependent,
                ),
            );
            assert_eq!(output, expected, "limit={limit}, filter={filter:?}");
            assert_eq!(snapshot(&actual), snapshot(&old));
            assert_eq!(actual_budget.used(), old_budget.used());
            drop(actual);
            drop(old);
            assert_eq!(actual_budget.used(), 0);
            assert_eq!(old_budget.used(), 0);
        }
    }
}

#[derive(Clone, Debug, Default)]
struct AllocationTrace(std::sync::Arc<std::sync::Mutex<Vec<u64>>>);
impl Budget for AllocationTrace {
    type Charge = Self;
    type Failure = std::convert::Infallible;
    const LIMITED: bool = false;
    fn grow<T>(
        values: &mut Vec<T>,
        _: &mut Self,
        additional: usize,
    ) -> std::result::Result<(), Self::Failure> {
        values.reserve(additional);
        Ok(())
    }
    fn charge(&self) -> Self {
        self.clone()
    }
    fn allowance(charge: &Self) -> Self {
        charge.clone()
    }
    fn resize(charge: &mut Self, bytes: u64) -> Result<()> {
        charge.0.lock().unwrap().push(bytes);
        Ok(())
    }
}

#[test]
fn independent_history_omits_only_final_explicit_buffer_admissions() {
    let data = source();
    for version in [0, 1] {
        for filter in filter_cases() {
            let packed = packed(&data, version, filter);
            let retained = AllocationTrace::default();
            let discarded = AllocationTrace::default();
            let mut old = ReaderState::new(&retained);
            let mut actual = ReaderState::new(&discarded);
            let expected = result(reference_decode(
                &mut old,
                &mut Cursor::new(&packed),
                version,
                data.len(),
                4096,
                false,
                DecodeMode::Lz,
            ));
            let output = result(
                actual.decode_member_from_reader_with_dictionary_and_history(
                    &mut Cursor::new(&packed),
                    version,
                    data.len(),
                    4096,
                    false,
                    DecodeMode::Lz,
                    HistoryRetention::DiscardIndependent,
                ),
            );
            assert_eq!(output, expected);
            assert_eq!(output.unwrap(), data);
            assert_eq!(old.history.len(), 4096);
            assert_eq!(old.history.capacity(), 4096 + 4096 / 4);
            assert!(actual.history.is_empty());
            assert_eq!(actual.history.capacity(), 0);
            let old = retained.0.lock().unwrap();
            let actual = discarded.0.lock().unwrap();
            let omitted = if filter.is_some() { 2 } else { 1 };
            assert_eq!(old.len() - actual.len(), omitted);
            assert_eq!(
                old.iter().sum::<u64>() - actual.iter().sum::<u64>(),
                4096 + 4096 / 4 + if filter.is_some() { 4096 } else { 0 }
            );
            // This observes only explicit Buffer capacity admissions, not every
            // allocator call or whole-chain peak memory.
        }
    }
}

#[test]
fn independent_history_preserves_undersized_window_zero_fill_compatibility() {
    let data = source();
    for version in [0, 1] {
        let packed = packed(&data, version, None);
        let mut old = ReaderState::new(&Allowance::default());
        let mut actual = ReaderState::new(&Allowance::default());
        let expected = result(reference_decode(
            &mut old,
            &mut Cursor::new(&packed),
            version,
            data.len(),
            32,
            false,
            DecodeMode::Lz,
        ))
        .unwrap();
        let output = result(
            actual.decode_member_from_reader_with_dictionary_and_history(
                &mut Cursor::new(&packed),
                version,
                data.len(),
                32,
                false,
                DecodeMode::Lz,
                HistoryRetention::DiscardIndependent,
            ),
        )
        .unwrap();
        assert_eq!(output, expected);
        // The retained original decoder fills an out-of-window reference with
        // zeroes. This deliberately undersized codec call is not a source
        // roundtrip; archive integrity checks still reject damaged payloads.
        assert_ne!(output, data);
        assert_eq!(output[96], 0);
        assert_eq!(data[96], 0xe8);
        let mut old_state = snapshot(&old);
        old_state.history.clear();
        old_state.history_capacity = 0;
        old_state.history_window = 0;
        assert_eq!(snapshot(&actual), old_state);
    }
}

#[test]
fn independent_history_filtered_unknown_version_keeps_validation_and_late_cancel_order() {
    let data = source()[..256].to_vec();
    let packed = packed(&data, 0, Some(crate::FilterKind::Delta { channels: 4 }));
    for version in [2, 255] {
        for dictionary in [0, 4096] {
            for mode in [
                DecodeMode::LiteralOnly,
                DecodeMode::Lz,
                DecodeMode::LzNoFilters,
            ] {
                for cancel_at in [0, 1, 3, 7, usize::MAX] {
                    for fail_at in [0, 1, 3, usize::MAX] {
                        let old_budget = RefusingBudget::new(fail_at);
                        let actual_budget = RefusingBudget::new(fail_at);
                        let old_token = crate::ReadCancellation::new();
                        let actual_token = crate::ReadCancellation::new();
                        let mut old = ReaderState::new(&old_budget);
                        let mut actual = ReaderState::new(&actual_budget);
                        old.read_control = crate::read_control::ReadControl::new(Some(&old_token));
                        actual.read_control =
                            crate::read_control::ReadControl::new(Some(&actual_token));
                        old.read_control.cancel_after_checks(cancel_at);
                        actual.read_control.cancel_after_checks(cancel_at);
                        let mut old_input = TracedReader::new(&packed, usize::MAX);
                        let mut actual_input = TracedReader::new(&packed, usize::MAX);
                        let expected = result(reference_decode(
                            &mut old,
                            &mut old_input,
                            version,
                            data.len(),
                            dictionary,
                            false,
                            mode,
                        ));
                        let output = result(
                            actual.decode_member_from_reader_with_dictionary_and_history(
                                &mut actual_input,
                                version,
                                data.len(),
                                dictionary,
                                false,
                                mode,
                                HistoryRetention::DiscardIndependent,
                            ),
                        );
                        assert!(output.is_err());
                        assert_eq!(output, expected);
                        assert_eq!(actual_input.calls, old_input.calls);
                        assert_eq!(snapshot(&actual), snapshot(&old));
                        assert_eq!(actual_token.is_cancelled(), old_token.is_cancelled());
                        assert_eq!(actual_budget.attempts(), old_budget.attempts());
                        drop(actual);
                        drop(old);
                        assert_eq!(actual_budget.used(), 0);
                        assert_eq!(old_budget.used(), 0);
                    }
                }
            }
        }
    }
}

// Full unchanged d2 buffered decoding body, independent of history-policy plumbing.
#[allow(clippy::too_many_arguments)]
fn reference_decode<B: Budget>(
    state: &mut ReaderState<B>,
    input: &mut impl Read,
    algorithm_version: u8,
    output_size: usize,
    dictionary_size: usize,
    solid: bool,
    mode: DecodeMode,
) -> Result<Buffer<u8, B>> {
    state.read_control.check_codec()?;
    let control = state.read_control.clone();
    let input = &mut control.reader(input);
    if dictionary_size == 0 {
        return Err(Error::InvalidData("RAR 5 dictionary size is zero"));
    }
    if !solid {
        state.reset();
    }

    let allowance = state.history.allowance();
    let mut output =
        Buffer::with_capacity(output_size.min(MAX_INITIAL_OUTPUT_CAPACITY), &allowance)?;
    let mut filters = Buffer::new(&allowance);

    loop {
        let block = read_compressed_block_with_allowance(input, &state.history.allowance())?;
        let payload = &*block.payload;
        let mut payload_bit_pos = 0;
        if block.header.has_tables {
            let (lengths, table_bits) = read_table_lengths_with_allowance(
                payload,
                algorithm_version,
                &block.payload.allowance(),
            )?;
            state.tables = Some(ReaderTables::from_lengths(
                &lengths,
                &block.payload.allowance(),
            )?);
            payload_bit_pos = table_bits;
        }
        let tables = state
            .tables
            .take()
            .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
        let mut bits = BitReader::new(payload);
        bits.bit_pos = payload_bit_pos;

        let mut poller = state.read_control.poller();
        while bits.bit_pos < block.header.payload_bits && output.len() < output_size {
            poller.check_codec(output.len())?;
            let symbol = tables.main.decode(&mut bits)?;
            match symbol {
                0..=255 => output.try_push(symbol as u8)?,
                256 if mode.uses_lz() => {
                    filters.try_push(read_filter(&mut bits, output.len())?)?;
                }
                257 if mode.uses_lz() => {
                    if state.last_length != 0 {
                        state.copy_match(
                            &mut output,
                            state.reps[0],
                            state.last_length,
                            output_size,
                            dictionary_size,
                        )?;
                    }
                }
                258..=261 if mode.uses_lz() => {
                    let rep_index = symbol - 258;
                    let distance = state.reps[rep_index];
                    if distance == 0 {
                        return Err(Error::InvalidData(
                            "RAR 5 repeat distance is not initialized",
                        ));
                    }
                    let length_slot = tables.length.decode(&mut bits)?;
                    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
                    // The length table has 44 symbols and read_bits limits
                    // the extra value to this slot's declared width.
                    let length = length_from_slot_parts(length_slot, length_extra);
                    state.reps[..=rep_index].rotate_right(1);
                    state.reps[0] = distance;
                    state.last_length = length;
                    state.copy_match(
                        &mut output,
                        distance,
                        length,
                        output_size,
                        dictionary_size,
                    )?;
                }
                262.. if mode.uses_lz() => {
                    let length_slot = symbol - 262;
                    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
                    // Main symbols end at slot 43 and read_bits limits the
                    // extra value to this slot's declared width.
                    let mut length = length_from_slot_parts(length_slot, length_extra);
                    let distance_slot = tables.distance.decode(&mut bits)?;
                    let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                    let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                        let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                        let low = tables.align.decode(&mut bits)? as u32;
                        (high << 4) | low
                    } else {
                        bits.read_bits(distance_bit_count as u8)?
                    };
                    // distance_slot_bit_count rejected slots above 65 and
                    // the extra value was read at exactly that width.
                    let distance =
                        distance_from_slot_parts(distance_slot, distance_bit_count, distance_extra);
                    length += length_bonus(distance);
                    state.reps.rotate_right(1);
                    state.reps[0] = distance;
                    state.last_length = length;
                    state.copy_match(
                        &mut output,
                        distance,
                        length,
                        output_size,
                        dictionary_size,
                    )?;
                }
                _ => {
                    return Err(Error::InvalidData(
                        "RAR 5 literal-only decoder encountered non-literal symbol",
                    ));
                }
            }
        }

        state.tables = Some(tables);
        if block.header.is_last || output.len() >= output_size {
            break;
        }
    }

    if output.len() == output_size {
        let history_output = if mode.applies_filters() && !filters.is_empty() {
            Some(Buffer::copied(
                &output[output.len().saturating_sub(dictionary_size)..],
                &allowance,
            )?)
        } else {
            None
        };
        if mode.applies_filters() {
            state.read_control.check_codec()?;
            apply_filters_with_allowance(&mut output, &filters, &state.read_control, &allowance)?;
        }
        state.remember_history(
            history_output.as_deref().unwrap_or(&output),
            dictionary_size,
        )?;
        Ok(output)
    } else {
        Err(Error::NeedMoreInput)
    }
}
