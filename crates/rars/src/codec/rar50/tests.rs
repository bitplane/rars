use crate::codec::workspace::RefusingBudget;

fn assert_each_allocation_refusal<T>(
    mut work: impl FnMut(&RefusingBudget) -> crate::codec::Result<T>,
) -> usize {
    let baseline = RefusingBudget::new(usize::MAX);
    drop(work(&baseline).unwrap());
    let attempts = baseline.attempts();
    assert!(attempts > 0);
    assert_eq!(baseline.used(), 0);

    for fail_at in 0..attempts {
        let budget = RefusingBudget::new(fail_at);
        assert!(
            matches!(work(&budget), Err(Error::Cancelled)),
            "failure at allocation {fail_at}"
        );
        assert_eq!(budget.used(), 0, "failure at allocation {fail_at}");
    }
    attempts
}

#[test]
fn reader_workspace_refusals_release_buffered_filters_and_checkpoints() {
    let data = b"raw reader dictionary and filtered output\n".repeat(32);
    for kind in [
        crate::FilterKind::E8,
        crate::FilterKind::Delta { channels: 2 },
    ] {
        let packed = Unpack50Encoder::new()
            .encode_member_with_filter(&data, 0, crate::FilterSpec::whole(kind))
            .unwrap();
        let attempts = assert_each_allocation_refusal(|budget| {
            let mut state = ReaderState::new(budget);
            let decoded = state.decode_member_with_dictionary(
                &packed,
                0,
                data.len(),
                64,
                false,
                DecodeMode::Lz,
            )?;
            assert_eq!(&*decoded, &data);
            let checkpoint = state.try_clone()?;
            assert_eq!(checkpoint.history, state.history);
            assert_eq!(
                checkpoint.tables.as_ref().unwrap().main.state.len(),
                state.tables.as_ref().unwrap().main.state.len()
            );
            Ok(decoded)
        });
        assert!(attempts > 15);
    }
}

#[test]
fn reader_workspace_refusals_release_streaming_history_and_input() {
    let data = b"streaming reader window\n".repeat(4000);
    let packed = encode_literal_only(&data, 0).unwrap();
    let attempts = assert_each_allocation_refusal(|budget| {
        let mut state = ReaderState::new(budget);
        let mut emitted = 0;
        let result = state.decode_member_from_reader_with_dictionary_to_sink(
            &mut packed.as_slice(),
            0,
            data.len(),
            1024,
            false,
            |chunk| {
                emitted += match chunk {
                    DecodedChunk::Bytes(bytes) => bytes.len(),
                    DecodedChunk::Repeated { len, .. } => len,
                };
                Ok::<(), std::convert::Infallible>(())
            },
        );
        match result {
            Ok(()) => {
                assert_eq!(emitted, data.len());
                assert_eq!(&*state.history, &data[data.len() - 1024..]);
                Ok(())
            }
            Err(StreamDecodeError::Decode(error)) => Err(error),
            Err(_) => panic!("unexpected streaming failure"),
        }
    });
    assert!(attempts > 8);
}

#[test]
fn reader_workspace_retained_output_and_checkpoint_remain_charged() {
    let data = b"retained reader result".repeat(20);
    let packed = encode_literal_only(&data, 0).unwrap();
    let ledger = Allowance::limited(256 * 1024);
    let mut state = ReaderState::new(&ledger);
    let output = state
        .decode_member_with_dictionary(&packed, 0, data.len(), 64, false, DecodeMode::Lz)
        .unwrap();
    let owners = ledger.used();
    let checkpoint = state.try_clone().unwrap();
    assert!(ledger.used() > owners);
    drop(state);
    assert!(ledger.used() > output.capacity() as u64);
    drop(checkpoint);
    assert_eq!(ledger.used(), output.capacity() as u64);
    assert_eq!(&*output, &data);
    drop(output);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn reader_workspace_history_replacement_admits_overlap_before_mutating() {
    let ledger = Allowance::limited(8);
    let mut state = ReaderState::new(&ledger);
    state.remember_history(b"ABCDEFGH", 8).unwrap();
    assert_eq!(ledger.used(), 8);
    assert!(matches!(
        state.remember_history(b"xy", 2),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(&*state.history, b"ABCDEFGH");
    assert_eq!(ledger.used(), 8);
    drop(state);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn bounded_reader_admits_input_before_reading_and_releases_on_errors() {
    struct Source<'a> {
        bytes: std::io::Cursor<&'a [u8]>,
        reads: usize,
    }
    impl Read for Source<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            self.bytes.read(buffer)
        }
    }
    let data: Vec<_> = (0..8192).map(|i| ((i * 71) ^ (i >> 5)) as u8).collect();
    let options = EncodeOptions::new(16).with_max_match_distance(1024);
    let denied = Allowance::limited(0);
    let mut source = Source {
        bytes: std::io::Cursor::new(&data),
        reads: 0,
    };
    let error = reader_to_with_allowance(
        &mut source,
        data.len() as u64,
        &mut std::io::sink(),
        0,
        options,
        256,
        None,
        &denied,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        crate::Error::Codec(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(source.reads, 0);
    assert_eq!(denied.used(), 0);

    let allowance = Allowance::limited(8 * 1024 * 1024);
    let mut output = Vec::new();
    reader_to_with_allowance(
        &mut std::io::Cursor::new(&data),
        data.len() as u64,
        &mut output,
        0,
        options,
        256,
        None,
        &allowance,
    )
    .unwrap();
    assert_eq!(decode_lz(&output, 0, data.len()).unwrap(), data);
    assert_eq!(allowance.used(), 0);
    for declared in [data.len() as u64 - 1, data.len() as u64 + 1] {
        assert!(reader_to_with_allowance(
            &mut std::io::Cursor::new(&data),
            declared,
            &mut std::io::sink(),
            0,
            options,
            256,
            None,
            &allowance
        )
        .is_err());
        assert_eq!(allowance.used(), 0);
    }
    let mut prefix = Vec::new();
    assert!(matches!(
        reader_to_with_allowance(
            &mut std::io::Cursor::new(&data),
            data.len() as u64,
            &mut prefix,
            0,
            options,
            256,
            Some(&mut |_| false),
            &allowance
        ),
        Err(crate::Error::Cancelled)
    ));
    assert!(
        !prefix.is_empty(),
        "streaming refusal can leave an emitted prefix"
    );
    assert_eq!(allowance.used(), 0);
}

#[test]
fn filtered_state_owns_transform_scratch_history_and_outputs() {
    let data: Vec<_> = (0..FILTERED_LZ_BLOCK_SIZE + 257)
        .map(|i| ((i * 17) ^ (i >> 9)) as u8)
        .collect();
    for version in [0, 1] {
        for optimal in [false, true] {
            let options = EncodeOptions::new(16)
                .with_optimal_parse(optimal)
                .with_max_match_distance(8192);
            for size in [4096, data.len()] {
                for kind in [
                    crate::FilterKind::Delta { channels: 3 },
                    crate::FilterKind::E8E9,
                    crate::FilterKind::Arm,
                ] {
                    let filters = [crate::FilterSpec::whole(kind)];
                    let allowance = Allowance::limited(16 * 1024 * 1024);
                    let mut state = EncoderState::new(options, &allowance);
                    let mut reference = Unpack50Encoder::with_options(options);
                    let expected = reference
                        .encode_member_with_filters(&data[..size], version, &filters)
                        .unwrap();
                    let packed = state
                        .encode(&data[..size], version, Some(&filters), None)
                        .unwrap();
                    assert_eq!(&*packed, expected);
                    assert_eq!(&*state.history, &data[size.saturating_sub(8192)..size]);
                    drop(packed);
                    let history_charge = allowance.used();
                    assert!(history_charge >= state.history.len() as u64);
                    let following = state.encode(b"next member", version, None, None).unwrap();
                    assert_eq!(
                        &*following,
                        reference.encode_member(b"next member", version).unwrap()
                    );
                    drop(state);
                    assert!(allowance.used() >= following.len() as u64);
                    drop(following);
                    assert_eq!(allowance.used(), 0);
                }
            }
        }
    }
}

#[test]
fn delta_scratch_refusal_does_not_modify_caller_input_or_leak_records() {
    let input = [7u8; 512];
    let filters = [crate::FilterSpec::whole(crate::FilterKind::Delta {
        channels: 3,
    })];
    let records = std::mem::size_of::<EncodeFilter>() as u64;
    for limit in [1024 + records - 1, 1024 + records] {
        let allowance = Allowance::limited(limit);
        let result = filtered_member_with_allowance(&input, &filters, &allowance);
        assert_eq!(input, [7; 512]);
        if limit == 1024 + records - 1 {
            assert!(matches!(result, Err(Error::WorkspaceLimitExceeded(_))));
            assert_eq!(allowance.used(), 0);
        } else {
            let (data, descriptors) = result.unwrap();
            assert_eq!(allowance.used(), 512 + records);
            assert_eq!(descriptors.len(), 1);
            assert_eq!(
                filters::delta_decode_with_control(
                    &data,
                    3,
                    rar50_delta_messages(),
                    &crate::read_control::ReadControl::default()
                )
                .unwrap(),
                input
            );
            drop((data, descriptors));
            assert_eq!(allowance.used(), 0);
        }
    }
}

#[test]
fn failed_stateful_encodes_preserve_history_and_allow_reuse() {
    let allowance = Allowance::limited(4 * 1024 * 1024);
    let options = EncodeOptions::new(16)
        .with_optimal_parse(true)
        .with_max_match_distance(128);
    let mut state = EncoderState::new(options, &allowance);
    drop(state.encode(b"existing history", 0, None, None).unwrap());
    let previous = state.history.to_vec();
    let retained = allowance.used();
    let blocker =
        Buffer::filled((4 * 1024 * 1024 - retained - 64) as usize, 0u8, &allowance).unwrap();
    assert!(matches!(
        state.encode(b"refused input", 0, None, None),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(&*state.history, previous);
    drop(blocker);
    assert_eq!(allowance.used(), retained);
    let filters = [crate::FilterSpec::whole(crate::FilterKind::E8)];
    assert!(matches!(
        state.encode(b"cancelled input", 0, Some(&filters), Some(&mut |_| false)),
        Err(Error::Cancelled)
    ));
    assert_eq!(&*state.history, previous);
    assert_eq!(allowance.used(), retained);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = state.encode(
            b"callback panic",
            0,
            Some(&filters),
            Some(&mut |_| panic!("callback")),
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(&*state.history, previous);
    assert_eq!(allowance.used(), retained);
    drop(state.encode(b"successful retry", 0, None, None).unwrap());
    assert!(state.history.ends_with(b"successful retry"));
    drop(state);
    assert_eq!(allowance.used(), 0);
}

#[test]
fn streaming_results_remain_owned_and_cancelled_runs_release_all_blocks() {
    let data: Vec<_> = (0..8192).map(|i| (i * 71) as u8).collect();
    let blocks = [(2048, false), (4096, false), (8192, true)];
    for optimal in [false, true] {
        let allowance = Allowance::limited(8 * 1024 * 1024);
        let options = EncodeOptions::new(16)
            .with_optimal_parse(optimal)
            .with_max_match_distance(1024);
        let expected =
            encode_lz_streaming_blocks(&data, b"prior history", &blocks, 0, options, None).unwrap();
        let outputs = streaming_blocks_with_allowance(
            &data,
            b"prior history",
            &blocks,
            0,
            options,
            None,
            &allowance,
        )
        .unwrap();
        for (actual, expected) in outputs.iter().zip(expected) {
            assert_eq!(&**actual, expected);
        }
        let mut outputs = outputs.into_iter();
        let first = outputs.next().unwrap();
        drop(outputs);
        assert!(allowance.used() >= first.len() as u64);
        drop(first);
        assert_eq!(allowance.used(), 0);
        assert!(matches!(
            streaming_blocks_with_allowance(
                &data,
                &[],
                &blocks,
                0,
                options,
                Some(&mut |_| false),
                &allowance
            ),
            Err(Error::Cancelled)
        ));
        assert_eq!(allowance.used(), 0);
        assert!(streaming_blocks_with_allowance(
            &data,
            &[],
            &[(9000, true)],
            0,
            options,
            None,
            &allowance
        )
        .is_err());
        assert_eq!(allowance.used(), 0);
    }
}

#[test]
fn streaming_block_plan_rejects_gaps_and_invalid_ends() {
    let data = b"ABCD";
    let options = EncodeOptions::new(0);
    let allowance = Allowance::default();
    for blocks in [
        vec![(0, false)],
        vec![(5, true)],
        vec![(2, false), (2, true)],
    ] {
        assert!(matches!(
            streaming_blocks_with_allowance(data, &[], &blocks, 0, options, None, &allowance,),
            Err(Error::InvalidData("RAR 5 streaming block range is invalid"))
        ));
    }
    assert!(matches!(
        streaming_blocks_with_allowance(data, &[], &[(2, false)], 0, options, None, &allowance,),
        Err(Error::InvalidData(
            "RAR 5 streaming blocks do not cover input"
        ))
    ));
}

#[test]
fn streaming_block_encode_errors_release_first_and_shared_search_state() {
    let data = b"ABCD";
    let blocks = [(2, false), (4, true)];
    let expected = Error::InvalidData("RAR 5 unknown compression algorithm version");
    for (optimal, history) in [(true, &b""[..]), (true, &b"prior"[..]), (false, &b""[..])] {
        let allowance = Allowance::limited(32 * 1024 * 1024);
        let options = EncodeOptions::new(0).with_optimal_parse(optimal);
        assert_eq!(
            streaming_blocks_with_allowance(data, history, &blocks, 2, options, None, &allowance,),
            Err(expected.clone()),
            "optimal={optimal}, history={history:?}"
        );
        assert_eq!(allowance.used(), 0);
    }
}

#[test]
fn empty_streaming_member_has_no_blocks_or_progress() {
    let options = EncodeOptions::new(0).with_optimal_parse(true);
    let allowance = Allowance::limited(0);
    let mut called = false;
    let mut progress = |_: usize| {
        called = true;
        true
    };
    let output =
        streaming_blocks_with_allowance(&[], &[], &[], 0, options, Some(&mut progress), &allowance)
            .unwrap();
    assert!(output.is_empty());
    assert!(!called);
    assert_eq!(allowance.used(), 0);
}

#[test]
fn member_allowance_covers_history_tables_and_retained_block_output() {
    let data = b"bounded member with repeated words and short matches\n".repeat(3000);
    let history = b"short matches and remembered history\n".repeat(1000);
    for version in [0, 1] {
        for optimal in [false, true] {
            let options = EncodeOptions::new(16)
                .with_optimal_parse(optimal)
                .with_max_match_distance(65536);
            for history in [&[][..], &history[..]] {
                let expected =
                    encode_lz_member_inner(&data, history, version, options, None).unwrap();
                let allowance = Allowance::limited(32 * 1024 * 1024);
                let output = encode_member_with_allowance(
                    &data, history, version, options, None, &allowance,
                )
                .unwrap();
                assert_eq!(&*output, expected);
                assert!(allowance.used() >= output.len() as u64);
                let retained = allowance.used();
                let second = encode_member_with_allowance(
                    b"another member",
                    &[],
                    version,
                    options,
                    None,
                    &allowance,
                )
                .unwrap();
                assert!(allowance.used() >= retained + second.len() as u64);
                drop(second);
                assert_eq!(allowance.used(), retained);
                drop(output);
                assert_eq!(allowance.used(), 0);
            }
        }
    }
}

#[test]
fn large_member_search_setup_failures_release_the_allowance() {
    let data = vec![b'A'; LZ_BLOCK_SIZE + 1];
    let filters = [crate::FilterSpec::whole(crate::FilterKind::E8)];
    for optimal in [false, true] {
        let options = EncodeOptions::new(0).with_optimal_parse(optimal);

        let unfiltered = Allowance::limited(0);
        assert!(matches!(
            encode_member_with_allowance(&data, &[], 0, options, None, &unfiltered,),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
        assert_eq!(unfiltered.used(), 0);

        for limit in [128, data.len() as u64 + 4096] {
            let filtered = Allowance::limited(limit);
            assert!(matches!(
                filtered_lz_blocks(&data, &filters, &[], 0, options, None, &filtered),
                Err(Error::WorkspaceLimitExceeded(_))
            ));
            assert_eq!(filtered.used(), 0);
        }
    }
}

#[test]
fn optimal_parse_pass_failures_release_the_allowance() {
    let data: Vec<u8> = (0..512).map(|i| (i * 71) as u8).collect();
    let options = EncodeOptions::new(16).with_optimal_parse(true);
    // The first limit fails while building the initial optimal path; the
    // second permits that path but fails while repricing it.
    for limit in [1_080_000, 1_105_000] {
        let allowance = Allowance::limited(limit);
        assert!(matches!(
            encode_member_with_allowance(&data, &[], 0, options, None, &allowance),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
        assert_eq!(allowance.used(), 0);
    }
}

#[test]
fn member_refusal_cancellation_and_unwind_release_the_whole_pipeline() {
    let data = b"member cancellation and refusal\n".repeat(100);
    let history = b"history".repeat(100);
    let options = EncodeOptions::new(16).with_optimal_parse(true);
    for limit in [0, 4096, 65536, 512 * 1024] {
        let allowance = Allowance::limited(limit);
        assert!(matches!(
            encode_member_with_allowance(&data, &history, 0, options, None, &allowance),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
        assert_eq!(allowance.used(), 0);
    }
    let allowance = Allowance::limited(16 * 1024 * 1024);
    assert!(matches!(
        encode_member_with_allowance(
            &data,
            &history,
            0,
            options,
            Some(&mut |_| false),
            &allowance
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(allowance.used(), 0);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = encode_member_with_allowance(
            &data,
            &history,
            0,
            options,
            Some(&mut |_| panic!("progress callback panic")),
            &allowance,
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(allowance.used(), 0);
}

#[test]
fn bit_growth_and_frame_copy_reserve_before_mutation() {
    let allowance = Allowance::limited(8);
    let mut writer = BitWriter::with_allowance(&allowance);
    writer.try_write_bits(0, 64).unwrap();
    let filled = writer.bytes.to_vec();
    let filled_bits = writer.bit_pos;
    assert!(writer.try_write_bits(1, 1).is_err());
    assert_eq!(&*writer.bytes, filled);
    assert_eq!(writer.bit_pos, filled_bits);
    drop(writer);
    assert_eq!(allowance.used(), 0);

    for limit in [18, 19] {
        let allowance = Allowance::limited(limit);
        let payload = Buffer::filled(8, 0u8, &allowance).unwrap();
        let frame = encode_compressed_block_with_allowance(&payload, 64, true, true, &allowance);
        if limit == 18 {
            assert!(matches!(frame, Err(Error::WorkspaceLimitExceeded(_))));
            assert_eq!(allowance.used(), 8);
        } else {
            let frame = frame.unwrap();
            assert_eq!(allowance.used(), 19);
            drop(payload);
            assert_eq!(allowance.used(), 11);
            drop(frame);
            assert_eq!(allowance.used(), 0);
        }
    }
}

#[test]
fn token_block_budget_refusals_release_all_encoder_owners() {
    let base = [
        EncodeToken::Literal(b'A'),
        EncodeToken::Literal(b'B'),
        EncodeToken::Match {
            length: 2,
            distance: 2,
        },
        EncodeToken::Match {
            length: 2,
            distance: 2,
        },
        EncodeToken::Match {
            length: 3,
            distance: 2,
        },
    ];

    for filtered in [false, true] {
        let mut tokens = Vec::new();
        if filtered {
            tokens.push(EncodeToken::Filter(EncodeFilter {
                offset: 0,
                length: 9,
                filter_type: FilterType::E8,
                channels: 0,
            }));
        }
        tokens.extend_from_slice(&base);
        tokens.extend(std::iter::repeat_n(EncodeToken::Literal(b'A'), 100));
        let expected = encode_token_block(&tokens, 0, DISTANCE_TABLE_SIZE_50, true).unwrap();
        let mut decoded = b"ABABABABA".to_vec();
        decoded.extend(std::iter::repeat_n(b'A', 100));
        assert_eq!(decode_lz(&expected, 0, decoded.len()).unwrap(), decoded);

        let mut limit = 0;
        let mut refusals = 0;
        let mut admitted = false;
        for _ in 0..256 {
            let allowance = Allowance::limited(limit);
            match encode_token_block_with_allowance(
                &tokens,
                0,
                DISTANCE_TABLE_SIZE_50,
                true,
                &allowance,
            ) {
                Err(Error::WorkspaceLimitExceeded(details)) => {
                    refusals += 1;
                    assert_eq!(allowance.used(), 0);
                    let next = details.used + details.required;
                    assert!(next > limit);
                    limit = next;
                }
                Ok(encoded) => {
                    assert_eq!(&*encoded, expected);
                    drop(encoded);
                    assert_eq!(allowance.used(), 0);
                    admitted = true;
                    break;
                }
                Err(error) => panic!("unexpected token block error: {error:?}"),
            }
        }
        assert!(
            admitted,
            "token block did not fit after 256 admission thresholds"
        );
        assert!(refusals > 1);

        let baseline_budget = RefusingBudget::new(usize::MAX);
        let baseline = encode_token_block_with_allowance(
            &tokens,
            0,
            DISTANCE_TABLE_SIZE_50,
            true,
            &baseline_budget,
        )
        .unwrap();
        assert_eq!(&*baseline, expected);
        let attempts = baseline_budget.attempts();
        drop(baseline);
        assert_eq!(baseline_budget.used(), 0);
        assert!(attempts > 1);

        for fail_at in 0..attempts {
            let budget = RefusingBudget::new(fail_at);
            assert_eq!(
                encode_token_block_with_allowance(
                    &tokens,
                    0,
                    DISTANCE_TABLE_SIZE_50,
                    true,
                    &budget,
                ),
                Err(Error::Cancelled),
                "filtered={filtered}, failure at allocation {fail_at}"
            );
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn member_allocation_refusals_release_search_and_output_owners() {
    let data = b"ABCDABCDABCDABCD".repeat(16);
    let filters = [EncodeFilter {
        offset: 0,
        length: data.len(),
        filter_type: FilterType::E8,
        channels: 0,
    }];

    for optimal in [false, true] {
        let options = EncodeOptions::new(16)
            .with_max_match_distance(256)
            .with_optimal_parse(optimal);
        let expected =
            encode_member_with_allowance(&data, &[], 0, options, None, &Allowance::default())
                .unwrap();
        assert_eq!(decode_lz(&expected, 0, data.len()).unwrap(), data);
        let attempts = assert_each_allocation_refusal(|budget| {
            encode_member_with_allowance(&data, &[], 0, options, None, budget)
        });
        assert!(attempts > 1);

        let expected = encode_filtered_member_with_allowance(
            &data,
            &[],
            0,
            &filters,
            options,
            None,
            &Allowance::default(),
        )
        .unwrap();
        assert_eq!(decode_lz(&expected, 0, data.len()).unwrap(), data);
        let attempts = assert_each_allocation_refusal(|budget| {
            encode_filtered_member_with_allowance(&data, &[], 0, &filters, options, None, budget)
        });
        assert!(attempts > 1);

        let blocks = [(data.len() / 2, false), (data.len(), true)];
        let expected = streaming_blocks_with_allowance(
            &data,
            &[],
            &blocks,
            0,
            options,
            None,
            &Allowance::default(),
        )
        .unwrap();
        let packed: Vec<_> = expected
            .iter()
            .flat_map(|block| block.iter().copied())
            .collect();
        assert_eq!(decode_lz(&packed, 0, data.len()).unwrap(), data);
        let attempts = assert_each_allocation_refusal(|budget| {
            streaming_blocks_with_allowance(&data, &[], &blocks, 0, options, None, budget)
        });
        assert!(attempts > 1);

        let specs = [crate::FilterSpec::whole(crate::FilterKind::E8)];
        let expected =
            filtered_lz_blocks(&data, &specs, &[], 0, options, None, &Allowance::default())
                .unwrap();
        assert_eq!(decode_lz(&expected, 0, data.len()).unwrap(), data);
        let attempts = assert_each_allocation_refusal(|budget| {
            filtered_lz_blocks(&data, &specs, &[], 0, options, None, budget)
        });
        assert!(attempts > 1);
    }
}

#[test]
fn filtered_multiblock_output_growth_refusals_release_storage() {
    let data = vec![b'A'; FILTERED_LZ_BLOCK_SIZE + 1];
    let filters = [crate::FilterSpec::whole(crate::FilterKind::E8)];
    let options = EncodeOptions::new(16).with_max_match_distance(256);
    let expected = filtered_lz_blocks(
        &data,
        &filters,
        &[],
        0,
        options,
        None,
        &Allowance::default(),
    )
    .unwrap();
    assert_eq!(decode_lz(&expected, 0, data.len()).unwrap(), data);
    assert_each_allocation_refusal(|budget| {
        filtered_lz_blocks(&data, &filters, &[], 0, options, None, budget)
    });
}

#[test]
fn member_history_and_large_output_refusals_release_storage() {
    let data: Vec<u8> = (0..2048)
        .map(|index| ((index * 71) ^ (index >> 3)) as u8)
        .collect();
    let history = vec![0xee; 256];
    let blocks = [(data.len() / 2, false), (data.len(), true)];
    let filters = [EncodeFilter {
        offset: 0,
        length: data.len(),
        filter_type: FilterType::E8,
        channels: 0,
    }];

    for optimal in [false, true] {
        let options = EncodeOptions::new(16)
            .with_max_match_distance(history.len())
            .with_optimal_parse(optimal);
        assert_each_allocation_refusal(|budget| {
            streaming_blocks_with_allowance(&data, &history, &blocks, 0, options, None, budget)
        });
        assert_each_allocation_refusal(|budget| {
            encode_filtered_member_with_allowance(
                &data, &history, 0, &filters, options, None, budget,
            )
        });
        assert_each_allocation_refusal(|budget| {
            let mut state = EncoderState::new(options, budget);
            state.encode(&data, 0, None, None)
        });
    }

    let large = vec![b'A'; LZ_BLOCK_SIZE + 1];
    let options = EncodeOptions::new(16).with_max_match_distance(256);
    let expected =
        encode_member_with_allowance(&large, &[], 0, options, None, &Allowance::default()).unwrap();
    assert_eq!(decode_lz(&expected, 0, large.len()).unwrap(), large);
    assert_each_allocation_refusal(|budget| {
        encode_member_with_allowance(&large, &[], 0, options, None, budget)
    });
}

#[test]
fn parse_repricing_and_lazy_literal_refusals_release_storage() {
    let optimal_data = wordy_text(4096);
    let optimal = EncodeOptions::new(32).with_optimal_parse(true);
    assert_each_allocation_refusal(|budget| {
        encode_tokens_with_allowance(
            &optimal_data,
            0..optimal_data.len(),
            MemberSearch::Fresh,
            optimal,
            DISTANCE_TABLE_SIZE_50,
            &[],
            None,
            budget,
        )
    });

    let pos = 160;
    let mut lazy_data: Vec<u8> = (0..240u16)
        .map(|value| value.wrapping_mul(91) as u8)
        .collect();
    lazy_data[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
    lazy_data[pos - 80..pos - 70].copy_from_slice(b"CDEFGHIJKL");
    lazy_data[pos..pos + 12].copy_from_slice(b"ABCDEFGHIJKL");
    let lazy = EncodeOptions::default()
        .with_lazy_matching(true)
        .with_lazy_lookahead(2);
    let tokens = encode_tokens_with_allowance(
        &lazy_data,
        pos..lazy_data.len(),
        MemberSearch::Fresh,
        lazy,
        DISTANCE_TABLE_SIZE_50,
        &[],
        None,
        &Allowance::default(),
    )
    .unwrap();
    assert!(matches!(tokens.first(), Some(EncodeToken::Literal(_))));
    assert_each_allocation_refusal(|budget| {
        encode_tokens_with_allowance(
            &lazy_data,
            pos..lazy_data.len(),
            MemberSearch::Fresh,
            lazy,
            DISTANCE_TABLE_SIZE_50,
            &[],
            None,
            budget,
        )
    });

    assert_each_allocation_refusal(|budget| EncoderCodeTable::from_lengths(&[1, 1], budget));
}

#[test]
fn production_limited_budget_covers_residual_allocation_sites() {
    let denied = Allowance::limited(0);
    assert!(matches!(
        EncoderCodeTable::from_lengths(&[1, 1], &denied),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(denied.used(), 0);

    let mut noise = 0x2545_f491_4f6c_dd1du64;
    let data: Vec<u8> = (0..4096)
        .map(|_| {
            noise ^= noise << 13;
            noise ^= noise >> 7;
            noise ^= noise << 17;
            b'A' + ((noise >> 40) as u8 & 1)
        })
        .collect();
    let options = EncodeOptions::new(64).with_optimal_parse(true);
    for start in [0, data.len() / 2] {
        let probe = Allowance::limited(64 * 1024 * 1024);
        let collector = OptimalCollector::with_allowance(&data, start, options, &probe).unwrap();
        let finder_bytes = probe.used();
        drop(collector);
        assert_eq!(probe.used(), 0);

        let span = data.len() - start;
        let run_bytes = span * std::mem::size_of::<(u32, u32)>();
        let initial_bytes = run_bytes + (span + 1) * std::mem::size_of::<u32>();
        for limit in [
            finder_bytes + run_bytes as u64 - 1,
            finder_bytes + initial_bytes as u64 - 1,
            finder_bytes + initial_bytes as u64,
        ] {
            let allowance = Allowance::limited(limit);
            let mut collector =
                OptimalCollector::with_allowance(&data, start, options, &allowance).unwrap();
            assert!(matches!(
                collector.collect(&data, start..data.len(), options),
                Err(Error::WorkspaceLimitExceeded(_))
            ));
            drop(collector);
            assert_eq!(allowance.used(), 0);
        }
    }

    let input = b"state history must be admitted after its packed output";
    let options = EncodeOptions::new(0).with_max_match_distance(32);
    let mut limit = 0u64;
    let mut refusals = 0;
    loop {
        let allowance = Allowance::limited(limit);
        let mut state = EncoderState::new(options, &allowance);
        match state.encode(input, 0, None, None) {
            Err(Error::WorkspaceLimitExceeded(details)) => {
                refusals += 1;
                let next = details.used + details.required;
                assert!(next > limit);
                limit = next;
            }
            Ok(packed) => {
                assert_eq!(&*state.history, &input[input.len() - 32..]);
                drop((packed, state));
                assert_eq!(allowance.used(), 0);
                break;
            }
            Err(error) => panic!("unexpected state error: {error:?}"),
        }
    }
    assert!(refusals > 1);
}

#[test]
fn token_block_allocation_refusals_cover_each_control_form() {
    let filter = EncodeToken::Filter(EncodeFilter {
        offset: 0,
        length: 1,
        filter_type: FilterType::E8,
        channels: 0,
    });
    let mut filters = vec![filter; 256];
    filters.push(EncodeToken::Literal(b'A'));

    let mut last_length = vec![
        EncodeToken::Literal(b'A'),
        EncodeToken::Match {
            length: 2,
            distance: 1,
        },
    ];
    last_length.extend(std::iter::repeat_n(
        EncodeToken::Match {
            length: 2,
            distance: 1,
        },
        256,
    ));

    let mut repeat_distance = last_length[..2].to_vec();
    repeat_distance.extend((0..256).map(|index| EncodeToken::Match {
        length: 3 + index % 2,
        distance: 1,
    }));

    let mut new_distance = vec![EncodeToken::Literal(b'A'); 100];
    new_distance.extend((0..256).map(|index| EncodeToken::Match {
        length: 10,
        distance: 70 + index % 5,
    }));

    for (tokens, output_size) in [
        (filters, 1),
        (last_length, 1 + 2 * 257),
        (repeat_distance, 3 + 128 * (3 + 4)),
        (new_distance, 100 + 256 * 10),
    ] {
        let packed = encode_token_block(&tokens, 0, DISTANCE_TABLE_SIZE_50, true).unwrap();
        assert_eq!(
            decode_lz(&packed, 0, output_size).unwrap(),
            vec![b'A'; output_size]
        );
        assert_each_allocation_refusal(|budget| {
            encode_token_block_with_allowance(&tokens, 0, DISTANCE_TABLE_SIZE_50, true, budget)
        });
    }
}

#[test]
fn filter_writer_allocation_refusals_cover_filter_type_bits() {
    for filter_type in [
        FilterType::Delta,
        FilterType::E8,
        FilterType::E8E9,
        FilterType::Arm,
    ] {
        let filter = EncodeFilter {
            offset: 0,
            length: 1,
            filter_type,
            channels: 1,
        };
        for prefix_bits in [9, 12] {
            let mut expected = BitWriter::new();
            expected.write_bits(0, prefix_bits);
            try_write_filter(&mut expected, filter).unwrap();
            let expected = expected.finish();

            let baseline = RefusingBudget::new(usize::MAX);
            let mut writer = BitWriter::with_allowance(&baseline);
            writer.try_write_bits(0, prefix_bits).unwrap();
            try_write_filter(&mut writer, filter).unwrap();
            assert_eq!(&*writer.bytes, expected);
            drop(writer);
            assert_eq!(baseline.used(), 0);

            assert_each_allocation_refusal(|budget| {
                let mut writer = BitWriter::with_allowance(budget);
                writer.try_write_bits(0, prefix_bits)?;
                try_write_filter(&mut writer, filter)?;
                Ok(writer.bytes)
            });
        }
    }
}

#[test]
fn table_level_writer_refusals_release_bit_storage() {
    let mut isolated_zeroes = [1u8; LEVEL_TABLE_SIZE];
    for index in (1..LEVEL_TABLE_SIZE).step_by(2) {
        isolated_zeroes[index] = 0;
    }
    let mut offset_zero_runs = [1u8; LEVEL_TABLE_SIZE];
    for start in (1..LEVEL_TABLE_SIZE).step_by(4) {
        offset_zero_runs[start..(start + 3).min(LEVEL_TABLE_SIZE)].fill(0);
    }
    for lengths in [
        [0u8; LEVEL_TABLE_SIZE],
        isolated_zeroes,
        offset_zero_runs,
        [15u8; LEVEL_TABLE_SIZE],
    ] {
        for prefix_bits in 0..=16 {
            let mut expected = BitWriter::new();
            expected.write_bits(0, prefix_bits);
            try_write_level_lengths(&mut expected, &lengths).unwrap();
            let expected = expected.finish();

            let baseline = RefusingBudget::new(usize::MAX);
            let mut writer = BitWriter::with_allowance(&baseline);
            writer.try_write_bits(0, prefix_bits).unwrap();
            try_write_level_lengths(&mut writer, &lengths).unwrap();
            assert_eq!(&*writer.bytes, expected);
            drop(writer);
            assert_eq!(baseline.used(), 0);

            assert_each_allocation_refusal(|budget| {
                let mut writer = BitWriter::with_allowance(budget);
                writer.try_write_bits(0, prefix_bits)?;
                try_write_level_lengths(&mut writer, &lengths)?;
                Ok(writer.bytes)
            });
        }
    }
}

#[test]
fn table_run_refusals_release_token_storage() {
    for count in [3, 10, 11, 138, 139, 1000] {
        assert_each_allocation_refusal(|budget| {
            let mut tokens = Buffer::new(budget);
            emit_repeat_level_run(&mut tokens, count)?;
            Ok(tokens)
        });
    }
    for count in [1, 3, 10, 11, 139, 1000] {
        assert_each_allocation_refusal(|budget| {
            let mut tokens = Buffer::new(budget);
            emit_zero_level_run(&mut tokens, count)?;
            Ok(tokens)
        });
    }
}

#[test]
fn filter_preparation_rejects_legacy_only_kinds() {
    let data = b"plain bytes";
    let filters = [crate::FilterSpec::whole(crate::FilterKind::Itanium)];
    let expected = Error::InvalidData("RAR 5 has no builtin type for this filter");
    assert_eq!(
        normalized_filter_specs(data.len(), &filters, &Allowance::default()),
        Err(expected.clone())
    );
    assert_eq!(
        filtered_member_with_allowance(data, &filters, &Allowance::default()),
        Err(expected)
    );
}

#[test]
fn parser_allowance_preserves_tokens_and_retains_the_returned_owner() {
    let data: Vec<_> = (0..8192u32)
        .map(|n| (n.wrapping_mul(71) ^ (n >> 4)) as u8)
        .collect();
    for optimal in [false, true] {
        let options = EncodeOptions::new(32)
            .with_max_match_distance(65536)
            .with_optimal_parse(optimal);
        let expected = encode_tokens_with_progress(
            &data,
            0..data.len(),
            MemberSearch::Fresh,
            options,
            DISTANCE_TABLE_SIZE_50,
            &[],
            None,
        )
        .unwrap();
        let allowance = Allowance::limited(16 * 1024 * 1024);
        for _ in 0..3 {
            let tokens = encode_tokens_with_allowance(
                &data,
                0..data.len(),
                MemberSearch::Fresh,
                options,
                DISTANCE_TABLE_SIZE_50,
                &[],
                None,
                &allowance,
            )
            .unwrap();
            assert_eq!(tokens, expected);
            let retained = allowance.used();
            assert!(retained >= (tokens.len() * std::mem::size_of::<EncodeToken>()) as u64);
            assert!(retained > 0);
            assert!(matches!(
                Buffer::<u8, _>::with_capacity(
                    (16 * 1024 * 1024 - retained + 1) as usize,
                    &allowance
                ),
                Err(Error::WorkspaceLimitExceeded(_))
            ));
            drop(tokens);
            assert_eq!(allowance.used(), 0);
        }
    }
}

#[test]
fn parser_refusal_and_cancellation_release_finders_matches_and_parse_arrays() {
    let data: Vec<_> = (0..16384u32)
        .map(|n| (n.wrapping_mul(73) ^ (n >> 3)) as u8)
        .collect();
    for optimal in [false, true] {
        let options = EncodeOptions::new(32)
            .with_max_match_distance(65536)
            .with_optimal_parse(optimal);
        for limit in [0, 524288] {
            let allowance = Allowance::limited(limit);
            let result = encode_tokens_with_allowance(
                &data,
                0..data.len(),
                MemberSearch::Fresh,
                options,
                DISTANCE_TABLE_SIZE_50,
                &[],
                None,
                &allowance,
            );
            assert!(matches!(result, Err(Error::WorkspaceLimitExceeded(_))));
            assert_eq!(allowance.used(), 0);
        }
        if optimal {
            // Admit the tree itself, then refuse match/parse workspace.
            let allowance = Allowance::limited(1_200_000);
            assert!(
                matches!(encode_tokens_with_allowance(&data, 0..data.len(), MemberSearch::Fresh,
                options, DISTANCE_TABLE_SIZE_50, &[], None, &allowance),
                Err(Error::WorkspaceLimitExceeded(details)) if details.used > 1_000_000)
            );
            assert_eq!(allowance.used(), 0);
        }
        let allowance = Allowance::limited(16 * 1024 * 1024);
        assert!(matches!(
            encode_tokens_with_allowance(
                &data,
                0..data.len(),
                MemberSearch::Fresh,
                options,
                DISTANCE_TABLE_SIZE_50,
                &[],
                Some(&mut |_| false),
                &allowance
            ),
            Err(Error::Cancelled)
        ));
        assert_eq!(allowance.used(), 0);
    }
}

#[test]
fn lazy_parser_honors_cancellation_at_final_progress_report() {
    let allowance = Allowance::default();
    let data = b"AB";
    let mut reports = 0;
    let result = encode_tokens_with_allowance(
        data,
        0..data.len(),
        MemberSearch::Fresh,
        EncodeOptions::new(0),
        DISTANCE_TABLE_SIZE_50,
        &[],
        Some(&mut |_| {
            reports += 1;
            reports == 1
        }),
        &allowance,
    );

    assert_eq!(result, Err(Error::Cancelled));
    assert_eq!(reports, 2);
}

#[test]
fn configured_x86_scanning_matches_default_across_poll_boundaries() {
    let mut input = vec![0; 192 * 1024];
    for pos in [65530, 65535, 65541, 131070, 131080] {
        input[pos] = 0xe9;
        input[pos + 1..pos + 5].copy_from_slice(&123456u32.to_le_bytes());
    }
    let token = crate::ReadCancellation::new();
    let control = crate::read_control::ReadControl::new(Some(&token));
    let mut expected = input.clone();
    e8e9_decode(&mut expected, 4096, true);
    e8e9_decode_with_control(&mut input, 4096, true, &control).unwrap();
    assert_eq!(input, expected);
}

#[test]
fn e8_decoder_adjusts_wrapped_negative_addresses() {
    let mut data = [0xe8, 0xff, 0xff, 0xff, 0xff];

    e8e9_decode(&mut data, 0, false);

    assert_eq!(
        u32::from_le_bytes(data[1..5].try_into().unwrap()),
        0x00ff_ffff
    );
}

#[test]
fn cancellation_interrupts_buffered_decode_and_filters() {
    let data = b"cancellable RAR5 symbols ".repeat(16384);
    let packed = encode_literal_only(&data, 0).unwrap();
    let token = crate::ReadCancellation::new();
    let mut decoder = Unpack50Decoder::new();
    decoder.read_control = crate::read_control::ReadControl::new(Some(&token));
    decoder.read_control.cancel_after_checks(16);
    assert_eq!(
        decoder
            .decode_member(&packed, 0, data.len(), false, DecodeMode::Lz)
            .unwrap_err(),
        Error::Cancelled
    );
    for arm in [false, true] {
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        control.cancel_after_checks(2);
        let mut bytes = vec![0; 384 * 1024];
        let result = if arm {
            arm_decode_with_control(&mut bytes, 0, &control)
        } else {
            e8e9_decode_with_control(&mut bytes, 0, true, &control)
        };
        assert_eq!(result.unwrap_err(), Error::Cancelled);
    }
}

#[test]
fn delta_filter_cancellation_leaves_output_unchanged() {
    let token = crate::ReadCancellation::new();
    let control = crate::read_control::ReadControl::new(Some(&token));
    control.cancel_after_checks(2);
    let mut bytes = vec![0x5a; 384 * 1024];
    let filter = PendingFilter {
        start: 0,
        length: bytes.len(),
        filter_type: FilterType::Delta,
        channels: 3,
    };

    assert_eq!(
        apply_filter_data(&mut bytes, &filter, &control),
        Err(Error::Cancelled)
    );
    assert!(bytes.iter().all(|&byte| byte == 0x5a));
}

#[test]
fn filter_application_propagates_range_and_cancellation_errors() {
    let original = [0xe8, 0, 0, 0, 0];
    let control = crate::read_control::ReadControl::default();
    for (start, length, message) in [
        (usize::MAX, 2, "RAR 5 filter range overflows"),
        (4, 2, "RAR 5 filter range exceeds output"),
    ] {
        let mut output = original;
        let filter = PendingFilter {
            start,
            length,
            filter_type: FilterType::E8,
            channels: 0,
        };
        assert_eq!(
            apply_filters_with_control(&mut output, &[filter], &control),
            Err(Error::InvalidData(message))
        );
        assert_eq!(output, original);
    }

    for kind in [FilterType::E8, FilterType::E8E9, FilterType::Arm] {
        for checks in [0, 1, 2] {
            let token = crate::ReadCancellation::new();
            let control = crate::read_control::ReadControl::new(Some(&token));
            control.cancel_after_checks(checks);
            let mut output = original;
            let filter = PendingFilter {
                start: 0,
                length: output.len(),
                filter_type: kind,
                channels: 0,
            };
            assert_eq!(
                apply_filters_with_control(&mut output, &[filter], &control),
                Err(Error::Cancelled),
                "kind={kind:?}, checks={checks}"
            );
            assert_eq!(output, original);
        }
    }
}

#[test]
fn repricing_keeps_the_smallest_actual_block_including_filters() {
    for filtered in [false, true] {
        let data = wordy_text(4096);
        let filters = if filtered {
            vec![EncodeFilter {
                offset: 0,
                length: data.len(),
                filter_type: FilterType::E8,
                channels: 0,
            }]
        } else {
            vec![]
        };
        let options = EncodeOptions::new(32).with_optimal_parse(true);
        let distances = DISTANCE_TABLE_SIZE_50;
        let selected = encode_tokens_with_progress(
            &data,
            0..data.len(),
            MemberSearch::Fresh,
            options,
            distances,
            &filters,
            None,
        )
        .unwrap();
        let lengths = table_lengths_with_filters(&selected, &filters, distances).unwrap();
        let selected_bits = token_stream_bits(&selected, &filters, &lengths, distances).unwrap();
        let all: Vec<_> = filters
            .iter()
            .copied()
            .map(EncodeToken::Filter)
            .chain(selected.iter().copied())
            .collect();
        let packed = encode_token_block(&all, 0, distances, true).unwrap();
        let parsed = parse_compressed_block(&packed).unwrap();
        assert_eq!(selected_bits, parsed.header.payload_bits);
        let mut collector = OptimalCollector::new(&data, 0, options);
        let matches = collector.collect(&data, 0..data.len(), options).unwrap();
        let mut pass =
            optimal_tokens(&data, 0..data.len(), options, distances, None, &matches).unwrap();
        for _ in 0..OPTIMAL_PARSE_PASSES {
            let lengths = table_lengths_with_filters(&pass, &filters, distances).unwrap();
            assert!(
                selected_bits <= token_stream_bits(&pass, &filters, &lengths, distances).unwrap()
            );
            pass = optimal_tokens(
                &data,
                0..data.len(),
                options,
                distances,
                Some(&TokenPrices {
                    lengths: lengths.slices(),
                }),
                &matches,
            )
            .unwrap();
        }
    }
}

#[test]
fn shorter_equal_price_match_can_expose_a_better_continuation() {
    let history = b"abcdefghijklm!mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let data = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut combined = history.to_vec();
    combined.extend_from_slice(data);
    let mut matches = BlockMatches {
        runs: Buffer::new(&Allowance::default()),
        starts: Buffer::new(&Allowance::default()),
    };
    for pos in 0..data.len() {
        matches.starts.push(matches.runs.len() as u32).unwrap();
        if pos == 0 {
            matches.runs.push((13, history.len() as u32)).unwrap();
        }
        if pos == 12 {
            matches
                .runs
                .push((40, (history.len() + 12 - 14) as u32))
                .unwrap();
        }
    }
    matches.starts.push(matches.runs.len() as u32).unwrap();
    let tokens = optimal_tokens(
        &combined,
        history.len()..combined.len(),
        EncodeOptions::new(32),
        DISTANCE_TABLE_SIZE_50,
        None,
        &matches,
    )
    .unwrap();
    assert_eq!(tokens.len(), 2);
    assert!(matches!(tokens[0], EncodeToken::Match { length: 12, .. }));
    assert!(matches!(tokens[1], EncodeToken::Match { length: 40, .. }));
}

#[test]
fn shared_streaming_finder_preserves_separate_block_bytes() {
    // Short blocks exercise seam hashes and wrap the dictionary repeatedly.
    let data: Vec<u8> = (0..8192).map(|i| ((i * 17 + i / 31) % 251) as u8).collect();
    for optimal in [false, true] {
        let options = EncodeOptions::new(32)
            .with_optimal_parse(optimal)
            .with_max_match_distance(128);
        let blocks: Vec<_> = (1..=32).map(|i| (i * 256, i % 4 == 0)).collect();
        let grouped = encode_lz_streaming_blocks(&data, &[], &blocks, 0, options, None).unwrap();
        let mut start = 0;
        for ((end, last), bytes) in blocks.into_iter().zip(grouped) {
            let reference =
                encode_lz_streaming_block(&data[start..end], &data[..start], 0, options, last)
                    .unwrap();
            assert_eq!(bytes, reference, "optimal={optimal}, start={start}");
            start = end;
        }
    }
}

#[test]
fn optimal_streaming_blocks_allow_zero_match_distance() {
    let data: Vec<u8> = (0..512).map(|i| (i * 71) as u8).collect();
    let options = EncodeOptions::new(16)
        .with_optimal_parse(true)
        .with_max_match_distance(0);
    let blocks =
        encode_lz_streaming_blocks(&data, &[], &[(256, false), (512, true)], 0, options, None)
            .unwrap();
    let packed: Vec<u8> = blocks.into_iter().flatten().collect();
    assert_eq!(decode_lz(&packed, 0, data.len()).unwrap(), data);
}
use super::*;

/// The flat code charged four bits for a symbol used once and four for one
/// used two hundred times, over an alphabet that is nothing like even.
#[test]
fn the_level_code_spends_fewer_bits_on_the_common_symbol() {
    let mut tokens = vec![LevelToken::plain(0); 200];
    for symbol in [4, 7, 9, 11] {
        tokens.push(LevelToken::plain(symbol));
    }
    let lengths = level_code_lengths_for_tokens(&tokens);
    assert!(
        lengths[0] < lengths[7],
        "the symbol used 200 times costs {} bits and one used once costs {}",
        lengths[0],
        lengths[7]
    );
}

/// Strict decoders rebuild the pre-table and reject one that does not fill
/// its code space, so whichever coding wins has to satisfy Kraft equality.
#[test]
fn every_level_code_fills_its_code_space() {
    let shapes: Vec<Vec<LevelToken>> = vec![
        vec![LevelToken::plain(3); 8],
        (0..20).map(LevelToken::plain).collect(),
        {
            let mut skewed = vec![LevelToken::plain(0); 900];
            skewed.extend((1..20).map(LevelToken::plain));
            skewed
        },
        (0..20)
            .flat_map(|symbol| std::iter::repeat_n(LevelToken::plain(symbol), 1 << symbol.min(9)))
            .collect(),
    ];
    for tokens in shapes {
        let lengths = level_code_lengths_for_tokens(&tokens);
        let used: Vec<u8> = lengths.iter().copied().filter(|&len| len != 0).collect();
        let kraft: f64 = used.iter().map(|&len| 0.5f64.powi(i32::from(len))).sum();
        assert!(
            (kraft - 1.0).abs() < 1e-9,
            "code over {} symbols fills {kraft} of its space: {lengths:?}",
            used.len()
        );
        assert!(
            used.iter().all(|&len| len <= 15),
            "{lengths:?} exceeds four bits"
        );
        assert!(HuffmanTable::from_lengths(&lengths).is_ok());
    }
}

/// The cost model has to agree with the writer, or it picks the wrong
/// coding whenever the two disagree about the table header.
#[test]
fn the_level_code_cost_matches_what_the_writer_emits() {
    let cases: Vec<[u8; LEVEL_TABLE_SIZE]> = vec![
        [4; LEVEL_TABLE_SIZE],
        {
            let mut lengths = [0u8; LEVEL_TABLE_SIZE];
            lengths[0] = 1;
            lengths[1] = 2;
            lengths[19] = 15;
            lengths
        },
        {
            let mut lengths = [0u8; LEVEL_TABLE_SIZE];
            lengths[2] = 15;
            lengths[3] = 15;
            lengths[9] = 3;
            lengths
        },
    ];
    for lengths in cases {
        let mut writer = BitWriter::new();
        write_level_lengths(&mut writer, &lengths);
        let header = level_code_cost(&lengths, &[0; LEVEL_TABLE_SIZE]);
        assert_eq!(
            header, writer.bit_pos,
            "header cost {header} against {} bits written for {lengths:?}",
            writer.bit_pos
        );
    }
}

fn encode_tokens(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
) -> Vec<EncodeToken> {
    let (combined, start) =
        member_window_with_allowance(input, history, options, &Allowance::default()).unwrap();
    encode_tokens_with_progress(
        &combined,
        start..combined.len(),
        MemberSearch::Fresh,
        options,
        distance_size,
        &[],
        None,
    )
    .expect("encoding without cancellation cannot be cancelled")
    .into_vec()
}

fn optimal_tokens(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    matches: &BlockMatches,
) -> Result<Vec<EncodeToken>> {
    optimal_tokens_in_workspace(
        combined,
        block,
        options,
        distance_size,
        prices,
        matches,
        &mut OptimalWorkspace::new(&Allowance::default()),
    )
    .map(Buffer::into_vec)
}

/// One block through the optimal parse, collecting its matches first the
/// way [`encode_tokens_with_progress`] does.
fn collected_optimal_tokens(
    data: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
) -> Vec<EncodeToken> {
    let mut collector = OptimalCollector::new(data, 0, options);
    let matches = collector.collect(data, 0..data.len(), options).unwrap();
    optimal_tokens(
        data,
        0..data.len(),
        options,
        distance_size,
        prices,
        &matches,
    )
    .unwrap()
}
fn should_lazy_emit_literal(
    input: &[u8],
    pos: usize,
    finder: &Rar50MatchFinder,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    current: MatchCandidate,
) -> bool {
    lazy_match_decision(
        input,
        pos,
        input.len(),
        finder,
        options,
        state,
        distance_size,
        current,
    )
    .0
}

fn checksum(flags: u8, size_bytes: &[u8]) -> u8 {
    size_bytes
        .iter()
        .fold(0x5a ^ flags, |acc, &byte| acc ^ byte)
}

#[test]
fn parses_one_byte_size_block_header() {
    let flags = 0xc7;
    let size = [3];
    let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb, 0xcc];

    let block = parse_compressed_block(&input).unwrap();
    assert_eq!(block.header_len, 3);
    assert_eq!(block.payload, 3..6);
    assert_eq!(block.header.flags, flags);
    assert!(block.header.is_last);
    assert!(block.header.has_tables);
    assert_eq!(block.header.final_byte_bits, 8);
    assert_eq!(block.header.payload_size, 3);
    assert_eq!(block.header.payload_bits, 24);
}

#[test]
fn parses_three_byte_size_block_header_with_partial_final_byte() {
    let flags = 0x94;
    let size = [0x34, 0x12, 0x00];
    let mut input = vec![flags, checksum(flags, &size), size[0], size[1], size[2]];
    input.resize(0x1234 + 5, 0);

    let block = parse_compressed_block(&input).unwrap();
    assert_eq!(block.header_len, 5);
    assert_eq!(block.payload, 5..0x1239);
    assert!(!block.header.is_last);
    assert!(block.header.has_tables);
    assert_eq!(block.header.final_byte_bits, 5);
    assert_eq!(block.header.payload_size, 0x1234);
    assert_eq!(block.header.payload_bits, (0x1234 - 1) * 8 + 5);
}

#[test]
fn rejects_reserved_size_length_selector() {
    let input = [0x18, 0x42, 0x00];

    assert_eq!(
        parse_compressed_block(&input),
        Err(Error::InvalidData("RAR 5 block size length is invalid"))
    );
}

#[test]
fn rejects_bad_block_header_checksum() {
    let input = [0xc7, 0x00, 0x03, 0xaa, 0xbb, 0xcc];

    assert_eq!(
        parse_compressed_block(&input),
        Err(Error::InvalidData("RAR 5 block header checksum mismatch"))
    );
}

#[test]
fn rejects_truncated_block_payload() {
    let flags = 0xc7;
    let size = [3];
    let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb];

    assert_eq!(parse_compressed_block(&input), Err(Error::NeedMoreInput));
}

#[test]
fn reads_level_lengths_with_literal_fifteen() {
    let mut nibbles = vec![1, 2, 15, 0, 3, 4];
    nibbles.resize(LEVEL_TABLE_SIZE + 1, 0);

    let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

    assert_eq!(&lengths[..6], &[1, 2, 15, 3, 4, 0]);
    assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4);
}

#[test]
fn reads_level_lengths_with_zero_run_at_current_position() {
    let mut nibbles = vec![7, 15, 3, 2];
    nibbles.resize(LEVEL_TABLE_SIZE - 3, 0);

    let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

    assert_eq!(lengths[0], 7);
    assert_eq!(&lengths[1..6], &[0, 0, 0, 0, 0]);
    assert_eq!(lengths[6], 2);
    assert_eq!(bits, (LEVEL_TABLE_SIZE - 3) * 4);
}

#[test]
fn level_zero_run_stops_at_level_table_boundary() {
    let mut nibbles = vec![0; LEVEL_TABLE_SIZE - 1];
    nibbles.extend([15, 15]); // a seventeen-entry zero run at the last slot
    let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();
    assert_eq!(lengths, [0; LEVEL_TABLE_SIZE]);
    assert_eq!(bits, (LEVEL_TABLE_SIZE + 1) * 4);
}

fn pack_nibbles(nibbles: &[u8]) -> Vec<u8> {
    nibbles
        .chunks(2)
        .map(|chunk| {
            let high = chunk[0] & 0x0f;
            let low = chunk.get(1).copied().unwrap_or(0) & 0x0f;
            (high << 4) | low
        })
        .collect()
}

#[test]
fn reads_rar50_second_level_table_lengths() {
    let mut writer = BitWriter::new();
    for _ in 0..LEVEL_TABLE_SIZE {
        writer.write_bits(5, 4);
    }
    for count in [138, 138, 138, 16] {
        writer.write_bits(19, 5);
        writer.write_bits(count - 11, 7);
    }
    let input = writer.finish();

    let (lengths, bits) = read_table_lengths(&input, 0).unwrap();

    assert_eq!(lengths.main.len(), MAIN_TABLE_SIZE);
    assert_eq!(lengths.distance.len(), DISTANCE_TABLE_SIZE_50);
    assert_eq!(lengths.align.len(), ALIGN_TABLE_SIZE);
    assert_eq!(lengths.length.len(), LENGTH_TABLE_SIZE);
    assert!(lengths.main.iter().all(|&length| length == 0));
    assert!(lengths.distance.iter().all(|&length| length == 0));
    assert!(lengths.align.iter().all(|&length| length == 0));
    assert!(lengths.length.iter().all(|&length| length == 0));
    assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4 * (5 + 7));
}

#[test]
fn table_length_runs_stop_at_the_table_boundary() {
    // The reference decoder clips an otherwise valid run to the table
    // length. Both zero runs and previous-length runs can cross it.
    for (first_symbol, run_symbol, expected) in [(19, 19, 0), (5, 17, 5)] {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        if first_symbol != run_symbol {
            writer.write_bits(first_symbol, 5);
        }
        for _ in 0..4 {
            writer.write_bits(run_symbol, 5);
            writer.write_bits(127, 7); // a 138-entry run
        }

        let (lengths, _) = read_table_lengths(&writer.finish(), 0).unwrap();
        assert!(lengths.main.iter().all(|&length| length == expected));
        assert!(lengths.distance.iter().all(|&length| length == expected));
        assert!(lengths.align.iter().all(|&length| length == expected));
        assert!(lengths.length.iter().all(|&length| length == expected));
    }
}

#[test]
fn truncated_table_run_extras_need_more_input() {
    // The last run symbol ends with fewer padding bits than its extra
    // field needs. Exercise both repeat-previous and zero runs at each
    // extra-field width.
    for (prefix, run) in [
        (&[][..], 19),
        (&[1, 1][..], 18),
        (&[1][..], 17),
        (&[1, 1][..], 16),
    ] {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        for &symbol in prefix {
            writer.write_bits(symbol, 5);
        }
        writer.write_bits(run, 5);
        assert_eq!(
            read_table_lengths(&writer.finish(), 0),
            Err(Error::NeedMoreInput),
            "run symbol {run}"
        );
    }
}

#[test]
fn malformed_table_prefixes_fail_before_table_symbols() {
    assert_eq!(read_table_lengths(&[], 0), Err(Error::NeedMoreInput));

    let mut invalid = BitWriter::new();
    for _ in 0..LEVEL_TABLE_SIZE {
        invalid.write_bits(1, 4);
    }
    assert!(matches!(
        read_table_lengths(&invalid.finish(), 0),
        Err(Error::InvalidData(_))
    ));

    let mut no_symbols = BitWriter::new();
    for _ in 0..LEVEL_TABLE_SIZE {
        no_symbols.write_bits(5, 4);
    }
    assert_eq!(
        read_table_lengths(&no_symbols.finish(), 0),
        Err(Error::NeedMoreInput)
    );
}

#[test]
fn truncated_level_escape_needs_its_count_nibble() {
    // The low nibble is an escape; its following count nibble is absent.
    assert_eq!(read_level_lengths(&[0x0f]), Err(Error::NeedMoreInput));
}

#[test]
fn decoders_reject_oversubscribed_secondary_huffman_tables() {
    for invalid_table in ["distance", "align", "length"] {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 1;
        let invalid_lengths = match invalid_table {
            "distance" => &mut lengths.distance,
            "align" => &mut lengths.align,
            "length" => &mut lengths.length,
            _ => unreachable!(),
        };
        invalid_lengths[..3].fill(1);
        let (payload, payload_bits) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let input = encode_compressed_block(&payload, payload_bits, true, true).unwrap();
        let expected = Error::InvalidData("RAR 5 oversubscribed Huffman table");

        assert_eq!(
            Unpack50Decoder::new().decode_member_with_dictionary(
                &input,
                0,
                1,
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::Lz,
            ),
            Err(expected.clone()),
            "{invalid_table}"
        );
        let result = Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(
            matches!(result, Err(StreamDecodeError::Decode(error)) if error == expected),
            "{invalid_table}"
        );
    }
}

#[test]
fn reads_rar70_table_length_count() {
    assert_eq!(
        table_length_count(1).unwrap(),
        MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
    );
}

#[test]
fn table_reader_rejects_unknown_algorithm_before_decoding() {
    let expected = Error::InvalidData("RAR 5 unknown compression algorithm version");
    assert_eq!(table_length_count(2).unwrap_err(), expected);
    assert_eq!(read_table_lengths(&[], 2).unwrap_err(), expected);
}

#[test]
fn encoded_table_lengths_round_trip_with_bit_count() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[b'B' as usize] = 3;
    lengths.main[262] = 3;
    lengths.distance[1] = 1;
    lengths.align[0] = 4;
    lengths.length[0] = 1;

    let (encoded, bit_count) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let (decoded, decoded_bits) = read_table_lengths(&encoded, 0).unwrap();

    assert_eq!(decoded, lengths);
    assert_eq!(decoded_bits, bit_count);
}

#[test]
fn table_encoder_validates_public_inputs() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[b'B' as usize] = 1;
    let encoded = encode_table_lengths(&lengths, 0).unwrap();
    assert_eq!(read_table_lengths(&encoded, 0).unwrap().0, lengths);

    assert_eq!(
        encode_table_lengths(&lengths, 2),
        Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version"
        ))
    );
    lengths.distance.pop();
    assert_eq!(
        encode_table_lengths(&lengths, 0),
        Err(Error::InvalidData("RAR 5 table length count mismatch"))
    );
    lengths.distance.push(0);
    lengths.main[0] = 16;
    assert_eq!(
        encode_table_lengths(&lengths, 0),
        Err(Error::InvalidData("RAR 5 Huffman length is too large"))
    );
}

#[test]
fn member_encoders_reject_unknown_algorithm_version() {
    let expected = Error::InvalidData("RAR 5 unknown compression algorithm version");
    assert_eq!(encode_literal_only(b"AB", 2).unwrap_err(), expected);
    assert_eq!(encode_lz_member(b"ABABABAB", 2).unwrap_err(), expected);
}

#[test]
fn table_level_encoder_uses_rar5_run_symbols() {
    let mut lengths =
        vec![0u8; MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_50 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE];
    lengths[..4].fill(6);
    lengths[8..21].fill(0);

    let tokens = encode_table_level_tokens(&lengths);

    assert!(tokens.contains(&LevelToken::repeat_previous_short(3)));
    assert!(tokens.iter().any(|token| token.symbol == 19));
}

#[test]
fn repeat_level_runs_cover_the_whole_requested_length() {
    for count in 3..=1024 {
        let mut tokens = Buffer::new(&Allowance::default());
        emit_repeat_level_run(&mut tokens, count).unwrap();
        let emitted: usize = tokens
            .iter()
            .map(|token| match token.symbol {
                16 => usize::from(token.extra_value) + 3,
                17 => usize::from(token.extra_value) + 11,
                other => panic!("unexpected repeat symbol {other}"),
            })
            .sum();
        assert_eq!(emitted, count, "repeat run of {count}");
    }
}

#[test]
fn zero_level_runs_cover_the_whole_requested_length() {
    for count in 1..=1024 {
        let mut tokens = Buffer::new(&Allowance::default());
        emit_zero_level_run(&mut tokens, count).unwrap();
        let emitted: usize = tokens
            .iter()
            .map(|token| match token.symbol {
                0 => 1,
                18 => usize::from(token.extra_value) + 3,
                19 => usize::from(token.extra_value) + 11,
                other => panic!("unexpected zero-run symbol {other}"),
            })
            .sum();
        assert_eq!(emitted, count, "zero run of {count}");
    }
}

#[test]
fn encoded_compressed_block_round_trips_header_fields() {
    let payload = [0xaa, 0xbb, 0xc0];
    let block = encode_compressed_block(&payload, 18, true, true).unwrap();

    let parsed = parse_compressed_block(&block).unwrap();

    assert_eq!(parsed.payload, 3..6);
    assert!(parsed.header.has_tables);
    assert!(parsed.header.is_last);
    assert_eq!(parsed.header.final_byte_bits, 2);
    assert_eq!(parsed.header.payload_bits, 18);
    assert_eq!(&block[parsed.payload], payload);
}

#[test]
fn rejects_table_repeat_without_previous_length() {
    let mut writer = BitWriter::new();
    for _ in 0..LEVEL_TABLE_SIZE {
        writer.write_bits(5, 4);
    }
    writer.write_bits(16, 5);
    writer.write_bits(0, 3);

    assert_eq!(
        read_table_lengths(&writer.finish(), 0),
        Err(Error::InvalidData(
            "RAR 5 table repeats missing previous length"
        ))
    );
}

#[test]
fn rejects_invalid_encoded_block_bit_counts() {
    assert_eq!(
        encode_compressed_block(&[0], 0, true, true),
        Err(Error::InvalidData("RAR 5 block has unused payload bytes"))
    );
    assert_eq!(
        encode_compressed_block(&[], 1, true, true),
        Err(Error::InvalidData("RAR 5 block bit count exceeds payload"))
    );
    let oversized = vec![0; 0x0100_0000];
    assert_eq!(
        encode_compressed_block(&oversized, oversized.len() * 8, false, true),
        Err(Error::InvalidData("RAR 5 block payload is too large"))
    );
}

#[test]
fn builds_named_decode_tables_from_lengths() {
    let lengths = TableLengths {
        main: vec![1, 1],
        distance: vec![1, 1],
        align: vec![4; ALIGN_TABLE_SIZE],
        length: vec![1, 1],
    };

    let tables = DecodeTables::from_lengths(&lengths).unwrap();

    assert!(!tables.main.is_empty());
    assert!(!tables.distance.is_empty());
    assert!(!tables.align.is_empty());
    assert!(!tables.length.is_empty());
    assert!(!tables.align_mode);
    let copied = tables.clone();
    drop(tables);
    for table in [
        &copied.main,
        &copied.distance,
        &copied.align,
        &copied.length,
    ] {
        assert!(!table.is_empty());
        assert_eq!(table.decode(&mut BitReader::new(&[0])).unwrap(), 0);
    }
    assert!(!copied.align_mode);
}

#[test]
fn rejects_oversubscribed_rar50_huffman_tables() {
    assert!(matches!(
        HuffmanTable::from_lengths(&[1, 1, 1]),
        Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
    ));
    assert!(matches!(
        HuffmanTable::from_lengths(&[16]),
        Err(Error::InvalidData("RAR 5 Huffman length is too large"))
    ));
}

#[test]
fn decoders_reject_empty_and_invalid_main_huffman_codes() {
    for (main_length, code, code_bits, message) in [
        (0, 1, 1, "RAR 5 empty Huffman table"),
        (2, 0xffff, 16, "RAR 5 invalid Huffman code"),
    ] {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = main_length;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter {
            bytes: Buffer::from_vec(bytes),
            bit_pos,
        };
        writer.write_bits(code, code_bits);
        let payload_bits = writer.bit_pos;
        let input = encode_compressed_block(&writer.finish(), payload_bits, true, true).unwrap();

        assert_eq!(decode_lz(&input, 0, 1), Err(Error::InvalidData(message)));
        let result = Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(matches!(
            result,
            Err(StreamDecodeError::Decode(Error::InvalidData(error))) if error == message
        ));
    }
}

#[test]
fn detects_rar50_align_mode_when_align_lengths_are_not_uniform_four() {
    let mut align = vec![4; ALIGN_TABLE_SIZE];
    align[0] = 0;
    align[3] = 3;
    let lengths = TableLengths {
        main: vec![1, 1],
        distance: vec![1, 1],
        align,
        length: vec![1, 1],
    };

    let tables = DecodeTables::from_lengths(&lengths).unwrap();

    assert!(tables.align_mode);
}

#[test]
fn decodes_synthetic_literal_only_block() {
    let payload = literal_only_payload(b"ABBA");
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

    let output = decode_literal_only(&input, 0, 4).unwrap();

    assert_eq!(output, b"ABBA");
}

#[test]
fn encodes_literal_only_member_that_decoder_reads() {
    let data = b"literal-only RAR5 codec stream\nwith repeated words words words";
    let input = encode_literal_only(data, 0).unwrap();

    let output = decode_literal_only(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
}

#[test]
fn encodes_literal_only_rar70_table_shape_that_decoder_reads() {
    let data = b"small RAR7-compatible literal block";
    let input = encode_literal_only(data, 1).unwrap();

    let output = decode_literal_only(&input, 1, data.len()).unwrap();

    assert_eq!(output, data);
}

#[test]
fn encodes_empty_literal_only_member() {
    let input = encode_literal_only(b"", 0).unwrap();

    let output = decode_literal_only(&input, 0, 0).unwrap();

    assert!(output.is_empty());
}

#[test]
fn encodes_lz_member_with_same_member_matches() {
    let data = b"RAR5 match writer phrase. RAR5 match writer phrase. RAR5 match writer phrase.";
    let lz = encode_lz_member(data, 0).unwrap();
    let literal = encode_literal_only(data, 0).unwrap();

    let output = decode_lz(&lz, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert!(lz.len() < literal.len());
    assert!(
        encode_tokens(data, &[], EncodeOptions::default(), DISTANCE_TABLE_SIZE_50)
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { .. }))
    );
}

#[test]
fn frequency_weighted_huffman_lengths_shorten_common_symbols() {
    let mut frequencies = vec![1usize; 24];
    frequencies[3] = 1024;

    let lengths = huffman::lengths_for_frequencies(&frequencies, 15);

    assert!(lengths[3] < lengths[0]);
    assert!(lengths.iter().all(|&length| length <= 15));
}

#[test]
fn lz_encoder_uses_frequency_weighted_huffman_lengths() {
    let mut data = vec![b'a'; 200];
    data.extend_from_slice(b"bcdefghijklmnopqrstuvwxyz");
    let input = encode_lz_member_with_options(&data, 0, EncodeOptions::new(0)).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert!(lengths.main[b'a' as usize] < lengths.main[b'z' as usize]);
}

fn code_is_complete(lengths: &[u8]) -> bool {
    let max_len = lengths.iter().copied().max().unwrap_or(0);
    if max_len == 0 {
        return true;
    }
    let sum: u64 = lengths
        .iter()
        .filter(|&&len| len != 0)
        .map(|&len| 1u64 << (max_len - len))
        .sum();
    sum == (1u64 << max_len)
}

#[test]
fn degenerate_inputs_emit_complete_huffman_tables() {
    // Highly repetitive data collapses the distance/length/align tables to a
    // single symbol. Those tables must still be transmitted as *complete*
    // prefix codes, or strict RAR 5 decoders (7-Zip / WinRAR, which build
    // with `Full_or_Empty`) reject the archive with a spurious data error.
    // See issue #19.
    let inputs: &[Vec<u8>] = &[
        vec![b'a'; 4000],
        b"ab".repeat(4000),
        (0u8..16).cycle().take(50_000).collect(),
        b"lorem ipsum dolor sit amet ".repeat(2000),
    ];
    for data in inputs {
        let input = encode_lz_member_with_options(data, 0, EncodeOptions::new(0)).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        assert!(code_is_complete(&lengths.main), "main table incomplete");
        assert!(
            code_is_complete(&lengths.distance),
            "distance table incomplete"
        );
        assert!(code_is_complete(&lengths.length), "length table incomplete");
        assert!(code_is_complete(&lengths.align), "align table incomplete");

        assert_eq!(&decode_lz(&input, 0, data.len()).unwrap(), data);
    }
}

#[test]
fn lazy_lz_parser_defers_short_match_for_longer_next_match() {
    let input = b"abcdXbcdYYYYYYYYYYYYabcdYYYYYYYYYYYY";
    let greedy = encode_tokens(
        input,
        &[],
        EncodeOptions::new(MAX_MATCH_CANDIDATES),
        DISTANCE_TABLE_SIZE_50,
    );
    let lazy = encode_tokens(
        input,
        &[],
        EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
        DISTANCE_TABLE_SIZE_50,
    );
    let packed = encode_lz_member_with_options(
        input,
        0,
        EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
    )
    .unwrap();

    assert!(greedy
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { length: 4, .. })));
    assert!(lazy
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { length, .. } if *length > 8)));
    assert_eq!(decode_lz(&packed, 0, input.len()).unwrap(), input);
}

#[test]
fn match_selection_uses_length_then_distance_for_equal_scores() {
    let state = EncoderMatchState::default();
    let distance_size = DISTANCE_TABLE_SIZE_50;
    assert_eq!(
        estimated_match_cost(&state, 5, 1, distance_size).unwrap(),
        10
    );
    assert_eq!(
        estimated_match_cost(&state, 6, 262_144, distance_size).unwrap(),
        26
    );
    assert_eq!(
        estimated_match_cost(&state, 6, 262_143, distance_size).unwrap(),
        26
    );

    let mut best = None;
    consider_match_candidate(&mut best, &state, distance_size, 5, 1);
    consider_match_candidate(&mut best, &state, distance_size, 6, 262_144);
    assert_eq!((best.unwrap().length, best.unwrap().distance), (6, 262_144));
    consider_match_candidate(&mut best, &state, distance_size, 6, 262_143);
    assert_eq!((best.unwrap().length, best.unwrap().distance), (6, 262_143));

    let mut best = None;
    let longer = std::hint::black_box((6, 262_144));
    let shorter = std::hint::black_box((5, 1));
    consider_match_candidate(&mut best, &state, distance_size, longer.0, longer.1);
    consider_match_candidate(&mut best, &state, distance_size, shorter.0, shorter.1);
    assert_eq!((best.unwrap().length, best.unwrap().distance), (6, 262_144));
}

#[test]
fn cost_aware_match_selection_prefers_repeat_distance_token() {
    let pos = 64;
    let pattern = b"abcdefgh";
    let mut input: Vec<u8> = (0..96u8).map(|byte| byte.wrapping_mul(37)).collect();
    input[pos - 30..pos - 22].copy_from_slice(pattern);
    input[pos - 10..pos - 2].copy_from_slice(pattern);
    input[pos..pos + 8].copy_from_slice(pattern);
    input[pos + 8] = b'X';

    let mut finder = Rar50MatchFinder::new(input.len());
    for candidate in 0..pos {
        finder.insert(&input, candidate);
    }
    let state = EncoderMatchState {
        reps: [30, 0, 0, 0],
        last_length: 8,
    };

    let best = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &state,
        DISTANCE_TABLE_SIZE_50,
    )
    .unwrap();

    assert_eq!((best.length, best.distance), (8, 30));
}

#[test]
fn lazy_parser_uses_match_cost_not_only_match_length() {
    let pos = 600;
    let mut input: Vec<u8> = (0..700u16)
        .map(|value| value.wrapping_mul(73) as u8)
        .collect();
    input[pos - 512..pos - 504].copy_from_slice(b"ABCDEFGH");
    input[pos - 504] = b'Z';
    input[pos - 29..pos - 21].copy_from_slice(b"BCDEFGHI");
    input[pos - 30] = b'x';
    input[pos..pos + 9].copy_from_slice(b"ABCDEFGHI");

    let mut finder = Rar50MatchFinder::new(input.len());
    for candidate in 0..pos {
        finder.insert(&input, candidate);
    }
    let state = EncoderMatchState {
        reps: [30, 0, 0, 0],
        last_length: 8,
    };
    let current = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &state,
        DISTANCE_TABLE_SIZE_50,
    )
    .unwrap();

    assert_eq!((current.length, current.distance), (8, 512));
    assert!(should_lazy_emit_literal(
        &input,
        pos,
        &finder,
        EncodeOptions::default().with_lazy_matching(true),
        &state,
        DISTANCE_TABLE_SIZE_50,
        current,
    ));
}

#[test]
fn lazy_parser_uses_bounded_cost_lookahead() {
    let pos = 160;
    let mut input: Vec<u8> = (0..240u16)
        .map(|value| value.wrapping_mul(91) as u8)
        .collect();
    input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
    input[pos - 80..pos - 70].copy_from_slice(b"CDEFGHIJKL");
    input[pos..pos + 12].copy_from_slice(b"ABCDEFGHIJKL");

    let mut finder = Rar50MatchFinder::new(input.len());
    for candidate in 0..pos {
        finder.insert(&input, candidate);
    }
    let state = EncoderMatchState::default();
    let current = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &state,
        DISTANCE_TABLE_SIZE_50,
    )
    .unwrap();

    assert_eq!((current.length, current.distance), (8, 30));
    assert!(!should_lazy_emit_literal(
        &input,
        pos,
        &finder,
        EncodeOptions::default()
            .with_lazy_matching(true)
            .with_lazy_lookahead(1),
        &state,
        DISTANCE_TABLE_SIZE_50,
        current,
    ));
    assert!(should_lazy_emit_literal(
        &input,
        pos,
        &finder,
        EncodeOptions::default()
            .with_lazy_matching(true)
            .with_lazy_lookahead(2),
        &state,
        DISTANCE_TABLE_SIZE_50,
        current,
    ));
}

#[test]
fn lazy_parser_charges_for_skipped_literals() {
    let pos = 160;
    let mut input: Vec<u8> = (0..240u16)
        .map(|value| value.wrapping_mul(91) as u8)
        .collect();
    input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
    input[pos - 80..pos - 71].copy_from_slice(b"CDEFGHIJK");
    input[pos..pos + 12].copy_from_slice(b"ABCDEFGHIJKL");

    let mut finder = Rar50MatchFinder::new(input.len());
    for candidate in 0..pos {
        finder.insert(&input, candidate);
    }
    let state = EncoderMatchState::default();
    let current = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &state,
        DISTANCE_TABLE_SIZE_50,
    )
    .unwrap();

    let next = best_match(
        &input,
        pos + 2,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &state,
        DISTANCE_TABLE_SIZE_50,
    )
    .unwrap();

    assert!(next.score > current.score);
    assert!(next.score <= current.score + 16);
    assert!(!should_lazy_emit_literal(
        &input,
        pos,
        &finder,
        EncodeOptions::default()
            .with_lazy_matching(true)
            .with_lazy_lookahead(2),
        &state,
        DISTANCE_TABLE_SIZE_50,
        current,
    ));
}

#[test]
fn lazy_match_lookahead_stops_at_the_member_boundary() {
    let input = b"abcdef";
    let mut finder = Rar50MatchFinder::new(input.len());
    for pos in 0..4 {
        finder.insert(input, pos);
    }
    let current = MatchCandidate {
        length: 4,
        distance: 1,
        score: 1000,
    };

    assert_eq!(
        lazy_match_decision(
            input,
            4,
            input.len(),
            &finder,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(4),
            &EncoderMatchState::default(),
            DISTANCE_TABLE_SIZE_50,
            current,
        ),
        (false, None)
    );
}

fn encode_lz_member_with_filter(data: &[u8], kind: crate::FilterKind) -> Result<Vec<u8>> {
    Unpack50Encoder::new().encode_member_with_filter(data, 0, crate::FilterSpec::whole(kind))
}

#[test]
fn encodes_lz_member_with_delta_filter_record() {
    let data: Vec<u8> = (0..96).map(|index| (index * 7 + index / 3) as u8).collect();
    let input =
        encode_lz_member_with_filter(&data, crate::FilterKind::Delta { channels: 3 }).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn rejects_invalid_delta_filter_channel_count() {
    assert_eq!(
        encode_lz_member_with_filter(b"abc", crate::FilterKind::Delta { channels: 0 }),
        Err(Error::InvalidData(
            "RAR 5 DELTA filter channel count is invalid"
        ))
    );
    assert_eq!(
        encode_lz_member_with_filter(b"abc", crate::FilterKind::Delta { channels: 33 }),
        Err(Error::InvalidData(
            "RAR 5 DELTA filter channel count is invalid"
        ))
    );
}

#[test]
fn filter_record_integers_round_trip_at_every_encoded_width() {
    for value in [0, 0xff, 0x100, 0xffff, 0x1_0000, 0xff_ffff, 0x100_0000] {
        let mut writer = BitWriter::new();
        try_write_filter_data(&mut writer, value).unwrap();
        let encoded = writer.finish();
        assert_eq!(
            read_filter_data(&mut BitReader::new(&encoded)).unwrap(),
            value
        );
    }
}

#[test]
fn truncated_filter_fields_and_overflowing_start_fail() {
    assert_eq!(
        read_filter_data(&mut BitReader::new(&[])),
        Err(Error::NeedMoreInput)
    );
    assert_eq!(
        read_filter_data(&mut BitReader::new(&[0])),
        Err(Error::NeedMoreInput)
    );
    assert_eq!(
        read_filter(&mut BitReader::new(&[]), 0),
        Err(Error::NeedMoreInput)
    );
    assert_eq!(
        read_filter(&mut BitReader::new(&[0, 0]), 0),
        Err(Error::NeedMoreInput)
    );

    let mut type_missing = BitWriter::new();
    type_missing.write_bits(0, 4); // The preceding Huffman code's tail.
    try_write_filter_data(&mut type_missing, 0).unwrap();
    try_write_filter_data(&mut type_missing, 1).unwrap();
    let data = type_missing.finish();
    let mut bits = BitReader::new(&data);
    bits.bit_pos = 4;
    assert_eq!(read_filter(&mut bits, 0), Err(Error::NeedMoreInput));

    let mut channels_missing = BitWriter::new();
    try_write_filter_data(&mut channels_missing, 0).unwrap();
    try_write_filter_data(&mut channels_missing, 1).unwrap();
    channels_missing.write_bits(0, 3); // DELTA, without its channel field.
    assert_eq!(
        read_filter(&mut BitReader::new(&channels_missing.finish()), 0),
        Err(Error::NeedMoreInput)
    );

    let mut start_overflow = BitWriter::new();
    try_write_filter(
        &mut start_overflow,
        EncodeFilter {
            offset: 1,
            length: 1,
            filter_type: FilterType::E8,
            channels: 0,
        },
    )
    .unwrap();
    assert_eq!(
        read_filter(&mut BitReader::new(&start_overflow.finish()), usize::MAX),
        Err(Error::InvalidData("RAR 5 filter start overflows"))
    );
}

#[test]
fn filter_record_writer_rejects_invalid_delta_channels() {
    for channels in [0, MAX_DELTA_CHANNELS + 1] {
        let mut writer = BitWriter::new();
        assert_eq!(
            try_write_filter(
                &mut writer,
                EncodeFilter {
                    offset: 0,
                    length: 1,
                    filter_type: FilterType::Delta,
                    channels,
                },
            ),
            Err(Error::InvalidData(
                "RAR 5 DELTA filter channel count is invalid"
            ))
        );
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn filter_record_writer_rejects_fields_beyond_u32() {
    for (offset, length, message) in [
        (u32::MAX as usize + 1, 1, "RAR 5 filter offset is too large"),
        (0, u32::MAX as usize + 1, "RAR 5 filter length is too large"),
    ] {
        let mut writer = BitWriter::new();
        assert_eq!(
            try_write_filter(
                &mut writer,
                EncodeFilter {
                    offset,
                    length,
                    filter_type: FilterType::E8,
                    channels: 0,
                },
            ),
            Err(Error::InvalidData(message))
        );
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn filter_transform_rejects_offset_beyond_record_width() {
    let mut data = [0xe8, 0, 0, 0, 0];
    assert_eq!(
        encode_filter_data(
            Rar50Filter::E8,
            &mut data,
            u32::MAX as usize + 1,
            &Allowance::default(),
        ),
        Err(Error::InvalidData("RAR 5 filter offset is too large"))
    );
    assert_eq!(data, [0xe8, 0, 0, 0, 0]);
}

#[test]
fn encodes_lz_member_with_e8_filter_record() {
    let mut data = b"\xe8\0\0\0\0plain text after call".to_vec();
    data.extend_from_slice(&[0xe8, 3, 0, 0, 0, b'X']);
    let input = encode_lz_member_with_filter(&data, crate::FilterKind::E8).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn short_e8_filter_range_round_trips_without_rewriting_bytes() {
    let data = [0xe8, 0, 0, 0];
    let packed = encode_lz_member_with_filter(&data, crate::FilterKind::E8).unwrap();
    assert_eq!(decode_lz(&packed, 0, data.len()).unwrap(), data);
}

#[test]
fn rar50_e8_filter_wraps_file_offset_modulo_16m() {
    let file_offset = 0x0110_0000;
    let mut encoded = vec![0xe8];
    encoded.extend_from_slice(&0x0010_0c08u32.to_le_bytes());

    let mut decoded = encoded.clone();
    e8e9_decode(&mut decoded, file_offset, false);

    assert_eq!(&decoded[1..5], &0x0000_0c07u32.to_le_bytes());
    e8e9_encode(&mut decoded, file_offset, false);
    assert_eq!(decoded, encoded);
}

#[test]
fn streaming_decode_reports_filtered_member_with_typed_sentinel() {
    let data = b"\xe8\0\0\0\0plain text after call".to_vec();
    let input = encode_lz_member_with_filter(&data, crate::FilterKind::E8).unwrap();
    let mut reader = input.as_slice();
    let mut decoder = Unpack50Decoder::new();

    let error = decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut reader,
            0,
            data.len(),
            128 * 1024,
            false,
            |_chunk| Ok::<_, std::convert::Infallible>(()),
        )
        .unwrap_err();

    assert!(matches!(error, StreamDecodeError::FilteredMember));
}

#[test]
fn streaming_filter_records_reconstruct_buffered_output() {
    let cases = [
        (
            (0..96).map(|index| (index * 7 + index / 3) as u8).collect(),
            crate::FilterKind::Delta { channels: 3 },
        ),
        (
            b"\xe8\0\0\0\0plain text after call".to_vec(),
            crate::FilterKind::E8,
        ),
        (
            b"\xe9\0\0\0\0jump target through e9".to_vec(),
            crate::FilterKind::E8E9,
        ),
        (
            vec![0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'],
            crate::FilterKind::Arm,
        ),
    ];

    for (expected, kind) in cases {
        let packed = encode_lz_member_with_filter(&expected, kind).unwrap();
        let mut raw = Vec::new();
        let mut filters = Vec::new();
        Unpack50Decoder::new()
            .decode_to_sink_with_filters(
                &mut packed.as_slice(),
                0,
                expected.len(),
                DEFAULT_DICTIONARY_SIZE,
                false,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => raw.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            raw.extend(std::iter::repeat_n(byte, len));
                        }
                    }
                    Ok::<(), std::convert::Infallible>(())
                },
                Some(&mut |filter| {
                    filters.push(filter);
                    Ok::<(), std::convert::Infallible>(())
                }),
            )
            .unwrap();

        assert_eq!(filters.len(), 1);
        apply_filters_with_control(
            &mut raw,
            &filters,
            &crate::read_control::ReadControl::default(),
        )
        .unwrap();
        assert_eq!(raw, expected);
    }
}

#[test]
fn encodes_lz_member_with_e8e9_filter_record() {
    let data = b"\xe9\0\0\0\0jump target through e9".to_vec();
    let input = encode_lz_member_with_filter(&data, crate::FilterKind::E8E9).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn encodes_lz_member_with_ranged_e8e9_filter_record() {
    let mut data = b"\xe8\0\0\0\0plain prefix outside filter range".to_vec();
    let range_start = data.len();
    for _ in 0..16 {
        let operand_pos = data.len() + 1;
        data.push(0xe8);
        let relative = 0x7000u32.wrapping_sub(operand_pos as u32);
        data.extend_from_slice(&relative.to_le_bytes());
        data.extend_from_slice(b" code ");
    }
    let range = range_start..data.len();
    data.extend_from_slice(b"\xe9\0\0\0\0plain suffix outside filter range");

    let input = Unpack50Encoder::new()
        .encode_member_with_filter(
            &data,
            0,
            crate::FilterSpec::range(crate::FilterKind::E8E9, range),
        )
        .unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn encodes_lz_member_with_multiple_filter_records() {
    let mut data = b"\xe8\0\0\0\0plain prefix outside filters".to_vec();
    let first_start = data.len();
    data.extend_from_slice(b"\xe8\0\0\0\0first filtered cluster");
    let first_end = data.len();
    data.extend_from_slice(b"large plain middle outside filters");
    let second_start = data.len();
    data.extend_from_slice(b"\xe8\0\0\0\0second filtered cluster");
    let second_end = data.len();

    let input = Unpack50Encoder::new()
        .encode_member_with_filters(
            &data,
            0,
            &[
                crate::FilterSpec::range(crate::FilterKind::E8, first_start..first_end),
                crate::FilterSpec::range(crate::FilterKind::E8, second_start..second_end),
            ],
        )
        .unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, table_bits) = read_table_lengths(&input[block.payload.clone()], 0).unwrap();
    let tables = DecodeTables::from_lengths(&lengths).unwrap();
    let mut bits = BitReader {
        input: &input[block.payload],
        bit_pos: table_bits,
    };
    assert_eq!(tables.main.decode(&mut bits).unwrap(), 256);
    let first = read_filter(&mut bits, 0).unwrap();
    assert_eq!(tables.main.decode(&mut bits).unwrap(), 256);
    let second = read_filter(&mut bits, 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_eq!(first.start, first_start);
    assert_eq!(second.start, second_start);
}

#[test]
fn encodes_lz_member_with_arm_filter_record() {
    let data = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
    let input = encode_lz_member_with_filter(&data, crate::FilterKind::Arm).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[256], 0);
}

#[test]
fn arm_filter_uses_wrapping_address_arithmetic_at_u32_boundary() {
    let original = [0x04, 0x00, 0x00, 0xeb, 0x08, 0x00, 0x00, 0xeb];
    let mut filtered = original;

    arm_encode(&mut filtered, u32::MAX - 3);
    assert_ne!(filtered, original);
    arm_decode(&mut filtered, u32::MAX - 3);

    assert_eq!(filtered, original);
}

#[test]
fn solid_encoder_emits_rar50_matches_against_previous_member_history() {
    let first = b"RAR5 solid shared phrase alpha beta gamma\n".repeat(16);
    let second = b"RAR5 solid shared phrase alpha beta gamma\nsecond\n".repeat(4);
    let solid = encode_lz_member_with_history(&second, &first, 0).unwrap();
    let standalone = encode_lz_member(&second, 0).unwrap();
    let mut decoder = Unpack50Decoder::new();

    assert_eq!(
        decoder
            .decode_member(
                &encode_lz_member(&first, 0).unwrap(),
                0,
                first.len(),
                false,
                DecodeMode::Lz
            )
            .unwrap(),
        first
    );
    assert_eq!(
        decoder
            .decode_member(&solid, 0, second.len(), true, DecodeMode::Lz)
            .unwrap(),
        second
    );
    assert!(solid.len() < standalone.len());
}

#[test]
fn public_decoder_clone_keeps_independent_solid_history_and_tables() {
    let first = b"RAR5 independent decoder history ".repeat(32);
    let second = b"RAR5 independent decoder history ".repeat(8);
    let packed_first = encode_lz_member(&first, 0).unwrap();
    let packed_second = encode_lz_member_with_history(&second, &first, 0).unwrap();
    let mut original = Unpack50Decoder::new();
    assert_eq!(
        original
            .decode_member(&packed_first, 0, first.len(), false, DecodeMode::Lz)
            .unwrap(),
        first
    );
    let mut copied = original.clone();
    let other = b"a different non-solid member";
    assert_eq!(
        original
            .decode_member(
                &encode_lz_member(other, 0).unwrap(),
                0,
                other.len(),
                false,
                DecodeMode::Lz
            )
            .unwrap(),
        other
    );
    drop(original);
    assert_eq!(
        copied
            .decode_member(&packed_second, 0, second.len(), true, DecodeMode::Lz)
            .unwrap(),
        second
    );
}

#[test]
fn large_lz_members_are_split_into_multiple_compressed_blocks() {
    // Two halves that do not look alike, so the second cannot be spelled
    // with the first's tables and gets its own block.
    let mut data = wordy_text(LZ_BLOCK_SIZE);
    data.extend((0..LZ_BLOCK_SIZE).map(|index| (index as u8).wrapping_mul(37)));
    let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap();
    let mut cursor = std::io::Cursor::new(encoded.as_slice());
    let first = read_compressed_block(&mut cursor).unwrap();
    let second = read_compressed_block(&mut cursor).unwrap();
    let mut decoder = Unpack50Decoder::new();

    assert!(!first.header.is_last);
    assert!(second.header.is_last);
    assert_eq!(
        decoder
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap(),
        data
    );
}

#[test]
fn a_member_that_does_not_move_is_left_in_one_block() {
    // Every chunk of this has the same byte distribution, so a fresh table
    // set per chunk would describe nothing the first one did not.
    let data = vec![0u8; LZ_BLOCK_SIZE * 4];
    let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap();
    let mut cursor = std::io::Cursor::new(encoded.as_slice());
    let only = read_compressed_block(&mut cursor).unwrap();
    let mut decoder = Unpack50Decoder::new();

    assert!(only.header.is_last, "a still member was cut up anyway");
    assert_eq!(
        decoder
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap(),
        data
    );
}

#[test]
fn a_block_never_grows_past_the_cap() {
    let data = vec![0u8; MAX_LZ_BLOCK_SIZE * 2 + LZ_BLOCK_SIZE];
    let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap();
    let mut cursor = std::io::Cursor::new(encoded.as_slice());
    let mut blocks = 0;
    loop {
        let block = read_compressed_block(&mut cursor).unwrap();
        blocks += 1;
        if block.header.is_last {
            break;
        }
    }

    // Uniform to the last byte, so only the cap can be ending these.
    assert_eq!(blocks, 3, "the cap stopped ending blocks");
}

#[test]
fn splitter_refuses_to_extend_an_empty_block_or_with_an_empty_chunk() {
    let mut splitter = BlockSplitter::new();
    assert!(!splitter.extends(b"AAAA"));
    splitter.accept(b"AAAA");
    assert!(!splitter.extends(b""));
    assert!(splitter.extends(b"AAAA"));
}

#[test]
fn the_splitter_reads_only_what_both_writers_can_see() {
    // The streaming writer decides with the open block's bytes and the next
    // chunk, and nothing else. Same bytes in, same answer, however the
    // chunks were handed over.
    let mut whole = BlockSplitter::new();
    whole.accept(&vec![7u8; 4096]);
    let mut piecemeal = BlockSplitter::new();
    for _ in 0..4 {
        piecemeal.accept(&vec![7u8; 1024]);
    }

    let next = vec![7u8; 4096];
    assert!(whole.extends(&next));
    assert_eq!(whole.extends(&next), piecemeal.extends(&next));

    let moved: Vec<u8> = (0..4096u32).map(|index| index as u8).collect();
    assert!(!whole.extends(&moved), "a block swallowed unlike data");
    assert_eq!(whole.extends(&moved), piecemeal.extends(&moved));
}

/// Words drawn from a small vocabulary in a repeating-but-not-periodic
/// order. Every position has several matches at different distances and
/// lengths, which is the case where taking the longest one and checking
/// two bytes ahead leaves bits on the floor.
fn wordy_text(len: usize) -> Vec<u8> {
    const WORDS: [&str; 12] = [
        "the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog ", "and ", "then ",
        "runs ", "away ",
    ];
    let mut out = Vec::with_capacity(len + 16);
    let mut noise = 0x2545_f491_4f6c_dd1du64;
    while out.len() < len {
        noise ^= noise << 13;
        noise ^= noise >> 7;
        noise ^= noise << 17;
        out.extend_from_slice(WORDS[(noise >> 40) as usize % WORDS.len()].as_bytes());
        if (noise >> 20).is_multiple_of(11) {
            out.push(b'\n');
        }
    }
    out.truncate(len);
    out
}

#[test]
fn the_optimal_parse_round_trips() {
    for data in [
        Vec::new(),
        b"a".to_vec(),
        b"abcabcabcabc".to_vec(),
        wordy_text(3),
        wordy_text(LZ_BLOCK_SIZE + 4096),
        vec![0u8; LZ_BLOCK_SIZE * 2],
    ] {
        let options = EncodeOptions::new(64).with_optimal_parse(true);
        let encoded = encode_lz_member_with_options(&data, 0, options).unwrap();
        let decoded = Unpack50Decoder::new()
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap();
        assert_eq!(decoded, data, "{} bytes did not round trip", data.len());
    }
}

#[test]
fn optimal_parse_with_matching_disabled_emits_literals() {
    let data = b"ABABABAB";
    let tokens = collected_optimal_tokens(
        data,
        EncodeOptions::new(0).with_optimal_parse(true),
        DISTANCE_TABLE_SIZE_50,
        None,
    );

    assert_eq!(
        tokens,
        data.iter()
            .copied()
            .map(EncodeToken::Literal)
            .collect::<Vec<_>>()
    );
}

#[test]
fn optimal_long_match_commitment_prunes_shorter_candidate_endpoints() {
    let history = 2;
    let span = NICE_MATCH_LENGTH + 8;
    let combined = vec![0; history + span];
    let mut price = vec![u32::MAX; span + 1];
    let mut arrive_length = vec![0; span + 1];
    let mut arrive_distance = vec![0; span + 1];
    let mut arrive_reps = vec![[0; 4]; span + 1];
    let mut arrive_last_length = vec![0; span + 1];
    price[0] = 0;
    arrive_reps[0] = [0, (history + 1) as u32, 0, 0];
    let runs = [(4, 1), (NICE_MATCH_LENGTH as u32, 2)];
    let mut starts = vec![2; span + 1];
    starts[0] = 0;
    let mut reaches = [(0, 0, 0); 8];

    price_optimal_paths(
        &combined,
        history..history + span,
        EncodeOptions::new(32).with_optimal_parse(true),
        DISTANCE_TABLE_SIZE_50,
        None,
        &runs,
        &starts,
        OptimalSlices {
            price: &mut price,
            arrive_length: &mut arrive_length,
            arrive_distance: &mut arrive_distance,
            arrive_reps: &mut arrive_reps,
            arrive_last_length: &mut arrive_last_length,
        },
        &mut reaches,
    );

    assert_eq!(price[4], u32::MAX);
    assert_ne!(price[NICE_MATCH_LENGTH], u32::MAX);
    assert_eq!(arrive_length[NICE_MATCH_LENGTH], NICE_MATCH_LENGTH as u32);
    assert_eq!(arrive_distance[NICE_MATCH_LENGTH], 2);
}

#[test]
fn the_optimal_parse_beats_lazy_matching_at_the_same_depth() {
    let data = wordy_text(256 * 1024);
    let base = EncodeOptions::new(64);
    let lazy = encode_lz_member_with_options(
        &data,
        0,
        base.with_lazy_matching(true).with_lazy_lookahead(2),
    )
    .unwrap();
    let optimal = encode_lz_member_with_options(&data, 0, base.with_optimal_parse(true)).unwrap();

    assert!(
        optimal.len() < lazy.len(),
        "optimal parse packed {} against lazy matching's {}",
        optimal.len(),
        lazy.len(),
    );
}

/// One chunk, copied once per round with fresh literals in between, so
/// every match after the first sits at the same distance and every one of
/// them is separated from the last by literals.
fn strided_repeats(gap: usize, rounds: usize) -> Vec<u8> {
    let mut noise = 0x1234_5678u32;
    let mut byte = move || {
        noise = noise.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (noise >> 24) as u8
    };
    let chunk: Vec<u8> = (0..48).map(|_| byte()).collect();
    let mut data = chunk.clone();
    for _ in 0..rounds {
        data.extend((0..gap).map(|_| byte()));
        data.extend_from_slice(&chunk);
    }
    data
}

#[test]
fn the_optimal_parse_reuses_a_distance_across_the_literals_between_matches() {
    let data = strided_repeats(8, 3000);
    let options = EncodeOptions::new(64).with_optimal_parse(true);
    let distance_size = DISTANCE_TABLE_SIZE_50;
    let tokens = collected_optimal_tokens(&data, options, distance_size, None);

    let mut state = EncoderMatchState::default();
    let (mut repeated, mut fresh) = (0, 0);
    for token in &tokens {
        if let EncodeToken::Match { length, distance } = *token {
            match state.encode_match(length, distance, distance_size).unwrap() {
                EncodedMatch::New { .. } => fresh += 1,
                _ => repeated += 1,
            }
            state.remember(length, distance);
        }
    }

    // Every match here is at the one distance the data repeats at, so all
    // but the first should be priced against what the path remembers.
    // Carrying only the arriving match instead left this at 244 repeated
    // against 2,756 fresh, because a literal wiped the distance before the
    // next match could be priced against it.
    assert!(
        fresh * 10 < repeated,
        "{repeated} matches reused a distance against {fresh} that did not",
    );
}

#[test]
fn reusing_a_remembered_distance_packs_strided_data_smaller() {
    let data = strided_repeats(8, 3000);
    let options = EncodeOptions::new(64).with_optimal_parse(true);
    let packed = encode_lz_member_with_options(&data, 0, options).unwrap();

    // 26,178 bytes when the path carries its remembered distances, 28,447
    // when it does not. The bound sits between the two.
    assert!(
        packed.len() < 27_000,
        "{} bytes packed from {}",
        packed.len(),
        data.len(),
    );
    let decoded = decode_lz(&packed, 0, data.len()).unwrap();
    assert_eq!(decoded, data);
}

/// Once the parse commits to a match it steps over the bytes that match
/// covers, so a block that repeats is emitted as whole matches back to back
/// rather than as the cheapest split of each one. That is the difference
/// between the parse pricing 4096 positions per match and pricing one, which
/// is worth 53.41s against 1.19s on a mebibyte of this.
#[test]
fn the_optimal_parse_steps_over_a_match_it_has_committed_to() {
    let block: Vec<u8> = (0..4096u32)
        .map(|index| (index * 7 + (index >> 5)) as u8)
        .collect();
    let data = block.repeat(16);
    let options = EncodeOptions::new(64).with_optimal_parse(true);
    let tokens = collected_optimal_tokens(&data, options, DISTANCE_TABLE_SIZE_50, None);

    let first = tokens
        .iter()
        .position(|token| {
            matches!(token, EncodeToken::Match { length, .. } if *length >= NICE_MATCH_LENGTH)
        })
        .expect("no match reached the length the parse commits at");
    for token in &tokens[first..] {
        let EncodeToken::Match { length, .. } = *token else {
            panic!("{token:?} interrupts the committed matches");
        };
        assert!(
            length >= NICE_MATCH_LENGTH,
            "a {length}-byte match interrupts the committed ones",
        );
    }
    // The first block is the only one with nothing behind it to match.
    assert_eq!(tokens.len() - first, data.len() / block.len() - 1);

    let packed = encode_lz_member_with_options(&data, 0, options).unwrap();
    assert_eq!(decode_lz(&packed, 0, data.len()).unwrap(), data);
}

#[test]
fn repricing_against_the_first_pass_beats_the_flat_guess() {
    let data = wordy_text(256 * 1024);
    let options = EncodeOptions::new(64).with_optimal_parse(true);
    let distance_size = DISTANCE_TABLE_SIZE_50;
    let guessed = collected_optimal_tokens(&data, options, distance_size, None);
    let lengths = table_lengths_for_tokens(&guessed, distance_size).unwrap();
    let prices = TokenPrices {
        lengths: lengths.slices(),
    };
    let repriced = collected_optimal_tokens(&data, options, distance_size, Some(&prices));

    let bits = |tokens: &[EncodeToken]| -> usize {
        let lengths = table_lengths_for_tokens(tokens, distance_size).unwrap();
        let prices = TokenPrices {
            lengths: lengths.slices(),
        };
        let mut state = EncoderMatchState::default();
        let mut total = 0;
        for token in tokens {
            match *token {
                EncodeToken::Filter(_) => {}
                EncodeToken::Literal(byte) => total += prices.literal(byte),
                EncodeToken::Match { length, distance } => {
                    total += prices
                        .match_cost(&state, length, distance, distance_size)
                        .unwrap();
                    state.remember(length, distance);
                }
            }
        }
        total
    };

    assert!(
        bits(&repriced) < bits(&guessed),
        "repriced {} bits against the guess's {}",
        bits(&repriced),
        bits(&guessed),
    );
}

#[test]
fn blocks_are_short_enough_to_refit_the_tables_when_the_data_changes() {
    // Four stretches, one block each, every one drawing from its own
    // sixteen bytes. A table per block codes sixteen symbols; one table
    // over the member codes sixty-four. Raising LZ_BLOCK_SIZE trades the
    // first for the second, which is what cost the corpus 6.4% until the
    // block came down from a mebibyte.
    let stretch_len = 64 * 1024;
    let mut data = Vec::with_capacity(stretch_len * 4);
    let mut noise = 0x2545_f491_4f6c_dd1du64;
    for stretch in 0..4u8 {
        for _ in 0..stretch_len {
            noise ^= noise << 13;
            noise ^= noise >> 7;
            noise ^= noise << 17;
            data.push(stretch * 16 + (noise >> 40) as u8 % 16);
        }
    }
    let options = EncodeOptions::new(0);

    let blocked = encode_lz_member_with_options(&data, 0, options).unwrap();
    let single = encode_lz_block(&data, &[], 0, &[], options, true, None).unwrap();

    assert!(
        blocked.len() * 100 < single.len() * 90,
        "member blocks {} did not beat one block over the lot {single}",
        blocked.len(),
        single = single.len(),
    );
}

#[test]
fn large_filtered_lz_members_split_filter_records_by_block() {
    let last_block_start = FILTERED_LZ_BLOCK_SIZE * 2;
    let mut data: Vec<_> = (0..last_block_start + 512)
        .map(|index| index as u8)
        .collect();
    data[256] = 0xe8;
    data[257..261].copy_from_slice(&0x20u32.to_le_bytes());
    data[last_block_start + 64] = 0xe8;
    data[last_block_start + 65..last_block_start + 69].copy_from_slice(&0x40u32.to_le_bytes());

    let encoded = Unpack50Encoder::with_options(EncodeOptions::new(0))
        .encode_member_with_filter(
            &data,
            0,
            crate::FilterSpec::range(crate::FilterKind::E8, 0..data.len()),
        )
        .unwrap();
    let mut cursor = std::io::Cursor::new(encoded.as_slice());
    let first = read_compressed_block(&mut cursor).unwrap();
    let mut blocks = 1usize;
    let mut last_is_last = first.header.is_last;
    while cursor.position() < encoded.len() as u64 {
        last_is_last = read_compressed_block(&mut cursor).unwrap().header.is_last;
        blocks += 1;
    }
    let mut decoder = Unpack50Decoder::new();

    assert!(!first.header.is_last);
    assert!(last_is_last);
    assert!(blocks > 2);
    assert_eq!(
        decoder
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap(),
        data
    );
}

/// The window a filtered member is parsed in reaches back into the
/// history the solid stream carries, and keeps reaching for every block
/// of it rather than only the first. Each block used to be handed its own
/// copy of that history and its own finder rebuilt from it, which cost
/// the member a re-insert per block and reached exactly this far.
#[test]
fn a_solid_filtered_member_matches_history_from_every_block() {
    // Bytes that do not compress on their own, so matching the history is
    // the only way this member gets small.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut earlier = Vec::with_capacity(FILTERED_LZ_BLOCK_SIZE * 3);
    while earlier.len() < FILTERED_LZ_BLOCK_SIZE * 3 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        earlier.extend_from_slice(&state.to_le_bytes());
    }
    earlier[512] = 0xe8;
    earlier[513..517].copy_from_slice(&0x30u32.to_le_bytes());
    // Repeating what came before means every block of this member, not
    // just its first, has something to match against the history.
    let data = earlier.clone();
    let filter = crate::FilterSpec::range(crate::FilterKind::E8, 0..data.len());

    let mut solid = Unpack50Encoder::with_options(EncodeOptions::new(16));
    solid
        .state
        .history
        .remember(&earlier, solid.state.options.max_match_distance)
        .unwrap();
    let against_history = solid
        .encode_member_with_filter(&data, 0, filter.clone())
        .unwrap();
    let alone = Unpack50Encoder::with_options(EncodeOptions::new(16))
        .encode_member_with_filter(&data, 0, filter)
        .unwrap();

    assert!(
        against_history.len() * 20 < alone.len(),
        "a member repeating its history packed to {} against {alone} on its own",
        against_history.len(),
        alone = alone.len(),
    );
}

#[test]
fn filters_are_split_before_rar_reader_filter_limit() {
    let data = vec![0u8; FILTERED_LZ_BLOCK_SIZE + 1];
    let encoded =
        Unpack50Encoder::with_options(EncodeOptions::new(0).with_max_match_distance(128 * 1024))
            .encode_member_with_filter(
                &data,
                0,
                crate::FilterSpec::whole(crate::FilterKind::Delta { channels: 4 }),
            )
            .unwrap();
    let mut cursor = std::io::Cursor::new(encoded.as_slice());
    let first = read_compressed_block(&mut cursor).unwrap();
    let second = read_compressed_block(&mut cursor).unwrap();
    let mut decoder = Unpack50Decoder::new();

    assert!(!first.header.is_last);
    assert!(second.header.is_last);
    assert_eq!(
        decoder
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap(),
        data
    );
}

#[test]
fn solid_encoder_history_limit_follows_encode_options_dictionary() {
    let mut encoder = Unpack50Encoder::with_options(
        EncodeOptions::new(0).with_max_match_distance(DEFAULT_DICTIONARY_SIZE + 1024),
    );
    encoder
        .state
        .history
        .remember(
            &vec![0x41; DEFAULT_DICTIONARY_SIZE + 512],
            encoder.state.options.max_match_distance,
        )
        .unwrap();

    assert_eq!(encoder.state.history.len(), DEFAULT_DICTIONARY_SIZE + 512);

    let mut capped =
        Unpack50Encoder::with_options(EncodeOptions::new(0).with_max_match_distance(1024));
    capped
        .state
        .history
        .remember(&vec![0x42; 4096], capped.state.options.max_match_distance)
        .unwrap();

    assert_eq!(capped.state.history.len(), 1024);
}

#[test]
fn cloned_encoder_keeps_an_independent_solid_history() {
    let first = b"prefix repeated across solid members";
    let second = b"prefix repeated across solid members with a suffix";
    let mut original = Unpack50Encoder::with_options(EncodeOptions::new(16));
    let packed_first = original.encode_member(first, 0).unwrap();
    let mut cloned = original.clone();
    let packed_original = original.encode_member(second, 0).unwrap();
    let packed_clone = cloned.encode_member(second, 0).unwrap();
    assert_eq!(packed_clone, packed_original);

    let mut decoder = Unpack50Decoder::new();
    assert_eq!(
        decoder
            .decode_member(&packed_first, 0, first.len(), false, DecodeMode::Lz)
            .unwrap(),
        first
    );
    assert_eq!(
        decoder
            .decode_member(&packed_clone, 0, second.len(), true, DecodeMode::Lz)
            .unwrap(),
        second
    );

    let clone_history = cloned.state.history.to_vec();
    original
        .encode_member(b"a divergent third member", 0)
        .unwrap();
    assert_eq!(cloned.state.history.to_vec(), clone_history);
}

#[test]
fn encodes_lz_member_with_last_length_repeat_symbols() {
    let data = b"abcdXabcdYabcdZabcd";
    let input = encode_lz_member(data, 0).unwrap();
    let block = parse_compressed_block(&input).unwrap();
    let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

    let output = decode_lz(&input, 0, data.len()).unwrap();

    assert_eq!(output, data);
    assert_ne!(lengths.main[257], 0);
}

#[test]
fn encodes_lz_member_using_rar70_distance_table_shape() {
    let data = b"RAR7-compatible repeated phrase repeated phrase repeated phrase";
    let input = encode_lz_member(data, 1).unwrap();

    let output = decode_lz(&input, 1, data.len()).unwrap();

    assert_eq!(output, data);
}

#[test]
fn decode_member_from_reader_accepts_incremental_input() {
    struct OneByteReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Read for OneByteReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            out[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    let payload = literal_only_payload(b"ABBA");
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
    let mut reader = OneByteReader {
        data: &input,
        pos: 0,
    };
    let mut decoder = Unpack50Decoder::new();

    let output = decoder
        .decode_member_from_reader(&mut reader, 0, 4, false, DecodeMode::LiteralOnly)
        .unwrap();

    assert_eq!(output, b"ABBA");
}

#[test]
fn decoders_stop_at_declared_size_before_a_nonfinal_block() {
    let payload = literal_only_payload(b"AB");
    let block = encode_compressed_block(&payload, payload.len() * 8, true, false).unwrap();
    let mut input = block.clone();
    input.extend_from_slice(b"not another block");

    assert_eq!(decode_literal_only(&input, 0, 2).unwrap(), b"AB");
    let mut reader = input.as_slice();
    let mut streamed = Vec::new();
    Unpack50Decoder::new()
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut reader,
            0,
            2,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => streamed.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        streamed.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::convert::Infallible>(())
            },
        )
        .unwrap();
    assert_eq!(streamed, b"AB");
    assert_eq!(reader, &input[block.len()..]);
}

#[test]
fn decodes_synthetic_new_match_block() {
    let payload = new_match_payload();
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

    let output = decode_lz(&input, 0, 4).unwrap();

    assert_eq!(output, b"ABAB");
}

#[test]
fn decodes_synthetic_last_length_match_block() {
    let payload = repeat_payload(257);
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

    let output = decode_lz(&input, 0, 6).unwrap();

    assert_eq!(output, b"ABABAB");
}

#[test]
fn decodes_synthetic_repeat_distance_match_block() {
    let payload = repeat_payload(258);
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

    let output = decode_lz(&input, 0, 6).unwrap();

    assert_eq!(output, b"ABABAB");
}

#[test]
fn rejects_literal_only_block_without_tables() {
    let input = encode_compressed_block(&[0], 8, false, true).unwrap();

    assert_eq!(
        decode_literal_only(&input, 0, 1),
        Err(Error::InvalidData("RAR 5 block reuses missing tables"))
    );
}

#[test]
fn decoders_propagate_malformed_table_errors() {
    let mut incomplete = BitWriter::new();
    for _ in 0..LEVEL_TABLE_SIZE {
        incomplete.write_bits(5, 4);
    }
    let incomplete = incomplete.finish();

    let mut invalid = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    invalid.main[..3].fill(1); // Three one-bit codes overfill the tree.
    let (invalid, invalid_bits) = encode_table_lengths_with_bit_count(&invalid, 0).unwrap();

    for (payload, payload_bits, expected) in [
        (
            incomplete.as_slice(),
            incomplete.len() * 8,
            Error::NeedMoreInput,
        ),
        (
            invalid.as_slice(),
            invalid_bits,
            Error::InvalidData("RAR 5 oversubscribed Huffman table"),
        ),
    ] {
        let input = encode_compressed_block(payload, payload_bits, true, true).unwrap();
        assert_eq!(
            Unpack50Decoder::new().decode_member_with_dictionary(
                &input,
                0,
                1,
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::LiteralOnly,
            ),
            Err(expected.clone())
        );
        let result = Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(matches!(result, Err(StreamDecodeError::Decode(error)) if error == expected));
    }
}

#[test]
fn decoders_reject_invalid_packed_huffman_symbol() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1; // Only the zero bit names a symbol.
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };
    writer.write_bits(0x7fff, 15); // No prefix can name 'A'.
    let payload_bits = writer.bit_pos;
    let input = encode_compressed_block(&writer.finish(), payload_bits, true, true).unwrap();
    let expected = Error::InvalidData("RAR 5 invalid Huffman code");

    assert_eq!(
        Unpack50Decoder::new().decode_member_with_dictionary(
            &input,
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            DecodeMode::LiteralOnly,
        ),
        Err(expected.clone())
    );
    let result = Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
        &mut input.as_slice(),
        0,
        1,
        DEFAULT_DICTIONARY_SIZE,
        false,
        |_chunk| Ok::<(), std::convert::Infallible>(()),
    );
    assert!(matches!(result, Err(StreamDecodeError::Decode(error)) if error == expected));
}

#[test]
fn decoders_report_truncated_match_extra_bits() {
    for (length_slot, distance_slot, packed) in [
        // Seven literals and a new match. Main symbol 270 means length
        // slot 8, which needs one more bit.
        (8, 0, 0b0000_0001),
        // Six literals, a new match, and distance slot 4. Its extra bit
        // is absent after the one-bit distance code.
        (0, 4, 0b0000_0010),
    ] {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 1;
        lengths.main[262 + length_slot] = 1;
        lengths.distance[distance_slot] = 1;
        let (tables, table_bits) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut input = encode_compressed_block(&tables, table_bits, true, false).unwrap();
        input.extend(encode_compressed_block(&[packed], 8, false, true).unwrap());

        let mut buffered = Unpack50Decoder::new();
        let mut cursor = std::io::Cursor::new(&input);
        assert_eq!(
            buffered.decode_member_from_reader_with_dictionary(
                &mut cursor,
                0,
                12,
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::Lz,
            ),
            Err(Error::NeedMoreInput),
            "length slot {length_slot}, distance slot {distance_slot}"
        );
        assert!(buffered.state.tables.is_none()); // Error occurred before the block completed.
        let mut streaming = Unpack50Decoder::new();
        let result = streaming.decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            12,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(matches!(
            result,
            Err(StreamDecodeError::Decode(Error::NeedMoreInput))
        ));
        assert!(streaming.state.tables.is_none());
    }
}

#[test]
fn decoders_reject_rar7_distance_slot_above_bit_limit() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_70],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[262] = 1; // New match with length slot 0.
    lengths.distance[66] = 1; // (66 - 2) / 2 = 32 extra bits.
    let (tables, table_bits) = encode_table_lengths_with_bit_count(&lengths, 1).unwrap();
    let mut input = encode_compressed_block(&tables, table_bits, true, false).unwrap();
    input.extend(encode_compressed_block(&[0], 2, false, true).unwrap());
    let expected = Error::InvalidData("RAR 5 distance slot is too large");

    let mut buffered = Unpack50Decoder::new();
    assert_eq!(
        buffered.decode_member_with_dictionary(
            &input,
            1,
            2,
            DEFAULT_DICTIONARY_SIZE,
            false,
            DecodeMode::Lz,
        ),
        Err(expected.clone())
    );
    assert!(buffered.state.tables.is_none());
    let mut streaming = Unpack50Decoder::new();
    let result = streaming.decode_member_from_reader_with_dictionary_to_sink(
        &mut input.as_slice(),
        1,
        2,
        DEFAULT_DICTIONARY_SIZE,
        false,
        |_chunk| Ok::<(), std::convert::Infallible>(()),
    );
    assert!(matches!(result, Err(StreamDecodeError::Decode(error)) if error == expected));
    assert!(streaming.state.tables.is_none());
}

#[test]
fn solid_decoders_report_truncated_repeat_length() {
    let bootstrap = new_match_payload();
    let bootstrap = encode_compressed_block(&bootstrap, bootstrap.len() * 8, true, true).unwrap();

    for (length_slot, packed) in [
        (0, 0b0000_0001), // Seven literals and a repeat, without its length code.
        (8, 0b0000_0010), // Six literals, repeat, length slot 8; extra bit absent.
    ] {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 1;
        lengths.main[258] = 1;
        lengths.length[length_slot] = 1;
        let (tables, table_bits) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut input = encode_compressed_block(&tables, table_bits, true, false).unwrap();
        input.extend(encode_compressed_block(&[packed], 8, false, true).unwrap());

        let mut buffered = Unpack50Decoder::new();
        assert_eq!(
            buffered
                .decode_member_with_dictionary(
                    &bootstrap,
                    0,
                    4,
                    DEFAULT_DICTIONARY_SIZE,
                    false,
                    DecodeMode::Lz,
                )
                .unwrap(),
            b"ABAB"
        );
        assert_eq!(
            buffered.decode_member_with_dictionary(
                &input,
                0,
                20,
                DEFAULT_DICTIONARY_SIZE,
                true,
                DecodeMode::Lz,
            ),
            Err(Error::NeedMoreInput)
        );
        assert!(buffered.state.tables.is_none());

        let mut streaming = Unpack50Decoder::new();
        streaming
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut bootstrap.as_slice(),
                0,
                4,
                DEFAULT_DICTIONARY_SIZE,
                false,
                |_chunk| Ok::<(), std::convert::Infallible>(()),
            )
            .unwrap();
        let result = streaming.decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            20,
            DEFAULT_DICTIONARY_SIZE,
            true,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(matches!(
            result,
            Err(StreamDecodeError::Decode(Error::NeedMoreInput))
        ));
        assert!(streaming.state.tables.is_none());
    }
}

#[test]
fn decoders_report_malformed_new_match_distance_fields() {
    let mut invalid_align = BitWriter::new();
    invalid_align.write_bits(0, 1); // New match, length slot 0.
    invalid_align.write_bits(0, 1); // Distance slot 10.
    invalid_align.write_bits(0x7fff, 15); // No alignment prefix names a symbol.
    let cases = [
        (
            None,
            false,
            0,
            vec![0],
            1,
            Error::InvalidData("RAR 5 empty Huffman table"),
        ),
        (
            Some(12),
            true,
            6,
            vec![0b0000_0010],
            8,
            Error::NeedMoreInput,
        ),
        (
            Some(10),
            true,
            0,
            invalid_align.finish(),
            17,
            Error::InvalidData("RAR 5 invalid Huffman code"),
        ),
    ];

    for (distance_slot, align_mode, literal_count, packed, packed_bits, expected) in cases {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[262] = 1;
        if literal_count != 0 {
            lengths.main[b'A' as usize] = 1;
        }
        if let Some(slot) = distance_slot {
            lengths.distance[slot] = 1;
        }
        if align_mode {
            lengths.align[0] = 1;
        }
        let (tables, table_bits) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut input = encode_compressed_block(&tables, table_bits, true, false).unwrap();
        input.extend(encode_compressed_block(&packed, packed_bits, false, true).unwrap());

        let mut buffered = Unpack50Decoder::new();
        assert_eq!(
            buffered.decode_member_with_dictionary(
                &input,
                0,
                20,
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::Lz,
            ),
            Err(expected.clone()),
            "distance slot {distance_slot:?}"
        );
        assert!(buffered.state.tables.is_none());
        let mut streaming = Unpack50Decoder::new();
        let result = streaming.decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            20,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(matches!(result, Err(StreamDecodeError::Decode(error)) if error == expected));
        assert!(streaming.state.tables.is_none());
    }
}

#[test]
fn decodes_length_slots() {
    assert_eq!(slot_to_length(0, 0).unwrap(), 2);
    assert_eq!(slot_to_length(7, 0).unwrap(), 9);
    assert_eq!(slot_to_length(8, 0).unwrap(), 10);
    assert_eq!(slot_to_length(8, 1).unwrap(), 11);
    assert_eq!(slot_to_length(11, 1).unwrap(), 17);
    assert_eq!(slot_to_length(12, 3).unwrap(), 21);
    assert_eq!(length_slot_extra_bits(43), 9);
}

#[test]
fn rejects_out_of_range_length_slots_and_extras() {
    assert!(slot_to_length(103, (1 << 24) - 1).is_ok());
    assert_eq!(
        slot_to_length(8, 2),
        Err(Error::InvalidData("RAR 5 length extra bits exceed slot"))
    );
    assert_eq!(
        slot_to_length(104, 0),
        Err(Error::InvalidData("RAR 5 length slot is too large"))
    );
}

#[test]
fn encoder_code_table_rejects_oversubscribed_lengths() {
    assert_eq!(
        EncoderCodeTable::from_lengths(&[1, 1, 1], &Allowance::default()).err(),
        Some(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
    );
}

#[test]
fn decodes_distance_slots() {
    assert_eq!(slot_to_distance(0, 0).unwrap(), 1);
    assert_eq!(slot_to_distance(3, 0).unwrap(), 4);
    assert_eq!(distance_slot_bit_count(4).unwrap(), 1);
    assert_eq!(slot_to_distance(4, 0).unwrap(), 5);
    assert_eq!(slot_to_distance(4, 1).unwrap(), 6);
    assert_eq!(distance_slot_bit_count(10).unwrap(), 4);
    assert_eq!(slot_to_distance(10, 15).unwrap(), 48);
}

#[cfg(target_pointer_width = "64")]
#[test]
fn encoder_rejects_distance_beyond_rar50_table() {
    // A caller may raise max_match_distance beyond the RAR 5.0 table's
    // range. Such a match must fail before indexing the frequency table.
    assert_eq!(
        EncoderMatchState::default().encode_match(4, 1usize << 40, DISTANCE_TABLE_SIZE_50),
        Err(Error::InvalidData("RAR 5 match distance is too large"))
    );
}

#[test]
fn match_pricing_and_encoding_reject_invalid_internal_candidates() {
    let mut repeated = EncoderMatchState::default();
    repeated.reps[0] = 1;
    repeated.last_length = 2;
    let too_short = Error::InvalidData("RAR 5 match length is too short");
    assert_eq!(
        repeated
            .encode_match(1, 1, DISTANCE_TABLE_SIZE_50)
            .unwrap_err(),
        too_short
    );
    assert_eq!(
        estimated_match_cost(&repeated, 1, 1, DISTANCE_TABLE_SIZE_50).unwrap_err(),
        too_short
    );

    let fresh = EncoderMatchState::default();
    let zero_distance = Error::InvalidData("RAR 5 match distance is zero");
    assert_eq!(
        fresh
            .encode_match(4, 0, DISTANCE_TABLE_SIZE_50)
            .unwrap_err(),
        zero_distance
    );
    assert_eq!(
        estimated_match_cost(&fresh, 4, 0, DISTANCE_TABLE_SIZE_50).unwrap_err(),
        zero_distance
    );
    let underflow = Error::InvalidData("RAR 5 adjusted match length underflows");
    assert_eq!(
        fresh
            .encode_match(2, 0x40001, DISTANCE_TABLE_SIZE_50)
            .unwrap_err(),
        underflow
    );
    assert_eq!(
        estimated_match_cost(&fresh, 2, 0x40001, DISTANCE_TABLE_SIZE_50).unwrap_err(),
        underflow
    );

    #[cfg(target_pointer_width = "64")]
    {
        let too_distant = Error::InvalidData("RAR 5 match distance is too large");
        assert_eq!(
            estimated_match_cost(&fresh, 4, 1usize << 40, DISTANCE_TABLE_SIZE_50).unwrap_err(),
            too_distant
        );
        let invalid_slot = Error::InvalidData("RAR 5 distance slot is too large");
        assert_eq!(
            fresh
                .encode_match(5, (1usize << 33) + 1, DISTANCE_TABLE_SIZE_70)
                .unwrap_err(),
            invalid_slot
        );
        assert_eq!(
            estimated_match_cost(&fresh, 5, (1usize << 33) + 1, DISTANCE_TABLE_SIZE_70)
                .unwrap_err(),
            invalid_slot
        );
    }
}

#[test]
fn table_construction_and_stream_pricing_reject_invalid_tokens() {
    let invalid = [EncodeToken::Match {
        length: 1,
        distance: 1,
    }];
    assert_eq!(
        table_lengths_for_tokens(&invalid, DISTANCE_TABLE_SIZE_50).err(),
        Some(Error::InvalidData("RAR 5 match length is too short"))
    );

    let lengths =
        table_lengths_for_tokens(&[EncodeToken::Literal(b'A')], DISTANCE_TABLE_SIZE_50).unwrap();
    assert_eq!(
        token_stream_bits(&invalid, &[], &lengths, DISTANCE_TABLE_SIZE_50),
        Err(Error::InvalidData("RAR 5 match length is too short"))
    );
}

#[test]
fn optimal_match_collection_grows_beyond_one_run_per_position() {
    let mut noise = 0x2545_f491_4f6c_dd1du64;
    let data: Vec<u8> = (0..4096)
        .map(|_| {
            noise ^= noise << 13;
            noise ^= noise >> 7;
            noise ^= noise << 17;
            b'A' + ((noise >> 40) as u8 & 1)
        })
        .collect();
    let options = EncodeOptions::new(64).with_optimal_parse(true);
    let baseline = RefusingBudget::new(usize::MAX);
    let mut collector = OptimalCollector::with_allowance(&data, 0, options, &baseline).unwrap();
    let matches = collector.collect(&data, 0..data.len(), options).unwrap();
    assert!(matches.runs.len() > data.len());
    drop(matches);
    drop(collector);
    assert_eq!(baseline.used(), 0);

    assert_each_allocation_refusal(|budget| {
        let mut collector = OptimalCollector::with_allowance(&data, 0, options, budget)?;
        collector.collect(&data, 0..data.len(), options)
    });

    let start = data.len() / 2;
    let baseline = RefusingBudget::new(usize::MAX);
    let mut collector = OptimalCollector::with_allowance(&data, start, options, &baseline).unwrap();
    let matches = collector
        .collect(&data, start..data.len(), options)
        .unwrap();
    assert!(matches.runs.len() > data.len() - start);
    drop(matches);
    drop(collector);
    assert_eq!(baseline.used(), 0);

    assert_each_allocation_refusal(|budget| {
        let mut collector = OptimalCollector::with_allowance(&data, start, options, budget)?;
        collector.collect(&data, start..data.len(), options)
    });
}

#[test]
fn distance_slots_beyond_native_address_width_use_out_of_window_sentinel() {
    for (slot, extra, distance) in [
        (63, (1u32 << 30) - 1, 1u64 << 32),
        (65, (1u32 << 31) - 1, 1u64 << 33),
    ] {
        assert_eq!(
            slot_to_distance(slot, extra).unwrap(),
            usize::try_from(distance).unwrap_or(usize::MAX)
        );
    }
}

#[test]
fn rejects_out_of_range_distance_slots_and_extras() {
    #[cfg(target_pointer_width = "64")]
    assert!(slot_to_distance(65, (1 << 31) - 1).is_ok());
    assert_eq!(
        slot_to_distance(4, 2),
        Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"))
    );
    assert_eq!(
        slot_to_distance(66, 0),
        Err(Error::InvalidData("RAR 5 distance slot is too large"))
    );
}

#[test]
fn bit_reader_accepts_large_rar5_distance_extras() {
    let mut bits = BitReader::new(&[0xff, 0x00, 0xaa, 0x55]);

    assert_eq!(bits.read_bits(32).unwrap(), 0xff00_aa55);
    assert_eq!(
        bits.read_bits(1),
        Err(Error::NeedMoreInput),
        "32-bit reads must not leave a partial cursor state"
    );
}

#[test]
fn copies_lz_matches_with_overlap() {
    let decoder = Unpack50Decoder::new();
    let mut output = b"AB".to_vec();

    decoder
        .copy_match(&mut output, 2, 6, 8, DEFAULT_DICTIONARY_SIZE)
        .unwrap();

    assert_eq!(output, b"ABABABAB");
}

#[test]
fn zero_fills_a_match_that_reaches_past_the_window() {
    let decoder = Unpack50Decoder::new();
    let mut output = b"AB".to_vec();

    decoder
        .copy_match(&mut output, 3, 1, 3, DEFAULT_DICTIONARY_SIZE)
        .unwrap();

    assert_eq!(output, b"AB\0");
}

#[test]
fn zero_fills_a_zero_distance_match_in_both_outputs() {
    let decoder = Unpack50Decoder::new();
    let mut buffered = b"A".to_vec();
    decoder
        .copy_match(&mut buffered, 0, 3, 4, DEFAULT_DICTIONARY_SIZE)
        .unwrap();
    assert_eq!(buffered, b"A\0\0\0");

    let mut streaming = StreamingOutput::new(Buffer::from_vec(b"A".to_vec()), 3, 1, 1).unwrap();
    let mut decoded = Vec::new();
    streaming
        .copy_match(0, 3, &mut |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => {
                    decoded.extend(std::iter::repeat_n(byte, len));
                }
            }
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
    streaming
        .finish(&mut |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => {
                    decoded.extend(std::iter::repeat_n(byte, len));
                }
            }
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
    assert_eq!(decoded, b"\0\0\0");
}

#[test]
fn rejects_a_match_that_runs_past_the_output_limit() {
    let decoder = Unpack50Decoder::new();
    let mut output = b"AB".to_vec();

    assert_eq!(
        decoder.copy_match(&mut output, 1, 2, 3, DEFAULT_DICTIONARY_SIZE),
        Err(Error::InvalidData("RAR 5 match exceeds output limit"))
    );
    assert_eq!(output, b"AB");
}

#[test]
fn zero_fills_a_match_distance_beyond_the_dictionary() {
    let decoder = Unpack50Decoder::new();
    let mut output = b"ABCD".to_vec();

    decoder.copy_match(&mut output, 4, 1, 5, 3).unwrap();

    assert_eq!(output, b"ABCD\0");
}

#[test]
fn buffered_reader_history_capacity_follows_the_active_dictionary() {
    let data = b"ABBA".repeat(4096);
    let packed = encode_literal_only(&data, 0).unwrap();
    let mut decoder = Unpack50Decoder::new();
    assert_eq!(
        decoder
            .decode_member_with_dictionary(
                &packed,
                0,
                data.len(),
                1024,
                false,
                DecodeMode::LiteralOnly
            )
            .unwrap(),
        data
    );
    assert_eq!(&*decoder.state.history, &data[data.len() - 1024..][..]);
    assert!(
        decoder.state.history.capacity() <= 1024,
        "retained {} bytes for a 1024-byte dictionary",
        decoder.state.history.capacity()
    );
    let next = b"next solid member";
    let packed = encode_literal_only(next, 0).unwrap();
    decoder
        .decode_member_with_dictionary(&packed, 0, next.len(), 1024, true, DecodeMode::LiteralOnly)
        .unwrap();
    let expected = [&data[data.len() - (1024 - next.len())..], next.as_slice()].concat();
    assert_eq!(decoder.state.history, expected);
    assert!(decoder.state.history.capacity() <= 1024);
    decoder
        .decode_member_with_dictionary(&packed, 0, next.len(), 8, true, DecodeMode::LiteralOnly)
        .unwrap();
    assert_eq!(&*decoder.state.history, &next[next.len() - 8..][..]);
    assert!(decoder.state.history.capacity() <= 8);
}

#[test]
fn filtered_reader_history_retains_only_the_raw_dictionary_tail() {
    let data = b"\xe8\0\0\0\0abcdefgh".repeat(256);
    let packed = encode_lz_member_with_filter(&data, crate::FilterKind::E8).unwrap();
    let raw = Unpack50Decoder::new()
        .decode_member_with_dictionary(&packed, 0, data.len(), 64, false, DecodeMode::LzNoFilters)
        .unwrap();
    let mut decoder = Unpack50Decoder::new();
    let decoded = decoder
        .decode_member_with_dictionary(&packed, 0, data.len(), 64, false, DecodeMode::Lz)
        .unwrap();
    assert_ne!(decoded, raw, "fixture must actually transform bytes");
    assert_eq!(&*decoder.state.history, &raw[raw.len() - 64..][..]);
    assert!(decoder.state.history.capacity() <= 64);
}

#[test]
fn failed_buffered_filter_preserves_previous_solid_history() {
    let data = b"\xe8\0\0\0\0abcdefghijklmnop".to_vec();
    let packed = encode_lz_member_with_filter(&data, crate::FilterKind::E8).unwrap();
    let mut decoder = Unpack50Decoder::new();
    decoder.state.history = Buffer::from_vec(b"old raw history".to_vec());
    let history = decoder.state.history.to_vec();
    // The record spans the full member, but the advertised output stops
    // one byte earlier: the failure happens during filter application.
    assert_eq!(
        decoder.decode_member_with_dictionary(&packed, 0, data.len() - 1, 64, true, DecodeMode::Lz),
        Err(Error::InvalidData("RAR 5 filter range exceeds output"))
    );
    assert_eq!(decoder.state.history, history);
}

#[test]
fn solid_history_is_capped_to_dictionary_size() {
    let mut decoder = Unpack50Decoder::new();
    let first_payload = literal_only_payload(b"ABBA");
    let first =
        encode_compressed_block(&first_payload, first_payload.len() * 8, true, true).unwrap();
    let second_payload = literal_only_payload(b"BAAB");
    let second =
        encode_compressed_block(&second_payload, second_payload.len() * 8, true, true).unwrap();

    assert_eq!(
        decoder
            .decode_member_with_dictionary(&first, 0, 4, 6, false, DecodeMode::LiteralOnly)
            .unwrap(),
        b"ABBA"
    );
    assert_eq!(&*decoder.state.history, &b"ABBA"[..]);

    assert_eq!(
        decoder
            .decode_member_with_dictionary(&second, 0, 4, 6, true, DecodeMode::LiteralOnly)
            .unwrap(),
        b"BAAB"
    );
    assert_eq!(&*decoder.state.history, &b"BABAAB"[..]);
}

#[test]
fn streaming_reader_history_capacity_follows_the_active_dictionary() {
    let data = b"ABBA".repeat(65536);
    let packed = encode_literal_only(&data, 0).unwrap();
    let mut decoder = Unpack50Decoder::new();
    let mut decoded = Vec::new();
    decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut packed.as_slice(),
            0,
            data.len(),
            1024,
            false,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.extend(std::iter::repeat_n(byte, len))
                    }
                }
                Ok::<(), std::convert::Infallible>(())
            },
        )
        .unwrap();
    assert_eq!(decoded, data);
    assert_eq!(&*decoder.state.history, &data[data.len() - 1024..][..]);
    assert!(decoder.state.history.capacity() <= 1024);
    let next = b"next solid member";
    let packed = encode_literal_only(next, 0).unwrap();
    decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut packed.as_slice(),
            0,
            next.len(),
            8,
            true,
            |_| Ok::<(), std::convert::Infallible>(()),
        )
        .unwrap();
    assert_eq!(&*decoder.state.history, &next[next.len() - 8..][..]);
    assert!(decoder.state.history.capacity() <= 8);
}

#[test]
fn streaming_decoder_history_is_capped_without_reordering() {
    let mut decoder = Unpack50Decoder::new();
    let first_payload = literal_only_payload(b"ABBA");
    let first =
        encode_compressed_block(&first_payload, first_payload.len() * 8, true, true).unwrap();
    let second_payload = literal_only_payload(b"BAAB");
    let second =
        encode_compressed_block(&second_payload, second_payload.len() * 8, true, true).unwrap();
    let mut decoded = Vec::new();

    decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut std::io::Cursor::new(&first),
            0,
            4,
            6,
            false,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::io::Error>(())
            },
        )
        .unwrap();
    assert_eq!(decoded, b"ABBA");
    assert_eq!(&*decoder.state.history, &b"ABBA"[..]);

    decoded.clear();
    decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut std::io::Cursor::new(&second),
            0,
            4,
            6,
            true,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::io::Error>(())
            },
        )
        .unwrap();
    assert_eq!(decoded, b"BAAB");
    assert_eq!(&*decoder.state.history, &b"BABAAB"[..]);
}

#[test]
fn solid_streaming_decoder_trims_inherited_history_before_member() {
    let payload = literal_only_payload(b"AB");
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
    let mut decoder = Unpack50Decoder::new();
    decoder.state.history.extend_from_slice(b"123456").unwrap();
    let mut decoded = Vec::new();

    decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            2,
            4,
            true,
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

    assert_eq!(decoded, b"AB");
    assert_eq!(&*decoder.state.history, &b"56AB"[..]);
}

#[test]
fn streaming_decoder_handles_each_match_control() {
    for (payload, expected) in [
        (new_match_payload(), b"ABAB".as_slice()),
        (repeat_payload(257), b"ABABAB".as_slice()),
        (repeat_payload(258), b"ABABAB".as_slice()),
    ] {
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
        let mut decoded = Vec::new();
        Unpack50Decoder::new()
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut input.as_slice(),
                0,
                expected.len(),
                DEFAULT_DICTIONARY_SIZE,
                false,
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
        assert_eq!(decoded, expected);
    }
}

#[test]
fn buffered_and_streaming_decoders_reuse_tables_after_table_only_block() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[b'B' as usize] = 1;
    let (tables, table_bits) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut input = encode_compressed_block(&tables, table_bits, true, false).unwrap();
    // A = 0, B = 1 with the two one-bit codes above.
    input.extend(encode_compressed_block(&[0b0110_0000], 4, false, true).unwrap());

    let buffered = Unpack50Decoder::new()
        .decode_member_with_dictionary(
            &input,
            0,
            4,
            DEFAULT_DICTIONARY_SIZE,
            false,
            DecodeMode::LiteralOnly,
        )
        .unwrap();
    assert_eq!(buffered, b"ABBA");

    let mut streamed = Vec::new();
    Unpack50Decoder::new()
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            4,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => streamed.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        streamed.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::convert::Infallible>(())
            },
        )
        .unwrap();
    assert_eq!(streamed, buffered);
}

#[test]
fn compressed_block_reader_accepts_empty_final_marker_and_checks_header() {
    let empty = encode_compressed_block(&[], 0, false, true).unwrap();
    let parsed = parse_compressed_block(&empty).unwrap();
    let streamed = read_compressed_block(&mut empty.as_slice()).unwrap();
    assert!(parsed.header.is_last);
    assert_eq!(parsed.header.payload_bits, 0);
    assert!(streamed.header.is_last);
    assert_eq!(streamed.header.payload_bits, 0);
    assert!(streamed.payload.is_empty());

    assert!(matches!(
        read_compressed_block(&mut empty[..2].as_ref()),
        Err(Error::NeedMoreInput)
    ));

    let mut bad_checksum = empty.clone();
    bad_checksum[1] ^= 1;
    assert!(matches!(
        read_compressed_block(&mut bad_checksum.as_slice()),
        Err(Error::InvalidData("RAR 5 block header checksum mismatch"))
    ));
    assert_eq!(
        parse_compressed_block(&bad_checksum),
        Err(Error::InvalidData("RAR 5 block header checksum mismatch"))
    );
    let mut invalid_size_width = empty;
    invalid_size_width[0] |= 0b11 << 3;
    assert!(matches!(
        read_compressed_block(&mut invalid_size_width.as_slice()),
        Err(Error::InvalidData("RAR 5 block size length is invalid"))
    ));
    assert_eq!(
        parse_compressed_block(&invalid_size_width),
        Err(Error::InvalidData("RAR 5 block size length is invalid"))
    );
}

#[test]
fn parser_handles_largest_declared_block_size_without_overflow() {
    let flags = 0b10 << 3; // three size bytes
    let checksum = 0x5a ^ flags ^ 0xff ^ 0xff ^ 0xff;
    let header = [flags, checksum, 0xff, 0xff, 0xff];
    assert_eq!(parse_compressed_block(&header), Err(Error::NeedMoreInput));
}

#[test]
fn reader_block_admits_capacity_before_reading_payload_and_releases_failures() {
    let packed = encode_compressed_block(&[0x31; 8], 64, false, true).unwrap();
    let header_len = parse_compressed_block(&packed).unwrap().header_len;
    let denied = Allowance::limited(7);
    let mut input = std::io::Cursor::new(&packed);
    let error = match read_compressed_block_with_allowance(&mut input, &denied) {
        Ok(_) => panic!("payload must exceed the allowance"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::WorkspaceLimitExceeded(ref details)
        if details.limit == 7 && details.required == 8 && details.used == 0));
    assert_eq!(input.position(), header_len as u64);
    assert_eq!(denied.used(), 0);

    let allowance = Allowance::limited(8);
    let block = read_compressed_block_with_allowance(&mut packed.as_slice(), &allowance).unwrap();
    assert_eq!(&*block.payload, &[0x31; 8]);
    assert_eq!(allowance.used(), 8);
    drop(block);
    assert_eq!(allowance.used(), 0);

    struct FailingPayload<'a> {
        header: &'a [u8],
    }
    impl Read for FailingPayload<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.header.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "payload read denied",
                ));
            }
            self.header.read(output)
        }
    }
    let mut failing = FailingPayload {
        header: &packed[..header_len],
    };
    let error = match read_compressed_block_with_allowance(&mut failing, &allowance) {
        Ok(_) => panic!("payload read must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Io(ref source)
        if matches!(**source, crate::Error::Io(ref io)
            if io.kind == std::io::ErrorKind::PermissionDenied)));
    assert_eq!(allowance.used(), 0);

    let mut truncated = &packed[..packed.len() - 1];
    assert!(matches!(
        read_compressed_block_with_allowance(&mut truncated, &allowance),
        Err(Error::NeedMoreInput)
    ));
    assert_eq!(allowance.used(), 0);
}

#[test]
fn reader_block_keeps_its_worker_charge_after_reservation_retirement() {
    use crate::codec::workspace::RESERVATION_BYTES;
    let packed = encode_compressed_block(&[0x31; 8], 64, false, true).unwrap();
    let ledger = Allowance::limited(128 + RESERVATION_BYTES);
    let mut reservation = ledger.reserve(16).unwrap();
    let allowance = reservation.allowance();
    reservation.start();
    let block = read_compressed_block_with_allowance(&mut packed.as_slice(), &allowance).unwrap();
    let larger = encode_compressed_block(&[0x31; 9], 72, false, true).unwrap();
    assert!(matches!(
        read_compressed_block_with_allowance(&mut larger.as_slice(), &allowance),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(allowance.used(), 8);
    reservation.retire();
    assert_eq!(ledger.used(), 8 + RESERVATION_BYTES);
    drop(block);
    assert_eq!(ledger.used(), RESERVATION_BYTES);
    drop(allowance);
    assert_eq!(ledger.used(), 0);
}

#[test]
fn parser_rejects_truncated_block_header_and_payload() {
    // A two-byte size field requires a fourth header byte.
    assert_eq!(
        parse_compressed_block(&[1 << 3, 0, 0]),
        Err(Error::NeedMoreInput)
    );
    let block = encode_compressed_block(&[0xaa, 0xbb], 16, false, true).unwrap();
    for length in 0..block.len() {
        assert_eq!(
            parse_compressed_block(&block[..length]),
            Err(Error::NeedMoreInput),
            "truncated at byte {length}"
        );
    }
    assert_eq!(
        parse_compressed_block(&block).unwrap().payload,
        3..block.len()
    );
}

#[test]
fn decoders_handle_uninitialized_match_controls() {
    for (symbol, buffered_error, streaming_error) in [
        (257, Error::NeedMoreInput, Error::NeedMoreInput),
        (
            258,
            Error::InvalidData("RAR 5 repeat distance is not initialized"),
            Error::InvalidData("RAR 5 repeat distance is not initialized"),
        ),
    ] {
        let input = control_only_block(symbol);
        assert_eq!(
            Unpack50Decoder::new().decode_member_with_dictionary(
                &input,
                0,
                1,
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::Lz,
            ),
            Err(buffered_error)
        );
        let result = Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(
            matches!(result, Err(StreamDecodeError::Decode(error)) if error == streaming_error)
        );
    }
}

#[test]
fn decoders_reject_match_that_exceeds_declared_output() {
    for (payload, declared_size) in [
        (new_match_payload(), 3), // AB, then a two-byte match.
        (repeat_payload(257), 5), // ABAB, then the previous match.
        (repeat_payload(258), 5), // ABAB, then a repeat distance.
    ] {
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
        assert_eq!(
            Unpack50Decoder::new().decode_member_with_dictionary(
                &input,
                0,
                declared_size,
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::Lz,
            ),
            Err(Error::InvalidData("RAR 5 match exceeds output limit"))
        );
        let result = Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            declared_size,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        );
        assert!(matches!(
            result,
            Err(StreamDecodeError::Decode(Error::InvalidData(
                "RAR 5 match exceeds output limit"
            )))
        ));
    }
}

#[test]
fn literal_only_decoder_rejects_every_lz_control_class() {
    for symbol in [256, 257, 258, 262] {
        let input = control_only_block(symbol);
        assert_eq!(
            Unpack50Decoder::new().decode_member_with_dictionary(
                &input,
                0,
                1,
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::LiteralOnly,
            ),
            Err(Error::InvalidData(
                "RAR 5 literal-only decoder encountered non-literal symbol"
            )),
            "control symbol {symbol}"
        );
    }
}

#[test]
fn decoder_defaults_match_fresh_state() {
    assert_eq!(BlockSplitter::default().counts, BlockSplitter::new().counts);
    assert_eq!(BlockSplitter::default().total, BlockSplitter::new().total);

    let default = Unpack50Decoder::default();
    let fresh = Unpack50Decoder::new();
    assert!(default.state.tables.is_none());
    assert!(fresh.state.tables.is_none());
    assert_eq!(default.state.reps, fresh.state.reps);
    assert_eq!(default.state.last_length, fresh.state.last_length);
    assert_eq!(default.state.history, fresh.state.history);
}

#[test]
fn decoders_reject_unsupported_filter_type() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[256] = 1;
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };
    writer.write_bits(1, 1); // filter control symbol
    writer.write_bits(0, 2); // one-byte offset
    writer.write_bits(0, 8);
    writer.write_bits(0, 2); // one-byte length
    writer.write_bits(1, 8);
    writer.write_bits(7, 3); // unsupported filter type
    let payload_bits = writer.bit_pos;
    let input = encode_compressed_block(&writer.finish(), payload_bits, true, true).unwrap();

    assert_eq!(
        Unpack50Decoder::new().decode_member_with_dictionary(
            &input,
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            DecodeMode::Lz,
        ),
        Err(Error::InvalidData("RAR 5 filter type is unsupported"))
    );
    let result = Unpack50Decoder::new().decode_to_sink_with_filters(
        &mut input.as_slice(),
        0,
        1,
        DEFAULT_DICTIONARY_SIZE,
        false,
        |_chunk| Ok::<(), std::convert::Infallible>(()),
        Some(&mut |_filter| Ok::<(), std::convert::Infallible>(())),
    );
    assert!(matches!(
        result,
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 filter type is unsupported"
        )))
    ));
}

#[test]
fn streaming_decoder_rejects_missing_tables_and_invalid_dictionary() {
    let input = encode_compressed_block(&[0], 8, false, true).unwrap();
    assert_eq!(
        Unpack50Decoder::new().decode_member_with_dictionary(
            &input,
            0,
            1,
            0,
            false,
            DecodeMode::LiteralOnly,
        ),
        Err(Error::InvalidData("RAR 5 dictionary size is zero"))
    );
    let decode = |dictionary_size| {
        Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            1,
            dictionary_size,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        )
    };
    assert!(matches!(
        decode(1),
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 block reuses missing tables"
        )))
    ));
    assert!(matches!(
        decode(0),
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 dictionary size is zero"
        )))
    ));
}

#[test]
fn streaming_decoder_propagates_sink_failure() {
    let payload = literal_only_payload(b"AB");
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
    let error = Unpack50Decoder::new()
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            2,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Err("sink failed"),
        )
        .unwrap_err();
    assert!(matches!(error, StreamDecodeError::Sink("sink failed")));
}

#[test]
fn streaming_decoder_propagates_sink_failure_during_literal_flush() {
    let data = vec![b'A'; STREAM_FLUSH_THRESHOLD];
    let input = encode_literal_only(&data, 0).unwrap();
    let mut decoder = Unpack50Decoder::new();
    let mut calls = 0;
    let error = decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            data.len(),
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| {
                calls += 1;
                Err("sink failed")
            },
        )
        .unwrap_err();
    assert!(matches!(error, StreamDecodeError::Sink("sink failed")));
    assert_eq!(calls, 1);
    assert!(decoder.state.tables.is_none()); // The flush failed inside the literal loop.
}

#[test]
fn streaming_decoder_observes_cancellation_after_literal_flush() {
    let data = vec![b'A'; STREAM_FLUSH_THRESHOLD + 1];
    let input = encode_literal_only(&data, 0).unwrap();
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
            Ok::<(), std::convert::Infallible>(())
        },
    );
    assert!(matches!(
        result,
        Err(StreamDecodeError::Decode(Error::Cancelled))
    ));
    assert_eq!(calls, 1);
    assert!(decoder.state.tables.is_none()); // The next symbol observed cancellation.
}

#[test]
fn streaming_match_output_propagates_sink_failures() {
    let mut repeated = StreamingOutput::new(
        Buffer::new(&Allowance::default()),
        STREAM_FLUSH_THRESHOLD,
        2,
        2,
    )
    .unwrap();
    assert!(matches!(
        repeated.push_repeated(b'A', STREAM_FLUSH_THRESHOLD, &mut |_chunk| Err("sink")),
        Err(StreamDecodeError::Sink("sink"))
    ));

    let mut zero_flush = StreamingOutput::new(Buffer::new(&Allowance::default()), 2, 2, 2).unwrap();
    zero_flush
        .push(b'A', &mut |_chunk| Ok::<(), &str>(()))
        .unwrap();
    assert!(matches!(
        zero_flush.push_zeroes(1, &mut |_chunk| Err("sink")),
        Err(StreamDecodeError::Sink("sink"))
    ));

    let mut zero_chunk = StreamingOutput::new(Buffer::from_vec(vec![0]), 1, 2, 2).unwrap();
    assert!(matches!(
        zero_chunk.push_zeroes(1, &mut |_chunk| Err("sink")),
        Err(StreamDecodeError::Sink("sink"))
    ));

    let mut copied = StreamingOutput::new(
        Buffer::new(&Allowance::default()),
        STREAM_FLUSH_THRESHOLD,
        2,
        2,
    )
    .unwrap();
    copied
        .push_repeated(b'A', STREAM_FLUSH_THRESHOLD - 1, &mut |_chunk| {
            Ok::<(), &str>(())
        })
        .unwrap();
    assert!(matches!(
        copied.copy_match(2, 1, &mut |_chunk| Err("sink")),
        Err(StreamDecodeError::Sink("sink"))
    ));
}

#[test]
fn decoder_reader_entry_points_observe_existing_cancellation() {
    let token = crate::ReadCancellation::new();
    token.cancel();
    let control = crate::read_control::ReadControl::new(Some(&token));
    let mut buffered = Unpack50Decoder::new();
    buffered.read_control = control.clone();
    assert_eq!(
        buffered.decode_member_from_reader_with_dictionary(
            &mut &[][..],
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            DecodeMode::Lz,
        ),
        Err(Error::Cancelled)
    );

    let mut streaming = Unpack50Decoder::new();
    streaming.read_control = control;
    let result = streaming.decode_member_from_reader_with_dictionary_to_sink(
        &mut &[][..],
        0,
        1,
        DEFAULT_DICTIONARY_SIZE,
        false,
        |_chunk| Ok::<(), std::convert::Infallible>(()),
    );
    assert!(matches!(
        result,
        Err(StreamDecodeError::Decode(Error::Cancelled))
    ));
}

#[test]
fn buffered_decoder_wrappers_observe_existing_cancellation() {
    let token = crate::ReadCancellation::new();
    token.cancel();
    let control = crate::read_control::ReadControl::new(Some(&token));
    let mut decoder = Unpack50Decoder::new();
    decoder.read_control = control.clone();
    assert_eq!(
        decoder.decode_member(&[], 0, 1, false, DecodeMode::Lz),
        Err(Error::Cancelled)
    );

    decoder.read_control = control.clone();
    assert_eq!(
        decoder.decode_member_with_dictionary(
            &[],
            0,
            1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            DecodeMode::Lz,
        ),
        Err(Error::Cancelled)
    );

    decoder.read_control = control;
    assert_eq!(
        decoder.decode_member_from_reader(&mut &[][..], 0, 1, false, DecodeMode::Lz),
        Err(Error::Cancelled)
    );
}

#[test]
fn buffered_decoder_observes_cancellation_before_and_during_filters() {
    let data: Vec<u8> = (0..96).map(|index| (index * 7 + index / 3) as u8).collect();
    let input =
        encode_lz_member_with_filter(&data, crate::FilterKind::Delta { channels: 3 }).unwrap();
    assert_eq!(decode_lz(&input, 0, data.len()).unwrap(), data);

    for successful_checks in [5, 6] {
        let token = crate::ReadCancellation::new();
        let mut decoder = Unpack50Decoder::new();
        decoder.read_control = crate::read_control::ReadControl::new(Some(&token));
        decoder.read_control.cancel_after_checks(successful_checks);
        assert_eq!(
            decoder.decode_member_from_reader_with_dictionary(
                &mut input.as_slice(),
                0,
                data.len(),
                DEFAULT_DICTIONARY_SIZE,
                false,
                DecodeMode::Lz,
            ),
            Err(Error::Cancelled),
            "after {successful_checks} checks"
        );
        assert!(decoder.state.tables.is_some()); // All packed symbols decoded first.
        assert!(decoder.state.history.is_empty()); // Filtered output was not committed.
    }
}

#[test]
fn streaming_decoder_rejects_filter_beyond_declared_output() {
    let data = b"\xe8\0\0\0\0plain text after call";
    let input = encode_lz_member_with_filter(data, crate::FilterKind::E8).unwrap();
    let mut record_count = 0;
    let error = Unpack50Decoder::new()
        .decode_to_sink_with_filters(
            &mut input.as_slice(),
            0,
            data.len() - 1,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
            Some(&mut |_filter| {
                record_count += 1;
                Ok::<(), std::convert::Infallible>(())
            }),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        StreamDecodeError::Decode(Error::InvalidData("RAR 5 filter range exceeds output"))
    ));
    assert_eq!(record_count, 0);
}

#[test]
fn streaming_decoder_propagates_filter_record_failure() {
    let data = b"\xe8\0\0\0\0plain text after call";
    let input = encode_lz_member_with_filter(data, crate::FilterKind::E8).unwrap();
    let error = Unpack50Decoder::new()
        .decode_to_sink_with_filters(
            &mut input.as_slice(),
            0,
            data.len(),
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), &str>(()),
            Some(&mut |_filter| Err("filter failed")),
        )
        .unwrap_err();
    assert!(matches!(error, StreamDecodeError::Sink("filter failed")));
}

#[test]
fn streaming_decoder_reports_truncated_block_and_incomplete_output() {
    let payload = literal_only_payload(b"AB");
    let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
    for truncated in [&input[..1], &input[..input.len() - 1]] {
        let mut reader = truncated;
        let error = Unpack50Decoder::new()
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut reader,
                0,
                2,
                DEFAULT_DICTIONARY_SIZE,
                false,
                |_chunk| Ok::<(), std::convert::Infallible>(()),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            StreamDecodeError::Decode(Error::NeedMoreInput)
        ));
    }
    let error = Unpack50Decoder::new()
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut input.as_slice(),
            0,
            3,
            DEFAULT_DICTIONARY_SIZE,
            false,
            |_chunk| Ok::<(), std::convert::Infallible>(()),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        StreamDecodeError::Decode(Error::NeedMoreInput)
    ));
}

#[test]
fn streaming_output_rejects_overruns_without_partial_emission() {
    let emitted = std::cell::RefCell::new(Vec::new());
    let mut sink = |chunk: DecodedChunk<'_>| {
        match chunk {
            DecodedChunk::Bytes(bytes) => emitted.borrow_mut().extend_from_slice(bytes),
            DecodedChunk::Repeated { byte, len } => {
                emitted.borrow_mut().extend(std::iter::repeat_n(byte, len));
            }
        }
        Ok::<(), std::convert::Infallible>(())
    };

    let mut literal = StreamingOutput::new(Buffer::new(&Allowance::default()), 1, 1, 1).unwrap();
    literal.push(b'A', &mut sink).unwrap();
    assert!(matches!(
        literal.push(b'B', &mut sink),
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 match exceeds output limit"
        )))
    ));
    literal.finish(&mut sink).unwrap();
    assert_eq!(&*emitted.borrow(), b"A");

    emitted.borrow_mut().clear();
    let mut repeated = StreamingOutput::new(Buffer::new(&Allowance::default()), 1, 1, 1).unwrap();
    assert!(matches!(
        repeated.push_repeated(b'B', 2, &mut sink),
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 match exceeds output limit"
        )))
    ));
    assert_eq!(repeated.written(), 0);
    assert!(emitted.borrow().is_empty());

    let mut zeroes = StreamingOutput::new(Buffer::from_vec(vec![0]), 1, 1, 1).unwrap();
    assert!(matches!(
        zeroes.push_zeroes(2, &mut sink),
        Err(StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 match exceeds output limit"
        )))
    ));
    assert_eq!(zeroes.written(), 0);
    assert!(emitted.borrow().is_empty());
    zeroes.push_zeroes(1, &mut sink).unwrap();
    assert_eq!(&*emitted.borrow(), &[0]);
    assert_eq!(zeroes.into_history().into_vec(), [0]);
}

#[test]
fn virtual_zero_history_does_not_overallocate_a_tiny_dictionary() {
    let mut output = StreamingOutput::new(Buffer::from_vec(vec![0]), 100_000, 1, 1).unwrap();
    let mut emitted = 0;
    output
        .copy_match(1, 100_000, &mut |chunk| {
            let DecodedChunk::Repeated { byte: 0, len } = chunk else {
                panic!("expected virtual zeros")
            };
            emitted += len;
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
    assert_eq!(emitted, 100_000);
    assert_eq!(output.history.iter().copied().collect::<Vec<_>>(), [0]);
    assert_eq!(output.history.capacity(), 1);
}

#[test]
fn virtual_zero_history_flush_refusal_releases_streaming_charge() {
    let budget = RefusingBudget::new(1);
    {
        let mut output = StreamingOutput::new(Buffer::new(&budget), 3, 1, 1).unwrap();
        output
            .push(0, &mut |_| Ok::<(), std::convert::Infallible>(()))
            .unwrap();
        let mut emitted = Vec::new();
        let error = output
            .copy_match(1, 2, &mut |chunk| {
                let DecodedChunk::Bytes(bytes) = chunk else {
                    panic!("expected initial literal")
                };
                emitted.extend_from_slice(bytes);
                Ok::<(), std::convert::Infallible>(())
            })
            .unwrap_err();
        assert!(matches!(error, StreamDecodeError::Decode(Error::Cancelled)));
        // The initial literal is streamed before retaining its history fails.
        assert_eq!(emitted, [0]);
        assert_eq!(output.written(), 1);
        assert!(output.history.is_empty());
        assert_eq!(budget.attempts(), 2);
    }
    assert_eq!(budget.used(), 0);
}

#[test]
fn streaming_flush_preserves_dictionary_tail_with_excess_allocation_capacity() {
    let mut output = StreamingOutput::new(Buffer::from_vec(b"ABC".to_vec()), 1, 3, 3).unwrap();
    // Model an allocator returning more capacity than requested. Vec's
    // public contract permits this even though this host allocates exactly.
    let mut history = Vec::with_capacity(8);
    history.extend_from_slice(b"ABC");
    output.history = crate::codec::workspace::Deque::from_buffer(Buffer::from_vec(history));
    assert!(output.history.capacity() > output.history_limit);
    let mut emitted = Vec::new();
    let mut sink = |chunk: DecodedChunk<'_>| {
        let DecodedChunk::Bytes(bytes) = chunk else {
            panic!("expected bytes")
        };
        emitted.extend_from_slice(bytes);
        Ok::<(), std::convert::Infallible>(())
    };
    output.push(b'D', &mut sink).unwrap();
    output.finish(&mut sink).unwrap();
    assert_eq!(emitted, b"D");
    assert_eq!(output.history.iter().copied().collect::<Vec<_>>(), b"BCD");
}

#[test]
fn initial_repeat_distance_zero_is_rejected_before_streaming_output() {
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
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };
    writer.write_bits(1, 1); // Repeat the still-zero first distance.
    writer.write_bits(0, 1); // Length two.
    let payload_bits = writer.bit_pos;
    let packed = encode_compressed_block(&writer.finish(), payload_bits, true, true).unwrap();
    assert_eq!(
        decode_lz(&packed, 0, 2),
        Err(Error::InvalidData(
            "RAR 5 repeat distance is not initialized"
        ))
    );
    let mut decoder = Unpack50Decoder::new();
    let mut emitted = Vec::new();
    let error = decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut packed.as_slice(),
            0,
            2,
            1,
            false,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => emitted.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        emitted.extend(std::iter::repeat_n(byte, len))
                    }
                }
                Ok::<(), std::convert::Infallible>(())
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        StreamDecodeError::Decode(Error::InvalidData(
            "RAR 5 repeat distance is not initialized"
        ))
    ));
    assert!(emitted.is_empty());
}

#[test]
fn zero_literal_and_initialized_matches_stream_virtual_zero_history() {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[0] = 1;
    lengths.main[258] = 2;
    lengths.main[262] = 2;
    lengths.distance[0] = 1;
    lengths.distance[1] = 1;
    lengths.length[0] = 1;
    lengths.length[1] = 1;
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };
    writer.write_bits(0, 1); // Zero literal.
    writer.write_bits(3, 2); // New match: length two.
    writer.write_bits(0, 1); // Distance one.
    writer.write_bits(2, 2); // Repeat distance one.
    writer.write_bits(0, 1); // Length two.
    let payload_bits = writer.bit_pos;
    let packed = encode_compressed_block(&writer.finish(), payload_bits, true, true).unwrap();
    assert_eq!(decode_lz(&packed, 0, 5).unwrap(), [0; 5]);
    let mut decoder = Unpack50Decoder::new();
    let mut bytes = Vec::new();
    let mut virtual_bytes = 0;
    decoder
        .decode_member_from_reader_with_dictionary_to_sink(
            &mut packed.as_slice(),
            0,
            5,
            1,
            false,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(literals) => bytes.extend_from_slice(literals),
                    DecodedChunk::Repeated { byte, len } => {
                        assert_eq!(byte, 0);
                        virtual_bytes += len;
                        bytes.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::convert::Infallible>(())
            },
        )
        .unwrap();
    assert_eq!(bytes, [0; 5]);
    assert_eq!(virtual_bytes, 4);
}

#[test]
fn streaming_zero_history_emits_large_match_without_materializing_it() {
    let mut output = StreamingOutput::new(Buffer::from_vec(vec![0, 0]), 100_000, 2, 2).unwrap();
    let mut chunks = Vec::new();
    output
        .copy_match(2, 100_000, &mut |chunk| {
            chunks.push(match chunk {
                DecodedChunk::Bytes(bytes) => (bytes[0], bytes.len()),
                DecodedChunk::Repeated { byte, len } => (byte, len),
            });
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
    assert_eq!(chunks, [(0, 100_000)]);
    assert_eq!(output.written(), 100_000);
    assert_eq!(output.into_history().into_vec(), [0, 0]);
}

#[test]
fn streaming_match_keeps_its_window_across_flushes() {
    let count = STREAM_FLUSH_THRESHOLD + 11;
    let mut output = StreamingOutput::new(Buffer::from_vec(b"abc".to_vec()), count, 3, 3).unwrap();
    let mut decoded = Vec::new();
    let mut sink = |chunk: DecodedChunk<'_>| {
        match chunk {
            DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
            DecodedChunk::Repeated { byte, len } => {
                decoded.extend(std::iter::repeat_n(byte, len));
            }
        }
        Ok::<(), std::convert::Infallible>(())
    };
    output.copy_match(3, count, &mut sink).unwrap();
    output.finish(&mut sink).unwrap();
    assert_eq!(
        decoded,
        b"abc"
            .iter()
            .copied()
            .cycle()
            .take(count)
            .collect::<Vec<_>>()
    );
    assert!(output.history.capacity() <= 3);
    assert_eq!(output.into_history().into_vec(), b"abc");
}

#[test]
fn streaming_window_accepts_match_beyond_old_64_mib_cap() {
    const OLD_STREAM_HISTORY_LIMIT: usize = 64 * 1024 * 1024;
    let distance = OLD_STREAM_HISTORY_LIMIT + 1;
    let history = vec![b'A'; distance];
    let mut output =
        StreamingOutput::new(Buffer::from_vec(history), 1, distance, distance).unwrap();
    let mut decoded = Vec::new();

    output
        .copy_match(distance, 1, &mut |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => {
                    decoded.extend(std::iter::repeat_n(byte, len));
                }
            }
            Ok::<(), std::io::Error>(())
        })
        .unwrap();
    output
        .finish(&mut |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => {
                    decoded.extend(std::iter::repeat_n(byte, len));
                }
            }
            Ok::<(), std::io::Error>(())
        })
        .unwrap();

    assert_eq!(decoded, b"A");
}

#[test]
fn streaming_window_zero_fills_match_beyond_declared_dictionary() {
    let mut output = StreamingOutput::new(Buffer::from_vec(vec![b'A'; 8]), 1, 7, 8).unwrap();
    let mut decoded = Vec::new();

    output
        .copy_match(8, 1, &mut |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => {
                    decoded.extend(std::iter::repeat_n(byte, len));
                }
            }
            Ok::<(), std::io::Error>(())
        })
        .unwrap();
    output
        .flush(&mut |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => {
                    decoded.extend(std::iter::repeat_n(byte, len));
                }
            }
            Ok::<(), std::io::Error>(())
        })
        .unwrap();

    assert_eq!(decoded, b"\0");
}

fn literal_only_payload(data: &[u8]) -> Vec<u8> {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[b'B' as usize] = 1;
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };
    for &byte in data {
        match byte {
            b'A' => writer.write_bits(0, 1),
            b'B' => writer.write_bits(1, 1),
            _ => panic!("test helper only encodes A/B"),
        }
    }
    writer.finish()
}

fn new_match_payload() -> Vec<u8> {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 2;
    lengths.main[b'B' as usize] = 2;
    lengths.main[262] = 2;
    lengths.distance[1] = 1;
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };

    writer.write_bits(0b00, 2); // 'A'
    writer.write_bits(0b01, 2); // 'B'
    writer.write_bits(0b10, 2); // match length 2
    writer.write_bits(0, 1); // distance slot 1
    writer.finish()
}

fn repeat_payload(repeat_symbol: usize) -> Vec<u8> {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 2;
    lengths.main[b'B' as usize] = 2;
    lengths.main[repeat_symbol] = 2;
    lengths.main[262] = 2;
    lengths.distance[1] = 1;
    lengths.length[0] = 1;
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };

    writer.write_bits(0b00, 2); // 'A'
    writer.write_bits(0b01, 2); // 'B'
    writer.write_bits(0b11, 2); // match length 2
    writer.write_bits(0, 1); // distance slot 1
    writer.write_bits(0b10, 2); // repeat control symbol
    if repeat_symbol == 258 {
        writer.write_bits(0, 1); // length slot 0
    }
    writer.finish()
}

fn control_only_block(symbol: usize) -> Vec<u8> {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; DISTANCE_TABLE_SIZE_50],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    lengths.main[b'A' as usize] = 1;
    lengths.main[symbol] = 1;
    let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(bytes),
        bit_pos,
    };
    writer.write_bits(1, 1);
    let payload_bits = writer.bit_pos;
    encode_compressed_block(&writer.finish(), payload_bits, true, true).unwrap()
}
