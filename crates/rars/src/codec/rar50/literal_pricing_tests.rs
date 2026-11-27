use super::*;
use crate::codec::workspace::Allowance;

// Retained upstream initialization, reach admission and backtracking. Pricing
// uses the original scalar implementation below, never the literal shortcut.
#[allow(clippy::too_many_arguments)]
fn reference_optimal_tokens(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    matches: &BlockMatches,
    workspace: &mut OptimalWorkspace,
) -> Result<Buffer<EncodeToken>> {
    let start = block.start;
    let end = block.end;
    let span = end - start;

    let allowance = workspace.price.allowance().clone();
    let OptimalWorkspace {
        price,
        arrive_length,
        arrive_distance,
        arrive_reps,
        arrive_last_length,
    } = workspace;
    price.resize(span + 1, u32::MAX)?;
    price.fill(u32::MAX);
    arrive_length.resize(span + 1, 0)?;
    arrive_length.fill(0);
    arrive_distance.resize(span + 1, 0)?;
    arrive_distance.fill(0);
    arrive_reps.resize(span + 1, [0; 4])?;
    arrive_reps.fill([0; 4]);
    arrive_last_length.resize(span + 1, 0)?;
    arrive_last_length.fill(0);
    price[0] = 0;

    // Admit the largest candidate list once. Pricing only borrows already
    // charged arrays, so its inner loop is identical for both budget policies.
    // Each position contributes at most four remembered-distance candidates.
    let longest_run = matches
        .starts
        .windows(2)
        .map(|pair| (pair[1] - pair[0]) as usize)
        .max()
        .unwrap_or(0);
    // A position contributes at most one run for each encodable match length.
    // Four remembered distances are added while pricing, so this bound cannot
    // approach usize::MAX for a valid BlockMatches collection.
    debug_assert!(longest_run <= MAX_ENCODER_MATCH_LENGTH);
    let reach_capacity = longest_run + 4;
    let mut reaches = Buffer::filled(reach_capacity, (0usize, 0usize, 0usize), &allowance)?;
    reference_price_optimal_paths(
        combined,
        block.clone(),
        options,
        distance_size,
        prices,
        &matches.runs,
        &matches.starts,
        OptimalSlices {
            price,
            arrive_length,
            arrive_distance,
            arrive_reps,
            arrive_last_length,
        },
        &mut reaches,
    );

    let mut reversed = Buffer::new(&allowance);
    let mut index = span;
    while index > 0 {
        let length = arrive_length[index] as usize;
        if length == 0 {
            reversed.push(EncodeToken::Literal(combined[start + index - 1]))?;
            index -= 1;
        } else {
            reversed.push(EncodeToken::Match {
                length,
                distance: arrive_distance[index] as usize,
            })?;
            index -= length;
        }
    }
    reversed.reverse();
    Ok(reversed)
}

#[allow(clippy::too_many_arguments)]
fn reference_encode_tokens(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_>,
    options: EncodeOptions,
    distance_size: usize,
    initial_filters: &[EncodeFilter],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &Allowance,
) -> Result<Buffer<EncodeToken>> {
    let start = block.start;
    let end = block.end;
    if options.optimal_parse {
        let mut own;
        let collector = match search {
            MemberSearch::Optimal(collector) => collector,
            _ => {
                own = OptimalCollector::with_allowance(combined, start, options, allowance)?;
                &mut own
            }
        };
        let matches = collector.collect(combined, block.clone(), options)?;
        // The prices come from the Huffman tables, and the tables come from
        // the parse, so the first pass has to guess. Each pass after it prices
        // against what the pass before actually produced.
        let mut workspace = OptimalWorkspace::new(allowance);
        let mut tokens = reference_optimal_tokens(
            combined,
            block.clone(),
            options,
            distance_size,
            None,
            &matches,
            &mut workspace,
        )?;
        let mut lengths =
            table_lengths_with_allowance(&tokens, initial_filters, distance_size, allowance)?;
        let mut best_bits = token_stream_bits(&tokens, initial_filters, &lengths, distance_size)?;
        let mut best = None;
        for _ in 1..OPTIMAL_PARSE_PASSES {
            let prices = TokenPrices {
                lengths: lengths.slices(),
            };
            let next = reference_optimal_tokens(
                combined,
                block.clone(),
                options,
                distance_size,
                Some(&prices),
                &matches,
                &mut workspace,
            )?;
            if next == tokens {
                break;
            }
            lengths =
                table_lengths_with_allowance(&next, initial_filters, distance_size, allowance)?;
            let bits = token_stream_bits(&next, initial_filters, &lengths, distance_size)?;
            if bits < best_bits {
                best_bits = bits;
                best = None;
            } else if best.is_none() {
                // Keep an earlier winner only when repricing actually loses.
                best = Some(std::mem::replace(&mut tokens, Buffer::new(allowance)));
            }
            tokens = next;
        }
        let tokens = best.unwrap_or(tokens);
        if progress.is_some_and(|report| !report(end - start)) {
            return Err(Error::Cancelled);
        }
        return Ok(tokens);
    }

    unreachable!("the reference covers only optimal parsing");
}

#[allow(clippy::too_many_arguments)]
fn reference_encode_block(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_>,
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &Allowance,
) -> Result<Buffer<u8>> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    let mut tokens = reference_encode_tokens(
        combined,
        block,
        search,
        options,
        distance_size,
        initial_filters,
        progress,
        allowance,
    )?;
    if !initial_filters.is_empty() {
        tokens.prepend(initial_filters.iter().copied().map(EncodeToken::Filter))?;
    }
    encode_token_block_with_allowance(
        &tokens,
        algorithm_version,
        distance_size,
        is_last,
        allowance,
    )
}

fn noise(size: usize) -> Vec<u8> {
    let mut state = 0x8bad_f00du32;
    (0..size)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

fn empty_matches(span: usize, allowance: &Allowance) -> Result<BlockMatches> {
    Ok(BlockMatches {
        runs: Buffer::new(allowance),
        starts: Buffer::filled(span + 1, 0, allowance)?,
        commits: Buffer::new(allowance),
    })
}

#[derive(Debug, PartialEq, Eq)]
struct WorkspaceState {
    price: Vec<u32>,
    length: Vec<u32>,
    distance: Vec<u32>,
    reps: Vec<[u32; 4]>,
    last_length: Vec<u32>,
}

fn workspace_state(workspace: &OptimalWorkspace) -> WorkspaceState {
    WorkspaceState {
        price: workspace.price.to_vec(),
        length: workspace.arrive_length.to_vec(),
        distance: workspace.arrive_distance.to_vec(),
        reps: workspace.arrive_reps.to_vec(),
        last_length: workspace.arrive_last_length.to_vec(),
    }
}

fn poison(workspace: &mut OptimalWorkspace, span: usize) {
    workspace.price.resize(span + 1, 0x1234_5678).unwrap();
    workspace.price.fill(0x1234_5678);
    workspace.arrive_length.resize(span + 1, 4096).unwrap();
    workspace.arrive_length.fill(4096);
    workspace.arrive_distance.resize(span + 1, 257).unwrap();
    workspace.arrive_distance.fill(257);
    workspace
        .arrive_reps
        .resize(span + 1, [3, 3, 7, 3])
        .unwrap();
    workspace.arrive_reps.fill([3, 3, 7, 3]);
    workspace.arrive_last_length.resize(span + 1, 511).unwrap();
    workspace.arrive_last_length.fill(511);
}

#[test]
fn empty_collections_match_the_retained_parser_for_every_price_mode() {
    let allowance = Allowance::default();
    for data in [
        Vec::new(),
        vec![1],
        (0..=255).collect(),
        noise(4096),
        b"abcd".repeat(1024),
    ] {
        for start in [0, data.len().min(128)] {
            let block = start..data.len();
            for candidates in [0, 128] {
                // The candidate-zero case also proves that identical bytes and
                // nonzero history cannot invent a remembered distance.
                let options = EncodeOptions::new(candidates)
                    .with_optimal_parse(true)
                    .with_max_match_distance(if candidates == 0 { usize::MAX } else { 0 });
                let mut collector = OptimalCollector::new(&data, start, options);
                let matches = collector.collect(&data, block.clone(), options).unwrap();
                assert!(matches.runs.is_empty());
                for distance_size in [DISTANCE_TABLE_SIZE_50, DISTANCE_TABLE_SIZE_70] {
                    let mut workspace = OptimalWorkspace::new(&allowance);
                    let mut old = OptimalWorkspace::new(&allowance);
                    let literals = reference_optimal_tokens(
                        &data,
                        block.clone(),
                        options,
                        distance_size,
                        None,
                        &matches,
                        &mut old,
                    )
                    .unwrap();
                    let lengths = table_lengths_for_tokens(&literals, distance_size).unwrap();
                    let actual = TokenPrices {
                        lengths: lengths.slices(),
                    };
                    for prices in [None, Some(&actual)] {
                        poison(&mut workspace, block.len());
                        let before = workspace_state(&workspace);
                        let expected = reference_optimal_tokens(
                            &data,
                            block.clone(),
                            options,
                            distance_size,
                            prices,
                            &matches,
                            &mut old,
                        )
                        .unwrap();
                        let result = optimal_tokens_in_workspace(
                            &data,
                            block.clone(),
                            options,
                            distance_size,
                            prices,
                            &matches,
                            &mut workspace,
                        )
                        .unwrap();
                        assert_eq!(result, expected);
                        assert_eq!(
                            workspace_state(&workspace),
                            before,
                            "literal shortcut must not initialize or read stale arrays"
                        );
                        assert!(result
                            .iter()
                            .all(|token| matches!(token, EncodeToken::Literal(_))));
                    }
                }
            }
        }
    }
}

#[test]
fn real_no_match_collections_use_the_shortcut_and_later_matches_reset_poison() {
    let allowance = Allowance::default();
    let options = EncodeOptions::new(128).with_optimal_parse(true);
    let repeated = b"abcd".repeat(1024);
    let literal = noise(repeated.len());
    let mut repeat_collector = OptimalCollector::new(&repeated, 0, options);
    let repeat_matches = repeat_collector
        .collect(&repeated, 0..repeated.len(), options)
        .unwrap();
    assert!(!repeat_matches.runs.is_empty());
    let mut literal_collector = OptimalCollector::new(&literal, 0, options);
    let literal_matches = literal_collector
        .collect(&literal, 0..literal.len(), options)
        .unwrap();
    assert!(
        literal_matches.runs.is_empty(),
        "fixture must really contain no collected four-byte match"
    );
    for distance_size in [DISTANCE_TABLE_SIZE_50, DISTANCE_TABLE_SIZE_70] {
        let mut workspace = OptimalWorkspace::new(&allowance);
        let mut old = OptimalWorkspace::new(&allowance);
        for (data, matches) in [
            (&repeated, &repeat_matches),
            (&literal, &literal_matches),
            (&repeated, &repeat_matches),
        ] {
            poison(&mut workspace, repeated.len());
            poison(&mut old, repeated.len());
            let before = workspace_state(&workspace);
            let expected = reference_optimal_tokens(
                data,
                0..data.len(),
                options,
                distance_size,
                None,
                matches,
                &mut old,
            )
            .unwrap();
            let result = optimal_tokens_in_workspace(
                data,
                0..data.len(),
                options,
                distance_size,
                None,
                matches,
                &mut workspace,
            )
            .unwrap();
            assert_eq!(result, expected);
            if matches.runs.is_empty() {
                assert_eq!(workspace_state(&workspace), before);
            } else {
                // Distance memory is scratch past the positions priced from.
                let (now, then) = (workspace_state(&workspace), workspace_state(&old));
                assert_eq!(
                    (now.price, now.length, now.distance),
                    (then.price, then.length, then.distance)
                );
            }
        }
    }
}

#[test]
fn literal_pipeline_keeps_filters_winner_selection_and_packed_bytes() {
    let allowance = Allowance::default();
    let input = noise(4096);
    let specs = [
        crate::FilterSpec::whole(crate::FilterKind::Delta { channels: 4 }),
        crate::FilterSpec::whole(crate::FilterKind::Arm),
    ];
    for candidates in [0, 128] {
        let options = EncodeOptions::new(candidates).with_optimal_parse(true);
        for version in [0, 1] {
            for specs in [&[][..], &specs[..1], &specs[1..]] {
                let (transformed, records) =
                    filtered_member_with_allowance(&input, specs, &allowance).unwrap();
                let mut collector = OptimalCollector::new(&transformed, 0, options);
                let matches = collector
                    .collect(&transformed, 0..transformed.len(), options)
                    .unwrap();
                assert!(matches.runs.is_empty());
                let expected = reference_encode_block(
                    &transformed,
                    0..transformed.len(),
                    MemberSearch::Fresh,
                    version,
                    &records,
                    options,
                    true,
                    None,
                    &allowance,
                )
                .unwrap();
                let actual = Unpack50Encoder::with_options(options)
                    .encode_member_with_filters(&input, version, specs)
                    .unwrap();
                assert_eq!(&*expected, actual);
                let decoded = Unpack50Decoder::new()
                    .decode_member(&actual, version, input.len(), false, DecodeMode::Lz)
                    .unwrap();
                assert_eq!(decoded, input);
            }
        }
    }
}

#[test]
fn literal_pipeline_retains_validation_before_final_progress_and_cancellation() {
    let allowance = Allowance::default();
    let data: Vec<_> = (0..32).collect();
    let options = EncodeOptions::new(128).with_optimal_parse(true);
    let valid = EncodeFilter {
        offset: 0,
        length: data.len(),
        filter_type: FilterType::Delta,
        channels: 1,
    };
    let invalid = EncodeFilter {
        channels: 0,
        ..valid
    };
    for version in [0, 1, 2] {
        for records in [&[][..], &[valid][..], &[invalid][..]] {
            for continue_work in [true, false] {
                let mut expected_reports = Vec::new();
                let mut expected_report = |amount| {
                    expected_reports.push(amount);
                    continue_work
                };
                let expected = reference_encode_block(
                    &data,
                    0..data.len(),
                    MemberSearch::Fresh,
                    version,
                    records,
                    options,
                    true,
                    Some(&mut expected_report),
                    &allowance,
                )
                .map(|buffer| buffer.to_vec());
                let mut actual_reports = Vec::new();
                let mut actual_report = |amount| {
                    actual_reports.push(amount);
                    continue_work
                };
                let actual = encode_lz_block_with_allowance(
                    &data,
                    0..data.len(),
                    MemberSearch::Fresh,
                    version,
                    records,
                    options,
                    true,
                    Some(&mut actual_report),
                    &allowance,
                )
                .map(|buffer| buffer.to_vec());
                assert_eq!(actual, expected);
                assert_eq!(actual_reports, expected_reports);
                if version > 1 || records == [invalid] {
                    assert!(actual_reports.is_empty());
                    assert!(matches!(actual, Err(Error::InvalidData(_))));
                } else {
                    assert_eq!(actual_reports, [data.len()]);
                    if !continue_work {
                        assert!(matches!(actual, Err(Error::Cancelled)));
                    }
                }
            }
        }
    }
}

fn bounded_parse(allowance: &Allowance, old: bool) -> (Result<Vec<EncodeToken>>, WorkspaceState) {
    let data: Vec<_> = (0..32).collect();
    let options = EncodeOptions::new(128).with_optimal_parse(true);
    let mut workspace = OptimalWorkspace::new(allowance);
    let result = (|| {
        let matches = empty_matches(data.len(), allowance)?;
        if old {
            reference_optimal_tokens(
                &data,
                0..data.len(),
                options,
                DISTANCE_TABLE_SIZE_50,
                None,
                &matches,
                &mut workspace,
            )
        } else {
            optimal_tokens_in_workspace(
                &data,
                0..data.len(),
                options,
                DISTANCE_TABLE_SIZE_50,
                None,
                &matches,
                &mut workspace,
            )
        }
    })()
    .map(|buffer| buffer.to_vec());
    (result, workspace_state(&workspace))
}

#[test]
fn bounded_literal_parses_match_the_full_parse_or_refuse_and_release_everything() {
    let unlimited = bounded_parse(&Allowance::default(), true).0.unwrap();
    let mut saw_limit = false;
    let mut saw_success = false;
    for limit in [0, 32, 128, 132, 256, 512, 1024, 2048, 4096, 65536] {
        let expected_budget = Allowance::limited(limit);
        let actual_budget = Allowance::limited(limit);
        let expected = bounded_parse(&expected_budget, true);
        let actual = bounded_parse(&actual_budget, false);
        saw_limit |= matches!(actual.0, Err(Error::WorkspaceLimitExceeded(_)));
        saw_success |= actual.0.is_ok();
        match &actual.0 {
            Ok(packed) => assert_eq!(packed, &unlimited, "limit={limit}"),
            Err(error) => assert!(
                matches!(error, Error::WorkspaceLimitExceeded(_)),
                "limit={limit}: {error}"
            ),
        }
        // The literal-only path does no more than the full parse.
        assert!(expected.0.is_err() || actual.0.is_ok(), "limit={limit}");
        assert_eq!(
            actual_budget.used(),
            0,
            "all owned charges must be released"
        );
        assert_eq!(expected_budget.used(), 0);
    }
    assert!(saw_limit && saw_success);
    let mut saw_refusal = false;
    let mut saw_success = false;
    for fail_at in 0..24 {
        let actual_budget = Allowance::refusing(fail_at);
        let actual = bounded_parse(&actual_budget, false);
        saw_refusal |= matches!(actual.0, Err(Error::Cancelled));
        saw_success |= actual.0.is_ok();
        match &actual.0 {
            Ok(packed) => assert_eq!(packed, &unlimited, "growth refusal={fail_at}"),
            Err(error) => assert_eq!(error, &Error::Cancelled, "growth refusal={fail_at}"),
        }
        assert_eq!(actual_budget.used(), 0);
    }
    assert!(saw_refusal && saw_success);
}

#[test]
fn bounded_outer_pipeline_keeps_errors_before_progress() {
    let data: Vec<_> = (0..32).collect();
    let options = EncodeOptions::new(128).with_optimal_parse(true);
    for limit in [0, 128, 4096, 65536, 8 * 1024 * 1024] {
        let mut expected_reports = Vec::new();
        let mut expected_report = |amount| {
            expected_reports.push(amount);
            false
        };
        let expected = reference_encode_block(
            &data,
            0..data.len(),
            MemberSearch::Fresh,
            0,
            &[],
            options,
            true,
            Some(&mut expected_report),
            &Allowance::limited(limit),
        )
        .map(|buffer| buffer.to_vec());
        let mut actual_reports = Vec::new();
        let mut actual_report = |amount| {
            actual_reports.push(amount);
            false
        };
        let actual = encode_lz_block_with_allowance(
            &data,
            0..data.len(),
            MemberSearch::Fresh,
            0,
            &[],
            options,
            true,
            Some(&mut actual_report),
            &Allowance::limited(limit),
        )
        .map(|buffer| buffer.to_vec());
        assert_eq!(actual, expected, "limit={limit}");
        assert_eq!(actual_reports, expected_reports);
    }
}

#[test]
fn literal_outer_pipeline_matches_old_parses_for_history_tails_and_real_matches() {
    let allowance = Allowance::default();
    let mut rare_repeat = noise(4096);
    rare_repeat.copy_within(128..144, 192);
    let cases = [
        Vec::new(),
        vec![7],
        (0..32).collect(),
        (0..=255).collect(),
        noise(4096),
        b"abcd".repeat(8),
        rare_repeat,
    ];
    let mut saw_empty = false;
    let mut saw_matches = false;
    for data in cases {
        for start in [0, data.len().min(3), data.len().min(128)] {
            for candidates in [0, 128] {
                let options = EncodeOptions::new(candidates).with_optimal_parse(true);
                let mut collector = OptimalCollector::new(&data, start, options);
                let matches = collector
                    .collect(&data, start..data.len(), options)
                    .unwrap();
                saw_empty |= matches.runs.is_empty();
                saw_matches |= !matches.runs.is_empty();
                for distance_size in [DISTANCE_TABLE_SIZE_50, DISTANCE_TABLE_SIZE_70] {
                    for continue_work in [true, false] {
                        let mut expected_reports = Vec::new();
                        let mut expected_report = |amount| {
                            expected_reports.push(amount);
                            continue_work
                        };
                        let expected = reference_encode_tokens(
                            &data,
                            start..data.len(),
                            MemberSearch::Fresh,
                            options,
                            distance_size,
                            &[],
                            Some(&mut expected_report),
                            &allowance,
                        );
                        let mut actual_reports = Vec::new();
                        let mut actual_report = |amount| {
                            actual_reports.push(amount);
                            continue_work
                        };
                        let actual = encode_tokens_with_allowance(
                            &data,
                            start..data.len(),
                            MemberSearch::Fresh,
                            options,
                            distance_size,
                            &[],
                            Some(&mut actual_report),
                            &allowance,
                        );
                        assert_eq!(actual, expected, "start={start}, candidates={candidates}");
                        assert_eq!(actual_reports, expected_reports);
                        assert_eq!(actual_reports, [data.len() - start]);
                    }
                }
            }
        }
    }
    assert!(saw_empty && saw_matches);
}

#[test]
fn bounded_outer_reparses_match_the_reference_or_refuse_and_release_everything() {
    let data: Vec<_> = (0..32).collect();
    let options = EncodeOptions::new(128).with_optimal_parse(true);
    let unlimited = reference_encode_block(
        &data,
        0..data.len(),
        MemberSearch::Fresh,
        0,
        &[],
        options,
        true,
        None,
        &Allowance::default(),
    )
    .map(|buffer| buffer.to_vec())
    .unwrap();
    let mut saw_refusal = false;
    let mut saw_success = false;
    for fail_at in 0..128 {
        for continue_work in [true, false] {
            let actual_budget = Allowance::refusing(fail_at);
            let mut actual_reports = Vec::new();
            let mut actual_report = |amount| {
                actual_reports.push(amount);
                continue_work
            };
            let actual = encode_lz_block_with_allowance(
                &data,
                0..data.len(),
                MemberSearch::Fresh,
                0,
                &[],
                options,
                true,
                Some(&mut actual_report),
                &actual_budget,
            )
            .map(|buffer| buffer.to_vec());
            saw_refusal |= matches!(actual, Err(Error::Cancelled));
            saw_success |= actual.is_ok();
            match &actual {
                Ok(packed) => assert_eq!(
                    packed, &unlimited,
                    "fail_at={fail_at}, continue={continue_work}"
                ),
                Err(error) => assert_eq!(error, &Error::Cancelled),
            }
            assert_eq!(actual_budget.used(), 0);
        }
    }
    assert!(saw_refusal && saw_success);
}

// Retain the original upstream scalar pricing loop as an independent oracle.
#[allow(clippy::too_many_arguments)]
fn reference_price_optimal_paths(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    runs: &[(u32, u32)],
    starts: &[u32],
    workspace: OptimalSlices<'_>,
    reaches: &mut [(usize, usize, usize)],
) {
    let start = block.start;
    let end = block.end;
    let span = end - start;
    let OptimalSlices {
        price,
        arrive_length,
        arrive_distance,
        arrive_reps,
        arrive_last_length,
    } = workspace;
    // The first position past a match the parse committed to. Nothing is
    // priced from the positions before it. See [`NICE_MATCH_LENGTH`].
    let mut committed_through = 0usize;

    for index in 0..span {
        let pos = start + index;
        if index < committed_through {
            continue;
        }
        // Every priced position extends a literal path to its successor;
        // a committed match skips only to an already priced endpoint. Blocks
        // are at most 1 MiB, so even all 15-bit literals stay below u32::MAX.
        let here = price[index];
        let literal_cost = prices.map_or(ESTIMATED_LITERAL_COST, |prices| {
            prices.literal(combined[pos]) as u32
        });
        let literal = here.saturating_add(literal_cost);
        if literal < price[index + 1] {
            price[index + 1] = literal;
            arrive_length[index + 1] = 0;
            arrive_distance[index + 1] = 0;
            // A literal emits no distance, so it leaves the remembered ones
            // exactly as it found them.
            arrive_reps[index + 1] = arrive_reps[index];
            arrive_last_length[index + 1] = arrive_last_length[index];
        }

        let max_distance = pos.min(options.max_match_distance);
        let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        if options.max_match_candidates == 0 || max_distance == 0 || max_length < 4 {
            continue;
        }

        let state = EncoderMatchState {
            reps: arrive_reps[index].map(|distance| distance as usize),
            last_length: arrive_last_length[index] as usize,
        };

        let mut reaches_len = 0;
        let mut longest = 0usize;

        // A match at a remembered distance is priced out of the main table
        // alone, a handful of bits against twenty for a fresh distance, so it
        // earns its place even when it is shorter than anything the collector
        // found. The collector only reports a candidate that beats the longest
        // found so far, so these have to be asked for separately.
        for repeat in state.reps {
            if repeat == 0 || repeat > max_distance {
                continue;
            }
            let length = match_length(combined, pos, repeat, max_length);
            if length >= 4 {
                reaches[reaches_len] = (4, length, repeat);
                reaches_len += 1;
            }
        }

        // The collector reports nearest first, so the first distance to reach
        // a length is the cheapest one that can. Each report that improves on
        // the longest so far owns one run of lengths. The tree measures
        // against the whole member where the chains stopped at the block, so
        // a length is capped here to what this block can still hold.
        for &(length, distance) in &runs[starts[index] as usize..starts[index + 1] as usize] {
            let length = (length as usize).min(max_length);
            if length > longest {
                reaches[reaches_len] = (longest + 1, length, distance as usize);
                reaches_len += 1;
                longest = length;
            }
        }

        let reaches = &reaches[..reaches_len];

        // Equal token prices do not make shorter matches redundant: their
        // endpoints can expose a better continuation. Price every endpoint
        // unless the explicit long-match heuristic commits past all of them.
        let committed_reach = reaches
            .iter()
            .map(|&(_, end, _)| end)
            .max()
            .filter(|&length| length >= NICE_MATCH_LENGTH);
        for &(run_start, run_end, distance) in reaches.iter() {
            let mut length = run_start.max(4);
            if let Some(committed) = committed_reach {
                if run_end < committed {
                    continue;
                }
                length = committed;
            }
            while length <= run_end {
                let reach = length;
                let cost = match prices {
                    Some(prices) => prices.match_cost(&state, reach, distance, distance_size),
                    None => estimated_match_cost(&state, reach, distance, distance_size),
                };
                if let Ok(cost) = cost {
                    let reached = here.saturating_add(cost as u32);
                    let target = index + reach;
                    if reached < price[target] {
                        price[target] = reached;
                        arrive_length[target] = reach as u32;
                        arrive_distance[target] = distance as u32;
                        let mut next = state;
                        next.remember(reach, distance);
                        arrive_reps[target] = next.reps.map(|distance| distance as u32);
                        arrive_last_length[target] = next.last_length as u32;
                    }
                }
                length = reach + 1;
            }
        }

        // A committed match is at least 512 bytes long. Even after the
        // distance bonus, that length and every collected u32 distance fit
        // their encoder tables, so the endpoint has already been priced.
        let longest_reach = reaches.iter().map(|&(_, length, _)| length).max();
        if let Some(reach) = longest_reach {
            if reach >= NICE_MATCH_LENGTH {
                committed_through = index + reach;
            }
        }
    }
}
