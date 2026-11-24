use super::*;

#[test]
fn prepared_run_prices_preserve_every_length_and_distance_boundary() {
    let distances = [0, 1, 3, 4, 5, 256, 257, 8192, 8193, 262144, 262145, 1 << 22];
    let states = [
        EncoderMatchState::default(),
        EncoderMatchState {
            reps: [1, 257, 8193, 262145],
            last_length: 511,
        },
        EncoderMatchState {
            reps: [3, 3, 7, 3],
            last_length: 4,
        },
    ];
    for seed in [0, 1, 7] {
        let codes = |size: usize| {
            (0..size)
                .map(|symbol| ((symbol * seed + seed) & 15) as u8)
                .collect::<Vec<_>>()
        };
        let main = codes(MAIN_TABLE_SIZE);
        let distance = codes(DISTANCE_TABLE_SIZE_70);
        let align = codes(ALIGN_TABLE_SIZE);
        let length = codes(LENGTH_TABLE_SIZE);
        let actual = TokenPrices {
            lengths: LengthSlices {
                main: &main,
                distance: &distance,
                align: &align,
                length: &length,
            },
        };
        for prices in [None, Some(&actual)] {
            let prepared = OptimalMatchPrices::new(prices);
            for distance_size in [DISTANCE_TABLE_SIZE_50, DISTANCE_TABLE_SIZE_70] {
                for state in states {
                    for distance in distances {
                        let run = prepared.run(&state, distance, distance_size, prices).ok();
                        for length in 1..=MAX_ENCODER_MATCH_LENGTH {
                            let expected = match prices {
                                Some(prices) => {
                                    prices.match_cost(&state, length, distance, distance_size)
                                }
                                None => {
                                    estimated_match_cost(&state, length, distance, distance_size)
                                }
                            }
                            .ok()
                            .map(|cost| cost as u32);
                            assert_eq!(
                                run.as_ref().and_then(|run| run.cost(length)),
                                expected,
                                "seed={seed}, actual={}, state={state:?}, distance={distance}, length={length}, table={distance_size}",
                                prices.is_some(),
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
#[cfg(target_pointer_width = "64")]
fn prepared_run_prices_refuse_unencodable_fresh_distances() {
    let prepared = OptimalMatchPrices::new(None);
    let state = EncoderMatchState::default();
    for (distance, size) in [
        (1usize << 40, DISTANCE_TABLE_SIZE_50),
        ((1usize << 40) + 1, DISTANCE_TABLE_SIZE_70),
    ] {
        assert!(prepared.run(&state, distance, size, None).is_err());
        assert!(estimated_match_cost(&state, 5, distance, size).is_err());
    }
}

#[derive(Debug, PartialEq)]
struct Paths {
    price: Vec<u32>,
    length: Vec<u32>,
    distance: Vec<u32>,
    reps: Vec<[u32; 4]>,
    last_length: Vec<u32>,
}

impl Paths {
    fn new(span: usize) -> Self {
        let mut price = vec![u32::MAX; span + 1];
        price[0] = 0;
        Self {
            price,
            length: vec![0; span + 1],
            distance: vec![0; span + 1],
            reps: vec![[0; 4]; span + 1],
            last_length: vec![0; span + 1],
        }
    }

    fn paths(&self) -> (&[u32], &[u32], &[u32]) {
        (&self.price, &self.length, &self.distance)
    }

    fn slices(&mut self) -> OptimalSlices<'_> {
        OptimalSlices {
            price: &mut self.price,
            arrive_length: &mut self.length,
            arrive_distance: &mut self.distance,
            arrive_reps: &mut self.reps,
            arrive_last_length: &mut self.last_length,
        }
    }
}

#[test]
fn prepared_pricing_preserves_all_paths_and_remembered_state() {
    let mut random = 0x1234_5678u32;
    let noise: Vec<_> = (0..4096)
        .map(|_| {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (random >> 31) as u8
        })
        .collect();
    let mut text = Vec::new();
    for i in 0..80 {
        text.extend_from_slice(b"the same match exposes different continuations ");
        text.push(i);
    }
    for data in [
        vec![0; 4096],
        b"abc".repeat(1366),
        text,
        noise,
        (0..1024u32)
            .flat_map(|word| (word * 71).to_le_bytes())
            .collect(),
    ] {
        for start in [0, 256] {
            let block = start..data.len();
            for candidates in [0, 16, 128] {
                let options = EncodeOptions::new(candidates).with_optimal_parse(true);
                let mut collector = OptimalCollector::new(&data, start, options);
                let matches = collector.collect(&data, block.clone(), options).unwrap();
                let capacity = matches
                    .starts
                    .windows(2)
                    .map(|pair| (pair[1] - pair[0]) as usize)
                    .max()
                    .unwrap_or(0)
                    + 4;
                for distance_size in [DISTANCE_TABLE_SIZE_50, DISTANCE_TABLE_SIZE_70] {
                    let mut workspace = OptimalWorkspace::new(&Allowance::default());
                    let tokens = optimal_tokens_in_workspace(
                        &data,
                        block.clone(),
                        options,
                        distance_size,
                        None,
                        &matches,
                        &mut workspace,
                    )
                    .unwrap();
                    let lengths = table_lengths_for_tokens(&tokens, distance_size).unwrap();
                    let actual = TokenPrices {
                        lengths: lengths.slices(),
                    };
                    for prices in [None, Some(&actual)] {
                        let mut expected = Paths::new(block.len());
                        let mut result = Paths::new(block.len());
                        let mut reaches = vec![(0, 0, 0); capacity];
                        reference_price_optimal_paths(
                            &data,
                            block.clone(),
                            options,
                            distance_size,
                            prices,
                            &matches.runs,
                            &matches.starts,
                            expected.slices(),
                            &mut reaches,
                        );
                        price_optimal_paths(
                            &data,
                            block.clone(),
                            options,
                            distance_size,
                            prices,
                            &matches.runs,
                            &matches.starts,
                            &matches.commits,
                            result.slices(),
                            &mut reaches,
                        );
                        // Distance memory is scratch, settled only at the
                        // positions the parse prices from, so compare the paths.
                        assert_eq!(result.paths(), expected.paths(), "start={start}, candidates={candidates}, table={distance_size}, actual={}", prices.is_some());
                    }
                }
            }
        }
    }
}

#[test]
fn ring_state_preserves_full_backtrace_endpoint_and_three_pricing_passes() {
    let span = 3 * OPTIMAL_STATE_RING_SIZE + 257;
    let mut random = 0xA17E_3B29u32;
    let mut mixed: Vec<_> = (0..span)
        .map(|_| {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (random >> 28) as u8
        })
        .collect();
    // A maximum-length match straddles a ring boundary and commits across
    // positions that may already have finite incoming prices.
    mixed.copy_within(0..MAX_ENCODER_MATCH_LENGTH, OPTIMAL_STATE_RING_SIZE - 2);
    let allowance = Allowance::default();
    let options = EncodeOptions::new(16).with_optimal_parse(true);
    for data in [vec![0; span], mixed] {
        let block = 0..data.len();
        let mut collector = OptimalCollector::new(&data, 0, options);
        let matches = collector.collect(&data, block.clone(), options).unwrap();
        assert!(matches
            .runs
            .iter()
            .any(|&(length, _)| length as usize == MAX_ENCODER_MATCH_LENGTH));
        let capacity = matches
            .starts
            .windows(2)
            .map(|pair| (pair[1] - pair[0]) as usize)
            .max()
            .unwrap_or(0)
            + 4;
        let mut workspace = OptimalWorkspace::new(&allowance);
        let mut previous_lengths: Option<OwnedLengths> = None;
        for _ in 0..OPTIMAL_PARSE_PASSES {
            let actual_prices = previous_lengths.as_ref().map(|lengths| TokenPrices {
                lengths: lengths.slices(),
            });
            let prices = actual_prices.as_ref();
            let mut expected = Paths::new(span);
            let mut reaches = vec![(0, 0, 0); capacity];
            reference_price_optimal_paths(
                &data,
                block.clone(),
                options,
                DISTANCE_TABLE_SIZE_50,
                prices,
                &matches.runs,
                &matches.starts,
                expected.slices(),
                &mut reaches,
            );
            let tokens = optimal_tokens_in_workspace(
                &data,
                block.clone(),
                options,
                DISTANCE_TABLE_SIZE_50,
                prices,
                &matches,
                &mut workspace,
            )
            .unwrap();
            assert_eq!(&workspace.arrive_length[..], &expected.length);
            assert_eq!(&workspace.arrive_distance[..], &expected.distance);
            assert_eq!(&workspace.price[..], &expected.price);
            assert_eq!(workspace.arrive_reps.len(), OPTIMAL_STATE_RING_SIZE);
            assert_eq!(workspace.arrive_last_length.len(), OPTIMAL_STATE_RING_SIZE);

            let mut expected_tokens = Vec::new();
            let mut index = span;
            while index != 0 {
                let length = expected.length[index] as usize;
                if length == 0 {
                    expected_tokens.push(EncodeToken::Literal(data[index - 1]));
                    index -= 1;
                } else {
                    expected_tokens.push(EncodeToken::Match {
                        length,
                        distance: expected.distance[index] as usize,
                    });
                    index -= length;
                }
            }
            expected_tokens.reverse();
            assert_eq!(&tokens[..], &expected_tokens);
            previous_lengths =
                Some(table_lengths_for_tokens(&tokens, DISTANCE_TABLE_SIZE_50).unwrap());
        }
    }
}

#[test]
fn ring_state_allocation_refusal_and_cancellation_release_every_owner() {
    use crate::codec::workspace::RefusingBudget;
    let data = vec![0; 2 * OPTIMAL_STATE_RING_SIZE + 128];
    let options = EncodeOptions::new(16).with_optimal_parse(true);
    let run = |budget: &RefusingBudget| {
        encode_tokens_with_allowance(
            &data,
            0..data.len(),
            MemberSearch::Fresh,
            options,
            DISTANCE_TABLE_SIZE_50,
            &[],
            None,
            budget,
        )
    };
    let baseline = RefusingBudget::new(usize::MAX);
    drop(run(&baseline).unwrap());
    let attempts = baseline.attempts();
    assert!(attempts > 0);
    assert_eq!(baseline.used(), 0);
    for fail_at in 0..attempts {
        let budget = RefusingBudget::new(fail_at);
        assert!(
            matches!(run(&budget), Err(Error::Cancelled)),
            "allocation{fail_at}"
        );
        assert_eq!(budget.used(), 0, "allocation{fail_at}");
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
            &allowance,
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(allowance.used(), 0);
}

// Independent pre-hoisting implementation retained for differential checks.
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
