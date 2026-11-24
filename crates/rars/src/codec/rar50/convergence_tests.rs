use super::*;
use std::cell::Cell;

thread_local! {
    static PRICING_PASSES: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn record_pricing_pass() {
    PRICING_PASSES.with(|count| count.set(count.get() + 1));
}

fn count_passes<T>(run: impl FnOnce() -> T) -> (T, usize) {
    PRICING_PASSES.with(|count| count.set(0));
    let result = run();
    (result, PRICING_PASSES.with(Cell::get))
}

#[derive(Debug)]
struct Reprice {
    changed: bool,
    tables_converged: bool,
    bits: usize,
    best_bits_before: usize,
}

struct Reference {
    selected: Vec<EncodeToken>,
    passes: usize,
    reprices: Vec<Reprice>,
    selected_pass: usize,
}

// Independent original three-pass pipeline, including its strict winner and
// earlier-winner-on-tie behavior. It deliberately does not stop on equal tables.
fn reference_pipeline(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    filters: &[EncodeFilter],
) -> Reference {
    let allowance = Allowance::default();
    let mut collector = OptimalCollector::new(combined, block.start, options);
    let matches = collector.collect(combined, block.clone(), options).unwrap();
    let mut workspace = OptimalWorkspace::new(&allowance);
    let mut tokens = optimal_tokens_in_workspace(
        combined,
        block.clone(),
        options,
        distance_size,
        None,
        &matches,
        &mut workspace,
    )
    .unwrap();
    let mut passes = 1;
    let mut lengths =
        table_lengths_with_allowance(&tokens, filters, distance_size, &allowance).unwrap();
    let mut best_bits = token_stream_bits(&tokens, filters, &lengths, distance_size).unwrap();
    let mut best = None;
    let mut selected_pass = 0;
    let mut reprices = Vec::new();
    for _ in 1..OPTIMAL_PARSE_PASSES {
        let prices = TokenPrices {
            lengths: lengths.slices(),
        };
        let next = optimal_tokens_in_workspace(
            combined,
            block.clone(),
            options,
            distance_size,
            Some(&prices),
            &matches,
            &mut workspace,
        )
        .unwrap();
        passes += 1;
        if next == tokens {
            reprices.push(Reprice {
                changed: false,
                tables_converged: true,
                bits: best_bits,
                best_bits_before: best_bits,
            });
            break;
        }
        let next_lengths =
            table_lengths_with_allowance(&next, filters, distance_size, &allowance).unwrap();
        let tables_converged = lengths.slices() == next_lengths.slices();
        lengths = next_lengths;
        let bits = token_stream_bits(&next, filters, &lengths, distance_size).unwrap();
        reprices.push(Reprice {
            changed: true,
            tables_converged,
            bits,
            best_bits_before: best_bits,
        });
        if bits < best_bits {
            best_bits = bits;
            best = None;
            selected_pass = passes - 1;
        } else if best.is_none() {
            best = Some(std::mem::replace(&mut tokens, Buffer::new(&allowance)));
        }
        tokens = next;
    }
    Reference {
        selected: best.unwrap_or(tokens).into_vec(),
        passes,
        reprices,
        selected_pass,
    }
}

fn generated_noise(seed: u32, size: usize, alphabet: u8) -> Vec<u8> {
    let mut state = seed;
    (0..size)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((state >> 24) as u8) % alphabet
        })
        .collect()
}

fn compare_pipeline(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    algorithm_version: u8,
    filters: &[EncodeFilter],
) -> (Reference, usize) {
    assert!(filters
        .iter()
        .all(|filter| filter.offset + filter.length <= block.len()));
    let distance_size = if algorithm_version == 0 {
        DISTANCE_TABLE_SIZE_50
    } else {
        DISTANCE_TABLE_SIZE_70
    };
    let (reference, reference_passes) = count_passes(|| {
        reference_pipeline(combined, block.clone(), options, distance_size, filters)
    });
    assert_eq!(reference.passes, reference_passes);
    let (actual, actual_passes) = count_passes(|| {
        encode_tokens_with_allowance(
            combined,
            block.clone(),
            MemberSearch::Fresh,
            options,
            distance_size,
            filters,
            None,
            &Allowance::default(),
        )
        .unwrap()
    });
    assert_eq!(
        &*actual,
        reference.selected,
        "start={}, candidates={}, version={algorithm_version}, filters={}",
        block.start,
        options.max_match_candidates,
        filters.len()
    );
    assert!(actual_passes <= reference.passes);
    let expected_full: Vec<_> = filters
        .iter()
        .copied()
        .map(EncodeToken::Filter)
        .chain(reference.selected.iter().copied())
        .collect();
    let actual_full: Vec<_> = filters
        .iter()
        .copied()
        .map(EncodeToken::Filter)
        .chain(actual.iter().copied())
        .collect();
    assert_eq!(
        encode_token_block(&actual_full, algorithm_version, distance_size, true).unwrap(),
        encode_token_block(&expected_full, algorithm_version, distance_size, true).unwrap(),
    );
    (reference, actual_passes)
}

#[test]
fn equal_tables_with_changed_tokens_skip_a_real_pricing_pass() {
    // The first Huffman-priced pass chooses a different token sequence, but
    // generates exactly the same four tables, so no third pass is priced.
    let input = generated_noise(92, 256, 2);
    let options = EncodeOptions::new(16).with_optimal_parse(true);
    for version in [0, 1] {
        let (reference, actual_passes) =
            compare_pipeline(&input, 0..input.len(), options, version, &[]);
        assert_eq!(reference.passes, 3);
        assert_eq!(actual_passes, 2);
        assert!(reference.reprices[0].changed);
        assert!(reference.reprices[0].tables_converged);
        assert!(!reference.reprices[1].changed);
        assert_eq!(
            reference.reprices[0].bits + 3,
            reference.reprices[0].best_bits_before
        );
        if version == 0 {
            assert_eq!(reference.reprices[0].best_bits_before, 575);
            assert_eq!(reference.reprices[0].bits, 572);
        }
        assert_eq!(reference.selected_pass, 1);
    }
}

#[test]
fn convergence_preserves_the_earlier_winner_on_ties_and_losses() {
    let options = EncodeOptions::new(16).with_optimal_parse(true);
    let mut saw_final_tie = false;
    let mut saw_final_loss = false;
    for version in [0, 1] {
        for seed in 0..128 {
            let input = generated_noise(seed, 256, 2);
            let (reference, _) = compare_pipeline(&input, 0..input.len(), options, version, &[]);
            let last = reference.reprices.last().unwrap();
            if last.changed && reference.selected_pass < reference.passes - 1 {
                saw_final_tie |= last.bits == last.best_bits_before;
                saw_final_loss |= last.bits > last.best_bits_before;
            }
            // A first-pass tie must not displace the earlier winner, while
            // the later strict improvement must still be selected.
            if version == 0 && seed == 3 {
                assert!(reference.reprices[0].changed);
                assert_eq!(
                    reference.reprices[0].bits,
                    reference.reprices[0].best_bits_before
                );
                assert_eq!(reference.selected_pass, 2);
            }
            // A losing reprice followed by an improvement must not leave the
            // earlier retained stream in place after that improvement.
            if version == 0 && seed == 1 {
                assert!(reference.reprices[0].bits > reference.reprices[0].best_bits_before);
                assert!(reference.reprices[1].bits < reference.reprices[1].best_bits_before);
                assert_eq!(reference.selected_pass, 2);
            }
        }
    }
    assert!(
        saw_final_tie,
        "corpus must retain an earlier winner on a final tie"
    );
    assert!(
        saw_final_loss,
        "corpus must retain an earlier winner on a final loss"
    );
}

#[test]
fn convergence_matches_the_original_pipeline_with_filters_and_history() {
    let filters = [
        EncodeFilter {
            offset: 0,
            length: 64,
            filter_type: FilterType::Delta,
            channels: 4,
        },
        EncodeFilter {
            offset: 64,
            length: 64,
            filter_type: FilterType::Arm,
            channels: 0,
        },
    ];
    let mut text = Vec::new();
    for i in 0..80 {
        text.extend_from_slice(b"repeated text with changing tails exposes shorter continuations ");
        text.push(i);
    }
    let corpus = [
        vec![0; 4096],
        b"abc".repeat(1366),
        text,
        generated_noise(92, 256, 2),
        generated_noise(23, 4096, 2),
        generated_noise(17, 4096, 255),
        (0..1024u32)
            .flat_map(|word| (word * 71).to_le_bytes())
            .collect(),
    ];
    for data in corpus {
        for start in [0, 128] {
            for candidates in [0, 16, 128] {
                let options = EncodeOptions::new(candidates).with_optimal_parse(true);
                for version in [0, 1] {
                    for records in [&[][..], &filters[..]] {
                        compare_pipeline(&data, start..data.len(), options, version, records);
                    }
                }
            }
        }
    }
}

#[test]
fn converged_pricing_keeps_the_final_progress_and_cancellation_boundary() {
    let input = generated_noise(92, 256, 2);
    let options = EncodeOptions::new(16).with_optimal_parse(true);
    for continue_work in [true, false] {
        let mut reports = Vec::new();
        let mut report = |amount| {
            reports.push(amount);
            continue_work
        };
        let result = encode_tokens_with_allowance(
            &input,
            0..input.len(),
            MemberSearch::Fresh,
            options,
            DISTANCE_TABLE_SIZE_50,
            &[],
            Some(&mut report),
            &Allowance::default(),
        );
        assert_eq!(reports, [input.len()]);
        if continue_work {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Error::Cancelled)));
        }
    }
}
