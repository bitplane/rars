#[test]
fn public_decoder_clone_keeps_independent_lz_and_ppmd_solid_state() {
    let first = b"RAR29 model and window history ".repeat(32);
    let second = b"RAR29 model and window history ".repeat(8);
    for engine in [super::ChainEngine::Lz, super::ChainEngine::Ppmd] {
        let mut encoder = super::Unpack29Encoder::new();
        let packed_first = encoder
            .encode_member_with_engine(&first, engine, &[], &mut |_| true)
            .unwrap();
        let packed_second = encoder
            .encode_member_with_engine(&second, engine, &[], &mut |_| true)
            .unwrap();
        let mut original = super::Unpack29::new();
        assert_eq!(
            original
                .decode_non_solid_member(&packed_first, first.len())
                .unwrap(),
            first
        );
        let mut copied = original.clone();
        original.reset_non_solid();
        drop(original);
        assert_eq!(
            copied.decode_member(&packed_second, second.len()).unwrap(),
            second
        );
    }
}

fn refuse_each_rar29_allocation(
    mut run: impl FnMut(&crate::codec::workspace::RefusingBudget) -> Result<()>,
) {
    use crate::codec::workspace::RefusingBudget;
    let baseline = RefusingBudget::new(usize::MAX);
    run(&baseline).unwrap();
    let attempts = baseline.attempts();
    assert!(attempts > 0);
    assert_eq!(baseline.used(), 0);
    for index in 0..attempts {
        let budget = RefusingBudget::new(index);
        assert!(
            matches!(run(&budget), Err(Error::Cancelled)),
            "allocation {index}"
        );
        assert_eq!(budget.used(), 0, "allocation {index}");
    }
}

#[test]
fn reader_rar29_refusals_release_input_huffman_history_results_and_checkpoints() {
    refuse_each_rar29_allocation(|budget| {
        let mut state = super::Reader29State::with_allowance(budget);
        let decoded = state.decode_member_owned(COMPRESSED_TEXT, 2400)?;
        assert_eq!(&decoded[..], expected_text());
        let checkpoint = state.try_clone()?;
        assert_eq!(checkpoint.output, state.output);
        assert_eq!(checkpoint.main.state.len(), state.main.state.len());
        let mut follower = COMPRESSED_TEXT;
        let mut out = super::Buffer::new(budget);
        state.decode_non_solid_member_from_reader(&mut follower, 2400, &mut out)?;
        assert_eq!(&out[..], expected_text());
        Ok(())
    });
}

#[test]
fn reader_rar29_refusals_release_vm_code_records_globals_execution_and_filters() {
    const COUNTER: &[u8] = &[
        0x0d, 0x05, 0xc0, 0x7c, 0x00, 0x0f, 0x01, 0x01, 0xaf, 0x80, 0x01, 0xe0, 0x20, 0x01, 0xf0,
        0x00, 0x3c, 0x03, 0x00, 0x1b, 0x80,
    ];
    let records = [
        OwnedVmFilterRecord {
            block_start: 0,
            block_size: 1,
            init_regs: Vec::new(),
            code: COUNTER,
            global_data: vec![b'A'],
        },
        OwnedVmFilterRecord {
            block_start: 1,
            block_size: 1,
            init_regs: Vec::new(),
            code: COUNTER,
            global_data: Vec::new(),
        },
    ];
    let refs = records.iter().collect::<Vec<_>>();
    let records = encoded_filter_records_at(&refs, 0, usize::MAX, &mut Vec::new()).unwrap();
    let packed = super::encode_member_inner(
        b"xx",
        &[],
        &records,
        EncodeOptions::default(),
        false,
        &mut [0; TABLE_COUNT],
        None,
    )
    .unwrap();
    refuse_each_rar29_allocation(|budget| {
        let mut state = super::Reader29State::with_allowance(budget);
        let decoded = state.decode_member_owned(&packed, 2)?;
        assert_eq!(&decoded[..], b"AB");
        let checkpoint = state.try_clone()?;
        assert_eq!(checkpoint.programs[0].globals, state.programs[0].globals);
        Ok(())
    });
}

#[test]
fn reader_rar29_refusals_release_standard_filter_scratch_and_output() {
    for (filter, regs) in [
        (StandardFilter::Delta, [2, 0, 0, 0, 0, 0, 0]),
        (StandardFilter::Rgb, [9, 0, 0, 0, 0, 0, 0]),
        (StandardFilter::Audio, [2, 0, 0, 0, 0, 0, 0]),
    ] {
        refuse_each_rar29_allocation(|budget| {
            let mut state = super::Reader29State::with_allowance(budget);
            state.output = super::Buffer::copied(&[0; 96], budget)?;
            state.programs.try_push(VmProgram {
                kind: VmProgramKind::Standard(filter),
                block_size: 96,
                exec_count: 0,
                globals: super::Buffer::new(budget),
            })?;
            state.filters.try_push(VmFilter {
                program: 0,
                start: 0,
                size: 96,
                regs,
                global_data: super::Buffer::new(budget),
            })?;
            let checkpoint = state.try_clone()?;
            assert_eq!(checkpoint.filters.len(), 1);
            let out = state.filtered_range_owned(0, 96, 0)?;
            assert_eq!(&out[..], &[0; 96]);
            assert!(state.filters.is_empty());
            Ok(())
        });
    }
}

#[test]
fn reader_rar29_returned_output_keeps_reservation_after_decoder_drop() {
    use crate::codec::workspace::Allowance;
    let ledger = Allowance::limited(128 * 1024);
    let mut reservation = ledger.reserve(120 * 1024).unwrap();
    reservation.start();
    let budget = reservation.allowance();
    let mut state = super::Reader29State::with_allowance(&budget);
    let out = state.decode_member_owned(COMPRESSED_TEXT, 2400).unwrap();
    drop(state);
    drop(budget);
    reservation.retire();
    assert!(ledger.used() >= out.capacity() as u64);
    assert_eq!(&out[..], expected_text());
    drop(out);
    assert_eq!(ledger.used(), 0);
}

type Unpack29 = super::Reader29State<super::Allowance>;
#[test]
fn ppmd_progress_preserves_bytes_and_interrupts_both_engines() {
    let input = b"PPMd cooperative cancellation payload\n".repeat(400);
    for escapes in [false, true] {
        let expected = if escapes {
            super::unpack29_encode_ppmd(&input, 1 << 20).unwrap()
        } else {
            super::unpack29_encode_ppmd_literals(&input).unwrap()
        };
        let actual =
            super::unpack29_encode_ppmd_with_progress(&input, escapes, None, 1 << 20, &mut |_| {
                true
            })
            .unwrap();
        assert_eq!(actual, expected);
        let mut stopped_at = 0;
        let result = super::unpack29_encode_ppmd_with_progress(
            &input,
            escapes,
            None,
            1 << 20,
            &mut |position| {
                stopped_at = position;
                position < 4096
            },
        );
        assert!(matches!(result, Err(super::Error::Cancelled)));
        assert!(stopped_at >= 4096 && stopped_at < input.len());
    }
}

#[test]
fn ppmd_progress_covers_entry_filtered_preprocessing_and_completion() {
    let input = b"PPMd cancellation boundary payload\n".repeat(400);
    for escapes in [false, true] {
        let mut calls = Vec::new();
        assert_eq!(
            super::unpack29_encode_ppmd_with_progress(
                &input,
                escapes,
                None,
                1 << 20,
                &mut |position| {
                    calls.push(position);
                    false
                },
            ),
            Err(super::Error::Cancelled)
        );
        assert_eq!(calls, [0]);

        let mut completions = 0;
        assert_eq!(
            super::unpack29_encode_ppmd_with_progress(
                &input,
                escapes,
                None,
                1 << 20,
                &mut |position| {
                    if position == input.len() {
                        completions += 1;
                        return false;
                    }
                    true
                },
            ),
            Err(super::Error::Cancelled)
        );
        assert_eq!(completions, 1);
    }

    let mut polls = 0;
    let filter = crate::FilterSpec::whole(crate::FilterKind::E8);
    assert_eq!(
        super::unpack29_encode_ppmd_with_progress(&input, true, Some(filter), 1 << 20, &mut |_| {
            polls += 1;
            polls < 3
        },),
        Err(super::Error::Cancelled)
    );
    // Entry, the bounded filter record, then the PPMd block itself.
    assert_eq!(polls, 3);

    let mut polls = 0;
    assert_eq!(
        super::unpack29_encode_ppmd_with_progress(
            &input,
            true,
            Some(crate::FilterSpec::whole(crate::FilterKind::E8)),
            1 << 20,
            &mut |_| {
                polls += 1;
                polls < 2
            },
        ),
        Err(super::Error::Cancelled)
    );
    assert_eq!(polls, 2);
}

#[test]
fn lz_progress_can_cancel_its_final_report() {
    let input = b"RAR29 final LZ progress boundary\n".repeat(400);
    let mut completions = 0;
    let result = super::unpack29_encode_literals_with_options_and_progress(
        &input,
        EncodeOptions::default(),
        &mut |position| {
            if position == input.len() {
                completions += 1;
                return false;
            }
            true
        },
    );

    assert_eq!(result, Err(super::Error::Cancelled));
    assert_eq!(completions, 1);
}

use super::{audio_decode_with_control, itanium_decode_with_control, rgb_decode_with_control};

#[test]
fn cancellation_interrupts_lz_and_ppmd_after_non_solid_reset() {
    let data = b"cancellable legacy symbols ".repeat(16384);
    for (ppmd, packed) in [
        (false, unpack29_encode_literals(&data).unwrap()),
        (true, unpack29_encode_ppmd_literals(&data).unwrap()),
    ] {
        let token = crate::ReadCancellation::new();
        let mut decoder = Unpack29::new();
        decoder.read_control = crate::read_control::ReadControl::new(Some(&token));
        // PPMd checks cancellation before allocating the initial model.
        decoder
            .read_control
            .cancel_after_checks(4 + usize::from(ppmd));
        assert_eq!(
            decoder
                .decode_non_solid_member(&packed, data.len())
                .unwrap_err(),
            Error::Cancelled
        );
        assert!(decoder.current_pos() > 0 && decoder.current_pos() < data.len());
    }
}

#[test]
fn cancellation_interrupts_standard_filter_passes() {
    for kind in 0..3 {
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        control.cancel_after_checks(2);
        let mut data = vec![0; 384 * 1024];
        let result = match kind {
            0 => itanium_decode_with_control(&mut data, 0, &control),
            1 => rgb_decode_with_control(&data, 96, 0, &control).map(|_| ()),
            _ => audio_decode_with_control(&data, 2, &control).map(|_| ()),
        };
        assert_eq!(result.unwrap_err(), Error::Cancelled);
    }
}

#[test]
fn cancellation_propagates_from_shared_standard_filter_decoders() {
    for (filter, regs) in [
        (StandardFilter::E8, [0; 7]),
        (StandardFilter::E8E9, [0; 7]),
        (StandardFilter::Delta, [1, 0, 0, 0, 0, 0, 0]),
    ] {
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        control.cancel_after_checks(2);
        let mut data = vec![0; 384 * 1024];
        assert_eq!(
            super::apply_standard_filter_with_control(filter, &mut data, 0, &regs, &control,),
            Err(Error::Cancelled)
        );
    }
}
use super::rarvm::{Instruction, Opcode, Operand, Program};
use std::ops::Range;

fn encode_tokens(input: &[u8], history: &[u8], options: EncodeOptions) -> Vec<EncodeToken> {
    encode_tokens_with_progress(input, history, options, None)
        .expect("encoding without cancellation cannot be cancelled")
}

fn should_lazy_emit_literal(
    input: &[u8],
    pos: usize,
    finder: &Rar29MatchFinder,
    options: EncodeOptions,
    state: &EncoderMatchState,
    current: MatchCandidate,
) -> bool {
    lazy_match_decision(input, pos, finder, options, state, current).0
}

use super::{
    apply_standard_filter, audio_encode, best_match, best_ppmd_match, canonical_codes,
    encode_level_tokens_against, encode_ppmd_hybrid, encode_table_level_tokens,
    encode_tokens_with_progress, encoded_filter_records_at, itanium_decode, itanium_encode,
    lazy_match_decision, level_code_lengths, split_large_filter, unpack29_decode,
    unpack29_encode_literals, unpack29_encode_ppmd, unpack29_encode_ppmd_literals,
    unpack29_encode_ppmd_with_filter, BitReader, BitWriter, ChainEngine, EncodeOptions,
    EncodeToken, EncoderMatchState, Error, Huffman, LevelToken, MatchCandidate,
    OwnedVmFilterRecord, PpmdEncodeToken, PpmdEncoder, Rar29MatchFinder, Result, StandardFilter,
    Unpack29Encoder, VmFilter, VmProgram, VmProgramKind, LENGTH_COUNT, LOW_OFFSET_COUNT,
    MAIN_COUNT, MAX_ENCODER_MATCH_LENGTH, MAX_ENCODER_MATCH_OFFSET, MAX_HISTORY,
    MAX_MATCH_CANDIDATES, MAX_VM_AUDIO_FILTER_BLOCK_SIZE, MAX_VM_DELTA_FILTER_BLOCK_SIZE,
    MAX_VM_FILTER_BLOCK_SIZE, OFFSET_COUNT, PPMD_DICTIONARY_MB, PPMD_ESC, PPMD_ORDER,
    RAR3_AUDIO_FILTER_BYTECODE, RAR3_DELTA_FILTER_BYTECODE, RAR3_ITANIUM_FILTER_BYTECODE,
    RAR3_RGB_FILTER_BYTECODE, STREAM_CHUNK, TABLE_COUNT,
};

/// A flat code charges the same for every symbol in play. The keep-tables
/// bit works by pushing the tokens onto one symbol, which buys nothing
/// unless the level code notices.
#[test]
fn the_level_code_spends_fewer_bits_on_the_common_symbol() {
    let mut tokens = vec![LevelToken::plain(0); 200];
    tokens.push(LevelToken::plain(7));
    tokens.push(LevelToken::plain(9));
    tokens.push(LevelToken::plain(11));
    let lengths = level_code_lengths(&tokens);
    assert!(
        lengths[0] < lengths[7],
        "the symbol used 200 times costs {} bits and the one used once costs {}",
        lengths[0],
        lengths[7]
    );
}

/// Symbols 0 to 15 are read as a delta against the table the reader holds,
/// so a table that has not changed is a run of zeroes. Runs of zero-length
/// codes and repeats stay as they are, since the reader takes those without
/// reference to what it holds.
#[test]
fn a_table_matching_the_previous_one_codes_as_deltas_of_zero() {
    let mut lengths = [0u8; TABLE_COUNT];
    for (position, slot) in lengths.iter_mut().enumerate().take(120) {
        *slot = (position % 13 + 1) as u8;
    }
    let against_itself = encode_level_tokens_against(&lengths, &lengths);
    assert!(
        against_itself
            .iter()
            .all(|token| token.symbol == 0 || token.symbol >= 16),
        "a table coded against itself should spend only zero deltas and runs"
    );

    let outright = encode_table_level_tokens(&lengths);
    assert!(
        outright.iter().any(|token| (1..16).contains(&token.symbol)),
        "the same table coded outright has to name its lengths"
    );
}

/// Members that share a shape and a vocabulary without repeating each
/// other. Every line carries a number that appears nowhere else, so there
/// is little for the chain to match and the PPMd model is what carries
/// between one member and the next.
fn related_text_member(seed: u64, lines: usize) -> Vec<u8> {
    const WORDS: [&str; 12] = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliet", "kilo", "lima",
    ];
    let mut state = seed | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::new();
    for line in 0..lines {
        for _ in 0..3 {
            out.extend_from_slice(WORDS[(next() % 12) as usize].as_bytes());
            out.push(b'.');
        }
        out.extend_from_slice(
            format!(
                "{} = {}\n",
                line + seed as usize * lines,
                next() % 1_000_000_007
            )
            .as_bytes(),
        );
    }
    out
}

/// WinRAR asks for a PPMd reset on 1 of the 68 PPMd blocks in a solid
/// archive of 70 small files and carries the model through the other 67.
/// Building a model per member instead is most of why that archive used to
/// be 18% smaller than ours.
#[test]
fn a_solid_chain_carries_one_ppmd_model_across_its_members() {
    // Members small enough that a model built for one alone never warms up,
    // which is the shape the win is really about: 70 manpages, not one book.
    let members: Vec<Vec<u8>> = (0..12).map(|i| related_text_member(i + 1, 40)).collect();
    let mut chain = Unpack29Encoder::with_options(EncodeOptions::default());
    let packed: Vec<Vec<u8>> = members
        .iter()
        .map(|member| {
            chain
                .encode_member_with_engine(member, ChainEngine::Smaller, &[], &mut |_| true)
                .unwrap()
        })
        .collect();

    // Which engine wins a given member is a size question and not the
    // point here. The point is that once one member has built a model, no
    // later member throws it away.
    let ppmd: Vec<&Vec<u8>> = packed.iter().filter(|block| block[0] & 0x80 != 0).collect();
    assert!(
        ppmd.len() > 2,
        "this chain was meant to go PPMd more than twice"
    );
    assert_eq!(
        ppmd[0][0] & 0x20,
        0x20,
        "the first PPMd member builds a model"
    );
    assert!(
        ppmd[1..].iter().all(|block| block[0] & 0x20 == 0),
        "no member after the first should throw the model away"
    );

    // The same member, coded by a chain that has read nothing.
    let alone = Unpack29Encoder::with_options(EncodeOptions::default())
        .encode_member_with_engine(
            members.last().unwrap(),
            ChainEngine::Smaller,
            &[],
            &mut |_| true,
        )
        .unwrap();
    let last = ppmd.last().unwrap();
    assert!(
        last.len() * 6 < alone.len() * 5,
        "a member coded against the chain's model cost {} bytes against {} on its own",
        last.len(),
        alone.len()
    );
}

/// Both engines carry state and only the winner's may advance, or the
/// reader is left holding something the writer never wrote.
#[test]
fn a_solid_chain_mixing_engines_round_trips() {
    let mut members: Vec<Vec<u8>> = Vec::new();
    for index in 0..3u64 {
        members.push(related_text_member(index + 1, 200));
        // Bytes PPMd loses on, so the chain has to switch engines and back.
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ index;
        let mut noise = Vec::new();
        while noise.len() < 20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            noise.extend_from_slice(&state.to_le_bytes());
        }
        members.push(noise);
    }

    let mut chain = Unpack29Encoder::with_options(EncodeOptions::default());
    let mut stream = Vec::new();
    let mut engines = Vec::new();
    for member in &members {
        let packed = chain
            .encode_member_with_engine(member, ChainEngine::Smaller, &[], &mut |_| true)
            .unwrap();
        engines.push(packed[0] & 0x80 != 0);
        stream.push(packed);
    }
    assert!(
        engines.contains(&true) && engines.contains(&false),
        "this chain was meant to use both engines, got {engines:?}"
    );

    let mut decoder = Unpack29::new();
    for (packed, member) in stream.iter().zip(&members) {
        assert_eq!(
            decoder.decode_member(packed, member.len()).unwrap(),
            *member
        );
    }
}

/// Calls to fixed addresses, which the x86 filter flattens into three
/// repeated values. See the writer's own copy of this for why the operand
/// is relative.
fn call_heavy_x86(seed: u32, calls: usize) -> Vec<u8> {
    const TARGETS: [u32; 3] = [0x1000, 0x2400, 0x3800];
    let mut data = Vec::with_capacity(calls * 16);
    let mut state = seed | 1;
    for index in 0..calls {
        let target = TARGETS[index % TARGETS.len()];
        let relative = target.wrapping_sub(data.len() as u32 + 5);
        data.push(0xe8);
        data.extend_from_slice(&relative.to_le_bytes());
        for _ in 0..11 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            data.push((state >> 24) as u8 | 0x40);
        }
    }
    data
}

/// Only the winning candidate may move the chain.
///
/// Every candidate codes the member for real, and each one leaves a
/// code-length table and a window behind it. A reader rebuilds both from
/// the bytes it actually reads, so committing a loser's leaves the next
/// member coded against a table and a history no decoder holds. That does
/// not show up as an error: the member after it decodes to plausible
/// rubbish, which is why this decodes the whole chain rather than checking
/// sizes.
#[test]
fn a_solid_chain_keeps_only_the_winning_candidates_state() {
    // One member per outcome. The x86 member takes the x86 filter, the
    // counters take the delta, and the text takes neither, so every
    // candidate both wins somewhere and loses somewhere. Text is the
    // member that matters: delta rewrites it into something with a very
    // different table, and that table is exactly what must not survive
    // losing.
    let x86 = call_heavy_x86(0x1234_5678, 400);
    let counters: Vec<u8> = (0..1600u32).flat_map(|n| (n * 7).to_le_bytes()).collect();
    let mut text = Vec::new();
    for index in 0..400u32 {
        text.extend_from_slice(format!("field_{index:04} = value {index:04}\n").as_bytes());
    }
    let members = [x86, counters, text];

    let candidates = vec![
        Vec::new(),
        vec![crate::FilterSpec::whole(crate::FilterKind::E8)],
        vec![crate::FilterSpec::whole(crate::FilterKind::Delta {
            channels: 4,
        })],
    ];
    let mut chain = Unpack29Encoder::with_options(EncodeOptions::default());
    let stream: Vec<Vec<u8>> = members
        .iter()
        .map(|member| {
            chain
                .encode_member_with_engine(member, ChainEngine::Lz, &candidates, &mut |_| true)
                .unwrap()
        })
        .collect();

    // A chain offered no candidates at all, to prove the filter was
    // chosen rather than never reached. Only the first member is
    // comparable member-for-member: once the chains disagree about what
    // they coded, they disagree about their histories too.
    let unfiltered_only = {
        let mut chain = Unpack29Encoder::with_options(EncodeOptions::default());
        members
            .iter()
            .map(|member| {
                chain
                    .encode_member_with_engine(member, ChainEngine::Lz, &[], &mut |_| true)
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    assert!(
        stream[0].len() < unfiltered_only[0].len(),
        "the x86 member should have taken the filter, got {} bytes against {}",
        stream[0].len(),
        unfiltered_only[0].len()
    );
    let chosen: usize = stream.iter().map(Vec::len).sum();
    let never: usize = unfiltered_only.iter().map(Vec::len).sum();
    assert!(
        chosen < never,
        "the chain that could choose wrote {chosen} bytes against {never}"
    );

    // Coding each member again for every candidate is only safe if the
    // losers leave nothing behind, so the chain is decoded a member at a
    // time and its table compared with the reader's after each one. The
    // bytes alone would not catch a wrong table: a member whose deltas are
    // applied to the wrong base still decodes, to rubbish, and only the
    // member after it notices.
    let mut decoder = Unpack29::new();
    let mut chain = Unpack29Encoder::with_options(EncodeOptions::default());
    for (index, member) in members.iter().enumerate() {
        let packed = chain
            .encode_member_with_engine(member, ChainEngine::Lz, &candidates, &mut |_| true)
            .unwrap();
        assert_eq!(packed, stream[index]);
        assert_eq!(
            decoder.decode_member(&packed, member.len()).unwrap(),
            *member
        );
        assert_eq!(
            chain.levels, decoder.levels,
            "member {index} left the writer holding a table the reader does not"
        );
        // The reader's window holds what the LZ layer coded, filters not
        // yet applied, which is the same thing the writer remembers.
        let common = chain.history.len().min(decoder.output.len());
        assert_eq!(
            chain.history[chain.history.len() - common..],
            decoder.output[decoder.output.len() - common..],
            "member {index} left the writer remembering bytes the reader never held"
        );
    }
}

/// The reader carries its table across the members of a solid chain, so
/// members that look alike stop paying to describe the same table again.
#[test]
fn a_solid_chain_stops_repaying_for_the_same_table() {
    let mut member = Vec::new();
    for index in 0..400u32 {
        member.extend_from_slice(format!("field_{index:04} = value {index:04}\n").as_bytes());
    }

    let mut chained = Unpack29Encoder::with_options(EncodeOptions::default());
    let first = chained.encode_member(&member).unwrap();
    let second = chained.encode_member(&member).unwrap();

    let mut alone = Unpack29Encoder::with_options(EncodeOptions::default());
    alone.encode_member(&member).unwrap();
    let restated = Unpack29Encoder::with_options(EncodeOptions::default())
        .encode_member(&member)
        .unwrap();

    assert_eq!(first.len(), restated.len());
    assert!(
        second.len() < restated.len(),
        "the second member of the chain cost {} bytes against {} on its own",
        second.len(),
        restated.len()
    );
}

/// The tokens the hybrid encoder emits for `input`, decided against the
/// same live model the production path prices against.
fn hybrid_tokens(input: &[u8], max_match_distance: usize) -> Vec<PpmdEncodeToken> {
    let mut encoder =
        PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, usize::from(PPMD_DICTIONARY_MB)).unwrap();
    let mut tokens = Vec::new();
    encode_ppmd_hybrid(input, max_match_distance, &mut encoder, |token| {
        tokens.push(token)
    })
    .unwrap();
    tokens
}

const COMPRESSED_TEXT: &[u8] = &[
    0x09, 0x10, 0x10, 0x93, 0xe4, 0xce, 0x7f, 0xa2, 0xba, 0x80, 0x46, 0x16, 0x82, 0x63, 0xe9, 0x9a,
    0x19, 0xe4, 0x10, 0xe0, 0x41, 0x3d, 0x16, 0xfc, 0x4d, 0xfa, 0x6f, 0xf2, 0x5c, 0xae, 0x32, 0x86,
    0xc9, 0x95, 0x9d, 0xf1, 0x04, 0xa4, 0xe8, 0x92, 0x8f, 0x12, 0xd7, 0xe7, 0xba, 0xcb, 0x26, 0xf1,
    0x97, 0xac, 0x7c, 0x5f, 0xfd, 0xa0, 0x00, 0x1f, 0x77, 0x50,
];

#[test]
fn decodes_rar29_lz_member() {
    assert_eq!(
        unpack29_decode(COMPRESSED_TEXT, 2400).unwrap(),
        expected_text()
    );
}

#[test]
fn rejects_oversubscribed_rar29_huffman_tables() {
    assert!(matches!(
        Huffman::from_lengths(&[1, 1, 1]),
        Err(Error::InvalidData("RAR 2.9 oversubscribed Huffman table"))
    ));
}

#[test]
fn codec_helpers_reject_out_of_contract_reads_and_history() {
    assert_eq!(
        BitReader::from_bytes(&[0; 4]).peek_bits(25),
        Err(Error::InvalidData("RAR 2.9 bit read is too wide"))
    );

    let mut decoder = Unpack29::new();
    decoder.base_offset = 10;
    decoder.output.extend_from_slice(b"retained").unwrap();
    assert_eq!(
        decoder.raw_range(9, 10),
        Err(Error::InvalidData(
            "RAR 2.9 retained history is unavailable"
        ))
    );
    assert_eq!(
        decoder.raw_range(12, 11),
        Err(Error::InvalidData(
            "RAR 2.9 retained history is unavailable"
        ))
    );
    assert_eq!(
        decoder.raw_range(10, 19),
        Err(Error::InvalidData(
            "RAR 2.9 retained history is unavailable"
        ))
    );
}

#[test]
fn canonical_assignment_matches_pinned_codes_and_generated_alphabets() {
    let pinned = canonical_codes(&[1, 2, 3, 3, 0]);
    assert_eq!(
        pinned
            .iter()
            .map(|code| code.map(|code| (code.code, code.len)))
            .collect::<Vec<_>>(),
        [Some((0, 1)), Some((2, 2)), Some((6, 3)), Some((7, 3)), None]
    );
    for size in [
        super::LEVEL_COUNT,
        MAIN_COUNT,
        OFFSET_COUNT,
        LOW_OFFSET_COUNT,
        LENGTH_COUNT,
    ] {
        let mut single = vec![0; size];
        single[size - 1] = 1;
        let mut deep = vec![0; size];
        let (mut a, mut b) = (1, 1);
        for frequency in deep.iter_mut().take(40) {
            *frequency = a;
            (a, b) = (b, a + b);
        }
        for frequencies in [
            vec![0; size],
            single,
            vec![1; size],
            (0..size).map(|i| usize::from(i % 3 == 0)).collect(),
            deep,
        ] {
            let lengths = crate::codec::huffman::lengths_for_frequencies(&frequencies, 15);
            assert!(lengths.iter().all(|&length| length <= 15));
            let codes = canonical_codes(&lengths);
            let table = Huffman::from_lengths(&lengths).unwrap();
            for (symbol, code) in codes.iter().enumerate() {
                assert_eq!(code.is_some(), frequencies[symbol] != 0);
                if let Some(code) = code {
                    let mut bits = BitWriter::default();
                    bits.write_bits(u32::from(code.code), code.len);
                    assert_eq!(
                        table
                            .decode(&mut BitReader::from_bytes(&bits.finish()))
                            .unwrap(),
                        symbol
                    );
                }
            }
        }
    }
}

#[test]
fn huffman_decoding_returns_the_index_from_its_constructor_alphabet() {
    for size in [20, MAIN_COUNT, OFFSET_COUNT, LOW_OFFSET_COUNT, LENGTH_COUNT] {
        let lengths = crate::codec::huffman::complete_lengths_for_frequencies(&vec![1; size], 15);
        let codes = canonical_codes(&lengths);
        let table = Huffman::from_lengths(&lengths).unwrap();

        for (expected, code) in codes.iter().enumerate() {
            let code = code.unwrap();
            let mut bits = BitWriter::default();
            bits.write_bits(u32::from(code.code), code.len);
            let mut bits = BitReader::from_bytes(&bits.finish());
            let decoded = table.decode(&mut bits).unwrap();
            assert_eq!(decoded, expected);
            assert!(decoded < size);
        }
    }
}

fn table_description(level_lengths: &[u8; 20], tokens: &[LevelToken]) -> Vec<u8> {
    let codes = canonical_codes(level_lengths);
    let mut bits = BitWriter::default();
    bits.write_bit(false);
    bits.write_bit(false);
    for &length in level_lengths {
        bits.write_bits(u32::from(length), 4);
    }
    for token in tokens {
        let code = codes[token.symbol].unwrap();
        bits.write_bits(u32::from(code.code), code.len);
        bits.write_bits(u32::from(token.extra_value), token.extra_bits);
    }
    bits.finish()
}

fn encoded_table_description(levels: &[u8; TABLE_COUNT]) -> Vec<u8> {
    let tokens = encode_table_level_tokens(levels);
    let level_lengths = level_code_lengths(&tokens);
    table_description(&level_lengths, &tokens)
}

#[test]
fn table_repeats_at_position_zero_are_rejected() {
    for symbol in [16, 17] {
        let mut level_lengths = [0; 20];
        level_lengths[0] = 1;
        level_lengths[symbol] = 1;
        let token = if symbol == 16 {
            LevelToken::repeat_previous_short(3)
        } else {
            LevelToken::repeat_previous_long(11)
        };
        let mut decoder = Unpack29::new();
        decoder.bits = BitReader::from_bytes(&table_description(&level_lengths, &[token]));

        let expected = if symbol == 16 {
            Error::InvalidData("RAR 2.9 table repeat at start")
        } else {
            Error::InvalidData("RAR 2.9 long table repeat at start")
        };
        assert_eq!(decoder.read_tables(), Err(expected));
    }
}

#[test]
fn table_run_past_the_destination_is_truncated_for_compatibility() {
    let mut level_lengths = [0; 20];
    level_lengths[0] = 1;
    level_lengths[19] = 1;
    let tokens = [
        LevelToken::zero_run_long(138),
        LevelToken::zero_run_long(138),
        LevelToken::zero_run_long(138),
    ];
    let mut decoder = Unpack29::new();
    decoder.bits = BitReader::from_bytes(&table_description(&level_lengths, &tokens));

    decoder.read_tables().unwrap();

    assert_eq!(decoder.levels, [0; TABLE_COUNT]);
}

#[test]
fn empty_level_and_main_tables_fail_when_used() {
    let mut empty_level_decoder = Unpack29::new();
    empty_level_decoder.bits = BitReader::from_bytes(&table_description(&[0; 20], &[]));
    assert_eq!(
        empty_level_decoder.read_tables(),
        Err(Error::InvalidData("RAR 2.9 empty Huffman table"))
    );

    let mut empty_main_decoder = Unpack29::new();
    empty_main_decoder.bits = BitReader::from_bytes(&encoded_table_description(&[0; TABLE_COUNT]));
    empty_main_decoder.read_tables().unwrap();
    assert_eq!(
        empty_main_decoder.main.decode(&mut empty_main_decoder.bits),
        Err(Error::InvalidData("RAR 2.9 empty Huffman table"))
    );
}

#[test]
fn incomplete_huffman_table_accepts_assigned_and_rejects_unassigned_prefixes() {
    let table = Huffman::from_lengths(&[2]).unwrap();
    let mut assigned = BitReader::from_bytes(&[0]);
    assert_eq!(table.decode(&mut assigned), Ok(0));

    let mut unassigned = BitReader::from_bytes(&[0x40, 0]);
    assert_eq!(
        table.decode(&mut unassigned),
        Err(Error::InvalidData("RAR 2.9 invalid Huffman code"))
    );
}

#[test]
fn truncated_table_headers_and_descriptions_need_more_input() {
    let mut truncated_header = BitWriter::default();
    truncated_header.write_bit(false);
    truncated_header.write_bit(false);
    truncated_header.write_bits(1, 4);
    let mut decoder = Unpack29::new();
    decoder.bits = BitReader::from_bytes(&truncated_header.finish());
    assert_eq!(decoder.read_tables(), Err(Error::NeedMoreInput));

    let mut level_lengths = [0; 20];
    level_lengths[0] = 1;
    level_lengths[19] = 1;
    let mut decoder = Unpack29::new();
    decoder.bits = BitReader::from_bytes(&table_description(
        &level_lengths,
        &[LevelToken::zero_run_long(138)],
    ));
    assert_eq!(decoder.read_tables(), Err(Error::NeedMoreInput));
}

#[test]
fn level_and_final_tables_reject_oversubscription() {
    let mut oversubscribed_level = BitWriter::default();
    oversubscribed_level.write_bit(false);
    oversubscribed_level.write_bit(false);
    for length in [1, 1, 1].into_iter().chain(std::iter::repeat_n(0, 17)) {
        oversubscribed_level.write_bits(length, 4);
    }
    let mut decoder = Unpack29::new();
    decoder.bits = BitReader::from_bytes(&oversubscribed_level.finish());
    assert_eq!(
        decoder.read_tables(),
        Err(Error::InvalidData("RAR 2.9 oversubscribed Huffman table"))
    );

    let mut level_lengths = [0; 20];
    level_lengths[1] = 1;
    level_lengths[19] = 1;
    let tokens = [
        LevelToken::plain(1),
        LevelToken::plain(1),
        LevelToken::plain(1),
        LevelToken::zero_run_long(138),
        LevelToken::zero_run_long(138),
        LevelToken::zero_run_long(125),
    ];
    let mut decoder = Unpack29::new();
    decoder.bits = BitReader::from_bytes(&table_description(&level_lengths, &tokens));
    assert_eq!(
        decoder.read_tables(),
        Err(Error::InvalidData("RAR 2.9 oversubscribed Huffman table"))
    );
}

#[test]
fn every_final_table_slice_rejects_oversubscription() {
    let slices = [
        MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT,
        MAIN_COUNT + OFFSET_COUNT..MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT,
        MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT..TABLE_COUNT,
    ];
    for slice in slices {
        let mut levels = [0; TABLE_COUNT];
        levels[b'A' as usize] = 1;
        levels[256] = 1;
        levels[slice.start] = 1;
        levels[slice.start + 1] = 1;
        levels[slice.start + 2] = 1;
        let mut decoder = Unpack29::new();
        decoder.bits = BitReader::from_bytes(&encoded_table_description(&levels));

        assert_eq!(
            decoder.read_tables(),
            Err(Error::InvalidData("RAR 2.9 oversubscribed Huffman table"))
        );
    }
}

#[test]
fn level_length_header_accepts_literal_fifteen_and_clips_zero_runs() {
    let mut bits = BitWriter::default();
    bits.write_bits(15, 4);
    bits.write_bits(0, 4);
    bits.write_bits(15, 4);
    bits.write_bits(15, 4);
    bits.write_bits(15, 4);
    bits.write_bits(1, 4);
    let mut bits = BitReader::from_bytes(&bits.finish());

    let lengths = Unpack29::read_level_lengths(&mut bits).unwrap();

    assert_eq!(lengths[0], 15);
    assert_eq!(lengths[1..], [0; 19]);
}

#[test]
fn unused_auxiliary_huffman_tables_may_be_empty() {
    let mut levels = [0; TABLE_COUNT];
    levels[b'A' as usize] = 1;
    levels[256] = 1;
    let mut decoder = Unpack29::new();
    decoder.bits = BitReader::from_bytes(&encoded_table_description(&levels));

    decoder.read_tables().unwrap();

    assert!(!decoder.main.state.is_empty());
    assert!(decoder.offsets.state.is_empty());
    assert!(decoder.low_offsets.state.is_empty());
    assert!(decoder.lengths.state.is_empty());
    assert_eq!(
        decoder.main.state.len()
            + decoder.offsets.state.len()
            + decoder.low_offsets.state.len()
            + decoder.lengths.state.len(),
        2
    );
    assert_eq!(
        MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT + LENGTH_COUNT,
        TABLE_COUNT
    );
}

#[test]
fn literal_encoder_round_trips_rar29_lz_blocks() {
    let input = b"literal-only RAR 2.9 baseline\nwith repeated text literal-only\n";
    let packed = unpack29_encode_literals(input).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn an_lz_member_ends_with_a_new_file_marker() {
    let input = b"RAR 2.9 terminator check, with repeated text to force a match: \
RAR 2.9 terminator check\n";
    let packed = unpack29_encode_literals(input).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn rejects_a_final_lz_marker_that_promises_a_missing_table() {
    let input = b"RAR 2.9 missing final table check\n".repeat(8);
    let mut packed = unpack29_encode_literals(&input).unwrap();
    let last_nonzero = packed.iter().rposition(|&byte| byte != 0).unwrap();
    let final_one = 1 << packed[last_nonzero].trailing_zeros();
    let preceding_bit = final_one << 1;
    assert_eq!(packed[last_nonzero] & preceding_bit, 0);
    packed[last_nonzero] ^= final_one | preceding_bit;

    assert!(matches!(
        unpack29_decode(&packed, input.len()),
        Err(Error::InvalidData("RAR 2.9 bitstream is truncated"))
    ));
}

/// A member split across LZ blocks marks every block but the last as having
/// another table after it.
#[test]
fn every_block_but_the_last_says_another_table_follows() {
    let input = b"rar29 multi block terminator check with repeated filler text\n".repeat(400);
    let packed = super::encode_member_with_options(
        &input,
        &[],
        EncodeOptions::new(96).with_block_size(4096),
    )
    .unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn rejects_a_new_file_marker_before_the_declared_member_size() {
    let first = b"first block ends too soon\n".repeat(64);
    let second = b"second block must not be decoded as the same member\n".repeat(64);
    let mut levels = [0; TABLE_COUNT];
    let mut packed = super::encode_member_inner(
        &first,
        &[],
        &[],
        EncodeOptions::new(96),
        false,
        &mut levels,
        None,
    )
    .unwrap();
    packed.extend_from_slice(
        &super::encode_member_inner(
            &second,
            &first,
            &[],
            EncodeOptions::new(96),
            false,
            &mut levels,
            None,
        )
        .unwrap(),
    );

    assert!(matches!(
        unpack29_decode(&packed, first.len() + second.len()),
        Err(Error::InvalidData(
            "RAR 2.9 member ended before its declared size"
        ))
    ));
}

#[test]
fn rejects_an_lz_literal_after_the_declared_member_size() {
    let input = b"literal-only RAR 2.9 member";
    let packed = unpack29_encode_literals(input).unwrap();

    assert!(matches!(
        unpack29_decode(&packed, input.len() - 1),
        Err(Error::InvalidData("RAR 2.9 LZ member has trailing data"))
    ));
}

#[test]
fn rejects_an_lz_match_crossing_the_declared_member_size() {
    let input = b"repeated tail ".repeat(256);
    let packed = Unpack29Encoder::new().encode_member(&input).unwrap();

    assert!(matches!(
        unpack29_decode(&packed, input.len() - 1),
        Err(Error::InvalidData(
            "RAR 2.9 member produces more output than its declared size"
        ))
    ));
}

#[test]
fn multi_block_lz_encoding_round_trips_large_repeated_documents() {
    let seed = b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><BODY><P>RAR29 repeated document body with enough structured text to \
exercise LZSS block table selection.</P></BODY></HTML>\n"
        .repeat(96);
    let input = seed.repeat(180);
    let single = super::encode_member_with_options(&input, &[], EncodeOptions::new(96)).unwrap();
    let blocked = super::encode_member_with_options(
        &input,
        &[],
        EncodeOptions::new(96).with_block_size(1024 * 1024),
    )
    .unwrap();

    assert_eq!(unpack29_decode(&single, input.len()).unwrap(), input);
    assert_eq!(unpack29_decode(&blocked, input.len()).unwrap(), input);
    assert!(blocked.len() < input.len());
}

#[test]
fn matched_member_streams_across_flush_and_history_boundaries() {
    struct RecordingSink {
        data: Vec<u8>,
        writes: Vec<usize>,
    }

    impl std::io::Write for RecordingSink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.writes.push(data.len());
            self.data.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // After the first literal, runs are encoded as 258-byte matches. The
    // match starting at 1,048,513 therefore crosses the first 1 MiB flush
    // boundary and has to be resumed by the next decode batch.
    let input = vec![b'Z'; MAX_HISTORY + STREAM_CHUNK + 513];
    let mut encoder = Unpack29Encoder::new();
    let packed = encoder.encode_member(&input).unwrap();
    assert_eq!(encoder.history.len(), MAX_HISTORY);

    let mut decoder = Unpack29::new();
    let mut sink = RecordingSink {
        data: Vec::new(),
        writes: Vec::new(),
    };
    decoder
        .decode_member_to(&packed, input.len(), &mut sink)
        .unwrap();

    assert_eq!(sink.data, input);
    assert_eq!(
        sink.writes,
        [STREAM_CHUNK; 5]
            .into_iter()
            .chain([513])
            .collect::<Vec<_>>()
    );
    assert_eq!(decoder.base_offset, input.len() - MAX_HISTORY);
    assert_eq!(decoder.output.len(), MAX_HISTORY);
    assert!(decoder.pending_match.is_none());
}

#[test]
fn solid_follower_can_match_the_oldest_retained_history() {
    let mut state = 0x6d2b_79f5u32;
    let marker: Vec<u8> = (0..MAX_ENCODER_MATCH_LENGTH)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let mut first = vec![b'X'; 17];
    first.extend_from_slice(&marker);
    first.resize(MAX_HISTORY + 17, b'Z');

    let options = EncodeOptions::default().with_max_match_distance(MAX_HISTORY);
    let mut encoder = Unpack29Encoder::with_options(options);
    let first_packed = encoder.encode_member(&first).unwrap();
    assert_eq!(encoder.history.len(), MAX_HISTORY);
    assert_eq!(&encoder.history[..marker.len()], marker);

    let follower_tokens = encode_tokens(&marker, &encoder.history, options);
    assert!(follower_tokens.iter().any(|token| matches!(
        token,
        EncodeToken::Match { offset, .. } if *offset == MAX_HISTORY
    )));
    let follower_packed = encoder.encode_member(&marker).unwrap();

    let mut decoder = Unpack29::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert_eq!(decoder.base_offset, 17);
    assert_eq!(
        decoder
            .decode_member(&follower_packed, marker.len())
            .unwrap(),
        marker
    );
    assert_eq!(decoder.output.len(), MAX_HISTORY);
    assert_eq!(decoder.base_offset, 17 + marker.len());
}

#[test]
fn block_encoder_trims_local_history_at_the_dictionary_boundary() {
    let history = vec![b'Z'; MAX_HISTORY];
    let options = EncodeOptions::new(0).with_block_size(1);
    let mut encoder = Unpack29Encoder::with_options(options);
    encoder.history.clone_from(&history);
    let packed = encoder.encode_member(b"AB").unwrap();

    let mut decoder = Unpack29::new();
    decoder.output = history.into();
    assert_eq!(decoder.decode_member(&packed, 2).unwrap(), b"AB");
    assert_eq!(encoder.history.len(), MAX_HISTORY);
    assert_eq!(&encoder.history[MAX_HISTORY - 2..], b"AB");
    assert_eq!(&decoder.output[MAX_HISTORY - 2..], b"AB");
}

#[test]
fn filter_spanning_a_flush_waits_for_complete_input_and_is_retired() {
    struct RecordingSink {
        data: Vec<u8>,
        writes: Vec<usize>,
    }

    impl std::io::Write for RecordingSink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.writes.push(data.len());
            self.data.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let filter_range = STREAM_CHUNK - 512..STREAM_CHUNK + 512;
    let mut input = vec![b'Z'; MAX_HISTORY + STREAM_CHUNK + 513];
    for position in (filter_range.start..filter_range.end - 4).step_by(16) {
        input[position] = 0xe8;
        input[position + 1..position + 5].copy_from_slice(&0x1234u32.to_le_bytes());
    }
    // Literal coding stops exactly at the streaming target. Match coding
    // can legally overshoot it and happen to complete this small filter in
    // the same decode pass, which would not exercise the wait.
    let packed = Unpack29Encoder::with_options(EncodeOptions::new(0))
        .encode_member_with_filter(
            &input,
            crate::FilterSpec::range(crate::FilterKind::E8, filter_range.clone()),
        )
        .unwrap();

    let mut decoder = Unpack29::new();
    let mut sink = RecordingSink {
        data: Vec::new(),
        writes: Vec::new(),
    };
    decoder
        .decode_member_to(&packed, input.len(), &mut sink)
        .unwrap();

    assert_eq!(sink.data, input);
    assert_eq!(sink.writes[0], filter_range.start);
    assert_eq!(sink.writes[1], STREAM_CHUNK + 512);
    assert!(decoder.filters.is_empty());

    let mut decoder = Unpack29::new();
    let mut prematurely_emitted = Vec::new();
    assert_eq!(
        decoder
            .decode_member_to(&packed, filter_range.end - 1, &mut prematurely_emitted)
            .unwrap_err(),
        Error::InvalidData("RAR 2.9 VM filter extends beyond output")
    );
    assert!(prematurely_emitted.is_empty());
}

#[test]
fn a_future_filter_stays_scheduled_until_its_range_is_published() {
    let mut decoder = Unpack29::new();
    decoder.output.resize(128, 0).unwrap();
    decoder
        .programs
        .push(VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: 8,
            exec_count: 0,
            globals: Vec::new().into(),
        })
        .unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: 64,
            size: 8,
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();

    assert_eq!(decoder.safe_flush_end(0, 32, 128).unwrap(), 32);
    assert_eq!(decoder.filtered_range(0, 32, 0).unwrap(), vec![0; 32]);
    assert_eq!(decoder.filters.len(), 1);

    assert_eq!(decoder.filtered_range(32, 72, 0).unwrap(), vec![0; 40]);
    assert!(decoder.filters.is_empty());
}

#[test]
fn history_trimming_discards_stale_filters_and_keeps_future_filters() {
    let mut decoder = Unpack29::new();
    decoder.output.resize(MAX_HISTORY + 64, 0).unwrap();
    decoder
        .programs
        .push(VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: 8,
            exec_count: 0,
            globals: Vec::new().into(),
        })
        .unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: 0,
            size: 8,
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: 128,
            size: 8,
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();

    decoder.trim_history(MAX_HISTORY + 64, MAX_HISTORY + 64);

    assert_eq!(decoder.base_offset, 64);
    assert_eq!(decoder.output.len(), MAX_HISTORY);
    assert_eq!(decoder.filters.len(), 1);
    assert_eq!(decoder.filters[0].start, 128);
    assert_eq!(decoder.filtered_range(64, 136, 0).unwrap(), vec![0; 72]);
    assert!(decoder.filters.is_empty());
}

#[test]
fn solid_ppmd_match_rejects_distance_beyond_retained_history() {
    let input = vec![b'Z'; MAX_HISTORY + 64];
    let packed = unpack29_encode_literals(&input).unwrap();
    let mut decoder = Unpack29::new();
    decoder
        .decode_non_solid_member_to(&packed, input.len(), &mut std::io::sink())
        .unwrap();
    assert_eq!(decoder.base_offset, 64);

    let mut encoder = PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, 1).unwrap();
    encoder.encode_match(MAX_HISTORY + 1, 32).unwrap();
    let (body, _) = encoder.finish_keeping_model().unwrap();
    let mut packed = vec![0x80 | 0x20 | (PPMD_ORDER as u8 - 1), 0];
    packed.extend_from_slice(&body);
    assert_eq!(
        decoder.decode_member_to(&packed, 32, &mut std::io::sink()),
        Err(Error::InvalidData("RAR 2.9 match distance is out of range"))
    );
}

#[test]
fn ppmd_member_rejects_a_vm_filter_range_beyond_native_output() {
    let record = super::encode_vm_filter_record_inner(
        super::VmFilterRecord {
            block_start: 0,
            block_size: u32::MAX as usize,
            init_regs: &[],
            code: super::RAR3_E8_FILTER_BYTECODE,
            global_data: &[],
        },
        0,
        true,
    )
    .unwrap();
    let mut encoder = PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, 1).unwrap();
    encoder.encode_literal(b'A').unwrap();
    encoder.encode_vm_filter_record(&record).unwrap();
    encoder.encode_literal(b'B').unwrap();
    let (body, _) = encoder.finish_keeping_model().unwrap();
    let mut packed = vec![0x80 | 0x20 | (PPMD_ORDER as u8 - 1), 0];
    packed.extend_from_slice(&body);
    let message = if cfg!(target_pointer_width = "32") {
        "RAR 2.9 VM filter size overflows"
    } else {
        "RAR 2.9 VM filter extends beyond output"
    };
    assert_eq!(
        unpack29_decode(&packed, 2),
        Err(Error::InvalidData(message))
    );
}

#[test]
fn stale_filter_ranges_do_not_change_later_published_bytes() {
    let mut decoder = Unpack29::new();
    decoder.output.resize(32, 0x5a).unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: usize::MAX,
            start: 0,
            size: 8,
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();

    assert_eq!(decoder.safe_flush_end(16, 32, 32).unwrap(), 32);
    assert_eq!(decoder.filtered_range(16, 32, 0).unwrap(), vec![0x5a; 16]);
}

#[test]
fn table_level_encoder_uses_rar29_run_symbols() {
    let mut lengths = [0u8; TABLE_COUNT];
    lengths[..4].fill(5);
    lengths[8..21].fill(0);

    let tokens = encode_table_level_tokens(&lengths);

    assert!(tokens.contains(&LevelToken::repeat_previous_short(3)));
    assert!(tokens.iter().any(|token| token.symbol == 19));
}

#[test]
fn lazy_lz_parser_defers_short_match_for_longer_next_match() {
    let input = b"abcdXbcdYYYYYYYYYYYYabcdYYYYYYYYYYYY";
    let greedy = encode_tokens(input, &[], EncodeOptions::new(MAX_MATCH_CANDIDATES));
    let lazy = encode_tokens(
        input,
        &[],
        EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
    );
    let packed = Unpack29Encoder::with_options(
        EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
    )
    .encode_member(input)
    .unwrap();

    assert!(greedy
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { length: 4, .. })));
    assert!(lazy
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { length, .. } if *length > 8)));
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn lazy_lz_parser_uses_match_cost_not_only_match_length() {
    let pos = 300_000usize;
    let mut input = vec![0u8; pos + 16];
    input[100..106].copy_from_slice(b"BCDEFG");
    input[106] = b'!';
    input[pos - 10..pos - 5].copy_from_slice(b"ABCD!");
    input[pos..pos + 7].copy_from_slice(b"ABCDEFG");
    let mut finder = Rar29MatchFinder::new(input.len());
    finder.insert(&input, 100);
    finder.insert(&input, pos - 10);

    let current = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::new(MAX_MATCH_CANDIDATES),
        &EncoderMatchState::default(),
    )
    .unwrap();
    let next = best_match(
        &input,
        pos + 1,
        input.len(),
        &finder,
        EncodeOptions::new(MAX_MATCH_CANDIDATES),
        &EncoderMatchState::default(),
    )
    .unwrap();

    assert_eq!(current.length, 4);
    assert_eq!(current.offset, 10);
    assert_eq!(next.length, 6);
    assert!(next.offset > 0x40000);
    assert!(!should_lazy_emit_literal(
        &input,
        pos,
        &finder,
        EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
        &EncoderMatchState::default(),
        current,
    ));
}

#[test]
fn lazy_lz_parser_uses_bounded_cost_lookahead() {
    let pos = 160;
    let mut input: Vec<u8> = (0..240u16)
        .map(|value| value.wrapping_mul(91) as u8)
        .collect();
    input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
    input[pos - 80..pos - 64].copy_from_slice(b"CDEFGHIJKLMNOPQR");
    input[pos..pos + 18].copy_from_slice(b"ABCDEFGHIJKLMNOPQR");

    let mut finder = Rar29MatchFinder::new(input.len());
    for candidate in 0..pos {
        finder.insert(&input, candidate);
    }
    let current = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &EncoderMatchState::default(),
    )
    .unwrap();

    assert_eq!((current.length, current.offset), (8, 30));
    assert!(!should_lazy_emit_literal(
        &input,
        pos,
        &finder,
        EncodeOptions::default()
            .with_lazy_matching(true)
            .with_lazy_lookahead(1),
        &EncoderMatchState::default(),
        current,
    ));
    assert!(should_lazy_emit_literal(
        &input,
        pos,
        &finder,
        EncodeOptions::default()
            .with_lazy_matching(true)
            .with_lazy_lookahead(2),
        &EncoderMatchState::default(),
        current,
    ));
}

#[test]
fn lazy_lz_parser_stops_lookahead_at_member_end() {
    let input = b"aaaaaa";
    let mut finder = Rar29MatchFinder::new(input.len());
    finder.insert(input, 0);
    let state = EncoderMatchState::default();
    let options = EncodeOptions::default()
        .with_lazy_matching(true)
        .with_lazy_lookahead(16);
    let current = best_match(input, 2, input.len(), &finder, options, &state).unwrap();

    assert_eq!((current.length, current.offset), (4, 2));
    assert!(!should_lazy_emit_literal(
        input, 2, &finder, options, &state, current,
    ));
}

#[test]
fn match_state_encodes_last_length_and_repeat_offset_symbols() {
    let mut state = EncoderMatchState::default();
    assert!(matches!(
        state.encode_match(12, 64).unwrap(),
        super::EncodedMatch::Fresh { .. }
    ));
    state.remember(12, 64);

    assert_eq!(
        state.encode_match(12, 64).unwrap(),
        super::EncodedMatch::LastLengthRepeat
    );
    assert!(matches!(
        state.encode_match(9, 64).unwrap(),
        super::EncodedMatch::RepeatOffset { index: 0, .. }
    ));

    assert!(matches!(
        state.encode_match(MAX_ENCODER_MATCH_LENGTH, 64).unwrap(),
        super::EncodedMatch::Fresh { .. }
    ));
    state.remember(MAX_ENCODER_MATCH_LENGTH, 64);
    assert_eq!(state.old_offsets, [64, 64, 0, 0]);
}

#[test]
fn match_field_encoders_reject_values_outside_the_wire_ranges() {
    assert_eq!(
        super::length_slot_for_match(2),
        Err(Error::InvalidData("RAR 2.9 match length is too short"))
    );
    assert_eq!(
        super::length_slot_for_match(MAX_ENCODER_MATCH_LENGTH + 1),
        Err(Error::InvalidData("RAR 2.9 match length is too long"))
    );
    assert_eq!(
        super::length_slot_for_repeat_match(1),
        Err(Error::InvalidData(
            "RAR 2.9 repeat match length is too short"
        ))
    );
    assert_eq!(
        super::length_slot_for_repeat_match(MAX_ENCODER_MATCH_LENGTH),
        Err(Error::InvalidData(
            "RAR 2.9 repeat match length is too long"
        ))
    );
    assert_eq!(
        super::offset_slot_for_match(0),
        Err(Error::InvalidData("RAR 2.9 match offset is zero"))
    );
    let last_slot = OFFSET_COUNT - 1;
    let largest_offset =
        super::OFFSET_BASES[last_slot] + (1usize << super::OFFSET_BITS[last_slot]) - 1 + 1;
    assert_eq!(
        super::offset_slot_for_match(largest_offset + 1),
        Err(Error::InvalidData("RAR 2.9 match offset is too large"))
    );
    let state = EncoderMatchState::default();
    for (length, offset, message) in [
        (0, 0x40000, "RAR 2.9 adjusted match length underflows"),
        (4, 0, "RAR 2.9 match offset is zero"),
        (5, largest_offset + 1, "RAR 2.9 match offset is too large"),
    ] {
        assert_eq!(
            state.encode_match(length, offset),
            Err(Error::InvalidData(message))
        );
        assert_eq!(
            super::estimated_match_cost(&state, length, offset),
            Err(Error::InvalidData(message))
        );
        let mut candidate = None;
        super::consider_match_candidate(&mut candidate, &state, length, offset);
        assert_eq!(candidate, None);
    }
}

#[test]
fn match_length_and_offset_slots_have_no_gaps() {
    for (bases, bits) in [
        (&super::LENGTH_BASES[..], &super::LENGTH_BITS[..]),
        (&super::OFFSET_BASES[..], &super::OFFSET_BITS[..]),
    ] {
        for index in 1..bases.len() {
            assert_eq!(bases[index], bases[index - 1] + (1usize << bits[index - 1]));
        }
    }
}

#[test]
fn match_search_respects_fresh_distance_length_adjustments() {
    for distance in [0x1fff, 0x2000, 0x3ffff, 0x40000] {
        let mut input = vec![0xff; distance + 4];
        input[..4].copy_from_slice(b"ABCD");
        input[distance..].copy_from_slice(b"ABCD");
        let mut finder = Rar29MatchFinder::new(input.len());
        finder.insert(&input, 0);
        let options = EncodeOptions::default();
        let fresh = best_match(
            &input,
            distance,
            input.len(),
            &finder,
            options,
            &EncoderMatchState::default(),
        );
        if distance == 0x40000 {
            assert_eq!(fresh, None);
        } else {
            let candidate = fresh.unwrap();
            assert_eq!((candidate.length, candidate.offset), (4, distance));
        }

        // A prior legal five-byte fresh match establishes this distance.
        // Repeat-distance lengths do not receive fresh-distance additions.
        let mut state = EncoderMatchState::default();
        assert!(matches!(
            state.encode_match(5, distance).unwrap(),
            super::EncodedMatch::Fresh { .. }
        ));
        state.remember(5, distance);
        let repeated = best_match(&input, distance, input.len(), &finder, options, &state).unwrap();
        assert_eq!((repeated.length, repeated.offset), (4, distance));
        assert!(matches!(
            state
                .encode_match(repeated.length, repeated.offset)
                .unwrap(),
            super::EncodedMatch::RepeatOffset { index: 0, .. }
        ));
    }
}

#[test]
fn match_search_ignores_a_remembered_offset_outside_its_window() {
    let input = b"abcdefghijklmnop";
    let finder = Rar29MatchFinder::new(input.len());
    let mut state = EncoderMatchState::default();
    state.old_offsets[0] = 9;
    let options = EncodeOptions::default().with_max_match_distance(8);

    assert_eq!(
        best_match(input, 8, input.len(), &finder, options, &state),
        None
    );
}

#[test]
fn cost_aware_match_selection_prefers_repeat_offset_token() {
    let pos = 600usize;
    let mut input: Vec<u8> = (0..pos + 16)
        .map(|index| (index as u8).wrapping_mul(37))
        .collect();
    input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
    input[pos - 512..pos - 503].copy_from_slice(b"ABCDEFGHI");
    input[pos..pos + 9].copy_from_slice(b"ABCDEFGHI");
    input[pos - 22] = 0x11;
    input[pos - 503] = 0x22;
    input[pos + 9] = 0x33;
    let mut finder = Rar29MatchFinder::new(input.len());
    finder.insert(&input, pos - 30);
    finder.insert(&input, pos - 512);

    let fresh = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &EncoderMatchState::default(),
    )
    .unwrap();
    let repeat = best_match(
        &input,
        pos,
        input.len(),
        &finder,
        EncodeOptions::default(),
        &EncoderMatchState {
            old_offsets: [30, 0, 0, 0],
            last_offset: 0,
            last_length: 0,
        },
    )
    .unwrap();

    assert_eq!((fresh.length, fresh.offset), (9, 512));
    assert_eq!((repeat.length, repeat.offset), (8, 30));
}

#[test]
fn match_finder_respects_configured_maximum_distance() {
    let phrase = b"rar29 bounded dictionary phrase";
    let mut input = Vec::new();
    input.extend_from_slice(phrase);
    input.extend(std::iter::repeat_n(0u8, 256 * 1024));
    input.extend_from_slice(phrase);

    let bounded = encode_tokens(
        &input,
        &[],
        EncodeOptions::new(MAX_MATCH_CANDIDATES).with_max_match_distance(128 * 1024),
    );
    let unbounded = encode_tokens(
        &input,
        &[],
        EncodeOptions::new(MAX_MATCH_CANDIDATES).with_max_match_distance(1024 * 1024),
    );

    assert!(!bounded
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { offset, .. } if *offset > 128 * 1024)));
    assert!(unbounded
        .iter()
        .any(|token| matches!(token, EncodeToken::Match { offset, .. } if *offset > 128 * 1024)));
}

#[test]
fn encode_options_cap_match_distance_at_the_rar29_window() {
    assert_eq!(
        EncodeOptions::default()
            .with_max_match_distance(usize::MAX)
            .max_match_distance,
        MAX_HISTORY
    );

    let options = EncodeOptions {
        max_match_distance: usize::MAX,
        ..EncodeOptions::default()
    };
    assert_eq!(
        Unpack29Encoder::with_options(options)
            .options
            .max_match_distance,
        MAX_HISTORY
    );
}

#[test]
fn public_encoders_handle_zero_match_distance_and_one_byte_blocks() {
    let input = b"small RAR29 blocks";
    let options = EncodeOptions::default()
        .with_max_match_distance(0)
        .with_block_size(1);
    let packed = Unpack29Encoder::with_options(options)
        .encode_member(input)
        .unwrap();
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);

    let packed = Unpack29Encoder::with_options(options)
        .encode_member_with_filter(input, crate::FilterSpec::whole(crate::FilterKind::E8))
        .unwrap();
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn solid_member_rejects_declared_output_beyond_native_range() {
    let mut decoder = super::Unpack29::new();
    decoder
        .decode_non_solid_member(COMPRESSED_TEXT, 2400)
        .unwrap();
    assert_eq!(
        decoder.decode_member(&[], usize::MAX),
        Err(Error::InvalidData("RAR 2.9 output size overflows"))
    );
}

#[test]
fn ppmd_match_finder_uses_the_declared_dictionary_past_one_megabyte() {
    let distance = MAX_ENCODER_MATCH_OFFSET + 4096;
    let phrase = b"RAR29 PPMd match beyond the old one-megabyte ceiling";
    let mut input = vec![0u8; distance + phrase.len()];
    input[..phrase.len()].copy_from_slice(phrase);
    input[distance..].copy_from_slice(phrase);
    let mut finder = Rar29MatchFinder::new(input.len());
    finder.insert(&input, 0);

    assert_eq!(
        best_ppmd_match(&input, distance, &finder, MAX_HISTORY),
        Some((phrase.len(), distance))
    );
}

#[test]
fn lz_encoder_uses_weighted_rar29_huffman_tables() {
    let mut input = Vec::new();
    for byte in 0u8..120 {
        input.push(b'A');
        input.push(byte);
    }
    let packed = Unpack29Encoder::new().encode_member(&input).unwrap();
    let mut decoder = Unpack29::new();
    decoder.bits.append(&packed);
    decoder.read_tables().unwrap();
    let main_lengths = &decoder.levels[..MAIN_COUNT];
    let nonzero_lengths = main_lengths
        .iter()
        .copied()
        .filter(|&length| length != 0)
        .collect::<std::collections::BTreeSet<_>>();

    assert!(nonzero_lengths.len() > 1);
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn copy_match_zero_fills_an_offset_that_reaches_past_the_stream() {
    let mut decoder = Unpack29::new();
    decoder.output.extend_from_slice(b"AB").unwrap();

    decoder.copy_match(4, 9, 6).unwrap();

    assert_eq!(&decoder.output[..], b"AB\0\0\0\0");
}

#[test]
fn an_undefined_repeat_distance_zero_fills_like_reference_readers() {
    let mut decoder = Unpack29::new();
    let mut main_lengths = vec![0; MAIN_COUNT];
    main_lengths[b'Z' as usize] = 1;
    main_lengths[259] = 1;
    decoder.main = Huffman::from_lengths(&main_lengths).unwrap();
    let mut repeat_lengths = vec![0; LENGTH_COUNT];
    repeat_lengths[2] = 1;
    decoder.lengths = Huffman::from_lengths(&repeat_lengths).unwrap();

    let main_codes = canonical_codes(&main_lengths);
    let repeat_codes = canonical_codes(&repeat_lengths);
    let mut bits = BitWriter::default();
    for code in [
        main_codes[b'Z' as usize].unwrap(),
        main_codes[259].unwrap(),
        repeat_codes[2].unwrap(),
    ] {
        bits.write_bits(u32::from(code.code), code.len);
    }
    decoder.bits = BitReader::from_bytes(&bits.finish());

    decoder.decode_lz(5).unwrap();

    assert_eq!(&decoder.output[..], b"Z\0\0\0\0");
}

#[test]
fn an_undefined_last_match_repeat_is_a_noop_like_reference_readers() {
    let mut decoder = Unpack29::new();
    let mut main_lengths = vec![0; MAIN_COUNT];
    main_lengths[258] = 1;
    main_lengths[b'X' as usize] = 2;
    main_lengths[b'Y' as usize] = 2;
    decoder.main = Huffman::from_lengths(&main_lengths).unwrap();

    let main_codes = canonical_codes(&main_lengths);
    let mut bits = BitWriter::default();
    for symbol in [b'X' as usize, 258, b'Y' as usize] {
        let code = main_codes[symbol].unwrap();
        bits.write_bits(u32::from(code.code), code.len);
    }
    decoder.bits = BitReader::from_bytes(&bits.finish());

    decoder.decode_lz(2).unwrap();

    assert_eq!(&decoder.output[..], b"XY");
    assert_eq!(decoder.last_length, 0);
}

#[test]
fn ppmd_literal_encoder_round_trips_rar29_ppmd_blocks() {
    let mut input = b"rar29 ppmd literal text payload alpha beta gamma\n".repeat(64);
    input.extend_from_slice(&[2, 2, 2, b'e', b's', b'c']);
    let packed = unpack29_encode_ppmd_literals(&input).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    assert_ne!(packed.first().copied(), Some(0));
}

#[test]
fn ppmd_end_block_command_reads_the_next_block() {
    let first = b"first PPMd block ";
    let second = b"and its continuation";
    let mut packed = vec![
        0x80 | 0x20 | ((PPMD_ORDER as u8) - 1),
        PPMD_DICTIONARY_MB - 1,
    ];
    let mut encoder =
        PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, usize::from(PPMD_DICTIONARY_MB)).unwrap();
    for &byte in first {
        encoder.encode_literal(byte).unwrap();
    }
    let (block, model) = encoder.finish_block_keeping_model().unwrap();
    packed.extend_from_slice(&block);

    packed.push(0x80 | ((PPMD_ORDER as u8) - 1));
    let mut encoder = PpmdEncoder::continuing(model, PPMD_ESC);
    for &byte in second {
        encoder.encode_literal(byte).unwrap();
    }
    let (block, _) = encoder.finish_keeping_model().unwrap();
    packed.extend_from_slice(&block);

    let expected = [first.as_slice(), second.as_slice()].concat();
    assert_eq!(unpack29_decode(&packed, expected.len()).unwrap(), expected);
}

#[test]
fn ppmd_member_can_end_in_an_empty_following_block() {
    let input = b"PPMd output ends before its final empty block";
    let mut packed = vec![
        0x80 | 0x20 | ((PPMD_ORDER as u8) - 1),
        PPMD_DICTIONARY_MB - 1,
    ];
    let mut encoder =
        PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, usize::from(PPMD_DICTIONARY_MB)).unwrap();
    for &byte in input {
        encoder.encode_literal(byte).unwrap();
    }
    let (block, model) = encoder.finish_block_keeping_model().unwrap();
    packed.extend_from_slice(&block);

    packed.push(0x80 | ((PPMD_ORDER as u8) - 1));
    let encoder = PpmdEncoder::continuing(model, PPMD_ESC);
    let (block, _) = encoder.finish_keeping_model().unwrap();
    packed.extend_from_slice(&block);

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn lz_member_can_end_in_an_empty_following_block() {
    let input = b"LZ output ends before its final empty block";
    let mut levels = [0; TABLE_COUNT];
    let options = EncodeOptions::default();
    let mut packed =
        super::encode_member_inner(input, &[], &[], options, true, &mut levels, None).unwrap();
    packed.extend_from_slice(
        &super::encode_member_inner(&[], input, &[], options, false, &mut levels, None).unwrap(),
    );

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn rejects_ppmd_eof_before_the_declared_member_size() {
    let input = b"PPMd member with an inflated declared size";
    let packed = unpack29_encode_ppmd_literals(input).unwrap();

    assert!(matches!(
        unpack29_decode(&packed, input.len() + 1),
        Err(Error::InvalidData(
            "RAR 2.9 member ended before its declared size"
        ))
    ));
}

#[test]
fn rejects_ppmd_output_after_the_declared_member_size() {
    let input = b"PPMd member with a shortened declared size";
    let packed = unpack29_encode_ppmd_literals(input).unwrap();

    assert!(matches!(
        unpack29_decode(&packed, input.len() - 1),
        Err(Error::InvalidData("RAR 2.9 PPMd member has trailing data"))
    ));
}

#[test]
fn rejects_a_truncated_ppmd_end_marker() {
    let input = b"PPMd member whose final range-coder byte is missing";
    let mut packed = unpack29_encode_ppmd_literals(input).unwrap();
    packed.pop();

    assert!(matches!(
        unpack29_decode(&packed, input.len()),
        Err(Error::InvalidData("RAR 2.9 bitstream is truncated"))
    ));
}

#[test]
fn ppmd_model_exhaustion_is_corruption() {
    assert!(matches!(
        super::require_ppmd_symbol(None),
        Err(Error::InvalidData("RAR 2.9 PPMd model is corrupt"))
    ));
}

#[test]
fn rejects_a_reserved_ppmd_command() {
    let input = b"PPMd stream followed by a reserved command";
    let mut packed = vec![
        0x80 | 0x20 | ((PPMD_ORDER as u8) - 1),
        PPMD_DICTIONARY_MB - 1,
    ];
    let mut encoder =
        PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, usize::from(PPMD_DICTIONARY_MB)).unwrap();
    for &byte in input {
        encoder.encode_literal(byte).unwrap();
    }
    packed.extend_from_slice(&encoder.finish_with_command(6).unwrap());

    assert!(matches!(
        unpack29_decode(&packed, input.len()),
        Err(Error::InvalidData("RAR 2.9 PPMd member has trailing data"))
    ));
    assert!(matches!(
        unpack29_decode(&packed, input.len() + 1),
        Err(Error::InvalidData("RAR 2.9 PPMd command is invalid"))
    ));
}

fn incomplete_ppmd_command(command: u8, parameters: &[u8]) -> Result<Vec<u8>> {
    let mut packed = vec![
        0x80 | 0x20 | ((PPMD_ORDER as u8) - 1),
        PPMD_DICTIONARY_MB - 1,
    ];
    let encoder = PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, usize::from(PPMD_DICTIONARY_MB)).unwrap();
    packed.extend_from_slice(
        &encoder
            .finish_with_command_prefix(command, parameters)
            .unwrap(),
    );
    unpack29_decode(&packed, 1)
}

#[test]
fn rejects_truncated_ppmd_match_parameters() {
    let cases = [
        (&[][..], "first offset byte"),
        (&[0][..], "second offset byte"),
        (&[0, 0][..], "third offset byte"),
        (&[0, 0, 0][..], "length byte"),
    ];
    for (parameters, missing) in cases {
        assert!(
            incomplete_ppmd_command(4, parameters).is_err(),
            "accepted a match missing its {missing}"
        );
    }
}

#[test]
fn rejects_a_truncated_ppmd_repeat_parameter() {
    assert!(matches!(
        incomplete_ppmd_command(5, &[]),
        Err(Error::InvalidData("RAR 2.9 bitstream is truncated"))
    ));
}

#[test]
fn rejects_truncated_ppmd_vm_parameters() {
    let cases = [
        (&[][..], "first record byte"),
        (&[6][..], "one-byte extended length"),
        (&[7][..], "two-byte length high byte"),
        (&[7, 0][..], "two-byte length low byte"),
        (&[0][..], "one-byte record body"),
        (&[6, 0][..], "extended-length record body"),
        (&[7, 0, 1][..], "two-byte-length record body"),
    ];
    for (parameters, missing) in cases {
        assert!(
            matches!(
                incomplete_ppmd_command(3, parameters),
                Err(Error::InvalidData("RAR 2.9 bitstream is truncated"))
            ),
            "accepted a VM command missing its {missing}"
        );
    }
}

#[test]
fn ppmd_encoder_advertises_period_compatible_model_for_external_decoders() {
    let packed =
        unpack29_encode_ppmd(b"rar29 ppmd dictionary header", MAX_ENCODER_MATCH_OFFSET).unwrap();

    assert_eq!(packed[0], 0xa7);
    assert_eq!(packed[1], 24);
}

#[test]
fn ppmd_encoder_emits_offset_one_repeat_escapes() {
    let input = b"seed "
        .iter()
        .copied()
        .chain(std::iter::repeat_n(b'Z', 512))
        .collect::<Vec<_>>();
    let tokens = hybrid_tokens(&input, MAX_ENCODER_MATCH_OFFSET);
    let packed = unpack29_encode_ppmd(&input, MAX_ENCODER_MATCH_OFFSET).unwrap();

    assert!(tokens
        .iter()
        .any(|token| matches!(token, PpmdEncodeToken::RepeatOffsetOne { length } if *length >= 4)));
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

/// PPMd's escape-4 matches copy out of the same window the LZ decoder
/// keeps, so a match reaching further back than the dictionary the file
/// header declares lands on whatever the decoder still happens to hold.
/// Nothing bounded them, so every RAR 3.0 and 4.0 PPMd member of a large
/// enough file failed its checksum in unrar; RAR 2.9 escaped only because
/// it declares a dictionary eight times larger.
#[test]
fn ppmd_matches_stay_inside_the_declared_dictionary() {
    let dictionary = 16 * 1024;
    // A distinctive block, repeated once inside the dictionary and once
    // well outside it. The near copy is the match the encoder should still
    // take, and it is what stops this passing merely because the bound
    // suppressed every match there was.
    let block: Vec<u8> = (0..2048u32)
        .map(|index| (index.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let mut input = block.clone();
    let filler = |input: &mut Vec<u8>, until: usize| {
        while input.len() < until {
            input.extend_from_slice(
                format!("filler line {:06} for the gap\n", input.len()).as_bytes(),
            );
        }
    };
    filler(&mut input, dictionary / 2);
    input.extend_from_slice(&block);
    filler(&mut input, 3 * dictionary);
    input.extend_from_slice(&block);
    let tokens = hybrid_tokens(&input, dictionary);

    let furthest = tokens
        .iter()
        .filter_map(|token| match token {
            PpmdEncodeToken::Match { offset, .. } => Some(*offset),
            _ => None,
        })
        .max()
        .expect("the payload has to produce matches for this to mean anything");
    assert!(
        furthest <= dictionary,
        "a match reached {furthest} bytes back, past the {dictionary} byte dictionary"
    );
}

#[test]
fn ppmd_encoder_emits_distance_match_escapes() {
    let phrase = b"repeated phrase for rar29 ppmd distance escape 4 ";
    let mut input = Vec::new();
    input.extend_from_slice(phrase);
    input.extend_from_slice(b"middle bytes make the repeat distance greater than one ");
    input.extend_from_slice(phrase);
    input.extend_from_slice(phrase);
    input.extend_from_slice(b"tail");
    let tokens = hybrid_tokens(&input, MAX_ENCODER_MATCH_OFFSET);
    let packed = unpack29_encode_ppmd(&input, MAX_ENCODER_MATCH_OFFSET).unwrap();

    assert!(tokens
            .iter()
            .any(|token| matches!(token, PpmdEncodeToken::Match { offset, length } if *offset > 1 && *length >= 32)));
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn ppmd_distance_match_lengths_stay_period_decoder_compatible() {
    let phrase = b"<html><body>RAR PPMd LZSS conversion phrase</body></html>\n";
    let mut input = Vec::new();
    for _ in 0..200 {
        input.extend_from_slice(phrase);
    }
    let tokens = hybrid_tokens(&input, MAX_ENCODER_MATCH_OFFSET);

    assert!(tokens.iter().any(
            |token| matches!(token, PpmdEncodeToken::Match { offset, length } if *offset > 1 && *length >= 32)
        ));
    assert!(!tokens
        .iter()
        .any(|token| matches!(token, PpmdEncodeToken::Match { length, .. } if *length > 255)));
}

#[test]
fn ppmd_encoder_emits_embedded_vm_filter_escape() {
    let input = b"\xe8\0\0\0\0rar29 ppmd embedded e8 filter payload\n".repeat(16);
    let packed = unpack29_encode_ppmd_with_filter(
        &input,
        crate::FilterSpec::whole(crate::FilterKind::E8),
        MAX_ENCODER_MATCH_OFFSET,
    )
    .unwrap();
    let plain_ppmd = unpack29_encode_ppmd(&input, MAX_ENCODER_MATCH_OFFSET).unwrap();
    let filtered_lz = Unpack29Encoder::new()
        .encode_member_with_filter(&input, crate::FilterSpec::whole(crate::FilterKind::E8))
        .unwrap();

    assert!(packed.len() != plain_ppmd.len() || packed.len() != filtered_lz.len());
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn same_block_filters_chain_in_wire_order() {
    let mut input = Vec::new();
    for index in 0..256u32 {
        input.push(0xe8);
        input.extend_from_slice(&index.wrapping_mul(97).to_le_bytes());
        input.extend_from_slice(b"chained-filter-payload");
    }
    let filters = [
        crate::FilterSpec::whole(crate::FilterKind::Delta { channels: 1 }),
        crate::FilterSpec::whole(crate::FilterKind::E8),
    ];
    let packed = Unpack29Encoder::new()
        .encode_member_with_filters(&input, &filters)
        .unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn archive_decoder_rejects_partially_overlapping_filters() {
    let input = vec![b'Z'; 96];
    for (second_start, second_size) in [(32, 64), (0, 63)] {
        let filters = [
            OwnedVmFilterRecord {
                block_start: 0,
                block_size: 64,
                init_regs: vec![(0, 1)],
                code: RAR3_DELTA_FILTER_BYTECODE,
                global_data: Vec::new(),
            },
            OwnedVmFilterRecord {
                block_start: second_start,
                block_size: second_size,
                init_regs: Vec::new(),
                code: super::RAR3_E8_FILTER_BYTECODE,
                global_data: Vec::new(),
            },
        ];
        let refs = filters.iter().collect::<Vec<_>>();
        let records = encoded_filter_records_at(&refs, 0, usize::MAX, &mut Vec::new()).unwrap();
        let packed = super::encode_member_inner(
            &input,
            &[],
            &records,
            EncodeOptions::default(),
            false,
            &mut [0; TABLE_COUNT],
            None,
        )
        .unwrap();

        assert_eq!(
            unpack29_decode(&packed, input.len()).unwrap_err(),
            Error::InvalidData("RAR 2.9 VM filters partially overlap")
        );
    }
}

#[test]
fn writer_rejects_partially_overlapping_filters() {
    let input = vec![b'Z'; 96];
    for second_range in [32..96, 0..63] {
        let filters = [
            crate::FilterSpec::range(crate::FilterKind::Delta { channels: 1 }, 0..64),
            crate::FilterSpec::range(crate::FilterKind::E8, second_range),
        ];

        assert_eq!(
            Unpack29Encoder::new()
                .encode_member_with_filters(&input, &filters)
                .unwrap_err(),
            Error::InvalidData("RAR 2.9 VM filters partially overlap")
        );
    }
}

#[test]
fn public_encoders_reject_invalid_filter_ranges() {
    let input = vec![b'Z'; 96];
    for (start, end) in [(32, 32), (64, 32), (0, 97)] {
        let range = start..end;
        let filter = crate::FilterSpec::range(crate::FilterKind::E8, range);

        assert_eq!(
            Unpack29Encoder::new()
                .encode_member_with_filter(&input, filter.clone())
                .unwrap_err(),
            Error::InvalidData("RAR 2.9 VM filter range is invalid")
        );
        assert_eq!(
            unpack29_encode_ppmd_with_filter(&input, filter, MAX_ENCODER_MATCH_OFFSET).unwrap_err(),
            Error::InvalidData("RAR 2.9 VM filter range is invalid")
        );
    }
}

#[test]
fn public_encoder_rejects_invalid_filter_parameters() {
    let input = vec![b'Z'; 96];
    let cases = [
        (
            crate::FilterKind::Delta { channels: 0 },
            Error::InvalidData("RAR 2.9 VM filter channel count is invalid"),
        ),
        (
            crate::FilterKind::Delta {
                channels: MAX_VM_DELTA_FILTER_BLOCK_SIZE + 1,
            },
            Error::InvalidData("RAR 2.9 VM filter channel count is invalid"),
        ),
        (
            crate::FilterKind::Audio { channels: 0 },
            Error::InvalidData("RAR 2.9 VM filter channel count is invalid"),
        ),
        (
            crate::FilterKind::Audio {
                channels: super::MAX_AUDIO_CHANNELS + 1,
            },
            Error::InvalidData("RAR 2.9 VM filter channel count is invalid"),
        ),
        (
            crate::FilterKind::Rgb { width: 0, pos_r: 0 },
            Error::InvalidData("RAR 2.9 RGB filter scanline width is invalid"),
        ),
        (
            crate::FilterKind::Rgb {
                width: MAX_VM_FILTER_BLOCK_SIZE + 1,
                pos_r: 0,
            },
            Error::InvalidData("RAR 2.9 RGB filter scanline width is invalid"),
        ),
        (
            crate::FilterKind::Rgb { width: 8, pos_r: 0 },
            Error::InvalidData("RAR 2.9 RGB filter parameters are invalid"),
        ),
        (
            crate::FilterKind::Rgb {
                width: 12,
                pos_r: 3,
            },
            Error::InvalidData("RAR 2.9 RGB filter parameters are invalid"),
        ),
    ];

    for (kind, expected) in cases {
        assert_eq!(
            Unpack29Encoder::new()
                .encode_member_with_filter(&input, crate::FilterSpec::whole(kind))
                .unwrap_err(),
            expected,
            "accepted {kind:?}"
        );
    }

    assert_eq!(
        Unpack29Encoder::new()
            .encode_member_with_filter(
                &input,
                crate::FilterSpec::whole(crate::FilterKind::Delta { channels: 33 }),
            )
            .unwrap_err(),
        Error::InvalidData("RAR 2.9 DELTA filter channel count is invalid")
    );
}

#[test]
fn filtered_entry_point_accepts_empty_input_without_filters() {
    let packed = Unpack29Encoder::new()
        .encode_member_with_filters(b"", &[])
        .unwrap();

    assert!(unpack29_decode(&packed, 0).unwrap().is_empty());
}

#[test]
fn filtered_progress_polls_preprocessing_and_keeps_cancelled_state_transactional() {
    let input = vec![b'Z'; MAX_VM_FILTER_BLOCK_SIZE * 2 + 16];
    let filter = crate::FilterSpec::whole(crate::FilterKind::E8);
    let mut at_entry = Unpack29Encoder::new();
    assert_eq!(
        at_entry.encode_member_with_filters_and_progress(
            &input,
            std::slice::from_ref(&filter),
            Some(&mut |_| false),
        ),
        Err(Error::Cancelled)
    );
    assert!(at_entry.history.is_empty());
    assert_eq!(at_entry.levels, [0; TABLE_COUNT]);

    let mut preprocessing = Unpack29Encoder::new();
    let mut polls = 0;
    let result = preprocessing.encode_member_with_filters_and_progress(
        &input,
        std::slice::from_ref(&filter),
        Some(&mut |_| {
            polls += 1;
            polls < 3
        }),
    );
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert_eq!(polls, 3);
    assert!(preprocessing.history.is_empty());
    assert_eq!(preprocessing.levels, [0; TABLE_COUNT]);

    let options = EncodeOptions::default().with_block_size(4096);
    let mut between_blocks = Unpack29Encoder::with_options(options);
    between_blocks.levels[0] = 7;
    let original_levels = between_blocks.levels;
    let result = between_blocks.encode_member_with_filters_and_progress(
        &input[..8192],
        &[filter],
        Some(&mut |position| position <= 4096),
    );
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert!(between_blocks.history.is_empty());
    assert_eq!(between_blocks.levels, original_levels);
}

#[test]
fn solid_candidate_transitions_are_cancellable_without_committing_state() {
    let seed = b"solid seed history and table state\n".repeat(200);
    let input = b"candidate transition payload with repeated text\n".repeat(300);
    let mut encoder = Unpack29Encoder::new();
    encoder.encode_member(&seed).unwrap();
    let original_history = encoder.history.clone();
    let original_levels = encoder.levels;
    let filter = crate::FilterSpec::whole(crate::FilterKind::E8);
    let candidates = [Vec::new(), vec![filter]];

    let mut completions = 0;
    let result =
        encoder.encode_member_with_engine(&input, ChainEngine::Lz, &candidates, &mut |position| {
            if position == input.len() {
                completions += 1;
                return completions < 3;
            }
            true
        });
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert_eq!(completions, 3);
    assert_eq!(encoder.history, original_history);
    assert_eq!(encoder.levels, original_levels);
    assert!(encoder.ppmd.is_none());

    // Candidate encodes can themselves poll at the completed member byte
    // count. Measure a successful two-candidate pass, then refuse its last
    // poll: that last poll is the explicit boundary after the candidate
    // has been evaluated and before its state can be committed.
    let candidates = [Vec::new(), Vec::new()];
    let mut successful_polls = 0;
    let mut probe = encoder.clone();
    probe
        .encode_member_with_engine(&input, ChainEngine::Lz, &candidates, &mut |position| {
            if position == input.len() {
                successful_polls += 1;
            }
            true
        })
        .unwrap();
    let mut polls = 0;
    let result =
        encoder.encode_member_with_engine(&input, ChainEngine::Lz, &candidates, &mut |position| {
            if position == input.len() {
                polls += 1;
                return polls < successful_polls;
            }
            true
        });
    assert_eq!(result, Err(Error::Cancelled));
    assert_eq!(polls, successful_polls);
    assert_eq!(encoder.history, original_history);
    assert_eq!(encoder.levels, original_levels);

    completions = 0;
    let result =
        encoder.encode_member_with_engine(&input, ChainEngine::Smaller, &[], &mut |position| {
            if position == input.len() {
                completions += 1;
                return completions < 3;
            }
            true
        });
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert_eq!(completions, 3);
    assert_eq!(encoder.history, original_history);
    assert_eq!(encoder.levels, original_levels);
    assert!(encoder.ppmd.is_none());
}

#[test]
fn plain_solid_candidate_propagates_encoder_cancellation() {
    let mut encoder = Unpack29Encoder::new();
    let input = b"plain candidate cancellation";
    let result = encoder.encode_member_with_engine(input, ChainEngine::Lz, &[], &mut |_| false);

    assert_eq!(result, Err(Error::Cancelled));
    assert!(encoder.history.is_empty());
    assert_eq!(encoder.levels, [0; TABLE_COUNT]);
}

fn encode_with_filter(input: &[u8], kind: crate::FilterKind) -> Result<Vec<u8>> {
    Unpack29Encoder::new().encode_member_with_filter(input, crate::FilterSpec::whole(kind))
}

fn encode_with_filter_range(
    input: &[u8],
    kind: crate::FilterKind,
    range: Range<usize>,
) -> Result<Vec<u8>> {
    Unpack29Encoder::new().encode_member_with_filter(input, crate::FilterSpec::range(kind, range))
}

fn encode_with_filter_ranges(
    input: &[u8],
    kind: crate::FilterKind,
    ranges: Vec<Range<usize>>,
) -> Result<Vec<u8>> {
    let filters: Vec<_> = ranges
        .into_iter()
        .map(|range| crate::FilterSpec::range(kind, range))
        .collect();
    Unpack29Encoder::new().encode_member_with_filters(input, &filters)
}

fn decode_with_raw_standard_filter(
    data: &[u8],
    code: &'static [u8],
    init_regs: Vec<(usize, u32)>,
) -> Result<Vec<u8>> {
    let filter = OwnedVmFilterRecord {
        block_start: 0,
        block_size: data.len(),
        init_regs,
        code,
        global_data: Vec::new(),
    };
    let mut levels = [0; TABLE_COUNT];
    let packed = super::encode_filtered_member_blocks(
        data,
        &[],
        &[filter],
        EncodeOptions::default(),
        &mut levels,
        None,
    )?;
    unpack29_decode(&packed, data.len())
}

#[test]
fn encoder_emits_rar29_offset_one_matches_for_repeated_bytes() {
    let input = b"Z".repeat(1024);
    let packed = unpack29_encode_literals(&input).unwrap();

    assert!(packed.len() < input.len() / 4);
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar29_dictionary_matches_for_repeated_sequences() {
    let input = b"abc123xyz-".repeat(128);
    let packed = unpack29_encode_literals(&input).unwrap();

    assert!(packed.len() < input.len() / 2);
    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_finds_rar29_matches_beyond_near_offsets() {
    let phrase = b"long-distance repeated phrase for rar29 low-offset coding.";
    let mut input = Vec::new();
    input.extend_from_slice(phrase);
    input.extend(std::iter::repeat_n(0, 300 * 1024));
    input.extend_from_slice(phrase);
    input.extend_from_slice(phrase);
    let tokens = encode_tokens(&input, &[], EncodeOptions::default());
    let packed = unpack29_encode_literals(&input).unwrap();

    assert!(tokens.iter().any(|token| matches!(
        token,
        EncodeToken::Match { offset, .. } if *offset > 0x40000
    )));
    assert!(packed.len() < input.len());
    let decoded = unpack29_decode(&packed, input.len()).unwrap();
    assert!(
        decoded == input,
        "RAR 2.9 long-distance match round-trip failed"
    );
}

#[test]
fn encoder_emits_rar29_e8_vm_filter_record() {
    let input = b"\xe8\0\0\0\0rar29 e8 filter writer payload\n".repeat(8);
    let packed = encode_with_filter(&input, crate::FilterKind::E8).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert!(
        decoded == input,
        "RAR 2.9 multi-filter E8 round-trip failed"
    );
}

#[test]
fn encoder_emits_rar29_e8e9_vm_filter_record() {
    let input = b"\xe9\0\0\0\0rar29 e8e9 filter writer payload\n".repeat(8);
    let packed = encode_with_filter(&input, crate::FilterKind::E8E9).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_e8_vm_filter_record() {
    let mut input = b"prefix data that should not be x86 filtered ".to_vec();
    let start = input.len();
    input.extend_from_slice(b"\xe8\0\0\0\0segmented e8 filtered payload\n");
    let end = input.len();
    input.extend_from_slice(b" suffix data that should also remain raw");
    let packed = encode_with_filter_range(&input, crate::FilterKind::E8, start..end).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_multiple_e8_vm_filter_records() {
    let mut input = vec![0x41u8; 80_000];
    for cluster_start in [8_000, 60_000] {
        for index in 0..8 {
            let pos = cluster_start + index * 64;
            input[pos] = 0xe8;
            input[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
        }
    }

    let packed = encode_with_filter_ranges(
        &input,
        crate::FilterKind::E8,
        vec![8_000..8_512, 60_000..60_512],
    )
    .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_e8e9_vm_filter_record() {
    let mut input = b"prefix data that should not be x86 filtered ".to_vec();
    let start = input.len();
    input.extend_from_slice(b"\xe9\0\0\0\0segmented e8e9 filtered payload\n");
    let end = input.len();
    input.extend_from_slice(b" suffix data that should also remain raw");
    let packed = encode_with_filter_range(&input, crate::FilterKind::E8E9, start..end).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_delta_vm_filter_record() {
    let input: Vec<u8> = (0..192).map(|index| (index * 13 + 7) as u8).collect();
    let packed = encode_with_filter(&input, crate::FilterKind::Delta { channels: 3 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_delta_vm_filter_record() {
    let mut input = b"prefix bytes before delta segment ".to_vec();
    let start = input.len();
    input.extend((0..192).map(|index| (index * 13 + 7) as u8));
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after delta segment");
    let packed =
        encode_with_filter_range(&input, crate::FilterKind::Delta { channels: 3 }, start..end)
            .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_itanium_vm_filter_record() {
    let mut input = vec![0u8; 48];
    input[16] = 22;
    input[21] = 20;
    input.extend_from_slice(b"rar29 itanium filter writer payload\n");
    let packed = encode_with_filter(&input, crate::FilterKind::Itanium).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_segmented_itanium_vm_filter_record() {
    let mut input = b"prefix bytes before itanium segment ".to_vec();
    let start = input.len();
    input.extend_from_slice(&[0; 48]);
    input[start + 16] = 22;
    input[start + 21] = 20;
    input.extend_from_slice(b"rar29 segmented itanium filter writer payload\n");
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after itanium segment");
    let packed = encode_with_filter_range(&input, crate::FilterKind::Itanium, start..end).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_rgb_vm_filter_record() {
    let width = 12;
    let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
    let packed = encode_with_filter(&input, crate::FilterKind::Rgb { width, pos_r: 0 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_rar29_rgb_filter_with_nonzero_red_position() {
    let width = 12;
    let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
    let packed = encode_with_filter(&input, crate::FilterKind::Rgb { width, pos_r: 2 }).unwrap();

    assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
}

#[test]
fn encoder_emits_rar29_segmented_rgb_vm_filter_record() {
    let width = 12;
    let mut input = b"prefix bytes before rgb segment ".to_vec();
    let start = input.len();
    input.extend((0..96).map(|index| (index * 29 + 11) as u8));
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after rgb segment");
    let packed = encode_with_filter_range(
        &input,
        crate::FilterKind::Rgb { width, pos_r: 0 },
        start..end,
    )
    .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_rejects_rar29_rgb_filter_with_unaligned_scanline_width() {
    let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
    assert!(encode_with_filter(&input, crate::FilterKind::Rgb { width: 8, pos_r: 0 }).is_err());
}

#[test]
fn encoder_rejects_rgb_ranges_shorter_than_a_pixel_or_scanline() {
    for (input, width) in [(b"ab".as_slice(), 3), (b"abc".as_slice(), 6)] {
        assert_eq!(
            Unpack29Encoder::new().encode_member_with_filter(
                input,
                crate::FilterSpec::whole(crate::FilterKind::Rgb { width, pos_r: 0 }),
            ),
            Err(Error::InvalidData(
                "RAR 2.9 RGB filter parameters are invalid"
            )),
        );
    }
}

#[test]
fn rgb_helpers_reject_invalid_parameters_even_without_caller_prechecks() {
    let expected = Err(Error::InvalidData(
        "RAR 2.9 RGB filter parameters are invalid",
    ));
    assert_eq!(super::rgb_encode(&[0; 6], 0, 0), expected);
    assert_eq!(
        super::rgb_decode_with_control(&[0; 6], 3, 3, &crate::read_control::ReadControl::default(),),
        expected,
    );
}

#[test]
fn encoder_emits_rar29_audio_vm_filter_record() {
    let input: Vec<u8> = (0..160)
        .map(|index| (index * 7 + index / 3) as u8)
        .collect();
    let packed = encode_with_filter(&input, crate::FilterKind::Audio { channels: 2 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn rar29_audio_channel_bounds_match_period_decoders() {
    let input: Vec<u8> = (0..256).map(|index| (index * 37 + 11) as u8).collect();
    for channels in [1, 32, 33, 128] {
        let encoded = audio_encode(&input, channels).unwrap();
        let mut decoded = encoded;
        let mut regs = [0; 7];
        regs[0] = channels as u32;
        apply_standard_filter(StandardFilter::Audio, &mut decoded, 0, &regs).unwrap();
        assert_eq!(decoded, input, "failed with {channels} channels");
    }

    for channels in [0, 129] {
        assert!(matches!(
            audio_encode(&input, channels),
            Err(Error::InvalidData(
                "RAR 2.9 AUDIO filter channel count is invalid"
            ))
        ));
        let mut data = input.clone();
        let mut regs = [0; 7];
        regs[0] = channels as u32;
        assert!(matches!(
            apply_standard_filter(StandardFilter::Audio, &mut data, 0, &regs),
            Err(Error::InvalidData(
                "RAR 2.9 AUDIO filter channel count is invalid"
            ))
        ));
    }
}

#[test]
fn audio_filter_bytecode_matches_builtin_transform() {
    let channels = 2;
    let input: Vec<u8> = (0..MAX_VM_AUDIO_FILTER_BLOCK_SIZE)
        .map(|index| (index * 7 + index / channels + index / 257) as u8)
        .collect();
    let encoded = audio_encode(&input, channels).unwrap();
    let program = Program::parse(RAR3_AUDIO_FILTER_BYTECODE).unwrap();
    let result = program
        .execute(super::rarvm::Invocation {
            input: &encoded,
            regs: [channels as u32, 0, 0, 0, 0, 0, 0],
            global_data: &[],
            file_offset: 0,
            exec_count: 0,
        })
        .unwrap();

    assert_eq!(result.output, input);
}

#[test]
fn rgb_filter_matches_the_captured_winrar_bytecode() {
    let program = Program::parse(RAR3_RGB_FILTER_BYTECODE).unwrap();
    for (width, pos_r) in [(3, 0), (12, 2), (63, 1)] {
        let input: Vec<u8> = (0..189)
            .map(|index| (index * 43 + index / 7 + 19) as u8)
            .collect();
        let encoded = super::rgb_encode(&input, width, pos_r).unwrap();
        let result = program
            .execute(super::rarvm::Invocation {
                input: &encoded,
                regs: [width as u32 + 3, pos_r as u32, 0, 0, 0, 0, 0],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            })
            .unwrap();

        assert_eq!(result.output, input, "width {width}, red position {pos_r}");
    }
}

#[test]
fn itanium_filter_matches_the_captured_winrar_bytecode() {
    let mut input = vec![0u8; 96];
    for bundle in 0..5 {
        input[bundle * 16] = 0x16;
        input[bundle * 16 + 5] = 0x50;
        input[bundle * 16 + 8] = (bundle * 29 + 7) as u8;
    }
    let file_offset = 0x12340;
    let mut encoded = input.clone();
    itanium_encode(&mut encoded, file_offset);
    let program = Program::parse(RAR3_ITANIUM_FILTER_BYTECODE).unwrap();
    let result = program
        .execute(super::rarvm::Invocation {
            input: &encoded,
            regs: [0; 7],
            global_data: &[],
            file_offset: u64::from(file_offset),
            exec_count: 0,
        })
        .unwrap();

    assert_eq!(result.output, input);
}

#[test]
fn audio_predictor_extremes_match_the_captured_winrar_bytecode() {
    let program = Program::parse(RAR3_AUDIO_FILTER_BYTECODE).unwrap();
    // These xorshift streams independently drive all six coefficient
    // choices and both sides of every +/-16 saturation guard.
    for seed in [2u32, 3, 4, 17] {
        let mut state = seed;
        let input: Vec<u8> = (0..16_384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let encoded = audio_encode(&input, 1).unwrap();
        assert_eq!(
            audio_decode_with_control(&encoded, 1, &crate::read_control::ReadControl::default(),)
                .unwrap(),
            input,
            "native predictor diverged for seed {seed}"
        );
        let result = program
            .execute(super::rarvm::Invocation {
                input: &encoded,
                regs: [1, 0, 0, 0, 0, 0, 0],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            })
            .unwrap();

        assert_eq!(result.output, input, "predictor diverged for seed {seed}");
    }
}

#[test]
fn large_audio_filters_are_split_into_rarvm_safe_blocks() {
    let filters = split_large_filter(
        MAX_VM_FILTER_BLOCK_SIZE * 2 + 123,
        crate::FilterSpec::whole(crate::FilterKind::Audio { channels: 4 }),
    )
    .unwrap();

    assert_eq!(filters.len(), 3);
    assert_eq!(filters[0].range, Some(0..MAX_VM_AUDIO_FILTER_BLOCK_SIZE));
    assert_eq!(
        filters[1].range,
        Some(MAX_VM_AUDIO_FILTER_BLOCK_SIZE..MAX_VM_AUDIO_FILTER_BLOCK_SIZE * 2)
    );
    assert_eq!(
        filters[2].range,
        Some(MAX_VM_AUDIO_FILTER_BLOCK_SIZE * 2..MAX_VM_FILTER_BLOCK_SIZE * 2 + 123)
    );
}

#[test]
fn large_delta_filters_are_split_into_rarvm_safe_blocks() {
    let filters = split_large_filter(
        MAX_VM_FILTER_BLOCK_SIZE * 2 + 123,
        crate::FilterSpec::whole(crate::FilterKind::Delta { channels: 4 }),
    )
    .unwrap();

    assert_eq!(filters.len(), 3);
    assert_eq!(filters[0].range, Some(0..MAX_VM_DELTA_FILTER_BLOCK_SIZE));
    assert_eq!(
        filters[1].range,
        Some(MAX_VM_DELTA_FILTER_BLOCK_SIZE..MAX_VM_DELTA_FILTER_BLOCK_SIZE * 2)
    );
    assert_eq!(
        filters[2].range,
        Some(MAX_VM_DELTA_FILTER_BLOCK_SIZE * 2..MAX_VM_FILTER_BLOCK_SIZE * 2 + 123)
    );
}

#[test]
fn segmented_audio_filters_redeclare_program_state() {
    let filters = [
        OwnedVmFilterRecord {
            block_start: 0,
            block_size: MAX_VM_AUDIO_FILTER_BLOCK_SIZE,
            init_regs: vec![(0, 4)],
            code: RAR3_AUDIO_FILTER_BYTECODE,
            global_data: Vec::new(),
        },
        OwnedVmFilterRecord {
            block_start: MAX_VM_AUDIO_FILTER_BLOCK_SIZE,
            block_size: 4096,
            init_regs: vec![(0, 4)],
            code: RAR3_AUDIO_FILTER_BYTECODE,
            global_data: Vec::new(),
        },
    ];
    let refs: Vec<&OwnedVmFilterRecord> = filters.iter().collect();
    let records = encoded_filter_records_at(&refs, 0, usize::MAX, &mut Vec::new()).unwrap();

    assert_vm_filter_declares_program(&records[0], 0);
    assert_vm_filter_declares_program(&records[1], 2);
}

#[test]
fn encoder_emits_rar29_segmented_audio_vm_filter_record() {
    let mut input = b"prefix bytes before audio segment ".to_vec();
    let start = input.len();
    input.extend((0..160).map(|index| (index * 7 + index / 3) as u8));
    let end = input.len();
    input.extend_from_slice(b" suffix bytes after audio segment");
    let packed =
        encode_with_filter_range(&input, crate::FilterKind::Audio { channels: 2 }, start..end)
            .unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_multiple_rar29_audio_vm_filter_records_for_large_ranges() {
    let input: Vec<u8> = (0..(MAX_VM_AUDIO_FILTER_BLOCK_SIZE * 2 + 64))
        .map(|index| (index * 7 + index / 3 + index / 257) as u8)
        .collect();
    let packed = encode_with_filter(&input, crate::FilterKind::Audio { channels: 4 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

#[test]
fn encoder_emits_multiple_rar29_delta_vm_filter_records_for_large_ranges() {
    let input: Vec<u8> = (0..(MAX_VM_DELTA_FILTER_BLOCK_SIZE * 2 + 64))
        .map(|index| (index * 11 + index / 5 + index / 251) as u8)
        .collect();
    let packed = encode_with_filter(&input, crate::FilterKind::Delta { channels: 4 }).unwrap();
    let decoded = unpack29_decode(&packed, input.len()).unwrap();

    assert_eq!(decoded, input);
}

fn assert_vm_filter_declares_program(record: &[u8], expected_selector: u32) {
    let first = record[0];
    assert_ne!(first & 0x80, 0);
    assert_ne!(first & 0x20, 0);
    assert_ne!(first & 0x10, 0);
    let inline_len = match first & 7 {
        len @ 0..=5 => len as usize + 1,
        6 => usize::from(record[1]) + 7,
        _ => u16::from_be_bytes([record[1], record[2]]) as usize,
    };
    let body_start = match first & 7 {
        0..=5 => 1,
        6 => 2,
        _ => 3,
    };
    let body = &record[body_start..body_start + inline_len];
    let mut bits = BitReader::from_bytes(body);
    assert_eq!(bits.read_encoded_u32().unwrap(), expected_selector);
    let _block_start = bits.read_encoded_u32().unwrap();
    let _block_size = bits.read_encoded_u32().unwrap();
    let mask = bits.read_bits(7).unwrap();
    for index in 0..7 {
        if mask & (1 << index) != 0 {
            let _ = bits.read_encoded_u32().unwrap();
        }
    }
    assert_eq!(
        bits.read_encoded_u32().unwrap() as usize,
        RAR3_AUDIO_FILTER_BYTECODE.len()
    );
}

#[test]
fn solid_encoder_emits_rar29_matches_against_previous_member_history() {
    let first = b"solid rar29 shared phrase alpha beta gamma ".repeat(4);
    let second = b"solid rar29 shared phrase alpha beta gamma ".repeat(2);
    let independent = unpack29_encode_literals(&second).unwrap();
    let mut encoder = Unpack29Encoder::new();
    let first_packed = encoder.encode_member(&first).unwrap();
    let second_packed = encoder.encode_member(&second).unwrap();

    assert!(second_packed.len() < independent.len());
    let mut decoder = Unpack29::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert_eq!(
        decoder.decode_member(&second_packed, second.len()).unwrap(),
        second
    );
}

#[test]
fn decode_member_from_reader_accepts_incremental_input() {
    struct TinyReader<'a> {
        input: &'a [u8],
    }

    impl std::io::Read for TinyReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.input.is_empty() {
                return Ok(0);
            }
            let len = self.input.len().min(out.len()).min(3);
            out[..len].copy_from_slice(&self.input[..len]);
            self.input = &self.input[len..];
            Ok(len)
        }
    }

    let mut decoder = Unpack29::new();
    let mut reader = TinyReader {
        input: COMPRESSED_TEXT,
    };
    let mut output = Vec::new();
    decoder
        .decode_member_from_reader(&mut reader, 2400, &mut output)
        .unwrap();

    assert_eq!(output, expected_text());
}

#[test]
fn member_output_entry_points_share_one_decode_contract() {
    let expected = expected_text();

    let mut decoder = Unpack29::new();
    let returned = decoder
        .decode_member(COMPRESSED_TEXT, expected.len())
        .unwrap();

    let mut decoder = Unpack29::new();
    let mut written = Vec::new();
    decoder
        .decode_member_to(COMPRESSED_TEXT, expected.len(), &mut written)
        .unwrap();

    let mut decoder = Unpack29::new();
    let mut reader = COMPRESSED_TEXT;
    let mut read_then_written = Vec::new();
    decoder
        .decode_member_from_reader(&mut reader, expected.len(), &mut read_then_written)
        .unwrap();

    assert_eq!(returned, expected);
    assert_eq!(written, expected);
    assert_eq!(read_then_written, expected);
}

#[test]
fn member_output_entry_points_report_the_same_truncation() {
    let truncated = &COMPRESSED_TEXT[..COMPRESSED_TEXT.len() / 2];
    let expected = Error::InvalidData("RAR 2.9 bitstream is truncated");

    let returned = Unpack29::new().decode_member(truncated, 2400).unwrap_err();

    let mut decoder = Unpack29::new();
    let mut written = Vec::new();
    let write_error = decoder
        .decode_member_to(truncated, 2400, &mut written)
        .unwrap_err();

    let mut decoder = Unpack29::new();
    let mut reader = truncated;
    let mut read_then_written = Vec::new();
    let reader_error = decoder
        .decode_member_from_reader(&mut reader, 2400, &mut read_then_written)
        .unwrap_err();

    assert_eq!(returned, expected);
    assert_eq!(write_error, expected);
    assert_eq!(reader_error, expected);
}

#[test]
fn member_output_entry_points_share_empty_member_handling() {
    let packed = unpack29_encode_literals(b"").unwrap();

    assert!(Unpack29::new()
        .decode_member(&packed, 0)
        .unwrap()
        .is_empty());

    let mut decoder = Unpack29::new();
    let mut written = Vec::new();
    decoder.decode_member_to(&packed, 0, &mut written).unwrap();
    assert!(written.is_empty());

    let mut decoder = Unpack29::new();
    let mut reader = packed.as_slice();
    decoder
        .decode_member_from_reader(&mut reader, 0, &mut written)
        .unwrap();
    assert!(written.is_empty());
}

#[test]
fn direct_codec_accepts_an_empty_stream_for_an_empty_member() {
    assert!(Unpack29::new().decode_member(&[], 0).unwrap().is_empty());
}

#[test]
fn empty_members_still_validate_a_supplied_table_header() {
    assert_eq!(
        Unpack29::new().decode_member(&[0], 0),
        Err(Error::InvalidData("RAR 2.9 bitstream is truncated"))
    );

    let invalid = table_description(&[0; 20], &[]);
    assert_eq!(
        Unpack29::new().decode_member(&invalid, 0),
        Err(Error::InvalidData("RAR 2.9 empty Huffman table"))
    );
}

#[test]
fn empty_solid_member_can_use_the_previous_members_huffman_tables() {
    let first = b"solid member with a retained Huffman table";
    let mut encoder = Unpack29Encoder::new();
    let mut first_packed = encoder.encode_member(first).unwrap();

    // Locate the last bit of the first member's end marker, then change
    // NewFileNewTables (0, 1) to NewFileKeepTables (0, 0). The latter is
    // valid legacy wire syntax even though our writer does not emit it.
    let mut probe = Unpack29::new();
    assert_eq!(
        probe.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    let keep_tables_bit = probe.bits.bit_pos - 1;
    let mask = 1 << (7 - keep_tables_bit % 8);
    assert_ne!(first_packed[keep_tables_bit / 8] & mask, 0);
    first_packed[keep_tables_bit / 8] &= !mask;

    let codes = canonical_codes(&encoder.levels[..MAIN_COUNT]);
    let end = codes[256].unwrap();
    let mut bits = BitWriter::default();
    bits.write_bits(u32::from(end.code), end.len);
    bits.write_bit(false); // new file
    bits.write_bit(true); // next member reads new tables
    let empty_packed = bits.finish();

    let mut decoder = Unpack29::new();
    assert_eq!(
        decoder.decode_member(&first_packed, first.len()).unwrap(),
        first
    );
    assert!(decoder.in_lz_block);
    assert!(decoder.decode_member(&empty_packed, 0).unwrap().is_empty());
    assert!(!decoder.in_lz_block);
}

#[test]
fn oversized_untrusted_filter_waits_across_a_streaming_batch() {
    let expected = vec![0; STREAM_CHUNK + 1];
    let packed = Unpack29Encoder::with_options(EncodeOptions::new(0))
        .encode_member(&expected)
        .unwrap();
    let mut decoder = Unpack29::new();
    decoder
        .programs
        .push(VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: expected.len(),
            exec_count: 0,
            globals: Vec::new().into(),
        })
        .unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: 0,
            size: expected.len(),
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();

    assert_eq!(
        decoder.decode_member(&packed, expected.len()).unwrap(),
        expected
    );
    assert!(decoder.filters.is_empty());
}

#[test]
fn slice_and_reader_entry_points_share_output_failures() {
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("deliberate failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let expected = Error::from(std::io::Error::other("deliberate failure"));
    let mut decoder = Unpack29::new();
    assert_eq!(
        decoder
            .decode_member_to(COMPRESSED_TEXT, 2400, &mut FailingWriter)
            .unwrap_err(),
        expected
    );

    let mut decoder = Unpack29::new();
    let mut reader = COMPRESSED_TEXT;
    assert_eq!(
        decoder
            .decode_member_from_reader(&mut reader, 2400, &mut FailingWriter)
            .unwrap_err(),
        expected
    );

    let mut decoder = Unpack29::new();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: 0,
            size: 1,
            regs: [0; 7],
            global_data: vec![1].into(),
        })
        .unwrap();
    assert_eq!(
        decoder
            .decode_non_solid_member_to(COMPRESSED_TEXT, 2400, &mut FailingWriter)
            .unwrap_err(),
        expected
    );
    assert!(decoder.filters.is_empty());
}

#[test]
fn decode_non_solid_member_resets_reusable_decoder_state() {
    let mut decoder = Unpack29::new();
    decoder.output.extend_from_slice(b"stale history").unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: 0,
            size: 1,
            regs: [0; 7],
            global_data: vec![1, 2, 3].into(),
        })
        .unwrap();

    let mut output = Vec::new();
    decoder
        .decode_non_solid_member_to(COMPRESSED_TEXT, 2400, &mut output)
        .unwrap();

    assert_eq!(output, expected_text());
    assert!(decoder.filters.is_empty());
}

#[test]
fn e8_filter_uses_member_relative_offset_in_solid_stream() {
    let mut decoder = Unpack29::new();
    let member_start = 1000usize;
    let filter_start = member_start + 100;
    decoder.output.resize(filter_start + 8, 0).unwrap();
    decoder.output[filter_start] = 0xe8;

    let call_operand_pos = 1u32;
    let member_relative_filter_start = (filter_start - member_start) as u32;
    let decoded_addr = 0x2000u32;
    let encoded_addr = decoded_addr
        .wrapping_add(member_relative_filter_start)
        .wrapping_add(call_operand_pos);
    decoder.output[filter_start + 1..filter_start + 5].copy_from_slice(&encoded_addr.to_le_bytes());
    decoder
        .programs
        .push(VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: 5,
            exec_count: 0,
            globals: Vec::new().into(),
        })
        .unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: filter_start,
            size: 5,
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();

    let filtered = decoder
        .filtered_range(member_start, filter_start + 5, member_start)
        .unwrap();
    let operand = u32::from_le_bytes([filtered[101], filtered[102], filtered[103], filtered[104]]);

    assert_eq!(operand, decoded_addr);
}

#[test]
fn generic_vm_filter_executes_from_filtered_range() {
    let mut decoder = Unpack29::new();
    decoder
        .output
        .extend_from_slice(&[0x11, 0x22, 0x33])
        .unwrap();
    decoder
        .programs
        .push(VmProgram {
            kind: VmProgramKind::Generic(
                Program {
                    static_data: Vec::new(),
                    instructions: vec![
                        Instruction {
                            opcode: Opcode::Mov,
                            byte_mode: true,
                            operands: vec![Operand::Absolute(0), Operand::Immediate(0x44)],
                        },
                        Instruction {
                            opcode: Opcode::Ret,
                            byte_mode: false,
                            operands: Vec::new(),
                        },
                    ],
                }
                .into(),
            ),
            block_size: 3,
            exec_count: 0,
            globals: Vec::new().into(),
        })
        .unwrap();
    decoder
        .filters
        .push(VmFilter {
            program: 0,
            start: 0,
            size: 3,
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();

    let filtered = decoder.filtered_range(0, 3, 0).unwrap();

    assert_eq!(filtered, [0x44, 0x22, 0x33]);
}

#[test]
fn generic_vm_filter_uses_explicit_then_retained_user_globals() {
    // Copies user-global byte 0 to the output, increments it, records one
    // retained user byte at global offset 0x30, then returns.
    const GLOBAL_COUNTER_PROGRAM: &[u8] = &[
        0x0d, 0x05, 0xc0, 0x7c, 0x00, 0x0f, 0x01, 0x01, 0xaf, 0x80, 0x01, 0xe0, 0x20, 0x01, 0xf0,
        0x00, 0x3c, 0x03, 0x00, 0x1b, 0x80,
    ];
    let filters = [
        OwnedVmFilterRecord {
            block_start: 0,
            block_size: 1,
            init_regs: Vec::new(),
            code: GLOBAL_COUNTER_PROGRAM,
            global_data: vec![b'A'],
        },
        OwnedVmFilterRecord {
            block_start: 1,
            block_size: 1,
            init_regs: Vec::new(),
            code: GLOBAL_COUNTER_PROGRAM,
            global_data: Vec::new(),
        },
    ];
    let refs = filters.iter().collect::<Vec<_>>();
    let records = encoded_filter_records_at(&refs, 0, usize::MAX, &mut Vec::new()).unwrap();
    let packed = super::encode_member_inner(
        &[0, 0],
        &[],
        &records,
        EncodeOptions::default(),
        false,
        &mut [0; TABLE_COUNT],
        None,
    )
    .unwrap();

    assert_eq!(unpack29_decode(&packed, 2).unwrap(), b"AB");
}

#[test]
fn standard_filters_reject_malformed_delta_and_rgb_registers() {
    let mut delta = vec![0; 32];
    let mut delta_regs = [0; 7];
    // 33 channels is legal here: the count comes from R[0], not from a
    // five-bit field, and the reference decoder allows up to 1024.
    delta_regs[0] = 33;
    assert_eq!(
        apply_standard_filter(StandardFilter::Delta, &mut delta, 0, &delta_regs),
        Ok(())
    );
    delta_regs[0] = super::MAX_DELTA_CHANNELS as u32 + 1;
    assert_eq!(
        apply_standard_filter(StandardFilter::Delta, &mut delta, 0, &delta_regs),
        Err(Error::InvalidData(
            "RAR 2.9 DELTA filter channel count is invalid"
        ))
    );
    delta_regs[0] = 0;
    assert_eq!(
        apply_standard_filter(StandardFilter::Delta, &mut delta, 0, &delta_regs),
        Err(Error::InvalidData(
            "RAR 2.9 DELTA filter channel count is invalid"
        ))
    );

    let mut rgb = vec![0; 32];
    let mut rgb_regs = [0; 7];
    rgb_regs[0] = 2;
    assert_eq!(
        apply_standard_filter(StandardFilter::Rgb, &mut rgb, 0, &rgb_regs),
        Err(Error::InvalidData(
            "RAR 2.9 RGB filter parameters are invalid"
        ))
    );
    rgb_regs[0] = 15;
    rgb_regs[1] = 3;
    assert_eq!(
        apply_standard_filter(StandardFilter::Rgb, &mut rgb, 0, &rgb_regs),
        Err(Error::InvalidData(
            "RAR 2.9 RGB filter parameters are invalid"
        ))
    );
}

#[test]
fn standard_filter_records_enforce_delta_and_audio_channel_bounds() {
    let input = vec![0; 1024];
    assert_eq!(
        decode_with_raw_standard_filter(&input, RAR3_DELTA_FILTER_BYTECODE, vec![(0, 0)]),
        Err(Error::InvalidData(
            "RAR 2.9 DELTA filter channel count is invalid"
        ))
    );
    assert_eq!(
        decode_with_raw_standard_filter(
            &input,
            RAR3_DELTA_FILTER_BYTECODE,
            vec![(0, (super::MAX_DELTA_CHANNELS + 1) as u32)],
        ),
        Err(Error::InvalidData(
            "RAR 2.9 DELTA filter channel count is invalid"
        ))
    );
    assert_eq!(
        decode_with_raw_standard_filter(
            &input,
            RAR3_DELTA_FILTER_BYTECODE,
            vec![(0, super::MAX_DELTA_CHANNELS as u32)],
        )
        .unwrap(),
        input
    );

    for channels in [0, super::MAX_AUDIO_CHANNELS + 1] {
        assert_eq!(
            decode_with_raw_standard_filter(
                &input,
                RAR3_AUDIO_FILTER_BYTECODE,
                vec![(0, channels as u32)],
            ),
            Err(Error::InvalidData(
                "RAR 2.9 AUDIO filter channel count is invalid"
            ))
        );
    }
}

#[test]
fn standard_rgb_filter_records_reject_nonportable_parameters() {
    let cases = [
        (vec![0; 2], 3, 0, "short input"),
        (vec![0; 12], 3, 0, "zero width"),
        (vec![0; 12], 11, 0, "unaligned width"),
        (vec![0; 12], 18, 0, "width beyond the block"),
        (vec![0; 12], 15, 3, "red channel beyond RGB"),
    ];
    for (input, encoded_width, pos_r, description) in cases {
        assert_eq!(
            decode_with_raw_standard_filter(
                &input,
                RAR3_RGB_FILTER_BYTECODE,
                vec![(0, encoded_width), (1, pos_r)],
            ),
            Err(Error::InvalidData(
                "RAR 2.9 RGB filter parameters are invalid"
            )),
            "accepted {description}"
        );
    }
}

#[test]
fn short_itanium_filter_records_are_defined_noops() {
    let mut empty = Vec::new();
    itanium_decode(&mut empty, 0);
    assert!(empty.is_empty());

    for len in [1, 20, 21, 22] {
        let input: Vec<u8> = (0..len).map(|index| (index * 17 + 3) as u8).collect();
        assert_eq!(
            decode_with_raw_standard_filter(&input, RAR3_ITANIUM_FILTER_BYTECODE, vec![]).unwrap(),
            input,
            "changed a {len}-byte non-branching block"
        );
    }
}

#[test]
fn short_itanium_filter_encoding_is_a_defined_noop() {
    for len in 4..=21 {
        let input: Vec<u8> = (0..len).map(|index| (index * 17 + 3) as u8).collect();
        let packed = encode_with_filter(&input, crate::FilterKind::Itanium).unwrap();
        assert_eq!(
            unpack29_decode(&packed, input.len()).unwrap(),
            input,
            "changed a {len}-byte block"
        );
    }
}

#[test]
fn vm_encoded_u32_accepts_32_bit_form() {
    let mut bits = super::BitReader::from_bytes(&[0xff; 5]);

    assert_eq!(bits.read_encoded_u32().unwrap(), 0xffff_ffff);
}

#[test]
fn vm_encoded_u32_accepts_the_signed_constant_form() {
    let mut encoded = BitWriter::default();
    encoded.write_bits(1, 2);
    encoded.write_bits(0x0a, 8);
    encoded.write_bits(0x05, 4);
    let mut bits = BitReader::from_bytes(&encoded.finish());

    assert_eq!(bits.read_encoded_u32().unwrap(), 0xffff_ffa5);
}

#[test]
fn vm_filter_record_serializer_uses_every_specified_length_form() {
    fn declared_payload(record: &[u8]) -> (usize, usize) {
        match record[0] & 7 {
            len @ 0..=5 => (1, usize::from(len) + 1),
            6 => (2, usize::from(record[1]) + 7),
            _ => (3, usize::from(u16::from_be_bytes([record[1], record[2]]))),
        }
    }

    let medium_code = vec![0; 53];
    let long_code = vec![0; 300];
    let records = [
        super::encode_vm_filter_record_inner(
            super::VmFilterRecord {
                block_start: 0,
                block_size: 1,
                init_regs: &[],
                code: &[],
                global_data: &[],
            },
            1,
            false,
        )
        .unwrap(),
        super::encode_vm_filter_record_inner(
            super::VmFilterRecord {
                block_start: 0,
                block_size: 1,
                init_regs: &[],
                code: &medium_code,
                global_data: &[],
            },
            0,
            true,
        )
        .unwrap(),
        super::encode_vm_filter_record_inner(
            super::VmFilterRecord {
                block_start: 0,
                block_size: 1,
                init_regs: &[],
                code: &long_code,
                global_data: &[],
            },
            0,
            true,
        )
        .unwrap(),
    ];

    assert!(matches!(records[0][0] & 7, 0..=5));
    assert_eq!(records[1][0] & 7, 6);
    assert_eq!(records[2][0] & 7, 7);
    for record in records {
        let (header_len, payload_len) = declared_payload(&record);
        assert_eq!(record.len(), header_len + payload_len);
    }
}

#[test]
fn decoder_reads_a_vm_filter_with_a_16_bit_payload_length() {
    let globals = vec![0x5a; 300];
    let record = super::encode_vm_filter_record_inner(
        super::VmFilterRecord {
            block_start: 3,
            block_size: 16,
            init_regs: &[],
            code: super::RAR3_E8_FILTER_BYTECODE,
            global_data: &globals,
        },
        0,
        true,
    )
    .unwrap();
    assert_eq!(record[0] & 7, 7);

    let mut decoder = Unpack29::new();
    decoder.bits = BitReader::from_bytes(&record);
    decoder.read_vm_code().unwrap();

    assert_eq!(decoder.programs.len(), 1);
    assert_eq!(decoder.filters.len(), 1);
    assert_eq!(decoder.filters[0].start, 3);
    assert_eq!(decoder.filters[0].size, 16);
    assert_eq!(
        &decoder.filters[0].global_data[super::VM_SYSTEM_GLOBAL_SIZE..],
        globals
    );
}

#[test]
fn vm_filter_record_serializer_rejects_invalid_fields() {
    assert_eq!(
        super::encode_vm_filter_record_inner(
            super::VmFilterRecord {
                block_start: 0,
                block_size: 0,
                init_regs: &[],
                code: &[1],
                global_data: &[],
            },
            0,
            true,
        ),
        Err(Error::InvalidData("RAR 2.9 VM filter block is empty"))
    );
    assert_eq!(
        super::encode_vm_filter_record_inner(
            super::VmFilterRecord {
                block_start: 0,
                block_size: 1,
                init_regs: &[],
                code: &[],
                global_data: &[],
            },
            0,
            true,
        ),
        Err(Error::InvalidData("RAR 2.9 VM filter bytecode is empty"))
    );
    assert_eq!(
        super::encode_vm_filter_record_inner(
            super::VmFilterRecord {
                block_start: 0,
                block_size: 1,
                init_regs: &[(7, 0)],
                code: &[1],
                global_data: &[],
            },
            0,
            true,
        ),
        Err(Error::InvalidData(
            "RAR 2.9 VM init register index is invalid"
        ))
    );

    let oversized_global = vec![0; 65_536];
    assert_eq!(
        super::encode_vm_filter_record_inner(
            super::VmFilterRecord {
                block_start: 0,
                block_size: 1,
                init_regs: &[],
                code: &[],
                global_data: &oversized_global,
            },
            1,
            false,
        ),
        Err(Error::InvalidData("RAR 2.9 VM filter record is too large"))
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn vm_filter_record_serializer_rejects_fields_wider_than_the_wire() {
    for (block_start, block_size, expected) in [
        (
            usize::MAX,
            1,
            Error::InvalidData("RAR 2.9 VM block start overflows"),
        ),
        (
            0,
            usize::MAX,
            Error::InvalidData("RAR 2.9 VM block size overflows"),
        ),
    ] {
        assert_eq!(
            super::encode_vm_filter_record_inner(
                super::VmFilterRecord {
                    block_start,
                    block_size,
                    init_regs: &[],
                    code: &[],
                    global_data: &[],
                },
                1,
                false,
            ),
            Err(expected)
        );
    }
}

#[test]
fn vm_filter_records_must_belong_to_their_encoding_block() {
    let filter = OwnedVmFilterRecord {
        block_start: 10,
        block_size: 1,
        init_regs: Vec::new(),
        code: super::RAR3_E8_FILTER_BYTECODE,
        global_data: Vec::new(),
    };

    assert_eq!(
        encoded_filter_records_at(&[&filter], 11, 32, &mut Vec::new()),
        Err(Error::InvalidData(
            "RAR 2.9 VM filter starts before its block"
        ))
    );
    assert_eq!(
        encoded_filter_records_at(&[&filter], 0, 10, &mut Vec::new()),
        Err(Error::InvalidData(
            "RAR 2.9 VM filter starts further past its block than the window can express"
        ))
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn member_relative_vm_filter_offsets_obey_the_u32_wire_boundary() {
    // PPMd callers declare filters relative to the whole member (base 0),
    // unlike LZ callers, which rebase them into dictionary-sized blocks.
    let mut filter = OwnedVmFilterRecord {
        block_start: u32::MAX as usize,
        block_size: 4,
        init_regs: Vec::new(),
        code: super::RAR3_E8_FILTER_BYTECODE,
        global_data: Vec::new(),
    };
    let records = encoded_filter_records_at(&[&filter], 0, usize::MAX, &mut Vec::new()).unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    let header_len = match record[0] & 7 {
        0..=5 => 1,
        6 => 2,
        _ => 3,
    };
    let mut body = BitReader::from_bytes(&record[header_len..]);
    assert_eq!(body.read_encoded_u32().unwrap(), 0);
    assert_eq!(body.read_encoded_u32().unwrap(), u32::MAX);
    assert_eq!(body.read_encoded_u32().unwrap(), 4);

    filter.block_start += 1;
    assert_eq!(
        encoded_filter_records_at(&[&filter], 0, usize::MAX, &mut Vec::new()),
        Err(Error::InvalidData("RAR 2.9 VM block start overflows"))
    );
    // The same absolute position is representable after an LZ block rebase.
    assert!(encoded_filter_records_at(&[&filter], filter.block_start, 4, &mut Vec::new(),).is_ok());
}

#[test]
fn archive_decoder_rejects_invalid_vm_program_records() {
    let cases = [
        (
            super::encode_vm_filter_record_inner(
                super::VmFilterRecord {
                    block_start: 0,
                    block_size: 1,
                    init_regs: &[],
                    code: &[],
                    global_data: &[],
                },
                2,
                false,
            )
            .unwrap(),
            Error::InvalidData("RAR 2.9 VM program index is invalid"),
        ),
        (
            super::encode_vm_filter_record_inner(
                super::VmFilterRecord {
                    block_start: 0,
                    block_size: 1,
                    init_regs: &[],
                    code: &[],
                    global_data: &[],
                },
                0,
                false,
            )
            .unwrap(),
            Error::InvalidData("RAR 2.9 VM code is empty"),
        ),
        (
            super::encode_vm_filter_record_inner(
                super::VmFilterRecord {
                    block_start: 0,
                    block_size: 1,
                    init_regs: &[],
                    code: &[1, 0],
                    global_data: &[],
                },
                0,
                true,
            )
            .unwrap(),
            Error::InvalidData("RARVM program checksum mismatch"),
        ),
    ];

    for (record, expected) in cases {
        let packed = super::encode_member_inner(
            &[0],
            &[],
            &[record],
            EncodeOptions::default(),
            false,
            &mut [0; TABLE_COUNT],
            None,
        )
        .unwrap();
        assert_eq!(unpack29_decode(&packed, 1), Err(expected));
    }
}

#[test]
fn archive_decoder_rejects_generic_vm_block_larger_than_work_memory() {
    // A checksum-valid nonstandard program with an implicit RET.
    const GENERIC_RET: &[u8] = &[0x5c, 0x5c];
    const TOO_LARGE: usize = 0x3c001;
    let filter = OwnedVmFilterRecord {
        block_start: 0,
        block_size: TOO_LARGE,
        init_regs: Vec::new(),
        code: GENERIC_RET,
        global_data: Vec::new(),
    };
    let records = encoded_filter_records_at(&[&filter], 0, usize::MAX, &mut Vec::new()).unwrap();
    let packed = super::encode_member_inner(
        &vec![0; TOO_LARGE],
        &[],
        &records,
        EncodeOptions::default(),
        false,
        &mut [0; TABLE_COUNT],
        None,
    )
    .unwrap();

    assert_eq!(
        unpack29_decode(&packed, TOO_LARGE),
        Err(Error::InvalidData("RARVM filter input is too large"))
    );
}

#[test]
fn vm_global_data_size_is_capped_before_reading_or_allocation() {
    let mut decoder = Unpack29::new();
    decoder
        .programs
        .push(VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: 1,
            exec_count: 0,
            globals: Vec::new().into(),
        })
        .unwrap();

    let mut data = BitWriter::default();
    data.write_encoded_u32(1);
    data.write_encoded_u32(0);
    data.write_encoded_u32(u32::MAX);

    assert_eq!(
        decoder.parse_vm_code(0x80 | 0x08, data.finish()),
        Err(Error::InvalidData("RAR 2.9 VM global data is too large"))
    );
}

#[test]
fn vm_code_size_is_capped_before_allocation() {
    let mut decoder = Unpack29::new();
    let mut data = BitWriter::default();
    data.write_encoded_u32(0);
    data.write_encoded_u32(1);
    data.write_encoded_u32(super::MAX_VM_CODE_SIZE as u32);

    assert_eq!(
        decoder.parse_vm_code(0x80, data.finish()),
        Err(Error::InvalidData("RAR 2.9 VM code is too large"))
    );
}

#[test]
fn vm_program_and_filter_counts_are_capped() {
    let mut decoder = Unpack29::new();
    decoder
        .programs
        .resize_with(super::MAX_VM_PROGRAMS, || VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: 1,
            exec_count: 0,
            globals: Vec::new().into(),
        })
        .unwrap();

    let mut new_program = BitWriter::default();
    new_program.write_encoded_u32((super::MAX_VM_PROGRAMS + 1) as u32);
    new_program.write_encoded_u32(1);
    new_program.write_encoded_u32(1);
    new_program.write_bits(0, 8);
    assert_eq!(
        decoder.parse_vm_code(0x80, new_program.finish()),
        Err(Error::InvalidData("RAR 2.9 VM program limit exceeded"))
    );

    decoder.programs.truncate(1);
    decoder.last_filter = 0;
    decoder
        .filters
        .resize_with(super::MAX_VM_FILTERS, || VmFilter {
            program: 0,
            start: 0,
            size: 1,
            regs: [0; 7],
            global_data: Vec::new().into(),
        })
        .unwrap();
    let mut reused_program = BitWriter::default();
    reused_program.write_encoded_u32(0);
    assert_eq!(
        decoder.parse_vm_code(0, reused_program.finish()),
        Err(Error::InvalidData("RAR 2.9 VM filter limit exceeded"))
    );
}

#[test]
fn itanium_filter_round_trips_with_high_file_offset() {
    let mut data = vec![0u8; 64];
    for (index, byte) in data.iter_mut().enumerate() {
        *byte = index as u8;
    }
    data[0] = 0;
    data[7] = 5 << 3;
    let original = data.clone();

    itanium_encode(&mut data, u32::MAX);
    itanium_decode(&mut data, u32::MAX);

    assert_eq!(data, original);
}

fn expected_text() -> Vec<u8> {
    "Hello, RAR 3.x fixture world.\n".repeat(80).into_bytes()
}
