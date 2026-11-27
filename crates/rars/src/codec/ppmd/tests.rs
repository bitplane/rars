use super::*;
use crate::codec::workspace::Allowance;

struct Bytes<'a> {
    input: &'a [u8],
}

impl PpmdByteReader for Bytes<'_> {
    fn read_ppmd_byte(&mut self) -> Result<u8> {
        let Some((&byte, rest)) = self.input.split_first() else {
            return Err(Error::NeedMoreInput);
        };
        self.input = rest;
        Ok(byte)
    }
}

const ESCAPE: u8 = 2;

// The order bits of a block header that resets the model.
fn order_bits(max_order: usize) -> u8 {
    if max_order <= 16 {
        max_order as u8 - 1
    } else {
        ((max_order - 16) / 3 + 15) as u8
    }
}

// What the writer's model codes for `data`, as a resetting block: header
// byte, the rest of the header, then the range-coded symbols.
fn encode(data: &[u8], max_order: usize, dictionary_mb: usize) -> (u8, Vec<u8>, Vec<u8>) {
    let mut encoder = PpmdEncoder::new(max_order, ESCAPE, dictionary_mb).unwrap();
    let mut symbols = Vec::new();
    for &byte in data {
        encoder.encode_literal(byte).unwrap();
        symbols.push(byte);
        if byte == ESCAPE {
            symbols.push(1);
        }
    }
    let (packed, _) = encoder.finish_keeping_model().unwrap();
    symbols.extend([ESCAPE, 2]);
    let mut input = vec![dictionary_mb as u8 - 1];
    input.extend(packed);
    (0x20 | order_bits(max_order), input, symbols)
}

fn decode_all(model: &mut Ppmd7, input: &mut Bytes, count: usize) -> Vec<u8> {
    (0..count)
        .map(|_| model.decode_symbol(input).unwrap().expect("a symbol"))
        .collect()
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn text(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&[u8]; 12] = [
        b"the ",
        b"model ",
        b"restarts ",
        b"when ",
        b"its ",
        b"pool ",
        b"fills, ",
        b"and ",
        b"free ",
        b"blocks ",
        b"join.\n",
        b"\x02escape ",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(WORDS[xorshift(&mut state) as usize % WORDS.len()]);
    }
    out.truncate(len);
    out
}

fn noise(len: usize, seed: u64, alphabet: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| (xorshift(&mut state) % alphabet) as u8)
        .collect()
}

fn periodic(len: usize, period: usize, every: u64, seed: u64) -> Vec<u8> {
    let block = noise(period, seed, 256);
    let mut state = seed ^ 0x9e37;
    (0..len)
        .map(|i| {
            if xorshift(&mut state).is_multiple_of(every) {
                xorshift(&mut state) as u8
            } else {
                block[i % period]
            }
        })
        .collect()
}

#[test]
fn decodes_what_the_writer_encodes_through_restarts_and_glue() {
    let cases = [
        (text(40_000, 1), 2, 1),
        (text(40_000, 2), 6, 1),
        (noise(40_000, 3, 256), 16, 4),
        // A 1 MiB pool fills quickly at order 64, so the model is glued
        // and restarted many times.
        (noise(300_000, 4, 40), 64, 1),
        ([text(100_000, 5), noise(100_000, 6, 256)].concat(), 25, 1),
        // A repeating block with frequent changes keeps the model below its
        // top order, writing raw text on most symbols, until the text area
        // rather than the units runs out.
        (periodic(600_000, 2000, 10, 11), 16, 1),
    ];
    let mut restarted = false;
    let mut glued = false;
    let mut text_filled = false;
    for (data, max_order, dictionary_mb) in cases {
        let (first, input, symbols) = encode(&data, max_order, dictionary_mb);
        let mut model = Ppmd7::with_allowance(&Allowance::default());
        let mut input = Bytes { input: &input };
        let mut escape = ESCAPE;
        model.decode_init(first, &mut input, &mut escape).unwrap();
        assert_eq!(
            decode_all(&mut model, &mut input, symbols.len()),
            symbols,
            "order {max_order}, {dictionary_mb} MiB"
        );
        restarted |= model.restarts > 1;
        glued |= model.glues > 0;
        text_filled |= model.text_restarts > 0;
    }
    assert!(restarted && glued && text_filled);
}

#[test]
fn a_copy_decodes_on_exactly_as_the_original() {
    let data = noise(200_000, 7, 40);
    let (first, input, symbols) = encode(&data, 64, 1);
    let budget = Allowance::limited(u64::MAX);
    let mut model = Ppmd7::with_allowance(&budget);
    let mut input = Bytes { input: &input };
    let mut escape = ESCAPE;
    model.decode_init(first, &mut input, &mut escape).unwrap();
    let half = symbols.len() / 2;
    assert_eq!(decode_all(&mut model, &mut input, half), symbols[..half]);
    assert!(model.glues > 0);
    let charged = budget.used();
    let mut copy = model.try_clone().unwrap();
    assert_eq!(budget.used(), 2 * charged);
    let mut copy_input = Bytes { input: input.input };
    let rest = symbols.len() - half;
    assert_eq!(
        decode_all(&mut copy, &mut copy_input, rest),
        symbols[half..]
    );
    assert_eq!(decode_all(&mut model, &mut input, rest), symbols[half..]);
}

#[test]
fn the_pool_is_charged_only_as_far_as_the_model_reaches() {
    // A short stream in a 25 MiB model touches a sliver of the pool.
    let (first, input, symbols) = encode(b"abracadabra, abracadabra", 6, 25);
    let budget = Allowance::limited(1 << 20);
    let mut model = Ppmd7::with_allowance(&budget);
    let mut bytes = Bytes { input: &input };
    let mut escape = ESCAPE;
    model.decode_init(first, &mut bytes, &mut escape).unwrap();
    assert_eq!(decode_all(&mut model, &mut bytes, symbols.len()), symbols);
    assert_eq!(budget.used(), CHARGE_STEP);
    drop(model);
    assert_eq!(budget.used(), 0);

    // A stream that fills a 1 MiB pool many times over needs all of it, and
    // no more, however often the model restarts.
    let (first, input, symbols) = encode(&noise(300_000, 4, 40), 64, 1);
    for (limit, completes) in [(1 << 20, true), (1 << 19, false)] {
        let budget = Allowance::limited(limit);
        let mut model = Ppmd7::with_allowance(&budget);
        let mut bytes = Bytes { input: &input };
        model.decode_init(first, &mut bytes, &mut escape).unwrap();
        let outcome = (0..symbols.len()).try_for_each(|_| {
            model.decode_symbol(&mut bytes)?;
            // The charge never lags behind what the model has reached.
            let reach = u64::from(model.text - model.align)
                + u64::from(model.lo_unit - model.units_start)
                + u64::from(model.align + model.size - model.hi_unit);
            assert!(budget.used() >= reach.min(model.mem.len() as u64));
            Ok(())
        });
        if completes {
            outcome.unwrap();
            assert!(model.restarts > 1);
            assert_eq!(budget.used(), 1 << 20);
        } else {
            assert!(matches!(outcome, Err(Error::WorkspaceLimitExceeded(_))));
            assert!(budget.used() <= limit);
        }
    }
}

#[test]
fn glueing_free_blocks_polls_for_cancellation() {
    let data = noise(200_000, 8, 40);
    let (first, input, symbols) = encode(&data, 64, 1);
    let token = crate::ReadCancellation::new();
    let control = crate::read_control::ReadControl::new(Some(&token));
    let mut model = Ppmd7::with_allowance(&Allowance::default());
    model.set_read_control(control.clone());
    let mut input = Bytes { input: &input };
    let mut escape = ESCAPE;
    model.decode_init(first, &mut input, &mut escape).unwrap();
    // The model polls only while glueing, so the first poll is the first glue.
    control.cancel_after_checks(0);
    let outcome = (0..symbols.len()).try_for_each(|_| model.decode_symbol(&mut input).map(drop));
    assert!(matches!(outcome, Err(Error::Cancelled)));
    assert_eq!(model.glues, 1);
}

#[test]
fn headers_must_name_an_order_and_a_model() {
    let mut model = Ppmd7::with_allowance(&Allowance::default());
    let mut escape = ESCAPE;
    let input = [0, 0, 0, 0, 0];
    assert!(matches!(
        model.decode_init(0x20, &mut Bytes { input: &input }, &mut escape),
        Err(Error::InvalidData("RAR PPMd order is invalid"))
    ));
    assert!(matches!(
        model.decode_init(0x05, &mut Bytes { input: &input }, &mut escape),
        Err(Error::InvalidData("RAR PPMd block reuses missing model"))
    ));
}

#[test]
fn contexts_are_charged_as_they_reach_down_the_pool() {
    let (first, input, _) = encode(b"abracadabra", 6, 1);
    let budget = Allowance::limited(u64::MAX);
    let mut model = Ppmd7::with_allowance(&budget);
    let mut escape = ESCAPE;
    model
        .decode_init(first, &mut Bytes { input: &input }, &mut escape)
        .unwrap();
    assert_eq!(budget.used(), CHARGE_STEP);
    let units = (CHARGE_STEP / u64::from(UNIT_SIZE)) as usize;
    for _ in 0..units {
        model.take_context_unit().unwrap();
    }
    assert_eq!(budget.used(), 2 * CHARGE_STEP);
}

#[test]
fn a_model_the_budget_refuses_cannot_be_continued() {
    let (first, input, _) = encode(b"abracadabra", 6, 1);
    let budget = Allowance::limited(CHARGE_STEP - 1);
    let mut model = Ppmd7::with_allowance(&budget);
    let mut escape = ESCAPE;
    assert!(matches!(
        model.decode_init(first, &mut Bytes { input: &input }, &mut escape),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(budget.used(), 0);
    assert!(matches!(
        model.decode_symbol(&mut Bytes { input: &[0; 8] }),
        Err(Error::InvalidData("RAR PPMd block reuses missing model"))
    ));
    assert!(matches!(
        model.decode_init(0x05, &mut Bytes { input: &[0; 8] }, &mut escape),
        Err(Error::InvalidData("RAR PPMd block reuses missing model"))
    ));
}

#[cfg(feature = "write")]
fn golden_cases() -> Vec<(Vec<u8>, usize, usize)> {
    vec![
        (text(40_000, 1), 2, 1),
        (text(40_000, 2), 6, 1),
        (noise(40_000, 3, 256), 16, 4),
        (noise(300_000, 4, 40), 64, 1),
        ([text(100_000, 5), noise(100_000, 6, 256)].concat(), 25, 1),
        (periodic(600_000, 2000, 10, 11), 16, 1),
    ]
}

// Codes `data` with escapes, matches and repeats mixed in, then a second
// block continuing the model.
#[cfg(feature = "write")]
macro_rules! code_with_commands {
    ($encoder:ty, $data:expr, $order:expr, $mb:expr) => {{
        let data: &[u8] = $data;
        let mut encoder = <$encoder>::new($order, ESCAPE, $mb).unwrap();
        for (i, chunk) in data.chunks(997).enumerate() {
            for &byte in chunk {
                encoder.encode_literal(byte).unwrap();
            }
            match i % 3 {
                0 => encoder.encode_match(2 + i * 31, 32 + i % 256).unwrap(),
                1 => encoder.encode_repeat_offset_one(4 + i % 256).unwrap(),
                _ => encoder
                    .encode_vm_filter_record(&[i as u8, 0x80, 3, 1])
                    .unwrap(),
            }
        }
        let (mut out, model) = encoder.finish_keeping_model().unwrap();
        let mut encoder = <$encoder>::continuing(model, ESCAPE);
        for &byte in &data[..data.len() / 2] {
            encoder.encode_literal(byte).unwrap();
        }
        out.extend(encoder.finish_keeping_model().unwrap().0);
        out
    }};
}

// Lengths and CRC-32s of what the writer codes for `golden_cases`. They were
// captured from the previous model, which kept contexts, states and a
// simulated suballocator apart and matched these bytes independently. They
// pin restarts, glueing and every escape command, which a round trip through
// one model could not: its encoder and decoder would agree on any mistake.
#[cfg(feature = "write")]
const GOLDEN: [(usize, u32); 6] = [
    (5730, 0xf72d8d8e),
    (5180, 0x1b264cd6),
    (40475, 0x782cacc1),
    (310836, 0x3eea2b1b),
    (120711, 0x587b7744),
    (334130, 0x802daf1d),
];

#[cfg(feature = "write")]
#[test]
fn the_writer_codes_exactly_what_the_previous_model_did() {
    for ((data, order, mb), (len, crc)) in golden_cases().into_iter().zip(GOLDEN) {
        let out = code_with_commands!(PpmdEncoder, &data, order, mb);
        assert_eq!(
            (out.len(), crate::crc32::crc32(&out)),
            (len, crc),
            "order {order}, {mb} MiB"
        );
    }
}

// A model ready to allocate from, with empty free lists.
fn pool(dictionary_mb: usize) -> Ppmd7 {
    let mut model = Ppmd7::for_encoding(6, dictionary_mb).unwrap();
    model.free_list = [0; NUM_INDEXES];
    model
}

fn free_blocks(model: &Ppmd7, indx: usize) -> Vec<u32> {
    let mut blocks = Vec::new();
    let mut node = model.free_list[indx];
    while node != 0 {
        blocks.push(node);
        node = model.u32_at(node);
    }
    blocks
}

#[test]
fn block_sizes_step_up_to_128_units() {
    let model = pool(1);
    let sizes: Vec<u32> = (0..NUM_INDEXES).map(|i| model.i2u(i)).collect();
    assert_eq!(sizes[..12], [1, 2, 3, 4, 6, 8, 10, 12, 15, 18, 21, 24]);
    assert!(sizes[11..].windows(2).all(|pair| pair[1] - pair[0] == 4));
    assert_eq!(sizes[NUM_INDEXES - 1], 128);
    for nu in 1..=128 {
        let indx = model.u2i(nu);
        assert!(model.i2u(indx) >= nu && (indx == 0 || model.i2u(indx - 1) < nu));
    }
}

#[test]
fn splitting_a_block_frees_an_inexact_residue_as_two_blocks() {
    let mut model = pool(1);
    let block = model.lo_unit;
    // Keep 3 of 8 units: the other 5 have no list of their own, so they
    // are freed as 4 units and 1.
    model.split_block(block, model.u2i(8), model.u2i(3));
    assert_eq!(free_blocks(&model, model.u2i(4)), [block + 3 * UNIT_SIZE]);
    assert_eq!(free_blocks(&model, 0), [block + 7 * UNIT_SIZE]);
}

#[test]
fn glueing_joins_adjacent_free_blocks_only() {
    let mut model = pool(1);
    let [a, b, c, d] = [(); 4].map(|_| model.alloc_units(0).unwrap().unwrap());
    // `c` stays in use: a context's first field is never zero.
    model.set_u16(c, 1);
    for block in [a, b, d] {
        model.insert_node(block, 0);
    }
    model.glue_free_blocks().unwrap();
    assert_eq!(free_blocks(&model, 1), [a]);
    assert_eq!(free_blocks(&model, 0), [d]);
}

#[test]
fn glueing_cuts_runs_into_128_unit_blocks_and_an_inexact_rest() {
    let mut model = pool(1);
    let a = model.alloc_units(NUM_INDEXES - 1).unwrap().unwrap();
    let b = model.alloc_units(model.u2i(4)).unwrap().unwrap();
    let c = model.alloc_units(model.u2i(3)).unwrap().unwrap();
    model.insert_node(a, NUM_INDEXES - 1);
    model.insert_node(b, model.u2i(4));
    model.insert_node(c, model.u2i(3));
    model.glue_free_blocks().unwrap();
    // 135 units: 128, then 7 as 6 and 1.
    assert_eq!(free_blocks(&model, NUM_INDEXES - 1), [a]);
    assert_eq!(free_blocks(&model, model.u2i(6)), [a + 128 * UNIT_SIZE]);
    assert_eq!(free_blocks(&model, 0), [a + 134 * UNIT_SIZE]);
    assert!(free_blocks(&model, model.u2i(4)).is_empty());
    assert!(free_blocks(&model, model.u2i(3)).is_empty());
}

#[test]
fn glueing_never_builds_a_run_too_long_for_its_16_bit_length() {
    let mut model = pool(1);
    let blocks: Vec<u32> = (0..520)
        .map(|_| model.alloc_units(NUM_INDEXES - 1).unwrap().unwrap())
        .collect();
    for &block in &blocks {
        model.insert_node(block, NUM_INDEXES - 1);
    }
    model.glue_free_blocks().unwrap();
    let mut refilled = free_blocks(&model, NUM_INDEXES - 1);
    refilled.sort_unstable();
    assert_eq!(refilled, blocks);
}

#[test]
fn rare_allocation_splits_a_larger_free_block() {
    let mut model = pool(1);
    model.glue_count = 1;
    let block = model.alloc_units(model.u2i(8)).unwrap().unwrap();
    model.insert_node(block, model.u2i(8));
    assert_eq!(model.alloc_units_rare(0).unwrap(), Some(block));
    assert_eq!(free_blocks(&model, model.u2i(6)), [block + UNIT_SIZE]);
    assert_eq!(free_blocks(&model, 0), [block + 7 * UNIT_SIZE]);
}

#[test]
fn rare_allocation_borrows_text_space_until_the_text_reaches_it() {
    let mut model = pool(1);
    model.glue_count = 2;
    let units_start = model.units_start;
    assert_eq!(
        model.alloc_units_rare(0).unwrap(),
        Some(units_start - UNIT_SIZE)
    );
    assert_eq!(model.units_start, units_start - UNIT_SIZE);
    model.text = model.units_start - UNIT_SIZE;
    assert_eq!(model.alloc_units_rare(0).unwrap(), None);
    assert_eq!(model.glue_count, 0);
    assert_eq!(model.glues, 0);
}

#[test]
fn rare_allocation_glues_once_then_waits_255_attempts() {
    let mut model = pool(1);
    model.glue_count = 0;
    model.alloc_units_rare(0).unwrap();
    assert_eq!((model.glues, model.glue_count), (1, 254));
    for _ in 0..254 {
        model.alloc_units_rare(0).unwrap();
    }
    assert_eq!((model.glues, model.glue_count), (1, 0));
    model.alloc_units_rare(0).unwrap();
    assert_eq!(model.glues, 2);
}

#[test]
fn headers_set_order_escape_and_range_or_fail_cleanly() {
    let mut model = Ppmd7::with_allowance(&Allowance::default());
    let mut escape = ESCAPE;
    assert!(matches!(
        model.decode_init(0x20, &mut Bytes { input: &[0, 1, 2] }, &mut escape),
        Err(Error::NeedMoreInput)
    ));
    // The largest order the header can name, an escape character and a
    // range code the coder reserves.
    let reserved = [0, 7, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(
        model.decode_init(0x7f, &mut Bytes { input: &reserved }, &mut escape),
        Err(Error::InvalidData("RAR PPMd range code is invalid"))
    ));
    assert_eq!(escape, 7);
    model
        .decode_init(
            0x7f,
            &mut Bytes {
                input: &[0, 9, 0, 0, 0, 0],
            },
            &mut escape,
        )
        .unwrap();
    assert_eq!((escape, model.max_order), (9, 64));
}

// A fresh model whose range coder reads `code` next.
fn fresh(code: u32) -> Ppmd7 {
    let mut model = Ppmd7::with_allowance(&Allowance::default());
    let mut escape = ESCAPE;
    let mut input = vec![0];
    input.extend(code.to_be_bytes());
    model
        .decode_init(0x25, &mut Bytes { input: &input }, &mut escape)
        .unwrap();
    model
}

#[test]
fn decoding_reports_impossible_ranges_and_ends_at_a_root_escape() {
    let mut model = fresh(0);
    model.rc.range = 256;
    assert!(matches!(
        model.decode_symbol(&mut Bytes { input: &[] }),
        Err(Error::InvalidData("RAR PPMd range is invalid"))
    ));
    // The root context has 256 symbols of frequency 1 and an escape of 1.
    // Corrupt input can leave the code past the range it should be within.
    let mut model = fresh(0);
    model.rc.range = 1000;
    model.rc.code = 900;
    assert!(matches!(
        model.decode_symbol(&mut Bytes { input: &[] }),
        Err(Error::InvalidData("RAR PPMd frequency sum is invalid"))
    ));
    let mut model = fresh(256 * (u32::MAX / 257));
    assert_eq!(
        model.decode_symbol(&mut Bytes { input: &[0; 8] }).unwrap(),
        None
    );
}

// A failed symbol can stop partway through an escape, in a state only that
// call's masks made consistent, so nothing may continue the model after it.
#[test]
fn a_failed_symbol_leaves_no_model_to_continue() {
    let missing = |outcome: Result<Option<u8>>| {
        matches!(
            outcome,
            Err(Error::InvalidData("RAR PPMd block reuses missing model"))
        )
    };
    let mut escape = ESCAPE;
    let continuing = |model: &mut Ppmd7, escape: &mut u8| {
        model.decode_init(0x05, &mut Bytes { input: &[0; 8] }, escape)
    };

    // Escaping past the root context ends with no symbol.
    let mut model = fresh(256 * (u32::MAX / 257));
    assert_eq!(
        model.decode_symbol(&mut Bytes { input: &[0; 8] }).unwrap(),
        None
    );
    assert!(missing(model.decode_symbol(&mut Bytes { input: &[0; 8] })));
    assert!(matches!(
        continuing(&mut model, &mut escape),
        Err(Error::InvalidData("RAR PPMd block reuses missing model"))
    ));

    // Input that runs out partway through a symbol.
    let (first, input, symbols) = encode(&text(4_000, 9), 6, 1);
    let cut = &input[..input.len() / 2];
    let mut model = Ppmd7::with_allowance(&Allowance::default());
    let mut bytes = Bytes { input: cut };
    model.decode_init(first, &mut bytes, &mut escape).unwrap();
    let outcome = (0..symbols.len()).try_for_each(|_| model.decode_symbol(&mut bytes).map(drop));
    assert!(matches!(outcome, Err(Error::NeedMoreInput)));
    assert!(missing(model.decode_symbol(&mut Bytes { input: &[0; 8] })));
    assert!(continuing(&mut model, &mut escape).is_err());

    // A block that resets the model starts afresh.
    let mut bytes = Bytes { input: &input };
    model.decode_init(first, &mut bytes, &mut escape).unwrap();
    assert_eq!(decode_all(&mut model, &mut bytes, symbols.len()), symbols);
}

#[test]
fn see_estimates_slow_their_adaptation_to_a_limit() {
    let mut see = See {
        summ: 3,
        shift: PERIOD_BITS - 1,
        count: 2,
    };
    see.update();
    assert_eq!((see.summ, see.shift, see.count), (3, PERIOD_BITS - 1, 1));
    see.update();
    assert_eq!(
        (see.summ, see.shift, see.count),
        (6, PERIOD_BITS, 3 << (PERIOD_BITS - 1))
    );
    see.update();
    assert_eq!(
        (see.summ, see.shift, see.count),
        (6, PERIOD_BITS, 3 << (PERIOD_BITS - 1))
    );
}

#[test]
fn the_writer_refuses_what_a_block_cannot_carry() {
    for (order, mb) in [(1, 1), (65, 1), (6, 0), (6, 257)] {
        assert!(PpmdEncoder::new(order, ESCAPE, mb).is_err(), "{order} {mb}");
    }
    let mut encoder = PpmdEncoder::new(6, ESCAPE, 1).unwrap();
    for (offset, length) in [(1, 32), (0x1000002, 32), (2, 31), (2, 288)] {
        assert!(encoder.encode_match(offset, length).is_err());
    }
    for length in [3, 260] {
        assert!(encoder.encode_repeat_offset_one(length).is_err());
    }
}
