use super::*;
use crate::codec::ppmd::PpmdEncoder;
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

fn decode_all<B: Budget>(model: &mut Ppmd7<B>, input: &mut Bytes, count: usize) -> Vec<u8> {
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
    let mut model = Ppmd7::with_allowance(&Allowance::default());
    let mut input = Bytes { input: &input };
    let mut escape = ESCAPE;
    model.decode_init(first, &mut input, &mut escape).unwrap();
    let half = symbols.len() / 2;
    assert_eq!(decode_all(&mut model, &mut input, half), symbols[..half]);
    assert!(model.glues > 0);
    let mut copy = model.try_clone().unwrap();
    let mut copy_input = Bytes { input: input.input };
    let rest = symbols.len() - half;
    assert_eq!(
        decode_all(&mut copy, &mut copy_input, rest),
        symbols[half..]
    );
    assert_eq!(decode_all(&mut model, &mut input, rest), symbols[half..]);
}

#[test]
fn the_declared_model_size_is_charged_when_a_block_resets_it() {
    let (first, input, _) = encode(b"abracadabra", 6, 3);
    let declared = 3 << 20;
    let budget = Allowance::limited(declared - 1);
    let mut model = Ppmd7::with_allowance(&budget);
    let mut escape = ESCAPE;
    assert!(matches!(
        model.decode_init(first, &mut Bytes { input: &input }, &mut escape),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    let budget = Allowance::limited(declared);
    let mut model = Ppmd7::with_allowance(&budget);
    model
        .decode_init(first, &mut Bytes { input: &input }, &mut escape)
        .unwrap();
    assert_eq!(budget.used(), declared);
    drop(model);
    assert_eq!(budget.used(), 0);
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
fn a_refused_model_cannot_be_continued() {
    let (first, input, symbols) = encode(b"abracadabra", 6, 1);
    let budget = Allowance::limited(2 << 20);
    let mut model = Ppmd7::with_allowance(&budget);
    let mut escape = ESCAPE;
    let mut bytes = Bytes { input: &input };
    model.decode_init(first, &mut bytes, &mut escape).unwrap();
    assert_eq!(decode_all(&mut model, &mut bytes, 3), symbols[..3]);

    // A reset that declares more than the budget allows loses the old model.
    let (first, input, _) = encode(b"abracadabra", 6, 3);
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
