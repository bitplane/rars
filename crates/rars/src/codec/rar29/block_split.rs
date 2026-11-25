//! Where one parse's tokens are cut into blocks with tables of their own.
//!
//! A block's code lengths fit the block as a whole, so a stretch of code next
//! to a stretch of tables pays for codes shaped for the mix of the two. A cut
//! costs a table header, a few hundred bits. Which wins depends on how far the
//! statistics move, so the cuts are priced: the parse is marked every
//! [`UNIT`] bytes, every run of whole units is priced as one block, and the
//! cheapest way to cover the parse with such runs is kept, provided its real
//! tables still code smaller than one block's.
//!
//! The reader keeps its repeat offsets from one block to the next, so each
//! piece is coded from the offsets the parse carried into it, and a token
//! codes to the same symbols however the parse is cut.
//!
//! Fixed blocks of half the writer's 64 KiB pack a stripped binary smaller
//! and man pages larger. Halving the unit about quadruples the runs priced, so
//! 4 KiB.
use super::*;

/// How finely the cuts are placed.
const UNIT: usize = 4 * 1024;

/// The longest parse the search will cut. Every run of units is priced, so
/// the work grows with the square of the units, and the writer's blocks are
/// this size anyway.
const SPLIT_SPAN: usize = 64 * 1024;

/// What a block costs besides its tables and symbols: the two header bits,
/// the end-of-block flags, and on average half a byte of padding, since every
/// table starts on a byte.
const FRAMING_BITS: usize = 8;

/// The table's four alphabets.
const ALPHABETS: [std::ops::Range<usize>; 4] = [
    0..OFFSET_TABLE,
    OFFSET_TABLE..LOW_OFFSET_TABLE,
    LOW_OFFSET_TABLE..LENGTH_TABLE,
    LENGTH_TABLE..TABLE_COUNT,
];

/// A unit boundary: the first token at or past it, where that token starts,
/// the repeat offsets coming into it, and the symbols coded before it.
struct Mark {
    token: usize,
    pos: usize,
    state: EncoderMatchState,
    counts: Box<[usize; TABLE_COUNT]>,
}

/// Cuts `tokens`, which code `start..end` from no repeat offsets as
/// `counted` says, into the blocks that code smallest.
pub(super) fn split(
    start: usize,
    end: usize,
    tokens: Vec<EncodeToken>,
    counted: Box<Counted>,
) -> Result<Vec<Piece>> {
    let whole = |tokens| {
        Ok(vec![Piece {
            end,
            state: EncoderMatchState::default(),
            tokens,
            counted: Some(counted),
        }])
    };
    if end - start > SPLIT_SPAN || end - start < 2 * UNIT {
        return whole(tokens);
    }
    let mut state = EncoderMatchState::default();
    let mut running = [0usize; TABLE_COUNT];
    let mut marks = vec![Mark {
        token: 0,
        pos: start,
        state,
        counts: Box::new(running),
    }];
    let mut pos = start;
    let mut next = start + UNIT;
    for (index, token) in tokens.iter().enumerate() {
        if pos >= next {
            marks.push(Mark {
                token: index,
                pos,
                state,
                counts: Box::new(running),
            });
            next = start + ((pos - start) / UNIT + 1) * UNIT;
        }
        match *token {
            EncodeToken::Literal(byte) => {
                running[usize::from(byte)] += 1;
                pos += 1;
            }
            EncodeToken::Match { length, offset } => {
                let (length, offset) = (length as usize, offset as usize);
                count_match(state.encode_match(length, offset)?, &mut running);
                state.remember(length, offset);
                pos += length;
            }
        }
    }
    marks.push(Mark {
        token: tokens.len(),
        pos: end,
        state,
        counts: Box::new(running),
    });

    // cheapest[last] covers marks 0..=last, its final block starting at from[last].
    let units = marks.len() - 1;
    // Only the symbols the parse uses can count anywhere in it, and pricing
    // skipped every other one anyway.
    let used = Used::new(&marks[0].counts, &marks[units].counts);
    let mut cheapest = vec![f64::MAX; units + 1];
    let mut from = vec![0usize; units + 1];
    cheapest[0] = 0.0;
    for last in 1..=units {
        for first in 0..last {
            let bits =
                cheapest[first] + estimated(&used, &marks[first].counts, &marks[last].counts);
            if bits < cheapest[last] {
                cheapest[last] = bits;
                from[last] = first;
            }
        }
    }
    // Where each block starts, the last block first.
    let mut cuts = Vec::new();
    let mut at = units;
    while at != 0 {
        cuts.push(from[at]);
        at = from[at];
    }
    if cuts.len() == 1 {
        return whole(tokens);
    }
    let mut split_bits = 0;
    let mut after = units;
    for &cut in &cuts {
        split_bits += priced(&marks[cut].counts, &marks[after].counts);
        after = cut;
    }
    if split_bits >= priced(&marks[0].counts, &marks[units].counts) {
        return whole(tokens);
    }

    // Cut from the back, so each piece is split off what is left.
    let mut pieces = Vec::with_capacity(cuts.len());
    let mut rest = tokens;
    let mut piece_end = end;
    let mut after = &marks[units];
    for &cut in &cuts {
        let mark = &marks[cut];
        let mut frequencies = [0usize; TABLE_COUNT];
        for (frequency, (after, before)) in frequencies
            .iter_mut()
            .zip(after.counts.iter().zip(mark.counts.iter()))
        {
            *frequency = after - before;
        }
        pieces.push(Piece {
            end: piece_end,
            state: mark.state,
            tokens: rest.split_off(mark.token),
            counted: Some(Box::new(Counted {
                frequencies,
                table: None,
            })),
        });
        piece_end = mark.pos;
        after = mark;
    }
    pieces.reverse();
    Ok(pieces)
}

/// Near what [`priced`] says, without building a Huffman code: each alphabet
/// at its entropy, and the table priced with lengths taken from the counts.
///
/// Building the codes for every run of units takes as long as level 2's whole
/// lazy parse.
fn estimated(used: &Used, before: &[usize; TABLE_COUNT], after: &[usize; TABLE_COUNT]) -> f64 {
    let mut table = [0u8; TABLE_COUNT];
    let mut symbols = 0.0;
    for alphabet in used.alphabets() {
        let mut total = 0usize;
        let mut sum = 0.0;
        for &symbol in alphabet {
            let symbol = usize::from(symbol);
            let frequency = after[symbol] - before[symbol] + usize::from(symbol == 256);
            if frequency != 0 {
                total += frequency;
                sum += self_information(frequency);
            }
        }
        if total == 0 {
            continue;
        }
        symbols += self_information(total) - sum;
        // Rounded down on both sides, which is near enough to price the table.
        let total_bits = total.ilog2();
        for &symbol in alphabet {
            let symbol = usize::from(symbol);
            let frequency = after[symbol] - before[symbol] + usize::from(symbol == 256);
            if frequency != 0 {
                table[symbol] = (total_bits - frequency.ilog2()).clamp(1, 15) as u8;
            }
        }
    }
    (4 * LEVEL_COUNT + table_level_bit_cost(&table) + FRAMING_BITS) as f64 + symbols
}

/// The symbols a parse uses, in order, and where each alphabet starts.
struct Used {
    symbols: Vec<u16>,
    /// Where each of [`ALPHABETS`] starts in `symbols`, and where the last ends.
    bounds: [usize; ALPHABETS.len() + 1],
}

impl Used {
    fn new(first: &[usize; TABLE_COUNT], last: &[usize; TABLE_COUNT]) -> Self {
        let mut symbols = Vec::new();
        let mut bounds = [0; ALPHABETS.len() + 1];
        for (index, alphabet) in ALPHABETS.into_iter().enumerate() {
            bounds[index] = symbols.len();
            symbols.extend(
                alphabet
                    .filter(|&symbol| symbol == 256 || last[symbol] != first[symbol])
                    .map(|symbol| symbol as u16),
            );
        }
        bounds[ALPHABETS.len()] = symbols.len();
        Self { symbols, bounds }
    }

    fn alphabets(&self) -> impl Iterator<Item = &[u16]> {
        self.bounds
            .windows(2)
            .map(|bounds| &self.symbols[bounds[0]..bounds[1]])
    }
}

/// `n log2 n`, from a table for the counts most symbols in a block have.
fn self_information(count: usize) -> f64 {
    const SMALL: usize = 4096;
    static TABLE: std::sync::OnceLock<Box<[f64]>> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        (0..SMALL)
            .map(|count| match count {
                0 => 0.0,
                _ => count as f64 * (count as f64).log2(),
            })
            .collect()
    });
    match table.get(count) {
        Some(&bits) => bits,
        None => count as f64 * (count as f64).log2(),
    }
}

/// The bits one block coding the symbols between two marks spends, leaving out
/// the extra bits its matches carry, which are the same however it is cut.
fn priced(before: &[usize; TABLE_COUNT], after: &[usize; TABLE_COUNT]) -> usize {
    let mut frequencies = [0usize; TABLE_COUNT];
    for (frequency, (after, before)) in frequencies.iter_mut().zip(after.iter().zip(before)) {
        *frequency = after - before;
    }
    frequencies[256] += 1;
    let table = table_lengths_for_frequencies(frequencies);
    let symbols: usize = frequencies
        .iter()
        .zip(&table)
        .map(|(&frequency, &bits)| frequency * usize::from(bits))
        .sum();
    4 * LEVEL_COUNT
        + level_tokens_bit_cost(&encode_table_level_tokens(&table))
        + FRAMING_BITS
        + symbols
}

#[cfg(test)]
#[path = "block_split_tests.rs"]
mod tests;
