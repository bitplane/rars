//! The shortest-path parse the top two levels spend their time on.
//!
//! The lazy parse commits to a match the moment it scores well on a fixed
//! guess at what tokens cost, with a one byte look ahead as its only way out.
//! This asks instead what the cheapest route through the block is, priced by
//! the code lengths the lazy parse's own tokens produced, and then again by
//! what that route produced. Each position keeps the repeat offsets of the
//! cheapest route that reached it, which is the approximation LZMA's optimal
//! parser makes and the RAR 2.0 one here makes too: carrying every reachable
//! repeat state would multiply the search out of reach.
//!
//! The lazy tokens stay in the running. A block is coded with whichever set
//! prices smaller under its own tables, so this can only shrink a block.
use super::*;

/// The most positions one parse prices at once.
///
/// The writer's blocks are this size, so a block is one parse. A caller with
/// larger blocks gets the lazy parse unchanged rather than an unbounded node
/// array.
const OPTIMAL_SPAN: usize = 64 * 1024;

/// What one block's shortest-path parse holds: a node per position, the
/// matches found at each, and the two-byte table.
///
/// Peak RSS coding a 4 MiB stripped binary on six threads was 23 MB above
/// level 3's, about 4 MB a parse. Charged per block that may parse at once,
/// with room for one where every position keeps all its matches.
pub(crate) const OPTIMAL_PARSE_WORKSPACE: u64 = 8 * 1024 * 1024;

/// A run reaching this far is taken without pricing the positions it covers.
const NICE_LENGTH: usize = MAX_ENCODER_MATCH_LENGTH;

/// Matches kept per position: the longest, since the nearer short ones are
/// usually covered by a repeat offset or the literal edge anyway.
const MAX_FOUND: usize = 16;

/// What a symbol the previous pass never coded is assumed to cost.
///
/// The lazy parse never emits a two-byte match, so the first priced pass sees
/// no code for any of them, and whatever this says is what decides whether it
/// tries them at all. Pricing them as dear as the longest code means it never
/// does, and each later pass only creeps towards them. Measured on 4 MiB of a
/// stripped binary at 128 candidates, two passes, packed bytes:
///
/// ```text
/// absent bits        4          6          8         11         13         15
/// packed     1,727,247  1,727,618  1,730,083  1,733,284  1,738,607  1,741,882
/// ```
///
/// Below 8 the binary gains a little more and text starts to lose, so 8.
const ABSENT_BITS: u32 = 8;

/// One block's matches, found once and shared by every range of it priced.
pub(super) struct Refiner {
    start: usize,
    found: Found,
}

impl Refiner {
    /// `None` for a block wider than one parse prices, which keeps the lazy
    /// parse rather than holding a node per byte of it.
    pub(super) fn new<C: Candidates>(
        data: &[u8],
        start: usize,
        end: usize,
        finder: &C,
        options: EncodeOptions,
    ) -> Option<Self> {
        if end <= start || end - start > OPTIMAL_SPAN {
            return None;
        }
        Some(Self {
            start,
            found: Found::collect(data, start, end, finder, options),
        })
    }

    /// Reparses `start..end`, a range of the block coming in with the repeat
    /// offsets of `state`, up to `optimal_parse_passes` times, and returns
    /// whichever set of tokens codes smallest.
    ///
    /// `tokens` were parsed coming in with `parsed_from`. They price the first
    /// pass, and stay in the running only if they still code from `state`.
    /// Returns the tokens kept and the bits they code to.
    pub(super) fn refine(
        &self,
        data: &[u8],
        (start, end): (usize, usize),
        options: EncodeOptions,
        tokens: Vec<EncodeToken>,
        (parsed_from, state): (EncoderMatchState, EncoderMatchState),
    ) -> Result<(Vec<EncodeToken>, usize)> {
        let found = self.found.from(start - self.start);
        let mut best_table = table_lengths_for_tokens(&tokens, parsed_from, 0)?;
        let mut best_bits = usize::MAX;
        if let Ok(table) = table_lengths_for_tokens(&tokens, state, 0) {
            best_bits = block_bits(&tokens, &table, state)?;
            best_table = table;
        }
        let mut best = tokens;
        for _ in 0..options.optimal_parse_passes {
            let prices = Prices::new(&best_table);
            let next = shortest_path(data, start, end, &found, &prices, options, state);
            let table = table_lengths_for_tokens(&next, state, 0)?;
            let bits = block_bits(&next, &table, state)?;
            if bits >= best_bits {
                break;
            }
            best = next;
            best_table = table;
            best_bits = bits;
        }
        Ok((best, best_bits))
    }
}

/// What these tokens code to as a block with tables of their own.
pub(super) fn priced_bits(tokens: &[EncodeToken], state: EncoderMatchState) -> Result<usize> {
    block_bits(tokens, &table_lengths_for_tokens(tokens, state, 0)?, state)
}

/// What a block of these tokens codes to under `table`, header included.
fn block_bits(
    tokens: &[EncodeToken],
    table: &[u8; TABLE_COUNT],
    mut state: EncoderMatchState,
) -> Result<usize> {
    let prices = Prices::new(table);
    let mut bits = 4 * LEVEL_COUNT + level_tokens_bit_cost(&encode_table_level_tokens(table));
    for token in tokens {
        bits += match *token {
            EncodeToken::Literal(byte) => prices.literal(byte),
            EncodeToken::Match { length, offset } => {
                let (length, offset) = (length as usize, offset as usize);
                let price = prices.of(state.encode_match(length, offset)?);
                state.remember(length, offset);
                price
            }
        } as usize;
    }
    Ok(bits)
}

/// Bits per symbol under one block's tables.
struct Prices {
    main: [u8; MAIN_COUNT],
    offsets: [u8; OFFSET_COUNT],
    low_offsets: [u8; LOW_OFFSET_COUNT],
    lengths: [u8; LENGTH_COUNT],
}

impl Prices {
    fn new(table: &[u8; TABLE_COUNT]) -> Self {
        let mut prices = Self {
            main: [0; MAIN_COUNT],
            offsets: [0; OFFSET_COUNT],
            low_offsets: [0; LOW_OFFSET_COUNT],
            lengths: [0; LENGTH_COUNT],
        };
        let (main, rest) = table.split_at(MAIN_COUNT);
        let (offsets, rest) = rest.split_at(OFFSET_COUNT);
        let (low_offsets, lengths) = rest.split_at(LOW_OFFSET_COUNT);
        prices.main.copy_from_slice(main);
        prices.offsets.copy_from_slice(offsets);
        prices.low_offsets.copy_from_slice(low_offsets);
        prices.lengths.copy_from_slice(lengths);
        prices
    }

    fn bits(length: u8) -> u32 {
        match length {
            0 => ABSENT_BITS,
            bits => u32::from(bits),
        }
    }

    fn literal(&self, byte: u8) -> u32 {
        Self::bits(self.main[usize::from(byte)])
    }

    fn of(&self, encoded: EncodedMatch) -> u32 {
        match encoded {
            EncodedMatch::LastLengthRepeat => Self::bits(self.main[258]),
            EncodedMatch::RepeatOffset {
                index, length_slot, ..
            } => {
                Self::bits(self.main[259 + index])
                    + Self::bits(self.lengths[length_slot])
                    + u32::from(LENGTH_BITS[length_slot])
            }
            EncodedMatch::Short { slot, .. } => {
                Self::bits(self.main[263 + slot]) + u32::from(SHORT_BITS[slot])
            }
            EncodedMatch::Fresh {
                length_slot,
                offset_slot,
                offset_extra,
                ..
            } => {
                let offset_bits = if offset_slot > 9 {
                    u32::from(OFFSET_BITS[offset_slot].saturating_sub(4))
                        + Self::bits(self.low_offsets[offset_extra & 0x0f])
                } else {
                    u32::from(OFFSET_BITS[offset_slot])
                };
                Self::bits(self.main[271 + length_slot])
                    + u32::from(LENGTH_BITS[length_slot])
                    + Self::bits(self.offsets[offset_slot])
                    + offset_bits
            }
        }
    }
}

/// A length and an offset in four bytes, since there is one per match found.
#[derive(Debug, Clone, Copy)]
struct FoundMatch(u32);

impl FoundMatch {
    const LENGTH_BITS: u32 = 9;

    fn new(length: usize, offset: usize) -> Self {
        debug_assert!(length <= MAX_ENCODER_MATCH_LENGTH && offset <= MAX_HISTORY);
        Self(((offset as u32) << Self::LENGTH_BITS) | length as u32)
    }

    fn length(self) -> usize {
        (self.0 & ((1 << Self::LENGTH_BITS) - 1)) as usize
    }

    fn offset(self) -> usize {
        (self.0 >> Self::LENGTH_BITS) as usize
    }
}

/// The matches at each position, each longer and further back than the last.
///
/// Matches do not depend on prices, so every priced pass shares one search.
struct Found {
    counts: Vec<u8>,
    runs: Vec<FoundMatch>,
}

/// The matches from some position of a block on.
struct FoundFrom<'a> {
    counts: &'a [u8],
    runs: &'a [FoundMatch],
}

impl Found {
    fn from(&self, skip: usize) -> FoundFrom<'_> {
        let runs: usize = self.counts[..skip].iter().copied().map(usize::from).sum();
        FoundFrom {
            counts: &self.counts[skip..],
            runs: &self.runs[runs..],
        }
    }

    fn collect<C: Candidates>(
        data: &[u8],
        start: usize,
        end: usize,
        finder: &C,
        options: EncodeOptions,
    ) -> Self {
        let mut found = Self {
            counts: Vec::with_capacity(end - start),
            runs: Vec::new(),
        };
        let mut committed_through = start;
        for pos in start..end {
            let before = found.runs.len();
            let cap = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
            let max_offset = pos.min(options.max_match_distance).min(MAX_HISTORY);
            let mut longest = 0usize;
            if pos >= committed_through && cap >= 4 && options.max_match_candidates != 0 {
                // A match must beat three bytes, the most a probe of byte three
                // can rule out before the whole match is measured.
                let mut best = 3usize;
                let mut checked = 0usize;
                let mut candidate = finder.before(pos);
                while candidate != match_finder::NO_POSITION {
                    let offset = pos - candidate;
                    if offset > max_offset {
                        break;
                    }
                    checked += 1;
                    if data[candidate + best] == data[pos + best] {
                        let length = match_length(data, pos, offset, cap);
                        if length > best {
                            best = length;
                            found.runs.push(FoundMatch::new(length, offset));
                            if length == cap {
                                break;
                            }
                        }
                    }
                    if checked >= options.max_match_candidates {
                        break;
                    }
                    candidate = finder.previous(candidate);
                }
                longest = best;
            }
            let count = found.runs.len() - before;
            if count > MAX_FOUND {
                found.runs.drain(before..before + count - MAX_FOUND);
            }
            found.counts.push((found.runs.len() - before) as u8);
            if longest >= NICE_LENGTH.min(cap) && found.runs.len() > before {
                committed_through = pos + longest;
            }
        }
        found
    }
}

/// The repeat state a route leaves behind, in half the bytes of the coder's.
#[derive(Debug, Clone, Copy, Default)]
struct RouteState {
    old_offsets: [u32; 4],
    last_offset: u32,
    last_length: u32,
}

impl RouteState {
    fn expand(self) -> EncoderMatchState {
        EncoderMatchState {
            old_offsets: self.old_offsets.map(|offset| offset as usize),
            last_offset: self.last_offset as usize,
            last_length: self.last_length as usize,
        }
    }

    fn of(state: &EncoderMatchState) -> Self {
        Self {
            old_offsets: state.old_offsets.map(|offset| offset as u32),
            last_offset: state.last_offset as u32,
            last_length: state.last_length as u32,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Node {
    cost: u32,
    /// The token that reached this node; an offset of zero is a literal.
    length: u16,
    offset: u32,
    state: RouteState,
}

impl Node {
    const UNREACHED: Self = Self {
        cost: u32::MAX,
        length: 0,
        offset: 0,
        state: RouteState {
            old_offsets: [0; 4],
            last_offset: 0,
            last_length: 0,
        },
    };
}

/// Lengths worth trying for a match, from just past `covered` to `longest`.
///
/// Every length inside a length slot is priced the same, so only the longest
/// length in each slot can be cheapest to reach its end, plus the longest
/// match found. `base` is what the slot table counts from.
fn candidate_lengths(covered: usize, longest: usize, base: usize, out: &mut Vec<usize>) {
    out.clear();
    for slot in 0..LENGTH_COUNT {
        let widest = LENGTH_BASES[slot] + (1usize << LENGTH_BITS[slot]) - 1 + base;
        if widest > covered && widest <= longest {
            out.push(widest);
        }
    }
    if longest > covered {
        out.push(longest);
    }
    out.sort_unstable();
    out.dedup();
}

/// The cheapest route through `start..end` under `prices`.
fn shortest_path(
    data: &[u8],
    start: usize,
    end: usize,
    found: &FoundFrom<'_>,
    prices: &Prices,
    options: EncodeOptions,
    state: EncoderMatchState,
) -> Vec<EncodeToken> {
    let span = end - start;
    let mut nodes = vec![Node::UNREACHED; span + 1];
    nodes[0].cost = 0;
    nodes[0].state = RouteState::of(&state);
    let mut lengths = Vec::new();
    let mut next_run = 0usize;
    let mut committed_through = 0usize;
    // The newest position of each two-byte pair, for the short-offset tokens.
    let mut pairs = vec![u32::MAX; 1 << 16];
    let pair = |pos: usize| usize::from(u16::from_le_bytes([data[pos], data[pos + 1]]));
    for pos in start.saturating_sub(256)..start {
        pairs[pair(pos)] = pos as u32;
    }

    for index in 0..span {
        let pos = start + index;
        let runs = &found.runs[next_run..next_run + usize::from(found.counts[index])];
        next_run += runs.len();
        let nearest_pair = if pos + 1 < data.len() {
            let slot = &mut pairs[pair(pos)];
            let previous = *slot;
            *slot = pos as u32;
            previous
        } else {
            u32::MAX
        };
        let here = nodes[index];
        if index < committed_through || here.cost == u32::MAX {
            continue;
        }
        let state = here.state.expand();
        let cap = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        let max_offset = pos.min(options.max_match_distance).min(MAX_HISTORY);
        let relax = |nodes: &mut [Node], length: usize, offset: usize, price: u32| {
            let cost = here.cost.saturating_add(price);
            let node = &mut nodes[index + length];
            if cost < node.cost {
                let mut next = state;
                if offset != 0 {
                    next.remember(length, offset);
                }
                *node = Node {
                    cost,
                    length: length as u16,
                    offset: offset as u32,
                    state: RouteState::of(&next),
                };
            }
        };

        relax(&mut nodes, 1, 0, prices.literal(data[pos]));
        let mut longest = 0usize;

        for (rep, &offset) in state.old_offsets.iter().enumerate() {
            if offset == 0
                || offset > max_offset
                || state.old_offsets[..rep].contains(&offset)
                || cap < 2
            {
                continue;
            }
            let reach = match_length(data, pos, offset, cap);
            if reach < 2 {
                continue;
            }
            candidate_lengths(1, reach, 2, &mut lengths);
            if offset == state.last_offset && state.last_length != 0 && state.last_length <= reach {
                lengths.push(state.last_length);
            }
            for &length in &lengths {
                if let Ok(encoded) = state.encode_match(length, offset) {
                    relax(&mut nodes, length, offset, prices.of(encoded));
                    longest = longest.max(length);
                }
            }
        }

        if cap >= 2 && nearest_pair != u32::MAX {
            let offset = pos - nearest_pair as usize;
            if offset <= 256 && offset <= max_offset {
                if let Ok(encoded) = state.encode_match(2, offset) {
                    relax(&mut nodes, 2, offset, prices.of(encoded));
                }
            }
        }

        let mut covered = 2usize;
        for run in runs {
            let (reach, offset) = (run.length().min(cap), run.offset());
            candidate_lengths(
                covered,
                reach,
                3 + match_length_adjustment(offset),
                &mut lengths,
            );
            for &length in &lengths {
                if let Ok(encoded) = state.encode_match(length, offset) {
                    relax(&mut nodes, length, offset, prices.of(encoded));
                    longest = longest.max(length);
                }
            }
            covered = covered.max(reach);
        }

        if longest >= NICE_LENGTH.min(cap) && longest > 1 {
            committed_through = index + longest;
        }
    }

    let mut tokens = Vec::new();
    let mut at = span;
    while at > 0 {
        let node = nodes[at];
        if node.offset == 0 {
            tokens.push(EncodeToken::Literal(data[start + at - 1]));
            at -= 1;
        } else {
            tokens.push(EncodeToken::Match {
                length: u32::from(node.length),
                offset: node.offset,
            });
            at -= usize::from(node.length);
        }
    }
    tokens.reverse();
    tokens
}

#[cfg(test)]
#[path = "optimal_parse_tests.rs"]
mod tests;
