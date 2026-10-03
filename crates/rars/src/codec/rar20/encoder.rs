//! RAR20 member encoding and bit emission.
use super::super::{huffman, match_finder};
use super::*;

const MAX_ENCODER_MATCH_OFFSET: usize = MAX_HISTORY;

const MAX_ENCODER_MATCH_LENGTH: usize = 258;

const MAX_MATCH_CANDIDATES: usize = 256;

type Rar20MatchFinder = match_finder::MatchFinder<3>;

pub fn unpack20_encode_literals(input: &[u8]) -> Result<Vec<u8>> {
    unpack20_encode_literals_with_options(input, EncodeOptions::default())
}

pub fn unpack20_encode_literals_with_options(
    input: &[u8],
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member(input, &[], None, options, None)
}

pub fn unpack20_encode_auto(input: &[u8]) -> Result<Vec<u8>> {
    unpack20_encode_auto_with_options(input, EncodeOptions::default())
}

pub fn unpack20_encode_auto_with_options(input: &[u8], options: EncodeOptions) -> Result<Vec<u8>> {
    let lz = unpack20_encode_literals_with_options(input, options)?;
    let mut best = lz;
    if options.try_audio {
        for channels in 1..=MAX_CHANNELS {
            if input.len() < channels * 64 {
                continue;
            }
            let audio = encode_audio_member(input, channels)?;
            if audio.len() < best.len() {
                best = audio;
            }
        }
    }
    Ok(best)
}

pub(crate) fn unpack20_encode_auto_with_options_and_progress(
    input: &[u8],
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    let mut best = encode_member(input, &[], None, options, Some(progress))?;
    if options.try_audio {
        for channels in 1..=MAX_CHANNELS {
            if input.len() < channels * 64 {
                continue;
            }
            let audio = encode_audio_member(input, channels)?;
            if audio.len() < best.len() {
                best = audio;
            }
        }
    }
    Ok(best)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeOptions {
    pub max_match_candidates: usize,
    pub max_match_distance: usize,
    pub lazy_matching: bool,
    pub lazy_lookahead: usize,
    /// Parse by shortest path rather than greedily. Costs several times the
    /// encode time, so it belongs at the top of the level ladder.
    pub optimal_parse: bool,
    pub try_audio: bool,
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            lazy_matching: false,
            lazy_lookahead: 1,
            optimal_parse: false,
            try_audio: true,
        }
    }

    pub const fn with_max_match_distance(mut self, distance: usize) -> Self {
        self.max_match_distance = if distance > MAX_ENCODER_MATCH_OFFSET {
            MAX_ENCODER_MATCH_OFFSET
        } else {
            distance
        };
        self
    }

    pub const fn with_lazy_matching(mut self, enabled: bool) -> Self {
        self.lazy_matching = enabled;
        self
    }

    pub const fn with_optimal_parse(mut self, enabled: bool) -> Self {
        self.optimal_parse = enabled;
        self
    }

    pub const fn with_lazy_lookahead(mut self, bytes: usize) -> Self {
        self.lazy_lookahead = bytes;
        self
    }

    pub const fn with_try_audio(mut self, enabled: bool) -> Self {
        self.try_audio = enabled;
        self
    }

    const fn constrained(mut self) -> Self {
        if self.max_match_distance > MAX_ENCODER_MATCH_OFFSET {
            self.max_match_distance = MAX_ENCODER_MATCH_OFFSET;
        }
        self
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new(MAX_MATCH_CANDIDATES)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Unpack20Encoder {
    history: Vec<u8>,
    table: Option<FixedEncodeTable>,
    options: EncodeOptions,
}

impl Unpack20Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            history: Vec::new(),
            table: None,
            options: options.constrained(),
        }
    }

    pub fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.encode_member_inner(input, None)
    }

    pub(crate) fn encode_member_with_progress(
        &mut self,
        input: &[u8],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        self.encode_member_inner(input, Some(progress))
    }

    fn encode_member_inner(
        &mut self,
        input: &[u8],
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let table = match self.table {
            Some(table) => table,
            None => {
                let table = FixedEncodeTable::new()?;
                self.table = Some(table);
                table
            }
        };
        let packed = encode_member(input, &self.history, Some(table), self.options, progress)?;
        self.remember(input);
        Ok(packed)
    }

    fn remember(&mut self, input: &[u8]) {
        self.history.extend_from_slice(input);
        let keep_from = self
            .history
            .len()
            .saturating_sub(self.options.max_match_distance);
        if keep_from != 0 {
            self.history.drain(..keep_from);
        }
    }
}

fn encode_member(
    input: &[u8],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    // The public field can be assigned directly, bypassing the builder clamp.
    let options = options.constrained();

    let tokens = match progress.as_mut() {
        Some(report) => {
            encode_tokens_with_progress(input, history, options, None, Some(&mut **report))?
        }
        None => encode_tokens_with_progress(input, history, options, None, None)?,
    };
    let table_lengths = table_lengths_for_tokens(&tokens, fixed_table)?;
    let packed = encode_member_with_tables(&tokens, history, fixed_table, &table_lengths)?;
    if fixed_table.is_some() {
        return Ok(packed);
    }

    // Re-parse against the prices the first pass implies, then again against
    // the prices that produced. A greedy parse has converged by the first
    // re-parse and a second buys 0.02%, but the shortest-path parse is far more
    // sensitive to its prices and a second pass is worth 0.12% to it.
    let refinements = if options.optimal_parse { 2 } else { 1 };
    let mut best_tokens = tokens;
    let mut best_table = table_lengths;
    let mut best_packed = packed;
    for _ in 0..refinements {
        let cost_model = CostModel::new(&best_table);
        let next_tokens = match progress.as_mut() {
            Some(report) => encode_tokens_with_progress(
                input,
                history,
                options,
                Some(&cost_model),
                Some(&mut **report),
            )?,
            None => encode_tokens_with_progress(input, history, options, Some(&cost_model), None)?,
        };
        if next_tokens == best_tokens {
            break;
        }
        let next_table = table_lengths_for_tokens(&next_tokens, fixed_table)?;
        let next_packed =
            encode_member_with_tables(&next_tokens, history, fixed_table, &next_table)?;
        if next_packed.len() >= best_packed.len() {
            break;
        }
        best_tokens = next_tokens;
        best_table = next_table;
        best_packed = next_packed;
    }
    Ok(best_packed)
}

fn table_lengths_for_tokens(
    tokens: &[EncodeToken],
    fixed_table: Option<FixedEncodeTable>,
) -> Result<[u8; TABLE_COUNT]> {
    let mut main_frequencies = [0usize; MAIN_COUNT];
    let mut offset_frequencies = [0usize; OFFSET_COUNT];
    let mut length_frequencies = [0usize; LENGTH_COUNT];
    for token in tokens {
        match *token {
            EncodeToken::Literal(byte) => main_frequencies[byte as usize] += 1,
            EncodeToken::RepeatLast => main_frequencies[256] += 1,
            EncodeToken::OldOffset {
                index,
                length,
                offset,
            } => {
                main_frequencies[257 + index] += 1;
                let (slot, _) = old_length_slot_for_match(length, offset)?;
                length_frequencies[slot] += 1;
            }
            EncodeToken::ShortOffset { offset } => {
                let (slot, _) = short_slot_for_match(offset)?;
                main_frequencies[261 + slot] += 1;
            }
            EncodeToken::Match { length, offset } => {
                let encoded_length = length - match_length_adjustment(offset);
                let (slot, _) = length_slot_for_match(encoded_length)?;
                main_frequencies[270 + slot] += 1;
                let (offset_slot, _) = offset_slot_for_match(offset)?;
                offset_frequencies[offset_slot] += 1;
            }
        }
    }
    let mut table_lengths = [0u8; TABLE_COUNT];
    let literal_len = if let Some(table) = fixed_table {
        table.length
    } else {
        let main_symbol_count = main_frequencies
            .iter()
            .filter(|&&frequency| frequency != 0)
            .count()
            + offset_frequencies
                .iter()
                .filter(|&&frequency| frequency != 0)
                .count()
            + length_frequencies
                .iter()
                .filter(|&&frequency| frequency != 0)
                .count();
        literal_code_len(main_symbol_count)
    };

    if fixed_table.is_some() {
        for len in &mut table_lengths[..256] {
            *len = literal_len;
        }
        table_lengths[256] = literal_len;
        for len in &mut table_lengths[270..270 + LENGTH_COUNT] {
            *len = literal_len;
        }
        for len in &mut table_lengths[257..269] {
            *len = literal_len;
        }
        for len in &mut table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT] {
            *len = literal_len;
        }
        for len in &mut table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT] {
            *len = literal_len;
        }
    } else {
        table_lengths[..MAIN_COUNT]
            .copy_from_slice(&huffman::lengths_for_frequency_array(&main_frequencies, 15));
        table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT].copy_from_slice(
            &huffman::lengths_for_frequency_array(&offset_frequencies, 15),
        );
        table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT].copy_from_slice(
            &huffman::lengths_for_frequency_array(&length_frequencies, 15),
        );
    }
    Ok(table_lengths)
}

fn encode_member_with_tables(
    tokens: &[EncodeToken],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    table_lengths: &[u8; TABLE_COUNT],
) -> Result<Vec<u8>> {
    let level_tokens = encode_table_level_tokens(table_lengths);
    let level_lengths = level_code_lengths_for_tokens(&level_tokens);
    let level_codes = canonical_codes(&level_lengths)?;
    let main_codes = canonical_codes(&table_lengths[..MAIN_COUNT])?;

    let mut bits = BitWriter::default();
    if fixed_table.is_none() || history.is_empty() {
        bits.write_bits(0, 2); // LZ block, do not keep previous tables.
        for &len in &level_lengths {
            bits.write_bits(len as u32, 4);
        }
        for token in level_tokens {
            let code = level_codes[token.symbol].ok_or(Error::InvalidData(
                "RAR 2.0 encoder missing level Huffman code",
            ))?;
            bits.write_bits(code.code as u32, code.len);
            if token.extra_bits != 0 {
                bits.write_bits(token.extra_value as u32, token.extra_bits);
            }
        }
    }
    let offset_codes = canonical_codes(&table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT])?;
    let length_codes = canonical_codes(&table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT])?;
    for token in tokens {
        match *token {
            EncodeToken::Literal(byte) => {
                let code = main_codes[byte as usize].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing literal Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
            }
            EncodeToken::RepeatLast => {
                let code = main_codes[256].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing repeat-last Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
            }
            EncodeToken::OldOffset {
                index,
                length,
                offset,
            } => {
                let code = main_codes[257 + index].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing old-offset Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                let (slot, extra) = old_length_slot_for_match(length, offset)?;
                let length_code = length_codes[slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing old-offset length Huffman code",
                ))?;
                bits.write_bits(length_code.code as u32, length_code.len);
                if LENGTH_BITS[slot] != 0 {
                    bits.write_bits(extra as u32, LENGTH_BITS[slot]);
                }
            }
            EncodeToken::ShortOffset { offset } => {
                let (slot, extra) = short_slot_for_match(offset)?;
                let code = main_codes[261 + slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing short-offset Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                bits.write_bits(extra as u32, SHORT_BITS[slot]);
            }
            EncodeToken::Match { length, offset } => {
                let encoded_length = length - match_length_adjustment(offset);
                let (slot, extra) = length_slot_for_match(encoded_length)?;
                let code = main_codes[270 + slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing match Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                if LENGTH_BITS[slot] != 0 {
                    bits.write_bits(extra as u32, LENGTH_BITS[slot]);
                }
                let (offset_slot, offset_extra) = offset_slot_for_match(offset)?;
                let offset = offset_codes[offset_slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing offset Huffman code",
                ))?;
                bits.write_bits(offset.code as u32, offset.len);
                if OFFSET_BITS[offset_slot] != 0 {
                    bits.write_bits(offset_extra as u32, OFFSET_BITS[offset_slot]);
                }
            }
        }
    }
    Ok(bits.finish())
}

#[derive(Debug, Clone, Copy)]
struct FixedEncodeTable {
    length: u8,
}

impl FixedEncodeTable {
    fn new() -> Result<Self> {
        Ok(Self {
            length: literal_code_len(256 + LENGTH_COUNT + OFFSET_COUNT),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodeToken {
    Literal(u8),
    RepeatLast,
    OldOffset {
        index: usize,
        length: usize,
        offset: usize,
    },
    ShortOffset {
        offset: usize,
    },
    Match {
        length: usize,
        offset: usize,
    },
}

/// Lengths worth trying for a match at one position.
///
/// Every length inside a length slot is priced the same: the slot's Huffman
/// code plus its fixed extra bits, with the extra value itself costing nothing.
/// So the parse only needs the longest length in each slot, plus the longest
/// match found. That is at most twenty-nine candidates where trying every
/// length is up to two hundred and fifty-six, for 0.03% of packed size.
fn candidate_lengths(best_length: usize, offset: usize, out: &mut Vec<usize>) {
    out.clear();
    let adjustment = match_length_adjustment(offset);
    for slot in 0..LENGTH_COUNT {
        let widest = LENGTH_BASES[slot] + (1usize << LENGTH_BITS[slot]) - 1;
        let length = widest + 3 + adjustment;
        if (3..=best_length).contains(&length) {
            out.push(length);
        }
    }
    // Callers only pass matches of at least three bytes.
    out.push(best_length);
    out.sort_unstable();
    out.dedup();
}

/// Parse the member by shortest path, priced by the previous pass's tables.
///
/// The greedy parse commits to a match the moment it finds one, with a two
/// position lazy check as its only way out. This asks instead what the cheapest
/// route to the end of the member is, so a match that looks good on its own can
/// lose to one that leaves the positions after it cheaper. Worth about 0.9% on
/// the bench corpus, which is more than everything else tried put together.
///
/// One approximation. The four recent offsets depend on the route taken, and
/// carrying every reachable rep state would multiply the search out of reach.
/// Each position keeps the rep list of the cheapest route that reached it,
/// which is what LZMA's optimal parser does with the same justification.
fn encode_tokens_optimal(
    input: &[u8],
    start: usize,
    end: usize,
    finder: &mut Rar20MatchFinder,
    options: EncodeOptions,
    cost_model: &CostModel<'_>,
) -> Vec<EncodeToken> {
    const UNREACHED: u64 = u64::MAX / 4;
    let span = end - start;
    let mut cost = vec![UNREACHED; span + 1];
    let mut from = vec![0usize; span + 1];
    let mut token: Vec<Option<EncodeToken>> = vec![None; span + 1];
    let mut reps = vec![[0usize; 4]; span + 1];
    let mut lengths = Vec::new();
    cost[0] = 0;

    for index in 0..span {
        // Every position is reachable through the one-byte literal edge.
        let pos = start + index;
        let here = cost[index];
        let node_reps = reps[index];

        let mut relax = |next: usize, price: u64, what: EncodeToken, next_reps: [usize; 4]| {
            // Literal, fresh, old-offset and short-match edges all end within span.
            if here + price < cost[next] {
                cost[next] = here + price;
                from[next] = index;
                token[next] = Some(what);
                reps[next] = next_reps;
            }
        };

        relax(
            index + 1,
            cost_model.literal_bits(input, pos, 1) as u64,
            EncodeToken::Literal(input[pos]),
            node_reps,
        );

        let cap = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        if let Some((best_length, offset)) =
            best_match(input, pos, end, finder, options, Some(cost_model))
        {
            let mut pushed = node_reps;
            push_old_offset(&mut pushed, offset);
            candidate_lengths(best_length.min(cap), offset, &mut lengths);
            for &length in &lengths {
                let candidate = SelectedMatch::Fresh { length, offset };
                if let Some(price) = cost_model.selected_cost(candidate) {
                    relax(
                        index + length,
                        price as u64,
                        EncodeToken::Match { length, offset },
                        pushed,
                    );
                }
            }
        }

        for (rep_index, &offset) in node_reps.iter().enumerate() {
            let reach = match_run_length(input, pos, offset, cap);
            if reach < 3 {
                continue;
            }
            let mut pushed = node_reps;
            push_old_offset(&mut pushed, offset);
            candidate_lengths(reach, offset, &mut lengths);
            for &length in &lengths {
                let candidate = SelectedMatch::OldOffset {
                    index: rep_index,
                    length,
                    offset,
                };
                if let Some(price) = cost_model.selected_cost(candidate) {
                    relax(
                        index + length,
                        price as u64,
                        EncodeToken::OldOffset {
                            index: rep_index,
                            length,
                            offset,
                        },
                        pushed,
                    );
                }
            }
        }

        if let Some(SelectedMatch::ShortOffset { offset }) =
            best_short_offset_match(input, pos, end)
        {
            let slot = short_slot_index(offset);
            let price = usize::from(cost_model.main[261 + slot]) + usize::from(SHORT_BITS[slot]);
            let mut pushed = node_reps;
            push_old_offset(&mut pushed, offset);
            relax(
                index + 2,
                price as u64,
                EncodeToken::ShortOffset { offset },
                pushed,
            );
        }

        finder.insert(input, pos);
    }

    let mut out = Vec::new();
    let mut at = span;
    while at > 0 {
        let what = token[at].expect("every parse position has a literal edge");
        out.push(what);
        at = from[at];
    }
    out.reverse();
    out
}

/// How far the bytes at `pos` repeat the bytes `offset` back, up to `cap`.
fn match_run_length(input: &[u8], pos: usize, offset: usize, cap: usize) -> usize {
    if offset == 0 {
        return 0;
    }
    let mut length = 0;
    while length < cap && input[pos + length] == input[pos - offset + length] {
        length += 1;
    }
    length
}

fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    cost_model: Option<&CostModel>,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    let mut tokens = Vec::new();
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let mut combined = Vec::with_capacity(history.len() + input.len());
    combined.extend_from_slice(history);
    combined.extend_from_slice(input);
    let mut finder = Rar20MatchFinder::new(combined.len());
    for history_pos in 0..history.len() {
        finder.insert(&combined, history_pos);
    }

    if let Some(cost_model) = cost_model.filter(|_| options.optimal_parse) {
        let start = history.len();
        let end = combined.len();
        return Ok(encode_tokens_optimal(
            &combined,
            start,
            end,
            &mut finder,
            options,
            cost_model,
        ));
    }

    let mut pos = history.len();
    let end = combined.len();
    let mut last_match = None;
    let mut old_offsets = [0usize; 4];
    let mut next_report = 0usize;
    while pos < end {
        let selected = select_match(
            &combined,
            pos,
            end,
            &finder,
            options,
            &old_offsets,
            cost_model,
        );
        if let Some(selected) = selected {
            let lazy = LazyMatchContext {
                input: &combined,
                end,
                finder: &finder,
                options,
                old_offsets: &old_offsets,
                cost_model,
            };
            if should_lazy_emit_literal(pos, selected, lazy) {
                tokens.push(EncodeToken::Literal(combined[pos]));
                finder.insert(&combined, pos);
                pos += 1;
                continue;
            }
            let (length, offset) = match selected {
                SelectedMatch::Fresh { length, offset } => {
                    if last_match == Some((length, offset)) {
                        tokens.push(EncodeToken::RepeatLast);
                    } else {
                        tokens.push(EncodeToken::Match { length, offset });
                        last_match = Some((length, offset));
                    }
                    (length, offset)
                }
                SelectedMatch::OldOffset {
                    index,
                    length,
                    offset,
                } => {
                    if last_match == Some((length, offset)) {
                        tokens.push(EncodeToken::RepeatLast);
                    } else {
                        tokens.push(EncodeToken::OldOffset {
                            index,
                            length,
                            offset,
                        });
                        last_match = Some((length, offset));
                    }
                    (length, offset)
                }
                SelectedMatch::ShortOffset { offset } => {
                    let length = 2;
                    tokens.push(EncodeToken::ShortOffset { offset });
                    last_match = Some((length, offset));
                    (length, offset)
                }
            };
            push_old_offset(&mut old_offsets, offset);
            for history_pos in pos..pos + length {
                finder.insert(&combined, history_pos);
            }
            pos += length;
        } else {
            tokens.push(EncodeToken::Literal(combined[pos]));
            finder.insert(&combined, pos);
            pos += 1;
        }
        let consumed = pos.saturating_sub(history.len());
        if consumed >= next_report {
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(consumed))
            {
                return Err(Error::Cancelled);
            }
            next_report = consumed.saturating_add(1024 * 1024);
        }
    }
    if progress.is_some_and(|report| !report(input.len())) {
        return Err(Error::Cancelled);
    }
    Ok(tokens)
}

/// Stand-in price for a literal the current table has no code for.
const ABSENT_LITERAL_BITS: usize = 15;

#[derive(Debug, Clone, Copy)]
struct CostModel<'a> {
    main: &'a [u8],
    offsets: &'a [u8],
    lengths: &'a [u8],
}

impl<'a> CostModel<'a> {
    fn new(table_lengths: &'a [u8; TABLE_COUNT]) -> Self {
        Self {
            main: &table_lengths[..MAIN_COUNT],
            offsets: &table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT],
            lengths: &table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT],
        }
    }

    fn selected_cost(self, selected: SelectedMatch) -> Option<usize> {
        match selected {
            SelectedMatch::Fresh { length, offset } => {
                let encoded_length = length.checked_sub(match_length_adjustment(offset))?;
                let (length_slot, _) = length_slot_for_match(encoded_length).ok()?;
                let (offset_slot, _) = offset_slot_for_match(offset).ok()?;
                Some(
                    usize::from(self.main[270 + length_slot])
                        + usize::from(LENGTH_BITS[length_slot])
                        + usize::from(self.offsets[offset_slot])
                        + usize::from(OFFSET_BITS[offset_slot]),
                )
            }
            SelectedMatch::OldOffset {
                index,
                length,
                offset,
            } => {
                let (length_slot, _) = old_length_slot_for_match(length, offset).ok()?;
                Some(
                    usize::from(self.main[257 + index])
                        + usize::from(self.lengths[length_slot])
                        + usize::from(LENGTH_BITS[length_slot]),
                )
            }
            SelectedMatch::ShortOffset { offset } => {
                let (slot, _) = short_slot_for_match(offset).ok()?;
                Some(usize::from(self.main[261 + slot]) + usize::from(SHORT_BITS[slot]))
            }
        }
    }

    /// What these bytes cost spelled out one literal at a time, in bits.
    ///
    /// A symbol the previous pass never emitted as a literal has no code, so it
    /// cannot be spelled that way at all. Price it high rather than free.
    fn literal_bits(self, input: &[u8], pos: usize, length: usize) -> usize {
        input[pos..(pos + length).min(input.len())]
            .iter()
            .map(|&byte| match self.main[usize::from(byte)] {
                0 => ABSENT_LITERAL_BITS,
                bits => usize::from(bits),
            })
            .sum()
    }

    /// Bits saved by taking this match instead of the literals it covers.
    ///
    /// The literals are priced from the table rather than assumed to be eight
    /// bits each. On text they run nearer four, so a flat eight overstates what
    /// every match is worth by around half.
    fn selected_score(self, selected: SelectedMatch, input: &[u8], pos: usize) -> Option<isize> {
        let cost = self.selected_cost(selected)?;
        let saved = self.literal_bits(input, pos, selected.length());
        Some(saved as isize - cost as isize)
    }
}

#[derive(Debug, Clone, Copy)]
enum SelectedMatch {
    Fresh {
        length: usize,
        offset: usize,
    },
    OldOffset {
        index: usize,
        length: usize,
        offset: usize,
    },
    ShortOffset {
        offset: usize,
    },
}

impl SelectedMatch {
    fn length(self) -> usize {
        match self {
            SelectedMatch::Fresh { length, .. } | SelectedMatch::OldOffset { length, .. } => length,
            SelectedMatch::ShortOffset { .. } => 2,
        }
    }

    fn score(self) -> isize {
        let length_score = self.length() as isize * 8;
        let cost = match self {
            SelectedMatch::OldOffset { .. } | SelectedMatch::ShortOffset { .. } => 4,
            SelectedMatch::Fresh { offset, .. } => 8 + OFFSET_BITS[offset_slot_index(offset)],
        };
        length_score - isize::from(cost)
    }
}

fn select_match(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar20MatchFinder,
    options: EncodeOptions,
    old_offsets: &[usize; 4],
    cost_model: Option<&CostModel<'_>>,
) -> Option<SelectedMatch> {
    let fresh = best_match(input, pos, end, finder, options, cost_model);
    let old = best_old_offset_match(input, pos, end, old_offsets, cost_model);
    if let Some(cost_model) = cost_model {
        return [
            fresh.map(|(length, offset)| SelectedMatch::Fresh { length, offset }),
            old.map(|(index, length, offset)| SelectedMatch::OldOffset {
                index,
                length,
                offset,
            }),
            best_short_offset_match(input, pos, end),
        ]
        .into_iter()
        .flatten()
        .max_by_key(|&selected| {
            (
                cost_model
                    .selected_score(selected, input, pos)
                    .unwrap_or(isize::MIN),
                selected.length(),
            )
        });
    }

    match (fresh, old) {
        (Some((fresh_length, _)), Some((index, old_length, old_offset)))
            if old_length + 1 >= fresh_length =>
        {
            Some(SelectedMatch::OldOffset {
                index,
                length: old_length,
                offset: old_offset,
            })
        }
        (Some((length, offset)), _) => Some(SelectedMatch::Fresh { length, offset }),
        (None, Some((index, length, offset))) => Some(SelectedMatch::OldOffset {
            index,
            length,
            offset,
        }),
        (None, None) => best_short_offset_match(input, pos, end),
    }
}

struct LazyMatchContext<'a> {
    input: &'a [u8],
    end: usize,
    finder: &'a Rar20MatchFinder,
    options: EncodeOptions,
    old_offsets: &'a [usize; 4],
    cost_model: Option<&'a CostModel<'a>>,
}

fn should_lazy_emit_literal(
    pos: usize,
    current: SelectedMatch,
    context: LazyMatchContext<'_>,
) -> bool {
    if !context.options.lazy_matching {
        return false;
    }
    let lookahead = context.options.lazy_lookahead.max(1);
    (1..=lookahead)
        .take_while(|offset| pos + offset < context.end)
        .any(|offset| {
            select_match(
                context.input,
                pos + offset,
                context.end,
                context.finder,
                context.options,
                context.old_offsets,
                context.cost_model,
            )
            .is_some_and(|next| {
                let current_score = context
                    .cost_model
                    .and_then(|cost_model| cost_model.selected_score(current, context.input, pos))
                    .unwrap_or_else(|| current.score());
                let next_score = context
                    .cost_model
                    .and_then(|cost_model| {
                        cost_model.selected_score(next, context.input, pos + offset)
                    })
                    .unwrap_or_else(|| next.score());
                let skipped_literal_score = context
                    .cost_model
                    .map_or(offset as isize * 8, |cost_model| {
                        cost_model.literal_bits(context.input, pos, offset) as isize
                    });
                next_score > current_score + skipped_literal_score
            })
        })
}

fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar20MatchFinder,
    options: EncodeOptions,
    cost_model: Option<&CostModel<'_>>,
) -> Option<(usize, usize)> {
    let max_offset = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0 || max_offset == 0 || max_length < 3 {
        return None;
    }
    let mut best = None;
    let mut checked = 0usize;
    let mut candidate = finder.first(input, pos);
    while candidate != match_finder::NO_POSITION {
        // Callers search before inserting this position, so every candidate is older.
        let offset = pos - candidate;
        if offset > max_offset {
            break;
        }
        checked += 1;
        // Without a cost model, a candidate can only improve on the current
        // best when it matches at least one byte past the best length, so
        // probe that byte first. The cost-model pass may prefer shorter but
        // cheaper matches, so it must evaluate every candidate. Probing is
        // safe because a best match reaching `max_length` breaks the loop.
        let best_length = best.map_or(0, |(length, _)| length);
        let probe_ok = cost_model.is_some()
            || best_length == 0
            || input[candidate + best_length] == input[pos + best_length];
        if probe_ok {
            let length = super::super::fast::match_length(input, pos, offset, max_length);
            let encodable = length >= 3 + match_length_adjustment(offset);
            if encodable && is_better_fresh_match(cost_model, input, pos, length, offset, best) {
                best = Some((length, offset));
                if length == max_length {
                    break;
                }
            }
        }
        if checked >= options.max_match_candidates {
            break;
        }
        candidate = finder.previous(candidate);
    }
    best
}

fn offset_slot_index(offset: usize) -> usize {
    offset_slot_for_match(offset)
        .map(|(slot, _)| slot)
        .unwrap_or(OFFSET_BITS.len() - 1)
}

fn is_better_fresh_match(
    cost_model: Option<&CostModel<'_>>,
    input: &[u8],
    pos: usize,
    length: usize,
    offset: usize,
    best: Option<(usize, usize)>,
) -> bool {
    let Some((best_length, best_offset)) = best else {
        return true;
    };
    if let Some(cost_model) = cost_model {
        let candidate = SelectedMatch::Fresh { length, offset };
        let best = SelectedMatch::Fresh {
            length: best_length,
            offset: best_offset,
        };
        let candidate_score = cost_model
            .selected_score(candidate, input, pos)
            .unwrap_or(isize::MIN);
        let best_score = cost_model
            .selected_score(best, input, pos)
            .unwrap_or(isize::MIN);
        return candidate_score > best_score
            || (candidate_score == best_score && length > best_length);
    }
    // The hash chain visits nearest matches first, so an equal-length later
    // candidate cannot have a smaller offset.
    length > best_length
}

fn best_old_offset_match(
    input: &[u8],
    pos: usize,
    end: usize,
    old_offsets: &[usize; 4],
    cost_model: Option<&CostModel<'_>>,
) -> Option<(usize, usize, usize)> {
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    let mut best = None;
    for (index, &offset) in old_offsets.iter().enumerate() {
        if offset == 0 {
            continue;
        }
        let length = match_length_at_offset(input, pos, max_length, offset);
        if old_length_slot_for_match(length, offset).is_ok()
            && is_better_old_offset_match(cost_model, input, pos, index, length, offset, best)
        {
            best = Some((index, length, offset));
        }
    }
    best
}

fn is_better_old_offset_match(
    cost_model: Option<&CostModel<'_>>,
    input: &[u8],
    pos: usize,
    index: usize,
    length: usize,
    offset: usize,
    best: Option<(usize, usize, usize)>,
) -> bool {
    let Some((best_index, best_length, best_offset)) = best else {
        return true;
    };
    if let Some(cost_model) = cost_model {
        let candidate = SelectedMatch::OldOffset {
            index,
            length,
            offset,
        };
        let best = SelectedMatch::OldOffset {
            index: best_index,
            length: best_length,
            offset: best_offset,
        };
        let candidate_score = cost_model
            .selected_score(candidate, input, pos)
            .unwrap_or(isize::MIN);
        let best_score = cost_model
            .selected_score(best, input, pos)
            .unwrap_or(isize::MIN);
        return candidate_score > best_score
            || (candidate_score == best_score
                && (length > best_length || (length == best_length && offset < best_offset)));
    }
    length > best_length || (length == best_length && offset < best_offset)
}

fn best_short_offset_match(input: &[u8], pos: usize, end: usize) -> Option<SelectedMatch> {
    if end - pos < 2 {
        return None;
    }
    let max_offset = pos.min(256);
    (1..=max_offset)
        .find(|&offset| {
            input[pos] == input[pos - offset] && input[pos + 1] == input[pos + 1 - offset]
        })
        .map(|offset| SelectedMatch::ShortOffset { offset })
}

fn match_length_at_offset(input: &[u8], pos: usize, max_length: usize, offset: usize) -> usize {
    super::super::fast::match_length(input, pos, offset, max_length)
}

fn match_length_adjustment(offset: usize) -> usize {
    usize::from(offset >= 0x2000) + usize::from(offset >= 0x40000)
}

fn old_length_adjustment(offset: usize) -> usize {
    usize::from(offset >= 0x101) + usize::from(offset >= 0x2000) + usize::from(offset >= 0x40000)
}

fn push_old_offset(old_offsets: &mut [usize; 4], offset: usize) {
    old_offsets[3] = old_offsets[2];
    old_offsets[2] = old_offsets[1];
    old_offsets[1] = old_offsets[0];
    old_offsets[0] = offset;
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 3 {
        return Err(Error::InvalidData("RAR 2.0 match length is too short"));
    }
    if length > MAX_ENCODER_MATCH_LENGTH {
        return Err(Error::InvalidData("RAR 2.0 match length is too long"));
    }
    let adjusted = length - 3;
    let slot = LENGTH_BASES.partition_point(|&base| base <= adjusted) - 1;
    Ok((slot, adjusted - LENGTH_BASES[slot]))
}

fn old_length_slot_for_match(length: usize, offset: usize) -> Result<(usize, usize)> {
    let encoded = length
        .checked_sub(old_length_adjustment(offset))
        .ok_or(Error::InvalidData(
            "RAR 2.0 adjusted old-offset length underflows",
        ))?;
    if encoded < 2 {
        return Err(Error::InvalidData(
            "RAR 2.0 old-offset match length is too short",
        ));
    }
    let adjusted = encoded - 2;
    if adjusted > 255 {
        return Err(Error::InvalidData(
            "RAR 2.0 old-offset match length is too long",
        ));
    }
    let slot = LENGTH_BASES.partition_point(|&base| base <= adjusted) - 1;
    Ok((slot, adjusted - LENGTH_BASES[slot]))
}

fn offset_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 {
        return Err(Error::InvalidData("RAR 2.0 match offset is zero"));
    }
    if offset > MAX_ENCODER_MATCH_OFFSET {
        return Err(Error::InvalidData("RAR 2.0 match offset is too large"));
    }
    let adjusted = offset - 1;
    let slot = OFFSET_BASES.partition_point(|&base| base <= adjusted) - 1;
    Ok((slot, adjusted - OFFSET_BASES[slot]))
}

fn short_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 || offset > 256 {
        return Err(Error::InvalidData(
            "RAR 2.0 short match offset is out of range",
        ));
    }
    let adjusted = offset - 1;
    let slot = short_slot_index(offset);
    Ok((slot, adjusted - SHORT_BASES[slot]))
}

fn short_slot_index(offset: usize) -> usize {
    let adjusted = offset - 1;
    SHORT_BASES.partition_point(|&base| base <= adjusted) - 1
}

fn literal_code_len(symbol_count: usize) -> u8 {
    // A nonempty member always emits at least one token and there are at most
    // TABLE_COUNT distinct symbols, so the result fits in u8.
    let len = usize::BITS - (symbol_count - 1).leading_zeros();
    len.max(1) as u8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LevelToken {
    symbol: usize,
    extra_bits: u8,
    extra_value: u8,
}

impl LevelToken {
    const fn plain(symbol: usize) -> Self {
        Self {
            symbol,
            extra_bits: 0,
            extra_value: 0,
        }
    }

    const fn repeat_previous(count: usize) -> Self {
        Self {
            symbol: 16,
            extra_bits: 2,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_short(count: usize) -> Self {
        Self {
            symbol: 17,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_long(count: usize) -> Self {
        Self {
            symbol: 18,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }
}

fn encode_table_level_tokens(lengths: &[u8; TABLE_COUNT]) -> Vec<LevelToken> {
    encode_level_tokens(lengths)
}

fn encode_level_tokens(lengths: &[u8]) -> Vec<LevelToken> {
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    let mut previous = None;
    while pos < lengths.len() {
        let value = lengths[pos];
        let mut run = 1usize;
        while pos + run < lengths.len() && lengths[pos + run] == value {
            run += 1;
        }

        if value == 0 {
            emit_zero_level_run(&mut tokens, run);
            previous = Some(0);
            pos += run;
            continue;
        }

        if previous == Some(value) && run >= 3 {
            let mut remaining = run;
            while remaining != 0 {
                let chunk = remaining.min(6);
                if chunk >= 3 {
                    tokens.push(LevelToken::repeat_previous(chunk));
                    remaining -= chunk;
                } else {
                    tokens.extend(std::iter::repeat_n(
                        LevelToken::plain(value as usize),
                        chunk,
                    ));
                    remaining = 0;
                }
            }
            pos += run;
            continue;
        }

        tokens.push(LevelToken::plain(value as usize));
        previous = Some(value);
        pos += 1;
    }
    tokens
}

fn emit_zero_level_run(tokens: &mut Vec<LevelToken>, mut run: usize) {
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) {
                chunk -= 3;
            }
            tokens.push(LevelToken::zero_run_long(chunk));
            run -= chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens.push(LevelToken::zero_run_short(chunk));
            run -= chunk;
        } else {
            tokens.extend(std::iter::repeat_n(LevelToken::plain(0), run));
            break;
        }
    }
}

fn level_code_lengths_for_tokens(tokens: &[LevelToken]) -> [u8; LEVEL_COUNT] {
    let mut used = [false; LEVEL_COUNT];
    for token in tokens {
        used[token.symbol] = true;
    }
    level_code_lengths_for_used_symbols(used)
}

fn encode_audio_member(input: &[u8], channels: usize) -> Result<Vec<u8>> {
    if channels == 0 || channels > MAX_CHANNELS {
        return Err(Error::InvalidData("RAR 2.0 audio channel count is invalid"));
    }
    let deltas = audio_encode(input, channels);
    let mut levels = vec![0u8; AUDIO_COUNT * channels];
    for channel in 0..channels {
        let mut frequencies = [0usize; AUDIO_COUNT];
        for index in (channel..deltas.len()).step_by(channels) {
            frequencies[deltas[index] as usize] += 1;
        }
        let channel_lengths = huffman::lengths_for_frequency_array(&frequencies, 15);
        for (symbol, len) in channel_lengths.into_iter().enumerate() {
            levels[channel * AUDIO_COUNT + symbol] = len;
        }
    }

    let level_symbols = encode_audio_table_level_symbols(&levels);
    let level_lengths = level_code_lengths_for_symbols(&level_symbols);
    let level_codes = canonical_codes(&level_lengths)?;
    let mut bits = BitWriter::default();
    bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
    bits.write_bits((channels - 1) as u32, 2);
    for &len in &level_lengths {
        bits.write_bits(len as u32, 4);
    }
    for symbol in level_symbols {
        let code = level_codes[symbol].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing audio-level Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
        // Audio levels are emitted directly as 0..=15, without run symbols.
    }

    let audio_codes = (0..channels)
        .map(|channel| canonical_codes(&levels[channel * AUDIO_COUNT..(channel + 1) * AUDIO_COUNT]))
        .collect::<Result<Vec<_>>>()?;
    for (index, &delta) in deltas.iter().enumerate() {
        let channel = index % channels;
        let code = audio_codes[channel][delta as usize].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing audio Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
    }
    Ok(bits.finish())
}

fn encode_audio_table_level_symbols(levels: &[u8]) -> Vec<usize> {
    levels.iter().map(|&len| len as usize).collect()
}

fn level_code_lengths_for_symbols(symbols: &[usize]) -> [u8; LEVEL_COUNT] {
    let mut used = [false; LEVEL_COUNT];
    for &symbol in symbols {
        used[symbol] = true;
    }
    level_code_lengths_for_used_symbols(used)
}

fn level_code_lengths_for_used_symbols(used: [bool; LEVEL_COUNT]) -> [u8; LEVEL_COUNT] {
    let mut lengths = [0u8; LEVEL_COUNT];
    for (symbol, is_used) in used.into_iter().enumerate() {
        if is_used {
            lengths[symbol] = 1;
        }
    }
    huffman::assign_flat_complete_code(&mut lengths);
    lengths
}

fn audio_encode(input: &[u8], channels: usize) -> Vec<u8> {
    let mut states = [AudioState::default(); MAX_CHANNELS];
    let mut channel_delta = 0i32;
    let mut deltas = Vec::with_capacity(input.len());
    for (index, &byte) in input.iter().enumerate() {
        let channel = index % channels;
        let state = &mut states[channel];
        state.byte_count = state.byte_count.wrapping_add(1);
        state.d4 = state.d3;
        state.d3 = state.d2;
        state.d2 = state.last_delta - state.d1;
        state.d1 = state.last_delta;

        let predicted = 8 * state.last_char
            + state.k[0] * state.d1
            + state.k[1] * state.d2
            + state.k[2] * state.d3
            + state.k[3] * state.d4
            + state.k[4] * channel_delta;
        let predicted = (predicted >> 3) & 0xff;
        let delta = (predicted as u8).wrapping_sub(byte);

        let d = (delta as i8 as i32) << 3;
        state.dif[0] = state.dif[0].wrapping_add(d.unsigned_abs());
        state.dif[1] = state.dif[1].wrapping_add((d - state.d1).unsigned_abs());
        state.dif[2] = state.dif[2].wrapping_add((d + state.d1).unsigned_abs());
        state.dif[3] = state.dif[3].wrapping_add((d - state.d2).unsigned_abs());
        state.dif[4] = state.dif[4].wrapping_add((d + state.d2).unsigned_abs());
        state.dif[5] = state.dif[5].wrapping_add((d - state.d3).unsigned_abs());
        state.dif[6] = state.dif[6].wrapping_add((d + state.d3).unsigned_abs());
        state.dif[7] = state.dif[7].wrapping_add((d - state.d4).unsigned_abs());
        state.dif[8] = state.dif[8].wrapping_add((d + state.d4).unsigned_abs());
        state.dif[9] = state.dif[9].wrapping_add((d - channel_delta).unsigned_abs());
        state.dif[10] = state.dif[10].wrapping_add((d + channel_delta).unsigned_abs());

        channel_delta = (byte.wrapping_sub(state.last_char as u8)) as i8 as i32;
        state.last_delta = channel_delta;
        state.last_char = byte as i32;

        if state.byte_count & 0x1f == 0 {
            let mut min_dif = state.dif[0];
            let mut num_min_dif = 0usize;
            state.dif[0] = 0;
            for diff_index in 1..state.dif.len() {
                if state.dif[diff_index] < min_dif {
                    min_dif = state.dif[diff_index];
                    num_min_dif = diff_index;
                }
                state.dif[diff_index] = 0;
            }
            match num_min_dif {
                1 if state.k[0] >= -16 => state.k[0] -= 1,
                2 if state.k[0] < 16 => state.k[0] += 1,
                3 if state.k[1] >= -16 => state.k[1] -= 1,
                4 if state.k[1] < 16 => state.k[1] += 1,
                5 if state.k[2] >= -16 => state.k[2] -= 1,
                6 if state.k[2] < 16 => state.k[2] += 1,
                7 if state.k[3] >= -16 => state.k[3] -= 1,
                8 if state.k[3] < 16 => state.k[3] += 1,
                9 if state.k[4] >= -16 => state.k[4] -= 1,
                10 if state.k[4] < 16 => state.k[4] += 1,
                _ => {}
            }
        }

        deltas.push(delta);
    }
    deltas
}

#[derive(Debug, Clone, Copy)]
struct HuffmanCode {
    code: u16,
    len: u8,
}

fn canonical_codes(lengths: &[u8]) -> Result<Vec<Option<HuffmanCode>>> {
    let mut count = [0u16; 16];
    for &len in lengths {
        if len > 15 {
            return Err(Error::InvalidData("RAR 2.0 Huffman length is too large"));
        }
        if len != 0 {
            count[len as usize] += 1;
        }
    }
    validate_huffman_counts(&count)?;

    let mut next_code = [0u16; 16];
    let mut code = 0u16;
    for len in 1..=15 {
        code = (code + count[len - 1]) << 1;
        next_code[len] = code;
    }

    let mut codes = vec![None; lengths.len()];
    for (symbol, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let code = next_code[len as usize];
        next_code[len as usize] += 1;
        codes[symbol] = Some(HuffmanCode { code, len });
    }
    Ok(codes)
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn write_bits(&mut self, value: u32, count: u8) {
        super::super::fast::write_msb_bits(
            &mut self.bytes,
            &mut self.bit_pos,
            u64::from(value),
            usize::from(count),
        );
    }

    #[cfg(test)]
    fn write_bit(&mut self, bit: bool) {
        self.write_bits(u32::from(bit), 1);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
