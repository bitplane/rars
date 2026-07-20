use super::{huffman, Error, Result};
use std::io::{Read, Write};

const MAIN_COUNT: usize = 298;
const OFFSET_COUNT: usize = 48;
const LENGTH_COUNT: usize = 28;
const LEVEL_COUNT: usize = 19;
const TABLE_COUNT: usize = MAIN_COUNT + OFFSET_COUNT + LENGTH_COUNT;
const AUDIO_COUNT: usize = 257;
const MAX_CHANNELS: usize = 4;
const OLD_LEVEL_COUNT: usize = AUDIO_COUNT * MAX_CHANNELS;
const MAX_HISTORY: usize = 1024 * 1024;

const LENGTH_BASES: [usize; LENGTH_COUNT] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_BITS: [u8; LENGTH_COUNT] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const OFFSET_BASES: [usize; OFFSET_COUNT] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const OFFSET_BITS: [u8; OFFSET_COUNT] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
const SHORT_BASES: [usize; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];
const MAX_ENCODER_MATCH_OFFSET: usize = MAX_HISTORY;
const MAX_ENCODER_MATCH_LENGTH: usize = 258;
const MATCH_HASH_BUCKETS: usize = 4096;
const MAX_MATCH_CANDIDATES: usize = 256;

pub fn unpack20_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack20::new();
    decoder.decode_member(input, output_size)
}

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
    pub try_audio: bool,
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            lazy_matching: false,
            lazy_lookahead: 1,
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

    pub const fn with_lazy_lookahead(mut self, bytes: usize) -> Self {
        self.lazy_lookahead = bytes;
        self
    }

    pub const fn with_try_audio(mut self, enabled: bool) -> Self {
        self.try_audio = enabled;
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
            options,
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

    let cost_model = CostModel::new(&table_lengths);
    let refined_tokens = match progress.as_mut() {
        Some(report) => encode_tokens_with_progress(
            input,
            history,
            options,
            Some(&cost_model),
            Some(&mut **report),
        )?,
        None => encode_tokens_with_progress(input, history, options, Some(&cost_model), None)?,
    };
    if refined_tokens == tokens {
        return Ok(packed);
    }
    let refined_table_lengths = table_lengths_for_tokens(&refined_tokens, fixed_table)?;
    let refined_packed = encode_member_with_tables(
        &refined_tokens,
        history,
        fixed_table,
        &refined_table_lengths,
    )?;
    if refined_packed.len() < packed.len() {
        Ok(refined_packed)
    } else {
        Ok(packed)
    }
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
                let encoded_length = length.checked_sub(match_length_adjustment(offset)).ok_or(
                    Error::InvalidData("RAR 2.0 adjusted match length underflows"),
                )?;
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
        literal_code_len(main_symbol_count)?
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
            .copy_from_slice(&validated_lengths_for_frequencies(&main_frequencies, 15));
        table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT]
            .copy_from_slice(&validated_lengths_for_frequencies(&offset_frequencies, 15));
        table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT]
            .copy_from_slice(&validated_lengths_for_frequencies(&length_frequencies, 15));
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
                if SHORT_BITS[slot] != 0 {
                    bits.write_bits(extra as u32, SHORT_BITS[slot]);
                }
            }
            EncodeToken::Match { length, offset } => {
                let encoded_length = length.checked_sub(match_length_adjustment(offset)).ok_or(
                    Error::InvalidData("RAR 2.0 adjusted match length underflows"),
                )?;
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
            length: literal_code_len(256 + LENGTH_COUNT + OFFSET_COUNT)?,
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

#[cfg(test)]
fn encode_tokens(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    cost_model: Option<&CostModel>,
) -> Vec<EncodeToken> {
    encode_tokens_with_progress(input, history, options, cost_model, None)
        .expect("encoding without cancellation cannot be cancelled")
}

fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    cost_model: Option<&CostModel>,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    let mut tokens = Vec::new();
    let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let mut combined = Vec::with_capacity(history.len() + input.len());
    combined.extend_from_slice(history);
    combined.extend_from_slice(input);
    for history_pos in 0..history.len().saturating_sub(2) {
        insert_match_position(&combined, history_pos, &mut buckets);
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
            &buckets,
            options,
            &old_offsets,
            cost_model,
        );
        if let Some(selected) = selected {
            let lazy = LazyMatchContext {
                input: &combined,
                end,
                buckets: &buckets,
                options,
                old_offsets: &old_offsets,
                cost_model,
            };
            if should_lazy_emit_literal(pos, selected, lazy) {
                tokens.push(EncodeToken::Literal(combined[pos]));
                insert_match_position(&combined, pos, &mut buckets);
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
                insert_match_position(&combined, history_pos, &mut buckets);
            }
            pos += length;
        } else {
            tokens.push(EncodeToken::Literal(combined[pos]));
            insert_match_position(&combined, pos, &mut buckets);
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

    fn selected_score(self, selected: SelectedMatch) -> Option<isize> {
        let cost = self.selected_cost(selected)?;
        Some(selected.length() as isize * 8 - cost as isize)
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
    buckets: &[Vec<usize>],
    options: EncodeOptions,
    old_offsets: &[usize; 4],
    cost_model: Option<&CostModel<'_>>,
) -> Option<SelectedMatch> {
    let fresh = best_match(input, pos, end, buckets, options, cost_model)
        .map(|(length, offset)| SelectedMatch::Fresh { length, offset });
    let old = best_old_offset_match(input, pos, end, old_offsets, cost_model).map(
        |(index, length, offset)| SelectedMatch::OldOffset {
            index,
            length,
            offset,
        },
    );
    if let Some(cost_model) = cost_model {
        return [fresh, old, best_short_offset_match(input, pos, end)]
            .into_iter()
            .flatten()
            .max_by_key(|&selected| {
                (
                    cost_model.selected_score(selected).unwrap_or(isize::MIN),
                    selected.length(),
                )
            });
    }

    let fresh = fresh.and_then(|selected| match selected {
        SelectedMatch::Fresh { length, offset } => Some((length, offset)),
        _ => None,
    });
    let old = old.and_then(|selected| match selected {
        SelectedMatch::OldOffset {
            index,
            length,
            offset,
        } => Some((index, length, offset)),
        _ => None,
    });
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
    buckets: &'a [Vec<usize>],
    options: EncodeOptions,
    old_offsets: &'a [usize; 4],
    cost_model: Option<&'a CostModel<'a>>,
}

fn should_lazy_emit_literal(
    pos: usize,
    current: SelectedMatch,
    context: LazyMatchContext<'_>,
) -> bool {
    if !context.options.lazy_matching || pos + 1 >= context.end {
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
                context.buckets,
                context.options,
                context.old_offsets,
                context.cost_model,
            )
            .is_some_and(|next| {
                let current_score = context
                    .cost_model
                    .and_then(|cost_model| cost_model.selected_score(current))
                    .unwrap_or_else(|| current.score());
                let next_score = context
                    .cost_model
                    .and_then(|cost_model| cost_model.selected_score(next))
                    .unwrap_or_else(|| next.score());
                let skipped_literal_score = offset as isize * 8;
                next_score > current_score + skipped_literal_score
            })
        })
}

fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &[Vec<usize>],
    options: EncodeOptions,
    cost_model: Option<&CostModel<'_>>,
) -> Option<(usize, usize)> {
    let max_offset = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0
        || max_offset == 0
        || max_length < 3
        || pos + 2 >= input.len()
    {
        return None;
    }
    let bucket = &buckets[match_hash(input, pos)];
    let mut best = None;
    let mut checked = 0usize;
    for &candidate in bucket.iter().rev() {
        if candidate >= pos {
            continue;
        }
        let offset = pos - candidate;
        if offset > max_offset {
            break;
        }
        checked += 1;
        let mut length = 0usize;
        while length < max_length && input[pos + length] == input[pos + length - offset] {
            length += 1;
        }
        let encodable = length >= 3 + match_length_adjustment(offset);
        if encodable && is_better_fresh_match(cost_model, length, offset, best) {
            best = Some((length, offset));
            if length == max_length {
                break;
            }
        }
        if checked >= options.max_match_candidates {
            break;
        }
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
        let candidate_score = cost_model.selected_score(candidate).unwrap_or(isize::MIN);
        let best_score = cost_model.selected_score(best).unwrap_or(isize::MIN);
        return candidate_score > best_score
            || (candidate_score == best_score
                && (length > best_length || (length == best_length && offset < best_offset)));
    }
    length > best_length || (length == best_length && offset < best_offset)
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
        if offset == 0 || offset > pos {
            continue;
        }
        let length = match_length_at_offset(input, pos, max_length, offset);
        if old_length_slot_for_match(length, offset).is_ok()
            && is_better_old_offset_match(cost_model, index, length, offset, best)
        {
            best = Some((index, length, offset));
        }
    }
    best
}

fn is_better_old_offset_match(
    cost_model: Option<&CostModel<'_>>,
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
        let candidate_score = cost_model.selected_score(candidate).unwrap_or(isize::MIN);
        let best_score = cost_model.selected_score(best).unwrap_or(isize::MIN);
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
    let mut length = 0usize;
    while length < max_length && input[pos + length] == input[pos + length - offset] {
        length += 1;
    }
    length
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

fn insert_match_position(input: &[u8], pos: usize, buckets: &mut [Vec<usize>]) {
    if pos + 2 < input.len() {
        buckets[match_hash(input, pos)].push(pos);
    }
}

fn match_hash(input: &[u8], pos: usize) -> usize {
    let value =
        ((input[pos] as usize) << 8) ^ ((input[pos + 1] as usize) << 4) ^ input[pos + 2] as usize;
    value & (MATCH_HASH_BUCKETS - 1)
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 3 {
        return Err(Error::InvalidData("RAR 2.0 match length is too short"));
    }
    let adjusted = length - 3;
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData("RAR 2.0 match length is too long"))
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
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData(
        "RAR 2.0 old-offset match length is too long",
    ))
}

fn offset_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 {
        return Err(Error::InvalidData("RAR 2.0 match offset is zero"));
    }
    let adjusted = offset - 1;
    for (slot, &base) in OFFSET_BASES.iter().enumerate() {
        let extra_bits = OFFSET_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData("RAR 2.0 match offset is too large"))
}

fn short_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 || offset > 256 {
        return Err(Error::InvalidData(
            "RAR 2.0 short match offset is out of range",
        ));
    }
    let adjusted = offset - 1;
    for (slot, &base) in SHORT_BASES.iter().enumerate() {
        let extra_bits = SHORT_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData(
        "RAR 2.0 short match offset is out of range",
    ))
}

fn literal_code_len(symbol_count: usize) -> Result<u8> {
    if symbol_count == 0 {
        return Err(Error::InvalidData("RAR 2.0 encoder has no literal symbols"));
    }
    let len = usize::BITS - (symbol_count - 1).leading_zeros();
    u8::try_from(len.max(1)).map_err(|_| Error::InvalidData("RAR 2.0 literal table is too large"))
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
            if matches!(run - chunk, 1 | 2) && chunk >= 14 {
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

fn validated_lengths_for_frequencies<const N: usize>(
    frequencies: &[usize; N],
    max_bits: u8,
) -> [u8; N] {
    let mut lengths = [0u8; N];
    lengths.copy_from_slice(&huffman::lengths_for_frequencies(frequencies, max_bits));
    if canonical_codes(&lengths).is_ok() {
        return lengths;
    }

    lengths.copy_from_slice(&huffman::uniform_lengths_for_frequencies(frequencies));
    lengths
}

fn encode_audio_member(input: &[u8], channels: usize) -> Result<Vec<u8>> {
    if channels == 0 || channels > MAX_CHANNELS {
        return Err(Error::InvalidData("RAR 2.0 audio channel count is invalid"));
    }
    let deltas = audio_encode(input, channels)?;
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
        match symbol {
            17 => bits.write_bits(0, 3),
            18 => bits.write_bits(127, 7),
            _ => {}
        }
    }

    for channel in 0..channels {
        let table = &levels[channel * AUDIO_COUNT..(channel + 1) * AUDIO_COUNT];
        validate_audio_table(table)?;
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
    let used_count = used.iter().filter(|&&used| used).count();
    let len = huffman::bits_for_symbol_count(used_count);
    let mut lengths = [0u8; LEVEL_COUNT];
    for (symbol, is_used) in used.into_iter().enumerate() {
        if is_used {
            lengths[symbol] = len;
        }
    }
    lengths
}

fn validate_audio_table(lengths: &[u8]) -> Result<()> {
    let mut count = [0u16; 16];
    for &len in lengths {
        if len > 15 {
            return Err(Error::InvalidData("RAR 2.0 Huffman length is too large"));
        }
        if len != 0 {
            count[len as usize] += 1;
        }
    }
    validate_huffman_counts(&count)
}

fn audio_encode(input: &[u8], channels: usize) -> Result<Vec<u8>> {
    if channels == 0 || channels > MAX_CHANNELS {
        return Err(Error::InvalidData("RAR 2.0 audio channel count is invalid"));
    }
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
    Ok(deltas)
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

#[derive(Debug, Clone)]
pub struct Unpack20 {
    bits: BitReader,
    levels: [u8; OLD_LEVEL_COUNT],
    main: Huffman,
    offsets: Huffman,
    lengths: Huffman,
    audio_tables: [Huffman; MAX_CHANNELS],
    audio_block: bool,
    channels: usize,
    cur_channel: usize,
    audio: [AudioState; MAX_CHANNELS],
    channel_delta: i32,
    old_offsets: [usize; 4],
    last_offset: usize,
    last_length: usize,
    pending_match: Option<(usize, usize)>,
    in_block: bool,
    output: Vec<u8>,
    base_offset: usize,
}

impl Unpack20 {
    pub fn new() -> Self {
        Self {
            bits: BitReader::new(),
            levels: [0; OLD_LEVEL_COUNT],
            main: Huffman::empty(),
            offsets: Huffman::empty(),
            lengths: Huffman::empty(),
            audio_tables: std::array::from_fn(|_| Huffman::empty()),
            audio_block: false,
            channels: 1,
            cur_channel: 0,
            audio: [AudioState::default(); MAX_CHANNELS],
            channel_delta: 0,
            old_offsets: [0; 4],
            last_offset: 0,
            last_length: 0,
            pending_match: None,
            in_block: false,
            output: Vec::new(),
            base_offset: 0,
        }
    }

    pub fn decode_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.0 output size overflows"))?;
        if !input.is_empty() {
            self.bits = BitReader::new();
        }
        self.bits.append(input);
        self.decode_until(target).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
            error => error,
        })?;
        self.read_last_tables()?;
        let out = self.raw_range(start, target)?.to_vec();
        self.trim_history(target, target);
        Ok(out)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        let decoded = self.decode_member(input, output_size)?;
        out.write_all(&decoded)
            .map_err(|_| Error::InvalidData("RAR 2.0 output write failed"))
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.0 output size overflows"))?;
        self.bits = BitReader::new();
        let mut packed = Vec::new();
        input
            .read_to_end(&mut packed)
            .map_err(|_| Error::InvalidData("RAR 2.0 input read failed"))?;
        self.bits.append(&packed);
        if !self.in_block && self.bits.remaining_bytes_from_current() > 0 {
            self.read_tables().map_err(|error| match error {
                Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
                error => error,
            })?;
            self.in_block = true;
        }
        self.decode_until(target).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
            error => error,
        })?;
        self.read_last_tables()?;

        let decoded = self.raw_range(start, target)?;
        out.write_all(decoded)
            .map_err(|_| Error::InvalidData("RAR 2.0 output write failed"))?;
        self.trim_history(target, target);
        Ok(())
    }

    fn decode_until(&mut self, target: usize) -> Result<()> {
        while self.current_pos() < target {
            self.drain_pending_match(target)?;
            if self.current_pos() >= target {
                break;
            }
            if !self.in_block {
                self.read_tables()?;
                self.in_block = true;
            }
            self.decode_lz(target)?;
        }
        Ok(())
    }

    fn read_tables(&mut self) -> Result<()> {
        let bit_field = self.bits.peek_bits(16)?;
        self.audio_block = bit_field & 0x8000 != 0;
        let keep_tables = bit_field & 0x4000 != 0;
        self.bits.read_bits(2)?;
        if !keep_tables {
            self.levels = [0; OLD_LEVEL_COUNT];
        }

        let table_size = if self.audio_block {
            self.channels = ((bit_field >> 12) as usize & 3) + 1;
            if self.cur_channel >= self.channels {
                self.cur_channel = 0;
            }
            self.bits.read_bits(2)?;
            AUDIO_COUNT * self.channels
        } else {
            TABLE_COUNT
        };

        let level_lengths = Self::read_level_lengths(&mut self.bits)?;
        let level_decoder = Huffman::from_lengths(&level_lengths)?;
        let mut new_levels = [0u8; OLD_LEVEL_COUNT];
        let mut pos = 0usize;
        while pos < table_size {
            let symbol = level_decoder.decode(&mut self.bits)?;
            match symbol {
                0..=15 => {
                    new_levels[pos] = (self.levels[pos].wrapping_add(symbol as u8)) & 0x0f;
                    pos += 1;
                }
                16 => {
                    if pos == 0 {
                        return Err(Error::InvalidData("RAR 2.0 table repeat at start"));
                    }
                    let count = 3 + self.bits.read_bits(2)? as usize;
                    let value = new_levels[pos - 1];
                    fill_levels(&mut new_levels, &mut pos, count, value)?;
                }
                17 => {
                    let count = 3 + self.bits.read_bits(3)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                18 => {
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.0 invalid level symbol")),
            }
        }

        self.levels = new_levels;
        if self.audio_block {
            for channel in 0..self.channels {
                let start = channel * AUDIO_COUNT;
                self.audio_tables[channel] =
                    Huffman::from_lengths(&self.levels[start..start + AUDIO_COUNT])?;
            }
        } else {
            self.main = Huffman::from_lengths(&self.levels[..MAIN_COUNT])?;
            self.offsets =
                Huffman::from_lengths(&self.levels[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT])?;
            self.lengths =
                Huffman::from_lengths(&self.levels[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT])?;
        }
        Ok(())
    }

    fn read_level_lengths(bits: &mut BitReader) -> Result<[u8; LEVEL_COUNT]> {
        let mut lengths = [0u8; LEVEL_COUNT];
        for length in &mut lengths {
            *length = bits.read_bits(4)? as u8;
        }
        Ok(lengths)
    }

    fn decode_lz(&mut self, output_size: usize) -> Result<()> {
        while self.current_pos() < output_size {
            if self.audio_block {
                self.decode_audio_byte()?;
                if !self.in_block {
                    return Ok(());
                }
                continue;
            }
            let symbol = self.main.decode(&mut self.bits)?;
            match symbol {
                0..=255 => self.output.push(symbol as u8),
                256 => {
                    if self.last_length != 0 {
                        let length = self.last_length;
                        let offset = self.last_offset;
                        self.push_old_offset(offset);
                        self.copy_match(length, offset, output_size)?;
                    }
                }
                257..=260 => {
                    let index = symbol - 257;
                    let offset = self.old_offsets[index];
                    let length_slot = self.lengths.decode(&mut self.bits)?;
                    if length_slot >= LENGTH_COUNT {
                        return Err(Error::InvalidData("RAR 2.0 invalid repeat length slot"));
                    }
                    let mut length = LENGTH_BASES[length_slot] + 2;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    if offset >= 0x101 {
                        length += 1;
                    }
                    if offset >= 0x2000 {
                        length += 1;
                    }
                    if offset >= 0x40000 {
                        length += 1;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                261..=268 => {
                    let index = symbol - 261;
                    let mut offset = SHORT_BASES[index] + 1;
                    if SHORT_BITS[index] != 0 {
                        offset += self.bits.read_bits(SHORT_BITS[index])? as usize;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = 2;
                    self.copy_match(2, offset, output_size)?;
                }
                269 => {
                    self.in_block = false;
                    return Ok(());
                }
                270..=297 => {
                    let length_slot = symbol - 270;
                    let mut length = LENGTH_BASES[length_slot] + 3;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    let offset = self.read_offset()?;
                    if offset >= 0x2000 {
                        length += 1;
                    }
                    if offset >= 0x40000 {
                        length += 1;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.0 invalid main symbol")),
            }
        }
        Ok(())
    }

    fn decode_audio_byte(&mut self) -> Result<()> {
        let symbol = self.audio_tables[self.cur_channel].decode(&mut self.bits)?;
        if symbol == 256 {
            self.in_block = false;
            return Ok(());
        }
        if symbol > 256 {
            return Err(Error::InvalidData("RAR 2.0 invalid audio symbol"));
        }
        let byte = self.decode_audio(symbol as u8);
        self.output.push(byte);
        self.cur_channel += 1;
        if self.cur_channel == self.channels {
            self.cur_channel = 0;
        }
        Ok(())
    }

    fn decode_audio(&mut self, delta: u8) -> u8 {
        let state = &mut self.audio[self.cur_channel];
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
            + state.k[4] * self.channel_delta;
        let predicted = (predicted >> 3) & 0xff;
        let byte = predicted.wrapping_sub(delta as i32) as u8;

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
        state.dif[9] = state.dif[9].wrapping_add((d - self.channel_delta).unsigned_abs());
        state.dif[10] = state.dif[10].wrapping_add((d + self.channel_delta).unsigned_abs());

        self.channel_delta = (byte.wrapping_sub(state.last_char as u8)) as i8 as i32;
        state.last_delta = self.channel_delta;
        state.last_char = byte as i32;

        if state.byte_count & 0x1f == 0 {
            let mut min_dif = state.dif[0];
            let mut num_min_dif = 0usize;
            state.dif[0] = 0;
            for index in 1..state.dif.len() {
                if state.dif[index] < min_dif {
                    min_dif = state.dif[index];
                    num_min_dif = index;
                }
                state.dif[index] = 0;
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

        byte
    }

    fn read_offset(&mut self) -> Result<usize> {
        let slot = self.offsets.decode(&mut self.bits)?;
        if slot >= OFFSET_COUNT {
            return Err(Error::InvalidData("RAR 2.0 invalid offset slot"));
        }
        let mut offset = OFFSET_BASES[slot] + 1;
        if OFFSET_BITS[slot] != 0 {
            offset += self.bits.read_bits(OFFSET_BITS[slot])? as usize;
        }
        Ok(offset)
    }

    fn copy_match(&mut self, length: usize, offset: usize, output_size: usize) -> Result<()> {
        let offset = if offset == 0 { 1 } else { offset };
        let current = self.current_pos();
        if offset > current {
            return Err(Error::InvalidData("RAR 2.0 match distance is out of range"));
        }
        for index in 0..length {
            if self.current_pos() >= output_size {
                self.pending_match = Some((length - index, offset));
                break;
            }
            let src = self.current_pos() - offset;
            let byte = *self
                .raw_byte(src)
                .ok_or(Error::InvalidData("RAR 2.0 match distance is out of range"))?;
            self.output.push(byte);
        }
        Ok(())
    }

    fn drain_pending_match(&mut self, output_size: usize) -> Result<()> {
        let Some((length, offset)) = self.pending_match.take() else {
            return Ok(());
        };
        self.copy_match(length, offset, output_size)
    }

    fn read_last_tables(&mut self) -> Result<()> {
        if self.bits.remaining_bytes_from_current() < 5 {
            return Ok(());
        }
        if self.audio_block {
            if self.audio_tables[self.cur_channel].symbols.is_empty() {
                return Ok(());
            }
            if self.audio_tables[self.cur_channel].decode(&mut self.bits)? == 256 {
                self.read_tables()?;
                self.in_block = true;
            }
        } else {
            if self.main.symbols.is_empty() {
                return Ok(());
            }
            if self.main.decode(&mut self.bits)? == 269 {
                self.read_tables()?;
                self.in_block = true;
            }
        }
        Ok(())
    }

    fn push_old_offset(&mut self, offset: usize) {
        self.old_offsets[3] = self.old_offsets[2];
        self.old_offsets[2] = self.old_offsets[1];
        self.old_offsets[1] = self.old_offsets[0];
        self.old_offsets[0] = offset;
    }

    fn current_pos(&self) -> usize {
        self.base_offset + self.output.len()
    }

    fn raw_byte(&self, position: usize) -> Option<&u8> {
        self.output.get(position.checked_sub(self.base_offset)?)
    }

    fn raw_range(&self, start: usize, end: usize) -> Result<&[u8]> {
        if start < self.base_offset || end < start {
            return Err(Error::InvalidData(
                "RAR 2.0 retained history is unavailable",
            ));
        }
        let rel_start = start - self.base_offset;
        let rel_end = end - self.base_offset;
        self.output
            .get(rel_start..rel_end)
            .ok_or(Error::InvalidData(
                "RAR 2.0 retained history is unavailable",
            ))
    }

    fn trim_history(&mut self, flushed_pos: usize, current_pos: usize) {
        let keep_from = current_pos.saturating_sub(MAX_HISTORY).min(flushed_pos);
        if keep_from <= self.base_offset {
            return;
        }
        let drain = keep_from - self.base_offset;
        self.output.drain(..drain);
        self.base_offset = keep_from;
    }
}

impl Default for Unpack20 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AudioState {
    k: [i32; 5],
    d1: i32,
    d2: i32,
    d3: i32,
    d4: i32,
    last_delta: i32,
    last_char: i32,
    byte_count: u32,
    dif: [u32; 11],
}

fn fill_levels(levels: &mut [u8], pos: &mut usize, count: usize, value: u8) -> Result<()> {
    let end = pos
        .checked_add(count)
        .ok_or(Error::InvalidData("RAR 2.0 table run overflows"))?;
    let end = end.min(levels.len());
    for item in &mut levels[*pos..end] {
        *item = value;
    }
    *pos = end;
    Ok(())
}

#[derive(Debug, Clone)]
struct Huffman {
    symbols: Vec<HuffmanSymbol>,
    first_code: [u16; 16],
    first_index: [usize; 16],
    counts: [u16; 16],
}

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    code: u16,
    len: u8,
    symbol: usize,
}

impl Huffman {
    fn empty() -> Self {
        Self {
            symbols: Vec::new(),
            first_code: [0; 16],
            first_index: [0; 16],
            counts: [0; 16],
        }
    }

    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &len in lengths {
            if len > 15 {
                return Err(Error::InvalidData("RAR 2.0 Huffman length is too large"));
            }
            if len != 0 {
                count[len as usize] += 1;
            }
        }
        if count.iter().all(|&value| value == 0) {
            return Ok(Self::empty());
        }
        validate_huffman_counts(&count)?;

        let mut first_code = [0u16; 16];
        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code + count[len - 1]) << 1;
            first_code[len] = code;
            next_code[len] = code;
        }

        let mut first_index = [0usize; 16];
        let mut index = 0usize;
        for len in 1..=15 {
            first_index[len] = index;
            index += usize::from(count[len]);
        }

        let mut symbols = Vec::new();
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            symbols.push(HuffmanSymbol { code, len, symbol });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));
        Ok(Self {
            symbols,
            first_code,
            first_index,
            counts: count,
        })
    }

    fn decode(&self, bits: &mut BitReader) -> Result<usize> {
        let mut code = 0u16;
        if self.symbols.is_empty() {
            return Err(Error::InvalidData("RAR 2.0 empty Huffman table"));
        }
        for len in 1..=15 {
            code = (code << 1) | bits.read_bit()? as u16;
            let count = self.counts[len];
            if count != 0 {
                let first = self.first_code[len];
                let offset = code.wrapping_sub(first);
                if offset < count {
                    let index = self.first_index[len] + usize::from(offset);
                    return Ok(self.symbols[index].symbol);
                }
            }
        }
        Err(Error::InvalidData("RAR 2.0 invalid Huffman code"))
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    let mut available = 1i32;
    for &len_count in count.iter().skip(1) {
        available = (available << 1) - i32::from(len_count);
        if available < 0 {
            return Err(Error::InvalidData("RAR 2.0 oversubscribed Huffman table"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct BitReader {
    input: Vec<u8>,
    bit_pos: usize,
}

impl BitReader {
    fn new() -> Self {
        Self {
            input: Vec::new(),
            bit_pos: 0,
        }
    }

    fn append(&mut self, input: &[u8]) {
        self.compact();
        self.input.extend_from_slice(input);
    }

    fn compact(&mut self) {
        let bytes = self.bit_pos / 8;
        if bytes == 0 {
            return;
        }
        self.input.drain(..bytes);
        self.bit_pos -= bytes * 8;
    }

    fn read_bit(&mut self) -> Result<u8> {
        self.read_bits(1).map(|value| value as u8)
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let value = self.peek_bits(count)?;
        self.bit_pos += count as usize;
        Ok(value)
    }

    fn peek_bits(&self, count: u8) -> Result<u32> {
        if count > 24 {
            return Err(Error::InvalidData("RAR 2.0 bit read is too wide"));
        }
        let mut value = 0u32;
        for i in 0..count as usize {
            let bit_index = self.bit_pos + i;
            let byte = *self.input.get(bit_index / 8).ok_or(Error::NeedMoreInput)?;
            let bit = (byte >> (7 - (bit_index % 8))) & 1;
            value = (value << 1) | bit as u32;
        }
        Ok(value)
    }

    fn remaining_bytes_from_current(&self) -> usize {
        self.input.len().saturating_sub(self.bit_pos / 8)
    }
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn write_bits(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            self.write_bit(((value >> shift) & 1) != 0);
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if self.bit_pos.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit {
            let shift = 7 - (self.bit_pos % 8);
            *self.bytes.last_mut().unwrap() |= 1 << shift;
        }
        self.bit_pos += 1;
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_tokens, unpack20_decode, unpack20_encode_literals, BitWriter, EncodeOptions,
        EncodeToken, Error, Huffman, Unpack20, Unpack20Encoder,
    };

    const AUTOREJ_PACKED: &[u8] = &[
        0x09, 0x14, 0x0c, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0xce, 0xf8, 0x1f, 0xc1, 0xe6, 0x05,
        0xfc, 0x39, 0xc3, 0x50, 0x65, 0x08, 0x41, 0x94, 0xc4, 0x1d, 0xf3, 0xcd, 0x0d, 0x8e, 0x20,
        0xf5, 0x9d, 0x8e, 0x76, 0x1d, 0xc5, 0x19, 0xde, 0x16, 0x5b, 0x52, 0xb8, 0x8e, 0x75, 0xcd,
        0xaf, 0x1f, 0xfc, 0x9e, 0xf7, 0x00, 0x01, 0xbe, 0x90,
    ];

    #[test]
    fn decodes_rar20_lz_member() {
        assert_eq!(
            unpack20_decode(AUTOREJ_PACKED, expected_text().len()).unwrap(),
            expected_text()
        );
    }

    #[test]
    fn rejects_oversubscribed_rar20_huffman_tables() {
        assert!(matches!(
            Huffman::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidData("RAR 2.0 oversubscribed Huffman table"))
        ));
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

        let mut decoder = Unpack20::new();
        let mut reader = TinyReader {
            input: AUTOREJ_PACKED,
        };
        let mut output = Vec::new();
        decoder
            .decode_member_from_reader(&mut reader, expected_text().len(), &mut output)
            .unwrap();

        assert_eq!(output, expected_text());
    }

    #[test]
    fn decodes_synthetic_audio_block() {
        let packed = synthetic_audio_block(8);
        let mut decoder = Unpack20::new();

        assert_eq!(decoder.decode_member(&packed, 8).unwrap(), vec![0; 8]);
    }

    #[test]
    fn audio_encoder_round_trips_interleaved_pcm_like_payload() {
        let input = interleaved_pcm_like_payload();
        let packed = super::encode_audio_member(&input, 4).unwrap();
        let decoded = unpack20_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn auto_encoder_uses_audio_when_it_beats_lz() {
        let input = interleaved_pcm_like_payload();
        let lz = unpack20_encode_literals(&input).unwrap();
        let auto = super::unpack20_encode_auto(&input).unwrap();
        let decoded = unpack20_decode(&auto, input.len()).unwrap();

        assert!(auto.len() < lz.len());
        assert_eq!(decoded, input);
    }

    #[test]
    fn default_encode_options_match_legacy_entry_points() {
        let input = b"rar20 option plumbing preserves default output ".repeat(128);
        assert_eq!(
            unpack20_encode_literals(&input).unwrap(),
            super::unpack20_encode_literals_with_options(&input, EncodeOptions::default()).unwrap()
        );
        assert_eq!(
            super::unpack20_encode_auto(&input).unwrap(),
            super::unpack20_encode_auto_with_options(&input, EncodeOptions::default()).unwrap()
        );

        let first = b"solid rar20 option seed ".repeat(64);
        let second = b"solid rar20 option seed with suffix ".repeat(32);
        let mut legacy = Unpack20Encoder::new();
        let mut explicit = Unpack20Encoder::with_options(EncodeOptions::default());
        assert_eq!(
            legacy.encode_member(&first).unwrap(),
            explicit.encode_member(&first).unwrap()
        );
        assert_eq!(
            legacy.encode_member(&second).unwrap(),
            explicit.encode_member(&second).unwrap()
        );
    }

    #[test]
    fn encode_options_can_disable_fresh_lz_matches() {
        let input = b"abcdefabcdefabcdefabcdef";
        let default_tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let literalish_tokens = encode_tokens(input, &[], EncodeOptions::new(0), None);

        assert!(default_tokens
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { .. })));
        assert!(!literalish_tokens
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { .. })));
    }

    #[test]
    fn table_level_encoder_uses_rar20_run_symbols() {
        let lengths = [0, 0, 0, 0, 5, 5, 5, 5, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let tokens = super::encode_level_tokens(&lengths);

        assert_eq!(
            tokens,
            vec![
                super::LevelToken::zero_run_short(4),
                super::LevelToken::plain(5),
                super::LevelToken::repeat_previous(3),
                super::LevelToken::plain(7),
                super::LevelToken::zero_run_short(10),
                super::LevelToken::plain(2),
            ]
        );
    }

    #[test]
    fn decodes_back_to_back_fresh_audio_blocks() {
        // No real RAR 2.x encoder we tested emits a mid-stream `audio_block,
        // !keep_tables` transition; reference encoders always either keep the
        // existing audio tables across boundaries or switch out to LZ. The
        // decoder branch that rebuilds `audio_tables` from a freshly-read level
        // table inside an audio sequence is therefore only reachable via a
        // hand-crafted fixture.
        let mut bits = BitWriter::default();
        write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ true);
        write_fresh_audio_block(&mut bits, 4, /*emit_end_sentinel=*/ false);
        let packed = bits.finish();

        let mut decoder = Unpack20::new();

        assert_eq!(decoder.decode_member(&packed, 8).unwrap(), vec![0; 8]);
    }

    fn expected_text() -> Vec<u8> {
        b"Hello text not audio.\r\n".repeat(100)
    }

    fn interleaved_pcm_like_payload() -> Vec<u8> {
        let mut input = Vec::new();
        for sample in 0..8192i16 {
            let left = sample.wrapping_mul(3).wrapping_add(200);
            let right = sample.wrapping_mul(3).wrapping_sub(200);
            input.extend_from_slice(&left.to_le_bytes());
            input.extend_from_slice(&right.to_le_bytes());
        }
        input
    }

    fn synthetic_audio_block(samples: usize) -> Vec<u8> {
        let mut bits = BitWriter::default();

        bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
        bits.write_bits(0, 2); // one channel.

        for symbol in 0..19 {
            let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
            bits.write_bits(len, 4);
        }

        bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
        bits.write_bit(true); // level symbol 18: 138 zeros.
        bits.write_bits(127, 7);
        bits.write_bit(true); // level symbol 18: 118 zeros.
        bits.write_bits(107, 7);

        for _ in 0..samples {
            bits.write_bit(false); // audio delta 0.
        }

        bits.finish()
    }

    fn write_fresh_audio_block(bits: &mut BitWriter, samples: usize, emit_end_sentinel: bool) {
        bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
        bits.write_bits(0, 2); // one channel.

        for symbol in 0..19 {
            let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
            bits.write_bits(len, 4);
        }

        // Audio table: symbol 0 (delta 0) = "0", symbol 256 (block end) = "1".
        bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
        bits.write_bit(true); // level symbol 18: 138 zeros (audio symbols 1..=138).
        bits.write_bits(127, 7);
        bits.write_bit(true); // level symbol 18: 117 zeros (audio symbols 139..=255).
        bits.write_bits(106, 7);
        bits.write_bit(false); // level symbol 1: block-end (256) has code length 1.

        for _ in 0..samples {
            bits.write_bit(false); // audio delta 0.
        }
        if emit_end_sentinel {
            bits.write_bit(true); // audio symbol 256: end of audio block.
        }
    }

    #[test]
    fn literal_encoder_round_trips_rar20_lz_blocks() {
        let input = b"literal-only RAR 2.0 baseline\nwith repeated text literal-only\n";
        let packed = unpack20_encode_literals(input).unwrap();

        assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_offset_one_matches_for_repeated_bytes() {
        let input = b"A".repeat(1024);
        let packed = unpack20_encode_literals(&input).unwrap();

        assert!(packed.len() < input.len() / 4);
        assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_dictionary_matches_for_repeated_sequences() {
        let input = b"abc123xyz-".repeat(128);
        let packed = unpack20_encode_literals(&input).unwrap();

        assert!(packed.len() < input.len() / 2);
        assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_repeat_last_matches_for_regular_streams() {
        let input = b"\x00\x01\x02\x03".repeat(4096);
        let tokens = encode_tokens(&input, &[], EncodeOptions::default(), None);
        let packed = unpack20_encode_literals(&input).unwrap();

        assert!(tokens
            .iter()
            .any(|token| matches!(token, EncodeToken::RepeatLast)));
        assert!(packed.len() < input.len() / 8);
        assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_minimum_length_fresh_matches() {
        let input = b"abcabc";
        let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let packed = unpack20_encode_literals(input).unwrap();

        assert!(matches!(
            tokens.as_slice(),
            [
                EncodeToken::Literal(b'a'),
                EncodeToken::Literal(b'b'),
                EncodeToken::Literal(b'c'),
                EncodeToken::Match {
                    length: 3,
                    offset: 3
                }
            ]
        ));
        assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_short_offset_matches() {
        let input = b"abab";
        let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let packed = unpack20_encode_literals(input).unwrap();

        assert!(matches!(
            tokens.as_slice(),
            [
                EncodeToken::Literal(b'a'),
                EncodeToken::Literal(b'b'),
                EncodeToken::ShortOffset { offset: 2 }
            ]
        ));
        assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar20_old_offset_matches() {
        let input = b"abcdabcdXYZXYZwxyzwxyz";
        let tokens = encode_tokens(input, &[], EncodeOptions::default(), None);
        let packed = unpack20_encode_literals(input).unwrap();

        assert!(tokens
            .iter()
            .any(|token| matches!(token, EncodeToken::OldOffset { .. })));
        assert_eq!(unpack20_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_finds_rar20_matches_beyond_near_offsets() {
        let phrase = b"long-distance repeated phrase for rar20 match finder.";
        let mut input = Vec::new();
        input.extend_from_slice(phrase);
        input.extend(std::iter::repeat_n(0, 300 * 1024));
        input.extend_from_slice(phrase);
        input.extend_from_slice(phrase);
        let tokens = encode_tokens(&input, &[], EncodeOptions::default(), None);
        let packed = unpack20_encode_literals(&input).unwrap();

        assert!(tokens.iter().any(|token| matches!(
            token,
            EncodeToken::Match { offset, .. } if *offset > 0x40000
        )));
        assert!(packed.len() < input.len());
        let decoded = unpack20_decode(&packed, input.len()).unwrap();
        assert!(
            decoded == input,
            "RAR 2.0 long-distance match round-trip failed"
        );
    }

    #[test]
    fn solid_encoder_emits_rar20_matches_against_previous_member_history() {
        let first = b"solid rar20 shared phrase alpha beta gamma ".repeat(4);
        let second = b"solid rar20 shared phrase alpha beta gamma ".repeat(2);
        let independent = unpack20_encode_literals(&second).unwrap();
        let mut encoder = Unpack20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();

        assert!(second_packed.len() < independent.len());
        let mut decoder = Unpack20::new();
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
    fn solid_encoder_reuses_rar20_tables_at_member_boundary() {
        let first: Vec<_> = (0u8..=255).cycle().take(4096).collect();
        let second = b"short literal member after reused rar20 table boundary\n";
        let independent = unpack20_encode_literals(second).unwrap();
        let mut encoder = Unpack20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(second).unwrap();

        assert!(second_packed.len() < independent.len());
        let mut decoder = Unpack20::new();
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
    fn solid_encoder_matches_immediately_after_rar20_table_boundary() {
        let phrase = b"rar20 table boundary match phrase with enough bytes ";
        let first = phrase.repeat(128);
        let second = phrase.repeat(8);
        let independent = unpack20_encode_literals(&second).unwrap();
        let mut encoder = Unpack20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();
        let tokens = encode_tokens(&second, &first, EncodeOptions::default(), None);

        assert!(matches!(tokens.first(), Some(EncodeToken::Match { .. })));
        assert!(second_packed.len() < independent.len());
        let mut decoder = Unpack20::new();
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
    fn solid_encoder_carries_rar20_history_across_multiple_members() {
        let first = b"rar20 multi member solid seed ".repeat(512);
        let second = b"rar20 multi member solid seed with middle tail ".repeat(128);
        let third = b"with middle tail ".repeat(64);
        let independent = unpack20_encode_literals(&third).unwrap();
        let mut encoder = Unpack20Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();
        let third_packed = encoder.encode_member(&third).unwrap();

        assert!(third_packed.len() < independent.len());
        let mut decoder = Unpack20::new();
        assert_eq!(
            decoder.decode_member(&first_packed, first.len()).unwrap(),
            first
        );
        assert_eq!(
            decoder.decode_member(&second_packed, second.len()).unwrap(),
            second
        );
        assert_eq!(
            decoder.decode_member(&third_packed, third.len()).unwrap(),
            third
        );
    }

    #[test]
    fn decode_member_to_streams_decoded_payload_through_writer_sink() {
        let input = b"abcabcabcabcabcabcabcabcabcabcabcabc";
        let packed = unpack20_encode_literals(input).unwrap();

        let mut decoder = Unpack20::new();
        let mut sink = Vec::new();
        decoder
            .decode_member_to(&packed, input.len(), &mut sink)
            .unwrap();
        assert_eq!(sink, input);

        // The error-mapping closure inside decode_member_to fires when the
        // sink's write_all returns Err — feed it a writer that always fails.
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut decoder = Unpack20::new();
        let err = decoder
            .decode_member_to(&packed, input.len(), &mut FailingWriter)
            .unwrap_err();
        assert_eq!(err, Error::InvalidData("RAR 2.0 output write failed"));
    }
}
