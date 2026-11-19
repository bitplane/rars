//! RAR20 member encoding and bit emission.
use super::super::workspace::{Allowance, Buffer};
use super::super::{huffman, match_finder};
use super::*;
use std::io::Read;
use std::ops::ControlFlow;

const MAX_ENCODER_MATCH_OFFSET: usize = MAX_HISTORY;

const MAX_ENCODER_MATCH_LENGTH: usize = 258;

const MAX_MATCH_CANDIDATES: usize = 256;

type Rar20MatchFinder = match_finder::MatchFinder<3>;

/// Takes packed bytes and how far into the member they reach; a break stops the coding.
pub(crate) type PackedOut<'a> = &'a mut dyn FnMut(&[u8], usize) -> Result<ControlFlow<()>>;

pub fn unpack20_encode_literals(input: &[u8]) -> Result<Vec<u8>> {
    unpack20_encode_literals_with_options(input, EncodeOptions::default())
}

pub fn unpack20_encode_literals_with_options(
    input: &[u8],
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member(input, &[], None, options, false, None)
}

pub fn unpack20_encode_auto(input: &[u8]) -> Result<Vec<u8>> {
    unpack20_encode_auto_with_options(input, EncodeOptions::default())
}

pub fn unpack20_encode_auto_with_options(input: &[u8], options: EncodeOptions) -> Result<Vec<u8>> {
    encode_member(input, &[], None, options, options.try_audio, None)
}

pub(crate) fn unpack20_encode_auto_with_options_and_progress(
    input: &[u8],
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_member(input, &[], None, options, options.try_audio, Some(progress))
}

/// [`unpack20_encode_auto_with_options_and_progress`], reading the member as
/// it is coded and handing `out` the packed bytes a block at a time, with how
/// far into the member they reach, so neither the member nor its packed form
/// is held whole. A break from `out` stops the coding.
pub(crate) fn unpack20_encode_streamed(
    input: &mut dyn Read,
    len: usize,
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
    out: PackedOut<'_>,
) -> Result<ControlFlow<()>> {
    let try_audio = options.try_audio;
    encode_streamed(
        input,
        len,
        &[],
        None,
        options,
        try_audio,
        progress,
        out,
        BLOCK_SIZE,
    )
    .map(|(flow, _)| flow)
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
    /// Priced re-parses beyond the ones a block needs to settle its tables.
    /// Each is kept only if it packs the block smaller, so adding them never
    /// makes the output larger.
    pub extra_priced_passes: usize,
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
            extra_priced_passes: 0,
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

    pub const fn with_extra_priced_passes(mut self, passes: usize) -> Self {
        self.extra_priced_passes = passes;
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

    /// [`Self::encode_member_with_progress`] read as it is coded; see
    /// [`unpack20_encode_streamed`]. The chain moves on only if `out` takes
    /// every byte.
    pub(crate) fn encode_member_streamed(
        &mut self,
        input: &mut dyn Read,
        len: usize,
        progress: &mut dyn FnMut(usize) -> bool,
        out: PackedOut<'_>,
    ) -> Result<ControlFlow<()>> {
        if len == 0 {
            return Ok(ControlFlow::Continue(()));
        }
        let table = self.table()?;
        let (flow, history) = encode_streamed(
            input,
            len,
            &self.history,
            Some(table),
            self.options,
            false,
            progress,
            out,
            BLOCK_SIZE,
        )?;
        if flow.is_continue() {
            self.history = history;
        }
        Ok(flow)
    }

    fn table(&mut self) -> Result<FixedEncodeTable> {
        match self.table {
            Some(table) => Ok(table),
            None => {
                let table = FixedEncodeTable::new()?;
                self.table = Some(table);
                Ok(table)
            }
        }
    }

    fn encode_member_inner(
        &mut self,
        input: &[u8],
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let table = self.table()?;
        let packed = encode_member(
            input,
            &self.history,
            Some(table),
            self.options,
            false,
            progress,
        )?;
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

/// Bytes coded per block. Each block is parsed against the dictionary before
/// it and gets tables of its own, so the parse's working set (its tokens, and
/// at levels 4–5 its nodes and match lists) is sized by the block, not by the
/// member.
const BLOCK_SIZE: usize = 1024 * 1024;

/// What coding one block holds beyond the member's own bytes: the window and
/// block, the match finders, the tokens, and at levels 4–5 the shortest-path
/// parse's nodes and match lists. Peak RSS on brett, coding 256 MiB streamed
/// with 1 MiB blocks, was 18–26 MB at level 3 and 73 MB at level 5.
const fn block_workspace(optimal_parse: bool) -> u64 {
    if optimal_parse {
        80 * 1024 * 1024
    } else {
        24 * 1024 * 1024
    }
}

fn encode_member(
    input: &[u8],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    options: EncodeOptions,
    try_audio: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    encode_member_in_blocks(
        input,
        history,
        fixed_table,
        options,
        try_audio,
        progress,
        BLOCK_SIZE,
    )
}

fn encode_member_in_blocks(
    input: &[u8],
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    options: EncodeOptions,
    try_audio: bool,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    block_size: usize,
) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut packed = Vec::new();
    let _ = encode_streamed(
        &mut &input[..],
        input.len(),
        history,
        fixed_table,
        options,
        try_audio,
        &mut |at| match progress.as_deref_mut() {
            Some(report) => report(at),
            None => true,
        },
        &mut |bytes, _| {
            packed.extend_from_slice(bytes);
            Ok(ControlFlow::Continue(()))
        },
        block_size,
    )?;
    // Nothing above breaks, so every packed byte was taken.
    Ok(packed)
}

/// Most blocks coded at once, so a batch's window and parses stay bounded.
const MAX_BLOCKS_SIDE_BY_SIDE: usize = 16;

fn blocks_per_batch() -> usize {
    crate::parallel::threads().clamp(1, MAX_BLOCKS_SIDE_BY_SIDE)
}

/// A block's workspace per block coded at once, charged as if this member may fan out.
pub(crate) fn coding_workspace(optimal_parse: bool, len: u64) -> u64 {
    let blocks = len.div_ceil(BLOCK_SIZE as u64).max(1);
    blocks
        .min(blocks_per_batch() as u64)
        .saturating_mul(block_workspace(optimal_parse))
}

/// Returns the member's last reach, which a chain's next member continues from.
#[allow(clippy::too_many_arguments)]
fn encode_streamed(
    input: &mut dyn Read,
    len: usize,
    history: &[u8],
    fixed_table: Option<FixedEncodeTable>,
    options: EncodeOptions,
    try_audio: bool,
    progress: &mut dyn FnMut(usize) -> bool,
    out: PackedOut<'_>,
    block_size: usize,
) -> Result<(ControlFlow<()>, Vec<u8>)> {
    let options = options.constrained();
    let reach = options.max_match_distance;
    let mut window = history[history.len().saturating_sub(reach)..].to_vec();
    let mut coder = BlockCoder::new(options, fixed_table, try_audio, window.is_empty());
    let side_by_side = crate::parallel::may_nest();
    let batch = match side_by_side {
        true => block_size.saturating_mul(blocks_per_batch()),
        false => block_size,
    };
    let mut base = 0;
    while base < len {
        let end = base.saturating_add(batch).min(len);
        window.drain(..window.len().saturating_sub(reach));
        let behind = window.len();
        window.resize(behind + (end - base), 0);
        input.read_exact(&mut window[behind..])?;
        let blocks: Vec<Block> = (behind..window.len())
            .step_by(block_size)
            .map(|start| {
                let stop = (start + block_size).min(window.len());
                Block {
                    start,
                    stop,
                    more: stop < window.len() || end < len,
                }
            })
            .collect();
        let lz = coder.code_lz_blocks(&window, &blocks, side_by_side, &mut |consumed| {
            progress(base + consumed)
        })?;
        for (block, lz) in blocks.iter().zip(lz) {
            let (start, stop) = (block.start, block.stop);
            coder.commit(&window[start..stop], lz, block.more)?;
            let at = base + (stop - behind);
            if !progress(at) {
                return Err(Error::Cancelled);
            }
            // The last byte may still take bits from the next block.
            let whole = coder.bits.take_whole_bytes();
            if !whole.is_empty() && out(&whole, at)?.is_break() {
                return Ok((ControlFlow::Break(()), Vec::new()));
            }
        }
        base = end;
    }
    let tail = coder.bits.finish();
    if !tail.is_empty() && out(&tail, len)?.is_break() {
        return Ok((ControlFlow::Break(()), Vec::new()));
    }
    window.drain(..window.len().saturating_sub(reach));
    Ok((ControlFlow::Continue(()), window))
}

/// Lends an optional progress callback to one call at a time.
fn again<'a>(
    progress: &'a mut Option<&mut dyn FnMut(usize) -> bool>,
) -> Option<&'a mut dyn FnMut(usize) -> bool> {
    match progress {
        Some(report) => Some(&mut **report),
        None => None,
    }
}

/// A block's place in a batch's window, and whether any block follows it in the member.
#[derive(Debug, Clone, Copy)]
struct Block {
    start: usize,
    stop: usize,
    more: bool,
}

/// Codes a member a block at a time into one bit stream. A block ends with the
/// symbol that makes the reader read new tables, then the next block's.
struct BlockCoder {
    options: EncodeOptions,
    fixed_table: Option<FixedEncodeTable>,
    try_audio: bool,
    audio: AudioCoder,
    /// False while a solid member continues the fixed table already sent.
    header: bool,
    bits: BitWriter,
}

impl BlockCoder {
    fn new(
        options: EncodeOptions,
        fixed_table: Option<FixedEncodeTable>,
        try_audio: bool,
        fresh: bool,
    ) -> Self {
        Self {
            options,
            fixed_table,
            try_audio,
            audio: AudioCoder::default(),
            header: fixed_table.is_none() || fresh,
            bits: BitWriter::default(),
        }
    }

    /// Workers cannot share `progress`, so blocks side by side report only as they commit.
    fn code_lz_blocks(
        &self,
        window: &[u8],
        blocks: &[Block],
        side_by_side: bool,
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<BitWriter>> {
        let reach = self.options.max_match_distance;
        let code = |index: usize, progress: Option<&mut dyn FnMut(usize) -> bool>| {
            let Block { start, stop, more } = blocks[index];
            // A fixed table never changes, so its blocks run on without new tables.
            let ends_table = more && self.fixed_table.is_none();
            let header = (index == 0 && self.header) || self.fixed_table.is_none();
            let behind = reach.min(start);
            code_lz_block(
                &window[start - behind..stop],
                behind,
                self.options,
                self.fixed_table,
                header,
                ends_table,
                progress,
            )
        };
        let indices: Vec<usize> = (0..blocks.len()).collect();
        if !side_by_side || blocks.len() == 1 {
            let first = blocks[0].start;
            return indices
                .into_iter()
                .map(|index| {
                    let into = blocks[index].start - first;
                    code(index, Some(&mut |consumed| progress(into + consumed)))
                })
                .collect();
        }
        match crate::parallel::map_prefix(indices, |index| code(index, None)) {
            (_, Some(error)) => Err(error),
            (coded, None) => Ok(coded),
        }
    }

    /// Writes `block` as its LZ coding `lz` or, when it packs smaller, as audio.
    fn commit(&mut self, block: &[u8], lz: BitWriter, more: bool) -> Result<()> {
        let mut best = lz;
        let mut audio = None;
        if self.try_audio {
            for channels in 1..=MAX_CHANNELS {
                if block.len() < channels * 64 {
                    continue;
                }
                let (bits, coder) = code_audio_block(block, channels, self.audio, more)?;
                if bits.bytes.len() < best.bytes.len() {
                    best = bits;
                    audio = Some(coder);
                }
            }
        }
        // An LZ block leaves the audio state alone.
        if let Some(coder) = audio {
            self.audio = coder;
        }
        self.bits.append(&best);
        self.header = self.fixed_table.is_none();
        Ok(())
    }
}

/// One block's LZ coding, its tables chosen by up to three parses: a greedy
/// one, then re-parses priced by the tables the one before implied. Only the
/// first advances progress, so each byte of the member is counted once; the
/// re-parses report the block's end, already reached, to stay cancellable.
#[allow(clippy::too_many_arguments)]
fn code_lz_block(
    window: &[u8],
    start: usize,
    options: EncodeOptions,
    fixed_table: Option<FixedEncodeTable>,
    header: bool,
    more: bool,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<BitWriter> {
    // Matches do not depend on prices, so every pass shares one search. A
    // fixed table is never re-parsed, so its greedy pass searches as it goes.
    let matches = (options.optimal_parse && fixed_table.is_none())
        .then(|| collect_match_lists(window, start, window.len(), options));
    let tokens = encode_tokens_with_progress(
        window,
        start,
        options,
        None,
        matches.as_ref(),
        again(&mut progress),
    )?;
    let table_lengths = table_lengths_for_tokens(&tokens, fixed_table, more)?;
    let mut best = BitWriter::default();
    write_lz_block(
        &mut best,
        &tokens,
        header,
        fixed_table,
        &table_lengths,
        more,
    )?;
    if fixed_table.is_some() {
        return Ok(best);
    }
    // Each pass's tokens die once packed; a pass that reproduces the last one
    // packs to the same length, which ends the loop.
    drop(tokens);

    // Re-parse against the prices the first pass implies, then again against
    // the prices that produced. A greedy parse has converged by the first
    // re-parse and a second buys 0.02%, but the shortest-path parse is far more
    // sensitive to its prices and a second pass is worth 0.12% to it. A third
    // and fourth buy another 0.06% on the bench's small members and 0.03% on its
    // 4 MiB text and binaries, which is what level 5 is for.
    let refinements = if options.optimal_parse { 2 } else { 1 } + options.extra_priced_passes;
    let span = window.len() - start;
    let mut poll = progress.map(|report| move |_: usize| report(span));
    let mut best_table = table_lengths;
    for _ in 0..refinements {
        let prices = absent_priced(&best_table);
        let cost_model = CostModel::new(&prices);
        let mut next_tokens = encode_tokens_with_progress(
            window,
            start,
            options,
            Some(&cost_model),
            matches.as_ref(),
            poll.as_mut()
                .map(|poll| poll as &mut dyn FnMut(usize) -> bool),
        )?;
        let next_table = table_lengths_for_tokens(&next_tokens, None, more)?;
        let mut next = BitWriter::default();
        write_lz_block(&mut next, &next_tokens, header, None, &next_table, more)?;
        // The repeats are tried on the packed result only. Prices drawn from a
        // table with them in would make the next parse shun the very matches
        // that become repeats, which cost 0.18% on an unstripped binary.
        if matches.is_some() && use_repeats(&mut next_tokens) {
            let repeat_table = table_lengths_for_tokens(&next_tokens, None, more)?;
            let mut repeated = BitWriter::default();
            write_lz_block(
                &mut repeated,
                &next_tokens,
                header,
                None,
                &repeat_table,
                more,
            )?;
            if repeated.bytes.len() < next.bytes.len() {
                next = repeated;
            }
        }
        if next.bytes.len() >= best.bytes.len() {
            break;
        }
        best_table = next_table;
        best = next;
    }
    Ok(best)
}

/// The table a priced pass reads its prices from, with every symbol the last
/// pass left without a code priced as dear as an absent literal.
///
/// Read as it stands, a missing length or offset slot costs nothing but its
/// extra bits, so the parse spends the next table on symbols it chose because
/// they looked free. Pricing them like a missing literal is worth 0.14% at
/// levels 4 and 5 on the bench's small members and 0.05% at level 3.
fn absent_priced(table: &[u8; TABLE_COUNT]) -> [u8; TABLE_COUNT] {
    table.map(|length| match length {
        0 => ABSENT_SYMBOL_BITS as u8,
        length => length,
    })
}

/// Swaps each match that copies what the one before it did, length and
/// offset both, for the repeat symbol, which says the same with no length or
/// offset. The shortest-path parse does not know the symbol, so it is found
/// after the parse; the greedy one already uses it as it goes. The reader
/// moves its recent offsets the same way for either, so nothing after the
/// swap changes. Returns whether anything was swapped.
fn use_repeats(tokens: &mut [EncodeToken]) -> bool {
    let mut last_match = None;
    let mut swapped = false;
    for token in tokens {
        let this = match *token {
            EncodeToken::Literal(_) => continue,
            EncodeToken::RepeatLast => last_match.expect("a repeat follows a match"),
            EncodeToken::OldOffset { length, offset, .. }
            | EncodeToken::Match { length, offset } => (usize::from(length), offset as usize),
            EncodeToken::ShortOffset { offset } => (2, offset as usize),
        };
        if last_match == Some(this) && *token != EncodeToken::RepeatLast {
            *token = EncodeToken::RepeatLast;
            swapped = true;
        }
        last_match = Some(this);
    }
    swapped
}

/// `more` when another block follows, whose tables symbol 269 announces.
fn table_lengths_for_tokens(
    tokens: &[EncodeToken],
    fixed_table: Option<FixedEncodeTable>,
    more: bool,
) -> Result<[u8; TABLE_COUNT]> {
    let mut main_frequencies = [0usize; MAIN_COUNT];
    main_frequencies[269] = usize::from(more);
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
                main_frequencies[257 + usize::from(index)] += 1;
                let (slot, _) = old_length_slot_for_match(usize::from(length), offset as usize)?;
                length_frequencies[slot] += 1;
            }
            EncodeToken::ShortOffset { offset } => {
                let (slot, _) = short_slot_for_match(offset as usize)?;
                main_frequencies[261 + slot] += 1;
            }
            EncodeToken::Match { length, offset } => {
                let (length, offset) = (usize::from(length), offset as usize);
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

fn write_lz_block(
    bits: &mut BitWriter,
    tokens: &[EncodeToken],
    header: bool,
    fixed_table: Option<FixedEncodeTable>,
    table_lengths: &[u8; TABLE_COUNT],
    more: bool,
) -> Result<()> {
    let level_tokens = encode_table_level_tokens(table_lengths);
    let level_lengths = level_code_lengths_for_tokens(&level_tokens);
    let level_codes = canonical_codes(&level_lengths)?;
    let main_codes = canonical_codes(&table_lengths[..MAIN_COUNT])?;
    debug_assert!(
        !(more && fixed_table.is_some()),
        "a fixed table is never replaced"
    );

    if header {
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
                let code = main_codes[257 + usize::from(index)].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing old-offset Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                let (slot, extra) =
                    old_length_slot_for_match(usize::from(length), offset as usize)?;
                let length_code = length_codes[slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing old-offset length Huffman code",
                ))?;
                bits.write_bits(length_code.code as u32, length_code.len);
                if LENGTH_BITS[slot] != 0 {
                    bits.write_bits(extra as u32, LENGTH_BITS[slot]);
                }
            }
            EncodeToken::ShortOffset { offset } => {
                let (slot, extra) = short_slot_for_match(offset as usize)?;
                let code = main_codes[261 + slot].ok_or(Error::InvalidData(
                    "RAR 2.0 encoder missing short-offset Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
                bits.write_bits(extra as u32, SHORT_BITS[slot]);
            }
            EncodeToken::Match { length, offset } => {
                let (length, offset) = (usize::from(length), offset as usize);
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
    if more {
        let code = main_codes[269].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing new-tables Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
    }
    Ok(())
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

/// Eight bytes, not thirty-two: random input is one token per byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodeToken {
    Literal(u8),
    RepeatLast,
    OldOffset { index: u8, length: u16, offset: u32 },
    ShortOffset { offset: u32 },
    Match { length: u16, offset: u32 },
}

impl EncodeToken {
    fn fresh(length: usize, offset: usize) -> Self {
        debug_assert!(length <= MAX_ENCODER_MATCH_LENGTH && offset <= MAX_ENCODER_MATCH_OFFSET);
        Self::Match {
            length: length as u16,
            offset: offset as u32,
        }
    }

    fn old_offset(index: usize, length: usize, offset: usize) -> Self {
        debug_assert!(index < 4 && length <= MAX_ENCODER_MATCH_LENGTH);
        debug_assert!(offset <= MAX_ENCODER_MATCH_OFFSET);
        Self::OldOffset {
            index: index as u8,
            length: length as u16,
            offset: offset as u32,
        }
    }

    fn short_offset(offset: usize) -> Self {
        debug_assert!(offset <= MAX_ENCODER_MATCH_OFFSET);
        Self::ShortOffset {
            offset: offset as u32,
        }
    }

    /// Lets the shortest-path parse walk back without storing back-links.
    fn parsed_length(self) -> usize {
        match self {
            Self::Literal(_) => 1,
            Self::RepeatLast => unreachable!("the shortest-path parse emits no repeats"),
            Self::OldOffset { length, .. } | Self::Match { length, .. } => usize::from(length),
            Self::ShortOffset { .. } => 2,
        }
    }
}

/// Lengths worth trying for a match at one position.
///
/// Every length inside a length slot is priced the same: the slot's Huffman
/// code plus its fixed extra bits, with the extra value itself costing nothing.
/// So the parse only needs the longest length in each slot, plus the longest
/// match found. That is at most twenty-nine candidates where trying every
/// length is up to two hundred and fifty-six, for 0.03% of packed size.
fn candidate_lengths(best_length: usize, adjustment: usize, out: &mut Vec<usize>) {
    out.clear();
    // Slot tops rise with the slot, so the list comes out sorted.
    for slot in 0..LENGTH_COUNT {
        let widest = LENGTH_BASES[slot] + (1usize << LENGTH_BITS[slot]) - 1;
        let length = widest + 3 + adjustment;
        if (3..=best_length).contains(&length) {
            out.push(length);
        }
    }
    // Callers only pass matches of at least three bytes.
    if out.last() != Some(&best_length) {
        out.push(best_length);
    }
}

/// Built once per pass, so pricing an edge is a lookup rather than a slot search.
struct EdgePrices {
    /// By length adjustment, then length; `None` where the length has no code.
    fresh: [[Option<u16>; MAX_ENCODER_MATCH_LENGTH + 1]; 3],
    offsets: [u16; OFFSET_COUNT],
    /// By recent-offset index, length adjustment, then length.
    old: [[[Option<u16>; MAX_ENCODER_MATCH_LENGTH + 1]; 4]; 4],
}

/// The nearest offset taking each old-offset length adjustment.
const OLD_ADJUSTMENT_OFFSETS: [usize; 4] = [1, 0x101, 0x2000, 0x40000];

impl EdgePrices {
    fn new(model: &CostModel<'_>) -> Box<Self> {
        let mut prices = Box::new(Self {
            fresh: [[None; MAX_ENCODER_MATCH_LENGTH + 1]; 3],
            offsets: [0; OFFSET_COUNT],
            old: [[[None; MAX_ENCODER_MATCH_LENGTH + 1]; 4]; 4],
        });
        for (adjustment, row) in prices.fresh.iter_mut().enumerate() {
            for (length, price) in row.iter_mut().enumerate().skip(adjustment) {
                if let Ok((slot, _)) = length_slot_for_match(length - adjustment) {
                    *price = Some(u16::from(model.main[270 + slot]) + u16::from(LENGTH_BITS[slot]));
                }
            }
        }
        for (slot, price) in prices.offsets.iter_mut().enumerate() {
            *price = u16::from(model.offsets[slot]) + u16::from(OFFSET_BITS[slot]);
        }
        for (index, rows) in prices.old.iter_mut().enumerate() {
            for (adjustment, row) in rows.iter_mut().enumerate() {
                let offset = OLD_ADJUSTMENT_OFFSETS[adjustment];
                debug_assert_eq!(old_length_adjustment(offset), adjustment);
                for (length, price) in row.iter_mut().enumerate() {
                    let Ok((slot, _)) = old_length_slot_for_match(length, offset) else {
                        continue;
                    };
                    *price = Some(
                        u16::from(model.main[257 + index])
                            + u16::from(model.lengths[slot])
                            + u16::from(LENGTH_BITS[slot]),
                    );
                }
            }
        }
        prices
    }
}

/// The nearest match per length at each position, so the parse can trade length against offset.
struct MatchLists {
    counts: Vec<u16>,
    /// Lengths and offsets both rise within a position, so a longer match is never also nearer.
    runs: Vec<FoundMatch>,
}

/// A length and an offset in four bytes, since there is one per match found.
#[derive(Debug, Clone, Copy)]
struct FoundMatch(u32);

impl FoundMatch {
    const LENGTH_BITS: u32 = 9;

    fn new(length: usize, offset: usize) -> Self {
        debug_assert!(length <= MAX_ENCODER_MATCH_LENGTH && offset <= MAX_ENCODER_MATCH_OFFSET);
        Self(((offset as u32) << Self::LENGTH_BITS) | length as u32)
    }

    fn length(self) -> usize {
        (self.0 & ((1 << Self::LENGTH_BITS) - 1)) as usize
    }

    fn offset(self) -> usize {
        (self.0 >> Self::LENGTH_BITS) as usize
    }
}

/// A run reaching this far is taken without pricing the positions it covers.
const NICE_MATCH_LENGTH: usize = MAX_ENCODER_MATCH_LENGTH;

/// From here a fresh match needs one more byte, so three-byte matches stop.
const LONGER_FRESH_OFFSET: usize = 0x2000;

/// How many chain candidates to try for a three-byte match the tree cannot report.
const THREE_BYTE_CANDIDATES: usize = 16;

fn collect_match_lists(
    input: &[u8],
    start: usize,
    end: usize,
    options: EncodeOptions,
) -> MatchLists {
    let allowance = Allowance::default();
    // Slots only have to outlive the furthest match accepted.
    let window = options.max_match_distance.saturating_add(1).min(end.max(1));
    let mut tree = match_finder::TreeMatchFinder::with_allowance(window, &allowance)
        .expect("unlimited finder allocation");
    let mut chain = Rar20MatchFinder::for_reach(window, window.min(LONGER_FRESH_OFFSET));
    let mut found: Buffer<(u32, u32), Allowance> = Buffer::new(&allowance);
    let candidates = options.max_match_candidates;
    let mut lists = MatchLists {
        counts: Vec::with_capacity(end - start),
        runs: Vec::new(),
    };
    for pos in 0..end {
        let max_offset = pos.min(options.max_match_distance);
        let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        found.clear();
        // Inserting into the tree is a search, so history positions search too.
        if max_length >= 4 && candidates != 0 {
            tree.matches(input, pos, max_length, max_offset, candidates, &mut found)
                .expect("unlimited match allocation");
        }
        if pos >= start {
            let before = lists.runs.len();
            let nearest_tree = found
                .first()
                .map_or(usize::MAX, |&(_, offset)| offset as usize);
            if candidates != 0 && max_length >= 3 {
                if let Some(offset) = nearest_three_byte_match(
                    input,
                    pos,
                    &chain,
                    max_offset
                        .min(nearest_tree - 1)
                        .min(LONGER_FRESH_OFFSET - 1),
                ) {
                    lists.runs.push(FoundMatch::new(3, offset));
                }
            }
            lists.runs.extend(
                found
                    .iter()
                    .map(|&(length, offset)| (length as usize, offset as usize))
                    .filter(|&(length, offset)| {
                        offset <= MAX_ENCODER_MATCH_OFFSET
                            && length >= 3 + match_length_adjustment(offset)
                    })
                    .map(|(length, offset)| FoundMatch::new(length, offset)),
            );
            lists.counts.push((lists.runs.len() - before) as u16);
        }
        chain.insert(input, pos);
    }
    lists
}

fn nearest_three_byte_match(
    input: &[u8],
    pos: usize,
    chain: &Rar20MatchFinder,
    max_offset: usize,
) -> Option<usize> {
    let mut candidate = chain.first(input, pos);
    for _ in 0..THREE_BYTE_CANDIDATES {
        if candidate == match_finder::NO_POSITION || pos - candidate > max_offset {
            return None;
        }
        if input[candidate..candidate + 3] == input[pos..pos + 3] {
            return Some(pos - candidate);
        }
        candidate = chain.previous(candidate);
    }
    None
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
    matches: &MatchLists,
    cost_model: &CostModel<'_>,
) -> Vec<EncodeToken> {
    let span = end - start;
    let mut nodes = vec![ParseNode::UNREACHED; span + 1];
    let mut lengths = Vec::new();
    let mut next_run = 0usize;
    // Positions inside a match long enough to take outright relax nothing.
    let mut committed_through = 0usize;
    let mut pairs = PairTable::new(input, start);
    let prices = EdgePrices::new(cost_model);
    debug_assert_eq!(
        matches.counts.len(),
        span,
        "lists collected for another buffer"
    );
    // A block starts with no recent offsets, which UNREACHED already holds.
    nodes[0].cost = 0;

    for index in 0..span {
        // Every position is reachable through the one-byte literal edge.
        let runs = &matches.runs[next_run..next_run + usize::from(matches.counts[index])];
        next_run += runs.len();
        if index < committed_through {
            continue;
        }
        let pos = start + index;
        let here = nodes[index].cost;
        let node_reps = nodes[index].reps.map(|offset| offset as usize);
        let cap = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        let nice = NICE_MATCH_LENGTH.min(cap);

        let mut relax = |next: usize, price: u64, what: EncodeToken, next_reps: [usize; 4]| {
            // Literal, fresh, old-offset and short-match edges all end within span.
            let node = &mut nodes[next];
            if here + price < node.cost {
                node.cost = here + price;
                node.token = what;
                node.reps = next_reps.map(|offset| offset as u32);
            }
        };

        relax(
            index + 1,
            cost_model.literal_bits(input, pos, 1) as u64,
            EncodeToken::Literal(input[pos]),
            node_reps,
        );

        // Only an edge actually relaxed can be committed to.
        let mut longest = 0usize;
        // Shorter lengths are left to the nearer run before, assuming a nearer offset is not dearer.
        let mut covered = 2usize;
        for &run in runs {
            let (reach, offset) = (run.length().min(cap), run.offset());
            let mut pushed = node_reps;
            push_old_offset(&mut pushed, offset);
            let adjustment = match_length_adjustment(offset);
            let fresh = &prices.fresh[adjustment];
            let offset_price = prices.offsets[offset_slot_index(offset)];
            candidate_lengths(reach, adjustment, &mut lengths);
            for &length in lengths.iter().filter(|&&length| length > covered) {
                if let Some(price) = fresh[length] {
                    relax(
                        index + length,
                        u64::from(price + offset_price),
                        EncodeToken::fresh(length, offset),
                        pushed,
                    );
                    longest = longest.max(length);
                }
            }
            covered = reach;
        }

        for (rep_index, &offset) in node_reps.iter().enumerate() {
            let reach = match_run_length(input, pos, offset, cap);
            if reach < 3 {
                continue;
            }
            let mut pushed = node_reps;
            push_old_offset(&mut pushed, offset);
            let old = &prices.old[rep_index][old_length_adjustment(offset)];
            candidate_lengths(reach, match_length_adjustment(offset), &mut lengths);
            for &length in &lengths {
                if let Some(price) = old[length] {
                    relax(
                        index + length,
                        u64::from(price),
                        EncodeToken::old_offset(rep_index, length, offset),
                        pushed,
                    );
                    longest = longest.max(length);
                }
            }
        }

        pairs.advance(input, pos);
        if let Some(SelectedMatch::ShortOffset { offset }) = pairs.nearest(input, pos, end) {
            let slot = short_slot_index(offset);
            let price = usize::from(cost_model.main[261 + slot]) + usize::from(SHORT_BITS[slot]);
            let mut pushed = node_reps;
            push_old_offset(&mut pushed, offset);
            relax(
                index + 2,
                price as u64,
                EncodeToken::short_offset(offset),
                pushed,
            );
        }

        if longest >= nice {
            committed_through = index + longest;
        }
    }

    let mut out = Vec::new();
    let mut at = span;
    while at > 0 {
        let what = nodes[at].token;
        out.push(what);
        at -= what.parsed_length();
    }
    out.reverse();
    out
}

/// Thirty-two bytes per input byte, where separate cost, link, token and rep arrays took eighty.
#[derive(Debug, Clone, Copy)]
struct ParseNode {
    cost: u64,
    token: EncodeToken,
    reps: [u32; 4],
}

impl ParseNode {
    // The repeat stands in for "no edge yet"; every reached node replaces it.
    const UNREACHED: Self = Self {
        cost: u64::MAX / 4,
        token: EncodeToken::RepeatLast,
        reps: [0; 4],
    };
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
    combined: &[u8],
    start: usize,
    options: EncodeOptions,
    cost_model: Option<&CostModel>,
    matches: Option<&MatchLists>,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    if let (Some(cost_model), Some(matches)) = (cost_model, matches) {
        return Ok(encode_tokens_optimal(
            combined,
            start,
            combined.len(),
            matches,
            cost_model,
        ));
    }
    let mut tokens = Vec::new();
    let mut finder = match matches {
        Some(lists) => FreshMatches::Listed(ListCursor::new(lists, start)),
        None => {
            // No match reaches past the dictionary, so the finder need not either.
            let reach = options.max_match_distance.max(1).min(combined.len());
            let mut finder = Rar20MatchFinder::for_reach(reach, reach);
            for history_pos in 0..start {
                finder.insert(combined, history_pos);
            }
            FreshMatches::Chain(finder)
        }
    };
    let mut pairs = PairTable::new(combined, start);
    let mut literal_totals = LiteralTotals::default();
    // A lazy look ahead prices a whole match from each position it tries.
    let priced_reach = options
        .lazy_lookahead
        .max(1)
        .saturating_add(MAX_ENCODER_MATCH_LENGTH);

    let mut pos = start;
    let end = combined.len();
    // A block starts with no recent offsets and nothing to repeat.
    let mut last_match = None;
    let mut old_offsets = [0; 4];
    let mut next_report = 0usize;
    while pos < end {
        if let Some(&model) = cost_model {
            literal_totals.cover(model, combined, pos, priced_reach);
        }
        let priced = cost_model.map(|model| model.with_literal_totals(&literal_totals));
        let cost_model = priced.as_ref();
        pairs.advance(combined, pos);
        let search = SearchContext {
            input: combined,
            end,
            finder: &finder,
            pairs: &pairs,
            options,
            old_offsets: &old_offsets,
            cost_model,
        };
        if let Some(selected) = select_match(&search, pos) {
            if should_lazy_emit_literal(pos, selected, &search) {
                tokens.push(EncodeToken::Literal(combined[pos]));
                finder.insert(combined, pos);
                pos += 1;
                continue;
            }
            let (length, offset) = match selected {
                SelectedMatch::Fresh { length, offset } => {
                    if last_match == Some((length, offset)) {
                        tokens.push(EncodeToken::RepeatLast);
                    } else {
                        tokens.push(EncodeToken::fresh(length, offset));
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
                        tokens.push(EncodeToken::old_offset(index, length, offset));
                        last_match = Some((length, offset));
                    }
                    (length, offset)
                }
                SelectedMatch::ShortOffset { offset } => {
                    let length = 2;
                    tokens.push(EncodeToken::short_offset(offset));
                    last_match = Some((length, offset));
                    (length, offset)
                }
            };
            push_old_offset(&mut old_offsets, offset);
            for history_pos in pos..pos + length {
                finder.insert(combined, history_pos);
            }
            pos += length;
        } else {
            tokens.push(EncodeToken::Literal(combined[pos]));
            finder.insert(combined, pos);
            pos += 1;
        }
        let consumed = pos - start;
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
    if progress.is_some_and(|report| !report(end - start)) {
        return Err(Error::Cancelled);
    }
    Ok(tokens)
}

/// Stand-in price for a symbol the current table has no code for.
const ABSENT_SYMBOL_BITS: usize = 15;

#[derive(Debug, Clone, Copy)]
struct CostModel<'a> {
    main: &'a [u8],
    offsets: &'a [u8],
    lengths: &'a [u8],
    /// Running literal totals, so pricing a span is two lookups, not a loop.
    literal_totals: Option<&'a LiteralTotals>,
    cheapest_fresh_length: usize,
}

impl<'a> CostModel<'a> {
    fn new(table_lengths: &'a [u8; TABLE_COUNT]) -> Self {
        let main = &table_lengths[..MAIN_COUNT];
        let cheapest_fresh_length = (0..LENGTH_COUNT)
            .map(|slot| usize::from(main[270 + slot]) + usize::from(LENGTH_BITS[slot]))
            .min()
            .unwrap_or(0);
        Self {
            main,
            offsets: &table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT],
            lengths: &table_lengths[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT],
            literal_totals: None,
            cheapest_fresh_length,
        }
    }

    fn with_literal_totals<'b>(self, totals: &'b LiteralTotals) -> CostModel<'b>
    where
        'a: 'b,
    {
        CostModel {
            literal_totals: Some(totals),
            ..self
        }
    }

    fn literal_price(self, byte: u8) -> usize {
        match self.main[usize::from(byte)] {
            0 => ABSENT_SYMBOL_BITS,
            bits => usize::from(bits),
        }
    }

    /// A candidate shorter than this cannot save `bits`, so one byte rules it out.
    fn shortest_saving_length(
        self,
        input: &[u8],
        pos: usize,
        bits: usize,
        max_length: usize,
    ) -> Option<usize> {
        let Some(totals) = self.literal_totals else {
            return (1..=max_length).find(|&length| self.literal_bits(input, pos, length) >= bits);
        };
        totals.shortest_reaching(pos, bits, max_length)
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
        let end = (pos + length).min(input.len());
        if let Some(totals) = self.literal_totals {
            return totals.between(pos, end);
        }
        input[pos..end]
            .iter()
            .map(|&byte| self.literal_price(byte))
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

/// How far ahead each rebuild prices; re-pricing the overlapped reach costs under 1% at this span.
const LITERAL_TOTALS_SPAN: usize = 64 * 1024;

/// Totals over the stretch ahead of the parse only, since no span priced reaches further.
#[derive(Debug, Default)]
struct LiteralTotals {
    base: usize,
    totals: Vec<u32>,
}

impl LiteralTotals {
    /// Rebuilds only when the parse has run past what was priced.
    fn cover(&mut self, model: CostModel<'_>, input: &[u8], pos: usize, reach: usize) {
        let want = pos.saturating_add(reach).min(input.len());
        if pos >= self.base && want - self.base < self.totals.len() {
            return;
        }
        let end = pos
            .saturating_add(reach.max(LITERAL_TOTALS_SPAN))
            .min(input.len());
        self.base = pos;
        self.totals.clear();
        // Totals wrap past a few hundred MiB; a span is at most a match, so differences stay exact.
        let mut total = 0u32;
        self.totals.push(total);
        for &byte in &input[pos..end] {
            total = total.wrapping_add(model.literal_price(byte) as u32);
            self.totals.push(total);
        }
    }

    fn between(&self, pos: usize, end: usize) -> usize {
        self.totals[end - self.base].wrapping_sub(self.totals[pos - self.base]) as usize
    }

    /// Totals only rise along a span, so a binary search finds the first length reaching `bits`.
    fn shortest_reaching(&self, pos: usize, bits: usize, max_length: usize) -> Option<usize> {
        let at = pos - self.base;
        let base = self.totals[at];
        let span = &self.totals[at + 1..=at + max_length];
        let below = span.partition_point(|&total| (total.wrapping_sub(base) as usize) < bits);
        (below < max_length).then_some(below + 1)
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

fn select_match(context: &SearchContext<'_>, pos: usize) -> Option<SelectedMatch> {
    let SearchContext {
        input,
        end,
        finder,
        pairs,
        options,
        old_offsets,
        cost_model,
    } = *context;
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
            pairs.nearest(input, pos, end),
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
        (None, None) => pairs.nearest(input, pos, end),
    }
}

#[derive(Clone, Copy)]
struct SearchContext<'a> {
    input: &'a [u8],
    end: usize,
    finder: &'a FreshMatches<'a>,
    pairs: &'a PairTable,
    options: EncodeOptions,
    old_offsets: &'a [usize; 4],
    cost_model: Option<&'a CostModel<'a>>,
}

fn should_lazy_emit_literal(
    pos: usize,
    current: SelectedMatch,
    context: &SearchContext<'_>,
) -> bool {
    if !context.options.lazy_matching {
        return false;
    }
    let lookahead = context.options.lazy_lookahead.max(1);
    (1..=lookahead)
        .take_while(|offset| pos + offset < context.end)
        .any(|offset| {
            select_match(context, pos + offset).is_some_and(|next| {
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

/// Lists collected for the shortest-path parse spare its greedy seed a search of its own.
enum FreshMatches<'a> {
    Chain(Rar20MatchFinder),
    Listed(ListCursor<'a>),
}

impl FreshMatches<'_> {
    /// Takes positions in order, each once, from the block's start.
    fn insert(&mut self, input: &[u8], pos: usize) {
        match self {
            Self::Chain(finder) => finder.insert(input, pos),
            Self::Listed(cursor) => cursor.step(pos),
        }
    }
}

struct ListCursor<'a> {
    lists: &'a MatchLists,
    start: usize,
    inserted: usize,
    next_run: usize,
}

impl<'a> ListCursor<'a> {
    fn new(lists: &'a MatchLists, start: usize) -> Self {
        Self {
            lists,
            start,
            inserted: 0,
            next_run: 0,
        }
    }

    fn step(&mut self, pos: usize) {
        debug_assert_eq!(
            pos,
            self.start + self.inserted,
            "list positions taken out of order"
        );
        self.next_run += usize::from(self.lists.counts[self.inserted]);
        self.inserted += 1;
    }

    /// The last run at a position is its longest, at the nearest offset reaching it.
    fn longest(&self, pos: usize) -> Option<(usize, usize)> {
        let counts = &self.lists.counts[self.inserted..];
        let ahead = pos - (self.start + self.inserted);
        let first = self.next_run
            + counts[..ahead]
                .iter()
                .map(|&count| usize::from(count))
                .sum::<usize>();
        let count = usize::from(counts[ahead]);
        (count != 0).then(|| {
            let found = self.lists.runs[first + count - 1];
            (found.length(), found.offset())
        })
    }
}

fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &FreshMatches<'_>,
    options: EncodeOptions,
    cost_model: Option<&CostModel<'_>>,
) -> Option<(usize, usize)> {
    let finder = match finder {
        FreshMatches::Chain(finder) => finder,
        FreshMatches::Listed(cursor) => {
            debug_assert!(cost_model.is_none(), "listed matches are not priced");
            return cursor.longest(pos);
        }
    };
    let max_offset = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0 || max_offset == 0 || max_length < 3 {
        return None;
    }
    let mut best: Option<(usize, usize)> = None;
    let mut best_score = isize::MIN;
    let mut reach_cache = PricedReach {
        offsets: 0..0,
        score: isize::MIN,
        length: 0,
    };
    let mut checked = 0usize;
    // No match under three bytes is encodable, so a candidate that differs in
    // its first three needs no measuring. On data with nothing to find that
    // is every candidate at every position.
    let prefix = &input[pos..pos + 3];
    let mut candidate = finder.first(input, pos);
    while candidate != match_finder::NO_POSITION {
        // Callers search before inserting this position, so every candidate is older.
        let offset = pos - candidate;
        if offset > max_offset {
            break;
        }
        checked += 1;
        let best_length = best.map_or(0, |(length, _)| length);
        // The shortest match that could still displace the best. A candidate
        // shorter than that cannot win, and one byte decides whether it is.
        let must_reach = match cost_model {
            None => best_length + 1,
            Some(model) if best_score != isize::MIN => {
                // Offsets only grow along the chain, so one slot's threshold
                // serves every candidate until the slot or the best changes.
                if !(reach_cache.offsets.contains(&offset) && reach_cache.score == best_score) {
                    reach_cache = priced_reach(model, input, pos, offset, best_score, max_length);
                }
                reach_cache.length
            }
            Some(_) => 0,
        };
        // A best match reaching `max_length` breaks the loop, so without a
        // cost model `must_reach` never passes it.
        let reachable = (must_reach <= 1
            || (must_reach <= max_length
                && input[candidate + must_reach - 1] == input[pos + must_reach - 1]))
            && input[candidate..candidate + 3] == *prefix;
        if reachable {
            let length = super::super::fast::match_length(input, pos, offset, max_length);
            let encodable = length >= 3 + match_length_adjustment(offset);
            let better = encodable
                && match cost_model {
                    Some(model) => {
                        let score = model
                            .selected_score(SelectedMatch::Fresh { length, offset }, input, pos)
                            .unwrap_or(isize::MIN);
                        let better = best.is_none()
                            || score > best_score
                            || (score == best_score && length > best_length);
                        if better {
                            best_score = score;
                        }
                        better
                    }
                    // The hash chain visits nearest matches first, so an
                    // equal-length later candidate cannot have a smaller offset.
                    None => length > best_length,
                };
            if better {
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

struct PricedReach {
    offsets: std::ops::Range<usize>,
    score: isize,
    length: usize,
}

/// Every offset in a slot costs the same, so one threshold covers the slot.
fn priced_reach(
    model: &CostModel<'_>,
    input: &[u8],
    pos: usize,
    offset: usize,
    best_score: isize,
    max_length: usize,
) -> PricedReach {
    let Ok((slot, _)) = offset_slot_for_match(offset) else {
        return PricedReach {
            offsets: offset..offset + 1,
            score: best_score,
            length: 0,
        };
    };
    let first = OFFSET_BASES[slot] + 1;
    let offset_cost = usize::from(model.offsets[slot]) + usize::from(OFFSET_BITS[slot]);
    let worth = best_score + (model.cheapest_fresh_length + offset_cost) as isize;
    PricedReach {
        offsets: first..first + (1usize << OFFSET_BITS[slot]),
        score: best_score,
        length: model
            .shortest_saving_length(input, pos, worth.max(0) as usize, max_length)
            .unwrap_or(usize::MAX),
    }
}

fn offset_slot_index(offset: usize) -> usize {
    offset_slot_for_match(offset)
        .map(|(slot, _)| slot)
        .unwrap_or(OFFSET_BITS.len() - 1)
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
    // An old offset codes two bytes at the least.
    if max_length < 2 {
        return None;
    }
    let prefix = &input[pos..pos + 2];
    for (index, &offset) in old_offsets.iter().enumerate() {
        if offset == 0 || input[pos - offset..pos - offset + 2] != *prefix {
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

const MAX_SHORT_OFFSET: usize = 256;

/// Last start of each two-byte pair, so the nearest short match is one lookup, not a scan of every offset.
struct PairTable {
    // Positions wrap past 4 GiB; a lookup re-checks the bytes it is pointed at.
    last: Vec<u32>,
    indexed_to: usize,
}

impl PairTable {
    /// Pairs further back than a short offset reaches can never match.
    fn new(input: &[u8], start: usize) -> Self {
        let mut table = Self {
            last: vec![0; 1 << 16],
            indexed_to: start.saturating_sub(MAX_SHORT_OFFSET),
        };
        table.advance(input, start);
        table
    }

    fn pair(input: &[u8], pos: usize) -> usize {
        usize::from(u16::from_le_bytes([input[pos], input[pos + 1]]))
    }

    fn advance(&mut self, input: &[u8], pos: usize) {
        let through = pos.min(input.len().saturating_sub(1));
        for at in self.indexed_to..through {
            self.last[Self::pair(input, at)] = at as u32;
        }
        self.indexed_to = self.indexed_to.max(through);
    }

    fn nearest(&self, input: &[u8], pos: usize, end: usize) -> Option<SelectedMatch> {
        if end - pos < 2 {
            return None;
        }
        debug_assert!(
            pos >= self.indexed_to,
            "short-match lookup behind the table"
        );
        let pair = Self::pair(input, pos);
        let floor = pos.saturating_sub(MAX_SHORT_OFFSET);
        // A lazy lookahead asks about positions the table has not reached yet.
        let unindexed = (self.indexed_to.max(floor)..pos)
            .rev()
            .find(|&at| Self::pair(input, at) == pair);
        let found = unindexed.or_else(|| {
            let offset = (pos as u32).wrapping_sub(self.last[pair]) as usize;
            let at = pos.checked_sub(offset)?;
            (offset != 0 && at >= floor && Self::pair(input, at) == pair).then_some(at)
        });
        found.map(|at| SelectedMatch::ShortOffset { offset: pos - at })
    }
}

fn match_length_at_offset(input: &[u8], pos: usize, max_length: usize, offset: usize) -> usize {
    super::super::fast::match_length(input, pos, offset, max_length)
}

fn match_length_adjustment(offset: usize) -> usize {
    usize::from(offset >= LONGER_FRESH_OFFSET) + usize::from(offset >= 0x40000)
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
    if offset == 0 || offset > MAX_SHORT_OFFSET {
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

/// Codes the level alphabet by how often each symbol is used, not by how many
/// of them appear.
///
/// A flat code charges every symbol in play the same, so a table spelled
/// mostly in a few lengths pays as if they were spread evenly. On the bench's
/// small members, where the tables are a tenth of the packed bytes, that was
/// an eighth of every table and the whole of the gap to RAR 2.50 there.
///
/// The 19 lengths are written four bits each, hence the cap of 15.
fn level_code_lengths_for_tokens(tokens: &[LevelToken]) -> [u8; LEVEL_COUNT] {
    let mut frequencies = [0usize; LEVEL_COUNT];
    for token in tokens {
        frequencies[token.symbol] += 1;
    }
    // One symbol in play gives a code with one branch and an empty slot beside
    // it, which a strict reader rejects. Only the flat assignment pads it.
    if frequencies.iter().filter(|&&count| count != 0).count() <= 1 {
        return level_code_lengths_for_used_symbols(frequencies.map(|count| count != 0));
    }
    huffman::lengths_for_frequency_array(&frequencies, 15)
}

/// A whole member coded as one audio block.
#[cfg(test)]
fn encode_audio_member(input: &[u8], channels: usize) -> Result<Vec<u8>> {
    code_audio_block(input, channels, AudioCoder::default(), false).map(|(bits, _)| bits.finish())
}

/// The audio predictors, which a reader keeps across blocks of either kind,
/// and the channel of the next byte.
#[derive(Debug, Clone, Copy, Default)]
struct AudioCoder {
    states: [AudioState; MAX_CHANNELS],
    channel_delta: i32,
    channel: usize,
}

/// One block coded as audio. `more` ends it with the symbol that makes the
/// reader read new tables, coded for the channel that comes next.
fn code_audio_block(
    input: &[u8],
    channels: usize,
    mut coder: AudioCoder,
    more: bool,
) -> Result<(BitWriter, AudioCoder)> {
    if channels == 0 || channels > MAX_CHANNELS {
        return Err(Error::InvalidData("RAR 2.0 audio channel count is invalid"));
    }
    // A reader with fewer channels than before starts again at the first.
    if coder.channel >= channels {
        coder.channel = 0;
    }
    let first = coder.channel;
    let deltas = audio_encode(input, channels, &mut coder);
    let channel_of = |index: usize| (first + index) % channels;
    let mut levels = vec![0u8; AUDIO_COUNT * channels];
    for channel in 0..channels {
        let mut frequencies = [0usize; AUDIO_COUNT];
        for (index, &delta) in deltas.iter().enumerate() {
            if channel_of(index) == channel {
                frequencies[delta as usize] += 1;
            }
        }
        if more && channel == coder.channel {
            frequencies[256] += 1;
        }
        let channel_lengths = huffman::lengths_for_frequency_array(&frequencies, 15);
        for (symbol, len) in channel_lengths.into_iter().enumerate() {
            levels[channel * AUDIO_COUNT + symbol] = len;
        }
    }

    // The reader runs one loop over either kind of table, so audio levels take
    // the same run symbols as LZ ones.
    let level_tokens = encode_level_tokens(&levels);
    let level_lengths = level_code_lengths_for_tokens(&level_tokens);
    let level_codes = canonical_codes(&level_lengths)?;
    let mut bits = BitWriter::default();
    bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
    bits.write_bits((channels - 1) as u32, 2);
    for &len in &level_lengths {
        bits.write_bits(len as u32, 4);
    }
    for token in level_tokens {
        let code = level_codes[token.symbol].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing audio-level Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
        if token.extra_bits != 0 {
            bits.write_bits(token.extra_value as u32, token.extra_bits);
        }
    }

    let audio_codes = (0..channels)
        .map(|channel| canonical_codes(&levels[channel * AUDIO_COUNT..(channel + 1) * AUDIO_COUNT]))
        .collect::<Result<Vec<_>>>()?;
    for (index, &delta) in deltas.iter().enumerate() {
        let code = audio_codes[channel_of(index)][delta as usize].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing audio Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
    }
    if more {
        let code = audio_codes[coder.channel][256].ok_or(Error::InvalidData(
            "RAR 2.0 encoder missing audio new-tables Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
    }
    Ok((bits, coder))
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

fn audio_encode(input: &[u8], channels: usize, coder: &mut AudioCoder) -> Vec<u8> {
    let AudioCoder {
        states,
        channel_delta,
        channel: next_channel,
    } = coder;
    let mut deltas = Vec::with_capacity(input.len());
    for &byte in input {
        let channel = *next_channel;
        *next_channel = (channel + 1) % channels;
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
            + state.k[4] * *channel_delta;
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
        state.dif[9] = state.dif[9].wrapping_add((d - *channel_delta).unsigned_abs());
        state.dif[10] = state.dif[10].wrapping_add((d + *channel_delta).unsigned_abs());

        *channel_delta = (byte.wrapping_sub(state.last_char as u8)) as i8 as i32;
        state.last_delta = *channel_delta;
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

    /// Appends `other`'s bits, which need not start on a byte boundary here.
    fn append(&mut self, other: &BitWriter) {
        let whole = other.bit_pos / 8;
        if self.bit_pos.is_multiple_of(8) {
            self.bytes.extend_from_slice(&other.bytes[..whole]);
            self.bit_pos += whole * 8;
        } else {
            for chunk in other.bytes[..whole].chunks(7) {
                let value = chunk
                    .iter()
                    .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));
                super::super::fast::write_msb_bits(
                    &mut self.bytes,
                    &mut self.bit_pos,
                    value,
                    chunk.len() * 8,
                );
            }
        }
        let tail = other.bit_pos % 8;
        if tail != 0 {
            self.write_bits(u32::from(other.bytes[whole] >> (8 - tail)), tail as u8);
        }
    }

    /// Takes the bytes no later bit can change, leaving a partial last byte.
    fn take_whole_bytes(&mut self) -> Vec<u8> {
        let whole = self.bit_pos / 8;
        let rest = self.bytes.split_off(whole);
        self.bit_pos -= whole * 8;
        std::mem::replace(&mut self.bytes, rest)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "block_tests.rs"]
mod block_tests;
