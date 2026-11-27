//! RAR5/7 LZ encoding, block selection, token pricing and table emission.

use super::super::huffman;
use super::super::match_finder;
use super::super::noise::{self, NoiseScan};
use super::*;
#[cfg(test)]
use std::io::Write;

/// Matches shorter than 4 bytes are never emitted, so candidate positions are
/// chained by a hash of their first 4 bytes.
type Rar50MatchFinder<B = Allowance> = match_finder::MatchFinder<4, B>;

type Rar50TreeMatchFinder<B> = match_finder::TreeMatchFinder<B>;

#[cfg(test)]
fn test_match_finder(window: usize) -> Rar50MatchFinder {
    Rar50MatchFinder::with_allowance(window, &Allowance::default())
        .expect("unlimited finder allocation")
}

const MAX_ENCODER_MATCH_OFFSET: usize = DEFAULT_DICTIONARY_SIZE;

const MAX_ENCODER_MATCH_LENGTH: usize = 4096;

/// The largest block the format allows a writer to emit.
const MAX_COMPRESSED_BLOCK_OUTPUT: usize = 4 * 1024 * 1024;

/// How much input goes into one compressed block.
///
/// Every block carries its own Huffman tables, so smaller blocks pay for the
/// extra tables and win back more by fitting each stretch of the data. Matches
/// still reach back across boundaries into the history, so shortening a block
/// costs no match range. The streaming writer reads in the same units, so both
/// paths produce the same blocks for the same input.
pub(crate) const LZ_BLOCK_SIZE: usize = 64 * 1024;

const _: () = assert!(LZ_BLOCK_SIZE <= MAX_COMPRESSED_BLOCK_OUTPUT);
// Runs are read a block at a time, so they start and end on noise cells.
const _: () = assert!(LZ_BLOCK_SIZE.is_multiple_of(noise::CELL));

/// The most input one block may cover once blocks are being extended.
///
/// A block only grows over data whose byte distribution is not moving, so the
/// bytes it covers compress to very little and the output stays far inside
/// [`MAX_COMPRESSED_BLOCK_OUTPUT`]. The cap is what the writer charges its
/// workspace for, so it is a memory decision as much as a size one: the
/// optimal parse prices every position in a block and its arrays scale with
/// the block, so a mebibyte is the point where the extra table sets saved stop
/// being worth the pages.
pub(crate) const MAX_LZ_BLOCK_SIZE: usize = 1024 * 1024;

const _: () = assert!(MAX_LZ_BLOCK_SIZE <= MAX_COMPRESSED_BLOCK_OUTPUT);

/// How far a chunk's byte distribution may sit from the open block's before
/// the block is closed, as a fraction of the chunk.
///
/// The statistic is how many of the chunk's bytes the open block's model puts
/// in the wrong place, so the limit reads as "extend while under one in a
/// hundred and twenty-eight of the next chunk's bytes are distributed
/// differently".
///
/// Only data that does not move at all falls under 512. That is the whole
/// design: a block grows over data a fresh table set could not describe any
/// better, and over nothing else.
const BLOCK_DRIFT_DIVISOR: u64 = 128;

/// Decides where one block ends, from the raw bytes alone.
///
/// Both writers have to cut a member the same way or the same input packs to
/// different archives, and they see it differently: the buffered path holds
/// the whole member while the streaming path reads it a chunk at a time and
/// compresses a wave of blocks in parallel. So the rule reads only the bytes
/// already folded into the open block plus the chunk being considered, which
/// both of them have at the moment they have to decide.
///
/// Every block still carries its own tables. Extending a block is what WinRAR
/// does on data like this; the format's table-reuse flag would say the same
/// thing more directly, but no archive WinRAR writes sets it, so no third
/// party decoder is known to have been tested against one that does.
#[derive(Debug, Clone)]
pub(crate) struct BlockSplitter {
    counts: [u32; 256],
    total: u64,
}

impl Default for BlockSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockSplitter {
    pub(crate) const fn new() -> Self {
        Self {
            counts: [0; 256],
            total: 0,
        }
    }

    /// Folds a chunk into the open block.
    pub(crate) fn accept(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            self.counts[usize::from(byte)] += 1;
        }
        self.total += chunk.len() as u64;
    }

    /// Starts a new block.
    pub(crate) fn reset(&mut self) {
        self.counts = [0; 256];
        self.total = 0;
    }

    /// Whether the open block should swallow `chunk` rather than end before it.
    ///
    /// Integer arithmetic throughout, because a block boundary decided by
    /// floating point would let the same input pack to different archives on
    /// two platforms whose `log2` disagree in the last bit.
    /// An accepted chunk is folded into the block; refusal leaves it unchanged.
    pub(crate) fn try_extend(&mut self, chunk: &[u8]) -> bool {
        let Some(counts) = self.extension_counts(chunk) else {
            return false;
        };
        // The decision already counted every byte. Fold those counts instead
        // of scanning an accepted chunk a second time through accept().
        for (ours, theirs) in self.counts.iter_mut().zip(counts) {
            *ours += theirs;
        }
        self.total += chunk.len() as u64;
        true
    }

    #[cfg(test)]
    pub(crate) fn extends(&self, chunk: &[u8]) -> bool {
        self.extension_counts(chunk).is_some()
    }

    fn extension_counts(&self, chunk: &[u8]) -> Option<[u32; 256]> {
        let open = self.total;
        if open == 0 || chunk.is_empty() {
            return None;
        }
        if open + chunk.len() as u64 > MAX_LZ_BLOCK_SIZE as u64 {
            return None;
        }
        let mut counts = [0u32; 256];
        for &byte in chunk {
            counts[usize::from(byte)] += 1;
        }
        let chunk_len = chunk.len() as u64;
        // How many of the chunk's bytes the open block's distribution places
        // wrongly. Both sides are scaled by `open` so neither divides early.
        let mut misplaced = 0u64;
        for (theirs, ours) in counts.iter().zip(&self.counts) {
            misplaced += (u64::from(*theirs) * open).abs_diff(u64::from(*ours) * chunk_len);
        }
        (misplaced / open <= chunk_len / BLOCK_DRIFT_DIVISOR).then_some(counts)
    }
}

#[cfg(test)]
mod splitter_tests {
    use super::{BlockSplitter, LZ_BLOCK_SIZE, MAX_LZ_BLOCK_SIZE};

    #[test]
    fn drift_threshold_accepts_256_changed_bytes_and_refuses_257() {
        let initial = vec![0; LZ_BLOCK_SIZE];
        for (changed, accepted) in [(256, true), (257, false)] {
            let mut splitter = BlockSplitter::new();
            splitter.accept(&initial);
            let mut next = initial.clone();
            next[..changed].fill(1);
            assert_eq!(splitter.try_extend(&next), accepted);
            if accepted {
                assert_eq!(splitter.total, (2 * LZ_BLOCK_SIZE) as u64);
                assert_eq!(splitter.counts[0], (2 * LZ_BLOCK_SIZE - changed) as u32);
                assert_eq!(splitter.counts[1], changed as u32);
            } else {
                assert_eq!(splitter.total, LZ_BLOCK_SIZE as u64);
                assert_eq!(splitter.counts[0], LZ_BLOCK_SIZE as u32);
                assert_eq!(splitter.counts[1], 0);
            }
            assert!(splitter.counts[2..].iter().all(|&count| count == 0));
        }
    }

    #[test]
    fn one_pass_extension_preserves_decisions_counts_and_refused_state() {
        let initial = vec![0; LZ_BLOCK_SIZE];
        for changed in [0, 1, 128, 255, 256, 257, 512, 1024] {
            let mut next = initial.clone();
            next[..changed].fill(1);
            let mut reference = BlockSplitter::new();
            let mut actual = BlockSplitter::new();
            assert!(!actual.try_extend(&next));
            assert_eq!(actual.counts, reference.counts);
            assert_eq!(actual.total, reference.total);
            reference.accept(&initial);
            actual.accept(&initial);
            for chunk in [&next[..], &initial[..], &[][..], &next[..], &initial[..31]] {
                let expected = reference.extends(chunk);
                assert_eq!(actual.try_extend(chunk), expected, "changed={changed}");
                if expected {
                    reference.accept(chunk);
                }
                assert_eq!(actual.counts, reference.counts);
                assert_eq!(actual.total, reference.total);
            }
        }
        let mut reference = BlockSplitter::new();
        let mut actual = BlockSplitter::new();
        reference.accept(&vec![7; MAX_LZ_BLOCK_SIZE - LZ_BLOCK_SIZE]);
        actual.accept(&vec![7; MAX_LZ_BLOCK_SIZE - LZ_BLOCK_SIZE]);
        for length in [LZ_BLOCK_SIZE, 1, 0] {
            let chunk = vec![7; length];
            let expected = reference.extends(&chunk);
            assert_eq!(actual.try_extend(&chunk), expected);
            if expected {
                reference.accept(&chunk);
            }
            assert_eq!(actual.counts, reference.counts);
            assert_eq!(actual.total, reference.total);
        }
    }
}

const MAX_BLOCK_HEADER_BYTES: u64 = 5;
const MAX_BLOCK_TABLE_BYTES: u64 = 1_248;

/// From format limits and two encoder invariants, so no tuning of what the
/// encoder chooses can outgrow it.
pub(crate) fn packed_most(input_size: u64) -> u64 {
    // The encoder never codes an empty block but perhaps the last, and gives a
    // block no more filter records than it has bytes: each covers at least
    // one byte of its block, and the filtered ranges are disjoint. A block is five header bytes
    // and at most 1,248 bytes of tables: twenty level lengths of eight bits,
    // 446 lengths of a fifteen-bit code and seven extra bits, and byte padding.
    const BLOCK_MOST: u64 = MAX_BLOCK_HEADER_BYTES + MAX_BLOCK_TABLE_BYTES;
    // A filter record, or a match of fifteen main bits, nine length bits,
    // fifteen distance bits, 34 raw distance bits and a fifteen-bit align
    // code, at most 91 bits; any token but a filter covers at least one byte.
    const TOKEN_MOST: u64 = 12;
    input_size
        .saturating_add(1)
        .saturating_mul(BLOCK_MOST + 2 * TOKEN_MOST)
}

/// The most bytes one filter record is given to cover. A longer filtered range
/// goes out as several records.
const MAX_FILTER_BLOCK_LENGTH: usize = 0x3ffff;

/// The most bytes a member's filter record covers.
///
/// A member's filters are cut at every multiple of this from the start of the
/// data, and each piece is a record (see [`filter_cells_in_place`]). Blocks
/// are cut on the same grid, so no piece straddles one. A reader holds a
/// record's bytes twice while it filters them, so this sets how much filter
/// memory it needs, and readers can be given a limit on it. WinRAR 7.12
/// writes no longer record.
const FILTER_CELL: usize = LZ_BLOCK_SIZE;

const _: () =
    assert!(FILTER_CELL <= MAX_FILTER_BLOCK_LENGTH && LZ_BLOCK_SIZE.is_multiple_of(FILTER_CELL));

/// The most channels a RAR 5 delta filter record can name. The count is written
/// as five bits biased by one, so this is what the format can say, not a policy.
pub(crate) const MAX_DELTA_CHANNELS: usize = 32;

/// Where the encoder stops looking for anything better.
///
/// A search that has reached this far ends, whether it is a chain walk or a
/// tree descent, and the optimal parse takes the
/// match and steps over the bytes it covers instead of pricing each of them. The
/// second half matters more than it sounds. The parse prices every position in a
/// block, because a cheaper path can arrive at any of them, so without it a
/// 4 KiB match gets confirmed at all 4096 of its positions to learn what the
/// first one already said.
///
/// 512 is where committing is free. Committing sooner buys time but packs
/// larger.
const NICE_MATCH_LENGTH: usize = 512;

const MAX_MATCH_CANDIDATES: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
struct LengthSlices<'a> {
    main: &'a [u8],
    distance: &'a [u8],
    align: &'a [u8],
    length: &'a [u8],
}

impl<B: Budget> OwnedLengths<B> {
    fn slices(&self) -> LengthSlices<'_> {
        LengthSlices {
            main: &self.main,
            distance: &self.distance,
            align: &self.align,
            length: &self.length,
        }
    }
}

pub fn encode_table_lengths(lengths: &TableLengths, algorithm_version: u8) -> Result<Vec<u8>> {
    encode_table_lengths_with_bit_count(lengths, algorithm_version).map(|(data, _)| data)
}

pub fn encode_table_lengths_with_bit_count(
    lengths: &TableLengths,
    algorithm_version: u8,
) -> Result<(Vec<u8>, usize)> {
    encode_table_slices(
        LengthSlices {
            main: &lengths.main,
            distance: &lengths.distance,
            align: &lengths.align,
            length: &lengths.length,
        },
        algorithm_version,
        &Allowance::default(),
    )
    .map(|(bytes, bits)| (bytes.into_vec(), bits))
}

fn encode_table_slices<B: Budget>(
    lengths: LengthSlices<'_>,
    algorithm_version: u8,
    allowance: &B,
) -> Result<(Buffer<u8, B>, usize)> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    if lengths.main.len() != MAIN_TABLE_SIZE
        || lengths.distance.len() != distance_size
        || lengths.align.len() != ALIGN_TABLE_SIZE
        || lengths.length.len() != LENGTH_TABLE_SIZE
    {
        return Err(Error::InvalidData("RAR 5 table length count mismatch"));
    }

    // The version and all four slice lengths were checked above. They form
    // one exact-sized table, so assembly cannot request further growth.
    let flattened = Buffer::from_slices(
        &[
            lengths.main,
            lengths.distance,
            lengths.align,
            lengths.length,
        ],
        allowance,
    )?;
    for &length in flattened.iter() {
        if length > 15 {
            return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
        }
    }

    let level_tokens = encode_table_level_tokens_with_allowance(&flattened, allowance)?;
    let level_lengths = level_code_lengths_with_allowance(&level_tokens, allowance)?;
    let level_table = EncoderCodeTable::from_lengths(&level_lengths, allowance)?;
    let mut writer = BitWriter::with_allowance(allowance);
    try_write_level_lengths(&mut writer, &level_lengths)?;
    for token in level_tokens.iter() {
        let (code, len) = level_table.code_for_present_symbol(token.symbol);
        writer
            .try_write_bits(usize::from(code), usize::from(len))
            .map_err(Into::into)?;
        if token.extra_bits != 0 {
            writer
                .try_write_bits(
                    usize::from(token.extra_value),
                    usize::from(token.extra_bits),
                )
                .map_err(Into::into)?;
        }
    }
    let bit_count = writer.bit_pos;
    Ok((writer.bytes, bit_count))
}

pub fn encode_compressed_block(
    payload: &[u8],
    payload_bits: usize,
    has_tables: bool,
    is_last: bool,
) -> Result<Vec<u8>> {
    encode_compressed_block_with_allowance(
        payload,
        payload_bits,
        has_tables,
        is_last,
        &Allowance::default(),
    )
    .map(Buffer::into_vec)
}

fn encode_compressed_block_with_allowance<B: Budget>(
    payload: &[u8],
    payload_bits: usize,
    has_tables: bool,
    is_last: bool,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    if payload_bits > payload.len() * 8 {
        return Err(Error::InvalidData("RAR 5 block bit count exceeds payload"));
    }
    if !payload.is_empty() && payload_bits <= (payload.len() - 1) * 8 {
        return Err(Error::InvalidData("RAR 5 block has unused payload bytes"));
    }
    if payload.len() > 0x00ff_ffff {
        return Err(Error::InvalidData("RAR 5 block payload is too large"));
    }

    let size_len = if payload.len() <= 0xff {
        1
    } else if payload.len() <= 0xffff {
        2
    } else {
        3
    };
    let final_byte_bits = if payload.is_empty() {
        1
    } else {
        ((payload_bits - 1) % 8) + 1
    };
    let mut flags = (final_byte_bits as u8) - 1;
    flags |= ((size_len - 1) as u8) << 3;
    if is_last {
        flags |= 0x40;
    }
    if has_tables {
        flags |= 0x80;
    }

    let mut size_bytes = [0u8; 3];
    let mut size = payload.len();
    for byte in &mut size_bytes[..size_len] {
        *byte = size as u8;
        size >>= 8;
    }
    let checksum = size_bytes[..size_len]
        .iter()
        .fold(0x5a ^ flags, |acc, &byte| acc ^ byte);
    // The header and bounded payload have an exact final size.
    Buffer::from_slices(
        &[&[flags, checksum], &size_bytes[..size_len], payload],
        allowance,
    )
}

pub fn encode_literal_only(data: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; distance_size],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    let present = literal_presence(data);
    let literal_count = present.iter().filter(|&&used| used).count();
    let literal_length = huffman::bits_for_symbol_count(literal_count);
    let mut literal_codes = [0u16; 256];
    let mut next_code = 0u16;
    for (symbol, used) in present.into_iter().enumerate() {
        if used {
            lengths.main[symbol] = literal_length;
            // Every literal has the same length, so canonical order is simply
            // the order of the present byte values.
            literal_codes[symbol] = next_code;
            next_code += 1;
        }
    }

    // The version, table sizes and generated lengths are all fixed above;
    // malformed-table errors remain available on the public table encoder.
    let (table_data, table_bits) = encode_table_lengths_with_bit_count(&lengths, algorithm_version)
        .expect("generated literal table is valid");
    let mut writer = BitWriter {
        bytes: Buffer::from_vec(table_data),
        bit_pos: table_bits,
    };
    for &byte in data {
        writer.write_bits(
            usize::from(literal_codes[byte as usize]),
            usize::from(literal_length),
        );
    }
    let payload_bits = writer.bit_pos;
    encode_compressed_block(&writer.finish(), payload_bits, true, true)
}

pub fn encode_lz_member(data: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
    encode_lz_member_with_history(data, &[], algorithm_version)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeOptions {
    pub max_match_candidates: usize,
    pub lazy_matching: bool,
    pub lazy_lookahead: usize,
    pub max_match_distance: usize,
    pub optimal_parse: bool,
    /// A match this long is taken without searching or pricing the positions
    /// it covers. Held between 8 and the longest match the encoder emits.
    pub nice_match_length: usize,
    /// How many times the optimal parse prices each block, at least once.
    pub parse_passes: usize,
    /// Parse greedily: take the best match at each position, searching only
    /// the remembered distances and `max_match_candidates` chain positions,
    /// without looking ahead. The fastest parse there is. Lazy matching and
    /// the optimal parse each take precedence over it.
    pub greedy: bool,
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            lazy_matching: false,
            lazy_lookahead: 1,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            optimal_parse: false,
            nice_match_length: NICE_MATCH_LENGTH,
            parse_passes: OPTIMAL_PARSE_PASSES,
            greedy: false,
        }
    }

    pub const fn with_greedy(mut self, enabled: bool) -> Self {
        self.greedy = enabled;
        self
    }

    pub const fn with_nice_match_length(mut self, length: usize) -> Self {
        self.nice_match_length = length;
        self
    }

    pub const fn with_parse_passes(mut self, passes: usize) -> Self {
        self.parse_passes = passes;
        self
    }

    pub(crate) const fn parses_greedily(&self) -> bool {
        self.greedy && !self.lazy_matching && !self.optimal_parse
    }

    fn nice(&self) -> usize {
        self.nice_match_length.clamp(8, MAX_ENCODER_MATCH_LENGTH)
    }

    pub const fn with_optimal_parse(mut self, enabled: bool) -> Self {
        self.optimal_parse = enabled;
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

    pub const fn with_max_match_distance(mut self, distance: usize) -> Self {
        self.max_match_distance = distance;
        self
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new(MAX_MATCH_CANDIDATES)
    }
}

pub fn encode_lz_member_with_history(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(
        data,
        history,
        algorithm_version,
        EncodeOptions::default(),
        None,
    )
}

pub fn encode_lz_member_with_options(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_with_history_and_options(data, &[], algorithm_version, options)
}

#[cfg(test)]
pub(crate) fn encode_lz_member_with_options_and_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, &[], algorithm_version, options, Some(progress))
}

#[cfg(test)]
pub(crate) fn encode_lz_reader_to(
    reader: &mut dyn Read,
    input_size: u64,
    output: &mut dyn Write,
    algorithm_version: u8,
    options: EncodeOptions,
    block_size: usize,
    progress: Option<&mut dyn FnMut(u64) -> bool>,
) -> crate::Result<()> {
    reader_to_with_allowance(
        reader,
        input_size,
        output,
        algorithm_version,
        options,
        block_size,
        progress,
        &Allowance::default(),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn reader_to_with_allowance<B: Budget>(
    reader: &mut dyn Read,
    input_size: u64,
    output: &mut dyn Write,
    algorithm_version: u8,
    options: EncodeOptions,
    block_size: usize,
    mut progress: Option<&mut dyn FnMut(u64) -> bool>,
    allowance: &B,
) -> crate::Result<()> {
    if block_size == 0 {
        return Err(crate::Error::InvalidHeader(
            "RAR 5 streaming block size is zero",
        ));
    }
    let block_size = block_size.min(MAX_COMPRESSED_BLOCK_OUTPUT);
    let mut history = Buffer::new(allowance);
    let mut chunk = Buffer::filled(input_size.min(block_size as u64) as usize, 0u8, allowance)?;
    let mut block = Buffer::new(allowance);
    let mut remaining = input_size;
    let mut completed = 0u64;
    let mut held: Option<Buffer<u8, B>> = None;
    while remaining != 0 || held.is_some() {
        // One chunk, then further chunks while the data is not moving, which is
        // the cut [`BlockSplitter`] makes for the other two writers. Deciding
        // needs the chunk in hand, so the one that ends a block is held over.
        let mut splitter = BlockSplitter::new();
        block.clear();
        match held.take() {
            Some(first) => block
                .extend_from_slice(&first)
                .map_err(Into::<Error>::into)?,
            None => {
                let wanted = usize::try_from(remaining.min(block_size as u64))
                    .map_err(|_| crate::Error::InvalidHeader("RAR 5 block size overflows usize"))?;
                reader.read_exact(&mut chunk[..wanted])?;
                remaining -= wanted as u64;
                block
                    .extend_from_slice(&chunk[..wanted])
                    .map_err(Into::<Error>::into)?;
            }
        }
        splitter.accept(&block);
        while remaining != 0 {
            let wanted = usize::try_from(remaining.min(block_size as u64))
                .map_err(|_| crate::Error::InvalidHeader("RAR 5 block size overflows usize"))?;
            reader.read_exact(&mut chunk[..wanted])?;
            remaining -= wanted as u64;
            if !splitter.try_extend(&chunk[..wanted]) {
                held = Some(Buffer::copied(&chunk[..wanted], allowance)?);
                break;
            }
            block
                .extend_from_slice(&chunk[..wanted])
                .map_err(Into::<Error>::into)?;
        }
        let (window, start) = member_window_with_allowance(&block, &history, options, allowance)?;
        let packed = encode_lz_block_with_allowance(
            &window,
            start..window.len(),
            MemberSearch::Fresh,
            algorithm_version,
            &[],
            options,
            remaining == 0 && held.is_none(),
            None,
            allowance,
        )?;
        drop(window);
        output.write_all(&packed)?;
        history.remember(&block, options.max_match_distance)?;
        completed += block.len() as u64;
        if progress
            .as_deref_mut()
            .is_some_and(|report| !report(completed))
        {
            return Err(crate::Error::Cancelled);
        }
    }
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(crate::Error::InvalidHeader(
            "entry source size changed while compressing",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_lz_streaming_block(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    is_last: bool,
) -> Result<Vec<u8>> {
    encode_lz_block(
        data,
        history,
        algorithm_version,
        &[],
        options,
        is_last,
        None,
    )
}

/// Encode adjacent streaming blocks with one match finder seeded with the
/// history, chosen as [`searches_tree`] chooses for a member.
#[cfg(test)]
pub(crate) fn encode_lz_streaming_blocks(
    data: &[u8],
    history: &[u8],
    blocks: &[(usize, bool)],
    algorithm_version: u8,
    options: EncodeOptions,
    block_done: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<Vec<u8>>> {
    streaming_blocks_with_allowance(
        data,
        history,
        blocks,
        algorithm_version,
        options,
        block_done,
        &Allowance::default(),
    )
    .map(|outputs| outputs.into_iter().map(Buffer::into_vec).collect())
}

#[cfg(test)]
pub(crate) fn streaming_blocks_with_allowance<B: Budget>(
    data: &[u8],
    history: &[u8],
    blocks: &[(usize, bool)],
    algorithm_version: u8,
    options: EncodeOptions,
    block_done: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    streaming_blocks_with_records(
        data,
        history,
        blocks,
        None,
        algorithm_version,
        options,
        block_done,
        allowance,
    )
}

#[cfg(test)]
/// [`streaming_blocks_with_allowance`] over bytes already filtered in place by
/// [`filter_streaming_blocks_in_place`], whose records these are, one list to
/// a block. `history` is the window the decoder will hold, so it is filtered
/// wherever the runs before were.
#[allow(clippy::too_many_arguments)]
pub(crate) fn streaming_blocks_with_records<B: Budget>(
    data: &[u8],
    history: &[u8],
    blocks: &[(usize, bool)],
    records: Option<&[Buffer<EncodeFilter, B>]>,
    algorithm_version: u8,
    options: EncodeOptions,
    block_done: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    // Refuse bad ranges before the window is allocated, as a caller's budget
    // would otherwise report the allocation instead.
    check_streaming_blocks(data.len(), blocks, records)?;
    let (combined, start) = member_window_with_allowance(data, history, options, allowance)?;
    streaming_blocks_in_window(
        &combined,
        start,
        blocks,
        records,
        algorithm_version,
        options,
        block_done,
        allowance,
    )
}

fn check_streaming_blocks<B: Budget>(
    len: usize,
    blocks: &[(usize, bool)],
    records: Option<&[Buffer<EncodeFilter, B>]>,
) -> Result<()> {
    if records.is_some_and(|records| records.len() != blocks.len()) {
        return Err(Error::InvalidData(
            "RAR 5 streaming blocks and filter records differ in number",
        ));
    }
    let mut previous = 0;
    for &(end, _) in blocks {
        if end <= previous || end > len {
            return Err(Error::InvalidData("RAR 5 streaming block range is invalid"));
        }
        previous = end;
    }
    if previous != len {
        return Err(Error::InvalidData(
            "RAR 5 streaming blocks do not cover input",
        ));
    }
    Ok(())
}

/// [`streaming_blocks_with_records`] over one window that already holds the
/// history and then the run, so a caller that owns both in one buffer is not
/// copied into a third. The run starts at `start`; block ends are offsets into
/// the run, as there. History further back than the match distance is ignored,
/// as it is when the window is built from separate parts.
#[allow(clippy::too_many_arguments)]
pub(crate) fn streaming_blocks_in_window<B: Budget>(
    window: &[u8],
    start: usize,
    blocks: &[(usize, bool)],
    records: Option<&[Buffer<EncodeFilter, B>]>,
    algorithm_version: u8,
    options: EncodeOptions,
    block_done: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    if start > window.len() {
        return Err(Error::InvalidData(
            "RAR 5 streaming run starts past its window",
        ));
    }
    let skip = start.saturating_sub(options.max_match_distance);
    streaming_blocks_from(
        &window[skip..],
        start - skip,
        None,
        blocks,
        records,
        algorithm_version,
        options,
        block_done,
        allowance,
    )
}

/// [`streaming_blocks_in_window`] for a run whose window is one job's part of
/// a group's, with a finder handed out by the group's shared index.
///
/// `window` must end where the run does and start where the group's window
/// does, and the finder must stand at the run's start; nothing is trimmed.
/// The match finder then collects what the job's own would, which is what
/// keeps the output unchanged (#276). Only a run whose own window would use a
/// packed index ([`packed_index_fits`]) shares one, so never a run that starts
/// its member.
///
/// A filtered run passes the blocks and records [`filter_run_in_place`] gave
/// it, over a window already holding its filtered bytes. Its own encode,
/// [`encode_filtered_run`], parses those blocks with the same collector.
#[allow(clippy::too_many_arguments)]
pub(crate) fn streaming_blocks_with_finder<B: Budget>(
    window: &[u8],
    start: usize,
    finder: crate::codec::packed_chain::PackedMatchFinder<B>,
    blocks: &[(usize, bool)],
    records: Option<&[Buffer<EncodeFilter, B>]>,
    algorithm_version: u8,
    options: EncodeOptions,
    block_done: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    if start > window.len() || !options.optimal_parse {
        return Err(Error::InvalidData(
            "RAR 5 shared finder needs an optimal parse within its window",
        ));
    }
    streaming_blocks_from(
        window,
        start,
        Some(RunFinder::Packed(finder)),
        blocks,
        records,
        algorithm_version,
        options,
        block_done,
        allowance,
    )
}

/// [`streaming_blocks_in_window`] for a run whose tree its group seeded,
/// [`seed_run_tree`] or [`seed_chain`] given the same window, run and options.
#[allow(clippy::too_many_arguments)]
pub(crate) fn streaming_blocks_with_tree<B: Budget>(
    window: &[u8],
    start: usize,
    tree: Rar50TreeMatchFinder<B>,
    blocks: &[(usize, bool)],
    records: Option<&[Buffer<EncodeFilter, B>]>,
    algorithm_version: u8,
    options: EncodeOptions,
    block_done: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    if start > window.len() || !options.optimal_parse {
        return Err(Error::InvalidData(
            "RAR 5 shared tree needs an optimal parse within its window",
        ));
    }
    let skip = tree_history(start, options).start;
    streaming_blocks_from(
        &window[skip..],
        start - skip,
        Some(RunFinder::Tree(tree)),
        blocks,
        records,
        algorithm_version,
        options,
        block_done,
        allowance,
    )
}

#[allow(clippy::too_many_arguments)]
fn streaming_blocks_from<B: Budget>(
    combined: &[u8],
    start: usize,
    mut finder: Option<RunFinder<B>>,
    blocks: &[(usize, bool)],
    records: Option<&[Buffer<EncodeFilter, B>]>,
    algorithm_version: u8,
    options: EncodeOptions,
    mut block_done: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    let data = &combined[start..];
    check_streaming_blocks(data.len(), blocks, records)?;
    let records_of =
        |index: usize| -> &[EncodeFilter] { records.map_or(NO_RECORDS, |records| &records[index]) };

    let mut at = start;
    let mut output = Buffer::with_capacity(blocks.len(), allowance)?;
    // Block ends are offsets into `data`, so the bytes a block covers are the
    // step from the end before it. Reporting them as they land is what keeps a
    // progress bar moving: a whole member can be one run, and a run that
    // reports only when it finishes reports nothing until it is done.
    let mut reported = 0usize;
    let mut report = |end: usize, block_done: &mut Option<&mut dyn FnMut(usize) -> bool>| {
        let delta = end - reported;
        reported = end;
        match block_done {
            Some(report) => report(delta),
            None => true,
        }
    };
    if blocks.is_empty() {
        return Ok(output);
    }
    if pipelines::<B>(options) {
        let mut block_start = at;
        pipelined_optimal_blocks(
            combined,
            blocks.iter().enumerate().map(|(index, &(end, is_last))| {
                let block = block_start..start + end;
                block_start = block.end;
                (block, records_of(index), is_last)
            }),
            collector_at(combined, at, finder.take(), options, allowance)?,
            algorithm_version,
            options,
            &mut |block, packed| {
                output.push_admitted(packed);
                if !report(block.end - start, &mut block_done) {
                    return Err(Error::Cancelled);
                }
                Ok(())
            },
            allowance,
        )?;
        return Ok(output);
    }
    let mut search = if options.optimal_parse {
        SharedMemberSearch::Optimal(collector_at(
            combined,
            at,
            finder.take(),
            options,
            allowance,
        )?)
    } else {
        SharedMemberSearch::Lazy(member_finder_with_allowance(
            combined, at, options, allowance,
        )?)
    };
    for (index, &(end, is_last)) in blocks.iter().enumerate() {
        let end = start + end;
        output.push_admitted(encode_lz_block_with_allowance(
            combined,
            at..end,
            search.borrow(),
            algorithm_version,
            records_of(index),
            options,
            is_last,
            None,
            allowance,
        )?);
        at = end;
        if !report(end - start, &mut block_done) {
            return Err(Error::Cancelled);
        }
    }
    Ok(output)
}

pub fn encode_lz_member_with_history_and_options(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, history, algorithm_version, options, None)
}

/// The writer rejects these before compressing anything, so reaching this is
/// either a direct `codec` caller or a bug. Either way the codec stays total.
fn rar50_filter(kind: crate::FilterKind) -> Result<Rar50Filter> {
    Rar50Filter::try_from(kind)
        .map_err(|_| Error::InvalidData("RAR 5 has no builtin type for this filter"))
}

/// Applies `filters` to a copy of `data`, returning the transformed bytes and
/// the records that describe them.
#[cfg(test)]
pub(crate) fn filtered_lz_member(
    data: &[u8],
    filters: &[crate::FilterSpec],
) -> Result<(Vec<u8>, Vec<EncodeFilter>)> {
    filtered_member_with_allowance(data, filters, &Allowance::default())
        .map(|(data, records)| (data.into_vec(), records.into_vec()))
}

/// The bytes a decoder's window holds after [`encode_filtered_run`] codes
/// `data`, which starts `file_offset` bytes into its member, with `filters`.
pub(crate) fn filtered_run_bytes<B: Budget>(
    data: &[u8],
    filters: &[crate::FilterSpec],
    file_offset: usize,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let mut filtered = Buffer::copied(data, allowance)?;
    filter_cells_in_place(&mut filtered, filters, file_offset, allowance)?;
    Ok(filtered)
}

/// Each block a filtered run is coded in, by its end in the run and whether
/// it is the member's last, and the filter records it opens with.
pub(crate) type FilteredRunBlocks<B> =
    (Buffer<(usize, bool), B>, Buffer<Buffer<EncodeFilter, B>, B>);

/// Transforms a run in place into the bytes [`encode_filtered_run`] codes,
/// and returns the blocks it codes them in, in the form
/// [`streaming_blocks_with_finder`] takes. A run in a window shared with its
/// neighbours is filtered where it lies, so the window holds what the
/// decoder's will.
pub(crate) fn filter_run_in_place<B: Budget>(
    data: &mut [u8],
    filters: &[crate::FilterSpec],
    file_offset: usize,
    is_last: bool,
    allowance: &B,
) -> Result<FilteredRunBlocks<B>> {
    let len = data.len();
    let blocks = filter_blocks_in_place(data, filters, file_offset, allowance)?;
    let mut ends = Buffer::with_capacity(blocks.len(), allowance)?;
    let mut records = Buffer::with_capacity(blocks.len(), allowance)?;
    for (block, block_records) in blocks {
        ends.push_admitted((block.end, is_last && block.end == len));
        records.push_admitted(block_records);
    }
    Ok((ends, records))
}

/// The end of each block [`filter_run_in_place`] cuts a run of `data` into,
/// which it decides from the bytes before they are filtered.
pub(crate) fn filtered_run_cuts(data: &[u8]) -> impl Iterator<Item = usize> + '_ {
    MemberBlocks::new(data, 0).map(|block| block.end)
}

/// One run of a member, `file_offset` bytes in, with `filters` ranged over the
/// run. `history` is what the window already holds, so it is filtered bytes
/// wherever earlier runs were filtered.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_filtered_run<B: Budget>(
    data: &[u8],
    filters: &[crate::FilterSpec],
    history: &[u8],
    file_offset: usize,
    is_last: bool,
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    filtered_lz_blocks(
        data,
        filters,
        history,
        file_offset,
        is_last,
        algorithm_version,
        options,
        progress,
        allowance,
    )
}

fn filtered_member_with_allowance<B: Budget>(
    data: &[u8],
    filters: &[crate::FilterSpec],
    allowance: &B,
) -> Result<(Buffer<u8, B>, Buffer<EncodeFilter, B>)> {
    let mut filtered = Buffer::copied(data, allowance)?;
    let mut records = Buffer::with_capacity(filters.len(), allowance)?;
    for filter in filters {
        let range = filter.range.clone().unwrap_or(0..data.len());
        if range.start >= range.end || range.end > data.len() {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        let filter_data = &mut filtered[range.clone()];
        let (filter_type, channels) = encode_filter_data(
            rar50_filter(filter.kind)?,
            filter_data,
            range.start,
            allowance,
        )?;
        records.push_admitted(EncodeFilter {
            offset: range.start,
            length: range.len(),
            filter_type,
            channels,
        });
    }
    Ok((filtered, records))
}

fn encode_filter_data<B: Budget>(
    kind: Rar50Filter,
    data: &mut [u8],
    file_offset: usize,
    allowance: &B,
) -> Result<(FilterType, usize)> {
    if file_offset > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter offset is too large"));
    }
    match kind {
        Rar50Filter::Delta { channels } => {
            let transformed = filters::delta_encode_with_allowance(
                data,
                channels,
                rar50_delta_messages(),
                allowance,
            )?;
            data.copy_from_slice(&transformed);
            Ok((FilterType::Delta, channels))
        }
        Rar50Filter::E8 => {
            e8e9_encode(data, file_offset as u32, false);
            Ok((FilterType::E8, 0))
        }
        Rar50Filter::E8E9 => {
            e8e9_encode(data, file_offset as u32, true);
            Ok((FilterType::E8E9, 0))
        }
        Rar50Filter::Arm => {
            arm_encode(data, file_offset as u32);
            Ok((FilterType::Arm, 0))
        }
    }
}

/// Transforms the member and cuts it into the blocks a filter record can
/// describe, then compresses those blocks against one search state.
///
/// The transform runs first and over the whole member, because the search has
/// to read final bytes: a block reaches back into the ones before it, and a
/// match must point at what the decoder will really have. Each block still
/// gets its own records covering only its own bytes, so a filtered range
/// spanning several blocks converts exactly as it did when each block was
/// transformed alone: the transform reads an absolute file offset, which the
/// cut does not change.
///
/// Compressing each block against a fresh copy of its history would re-copy
/// and re-insert 126 MiB for a 4 MiB member at 64 KiB a block.
#[allow(clippy::too_many_arguments)]
fn filtered_lz_blocks<B: Budget>(
    data: &[u8],
    filters: &[crate::FilterSpec],
    history: &[u8],
    file_offset: usize,
    is_last: bool,
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let start = history.len();
    let mut combined = Buffer::from_slices(&[history, data], allowance)?;
    let blocks = filter_blocks_in_place(&mut combined[start..], filters, file_offset, allowance)?;
    if pipelines::<B>(options) {
        let mut out = Buffer::new(allowance);
        let end = combined.len();
        pipelined_optimal_blocks(
            &combined,
            blocks.into_iter().map(|(block, records)| {
                let block = start + block.start..start + block.end;
                let last = is_last && block.end == end;
                (block, records, last)
            }),
            OptimalCollector::with_allowance(&combined, start, options, allowance)?,
            algorithm_version,
            options,
            &mut |block, packed| {
                out.extend_from_slice(&packed).map_err(Into::into)?;
                report_through(&mut progress, block.end - start)
            },
            allowance,
        )?;
        return Ok(out);
    }

    // One search state for the whole member, as the unfiltered path has.
    let mut search = if options.optimal_parse {
        SharedMemberSearch::Optimal(OptimalCollector::with_allowance(
            &combined, start, options, allowance,
        )?)
    } else {
        SharedMemberSearch::Lazy(member_finder_with_allowance(
            &combined, start, options, allowance,
        )?)
    };

    let mut out = Buffer::new(allowance);
    for (block, records) in blocks {
        let mut chunk_progress = |position: usize| {
            progress
                .as_deref_mut()
                .is_none_or(|report| report(block.start.saturating_add(position)))
        };
        let packed = encode_lz_block_with_allowance(
            &combined,
            start + block.start..start + block.end,
            search.borrow(),
            algorithm_version,
            &records,
            options,
            is_last && block.end == data.len(),
            Some(&mut chunk_progress),
            allowance,
        )?;
        out.extend_from_slice(&packed).map_err(Into::into)?;
    }
    Ok(out)
}

type FilteredBlocks<B> = Buffer<(Range<usize>, Buffer<EncodeFilter, B>), B>;

/// Transforms `data`, which starts `file_offset` bytes into its member, and
/// cuts it into the blocks it is coded in. Returns each block's range and
/// records.
///
/// The blocks are the ones the member would be cut into unfiltered (see
/// [`MemberBlocks`]), judged on the bytes as they were before the transform,
/// as the streaming writer judges them when it reads the member. The
/// transform is [`filter_cells_in_place`]'s, which does not depend on where
/// the blocks fall, so a filter costs its member no blocks of its own, only
/// a few bytes of record for each [`FILTER_CELL`] it covers.
fn filter_blocks_in_place<B: Budget>(
    data: &mut [u8],
    filters: &[crate::FilterSpec],
    file_offset: usize,
    allowance: &B,
) -> Result<FilteredBlocks<B>> {
    // Every cut is decided before any byte is transformed.
    let cuts = Buffer::collect(MemberBlocks::new(data, 0), allowance)?;
    let mut records = filter_cells_in_place(data, filters, file_offset, allowance)?
        .into_iter()
        .peekable();
    let mut blocks = Buffer::with_capacity(cuts.len(), allowance)?;
    for block in cuts {
        let mut own = Buffer::new(allowance);
        // Blocks are cut on the cell grid, so a cell's records all fall in
        // one block.
        while let Some(record) = records.next_if(|record| record.offset < block.end) {
            own.push(EncodeFilter {
                offset: record.offset - block.start,
                ..record
            })
            .map_err(Into::into)?;
        }
        blocks.push_admitted((block, own));
    }
    Ok(blocks)
}

/// Transforms `data`, which starts `file_offset` bytes into its member, one
/// [`FILTER_CELL`] at a time. Each filter is cut at every multiple of a cell
/// from the start of `data`, and each piece converts on its own and gets a
/// record of its own, which is how the decoder undoes it: an x86 call or a
/// delta plane that straddles a cut converts on each side separately.
/// Returns the records, with offsets into `data`, in the order the decoder
/// meets them.
fn filter_cells_in_place<B: Budget>(
    data: &mut [u8],
    filters: &[crate::FilterSpec],
    file_offset: usize,
    allowance: &B,
) -> Result<Buffer<EncodeFilter, B>> {
    let filters = normalized_filter_specs(data.len(), filters, allowance)?;
    let mut records = Buffer::new(allowance);
    for cell_start in (0..data.len()).step_by(FILTER_CELL) {
        let cell_end = (cell_start + FILTER_CELL).min(data.len());
        for filter in filters.iter() {
            let start = filter.range.start.max(cell_start);
            let end = filter.range.end.min(cell_end);
            if start >= end {
                continue;
            }
            let (filter_type, channels) = encode_filter_data(
                filter.kind,
                &mut data[start..end],
                file_offset + start,
                allowance,
            )?;
            records
                .push(EncodeFilter {
                    offset: start,
                    length: end - start,
                    filter_type,
                    channels,
                })
                .map_err(Into::into)?;
        }
    }
    Ok(records)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedFilterSpec {
    kind: Rar50Filter,
    range: Range<usize>,
}

/// Transforms a run of streaming blocks in place and returns each block's
/// filter records, for [`streaming_blocks_with_records`].
///
/// A solid run can hold the ends and starts of several members. `segments`
/// says where each member's bytes lie in `data` and how far into the member
/// they start, since a filter converts by position in its own file and not in
/// the stream. `filters` are ranged over `data`, each inside one segment.
///
/// A record covers bytes of one block and no more than a record can describe,
/// so a filter is cut at both, as [`filter_blocks_in_place`] cuts it.
pub(crate) fn filter_streaming_blocks_in_place<B: Budget>(
    data: &mut [u8],
    blocks: &[(usize, bool)],
    filters: &[crate::FilterSpec],
    segments: &[(Range<usize>, usize)],
    allowance: &B,
) -> Result<Buffer<Buffer<EncodeFilter, B>, B>> {
    let mut filters = normalized_filter_specs(data.len(), filters, allowance)?;
    filters.sort_unstable_by_key(|filter| filter.range.start);
    // `packed_most` counts on no more records in a block than it has bytes.
    debug_assert!(
        filters
            .windows(2)
            .all(|pair| pair[0].range.end <= pair[1].range.start),
        "solid filter ranges overlap"
    );
    let mut placed = Buffer::with_capacity(filters.len(), allowance)?;
    for filter in filters.iter() {
        let Some((segment, file_offset)) = segments.iter().find(|(segment, _)| {
            segment.start <= filter.range.start && filter.range.end <= segment.end
        }) else {
            return Err(Error::InvalidData(
                "RAR 5 solid filter does not lie in one member",
            ));
        };
        placed.push_admitted(file_offset + (filter.range.start - segment.start));
    }
    let mut records = Buffer::with_capacity(blocks.len(), allowance)?;
    let mut block_start = 0usize;
    for &(block_end, _) in blocks {
        let mut block_records = Buffer::new(allowance);
        for (filter, &file_offset) in filters.iter().zip(placed.iter()) {
            let mut start = filter.range.start.max(block_start);
            let end = filter.range.end.min(block_end);
            while start < end {
                let piece_end = (start + MAX_FILTER_BLOCK_LENGTH).min(end);
                let (filter_type, channels) = encode_filter_data(
                    filter.kind,
                    &mut data[start..piece_end],
                    file_offset + (start - filter.range.start),
                    allowance,
                )?;
                block_records
                    .push(EncodeFilter {
                        offset: start - block_start,
                        length: piece_end - start,
                        filter_type,
                        channels,
                    })
                    .map_err(Into::into)?;
                start = piece_end;
            }
        }
        records.push_admitted(block_records);
        block_start = block_end;
    }
    Ok(records)
}

fn normalized_filter_specs<B: Budget>(
    data_len: usize,
    filters: &[crate::FilterSpec],
    allowance: &B,
) -> Result<Buffer<NormalizedFilterSpec, B>> {
    let mut normalized = Buffer::with_capacity(filters.len(), allowance)?;
    for filter in filters {
        let range = filter.range.clone().unwrap_or(0..data_len);
        if range.start >= range.end || range.end > data_len {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        normalized.push_admitted(NormalizedFilterSpec {
            kind: rar50_filter(filter.kind)?,
            range,
        });
    }
    Ok(normalized)
}

fn encode_lz_member_inner(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    encode_member_with_allowance(
        data,
        history,
        algorithm_version,
        options,
        progress,
        &Allowance::default(),
    )
    .map(Buffer::into_vec)
}

pub(crate) fn encode_owned_member<B: Budget>(
    data: &[u8],
    version: u8,
    options: EncodeOptions,
    filters: Option<&[crate::FilterSpec]>,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    match filters {
        None => encode_member_with_allowance(data, &[], version, options, progress, allowance),
        Some(filters) => {
            EncoderState::new(options, allowance).encode(data, version, Some(filters), progress)
        }
    }
}

pub(crate) fn filtered_owned_member<B: Budget>(
    data: &[u8],
    filters: &[crate::FilterSpec],
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    filtered_member_with_allowance(data, filters, allowance).map(|(bytes, _)| bytes)
}

fn encode_member_with_allowance<B: Budget>(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let (window, start) = member_window_with_allowance(data, history, options, allowance)?;
    let combined = &*window;
    if data.len() > LZ_BLOCK_SIZE {
        // One search state for the whole member; building one per block
        // rehashes a window of history every 64 KiB, half the encode of a
        // 16 MiB member. The optimal parse's collector searches each block
        // once and lets the passes replay the answers.
        if pipelines::<B>(options) {
            let mut out = Buffer::new(allowance);
            pipelined_optimal_blocks(
                combined,
                MemberBlocks::new(combined, start)
                    .map(|block| (block.clone(), NO_RECORDS, block.end == combined.len())),
                OptimalCollector::with_allowance(combined, start, options, allowance)?,
                algorithm_version,
                options,
                &mut |block, packed| {
                    out.extend_from_slice(&packed).map_err(Into::into)?;
                    report_through(&mut progress, block.end - start)
                },
                allowance,
            )?;
            return Ok(out);
        }
        let mut search = if options.optimal_parse {
            SharedMemberSearch::Optimal(OptimalCollector::with_allowance(
                combined, start, options, allowance,
            )?)
        } else {
            SharedMemberSearch::Lazy(member_finder_with_allowance(
                combined, start, options, allowance,
            )?)
        };

        let mut out = Buffer::new(allowance);
        let mut completed = 0usize;
        for block in MemberBlocks::new(combined, start) {
            let is_last = block.end == combined.len();
            let mut chunk_progress = |position: usize| {
                progress
                    .as_deref_mut()
                    .is_none_or(|report| report(completed.saturating_add(position)))
            };
            let len = block.end - block.start;
            let packed = encode_lz_block_with_allowance(
                combined,
                block,
                search.borrow(),
                algorithm_version,
                &[],
                options,
                is_last,
                Some(&mut chunk_progress),
                allowance,
            )?;
            out.extend_from_slice(&packed).map_err(Into::into)?;
            completed = completed.saturating_add(len);
        }
        return Ok(out);
    }
    encode_lz_block_with_allowance(
        combined,
        start..combined.len(),
        MemberSearch::Fresh,
        algorithm_version,
        &[],
        options,
        true,
        progress,
        allowance,
    )
}

/// A member's LZ blocks, from `start` to the end of `combined`: one chunk at a
/// time, extended while the data is not moving. See [`BlockSplitter`].
struct MemberBlocks<'a> {
    combined: &'a [u8],
    start: usize,
    splitter: BlockSplitter,
}

impl<'a> MemberBlocks<'a> {
    fn new(combined: &'a [u8], start: usize) -> Self {
        Self {
            combined,
            start,
            splitter: BlockSplitter::new(),
        }
    }
}

impl Iterator for MemberBlocks<'_> {
    type Item = std::ops::Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let combined = self.combined;
        let block_start = self.start;
        if block_start >= combined.len() {
            return None;
        }
        self.splitter.reset();
        let mut block_end = (block_start + LZ_BLOCK_SIZE).min(combined.len());
        self.splitter.accept(&combined[block_start..block_end]);
        while block_end < combined.len() {
            let next_end = (block_end + LZ_BLOCK_SIZE).min(combined.len());
            if !self.splitter.try_extend(&combined[block_end..next_end]) {
                break;
            }
            block_end = next_end;
        }
        self.start = block_end;
        Some(block_start..block_end)
    }
}

/// How many bytes of blocks the pipelined parse holds at once, collected or
/// being priced. A member over this size is charged for one block of it (see
/// `tree_lz_workspace`), and a block's matches and parse arrays grow with its
/// bytes, so several smaller blocks in flight fit the same charge.
const PIPELINED_BLOCK_BYTES: usize = MAX_LZ_BLOCK_SIZE;

/// A member's optimal parse with its blocks priced on other threads.
///
/// The collector has to visit the blocks in order, one at a time, but nothing
/// it finds depends on prices, and no block's parse depends on another's. So
/// this thread collects the next batch while the pool prices the one before.
/// Each block is coded by the same functions as the sequential walk, so the
/// output is the same at every thread count.
///
/// `blocks` gives each block with the filter records it opens with and whether
/// it is the last. `emit` takes each block's packed bytes in order.
fn pipelined_optimal_blocks<B: Budget, R: std::ops::Deref<Target = [EncodeFilter]> + Send>(
    combined: &[u8],
    blocks: impl Iterator<Item = (std::ops::Range<usize>, R, bool)> + Send,
    mut collector: OptimalCollector<B>,
    algorithm_version: u8,
    options: EncodeOptions,
    emit: &mut dyn FnMut(std::ops::Range<usize>, Buffer<u8, B>) -> Result<()>,
    allowance: &B,
) -> Result<()> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    type Collected<B, R> = Vec<(std::ops::Range<usize>, R, bool, BlockMatches<B>)>;
    let mut blocks = blocks.peekable();
    // Takes blocks while they fit `room`, and one anyway when `at_least_one`,
    // so a lone block larger than the room still makes progress.
    let mut collect = |collector: &mut OptimalCollector<B>,
                       room: usize,
                       at_least_one: bool|
     -> Result<Collected<B, R>> {
        let mut batch = Vec::new();
        let mut bytes = 0usize;
        while let Some((block, _, _)) = blocks.peek() {
            let len = block.end - block.start;
            if bytes + len > room && !(at_least_one && batch.is_empty()) {
                break;
            }
            let (block, records, is_last) = blocks.next().expect("peeked");
            bytes += len;
            let matches = collector.collect(combined, block.clone(), options)?;
            batch.push((block, records, is_last, matches));
        }
        Ok(batch)
    };
    let price =
        |(block, records, is_last, matches): (std::ops::Range<usize>, R, bool, BlockMatches<B>)| {
            if !B::LIMITED && options.parse_passes == 1 && records.is_empty() {
                let packed = encode_single_pass_block(
                    combined,
                    block.clone(),
                    options,
                    algorithm_version,
                    distance_size,
                    is_last,
                    matches,
                    None,
                    allowance,
                )?;
                return Ok((block, packed));
            }
            let mut tokens = optimal_tokens_for_matches(
                combined,
                block.clone(),
                options,
                distance_size,
                &records,
                &matches,
                allowance,
            )?;
            drop(matches);
            if !records.is_empty() {
                tokens.prepend(records.iter().copied().map(EncodeToken::Filter))?;
            }
            let packed = encode_token_block_with_allowance(
                &tokens,
                algorithm_version,
                distance_size,
                is_last,
                allowance,
            )?;
            Ok::<_, Error>((block, packed))
        };

    let mut pending = collect(&mut collector, PIPELINED_BLOCK_BYTES / 2, true)?;
    while !pending.is_empty() {
        let held: usize = pending
            .iter()
            .map(|(block, _, _, _)| block.end - block.start)
            .sum();
        let room = PIPELINED_BLOCK_BYTES
            .saturating_sub(held)
            .min(PIPELINED_BLOCK_BYTES / 2);
        let (collected, (packed, failure)) = crate::parallel::join(
            || collect(&mut collector, room, false),
            || crate::parallel::map_prefix(pending, price),
        );
        for (block, packed) in packed {
            emit(block, packed)?;
        }
        if let Some(error) = failure {
            return Err(error);
        }
        pending = collected?;
        if pending.is_empty() {
            pending = collect(&mut collector, PIPELINED_BLOCK_BYTES / 2, true)?;
        }
    }
    Ok(())
}

const NO_RECORDS: &[EncodeFilter] = &[];

/// Reports progress through `position`, turning a refusal into cancellation.
fn report_through(
    progress: &mut Option<&mut dyn FnMut(usize) -> bool>,
    position: usize,
) -> Result<()> {
    if progress
        .as_deref_mut()
        .is_some_and(|report| !report(position))
    {
        return Err(Error::Cancelled);
    }
    Ok(())
}

/// Whether a member's optimal parse may price its blocks on other threads.
/// A limited allowance is admitted for one block's workspace at a time, and
/// keeps that.
fn pipelines<B: Budget>(options: EncodeOptions) -> bool {
    options.optimal_parse && !B::LIMITED && crate::parallel::may_nest()
}

#[allow(clippy::too_many_arguments)]
fn encode_filtered_member_with_allowance<B: Budget>(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    filters: &[EncodeFilter],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let (window, start) = member_window_with_allowance(data, history, options, allowance)?;
    let end = window.len();
    encode_lz_block_with_allowance(
        &window,
        start..end,
        MemberSearch::Fresh,
        algorithm_version,
        filters,
        options,
        true,
        progress,
        allowance,
    )
}

/// How far back a parse over `reach` bytes has to remember.
///
/// Nothing further than the maximum distance is ever accepted as a match, so a
/// link to anything older can be dropped. Neither can a match reach back past
/// the start of what is being parsed, so a member shorter than the dictionary
/// sets the window instead: asking for `--dict-size 32m` on a one-megabyte
/// member should not reserve thirty-two megabytes of links that can never name
/// a position.
fn finder_window(options: EncodeOptions, reach: usize) -> usize {
    options.max_match_distance.min(reach).max(LZ_BLOCK_SIZE)
}

/// Chain links and heads, one block of tokens, Huffman tables and the payload.
/// The framed block copies the payload after the tokens have been released.
pub(crate) fn lazy_parse_workspace(options: EncodeOptions, window: usize, block: usize) -> u64 {
    let finder = finder_window(options, window);
    let tokens = block.max(4).next_power_of_two() as u64 * size_of::<PackedToken>() as u64;
    let tables = huffman_workspace();
    let payload = unfiltered_payload_bytes(options, block as u64);
    Rar50MatchFinder::bytes_for_window(finder)
        .saturating_add(tables)
        .saturating_add(
            tokens
                .saturating_add(payload)
                .max(payload.saturating_mul(2)),
        )
}

fn huffman_workspace() -> u64 {
    let symbols = MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE;
    symbols as u64
        * (size_of::<usize>()
            + size_of::<u8>()
            + size_of::<(u16, u8)>()
            + size_of::<LevelToken>()
            + 3 * size_of::<usize>()) as u64
}

fn unfiltered_payload_bytes(options: EncodeOptions, bytes: u64) -> u64 {
    // Fifteen bits per literal, or at least four bytes per match. A match of
    // up to nine bytes has no length extras. Longer matches amortize them.
    let (distance_slot, _) = distance_slot_for_valid_match(options.max_match_distance.max(1));
    let distance_bits = distance_slot_bit_count_valid(distance_slot) as u64;
    let bits_per_byte = 15u64.max((3 * 15 + distance_bits.saturating_sub(4)).div_ceil(4));
    bytes.saturating_mul(bits_per_byte).div_ceil(8)
}

/// Workspace for an unfiltered one-pass parse whose collector is a tree.
pub(crate) fn single_pass_tree_workspace(
    options: EncodeOptions,
    window: usize,
    run: usize,
    block_size: usize,
) -> u64 {
    let bytes = run.min(PIPELINED_BLOCK_BYTES) as u64;
    // A batch larger than half the pipe is one block. Otherwise it can
    // include one short final block in addition to its full input chunks.
    let pricing_blocks = run
        .min(PIPELINED_BLOCK_BYTES / 2)
        .div_ceil(block_size)
        .max(1) as u64;
    // While pricing a half-pipe, the collector may fill the other half.
    let collected_blocks = pricing_blocks * 2;
    let matches = bytes * (match_finder::TREE_MAX_RUNS * size_of::<(u32, u32)>()) as u64
        + (bytes + collected_blocks) * size_of::<u32>() as u64
        + (bytes / options.nice() as u64) * (2 * size_of::<match_finder::CommittedMatch>()) as u64
        + collected_blocks * (4 * size_of::<match_finder::CommittedMatch>()) as u64;
    // Pricing owns the match runs, three arrays and the distance-state ring.
    // Backtracking and coding release the runs. Even the match start offsets
    // alone cover the extra bytes per input byte those stages can need.
    let per_byte = 3 * size_of::<u32>();
    let per_block = 9 * size_of::<u32>()
        + OPTIMAL_STATE_RING_SIZE * (size_of::<[u32; 4]>() + size_of::<u32>())
        + (match_finder::TREE_MAX_RUNS + 4) * size_of::<(usize, usize, usize)>();
    let with_offsets = per_byte + size_of::<u32>();
    debug_assert!(2 * size_of::<u32>() + size_of::<PackedToken>() <= with_offsets);
    debug_assert!(
        unfiltered_payload_bytes(options, bytes) * 2 + bytes * size_of::<PackedToken>() as u64
            <= bytes * with_offsets as u64
    );
    debug_assert!(huffman_workspace() + 4 * MAX_BLOCK_TABLE_BYTES <= per_block as u64);
    let retained = unfiltered_payload_bytes(options, run as u64)
        + (run.div_ceil(block_size) as u64) * (MAX_BLOCK_TABLE_BYTES + MAX_BLOCK_HEADER_BYTES + 1);
    Rar50TreeMatchFinder::<Allowance>::bytes_for_window(finder_window(options, window)) as u64
        + matches
        + bytes * per_byte as u64
        + pricing_blocks * per_block as u64
        + retained
}

/// A finder for the whole member, seeded with the history it carries in. It
/// keeps growing as the blocks are parsed, so it is sized to the widest window
/// the member could ever want rather than to any one block.
fn member_finder_with_allowance<B: Budget>(
    combined: &[u8],
    start: usize,
    options: EncodeOptions,
    allowance: &B,
) -> Result<Rar50MatchFinder<B>> {
    let mut finder =
        Rar50MatchFinder::with_allowance(finder_window(options, combined.len()), allowance)?;
    finder.insert_run(combined, 0..start.min(combined.len().saturating_sub(3)));
    Ok(finder)
}

/// A finder holding everything a parse of `block` may reach back to, and
/// nothing older.
fn seeded_finder<B: Budget>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    allowance: &B,
) -> Result<Rar50MatchFinder<B>> {
    // Sized to what this block can actually reach, not to the maximum distance,
    // so the first blocks of a member do not clear a window the data is not yet
    // long enough to fill.
    let behind = block.start.min(options.max_match_distance);
    let mut finder =
        Rar50MatchFinder::with_allowance(behind + (block.end - block.start), allowance)?;
    for pos in block.start - behind..block.start {
        finder.insert(combined, pos);
    }
    Ok(finder)
}

/// The search state a member shares across its blocks, when it has any.
enum MemberSearch<'a, B: Budget = Allowance> {
    /// Nothing shared: the block builds what it needs and drops it.
    Fresh,
    /// The member's chain finder, which the lazy path feeds block by block.
    Lazy(&'a mut Rar50MatchFinder<B>),
    /// The member's match collector, which the optimal parse feeds block by
    /// block.
    Optimal(&'a mut OptimalCollector<B>),
}

/// The history a tree seeded for a parse from `start` holds.
fn tree_history(start: usize, options: EncodeOptions) -> Range<usize> {
    start.saturating_sub(options.max_match_distance)..start
}

/// How far a tree descent at `pos` compares, in a window that ends with
/// `combined`.
fn tree_len_limit(combined: &[u8], pos: usize, options: EncodeOptions) -> usize {
    (combined.len() - pos).min(options.nice())
}

/// A finder handed to a run that shares its window with the runs around it,
/// standing where the run's own would.
pub(crate) enum RunFinder<B: Budget> {
    /// Over the group's packed index, for a run that walks chains.
    Packed(crate::codec::packed_chain::PackedMatchFinder<B>),
    /// The tree a run that searches one would have seeded.
    Tree(Rar50TreeMatchFinder<B>),
}

/// What [`seed_chain`] holds besides the trees it returns.
pub(crate) fn run_trees_workspace(options: EncodeOptions) -> u64 {
    if !options.optimal_parse {
        return 0;
    }
    match_finder::SeedTree::<Allowance>::bytes_for_reach(options.max_match_distance) as u64
}

/// The runs a shared tree can seed: those with history, and at least `nice`
/// long, since a descent compares at most `nice` bytes and a run's own window
/// ends where the run does, so the seed tree's descents compare as far as the
/// run's would only if no run ends within that of its history.
fn seeds_from_shared(run: &Range<usize>, options: EncodeOptions) -> bool {
    debug_assert!(run.start <= run.end);
    run.start > 0 && run.end - run.start >= options.nice()
}

/// How `runs` are seeded: in chains of consecutive runs, given as ranges of
/// their indexes, each seeded from one shared tree when it holds several runs
/// ([`seed_chain`]) and on its own otherwise ([`seed_run_tree`]). Runs in no
/// chain seed their own.
///
/// A shared tree puts each position in once, but in order: a run's tree is
/// ready only once everything before its history's end is in. Positions of
/// one hash go in on one thread, and a hash that a large part of the window
/// has makes that order slow however many threads there are. So a chain is
/// cut where it would span more than a dictionary, when the extra positions
/// the runs then put in for themselves cost less than the wait.
pub(crate) fn seed_chains(
    window: &[u8],
    runs: &[Range<usize>],
    options: EncodeOptions,
) -> Vec<Range<usize>> {
    let history = |index: usize| tree_history(runs[index].start, options);
    let chains = |limit: usize| {
        let mut chains: Vec<Range<usize>> = Vec::new();
        for (index, run) in runs.iter().enumerate() {
            if run.start == 0 {
                continue;
            }
            if let Some(chain) = chains.last_mut() {
                let joins = chain.end == index
                    && runs[chain.start..=index]
                        .iter()
                        .all(|run| seeds_from_shared(run, options))
                    && history(index).end - history(chain.start).start <= limit;
                if joins {
                    chain.end += 1;
                    continue;
                }
            }
            chains.push(index..index + 1);
        }
        // A run alone is seeded here only when its history splits between
        // threads; otherwise its job seeds it as well as this could.
        chains.retain(|chain| {
            chain.len() > 1 || match_finder::seed_shares(history(chain.start).len()) >= 2
        });
        chains
    };
    let together = chains(usize::MAX);
    let apart = chains(options.max_match_distance);
    if together == apart {
        return apart;
    }
    let span = |chain: &Range<usize>| history(chain.end - 1).end - history(chain.start).start;
    let threads = crate::parallel::threads().max(1);
    let (Some(first), Some(last)) = (together.first(), together.last()) else {
        return apart;
    };
    let skew = match_finder::seed_skew(
        window,
        history(first.start).start..history(last.end - 1).end,
        threads,
    );
    let time = |chains: &[Range<usize>]| {
        let longest = chains.iter().map(span).max().unwrap_or(0) as f64;
        let work = chains.iter().map(span).sum::<usize>() as f64;
        (longest * skew).max(work / threads as f64)
    };
    if time(&apart) <= time(&together) {
        apart
    } else {
        together
    }
}

/// The tree a run of `window` would seed alone, from the dictionary before
/// it, split by hash between the threads this one may fan out to.
///
/// The run need not search a tree in a window of its own
/// ([`searches_tree`]): the tail of a run that does is coded on the tree
/// that run's parse has built, which holds what this one does.
pub(crate) fn seed_run_tree<B: Budget>(
    window: &[u8],
    run: Range<usize>,
    options: EncodeOptions,
    allowance: &B,
) -> Result<Rar50TreeMatchFinder<B>> {
    let history = tree_history(run.start, options);
    // The run's own window, as its collector would seed it.
    let combined = &window[history.start..run.end];
    Rar50TreeMatchFinder::seeded(
        finder_window(options, combined.len()),
        combined,
        0..history.len(),
        |pos| tree_len_limit(combined, pos, options),
        options.max_match_candidates,
        match_finder::seed_shares(history.len()),
        allowance,
    )
}

/// The trees of one of [`seed_chains`]'s chains of several runs of `window`,
/// in their order, seeded from one shared tree ([`run_trees_workspace`]).
/// Each is the one [`seed_run_tree`] would seed for its run, so the output
/// does not change.
pub(crate) fn seed_chain<B: Budget>(
    window: &[u8],
    runs: &[Range<usize>],
    options: EncodeOptions,
    allowance: &B,
) -> Result<Vec<Rar50TreeMatchFinder<B>>> {
    let mut seed = match_finder::SeedTree::with_allowance(options.max_match_distance, allowance)?;
    runs.iter()
        .map(|run| {
            let history = tree_history(run.start, options);
            let reach = run.end - history.start;
            seed.seed(
                window,
                history,
                finder_window(options, reach),
                |pos| tree_len_limit(window, pos, options),
                options.max_match_candidates,
                allowance,
            )
        })
        .collect()
}

/// The trees [`seed_run_tree`] and [`seed_chain`] seed for `runs` of `window`
/// in `chains`, one for each run, or `None` where no chain holds it.
#[cfg(all(test, feature = "parallel"))]
pub(crate) fn run_trees(
    window: &[u8],
    runs: &[Range<usize>],
    chains: &[Range<usize>],
    options: EncodeOptions,
    allowance: &Allowance,
) -> Result<Vec<Option<Rar50TreeMatchFinder<Allowance>>>> {
    let mut trees: Vec<Option<_>> = runs.iter().map(|_| None).collect();
    for chain in chains {
        let seeded = match &runs[chain.clone()] {
            [run] => vec![seed_run_tree(window, run.clone(), options, allowance)?],
            chained => seed_chain(window, chained, options, allowance)?,
        };
        for (slot, tree) in trees[chain.clone()].iter_mut().zip(seeded) {
            *slot = Some(tree);
        }
    }
    Ok(trees)
}

/// Whether an optimal parse of `window` from `start` searches a binary tree.
///
/// A tree finds what a chain walk of the same depth misses. But the only way
/// into a tree is a descent per position, so bringing in history costs a
/// search per byte, where a chain takes each byte with one store. A parse at
/// least as long as the history it carries can afford that. A block job's run
/// is a dictionary long, with a dictionary of history behind it.
///
/// A member's last run is usually shorter than the history behind it. Down to
/// a quarter of that history it still searches a tree (#407). A shorter scrap
/// keeps the chains.
pub(crate) fn searches_tree(window: usize, start: usize, options: EncodeOptions) -> bool {
    start.min(options.max_match_distance) <= (window - start).saturating_mul(4)
}

/// Whether the optimal parse of a window this long from `start` searches a
/// packed index rather than chains or a tree. Block jobs that share an index
/// must be ones whose own window would have used one.
pub(crate) fn packed_index_fits(window: usize, start: usize, options: EncodeOptions) -> bool {
    !searches_tree(window, start, options)
        && window >= 1024 * 1024
        && window <= options.max_match_distance.saturating_mul(2)
        && window <= u32::MAX as usize / 6
}

/// The collector a run's blocks share from `at`: over a finder handed out by
/// the run's group when there is one, built for the window otherwise.
fn collector_at<B: Budget>(
    combined: &[u8],
    at: usize,
    finder: Option<RunFinder<B>>,
    options: EncodeOptions,
    allowance: &B,
) -> Result<OptimalCollector<B>> {
    match finder {
        Some(RunFinder::Packed(finder)) => {
            debug_assert_eq!(finder.position(), at.min(combined.len().saturating_sub(3)));
            Ok(OptimalCollector {
                finder: CollectorFinder::Packed(finder),
                noise: NoiseScan::with_cells(at),
            })
        }
        Some(RunFinder::Tree(tree)) => {
            OptimalCollector::with_tree(combined, at, tree, options, allowance)
        }
        None => OptimalCollector::with_allowance(combined, at, options, allowance),
    }
}

// One per member or run being coded, so the collector's noise histogram is
// not worth a box.
#[allow(clippy::large_enum_variant)]
enum SharedMemberSearch<B: Budget> {
    Lazy(Rar50MatchFinder<B>),
    Optimal(OptimalCollector<B>),
}

impl<B: Budget> SharedMemberSearch<B> {
    fn borrow(&mut self) -> MemberSearch<'_, B> {
        match self {
            Self::Lazy(finder) => MemberSearch::Lazy(finder),
            Self::Optimal(collector) => MemberSearch::Optimal(collector),
        }
    }
}

/// The matches at every position of one block, found once and priced by every
/// pass of the optimal parse. The runs at one position carry strictly
/// increasing lengths and distances, so each is the nearest distance found
/// that reaches its length.
///
/// One position holds at most one run per length it can reach, so the whole
/// block is bounded by the block size times [`NICE_MATCH_LENGTH`]. Nothing
/// approaches that: the worst measured is about six runs per position, on a
/// mebibyte of two-symbol noise, where every position has many candidates whose
/// lengths creep up one byte at a time.
struct BlockMatches<B: Budget = Allowance> {
    /// Every position's runs, one position after another.
    runs: Buffer<(u32, u32), B>,
    /// Where each position's runs start in `runs`, with one extra entry to
    /// close the last position.
    starts: Buffer<u32, B>,
    /// The matches the collector committed to, in order, whose interiors it
    /// left unsearched.
    commits: Buffer<match_finder::CommittedMatch, B>,
}

/// One match finder for a member's whole optimal parse, and the walk that asks
/// it about each block once.
///
/// The parse prices each block [`OPTIMAL_PARSE_PASSES`] times, but nothing the
/// finder answers depends on the prices. Collecting the answers first and
/// replaying them lets every pass after the first skip the finder entirely.
///
/// Searching once is also what makes the tree finder affordable, and the tree
/// is where the speed is: pricing every position means searching at every
/// position, which is the load a chain walk carries worst and a tree carries
/// best. See [`searches_tree`] for which parses get one.
struct OptimalCollector<B: Budget = Allowance> {
    finder: CollectorFinder<B>,
    /// Which positions the finder leaves out ([`NoiseScan::skips`]), in
    /// cells counted from where the run starts, so that the run's blocks
    /// collect the same whether its window ends with it or runs on into the
    /// next run, and its tree holds what a tree seeded there would.
    noise: NoiseScan,
}

#[test]
fn packed_collector_preserves_frontiers_across_committed_interiors_and_blocks() {
    let mut state = 0x5e91_d742_037b_a6cdu64;
    let mut input = vec![0; 1024 * 1024];
    for byte in &mut input {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    // Two blocks behind a long history, which keeps chains rather than a tree.
    let start = input.len() - 2 * LZ_BLOCK_SIZE;
    input.copy_within(0..LZ_BLOCK_SIZE, start);
    input.copy_within(0..LZ_BLOCK_SIZE / 2, start + LZ_BLOCK_SIZE);
    let allowance = Allowance::default();
    let options = EncodeOptions {
        max_match_distance: 4 * 1024 * 1024,
        max_match_candidates: 128,
        optimal_parse: true,
        ..EncodeOptions::default()
    };
    let mut packed = OptimalCollector::with_allowance(&input, start, options, &allowance).unwrap();
    assert!(matches!(&packed.finder, CollectorFinder::Packed(_)));
    let mut ordinary = OptimalCollector {
        finder: CollectorFinder::Chains(
            member_finder_with_allowance(&input, start, options, &allowance).unwrap(),
        ),
        noise: NoiseScan::with_cells(start),
    };
    for block in [
        start..start + LZ_BLOCK_SIZE,
        start + LZ_BLOCK_SIZE..start + 2 * LZ_BLOCK_SIZE,
    ] {
        let expected = ordinary.collect(&input, block.clone(), options).unwrap();
        let actual = packed.collect(&input, block, options).unwrap();
        assert_eq!(actual.starts.len(), expected.starts.len());
        for (offset, (a, e)) in actual
            .starts
            .windows(2)
            .zip(expected.starts.windows(2))
            .enumerate()
        {
            let actual_runs = &actual.runs[a[0] as usize..a[1] as usize];
            let expected_runs = &expected.runs[e[0] as usize..e[1] as usize];
            assert!(
                actual_runs.iter().copied().eq(expected_runs
                    .iter()
                    .copied()
                    .filter(|&(length, _)| length >= 4)),
                "legal frontier at position {offset}"
            );
        }
    }
    let small =
        OptimalCollector::with_allowance(&input[..1024 * 1024 - 1], start, options, &allowance)
            .unwrap();
    assert!(matches!(&small.finder, CollectorFinder::Chains(_)));
    let short_dictionary = EncodeOptions {
        max_match_distance: 128 * 1024,
        ..options
    };
    // A tail under a quarter of its history, so not a tree; and a window
    // past twice the dictionary, so not the packed index.
    let bounded = OptimalCollector::with_allowance(
        &input,
        input.len() - LZ_BLOCK_SIZE / 4,
        short_dictionary,
        &allowance,
    )
    .unwrap();
    assert!(matches!(&bounded.finder, CollectorFinder::Chains(_)));
}

/// A run at least as long as the history behind it searches a tree, seeded
/// with that history, and the tree then answers what one that had parsed the
/// history itself would: same matches at every position of the run.
#[test]
fn a_seeded_tree_collects_what_a_tree_that_parsed_the_history_does() {
    let mut state = 0x0b5e_55ed_7ee5_1234u64;
    let mut input: Vec<u8> = (0..512 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // Few symbols, so chains and trees both get busy.
            b"abcd"[(state % 4) as usize]
        })
        .collect();
    // Long copies make the parse commit and step over their interiors, which
    // the tree must still hold for the third copy to find the second.
    input.copy_within(0..64 * 1024, 100 * 1024);
    input.copy_within(100 * 1024..164 * 1024, 300 * 1024);
    let options = EncodeOptions {
        max_match_distance: 256 * 1024,
        max_match_candidates: 32,
        optimal_parse: true,
        ..EncodeOptions::default()
    }
    .with_nice_match_length(64);
    let allowance = Allowance::default();
    let start = 256 * 1024;
    assert!(searches_tree(input.len(), 0, options));
    assert!(searches_tree(input.len(), start, options));
    assert!(!searches_tree(start + 1024, start, options));

    let mut seeded = OptimalCollector::with_allowance(&input, start, options, &allowance).unwrap();
    assert!(matches!(&seeded.finder, CollectorFinder::Tree(..)));
    let mut parsed = OptimalCollector::with_allowance(&input, 0, options, &allowance).unwrap();
    for block in (0..start).step_by(LZ_BLOCK_SIZE) {
        parsed
            .collect(&input, block..block + LZ_BLOCK_SIZE, options)
            .unwrap();
    }
    let mut found = 0;
    for block in (start..input.len()).step_by(LZ_BLOCK_SIZE) {
        let block = block..block + LZ_BLOCK_SIZE;
        let expected = parsed.collect(&input, block.clone(), options).unwrap();
        let actual = seeded.collect(&input, block, options).unwrap();
        assert!(actual.starts[..] == expected.starts[..]);
        assert!(actual.runs[..] == expected.runs[..]);
        found += actual.runs.len();
    }
    assert!(found > 0);
}

/// Runs of one window seeded from a shared tree code the bytes each codes
/// seeding its own, at any thread count.
#[test]
#[cfg(feature = "parallel")]
fn runs_seeded_together_code_as_runs_seeded_alone() {
    const KIB: usize = 1024;
    let mut state = 0x7ee5_0b5e_5eed_4321u64;
    let mut window: Vec<u8> = (0..3 * 1024 * KIB)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b"abcdefgh"[(state % 8) as usize]
        })
        .collect();
    window.copy_within(0..256 * KIB, 1024 * KIB);
    window.copy_within(1024 * KIB..1280 * KIB, 2560 * KIB);
    let options = EncodeOptions {
        max_match_distance: 1024 * KIB,
        max_match_candidates: 16,
        optimal_parse: true,
        ..EncodeOptions::default()
    }
    .with_nice_match_length(64)
    .with_parse_passes(2);
    let allowance = Allowance::default();
    let runs: Vec<Range<usize>> = (1..6)
        .map(|run| run * 512 * KIB..(run + 1) * 512 * KIB)
        .collect();
    let blocks = [(256 * KIB, false), (512 * KIB, false)];
    let alone: Vec<Vec<Buffer<u8>>> = runs
        .iter()
        .map(|run| {
            let skip = tree_history(run.start, options).start;
            assert!(searches_tree(run.end - skip, run.start - skip, options));
            streaming_blocks_in_window(
                &window[..run.end],
                run.start,
                &blocks,
                None,
                0,
                options,
                None,
                &allowance,
            )
            .unwrap()
            .into_iter()
            .collect()
        })
        .collect();
    for threads in [1, 2, 8] {
        crate::parallel::private_pool(threads).install(|| {
            // One shared tree for them all, each run on its own, and the
            // chains seeding would choose.
            let layouts = [
                std::iter::once(0..runs.len()).collect::<Vec<_>>(),
                (0..runs.len()).map(|run| run..run + 1).collect(),
                seed_chains(&window, &runs, options),
            ];
            for chains in &layouts {
                let trees = run_trees(&window, &runs, chains, options, &allowance).unwrap();
                for ((run, tree), alone) in runs.iter().zip(trees).zip(&alone) {
                    // A run left out seeds its own, as `alone` did.
                    let Some(tree) = tree else {
                        continue;
                    };
                    check_seeded_run(&window, run, tree, &blocks, options, alone, threads);
                }
            }
        });
    }
}

/// Codes `run` of `window` on `tree` and checks it codes `alone`'s blocks.
#[cfg(all(test, feature = "parallel"))]
fn check_seeded_run(
    window: &[u8],
    run: &Range<usize>,
    tree: Rar50TreeMatchFinder<Allowance>,
    blocks: &[(usize, bool)],
    options: EncodeOptions,
    alone: &[Buffer<u8>],
    threads: usize,
) {
    let together = streaming_blocks_with_tree(
        &window[..run.end],
        run.start,
        tree,
        blocks,
        None,
        0,
        options,
        None,
        &Allowance::default(),
    )
    .unwrap();
    assert!(
        together
            .iter()
            .map(|block| &block[..])
            .eq(alone.iter().map(|block| &block[..])),
        "run {run:?} at {threads} threads differs"
    );
}

enum CollectorFinder<B: Budget = Allowance> {
    Packed(super::super::packed_chain::PackedMatchFinder<B>),

    /// The tree, and where each stretch as long as the longest match last
    /// began, for the matches the tree stops short of. See
    /// [`measure_past_nice`] for which parses keep the stretches.
    Tree(
        Rar50TreeMatchFinder<B>,
        Option<match_finder::WindowIndex<B>>,
    ),
    Chains(Rar50MatchFinder<B>),
}

impl OptimalCollector {
    #[cfg(test)]
    fn new(combined: &[u8], start: usize, options: EncodeOptions) -> Self {
        Self::with_allowance(combined, start, options, &Allowance::default())
            .expect("unlimited collector allocation")
    }
}

impl<B: Budget> OptimalCollector<B> {
    fn with_allowance(
        combined: &[u8],
        start: usize,
        options: EncodeOptions,
        allowance: &B,
    ) -> Result<Self> {
        if searches_tree(combined.len(), start, options) {
            // The history goes in as the collector would have put it there had
            // it parsed it: every position, each with the descent a search
            // makes.
            let tree = Rar50TreeMatchFinder::seeded(
                finder_window(options, combined.len()),
                combined,
                tree_history(start, options),
                |pos| tree_len_limit(combined, pos, options),
                options.max_match_candidates,
                1,
                allowance,
            )?;
            return Self::with_tree(combined, start, tree, options, allowance);
        }
        if packed_index_fits(combined.len(), start, options) {
            // Captured bounded jobs can store each complete hash chain as a
            // contiguous byte stream. Static input limits select the backend;
            // available memory never changes its candidate quality.
            let mut finder =
                super::super::packed_chain::PackedMatchFinder::with_allowance(combined, allowance)?;
            for pos in 0..start.min(combined.len().saturating_sub(3)) {
                finder.insert(combined, pos);
            }
            return Ok(Self {
                finder: CollectorFinder::Packed(finder),
                noise: NoiseScan::with_cells(start),
            });
        }

        Ok(Self {
            finder: CollectorFinder::Chains(member_finder_with_allowance(
                combined, start, options, allowance,
            )?),
            noise: NoiseScan::with_cells(start),
        })
    }

    /// The collector over `tree`, which holds what
    /// [`Self::with_allowance`] would have seeded one with at `start`.
    fn with_tree(
        combined: &[u8],
        start: usize,
        tree: Rar50TreeMatchFinder<B>,
        options: EncodeOptions,
        allowance: &B,
    ) -> Result<Self> {
        let stretches = if options.parse_passes > 1 {
            let mut stretches = match_finder::WindowIndex::with_allowance(
                finder_window(options, combined.len()),
                MAX_ENCODER_MATCH_LENGTH,
                allowance,
            )?;
            for pos in tree_history(start, options) {
                stretches.insert(combined, pos);
            }
            Some(stretches)
        } else {
            None
        };
        Ok(Self {
            finder: CollectorFinder::Tree(tree, stretches),
            noise: NoiseScan::with_cells(start),
        })
    }

    /// Finds the matches the parse will price at each position of `block`,
    /// taking the positions into the finder as it goes. Blocks must arrive in
    /// order, each exactly once, the same discipline the member's shared chain
    /// finder already asks of the lazy path.
    ///
    /// Searching stops where the parse stops pricing. A match that reaches
    /// [`NICE_MATCH_LENGTH`] is one the parse commits to and steps over, so the
    /// positions it covers are not searched from either.
    fn collect(
        &mut self,
        combined: &[u8],
        block: std::ops::Range<usize>,
        options: EncodeOptions,
    ) -> Result<BlockMatches<B>> {
        let allowance = match &self.finder {
            CollectorFinder::Packed(finder) => finder.allowance(),
            CollectorFinder::Tree(finder, _) => finder.allowance(),
            CollectorFinder::Chains(finder) => finder.allowance(),
        };
        let span = block.end - block.start;
        let mut matches = BlockMatches {
            // One run per position to start with, which is where data that
            // matches at all lands, so the common case grows this once.
            runs: Buffer::with_capacity(span, &allowance)?,
            starts: Buffer::with_capacity(span + 1, &allowance)?,
            commits: Buffer::new(&allowance),
        };
        if let CollectorFinder::Packed(finder) = &mut self.finder {
            finder
                .collect_block(
                    combined,
                    block,
                    options.max_match_distance,
                    options.max_match_candidates,
                    options.nice(),
                    MAX_ENCODER_MATCH_LENGTH,
                    &mut matches.runs,
                    &mut matches.starts,
                    &mut matches.commits,
                    &mut self.noise,
                )
                .map_err(Into::into)?;
            return Ok(matches);
        }
        // The first position past a match the parse will commit to. The parse
        // reaches the same decision from the same lengths, and where it steps
        // over the position this one was found at, it looks the match up in
        // `commits` instead; see [`match_finder::CommittedMatch`].
        let mut committed_through = block.start;
        for pos in block.clone() {
            matches.starts.push_admitted(matches.runs.len() as u32);
            let searching = pos >= committed_through && options.max_match_candidates != 0;
            let max_distance = pos.min(options.max_match_distance);
            let before = matches.runs.len();
            match &mut self.finder {
                CollectorFinder::Packed(_) => unreachable!("packed collector dispatched above"),
                CollectorFinder::Tree(tree, stretches) => {
                    let stretch = stretches
                        .as_mut()
                        .map_or(match_finder::NO_POSITION, |stretches| {
                            stretches.insert(combined, pos)
                        });
                    let avail = combined.len() - pos;
                    if avail < 4 || self.noise.skips(combined, pos) {
                        continue;
                    }
                    // Compares stop where the parse stops caring about better
                    // alternatives. A match that reaches that far is measured
                    // out to its real end, which is the length the parse
                    // commits to and steps over.
                    let len_limit = avail.min(options.nice());
                    if !searching {
                        // A position the parse steps over still goes in, with
                        // a distance limit of zero so nothing is reported.
                        // Leaving it out would save its descent but leave a
                        // hole the length of the match, and a third copy of
                        // something then finds only the first, which may have
                        // left the window.
                        tree.matches(
                            combined,
                            pos,
                            len_limit,
                            0,
                            options.max_match_candidates,
                            &mut matches.runs,
                        )
                        .map_err(Into::into)?;
                        continue;
                    }
                    tree.matches(
                        combined,
                        pos,
                        len_limit,
                        max_distance,
                        options.max_match_candidates,
                        &mut matches.runs,
                    )
                    .map_err(Into::into)?;
                    measure_past_nice(
                        combined,
                        pos,
                        len_limit,
                        avail.min(MAX_ENCODER_MATCH_LENGTH),
                        block.end,
                        max_distance,
                        stretches.as_ref(),
                        stretch,
                        &mut matches.runs,
                        before,
                    )
                    .map_err(Into::into)?;
                }
                CollectorFinder::Chains(finder) => {
                    // Inserting into a chain is one store, so every position
                    // goes in whether or not it is searched from. That keeps a
                    // solid member's candidates exactly what they were.

                    let first_candidate = if combined.len() - pos >= 4 {
                        finder.insert_and_first(combined, pos)
                    } else {
                        match_finder::NO_POSITION
                    };
                    let max_length = (block.end - pos).min(MAX_ENCODER_MATCH_LENGTH);
                    if !searching
                        || max_distance == 0
                        || max_length < 4
                        || self.noise.skips(combined, pos)
                    {
                        continue;
                    }

                    finder
                        .collect_improving(
                            combined,
                            pos,
                            first_candidate,
                            max_length,
                            max_distance,
                            options.max_match_candidates,
                            options.nice(),
                            &mut matches.runs,
                        )
                        .map_err(Into::into)?;
                }
            }
            // The parse can only take a match the block still has room for, so
            // the reach it will commit to is measured the way it measures it.
            if let Some(&run) = matches.runs[before..].last() {
                let reach = (run.0 as usize)
                    .min(block.end - pos)
                    .min(MAX_ENCODER_MATCH_LENGTH);
                if reach >= options.nice() {
                    committed_through = pos + reach;
                    matches
                        .commits
                        .push(match_finder::CommittedMatch::at(pos, reach, run))
                        .map_err(Into::into)?;
                }
            }
        }
        matches.starts.push_admitted(matches.runs.len() as u32);
        Ok(matches)
    }
}

/// How many of the stretches after a position [`measure_past_nice`] asks
/// after, besides its own. See [`match_finder::WindowIndex::distances_ahead`].
const STRETCHES_AHEAD: usize = 8;

/// Measures the longest run a tree descent reported out to its real end, when
/// the descent stopped at `len_limit` and the match may run on, and offers the
/// nearest earlier copy of the whole stretch ahead, `stretch`, when that
/// reaches further. `runs[before..]` are this position's runs.
///
/// The tree stops at the nearest copy of the nice length, and the copy that
/// runs on can be further back. 4 MiB of a zero run and a phrase, repeating
/// every 8,191 bytes, has dozens of nearer copies of each phrase start that
/// end with the phrase. Given the period, the parse codes the rest as repeats
/// of one match at a bit or two each.
///
/// A parse that prices once keeps no stretches. It commits to the longest
/// match at its nice length of 32 without pricing it.
#[allow(clippy::too_many_arguments)]
fn measure_past_nice<B: Budget>(
    combined: &[u8],
    pos: usize,
    len_limit: usize,
    limit: usize,
    block_end: usize,
    max_distance: usize,
    stretches: Option<&match_finder::WindowIndex<B>>,
    stretch: usize,
    runs: &mut Buffer<(u32, u32), B>,
    before: usize,
) -> std::result::Result<(), B::Failure> {
    let Some(last) = runs[before..].last_mut() else {
        return Ok(());
    };
    if last.0 as usize != len_limit || len_limit >= limit {
        return Ok(());
    }
    last.0 = match_length(combined, pos, last.1 as usize, limit) as u32;
    let reach = last.0 as usize;
    if stretches.is_none()
        && last.1 > 1
        && reach < limit
        && pos + reach < block_end
        && (1..=2).any(|ahead| {
            let start = pos + ahead;
            combined[start - 1] == combined[start]
                && combined[start] == combined[start + 1]
                && combined[start] == combined[pos + reach]
                && match_length(combined, start, 1, reach + 1 - ahead) > reach - ahead
        })
    {
        // A long match may start just before a byte run and end inside it.
        // Keep its shorter lengths available and let the parse reach the run
        // with a literal or two instead of committing to the distant match.
        last.0 = (len_limit - 1) as u32;
        let count = runs.len();
        if count > before + 1 && runs[count - 2].0 == runs[count - 1].0 {
            runs.pop();
        }
        return Ok(());
    }
    let Some(stretches) = stretches.filter(|_| reach < limit) else {
        return Ok(());
    };
    let mut ahead = [match_finder::NO_POSITION; STRETCHES_AHEAD];
    stretches.distances_ahead(combined, pos, &mut ahead);
    let here = if stretch < pos {
        pos - stretch
    } else {
        match_finder::NO_POSITION
    };
    let mut best = (reach, 0);
    for distance in std::iter::once(here).chain(ahead) {
        if distance > max_distance || distance > pos {
            continue;
        }
        let length = match_length(combined, pos, distance, limit);
        if length > best.0 || (length == best.0 && length > reach && distance < best.1) {
            best = (length, distance);
        }
    }
    let (length, distance) = best;
    if length <= reach {
        return Ok(());
    }
    // Runs grow in length and distance together, each the nearest distance
    // that reaches its length, so the ones this outreaches from no nearer
    // give way to it.
    while runs.len() > before && runs[runs.len() - 1].1 as usize >= distance {
        runs.pop();
    }
    // As many runs as the tree reports at most, the shortest giving way.
    if runs.len() - before == match_finder::TREE_MAX_RUNS {
        runs[before..].rotate_left(1);
        runs.pop();
    }
    runs.push((length as u32, distance as u32))
}

/// The bytes one member's parse reaches across, and where its own data starts.
///
/// A member with no history to carry borrows its own data rather than copying
/// it, which is every member of a non-solid archive.
enum MemberWindow<'a, B: Budget> {
    Borrowed(&'a [u8]),
    Owned(Buffer<u8, B>),
}

impl<B: Budget> std::ops::Deref for MemberWindow<'_, B> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,
            Self::Owned(data) => data,
        }
    }
}

fn member_window_with_allowance<'a, B: Budget>(
    data: &'a [u8],
    history: &[u8],
    options: EncodeOptions,
    allowance: &B,
) -> Result<(MemberWindow<'a, B>, usize)> {
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    if history.is_empty() {
        return Ok((MemberWindow::Borrowed(data), 0));
    }
    let combined = Buffer::from_slices(&[history, data], allowance)?;
    Ok((MemberWindow::Owned(combined), history.len()))
}

/// One block, with its own history and its own finder. The member path shares
/// a finder across blocks instead; this is for the callers that encode a block
/// on its own, which are the filtered path and the tests.
#[cfg(test)]
fn encode_lz_block(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let (combined, start) =
        member_window_with_allowance(data, history, options, &Allowance::default())?;
    encode_lz_block_in_window(
        &combined,
        start..combined.len(),
        MemberSearch::Fresh,
        algorithm_version,
        initial_filters,
        options,
        is_last,
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn encode_lz_block_in_window(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_>,
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let allowance = match &search {
        MemberSearch::Fresh => Allowance::default(),
        MemberSearch::Lazy(finder) => finder.allowance(),
        MemberSearch::Optimal(collector) => match &collector.finder {
            CollectorFinder::Packed(finder) => finder.allowance(),
            CollectorFinder::Tree(finder, _) => finder.allowance(),
            CollectorFinder::Chains(finder) => finder.allowance(),
        },
    };
    encode_lz_block_with_allowance(
        combined,
        block,
        search,
        algorithm_version,
        initial_filters,
        options,
        is_last,
        progress,
        &allowance,
    )
    .map(Buffer::into_vec)
}

#[allow(clippy::too_many_arguments)]
fn encode_lz_block_with_allowance<B: Budget>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_, B>,
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    if !options.optimal_parse {
        let tokens = lazy_tokens::<B, PackedToken>(
            combined,
            block,
            search,
            options,
            distance_size,
            progress,
            allowance,
        )?;
        let payload = encode_token_payload(
            tokens.iter().copied().map(PackedToken::decode),
            initial_filters,
            algorithm_version,
            distance_size,
            allowance,
        )?;
        drop(tokens);
        return encode_compressed_block_with_allowance(
            &payload.bytes,
            payload.bit_pos,
            true,
            is_last,
            allowance,
        );
    }

    if !B::LIMITED && options.parse_passes == 1 && initial_filters.is_empty() {
        let matches = collect_optimal_matches(combined, block.clone(), search, options, allowance)?;
        return encode_single_pass_block(
            combined,
            block,
            options,
            algorithm_version,
            distance_size,
            is_last,
            matches,
            progress,
            allowance,
        );
    }

    let mut tokens = encode_optimal_tokens(
        combined,
        block,
        search,
        options,
        distance_size,
        initial_filters,
        progress,
        allowance,
    )?;
    if !initial_filters.is_empty() {
        tokens.prepend(initial_filters.iter().copied().map(EncodeToken::Filter))?;
    }
    encode_token_block_with_allowance(
        &tokens,
        algorithm_version,
        distance_size,
        is_last,
        allowance,
    )
}

#[cfg(test)]
fn encode_token_block(
    tokens: &[EncodeToken],
    algorithm_version: u8,
    distance_size: usize,
    is_last: bool,
) -> Result<Vec<u8>> {
    encode_token_block_with_allowance(
        tokens,
        algorithm_version,
        distance_size,
        is_last,
        &Allowance::default(),
    )
    .map(Buffer::into_vec)
}

fn encode_token_block_with_allowance<B: Budget>(
    tokens: &[EncodeToken],
    algorithm_version: u8,
    distance_size: usize,
    is_last: bool,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let payload = encode_token_payload(
        tokens.iter().copied(),
        &[],
        algorithm_version,
        distance_size,
        allowance,
    )?;
    encode_compressed_block_with_allowance(
        &payload.bytes,
        payload.bit_pos,
        true,
        is_last,
        allowance,
    )
}

fn encode_token_payload<B: Budget>(
    tokens: impl Iterator<Item = EncodeToken> + Clone,
    filters: &[EncodeFilter],
    algorithm_version: u8,
    distance_size: usize,
    allowance: &B,
) -> Result<BitWriter<B>> {
    let (lengths, stream_bits) =
        stream_lengths_and_bits(tokens.clone(), filters, distance_size, allowance)?;

    let main_table = EncoderCodeTable::from_lengths(&lengths.main, allowance)?;
    let distance_table = EncoderCodeTable::from_lengths(&lengths.distance, allowance)?;
    let align_table = EncoderCodeTable::from_lengths(&lengths.align, allowance)?;
    let length_table = EncoderCodeTable::from_lengths(&lengths.length, allowance)?;
    let (table_data, table_bits) =
        encode_table_slices(lengths.slices(), algorithm_version, allowance)?;
    let payload_bits = table_bits + stream_bits;
    let mut writer = BitWriter {
        bytes: table_data,
        bit_pos: table_bits,
    };
    writer
        .bytes
        .reserve_total_capacity(payload_bits.div_ceil(8))?;
    let mut state = EncoderMatchState::default();
    let mut bits = PendingBits::default();
    for token in filters
        .iter()
        .copied()
        .map(EncodeToken::Filter)
        .chain(tokens)
    {
        match token {
            EncodeToken::Filter(filter) => {
                let (code, len) = main_table.code_for_present_symbol(256);
                bits.put(&mut writer, usize::from(code), usize::from(len));
                bits.flush(&mut writer);
                // stream_lengths_and_bits validated this same record before
                // its exact payload allocation was admitted.
                write_valid_filter(&mut writer, filter);
            }
            EncodeToken::Literal(byte) => {
                let (code, len) = main_table.code_for_present_symbol(byte as usize);
                bits.put(&mut writer, usize::from(code), usize::from(len));
            }
            EncodeToken::Match { length, distance } => {
                match state.encode_valid_match(length, distance, distance_size) {
                    EncodedMatch::LastLengthRepeat => {
                        let (code, len) = main_table.code_for_present_symbol(257);
                        bits.put(&mut writer, usize::from(code), usize::from(len));
                    }
                    EncodedMatch::RepeatDistance {
                        index,
                        length_slot,
                        length_extra,
                    } => {
                        let (code, len) = main_table.code_for_present_symbol(258 + index);
                        bits.put(&mut writer, usize::from(code), usize::from(len));
                        let (code, len) = length_table.code_for_present_symbol(length_slot);
                        bits.put(&mut writer, usize::from(code), usize::from(len));
                        let length_extra_bits = length_slot_extra_bits(length_slot);
                        if length_extra_bits != 0 {
                            bits.put(&mut writer, length_extra, usize::from(length_extra_bits));
                        }
                    }
                    EncodedMatch::New {
                        length_slot,
                        length_extra,
                        distance_slot,
                        distance_extra,
                        distance_bit_count,
                    } => {
                        let (code, len) = main_table.code_for_present_symbol(262 + length_slot);
                        bits.put(&mut writer, usize::from(code), usize::from(len));
                        let length_extra_bits = length_slot_extra_bits(length_slot);
                        if length_extra_bits != 0 {
                            bits.put(&mut writer, length_extra, usize::from(length_extra_bits));
                        }
                        let (code, len) = distance_table.code_for_present_symbol(distance_slot);
                        bits.put(&mut writer, usize::from(code), usize::from(len));
                        if distance_bit_count >= 4 {
                            if distance_bit_count > 4 {
                                bits.put(&mut writer, distance_extra >> 4, distance_bit_count - 4);
                            }
                            let (code, len) =
                                align_table.code_for_present_symbol(distance_extra & 0x0f);
                            bits.put(&mut writer, usize::from(code), usize::from(len));
                        } else if distance_bit_count != 0 {
                            bits.put(&mut writer, distance_extra, distance_bit_count);
                        }
                    }
                }
                state.remember(length, distance);
            }
        }
    }
    bits.flush(&mut writer);

    debug_assert_eq!(writer.bit_pos, payload_bits);
    Ok(writer)
}

/// Codes waiting to be written, most significant first, so that a token's
/// several codes and the short tokens after it reach the writer in one call.
#[derive(Default)]
struct PendingBits {
    value: u64,
    count: usize,
}

impl PendingBits {
    #[inline]
    fn put<B: Budget>(&mut self, writer: &mut BitWriter<B>, value: usize, count: usize) {
        debug_assert!(count < 64);
        if self.count + count > 64 {
            self.flush(writer);
        }
        let value = value as u64 & ((1u64 << count) - 1);
        self.value = (self.value << count) | value;
        self.count += count;
    }

    #[inline]
    fn flush<B: Budget>(&mut self, writer: &mut BitWriter<B>) {
        if self.count != 0 {
            writer
                .bytes
                .write_msb_bits_admitted(&mut writer.bit_pos, self.value, self.count);
            self.value = 0;
            self.count = 0;
        }
    }
}

#[derive(Debug)]
struct EncoderState<B: Budget> {
    history: Buffer<u8, B>,
    options: EncodeOptions,
}

impl<B: Budget> EncoderState<B> {
    fn new(options: EncodeOptions, allowance: &B) -> Self {
        Self {
            history: Buffer::new(allowance),
            options,
        }
    }
    fn encode(
        &mut self,
        input: &[u8],
        version: u8,
        filters: Option<&[crate::FilterSpec]>,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, B>> {
        let allowance = self.history.allowance();
        let packed = match filters {
            None => encode_member_with_allowance(
                input,
                &self.history,
                version,
                self.options,
                progress,
                &allowance,
            )?,
            Some(filters) if input.len() > LZ_BLOCK_SIZE => filtered_lz_blocks(
                input,
                filters,
                &self.history,
                0,
                true,
                version,
                self.options,
                progress,
                &allowance,
            )?,
            Some(filters) => {
                let (filtered, records) =
                    filtered_member_with_allowance(input, filters, &allowance)?;
                encode_filtered_member_with_allowance(
                    &filtered,
                    &self.history,
                    version,
                    &records,
                    self.options,
                    progress,
                    &allowance,
                )?
            }
        };
        // Commit history only after the encode and its callback succeed. The
        // packed result remains charged while any history growth is admitted.
        self.history
            .remember(input, self.options.max_match_distance)?;
        Ok(packed)
    }
}

#[derive(Debug)]
pub struct Unpack50Encoder {
    state: EncoderState<Allowance>,
}

impl Clone for Unpack50Encoder {
    fn clone(&self) -> Self {
        Self {
            state: EncoderState {
                history: Buffer::from_vec(self.state.history.to_vec()),
                options: self.state.options,
            },
        }
    }
}

impl Default for Unpack50Encoder {
    fn default() -> Self {
        Self::with_options(EncodeOptions::default())
    }
}

impl Unpack50Encoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            state: EncoderState::new(options, &Allowance::default()),
        }
    }
    pub fn encode_member(&mut self, input: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
        self.state
            .encode(input, algorithm_version, None, None)
            .map(Buffer::into_vec)
    }
    pub fn encode_member_with_filter(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filter: crate::FilterSpec,
    ) -> Result<Vec<u8>> {
        self.encode_member_with_filters(input, algorithm_version, &[filter])
    }
    pub fn encode_member_with_filters(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filters: &[crate::FilterSpec],
    ) -> Result<Vec<u8>> {
        self.state
            .encode(input, algorithm_version, Some(filters), None)
            .map(Buffer::into_vec)
    }
    #[cfg(test)]
    pub(crate) fn encode_member_with_filters_and_progress(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filters: &[crate::FilterSpec],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        self.state
            .encode(input, algorithm_version, Some(filters), Some(progress))
            .map(Buffer::into_vec)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodeToken {
    Filter(EncodeFilter),
    Literal(u8),
    Match { length: usize, distance: usize },
}

/// A packed token is a literal when its distance is zero. Match lengths need
/// thirteen bits, leaving room for every distance the RAR 7 encoder accepts.
#[derive(Clone, Copy)]
struct PackedToken(u64);

impl PackedToken {
    const LENGTH_BITS: u32 = MAX_ENCODER_MATCH_LENGTH.ilog2() + 1;
    const LENGTH_MASK: u64 = (1 << Self::LENGTH_BITS) - 1;

    fn decode(self) -> EncodeToken {
        let distance = (self.0 >> Self::LENGTH_BITS) as usize;
        if distance == 0 {
            EncodeToken::Literal(self.0 as u8)
        } else {
            EncodeToken::Match {
                length: (self.0 & Self::LENGTH_MASK) as usize,
                distance,
            }
        }
    }
}

impl From<EncodeToken> for PackedToken {
    fn from(token: EncodeToken) -> Self {
        match token {
            EncodeToken::Literal(byte) => Self(u64::from(byte)),
            EncodeToken::Match { length, distance } => {
                debug_assert!((distance as u64) <= (u64::MAX >> Self::LENGTH_BITS));
                debug_assert!((length as u64) <= Self::LENGTH_MASK);
                Self(((distance as u64) << Self::LENGTH_BITS) | length as u64)
            }
            EncodeToken::Filter(_) => unreachable!("filters are stored separately"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncodeFilter {
    offset: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct EncoderMatchState {
    reps: [usize; 4],
    last_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedMatch {
    LastLengthRepeat,
    RepeatDistance {
        index: usize,
        length_slot: usize,
        length_extra: usize,
    },
    New {
        length_slot: usize,
        length_extra: usize,
        distance_slot: usize,
        distance_extra: usize,
        distance_bit_count: usize,
    },
}

impl EncoderMatchState {
    fn encode_match(
        &self,
        length: usize,
        distance: usize,
        distance_size: usize,
    ) -> Result<EncodedMatch> {
        if distance == self.reps[0] && length == self.last_length {
            return Ok(EncodedMatch::LastLengthRepeat);
        }
        if let Some(index) = self
            .reps
            .iter()
            .position(|&repeat_distance| repeat_distance == distance && repeat_distance != 0)
        {
            let (length_slot, length_extra) = length_slot_for_match(length)?;
            return Ok(EncodedMatch::RepeatDistance {
                index,
                length_slot,
                length_extra,
            });
        }

        let (distance_slot, distance_extra) = distance_slot_for_match(distance, distance_size)?;
        let encoded_length = length
            .checked_sub(length_bonus(distance))
            .ok_or(Error::InvalidData("RAR 5 adjusted match length underflows"))?;
        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
        let (length_slot, length_extra) = length_slot_for_match(encoded_length)?;
        Ok(EncodedMatch::New {
            length_slot,
            length_extra,
            distance_slot,
            distance_extra,
            distance_bit_count,
        })
    }

    /// Encode a match after [`table_lengths_with_allowance`] has validated the
    /// same immutable token sequence from the same initial state.
    fn encode_valid_match(
        &self,
        length: usize,
        distance: usize,
        distance_size: usize,
    ) -> EncodedMatch {
        if distance == self.reps[0] && length == self.last_length {
            return EncodedMatch::LastLengthRepeat;
        }
        if let Some(index) = self
            .reps
            .iter()
            .position(|&repeat_distance| repeat_distance == distance && repeat_distance != 0)
        {
            let (length_slot, length_extra) = length_slot_for_valid_match(length);
            return EncodedMatch::RepeatDistance {
                index,
                length_slot,
                length_extra,
            };
        }

        let (distance_slot, distance_extra) = distance_slot_for_valid_match(distance);
        debug_assert!(distance_slot < distance_size);
        let bonus = length_bonus(distance);
        debug_assert!(length >= bonus + 2);
        let (length_slot, length_extra) = length_slot_for_valid_match(length - bonus);
        EncodedMatch::New {
            length_slot,
            length_extra,
            distance_slot,
            distance_extra,
            distance_bit_count: distance_slot_bit_count_valid(distance_slot),
        }
    }

    fn remember(&mut self, length: usize, distance: usize) {
        if distance == self.reps[0] && length == self.last_length {
            return;
        }
        let [first, second, third, _] = self.reps;
        self.reps = if distance == first {
            self.reps
        } else if distance == second {
            [distance, first, third, self.reps[3]]
        } else if distance == third {
            [distance, first, second, self.reps[3]]
        } else {
            [distance, first, second, third]
        };
        self.last_length = length;
    }
}

/// The Huffman code lengths a block of tokens produces. The block writer needs
/// these to emit the tables; the optimal parse needs them to know what each
/// token it is considering will actually cost.
#[cfg(test)]
fn table_lengths_for_tokens(tokens: &[EncodeToken], distance_size: usize) -> Result<OwnedLengths> {
    table_lengths_with_filters(tokens, &[], distance_size)
}

#[cfg(test)]
fn table_lengths_with_filters(
    tokens: &[EncodeToken],
    filters: &[EncodeFilter],
    distance_size: usize,
) -> Result<OwnedLengths> {
    table_lengths_with_allowance(tokens, filters, distance_size, &Allowance::default())
}

fn table_lengths_with_allowance<B: Budget>(
    tokens: &[EncodeToken],
    filters: &[EncodeFilter],
    distance_size: usize,
    allowance: &B,
) -> Result<OwnedLengths<B>> {
    table_lengths_for_stream(tokens.iter().copied(), filters, distance_size, allowance)
}

fn table_lengths_for_stream<B: Budget>(
    tokens: impl Iterator<Item = EncodeToken>,
    filters: &[EncodeFilter],
    distance_size: usize,
    allowance: &B,
) -> Result<OwnedLengths<B>> {
    stream_lengths_and_bits(tokens, filters, distance_size, allowance).map(|(lengths, _)| lengths)
}

/// The Huffman code lengths of a stream of tokens, and how many bits the
/// stream codes to under them, tables not included.
///
/// The count falls out of the symbol frequencies: every code is its length
/// once per use, and the extra bits and filter records do not depend on the
/// tables at all.
fn stream_lengths_and_bits<B: Budget>(
    tokens: impl Iterator<Item = EncodeToken>,
    filters: &[EncodeFilter],
    distance_size: usize,
    allowance: &B,
) -> Result<(OwnedLengths<B>, usize)> {
    let mut main_frequencies = Buffer::filled(MAIN_TABLE_SIZE, 0usize, allowance)?;
    main_frequencies[256] = filters.len();
    let mut distance_frequencies = Buffer::filled(distance_size, 0usize, allowance)?;
    let mut align_frequencies = Buffer::filled(ALIGN_TABLE_SIZE, 0usize, allowance)?;
    let mut length_frequencies = Buffer::filled(LENGTH_TABLE_SIZE, 0usize, allowance)?;
    let mut extra_bits = 0usize;
    let filter_record_bits = |filter: EncodeFilter| -> Result<usize> {
        let mut writer = BitWriter::with_allowance(allowance);
        try_write_filter(&mut writer, filter)?;
        Ok(writer.bit_pos)
    };
    for &filter in filters {
        extra_bits += filter_record_bits(filter)?;
    }
    let mut state = EncoderMatchState::default();
    for token in tokens {
        match token {
            EncodeToken::Filter(filter) => {
                main_frequencies[256] += 1;
                extra_bits += filter_record_bits(filter)?;
            }
            EncodeToken::Literal(byte) => main_frequencies[byte as usize] += 1,
            EncodeToken::Match { length, distance } => {
                match state.encode_match(length, distance, distance_size)? {
                    EncodedMatch::LastLengthRepeat => main_frequencies[257] += 1,
                    EncodedMatch::RepeatDistance {
                        index, length_slot, ..
                    } => {
                        main_frequencies[258 + index] += 1;
                        length_frequencies[length_slot] += 1;
                        extra_bits += usize::from(length_slot_extra_bits(length_slot));
                    }
                    EncodedMatch::New {
                        length_slot,
                        distance_slot,
                        distance_extra,
                        distance_bit_count,
                        ..
                    } => {
                        main_frequencies[262 + length_slot] += 1;
                        distance_frequencies[distance_slot] += 1;
                        extra_bits += usize::from(length_slot_extra_bits(length_slot));
                        if distance_bit_count >= 4 {
                            align_frequencies[distance_extra & 0x0f] += 1;
                            extra_bits += distance_bit_count - 4;
                        } else {
                            extra_bits += distance_bit_count;
                        }
                    }
                }
                state.remember(length, distance);
            }
        }
    }

    let lengths = OwnedLengths {
        main: huffman::complete_lengths_with_allowance(&main_frequencies, 15, allowance)?,
        distance: huffman::complete_lengths_with_allowance(&distance_frequencies, 15, allowance)?,
        align: huffman::complete_lengths_with_allowance(&align_frequencies, 15, allowance)?,
        length: huffman::complete_lengths_with_allowance(&length_frequencies, 15, allowance)?,
    };
    let coded = |frequencies: &[usize], lengths: &[u8]| -> usize {
        frequencies
            .iter()
            .zip(lengths)
            .map(|(&count, &length)| count * usize::from(length))
            .sum()
    };
    let bits = extra_bits
        + coded(&main_frequencies, &lengths.main)
        + coded(&distance_frequencies, &lengths.distance)
        + coded(&align_frequencies, &lengths.align)
        + coded(&length_frequencies, &lengths.length);
    Ok((lengths, bits))
}

/// Actual payload size, including the transmitted tables and filter records.
/// Padding and block-header size are monotonic in this bit count.
fn token_stream_bits<B: Budget>(
    tokens: &[EncodeToken],
    filters: &[EncodeFilter],
    lengths: &OwnedLengths<B>,
    distance_size: usize,
) -> Result<usize> {
    let version = if distance_size == DISTANCE_TABLE_SIZE_70 {
        1
    } else {
        0
    };
    let allowance = lengths.main.allowance();
    let (_, bits) = encode_table_slices(lengths.slices(), version, &allowance)?;
    token_stream_bits_after_tables(
        tokens.iter().copied(),
        filters,
        lengths,
        distance_size,
        bits,
    )
}

fn token_stream_bits_after_tables<B: Budget>(
    tokens: impl Iterator<Item = EncodeToken>,
    filters: &[EncodeFilter],
    lengths: &OwnedLengths<B>,
    distance_size: usize,
    mut bits: usize,
) -> Result<usize> {
    let allowance = lengths.main.allowance();
    let prices = TokenPrices {
        lengths: lengths.slices(),
    };
    let mut state = EncoderMatchState::default();
    for token in filters
        .iter()
        .copied()
        .map(EncodeToken::Filter)
        .chain(tokens)
    {
        match token {
            EncodeToken::Literal(byte) => bits += prices.literal(byte),
            EncodeToken::Match { length, distance } => {
                bits += prices.match_cost(&state, length, distance, distance_size)?;
                state.remember(length, distance);
            }
            EncodeToken::Filter(filter) => {
                let mut writer = BitWriter::with_allowance(&allowance);
                try_write_filter(&mut writer, filter)?;
                bits += usize::from(lengths.main[256]) + writer.bit_pos;
            }
        }
    }
    Ok(bits)
}

struct OptimalWorkspace<B: Budget = Allowance> {
    price: Buffer<u32, B>,
    arrive_length: Buffer<u32, B>,
    arrive_distance: Buffer<u32, B>,
    arrive_reps: Buffer<[u32; 4], B>,
    arrive_last_length: Buffer<u32, B>,
}

const OPTIMAL_STATE_RING_SIZE: usize = 8192;
const _: () = assert!(OPTIMAL_STATE_RING_SIZE.is_power_of_two());
const _: () = assert!(OPTIMAL_STATE_RING_SIZE > MAX_ENCODER_MATCH_LENGTH);

impl<B: Budget> OptimalWorkspace<B> {
    fn new(allowance: &B) -> Self {
        Self {
            price: Buffer::new(allowance),
            arrive_length: Buffer::new(allowance),
            arrive_distance: Buffer::new(allowance),
            arrive_reps: Buffer::new(allowance),
            arrive_last_length: Buffer::new(allowance),
        }
    }
}

/// What a literal is assumed to cost before any block has been coded, in the
/// same bit units [`estimated_match_cost`] reports. A literal is one main-table
/// symbol out of 256 plus the odds that the table is skewed, so eight is the
/// floor and nine is what real blocks measure.
const ESTIMATED_LITERAL_COST: u32 = 9;

/// How many times the optimal parse runs over a block. The first pass guesses
/// prices; the rest reprice against the tables the pass before produced.
const OPTIMAL_PARSE_PASSES: usize = 3;

/// What a symbol the first pass never used is assumed to cost. Reaching for
/// one is not forbidden, only expensive: the tables are rebuilt from whatever
/// the last pass chose, so a symbol that earns its place gets a real code.
const UNUSED_SYMBOL_COST: usize = 15;

/// Prices a token against the code lengths a previous pass produced, which is
/// what the block will really spend, rather than against the flat guess in
/// [`estimated_match_cost`].
struct TokenPrices<'a> {
    lengths: LengthSlices<'a>,
}

impl TokenPrices<'_> {
    fn code(bits: u8) -> usize {
        if bits == 0 {
            UNUSED_SYMBOL_COST
        } else {
            usize::from(bits)
        }
    }

    fn literal(&self, byte: u8) -> usize {
        Self::code(self.lengths.main[byte as usize])
    }

    // This is the inner optimal-parse loop's pricing operation. Keep it in
    // that loop rather than returning a codec Result through a stack slot for
    // every candidate length, including across generic codegen units.
    #[inline(always)]
    fn match_cost(
        &self,
        state: &EncoderMatchState,
        length: usize,
        distance: usize,
        distance_size: usize,
    ) -> Result<usize> {
        Ok(match state.encode_match(length, distance, distance_size)? {
            EncodedMatch::LastLengthRepeat => Self::code(self.lengths.main[257]),
            EncodedMatch::RepeatDistance {
                index, length_slot, ..
            } => {
                Self::code(self.lengths.main[258 + index])
                    + Self::code(self.lengths.length[length_slot])
                    + usize::from(length_slot_extra_bits(length_slot))
            }
            EncodedMatch::New {
                length_slot,
                distance_slot,
                distance_extra,
                distance_bit_count,
                ..
            } => {
                let align = if distance_bit_count >= 4 {
                    distance_bit_count - 4 + Self::code(self.lengths.align[distance_extra & 0x0f])
                } else {
                    distance_bit_count
                };
                Self::code(self.lengths.main[262 + length_slot])
                    + usize::from(length_slot_extra_bits(length_slot))
                    + Self::code(self.lengths.distance[distance_slot])
                    + align
            }
        })
    }
}

/// Length prices are invariant throughout one pass. A run also keeps the same
/// distance and arriving state while it prices every possible endpoint.
///
/// Lengths are priced one by one rather than a slot at a time, so the loop
/// that offers every endpoint of a run reads its costs in step with the
/// endpoints and has no branch to mispredict. A code is at most 15 bits and a
/// length slot's extra bits at most 9, so each cost fits a byte.
struct OptimalMatchPrices {
    /// What a fresh distance's match length costs, by encoded length.
    new_lengths: [u8; MAX_ENCODER_MATCH_LENGTH + 1],
    /// What a remembered distance's match length costs, by length.
    repeat_lengths: [u8; MAX_ENCODER_MATCH_LENGTH + 1],
    repeats: [u32; 4],
    last_repeat: u32,
}

struct MatchRunPrice<'a> {
    lengths: &'a [u8; MAX_ENCODER_MATCH_LENGTH + 1],
    distance: u32,
    bonus: usize,
    last_length: Option<usize>,
    last_repeat: u32,
}

/// The cost of every encodable length under one length table, indexed by the
/// length as coded. The two shortest cannot be coded and cost nothing here;
/// [`MatchRunPrice`] never asks for them.
fn length_costs(slot_code: impl Fn(usize) -> usize) -> [u8; MAX_ENCODER_MATCH_LENGTH + 1] {
    let slots: [u8; LENGTH_TABLE_SIZE] = std::array::from_fn(|slot| {
        let cost = slot_code(slot) + usize::from(length_slot_extra_bits(slot));
        u8::try_from(cost).expect("a length code and its extra bits fit a byte")
    });
    std::array::from_fn(|encoded| {
        if encoded < 2 {
            0
        } else {
            slots[length_slot_for_valid_match(encoded).0]
        }
    })
}

impl OptimalMatchPrices {
    fn new(prices: Option<&TokenPrices<'_>>) -> Self {
        Self {
            new_lengths: length_costs(|slot| {
                prices.map_or(0, |prices| {
                    TokenPrices::code(prices.lengths.main[262 + slot])
                })
            }),
            repeat_lengths: length_costs(|slot| {
                prices.map_or(0, |prices| TokenPrices::code(prices.lengths.length[slot]))
            }),
            repeats: std::array::from_fn(|index| {
                prices.map_or(5, |prices| {
                    TokenPrices::code(prices.lengths.main[258 + index]) as u32
                })
            }),
            last_repeat: prices.map_or(2, |prices| {
                TokenPrices::code(prices.lengths.main[257]) as u32
            }),
        }
    }

    fn run(
        &self,
        state: &EncoderMatchState,
        distance: usize,
        distance_size: usize,
        prices: Option<&TokenPrices<'_>>,
    ) -> Result<MatchRunPrice<'_>> {
        if let Some(index) = state
            .reps
            .iter()
            .position(|&repeat| repeat == distance && repeat != 0)
        {
            return Ok(MatchRunPrice {
                lengths: &self.repeat_lengths,
                distance: self.repeats[index],
                bonus: 0,
                last_length: (index == 0).then_some(state.last_length),
                last_repeat: self.last_repeat,
            });
        }
        let (slot, extra) = distance_slot_for_match(distance, distance_size)?;
        let bits = distance_slot_bit_count(slot)?;
        let cost = prices.map_or(10 + bits, |prices| {
            TokenPrices::code(prices.lengths.distance[slot])
                + if bits >= 4 {
                    bits - 4 + TokenPrices::code(prices.lengths.align[extra & 0x0f])
                } else {
                    bits
                }
        });
        Ok(MatchRunPrice {
            lengths: &self.new_lengths,
            distance: cost as u32,
            bonus: length_bonus(distance),
            last_length: None,
            last_repeat: self.last_repeat,
        })
    }
}

/// The cheapest arrival found so far at each position of a block: its price,
/// and the length and distance of the match that reached it, zero for a
/// literal.
struct Arrivals<'a> {
    price: &'a mut [u32],
    length: &'a mut [u32],
    distance: &'a mut [u32],
}

impl MatchRunPrice<'_> {
    /// Offers the endpoint of every length in `lengths`, at `distance`, from
    /// the position `index` that was reached for `here`. An endpoint takes an
    /// offer only if it is strictly cheaper, so the first offer of a price
    /// keeps it.
    #[inline(always)]
    fn relax(
        &self,
        here: u32,
        index: usize,
        lengths: std::ops::RangeInclusive<usize>,
        distance: u32,
        mut paths: Arrivals<'_>,
    ) {
        // A length the distance bonus leaves under two cannot be coded.
        let first = (*lengths.start()).max(self.bonus + 2);
        let last = *lengths.end();
        if first > last {
            return;
        }
        let base = here.saturating_add(self.distance);
        match self.last_length {
            // The remembered last length is coded on its own, for its own
            // price, and the lengths either side of it as usual.
            Some(repeat) if (first..=last).contains(&repeat) => {
                self.relax_lengths(base, index, first, repeat - 1, distance, &mut paths);
                let reached = here.saturating_add(self.last_repeat);
                let target = index + repeat;
                if reached < paths.price[target] {
                    paths.price[target] = reached;
                    paths.length[target] = repeat as u32;
                    paths.distance[target] = distance;
                }
                self.relax_lengths(base, index, repeat + 1, last, distance, &mut paths);
            }
            _ => self.relax_lengths(base, index, first, last, distance, &mut paths),
        }
    }

    /// The loop every endpoint goes through.
    ///
    /// Endpoints are compared eight at a time, which the compiler does in
    /// vector registers, and only a group with a winner is updated. A
    /// branch-free update of all three arrays stores every endpoint where few
    /// of them win.
    #[inline(always)]
    fn relax_lengths(
        &self,
        base: u32,
        index: usize,
        first: usize,
        last: usize,
        distance: u32,
        paths: &mut Arrivals<'_>,
    ) {
        const GROUP: usize = 8;
        if first > last {
            return;
        }
        let count = last + 1 - first;
        let costs = &self.lengths[first - self.bonus..][..count];
        let price = &mut paths.price[index + first..][..count];
        let arrive_length = &mut paths.length[index + first..][..count];
        let arrive_distance = &mut paths.distance[index + first..][..count];
        let mut offset = 0;
        while offset < count {
            let group = GROUP.min(count - offset);
            if group == GROUP {
                let costs: &[u8; GROUP] = costs[offset..offset + GROUP].try_into().unwrap();
                let prices: &[u32; GROUP] = price[offset..offset + GROUP].try_into().unwrap();
                let mut wins = false;
                for (&cost, &price) in costs.iter().zip(prices) {
                    wins |= base.saturating_add(u32::from(cost)) < price;
                }
                if !wins {
                    offset += GROUP;
                    continue;
                }
            }
            for at in offset..offset + group {
                let reached = base.saturating_add(u32::from(costs[at]));
                if reached < price[at] {
                    price[at] = reached;
                    // Lengths stop at MAX_ENCODER_MATCH_LENGTH, far inside a u32.
                    arrive_length[at] = (first + at) as u32;
                    arrive_distance[at] = distance;
                }
            }
            offset += group;
        }
    }

    #[cfg(test)]
    #[inline]
    fn cost(&self, length: usize) -> Option<u32> {
        if self.last_length == Some(length) {
            return Some(self.last_repeat);
        }
        let encoded = length.checked_sub(self.bonus)?;
        if encoded < 2 {
            return None;
        }
        debug_assert!(length <= MAX_ENCODER_MATCH_LENGTH);
        Some(self.distance + u32::from(self.lengths[encoded]))
    }
}

struct OptimalSlices<'a> {
    price: &'a mut [u32],
    arrive_length: &'a mut [u32],
    arrive_distance: &'a mut [u32],
    arrive_reps: &'a mut [[u32; 4]],
    arrive_last_length: &'a mut [u32],
}

// No growth or ownership changes occur here. Keep one pricing implementation
// for bounded and unlimited execution instead of specializing this hot loop on
// their differently sized allocation owners and fallible push operations.
#[allow(clippy::too_many_arguments)]
fn price_optimal_paths(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    runs: &[(u32, u32)],
    starts: &[u32],
    commits: &[match_finder::CommittedMatch],
    workspace: OptimalSlices<'_>,
    reaches: &mut [(usize, usize, usize)],
) {
    if workspace.arrive_reps.len() < block.len() + 1 {
        price_optimal_paths_with_state::<true>(
            combined,
            block,
            options,
            distance_size,
            prices,
            runs,
            starts,
            commits,
            workspace,
            reaches,
        );
        return;
    }
    price_optimal_paths_with_state::<false>(
        combined,
        block,
        options,
        distance_size,
        prices,
        runs,
        starts,
        commits,
        workspace,
        reaches,
    );
}

#[allow(clippy::too_many_arguments)]
fn price_optimal_paths_with_state<const RING: bool>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    runs: &[(u32, u32)],
    starts: &[u32],
    commits: &[match_finder::CommittedMatch],
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
    let (arrive_reps, arrive_last_length, state_mask) = if RING {
        // Prove both lengths once in this specialization. Constant masks then
        // stay within these arrays without per-access dynamic length checks.
        let fixed_reps: &mut [[u32; 4]; OPTIMAL_STATE_RING_SIZE] = arrive_reps
            .try_into()
            .expect("ring recent-distance storage has its planned length");
        let fixed_last: &mut [u32; OPTIMAL_STATE_RING_SIZE] = arrive_last_length
            .try_into()
            .expect("ring last-length storage has its planned length");
        let reps: &mut [[u32; 4]] = fixed_reps;
        let last: &mut [u32] = fixed_last;
        (reps, last, OPTIMAL_STATE_RING_SIZE - 1)
    } else {
        (arrive_reps, arrive_last_length, usize::MAX)
    };
    // The first position past a match the parse committed to. Nothing is
    // priced from the positions before it. See [`NICE_MATCH_LENGTH`].
    let mut committed_through = 0usize;
    // Where a match the collector committed to may still reach after this
    // parse's own commit ends, and the collector's commit to look at next.
    let mut landed_until = 0usize;
    let mut commit = 0usize;
    let match_prices = OptimalMatchPrices::new(prices);
    let nice = options.nice();

    for index in 0..span {
        let pos = start + index;
        if index < committed_through {
            continue;
        }
        // The distance memory this position is reached with, built once from
        // the edge that won it rather than stored on every improvement. Every
        // edge into it came from a position already passed, so the winner is
        // settled, and its source was priced: a skipped position emits no
        // edge. Sources lie at most 4096 back, inside the 8192-slot ring.
        let state = if index == 0 {
            EncoderMatchState {
                reps: arrive_reps[0].map(|distance| distance as usize),
                last_length: arrive_last_length[0] as usize,
            }
        } else {
            let length = arrive_length[index] as usize;
            let from = (index - length.max(1)) & state_mask;
            let mut state = EncoderMatchState {
                reps: arrive_reps[from].map(|distance| distance as usize),
                last_length: arrive_last_length[from] as usize,
            };
            // A literal emits no distance, so it leaves the remembered ones
            // exactly as it found them.
            if length != 0 {
                state.remember(length, arrive_distance[index] as usize);
            }
            let slot = index & state_mask;
            arrive_reps[slot] = state.reps.map(|distance| distance as u32);
            arrive_last_length[slot] = state.last_length as u32;
            state
        };
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
        }

        let max_distance = pos.min(options.max_match_distance);
        let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        if options.max_match_candidates == 0 || max_distance == 0 || max_length < 4 {
            continue;
        }

        let mut reaches_len = 0;
        let mut longest = 0usize;
        let mut farthest = 0usize;

        // A match at a remembered distance is priced out of the main table
        // alone, a handful of bits against twenty for a fresh distance, so it
        // earns its place even when it is shorter than anything the collector
        // found. The collector only reports a candidate that beats the longest
        // found so far, so these have to be asked for separately.
        for repeat in state.reps {
            if repeat == 0 || repeat > max_distance {
                continue;
            }
            let length = if RING {
                // Only matches of at least four bytes reach the price graph.
                // Reject shorter repeats before calling the extension kernel;
                // the guard above proves both prefixes and the suffix fit.
                if combined[pos..pos + 4] != combined[pos - repeat..pos - repeat + 4] {
                    continue;
                }
                4 + match_length(combined, pos + 4, repeat, max_length - 4)
            } else {
                match_length(combined, pos, repeat, max_length)
            };
            if length >= 4 {
                reaches[reaches_len] = (4, length, repeat);
                reaches_len += 1;
                farthest = farthest.max(length);
            }
        }

        // The collector reports nearest first, so the first distance to reach
        // a length is the cheapest one that can. Each report that improves on
        // the longest so far owns one run of lengths. The tree measures
        // against the whole member where the chains stopped at the block, so
        // a length is capped here to what this block can still hold.
        //
        // A run at a remembered distance offers what that distance's own
        // reach above already offered, at the same prices: the reach was
        // measured out to the real end of the match, which is as far as any
        // run at that distance gets. Such a run is left out.
        let repeat_reaches = reaches_len;
        let mut found = &runs[starts[index] as usize..starts[index + 1] as usize];
        // Nothing found here may be a position the collector stepped over,
        // inside a match it committed to where this parse did not.
        let tail;
        if found.is_empty() && index < landed_until {
            if let Some(run) = committed_tail(commits, &mut commit, pos) {
                tail = [run];
                found = &tail;
            }
        }
        for &(length, distance) in found {
            let length = (length as usize).min(max_length);
            if length > longest {
                let distance = distance as usize;
                if !reaches[..repeat_reaches]
                    .iter()
                    .any(|&(_, reach, repeat)| repeat == distance && reach >= length)
                {
                    reaches[reaches_len] = (longest + 1, length, distance);
                    reaches_len += 1;
                }
                longest = length;
            }
        }

        let reaches = &reaches[..reaches_len];
        // A run left out above reached no further than its distance's reach.
        let farthest = farthest.max(longest);

        // Equal token prices do not make shorter matches redundant: their
        // endpoints can expose a better continuation. Price every endpoint
        // unless the explicit long-match heuristic commits past all of them.
        let committed_reach = (farthest >= nice).then_some(farthest);
        for &(run_start, run_end, distance) in reaches.iter() {
            let mut length = run_start.max(4);
            if let Some(committed) = committed_reach {
                if run_end < committed {
                    continue;
                }
                length = committed;
            }
            let Ok(run_price) = match_prices.run(&state, distance, distance_size, prices) else {
                continue;
            };
            run_price.relax(
                here,
                index,
                length..=run_end,
                distance as u32,
                Arrivals {
                    price: &mut *price,
                    length: &mut *arrive_length,
                    distance: &mut *arrive_distance,
                },
            );
        }

        // A committed match is at least eight bytes long. Even after the
        // distance bonus, that length and every collected u32 distance fit
        // their encoder tables, so the endpoint has already been priced.
        if let Some(reach) = committed_reach {
            committed_through = index + reach;
            landed_until = committed_through + MAX_ENCODER_MATCH_LENGTH;
        }
    }
}

/// What is left at `pos` of the match the collector committed to around it,
/// if it committed to one, moving `commit` on past those behind `pos`.
#[cold]
fn committed_tail(
    commits: &[match_finder::CommittedMatch],
    commit: &mut usize,
    pos: usize,
) -> Option<(u32, u32)> {
    while commits.get(*commit).is_some_and(|c| c.end <= pos) {
        *commit += 1;
    }
    commits.get(*commit).and_then(|c| c.tail(pos))
}

/// Prices every path through the block and keeps the cheapest, instead of
/// taking the longest match at each position and checking one or two bytes
/// ahead. Prices come from [`estimated_match_cost`], so this is only as good
/// as that estimate, but it sees the whole block where lazy matching sees two
/// bytes.
///
/// The repeated-distance discount depends on the path taken, which a forward
/// pass does not know. Each node carries the whole four-slot distance memory
/// the cheapest path to it leaves behind, so the next hop is priced against
/// what that path would really have remembered. Two paths reaching one node
/// with different memories still collapse into whichever was cheaper, so this
/// stays an approximation, just a far closer one than carrying the arriving
/// match alone. It is also not quite every path: once a match reaches
/// [`NICE_MATCH_LENGTH`] the parse takes it and steps over the bytes it covers
/// rather than pricing each of them.
///
/// Does no searching of its own: `matches` holds what an [`OptimalCollector`]
/// found at each position of this block, and prices never change what a
/// search would find, so every pass prices the same collection.
fn optimal_tokens_in_workspace<B: Budget>(
    combined: &[u8],
    block: Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    matches: &BlockMatches<B>,
    workspace: &mut OptimalWorkspace<B>,
) -> Result<Buffer<EncodeToken, B>> {
    price_optimal_tokens::<B, EncodeToken, false>(
        combined,
        block,
        options,
        distance_size,
        prices,
        matches,
        workspace,
    )
}

fn price_optimal_tokens<B: Budget, T: From<EncodeToken>, const BOUNDED: bool>(
    combined: &[u8],
    block: Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    matches: impl std::borrow::Borrow<BlockMatches<B>>,
    workspace: &mut OptimalWorkspace<B>,
) -> Result<Buffer<T, B>> {
    #[cfg(test)]
    convergence_tests::record_pricing_pass();
    let start = block.start;
    let end = block.end;
    let span = end - start;

    let allowance = workspace.price.allowance();
    let found = matches.borrow();
    if !B::LIMITED && found.runs.is_empty() {
        // Every parse starts with empty distance memory. Without a collected
        // match, literals cannot introduce a remembered distance, so they are
        // the only path through this block under any set of table prices.
        // Limited parses retain their allocation and refusal order below.
        return Buffer::collect(
            combined[block]
                .iter()
                .copied()
                .map(EncodeToken::Literal)
                .map(T::from),
            &allowance,
        );
    }
    let OptimalWorkspace {
        price,
        arrive_length,
        arrive_distance,
        arrive_reps,
        arrive_last_length,
    } = workspace;
    let state_length = (span + 1).min(OPTIMAL_STATE_RING_SIZE);
    price.resize(span + 1, u32::MAX)?;
    price.fill(u32::MAX);
    arrive_length.resize(span + 1, 0)?;
    arrive_length.fill(0);
    arrive_distance.resize(span + 1, 0)?;
    arrive_distance.fill(0);
    arrive_reps.resize(state_length, [0; 4])?;
    arrive_reps.fill([0; 4]);
    arrive_last_length.resize(state_length, 0)?;
    arrive_last_length.fill(0);
    price[0] = 0;

    // Admit the largest candidate list once. Pricing only borrows already
    // charged arrays, so its inner loop is identical for both budget policies.
    // Each position contributes at most four remembered-distance candidates.
    let longest_run = found
        .starts
        .windows(2)
        .map(|pair| (pair[1] - pair[0]) as usize)
        .max()
        .unwrap_or(0);
    // A position contributes at most one run for each encodable match length.
    // Four remembered distances are added while pricing, so this bound cannot
    // approach usize::MAX for a valid BlockMatches collection.
    debug_assert!(longest_run <= MAX_ENCODER_MATCH_LENGTH);
    let reach_capacity = longest_run + 4;
    let mut reaches = Buffer::filled(reach_capacity, (0usize, 0usize, 0usize), &allowance)?;
    price_optimal_paths(
        combined,
        block.clone(),
        options,
        distance_size,
        prices,
        &found.runs,
        &found.starts,
        &found.commits,
        OptimalSlices {
            price,
            arrive_length,
            arrive_distance,
            arrive_reps,
            arrive_last_length,
        },
        &mut reaches,
    );

    if BOUNDED {
        drop(matches);
        *price = Buffer::new(&allowance);
        *arrive_reps = Buffer::new(&allowance);
        *arrive_last_length = Buffer::new(&allowance);
        drop(reaches);
    }
    let mut reversed = Buffer::new(&allowance);
    let mut index = span;
    while index > 0 {
        if BOUNDED && reversed.len() == reversed.capacity() {
            reversed.grow_in_place(reversed.capacity().max(2).saturating_mul(2).min(span))?;
        }
        let length = arrive_length[index] as usize;
        if length == 0 {
            reversed
                .push(T::from(EncodeToken::Literal(combined[start + index - 1])))
                .map_err(Into::into)?;
            index -= 1;
        } else {
            reversed
                .push(T::from(EncodeToken::Match {
                    length,
                    distance: arrive_distance[index] as usize,
                }))
                .map_err(Into::into)?;
            index -= length;
        }
    }
    reversed.reverse();
    Ok(reversed)
}

#[cfg(test)]
fn encode_tokens_with_progress(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_>,
    options: EncodeOptions,
    distance_size: usize,
    initial_filters: &[EncodeFilter],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Buffer<EncodeToken>> {
    let allowance = match &search {
        MemberSearch::Fresh => Allowance::default(),
        MemberSearch::Lazy(finder) => finder.allowance().clone(),
        MemberSearch::Optimal(collector) => match &collector.finder {
            CollectorFinder::Packed(finder) => finder.allowance(),
            CollectorFinder::Tree(finder, _) => finder.allowance().clone(),
            CollectorFinder::Chains(finder) => finder.allowance().clone(),
        },
    };
    encode_tokens_with_allowance(
        combined,
        block,
        search,
        options,
        distance_size,
        initial_filters,
        progress,
        &allowance,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn encode_tokens_with_allowance<B: Budget>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_, B>,
    options: EncodeOptions,
    distance_size: usize,
    initial_filters: &[EncodeFilter],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<EncodeToken, B>> {
    if options.optimal_parse {
        encode_optimal_tokens(
            combined,
            block,
            search,
            options,
            distance_size,
            initial_filters,
            progress,
            allowance,
        )
    } else {
        lazy_tokens::<B, EncodeToken>(
            combined,
            block,
            search,
            options,
            distance_size,
            progress,
            allowance,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_optimal_tokens<B: Budget>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_, B>,
    options: EncodeOptions,
    distance_size: usize,
    initial_filters: &[EncodeFilter],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<EncodeToken, B>> {
    let block_len = block.len();
    let matches = collect_optimal_matches(combined, block.clone(), search, options, allowance)?;
    let tokens = optimal_tokens_for_matches(
        combined,
        block,
        options,
        distance_size,
        initial_filters,
        &matches,
        allowance,
    )?;
    if progress.is_some_and(|report| !report(block_len)) {
        return Err(Error::Cancelled);
    }
    Ok(tokens)
}

fn collect_optimal_matches<B: Budget>(
    combined: &[u8],
    block: Range<usize>,
    search: MemberSearch<'_, B>,
    options: EncodeOptions,
    allowance: &B,
) -> Result<BlockMatches<B>> {
    match search {
        MemberSearch::Optimal(collector) => collector.collect(combined, block, options),
        _ => {
            // A fresh index has no continuation once this block's matches
            // are collected. Drop it before allocating pricing workspace.
            let mut own =
                OptimalCollector::with_allowance(combined, block.start, options, allowance)?;
            own.collect(combined, block, options)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_single_pass_block<B: Budget>(
    combined: &[u8],
    block: Range<usize>,
    options: EncodeOptions,
    algorithm_version: u8,
    distance_size: usize,
    is_last: bool,
    matches: BlockMatches<B>,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let span = block.len();
    let tokens = price_optimal_tokens::<B, PackedToken, true>(
        combined,
        block,
        options,
        distance_size,
        None,
        matches,
        &mut OptimalWorkspace::new(allowance),
    )?;
    if progress.is_some_and(|report| !report(span)) {
        return Err(Error::Cancelled);
    }
    let payload = encode_token_payload(
        tokens.iter().copied().map(PackedToken::decode),
        NO_RECORDS,
        algorithm_version,
        distance_size,
        allowance,
    )?;
    drop(tokens);
    encode_compressed_block_with_allowance(
        &payload.bytes,
        payload.bit_pos,
        true,
        is_last,
        allowance,
    )
}

fn lazy_tokens<B: Budget, T: From<EncodeToken>>(
    combined: &[u8],
    block: Range<usize>,
    search: MemberSearch<'_, B>,
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<T, B>> {
    let start = block.start;
    let end = block.end;

    let mut own;
    let finder = match search {
        MemberSearch::Lazy(finder) => finder,
        _ => {
            own = seeded_finder(combined, start..end, options, allowance)?;
            &mut own
        }
    };
    if options.parses_greedily() {
        return greedy_tokens(
            combined,
            block,
            finder,
            options,
            distance_size,
            progress,
            allowance,
        );
    }
    let mut tokens = Buffer::new(allowance);
    let mut pos = start;
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    let mut pending_match: Option<MatchCandidate> = None;
    // The scan decides only where the chain is walked; every position still
    // goes into it.
    let mut noise = NoiseScan::with_cells(start);
    while pos < end {
        let candidate = pending_match.take().or_else(|| {
            let chain = !noise.skips(combined, pos);
            best_match_with(
                combined,
                pos,
                end,
                finder,
                options,
                &state,
                distance_size,
                chain,
            )
        });
        if let Some(candidate) = candidate {
            let (emit_literal, cached_next) = lazy_match_decision(
                combined,
                pos,
                end,
                finder,
                options,
                &state,
                distance_size,
                candidate,
                &mut noise,
            );
            if emit_literal {
                tokens
                    .push(T::from(EncodeToken::Literal(combined[pos])))
                    .map_err(Into::into)?;
                finder.insert(combined, pos);
                pos += 1;
                pending_match = cached_next;
                continue;
            }
            let MatchCandidate {
                length, distance, ..
            } = candidate;
            tokens
                .push(T::from(EncodeToken::Match { length, distance }))
                .map_err(Into::into)?;
            state.remember(length, distance);
            for history_pos in pos..pos + length {
                finder.insert(combined, history_pos);
            }
            pos += length;
        } else {
            tokens
                .push(T::from(EncodeToken::Literal(combined[pos])))
                .map_err(Into::into)?;
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

/// How many positions after a match's first the greedy parse puts into the
/// finder. The rest of a long match is stepped over unhashed, which costs
/// about a quarter of a percent on binaries and buys a tenth of the time.
const GREEDY_INSERTED_PER_MATCH: usize = 16;

/// The least score a greedy match must beat to be taken over a literal. A four
/// byte match whose estimated cost is 16 bits or more goes out as literals,
/// which leaves the next position free to start a longer one.
const GREEDY_MIN_SCORE: isize = 48;

/// Each run of this many positions without a match adds one more literal the
/// greedy parse steps over unsearched, so data that does not compress is
/// crossed in a fraction of the searches.
const GREEDY_MISS_SHIFT: u32 = 7;

/// The greedy parse: at each position the best of the remembered distances and
/// the first `max_match_candidates` positions in the hash chain, taken without
/// looking ahead. Matches enter the finder only partly; see
/// [`GREEDY_INSERTED_PER_MATCH`].
fn greedy_tokens<B: Budget, T: From<EncodeToken>>(
    combined: &[u8],
    block: Range<usize>,
    finder: &mut Rar50MatchFinder<B>,
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<T, B>> {
    let start = block.start;
    let end = block.end;
    let mut tokens = Buffer::new(allowance);
    let mut pos = start;
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    let mut misses = 0usize;
    // The last position with four bytes after it to hash.
    let searchable_end = end.min(combined.len().saturating_sub(3));
    let word = |at: usize| u32::from_le_bytes(combined[at..at + 4].try_into().unwrap());
    while pos < end {
        if pos >= searchable_end || end - pos < 4 {
            tokens
                .push(T::from(EncodeToken::Literal(combined[pos])))
                .map_err(Into::into)?;
            finder.insert(combined, pos);
            pos += 1;
            continue;
        }
        let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        let max_distance = pos.min(options.max_match_distance);
        let here = word(pos);
        let mut candidate = finder.insert_and_first(combined, pos);
        let mut best = None;
        for &distance in &state.reps {
            if distance != 0 && distance <= max_distance && word(pos - distance) == here {
                let length = match_length(combined, pos, distance, max_length);
                consider_match_candidate(&mut best, &state, distance_size, length, distance);
            }
        }
        let mut checked = 0;
        while candidate != match_finder::NO_POSITION && checked < options.max_match_candidates {
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            if distance != state.reps[0] && word(candidate) == here {
                let length = match_length(combined, pos, distance, max_length);
                consider_match_candidate(&mut best, &state, distance_size, length, distance);
            }
            if checked < options.max_match_candidates {
                candidate = finder.previous(candidate);
            }
        }
        match best {
            Some(MatchCandidate {
                length,
                distance,
                score,
            }) if score > GREEDY_MIN_SCORE => {
                tokens
                    .push(T::from(EncodeToken::Match { length, distance }))
                    .map_err(Into::into)?;
                state.remember(length, distance);
                let inserted_end = (pos + length)
                    .min(pos + 1 + GREEDY_INSERTED_PER_MATCH)
                    .min(searchable_end);
                finder.insert_run(combined, pos + 1..inserted_end);
                pos += length;
                misses = 0;
            }
            _ => {
                misses += 1;
                let skipped = 1 + (misses >> GREEDY_MISS_SHIFT).min(end - pos - 1);
                for &byte in &combined[pos..pos + skipped] {
                    tokens
                        .push(T::from(EncodeToken::Literal(byte)))
                        .map_err(Into::into)?;
                }
                pos += skipped;
            }
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

/// The optimal parse of one block whose matches are already collected.
///
/// Nothing here reads state from another block: every parse starts with empty
/// distance memory, and its prices come from its own passes. That is what lets
/// a member's blocks be priced on several threads once the collector, which is
/// sequential, has been through them.
fn optimal_tokens_for_matches<B: Budget>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    initial_filters: &[EncodeFilter],
    matches: &BlockMatches<B>,
    allowance: &B,
) -> Result<Buffer<EncodeToken, B>> {
    // The prices come from the Huffman tables, and the tables come from
    // the parse, so the first pass has to guess. Each pass after it prices
    // against what the pass before actually produced.
    let mut workspace = OptimalWorkspace::new(allowance);
    let mut tokens = optimal_tokens_in_workspace(
        combined,
        block.clone(),
        options,
        distance_size,
        None,
        matches,
        &mut workspace,
    )?;
    let mut lengths =
        table_lengths_with_allowance(&tokens, initial_filters, distance_size, allowance)?;
    let mut best_bits = token_stream_bits(&tokens, initial_filters, &lengths, distance_size)?;
    // Without a collected match, every pass starts with no remembered
    // distance and can only produce the same literals. Keep the first
    // tables and stream validation before skipping the equal reparse.
    // Limited callers retain every original admission and refusal point.
    let passes = if !B::LIMITED && matches.runs.is_empty() {
        1
    } else {
        options.parse_passes.max(1)
    };
    let mut best = None;
    for _ in 1..passes {
        let prices = TokenPrices {
            lengths: lengths.slices(),
        };
        let next = optimal_tokens_in_workspace(
            combined,
            block.clone(),
            options,
            distance_size,
            Some(&prices),
            matches,
            &mut workspace,
        )?;
        if next == tokens {
            break;
        }
        let next_lengths =
            table_lengths_with_allowance(&next, initial_filters, distance_size, allowance)?;
        let tables_converged = lengths.slices() == next_lengths.slices();
        lengths = next_lengths;
        let bits = token_stream_bits(&next, initial_filters, &lengths, distance_size)?;
        if bits < best_bits {
            best_bits = bits;
            best = None;
        } else if best.is_none() {
            // Keep an earlier winner only when repricing actually loses.
            best = Some(std::mem::replace(&mut tokens, Buffer::new(allowance)));
        }
        tokens = next;
        if tables_converged {
            // With the same matches, initial state and table prices, the
            // next pass would reproduce these tokens and stop above. Keep
            // the normal winner and tie handling before skipping it.
            break;
        }
    }
    Ok(best.unwrap_or(tokens))
}

#[cfg(test)]
#[path = "convergence_tests.rs"]
mod convergence_tests;

/// Decides whether a literal should be emitted instead of `current` because a
/// better match starts within the lazy lookahead window. Also returns the
/// match found one byte ahead (when computed) so the caller can reuse it for
/// the next position instead of searching again.
#[allow(clippy::too_many_arguments)]
fn lazy_match_decision<B: Budget>(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar50MatchFinder<B>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    current: MatchCandidate,
    noise: &mut NoiseScan,
) -> (bool, Option<MatchCandidate>) {
    if !options.lazy_matching {
        return (false, None);
    }
    let lookahead = options.lazy_lookahead.max(1);
    let mut cached_next = None;
    for offset in 1..=lookahead {
        if pos + offset >= end {
            break;
        }
        let next = best_match_with(
            input,
            pos + offset,
            end,
            finder,
            options,
            state,
            distance_size,
            !noise.skips(input, pos + offset),
        );
        if offset == 1 {
            cached_next = next;
        }
        let skipped_literal_score = offset as isize * 8;
        if next.is_some_and(|next| next.score > current.score + skipped_literal_score) {
            return (true, cached_next);
        }
    }
    (false, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchCandidate {
    length: usize,
    distance: usize,
    score: isize,
}

#[cfg(test)]
fn best_match<B: Budget>(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar50MatchFinder<B>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
) -> Option<MatchCandidate> {
    best_match_with(input, pos, end, finder, options, state, distance_size, true)
}

/// The best match at `pos`, from the remembered distances and, when `chain`
/// is set, the hash chain.
#[allow(clippy::too_many_arguments)]
fn best_match_with<B: Budget>(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar50MatchFinder<B>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    chain: bool,
) -> Option<MatchCandidate> {
    let max_distance = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0 || max_distance == 0 || max_length < 4 {
        return None;
    }
    let mut best = None;

    let mut checked = 0usize;
    for distance in state.reps {
        // Remembered matches were admitted under this same distance limit at
        // an earlier position, so only unfilled repeat slots need skipping.
        if distance == 0 {
            continue;
        }
        let length = match_length(input, pos, distance, max_length);
        consider_match_candidate(&mut best, state, distance_size, length, distance);
    }
    if let Some(best) = best {
        if best.length == max_length || best.length >= options.nice() {
            return Some(best);
        }
    }

    if chain {
        let mut candidate = finder.first(input, pos);
        while candidate != match_finder::NO_POSITION {
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            // A candidate can only improve on the current best when it matches at
            // least one byte past the best length, so probe that byte first.
            let best_length = best.map_or(0, |best: MatchCandidate| best.length);
            if best_length == 0 || input[candidate + best_length] == input[pos + best_length] {
                let length = match_length(input, pos, distance, max_length);
                consider_match_candidate(&mut best, state, distance_size, length, distance);
            }
            if let Some(best) = best {
                if best.length == max_length || best.length >= options.nice() {
                    break;
                }
            }
            if checked >= options.max_match_candidates {
                break;
            }
            candidate = finder.previous(candidate);
        }
    }
    best
}

fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    super::super::fast::match_length(input, pos, distance, max_length)
}

#[inline]
fn consider_match_candidate(
    best: &mut Option<MatchCandidate>,
    state: &EncoderMatchState,
    distance_size: usize,
    length: usize,
    distance: usize,
) {
    if length < 4 {
        return;
    }
    let Ok(cost) = estimated_match_cost(state, length, distance, distance_size) else {
        return;
    };
    let candidate = MatchCandidate {
        length,
        distance,
        score: (length as isize * 16) - cost as isize,
    };
    if best.is_none_or(|best| {
        candidate.score > best.score
            || (candidate.score == best.score
                && (candidate.length > best.length
                    || (candidate.length == best.length && candidate.distance < best.distance)))
    }) {
        *best = Some(candidate);
    }
}

// Generic parsers can be instantiated in a different codegen unit. Keep the
// estimate available for inlining into their per-length pricing loop.
#[inline]
fn estimated_match_cost(
    state: &EncoderMatchState,
    length: usize,
    distance: usize,
    distance_size: usize,
) -> Result<usize> {
    if distance == state.reps[0] && length == state.last_length {
        return Ok(2);
    }
    if state
        .reps
        .iter()
        .any(|&repeat_distance| repeat_distance == distance && repeat_distance != 0)
    {
        let (length_slot, _) = length_slot_for_match(length)?;
        return Ok(5 + usize::from(length_slot_extra_bits(length_slot)));
    }

    let (distance_slot, _) = distance_slot_for_match(distance, distance_size)?;
    let encoded_length = length
        .checked_sub(length_bonus(distance))
        .ok_or(Error::InvalidData("RAR 5 adjusted match length underflows"))?;
    let (length_slot, _) = length_slot_for_match(encoded_length)?;
    Ok(10
        + usize::from(length_slot_extra_bits(length_slot))
        + distance_slot_bit_count(distance_slot)?)
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 2 {
        return Err(Error::InvalidData("RAR 5 match length is too short"));
    }
    Ok(length_slot_for_valid_match(length))
}

fn length_slot_for_valid_match(length: usize) -> (usize, usize) {
    debug_assert!(length >= 2);
    let value = length - 2;
    if value < 8 {
        return (value, 0);
    }
    let bit_count = value.ilog2() as usize - 2;
    let slot = ((bit_count + 1) << 2) | ((value >> bit_count) & 3);
    // The encoder caps matches at 4096 bytes, which fits slots 0..44.
    (slot, value & ((1 << bit_count) - 1))
}

fn distance_slot_for_match(distance: usize, distance_size: usize) -> Result<(usize, usize)> {
    // Every emitted match comes from an earlier input position, and the two
    // production distance tables both have at least four entries.
    if distance == 0 {
        return Err(Error::InvalidData("RAR 5 match distance is zero"));
    }
    let result = distance_slot_for_valid_match(distance);
    if result.0 >= distance_size {
        return Err(Error::InvalidData("RAR 5 match distance is too large"));
    }
    Ok(result)
}

fn distance_slot_for_valid_match(distance: usize) -> (usize, usize) {
    debug_assert!(distance != 0);
    let value = distance - 1;
    if value < 4 {
        return (value, 0);
    }
    let bit_count = value.ilog2() as usize - 1;
    let slot = (bit_count << 1) + 2 + ((value >> bit_count) & 1);
    (slot, value & ((1 << bit_count) - 1))
}

fn distance_slot_bit_count_valid(slot: usize) -> usize {
    if slot < 4 {
        0
    } else {
        (slot - 2) >> 1
    }
}

fn literal_presence(data: &[u8]) -> [bool; 256] {
    let mut present = [false; 256];
    for &byte in data {
        present[byte as usize] = true;
    }
    present
}

fn try_write_filter<B: Budget>(writer: &mut BitWriter<B>, filter: EncodeFilter) -> Result<()> {
    if filter.offset > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter offset is too large"));
    }
    if filter.length > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter length is too large"));
    }
    try_write_filter_data(writer, filter.offset as u32)?;
    try_write_filter_data(writer, filter.length as u32)?;
    match filter.filter_type {
        FilterType::Delta => {
            if filter.channels == 0 || filter.channels > MAX_DELTA_CHANNELS {
                return Err(Error::InvalidData(
                    "RAR 5 DELTA filter channel count is invalid",
                ));
            }
            writer.try_write_bits(0, 3).map_err(Into::into)?;
            writer
                .try_write_bits(filter.channels - 1, 5)
                .map_err(Into::into)?;
        }
        FilterType::E8 => writer.try_write_bits(1, 3).map_err(Into::into)?,
        FilterType::E8E9 => writer.try_write_bits(2, 3).map_err(Into::into)?,
        FilterType::Arm => writer.try_write_bits(3, 3).map_err(Into::into)?,
    }
    Ok(())
}

fn write_valid_filter<B: Budget>(writer: &mut BitWriter<B>, filter: EncodeFilter) {
    debug_assert!(u32::try_from(filter.offset).is_ok());
    debug_assert!(u32::try_from(filter.length).is_ok());
    write_filter_data_admitted(writer, filter.offset as u32);
    write_filter_data_admitted(writer, filter.length as u32);
    match filter.filter_type {
        FilterType::Delta => {
            debug_assert!((1..=MAX_DELTA_CHANNELS).contains(&filter.channels));
            writer.write_admitted_bits(0, 3);
            writer.write_admitted_bits(filter.channels - 1, 5);
        }
        FilterType::E8 => writer.write_admitted_bits(1, 3),
        FilterType::E8E9 => writer.write_admitted_bits(2, 3),
        FilterType::Arm => writer.write_admitted_bits(3, 3),
    }
}

fn try_write_filter_data<B: Budget>(writer: &mut BitWriter<B>, value: u32) -> Result<()> {
    let byte_count = filter_data_byte_count(value);
    writer
        .try_write_bits(byte_count - 1, 2)
        .map_err(Into::into)?;
    for index in 0..byte_count {
        writer
            .try_write_bits(((value >> (index * 8)) & 0xff) as usize, 8)
            .map_err(Into::into)?;
    }
    Ok(())
}

fn write_filter_data_admitted<B: Budget>(writer: &mut BitWriter<B>, value: u32) {
    let byte_count = filter_data_byte_count(value);
    writer.write_admitted_bits(byte_count - 1, 2);
    for index in 0..byte_count {
        writer.write_admitted_bits(((value >> (index * 8)) & 0xff) as usize, 8);
    }
}

fn filter_data_byte_count(value: u32) -> usize {
    ((u32::BITS - value.leading_zeros()).div_ceil(8) as usize).max(1)
}

fn e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) =
        super::super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask)
    {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32) % X86_FILTER_FILE_SIZE;
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let candidate = addr.wrapping_add(offset);
        let new_addr = if candidate < X86_FILTER_FILE_SIZE {
            Some(candidate)
        } else {
            let candidate = addr.wrapping_sub(X86_FILTER_FILE_SIZE);
            (candidate & 0x8000_0000 != 0 && candidate.wrapping_add(offset) & 0x8000_0000 == 0)
                .then_some(candidate)
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }
}

fn arm_encode(data: &mut [u8], file_offset: u32) {
    let mut pos = 0usize;
    while pos + 3 < data.len() {
        if data[pos + 3] == 0xeb {
            let mut offset = u32::from(data[pos])
                | (u32::from(data[pos + 1]) << 8)
                | (u32::from(data[pos + 2]) << 16);
            offset = offset.wrapping_add(file_offset.wrapping_add(pos as u32) / 4);
            data[pos] = offset as u8;
            data[pos + 1] = (offset >> 8) as u8;
            data[pos + 2] = (offset >> 16) as u8;
        }
        pos += 4;
    }
}

struct EncoderCodeTable<B: Budget> {
    symbols: Buffer<(u16, u8), B>,
}

impl<B: Budget> EncoderCodeTable<B> {
    fn from_lengths(lengths: &[u8], allowance: &B) -> Result<Self> {
        let mut counts = [0u16; 16];
        // Both callers use the encoder's length generators, capped at 15 bits.
        for &length in lengths {
            if length != 0 {
                counts[length as usize] += 1;
            }
        }
        validate_huffman_counts(&counts)?;
        let mut next = [0u16; 16];
        let mut code = 0;
        for length in 1..16 {
            code = (code + counts[length - 1]) << 1;
            next[length] = code;
        }
        let mut symbols = Buffer::filled(lengths.len(), (0u16, 0u8), allowance)?;
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                symbols[symbol] = (next[length as usize], length);
                next[length as usize] += 1;
            }
        }
        Ok(Self { symbols })
    }
    fn code_for_present_symbol(&self, symbol: usize) -> (u16, u8) {
        // Both encoder callers build frequencies from the exact token stream
        // they emit immediately afterwards. Every requested symbol therefore
        // has a non-zero code in this fixed-size array.
        debug_assert!(symbol < self.symbols.len());
        debug_assert_ne!(self.symbols[symbol].1, 0);
        self.symbols[symbol]
    }
}

struct BitWriter<B: Budget = Allowance> {
    bytes: Buffer<u8, B>,
    bit_pos: usize,
}

impl BitWriter {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_allowance(&Allowance::default())
    }
    fn write_bits(&mut self, value: usize, count: usize) {
        self.try_write_bits(value, count).unwrap();
    }
    fn finish(self) -> Vec<u8> {
        self.bytes.into_vec()
    }
}

impl<B: Budget> BitWriter<B> {
    fn with_allowance(allowance: &B) -> Self {
        Self {
            bytes: Buffer::new(allowance),
            bit_pos: 0,
        }
    }
    #[inline]
    fn try_write_bits(
        &mut self,
        value: usize,
        count: usize,
    ) -> std::result::Result<(), B::Failure> {
        self.bytes
            .write_msb_bits(&mut self.bit_pos, value as u64, count)
    }
    fn write_admitted_bits(&mut self, value: usize, count: usize) {
        self.bytes
            .write_msb_bits_admitted(&mut self.bit_pos, value as u64, count);
    }
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

    const fn repeat_previous_short(count: usize) -> Self {
        Self {
            symbol: 16,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn repeat_previous_long(count: usize) -> Self {
        Self {
            symbol: 17,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }

    const fn zero_run_short(count: usize) -> Self {
        Self {
            symbol: 18,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_long(count: usize) -> Self {
        Self {
            symbol: 19,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }
}

#[cfg(test)]
fn encode_table_level_tokens(lengths: &[u8]) -> Vec<LevelToken> {
    encode_table_level_tokens_with_allowance(lengths, &Allowance::default())
        .unwrap()
        .into_vec()
}

fn encode_table_level_tokens_with_allowance<B: Budget>(
    lengths: &[u8],
    allowance: &B,
) -> Result<Buffer<LevelToken, B>> {
    let mut tokens = Buffer::new(allowance);
    let mut pos = 0usize;
    let mut previous = None;
    while pos < lengths.len() {
        let value = lengths[pos];
        let mut run = 1usize;
        while pos + run < lengths.len() && lengths[pos + run] == value {
            run += 1;
        }

        if value == 0 {
            emit_zero_level_run(&mut tokens, run)?;
            previous = Some(0);
            pos += run;
            continue;
        }

        if previous == Some(value) && run >= 3 {
            emit_repeat_level_run(&mut tokens, run)?;
            pos += run;
            continue;
        }

        tokens
            .push(LevelToken::plain(value as usize))
            .map_err(Into::into)?;
        previous = Some(value);
        pos += 1;
    }
    Ok(tokens)
}

fn emit_repeat_level_run<B: Budget>(
    tokens: &mut Buffer<LevelToken, B>,
    mut run: usize,
) -> Result<()> {
    while run >= 3 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) {
                chunk -= 3;
            }
            tokens
                .push(LevelToken::repeat_previous_long(chunk))
                .map_err(Into::into)?;
            run -= chunk;
        } else {
            let chunk = run.min(10);
            tokens
                .push(LevelToken::repeat_previous_short(chunk))
                .map_err(Into::into)?;
            run -= chunk;
        }
    }
    debug_assert_eq!(run, 0);
    Ok(())
}

fn emit_zero_level_run<B: Budget>(
    tokens: &mut Buffer<LevelToken, B>,
    mut run: usize,
) -> Result<()> {
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) {
                chunk -= 3;
            }
            tokens
                .push(LevelToken::zero_run_long(chunk))
                .map_err(Into::into)?;
            run -= chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens
                .push(LevelToken::zero_run_short(chunk))
                .map_err(Into::into)?;
            run -= chunk;
        } else {
            for _ in 0..run {
                tokens.push(LevelToken::plain(0)).map_err(Into::into)?;
            }
            break;
        }
    }
    Ok(())
}

/// Prices the level alphabet by how often each symbol is used, where a flat
/// code charged the same for every symbol in play.
///
/// A block's table is mostly runs and short lengths, so its tokens are far from
/// evenly spread and a flat code overpays for the common ones. Both codings are
/// costed here and the cheaper is written, because weighting can lose: a code
/// this deep spends eight bits rather than four to declare a length of fifteen,
/// and over twenty symbols that occasionally outweighs what the tokens save.
///
/// Either way the code must be *complete*. Strict decoders rebuild the
/// pre-table (7-Zip's `k_BuildMode_Full`) and reject an under-full one. Huffman
/// gives Kraft equality by construction once two symbols are in play. The
/// near-uniform assignment also satisfies equality for any used-symbol count,
/// adding a phantom code when only one symbol is used.
#[cfg(test)]
fn level_code_lengths_for_tokens(tokens: &[LevelToken]) -> [u8; LEVEL_TABLE_SIZE] {
    level_code_lengths_with_allowance(tokens, &Allowance::default()).unwrap()
}

fn level_code_lengths_with_allowance<B: Budget>(
    tokens: &[LevelToken],
    allowance: &B,
) -> Result<[u8; LEVEL_TABLE_SIZE]> {
    let mut frequencies = [0usize; LEVEL_TABLE_SIZE];
    for token in tokens {
        frequencies[token.symbol] += 1;
    }

    let mut flat = [0u8; LEVEL_TABLE_SIZE];
    for (symbol, &count) in frequencies.iter().enumerate() {
        flat[symbol] = u8::from(count != 0);
    }
    huffman::assign_flat_complete_code(&mut flat);
    // One symbol in play leaves an empty branch beside it, and the flat
    // assignment is the only one that pads it into a complete code.
    if frequencies.iter().filter(|&&count| count != 0).count() <= 1 {
        return Ok(flat);
    }

    let owned = huffman::lengths_with_allowance(&frequencies, 15, allowance)?;
    let mut weighted = [0; LEVEL_TABLE_SIZE];
    weighted.copy_from_slice(&owned);
    Ok(
        match level_code_cost(&weighted, &frequencies) < level_code_cost(&flat, &frequencies) {
            true => weighted,
            false => flat,
        },
    )
}

/// What a level code costs in bits: the lengths at the head of the table as
/// [`write_level_lengths`] will write them, plus the tokens they code.
///
/// The tokens' own extra bits are the same under either code and are left out.
fn level_code_cost(
    lengths: &[u8; LEVEL_TABLE_SIZE],
    frequencies: &[usize; LEVEL_TABLE_SIZE],
) -> usize {
    let mut bits = 0usize;
    let mut pos = 0usize;
    while pos < LEVEL_TABLE_SIZE {
        if lengths[pos] != 0 {
            bits += if lengths[pos] == 15 { 8 } else { 4 };
            pos += 1;
            continue;
        }
        let mut run = 1usize;
        while pos + run < LEVEL_TABLE_SIZE && lengths[pos + run] == 0 {
            run += 1;
        }
        pos += run;
        while run >= 3 {
            bits += 8;
            run -= run.min(17);
        }
        bits += run * 4;
    }
    bits + (0..LEVEL_TABLE_SIZE)
        .map(|symbol| usize::from(lengths[symbol]) * frequencies[symbol])
        .sum::<usize>()
}

#[cfg(test)]
fn write_level_lengths(writer: &mut BitWriter, lengths: &[u8; LEVEL_TABLE_SIZE]) {
    try_write_level_lengths(writer, lengths).unwrap();
}

fn try_write_level_lengths<B: Budget>(
    writer: &mut BitWriter<B>,
    lengths: &[u8; LEVEL_TABLE_SIZE],
) -> Result<()> {
    let mut pos = 0usize;
    while pos < LEVEL_TABLE_SIZE {
        let length = lengths[pos];
        if length == 0 {
            let mut count = 1usize;
            while pos + count < LEVEL_TABLE_SIZE && lengths[pos + count] == 0 {
                count += 1;
            }
            while count >= 3 {
                let chunk = count.min(17);
                writer.try_write_bits(15, 4).map_err(Into::into)?;
                writer.try_write_bits(chunk - 2, 4).map_err(Into::into)?;
                pos += chunk;
                count -= chunk;
            }
            for _ in 0..count {
                writer.try_write_bits(0, 4).map_err(Into::into)?;
                pos += 1;
            }
        } else {
            writer
                .try_write_bits(usize::from(length), 4)
                .map_err(Into::into)?;
            if length == 15 {
                writer.try_write_bits(0, 4).map_err(Into::into)?;
            }
            pos += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pricing_tests.rs"]
mod pricing_tests;

#[cfg(test)]
#[path = "literal_pricing_tests.rs"]
mod literal_pricing_tests;
