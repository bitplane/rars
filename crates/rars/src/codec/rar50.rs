use super::filters::{self, DeltaErrorMessages, FilterOp};
use super::{huffman, match_finder, Error, Result};
use std::collections::VecDeque;
use std::io::Read;
#[cfg(test)]
use std::io::Write;
use std::ops::Range;

pub const LEVEL_TABLE_SIZE: usize = 20;
pub const MAIN_TABLE_SIZE: usize = 306;
pub const DISTANCE_TABLE_SIZE_50: usize = 64;
pub const DISTANCE_TABLE_SIZE_70: usize = 80;
pub const ALIGN_TABLE_SIZE: usize = 16;
pub const LENGTH_TABLE_SIZE: usize = 44;
const DEFAULT_DICTIONARY_SIZE: usize = 4 * 1024 * 1024;
const MAX_INITIAL_OUTPUT_CAPACITY: usize = 1024 * 1024;
const STREAM_FLUSH_THRESHOLD: usize = 64 * 1024;
const MAX_ENCODER_MATCH_OFFSET: usize = DEFAULT_DICTIONARY_SIZE;
const MAX_ENCODER_MATCH_LENGTH: usize = 4096;
/// The largest block the format allows a writer to emit.
const MAX_COMPRESSED_BLOCK_OUTPUT: usize = 4 * 1024 * 1024;
/// How much input goes into one compressed block.
///
/// Every block carries its own Huffman tables, so smaller blocks pay for the
/// extra tables and win back more by fitting each stretch of the data. Matches
/// still reach back across boundaries into the history, so shortening a block
/// costs no match range. Measured over the corpus, 64 KiB packs 6.4% smaller
/// than a mebibyte and within 0.2% of the best size tried at any point between
/// 16 KiB and 256 KiB. The streaming writer reads in the same units, so both
/// paths produce the same blocks for the same input.
pub(crate) const LZ_BLOCK_SIZE: usize = 64 * 1024;
const _: () = assert!(LZ_BLOCK_SIZE <= MAX_COMPRESSED_BLOCK_OUTPUT);
const MAX_FILTER_BLOCK_LENGTH: usize = 0x3ffff;
/// How much input goes into one compressed block once a filter is carried.
///
/// A filter record cannot describe more than [`MAX_FILTER_BLOCK_LENGTH`] bytes,
/// so this is the smaller of that ceiling and the plain block size. Splitting a
/// filtered range across blocks costs one more record per block and converts
/// the same bytes either way: the transform reads an absolute file offset, and
/// an instruction straddling a boundary was already left alone at the old
/// 256 KiB one.
const FILTERED_LZ_BLOCK_SIZE: usize = if LZ_BLOCK_SIZE < MAX_FILTER_BLOCK_LENGTH {
    LZ_BLOCK_SIZE
} else {
    MAX_FILTER_BLOCK_LENGTH
};
const NICE_MATCH_LENGTH: usize = 512;

/// Matches shorter than 4 bytes are never emitted, so candidate positions are
/// chained by a hash of their first 4 bytes.
type Rar50MatchFinder = match_finder::MatchFinder<4>;
const MAX_MATCH_CANDIDATES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedBlock {
    pub header: CompressedBlockHeader,
    pub header_len: usize,
    pub payload: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedBlockHeader {
    pub flags: u8,
    pub is_last: bool,
    pub has_tables: bool,
    pub final_byte_bits: u8,
    pub payload_size: usize,
    pub payload_bits: usize,
}

struct OwnedCompressedBlock {
    header: CompressedBlockHeader,
    payload: Vec<u8>,
}

#[derive(Debug)]
#[doc(hidden)]
pub enum StreamDecodeError<E> {
    Decode(Error),
    FilteredMember,
    Sink(E),
}

impl<E> From<Error> for StreamDecodeError<E> {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum DecodedChunk<'a> {
    Bytes(&'a [u8]),
    Repeated { byte: u8, len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableLengths {
    pub main: Vec<u8>,
    pub distance: Vec<u8>,
    pub align: Vec<u8>,
    pub length: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecodeTables {
    pub main: HuffmanTable,
    pub distance: HuffmanTable,
    pub align: HuffmanTable,
    pub length: HuffmanTable,
    pub align_mode: bool,
}

impl DecodeTables {
    pub fn from_lengths(lengths: &TableLengths) -> Result<Self> {
        let align_mode = lengths
            .align
            .iter()
            .any(|&length| length != 0 && length != 4);
        Ok(Self {
            main: HuffmanTable::from_lengths(&lengths.main)?,
            distance: HuffmanTable::from_lengths(&lengths.distance)?,
            align: HuffmanTable::from_lengths(&lengths.align)?,
            length: HuffmanTable::from_lengths(&lengths.length)?,
            align_mode,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    LiteralOnly,
    Lz,
    LzNoFilters,
}

impl DecodeMode {
    fn uses_lz(self) -> bool {
        matches!(self, Self::Lz | Self::LzNoFilters)
    }

    fn applies_filters(self) -> bool {
        matches!(self, Self::Lz)
    }
}

pub fn parse_compressed_block(input: &[u8]) -> Result<CompressedBlock> {
    if input.len() < 3 {
        return Err(Error::NeedMoreInput);
    }

    let flags = input[0];
    let checksum = input[1];
    let size_bytes = match (flags >> 3) & 0x03 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => return Err(Error::InvalidData("RAR 5 block size length is invalid")),
    };
    let header_len = 2 + size_bytes;
    if input.len() < header_len {
        return Err(Error::NeedMoreInput);
    }

    let size_data = &input[2..header_len];
    let actual = size_data
        .iter()
        .fold(checksum ^ flags, |acc, &byte| acc ^ byte);
    if actual != 0x5a {
        return Err(Error::InvalidData("RAR 5 block header checksum mismatch"));
    }

    let payload_size = size_data
        .iter()
        .enumerate()
        .fold(0usize, |acc, (index, &byte)| {
            acc | (usize::from(byte) << (index * 8))
        });
    let payload_end = header_len
        .checked_add(payload_size)
        .ok_or(Error::InvalidData("RAR 5 block size overflows"))?;
    if input.len() < payload_end {
        return Err(Error::NeedMoreInput);
    }

    let final_byte_bits = ((flags & 0x07) + 1).min(8);
    let payload_bits = if payload_size == 0 {
        0
    } else {
        (payload_size - 1) * 8 + usize::from(final_byte_bits)
    };

    Ok(CompressedBlock {
        header: CompressedBlockHeader {
            flags,
            is_last: flags & 0x40 != 0,
            has_tables: flags & 0x80 != 0,
            final_byte_bits,
            payload_size,
            payload_bits,
        },
        header_len,
        payload: header_len..payload_end,
    })
}

pub fn read_level_lengths(input: &[u8]) -> Result<([u8; LEVEL_TABLE_SIZE], usize)> {
    let mut bits = BitReader::new(input);
    let mut lengths = [0; LEVEL_TABLE_SIZE];
    let mut pos = 0;
    while pos < LEVEL_TABLE_SIZE {
        let length = bits.read_bits(4)? as u8;
        if length == 15 {
            let zero_count = bits.read_bits(4)? as usize;
            if zero_count == 0 {
                lengths[pos] = 15;
                pos += 1;
            } else {
                let count = zero_count + 2;
                for _ in 0..count {
                    if pos >= LEVEL_TABLE_SIZE {
                        break;
                    }
                    lengths[pos] = 0;
                    pos += 1;
                }
            }
        } else {
            lengths[pos] = length;
            pos += 1;
        }
    }
    Ok((lengths, bits.bit_pos))
}

pub fn table_length_count(algorithm_version: u8) -> Result<usize> {
    match algorithm_version {
        0 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_50 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        1 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        _ => Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}

pub fn read_table_lengths(input: &[u8], algorithm_version: u8) -> Result<(TableLengths, usize)> {
    let table_size = table_length_count(algorithm_version)?;
    let (level_lengths, level_bits) = read_level_lengths(input)?;
    let level_decoder = HuffmanTable::from_lengths(&level_lengths)?;
    let mut bits = BitReader::new(input);
    bits.bit_pos = level_bits;

    let mut lengths = Vec::with_capacity(table_size);
    while lengths.len() < table_size {
        let number = level_decoder.decode(&mut bits)?;
        match number {
            0..=15 => lengths.push(number as u8),
            16 | 17 => {
                if lengths.is_empty() {
                    return Err(Error::InvalidData(
                        "RAR 5 table repeats missing previous length",
                    ));
                }
                let count = if number == 16 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                let previous = *lengths.last().unwrap();
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(previous);
                }
            }
            18 | 19 => {
                let count = if number == 18 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(0);
                }
            }
            _ => return Err(Error::InvalidData("RAR 5 invalid level-table symbol")),
        }
    }

    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => unreachable!("validated by table_length_count"),
    };
    let distance_start = MAIN_TABLE_SIZE;
    let align_start = distance_start + distance_size;
    let length_start = align_start + ALIGN_TABLE_SIZE;

    Ok((
        TableLengths {
            main: lengths[..distance_start].to_vec(),
            distance: lengths[distance_start..align_start].to_vec(),
            align: lengths[align_start..length_start].to_vec(),
            length: lengths[length_start..].to_vec(),
        },
        bits.bit_pos,
    ))
}

pub fn encode_table_lengths(lengths: &TableLengths, algorithm_version: u8) -> Result<Vec<u8>> {
    encode_table_lengths_with_bit_count(lengths, algorithm_version).map(|(data, _)| data)
}

pub fn encode_table_lengths_with_bit_count(
    lengths: &TableLengths,
    algorithm_version: u8,
) -> Result<(Vec<u8>, usize)> {
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

    let flattened = lengths
        .main
        .iter()
        .chain(lengths.distance.iter())
        .chain(lengths.align.iter())
        .chain(lengths.length.iter())
        .copied()
        .collect::<Vec<_>>();
    for &length in &flattened {
        if length > 15 {
            return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
        }
    }

    let level_tokens = encode_table_level_tokens(&flattened);
    let level_lengths = level_code_lengths_for_tokens(&level_tokens);
    let level_table = HuffmanTable::from_lengths(&level_lengths)?;
    let mut writer = BitWriter::new();
    write_level_lengths(&mut writer, &level_lengths);
    for token in level_tokens {
        let (code, len) = level_table.code_for_symbol(token.symbol)?;
        writer.write_bits(usize::from(code), usize::from(len));
        if token.extra_bits != 0 {
            writer.write_bits(
                usize::from(token.extra_value),
                usize::from(token.extra_bits),
            );
        }
    }
    let bit_count = writer.bit_pos;
    Ok((writer.finish(), bit_count))
}

pub fn encode_compressed_block(
    payload: &[u8],
    payload_bits: usize,
    has_tables: bool,
    is_last: bool,
) -> Result<Vec<u8>> {
    if payload_bits > payload.len() * 8 {
        return Err(Error::InvalidData("RAR 5 block bit count exceeds payload"));
    }
    if payload.is_empty() && payload_bits != 0 {
        return Err(Error::InvalidData("RAR 5 empty block has payload bits"));
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
    flags |= match size_len {
        1 => 0,
        2 => 1 << 3,
        3 => 2 << 3,
        _ => unreachable!("size_len is constrained above"),
    };
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
    let mut out = Vec::with_capacity(2 + size_len + payload.len());
    out.push(flags);
    out.push(checksum);
    out.extend_from_slice(&size_bytes[..size_len]);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_literal_only(
    input: &[u8],
    algorithm_version: u8,
    output_size: usize,
) -> Result<Vec<u8>> {
    let mut decoder = Unpack50Decoder::new();
    decoder.decode_member(
        input,
        algorithm_version,
        output_size,
        false,
        DecodeMode::LiteralOnly,
    )
}

pub fn decode_lz(input: &[u8], algorithm_version: u8, output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack50Decoder::new();
    decoder.decode_member(input, algorithm_version, output_size, false, DecodeMode::Lz)
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
    for (symbol, used) in present.into_iter().enumerate() {
        if used {
            lengths.main[symbol] = literal_length;
        }
    }

    let table = HuffmanTable::from_lengths(&lengths.main)?;
    let (table_data, table_bits) =
        encode_table_lengths_with_bit_count(&lengths, algorithm_version)?;
    let mut writer = BitWriter {
        bytes: table_data,
        bit_pos: table_bits,
    };
    for &byte in data {
        let (code, len) = table.code_for_symbol(byte as usize)?;
        writer.write_bits(usize::from(code), usize::from(len));
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
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            lazy_matching: false,
            lazy_lookahead: 1,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            optimal_parse: false,
        }
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
        &[],
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

pub(crate) fn encode_lz_member_with_options_and_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, &[], algorithm_version, &[], options, Some(progress))
}

#[cfg(test)]
pub(crate) fn encode_lz_reader_to(
    reader: &mut dyn Read,
    input_size: u64,
    output: &mut dyn Write,
    algorithm_version: u8,
    options: EncodeOptions,
    block_size: usize,
    mut progress: Option<&mut dyn FnMut(u64) -> bool>,
) -> crate::Result<()> {
    if block_size == 0 {
        return Err(crate::Error::InvalidHeader(
            "RAR 5 streaming block size is zero",
        ));
    }
    let block_size = block_size.min(MAX_COMPRESSED_BLOCK_OUTPUT);
    let mut history = Vec::new();
    let mut buffer = vec![0; block_size];
    let mut remaining = input_size;
    let mut completed = 0u64;
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(block_size as u64))
            .map_err(|_| crate::Error::InvalidHeader("RAR 5 block size overflows usize"))?;
        reader.read_exact(&mut buffer[..wanted])?;
        remaining -= wanted as u64;
        let packed = encode_lz_block(
            &buffer[..wanted],
            &history,
            algorithm_version,
            &[],
            options,
            remaining == 0,
            None,
        )?;
        output.write_all(&packed)?;
        history.extend_from_slice(&buffer[..wanted]);
        let keep_from = history.len().saturating_sub(options.max_match_distance);
        if keep_from != 0 {
            history.drain(..keep_from);
        }
        completed += wanted as u64;
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

pub fn encode_lz_member_with_history_and_options(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, history, algorithm_version, &[], options, None)
}

/// The filters RAR 5 has a builtin type for.
///
/// Narrower than [`crate::FilterKind`], which names every filter any format
/// can apply. The conversion below is where a filter RAR 5 cannot encode is
/// turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rar50Filter {
    Delta { channels: usize },
    E8,
    E8E9,
    Arm,
}

/// The writer rejects these before compressing anything, so reaching this is
/// either a direct `codec` caller or a bug. Either way the codec stays total.
fn rar50_filter(kind: crate::FilterKind) -> Result<Rar50Filter> {
    Rar50Filter::try_from(kind)
        .map_err(|_| Error::InvalidData("RAR 5 has no builtin type for this filter"))
}

impl TryFrom<crate::FilterKind> for Rar50Filter {
    type Error = crate::UnsupportedFilterKind;

    fn try_from(kind: crate::FilterKind) -> std::result::Result<Self, Self::Error> {
        use crate::FilterKind as Kind;
        match kind {
            Kind::Delta { channels } => Ok(Self::Delta { channels }),
            Kind::E8 => Ok(Self::E8),
            Kind::E8E9 => Ok(Self::E8E9),
            Kind::Arm => Ok(Self::Arm),
            // No wildcard arm: an eighth filter has to be decided about here.
            kind @ (Kind::Itanium | Kind::Rgb { .. } | Kind::Audio { .. }) => {
                Err(crate::UnsupportedFilterKind(kind))
            }
        }
    }
}

/// Applies `filters` to a copy of `data`, returning the transformed bytes and
/// the records that describe them.
pub(crate) fn filtered_lz_member(
    data: &[u8],
    filters: &[crate::FilterSpec],
) -> Result<(Vec<u8>, Vec<EncodeFilter>)> {
    let mut filtered = data.to_vec();
    let mut records = Vec::with_capacity(filters.len());
    for filter in filters {
        let range = filter.range.clone().unwrap_or(0..data.len());
        if range.start >= range.end || range.end > data.len() {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        if range.start > u32::MAX as usize {
            return Err(Error::InvalidData("RAR 5 filter offset is too large"));
        }

        let filter_data = &mut filtered[range.clone()];
        let (filter_type, channels) =
            encode_filter_data(rar50_filter(filter.kind)?, filter_data, range.start)?;
        records.push(EncodeFilter {
            offset: range.start,
            length: range.len(),
            filter_type,
            channels,
        });
    }
    Ok((filtered, records))
}

fn encode_filter_data(
    kind: Rar50Filter,
    data: &mut [u8],
    file_offset: usize,
) -> Result<(FilterType, usize)> {
    if file_offset > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter offset is too large"));
    }
    match kind {
        Rar50Filter::Delta { channels } => {
            filters::encode_in_place(
                FilterOp::Delta { channels },
                data,
                0,
                rar50_delta_messages(),
            )?;
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

fn filtered_lz_blocks(
    data: &[u8],
    filters: &[crate::FilterSpec],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let filters = normalized_filter_specs(data.len(), filters)?;
    let mut out = Vec::new();
    let mut block_history =
        history[history.len().saturating_sub(options.max_match_distance)..].to_vec();
    let mut chunk_start = 0usize;
    while chunk_start < data.len() {
        let chunk_end = (chunk_start + FILTERED_LZ_BLOCK_SIZE).min(data.len());
        let mut chunk = data[chunk_start..chunk_end].to_vec();
        let mut records = Vec::new();
        for filter in &filters {
            let start = filter.range.start.max(chunk_start);
            let end = filter.range.end.min(chunk_end);
            if start >= end {
                continue;
            }
            let local_start = start - chunk_start;
            let local_end = end - chunk_start;
            let (filter_type, channels) =
                encode_filter_data(filter.kind, &mut chunk[local_start..local_end], start)?;
            records.push(EncodeFilter {
                offset: local_start,
                length: local_end - local_start,
                filter_type,
                channels,
            });
        }
        let mut chunk_progress = |position: usize| {
            progress
                .as_deref_mut()
                .is_none_or(|report| report(chunk_start.saturating_add(position)))
        };
        out.extend(encode_lz_block(
            &chunk,
            &block_history,
            algorithm_version,
            &records,
            options,
            chunk_end == data.len(),
            Some(&mut chunk_progress),
        )?);
        block_history.extend_from_slice(&chunk);
        let keep_from = block_history
            .len()
            .saturating_sub(options.max_match_distance);
        if keep_from != 0 {
            block_history.drain(..keep_from);
        }
        chunk_start = chunk_end;
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedFilterSpec {
    kind: Rar50Filter,
    range: Range<usize>,
}

fn normalized_filter_specs(
    data_len: usize,
    filters: &[crate::FilterSpec],
) -> Result<Vec<NormalizedFilterSpec>> {
    let mut normalized = Vec::with_capacity(filters.len());
    for filter in filters {
        let range = filter.range.clone().unwrap_or(0..data_len);
        if range.start >= range.end || range.end > data_len {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        normalized.push(NormalizedFilterSpec {
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
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    if data.len() > LZ_BLOCK_SIZE && initial_filters.is_empty() {
        let mut out = Vec::new();
        let mut block_history =
            history[history.len().saturating_sub(options.max_match_distance)..].to_vec();
        let mut chunks = data.chunks(LZ_BLOCK_SIZE).peekable();
        let mut completed = 0usize;
        while let Some(chunk) = chunks.next() {
            let is_last = chunks.peek().is_none();
            let mut chunk_progress = |position: usize| {
                progress
                    .as_deref_mut()
                    .is_none_or(|report| report(completed.saturating_add(position)))
            };
            out.extend(encode_lz_block(
                chunk,
                &block_history,
                algorithm_version,
                &[],
                options,
                is_last,
                Some(&mut chunk_progress),
            )?);
            completed = completed.saturating_add(chunk.len());
            block_history.extend_from_slice(chunk);
            let keep_from = block_history
                .len()
                .saturating_sub(options.max_match_distance);
            if keep_from != 0 {
                block_history.drain(..keep_from);
            }
        }
        return Ok(out);
    }

    encode_lz_block(
        data,
        history,
        algorithm_version,
        initial_filters,
        options,
        true,
        progress,
    )
}

fn encode_lz_block(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    let mut tokens = Vec::new();
    tokens.extend(initial_filters.iter().copied().map(EncodeToken::Filter));
    tokens.extend(encode_tokens_with_progress(
        data,
        history,
        options,
        distance_size,
        progress,
    )?);
    let lengths = table_lengths_for_tokens(&tokens, distance_size)?;

    let main_table = HuffmanTable::from_lengths(&lengths.main)?;
    let distance_table = HuffmanTable::from_lengths(&lengths.distance)?;
    let align_table = HuffmanTable::from_lengths(&lengths.align)?;
    let length_table = HuffmanTable::from_lengths(&lengths.length)?;
    let (table_data, table_bits) =
        encode_table_lengths_with_bit_count(&lengths, algorithm_version)?;
    let mut writer = BitWriter {
        bytes: table_data,
        bit_pos: table_bits,
    };
    let mut state = EncoderMatchState::default();
    for token in tokens {
        match token {
            EncodeToken::Filter(filter) => {
                let (code, len) = main_table.code_for_symbol(256)?;
                writer.write_bits(usize::from(code), usize::from(len));
                write_filter(&mut writer, filter)?;
            }
            EncodeToken::Literal(byte) => {
                let (code, len) = main_table.code_for_symbol(byte as usize)?;
                writer.write_bits(usize::from(code), usize::from(len));
            }
            EncodeToken::Match { length, distance } => {
                match state.encode_match(length, distance, distance_size)? {
                    EncodedMatch::LastLengthRepeat => {
                        let (code, len) = main_table.code_for_symbol(257)?;
                        writer.write_bits(usize::from(code), usize::from(len));
                    }
                    EncodedMatch::RepeatDistance {
                        index,
                        length_slot,
                        length_extra,
                    } => {
                        let (code, len) = main_table.code_for_symbol(258 + index)?;
                        writer.write_bits(usize::from(code), usize::from(len));
                        let (code, len) = length_table.code_for_symbol(length_slot)?;
                        writer.write_bits(usize::from(code), usize::from(len));
                        let length_extra_bits = length_slot_extra_bits(length_slot)?;
                        if length_extra_bits != 0 {
                            writer.write_bits(length_extra, usize::from(length_extra_bits));
                        }
                    }
                    EncodedMatch::New {
                        length_slot,
                        length_extra,
                        distance_slot,
                        distance_extra,
                        distance_bit_count,
                    } => {
                        let (code, len) = main_table.code_for_symbol(262 + length_slot)?;
                        writer.write_bits(usize::from(code), usize::from(len));
                        let length_extra_bits = length_slot_extra_bits(length_slot)?;
                        if length_extra_bits != 0 {
                            writer.write_bits(length_extra, usize::from(length_extra_bits));
                        }
                        let (code, len) = distance_table.code_for_symbol(distance_slot)?;
                        writer.write_bits(usize::from(code), usize::from(len));
                        if distance_bit_count >= 4 {
                            if distance_bit_count > 4 {
                                writer.write_bits(distance_extra >> 4, distance_bit_count - 4);
                            }
                            let (code, len) = align_table.code_for_symbol(distance_extra & 0x0f)?;
                            writer.write_bits(usize::from(code), usize::from(len));
                        } else if distance_bit_count != 0 {
                            writer.write_bits(distance_extra, distance_bit_count);
                        }
                    }
                }
                state.remember(length, distance);
            }
        }
    }

    let payload_bits = writer.bit_pos;
    encode_compressed_block(&writer.finish(), payload_bits, true, is_last)
}

#[derive(Debug, Clone, Default)]
pub struct Unpack50Encoder {
    history: Vec<u8>,
    options: EncodeOptions,
}

impl Unpack50Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            history: Vec::new(),
            options,
        }
    }

    pub fn encode_member(&mut self, input: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
        let packed = encode_lz_member_with_history_and_options(
            input,
            &self.history,
            algorithm_version,
            self.options,
        )?;
        self.remember(input);
        Ok(packed)
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
        if input.len() > FILTERED_LZ_BLOCK_SIZE {
            let packed = filtered_lz_blocks(
                input,
                filters,
                &self.history,
                algorithm_version,
                self.options,
                None,
            )?;
            self.remember(input);
            return Ok(packed);
        }
        let (filtered, records) = filtered_lz_member(input, filters)?;
        let packed = encode_lz_member_inner(
            &filtered,
            &self.history,
            algorithm_version,
            &records,
            self.options,
            None,
        )?;
        // Remembering the caller's input rather than the filtered bytes only
        // matters once history is carried between members, and the RAR 5
        // writer refuses a filter in a solid archive, so it never is. The RAR
        // 2.9 encoder had the same shape and did carry history: every member
        // after a filtered one referred to bytes no decoder had.
        self.remember(input);
        Ok(packed)
    }

    pub(crate) fn encode_member_with_filters_and_progress(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filters: &[crate::FilterSpec],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        let packed = if input.len() > FILTERED_LZ_BLOCK_SIZE {
            filtered_lz_blocks(
                input,
                filters,
                &self.history,
                algorithm_version,
                self.options,
                Some(progress),
            )?
        } else {
            let (filtered, records) = filtered_lz_member(input, filters)?;
            encode_lz_member_inner(
                &filtered,
                &self.history,
                algorithm_version,
                &records,
                self.options,
                Some(progress),
            )?
        };
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

#[derive(Debug, Clone, Copy)]
enum EncodeToken {
    Filter(EncodeFilter),
    Literal(u8),
    Match { length: usize, distance: usize },
}

#[derive(Debug, Clone, Copy)]
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
        if distance == self.reps[0] && length == self.last_length && self.last_length != 0 {
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

    fn remember(&mut self, length: usize, distance: usize) {
        if distance == self.reps[0] && length == self.last_length {
            return;
        }
        if let Some(index) = self
            .reps
            .iter()
            .position(|&repeat_distance| repeat_distance == distance)
        {
            self.reps[..=index].rotate_right(1);
        } else {
            self.reps.rotate_right(1);
        }
        self.reps[0] = distance;
        self.last_length = length;
    }
}

/// The Huffman code lengths a block of tokens produces. The block writer needs
/// these to emit the tables; the optimal parse needs them to know what each
/// token it is considering will actually cost.
fn table_lengths_for_tokens(tokens: &[EncodeToken], distance_size: usize) -> Result<TableLengths> {
    let mut main_frequencies = vec![0usize; MAIN_TABLE_SIZE];
    let mut distance_frequencies = vec![0usize; distance_size];
    let mut align_frequencies = vec![0usize; ALIGN_TABLE_SIZE];
    let mut length_frequencies = vec![0usize; LENGTH_TABLE_SIZE];
    let mut state = EncoderMatchState::default();
    for token in tokens {
        match *token {
            EncodeToken::Filter(_) => main_frequencies[256] += 1,
            EncodeToken::Literal(byte) => main_frequencies[byte as usize] += 1,
            EncodeToken::Match { length, distance } => {
                match state.encode_match(length, distance, distance_size)? {
                    EncodedMatch::LastLengthRepeat => main_frequencies[257] += 1,
                    EncodedMatch::RepeatDistance {
                        index, length_slot, ..
                    } => {
                        main_frequencies[258 + index] += 1;
                        length_frequencies[length_slot] += 1;
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
                        if distance_bit_count >= 4 {
                            align_frequencies[distance_extra & 0x0f] += 1;
                        }
                    }
                }
                state.remember(length, distance);
            }
        }
    }

    Ok(TableLengths {
        main: huffman::complete_lengths_for_frequencies(&main_frequencies, 15),
        distance: huffman::complete_lengths_for_frequencies(&distance_frequencies, 15),
        align: huffman::complete_lengths_for_frequencies(&align_frequencies, 15),
        length: huffman::complete_lengths_for_frequencies(&length_frequencies, 15),
    })
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
    lengths: &'a TableLengths,
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
                    + usize::from(length_slot_extra_bits(length_slot)?)
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
                    + usize::from(length_slot_extra_bits(length_slot)?)
                    + Self::code(self.lengths.distance[distance_slot])
                    + align
            }
        })
    }
}

/// Prices every path through the block and keeps the cheapest, instead of
/// taking the longest match at each position and checking one or two bytes
/// ahead. Prices come from [`estimated_match_cost`], so this is only as good
/// as that estimate, but it sees the whole block where lazy matching sees two
/// bytes.
///
/// The repeated-distance discount depends on the path taken, which a forward
/// pass does not know. Each node carries the match that arrives at it and
/// prices the next hop against that one distance, which catches
/// same-distance runs and misses the deeper three slots.
fn optimal_tokens(
    combined: &[u8],
    start: usize,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
) -> Result<Vec<EncodeToken>> {
    let end = combined.len();
    let span = end - start;
    let mut finder = Rar50MatchFinder::new(end);
    for history_pos in 0..start {
        finder.insert(combined, history_pos);
    }

    let mut price = vec![u32::MAX; span + 1];
    let mut arrive_length = vec![0u32; span + 1];
    let mut arrive_distance = vec![0u32; span + 1];
    price[0] = 0;

    // Runs of `(shortest, longest, distance)` from the position being priced,
    // in the order the chain found them. Reused to keep one allocation.
    let mut reaches: Vec<(usize, usize, usize)> = Vec::new();

    for index in 0..span {
        let pos = start + index;
        finder.insert(combined, pos);
        let here = price[index];
        if here == u32::MAX {
            continue;
        }
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

        let mut state = EncoderMatchState::default();
        state.reps[0] = arrive_distance[index] as usize;
        state.last_length = arrive_length[index] as usize;

        // The chain walks nearest first, so the first distance to reach a
        // length is the cheapest one that can. Each step that improves on the
        // longest so far owns one run of lengths.
        reaches.clear();
        let mut longest = 0usize;
        let mut checked = 0usize;
        let mut candidate = finder.first(combined, pos);
        while candidate != match_finder::NO_POSITION
            && longest < max_length
            && longest < NICE_MATCH_LENGTH
        {
            if candidate >= pos {
                candidate = finder.previous(candidate);
                continue;
            }
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            if combined[candidate + longest] == combined[pos + longest] {
                let length = match_length(combined, pos, distance, max_length);
                if length > longest {
                    reaches.push((longest + 1, length, distance));
                    longest = length;
                }
            }
            if checked >= options.max_match_candidates {
                break;
            }
            candidate = finder.previous(candidate);
        }

        // Matches that share a distance and a length slot cost the same, so
        // only the longest of each run is worth pricing. Stepping slot to
        // slot turns a four-thousand-step loop into a few dozen on data that
        // matches long.
        for &(run_start, run_end, distance) in reaches.iter() {
            let mut length = run_start.max(4);
            while length <= run_end {
                let reach =
                    same_price_run_end(&state, length, distance, distance_size).min(run_end);
                let cost = match prices {
                    Some(prices) => prices.match_cost(&state, reach, distance, distance_size),
                    None => estimated_match_cost(&state, reach, distance, distance_size),
                };
                if let Ok(cost) = cost {
                    let reached = here.saturating_add(cost as u32);
                    let target = index + reach;
                    if reached < price[target] {
                        price[target] = reached;
                        arrive_length[target] = reach as u32;
                        arrive_distance[target] = distance as u32;
                    }
                }
                length = reach + 1;
            }
        }
    }

    let mut reversed = Vec::new();
    let mut index = span;
    while index > 0 {
        let length = arrive_length[index] as usize;
        if length == 0 {
            reversed.push(EncodeToken::Literal(combined[start + index - 1]));
            index -= 1;
        } else {
            reversed.push(EncodeToken::Match {
                length,
                distance: arrive_distance[index] as usize,
            });
            index -= length;
        }
    }
    reversed.reverse();
    Ok(reversed)
}

/// The longest match at `distance` that costs exactly what a match of
/// `length` costs. Only the length slot varies with length, and a slot covers
/// a run of consecutive lengths, so the end of that run is the last length
/// worth pricing.
fn same_price_run_end(
    state: &EncoderMatchState,
    length: usize,
    distance: usize,
    distance_size: usize,
) -> usize {
    // Repeating the last distance at the last length codes in two bits, so
    // that one length must be priced on its own rather than folded into the
    // run around it.
    let repeat_length = (distance == state.reps[0] && state.last_length != 0)
        .then_some(state.last_length)
        .filter(|&repeat_length| repeat_length >= length);
    if repeat_length == Some(length) {
        return length;
    }
    let repeated = state
        .reps
        .iter()
        .any(|&repeat_distance| repeat_distance == distance && repeat_distance != 0);
    let bonus = if repeated { 0 } else { length_bonus(distance) };
    let Some(value) = length.checked_sub(2 + bonus) else {
        return length;
    };
    if value < 8 {
        return length;
    }
    let bit_count = value.ilog2() as usize - 2;
    let last_value = (((value >> bit_count) + 1) << bit_count) - 1;
    let mut end = (last_value + 2 + bonus).max(length);
    if let Some(repeat_length) = repeat_length {
        end = end.min(repeat_length - 1);
    }
    // A distance whose extra bits change with length would break the run, but
    // the distance is fixed here, so only the length slot moves.
    let _ = distance_size;
    end.max(length).min(MAX_ENCODER_MATCH_LENGTH)
}

fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    let mut tokens = Vec::new();
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let mut combined = Vec::with_capacity(history.len() + input.len());
    combined.extend_from_slice(history);
    combined.extend_from_slice(input);
    if options.optimal_parse {
        // The prices come from the Huffman tables, and the tables come from
        // the parse, so the first pass has to guess. Each pass after it prices
        // against what the pass before actually produced.
        let mut tokens = optimal_tokens(&combined, history.len(), options, distance_size, None)?;
        for _ in 1..OPTIMAL_PARSE_PASSES {
            let lengths = table_lengths_for_tokens(&tokens, distance_size)?;
            let prices = TokenPrices { lengths: &lengths };
            tokens = optimal_tokens(
                &combined,
                history.len(),
                options,
                distance_size,
                Some(&prices),
            )?;
        }
        if progress.is_some_and(|report| !report(input.len())) {
            return Err(Error::Cancelled);
        }
        return Ok(tokens);
    }
    let mut finder = Rar50MatchFinder::new(combined.len());
    for history_pos in 0..history.len() {
        finder.insert(&combined, history_pos);
    }

    let mut pos = history.len();
    let end = combined.len();
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    let mut pending_match: Option<MatchCandidate> = None;
    while pos < end {
        let candidate = pending_match
            .take()
            .or_else(|| best_match(&combined, pos, end, &finder, options, &state, distance_size));
        if let Some(candidate) = candidate {
            let (emit_literal, cached_next) = lazy_match_decision(
                &combined,
                pos,
                &finder,
                options,
                &state,
                distance_size,
                candidate,
            );
            if emit_literal {
                tokens.push(EncodeToken::Literal(combined[pos]));
                finder.insert(&combined, pos);
                pos += 1;
                pending_match = cached_next;
                continue;
            }
            let MatchCandidate {
                length, distance, ..
            } = candidate;
            tokens.push(EncodeToken::Match { length, distance });
            state.remember(length, distance);
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

/// Decides whether a literal should be emitted instead of `current` because a
/// better match starts within the lazy lookahead window. Also returns the
/// match found one byte ahead (when computed) so the caller can reuse it for
/// the next position instead of searching again.
fn lazy_match_decision(
    input: &[u8],
    pos: usize,
    finder: &Rar50MatchFinder,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    current: MatchCandidate,
) -> (bool, Option<MatchCandidate>) {
    let end = input.len();
    if !options.lazy_matching || pos + 1 >= end {
        return (false, None);
    }
    let lookahead = options.lazy_lookahead.max(1);
    let mut cached_next = None;
    for offset in 1..=lookahead {
        if pos + offset >= end {
            break;
        }
        let next = best_match(
            input,
            pos + offset,
            end,
            finder,
            options,
            state,
            distance_size,
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
    cost: usize,
}

fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar50MatchFinder,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
) -> Option<MatchCandidate> {
    let max_distance = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0
        || max_distance == 0
        || max_length < 4
        || pos + 3 >= input.len()
    {
        return None;
    }
    let mut best = None;
    let mut checked = 0usize;
    for distance in state.reps {
        if distance == 0 || distance > max_distance {
            continue;
        }
        let length = match_length(input, pos, distance, max_length);
        consider_match_candidate(&mut best, state, distance_size, length, distance);
    }
    if let Some(best) = best {
        if best.length == max_length || best.length >= NICE_MATCH_LENGTH {
            return Some(best);
        }
    }
    let mut candidate = finder.first(input, pos);
    while candidate != match_finder::NO_POSITION {
        if candidate >= pos {
            candidate = finder.previous(candidate);
            continue;
        }
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
            if best.length == max_length || best.length >= NICE_MATCH_LENGTH {
                break;
            }
        }
        if checked >= options.max_match_candidates {
            break;
        }
        candidate = finder.previous(candidate);
    }
    best
}

fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    super::fast::match_length(input, pos, distance, max_length)
}

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
        cost,
    };
    if best.is_none_or(|best| {
        candidate.score > best.score
            || (candidate.score == best.score
                && (candidate.length > best.length
                    || (candidate.length == best.length && candidate.cost < best.cost)
                    || (candidate.length == best.length
                        && candidate.cost == best.cost
                        && candidate.distance < best.distance)))
    }) {
        *best = Some(candidate);
    }
}

fn estimated_match_cost(
    state: &EncoderMatchState,
    length: usize,
    distance: usize,
    distance_size: usize,
) -> Result<usize> {
    if distance == state.reps[0] && length == state.last_length && state.last_length != 0 {
        return Ok(2);
    }
    if state
        .reps
        .iter()
        .any(|&repeat_distance| repeat_distance == distance && repeat_distance != 0)
    {
        let (length_slot, _) = length_slot_for_match(length)?;
        return Ok(5 + usize::from(length_slot_extra_bits(length_slot)?));
    }

    let (distance_slot, _) = distance_slot_for_match(distance, distance_size)?;
    let encoded_length = length
        .checked_sub(length_bonus(distance))
        .ok_or(Error::InvalidData("RAR 5 adjusted match length underflows"))?;
    let (length_slot, _) = length_slot_for_match(encoded_length)?;
    Ok(10
        + usize::from(length_slot_extra_bits(length_slot)?)
        + distance_slot_bit_count(distance_slot)?)
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 2 {
        return Err(Error::InvalidData("RAR 5 match length is too short"));
    }
    let value = length - 2;
    if value < 8 {
        return Ok((value, 0));
    }
    let bit_count = value.ilog2() as usize - 2;
    let slot = ((bit_count + 1) << 2) | ((value >> bit_count) & 3);
    if slot >= LENGTH_TABLE_SIZE {
        return Err(Error::InvalidData("RAR 5 match length is too long"));
    }
    Ok((slot, value & ((1 << bit_count) - 1)))
}

fn distance_slot_for_match(distance: usize, distance_size: usize) -> Result<(usize, usize)> {
    if distance == 0 {
        return Err(Error::InvalidData("RAR 5 match distance is zero"));
    }
    let value = distance - 1;
    if value < 4 {
        if value >= distance_size {
            return Err(Error::InvalidData("RAR 5 match distance is too large"));
        }
        return Ok((value, 0));
    }
    let bit_count = value.ilog2() as usize - 1;
    let slot = (bit_count << 1) + 2 + ((value >> bit_count) & 1);
    if slot >= distance_size {
        return Err(Error::InvalidData("RAR 5 match distance is too large"));
    }
    Ok((slot, value & ((1 << bit_count) - 1)))
}

fn literal_presence(data: &[u8]) -> [bool; 256] {
    let mut present = [false; 256];
    for &byte in data {
        present[byte as usize] = true;
    }
    present
}

#[derive(Debug, Clone)]
pub struct Unpack50Decoder {
    tables: Option<DecodeTables>,
    reps: [usize; 4],
    last_length: usize,
    history: Vec<u8>,
}

impl Unpack50Decoder {
    pub fn new() -> Self {
        Self {
            tables: None,
            reps: [0; 4],
            last_length: 0,
            history: Vec::new(),
        }
    }

    pub fn decode_member(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        self.decode_member_with_dictionary(
            input,
            algorithm_version,
            output_size,
            DEFAULT_DICTIONARY_SIZE,
            solid,
            mode,
        )
    }

    pub fn decode_member_with_dictionary(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        let mut input = std::io::Cursor::new(input);
        self.decode_member_from_reader_with_dictionary(
            &mut input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            mode,
        )
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        self.decode_member_from_reader_with_dictionary(
            input,
            algorithm_version,
            output_size,
            DEFAULT_DICTIONARY_SIZE,
            solid,
            mode,
        )
    }

    pub fn decode_member_from_reader_with_dictionary(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero"));
        }
        if !solid {
            self.reset();
        }

        let mut output = Vec::with_capacity(output_size.min(MAX_INITIAL_OUTPUT_CAPACITY));
        let mut filters = Vec::new();

        loop {
            let block = read_compressed_block(input)?;
            let payload = block.payload.as_slice();
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(DecodeTables::from_lengths(&lengths)?);
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new(payload);
            bits.bit_pos = payload_bit_pos;

            while bits.bit_pos < block.header.payload_bits && output.len() < output_size {
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => output.push(symbol as u8),
                    256 if mode.uses_lz() => {
                        filters.push(read_filter(&mut bits, output.len())?);
                    }
                    257 if mode.uses_lz() => {
                        if self.last_length != 0 {
                            self.copy_match(
                                &mut output,
                                self.reps[0],
                                self.last_length,
                                output_size,
                                dictionary_size,
                            )?;
                        }
                    }
                    258..=261 if mode.uses_lz() => {
                        let rep_index = symbol - 258;
                        let distance = self.reps[rep_index];
                        if distance == 0 {
                            return Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            ));
                        }
                        let length_slot = tables.length.decode(&mut bits)?;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let length = slot_to_length(length_slot, length_extra)?;
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        self.copy_match(
                            &mut output,
                            distance,
                            length,
                            output_size,
                            dictionary_size,
                        )?;
                    }
                    262.. if mode.uses_lz() => {
                        let length_slot = symbol - 262;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let mut length = slot_to_length(length_slot, length_extra)?;
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        let distance = slot_to_distance(distance_slot, distance_extra)?;
                        length += length_bonus(distance);
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        self.copy_match(
                            &mut output,
                            distance,
                            length,
                            output_size,
                            dictionary_size,
                        )?;
                    }
                    _ if mode == DecodeMode::LiteralOnly => {
                        return Err(Error::InvalidData(
                            "RAR 5 literal-only decoder encountered non-literal symbol",
                        ));
                    }
                    _ => {
                        return Err(Error::InvalidData(
                            "RAR 5 decoder encountered unsupported control symbol",
                        ));
                    }
                }
            }

            self.tables = Some(tables);
            if block.header.is_last || output.len() >= output_size {
                break;
            }
        }

        if output.len() == output_size {
            let history_output = if mode.applies_filters() && !filters.is_empty() {
                Some(output.clone())
            } else {
                None
            };
            if mode.applies_filters() {
                apply_filters(&mut output, &filters)?;
            }
            self.history
                .extend_from_slice(history_output.as_deref().unwrap_or(&output));
            if self.history.len() > dictionary_size {
                let discard = self.history.len() - dictionary_size;
                self.history.drain(..discard);
            }
            Ok(output)
        } else {
            Err(Error::NeedMoreInput)
        }
    }

    pub fn decode_member_from_reader_with_dictionary_to_sink<E>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mut sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero").into());
        }
        if !solid {
            self.reset();
        }

        // VecDeque grows as decoded bytes arrive, so using the declared
        // dictionary here does not allocate a potentially huge RAR 7 window
        // up front. It does, however, retain every byte that a legal match may
        // reference instead of silently truncating the window at 64 MiB.
        let history_limit = dictionary_size;
        if self.history.len() > history_limit {
            let discard = self.history.len() - history_limit;
            self.history.drain(..discard);
        }
        let mut output = StreamingOutput::new(
            std::mem::take(&mut self.history),
            output_size,
            dictionary_size,
            history_limit,
        );

        loop {
            let block = read_compressed_block(input)?;
            let payload = block.payload.as_slice();
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(DecodeTables::from_lengths(&lengths)?);
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new(payload);
            bits.bit_pos = payload_bit_pos;

            while bits.bit_pos < block.header.payload_bits && output.written() < output_size {
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => output.push(symbol as u8, &mut sink)?,
                    256 => {
                        return Err(StreamDecodeError::FilteredMember);
                    }
                    257 => {
                        if self.last_length != 0 {
                            output.copy_match(self.reps[0], self.last_length, &mut sink)?;
                        }
                    }
                    258..=261 => {
                        let rep_index = symbol - 258;
                        let distance = self.reps[rep_index];
                        if distance == 0 {
                            return Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            )
                            .into());
                        }
                        let length_slot = tables.length.decode(&mut bits)?;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let length = slot_to_length(length_slot, length_extra)?;
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        output.copy_match(distance, length, &mut sink)?;
                    }
                    262.. => {
                        let length_slot = symbol - 262;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let mut length = slot_to_length(length_slot, length_extra)?;
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        let distance = slot_to_distance(distance_slot, distance_extra)?;
                        length += length_bonus(distance);
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        output.copy_match(distance, length, &mut sink)?;
                    }
                }
            }

            self.tables = Some(tables);
            if block.header.is_last || output.written() >= output_size {
                break;
            }
        }

        if output.written() == output_size {
            output.finish(&mut sink)?;
            self.history = output.into_history();
            Ok(())
        } else {
            Err(Error::NeedMoreInput.into())
        }
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.last_length = 0;
        self.history.clear();
    }

    fn copy_match(
        &self,
        output: &mut Vec<u8>,
        distance: usize,
        length: usize,
        output_limit: usize,
        dictionary_size: usize,
    ) -> Result<()> {
        if distance > dictionary_size {
            return Err(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary",
            ));
        }
        if distance == 0 || distance > self.history.len() + output.len() {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window"));
        }
        if output
            .len()
            .checked_add(length)
            .is_none_or(|end| end > output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit"));
        }
        let mut remaining = length;
        while remaining > 0 {
            if distance <= output.len() {
                // The match lies entirely in already-decoded output: copy in
                // runs rather than one byte at a time.
                if distance == 1 {
                    // A one-byte repeat is a fill, not a copy.
                    let b = output[output.len() - 1];
                    output.resize(output.len() + remaining, b);
                    remaining = 0;
                } else {
                    let start = output.len() - distance;
                    let take = remaining.min(distance);
                    output.extend_from_within(start..start + take);
                    remaining -= take;
                }
            } else {
                let history_distance = distance - output.len();
                let index = self.history.len() - history_distance;
                let take = remaining.min(history_distance);
                output.extend_from_slice(&self.history[index..index + take]);
                remaining -= take;
            }
        }
        Ok(())
    }
}

struct StreamingOutput {
    history: VecDeque<u8>,
    pending: Vec<u8>,
    written: usize,
    output_limit: usize,
    dictionary_size: usize,
    history_limit: usize,
    all_zero: bool,
}

impl StreamingOutput {
    fn new(
        history: Vec<u8>,
        output_limit: usize,
        dictionary_size: usize,
        history_limit: usize,
    ) -> Self {
        Self {
            all_zero: history.iter().all(|&byte| byte == 0),
            history: history.into(),
            pending: Vec::with_capacity(STREAM_FLUSH_THRESHOLD),
            written: 0,
            output_limit,
            dictionary_size,
            history_limit,
        }
    }

    fn written(&self) -> usize {
        self.written
    }

    fn push<E>(
        &mut self,
        byte: u8,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.written >= self.output_limit {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if byte != 0 {
            self.all_zero = false;
        }
        self.pending.push(byte);
        self.written += 1;
        if self.pending.len() >= STREAM_FLUSH_THRESHOLD {
            self.flush(sink)?;
        }
        Ok(())
    }

    fn push_repeated<E>(
        &mut self,
        byte: u8,
        mut count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self
            .written
            .checked_add(count)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if byte != 0 {
            self.all_zero = false;
        }
        while count > 0 {
            let available = STREAM_FLUSH_THRESHOLD - self.pending.len();
            let take = count.min(available.max(1));
            let old_len = self.pending.len();
            self.pending.resize(old_len + take, byte);
            self.written += take;
            count -= take;
            if self.pending.len() >= STREAM_FLUSH_THRESHOLD {
                self.flush(sink)?;
            }
        }
        Ok(())
    }

    fn push_zeroes<E>(
        &mut self,
        count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self
            .written
            .checked_add(count)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        self.flush(sink)?;
        sink(DecodedChunk::Repeated {
            byte: 0,
            len: count,
        })
        .map_err(StreamDecodeError::Sink)?;
        self.written += count;
        if self.history.is_empty() && self.history_limit != 0 {
            self.history.push_back(0);
        }
        Ok(())
    }

    fn copy_match<E>(
        &mut self,
        distance: usize,
        length: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if distance > self.dictionary_size {
            return Err(Error::InvalidData("RAR 5 match distance exceeds dictionary").into());
        }
        if self.all_zero && distance <= self.written + self.history.len() {
            return self.push_zeroes(length, sink);
        }
        if distance == 0 || distance > self.history.len() + self.pending.len() {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window").into());
        }
        if self
            .written
            .checked_add(length)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if distance == 1 {
            let byte = self.byte_at_distance(1)?;
            return self.push_repeated(byte, length, sink);
        }
        for _ in 0..length {
            let byte = self.byte_at_distance(distance)?;
            self.push(byte, sink)?;
        }
        Ok(())
    }

    fn byte_at_distance(&self, distance: usize) -> Result<u8> {
        if distance <= self.pending.len() {
            Ok(self.pending[self.pending.len() - distance])
        } else {
            let history_distance = distance - self.pending.len();
            if history_distance > self.history.len() {
                return Err(Error::InvalidData("RAR 5 match distance exceeds window"));
            }
            Ok(*self
                .history
                .get(self.history.len() - history_distance)
                .ok_or(Error::InvalidData("RAR 5 match distance exceeds window"))?)
        }
    }

    fn flush<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.pending.is_empty() {
            return Ok(());
        }
        sink(DecodedChunk::Bytes(&self.pending)).map_err(StreamDecodeError::Sink)?;
        self.history.extend(self.pending.iter().copied());
        self.pending.clear();
        while self.history.len() > self.history_limit {
            self.history.pop_front();
        }
        Ok(())
    }

    fn finish<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.flush(sink)
    }

    fn into_history(self) -> Vec<u8> {
        self.history.into()
    }
}

fn read_compressed_block(input: &mut impl Read) -> Result<OwnedCompressedBlock> {
    let mut fixed = [0u8; 2];
    input
        .read_exact(&mut fixed)
        .map_err(|_| Error::NeedMoreInput)?;
    let flags = fixed[0];
    let checksum = fixed[1];
    let size_bytes_len = match (flags >> 3) & 0x03 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => return Err(Error::InvalidData("RAR 5 block size length is invalid")),
    };
    let mut size_bytes = [0u8; 3];
    input
        .read_exact(&mut size_bytes[..size_bytes_len])
        .map_err(|_| Error::NeedMoreInput)?;

    let actual = size_bytes[..size_bytes_len]
        .iter()
        .fold(checksum ^ flags, |acc, &byte| acc ^ byte);
    if actual != 0x5a {
        return Err(Error::InvalidData("RAR 5 block header checksum mismatch"));
    }

    let payload_size = size_bytes[..size_bytes_len]
        .iter()
        .enumerate()
        .fold(0usize, |acc, (index, &byte)| {
            acc | (usize::from(byte) << (index * 8))
        });
    let mut payload = vec![0; payload_size];
    input
        .read_exact(&mut payload)
        .map_err(|_| Error::NeedMoreInput)?;
    let final_byte_bits = ((flags & 0x07) + 1).min(8);
    let payload_bits = if payload_size == 0 {
        0
    } else {
        (payload_size - 1) * 8 + usize::from(final_byte_bits)
    };

    Ok(OwnedCompressedBlock {
        header: CompressedBlockHeader {
            flags,
            is_last: flags & 0x40 != 0,
            has_tables: flags & 0x80 != 0,
            final_byte_bits,
            payload_size,
            payload_bits,
        },
        payload,
    })
}

impl Default for Unpack50Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFilter {
    start: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterType {
    Delta,
    E8,
    E8E9,
    Arm,
}

fn read_filter(bits: &mut BitReader<'_>, current_pos: usize) -> Result<PendingFilter> {
    let offset = read_filter_data(bits)? as usize;
    let length = read_filter_data(bits)? as usize;
    let filter_type = match bits.read_bits(3)? {
        0 => FilterType::Delta,
        1 => FilterType::E8,
        2 => FilterType::E8E9,
        3 => FilterType::Arm,
        _ => return Err(Error::InvalidData("RAR 5 filter type is unsupported")),
    };
    let channels = if filter_type == FilterType::Delta {
        bits.read_bits(5)? as usize + 1
    } else {
        0
    };
    Ok(PendingFilter {
        start: current_pos
            .checked_add(offset)
            .ok_or(Error::InvalidData("RAR 5 filter start overflows"))?,
        length,
        filter_type,
        channels,
    })
}

fn read_filter_data(bits: &mut BitReader<'_>) -> Result<u32> {
    let byte_count = bits.read_bits(2)? as usize + 1;
    let mut data = 0;
    for index in 0..byte_count {
        data |= bits.read_bits(8)? << (index * 8);
    }
    Ok(data)
}

fn write_filter(writer: &mut BitWriter, filter: EncodeFilter) -> Result<()> {
    if filter.offset > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter offset is too large"));
    }
    if filter.length > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter length is too large"));
    }
    write_filter_data(writer, filter.offset as u32);
    write_filter_data(writer, filter.length as u32);
    match filter.filter_type {
        FilterType::Delta => {
            if filter.channels == 0 || filter.channels > 32 {
                return Err(Error::InvalidData(
                    "RAR 5 DELTA filter channel count is invalid",
                ));
            }
            writer.write_bits(0, 3);
            writer.write_bits(filter.channels - 1, 5);
        }
        FilterType::E8 => writer.write_bits(1, 3),
        FilterType::E8E9 => writer.write_bits(2, 3),
        FilterType::Arm => writer.write_bits(3, 3),
    }
    Ok(())
}

fn write_filter_data(writer: &mut BitWriter, value: u32) {
    let byte_count = if value <= 0xff {
        1
    } else if value <= 0xffff {
        2
    } else if value <= 0x00ff_ffff {
        3
    } else {
        4
    };
    writer.write_bits(byte_count - 1, 2);
    for index in 0..byte_count {
        writer.write_bits(((value >> (index * 8)) & 0xff) as usize, 8);
    }
}

fn apply_filters(output: &mut [u8], filters: &[PendingFilter]) -> Result<()> {
    for filter in filters {
        let end = filter
            .start
            .checked_add(filter.length)
            .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
        let data = output
            .get_mut(filter.start..end)
            .ok_or(Error::InvalidData("RAR 5 filter range exceeds output"))?;
        match filter.filter_type {
            FilterType::Delta => {
                let decoded = filters::delta_decode(data, filter.channels, rar50_delta_messages())?;
                data.copy_from_slice(&decoded);
            }
            FilterType::E8 => e8e9_decode(data, filter.start as u32, false),
            FilterType::E8E9 => e8e9_decode(data, filter.start as u32, true),
            FilterType::Arm => arm_decode(data, filter.start as u32),
        }
    }
    Ok(())
}

fn rar50_delta_messages() -> DeltaErrorMessages {
    DeltaErrorMessages {
        invalid_channels: "RAR 5 DELTA filter channel count is invalid",
        zero_channels: "RAR 5 DELTA filter has zero channels",
        truncated_source: "RAR 5 DELTA filter source is truncated",
    }
}

fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32) % X86_FILTER_FILE_SIZE;
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let new_addr = if addr & 0x8000_0000 != 0 {
            (addr.wrapping_add(offset) & 0x8000_0000 == 0)
                .then(|| addr.wrapping_add(X86_FILTER_FILE_SIZE))
        } else {
            (addr.wrapping_sub(X86_FILTER_FILE_SIZE) & 0x8000_0000 != 0)
                .then(|| addr.wrapping_sub(offset))
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }
}

fn e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
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

const X86_FILTER_FILE_SIZE: u32 = 0x0100_0000;

fn arm_decode(data: &mut [u8], file_offset: u32) {
    let mut pos = 0usize;
    while pos + 3 < data.len() {
        if data[pos + 3] == 0xeb {
            let mut offset = u32::from(data[pos])
                | (u32::from(data[pos + 1]) << 8)
                | (u32::from(data[pos + 2]) << 16);
            offset = offset.wrapping_sub(file_offset.wrapping_add(pos as u32) / 4);
            data[pos] = offset as u8;
            data[pos + 1] = (offset >> 8) as u8;
            data[pos + 2] = (offset >> 16) as u8;
        }
        pos += 4;
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

fn length_slot_extra_bits(slot: usize) -> Result<u8> {
    if slot < 8 {
        Ok(0)
    } else {
        let bit_count = (slot >> 2) - 1;
        if bit_count > 24 {
            Err(Error::InvalidData("RAR 5 length slot is too large"))
        } else {
            Ok(bit_count as u8)
        }
    }
}

fn length_bonus(distance: usize) -> usize {
    usize::from(distance > 0x100) + usize::from(distance > 0x2000) + usize::from(distance > 0x40000)
}

pub fn slot_to_length(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 8 {
        return Ok(slot + 2);
    }
    let bit_count = (slot >> 2) - 1;
    if bit_count > 24 {
        return Err(Error::InvalidData("RAR 5 length slot is too large"));
    }
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 length extra bits exceed slot"));
    }
    Ok((((4 | (slot & 3)) << bit_count) | extra_bits as usize) + 2)
}

pub fn distance_slot_bit_count(slot: usize) -> Result<usize> {
    if slot < 4 {
        Ok(0)
    } else {
        let bit_count = (slot - 2) >> 1;
        if bit_count > 31 {
            Err(Error::InvalidData("RAR 5 distance slot is too large"))
        } else {
            Ok(bit_count)
        }
    }
}

pub fn slot_to_distance(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 4 {
        return Ok(slot + 1);
    }
    let bit_count = distance_slot_bit_count(slot)?;
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"));
    }
    Ok((((2 | (slot & 1)) << bit_count) | extra_bits as usize) + 1)
}

#[derive(Debug, Clone)]
pub struct HuffmanTable {
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

impl HuffmanTable {
    pub fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &length in lengths {
            if length > 15 {
                return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
            }
            if length != 0 {
                count[length as usize] += 1;
            }
        }
        validate_huffman_counts(&count)?;

        let mut first_code = [0u16; 16];
        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for length in 1..=15 {
            code = (code + count[length - 1]) << 1;
            first_code[length] = code;
            next_code[length] = code;
        }

        let mut first_index = [0usize; 16];
        let mut index = 0usize;
        for length in 1..=15 {
            first_index[length] = index;
            index += usize::from(count[length]);
        }

        let mut symbols = Vec::new();
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let code = next_code[length as usize];
            next_code[length as usize] += 1;
            symbols.push(HuffmanSymbol {
                code,
                len: length,
                symbol,
            });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));
        Ok(Self {
            symbols,
            first_code,
            first_index,
            counts: count,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        if self.symbols.is_empty() {
            return Err(Error::InvalidData("RAR 5 empty Huffman table"));
        }
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code << 1) | bits.read_bits(1)? as u16;
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
        Err(Error::InvalidData("RAR 5 invalid Huffman code"))
    }

    fn code_for_symbol(&self, symbol: usize) -> Result<(u16, u8)> {
        self.symbols
            .iter()
            .find(|item| item.symbol == symbol)
            .map(|item| (item.code, item.len))
            .ok_or(Error::InvalidData("RAR 5 missing Huffman symbol"))
    }
}

struct BitReader<'a> {
    input: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, bit_pos: 0 }
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        if count > 32 {
            return Err(Error::InvalidData("RAR 5 bit read is too wide"));
        }
        let end = self
            .bit_pos
            .checked_add(usize::from(count))
            .ok_or(Error::NeedMoreInput)?;
        if end > self.input.len() * 8 {
            return Err(Error::NeedMoreInput);
        }

        let mut value = 0u32;
        let mut remaining = usize::from(count);
        while remaining != 0 {
            let byte = self.input[self.bit_pos / 8];
            let bit_offset = self.bit_pos % 8;
            let available = 8 - bit_offset;
            let take = available.min(remaining);
            let shift = available - take;
            let mask = ((1u16 << take) - 1) as u8;
            let chunk = (byte >> shift) & mask;
            value = (value << take) | u32::from(chunk);
            self.bit_pos += take;
            remaining -= take;
        }

        Ok(value)
    }
}

struct BitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_pos: 0,
        }
    }

    fn write_bits(&mut self, value: usize, count: usize) {
        for bit in (0..count).rev() {
            if self.bit_pos.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (value >> bit) & 1 != 0 {
                let byte = self.bytes.last_mut().unwrap();
                *byte |= 1 << (7 - (self.bit_pos % 8));
            }
            self.bit_pos += 1;
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    let mut available = 1i32;
    for &len_count in count.iter().skip(1) {
        available = (available << 1) - i32::from(len_count);
        if available < 0 {
            return Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"));
        }
    }
    Ok(())
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

fn encode_table_level_tokens(lengths: &[u8]) -> Vec<LevelToken> {
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
            emit_repeat_level_run(&mut tokens, run);
            pos += run;
            continue;
        }

        tokens.push(LevelToken::plain(value as usize));
        previous = Some(value);
        pos += 1;
    }
    tokens
}

fn emit_repeat_level_run(tokens: &mut Vec<LevelToken>, mut run: usize) {
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) && chunk >= 14 {
                chunk -= 3;
            }
            tokens.push(LevelToken::repeat_previous_long(chunk));
            run -= chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens.push(LevelToken::repeat_previous_short(chunk));
            run -= chunk;
        } else {
            break;
        }
    }
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

fn level_code_lengths_for_tokens(tokens: &[LevelToken]) -> [u8; LEVEL_TABLE_SIZE] {
    // Mark used level symbols, then normalise to a *complete* canonical code.
    // The pre-table is rebuilt by strict decoders (7-Zip's `k_BuildMode_Full`),
    // which reject an under-full table, so a uniform length assignment is only
    // valid when the used-symbol count is a power of two.
    let mut lengths = [0u8; LEVEL_TABLE_SIZE];
    for token in tokens {
        lengths[token.symbol] = 1;
    }
    huffman::assign_flat_complete_code(&mut lengths);
    lengths
}

fn write_level_lengths(writer: &mut BitWriter, lengths: &[u8; LEVEL_TABLE_SIZE]) {
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
                writer.write_bits(15, 4);
                writer.write_bits(chunk - 2, 4);
                pos += chunk;
                count -= chunk;
            }
            for _ in 0..count {
                writer.write_bits(0, 4);
                pos += 1;
            }
        } else {
            writer.write_bits(usize::from(length), 4);
            if length == 15 {
                writer.write_bits(0, 4);
            }
            pos += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_tokens(
        input: &[u8],
        history: &[u8],
        options: EncodeOptions,
        distance_size: usize,
    ) -> Vec<EncodeToken> {
        encode_tokens_with_progress(input, history, options, distance_size, None)
            .expect("encoding without cancellation cannot be cancelled")
    }
    fn should_lazy_emit_literal(
        input: &[u8],
        pos: usize,
        finder: &Rar50MatchFinder,
        options: EncodeOptions,
        state: &EncoderMatchState,
        distance_size: usize,
        current: MatchCandidate,
    ) -> bool {
        lazy_match_decision(input, pos, finder, options, state, distance_size, current).0
    }

    fn checksum(flags: u8, size_bytes: &[u8]) -> u8 {
        size_bytes
            .iter()
            .fold(0x5a ^ flags, |acc, &byte| acc ^ byte)
    }

    #[test]
    fn parses_one_byte_size_block_header() {
        let flags = 0xc7;
        let size = [3];
        let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb, 0xcc];

        let block = parse_compressed_block(&input).unwrap();
        assert_eq!(block.header_len, 3);
        assert_eq!(block.payload, 3..6);
        assert_eq!(block.header.flags, flags);
        assert!(block.header.is_last);
        assert!(block.header.has_tables);
        assert_eq!(block.header.final_byte_bits, 8);
        assert_eq!(block.header.payload_size, 3);
        assert_eq!(block.header.payload_bits, 24);
    }

    #[test]
    fn parses_three_byte_size_block_header_with_partial_final_byte() {
        let flags = 0x94;
        let size = [0x34, 0x12, 0x00];
        let mut input = vec![flags, checksum(flags, &size), size[0], size[1], size[2]];
        input.resize(0x1234 + 5, 0);

        let block = parse_compressed_block(&input).unwrap();
        assert_eq!(block.header_len, 5);
        assert_eq!(block.payload, 5..0x1239);
        assert!(!block.header.is_last);
        assert!(block.header.has_tables);
        assert_eq!(block.header.final_byte_bits, 5);
        assert_eq!(block.header.payload_size, 0x1234);
        assert_eq!(block.header.payload_bits, (0x1234 - 1) * 8 + 5);
    }

    #[test]
    fn rejects_reserved_size_length_selector() {
        let input = [0x18, 0x42, 0x00];

        assert_eq!(
            parse_compressed_block(&input),
            Err(Error::InvalidData("RAR 5 block size length is invalid"))
        );
    }

    #[test]
    fn rejects_bad_block_header_checksum() {
        let input = [0xc7, 0x00, 0x03, 0xaa, 0xbb, 0xcc];

        assert_eq!(
            parse_compressed_block(&input),
            Err(Error::InvalidData("RAR 5 block header checksum mismatch"))
        );
    }

    #[test]
    fn rejects_truncated_block_payload() {
        let flags = 0xc7;
        let size = [3];
        let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb];

        assert_eq!(parse_compressed_block(&input), Err(Error::NeedMoreInput));
    }

    #[test]
    fn reads_level_lengths_with_literal_fifteen() {
        let mut nibbles = vec![1, 2, 15, 0, 3, 4];
        nibbles.resize(LEVEL_TABLE_SIZE + 1, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(&lengths[..6], &[1, 2, 15, 3, 4, 0]);
        assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4);
    }

    #[test]
    fn reads_level_lengths_with_zero_run_at_current_position() {
        let mut nibbles = vec![7, 15, 3, 2];
        nibbles.resize(LEVEL_TABLE_SIZE - 3, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(lengths[0], 7);
        assert_eq!(&lengths[1..6], &[0, 0, 0, 0, 0]);
        assert_eq!(lengths[6], 2);
        assert_eq!(bits, (LEVEL_TABLE_SIZE - 3) * 4);
    }

    fn pack_nibbles(nibbles: &[u8]) -> Vec<u8> {
        nibbles
            .chunks(2)
            .map(|chunk| {
                let high = chunk[0] & 0x0f;
                let low = chunk.get(1).copied().unwrap_or(0) & 0x0f;
                (high << 4) | low
            })
            .collect()
    }

    #[test]
    fn reads_rar50_second_level_table_lengths() {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        for count in [138, 138, 138, 16] {
            writer.write_bits(19, 5);
            writer.write_bits(count - 11, 7);
        }
        let input = writer.finish();

        let (lengths, bits) = read_table_lengths(&input, 0).unwrap();

        assert_eq!(lengths.main.len(), MAIN_TABLE_SIZE);
        assert_eq!(lengths.distance.len(), DISTANCE_TABLE_SIZE_50);
        assert_eq!(lengths.align.len(), ALIGN_TABLE_SIZE);
        assert_eq!(lengths.length.len(), LENGTH_TABLE_SIZE);
        assert!(lengths.main.iter().all(|&length| length == 0));
        assert!(lengths.distance.iter().all(|&length| length == 0));
        assert!(lengths.align.iter().all(|&length| length == 0));
        assert!(lengths.length.iter().all(|&length| length == 0));
        assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4 * (5 + 7));
    }

    #[test]
    fn reads_rar70_table_length_count() {
        assert_eq!(
            table_length_count(1).unwrap(),
            MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
        );
    }

    #[test]
    fn encoded_table_lengths_round_trip_with_bit_count() {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 1;
        lengths.main[b'B' as usize] = 3;
        lengths.main[262] = 3;
        lengths.distance[1] = 1;
        lengths.align[0] = 4;
        lengths.length[0] = 1;

        let (encoded, bit_count) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let (decoded, decoded_bits) = read_table_lengths(&encoded, 0).unwrap();

        assert_eq!(decoded, lengths);
        assert_eq!(decoded_bits, bit_count);
    }

    #[test]
    fn table_level_encoder_uses_rar5_run_symbols() {
        let mut lengths =
            vec![
                0u8;
                MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_50 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
            ];
        lengths[..4].fill(6);
        lengths[8..21].fill(0);

        let tokens = encode_table_level_tokens(&lengths);

        assert!(tokens.contains(&LevelToken::repeat_previous_short(3)));
        assert!(tokens.iter().any(|token| token.symbol == 19));
    }

    #[test]
    fn encoded_compressed_block_round_trips_header_fields() {
        let payload = [0xaa, 0xbb, 0xc0];
        let block = encode_compressed_block(&payload, 18, true, true).unwrap();

        let parsed = parse_compressed_block(&block).unwrap();

        assert_eq!(parsed.payload, 3..6);
        assert!(parsed.header.has_tables);
        assert!(parsed.header.is_last);
        assert_eq!(parsed.header.final_byte_bits, 2);
        assert_eq!(parsed.header.payload_bits, 18);
        assert_eq!(&block[parsed.payload], payload);
    }

    #[test]
    fn rejects_table_repeat_without_previous_length() {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        writer.write_bits(16, 5);
        writer.write_bits(0, 3);

        assert_eq!(
            read_table_lengths(&writer.finish(), 0),
            Err(Error::InvalidData(
                "RAR 5 table repeats missing previous length"
            ))
        );
    }

    #[test]
    fn rejects_invalid_encoded_block_bit_counts() {
        assert_eq!(
            encode_compressed_block(&[0], 0, true, true),
            Err(Error::InvalidData("RAR 5 block has unused payload bytes"))
        );
        assert_eq!(
            encode_compressed_block(&[], 1, true, true),
            Err(Error::InvalidData("RAR 5 block bit count exceeds payload"))
        );
    }

    #[test]
    fn builds_named_decode_tables_from_lengths() {
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        };

        let tables = DecodeTables::from_lengths(&lengths).unwrap();

        assert!(!tables.main.is_empty());
        assert!(!tables.distance.is_empty());
        assert!(!tables.align.is_empty());
        assert!(!tables.length.is_empty());
        assert!(!tables.align_mode);
    }

    #[test]
    fn rejects_oversubscribed_rar50_huffman_tables() {
        assert!(matches!(
            HuffmanTable::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
        ));
    }

    #[test]
    fn detects_rar50_align_mode_when_align_lengths_are_not_uniform_four() {
        let mut align = vec![4; ALIGN_TABLE_SIZE];
        align[0] = 0;
        align[3] = 3;
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align,
            length: vec![1, 1],
        };

        let tables = DecodeTables::from_lengths(&lengths).unwrap();

        assert!(tables.align_mode);
    }

    #[test]
    fn decodes_synthetic_literal_only_block() {
        let payload = literal_only_payload(b"ABBA");
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_literal_only(&input, 0, 4).unwrap();

        assert_eq!(output, b"ABBA");
    }

    #[test]
    fn encodes_literal_only_member_that_decoder_reads() {
        let data = b"literal-only RAR5 codec stream\nwith repeated words words words";
        let input = encode_literal_only(data, 0).unwrap();

        let output = decode_literal_only(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn encodes_literal_only_rar70_table_shape_that_decoder_reads() {
        let data = b"small RAR7-compatible literal block";
        let input = encode_literal_only(data, 1).unwrap();

        let output = decode_literal_only(&input, 1, data.len()).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn encodes_empty_literal_only_member() {
        let input = encode_literal_only(b"", 0).unwrap();

        let output = decode_literal_only(&input, 0, 0).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn encodes_lz_member_with_same_member_matches() {
        let data = b"RAR5 match writer phrase. RAR5 match writer phrase. RAR5 match writer phrase.";
        let lz = encode_lz_member(data, 0).unwrap();
        let literal = encode_literal_only(data, 0).unwrap();

        let output = decode_lz(&lz, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert!(lz.len() < literal.len());
        assert!(
            encode_tokens(data, &[], EncodeOptions::default(), DISTANCE_TABLE_SIZE_50)
                .iter()
                .any(|token| matches!(token, EncodeToken::Match { .. }))
        );
    }

    #[test]
    fn frequency_weighted_huffman_lengths_shorten_common_symbols() {
        let mut frequencies = vec![1usize; 24];
        frequencies[3] = 1024;

        let lengths = huffman::lengths_for_frequencies(&frequencies, 15);

        assert!(lengths[3] < lengths[0]);
        assert!(lengths.iter().all(|&length| length <= 15));
    }

    #[test]
    fn lz_encoder_uses_frequency_weighted_huffman_lengths() {
        let mut data = vec![b'a'; 200];
        data.extend_from_slice(b"bcdefghijklmnopqrstuvwxyz");
        let input = encode_lz_member_with_options(&data, 0, EncodeOptions::new(0)).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert!(lengths.main[b'a' as usize] < lengths.main[b'z' as usize]);
    }

    fn code_is_complete(lengths: &[u8]) -> bool {
        let max_len = lengths.iter().copied().max().unwrap_or(0);
        if max_len == 0 {
            return true;
        }
        let sum: u64 = lengths
            .iter()
            .filter(|&&len| len != 0)
            .map(|&len| 1u64 << (max_len - len))
            .sum();
        sum == (1u64 << max_len)
    }

    #[test]
    fn degenerate_inputs_emit_complete_huffman_tables() {
        // Highly repetitive data collapses the distance/length/align tables to a
        // single symbol. Those tables must still be transmitted as *complete*
        // prefix codes, or strict RAR 5 decoders (7-Zip / WinRAR, which build
        // with `Full_or_Empty`) reject the archive with a spurious data error.
        // See issue #19.
        let inputs: &[Vec<u8>] = &[
            vec![b'a'; 4000],
            b"ab".repeat(4000),
            (0u8..16).cycle().take(50_000).collect(),
            b"lorem ipsum dolor sit amet ".repeat(2000),
        ];
        for data in inputs {
            let input = encode_lz_member_with_options(data, 0, EncodeOptions::new(0)).unwrap();
            let block = parse_compressed_block(&input).unwrap();
            let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

            assert!(code_is_complete(&lengths.main), "main table incomplete");
            assert!(
                code_is_complete(&lengths.distance),
                "distance table incomplete"
            );
            assert!(code_is_complete(&lengths.length), "length table incomplete");
            assert!(code_is_complete(&lengths.align), "align table incomplete");

            assert_eq!(&decode_lz(&input, 0, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn lazy_lz_parser_defers_short_match_for_longer_next_match() {
        let input = b"abcdXbcdYYYYYYYYYYYYabcdYYYYYYYYYYYY";
        let greedy = encode_tokens(
            input,
            &[],
            EncodeOptions::new(MAX_MATCH_CANDIDATES),
            DISTANCE_TABLE_SIZE_50,
        );
        let lazy = encode_tokens(
            input,
            &[],
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
            DISTANCE_TABLE_SIZE_50,
        );
        let packed = encode_lz_member_with_options(
            input,
            0,
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
        )
        .unwrap();

        assert!(greedy
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { length: 4, .. })));
        assert!(lazy
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { length, .. } if *length > 8)));
        assert_eq!(decode_lz(&packed, 0, input.len()).unwrap(), input);
    }

    #[test]
    fn cost_aware_match_selection_prefers_repeat_distance_token() {
        let pos = 64;
        let pattern = b"abcdefgh";
        let mut input: Vec<u8> = (0..96u8).map(|byte| byte.wrapping_mul(37)).collect();
        input[pos - 30..pos - 22].copy_from_slice(pattern);
        input[pos - 10..pos - 2].copy_from_slice(pattern);
        input[pos..pos + 8].copy_from_slice(pattern);
        input[pos + 8] = b'X';

        let mut finder = Rar50MatchFinder::new(input.len());
        for candidate in 0..pos {
            finder.insert(&input, candidate);
        }
        let state = EncoderMatchState {
            reps: [30, 0, 0, 0],
            last_length: 8,
        };

        let best = best_match(
            &input,
            pos,
            input.len(),
            &finder,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
        )
        .unwrap();

        assert_eq!((best.length, best.distance), (8, 30));
    }

    #[test]
    fn lazy_parser_uses_match_cost_not_only_match_length() {
        let pos = 600;
        let mut input: Vec<u8> = (0..700u16)
            .map(|value| value.wrapping_mul(73) as u8)
            .collect();
        input[pos - 512..pos - 504].copy_from_slice(b"ABCDEFGH");
        input[pos - 504] = b'Z';
        input[pos - 29..pos - 21].copy_from_slice(b"BCDEFGHI");
        input[pos - 30] = b'x';
        input[pos..pos + 9].copy_from_slice(b"ABCDEFGHI");

        let mut finder = Rar50MatchFinder::new(input.len());
        for candidate in 0..pos {
            finder.insert(&input, candidate);
        }
        let state = EncoderMatchState {
            reps: [30, 0, 0, 0],
            last_length: 8,
        };
        let current = best_match(
            &input,
            pos,
            input.len(),
            &finder,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
        )
        .unwrap();

        assert_eq!((current.length, current.distance), (8, 512));
        assert!(should_lazy_emit_literal(
            &input,
            pos,
            &finder,
            EncodeOptions::default().with_lazy_matching(true),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
        ));
    }

    #[test]
    fn lazy_parser_uses_bounded_cost_lookahead() {
        let pos = 160;
        let mut input: Vec<u8> = (0..240u16)
            .map(|value| value.wrapping_mul(91) as u8)
            .collect();
        input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
        input[pos - 80..pos - 70].copy_from_slice(b"CDEFGHIJKL");
        input[pos..pos + 12].copy_from_slice(b"ABCDEFGHIJKL");

        let mut finder = Rar50MatchFinder::new(input.len());
        for candidate in 0..pos {
            finder.insert(&input, candidate);
        }
        let state = EncoderMatchState::default();
        let current = best_match(
            &input,
            pos,
            input.len(),
            &finder,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
        )
        .unwrap();

        assert_eq!((current.length, current.distance), (8, 30));
        assert!(!should_lazy_emit_literal(
            &input,
            pos,
            &finder,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(1),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
        ));
        assert!(should_lazy_emit_literal(
            &input,
            pos,
            &finder,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(2),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
        ));
    }

    #[test]
    fn lazy_parser_charges_for_skipped_literals() {
        let pos = 160;
        let mut input: Vec<u8> = (0..240u16)
            .map(|value| value.wrapping_mul(91) as u8)
            .collect();
        input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
        input[pos - 80..pos - 71].copy_from_slice(b"CDEFGHIJK");
        input[pos..pos + 12].copy_from_slice(b"ABCDEFGHIJKL");

        let mut finder = Rar50MatchFinder::new(input.len());
        for candidate in 0..pos {
            finder.insert(&input, candidate);
        }
        let state = EncoderMatchState::default();
        let current = best_match(
            &input,
            pos,
            input.len(),
            &finder,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
        )
        .unwrap();

        let next = best_match(
            &input,
            pos + 2,
            input.len(),
            &finder,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
        )
        .unwrap();

        assert!(next.score > current.score);
        assert!(next.score <= current.score + 16);
        assert!(!should_lazy_emit_literal(
            &input,
            pos,
            &finder,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(2),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
        ));
    }

    fn encode_lz_member_with_filter(data: &[u8], kind: crate::FilterKind) -> Result<Vec<u8>> {
        Unpack50Encoder::new().encode_member_with_filter(data, 0, crate::FilterSpec::whole(kind))
    }

    #[test]
    fn encodes_lz_member_with_delta_filter_record() {
        let data: Vec<u8> = (0..96).map(|index| (index * 7 + index / 3) as u8).collect();
        let input =
            encode_lz_member_with_filter(&data, crate::FilterKind::Delta { channels: 3 }).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn rejects_invalid_delta_filter_channel_count() {
        assert_eq!(
            encode_lz_member_with_filter(b"abc", crate::FilterKind::Delta { channels: 0 }),
            Err(Error::InvalidData(
                "RAR 5 DELTA filter channel count is invalid"
            ))
        );
        assert_eq!(
            encode_lz_member_with_filter(b"abc", crate::FilterKind::Delta { channels: 33 }),
            Err(Error::InvalidData(
                "RAR 5 DELTA filter channel count is invalid"
            ))
        );
    }

    #[test]
    fn encodes_lz_member_with_e8_filter_record() {
        let mut data = b"\xe8\0\0\0\0plain text after call".to_vec();
        data.extend_from_slice(&[0xe8, 3, 0, 0, 0, b'X']);
        let input = encode_lz_member_with_filter(&data, crate::FilterKind::E8).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn rar50_e8_filter_wraps_file_offset_modulo_16m() {
        let file_offset = 0x0110_0000;
        let mut encoded = vec![0xe8];
        encoded.extend_from_slice(&0x0010_0c08u32.to_le_bytes());

        let mut decoded = encoded.clone();
        e8e9_decode(&mut decoded, file_offset, false);

        assert_eq!(&decoded[1..5], &0x0000_0c07u32.to_le_bytes());
        e8e9_encode(&mut decoded, file_offset, false);
        assert_eq!(decoded, encoded);
    }

    #[test]
    fn streaming_decode_reports_filtered_member_with_typed_sentinel() {
        let data = b"\xe8\0\0\0\0plain text after call".to_vec();
        let input = encode_lz_member_with_filter(&data, crate::FilterKind::E8).unwrap();
        let mut reader = input.as_slice();
        let mut decoder = Unpack50Decoder::new();

        let error = decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut reader,
                0,
                data.len(),
                128 * 1024,
                false,
                |_chunk| Ok::<_, std::convert::Infallible>(()),
            )
            .unwrap_err();

        assert!(matches!(error, StreamDecodeError::FilteredMember));
    }

    #[test]
    fn encodes_lz_member_with_e8e9_filter_record() {
        let data = b"\xe9\0\0\0\0jump target through e9".to_vec();
        let input = encode_lz_member_with_filter(&data, crate::FilterKind::E8E9).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn encodes_lz_member_with_ranged_e8e9_filter_record() {
        let mut data = b"\xe8\0\0\0\0plain prefix outside filter range".to_vec();
        let range_start = data.len();
        for _ in 0..16 {
            let operand_pos = data.len() + 1;
            data.push(0xe8);
            let relative = 0x7000u32.wrapping_sub(operand_pos as u32);
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(b" code ");
        }
        let range = range_start..data.len();
        data.extend_from_slice(b"\xe9\0\0\0\0plain suffix outside filter range");

        let input = Unpack50Encoder::new()
            .encode_member_with_filter(
                &data,
                0,
                crate::FilterSpec::range(crate::FilterKind::E8E9, range),
            )
            .unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn encodes_lz_member_with_multiple_filter_records() {
        let mut data = b"\xe8\0\0\0\0plain prefix outside filters".to_vec();
        let first_start = data.len();
        data.extend_from_slice(b"\xe8\0\0\0\0first filtered cluster");
        let first_end = data.len();
        data.extend_from_slice(b"large plain middle outside filters");
        let second_start = data.len();
        data.extend_from_slice(b"\xe8\0\0\0\0second filtered cluster");
        let second_end = data.len();

        let input = Unpack50Encoder::new()
            .encode_member_with_filters(
                &data,
                0,
                &[
                    crate::FilterSpec::range(crate::FilterKind::E8, first_start..first_end),
                    crate::FilterSpec::range(crate::FilterKind::E8, second_start..second_end),
                ],
            )
            .unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, table_bits) = read_table_lengths(&input[block.payload.clone()], 0).unwrap();
        let tables = DecodeTables::from_lengths(&lengths).unwrap();
        let mut bits = BitReader {
            input: &input[block.payload],
            bit_pos: table_bits,
        };
        assert_eq!(tables.main.decode(&mut bits).unwrap(), 256);
        let first = read_filter(&mut bits, 0).unwrap();
        assert_eq!(tables.main.decode(&mut bits).unwrap(), 256);
        let second = read_filter(&mut bits, 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_eq!(first.start, first_start);
        assert_eq!(second.start, second_start);
    }

    #[test]
    fn encodes_lz_member_with_arm_filter_record() {
        let data = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
        let input = encode_lz_member_with_filter(&data, crate::FilterKind::Arm).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn arm_filter_uses_wrapping_address_arithmetic_at_u32_boundary() {
        let original = [0x04, 0x00, 0x00, 0xeb, 0x08, 0x00, 0x00, 0xeb];
        let mut filtered = original;

        arm_encode(&mut filtered, u32::MAX - 3);
        assert_ne!(filtered, original);
        arm_decode(&mut filtered, u32::MAX - 3);

        assert_eq!(filtered, original);
    }

    #[test]
    fn solid_encoder_emits_rar50_matches_against_previous_member_history() {
        let first = b"RAR5 solid shared phrase alpha beta gamma\n".repeat(16);
        let second = b"RAR5 solid shared phrase alpha beta gamma\nsecond\n".repeat(4);
        let solid = encode_lz_member_with_history(&second, &first, 0).unwrap();
        let standalone = encode_lz_member(&second, 0).unwrap();
        let mut decoder = Unpack50Decoder::new();

        assert_eq!(
            decoder
                .decode_member(
                    &encode_lz_member(&first, 0).unwrap(),
                    0,
                    first.len(),
                    false,
                    DecodeMode::Lz
                )
                .unwrap(),
            first
        );
        assert_eq!(
            decoder
                .decode_member(&solid, 0, second.len(), true, DecodeMode::Lz)
                .unwrap(),
            second
        );
        assert!(solid.len() < standalone.len());
    }

    #[test]
    fn large_lz_members_are_split_into_multiple_compressed_blocks() {
        let data = vec![0u8; LZ_BLOCK_SIZE + 1];
        let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap();
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let first = read_compressed_block(&mut cursor).unwrap();
        let second = read_compressed_block(&mut cursor).unwrap();
        let mut decoder = Unpack50Decoder::new();

        assert!(!first.header.is_last);
        assert!(second.header.is_last);
        assert_eq!(
            decoder
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    /// Words drawn from a small vocabulary in a repeating-but-not-periodic
    /// order. Every position has several matches at different distances and
    /// lengths, which is the case where taking the longest one and checking
    /// two bytes ahead leaves bits on the floor.
    fn wordy_text(len: usize) -> Vec<u8> {
        const WORDS: [&str; 12] = [
            "the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog ", "and ",
            "then ", "runs ", "away ",
        ];
        let mut out = Vec::with_capacity(len + 16);
        let mut noise = 0x2545_f491_4f6c_dd1du64;
        while out.len() < len {
            noise ^= noise << 13;
            noise ^= noise >> 7;
            noise ^= noise << 17;
            out.extend_from_slice(WORDS[(noise >> 40) as usize % WORDS.len()].as_bytes());
            if (noise >> 20).is_multiple_of(11) {
                out.push(b'\n');
            }
        }
        out.truncate(len);
        out
    }

    #[test]
    fn the_optimal_parse_round_trips() {
        for data in [
            Vec::new(),
            b"a".to_vec(),
            b"abcabcabcabc".to_vec(),
            wordy_text(3),
            wordy_text(LZ_BLOCK_SIZE + 4096),
            vec![0u8; LZ_BLOCK_SIZE * 2],
        ] {
            let options = EncodeOptions::new(64).with_optimal_parse(true);
            let encoded = encode_lz_member_with_options(&data, 0, options).unwrap();
            let decoded = Unpack50Decoder::new()
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap();
            assert_eq!(decoded, data, "{} bytes did not round trip", data.len());
        }
    }

    #[test]
    fn the_optimal_parse_beats_lazy_matching_at_the_same_depth() {
        let data = wordy_text(256 * 1024);
        let base = EncodeOptions::new(64);
        let lazy = encode_lz_member_with_options(
            &data,
            0,
            base.with_lazy_matching(true).with_lazy_lookahead(2),
        )
        .unwrap();
        let optimal =
            encode_lz_member_with_options(&data, 0, base.with_optimal_parse(true)).unwrap();

        assert!(
            optimal.len() < lazy.len(),
            "optimal parse packed {} against lazy matching's {}",
            optimal.len(),
            lazy.len(),
        );
    }

    #[test]
    fn repricing_against_the_first_pass_beats_the_flat_guess() {
        let data = wordy_text(256 * 1024);
        let options = EncodeOptions::new(64).with_optimal_parse(true);
        let distance_size = DISTANCE_TABLE_SIZE_50;
        let guessed = optimal_tokens(&data, 0, options, distance_size, None).unwrap();
        let lengths = table_lengths_for_tokens(&guessed, distance_size).unwrap();
        let prices = TokenPrices { lengths: &lengths };
        let repriced = optimal_tokens(&data, 0, options, distance_size, Some(&prices)).unwrap();

        let bits = |tokens: &[EncodeToken]| -> usize {
            let lengths = table_lengths_for_tokens(tokens, distance_size).unwrap();
            let prices = TokenPrices { lengths: &lengths };
            let mut state = EncoderMatchState::default();
            let mut total = 0;
            for token in tokens {
                match *token {
                    EncodeToken::Filter(_) => {}
                    EncodeToken::Literal(byte) => total += prices.literal(byte),
                    EncodeToken::Match { length, distance } => {
                        total += prices
                            .match_cost(&state, length, distance, distance_size)
                            .unwrap();
                        state.remember(length, distance);
                    }
                }
            }
            total
        };

        assert!(
            bits(&repriced) < bits(&guessed),
            "repriced {} bits against the guess's {}",
            bits(&repriced),
            bits(&guessed),
        );
    }

    #[test]
    fn blocks_are_short_enough_to_refit_the_tables_when_the_data_changes() {
        // Four stretches, one block each, every one drawing from its own
        // sixteen bytes. A table per block codes sixteen symbols; one table
        // over the member codes sixty-four. Raising LZ_BLOCK_SIZE trades the
        // first for the second, which is what cost the corpus 6.4% until the
        // block came down from a mebibyte.
        let stretch_len = 64 * 1024;
        let mut data = Vec::with_capacity(stretch_len * 4);
        let mut noise = 0x2545_f491_4f6c_dd1du64;
        for stretch in 0..4u8 {
            for _ in 0..stretch_len {
                noise ^= noise << 13;
                noise ^= noise >> 7;
                noise ^= noise << 17;
                data.push(stretch * 16 + (noise >> 40) as u8 % 16);
            }
        }
        let options = EncodeOptions::new(0);

        let blocked = encode_lz_member_with_options(&data, 0, options).unwrap();
        let single = encode_lz_block(&data, &[], 0, &[], options, true, None).unwrap();

        assert!(
            blocked.len() * 100 < single.len() * 90,
            "member blocks {} did not beat one block over the lot {single}",
            blocked.len(),
            single = single.len(),
        );
    }

    #[test]
    fn large_filtered_lz_members_split_filter_records_by_block() {
        let last_block_start = FILTERED_LZ_BLOCK_SIZE * 2;
        let mut data: Vec<_> = (0..last_block_start + 512)
            .map(|index| index as u8)
            .collect();
        data[256] = 0xe8;
        data[257..261].copy_from_slice(&0x20u32.to_le_bytes());
        data[last_block_start + 64] = 0xe8;
        data[last_block_start + 65..last_block_start + 69].copy_from_slice(&0x40u32.to_le_bytes());

        let encoded = Unpack50Encoder::with_options(EncodeOptions::new(0))
            .encode_member_with_filter(
                &data,
                0,
                crate::FilterSpec::range(crate::FilterKind::E8, 0..data.len()),
            )
            .unwrap();
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let first = read_compressed_block(&mut cursor).unwrap();
        let mut blocks = 1usize;
        let mut last_is_last = first.header.is_last;
        while cursor.position() < encoded.len() as u64 {
            last_is_last = read_compressed_block(&mut cursor).unwrap().header.is_last;
            blocks += 1;
        }
        let mut decoder = Unpack50Decoder::new();

        assert!(!first.header.is_last);
        assert!(last_is_last);
        assert!(blocks > 2);
        assert_eq!(
            decoder
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    #[test]
    fn filters_are_split_before_rar_reader_filter_limit() {
        let data = vec![0u8; FILTERED_LZ_BLOCK_SIZE + 1];
        let encoded = Unpack50Encoder::with_options(
            EncodeOptions::new(0).with_max_match_distance(128 * 1024),
        )
        .encode_member_with_filter(
            &data,
            0,
            crate::FilterSpec::whole(crate::FilterKind::Delta { channels: 4 }),
        )
        .unwrap();
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let first = read_compressed_block(&mut cursor).unwrap();
        let second = read_compressed_block(&mut cursor).unwrap();
        let mut decoder = Unpack50Decoder::new();

        assert!(!first.header.is_last);
        assert!(second.header.is_last);
        assert_eq!(
            decoder
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    #[test]
    fn solid_encoder_history_limit_follows_encode_options_dictionary() {
        let mut encoder = Unpack50Encoder::with_options(
            EncodeOptions::new(0).with_max_match_distance(DEFAULT_DICTIONARY_SIZE + 1024),
        );
        encoder.remember(&vec![0x41; DEFAULT_DICTIONARY_SIZE + 512]);

        assert_eq!(encoder.history.len(), DEFAULT_DICTIONARY_SIZE + 512);

        let mut capped =
            Unpack50Encoder::with_options(EncodeOptions::new(0).with_max_match_distance(1024));
        capped.remember(&vec![0x42; 4096]);

        assert_eq!(capped.history.len(), 1024);
    }

    #[test]
    fn encodes_lz_member_with_last_length_repeat_symbols() {
        let data = b"abcdXabcdYabcdZabcd";
        let input = encode_lz_member(data, 0).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[257], 0);
    }

    #[test]
    fn encodes_lz_member_using_rar70_distance_table_shape() {
        let data = b"RAR7-compatible repeated phrase repeated phrase repeated phrase";
        let input = encode_lz_member(data, 1).unwrap();

        let output = decode_lz(&input, 1, data.len()).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn decode_member_from_reader_accepts_incremental_input() {
        struct OneByteReader<'a> {
            data: &'a [u8],
            pos: usize,
        }

        impl Read for OneByteReader<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                out[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }

        let payload = literal_only_payload(b"ABBA");
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
        let mut reader = OneByteReader {
            data: &input,
            pos: 0,
        };
        let mut decoder = Unpack50Decoder::new();

        let output = decoder
            .decode_member_from_reader(&mut reader, 0, 4, false, DecodeMode::LiteralOnly)
            .unwrap();

        assert_eq!(output, b"ABBA");
    }

    #[test]
    fn decodes_synthetic_new_match_block() {
        let payload = new_match_payload();
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_lz(&input, 0, 4).unwrap();

        assert_eq!(output, b"ABAB");
    }

    #[test]
    fn decodes_synthetic_last_length_match_block() {
        let payload = repeat_payload(257);
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_lz(&input, 0, 6).unwrap();

        assert_eq!(output, b"ABABAB");
    }

    #[test]
    fn decodes_synthetic_repeat_distance_match_block() {
        let payload = repeat_payload(258);
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_lz(&input, 0, 6).unwrap();

        assert_eq!(output, b"ABABAB");
    }

    #[test]
    fn rejects_literal_only_block_without_tables() {
        let input = encode_compressed_block(&[0], 8, false, true).unwrap();

        assert_eq!(
            decode_literal_only(&input, 0, 1),
            Err(Error::InvalidData("RAR 5 block reuses missing tables"))
        );
    }

    #[test]
    fn decodes_length_slots() {
        assert_eq!(slot_to_length(0, 0).unwrap(), 2);
        assert_eq!(slot_to_length(7, 0).unwrap(), 9);
        assert_eq!(slot_to_length(8, 0).unwrap(), 10);
        assert_eq!(slot_to_length(8, 1).unwrap(), 11);
        assert_eq!(slot_to_length(11, 1).unwrap(), 17);
        assert_eq!(slot_to_length(12, 3).unwrap(), 21);
    }

    #[test]
    fn decodes_distance_slots() {
        assert_eq!(slot_to_distance(0, 0).unwrap(), 1);
        assert_eq!(slot_to_distance(3, 0).unwrap(), 4);
        assert_eq!(distance_slot_bit_count(4).unwrap(), 1);
        assert_eq!(slot_to_distance(4, 0).unwrap(), 5);
        assert_eq!(slot_to_distance(4, 1).unwrap(), 6);
        assert_eq!(distance_slot_bit_count(10).unwrap(), 4);
        assert_eq!(slot_to_distance(10, 15).unwrap(), 48);
    }

    #[test]
    fn bit_reader_accepts_large_rar5_distance_extras() {
        let mut bits = BitReader::new(&[0xff, 0x00, 0xaa, 0x55]);

        assert_eq!(bits.read_bits(32).unwrap(), 0xff00_aa55);
        assert_eq!(
            bits.read_bits(1),
            Err(Error::NeedMoreInput),
            "32-bit reads must not leave a partial cursor state"
        );
    }

    #[test]
    fn copies_lz_matches_with_overlap() {
        let decoder = Unpack50Decoder::new();
        let mut output = b"AB".to_vec();

        decoder
            .copy_match(&mut output, 2, 6, 8, DEFAULT_DICTIONARY_SIZE)
            .unwrap();

        assert_eq!(output, b"ABABABAB");
    }

    #[test]
    fn rejects_invalid_match_copy() {
        let decoder = Unpack50Decoder::new();
        let mut output = b"AB".to_vec();

        assert_eq!(
            decoder.copy_match(&mut output, 3, 1, 3, DEFAULT_DICTIONARY_SIZE),
            Err(Error::InvalidData("RAR 5 match distance exceeds window"))
        );
        assert_eq!(
            decoder.copy_match(&mut output, 1, 2, 3, DEFAULT_DICTIONARY_SIZE),
            Err(Error::InvalidData("RAR 5 match exceeds output limit"))
        );
    }

    #[test]
    fn rejects_match_distance_beyond_dictionary() {
        let decoder = Unpack50Decoder::new();
        let mut output = b"ABCD".to_vec();

        assert_eq!(
            decoder.copy_match(&mut output, 4, 1, 5, 3),
            Err(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary"
            ))
        );
    }

    #[test]
    fn solid_history_is_capped_to_dictionary_size() {
        let mut decoder = Unpack50Decoder::new();
        let first_payload = literal_only_payload(b"ABBA");
        let first =
            encode_compressed_block(&first_payload, first_payload.len() * 8, true, true).unwrap();
        let second_payload = literal_only_payload(b"BAAB");
        let second =
            encode_compressed_block(&second_payload, second_payload.len() * 8, true, true).unwrap();

        assert_eq!(
            decoder
                .decode_member_with_dictionary(&first, 0, 4, 6, false, DecodeMode::LiteralOnly)
                .unwrap(),
            b"ABBA"
        );
        assert_eq!(decoder.history, b"ABBA");

        assert_eq!(
            decoder
                .decode_member_with_dictionary(&second, 0, 4, 6, true, DecodeMode::LiteralOnly)
                .unwrap(),
            b"BAAB"
        );
        assert_eq!(decoder.history, b"BABAAB");
    }

    #[test]
    fn streaming_decoder_history_is_capped_without_reordering() {
        let mut decoder = Unpack50Decoder::new();
        let first_payload = literal_only_payload(b"ABBA");
        let first =
            encode_compressed_block(&first_payload, first_payload.len() * 8, true, true).unwrap();
        let second_payload = literal_only_payload(b"BAAB");
        let second =
            encode_compressed_block(&second_payload, second_payload.len() * 8, true, true).unwrap();
        let mut decoded = Vec::new();

        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut std::io::Cursor::new(&first),
                0,
                4,
                6,
                false,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.extend(std::iter::repeat_n(byte, len));
                        }
                    }
                    Ok::<(), std::io::Error>(())
                },
            )
            .unwrap();
        assert_eq!(decoded, b"ABBA");
        assert_eq!(decoder.history, b"ABBA");

        decoded.clear();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut std::io::Cursor::new(&second),
                0,
                4,
                6,
                true,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.extend(std::iter::repeat_n(byte, len));
                        }
                    }
                    Ok::<(), std::io::Error>(())
                },
            )
            .unwrap();
        assert_eq!(decoded, b"BAAB");
        assert_eq!(decoder.history, b"BABAAB");
    }

    #[test]
    fn streaming_window_accepts_match_beyond_old_64_mib_cap() {
        const OLD_STREAM_HISTORY_LIMIT: usize = 64 * 1024 * 1024;
        let distance = OLD_STREAM_HISTORY_LIMIT + 1;
        let history = vec![b'A'; distance];
        let mut output = StreamingOutput::new(history, 1, distance, distance);
        let mut decoded = Vec::new();

        output
            .copy_match(distance, 1, &mut |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::io::Error>(())
            })
            .unwrap();
        output
            .finish(&mut |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::io::Error>(())
            })
            .unwrap();

        assert_eq!(decoded, b"A");
    }

    #[test]
    fn streaming_window_rejects_match_beyond_declared_dictionary() {
        let mut output = StreamingOutput::new(vec![b'A'; 8], 1, 7, 8);

        assert!(matches!(
            output.copy_match(8, 1, &mut |_| Ok::<(), std::io::Error>(())),
            Err(StreamDecodeError::Decode(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary"
            )))
        ));
    }

    fn literal_only_payload(data: &[u8]) -> Vec<u8> {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 1;
        lengths.main[b'B' as usize] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter { bytes, bit_pos };
        for &byte in data {
            match byte {
                b'A' => writer.write_bits(0, 1),
                b'B' => writer.write_bits(1, 1),
                _ => panic!("test helper only encodes A/B"),
            }
        }
        writer.finish()
    }

    fn new_match_payload() -> Vec<u8> {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 2;
        lengths.main[b'B' as usize] = 2;
        lengths.main[262] = 2;
        lengths.distance[1] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter { bytes, bit_pos };

        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b10, 2); // match length 2
        writer.write_bits(0, 1); // distance slot 1
        writer.finish()
    }

    fn repeat_payload(repeat_symbol: usize) -> Vec<u8> {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 2;
        lengths.main[b'B' as usize] = 2;
        lengths.main[repeat_symbol] = 2;
        lengths.main[262] = 2;
        lengths.distance[1] = 1;
        lengths.length[0] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter { bytes, bit_pos };

        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b11, 2); // match length 2
        writer.write_bits(0, 1); // distance slot 1
        writer.write_bits(0b10, 2); // repeat control symbol
        if repeat_symbol == 258 {
            writer.write_bits(0, 1); // length slot 0
        }
        writer.finish()
    }
}
