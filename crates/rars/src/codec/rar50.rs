use super::filters::{self, DeltaErrorMessages};
use super::workspace::{Allowance, Budget, Buffer};
#[cfg(feature = "write")]
use super::{huffman, match_finder};
use super::{Error, Result};
use std::io::Read;
#[cfg(all(test, feature = "write"))]
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
#[cfg(feature = "write")]
const MAX_ENCODER_MATCH_OFFSET: usize = DEFAULT_DICTIONARY_SIZE;
#[cfg(feature = "write")]
const MAX_ENCODER_MATCH_LENGTH: usize = 4096;
/// The largest block the format allows a writer to emit.
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
pub(crate) const LZ_BLOCK_SIZE: usize = 64 * 1024;
#[cfg(feature = "write")]
const _: () = assert!(LZ_BLOCK_SIZE <= MAX_COMPRESSED_BLOCK_OUTPUT);

/// The most input one block may cover once blocks are being extended.
///
/// A block only grows over data whose byte distribution is not moving, so the
/// bytes it covers compress to very little and the output stays far inside
/// [`MAX_COMPRESSED_BLOCK_OUTPUT`]. The cap is what the writer charges its
/// workspace for, so it is a memory decision as much as a size one: the
/// optimal parse prices every position in a block and its arrays scale with
/// the block, so a mebibyte is the point where the extra table sets saved stop
/// being worth the pages.
#[cfg(feature = "write")]
pub(crate) const MAX_LZ_BLOCK_SIZE: usize = 1024 * 1024;
#[cfg(feature = "write")]
const _: () = assert!(MAX_LZ_BLOCK_SIZE <= MAX_COMPRESSED_BLOCK_OUTPUT);

/// How far a chunk's byte distribution may sit from the open block's before
/// the block is closed, as a fraction of the chunk.
///
/// The statistic is how many of the chunk's bytes the open block's model puts
/// in the wrong place, so the limit reads as "extend while under one in a
/// hundred and twenty-eight of the next chunk's bytes are distributed
/// differently". Measured over the bench corpus, per 64 KiB chunk:
///
/// ```text
/// class                       min   median      max
/// large-compressible            0        0        0
/// large-incompressible      3,243    3,751    5,133
/// large-source-tree         6,274   16,972   54,003
/// large-text                2,319   30,598   90,929
/// large-bin-unstripped     18,298   38,875  110,933
/// large-bin-stripped       13,982   60,996  113,086
/// ```
///
/// Only data that does not move at all falls under 512, and the nearest class
/// that does move sits four and a half times above it. That gap is the whole
/// design: a block grows over data a fresh table set could not describe any
/// better, and over nothing else.
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
pub(crate) struct BlockSplitter {
    counts: [u32; 256],
    total: u64,
}

#[cfg(feature = "write")]
impl Default for BlockSplitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "write")]
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
    pub(crate) fn extends(&self, chunk: &[u8]) -> bool {
        let open = self.total;
        if open == 0 || chunk.is_empty() {
            return false;
        }
        if open + chunk.len() as u64 > MAX_LZ_BLOCK_SIZE as u64 {
            return false;
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
        misplaced / open <= chunk_len / BLOCK_DRIFT_DIVISOR
    }
}
#[cfg(feature = "write")]
const MAX_FILTER_BLOCK_LENGTH: usize = 0x3ffff;
/// The most channels a RAR 5 delta filter record can name. The count is written
/// as five bits biased by one, so this is what the format can say, not a policy.
#[cfg(feature = "write")]
pub(crate) const MAX_DELTA_CHANNELS: usize = 32;
/// How much input goes into one compressed block once a filter is carried.
///
/// A filter record cannot describe more than [`MAX_FILTER_BLOCK_LENGTH`] bytes,
/// so this is the smaller of that ceiling and the plain block size. Splitting a
/// filtered range across blocks costs one more record per block and converts
/// the same bytes either way: the transform reads an absolute file offset, and
/// an instruction straddling a boundary was already left alone at the old
/// 256 KiB one.
#[cfg(feature = "write")]
const FILTERED_LZ_BLOCK_SIZE: usize = if LZ_BLOCK_SIZE < MAX_FILTER_BLOCK_LENGTH {
    LZ_BLOCK_SIZE
} else {
    MAX_FILTER_BLOCK_LENGTH
};
/// Where the encoder stops looking for anything better.
///
/// A search that has reached this far ends, whether it is a chain walk or a
/// tree descent, and the optimal parse takes the
/// match and steps over the bytes it covers instead of pricing each of them. The
/// second half matters more than it sounds. The parse prices every position in a
/// block, because a cheaper path can arrive at any of them, so without it a
/// 4 KiB match gets confirmed at all 4096 of its positions to learn what the
/// first one already said. On a mebibyte that repeats, that cost level 5
/// fifty-three seconds to save four bytes over level 3.
///
/// 512 is where committing is free. On a mebibyte of source at level 5 it packs
/// two bytes smaller than pricing every position and finishes in 7.08s rather
/// than 7.31s, and the repeating mebibyte drops to 1.19s. Committing sooner does
/// buy time, and it is not worth it: at 128 the source packs 0.16% larger for
/// 1.2x, at 64 it packs 0.47% larger for 1.5x, and neither closes the distance
/// to WinRAR.
#[cfg(feature = "write")]
const NICE_MATCH_LENGTH: usize = 512;

/// Matches shorter than 4 bytes are never emitted, so candidate positions are
/// chained by a hash of their first 4 bytes.
#[cfg(feature = "write")]
type Rar50MatchFinder<B = Allowance> = match_finder::MatchFinder<4, B>;
#[cfg(feature = "write")]
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

struct OwnedCompressedBlock<B: Budget = Allowance> {
    header: CompressedBlockHeader,
    payload: Buffer<u8, B>,
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

struct OwnedLengths<B: Budget = Allowance> {
    main: Buffer<u8, B>,
    distance: Buffer<u8, B>,
    align: Buffer<u8, B>,
    length: Buffer<u8, B>,
}

#[derive(Clone, Copy)]
#[cfg(feature = "write")]
struct LengthSlices<'a> {
    main: &'a [u8],
    distance: &'a [u8],
    align: &'a [u8],
    length: &'a [u8],
}
#[cfg(feature = "write")]
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
    // The size field is at most three bytes and the header at most five, so
    // this sum fits even on a 32-bit target.
    let payload_end = header_len + payload_size;
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

#[derive(Debug)]
struct ReaderTables<B: Budget> {
    main: HuffmanState<B>,
    distance: HuffmanState<B>,
    align: HuffmanState<B>,
    length: HuffmanState<B>,
    align_mode: bool,
}
impl<B: Budget> ReaderTables<B> {
    fn from_lengths(lengths: &OwnedLengths<B>, allowance: &B) -> Result<Self> {
        Ok(Self {
            main: HuffmanState::from_lengths(&lengths.main, allowance)?,
            distance: HuffmanState::from_lengths(&lengths.distance, allowance)?,
            align: HuffmanState::from_lengths(&lengths.align, allowance)?,
            length: HuffmanState::from_lengths(&lengths.length, allowance)?,
            align_mode: lengths
                .align
                .iter()
                .any(|&length| length != 0 && length != 4),
        })
    }
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            main: self.main.try_clone()?,
            distance: self.distance.try_clone()?,
            align: self.align.try_clone()?,
            length: self.length.try_clone()?,
            align_mode: self.align_mode,
        })
    }
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
    read_table_lengths_with_allowance(input, algorithm_version, &Allowance::default()).map(
        |(lengths, bits)| {
            (
                TableLengths {
                    main: lengths.main.into_vec(),
                    distance: lengths.distance.into_vec(),
                    align: lengths.align.into_vec(),
                    length: lengths.length.into_vec(),
                },
                bits,
            )
        },
    )
}

fn read_table_lengths_with_allowance<B: Budget>(
    input: &[u8],
    algorithm_version: u8,
    allowance: &B,
) -> Result<(OwnedLengths<B>, usize)> {
    let table_size = table_length_count(algorithm_version)?;
    let (level_lengths, level_bits) = read_level_lengths(input)?;
    let level_decoder = HuffmanState::from_lengths(&level_lengths, allowance)?;
    let mut bits = BitReader::new(input);
    bits.bit_pos = level_bits;

    let mut lengths = Buffer::with_capacity(table_size, allowance)?;
    while lengths.len() < table_size {
        let number = level_decoder.decode(&mut bits)?;
        match number {
            0..=15 => lengths.push_admitted(number as u8),
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
                    lengths.push_admitted(previous);
                }
            }
            _ => {
                // The level table has exactly 20 symbols, so these are 18/19.
                let count = if number == 18 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push_admitted(0);
                }
            }
        }
    }

    // table_length_count above rejects every version other than 0 and 1.
    let distance_size = if algorithm_version == 0 {
        DISTANCE_TABLE_SIZE_50
    } else {
        DISTANCE_TABLE_SIZE_70
    };
    let distance_start = MAIN_TABLE_SIZE;
    let align_start = distance_start + distance_size;
    let length_start = align_start + ALIGN_TABLE_SIZE;

    Ok((
        OwnedLengths {
            main: Buffer::copied(&lengths[..distance_start], allowance)?,
            distance: Buffer::copied(&lengths[distance_start..align_start], allowance)?,
            align: Buffer::copied(&lengths[align_start..length_start], allowance)?,
            length: Buffer::copied(&lengths[length_start..], allowance)?,
        },
        bits.bit_pos,
    ))
}

#[cfg(feature = "write")]
pub fn encode_table_lengths(lengths: &TableLengths, algorithm_version: u8) -> Result<Vec<u8>> {
    encode_table_lengths_with_bit_count(lengths, algorithm_version).map(|(data, _)| data)
}

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
pub fn encode_lz_member(data: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
    encode_lz_member_with_history(data, &[], algorithm_version)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "write")]
pub struct EncodeOptions {
    pub max_match_candidates: usize,
    pub lazy_matching: bool,
    pub lazy_lookahead: usize,
    pub max_match_distance: usize,
    pub optimal_parse: bool,
}

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new(MAX_MATCH_CANDIDATES)
    }
}

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
pub fn encode_lz_member_with_options(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_with_history_and_options(data, &[], algorithm_version, options)
}

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
pub(crate) fn encode_lz_member_with_options_and_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, &[], algorithm_version, options, Some(progress))
}

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
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
#[cfg(all(test, feature = "write"))]
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "write")]
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
            if !splitter.extends(&chunk[..wanted]) {
                held = Some(Buffer::copied(&chunk[..wanted], allowance)?);
                break;
            }
            splitter.accept(&chunk[..wanted]);
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

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
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

/// Encode adjacent streaming blocks with one seeded chain finder. The first
/// block without history keeps its existing tree parse; subsequent blocks use
/// chains just as separately seeded streaming blocks do.
#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
pub(crate) fn streaming_blocks_with_allowance<B: Budget>(
    data: &[u8],
    history: &[u8],
    blocks: &[(usize, bool)],
    algorithm_version: u8,
    options: EncodeOptions,
    mut block_done: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<Buffer<u8, B>, B>> {
    let mut previous = 0;
    for &(end, _) in blocks {
        if end <= previous || end > data.len() {
            return Err(Error::InvalidData("RAR 5 streaming block range is invalid"));
        }
        previous = end;
    }
    if previous != data.len() {
        return Err(Error::InvalidData(
            "RAR 5 streaming blocks do not cover input",
        ));
    }
    let (combined, start) = member_window_with_allowance(data, history, options, allowance)?;

    let mut at = start;
    let mut output = Buffer::with_capacity(blocks.len(), allowance)?;
    let mut first = 0;
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
    if start == 0 && options.optimal_parse && !blocks.is_empty() {
        let (end, is_last) = blocks[0];
        output.push_admitted(encode_lz_block_with_allowance(
            &combined[..end],
            0..end,
            MemberSearch::Fresh,
            algorithm_version,
            &[],
            options,
            is_last,
            None,
            allowance,
        )?);
        at = end;
        first = 1;
        if !report(end, &mut block_done) {
            return Err(Error::Cancelled);
        }
    }
    if first == blocks.len() {
        return Ok(output);
    }
    let finder = member_finder_with_allowance(&combined, at, options, allowance)?;
    let mut search = if options.optimal_parse {
        SharedMemberSearch::Optimal(OptimalCollector {
            finder: CollectorFinder::Chains(finder),
        })
    } else {
        SharedMemberSearch::Lazy(finder)
    };
    for &(end, is_last) in &blocks[first..] {
        let end = start + end;
        output.push_admitted(encode_lz_block_with_allowance(
            &combined,
            at..end,
            search.borrow(),
            algorithm_version,
            &[],
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

#[cfg(feature = "write")]
pub fn encode_lz_member_with_history_and_options(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, history, algorithm_version, options, None)
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
#[cfg(feature = "write")]
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
#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
pub(crate) fn filtered_lz_member(
    data: &[u8],
    filters: &[crate::FilterSpec],
) -> Result<(Vec<u8>, Vec<EncodeFilter>)> {
    filtered_member_with_allowance(data, filters, &Allowance::default())
        .map(|(data, records)| (data.into_vec(), records.into_vec()))
}
#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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
/// Blocks used to be compressed one at a time, each against a fresh copy of
/// the history behind it and a finder rebuilt from that copy. That is the
/// cost [`encode_lz_member_inner`] took off the unfiltered path and left
/// here: at 64 KiB a block, a four-megabyte member re-copied and re-inserted
/// 126 MiB of history, thirty-one times what it holds.
#[cfg(feature = "write")]
fn filtered_lz_blocks<B: Budget>(
    data: &[u8],
    filters: &[crate::FilterSpec],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let filters = normalized_filter_specs(data.len(), filters, allowance)?;
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let start = history.len();
    let mut combined = Buffer::from_slices(&[history, data], allowance)?;

    let mut blocks = Buffer::new(allowance);
    let mut chunk_start = 0usize;
    while chunk_start < data.len() {
        let chunk_end = (chunk_start + FILTERED_LZ_BLOCK_SIZE).min(data.len());
        let mut records = Buffer::new(allowance);
        for filter in filters.iter() {
            let filter_start = filter.range.start.max(chunk_start);
            let filter_end = filter.range.end.min(chunk_end);
            if filter_start >= filter_end {
                continue;
            }
            let (filter_type, channels) = encode_filter_data(
                filter.kind,
                &mut combined[start + filter_start..start + filter_end],
                filter_start,
                allowance,
            )?;
            records
                .push(EncodeFilter {
                    offset: filter_start - chunk_start,
                    length: filter_end - filter_start,
                    filter_type,
                    channels,
                })
                .map_err(Into::into)?;
        }
        blocks
            .push((chunk_start..chunk_end, records))
            .map_err(Into::into)?;
        chunk_start = chunk_end;
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
            block.end == data.len(),
            Some(&mut chunk_progress),
            allowance,
        )?;
        out.extend_from_slice(&packed).map_err(Into::into)?;
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "write")]
struct NormalizedFilterSpec {
    kind: Rar50Filter,
    range: Range<usize>,
}

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
pub(crate) fn filtered_owned_member<B: Budget>(
    data: &[u8],
    filters: &[crate::FilterSpec],
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    filtered_member_with_allowance(data, filters, allowance).map(|(bytes, _)| bytes)
}

#[cfg(feature = "write")]
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
        // One search state for the whole member. It used to be built per
        // block, which meant rehashing a window of history every 64 KiB: on a
        // 16 MiB member that was half the encode. The optimal parse used to be
        // worse still, rebuilding per pass; its collector searches each block
        // once and lets the passes replay the answers.
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
        let mut block_start = start;
        let mut splitter = BlockSplitter::new();
        while block_start < combined.len() {
            // Take one chunk, then keep taking them while the data is not
            // moving. See [`BlockSplitter`].
            splitter.reset();
            let mut block_end = (block_start + LZ_BLOCK_SIZE).min(combined.len());
            splitter.accept(&combined[block_start..block_end]);
            while block_end < combined.len() {
                let next_end = (block_end + LZ_BLOCK_SIZE).min(combined.len());
                let next = &combined[block_end..next_end];
                if !splitter.extends(next) {
                    break;
                }
                splitter.accept(next);
                block_end = next_end;
            }
            let is_last = block_end == combined.len();
            let mut chunk_progress = |position: usize| {
                progress
                    .as_deref_mut()
                    .is_none_or(|report| report(completed.saturating_add(position)))
            };
            let packed = encode_lz_block_with_allowance(
                combined,
                block_start..block_end,
                search.borrow(),
                algorithm_version,
                &[],
                options,
                is_last,
                Some(&mut chunk_progress),
                allowance,
            )?;
            out.extend_from_slice(&packed).map_err(Into::into)?;
            completed = completed.saturating_add(block_end - block_start);
            block_start = block_end;
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

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
fn finder_window(options: EncodeOptions, reach: usize) -> usize {
    options.max_match_distance.min(reach).max(LZ_BLOCK_SIZE)
}

/// A finder for the whole member, seeded with the history it carries in. It
/// keeps growing as the blocks are parsed, so it is sized to the widest window
/// the member could ever want rather than to any one block.
#[cfg(feature = "write")]
fn member_finder_with_allowance<B: Budget>(
    combined: &[u8],
    start: usize,
    options: EncodeOptions,
    allowance: &B,
) -> Result<Rar50MatchFinder<B>> {
    let mut finder =
        Rar50MatchFinder::with_allowance(finder_window(options, combined.len()), allowance)?;
    for pos in 0..start {
        finder.insert(combined, pos);
    }
    Ok(finder)
}

/// A finder holding everything a parse of `block` may reach back to, and
/// nothing older.
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
enum MemberSearch<'a, B: Budget = Allowance> {
    /// Nothing shared: the block builds what it needs and drops it.
    Fresh,
    /// The member's chain finder, which the lazy path feeds block by block.
    Lazy(&'a mut Rar50MatchFinder<B>),
    /// The member's match collector, which the optimal parse feeds block by
    /// block.
    Optimal(&'a mut OptimalCollector<B>),
}

#[cfg(feature = "write")]
enum SharedMemberSearch<B: Budget> {
    Lazy(Rar50MatchFinder<B>),
    Optimal(OptimalCollector<B>),
}

#[cfg(feature = "write")]
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
/// lengths creep up one byte at a time. That block cost three megabytes.
#[cfg(feature = "write")]
struct BlockMatches<B: Budget = Allowance> {
    /// Every position's runs, one position after another.
    runs: Buffer<(u32, u32), B>,
    /// Where each position's runs start in `runs`, with one extra entry to
    /// close the last position.
    starts: Buffer<u32, B>,
}

/// One match finder for a member's whole optimal parse, and the walk that asks
/// it about each block once.
///
/// The parse prices each block [`OPTIMAL_PARSE_PASSES`] times, but nothing the
/// finder answers depends on the prices, so it used to be asked the same
/// questions once per pass, through a finder rebuilt and reseeded once per
/// pass. Collecting the answers first and replaying them lets every pass after
/// the first skip the finder entirely.
///
/// Searching once is also what makes the tree finder affordable, and the tree
/// is where the speed is: pricing every position means searching at every
/// position, which is the load a chain walk carries worst and a tree carries
/// best. A member that starts with no history gets the tree. One that carries
/// history keeps the chains, because the only way into a tree is a descent per
/// position, and paying that across a dictionary of history would cost more
/// than the chains ever did.
#[cfg(feature = "write")]
struct OptimalCollector<B: Budget = Allowance> {
    finder: CollectorFinder<B>,
}

#[cfg(feature = "write")]
enum CollectorFinder<B: Budget = Allowance> {
    Tree(match_finder::TreeMatchFinder<B>),
    Chains(Rar50MatchFinder<B>),
}

#[cfg(feature = "write")]
impl OptimalCollector {
    #[cfg(all(test, feature = "write"))]
    fn new(combined: &[u8], start: usize, options: EncodeOptions) -> Self {
        Self::with_allowance(combined, start, options, &Allowance::default())
            .expect("unlimited collector allocation")
    }
}

#[cfg(feature = "write")]
impl<B: Budget> OptimalCollector<B> {
    fn with_allowance(
        combined: &[u8],
        start: usize,
        options: EncodeOptions,
        allowance: &B,
    ) -> Result<Self> {
        let finder = if start == 0 {
            CollectorFinder::Tree(match_finder::TreeMatchFinder::with_allowance(
                finder_window(options, combined.len()),
                allowance,
            )?)
        } else {
            CollectorFinder::Chains(member_finder_with_allowance(
                combined, start, options, allowance,
            )?)
        };
        Ok(Self { finder })
    }

    /// Finds the matches the parse will price at each position of `block`,
    /// taking the positions into the finder as it goes. Blocks must arrive in
    /// order, each exactly once, the same discipline the member's shared chain
    /// finder already asks of the lazy path.
    ///
    /// Searching stops where the parse stops pricing. A match that reaches
    /// [`NICE_MATCH_LENGTH`] is one the parse commits to and steps over, so the
    /// positions it covers are not searched from either. Skipping the pricing
    /// alone would have left the search doing all the work it used to: on a
    /// mebibyte that repeats, one search per 4 KiB became a million.
    fn collect(
        &mut self,
        combined: &[u8],
        block: std::ops::Range<usize>,
        options: EncodeOptions,
    ) -> Result<BlockMatches<B>> {
        let allowance = match &self.finder {
            CollectorFinder::Tree(finder) => finder.allowance(),
            CollectorFinder::Chains(finder) => finder.allowance(),
        };
        let span = block.end - block.start;
        let mut matches = BlockMatches {
            // One run per position to start with, which is where data that
            // matches at all lands, so the common case grows this once.
            runs: Buffer::with_capacity(span, &allowance)?,
            starts: Buffer::with_capacity(span + 1, &allowance)?,
        };
        // The first position past a match the parse will commit to. The parse
        // reaches the same decision from the same lengths, so the two agree on
        // which positions matter without having to be told.
        let mut committed_through = block.start;
        for pos in block.clone() {
            matches.starts.push_admitted(matches.runs.len() as u32);
            let searching = pos >= committed_through && options.max_match_candidates != 0;
            let max_distance = pos.min(options.max_match_distance);
            let before = matches.runs.len();
            match &mut self.finder {
                CollectorFinder::Tree(tree) => {
                    // Inserting into a tree is the same descent as searching
                    // it, so a position the parse steps over is stepped over
                    // here too rather than inserted for nothing. Its bytes are
                    // a copy of what the match already points at, so the tree
                    // loses little by not holding them.
                    let avail = combined.len() - pos;
                    if !searching || avail < 4 {
                        continue;
                    }
                    // Compares stop where the parse stops caring about better
                    // alternatives. A match that reaches that far is measured
                    // out to its real end, which is the length the parse
                    // commits to and steps over.
                    let len_limit = avail.min(NICE_MATCH_LENGTH);
                    tree.matches(
                        combined,
                        pos,
                        len_limit,
                        max_distance,
                        options.max_match_candidates,
                        &mut matches.runs,
                    )
                    .map_err(Into::into)?;
                    if let Some(last) = matches.runs[before..].last_mut() {
                        let limit = avail.min(MAX_ENCODER_MATCH_LENGTH);
                        if last.0 as usize == len_limit && len_limit < limit {
                            last.0 = match_length(combined, pos, last.1 as usize, limit) as u32;
                        }
                    }
                }
                CollectorFinder::Chains(finder) => {
                    // Inserting into a chain is one store, so every position
                    // goes in whether or not it is searched from. That keeps a
                    // solid member's candidates exactly what they were.
                    finder.insert(combined, pos);
                    let max_length = (block.end - pos).min(MAX_ENCODER_MATCH_LENGTH);
                    if !searching || max_distance == 0 || max_length < 4 {
                        continue;
                    }
                    // The chain walks nearest first, so the first distance to
                    // reach a length is the cheapest one that can.
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
                                matches
                                    .runs
                                    .push((length as u32, distance as u32))
                                    .map_err(Into::into)?;
                                longest = length;
                            }
                        }
                        if checked >= options.max_match_candidates {
                            break;
                        }
                        candidate = finder.previous(candidate);
                    }
                }
            }
            // The parse can only take a match the block still has room for, so
            // the reach it will commit to is measured the way it measures it.
            if let Some(&(length, _)) = matches.runs[before..].last() {
                let reach = (length as usize)
                    .min(block.end - pos)
                    .min(MAX_ENCODER_MATCH_LENGTH);
                if reach >= NICE_MATCH_LENGTH {
                    committed_through = pos + reach;
                }
            }
        }
        matches.starts.push_admitted(matches.runs.len() as u32);
        Ok(matches)
    }
}

/// The bytes one member's parse reaches across, and where its own data starts.
///
/// A member with no history to carry borrows its own data rather than copying
/// it, which is every member of a non-solid archive.
#[cfg(feature = "write")]
enum MemberWindow<'a, B: Budget> {
    Borrowed(&'a [u8]),
    Owned(Buffer<u8, B>),
}
#[cfg(feature = "write")]
impl<B: Budget> std::ops::Deref for MemberWindow<'_, B> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,
            Self::Owned(data) => data,
        }
    }
}
#[cfg(feature = "write")]
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
#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
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
#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
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
            CollectorFinder::Tree(finder) => finder.allowance(),
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
#[cfg(feature = "write")]
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
    let mut tokens = encode_tokens_with_allowance(
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

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
fn encode_token_block_with_allowance<B: Budget>(
    tokens: &[EncodeToken],
    algorithm_version: u8,
    distance_size: usize,
    is_last: bool,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let lengths = table_lengths_with_allowance(tokens, &[], distance_size, allowance)?;

    let main_table = EncoderCodeTable::from_lengths(&lengths.main, allowance)?;
    let distance_table = EncoderCodeTable::from_lengths(&lengths.distance, allowance)?;
    let align_table = EncoderCodeTable::from_lengths(&lengths.align, allowance)?;
    let length_table = EncoderCodeTable::from_lengths(&lengths.length, allowance)?;
    let (table_data, table_bits) =
        encode_table_slices(lengths.slices(), algorithm_version, allowance)?;
    let payload_bits =
        token_stream_bits_after_tables(tokens, &[], &lengths, distance_size, table_bits)?;
    let mut writer = BitWriter {
        bytes: table_data,
        bit_pos: table_bits,
    };
    writer
        .bytes
        .reserve_total_capacity(payload_bits.div_ceil(8))?;
    let mut state = EncoderMatchState::default();
    for &token in tokens {
        match token {
            EncodeToken::Filter(filter) => {
                let (code, len) = main_table.code_for_present_symbol(256);
                writer.write_admitted_bits(usize::from(code), usize::from(len));
                // token_stream_bits_after_tables validated this same record
                // before its exact payload allocation was admitted.
                write_valid_filter(&mut writer, filter);
            }
            EncodeToken::Literal(byte) => {
                let (code, len) = main_table.code_for_present_symbol(byte as usize);
                writer.write_admitted_bits(usize::from(code), usize::from(len));
            }
            EncodeToken::Match { length, distance } => {
                match state.encode_valid_match(length, distance, distance_size) {
                    EncodedMatch::LastLengthRepeat => {
                        let (code, len) = main_table.code_for_present_symbol(257);
                        writer.write_admitted_bits(usize::from(code), usize::from(len));
                    }
                    EncodedMatch::RepeatDistance {
                        index,
                        length_slot,
                        length_extra,
                    } => {
                        let (code, len) = main_table.code_for_present_symbol(258 + index);
                        writer.write_admitted_bits(usize::from(code), usize::from(len));
                        let (code, len) = length_table.code_for_present_symbol(length_slot);
                        writer.write_admitted_bits(usize::from(code), usize::from(len));
                        let length_extra_bits = length_slot_extra_bits(length_slot);
                        if length_extra_bits != 0 {
                            writer
                                .write_admitted_bits(length_extra, usize::from(length_extra_bits));
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
                        writer.write_admitted_bits(usize::from(code), usize::from(len));
                        let length_extra_bits = length_slot_extra_bits(length_slot);
                        if length_extra_bits != 0 {
                            writer
                                .write_admitted_bits(length_extra, usize::from(length_extra_bits));
                        }
                        let (code, len) = distance_table.code_for_present_symbol(distance_slot);
                        writer.write_admitted_bits(usize::from(code), usize::from(len));
                        if distance_bit_count >= 4 {
                            if distance_bit_count > 4 {
                                writer.write_admitted_bits(
                                    distance_extra >> 4,
                                    distance_bit_count - 4,
                                );
                            }
                            let (code, len) =
                                align_table.code_for_present_symbol(distance_extra & 0x0f);
                            writer.write_admitted_bits(usize::from(code), usize::from(len));
                        } else if distance_bit_count != 0 {
                            writer.write_admitted_bits(distance_extra, distance_bit_count);
                        }
                    }
                }
                state.remember(length, distance);
            }
        }
    }

    debug_assert_eq!(writer.bit_pos, payload_bits);
    encode_compressed_block_with_allowance(&writer.bytes, payload_bits, true, is_last, allowance)
}

#[derive(Debug)]
#[cfg(feature = "write")]
struct EncoderState<B: Budget> {
    history: Buffer<u8, B>,
    options: EncodeOptions,
}
#[cfg(feature = "write")]
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
            Some(filters) if input.len() > FILTERED_LZ_BLOCK_SIZE => filtered_lz_blocks(
                input,
                filters,
                &self.history,
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
#[cfg(feature = "write")]
pub struct Unpack50Encoder {
    state: EncoderState<Allowance>,
}
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
impl Default for Unpack50Encoder {
    fn default() -> Self {
        Self::with_options(EncodeOptions::default())
    }
}
#[cfg(feature = "write")]
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
    #[cfg(all(test, feature = "write"))]
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
#[cfg(feature = "write")]
enum EncodeToken {
    Filter(EncodeFilter),
    Literal(u8),
    Match { length: usize, distance: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "write")]
pub(crate) struct EncodeFilter {
    offset: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

#[derive(Debug, Clone, Copy, Default)]
#[cfg(feature = "write")]
struct EncoderMatchState {
    reps: [usize; 4],
    last_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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
#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
fn table_lengths_for_tokens(tokens: &[EncodeToken], distance_size: usize) -> Result<OwnedLengths> {
    table_lengths_with_filters(tokens, &[], distance_size)
}

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
fn table_lengths_with_filters(
    tokens: &[EncodeToken],
    filters: &[EncodeFilter],
    distance_size: usize,
) -> Result<OwnedLengths> {
    table_lengths_with_allowance(tokens, filters, distance_size, &Allowance::default())
}

#[cfg(feature = "write")]
fn table_lengths_with_allowance<B: Budget>(
    tokens: &[EncodeToken],
    filters: &[EncodeFilter],
    distance_size: usize,
    allowance: &B,
) -> Result<OwnedLengths<B>> {
    let mut main_frequencies = Buffer::filled(MAIN_TABLE_SIZE, 0usize, allowance)?;
    main_frequencies[256] = filters.len();
    let mut distance_frequencies = Buffer::filled(distance_size, 0usize, allowance)?;
    let mut align_frequencies = Buffer::filled(ALIGN_TABLE_SIZE, 0usize, allowance)?;
    let mut length_frequencies = Buffer::filled(LENGTH_TABLE_SIZE, 0usize, allowance)?;
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

    Ok(OwnedLengths {
        main: huffman::complete_lengths_with_allowance(&main_frequencies, 15, allowance)?,
        distance: huffman::complete_lengths_with_allowance(&distance_frequencies, 15, allowance)?,
        align: huffman::complete_lengths_with_allowance(&align_frequencies, 15, allowance)?,
        length: huffman::complete_lengths_with_allowance(&length_frequencies, 15, allowance)?,
    })
}

/// Actual payload size, including the transmitted tables and filter records.
/// Padding and block-header size are monotonic in this bit count.
#[cfg(feature = "write")]
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
    token_stream_bits_after_tables(tokens, filters, lengths, distance_size, bits)
}

#[cfg(feature = "write")]
fn token_stream_bits_after_tables<B: Budget>(
    tokens: &[EncodeToken],
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
        .chain(tokens.iter().copied())
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

#[cfg(feature = "write")]
struct OptimalWorkspace<B: Budget = Allowance> {
    price: Buffer<u32, B>,
    arrive_length: Buffer<u32, B>,
    arrive_distance: Buffer<u32, B>,
    arrive_reps: Buffer<[u32; 4], B>,
    arrive_last_length: Buffer<u32, B>,
}
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
const ESTIMATED_LITERAL_COST: u32 = 9;

/// How many times the optimal parse runs over a block. The first pass guesses
/// prices; the rest reprice against the tables the pass before produced.
#[cfg(feature = "write")]
const OPTIMAL_PARSE_PASSES: usize = 3;

/// What a symbol the first pass never used is assumed to cost. Reaching for
/// one is not forbidden, only expensive: the tables are rebuilt from whatever
/// the last pass chose, so a symbol that earns its place gets a real code.
#[cfg(feature = "write")]
const UNUSED_SYMBOL_COST: usize = 15;

/// Prices a token against the code lengths a previous pass produced, which is
/// what the block will really spend, rather than against the flat guess in
/// [`estimated_match_cost`].
#[cfg(feature = "write")]
struct TokenPrices<'a> {
    lengths: LengthSlices<'a>,
}

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
fn price_optimal_paths(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    runs: &[(u32, u32)],
    starts: &[u32],
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
    // The first position past a match the parse committed to. Nothing is
    // priced from the positions before it. See [`NICE_MATCH_LENGTH`].
    let mut committed_through = 0usize;

    for index in 0..span {
        let pos = start + index;
        if index < committed_through {
            continue;
        }
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
            // A literal emits no distance, so it leaves the remembered ones
            // exactly as it found them.
            arrive_reps[index + 1] = arrive_reps[index];
            arrive_last_length[index + 1] = arrive_last_length[index];
        }

        let max_distance = pos.min(options.max_match_distance);
        let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        if options.max_match_candidates == 0 || max_distance == 0 || max_length < 4 {
            continue;
        }

        let state = EncoderMatchState {
            reps: arrive_reps[index].map(|distance| distance as usize),
            last_length: arrive_last_length[index] as usize,
        };

        let mut reaches_len = 0;
        let mut longest = 0usize;

        // A match at a remembered distance is priced out of the main table
        // alone, a handful of bits against twenty for a fresh distance, so it
        // earns its place even when it is shorter than anything the collector
        // found. The collector only reports a candidate that beats the longest
        // found so far, so these have to be asked for separately.
        for repeat in state.reps {
            if repeat == 0 || repeat > max_distance {
                continue;
            }
            let length = match_length(combined, pos, repeat, max_length);
            if length >= 4 {
                reaches[reaches_len] = (4, length, repeat);
                reaches_len += 1;
            }
        }

        // The collector reports nearest first, so the first distance to reach
        // a length is the cheapest one that can. Each report that improves on
        // the longest so far owns one run of lengths. The tree measures
        // against the whole member where the chains stopped at the block, so
        // a length is capped here to what this block can still hold.
        for &(length, distance) in &runs[starts[index] as usize..starts[index + 1] as usize] {
            let length = (length as usize).min(max_length);
            if length > longest {
                reaches[reaches_len] = (longest + 1, length, distance as usize);
                reaches_len += 1;
                longest = length;
            }
        }

        let reaches = &reaches[..reaches_len];

        // Equal token prices do not make shorter matches redundant: their
        // endpoints can expose a better continuation. Price every endpoint
        // unless the explicit long-match heuristic commits past all of them.
        let committed_reach = reaches
            .iter()
            .map(|&(_, end, _)| end)
            .max()
            .filter(|&length| length >= NICE_MATCH_LENGTH);
        for &(run_start, run_end, distance) in reaches.iter() {
            let mut length = run_start.max(4);
            if let Some(committed) = committed_reach {
                if run_end < committed {
                    continue;
                }
                length = committed;
            }
            while length <= run_end {
                let reach = length;
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
                        let mut next = state;
                        next.remember(reach, distance);
                        arrive_reps[target] = next.reps.map(|distance| distance as u32);
                        arrive_last_length[target] = next.last_length as u32;
                    }
                }
                length = reach + 1;
            }
        }

        // A committed match is at least 512 bytes long. Even after the
        // distance bonus, that length and every collected u32 distance fit
        // their encoder tables, so the endpoint has already been priced.
        let longest_reach = reaches.iter().map(|&(_, length, _)| length).max();
        if let Some(reach) = longest_reach {
            if reach >= NICE_MATCH_LENGTH {
                committed_through = index + reach;
            }
        }
    }
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
#[cfg(feature = "write")]
fn optimal_tokens_in_workspace<B: Budget>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    options: EncodeOptions,
    distance_size: usize,
    prices: Option<&TokenPrices<'_>>,
    matches: &BlockMatches<B>,
    workspace: &mut OptimalWorkspace<B>,
) -> Result<Buffer<EncodeToken, B>> {
    let start = block.start;
    let end = block.end;
    let span = end - start;

    let allowance = workspace.price.allowance().clone();
    let OptimalWorkspace {
        price,
        arrive_length,
        arrive_distance,
        arrive_reps,
        arrive_last_length,
    } = workspace;
    price.resize(span + 1, u32::MAX)?;
    price.fill(u32::MAX);
    arrive_length.resize(span + 1, 0)?;
    arrive_length.fill(0);
    arrive_distance.resize(span + 1, 0)?;
    arrive_distance.fill(0);
    arrive_reps.resize(span + 1, [0; 4])?;
    arrive_reps.fill([0; 4]);
    arrive_last_length.resize(span + 1, 0)?;
    arrive_last_length.fill(0);
    price[0] = 0;

    // Admit the largest candidate list once. Pricing only borrows already
    // charged arrays, so its inner loop is identical for both budget policies.
    // Each position contributes at most four remembered-distance candidates.
    let longest_run = matches
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
        &matches.runs,
        &matches.starts,
        OptimalSlices {
            price,
            arrive_length,
            arrive_distance,
            arrive_reps,
            arrive_last_length,
        },
        &mut reaches,
    );

    let mut reversed = Buffer::new(&allowance);
    let mut index = span;
    while index > 0 {
        let length = arrive_length[index] as usize;
        if length == 0 {
            reversed
                .push(EncodeToken::Literal(combined[start + index - 1]))
                .map_err(Into::into)?;
            index -= 1;
        } else {
            reversed
                .push(EncodeToken::Match {
                    length,
                    distance: arrive_distance[index] as usize,
                })
                .map_err(Into::into)?;
            index -= length;
        }
    }
    reversed.reverse();
    Ok(reversed)
}

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
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
            CollectorFinder::Tree(finder) => finder.allowance().clone(),
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

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "write")]
fn encode_tokens_with_allowance<B: Budget>(
    combined: &[u8],
    block: std::ops::Range<usize>,
    search: MemberSearch<'_, B>,
    options: EncodeOptions,
    distance_size: usize,
    initial_filters: &[EncodeFilter],
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    allowance: &B,
) -> Result<Buffer<EncodeToken, B>> {
    let start = block.start;
    let end = block.end;
    if options.optimal_parse {
        let mut own;
        let collector = match search {
            MemberSearch::Optimal(collector) => collector,
            _ => {
                own = OptimalCollector::with_allowance(combined, start, options, allowance)?;
                &mut own
            }
        };
        let matches = collector.collect(combined, block.clone(), options)?;
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
            &matches,
            &mut workspace,
        )?;
        let mut lengths =
            table_lengths_with_allowance(&tokens, initial_filters, distance_size, allowance)?;
        let mut best_bits = token_stream_bits(&tokens, initial_filters, &lengths, distance_size)?;
        let mut best = None;
        for _ in 1..OPTIMAL_PARSE_PASSES {
            let prices = TokenPrices {
                lengths: lengths.slices(),
            };
            let next = optimal_tokens_in_workspace(
                combined,
                block.clone(),
                options,
                distance_size,
                Some(&prices),
                &matches,
                &mut workspace,
            )?;
            if next == tokens {
                break;
            }
            lengths =
                table_lengths_with_allowance(&next, initial_filters, distance_size, allowance)?;
            let bits = token_stream_bits(&next, initial_filters, &lengths, distance_size)?;
            if bits < best_bits {
                best_bits = bits;
                best = None;
            } else if best.is_none() {
                // Keep an earlier winner only when repricing actually loses.
                best = Some(std::mem::replace(&mut tokens, Buffer::new(allowance)));
            }
            tokens = next;
        }
        let tokens = best.unwrap_or(tokens);
        if progress.is_some_and(|report| !report(end - start)) {
            return Err(Error::Cancelled);
        }
        return Ok(tokens);
    }

    let mut own;
    let finder = match search {
        MemberSearch::Lazy(finder) => finder,
        _ => {
            own = seeded_finder(combined, start..end, options, allowance)?;
            &mut own
        }
    };
    let mut tokens = Buffer::new(allowance);
    let mut pos = start;
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    let mut pending_match: Option<MatchCandidate> = None;
    while pos < end {
        let candidate = pending_match
            .take()
            .or_else(|| best_match(combined, pos, end, finder, options, &state, distance_size));
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
            );
            if emit_literal {
                tokens
                    .push(EncodeToken::Literal(combined[pos]))
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
                .push(EncodeToken::Match { length, distance })
                .map_err(Into::into)?;
            state.remember(length, distance);
            for history_pos in pos..pos + length {
                finder.insert(combined, history_pos);
            }
            pos += length;
        } else {
            tokens
                .push(EncodeToken::Literal(combined[pos]))
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

/// Decides whether a literal should be emitted instead of `current` because a
/// better match starts within the lazy lookahead window. Also returns the
/// match found one byte ahead (when computed) so the caller can reuse it for
/// the next position instead of searching again.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "write")]
fn lazy_match_decision<B: Budget>(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar50MatchFinder<B>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    current: MatchCandidate,
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
#[cfg(feature = "write")]
struct MatchCandidate {
    length: usize,
    distance: usize,
    score: isize,
}

#[cfg(feature = "write")]
fn best_match<B: Budget>(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar50MatchFinder<B>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
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
        if best.length == max_length || best.length >= NICE_MATCH_LENGTH {
            return Some(best);
        }
    }
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

#[cfg(feature = "write")]
fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    super::fast::match_length(input, pos, distance, max_length)
}

#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 2 {
        return Err(Error::InvalidData("RAR 5 match length is too short"));
    }
    Ok(length_slot_for_valid_match(length))
}

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
fn distance_slot_bit_count_valid(slot: usize) -> usize {
    if slot < 4 {
        0
    } else {
        (slot - 2) >> 1
    }
}

#[cfg(feature = "write")]
fn literal_presence(data: &[u8]) -> [bool; 256] {
    let mut present = [false; 256];
    for &byte in data {
        present[byte as usize] = true;
    }
    present
}

#[derive(Debug)]
pub struct Unpack50Decoder {
    pub(crate) read_control: crate::read_control::ReadControl,
    state: ReaderState<Allowance>,
}
impl Clone for Unpack50Decoder {
    fn clone(&self) -> Self {
        Self {
            read_control: self.read_control.clone(),
            state: self.state.try_clone().expect("unlimited decoder copy"),
        }
    }
}
impl Unpack50Decoder {
    pub fn new() -> Self {
        Self {
            read_control: crate::read_control::ReadControl::default(),
            state: ReaderState::new(&Allowance::default()),
        }
    }
    #[cfg(all(test, feature = "write"))]
    fn copy_match(
        &self,
        output: &mut Vec<u8>,
        distance: usize,
        length: usize,
        output_limit: usize,
        dictionary_size: usize,
    ) -> Result<()> {
        let mut owned = Buffer::from_vec(std::mem::take(output));
        let result =
            self.state
                .copy_match(&mut owned, distance, length, output_limit, dictionary_size);
        *output = owned.into_vec();
        result
    }
    pub fn decode_member(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member(input, algorithm_version, output_size, solid, mode)
            .map(Buffer::into_vec)
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
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member_with_dictionary(
                input,
                algorithm_version,
                output_size,
                dictionary_size,
                solid,
                mode,
            )
            .map(Buffer::into_vec)
    }
    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member_from_reader(input, algorithm_version, output_size, solid, mode)
            .map(Buffer::into_vec)
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
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member_from_reader_with_dictionary(
                input,
                algorithm_version,
                output_size,
                dictionary_size,
                solid,
                mode,
            )
            .map(Buffer::into_vec)
    }
    pub fn decode_member_from_reader_with_dictionary_to_sink<E>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member_from_reader_with_dictionary_to_sink(
                input,
                algorithm_version,
                output_size,
                dictionary_size,
                solid,
                sink,
            )
    }
    #[cfg(all(test, feature = "write"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_to_sink_with_filters<E>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
        filters: Option<&mut dyn FnMut(PendingFilter) -> std::result::Result<(), E>>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.state.read_control = self.read_control.clone();
        self.state.decode_to_sink_with_filters(
            input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            sink,
            filters,
        )
    }
}

#[derive(Debug)]
pub(crate) struct ReaderState<B: Budget> {
    pub(crate) read_control: crate::read_control::ReadControl,
    tables: Option<ReaderTables<B>>,
    reps: [usize; 4],
    last_length: usize,
    history: Buffer<u8, B>,
}

impl<B: Budget> ReaderState<B> {
    pub(crate) fn allowance(&self) -> B {
        self.history.allowance()
    }
    pub(crate) fn new(allowance: &B) -> Self {
        Self {
            read_control: crate::read_control::ReadControl::default(),
            tables: None,
            reps: [0; 4],
            last_length: 0,
            history: Buffer::new(allowance),
        }
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            read_control: self.read_control.clone(),
            tables: self
                .tables
                .as_ref()
                .map(ReaderTables::try_clone)
                .transpose()?,
            reps: self.reps,
            last_length: self.last_length,
            history: Buffer::copied(&self.history, &self.history.allowance())?,
        })
    }
    pub fn decode_member(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
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
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
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
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
        let control = self.read_control.clone();
        let input = &mut control.reader(input);
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
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
        let control = self.read_control.clone();
        let input = &mut control.reader(input);
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero"));
        }
        if !solid {
            self.reset();
        }

        let allowance = self.history.allowance();
        let mut output =
            Buffer::with_capacity(output_size.min(MAX_INITIAL_OUTPUT_CAPACITY), &allowance)?;
        let mut filters = Buffer::new(&allowance);

        loop {
            let block = read_compressed_block_with_allowance(input, &self.history.allowance())?;
            let payload = &*block.payload;
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths_with_allowance(
                    payload,
                    algorithm_version,
                    &block.payload.allowance(),
                )?;
                self.tables = Some(ReaderTables::from_lengths(
                    &lengths,
                    &block.payload.allowance(),
                )?);
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new(payload);
            bits.bit_pos = payload_bit_pos;

            let mut poller = self.read_control.poller();
            while bits.bit_pos < block.header.payload_bits && output.len() < output_size {
                poller.check_codec(output.len())?;
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => output.try_push(symbol as u8)?,
                    256 if mode.uses_lz() => {
                        filters.try_push(read_filter(&mut bits, output.len())?)?;
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
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
                        // The length table has 44 symbols and read_bits limits
                        // the extra value to this slot's declared width.
                        let length = length_from_slot_parts(length_slot, length_extra);
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
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
                        // Main symbols end at slot 43 and read_bits limits the
                        // extra value to this slot's declared width.
                        let mut length = length_from_slot_parts(length_slot, length_extra);
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        // distance_slot_bit_count rejected slots above 65 and
                        // the extra value was read at exactly that width.
                        let distance = distance_from_slot_parts(
                            distance_slot,
                            distance_bit_count,
                            distance_extra,
                        );
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
                    _ => {
                        return Err(Error::InvalidData(
                            "RAR 5 literal-only decoder encountered non-literal symbol",
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
                Some(Buffer::copied(
                    &output[output.len().saturating_sub(dictionary_size)..],
                    &allowance,
                )?)
            } else {
                None
            };
            if mode.applies_filters() {
                self.read_control.check_codec()?;
                apply_filters_with_allowance(
                    &mut output,
                    &filters,
                    &self.read_control,
                    &allowance,
                )?;
            }
            self.remember_history(
                history_output.as_deref().unwrap_or(&output),
                dictionary_size,
            )?;
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
        sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.decode_to_sink_with_filters(
            input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            sink,
            None,
        )
    }

    // Mirrors the public streaming entry point, adding a filter-record destination.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_to_sink_with_filters<E>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mut sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
        mut filters: Option<&mut dyn FnMut(PendingFilter) -> std::result::Result<(), E>>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.read_control.check_codec()?;
        let control = self.read_control.clone();
        let input = &mut control.reader(input);
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
            self.history.discard_prefix(discard);
        }
        let mut output = StreamingOutput::new(
            {
                let allowance = self.history.allowance();
                std::mem::replace(&mut self.history, Buffer::new(&allowance))
            },
            output_size,
            dictionary_size,
            history_limit,
        )?;

        loop {
            let block = read_compressed_block_with_allowance(input, &output.history.allowance())?;
            let payload = &*block.payload;
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths_with_allowance(
                    payload,
                    algorithm_version,
                    &block.payload.allowance(),
                )?;
                self.tables = Some(ReaderTables::from_lengths(
                    &lengths,
                    &block.payload.allowance(),
                )?);
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new(payload);
            bits.bit_pos = payload_bit_pos;

            let mut poller = self.read_control.poller();
            while bits.bit_pos < block.header.payload_bits && output.written() < output_size {
                poller.check_codec(output.written())?;
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => output.push(symbol as u8, &mut sink)?,
                    256 => {
                        let Some(filters) = filters.as_mut() else {
                            return Err(StreamDecodeError::FilteredMember);
                        };
                        let filter = read_filter(&mut bits, output.written())?;
                        if filter
                            .start
                            .checked_add(filter.length)
                            .is_none_or(|end| end > output_size)
                        {
                            return Err(
                                Error::InvalidData("RAR 5 filter range exceeds output").into()
                            );
                        }
                        filters(filter).map_err(StreamDecodeError::Sink)?;
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
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
                        // The length table has 44 symbols and read_bits limits
                        // the extra value to this slot's declared width.
                        let length = length_from_slot_parts(length_slot, length_extra);
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        output.copy_match(distance, length, &mut sink)?;
                    }
                    262.. => {
                        let length_slot = symbol - 262;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
                        // Main symbols end at slot 43 and read_bits limits the
                        // extra value to this slot's declared width.
                        let mut length = length_from_slot_parts(length_slot, length_extra);
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        // distance_slot_bit_count rejected slots above 65 and
                        // the extra value was read at exactly that width.
                        let distance = distance_from_slot_parts(
                            distance_slot,
                            distance_bit_count,
                            distance_extra,
                        );
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

    fn remember_history(&mut self, output: &[u8], dictionary_size: usize) -> Result<()> {
        let incoming = &output[output.len().saturating_sub(dictionary_size)..];
        let keep = self.history.len().min(dictionary_size - incoming.len());
        let required = keep + incoming.len();
        if self.history.capacity() > dictionary_size || self.history.capacity() < required {
            // Allocate only the retained tail, never the whole member. Replace
            // oversized storage when the active dictionary shrinks as well.
            let capacity =
                reader_history_capacity(self.history.capacity(), required, dictionary_size);
            let mut history = Buffer::with_capacity(capacity, &self.history.allowance())?;
            history
                .extend_from_slice(&self.history[self.history.len() - keep..])
                .map_err(Into::into)?;
            history.extend_from_slice(incoming).map_err(Into::into)?;
            self.history = history;
        } else {
            self.history.discard_prefix(self.history.len() - keep);
            self.history
                .extend_from_slice(incoming)
                .map_err(Into::into)?;
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.last_length = 0;
        self.history.clear();
    }

    fn copy_match(
        &self,
        output: &mut Buffer<u8, B>,
        distance: usize,
        length: usize,
        output_limit: usize,
        dictionary_size: usize,
    ) -> Result<()> {
        if output
            .len()
            .checked_add(length)
            .is_none_or(|end| end > output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit"));
        }
        // A match reaching past the start of the window writes zeroes rather
        // than failing. WinRAR never clears its window and guards the copy
        // with a first-wrap flag instead, so those bytes read as zero there,
        // and an archive that leans on it stays readable here. Nothing is
        // swallowed: a stream that is damaged rather than merely odd still
        // fails its file hash.
        if distance == 0
            || distance > dictionary_size
            || distance > self.history.len() + output.len()
        {
            output.resize(output.len() + length, 0)?;
            return Ok(());
        }
        let mut remaining = length;
        while remaining > 0 {
            if distance <= output.len() {
                // The match lies entirely in already-decoded output: copy in
                // runs rather than one byte at a time.
                if distance == 1 {
                    // A one-byte repeat is a fill, not a copy.
                    let b = output[output.len() - 1];
                    output.resize(output.len() + remaining, b)?;
                    remaining = 0;
                } else {
                    let start = output.len() - distance;
                    let take = remaining.min(distance);
                    output.extend_from_within(start..start + take)?;
                    remaining -= take;
                }
            } else {
                let history_distance = distance - output.len();
                let index = self.history.len() - history_distance;
                let take = remaining.min(history_distance);
                output
                    .extend_from_slice(&self.history[index..index + take])
                    .map_err(Into::into)?;
                remaining -= take;
            }
        }
        Ok(())
    }
}

// Preserve amortized growth without letting a retained dictionary allocation
// grow to the member size or keep a previous, larger dictionary alive.
fn reader_history_capacity(current: usize, required: usize, limit: usize) -> usize {
    if current > limit {
        required
    } else {
        required.max(current.saturating_mul(2)).max(8).min(limit)
    }
}

struct StreamingOutput<B: Budget = Allowance> {
    history: super::workspace::Deque<u8, B>,
    pending: Buffer<u8, B>,
    written: usize,
    output_limit: usize,
    dictionary_size: usize,
    history_limit: usize,
    all_zero: bool,
}

impl<B: Budget> StreamingOutput<B> {
    fn new(
        mut history: Buffer<u8, B>,
        output_limit: usize,
        dictionary_size: usize,
        history_limit: usize,
    ) -> Result<Self> {
        if history.capacity() > history_limit {
            history = Buffer::copied(&history, &history.allowance())?;
        }
        let allowance = history.allowance();
        Ok(Self {
            all_zero: history.iter().all(|&byte| byte == 0),
            history: super::workspace::Deque::from_buffer(history),
            pending: Buffer::with_capacity(STREAM_FLUSH_THRESHOLD, &allowance)?,
            written: 0,
            output_limit,
            dictionary_size,
            history_limit,
        })
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
        self.pending.try_push(byte)?;
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
            self.pending.resize(old_len + take, byte)?;
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
        // copy_match only reaches this path with an initialized positive
        // distance. Either retained history exists, or flushing the pending
        // zero literals retains at least one byte (the dictionary is nonzero).
        debug_assert!(!self.history.is_empty());
        sink(DecodedChunk::Repeated {
            byte: 0,
            len: count,
        })
        .map_err(StreamDecodeError::Sink)?;
        self.written += count;
        Ok(())
    }

    fn copy_match<E>(
        &mut self,
        distance: usize,
        length: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.all_zero && distance <= self.written + self.history.len() {
            return self.push_zeroes(length, sink);
        }
        // Zero-fill out-of-window matches, as the buffered decoder does.
        if distance == 0
            || distance > self.dictionary_size
            || distance > self.history.len() + self.pending.len()
        {
            return self.push_repeated(0, length, sink);
        }
        if self
            .written
            .checked_add(length)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if distance == 1 {
            let byte = self.byte_at_distance(1);
            return self.push_repeated(byte, length, sink);
        }
        for _ in 0..length {
            let byte = self.byte_at_distance(distance);
            self.push(byte, sink)?;
        }
        Ok(())
    }

    fn byte_at_distance(&self, distance: usize) -> u8 {
        // copy_match admits only distances inside the current window. Every
        // copied byte extends that window; flush retains at least distance
        // bytes because distance is bounded by dictionary_size.
        if distance <= self.pending.len() {
            self.pending[self.pending.len() - distance]
        } else {
            let history_distance = distance - self.pending.len();
            self.history[self.history.len() - history_distance]
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
        let incoming = &self.pending[self.pending.len().saturating_sub(self.history_limit)..];
        let keep = self.history.len().min(self.history_limit - incoming.len());
        let required = keep + incoming.len();
        if self.history.capacity() > self.history_limit || self.history.capacity() < required {
            let capacity =
                reader_history_capacity(self.history.capacity(), required, self.history_limit);
            let mut history =
                super::workspace::Deque::with_capacity(capacity, &self.history.allowance())?;
            history.extend_admitted(self.history.iter().skip(self.history.len() - keep).copied());
            history.extend_admitted(incoming.iter().copied());
            self.history = history;
        } else {
            self.history.discard_prefix(self.history.len() - keep);
            self.history.extend_admitted(incoming.iter().copied());
        }
        self.pending.clear();
        Ok(())
    }

    fn finish<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.flush(sink)
    }

    fn into_history(self) -> Buffer<u8, B> {
        self.history.into_buffer()
    }
}

#[cfg(all(test, feature = "write"))]
fn read_compressed_block(input: &mut impl Read) -> Result<OwnedCompressedBlock> {
    read_compressed_block_with_allowance(input, &Allowance::default())
}

fn read_compressed_block_with_allowance<B: Budget>(
    input: &mut impl Read,
    allowance: &B,
) -> Result<OwnedCompressedBlock<B>> {
    let mut fixed = [0u8; 2];
    input
        .read_exact(&mut fixed)
        .map_err(Error::from_read_error)?;
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
        .map_err(Error::from_read_error)?;

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
    let mut payload = Buffer::filled(payload_size, 0, allowance)?;
    input
        .read_exact(&mut payload)
        .map_err(Error::from_read_error)?;
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
pub(crate) struct PendingFilter {
    pub(crate) start: usize,
    pub(crate) length: usize,
    pub(crate) filter_type: FilterType,
    pub(crate) channels: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterType {
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
fn write_filter_data_admitted<B: Budget>(writer: &mut BitWriter<B>, value: u32) {
    let byte_count = filter_data_byte_count(value);
    writer.write_admitted_bits(byte_count - 1, 2);
    for index in 0..byte_count {
        writer.write_admitted_bits(((value >> (index * 8)) & 0xff) as usize, 8);
    }
}

#[cfg(feature = "write")]
fn filter_data_byte_count(value: u32) -> usize {
    ((u32::BITS - value.leading_zeros()).div_ceil(8) as usize).max(1)
}

#[cfg(all(test, feature = "write"))]
fn apply_filters_with_control(
    output: &mut [u8],
    filters: &[PendingFilter],
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    apply_filters_with_allowance(output, filters, control, &Allowance::default())
}
fn apply_filters_with_allowance<B: Budget>(
    output: &mut [u8],
    filters: &[PendingFilter],
    control: &crate::read_control::ReadControl,
    allowance: &B,
) -> Result<()> {
    control.check_codec()?;
    for filter in filters {
        control.check_codec()?;
        let end = filter
            .start
            .checked_add(filter.length)
            .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
        let data = output
            .get_mut(filter.start..end)
            .ok_or(Error::InvalidData("RAR 5 filter range exceeds output"))?;
        apply_filter_data_with_allowance(data, filter, control, allowance)?;
    }
    Ok(())
}

#[cfg(all(test, feature = "write"))]
pub(crate) fn apply_filter_data(
    data: &mut [u8],
    filter: &PendingFilter,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    apply_filter_data_with_allowance(data, filter, control, &Allowance::default())
}
pub(crate) fn apply_filter_data_with_allowance<B: Budget>(
    data: &mut [u8],
    filter: &PendingFilter,
    control: &crate::read_control::ReadControl,
    allowance: &B,
) -> Result<()> {
    match filter.filter_type {
        FilterType::Delta => {
            let decoded = filters::delta_decode_with_allowance(
                data,
                filter.channels,
                rar50_delta_messages(),
                control,
                allowance,
            )?;
            data.copy_from_slice(&decoded);
        }
        FilterType::E8 => e8e9_decode_with_control(data, filter.start as u32, false, control)?,
        FilterType::E8E9 => e8e9_decode_with_control(data, filter.start as u32, true, control)?,
        FilterType::Arm => arm_decode_with_control(data, filter.start as u32, control)?,
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

#[cfg(all(test, feature = "write"))]
fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    e8e9_decode_with_control(
        data,
        file_offset,
        include_e9,
        &crate::read_control::ReadControl::default(),
    )
    .expect("uncancelled filter");
}

fn e8e9_decode_with_control(
    data: &mut [u8],
    file_offset: u32,
    include_e9: bool,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    control.check_codec()?;
    let mut poller = control.poller();
    if data.len() <= 4 {
        return Ok(());
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while opcode_pos < opcode_limit {
        poller.check_codec(opcode_pos)?;
        let scan_end = if control.is_enabled() {
            opcode_limit.min(opcode_pos.saturating_add(64 * 1024))
        } else {
            opcode_limit
        };
        let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, scan_end, cmp_mask) else {
            opcode_pos = scan_end;
            continue;
        };
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

    Ok(())
}

#[cfg(feature = "write")]
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

#[cfg(all(test, feature = "write"))]
fn arm_decode(data: &mut [u8], file_offset: u32) {
    arm_decode_with_control(
        data,
        file_offset,
        &crate::read_control::ReadControl::default(),
    )
    .expect("uncancelled filter");
}

fn arm_decode_with_control(
    data: &mut [u8],
    file_offset: u32,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    control.check_codec()?;
    let mut poller = control.poller();
    let mut pos = 0usize;
    while pos + 3 < data.len() {
        poller.check_codec(pos)?;
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

    Ok(())
}

#[cfg(feature = "write")]
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

fn length_slot_extra_bits(slot: usize) -> u8 {
    if slot < 8 {
        0
    } else {
        ((slot >> 2) - 1) as u8
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
    let max_extra = (1u32 << bit_count) - 1;
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 length extra bits exceed slot"));
    }
    Ok(length_from_slot_parts(slot, extra_bits))
}

fn length_from_slot_parts(slot: usize, extra_bits: u32) -> usize {
    if slot < 8 {
        slot + 2
    } else {
        let bit_count = (slot >> 2) - 1;
        debug_assert!(bit_count <= 24);
        debug_assert!(extra_bits < 1u32 << bit_count);
        (((4 | (slot & 3)) << bit_count) | extra_bits as usize) + 2
    }
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
    let max_extra = (1u32 << bit_count) - 1;
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"));
    }
    Ok(distance_from_slot_parts(slot, bit_count, extra_bits))
}

fn distance_from_slot_parts(slot: usize, bit_count: usize, extra_bits: u32) -> usize {
    if slot < 4 {
        return slot + 1;
    }
    debug_assert!(bit_count <= 31);
    debug_assert!(extra_bits < 1u32 << bit_count);
    let distance = (((2u64 | (slot & 1) as u64) << bit_count) | u64::from(extra_bits)) + 1;
    // RAR 5 slots can name more than a 32-bit host can address. Preserve the
    // decoder's out-of-window zero-fill behavior instead of wrapping to a
    // plausible distance (or panicking on arithmetic overflow).
    usize::try_from(distance).unwrap_or(usize::MAX)
}

#[derive(Debug)]
pub struct HuffmanTable {
    state: HuffmanState<Allowance>,
}
impl Clone for HuffmanTable {
    fn clone(&self) -> Self {
        Self {
            state: self.state.try_clone().expect("unlimited table copy"),
        }
    }
}
impl HuffmanTable {
    pub fn from_lengths(lengths: &[u8]) -> Result<Self> {
        Ok(Self {
            state: HuffmanState::from_lengths(lengths, &Allowance::default())?,
        })
    }
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
    #[cfg(all(test, feature = "write"))]
    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        self.state.decode(bits)
    }
}
#[derive(Debug)]
struct HuffmanState<B: Budget> {
    state: super::canonical::Huffman<B>,
}

impl<B: Budget> HuffmanState<B> {
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
    fn from_lengths(lengths: &[u8], allowance: &B) -> Result<Self> {
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

        Ok(Self {
            state: super::canonical::Huffman::from_counts(lengths, count, allowance)?,
        })
    }
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            state: self.state.try_clone()?,
        })
    }
    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        self.state.decode(
            || bits.read_bits(1).map(|bit| bit as u16),
            "RAR 5 empty Huffman table",
            "RAR 5 invalid Huffman code",
        )
    }
}

#[cfg(feature = "write")]
struct EncoderCodeTable<B: Budget> {
    symbols: Buffer<(u16, u8), B>,
}
#[cfg(feature = "write")]
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

struct BitReader<'a> {
    input: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, bit_pos: 0 }
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let count = usize::from(count);
        let byte_pos = self.bit_pos / 8;
        let bit_offset = self.bit_pos % 8;
        // A read spans at most 33 bits after accounting for its starting
        // offset. Compare that local byte span rather than multiplying the
        // entire input length by eight, which can overflow for a huge slice.
        let bytes_needed = (bit_offset + count).div_ceil(8);
        if bytes_needed > self.input.len().saturating_sub(byte_pos) {
            return Err(Error::NeedMoreInput);
        }

        let mut value = 0u32;
        let mut remaining = count;
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

#[cfg(feature = "write")]
struct BitWriter<B: Budget = Allowance> {
    bytes: Buffer<u8, B>,
    bit_pos: usize,
}

#[cfg(feature = "write")]
impl BitWriter {
    #[cfg(all(test, feature = "write"))]
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
#[cfg(feature = "write")]
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

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    super::canonical::validate_counts(count, "RAR 5 oversubscribed Huffman table")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "write")]
struct LevelToken {
    symbol: usize,
    extra_bits: u8,
    extra_value: u8,
}

#[cfg(feature = "write")]
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

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
fn encode_table_level_tokens(lengths: &[u8]) -> Vec<LevelToken> {
    encode_table_level_tokens_with_allowance(lengths, &Allowance::default())
        .unwrap()
        .into_vec()
}
#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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

#[cfg(feature = "write")]
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
#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
fn level_code_lengths_for_tokens(tokens: &[LevelToken]) -> [u8; LEVEL_TABLE_SIZE] {
    level_code_lengths_with_allowance(tokens, &Allowance::default()).unwrap()
}
#[cfg(feature = "write")]
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
#[cfg(feature = "write")]
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

#[cfg(all(test, feature = "write"))]
#[cfg(feature = "write")]
fn write_level_lengths(writer: &mut BitWriter, lengths: &[u8; LEVEL_TABLE_SIZE]) {
    try_write_level_lengths(writer, lengths).unwrap();
}
#[cfg(feature = "write")]
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

#[cfg(all(test, feature = "write"))]
mod tests;
