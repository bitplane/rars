#[cfg(feature = "write")]
mod encoder;
#[cfg(feature = "write")]
pub use encoder::{
    encode_compressed_block, encode_literal_only, encode_lz_member, encode_lz_member_with_history,
    encode_lz_member_with_history_and_options, encode_lz_member_with_options, encode_table_lengths,
    encode_table_lengths_with_bit_count, EncodeOptions, Unpack50Encoder,
};
#[cfg(all(test, feature = "write"))]
pub(crate) use encoder::{
    encode_lz_member_with_options_and_progress, encode_lz_reader_to, filtered_lz_member,
};
#[cfg(feature = "write")]
pub(crate) use encoder::{
    encode_owned_member, filtered_owned_member, streaming_blocks_with_allowance, BlockSplitter,
    LZ_BLOCK_SIZE, MAX_DELTA_CHANNELS, MAX_LZ_BLOCK_SIZE,
};

use super::filters::{self, DeltaErrorMessages};
use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};
use std::io::Read;
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
// Literals decoded per burst before the loop polls again.
const LITERAL_BURST: usize = 256;
/// The longest filter the streaming decoder holds back to apply in place:
/// unrar's `MAX_FILTER_BLOCK_SIZE`. A longer one ends streaming with
/// `StreamDecodeError::FilteredMember`, leaving the member to a caller that
/// can buffer it or decode it through scratch.
const MAX_STREAMED_FILTER_LENGTH: usize = 0x40_0000;
/// The most filters the streaming decoder holds at once: unrar's
/// `MAX_UNPACK_FILTERS`. More also end streaming with `FilteredMember`.
const MAX_STREAMED_FILTERS: usize = 8192;

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
    Ok((lengths, bits.position()))
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
    let mut bits = BitReader::at(input, level_bits);

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
        bits.position(),
    ))
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
        result.map(drop)
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

/// Buffered workers may discard state they will never use. Public and stateful
/// decoding retains history; solid and limited decoding always overrides this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryRetention {
    Retain,
    DiscardIndependent,
}

#[derive(Debug)]
pub(crate) struct ReaderState<B: Budget> {
    pub(crate) read_control: crate::read_control::ReadControl,
    tables: Option<ReaderTables<B>>,
    reps: [usize; 4],
    last_length: usize,
    history: Buffer<u8, B>,
    // A streamed member's history, kept as is so the next stream reuses it.
    streamed_history: Option<StreamedHistory<B>>,
    // Only this tail is reachable. Older bytes may remain as physical slack.
    history_window: usize,
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
            streamed_history: None,
            history_window: 0,
        }
    }

    fn flatten_streamed_history(&mut self, dictionary_size: usize) -> Result<()> {
        if let Some(history) = self.streamed_history.take() {
            self.history = history.into_buffer();
            // Bounded readers give back the ring's flush slack.
            let limit = reader_history_limit::<B>(dictionary_size).max(self.history.len());
            if B::LIMITED && self.history.capacity() > limit {
                self.history.shrink_to(limit)?;
            }
        }
        Ok(())
    }

    fn reachable_history(&self) -> &[u8] {
        debug_assert!(self.streamed_history.is_none());
        debug_assert!(self.history_window <= self.history.len());
        &self.history[self.history.len() - self.history_window..]
    }

    #[cfg(all(test, feature = "write"))]
    fn history_bytes(&self) -> Vec<u8> {
        match &self.streamed_history {
            Some(history) => history.to_vec(),
            None => self.reachable_history().to_vec(),
        }
    }

    #[cfg(all(test, feature = "write"))]
    fn history_capacity(&self) -> usize {
        self.streamed_history
            .as_ref()
            .map_or(self.history.capacity(), |history| history.allocated())
    }

    #[cfg(test)]
    fn with_history(history: Buffer<u8, B>) -> Self {
        let mut state = Self::new(&history.allowance());
        state.history_window = history.len();
        state.history = history;
        state
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
            history_window: self.history_window,
            history: match &self.streamed_history {
                Some(streamed) => {
                    let (front, back) = streamed.as_slices();
                    let mut history = Buffer::with_capacity(streamed.len, &streamed.allowance())?;
                    history.extend_from_slice(front).map_err(Into::into)?;
                    history.extend_from_slice(back).map_err(Into::into)?;
                    history
                }
                // Slack is not reachable history and need not be copied.
                None => Buffer::copied(self.reachable_history(), &self.history.allowance())?,
            },
            streamed_history: None,
        })
    }

    /// Solid state moves rather than copies, so a failed decode loses the chain.
    pub(crate) fn take_for_stream(&mut self, solid: bool) -> Self {
        let mut decoder = Self::new(&self.allowance());
        decoder.read_control = self.read_control.clone();
        if solid {
            return std::mem::replace(self, decoder);
        }
        if !B::LIMITED {
            // An independent member needs no old bytes. Reusing the allocation
            // keeps allocators from retaining a freed window per member.
            let mut history = match self.streamed_history.take() {
                Some(ring) => ring.bytes,
                None => std::mem::replace(&mut self.history, Buffer::new(&decoder.allowance())),
            };
            history.clear();
            self.history_window = 0;
            decoder.history = history;
        }
        decoder
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
        self.decode_member_with_dictionary_and_history(
            input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            mode,
            HistoryRetention::Retain,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_member_with_dictionary_and_history(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
        history: HistoryRetention,
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
        let mut input = std::io::Cursor::new(input);
        self.decode_member_from_reader_with_dictionary_and_history(
            &mut input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            mode,
            history,
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
        self.decode_member_from_reader_with_dictionary_and_history(
            input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            mode,
            HistoryRetention::Retain,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_member_from_reader_with_dictionary_and_history(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
        history: HistoryRetention,
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
        self.flatten_streamed_history(dictionary_size)?;

        let allowance = self.history.allowance();
        let mut output =
            Buffer::with_capacity(output_size.min(MAX_INITIAL_OUTPUT_CAPACITY), &allowance)?;
        let mut filters = Buffer::new(&allowance);
        let mut literals = [0; LITERAL_BURST];
        let mut overrun = None;

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
            let mut bits = BitReader::at(payload, payload_bit_pos);
            let payload_bits = block.header.payload_bits;

            let mut poller = self.read_control.poller();
            while bits.position() < payload_bits && output.len() < output_size {
                poller.check_codec(output.len())?;
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => {
                        output.try_push(symbol as u8)?;
                        let room = (output_size - output.len()).min(LITERAL_BURST);
                        let count =
                            bits.literal_burst(&tables.main, payload_bits, &mut literals[..room]);
                        if count != 0 {
                            output
                                .extend_from_slice(&literals[..count])
                                .map_err(Into::into)?;
                        }
                    }
                    256 if mode.uses_lz() => {
                        filters.try_push(read_filter(&mut bits, output.len())?)?;
                    }
                    257 if mode.uses_lz() => {
                        if self.last_length != 0 {
                            overrun = self.copy_match(
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
                        overrun = self.copy_match(
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
                        overrun = self.copy_match(
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
            let retain_history = B::LIMITED || solid || history == HistoryRetention::Retain;
            let history_output = if retain_history && mode.applies_filters() && !filters.is_empty()
            {
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
            if retain_history {
                self.remember_history(
                    history_output.as_deref().unwrap_or(&output),
                    dictionary_size,
                )?;
                if let Some(overrun) = overrun {
                    self.remember_overrun(overrun, dictionary_size)?;
                }
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

        // The ring grows as decoded bytes arrive, so using the declared
        // dictionary here does not allocate a potentially huge RAR 7 window
        // up front. It does, however, retain every byte that a legal match may
        // reference instead of silently truncating the window at 64 MiB.
        let history_limit = dictionary_size;
        let retained = self.history_window.min(history_limit);
        let history = match self.streamed_history.take() {
            Some(mut history) => {
                history.keep_newest(retained);
                history
            }
            None => {
                self.history.discard_prefix(self.history.len() - retained);
                let allowance = self.history.allowance();
                StreamedHistory::from(std::mem::replace(
                    &mut self.history,
                    Buffer::new(&allowance),
                ))
            }
        };
        // The history is moved out. Keep the empty state consistent even
        // if streaming setup or decoding fails; callers checkpoint as needed.
        self.history_window = 0;
        let mut output =
            StreamingOutput::new(history, output_size, dictionary_size, history_limit)?;
        output.stage.control = self.read_control.clone();
        self.decode_blocks(
            input,
            algorithm_version,
            &mut output,
            &mut sink,
            &mut filters,
        )?;
        self.finish_stream(output, &mut sink)
    }

    fn finish_stream<E>(
        &mut self,
        mut output: StreamingOutput<B>,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if output.written() == output.output_limit {
            output.finish(sink)?;
            let history = output.into_history();
            self.history_window = history.len;
            self.streamed_history = Some(history);
            Ok(())
        } else {
            Err(Error::NeedMoreInput.into())
        }
    }

    fn decode_blocks<E>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output: &mut StreamingOutput<B>,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
        filters: &mut Option<&mut dyn FnMut(PendingFilter) -> std::result::Result<(), E>>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let output_size = output.output_limit;
        let mut literals = [0; LITERAL_BURST];

        loop {
            let block = read_compressed_block_with_allowance(input, &output.ring.allowance())?;
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
            let mut bits = BitReader::at(payload, payload_bit_pos);
            let payload_bits = block.header.payload_bits;

            let mut poller = self.read_control.poller();
            while bits.position() < payload_bits && output.written() < output_size {
                poller.check_codec(output.written())?;
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => {
                        output.push(symbol as u8, sink)?;
                        let room = output.literal_room();
                        let count =
                            bits.literal_burst(&tables.main, payload_bits, &mut literals[..room]);
                        if count != 0 {
                            output.push_literals(&literals[..count], sink)?;
                        }
                    }
                    256 => {
                        let filter = read_filter(&mut bits, output.written())?;
                        output.accept_filter(filter, filters)?;
                    }
                    257 => {
                        if self.last_length != 0 {
                            output.copy_match(self.reps[0], self.last_length, sink)?;
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
                        output.copy_match(distance, length, sink)?;
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
                        output.copy_match(distance, length, sink)?;
                    }
                }
            }

            self.tables = Some(tables);
            if block.header.is_last || output.written() >= output_size {
                return Ok(());
            }
        }
    }

    fn remember_history(&mut self, output: &[u8], dictionary_size: usize) -> Result<()> {
        self.flatten_streamed_history(dictionary_size)?;
        let incoming = &output[output.len().saturating_sub(dictionary_size)..];
        let keep = self.history_window.min(dictionary_size - incoming.len());
        let required = keep + incoming.len();
        let limit = reader_history_limit::<B>(dictionary_size);
        let capacity = self.history.capacity();

        // Unlimited readers amortize moves across small members. Bounded
        // readers retain the original exact-window growth and peak charge.
        if !B::LIMITED
            && incoming.len() < dictionary_size
            && capacity <= limit
            && self.history.len() + incoming.len() <= capacity
        {
            self.history
                .extend_from_slice(incoming)
                .map_err(Into::into)?;
        } else if capacity <= limit
            && capacity >= required
            && (B::LIMITED || capacity == limit || incoming.len() == dictionary_size)
        {
            // Compact a full slack buffer in place. A full incoming dictionary
            // replaces every old byte, including any discontinuous prefix.
            self.history.discard_prefix(self.history.len() - keep);
            self.history
                .extend_from_slice(incoming)
                .map_err(Into::into)?;
        } else {
            // Admit the replacement before touching the old window. Growing
            // toward the slack limit avoids moving a full dictionary per file.
            let capacity = reader_history_capacity::<B>(capacity, required, dictionary_size);
            let mut history = Buffer::with_capacity(capacity, &self.history.allowance())?;
            history
                .extend_from_slice(&self.history[self.history.len() - keep..])
                .map_err(Into::into)?;
            history.extend_from_slice(incoming).map_err(Into::into)?;
            self.history = history;
        }
        // Physical slack must never become reachable when a later member
        // declares a larger dictionary.
        self.history_window = required;
        Ok(())
    }

    fn remember_overrun(&mut self, overrun: Overrun, dictionary_size: usize) -> Result<()> {
        let mut bytes = Buffer::with_capacity(overrun.len, &self.history.allowance())?;
        match overrun.distance {
            None => bytes.resize(overrun.len, 0)?,
            Some(distance) => {
                // The window already holds `distance` bytes: copy_match checked.
                let history = self.reachable_history();
                for index in 0..overrun.len {
                    let byte = if index < distance {
                        history[history.len() - distance + index]
                    } else {
                        bytes[index - distance]
                    };
                    bytes.try_push(byte)?;
                }
            }
        }
        self.remember_history(&bytes, dictionary_size)
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.last_length = 0;
        self.history.clear();
        if let Some(history) = &mut self.streamed_history {
            history.keep_newest(0);
        }
        self.history_window = 0;
    }

    fn copy_match(
        &self,
        output: &mut Buffer<u8, B>,
        distance: usize,
        length: usize,
        output_limit: usize,
        dictionary_size: usize,
    ) -> Result<Option<Overrun>> {
        // A match reaching past the start of the window writes zeroes rather
        // than failing. WinRAR never clears its window and guards the copy
        // with a first-wrap flag instead, so those bytes read as zero there,
        // and an archive that leans on it stays readable here. Nothing is
        // swallowed: a stream that is damaged rather than merely odd still
        // fails its file hash.
        let zero_fill = distance == 0
            || distance > dictionary_size
            || distance > self.history_window + output.len();
        let visible = length.min(output_limit.saturating_sub(output.len()));
        let overrun = Overrun::of(distance, zero_fill, length - visible);
        self.copy_visible(output, distance, visible, zero_fill)?;
        Ok(overrun)
    }

    fn copy_visible(
        &self,
        output: &mut Buffer<u8, B>,
        distance: usize,
        length: usize,
        zero_fill: bool,
    ) -> Result<()> {
        if zero_fill {
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
                    let len = output.len();
                    if remaining <= SHORT_MATCH
                        && distance >= SHORT_MATCH
                        && output.capacity() - len >= SHORT_MATCH
                    {
                        // A fixed-width copy into spare capacity, cut back to
                        // the match: cheaper than a variable-length memcpy.
                        let bytes: [u8; SHORT_MATCH] = output[start..start + SHORT_MATCH]
                            .try_into()
                            .expect("fixed-width slice");
                        output.extend_from_slice(&bytes).map_err(Into::into)?;
                        output.truncate(len + remaining);
                        return Ok(());
                    }
                    if remaining <= distance {
                        return output.extend_from_within(start..start + remaining);
                    }
                    // Newly appended bytes are initialized repetitions of
                    // the same period. Reuse that growing run so short
                    // overlapping matches take logarithmically many copies.
                    while remaining > 0 {
                        let take = remaining.min(output.len() - start);
                        output.extend_from_within(start..start + take)?;
                        remaining -= take;
                    }
                    return Ok(());
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

// Bounded readers keep the original allocation and refusal policy. Unlimited
// readers keep a quarter dictionary of spare storage across both decode paths.
fn reader_history_limit<B: Budget>(dictionary_size: usize) -> usize {
    if B::LIMITED {
        dictionary_size
    } else {
        dictionary_size.saturating_add(dictionary_size / 4)
    }
}

fn reader_history_capacity<B: Budget>(
    current: usize,
    required: usize,
    dictionary_size: usize,
) -> usize {
    let limit = reader_history_limit::<B>(dictionary_size);
    let capacity = if current > limit {
        if B::LIMITED {
            required
        } else {
            // A reset can leave a large allocation with little live history.
            // Start small again instead of preallocating the new dictionary.
            required.max(8).min(limit)
        }
    } else {
        required.max(current.saturating_mul(2)).max(8).min(limit)
    };
    if !B::LIMITED && capacity >= dictionary_size {
        limit
    } else {
        capacity
    }
}

/// A streamed member's window: the newest `len` bytes of a ring end before `end`.
#[derive(Debug)]
pub(crate) struct StreamedHistory<B: Budget = Allowance> {
    bytes: Buffer<u8, B>,
    end: usize,
    len: usize,
}

impl<B: Budget> StreamedHistory<B> {
    // Initialized ring space; fixed-width copies may land anywhere in it.
    fn capacity(&self) -> usize {
        self.bytes.len()
    }

    fn allocated(&self) -> usize {
        self.bytes.capacity()
    }

    /// Ring index of the byte `distance` back from the newest.
    fn back(&self, distance: usize) -> usize {
        debug_assert!(distance <= self.capacity());
        if distance <= self.end {
            self.end - distance
        } else {
            self.end + self.capacity() - distance
        }
    }

    fn advance(&mut self, count: usize) {
        self.end += count;
        self.len += count;
    }

    fn allowance(&self) -> B {
        self.bytes.allowance()
    }

    /// Oldest bytes first.
    fn as_slices(&self) -> (&[u8], &[u8]) {
        if self.len <= self.end {
            (&self.bytes[self.end - self.len..self.end], &[])
        } else {
            let start = self.capacity() - (self.len - self.end);
            (&self.bytes[start..], &self.bytes[..self.end])
        }
    }

    #[cfg(test)]
    fn to_vec(&self) -> Vec<u8> {
        let (older, newer) = self.as_slices();
        [older, newer].concat()
    }

    fn keep_newest(&mut self, count: usize) {
        self.len = self.len.min(count);
    }

    /// Flattens in place, oldest byte first, without allocating.
    fn into_buffer(mut self) -> Buffer<u8, B> {
        let start = self.back(self.len);
        self.bytes.rotate_left(start);
        self.bytes.truncate(self.len);
        self.bytes
    }

    /// Grows the allocation itself so no second copy is resident; true if it moved.
    fn grow(&mut self, capacity: usize) -> Result<bool> {
        if B::LIMITED {
            // Keep the exact charge rather than the ledger's doubling.
            self.relocate(capacity)?;
            return Ok(true);
        }
        let moved = self.len > self.end;
        if moved {
            let start = self.back(self.len);
            self.bytes.rotate_left(start);
            self.end = self.len;
        }
        self.bytes.reserve_exact(capacity - self.bytes.len());
        self.bytes.resize(capacity, 0)?;
        Ok(moved)
    }

    /// Moves the window into a fresh ring of `capacity` bytes, ending at `len`.
    fn relocate(&mut self, capacity: usize) -> Result<()> {
        debug_assert!(capacity > self.len);
        let mut bytes = Buffer::with_capacity(capacity, &self.allowance())?;
        let (older, newer) = self.as_slices();
        bytes.extend_from_slice(older).map_err(Into::into)?;
        bytes.extend_from_slice(newer).map_err(Into::into)?;
        bytes.resize(capacity, 0)?;
        self.bytes = bytes;
        self.end = self.len;
        Ok(())
    }
}

impl<B: Budget> From<Buffer<u8, B>> for StreamedHistory<B> {
    // Spare capacity becomes ring space only as the ring grows into it.
    fn from(history: Buffer<u8, B>) -> Self {
        Self {
            end: history.len(),
            len: history.len(),
            bytes: history,
        }
    }
}

/// A final match's bytes past the declared size, kept for the next solid member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Overrun {
    // None when the match zero-fills.
    distance: Option<usize>,
    len: usize,
}

impl Overrun {
    fn of(distance: usize, zero_fill: bool, len: usize) -> Option<Self> {
        (len != 0).then_some(Self {
            distance: (!zero_fill).then_some(distance),
            len,
        })
    }
}

// Room past the newest byte for a fixed-width short match to over-copy into.
const SHORT_MATCH: usize = 32;
// Ring space beyond the reachable history: unflushed output plus over-copy.
const STREAM_SLACK: usize = STREAM_FLUSH_THRESHOLD + SHORT_MATCH;

struct StreamingOutput<B: Budget = Allowance> {
    // History, then the `pending` bytes not yet flushed, which never wrap.
    ring: StreamedHistory<B>,
    pending: usize,
    max_capacity: usize,
    stage: FilterStage<B>,
    written: usize,
    output_limit: usize,
    dictionary_size: usize,
    history_limit: usize,
    all_zero: bool,
}

impl<B: Budget> StreamingOutput<B> {
    fn new(
        history: impl Into<StreamedHistory<B>>,
        output_limit: usize,
        dictionary_size: usize,
        history_limit: usize,
    ) -> Result<Self> {
        let mut ring = history.into();
        ring.keep_newest(history_limit);
        let max_capacity = history_limit.saturating_add(STREAM_SLACK);
        // A reset can leave a large ring under a smaller dictionary.
        if ring.allocated() > reader_history_limit::<B>(history_limit).saturating_add(STREAM_SLACK)
        {
            ring.relocate(ring.len + STREAM_SLACK)?;
        }
        let (older, newer) = ring.as_slices();
        let all_zero = older.iter().chain(newer).all(|&byte| byte == 0);
        let allowance = ring.allowance();
        Ok(Self {
            all_zero,
            ring,
            pending: 0,
            max_capacity,
            stage: FilterStage::new(&allowance),
            written: 0,
            output_limit,
            dictionary_size,
            history_limit,
        })
    }

    fn written(&self) -> usize {
        self.written
    }

    fn accept_filter<E>(
        &mut self,
        filter: PendingFilter,
        filters: &mut Option<&mut dyn FnMut(PendingFilter) -> std::result::Result<(), E>>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if filter
            .start
            .checked_add(filter.length)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 filter range exceeds output").into());
        }
        match filters.as_mut() {
            Some(filters) => filters(filter).map_err(StreamDecodeError::Sink),
            None => self.stage.hold(filter),
        }
    }

    /// Grows the ring so `count` more bytes cannot overwrite history; true if it moved.
    fn make_room(&mut self, count: usize) -> Result<bool> {
        let capacity = self.ring.capacity();
        let required = self.ring.len + count + SHORT_MATCH;
        if required <= capacity || capacity >= self.max_capacity {
            return Ok(false);
        }
        debug_assert!(required <= self.max_capacity);
        // Room for a whole flush at once, so small dictionaries grow only once.
        let capacity = required
            .max(capacity.saturating_mul(2))
            .max(self.ring.len + STREAM_SLACK)
            .min(self.max_capacity);
        self.ring.grow(capacity)
    }

    /// Contiguous room at the end of the ring before the next flush.
    fn room(&self) -> usize {
        (STREAM_FLUSH_THRESHOLD - self.pending).min(self.ring.capacity() - self.ring.end)
    }

    fn advance<E>(
        &mut self,
        count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.ring.advance(count);
        self.pending += count;
        self.written += count;
        if self.pending == STREAM_FLUSH_THRESHOLD || self.ring.end == self.ring.capacity() {
            self.flush(sink)?;
        }
        Ok(())
    }

    fn check_limit(&self, count: usize) -> Result<()> {
        if self
            .written
            .checked_add(count)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit"));
        }
        Ok(())
    }

    fn push<E>(
        &mut self,
        byte: u8,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.check_limit(1)?;
        if byte != 0 {
            self.all_zero = false;
        }
        self.make_room(1)?;
        self.ring.bytes[self.ring.end] = byte;
        self.advance(1, sink)
    }

    // None straight after a flush, so the decoder polls before more output.
    fn literal_room(&self) -> usize {
        if self.pending == 0 {
            return 0;
        }
        (STREAM_FLUSH_THRESHOLD - self.pending)
            .min(self.output_limit - self.written)
            .min(LITERAL_BURST)
    }

    fn push_literals<E>(
        &mut self,
        mut literals: &[u8],
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.check_limit(literals.len())?;
        if self.all_zero && literals.iter().any(|&byte| byte != 0) {
            self.all_zero = false;
        }
        while !literals.is_empty() {
            self.make_room(literals.len().min(STREAM_FLUSH_THRESHOLD - self.pending))?;
            let take = literals.len().min(self.room());
            let end = self.ring.end;
            self.ring.bytes[end..end + take].copy_from_slice(&literals[..take]);
            literals = &literals[take..];
            self.advance(take, sink)?;
        }
        Ok(())
    }

    fn push_repeated<E>(
        &mut self,
        byte: u8,
        mut count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.check_limit(count)?;
        if byte != 0 {
            self.all_zero = false;
        }
        while count > 0 {
            self.make_room(count.min(STREAM_FLUSH_THRESHOLD - self.pending))?;
            let take = count.min(self.room());
            let end = self.ring.end;
            self.ring.bytes[end..end + take].fill(byte);
            count -= take;
            self.advance(take, sink)?;
        }
        Ok(())
    }

    fn push_zeroes<E>(
        &mut self,
        count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.check_limit(count)?;
        self.flush(sink)?;
        // copy_match only reaches this path with an initialized positive
        // distance, so the window holds at least one (zero) byte.
        debug_assert!(self.ring.len != 0);
        self.stage.emit(
            DecodedChunk::Repeated {
                byte: 0,
                len: count,
            },
            sink,
        )?;
        self.written += count;
        Ok(())
    }

    /// The usual match, taken whole from the ring with no flush, growth or
    /// sink call; false leaves it to the general copy.
    #[inline(always)]
    fn copy_short(&mut self, distance: usize, length: usize) -> bool {
        let end = self.ring.end;
        let capacity = self.ring.capacity();
        if self.all_zero
            || length > SHORT_MATCH
            || distance < length
            || distance > end
            || distance > self.ring.len
            || distance > self.dictionary_size
            || length > self.output_limit - self.written
            || self.pending + length >= STREAM_FLUSH_THRESHOLD
            || end + SHORT_MATCH >= capacity
            || (self.ring.len + length + SHORT_MATCH > capacity && capacity < self.max_capacity)
        {
            return false;
        }
        let source = end - distance;
        let bytes: [u8; SHORT_MATCH] = self.ring.bytes[source..source + SHORT_MATCH]
            .try_into()
            .expect("fixed-width slice");
        self.ring.bytes[end..end + SHORT_MATCH].copy_from_slice(&bytes);
        self.ring.advance(length);
        self.pending += length;
        self.written += length;
        true
    }

    #[inline]
    fn copy_match<E>(
        &mut self,
        distance: usize,
        length: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.copy_short(distance, length) {
            return Ok(());
        }
        let visible = length.min(self.output_limit - self.written);
        if self.all_zero && distance <= self.written + self.ring.len - self.pending {
            // Zeroes that never reach the ring are implied by its zero fill.
            return self.push_zeroes(visible, sink);
        }
        // Zero-fill out-of-window matches, as the buffered decoder does.
        let zero_fill =
            distance == 0 || distance > self.dictionary_size || distance > self.ring.len;
        let overrun = Overrun::of(distance, zero_fill, length - visible);
        self.copy_visible(distance, visible, zero_fill, sink)?;
        if let Some(overrun) = overrun {
            self.retain_overrun(overrun, sink)?;
        }
        Ok(())
    }

    // Flushes first so the overrun is never part of a pending chunk.
    fn retain_overrun<E>(
        &mut self,
        overrun: Overrun,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.flush(sink)?;
        for _ in 0..overrun.len {
            self.make_room(1)?;
            let byte = overrun
                .distance
                .map_or(0, |distance| self.ring.bytes[self.ring.back(distance)]);
            if byte != 0 {
                self.all_zero = false;
            }
            let end = self.ring.end;
            self.ring.bytes[end] = byte;
            self.ring.advance(1);
            if self.ring.end == self.ring.capacity() {
                self.ring.end = 0;
            }
            self.ring.keep_newest(self.history_limit);
        }
        Ok(())
    }

    fn copy_visible<E>(
        &mut self,
        distance: usize,
        length: usize,
        zero_fill: bool,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if zero_fill {
            return self.push_repeated(0, length, sink);
        }
        self.check_limit(length)?;
        if distance == 1 {
            let byte = self.ring.bytes[self.ring.back(1)];
            return self.push_repeated(byte, length, sink);
        }
        // Start of the run being repeated, while the ring has not wrapped or
        // moved under it. Each copy extends that run, so overlapping
        // short-distance matches double instead of copying one period at a time.
        let mut run = None;
        let mut remaining = length;
        while remaining != 0 {
            if self.make_room(remaining.min(STREAM_FLUSH_THRESHOLD - self.pending))? {
                run = None;
            }
            let capacity = self.ring.capacity();
            let end = self.ring.end;
            let room = self.room();
            if remaining <= SHORT_MATCH
                && distance >= remaining
                && distance <= end
                && remaining <= room
                && end + SHORT_MATCH <= capacity
            {
                // make_room keeps SHORT_MATCH unreachable bytes past the end.
                let source = end - distance;
                let bytes: [u8; SHORT_MATCH] = self.ring.bytes[source..source + SHORT_MATCH]
                    .try_into()
                    .expect("fixed-width slice");
                self.ring.bytes[end..end + SHORT_MATCH].copy_from_slice(&bytes);
                return self.advance(remaining, sink);
            }
            let source = match run {
                Some(start) if start < end => start,
                _ => self.ring.back(distance),
            };
            let available = if source < end {
                run = Some(source);
                end - source
            } else {
                run = None;
                capacity - source
            };
            let take = remaining.min(room).min(available);
            self.ring.bytes.copy_within(source..source + take, end);
            if take != available {
                // The run stays a whole number of periods only if copied whole.
                run = None;
            }
            remaining -= take;
            self.advance(take, sink)?;
        }
        Ok(())
    }

    fn flush<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.pending != 0 {
            let end = self.ring.end;
            self.stage.emit(
                DecodedChunk::Bytes(&self.ring.bytes[end - self.pending..end]),
                sink,
            )?;
            self.pending = 0;
            self.ring.keep_newest(self.history_limit);
        }
        if self.ring.end == self.ring.capacity() {
            self.ring.end = 0;
        }
        Ok(())
    }

    fn finish<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.flush(sink)?;
        self.stage.finish()
    }

    fn into_history(self) -> StreamedHistory<B> {
        self.ring
    }
}

/// Decoded bytes on their way to the sink, with the member's filters applied
/// in place. A filter is declared before the bytes it covers, so bytes before
/// the next filter pass straight through, and a filter's range is held until
/// it is complete, transformed, and released. History keeps the unfiltered
/// bytes, which later matches copy from.
///
/// Filters must arrive in order and not overlap, each at most
/// `MAX_STREAMED_FILTER_LENGTH` long, at most `MAX_STREAMED_FILTERS` held at
/// once; anything else ends streaming with `StreamDecodeError::FilteredMember`.
struct FilterStage<B: Budget = Allowance> {
    /// Accepted filters in output order; those from `applied` on are pending.
    filters: Buffer<PendingFilter, B>,
    /// How many filters at the front of `filters` have been applied.
    applied: usize,
    /// Bytes from the next filter's start up to `position`, never past its end.
    held: Buffer<u8, B>,
    /// Output position of the next byte to arrive.
    position: usize,
    /// End of the last filter accepted.
    filtered_to: usize,
    control: crate::read_control::ReadControl,
}

impl<B: Budget> FilterStage<B> {
    fn new(allowance: &B) -> Self {
        Self {
            filters: Buffer::new(allowance),
            applied: 0,
            held: Buffer::new(allowance),
            position: 0,
            filtered_to: 0,
            control: crate::read_control::ReadControl::default(),
        }
    }

    /// Accepts a filter whose bytes have not arrived yet.
    fn hold<E>(&mut self, filter: PendingFilter) -> std::result::Result<(), StreamDecodeError<E>> {
        if filter.start < self.filtered_to
            || filter.length > MAX_STREAMED_FILTER_LENGTH
            || self.filters.len() - self.applied >= MAX_STREAMED_FILTERS
        {
            return Err(StreamDecodeError::FilteredMember);
        }
        self.filtered_to = filter.start + filter.length;
        self.filters.try_push(filter)?;
        Ok(())
    }

    fn emit<E>(
        &mut self,
        chunk: DecodedChunk<'_>,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let mut chunk = chunk;
        loop {
            let Some(&next) = self.next() else {
                self.position += chunk_len(chunk);
                return sink(chunk).map_err(StreamDecodeError::Sink);
            };
            let len = chunk_len(chunk);
            if len == 0 {
                return self.release(sink);
            }
            // Bytes before the next filter pass straight through, and so
            // does everything once the filters are done.
            if self.position < next.start {
                let direct = (next.start - self.position).min(len);
                let (head, tail) = split_chunk(chunk, direct);
                sink(head).map_err(StreamDecodeError::Sink)?;
                self.position += direct;
                chunk = tail;
                continue;
            }
            // Only the bytes the filter covers are held.
            let covered = (next.start + next.length - self.position).min(len);
            let (head, tail) = split_chunk(chunk, covered);
            match head {
                DecodedChunk::Bytes(bytes) => self
                    .held
                    .extend_from_slice(bytes)
                    .map_err(|error| StreamDecodeError::Decode(error.into()))?,
                DecodedChunk::Repeated { byte, len } => {
                    self.held.resize(self.held.len() + len, byte)?;
                }
            }
            self.position += covered;
            chunk = tail;
            self.release(sink)?;
        }
    }

    fn next(&self) -> Option<&PendingFilter> {
        self.filters.get(self.applied)
    }

    /// Applies every filter whose range is complete, in order, and passes on
    /// the bytes before the next one.
    fn release<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        while let Some(&filter) = self.next() {
            if filter.start + filter.length > self.position {
                break;
            }
            let held_start = self.position - self.held.len();
            let at = filter.start - held_start;
            let allowance = self.held.allowance();
            apply_filter_data_with_allowance(
                &mut self.held[at..at + filter.length],
                &filter,
                &self.control,
                &allowance,
            )?;
            // Drop applied filters in batches, so draining a long queue
            // moves each descriptor a bounded number of times.
            self.applied += 1;
            if self.applied * 2 >= self.filters.len() {
                self.filters.discard_prefix(self.applied);
                self.applied = 0;
            }
            let to = self
                .next()
                .map_or(self.position, |next| next.start.min(self.position));
            let count = to - held_start;
            if count != 0 {
                sink(DecodedChunk::Bytes(&self.held[..count])).map_err(StreamDecodeError::Sink)?;
                self.held.discard_prefix(count);
            }
        }
        Ok(())
    }

    /// Every byte has arrived: each filter has been applied and released.
    fn finish<E>(&self) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.next().is_none() && self.held.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidData("RAR 5 filter range exceeds output").into())
        }
    }
}

fn chunk_len(chunk: DecodedChunk<'_>) -> usize {
    match chunk {
        DecodedChunk::Bytes(bytes) => bytes.len(),
        DecodedChunk::Repeated { len, .. } => len,
    }
}

fn split_chunk(chunk: DecodedChunk<'_>, at: usize) -> (DecodedChunk<'_>, DecodedChunk<'_>) {
    match chunk {
        DecodedChunk::Bytes(bytes) => {
            let (head, tail) = bytes.split_at(at);
            (DecodedChunk::Bytes(head), DecodedChunk::Bytes(tail))
        }
        DecodedChunk::Repeated { byte, len } => (
            DecodedChunk::Repeated { byte, len: at },
            DecodedChunk::Repeated {
                byte,
                len: len - at,
            },
        ),
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
                count[length as usize] = count[length as usize]
                    .checked_add(1)
                    .ok_or(Error::InvalidData("RAR 5 oversubscribed Huffman table"))?;
            }
        }
        validate_huffman_counts(&count)?;

        Ok(Self {
            state: super::canonical::Huffman::from_counts_with_lookup(lengths, count, allowance)?,
        })
    }
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            state: self.state.try_clone()?,
        })
    }
    #[inline(always)]
    fn quick_entry(&self, peek: u32) -> u32 {
        self.state.quick_entry(peek)
    }
    /// Decodes from a 15-bit peek: one table lookup for nearly every code
    /// rather than a bounds-checked read per bit. Only the code's own bits
    /// are consumed, and the results are those of reading bit by bit: a code
    /// that runs past the end of the input needs more input, and a code is
    /// invalid only when 15 real bits start none.
    // Always inlined: it runs once per symbol, and as a call it saved and
    // restored registers every time.
    #[inline(always)]
    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        let (peek, available) = bits.peek15();
        let (symbol, len) = self.state.decode_peeked_checked(
            peek,
            available,
            "RAR 5 empty Huffman table",
            "RAR 5 invalid Huffman code",
        )?;
        bits.skip(len);
        Ok(symbol)
    }
}

#[derive(Clone, Copy)]
struct BitReader<'a> {
    input: &'a [u8],
    byte_pos: usize,
    // MSB-first; bits below `cache_bits` may preview the next input bytes.
    cache: u64,
    cache_bits: u32,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self::at(input, 0)
    }

    fn at(input: &'a [u8], bit_pos: usize) -> Self {
        debug_assert!(bit_pos.div_ceil(8) <= input.len());
        let mut reader = Self {
            input,
            byte_pos: bit_pos / 8,
            cache: 0,
            cache_bits: 0,
        };
        let offset = (bit_pos % 8) as u32;
        if offset != 0 {
            reader.refill();
            reader.skip(offset.min(reader.cache_bits) as usize);
        }
        reader
    }

    #[inline(always)]
    fn position(&self) -> usize {
        self.byte_pos * 8 - self.cache_bits as usize
    }

    #[inline(always)]
    fn refill(&mut self) {
        if let Some(bytes) = self
            .input
            .get(self.byte_pos..)
            .and_then(|rest| rest.first_chunk::<8>())
        {
            self.cache |= u64::from_be_bytes(*bytes) >> self.cache_bits;
            let whole = (64 - self.cache_bits) & !7;
            self.byte_pos += (whole / 8) as usize;
            self.cache_bits += whole;
        } else {
            // Inline: any call here spills the burst's reader to the stack.
            while self.cache_bits <= 56 && self.byte_pos < self.input.len() {
                self.cache |= u64::from(self.input[self.byte_pos]) << (56 - self.cache_bits);
                self.byte_pos += 1;
                self.cache_bits += 8;
            }
        }
    }

    /// The next 15 bits, most significant first, with zeros past the end of
    /// the input, and how many of them are real (at most 15).
    #[inline(always)]
    fn peek15(&mut self) -> (u32, usize) {
        if self.cache_bits < 15 {
            self.refill();
        }
        ((self.cache >> 49) as u32, self.cache_bits.min(15) as usize)
    }

    /// Consumes `count` bits already seen through [`Self::peek15`].
    #[inline(always)]
    fn skip(&mut self, count: usize) {
        debug_assert!(count <= self.cache_bits as usize);
        self.cache <<= count;
        self.cache_bits -= count as u32;
    }

    #[inline(always)]
    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let count = u32::from(count);
        if count == 0 {
            return Ok(0);
        }
        if count > 32 || self.cache_bits < count {
            return self.read_bits_slow(count);
        }
        let value = (self.cache >> (64 - count)) as u32;
        self.skip(count as usize);
        Ok(value)
    }

    #[inline(never)]
    fn read_bits_slow(&mut self, count: u32) -> Result<u32> {
        let remaining = (self.input.len().saturating_sub(self.byte_pos))
            .saturating_mul(8)
            .saturating_add(self.cache_bits as usize);
        // Refusal consumes nothing, even for wide reads.
        if remaining < count as usize {
            return Err(Error::NeedMoreInput);
        }
        if count > 32 {
            // Wider internal reads keep the low 32 bits.
            let mut value = 0u32;
            let mut left = count;
            while left != 0 {
                let take = left.min(16);
                value = (value << take) | self.read_bits(take as u8)?;
                left -= take;
            }
            return Ok(value);
        }
        self.refill();
        let value = (self.cache >> (64 - count)) as u32;
        self.skip(count as usize);
        Ok(value)
    }

    /// A call-free loop over a copy, so the reader stays in registers per literal.
    #[inline(always)]
    fn literal_burst<B: Budget>(
        &mut self,
        table: &HuffmanState<B>,
        end: usize,
        out: &mut [u8],
    ) -> usize {
        if B::LIMITED {
            return 0;
        }
        let mut bits = *self;
        let mut count = 0;
        while count < out.len() && bits.position() < end {
            let (peek, available) = bits.peek15();
            let entry = table.quick_entry(peek);
            let len = (entry & 15) as usize;
            if entry == 0 || entry >= 256 << 4 || len > available {
                break;
            }
            bits.skip(len);
            out[count] = (entry >> 4) as u8;
            count += 1;
        }
        *self = bits;
        count
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    super::canonical::validate_counts(count, "RAR 5 oversubscribed Huffman table")
}

#[cfg(test)]
#[path = "rar50/streaming_copy_tests.rs"]
mod streaming_copy_tests;

#[cfg(test)]
#[path = "rar50/huffman_tests.rs"]
mod huffman_tests;

#[cfg(test)]
#[path = "rar50/bit_reader_tests.rs"]
mod bit_reader_tests;

#[cfg(test)]
#[path = "rar50/checkpoint_tests.rs"]
mod checkpoint_tests;

#[cfg(all(test, feature = "write"))]
#[path = "rar50/history_retention_tests.rs"]
mod history_retention_tests;

#[cfg(test)]
mod bit_lookup_tests;
#[cfg(test)]
#[path = "rar50/history_window_tests.rs"]
mod history_window_tests;
