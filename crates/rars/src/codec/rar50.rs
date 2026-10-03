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

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    super::canonical::validate_counts(count, "RAR 5 oversubscribed Huffman table")
}
