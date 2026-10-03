#[cfg(feature = "write")]
mod encoder;
#[cfg(feature = "write")]
pub(crate) use encoder::{
    filtered_members, unpack29_encode_literals_with_options_and_progress,
    unpack29_encode_ppmd_with_progress, MAX_VM_DELTA_FILTER_BLOCK_SIZE,
};
#[cfg(feature = "write")]
pub use encoder::{
    unpack29_encode_literals, unpack29_encode_literals_with_options, unpack29_encode_ppmd,
    unpack29_encode_ppmd_literals, unpack29_encode_ppmd_with_filter, ChainEngine, EncodeOptions,
    Unpack29Encoder,
};

mod standard_filters;
#[cfg(all(test, feature = "write"))]
use standard_filters::{
    apply_standard_filter, apply_standard_filter_with_control, audio_decode_with_control,
    itanium_decode, itanium_decode_with_control, rgb_decode_with_control,
};
use standard_filters::{apply_standard_filter_with_allowance, identify_standard_filter};

use super::filters::DeltaErrorMessages;
#[cfg(all(test, feature = "write"))]
use super::filters::MAX_DELTA_CHANNELS;
use super::ppmd::{PpmdByteReader, PpmdState};
use super::rarvm;
use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};
use std::io::{Read, Write};

const MAIN_COUNT: usize = 299;
const OFFSET_COUNT: usize = 60;
const LOW_OFFSET_COUNT: usize = 17;
const LENGTH_COUNT: usize = 28;
const LEVEL_COUNT: usize = 20;
const TABLE_COUNT: usize = MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT + LENGTH_COUNT;
const MAX_HISTORY: usize = 4 * 1024 * 1024;
const STREAM_CHUNK: usize = 1024 * 1024;
// RARVM's standard AUDIO filter reserves an eight-bit-ish compatibility
// range wider than WinRAR's usual 1..=4 channel choices. UnRAR accepts up to
// 128; keep this distinct from DELTA's 1024-channel ceiling.
const MAX_AUDIO_CHANNELS: usize = 128;
const MAX_VM_GLOBAL_DATA: usize = 0x2000;
const VM_SYSTEM_GLOBAL_SIZE: usize = 64;
const MAX_VM_USER_GLOBAL_DATA: usize = MAX_VM_GLOBAL_DATA - VM_SYSTEM_GLOBAL_SIZE;
const MAX_VM_CODE_SIZE: usize = 64 * 1024;
const MAX_VM_PROGRAMS: usize = 8192;
const MAX_VM_FILTERS: usize = 8192;

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
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];
const OFFSET_BITS: [u8; OFFSET_COUNT] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];
const SHORT_BASES: [usize; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];
const INVALID_MATCH_OFFSET: usize = usize::MAX;

pub fn unpack29_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack29::new();
    decoder.decode_non_solid_member(input, output_size)
}

/// The filters the RAR 2.9 family ships as RarVM programs.
///
/// Narrower than [`crate::FilterKind`], which names every filter any format
/// can apply. The conversion below is where a filter this family cannot encode
/// is turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rar29Filter {
    E8,
    E8E9,
    Delta { channels: usize },
    Itanium,
    Rgb { width: usize, pos_r: usize },
    Audio { channels: usize },
}

impl TryFrom<crate::FilterKind> for Rar29Filter {
    type Error = crate::UnsupportedFilterKind;

    fn try_from(kind: crate::FilterKind) -> std::result::Result<Self, Self::Error> {
        use crate::FilterKind as Kind;
        match kind {
            Kind::E8 => Ok(Self::E8),
            Kind::E8E9 => Ok(Self::E8E9),
            Kind::Delta { channels } => Ok(Self::Delta { channels }),
            Kind::Itanium => Ok(Self::Itanium),
            Kind::Rgb { width, pos_r } => Ok(Self::Rgb { width, pos_r }),
            Kind::Audio { channels } => Ok(Self::Audio { channels }),
            // No wildcard arm: an eighth filter has to be decided about here.
            kind @ Kind::Arm => Err(crate::UnsupportedFilterKind(kind)),
        }
    }
}

fn rar29_delta_messages() -> DeltaErrorMessages {
    DeltaErrorMessages {
        invalid_channels: "RAR 2.9 DELTA filter channel count is invalid",
        zero_channels: "RAR 2.9 DELTA filter has zero channels",
        truncated_source: "RAR 2.9 DELTA filter source is truncated",
    }
}

#[derive(Debug, Clone)]
pub struct Unpack29 {
    pub(crate) read_control: crate::read_control::ReadControl,
    state: Reader29State<Allowance>,
}
impl Clone for Reader29State<Allowance> {
    fn clone(&self) -> Self {
        self.try_clone().expect("unlimited RAR3 decoder copy")
    }
}
impl Default for Unpack29 {
    fn default() -> Self {
        Self::new()
    }
}
impl Unpack29 {
    pub fn new() -> Self {
        Self {
            read_control: Default::default(),
            state: Reader29State::with_allowance(&Allowance::default()),
        }
    }
    pub fn reset_non_solid(&mut self) {
        self.state.reset_non_solid();
    }
    pub fn decode_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member_owned(input, output_size)
            .map(Buffer::into_vec)
    }
    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.state.read_control = self.read_control.clone();
        self.state.decode_member_to(input, output_size, out)
    }
    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member_from_reader(input, output_size, out)
    }
    pub fn decode_non_solid_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_non_solid_member_owned(input, output_size)
            .map(Buffer::into_vec)
    }
    pub fn decode_non_solid_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_non_solid_member_to(input, output_size, out)
    }
    pub fn decode_non_solid_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_non_solid_member_from_reader(input, output_size, out)
    }
}
#[derive(Debug)]
pub(crate) struct Reader29State<B: Budget> {
    pub(crate) read_control: crate::read_control::ReadControl,
    bits: BitReader<B>,
    levels: [u8; TABLE_COUNT],
    main: Huffman<B>,
    offsets: Huffman<B>,
    low_offsets: Huffman<B>,
    lengths: Huffman<B>,
    old_offsets: [usize; 4],
    last_offset: usize,
    last_length: usize,
    last_low_offset: usize,
    low_offset_repeats: usize,
    pending_match: Option<(usize, usize)>,
    in_lz_block: bool,
    block_mode: BlockMode,
    ppmd: PpmdState<B>,
    ppmd_esc: u8,
    filters: Buffer<VmFilter<B>, B>,
    programs: Buffer<VmProgram<B>, B>,
    last_filter: usize,
    base_offset: usize,
    output: Buffer<u8, B>,
    last_block_end: Option<LzBlockEnd>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockMode {
    Lz,
    Ppmd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LzBlockEnd {
    SameFileNewTable,
    NewFileKeepTables,
    NewFileNewTables,
}

fn require_ppmd_symbol(symbol: Option<u8>) -> Result<u8> {
    symbol.ok_or(Error::InvalidData("RAR 2.9 PPMd model is corrupt"))
}

#[derive(Debug)]
struct VmFilter<B: Budget = Allowance> {
    program: usize,
    start: usize,
    size: usize,
    regs: [u32; 7],
    global_data: Buffer<u8, B>,
}

#[derive(Debug)]
struct VmProgram<B: Budget = Allowance> {
    kind: VmProgramKind<B>,
    block_size: usize,
    exec_count: u32,
    globals: Buffer<u8, B>,
}

#[derive(Debug)]
enum VmProgramKind<B: Budget = Allowance> {
    Standard(StandardFilter),
    Generic(rarvm::OwnedProgram<B>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandardFilter {
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
}

impl<B: Budget> Reader29State<B> {
    pub(crate) fn with_allowance(allowance: &B) -> Self {
        Self {
            read_control: crate::read_control::ReadControl::default(),
            bits: BitReader::with_allowance(allowance),
            levels: [0; TABLE_COUNT],
            main: Huffman::with_allowance(allowance),
            offsets: Huffman::with_allowance(allowance),
            low_offsets: Huffman::with_allowance(allowance),
            lengths: Huffman::with_allowance(allowance),
            // UnRAR uses an invalid all-bits-one distance here. If a malformed
            // stream repeats a distance before defining one, CopyString sees
            // it as unavailable history and writes deterministic zeroes.
            old_offsets: [INVALID_MATCH_OFFSET; 4],
            last_offset: INVALID_MATCH_OFFSET,
            last_length: 0,
            last_low_offset: 0,
            low_offset_repeats: 0,
            pending_match: None,
            in_lz_block: false,
            block_mode: BlockMode::Lz,
            ppmd: PpmdState::with_allowance(allowance),
            ppmd_esc: 2,
            filters: Buffer::new(allowance),
            programs: Buffer::new(allowance),
            last_filter: 0,
            base_offset: 0,
            output: Buffer::new(allowance),
            last_block_end: None,
        }
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        let allowance = self.output.allowance();
        Ok(Self {
            read_control: self.read_control.clone(),
            bits: self.bits.try_clone()?,
            levels: self.levels,
            main: self.main.try_clone()?,
            offsets: self.offsets.try_clone()?,
            low_offsets: self.low_offsets.try_clone()?,
            lengths: self.lengths.try_clone()?,
            old_offsets: self.old_offsets,
            last_offset: self.last_offset,
            last_length: self.last_length,
            last_low_offset: self.last_low_offset,
            low_offset_repeats: self.low_offset_repeats,
            pending_match: self.pending_match,
            in_lz_block: self.in_lz_block,
            block_mode: self.block_mode,
            ppmd: self.ppmd.try_clone()?,
            ppmd_esc: self.ppmd_esc,
            filters: Buffer::try_collect(
                self.filters.iter().map(|filter| {
                    Ok(VmFilter {
                        program: filter.program,
                        start: filter.start,
                        size: filter.size,
                        regs: filter.regs,
                        global_data: Buffer::copied(&filter.global_data, &allowance)?,
                    })
                }),
                &allowance,
            )?,
            programs: Buffer::try_collect(
                self.programs.iter().map(|program| {
                    Ok(VmProgram {
                        kind: match &program.kind {
                            VmProgramKind::Standard(kind) => VmProgramKind::Standard(*kind),
                            VmProgramKind::Generic(program) => {
                                VmProgramKind::Generic(program.try_clone()?)
                            }
                        },
                        block_size: program.block_size,
                        exec_count: program.exec_count,
                        globals: Buffer::copied(&program.globals, &allowance)?,
                    })
                }),
                &allowance,
            )?,
            last_filter: self.last_filter,
            base_offset: self.base_offset,
            output: Buffer::copied(&self.output, &allowance)?,
            last_block_end: self.last_block_end,
        })
    }
    pub fn reset_non_solid(&mut self) {
        let control = self.read_control.clone();
        *self = Self::with_allowance(&self.output.allowance());
        self.read_control = control;
    }

    pub fn decode_non_solid_member_owned(
        &mut self,
        input: &[u8],
        output_size: usize,
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
        self.reset_non_solid();
        self.decode_member_owned(input, output_size)
    }

    pub fn decode_non_solid_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.read_control.check_codec()?;
        self.reset_non_solid();
        self.decode_member_to(input, output_size, out)
    }

    pub fn decode_non_solid_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.read_control.check_codec()?;
        let control = self.read_control.clone();
        let input = &mut control.reader(input);
        self.reset_non_solid();
        self.decode_member_from_reader(input, output_size, out)
    }

    pub fn decode_member_owned(
        &mut self,
        input: &[u8],
        output_size: usize,
    ) -> Result<Buffer<u8, B>> {
        let mut out = Buffer::new(&self.output.allowance());
        self.decode_member_to(input, output_size, &mut out)?;
        Ok(out)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.decode_loaded_member_to(input, output_size, out)
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.read_control.check_codec()?;
        let control = self.read_control.clone();
        let input = &mut control.reader(input);
        self.bits = BitReader::with_allowance(&self.output.allowance());
        self.bits.input.read_to_end(input)?;
        self.decode_bits_member_to(output_size, out)
    }

    /// Decodes one complete packed member while retaining solid dictionary,
    /// table, PPMd and VM state for the next member.
    fn decode_loaded_member_to(
        &mut self,
        packed: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.read_control.check_codec()?;
        self.bits = BitReader::from_bytes_with_allowance(packed, &self.output.allowance())?;
        self.decode_bits_member_to(output_size, out)
    }
    fn decode_bits_member_to(&mut self, output_size: usize, out: &mut impl Write) -> Result<()> {
        // `last_block_end` describes control flow within one member. A solid
        // follower legitimately starts after the previous member's new-file
        // marker, so do not mistake that marker for an early end in this one.
        self.last_block_end = None;
        let start = self.current_pos();
        let final_target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.9 output size overflows"))?;
        let mut flushed = start;
        let mut target = start.saturating_add(STREAM_CHUNK).min(final_target);
        // Empty members in solid mode still carry their own block init bytes
        // (typically the (esc, 0) end-of-block marker + 4-byte range coder
        // flush). When output_size is zero, decode_until skips its loop body
        // and never reads tables, so do the init here so finish_member can
        // observe the block end.
        if final_target == start && !self.in_lz_block && !self.bits.input.is_empty() {
            self.read_tables().map_err(|error| match error {
                Error::NeedMoreInput => Error::InvalidData("RAR 2.9 bitstream is truncated"),
                error => error,
            })?;
            self.in_lz_block = true;
        }

        while flushed < final_target {
            self.decode_until(target).map_err(|error| match error {
                Error::NeedMoreInput => Error::InvalidData("RAR 2.9 bitstream is truncated"),
                error => error,
            })?;

            let safe_end = self.safe_flush_end(flushed, target, final_target)?;
            if safe_end <= flushed {
                target = self
                    .current_pos()
                    .saturating_add(STREAM_CHUNK)
                    .min(final_target);
                continue;
            }

            let decoded = self.filtered_range_owned(flushed, safe_end, start)?;
            out.write_all(&decoded).map_err(Error::from)?;
            flushed = safe_end;
            self.trim_history(flushed, self.current_pos());
            target = self
                .current_pos()
                .saturating_add(STREAM_CHUNK)
                .min(final_target);
        }
        if self.pending_match.is_some() {
            return Err(Error::InvalidData(
                "RAR 2.9 member produces more output than its declared size",
            ));
        }
        self.finish_member().map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.9 bitstream is truncated"),
            error => error,
        })?;
        Ok(())
    }

    fn decode_until(&mut self, target: usize) -> Result<()> {
        let mut poller = self.read_control.poller();
        while self.current_pos() < target {
            poller.check_codec(self.current_pos())?;
            self.drain_pending_match(target)?;
            if self.current_pos() >= target {
                break;
            }
            if !self.in_lz_block {
                if matches!(
                    self.last_block_end,
                    Some(LzBlockEnd::NewFileKeepTables | LzBlockEnd::NewFileNewTables)
                ) {
                    return Err(Error::InvalidData(
                        "RAR 2.9 member ended before its declared size",
                    ));
                }
                self.read_tables()?;
                self.in_lz_block = true;
            }
            match self.block_mode {
                BlockMode::Lz => self.decode_lz(target)?,
                BlockMode::Ppmd => self.decode_ppmd(target)?,
            }
        }
        Ok(())
    }

    fn read_tables(&mut self) -> Result<()> {
        self.bits.align_byte();
        if self.bits.peek_bit()? != 0 {
            let first_byte = self.bits.read_bits(8)? as u8;
            self.ppmd.set_read_control(self.read_control.clone());
            self.ppmd
                .decode_init(first_byte, &mut self.bits, &mut self.ppmd_esc)?;
            self.block_mode = BlockMode::Ppmd;
            return Ok(());
        }
        self.bits.read_bit()?;
        self.block_mode = BlockMode::Lz;
        let keep_tables = self.bits.read_bit()? != 0;
        self.last_low_offset = 0;
        self.low_offset_repeats = 0;
        if !keep_tables {
            self.levels = [0; TABLE_COUNT];
        }

        let level_lengths = Self::read_level_lengths(&mut self.bits)?;
        let level_decoder =
            Huffman::from_lengths_with_allowance(&level_lengths, &self.output.allowance())?;
        let mut new_levels = [0u8; TABLE_COUNT];
        let mut pos = 0usize;
        while pos < TABLE_COUNT {
            let symbol = level_decoder.decode(&mut self.bits)?;
            match symbol {
                0..=15 => {
                    new_levels[pos] = (self.levels[pos].wrapping_add(symbol as u8)) & 0x0f;
                    pos += 1;
                }
                16 => {
                    if pos == 0 {
                        return Err(Error::InvalidData("RAR 2.9 table repeat at start"));
                    }
                    let count = 3 + self.bits.read_bits(3)? as usize;
                    let value = new_levels[pos - 1];
                    fill_levels(&mut new_levels, &mut pos, count, value)?;
                }
                17 => {
                    if pos == 0 {
                        return Err(Error::InvalidData("RAR 2.9 long table repeat at start"));
                    }
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    let value = new_levels[pos - 1];
                    fill_levels(&mut new_levels, &mut pos, count, value)?;
                }
                18 => {
                    let count = 3 + self.bits.read_bits(3)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                _ => {
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
            }
        }

        self.levels = new_levels;
        self.main = Huffman::from_lengths_with_allowance(
            &self.levels[..MAIN_COUNT],
            &self.output.allowance(),
        )?;
        self.offsets = Huffman::from_lengths_with_allowance(
            &self.levels[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT],
            &self.output.allowance(),
        )?;
        self.low_offsets = Huffman::from_lengths_with_allowance(
            &self.levels[MAIN_COUNT + OFFSET_COUNT..MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT],
            &self.output.allowance(),
        )?;
        self.lengths = Huffman::from_lengths_with_allowance(
            &self.levels[MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT..],
            &self.output.allowance(),
        )?;
        Ok(())
    }

    fn read_level_lengths(bits: &mut BitReader<B>) -> Result<[u8; LEVEL_COUNT]> {
        let mut lengths = [0u8; LEVEL_COUNT];
        let mut pos = 0usize;
        while pos < LEVEL_COUNT {
            let value = bits.read_bits(4)? as u8;
            if value == 15 {
                let zero_count = bits.read_bits(4)? as usize;
                if zero_count == 0 {
                    lengths[pos] = 15;
                    pos += 1;
                } else {
                    pos = pos.saturating_add(zero_count + 2).min(LEVEL_COUNT);
                }
            } else {
                lengths[pos] = value;
                pos += 1;
            }
        }
        Ok(lengths)
    }

    fn decode_lz(&mut self, output_size: usize) -> Result<()> {
        let mut poller = self.read_control.poller();
        while self.current_pos() < output_size {
            poller.check_codec(self.current_pos())?;
            let symbol = self.main.decode(&mut self.bits)?;
            match symbol {
                0..=255 => self.output.try_push(symbol as u8)?,
                256 => {
                    self.read_end_of_block()?;
                    return Ok(());
                }
                257 => {
                    self.read_vm_code()?;
                }
                258 => {
                    if self.last_length != 0 {
                        self.copy_match(self.last_length, self.last_offset, output_size)?;
                    }
                }
                259..=262 => {
                    let index = symbol - 259;
                    let offset = self.old_offsets[index];
                    let length_slot = self.lengths.decode(&mut self.bits)?;
                    let mut length = LENGTH_BASES[length_slot] + 2;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    self.rotate_old_offset(index);
                    self.last_offset = offset;
                    self.last_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                263..=270 => {
                    let index = symbol - 263;
                    let mut offset = SHORT_BASES[index] + 1;
                    offset += self.bits.read_bits(SHORT_BITS[index])? as usize;
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = 2;
                    self.copy_match(2, offset, output_size)?;
                }
                _ => {
                    let length_slot = symbol - 271;
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
            }
        }
        Ok(())
    }

    fn decode_ppmd(&mut self, output_size: usize) -> Result<()> {
        let mut poller = self.read_control.poller();
        while self.current_pos() < output_size {
            poller.check_codec(self.current_pos())?;
            let symbol = require_ppmd_symbol(self.ppmd.decode_symbol(&mut self.bits)?)?;
            if symbol != self.ppmd_esc {
                self.output.try_push(symbol)?;
                continue;
            }

            let next = require_ppmd_symbol(self.ppmd.decode_symbol(&mut self.bits)?)?;
            match next {
                0 => {
                    self.in_lz_block = false;
                    return Ok(());
                }
                1 => self.output.try_push(self.ppmd_esc)?,
                2 => {
                    return Err(Error::InvalidData(
                        "RAR 2.9 member ended before its declared size",
                    ));
                }
                3 => {
                    self.read_vm_code_ppmd()?;
                }
                4 => {
                    let mut offset = 0usize;
                    for _ in 0..3 {
                        offset = (offset << 8) | self.read_ppmd_required_byte()? as usize;
                    }
                    offset += 2;
                    let length = self.read_ppmd_required_byte()? as usize + 32;
                    self.copy_match(length, offset, output_size)?;
                }
                5 => {
                    let length = self.read_ppmd_required_byte()? as usize + 4;
                    self.copy_match(length, 1, output_size)?;
                }
                6..=u8::MAX => {
                    return Err(Error::InvalidData("RAR 2.9 PPMd command is invalid"));
                }
            }
        }
        Ok(())
    }

    fn read_ppmd_required_byte(&mut self) -> Result<u8> {
        require_ppmd_symbol(self.ppmd.decode_symbol(&mut self.bits)?)
    }

    fn finish_ppmd_member(&mut self) -> Result<bool> {
        let symbol = require_ppmd_symbol(self.ppmd.decode_symbol(&mut self.bits)?)?;
        if symbol != self.ppmd_esc {
            return Err(Error::InvalidData("RAR 2.9 PPMd member has trailing data"));
        }
        let next = require_ppmd_symbol(self.ppmd.decode_symbol(&mut self.bits)?)?;
        match next {
            2 => {
                self.in_lz_block = false;
                Ok(true)
            }
            0 => {
                self.in_lz_block = false;
                self.read_tables()?;
                self.in_lz_block = true;
                Ok(false)
            }
            _ => Err(Error::InvalidData("RAR 2.9 PPMd member has trailing data")),
        }
    }

    fn finish_member(&mut self) -> Result<()> {
        loop {
            let finished = match self.block_mode {
                BlockMode::Lz => self.finish_lz_member()?,
                BlockMode::Ppmd => self.finish_ppmd_member()?,
            };
            if finished {
                return Ok(());
            }
        }
    }

    fn finish_lz_member(&mut self) -> Result<bool> {
        if !self.in_lz_block {
            return Ok(true);
        }
        let symbol = self.main.decode(&mut self.bits)?;
        if symbol != 256 {
            return Err(Error::InvalidData("RAR 2.9 LZ member has trailing data"));
        }
        match self.read_end_of_block()? {
            LzBlockEnd::SameFileNewTable => {
                self.read_tables()?;
                self.in_lz_block = true;
                Ok(false)
            }
            LzBlockEnd::NewFileKeepTables | LzBlockEnd::NewFileNewTables => Ok(true),
        }
    }

    fn read_end_of_block(&mut self) -> Result<LzBlockEnd> {
        let end = self.read_end_of_block_inner()?;
        self.last_block_end = Some(end);
        Ok(end)
    }

    fn read_end_of_block_inner(&mut self) -> Result<LzBlockEnd> {
        if self.bits.read_bit()? != 0 {
            self.in_lz_block = false;
            return Ok(LzBlockEnd::SameFileNewTable);
        }
        if self.bits.read_bit()? != 0 {
            self.in_lz_block = false;
            Ok(LzBlockEnd::NewFileNewTables)
        } else {
            self.in_lz_block = true;
            Ok(LzBlockEnd::NewFileKeepTables)
        }
    }

    fn read_offset(&mut self) -> Result<usize> {
        let slot = self.offsets.decode(&mut self.bits)?;
        let mut offset = OFFSET_BASES[slot] + 1;
        let extra_bits = OFFSET_BITS[slot];
        if extra_bits != 0 {
            if slot > 9 {
                if extra_bits > 4 {
                    offset += (self.bits.read_bits(extra_bits - 4)? as usize) << 4;
                }
                if self.low_offset_repeats > 0 {
                    self.low_offset_repeats -= 1;
                    offset += self.last_low_offset;
                } else {
                    let low = self.low_offsets.decode(&mut self.bits)?;
                    if low == 16 {
                        self.low_offset_repeats = 15;
                        offset += self.last_low_offset;
                    } else {
                        self.last_low_offset = low;
                        offset += low;
                    }
                }
            } else {
                offset += self.bits.read_bits(extra_bits)? as usize;
            }
        }
        Ok(offset)
    }

    fn read_vm_code(&mut self) -> Result<()> {
        let mut poller = self.read_control.poller();
        let first_byte = self.bits.read_bits(8)?;
        let mut len = (first_byte & 7) + 1;
        if len == 7 {
            len = self.bits.read_bits(8)? + 7;
        } else if len == 8 {
            len = self.bits.read_bits(16)?;
        }
        let mut data = Buffer::with_capacity(len as usize, &self.output.allowance())?;
        for _ in 0..len {
            poller.check_codec(data.len())?;
            data.push_admitted(self.bits.read_bits(8)? as u8);
        }

        self.parse_vm_code_owned(first_byte, data)
    }

    fn read_vm_code_ppmd(&mut self) -> Result<()> {
        let mut poller = self.read_control.poller();
        let first_byte = u32::from(self.read_ppmd_required_byte()?);
        let mut len = (first_byte & 7) + 1;
        if len == 7 {
            len = u32::from(self.read_ppmd_required_byte()?) + 7;
        } else if len == 8 {
            len = (u32::from(self.read_ppmd_required_byte()?) << 8)
                | u32::from(self.read_ppmd_required_byte()?);
        }
        let mut data = Buffer::with_capacity(len as usize, &self.output.allowance())?;
        for _ in 0..len {
            poller.check_codec(data.len())?;
            data.push_admitted(self.read_ppmd_required_byte()?);
        }

        self.parse_vm_code_owned(first_byte, data)
    }

    fn parse_vm_code_owned(&mut self, first_byte: u32, data: Buffer<u8, B>) -> Result<()> {
        let mut vm = BitReader {
            input: data,
            bit_pos: 0,
        };
        let program_index = if first_byte & 0x80 != 0 {
            let value = vm.read_encoded_u32()?;
            if value == 0 {
                self.filters.clear();
                self.programs.clear();
                0
            } else {
                usize::try_from(value - 1)
                    .map_err(|_| Error::InvalidData("RAR 2.9 VM program index overflows"))?
            }
        } else {
            self.last_filter
        };
        if program_index > self.programs.len() {
            return Err(Error::InvalidData("RAR 2.9 VM program index is invalid"));
        }
        self.last_filter = program_index;
        let new_program = program_index == self.programs.len();

        let mut block_start = vm.read_encoded_u32()? as usize;
        if first_byte & 0x40 != 0 {
            block_start += 258;
        }
        block_start = self
            .current_pos()
            .checked_add(block_start)
            .ok_or(Error::InvalidData("RAR 2.9 VM block start overflows"))?;

        let mut block_size = self
            .programs
            .get(program_index)
            .map(|program| program.block_size)
            .unwrap_or(0);
        if first_byte & 0x20 != 0 {
            block_size = vm.read_encoded_u32()? as usize;
        }

        let mut regs = [0u32; 7];
        regs[3] = 0x3c000;
        regs[4] = block_size as u32;
        if let Some(program) = self.programs.get(program_index) {
            regs[5] = program.exec_count;
        }
        if first_byte & 0x10 != 0 {
            let mask = vm.read_bits(7)?;
            for (index, reg) in regs.iter_mut().enumerate() {
                if mask & (1 << index) != 0 {
                    *reg = vm.read_encoded_u32()?;
                }
            }
        }

        if new_program {
            if self.programs.len() >= MAX_VM_PROGRAMS {
                return Err(Error::InvalidData("RAR 2.9 VM program limit exceeded"));
            }
            let code_size = vm.read_encoded_u32()? as usize;
            if code_size == 0 {
                return Err(Error::InvalidData("RAR 2.9 VM code is empty"));
            }
            if code_size >= MAX_VM_CODE_SIZE {
                return Err(Error::InvalidData("RAR 2.9 VM code is too large"));
            }
            let mut code = Buffer::with_capacity(code_size, &self.output.allowance())?;
            for _ in 0..code_size {
                code.push_admitted(vm.read_bits(8)? as u8);
            }
            let kind = identify_standard_filter(&code)
                .map(VmProgramKind::Standard)
                .map_or_else(
                    || {
                        rarvm::OwnedProgram::parse(&code, &self.output.allowance())
                            .map(VmProgramKind::Generic)
                    },
                    Ok,
                )?;
            self.programs.try_push(VmProgram {
                kind,
                block_size,
                exec_count: 0,
                globals: Buffer::new(&self.output.allowance()),
            })?;
        } else {
            // Equality is the new-program case above, and greater indices were
            // rejected before parsing the record.
            let program = &mut self.programs[program_index];
            program.exec_count = program.exec_count.wrapping_add(1);
            program.block_size = block_size;
        }

        let mut global_data = Buffer::new(&self.output.allowance());
        if first_byte & 0x08 != 0 {
            let data_size = vm.read_encoded_u32()? as usize;
            if data_size > MAX_VM_USER_GLOBAL_DATA {
                return Err(Error::InvalidData("RAR 2.9 VM global data is too large"));
            }
            global_data =
                Buffer::with_capacity(VM_SYSTEM_GLOBAL_SIZE + data_size, &self.output.allowance())?;
            global_data.resize(VM_SYSTEM_GLOBAL_SIZE, 0)?;
            for _ in 0..data_size {
                global_data.push_admitted(vm.read_bits(8)? as u8);
            }
        }

        if self.filters.len() >= MAX_VM_FILTERS {
            return Err(Error::InvalidData("RAR 2.9 VM filter limit exceeded"));
        }
        self.filters.try_push(VmFilter {
            program: program_index,
            start: block_start,
            size: block_size,
            regs,
            global_data,
        })?;
        Ok(())
    }

    fn filtered_range_owned(
        &mut self,
        start: usize,
        end: usize,
        member_start: usize,
    ) -> Result<Buffer<u8, B>> {
        let mut out = Buffer::with_capacity(end - start, &self.output.allowance())?;
        let mut pos = start;
        let filters = Buffer::collect(
            self.filters
                .iter()
                .enumerate()
                .filter_map(|(index, filter)| {
                    (filter.start >= start && filter.start + filter.size <= end).then_some(index)
                }),
            &self.output.allowance(),
        )?;
        let mut applied = Buffer::filled(self.filters.len(), false, &self.output.allowance())?;
        let mut index = 0;
        while index < filters.len() {
            let first = self
                .filters
                .get(filters[index])
                .ok_or(Error::InvalidData("RAR 2.9 VM filter is missing"))?;
            let filter_start = first.start;
            let filter_size = first.size;
            if filter_start < pos {
                return Err(Error::InvalidData("RAR 2.9 VM filters partially overlap"));
            }
            out.extend_from_slice(self.raw_range(pos, filter_start)?)
                .map_err(Into::into)?;
            let mut block = Buffer::copied(
                self.raw_range(filter_start, filter_start + filter_size)?,
                &self.output.allowance(),
            )?;
            let file_offset = filter_start
                .checked_sub(member_start)
                .ok_or(Error::InvalidData("RAR 2.9 VM filter starts before file"))?
                as u32;
            loop {
                let (program_index, regs, global_data) = {
                    let filter = self
                        .filters
                        .get(filters[index])
                        .ok_or(Error::InvalidData("RAR 2.9 VM filter is missing"))?;
                    (filter.program, filter.regs, &filter.global_data)
                };
                let program = self
                    .programs
                    .get_mut(program_index)
                    .ok_or(Error::InvalidData("RAR 2.9 VM program is missing"))?;
                match &program.kind {
                    VmProgramKind::Standard(standard) => apply_standard_filter_with_allowance(
                        *standard,
                        &mut block,
                        file_offset,
                        &regs,
                        &self.read_control,
                    )?,
                    VmProgramKind::Generic(generic) => {
                        let globals = if global_data.is_empty() {
                            &program.globals[..]
                        } else {
                            &global_data[..]
                        };
                        let result = generic.execute_with_control(
                            rarvm::Invocation {
                                input: &block,
                                regs,
                                global_data: globals,
                                file_offset: file_offset as u64,
                                exec_count: program.exec_count,
                            },
                            &self.read_control,
                        )?;
                        program.globals = result.globals;
                        block = result.output;
                    }
                }
                applied[filters[index]] = true;
                index += 1;
                let Some(next) = filters.get(index).and_then(|&next| self.filters.get(next)) else {
                    break;
                };
                if next.start != filter_start || next.size != block.len() {
                    break;
                }
            }
            out.extend_from_slice(&block).map_err(Into::into)?;
            pos = filter_start + filter_size;
        }
        out.extend_from_slice(self.raw_range(pos, end)?)
            .map_err(Into::into)?;
        let mut index = 0;
        self.filters.retain(|_| {
            let keep = !applied[index];
            index += 1;
            keep
        });
        Ok(out)
    }

    fn safe_flush_end(&self, start: usize, end: usize, final_target: usize) -> Result<usize> {
        let current = self.current_pos();
        let mut safe_end = end;
        for filter in &self.filters {
            let filter_end = filter
                .start
                .checked_add(filter.size)
                .ok_or(Error::InvalidData("RAR 2.9 VM filter size overflows"))?;
            if filter.start >= safe_end || filter_end <= start {
                continue;
            }
            if filter_end > final_target {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM filter extends beyond output",
                ));
            }
            if filter_end > current {
                safe_end = safe_end.min(filter.start);
            }
        }
        Ok(safe_end)
    }

    fn copy_match(&mut self, length: usize, offset: usize, output_size: usize) -> Result<()> {
        // A match reaching past the start of the stream writes zeroes rather
        // than failing. Current UnRAR makes the same decision with its
        // first-window flag, and libarchive reads from a zero-initialized
        // circular dictionary. The decision is taken once for the whole
        // match: a copy does not start on zeroes and cross into real bytes
        // partway.
        let before_window = offset > self.current_pos();
        for index in 0..length {
            if self.current_pos() >= output_size {
                self.pending_match = Some((length - index, offset));
                break;
            }
            let byte = if before_window {
                0
            } else {
                let src = self.current_pos() - offset;
                *self
                    .raw_byte(src)
                    .ok_or(Error::InvalidData("RAR 2.9 match distance is out of range"))?
            };
            self.output.try_push(byte)?;
        }
        Ok(())
    }

    fn drain_pending_match(&mut self, output_size: usize) -> Result<()> {
        let Some((length, offset)) = self.pending_match.take() else {
            return Ok(());
        };
        self.copy_match(length, offset, output_size)
    }

    fn push_old_offset(&mut self, offset: usize) {
        self.old_offsets[3] = self.old_offsets[2];
        self.old_offsets[2] = self.old_offsets[1];
        self.old_offsets[1] = self.old_offsets[0];
        self.old_offsets[0] = offset;
    }

    fn rotate_old_offset(&mut self, index: usize) {
        let value = self.old_offsets[index];
        for i in (1..=index).rev() {
            self.old_offsets[i] = self.old_offsets[i - 1];
        }
        self.old_offsets[0] = value;
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
                "RAR 2.9 retained history is unavailable",
            ));
        }
        let rel_start = start - self.base_offset;
        let rel_end = end - self.base_offset;
        self.output
            .get(rel_start..rel_end)
            .ok_or(Error::InvalidData(
                "RAR 2.9 retained history is unavailable",
            ))
    }

    fn trim_history(&mut self, flushed_pos: usize, current_pos: usize) {
        let keep_from = current_pos.saturating_sub(MAX_HISTORY);
        let keep_from = keep_from.min(flushed_pos);
        if keep_from <= self.base_offset {
            return;
        }
        let drain = keep_from - self.base_offset;
        self.output.discard_prefix(drain);
        self.base_offset = keep_from;
        self.filters
            .retain(|filter| filter.start + filter.size > self.base_offset);
    }
}

#[cfg(all(test, feature = "write"))]
impl Reader29State<Allowance> {
    fn filtered_range(&mut self, start: usize, end: usize, member_start: usize) -> Result<Vec<u8>> {
        self.filtered_range_owned(start, end, member_start)
            .map(Buffer::into_vec)
    }
    fn parse_vm_code(&mut self, first_byte: u32, data: Vec<u8>) -> Result<()> {
        self.parse_vm_code_owned(first_byte, data.into())
    }

    fn new() -> Self {
        Self::with_allowance(&Allowance::default())
    }
    fn decode_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        self.decode_member_owned(input, output_size)
            .map(Buffer::into_vec)
    }
    fn decode_non_solid_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        self.decode_non_solid_member_owned(input, output_size)
            .map(Buffer::into_vec)
    }
}
fn fill_levels(levels: &mut [u8], pos: &mut usize, count: usize, value: u8) -> Result<()> {
    let end = pos
        .checked_add(count)
        .ok_or(Error::InvalidData("RAR 2.9 table run overflows"))?;
    let end = end.min(levels.len());
    for item in &mut levels[*pos..end] {
        *item = value;
    }
    *pos = end;
    Ok(())
}

#[derive(Debug)]
struct Huffman<B: Budget = Allowance> {
    state: super::canonical::Huffman<B>,
}

impl<B: Budget> Huffman<B> {
    fn with_allowance(allowance: &B) -> Self {
        Self {
            state: super::canonical::Huffman::with_allowance(allowance),
        }
    }
    fn from_lengths_with_allowance(lengths: &[u8], allowance: &B) -> Result<Self> {
        let mut count = [0u16; 16];
        for &len in lengths {
            if len != 0 {
                count[len as usize] += 1;
            }
        }
        if count.iter().all(|&value| value == 0) {
            return Ok(Self::with_allowance(allowance));
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
    fn decode(&self, bits: &mut BitReader<B>) -> Result<usize> {
        self.state.decode(
            || bits.read_bit().map(|bit| bit as u16),
            "RAR 2.9 empty Huffman table",
            "RAR 2.9 invalid Huffman code",
        )
    }
}

#[cfg(all(test, feature = "write"))]
impl Huffman<Allowance> {
    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        Self::from_lengths_with_allowance(lengths, &Allowance::default())
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    super::canonical::validate_counts(count, "RAR 2.9 oversubscribed Huffman table")
}

#[derive(Debug)]
struct BitReader<B: Budget = Allowance> {
    input: Buffer<u8, B>,
    bit_pos: usize,
}

impl<B: Budget> BitReader<B> {
    fn with_allowance(allowance: &B) -> Self {
        Self {
            input: Buffer::new(allowance),
            bit_pos: 0,
        }
    }

    fn from_bytes_with_allowance(input: &[u8], allowance: &B) -> Result<Self> {
        Ok(Self {
            input: Buffer::copied(input, allowance)?,
            bit_pos: 0,
        })
    }
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            input: Buffer::copied(&self.input, &self.input.allowance())?,
            bit_pos: self.bit_pos,
        })
    }

    #[cfg(all(test, feature = "write"))]
    fn append(&mut self, input: &[u8]) {
        self.compact();
        self.input
            .extend_from_slice(input)
            .map_err(Into::into)
            .expect("test input allowance");
    }

    #[cfg(all(test, feature = "write"))]
    fn compact(&mut self) {
        let bytes = self.bit_pos / 8;
        if bytes == 0 {
            return;
        }
        self.input.discard_prefix(bytes);
        self.bit_pos -= bytes * 8;
    }

    fn align_byte(&mut self) {
        self.bit_pos = (self.bit_pos + 7) & !7;
    }

    fn peek_bit(&self) -> Result<u8> {
        self.peek_bits(1).map(|value| value as u8)
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
            return Err(Error::InvalidData("RAR 2.9 bit read is too wide"));
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

    fn read_encoded_u32(&mut self) -> Result<u32> {
        match self.read_bits(2)? {
            0 => self.read_bits(4),
            1 => {
                let high = self.read_bits(8)?;
                if high >= 16 {
                    Ok(high)
                } else {
                    Ok(0xffff_ff00 | (high << 4) | self.read_bits(4)?)
                }
            }
            2 => self.read_bits(16),
            _ => Ok((self.read_bits(16)? << 16) | self.read_bits(16)?),
        }
    }
}

impl<B: Budget> PpmdByteReader for BitReader<B> {
    fn read_ppmd_byte(&mut self) -> Result<u8> {
        self.read_bits(8).map(|value| value as u8)
    }
}

#[cfg(all(test, feature = "write"))]
impl BitReader<Allowance> {
    fn from_bytes(input: &[u8]) -> Self {
        Self::from_bytes_with_allowance(input, &Allowance::default()).expect("unlimited RAR3 input")
    }
}
