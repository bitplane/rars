#[cfg(feature = "write")]
mod encoder;
#[cfg(feature = "write")]
pub(crate) use encoder::unpack20_encode_auto_with_options_and_progress;
#[cfg(feature = "write")]
pub use encoder::{
    unpack20_encode_auto, unpack20_encode_auto_with_options, unpack20_encode_literals,
    unpack20_encode_literals_with_options, EncodeOptions, Unpack20Encoder,
};

use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};
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

pub fn unpack20_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack20::new();
    decoder.decode_member(input, output_size)
}

#[derive(Debug, Clone)]
pub struct Unpack20 {
    pub(crate) read_control: crate::read_control::ReadControl,
    state: Reader20State<Allowance>,
}
impl Clone for Reader20State<Allowance> {
    fn clone(&self) -> Self {
        self.try_clone().expect("unlimited legacy decoder copy")
    }
}
impl Unpack20 {
    pub fn new() -> Self {
        Self {
            read_control: crate::read_control::ReadControl::default(),
            state: Reader20State::with_allowance(&Allowance::default()),
        }
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
}
#[cfg(all(test, feature = "write"))]
impl Reader20State<Allowance> {
    fn new() -> Self {
        Self::with_allowance(&Allowance::default())
    }
    fn decode_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        self.decode_member_owned(input, output_size)
            .map(Buffer::into_vec)
    }
}
#[derive(Debug)]
pub(crate) struct Reader20State<B: Budget> {
    pub(crate) read_control: crate::read_control::ReadControl,
    bits: BitReader<B>,
    levels: [u8; OLD_LEVEL_COUNT],
    main: Huffman<B>,
    offsets: Huffman<B>,
    lengths: Huffman<B>,
    audio_tables: [Huffman<B>; MAX_CHANNELS],
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
    output: Buffer<u8, B>,
    base_offset: usize,
}

impl<B: Budget> Reader20State<B> {
    pub(crate) fn with_allowance(allowance: &B) -> Self {
        Self {
            read_control: crate::read_control::ReadControl::default(),
            bits: BitReader::with_allowance(allowance),
            levels: [0; OLD_LEVEL_COUNT],
            main: Huffman::with_allowance(allowance),
            offsets: Huffman::with_allowance(allowance),
            lengths: Huffman::with_allowance(allowance),
            audio_tables: std::array::from_fn(|_| Huffman::with_allowance(allowance)),
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
            output: Buffer::new(allowance),
            base_offset: 0,
        }
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            read_control: self.read_control.clone(),
            bits: self.bits.try_clone()?,
            levels: self.levels,
            main: self.main.try_clone()?,
            offsets: self.offsets.try_clone()?,
            lengths: self.lengths.try_clone()?,
            audio_tables: [
                self.audio_tables[0].try_clone()?,
                self.audio_tables[1].try_clone()?,
                self.audio_tables[2].try_clone()?,
                self.audio_tables[3].try_clone()?,
            ],
            audio_block: self.audio_block,
            channels: self.channels,
            cur_channel: self.cur_channel,
            audio: self.audio,
            channel_delta: self.channel_delta,
            old_offsets: self.old_offsets,
            last_offset: self.last_offset,
            last_length: self.last_length,
            pending_match: self.pending_match,
            in_block: self.in_block,
            output: Buffer::copied(&self.output, &self.output.allowance())?,
            base_offset: self.base_offset,
        })
    }
    pub fn decode_member_owned(
        &mut self,
        input: &[u8],
        output_size: usize,
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.0 output size overflows"))?;
        if !input.is_empty() {
            self.bits = BitReader::with_allowance(&self.output.allowance());
        }
        self.bits.append(input)?;
        self.decode_until(target).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.0 bitstream is truncated"),
            error => error,
        })?;
        self.read_last_tables()?;
        let out = Buffer::copied(self.raw_range(start, target), &self.output.allowance())?;
        self.trim_history(target, target);
        Ok(out)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.read_control.check_codec()?;
        let decoded = self.decode_member_owned(input, output_size)?;
        out.write_all(&decoded).map_err(Error::from)
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
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.0 output size overflows"))?;
        self.bits = BitReader::with_allowance(&self.output.allowance());
        self.bits.input.read_to_end(input)?;
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

        let decoded = self.raw_range(start, target);
        out.write_all(decoded).map_err(Error::from)?;
        self.trim_history(target, target);
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
        let level_decoder = Huffman::with_lengths(&level_lengths, &self.output.allowance())?;
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
                _ => {
                    // 18: the pre-table contains exactly 19 symbols.
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
            }
        }

        self.levels = new_levels;
        if self.audio_block {
            for channel in 0..self.channels {
                let start = channel * AUDIO_COUNT;
                self.audio_tables[channel] = Huffman::with_lengths(
                    &self.levels[start..start + AUDIO_COUNT],
                    &self.output.allowance(),
                )?;
            }
        } else {
            self.main =
                Huffman::with_lengths(&self.levels[..MAIN_COUNT], &self.output.allowance())?;
            self.offsets = Huffman::with_lengths(
                &self.levels[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT],
                &self.output.allowance(),
            )?;
            self.lengths = Huffman::with_lengths(
                &self.levels[MAIN_COUNT + OFFSET_COUNT..TABLE_COUNT],
                &self.output.allowance(),
            )?;
        }
        Ok(())
    }

    fn read_level_lengths(bits: &mut BitReader<B>) -> Result<[u8; LEVEL_COUNT]> {
        let mut lengths = [0u8; LEVEL_COUNT];
        for length in &mut lengths {
            *length = bits.read_bits(4)? as u8;
        }
        Ok(lengths)
    }

    fn decode_lz(&mut self, output_size: usize) -> Result<()> {
        let mut poller = self.read_control.poller();
        while self.current_pos() < output_size {
            poller.check_codec(self.current_pos())?;
            if self.audio_block {
                self.decode_audio_byte()?;
                if !self.in_block {
                    return Ok(());
                }
                continue;
            }
            let symbol = self.main.decode(&mut self.bits)?;
            match symbol {
                0..=255 => self.output.try_push(symbol as u8)?,
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
                    offset += self.bits.read_bits(SHORT_BITS[index])? as usize;
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = 2;
                    self.copy_match(2, offset, output_size)?;
                }
                269 => {
                    self.in_block = false;
                    return Ok(());
                }
                _ => {
                    // 270..=297: the main table contains exactly 298 symbols.
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
        let byte = self.decode_audio(symbol as u8);
        self.output.try_push(byte)?;
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
        let mut offset = OFFSET_BASES[slot] + 1;
        if OFFSET_BITS[slot] != 0 {
            offset += self.bits.read_bits(OFFSET_BITS[slot])? as usize;
        }
        Ok(offset)
    }

    fn copy_match(&mut self, length: usize, offset: usize, output_size: usize) -> Result<()> {
        let offset = if offset == 0 { 1 } else { offset };
        // A match reaching past the start of the stream writes zeroes rather
        // than failing. WinRAR never clears its window and guards the copy
        // with a first-wrap flag instead, so those bytes read as zero there,
        // and an archive that leans on it stays readable here. The decision
        // is taken once for the whole match, as it is there: a copy does not
        // start on zeroes and cross into real bytes partway.
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
                self.raw_byte(src)
            };
            self.output.try_push(byte)?;
        }
        Ok(())
    }

    fn drain_pending_match(&mut self, output_size: usize) -> Result<()> {
        let Some((length, offset)) = self.pending_match.take() else {
            return Ok(());
        };
        self.copy_match(length, offset, output_size)?;
        Ok(())
    }

    fn read_last_tables(&mut self) -> Result<()> {
        if self.bits.remaining_bytes_from_current() < 5 {
            return Ok(());
        }
        if self.audio_block {
            if self.audio_tables[self.cur_channel].state.is_empty() {
                return Ok(());
            }
            if self.audio_tables[self.cur_channel].decode(&mut self.bits)? == 256 {
                self.read_tables()?;
                self.in_block = true;
            }
        } else {
            if self.main.state.is_empty() {
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

    fn raw_byte(&self, position: usize) -> u8 {
        // Decoder offsets are at most MAX_HISTORY; trimming retains that window.
        self.output[position - self.base_offset]
    }

    fn raw_range(&self, start: usize, end: usize) -> &[u8] {
        // Callers take the range before trimming the completed member.
        let rel_start = start - self.base_offset;
        let rel_end = end - self.base_offset;
        &self.output[rel_start..rel_end]
    }

    fn trim_history(&mut self, flushed_pos: usize, current_pos: usize) {
        let keep_from = current_pos.saturating_sub(MAX_HISTORY).min(flushed_pos);
        if keep_from <= self.base_offset {
            return;
        }
        let drain = keep_from - self.base_offset;
        self.output.discard_prefix(drain);
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
    fn with_lengths(lengths: &[u8], allowance: &B) -> Result<Self> {
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
            "RAR 2.0 empty Huffman table",
            "RAR 2.0 invalid Huffman code",
        )
    }
}

#[cfg(all(test, feature = "write"))]
impl Huffman<Allowance> {
    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        Self::with_lengths(lengths, &Allowance::default())
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    super::canonical::validate_counts(count, "RAR 2.0 oversubscribed Huffman table")
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

    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            input: Buffer::copied(&self.input, &self.input.allowance())?,
            bit_pos: self.bit_pos,
        })
    }
    fn append(&mut self, input: &[u8]) -> Result<()> {
        self.compact();
        self.input.extend_from_slice(input).map_err(Into::into)
    }

    fn compact(&mut self) {
        let bytes = self.bit_pos / 8;
        if bytes == 0 {
            return;
        }
        self.input.discard_prefix(bytes);
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

#[cfg(all(test, feature = "write"))]
impl BitReader<Allowance> {
    fn new() -> Self {
        Self::with_allowance(&Allowance::default())
    }
}
