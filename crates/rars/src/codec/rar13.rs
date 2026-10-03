#[cfg(feature = "write")]
mod encoder;
#[cfg(feature = "write")]
pub(crate) use encoder::unpack15_encode_with_options_and_progress;
#[cfg(feature = "write")]
pub use encoder::{
    find_long_lz, unpack15_encode, unpack15_encode_with_options, EncodeOptions, LongLz,
    Unpack15Encoder,
};

use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};
use std::io::{Read, Write};

const DEC_L1: &[u16] = &[
    0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff,
];
const POS_L1: &[u16] = &[0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const DEC_L2: &[u16] = &[
    0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff,
];
const POS_L2: &[u16] = &[0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const DEC_HF0: &[u16] = &[
    0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff,
];
const POS_HF0: &[u16] = &[0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const DEC_HF1: &[u16] = &[
    0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff,
];
const POS_HF1: &[u16] = &[0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const DEC_HF2: &[u16] = &[
    0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff,
];
const POS_HF2: &[u16] = &[0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const DEC_HF3: &[u16] = &[0x0800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const DEC_HF4: &[u16] = &[0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: &[u16] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

const SHORT_LEN1: [u8; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u8; 15] = [
    0x00, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];
const SHORT_LEN2: [u8; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u8; 15] = [
    0x00, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0,
];

pub fn unpack15_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack15::new();
    decoder.decode_member(input, output_size, false)
}

#[derive(Clone)]
pub struct Unpack15 {
    pub(crate) read_control: crate::read_control::ReadControl,
    state: Reader15State<Allowance>,
}
impl Clone for Reader15State<Allowance> {
    fn clone(&self) -> Self {
        self.try_clone().expect("unlimited legacy decoder copy")
    }
}
impl Unpack15 {
    pub fn new() -> Self {
        Self {
            read_control: crate::read_control::ReadControl::default(),
            state: Reader15State::with_allowance(&Allowance::default())
                .expect("unlimited legacy decoder"),
        }
    }
    pub fn decode_member(&mut self, input: &[u8], target: usize, solid: bool) -> Result<Vec<u8>> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member(input, target, solid)
            .map(Buffer::into_vec)
    }
    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        self.state.read_control = self.read_control.clone();
        self.state.decode_member_to(input, target, solid, out)
    }
    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        self.state.read_control = self.read_control.clone();
        self.state
            .decode_member_from_reader(input, target, solid, out)
    }
}
#[cfg(all(test, feature = "write"))]
impl Reader15State<Allowance> {
    fn new() -> Self {
        Self::with_allowance(&Allowance::default()).unwrap()
    }
}
pub(crate) struct Reader15State<B: Budget> {
    pub(crate) read_control: crate::read_control::ReadControl,
    bits: ReaderBits<B>,
    target: usize,
    output_written: usize,
    window: Buffer<u8, B>,
    unp_ptr: usize,
    prev_ptr: usize,
    first_win_done: bool,
    // State names follow RAR13_FORMAT_SPECIFICATION.md §6 so the codec state
    // lines up directly with the documented Unpack15 tables and traces.
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    buf60: u32,
    st_mode: bool,
    l_count: u32,
    flag_buf: u32,
    flags_cnt: i32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_length: u32,
    #[cfg(all(test, feature = "write"))]
    token_stats: DecodeTokenStats,
    #[cfg(all(test, feature = "write"))]
    old_distance_events: Vec<OldDistanceEvent>,
}

#[cfg(all(test, feature = "write"))]
#[derive(Clone, Copy, Debug, Default)]
struct DecodeTokenStats {
    literals: u64,
    st_literals: u64,
    st_matches: u64,
    st_match_bytes: u64,
    short_matches: u64,
    short_match_bytes: u64,
    repeat_matches: u64,
    repeat_match_bytes: u64,
    old_distance_matches: u64,
    old_distance_match_bytes: u64,
    old_distance_codes: [u64; 4],
    old_distance_near: u64,
    old_distance_far: u64,
    long_near_matches: u64,
    long_near_match_bytes: u64,
    long_far_matches: u64,
    long_far_match_bytes: u64,
}

#[cfg(all(test, feature = "write"))]
#[derive(Clone, Copy, Debug)]
struct OldDistanceEvent {
    output_position: usize,
    short_code: u32,
    distance: u32,
    length: u32,
    max_dist3: u32,
}

impl<B: Budget> Reader15State<B> {
    /// A decoder ready to read either a fresh member or a solid continuation.
    ///
    /// The starting state comes from `reset_non_solid` rather than being
    /// hand-copied, because the two drifted: the tables `init_huff` fills were
    /// left zeroed here. Nothing noticed while every archive opened with a
    /// non-solid member, since that member resets them before the first symbol
    /// is read. A first member carrying the solid flag skips the reset and
    /// decoded against zeroes.
    pub(crate) fn with_allowance(allowance: &B) -> Result<Self> {
        let mut decoder = Self {
            read_control: crate::read_control::ReadControl::default(),
            bits: ReaderBits::with_allowance(&[], allowance)?,
            target: 0,
            output_written: 0,
            window: Buffer::filled(0x10000, 0, allowance)?,
            unp_ptr: 0,
            prev_ptr: 0,
            first_win_done: false,
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            avr_plc: 0,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0,
            nhfb: 0,
            nlzb: 0,
            num_huf: 0,
            buf60: 0,
            st_mode: false,
            l_count: 0,
            flag_buf: 0,
            flags_cnt: 0,
            old_dist: [0; 4],
            old_dist_ptr: 0,
            last_dist: 0,
            last_length: 0,
            #[cfg(all(test, feature = "write"))]
            token_stats: DecodeTokenStats::default(),
            #[cfg(all(test, feature = "write"))]
            old_distance_events: Vec::new(),
        };
        decoder.reset_non_solid();
        Ok(decoder)
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            read_control: self.read_control.clone(),
            bits: self.bits.try_clone()?,
            target: self.target,
            output_written: self.output_written,
            window: Buffer::copied(&self.window, &self.window.allowance())?,
            unp_ptr: self.unp_ptr,
            prev_ptr: self.prev_ptr,
            first_win_done: self.first_win_done,
            ch_set: self.ch_set,
            ch_set_a: self.ch_set_a,
            ch_set_b: self.ch_set_b,
            ch_set_c: self.ch_set_c,
            n_to_pl: self.n_to_pl,
            n_to_pl_b: self.n_to_pl_b,
            n_to_pl_c: self.n_to_pl_c,
            avr_plc: self.avr_plc,
            avr_plc_b: self.avr_plc_b,
            avr_ln1: self.avr_ln1,
            avr_ln2: self.avr_ln2,
            avr_ln3: self.avr_ln3,
            max_dist3: self.max_dist3,
            nhfb: self.nhfb,
            nlzb: self.nlzb,
            num_huf: self.num_huf,
            buf60: self.buf60,
            st_mode: self.st_mode,
            l_count: self.l_count,
            flag_buf: self.flag_buf,
            flags_cnt: self.flags_cnt,
            old_dist: self.old_dist,
            old_dist_ptr: self.old_dist_ptr,
            last_dist: self.last_dist,
            last_length: self.last_length,
            #[cfg(all(test, feature = "write"))]
            token_stats: self.token_stats,
            #[cfg(all(test, feature = "write"))]
            old_distance_events: self.old_distance_events.clone(),
        })
    }
    pub fn decode_member(
        &mut self,
        input: &[u8],
        target: usize,
        solid: bool,
    ) -> Result<Buffer<u8, B>> {
        self.read_control.check_codec()?;
        let mut output = Buffer::with_capacity(target, &self.window.allowance())?;
        self.decode_member_to(input, target, solid, &mut output)?;
        Ok(output)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        self.read_control.check_codec()?;
        self.init_member(target, solid);
        self.bits = ReaderBits::with_allowance(input, &self.window.allowance())?;
        self.decode_loop(out)
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        self.read_control.check_codec()?;
        let control = self.read_control.clone();
        let input = &mut control.reader(input);
        const OUTPUT_CHUNK: usize = 64 * 1024;

        self.init_member(target, solid);
        self.bits = ReaderBits::with_allowance(&[], &self.window.allowance())?;
        self.bits.input.read_to_end(input)?;

        while self.output_written < self.target {
            let chunk_target = self
                .output_written
                .saturating_add(OUTPUT_CHUNK)
                .min(self.target);
            let mut chunk = Buffer::with_capacity(
                chunk_target - self.output_written,
                &self.window.allowance(),
            )?;
            self.decode_loop_until(chunk_target, &mut chunk)?;
            out.write_all(&chunk).map_err(Error::from)?;
        }
        Ok(())
    }

    fn init_member(&mut self, target: usize, solid: bool) {
        self.target = target;
        self.output_written = 0;
        self.flags_cnt = -2;
        self.flag_buf = 0;
        self.st_mode = false;
        self.l_count = 0;

        if !solid {
            self.reset_non_solid();
        }
    }

    fn decode_loop(&mut self, out: &mut impl Write) -> Result<()> {
        if self.target == 0 {
            return Ok(());
        }

        self.decode_loop_until(self.target, out)
    }

    fn decode_loop_until(&mut self, target: usize, out: &mut impl Write) -> Result<()> {
        let mut poller = self.read_control.poller();
        while self.output_written < target {
            poller.check_codec(self.output_written)?;
            self.decode_step(out)?;
        }

        Ok(())
    }

    fn decode_step(&mut self, out: &mut impl Write) -> Result<()> {
        if self.flags_cnt == -2 {
            self.get_flags_buf()?;
            self.flags_cnt = 8;
        }

        self.unp_ptr &= 0xffff;
        self.first_win_done |= self.prev_ptr > self.unp_ptr;
        self.prev_ptr = self.unp_ptr;

        if self.st_mode {
            return self.huff_decode(out);
        }

        self.flags_cnt -= 1;
        if self.flags_cnt < 0 {
            self.get_flags_buf()?;
            self.flags_cnt = 7;
        }

        if self.flag_buf & 0x80 != 0 {
            self.flag_buf = (self.flag_buf << 1) & 0xff;
            if self.nlzb > self.nhfb {
                self.long_lz(out)
            } else {
                self.huff_decode(out)
            }
        } else {
            self.flag_buf = (self.flag_buf << 1) & 0xff;
            self.flags_cnt -= 1;
            if self.flags_cnt < 0 {
                self.get_flags_buf()?;
                self.flags_cnt = 7;
            }
            if self.flag_buf & 0x80 != 0 {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                if self.nlzb > self.nhfb {
                    self.huff_decode(out)
                } else {
                    self.long_lz(out)
                }
            } else {
                self.flag_buf = (self.flag_buf << 1) & 0xff;
                self.short_lz(out)
            }
        }
    }

    fn reset_non_solid(&mut self) {
        self.window.fill(0);
        self.unp_ptr = 0;
        self.prev_ptr = 0;
        self.first_win_done = false;
        self.avr_plc_b = 0;
        self.avr_ln1 = 0;
        self.avr_ln2 = 0;
        self.avr_ln3 = 0;
        self.num_huf = 0;
        self.buf60 = 0;
        self.avr_plc = 0x3500;
        self.max_dist3 = 0x2001;
        self.nhfb = 0x80;
        self.nlzb = 0x80;
        self.old_dist = [u32::MAX; 4];
        self.old_dist_ptr = 0;
        self.last_dist = u32::MAX;
        self.last_length = 0;
        self.init_huff();
    }

    fn short_lz(&mut self, out: &mut impl Write) -> Result<()> {
        self.num_huf = 0;
        let mut bit_field = self.bits.get_bits();
        if self.l_count == 2 {
            self.bits.add_bits(1);
            if bit_field >= 0x8000 {
                #[cfg(all(test, feature = "write"))]
                {
                    self.token_stats.repeat_matches += 1;
                    self.token_stats.repeat_match_bytes += u64::from(self.last_length);
                }
                self.copy_string(self.last_dist, self.last_length, out)?;
                return Ok(());
            }
            bit_field = (bit_field << 1) & 0xffff;
            self.l_count = 0;
        }

        let bit_byte = (bit_field >> 8) as u8;
        let mut length = 0usize;
        // Both prefix tables cover every byte in either Buf60 state.
        // The exhaustive table test verifies that a matching entry always exists.
        if self.avr_ln1 < 37 {
            loop {
                let short_len = self.short_len1(length);
                let mask = (!(0xffu16 >> short_len)) as u8;
                if ((bit_byte ^ SHORT_XOR1[length]) & mask) == 0 {
                    break;
                }
                length += 1;
            }
            self.bits.add_bits(self.short_len1(length) as usize);
        } else {
            loop {
                let short_len = self.short_len2(length);
                let mask = (!(0xffu16 >> short_len)) as u8;
                if ((bit_byte ^ SHORT_XOR2[length]) & mask) == 0 {
                    break;
                }
                length += 1;
            }
            self.bits.add_bits(self.short_len2(length) as usize);
        }

        let mut length = length as u32;
        if length >= 9 {
            if length == 9 {
                self.l_count += 1;
                #[cfg(all(test, feature = "write"))]
                {
                    self.token_stats.repeat_matches += 1;
                    self.token_stats.repeat_match_bytes += u64::from(self.last_length);
                }
                self.copy_string(self.last_dist, self.last_length, out)?;
                return Ok(());
            }
            if length == 14 {
                self.l_count = 0;
                length = self.decode_num(self.bits.get_bits(), 3, DEC_L2, POS_L2) + 5;
                let distance = (self.bits.get_bits() >> 1) | 0x8000;
                self.bits.add_bits(15);
                self.last_length = length;
                self.last_dist = distance;
                #[cfg(all(test, feature = "write"))]
                {
                    self.token_stats.short_matches += 1;
                    self.token_stats.short_match_bytes += u64::from(length);
                }
                self.copy_string(distance, length, out)?;
                return Ok(());
            }

            self.l_count = 0;
            let save_length = length;
            let distance =
                self.old_dist[(self.old_dist_ptr.wrapping_sub((length - 9) as usize)) & 3];
            length = self.decode_num(self.bits.get_bits(), 2, DEC_L1, POS_L1) + 2;
            if length == 0x101 && save_length == 10 {
                self.buf60 ^= 1;
                return Ok(());
            }
            if distance > 256 {
                length += 1;
            }
            if distance >= self.max_dist3 {
                length += 1;
            }

            self.remember_match(distance, length);
            #[cfg(all(test, feature = "write"))]
            {
                self.old_distance_events.push(OldDistanceEvent {
                    output_position: self.output_written,
                    short_code: save_length,
                    distance,
                    length,
                    max_dist3: self.max_dist3,
                });
                self.token_stats.old_distance_matches += 1;
                self.token_stats.old_distance_match_bytes += u64::from(length);
                self.token_stats.old_distance_codes[(save_length - 10) as usize] += 1;
                if distance <= 256 {
                    self.token_stats.old_distance_near += 1;
                } else {
                    self.token_stats.old_distance_far += 1;
                }
            }
            self.copy_string(distance, length, out)?;
            return Ok(());
        }

        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_place =
            (self.decode_num(self.bits.get_bits(), 5, DEC_HF2, POS_HF2) & 0xff) as usize;
        let mut distance = self.ch_set_a[distance_place] as u32;
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance as u16;
        }
        length += 2;
        distance += 1;
        self.remember_match(distance, length);
        #[cfg(all(test, feature = "write"))]
        {
            self.token_stats.short_matches += 1;
            self.token_stats.short_match_bytes += u64::from(length);
        }
        self.copy_string(distance, length, out)
    }

    fn long_lz(&mut self, out: &mut impl Write) -> Result<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let bit_field = self.bits.get_bits();
        let mut length = if self.avr_ln2 >= 122 {
            self.decode_num(bit_field, 3, DEC_L2, POS_L2)
        } else if self.avr_ln2 >= 64 {
            self.decode_num(bit_field, 2, DEC_L1, POS_L1)
        } else if bit_field < 0x100 {
            self.bits.add_bits(16);
            bit_field
        } else {
            let mut length = 0u32;
            while ((bit_field << length) & 0x8000) == 0 {
                length += 1;
            }
            self.bits.add_bits((length + 1) as usize);
            length
        };

        self.avr_ln2 += length;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let bit_field = self.bits.get_bits();
        let distance_place = if self.avr_plc_b > 0x28ff {
            self.decode_num(bit_field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            self.decode_num(bit_field, 5, DEC_HF1, POS_HF1)
        } else {
            self.decode_num(bit_field, 4, DEC_HF0, POS_HF0)
        };

        self.avr_plc_b += distance_place;
        self.avr_plc_b -= self.avr_plc_b >> 8;

        let idx = (distance_place & 0xff) as usize;
        let mut distance;
        let mut new_distance_place;
        loop {
            distance = self.ch_set_b[idx] as u32;
            new_distance_place = self.n_to_pl_b[(distance & 0xff) as usize] as usize;
            self.n_to_pl_b[(distance & 0xff) as usize] =
                self.n_to_pl_b[(distance & 0xff) as usize].wrapping_add(1);
            distance += 1;
            if distance & 0xff == 0 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }

        self.ch_set_b[idx] = self.ch_set_b[new_distance_place];
        self.ch_set_b[new_distance_place] = distance as u16;

        distance = ((distance & 0xff00) | (self.bits.get_bits() >> 8)) >> 1;
        self.bits.add_bits(7);

        let old_avr3 = self.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        length += 3;
        if distance >= self.max_dist3 {
            length += 1;
        }
        if distance <= 256 {
            length += 8;
        }
        if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }

        self.remember_match(distance, length);
        #[cfg(all(test, feature = "write"))]
        if distance <= 256 {
            self.token_stats.long_near_matches += 1;
            self.token_stats.long_near_match_bytes += u64::from(length);
        } else {
            self.token_stats.long_far_matches += 1;
            self.token_stats.long_far_match_bytes += u64::from(length);
        }
        self.copy_string(distance, length, out)
    }

    fn huff_decode(&mut self, out: &mut impl Write) -> Result<()> {
        let bit_field = self.bits.get_bits();

        let mut byte_place = if self.avr_plc > 0x75ff {
            self.decode_num(bit_field, 8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            self.decode_num(bit_field, 6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            self.decode_num(bit_field, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            self.decode_num(bit_field, 5, DEC_HF1, POS_HF1)
        } else {
            self.decode_num(bit_field, 4, DEC_HF0, POS_HF0)
        } & 0xff;

        if self.st_mode {
            if byte_place == 0 && bit_field > 0x0fff {
                byte_place = 0x100;
            }
            if byte_place == 0 {
                let bit_field = self.bits.get_bits();
                self.bits.add_bits(1);
                if bit_field & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = false;
                    return Ok(());
                }

                let length = if bit_field & 0x4000 != 0 { 4 } else { 3 };
                self.bits.add_bits(1);
                let mut distance = self.decode_num(self.bits.get_bits(), 5, DEC_HF2, POS_HF2);
                distance = (distance << 5) | (self.bits.get_bits() >> 11);
                self.bits.add_bits(5);
                #[cfg(all(test, feature = "write"))]
                {
                    self.token_stats.st_matches += 1;
                    self.token_stats.st_match_bytes += u64::from(length);
                }
                self.copy_string(distance, length, out)?;
                return Ok(());
            }
            byte_place -= 1;
        } else {
            if self.num_huf >= 16 && self.flags_cnt == 0 {
                self.st_mode = true;
            }
            self.num_huf += 1;
        }

        self.avr_plc += byte_place;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }

        let byte = (self.ch_set[byte_place as usize] >> 8) as u8;
        #[cfg(all(test, feature = "write"))]
        if self.st_mode {
            self.token_stats.st_literals += 1;
        } else {
            self.token_stats.literals += 1;
        }
        self.put_byte(byte, out)?;

        let idx = byte_place as usize;
        let mut cur_byte;
        let mut new_byte_place;
        loop {
            cur_byte = self.ch_set[idx] as u32;
            new_byte_place = self.n_to_pl[(cur_byte & 0xff) as usize] as usize;
            self.n_to_pl[(cur_byte & 0xff) as usize] =
                self.n_to_pl[(cur_byte & 0xff) as usize].wrapping_add(1);
            cur_byte += 1;
            if cur_byte & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }

        self.ch_set[idx] = self.ch_set[new_byte_place];
        self.ch_set[new_byte_place] = cur_byte as u16;
        Ok(())
    }

    fn get_flags_buf(&mut self) -> Result<()> {
        let flags_place = self.decode_num(self.bits.get_bits(), 5, DEC_HF2, POS_HF2) as usize;
        if flags_place >= self.ch_set_c.len() {
            return Ok(());
        }

        let mut flags;
        let mut new_flags_place;
        loop {
            flags = self.ch_set_c[flags_place] as u32;
            new_flags_place = self.n_to_pl_c[(flags & 0xff) as usize] as usize;
            self.n_to_pl_c[(flags & 0xff) as usize] =
                self.n_to_pl_c[(flags & 0xff) as usize].wrapping_add(1);
            self.flag_buf = flags >> 8;
            flags += 1;
            if flags & 0xff == 0 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                break;
            }
        }

        self.ch_set_c[flags_place] = self.ch_set_c[new_flags_place];
        self.ch_set_c[new_flags_place] = flags as u16;
        Ok(())
    }

    fn decode_num(
        &mut self,
        num: u32,
        mut start_pos: u32,
        dec_tab: &[u16],
        pos_tab: &[u16],
    ) -> u32 {
        let num = num & 0xfff0;
        let mut i = 0usize;
        while dec_tab[i] as u32 <= num {
            start_pos += 1;
            i += 1;
        }
        self.bits.add_bits(start_pos as usize);
        ((num - if i > 0 { dec_tab[i - 1] as u32 } else { 0 }) >> (16 - start_pos))
            + pos_tab[start_pos as usize] as u32
    }

    fn copy_string(&mut self, distance: u32, length: u32, out: &mut impl Write) -> Result<()> {
        if self.output_written + length as usize > self.target {
            return Err(Error::InvalidData("RAR 1.3 match exceeds output size"));
        }

        if (!self.first_win_done && distance as usize > self.unp_ptr)
            || distance as usize > 0x10000
            || distance == 0
        {
            for _ in 0..length {
                self.put_byte(0, out)?;
            }
        } else {
            for _ in 0..length {
                let byte = self.window[(self.unp_ptr.wrapping_sub(distance as usize)) & 0xffff];
                self.put_byte(byte, out)?;
            }
        }
        Ok(())
    }

    fn put_byte(&mut self, byte: u8, out: &mut impl Write) -> Result<()> {
        if self.output_written >= self.target {
            return Err(Error::InvalidData("RAR 1.3 literal exceeds output size"));
        }
        self.window[self.unp_ptr] = byte;
        self.unp_ptr = (self.unp_ptr + 1) & 0xffff;
        out.write_all(&[byte]).map_err(Error::from)?;
        self.output_written += 1;
        Ok(())
    }

    fn remember_match(&mut self, distance: u32, length: u32) {
        self.old_dist[self.old_dist_ptr] = distance;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
    }

    fn short_len1(&self, pos: usize) -> u32 {
        if pos == 1 {
            self.buf60 + 3
        } else {
            SHORT_LEN1[pos] as u32
        }
    }

    fn short_len2(&self, pos: usize) -> u32 {
        if pos == 3 {
            self.buf60 + 3
        } else {
            SHORT_LEN2[pos] as u32
        }
    }

    fn init_huff(&mut self) {
        for i in 0..256 {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_b[i] = (i as u16) << 8;
            self.ch_set_a[i] = i as u16;
            self.ch_set_c[i] = (0u8.wrapping_sub(i as u8) as u16) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }
}

impl Default for Unpack15 {
    fn default() -> Self {
        Self::new()
    }
}

fn corr_huff(char_set: &mut [u16; 256], num_to_place: &mut [u8; 256]) {
    let mut pos = 0usize;
    for rank in (0..=7).rev() {
        for _ in 0..32 {
            char_set[pos] = (char_set[pos] & !0xff) | rank;
            pos += 1;
        }
    }
    *num_to_place = [0; 256];
    for rank in (0..=6).rev() {
        num_to_place[rank] = ((7 - rank) * 32) as u8;
    }
}

struct ReaderBits<B: Budget> {
    input: Buffer<u8, B>,
    bit_pos: usize,
}

impl<B: Budget> ReaderBits<B> {
    fn with_allowance(input: &[u8], allowance: &B) -> Result<Self> {
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

    fn get_bits(&self) -> u32 {
        let mut value = 0u32;
        for i in 0..16 {
            value <<= 1;
            let bit_index = self.bit_pos + i;
            let byte = self.input.get(bit_index / 8).copied().unwrap_or(0);
            value |= ((byte >> (7 - (bit_index % 8))) & 1) as u32;
        }
        value
    }

    fn add_bits(&mut self, count: usize) {
        self.bit_pos += count;
    }
}

#[cfg(all(test, feature = "write"))]
impl ReaderBits<Allowance> {
    fn new(input: &[u8]) -> Self {
        Self::with_allowance(input, &Allowance::default()).unwrap()
    }
}
