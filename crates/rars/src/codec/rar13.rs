use super::{Error, Result};
use std::io::{Read, Write};

const MATCH_HASH_BUCKETS: usize = 4096;
const MAX_LONG_MATCH_CANDIDATES: usize = 64;
const MAX_LONG_LZ_DISTANCE: usize = 0x7fff;

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

pub fn unpack15_encode(input: &[u8]) -> Result<Vec<u8>> {
    unpack15_encode_with_options(input, EncodeOptions::default())
}

pub fn unpack15_encode_with_options(input: &[u8], options: EncodeOptions) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut encoder = Unpack15Encoder::with_options(options);
    encoder.encode_member(input)
}

pub(crate) fn unpack15_encode_with_options_and_progress(
    input: &[u8],
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    Unpack15Encoder::with_options(options).encode_member_with_progress(input, progress)
}

pub fn unpack15_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack15::new();
    decoder.decode_member(input, output_size, false)
}

pub struct Unpack15Encoder {
    bits: BitWriter,
    options: EncodeOptions,
    // State names follow RAR13_FORMAT_SPECIFICATION.md §6 so the codec state
    // lines up directly with the documented Unpack15 tables and traces.
    ch_set: [u16; 256],
    ch_set_c: [u16; 256],
    ch_set_b: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    ch_set_a: [u16; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_length: u32,
    l_count: u32,
    #[cfg(test)]
    stmode_literal_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions {
    old_distance_tokens: bool,
    lazy_matching: bool,
    stmode_literal_runs: bool,
    max_long_match_distance: usize,
}

impl EncodeOptions {
    pub const fn new() -> Self {
        Self {
            old_distance_tokens: true,
            lazy_matching: true,
            stmode_literal_runs: true,
            max_long_match_distance: MAX_LONG_LZ_DISTANCE,
        }
    }

    pub const fn with_old_distance_tokens(mut self, enabled: bool) -> Self {
        self.old_distance_tokens = enabled;
        self
    }

    pub const fn with_lazy_matching(mut self, enabled: bool) -> Self {
        self.lazy_matching = enabled;
        self
    }

    pub const fn with_stmode_literal_runs(mut self, enabled: bool) -> Self {
        self.stmode_literal_runs = enabled;
        self
    }

    pub const fn with_max_long_match_distance(mut self, distance: usize) -> Self {
        self.max_long_match_distance = distance;
        self
    }

    pub const fn old_distance_tokens_enabled(self) -> bool {
        self.old_distance_tokens
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl Unpack15Encoder {
    pub fn new() -> Self {
        Self::with_options(EncodeOptions::default())
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        let mut encoder = Self {
            bits: BitWriter::new(),
            options,
            ch_set: [0; 256],
            ch_set_c: [0; 256],
            ch_set_b: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            ch_set_a: [0; 256],
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            num_huf: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            last_dist: u32::MAX,
            last_length: 0,
            l_count: 0,
            #[cfg(test)]
            stmode_literal_count: 0,
        };
        encoder.init_huff();
        encoder
    }

    pub fn encode_literals_only(mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.encode_literals_only_member(input)
    }

    fn encode_literals_only_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.bits = BitWriter::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_nhfb = self.nhfb;
            let mut plan_nlzb = self.nlzb;
            let mut plan_num_huf = self.num_huf;
            let mut group_enters_stmode = false;

            while flag_bits < 8 && pos < input.len() {
                let flag = huff_flag_bits(plan_nlzb <= plan_nhfb);
                if flag_bits + flag.len() > 8 {
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                payloads.push(EncodedToken::Literal(input[pos]));
                flag_bits += flag.len();
                if flag_bits == 8 && plan_num_huf >= 16 && pos + 1 < input.len() {
                    group_enters_stmode = true;
                }
                plan_num_huf += 1;
                pos += 1;
                plan_huff_effect(&mut plan_nhfb, &mut plan_nlzb);
            }

            self.emit_flags_byte(flags)?;
            self.emit_payloads(payloads)?;
            if group_enters_stmode {
                if self.options.stmode_literal_runs {
                    self.emit_stmode_literal_run(input, &[], &mut pos, false)?;
                }
                self.emit_stmode_exit()?;
            }
        }
        Ok(std::mem::take(&mut self.bits).finish())
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
        mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.bits = BitWriter::new();
        let buckets = long_lz_buckets(input);
        let mut pos = 0usize;
        let mut next_report = 0usize;
        while pos < input.len() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_encoder = self.clone_for_planning();
            let mut group_enters_stmode = false;

            while flag_bits < 8 && pos < input.len() {
                let state = plan_encoder.lz_plan_state();
                if let Some(token) = plan_encoder
                    .choose_lz_token(input, pos, &buckets, state, flag_bits)
                    .filter(|token| {
                        !self.options.lazy_matching
                            || !should_lazy_emit_literal(
                                input,
                                pos,
                                &buckets,
                                *token,
                                state.max_dist3,
                                self.options,
                            )
                    })
                {
                    let flag = token.flag_bits(state.nlzb, state.nhfb);
                    let next_pos = pos + token.length() as usize;
                    let leaves_unfillable_flag_bit =
                        flag_bits + flag.len() == 7 && next_pos < input.len();
                    if flag_bits + flag.len() <= 8 && !leaves_unfillable_flag_bit {
                        write_planned_flag_bits(&mut flags, flag_bits, flag);
                        flag_bits += flag.len();
                        pos = next_pos;
                        plan_encoder.emit_payloads(vec![token])?;
                        payloads.push(token);
                        continue;
                    }
                }

                let flag = huff_flag_bits(plan_encoder.nlzb <= plan_encoder.nhfb);
                if flag_bits + flag.len() > 8 {
                    break;
                }
                write_planned_flag_bits(&mut flags, flag_bits, flag);
                let literal = input[pos];
                payloads.push(EncodedToken::Literal(input[pos]));
                flag_bits += flag.len();
                if flag_bits == 8 && plan_encoder.num_huf >= 16 && pos + 1 < input.len() {
                    group_enters_stmode = true;
                }
                pos += 1;
                plan_encoder.emit_literal(literal)?;
            }

            self.emit_flags_byte(flags)?;
            self.emit_payloads(payloads)?;
            if group_enters_stmode {
                if self.options.stmode_literal_runs {
                    self.emit_stmode_literal_run(input, &buckets, &mut pos, true)?;
                }
                self.emit_stmode_exit()?;
            }
            if pos >= next_report {
                if progress.as_deref_mut().is_some_and(|report| !report(pos)) {
                    return Err(Error::Cancelled);
                }
                next_report = pos.saturating_add(1024 * 1024);
            }
        }
        if progress.is_some_and(|report| !report(input.len())) {
            return Err(Error::Cancelled);
        }
        Ok(std::mem::take(&mut self.bits).finish())
    }

    fn clone_for_planning(&self) -> Self {
        Self {
            bits: BitWriter::new(),
            options: self.options,
            ch_set: self.ch_set,
            ch_set_c: self.ch_set_c,
            ch_set_b: self.ch_set_b,
            n_to_pl: self.n_to_pl,
            n_to_pl_b: self.n_to_pl_b,
            n_to_pl_c: self.n_to_pl_c,
            ch_set_a: self.ch_set_a,
            avr_plc: self.avr_plc,
            avr_plc_b: self.avr_plc_b,
            avr_ln1: self.avr_ln1,
            avr_ln2: self.avr_ln2,
            avr_ln3: self.avr_ln3,
            max_dist3: self.max_dist3,
            nhfb: self.nhfb,
            nlzb: self.nlzb,
            num_huf: self.num_huf,
            old_dist: self.old_dist,
            old_dist_ptr: self.old_dist_ptr,
            last_dist: self.last_dist,
            last_length: self.last_length,
            l_count: self.l_count,
            #[cfg(test)]
            stmode_literal_count: self.stmode_literal_count,
        }
    }

    fn lz_plan_state(&self) -> LzPlanState {
        LzPlanState {
            last_dist: self.last_dist,
            last_length: self.last_length,
            old_dist: self.old_dist,
            old_dist_ptr: self.old_dist_ptr,
            max_dist3: self.max_dist3,
            nlzb: self.nlzb,
            nhfb: self.nhfb,
            l_count: self.l_count,
        }
    }

    fn choose_lz_token(
        &self,
        input: &[u8],
        pos: usize,
        buckets: &[Vec<usize>],
        state: LzPlanState,
        flag_bits: usize,
    ) -> Option<EncodedToken> {
        let candidates = find_lz_tokens(input, pos, buckets, state, self.options);
        candidates
            .into_iter()
            .filter(|token| {
                let flag_len = token.flag_bits(state.nlzb, state.nhfb).len();
                let next_pos = pos + token.length() as usize;
                next_pos == input.len()
                    || (flag_bits + flag_len != 7
                        && !(flag_len == 1 && flag_bits.is_multiple_of(2)))
            })
            .filter_map(|token| self.token_bit_cost(token, state).map(|cost| (token, cost)))
            .min_by(|(left, left_cost), (right, right_cost)| {
                let left_score = left_cost * 256 / left.length() as usize;
                let right_score = right_cost * 256 / right.length() as usize;
                left_score
                    .cmp(&right_score)
                    .then_with(|| right.length().cmp(&left.length()))
            })
            .map(|(token, _)| token)
    }

    fn token_bit_cost(&self, token: EncodedToken, state: LzPlanState) -> Option<usize> {
        let flag_cost = token.flag_bits(state.nlzb, state.nhfb).len();
        match token {
            EncodedToken::Literal(byte) => {
                let place = self
                    .ch_set
                    .iter()
                    .position(|&value| (value >> 8) as u8 == byte)?;
                Some(flag_cost + self.literal_place_bit_cost(place)?)
            }
            EncodedToken::RepeatLast(_) => {
                Some(flag_cost + self.repeat_last_bit_cost(state.l_count))
            }
            EncodedToken::ShortLz(token) => {
                let distance_value = token.distance.checked_sub(1)?;
                let distance_place = self
                    .ch_set_a
                    .iter()
                    .position(|&value| value as u32 == distance_value)?;
                Some(
                    flag_cost
                        + l_count_break_bit_cost(state.l_count)
                        + self.short_lz_prefix_bit_cost(token.length - 2)?
                        + decode_num_bit_cost(distance_place as u32, 5, DEC_HF2, POS_HF2)?,
                )
            }
            EncodedToken::OldDist(token) => {
                let length_code = old_dist_lz_length_code(
                    token.length,
                    token.distance,
                    state.max_dist3,
                    token.short_code,
                )?;
                Some(
                    flag_cost
                        + l_count_break_bit_cost(state.l_count)
                        + self.short_lz_prefix_bit_cost(token.short_code)?
                        + decode_num_bit_cost(length_code, 2, DEC_L1, POS_L1)?,
                )
            }
            EncodedToken::LongLz(token) => {
                let length_code = long_lz_length_code_for_distance(token, state.max_dist3)?;
                let distance_place = self.long_lz_distance_place(token.distance).ok()?;
                Some(
                    flag_cost
                        + self.long_lz_length_bit_cost(length_code)?
                        + self.long_lz_distance_bit_cost(distance_place)?
                        + 7,
                )
            }
        }
    }

    fn emit_payloads(&mut self, payloads: Vec<EncodedToken>) -> Result<()> {
        for payload in payloads {
            match payload {
                EncodedToken::Literal(byte) => self.emit_literal(byte)?,
                EncodedToken::ShortLz(short_lz) => {
                    self.emit_short_lz(short_lz)?;
                }
                EncodedToken::RepeatLast(repeat) => {
                    self.emit_repeat_last(repeat)?;
                }
                EncodedToken::OldDist(old_lz) => {
                    self.emit_old_dist_lz(old_lz)?;
                }
                EncodedToken::LongLz(long_lz) => {
                    self.emit_long_lz(long_lz)?;
                }
            }
        }

        Ok(())
    }

    fn emit_flags_byte(&mut self, flags: u8) -> Result<()> {
        let flags_place = self
            .ch_set_c
            .iter()
            .position(|&value| (value >> 8) as u8 == flags)
            .ok_or(Error::InvalidData("RAR 1.3 flag byte is not encodable"))?;
        emit_decode_num(&mut self.bits, flags_place as u32, 5, DEC_HF2, POS_HF2)?;

        let mut cur_flags;
        let mut new_flags_place;
        loop {
            cur_flags = self.ch_set_c[flags_place] as u32;
            new_flags_place = self.n_to_pl_c[(cur_flags & 0xff) as usize] as usize;
            self.n_to_pl_c[(cur_flags & 0xff) as usize] =
                self.n_to_pl_c[(cur_flags & 0xff) as usize].wrapping_add(1);
            cur_flags += 1;
            if cur_flags & 0xff == 0 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                break;
            }
        }

        self.ch_set_c[flags_place] = self.ch_set_c[new_flags_place];
        self.ch_set_c[new_flags_place] = cur_flags as u16;
        Ok(())
    }

    fn emit_literal(&mut self, byte: u8) -> Result<()> {
        let byte_place = self
            .ch_set
            .iter()
            .position(|&value| (value >> 8) as u8 == byte)
            .ok_or(Error::InvalidData("RAR 1.3 literal is not encodable"))?;
        self.emit_literal_place(byte_place, byte_place, true)
    }

    fn emit_stmode_literal(&mut self, byte: u8) -> Result<()> {
        let byte_place = self
            .ch_set
            .iter()
            .position(|&value| (value >> 8) as u8 == byte)
            .ok_or(Error::InvalidData(
                "RAR 1.3 stmode literal is not encodable",
            ))?;
        #[cfg(test)]
        {
            self.stmode_literal_count += 1;
        }
        self.emit_literal_place(byte_place + 1, byte_place, false)
    }

    fn emit_stmode_literal_run(
        &mut self,
        input: &[u8],
        buckets: &[Vec<usize>],
        pos: &mut usize,
        allow_lz: bool,
    ) -> Result<()> {
        while *pos + 1 < input.len() {
            if allow_lz
                && find_lz_token(
                    input,
                    *pos,
                    buckets,
                    LzPlanState {
                        last_dist: self.last_dist,
                        last_length: self.last_length,
                        old_dist: self.old_dist,
                        old_dist_ptr: self.old_dist_ptr,
                        max_dist3: self.max_dist3,
                        nlzb: self.nlzb,
                        nhfb: self.nhfb,
                        l_count: self.l_count,
                    },
                    self.options,
                )
                .is_some()
            {
                break;
            }
            self.emit_stmode_literal(input[*pos])?;
            *pos += 1;
        }
        Ok(())
    }

    fn emit_literal_place(
        &mut self,
        encoded_place: usize,
        decoded_place: usize,
        update_num_huf: bool,
    ) -> Result<()> {
        if encoded_place > self.ch_set.len() || decoded_place >= self.ch_set.len() {
            return Err(Error::InvalidData("RAR 1.3 literal is not encodable"));
        }

        let (start_pos, dec_tab, pos_tab) = if self.avr_plc > 0x75ff {
            (8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            (6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(
            &mut self.bits,
            encoded_place as u32,
            start_pos,
            dec_tab,
            pos_tab,
        )?;

        self.avr_plc += decoded_place as u32;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }
        if update_num_huf {
            self.num_huf += 1;
        }

        let idx = decoded_place;
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

    fn emit_short_lz(&mut self, short_lz: ShortLz) -> Result<()> {
        self.num_huf = 0;
        if self.l_count == 2 {
            self.bits.write_bits(0, 1);
            self.l_count = 0;
        }
        let length_place = short_lz.length - 2;
        self.emit_short_lz_code(length_place as usize)?;
        self.l_count = 0;

        self.avr_ln1 += length_place;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_value = short_lz.distance - 1;
        let distance_place = self
            .ch_set_a
            .iter()
            .position(|&value| value as u32 == distance_value)
            .ok_or(Error::InvalidData(
                "RAR 1.3 ShortLZ distance is not encodable",
            ))?;
        emit_decode_num(&mut self.bits, distance_place as u32, 5, DEC_HF2, POS_HF2)?;
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance_value as u16;
        }
        self.remember_match(short_lz.distance, short_lz.length);
        Ok(())
    }

    fn emit_repeat_last(&mut self, repeat: RepeatLastLz) -> Result<()> {
        if self.last_dist != repeat.distance || self.last_length != repeat.length {
            return Err(Error::InvalidData(
                "RAR 1.3 repeat-last state is not encodable",
            ));
        }
        self.num_huf = 0;
        if self.l_count == 2 {
            self.bits.write_bits(1, 1);
        } else {
            self.emit_short_lz_code(9)?;
            self.l_count += 1;
        }
        Ok(())
    }

    fn emit_old_dist_lz(&mut self, old_lz: OldDistLz) -> Result<()> {
        self.num_huf = 0;
        if self.l_count == 2 {
            self.bits.write_bits(0, 1);
            self.l_count = 0;
        }
        self.emit_short_lz_code(old_lz.short_code as usize)?;
        self.l_count = 0;

        let expected_distance = self.old_dist[(self
            .old_dist_ptr
            .wrapping_sub((old_lz.short_code - 9) as usize))
            & 3];
        if expected_distance != old_lz.distance {
            return Err(Error::InvalidData(
                "RAR 1.3 old-distance state is not encodable",
            ));
        }
        let length_code = old_dist_lz_length_code(
            old_lz.length,
            old_lz.distance,
            self.max_dist3,
            old_lz.short_code,
        )
        .ok_or(Error::InvalidData(
            "RAR 1.3 old-distance length is not encodable",
        ))?;
        emit_decode_num(&mut self.bits, length_code, 2, DEC_L1, POS_L1)?;
        self.remember_match(old_lz.distance, old_lz.length);
        Ok(())
    }

    fn emit_short_lz_code(&mut self, code: usize) -> Result<()> {
        let (code_len, code_byte) = if self.avr_ln1 < 37 {
            (self.short_len1(code), SHORT_XOR1[code])
        } else {
            (self.short_len2(code), SHORT_XOR2[code])
        };
        self.bits
            .write_bits((code_byte >> (8 - code_len)) as u32, code_len as usize);
        Ok(())
    }

    fn short_lz_prefix_bit_cost(&self, code: u32) -> Option<usize> {
        let code = usize::try_from(code).ok()?;
        if code >= SHORT_XOR1.len() {
            return None;
        }
        Some(if self.avr_ln1 < 37 {
            self.short_len1(code)
        } else {
            self.short_len2(code)
        } as usize)
    }

    fn repeat_last_bit_cost(&self, l_count: u32) -> usize {
        if l_count == 2 {
            1
        } else {
            self.short_lz_prefix_bit_cost(9)
                .expect("repeat-last code is encodable")
        }
    }

    fn emit_long_lz(&mut self, long_lz: LongLz) -> Result<()> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let length_code = self.long_lz_length_code(long_lz).ok_or(Error::InvalidData(
            "RAR 1.3 LongLZ match length is not encodable for distance",
        ))?;
        emit_long_lz_length(&mut self.bits, self.avr_ln2, length_code)?;
        self.avr_ln2 += length_code;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let distance_place = self.long_lz_distance_place(long_lz.distance)?;
        let (start_pos, dec_tab, pos_tab) = if self.avr_plc_b > 0x28ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(
            &mut self.bits,
            distance_place as u32,
            start_pos,
            dec_tab,
            pos_tab,
        )?;
        self.avr_plc_b += distance_place as u32;
        self.avr_plc_b -= self.avr_plc_b >> 8;

        let idx = distance_place;
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

        let low_byte = ((long_lz.distance << 1) & 0xff) as u8;
        self.bits.write_bits((low_byte >> 1) as u32, 7);

        let old_avr3 = self.avr_ln3;
        if length_code != 1 && length_code != 4 {
            if length_code == 0 && long_lz.distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) {
            self.max_dist3 = 0x7f00;
        } else {
            self.max_dist3 = 0x2001;
        }

        self.remember_match(long_lz.distance, long_lz.length);
        Ok(())
    }

    fn long_lz_length_code(&self, long_lz: LongLz) -> Option<u32> {
        long_lz_length_code_for_distance(long_lz, self.max_dist3)
    }

    fn long_lz_distance_place(&self, target_distance: u32) -> Result<usize> {
        let wanted_high = ((target_distance << 1) & 0xff00) as u16;
        self.ch_set_b
            .iter()
            .position(|&value| value & 0xff00 == wanted_high)
            .ok_or(Error::InvalidData(
                "RAR 1.3 LongLZ distance is not encodable",
            ))
    }

    fn literal_place_bit_cost(&self, place: usize) -> Option<usize> {
        if self.avr_plc > 0x75ff {
            decode_num_bit_cost(place as u32, 8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            decode_num_bit_cost(place as u32, 6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            decode_num_bit_cost(place as u32, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            decode_num_bit_cost(place as u32, 5, DEC_HF1, POS_HF1)
        } else {
            decode_num_bit_cost(place as u32, 4, DEC_HF0, POS_HF0)
        }
    }

    fn long_lz_length_bit_cost(&self, length_code: u32) -> Option<usize> {
        if self.avr_ln2 >= 122 {
            decode_num_bit_cost(length_code, 3, DEC_L2, POS_L2)
        } else if self.avr_ln2 >= 64 {
            decode_num_bit_cost(length_code, 2, DEC_L1, POS_L1)
        } else if length_code <= 7 {
            Some(length_code as usize + 1)
        } else if length_code < 0x100 {
            Some(16)
        } else {
            None
        }
    }

    fn long_lz_distance_bit_cost(&self, distance_place: usize) -> Option<usize> {
        if self.avr_plc_b > 0x28ff {
            decode_num_bit_cost(distance_place as u32, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            decode_num_bit_cost(distance_place as u32, 5, DEC_HF1, POS_HF1)
        } else {
            decode_num_bit_cost(distance_place as u32, 4, DEC_HF0, POS_HF0)
        }
    }

    fn emit_stmode_exit(&mut self) -> Result<()> {
        let (start_pos, dec_tab, pos_tab) = if self.avr_plc > 0x75ff {
            (8, DEC_HF4, POS_HF4)
        } else if self.avr_plc > 0x5dff {
            (6, DEC_HF3, POS_HF3)
        } else if self.avr_plc > 0x35ff {
            (5, DEC_HF2, POS_HF2)
        } else if self.avr_plc > 0x0dff {
            (5, DEC_HF1, POS_HF1)
        } else {
            (4, DEC_HF0, POS_HF0)
        };
        emit_decode_num(&mut self.bits, 0, start_pos, dec_tab, pos_tab)?;
        self.bits.write_bits(1, 1);
        self.num_huf = 0;
        Ok(())
    }

    fn init_huff(&mut self) {
        for i in 0..256 {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_c[i] = (0u8.wrapping_sub(i as u8) as u16) << 8;
            self.ch_set_b[i] = (i as u16) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        for i in 0..256 {
            self.ch_set_a[i] = i as u16;
        }
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }

    fn remember_match(&mut self, distance: u32, length: u32) {
        self.old_dist[self.old_dist_ptr] = distance;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
    }

    fn short_len1(&self, pos: usize) -> u8 {
        if pos == 1 {
            3
        } else {
            SHORT_LEN1[pos]
        }
    }

    fn short_len2(&self, pos: usize) -> u8 {
        if pos == 3 {
            3
        } else {
            SHORT_LEN2[pos]
        }
    }
}

impl Default for Unpack15Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
struct LzPlanState {
    last_dist: u32,
    last_length: u32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    max_dist3: u32,
    nlzb: u32,
    nhfb: u32,
    l_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedToken {
    Literal(u8),
    ShortLz(ShortLz),
    RepeatLast(RepeatLastLz),
    OldDist(OldDistLz),
    LongLz(LongLz),
}

impl EncodedToken {
    fn length(self) -> u32 {
        match self {
            Self::Literal(_) => 1,
            Self::ShortLz(token) => token.length,
            Self::RepeatLast(token) => token.length,
            Self::OldDist(token) => token.length,
            Self::LongLz(token) => token.length,
        }
    }

    fn flag_bits(self, nlzb: u32, nhfb: u32) -> &'static [bool] {
        match self {
            Self::Literal(_) => huff_flag_bits(nlzb <= nhfb),
            Self::LongLz(_) => long_lz_flag_bits(nlzb > nhfb),
            Self::ShortLz(_) | Self::RepeatLast(_) | Self::OldDist(_) => &[false, false],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShortLz {
    pub distance: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepeatLastLz {
    pub distance: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OldDistLz {
    pub distance: u32,
    pub length: u32,
    pub short_code: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongLz {
    pub distance: u32,
    pub length: u32,
}

fn huff_flag_bits(prefer_huff_on_one: bool) -> &'static [bool] {
    if prefer_huff_on_one {
        &[true]
    } else {
        &[false, true]
    }
}

fn long_lz_flag_bits(prefer_long_lz_on_one: bool) -> &'static [bool] {
    if prefer_long_lz_on_one {
        &[true]
    } else {
        &[false, true]
    }
}

fn write_planned_flag_bits(flags: &mut u8, start: usize, bits: &[bool]) {
    for (offset, &bit) in bits.iter().enumerate() {
        if bit {
            *flags |= 1 << (7 - start - offset);
        }
    }
}

fn plan_huff_effect(nhfb: &mut u32, nlzb: &mut u32) {
    *nhfb += 16;
    if *nhfb > 0xff {
        *nhfb = 0x90;
        *nlzb >>= 1;
    }
}

fn l_count_break_bit_cost(l_count: u32) -> usize {
    usize::from(l_count == 2)
}

fn find_lz_token(
    input: &[u8],
    pos: usize,
    buckets: &[Vec<usize>],
    state: LzPlanState,
    options: EncodeOptions,
) -> Option<EncodedToken> {
    find_lz_tokens(input, pos, buckets, state, options)
        .into_iter()
        .next()
}

fn find_lz_tokens(
    input: &[u8],
    pos: usize,
    buckets: &[Vec<usize>],
    state: LzPlanState,
    options: EncodeOptions,
) -> Vec<EncodedToken> {
    let mut tokens = Vec::with_capacity(4);
    if let Some(repeat) = find_repeat_last_lz(input, pos, state.last_dist, state.last_length) {
        tokens.push(EncodedToken::RepeatLast(repeat));
    }
    if options.old_distance_tokens {
        if let Some(old_lz) = find_old_dist_lz(
            input,
            pos,
            state.old_dist,
            state.old_dist_ptr,
            state.max_dist3,
        ) {
            tokens.push(EncodedToken::OldDist(old_lz));
        }
    }
    if let Some(short_lz) = find_short_lz(input, pos) {
        tokens.push(EncodedToken::ShortLz(short_lz));
    }
    if let Some(long_lz) = find_long_lz_with_buckets(
        input,
        pos,
        options.max_long_match_distance,
        buckets,
        MAX_LONG_MATCH_CANDIDATES,
    )
    .filter(|long_lz| long_lz_length_code_for_distance(*long_lz, state.max_dist3).is_some())
    {
        tokens.push(EncodedToken::LongLz(long_lz));
    }
    tokens
}

fn should_lazy_emit_literal(
    input: &[u8],
    pos: usize,
    buckets: &[Vec<usize>],
    current: EncodedToken,
    max_dist3: u32,
    options: EncodeOptions,
) -> bool {
    if !matches!(current, EncodedToken::ShortLz(_) | EncodedToken::LongLz(_))
        || pos + 1 >= input.len()
    {
        return false;
    }

    let next = find_lz_token(
        input,
        pos + 1,
        buckets,
        LzPlanState {
            last_dist: u32::MAX,
            last_length: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            max_dist3,
            nlzb: 0,
            nhfb: 0,
            l_count: 0,
        },
        options,
    );
    next.is_some_and(|next| {
        matches!(next, EncodedToken::ShortLz(_) | EncodedToken::LongLz(_))
            && next.length() >= current.length() + 2
    })
}

fn find_short_lz(input: &[u8], pos: usize) -> Option<ShortLz> {
    if pos < 2 {
        return None;
    }

    let max_distance = pos.min(256);
    let mut best = ShortLz {
        distance: 0,
        length: 0,
    };
    for distance in 1..=max_distance {
        let mut length = 0usize;
        while length < 10
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3
            && (length > best.length as usize
                || (length == best.length as usize && distance < best.distance as usize))
        {
            best = ShortLz {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

fn find_repeat_last_lz(
    input: &[u8],
    pos: usize,
    last_dist: u32,
    last_length: u32,
) -> Option<RepeatLastLz> {
    if last_dist == u32::MAX || last_dist == 0 || last_length == 0 {
        return None;
    }
    let distance = usize::try_from(last_dist).ok()?;
    let length = usize::try_from(last_length).ok()?;
    if distance > pos || pos.checked_add(length)? > input.len() {
        return None;
    }
    let matches = (0..length).all(|offset| input[pos + offset] == input[pos + offset - distance]);
    matches.then_some(RepeatLastLz {
        distance: last_dist,
        length: last_length,
    })
}

fn find_old_dist_lz(
    input: &[u8],
    pos: usize,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    _max_dist3: u32,
) -> Option<OldDistLz> {
    let mut best = OldDistLz {
        distance: 0,
        length: 0,
        short_code: 0,
    };
    for short_code in 10..=13 {
        let distance = old_dist[(old_dist_ptr.wrapping_sub((short_code - 9) as usize)) & 3];
        if distance == u32::MAX || distance == 0 {
            continue;
        }
        let Ok(distance_usize) = usize::try_from(distance) else {
            continue;
        };
        if distance_usize > pos {
            continue;
        }
        let mut length = 0usize;
        while length < 258
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance_usize]
        {
            length += 1;
        }
        if length >= 3
            && old_dist_lz_is_encodable(length as u32, distance, short_code)
            && length > best.length as usize
        {
            best = OldDistLz {
                distance,
                length: length as u32,
                short_code,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

fn old_dist_lz_is_encodable(length: u32, distance: u32, short_code: u32) -> bool {
    old_dist_lz_length_code(length, distance, 0x2001, short_code).is_some()
        && old_dist_lz_length_code(length, distance, 0x7f00, short_code).is_some()
}

fn old_dist_lz_length_code(
    length: u32,
    distance: u32,
    max_dist3: u32,
    short_code: u32,
) -> Option<u32> {
    let decoded_bonus = u32::from(distance > 256) + u32::from(distance >= max_dist3);
    let length_code = length.checked_sub(2 + decoded_bonus)?;
    if short_code == 10 && length_code == 0xff {
        return None;
    }
    Some(length_code)
}

fn long_lz_length_code_for_distance(long_lz: LongLz, max_dist3: u32) -> Option<u32> {
    let decoded_bonus =
        u32::from(long_lz.distance >= max_dist3) + u32::from(long_lz.distance <= 256);
    long_lz.length.checked_sub(3 + decoded_bonus)
}

pub fn find_long_lz(input: &[u8], pos: usize, max_match_distance: usize) -> Option<LongLz> {
    if pos < 257 {
        return None;
    }

    let max_distance = pos.min(MAX_LONG_LZ_DISTANCE).min(max_match_distance);
    if max_distance < 257 {
        return None;
    }
    let mut best = LongLz {
        distance: 0,
        length: 0,
    };
    for distance in 257..=max_distance {
        let mut length = 0usize;
        while length < 258
            && pos + length < input.len()
            && input[pos + length] == input[pos + length - distance]
        {
            length += 1;
        }
        if length >= 3 && length > best.length as usize {
            best = LongLz {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 3).then_some(best)
}

fn find_long_lz_with_buckets(
    input: &[u8],
    pos: usize,
    max_match_distance: usize,
    buckets: &[Vec<usize>],
    max_candidates: usize,
) -> Option<LongLz> {
    if pos < 257 || pos + 2 >= input.len() || max_candidates == 0 {
        return None;
    }

    let max_distance = pos.min(MAX_LONG_LZ_DISTANCE).min(max_match_distance);
    if max_distance < 257 {
        return None;
    }
    let max_length = (input.len() - pos).min(258);
    let mut best = LongLz {
        distance: 0,
        length: 0,
    };
    let mut checked = 0usize;
    for &candidate in buckets[match_hash(input, pos)].iter().rev() {
        if candidate >= pos {
            continue;
        }
        let distance = pos - candidate;
        if distance > max_distance {
            break;
        }
        if distance < 257 {
            continue;
        }
        checked += 1;
        let mut length = 0usize;
        while length < max_length && input[pos + length] == input[pos + length - distance] {
            length += 1;
        }
        if length >= 3
            && (length > best.length as usize
                || (length == best.length as usize && distance < best.distance as usize))
        {
            best = LongLz {
                distance: distance as u32,
                length: length as u32,
            };
            if length == max_length {
                break;
            }
        }
        if checked >= max_candidates {
            break;
        }
    }

    (best.length >= 3).then_some(best)
}

fn long_lz_buckets(input: &[u8]) -> Vec<Vec<usize>> {
    let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
    for pos in 0..input.len().saturating_sub(2) {
        buckets[match_hash(input, pos)].push(pos);
    }
    buckets
}

fn match_hash(input: &[u8], pos: usize) -> usize {
    let value =
        ((input[pos] as usize) << 8) ^ ((input[pos + 1] as usize) << 4) ^ input[pos + 2] as usize;
    value & (MATCH_HASH_BUCKETS - 1)
}

fn emit_long_lz_length(bits: &mut BitWriter, avr_ln2: u32, length_code: u32) -> Result<()> {
    if avr_ln2 >= 122 {
        return emit_decode_num(bits, length_code, 3, DEC_L2, POS_L2);
    }
    if avr_ln2 >= 64 {
        return emit_decode_num(bits, length_code, 2, DEC_L1, POS_L1);
    }
    if length_code <= 7 {
        bits.write_bits(1, length_code as usize + 1);
        return Ok(());
    }
    if length_code < 0x100 {
        bits.write_bits(length_code, 16);
        return Ok(());
    }
    Err(Error::InvalidData(
        "RAR 1.3 LongLZ encoder length is not encodable",
    ))
}

fn emit_decode_num(
    bits: &mut BitWriter,
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> Result<()> {
    if let Some((code, len)) = encode_decode_num_prefix(target, start_pos, dec_tab, pos_tab) {
        bits.write_bits(code, len);
        return Ok(());
    }
    Err(Error::InvalidData(
        "RAR 1.3 DecodeNum value is not encodable",
    ))
}

fn decode_num_bit_cost(
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> Option<usize> {
    encode_decode_num_prefix(target, start_pos, dec_tab, pos_tab).map(|(_, len)| len)
}

fn encode_decode_num_prefix(
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> Option<(u32, usize)> {
    let end = 16.min(pos_tab.len().saturating_sub(1));
    for (len, &base) in pos_tab
        .iter()
        .enumerate()
        .take(end + 1)
        .skip(start_pos as usize)
    {
        let dec_index = len.checked_sub(start_pos as usize)?;
        let upper = u32::from(*dec_tab.get(dec_index)?);
        let previous = if dec_index == 0 {
            0
        } else {
            u32::from(dec_tab[dec_index - 1])
        };
        let max_num = upper.checked_sub(1)? & !0xf;
        if max_num < previous {
            continue;
        }
        let base = u32::from(base);
        let max_target = ((max_num - previous) >> (16 - len)) + base;
        if target >= base && target <= max_target {
            let num = previous + ((target - base) << (16 - len));
            return Some((num >> (16 - len), len));
        }
    }
    None
}

#[cfg(test)]
fn decode_num_prefix_is_stable(
    code: u32,
    len: usize,
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> bool {
    let relevant_tail_bits = 16usize.saturating_sub(len + 4);
    for tail in 0..(1u32 << relevant_tail_bits) {
        let bit_field = (code << (16 - len)) | (tail << 4);
        let (decoded, consumed) = simulate_decode_num(bit_field, start_pos, dec_tab, pos_tab);
        if decoded != target || consumed != len {
            return false;
        }
    }
    true
}

#[cfg(test)]
fn simulate_decode_num(
    bit_field: u32,
    mut start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) -> (u32, usize) {
    let num = bit_field & 0xfff0;
    let mut i = 0usize;
    while dec_tab[i] as u32 <= num {
        start_pos += 1;
        i += 1;
    }
    (
        ((num - if i > 0 { dec_tab[i - 1] as u32 } else { 0 }) >> (16 - start_pos))
            + pos_tab[start_pos as usize] as u32,
        start_pos as usize,
    )
}

#[derive(Clone)]
pub struct Unpack15 {
    bits: BitReader,
    target: usize,
    output_written: usize,
    window: [u8; 0x10000],
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
}

impl Unpack15 {
    pub fn new() -> Self {
        Self {
            bits: BitReader::new(&[]),
            target: 0,
            output_written: 0,
            window: [0; 0x10000],
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
            avr_plc: 0x3500,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0x2001,
            nhfb: 0x80,
            nlzb: 0x80,
            num_huf: 0,
            buf60: 0,
            st_mode: false,
            l_count: 0,
            flag_buf: 0,
            flags_cnt: 0,
            old_dist: [u32::MAX; 4],
            old_dist_ptr: 0,
            last_dist: u32::MAX,
            last_length: 0,
        }
    }

    pub fn decode_member(&mut self, input: &[u8], target: usize, solid: bool) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(target);
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
        self.init_member(target, solid);
        self.bits = BitReader::new_final(input);
        self.decode_loop(out).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 1.3 bitstream is truncated"),
            error => error,
        })
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        target: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        const OUTPUT_CHUNK: usize = 64 * 1024;

        self.init_member(target, solid);
        self.bits = BitReader::new(&[]);
        let mut packed = Vec::new();
        input
            .read_to_end(&mut packed)
            .map_err(|_| Error::InvalidData("RAR 1.3 input read failed"))?;
        self.bits.append(&packed);
        self.bits.finish();

        while self.output_written < self.target {
            let chunk_target = self
                .output_written
                .saturating_add(OUTPUT_CHUNK)
                .min(self.target);
            let mut chunk = Vec::with_capacity(chunk_target - self.output_written);
            self.decode_loop_until(chunk_target, &mut chunk)
                .map_err(|error| match error {
                    Error::NeedMoreInput => Error::InvalidData("RAR 1.3 bitstream is truncated"),
                    error => error,
                })?;
            out.write_all(&chunk)
                .map_err(|_| Error::InvalidData("RAR 1.3 output write failed"))?;
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
        while self.output_written < target {
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
        self.window = [0; 0x10000];
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
        let mut bit_field = self.bits.get_bits()?;
        if self.l_count == 2 {
            self.bits.add_bits(1);
            if bit_field >= 0x8000 {
                self.copy_string(self.last_dist, self.last_length, out)?;
                return Ok(());
            }
            bit_field = (bit_field << 1) & 0xffff;
            self.l_count = 0;
        }

        let bit_byte = (bit_field >> 8) as u8;
        let mut length = 0usize;
        if self.avr_ln1 < 37 {
            while length < SHORT_XOR1.len() {
                let short_len = self.short_len1(length);
                let mask = (!(0xffu16 >> short_len)) as u8;
                if ((bit_byte ^ SHORT_XOR1[length]) & mask) == 0 {
                    break;
                }
                length += 1;
            }
            self.bits.add_bits(self.short_len1(length) as usize);
        } else {
            while length < SHORT_XOR2.len() {
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
                self.copy_string(self.last_dist, self.last_length, out)?;
                return Ok(());
            }
            if length == 14 {
                self.l_count = 0;
                length = self.decode_num(self.bits.get_bits()?, 3, DEC_L2, POS_L2) + 5;
                let distance = (self.bits.get_bits()? >> 1) | 0x8000;
                self.bits.add_bits(15);
                self.last_length = length;
                self.last_dist = distance;
                self.copy_string(distance, length, out)?;
                return Ok(());
            }

            self.l_count = 0;
            let save_length = length;
            let distance =
                self.old_dist[(self.old_dist_ptr.wrapping_sub((length - 9) as usize)) & 3];
            length = self.decode_num(self.bits.get_bits()?, 2, DEC_L1, POS_L1) + 2;
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
            self.copy_string(distance, length, out)?;
            return Ok(());
        }

        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_place =
            (self.decode_num(self.bits.get_bits()?, 5, DEC_HF2, POS_HF2) & 0xff) as usize;
        let mut distance = self.ch_set_a[distance_place] as u32;
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance as u16;
        }
        length += 2;
        distance += 1;
        self.remember_match(distance, length);
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

        let bit_field = self.bits.get_bits()?;
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

        let bit_field = self.bits.get_bits()?;
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

        distance = ((distance & 0xff00) | (self.bits.get_bits()? >> 8)) >> 1;
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
        self.copy_string(distance, length, out)
    }

    fn huff_decode(&mut self, out: &mut impl Write) -> Result<()> {
        let bit_field = self.bits.get_bits()?;

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
                let bit_field = self.bits.get_bits()?;
                self.bits.add_bits(1);
                if bit_field & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = false;
                    return Ok(());
                }

                let length = if bit_field & 0x4000 != 0 { 4 } else { 3 };
                self.bits.add_bits(1);
                let mut distance = self.decode_num(self.bits.get_bits()?, 5, DEC_HF2, POS_HF2);
                distance = (distance << 5) | (self.bits.get_bits()? >> 11);
                self.bits.add_bits(5);
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
        let flags_place = self.decode_num(self.bits.get_bits()?, 5, DEC_HF2, POS_HF2) as usize;
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
        out.write_all(&[byte])
            .map_err(|_| Error::InvalidData("RAR 1.3 output write failed"))?;
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

#[cfg(test)]
mod tests {
    use super::{
        decode_num_bit_cost, decode_num_prefix_is_stable, find_long_lz, find_lz_token,
        find_old_dist_lz, long_lz_buckets, should_lazy_emit_literal, unpack15_decode,
        unpack15_encode, EncodeOptions, EncodedToken, LongLz, LzPlanState, OldDistLz, ShortLz,
        Unpack15, Unpack15Encoder, DEC_HF0, DEC_HF1, DEC_HF2, DEC_HF3, DEC_HF4, DEC_L1, DEC_L2,
        POS_HF0, POS_HF1, POS_HF2, POS_HF3, POS_HF4, POS_L1, POS_L2,
    };

    fn brute_decode_num_bit_cost(
        target: u32,
        start_pos: u32,
        dec_tab: &[u16],
        pos_tab: &[u16],
    ) -> Option<usize> {
        for len in start_pos as usize..=16 {
            for code in 0..(1u32 << len) {
                if decode_num_prefix_is_stable(code, len, target, start_pos, dec_tab, pos_tab) {
                    return Some(len);
                }
            }
        }
        None
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
                let len = self.input.len().min(out.len()).min(2);
                out[..len].copy_from_slice(&self.input[..len]);
                self.input = &self.input[len..];
                Ok(len)
            }
        }

        let expected = b"RAR 1.4 incremental input fixture\n".repeat(32);
        let packed = unpack15_encode(&expected).unwrap();
        assert_eq!(unpack15_decode(&packed, expected.len()).unwrap(), expected);

        let mut reader = TinyReader { input: &packed };
        let mut decoder = Unpack15::new();
        let mut output = Vec::new();
        decoder
            .decode_member_from_reader(&mut reader, expected.len(), false, &mut output)
            .unwrap();

        assert_eq!(output, expected);
    }

    #[test]
    fn decode_num_bit_cost_matches_prefix_search_at_table_boundaries() {
        let tables = [
            (4, DEC_HF0, POS_HF0),
            (5, DEC_HF1, POS_HF1),
            (5, DEC_HF2, POS_HF2),
            (6, DEC_HF3, POS_HF3),
            (8, DEC_HF4, POS_HF4),
            (2, DEC_L1, POS_L1),
            (3, DEC_L2, POS_L2),
        ];
        let targets = [0, 1, 2, 3, 7, 8, 16, 24, 32, 33, 53, 117, 233, 255, 256];

        for (start_pos, dec_tab, pos_tab) in tables {
            for target in targets {
                assert_eq!(
                    decode_num_bit_cost(target, start_pos, dec_tab, pos_tab),
                    brute_decode_num_bit_cost(target, start_pos, dec_tab, pos_tab),
                    "target {target}, start_pos {start_pos}"
                );
            }
        }
    }

    #[test]
    fn encoder_emits_rar15_very_long_lz_matches() {
        let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
        input.extend_from_within(..258);

        assert_eq!(
            find_long_lz(&input, 300, 0x8000),
            Some(LongLz {
                distance: 300,
                length: 258
            })
        );
        let packed = unpack15_encode(&input).unwrap();

        assert!(
            packed.len() < 330,
            "very-long LongLZ should encode a 258-byte repeat compactly, got {} bytes",
            packed.len()
        );
        assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_adjusts_rar15_long_lz_length_for_far_distance_bonus() {
        let mut input: Vec<_> = (0..9000).map(|index| (index * 73 + 19) as u8).collect();
        input.extend_from_within(..10);

        let packed = unpack15_encode(&input).unwrap();

        assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_reuses_rar15_repeat_last_token() {
        let input = b"abcdefghijklmnop".repeat(64);
        let packed = unpack15_encode(&input).unwrap();

        assert!(
            packed.len() < 100,
            "repeat-last tokens should keep a simple repeated pattern compact, got {} bytes",
            packed.len()
        );
        assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn old_distance_finder_maps_ring_entries_to_short_lz_codes() {
        let mut input: Vec<_> = (0..80).map(|index| (index * 37 + 11) as u8).collect();
        let pos = input.len();
        input.extend_from_within(pos - 33..pos - 13);

        assert_eq!(
            find_old_dist_lz(&input, pos, [11, 22, 33, 44], 0, 0x2001),
            Some(OldDistLz {
                distance: 33,
                length: 20,
                short_code: 11,
            })
        );
    }

    #[test]
    fn old_distance_finder_rejects_buf60_toggle_encoding() {
        let mut input = b"abcd".repeat(128);
        let pos = input.len();
        input.extend((0..257).map(|index| b"abcd"[index % 4]));

        assert_eq!(
            find_old_dist_lz(&input, pos, [u32::MAX, 4, u32::MAX, u32::MAX], 2, 0x2001),
            None,
            "short-code 10 with decoded base length 0x101 is the Buf60 toggle, not a match"
        );
    }

    #[test]
    fn planner_emits_safe_old_distance_token() {
        let mut input: Vec<_> = (0..80).map(|index| (index * 37 + 11) as u8).collect();
        let pos = input.len();
        input.extend_from_within(pos - 33..pos - 13);

        let encoder = Unpack15Encoder::new();
        let buckets = long_lz_buckets(&input);
        let token = encoder
            .choose_lz_token(
                &input,
                pos,
                &buckets,
                LzPlanState {
                    last_dist: u32::MAX,
                    last_length: 0,
                    old_dist: [11, 22, 33, 44],
                    old_dist_ptr: 0,
                    max_dist3: 0x2001,
                    nlzb: encoder.nlzb,
                    nhfb: encoder.nhfb,
                    l_count: encoder.l_count,
                },
                0,
            )
            .expect("old-distance candidate should be selected");

        assert_eq!(
            token,
            EncodedToken::OldDist(OldDistLz {
                distance: 33,
                length: 20,
                short_code: 11,
            })
        );
    }

    #[test]
    fn encoder_exits_stmode_when_literal_runs_trigger_decoder_mode() {
        let input: Vec<_> = (0..96).map(|index| (index * 73 + 19) as u8).collect();
        let packed = unpack15_encode(&input).unwrap();

        assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_stmode_literals_for_long_literal_runs() {
        let input: Vec<_> = (0..128).map(|index| (index * 73 + 19) as u8).collect();
        let mut encoder = Unpack15Encoder::new();
        let packed = encoder.encode_member(&input).unwrap();

        assert!(
            encoder.stmode_literal_count > 0,
            "long literal runs should use stmode literals before exiting stmode"
        );
        assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_options_can_disable_stmode_literal_runs() {
        let input: Vec<_> = (0..128).map(|index| (index * 73 + 19) as u8).collect();
        let mut encoder =
            Unpack15Encoder::with_options(EncodeOptions::new().with_stmode_literal_runs(false));
        let packed = encoder.encode_member(&input).unwrap();

        assert_eq!(encoder.stmode_literal_count, 0);
        assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_options_bound_long_lz_search_distance() {
        let mut input: Vec<_> = (0u8..=255).cycle().take(300).collect();
        input.extend_from_within(..64);

        assert_eq!(find_long_lz(&input, 300, 256), None);
        assert_eq!(
            find_long_lz(&input, 300, 0x8000),
            Some(LongLz {
                distance: 300,
                length: 64
            })
        );
    }

    #[test]
    fn long_lz_search_rejects_unencodable_32k_distance() {
        let mut input = Vec::with_capacity(0x8000 + 64);
        let mut state = 0x1234_5678u32;
        for _ in 0..0x8000 + 64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push((state >> 24) as u8);
        }
        let repeated = input[..64].to_vec();
        input[0x8000..0x8000 + 64].copy_from_slice(&repeated);

        let token = find_long_lz(&input, 0x8000, 0x8000);

        assert_ne!(token.map(|token| token.distance), Some(0x8000));
    }

    #[test]
    fn lazy_match_prefers_longer_next_position_match() {
        let input = b"abcXbcQRSTabcQRSTUV";
        let buckets = long_lz_buckets(input);
        let token = find_lz_token(
            input,
            10,
            &buckets,
            LzPlanState {
                last_dist: u32::MAX,
                last_length: 0,
                old_dist: [u32::MAX; 4],
                old_dist_ptr: 0,
                max_dist3: 0x2001,
                nlzb: 0,
                nhfb: 0,
                l_count: 0,
            },
            EncodeOptions::default(),
        )
        .unwrap();

        assert!(matches!(
            token,
            EncodedToken::ShortLz(super::ShortLz { length: 3, .. })
        ));
        assert!(should_lazy_emit_literal(
            input,
            10,
            &buckets,
            token,
            0x2001,
            EncodeOptions::default()
        ));

        let packed = unpack15_encode(input).unwrap();
        assert_eq!(unpack15_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn cost_aware_selection_prefers_better_bits_per_byte_token() {
        let mut input = vec![b'Z'; 40];
        input[7] = b'A';
        input[8] = b'A';
        input[9] = b'A';
        input[10] = b'B';
        input[39] = b'A';
        let pos = input.len();
        input.extend_from_slice(b"AAAAAAAAAA");

        let mut encoder = Unpack15Encoder::new();
        encoder.old_dist = [u32::MAX, u32::MAX, u32::MAX, 33];
        let buckets = long_lz_buckets(&input);
        let token = encoder
            .choose_lz_token(
                &input,
                pos,
                &buckets,
                LzPlanState {
                    last_dist: u32::MAX,
                    last_length: 0,
                    old_dist: encoder.old_dist,
                    old_dist_ptr: encoder.old_dist_ptr,
                    max_dist3: encoder.max_dist3,
                    nlzb: encoder.nlzb,
                    nhfb: encoder.nhfb,
                    l_count: encoder.l_count,
                },
                0,
            )
            .unwrap();

        assert_eq!(
            token,
            EncodedToken::ShortLz(ShortLz {
                distance: 1,
                length: 10,
            })
        );
    }

    #[test]
    fn planner_uses_simulated_max_dist3_for_old_distance_candidates() {
        let mut state = 0x1234_5678u32;
        let mut input = Vec::with_capacity(9004);
        for _ in 0..9004 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            input.push(state as u8);
        }
        let pos = 9000;
        let prefix = [input[0], input[1], input[2]];
        input[pos..pos + 3].copy_from_slice(&prefix);
        input[pos + 3] = input[3].wrapping_add(1);

        let mut encoder = Unpack15Encoder::new();
        encoder.max_dist3 = 0x7f00;
        let buckets = long_lz_buckets(&input);
        let token = encoder.choose_lz_token(
            &input,
            pos,
            &buckets,
            LzPlanState {
                last_dist: u32::MAX,
                last_length: 0,
                old_dist: [u32::MAX, u32::MAX, u32::MAX, 9000],
                old_dist_ptr: 0,
                max_dist3: 0x2001,
                nlzb: encoder.nlzb,
                nhfb: encoder.nhfb,
                l_count: encoder.l_count,
            },
            0,
        );

        assert_eq!(token, None);
    }

    #[test]
    fn encoder_round_trips_source_shaped_payload() {
        let source = include_bytes!("rar13.rs");
        let input = &source[..source.len().min(50_902)];

        let packed = unpack15_encode(input).unwrap();
        let decoded = unpack15_decode(&packed, input.len()).unwrap();

        let first_diff = decoded
            .iter()
            .zip(input)
            .position(|(actual, expected)| actual != expected);
        assert_eq!(first_diff, None, "first differing byte in decoded payload");
        assert_eq!(decoded, input);
    }
}

#[derive(Clone)]
struct BitReader {
    input: Vec<u8>,
    bit_pos: usize,
    final_input: bool,
}

impl BitReader {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            bit_pos: 0,
            final_input: false,
        }
    }

    fn new_final(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            bit_pos: 0,
            final_input: true,
        }
    }

    fn append(&mut self, input: &[u8]) {
        self.compact();
        self.input.extend_from_slice(input);
    }

    fn finish(&mut self) {
        self.final_input = true;
    }

    fn compact(&mut self) {
        let bytes = self.bit_pos / 8;
        if bytes == 0 {
            return;
        }
        self.input.drain(..bytes);
        self.bit_pos -= bytes * 8;
    }

    fn get_bits(&self) -> Result<u32> {
        let mut value = 0u32;
        for i in 0..16 {
            value <<= 1;
            let bit_index = self.bit_pos + i;
            let byte = match self.input.get(bit_index / 8).copied() {
                Some(byte) => byte,
                None if self.final_input => 0,
                None => return Err(Error::NeedMoreInput),
            };
            value |= ((byte >> (7 - (bit_index % 8))) & 1) as u32;
        }
        Ok(value)
    }

    fn add_bits(&mut self, count: usize) {
        self.bit_pos += count;
    }
}

#[derive(Default)]
struct BitWriter {
    output: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_pos: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            let bit = ((value >> i) & 1) as u8;
            if self.bit_pos.is_multiple_of(8) {
                self.output.push(0);
            }
            if bit != 0 {
                let idx = self.output.len() - 1;
                self.output[idx] |= 1 << (7 - (self.bit_pos % 8));
            }
            self.bit_pos += 1;
        }
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }
}
