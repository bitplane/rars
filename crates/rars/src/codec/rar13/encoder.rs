//! RAR13 member encoding and bit emission.
use super::*;

/// Prebuilt long-LZ candidate index. Unlike the other encoders, rar13 builds
/// the index for the whole member up front and then queries it at arbitrary
/// positions, so candidates are stored per hash as position-sorted arrays: a
/// binary search finds the newest candidate before the query position and
/// iteration proceeds toward older ones with array locality. A linked-chain
/// finder is a poor fit here because its head always points at the newest
/// position in the member, forcing every query to pointer-chase past all
/// not-yet-reached positions.
#[derive(Debug, Clone)]
struct Rar13MatchFinder {
    buckets: Vec<Vec<usize>>,
}

const LONG_LZ_HASH_BITS: u32 = 16;

impl Rar13MatchFinder {
    fn build(input: &[u8]) -> Self {
        let mut buckets = vec![Vec::new(); 1 << LONG_LZ_HASH_BITS];
        for pos in 0..input.len().saturating_sub(2) {
            buckets[Self::hash(input, pos)].push(pos);
        }
        Self { buckets }
    }

    fn hash(input: &[u8], pos: usize) -> usize {
        let value = u32::from(input[pos])
            | (u32::from(input[pos + 1]) << 8)
            | (u32::from(input[pos + 2]) << 16);
        (value.wrapping_mul(0x9E37_79B1) >> (32 - LONG_LZ_HASH_BITS)) as usize
    }

    /// Candidate positions strictly before `pos` sharing its 3-byte hash,
    /// newest first. The caller must ensure 3 bytes are readable at `pos`.
    fn candidates_before(&self, input: &[u8], pos: usize) -> impl Iterator<Item = usize> + '_ {
        let bucket = &self.buckets[Self::hash(input, pos)];
        let end = bucket.partition_point(|&candidate| candidate < pos);
        bucket[..end].iter().rev().copied()
    }
}

const MAX_LONG_MATCH_CANDIDATES: usize = 64;

const MAX_LONG_LZ_DISTANCE: usize = 0x7fff;

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

    #[cfg(test)]
    pub(crate) const fn lazy_matching_enabled(self) -> bool {
        self.lazy_matching
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
        Ok(self.encode_literals_only_member(input))
    }

    fn encode_literals_only_member(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
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
                // Literal-only planning can start with two-bit flags after a
                // match-heavy solid member. Huffman updates only move that
                // choice toward one-bit flags; the switch occurs after an
                // even number of bits, so a flag cannot straddle the byte.
                let flag = huff_flag_bits(plan_nlzb <= plan_nhfb);
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

            self.emit_flags_byte(flags);
            self.emit_payloads(payloads);
            if group_enters_stmode {
                if self.options.stmode_literal_runs {
                    self.emit_stmode_literal_run(input, None, &mut pos);
                }
                self.emit_stmode_exit();
            }
        }
        std::mem::take(&mut self.bits).finish()
    }

    pub fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.encode_member_inner(input, None)
    }

    #[cfg(any(test, feature = "write"))]
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
        // Everything the decoder drops at a member boundary has to be dropped
        // here too. The adaptive tables carry across a solid run, but the
        // short-LZ literal run does not: `Unpack15::init_member` clears it for
        // every member, solid or not. Leaving it set here made the encoder
        // write a break bit at the start of the next member that no decoder
        // was going to read, and one stray bit desynchronises the rest of the
        // archive.
        self.l_count = 0;
        let buckets = long_lz_buckets(input);
        let mut pos = 0usize;
        let mut next_report = 0usize;
        let mut straddle: Option<Straddle> = None;
        while pos < input.len() || straddle.is_some() {
            let mut flags = 0u8;
            let mut flag_bits = 0usize;
            let mut payloads = Vec::new();
            let mut plan_encoder = self.clone_for_planning();
            let mut group_enters_stmode = false;

            if let Some(carried) = straddle.take() {
                write_planned_flag_bits(&mut flags, 0, carried.rest);
                flag_bits = carried.rest.len();
                payloads.push(carried.token);
                plan_encoder.emit_payloads(vec![carried.token]);
            }

            while flag_bits < 8 && pos < input.len() {
                let state = plan_encoder.lz_plan_state();
                if let Some(token) = plan_encoder
                    .choose_lz_token(input, pos, &buckets, state)
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
                    if flag_fits(flag_bits, flag) {
                        write_planned_flag_bits(&mut flags, flag_bits, flag);
                        flag_bits += flag.len();
                        pos = next_pos;
                        plan_encoder.emit_payloads(vec![token.into()]);
                        payloads.push(token.into());
                        continue;
                    }
                }

                let flag = huff_flag_bits(plan_encoder.nlzb <= plan_encoder.nhfb);
                if flag_bits + flag.len() > 8 {
                    straddle = Some(split_flag(
                        &mut flags,
                        flag_bits,
                        flag,
                        EncodedToken::Literal(input[pos]),
                    ));
                    pos += 1;
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
                plan_encoder.emit_literal(literal);
            }

            self.emit_flags_byte(flags);
            self.emit_payloads(payloads);
            if group_enters_stmode {
                if self.options.stmode_literal_runs {
                    self.emit_stmode_literal_run(input, Some(&buckets), &mut pos);
                }
                self.emit_stmode_exit();
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
        buckets: &Rar13MatchFinder,
        state: LzPlanState,
    ) -> Option<MatchToken> {
        let candidates = find_lz_tokens(input, pos, buckets, state, self.options);
        candidates
            .into_iter()
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

    fn token_bit_cost(&self, token: MatchToken, state: LzPlanState) -> Option<usize> {
        let flag_cost = token.flag_bits(state.nlzb, state.nhfb).len();
        match token {
            MatchToken::RepeatLast(_) => Some(flag_cost + self.repeat_last_bit_cost(state.l_count)),
            MatchToken::ShortLz(token) => {
                let distance_value = token.distance - 1;
                let distance_place = self
                    .ch_set_a
                    .iter()
                    .position(|&value| value as u32 == distance_value)
                    .expect("short-distance alphabet contains every distance");
                Some(
                    flag_cost
                        + l_count_break_bit_cost(state.l_count)
                        + self.short_lz_prefix_bit_cost(token.length - 2)
                        + decode_num_bit_cost(distance_place as u32, 5, DEC_HF2, POS_HF2)?,
                )
            }
            MatchToken::OldDist(token) => {
                let length_code = old_dist_lz_length_code(
                    token.length,
                    token.distance,
                    state.max_dist3,
                    token.short_code,
                )
                .expect("old-distance candidate passed both distance thresholds");
                Some(
                    flag_cost
                        + l_count_break_bit_cost(state.l_count)
                        + self.short_lz_prefix_bit_cost(token.short_code)
                        + decode_num_bit_cost(length_code, 2, DEC_L1, POS_L1)?,
                )
            }
            MatchToken::LongLz(token) => {
                let length_code = long_lz_length_code_for_distance(token, state.max_dist3)
                    .expect("long-match candidate passed distance threshold validation");
                let distance_place = self.long_lz_distance_place(token.distance);
                Some(
                    flag_cost
                        + self.long_lz_length_bit_cost(length_code)
                        + self.long_lz_distance_bit_cost(distance_place)
                        + 7,
                )
            }
        }
    }

    fn emit_payloads(&mut self, payloads: Vec<EncodedToken>) {
        for payload in payloads {
            match payload {
                EncodedToken::Literal(byte) => self.emit_literal(byte),
                EncodedToken::ShortLz(short_lz) => {
                    self.emit_short_lz(short_lz);
                }
                EncodedToken::RepeatLast(repeat) => {
                    self.emit_repeat_last(repeat);
                }
                EncodedToken::OldDist(old_lz) => {
                    self.emit_old_dist_lz(old_lz);
                }
                EncodedToken::LongLz(long_lz) => {
                    self.emit_long_lz(long_lz);
                }
            }
        }
    }

    fn emit_flags_byte(&mut self, flags: u8) {
        let flags_place = self
            .ch_set_c
            .iter()
            .position(|&value| (value >> 8) as u8 == flags)
            .expect("flag alphabet contains every byte");
        emit_decode_num(&mut self.bits, flags_place as u32, 5, DEC_HF2, POS_HF2);

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
    }

    fn emit_literal(&mut self, byte: u8) {
        let byte_place = self
            .ch_set
            .iter()
            .position(|&value| (value >> 8) as u8 == byte)
            .expect("literal alphabet contains every byte");
        self.emit_literal_place(byte_place, byte_place, true)
    }

    fn emit_stmode_literal(&mut self, byte: u8) {
        let byte_place = self
            .ch_set
            .iter()
            .position(|&value| (value >> 8) as u8 == byte)
            .expect("literal alphabet contains every byte");
        #[cfg(test)]
        {
            self.stmode_literal_count += 1;
        }
        self.emit_literal_place(byte_place + 1, byte_place, false)
    }

    fn emit_stmode_literal_run(
        &mut self,
        input: &[u8],
        buckets: Option<&Rar13MatchFinder>,
        pos: &mut usize,
    ) {
        while *pos + 1 < input.len() {
            if buckets
                .and_then(|buckets| {
                    find_lz_token(
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
                })
                .is_some()
            {
                break;
            }
            self.emit_stmode_literal(input[*pos]);
            *pos += 1;
        }
    }

    fn emit_literal_place(
        &mut self,
        encoded_place: usize,
        decoded_place: usize,
        update_num_huf: bool,
    ) {
        debug_assert!(encoded_place <= self.ch_set.len());
        debug_assert!(decoded_place < self.ch_set.len());

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
        );

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
    }

    fn emit_short_lz(&mut self, short_lz: ShortLz) {
        debug_assert!((1..=256).contains(&short_lz.distance));
        debug_assert!((2..=10).contains(&short_lz.length));
        self.num_huf = 0;
        if self.l_count == 2 {
            self.bits.write_bits(0, 1);
            self.l_count = 0;
        }
        let length_place = short_lz.length - 2;
        self.emit_short_lz_code(length_place as usize);
        self.l_count = 0;

        self.avr_ln1 += length_place;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let distance_value = short_lz.distance - 1;
        let distance_place = self
            .ch_set_a
            .iter()
            .position(|&value| value as u32 == distance_value)
            .expect("short-distance alphabet contains every distance");
        emit_decode_num(&mut self.bits, distance_place as u32, 5, DEC_HF2, POS_HF2);
        if distance_place > 0 {
            let last_distance = self.ch_set_a[distance_place - 1];
            self.ch_set_a[distance_place] = last_distance;
            self.ch_set_a[distance_place - 1] = distance_value as u16;
        }
        self.remember_match(short_lz.distance, short_lz.length);
    }

    fn emit_repeat_last(&mut self, repeat: RepeatLastLz) {
        debug_assert_eq!(self.last_dist, repeat.distance);
        debug_assert_eq!(self.last_length, repeat.length);
        self.num_huf = 0;
        if self.l_count == 2 {
            self.bits.write_bits(1, 1);
        } else {
            self.emit_short_lz_code(9);
            self.l_count += 1;
        }
    }

    fn emit_old_dist_lz(&mut self, old_lz: OldDistLz) {
        self.num_huf = 0;
        if self.l_count == 2 {
            self.bits.write_bits(0, 1);
            self.l_count = 0;
        }
        self.emit_short_lz_code(old_lz.short_code as usize);
        self.l_count = 0;

        let expected_distance = self.old_dist[(self
            .old_dist_ptr
            .wrapping_sub((old_lz.short_code - 9) as usize))
            & 3];
        debug_assert_eq!(expected_distance, old_lz.distance);
        let length_code = old_dist_lz_length_code(
            old_lz.length,
            old_lz.distance,
            self.max_dist3,
            old_lz.short_code,
        )
        .expect("selected old-distance length passed planner validation");
        emit_decode_num(&mut self.bits, length_code, 2, DEC_L1, POS_L1);
        self.remember_match(old_lz.distance, old_lz.length);
    }

    fn emit_short_lz_code(&mut self, code: usize) {
        let (code_len, code_byte) = if self.avr_ln1 < 37 {
            (self.short_len1(code), SHORT_XOR1[code])
        } else {
            (self.short_len2(code), SHORT_XOR2[code])
        };
        self.bits
            .write_bits((code_byte >> (8 - code_len)) as u32, code_len as usize);
    }

    fn short_lz_prefix_bit_cost(&self, code: u32) -> usize {
        debug_assert!(code < SHORT_XOR1.len() as u32);
        let code = code as usize;
        (if self.avr_ln1 < 37 {
            self.short_len1(code)
        } else {
            self.short_len2(code)
        }) as usize
    }

    fn repeat_last_bit_cost(&self, l_count: u32) -> usize {
        if l_count == 2 {
            1
        } else {
            self.short_lz_prefix_bit_cost(9)
        }
    }

    fn emit_long_lz(&mut self, long_lz: LongLz) {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let length_code = self
            .long_lz_length_code(long_lz)
            .expect("selected long-match length passed planner validation");
        emit_long_lz_length(&mut self.bits, self.avr_ln2, length_code);
        self.avr_ln2 += length_code;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let distance_place = self.long_lz_distance_place(long_lz.distance);
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
        );
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
    }

    fn long_lz_length_code(&self, long_lz: LongLz) -> Option<u32> {
        long_lz_length_code_for_distance(long_lz, self.max_dist3)
    }

    fn long_lz_distance_place(&self, target_distance: u32) -> usize {
        let wanted_high = ((target_distance << 1) & 0xff00) as u16;
        self.ch_set_b
            .iter()
            .position(|&value| value & 0xff00 == wanted_high)
            .expect("long-distance alphabet contains every high byte")
    }

    fn long_lz_length_bit_cost(&self, length_code: u32) -> usize {
        debug_assert!(length_code < 0x100);
        if self.avr_ln2 >= 122 {
            decode_num_bit_cost(length_code, 3, DEC_L2, POS_L2)
                .expect("L2 represents every length symbol")
        } else if self.avr_ln2 >= 64 {
            decode_num_bit_cost(length_code, 2, DEC_L1, POS_L1)
                .expect("L1 represents every length symbol")
        } else if length_code <= 7 {
            length_code as usize + 1
        } else {
            16
        }
    }

    fn long_lz_distance_bit_cost(&self, distance_place: usize) -> usize {
        debug_assert!(distance_place < 256);
        let cost = if self.avr_plc_b > 0x28ff {
            decode_num_bit_cost(distance_place as u32, 5, DEC_HF2, POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            decode_num_bit_cost(distance_place as u32, 5, DEC_HF1, POS_HF1)
        } else {
            decode_num_bit_cost(distance_place as u32, 4, DEC_HF0, POS_HF0)
        };
        cost.expect("distance codebooks represent every adaptive rank")
    }

    fn emit_stmode_exit(&mut self) {
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
        emit_decode_num(&mut self.bits, 0, start_pos, dec_tab, pos_tab);
        self.bits.write_bits(1, 1);
        self.num_huf = 0;
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

/// Candidates from the match finder; literals take a separate planning path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchToken {
    ShortLz(ShortLz),
    RepeatLast(RepeatLastLz),
    OldDist(OldDistLz),
    LongLz(LongLz),
}

impl MatchToken {
    fn length(self) -> u32 {
        match self {
            Self::ShortLz(token) => token.length,
            Self::RepeatLast(token) => token.length,
            Self::OldDist(token) => token.length,
            Self::LongLz(token) => token.length,
        }
    }

    fn flag_bits(self, nlzb: u32, nhfb: u32) -> &'static [bool] {
        match self {
            Self::LongLz(_) => long_lz_flag_bits(nlzb > nhfb),
            Self::ShortLz(_) | Self::RepeatLast(_) | Self::OldDist(_) => &[false, false],
        }
    }
}

impl From<MatchToken> for EncodedToken {
    fn from(token: MatchToken) -> Self {
        match token {
            MatchToken::ShortLz(value) => Self::ShortLz(value),
            MatchToken::RepeatLast(value) => Self::RepeatLast(value),
            MatchToken::OldDist(value) => Self::OldDist(value),
            MatchToken::LongLz(value) => Self::LongLz(value),
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

/// A token whose flag did not fit in what was left of a flags byte.
///
/// `Unpack15` fetches the next flags byte the moment it runs out of bits, and
/// it does that in the middle of reading a flag, not between tokens. So a
/// two-bit flag at the last bit of a byte is legal: its first bit closes that
/// byte and its second opens the next one, and only then does the decoder read
/// the token's payload. Padding the byte out instead leaves a bit the decoder
/// still reads as a flag, which desynchronises everything after it.
#[derive(Clone, Copy)]
struct Straddle {
    token: EncodedToken,
    /// The flag bits that belong at the front of the next flags byte.
    rest: &'static [bool],
}

fn split_flag(
    flags: &mut u8,
    flag_bits: usize,
    flag: &'static [bool],
    token: EncodedToken,
) -> Straddle {
    let fits = 8 - flag_bits;
    write_planned_flag_bits(flags, flag_bits, &flag[..fits]);
    Straddle {
        token,
        rest: &flag[fits..],
    }
}

fn write_planned_flag_bits(flags: &mut u8, start: usize, bits: &[bool]) {
    for (offset, &bit) in bits.iter().enumerate() {
        if bit {
            *flags |= 1 << (7 - start - offset);
        }
    }
}

fn flag_fits(used: usize, flag: &[bool]) -> bool {
    used + flag.len() <= 8
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
    buckets: &Rar13MatchFinder,
    state: LzPlanState,
    options: EncodeOptions,
) -> Option<MatchToken> {
    find_lz_tokens(input, pos, buckets, state, options)
        .into_iter()
        .next()
}

fn find_lz_tokens(
    input: &[u8],
    pos: usize,
    buckets: &Rar13MatchFinder,
    state: LzPlanState,
    options: EncodeOptions,
) -> Vec<MatchToken> {
    let mut tokens = Vec::with_capacity(4);
    if let Some(repeat) = find_repeat_last_lz(input, pos, state.last_dist, state.last_length) {
        tokens.push(MatchToken::RepeatLast(repeat));
    }
    if options.old_distance_tokens {
        if let Some(old_lz) = find_old_dist_lz(
            input,
            pos,
            state.old_dist,
            state.old_dist_ptr,
            state.max_dist3,
        ) {
            tokens.push(MatchToken::OldDist(old_lz));
        }
    }
    if let Some(short_lz) = find_short_lz(input, pos) {
        tokens.push(MatchToken::ShortLz(short_lz));
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
        tokens.push(MatchToken::LongLz(long_lz));
    }
    tokens
}

fn should_lazy_emit_literal(
    input: &[u8],
    pos: usize,
    buckets: &Rar13MatchFinder,
    current: MatchToken,
    max_dist3: u32,
    options: EncodeOptions,
) -> bool {
    if !matches!(current, MatchToken::ShortLz(_) | MatchToken::LongLz(_)) {
        return false;
    }

    // Selected matches fit at least two bytes of the remaining input.
    debug_assert!(pos + 1 < input.len());

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
        matches!(next, MatchToken::ShortLz(_) | MatchToken::LongLz(_))
            && next.length() >= current.length() + 2
    })
}

fn find_short_lz(input: &[u8], pos: usize) -> Option<ShortLz> {
    if pos == 0 {
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
        // Distances increase, so the first match of a given length is nearest.
        if length >= 2 && length > best.length as usize {
            best = ShortLz {
                distance: distance as u32,
                length: length as u32,
            };
        }
    }

    (best.length >= 2).then_some(best)
}

fn find_repeat_last_lz(
    input: &[u8],
    pos: usize,
    last_dist: u32,
    last_length: u32,
) -> Option<RepeatLastLz> {
    if last_dist == u32::MAX {
        return None;
    }
    debug_assert!((1..=MAX_LONG_LZ_DISTANCE as u32).contains(&last_dist));
    debug_assert!((2..=258).contains(&last_length));
    debug_assert!(pos <= input.len());
    let distance = last_dist as usize;
    let length = last_length as usize;
    if distance > pos || pos + length > input.len() {
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
        if distance == u32::MAX {
            continue;
        }
        debug_assert!((1..=MAX_LONG_LZ_DISTANCE as u32).contains(&distance));
        let distance_usize = distance as usize;
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
    _short_code: u32,
) -> Option<u32> {
    let decoded_bonus = u32::from(distance > 256) + u32::from(distance >= max_dist3);
    let length_code = length.checked_sub(2 + decoded_bonus)?;
    // DOS RAR 1.402 does not reliably decode an old-distance match whose
    // length symbol reaches the all-ones value.  Code 10 also reserves that
    // value for the Buf60 toggle, but the compatibility limit applies to all
    // four old-distance codes.
    if length_code == 0xff {
        return None;
    }
    Some(length_code)
}

fn long_lz_length_code_for_distance(long_lz: LongLz, max_dist3: u32) -> Option<u32> {
    let decoded_bonus =
        u32::from(long_lz.distance >= max_dist3) + if long_lz.distance <= 256 { 8 } else { 0 };
    long_lz.length.checked_sub(3 + decoded_bonus)
}

pub fn find_long_lz(input: &[u8], pos: usize, max_match_distance: usize) -> Option<LongLz> {
    if pos == 0 {
        return None;
    }

    let max_distance = pos.min(MAX_LONG_LZ_DISTANCE).min(max_match_distance);
    if max_distance == 0 {
        return None;
    }
    let mut best = LongLz {
        distance: 0,
        length: 0,
    };
    for distance in 1..=max_distance {
        let length = super::super::fast::match_length(input, pos, distance, 258);
        // LongLZ adds eight to the decoded length for distances up to 256,
        // so its shortest encodable near-distance match is eleven bytes.
        let min_length = if distance <= 256 { 11 } else { 3 };
        if length >= min_length && length > best.length as usize {
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
    buckets: &Rar13MatchFinder,
    max_candidates: usize,
) -> Option<LongLz> {
    if pos == 0 || pos + 2 >= input.len() {
        return None;
    }

    let max_distance = pos.min(MAX_LONG_LZ_DISTANCE).min(max_match_distance);
    if max_distance == 0 {
        return None;
    }
    let max_length = (input.len() - pos).min(258);
    let mut best = LongLz {
        distance: 0,
        length: 0,
    };
    let mut checked = 0usize;
    for candidate in buckets.candidates_before(input, pos) {
        let distance = pos - candidate;
        if distance > max_distance {
            break;
        }
        // Near-distance candidates are a separate, bounded set and must not
        // consume the established search budget for older matches.
        if distance > 256 {
            if checked >= max_candidates {
                break;
            }
            checked += 1;
        }
        // A candidate can only improve on the current best when it matches at
        // least one byte past the best length, so probe that byte first. The
        // loop breaks once best reaches `max_length`, so the probe index stays
        // in bounds.
        if best.length == 0
            || input[candidate + best.length as usize] == input[pos + best.length as usize]
        {
            let length = super::super::fast::match_length(input, pos, distance, max_length);
            let min_length = if distance <= 256 { 11 } else { 3 };
            // Candidates arrive nearest first, so equal lengths cannot win.
            if length >= min_length && length > best.length as usize {
                best = LongLz {
                    distance: distance as u32,
                    length: length as u32,
                };
                if length == max_length {
                    break;
                }
            }
        }
    }

    (best.length >= 3).then_some(best)
}

fn long_lz_buckets(input: &[u8]) -> Rar13MatchFinder {
    Rar13MatchFinder::build(input)
}

fn emit_long_lz_length(bits: &mut BitWriter, avr_ln2: u32, length_code: u32) {
    debug_assert!(length_code < 0x100);
    if avr_ln2 >= 122 {
        emit_decode_num(bits, length_code, 3, DEC_L2, POS_L2);
    } else if avr_ln2 >= 64 {
        emit_decode_num(bits, length_code, 2, DEC_L1, POS_L1);
    } else if length_code <= 7 {
        bits.write_bits(1, length_code as usize + 1);
    } else {
        bits.write_bits(length_code, 16);
    }
}

fn emit_decode_num(
    bits: &mut BitWriter,
    target: u32,
    start_pos: u32,
    dec_tab: &[u16],
    pos_tab: &[u16],
) {
    let (code, len) = encode_decode_num_prefix(target, start_pos, dec_tab, pos_tab)
        .expect("emitted symbol passed fixed codebook validation");
    bits.write_bits(code, len);
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
    // Fixed table/start pairs cover every visited index and have positive thresholds.
    let end = 16.min(pos_tab.len().saturating_sub(1));
    for (len, &base) in pos_tab
        .iter()
        .enumerate()
        .take(end + 1)
        .skip(start_pos as usize)
    {
        let dec_index = len - start_pos as usize;
        let upper = u32::from(dec_tab[dec_index]);
        let previous = if dec_index == 0 {
            0
        } else {
            u32::from(dec_tab[dec_index - 1])
        };
        let max_num = (upper - 1) & !0xf;
        if max_num < previous {
            continue;
        }
        let base = u32::from(base);
        let max_target = ((max_num - previous) >> (16 - len)) + base;
        if target <= max_target {
            // Nonempty fixed-table intervals are contiguous, so earlier ones
            // already handle every target below this base.
            debug_assert!(target >= base);
            let num = previous + ((target - base) << (16 - len));
            return Some((num >> (16 - len), len));
        }
    }
    None
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

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
        super::super::fast::write_msb_bits(
            &mut self.output,
            &mut self.bit_pos,
            u64::from(value),
            count,
        );
    }

    fn finish(self) -> Vec<u8> {
        self.output
    }
}

#[cfg(test)]
#[path = "solid_regressions.rs"]
mod solid_regressions;
