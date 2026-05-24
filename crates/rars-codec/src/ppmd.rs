use crate::{Error, Result};

const MAX_FREQ: u32 = 124;
const MIN_MODEL_CONTEXTS: usize = 1;
// Legacy cap retained for `model_context_limit`; the per-unit suballocator
// is the actual restart trigger.
const PPMD_CONTEXT_BYTES: usize = 16;

// PPMd-H suballocator parameters, per the format-level spec at
// rar-research/doc/PPMD_ALGORITHM_SPECIFICATION.md §4.
const ALLOC_UNIT_BYTES: usize = 12;
const N_BUCKETS: usize = 38;
const MAX_BUCKET_UNITS: usize = 128;

// Lookup tables built once from the spec's bucket-construction algorithm
// (§4.2):
//   for i in 0..38: step = if i >= 12 { 4 } else { i / 4 + 1 }
//                   repeat step times: units_to_index[k++] = i
//                   index_to_units[i] = k
struct AllocTables {
    units_to_index: [u8; MAX_BUCKET_UNITS],
    index_to_units: [u8; N_BUCKETS],
}

fn build_alloc_tables() -> AllocTables {
    let mut units_to_index = [0u8; MAX_BUCKET_UNITS];
    let mut index_to_units = [0u8; N_BUCKETS];
    let mut k: usize = 0;
    for i in 0..N_BUCKETS {
        let step = if i >= 12 { 4 } else { i / 4 + 1 };
        for _ in 0..step {
            if k < units_to_index.len() {
                units_to_index[k] = i as u8;
            }
            k += 1;
        }
        index_to_units[i] = k.min(u8::MAX as usize) as u8;
    }
    AllocTables { units_to_index, index_to_units }
}

fn alloc_tables() -> &'static AllocTables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<AllocTables> = OnceLock::new();
    TABLES.get_or_init(build_alloc_tables)
}

#[derive(Debug, Clone)]
struct Suballocator {
    // Total byte budget (= dict_mb * 1 MiB).
    pool_bytes: usize,
    // Bytes currently committed to live unit allocations.
    units_used: usize,
    // Reserved-text byte budget (1/8 of the pool rounded to whole units,
    // matching spec §5.2). text_ptr reaching this triggers a restart.
    text_capacity: usize,
    // Free-list block counts per bucket. We track counts only — no addresses,
    // so we can't run the block-coalescing (glue) pass from §4.3. Without
    // gluing, fragmentation makes us reach exhaustion fractionally earlier
    // than the reference, but the restart trigger is the same condition.
    free_counts: [u32; N_BUCKETS],
}

impl Default for Suballocator {
    fn default() -> Self {
        Self {
            pool_bytes: 0,
            units_used: 0,
            text_capacity: 0,
            free_counts: [0; N_BUCKETS],
        }
    }
}

impl Suballocator {
    fn reset(&mut self, pool_bytes: usize) {
        self.pool_bytes = pool_bytes;
        self.units_used = 0;
        self.text_capacity = (pool_bytes / 8 / ALLOC_UNIT_BYTES) * ALLOC_UNIT_BYTES;
        self.free_counts = [0; N_BUCKETS];
    }

    fn bucket_for(units: usize) -> Option<usize> {
        if units == 0 || units > MAX_BUCKET_UNITS {
            return None;
        }
        Some(alloc_tables().units_to_index[units - 1] as usize)
    }

    fn bucket_units(bucket: usize) -> usize {
        alloc_tables().index_to_units[bucket] as usize
    }

    fn alloc(&mut self, units: usize) -> bool {
        let Some(bucket) = Self::bucket_for(units) else {
            return false;
        };
        if self.free_counts[bucket] > 0 {
            self.free_counts[bucket] -= 1;
            return true;
        }
        let bytes = Self::bucket_units(bucket) * ALLOC_UNIT_BYTES;
        // Uninitialised pool (test fixtures that bypass decode_init): act
        // as unbounded rather than refusing everything.
        if self.pool_bytes > 0 && self.units_used + bytes > self.pool_bytes {
            return false;
        }
        self.units_used += bytes;
        true
    }

    fn free(&mut self, units: usize) {
        if let Some(bucket) = Self::bucket_for(units) {
            self.free_counts[bucket] += 1;
        }
    }

    fn text_has_room(&self, text_len: usize) -> bool {
        // When pool isn't initialised (test fixtures that bypass decode_init),
        // text_capacity is 0 — treat that as "unbounded" so we don't break
        // out-of-band callers.
        self.text_capacity == 0 || text_len < self.text_capacity
    }
}
const BIN_SCALE: u32 = 1 << 14;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u8 = 7;
const TOP: u32 = 1 << 24;
const BOT: u32 = 1 << 15;
const INIT_BIN_ESC: [u16; 8] = [
    0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051,
];
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

pub trait PpmdByteReader {
    fn read_ppmd_byte(&mut self) -> Result<u8>;
}

#[derive(Debug, Clone)]
pub struct PpmdDecoder {
    min_context: usize,
    max_context: usize,
    found_state: StateRef,
    order_fall: usize,
    init_esc: u32,
    prev_success: u32,
    max_order: usize,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,
    ns2bs_indx: [u8; 256],
    ns2indx: [u8; 256],
    bin_summ: [[u16; 64]; 128],
    see: [[See; 16]; 25],
    dummy_see: See,
    contexts: Vec<Context>,
    text: Vec<u8>,
    range: RangeDecoder,
    allocated: bool,
    max_contexts: usize,
    suballoc: Suballocator,
}

#[derive(Debug, Clone)]
pub struct PpmdEncoder {
    model: PpmdDecoder,
    range: RangeEncoder,
    esc_char: u8,
}

#[derive(Debug, Clone)]
struct Context {
    states: Vec<State>,
    summ_freq: u16,
    suffix: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct State {
    symbol: u8,
    freq: u8,
    successor: Successor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Successor {
    None,
    Raw(usize),
    Context(usize),
}

#[derive(Debug, Clone, Copy)]
struct StateRef {
    context: usize,
    index: usize,
}

#[derive(Debug, Clone, Copy)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

#[derive(Debug, Clone)]
struct RangeDecoder {
    range: u32,
    code: u32,
    low: u32,
}

impl PpmdDecoder {
    pub fn new() -> Self {
        let mut ns2bs_indx = [0u8; 256];
        ns2bs_indx[0] = 0;
        ns2bs_indx[1] = 2;
        ns2bs_indx[2..11].fill(4);
        ns2bs_indx[11..].fill(6);

        let mut ns2indx = [0u8; 256];
        ns2indx[0] = 0;
        ns2indx[1] = 1;
        ns2indx[2] = 2;
        let mut m = 3u8;
        let mut k = 1u8;
        for item in ns2indx.iter_mut().skip(3) {
            *item = m;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
        }

        Self {
            min_context: 0,
            max_context: 0,
            found_state: StateRef {
                context: 0,
                index: 0,
            },
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            ns2bs_indx,
            ns2indx,
            bin_summ: [[0; 64]; 128],
            see: [[See {
                summ: 0,
                shift: 0,
                count: 0,
            }; 16]; 25],
            dummy_see: See {
                summ: 0,
                shift: PERIOD_BITS,
                count: 64,
            },
            contexts: Vec::new(),
            text: Vec::new(),
            range: RangeDecoder::new(),
            allocated: false,
            max_contexts: MIN_MODEL_CONTEXTS,
            suballoc: Suballocator::default(),
        }
    }

    // Units occupied by a context's state array. Single-state (binary)
    // contexts store the state inline, so the array is 0 units. Otherwise
    // ceil(n/2) units fit n states at 2-per-unit (states are 6 bytes each).
    fn state_array_units(n: usize) -> usize {
        if n < 2 {
            0
        } else {
            (n + 1) / 2
        }
    }

    pub fn decode_init(
        &mut self,
        first_byte: u8,
        input: &mut impl PpmdByteReader,
        esc_char: &mut u8,
    ) -> Result<()> {
        let reset = first_byte & 0x20 != 0;
        let max_mb = if reset {
            Some(input.read_ppmd_byte()?)
        } else {
            None
        };
        if first_byte & 0x40 != 0 {
            *esc_char = input.read_ppmd_byte()?;
        }
        self.range.init(input)?;
        if reset {
            let mut max_order = ((first_byte & 0x1f) as usize) + 1;
            if max_order > 16 {
                max_order = 16 + (max_order - 16) * 3;
            }
            if max_order == 1 {
                return Err(Error::InvalidData("RAR PPMd order is invalid"));
            }
            let dictionary_mb = max_mb.unwrap_or(0) as usize + 1;
            self.max_contexts = model_context_limit(dictionary_mb);
            self.suballoc
                .reset(dictionary_mb.saturating_mul(1024 * 1024));
            self.init_model(max_order);
            self.allocated = true;
        } else if !self.allocated {
            return Err(Error::InvalidData("RAR PPMd block reuses missing model"));
        }
        Ok(())
    }

    pub fn decode_symbol(&mut self, input: &mut impl PpmdByteReader) -> Result<Option<u8>> {
        let mut mask = [true; 256];
        let min = self.min_context;
        if self.contexts[min].states.len() != 1 {
            let summ_freq = self.contexts[min].summ_freq as u32;
            if summ_freq > self.range.range {
                return Err(Error::InvalidData("RAR PPMd range is invalid"));
            }
            let mut count = self.range.get_threshold(summ_freq)?;
            let mut hi_cnt = 0u32;
            let mut found = None;
            for (index, state) in self.contexts[min].states.iter().enumerate() {
                if count < state.freq as u32 {
                    found = Some((index, hi_cnt, state.freq as u32, state.symbol));
                    break;
                }
                count -= state.freq as u32;
                hi_cnt += state.freq as u32;
            }
            if let Some((index, start, size, symbol)) = found {
                self.range.decode(start, size);
                self.found_state = StateRef {
                    context: min,
                    index,
                };
                if index == 0 {
                    self.update1_0()?;
                } else {
                    self.prev_success = 0;
                    self.update1()?;
                }
                self.range.normalize(input)?;
                return Ok(Some(symbol));
            }
            if hi_cnt >= summ_freq {
                return Err(Error::InvalidData("RAR PPMd frequency sum is invalid"));
            }
            self.prev_success = 0;
            self.range.decode(hi_cnt, summ_freq - hi_cnt);
            self.hi_bits_flag = hi_bits_flag(self.state(self.found_state)?.symbol, 3);
            for state in &self.contexts[min].states {
                mask[state.symbol as usize] = false;
            }
        } else {
            let state = self.contexts[min].states[0];
            let idx = self.bin_summ_index(state)?;
            let prob = self.bin_summ[idx.0][idx.1] as u32;
            let size0 = (self.range.range >> 14).wrapping_mul(prob);
            let next_prob = update_prob_1(prob);
            if self.range.code.wrapping_sub(self.range.low) < size0 {
                self.bin_summ[idx.0][idx.1] = (next_prob + (1 << INT_BITS)) as u16;
                self.range.decode_bit0(size0);
                self.found_state = StateRef {
                    context: min,
                    index: 0,
                };
                self.update_bin()?;
                self.range.normalize(input)?;
                return Ok(Some(state.symbol));
            }
            self.bin_summ[idx.0][idx.1] = next_prob as u16;
            self.init_esc = EXP_ESCAPE[(next_prob >> 10) as usize] as u32;
            self.range.decode_bit1(size0);
            mask[state.symbol as usize] = false;
            self.prev_success = 0;
        }

        loop {
            self.range.normalize(input)?;
            let mut mc = self.min_context;
            let num_masked = self.contexts[mc].states.len();
            loop {
                self.order_fall += 1;
                let Some(suffix) = self.contexts[mc].suffix else {
                    return Ok(None);
                };
                mc = suffix;
                if self.contexts[mc].states.len() != num_masked {
                    break;
                }
            }
            self.min_context = mc;

            let hi_cnt = self.contexts[mc]
                .states
                .iter()
                .filter(|state| mask[state.symbol as usize])
                .map(|state| state.freq as u32)
                .sum::<u32>();
            let (see_ref, esc_freq) = self.make_esc_freq(num_masked)?;
            let freq_sum = hi_cnt + esc_freq;
            if freq_sum > self.range.range {
                return Err(Error::InvalidData("RAR PPMd escape range is invalid"));
            }
            let mut count = self.range.get_threshold(freq_sum)?;
            if count < hi_cnt {
                let mut start = 0u32;
                for (index, state) in self.contexts[mc].states.iter().enumerate() {
                    if !mask[state.symbol as usize] {
                        continue;
                    }
                    let freq = state.freq as u32;
                    if count < freq {
                        let symbol = state.symbol;
                        self.range.decode(start, freq);
                        self.update_see(see_ref);
                        self.found_state = StateRef { context: mc, index };
                        self.update2()?;
                        self.range.normalize(input)?;
                        return Ok(Some(symbol));
                    }
                    count -= freq;
                    start += freq;
                }
                return Err(Error::InvalidData("RAR PPMd masked symbol is invalid"));
            }
            if count >= freq_sum {
                return Err(Error::InvalidData("RAR PPMd escape symbol is invalid"));
            }
            self.range.decode(hi_cnt, freq_sum - hi_cnt);
            self.add_see_summ(see_ref, freq_sum);
            for state in &self.contexts[mc].states {
                mask[state.symbol as usize] = false;
            }
        }
    }

    fn encode_symbol(&mut self, symbol: u8, output: &mut RangeEncoder) -> Result<()> {
        let mut mask = [true; 256];
        let min = self.min_context;
        if self.contexts[min].states.len() != 1 {
            let summ_freq = self.contexts[min].summ_freq as u32;
            let mut start = 0u32;
            let mut found = None;
            for (index, state) in self.contexts[min].states.iter().enumerate() {
                if state.symbol == symbol {
                    found = Some((index, start, state.freq as u32));
                    break;
                }
                start += state.freq as u32;
            }
            if let Some((index, start, size)) = found {
                output.encode(start, size, summ_freq);
                self.found_state = StateRef {
                    context: min,
                    index,
                };
                if index == 0 {
                    self.update1_0()?;
                } else {
                    self.prev_success = 0;
                    self.update1()?;
                }
                output.normalize();
                return Ok(());
            }
            if start >= summ_freq {
                return Err(Error::InvalidData("RAR PPMd frequency sum is invalid"));
            }
            self.prev_success = 0;
            output.encode(start, summ_freq - start, summ_freq);
            self.hi_bits_flag = hi_bits_flag(self.state(self.found_state)?.symbol, 3);
            for state in &self.contexts[min].states {
                mask[state.symbol as usize] = false;
            }
        } else {
            let state = self.contexts[min].states[0];
            let idx = self.bin_summ_index(state)?;
            let prob = self.bin_summ[idx.0][idx.1] as u32;
            let size0 = (output.range >> 14).wrapping_mul(prob);
            let next_prob = update_prob_1(prob);
            if state.symbol == symbol {
                self.bin_summ[idx.0][idx.1] = (next_prob + (1 << INT_BITS)) as u16;
                output.encode_bit0(size0);
                self.found_state = StateRef {
                    context: min,
                    index: 0,
                };
                self.update_bin()?;
                output.normalize();
                return Ok(());
            }
            self.bin_summ[idx.0][idx.1] = next_prob as u16;
            self.init_esc = EXP_ESCAPE[(next_prob >> 10) as usize] as u32;
            output.encode_bit1(size0);
            mask[state.symbol as usize] = false;
            self.prev_success = 0;
        }

        loop {
            output.normalize();
            let mut mc = self.min_context;
            let num_masked = self.contexts[mc].states.len();
            loop {
                self.order_fall += 1;
                let Some(suffix) = self.contexts[mc].suffix else {
                    return Err(Error::InvalidData("RAR PPMd symbol is not encodable"));
                };
                mc = suffix;
                if self.contexts[mc].states.len() != num_masked {
                    break;
                }
            }
            self.min_context = mc;

            let hi_cnt = self.contexts[mc]
                .states
                .iter()
                .filter(|state| mask[state.symbol as usize])
                .map(|state| state.freq as u32)
                .sum::<u32>();
            let (see_ref, esc_freq) = self.make_esc_freq(num_masked)?;
            let freq_sum = hi_cnt + esc_freq;
            let mut start = 0u32;
            let mut found = None;
            for (index, state) in self.contexts[mc].states.iter().enumerate() {
                if !mask[state.symbol as usize] {
                    continue;
                }
                let freq = state.freq as u32;
                if state.symbol == symbol {
                    found = Some((index, start, freq));
                    break;
                }
                start += freq;
            }
            if let Some((index, start, freq)) = found {
                output.encode(start, freq, freq_sum);
                self.update_see(see_ref);
                self.found_state = StateRef { context: mc, index };
                self.update2()?;
                output.normalize();
                return Ok(());
            }
            output.encode(hi_cnt, freq_sum - hi_cnt, freq_sum);
            self.add_see_summ(see_ref, freq_sum);
            for state in &self.contexts[mc].states {
                mask[state.symbol as usize] = false;
            }
        }
    }

    fn init_model(&mut self, max_order: usize) {
        self.contexts.clear();
        self.text.clear();
        // Spec §5.2 RestartModel: clear free lists, reserve root context
        // (1 unit) + its 256-state array (128 units).
        let pool = self.suballoc.pool_bytes;
        self.suballoc.reset(pool);
        self.suballoc.alloc(1);
        self.suballoc.alloc(128);
        self.max_order = max_order;
        self.order_fall = max_order;
        self.init_rl = -(max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        let states = (0..=255)
            .map(|symbol| State {
                symbol,
                freq: 1,
                successor: Successor::None,
            })
            .collect();
        self.contexts.push(Context {
            states,
            summ_freq: 257,
            suffix: None,
        });
        self.min_context = 0;
        self.max_context = 0;
        self.found_state = StateRef {
            context: 0,
            index: 0,
        };

        for i in 0..128 {
            for (k, &init_bin_esc) in INIT_BIN_ESC.iter().enumerate() {
                let value = BIN_SCALE - u32::from(init_bin_esc) / (i as u32 + 2);
                for m in (0..64).step_by(8) {
                    self.bin_summ[i][k + m] = value as u16;
                }
            }
        }
        for i in 0..25 {
            let summ = ((5 * i + 10) << (PERIOD_BITS - 4)) as u16;
            for k in 0..16 {
                self.see[i][k] = See {
                    summ,
                    shift: PERIOD_BITS - 4,
                    count: 4,
                };
            }
        }
        self.dummy_see = See {
            summ: 0,
            shift: PERIOD_BITS,
            count: 64,
        };
    }

    fn bin_summ_index(&mut self, state: State) -> Result<(usize, usize)> {
        let suffix = self.contexts[self.min_context]
            .suffix
            .ok_or(Error::InvalidData("RAR PPMd binary context has no suffix"))?;
        let suffix_stats = self.contexts[suffix].states.len();
        self.hi_bits_flag = hi_bits_flag(self.state(self.found_state)?.symbol, 3);
        let row = state.freq as usize - 1;
        let col = self.prev_success as usize
            + ((self.run_length >> 26) as usize & 0x20)
            + self.ns2bs_indx[suffix_stats - 1] as usize
            + hi_bits_flag(state.symbol, 4) as usize
            + self.hi_bits_flag as usize;
        Ok((row, col))
    }

    fn make_esc_freq(&mut self, num_masked: usize) -> Result<(SeeRef, u32)> {
        let mc = self.min_context;
        let num_stats = self.contexts[mc].states.len();
        if num_stats == 256 {
            return Ok((SeeRef::Dummy, 1));
        }
        if num_masked >= num_stats {
            return Err(Error::InvalidData("RAR PPMd masked-state count is invalid"));
        }
        let non_masked = num_stats
            .checked_sub(num_masked)
            .ok_or(Error::InvalidData("RAR PPMd masked-state count is invalid"))?;
        let suffix = self.contexts[mc].suffix.unwrap_or(mc);
        let suffix_stats = self.contexts[suffix].states.len();
        let suffix_delta = suffix_stats
            .checked_sub(num_stats)
            .ok_or(Error::InvalidData("RAR PPMd suffix-state count is invalid"))?;
        let col = (non_masked < suffix_delta) as usize
            + 2 * ((self.contexts[mc].summ_freq as usize) < 11 * num_stats) as usize
            + 4 * (num_masked > non_masked) as usize
            + self.hi_bits_flag as usize;
        let row = self.ns2indx[non_masked - 1] as usize;
        let see = &mut self.see[row][col];
        let summ = see.summ;
        let r = (summ >> see.shift) as u32;
        see.summ = summ.wrapping_sub(r as u16);
        Ok((SeeRef::Table(row, col), r + u32::from(r == 0)))
    }

    fn update_see(&mut self, see_ref: SeeRef) {
        let see = match see_ref {
            SeeRef::Dummy => &mut self.dummy_see,
            SeeRef::Table(row, col) => &mut self.see[row][col],
        };
        if see.shift < PERIOD_BITS {
            see.count = see.count.wrapping_sub(1);
            if see.count == 0 {
                see.summ = see.summ.wrapping_shl(1);
                see.count = 3 << see.shift;
                see.shift += 1;
            }
        }
    }

    fn add_see_summ(&mut self, see_ref: SeeRef, value: u32) {
        let see = match see_ref {
            SeeRef::Dummy => &mut self.dummy_see,
            SeeRef::Table(row, col) => &mut self.see[row][col],
        };
        see.summ = see.summ.wrapping_add(value as u16);
    }

    fn update1_0(&mut self) -> Result<()> {
        let fs = self.found_state;
        let freq = self.state(fs)?.freq as u32;
        let summ_freq = self.contexts[fs.context].summ_freq as u32;
        self.prev_success = u32::from(2 * freq > summ_freq);
        self.run_length += self.prev_success as i32;
        self.contexts[fs.context].summ_freq = self.contexts[fs.context].summ_freq.wrapping_add(4);
        self.state_mut(fs)?.freq = (freq + 4) as u8;
        if freq + 4 > MAX_FREQ {
            self.rescale();
        }
        self.next_context()
    }

    fn update1(&mut self) -> Result<()> {
        let fs = self.found_state;
        let freq = self.state(fs)?.freq as u32 + 4;
        self.contexts[fs.context].summ_freq = self.contexts[fs.context].summ_freq.wrapping_add(4);
        self.state_mut(fs)?.freq = freq as u8;
        if fs.index > 0
            && self.contexts[fs.context].states[fs.index].freq
                > self.contexts[fs.context].states[fs.index - 1].freq
        {
            self.contexts[fs.context]
                .states
                .swap(fs.index, fs.index - 1);
            self.found_state.index -= 1;
            if freq > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context()
    }

    fn update2(&mut self) -> Result<()> {
        let fs = self.found_state;
        let freq = self.state(fs)?.freq as u32 + 4;
        self.run_length = self.init_rl;
        self.contexts[fs.context].summ_freq = self.contexts[fs.context].summ_freq.wrapping_add(4);
        self.state_mut(fs)?.freq = freq as u8;
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.update_model()
    }

    fn update_bin(&mut self) -> Result<()> {
        let fs = self.found_state;
        let freq = self.state(fs)?.freq;
        self.state_mut(fs)?.freq = freq.wrapping_add(u8::from(freq < 128));
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context()
    }

    fn next_context(&mut self) -> Result<()> {
        let successor = self.state(self.found_state)?.successor;
        if let Successor::Context(context) = successor {
            if self.order_fall == 0 {
                self.max_context = context;
                self.min_context = context;
                return Ok(());
            }
        }
        self.update_model()
    }

    fn update_model(&mut self) -> Result<()> {
        let fs = self.state(self.found_state)?;
        let found_symbol = fs.symbol;
        if fs.freq < (MAX_FREQ / 4) as u8 && self.contexts[self.min_context].suffix.is_some() {
            let suffix = self.contexts[self.min_context].suffix.unwrap();
            if self.contexts[suffix].states.len() == 1 {
                let freq = self.contexts[suffix].states[0].freq;
                if freq < 32 {
                    self.contexts[suffix].states[0].freq += 1;
                }
            } else if let Some(mut index) = self.contexts[suffix]
                .states
                .iter()
                .position(|state| state.symbol == found_symbol)
            {
                if index > 0
                    && self.contexts[suffix].states[index].freq
                        >= self.contexts[suffix].states[index - 1].freq
                {
                    self.contexts[suffix].states.swap(index, index - 1);
                    index -= 1;
                }
                if self.contexts[suffix].states[index].freq < (MAX_FREQ - 9) as u8 {
                    self.contexts[suffix].states[index].freq += 2;
                    self.contexts[suffix].summ_freq =
                        self.contexts[suffix].summ_freq.wrapping_add(2);
                }
            }
        }

        if self.order_fall == 0 {
            let Some(context) = self.create_successors() else {
                self.init_model(self.max_order);
                return Ok(());
            };
            self.max_context = context;
            self.min_context = context;
            self.state_mut(self.found_state)?.successor = Successor::Context(context);
            return Ok(());
        }

        // Spec §8.3 step 3: text_ptr reaching units_start triggers a restart.
        if !self.suballoc.text_has_room(self.text.len()) {
            self.init_model(self.max_order);
            return Ok(());
        }
        self.text.push(found_symbol);
        let max_successor = Successor::Raw(self.text.len());
        let mut min_successor = fs.successor;
        if min_successor != Successor::None {
            if matches!(min_successor, Successor::Raw(_)) {
                let Some(context) = self.create_successors() else {
                    self.init_model(self.max_order);
                    return Ok(());
                };
                min_successor = Successor::Context(context);
            }
            self.order_fall -= 1;
            if self.order_fall == 0 && self.max_context != self.min_context {
                self.text.pop();
            }
        } else {
            self.state_mut(self.found_state)?.successor = max_successor;
            min_successor = Successor::Context(self.min_context);
        }

        let mc = self.min_context;
        let mut c = self.max_context;
        self.min_context = match min_successor {
            Successor::Context(context) => context,
            _ => self.min_context,
        };
        self.max_context = self.min_context;
        if c == mc {
            return Ok(());
        }

        let ns = self.contexts[mc].states.len() as u32;
        let s0 = self.contexts[mc]
            .summ_freq
            .checked_sub(ns as u16)
            .map(u32::from)
            .and_then(|value| value.checked_sub(fs.freq as u32 - 1))
            .ok_or(Error::InvalidData("RAR PPMd model frequency is invalid"))?;
        while c != mc {
            let ns1 = self.contexts[c].states.len() as u32;
            let mut sum;
            if ns1 != 1 {
                sum = self.contexts[c].summ_freq as u32;
                sum += u32::from(2 * ns1 < ns) + 2 * u32::from(4 * ns1 <= ns && sum <= 8 * ns1);
            } else {
                let old = self.contexts[c].states[0];
                let freq = if old.freq < (MAX_FREQ / 4 - 1) as u8 {
                    old.freq * 2
                } else {
                    (MAX_FREQ - 4) as u8
                };
                self.contexts[c].states[0].freq = freq;
                sum = freq as u32 + self.init_esc + u32::from(ns > 3);
            }

            let mut cf = (sum + 6)
                .checked_mul(2)
                .and_then(|value| value.checked_mul(fs.freq as u32))
                .ok_or(Error::InvalidData("RAR PPMd model frequency overflows"))?;
            let sf = s0
                .checked_add(sum)
                .ok_or(Error::InvalidData("RAR PPMd model frequency overflows"))?;
            if sf == 0 {
                return Err(Error::InvalidData("RAR PPMd model frequency is invalid"));
            }
            if cf < 6 * sf {
                cf = 1 + u32::from(cf > sf) + u32::from(cf >= 4 * sf);
                sum += 3;
            } else {
                cf = 4
                    + u32::from(cf >= 9 * sf)
                    + u32::from(cf >= 12 * sf)
                    + u32::from(cf >= 15 * sf);
                sum += cf;
            }
            let old_n = self.contexts[c].states.len();
            if !self.grow_state_array(old_n, old_n + 1) {
                self.init_model(self.max_order);
                return Ok(());
            }
            self.contexts[c].states.push(State {
                symbol: found_symbol,
                freq: cf as u8,
                successor: if self.order_fall == 0 {
                    min_successor
                } else {
                    max_successor
                },
            });
            self.contexts[c].summ_freq = u16::try_from(sum)
                .map_err(|_| Error::InvalidData("RAR PPMd model frequency overflows"))?;
            c = self.contexts[c].suffix.unwrap_or(mc);
        }
        Ok(())
    }

    fn create_successors(&mut self) -> Option<usize> {
        let up_branch = match self.state(self.found_state).ok()?.successor {
            Successor::Raw(pos) => pos,
            Successor::Context(context) if self.order_fall == 0 => return Some(context),
            _ => return None,
        };
        let mut c = self.min_context;
        let mut ps = Vec::new();
        if self.order_fall != 0 {
            ps.push(self.found_state);
        }
        while let Some(suffix) = self.contexts[c].suffix {
            c = suffix;
            let found_symbol = self.state(self.found_state).ok()?.symbol;
            let index = self.contexts[c]
                .states
                .iter()
                .position(|state| state.symbol == found_symbol)?;
            let successor = self.contexts[c].states[index].successor;
            if successor != Successor::Raw(up_branch) {
                if let Successor::Context(context) = successor {
                    c = context;
                    if ps.is_empty() {
                        return Some(c);
                    }
                    break;
                }
                return None;
            }
            ps.push(StateRef { context: c, index });
        }
        if ps.is_empty() {
            return Some(c);
        }

        let new_sym = *self.text.get(up_branch)?;
        let up_successor = Successor::Raw(up_branch + 1);
        let new_freq = if self.contexts[c].states.len() == 1 {
            self.contexts[c].states[0].freq
        } else {
            let state = self.contexts[c]
                .states
                .iter()
                .find(|state| state.symbol == new_sym)?;
            let cf = state.freq as u32 - 1;
            let s0 = self.contexts[c].summ_freq as u32 - self.contexts[c].states.len() as u32 - cf;
            (1 + if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                (2 * cf + 3 * s0 - 1) / (2 * s0)
            }) as u8
        };

        while let Some(state_ref) = ps.pop() {
            let context = self.push_context(Context {
                states: vec![State {
                    symbol: new_sym,
                    freq: new_freq,
                    successor: up_successor,
                }],
                summ_freq: 0,
                suffix: Some(c),
            })?;
            self.state_mut(state_ref).ok()?.successor = Successor::Context(context);
            c = context;
        }
        Some(c)
    }

    fn push_context(&mut self, context: Context) -> Option<usize> {
        if self.contexts.len() >= self.max_contexts {
            return None;
        }
        // 1 unit for the context header; binary contexts (1 state) carry
        // their state inline, multi-state contexts also need a state array
        // (allocated below).
        if !self.suballoc.alloc(1) {
            return None;
        }
        let array_units = Self::state_array_units(context.states.len());
        if array_units > 0 && !self.suballoc.alloc(array_units) {
            self.suballoc.free(1);
            return None;
        }
        let index = self.contexts.len();
        self.contexts.push(context);
        Some(index)
    }

    // Grow a context's state array from `old_n` → `new_n` states. Models
    // ExpandUnits: if the same bucket still fits, no realloc happens;
    // otherwise allocate the new size first, then release the old slot.
    fn grow_state_array(&mut self, old_n: usize, new_n: usize) -> bool {
        let old_units = Self::state_array_units(old_n);
        let new_units = Self::state_array_units(new_n);
        if new_units == 0 || new_units <= old_units {
            return true;
        }
        if old_units > 0 {
            let old_b = Suballocator::bucket_for(old_units);
            let new_b = Suballocator::bucket_for(new_units);
            if old_b == new_b {
                return true;
            }
        }
        if !self.suballoc.alloc(new_units) {
            return false;
        }
        if old_units > 0 {
            self.suballoc.free(old_units);
        }
        true
    }

    // Rescale shrinks a state array. Models ShrinkUnits: if the surviving
    // states still fit in the original bucket, nothing changes; otherwise
    // return the old slot and reallocate at the smaller bucket.
    fn shrink_state_array(&mut self, old_n: usize, new_n: usize) {
        let old_units = Self::state_array_units(old_n);
        let new_units = Self::state_array_units(new_n);
        if old_units == 0 || new_units >= old_units {
            return;
        }
        let old_b = Suballocator::bucket_for(old_units);
        let new_b = if new_units > 0 {
            Suballocator::bucket_for(new_units)
        } else {
            None
        };
        if old_b == new_b && new_b.is_some() {
            return;
        }
        self.suballoc.free(old_units);
        if new_units > 0 {
            let _ = self.suballoc.alloc(new_units);
        }
    }

    fn rescale(&mut self) {
        let ctx = self.min_context;
        let original_state_count = self.contexts[ctx].states.len();
        let mut states = self.contexts[ctx].states.clone();
        let found = self.found_state.index;
        if found != 0 {
            let state = states.remove(found);
            states.insert(0, state);
            self.found_state.index = 0;
        }
        let mut sum_freq = states[0].freq as u32;
        let mut esc_freq = self.contexts[ctx].summ_freq as u32 - sum_freq;
        let adder = u32::from(self.order_fall != 0);
        sum_freq = (sum_freq + 4 + adder) >> 1;
        states[0].freq = sum_freq as u8;
        for index in 1..states.len() {
            let freq = states[index].freq as u32;
            esc_freq -= freq;
            let freq = (freq + adder) >> 1;
            sum_freq += freq;
            states[index].freq = freq as u8;
            let mut j = index;
            while j > 0 && states[j].freq > states[j - 1].freq {
                states.swap(j, j - 1);
                j -= 1;
            }
        }
        while states.last().is_some_and(|state| state.freq == 0) {
            states.pop();
            esc_freq += 1;
        }
        if states.len() == 1 {
            let mut freq = states[0].freq as u32;
            while esc_freq > 1 {
                esc_freq >>= 1;
                freq = (freq + 1) >> 1;
            }
            states[0].freq = freq as u8;
            self.shrink_state_array(original_state_count, 1);
            self.contexts[ctx].states = states;
            self.found_state.index = 0;
            return;
        }
        self.contexts[ctx].summ_freq = (sum_freq + esc_freq - (esc_freq >> 1)) as u16;
        self.shrink_state_array(original_state_count, states.len());
        self.contexts[ctx].states = states;
        self.found_state.index = 0;
    }

    fn state(&self, state: StateRef) -> Result<State> {
        self.contexts
            .get(state.context)
            .and_then(|context| context.states.get(state.index))
            .copied()
            .ok_or(Error::InvalidData("RAR PPMd state reference is invalid"))
    }

    fn state_mut(&mut self, state: StateRef) -> Result<&mut State> {
        self.contexts
            .get_mut(state.context)
            .and_then(|context| context.states.get_mut(state.index))
            .ok_or(Error::InvalidData("RAR PPMd state reference is invalid"))
    }
}

impl PpmdEncoder {
    pub fn new(max_order: usize, esc_char: u8, dictionary_mb: usize) -> Result<Self> {
        if !(2..=64).contains(&max_order) {
            return Err(Error::InvalidData("RAR PPMd order is invalid"));
        }
        if dictionary_mb == 0 {
            return Err(Error::InvalidData("RAR PPMd dictionary size is invalid"));
        }
        let mut model = PpmdDecoder::new();
        model.max_contexts = model_context_limit(dictionary_mb);
        model.suballoc
            .reset(dictionary_mb.saturating_mul(1024 * 1024));
        model.init_model(max_order);
        model.allocated = true;
        Ok(Self {
            model,
            range: RangeEncoder::new(),
            esc_char,
        })
    }

    pub fn encode_literal(&mut self, symbol: u8) -> Result<()> {
        self.model.encode_symbol(symbol, &mut self.range)?;
        if symbol == self.esc_char {
            self.model.encode_symbol(1, &mut self.range)?;
        }
        Ok(())
    }

    pub fn encode_repeat_offset_one(&mut self, length: usize) -> Result<()> {
        if !(4..=259).contains(&length) {
            return Err(Error::InvalidData(
                "RAR PPMd offset-one repeat length is invalid",
            ));
        }
        self.model.encode_symbol(self.esc_char, &mut self.range)?;
        self.model.encode_symbol(5, &mut self.range)?;
        self.model
            .encode_symbol((length - 4) as u8, &mut self.range)?;
        Ok(())
    }

    pub fn encode_match(&mut self, offset: usize, length: usize) -> Result<()> {
        if !(2..=0x1000001).contains(&offset) || !(32..=287).contains(&length) {
            return Err(Error::InvalidData("RAR PPMd match is invalid"));
        }
        let encoded_offset = offset - 2;
        self.model.encode_symbol(self.esc_char, &mut self.range)?;
        self.model.encode_symbol(4, &mut self.range)?;
        self.model
            .encode_symbol(((encoded_offset >> 16) & 0xff) as u8, &mut self.range)?;
        self.model
            .encode_symbol(((encoded_offset >> 8) & 0xff) as u8, &mut self.range)?;
        self.model
            .encode_symbol((encoded_offset & 0xff) as u8, &mut self.range)?;
        self.model
            .encode_symbol((length - 32) as u8, &mut self.range)?;
        Ok(())
    }

    pub fn encode_vm_filter_record(&mut self, record: &[u8]) -> Result<()> {
        self.model.encode_symbol(self.esc_char, &mut self.range)?;
        self.model.encode_symbol(3, &mut self.range)?;
        for &byte in record {
            self.model.encode_symbol(byte, &mut self.range)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<Vec<u8>> {
        self.model.encode_symbol(self.esc_char, &mut self.range)?;
        self.model.encode_symbol(2, &mut self.range)?;
        Ok(self.range.finish())
    }
}

#[derive(Debug, Clone, Copy)]
enum SeeRef {
    Dummy,
    Table(usize, usize),
}

impl RangeDecoder {
    fn new() -> Self {
        Self {
            range: 0xffff_ffff,
            code: 0,
            low: 0,
        }
    }

    fn init(&mut self, input: &mut impl PpmdByteReader) -> Result<()> {
        self.code = 0;
        self.range = 0xffff_ffff;
        self.low = 0;
        for _ in 0..4 {
            self.code = (self.code << 8) | input.read_ppmd_byte()? as u32;
        }
        if self.code == 0xffff_ffff {
            return Err(Error::InvalidData("RAR PPMd range code is invalid"));
        }
        Ok(())
    }

    fn get_threshold(&mut self, total: u32) -> Result<u32> {
        if total == 0 {
            return Err(Error::InvalidData("RAR PPMd frequency sum is zero"));
        }
        self.range /= total;
        Ok(self.code.wrapping_sub(self.low) / self.range)
    }

    fn decode(&mut self, start: u32, size: u32) {
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.range = self.range.wrapping_mul(size);
    }

    fn decode_bit0(&mut self, size0: u32) {
        self.range = size0;
    }

    fn decode_bit1(&mut self, size0: u32) {
        self.low = self.low.wrapping_add(size0);
        self.range = (self.range & !(BIN_SCALE - 1)).wrapping_sub(size0);
    }

    fn normalize(&mut self, input: &mut impl PpmdByteReader) -> Result<()> {
        while (self.low ^ self.low.wrapping_add(self.range)) < TOP
            || (self.range < BOT && {
                self.range = self.low.wrapping_neg() & (BOT - 1);
                true
            })
        {
            self.code = (self.code << 8) | input.read_ppmd_byte()? as u32;
            self.range <<= 8;
            self.low <<= 8;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RangeEncoder {
    low: u32,
    range: u32,
    out: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        Self {
            low: 0,
            range: 0xffff_ffff,
            out: Vec::new(),
        }
    }

    fn encode(&mut self, start: u32, size: u32, total: u32) {
        self.range /= total;
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
    }

    fn encode_bit0(&mut self, size0: u32) {
        self.range = size0;
    }

    fn encode_bit1(&mut self, size0: u32) {
        self.low = self.low.wrapping_add(size0);
        self.range = (self.range & !(BIN_SCALE - 1)).wrapping_sub(size0);
    }

    fn normalize(&mut self) {
        while (self.low ^ self.low.wrapping_add(self.range)) < TOP
            || (self.range < BOT && {
                self.range = self.low.wrapping_neg() & (BOT - 1);
                true
            })
        {
            self.out.push((self.low >> 24) as u8);
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..4 {
            self.out.push((self.low >> 24) as u8);
            self.low <<= 8;
        }
        self.out
    }
}

fn update_prob_1(prob: u32) -> u32 {
    prob - ((prob + (1 << 5)) >> INT_BITS)
}

fn hi_bits_flag(symbol: u8, bits: u32) -> u32 {
    ((symbol as u32 + 0xc0) >> (8 - bits)) & (1 << bits)
}

fn model_context_limit(dictionary_mb: usize) -> usize {
    dictionary_mb
        .saturating_mul(1024 * 1024)
        .checked_div(PPMD_CONTEXT_BYTES)
        .unwrap_or(usize::MAX)
        .max(MIN_MODEL_CONTEXTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_tables_match_spec_pattern() {
        let t = alloc_tables();
        // Spec §4.2: bucket sizes are 1,2,3,4 then groups of 4 at strides 1,2,3,4.
        // First 12 buckets cover 1..4, then 6,8,10,12, then 15,18,21,24.
        assert_eq!(t.index_to_units[0], 1);
        assert_eq!(t.index_to_units[1], 2);
        assert_eq!(t.index_to_units[2], 3);
        assert_eq!(t.index_to_units[3], 4);
        assert_eq!(t.index_to_units[4], 6);
        assert_eq!(t.index_to_units[5], 8);
        assert_eq!(t.index_to_units[6], 10);
        assert_eq!(t.index_to_units[7], 12);
        assert_eq!(t.index_to_units[8], 15);
        assert_eq!(t.index_to_units[9], 18);
        assert_eq!(t.index_to_units[10], 21);
        assert_eq!(t.index_to_units[11], 24);
        // From bucket 12 onward, stride is 4: 28, 32, 36, 40 ... up to 128.
        assert_eq!(t.index_to_units[12], 28);
        assert_eq!(t.index_to_units[N_BUCKETS - 1], 128);

        // 1-unit requests resolve to bucket 0; 2 → 1; 5,6 → 4 (the 6-unit bucket).
        assert_eq!(t.units_to_index[0], 0);
        assert_eq!(t.units_to_index[1], 1);
        assert_eq!(t.units_to_index[4], 4); // 5 units
        assert_eq!(t.units_to_index[5], 4); // 6 units (same bucket as 5)
    }

    #[test]
    fn suballoc_alloc_until_exhaustion() {
        let mut s = Suballocator::default();
        s.reset(4 * ALLOC_UNIT_BYTES); // 48 bytes = 4 units
        assert!(s.alloc(2)); // bucket 1 = 2 units
        assert!(s.alloc(2)); // another 2 units → 4 used
        assert!(!s.alloc(1)); // pool full
    }

    #[test]
    fn suballoc_reuses_freed_bucket() {
        let mut s = Suballocator::default();
        s.reset(4 * ALLOC_UNIT_BYTES);
        assert!(s.alloc(2));
        assert!(s.alloc(2));
        assert!(!s.alloc(2)); // full
        s.free(2); // freed → bucket 1 has 1 slot
        assert!(s.alloc(2)); // reuses freed slot
        assert!(!s.alloc(2)); // pool truly full again
    }

    #[test]
    fn suballoc_uninitialised_pool_acts_unbounded() {
        let mut s = Suballocator::default();
        // pool_bytes=0; the suballoc shouldn't reject any allocation since the
        // model hasn't been told its budget yet.
        for _ in 0..1000 {
            assert!(s.alloc(2));
        }
        assert!(s.text_has_room(usize::MAX / 2));
    }

    #[test]
    fn state_array_units_handles_boundaries() {
        assert_eq!(PpmdDecoder::state_array_units(0), 0);
        assert_eq!(PpmdDecoder::state_array_units(1), 0); // binary: inline
        assert_eq!(PpmdDecoder::state_array_units(2), 1);
        assert_eq!(PpmdDecoder::state_array_units(3), 2);
        assert_eq!(PpmdDecoder::state_array_units(4), 2);
        assert_eq!(PpmdDecoder::state_array_units(255), 128);
        assert_eq!(PpmdDecoder::state_array_units(256), 128);
    }

    struct Bytes<'a> {
        input: &'a [u8],
    }

    impl PpmdByteReader for Bytes<'_> {
        fn read_ppmd_byte(&mut self) -> Result<u8> {
            let Some((&byte, rest)) = self.input.split_first() else {
                return Err(Error::NeedMoreInput);
            };
            self.input = rest;
            Ok(byte)
        }
    }

    #[test]
    fn decode_init_rejects_truncated_range_header_without_panic() {
        let mut decoder = PpmdDecoder::new();
        let mut input = Bytes { input: &[0, 0] };
        let mut esc = 0;

        assert_eq!(
            decoder.decode_init(0x20 | 1, &mut input, &mut esc),
            Err(Error::NeedMoreInput)
        );
    }

    #[test]
    fn decode_init_rejects_reuse_before_model_allocation() {
        let mut decoder = PpmdDecoder::new();
        let mut input = Bytes {
            input: &[0, 0, 0, 0],
        };
        let mut esc = 0;

        assert_eq!(
            decoder.decode_init(0, &mut input, &mut esc),
            Err(Error::InvalidData("RAR PPMd block reuses missing model"))
        );
    }

    #[test]
    fn decode_init_accepts_max_wire_order_without_growing_unbounded_model() {
        let mut decoder = PpmdDecoder::new();
        let mut input = Bytes {
            input: &[0, 0, 0, 0, 0],
        };
        let mut esc = 0;

        decoder
            .decode_init(0x20 | 0x1f, &mut input, &mut esc)
            .unwrap();

        assert_eq!(decoder.max_order, 64);
        assert_eq!(decoder.contexts.len(), 1);
        assert_eq!(decoder.contexts[0].states.len(), 256);
        assert_eq!(decoder.max_contexts, model_context_limit(1));
    }

    #[test]
    fn encoder_rejects_orders_outside_model_bounds() {
        assert!(matches!(
            PpmdEncoder::new(1, 2, 1),
            Err(Error::InvalidData("RAR PPMd order is invalid"))
        ));
        assert!(matches!(
            PpmdEncoder::new(65, 2, 1),
            Err(Error::InvalidData("RAR PPMd order is invalid"))
        ));
    }

    #[test]
    fn encoder_rejects_zero_dictionary_size() {
        assert!(matches!(
            PpmdEncoder::new(4, 2, 0),
            Err(Error::InvalidData("RAR PPMd dictionary size is invalid"))
        ));
    }

    #[test]
    fn range_decoder_rejects_zero_total_without_panic() {
        let mut decoder = RangeDecoder::new();
        let mut input = Bytes {
            input: &[0, 0, 0, 0],
        };
        decoder.init(&mut input).unwrap();

        assert_eq!(
            decoder.get_threshold(0),
            Err(Error::InvalidData("RAR PPMd frequency sum is zero"))
        );
    }

    #[test]
    fn context_allocation_respects_dictionary_limit() {
        let mut decoder = PpmdDecoder::new();
        decoder.max_contexts = 1;
        decoder.init_model(4);

        assert_eq!(
            decoder.push_context(Context {
                states: Vec::new(),
                summ_freq: 0,
                suffix: None,
            }),
            None
        );
    }

    #[test]
    fn make_esc_freq_rejects_invalid_masked_state_count() {
        let mut decoder = PpmdDecoder::new();
        decoder.init_model(4);
        decoder.contexts.push(Context {
            states: vec![
                State {
                    symbol: b'a',
                    freq: 1,
                    successor: Successor::None,
                },
                State {
                    symbol: b'b',
                    freq: 1,
                    successor: Successor::None,
                },
            ],
            summ_freq: 2,
            suffix: Some(0),
        });
        decoder.min_context = 1;

        assert!(matches!(
            decoder.make_esc_freq(2),
            Err(Error::InvalidData("RAR PPMd masked-state count is invalid"))
        ));
    }

    #[test]
    fn update_model_rejects_invalid_frequency_arithmetic() {
        let mut decoder = PpmdDecoder::new();
        decoder.init_model(4);
        decoder.contexts.push(Context {
            states: vec![State {
                symbol: b'a',
                freq: 10,
                successor: Successor::None,
            }],
            summ_freq: 1,
            suffix: Some(0),
        });
        decoder.min_context = 1;
        decoder.max_context = 0;
        decoder.found_state = StateRef {
            context: 1,
            index: 0,
        };
        decoder.order_fall = 1;

        assert!(matches!(
            decoder.update_model(),
            Err(Error::InvalidData("RAR PPMd model frequency is invalid"))
        ));
    }

    #[test]
    fn update_paths_reject_invalid_state_reference_without_panic() {
        let mut decoder = PpmdDecoder::new();
        decoder.init_model(4);
        decoder.found_state = StateRef {
            context: 99,
            index: 0,
        };

        assert_eq!(
            decoder.update1_0(),
            Err(Error::InvalidData("RAR PPMd state reference is invalid"))
        );

        decoder.found_state = StateRef {
            context: 0,
            index: 999,
        };
        assert_eq!(
            decoder.update_bin(),
            Err(Error::InvalidData("RAR PPMd state reference is invalid"))
        );
    }
}
