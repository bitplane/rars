// The RAR 2.9 PPMd (var.H) model, kept as the reference keeps it: one pool
// of 12-byte units holding contexts and state vectors above the raw text,
// with the reference suballocator's free lists threaded through the pool.
// Ported from 7-Zip's public-domain Ppmd7.c and Ppmd7aDec.c (Igor Pavlov,
// after Dmitry Shkarin's PPMd var.H and Dmitry Subbotin's carryless range
// coder). References are byte offsets into the pool, and 0 is null.
//
// The model is consistent whatever the input: input only chooses symbols.
// So pool indexing never fails on corrupt data, and a failing index is a bug.

#[cfg(any(test, feature = "write"))]
use super::workspace::Allowance;
use super::workspace::Budget;
use super::{Error, Result};

const MAX_FREQ: u32 = 124;
const UNIT_SIZE: u32 = 12;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u8 = 7;
const BIN_SCALE: u32 = 1 << (INT_BITS + PERIOD_BITS as u32);
const NUM_INDEXES: usize = 38;
const MAX_ORDER: usize = 64;
const TOP: u32 = 1 << 24;
const BOT: u32 = 1 << 15;
// The budget is charged for the pool in steps of this many bytes.
const CHARGE_STEP: u64 = 64 * 1024;
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];
const INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

pub trait PpmdByteReader {
    fn read_ppmd_byte(&mut self) -> Result<u8>;
}

#[derive(Debug, Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    // After a symbol is found among the states an escape left: the
    // estimate adapts more slowly as it gathers evidence.
    #[inline(always)]
    fn update(&mut self) {
        if self.shift < PERIOD_BITS {
            self.count = self.count.wrapping_sub(1);
            if self.count == 0 {
                self.summ = self.summ.wrapping_shl(1);
                self.count = 3 << self.shift;
                self.shift += 1;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SeeRef {
    Dummy,
    Table(usize, usize),
}

#[derive(Debug, Clone)]
struct RangeDecoder {
    range: u32,
    // Relative to `low`, as in Ppmd7aDec.c.
    code: u32,
    low: u32,
}

impl RangeDecoder {
    fn init(&mut self, input: &mut impl PpmdByteReader) -> Result<()> {
        self.code = 0;
        self.range = u32::MAX;
        self.low = 0;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(input.read_ppmd_byte()?);
        }
        if self.code == u32::MAX {
            return Err(Error::InvalidData("RAR PPMd range code is invalid"));
        }
        Ok(())
    }

    #[inline(always)]
    fn threshold(&mut self, total: u32) -> u32 {
        self.range /= total;
        self.code / self.range
    }

    #[inline(always)]
    fn decode(&mut self, start: u32, size: u32) {
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.code = self.code.wrapping_sub(start);
        self.range = self.range.wrapping_mul(size);
    }

    #[inline(always)]
    fn normalize(&mut self, input: &mut impl PpmdByteReader) -> Result<()> {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    return Ok(());
                }
                self.range = self.low.wrapping_neg() & (BOT - 1);
            }
            self.code = (self.code << 8) | u32::from(input.read_ppmd_byte()?);
            self.range <<= 8;
            self.low <<= 8;
        }
    }
}

#[derive(Debug)]
pub(crate) struct Ppmd7<B: Budget> {
    // The pool, reserved at its declared size. Untouched pages cost nothing,
    // so the budget is charged only for what the model has reached.
    mem: Vec<u8>,
    charge: B::Charge,
    charged: u64,
    // The furthest each region has reached since the pool was allocated. Its
    // pages stay touched across restarts, so these never move back.
    text_peak: u32,
    lo_peak: u32,
    units_floor: u32,
    hi_floor: u32,
    size: u32,
    align: u32,
    text: u32,
    units_start: u32,
    lo_unit: u32,
    hi_unit: u32,
    glue_count: u32,
    free_list: [u32; NUM_INDEXES],
    indx2units: [u8; NUM_INDEXES],
    units2indx: [u8; 128],
    ns2bs_indx: [u8; 256],
    ns2indx: [u8; 256],
    see: [[See; 16]; 25],
    dummy_see: See,
    bin_summ: [[u16; 64]; 128],
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,
    rc: RangeDecoder,
    allocated: bool,
    read_control: crate::read_control::ReadControl,
    #[cfg(test)]
    restarts: usize,
    #[cfg(test)]
    glues: usize,
    #[cfg(test)]
    text_restarts: usize,
}

#[inline(always)]
fn hi_bits_flag3(symbol: u8) -> u32 {
    ((u32::from(symbol) + 0xc0) >> (8 - 3)) & (1 << 3)
}

#[inline(always)]
fn hi_bits_flag4(symbol: u8) -> u32 {
    ((u32::from(symbol) + 0xc0) >> (8 - 4)) & (1 << 4)
}

impl<B: Budget> Ppmd7<B> {
    pub(crate) fn with_allowance(allowance: &B) -> Self {
        let mut indx2units = [0u8; NUM_INDEXES];
        let mut units2indx = [0u8; 128];
        let mut k = 0usize;
        for (i, units) in indx2units.iter_mut().enumerate() {
            let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                units2indx[k] = i as u8;
                k += 1;
            }
            *units = k as u8;
        }
        let mut ns2bs_indx = [0u8; 256];
        ns2bs_indx[0] = 0;
        ns2bs_indx[1] = 2;
        ns2bs_indx[2..11].fill(4);
        ns2bs_indx[11..].fill(6);
        let mut ns2indx = [0u8; 256];
        ns2indx[..3].copy_from_slice(&[0, 1, 2]);
        let (mut m, mut k) = (3u8, 1u8);
        for item in ns2indx.iter_mut().skip(3) {
            *item = m;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
        }
        Self {
            mem: Vec::new(),
            charge: allowance.charge(),
            charged: 0,
            text_peak: 0,
            lo_peak: 0,
            units_floor: 0,
            hi_floor: 0,
            size: 0,
            align: 0,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            glue_count: 0,
            free_list: [0; NUM_INDEXES],
            indx2units,
            units2indx,
            ns2bs_indx,
            ns2indx,
            see: [[See::default(); 16]; 25],
            dummy_see: See::default(),
            bin_summ: [[0; 64]; 128],
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            rc: RangeDecoder {
                range: 0,
                code: 0,
                low: 0,
            },
            allocated: false,
            read_control: crate::read_control::ReadControl::default(),
            #[cfg(test)]
            restarts: 0,
            #[cfg(test)]
            glues: 0,
            #[cfg(test)]
            text_restarts: 0,
        }
    }

    pub(crate) fn set_read_control(&mut self, control: crate::read_control::ReadControl) {
        self.read_control = control;
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        // Only the text, the units in use and the contexts carry data.
        let mut charge = B::allowance(&self.charge).charge();
        B::resize(&mut charge, self.charged)?;
        let mut mem = vec![0u8; self.mem.len()];
        for range in [
            0..self.text as usize,
            self.units_start as usize..self.lo_unit as usize,
            self.hi_unit as usize..self.mem.len(),
        ] {
            mem[range.clone()].copy_from_slice(&self.mem[range]);
        }
        Ok(Self {
            mem,
            charge,
            rc: self.rc.clone(),
            read_control: self.read_control.clone(),
            ..*self
        })
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
        self.rc.init(input)?;
        if reset {
            let mut max_order = u32::from(first_byte & 0x1f) + 1;
            if max_order > 16 {
                max_order = 16 + (max_order - 16) * 3;
            }
            if max_order == 1 {
                return Err(Error::InvalidData("RAR PPMd order is invalid"));
            }
            let size = (u32::from(max_mb.unwrap_or(0)) + 1) << 20;
            // Until the new model is charged there is none to continue.
            self.allocated = false;
            if self.size != size || self.mem.is_empty() {
                self.mem = Vec::new();
                B::resize(&mut self.charge, 0)?;
                self.charged = 0;
                self.align = 4u32.wrapping_sub(size) & 3;
                self.mem = vec![0u8; (self.align + size) as usize];
                self.size = size;
            }
            self.max_order = max_order;
            self.restart_model();
            if self.charged == 0 {
                self.mark_reach();
            }
            self.charge_reached()?;
            self.allocated = true;
        } else if !self.allocated {
            return Err(Error::InvalidData("RAR PPMd block reuses missing model"));
        }
        Ok(())
    }

    #[inline(always)]
    fn u8_at(&self, at: u32) -> u8 {
        self.mem[at as usize]
    }
    #[inline(always)]
    fn set_u8(&mut self, at: u32, value: u8) {
        self.mem[at as usize] = value;
    }
    #[inline(always)]
    fn u16_at(&self, at: u32) -> u16 {
        u16::from_le_bytes(self.mem[at as usize..][..2].try_into().unwrap())
    }
    #[inline(always)]
    fn set_u16(&mut self, at: u32, value: u16) {
        self.mem[at as usize..][..2].copy_from_slice(&value.to_le_bytes());
    }
    #[inline(always)]
    fn u32_at(&self, at: u32) -> u32 {
        u32::from_le_bytes(self.mem[at as usize..][..4].try_into().unwrap())
    }
    #[inline(always)]
    fn set_u32(&mut self, at: u32, value: u32) {
        self.mem[at as usize..][..4].copy_from_slice(&value.to_le_bytes());
    }

    // Context: NumStats u16, SummFreq u16 (or OneState symbol, freq), Stats
    // u32 (or OneState successor), Suffix u32.
    #[inline(always)]
    fn num_stats(&self, ctx: u32) -> u32 {
        u32::from(self.u16_at(ctx))
    }
    #[inline(always)]
    fn summ_freq(&self, ctx: u32) -> u32 {
        u32::from(self.u16_at(ctx + 2))
    }
    #[inline(always)]
    fn set_summ_freq(&mut self, ctx: u32, value: u32) {
        self.set_u16(ctx + 2, value as u16);
    }
    #[inline(always)]
    fn stats(&self, ctx: u32) -> u32 {
        self.u32_at(ctx + 4)
    }
    #[inline(always)]
    fn suffix(&self, ctx: u32) -> u32 {
        self.u32_at(ctx + 8)
    }
    #[inline(always)]
    fn one_state(ctx: u32) -> u32 {
        ctx + 2
    }

    // State: Symbol u8, Freq u8, Successor u32 (unaligned).
    #[inline(always)]
    fn symbol(&self, s: u32) -> u8 {
        self.u8_at(s)
    }
    #[inline(always)]
    fn freq(&self, s: u32) -> u32 {
        u32::from(self.u8_at(s + 1))
    }
    #[inline(always)]
    fn set_freq(&mut self, s: u32, value: u32) {
        self.set_u8(s + 1, value as u8);
    }
    #[inline(always)]
    fn successor(&self, s: u32) -> u32 {
        self.u32_at(s + 2)
    }
    #[inline(always)]
    fn set_successor(&mut self, s: u32, value: u32) {
        self.set_u32(s + 2, value);
    }
    #[inline(always)]
    fn swap_states(&mut self, a: u32, b: u32) {
        let mut x = [0u8; 6];
        x.copy_from_slice(&self.mem[a as usize..][..6]);
        self.mem.copy_within(b as usize..b as usize + 6, a as usize);
        self.mem[b as usize..][..6].copy_from_slice(&x);
    }
    #[inline(always)]
    fn copy_state(&mut self, from: u32, to: u32) {
        self.mem
            .copy_within(from as usize..from as usize + 6, to as usize);
    }

    #[inline(always)]
    fn i2u(&self, indx: usize) -> u32 {
        u32::from(self.indx2units[indx])
    }
    #[inline(always)]
    fn u2i(&self, nu: u32) -> usize {
        usize::from(self.units2indx[nu as usize - 1])
    }

    // Where a fresh pool's regions start out.
    fn mark_reach(&mut self) {
        self.text_peak = self.text;
        self.lo_peak = self.lo_unit;
        self.units_floor = self.units_start;
        self.hi_floor = self.hi_unit;
    }

    // Charge the budget for the parts of the pool the model has reached.
    // Called whenever a region passes its furthest point so far.
    #[cold]
    fn charge_reached(&mut self) -> Result<()> {
        self.text_peak = self.text_peak.max(self.text);
        self.lo_peak = self.lo_peak.max(self.lo_unit);
        self.units_floor = self.units_floor.min(self.units_start);
        self.hi_floor = self.hi_floor.min(self.hi_unit);
        let end = self.align + self.size;
        let reached = u64::from(self.text_peak - self.align)
            + u64::from(self.lo_peak - self.units_floor)
            + u64::from(end - self.hi_floor);
        let reached = reached
            .next_multiple_of(CHARGE_STEP)
            .min(self.mem.len() as u64);
        if reached > self.charged {
            B::resize(&mut self.charge, reached)?;
            self.charged = reached;
        }
        Ok(())
    }

    // New contexts take units from the top of the pool, downwards.
    #[inline(always)]
    fn take_context_unit(&mut self) -> Result<u32> {
        self.hi_unit -= UNIT_SIZE;
        if self.hi_unit < self.hi_floor {
            self.charge_reached()?;
        }
        Ok(self.hi_unit)
    }

    #[inline(always)]
    fn insert_node(&mut self, node: u32, indx: usize) {
        self.set_u32(node, self.free_list[indx]);
        self.free_list[indx] = node;
    }

    #[inline(always)]
    fn remove_node(&mut self, indx: usize) -> u32 {
        let node = self.free_list[indx];
        self.free_list[indx] = self.u32_at(node);
        node
    }

    fn split_block(&mut self, ptr: u32, old_indx: usize, new_indx: usize) {
        let nu = self.i2u(old_indx) - self.i2u(new_indx);
        let ptr = ptr + UNIT_SIZE * self.i2u(new_indx);
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i -= 1;
            let k = self.i2u(i);
            self.insert_node(ptr + UNIT_SIZE * k, (nu - k - 1) as usize);
        }
        self.insert_node(ptr, i);
    }

    // Join adjacent free blocks and refill the free lists from them.
    // Free nodes: Stamp u16 (0 = free), NU u16, Next u32. A walk can visit
    // every unit of a large pool, so each one polls for cancellation, which
    // ends the decode.
    fn glue_free_blocks(&mut self) -> Result<()> {
        #[cfg(test)]
        {
            self.glues += 1;
        }
        let mut poller = self.read_control.poller();
        let mut visited = 0usize;
        self.glue_count = 255;
        if self.lo_unit != self.hi_unit {
            self.set_u16(self.lo_unit, 1);
        }
        let mut n = 0u32;
        for i in 0..NUM_INDEXES {
            let nu = self.i2u(i) as u16;
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                visited += 1;
                poller.check_codec(visited)?;
                let node = next;
                next = self.u32_at(node);
                self.set_u16(node, 0);
                self.set_u16(node + 2, nu);
                self.set_u32(node + 4, n);
                n = node;
            }
        }
        let mut head = n;
        // Where the link to the current node is kept: `head`, or a node's Next.
        let mut prev: Option<u32> = None;
        while n != 0 {
            visited += 1;
            poller.check_codec(visited)?;
            let node = n;
            let mut nu = u32::from(self.u16_at(node + 2));
            n = self.u32_at(node + 4);
            if nu == 0 {
                match prev {
                    None => head = n,
                    Some(link) => self.set_u32(link, n),
                }
                continue;
            }
            prev = Some(node + 4);
            loop {
                let node2 = node + nu * UNIT_SIZE;
                nu += u32::from(self.u16_at(node2 + 2));
                if self.u16_at(node2) != 0 || nu >= 0x10000 {
                    break;
                }
                self.set_u16(node + 2, nu as u16);
                self.set_u16(node2 + 2, 0);
            }
        }
        n = head;
        while n != 0 {
            visited += 1;
            poller.check_codec(visited)?;
            let mut node = n;
            let mut nu = u32::from(self.u16_at(node + 2));
            n = self.u32_at(node + 4);
            if nu == 0 {
                continue;
            }
            while nu > 128 {
                self.insert_node(node, NUM_INDEXES - 1);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i -= 1;
                let k = self.i2u(i);
                self.insert_node(node + k * UNIT_SIZE, (nu - k - 1) as usize);
            }
            self.insert_node(node, i);
        }
        Ok(())
    }

    // `None` when the pool is full, which restarts the model.
    #[cold]
    fn alloc_units_rare(&mut self, indx: usize) -> Result<Option<u32>> {
        if self.glue_count == 0 {
            self.glue_free_blocks()?;
            if self.free_list[indx] != 0 {
                return Ok(Some(self.remove_node(indx)));
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == NUM_INDEXES {
                let bytes = UNIT_SIZE * self.i2u(indx);
                self.glue_count -= 1;
                if self.units_start - self.text <= bytes {
                    return Ok(None);
                }
                self.units_start -= bytes;
                if self.units_start < self.units_floor {
                    self.charge_reached()?;
                }
                return Ok(Some(self.units_start));
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let block = self.remove_node(i);
        self.split_block(block, i, indx);
        Ok(Some(block))
    }

    #[inline]
    fn alloc_units(&mut self, indx: usize) -> Result<Option<u32>> {
        if self.free_list[indx] != 0 {
            return Ok(Some(self.remove_node(indx)));
        }
        let bytes = UNIT_SIZE * self.i2u(indx);
        if self.hi_unit - self.lo_unit >= bytes {
            let at = self.lo_unit;
            self.lo_unit += bytes;
            if self.lo_unit > self.lo_peak {
                self.charge_reached()?;
            }
            return Ok(Some(at));
        }
        self.alloc_units_rare(indx)
    }

    fn restart_model(&mut self) {
        #[cfg(test)]
        {
            self.restarts += 1;
        }
        self.free_list = [0; NUM_INDEXES];
        self.text = self.align;
        self.hi_unit = self.text + self.size;
        self.units_start = self.hi_unit - self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE;
        self.lo_unit = self.units_start;
        self.glue_count = 0;
        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit -= UNIT_SIZE;
        let mc = self.hi_unit;
        let s = self.lo_unit;
        self.lo_unit += UNIT_SIZE * 128;
        self.max_context = mc;
        self.min_context = mc;
        self.found_state = s;
        self.set_u16(mc, 256);
        self.set_summ_freq(mc, 257);
        self.set_u32(mc + 4, s);
        self.set_u32(mc + 8, 0);
        for i in 0..256u32 {
            let at = s + 6 * i;
            self.set_u8(at, i as u8);
            self.set_u8(at + 1, 1);
            self.set_successor(at, 0);
        }
        for (i, row) in self.bin_summ.iter_mut().enumerate() {
            for (k, &esc) in INIT_BIN_ESC.iter().enumerate() {
                let value = (BIN_SCALE - u32::from(esc) / (i as u32 + 2)) as u16;
                for m in (0..64).step_by(8) {
                    row[k + m] = value;
                }
            }
        }
        for (i, row) in self.see.iter_mut().enumerate() {
            let summ = ((5 * i as u32 + 10) << (PERIOD_BITS - 4)) as u16;
            row.fill(See {
                summ,
                shift: PERIOD_BITS - 4,
                count: 4,
            });
        }
        self.dummy_see = See {
            summ: 0,
            shift: PERIOD_BITS,
            count: 64,
        };
    }

    fn create_successors(&mut self) -> Result<Option<u32>> {
        let mut c = self.min_context;
        let up_branch = self.successor(self.found_state);
        let found_symbol = self.symbol(self.found_state);
        let mut ps = [0u32; MAX_ORDER];
        let mut num_ps = 0;
        if self.order_fall != 0 {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }
        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s = if self.num_stats(c) != 1 {
                let mut s = self.stats(c);
                while self.symbol(s) != found_symbol {
                    s += 6;
                }
                s
            } else {
                Self::one_state(c)
            };
            let successor = self.successor(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return Ok(Some(c));
                }
                break;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }
        if num_ps == 0 {
            return Ok(Some(c));
        }
        let new_symbol = self.u8_at(up_branch);
        let up_branch = up_branch + 1;
        let new_freq = if self.num_stats(c) == 1 {
            self.freq(Self::one_state(c))
        } else {
            let mut s = self.stats(c);
            while self.symbol(s) != new_symbol {
                s += 6;
            }
            let cf = self.freq(s) - 1;
            let s0 = self.summ_freq(c) - self.num_stats(c) - cf;
            1 + if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                (2 * cf + s0 - 1) / (2 * s0) + 1
            }
        };
        loop {
            let c1 = if self.hi_unit != self.lo_unit {
                self.take_context_unit()?
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                match self.alloc_units_rare(0)? {
                    Some(c1) => c1,
                    None => return Ok(None),
                }
            };
            self.set_u16(c1, 1);
            let one = Self::one_state(c1);
            self.set_u8(one, new_symbol);
            self.set_u8(one + 1, new_freq as u8);
            self.set_successor(one, up_branch);
            self.set_u32(c1 + 8, c);
            num_ps -= 1;
            self.set_successor(ps[num_ps], c1);
            c = c1;
            if num_ps == 0 {
                return Ok(Some(c));
            }
        }
    }

    fn update_model(&mut self) -> Result<()> {
        let fs = self.found_state;
        let fs_symbol = self.symbol(fs);
        let fs_freq = self.freq(fs);
        if fs_freq < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            let c = self.suffix(self.min_context);
            if self.num_stats(c) == 1 {
                let s = Self::one_state(c);
                if self.freq(s) < 32 {
                    self.set_freq(s, self.freq(s) + 1);
                }
            } else {
                let mut s = self.stats(c);
                if self.symbol(s) != fs_symbol {
                    loop {
                        s += 6;
                        if self.symbol(s) == fs_symbol {
                            break;
                        }
                    }
                    if self.freq(s) >= self.freq(s - 6) {
                        self.swap_states(s, s - 6);
                        s -= 6;
                    }
                }
                if self.freq(s) < MAX_FREQ - 9 {
                    self.set_freq(s, self.freq(s) + 2);
                    self.set_summ_freq(c, self.summ_freq(c) + 2);
                }
            }
        }

        if self.order_fall == 0 {
            match self.create_successors()? {
                None => self.restart_model(),
                Some(c) => {
                    self.min_context = c;
                    self.max_context = c;
                    self.set_successor(self.found_state, c);
                }
            }
            return Ok(());
        }

        self.set_u8(self.text, fs_symbol);
        self.text += 1;
        if self.text > self.text_peak {
            self.charge_reached()?;
        }
        if self.text >= self.units_start {
            #[cfg(test)]
            {
                self.text_restarts += 1;
            }
            self.restart_model();
            return Ok(());
        }
        let mut max_successor = self.text;
        let mut min_successor = self.successor(fs);
        if min_successor != 0 {
            if min_successor <= max_successor {
                match self.create_successors()? {
                    None => {
                        self.restart_model();
                        return Ok(());
                    }
                    Some(cs) => min_successor = cs,
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                max_successor = min_successor;
                self.text -= u32::from(self.max_context != self.min_context);
            }
        } else {
            self.set_successor(fs, max_successor);
            min_successor = self.min_context;
        }

        let mc = self.min_context;
        let mut c = self.max_context;
        self.min_context = min_successor;
        self.max_context = min_successor;
        if c == mc {
            return Ok(());
        }
        let ns = self.num_stats(mc);
        let fs_freq = self.freq(self.found_state);
        let s0 = self
            .summ_freq(mc)
            .wrapping_sub(ns)
            .wrapping_sub(fs_freq - 1);
        loop {
            let ns1 = self.num_stats(c);
            let mut sum;
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    let old_nu = ns1 >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let Some(ptr) = self.alloc_units(i + 1)? else {
                            self.restart_model();
                            return Ok(());
                        };
                        let old = self.stats(c);
                        self.mem.copy_within(
                            old as usize..(old + old_nu * UNIT_SIZE) as usize,
                            ptr as usize,
                        );
                        self.insert_node(old, i);
                        self.set_u32(c + 4, ptr);
                    }
                }
                sum = self.summ_freq(c);
                sum += u32::from(2 * ns1 < ns) + 2 * u32::from((4 * ns1 <= ns) & (sum <= 8 * ns1));
            } else {
                let Some(s) = self.alloc_units(0)? else {
                    self.restart_model();
                    return Ok(());
                };
                let one = Self::one_state(c);
                let mut freq = self.freq(one);
                self.copy_state(one, s);
                self.set_u32(c + 4, s);
                if freq < MAX_FREQ / 4 - 1 {
                    freq <<= 1;
                } else {
                    freq = MAX_FREQ - 4;
                }
                self.set_freq(s, freq);
                sum = freq + self.init_esc + u32::from(ns > 3);
            }
            let s = self.stats(c) + ns1 * 6;
            let mut cf = 2 * (sum + 6) * fs_freq;
            let sf = s0.wrapping_add(sum);
            self.set_u8(s, fs_symbol);
            self.set_u16(c, (ns1 + 1) as u16);
            self.set_successor(s, max_successor);
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
            self.set_summ_freq(c, sum);
            self.set_freq(s, cf);
            c = self.suffix(c);
            if c == mc {
                return Ok(());
            }
        }
    }

    #[cold]
    fn rescale(&mut self) {
        let mc = self.min_context;
        let stats = self.stats(mc);
        let mut s = self.found_state;
        if s != stats {
            let mut tmp = [0u8; 6];
            tmp.copy_from_slice(&self.mem[s as usize..][..6]);
            self.mem
                .copy_within(stats as usize..s as usize, stats as usize + 6);
            self.mem[stats as usize..][..6].copy_from_slice(&tmp);
            s = stats;
        }
        let mut sum_freq = self.freq(s);
        let mut esc_freq = self.summ_freq(mc).wrapping_sub(sum_freq);
        let adder = u32::from(self.order_fall != 0);
        sum_freq = (sum_freq + 4 + adder) >> 1;
        let mut i = self.num_stats(mc) - 1;
        self.set_freq(s, sum_freq);
        loop {
            s += 6;
            let mut freq = self.freq(s);
            esc_freq = esc_freq.wrapping_sub(freq);
            freq = (freq + adder) >> 1;
            sum_freq += freq;
            self.set_freq(s, freq);
            if freq > self.freq(s - 6) {
                let mut tmp = [0u8; 6];
                tmp.copy_from_slice(&self.mem[s as usize..][..6]);
                let mut s1 = s;
                loop {
                    self.copy_state(s1 - 6, s1);
                    s1 -= 6;
                    if s1 == stats || freq <= self.freq(s1 - 6) {
                        break;
                    }
                }
                self.mem[s1 as usize..][..6].copy_from_slice(&tmp);
            }
            i -= 1;
            if i == 0 {
                break;
            }
        }
        if self.freq(s) == 0 {
            let mut removed = 0;
            loop {
                removed += 1;
                s -= 6;
                if self.freq(s) != 0 {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(removed);
            let num_stats = self.num_stats(mc);
            let num_stats_new = num_stats - removed;
            self.set_u16(mc, num_stats_new as u16);
            let n0 = (num_stats + 1) >> 1;
            if num_stats_new == 1 {
                let mut freq = self.freq(stats);
                loop {
                    esc_freq >>= 1;
                    freq = (freq + 1) >> 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                let one = Self::one_state(mc);
                self.copy_state(stats, one);
                self.set_freq(one, freq);
                self.found_state = one;
                let indx = self.u2i(n0);
                self.insert_node(stats, indx);
                return;
            }
            let n1 = (num_stats_new + 1) >> 1;
            if n0 != n1 {
                let i0 = self.u2i(n0);
                let i1 = self.u2i(n1);
                if i0 != i1 {
                    if self.free_list[i1] != 0 {
                        let ptr = self.remove_node(i1);
                        self.set_u32(mc + 4, ptr);
                        self.mem.copy_within(
                            stats as usize..(stats + n1 * UNIT_SIZE) as usize,
                            ptr as usize,
                        );
                        self.insert_node(stats, i0);
                    } else {
                        self.split_block(stats, i0, i1);
                    }
                }
            }
        }
        self.set_summ_freq(mc, sum_freq + esc_freq - (esc_freq >> 1));
        self.found_state = self.stats(mc);
    }

    #[inline(always)]
    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeRef, u32) {
        let mc = self.min_context;
        let num_stats = self.num_stats(mc);
        if num_stats == 256 {
            return (SeeRef::Dummy, 1);
        }
        let non_masked = num_stats - num_masked;
        let row = usize::from(self.ns2indx[non_masked as usize - 1]);
        let suffix_stats = self.num_stats(self.suffix(mc));
        let col = u32::from(non_masked < suffix_stats.wrapping_sub(num_stats))
            + 2 * u32::from(self.summ_freq(mc) < 11 * num_stats)
            + 4 * u32::from(num_masked > non_masked)
            + self.hi_bits_flag;
        let see = &mut self.see[row][col as usize];
        let r = u32::from(see.summ >> see.shift);
        see.summ = see.summ.wrapping_sub(r as u16);
        (SeeRef::Table(row, col as usize), r + u32::from(r == 0))
    }

    #[inline(always)]
    fn see(&mut self, see: SeeRef) -> &mut See {
        match see {
            SeeRef::Dummy => &mut self.dummy_see,
            SeeRef::Table(row, col) => &mut self.see[row][col],
        }
    }

    #[inline(always)]
    fn next_context(&mut self) -> Result<()> {
        let c = self.successor(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
            return Ok(());
        }
        self.update_model()
    }

    #[inline(always)]
    fn update1(&mut self) -> Result<()> {
        let mut s = self.found_state;
        let freq = self.freq(s) + 4;
        let mc = self.min_context;
        self.set_summ_freq(mc, self.summ_freq(mc) + 4);
        self.set_freq(s, freq);
        if freq > self.freq(s - 6) {
            self.swap_states(s, s - 6);
            s -= 6;
            self.found_state = s;
            if freq > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context()
    }

    #[inline(always)]
    fn update1_0(&mut self) -> Result<()> {
        let s = self.found_state;
        let mc = self.min_context;
        let freq = self.freq(s);
        let summ_freq = self.summ_freq(mc);
        self.prev_success = u32::from(2 * freq > summ_freq);
        self.run_length += self.prev_success as i32;
        self.set_summ_freq(mc, summ_freq + 4);
        self.set_freq(s, freq + 4);
        if freq + 4 > MAX_FREQ {
            self.rescale();
        }
        self.next_context()
    }

    // The binary context's probability cell, which also records the high
    // bit of the previous symbol for the SEE contexts that follow.
    #[inline(always)]
    fn bin_summ_index(&mut self, mc: u32) -> (usize, usize) {
        let s = Self::one_state(mc);
        self.hi_bits_flag = hi_bits_flag3(self.symbol(self.found_state));
        let row = self.freq(s) as usize - 1;
        let col = self.prev_success as usize
            + ((self.run_length >> 26) & 0x20) as usize
            + usize::from(self.ns2bs_indx[self.num_stats(self.suffix(mc)) as usize - 1])
            + hi_bits_flag4(self.symbol(s)) as usize
            + self.hi_bits_flag as usize;
        (row, col)
    }

    #[inline(always)]
    fn update_bin(&mut self, s: u32) -> Result<()> {
        let freq = self.freq(s);
        let c = self.successor(s);
        self.found_state = s;
        self.prev_success = 1;
        self.run_length += 1;
        self.set_freq(s, freq + u32::from(freq < 128));
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
            return Ok(());
        }
        self.update_model()
    }

    #[inline(always)]
    fn update2(&mut self) -> Result<()> {
        let s = self.found_state;
        let freq = self.freq(s) + 4;
        self.run_length = self.init_rl;
        let mc = self.min_context;
        self.set_summ_freq(mc, self.summ_freq(mc) + 4);
        self.set_freq(s, freq);
        if freq > MAX_FREQ {
            self.rescale();
        }
        self.update_model()
    }

    pub fn decode_symbol(&mut self, input: &mut impl PpmdByteReader) -> Result<Option<u8>> {
        if !self.allocated {
            return Err(Error::InvalidData("RAR PPMd block reuses missing model"));
        }
        let symbol = self.decode_next_symbol(input);
        // A symbol that fails partway through an escape leaves the model in a
        // lower-order context with `order_fall` raised for contexts it never
        // took the symbol from, a state that only this call's masks made
        // consistent. Decoding on from it reads text bytes as context
        // pointers, so a later block must reset the model first.
        if !matches!(symbol, Ok(Some(_))) {
            self.allocated = false;
        }
        symbol
    }

    #[inline(always)]
    fn decode_next_symbol(&mut self, input: &mut impl PpmdByteReader) -> Result<Option<u8>> {
        let mut mask = [0xffu8; 256];
        let mc = self.min_context;
        let num_stats = self.num_stats(mc);
        if num_stats != 1 {
            let mut s = self.stats(mc);
            let summ_freq = self.summ_freq(mc);
            if summ_freq > self.rc.range {
                return Err(Error::InvalidData("RAR PPMd range is invalid"));
            }
            let mut count = self.rc.threshold(summ_freq);
            let hi_cnt = count;
            let freq = self.freq(s);
            count = count.wrapping_sub(freq);
            if (count as i32) < 0 {
                self.rc.decode(0, freq);
                self.rc.normalize(input)?;
                self.found_state = s;
                let symbol = self.symbol(s);
                self.update1_0()?;
                return Ok(Some(symbol));
            }
            self.prev_success = 0;
            let mut i = num_stats - 1;
            loop {
                s += 6;
                let freq = self.freq(s);
                count = count.wrapping_sub(freq);
                if (count as i32) < 0 {
                    self.rc
                        .decode(hi_cnt.wrapping_sub(count).wrapping_sub(freq), freq);
                    self.rc.normalize(input)?;
                    self.found_state = s;
                    let symbol = self.symbol(s);
                    self.update1()?;
                    return Ok(Some(symbol));
                }
                i -= 1;
                if i == 0 {
                    break;
                }
            }
            if hi_cnt >= summ_freq {
                return Err(Error::InvalidData("RAR PPMd frequency sum is invalid"));
            }
            let hi_cnt = hi_cnt.wrapping_sub(count);
            self.rc.decode(hi_cnt, summ_freq - hi_cnt);
            self.hi_bits_flag = hi_bits_flag3(self.symbol(self.found_state));
            let stats = self.stats(mc);
            for k in 0..num_stats {
                mask[usize::from(self.symbol(stats + 6 * k))] = 0;
            }
        } else {
            let s = Self::one_state(mc);
            let (row, col) = self.bin_summ_index(mc);
            let prob = u32::from(self.bin_summ[row][col]);
            let size0 = (self.rc.range >> 14).wrapping_mul(prob);
            let prob = prob - ((prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS);
            if self.rc.code < size0 {
                self.bin_summ[row][col] = (prob + (1 << INT_BITS)) as u16;
                self.rc.range = size0;
                self.rc.normalize(input)?;
                let symbol = self.symbol(s);
                self.update_bin(s)?;
                return Ok(Some(symbol));
            }
            self.bin_summ[row][col] = prob as u16;
            self.init_esc = u32::from(EXP_ESCAPE[(prob >> 10) as usize]);
            self.rc.low = self.rc.low.wrapping_add(size0);
            self.rc.code = self.rc.code.wrapping_sub(size0);
            self.rc.range = (self.rc.range & !(BIN_SCALE - 1)).wrapping_sub(size0);
            mask[usize::from(self.symbol(s))] = 0;
            self.prev_success = 0;
        }

        loop {
            self.rc.normalize(input)?;
            let mut mc = self.min_context;
            let num_masked = self.num_stats(mc);
            loop {
                self.order_fall += 1;
                let suffix = self.suffix(mc);
                if suffix == 0 {
                    return Ok(None);
                }
                mc = suffix;
                if self.num_stats(mc) != num_masked {
                    break;
                }
            }
            let stats = self.stats(mc);
            let num_stats = self.num_stats(mc);
            self.min_context = mc;
            let mut hi_cnt = 0u32;
            for k in 0..num_stats {
                let s = stats + 6 * k;
                hi_cnt += self.freq(s) & u32::from(mask[usize::from(self.symbol(s))]);
            }
            let (see, esc_freq) = self.make_esc_freq(num_masked);
            let freq_sum = esc_freq + hi_cnt;
            if freq_sum > self.rc.range {
                return Err(Error::InvalidData("RAR PPMd escape range is invalid"));
            }
            let count = self.rc.threshold(freq_sum);
            if count < hi_cnt {
                let mut s = stats;
                let mut left = count;
                loop {
                    left = left
                        .wrapping_sub(self.freq(s) & u32::from(mask[usize::from(self.symbol(s))]));
                    s += 6;
                    if (left as i32) < 0 {
                        break;
                    }
                }
                s -= 6;
                let freq = self.freq(s);
                self.rc
                    .decode(count.wrapping_sub(left).wrapping_sub(freq), freq);
                self.rc.normalize(input)?;
                self.see(see).update();
                self.found_state = s;
                let symbol = self.symbol(s);
                self.update2()?;
                return Ok(Some(symbol));
            }
            if count >= freq_sum {
                return Err(Error::InvalidData("RAR PPMd escape symbol is invalid"));
            }
            self.rc.decode(hi_cnt, freq_sum - hi_cnt);
            let see = self.see(see);
            see.summ = see.summ.wrapping_add(freq_sum as u16);
            for k in 0..num_stats {
                mask[usize::from(self.symbol(stats + 6 * k))] = 0;
            }
        }
    }
}

// The writer's side: the same model, coding symbols instead of reading them.

#[cfg(any(test, feature = "write"))]
impl Ppmd7<Allowance> {
    fn for_encoding(max_order: usize, dictionary_mb: usize) -> Result<Self> {
        if !(2..=MAX_ORDER).contains(&max_order) {
            return Err(Error::InvalidData("RAR PPMd order is invalid"));
        }
        if !(1..=256).contains(&dictionary_mb) {
            return Err(Error::InvalidData("RAR PPMd dictionary size is invalid"));
        }
        let mut model = Self::with_allowance(&Allowance::default());
        let size = (dictionary_mb as u32) << 20;
        model.align = 4u32.wrapping_sub(size) & 3;
        model.mem = vec![0u8; (model.align + size) as usize];
        model.size = size;
        model.max_order = max_order as u32;
        model.restart_model();
        model.mark_reach();
        model.allocated = true;
        Ok(model)
    }

    fn encode_symbol(&mut self, symbol: u8, out: &mut RangeEncoder) -> Result<()> {
        let mut mask = [0xffu8; 256];
        let mc = self.min_context;
        let num_stats = self.num_stats(mc);
        if num_stats != 1 {
            let summ_freq = self.summ_freq(mc);
            let stats = self.stats(mc);
            let mut start = 0u32;
            for k in 0..num_stats {
                let s = stats + 6 * k;
                let freq = self.freq(s);
                if self.symbol(s) == symbol {
                    out.encode(start, freq, summ_freq);
                    out.normalize();
                    self.found_state = s;
                    if k == 0 {
                        return self.update1_0();
                    }
                    self.prev_success = 0;
                    return self.update1();
                }
                start += freq;
            }
            if start >= summ_freq {
                return Err(Error::InvalidData("RAR PPMd frequency sum is invalid"));
            }
            self.prev_success = 0;
            out.encode(start, summ_freq - start, summ_freq);
            self.hi_bits_flag = hi_bits_flag3(self.symbol(self.found_state));
            for k in 0..num_stats {
                mask[usize::from(self.symbol(stats + 6 * k))] = 0;
            }
        } else {
            let s = Self::one_state(mc);
            let (row, col) = self.bin_summ_index(mc);
            let prob = u32::from(self.bin_summ[row][col]);
            let size0 = (out.range >> 14).wrapping_mul(prob);
            let prob = prob - ((prob + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS);
            if self.symbol(s) == symbol {
                self.bin_summ[row][col] = (prob + (1 << INT_BITS)) as u16;
                out.range = size0;
                out.normalize();
                return self.update_bin(s);
            }
            self.bin_summ[row][col] = prob as u16;
            self.init_esc = u32::from(EXP_ESCAPE[(prob >> 10) as usize]);
            out.low = out.low.wrapping_add(size0);
            out.range = (out.range & !(BIN_SCALE - 1)).wrapping_sub(size0);
            mask[usize::from(self.symbol(s))] = 0;
            self.prev_success = 0;
        }

        loop {
            out.normalize();
            let mut mc = self.min_context;
            let num_masked = self.num_stats(mc);
            loop {
                self.order_fall += 1;
                let suffix = self.suffix(mc);
                if suffix == 0 {
                    return Err(Error::InvalidData("RAR PPMd symbol is not encodable"));
                }
                mc = suffix;
                if self.num_stats(mc) != num_masked {
                    break;
                }
            }
            let stats = self.stats(mc);
            let num_stats = self.num_stats(mc);
            self.min_context = mc;
            let mut hi_cnt = 0u32;
            for k in 0..num_stats {
                let s = stats + 6 * k;
                hi_cnt += self.freq(s) & u32::from(mask[usize::from(self.symbol(s))]);
            }
            let (see, esc_freq) = self.make_esc_freq(num_masked);
            let freq_sum = esc_freq + hi_cnt;
            let mut start = 0u32;
            for k in 0..num_stats {
                let s = stats + 6 * k;
                let offered = self.freq(s) & u32::from(mask[usize::from(self.symbol(s))]);
                if offered != 0 && self.symbol(s) == symbol {
                    out.encode(start, offered, freq_sum);
                    out.normalize();
                    self.see(see).update();
                    self.found_state = s;
                    return self.update2();
                }
                start += offered;
            }
            out.encode(hi_cnt, freq_sum - hi_cnt, freq_sum);
            let see = self.see(see);
            see.summ = see.summ.wrapping_add(freq_sum as u16);
            for k in 0..num_stats {
                mask[usize::from(self.symbol(stats + 6 * k))] = 0;
            }
        }
    }
}

#[cfg(any(test, feature = "write"))]
impl Clone for Ppmd7<Allowance> {
    fn clone(&self) -> Self {
        self.try_clone().expect("unlimited PPMd model copy")
    }
}

// Subbotin's carryless range coder, writing what `RangeDecoder` reads.
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "write"))]
struct RangeEncoder {
    low: u32,
    range: u32,
    out: Vec<u8>,
}

#[cfg(any(test, feature = "write"))]
impl RangeEncoder {
    fn new() -> Self {
        Self {
            low: 0,
            range: u32::MAX,
            out: Vec::new(),
        }
    }

    fn encode(&mut self, start: u32, size: u32, total: u32) {
        self.range /= total;
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
    }

    fn normalize(&mut self) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= BOT {
                    return;
                }
                self.range = self.low.wrapping_neg() & (BOT - 1);
            }
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

/// A PPMd model handed from one block to the next in a solid chain.
///
/// The state is boxed. Its tables come to about 19 KB, and a chain moves the
/// model through several calls and holds a trial's best beside the current
/// one; unoptimised, each move took its own copy on the stack, and a solid
/// archive overflowed the 1 MiB main thread Windows gives the CLI.
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "write"))]
pub struct PpmdModel {
    state: Box<Ppmd7<Allowance>>,
}

/// Codes one RAR 2.9 PPMd block: literals and the escape commands the
/// reader understands.
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "write"))]
pub struct PpmdEncoder {
    model: PpmdModel,
    range: RangeEncoder,
    esc_char: u8,
}

#[cfg(any(test, feature = "write"))]
impl PpmdEncoder {
    pub fn new(max_order: usize, esc_char: u8, dictionary_mb: usize) -> Result<Self> {
        Ok(Self {
            model: PpmdModel {
                state: Box::new(Ppmd7::for_encoding(max_order, dictionary_mb)?),
            },
            range: RangeEncoder::new(),
            esc_char,
        })
    }

    /// Carries a model from one block into the next.
    ///
    /// A block that clears the reset bit in its header leaves the reader's
    /// model alone and only re-reads the range coder, so a solid chain can keep
    /// one model across every member in it. Each block still gets a fresh range
    /// coder, which is what lets a member's packed bytes start on a byte
    /// boundary of their own.
    #[cfg(feature = "write")]
    pub fn continuing(model: PpmdModel, esc_char: u8) -> Self {
        Self {
            model,
            range: RangeEncoder::new(),
            esc_char,
        }
    }

    fn code(&mut self, symbol: u8) -> Result<()> {
        self.model.state.encode_symbol(symbol, &mut self.range)
    }

    /// The bytes coded so far; a carryless coder never revises them.
    #[cfg(feature = "write")]
    pub(crate) fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.range.out)
    }

    /// Ends the block and hands the model back for the next one to continue.
    pub fn finish_keeping_model(mut self) -> Result<(Vec<u8>, PpmdModel)> {
        self.code(self.esc_char)?;
        self.code(2)?;
        Ok((self.range.finish(), self.model))
    }

    /// Ends this PPMd block while keeping the member open for another block.
    #[cfg(all(test, feature = "write"))]
    pub(crate) fn finish_block_keeping_model(mut self) -> Result<(Vec<u8>, PpmdModel)> {
        self.code(self.esc_char)?;
        self.code(0)?;
        Ok((self.range.finish(), self.model))
    }

    #[cfg(all(test, feature = "write"))]
    pub(crate) fn finish_with_command(self, command: u8) -> Result<Vec<u8>> {
        self.finish_with_command_prefix(command, &[])
    }

    #[cfg(all(test, feature = "write"))]
    pub(crate) fn finish_with_command_prefix(
        mut self,
        command: u8,
        parameters: &[u8],
    ) -> Result<Vec<u8>> {
        self.code(self.esc_char)?;
        self.code(command)?;
        for &parameter in parameters {
            self.code(parameter)?;
        }
        Ok(self.range.finish())
    }

    pub fn encode_literal(&mut self, symbol: u8) -> Result<()> {
        self.code(symbol)?;
        if symbol == self.esc_char {
            self.code(1)?;
        }
        Ok(())
    }

    pub fn encode_repeat_offset_one(&mut self, length: usize) -> Result<()> {
        if !(4..=259).contains(&length) {
            return Err(Error::InvalidData(
                "RAR PPMd offset-one repeat length is invalid",
            ));
        }
        self.code(self.esc_char)?;
        self.code(5)?;
        self.code((length - 4) as u8)
    }

    pub fn encode_match(&mut self, offset: usize, length: usize) -> Result<()> {
        if !(2..=0x1000001).contains(&offset) || !(32..=287).contains(&length) {
            return Err(Error::InvalidData("RAR PPMd match is invalid"));
        }
        let encoded_offset = offset - 2;
        self.code(self.esc_char)?;
        self.code(4)?;
        self.code(((encoded_offset >> 16) & 0xff) as u8)?;
        self.code(((encoded_offset >> 8) & 0xff) as u8)?;
        self.code((encoded_offset & 0xff) as u8)?;
        self.code((length - 32) as u8)
    }

    #[cfg(feature = "write")]
    pub fn encode_vm_filter_record(&mut self, record: &[u8]) -> Result<()> {
        self.code(self.esc_char)?;
        self.code(3)?;
        for &byte in record {
            self.code(byte)?;
        }
        Ok(())
    }

    /// Bits spent so far, to fractional precision. log2 of the range register
    /// falls as symbols narrow the interval and rises by eight for every byte
    /// normalisation flushes, so the difference between two readings is the
    /// cost of whatever was coded between them. The RAR 2.9 tokeniser reads
    /// this to price escape tokens against the literals they would replace.
    #[cfg(feature = "write")]
    pub(crate) fn spent_bits(&self) -> f64 {
        8.0 * self.range.out.len() as f64 - f64::from(self.range.range.max(1)).log2()
    }
}

#[cfg(test)]
mod tests;
