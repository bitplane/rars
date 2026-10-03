use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};

const MAX_FREQ: u32 = 124;
const MIN_MODEL_CONTEXTS: usize = 1;

// PPMd-H suballocator parameters, per the format-level spec at
// rar-research/doc/PPMD_ALGORITHM_SPECIFICATION.md §4.
const ALLOC_UNIT_BYTES: usize = 12;
const N_BUCKETS: usize = 38;
const MAX_BUCKET_UNITS: usize = 128;
// Spec §4.3: countdown reset value after a successful glue pass.
const GLUE_RESET: u32 = 255;
// Sentinel offset for "no allocation" (binary contexts carry their state
// inline; their array_offset field is unused but typed `u32`).
const NULL_OFFSET: u32 = u32::MAX;

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
    for (i, index_to_unit) in index_to_units.iter_mut().enumerate() {
        let step = if i >= 12 { 4 } else { i / 4 + 1 };
        for _ in 0..step {
            // The bucket construction has exactly 128 entries: the first
            // 12 buckets contribute 24 and the remaining 26 contribute 104.
            units_to_index[k] = i as u8;
            k += 1;
        }
        *index_to_unit = k.min(u8::MAX as usize) as u8;
    }
    AllocTables {
        units_to_index,
        index_to_units,
    }
}

fn alloc_tables() -> &'static AllocTables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<AllocTables> = OnceLock::new();
    TABLES.get_or_init(build_alloc_tables)
}

// Spec §4.1 layout: contexts grow downward from `hi_unit`, state arrays
// grow upward from `lo_unit`. Tracking the side matters for adjacency
// patterns (gluing) and for which bump pointer advances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocSide {
    Lo, // state arrays
    Hi, // context headers
}

#[derive(Debug)]
struct Suballocator<B: Budget = Allowance> {
    read_control: crate::read_control::ReadControl,
    // Original pool size in bytes (C's p->Size). Preserved across restarts so
    // the text/units split — which depends on the exact byte size, not the
    // unit-truncated one — stays identical to the reference each restart.
    size_bytes: usize,
    // Total unit budget (= dict_mb * 1 MiB / 12, capped at u32::MAX).
    pool_units: u32,
    // Byte slack at the pool top (= Size % UNIT_SIZE). The C reference sets
    // HiUnit = Base + Size with Size not necessarily a unit multiple, so all
    // its pointers sit at `unit*12 + rem`. We keep unit offsets but fold this
    // remainder into byte-domain comparisons (text capacity / fallback bump)
    // so restart timing matches the reference exactly.
    rem: u32,
    // Text region capacity in bytes. text_ptr reaching this triggers a
    // restart. Mirrors C's UnitsStart byte pointer (= Size - 84*text_units).
    text_capacity_bytes: usize,
    // Bump pointers (in units). lo_bump grows up, hi_bump grows down;
    // valid bumpable space is [lo_bump, hi_bump). Both start at units_start.
    units_start: u32,
    lo_bump: u32,
    hi_bump: u32,
    // Free lists hold released block offsets (in units), one list per bucket.
    free_lists: [Buffer<u32, B>; N_BUCKETS],
    // Countdown for the glue pass (spec §4.3). Starts at 0, gets refreshed
    // to GLUE_RESET after each successful glue.
    glue_count: u32,
    // Test escape hatch: when reset hasn't been called (pool_units == 0),
    // act as unbounded so unit tests bypassing decode_init still work.
    unbounded: bool,
}

impl<B: Budget> Suballocator<B> {
    fn try_clone(&self) -> Result<Self> {
        let allowance = self.free_lists[0].allowance();
        let mut free_lists = std::array::from_fn(|_| Buffer::new(&allowance));
        for (copy, original) in free_lists.iter_mut().zip(&self.free_lists) {
            *copy = Buffer::copied(original, &allowance)?;
        }
        Ok(Self {
            read_control: self.read_control.clone(),
            size_bytes: self.size_bytes,
            pool_units: self.pool_units,
            rem: self.rem,
            text_capacity_bytes: self.text_capacity_bytes,
            units_start: self.units_start,
            lo_bump: self.lo_bump,
            hi_bump: self.hi_bump,
            free_lists,
            glue_count: self.glue_count,
            unbounded: self.unbounded,
        })
    }
    fn with_allowance(allowance: &B) -> Self {
        Self {
            read_control: crate::read_control::ReadControl::default(),
            size_bytes: 0,
            pool_units: 0,
            rem: 0,
            text_capacity_bytes: 0,
            units_start: 0,
            lo_bump: 0,
            hi_bump: 0,
            free_lists: std::array::from_fn(|_| Buffer::new(allowance)),
            glue_count: 0,
            unbounded: true,
        }
    }
}

impl<B: Budget> Suballocator<B> {
    fn reset(&mut self, pool_bytes: usize) {
        let pool_units_usize = pool_bytes / ALLOC_UNIT_BYTES;
        // Cap at u32::MAX-1 (NULL_OFFSET is u32::MAX). Even 256 MiB / 12 =
        // ~22M fits comfortably, so this is theoretical.
        let pool_units = pool_units_usize.min(u32::MAX as usize - 1) as u32;
        // Ppmd7_RestartModel byte layout:
        //   text_units  = Size / 8 / UNIT_SIZE
        //   UnitsStart  = HiUnit - 7 * text_units * UNIT_SIZE
        // i.e. the units region is exactly 7*text_units units carved off the
        // top; the leftover slack (Size % 96, plus Size % 12) all stays in the
        // text region. The previous code took `pool_units / 8` for text and
        // gave the slack to the units region — 5+ extra bump units versus the
        // reference, which desynchronised restart timing on large inputs.
        let text_units = (pool_bytes / 8 / ALLOC_UNIT_BYTES) as u32;
        let units_region = text_units.saturating_mul(7).min(pool_units);
        self.size_bytes = pool_bytes;
        self.pool_units = pool_units;
        self.rem = (pool_bytes % ALLOC_UNIT_BYTES) as u32;
        self.units_start = pool_units - units_region;
        self.lo_bump = self.units_start;
        self.hi_bump = pool_units;
        // UnitsStart byte pointer = units_start*12 + rem (= Size - 84*text_units).
        self.text_capacity_bytes = self.units_start as usize * ALLOC_UNIT_BYTES + self.rem as usize;
        for fl in &mut self.free_lists {
            fl.clear();
        }
        self.glue_count = 0;
        self.unbounded = pool_bytes == 0;
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

    fn try_alloc(
        &mut self,
        units: usize,
        side: AllocSide,
        text_len_bytes: usize,
    ) -> Result<Option<u32>> {
        let Some(bucket) = Self::bucket_for(units) else {
            return Ok(None);
        };
        // Reference ordering differs by side. Lo-side state arrays go through
        // `Ppmd7_AllocUnits` (free_list first, then lo-bump, then rare). Hi-side
        // 1-unit context headers go through the inlined sequence in
        // `Ppmd7_CreateSuccessors` (hi-bump first, then free_list[0], then
        // `Ppmd7_AllocUnitsRare(0)`). The two are not interchangeable: every
        // time a free 1-unit block exists alongside hi-side headroom, the two
        // orderings consume different memory cells. Adjacency at the next glue
        // diverges, and the drift compounds across millions of decode steps.
        match side {
            AllocSide::Hi => {
                if let Some(offset) = self.try_bump(bucket, side) {
                    return Ok(Some(offset));
                }
                if let Some(offset) = self.free_lists[bucket].pop() {
                    return Ok(Some(offset));
                }
            }
            AllocSide::Lo => {
                if let Some(offset) = self.free_lists[bucket].pop() {
                    return Ok(Some(offset));
                }
                if let Some(offset) = self.try_bump(bucket, side) {
                    return Ok(Some(offset));
                }
            }
        }
        // Rare path (mirrors Ppmd7_AllocUnitsRare):
        //   1. If glue_count == 0, glue and retry the bucket's free list.
        //   2. Walk upward through larger buckets; if found, split.
        //   3. Otherwise shrink units_start (consume text-reservation).
        if self.glue_count == 0 {
            self.glue_inner()?;
            self.glue_count = GLUE_RESET;
            if let Some(offset) = self.free_lists[bucket].pop() {
                return Ok(Some(offset));
            }
        }
        for i in (bucket + 1)..N_BUCKETS {
            if let Some(offset) = self.free_lists[i].pop() {
                let large_size = Self::bucket_units(i) as u32;
                let need = Self::bucket_units(bucket) as u32;
                let leftover = large_size - need;
                self.emit_run(offset + need, leftover)?;
                return Ok(Some(offset));
            }
        }
        self.glue_count = self.glue_count.saturating_sub(1);
        Ok(self.fallback_bump(bucket, text_len_bytes))
    }

    // Spec / ref Ppmd7_AllocUnitsRare bump-fallback: when no free block at
    // any bucket size satisfies the request, shrink `units_start` downward
    // (into the text-reservation zone). Succeeds only if the new units
    // floor would still sit above the current text-write position.
    fn fallback_bump(&mut self, bucket: usize, text_len_bytes: usize) -> Option<u32> {
        // An unbounded allocator always succeeds in try_bump, so only a
        // bounded pool reaches this fallback.
        let need_units = Self::bucket_units(bucket) as u32;
        let need_bytes = need_units as u64 * ALLOC_UNIT_BYTES as u64;
        // UnitsStart byte pointer includes the pool-top remainder, matching
        // the C reference (all its pointers sit at unit*12 + rem).
        let units_start_bytes = self.units_start as u64 * ALLOC_UNIT_BYTES as u64 + self.rem as u64;
        // Match C: `(us - Text) > numBytes`. Strict greater-than (not ≥).
        if units_start_bytes <= text_len_bytes as u64 + need_bytes {
            return None;
        }
        let new_units_start = self.units_start - need_units;
        self.units_start = new_units_start;
        // Lower the text capacity so text_has_room reflects the new boundary.
        self.text_capacity_bytes = new_units_start as usize * ALLOC_UNIT_BYTES + self.rem as usize;
        Some(new_units_start)
    }

    fn try_bump(&mut self, bucket: usize, side: AllocSide) -> Option<u32> {
        let block = Self::bucket_units(bucket) as u32;
        if self.unbounded {
            // No real pool; hand out monotonic offsets so each alloc is
            // distinguishable but never adjacent to another (so gluing is
            // a no-op for the tests).
            let off = self.lo_bump;
            self.lo_bump = self.lo_bump.saturating_add(block);
            return Some(off);
        }
        // hi_bump - lo_bump is the bumpable headroom in units.
        if self.hi_bump.saturating_sub(self.lo_bump) < block {
            return None;
        }
        match side {
            AllocSide::Lo => {
                let off = self.lo_bump;
                self.lo_bump += block;
                Some(off)
            }
            AllocSide::Hi => {
                self.hi_bump -= block;
                Some(self.hi_bump)
            }
        }
    }

    fn try_free(&mut self, offset: u32, units: usize) -> Result<()> {
        if offset == NULL_OFFSET {
            return Ok(());
        }
        if let Some(bucket) = Self::bucket_for(units) {
            self.free_lists[bucket].try_push(offset)?;
        }
        Ok(())
    }

    // Ppmd7_SplitBlock: carve a block of `old_units` (bucket I2U value) down
    // to `new_units` (bucket I2U value) in place. The first `new_units`
    // stay at `base_offset`; the (old_units - new_units) residue is pushed
    // onto the appropriate smaller bucket(s). The "kept" prefix is NOT
    // pushed — the caller is still using it as live storage.
    fn try_split_in_place(
        &mut self,
        base_offset: u32,
        old_units: u32,
        new_units: u32,
    ) -> Result<()> {
        let nu = old_units - new_units;
        let residue_offset = base_offset + new_units;
        // Both inputs are distinct bucket sizes; their difference is 1..128.
        let mut i = Self::bucket_for(nu as usize).expect("split residue is a valid bucket size");
        if Self::bucket_units(i) as u32 != nu {
            // Inexact fit: the C reference pushes the smaller piece first
            // (at offset + bucket_units(i-1)) onto bucket index `nu - k - 1`,
            // then the i-1-sized prefix onto bucket i-1. Order across
            // buckets is irrelevant; per-bucket LIFO is unaffected.
            let k = Self::bucket_units(i - 1) as u32;
            let small_bucket = (nu - k - 1) as usize;
            self.free_lists[small_bucket].try_push(residue_offset + k)?;
            i -= 1;
        }
        self.free_lists[i].try_push(residue_offset)?;
        Ok(())
    }

    // Faithful port of Ppmd7_GlueFreeBlocks (§4.4). The earlier
    // sort-by-offset version diverged from the reference in three ways that
    // all change the resulting free-list state — and therefore the timing of
    // the next allocation failure / model restart:
    //   1. Threading order: the reference walks free_list[0..38], each list
    //      head-first (most-recent first), prepending every node to a single
    //      glue list. We rebuild that exact order so the fill pass re-buckets
    //      runs in the same sequence (per-bucket LIFO must match).
    //   2. Merge cap: a merged run may not reach 0x10000 units (NU is 16-bit).
    //   3. Fill split: runs are emitted as repeated 128-unit blocks, then the
    //      <=128 remainder via Ppmd7_SplitBlock's exact-or-two-piece rule —
    //      not "largest bucket fitting" greedily.
    fn glue_inner(&mut self) -> Result<()> {
        let mut poller = self.read_control.poller();
        // Step 1: thread free blocks into the reference's list order.
        // list[k] = (offset, nu). The reference's prepend walk ends with
        // bucket 37 first, each bucket in its original Vec order.
        let allowance = self.free_lists[0].allowance();
        let count = self.free_lists.iter().try_fold(0usize, |total, list| {
            total
                .checked_add(list.len())
                .ok_or(Error::InvalidData("PPMd free-list size overflows"))
        })?;
        let mut list = Buffer::with_capacity(count, &allowance)?;
        // Reversing the bucket order and visiting each bucket oldest-first
        // produces exactly the prior head-first/prepend walk, without moving
        // all previous entries for each insertion.
        for bucket in (0..N_BUCKETS).rev() {
            let nu = Self::bucket_units(bucket) as u32;
            for &off in &self.free_lists[bucket] {
                poller.check_codec(0)?;
                list.push_admitted((off, nu));
            }
            self.free_lists[bucket].clear();
        }
        if list.is_empty() {
            return Ok(());
        }

        // Step 2: glue pass. Absorb the physically-next free block while the
        // combined size stays < 0x10000. `nu_at` maps a block's start offset
        // to its current size; absorbed blocks are set to 0.
        let mut nu_at = GlueIndex::new(&list, &allowance, &self.read_control)?;
        for &(off, _) in list.iter() {
            poller.check_codec(0)?;
            let mut cur = match nu_at.get(&off) {
                Some(&n) if n != 0 => n,
                _ => continue,
            };
            loop {
                poller.check_codec(0)?;
                let next_off = off + cur;
                match nu_at.get(&next_off) {
                    Some(&n2) => {
                        let new = cur + n2;
                        if new >= 0x10000 {
                            break;
                        }
                        cur = new;
                        nu_at.insert(next_off, 0);
                    }
                    None => break,
                }
            }
            nu_at.insert(off, cur);
        }

        // Step 3: fill pass in list order.
        for &(off, _) in list.iter() {
            poller.check_codec(0)?;
            let nu = match nu_at.get(&off) {
                Some(&n) if n != 0 => n,
                _ => continue,
            };
            self.emit_run(off, nu)?;
        }
        Ok(())
    }

    // Re-bucket a single merged run exactly as Ppmd7_GlueFreeBlocks' fill /
    // Ppmd7_SplitBlock do: peel 128-unit (bucket 37) blocks, then split the
    // <=128 remainder into its exact bucket, or two pieces when inexact.
    fn emit_run(&mut self, mut offset: u32, mut remaining: u32) -> Result<()> {
        const LAST_BUCKET: usize = N_BUCKETS - 1; // 37 == 128 units
        while remaining > MAX_BUCKET_UNITS as u32 {
            self.push_free(LAST_BUCKET, offset)?;
            offset += MAX_BUCKET_UNITS as u32;
            remaining -= MAX_BUCKET_UNITS as u32;
        }
        // Callers pass positive runs; the loop leaves 1..=128 units.
        let mut i = Self::bucket_for(remaining as usize).expect("run remainder fits a bucket");
        if Self::bucket_units(i) as u32 != remaining {
            let k = Self::bucket_units(i - 1) as u32;
            let small_bucket = (remaining - k - 1) as usize;
            self.push_free(small_bucket, offset + k)?;
            i -= 1;
        }
        self.push_free(i, offset)?;
        Ok(())
    }

    fn push_free(&mut self, bucket: usize, offset: u32) -> Result<()> {
        self.free_lists[bucket].try_push(offset)
    }

    fn text_has_room(&self, text_len: usize) -> bool {
        // When pool isn't initialised (test fixtures that bypass decode_init),
        // text_capacity is 0 — treat that as "unbounded" so we don't break
        // out-of-band callers.
        self.text_capacity_bytes == 0 || text_len < self.text_capacity_bytes
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
#[cfg(any(test, feature = "write"))]
pub struct PpmdDecoder {
    state: PpmdState<Allowance>,
}
impl Clone for PpmdState<Allowance> {
    fn clone(&self) -> Self {
        self.try_clone().expect("unlimited PPMd model copy")
    }
}
#[cfg(any(test, feature = "write"))]
impl PpmdDecoder {
    pub fn new() -> Self {
        Self {
            state: PpmdState::with_allowance(&Allowance::default()),
        }
    }
}
#[cfg(test)]
impl PpmdState<Allowance> {
    fn new() -> Self {
        Self::with_allowance(&Allowance::default())
    }
}
#[derive(Debug)]
pub(crate) struct PpmdState<B: Budget> {
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
    contexts: Buffer<Context<B>, B>,
    text: Buffer<u8, B>,
    range: RangeDecoder,
    allocated: bool,
    max_contexts: usize,
    suballoc: Suballocator<B>,
}

#[derive(Debug, Clone)]
#[cfg(any(test, feature = "write"))]
pub struct PpmdEncoder {
    model: PpmdDecoder,
    range: RangeEncoder,
    esc_char: u8,
}

#[derive(Debug)]
struct Context<B: Budget = Allowance> {
    states: Buffer<State, B>,
    summ_freq: u16,
    suffix: Option<usize>,
    // Simulated suballoc offsets so gluing (spec §4.3) can detect adjacency.
    // header_offset: from Hi side (1 unit). array_offset: from Lo side,
    // set to NULL_OFFSET for binary contexts (states.len() == 1) which
    // carry their state inline.
    header_offset: u32,
    array_offset: u32,
}

impl<B: Budget> Context<B> {
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            states: Buffer::copied(&self.states, &self.states.allowance())?,
            summ_freq: self.summ_freq,
            suffix: self.suffix,
            header_offset: self.header_offset,
            array_offset: self.array_offset,
        })
    }
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

impl<B: Budget> PpmdState<B> {
    pub(crate) fn set_read_control(&mut self, control: crate::read_control::ReadControl) {
        self.suballoc.read_control = control;
    }
    pub(crate) fn with_allowance(allowance: &B) -> Self {
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
            contexts: Buffer::new(allowance),
            text: Buffer::new(allowance),
            range: RangeDecoder::new(),
            allocated: false,
            max_contexts: MIN_MODEL_CONTEXTS,
            suballoc: Suballocator::with_allowance(allowance),
        }
    }

    // Units occupied by a context's state array. Single-state (binary)
    // contexts store the state inline, so the array is 0 units. Otherwise
    // ceil(n/2) units fit n states at 2-per-unit (states are 6 bytes each).
    fn state_array_units(n: usize) -> usize {
        if n < 2 {
            0
        } else {
            n.div_ceil(2)
        }
    }

    pub(crate) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            min_context: self.min_context,
            max_context: self.max_context,
            found_state: self.found_state,
            order_fall: self.order_fall,
            init_esc: self.init_esc,
            prev_success: self.prev_success,
            max_order: self.max_order,
            hi_bits_flag: self.hi_bits_flag,
            run_length: self.run_length,
            init_rl: self.init_rl,
            ns2bs_indx: self.ns2bs_indx,
            ns2indx: self.ns2indx,
            bin_summ: self.bin_summ,
            see: self.see,
            dummy_see: self.dummy_see,
            contexts: Buffer::try_collect(
                self.contexts.iter().map(Context::try_clone),
                &self.contexts.allowance(),
            )?,
            text: Buffer::copied(&self.text, &self.text.allowance())?,
            range: self.range.clone(),
            allocated: self.allocated,
            max_contexts: self.max_contexts,
            suballoc: self.suballoc.try_clone()?,
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
            self.init_model(max_order)?;
            self.allocated = true;
        } else if !self.allocated {
            return Err(Error::InvalidData("RAR PPMd block reuses missing model"));
        }
        Ok(())
    }

    pub fn decode_symbol(&mut self, input: &mut impl PpmdByteReader) -> Result<Option<u8>> {
        // Ordinary symbol/context work is bounded by the model order and the
        // 256-symbol alphabet; the enclosing decoder polls between symbols.
        // Free-list maintenance can traverse the whole model and polls itself.
        self.decode_symbol_inner(input)
    }

    fn decode_symbol_inner(&mut self, input: &mut impl PpmdByteReader) -> Result<Option<u8>> {
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
                let mut selected = None;
                for (index, state) in self.contexts[mc].states.iter().enumerate() {
                    if !mask[state.symbol as usize] {
                        continue;
                    }
                    let freq = state.freq as u32;
                    if count < freq {
                        selected = Some((index, start, freq, state.symbol));
                        break;
                    }
                    count -= freq;
                    start += freq;
                }
                // hi_cnt was summed from these same unmodified, unmasked
                // frequencies, so count < hi_cnt must select a state.
                let (index, start, freq, symbol) =
                    selected.expect("masked threshold selects a state");
                self.range.decode(start, freq);
                self.update_see(see_ref);
                self.found_state = StateRef { context: mc, index };
                self.update2()?;
                self.range.normalize(input)?;
                return Ok(Some(symbol));
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

    #[cfg(any(test, feature = "write"))]
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

    fn init_model(&mut self, max_order: usize) -> Result<()> {
        self.suballoc.read_control.check_codec()?;
        self.contexts.clear();
        self.text.clear();
        // Spec §5.2 RestartModel: clear free lists, reserve root context
        // (1 unit from Hi) + its 256-state array (128 units from Lo).
        // Reuse the exact original byte size (C's p->Size) so the text/units
        // split and the pool-top remainder survive the restart unchanged.
        let unbounded_before = self.suballoc.unbounded;
        let reset_arg = if unbounded_before {
            0
        } else {
            self.suballoc.size_bytes
        };
        self.suballoc.reset(reset_arg);
        // At init time text is empty.
        let header_offset = self
            .suballoc
            .try_alloc(1, AllocSide::Hi, 0)?
            .unwrap_or(NULL_OFFSET);
        let array_offset = self
            .suballoc
            .try_alloc(128, AllocSide::Lo, 0)?
            .unwrap_or(NULL_OFFSET);
        self.max_order = max_order;
        self.order_fall = max_order;
        self.init_rl = -(max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        let states = Buffer::collect(
            (0..=255).map(|symbol| State {
                symbol,
                freq: 1,
                successor: Successor::None,
            }),
            &self.contexts.allowance(),
        )?;
        self.contexts.try_push(Context {
            states,
            summ_freq: 257,
            suffix: None,
            header_offset,
            array_offset,
        })?;
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
        Ok(())
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
        // The guard above establishes num_masked < num_stats.
        let non_masked = num_stats - num_masked;
        let suffix = self.contexts[mc].suffix.unwrap_or(mc);
        let suffix_stats = self.contexts[suffix].states.len();
        // Spec §9.1: the subtraction is unsigned C wraparound — when
        // `suffix.num_stats < min_context.num_stats`, the underflow yields a
        // very large value and the `non_masked < suffix_delta` comparison
        // evaluates to TRUE. Replicate the wraparound here.
        let suffix_delta = suffix_stats.wrapping_sub(num_stats);
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
            self.rescale()?;
        }
        self.next_context()
    }

    fn update1(&mut self) -> Result<()> {
        let fs = self.found_state;
        let freq = self.state(fs)?.freq as u32 + 4;
        self.contexts[fs.context].summ_freq = self.contexts[fs.context].summ_freq.wrapping_add(4);
        self.state_mut(fs)?.freq = freq as u8;
        // Both decode and encode call update1 only for a non-first state.
        if self.contexts[fs.context].states[fs.index].freq
            > self.contexts[fs.context].states[fs.index - 1].freq
        {
            self.contexts[fs.context]
                .states
                .swap(fs.index, fs.index - 1);
            self.found_state.index -= 1;
            if freq > MAX_FREQ {
                self.rescale()?;
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
            self.rescale()?;
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
            let Some(context) = self.create_successors()? else {
                self.init_model(self.max_order)?;
                return Ok(());
            };
            self.max_context = context;
            self.min_context = context;
            self.state_mut(self.found_state)?.successor = Successor::Context(context);
            return Ok(());
        }

        // Match Ppmd7_UpdateModel exactly: advance text first, then check
        // `text >= UnitsStart`. The previous "check then push" version
        // restarted one symbol later than the reference, advancing the range
        // coder by one extra symbol before resetting — which left the
        // post-restart state out of sync.
        self.text.try_push(found_symbol)?;
        let max_successor = Successor::Raw(self.text.len());
        if !self.suballoc.text_has_room(self.text.len()) {
            self.init_model(self.max_order)?;
            return Ok(());
        }
        let (min_context, had_successor) = match fs.successor {
            Successor::None => {
                self.state_mut(self.found_state)?.successor = max_successor;
                (self.min_context, false)
            }
            Successor::Context(context) => (context, true),
            Successor::Raw(_) => {
                let Some(context) = self.create_successors()? else {
                    self.init_model(self.max_order)?;
                    return Ok(());
                };
                (context, true)
            }
        };
        if had_successor {
            self.order_fall -= 1;
            if self.order_fall == 0 && self.max_context != self.min_context {
                self.text.pop();
            }
        }
        let min_successor = Successor::Context(min_context);

        let mc = self.min_context;
        let mut c = self.max_context;
        self.min_context = min_context;
        self.max_context = min_context;
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

            // sum is at most u16::MAX + 3 here, s0 at most u16::MAX,
            // and fs.freq at most u8::MAX. Even the largest product is
            // below 34 million, so u32 arithmetic cannot overflow.
            let mut cf = (sum + 6) * 2 * fs.freq as u32;
            let sf = s0 + sum;
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
            if !self.grow_state_array(c, old_n + 1)? {
                self.init_model(self.max_order)?;
                return Ok(());
            }
            self.contexts[c].states.try_push(State {
                symbol: found_symbol,
                freq: cf as u8,
                successor: if self.order_fall == 0 {
                    min_successor
                } else {
                    max_successor
                },
            })?;
            self.contexts[c].summ_freq = u16::try_from(sum)
                .map_err(|_| Error::InvalidData("RAR PPMd model frequency overflows"))?;
            c = self.contexts[c].suffix.unwrap_or(mc);
        }
        Ok(())
    }

    fn create_successors(&mut self) -> Result<Option<usize>> {
        // Missing links retain the reference model's restart path. Workspace
        // refusal is propagated separately and must never restart the model.
        macro_rules! pressure {
            ($value:expr) => {
                match $value {
                    Some(value) => value,
                    None => return Ok(None),
                }
            };
        }
        let up_branch = match pressure!(self.state(self.found_state).ok()).successor {
            Successor::Raw(pos) => pos,
            Successor::Context(context) if self.order_fall == 0 => return Ok(Some(context)),
            _ => return Ok(None),
        };
        let mut c = self.min_context;
        let allowance = self.contexts.allowance();
        let mut ps = Buffer::new(&allowance);
        if self.order_fall != 0 {
            ps.try_push(self.found_state)?;
        }
        while let Some(suffix) = self.contexts[c].suffix {
            c = suffix;
            let found_symbol = pressure!(self.state(self.found_state).ok()).symbol;
            let index = pressure!(self.contexts[c]
                .states
                .iter()
                .position(|state| state.symbol == found_symbol));
            let successor = self.contexts[c].states[index].successor;
            if successor != Successor::Raw(up_branch) {
                if let Successor::Context(context) = successor {
                    c = context;
                    if ps.is_empty() {
                        return Ok(Some(c));
                    }
                    break;
                }
                return Ok(None);
            }
            ps.try_push(StateRef { context: c, index })?;
        }
        if ps.is_empty() {
            return Ok(Some(c));
        }
        let new_sym = *pressure!(self.text.get(up_branch));
        let up_successor = Successor::Raw(up_branch + 1);
        let new_freq = if self.contexts[c].states.len() == 1 {
            self.contexts[c].states[0].freq
        } else {
            let state = pressure!(self.contexts[c]
                .states
                .iter()
                .find(|state| state.symbol == new_sym));
            let cf = state.freq as u32 - 1;
            let s0 = self.contexts[c].summ_freq as u32 - self.contexts[c].states.len() as u32 - cf;
            (1 + if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                (2 * cf + 3 * s0 - 1) / (2 * s0)
            }) as u8
        };
        while let Some(state_ref) = ps.pop() {
            let context = pressure!(self.push_context(Context {
                states: Buffer::filled(
                    1,
                    State {
                        symbol: new_sym,
                        freq: new_freq,
                        successor: up_successor
                    },
                    &allowance
                )?,
                summ_freq: 0,
                suffix: Some(c),
                header_offset: NULL_OFFSET,
                array_offset: NULL_OFFSET,
            })?);
            pressure!(self.state_mut(state_ref).ok()).successor = Successor::Context(context);
            c = context;
        }
        Ok(Some(c))
    }

    fn push_context(&mut self, mut context: Context<B>) -> Result<Option<usize>> {
        if self.contexts.len() >= self.max_contexts {
            return Ok(None);
        }
        // 1 unit for the context header (Hi side); binary contexts (1 state)
        // carry their state inline, multi-state contexts also need a state
        // array (Lo side).
        let text_len = self.text.len();
        let Some(header_offset) = self.suballoc.try_alloc(1, AllocSide::Hi, text_len)? else {
            return Ok(None);
        };
        let array_units = Self::state_array_units(context.states.len());
        let array_offset = if array_units > 0 {
            match self
                .suballoc
                .try_alloc(array_units, AllocSide::Lo, text_len)?
            {
                Some(off) => off,
                None => {
                    self.suballoc.try_free(header_offset, 1)?;
                    return Ok(None);
                }
            }
        } else {
            NULL_OFFSET
        };
        context.header_offset = header_offset;
        context.array_offset = array_offset;
        let index = self.contexts.len();
        self.contexts.try_push(context)?;
        Ok(Some(index))
    }

    // Grow a context's state array from its current size → `new_n` states.
    // Models ExpandUnits: if the same bucket still fits, no realloc happens;
    // otherwise allocate the new size first, then release the old slot. The
    // context's array_offset is updated to point at the new block when
    // moved.
    fn grow_state_array(&mut self, ctx_idx: usize, new_n: usize) -> Result<bool> {
        let old_n = self.contexts[ctx_idx].states.len();
        let old_units = Self::state_array_units(old_n);
        let new_units = Self::state_array_units(new_n);
        // Called only for old_n + 1 during UpdateModel. The new array has
        // positive size; unchanged bucket sizes are handled below.
        if old_units > 0 {
            let old_b = Suballocator::<B>::bucket_for(old_units);
            let new_b = Suballocator::<B>::bucket_for(new_units);
            if old_b == new_b {
                return Ok(true);
            }
        }
        let text_len = self.text.len();
        let new_offset = match self
            .suballoc
            .try_alloc(new_units, AllocSide::Lo, text_len)?
        {
            Some(off) => off,
            None => return Ok(false),
        };
        if old_units > 0 {
            let old_offset = self.contexts[ctx_idx].array_offset;
            self.suballoc.try_free(old_offset, old_units)?;
        }
        self.contexts[ctx_idx].array_offset = new_offset;
        Ok(true)
    }

    // Rescale shrinks a state array. Mirrors Ppmd7_Rescale's branch at
    // Ppmd7.c:901-919: if the target bucket has a free block, swap to it
    // (pop i1, push old to i0); otherwise SplitBlock the existing block in
    // place — the first i1 units stay at the current address as the new
    // array, the (i0 - i1)-unit residue is bucketed onto smaller free lists.
    // No bump is consumed on the in-place path, which matters because over
    // many rescales the reference never grows lo_bump from shrinks.
    //
    // Collapse-to-unary (new_n == 1, new_units == 0) is handled by Rescale's
    // earlier branch (Ppmd7.c:881-898), which frees `stats` at bucket
    // U2I(n0) and copies the surviving state into the inline OneState slot.
    fn shrink_state_array(&mut self, ctx_idx: usize, old_n: usize, new_n: usize) -> Result<()> {
        let old_units = Self::state_array_units(old_n);
        let new_units = Self::state_array_units(new_n);
        // Rescale starts with a multi-state context, so old_units is positive.
        if new_units >= old_units {
            return Ok(());
        }
        if new_units == 0 {
            // Collapse to unary: free the whole array, clear the pointer.
            let old_offset = self.contexts[ctx_idx].array_offset;
            self.suballoc.try_free(old_offset, old_units)?;
            self.contexts[ctx_idx].array_offset = NULL_OFFSET;
            return Ok(());
        }
        // Contexts contain at most 256 states, so both nonzero array sizes
        // are in the allocator's 1..=128-unit range.
        let i0 = Suballocator::<B>::bucket_for(old_units).expect("old array fits a bucket");
        let i1 = Suballocator::<B>::bucket_for(new_units).expect("new array fits a bucket");
        if i0 == i1 {
            return Ok(());
        }
        let old_offset = self.contexts[ctx_idx].array_offset;
        if let Some(swap_offset) = self.suballoc.free_lists[i1].pop() {
            // Swap path: take a same-sized block from the target bucket,
            // return the oversized block to its bucket. Data lives in
            // self.contexts[ctx_idx].states (Vec), so no MEM_12_CPY needed.
            self.suballoc.try_free(old_offset, old_units)?;
            self.contexts[ctx_idx].array_offset = swap_offset;
        } else {
            // SplitBlock in place: keep the first I2U(i1) units at the same
            // address, bucket the residue. Matches Ppmd7_SplitBlock.
            let i0_units = Suballocator::<B>::bucket_units(i0) as u32;
            let i1_units = Suballocator::<B>::bucket_units(i1) as u32;
            self.suballoc
                .try_split_in_place(old_offset, i0_units, i1_units)?;
            // array_offset is unchanged.
        }
        Ok(())
    }

    fn rescale(&mut self) -> Result<()> {
        let ctx = self.min_context;
        let original_state_count = self.contexts[ctx].states.len();
        let mut states = Buffer::copied(&self.contexts[ctx].states, &self.contexts.allowance())?;
        let found = self.found_state.index;
        if found != 0 {
            let state = states.remove(found);
            states.insert(0, state)?;
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
            self.shrink_state_array(ctx, original_state_count, 1)?;
            self.contexts[ctx].states = states;
            self.found_state.index = 0;
            return Ok(());
        }
        self.contexts[ctx].summ_freq = (sum_freq + esc_freq - (esc_freq >> 1)) as u16;
        self.shrink_state_array(ctx, original_state_count, states.len())?;
        self.contexts[ctx].states = states;
        self.found_state.index = 0;
        Ok(())
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

#[cfg(any(test, feature = "write"))]
impl PpmdEncoder {
    pub fn new(max_order: usize, esc_char: u8, dictionary_mb: usize) -> Result<Self> {
        if !(2..=64).contains(&max_order) {
            return Err(Error::InvalidData("RAR PPMd order is invalid"));
        }
        if dictionary_mb == 0 {
            return Err(Error::InvalidData("RAR PPMd dictionary size is invalid"));
        }
        let mut model = PpmdDecoder::new();
        model.state.max_contexts = model_context_limit(dictionary_mb);
        model
            .state
            .suballoc
            .reset(dictionary_mb.saturating_mul(1024 * 1024));
        model.state.init_model(max_order)?;
        model.state.allocated = true;
        Ok(Self {
            model,
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
    pub fn continuing(model: PpmdDecoder, esc_char: u8) -> Self {
        Self {
            model,
            range: RangeEncoder::new(),
            esc_char,
        }
    }

    /// Ends the block and hands the model back for the next one to continue.
    pub fn finish_keeping_model(mut self) -> Result<(Vec<u8>, PpmdDecoder)> {
        self.model
            .state
            .encode_symbol(self.esc_char, &mut self.range)?;
        self.model.state.encode_symbol(2, &mut self.range)?;
        Ok((self.range.finish(), self.model))
    }

    /// Ends this PPMd block while keeping the member open for another block.
    #[cfg(all(test, feature = "write"))]
    pub(crate) fn finish_block_keeping_model(mut self) -> Result<(Vec<u8>, PpmdDecoder)> {
        self.model
            .state
            .encode_symbol(self.esc_char, &mut self.range)?;
        self.model.state.encode_symbol(0, &mut self.range)?;
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
        self.model
            .state
            .encode_symbol(self.esc_char, &mut self.range)?;
        self.model.state.encode_symbol(command, &mut self.range)?;
        for &parameter in parameters {
            self.model.state.encode_symbol(parameter, &mut self.range)?;
        }
        Ok(self.range.finish())
    }

    pub fn encode_literal(&mut self, symbol: u8) -> Result<()> {
        self.model.state.encode_symbol(symbol, &mut self.range)?;
        if symbol == self.esc_char {
            self.model.state.encode_symbol(1, &mut self.range)?;
        }
        Ok(())
    }

    pub fn encode_repeat_offset_one(&mut self, length: usize) -> Result<()> {
        if !(4..=259).contains(&length) {
            return Err(Error::InvalidData(
                "RAR PPMd offset-one repeat length is invalid",
            ));
        }
        self.model
            .state
            .encode_symbol(self.esc_char, &mut self.range)?;
        self.model.state.encode_symbol(5, &mut self.range)?;
        self.model
            .state
            .encode_symbol((length - 4) as u8, &mut self.range)?;
        Ok(())
    }

    pub fn encode_match(&mut self, offset: usize, length: usize) -> Result<()> {
        if !(2..=0x1000001).contains(&offset) || !(32..=287).contains(&length) {
            return Err(Error::InvalidData("RAR PPMd match is invalid"));
        }
        let encoded_offset = offset - 2;
        self.model
            .state
            .encode_symbol(self.esc_char, &mut self.range)?;
        self.model.state.encode_symbol(4, &mut self.range)?;
        self.model
            .state
            .encode_symbol(((encoded_offset >> 16) & 0xff) as u8, &mut self.range)?;
        self.model
            .state
            .encode_symbol(((encoded_offset >> 8) & 0xff) as u8, &mut self.range)?;
        self.model
            .state
            .encode_symbol((encoded_offset & 0xff) as u8, &mut self.range)?;
        self.model
            .state
            .encode_symbol((length - 32) as u8, &mut self.range)?;
        Ok(())
    }

    #[cfg(feature = "write")]
    pub fn encode_vm_filter_record(&mut self, record: &[u8]) -> Result<()> {
        self.model
            .state
            .encode_symbol(self.esc_char, &mut self.range)?;
        self.model.state.encode_symbol(3, &mut self.range)?;
        for &byte in record {
            self.model.state.encode_symbol(byte, &mut self.range)?;
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
        while normalize_range(self.low, &mut self.range) {
            self.code = (self.code << 8) | input.read_ppmd_byte()? as u32;
            self.range <<= 8;
            self.low <<= 8;
        }
        Ok(())
    }
}

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
        while normalize_range(self.low, &mut self.range) {
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

fn normalize_range(low: u32, range: &mut u32) -> bool {
    if (low ^ low.wrapping_add(*range)) < TOP {
        return true;
    }
    if *range >= BOT {
        return false;
    }
    *range = low.wrapping_neg() & (BOT - 1);
    true
}

fn update_prob_1(prob: u32) -> u32 {
    prob - ((prob + (1 << 5)) >> INT_BITS)
}

fn hi_bits_flag(symbol: u8, bits: u32) -> u32 {
    ((symbol as u32 + 0xc0) >> (8 - bits)) & (1 << bits)
}

#[cfg(test)]
impl Default for Suballocator<Allowance> {
    fn default() -> Self {
        Self::with_allowance(&Allowance::default())
    }
}
#[cfg(test)]
impl Suballocator<Allowance> {
    fn alloc(&mut self, units: usize, side: AllocSide, text_len_bytes: usize) -> Option<u32> {
        self.try_alloc(units, side, text_len_bytes)
            .expect("unlimited arena allocation")
    }
    fn free(&mut self, offset: u32, units: usize) {
        self.try_free(offset, units).unwrap();
    }
    fn split_in_place(&mut self, base: u32, old: u32, new: u32) {
        self.try_split_in_place(base, old, new).unwrap();
    }
    fn glue(&mut self) {
        self.glue_inner().expect("unlimited glue maintenance");
    }
}
/// Keep the glue walk's original order while admitting an exact allocation
/// for its offset lookup. The last original entry wins for duplicate offsets,
/// matching the previous map's insert semantics without opaque hash-table RAM.
struct GlueIndex<B: Budget> {
    entries: Buffer<Option<(u32, u32)>, B>,
}
impl<B: Budget> GlueIndex<B> {
    fn new(
        list: &[(u32, u32)],
        allowance: &B,
        control: &crate::read_control::ReadControl,
    ) -> Result<Self> {
        control.check_codec()?;
        if list.is_empty() {
            return Ok(Self {
                entries: Buffer::new(allowance),
            });
        }
        let count = list
            .len()
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::InvalidData("PPMd glue lookup size overflows"))?;
        let mut out = Self {
            entries: Buffer::filled(count, None, allowance)?,
        };
        let mut poller = control.poller();
        for &(offset, units) in list {
            poller.check_codec(0)?;
            out.insert(offset, units);
        }
        Ok(out)
    }
    fn hash(mut value: u32) -> usize {
        value ^= value >> 16;
        value = value.wrapping_mul(0x85eb_ca6b);
        value ^= value >> 13;
        value = value.wrapping_mul(0xc2b2_ae35);
        (value ^ (value >> 16)) as usize
    }
    fn slot(&self, offset: u32) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let mask = self.entries.len() - 1;
        let mut index = Self::hash(offset) & mask;
        loop {
            match self.entries[index] {
                Some((key, _)) if key != offset => index = (index + 1) & mask,
                _ => return Some(index),
            }
        }
    }
    fn get(&self, offset: &u32) -> Option<&u32> {
        self.entries[self.slot(*offset)?]
            .as_ref()
            .map(|(_, units)| units)
    }
    fn insert(&mut self, offset: u32, units: u32) {
        let index = self
            .slot(offset)
            .expect("glue inserts into a nonempty lookup");
        self.entries[index] = Some((offset, units));
    }
}

// Upper bound on the number of live context records. The C reference
// (Ppmd7.c) has NO independent context cap — model restart is driven solely
// by suballocator exhaustion (`Ppmd7_AllocUnits`/`AllocUnitsRare` returning
// NULL). A context header is one 12-byte unit, and headers + state arrays
// share the pool, so the live context count can never exceed `pool_units`
// (= Size / UNIT_SIZE). Sizing the cap to that makes the suballocator the
// binding constraint, exactly as in the reference, while still bounding Vec
// growth defensively. A smaller cap (the old Size/16) forced a premature
// RestartModel that desynchronised the decoder from the reference.
fn model_context_limit(dictionary_mb: usize) -> usize {
    dictionary_mb
        .saturating_mul(1024 * 1024)
        .checked_div(ALLOC_UNIT_BYTES)
        .unwrap_or(usize::MAX)
        .max(MIN_MODEL_CONTEXTS)
}

#[cfg(test)]
mod tests;
