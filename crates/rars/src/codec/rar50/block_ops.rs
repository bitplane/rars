//! A block's symbols need only its tables, so they decode ahead of the window
//! as operations; replaying them in order resolves what earlier blocks decide.
use super::{
    distance_from_slot_parts, distance_slot_bit_count, length_bonus, length_from_slot_parts,
    length_slot_extra_bits, read_filter, read_filter_record, BitReader, Budget, Buffer,
    DecodedChunk, Error, Overrun, PendingFilter, ReaderState, ReaderTables, Result,
    StreamDecodeError, StreamingOutput, LITERAL_BURST, SHORT_MATCH, STREAM_FLUSH_THRESHOLD,
};
use crate::read_control::Poller;
use std::hint::select_unpredictable;

// A list holds at most 4 MiB of each; a longer block takes several lists.
// Tests and fuzzing use tiny lists so small inputs still split blocks.
#[cfg(not(any(test, fuzzing)))]
const MAX_OPS: usize = 512 * 1024;
#[cfg(not(any(test, fuzzing)))]
const MAX_LITERALS: usize = 4 * 1024 * 1024;
#[cfg(any(test, fuzzing))]
const MAX_OPS: usize = 48;
#[cfg(any(test, fuzzing))]
const MAX_LITERALS: usize = 300;
// Literals copied between cancellation polls.
const LITERAL_POLL: usize = 64 * 1024;

const TAG_SHIFT: u32 = 61;
const LENGTH_SHIFT: u32 = 48;
const LENGTH_MASK: u64 = (1 << (TAG_SHIFT - LENGTH_SHIFT)) - 1;
const PREFIX_SHIFT: u32 = 38;
const PREFIX_MASK: u64 = (1 << (LENGTH_SHIFT - PREFIX_SHIFT)) - 1;
const VALUE_MASK: u64 = (1 << PREFIX_SHIFT) - 1;
// The longest literal run an operation carries ahead of itself.
const MAX_PREFIX: usize = PREFIX_MASK as usize;

const LITERALS: u64 = 0;
const MATCH: u64 = 1;
const REPEAT: u64 = 2;
const REPEAT_LAST: u64 = 3;
const FILTER: u64 = 4;
const REPEAT_CHECK: u64 = 5;
const BLOCK: u64 = 6;

/// Tag, a 13-bit length, the 10-bit count of literals decoded just before
/// it, and a 38-bit distance, repeat index or literal count. Carrying the
/// literals saves the replay a dispatch on most matches.
#[derive(Clone, Copy)]
struct Op(u64);

impl Op {
    fn new(tag: u64, length: usize, value: usize) -> Self {
        Self::after(0, tag, length, value)
    }

    fn after(prefix: usize, tag: u64, length: usize, value: usize) -> Self {
        debug_assert!(length as u64 <= LENGTH_MASK);
        debug_assert!(prefix <= MAX_PREFIX);
        // A distance no window can hold only has to stay out of range.
        let value = (value as u64).min(VALUE_MASK);
        Self(
            (tag << TAG_SHIFT)
                | ((length as u64) << LENGTH_SHIFT)
                | ((prefix as u64) << PREFIX_SHIFT)
                | value,
        )
    }

    fn tag(self) -> u64 {
        self.0 >> TAG_SHIFT
    }

    fn length(self) -> usize {
        ((self.0 >> LENGTH_SHIFT) & LENGTH_MASK) as usize
    }

    fn prefix(self) -> usize {
        ((self.0 >> PREFIX_SHIFT) & PREFIX_MASK) as usize
    }

    fn value(self) -> usize {
        usize::try_from(self.0 & VALUE_MASK).unwrap_or(usize::MAX)
    }
}

/// How decoding a list ended.
#[derive(Debug)]
pub(super) enum Stop {
    BlockEnd,
    /// The list is full; the block continues at this bit.
    Full(usize),
    /// Reported only if replay consumes every operation before it.
    Failed(Error),
}

/// Lets the declared-size check find the serial decoder's stopping point.
#[derive(Default)]
pub(super) struct Reached {
    pub(super) blocks: usize,
    pub(super) symbols: usize,
}

/// The match state that carries from one block to the next.
pub(super) struct Repeats<'a> {
    pub(super) distances: &'a mut [usize; 4],
    pub(super) last_length: &'a mut usize,
}

#[derive(Default)]
pub(super) struct BlockOps {
    ops: Vec<Op>,
    literals: Vec<u8>,
    // Starts are relative to the output position where the filter is read.
    filters: Vec<PendingFilter>,
}

impl BlockOps {
    pub(super) fn clear(&mut self) {
        self.ops.clear();
        self.literals.clear();
        self.filters.clear();
    }

    /// Marks where the next block's operations start.
    pub(super) fn begin_block(&mut self) {
        self.ops.push(Op::new(BLOCK, 0, 0));
    }

    /// Appends a block's operations from `bit_pos` on.
    pub(super) fn decode<B: Budget>(
        &mut self,
        tables: &ReaderTables<B>,
        payload: &[u8],
        bit_pos: usize,
        payload_bits: usize,
    ) -> Stop {
        let mut run_start = self.literals.len();
        let decoded = self.decode_symbols(tables, payload, bit_pos, payload_bits, &mut run_start);
        // Literals no operation carried replay on their own, before any failure.
        let run = self.literals.len() - run_start;
        if run != 0 {
            self.ops.push(Op::new(LITERALS, 0, run));
        }
        match decoded {
            Ok(None) => Stop::BlockEnd,
            Ok(Some(bit_pos)) => Stop::Full(bit_pos),
            Err(error) => Stop::Failed(error),
        }
    }

    /// Appends an operation, carrying the literals decoded since the last one.
    #[inline(always)]
    fn push(&mut self, run_start: &mut usize, tag: u64, length: usize, value: usize) {
        let mut prefix = self.literals.len() - *run_start;
        if prefix > MAX_PREFIX {
            self.ops.push(Op::new(LITERALS, 0, prefix));
            prefix = 0;
        }
        self.ops.push(Op::after(prefix, tag, length, value));
        *run_start = self.literals.len();
    }

    fn decode_symbols<B: Budget>(
        &mut self,
        tables: &ReaderTables<B>,
        payload: &[u8],
        bit_pos: usize,
        payload_bits: usize,
        run_start: &mut usize,
    ) -> Result<Option<usize>> {
        let mut bits = BitReader::at(payload, bit_pos);
        while bits.position() < payload_bits {
            if self.ops.len() >= MAX_OPS || self.literals.len() >= MAX_LITERALS {
                return Ok(Some(bits.position()));
            }
            let symbol = tables.main.decode(&mut bits)?;
            match symbol {
                0..=255 => {
                    self.literals.push(symbol as u8);
                    loop {
                        let len = self.literals.len();
                        self.literals.resize(len + LITERAL_BURST, 0);
                        let count = bits.literal_burst(
                            &tables.main,
                            payload_bits,
                            &mut self.literals[len..],
                        );
                        self.literals.truncate(len + count);
                        if count < LITERAL_BURST || self.literals.len() >= MAX_LITERALS {
                            break;
                        }
                    }
                }
                256 => {
                    self.filters.push(read_filter(&mut bits, 0)?);
                    self.push(run_start, FILTER, 0, 0);
                }
                257 => self.push(run_start, REPEAT_LAST, 0, 0),
                258..=261 => {
                    let index = symbol - 258;
                    match repeat_length(tables, &mut bits) {
                        Ok(length) => self.push(run_start, REPEAT, length, index),
                        Err(error) => {
                            // An unset repeat distance is reported before the length is read.
                            self.push(run_start, REPEAT_CHECK, 0, index);
                            return Err(error);
                        }
                    }
                }
                _ => {
                    let (length, distance) = new_match(tables, &mut bits, symbol)?;
                    self.push(run_start, MATCH, length, distance);
                }
            }
        }
        Ok(None)
    }

    /// Replays the list up to where the serial decoder would stop, counting what it reaches.
    pub(super) fn apply<B: Budget, E>(
        &self,
        repeats: &mut Repeats<'_>,
        output: &mut StreamingOutput<B>,
        poller: &mut Poller,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
        filters: &mut Option<&mut dyn FnMut(PendingFilter) -> std::result::Result<(), E>>,
        reached: &mut Reached,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let output_size = output.output_limit;
        // Held in locals for the walk and stored back however it ends.
        let mut reps = *repeats.distances;
        let mut last_length = *repeats.last_length;
        let mut literals = self.literals.as_slice();
        let mut block_filters = self.filters.iter();
        // Bytes the unchecked copies may write before the output needs a look.
        let mut budget = output.fast_budget();
        let mut walk = || {
            for &op in &self.ops {
                if output.written() >= output_size {
                    break;
                }
                poller.check_codec(output.written())?;
                // The literals before this symbol, then the symbol itself.
                let prefix = op.prefix();
                if prefix < budget {
                    output.push_literals_within_budget(literals, prefix);
                    literals = &literals[prefix..];
                    reached.symbols += prefix;
                    budget -= prefix;
                } else {
                    let (run, rest) = literals.split_at(prefix);
                    literals = rest;
                    let visible = run.len().min(output_size - output.written());
                    reached.symbols += visible;
                    output.push_literals(&run[..visible], sink)?;
                    budget = output.fast_budget();
                    if output.written() >= output_size {
                        break;
                    }
                    poller.check_codec(output.written())?;
                }
                let tag = op.tag();
                if (MATCH..=REPEAT_LAST).contains(&tag) {
                    reached.symbols += 1;
                    // A new distance pushes all four along; a repeat moves its own to the front.
                    // Selects rather than branches, since the kinds of symbol interleave at random.
                    let fresh = tag == MATCH;
                    let index = select_unpredictable(fresh, 3, op.value());
                    let distance = select_unpredictable(fresh, op.value(), pick(reps, index));
                    if tag == REPEAT {
                        initialized(distance)?;
                    }
                    let length = select_unpredictable(tag == REPEAT_LAST, last_length, op.length());
                    let [r0, r1, r2, r3] = reps;
                    reps = [
                        distance,
                        select_unpredictable(index >= 1, r0, r1),
                        select_unpredictable(index >= 2, r1, r2),
                        select_unpredictable(index >= 3, r2, r3),
                    ];
                    last_length = length;
                    if length <= budget && output.copy_within_budget(distance, length) {
                        budget -= length;
                        continue;
                    }
                    if length != 0 {
                        output.copy_match(distance, length, sink)?;
                    }
                    budget = output.fast_budget();
                    continue;
                }
                match tag {
                    LITERALS => {
                        let (run, rest) = literals.split_at(op.value());
                        literals = rest;
                        let visible = run.len().min(output_size - output.written());
                        reached.symbols += visible;
                        for piece in run[..visible].chunks(LITERAL_POLL) {
                            poller.check_codec(output.written())?;
                            output.push_literals(piece, sink)?;
                        }
                    }
                    FILTER => {
                        reached.symbols += 1;
                        let mut filter = *block_filters.next().expect("one filter per filter op");
                        filter.start = output
                            .written()
                            .checked_add(filter.start)
                            .ok_or(Error::InvalidData("RAR 5 filter start overflows"))?;
                        output.accept_filter(filter, filters)?;
                    }
                    REPEAT_CHECK => {
                        initialized(pick(reps, op.value()))?;
                    }
                    BLOCK => {
                        reached.blocks += 1;
                        reached.symbols = 0;
                    }
                    tag => unreachable!("operation tag {tag}"),
                }
                budget = output.fast_budget();
            }
            Ok(())
        };
        let walked = walk();
        *repeats.distances = reps;
        *repeats.last_length = last_length;
        walked
    }
}

/// Where the buffered decoder writes a member: flat, with its filters kept for the end.
pub(super) struct Flat<'a, B: Budget> {
    pub(super) output: &'a mut Buffer<u8, B>,
    pub(super) filters: &'a mut Buffer<PendingFilter, B>,
    pub(super) output_size: usize,
    pub(super) dictionary_size: usize,
    pub(super) overrun: &'a mut Option<Overrun>,
}

/// Where a buffered replay stopped in its list.
#[derive(PartialEq, Eq)]
pub(super) enum Walked {
    /// Every operation applied.
    All,
    /// At the end of a block's symbols, before the next block's.
    BlockEnd,
    Within,
}

impl BlockOps {
    /// [`Self::apply`] for the buffered decoder, which owns the repeat state and history.
    pub(super) fn apply_buffered<B: Budget>(
        &self,
        state: &mut ReaderState<B>,
        flat: &mut Flat<'_, B>,
        poller: &mut Poller,
        reached: &mut Reached,
    ) -> Result<Walked> {
        let output_size = flat.output_size;
        let mut literals = self.literals.as_slice();
        let mut block_filters = self.filters.iter();
        for &op in &self.ops {
            if flat.output.len() >= output_size {
                return Ok(if op.tag() == BLOCK {
                    Walked::BlockEnd
                } else {
                    Walked::Within
                });
            }
            poller.check_codec(flat.output.len())?;
            let prefix = op.prefix();
            if prefix != 0 {
                let len = flat.output.len();
                let visible = prefix.min(output_size - len);
                reached.symbols += visible;
                match literals.first_chunk::<SHORT_MATCH>() {
                    // A fixed-width copy into spare capacity, cut back to the run.
                    Some(bytes)
                        if prefix <= SHORT_MATCH && flat.output.capacity() - len >= SHORT_MATCH =>
                    {
                        flat.output.extend_from_slice(bytes).map_err(Into::into)?;
                        flat.output.truncate(len + visible);
                    }
                    _ => flat
                        .output
                        .extend_from_slice(&literals[..visible])
                        .map_err(Into::into)?,
                }
                literals = &literals[prefix..];
                if flat.output.len() >= output_size {
                    return Ok(Walked::Within);
                }
            }
            let tag = op.tag();
            match tag {
                MATCH | REPEAT | REPEAT_LAST => {
                    reached.symbols += 1;
                    let index = if tag == MATCH { 3 } else { op.value() };
                    let distance = if tag == MATCH {
                        op.value()
                    } else {
                        pick(state.reps, index)
                    };
                    if tag == REPEAT {
                        initialized(distance)?;
                    }
                    let length = if tag == REPEAT_LAST {
                        state.last_length
                    } else {
                        op.length()
                    };
                    state.reps[..=index].rotate_right(1);
                    state.reps[0] = distance;
                    state.last_length = length;
                    if length != 0 {
                        *flat.overrun = state.copy_match(
                            flat.output,
                            distance,
                            length,
                            output_size,
                            flat.dictionary_size,
                        )?;
                    }
                }
                LITERALS => {
                    let (run, rest) = literals.split_at(op.value());
                    literals = rest;
                    let visible = run.len().min(output_size - flat.output.len());
                    reached.symbols += visible;
                    for piece in run[..visible].chunks(LITERAL_POLL) {
                        poller.check_codec(flat.output.len())?;
                        flat.output.extend_from_slice(piece).map_err(Into::into)?;
                    }
                    if visible < run.len() {
                        return Ok(Walked::Within);
                    }
                }
                FILTER => {
                    reached.symbols += 1;
                    let mut filter = *block_filters.next().expect("one filter per filter op");
                    filter.start = flat
                        .output
                        .len()
                        .checked_add(filter.start)
                        .ok_or(Error::InvalidData("RAR 5 filter start overflows"))?;
                    flat.filters.try_push(filter)?;
                }
                REPEAT_CHECK => {
                    initialized(pick(state.reps, op.value()))?;
                }
                BLOCK => {
                    reached.blocks += 1;
                    reached.symbols = 0;
                }
                tag => unreachable!("operation tag {tag}"),
            }
        }
        Ok(Walked::All)
    }
}

/// The replay's unchecked copies, which only replay can keep within a budget.
impl<B: Budget> StreamingOutput<B> {
    /// Bytes that can be written before a flush, a growth, the output limit
    /// or a zero-filled window needs the checked path, with room left past
    /// the newest byte for one fixed-width over-copy.
    #[inline]
    fn fast_budget(&self) -> usize {
        if self.all_zero {
            return 0;
        }
        let capacity = self.ring.capacity();
        let budget = (self.output_limit - self.written)
            .min((STREAM_FLUSH_THRESHOLD - 1).saturating_sub(self.pending))
            .min(capacity.saturating_sub(self.ring.end + SHORT_MATCH));
        if capacity < self.max_capacity {
            budget.min(capacity.saturating_sub(self.ring.len + SHORT_MATCH))
        } else {
            budget
        }
    }

    #[inline(always)]
    fn advance_unflushed(&mut self, count: usize) {
        self.ring.advance(count);
        self.pending += count;
        self.written += count;
    }

    /// Appends the first `count` bytes of `literals` within a [`Self::fast_budget`].
    #[inline(always)]
    fn push_literals_within_budget(&mut self, literals: &[u8], count: usize) {
        let end = self.ring.end;
        if let Some(bytes) = literals
            .first_chunk::<SHORT_MATCH>()
            .filter(|_| count <= SHORT_MATCH)
        {
            self.ring.bytes[end..end + SHORT_MATCH].copy_from_slice(bytes);
        } else {
            self.ring.bytes[end..end + count].copy_from_slice(&literals[..count]);
        }
        self.advance_unflushed(count);
    }

    /// A match within a [`Self::fast_budget`] whose source is stored and
    /// contiguous; false leaves it to [`Self::copy_match`].
    #[inline(always)]
    fn copy_within_budget(&mut self, distance: usize, length: usize) -> bool {
        let end = self.ring.end;
        if distance == 0
            || distance > end
            || distance > self.ring.len
            || distance > self.dictionary_size
        {
            return false;
        }
        let source = end - distance;
        if length <= SHORT_MATCH && distance >= length {
            let bytes: [u8; SHORT_MATCH] = self.ring.bytes[source..source + SHORT_MATCH]
                .try_into()
                .expect("fixed-width slice");
            self.ring.bytes[end..end + SHORT_MATCH].copy_from_slice(&bytes);
        } else if distance >= length {
            self.ring.bytes.copy_within(source..source + length, end);
        } else if distance >= SHORT_MATCH {
            // Each piece reads only bytes already written, so the overlap repeats.
            for offset in (0..length).step_by(SHORT_MATCH) {
                let from = source + offset;
                let bytes: [u8; SHORT_MATCH] = self.ring.bytes[from..from + SHORT_MATCH]
                    .try_into()
                    .expect("fixed-width slice");
                let to = end + offset;
                self.ring.bytes[to..to + SHORT_MATCH].copy_from_slice(&bytes);
            }
        } else {
            return false;
        }
        self.advance_unflushed(length);
        true
    }
}

/// Finds where the serial decoder stopped, which replayed operations do not record.
pub(super) fn skip_symbols<'a, B: Budget>(
    tables: &ReaderTables<B>,
    payload: &'a [u8],
    bit_pos: usize,
    count: usize,
) -> Result<BitReader<'a>> {
    let mut bits = BitReader::at(payload, bit_pos);
    for _ in 0..count {
        match tables.main.decode(&mut bits)? {
            0..=255 | 257 => {}
            256 => {
                read_filter_record(&mut bits)?;
            }
            258..=261 => drop(repeat_length(tables, &mut bits)?),
            symbol => drop(new_match(tables, &mut bits, symbol)?),
        }
    }
    Ok(bits)
}

/// Shared by decoding and skipping so both read a match's bits alike.
#[inline(always)]
fn new_match<B: Budget>(
    tables: &ReaderTables<B>,
    bits: &mut BitReader<'_>,
    symbol: usize,
) -> Result<(usize, usize)> {
    let length_slot = symbol - 262;
    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
    let length = length_from_slot_parts(length_slot, length_extra);
    let distance_slot = tables.distance.decode(bits)?;
    let distance_bit_count = distance_slot_bit_count(distance_slot)?;
    let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
        let high = bits.read_wide_bits(distance_bit_count - 4)?;
        let low = tables.align.decode(bits)? as u64;
        (high << 4) | low
    } else {
        bits.read_wide_bits(distance_bit_count)?
    };
    let distance = distance_from_slot_parts(distance_slot, distance_bit_count, distance_extra);
    Ok((length + length_bonus(distance), distance))
}

fn repeat_length<B: Budget>(tables: &ReaderTables<B>, bits: &mut BitReader<'_>) -> Result<usize> {
    let length_slot = tables.length.decode(bits)?;
    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
    Ok(length_from_slot_parts(length_slot, length_extra))
}

/// `reps[index]` for an index below four, without indexing memory.
#[inline(always)]
fn pick(reps: [usize; 4], index: usize) -> usize {
    let [r0, r1, r2, r3] = reps;
    select_unpredictable(
        index < 2,
        select_unpredictable(index == 0, r0, r1),
        select_unpredictable(index == 2, r2, r3),
    )
}

fn initialized(distance: usize) -> Result<usize> {
    if distance == 0 {
        return Err(Error::InvalidData(
            "RAR 5 repeat distance is not initialized",
        ));
    }
    Ok(distance)
}
