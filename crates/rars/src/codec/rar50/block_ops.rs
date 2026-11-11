//! A block's symbols need only its tables, so they decode ahead of the window
//! as operations; replaying them in order resolves what earlier blocks decide.
use super::{
    distance_from_slot_parts, distance_slot_bit_count, length_bonus, length_from_slot_parts,
    length_slot_extra_bits, read_filter, BitReader, Budget, DecodedChunk, Error, PendingFilter,
    ReaderTables, Result, StreamDecodeError, StreamingOutput, LITERAL_BURST,
};
use crate::read_control::Poller;

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
const VALUE_MASK: u64 = (1 << LENGTH_SHIFT) - 1;

const LITERALS: u64 = 0;
const MATCH: u64 = 1;
const REPEAT: u64 = 2;
const REPEAT_LAST: u64 = 3;
const FILTER: u64 = 4;
const REPEAT_CHECK: u64 = 5;
const BLOCK: u64 = 6;

/// Tag, a 13-bit length and a 48-bit distance, repeat index or literal count.
#[derive(Clone, Copy)]
struct Op(u64);

impl Op {
    fn new(tag: u64, length: usize, value: usize) -> Self {
        debug_assert!(length as u64 <= LENGTH_MASK);
        // A distance no window can hold only has to stay out of range.
        let value = (value as u64).min(VALUE_MASK);
        Self((tag << TAG_SHIFT) | ((length as u64) << LENGTH_SHIFT) | value)
    }

    fn tag(self) -> u64 {
        self.0 >> TAG_SHIFT
    }

    fn length(self) -> usize {
        ((self.0 >> LENGTH_SHIFT) & LENGTH_MASK) as usize
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
        match self.decode_symbols(tables, payload, bit_pos, payload_bits) {
            Ok(None) => Stop::BlockEnd,
            Ok(Some(bit_pos)) => Stop::Full(bit_pos),
            Err(error) => Stop::Failed(error),
        }
    }

    fn decode_symbols<B: Budget>(
        &mut self,
        tables: &ReaderTables<B>,
        payload: &[u8],
        bit_pos: usize,
        payload_bits: usize,
    ) -> Result<Option<usize>> {
        let mut bits = BitReader::at(payload, bit_pos);
        while bits.position() < payload_bits {
            if self.ops.len() >= MAX_OPS || self.literals.len() >= MAX_LITERALS {
                return Ok(Some(bits.position()));
            }
            let symbol = tables.main.decode(&mut bits)?;
            match symbol {
                0..=255 => {
                    let start = self.literals.len();
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
                    self.ops
                        .push(Op::new(LITERALS, 0, self.literals.len() - start));
                }
                256 => {
                    self.filters.push(read_filter(&mut bits, 0)?);
                    self.ops.push(Op::new(FILTER, 0, 0));
                }
                257 => self.ops.push(Op::new(REPEAT_LAST, 0, 0)),
                258..=261 => {
                    let index = symbol - 258;
                    match repeat_length(tables, &mut bits) {
                        Ok(length) => self.ops.push(Op::new(REPEAT, length, index)),
                        Err(error) => {
                            // An unset repeat distance is reported before the length is read.
                            self.ops.push(Op::new(REPEAT_CHECK, 0, index));
                            return Err(error);
                        }
                    }
                }
                _ => {
                    let length_slot = symbol - 262;
                    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
                    let length = length_from_slot_parts(length_slot, length_extra);
                    let distance_slot = tables.distance.decode(&mut bits)?;
                    let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                    let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                        let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                        let low = tables.align.decode(&mut bits)? as u32;
                        (high << 4) | low
                    } else {
                        bits.read_bits(distance_bit_count as u8)?
                    };
                    let distance =
                        distance_from_slot_parts(distance_slot, distance_bit_count, distance_extra);
                    self.ops
                        .push(Op::new(MATCH, length + length_bonus(distance), distance));
                }
            }
        }
        Ok(None)
    }

    /// Replays the list up to where the serial decoder would stop, counting blocks reached.
    pub(super) fn apply<B: Budget, E>(
        &self,
        repeats: &mut Repeats<'_>,
        output: &mut StreamingOutput<B>,
        poller: &mut Poller,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
        filters: &mut Option<&mut dyn FnMut(PendingFilter) -> std::result::Result<(), E>>,
        blocks_begun: &mut usize,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let output_size = output.output_limit;
        let Repeats {
            distances: reps,
            last_length,
        } = repeats;
        let mut literals = self.literals.as_slice();
        let mut block_filters = self.filters.iter();
        for &op in &self.ops {
            if output.written() >= output_size {
                break;
            }
            poller.check_codec(output.written())?;
            match op.tag() {
                LITERALS => {
                    let (run, rest) = literals.split_at(op.value());
                    literals = rest;
                    let visible = run.len().min(output_size - output.written());
                    for piece in run[..visible].chunks(LITERAL_POLL) {
                        poller.check_codec(output.written())?;
                        output.push_literals(piece, sink)?;
                    }
                }
                MATCH => {
                    let (distance, length) = (op.value(), op.length());
                    reps.rotate_right(1);
                    reps[0] = distance;
                    **last_length = length;
                    output.copy_match(distance, length, sink)?;
                }
                REPEAT => {
                    let (index, length) = (op.value(), op.length());
                    let distance = initialized(reps[index])?;
                    reps[..=index].rotate_right(1);
                    reps[0] = distance;
                    **last_length = length;
                    output.copy_match(distance, length, sink)?;
                }
                REPEAT_LAST => {
                    if **last_length != 0 {
                        output.copy_match(reps[0], **last_length, sink)?;
                    }
                }
                FILTER => {
                    let mut filter = *block_filters.next().expect("one filter per filter op");
                    filter.start = output
                        .written()
                        .checked_add(filter.start)
                        .ok_or(Error::InvalidData("RAR 5 filter start overflows"))?;
                    output.accept_filter(filter, filters)?;
                }
                REPEAT_CHECK => {
                    initialized(reps[op.value()])?;
                }
                BLOCK => *blocks_begun += 1,
                tag => unreachable!("operation tag {tag}"),
            }
        }
        Ok(())
    }
}

fn repeat_length<B: Budget>(tables: &ReaderTables<B>, bits: &mut BitReader<'_>) -> Result<usize> {
    let length_slot = tables.length.decode(bits)?;
    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot))?;
    Ok(length_from_slot_parts(length_slot, length_extra))
}

fn initialized(distance: usize) -> Result<usize> {
    if distance == 0 {
        return Err(Error::InvalidData(
            "RAR 5 repeat distance is not initialized",
        ));
    }
    Ok(distance)
}
