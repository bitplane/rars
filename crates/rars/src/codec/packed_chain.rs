//! A bounded job's exact hash chains, stored as reverse-readable delta streams.
//! Construction sees the captured input twice. Insertion only publishes the
//! already-built prefix of one bucket; future positions remain unreachable.

use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};

const HASH_BITS: u32 = 17;
const BUCKETS: usize = 1 << HASH_BITS;
const NO_LINK: u32 = u32::MAX;

#[inline]
fn hash(input: &[u8], pos: usize) -> usize {
    let value = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
    (value.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

#[inline]
fn encoded_length(delta: u32) -> usize {
    match delta {
        0..=32_767 => 2,
        32_768..=1_073_741_823 => 4,
        _ => 6,
    }
}

fn encode(output: &mut [u8], delta: u32) {
    let last = output.len() / 2 - 1;
    for (index, bytes) in output.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let mut unit = ((delta >> (index * 15)) & 0x7FFF) as u16;
        if index != last {
            unit |= 0x8000;
        }
        bytes.copy_from_slice(&unit.to_le_bytes());
    }
}

#[inline]
fn decode_before(input: &[u8], end: usize) -> (u32, usize) {
    debug_assert_eq!(end & 1, 0);
    debug_assert_eq!(
        u16::from_le_bytes(input[end - 2..end].try_into().unwrap()) & 0x8000,
        0
    );
    if end < 4 {
        return decode_before_scalar(input, end);
    }
    let word = u32::from_le_bytes(input[end - 4..end].try_into().unwrap());
    let length = if word & 0x8000 == 0 { 2 } else { 4 };
    if length == 4
        && end >= 6
        && u16::from_le_bytes(input[end - 6..end - 4].try_into().unwrap()) & 0x8000 != 0
    {
        return decode_before_scalar(input, end);
    }
    let shifted = word >> ((4 - length) * 8);
    ((shifted & 0x7FFF) | ((shifted >> 1) & 0x3FFF_8000), length)
}

#[inline]
fn decode_before_scalar(input: &[u8], end: usize) -> (u32, usize) {
    debug_assert_eq!(end & 1, 0);
    let mut start = end - 2;
    let mut delta = u32::from(u16::from_le_bytes(input[start..end].try_into().unwrap()));
    debug_assert_eq!(delta & 0x8000, 0);
    while start >= 2 {
        let previous = u16::from_le_bytes(input[start - 2..start].try_into().unwrap());
        if previous & 0x8000 == 0 {
            break;
        }
        start -= 2;
        delta = (delta << 15) | u32::from(previous & 0x7FFF);
    }
    (delta, end - start)
}

/// What a candidate must hold to beat the best length so far.
struct Probe {
    /// Where the four bytes compared start, from the candidate.
    offset: usize,
    /// The position's own bytes there.
    wanted: u32,
    /// Which of them count.
    mask: u32,
}

impl Probe {
    #[inline(always)]
    fn new(input: &[u8], pos: usize, longest: usize) -> Self {
        let offset = longest.saturating_sub(3);
        let counted = (longest + 1).min(4) as u32;
        Self {
            offset,
            wanted: u32::from_le_bytes(input[pos + offset..pos + offset + 4].try_into().unwrap()),
            mask: u32::MAX >> (32 - 8 * counted),
        }
    }
}

/// Input up to this long has no delta of 2^30 or more, so every record is one
/// unit or two.
const PAIRED_INPUT_LIMIT: usize = 1 << 30;
/// Units decoded at a time once a walk is past its first candidates: one
/// cache line of the stream.
const UNITS: usize = 32;
/// The first stretch is short: a walk that ends at its first candidate, as it
/// does across a long repeat, has decoded little it did not need.
const FIRST_UNITS: usize = 4;

/// The top bit of each unit in an eight-byte word. A unit that carries it is
/// the first of a two-unit record.
const TOPS: u64 = 0x8000_8000_8000_8000;
/// The top bits of a word of two-unit records that starts with a record's
/// first unit.
const JOINED_FROM_FIRST: u64 = 0x0000_8000_0000_8000;
/// The same for a word that starts with a record's last unit.
const JOINED_FROM_LAST: u64 = 0x8000_0000_8000_0000;

/// Which units of a stretch of whole eight-byte words carry the top bit.
struct Stretch {
    /// The top bits set in any word.
    any: u64,
    /// The top bits set in every word.
    all: u64,
}

impl Stretch {
    /// Whether every word's top bits are exactly `tops`.
    #[inline(always)]
    fn is(&self, tops: u64) -> bool {
        self.any == tops && self.all == tops
    }
}

#[inline(always)]
fn survey(bytes: &[u8]) -> Stretch {
    let mut any = 0;
    let mut all = TOPS;
    for word in bytes.as_chunks::<8>().0 {
        let word = u64::from_le_bytes(*word);
        any |= word;
        all &= word;
    }
    Stretch {
        any: any & TOPS,
        all,
    }
}

/// The deltas of `bytes`, all two-unit records, newest first.
#[inline(always)]
fn join_all(deltas: &mut [u32], bytes: &[u8]) {
    for (delta, record) in deltas.iter_mut().zip(bytes.rchunks_exact(4)) {
        let record = u32::from_le_bytes(record.try_into().unwrap());
        *delta = (record & 0x7FFF) | (record >> 16 << 15);
    }
}

/// The deltas of a stretch that mixes both record widths, and how many.
/// Every unit is read as if it ended a record, and kept only if it does.
/// `newer` is the unit after `older`, and the newest not yet decoded.
#[inline(always)]
fn decode_mixed(deltas: &mut [u32; UNITS], older: &[u8], mut newer: u32) -> usize {
    let mut records = 0;
    for bytes in older.rchunks_exact(2) {
        let unit = u32::from(u16::from_le_bytes(bytes.try_into().unwrap()));
        deltas[records % UNITS] = if unit & 0x8000 != 0 {
            (newer << 15) | (unit & 0x7FFF)
        } else {
            newer
        };
        records += usize::from(newer & 0x8000 == 0);
        newer = unit;
    }
    records
}

/// One position's walk over a stream whose records are one unit or two.
///
/// It stands apart from its caller so the loops keep their state in
/// registers: inlined into the block loop, they spill on every candidate.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn walk_paired<B: Budget>(
    packed: &[u8],
    input: &[u8],
    pos: usize,
    mut cursor: usize,
    limit: usize,
    max_length: usize,
    max_distance: usize,
    cut: usize,
    out: &mut Buffer<(u32, u32), B>,
) -> std::result::Result<(), B::Failure> {
    let prefix = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
    // The oldest position still within reach.
    let floor = pos.saturating_sub(max_distance);
    let mut candidate = pos;
    let mut longest = 0;
    let mut remaining = cut;
    if remaining == 0 || limit == 0 {
        return Ok(());
    }
    // An improving match shares every byte up to and including the one at the
    // best length so far. The test is on the last four of those, or on all of
    // them while there are fewer: one comparison, and far fewer candidates
    // reach the full measurement than a single byte lets through.
    let mut probe = Probe::new(input, pos, 0);
    let mut deltas = [0; UNITS];
    let mut units = FIRST_UNITS;
    'walk: loop {
        // A stretch of the stream is decoded before any of its candidates is
        // tested. Where a stretch starts and stops does not depend on what is
        // in it, so decoding one is not kept waiting on the lengths in the
        // one before, and the tests run one after another with nothing
        // between them.
        let records = if cursor >= 2 * units + 2 {
            let stretch = &packed[cursor - 2 * units - 2..cursor];
            let (older, newest) = stretch.split_at(2 * units);
            let newer = u32::from(u16::from_le_bytes(newest.try_into().unwrap()));
            let whole = newer & 0x8000 == 0;
            let held = survey(older);
            cursor -= 2 * units;
            if units != UNITS {
                // The first stretch is too short to be worth telling apart.
                decode_mixed(&mut deltas, older, newer)
            } else if held.is(0) && whole {
                // Every record here is a single unit, as they are wherever a
                // bucket is busy, and the units are the deltas as they stand.
                for (delta, bytes) in deltas.iter_mut().zip(stretch[2..].rchunks_exact(2)) {
                    *delta = u32::from(u16::from_le_bytes(bytes.try_into().unwrap()));
                }
                UNITS
            } else if held.is(JOINED_FROM_LAST) {
                // Every record is two units, as they are wherever a bucket
                // is quiet. The newest unit ends the record the one before it
                // starts, and the oldest surveyed is left for the next
                // stretch.
                join_all(&mut deltas[..UNITS / 2], &stretch[2..]);
                UNITS / 2
            } else if held.is(JOINED_FROM_FIRST) && !whole {
                // The same, where the last stretch stopped between the newest
                // record's two units.
                join_all(&mut deltas[..UNITS / 2], older);
                UNITS / 2
            } else {
                decode_mixed(&mut deltas, older, newer)
            }
        } else {
            // Too near the start of the stream for a stretch. The last
            // stretch may have stopped between a record's two units.
            if cursor >= 2 && packed[cursor - 1] & 0x80 != 0 {
                cursor -= 2;
            }
            if cursor < 2 {
                break;
            }
            let (delta, length) = decode_before(packed, cursor);
            cursor -= length;
            deltas[0] = delta;
            1
        };
        units = UNITS;
        let records = records.min(remaining);
        for &delta in &deltas[..records] {
            let delta = delta as usize;
            // A bucket's first record is zero, and nothing past it is this
            // bucket's.
            if delta.wrapping_sub(1) >= candidate - floor {
                break 'walk;
            }
            candidate -= delta;
            let found = u32::from_le_bytes(
                input[candidate + probe.offset..candidate + probe.offset + 4]
                    .try_into()
                    .unwrap(),
            );
            if (found ^ probe.wanted) & probe.mask == 0 {
                let difference = prefix
                    ^ u32::from_le_bytes(input[candidate..candidate + 4].try_into().unwrap());
                let distance = pos - candidate;
                let length = if difference != 0 {
                    (difference.trailing_zeros() / 8) as usize
                } else {
                    4 + super::fast::match_length(input, pos + 4, distance, max_length - 4)
                };
                if length > longest {
                    if length >= 4 {
                        out.push((length as u32, distance as u32))?;
                    }
                    longest = length;
                    if longest >= limit {
                        break 'walk;
                    }
                    probe = Probe::new(input, pos, longest);
                }
            }
        }
        remaining -= records;
        if remaining == 0 {
            break;
        }
    }
    Ok(())
}

/// The packed chains a finder walks: built for it alone, or shared.
#[derive(Debug)]
enum Stream<B: Budget> {
    Own(Buffer<u8, B>),
    Shared(std::sync::Arc<SharedPackedIndex<B>>),
}

impl<B: Budget> std::ops::Deref for Stream<B> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Own(packed) => packed,
            Self::Shared(index) => &index.packed,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PackedMatchFinder<B: Budget = Allowance> {
    cursor: Buffer<u32, B>,
    packed: Stream<B>,
    next_position: usize,
}

/// Calls `visit` with each position in `positions` whose `owner` is `part`,
/// in order. Most positions belong to other parts, so they are compared 64 at
/// a time into a mask, which compiles to vector compares, and only the set
/// bits are visited.
fn each_owned(
    owner: &[u8],
    positions: std::ops::Range<usize>,
    part: u8,
    mut visit: impl FnMut(usize),
) {
    let from = positions.start;
    for (index, block) in owner[positions].chunks(64).enumerate() {
        let mut mask = block.iter().enumerate().fold(0u64, |mask, (bit, &of)| {
            mask | (u64::from(of == part) << bit)
        });
        while mask != 0 {
            visit(from + index * 64 + mask.trailing_zeros() as usize);
            mask &= mask - 1;
        }
    }
}

/// One set of packed chains over a window several finders search, each from
/// its own position. A bucket's chain here holds every position a finder
/// built over a later, shorter window would hold, newest first, plus older
/// ones; a walk stops on its distance floor at the first of those, where the
/// shorter window's chain would have ended. So a finder handed out at a
/// position collects what one built over its own window would, provided its
/// input ends where that window does and its distances are measured the same
/// way (see `rar50` encoder's block jobs).
#[derive(Debug)]
pub(crate) struct SharedPackedIndex<B: Budget = Allowance> {
    packed: Buffer<u8, B>,
}

impl<B: Budget> SharedPackedIndex<B> {
    /// Builds the index over `window` and hands out finders standing at each
    /// of `positions`, ascending, as if every position before it had been
    /// inserted.
    ///
    /// Building is split by bucket range across the pool: every part walks
    /// the whole window and writes only its own buckets' records, which lie
    /// together in the stream. A bucket's records depend only on its own
    /// positions in order, so the stream is the one a single pass writes. The
    /// write cursors just before a position are where insertion would have
    /// left each bucket, so each part copies its range of them into every
    /// finder it passes.
    ///
    /// Each position is hashed once, up front and in parallel, into the
    /// number of the part that owns its bucket. A part then passes over
    /// other parts' positions with a byte comparison; hashing them in every
    /// part made the build cost the window once per thread, which at 32
    /// threads lost more than sharing saved.
    ///
    /// A finder chooses its walk by the length of the input it is given, which
    /// for a shared index is shorter than the window the stream was built
    /// over. So the window must stay where every record is one unit or two.
    pub(crate) fn finders_over(
        window: &[u8],
        positions: &[usize],
        allowance: &B,
    ) -> Result<Buffer<PackedMatchFinder<B>, B>> {
        if window.len() > PAIRED_INPUT_LIMIT {
            return Err(Error::InvalidData(
                "shared packed window exceeds the paired walk's reach",
            ));
        }
        debug_assert!(positions.windows(2).all(|pair| pair[0] <= pair[1]));
        let insertable = window.len().saturating_sub(3);
        let targets = Buffer::collect(
            positions.iter().map(|&position| position.min(insertable)),
            allowance,
        )?;
        let span = BUCKETS.div_ceil(crate::parallel::threads().clamp(1, 64));
        let ranges = || {
            (0..BUCKETS)
                .step_by(span)
                .map(move |start| start..(start + span).min(BUCKETS))
        };
        const STRIPE: usize = 1 << 20;
        let mut owner = Buffer::filled(insertable, 0u8, allowance)?;
        let mut stripes: Vec<(usize, &mut [u8])> = owner
            .chunks_mut(STRIPE)
            .enumerate()
            .map(|(index, stripe)| (index * STRIPE, stripe))
            .collect();
        crate::parallel::for_each_mut(&mut stripes, |_, (from, stripe)| {
            for (pos, part) in (*from..).zip(stripe.iter_mut()) {
                *part = (hash(window, pos) / span) as u8;
            }
        });
        drop(stripes);
        let owner = &owner[..];
        let delta_at = |head: &mut [u32], index: usize, pos: usize| {
            let previous = std::mem::replace(&mut head[index], pos as u32);
            if previous == NO_LINK {
                0
            } else {
                pos as u32 - previous
            }
        };

        // Each bucket's stream length, a part of the buckets at a time.
        struct Count<B: Budget> {
            buckets: std::ops::Range<usize>,
            lengths: Buffer<u32, B>,
            head: Buffer<u32, B>,
            overflowed: bool,
        }
        let mut counts = Vec::new();
        for buckets in ranges() {
            counts.push(Count {
                lengths: Buffer::filled(buckets.len(), 0u32, allowance)?,
                head: Buffer::filled(buckets.len(), NO_LINK, allowance)?,
                buckets,
                overflowed: false,
            });
        }
        crate::parallel::for_each_mut(&mut counts, |_, count| {
            let part = (count.buckets.start / span) as u8;
            each_owned(owner, 0..insertable, part, |pos| {
                let index = hash(window, pos) - count.buckets.start;
                let length = encoded_length(delta_at(&mut count.head, index, pos)) as u32;
                match count.lengths[index].checked_add(length) {
                    Some(total) => count.lengths[index] = total,
                    None => count.overflowed = true,
                }
            });
        });
        if counts.iter().any(|count| count.overflowed) {
            return Err(Error::InvalidData(
                "packed finder bucket exceeds u32 offsets",
            ));
        }
        let mut starts = Buffer::filled(BUCKETS + 1, 0u32, allowance)?;
        let mut total = 0u32;
        for count in &counts {
            for (index, &length) in count.lengths.iter().enumerate() {
                starts[count.buckets.start + index] = total;
                total = total.checked_add(length).ok_or(Error::InvalidData(
                    "packed finder storage exceeds u32 offsets",
                ))?;
            }
        }
        starts[BUCKETS] = total;
        drop(counts);

        // The records, and each finder's cursors, a part of the buckets at a
        // time. A part owns its buckets' stretch of the stream and of every
        // finder's cursor array.
        let mut packed = Buffer::filled(total as usize, 0u8, allowance)?;
        let mut cursors = Vec::with_capacity(targets.len());
        for _ in 0..targets.len() {
            cursors.push(Buffer::filled(BUCKETS, 0u32, allowance)?);
        }
        struct Fill<'a, B: Budget> {
            buckets: std::ops::Range<usize>,
            base: usize,
            packed: &'a mut [u8],
            cursors: Vec<&'a mut [u32]>,
            write: Buffer<u32, B>,
            head: Buffer<u32, B>,
        }
        let mut fills = Vec::new();
        let mut rest: &mut [u8] = &mut packed;
        let mut chunks: Vec<std::slice::ChunksMut<'_, u32>> = cursors
            .iter_mut()
            .map(|cursor| cursor.chunks_mut(span))
            .collect();
        for buckets in ranges() {
            let base = starts[buckets.start] as usize;
            let (mine, after) = rest.split_at_mut(starts[buckets.end] as usize - base);
            rest = after;
            fills.push(Fill {
                write: Buffer::copied(&starts[buckets.clone()], allowance)?,
                head: Buffer::filled(buckets.len(), NO_LINK, allowance)?,
                cursors: chunks
                    .iter_mut()
                    .map(|chunk| chunk.next().expect("one chunk per part"))
                    .collect(),
                buckets,
                base,
                packed: mine,
            });
        }
        drop(chunks);
        crate::parallel::for_each_mut(&mut fills, |_, fill| {
            let part = (fill.buckets.start / span) as u8;
            let insert = |fill: &mut Fill<'_, B>, positions: std::ops::Range<usize>| {
                each_owned(owner, positions, part, |pos| {
                    let index = hash(window, pos) - fill.buckets.start;
                    let delta = delta_at(&mut fill.head, index, pos);
                    let length = encoded_length(delta);
                    let start = fill.write[index] as usize - fill.base;
                    encode(&mut fill.packed[start..start + length], delta);
                    fill.write[index] += length as u32;
                });
            };
            let mut from = 0;
            for (next, &target) in targets.iter().enumerate() {
                insert(fill, from..target);
                fill.cursors[next].copy_from_slice(&fill.write);
                from = target;
            }
            insert(fill, from..insertable);
        });
        drop(fills);

        let index = std::sync::Arc::new(Self { packed });
        let mut finders = Buffer::with_capacity(targets.len(), allowance)?;
        for (cursor, &target) in cursors.into_iter().zip(targets.iter()) {
            finders.push_admitted(PackedMatchFinder {
                cursor,
                packed: Stream::Shared(std::sync::Arc::clone(&index)),
                next_position: target,
            });
        }
        Ok(finders)
    }
}

/// The end of the record that starts at `end`.
#[inline]
fn past_record(packed: &[u8], mut end: usize) -> usize {
    loop {
        let unit = u16::from_le_bytes(packed[end..end + 2].try_into().unwrap());
        end += 2;
        if unit & 0x8000 == 0 {
            return end;
        }
    }
}

/// Every position's delta to the one before it in its bucket, bucket after
/// bucket, and where each bucket starts.
fn build<B: Budget>(input: &[u8], allowance: &B) -> Result<(Buffer<u8, B>, Buffer<u32, B>)> {
    u32::try_from(input.len())
        .map_err(|_| Error::InvalidData("packed finder input exceeds u32 positions"))?;
    let mut head = Buffer::filled(BUCKETS, NO_LINK, allowance)?;
    let mut cursor = Buffer::filled(BUCKETS, 0u32, allowance)?;
    let positions = input.len().saturating_sub(3);
    for pos in 0..positions {
        let bucket = hash(input, pos);
        let previous = head[bucket];
        let delta = if previous == NO_LINK {
            0
        } else {
            pos as u32 - previous
        };
        cursor[bucket] = cursor[bucket]
            .checked_add(encoded_length(delta) as u32)
            .ok_or(Error::InvalidData(
                "packed finder bucket exceeds u32 offsets",
            ))?;
        head[bucket] = pos as u32;
    }
    let mut total = 0u32;
    for count in cursor.iter_mut() {
        let length = *count;
        *count = total;
        total = total.checked_add(length).ok_or(Error::InvalidData(
            "packed finder storage exceeds u32 offsets",
        ))?;
    }
    let mut packed = Buffer::filled(total as usize, 0u8, allowance)?;
    head.fill(NO_LINK);
    for pos in 0..positions {
        let bucket = hash(input, pos);
        let previous = head[bucket];
        let delta = if previous == NO_LINK {
            0
        } else {
            pos as u32 - previous
        };
        let length = encoded_length(delta);
        let start = cursor[bucket] as usize;
        encode(&mut packed[start..start + length], delta);
        cursor[bucket] += length as u32;
        head[bucket] = pos as u32;
    }
    // Each final bucket end is the next bucket's initial start, including
    // empty buckets. Recover those starts without another input scan.
    for bucket in (1..BUCKETS).rev() {
        cursor[bucket] = cursor[bucket - 1];
    }
    cursor[0] = 0;
    // Head positions were needed only to construct exact deltas. Runtime
    // insertion finds the next record boundary directly in its stream.
    drop(head);
    Ok((packed, cursor))
}

impl<B: Budget> PackedMatchFinder<B> {
    pub(crate) fn with_allowance(input: &[u8], allowance: &B) -> Result<Self> {
        let (packed, cursor) = build(input, allowance)?;
        Ok(Self {
            cursor,
            packed: Stream::Own(packed),
            next_position: 0,
        })
    }

    /// The next position this finder will insert.
    pub(crate) fn position(&self) -> usize {
        self.next_position
    }

    pub(crate) fn allowance(&self) -> B {
        match &self.packed {
            Stream::Own(packed) => packed.allowance(),
            Stream::Shared(index) => index.packed.allowance(),
        }
    }

    /// Only dense, increasing positions from this same captured input are
    /// supported. The returned cursor ends at this position's own delta.
    #[inline]
    pub(crate) fn insert(&mut self, input: &[u8], pos: usize) -> usize {
        debug_assert_eq!(pos, self.next_position);
        debug_assert!(pos + 4 <= input.len());
        let bucket = hash(input, pos);
        let end = past_record(&self.packed, self.cursor[bucket] as usize);
        self.cursor[bucket] = end as u32;
        self.next_position = pos + 1;
        self.cursor[bucket] as usize
    }

    /// Replay the ordinary chain's nearest-first budget, including collisions
    /// and sub-four-byte probe state. Store only parser-usable runs. No
    /// allocation occurs except when the caller's output needs capacity.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn collect_improving(
        &self,
        input: &[u8],
        pos: usize,
        end_cursor: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
        nice: usize,
        out: &mut Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        debug_assert!(max_length >= 4 && pos + max_length <= input.len());
        debug_assert_eq!(self.next_position, pos + 1);
        if input.len() > PAIRED_INPUT_LIMIT {
            return self.collect_improving_wide(
                input,
                pos,
                end_cursor,
                max_length,
                max_distance,
                cut,
                nice,
                out,
            );
        }
        walk_paired(
            &self.packed,
            input,
            pos,
            end_cursor,
            max_length.min(nice),
            max_length,
            max_distance,
            cut,
            out,
        )
    }

    /// The walk for input long enough to hold a three-unit record, which the
    /// paired decode does not read.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn collect_improving_wide(
        &self,
        input: &[u8],
        pos: usize,
        end_cursor: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
        nice: usize,
        out: &mut Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        let prefix = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        let mut candidate = pos;
        let mut cursor = end_cursor;
        let mut longest = 0;
        let mut checked = 0;
        while checked < cut && longest < max_length && longest < nice {
            let (delta, length) = decode_before(&self.packed, cursor);
            cursor -= length;
            if delta == 0 {
                break;
            }
            candidate -= delta as usize;
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            // Any improving match shares the byte at the previous best
            // length, including sub-four-byte collision state.
            if input[candidate + longest] != input[pos + longest] {
                continue;
            }
            let difference =
                prefix ^ u32::from_le_bytes(input[candidate..candidate + 4].try_into().unwrap());
            let length = if difference != 0 {
                (difference.trailing_zeros() / 8) as usize
            } else {
                4 + super::fast::match_length(input, pos + 4, distance, max_length - 4)
            };
            if length > longest {
                if length >= 4 {
                    out.push((length as u32, distance as u32))?;
                }
                longest = length;
            }
        }
        Ok(())
    }

    /// Keep the complete packed-chain walk outside parser/pricing frames. The
    /// caller preallocates one start per block position plus the terminal start.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn collect_block(
        &mut self,
        input: &[u8],
        block: std::ops::Range<usize>,
        distance_limit: usize,
        cut: usize,
        nice: usize,
        max_match_length: usize,
        runs: &mut Buffer<(u32, u32), B>,
        starts: &mut Buffer<u32, B>,
    ) -> std::result::Result<(), B::Failure> {
        debug_assert!(block.start <= block.end && block.end <= input.len());
        let mut committed_through = block.start;
        for pos in block.clone() {
            starts.push_admitted(runs.len() as u32);
            // Dense insertion includes NICE interiors and nonfinal block tails
            // that are too short to search but still have a full input prefix.
            if input.len() - pos < 4 {
                continue;
            }
            let cursor = self.insert(input, pos);
            let remaining = block.end - pos;
            let max_length = remaining.min(max_match_length);
            let max_distance = pos.min(distance_limit);
            let before = runs.len();
            if pos >= committed_through && cut != 0 && max_distance != 0 && max_length >= 4 {
                self.collect_improving(
                    input,
                    pos,
                    cursor,
                    max_length,
                    max_distance,
                    cut,
                    nice,
                    runs,
                )?;
            }
            if let Some(&(length, _)) = runs[before..].last() {
                let reach = (length as usize).min(remaining).min(max_match_length);
                if reach >= nice {
                    committed_through = pos + reach;
                }
            }
        }
        starts.push_admitted(runs.len() as u32);
        if block.end == input.len() {
            // This captured index has no future readable position. Retire it
            // before the caller allocates the final block's pricing workspace.
            // A shared index stays with its other finders.
            let allowance = self.allowance();
            self.packed = Stream::Own(Buffer::new(&allowance));
            self.cursor = Buffer::new(&allowance);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::match_finder::{MatchFinder, NO_POSITION};
    use crate::codec::workspace::RefusingBudget;

    #[test]
    fn reverse_delta_codes_cover_all_width_boundaries() {
        let values = [0, 1, 32_767, 32_768, 1_073_741_823, 1_073_741_824, u32::MAX];
        let mut bytes = Vec::new();
        for &value in &values {
            let start = bytes.len();
            bytes.resize(start + encoded_length(value), 0);
            encode(&mut bytes[start..], value);
        }
        let mut end = bytes.len();
        for &value in values.iter().rev() {
            let (actual, length) = decode_before(&bytes, end);
            assert_eq!(actual, value);
            assert_eq!(length, encoded_length(value));
            end -= length;
        }
        assert_eq!(end, 0);
    }

    #[test]
    fn broadword_decode_matches_scalar_on_mixed_records_and_bucket_sentinels() {
        let mut bytes = Vec::new();
        for value in 0..=u16::MAX as u32 {
            if value % 257 == 0 {
                // A new bucket starts with a zero sentinel, including at
                // global offset zero; empty buckets add no physical bytes.
                let start = bytes.len();
                let length = encoded_length(0);
                bytes.resize(start + length, 0);
                encode(&mut bytes[start..], 0);
                assert_eq!(decode_before(&bytes, bytes.len()), (0, length));
            }
            for delta in [value, value << 14, u32::MAX - value] {
                let start = bytes.len();
                let length = encoded_length(delta);
                bytes.resize(start + length, 0);
                encode(&mut bytes[start..], delta);
                let end = bytes.len();
                assert_eq!(decode_before(&bytes, end), (delta, length));
                assert_eq!(
                    decode_before(&bytes, end),
                    decode_before_scalar(&bytes, end)
                );
            }
        }
    }

    #[test]
    fn survey_tells_single_units_and_both_orders_of_joined_units_apart() {
        let plain = [0x34u8, 0x12].repeat(32);
        assert!(survey(&plain).is(0));
        for unit in 0..32 {
            let mut bytes = plain.clone();
            bytes[2 * unit + 1] |= 0x80;
            let held = survey(&bytes);
            assert!(!held.is(0), "joined unit{unit}");
            assert!(!held.is(JOINED_FROM_FIRST) && !held.is(JOINED_FROM_LAST));
        }

        // Two-unit records throughout, from a record's first unit and from
        // its last, and neither once a single unit is out of step.
        let from_first = [0x34u8, 0x92, 0x56, 0x00].repeat(16);
        let from_last = [0x56u8, 0x00, 0x34, 0x92].repeat(16);
        assert!(survey(&from_first).is(JOINED_FROM_FIRST));
        assert!(!survey(&from_first).is(JOINED_FROM_LAST));
        assert!(survey(&from_last).is(JOINED_FROM_LAST));
        assert!(!survey(&from_last).is(JOINED_FROM_FIRST));
        for unit in 0..32 {
            for bytes in [&from_first, &from_last] {
                let mut bytes = bytes.clone();
                bytes[2 * unit + 1] ^= 0x80;
                let held = survey(&bytes);
                assert!(!held.is(JOINED_FROM_FIRST) && !held.is(JOINED_FROM_LAST));
                assert!(!held.is(0));
            }
        }
        let mut deltas = [0; 16];
        join_all(&mut deltas, &from_first);
        assert_eq!(deltas, [(0x56 << 15) | 0x1234; 16]);
    }

    /// Chains long enough for most of the ways the paired walk reads a
    /// stream: stretches of single units, stretches that mix both record
    /// widths, records split across two stretches, and buckets at the very
    /// start of the stream.
    fn long_chain_fixture() -> Vec<u8> {
        let mut input = fixture(420_000);
        // A busy bucket whose deltas all fit one unit.
        for pos in (50_000..input.len() - 64).step_by(61) {
            input[pos..pos + 12].copy_from_slice(b"busy-bucket!");
        }
        // One whose deltas straddle the one-unit limit, in no fixed order.
        let mut pos = 1_000;
        let mut state = 0x1234_5678u32;
        while pos + 64 < input.len() {
            input[pos..pos + 14].copy_from_slice(b"edge-of-a-unit");
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pos += if state >> 31 == 0 { 2_000 } else { 33_000 } + (state >> 20) as usize % 700;
        }
        // One that is busy in bursts with a long gap between them, so that
        // a two-unit record split across two stretches is followed by a
        // stretch of single units.
        let mut pos = 3_000;
        while pos + 64 < input.len() {
            for _ in 0..45 {
                if pos + 64 >= input.len() {
                    break;
                }
                input[pos..pos + 12].copy_from_slice(b"burst-bucket");
                pos += 300;
            }
            pos += 34_000;
        }
        input
    }

    /// Check the paired walk against the record-at-a-time walk at every
    /// position `sampled` picks, given the position and where its stream
    /// ends. Returns how many walks were compared.
    fn compare_walks(input: &[u8], sampled: impl Fn(usize, usize) -> bool) -> usize {
        let allowance = Allowance::default();
        let mut finder = PackedMatchFinder::with_allowance(input, &allowance).unwrap();
        let mut compared = 0;
        for pos in 0..input.len() - 3 {
            let end = finder.insert(input, pos);
            if !sampled(pos, end) {
                continue;
            }
            for (cut, cap, nice, window) in [
                (1, 512, 512, usize::MAX),
                (3, 512, 512, usize::MAX),
                (128, 512, 512, usize::MAX),
                (128, 40, 16, usize::MAX),
                (128, 512, 512, 100_000),
                (300, 512, 512, usize::MAX),
                (5_000, 4_096, 4_096, usize::MAX),
            ] {
                let max_length = cap.min(input.len() - pos);
                if max_length < 4 {
                    continue;
                }
                let max_distance = pos.min(window);
                let mut expected = Buffer::new(&allowance);
                let mut actual = Buffer::new(&allowance);
                finder
                    .collect_improving_wide(
                        input,
                        pos,
                        end,
                        max_length,
                        max_distance,
                        cut,
                        nice,
                        &mut expected,
                    )
                    .unwrap();
                finder
                    .collect_improving(
                        input,
                        pos,
                        end,
                        max_length,
                        max_distance,
                        cut,
                        nice,
                        &mut actual,
                    )
                    .unwrap();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "pos{pos} cut{cut} cap{cap} nice{nice} window{window}"
                );
                compared += 1;
            }
        }
        compared
    }

    #[test]
    fn paired_walk_matches_the_record_at_a_time_walk_on_long_chains() {
        let input = long_chain_fixture();
        let finder = PackedMatchFinder::with_allowance(&input, &Allowance::default()).unwrap();
        let mut widths = [0usize; 2];
        let mut end = finder.packed.len();
        while end > 0 {
            let (_, length) = decode_before(&finder.packed, end);
            widths[length / 2 - 1] += 1;
            end -= length;
        }
        assert!(widths[0] > 1_000 && widths[1] > 1_000, "{widths:?}");
        // Every position near the stream's start, where a stretch does not
        // fit, and a sample of the rest.
        let compared = compare_walks(&input, |pos, end| end <= 4 * UNITS || pos % 5 == 0);
        assert!(compared > 500_000, "{compared}");
    }

    #[test]
    fn paired_walk_matches_the_record_at_a_time_walk_on_quiet_buckets() {
        // Buckets that hold nothing but one phrase, far enough apart that
        // every delta takes two units: whole stretches of two-unit records.
        // The filler is one long run, all in a bucket of its own.
        const SPACING: usize = 33_500;
        const PHRASE: &[u8] = b"quiet-bucket";
        let mut input = vec![0xAA; 45 * SPACING];
        // Each copy is followed by the same tail with one byte of its own, in
        // a different place each time. How far a copy matches a later one
        // then varies down the chain, so the runs a walk stores depend on
        // every candidate it visits and not just the nearest.
        const TAIL: &[u8] = b"-and-a-tail-that-every-copy-shares-in-part";
        let mut copies = 0usize;
        let mut place = |input: &mut [u8], pos: usize| {
            let tail = pos + PHRASE.len();
            input[pos..tail].copy_from_slice(PHRASE);
            input[tail..tail + TAIL.len()].copy_from_slice(TAIL);
            input[tail + copies * 7_919 % TAIL.len()] = 0x80 | copies as u8;
            copies += 1;
        };
        for pos in (700..input.len() - 64).step_by(SPACING) {
            place(&mut input, pos);
        }
        // Two close pairs put a single-unit record among them. A walk that
        // starts after one meets the stretches beyond it between a record's
        // two units, and after both, on a record again.
        for near in [700 + 30 * SPACING + 100, 700 + 36 * SPACING + 100] {
            place(&mut input, near);
        }
        let compared = compare_walks(&input, |pos, _| {
            !(170..=SPACING - 8).contains(&((pos + SPACING - 700) % SPACING))
        });
        assert!(compared > 40_000, "{compared}");
    }

    #[test]
    fn wide_leb_canonical_boundaries_and_reverse_records() {
        let cases: &[(u32, &[u8])] = &[
            (0, &[0, 0]),
            (32_767, &[0xFF, 0x7F]),
            (32_768, &[0, 0x80, 1, 0]),
            (1_073_741_823, &[0xFF, 0xFF, 0xFF, 0x7F]),
            (1_073_741_824, &[0, 0x80, 0, 0x80, 1, 0]),
            (u32::MAX, &[0xFF, 0xFF, 0xFF, 0xFF, 3, 0]),
        ];
        let mut bytes = Vec::new();
        for &(delta, expected) in cases {
            let start = bytes.len();
            bytes.resize(start + encoded_length(delta), 0);
            encode(&mut bytes[start..], delta);
            assert_eq!(&bytes[start..], expected);
            assert_eq!(decode_before(&bytes, bytes.len()), (delta, expected.len()));
            assert_eq!(
                decode_before_scalar(&bytes, bytes.len()),
                (delta, expected.len())
            );
        }
        let mut end = bytes.len();
        for &(delta, expected) in cases.iter().rev() {
            assert_eq!(decode_before(&bytes, end), (delta, expected.len()));
            end -= expected.len();
        }
        assert_eq!(end, 0);
    }

    #[test]
    fn packed_empty_buckets_and_first_global_record_have_safe_boundaries() {
        let allowance = Allowance::default();
        let empty = PackedMatchFinder::with_allowance(b"abc", &allowance).unwrap();
        assert!(empty.packed.is_empty());
        assert!(empty.cursor.iter().all(|&cursor| cursor == 0));
        let input = b"aaaazzzzaaaa";
        let mut finder = PackedMatchFinder::with_allowance(input, &allowance).unwrap();
        assert!(finder.cursor.windows(2).any(|pair| pair[0] == pair[1]));
        let sentinel_length = encoded_length(0);
        assert_eq!(
            decode_before(&finder.packed, sentinel_length),
            (0, sentinel_length)
        );
        for pos in 0..input.len() - 3 {
            let end = finder.insert(input, pos);
            let (delta, _) = decode_before(&finder.packed, end);
            assert!(delta == 0 || delta as usize <= pos);
        }
    }

    /// Each block's runs and the start of each position's runs in them.
    type Collected = Vec<(Vec<(u32, u32)>, Vec<u32>)>;

    /// A member's runs, collected block by block the way a block job's
    /// collector does: from its own window (history, then the run), or from a
    /// finder handed out by one index over the whole group's window. A job
    /// that starts at the member's start leaves its first block to the tree
    /// search, as the encoder does, so its finder starts after that block.
    fn collect_runs(
        member: &[u8],
        runs: &[std::ops::Range<usize>],
        dictionary: usize,
        block: usize,
        cut: usize,
        nice: usize,
        shared: bool,
    ) -> Collected {
        const MAX_MATCH: usize = 0x1001;
        let allowance = Allowance::default();
        let blocks_of = |run: &std::ops::Range<usize>| -> Vec<std::ops::Range<usize>> {
            let first = if run.start == 0 {
                (run.start + block).min(run.end)
            } else {
                run.start
            };
            (first..run.end)
                .step_by(block)
                .map(|start| start..(start + block).min(run.end))
                .collect()
        };
        let group_start = runs[0].start.saturating_sub(dictionary);
        let group = &member[group_start..runs.last().unwrap().end];
        let mut shared_finders = if shared {
            let at: Vec<usize> = runs
                .iter()
                .map(|run| blocks_of(run).first().map_or(run.end, |b| b.start) - group_start)
                .collect();
            Some(
                SharedPackedIndex::finders_over(group, &at, &allowance)
                    .unwrap()
                    .into_vec()
                    .into_iter(),
            )
        } else {
            None
        };
        let mut collected = Vec::new();
        for run in runs {
            let blocks = blocks_of(run);
            let at = blocks.first().map_or(run.end, |b| b.start);
            let (input, origin, mut finder) = match &mut shared_finders {
                Some(finders) => (
                    &group[..run.end - group_start],
                    group_start,
                    finders.next().unwrap(),
                ),
                None => {
                    let window_start = run.start.saturating_sub(dictionary);
                    let window = &member[window_start..run.end];
                    let mut finder = PackedMatchFinder::with_allowance(window, &allowance).unwrap();
                    for pos in 0..(at - window_start).min(window.len().saturating_sub(3)) {
                        finder.insert(window, pos);
                    }
                    (window, window_start, finder)
                }
            };
            for block in blocks {
                let mut found = Buffer::new(&allowance);
                let mut starts = Buffer::with_capacity(block.len() + 1, &allowance).unwrap();
                finder
                    .collect_block(
                        input,
                        block.start - origin..block.end - origin,
                        dictionary,
                        cut,
                        nice,
                        MAX_MATCH,
                        &mut found,
                        &mut starts,
                    )
                    .unwrap();
                collected.push((found.into_vec(), starts.into_vec()));
            }
        }
        collected
    }

    #[test]
    fn a_shared_index_collects_what_each_jobs_own_index_does() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let length = 64 * 1024;
        let words: [&[u8]; 8] = [
            b"volume ", b"header ", b"the ", b"of ", b"match ", b"block ", b"\n", b"window ",
        ];
        let mut text = Vec::with_capacity(length + 8);
        while text.len() < length {
            text.extend_from_slice(words[(next() % 8) as usize]);
        }
        text.truncate(length);
        let noise: Vec<u8> = (0..length).map(|_| next() as u8).collect();
        let two_symbols: Vec<u8> = (0..length).map(|_| b'a' + (next() & 1) as u8).collect();
        // Long repeats with the odd change, so matches reach the nice length
        // and commit across block and run boundaries.
        let mut repeats: Vec<u8> = b"0123456789abcdefghij".repeat(length / 20 + 1);
        repeats.truncate(length);
        for _ in 0..200 {
            let at = (next() as usize) % length;
            repeats[at] = next() as u8;
        }

        let dictionary = 8 * 1024;
        let runs_from = |start: usize, sizes: &[usize]| {
            let mut runs = Vec::new();
            let mut at = start;
            for &size in sizes {
                runs.push(at..(at + size).min(length));
                at += size;
            }
            runs
        };
        let groups = [
            // From the member's start: the first jobs have partial history.
            runs_from(0, &[5 * 1024, 5 * 1024, 12 * 1024, 12 * 1024]),
            // Mid-member: every job carries a full dictionary of history.
            runs_from(10 * 1024, &[12 * 1024, 7 * 1024, 12 * 1024]),
            // Ending in a run too short to search.
            runs_from(length - 12 * 1024 - 2, &[12 * 1024, 2]),
        ];
        for (name, member) in [
            ("text", &text),
            ("noise", &noise),
            ("two symbols", &two_symbols),
            ("repeats", &repeats),
        ] {
            for runs in &groups {
                for (cut, nice) in [(32, 64), (128, 1024)] {
                    let own = collect_runs(member, runs, dictionary, 4 * 1024, cut, nice, false);
                    let shared = collect_runs(member, runs, dictionary, 4 * 1024, cut, nice, true);
                    assert_eq!(own.len(), shared.len());
                    for (index, (own, shared)) in own.iter().zip(&shared).enumerate() {
                        assert!(
                            own == shared,
                            "{name}, runs {runs:?}, cut {cut}, nice {nice}: block {index} differs"
                        );
                    }
                }
            }
        }
    }

    fn fixture(length: usize) -> Vec<u8> {
        let mut state = 0x7A59_1234_AA55_0123u64;
        let mut input = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            input.push(state as u8);
        }
        for pos in (0..length.saturating_sub(32)).step_by(97) {
            input[pos..pos + 16].copy_from_slice(b"repeated-prefix!");
        }
        input
    }

    fn compare(input: &[u8], seed: usize, window: usize) {
        let allowance = Allowance::default();
        let mut packed = PackedMatchFinder::with_allowance(input, &allowance).unwrap();
        let mut wide = MatchFinder::<4>::new(window);
        assert_eq!(packed.next_position, 0);
        for pos in 0..seed {
            packed.insert(input, pos);
            wide.insert(input, pos);
        }
        for pos in seed..input.len() - 3 {
            let end = packed.insert(input, pos);
            wide.insert(input, pos);
            if pos % 7 != 0 {
                continue;
            }
            for cut in [0, 1, 8, 128] {
                for (cap, nice) in [(4, 512), (32, 16), (512, 512)] {
                    let max_length = cap.min(input.len() - pos);
                    if max_length < 4 {
                        continue;
                    }
                    let max_distance = pos.min(window);
                    let mut expected = Buffer::new(&allowance);
                    let mut actual = Buffer::new(&allowance);
                    let mut longest = 0;
                    let mut checked = 0;
                    let mut candidate = wide.first(input, pos);
                    while candidate != NO_POSITION && longest < max_length && longest < nice {
                        if candidate >= pos {
                            candidate = wide.previous(candidate);
                            continue;
                        }
                        let distance = pos - candidate;
                        if distance > max_distance || checked == cut {
                            break;
                        }
                        checked += 1;
                        if input[candidate + longest] == input[pos + longest] {
                            let length =
                                super::super::fast::match_length(input, pos, distance, max_length);
                            if length > longest {
                                if length >= 4 {
                                    expected.push((length as u32, distance as u32)).unwrap();
                                }
                                longest = length;
                            }
                        }
                        if checked == cut {
                            break;
                        }
                        candidate = wide.previous(candidate);
                    }
                    packed
                        .collect_improving(
                            input,
                            pos,
                            end,
                            max_length,
                            max_distance,
                            cut,
                            nice,
                            &mut actual,
                        )
                        .unwrap();
                    assert_eq!(
                        &actual[..],
                        &expected[..],
                        "pos{pos} cut{cut} cap{cap} window{window}"
                    );
                }
            }
        }
    }

    #[test]
    fn packed_frontiers_match_original_hash_chains() {
        let random = fixture(8192);
        let pattern: Vec<_> = (0..8192)
            .map(|pos| b"abcdabcdXabcdabcdY"[pos % 18])
            .collect();
        for input in [&random[..], &pattern[..]] {
            for window in [32, 4096, 16384] {
                compare(input, 0, window);
            }
        }
    }

    #[test]
    fn packed_collision_probe_keeps_subfour_state_cut_and_refusal_order() {
        let target = hash(b"abcd", 0);
        let zero = (0u32..1 << 24)
            .find_map(|value| {
                let word = value.to_le_bytes();
                (word[0] != b'a' && hash(&word, 0) == target).then_some(word)
            })
            .unwrap();
        let one = (0u32..1 << 24)
            .find_map(|upper| {
                let word = (u32::from(b'a') | (upper << 8)).to_le_bytes();
                (word[1] != b'b' && hash(&word, 0) == target).then_some(word)
            })
            .unwrap();
        let mut input = vec![0; 75];
        input[..12].copy_from_slice(b"abcdlongtail");
        input[16..21].copy_from_slice(b"abcdX");
        input[32..36].copy_from_slice(&one);
        input[48..52].copy_from_slice(&zero);
        input[63..].copy_from_slice(b"abcdlongtail");
        // Position 63 is included in this exhaustive-budget/cap oracle. Its
        // nearest collisions first prove zero and then one matching byte.
        compare(&input, 0, 128);

        let budget = RefusingBudget::new(usize::MAX);
        let mut finder = PackedMatchFinder::with_allowance(&input, &budget).unwrap();
        let constructor_attempts = budget.attempts();
        let mut end = 0;
        for pos in 0..=63 {
            end = finder.insert(&input, pos);
        }
        let mut runs = Buffer::new(&budget);
        finder
            .collect_improving(&input, 63, end, 12, 63, 4, 512, &mut runs)
            .unwrap();
        assert_eq!(&runs[..], &[(4, 47), (12, 63)]);
        runs.clear();
        finder
            .collect_improving(&input, 63, end, 12, 63, 2, 512, &mut runs)
            .unwrap();
        assert!(runs.is_empty(), "both collisions consume the visit budget");
        drop((runs, finder));
        assert_eq!(budget.used(), 0);

        // One admitted output slot lets the first legal run survive; growing
        // for the second legal run refuses at exactly the same frontier point.
        let budget = RefusingBudget::new(constructor_attempts + 1);
        let mut finder = PackedMatchFinder::with_allowance(&input, &budget).unwrap();
        let mut runs = Buffer::with_capacity(1, &budget).unwrap();
        for pos in 0..=63 {
            end = finder.insert(&input, pos);
        }
        assert_eq!(
            finder.collect_improving(&input, 63, end, 12, 63, 4, 512, &mut runs),
            Err(super::super::Error::Cancelled)
        );
        assert_eq!(&runs[..], &[(4, 47)]);
        drop((runs, finder));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn packed_seeded_history_preserves_expiry_and_future_visibility() {
        let mut input = fixture(8192);
        input.copy_within(100..900, 4096);
        compare(&input, 4096, 256);
        compare(&input, 4096, 8192);
    }

    #[test]
    fn packed_allocations_are_exact_charged_and_refusal_releases_them() {
        let input = fixture(2048);
        for fail_at in 0..4 {
            let allowance = RefusingBudget::new(fail_at);
            let finder = PackedMatchFinder::with_allowance(&input, &allowance);
            drop(finder);
            assert_eq!(allowance.used(), 0, "refusal{fail_at}");
        }
        let allowance = Allowance::limited(u64::MAX);
        let mut finder = PackedMatchFinder::with_allowance(&input, &allowance).unwrap();
        let Stream::Own(packed) = &finder.packed else {
            panic!("a finder built alone owns its stream");
        };
        assert_eq!(packed.capacity(), packed.len());
        let charged = allowance.used();
        assert_eq!(charged, (BUCKETS * 4 + finder.packed.len()) as u64);
        for pos in 0..input.len() - 3 {
            finder.insert(&input, pos);
        }
        assert_eq!(allowance.used(), charged, "insertion cannot allocate");
        drop(finder);
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn packed_terminal_block_releases_index_but_keeps_match_output() {
        let input = vec![b'x'; 80];
        let allowance = Allowance::limited(u64::MAX);
        let mut finder = PackedMatchFinder::with_allowance(&input, &allowance).unwrap();
        for pos in 0..4 {
            finder.insert(&input, pos);
        }
        let index_bytes = allowance.used();
        let mut runs = Buffer::with_capacity(80, &allowance).unwrap();
        let mut starts = Buffer::with_capacity(81, &allowance).unwrap();
        let output_bytes = allowance.used() - index_bytes;
        finder
            .collect_block(&input, 4..20, 64, 128, 512, 16, &mut runs, &mut starts)
            .unwrap();
        assert_eq!(allowance.used(), index_bytes + output_bytes);
        assert!(!finder.packed.is_empty() && !finder.cursor.is_empty());
        assert_eq!(finder.next_position, 20);
        finder
            .collect_block(&input, 20..80, 64, 128, 512, 16, &mut runs, &mut starts)
            .unwrap();
        assert!(finder.packed.is_empty() && finder.cursor.is_empty());
        assert_eq!(allowance.used(), output_bytes);
        assert_eq!(finder.next_position, input.len() - 3);

        // Equal bytes always yield the nearest distance1 and the exact cap.
        // Check both accumulated blocks after their index has been released.
        let mut expected_runs = Vec::new();
        let mut expected_starts = Vec::new();
        for block in [4..20, 20..80] {
            for pos in block.clone() {
                expected_starts.push(expected_runs.len() as u32);
                let length = (block.end - pos).min(16);
                if length >= 4 {
                    expected_runs.push((length as u32, 1));
                }
            }
            expected_starts.push(expected_runs.len() as u32);
        }
        assert_eq!(&runs[..], &expected_runs);
        assert_eq!(&starts[..], &expected_starts);
        drop(runs);
        drop(starts);
        assert_eq!(allowance.used(), 0);
    }
}
