//! Match finders shared by the LZ encoders.
//!
//! [`MatchFinder`] is a hash chain. Positions are indexed into a
//! single-bucket-per-hash chain: `head` maps a hash of the `MIN_MATCH` bytes
//! at a position to the most recently inserted position, and `prev` links each
//! inserted position to the previous position with the same hash. Walking a
//! chain therefore visits candidates from the smallest distance to the
//! largest, so callers can stop as soon as a candidate falls outside their
//! window. Inserting costs one store, so a caller can skip past bytes it has
//! already decided about for free, which is what the lazy encoders do.
//!
//! `TreeMatchFinder` keeps the positions sharing a hash in a binary tree
//! ordered by the bytes that follow them, after LZMA. One descent finds every
//! improving match and re-hangs the tree under the new position, and each node
//! on the way down narrows a proven-prefix bound, so the descent never re-reads
//! bytes it has already matched. That is what a deep chain walk cannot avoid,
//! and why the tree serves the optimal parse, which searches at every position
//! anyway. The price is that inserting *is* a descent, so history cannot be
//! seeded cheaply, and the tree costs six bytes per byte of window up to
//! 16 MiB, and eight past it, against the chain's four.
//!
//! `prev` holds one link per position in a window rather than one per position
//! in the input, indexed by position modulo the window. A link is only followed
//! while the candidate it names is inside the window, and a slot is only reused
//! once the position it held has fallen out, so the two never overlap. That
//! bounds the finder by the window instead of by the data, which is what lets
//! one finder span every block of a member: rebuilding it per block meant
//! rehashing the whole history each time.
//!
//! Links are 32 bits, so the window costs four bytes per byte it covers rather
//! than eight, and twice as many links share a cache line. Positions past four
//! gigabytes keep only their low half; `resolve` measures back from the newest
//! position inserted to recover the rest.

use super::workspace::{Allowance, Budget, Buffer};
use super::Result;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering::Relaxed};

/// Sentinel for "no position" in `head`/`prev` chains.
pub(crate) const NO_POSITION: usize = usize::MAX;

/// The sentinel as it is stored. A position whose low 32 bits are all set is
/// indistinguishable from it and ends its chain one link early. That costs one
/// candidate every four gigabytes and cannot cost correctness: a caller
/// confirms every candidate by comparing the bytes at it.
const NO_LINK: u32 = u32::MAX;

/// Reads a stored link back as the position it names, given the newest position
/// the finder holds.
///
/// Only the low 32 bits of a position survive storage. No link names a position
/// newer than `newest`, so measuring back from `newest` recovers it exactly
/// whenever the input fits in 32 bits, and within four gigabytes of the true one
/// when it does not. Neither case can underflow: below four gigabytes the stored
/// link is the position itself and so no higher than `newest`, and above it the
/// distance is a `u32` and `newest` is not.
fn resolve(newest: usize, link: u32) -> usize {
    if link == NO_LINK {
        return NO_POSITION;
    }
    newest - (newest as u32).wrapping_sub(link) as usize
}

/// The multiplicative mix every finder hashes with.
fn mix(value: u32, bits: u32) -> usize {
    (value.wrapping_mul(0x9E37_79B1) >> (32 - bits)) as usize
}

#[derive(Debug)]
pub(crate) struct MatchFinder<const MIN_MATCH: usize, B: Budget = Allowance> {
    head: Buffer<u32, B>,
    prev: Buffer<u32, B>,
    mask: usize,
    hash_bits: u32,
    /// The highest position inserted so far, and so at least as high as any
    /// position a link can name. Truncated links are read back against it.
    newest: usize,
}

#[cfg(any(test, feature = "write"))]
impl<const MIN_MATCH: usize> MatchFinder<MIN_MATCH> {
    #[cfg(test)]
    pub(crate) fn new(window: usize) -> Self {
        Self::with_allowance(window, &Allowance::default()).expect("unlimited finder allocation")
    }

    /// More heads keep a long reach from crowding each chain with collisions.
    #[cfg(feature = "write")]
    pub(crate) fn for_reach(window: usize, reach: usize) -> Self {
        Self::build(window, Self::reach_hash_bits(reach), &Allowance::default())
            .expect("unlimited finder allocation")
    }

    /// What [`MatchFinder::for_reach`] allocates for this window and reach.
    #[cfg(feature = "write")]
    pub(crate) fn bytes_for_reach(window: usize, reach: usize) -> u64 {
        Self::bytes_with_hash_bits(window, Self::reach_hash_bits(reach))
    }

    #[cfg(feature = "write")]
    pub(crate) fn bytes_for_window(window: usize) -> u64 {
        Self::bytes_with_hash_bits(window, Self::HASH_BITS)
    }

    #[cfg(feature = "write")]
    fn bytes_with_hash_bits(window: usize, hash_bits: u32) -> u64 {
        let links = window
            .max(1)
            .checked_next_power_of_two()
            .unwrap_or(usize::MAX) as u64;
        let heads = 1u64 << hash_bits;
        links
            .saturating_add(heads)
            .saturating_mul(size_of::<u32>() as u64)
    }

    /// The most heads [`MatchFinder::for_reach`] hangs chains off, as bits.
    ///
    /// The 32-byte finder searches for long matches only, so a chain that
    /// shares its bucket with unrelated strings is mostly misses; it takes
    /// more heads than the LZ finders, whose collisions are a different trade.
    #[cfg(feature = "write")]
    const MAX_REACH_HASH_BITS: u32 = match MIN_MATCH {
        32 => 23,
        _ => 20,
    };

    /// Bits of heads beyond one head per position of reach.
    #[cfg(feature = "write")]
    const REACH_HASH_SLACK: u32 = match MIN_MATCH {
        32 => 1,
        _ => 0,
    };

    /// Heads follow the reach, not the window, so filling ahead offers the same candidates.
    #[cfg(feature = "write")]
    fn reach_hash_bits(reach: usize) -> u32 {
        (reach.max(1).next_power_of_two().trailing_zeros() + Self::REACH_HASH_SLACK)
            .clamp(Self::HASH_BITS, Self::MAX_REACH_HASH_BITS)
    }
}

impl<const MIN_MATCH: usize, B: Budget> MatchFinder<MIN_MATCH, B> {
    const HASH_BITS: u32 = match MIN_MATCH {
        3 => 16,
        4 | 6 | 32 => 17,
        _ => panic!("match finder supports MIN_MATCH of 3, 4, 6 or 32"),
    };

    /// Builds a finder that remembers the last `window` positions.
    ///
    /// The caller must not accept a match further back than `window`, which is
    /// the check it already makes against its own maximum distance. A link to a
    /// position that has fallen out of the window is still readable, and still
    /// names the position it named, so that check rejects it the same way it
    /// rejects a match that is merely too far away.
    pub(crate) fn with_allowance(window: usize, allowance: &B) -> Result<Self> {
        Self::build(window, Self::HASH_BITS, allowance)
    }

    fn build(window: usize, hash_bits: u32, allowance: &B) -> Result<Self> {
        let window = window
            .max(1)
            .checked_next_power_of_two()
            .ok_or(super::Error::InvalidData("finder window overflows"))?;
        Ok(Self {
            head: Buffer::filled(1 << hash_bits, NO_LINK, allowance)?,
            // Zero rather than the sentinel, and nothing reads it either way: a
            // link is only ever followed from a position that has been
            // inserted, and inserting a position writes its slot first. Zero
            // lets the allocator hand back pages it has not had to touch, so a
            // window wider than the data has reached costs nothing yet.
            prev: Buffer::filled(window, 0, allowance)?,
            mask: window - 1,
            hash_bits,
            newest: 0,
        })
    }

    #[cfg(feature = "write")]
    pub(crate) fn allowance(&self) -> B {
        self.head.allowance()
    }

    /// How many positions back a link is kept.
    #[cfg(all(test, feature = "write"))]
    pub(crate) fn window(&self) -> usize {
        self.mask + 1
    }

    #[inline]
    fn hash(&self, input: &[u8], pos: usize) -> usize {
        let value = if MIN_MATCH == 3 {
            u32::from(input[pos])
                | (u32::from(input[pos + 1]) << 8)
                | (u32::from(input[pos + 2]) << 16)
        } else if MIN_MATCH == 32 {
            let (words, _) = input[pos..pos + 32].as_chunks::<8>();
            let wide = words
                .iter()
                .map(|&word| u64::from_le_bytes(word))
                .fold(0u64, |hash, word| {
                    (hash ^ word).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                });
            (wide ^ (wide >> 32)) as u32
        } else if MIN_MATCH == 6 {
            // Six bytes do not fit the 32-bit mix, so they get a 64-bit one,
            // whose top bits depend on every byte. One eight-byte load where
            // the input allows it, the same six bytes either way.
            let value = match input.get(pos..pos + 8) {
                Some(word) => {
                    u64::from_le_bytes(word.try_into().expect("eight bytes")) & 0xFFFF_FFFF_FFFF
                }
                None => {
                    let low = u32::from_le_bytes([
                        input[pos],
                        input[pos + 1],
                        input[pos + 2],
                        input[pos + 3],
                    ]);
                    u64::from(low)
                        | (u64::from(u16::from_le_bytes([input[pos + 4], input[pos + 5]])) << 32)
                }
            };
            return (value.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - self.hash_bits)) as usize;
        } else {
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]])
        };
        mix(value, self.hash_bits)
    }

    /// Records `pos` as a future match candidate. Positions too close to the
    /// end of the input to fit `MIN_MATCH` bytes are ignored.
    #[inline]
    pub(crate) fn insert(&mut self, input: &[u8], pos: usize) {
        if pos + MIN_MATCH <= input.len() {
            let hash = self.hash(input, pos);
            self.prev[pos & self.mask] = self.head[hash];
            self.head[hash] = pos as u32;
            self.newest = self.newest.max(pos);
        }
    }

    /// Returns the most recently inserted candidate sharing `pos`'s hash, or
    /// [`NO_POSITION`]. The caller must ensure at least `MIN_MATCH` bytes are
    /// readable at `pos`.
    pub(crate) fn first(&self, input: &[u8], pos: usize) -> usize {
        resolve(self.newest, self.head[self.hash(input, pos)])
    }

    /// For a finder filled ahead: skips candidates an in-order parse at `limit` has not inserted.
    #[cfg(feature = "write")]
    pub(crate) fn first_before(&self, pos: usize, limit: usize) -> usize {
        let mut candidate = self.previous(pos);
        while candidate != NO_POSITION && candidate >= limit {
            candidate = self.previous(candidate);
        }
        candidate
    }

    /// Returns the next-older candidate in `candidate`'s chain, or
    /// [`NO_POSITION`].
    pub(crate) fn previous(&self, candidate: usize) -> usize {
        let older = resolve(self.newest, self.prev[candidate & self.mask]);
        // Chains run newest to oldest. A link that does not step back is one
        // whose slot has been reused, or whose position wrapped past four
        // gigabytes; either way the chain ends here, which is what keeps the
        // walk finite. This also covers the sentinel, which is above every
        // position.
        if older >= candidate {
            return NO_POSITION;
        }
        older
    }
}

pub(crate) trait ChainRule {
    type Error;

    /// The byte a candidate must match before measuring, if there is one.
    fn probe(&mut self, distance: usize) -> Option<usize>;

    /// Check the prefix and measure a candidate, returning zero for a rejection.
    fn measure(&self, candidate: usize, distance: usize) -> usize;

    /// Consider a measured match. Return true to end the search.
    fn consider(
        &mut self,
        length: usize,
        distance: usize,
    ) -> std::result::Result<bool, Self::Error>;
}

/// Walk older candidates in distance order. The starting candidate and links
/// must be older than `pos`, or be `NO_POSITION`.
#[allow(clippy::too_many_arguments)]
#[inline]
pub(crate) fn walk_chain<R: ChainRule>(
    input: &[u8],
    pos: usize,
    mut candidate: usize,
    max_length: usize,
    max_distance: usize,
    mut remaining: usize,
    previous: impl Fn(usize) -> usize,
    rule: &mut R,
) -> std::result::Result<(), R::Error> {
    while candidate != NO_POSITION && remaining != 0 {
        let distance = pos - candidate;
        if distance > max_distance {
            break;
        }
        remaining -= 1;
        if visit(input, pos, candidate, distance, max_length, rule)? {
            break;
        }
        if remaining == 0 {
            break;
        }
        candidate = previous(candidate);
    }
    Ok(())
}

/// Probe, measure and consider one candidate. Returns true to end the walk.
#[inline(always)]
fn visit<R: ChainRule>(
    input: &[u8],
    pos: usize,
    candidate: usize,
    distance: usize,
    max_length: usize,
    rule: &mut R,
) -> std::result::Result<bool, R::Error> {
    if rule
        .probe(distance)
        .is_none_or(|probe| probe < max_length && input[candidate + probe] == input[pos + probe])
    {
        let length = rule.measure(candidate, distance);
        if length != 0 && rule.consider(length, distance)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// [`walk_chain`] one candidate at a time, for a caller that interleaves
/// several walks to keep their loads in flight together.
#[cfg(feature = "write")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChainWalk {
    candidate: usize,
    remaining: usize,
}

#[cfg(feature = "write")]
impl ChainWalk {
    #[inline]
    pub(crate) fn new(candidate: usize, remaining: usize) -> Self {
        Self {
            candidate,
            remaining,
        }
    }

    /// Look at the next candidate. Returns false once the walk is over, and
    /// keeps returning false after that.
    #[inline(always)]
    pub(crate) fn step<R: ChainRule>(
        &mut self,
        input: &[u8],
        pos: usize,
        max_length: usize,
        max_distance: usize,
        previous: impl Fn(usize) -> usize,
        rule: &mut R,
    ) -> std::result::Result<bool, R::Error> {
        let candidate = self.candidate;
        if candidate == NO_POSITION || self.remaining == 0 {
            return Ok(false);
        }
        let distance = pos - candidate;
        if distance > max_distance {
            self.remaining = 0;
            return Ok(false);
        }
        self.remaining -= 1;
        if visit(input, pos, candidate, distance, max_length, rule)? {
            self.remaining = 0;
            return Ok(false);
        }
        if self.remaining == 0 {
            return Ok(false);
        }
        self.candidate = previous(candidate);
        Ok(true)
    }
}

// Fusing insertion and lookup shares one hash and skips the self link.
impl<B: Budget> MatchFinder<4, B> {
    /// Insert a readable position and return its first older candidate. Like
    /// the encoder's ordinary insertion schedule, positions arrive in order.
    #[inline]
    pub(crate) fn insert_and_first(&mut self, input: &[u8], pos: usize) -> usize {
        debug_assert!(pos + 4 <= input.len());
        self.record_and_first(self.hash(input, pos), pos)
    }

    /// Inserts each of `positions` in order, every one with four bytes
    /// readable at it: the stretch a parse steps over inside a match.
    #[cfg(feature = "write")]
    #[inline]
    pub(crate) fn insert_run(&mut self, input: &[u8], positions: std::ops::Range<usize>) {
        if positions.is_empty() {
            return;
        }
        debug_assert!(positions.start >= self.newest);
        debug_assert!(positions.end + 3 <= input.len());
        let last = positions.end - 1;
        for pos in positions {
            let hash = self.hash(input, pos);
            self.prev[pos & self.mask] = self.head[hash];
            self.head[hash] = pos as u32;
        }
        self.newest = self.newest.max(last);
    }

    #[inline]
    fn record_and_first(&mut self, hash: usize, pos: usize) -> usize {
        debug_assert!(pos >= self.newest);
        let previous = self.head[hash];
        self.prev[pos & self.mask] = previous;
        self.head[hash] = pos as u32;
        self.newest = pos;
        // The ordinary first() sees the sentinel rather than this position,
        // so it never reaches its otherwise valid previous link.
        if pos as u32 == NO_LINK {
            return NO_POSITION;
        }
        let older = if pos <= u32::MAX as usize {
            previous as usize
        } else {
            resolve(self.newest, previous)
        };
        if older < pos {
            older
        } else {
            NO_POSITION
        }
    }

    /// Preserve the ordinary collector's candidate visits, cutoffs and every
    /// improving run, including sub-four-byte hash collisions. A verified
    /// four-byte prefix only needs its remaining suffix compared again.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub(crate) fn collect_improving(
        &self,
        input: &[u8],
        pos: usize,
        first: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
        nice: usize,
        out: &mut Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        if self.newest <= u32::MAX as usize {
            self.collect_improving_with_positions::<true>(
                input,
                pos,
                first,
                max_length,
                max_distance,
                cut,
                nice,
                out,
            )
        } else {
            self.collect_improving_with_positions::<false>(
                input,
                pos,
                first,
                max_length,
                max_distance,
                cut,
                nice,
                out,
            )
        }
    }

    #[inline]
    fn previous_for_collection<const SHORT: bool>(&self, candidate: usize) -> usize {
        let raw = self.prev[candidate & self.mask];
        let older = if SHORT {
            // Before wrapping, raw links are absolute positions. The sentinel
            // is also >= every candidate, so the same rejection covers it.
            raw as usize
        } else {
            resolve(self.newest, raw)
        };
        if older >= candidate {
            NO_POSITION
        } else {
            older
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn collect_improving_with_positions<const SHORT: bool>(
        &self,
        input: &[u8],
        pos: usize,
        mut first: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
        nice: usize,
        out: &mut Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        debug_assert!(max_length >= 4 && pos + max_length <= input.len());
        if cut == 0 || nice == 0 {
            return Ok(());
        }
        let previous = |candidate| self.previous_for_collection::<SHORT>(candidate);
        while first != NO_POSITION && first >= pos {
            first = previous(first);
        }
        walk_chain(
            input,
            pos,
            first,
            max_length,
            max_distance,
            cut,
            previous,
            &mut ImprovingRuns {
                input,
                pos,
                max_length,
                stop_length: max_length.min(nice),
                prefix: u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap()),
                longest: 0,
                out,
            },
        )
    }
}

struct ImprovingRuns<'a, B: Budget> {
    input: &'a [u8],
    pos: usize,
    max_length: usize,
    stop_length: usize,
    prefix: u32,
    longest: usize,
    out: &'a mut Buffer<(u32, u32), B>,
}

impl<B: Budget> ChainRule for ImprovingRuns<'_, B> {
    type Error = B::Failure;

    #[inline]
    fn probe(&mut self, _distance: usize) -> Option<usize> {
        Some(self.longest)
    }

    #[inline]
    fn measure(&self, candidate: usize, distance: usize) -> usize {
        let difference = self.prefix
            ^ u32::from_le_bytes(self.input[candidate..candidate + 4].try_into().unwrap());
        if difference != 0 {
            (difference.trailing_zeros() / 8) as usize
        } else {
            4 + super::fast::match_length(self.input, self.pos + 4, distance, self.max_length - 4)
        }
    }

    #[inline]
    fn consider(
        &mut self,
        length: usize,
        distance: usize,
    ) -> std::result::Result<bool, B::Failure> {
        if length > self.longest {
            self.out.push((length as u32, distance as u32))?;
            self.longest = length;
        }
        Ok(self.longest >= self.stop_length)
    }
}

/// The most runs [`TreeMatchFinder::matches`] reports for one position.
pub(crate) const TREE_MAX_RUNS: usize = 8;

/// A match an optimal parse's collector committed to, whose interior it does
/// not search.
///
/// The parse commits too, but it can reach a long match sooner, through a
/// remembered distance the collector never sees, step over the position where
/// the collector committed, and land inside the collector's match with nothing
/// searched there. Every byte to the end of that match would then be priced
/// as a literal. So the parse looks up what is left of the committed match
/// where it lands, which a search there would have found at least.
#[cfg(feature = "write")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CommittedMatch {
    start: usize,
    /// The first position past the committed reach.
    pub(crate) end: usize,
    length: u32,
    distance: u32,
}

#[cfg(feature = "write")]
impl CommittedMatch {
    /// `run`, found at `pos`, committed to as far as `reach`.
    pub(crate) fn at(pos: usize, reach: usize, run: (u32, u32)) -> Self {
        Self {
            start: pos,
            end: pos + reach,
            length: run.0,
            distance: run.1,
        }
    }

    /// What is left of the committed match at `pos`, inside its reach, if
    /// that is still a match.
    pub(crate) fn tail(&self, pos: usize) -> Option<(u32, u32)> {
        let length = (self.length as usize).checked_sub(pos.checked_sub(self.start)?)?;
        (pos < self.end && length >= 4).then_some((length as u32, self.distance))
    }
}

/// A binary-tree match finder, after LZMA's BT4.
///
/// Positions sharing a hash of their first four bytes form a binary search
/// tree ordered by the bytes at them, newest position at the root. The two
/// children of each position live in `son`, one window slot per position as
/// with the chain finder's `prev`, and the same rules keep slot reuse and the
/// window from ever overlapping.
///
/// A window of up to 16 MiB stores each child as its distance back from the
/// node holding the link, in 24 bits ([`NarrowLinks`]): six bytes a slot
/// rather than eight. A child that far back has fallen out of the window, so
/// it is stored as no child, which a descent treats the same way. A larger
/// window stores truncated positions, read back with the position being
/// searched for as the reference, which is always the newest.
///
/// Positions with different hashes never link to each other, so each hash's
/// tree is built by its own insertions alone. That is what lets a
/// [`SeedTree`] put history in on several threads at once, each owning a
/// share of the hashes. The links are atomics for that only: every access is
/// relaxed, and no link is touched by two threads at once.
#[derive(Debug)]
pub(crate) struct TreeMatchFinder<B: Budget = Allowance> {
    head: Buffer<AtomicU32, B>,
    /// Two links per window slot: the child whose bytes compare lesser first,
    /// then the greater-or-equal one, in LZMA's layout.
    son: Links<B>,
    mask: usize,
    /// Position `pos` keeps its links in slot `(pos + shift) & mask`. Only a
    /// tree a [`SeedTree`] hands on whole has slots offset from its positions.
    shift: usize,
    /// Positions before this count as fallen out of the window. Only a
    /// [`SeedTree`] raises it from zero.
    oldest: usize,
}

impl TreeMatchFinder {
    #[cfg(test)]
    pub(crate) fn new(window: usize) -> Self {
        Self::with_allowance(window, &Allowance::default()).expect("unlimited finder allocation")
    }

    /// A finder storing truncated positions, as a window past 16 MiB does.
    #[cfg(all(test, feature = "write", feature = "parallel"))]
    fn with_wide_links(window: usize) -> Self {
        let mut finder = Self::new(window);
        finder.son = Links::Wide(
            Buffer::filled_with(
                2 * (finder.mask + 1),
                || AtomicU32::new(0),
                &Allowance::default(),
            )
            .expect("unlimited finder allocation"),
        );
        finder
    }
}

impl<B: Budget> TreeMatchFinder<B> {
    const HASH_BITS: u32 = 17;
    const MIN_MATCH: usize = 4;
    /// The most runs one position reports: the longest found.
    ///
    /// A descent through noise lengthens its match a byte or two at a time,
    /// reporting each step, where a chain walk in recency order finds few
    /// improvements. Uncapped, two-symbol noise averaged over twelve runs a
    /// position, and a block job seeding a tree from a 4 MiB dictionary of it
    /// counted 229 MiB against the 151 MiB it is charged; at eight it counts
    /// 133 MiB. On 32 MiB each of text, source and binaries at level 3 the
    /// cap moves the output by at most five bytes.
    const MAX_RUNS: usize = TREE_MAX_RUNS;

    /// What the tree's heads and two links per window slot allocate.
    #[cfg(feature = "write")]
    pub(crate) fn bytes_for_window(window: usize) -> usize {
        let slots = window.max(1).next_power_of_two();
        (1 << Self::HASH_BITS) * size_of::<u32>() + Self::link_bytes_per_slot(slots) * slots
    }

    /// What the two links of one window slot take in a window of `window`
    /// positions.
    #[cfg(feature = "write")]
    pub(crate) fn link_bytes_per_slot(window: usize) -> usize {
        if window.max(1).next_power_of_two() <= NarrowLinks::<B>::MAX_WINDOW {
            6
        } else {
            2 * size_of::<u32>()
        }
    }

    /// Builds a finder that remembers the last `window` positions, at six
    /// bytes of links per byte of window up to 16 MiB and eight past it.
    pub(crate) fn with_allowance(window: usize, allowance: &B) -> Result<Self> {
        let window = window
            .max(1)
            .checked_next_power_of_two()
            .ok_or(super::Error::InvalidData("finder window overflows"))?;
        Ok(Self {
            head: Buffer::filled_with(1 << Self::HASH_BITS, || AtomicU32::new(NO_LINK), allowance)?,
            // Zero rather than the sentinel for the same reason as the chain
            // finder's `prev`: a slot is always written during its position's
            // own insertion before any link can lead to it.
            son: if window <= NarrowLinks::<B>::MAX_WINDOW {
                Links::Narrow(NarrowLinks(Buffer::filled_with(
                    6 * window,
                    || AtomicU8::new(0),
                    allowance,
                )?))
            } else {
                Links::Wide(Buffer::filled_with(
                    window
                        .checked_mul(2)
                        .ok_or(super::Error::InvalidData("finder window overflows"))?,
                    || AtomicU32::new(0),
                    allowance,
                )?)
            },
            mask: window - 1,
            shift: 0,
            oldest: 0,
        })
    }

    /// Builds a finder for `window` holding `history`, each position put in
    /// with the descent [`Self::matches`] makes at `len_limit(pos)` and `cut`,
    /// reporting nothing, split between `shares` threads by hash. `history`
    /// must fit in the window, counted from the start of `input` when it is
    /// split ([`Self::insert_range`]), and `len_limit` must keep to
    /// [`Self::matches`]'s rules. The links are the same for any `shares`.
    #[cfg(feature = "write")]
    pub(crate) fn seeded(
        window: usize,
        input: &[u8],
        history: std::ops::Range<usize>,
        len_limit: impl Fn(usize) -> usize + Sync,
        cut: usize,
        shares: usize,
        allowance: &B,
    ) -> Result<Self> {
        let finder = Self::with_allowance(window, allowance)?;
        debug_assert!(history.len() <= finder.mask + 1);
        finder.insert_range(input, history, &len_limit, cut, shares);
        Ok(finder)
    }

    /// Inserts the positions of `range` that have four bytes left, as
    /// [`Self::seeded`] does, split between `shares` threads by hash. Noise
    /// is left out ([`super::noise::NoiseScan::skips`]), judged in cells
    /// counted from the end of `range`, where the run it is history for
    /// starts.
    ///
    /// Each hash's positions still go in in order, so the links come out the
    /// same on any number of threads, provided no position of `range` shares
    /// a slot with one a descent can still reach: everything from
    /// [`Self::oldest`] to the end of `range` must fit in the window.
    #[cfg(feature = "write")]
    fn insert_range(
        &self,
        input: &[u8],
        range: std::ops::Range<usize>,
        len_limit: &(impl Fn(usize) -> usize + Sync),
        cut: usize,
        shares: usize,
    ) {
        debug_assert!(shares == 1 || range.end - range.start.min(self.oldest) <= self.mask + 1);
        let end = range
            .end
            .min(input.len().saturating_sub(Self::MIN_MATCH - 1));
        let insert = |share: usize| {
            // The tree collector leaves the same positions out, in cells
            // counted from the run the history is for.
            let mut noise = super::noise::NoiseScan::with_cells(range.end);
            for pos in range.start..end {
                let hash = self.hash(input, pos);
                if (shares == 1 || (hash * shares) >> Self::HASH_BITS == share)
                    && !noise.skips(input, pos)
                {
                    let inserted =
                        self.descend::<true>(input, pos, hash, len_limit(pos), 0, cut, None);
                    debug_assert!(
                        inserted.is_ok(),
                        "a descent reporting nothing allocates nothing"
                    );
                }
            }
        };
        // Share 0 holds the hash of a run of zeroes, which can be most of the
        // work in machine code, and `spread` keeps it on this thread.
        crate::parallel::spread(shares.max(1), insert);
    }

    fn hash(&self, input: &[u8], pos: usize) -> usize {
        mix(
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]),
            Self::HASH_BITS,
        )
    }

    /// Starts loading what the descent at `pos` reads first, the newest
    /// position under its hash: its child links and its bytes. Called a
    /// position ahead, those misses overlap the descent before it.
    #[cfg(feature = "write")]
    #[inline]
    pub(crate) fn prefetch(&self, input: &[u8], pos: usize) {
        if pos + Self::MIN_MATCH > input.len() {
            return;
        }
        let newest = resolve(pos, self.head[self.hash(input, pos)].load(Relaxed));
        if newest < pos {
            let pair = self.slot(newest) << 1;
            match &self.son {
                Links::Wide(son) => crate::simd::prefetch(son, pair),
                Links::Narrow(son) => crate::simd::prefetch(&son.0, 3 * pair),
            }
            crate::simd::prefetch(input, newest);
        }
    }

    /// Where `pos` keeps its two links.
    #[inline(always)]
    fn slot(&self, pos: usize) -> usize {
        (pos.wrapping_add(self.shift)) & self.mask
    }

    /// The child `owner` links to at `index`, as [`Son::child`] reads it.
    #[cfg(feature = "write")]
    fn child(&self, reference: usize, owner: usize, index: usize) -> usize {
        match &self.son {
            Links::Wide(son) => son.child(reference, owner, index),
            Links::Narrow(son) => son.child(reference, owner, index),
        }
    }

    /// Links `owner` to `child` at `index`, as [`Son::hang`] does.
    #[cfg(feature = "write")]
    fn hang(&self, owner: usize, index: usize, child: usize) {
        match &self.son {
            Links::Wide(son) => son.hang(owner, index, child),
            Links::Narrow(son) => son.hang(owner, index, child),
        }
    }

    /// Each hash's head and the two child links of each window slot, as
    /// stored, for tests to compare whole trees.
    #[cfg(test)]
    fn links(&self) -> (Vec<u32>, Vec<u32>) {
        let head = self.head.iter().map(|link| link.load(Relaxed)).collect();
        let son = match &self.son {
            Links::Wide(son) => son.iter().map(|link| link.load(Relaxed)).collect(),
            Links::Narrow(son) => (0..2 * (self.mask + 1))
                .map(|index| son.stored(index) as u32)
                .collect(),
        };
        (head, son)
    }

    #[cfg(feature = "write")]
    pub(crate) fn allowance(&self) -> B {
        self.head.allowance()
    }

    /// Finds the matches at `pos` and inserts `pos`, in one descent.
    ///
    /// Pushes `(length, distance)` pairs onto `out` with both strictly
    /// increasing, so each pair is the nearest distance found that reaches its
    /// length, and nothing shorter than four bytes or further than
    /// `max_distance` is reported. Comparing stops at `len_limit`, which must
    /// leave `pos + len_limit` readable; a pair whose length equals it may
    /// really extend further, which the caller measures if it cares. A node
    /// that matches the whole limit gives its place to the new position, since
    /// the two are interchangeable prefixes and the new one is nearer
    /// everything to come. `cut` bounds the nodes visited,
    /// and whatever hangs below the last one is cut off rather than left
    /// dangling. The caller must skip positions with fewer than four bytes
    /// left, as the tree collector does. On allocation refusal, discard the finder:
    /// the insertion may have been partially applied before output growth failed.
    pub(crate) fn matches(
        &mut self,
        input: &[u8],
        pos: usize,
        len_limit: usize,
        max_distance: usize,
        cut: usize,
        out: &mut Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        self.matches_with_extension::<true>(input, pos, len_limit, max_distance, cut, out)
    }

    // The scalar specialization is retained for differential tests only.
    fn matches_with_extension<const FAST: bool>(
        &mut self,
        input: &[u8],
        pos: usize,
        len_limit: usize,
        max_distance: usize,
        cut: usize,
        out: &mut Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        let hash = self.hash(input, pos);
        self.descend::<FAST>(input, pos, hash, len_limit, max_distance, cut, Some(out))
    }

    /// The descent of [`Self::matches`], reporting to `out` when there is one.
    /// It touches only the links of `hash`'s tree and of `pos`'s slot, so
    /// descents for different hashes can run side by side.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn descend<const FAST: bool>(
        &self,
        input: &[u8],
        pos: usize,
        hash: usize,
        len_limit: usize,
        max_distance: usize,
        cut: usize,
        out: Option<&mut Buffer<(u32, u32), B>>,
    ) -> std::result::Result<(), B::Failure> {
        match &self.son {
            Links::Wide(son) => {
                self.descend_in::<FAST, _>(son, input, pos, hash, len_limit, max_distance, cut, out)
            }
            Links::Narrow(son) => {
                self.descend_in::<FAST, _>(son, input, pos, hash, len_limit, max_distance, cut, out)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn descend_in<const FAST: bool, S: Son>(
        &self,
        son: &S,
        input: &[u8],
        pos: usize,
        hash: usize,
        len_limit: usize,
        max_distance: usize,
        cut: usize,
        mut out: Option<&mut Buffer<(u32, u32), B>>,
    ) -> std::result::Result<(), B::Failure> {
        // The tree collector calls this only when at least four bytes remain.
        // Unlike the chain finder, it skips near-end positions before calling.
        debug_assert!(len_limit >= Self::MIN_MATCH && pos + len_limit <= input.len());
        // A load and a store rather than a swap, which would be a locked
        // instruction: no other thread touches this hash.
        let head = &self.head[hash];
        let mut current = resolve(pos, head.load(Relaxed));
        head.store(pos as u32, Relaxed);
        // The two attachment points still waiting for a subtree, starting as
        // the new position's own child slots, and the nodes they belong to.
        // Each step down hangs the node just compared on one of them and
        // moves that side into the node's matching child slot.
        let mut ptr0 = (self.slot(pos) << 1) + 1;
        let mut ptr1 = self.slot(pos) << 1;
        let mut owner0 = pos;
        let mut owner1 = pos;
        // How much of the prefix is proven to match on each side of the
        // descent. Everything below a node compares the same way the node
        // did up to its recorded length, so bytes before the smaller of the
        // two never need reading again.
        let mut len0 = 0usize;
        let mut len1 = 0usize;
        let mut longest = Self::MIN_MATCH - 1;
        let mut budget = cut;
        let mut floor = pos;
        let lowest = pos.saturating_sub(self.mask).max(self.oldest);
        let first = out.as_ref().map_or(0, |out| out.len());
        loop {
            // A candidate that does not step back is a reused slot or the
            // sentinel; one further back than the window has fallen out of it.
            // Either ends the descent, sealing both attachment points so no
            // stale link survives below them. A spent budget ends it the same
            // way, dropping whatever subtree the budget could not reach.
            if current >= floor || current < lowest || budget == 0 {
                son.hang(owner0, ptr0, NO_POSITION);
                son.hang(owner1, ptr1, NO_POSITION);
                return Ok(());
            }
            budget -= 1;
            floor = current;
            let pair = self.slot(current) << 1;
            let mut len = len0.min(len1);
            if input[current + len] == input[pos + len] {
                len += 1;
                if FAST {
                    len +=
                        super::fast::match_length(input, pos + len, pos - current, len_limit - len);
                } else {
                    while len < len_limit && input[current + len] == input[pos + len] {
                        len += 1;
                    }
                }
                if len > longest {
                    if let Some(out) = out.as_deref_mut().filter(|_| pos - current <= max_distance)
                    {
                        let run = (len as u32, (pos - current) as u32);
                        if out.len() - first == Self::MAX_RUNS {
                            // Full: the shortest run gives way, and the
                            // lengths it covered fall to the next one's
                            // distance.
                            out[first..].rotate_left(1);
                            *out.last_mut().expect("a full list holds runs") = run;
                        } else {
                            out.push(run)?;
                        }
                    }
                    longest = len;
                    if len == len_limit {
                        // The node's whole comparable prefix is the new
                        // position's prefix, so the new position adopts its
                        // children and the node drops out as the farther of
                        // two interchangeable candidates.
                        son.hang(owner1, ptr1, son.child(pos, current, pair));
                        son.hang(owner0, ptr0, son.child(pos, current, pair + 1));
                        return Ok(());
                    }
                }
            }
            if input[current + len] < input[pos + len] {
                son.hang_near(owner1, ptr1, current);
                ptr1 = pair + 1;
                owner1 = current;
                len1 = len;
                current = son.next(pos, current, ptr1);
            } else {
                son.hang_near(owner0, ptr0, current);
                ptr0 = pair;
                owner0 = current;
                len0 = len;
                current = son.next(pos, current, ptr0);
            }
        }
    }
}

/// A tree's child links, by the widest window they can serve.
#[derive(Debug)]
enum Links<B: Budget> {
    /// Each child's position, truncated to 32 bits.
    Wide(Buffer<AtomicU32, B>),
    Narrow(NarrowLinks<B>),
}

/// How a tree's descent reads and writes its child links. `index` is a
/// slot's first link, or its second one past it.
trait Son {
    /// The child linked at `index` of `owner`'s slot, or [`NO_POSITION`].
    /// `reference` is the newest position the tree holds.
    fn child(&self, reference: usize, owner: usize, index: usize) -> usize;
    /// [`Self::child`] for a descent, which stops at any candidate not older
    /// than `owner`: where there is no child this can return one of those
    /// rather than [`NO_POSITION`].
    fn next(&self, reference: usize, owner: usize, index: usize) -> usize;
    /// Links `child`, older than `owner`, or [`NO_POSITION`], at `index` of
    /// `owner`'s slot.
    fn hang(&self, owner: usize, index: usize, child: usize);
    /// [`Self::hang`] for a child less than a window older than `owner`.
    fn hang_near(&self, owner: usize, index: usize, child: usize);
}

impl<B: Budget> Son for Buffer<AtomicU32, B> {
    #[inline(always)]
    fn child(&self, reference: usize, _owner: usize, index: usize) -> usize {
        resolve(reference, self[index].load(Relaxed))
    }

    #[inline(always)]
    fn next(&self, reference: usize, owner: usize, index: usize) -> usize {
        self.child(reference, owner, index)
    }

    #[inline(always)]
    fn hang(&self, _owner: usize, index: usize, child: usize) {
        let link = if child == NO_POSITION {
            NO_LINK
        } else {
            child as u32
        };
        self[index].store(link, Relaxed);
    }

    #[inline(always)]
    fn hang_near(&self, owner: usize, index: usize, child: usize) {
        self.hang(owner, index, child);
    }
}

/// Child links as 24-bit distances back from the node holding them, zero for
/// none, three bytes each, low byte first. Bytes rather than a word holding
/// parts of both of a slot's links: a descent then writes a link with three
/// stores and no read.
#[derive(Debug)]
struct NarrowLinks<B: Budget>(Buffer<AtomicU8, B>);

impl<B: Budget> NarrowLinks<B> {
    /// Distances below this fit; it is also the largest window, since a
    /// child no closer than that has fallen out of it.
    const MAX_WINDOW: usize = 1 << 24;

    #[inline(always)]
    fn stored(&self, index: usize) -> usize {
        let bytes = &self.0[3 * index..3 * index + 3];
        usize::from(bytes[0].load(Relaxed))
            | usize::from(bytes[1].load(Relaxed)) << 8
            | usize::from(bytes[2].load(Relaxed)) << 16
    }

    #[inline(always)]
    fn store(&self, index: usize, distance: usize) {
        let bytes = &self.0[3 * index..3 * index + 3];
        bytes[0].store(distance as u8, Relaxed);
        bytes[1].store((distance >> 8) as u8, Relaxed);
        bytes[2].store((distance >> 16) as u8, Relaxed);
    }
}

impl<B: Budget> Son for NarrowLinks<B> {
    #[inline(always)]
    fn child(&self, _reference: usize, owner: usize, index: usize) -> usize {
        match self.stored(index) {
            0 => NO_POSITION,
            // A handed-on tree's slots can still hold distances from before
            // its history, which reach back past its first position.
            distance => owner.checked_sub(distance).unwrap_or(NO_POSITION),
        }
    }

    /// No child reads back as `owner` itself, and a distance past the first
    /// position wraps to above it.
    #[inline(always)]
    fn next(&self, _reference: usize, owner: usize, index: usize) -> usize {
        owner.wrapping_sub(self.stored(index))
    }

    #[inline(always)]
    fn hang(&self, owner: usize, index: usize, child: usize) {
        let distance = match child {
            NO_POSITION => 0,
            child => {
                debug_assert!(child < owner);
                Some(owner - child)
                    .filter(|&distance| distance < Self::MAX_WINDOW)
                    .unwrap_or(0)
            }
        };
        self.store(index, distance);
    }

    #[inline(always)]
    fn hang_near(&self, owner: usize, index: usize, child: usize) {
        debug_assert!(child < owner && owner - child < Self::MAX_WINDOW);
        self.store(index, owner - child);
    }
}

/// How many threads, by hash, to put `positions` of history into a tree on:
/// as many as this thread may fan out to, but no more than give each a share
/// worth its while, since every share reads every position to find its own.
#[cfg(feature = "write")]
pub(crate) fn seed_shares(positions: usize) -> usize {
    const MIN_SHARE: usize = 256 * 1024;
    if crate::parallel::may_nest() {
        crate::parallel::threads().min(positions / MIN_SHARE).max(1)
    } else {
        1
    }
}

/// About how much of putting `positions` of `input` into a tree falls to the
/// busiest of `shares` hash shares, as a fraction of the whole, from a sample
/// of the positions. A share's hashes go in on one thread, so this much of
/// the work is done in sequence however many threads there are: in machine
/// code, say, where runs of zeroes all have one hash.
#[cfg(feature = "write")]
pub(crate) fn seed_skew(input: &[u8], positions: std::ops::Range<usize>, shares: usize) -> f64 {
    const STEP: usize = 7;
    let bits = TreeMatchFinder::<Allowance>::HASH_BITS;
    let shares = shares.max(1);
    let end = positions.end.min(
        input
            .len()
            .saturating_sub(TreeMatchFinder::<Allowance>::MIN_MATCH - 1),
    );
    let mut counts = vec![0usize; shares];
    for pos in (positions.start..end).step_by(STEP) {
        let bytes = [input[pos], input[pos + 1], input[pos + 2], input[pos + 3]];
        counts[(mix(u32::from_le_bytes(bytes), bits) * shares) >> bits] += 1;
    }
    let total: usize = counts.iter().sum();
    let busiest = counts.into_iter().max().unwrap_or(0);
    if total == 0 {
        1.0
    } else {
        busiest as f64 / total as f64
    }
}

/// One tree that seeds the trees of several runs over one window, so history
/// the runs share goes in once rather than once per run.
///
/// A run's tree holds the dictionary before it, every position put in by a
/// descent. A position's place in its hash's tree depends only on the
/// positions newer than it, since each insertion puts the new position at the
/// root and splits the tree beneath it. So a tree that took in more history
/// than a run's, from further back, holds the run's tree within it: the
/// older positions only ever hang below the run's, and a descent reaches them
/// after it has passed every position the run's own tree has. A descent's
/// `cut` is spent in the same order, so it stops at the same position or
/// among the older ones. Cutting the older positions off as a run's tree is
/// copied out leaves exactly the tree the run would have seeded.
///
/// The tree is built a hash share per thread. Its window is the dictionary,
/// and positions older than the history being seeded count as out of it, so
/// no slot an insertion overwrites can be reached by another thread's
/// descent.
#[cfg(feature = "write")]
#[derive(Debug)]
pub(crate) struct SeedTree<B: Budget = Allowance> {
    tree: TreeMatchFinder<B>,
    /// The first position not yet inserted.
    next: usize,
}

#[cfg(feature = "write")]
impl<B: Budget> SeedTree<B> {
    /// What [`Self::with_allowance`] allocates for a dictionary of `reach`.
    pub(crate) fn bytes_for_reach(reach: usize) -> usize {
        TreeMatchFinder::<B>::bytes_for_window(reach)
    }

    /// A seed tree for histories up to `reach` long.
    pub(crate) fn with_allowance(reach: usize, allowance: &B) -> Result<Self> {
        Ok(Self {
            tree: TreeMatchFinder::with_allowance(reach, allowance)?,
            next: 0,
        })
    }

    /// The tree [`TreeMatchFinder::seeded`] builds for `window` from
    /// `history` of `input`, with positions counted from `history.start`, as
    /// a run whose input starts there counts them.
    ///
    /// Histories must come in order, neither end before the last one's, and
    /// none longer than the reach. Every position of a history must be
    /// inserted at the same `len_limit` as any later history's run would
    /// insert it at.
    pub(crate) fn seed(
        &mut self,
        input: &[u8],
        history: std::ops::Range<usize>,
        window: usize,
        len_limit: impl Fn(usize) -> usize + Sync,
        cut: usize,
        allowance: &B,
    ) -> Result<TreeMatchFinder<B>> {
        self.insert(input, history.clone(), len_limit, cut);
        self.copy(input, history, window, allowance)
    }

    /// [`Self::seed`] for the last history, handing on the seed tree itself
    /// where it can stand for the copy: where its window is the run's and its
    /// links are distances, which need no rebasing. Its slots are left where
    /// they are, offset from the run's positions.
    pub(crate) fn finish(
        mut self,
        input: &[u8],
        history: std::ops::Range<usize>,
        window: usize,
        len_limit: impl Fn(usize) -> usize + Sync,
        cut: usize,
        allowance: &B,
    ) -> Result<TreeMatchFinder<B>> {
        self.insert(input, history.clone(), len_limit, cut);
        let Some(newest) = history.end.checked_sub(1) else {
            return self.copy(input, history, window, allowance);
        };
        if window.max(1).next_power_of_two() != self.tree.mask + 1
            || !matches!(self.tree.son, Links::Narrow(_))
        {
            return self.copy(input, history, window, allowance);
        }
        let base = history.start;
        for head in self.tree.head.iter() {
            let link = match resolve(newest, head.load(Relaxed)) {
                NO_POSITION => NO_LINK,
                pos if pos < base => NO_LINK,
                pos => (pos - base) as u32,
            };
            head.store(link, Relaxed);
        }
        self.tree.shift = base & self.tree.mask;
        self.tree.oldest = 0;
        Ok(self.tree)
    }

    fn insert(
        &mut self,
        input: &[u8],
        history: std::ops::Range<usize>,
        len_limit: impl Fn(usize) -> usize + Sync,
        cut: usize,
    ) {
        debug_assert!(history.start >= self.tree.oldest && history.end >= self.next);
        debug_assert!(history.len() <= self.tree.mask + 1);
        self.tree.oldest = history.start;
        let from = self.next.max(history.start);
        let shares = seed_shares(history.end - from);
        self.tree
            .insert_range(input, from..history.end, &len_limit, cut, shares);
        self.next = history.end;
    }

    /// `history`'s part of the tree, in a finder of its own for `window`.
    fn copy(
        &self,
        input: &[u8],
        history: std::ops::Range<usize>,
        window: usize,
        allowance: &B,
    ) -> Result<TreeMatchFinder<B>> {
        let copy = TreeMatchFinder::with_allowance(window, allowance)?;
        debug_assert!(history.len() <= copy.mask + 1);
        let Some(newest) = history.end.checked_sub(1) else {
            return Ok(copy);
        };
        let base = history.start;
        // A link to a position before the history is a link to nothing in
        // the run's tree.
        let rebase = |link: u32| match resolve(newest, link) {
            NO_POSITION => NO_LINK,
            pos if pos < base => NO_LINK,
            pos => (pos - base) as u32,
        };
        for (to, from) in copy.head.iter().zip(self.tree.head.iter()) {
            to.store(rebase(from.load(Relaxed)), Relaxed);
        }
        // A child before the history is no child in the run's tree.
        let rebase = |pos: usize| match pos {
            NO_POSITION => NO_POSITION,
            pos if pos < base => NO_POSITION,
            pos => pos - base,
        };
        // Only positions that were inserted have links of their own.
        let end = history.end.min(
            input
                .len()
                .saturating_sub(TreeMatchFinder::<B>::MIN_MATCH - 1),
        );
        let span = end.saturating_sub(base);
        let pieces = seed_shares(span);
        crate::parallel::spread(pieces, |piece| {
            let first = base + span * piece / pieces;
            let last = base + span * (piece + 1) / pieces;
            for pos in first..last {
                let from = self.tree.slot(pos) << 1;
                let to = copy.slot(pos - base) << 1;
                for side in 0..2 {
                    let child = self.tree.child(newest, pos, from + side);
                    copy.hang(pos - base, to + side, rebase(child));
                }
            }
        });
        Ok(copy)
    }
}

/// Where the same long stretch of bytes last began, for a match finder that
/// stops at a nice length.
///
/// A finder that stops at the first match long enough to commit to finds the
/// nearest copy of a prefix, and the copy that runs on can be further back.
/// The tree cannot hold that one: a node that matches the new position as far
/// as the descent compares gives its place to it, so it keeps one position
/// for every distinct prefix of the nice length, the newest. This keeps one
/// for every distinct `span` bytes instead, by a rolling hash of the `span`
/// bytes at each position, so the newest earlier position with the same hash
/// is the nearest copy of the whole stretch, which a parse can take as the
/// longest match there is.
///
/// Positions go in one at a time, in order. What it holds at a position is a
/// property of the bytes before it and nothing else, so two parses of the same
/// window that searched different positions see the same candidates.
#[cfg(feature = "write")]
#[derive(Debug)]
pub(crate) struct WindowIndex<B: Budget = Allowance> {
    table: Buffer<u32, B>,
    shift: u32,
    span: usize,
    /// The weight of a window's first byte, for rolling it out.
    first_weight: u64,
    hash: u64,
    /// The position `hash` covers, or [`NO_POSITION`] before the first.
    at: usize,
}

#[cfg(feature = "write")]
impl<B: Budget> WindowIndex<B> {
    const MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

    /// An index of `span`-byte stretches for a window this long, a slot for
    /// every sixteen positions in it, between 4,096 and 262,144 slots: at most
    /// a mebibyte. Slots are shared by hash and the newest position takes one,
    /// so a stretch further back than a few times the slot count has usually
    /// been overwritten. A stretch that repeats is found at its nearest copy,
    /// which is the one worth finding.
    pub(crate) fn with_allowance(window: usize, span: usize, allowance: &B) -> Result<Self> {
        let slots = (window / 16).clamp(1 << 12, 1 << 18).next_power_of_two();
        let first_weight = (1..span).fold(1u64, |weight, _| weight.wrapping_mul(Self::MULTIPLIER));
        Ok(Self {
            table: Buffer::filled(slots, NO_LINK, allowance)?,
            shift: 64 - slots.trailing_zeros(),
            span,
            first_weight,
            hash: 0,
            at: NO_POSITION,
        })
    }

    /// Takes `pos` in and returns the newest earlier position whose `span`
    /// bytes hashed the same, or [`NO_POSITION`]. A position with fewer than
    /// `span` bytes left has no stretch to index. The caller confirms a
    /// candidate by comparing bytes, since a hash can collide.
    pub(crate) fn insert(&mut self, input: &[u8], pos: usize) -> usize {
        let Some(last) = pos.checked_add(self.span).filter(|&end| end <= input.len()) else {
            self.at = NO_POSITION;
            return NO_POSITION;
        };
        if self.at != NO_POSITION && self.at + 1 == pos {
            let outgoing = u64::from(input[pos - 1]).wrapping_mul(self.first_weight);
            self.hash = self
                .hash
                .wrapping_sub(outgoing)
                .wrapping_mul(Self::MULTIPLIER)
                .wrapping_add(u64::from(input[last - 1]));
        } else {
            self.hash = input[pos..last].iter().fold(0u64, |hash, &byte| {
                hash.wrapping_mul(Self::MULTIPLIER)
                    .wrapping_add(u64::from(byte))
            });
        }
        self.at = pos;
        let slot = self.slot(self.hash);
        let previous = resolve(pos, self.table[slot]);
        self.table[slot] = pos as u32;
        previous
    }

    fn slot(&self, hash: u64) -> usize {
        (hash.wrapping_mul(Self::MULTIPLIER) >> self.shift) as usize
    }

    /// The distances back to the newest earlier copies of the stretches that
    /// start just after `pos`, the position last inserted, one for each of
    /// the next `ahead.len()` positions that has a stretch, nearest stretch
    /// first and [`NO_POSITION`] where there is none.
    ///
    /// A slot is shared, so one stretch's copy is lost whenever a stretch
    /// inserted after it hashes to the same slot. Over a repeat the same
    /// stretches meet the same neighbours every time round, so a stretch that
    /// lost its copy once loses it every time. Asking after its neighbours as
    /// well finds the copy through any one that kept theirs; nothing older
    /// than `pos` has been inserted for them, so their copies are where the
    /// table left them. A match at one of these distances starts at `pos` only
    /// if the bytes before the stretch match too, which the caller measures.
    pub(crate) fn distances_ahead(&self, input: &[u8], pos: usize, ahead: &mut [usize]) {
        ahead.fill(NO_POSITION);
        if self.at != pos {
            return;
        }
        let mut hash = self.hash;
        for (step, distance) in (1..).zip(ahead.iter_mut()) {
            let start = pos + step;
            let Some(&incoming) = input.get(start + self.span - 1) else {
                return;
            };
            let outgoing = u64::from(input[start - 1]).wrapping_mul(self.first_weight);
            hash = hash
                .wrapping_sub(outgoing)
                .wrapping_mul(Self::MULTIPLIER)
                .wrapping_add(u64::from(incoming));
            let copy = resolve(pos, self.table[self.slot(hash)]);
            if copy < pos {
                *distance = start - copy;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve, MatchFinder, TreeMatchFinder, NO_LINK, NO_POSITION};

    /// Four repeats of the same four bytes, so every position shares a hash and
    /// they form one chain.
    const REPEATED: &[u8] = b"abcdabcdabcdabcd";

    #[test]
    fn a_chain_walks_from_the_nearest_candidate_to_the_furthest() {
        let mut finder = MatchFinder::<4>::new(REPEATED.len());
        for pos in [0, 4, 8] {
            finder.insert(REPEATED, pos);
        }

        let mut walked = Vec::new();
        let mut candidate = finder.first(REPEATED, 12);
        while candidate != NO_POSITION {
            walked.push(candidate);
            candidate = finder.previous(candidate);
        }
        assert_eq!(walked, [8, 4, 0]);
    }

    #[test]
    fn a_position_that_has_fallen_out_of_the_window_still_names_itself() {
        // A candidate three thousand bytes back, found through a window of
        // sixty-four. It reads back as the position it named rather than as
        // something inside the window, which is what leaves the caller to
        // reject it on distance.
        let data = vec![b'x'; 4096];
        let mut finder = MatchFinder::<4>::new(64);
        finder.insert(&data, 0);
        finder.insert(&data, 2048);
        assert_eq!(finder.first(&data, 3000), 2048);
        assert_eq!(finder.previous(2048), 0);
    }

    #[test]
    fn resolving_recovers_a_position_stored_below_four_gigabytes() {
        assert_eq!(resolve(1_000, 0), 0);
        assert_eq!(resolve(1_000, 999), 999);
        assert_eq!(resolve(1_000, 1_000), 1_000);
        assert_eq!(resolve(1_000, NO_LINK), NO_POSITION);
    }

    #[allow(clippy::too_many_arguments)]
    fn ordinary_chain_frontier<B: super::Budget>(
        finder: &MatchFinder<4, B>,
        input: &[u8],
        pos: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
        nice: usize,
        out: &mut super::Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        if cut == 0 {
            return Ok(());
        }
        let mut longest = 0;
        let mut checked = 0;
        let mut candidate = finder.first(input, pos);
        while candidate != NO_POSITION && longest < max_length && longest < nice {
            if candidate >= pos {
                candidate = finder.previous(candidate);
                continue;
            }
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            if input[candidate + longest] == input[pos + longest] {
                let length = super::super::fast::match_length(input, pos, distance, max_length);
                if length > longest {
                    out.push((length as u32, distance as u32))?;
                    longest = length;
                }
            }
            if checked >= cut {
                break;
            }
            candidate = finder.previous(candidate);
        }
        Ok(())
    }

    #[test]
    fn raw_fused_frontiers_preserve_collisions_overlap_cut_and_expiry() {
        let mut random = Vec::with_capacity(24 * 1024);
        let mut state = 0x7a59_1234_aa55_0123u64;
        for _ in 0..24 * 1024 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            random.push(state as u8);
        }
        let patterned = b"abcdabcdXYZabcdabcdXYQ----abcdabcdXYZabcdabcdXYR".repeat(48);
        for input in [&random[..], &patterned[..]] {
            for (window, cut, cap, nice) in [
                (1, 0, 4, 512),
                (8, 1, 17, 8),
                (64, 2, 65, 512),
                (4096, 128, 513, 512),
                (65536, 128, 4096, 512),
            ] {
                let mut fused = MatchFinder::<4>::new(window);
                let mut ordinary = MatchFinder::<4>::new(window);
                let allowance = super::Allowance::default();
                let mut actual = super::Buffer::new(&allowance);
                let mut wide = super::Buffer::new(&allowance);
                let mut expected = super::Buffer::new(&allowance);
                for pos in 0..input.len() - 3 {
                    let first = fused.insert_and_first(input, pos);
                    ordinary.insert(input, pos);
                    actual.clear();
                    wide.clear();
                    expected.clear();
                    let limit = cap.min(input.len() - pos);
                    let distance = pos.min(window);
                    ordinary_chain_frontier(
                        &ordinary,
                        input,
                        pos,
                        limit,
                        distance,
                        cut,
                        nice,
                        &mut expected,
                    )
                    .unwrap();
                    fused
                        .collect_improving(
                            input,
                            pos,
                            first,
                            limit,
                            distance,
                            cut,
                            nice,
                            &mut actual,
                        )
                        .unwrap();
                    fused
                        .collect_improving_with_positions::<false>(
                            input, pos, first, limit, distance, cut, nice, &mut wide,
                        )
                        .unwrap();
                    assert_eq!(&wide[..], &expected[..]);
                    assert_eq!(
                        &actual[..],
                        &expected[..],
                        "position {pos}, window {window}, cut {cut}"
                    );
                }
            }
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn raw_fused_insertion_preserves_wrapped_positions_and_sentinel() {
        let wrap = 1usize << 32;
        let mut fused = MatchFinder::<4>::new(64);
        let mut ordinary = MatchFinder::<4>::new(64);
        for pos in [wrap - 5, wrap - 1, wrap, wrap + 16, wrap + 70000] {
            let actual = fused.record_and_first(0, pos);
            ordinary.prev[pos & ordinary.mask] = ordinary.head[0];
            ordinary.head[0] = pos as u32;
            ordinary.newest = ordinary.newest.max(pos);
            let mut expected = resolve(ordinary.newest, ordinary.head[0]);
            if expected != NO_POSITION && expected >= pos {
                expected = ordinary.previous(expected);
            }
            assert_eq!(actual, expected, "position {pos}");
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn raw_fused_predecessor_specializations_preserve_stale_links_and_wrap() {
        let wrap = 1usize << 32;
        let mut finder = MatchFinder::<4>::new(64);
        for (newest, candidate, raw) in [
            (64, 32, 0),
            (64, 32, 32),
            (64, 32, 63),
            (64, 32, NO_LINK),
            (wrap - 1, wrap - 2, 0),
            (wrap - 1, wrap - 2, NO_LINK),
            (wrap + 16, wrap + 8, 0),
            (wrap + 16, wrap + 8, 32),
            (wrap + 16, wrap + 8, NO_LINK),
            (wrap + 16, 8, 0),
        ] {
            finder.newest = newest;
            finder.prev[candidate & finder.mask] = raw;
            let expected = finder.previous(candidate);
            assert_eq!(finder.previous_for_collection::<false>(candidate), expected);
            if newest <= u32::MAX as usize {
                assert_eq!(finder.previous_for_collection::<true>(candidate), expected);
            }
        }
    }

    #[test]
    fn raw_tree_fast_extension_preserves_runs_and_complete_topology() {
        let mut input = b"abcdabcdXYZabcdabcdXYQ----abcdabcdXYZabcdabcdXYR".repeat(128);
        input.extend(std::iter::repeat_n(b'z', 2048));
        for (window, cut, cap) in [(8, 0, 4), (64, 1, 17), (256, 2, 512), (8192, 128, 513)] {
            let mut scalar = TreeMatchFinder::new(window);
            let mut fast = TreeMatchFinder::new(window);
            let allowance = super::Allowance::default();
            let mut expected = super::Buffer::new(&allowance);
            let mut actual = super::Buffer::new(&allowance);
            for pos in 0..input.len() - 3 {
                expected.clear();
                actual.clear();
                let limit = cap.min(input.len() - pos);
                let distance = pos.min(window.saturating_sub(1));
                scalar
                    .matches_with_extension::<false>(
                        &input,
                        pos,
                        limit,
                        distance,
                        cut,
                        &mut expected,
                    )
                    .unwrap();
                fast.matches_with_extension::<true>(&input, pos, limit, distance, cut, &mut actual)
                    .unwrap();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "position {pos}, window {window}, cut {cut}"
                );
                // Only this hash and the touched child slots can change.
                // Compare the full topology periodically and at final expiry.
                if pos % 127 == 0 || pos == input.len() - 4 {
                    assert_eq!(fast.links(), scalar.links());
                }
            }
        }
    }

    fn raw_collision_fixture() -> Vec<u8> {
        let prefix = b"abcd";
        let finder = MatchFinder::<4>::new(64);
        let hash = finder.hash(prefix, 0);
        let collision = (0u32..1 << 24)
            .find_map(|upper| {
                let word = (u32::from(b'a') | (upper << 8)).to_le_bytes();
                (word[1] != b'b' && finder.hash(&word, 0) == hash).then_some(word)
            })
            .unwrap();
        let mut input = vec![0; 48];
        input[..12].copy_from_slice(b"abcdlongtail");
        input[16..20].copy_from_slice(&collision);
        input[32..44].copy_from_slice(b"abcdlongtail");
        input
    }

    #[test]
    fn raw_fused_subfour_runs_preserve_allocation_refusal_and_cleanup() {
        use super::super::workspace::RefusingBudget;
        let input = raw_collision_fixture();
        let probe = RefusingBudget::new(usize::MAX);
        let mut finder = MatchFinder::<4, _>::with_allowance(64, &probe).unwrap();
        finder.insert(&input, 0);
        finder.insert(&input, 16);
        let first = finder.insert_and_first(&input, 32);
        let mut runs = super::Buffer::new(&probe);
        finder
            .collect_improving(&input, 32, first, 12, 32, 128, 512, &mut runs)
            .unwrap();
        assert_eq!(runs[0].0, 1);
        assert_eq!(runs[1], (12, 32));
        let attempts = probe.attempts();
        drop((runs, finder));
        assert_eq!(probe.used(), 0);
        for fail_at in 0..attempts {
            let fused_budget = RefusingBudget::new(fail_at);
            let ordinary_budget = RefusingBudget::new(fail_at);
            let run = |budget: &RefusingBudget, fused: bool| {
                let mut finder = MatchFinder::<4, _>::with_allowance(64, budget)?;
                finder.insert(&input, 0);
                finder.insert(&input, 16);
                let first = if fused {
                    finder.insert_and_first(&input, 32)
                } else {
                    finder.insert(&input, 32);
                    finder.first(&input, 32)
                };
                let mut output = super::Buffer::new(budget);
                if fused {
                    finder.collect_improving(&input, 32, first, 12, 32, 128, 512, &mut output)
                } else {
                    ordinary_chain_frontier(&finder, &input, 32, 12, 32, 128, 512, &mut output)
                }
            };
            assert_eq!(run(&fused_budget, true), run(&ordinary_budget, false));
            assert_eq!(fused_budget.attempts(), ordinary_budget.attempts());
            assert_eq!(fused_budget.used(), 0);
            assert_eq!(ordinary_budget.used(), 0);
        }
    }

    /// Every improving match at each position of `input`, walked in order the
    /// way the optimal parse's collector does.
    fn tree_matches_at_every_position(input: &[u8], cut: usize) -> Vec<Vec<(u32, u32)>> {
        let mut finder = TreeMatchFinder::new(input.len());
        let mut all = Vec::new();
        for pos in 0..input.len() {
            let mut out = super::Buffer::new(&super::Allowance::default());
            if pos + 4 <= input.len() {
                let len_limit = input.len() - pos;
                finder
                    .matches(input, pos, len_limit, pos, cut, &mut out)
                    .unwrap();
            }
            all.push(out.into_vec());
        }
        all
    }

    #[test]
    fn the_tree_reports_the_nearest_distance_for_each_length() {
        // At the last "abcd" the nearest candidate matches everything there is,
        // so it is the only report; nothing farther can improve on it.
        let all = tree_matches_at_every_position(REPEATED, usize::MAX);
        assert_eq!(all[12], [(4, 4)]);
        // At position 8 both distances 4 and 8 match 8 bytes; only the nearer
        // is worth reporting.
        assert_eq!(all[8], [(8, 4)]);
    }

    #[test]
    fn the_tree_reports_runs_of_increasing_length_and_distance() {
        // "abc" twelve bytes back, "abcde" twenty-two back. The parse wants
        // both: the nearer is cheaper at its length, the farther reaches
        // longer.
        let input = b"abcdeXXXXX_abcdfYYYY__abcdeZZ";
        let all = tree_matches_at_every_position(input, usize::MAX);
        assert_eq!(all[22], [(4, 11), (5, 22)]);
    }

    #[test]
    fn a_position_reports_at_most_eight_runs_and_keeps_the_longest() {
        // Two-symbol noise, where a descent lengthens its match a byte at a
        // time and would report a run for each step.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let input: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b'a' + (state & 1) as u8
            })
            .collect();
        let all = tree_matches_at_every_position(&input, usize::MAX);
        let mut capped = 0;
        for (pos, runs) in all.iter().enumerate() {
            assert!(runs.len() <= TreeMatchFinder::<super::Allowance>::MAX_RUNS);
            assert!(runs.windows(2).all(|pair| pair[0].0 < pair[1].0));
            capped += usize::from(runs.len() == TreeMatchFinder::<super::Allowance>::MAX_RUNS);
            let longest = (1..=pos)
                .map(|distance| {
                    (0..input.len() - pos)
                        .take_while(|&at| input[pos + at] == input[pos + at - distance])
                        .count()
                })
                .max()
                .unwrap_or(0);
            let reported = runs.last().map_or(0, |&(length, _)| length as usize);
            assert_eq!(reported, if longest >= 4 { longest } else { 0 }, "{pos}");
        }
        assert!(capped > 0, "the noise never filled a position's runs");
    }

    #[test]
    #[cfg(feature = "write")]
    fn a_stretch_is_found_at_its_nearest_earlier_copy() {
        // Noise repeating every 300 bytes, with a stray byte in the third
        // copy. Each 64-byte stretch's nearest earlier copy is a whole number
        // of periods back, the fewest that miss the stray byte.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let period: Vec<u8> = (0..300)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let mut input = period.repeat(5);
        input[700] ^= 1;
        // The most slots there are, so no two of these stretches share one.
        let mut index =
            super::WindowIndex::with_allowance(1 << 22, 64, &super::Allowance::default()).unwrap();
        // The stray byte breaks every stretch over it, and its copies.
        let stray = |start: usize| (start..start + 64).contains(&700);
        let nearest_copy = |start: usize| {
            (1..=start / 300)
                .map(|periods| start - periods * 300)
                .find(|&copy| !stray(start) && !stray(copy))
        };
        let mut ahead = [0; 4];
        for pos in 0..input.len() {
            let found = index.insert(&input, pos);
            if pos + 64 > input.len() {
                assert_eq!(found, NO_POSITION, "{pos}");
                continue;
            }
            assert_eq!(found, nearest_copy(pos).unwrap_or(NO_POSITION), "{pos}");

            // The stretches after this one, asked after from here, report
            // their own nearest copies.
            index.distances_ahead(&input, pos, &mut ahead);
            for (step, &distance) in (1..).zip(&ahead) {
                let start = pos + step;
                let expected = if start + 64 > input.len() {
                    NO_POSITION
                } else {
                    nearest_copy(start).map_or(NO_POSITION, |copy| start - copy)
                };
                assert_eq!(distance, expected, "{pos} + {step}");
            }
        }
    }

    #[test]
    fn a_spent_budget_ends_the_descent_but_keeps_what_it_found() {
        let input = b"abcdeXXXXX_abcdfYYYY__abcdeZZ";
        let all = tree_matches_at_every_position(input, 1);
        assert_eq!(all[22], [(4, 11)]);
    }

    #[test]
    fn the_tree_drops_candidates_outside_its_window() {
        let input = vec![b'x'; 4096];
        let mut finder = TreeMatchFinder::new(64);
        let mut matches = super::Buffer::new(&super::Allowance::default());
        finder.matches(&input, 0, 16, 0, 8, &mut matches).unwrap();
        finder
            .matches(&input, 2048, 16, 2048, 8, &mut matches)
            .unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn the_tree_does_not_report_matches_beyond_the_requested_distance() {
        let input = vec![b'x'; 64];
        let mut finder = TreeMatchFinder::new(64);
        let mut matches = super::Buffer::new(&super::Allowance::default());
        finder.matches(&input, 0, 16, 0, 8, &mut matches).unwrap();
        finder.matches(&input, 16, 16, 8, 8, &mut matches).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    #[cfg(feature = "write")]
    fn heads_follow_the_reach_between_the_default_and_a_mebibyte() {
        let heads = |reach| MatchFinder::<3>::for_reach(reach, reach).head.len();
        assert_eq!(heads(1000), 1 << 16);
        assert_eq!(heads(300_000), 1 << 19);
        assert_eq!(heads(1 << 20), 1 << 20);
        assert_eq!(heads(4 << 20), 1 << 20);
        assert_eq!(MatchFinder::<4>::for_reach(1000, 1000).head.len(), 1 << 17);
    }

    #[test]
    #[cfg(feature = "write")]
    fn the_long_match_finder_takes_two_heads_per_position_of_reach() {
        let heads = |reach| MatchFinder::<32>::for_reach(reach, reach).head.len();
        assert_eq!(heads(1000), 1 << 17);
        assert_eq!(heads(1 << 20), 1 << 21);
        assert_eq!(heads(4 << 20), 1 << 23);
        assert_eq!(heads(16 << 20), 1 << 23);
        assert_eq!(
            MatchFinder::<6>::for_reach(4 << 20, 4 << 20).head.len(),
            1 << 20
        );
    }

    #[test]
    #[cfg(feature = "write")]
    fn a_finder_for_a_reach_is_priced_at_what_it_allocates() {
        for (window, reach) in [(1, 1), (1000, 1000), (5000, 4 << 20), (6 << 20, 4 << 20)] {
            let finder = MatchFinder::<4>::for_reach(window, reach);
            assert_eq!(
                MatchFinder::<4>::bytes_for_reach(window, reach),
                4 * (finder.head.len() + finder.prev.len()) as u64,
                "window {window}, reach {reach}"
            );
            let finder = MatchFinder::<32>::for_reach(window, reach);
            assert_eq!(
                MatchFinder::<32>::bytes_for_reach(window, reach),
                4 * (finder.head.len() + finder.prev.len()) as u64,
                "long finder, window {window}, reach {reach}"
            );
        }
    }

    #[test]
    fn a_refused_tree_child_table_releases_its_head_table() {
        let head_bytes = (1 << 17) * std::mem::size_of::<u32>();
        let allowance = super::Allowance::limited(head_bytes as u64);
        assert!(TreeMatchFinder::with_allowance(64, &allowance).is_err());
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn a_node_matching_the_whole_limit_hands_its_children_to_the_new_position() {
        // Degenerate data: every position matches every earlier one to the
        // limit, so each descent must stop at its first node rather than walk
        // them all. Matching to the limit and improving on nothing are the
        // only exits that leave a single report.
        let input = vec![b'z'; 512];
        let all = tree_matches_at_every_position(&input, usize::MAX);
        for (pos, matches) in all.iter().enumerate().skip(1).take(507) {
            assert_eq!(
                matches.as_slice(),
                [((input.len() - pos) as u32, 1)],
                "position {pos} did not stop at its nearest candidate",
            );
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn resolving_recovers_a_position_stored_past_four_gigabytes() {
        // The one path no member that fits in this machine's memory reaches: an
        // input long enough that positions lose their high half. Measuring back
        // from the newest position recovers them while the two are within four
        // gigabytes of each other, which the window guarantees.
        const FOUR_GIB: usize = 1 << 32;
        let newest = FOUR_GIB + 16;
        assert_eq!(resolve(newest, 16), newest);
        assert_eq!(resolve(newest, 1), FOUR_GIB + 1);
        assert_eq!(resolve(newest, 0), FOUR_GIB);
        // Below the boundary the stored half wrapped and `newest` did not, so
        // the two are only comparable through the subtraction.
        assert_eq!(resolve(newest, u32::MAX - 1), FOUR_GIB - 2);
    }

    /// Few symbols with long copies, so descents run deep, hit the cut and
    /// match whole limits.
    #[cfg(all(feature = "write", feature = "parallel"))]
    fn busy_input(len: usize) -> Vec<u8> {
        let mut state = 0x5eed_7ee5_0b5e_1234u64;
        let mut input: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"abcd"[(state % 4) as usize]
            })
            .collect();
        input.copy_within(0..len / 8, len / 3);
        input.copy_within(len / 3..len / 3 + len / 8, len / 2);
        input
    }

    /// Each run's tree, seeded alone with its history split between threads
    /// or out of a shared seed tree, is the one it would have seeded on its
    /// own on one thread, link for link, on any number of threads: for runs
    /// whose history is the start of the input, runs a whole reach in, and
    /// a run whose history starts past everything seeded before it.
    #[test]
    #[cfg(all(feature = "write", feature = "parallel"))]
    fn a_seed_tree_hands_each_run_the_tree_it_would_have_seeded() {
        const KIB: usize = 1024;
        let input = busy_input(5 * 1024 * KIB);
        let reach = 1024 * KIB;
        let (nice, cut) = (48, 12);
        let allowance = super::Allowance::default();
        let runs = [
            512 * KIB..1024 * KIB,
            1024 * KIB..1536 * KIB,
            1536 * KIB..2048 * KIB,
            2048 * KIB..3072 * KIB,
            4608 * KIB..5 * 1024 * KIB,
        ];
        let window = |run: &std::ops::Range<usize>| reach.min(run.end);
        let history = |run: &std::ops::Range<usize>| run.start.saturating_sub(reach)..run.start;
        let expected: Vec<_> = runs
            .iter()
            .map(|run| {
                let base = history(run).start;
                let own = &input[base..run.end];
                TreeMatchFinder::seeded(
                    window(run),
                    own,
                    0..run.start - base,
                    |pos| (own.len() - pos).min(nice),
                    cut,
                    1,
                    &allowance,
                )
                .unwrap()
                .links()
            })
            .collect();
        for threads in [1, 2, 8] {
            crate::parallel::private_pool(threads).install(|| {
                for (run, expected) in runs.iter().zip(&expected) {
                    let base = history(run).start;
                    let own = &input[base..run.end];
                    let split = TreeMatchFinder::seeded(
                        window(run),
                        own,
                        0..run.start - base,
                        |pos| (own.len() - pos).min(nice),
                        cut,
                        super::seed_shares(run.start - base),
                        &allowance,
                    )
                    .unwrap();
                    assert!(
                        split.links() == *expected,
                        "run {run:?} seeded alone at {threads} threads differs"
                    );
                }
                let mut seed = super::SeedTree::with_allowance(reach, &allowance).unwrap();
                for (run, expected) in runs.iter().zip(&expected) {
                    let tree = seed
                        .seed(
                            &input,
                            history(run),
                            window(run),
                            |pos| (input.len() - pos).min(nice),
                            cut,
                            &allowance,
                        )
                        .unwrap();
                    assert!(
                        tree.links() == *expected,
                        "run {run:?} at {threads} threads differs"
                    );
                }
            });
        }
    }

    #[test]
    #[cfg(all(feature = "write", feature = "parallel"))]
    fn narrow_links_find_what_wide_links_find() {
        let input = busy_input(256 * 1024);
        let allowance = super::Allowance::default();
        for (window, cut, nice) in [(64, 4, 16), (4096, 16, 48), (64 * 1024, 128, 273)] {
            let mut narrow = TreeMatchFinder::new(window);
            let mut wide = TreeMatchFinder::with_wide_links(window);
            assert!(matches!(narrow.son, super::Links::Narrow(_)));
            let mut expected = super::Buffer::new(&allowance);
            let mut actual = super::Buffer::new(&allowance);
            for pos in 0..input.len() - 3 {
                expected.clear();
                actual.clear();
                let limit = nice.min(input.len() - pos);
                let distance = pos.min(window - 1);
                wide.matches(&input, pos, limit, distance, cut, &mut expected)
                    .unwrap();
                narrow
                    .matches(&input, pos, limit, distance, cut, &mut actual)
                    .unwrap();
                assert_eq!(
                    &actual[..],
                    &expected[..],
                    "position {pos}, window {window}"
                );
            }
        }
    }

    #[test]
    #[cfg(all(feature = "write", feature = "parallel"))]
    fn a_seed_tree_handed_on_finds_what_the_last_runs_own_tree_finds() {
        const KIB: usize = 1024;
        let input = busy_input(1024 * KIB);
        let reach = 128 * KIB;
        let (nice, cut) = (48, 12);
        let allowance = super::Allowance::default();
        let runs = [
            64 * KIB..128 * KIB,
            128 * KIB..256 * KIB,
            352 * KIB..416 * KIB,
        ];
        let history = |run: &std::ops::Range<usize>| run.start.saturating_sub(reach)..run.start;
        let last = runs.last().unwrap();
        let base = history(last).start;
        let own = &input[base..last.end];
        let collect = |tree: &mut TreeMatchFinder| {
            let mut found = Vec::new();
            let mut out = super::Buffer::new(&allowance);
            for pos in last.start - base..own.len() - 3 {
                out.clear();
                let limit = (own.len() - pos).min(nice);
                tree.matches(own, pos, limit, reach, cut, &mut out).unwrap();
                found.push(out.to_vec());
            }
            found
        };
        let mut alone = TreeMatchFinder::seeded(
            reach,
            own,
            0..last.start - base,
            |pos| (own.len() - pos).min(nice),
            cut,
            1,
            &allowance,
        )
        .unwrap();
        let expected = collect(&mut alone);
        for threads in [1, 2, 8] {
            crate::parallel::private_pool(threads).install(|| {
                let mut seed = super::SeedTree::with_allowance(reach, &allowance).unwrap();
                for run in &runs[..runs.len() - 1] {
                    let window = reach.min(run.end - history(run).start);
                    seed.seed(
                        &input,
                        history(run),
                        window,
                        |pos| (input.len() - pos).min(nice),
                        cut,
                        &allowance,
                    )
                    .unwrap();
                }
                let mut handed = seed
                    .finish(
                        &input,
                        history(last),
                        reach,
                        |pos| (input.len() - pos).min(nice),
                        cut,
                        &allowance,
                    )
                    .unwrap();
                // Handed on whole, its slots stay offset from the run's positions.
                assert_ne!(handed.shift, 0);
                assert!(
                    collect(&mut handed) == expected,
                    "the handed-on tree differs at {threads} threads"
                );
            });
        }
    }
}
