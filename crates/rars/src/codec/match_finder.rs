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
//! seeded cheaply, and the tree costs eight bytes per byte of window against
//! the chain's four.
//!
//! `prev` holds one link per position in a window rather than one per position
//! in the input, indexed by position modulo the window. A link is only followed
//! while the candidate it names is inside the window, and a slot is only reused
//! once the position it held has fallen out, so the two never overlap. That
//! bounds the finder by the window instead of by the data, which is what lets
//! one finder span every block of a member: rebuilding it per block meant
//! rehashing the whole history each time, which measured at about 40% of the
//! encode on a 16 MiB member.
//!
//! Links are 32 bits, so the window costs four bytes per byte it covers rather
//! than eight, and twice as many links share a cache line. Positions past four
//! gigabytes keep only their low half; `resolve` measures back from the newest
//! position inserted to recover the rest.

use super::workspace::{Allowance, Budget, Buffer};
use super::Result;

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
    pub(crate) fn new(window: usize) -> Self {
        Self::with_allowance(window, &Allowance::default()).expect("unlimited finder allocation")
    }

    /// More heads keep a long reach from crowding each chain with collisions.
    #[cfg(feature = "write")]
    pub(crate) fn with_hash_bits(window: usize, hash_bits: u32) -> Self {
        Self::build(window, hash_bits, &Allowance::default()).expect("unlimited finder allocation")
    }
}

impl<const MIN_MATCH: usize, B: Budget> MatchFinder<MIN_MATCH, B> {
    const HASH_BITS: u32 = match MIN_MATCH {
        3 => 16,
        4 | 32 => 17,
        _ => panic!("match finder supports MIN_MATCH of 3, 4 or 32"),
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
        } else {
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]])
        };
        mix(value, self.hash_bits)
    }

    /// Records `pos` as a future match candidate. Positions too close to the
    /// end of the input to fit `MIN_MATCH` bytes are ignored.
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

// Fusing insertion and lookup shares one hash and skips the self link.
impl<B: Budget> MatchFinder<4, B> {
    /// Insert a readable position and return its first older candidate. Like
    /// the encoder's ordinary insertion schedule, positions arrive in order.
    #[inline]
    pub(crate) fn insert_and_first(&mut self, input: &[u8], pos: usize) -> usize {
        debug_assert!(pos + 4 <= input.len());
        self.record_and_first(self.hash(input, pos), pos)
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
        first: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
        nice: usize,
        out: &mut Buffer<(u32, u32), B>,
    ) -> std::result::Result<(), B::Failure> {
        debug_assert!(max_length >= 4 && pos + max_length <= input.len());
        if cut == 0 {
            return Ok(());
        }
        let prefix = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        let mut longest = 0;
        let mut checked = 0;
        let mut candidate = first;
        while candidate != NO_POSITION && longest < max_length && longest < nice {
            if candidate >= pos {
                candidate = self.previous_for_collection::<SHORT>(candidate);
                continue;
            }
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            if input[candidate + longest] == input[pos + longest] {
                let difference = prefix
                    ^ u32::from_le_bytes(input[candidate..candidate + 4].try_into().unwrap());
                let length = if difference != 0 {
                    (difference.trailing_zeros() / 8) as usize
                } else {
                    4 + super::fast::match_length(input, pos + 4, distance, max_length - 4)
                };
                if length > longest {
                    out.push((length as u32, distance as u32))?;
                    longest = length;
                }
            }
            if checked >= cut {
                break;
            }
            candidate = self.previous_for_collection::<SHORT>(candidate);
        }
        Ok(())
    }
}

/// A binary-tree match finder, after LZMA's BT4.
///
/// Positions sharing a hash of their first four bytes form a binary search
/// tree ordered by the bytes at them, newest position at the root. The two
/// children of each position live in `son`, one window slot per position as
/// with the chain finder's `prev`, and the same rules keep slot reuse and the
/// window from ever overlapping. Truncated links are read back with the
/// position being searched for as the reference, which is always the newest.
#[derive(Debug)]
pub(crate) struct TreeMatchFinder<B: Budget = Allowance> {
    head: Buffer<u32, B>,
    /// Two links per window slot: the child whose bytes compare lesser first,
    /// then the greater-or-equal one, in LZMA's layout.
    son: Buffer<u32, B>,
    mask: usize,
}

impl TreeMatchFinder {
    #[cfg(test)]
    pub(crate) fn new(window: usize) -> Self {
        Self::with_allowance(window, &Allowance::default()).expect("unlimited finder allocation")
    }
}

impl<B: Budget> TreeMatchFinder<B> {
    const HASH_BITS: u32 = 17;
    const MIN_MATCH: usize = 4;

    /// Builds a finder that remembers the last `window` positions, at eight
    /// bytes of links per byte of window.
    pub(crate) fn with_allowance(window: usize, allowance: &B) -> Result<Self> {
        let window = window
            .max(1)
            .checked_next_power_of_two()
            .ok_or(super::Error::InvalidData("finder window overflows"))?;
        Ok(Self {
            head: Buffer::filled(1 << Self::HASH_BITS, NO_LINK, allowance)?,
            // Zero rather than the sentinel for the same reason as the chain
            // finder's `prev`: a slot is always written during its position's
            // own insertion before any link can lead to it, and untouched
            // zeroes let the allocator defer the pages.
            son: Buffer::filled(
                window
                    .checked_mul(2)
                    .ok_or(super::Error::InvalidData("finder window overflows"))?,
                0,
                allowance,
            )?,
            mask: window - 1,
        })
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
        // The tree collector calls this only when at least four bytes remain.
        // Unlike the chain finder, it skips near-end positions before calling.
        debug_assert!(len_limit >= Self::MIN_MATCH && pos + len_limit <= input.len());
        let hash = mix(
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]),
            Self::HASH_BITS,
        );
        let mut current = resolve(pos, self.head[hash]);
        self.head[hash] = pos as u32;
        // The two attachment points still waiting for a subtree, starting as
        // the new position's own child slots. Each step down hangs the node
        // just compared on one of them and moves that side into the node's
        // matching child slot.
        let mut ptr0 = ((pos & self.mask) << 1) + 1;
        let mut ptr1 = (pos & self.mask) << 1;
        // How much of the prefix is proven to match on each side of the
        // descent. Everything below a node compares the same way the node
        // did up to its recorded length, so bytes before the smaller of the
        // two never need reading again.
        let mut len0 = 0usize;
        let mut len1 = 0usize;
        let mut longest = Self::MIN_MATCH - 1;
        let mut budget = cut;
        let mut floor = pos;
        loop {
            // A candidate that does not step back is a reused slot or the
            // sentinel; one further back than the window has fallen out of it.
            // Either ends the descent, sealing both attachment points so no
            // stale link survives below them. A spent budget ends it the same
            // way, dropping whatever subtree the budget could not reach.
            if current >= floor || pos - current > self.mask || budget == 0 {
                self.son[ptr0] = NO_LINK;
                self.son[ptr1] = NO_LINK;
                return Ok(());
            }
            budget -= 1;
            floor = current;
            let pair = (current & self.mask) << 1;
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
                    if pos - current <= max_distance {
                        out.push((len as u32, (pos - current) as u32))?;
                    }
                    longest = len;
                    if len == len_limit {
                        // The node's whole comparable prefix is the new
                        // position's prefix, so the new position adopts its
                        // children and the node drops out as the farther of
                        // two interchangeable candidates.
                        self.son[ptr1] = self.son[pair];
                        self.son[ptr0] = self.son[pair + 1];
                        return Ok(());
                    }
                }
            }
            if input[current + len] < input[pos + len] {
                self.son[ptr1] = current as u32;
                ptr1 = pair + 1;
                len1 = len;
                current = resolve(pos, self.son[ptr1]);
            } else {
                self.son[ptr0] = current as u32;
                ptr0 = pair;
                len0 = len;
                current = resolve(pos, self.son[ptr0]);
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
                    assert_eq!(&fast.head[..], &scalar.head[..]);
                    assert_eq!(&fast.son[..], &scalar.son[..]);
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
}
