//! Hash-chain match finder shared by the LZ encoders.
//!
//! Positions are indexed into a single-bucket-per-hash chain: `head` maps a
//! hash of the `MIN_MATCH` bytes at a position to the most recently inserted
//! position, and `prev` links each inserted position to the previous position
//! with the same hash. Walking a chain therefore visits candidates from the
//! smallest distance to the largest, so callers can stop as soon as a
//! candidate falls outside their window.
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

#[derive(Debug, Clone)]
pub(crate) struct MatchFinder<const MIN_MATCH: usize> {
    head: Vec<u32>,
    prev: Vec<u32>,
    mask: usize,
    /// The highest position inserted so far, and so at least as high as any
    /// position a link can name. Truncated links are read back against it.
    newest: usize,
}

impl<const MIN_MATCH: usize> MatchFinder<MIN_MATCH> {
    const HASH_BITS: u32 = match MIN_MATCH {
        3 => 16,
        4 => 17,
        _ => panic!("match finder supports MIN_MATCH of 3 or 4"),
    };

    /// Builds a finder that remembers the last `window` positions.
    ///
    /// The caller must not accept a match further back than `window`, which is
    /// the check it already makes against its own maximum distance. A link to a
    /// position that has fallen out of the window is still readable, and still
    /// names the position it named, so that check rejects it the same way it
    /// rejects a match that is merely too far away.
    pub(crate) fn new(window: usize) -> Self {
        let window = window.max(1).next_power_of_two();
        Self {
            head: vec![NO_LINK; 1 << Self::HASH_BITS],
            // Zero rather than the sentinel, and nothing reads it either way: a
            // link is only ever followed from a position that has been
            // inserted, and inserting a position writes its slot first. Zero
            // lets the allocator hand back pages it has not had to touch, so a
            // window wider than the data has reached costs nothing yet.
            prev: vec![0; window],
            mask: window - 1,
            newest: 0,
        }
    }

    fn hash(input: &[u8], pos: usize) -> usize {
        let value = if MIN_MATCH == 3 {
            u32::from(input[pos])
                | (u32::from(input[pos + 1]) << 8)
                | (u32::from(input[pos + 2]) << 16)
        } else {
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]])
        };
        (value.wrapping_mul(0x9E37_79B1) >> (32 - Self::HASH_BITS)) as usize
    }

    /// Records `pos` as a future match candidate. Positions too close to the
    /// end of the input to fit `MIN_MATCH` bytes are ignored.
    pub(crate) fn insert(&mut self, input: &[u8], pos: usize) {
        if pos + MIN_MATCH <= input.len() {
            let hash = Self::hash(input, pos);
            self.prev[pos & self.mask] = self.head[hash];
            self.head[hash] = pos as u32;
            self.newest = self.newest.max(pos);
        }
    }

    /// Returns the most recently inserted candidate sharing `pos`'s hash, or
    /// [`NO_POSITION`]. The caller must ensure at least `MIN_MATCH` bytes are
    /// readable at `pos`.
    pub(crate) fn first(&self, input: &[u8], pos: usize) -> usize {
        resolve(self.newest, self.head[Self::hash(input, pos)])
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

#[cfg(test)]
mod tests {
    use super::{resolve, MatchFinder, NO_LINK, NO_POSITION};

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
