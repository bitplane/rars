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

/// Sentinel for "no position" in `head`/`prev` chains.
pub(crate) const NO_POSITION: usize = usize::MAX;

#[derive(Debug, Clone)]
pub(crate) struct MatchFinder<const MIN_MATCH: usize> {
    head: Vec<usize>,
    prev: Vec<usize>,
    mask: usize,
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
            head: vec![NO_POSITION; 1 << Self::HASH_BITS],
            prev: vec![NO_POSITION; window],
            mask: window - 1,
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
            self.head[hash] = pos;
        }
    }

    /// Returns the most recently inserted candidate sharing `pos`'s hash, or
    /// [`NO_POSITION`]. The caller must ensure at least `MIN_MATCH` bytes are
    /// readable at `pos`.
    pub(crate) fn first(&self, input: &[u8], pos: usize) -> usize {
        self.head[Self::hash(input, pos)]
    }

    /// Returns the next-older candidate in `candidate`'s chain, or
    /// [`NO_POSITION`].
    pub(crate) fn previous(&self, candidate: usize) -> usize {
        self.prev[candidate & self.mask]
    }
}
