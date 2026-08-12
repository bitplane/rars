//! Hash-chain match finder shared by the LZ encoders.
//!
//! Positions are indexed into a single-bucket-per-hash chain: `head` maps a
//! hash of the `MIN_MATCH` bytes at a position to the most recently inserted
//! position, and `prev` links each inserted position to the previous position
//! with the same hash. Walking a chain therefore visits candidates from the
//! smallest distance to the largest, so callers can stop as soon as a
//! candidate falls outside their window.

/// Sentinel for "no position" in `head`/`prev` chains.
pub(crate) const NO_POSITION: usize = usize::MAX;

#[derive(Debug, Clone)]
pub(crate) struct MatchFinder<const MIN_MATCH: usize> {
    head: Vec<usize>,
    prev: Vec<usize>,
}

impl<const MIN_MATCH: usize> MatchFinder<MIN_MATCH> {
    const HASH_BITS: u32 = match MIN_MATCH {
        3 => 16,
        4 => 17,
        _ => panic!("match finder supports MIN_MATCH of 3 or 4"),
    };

    pub(crate) fn new(len: usize) -> Self {
        Self {
            head: vec![NO_POSITION; 1 << Self::HASH_BITS],
            prev: vec![NO_POSITION; len],
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
            self.prev[pos] = self.head[hash];
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
        self.prev[candidate]
    }
}
