//! Telling a match finder where the input looks like noise, so it can leave
//! those positions unsearched.
//!
//! Already-compressed data inside an archive, such as the members of a tar of
//! zstd files or the body of a video, packs to its own size however hard it is
//! searched, and a tree descent or a full chain walk per byte of it finds
//! nothing. The whole-member probe in `incompressible` cannot help when such
//! data is mixed with something that compresses, such as a tar's headers.
//!
//! A position is noise when the [`REACH`] bytes from it have an almost flat
//! byte histogram. Literals still get their Huffman code, so the only thing
//! skipping a position gives up is a match starting there, and matches in such
//! bytes are rare and short.
//!
//! A copy of noise seen earlier in the window is the exception: a tar can hold
//! the same zip twice. So one noise position in about [`ANCHOR_RATE`] is still
//! put in and searched, chosen by its own four bytes, so the same positions are
//! chosen in every copy. A copy then finds the one before at its first anchor,
//! and the parse follows the match from there.
//!
//! The verdict at a position depends only on the bytes from it onwards, never
//! on where the caller's input starts, so finders over different windows of
//! the same data, such as a run's own tree and the shared tree that seeds it,
//! agree wherever both inputs hold [`REACH`] bytes from the position.
//!
//! Where an input ends matters too, and a member's runs are coded in windows
//! that end where a run does on some thread counts and run on into the next
//! run on others. A scan made [`NoiseScan::with_cells`] answers the same for
//! both: no reach that crosses a cell boundary is noise, and runs start and
//! end on cell boundaries.

/// How many bytes from a position are judged.
pub(crate) const REACH: usize = 2048;

/// The largest sum of squared byte counts over [`REACH`] bytes that counts as
/// noise: 15% over what uniform random bytes average, which is many times
/// their spread. That keeps the skewed bytes of Huffman-coded data in, while
/// machine code and text sit several times above it.
const MAX_SQUARES: u32 = ((REACH + REACH * (REACH - 1) / 256) * 23 / 20) as u32;

/// The cells of [`NoiseScan::with_cells`]: the block size runs are read in,
/// so every run is a whole number of them.
pub(crate) const CELL: usize = 64 * 1024;
const _: () = assert!(CELL.is_power_of_two() && CELL >= 2 * REACH);

/// About one position in this many is an anchor. Searching an anchor costs a
/// whole search, and the first anchor in a copy is where the copy is found, so
/// this is the trade between the time spent on noise and the bytes of a copy
/// coded as literals before it is found.
const ANCHOR_RATE: u32 = 32;
const _: () = assert!(ANCHOR_RATE.is_power_of_two());

/// Whether `pos` is one of the noise positions a match finder still searches,
/// by its own four bytes. A position without four bytes after it never is.
fn is_anchor(input: &[u8], pos: usize) -> bool {
    let Some(bytes) = input.get(pos..pos + 4) else {
        return false;
    };
    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    word.wrapping_mul(0x9E37_79B1) >> (32 - ANCHOR_RATE.trailing_zeros()) == 0
}

/// How many of the latest verdicts a scan keeps, so a caller can step back a
/// little, as a lazy parse does after looking ahead.
const KEPT: usize = 64;

/// How many positions a scan tries to clear at once. The reaches of `STRIDE`
/// positions in a row all hold the bytes from the last one's start to the
/// first one's end, and a sum of squared counts only grows as bytes are
/// added, so when those shared bytes alone are over [`MAX_SQUARES`], none of
/// the positions is noise. On machine code and text that settles about 99%
/// of strides from one plain count of half a reach, where sliding the
/// histogram a byte at a time costs a few times as much.
const STRIDE: usize = REACH / 2;

/// A sliding histogram over the input, answering for positions in about
/// increasing order.
pub(crate) struct NoiseScan {
    counts: [u16; 256],
    /// The sum of the squares of `counts`.
    squares: u32,
    /// The position `counts` covers [`REACH`] bytes from, or `usize::MAX`
    /// before the first.
    at: usize,
    /// The verdicts at `at` and the positions before it, `at`'s in the low
    /// bit.
    kept: u64,
    /// How many of `kept` hold verdicts.
    held: usize,
    /// How far the histogram slides before the next stride is tried.
    sliding_until: usize,
    /// The latest stride cleared without the histogram.
    clear: std::ops::Range<usize>,
    /// Where a cell starts, for a scan with cells, or `usize::MAX`.
    cells: usize,
}

impl NoiseScan {
    pub(crate) const fn new() -> Self {
        Self {
            counts: [0; 256],
            squares: 0,
            at: usize::MAX,
            kept: 0,
            held: 0,
            sliding_until: 0,
            clear: 0..0,
            cells: usize::MAX,
        }
    }

    /// A scan that never calls noise a position whose reach crosses into
    /// another of the [`CELL`]-byte cells, counted either way from `origin`.
    pub(crate) const fn with_cells(origin: usize) -> Self {
        let mut scan = Self::new();
        scan.cells = origin;
        scan
    }

    /// Whether a match finder leaves `pos` out: neither puts it in nor
    /// searches from it. That is a noise position that is not an anchor.
    #[inline]
    pub(crate) fn skips(&mut self, input: &[u8], pos: usize) -> bool {
        self.is_noise(input, pos) && !is_anchor(input, pos)
    }

    /// Whether the reach from `pos` crosses a cell boundary.
    #[inline]
    fn crosses_cells(&self, pos: usize) -> bool {
        self.cells != usize::MAX && pos.wrapping_sub(self.cells) & (CELL - 1) > CELL - REACH
    }

    /// Whether the [`REACH`] bytes of `input` from `pos` look like noise. A
    /// position without that many bytes after it never does.
    ///
    /// Moving forward costs about a step per position. Stepping back further
    /// than [`KEPT`] positions, or forward past a whole reach, costs up to a
    /// reach of steps.
    #[inline]
    pub(crate) fn is_noise(&mut self, input: &[u8], pos: usize) -> bool {
        if input.len() < REACH
            || pos > input.len() - REACH
            || self.crosses_cells(pos)
            || self.clear.contains(&pos)
        {
            return false;
        }
        if self.at != usize::MAX {
            if pos <= self.at {
                if self.at - pos < self.held {
                    return self.kept >> (self.at - pos) & 1 != 0;
                }
            } else if pos < self.sliding_until {
                self.slide(input, pos);
                return self.kept & 1 != 0;
            }
        }
        self.stride(input, pos)
    }

    /// Starts a stride at `pos`: clears it from the bytes its positions share
    /// when they say enough, and slides the histogram through it otherwise.
    #[cold]
    fn stride(&mut self, input: &[u8], pos: usize) -> bool {
        if shared_squares(&input[pos + STRIDE - 1..pos + REACH]) > MAX_SQUARES {
            self.clear = pos..pos + STRIDE;
            return false;
        }
        if self.at != usize::MAX && self.at < pos && pos - self.at <= REACH {
            self.slide(input, pos);
        } else {
            self.restart(input, pos);
        }
        self.sliding_until = pos + STRIDE;
        self.kept & 1 != 0
    }

    /// Moves the histogram forward to `pos`, judging every position on the
    /// way. Each position up to `pos` has a whole reach after it.
    fn slide(&mut self, input: &[u8], pos: usize) {
        let mut squares = self.squares;
        let mut kept = self.kept;
        let counts = &mut self.counts;
        for (&out, &in_) in input[self.at..pos]
            .iter()
            .zip(&input[self.at + REACH..pos + REACH])
        {
            let out = &mut counts[out as usize];
            squares -= 2 * u32::from(*out) - 1;
            *out -= 1;
            let in_ = &mut counts[in_ as usize];
            squares += 2 * u32::from(*in_) + 1;
            *in_ += 1;
            kept = kept << 1 | u64::from(squares <= MAX_SQUARES);
        }
        self.held = (self.held + (pos - self.at)).min(KEPT);
        self.squares = squares;
        self.kept = kept;
        self.at = pos;
    }

    fn restart(&mut self, input: &[u8], pos: usize) {
        self.counts = [0; 256];
        for &byte in &input[pos..pos + REACH] {
            self.counts[byte as usize] += 1;
        }
        self.squares = self
            .counts
            .iter()
            .map(|&count| u32::from(count) * u32::from(count))
            .sum();
        self.at = pos;
        self.kept = u64::from(self.squares <= MAX_SQUARES);
        self.held = 1;
    }
}

/// The sum of the squared byte counts of `bytes`, counted four ways so that
/// a run of one byte value does not wait on its own count.
fn shared_squares(bytes: &[u8]) -> u32 {
    let mut counts = [[0u16; 256]; 4];
    let (quads, rest) = bytes.as_chunks::<4>();
    for quad in quads {
        for (lane, &byte) in quad.iter().enumerate() {
            counts[lane][byte as usize] += 1;
        }
    }
    for (lane, &byte) in rest.iter().enumerate() {
        counts[lane][byte as usize] += 1;
    }
    (0..256)
        .map(|byte| {
            let count: u32 = counts.iter().map(|lane| u32::from(lane[byte])).sum();
            count * count
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    fn verdict(input: &[u8], pos: usize) -> bool {
        NoiseScan::new().is_noise(input, pos)
    }

    fn reference(input: &[u8], pos: usize) -> bool {
        let Some(reach) = input.get(pos..pos + REACH) else {
            return false;
        };
        let mut counts = [0u32; 256];
        for &byte in reach {
            counts[byte as usize] += 1;
        }
        counts.iter().map(|count| count * count).sum::<u32>() <= MAX_SQUARES
    }

    #[test]
    fn every_verdict_is_the_histograms_whichever_way_it_is_reached() {
        // Noise with stretches of text and of skewed bytes between, so that
        // strides are cleared, slid through, and slid through near the limit.
        let mut input = noise(24 * REACH, 7);
        input[5 * REACH..7 * REACH].copy_from_slice(&b"some text, ".repeat(REACH)[..2 * REACH]);
        for (index, byte) in input[12 * REACH..16 * REACH].iter_mut().enumerate() {
            if index % 40 == 0 {
                *byte = 0;
            }
        }
        let mut forward = NoiseScan::new();
        let mut lazy = NoiseScan::new();
        let mut jumping = NoiseScan::new();
        for pos in 0..input.len() {
            let expected = reference(&input, pos);
            assert_eq!(forward.is_noise(&input, pos), expected, "at {pos}");
            for ahead in [1, 2, 0] {
                let at = pos + ahead;
                assert_eq!(lazy.is_noise(&input, at), reference(&input, at), "at {at}");
            }
            if pos % 37 == 0 {
                let at = pos * 3 % input.len();
                assert_eq!(
                    jumping.is_noise(&input, at),
                    reference(&input, at),
                    "at {at}"
                );
            }
        }
        assert!((0..input.len()).any(|pos| reference(&input, pos)));
        assert!((0..input.len() - REACH).any(|pos| !reference(&input, pos)));
    }

    #[test]
    fn random_bytes_are_noise_and_text_is_not() {
        let random = noise(3 * REACH, 1);
        assert!((0..2 * REACH).all(|pos| verdict(&random, pos)));
        let text = b"the same words again and again, ".repeat(REACH);
        assert!(!verdict(&text, 0));
    }

    #[test]
    fn no_reach_across_a_cell_boundary_is_noise() {
        let random = noise(3 * CELL, 8);
        for origin in [0, 5, CELL + 77, 2 * CELL + REACH] {
            let mut scan = NoiseScan::with_cells(origin);
            for pos in 0..random.len() - REACH {
                let offset = pos.wrapping_sub(origin) % CELL;
                let crosses = offset > CELL - REACH;
                assert_eq!(scan.is_noise(&random, pos), !crosses, "{origin} {pos}");
            }
        }
    }

    #[test]
    fn about_one_noise_position_in_the_anchor_rate_is_kept() {
        let random = noise(64 * REACH, 6);
        let mut scan = NoiseScan::new();
        let kept = (0..60 * REACH)
            .filter(|&pos| !scan.skips(&random, pos))
            .count();
        let expected = 60 * REACH / ANCHOR_RATE as usize;
        assert!(
            kept > expected * 9 / 10 && kept < expected * 11 / 10,
            "{kept}"
        );
    }

    #[test]
    fn a_position_without_a_whole_reach_after_it_is_not_noise() {
        let random = noise(REACH + 10, 2);
        assert!(verdict(&random, 10));
        assert!(!verdict(&random, 11));
        assert!(!verdict(&random[..REACH - 1], 0));
    }

    #[test]
    fn a_compressible_stretch_ends_the_noise_before_it_and_not_after() {
        let mut input = noise(4 * REACH, 3);
        let zeros = 2 * REACH..2 * REACH + 512;
        input[zeros.clone()].fill(0);
        assert!(verdict(&input, zeros.start - REACH - 1));
        assert!(!verdict(&input, zeros.start - REACH + 300));
        assert!(!verdict(&input, zeros.start + 200));
        assert!(verdict(&input, zeros.end));
    }

    #[test]
    fn a_scan_answers_as_a_fresh_one_does_in_any_order() {
        let mut input = noise(6 * REACH, 4);
        input[3 * REACH..3 * REACH + 300].fill(b'a');
        let positions = (0..input.len()).step_by(7).flat_map(|pos| {
            [
                pos,
                pos.saturating_sub(3),
                pos + 2 * REACH,
                pos.saturating_sub(200),
            ]
        });
        let mut scan = NoiseScan::new();
        for pos in positions.filter(|&pos| pos < input.len()) {
            assert_eq!(scan.is_noise(&input, pos), verdict(&input, pos), "at {pos}");
        }
    }

    #[test]
    fn the_verdict_does_not_depend_on_where_the_input_starts() {
        let input = noise(3 * REACH, 5);
        for start in [1, 100, REACH] {
            let mut whole = NoiseScan::new();
            let mut part = NoiseScan::new();
            for pos in start..input.len() {
                assert_eq!(
                    whole.is_noise(&input, pos),
                    part.is_noise(&input[start..], pos - start)
                );
            }
        }
    }
}
