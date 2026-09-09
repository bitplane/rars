use super::workspace::{Allowance, Budget, Buffer};
use super::Result;

/// Like [`lengths_for_frequencies`], but guarantees the returned code lengths
/// form a *complete* canonical prefix code (Kraft equality) whenever at least
/// one symbol is used.
///
/// Strict RAR 5 decoders build their tables with 7-Zip's
/// `k_BuildMode_Full_or_Empty`, which rejects any under-full table (a table
/// whose codes leave part of the code space unassigned). A frequency table
/// with a single used symbol otherwise yields one length-1 code — Kraft sum
/// `0.5` — and such archives decode fine in unRAR but fail in 7-Zip / WinRAR
/// with a spurious "Data Error". Real Huffman codes for two or more symbols are
/// already complete, so this only adjusts the degenerate single-symbol case (and
/// the rare uniform-length fallback), padding with phantom codes that are never
/// emitted.
#[cfg(test)]
pub(crate) fn complete_lengths_for_frequencies(frequencies: &[usize], max_bits: u8) -> Vec<u8> {
    complete_lengths_with_allowance(frequencies, max_bits, &Allowance::default())
        .expect("unlimited Huffman allocation")
        .into_vec()
}

/// Returns true if the non-zero code lengths form a complete prefix code
/// (Kraft sum exactly 1), or if the table is empty (no used symbol).
fn is_complete_code(lengths: &[u8]) -> bool {
    // Kraft sum in units of 2^-max_len, accumulated as an integer to avoid
    // floating point. A complete code has sum == 2^max_len.
    let max_len = lengths.iter().copied().max().unwrap_or(0);
    if max_len == 0 {
        return true; // empty table
    }
    let mut sum: u64 = 0;
    for &len in lengths {
        if len != 0 {
            sum += 1u64 << (max_len - len);
        }
    }
    sum == (1u64 << max_len)
}

/// Overwrites `lengths` with a complete near-uniform canonical code over the
/// currently-used symbols (those with a non-zero length), preserving symbol
/// order. A single used symbol is padded with one phantom length-1 code so the
/// result satisfies Kraft equality; an empty table is left untouched. Callers
/// that need a guaranteed-complete code (e.g. tables a strict decoder builds
/// with `Full`/`Full_or_Empty`) can mark used symbols with any non-zero length
/// and call this to normalise them.
pub(crate) fn assign_flat_complete_code(lengths: &mut [u8]) {
    let n = lengths.iter().filter(|&&length| length != 0).count();
    if n == 0 {
        return;
    }
    if n == 1 {
        let symbol = lengths.iter().position(|&length| length != 0).unwrap();
        lengths[symbol] = 1;
        let phantom = usize::from(symbol == 0);
        if phantom < lengths.len() {
            lengths[phantom] = 1;
        }
        return;
    }
    let k = (usize::BITS - (n - 1).leading_zeros()) as u8;
    let short_count = (1usize << k) - n;
    for (index, length) in lengths
        .iter_mut()
        .filter(|length| **length != 0)
        .enumerate()
    {
        *length = if index < short_count { k - 1 } else { k };
    }
}

pub(crate) fn lengths_for_frequencies(frequencies: &[usize], max_bits: u8) -> Vec<u8> {
    lengths_with_allowance(frequencies, max_bits, &Allowance::default())
        .expect("unlimited Huffman allocation")
        .into_vec()
}

pub(crate) fn complete_lengths_with_allowance<B: Budget>(
    frequencies: &[usize],
    max_bits: u8,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let mut lengths = lengths_with_allowance(frequencies, max_bits, allowance)?;
    if !is_complete_code(&lengths) {
        assign_flat_complete_code(&mut lengths);
    }
    Ok(lengths)
}

pub(crate) fn lengths_with_allowance<B: Budget>(
    frequencies: &[usize],
    max_bits: u8,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let used_count = frequencies
        .iter()
        .filter(|&&frequency| frequency != 0)
        .count();
    let mut lengths = Buffer::filled(frequencies.len(), 0u8, allowance)?;
    if used_count <= 1 {
        uniform_lengths_into(&mut lengths, frequencies);
        return Ok(lengths);
    }

    // Parents replace the old per-node symbol vectors. Node order breaks ties
    // exactly as the original heap did; every parent is created after its children.
    let capacity = frequencies
        .len()
        .checked_add(used_count - 1)
        .ok_or(super::Error::InvalidData("Huffman node count overflows"))?;
    let mut parents = Buffer::filled(capacity, usize::MAX, allowance)?;
    let mut heap = Buffer::with_capacity(used_count, allowance)?;
    let mut order = 0;
    for (symbol, &frequency) in frequencies.iter().enumerate() {
        if frequency != 0 {
            heap.push((frequency, order, symbol)).map_err(Into::into)?;
            order += 1;
        }
    }
    // Sorting once constructs a valid min-heap without auxiliary allocation.
    heap.sort_unstable();
    let mut next = frequencies.len();
    while heap.len() > 1 {
        let (left_frequency, _, left) = pop_min(&mut heap);
        let (right_frequency, _, right) = pop_min(&mut heap);
        parents[left] = next;
        parents[right] = next;
        heap.push((left_frequency.saturating_add(right_frequency), order, next))
            .map_err(Into::into)?;
        let mut child = heap.len() - 1;
        while child != 0 {
            let parent = (child - 1) / 2;
            if heap[parent] <= heap[child] {
                break;
            }
            heap.swap(parent, child);
            child = parent;
        }
        next += 1;
        order += 1;
    }
    // Replace parent indices with depths in reverse creation order.
    for node in (0..next).rev() {
        parents[node] = if parents[node] == usize::MAX {
            0
        } else {
            parents[parents[node]] + 1
        };
    }
    for (length, &depth) in lengths.iter_mut().zip(parents.iter()) {
        *length = depth as u8;
    }
    if lengths.iter().any(|&length| length > max_bits) {
        limit_code_lengths(&mut lengths, frequencies, max_bits);
    }
    Ok(lengths)
}

fn pop_min<B: Budget>(heap: &mut Buffer<(usize, usize, usize), B>) -> (usize, usize, usize) {
    let last = heap.pop().expect("frequency heap has a node");
    if heap.is_empty() {
        return last;
    }
    let first = std::mem::replace(&mut heap[0], last);
    let mut parent = 0;
    loop {
        let left = parent * 2 + 1;
        if left >= heap.len() {
            break;
        }
        let right = left + 1;
        let child = if right < heap.len() && heap[right] < heap[left] {
            right
        } else {
            left
        };
        if heap[parent] <= heap[child] {
            break;
        }
        heap.swap(parent, child);
        parent = child;
    }
    first
}

fn uniform_lengths_into(lengths: &mut [u8], frequencies: &[usize]) {
    let bits = bits_for_symbol_count(
        frequencies
            .iter()
            .filter(|&&frequency| frequency != 0)
            .count(),
    );
    for (length, &frequency) in lengths.iter_mut().zip(frequencies) {
        *length = if frequency == 0 { 0 } else { bits };
    }
}

/// Bring every code length down to `max_bits`, keeping the code complete.
///
/// A code deeper than the format allows used to be replaced by a uniform one
/// over the same symbols. That is a far worse code: on a skewed 289 symbol main
/// table a flat code spends nine bits on every token where the Huffman code it
/// replaced averaged closer to six, and the codes that trip the limit overflow
/// it by a bit or two, not by enough to justify giving up.
///
/// Clamping the over-long lengths breaks Kraft equality, so this pays the
/// difference back by lengthening the symbols that cost least per bit, then
/// spends whatever is left over on the most frequent ones so the code comes out
/// complete. Package-merge would be optimal; this is within a fraction of a
/// percent of it and much shorter.
fn limit_code_lengths(lengths: &mut [u8], frequencies: &[usize], max_bits: u8) {
    // No prefix code over this many symbols fits in this many bits however it
    // is arranged, so there is nothing to repair towards.
    let used = lengths.iter().filter(|&&length| length != 0).count();
    if max_bits == 0 || max_bits >= usize::BITS as u8 || used > (1usize << max_bits) {
        uniform_lengths_into(lengths, frequencies);
        return;
    }

    for length in lengths.iter_mut() {
        if *length > max_bits {
            *length = max_bits;
        }
    }

    // Kraft sum in units of 2^-max_bits, so it stays exact in integers.
    let target: u64 = 1 << max_bits;
    let mut sum: u64 = lengths
        .iter()
        .filter(|&&length| length != 0)
        .map(|&length| 1u64 << (max_bits - length))
        .sum();

    while sum > target {
        let Some(symbol) = (0..lengths.len())
            .filter(|&symbol| lengths[symbol] != 0 && lengths[symbol] < max_bits)
            .min_by_key(|&symbol| (frequencies[symbol], std::cmp::Reverse(lengths[symbol])))
        else {
            break;
        };
        sum -= 1u64 << (max_bits - lengths[symbol] - 1);
        lengths[symbol] += 1;
    }

    while let Some(symbol) = (0..lengths.len())
        .filter(|&symbol| lengths[symbol] > 1)
        .filter(|&symbol| sum + (1u64 << (max_bits - lengths[symbol])) <= target)
        .max_by_key(|&symbol| (frequencies[symbol], lengths[symbol]))
    {
        sum += 1u64 << (max_bits - lengths[symbol]);
        lengths[symbol] -= 1;
    }
}

pub(crate) fn lengths_for_frequency_array<const N: usize>(
    frequencies: &[usize; N],
    max_bits: u8,
) -> [u8; N] {
    let mut lengths = [0u8; N];
    lengths.copy_from_slice(&lengths_for_frequencies(frequencies, max_bits));
    lengths
}

pub(crate) fn uniform_lengths_for_frequencies(frequencies: &[usize]) -> Vec<u8> {
    let used_count = frequencies
        .iter()
        .filter(|&&frequency| frequency != 0)
        .count();
    let uniform_length = bits_for_symbol_count(used_count);
    frequencies
        .iter()
        .map(|&frequency| if frequency == 0 { 0 } else { uniform_length })
        .collect()
}

pub(crate) fn bits_for_symbol_count(count: usize) -> u8 {
    match count {
        0 | 1 => 1,
        _ => usize::BITS as u8 - (count - 1).leading_zeros() as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charged_tree_preserves_heap_ties_and_saturating_frequencies() {
        // Independent reference for the replaced per-node symbol-list tree.
        fn reference(frequencies: &[usize]) -> Vec<u8> {
            use std::{cmp::Reverse, collections::BinaryHeap};
            let mut lengths = vec![0u8; frequencies.len()];
            let mut heap = BinaryHeap::new();
            let mut order = 0;
            for (symbol, &frequency) in frequencies.iter().enumerate() {
                if frequency != 0 {
                    heap.push(Reverse((frequency, order, vec![symbol])));
                    order += 1;
                }
            }
            if heap.len() <= 1 {
                uniform_lengths_into(&mut lengths, frequencies);
                return lengths;
            }
            while heap.len() > 1 {
                let Reverse((left, _, mut symbols)) = heap.pop().unwrap();
                let Reverse((right, _, mut other)) = heap.pop().unwrap();
                for &symbol in symbols.iter().chain(&other) {
                    lengths[symbol] += 1;
                }
                symbols.append(&mut other);
                heap.push(Reverse((left.saturating_add(right), order, symbols)));
                order += 1;
            }
            if lengths.iter().any(|&length| length > 15) {
                limit_code_lengths(&mut lengths, frequencies, 15);
            }
            lengths
        }
        let allowance = Allowance::limited(1024 * 1024);
        let mut state = 71u64;
        for count in [0, 1, 2, 20, 64, 306, 1024] {
            for shape in 0..8 {
                let frequencies: Vec<_> = (0..count)
                    .map(|_| {
                        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                        match shape {
                            0 => 0,
                            1 => 1,
                            2 => usize::MAX,
                            3 => (state % 3) as usize,
                            _ => (state >> (shape * 7)) as usize,
                        }
                    })
                    .collect();
                let actual = lengths_with_allowance(&frequencies, 15, &allowance).unwrap();
                assert_eq!(&*actual, reference(&frequencies));
                assert_eq!(allowance.used(), count as u64);
                drop(actual);
                assert_eq!(allowance.used(), 0);
            }
        }
    }

    #[test]
    fn tree_refusal_releases_scratch_and_success_retains_only_lengths() {
        let frequencies = [1, 3, 7, 11];
        let peak = 4
            + 7 * std::mem::size_of::<usize>() as u64
            + 4 * std::mem::size_of::<(usize, usize, usize)>() as u64;
        for limit in [0, 4, peak - 1] {
            let allowance = Allowance::limited(limit);
            assert!(matches!(
                lengths_with_allowance(&frequencies, 15, &allowance),
                Err(super::super::Error::WorkspaceLimitExceeded(_))
            ));
            assert_eq!(allowance.used(), 0);
        }
        let allowance = Allowance::limited(peak);
        let lengths = complete_lengths_with_allowance(&frequencies, 15, &allowance).unwrap();
        assert_eq!(allowance.used(), 4);
        drop(lengths);
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn weighted_lengths_favour_common_symbols() {
        let frequencies = [1, 1, 16, 1];
        let lengths = lengths_for_frequencies(&frequencies, 15);

        assert!(lengths[2] < lengths[0]);
        assert!(lengths.iter().all(|&length| length <= 15));
    }

    #[test]
    fn lengths_too_deep_to_limit_fall_back_to_uniform_lengths() {
        // 1024 symbols cannot be spelled in one bit however they are arranged,
        // so there is no length-limited code to find.
        let frequencies = (1..=1024).collect::<Vec<_>>();
        let lengths = lengths_for_frequencies(&frequencies, 1);

        assert!(lengths.iter().all(|&length| length == 10));
    }

    #[test]
    fn deep_codes_are_limited_rather_than_flattened() {
        // Fibonacci frequencies are the worst case for Huffman depth, and this
        // alphabet wants codes far deeper than fifteen bits.
        let mut frequencies = vec![1usize, 1];
        while frequencies.len() < 40 {
            let next = frequencies[frequencies.len() - 1] + frequencies[frequencies.len() - 2];
            frequencies.push(next);
        }
        let lengths = lengths_for_frequencies(&frequencies, 15);

        assert!(lengths.iter().all(|&length| length <= 15), "{lengths:?}");
        assert!(is_complete_code(&lengths), "{lengths:?}");
        // A flat code over forty symbols is six bits each, and on frequencies
        // this skewed the limited code has to beat that.
        let flat: usize = frequencies.iter().sum::<usize>() * 6;
        let limited: usize = frequencies
            .iter()
            .zip(&lengths)
            .map(|(&frequency, &length)| frequency * usize::from(length))
            .sum();
        assert!(limited < flat, "limited {limited} flat {flat}");
    }

    #[test]
    fn limited_codes_stay_decodable_for_every_shape_of_input() {
        // rar29 feeds this straight into a table it writes, with no validation
        // pass behind it, so the one thing that must always hold is that the
        // result is a usable prefix code inside the format's bit limit.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for symbols in [2usize, 3, 17, 64, 255, 299] {
            for skew in 0..8 {
                let frequencies: Vec<usize> = (0..symbols)
                    .map(|_| match skew {
                        // Increasingly lopsided distributions, which is what
                        // drives a Huffman code past the depth limit.
                        0 => 1,
                        s => 1 + (next() % (1u64 << (s * 8).min(60))) as usize,
                    })
                    .collect();
                let lengths = lengths_for_frequencies(&frequencies, 15);

                assert_eq!(lengths.len(), symbols);
                assert!(
                    lengths.iter().all(|&length| length <= 15),
                    "over the limit: {symbols} symbols, skew {skew}"
                );
                let deepest = lengths.iter().copied().max().unwrap_or(0);
                if deepest > 0 {
                    let kraft: u64 = lengths
                        .iter()
                        .filter(|&&length| length != 0)
                        .map(|&length| 1u64 << (deepest - length))
                        .sum();
                    assert!(
                        kraft <= 1u64 << deepest,
                        "not a prefix code: {symbols} symbols, skew {skew}"
                    );
                }
            }
        }
    }

    fn kraft_sum_is_one(lengths: &[u8]) -> bool {
        let max_len = lengths.iter().copied().max().unwrap_or(0);
        if max_len == 0 {
            return lengths.iter().all(|&len| len == 0);
        }
        let sum: u64 = lengths
            .iter()
            .filter(|&&len| len != 0)
            .map(|&len| 1u64 << (max_len - len))
            .sum();
        sum == (1u64 << max_len)
    }

    #[test]
    fn single_symbol_table_is_completed_with_a_phantom_code() {
        // A lone used symbol would otherwise get one length-1 code (Kraft 0.5),
        // which strict RAR 5 decoders reject. It must be padded to a complete
        // code without disturbing the used symbol's own length.
        for used in [0usize, 1, 7, 40] {
            let mut frequencies = vec![0usize; 44];
            frequencies[used] = 123;
            let lengths = complete_lengths_for_frequencies(&frequencies, 15);
            assert_eq!(lengths[used], 1, "used symbol {used} keeps a length-1 code");
            assert_eq!(
                lengths.iter().filter(|&&len| len != 0).count(),
                2,
                "exactly one phantom code was added for used symbol {used}"
            );
            assert!(
                kraft_sum_is_one(&lengths),
                "used symbol {used} yields a complete code"
            );
        }
    }

    #[test]
    fn empty_table_stays_empty() {
        let lengths = complete_lengths_for_frequencies(&[0usize; 16], 15);
        assert!(lengths.iter().all(|&len| len == 0));
    }

    #[test]
    fn completed_codes_are_always_complete_for_any_symbol_count() {
        for used_count in 1..=64usize {
            let mut frequencies = vec![0usize; 306];
            for (i, freq) in frequencies.iter_mut().take(used_count).enumerate() {
                *freq = 1 + i; // distinct frequencies, still a valid Huffman input
            }
            let lengths = complete_lengths_for_frequencies(&frequencies, 15);
            assert!(
                kraft_sum_is_one(&lengths),
                "code for {used_count} symbols must be complete"
            );
            assert!(lengths.iter().all(|&len| len <= 15));
        }
    }

    #[test]
    fn multi_symbol_huffman_code_is_left_optimal() {
        // A skewed distribution already yields a complete Huffman code; the
        // completeness pass must not flatten it into a uniform code.
        let frequencies = [100usize, 1, 1, 1, 1];
        let optimal = lengths_for_frequencies(&frequencies, 15);
        let completed = complete_lengths_for_frequencies(&frequencies, 15);
        assert_eq!(optimal, completed);
        assert!(kraft_sum_is_one(&completed));
    }
}
