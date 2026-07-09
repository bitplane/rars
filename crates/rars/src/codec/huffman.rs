use std::cmp::Reverse;
use std::collections::BinaryHeap;

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
pub(crate) fn complete_lengths_for_frequencies(frequencies: &[usize], max_bits: u8) -> Vec<u8> {
    let mut lengths = lengths_for_frequencies(frequencies, max_bits);
    if !is_complete_code(&lengths) {
        assign_flat_complete_code(&mut lengths);
    }
    lengths
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
    let used: Vec<usize> = lengths
        .iter()
        .enumerate()
        .filter(|(_, &len)| len != 0)
        .map(|(symbol, _)| symbol)
        .collect();
    let n = used.len();
    if n == 0 {
        return;
    }
    for len in lengths.iter_mut() {
        *len = 0;
    }
    if n == 1 {
        lengths[used[0]] = 1;
        // Pad with one phantom length-1 code so the two codes fill the space.
        let phantom = if used[0] == 0 { 1 } else { 0 };
        if phantom < lengths.len() {
            lengths[phantom] = 1;
        }
        return;
    }
    // Complete "flat" code: with k = ceil(log2 n), assign `2^k - n` symbols
    // length k-1 and the remaining `2n - 2^k` symbols length k. This satisfies
    // Kraft equality exactly.
    let k = (usize::BITS - (n - 1).leading_zeros()) as u8; // ceil(log2 n)
    let cap = 1usize << k;
    let short_count = cap - n; // symbols at length k-1
    for (i, &symbol) in used.iter().enumerate() {
        lengths[symbol] = if i < short_count { k - 1 } else { k };
    }
}

pub(crate) fn lengths_for_frequencies(frequencies: &[usize], max_bits: u8) -> Vec<u8> {
    let used_count = frequencies
        .iter()
        .filter(|&&frequency| frequency != 0)
        .count();
    if used_count <= 1 {
        return uniform_lengths_for_frequencies(frequencies);
    }

    let mut lengths = vec![0u8; frequencies.len()];
    let mut heap = BinaryHeap::new();
    let mut order = 0usize;
    for (symbol, &frequency) in frequencies.iter().enumerate() {
        if frequency == 0 {
            continue;
        }
        heap.push(Reverse((frequency, order, vec![symbol])));
        order += 1;
    }

    while heap.len() > 1 {
        let Reverse((left_frequency, _, mut left_symbols)) =
            heap.pop().expect("frequency heap has a left node");
        let Reverse((right_frequency, _, mut right_symbols)) =
            heap.pop().expect("frequency heap has a right node");
        for &symbol in left_symbols.iter().chain(right_symbols.iter()) {
            lengths[symbol] += 1;
        }
        left_symbols.append(&mut right_symbols);
        heap.push(Reverse((
            left_frequency.saturating_add(right_frequency),
            order,
            left_symbols,
        )));
        order += 1;
    }

    if lengths.iter().any(|&length| length > max_bits) {
        uniform_lengths_for_frequencies(frequencies)
    } else {
        lengths
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
    fn weighted_lengths_favour_common_symbols() {
        let frequencies = [1, 1, 16, 1];
        let lengths = lengths_for_frequencies(&frequencies, 15);

        assert!(lengths[2] < lengths[0]);
        assert!(lengths.iter().all(|&length| length <= 15));
    }

    #[test]
    fn excessive_lengths_fall_back_to_uniform_lengths() {
        let frequencies = (1..=1024).collect::<Vec<_>>();
        let lengths = lengths_for_frequencies(&frequencies, 1);

        assert!(lengths.iter().all(|&length| length == 10));
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
