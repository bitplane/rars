use std::cmp::Reverse;
use std::collections::BinaryHeap;

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
}
