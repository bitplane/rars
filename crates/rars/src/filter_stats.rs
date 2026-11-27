//! Byte statistics that stand in for a sample encode when judging a filter.

use crate::codec::workspace::Allowance;
use crate::codec::workspace::Buffer;
use crate::codec::Result;

/// Entries in each table [`x86_repeat_gain`] remembers operands in.
const OPERAND_TABLE_BITS: u32 = 12;

/// How many more x86 operands repeat an earlier one once converted than did
/// before, for the calls and for the jumps, out of how many there are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OperandRepeats {
    pub(crate) calls: i64,
    pub(crate) jumps: i64,
    pub(crate) opcodes: usize,
}

/// What converting the x86 operands in `data`, which starts `offset` bytes
/// into whatever it is cut from, does to how often they repeat.
///
/// The operands are parsed as the E8E9 filter parses them. An operand repeats
/// when the last one that fell in its slot of a small table had the same
/// value, so a repeat is one recent enough for a coder to match. Converting
/// turns a call's displacement into the address it reaches, which repeats
/// wherever one function is called from many places; the displacements of
/// those calls are all different. Bytes that only happen to hold the opcode
/// repeat as often either way, or less once converted.
///
/// Only operands within the filter's 16 MiB reach either way are converted, as
/// the filter converts only those.
pub(crate) fn x86_repeat_gain(
    data: &[u8],
    offset: usize,
    allowance: &Allowance,
) -> Result<OperandRepeats> {
    let mut gain = OperandRepeats::default();
    if data.len() <= 4 {
        return Ok(gain);
    }
    let size = 1usize << OPERAND_TABLE_BITS;
    let mut relative = Buffer::filled(size, u32::MAX, allowance)?;
    let mut absolute = Buffer::filled(size, u32::MAX, allowance)?;
    let slot =
        |value: u32| (value.wrapping_mul(0x9e37_79b1) >> (u32::BITS - OPERAND_TABLE_BITS)) as usize;
    let limit = data.len() - 4;
    let mut pos = 0;
    while let Some(found) = crate::codec::fast::next_x86_opcode(data, pos, limit, 0xfe) {
        let operand = u32::from_le_bytes(
            data[found + 1..found + 5]
                .try_into()
                .expect("an opcode before the limit has four operand bytes"),
        );
        let within_reach = operand.wrapping_add(0x0100_0000) < 0x0200_0000;
        let target = if within_reach {
            operand.wrapping_add((offset + found + 1) as u32)
        } else {
            operand
        };
        let repeated = std::mem::replace(&mut relative[slot(operand)], operand) == operand;
        let repeats = std::mem::replace(&mut absolute[slot(target)], target) == target;
        let change = i64::from(repeats) - i64::from(repeated);
        if data[found] == 0xe8 {
            gain.calls += change;
        } else {
            gain.jumps += change;
        }
        gain.opcodes += 1;
        pos = found + 5;
    }
    Ok(gain)
}

/// The most entries the match finder [`lz_cost`] runs has.
const LZ_TABLE_BITS: u32 = 14;

/// Roughly how many bits an LZ coder would spend on `data`.
///
/// A greedy parse with one candidate per position, literals priced at their
/// own order-0 entropy, and each match at a fixed cost plus the width of its
/// distance, or less for the distance before. It builds no tables and writes
/// nothing, so it costs a fraction of the lightest encode.
pub(crate) fn lz_cost(data: &[u8], allowance: &Allowance) -> Result<u64> {
    let bits = data
        .len()
        .next_power_of_two()
        .trailing_zeros()
        .clamp(8, LZ_TABLE_BITS);
    let mut heads = Buffer::filled(1usize << bits, u32::MAX, allowance)?;
    let mut literals = [0u32; 256];
    let mut literal_count = 0u64;
    let mut match_bits = 0u64;
    let mut last_distance = 0usize;
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let word = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("four bytes"));
        let slot = (word.wrapping_mul(0x9e37_79b1) >> (u32::BITS - bits)) as usize;
        let candidate = std::mem::replace(&mut heads[slot], pos as u32);
        let distance = pos.wrapping_sub(candidate as usize);
        let length = if candidate == u32::MAX {
            0
        } else {
            crate::codec::fast::match_length(data, pos, distance, data.len() - pos)
        };
        if length >= 4 {
            match_bits += if distance == last_distance {
                8
            } else {
                12 + u64::from(usize::BITS - distance.leading_zeros())
            };
            last_distance = distance;
            pos += length;
        } else {
            literals[usize::from(data[pos])] += 1;
            literal_count += 1;
            pos += 1;
        }
    }
    for &byte in &data[pos..] {
        literals[usize::from(byte)] += 1;
        literal_count += 1;
    }
    Ok(match_bits + entropy_bits(&literals, literal_count))
}

/// Bits to code `total` symbols counted in `counts` at their order-0 entropy.
fn entropy_bits(counts: &[u32; 256], total: u64) -> u64 {
    let total = total as f64;
    let bits: f64 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let count = f64::from(count);
            count * (total / count).log2()
        })
        .sum();
    bits as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::Allowance;

    /// Calls from all over a buffer to a few functions, as code is laid out.
    fn calls_to_few_places(len: usize) -> Vec<u8> {
        let mut data = vec![0x90u8; len];
        let mut state = 0x1234_5678u32;
        let targets = [0x400u32, 0x1800, 0x2c00, 0x7000];
        for pos in (0..len - 5).step_by(13) {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let target = targets[(state >> 16) as usize % targets.len()];
            let displacement = target.wrapping_sub(pos as u32 + 1);
            data[pos] = 0xe8;
            data[pos + 1..pos + 5].copy_from_slice(&displacement.to_le_bytes());
        }
        data
    }

    #[test]
    fn calls_to_shared_targets_gain_repeats_once_converted() {
        let data = calls_to_few_places(64 * 1024);
        let gain = x86_repeat_gain(&data, 0, &Allowance::default()).unwrap();
        assert!(gain.opcodes > 4000, "{gain:?}");
        assert!(gain.calls as usize > gain.opcodes * 9 / 10, "{gain:?}");
        assert_eq!(gain.jumps, 0);
    }

    #[test]
    fn repeated_operands_lose_repeats_once_converted() {
        let data: Vec<u8> = [0xe9, 0x10, 0x20, 0x00, 0x00, 0x41].repeat(2000);
        let gain = x86_repeat_gain(&data, 0, &Allowance::default()).unwrap();
        assert_eq!(gain.calls, 0);
        assert!(gain.jumps < -1900, "{gain:?}");
        assert_eq!(
            x86_repeat_gain(&data[..4], 0, &Allowance::default()).unwrap(),
            OperandRepeats::default()
        );
    }

    #[test]
    fn lz_cost_prices_repetition_below_noise() {
        let allowance = Allowance::default();
        let mut state = 1u32;
        let noise: Vec<u8> = (0..32 * 1024)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 24) as u8
            })
            .collect();
        let repeated = noise[..1024].repeat(32);
        let noise_bits = lz_cost(&noise, &allowance).unwrap();
        assert!(noise_bits > 7 * noise.len() as u64, "{noise_bits}");
        assert!(lz_cost(&repeated, &allowance).unwrap() * 8 < noise_bits);
        assert_eq!(lz_cost(&[], &allowance).unwrap(), 0);
        assert!(lz_cost(&[1, 2, 3], &allowance).unwrap() > 0);
    }

    #[test]
    fn statistics_charge_their_tables() {
        let data = calls_to_few_places(4096);
        assert!(x86_repeat_gain(&data, 0, &Allowance::limited(0)).is_err());
        assert!(lz_cost(&data, &Allowance::limited(0)).is_err());
    }
}
