use super::{Error, Result};

const MAX_PARITY: usize = 255;
const MAX_POLYNOMIAL: usize = 512;
const PRIMITIVE_POLYNOMIAL: u16 = 0x11d;

#[derive(Debug, Clone)]
pub(crate) struct RSCoder8 {
    parity_size: usize,
    gf_exp: [u8; MAX_POLYNOMIAL],
    gf_log: [u16; MAX_PARITY + 1],
    generator: Vec<u8>,
}

impl RSCoder8 {
    pub(crate) fn new(parity_size: usize) -> Result<Self> {
        if parity_size == 0 || parity_size > MAX_PARITY {
            return Err(Error::InvalidParitySize);
        }
        let mut coder = Self {
            parity_size,
            gf_exp: [0; MAX_POLYNOMIAL],
            gf_log: [0; MAX_PARITY + 1],
            generator: vec![0; parity_size],
        };
        coder.init_field();
        coder.init_generator();
        Ok(coder)
    }

    #[cfg(test)]
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut shift = vec![0u8; self.parity_size + 1];
        for &byte in data {
            let feedback = byte ^ shift[self.parity_size - 1];
            for index in (1..self.parity_size).rev() {
                shift[index] = shift[index - 1] ^ self.mul(self.generator[index], feedback);
            }
            shift[0] = self.mul(self.generator[0], feedback);
        }
        (0..self.parity_size)
            .map(|index| shift[self.parity_size - index - 1])
            .collect()
    }

    pub(crate) fn correct_erasures(&self, codeword: &mut [u8], erasures: &[usize]) -> Result<()> {
        if codeword.is_empty() || codeword.len() > MAX_PARITY {
            return Err(Error::InvalidCodewordSize);
        }
        if erasures.len() > self.parity_size {
            return Err(Error::TooManyErasures);
        }
        if erasures.iter().any(|&index| index >= codeword.len()) {
            return Err(Error::InvalidCodewordSize);
        }

        let mut syndromes = vec![0u8; self.parity_size];
        let mut all_zero = true;
        for (index, syndrome) in syndromes.iter_mut().enumerate() {
            let factor = self.gf_exp[index + 1];
            let mut sum = 0;
            for &byte in codeword.iter() {
                sum = byte ^ self.mul(factor, sum);
            }
            *syndrome = sum;
            all_zero &= sum == 0;
        }
        if all_zero {
            return Ok(());
        }
        if erasures.is_empty() {
            return Err(Error::DecodeFailed);
        }

        let mut locator = vec![0u8; self.parity_size + 1];
        locator[0] = 1;
        for &erasure in erasures {
            let multiplier = self.gf_exp[codeword.len() - erasure - 1];
            for index in (1..=self.parity_size).rev() {
                locator[index] ^= self.mul(multiplier, locator[index - 1]);
            }
        }

        let mut error_locs = Vec::new();
        let mut denominators = Vec::new();
        // Roots 0 and 255 are the same element, so a full-length codeword
        // must not search both.
        for root in (MAX_PARITY + 1 - codeword.len())..=MAX_PARITY {
            let mut sum = 0;
            for (power, &coefficient) in locator.iter().enumerate() {
                sum ^= self.mul(self.gf_exp[(power * root) % MAX_PARITY], coefficient);
            }
            if sum == 0 {
                let loc = MAX_PARITY - root;
                error_locs.push(loc);
                let mut denominator = 0;
                for index in (1..=self.parity_size).step_by(2) {
                    denominator ^= self.mul(
                        locator[index],
                        self.gf_exp[(root * (index - 1)) % MAX_PARITY],
                    );
                }
                denominators.push(denominator);
            }
        }
        // Each validated erasure supplies a root in this range. The locator's
        // constant term is one, so it has at most parity_size distinct roots.
        let evaluator = self.multiply_polynomials(&locator, &syndromes);
        for (&loc, &denominator) in error_locs.iter().zip(&denominators) {
            if denominator == 0 {
                return Err(Error::DecodeFailed);
            }
            let data_pos = codeword
                .len()
                .checked_sub(loc + 1)
                .ok_or(Error::DecodeFailed)?;
            let dloc = MAX_PARITY - loc;
            let mut numerator = 0;
            for (index, &coefficient) in evaluator.iter().enumerate() {
                numerator ^= self.mul(coefficient, self.gf_exp[(dloc * index) % MAX_PARITY]);
            }
            let correction = self.mul(
                numerator,
                self.gf_exp[MAX_PARITY - usize::from(self.gf_log[denominator as usize])],
            );
            codeword[data_pos] ^= correction;
        }
        Ok(())
    }

    fn init_field(&mut self) {
        let mut value = 1u16;
        for index in 0..MAX_PARITY {
            self.gf_log[value as usize] = index as u16;
            self.gf_exp[index] = value as u8;
            value <<= 1;
            if value > 0xff {
                value ^= PRIMITIVE_POLYNOMIAL;
            }
        }
        for index in MAX_PARITY..MAX_POLYNOMIAL {
            self.gf_exp[index] = self.gf_exp[index - MAX_PARITY];
        }
    }

    fn init_generator(&mut self) {
        let mut current = vec![0u8; self.parity_size];
        current[0] = 1;
        for index in 1..=self.parity_size {
            let mut factor = vec![0u8; self.parity_size];
            factor[0] = self.gf_exp[index];
            if self.parity_size > 1 {
                factor[1] = 1;
            }
            self.generator = self.multiply_polynomials(&factor, &current);
            current.clone_from(&self.generator);
        }
    }

    fn multiply_polynomials(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; self.parity_size];
        for left_index in 0..self.parity_size {
            if left.get(left_index).copied().unwrap_or(0) == 0 {
                continue;
            }
            for right_index in 0..(self.parity_size - left_index) {
                out[left_index + right_index] ^= self.mul(
                    left[left_index],
                    right.get(right_index).copied().unwrap_or(0),
                );
            }
        }
        out
    }

    /// One table per call replaces a log and exp lookup for every byte.
    fn accumulate_scaled(&self, destination: &mut [u8], source: &[u8], coefficient: u8) {
        let destination = &mut destination[..source.len()];
        match coefficient {
            0 => {}
            1 => {
                for (target, &byte) in destination.iter_mut().zip(source) {
                    *target ^= byte;
                }
            }
            _ => {
                let mut table = [0u8; 256];
                for (byte, product) in table.iter_mut().enumerate() {
                    *product = self.mul(coefficient, byte as u8);
                }
                for (target, &byte) in destination.iter_mut().zip(source) {
                    *target ^= table[byte as usize];
                }
            }
        }
    }

    fn mul(&self, left: u8, right: u8) -> u8 {
        if left == 0 || right == 0 {
            0
        } else {
            self.gf_exp[usize::from(self.gf_log[left as usize] + self.gf_log[right as usize])]
        }
    }
}

pub fn reconstruct_data_volumes(
    data_volumes: &[Option<&[u8]>],
    recovery_count: usize,
    recovery_volumes: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>> {
    if data_volumes.is_empty() || data_volumes.len() + recovery_count > MAX_PARITY {
        return Err(Error::InvalidCodewordSize);
    }
    if recovery_volumes.is_empty() || recovery_count == 0 {
        return Err(Error::InvalidParitySize);
    }
    let shard_len = recovery_volumes[0].1.len();
    if recovery_volumes
        .iter()
        .any(|&(index, data)| index >= recovery_count || data.len() != shard_len)
    {
        return Err(Error::InvalidCodewordSize);
    }
    if data_volumes
        .iter()
        .flatten()
        .any(|data| data.len() > shard_len)
    {
        return Err(Error::InvalidCodewordSize);
    }

    let mut recovery_by_index = vec![None; recovery_count];
    for &(index, data) in recovery_volumes {
        if recovery_by_index[index].replace(data).is_some() {
            return Err(Error::InvalidCodewordSize);
        }
    }

    let missing_data: Vec<_> = data_volumes
        .iter()
        .enumerate()
        .filter_map(|(index, data)| data.is_none().then_some(index))
        .collect();
    if missing_data.is_empty() {
        return Ok(data_volumes
            .iter()
            .map(|data| {
                // No missing data volumes were found above.
                let data = data.expect("every data volume is present");
                let mut out = vec![0; shard_len];
                out[..data.len()].copy_from_slice(data);
                out
            })
            .collect());
    }

    let missing_recovery: Vec<_> = recovery_by_index
        .iter()
        .enumerate()
        .filter_map(|(index, data)| data.is_none().then_some(data_volumes.len() + index))
        .collect();
    let mut erasures = missing_data.clone();
    erasures.extend(missing_recovery);
    if erasures.len() > recovery_count {
        return Err(Error::TooManyErasures);
    }

    let coder = RSCoder8::new(recovery_count)?;
    let mut out: Vec<Vec<u8>> = data_volumes
        .iter()
        .map(|data| {
            let mut shard = vec![0; shard_len];
            if let Some(data) = data {
                shard[..data.len()].copy_from_slice(data);
            }
            shard
        })
        .collect();

    // The erasures are the same at every offset, so decoding is one linear map
    // from surviving bytes to missing ones. Decoding a codeword holding a single
    // one reads off that survivor's coefficient for each missing volume.
    let surviving = data_volumes
        .iter()
        .chain(&recovery_by_index)
        .enumerate()
        .filter_map(|(position, data)| Some((position, (*data)?)));
    let mut codeword = vec![0; data_volumes.len() + recovery_count];
    for (position, source) in surviving {
        codeword.fill(0);
        codeword[position] = 1;
        coder.correct_erasures(&mut codeword, &erasures)?;
        for &index in &missing_data {
            coder.accumulate_scaled(&mut out[index], source, codeword[index]);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{reconstruct_data_volumes, Error, RSCoder8};

    #[test]
    fn rs8_encoder_matches_unrar_generator_shape() {
        let coder = RSCoder8::new(11).unwrap();
        assert_eq!(
            coder.generator,
            vec![97, 180, 203, 151, 195, 196, 219, 7, 113, 50, 69]
        );
    }

    #[test]
    fn rs8_reconstructs_single_erased_data_symbol() {
        let coder = RSCoder8::new(4).unwrap();
        let data = b"rar recovery data";
        let parity = coder.encode(data);
        let mut codeword = [data.as_slice(), parity.as_slice()].concat();
        let original = codeword.clone();
        codeword[3] ^= 0xa5;

        coder.correct_erasures(&mut codeword, &[3]).unwrap();

        assert_eq!(codeword, original);
    }

    #[test]
    fn rs8_reconstructs_multiple_erased_symbols_including_parity() {
        let coder = RSCoder8::new(5).unwrap();
        let data = b"rar3-rs8";
        let parity = coder.encode(data);
        let mut codeword = [data.as_slice(), parity.as_slice()].concat();
        let original = codeword.clone();
        codeword[1] = 0;
        codeword[7] = 0;
        codeword[10] = 0;

        coder.correct_erasures(&mut codeword, &[1, 7, 10]).unwrap();

        assert_eq!(codeword, original);
    }

    #[test]
    fn rs8_reconstructs_the_last_symbol_of_a_full_length_codeword() {
        let coder = RSCoder8::new(2).unwrap();
        let data: Vec<u8> = (0..253).map(|index| index as u8 ^ 0x5a).collect();
        let parity = coder.encode(&data);
        let mut codeword = [data.as_slice(), parity.as_slice()].concat();
        let original = codeword.clone();
        codeword[0] = 0;
        codeword[254] = 0;

        coder.correct_erasures(&mut codeword, &[0, 254]).unwrap();

        assert_eq!(codeword, original);
    }

    #[test]
    fn accumulate_scaled_adds_the_scaled_source_into_the_destination() {
        let coder = RSCoder8::new(1).unwrap();
        let source: Vec<u8> = (0..=255).chain([0, 7, 255]).collect();
        let start: Vec<u8> = (0..source.len()).map(|i| (i * 37 + 11) as u8).collect();
        for coefficient in 0..=255u8 {
            let mut actual = start.clone();
            coder.accumulate_scaled(&mut actual, &source, coefficient);
            let expected: Vec<u8> = start
                .iter()
                .zip(&source)
                .map(|(&base, &byte)| base ^ coder.mul(coefficient, byte))
                .collect();
            assert_eq!(actual, expected, "coefficient {coefficient}");
        }
    }

    #[test]
    fn accumulate_scaled_by_zero_leaves_the_destination_and_by_one_xors() {
        let coder = RSCoder8::new(1).unwrap();
        let mut destination = [0x0f, 0xf0, 0xaa];
        coder.accumulate_scaled(&mut destination, &[1, 2, 3], 0);
        assert_eq!(destination, [0x0f, 0xf0, 0xaa]);
        coder.accumulate_scaled(&mut destination, &[0xff, 0xff, 0x55], 1);
        assert_eq!(destination, [0xf0, 0x0f, 0xff]);
    }

    #[test]
    fn accumulate_scaled_touches_only_the_source_length() {
        let coder = RSCoder8::new(1).unwrap();
        let mut destination = [1, 2, 3, 4];
        coder.accumulate_scaled(&mut destination, &[1, 1], 1);
        assert_eq!(destination, [0, 3, 3, 4]);
    }

    #[test]
    fn rs8_rejects_more_erasures_than_parity_symbols() {
        let coder = RSCoder8::new(2).unwrap();
        let mut codeword = b"abcde".to_vec();

        assert_eq!(
            coder.correct_erasures(&mut codeword, &[0, 1, 2]),
            Err(Error::TooManyErasures)
        );
    }

    #[test]
    fn rs8_rejects_invalid_parameters_and_corrupt_unmarked_codewords() {
        assert_eq!(RSCoder8::new(0).unwrap_err(), Error::InvalidParitySize);
        assert_eq!(RSCoder8::new(256).unwrap_err(), Error::InvalidParitySize);

        let coder = RSCoder8::new(1).unwrap();
        assert_eq!(
            coder.correct_erasures(&mut [], &[]),
            Err(Error::InvalidCodewordSize)
        );
        assert_eq!(
            coder.correct_erasures(&mut [0; 256], &[]),
            Err(Error::InvalidCodewordSize)
        );
        assert_eq!(
            coder.correct_erasures(&mut [0; 2], &[2]),
            Err(Error::InvalidCodewordSize)
        );
        assert_eq!(coder.correct_erasures(&mut [0; 2], &[]), Ok(()));
        assert_eq!(
            coder.correct_erasures(&mut [1, 0], &[]),
            Err(Error::DecodeFailed)
        );
    }

    #[test]
    fn rs8_reports_each_failure_category() {
        for (error, message) in [
            (
                Error::InvalidParitySize,
                "RAR 3 recovery parity size is invalid",
            ),
            (
                Error::InvalidCodewordSize,
                "RAR 3 recovery codeword size is invalid",
            ),
            (
                Error::TooManyErasures,
                "RAR 3 recovery data cannot repair this many erasures",
            ),
            (Error::DecodeFailed, "RAR 3 recovery decode failed"),
        ] {
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn rs8_rejects_duplicate_erasure_positions() {
        for parity in 2..=4 {
            let coder = RSCoder8::new(parity).unwrap();
            for codeword_len in 2..=8 {
                for index in 0..codeword_len {
                    let mut codeword = vec![0; codeword_len];
                    codeword[0] = 1;
                    assert!(
                        coder
                            .correct_erasures(&mut codeword, &[index, index])
                            .is_err(),
                        "parity={parity}, length={codeword_len}, index={index}"
                    );
                }
            }
        }
    }

    #[test]
    fn rev3_rejects_invalid_shard_geometry_and_duplicate_recovery_indices() {
        let present = [1u8, 2];
        let recovery = [3u8, 4];
        type Case<'a> = (
            &'a [Option<&'a [u8]>],
            usize,
            &'a [(usize, &'a [u8])],
            Error,
        );
        let cases: &[Case<'_>] = &[
            (&[], 1, &[(0, &recovery)], Error::InvalidCodewordSize),
            (&[None], 255, &[(0, &recovery)], Error::InvalidCodewordSize),
            (&[None], 0, &[(0, &recovery)], Error::InvalidParitySize),
            (&[None], 1, &[], Error::InvalidParitySize),
            (&[None], 1, &[(1, &recovery)], Error::InvalidCodewordSize),
            (
                &[None],
                1,
                &[(0, &recovery), (0, &present[..1])],
                Error::InvalidCodewordSize,
            ),
            (
                &[Some(&present)],
                1,
                &[(0, &recovery[..1])],
                Error::InvalidCodewordSize,
            ),
            (
                &[None],
                1,
                &[(0, &recovery), (0, &recovery)],
                Error::InvalidCodewordSize,
            ),
            (&[None, None], 1, &[(0, &recovery)], Error::TooManyErasures),
        ];
        for &(data, count, shards, ref expected) in cases {
            assert_eq!(
                reconstruct_data_volumes(data, count, shards),
                Err(expected.clone())
            );
        }
    }

    #[test]
    fn rev3_returns_healthy_padded_data_without_decoding() {
        let actual = b"a";
        let recovery = b"rs";
        assert_eq!(
            reconstruct_data_volumes(&[Some(actual)], 1, &[(0, recovery)]),
            Ok(vec![b"a\0".to_vec()])
        );
    }

    fn reconstruct_per_byte(
        data_volumes: &[Option<&[u8]>],
        recovery_count: usize,
        recovery_volumes: &[(usize, &[u8])],
    ) -> Vec<Vec<u8>> {
        let shard_len = recovery_volumes[0].1.len();
        let total = data_volumes.len() + recovery_count;
        let mut codewords = vec![vec![0u8; total]; shard_len];
        for (index, data) in data_volumes.iter().enumerate() {
            for (offset, &byte) in data.unwrap_or_default().iter().enumerate() {
                codewords[offset][index] = byte;
            }
        }
        for &(index, data) in recovery_volumes {
            for (offset, &byte) in data.iter().enumerate() {
                codewords[offset][data_volumes.len() + index] = byte;
            }
        }
        let erasures: Vec<_> = (0..total)
            .filter(|&index| match data_volumes.get(index) {
                Some(data) => data.is_none(),
                None => recovery_volumes
                    .iter()
                    .all(|&(rev, _)| rev != index - data_volumes.len()),
            })
            .collect();
        let coder = RSCoder8::new(recovery_count).unwrap();
        for codeword in &mut codewords {
            coder.correct_erasures(codeword, &erasures).unwrap();
        }
        (0..data_volumes.len())
            .map(|index| codewords.iter().map(|codeword| codeword[index]).collect())
            .collect()
    }

    fn rev3_test_bytes(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    fn encode_rev3<T: AsRef<[u8]>>(
        data: &[T],
        recovery_count: usize,
        shard_len: usize,
    ) -> Vec<Vec<u8>> {
        let coder = RSCoder8::new(recovery_count).unwrap();
        let mut recovery = vec![vec![0; shard_len]; recovery_count];
        for offset in 0..shard_len {
            let column: Vec<_> = data
                .iter()
                .map(|shard| shard.as_ref().get(offset).copied().unwrap_or(0))
                .collect();
            for (row, byte) in recovery.iter_mut().zip(coder.encode(&column)) {
                row[offset] = byte;
            }
        }
        recovery
    }

    #[test]
    fn rev3_rebuilds_every_missing_mix_like_the_per_byte_decode() {
        let shard_len = 37;
        // Unequal lengths, a byte-short volume, and empty volumes mid-set and last.
        let lengths = [shard_len, 20, 0, shard_len - 1, 5, 0];
        let data: Vec<Vec<u8>> = lengths
            .iter()
            .enumerate()
            .map(|(index, &len)| rev3_test_bytes(len, index as u32 + 1))
            .collect();
        for recovery_count in 1..=4 {
            let mut recovery = encode_rev3(&data, recovery_count, shard_len);
            let total = data.len() + recovery_count;
            for mask in 1u32..(1 << total) {
                let missing = |index: usize| mask & (1 << index) != 0;
                if mask.count_ones() as usize > recovery_count
                    || (0..data.len()).all(|index| !missing(index))
                {
                    continue;
                }
                let volumes: Vec<Option<&[u8]>> = data
                    .iter()
                    .enumerate()
                    .map(|(index, shard)| (!missing(index)).then_some(shard.as_slice()))
                    .collect();
                for damage in [false, true] {
                    // A damaged survivor makes the column inconsistent, which
                    // the decode still maps the same way.
                    recovery[0][3] ^= u8::from(damage);
                    let present: Vec<(usize, &[u8])> = recovery
                        .iter()
                        .enumerate()
                        .filter(|&(index, _)| !missing(data.len() + index))
                        .map(|(index, shard)| (index, shard.as_slice()))
                        .collect();
                    let repaired =
                        reconstruct_data_volumes(&volumes, recovery_count, &present).unwrap();
                    assert_eq!(
                        repaired,
                        reconstruct_per_byte(&volumes, recovery_count, &present),
                        "parity {recovery_count}, missing {mask:#b}, damaged {damage}"
                    );
                    if !damage || missing(data.len()) {
                        for (shard, original) in repaired.iter().zip(&data) {
                            assert_eq!(&shard[..original.len()], original.as_slice());
                            assert!(shard[original.len()..].iter().all(|&byte| byte == 0));
                        }
                    }
                    recovery[0][3] ^= u8::from(damage);
                }
            }
        }
    }

    #[test]
    fn rev3_rebuild_fingerprints_are_unchanged() {
        // CRC32s of rebuilds made by the per-byte decode. Random recovery
        // volumes match no data, so every missing byte depends on the map.
        let shard_len = 4097;
        let data: Vec<Vec<u8>> = [shard_len, 4096, 0, 1000, shard_len, 13]
            .iter()
            .enumerate()
            .map(|(index, &len)| rev3_test_bytes(len, index as u32 + 10))
            .collect();
        let recovery: Vec<Vec<u8>> = (0..3)
            .map(|index| rev3_test_bytes(shard_len, index + 20))
            .collect();
        let mut found = Vec::new();
        for (missing_data, missing_recovery) in [
            (&[0][..], &[][..]),
            (&[2, 4], &[]),
            (&[1, 3], &[1]),
            (&[0, 1, 2], &[]),
            (&[5], &[0, 2]),
        ] {
            let volumes: Vec<Option<&[u8]>> = data
                .iter()
                .enumerate()
                .map(|(index, shard)| (!missing_data.contains(&index)).then_some(shard.as_slice()))
                .collect();
            let present: Vec<(usize, &[u8])> = recovery
                .iter()
                .enumerate()
                .filter(|(index, _)| !missing_recovery.contains(index))
                .map(|(index, shard)| (index, shard.as_slice()))
                .collect();
            let repaired = reconstruct_data_volumes(&volumes, 3, &present).unwrap();
            found.push(crate::crc32::crc32(&repaired.concat()));
        }
        assert_eq!(
            found,
            [
                0x1237_6c6e,
                0x83ff_42de,
                0xf4a4_a312,
                0x4e45_b3b4,
                0xf963_6b1b
            ]
        );
    }

    #[test]
    fn rev3_rebuilds_empty_shards() {
        assert_eq!(
            reconstruct_data_volumes(&[Some(&[]), None], 1, &[(0, &[])]),
            Ok(vec![Vec::new(), Vec::new()])
        );
    }

    #[test]
    fn rev3_reconstructs_missing_data_volume_from_recovery_volume() {
        let data = [
            b"volume-one".as_slice(),
            b"volume-two".as_slice(),
            b"volume-three".as_slice(),
        ];
        let recovery_count = 2;
        let shard_len = data.iter().map(|shard| shard.len()).max().unwrap();
        let recovery = encode_rev3(&data, recovery_count, shard_len);

        let repaired = reconstruct_data_volumes(
            &[Some(data[0]), None, Some(data[2])],
            recovery_count,
            &[(0, recovery[0].as_slice())],
        )
        .unwrap();

        assert_eq!(&repaired[1][..data[1].len()], data[1]);
    }
}
