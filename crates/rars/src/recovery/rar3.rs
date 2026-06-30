const MAX_PARITY: usize = 255;
const MAX_POLYNOMIAL: usize = 512;
const PRIMITIVE_POLYNOMIAL: u16 = 0x11d;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidParitySize,
    InvalidCodewordSize,
    TooManyErasures,
    DecodeFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParitySize => f.write_str("RAR 3 recovery parity size is invalid"),
            Self::InvalidCodewordSize => f.write_str("RAR 3 recovery codeword size is invalid"),
            Self::TooManyErasures => {
                f.write_str("RAR 3 recovery data cannot repair this many erasures")
            }
            Self::DecodeFailed => f.write_str("RAR 3 recovery decode failed"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

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
        for root in (MAX_PARITY - codeword.len())..=MAX_PARITY {
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
        if error_locs.is_empty() || error_locs.len() > self.parity_size {
            return Err(Error::DecodeFailed);
        }

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
    if recovery_volumes.is_empty() || recovery_count == 0 || recovery_count > MAX_PARITY {
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
                let mut out = vec![0; shard_len];
                if let Some(data) = data {
                    out[..data.len()].copy_from_slice(data);
                }
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

    for offset in 0..shard_len {
        let mut codeword = vec![0; data_volumes.len() + recovery_count];
        for (index, data) in data_volumes.iter().enumerate() {
            if let Some(data) = data {
                codeword[index] = data.get(offset).copied().unwrap_or(0);
            }
        }
        for (index, data) in recovery_by_index.iter().enumerate() {
            if let Some(data) = data {
                codeword[data_volumes.len() + index] = data[offset];
            }
        }
        coder.correct_erasures(&mut codeword, &erasures)?;
        for &index in &missing_data {
            out[index][offset] = codeword[index];
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
    fn rs8_rejects_more_erasures_than_parity_symbols() {
        let coder = RSCoder8::new(2).unwrap();
        let mut codeword = b"abcde".to_vec();

        assert_eq!(
            coder.correct_erasures(&mut codeword, &[0, 1, 2]),
            Err(Error::TooManyErasures)
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
        let coder = RSCoder8::new(recovery_count).unwrap();
        let shard_len = data.iter().map(|shard| shard.len()).max().unwrap();
        let mut recovery = vec![vec![0; shard_len]; recovery_count];
        for offset in 0..shard_len {
            let column: Vec<_> = data
                .iter()
                .map(|shard| shard.get(offset).copied().unwrap_or(0))
                .collect();
            let encoded = coder.encode(&column);
            for (row, byte) in recovery.iter_mut().zip(encoded) {
                row[offset] = byte;
            }
        }

        let repaired = reconstruct_data_volumes(
            &[Some(data[0]), None, Some(data[2])],
            recovery_count,
            &[(0, recovery[0].as_slice())],
        )
        .unwrap();

        assert_eq!(&repaired[1][..data[1].len()], data[1]);
    }
}
