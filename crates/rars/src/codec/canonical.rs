//! Canonical decoder mechanics shared by the explicit-table RAR formats.
//! Code-length parsing, diagnostics and bit input remain format-specific.
use super::workspace::{Allowance, Budget, Buffer};
use super::{Error, Result};

#[derive(Debug)]
pub(super) struct Huffman<B: Budget = Allowance> {
    symbols: Buffer<usize, B>,
    first_code: [u16; 16],
    first_index: [usize; 16],
    counts: [u16; 16],
}

impl<B: Budget> Huffman<B> {
    pub(super) fn with_allowance(allowance: &B) -> Self {
        Self {
            symbols: Buffer::new(allowance),
            first_code: [0; 16],
            first_index: [0; 16],
            counts: [0; 16],
        }
    }

    /// `counts` has been checked for oversubscription and corresponds to
    /// `lengths`; only nonzero lengths 1..=15 contribute symbols. Incomplete
    /// tables are accepted: unused alphabets and unassigned prefixes occur in
    /// the supported formats. Invalid prefixes are rejected when decoded.
    pub(super) fn from_counts(lengths: &[u8], counts: [u16; 16], allowance: &B) -> Result<Self> {
        let mut first_code = [0u16; 16];
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code + counts[len - 1]) << 1;
            first_code[len] = code;
        }
        let mut first_index = [0usize; 16];
        let mut index = 0usize;
        for len in 1..=15 {
            first_index[len] = index;
            index += usize::from(counts[len]);
        }
        // Codes of one length follow alphabet order. Scatter directly into
        // those ranges instead of storing (code, length, symbol) and sorting.
        // Keep usize indices: the public RAR5 constructor also accepts sparse
        // alphabets whose symbol index exceeds a 16-bit value.
        let mut symbols = Buffer::filled(index, 0, allowance)?;
        let mut next_index = first_index;
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            symbols[next_index[len as usize]] = symbol;
            next_index[len as usize] += 1;
        }
        Ok(Self {
            symbols,
            first_code,
            first_index,
            counts,
        })
    }

    pub(super) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            symbols: Buffer::copied(&self.symbols, &self.symbols.allowance())?,
            first_code: self.first_code,
            first_index: self.first_index,
            counts: self.counts,
        })
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.symbols.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Read only the bits of the selected code. A speculative wide peek would
    /// change truncation and incremental-input behavior near an input boundary.
    pub(super) fn decode(
        &self,
        mut read_bit: impl FnMut() -> Result<u16>,
        empty: &'static str,
        invalid: &'static str,
    ) -> Result<usize> {
        if self.is_empty() {
            return Err(Error::InvalidData(empty));
        }
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code << 1) | read_bit()?;
            let count = self.counts[len];
            if count != 0 {
                let offset = code.wrapping_sub(self.first_code[len]);
                if offset < count {
                    let index = self.first_index[len] + usize::from(offset);
                    return Ok(self.symbols[index]);
                }
            }
        }
        Err(Error::InvalidData(invalid))
    }
}

pub(super) fn validate_counts(counts: &[u16; 16], oversubscribed: &'static str) -> Result<()> {
    let mut available = 1i32;
    for &count in counts.iter().skip(1) {
        available = (available << 1) - i32::from(count);
        if available < 0 {
            return Err(Error::InvalidData(oversubscribed));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_codes_keep_alphabet_indices_and_consume_only_their_bits() {
        let lengths = [3, 0, 1, 3, 2];
        let mut counts = [0; 16];
        counts[1] = 1;
        counts[2] = 1;
        counts[3] = 2;
        let table = Huffman::from_counts(&lengths, counts, &Allowance::default()).unwrap();
        assert_eq!(table.len(), 4);
        // Canonical order is (length, alphabet index): 2=0, 4=10,
        // 0=110, 3=111. Each input ends exactly at the selected code.
        for (symbol, bits) in [
            (2, vec![0]),
            (4, vec![1, 0]),
            (0, vec![1, 1, 0]),
            (3, vec![1, 1, 1]),
        ] {
            let mut input = bits.into_iter();
            assert_eq!(
                table.decode(
                    || input.next().ok_or(Error::NeedMoreInput),
                    "empty",
                    "invalid"
                ),
                Ok(symbol)
            );
            assert_eq!(input.next(), None);
        }
    }

    #[test]
    fn empty_invalid_truncated_and_cancelled_codes_keep_their_errors() {
        let table = Huffman::with_allowance(&Allowance::default());
        assert_eq!(
            table.decode(
                || panic!("empty table must not read input"),
                "empty",
                "invalid"
            ),
            Err(Error::InvalidData("empty"))
        );
        let mut counts = [0; 16];
        counts[2] = 1;
        validate_counts(&counts, "oversubscribed").unwrap();
        let table = Huffman::from_counts(&[2], counts, &Allowance::default()).unwrap();
        assert_eq!(
            table.decode(|| Ok(1), "empty", "invalid"),
            Err(Error::InvalidData("invalid"))
        );
        assert_eq!(
            table.decode(|| Err(Error::NeedMoreInput), "empty", "invalid"),
            Err(Error::NeedMoreInput)
        );
        assert_eq!(
            table.decode(|| Err(Error::Cancelled), "empty", "invalid"),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn table_and_checkpoint_allocations_are_admitted_and_released() {
        let mut counts = [0; 16];
        counts[1] = 2;
        let allowance = Allowance::limited(64 * 1024);
        let table = Huffman::from_counts(&[1, 1], counts, &allowance).unwrap();
        let retained = allowance.used();
        assert_eq!(retained, (2 * std::mem::size_of::<usize>()) as u64);
        let copy = table.try_clone().unwrap();
        assert_eq!(allowance.used(), retained * 2);
        drop(table);
        assert_eq!(copy.decode(|| Ok(1), "empty", "invalid"), Ok(1));
        assert_eq!(allowance.used(), retained);
        drop(copy);
        assert_eq!(allowance.used(), 0);
        let allowance = Allowance::limited(retained);
        let table = Huffman::from_counts(&[1, 1], counts, &allowance).unwrap();
        assert!(matches!(
            table.try_clone(),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
        assert_eq!(allowance.used(), retained);
        drop(table);
        assert_eq!(allowance.used(), 0);
        assert!(matches!(
            Huffman::from_counts(&[1, 1], counts, &Allowance::limited(0)),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
    }

    #[test]
    fn sparse_alphabet_keeps_the_full_symbol_index() {
        let mut lengths = vec![0; 65_538];
        lengths[65_537] = 1;
        let mut counts = [0; 16];
        counts[1] = 1;
        let table = Huffman::from_counts(&lengths, counts, &Allowance::default()).unwrap();
        assert_eq!(table.decode(|| Ok(0), "empty", "invalid"), Ok(65_537));
    }
}
