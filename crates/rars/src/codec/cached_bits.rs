use super::canonical::Huffman;
use super::{Error, Result};

#[derive(Clone, Copy)]
pub(super) struct CachedBits<'a> {
    input: &'a [u8],
    byte_pos: usize,
    // MSB-first; bits below `cache_bits` may preview the next input bytes.
    pub(super) cache: u64,
    pub(super) cache_bits: u32,
}

impl<'a> CachedBits<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self::at(input, 0)
    }

    pub(super) fn at(input: &'a [u8], bit_pos: usize) -> Self {
        debug_assert!(bit_pos.div_ceil(8) <= input.len());
        let mut reader = Self {
            input,
            byte_pos: bit_pos / 8,
            cache: 0,
            cache_bits: 0,
        };
        let offset = (bit_pos % 8) as u32;
        if offset != 0 {
            reader.refill();
            reader.skip(offset.min(reader.cache_bits) as usize);
        }
        reader
    }

    #[inline(always)]
    pub(super) fn position(&self) -> usize {
        self.byte_pos * 8 - self.cache_bits as usize
    }

    #[inline(always)]
    pub(super) fn refill(&mut self) {
        if let Some(bytes) = self
            .input
            .get(self.byte_pos..)
            .and_then(|rest| rest.first_chunk::<8>())
        {
            self.cache |= u64::from_be_bytes(*bytes) >> self.cache_bits;
            let whole = (64 - self.cache_bits) & !7;
            self.byte_pos += (whole / 8) as usize;
            self.cache_bits += whole;
        } else {
            // Inline: any call here spills the burst's reader to the stack.
            while self.cache_bits <= 56 && self.byte_pos < self.input.len() {
                self.cache |= u64::from(self.input[self.byte_pos]) << (56 - self.cache_bits);
                self.byte_pos += 1;
                self.cache_bits += 8;
            }
        }
    }

    /// The next 15 bits, most significant first, with zeros past the end of
    /// the input, and how many of them are real (at most 15).
    #[inline(always)]
    pub(super) fn peek15(&mut self) -> (u32, usize) {
        if self.cache_bits < 15 {
            self.refill();
        }
        ((self.cache >> 49) as u32, self.cache_bits.min(15) as usize)
    }

    /// Consumes `count` bits already seen through [`Self::peek15`].
    #[inline(always)]
    pub(super) fn skip(&mut self, count: usize) {
        debug_assert!(count <= self.cache_bits as usize);
        self.cache <<= count;
        self.cache_bits -= count as u32;
    }

    #[inline(always)]
    pub(super) fn read_bits(&mut self, count: u8) -> Result<u32> {
        let count = u32::from(count);
        if count == 0 {
            return Ok(0);
        }
        if count > 32 || self.cache_bits < count {
            return self.read_bits_slow(count);
        }
        let value = (self.cache >> (64 - count)) as u32;
        self.skip(count as usize);
        Ok(value)
    }

    /// RAR 7 distance extras run past 32 bits.
    #[inline(always)]
    pub(super) fn read_wide_bits(&mut self, count: usize) -> Result<u64> {
        if count <= 32 {
            return self.read_bits(count as u8).map(u64::from);
        }
        if self.remaining_bits() < count {
            return Err(Error::NeedMoreInput);
        }
        let high = self.read_bits((count - 32) as u8)?;
        let low = self.read_bits(32)?;
        Ok(u64::from(high) << 32 | u64::from(low))
    }

    fn remaining_bits(&self) -> usize {
        (self.input.len().saturating_sub(self.byte_pos))
            .saturating_mul(8)
            .saturating_add(self.cache_bits as usize)
    }

    #[inline(never)]
    fn read_bits_slow(&mut self, count: u32) -> Result<u32> {
        // Refusal consumes nothing, even for wide reads.
        if self.remaining_bits() < count as usize {
            return Err(Error::NeedMoreInput);
        }
        if count > 32 {
            // Wider internal reads keep the low 32 bits.
            let mut value = 0u32;
            let mut left = count;
            while left != 0 {
                let take = left.min(16);
                value = (value << take) | self.read_bits(take as u8)?;
                left -= take;
            }
            return Ok(value);
        }
        self.refill();
        let value = (self.cache >> (64 - count)) as u32;
        self.skip(count as usize);
        Ok(value)
    }

    /// Consumes nothing on `None`, leaving the code to the caller's full decoder.
    #[inline(always)]
    pub(super) fn quick_literal(&mut self, table: &Huffman) -> Option<u8> {
        let (peek, available) = self.peek15();
        let entry = table.quick_entry(peek);
        let len = (entry & 15) as usize;
        if entry == 0 || entry >= 256 << 4 || len > available {
            return None;
        }
        self.skip(len);
        Some((entry >> 4) as u8)
    }

    /// A call-free loop over a copy, so the reader stays in registers per literal.
    #[inline(always)]
    pub(super) fn quick_literals(&mut self, table: &Huffman, out: &mut [u8]) -> usize {
        let mut bits = *self;
        let mut count = 0;
        while count < out.len() {
            let Some(literal) = bits.quick_literal(table) else {
                break;
            };
            out[count] = literal;
            count += 1;
        }
        *self = bits;
        count
    }
}
