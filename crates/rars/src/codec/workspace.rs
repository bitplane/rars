//! Fallible ownership of codec allocation capacity. A local allowance never
//! reaches into a sibling worker's spare bytes. Internal admission tests connect
//! these owners to coordinator reservations; unlimited handles preserve behaviour.
use super::{Error, Result};
#[cfg(test)]
mod ledger;
#[cfg(test)]
pub(crate) use ledger::{Charge, Limited, Reservation, RESERVATION_BYTES};

/// A zero-sized policy: its buffers have exactly Vec's layout and no ledger
/// branch in their hot operations. Limited buffers are a separate instantiation.
#[derive(Clone, Debug, Default)]
pub(crate) struct Allowance {
    _unlimited: (),
}
impl Allowance {
    #[cfg(test)]
    pub(crate) fn limited(limit: u64) -> Limited {
        Limited::new(limit)
    }
}

pub(crate) trait Budget: Clone + std::fmt::Debug {
    type Charge: std::fmt::Debug;
    type Failure: Into<Error>;
    fn grow<T>(
        values: &mut Vec<T>,
        charge: &mut Self::Charge,
        additional: usize,
    ) -> std::result::Result<(), Self::Failure>;
    const LIMITED: bool;
    fn charge(&self) -> Self::Charge;
    fn allowance(charge: &Self::Charge) -> Self;
    fn resize(charge: &mut Self::Charge, bytes: u64) -> Result<()>;
}
impl Budget for Allowance {
    type Charge = ();
    type Failure = std::convert::Infallible;
    fn grow<T>(
        values: &mut Vec<T>,
        _: &mut (),
        additional: usize,
    ) -> std::result::Result<(), Self::Failure> {
        values.reserve(additional);
        Ok(())
    }
    const LIMITED: bool = false;
    fn charge(&self) {}
    fn allowance(_: &()) -> Self {
        Self::default()
    }
    fn resize(_: &mut (), _: u64) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl Budget for Limited {
    type Charge = Charge;
    type Failure = Error;
    fn grow<T>(values: &mut Vec<T>, charge: &mut Charge, additional: usize) -> Result<()> {
        let end = values
            .len()
            .checked_add(additional)
            .ok_or(Error::InvalidData("codec capacity overflows"))?;
        if end <= values.capacity() {
            return Ok(());
        }
        let capacity = end.max(values.capacity().saturating_mul(2)).max(4);
        let bytes = allocation_size::<T>(capacity)?;
        let peak = bytes
            .checked_add(charge.bytes)
            .ok_or(Error::InvalidData("codec capacity overflows"))?;
        Self::resize(charge, peak)?;
        let mut replacement = Vec::with_capacity(capacity);
        replacement.append(values);
        *values = replacement;
        Self::resize(charge, bytes)?;
        Ok(())
    }
    const LIMITED: bool = true;
    fn charge(&self) -> Charge {
        Charge {
            allowance: self.clone(),
            bytes: 0,
        }
    }
    fn allowance(charge: &Charge) -> Self {
        charge.allowance.clone()
    }
    fn resize(charge: &mut Charge, bytes: u64) -> Result<()> {
        charge.resize(bytes)
    }
}

/// Storage is dropped before its charge. Slice access cannot grow an allocation
/// behind the ledger's back; growth and ownership transfer are explicit.
#[derive(Debug)]
pub(crate) struct Buffer<T, B: Budget = Allowance> {
    values: Vec<T>,
    charge: B::Charge,
}
impl<T, B: Budget> Buffer<T, B> {
    pub(crate) fn new(allowance: &B) -> Self {
        Self {
            values: Vec::new(),
            charge: allowance.charge(),
        }
    }
    pub(crate) fn with_capacity(capacity: usize, allowance: &B) -> Result<Self> {
        let bytes = allocation_size::<T>(capacity)?;
        let mut out = Self::new(allowance);
        B::resize(&mut out.charge, bytes)?;
        out.values = Vec::with_capacity(capacity);
        Ok(out)
    }
    pub(crate) fn filled(len: usize, value: T, allowance: &B) -> Result<Self>
    where
        T: Clone,
    {
        // Keep vec![0; n]'s zeroed allocation fast path for finder links.
        let bytes = allocation_size::<T>(len)?;
        let mut out = Self::new(allowance);
        B::resize(&mut out.charge, bytes)?;
        out.values = vec![value; len];
        Ok(out)
    }
    pub(crate) fn allowance(&self) -> B {
        B::allowance(&self.charge)
    }
    fn reserve(&mut self, additional: usize) -> Result<()> {
        B::grow(&mut self.values, &mut self.charge, additional).map_err(Into::into)
    }
    #[inline]
    pub(crate) fn push(&mut self, value: T) -> std::result::Result<(), B::Failure> {
        if B::LIMITED && self.values.len() == self.values.capacity() {
            B::grow(&mut self.values, &mut self.charge, 1)?;
        }
        self.values.push(value);
        Ok(())
    }
    pub(crate) fn try_push(&mut self, value: T) -> Result<()> {
        self.push(value).map_err(Into::into)
    }
    pub(crate) fn collect(values: impl IntoIterator<Item = T>, allowance: &B) -> Result<Self> {
        let values = values.into_iter();
        let mut out = Self::with_capacity(values.size_hint().0, allowance)?;
        for value in values {
            out.try_push(value)?;
        }
        Ok(out)
    }
    pub(crate) fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.values.retain(keep);
    }
    pub(crate) fn truncate(&mut self, len: usize) {
        self.values.truncate(len);
    }
    pub(crate) fn resize(&mut self, len: usize, value: T) -> Result<()>
    where
        T: Clone,
    {
        if B::LIMITED && len > self.values.capacity() {
            self.reserve(len - self.values.len())?;
        }
        self.values.resize(len, value);
        Ok(())
    }
    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }
    pub(crate) fn copied(values: &[T], allowance: &B) -> Result<Self>
    where
        T: Copy,
    {
        let mut out = Self::with_capacity(values.len(), allowance)?;
        out.extend_from_slice(values).map_err(Into::into)?;
        Ok(out)
    }
    /// Admit the final window before modifying it. A refusal keeps the old
    /// history intact, and input larger than the window is never copied in full.
    pub(crate) fn remember(&mut self, input: &[T], limit: usize) -> Result<()>
    where
        T: Copy,
    {
        let input = &input[input.len().saturating_sub(limit)..];
        let keep = self.len().min(limit - input.len());
        self.reserve((keep + input.len()).saturating_sub(self.len()))?;
        let start = self.len() - keep;
        self.values.copy_within(start.., 0);
        self.values.truncate(keep);
        self.extend_from_slice(input).map_err(Into::into)
    }
    pub(crate) fn extend_from_slice(&mut self, values: &[T]) -> std::result::Result<(), B::Failure>
    where
        T: Copy,
    {
        if B::LIMITED && values.len() > self.values.capacity() - self.values.len() {
            B::grow(&mut self.values, &mut self.charge, values.len())?;
        }
        self.values.extend_from_slice(values);
        Ok(())
    }
    pub(crate) fn prepend(&mut self, prefix: impl ExactSizeIterator<Item = T>) -> Result<()> {
        self.reserve(prefix.len())?;
        let old_len = self.values.len();
        for value in prefix {
            self.push(value).map_err(Into::into)?;
        }
        let inserted = self.values.len() - old_len;
        self.values.rotate_right(inserted);
        Ok(())
    }
}
pub(crate) struct BufferIter<T, B: Budget> {
    values: std::vec::IntoIter<T>,
    _charge: B::Charge,
}
impl<T, B: Budget> IntoIterator for Buffer<T, B> {
    type Item = T;
    type IntoIter = BufferIter<T, B>;
    fn into_iter(self) -> Self::IntoIter {
        BufferIter {
            values: self.values.into_iter(),
            _charge: self.charge,
        }
    }
}
impl<T, B: Budget> Iterator for BufferIter<T, B> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl<T, B: Budget> ExactSizeIterator for BufferIter<T, B> {}
impl<T> Buffer<T> {
    pub(crate) fn from_vec(values: Vec<T>) -> Self {
        Self { values, charge: () }
    }
    /// Only unlimited buffers can cross an existing unaccounted Vec boundary.
    pub(crate) fn into_vec(self) -> Vec<T> {
        self.values
    }
}
impl<B: Budget> Buffer<u8, B> {
    pub(crate) fn write_msb_bits(
        &mut self,
        bit_pos: &mut usize,
        value: u64,
        count: usize,
    ) -> std::result::Result<(), B::Failure> {
        let used = *bit_pos % 8;
        let additional = (used + count).div_ceil(8) - usize::from(used != 0);
        if B::LIMITED && additional > self.values.capacity() - self.values.len() {
            B::grow(&mut self.values, &mut self.charge, additional)?;
        }
        super::fast::write_msb_bits(&mut self.values, bit_pos, value, count);
        Ok(())
    }
}
fn allocation_size<T>(capacity: usize) -> Result<u64> {
    capacity
        .checked_mul(std::mem::size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .map(|bytes| bytes as u64)
        .ok_or(Error::InvalidData("codec capacity overflows"))
}
impl<T, B: Budget> std::ops::Deref for Buffer<T, B> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T, B: Budget> std::ops::DerefMut for Buffer<T, B> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}
impl<T: PartialEq, B: Budget, C: Budget> PartialEq<Buffer<T, C>> for Buffer<T, B> {
    fn eq(&self, other: &Buffer<T, C>) -> bool {
        **self == **other
    }
}
impl<T: PartialEq, B: Budget> PartialEq<Vec<T>> for Buffer<T, B> {
    fn eq(&self, other: &Vec<T>) -> bool {
        &**self == other.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_admits_before_mutation_and_only_copies_the_retained_tail() {
        for limit in [10, 11] {
            let allowance = Allowance::limited(limit);
            let mut history = Buffer::copied(b"abc", &allowance).unwrap();
            let result = history.remember(b"0123456789", 8);
            if limit == 10 {
                assert!(matches!(result, Err(Error::WorkspaceLimitExceeded(_))));
                assert_eq!(&*history, b"abc");
                assert_eq!(allowance.used(), 3);
            } else {
                result.unwrap();
                assert_eq!(&*history, b"23456789");
                assert_eq!(allowance.used(), 8);
            }
        }
        let input = vec![42; 1024 * 1024];
        let allowance = Allowance::limited(8);
        let mut history = Buffer::new(&allowance);
        history.remember(&input, 8).unwrap();
        history.remember(b"abc", 8).unwrap();
        assert_eq!(&*history, &[42, 42, 42, 42, 42, b'a', b'b', b'c']);
        assert_eq!(allowance.used(), 8);
        history.remember(b"discard", 0).unwrap();
        assert!(history.is_empty());
        assert_eq!(allowance.used(), 8, "spare capacity remains owned");
        drop(history);
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn consuming_a_container_keeps_its_allocation_and_extracted_children_charged() {
        let allowance = Allowance::limited(4096);
        let mut owners = Buffer::with_capacity(2, &allowance).unwrap();
        owners
            .push(Buffer::filled(8, 1u8, &allowance).unwrap())
            .unwrap();
        owners
            .push(Buffer::filled(16, 2u8, &allowance).unwrap())
            .unwrap();
        let total = allowance.used();
        let mut iter = owners.into_iter();
        let first = iter.next().unwrap();
        assert_eq!(iter.len(), 1);
        assert_eq!(allowance.used(), total);
        drop(iter);
        assert_eq!(allowance.used(), 8);
        assert_eq!(&*first, &[1; 8]);
        drop(first);
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn unlimited_buffers_and_success_results_keep_the_existing_layout() {
        assert_eq!(
            std::mem::size_of::<Buffer<u8>>(),
            std::mem::size_of::<Vec<u8>>()
        );
        assert!(
            std::mem::size_of::<Result<usize>>() <= std::mem::size_of::<(&str, usize)>(),
            "large diagnostics must not widen hot codec results"
        );
    }

    #[test]
    fn growth_reserves_replacement_peak_and_refusal_preserves_storage() {
        for limit in [23, 24] {
            let allowance = Allowance::limited(limit);
            let mut buffer = Buffer::filled(1, 7u64, &allowance).unwrap();
            // Bounded growth requests at least four elements: 8 old + 32 new.
            assert!(matches!(
                buffer.push(9),
                Err(Error::WorkspaceLimitExceeded(details)) if details.required == 40 && details.used == 8
            ));
            assert_eq!(&*buffer, &[7]);
            assert_eq!(allowance.used(), 8);
            drop(buffer);
            assert_eq!(allowance.used(), 0);
        }
        let allowance = Allowance::limited(40);
        let mut buffer = Buffer::filled(1, 7u64, &allowance).unwrap();
        buffer.push(9).unwrap();
        assert_eq!(&*buffer, &[7, 9]);
        assert_eq!(allowance.used(), 32);
        buffer.clear();
        assert_eq!(allowance.used(), 32, "spare capacity is still owned");
        drop(buffer);
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn prepend_keeps_order_and_refuses_before_mutating_a_full_buffer() {
        let allowance = Allowance::limited(8);
        let mut buffer = Buffer::filled(4, 7u8, &allowance).unwrap();
        assert!(buffer.prepend([1, 2].into_iter()).is_err());
        assert_eq!(&*buffer, &[7, 7, 7, 7]);
        assert_eq!(allowance.used(), 4);
        drop(buffer);
        let allowance = Allowance::limited(12);
        let mut buffer = Buffer::filled(4, 7u8, &allowance).unwrap();
        buffer.prepend([1, 2].into_iter()).unwrap();
        assert_eq!(&*buffer, &[1, 2, 7, 7, 7, 7]);
        assert_eq!(allowance.used(), 8);
    }

    #[test]
    fn ownership_keeps_charges_through_failure_and_unwind() {
        struct Probe(Limited);
        impl Drop for Probe {
            fn drop(&mut self) {
                assert!(self.0.used() > 0);
            }
        }
        let allowance = Allowance::limited(4096);
        let result = std::panic::catch_unwind(|| {
            let mut values = Buffer::with_capacity(1, &allowance).unwrap();
            values.push(Probe(allowance.clone())).unwrap();
            assert!(Buffer::<u8, _>::with_capacity(4096, &allowance).is_err());
            panic!("unwind the worker");
        });
        assert!(result.is_err());
        assert_eq!(allowance.used(), 0);
        drop(Buffer::<u8, _>::with_capacity(4096, &allowance).unwrap());
        assert_eq!(allowance.used(), 0);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn retained_buffers_move_between_threads_without_releasing_capacity() {
        let allowance = Allowance::limited(32);
        let retained = Buffer::filled(32, 1u8, &allowance).unwrap();
        let clone = allowance.clone();
        std::thread::spawn(move || {
            assert_eq!(clone.used(), 32);
            assert!(Buffer::<u8, _>::with_capacity(1, &clone).is_err());
            drop(retained);
            assert_eq!(clone.used(), 0);
        })
        .join()
        .unwrap();
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn independent_allowances_do_not_race_for_each_others_spare_bytes() {
        let first = Allowance::limited(16);
        let second = Allowance::limited(16);
        let kept = Buffer::<u8, _>::with_capacity(16, &first).unwrap();
        assert!(Buffer::<u8, _>::with_capacity(1, &first).is_err());
        drop(Buffer::<u8, _>::with_capacity(16, &second).unwrap());
        assert_eq!(first.used(), 16);
        assert_eq!(second.used(), 0);
        drop(kept);
        assert_eq!(first.used(), 0);
    }
}
