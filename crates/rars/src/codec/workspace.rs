//! Fallible ownership of codec allocation capacity. A local allowance never
//! reaches into a sibling worker's spare bytes. Internal admission tests connect
//! these owners to coordinator reservations; unlimited handles preserve behaviour.
use super::{Error, Result};
pub(crate) mod coordinator;
mod ledger;
pub(crate) use ledger::{Charge, Limited, Reservation};

/// Whether `error` is a codec workspace refusal.
pub(crate) fn is_refusal(error: &crate::Error) -> bool {
    matches!(
        error.root_cause(),
        crate::Error::Codec(Error::WorkspaceLimitExceeded(_))
    )
}

/// The one workspace budget type. `Allowance::default()` is unlimited and
/// [`Limited::limited`] refuses growth past a ceiling, so every codec is
/// compiled once.
pub(crate) type Allowance = Limited;

/// Admit a boxed value before constructing it. Its storage is freed before
/// the charge, including when construction fails or a decoder is replaced.
#[derive(Debug)]
pub(crate) struct Boxed<T> {
    value: Box<T>,
    _charge: Charge,
}
impl<T> Boxed<T> {
    pub(crate) fn try_new<E: From<Error>>(
        make: impl FnOnce() -> std::result::Result<T, E>,
        allowance: &Allowance,
    ) -> std::result::Result<Self, E> {
        let mut charge = allowance.charge();
        Allowance::resize(&mut charge, allocation_size::<T>(1)?)?;
        let value = make()?;
        Ok(Self {
            value: Box::new(value),
            _charge: charge,
        })
    }
}
impl<T> std::ops::Deref for Boxed<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> std::ops::DerefMut for Boxed<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
impl Limited {
    pub(crate) fn grow<T>(
        values: &mut Vec<T>,
        charge: &mut Charge,
        additional: usize,
    ) -> Result<()> {
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
        values.reserve_exact(capacity - values.len());
        Self::resize(charge, bytes)?;
        Ok(())
    }
    pub(crate) fn charge_is_limited(charge: &Charge) -> bool {
        charge.allowance.is_limited()
    }
    pub(crate) fn charge(&self) -> Charge {
        Charge {
            allowance: self.clone(),
            bytes: 0,
        }
    }
    pub(crate) fn allowance(charge: &Charge) -> Self {
        charge.allowance.clone()
    }
    pub(crate) fn resize(charge: &mut Charge, bytes: u64) -> Result<()> {
        charge.resize(bytes)
    }
}

/// Storage is dropped before its charge. Slice access cannot grow an allocation
/// behind the ledger's back; growth and ownership transfer are explicit.
#[derive(Debug)]
pub(crate) struct Buffer<T> {
    values: Vec<T>,
    charge: Charge,
}
impl<T> Buffer<T> {
    pub(crate) fn new(allowance: &Allowance) -> Self {
        Self {
            values: Vec::new(),
            charge: allowance.charge(),
        }
    }
    pub(crate) fn with_capacity(capacity: usize, allowance: &Allowance) -> Result<Self> {
        let bytes = allocation_size::<T>(capacity)?;
        let mut out = Self::new(allowance);
        Allowance::resize(&mut out.charge, bytes)?;
        out.values = Vec::with_capacity(capacity);
        Ok(out)
    }
    pub(crate) fn filled(len: usize, value: T, allowance: &Allowance) -> Result<Self>
    where
        T: Clone,
    {
        // Keep vec![0; n]'s zeroed allocation fast path for finder links.
        let bytes = allocation_size::<T>(len)?;
        let mut out = Self::new(allowance);
        Allowance::resize(&mut out.charge, bytes)?;
        out.values = vec![value; len];
        Ok(out)
    }
    /// [`Self::filled`] for values that are not `Clone`, each made by `make`.
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn filled_with(
        len: usize,
        make: impl FnMut() -> T,
        allowance: &Allowance,
    ) -> Result<Self> {
        let bytes = allocation_size::<T>(len)?;
        let mut out = Self::new(allowance);
        Allowance::resize(&mut out.charge, bytes)?;
        out.values = std::iter::repeat_with(make).take(len).collect();
        Ok(out)
    }
    /// Admit one exact allocation before copying slices that form a buffer.
    /// The total is checked first, so none of the copies can grow past its
    /// charged capacity.
    #[cfg(feature = "write")]
    pub(crate) fn from_slices(slices: &[&[T]], allowance: &Allowance) -> Result<Self>
    where
        T: Copy,
    {
        let len = slices.iter().try_fold(0usize, |total, slice| {
            total
                .checked_add(slice.len())
                .ok_or(Error::InvalidData("codec capacity overflows"))
        })?;
        let mut out = Self::with_capacity(len, allowance)?;
        for slice in slices {
            out.values.extend_from_slice(slice);
        }
        Ok(out)
    }
    pub(crate) fn capacity(&self) -> usize {
        self.values.capacity()
    }
    pub(crate) fn discard_prefix(&mut self, count: usize) {
        self.values.drain(..count);
    }
    pub(crate) fn extend_from_within(&mut self, range: std::ops::Range<usize>) -> Result<()>
    where
        T: Copy,
    {
        self.reserve(range.len())?;
        self.values.extend_from_within(range);
        Ok(())
    }
    pub(crate) fn allowance(&self) -> Allowance {
        Allowance::allowance(&self.charge)
    }
    /// Whether this buffer's budget has a ceiling.
    pub(crate) fn is_limited(&self) -> bool {
        Allowance::charge_is_limited(&self.charge)
    }
    fn reserve(&mut self, additional: usize) -> Result<()> {
        Allowance::grow(&mut self.values, &mut self.charge, additional)
    }
    /// Grows to hold `total` values, doubling as usual but never past
    /// `ceiling` unless `total` itself needs more. A window that settles at a
    /// known size then never pays for a doubling beyond it.
    pub(crate) fn reserve_up_to(&mut self, total: usize, ceiling: usize) -> Result<()> {
        let capacity = self.values.capacity();
        if total <= capacity {
            return Ok(());
        }
        let capacity = capacity.saturating_mul(2).min(ceiling).max(total);
        let mut replacement = Self::with_capacity(capacity, &self.allowance())?;
        replacement.values.append(&mut self.values);
        *self = replacement;
        Ok(())
    }
    #[cfg(feature = "write")]
    pub(crate) fn reserve_total_capacity(&mut self, total: usize) -> Result<()> {
        if total > self.values.capacity() {
            self.reserve(total.saturating_sub(self.values.len()))?;
        }
        debug_assert!(self.values.capacity() >= total);
        Ok(())
    }
    #[inline]
    pub(crate) fn push(&mut self, value: T) -> std::result::Result<(), crate::codec::Error> {
        if self.values.len() == self.values.capacity() {
            Allowance::grow(&mut self.values, &mut self.charge, 1)?;
        }
        self.values.push(value);
        Ok(())
    }
    /// Append after the caller has admitted enough capacity for the complete
    /// collection. This cannot grow the allocation or change its charge.
    pub(crate) fn push_admitted(&mut self, value: T) {
        debug_assert!(self.values.len() < self.values.capacity());
        self.values.push(value);
    }
    pub(crate) fn try_push(&mut self, value: T) -> Result<()> {
        self.push(value)
    }
    pub(crate) fn collect(
        values: impl IntoIterator<Item = T>,
        allowance: &Allowance,
    ) -> Result<Self> {
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
    /// Grows the allocation in place to exactly `capacity` values. The
    /// allocator can often extend a large block without copying it, where a
    /// fresh buffer always holds the old and new storage at once. Some
    /// allocators do copy, so the charge covers both until growth is done.
    pub(crate) fn grow_exact(&mut self, capacity: usize) -> Result<()> {
        if capacity <= self.values.capacity() {
            return Ok(());
        }
        let old = allocation_size::<T>(self.values.capacity())?;
        let new = allocation_size::<T>(capacity)?;
        let peak = old
            .checked_add(new)
            .ok_or(Error::InvalidData("codec capacity overflows"))?;
        Allowance::resize(&mut self.charge, peak)?;
        self.values.reserve_exact(capacity - self.values.len());
        Allowance::resize(
            &mut self.charge,
            allocation_size::<T>(self.values.capacity())?,
        )
    }
    /// Lets the allocator move the values without a second copy alive, for
    /// a budget that need not count both at once.
    pub(crate) fn grow_in_place(&mut self, capacity: usize) -> Result<()> {
        debug_assert!(!self.is_limited());
        if capacity <= self.values.capacity() {
            return Ok(());
        }
        Allowance::resize(&mut self.charge, allocation_size::<T>(capacity)?)?;
        self.values.reserve_exact(capacity - self.values.len());
        Ok(())
    }
    pub(crate) fn shrink_to(&mut self, capacity: usize) -> Result<()> {
        self.values.shrink_to(capacity);
        Allowance::resize(
            &mut self.charge,
            allocation_size::<T>(self.values.capacity())?,
        )
    }
    pub(crate) fn truncate(&mut self, len: usize) {
        self.values.truncate(len);
    }
    pub(crate) fn resize(&mut self, len: usize, value: T) -> Result<()>
    where
        T: Clone,
    {
        if len > self.values.capacity() {
            self.reserve(len - self.values.len())?;
        }
        self.values.resize(len, value);
        Ok(())
    }
    #[cfg(all(test, feature = "write"))]
    pub(crate) fn resize_with(&mut self, len: usize, make: impl FnMut() -> T) -> Result<()> {
        if len > self.values.capacity() {
            self.reserve(len - self.values.len())?;
        }
        self.values.resize_with(len, make);
        Ok(())
    }
    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }
    pub(crate) fn try_collect(
        values: impl ExactSizeIterator<Item = Result<T>>,
        allowance: &Allowance,
    ) -> Result<Self> {
        let mut out = Self::with_capacity(values.len(), allowance)?;
        for value in values {
            out.push_admitted(value?);
        }
        Ok(out)
    }
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }
    pub(crate) fn copied(values: &[T], allowance: &Allowance) -> Result<Self>
    where
        T: Copy,
    {
        let mut out = Self::with_capacity(values.len(), allowance)?;
        out.extend_from_slice(values)?;
        Ok(out)
    }
    /// Admit the final window before modifying it. A refusal keeps the old
    /// history intact, and input larger than the window is never copied in full.
    #[cfg(any(test, feature = "write"))]
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
        self.extend_from_slice(input)
    }
    pub(crate) fn extend_from_slice(
        &mut self,
        values: &[T],
    ) -> std::result::Result<(), crate::codec::Error>
    where
        T: Copy,
    {
        if values.len() > self.values.capacity() - self.values.len() {
            Allowance::grow(&mut self.values, &mut self.charge, values.len())?;
        }
        self.values.extend_from_slice(values);
        Ok(())
    }
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn prepend(&mut self, prefix: impl ExactSizeIterator<Item = T>) -> Result<()> {
        self.reserve(prefix.len())?;
        let old_len = self.values.len();
        for value in prefix {
            self.push(value)?;
        }
        let inserted = self.values.len() - old_len;
        self.values.rotate_right(inserted);
        Ok(())
    }
}
pub(crate) struct BufferIter<T> {
    values: std::vec::IntoIter<T>,
    _charge: Charge,
}
impl<'a, T> IntoIterator for &'a Buffer<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<'a, T> IntoIterator for &'a mut Buffer<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
impl<T> IntoIterator for Buffer<T> {
    type Item = T;
    type IntoIter = BufferIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        BufferIter {
            values: self.values.into_iter(),
            _charge: self.charge,
        }
    }
}
impl<T> Iterator for BufferIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl<T> ExactSizeIterator for BufferIter<T> {}
#[cfg(test)]
impl<T> From<Vec<T>> for Buffer<T> {
    fn from(values: Vec<T>) -> Self {
        Self::from_vec(values)
    }
}
impl<T> Buffer<T> {
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn from_vec(values: Vec<T>) -> Self {
        Self {
            values,
            charge: Allowance::default().charge(),
        }
    }
    /// The values leave the budget: their charge is released.
    pub(crate) fn into_vec(mut self) -> Vec<T> {
        std::mem::take(&mut self.values)
    }
}
impl Buffer<u8> {
    pub(crate) fn read_to_end(&mut self, input: &mut impl std::io::Read) -> Result<()> {
        let mut chunk = [0u8; 32 * 1024];
        loop {
            let len = match input.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(len) => len,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(Error::from(error)),
            };
            self.extend_from_slice(&chunk[..len])?;
        }
    }
    #[cfg(feature = "write")]
    pub(crate) fn write_msb_bits(
        &mut self,
        bit_pos: &mut usize,
        value: u64,
        count: usize,
    ) -> std::result::Result<(), crate::codec::Error> {
        let used = *bit_pos % 8;
        let additional = (used + count).div_ceil(8) - usize::from(used != 0);
        if additional > self.values.capacity() - self.values.len() {
            Allowance::grow(&mut self.values, &mut self.charge, additional)?;
        }
        super::fast::write_msb_bits(&mut self.values, bit_pos, value, count);
        Ok(())
    }
    #[cfg(feature = "write")]
    pub(crate) fn write_msb_bits_admitted(
        &mut self,
        bit_pos: &mut usize,
        value: u64,
        count: usize,
    ) {
        let used = *bit_pos % 8;
        let additional = (used + count).div_ceil(8) - usize::from(used != 0);
        debug_assert!(additional <= self.values.capacity() - self.values.len());
        super::fast::write_msb_bits(&mut self.values, bit_pos, value, count);
    }
}
fn allocation_size<T>(capacity: usize) -> Result<u64> {
    capacity
        .checked_mul(std::mem::size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .map(|bytes| bytes as u64)
        .ok_or(Error::InvalidData("codec capacity overflows"))
}
impl std::io::Write for Buffer<u8> {
    fn write(&mut self, values: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(values)
            .map_err(|error| std::io::Error::other(crate::Error::from(error)))?;
        Ok(values.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<T> std::ops::Deref for Buffer<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T> std::ops::DerefMut for Buffer<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}
impl<T: PartialEq> PartialEq<Buffer<T>> for Buffer<T> {
    fn eq(&self, other: &Buffer<T>) -> bool {
        **self == **other
    }
}
impl<T: PartialEq> PartialEq<Vec<T>> for Buffer<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        &**self == other.as_slice()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn interrupted_reads_retry_and_buffer_flush_preserves_charge() {
        use std::io::{self, Cursor, Read, Write};
        struct InterruptedOnce {
            interrupted: bool,
            data: Cursor<&'static [u8]>,
        }
        impl Read for InterruptedOnce {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.data.read(out)
            }
        }
        let ledger = Allowance::limited(16);
        let mut input = InterruptedOnce {
            interrupted: false,
            data: Cursor::new(b"payload".as_slice()),
        };
        let mut bytes = Buffer::new(&ledger);
        bytes.read_to_end(&mut input).unwrap();
        assert!(input.interrupted);
        assert_eq!(&*bytes, b"payload");
        let charged = ledger.used();
        assert!(charged >= 7);
        bytes.flush().unwrap();
        assert_eq!(&*bytes, b"payload");
        assert_eq!(ledger.used(), charged);
        drop(bytes);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn boxed_workspace_is_admitted_before_construction_and_released_on_failure() {
        let small = Allowance::limited(31);
        let mut constructed = false;
        let denied = Boxed::try_new(
            || {
                constructed = true;
                Ok::<_, Error>([0u8; 32])
            },
            &small,
        );
        assert!(matches!(denied, Err(Error::WorkspaceLimitExceeded(_))));
        assert!(!constructed);
        assert_eq!(small.used(), 0);
        let budget = Allowance::limited(32);
        let failed = Boxed::<[u8; 32]>::try_new(|| Err::<[u8; 32], _>(Error::Cancelled), &budget);
        assert!(matches!(failed, Err(Error::Cancelled)));
        assert_eq!(budget.used(), 0);
        let value = Boxed::try_new(|| Ok::<_, Error>([7u8; 32]), &budget).unwrap();
        assert_eq!(budget.used(), 32);
        assert_eq!(*value, [7; 32]);
        drop(value);
        assert_eq!(budget.used(), 0);
    }

    use super::*;

    #[test]
    fn reader_buffer_writer_preserves_typed_workspace_failure() {
        use std::io::Write;
        let ledger = Allowance::limited(0);
        let mut buffer = Buffer::new(&ledger);
        let error = buffer.write_all(b"cannot fit").unwrap_err();
        assert!(matches!(
            Error::from(error),
            Error::WorkspaceLimitExceeded(_)
        ));
        assert!(buffer.is_empty());
        assert_eq!(ledger.used(), 0);
    }

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
    fn success_results_stay_narrow() {
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
            assert!(Buffer::<u8>::with_capacity(4096, &allowance).is_err());
            panic!("unwind the worker");
        });
        assert!(result.is_err());
        assert_eq!(allowance.used(), 0);
        drop(Buffer::<u8>::with_capacity(4096, &allowance).unwrap());
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
            assert!(Buffer::<u8>::with_capacity(1, &clone).is_err());
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
        let kept = Buffer::<u8>::with_capacity(16, &first).unwrap();
        assert!(Buffer::<u8>::with_capacity(1, &first).is_err());
        drop(Buffer::<u8>::with_capacity(16, &second).unwrap());
        assert_eq!(first.used(), 16);
        assert_eq!(second.used(), 0);
        drop(kept);
        assert_eq!(first.used(), 0);
    }

    #[test]
    fn growing_in_place_admits_both_copies_then_settles_at_the_new_capacity() {
        let allowance = Allowance::limited(48);
        let mut bytes = Buffer::filled(16, 7u8, &allowance).unwrap();
        bytes.grow_exact(32).unwrap();
        assert_eq!(bytes.capacity(), 32);
        assert_eq!(allowance.used(), 32);
        assert!(bytes.iter().all(|&byte| byte == 7) && bytes.len() == 16);
        bytes.grow_exact(8).unwrap();
        assert_eq!(allowance.used(), 32);

        // 32 held and 48 more would be 80 at the move: refused, and unchanged.
        assert!(matches!(
            bytes.grow_exact(48),
            Err(Error::WorkspaceLimitExceeded(_))
        ));
        assert_eq!((bytes.capacity(), allowance.used()), (32, 32));
        drop(bytes);
        assert_eq!(allowance.used(), 0);
    }
}
