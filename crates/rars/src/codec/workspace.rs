//! Fallible ownership of codec allocation capacity. A local allowance never
//! reaches into a sibling worker's spare bytes. Internal admission tests connect
//! these owners to coordinator reservations; unlimited handles preserve behaviour.
use super::{Error, Result};
mod ledger;
pub(crate) use ledger::{Charge, Limited, Reservation, RESERVATION_BYTES};

/// A zero-sized policy: its buffers have exactly Vec's layout and no ledger
/// branch in their hot operations. Limited buffers are a separate instantiation.
#[derive(Clone, Debug, Default)]
pub(crate) struct Allowance {
    _unlimited: (),
}
impl Allowance {
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

/// Admit a boxed value before constructing it. Its storage is freed before
/// the charge, including when construction fails or a decoder is replaced.
#[derive(Debug)]
pub(crate) struct Boxed<T, B: Budget = Allowance> {
    value: Box<T>,
    _charge: B::Charge,
}
impl<T, B: Budget> Boxed<T, B> {
    pub(crate) fn try_new<E: From<Error>>(
        make: impl FnOnce() -> std::result::Result<T, E>,
        allowance: &B,
    ) -> std::result::Result<Self, E> {
        let mut charge = allowance.charge();
        B::resize(&mut charge, allocation_size::<T>(1)?)?;
        let value = make()?;
        Ok(Self {
            value: Box::new(value),
            _charge: charge,
        })
    }
}
impl<T, B: Budget> std::ops::Deref for Boxed<T, B> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T, B: Budget> std::ops::DerefMut for Boxed<T, B> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
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

/// Test policy that uses the production ledger but can refuse one chosen
/// growth operation. Keeping the policy beside [`Budget`] lets coverage count
/// its monomorphizations as tests of production generic code rather than as
/// test-module functions.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct RefusingBudget {
    inner: Limited,
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail_at: usize,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct RefusingCharge {
    inner: Charge,
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail_at: usize,
}

#[cfg(test)]
impl RefusingBudget {
    pub(crate) fn new(fail_at: usize) -> Self {
        Self {
            inner: Allowance::limited(64 * 1024 * 1024),
            attempts: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            fail_at,
        }
    }

    pub(crate) fn attempts(&self) -> usize {
        self.attempts.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn used(&self) -> u64 {
        self.inner.used()
    }
}

#[cfg(test)]
fn refuse_once(attempts: &std::sync::atomic::AtomicUsize, fail_at: usize) -> Result<()> {
    if attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == fail_at {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
impl Budget for RefusingBudget {
    type Charge = RefusingCharge;
    type Failure = Error;
    const LIMITED: bool = true;

    fn grow<T>(values: &mut Vec<T>, charge: &mut Self::Charge, additional: usize) -> Result<()> {
        refuse_once(&charge.attempts, charge.fail_at)?;
        <Limited as Budget>::grow(values, &mut charge.inner, additional)
    }

    fn charge(&self) -> Self::Charge {
        RefusingCharge {
            inner: <Limited as Budget>::charge(&self.inner),
            attempts: self.attempts.clone(),
            fail_at: self.fail_at,
        }
    }

    fn allowance(charge: &Self::Charge) -> Self {
        Self {
            inner: <Limited as Budget>::allowance(&charge.inner),
            attempts: charge.attempts.clone(),
            fail_at: charge.fail_at,
        }
    }

    fn resize(charge: &mut Self::Charge, bytes: u64) -> Result<()> {
        if bytes > charge.inner.bytes() {
            refuse_once(&charge.attempts, charge.fail_at)?;
        }
        <Limited as Budget>::resize(&mut charge.inner, bytes)
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
    /// Admit one exact allocation before copying slices that form a buffer.
    /// The total is checked first, so none of the copies can grow past its
    /// charged capacity.
    pub(crate) fn from_slices(slices: &[&[T]], allowance: &B) -> Result<Self>
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
        if B::LIMITED {
            self.reserve(range.len())?;
        }
        self.values.extend_from_within(range);
        Ok(())
    }
    pub(crate) fn allowance(&self) -> B {
        B::allowance(&self.charge)
    }
    fn reserve(&mut self, additional: usize) -> Result<()> {
        B::grow(&mut self.values, &mut self.charge, additional).map_err(Into::into)
    }
    pub(crate) fn reserve_total_capacity(&mut self, total: usize) -> Result<()> {
        if total > self.values.capacity() {
            self.reserve(total.saturating_sub(self.values.len()))?;
        }
        debug_assert!(self.values.capacity() >= total);
        Ok(())
    }
    #[inline]
    pub(crate) fn push(&mut self, value: T) -> std::result::Result<(), B::Failure> {
        if B::LIMITED && self.values.len() == self.values.capacity() {
            B::grow(&mut self.values, &mut self.charge, 1)?;
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
    #[cfg(test)]
    pub(crate) fn resize_with(&mut self, len: usize, make: impl FnMut() -> T) -> Result<()> {
        if B::LIMITED && len > self.values.capacity() {
            self.reserve(len - self.values.len())?;
        }
        self.values.resize_with(len, make);
        Ok(())
    }
    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }
    pub(crate) fn insert(&mut self, index: usize, value: T) -> Result<()> {
        if B::LIMITED {
            self.reserve(1)?;
        }
        self.values.insert(index, value);
        Ok(())
    }
    pub(crate) fn remove(&mut self, index: usize) -> T {
        self.values.remove(index)
    }
    pub(crate) fn try_collect(
        values: impl ExactSizeIterator<Item = Result<T>>,
        allowance: &B,
    ) -> Result<Self> {
        let mut out = Self::with_capacity(values.len(), allowance)?;
        for value in values {
            out.push_admitted(value?);
        }
        Ok(out)
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
/// A charged ring keeps its allocation ownership when converted to or from a
/// contiguous history. Neither conversion allocates new storage.
#[derive(Debug)]
pub(crate) struct Deque<T, B: Budget = Allowance> {
    values: std::collections::VecDeque<T>,
    charge: B::Charge,
}
impl<T, B: Budget> Deque<T, B> {
    pub(crate) fn from_buffer(buffer: Buffer<T, B>) -> Self {
        Self {
            values: buffer.values.into(),
            charge: buffer.charge,
        }
    }
    pub(crate) fn into_buffer(self) -> Buffer<T, B> {
        Buffer {
            values: self.values.into(),
            charge: self.charge,
        }
    }
    pub(crate) fn with_capacity(capacity: usize, allowance: &B) -> Result<Self> {
        Ok(Self::from_buffer(Buffer::with_capacity(
            capacity, allowance,
        )?))
    }
    pub(crate) fn allowance(&self) -> B {
        B::allowance(&self.charge)
    }
    pub(crate) fn capacity(&self) -> usize {
        self.values.capacity()
    }
    pub(crate) fn discard_prefix(&mut self, count: usize) {
        self.values.drain(..count);
    }
    pub(crate) fn extend_admitted(&mut self, values: impl ExactSizeIterator<Item = T>) {
        assert!(values.len() <= self.values.capacity() - self.values.len());
        self.values.extend(values);
    }
}
impl<T, B: Budget> std::ops::Deref for Deque<T, B> {
    type Target = std::collections::VecDeque<T>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
pub(crate) struct BufferIter<T, B: Budget> {
    values: std::vec::IntoIter<T>,
    _charge: B::Charge,
}
impl<'a, T, B: Budget> IntoIterator for &'a Buffer<T, B> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<'a, T, B: Budget> IntoIterator for &'a mut Buffer<T, B> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
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
#[cfg(test)]
impl<T> From<Vec<T>> for Buffer<T> {
    fn from(values: Vec<T>) -> Self {
        Self::from_vec(values)
    }
}
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
    pub(crate) fn read_to_end(&mut self, input: &mut impl std::io::Read) -> Result<()> {
        let mut chunk = [0u8; 32 * 1024];
        loop {
            let len = match input.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(len) => len,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(Error::from(error)),
            };
            self.extend_from_slice(&chunk[..len]).map_err(Into::into)?;
        }
    }
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
impl<B: Budget> std::io::Write for Buffer<u8, B> {
    fn write(&mut self, values: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(values)
            .map_err(|error| std::io::Error::other(crate::Error::from(error.into())))?;
        Ok(values.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
        let failed =
            Boxed::<[u8; 32], _>::try_new(|| Err::<[u8; 32], _>(Error::Cancelled), &budget);
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
    fn reader_ring_preserves_capacity_charge_through_wrapped_conversion() {
        let ledger = Allowance::limited(8);
        let buffer = Buffer::copied(b"ABCDEFGH", &ledger).unwrap();
        let storage = buffer.as_ptr();
        let mut ring = Deque::from_buffer(buffer);
        ring.discard_prefix(5);
        ring.extend_admitted(b"12345".iter().copied());
        assert!(!ring.as_slices().1.is_empty());
        assert_eq!(ledger.used(), 8);
        let buffer = ring.into_buffer();
        assert_eq!(&*buffer, b"FGH12345");
        assert_eq!(buffer.as_ptr(), storage);
        assert_eq!(buffer.capacity(), 8);
        assert_eq!(ledger.used(), 8);
        drop(buffer);
        assert_eq!(ledger.used(), 0);
        assert_eq!(
            std::mem::size_of::<Deque<u8>>(),
            std::mem::size_of::<std::collections::VecDeque<u8>>()
        );
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
