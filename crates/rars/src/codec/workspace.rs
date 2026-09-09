//! Fallible ownership of codec allocation capacity. A local allowance never
//! reaches into a sibling worker's spare bytes. Future coordinator integration
//! will supply the allowance; unlimited handles preserve existing codec behaviour.
use super::{Error, Result};
#[cfg(test)]
use std::sync::{Arc, Mutex};

/// A zero-sized policy: its buffers have exactly Vec's layout and no ledger
/// branch in their hot operations. Limited buffers are a separate instantiation.
#[derive(Clone, Debug, Default)]
pub(crate) struct Allowance {
    _unlimited: (),
}
impl Allowance {
    #[cfg(test)]
    pub(crate) fn limited(limit: u64) -> Limited {
        Limited(Arc::new(State {
            limit,
            used: Mutex::new(0),
        }))
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

// This constructor remains internal test coverage until all codec allocation
// paths and coordinator reservations can be connected without scope holes.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct Limited(Arc<State>);
#[cfg(test)]
#[derive(Debug)]
struct State {
    limit: u64,
    used: Mutex<u64>,
}
#[cfg(test)]
impl Limited {
    pub(crate) fn used(&self) -> u64 {
        *self.0.used.lock().unwrap()
    }
}
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Charge {
    allowance: Limited,
    bytes: u64,
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
        let state = &charge.allowance.0;
        let mut used = state.used.lock().expect("codec allowance lock poisoned");
        if bytes > charge.bytes {
            let extra = bytes - charge.bytes;
            if extra > state.limit.saturating_sub(*used) {
                return Err(Error::WorkspaceLimitExceeded(Box::new(
                    super::WorkspaceLimitError {
                        limit: state.limit,
                        required: bytes,
                        used: *used,
                    },
                )));
            }
            *used += extra;
        } else {
            *used -= charge.bytes - bytes;
        }
        charge.bytes = bytes;
        Ok(())
    }
}
#[cfg(test)]
impl Drop for Charge {
    fn drop(&mut self) {
        Limited::resize(self, 0).expect("releasing codec capacity cannot fail");
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
