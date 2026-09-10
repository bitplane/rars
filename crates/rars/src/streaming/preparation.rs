//! Ownership of preparation capacity, including temporary replacement peaks.
use super::{CapacityCharge, WriterResources};
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct Bytes {
    bytes: Vec<u8>,
    len: usize,
    charge: Option<CapacityCharge>,
}
impl Bytes {
    pub(crate) fn new(resources: &WriterResources) -> Self {
        Self {
            bytes: Vec::new(),
            len: 0,
            charge: resources.preparation_charge(),
        }
    }
    pub(crate) fn output(resources: &WriterResources) -> Self {
        Self {
            bytes: Vec::new(),
            len: 0,
            charge: resources.execution_charge(),
        }
    }
    pub(crate) fn take_vec(&mut self) -> Vec<u8> {
        self.bytes.truncate(self.len);
        self.len = 0;
        std::mem::take(&mut self.bytes)
    }
    pub(crate) fn zeroed(len: usize, resources: &WriterResources) -> Result<Self> {
        let mut out = Self::new(resources);
        out.grow(len)?;
        out.len = len;
        Ok(out)
    }
    fn grow(&mut self, capacity: usize) -> Result<()> {
        if capacity <= self.bytes.len() {
            return Ok(());
        }
        if capacity > isize::MAX as usize {
            return Err(Error::InvalidArgument("preparation capacity overflows"));
        }
        let peak = self
            .bytes
            .len()
            .checked_add(capacity)
            .ok_or(Error::InvalidArgument("preparation capacity overflows"))?;
        if let Some(charge) = &mut self.charge {
            charge.grow_to(peak as u64)?;
        }
        let mut replacement = vec![0; capacity];
        replacement[..self.len].copy_from_slice(&self.bytes[..self.len]);
        self.bytes = replacement;
        if let Some(charge) = &mut self.charge {
            charge.shrink_to(capacity as u64);
        }
        Ok(())
    }
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        if self.charge.is_none() {
            self.bytes.truncate(self.len);
            self.bytes.extend_from_slice(bytes);
            self.len = self.bytes.len();
            return Ok(());
        }
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(Error::InvalidArgument("preparation length overflows"))?;
        if end > self.bytes.len() {
            let capacity = end
                .checked_next_power_of_two()
                .ok_or(Error::InvalidArgument("preparation capacity overflows"))?;
            self.grow(capacity)?;
        }
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    pub(crate) fn vint(&mut self, mut value: u64) -> Result<()> {
        let mut bytes = [0; 10];
        let mut len = 0;
        loop {
            bytes[len] = (value as u8 & 0x7f) | if value >= 128 { 128 } else { 0 };
            len += 1;
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        self.extend_from_slice(&bytes[..len])
    }
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self
    }
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
}
impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl std::ops::DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

/// Fixed-capacity descriptor array, admitted before allocating. Consuming its
/// elements keeps the backing allocation charged until the iterator is dropped.
#[derive(Debug)]
pub(crate) struct Records<T> {
    values: Vec<T>,
    limit: usize,
    charge: Option<CapacityCharge>,
}
#[cfg(test)]
impl<T: Clone> Clone for Records<T> {
    fn clone(&self) -> Self {
        assert!(
            self.charge.is_none(),
            "charged owners require fallible copying"
        );
        self.values.clone().into()
    }
}
#[cfg(test)]
impl<T> From<Vec<T>> for Records<T> {
    fn from(values: Vec<T>) -> Self {
        Self {
            limit: values.capacity(),
            values,
            charge: None,
        }
    }
}
impl<T> Records<T> {
    pub(crate) fn new(limit: usize, resources: &WriterResources) -> Result<Self> {
        Self::with_charge(limit, resources.preparation_charge())
    }
    pub(crate) fn with_charge(limit: usize, mut charge: Option<CapacityCharge>) -> Result<Self> {
        let bytes = limit
            .checked_mul(std::mem::size_of::<T>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or(Error::InvalidArgument(
                "preparation records capacity overflows",
            ))?;
        if let Some(charge) = &mut charge {
            charge.grow_to(bytes as u64)?;
        }
        // with_capacity requests exactly this layout. No subsequent growth is allowed.
        Ok(Self {
            values: Vec::with_capacity(limit),
            limit,
            charge,
        })
    }
    pub(crate) fn collect<I>(values: I, resources: &WriterResources) -> Result<Self>
    where
        I: ExactSizeIterator<Item = Result<T>>,
    {
        let mut out = Self::new(values.len(), resources)?;
        for value in values {
            out.push(value?)?;
        }
        Ok(out)
    }

    /// Grow only on explicit request, reserving the old and replacement arrays
    /// together before moving elements. Fixed-admission callers use `push`.
    pub(crate) fn push_growing(&mut self, value: T) -> Result<()> {
        if self.values.len() == self.limit {
            let limit = self
                .limit
                .max(1)
                .checked_mul(2)
                .ok_or(Error::InvalidArgument(
                    "preparation records capacity overflows",
                ))?;
            let bytes = limit
                .checked_mul(std::mem::size_of::<T>())
                .filter(|bytes| *bytes <= isize::MAX as usize)
                .ok_or(Error::InvalidArgument(
                    "preparation records capacity overflows",
                ))?;
            if let Some(charge) = &mut self.charge {
                charge.grow_to((bytes as u64).checked_add(charge.bytes()).ok_or(
                    Error::InvalidArgument("preparation records capacity overflows"),
                )?)?;
            }
            let mut replacement = Vec::with_capacity(limit);
            replacement.append(&mut self.values);
            self.values = replacement;
            self.limit = limit;
            if let Some(charge) = &mut self.charge {
                charge.shrink_to(bytes as u64);
            }
        }
        self.push(value)
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }

    pub(crate) fn push(&mut self, value: T) -> Result<()> {
        if self.values.len() == self.limit {
            return Err(Error::WriterFailure(
                "preparation record count exceeded admission",
            ));
        }
        self.values.push(value);
        Ok(())
    }
}
impl<T> std::ops::Deref for Records<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T> std::ops::DerefMut for Records<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}
pub(crate) struct RecordIter<T> {
    iter: std::vec::IntoIter<T>,
    _charge: Option<CapacityCharge>,
}
impl<T> Iterator for RecordIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}
impl<T> ExactSizeIterator for RecordIter<T> {}

impl<T> IntoIterator for Records<T> {
    type Item = T;
    type IntoIter = RecordIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        RecordIter {
            iter: self.values.into_iter(),
            _charge: self.charge,
        }
    }
}
impl<'a, T> IntoIterator for &'a Records<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}
impl<'a, T> IntoIterator for &'a mut Records<T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

pub(crate) struct Owned<T> {
    value: Box<T>,
    _charge: Option<CapacityCharge>,
}
impl<T> Owned<T> {
    pub(crate) fn new(value: T, resources: &WriterResources) -> Result<Self> {
        let mut charge = resources.preparation_charge();
        if let Some(charge) = &mut charge {
            charge.grow_to(std::mem::size_of::<T>() as u64)?;
        }
        Ok(Self {
            value: Box::new(value),
            _charge: charge,
        })
    }
    pub(crate) fn into_inner(self) -> T {
        *self.value
    }
}
impl<T> std::ops::Deref for Owned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> std::ops::DerefMut for Owned<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T> AsRef<T> for Owned<T> {
    fn as_ref(&self) -> &T {
        self
    }
}
impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl PartialEq<Vec<u8>> for Bytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &**self == other.as_slice()
    }
}
impl PartialEq<Bytes> for Vec<u8> {
    fn eq(&self, other: &Bytes) -> bool {
        self.as_slice() == &**other
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn preparation_growth_satisfies_both_ledgers_or_leaves_both_unchanged() {
        use crate::codec::workspace::Allowance;
        let ledger = Allowance::limited(1024);
        let resources = WriterResources::default()
            .with_max_preparation_bytes(64)
            .with_execution_allowance(ledger.clone());
        let mut bytes = Bytes::zeroed(32, &resources).unwrap();
        assert!(bytes.extend_from_slice(&[1; 40]).is_err());
        assert_eq!(&*bytes, &[0; 32]);
        assert_eq!(ledger.used(), 32);
        drop(bytes);
        assert_eq!(ledger.used(), 0);
        drop(Bytes::zeroed(64, &resources).unwrap());
        let small = Allowance::limited(16);
        let constrained = resources.clone().with_execution_allowance(small.clone());
        assert!(Bytes::zeroed(32, &constrained).is_err());
        assert_eq!(small.used(), 0);
        drop(Bytes::zeroed(64, &resources).unwrap());
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn descriptor_growth_counts_replacement_peak_and_preserves_refused_input() {
        let resources = WriterResources::default().with_max_preparation_bytes(23);
        let mut records = Records::new(1, &resources).unwrap();
        records.push(7u64).unwrap();
        assert!(matches!(
            records.push_growing(9),
            Err(Error::WriterPreparationLimitExceeded { required: 24, .. })
        ));
        assert_eq!(&*records, &[7]);
        assert_eq!(used(&resources), 8);
        drop(records);
        assert_eq!(used(&resources), 0);
        let resources = resources.with_max_preparation_bytes(24);
        let mut records = Records::new(1, &resources).unwrap();
        records.push(7u64).unwrap();
        records.push_growing(9).unwrap();
        assert_eq!(&*records, &[7, 9]);
        assert_eq!(used(&resources), 16);
        drop(records);
        assert_eq!(used(&resources), 0);
    }

    use super::*;
    fn used(resources: &WriterResources) -> u64 {
        *resources
            .preparation_budget
            .as_ref()
            .unwrap()
            .used
            .lock()
            .unwrap()
    }

    #[test]
    fn byte_growth_admits_replacement_peak_and_preserves_refused_contents() {
        let resources = WriterResources::default().with_max_preparation_bytes(11);
        let mut bytes = Bytes::new(&resources);
        bytes.extend_from_slice(b"abcd").unwrap();
        assert_eq!(used(&resources), 4);
        assert_eq!(
            bytes.extend_from_slice(b"e").unwrap_err(),
            Error::WriterPreparationLimitExceeded {
                limit: 11,
                required: 12,
                used: 4
            }
        );
        assert_eq!(&*bytes, b"abcd");
        assert_eq!(used(&resources), 4);
        drop(bytes);
        assert_eq!(used(&resources), 0);
        let resources = resources.with_max_preparation_bytes(12);
        let mut bytes = Bytes::new(&resources);
        bytes.extend_from_slice(b"abcd").unwrap();
        bytes.extend_from_slice(b"e").unwrap();
        assert_eq!(bytes.capacity(), 8);
        assert_eq!(used(&resources), 8);
        let mut other = Bytes::new(&resources.clone());
        assert!(other.extend_from_slice(b"12345").is_err());
        drop(bytes);
        other.extend_from_slice(b"12345").unwrap();
        drop(other);
        assert_eq!(used(&resources), 0);
    }

    #[test]
    fn records_and_boxed_state_keep_their_allocation_charged_until_freed() {
        struct Probe(WriterResources);
        impl Drop for Probe {
            fn drop(&mut self) {
                assert!(used(&self.0) > 0);
            }
        }
        let resources = WriterResources::default().with_max_preparation_bytes(4096);
        let mut records = Records::new(2, &resources).unwrap();
        records.push(Probe(resources.clone())).unwrap();
        records.push(Probe(resources.clone())).unwrap();
        let bytes = 2 * std::mem::size_of::<Probe>() as u64;
        assert_eq!(used(&resources), bytes);
        let mut iter = records.into_iter();
        drop(iter.next());
        assert_eq!(used(&resources), bytes);
        drop(iter);
        assert_eq!(used(&resources), 0);
        let failure = std::panic::catch_unwind(|| {
            let _owned = Owned::new(Probe(resources.clone()), &resources).unwrap();
            let _bytes = Bytes::zeroed(100, &resources).unwrap();
            panic!("injected failure");
        });
        assert!(failure.is_err());
        assert_eq!(used(&resources), 0);
    }

    #[test]
    fn concurrent_preparation_shares_one_admission_boundary() {
        let resources = WriterResources::default().with_max_preparation_bytes(128);
        std::thread::scope(|scope| {
            let hold = Bytes::zeroed(128, &resources).unwrap();
            scope
                .spawn(|| assert!(Bytes::zeroed(1, &resources.clone()).is_err()))
                .join()
                .unwrap();
            drop(hold);
            scope
                .spawn(|| {
                    Bytes::zeroed(128, &resources.clone()).unwrap();
                })
                .join()
                .unwrap();
        });
        assert_eq!(used(&resources), 0);
    }
}
