//! Internal workspace ledger: what everything charged to one budget holds.
use super::{Error, Result};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Ledger {
    limit: u64,
    used: Mutex<u64>,
}
/// A workspace budget. Without a ledger it is unlimited, and charging it
/// only records the bytes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Limited {
    ledger: Option<Arc<Ledger>>,
    #[cfg(test)]
    refusal: Option<Arc<Refusal>>,
}
/// Fault injection for tests: the `fail_at`th time anything charged to this
/// budget grows, the growth fails with [`Error::Cancelled`].
#[cfg(test)]
#[derive(Debug)]
struct Refusal {
    attempts: std::sync::atomic::AtomicUsize,
    fail_at: usize,
}
#[derive(Debug)]
pub(crate) struct Charge {
    pub(super) allowance: Limited,
    pub(super) bytes: u64,
}
fn refusal(limit: u64, required: u64, used: u64) -> Error {
    Error::WorkspaceLimitExceeded(Box::new(crate::codec::WorkspaceLimitError {
        limit,
        required,
        used,
    }))
}
impl Limited {
    /// A budget that refuses growth past `limit` bytes. Callers spell it
    /// `Allowance::limited`.
    #[allow(clippy::self_named_constructors)]
    pub(crate) fn limited(limit: u64) -> Self {
        Self {
            ledger: Some(Arc::new(Ledger {
                limit,
                used: Mutex::new(0),
            })),
            #[cfg(test)]
            refusal: None,
        }
    }
    /// A generous limited budget whose `fail_at`th growth is refused, so a
    /// test can walk every refusal point by counting [`Self::attempts`] on a
    /// run that refuses nothing.
    #[cfg(test)]
    pub(crate) fn refusing(fail_at: usize) -> Self {
        Self {
            refusal: Some(Arc::new(Refusal {
                attempts: std::sync::atomic::AtomicUsize::new(0),
                fail_at,
            })),
            ..Self::limited(64 * 1024 * 1024)
        }
    }
    /// How many growths a [`Self::refusing`] budget has been asked for.
    #[cfg(test)]
    pub(crate) fn attempts(&self) -> usize {
        self.refusal.as_ref().map_or(0, |refusal| {
            refusal.attempts.load(std::sync::atomic::Ordering::Relaxed)
        })
    }
    #[cfg(test)]
    fn attempt(&self) -> Result<()> {
        match &self.refusal {
            Some(refusal)
                if refusal
                    .attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    == refusal.fail_at =>
            {
                Err(Error::Cancelled)
            }
            _ => Ok(()),
        }
    }
    pub(crate) fn is_limited(&self) -> bool {
        self.ledger.is_some()
    }
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn limit(&self) -> u64 {
        self.ledger.as_ref().map_or(u64::MAX, |ledger| ledger.limit)
    }
    pub(crate) fn used(&self) -> u64 {
        self.ledger
            .as_ref()
            .map_or(0, |ledger| *ledger.used.lock().unwrap())
    }
    pub(crate) fn available(&self) -> u64 {
        self.ledger
            .as_ref()
            .map_or(u64::MAX, |ledger| ledger.limit - self.used())
    }
    #[cfg(any(test, all(feature = "recovery", feature = "write")))]
    pub(crate) fn check_capacity(&self, required: u64) -> Result<()> {
        if let Some(ledger) = &self.ledger {
            let used = *ledger.used.lock().unwrap();
            if required > ledger.limit - used {
                return Err(refusal(ledger.limit, required, used));
            }
        }
        Ok(())
    }
    fn take(&self, bytes: u64, required: u64) -> Result<()> {
        let Some(ledger) = &self.ledger else {
            return Ok(());
        };
        let mut used = ledger.used.lock().unwrap();
        if bytes > ledger.limit - *used {
            return Err(refusal(ledger.limit, required, *used));
        }
        *used += bytes;
        Ok(())
    }
    fn release(&self, bytes: u64) {
        if let Some(ledger) = &self.ledger {
            *ledger.used.lock().unwrap() -= bytes;
        }
    }
}
impl Charge {
    #[cfg(feature = "write")]
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(super) fn resize(&mut self, bytes: u64) -> Result<()> {
        #[cfg(test)]
        if bytes > self.bytes {
            self.allowance.attempt()?;
        }
        if self.allowance.ledger.is_none() {
            self.bytes = bytes;
            return Ok(());
        }
        if bytes > self.bytes {
            self.allowance.take(bytes - self.bytes, bytes)?;
        } else {
            self.allowance.release(self.bytes - bytes);
        }
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        self.resize(0).expect("releasing capacity cannot fail");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::Buffer;

    #[test]
    fn clones_share_one_ledger_and_drops_release_it() {
        let ledger = Limited::limited(128);
        let worker = ledger.clone();
        let left = Buffer::filled(80, 7u8, &ledger).unwrap();
        let mut right = Buffer::filled(48, 9u8, &worker).unwrap();
        assert_eq!(ledger.available(), 0);
        assert!(
            matches!(worker.check_capacity(1), Err(Error::WorkspaceLimitExceeded(e)) if (e.limit, e.required, e.used) == (128, 1, 128))
        );
        assert!(right.resize(49, 0).is_err());
        assert_eq!(&*right, &[9u8; 48]);
        drop(left);
        let again = Buffer::filled(80, 0u8, &worker).unwrap();
        assert_eq!(ledger.used(), 128);
        drop((right, again));
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn unwind_releases_what_was_charged() {
        let ledger = Limited::limited(64);
        let result = std::panic::catch_unwind(|| {
            let _bytes = Buffer::filled(32, 0u8, &ledger).unwrap();
            assert_eq!(ledger.used(), 32);
            panic!("injected unwind");
        });
        assert!(result.is_err());
        assert_eq!(ledger.used(), 0);
    }
}
