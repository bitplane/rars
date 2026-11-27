//! Internal admission ledger. Reservations are fixed before dispatch; retiring
//! one returns only unused space, while escaped owners retain their charges.
use super::{Error, Result};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Ledger {
    limit: u64,
    used: Mutex<u64>,
}
#[derive(Debug)]
struct Usage {
    capacity: u64,
    used: u64,
    retired: bool,
}
impl Drop for Usage {
    fn drop(&mut self) {
        debug_assert!(self.retired && self.used == 0);
    }
}
/// A workspace budget. Without a ledger it is unlimited, and charging it
/// only records the bytes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Limited {
    ledger: Option<Arc<Ledger>>,
    scope: Option<Arc<Mutex<Usage>>>,
}
#[derive(Debug)]
pub(crate) struct Charge {
    pub(super) allowance: Limited,
    pub(super) bytes: u64,
}
#[derive(Debug)]
pub(crate) struct Reservation {
    allowance: Limited,
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
            scope: None,
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
        match (&self.scope, &self.ledger) {
            (Some(scope), _) => scope.lock().unwrap().used,
            (None, Some(ledger)) => *ledger.used.lock().unwrap(),
            (None, None) => 0,
        }
    }
    pub(crate) fn available(&self) -> u64 {
        match (&self.scope, &self.ledger) {
            (Some(scope), _) => {
                let usage = scope.lock().unwrap();
                usage.capacity - usage.used
            }
            (None, Some(ledger)) => ledger.limit - self.used(),
            (None, None) => u64::MAX,
        }
    }
    pub(crate) fn check_capacity(&self, required: u64) -> Result<()> {
        if let Some(scope) = &self.scope {
            let usage = scope.lock().unwrap();
            if required > usage.capacity - usage.used {
                return Err(refusal(usage.capacity, required, usage.used));
            }
        } else if let Some(ledger) = &self.ledger {
            let used = *ledger.used.lock().unwrap();
            if required > ledger.limit - used {
                return Err(refusal(ledger.limit, required, used));
            }
        }
        Ok(())
    }
    fn reserve_global(&self, bytes: u64, required: u64) -> Result<()> {
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
    fn release_global(&self, bytes: u64) {
        if let Some(ledger) = &self.ledger {
            *ledger.used.lock().unwrap() -= bytes;
        }
    }
    pub(crate) fn reserve(&self, capacity: u64) -> Result<Reservation> {
        if self.scope.is_some() {
            return Err(Error::InvalidData(
                "workers cannot reserve global workspace",
            ));
        }
        if self.ledger.is_none() {
            return Ok(Reservation {
                allowance: self.clone(),
            });
        }
        self.reserve_global(capacity, capacity)?;
        Ok(Reservation {
            allowance: Self {
                ledger: self.ledger.clone(),
                scope: Some(Arc::new(Mutex::new(Usage {
                    capacity,
                    used: 0,
                    retired: false,
                }))),
            },
        })
    }
}
impl Charge {
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(super) fn resize(&mut self, bytes: u64) -> Result<()> {
        if self.allowance.ledger.is_none() {
            self.bytes = bytes;
            return Ok(());
        }
        if let Some(scope) = &self.allowance.scope {
            let mut usage = scope.lock().unwrap();
            if bytes > self.bytes {
                let extra = bytes - self.bytes;
                if extra > usage.capacity - usage.used {
                    return Err(refusal(usage.capacity, bytes, usage.used));
                }
                usage.used += extra;
            } else {
                let released = self.bytes - bytes;
                usage.used -= released;
                if usage.retired {
                    usage.capacity -= released;
                    self.allowance.release_global(released);
                }
            }
        } else if bytes > self.bytes {
            self.allowance.reserve_global(bytes - self.bytes, bytes)?;
        } else {
            self.allowance.release_global(self.bytes - bytes);
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
impl Reservation {
    pub(crate) fn allowance(&self) -> Limited {
        self.allowance.clone()
    }
    pub(crate) fn retire(self) {
        drop(self);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let Some(scope) = &self.allowance.scope else {
            return;
        };
        let mut usage = scope.lock().unwrap();
        let unused = usage.capacity - usage.used;
        usage.capacity = usage.used;
        usage.retired = true;
        self.allowance.release_global(unused);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::Buffer;

    #[test]
    fn scoped_capacity_never_borrows_global_spare_space_and_stays_retired() {
        let ledger = Limited::limited(128);
        let reservation = ledger.reserve(16).unwrap();
        let local = reservation.allowance();
        assert_eq!(local.available(), 16);
        local.check_capacity(16).unwrap();
        assert!(
            matches!(local.check_capacity(17), Err(Error::WorkspaceLimitExceeded(e)) if (e.limit, e.required, e.used) == (16, 17, 0))
        );
        let bytes = Buffer::filled(8, 1u8, &local).unwrap();
        assert_eq!(local.available(), 8);
        assert!(ledger.available() > local.available());
        local.check_capacity(8).unwrap();
        assert!(
            matches!(local.check_capacity(9), Err(Error::WorkspaceLimitExceeded(e)) if (e.limit, e.required, e.used) == (16, 9, 8))
        );
        reservation.retire();
        assert_eq!(local.available(), 0);
        local.check_capacity(0).unwrap();
        assert!(
            matches!(local.check_capacity(1), Err(Error::WorkspaceLimitExceeded(e)) if (e.limit, e.required, e.used) == (8, 1, 8))
        );
        drop(bytes);
        assert_eq!(local.available(), 0);
        assert_eq!(ledger.used(), 0);
        drop(local);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn retirement_releases_only_unused_reservations_and_keeps_escaped_outputs() {
        let ledger = Limited::limited(128);
        let first = ledger.reserve(80).unwrap();
        let second = ledger.reserve(32).unwrap();
        assert_eq!(ledger.used(), 112);
        assert!(ledger.reserve(17).is_err());
        let a = first.allowance();
        let b = second.allowance();
        assert!(a.reserve(1).is_err());
        let left = Buffer::filled(48, 7u8, &a).unwrap();
        let mut right = Buffer::filled(16, 9u8, &b).unwrap();
        assert!(Buffer::filled(33, 0u8, &a).is_err());
        assert_eq!(ledger.used(), 112);
        first.retire();
        assert_eq!(ledger.used(), 80);
        second.retire();
        assert_eq!(ledger.used(), 64);
        assert!(right.resize(17, 0).is_err());
        assert_eq!(&*right, &[9u8; 16]);
        drop(left);
        assert_eq!(ledger.used(), 16);
        drop(right);
        assert_eq!(ledger.used(), 0);
        assert!(Buffer::filled(1, 0u8, &a).is_err());
        drop((a, b));
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn unwind_releases_the_admitted_scope() {
        let ledger = Limited::limited(64);
        let result = std::panic::catch_unwind(|| {
            let reservation = ledger.reserve(48).unwrap();
            assert_eq!(ledger.used(), 48);
            let _bytes = Buffer::filled(32, 0u8, &reservation.allowance()).unwrap();
            drop(reservation);
            panic!("injected unwind");
        });
        assert!(result.is_err());
        assert_eq!(ledger.used(), 0);
        ledger.reserve(64).unwrap().retire();
        assert_eq!(ledger.used(), 0);
    }
}
