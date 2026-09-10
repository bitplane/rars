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
    ledger: Arc<Ledger>,
    capacity: u64,
    used: u64,
    started: bool,
    retired: bool,
}
// Count the per-reservation control payload until its last handle drops.
// Allocator/reference-count headers follow the existing overhead exclusion.
pub(crate) const RESERVATION_BYTES: u64 = std::mem::size_of::<Mutex<Usage>>() as u64;
impl Drop for Usage {
    fn drop(&mut self) {
        debug_assert!(self.retired && self.used == 0);
        *self.ledger.used.lock().unwrap() -= RESERVATION_BYTES;
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Limited {
    ledger: Arc<Ledger>,
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
    pub(super) fn new(limit: u64) -> Self {
        Self {
            ledger: Arc::new(Ledger {
                limit,
                used: Mutex::new(0),
            }),
            scope: None,
        }
    }
    pub(crate) fn limit(&self) -> u64 {
        self.ledger.limit
    }
    pub(crate) fn used(&self) -> u64 {
        match &self.scope {
            Some(scope) => scope.lock().unwrap().used,
            None => *self.ledger.used.lock().unwrap(),
        }
    }
    pub(crate) fn available(&self) -> u64 {
        match &self.scope {
            Some(scope) => {
                let usage = scope.lock().unwrap();
                usage.capacity - usage.used
            }
            None => self.ledger.limit - self.used(),
        }
    }
    pub(crate) fn check_capacity(&self, required: u64) -> Result<()> {
        if let Some(scope) = &self.scope {
            let usage = scope.lock().unwrap();
            if required > usage.capacity - usage.used {
                return Err(refusal(usage.capacity, required, usage.used));
            }
        } else {
            let used = *self.ledger.used.lock().unwrap();
            if required > self.ledger.limit - used {
                return Err(refusal(self.ledger.limit, required, used));
            }
        }
        Ok(())
    }
    fn reserve_global(&self, bytes: u64, required: u64) -> Result<()> {
        let mut used = self.ledger.used.lock().unwrap();
        if bytes > self.ledger.limit - *used {
            return Err(refusal(self.ledger.limit, required, *used));
        }
        *used += bytes;
        Ok(())
    }
    fn release_global(&self, bytes: u64) {
        *self.ledger.used.lock().unwrap() -= bytes;
    }
    pub(crate) fn reserve(&self, capacity: u64) -> Result<Reservation> {
        if self.scope.is_some() {
            return Err(Error::InvalidData(
                "workers cannot reserve global workspace",
            ));
        }
        let committed = capacity
            .checked_add(RESERVATION_BYTES)
            .ok_or(Error::InvalidData("workspace reservation overflows"))?;
        self.reserve_global(committed, committed)?;
        Ok(Reservation {
            allowance: Self {
                ledger: self.ledger.clone(),
                scope: Some(Arc::new(Mutex::new(Usage {
                    ledger: self.ledger.clone(),
                    capacity,
                    used: 0,
                    started: false,
                    retired: false,
                }))),
            },
        })
    }
}
impl Charge {
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(super) fn resize(&mut self, bytes: u64) -> Result<()> {
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
    /// Extensions are a coordinator action before dispatch, never a worker's
    /// attempt to take spare global capacity after an underestimate.
    #[cfg(test)]
    pub(crate) fn extend(&mut self, additional: u64) -> Result<()> {
        let mut usage = self.allowance.scope.as_ref().unwrap().lock().unwrap();
        if usage.started || usage.retired {
            return Err(Error::InvalidData("workspace extension after dispatch"));
        }
        let capacity = usage
            .capacity
            .checked_add(additional)
            .ok_or(Error::InvalidData("workspace reservation overflows"))?;
        self.allowance.reserve_global(additional, capacity)?;
        usage.capacity = capacity;
        Ok(())
    }
    pub(crate) fn start(&mut self) {
        let mut usage = self.allowance.scope.as_ref().unwrap().lock().unwrap();
        assert!(!usage.retired);
        usage.started = true;
    }
    pub(crate) fn retire(self) {
        drop(self);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut usage = self.allowance.scope.as_ref().unwrap().lock().unwrap();
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
    fn retirement_releases_only_unused_reservations_and_keeps_escaped_outputs() {
        let ledger = Limited::new(128 + 2 * RESERVATION_BYTES);
        let mut first = ledger.reserve(64).unwrap();
        let mut second = ledger.reserve(32).unwrap();
        first.extend(16).unwrap();
        assert_eq!(ledger.used(), 112 + 2 * RESERVATION_BYTES);
        assert!(ledger.reserve(17).is_err());
        first.start();
        second.start();
        assert!(first.extend(1).is_err());
        let a = first.allowance();
        let b = second.allowance();
        assert!(a.reserve(1).is_err());
        let left = Buffer::filled(48, 7u8, &a).unwrap();
        let mut right = Buffer::filled(16, 9u8, &b).unwrap();
        assert!(Buffer::filled(33, 0u8, &a).is_err());
        assert_eq!(ledger.used(), 112 + 2 * RESERVATION_BYTES);
        first.retire();
        assert_eq!(ledger.used(), 80 + 2 * RESERVATION_BYTES);
        second.retire();
        assert_eq!(ledger.used(), 64 + 2 * RESERVATION_BYTES);
        assert!(right.resize(17, 0).is_err());
        assert_eq!(&*right, &[9u8; 16]);
        drop(left);
        assert_eq!(ledger.used(), 16 + 2 * RESERVATION_BYTES);
        drop(right);
        assert_eq!(ledger.used(), 2 * RESERVATION_BYTES);
        assert!(Buffer::filled(1, 0u8, &a).is_err());
        drop((a, b));
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn failed_extension_and_unwind_release_the_admitted_scope() {
        let ledger = Limited::new(64 + RESERVATION_BYTES);
        let result = std::panic::catch_unwind(|| {
            let mut reservation = ledger.reserve(48).unwrap();
            assert!(reservation.extend(17).is_err());
            assert_eq!(ledger.used(), 48 + RESERVATION_BYTES);
            let _bytes = Buffer::filled(32, 0u8, &reservation.allowance()).unwrap();
            reservation.start();
            panic!("injected unwind");
        });
        assert!(result.is_err());
        assert_eq!(ledger.used(), 0);
        ledger.reserve(64).unwrap().retire();
        assert_eq!(ledger.used(), 0);
    }
}
