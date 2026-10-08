//! A 64-bit atomic counter for targets without 64-bit atomics.
//!
//! 32-bit PowerPC, MIPS and older ARM have no `std::sync::atomic::AtomicU64`.
//! Byte budgets can exceed 4 GiB there too, so a narrower atomic would wrap;
//! those targets get a mutex with the same interface instead.

#[cfg(target_has_atomic = "64")]
pub(crate) use std::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
pub(crate) use fallback::AtomicU64;

// Also built for tests so 64-bit hosts exercise it.
#[cfg(any(test, not(target_has_atomic = "64")))]
mod fallback {
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    pub(crate) struct AtomicU64(Mutex<u64>);

    // Which methods are live depends on the enabled features.
    #[allow(dead_code)]
    impl AtomicU64 {
        pub(crate) const fn new(value: u64) -> Self {
            Self(Mutex::new(value))
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, u64> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        pub(crate) fn load(&self, _: Ordering) -> u64 {
            *self.lock()
        }

        pub(crate) fn store(&self, value: u64, _: Ordering) {
            *self.lock() = value;
        }

        pub(crate) fn fetch_add(&self, value: u64, _: Ordering) -> u64 {
            let mut current = self.lock();
            let previous = *current;
            *current = previous.wrapping_add(value);
            previous
        }

        pub(crate) fn fetch_sub(&self, value: u64, _: Ordering) -> u64 {
            let mut current = self.lock();
            let previous = *current;
            *current = previous.wrapping_sub(value);
            previous
        }

        pub(crate) fn compare_exchange_weak(
            &self,
            expected: u64,
            new: u64,
            _: Ordering,
            _: Ordering,
        ) -> Result<u64, u64> {
            let mut current = self.lock();
            if *current == expected {
                *current = new;
                Ok(expected)
            } else {
                Err(*current)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::AtomicU64;
        use std::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed};

        #[test]
        fn counts_past_32_bits() {
            let value = AtomicU64::new(u64::from(u32::MAX));
            assert_eq!(value.fetch_add(2, Relaxed), u64::from(u32::MAX));
            assert_eq!(value.load(Relaxed), 1 << 32 | 1);
            assert_eq!(value.fetch_sub(1 << 32, AcqRel), 1 << 32 | 1);
            assert_eq!(value.load(Relaxed), 1);
            value.store(5 << 32, Relaxed);
            assert_eq!(value.load(Relaxed), 5 << 32);
        }

        #[test]
        fn compare_exchange_reports_the_current_value() {
            let value = AtomicU64::new(7);
            assert_eq!(value.compare_exchange_weak(6, 9, AcqRel, Acquire), Err(7));
            assert_eq!(value.compare_exchange_weak(7, 9, AcqRel, Acquire), Ok(7));
            assert_eq!(value.load(Relaxed), 9);
        }

        #[test]
        fn concurrent_reservations_never_exceed_the_limit() {
            let used = AtomicU64::new(0);
            let limit = 1000;
            let granted = AtomicU64::new(0);
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    scope.spawn(|| {
                        for _ in 0..500 {
                            let mut current = used.load(Acquire);
                            while let Some(next) = Some(current + 3).filter(|n| *n <= limit) {
                                match used.compare_exchange_weak(current, next, AcqRel, Acquire) {
                                    Ok(_) => {
                                        granted.fetch_add(3, Relaxed);
                                        break;
                                    }
                                    Err(actual) => current = actual,
                                }
                            }
                        }
                    });
                }
            });
            assert_eq!(used.load(Relaxed), 999);
            assert_eq!(granted.load(Relaxed), 999);
        }
    }
}
