//! Batch admission happens before dispatch. Workers cannot borrow a sibling's
//! unused allowance, and publication starts only after every callback joins.
use super::{Buffer, Limited, Reservation, RESERVATION_BYTES};
use crate::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};

struct Slot<T, O> {
    item: T,
    hint: u64,
    reservation: Option<Reservation>,
    result: Option<Result<O>>,
}

pub(crate) fn extract_windowed<T, O, I, H, M, P>(
    items: I,
    ledger: &Limited,
    hint: H,
    map: M,
    mut publish: P,
) -> Result<()>
where
    T: Copy + Send,
    O: Send,
    I: Iterator<Item = T>,
    H: Fn(T) -> u64,
    M: Fn(T, &Limited) -> Result<O> + Sync + Send,
    P: FnMut(O) -> Result<()>,
{
    let overhead = std::mem::size_of::<Slot<T, O>>() as u64;
    // A member estimated above the whole workspace runs alone with all of it,
    // as it would sequentially; its real allocations decide.
    let ceiling = ledger
        .available()
        .saturating_sub(overhead + RESERVATION_BYTES);
    let hint = |item| hint(item).min(ceiling);
    let mut items = items.peekable();
    while let Some(&first) = items.peek() {
        let first_cost = hint(first)
            .saturating_add(overhead)
            .saturating_add(RESERVATION_BYTES);
        ledger.check_capacity(first_cost)?;
        let capacity = crate::parallel::default_window()
            .max(1)
            .min((ledger.available() / first_cost.max(1)).min(usize::MAX as u64) as usize);
        let mut slots = Buffer::with_capacity(capacity, ledger)?;
        let mut required = 0u64;
        while slots.len() < capacity {
            let Some(&item) = items.peek() else { break };
            let hint = hint(item);
            let next = required
                .saturating_add(hint)
                .saturating_add(RESERVATION_BYTES);
            if next > ledger.available() {
                break;
            }
            items.next();
            slots.push_admitted(Slot {
                item,
                hint,
                reservation: None,
                result: None,
            });
            required = next;
        }
        // Admission hints choose the batch width; they are not decoder upper bounds.
        // The first-cost check includes its slot allocation, so at least one
        // member fits. Only the coordinator holds the global allowance here.
        debug_assert!(!slots.is_empty());
        let spare = ledger.available() - required;
        let extra = spare / slots.len() as u64;
        for slot in &mut slots {
            slot.reservation = Some(ledger.reserve(slot.hint + extra)?);
        }
        let stopped = AtomicBool::new(false);
        crate::parallel::for_each_mut(&mut slots, |_, slot| {
            let mut reservation = slot.reservation.take().expect("admitted worker");
            if !stopped.load(Ordering::Acquire) {
                reservation.start();
                let result = map(slot.item, &reservation.allowance());
                if result.is_err() {
                    stopped.store(true, Ordering::Release);
                }
                slot.result = Some(result);
            }
            reservation.retire();
        });
        // The members ahead of a failure are published, as sequential
        // extraction would; a member skipped once a later one failed ends the
        // prefix. Dropping slots frees the rest, including results whose
        // reservations have retired.
        for index in 0..slots.len() {
            match slots[index].result.take() {
                Some(result) => publish(result?)?,
                None => {
                    let failure = slots[index..]
                        .iter_mut()
                        .find_map(|slot| slot.result.take()?.err());
                    return Err(failure.unwrap_or(Error::Cancelled));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::Allowance;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_large_later_hint_waits_for_the_next_batch_in_publication_order() {
        let overhead = std::mem::size_of::<Slot<usize, Buffer<u8, Limited>>>() as u64;
        let limit = 4 * (overhead + RESERVATION_BYTES + 16);
        let ledger = Allowance::limited(limit);
        let published = AtomicUsize::new(0);
        extract_windowed(
            0..3usize,
            &ledger,
            |index| {
                if index == 1 {
                    limit - overhead - RESERVATION_BYTES
                } else {
                    16
                }
            },
            |index, local| {
                if index == 1 {
                    assert_eq!(published.load(Ordering::SeqCst), 1);
                }
                Ok(Buffer::filled(16, index as u8, local)?)
            },
            |data| {
                let expected = published.fetch_add(1, Ordering::SeqCst) as u8;
                assert_eq!(&*data, &[expected; 16]);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(published.load(Ordering::SeqCst), 3);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn a_hint_above_the_whole_workspace_runs_alone_with_all_of_it() {
        let ledger = Allowance::limited(1 << 20);
        let mut published = Vec::new();
        extract_windowed(
            0..3usize,
            &ledger,
            |index| if index == 1 { u64::MAX } else { 16 },
            |index, local| {
                Ok(Buffer::filled(
                    if index == 1 { 900 << 10 } else { 16 },
                    0u8,
                    local,
                )?)
            },
            |data| {
                published.push(data.len());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(published, [16, 900 << 10, 16]);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn the_members_ahead_of_a_failure_are_published() {
        let ledger = Allowance::limited(1 << 20);
        let finished = AtomicUsize::new(0);
        let mut published = Vec::new();
        let error = extract_windowed(
            0..3usize,
            &ledger,
            |_| 16,
            |index, _| {
                if index < 2 {
                    finished.fetch_add(1, Ordering::SeqCst);
                    return Ok(index);
                }
                // Fail only once the others are done, so none is skipped.
                while finished.load(Ordering::SeqCst) < 2 {
                    std::hint::spin_loop();
                }
                Err(Error::Cancelled)
            },
            |index| {
                published.push(index);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(error, Error::Cancelled));
        assert_eq!(published, [0, 1]);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn admitted_results_remain_charged_during_publication() {
        let ledger = Allowance::limited(8192);
        let published = AtomicUsize::new(0);
        extract_windowed(
            0..4,
            &ledger,
            |_| 256,
            |index, local| Ok(Buffer::filled(256, index as u8, local)?),
            |data| {
                assert!(ledger.used() >= data.len() as u64 + RESERVATION_BYTES);
                assert!(ledger.used() <= ledger.limit());
                published.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(published.load(Ordering::Relaxed), 4);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn admission_refusal_runs_no_worker() {
        let ledger = Allowance::limited(1);
        let error = extract_windowed(
            0..1,
            &ledger,
            |_| 1,
            |_, _| -> Result<()> { panic!("unadmitted worker ran") },
            |_| panic!("unadmitted result published"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn underestimated_hint_refuses_runtime_growth_without_publishing() {
        let ledger = Allowance::limited(8192);
        let error = extract_windowed(
            0..2,
            &ledger,
            |_| 1,
            |_, local| Ok(Buffer::filled(16384, 0u8, local)?),
            |_| panic!("refused result published"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(ledger.used(), 0);
    }

    #[test]
    fn worker_and_sink_failures_release_sibling_results_and_stop_batches() {
        for sink_failure in [false, true] {
            let ledger = Allowance::limited(8192);
            let launched = AtomicUsize::new(0);
            let published = AtomicUsize::new(0);
            let error = extract_windowed(
                0..100,
                &ledger,
                |_| 256,
                |_, local| {
                    launched.fetch_add(1, Ordering::Relaxed);
                    let data = Buffer::filled(256, 0u8, local)?;
                    if sink_failure {
                        Ok(data)
                    } else {
                        Err(Error::Cancelled)
                    }
                },
                |_| {
                    published.fetch_add(1, Ordering::Relaxed);
                    Err(Error::Cancelled)
                },
            )
            .unwrap_err();
            assert_eq!(error, Error::Cancelled);
            assert!(launched.load(Ordering::Relaxed) <= crate::parallel::default_window());
            assert_eq!(published.load(Ordering::Relaxed), usize::from(sink_failure));
            assert_eq!(ledger.used(), 0);
        }
    }
}
