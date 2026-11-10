//! Fan-out helpers, and the one place that knows whether there is anything to
//! fan out to.
//!
//! Without the `parallel` feature these helpers run sequentially.
//! Bare WebAssembly also has no threads: `wasm32-unknown-unknown` has no way to
//! start one, so rayon's pool panics the first time it is touched rather than
//! degrading. The `sequential` module below is the same three functions done in
//! sequence, and rayon is not compiled in at all for that target.

#[cfg(any(
    not(feature = "parallel"),
    all(target_arch = "wasm32", target_os = "unknown")
))]
pub(crate) use sequential::*;
#[cfg(all(
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
pub(crate) use threaded::*;

#[cfg(all(
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
mod threaded {
    use rayon::prelude::*;

    /// Process preallocated slots without allocating a separate result vector.
    /// Returns only after every admitted callback has finished.
    pub(crate) fn for_each_mut<T, F>(items: &mut [T], apply: F)
    where
        T: Send,
        F: Fn(usize, &mut T) + Sync + Send,
    {
        items
            .par_iter_mut()
            .enumerate()
            .for_each(|(index, item)| apply(index, item));
    }

    /// Maps `items` in parallel and returns, in order, the outputs before the
    /// first failure together with that failure, so a caller can still publish
    /// the successful prefix.
    pub(crate) fn map_prefix<T, O, E, F>(items: Vec<T>, map: F) -> (Vec<O>, Option<E>)
    where
        T: Send,
        O: Send,
        E: Send,
        F: Fn(T) -> Result<O, E> + Sync + Send,
    {
        let mut outputs = Vec::with_capacity(items.len());
        for result in items.into_par_iter().map(map).collect::<Vec<_>>() {
            match result {
                Ok(output) => outputs.push(output),
                Err(error) => return (outputs, Some(error)),
            }
        }
        (outputs, None)
    }

    /// Maps `items` in parallel but keeps only a window of results alive,
    /// handing each to `consume` in order before starting the next window.
    ///
    /// Mapping everything up front is simpler, but it holds every result at
    /// once; when the results are compressed file payloads that is the
    /// difference between one copy of the archive in memory and two.
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn map_slice_windowed<'a, T, O, E, F, C>(
        items: &'a [T],
        window: usize,
        map: F,
        mut consume: C,
    ) -> Result<(), E>
    where
        T: Sync + 'a,
        O: Send,
        E: Send,
        F: Fn(&'a T) -> Result<O, E> + Sync + Send,
        C: FnMut(&'a T, O) -> Result<(), E>,
    {
        let window = window.max(1);
        for chunk in items.chunks(window) {
            let mapped: Vec<O> = chunk.par_iter().map(&map).collect::<Result<_, E>>()?;
            for (item, output) in chunk.iter().zip(mapped) {
                consume(item, output)?;
            }
        }
        Ok(())
    }

    /// How many members to keep in flight at once.
    pub(crate) fn default_window() -> usize {
        threads()
    }

    /// How many members can be worked on at the same time.
    pub(crate) fn threads() -> usize {
        rayon::current_num_threads().max(1)
    }

    /// Not inside the pool, where members already run side by side, nor at one thread.
    pub(crate) fn may_spawn() -> bool {
        rayon::current_thread_index().is_none() && threads() > 1
    }

    const DEFAULT_BLOCK_DECODE_WORKERS: usize = 8;

    /// None inside the pool, where members already decode side by side.
    pub(crate) fn block_decode_workers(policy: crate::read_control::DecodeWorkers) -> usize {
        use crate::read_control::DecodeWorkers;
        if rayon::current_thread_index().is_some() {
            return 0;
        }
        match policy {
            DecodeWorkers::Serial => 0,
            DecodeWorkers::AtMost(cap) => cap.min(threads()),
            // Unit tests take the worker path even on one core.
            DecodeWorkers::Auto => (threads() - 1)
                .min(DEFAULT_BLOCK_DECODE_WORKERS)
                .max(usize::from(cfg!(test))),
        }
    }
}

#[cfg(any(
    test,
    not(feature = "parallel"),
    all(target_arch = "wasm32", target_os = "unknown")
))]
mod sequential {
    /// Process preallocated slots without allocating a separate result vector.
    /// Returns only after every admitted callback has finished.
    pub(crate) fn for_each_mut<T, F>(items: &mut [T], apply: F)
    where
        T: Send,
        F: Fn(usize, &mut T) + Sync + Send,
    {
        items
            .iter_mut()
            .enumerate()
            .for_each(|(index, item)| apply(index, item));
    }

    pub(crate) fn map_prefix<T, O, E, F>(items: Vec<T>, map: F) -> (Vec<O>, Option<E>)
    where
        T: Send,
        O: Send,
        E: Send,
        F: Fn(T) -> Result<O, E> + Sync + Send,
    {
        let mut outputs = Vec::with_capacity(items.len());
        for item in items {
            match map(item) {
                Ok(output) => outputs.push(output),
                Err(error) => return (outputs, Some(error)),
            }
        }
        (outputs, None)
    }

    /// One at a time, so the window only decides how much output is alive at
    /// once rather than how much work runs at once.
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn map_slice_windowed<'a, T, O, E, F, C>(
        items: &'a [T],
        _window: usize,
        map: F,
        mut consume: C,
    ) -> Result<(), E>
    where
        T: Sync + 'a,
        O: Send,
        E: Send,
        F: Fn(&'a T) -> Result<O, E> + Sync + Send,
        C: FnMut(&'a T, O) -> Result<(), E>,
    {
        for item in items {
            let output = map(item)?;
            consume(item, output)?;
        }
        Ok(())
    }

    pub(crate) fn default_window() -> usize {
        1
    }

    pub(crate) fn may_spawn() -> bool {
        false
    }

    #[cfg(any(test, feature = "write"))]
    pub(crate) fn threads() -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::sequential;

    #[test]
    fn sequential_slots_and_collect_keep_order_and_stop_on_error() {
        let mut slots = [7, 7, 7];
        sequential::for_each_mut(&mut slots, |index, slot| *slot += index);
        assert_eq!(slots, [7, 8, 9]);
        sequential::for_each_mut::<usize, _>(&mut [], |_, _| panic!("empty callback"));
        let mapped = sequential::map_prefix(vec![3, 1, 2], |x| Ok::<_, ()>(x * 2));
        assert_eq!(mapped, (vec![6, 2, 4], None));
        let empty = sequential::map_prefix(Vec::<usize>::new(), |_| -> Result<usize, ()> {
            panic!("empty map")
        });
        assert_eq!(empty, (vec![], None));
        let visited = std::sync::Mutex::new(Vec::new());
        let mapped = sequential::map_prefix(vec![3, 1, 2], |x| {
            visited.lock().unwrap().push(x);
            if x == 1 {
                Err(11)
            } else {
                Ok(x)
            }
        });
        assert_eq!(mapped, (vec![3], Some(11)));
        assert_eq!(*visited.lock().unwrap(), [3, 1]);
        assert_eq!(sequential::default_window(), 1);
        assert_eq!(sequential::threads(), 1);
        assert!(!sequential::may_spawn());
    }

    #[test]
    fn sequential_windows_publish_in_order_and_preserve_both_failure_kinds() {
        let input = [3, 1, 2];
        for window in [0, 1, 8] {
            let mut emitted = vec![];
            let result: Result<(), ()> = sequential::map_slice_windowed(
                &input,
                window,
                |x| Ok(x * 2),
                |x, y| {
                    emitted.push((*x, y));
                    Ok(())
                },
            );
            assert_eq!(result, Ok(()));
            assert_eq!(emitted, [(3, 6), (1, 2), (2, 4)]);
        }
        let mut emitted = vec![];
        let result = sequential::map_slice_windowed(
            &input,
            2,
            |x| if *x == 1 { Err(11) } else { Ok(x * 2) },
            |x, y| {
                emitted.push((*x, y));
                Ok(())
            },
        );
        assert_eq!(result, Err(11));
        assert_eq!(emitted, [(3, 6)]);
        let mut emitted = vec![];
        let visited = std::sync::Mutex::new(Vec::new());
        let result = sequential::map_slice_windowed(
            &input,
            2,
            |x| {
                visited.lock().unwrap().push(*x);
                Ok(x * 2)
            },
            |x, y| {
                emitted.push((*x, y));
                if *x == 1 {
                    Err(12)
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err(12));
        assert_eq!(emitted, [(3, 6), (1, 2)]);
        assert_eq!(*visited.lock().unwrap(), [3, 1]);
        let empty: Result<(), ()> = sequential::map_slice_windowed::<usize, usize, _, _, _>(
            &[],
            0,
            |_| panic!("empty map"),
            |_, _| panic!("empty consume"),
        );
        assert_eq!(empty, Ok(()));
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn threaded_windows_preserve_order_and_wait_for_admitted_callbacks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;
        let input = [3, 1, 2, 4];
        let active = AtomicUsize::new(0);
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        for window in [0, 1, 2, 8] {
            let mut emitted = Vec::new();
            let result: Result<(), ()> = super::threaded::map_slice_windowed(
                &input,
                window,
                |x| {
                    active.fetch_add(1, Ordering::Relaxed);
                    let _active = Active(&active);
                    Ok(x * 2)
                },
                |x, y| {
                    emitted.push((*x, y));
                    Ok(())
                },
            );
            assert_eq!(result, Ok(()));
            assert_eq!(emitted, [(3, 6), (1, 2), (2, 4), (4, 8)]);
            assert_eq!(active.load(Ordering::Acquire), 0);
        }
        let mut emitted = Vec::new();
        let result = super::threaded::map_slice_windowed(
            &input,
            2,
            |x| {
                active.fetch_add(1, Ordering::Relaxed);
                let _active = Active(&active);
                if *x == 2 {
                    Err(11)
                } else {
                    Ok(x * 2)
                }
            },
            |x, y| {
                emitted.push((*x, y));
                Ok(())
            },
        );
        assert_eq!(result, Err(11));
        // A mapping failure discards the whole failed window. Earlier windows
        // are already published, and every admitted mapping has returned.
        assert_eq!(emitted, [(3, 6), (1, 2)]);
        assert_eq!(active.load(Ordering::Acquire), 0);

        let visited = Mutex::new(Vec::new());
        emitted.clear();
        let result = super::threaded::map_slice_windowed(
            &input,
            2,
            |x| {
                visited.lock().unwrap().push(*x);
                Ok(x * 2)
            },
            |x, y| {
                emitted.push((*x, y));
                if *x == 1 {
                    Err(12)
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err(12));
        assert_eq!(emitted, [(3, 6), (1, 2)]);
        let mut visited = visited.into_inner().unwrap();
        visited.sort_unstable();
        assert_eq!(
            visited,
            [1, 3],
            "later windows must not start after consumer failure"
        );

        emitted.clear();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), ()> = super::threaded::map_slice_windowed(
                &input,
                2,
                |x| {
                    active.fetch_add(1, Ordering::Relaxed);
                    let _active = Active(&active);
                    assert_ne!(*x, 2, "injected map panic");
                    Ok(x * 2)
                },
                |x, y| {
                    emitted.push((*x, y));
                    Ok(())
                },
            );
        }));
        assert!(result.is_err());
        assert_eq!(emitted, [(3, 6), (1, 2)]);
        assert_eq!(active.load(Ordering::Acquire), 0);
        let empty: Result<(), ()> = super::threaded::map_slice_windowed::<usize, usize, _, _, _>(
            &[],
            0,
            |_| panic!("empty map"),
            |_, _| panic!("empty consume"),
        );
        assert_eq!(empty, Ok(()));
    }
}
