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

    pub(crate) fn map_collect<T, O, E, F>(items: Vec<T>, map: F) -> Result<Vec<O>, E>
    where
        T: Send,
        O: Send,
        E: Send,
        F: Fn(T) -> Result<O, E> + Sync + Send,
    {
        items.into_par_iter().map(map).collect()
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

    pub(crate) fn map_collect<T, O, E, F>(items: Vec<T>, map: F) -> Result<Vec<O>, E>
    where
        T: Send,
        O: Send,
        E: Send,
        F: Fn(T) -> Result<O, E> + Sync + Send,
    {
        items.into_iter().map(map).collect()
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
        let mapped: Result<Vec<_>, ()> = sequential::map_collect(vec![3, 1, 2], |x| Ok(x * 2));
        assert_eq!(mapped, Ok(vec![6, 2, 4]));
        let empty: Result<Vec<usize>, ()> =
            sequential::map_collect(Vec::<usize>::new(), |_| panic!("empty map"));
        assert_eq!(empty, Ok(vec![]));
        let visited = std::sync::Mutex::new(Vec::new());
        let mapped = sequential::map_collect(vec![3, 1, 2], |x| {
            visited.lock().unwrap().push(x);
            if x == 1 {
                Err(11)
            } else {
                Ok(x)
            }
        });
        assert_eq!(mapped, Err(11));
        assert_eq!(*visited.lock().unwrap(), [3, 1]);
        assert_eq!(sequential::default_window(), 1);
        assert_eq!(sequential::threads(), 1);
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
}
