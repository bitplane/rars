//! Fan-out helpers, and the one place that knows whether there is anything to
//! fan out to.
//!
//! Bare WebAssembly has no threads: `wasm32-unknown-unknown` has no way to
//! start one, so rayon's pool panics the first time it is touched rather than
//! degrading. The `wasm` module below is the same three functions done in
//! sequence, and rayon is not compiled in at all for that target.

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) use threaded::*;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) use wasm::*;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod threaded {
    use rayon::prelude::*;

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

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm {
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

    pub(crate) fn threads() -> usize {
        1
    }
}
