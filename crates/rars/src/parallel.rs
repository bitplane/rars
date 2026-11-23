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

thread_local! {
    static CAP: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Caps this thread's fan-out until dropped; `None` leaves the cap it finds.
pub(crate) struct ThreadCap(Option<Option<usize>>);

impl ThreadCap {
    pub(crate) fn set(threads: Option<usize>) -> Self {
        Self(threads.map(|threads| CAP.replace(Some(threads.max(1)))))
    }

    /// The cap in force here, for a helper thread to take on.
    #[cfg_attr(
        any(
            not(feature = "parallel"),
            all(target_arch = "wasm32", target_os = "unknown")
        ),
        allow(dead_code)
    )]
    pub(crate) fn current() -> Option<usize> {
        CAP.get()
    }
}

impl Drop for ThreadCap {
    fn drop(&mut self) {
        if let Some(previous) = self.0 {
            CAP.set(previous);
        }
    }
}

#[cfg(all(
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
mod threaded {
    use rayon::prelude::*;
    #[cfg(any(test, feature = "write", feature = "recovery"))]
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Windows of several items in the pool, whose items may block on what their siblings hold.
    #[cfg(any(test, feature = "write", feature = "recovery"))]
    static FANNED_OUT: AtomicUsize = AtomicUsize::new(0);

    #[cfg(any(test, feature = "write"))]
    struct FanOut;

    #[cfg(any(test, feature = "write"))]
    impl FanOut {
        fn start() -> Self {
            #[cfg(test)]
            assert!(
                !PRIVATE_POOL.get(),
                "a private pool ignores windows elsewhere, so it must not open one"
            );
            FANNED_OUT.fetch_add(1, Ordering::SeqCst);
            Self
        }
    }

    // Unit tests share one process, and with it FANNED_OUT: a window one test
    // opens turns nesting off in every other test's pool, though its items can
    // only block threads of the pool they run in. A test that needs nesting on
    // runs in a private pool, whose workers count only their own windows, and
    // they open none.
    #[cfg(test)]
    thread_local! {
        static PRIVATE_POOL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// A pool for one test, where other tests' windows do not turn nesting off.
    #[cfg(test)]
    #[cfg_attr(not(feature = "write"), allow(dead_code))]
    pub(crate) fn private_pool(threads: usize) -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .start_handler(|_| PRIVATE_POOL.set(true))
            .build()
            .unwrap()
    }

    #[cfg(any(test, feature = "write"))]
    impl Drop for FanOut {
        fn drop(&mut self) {
            FANNED_OUT.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Process preallocated slots without allocating a separate result vector.
    /// Returns only after every admitted callback has finished.
    pub(crate) fn for_each_mut<T, F>(items: &mut [T], apply: F)
    where
        T: Send,
        F: Fn(usize, &mut T) + Sync + Send,
    {
        if items.len() == 1 {
            return apply(0, &mut items[0]);
        }
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
        if let [_] = items.as_slice() {
            let item = items.into_iter().next().expect("one item");
            return match map(item) {
                Ok(output) => (vec![output], None),
                Err(error) => (Vec::new(), Some(error)),
            };
        }
        let mut outputs = Vec::with_capacity(items.len());
        for result in items.into_par_iter().map(map).collect::<Vec<_>>() {
            match result {
                Ok(output) => outputs.push(output),
                Err(error) => return (outputs, Some(error)),
            }
        }
        (outputs, None)
    }

    /// How many windows of items [`map_ordered`] starts ahead of the oldest
    /// one it has not consumed.
    const LOOKAHEAD: usize = 64;

    /// Maps `items` on the pool, at most `window` at a time, and hands each
    /// result to `consume` in order, on the calling thread. Unlike a batch, a
    /// slow item holds back only the consumption of the items after it: they
    /// keep starting, as far as `admit` lets them, up to [`LOOKAHEAD`] windows
    /// ahead of it.
    ///
    /// `admit(item, idle)` is asked, in order, whether the next item may
    /// start. `idle` means nothing has started that is not consumed, and then
    /// it must say yes. `finished(item)` follows the end of its mapping, and
    /// `consumed(item)` its consumption, so `admit` can count what a running
    /// item holds apart from what its result holds. The last item is mapped on
    /// the calling thread, which would otherwise wait. A failure, from `map`
    /// or `consume`, is returned once the items before it are consumed; items
    /// not yet started are skipped and those running are waited for.
    ///
    /// Call it only where [`may_spawn`] holds: it blocks the calling thread.
    pub(crate) fn map_ordered<T, O, E, F, A, D, R, C>(
        items: &[T],
        window: usize,
        mut admit: A,
        mut finished: D,
        mut consumed: R,
        map: F,
        mut consume: C,
    ) -> Result<(), E>
    where
        T: Copy + Send,
        O: Send,
        E: Send,
        F: Fn(T) -> Result<O, E> + Sync,
        A: FnMut(T, bool) -> bool,
        D: FnMut(T),
        R: FnMut(T),
        C: FnMut(O) -> Result<(), E>,
    {
        use std::collections::VecDeque;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;

        // A task's result, or None when it was skipped or panicked.
        type Report<O, E> = (usize, Option<Result<O, E>>);
        // Reports None if the task unwinds, so the calling thread stops
        // waiting for it; leaving the scope then raises the panic.
        struct Reporter<O, E> {
            index: usize,
            sender: Option<mpsc::Sender<Report<O, E>>>,
        }
        impl<O, E> Reporter<O, E> {
            fn send(mut self, result: Option<Result<O, E>>) {
                if let Some(sender) = self.sender.take() {
                    let _ = sender.send((self.index, result));
                }
            }
        }
        impl<O, E> Drop for Reporter<O, E> {
            fn drop(&mut self) {
                if let Some(sender) = self.sender.take() {
                    let _ = sender.send((self.index, None));
                }
            }
        }
        enum Slot<O, E> {
            Running,
            Done(Option<Result<O, E>>),
        }

        let window = window.max(1);
        let ahead = window.saturating_mul(LOOKAHEAD);
        let stop = AtomicBool::new(false);
        let (map, stop) = (&map, &stop);
        let (sender, receiver) = mpsc::channel::<Report<O, E>>();
        // Tasks keep this thread's cap on any fan-out of their own.
        let cap = super::ThreadCap::current();
        rayon::in_place_scope(|scope| {
            // The started items not yet consumed, from `head` on.
            let mut slots = VecDeque::new();
            let (mut head, mut next, mut running) = (0, 0, 0);
            let finish = |result| {
                stop.store(true, Ordering::Release);
                result
            };
            loop {
                while next < items.len() && running < window && next - head < ahead {
                    let item = items[next];
                    let idle = next == head;
                    if !admit(item, idle) {
                        debug_assert!(!idle, "an idle call always admits");
                        if !idle {
                            break;
                        }
                    }
                    if next + 1 == items.len() {
                        slots.push_back(Slot::Done(Some(map(item))));
                        finished(item);
                    } else {
                        slots.push_back(Slot::Running);
                        running += 1;
                        let reporter = Reporter {
                            index: next,
                            sender: Some(sender.clone()),
                        };
                        scope.spawn(move |_| {
                            let _cap = super::ThreadCap::set(cap);
                            let stopped = stop.load(Ordering::Acquire);
                            reporter.send((!stopped).then(|| map(item)));
                        });
                    }
                    next += 1;
                }
                match slots.front() {
                    None => return Ok(()),
                    Some(Slot::Done(_)) => {}
                    Some(Slot::Running) => {
                        let (index, result) = receiver.recv().expect("this thread holds a sender");
                        slots[index - head] = Slot::Done(result);
                        running -= 1;
                        finished(items[index]);
                        continue;
                    }
                }
                let Some(Slot::Done(Some(result))) = slots.pop_front() else {
                    // A task panicked; leaving the scope raises it.
                    return finish(Ok(()));
                };
                match result.and_then(&mut consume) {
                    Ok(()) => consumed(items[head]),
                    Err(error) => return finish(Err(error)),
                }
                head += 1;
            }
        })
    }

    /// Maps `items` in parallel but keeps only a window of results alive,
    /// handing each to `consume` in order before starting the next window.
    ///
    /// Mapping everything up front is simpler, but it holds every result at
    /// once; when the results are compressed file payloads that is the
    /// difference between one copy of the archive in memory and two.
    ///
    /// `admit` lets each item into a window, in order and on the calling
    /// thread, and what it returns goes with the item until it is consumed: a
    /// budget's permit, say, held until the item's result is written. A window
    /// is consumed only once all of it is mapped, so no item may wait on what
    /// an earlier item of its window holds. `admit(item, true)` opens a window,
    /// with nothing of this call's held, and may wait; `admit(item, false)`
    /// returns `None` rather than wait, which closes the window, and the item
    /// opens the next one.
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn map_slice_windowed<'a, T, A, O, E, D, F, C>(
        items: &'a [T],
        window: usize,
        mut admit: D,
        map: F,
        mut consume: C,
    ) -> Result<(), E>
    where
        T: Sync + 'a,
        A: Send,
        O: Send,
        E: Send,
        D: FnMut(&'a T, bool) -> Result<Option<A>, E>,
        F: Fn(&'a T, A) -> Result<O, E> + Sync + Send,
        C: FnMut(&'a T, O) -> Result<(), E>,
    {
        let window = window.max(1);
        let mut rest = items;
        while !rest.is_empty() {
            let mut admitted = Vec::with_capacity(window.min(rest.len()));
            for item in rest.iter().take(window) {
                match admit(item, admitted.is_empty())? {
                    Some(ticket) => admitted.push((item, ticket)),
                    None if admitted.is_empty() => {
                        unreachable!("the item that opens a window is always admitted")
                    }
                    None => break,
                }
            }
            rest = &rest[admitted.len()..];
            // A lone item has no sibling to steal, so its own work may still fan out.
            let fan_out = (admitted.len() > 1).then(FanOut::start);
            let mapped: Result<Vec<(&'a T, O)>, E> = admitted
                .into_par_iter()
                .map(|(item, ticket)| map(item, ticket).map(|output| (item, output)))
                .collect();
            drop(fan_out);
            for (item, output) in mapped? {
                consume(item, output)?;
            }
        }
        Ok(())
    }

    /// How many members to keep in flight at once.
    pub(crate) fn default_window() -> usize {
        threads()
    }

    /// Runs both, side by side when there is a thread free.
    #[cfg(feature = "write")]
    pub(crate) fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        if !may_nest() {
            return (a(), b());
        }
        rayon::join(a, b)
    }

    /// How many members can be worked on at the same time, within this thread's cap.
    pub(crate) fn threads() -> usize {
        let pool = rayon::current_num_threads().max(1);
        super::ThreadCap::current().map_or(pool, |cap| cap.min(pool))
    }

    /// Whether work inside an item may fan out: not while blocking siblings wait in the pool.
    #[cfg(any(feature = "write", feature = "recovery"))]
    pub(crate) fn may_nest() -> bool {
        #[cfg(test)]
        if PRIVATE_POOL.get() {
            return threads() > 1;
        }
        threads() > 1 && FANNED_OUT.load(Ordering::SeqCst) == 0
    }

    /// Not inside the pool, where members already run side by side, nor at one thread.
    pub(crate) fn may_spawn() -> bool {
        rayon::current_thread_index().is_none() && threads() > 1
    }

    const DEFAULT_BLOCK_DECODE_WORKERS: usize = 4;

    /// None under a cap of one. Members decoding side by side in the pool
    /// share one pool of these workers, so together they add only that many
    /// threads, and the largest of them no longer decodes alone.
    pub(crate) fn block_decode_workers(policy: crate::read_control::DecodeWorkers) -> usize {
        use crate::read_control::DecodeWorkers;
        if super::ThreadCap::current() == Some(1) {
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

    /// One at a time, in order.
    #[cfg_attr(all(test, feature = "parallel"), allow(dead_code))]
    pub(crate) fn map_ordered<T, O, E, F, A, D, R, C>(
        items: &[T],
        _window: usize,
        mut admit: A,
        mut finished: D,
        mut consumed: R,
        map: F,
        mut consume: C,
    ) -> Result<(), E>
    where
        T: Copy + Send,
        O: Send,
        E: Send,
        F: Fn(T) -> Result<O, E> + Sync,
        A: FnMut(T, bool) -> bool,
        D: FnMut(T),
        R: FnMut(T),
        C: FnMut(O) -> Result<(), E>,
    {
        for &item in items {
            let admitted = admit(item, true);
            debug_assert!(admitted, "an idle call always admits");
            let output = map(item);
            finished(item);
            consume(output?)?;
            consumed(item);
        }
        Ok(())
    }

    /// One at a time, so the window only decides how much output is alive at
    /// once rather than how much work runs at once. Each item opens its own
    /// window, so each is admitted with nothing else of this call's held.
    #[cfg(any(test, feature = "write"))]
    pub(crate) fn map_slice_windowed<'a, T, A, O, E, D, F, C>(
        items: &'a [T],
        _window: usize,
        mut admit: D,
        map: F,
        mut consume: C,
    ) -> Result<(), E>
    where
        T: Sync + 'a,
        A: Send,
        O: Send,
        E: Send,
        D: FnMut(&'a T, bool) -> Result<Option<A>, E>,
        F: Fn(&'a T, A) -> Result<O, E> + Sync + Send,
        C: FnMut(&'a T, O) -> Result<(), E>,
    {
        for item in items {
            let Some(ticket) = admit(item, true)? else {
                unreachable!("the item that opens a window is always admitted")
            };
            let output = map(item, ticket)?;
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

    #[cfg(any(feature = "write", feature = "recovery"))]
    #[cfg_attr(all(test, feature = "parallel"), allow(dead_code))]
    pub(crate) fn may_nest() -> bool {
        false
    }

    #[cfg(any(test, feature = "write", feature = "recovery"))]
    pub(crate) fn threads() -> usize {
        1
    }

    #[cfg(feature = "write")]
    #[cfg_attr(all(test, feature = "parallel"), allow(dead_code))]
    pub(crate) fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        (a(), b())
    }
}

#[cfg(test)]
mod tests {
    use super::sequential;

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn a_thread_cap_bounds_fan_out_until_dropped() {
        use super::{block_decode_workers, default_window, may_spawn, threads, ThreadCap};
        use crate::read_control::DecodeWorkers;
        let uncapped = threads();
        {
            let _one = ThreadCap::set(Some(1));
            assert_eq!(default_window(), 1);
            assert!(!may_spawn());
            assert_eq!(block_decode_workers(DecodeWorkers::Auto), 0);
            assert_eq!(block_decode_workers(DecodeWorkers::AtMost(4)), 0);
            {
                let _unset = ThreadCap::set(None);
                assert_eq!(threads(), 1);
                let _two = ThreadCap::set(Some(2));
                assert_eq!(threads(), uncapped.min(2));
                assert!(block_decode_workers(DecodeWorkers::AtMost(8)) <= 2);
            }
            assert_eq!(threads(), 1);
        }
        assert_eq!(ThreadCap::current(), None);
        assert_eq!(threads(), uncapped);
        let _zero = ThreadCap::set(Some(0));
        assert!(!may_spawn());
    }

    #[cfg(feature = "write")]
    #[test]
    fn read_entry_points_cap_the_calling_thread_for_the_call() {
        use super::ThreadCap;
        let mut builder = crate::Builder::new(crate::ArchiveVersion::Rar50);
        builder
            .add_bytes(b"a".to_vec(), b"x".to_vec(), None, None)
            .unwrap();
        let archive = crate::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let options = crate::ArchiveReadOptions::new().with_threads(1);
        archive
            .extract_to_parallel_buffered_with_options(options, |_| {
                assert_eq!(ThreadCap::current(), Some(1));
                Ok(Box::new(std::io::sink()))
            })
            .unwrap();
        archive
            .test_with_options_and_callback(options, |_| {
                assert_eq!(ThreadCap::current(), Some(1));
                Ok(())
            })
            .unwrap();
        assert_eq!(ThreadCap::current(), None);
    }

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
                |_, _| Ok(Some(())),
                |x, ()| Ok(x * 2),
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
            |_, _| Ok(Some(())),
            |x, ()| if *x == 1 { Err(11) } else { Ok(x * 2) },
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
            |_, _| Ok(Some(())),
            |x, ()| {
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
        let empty: Result<(), ()> = sequential::map_slice_windowed::<usize, (), usize, _, _, _, _>(
            &[],
            0,
            |_, _| Ok(Some(())),
            |_, ()| panic!("empty map"),
            |_, _| panic!("empty consume"),
        );
        assert_eq!(empty, Ok(()));
    }

    /// What a windowed map did, in order: `A` for an admission (and whether
    /// it opened a window), `R` for one refused, `C` for a consumption.
    fn admission_log(
        windowed: impl FnOnce(
            &mut dyn FnMut(&usize, bool) -> Result<Option<usize>, ()>,
            &mut dyn FnMut(&usize, usize) -> Result<(), ()>,
        ) -> Result<(), ()>,
    ) -> Vec<String> {
        let log = std::cell::RefCell::new(Vec::new());
        // Refuses 3 and 5 unless they open a window, as a full budget would.
        let mut admit = |item: &usize, opens: bool| {
            let admitted = opens || (*item != 3 && *item != 5);
            let mark = if admitted { "A" } else { "R" };
            log.borrow_mut()
                .push(format!("{mark}{item}{}", if opens { "*" } else { "" }));
            Ok(admitted.then_some(*item * 10))
        };
        let mut consume = |item: &usize, output: usize| {
            assert_eq!(output, item * 10 + 1);
            log.borrow_mut().push(format!("C{item}"));
            Ok(())
        };
        windowed(&mut admit, &mut consume).unwrap();
        log.into_inner()
    }

    #[test]
    fn a_refused_admission_closes_the_window_and_opens_the_next() {
        let input = [1, 2, 3, 4, 5, 6];
        // One at a time, every item opens its own window and may wait.
        let sequential = admission_log(|admit, consume| {
            sequential::map_slice_windowed(&input, 4, admit, |_, ticket| Ok(ticket + 1), consume)
        });
        assert_eq!(
            sequential,
            ["A1*", "C1", "A2*", "C2", "A3*", "C3", "A4*", "C4", "A5*", "C5", "A6*", "C6"]
        );
        #[cfg(all(
            feature = "parallel",
            not(all(target_arch = "wasm32", target_os = "unknown"))
        ))]
        {
            // A window is written before the item it refused is admitted
            // again, now opening the next one, where it may wait.
            let threaded = admission_log(|admit, consume| {
                super::threaded::map_slice_windowed(
                    &input,
                    4,
                    admit,
                    |_, ticket| Ok(ticket + 1),
                    consume,
                )
            });
            assert_eq!(
                threaded,
                [
                    "A1*", "A2", "R3", "C1", "C2", "A3*", "A4", "R5", "C3", "C4", "A5*", "A6",
                    "C5", "C6"
                ]
            );
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn ordered_maps_start_past_a_slow_item_and_consume_in_order() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let fourth_done = AtomicBool::new(false);
        let waited = AtomicBool::new(false);
        let mut consumed = Vec::new();
        let (mut admitted, mut finished, mut released) = (0, 0, 0);
        let mut last_on_caller = false;
        pool.install(|| {
            let caller = std::thread::current().id();
            super::threaded::map_ordered(
                &[0, 1, 2, 3, 4, 5, 6],
                2,
                |_, _| {
                    admitted += 1;
                    true
                },
                |_| finished += 1,
                |_| released += 1,
                |item| {
                    if item == 0 {
                        // A batch of two would never start item 4 while this runs.
                        let start = Instant::now();
                        while !fourth_done.load(Ordering::Acquire)
                            && start.elapsed() < Duration::from_secs(10)
                        {
                            std::thread::yield_now();
                        }
                        waited.store(fourth_done.load(Ordering::Acquire), Ordering::Release);
                    }
                    if item == 4 {
                        fourth_done.store(true, Ordering::Release);
                    }
                    Ok::<_, ()>((item, std::thread::current().id() == caller))
                },
                |(item, on_caller)| {
                    consumed.push(item);
                    last_on_caller = on_caller;
                    Ok(())
                },
            )
        })
        .unwrap();
        assert!(waited.load(Ordering::Acquire));
        assert_eq!(consumed, [0, 1, 2, 3, 4, 5, 6]);
        assert!(last_on_caller, "the last item maps on the calling thread");
        assert_eq!((admitted, finished, released), (7, 7, 7));
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn ordered_maps_consume_the_prefix_ahead_of_a_failure() {
        for fail_in_consume in [false, true] {
            let mut consumed = Vec::new();
            let result = super::threaded::map_ordered(
                &[0, 1, 2, 3, 4, 5, 6, 7],
                3,
                |_, _| true,
                |_| {},
                |_| {},
                |item| {
                    if item == 3 && !fail_in_consume {
                        Err(item)
                    } else {
                        Ok(item)
                    }
                },
                |item| {
                    if item == 3 {
                        return Err(30);
                    }
                    consumed.push(item);
                    Ok(())
                },
            );
            assert_eq!(result, Err(if fail_in_consume { 30 } else { 3 }));
            assert_eq!(consumed, [0, 1, 2]);
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn ordered_maps_wait_for_room_and_admit_when_idle() {
        use std::cell::Cell;
        // Each item holds one unit until consumed, against a limit of two;
        // item 2 is over the limit alone and starts only when nothing is held.
        let held = Cell::new(0u32);
        let mut most = 0;
        let mut consumed = Vec::new();
        let costs = [1u32, 1, 5, 1, 1, 1];
        super::threaded::map_ordered(
            &[0usize, 1, 2, 3, 4, 5],
            4,
            |item, idle| {
                let cost = costs[item];
                if !idle && held.get() + cost > 2 {
                    return false;
                }
                assert!(!idle || held.get() == 0);
                held.set(held.get() + cost);
                most = most.max(held.get());
                true
            },
            |_| {},
            |item| held.set(held.get() - costs[item]),
            Ok::<_, ()>,
            |item| {
                consumed.push(item);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(consumed, [0, 1, 2, 3, 4, 5]);
        assert_eq!(held.get(), 0);
        assert_eq!(most, 5);
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
                |_, _| Ok(Some(())),
                |x, ()| {
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
            |_, _| Ok(Some(())),
            |x, ()| {
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
            |_, _| Ok(Some(())),
            |x, ()| {
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
                |_, _| Ok(Some(())),
                |x, ()| {
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
        let empty: Result<(), ()> =
            super::threaded::map_slice_windowed::<usize, (), usize, _, _, _, _>(
                &[],
                0,
                |_, _| Ok(Some(())),
                |_, ()| panic!("empty map"),
                |_, _| panic!("empty consume"),
            );
        assert_eq!(empty, Ok(()));
    }
}
