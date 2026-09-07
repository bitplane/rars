//! Demand-driven, archive-order decoding for one scoped writer call.
use super::*;
use crate::streaming::SourceFactory;
use crate::{Error, ReadCancellation};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Condvar, Mutex,
};

#[derive(Default)]
struct State {
    requested: Option<usize>,
    ready: BTreeMap<usize, Arc<Lease>>,
    error: Option<Error>,
    done: bool,
    published: std::collections::BTreeSet<usize>,
}

pub(super) struct Delivery {
    state: Mutex<State>,
    changed: Condvar,
    cancellation: ReadCancellation,
    pub(super) used: Arc<AtomicU64>,
}

struct Lease {
    source: Option<EntrySource>,
    size: u64,
    used: Arc<AtomicU64>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        drop(self.source.take());
        self.used.fetch_sub(self.size, Ordering::AcqRel);
    }
}

struct Reader {
    reader: Box<dyn crate::EntryReader>,
    _lease: Arc<Lease>,
}
impl Read for Reader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(bytes)
    }
}
impl Seek for Reader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.reader.seek(position)
    }
}
struct Source {
    index: usize,
    size: u64,
    delivery: Arc<Delivery>,
}
impl SourceFactory for Source {
    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }
    fn open(&self) -> Result<Box<dyn crate::EntryReader>> {
        let mut state = self.delivery.state.lock().unwrap();
        state.requested = Some(
            state
                .requested
                .map_or(self.index, |index| index.max(self.index)),
        );
        self.delivery.changed.notify_all();
        loop {
            if let Some(error) = &state.error {
                return Err(error.clone());
            }
            if self.delivery.cancellation.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if let Some(lease) = state.ready.get(&self.index).cloned() {
                drop(state);
                return Ok(Box::new(Reader {
                    reader: lease.source.as_ref().expect("live lease").open()?,
                    _lease: lease,
                }));
            }
            if state.published.contains(&self.index) {
                return Err(Error::WriterFailure("rewrite source already consumed"));
            }
            if state.done || self.delivery.cancellation.is_cancelled() {
                return Err(Error::Cancelled);
            }
            state = self.delivery.changed.wait(state).unwrap();
        }
    }
    fn release(&self) {
        self.delivery
            .state
            .lock()
            .unwrap()
            .ready
            .remove(&self.index);
        self.delivery.changed.notify_all();
    }
}

impl Delivery {
    pub(super) fn wait_for(&self, index: usize) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        while state.requested.is_none_or(|requested| requested < index) {
            if self.cancellation.is_cancelled() {
                return Err(Error::Cancelled);
            }
            state = self
                .changed
                .wait_timeout(state, std::time::Duration::from_millis(50))
                .unwrap()
                .0;
        }
        if self.cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
    pub(super) fn publish(&self, index: usize, source: EntrySource) -> Result<()> {
        let size = source.len()?;
        if self.cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let mut state = self.state.lock().unwrap();
        state.published.insert(index);
        state.ready.insert(
            index,
            Arc::new(Lease {
                source: Some(source),
                size,
                used: self.used.clone(),
            }),
        );
        self.changed.notify_all();
        Ok(())
    }
}

struct StopOnDrop(Arc<Delivery>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancellation.cancel();
        self.0.state.lock().unwrap().ready.clear();
        self.0.changed.notify_all();
    }
}

pub(super) fn run<T>(
    archive: &Archive,
    indices: &[usize],
    options: ArchiveReadOptions<'_>,
    staging: &RewriteStaging,
    progress: Option<Arc<dyn crate::WriteProgress>>,
    consume: impl FnOnce(Vec<EntrySource>) -> Result<T>,
) -> Result<T> {
    options.check_cancelled()?;
    let delivery = Arc::new(Delivery {
        state: Mutex::new(State::default()),
        changed: Condvar::new(),
        cancellation: options
            .cancellation
            .map_or_else(ReadCancellation::new, ReadCancellation::child),
        used: Arc::new(AtomicU64::new(0)),
    });
    let sizes: BTreeMap<_, _> = archive
        .members()
        .enumerate()
        .map(|(i, member)| (i, member.meta.unpacked_size))
        .collect();
    let sources = indices
        .iter()
        .map(|&index| {
            let size = *sizes.get(&index).ok_or(Error::EntryNotFound)?;
            Ok(EntrySource::from_factory(Source {
                index,
                size,
                delivery: delivery.clone(),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    std::thread::scope(|scope| {
        let worker = &delivery;
        let decoder = scope.spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::native::stage(
                    archive,
                    indices,
                    options.with_cancellation(&worker.cancellation),
                    staging,
                    progress,
                    Some(worker),
                )
            }))
            .unwrap_or(Err(Error::WriterFailure("rewrite decoder thread panicked")));
            let mut state = worker.state.lock().unwrap();
            state.error = result.as_ref().err().cloned();
            state.done = true;
            worker.changed.notify_all();
            result.map(|_| ())
        });
        // Unwind, writer failure and unused sources must all wake a waiting decoder.
        let guard = StopOnDrop(delivery.clone());
        let result = consume(sources);
        let requested = delivery.state.lock().unwrap().requested;
        if result.is_err() || requested != indices.iter().copied().max() {
            delivery.cancellation.cancel();
            delivery.changed.notify_all();
        }
        let decoded = decoder
            .join()
            .map_err(|_| Error::WriterFailure("rewrite decoder thread panicked"))?;
        drop(guard);
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                match decoded {
                    Err(Error::Cancelled) if requested != indices.iter().copied().max() => {}
                    other => other?,
                }
                Ok(value)
            }
        }
    })
}
