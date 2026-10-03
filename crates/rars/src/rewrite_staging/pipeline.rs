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
    max_preparation_window: usize,
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
    fn max_preparation_window(&self) -> usize {
        self.delivery.max_preparation_window
    }
    fn len(&self) -> Result<u64> {
        Ok(self.size)
    }
    fn open(&self) -> Result<Box<dyn crate::EntryReader>> {
        self.open_with_cancellation(|| self.delivery.cancellation.is_cancelled())
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

impl Source {
    fn open_with_cancellation(
        &self,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Box<dyn crate::EntryReader>> {
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
            if is_cancelled() {
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
            if state.done || is_cancelled() {
                return Err(Error::Cancelled);
            }
            state = self.delivery.changed.wait(state).unwrap();
        }
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
    let sizes: BTreeMap<_, _> = archive
        .members()
        .enumerate()
        .map(|(i, member)| (i, member.meta.unpacked_size))
        .collect();
    // A preparation window can retain every source until its members are emitted.
    // Bound it by the largest selected payload so even mixed-size windows fit.
    let largest = indices
        .iter()
        .filter_map(|index| sizes.get(index))
        .copied()
        .max()
        .unwrap_or(0);
    let max_preparation_window = usize::try_from(staging.max_staged_bytes / largest.max(1))
        .unwrap_or(usize::MAX)
        .max(1);
    let delivery = Arc::new(Delivery {
        state: Mutex::new(State::default()),
        changed: Condvar::new(),
        cancellation: options
            .cancellation
            .map_or_else(ReadCancellation::new, ReadCancellation::child),
        used: Arc::new(AtomicU64::new(0)),
        max_preparation_window,
    });
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
                finish_decoder(decoded, requested != indices.iter().copied().max())?;
                Ok(value)
            }
        }
    })
}

fn finish_decoder(decoded: Result<()>, unused_sources: bool) -> Result<()> {
    match decoded {
        // Stopping an unused source can race with entry selection, which adds
        // context to cancellation. Its category is unchanged by that context.
        Err(error) if unused_sources && error.kind() == crate::ErrorKind::Cancelled => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn unused_source_shutdown_accepts_contextual_cancellation_only() {
        let cancelled = Error::AtEntry {
            name: b"file".to_vec(),
            operation: "selecting",
            source: Box::new(Error::Cancelled),
        };
        assert_eq!(finish_decoder(Err(cancelled.clone()), true), Ok(()));
        assert_eq!(
            finish_decoder(Err(cancelled.clone()), false),
            Err(cancelled)
        );
        let error = Error::InvalidArgument("decoder refused");
        assert_eq!(finish_decoder(Err(error.clone()), true), Err(error));
    }

    struct CancelAtStagingFinish(AtomicBool);

    impl crate::WriteProgress for CancelAtStagingFinish {
        fn report(&self, event: crate::WriteProgressEvent<'_>) {
            if matches!(
                event,
                crate::WriteProgressEvent::OperationFinished {
                    operation: crate::WriteOperation::Staging,
                    ..
                }
            ) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn delivery() -> Arc<Delivery> {
        Arc::new(Delivery {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            cancellation: ReadCancellation::new(),
            used: Arc::new(AtomicU64::new(0)),
            max_preparation_window: usize::MAX,
        })
    }

    #[test]
    fn rewrite_source_reopens_a_live_lease_and_refuses_a_consumed_one() {
        let delivery = delivery();
        delivery.used.store(6, Ordering::Relaxed);
        delivery.state.lock().unwrap().ready.insert(
            0,
            Arc::new(Lease {
                source: Some(EntrySource::from_bytes(b"abcdef".to_vec())),
                size: 6,
                used: delivery.used.clone(),
            }),
        );
        let source = Source {
            index: 0,
            size: 6,
            delivery: delivery.clone(),
        };
        let mut reader = source.open().unwrap();
        assert_eq!(reader.seek(SeekFrom::Start(3)).unwrap(), 3);
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).unwrap();
        assert_eq!(suffix, b"def");
        delivery.wait_for(0).unwrap();
        source.release();
        assert_eq!(delivery.used.load(Ordering::Relaxed), 6);
        drop(reader);
        assert_eq!(delivery.used.load(Ordering::Relaxed), 0);
        delivery.state.lock().unwrap().published.insert(0);
        assert!(matches!(
            source.open(),
            Err(Error::WriterFailure("rewrite source already consumed"))
        ));
        delivery.state.lock().unwrap().published.clear();
        delivery.state.lock().unwrap().done = true;
        assert!(matches!(source.open(), Err(Error::Cancelled)));
    }

    #[test]
    fn cancelled_delivery_refuses_waits_opens_and_publication() {
        let delivery = delivery();
        delivery.cancellation.cancel();
        let source = Source {
            index: 0,
            size: 1,
            delivery: delivery.clone(),
        };
        assert!(matches!(delivery.wait_for(1), Err(Error::Cancelled)));
        assert!(matches!(source.open(), Err(Error::Cancelled)));
        assert!(matches!(delivery.wait_for(0), Err(Error::Cancelled)));
        assert!(matches!(
            delivery.publish(0, EntrySource::from_bytes(b"x".to_vec())),
            Err(Error::Cancelled)
        ));
        assert_eq!(delivery.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancellation_between_observations_refuses_to_wait_for_a_source() {
        let delivery = delivery();
        let source = Source {
            index: 0,
            size: 1,
            delivery: delivery.clone(),
        };
        let mut observations = 0;
        let result = source.open_with_cancellation(|| {
            let cancelled = delivery.cancellation.is_cancelled();
            observations += 1;
            if observations == 1 {
                // Model cancellation after the first atomic load returned false.
                delivery.cancellation.cancel();
            }
            cancelled
        });
        assert!(matches!(result, Err(Error::Cancelled)));
        assert_eq!(observations, 2);
        let state = delivery.state.lock().unwrap();
        assert_eq!(state.requested, Some(0));
        assert!(!state.done);
        assert!(state.ready.is_empty());
        assert!(state.published.is_empty());
        assert_eq!(delivery.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn published_source_delivers_bytes_and_releases_its_charge() {
        let delivery = delivery();
        let source = Source {
            index: 0,
            size: 7,
            delivery: delivery.clone(),
        };
        assert_eq!(source.len().unwrap(), 7);
        // Native staging charges the bytes before publishing the lease.
        delivery.used.store(7, Ordering::Relaxed);
        delivery
            .publish(0, EntrySource::from_bytes(b"payload".to_vec()))
            .unwrap();
        let mut reader = source.open().unwrap();
        delivery.wait_for(0).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"payload");
        source.release();
        assert_eq!(delivery.used.load(Ordering::Relaxed), 7);
        drop(reader);
        assert_eq!(delivery.used.load(Ordering::Relaxed), 0);
        assert!(matches!(
            source.open(),
            Err(Error::WriterFailure("rewrite source already consumed"))
        ));
    }

    #[test]
    fn writer_that_never_opens_its_rewrite_source_stops_the_decoder() {
        let root = crate::scratch::case("rewrite-unused-source");
        let mut builder = crate::Builder::new(crate::ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let archive = crate::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let staging = RewriteStaging {
            directory: root.to_path_buf(),
            max_staged_bytes: 7,
        };

        let value = run(
            &archive,
            &[0],
            ArchiveReadOptions::default(),
            &staging,
            None,
            |sources| {
                assert_eq!(sources.len(), 1);
                Ok(17)
            },
        )
        .unwrap();
        assert_eq!(value, 17);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);

        assert_eq!(
            run(
                &archive,
                &[0],
                ArchiveReadOptions::default(),
                &staging,
                None,
                |_sources| -> Result<()> { Err(Error::InvalidArgument("writer refused")) },
            )
            .unwrap_err(),
            Error::InvalidArgument("writer refused")
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn cancellation_after_final_source_request_reaches_writer() {
        let root = crate::scratch::case("rewrite-final-request-cancelled");
        let mut builder = crate::Builder::new(crate::ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let archive = crate::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let staging = RewriteStaging {
            directory: root.to_path_buf(),
            max_staged_bytes: 7,
        };
        let progress = Arc::new(CancelAtStagingFinish(AtomicBool::new(false)));

        let result = run(
            &archive,
            &[0],
            ArchiveReadOptions::default(),
            &staging,
            Some(progress.clone()),
            |sources| {
                let error = sources[0].open().err().expect("staging should cancel");
                assert_eq!(error.kind(), crate::ErrorKind::Cancelled, "{error:?}");
                Ok(17)
            },
        );
        assert!(progress.0.load(Ordering::Relaxed));
        assert_eq!(result.unwrap_err(), Error::Cancelled);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }
}
