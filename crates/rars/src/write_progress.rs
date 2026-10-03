pub(crate) use crate::progress::ProgressReporter;
use crate::progress::{WriteOperation, WriteProgress, WriteProgressEvent};

pub(crate) struct WorkTracker<'a> {
    progress: Option<ProgressReporter<'a>>,
    operation: WriteOperation,
    total: u64,
    state: Mutex<WorkState>,
}

#[derive(Default)]
struct WorkState {
    completed: u64,
}

impl<'a> WorkTracker<'a> {
    pub(crate) fn reporter(&self) -> Option<ProgressReporter<'a>> {
        self.progress
    }

    pub(crate) fn check(&self) -> crate::Result<()> {
        check_cancelled(self.progress)
    }
    pub(crate) fn new(
        progress: Option<ProgressReporter<'a>>,
        operation: WriteOperation,
        total: u64,
    ) -> Self {
        Self {
            progress,
            operation,
            total,
            state: Mutex::new(WorkState::default()),
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.progress.is_some_and(ProgressReporter::is_cancelled)
    }

    pub(crate) fn advance(&self, amount: u64) -> bool {
        let Some(progress) = self.progress else {
            return true;
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.completed = state.completed.saturating_add(amount).min(self.total);
        progress.report(WriteProgressEvent::Advanced {
            operation: self.operation,
            completed_bytes: state.completed,
            total_bytes: self.total,
            pass: 1,
        });
        !progress.is_cancelled()
    }

    pub(crate) fn finish(&self) -> bool {
        let completed = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .completed;
        self.advance(self.total.saturating_sub(completed))
    }

    pub(crate) fn entry_started(
        &self,
        index: usize,
        total_entries: usize,
        name: &[u8],
        input_bytes: u64,
    ) {
        if let Some(progress) = self.progress {
            progress.report(WriteProgressEvent::EntryStarted {
                operation: self.operation,
                index,
                total_entries,
                name,
                input_bytes,
            });
        }
    }

    pub(crate) fn entry_finished(
        &self,
        index: usize,
        total_entries: usize,
        name: &[u8],
        input_bytes: u64,
    ) {
        if let Some(progress) = self.progress {
            progress.report(WriteProgressEvent::EntryFinished {
                operation: self.operation,
                index,
                total_entries,
                name,
                input_bytes,
            });
        }
    }
}
use std::sync::Mutex;

/// Combine cancellation policy with optional presentation for one write.
pub(crate) struct ResourceProgress<'a> {
    resources: &'a crate::WriterResources,
    inner: Option<ProgressReporter<'a>>,
    cancelled: std::sync::atomic::AtomicBool,
}
impl<'a> ResourceProgress<'a> {
    pub(crate) fn new(
        resources: &'a crate::WriterResources,
        inner: Option<ProgressReporter<'a>>,
    ) -> Self {
        Self {
            resources,
            inner,
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl WriteProgress for ResourceProgress<'_> {
    fn report(&self, event: WriteProgressEvent<'_>) {
        if let Some(inner) = self.inner {
            inner.report(event);
        }
    }
    fn is_cancelled(&self) -> bool {
        use std::sync::atomic::Ordering;
        if self.cancelled.load(Ordering::Relaxed)
            || self.resources.is_cancelled()
            || self.inner.is_some_and(ProgressReporter::is_cancelled)
        {
            self.cancelled.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

pub(crate) fn check_cancelled(progress: Option<ProgressReporter<'_>>) -> crate::Result<()> {
    if progress.is_some_and(ProgressReporter::is_cancelled) {
        Err(crate::Error::Cancelled)
    } else {
        Ok(())
    }
}

/// Preserve typed cancellation through APIs which can only return I/O errors.
/// Never use ErrorKind::Interrupted: write_all/read_exact would retry forever.
pub(crate) struct CancellableIo<'a, T> {
    pub(crate) inner: T,
    pub(crate) progress: Option<ProgressReporter<'a>>,
}
impl<T> CancellableIo<'_, T> {
    fn check(&self) -> std::io::Result<()> {
        check_cancelled(self.progress).map_err(std::io::Error::other)
    }
}
impl<T: std::io::Read> std::io::Read for CancellableIo<'_, T> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.check()?;
        let len = if self.progress.is_some() {
            buffer.len().min(64 * 1024)
        } else {
            buffer.len()
        };
        self.inner.read(&mut buffer[..len])
    }
}
impl<T: std::io::Write> std::io::Write for CancellableIo<'_, T> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.check()?;
        let len = if self.progress.is_some() {
            buffer.len().min(64 * 1024)
        } else {
            buffer.len()
        };
        self.inner.write(&buffer[..len])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}
impl<T: std::io::Seek> std::io::Seek for CancellableIo<'_, T> {
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        self.check()?;
        self.inner.seek(from)
    }
}

#[cfg(test)]
#[test]
fn callback_panic_keeps_peer_progress_and_completion_usable() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let panic_once = AtomicBool::new(true);
    let reported = Mutex::new(Vec::new());
    let callback = |event: WriteProgressEvent<'_>| {
        if let WriteProgressEvent::Advanced {
            completed_bytes, ..
        } = event
        {
            if panic_once.swap(false, Ordering::Relaxed) {
                panic!("injected progress callback panic");
            }
            reported.lock().unwrap().push(completed_bytes);
        }
    };
    let work = WorkTracker::new(
        Some(ProgressReporter(&callback)),
        WriteOperation::Compression,
        10,
    );
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| work.advance(3));
        assert!(worker.join().is_err());
        let peer = scope.spawn(|| work.advance(2));
        assert!(peer.join().unwrap());
    });
    assert!(work.finish());
    assert_eq!(*reported.lock().unwrap(), [5, 10]);
}

/// Count accepted output without buffering an archive or guessing its final size.
pub(crate) struct EmissionWriter<'a> {
    output: &'a mut dyn std::io::Write,
    progress: Option<ProgressReporter<'a>>,
    completed: u64,
    reported: u64,
    started: bool,
}
impl<'a> EmissionWriter<'a> {
    pub(crate) fn new(
        output: &'a mut dyn std::io::Write,
        progress: Option<ProgressReporter<'a>>,
    ) -> Self {
        Self {
            output,
            progress,
            completed: 0,
            reported: 0,
            started: false,
        }
    }
    fn start(&mut self) -> crate::Result<()> {
        check_cancelled(self.progress)?;
        if !self.started {
            self.started = true;
            if let Some(progress) = self.progress {
                progress.report(WriteProgressEvent::OperationStarted {
                    operation: WriteOperation::Emission,
                    total_bytes: None,
                    total_entries: None,
                    pass: 1,
                });
            }
        }
        check_cancelled(self.progress)
    }
    fn advance(&mut self) -> crate::Result<()> {
        if self.completed != self.reported {
            self.reported = self.completed;
            if let Some(progress) = self.progress {
                progress.report(WriteProgressEvent::BytesWritten {
                    completed_bytes: self.completed,
                });
            }
        }
        check_cancelled(self.progress)
    }
    pub(crate) fn finish(&mut self) -> crate::Result<()> {
        self.start()?;
        self.advance()?;
        if let Some(progress) = self.progress {
            progress.report(WriteProgressEvent::OperationFinished {
                operation: WriteOperation::Emission,
                total_bytes: Some(self.completed),
                total_entries: None,
                pass: 1,
            });
        }
        check_cancelled(self.progress)
    }
}
impl std::io::Write for EmissionWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.start().map_err(std::io::Error::other)?;
        let written = self.output.write(&bytes[..bytes.len().min(64 * 1024)])?;
        self.completed += written as u64;
        if self.completed - self.reported >= 64 * 1024 {
            self.advance().map_err(std::io::Error::other)?;
        }
        check_cancelled(self.progress).map_err(std::io::Error::other)?;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        check_cancelled(self.progress).map_err(std::io::Error::other)?;
        self.output.flush()
    }
}
