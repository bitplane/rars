/// A high-level archive-writing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteOperation {
    /// Compressing or otherwise preparing member payloads.
    Compression,
    /// Building a RAR 5 recovery record.
    Recovery,
    /// Writing finished archive bytes to the output.
    Emission,
}

/// Progress reported by archive writers.
///
/// Callbacks can be invoked concurrently when parallel compression is enabled.
/// Each member starts before its source is consumed and finishes after its packed
/// payload is prepared. Different members may overlap. `Advanced` is the absolute
/// byte counter; entry events must not be added to it. A failed operation does not
/// report `OperationFinished`. Emission can contain recovery sub-operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteProgressEvent<'a> {
    /// An operation has started.
    OperationStarted {
        operation: WriteOperation,
        total_bytes: Option<u64>,
        total_entries: Option<usize>,
        pass: usize,
    },
    /// Work on one archive member has started.
    EntryStarted {
        operation: WriteOperation,
        index: usize,
        total_entries: usize,
        name: &'a [u8],
        input_bytes: u64,
    },
    /// Work on one archive member has finished.
    EntryFinished {
        operation: WriteOperation,
        index: usize,
        total_entries: usize,
        name: &'a [u8],
        input_bytes: u64,
    },
    /// Absolute progress within the current operation or pass.
    Advanced {
        operation: WriteOperation,
        completed_bytes: u64,
        total_bytes: u64,
        pass: usize,
    },
    /// One volume of a multi-volume set has been written out.
    VolumeFinished {
        volume_number: usize,
        total_volumes: Option<usize>,
        bytes: u64,
    },
    /// An operation has finished.
    OperationFinished {
        operation: WriteOperation,
        total_bytes: Option<u64>,
        total_entries: Option<usize>,
        pass: usize,
    },
}

/// Receives archive-writing progress events.
pub trait WriteProgress: Send + Sync {
    fn report(&self, event: WriteProgressEvent<'_>);

    /// Returns true when the caller wants the active write operation to stop.
    /// RAR5/7 streaming writes retain an observed request for the rest of the write.
    fn is_cancelled(&self) -> bool {
        false
    }
}

impl<F> WriteProgress for F
where
    F: Fn(WriteProgressEvent<'_>) + Send + Sync,
{
    fn report(&self, event: WriteProgressEvent<'_>) {
        self(event);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProgressReporter<'a>(pub(crate) &'a dyn WriteProgress);

impl std::fmt::Debug for ProgressReporter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProgressReporter(..)")
    }
}

impl ProgressReporter<'_> {
    pub(crate) fn report(self, event: WriteProgressEvent<'_>) {
        self.0.report(event);
    }

    pub(crate) fn is_cancelled(self) -> bool {
        self.0.is_cancelled()
    }
}

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
