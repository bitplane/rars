/// A high-level archive-writing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteOperation {
    /// Compressing or otherwise preparing member payloads.
    Compression,
    /// Building a RAR 5 recovery record.
    Recovery,
}

/// Progress reported by archive writers.
///
/// Callbacks can be invoked concurrently when parallel compression is enabled.
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

    pub(crate) fn is_cancelled(&self) -> bool {
        self.progress.is_some_and(ProgressReporter::is_cancelled)
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
