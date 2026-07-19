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
}
