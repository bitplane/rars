//! Progress events shared by archive writing and recovery generation.

/// A high-level archive-writing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteOperation {
    /// Decoding and verifying source payloads for a rewrite; may overlap encoding.
    Staging,
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
    /// Writers retain an observed request for the rest of the write.
    /// Cancellation is cooperative: it cannot interrupt a blocked caller I/O
    /// operation or an indivisible allocation or cryptographic setup call.
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

#[cfg(test)]
#[test]
fn progress_reporter_debug_does_not_expose_the_callback() {
    let callback = |_event: WriteProgressEvent<'_>| {};
    assert_eq!(
        format!("{:?}", ProgressReporter(&callback)),
        "ProgressReporter(..)"
    );
}
