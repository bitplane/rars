//! Cooperative reader cancellation, with observation local to an operation.
use crate::{Error, Result};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// A shared one-way cancellation signal for archive readers.
/// Clone the token to cancel from another thread or an input/output callback.
/// Supply it through [`crate::ArchiveReadOptions::with_cancellation`]. A token
/// cannot be reset; create a new one for another operation after cancellation.
/// Parsing does not retain the token or apply it to later extraction.
///
/// Readers check before starting work, between headers and members, around
/// output callbacks, during bounded reads/writes, and periodically in decoder,
/// filter and VM loops. Parallel extraction joins admitted workers before
/// returning; workers check the signal before decoding and during codec work.
///
/// Cancellation is cooperative, without a wall-clock deadline. Blocked caller
/// I/O, key derivation, allocation, copies and individual checksum/crypto library
/// operations cannot be preempted. Once observed, cancellation returns
/// [`Error::Cancelled`] (possibly with entry/volume context). An unrelated error
/// is not replaced merely because the signal was set concurrently.
///
/// Partial output and earlier extracted members can remain. The call aborts;
/// it does not resume solid state, roll back sinks or refund output budgets.
#[derive(Clone, Debug, Default)]
pub struct ReadCancellation(Arc<AtomicBool>);

impl ReadCancellation {
    /// Creates an uncancelled signal.
    pub fn new() -> Self {
        Self::default()
    }
    /// Signals cancellation to every clone. Calling this repeatedly is harmless.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    /// Returns whether any clone has signalled cancellation.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ReadControl(Option<Arc<Observation>>);

#[derive(Debug)]
struct Observation {
    token: ReadCancellation,
    observed: AtomicBool,
    #[cfg(test)]
    checks_remaining: std::sync::atomic::AtomicUsize,
}

impl ReadControl {
    pub(crate) fn is_enabled(&self) -> bool {
        self.0.is_some()
    }
    pub(crate) fn new(token: Option<&ReadCancellation>) -> Self {
        Self(token.map(|token| {
            Arc::new(Observation {
                token: token.clone(),
                observed: AtomicBool::new(false),
                #[cfg(test)]
                checks_remaining: std::sync::atomic::AtomicUsize::new(usize::MAX),
            })
        }))
    }
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(state) = &self.0 {
            #[cfg(test)]
            if state
                .checks_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n != usize::MAX).then(|| n.saturating_sub(1))
                })
                == Ok(0)
            {
                state.token.cancel();
            }
            if state.token.is_cancelled() {
                state.observed.store(true, Ordering::Relaxed);
                return Err(Error::Cancelled);
            }
        }
        Ok(())
    }
    /// Test-only checkpoint scheduling avoids races and wall-clock sleeps.
    #[cfg(test)]
    pub(crate) fn cancel_after_checks(&self, successful_checks: usize) {
        self.0
            .as_ref()
            .expect("configured token")
            .checks_remaining
            .store(successful_checks, Ordering::Relaxed);
    }
    pub(crate) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        // Do not turn a real error into cancellation just because the token was
        // signalled later. Restore only cancellation actually observed by this work.
        if self
            .0
            .as_ref()
            .is_some_and(|s| s.observed.load(Ordering::Relaxed))
        {
            match result {
                Err(e) if e.kind() == crate::ErrorKind::Cancelled => Err(e),
                _ => Err(Error::Cancelled),
            }
        } else {
            result
        }
    }
    pub(crate) fn check_codec(&self) -> crate::codec::Result<()> {
        self.check().map_err(|_| crate::codec::Error::Cancelled)
    }
    pub(crate) fn reader<R>(&self, reader: R) -> ControlledReader<R> {
        ControlledReader {
            reader,
            control: self.clone(),
        }
    }
    pub(crate) fn write_all(&self, writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
        if !self.is_enabled() {
            return writer.write_all(bytes);
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            self.check().map_err(io::Error::other)?;
            match writer.write(&remaining[..remaining.len().min(64 * 1024)]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => remaining = &remaining[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        self.check().map_err(io::Error::other)
    }
    pub(crate) fn poller(&self) -> Poller {
        Poller {
            control: self.clone(),
            steps: 0,
            next_position: 0,
        }
    }
}

pub(crate) struct ControlledReader<R> {
    reader: R,
    control: ReadControl,
}
impl<R: Read> Read for ControlledReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.control.0.is_none() {
            return self.reader.read(bytes);
        }
        self.control.check().map_err(io::Error::other)?;
        let len = bytes.len().min(64 * 1024);
        self.reader.read(&mut bytes[..len])
    }
}
impl<R: Seek> Seek for ControlledReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.control.check().map_err(io::Error::other)?;
        self.reader.seek(pos)
    }
}

pub(crate) struct Poller {
    control: ReadControl,
    steps: usize,
    next_position: usize,
}
impl Poller {
    // Bound both no-output symbol work and runs that expand large matches.
    pub(crate) fn check(&mut self, position: usize) -> Result<()> {
        if self.control.0.is_none() {
            return Ok(());
        }
        if self.steps == 0 || position >= self.next_position {
            self.control.check()?;
            self.steps = 4096;
            self.next_position = position.saturating_add(64 * 1024);
        }
        self.steps -= 1;
        Ok(())
    }
    pub(crate) fn check_codec(&mut self, position: usize) -> crate::codec::Result<()> {
        self.check(position)
            .map_err(|_| crate::codec::Error::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_observation_is_local_and_survives_error_adapters() {
        let token = ReadCancellation::new();
        let observed = ReadControl::new(Some(&token));
        let unrelated = ReadControl::new(Some(&token));
        token.clone().cancel();
        assert!(observed.check().is_err());
        assert_eq!(
            observed
                .finish::<()>(Err(Error::WrongPasswordOrCorruptData))
                .unwrap_err()
                .kind(),
            crate::ErrorKind::Cancelled
        );
        assert!(matches!(
            unrelated.finish::<()>(Err(Error::WrongPasswordOrCorruptData)),
            Err(Error::WrongPasswordOrCorruptData)
        ));
    }

    #[test]
    fn reader_bounds_reads_and_preserves_the_cancellation_sentinel() {
        struct Source {
            token: ReadCancellation,
            calls: usize,
        }
        impl Read for Source {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                assert!(bytes.len() <= 64 * 1024);
                self.token.cancel();
                bytes.fill(42);
                Ok(bytes.len())
            }
        }
        let token = ReadCancellation::new();
        let control = ReadControl::new(Some(&token));
        let mut source = Source { token, calls: 0 };
        let mut reader = control.reader(&mut source);
        let mut bytes = vec![0; 128 * 1024];
        assert_eq!(reader.read(&mut bytes).unwrap(), 64 * 1024);
        let err = Error::from(reader.read(&mut bytes).unwrap_err());
        assert_eq!(err.kind(), crate::ErrorKind::Cancelled);
        assert_eq!(source.calls, 1);
    }

    #[test]
    fn polling_bounds_both_output_and_no_output_work() {
        for output in [false, true] {
            let token = ReadCancellation::new();
            let control = ReadControl::new(Some(&token));
            control.cancel_after_checks(1);
            let mut poller = control.poller();
            poller.check(0).unwrap();
            if output {
                assert!(poller.check(64 * 1024).is_err());
            } else {
                for _ in 1..4096 {
                    poller.check(0).unwrap();
                }
                assert!(poller.check(0).is_err());
            }
        }
    }
}
