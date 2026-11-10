use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

use crate::codec::workspace::Budget;

const INLINE_LIMIT: u64 = 256 << 10;
const CHUNK: usize = 1 << 20;
const BUFFERS: usize = 4;

#[derive(Debug)]
pub(crate) enum PipeError<E> {
    Produce(E),
    Write(std::io::Error),
}

/// The pooled buffers' charge when a member of `size` bytes should be pipelined, or None to run inline.
pub(crate) fn admit<B: Budget>(size: u64, allowance: &B) -> Option<B::Charge> {
    if size <= INLINE_LIMIT || !crate::parallel::may_spawn() {
        return None;
    }
    let mut charge = allowance.charge();
    B::resize(&mut charge, (CHUNK * BUFFERS) as u64).ok()?;
    Some(charge)
}

/// The producer's side: fills pooled buffers and hands each full one to the writer and the checksum.
pub(crate) struct Chunks<'a> {
    buffer: Vec<u8>,
    filled: usize,
    allocated: usize,
    stop: &'a AtomicBool,
    spare: mpsc::Receiver<Vec<u8>>,
    check: mpsc::SyncSender<Arc<Vec<u8>>>,
    full: mpsc::SyncSender<Arc<Vec<u8>>>,
}

impl Chunks<'_> {
    /// The unfilled rest of the current buffer; fails once the writer has stopped.
    pub(crate) fn space(&mut self) -> std::io::Result<&mut [u8]> {
        if self.buffer.is_empty() {
            self.buffer = match self.spare.try_recv() {
                Ok(buffer) => buffer,
                Err(_) if self.allocated < BUFFERS => {
                    self.allocated += 1;
                    Vec::new()
                }
                Err(_) => self.spare.recv().map_err(|_| stopped())?,
            };
            self.buffer.resize(CHUNK, 0);
        }
        if self.stop.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        Ok(&mut self.buffer[self.filled..])
    }

    pub(crate) fn commit(&mut self, count: usize) -> std::io::Result<()> {
        self.filled += count;
        if self.filled == CHUNK {
            self.send()?;
        }
        Ok(())
    }

    pub(crate) fn push(&mut self, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let space = self.space()?;
            let take = space.len().min(bytes.len());
            space[..take].copy_from_slice(&bytes[..take]);
            self.commit(take)?;
            bytes = &bytes[take..];
        }
        Ok(())
    }

    pub(crate) fn push_repeated(&mut self, byte: u8, mut len: usize) -> std::io::Result<()> {
        while len > 0 {
            let space = self.space()?;
            let take = space.len().min(len);
            space[..take].fill(byte);
            self.commit(take)?;
            len -= take;
        }
        Ok(())
    }

    fn send(&mut self) -> std::io::Result<()> {
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.truncate(std::mem::take(&mut self.filled));
        if buffer.is_empty() {
            return Ok(());
        }
        let chunk = Arc::new(buffer);
        if self.check.send(chunk.clone()).is_err() || self.full.send(chunk).is_err() {
            return Err(stopped());
        }
        Ok(())
    }
}

fn stopped() -> std::io::Error {
    std::io::Error::other("member output stopped")
}

/// Produces and checksums off the caller, which writes; a write failure wins because the producer only sees the stop it causes.
pub(crate) fn run<T, E, P, C>(
    produce: P,
    check: &mut C,
    writer: &mut dyn Write,
) -> Result<T, PipeError<E>>
where
    T: Send,
    E: Send,
    P: FnOnce(&mut Chunks<'_>) -> Result<T, E> + Send,
    C: FnMut(&[u8]) + Send,
{
    let stop = AtomicBool::new(false);
    let (spare_tx, spare_rx) = mpsc::sync_channel::<Vec<u8>>(BUFFERS);
    let (full_tx, full_rx) = mpsc::sync_channel::<Arc<Vec<u8>>>(BUFFERS);
    let (check_tx, check_rx) = mpsc::sync_channel::<Arc<Vec<u8>>>(BUFFERS);
    let give_back = |chunk: Arc<Vec<u8>>, spare: &mpsc::SyncSender<Vec<u8>>| {
        if let Some(buffer) = Arc::into_inner(chunk) {
            let _ = spare.send(buffer);
        }
    };

    std::thread::scope(|scope| {
        let stop = &stop;
        let producer = scope.spawn(move || {
            let mut chunks = Chunks {
                buffer: Vec::new(),
                filled: 0,
                allocated: 0,
                stop,
                spare: spare_rx,
                check: check_tx,
                full: full_tx,
            };
            let result = produce(&mut chunks);
            let _ = chunks.send();
            result
        });
        let spare = spare_tx.clone();
        scope.spawn(move || {
            for chunk in check_rx {
                check(&chunk);
                give_back(chunk, &spare);
            }
        });

        let mut outcome = Ok(());
        let mut writer_panic = None;
        for chunk in full_rx {
            if outcome.is_ok() && writer_panic.is_none() {
                // A panicking writer must keep draining, or a producer waiting for a spare never wakes.
                let written = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    writer.write_all(&chunk)
                }));
                match written {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => outcome = Err(error),
                    Err(panic) => writer_panic = Some(panic),
                }
                if outcome.is_err() || writer_panic.is_some() {
                    stop.store(true, Ordering::Relaxed);
                }
            }
            give_back(chunk, &spare_tx);
        }
        let produced = producer.join();
        if let Some(panic) = writer_panic {
            std::panic::resume_unwind(panic);
        }
        let produced = produced.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        outcome.map_err(PipeError::Write)?;
        produced.map_err(PipeError::Produce)
    })
}
