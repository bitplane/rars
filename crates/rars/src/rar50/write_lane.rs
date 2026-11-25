use super::{Archive, DecoderSession, ExtractedEntryMeta, FileHeader, Redirections, Settling};
use crate::codec::rar50::HistoryRetention;
use crate::codec::workspace::{Budget, Buffer};
use crate::error::{Error, Result};
use crate::output_limit::OutputBudget;
use crate::read_control::ReadControl;
use std::io::Write;
use std::sync::mpsc;
use std::thread::JoinHandle;

// As `LimitedWriter` cuts writes when a control can cancel them.
const CONTROLLED_WRITE: usize = 64 * 1024;

/// How a member's write ended, told apart as `LimitedWriter` tells it.
enum Outcome {
    Written,
    Sink(std::io::Error),
    Cancelled,
}

struct Job<B: Budget> {
    writer: Box<dyn Write + Send>,
    data: Buffer<u8, B>,
    /// The member passed its checks, so its writer is flushed once written.
    verified: bool,
}

struct Done {
    outcome: Outcome,
    // Seen as the write ended, where writing in place would have looked.
    cancelled: bool,
}

/// A member decoded on the calling thread while the one before it is written.
pub(super) struct Decoded<'f, B: Budget> {
    file: &'f FileHeader,
    // False when the member failed the checks made before its output opens.
    opens: bool,
    decoded: Result<(Buffer<u8, B>, Result<()>)>,
}

struct Pending<'f> {
    file: &'f FileHeader,
    meta: ExtractedEntryMeta,
    verified: Result<()>,
}

/// Writes each buffered solid member on its own thread so its successor decodes meanwhile.
pub(super) struct Lane<'s, 'a, 'f, B: Budget> {
    settling: &'s Settling<'a>,
    jobs: Option<mpsc::Sender<Job<B>>>,
    done: mpsc::Receiver<Done>,
    thread: Option<JoinHandle<()>>,
    pending: Option<Pending<'f>>,
}

impl<'s, 'a, 'f, B: Budget> Lane<'s, 'a, 'f, B> {
    /// Only where outputs can be sent and nothing has to see a write as it happens.
    pub(super) fn start(
        settling: Option<&'s Settling<'a>>,
        selecting: bool,
        options: crate::ArchiveReadOptions<'_>,
        budget: &OutputBudget,
    ) -> Option<Self> {
        let settling = settling.filter(|_| {
            !selecting
                && !options.salvage
                && options.rar50_scratch.is_none()
                && !budget.is_limited()
                && !B::LIMITED
                && crate::parallel::may_spawn()
        })?;
        let control = budget.control.clone();
        let (jobs, queued) = mpsc::channel::<Job<B>>();
        let (finished, done) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("rars-write".into())
            .spawn(move || {
                for Job {
                    mut writer,
                    data,
                    verified,
                } in queued
                {
                    let outcome = write_member(&control, &mut *writer, &data, verified);
                    drop(writer);
                    drop(data);
                    let cancelled = control.check().is_err();
                    if finished.send(Done { outcome, cancelled }).is_err() {
                        return;
                    }
                }
            })
            .ok()?;
        Some(Self {
            settling,
            jobs: Some(jobs),
            done,
            thread: Some(thread),
            pending: None,
        })
    }

    /// Decodes a member that only its write sets apart, before anything about it is seen.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn decode(
        &self,
        archive: &Archive,
        file: &'f FileHeader,
        options: crate::ArchiveReadOptions<'_>,
        redirections: Redirections,
        buffered_decode_limit: u64,
        budget: &OutputBudget,
        session: &mut DecoderSession<'_, B>,
    ) -> Option<Decoded<'f, B>> {
        if file.is_directory()
            || file.is_stored()
            || file.is_split_before()
            || file.is_split_after()
            || file.should_stream_decode(buffered_decode_limit)
            || redirections.redirects(file)
        {
            return None;
        }
        let checked = options.check_cancelled().and_then(|()| {
            file.check_dictionary_limit(options.rar50_dictionary_size_limit)?;
            file.check_output_limit(budget)?;
            options.check_cancelled()
        });
        Some(match checked {
            Err(error) => Decoded {
                file,
                opens: false,
                decoded: Err(error),
            },
            Ok(()) => Decoded {
                file,
                opens: true,
                decoded: session.decode_to_write(archive, file),
            },
        })
    }

    /// Opens a decoded member's output and queues its write; Some when it settled at once.
    pub(super) fn write(
        &mut self,
        decoded: Decoded<'f, B>,
        options: crate::ArchiveReadOptions<'_>,
        budget: &OutputBudget,
    ) -> Option<Result<()>> {
        let Decoded {
            file,
            opens,
            decoded,
        } = decoded;
        if !opens {
            return Some(decoded.map(drop));
        }
        // Settling the member before may have cancelled since this one was checked.
        if let Err(error) = options.check_cancelled() {
            return Some(Err(error));
        }
        let meta = file.metadata();
        let opened = self
            .settling
            .open(&meta)
            .and_then(|writer| options.check_cancelled().map(|()| writer))
            .and_then(|writer| budget.control.check().map(|()| writer));
        let (writer, (data, verified)) = match (opened, decoded) {
            (Err(error), _) => return Some(self.settling.settle(&meta, Err(error))),
            (Ok(writer), Err(error)) => {
                drop(writer);
                let result =
                    budget.conclude(&file.name, None, None, file.cut_short_result(Err(error)));
                return Some(self.settling.settle(&meta, result));
            }
            (Ok(writer), Ok(decoded)) => (writer, decoded),
        };
        let jobs = self.jobs.as_ref().expect("taken only on drop");
        // A send fails only once the thread has gone, which `settle` reports.
        let _ = jobs.send(Job {
            writer,
            data,
            verified: verified.is_ok(),
        });
        self.pending = Some(Pending {
            file,
            meta,
            verified,
        });
        None
    }

    /// The member whose write is queued, once written, with its result as written in place.
    pub(super) fn settle(&mut self, budget: &OutputBudget) -> Option<(&'f FileHeader, Result<()>)> {
        let Pending {
            file,
            meta,
            verified,
        } = self.pending.take()?;
        let Done { outcome, cancelled } = self.wait();
        let result = match outcome {
            Outcome::Written if !cancelled => file.cut_short_result(verified),
            Outcome::Written => budget.conclude(&file.name, None, None, verified),
            Outcome::Sink(error) => budget.conclude(&file.name, None, Some(error.into()), Ok(())),
            Outcome::Cancelled => budget.conclude(&file.name, None, None, Err(Error::Cancelled)),
        };
        Some((file, self.settling.settle(&meta, result)))
    }

    fn wait(&mut self) -> Done {
        if let Ok(done) = self.done.recv() {
            return done;
        }
        // The thread drops its sender only by panicking while it has a job.
        let thread = self.thread.take().expect("joined only here or on drop");
        match thread.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => unreachable!("the lane reports every job it takes"),
        }
    }
}

impl<B: Budget> Drop for Lane<'_, '_, '_, B> {
    fn drop(&mut self) {
        self.jobs = None;
        if let Some(thread) = self.thread.take() {
            if let Err(panic) = thread.join() {
                if !std::thread::panicking() {
                    std::panic::resume_unwind(panic);
                }
            }
        }
    }
}

/// `LimitedWriter`'s writes for a member under no output limit, then the
/// flush [`OutputBudget::write_member`] gives a verified member.
fn write_member(
    control: &ReadControl,
    writer: &mut dyn Write,
    mut bytes: &[u8],
    verified: bool,
) -> Outcome {
    while !bytes.is_empty() {
        if control.check().is_err() {
            return Outcome::Cancelled;
        }
        let len = if control.is_enabled() {
            bytes.len().min(CONTROLLED_WRITE)
        } else {
            bytes.len()
        };
        match writer.write(&bytes[..len]) {
            Ok(0) => return Outcome::Sink(std::io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Outcome::Sink(error),
        }
    }
    if verified {
        if control.check().is_err() {
            return Outcome::Cancelled;
        }
        if let Err(error) = writer.flush() {
            return Outcome::Sink(error);
        }
    }
    Outcome::Written
}

impl<B: Budget> DecoderSession<'_, B> {
    /// Leaves a member that would still be written to fail at its write, so the chain goes on.
    fn decode_to_write(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
    ) -> Result<(Buffer<u8, B>, Result<()>)> {
        self.decoder.read_control.check()?;
        self.guard_solid_chain(file, |session| {
            session.claim_ahead(file);
            let decoded = session.decode_checked(
                archive,
                file,
                HistoryRetention::Retain,
                &mut std::io::sink(),
            );
            let whole = decoded.as_ref().is_ok_and(|(_, verified)| verified.is_ok());
            session.settle_ahead(file, whole);
            decoded
        })
    }
}
