//! Verified payload staging for archive rewrites.

use crate::{Archive, ArchiveReadOptions, EntrySource, Result};
use std::path::PathBuf;
use std::sync::Arc;

/// Disk policy for [`Archive::stage_rewrite_sources`].
///
/// The directory must already exist and be trusted: private files are reopened
/// by path. Payloads are plaintext, even for encrypted input. Cleanup on drop is
/// best effort, not secure erasure; process termination may leave files behind.
/// The byte limit covers retained payloads only, not filesystem overhead,
/// discarded solid dependencies, decoder workspace or writer output spools.
#[derive(Debug, Clone)]
pub struct RewriteStaging {
    /// Existing, trusted directory for private temporary payload files.
    pub directory: PathBuf,
    /// Inclusive limit on the sum of retained, uncompressed payload bytes.
    pub max_staged_bytes: u64,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod pipeline;

impl Archive {
    /// Supply verified payloads on demand during one writer call. Decoding uses
    /// one archive-order traversal, including required solid predecessors.
    /// Sources belong to one write in this call only: assign each source to one
    /// output member, and do not retain it after the call returns.
    /// The staging limit covers simultaneously retained plaintext payloads.
    /// Writers release compressed payload sources when no reread is needed;
    /// stored fallback can retain sources through emission. Output streams may
    /// contain a prefix on failure; use staged path publication for rollback.
    pub fn with_rewrite_sources<T>(
        &self,
        indices: &[usize],
        options: ArchiveReadOptions<'_>,
        staging: &RewriteStaging,
        progress: Option<Arc<dyn crate::WriteProgress>>,
        consume: impl FnOnce(Vec<EntrySource>) -> Result<T>,
    ) -> Result<T> {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            pipeline::run(self, indices, options, staging, progress, consume)
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let _ = (indices, options, staging, progress, consume);
            Err(crate::Error::InvalidArgument(
                "rewrite staging requires disk storage",
            ))
        }
    }

    /// Verify and stage selected payloads in one archive-order extraction pass.
    ///
    /// Indices count all members, including directories and redirections, but
    /// selected indices must identify distinct, unsplit payload members. Results
    /// follow the requested order. Metadata must be transferred separately.
    /// Solid predecessors are decoded and verified even when not selected;
    /// unrelated independent payloads and the suffix after the last selection
    /// are not decoded. Read options apply to this entire traversal.
    ///
    /// No sources are returned on failure. Successful sources can be reopened
    /// independently without reading the archive again. Temporary files survive
    /// until the last source or open reader drops. This stages the entire
    /// selection before returning, with an explicit disk limit; it is not a
    /// total memory limit or an incremental writer pipeline. Bare WebAssembly
    /// is unsupported because this operation requires disk storage.
    pub fn stage_rewrite_sources(
        &self,
        indices: &[usize],
        options: ArchiveReadOptions<'_>,
        staging: &RewriteStaging,
    ) -> Result<Vec<EntrySource>> {
        self.stage_rewrite_sources_with_progress(indices, options, staging, None)
    }

    /// Staging with a separate [`crate::WriteOperation::Staging`] progress phase.
    /// Counts decoded bytes, including discarded solid predecessors. Entry indices
    /// count decoded payloads in traversal order, not original archive indices.
    /// Byte progress precedes integrity verification; finished events follow it.
    /// Declared progress totals saturate at `u64::MAX`.
    ///
    /// Callback cancellation is checked around reports, between members and at
    /// bounded output writes. Supply `options.cancellation` to also interrupt
    /// decoder work that has not produced output. Blocked I/O cannot be preempted.
    pub fn stage_rewrite_sources_with_progress(
        &self,
        indices: &[usize],
        options: ArchiveReadOptions<'_>,
        staging: &RewriteStaging,
        progress: Option<Arc<dyn crate::WriteProgress>>,
    ) -> Result<Vec<EntrySource>> {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            native::stage(self, indices, options, staging, progress, None)
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let _ = (indices, options, staging, progress);
            Err(crate::Error::InvalidArgument(
                "rewrite staging requires disk storage",
            ))
        }
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod native {
    use super::*;
    use crate::{
        streaming::Spool, Error, ExtractionDecision, WriteOperation, WriteProgress,
        WriteProgressEvent, WriterResources,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        io::Write,
        rc::Rc,
    };

    struct Sink {
        spool: Rc<RefCell<Spool>>,
        used: Arc<AtomicU64>,
        limit: u64,
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let count = bytes.len() as u64;
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(count)
                        .filter(|required| *required <= self.limit)
                })
                .map_err(|used| {
                    std::io::Error::other(Error::RewriteStagingLimitExceeded {
                        limit: self.limit,
                        required: used.saturating_add(count),
                    })
                })?;
            let written = match self.spool.borrow_mut().write(bytes) {
                Ok(written) => written,
                Err(error) => {
                    self.used.fetch_sub(count, Ordering::AcqRel);
                    return Err(error);
                }
            };
            self.used
                .fetch_sub(count - written as u64, Ordering::AcqRel);
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.spool.borrow_mut().flush()
        }
    }

    impl Drop for Sink {
        fn drop(&mut self) {
            self.spool.borrow_mut().park();
        }
    }

    struct Progress {
        callback: Arc<dyn WriteProgress>,
        completed: Cell<u64>,
        total: u64,
        entries: usize,
    }

    impl Progress {
        fn check(&self) -> Result<()> {
            if self.callback.is_cancelled() {
                Err(Error::Cancelled)
            } else {
                Ok(())
            }
        }

        fn report(&self, event: WriteProgressEvent<'_>) -> Result<()> {
            self.check()?;
            self.callback.report(event);
            self.check()
        }

        fn finish_entry(&self, entry: &(usize, Vec<u8>, u64)) -> Result<()> {
            self.report(WriteProgressEvent::EntryFinished {
                operation: WriteOperation::Staging,
                index: entry.0,
                total_entries: self.entries,
                name: &entry.1,
                input_bytes: entry.2,
            })
        }
    }

    struct ProgressSink {
        inner: Box<dyn Write>,
        progress: Rc<Progress>,
    }

    impl Write for ProgressSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.progress.check().map_err(std::io::Error::other)?;
            let written = self.inner.write(&bytes[..bytes.len().min(64 * 1024)])?;
            let completed = self.progress.completed.get().saturating_add(written as u64);
            self.progress.completed.set(completed);
            self.progress
                .report(WriteProgressEvent::Advanced {
                    operation: WriteOperation::Staging,
                    completed_bytes: completed,
                    total_bytes: self.progress.total,
                    pass: 1,
                })
                .map_err(std::io::Error::other)?;
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    pub(super) fn stage(
        archive: &Archive,
        indices: &[usize],
        options: ArchiveReadOptions<'_>,
        staging: &RewriteStaging,
        progress: Option<Arc<dyn WriteProgress>>,
        delivery: Option<&super::pipeline::Delivery>,
    ) -> Result<Vec<EntrySource>> {
        options.check_cancelled()?;
        if progress
            .as_ref()
            .is_some_and(|progress| progress.is_cancelled())
        {
            return Err(Error::Cancelled);
        }
        let mut selected = BTreeMap::new();
        for &index in indices {
            if selected.insert(index, None).is_some() {
                return Err(Error::DuplicateEntry);
            }
        }
        let Some(&last) = selected.keys().next_back() else {
            return Ok(Vec::new());
        };
        let mut required = 0u64;
        let mut found = 0;
        let solid = match archive {
            Archive::Rar13(a) => a.main.is_solid(),
            Archive::Rar15To40(a) => a.main.is_solid(),
            Archive::Rar50Plus(a) => a.main.is_solid(),
        };
        let mut total = 0u64;
        let mut entries = 0;
        for (index, member) in archive.members().enumerate() {
            options.check_cancelled()?;
            if index <= last
                && (selected.contains_key(&index) || solid)
                && !member.meta.is_directory
                && !member.meta.is_redirection
            {
                total = total.saturating_add(member.meta.unpacked_size);
                entries += 1;
            }
            if !selected.contains_key(&index) {
                continue;
            }
            let meta = member.meta;
            if meta.is_directory
                || meta.is_redirection
                || meta.is_split_before
                || meta.is_split_after
            {
                return Err(Error::InvalidArgument(
                    "rewrite staging requires unsplit payload members",
                ));
            }
            let sum = if delivery.is_some() {
                Some(required.max(meta.unpacked_size))
            } else {
                required.checked_add(meta.unpacked_size)
            };
            if sum.is_none_or(|sum| sum > staging.max_staged_bytes) {
                return Err(Error::RewriteStagingLimitExceeded {
                    limit: staging.max_staged_bytes,
                    required: sum.unwrap_or(u64::MAX),
                });
            }
            required = sum.unwrap();
            found += 1;
        }
        if found != selected.len() {
            return Err(Error::EntryNotFound);
        }
        let progress = progress.map(|callback| {
            Rc::new(Progress {
                callback,
                completed: Cell::new(0),
                total,
                entries,
            })
        });
        if let Some(progress) = &progress {
            progress.report(WriteProgressEvent::OperationStarted {
                operation: WriteOperation::Staging,
                total_bytes: Some(total),
                total_entries: Some(entries),
                pass: 1,
            })?;
        }
        let resources = WriterResources::new(0).with_temp_dir(&staging.directory);
        let used = delivery.map_or_else(
            || Arc::new(AtomicU64::new(0)),
            |delivery| delivery.used.clone(),
        );
        let mut index = 0;
        let mut pending = None;
        let mut decoded = 0;
        let mut staged_pending = None;
        archive.extract_with_control(options, |member| {
            publish_pending(&mut staged_pending, &mut selected, delivery)?;
            if let Some(progress) = &progress {
                if let Some(entry) = pending.take() {
                    progress.finish_entry(&entry)?;
                }
            }
            let current = index;
            index += 1;
            if current > last {
                return Ok(ExtractionDecision::Stop);
            }
            let wanted = selected.contains_key(&current);
            let dependency = solid && !member.meta.is_directory && !member.meta.is_redirection;
            if !wanted && !dependency {
                return Ok(ExtractionDecision::Skip);
            }
            if let Some(delivery) = delivery {
                // Dependencies are decoded only on demand for the next retained member.
                let next = selected
                    .range(current..)
                    .next()
                    .map(|(&index, _)| index)
                    .unwrap_or(last);
                delivery.wait_for(next)?;
            }
            if let Some(progress) = &progress {
                progress.report(WriteProgressEvent::EntryStarted {
                    operation: WriteOperation::Staging,
                    index: decoded,
                    total_entries: entries,
                    name: &member.meta.name,
                    input_bytes: member.meta.unpacked_size,
                })?;
                pending = Some((decoded, member.meta.name.clone(), member.meta.unpacked_size));
            }
            decoded += 1;
            let sink: Box<dyn Write> = if let Some(slot) = selected.get_mut(&current) {
                let spool = Rc::new(RefCell::new(Spool::create(&resources)?));
                *slot = Some(spool.clone());
                staged_pending = Some(current);
                Box::new(Sink {
                    spool,
                    used: used.clone(),
                    limit: staging.max_staged_bytes,
                })
            } else {
                Box::new(std::io::sink())
            };
            Ok(ExtractionDecision::Extract(
                if let Some(progress) = &progress {
                    Box::new(ProgressSink {
                        inner: sink,
                        progress: progress.clone(),
                    })
                } else {
                    sink
                },
            ))
        })?;
        if let Some(progress) = &progress {
            if let Some(entry) = pending.take() {
                progress.finish_entry(&entry)?;
            }
            progress.report(WriteProgressEvent::OperationFinished {
                operation: WriteOperation::Staging,
                total_bytes: Some(total),
                total_entries: Some(entries),
                pass: 1,
            })?;
        }
        publish_pending(&mut staged_pending, &mut selected, delivery)?;
        if delivery.is_some() {
            return Ok(Vec::new());
        }
        indices
            .iter()
            .map(|index| {
                let spool = selected
                    .remove(index)
                    .flatten()
                    .ok_or(Error::InvalidHeader("staged rewrite member disappeared"))?;
                let spool = Rc::try_unwrap(spool)
                    .map_err(|_| Error::InvalidHeader("rewrite sink still active"))?
                    .into_inner();
                Ok(spool.into_source())
            })
            .collect()
    }

    fn publish_pending(
        pending: &mut Option<usize>,
        selected: &mut BTreeMap<usize, Option<Rc<RefCell<Spool>>>>,
        delivery: Option<&super::pipeline::Delivery>,
    ) -> Result<()> {
        if let (Some(index), Some(delivery)) = (pending.take(), delivery) {
            let spool = selected
                .remove(&index)
                .flatten()
                .ok_or(Error::WriterFailure("rewrite spool disappeared"))?;
            let spool = Rc::try_unwrap(spool)
                .map_err(|_| Error::WriterFailure("rewrite sink still active"))?
                .into_inner();
            delivery.publish(index, spool.into_source())?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn runtime_limit_counts_all_sinks_and_refuses_before_writing() {
            let root = crate::scratch::case("rewrite-runtime-limit");
            let resources = WriterResources::new(0).with_temp_dir(&*root);
            let used = Arc::new(AtomicU64::new(0));
            let make_sink = || Sink {
                spool: Rc::new(RefCell::new(Spool::create(&resources).unwrap())),
                used: used.clone(),
                limit: 5,
            };
            let mut first = make_sink();
            let mut second = make_sink();
            first.write_all(b"abc").unwrap();
            second.write_all(b"de").unwrap();
            let error = Error::from(second.write_all(b"f").unwrap_err());
            assert_eq!(
                error,
                Error::RewriteStagingLimitExceeded {
                    limit: 5,
                    required: 6
                }
            );
            assert_eq!(used.load(Ordering::Acquire), 5);
            assert_eq!(second.spool.borrow().len(), 2);
        }
    }
}
