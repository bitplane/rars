//! Verified payload staging for archive rewrites.

use crate::{Archive, ArchiveReadOptions, EntrySource, Result};
use std::path::PathBuf;

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

impl Archive {
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
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            native::stage(self, indices, options, staging)
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let _ = (indices, options, staging);
            Err(crate::Error::InvalidArgument(
                "rewrite staging requires disk storage",
            ))
        }
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
mod native {
    use super::*;
    use crate::{streaming::Spool, Error, ExtractionDecision, WriterResources};
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        io::Write,
        rc::Rc,
    };

    struct Sink {
        spool: Rc<RefCell<Spool>>,
        used: Rc<Cell<u64>>,
        limit: u64,
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let required = self.used.get().checked_add(bytes.len() as u64);
            if required.is_none_or(|required| required > self.limit) {
                return Err(std::io::Error::other(Error::RewriteStagingLimitExceeded {
                    limit: self.limit,
                    required: required.unwrap_or(u64::MAX),
                }));
            }
            let written = self.spool.borrow_mut().write(bytes)?;
            self.used.set(self.used.get() + written as u64);
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

    pub(super) fn stage(
        archive: &Archive,
        indices: &[usize],
        options: ArchiveReadOptions<'_>,
        staging: &RewriteStaging,
    ) -> Result<Vec<EntrySource>> {
        options.check_cancelled()?;
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
        for (index, member) in archive.members().enumerate() {
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
            let sum = required.checked_add(meta.unpacked_size);
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
        let solid = match archive {
            Archive::Rar13(a) => a.main.is_solid(),
            Archive::Rar15To40(a) => a.main.is_solid(),
            Archive::Rar50Plus(a) => a.main.is_solid(),
        };
        let resources = WriterResources::new(0).with_temp_dir(&staging.directory);
        let used = Rc::new(Cell::new(0));
        let mut index = 0;
        archive.extract_with_control(options, |member| {
            let current = index;
            index += 1;
            if current > last {
                return Ok(ExtractionDecision::Stop);
            }
            if let Some(slot) = selected.get_mut(&current) {
                let spool = Rc::new(RefCell::new(Spool::create(&resources)?));
                *slot = Some(spool.clone());
                Ok(ExtractionDecision::Extract(Box::new(Sink {
                    spool,
                    used: used.clone(),
                    limit: staging.max_staged_bytes,
                })))
            } else if solid && !member.meta.is_directory && !member.meta.is_redirection {
                Ok(ExtractionDecision::Extract(Box::new(std::io::sink())))
            } else {
                Ok(ExtractionDecision::Skip)
            }
        })?;
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn runtime_limit_counts_all_sinks_and_refuses_before_writing() {
            let root = crate::scratch::case("rewrite-runtime-limit");
            let resources = WriterResources::new(0).with_temp_dir(&*root);
            let used = Rc::new(Cell::new(0));
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
            assert_eq!(used.get(), 5);
            assert_eq!(second.spool.borrow().len(), 2);
        }
    }
}
