use super::{restore_output_metadata, ExtractEngine, Warning};
use crate::extract_dir::{ExtractedDir, SkippedLink};
use crate::output_links::{Select, Settled, SettledSource};
use crate::output_staging::OverwritePolicy;
use crate::ExtractedLink;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// How [`DirExtraction`] writes.
#[derive(Debug, Clone, Copy)]
pub struct DirMode {
    pub overwrite: OverwritePolicy,
    /// Writes each destination itself instead of staging it.
    pub in_place: bool,
    pub restore_times: bool,
    pub restore_modes: bool,
    pub symlinks: crate::SymlinkPolicy,
    /// Writes every file straight into the directory under its base name.
    pub flatten: bool,
    /// Follows "`<path>` already exists" when `overwrite` is `Never` refuses a file.
    pub exists_hint: &'static str,
}

/// The engine behind [`crate::Archive::extract_to_dir`] and the Python binding's `extractall`.
/// Stages each file and publishes it once verified, so a hard link or FIFO at the destination
/// is never written through, unless writing in place.
pub struct DirExtraction<'a> {
    engine: ExtractEngine<'a>,
    skipped_links: Arc<Mutex<Vec<SkippedLink>>>,
    /// Flattened under `Always`: a member that replaced an earlier one is listed once.
    listed_once: bool,
}

impl<'a> DirExtraction<'a> {
    pub fn new(
        out_dir: &'a Path,
        family: crate::ArchiveFamily,
        encoding: Option<crate::filename::LegacyNameEncoding>,
        mode: DirMode,
    ) -> Self {
        let mut engine =
            ExtractEngine::new(out_dir, mode.overwrite, mode.in_place, mode.flatten, family);
        engine.legacy_name_encoding(encoding);
        engine.exists_hint(mode.exists_hint);
        engine.leave_directory_time();
        engine.refuse_decoded_repeats();
        engine.look_in_made_directories();
        if mode.overwrite == OverwritePolicy::Always {
            engine.allow_overwrite_repeats();
        }
        if !mode.restore_times {
            engine.ignore_times();
        }
        if !mode.restore_modes {
            engine.ignore_modes();
        }
        engine.symlinks(mode.symlinks);
        let skipped_links = Arc::new(Mutex::new(Vec::new()));
        let skipped = Arc::clone(&skipped_links);
        engine.warn_to(Box::new(move |warning| {
            if let Warning::SkippedLink { stored, target, .. } = warning {
                skipped
                    .lock()
                    .expect("skipped links lock poisoned")
                    .push(SkippedLink {
                        name: stored.to_vec(),
                        target: target.to_vec(),
                    });
            }
        }));
        Self {
            engine,
            skipped_links,
            listed_once: mode.flatten && mode.overwrite == OverwritePolicy::Always,
        }
    }

    /// See [`ExtractEngine::publish_waiter`].
    pub fn publish_waiter(&self) -> impl Fn() + Send + Sync + 'static {
        self.engine.publish_waiter()
    }

    /// Members verified before a failure stay published, with their times and modes; the rest
    /// never reach their destinations.
    pub fn finish(mut self, result: crate::Result<()>) -> crate::Result<ExtractedDir> {
        if let Err(error) = result.and_then(|()| self.engine.queued_failure()) {
            // The extraction error wins over one publishing or restoring what verified.
            let _ = restore_output_metadata(&self.engine.abandon());
            return Err(error);
        }
        let outputs = self.engine.publish()?;
        restore_output_metadata(&outputs)?;
        let mut paths: Vec<_> = outputs.into_iter().map(|output| output.path).collect();
        if self.listed_once {
            let mut seen = HashSet::new();
            paths.reverse();
            paths.retain(|path| seen.insert(path.clone()));
            paths.reverse();
        }
        let skipped_links = std::mem::take(
            &mut *self
                .skipped_links
                .lock()
                .expect("skipped links lock poisoned"),
        );
        Ok(ExtractedDir {
            paths,
            skipped_links,
        })
    }
}

/// Where [`extract_archive`] writes: [`DirExtraction`], or a wrapper around an engine.
pub trait Outputs {
    fn open(&mut self, meta: &crate::ExtractedEntryMeta) -> crate::Result<Box<dyn Write + Send>>;
    fn settle(&mut self, outcome: Settled) -> crate::Result<()>;
    fn link(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
        link: ExtractedLink<'_>,
    ) -> crate::Result<()>;
    /// See [`ExtractEngine::can_open_ahead`].
    fn can_open_ahead(&self) -> bool;
    /// See [`ExtractEngine::written_elsewhere`].
    fn written_elsewhere(&mut self, elsewhere: bool);
}

impl Outputs for DirExtraction<'_> {
    fn open(&mut self, meta: &crate::ExtractedEntryMeta) -> crate::Result<Box<dyn Write + Send>> {
        self.engine.open_settled(meta)
    }

    fn settle(&mut self, outcome: Settled) -> crate::Result<()> {
        // A failed open was the member's own error; the handler decided whether the run goes on.
        self.engine.settle(outcome != Settled::Failed).map(drop)
    }

    fn link(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
        link: ExtractedLink<'_>,
    ) -> crate::Result<()> {
        self.engine.create_link(meta, link)
    }

    fn can_open_ahead(&self) -> bool {
        self.engine.can_open_ahead()
    }

    fn written_elsewhere(&mut self, elsewhere: bool) {
        self.engine.written_elsewhere(elsewhere);
    }
}

/// The one choice of decode path for directory extraction, so the library, Python and the CLI agree.
pub fn extract_archive(
    archive: &crate::Archive,
    read: crate::ArchiveReadOptions<'_>,
    select: Option<&Select<'_>>,
    outputs: &Mutex<impl Outputs + Send>,
) -> crate::Result<()> {
    let lock = || outputs.lock().expect("outputs lock poisoned");
    let open = |meta: &crate::ExtractedEntryMeta| lock().open(meta);
    let link = |meta: &crate::ExtractedEntryMeta, made: ExtractedLink<'_>| lock().link(meta, made);
    let settled = |_: &crate::ExtractedEntryMeta, outcome| lock().settle(outcome);
    let ahead = lock().can_open_ahead();
    // Only RAR 5's write lane hands outputs to other threads.
    lock().written_elsewhere(
        ahead
            && select.is_none()
            && !read.salvage
            && matches!(archive, crate::Archive::Rar50Plus(_)),
    );
    if select.is_none() && !ahead {
        return crate::output_links::settle_in_order(
            read,
            open,
            link,
            settled,
            |read, open, link| archive.extract_with_links(read, open, link),
        );
    }
    crate::output_links::extract_settled(
        SettledSource::Archive(archive),
        read,
        select,
        open,
        link,
        settled,
    )
}

#[cfg(test)]
#[path = "dir_tests.rs"]
mod tests;
