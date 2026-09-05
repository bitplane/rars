//! One archive builder for every format.
//!
//! The writers underneath are per-family and take different entry types, and
//! choosing between them is the same twenty decisions in every binding. This
//! module makes that choice once: name the format, add members, ask for bytes
//! or a file or a volume set. The Python extension and the WebAssembly package
//! are thin translations of the type below, which is the point of it living
//! here rather than in one of them.

use crate::{
    rar13, rar15_40, rar50, ArchiveFamily, ArchiveVersion, EntrySource, Error, FeatureSet, Result,
    WriteProgress, WriterResources,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The DOS archive bit, which is what a member gets when the caller offers no
/// mode of its own. Zero would be legal and would read as "no attributes",
/// which no real RAR writer emits.
const DOS_ARCHIVE_ATTR: u32 = 0x20;

// Host IDs are format-specific: legacy RAR uses 3 for Unix, RAR 5 uses 1.
// Keep the host paired with its attributes. Merely correcting the RAR 5 ID
// while retaining DOS_ARCHIVE_ATTR would make reference extractors interpret
// 0x20 as Unix permissions, producing an unexpectedly restricted file.
const RAR15_HOST_UNIX: u8 = 3;
const RAR50_HOST_UNIX: u64 = 1;

struct PendingArchive {
    path: Option<PathBuf>,
}

impl PendingArchive {
    fn create(destination: &Path) -> Result<(Self, fs::File)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = destination.with_file_name(format!(
                ".rars-writing-{}-{sequence:016x}",
                std::process::id()
            ));
            match fs::File::options().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((Self { path: Some(path) }, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique archive temporary file",
        )
        .into())
    }
}

impl Drop for PendingArchive {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EntryAttributes {
    Dos(u64),
    Unix(u32),
}

/// A member queued for writing.
///
/// The bytes are either held directly or fetched from an [`EntrySource`] when
/// the writer reaches the member. Sources are what keep a large archive off the
/// heap; the legacy families cannot stream, so they read each source into
/// `data` first.
#[derive(Debug, Clone)]
struct BuilderEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    source: Option<EntrySource>,
    mtime: Option<u32>,
    mtime_nanoseconds: Option<u32>,
    attributes: EntryAttributes,
}

impl BuilderEntry {
    fn attributes(&self) -> u64 {
        match self.attributes {
            // add_bytes/add_source can receive permission bits alone, whereas
            // add_path supplies a complete st_mode. Supply regular-file type
            // bits only when absent so both forms describe Unix metadata.
            EntryAttributes::Unix(mode) if mode & 0o170000 == 0 => u64::from(mode | 0o100000),
            EntryAttributes::Unix(mode) => u64::from(mode),
            EntryAttributes::Dos(attributes) => attributes,
        }
    }

    fn rar50_attr(&self) -> u64 {
        self.attributes()
    }

    fn rar15_attr(&self) -> u32 {
        // set_dos_attributes validates the target family's field width.
        self.attributes() as u32
    }

    fn rar13_attr(&self) -> u8 {
        match self.attributes {
            EntryAttributes::Dos(attributes) => attributes as u8,
            EntryAttributes::Unix(_) => DOS_ARCHIVE_ATTR as u8,
        }
    }

    fn rar50_host_os(&self) -> u64 {
        if matches!(self.attributes, EntryAttributes::Unix(_)) {
            RAR50_HOST_UNIX
        } else {
            0 // Windows host, DOS attributes.
        }
    }

    fn rar15_host_os(&self) -> u8 {
        // The RAR 1.5 writer still downgrades Unix metadata to DOS for old
        // extractor compatibility; RAR 2.x-4.x retain the Unix host and mode.
        if matches!(self.attributes, EntryAttributes::Unix(_)) {
            RAR15_HOST_UNIX
        } else {
            0 // MS-DOS host, DOS attributes.
        }
    }
}

/// Assembles an archive from members added one at a time.
///
/// Nothing is encoded until [`to_bytes`](Self::to_bytes),
/// [`write_to_path`](Self::write_to_path) or
/// [`build_volumes`](Self::build_volumes) is called, so the same builder can be
/// written more than once and to more than one format.
///
/// ```no_run
/// # fn main() -> rars::Result<()> {
/// let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50);
/// builder.add_bytes(b"hello.txt".to_vec(), b"hello".to_vec(), None, None)?;
/// let archive = builder.to_bytes()?;
/// # let _ = archive;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Builder {
    format: ArchiveVersion,
    compression: Option<u8>,
    store: bool,
    solid: bool,
    password: Option<Vec<u8>>,
    encrypt_headers: bool,
    comment: Option<Vec<u8>>,
    recovery_percent: Option<u64>,
    volume_size: Option<usize>,
    entries: Vec<BuilderEntry>,
}

impl Builder {
    /// A builder for `format`, with the writer's own default compression level.
    pub fn new(format: ArchiveVersion) -> Self {
        Self {
            format,
            compression: None,
            store: false,
            solid: false,
            password: None,
            encrypt_headers: false,
            comment: None,
            recovery_percent: None,
            volume_size: None,
            entries: Vec::new(),
        }
    }

    /// The format this builder writes.
    pub fn format(&self) -> ArchiveVersion {
        self.format
    }

    /// Compression level, 0 to 5. `None` leaves the writer's default in place.
    pub fn compression_level(mut self, level: Option<u8>) -> Self {
        self.compression = level;
        self
    }

    /// Store members without compressing them. Storing is a compression level,
    /// not a kind of member, so this wins over any level set above.
    pub fn store(mut self, store: bool) -> Self {
        self.store = store;
        self
    }

    /// Compress members against each other rather than independently.
    pub fn solid(mut self, solid: bool) -> Self {
        self.solid = solid;
        self
    }

    /// Encrypt member data with `password`.
    pub fn password(mut self, password: Option<Vec<u8>>) -> Self {
        self.password = password;
        self
    }

    /// Encrypt the headers as well as the data, hiding the member names. Needs
    /// a password.
    pub fn header_encryption(mut self, encrypt: bool) -> Self {
        self.encrypt_headers = encrypt;
        self
    }

    /// An archive comment.
    pub fn comment(mut self, comment: Option<Vec<u8>>) -> Self {
        self.comment = comment;
        self
    }

    /// Add a recovery record covering this percentage of the archive.
    pub fn recovery_percent(mut self, percent: Option<u64>) -> Self {
        self.recovery_percent = percent;
        self
    }

    /// Split the output into volumes of at most this many bytes.
    /// [`build_volumes`](Self::build_volumes) requires it; the single-archive
    /// entry points refuse to run while it is set.
    pub fn volume_size(mut self, size: Option<usize>) -> Self {
        self.volume_size = size;
        self
    }

    /// How many members are queued.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no members are queued.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The queued member names, in the order they will be written.
    pub fn names(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.iter().map(|entry| entry.name.as_slice())
    }

    /// Queue `data` under `name`.
    ///
    /// `mode` is a Unix mode, with optional file-type bits. Without a mode,
    /// the member uses DOS archive attributes and the extractor's default permissions.
    /// RAR 1.3-1.5 output uses DOS metadata even when a Unix mode is supplied.
    pub fn add_bytes(
        &mut self,
        name: Vec<u8>,
        data: Vec<u8>,
        mtime: Option<u32>,
        mode: Option<u32>,
    ) -> Result<()> {
        self.push(BuilderEntry {
            name: validate_entry_name(name)?,
            data,
            source: None,
            mtime,
            mtime_nanoseconds: None,
            attributes: mode.map_or(
                EntryAttributes::Dos(u64::from(DOS_ARCHIVE_ATTR)),
                EntryAttributes::Unix,
            ),
        })
    }

    /// Queue a member whose bytes are fetched from `source` when the writer
    /// reaches it.
    /// `mode` has the same meaning as in [`add_bytes`](Self::add_bytes).
    pub fn add_source(
        &mut self,
        name: Vec<u8>,
        source: EntrySource,
        mtime: Option<u32>,
        mode: Option<u32>,
    ) -> Result<()> {
        self.push(BuilderEntry {
            name: validate_entry_name(name)?,
            data: Vec::new(),
            source: Some(source),
            mtime,
            mtime_nanoseconds: None,
            attributes: mode.map_or(
                EntryAttributes::Dos(u64::from(DOS_ARCHIVE_ATTR)),
                EntryAttributes::Unix,
            ),
        })
    }

    /// Add nanosecond precision to a queued RAR5/7 modification time.
    /// The member must already have whole seconds; legacy output is unsupported.
    pub fn set_mtime_nanoseconds(&mut self, name: &[u8], nanoseconds: u32) -> Result<()> {
        if self.format.family() != crate::ArchiveFamily::Rar50Plus || nanoseconds >= 1_000_000_000 {
            return Err(Error::InvalidHeader(
                "nanosecond modification times require RAR5/7 and a fraction below one second",
            ));
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.name == name)
            .ok_or_else(|| Error::AtEntry {
                name: name.to_vec(),
                operation: "setting modification time precision",
                source: Box::new(Error::InvalidHeader("no such archive entry")),
            })?;
        if entry.mtime.is_none() {
            return Err(Error::InvalidHeader(
                "fractional modification time requires whole seconds",
            ));
        }
        entry.mtime_nanoseconds = Some(nanoseconds);
        Ok(())
    }

    /// Set DOS/Windows attributes for a queued file, replacing any Unix mode.
    ///
    /// The output host is paired with these flags. Attribute width is checked
    /// against the target format (8 bits for RAR 1.3/1.4, 32 for RAR 1.5-4.x).
    /// Directory attributes are rejected: setting flags cannot turn a queued
    /// file into a directory entry. Errors leave the queued metadata unchanged.
    pub fn set_dos_attributes(&mut self, name: &[u8], attributes: u64) -> Result<()> {
        use crate::ArchiveFamily;
        let max = match self.format.family() {
            ArchiveFamily::Rar13 => u64::from(u8::MAX),
            ArchiveFamily::Rar15To40 => u64::from(u32::MAX),
            ArchiveFamily::Rar50Plus => u64::MAX,
        };
        if attributes > max {
            return Err(Error::InvalidHeader(
                "DOS attributes exceed the target format's field width",
            ));
        }
        if attributes & 0x10 != 0 {
            return Err(Error::InvalidHeader(
                "DOS directory attributes require a directory entry",
            ));
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.name == name)
            .ok_or_else(|| Error::AtEntry {
                name: name.to_vec(),
                operation: "setting DOS attributes",
                source: Box::new(Error::InvalidHeader("no such archive entry")),
            })?;
        entry.attributes = EntryAttributes::Dos(attributes);
        Ok(())
    }

    /// Queue a file, or every file under a directory, named `archive_name` in
    /// the archive. Children are added in sorted order so the same tree gives
    /// the same archive twice.
    ///
    /// Symlinks are refused rather than followed, at the root and at every
    /// level below it: a link is a name for someone else's file, and copying
    /// what it points at is not what the caller asked for.
    pub fn add_path(&mut self, path: &Path, archive_name: &[u8]) -> Result<()> {
        let link_meta = fs::symlink_metadata(path)?;
        if link_meta.file_type().is_symlink() {
            return Err(Error::AtEntry {
                name: archive_name.to_vec(),
                operation: "adding",
                source: Box::new(Error::InvalidHeader(
                    "input is a symlink; refusing to follow it",
                )),
            });
        }
        let meta = fs::metadata(path)?;
        if meta.is_dir() {
            let mut children = fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                let mut child_name = archive_name.to_vec();
                child_name.push(b'/');
                child_name.extend_from_slice(child.file_name().to_string_lossy().as_bytes());
                self.add_path(&child.path(), &child_name)?;
            }
        } else if meta.is_file() {
            self.add_source(
                archive_name.to_vec(),
                EntrySource::from_path(path),
                None,
                unix_mode(&meta),
            )?;
        }
        Ok(())
    }

    /// Drop the member called `name`. Errors if no member has that name.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.name != name);
        if self.entries.len() == before {
            return Err(Error::AtEntry {
                name: name.to_vec(),
                operation: "removing",
                source: Box::new(Error::InvalidHeader("no such archive entry")),
            });
        }
        Ok(())
    }

    /// Rename the member called `old` to `new`.
    pub fn rename(&mut self, old: &[u8], new: Vec<u8>) -> Result<()> {
        let new = validate_entry_name(new)?;
        let index = self
            .entries
            .iter()
            .position(|entry| entry.name == old)
            .ok_or_else(|| Error::AtEntry {
                name: old.to_vec(),
                operation: "renaming",
                source: Box::new(Error::InvalidHeader("no such archive entry")),
            })?;
        if old != new {
            self.reject_duplicate_name(&new)?;
        }
        self.entries[index].name = new;
        Ok(())
    }

    fn push(&mut self, entry: BuilderEntry) -> Result<()> {
        self.reject_duplicate_name(&entry.name)?;
        self.entries.push(entry);
        Ok(())
    }

    fn reject_duplicate_name(&self, name: &[u8]) -> Result<()> {
        if self.entries.iter().any(|entry| entry.name == name) {
            return Err(Error::AtEntry {
                name: name.to_vec(),
                operation: "adding",
                source: Box::new(Error::InvalidHeader("duplicate archive entry name")),
            });
        }
        Ok(())
    }

    /// Encode the whole archive into memory.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.to_bytes_with_progress(None)
    }

    /// As [`to_bytes`](Self::to_bytes), reporting progress as it goes.
    pub fn to_bytes_with_progress(&self, progress: Option<&dyn WriteProgress>) -> Result<Vec<u8>> {
        self.check_single()?;
        if self.streams_rar50() {
            let mut output = Vec::new();
            self.write_streaming_rar50(&mut output, &WriterResources::default(), progress)?;
            return Ok(output);
        }
        self.materialized()?.build_single(progress)
    }

    /// Write the archive to `output`.
    ///
    /// RAR 5 and RAR 7 stream: peak memory is one member plus the dictionary,
    /// whatever the archive weighs. The legacy families have no streaming
    /// writer, so they encode into memory first and this is
    /// [`to_bytes`](Self::to_bytes) followed by a write.
    pub fn write_to(
        &self,
        output: &mut dyn Write,
        resources: &WriterResources,
        progress: Option<&dyn WriteProgress>,
    ) -> Result<()> {
        self.check_single()?;
        if self.streams_rar50() {
            return self.write_streaming_rar50(output, resources, progress);
        }
        let data = self.materialized()?.build_single(progress)?;
        output.write_all(&data)?;
        Ok(())
    }

    /// Write the archive to `path`, streaming where the format allows it.
    /// The completed archive replaces the destination only after writing and syncing succeed.
    ///
    /// Any spooling the writer needs goes beside the output rather than in the
    /// system temporary directory, which is often a memory-backed filesystem
    /// too small for the archive being written.
    pub fn write_to_path(&self, path: &Path, progress: Option<&dyn WriteProgress>) -> Result<()> {
        let resources = match path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            Some(parent) => WriterResources::default().with_temp_dir(parent),
            None => WriterResources::default(),
        };
        let (mut pending, mut output) = PendingArchive::create(path)?;
        let result = self
            .write_to(&mut output, &resources, progress)
            .and_then(|()| output.sync_all().map_err(Error::from));
        // Close before rename or cleanup on platforms that disallow removing
        // open files. Declaration order also closes it first during unwinding.
        drop(output);
        result?;
        fs::rename(pending.path.as_ref().unwrap(), path)?;
        pending.path = None;
        Ok(())
    }

    /// Encode the archive as a volume set, one `Vec` per volume.
    ///
    /// Requires [`volume_size`](Self::volume_size). Naming the parts on disk is
    /// the caller's job, because the two families number them differently.
    pub fn build_volumes(&self, progress: Option<&dyn WriteProgress>) -> Result<Vec<Vec<u8>>> {
        let volume_size = self
            .volume_size
            .ok_or(Error::InvalidHeader("volume_size is required"))?;
        if self.entries.is_empty() {
            return Err(Error::InvalidHeader("archive builder has no entries"));
        }
        let this = self.materialized()?;
        match self.format.family() {
            ArchiveFamily::Rar50Plus => this.build_rar50_volumes(volume_size, progress),
            ArchiveFamily::Rar15To40 => this.build_rar15_volumes(volume_size, progress),
            ArchiveFamily::Rar13 => this.build_rar13_volumes(volume_size, progress),
        }
    }

    /// Whether writing goes through the streaming RAR 5 writer, which serves
    /// everything this builder can ask for except volume sets. Header
    /// encryption without a password is not one of the things it can do, so
    /// that combination falls back and is rejected by the writer proper.
    pub fn streams_rar50(&self) -> bool {
        matches!(self.format, ArchiveVersion::Rar50 | ArchiveVersion::Rar70)
            && self.volume_size.is_none()
            && (!self.encrypt_headers || self.password.is_some())
    }

    fn check_single(&self) -> Result<()> {
        if self.entries.is_empty() {
            return Err(Error::InvalidHeader("archive builder has no entries"));
        }
        if self.volume_size.is_some() {
            return Err(Error::InvalidHeader(
                "use build_volumes for multivolume archives",
            ));
        }
        Ok(())
    }

    /// A copy with every source read into memory, for the writers that cannot
    /// take one. Returns a borrow when there is nothing to read, so the common
    /// case does not copy the members twice.
    fn materialized(&self) -> Result<std::borrow::Cow<'_, Self>> {
        if self.streams_rar50() || !self.entries.iter().any(|entry| entry.source.is_some()) {
            return Ok(std::borrow::Cow::Borrowed(self));
        }
        let mut owned = self.clone();
        for entry in &mut owned.entries {
            if let Some(source) = entry.source.take() {
                entry.data = crate::write_stream::MemberBytes::Source(&source)
                    .load()?
                    .into_owned();
            }
        }
        Ok(std::borrow::Cow::Owned(owned))
    }

    fn build_single(&self, progress: Option<&dyn WriteProgress>) -> Result<Vec<u8>> {
        match self.format.family() {
            ArchiveFamily::Rar50Plus => self.build_rar50_single(progress),
            ArchiveFamily::Rar15To40 => self.build_rar15_single(progress),
            ArchiveFamily::Rar13 => self.build_rar13_single(progress),
        }
    }

    fn features(&self) -> FeatureSet {
        let mut features = FeatureSet::store_only();
        features.solid = self.solid;
        features.header_encryption = self.encrypt_headers;
        features
    }

    /// Storing is a compression level, not a kind of member, so `store` wins
    /// over any level the caller asked for.
    fn rar50_options(&self) -> rar50::WriterOptions {
        let mut options = rar50::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        if self.store {
            options = options.with_compression_level(0);
        }
        options
    }

    /// Whether to look for a data filter, which the archive has to be able to
    /// carry. One answer for every RAR 5 path: when the streaming writer worked
    /// this out for itself, an archive built from bytes came out unfiltered and
    /// larger than the same archive built from files.
    fn rar50_filter_policy(&self) -> rar50::FilterPolicy {
        if self.solid || self.store {
            rar50::FilterPolicy::None
        } else {
            rar50::FilterPolicy::Auto
        }
    }

    fn rar50_entries(&self) -> Vec<rar50::ArchiveEntry> {
        self.entries
            .iter()
            .map(|entry| {
                let source = entry.source.clone().unwrap_or_else(|| {
                    // From the slice, not the Vec: `From<Vec<u8>>` cannot reuse
                    // the buffer, so cloning first copied every member twice.
                    EntrySource::from_bytes(Arc::<[u8]>::from(entry.data.as_slice()))
                });
                let built = rar50::ArchiveEntry::new(entry.name.clone(), source)
                    .with_mtime(entry.mtime)
                    .with_mtime_nanoseconds(entry.mtime_nanoseconds)
                    .with_attributes(entry.rar50_attr())
                    .with_host_os(entry.rar50_host_os());
                match self.password.as_deref() {
                    Some(password) => built.with_password(password.to_vec()),
                    None => built,
                }
            })
            .collect()
    }

    fn write_streaming_rar50(
        &self,
        output: &mut dyn Write,
        resources: &WriterResources,
        progress: Option<&dyn WriteProgress>,
    ) -> Result<()> {
        let mut extras = rar50::ArchiveExtras::default()
            .with_recovery_percent(self.recovery_percent)
            .with_filter_policy(self.rar50_filter_policy());
        if let Some(comment) = self.comment.as_deref() {
            extras = extras.with_comment(comment);
        }
        rar50::write_streaming_archive_with_progress(
            &self.rar50_entries(),
            self.rar50_options(),
            extras,
            resources,
            progress,
            output,
        )
    }

    fn build_rar50_single(&self, progress: Option<&dyn WriteProgress>) -> Result<Vec<u8>> {
        let writer = rar50::Rar50Writer::new(self.rar50_options());
        let writer = match progress {
            Some(progress) => writer.progress(progress),
            None => writer,
        };
        let writer = writer
            .entries(self.rar50_entries())
            .filter_policy(self.rar50_filter_policy())
            .recovery_percent(self.recovery_percent);
        let writer = match (self.comment.as_deref(), self.password.as_deref()) {
            (Some(comment), Some(password)) => writer.encrypted_archive_comment(comment, password),
            (comment, _) => writer.archive_comment(comment),
        };
        writer.finish()
    }

    fn rar15_options(&self) -> rar15_40::WriterOptions {
        let mut options = rar15_40::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        options
    }

    fn build_rar15_single(&self, progress: Option<&dyn WriteProgress>) -> Result<Vec<u8>> {
        let options = self.rar15_options();
        if self.store {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rar15_40::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar15_attr(),
                    host_os: entry.rar15_host_os(),
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rar15_40::write_stored_archive_with_comment(&entries, options, self.comment.as_deref())
        } else {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rar15_40::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar15_attr(),
                    host_os: entry.rar15_host_os(),
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rar15_40::write_compressed_archive_with_comment_and_progress(
                &entries,
                options,
                self.comment.as_deref(),
                progress,
            )
        }
    }

    fn rar13_options(&self) -> rar13::WriterOptions {
        let mut options = rar13::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        options
    }

    fn build_rar13_single(&self, progress: Option<&dyn WriteProgress>) -> Result<Vec<u8>> {
        let options = self.rar13_options();
        if self.store {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rar13::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar13_attr(),
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rar13::write_stored_archive_with_comment(&entries, options, self.comment.as_deref())
        } else {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rar13::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar13_attr(),
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rar13::write_compressed_archive_with_comment_and_progress(
                &entries,
                options,
                self.comment.as_deref(),
                progress,
            )
        }
    }

    fn build_rar50_volumes(
        &self,
        volume_size: usize,
        progress: Option<&dyn WriteProgress>,
    ) -> Result<Vec<Vec<u8>>> {
        if self.comment.is_some() {
            return Err(Error::InvalidHeader(
                "RAR 5 volume comments are not supported",
            ));
        }
        let mut sink = rar50::CollectedVolumes::new();
        rar50::write_streaming_volumes_with_progress(
            &self.rar50_entries(),
            self.rar50_options(),
            rar50::ArchiveExtras::default()
                .with_recovery_percent(self.recovery_percent)
                .with_filter_policy(self.rar50_filter_policy()),
            volume_size as u64,
            &mut sink,
            &WriterResources::default(),
            progress,
        )?;
        Ok(sink.take())
    }

    fn single_volume_entry(&self) -> Result<&BuilderEntry> {
        match self.entries.as_slice() {
            [entry] => Ok(entry),
            _ => Err(Error::InvalidHeader("legacy volumes support one input")),
        }
    }

    fn build_rar15_volumes(
        &self,
        volume_size: usize,
        progress: Option<&dyn WriteProgress>,
    ) -> Result<Vec<Vec<u8>>> {
        let entry = self.single_volume_entry()?;
        let options = self.rar15_options();
        if self.store {
            rar15_40::write_stored_volumes(
                rar15_40::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar15_attr(),
                    host_os: entry.rar15_host_os(),
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
            )
        } else {
            rar15_40::write_compressed_volumes_with_progress(
                rar15_40::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar15_attr(),
                    host_os: entry.rar15_host_os(),
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
                progress,
            )
        }
    }

    fn build_rar13_volumes(
        &self,
        volume_size: usize,
        progress: Option<&dyn WriteProgress>,
    ) -> Result<Vec<Vec<u8>>> {
        let entry = self.single_volume_entry()?;
        let options = self.rar13_options();
        if self.store {
            rar13::write_stored_volumes(
                rar13::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar13_attr(),
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
            )
        } else {
            rar13::write_compressed_volumes_with_progress(
                rar13::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: entry.rar13_attr(),
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
                progress,
            )
        }
    }
}

/// Reject a member name that would not survive extraction: absolute paths,
/// `..`, drive letters and NUL bytes. Checking on the way in means an archive
/// this crate writes is one this crate will extract, rather than one that trips
/// the extractor's own guard later.
pub fn validate_entry_name(name: Vec<u8>) -> Result<Vec<u8>> {
    entry_relative_path(&name)?;
    Ok(name)
}

/// The path a member name denotes below an output directory, or an error if it
/// denotes anywhere else. Backslashes are separators, because that is what a
/// DOS-era writer put in the header.
pub fn entry_relative_path(name: &[u8]) -> Result<std::path::PathBuf> {
    use std::path::{Component, PathBuf};

    if name.contains(&0) {
        return Err(Error::InvalidHeader(
            "unsafe archive path contains NUL byte",
        ));
    }
    let text = std::str::from_utf8(name)
        .map_err(|_| Error::InvalidHeader("archive entry name is not UTF-8"))?
        .replace('\\', "/");
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(Error::InvalidHeader("unsafe archive path"));
    }
    let mut out = PathBuf::new();
    for component in Path::new(&text).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(Error::InvalidHeader("unsafe archive path")),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(Error::InvalidHeader("empty archive path"));
    }
    Ok(out)
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builder_with(format: ArchiveVersion) -> Builder {
        let mut builder = Builder::new(format);
        builder
            .add_bytes(b"a.txt".to_vec(), b"hello world".repeat(64), None, None)
            .unwrap();
        builder
            .add_bytes(b"dir/b.txt".to_vec(), b"second member".to_vec(), None, None)
            .unwrap();
        builder
    }

    /// Every version this crate can write, which is all of them. The loop is
    /// over `ArchiveVersion::ALL` so a tenth version is a failing test rather
    /// than a gap.
    #[test]
    fn writes_every_family() {
        for format in ArchiveVersion::ALL {
            let archive = builder_with(format).to_bytes().unwrap();
            let read = crate::ArchiveReader::read_owned(archive).unwrap();
            let names: Vec<_> = read
                .members()
                .map(|member| member.meta.name_bytes().to_vec())
                .collect();
            assert_eq!(
                names,
                vec![b"a.txt".to_vec(), b"dir/b.txt".to_vec()],
                "{format}"
            );
        }
    }

    #[test]
    fn stored_and_compressed_round_trip_to_the_same_bytes() {
        for store in [false, true] {
            let archive = builder_with(ArchiveVersion::Rar50)
                .store(store)
                .to_bytes()
                .unwrap();
            let read = crate::ArchiveReader::read_owned(archive).unwrap();
            let data = read.read_member(b"a.txt", None).unwrap().unwrap();
            assert_eq!(data, b"hello world".repeat(64));
        }
    }

    #[test]
    fn rejects_a_duplicate_name() {
        let mut builder = Builder::new(ArchiveVersion::Rar50);
        builder
            .add_bytes(b"a".to_vec(), vec![], None, None)
            .unwrap();
        let error = builder
            .add_bytes(b"a".to_vec(), vec![], None, None)
            .unwrap_err();
        assert!(error.to_string().contains("duplicate archive entry name"));
        assert_eq!(builder.names().collect::<Vec<_>>(), vec![&b"a"[..]]);
    }

    #[test]
    fn rejected_edits_preserve_a_usable_archive() {
        let mut builder = builder_with(ArchiveVersion::Rar50).store(true);
        let before = builder.to_bytes().unwrap();
        assert!(builder.rename(b"a.txt", b"dir/b.txt".to_vec()).is_err());
        assert_eq!(builder.to_bytes().unwrap(), before);
        assert!(builder
            .add_bytes(b"a.txt".to_vec(), b"replacement".to_vec(), None, None)
            .is_err());
        assert_eq!(builder.to_bytes().unwrap(), before);

        builder.rename(b"a.txt", b"a.txt".to_vec()).unwrap();
        assert_eq!(builder.to_bytes().unwrap(), before);
        builder.rename(b"a.txt", b"renamed.txt".to_vec()).unwrap();
        let archive = crate::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(
            archive.read_member(b"renamed.txt", None).unwrap().unwrap(),
            b"hello world".repeat(64)
        );
    }

    #[test]
    fn rejects_an_escaping_name() {
        let mut builder = Builder::new(ArchiveVersion::Rar50);
        for name in [&b"../escape"[..], b"/absolute", b"C:\\drive"] {
            assert!(builder
                .add_bytes(name.to_vec(), vec![], None, None)
                .is_err());
        }
    }

    #[test]
    fn renames_and_removes() {
        let mut builder = builder_with(ArchiveVersion::Rar50);
        builder.rename(b"a.txt", b"c.txt".to_vec()).unwrap();
        builder.remove(b"dir/b.txt").unwrap();
        assert_eq!(builder.names().collect::<Vec<_>>(), vec![&b"c.txt"[..]]);
        assert!(builder.remove(b"gone").is_err());
        assert!(builder.rename(b"gone", b"x".to_vec()).is_err());
    }

    #[test]
    fn refuses_a_single_archive_when_a_volume_size_is_set() {
        let error = builder_with(ArchiveVersion::Rar50)
            .volume_size(Some(4096))
            .to_bytes()
            .unwrap_err();
        assert!(error.to_string().contains("build_volumes"));
    }

    #[test]
    fn splits_into_volumes() {
        let mut builder = Builder::new(ArchiveVersion::Rar50);
        builder
            .add_bytes(b"big.bin".to_vec(), vec![7u8; 300_000], None, None)
            .unwrap();
        let volumes = builder
            .store(true)
            .volume_size(Some(64 * 1024))
            .build_volumes(None)
            .unwrap();
        assert!(volumes.len() > 1, "expected a split, got {}", volumes.len());
    }
}
