//! High-level RAR archive API.
//!
//! This crate is the supported public Rust API for `rars`. It is the facade
//! over the version-specific format modules, detects archive families, exposes
//! common member metadata, and streams extraction or recovery output to
//! caller-provided writers without requiring callers to buffer whole archives
//! in memory. New Rust users should depend on this crate rather than the
//! lower-level `rars-*` implementation crates, which ended at 0.3.x.

/// Where the unit tests write their files. Shared with the integration tests
/// by path rather than by API.
#[cfg(test)]
#[path = "../tests/support/scratch.rs"]
mod scratch;

pub mod builder;
#[doc(hidden)]
pub mod codec;
pub mod crc32;
#[doc(hidden)]
pub mod crypto;
pub mod detect;
pub mod error;
mod fast;
pub mod features;
pub mod filename;
pub mod filter;
mod filter_search;
mod io_util;
mod output_limit;
mod parallel;
mod parse_budget;
mod read_control;
pub use read_control::ReadCancellation;
pub mod rar13;
pub mod rar15_40;
pub mod rar50;
#[doc(hidden)]
pub mod recovery;
mod rewrite;
mod source;
mod streaming;
pub mod timestamp;
mod tzif;
pub mod version;
mod volume_extract;
pub mod write_plan;
mod write_progress;
mod write_stream;
mod x86_filter_scan;

pub use builder::{entry_relative_path, validate_entry_name, Builder};
pub use detect::{detect_archive_family, find_archive_start, ArchiveSignature, SFX_SCAN_LIMIT};
pub use error::{Error, ErrorKind, Result};
pub use features::{Feature, FeatureSet};
pub use filter::{
    formats_supporting_filter, FilterKind, FilterPolicy, FilterSpec, UnsupportedFilterKind,
};
use std::io::{Read, Write};
use std::path::Path;
pub use streaming::{
    EntryReader, EntrySource, WriteCancellation, WriterResources, DEFAULT_WRITER_MEMORY_LIMIT,
};
pub use timestamp::StoredTimestamp;
pub use version::{ArchiveFamily, ArchiveVersion};
pub use write_plan::{
    formats_supporting, supported_features, supports, MemberCoding, PlanShape, WriterOption,
};
pub use write_progress::{WriteOperation, WriteProgress, WriteProgressEvent};

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Options used while parsing or extracting archives.
pub struct ArchiveReadOptions<'a> {
    /// Password bytes used for encrypted headers or payloads.
    pub password: Option<&'a [u8]>,
    /// Cooperative cancellation for this parsing or extraction call. Parsing
    /// does not retain the token for later extraction. A cancelled token stays
    /// cancelled; use a new token for a new operation. Partial output may remain.
    /// Blocked caller I/O and indivisible library work cannot be preempted.
    pub cancellation: Option<&'a ReadCancellation>,
    /// Inclusive top-level header count for one physical archive parse.
    /// Counts main, encryption, file/directory, service, unknown and end headers;
    /// standalone signatures/markers and nested records are not separate headers.
    /// None preserves defaults; zero refuses even an empty archive's main header.
    /// Each parsing call (including each independently parsed volume) starts fresh.
    /// Extraction does not apply this policy retroactively.
    pub max_header_count: Option<u64>,
    /// Inclusive cumulative plaintext header bytes for one physical archive parse.
    /// Includes CRC/size fields, names and extras; nested records count once in
    /// their enclosing header. Excludes payloads, SFX and standalone signatures,
    /// and encryption salt/IV/padding. RAR1.3's embedded signature counts as part
    /// of its main header. Encrypted sizes require first-block decryption.
    ///
    /// Admission precedes full-header allocation; bounded prefixes and encryption
    /// framing can consume additional space. This is not a total RAM/CPU limit:
    /// source copies, metadata overhead and key derivation are outside the quota.
    /// None preserves defaults; zero refuses the main header. Resets per parse,
    /// not across a caller's separately parsed volume set. No partial Archive is
    /// returned on refusal. Existing end-record and tolerant-tail handling stays.
    pub max_header_bytes: Option<u64>,
    /// Optional RAR 5 whole-member buffered decode limit, including logical
    /// members split across volumes. This does not bound decoder dictionaries.
    ///
    /// Filtered RAR 5 members need whole-member transforms. Compressed members
    /// above this limit use the streaming path and reject filtered streams
    /// with a typed buffered-decode-limit error instead of buffering the full member.
    pub rar50_buffered_decode_limit: Option<u64>,
    /// Inclusive ceiling on a compressed RAR5/7 member's declared dictionary size.
    /// `None` leaves dictionary sizes unrestricted; zero rejects compressed members.
    /// Stored entries, directories and redirections are exempt. This is not a
    /// total-memory budget: history copies, buffered output and parallel jobs
    /// consume additional memory.
    ///
    /// Supply this option to extraction, including volume extraction. Parsing
    /// does not retain it. Legacy formats, comment/recovery helpers and direct
    /// codec calls are outside its scope. Earlier members may already be emitted
    /// when a later member exceeds the limit; its output callback is not opened.
    pub rar50_dictionary_size_limit: Option<u64>,
    /// Inclusive logical member output ceiling for every archive family, independent of RAM usage.
    /// None preserves defaults; zero permits empty output. Apply to extraction,
    /// not parsing. Known oversized members and unsupported unknown-size members
    /// are refused before opening output. Runtime failures can leave partial output.
    /// The ceiling resets per logical member, not per volume fragment. Discarding
    /// a solid member's bytes does not exempt it; retries and history copies are
    /// not counted twice. Direct codecs, password-only default wrappers and
    /// comment/recovery helpers are outside this explicit policy.
    pub max_member_output_bytes: Option<u64>,
    /// Inclusive total logical output ceiling for one extraction call, across
    /// all members and volumes. Counts bytes accepted by output writers, including
    /// discarded solid contents; retries and history copies do not count twice.
    /// None preserves defaults; zero permits empty output. Known sizes are
    /// admitted before opening output; unknown-size logical members are refused.
    /// Errors can leave earlier output and a failing member's prefix.
    /// Short writes charge only accepted bytes; refused chunks need not fill
    /// the remaining allowance. A per-member refusal takes precedence when both
    /// output ceilings reject the same admission or write. Separate extraction
    /// calls, including calls for nested archives, do not share this budget.
    ///
    /// Configuring this option makes parallel entry points extract sequentially
    /// for deterministic admission and accounting. This can reduce throughput.
    /// It is not a CPU/RAM budget: buffered decoding can precede the output guard.
    /// Parsing does not retain policy; password-only wrappers, direct codecs and
    /// comment/recovery helpers keep defaults. Each extraction starts a new budget.
    pub max_total_output_bytes: Option<u64>,
}

impl<'a> ArchiveReadOptions<'a> {
    /// Uses a shared cancellation signal without retaining policy in the archive.
    pub fn with_cancellation(mut self, token: &'a ReadCancellation) -> Self {
        self.cancellation = Some(token);
        self
    }

    pub(crate) fn check_cancelled(&self) -> Result<()> {
        if self
            .cancellation
            .is_some_and(ReadCancellation::is_cancelled)
        {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
    /// Creates read options without a password.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the top-level header ceiling for each physical archive parse.
    pub fn with_max_header_count(mut self, limit: u64) -> Self {
        self.max_header_count = Some(limit);
        self
    }

    /// Sets the cumulative plaintext-header byte ceiling for each parse.
    pub fn with_max_header_bytes(mut self, limit: u64) -> Self {
        self.max_header_bytes = Some(limit);
        self
    }

    /// Creates read options with a password.
    pub fn with_password(password: &'a [u8]) -> Self {
        Self {
            password: Some(password),
            ..Self::default()
        }
    }

    /// Creates read options with an optional password.
    pub fn with_optional_password(password: Option<&'a [u8]>) -> Self {
        Self {
            password,
            ..Self::default()
        }
    }

    /// Sets the logical member output ceiling.
    pub fn with_max_member_output_bytes(mut self, limit: u64) -> Self {
        self.max_member_output_bytes = Some(limit);
        self
    }

    /// Sets the total logical output ceiling and selects sequential extraction.
    pub fn with_max_total_output_bytes(mut self, limit: u64) -> Self {
        self.max_total_output_bytes = Some(limit);
        self
    }

    /// Sets the RAR5/7 declared dictionary-size ceiling for member extraction.
    pub fn with_rar50_dictionary_size_limit(mut self, limit: u64) -> Self {
        self.rar50_dictionary_size_limit = Some(limit);
        self
    }

    /// Sets the RAR 5 whole-member buffered decode limit.
    pub fn with_rar50_buffered_decode_limit(mut self, limit: u64) -> Self {
        self.rar50_buffered_decode_limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A parsed RAR archive, preserving the concrete archive family.
pub enum Archive {
    /// RAR 1.3/1.4 archive.
    Rar13(rar13::Archive),
    /// RAR 1.5 through RAR 4.x archive.
    Rar15To40(rar15_40::Archive),
    /// RAR 5.0 or later archive, including RAR 7 archives.
    Rar50Plus(rar50::Archive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Metadata supplied to streaming extraction callbacks.
pub struct ExtractedEntryMeta {
    /// Raw entry name bytes as stored by the archive family.
    pub name: Vec<u8>,
    /// Stored modification time: DOS/FAT for legacy RAR, Unix seconds for RAR5.
    /// `None` means absent; `Some(0)` is a valid RAR5 Unix epoch timestamp.
    pub file_time: Option<u32>,
    /// File attributes widened to a common integer type, exactly as stored.
    pub file_attr: u64,
    /// How to read `file_attr`, from the host OS the entry records.
    pub attr_source: AttrSource,
    /// Detail `file_time` is too coarse to hold, when the archive carries it.
    pub mtime_refinement: Option<TimeRefinement>,
    /// Whether the entry is a directory.
    pub is_directory: bool,
}

impl ExtractedEntryMeta {
    /// Creates common metadata for extraction callbacks.
    /// Pass `None` for an absent timestamp; a numeric value means it is present.
    pub fn new(
        name: Vec<u8>,
        file_time: impl Into<Option<u32>>,
        file_attr: u64,
        is_directory: bool,
    ) -> Self {
        Self {
            name,
            file_time: file_time.into(),
            file_attr,
            attr_source: AttrSource::Unknown,
            mtime_refinement: None,
            is_directory,
        }
    }

    /// Records how `file_attr` should be read.
    #[must_use]
    pub fn with_attr_source(mut self, attr_source: AttrSource) -> Self {
        self.attr_source = attr_source;
        self
    }

    /// Records detail `file_time` is too coarse to hold.
    #[must_use]
    pub fn with_mtime_refinement(mut self, refinement: Option<TimeRefinement>) -> Self {
        self.mtime_refinement = refinement;
        self
    }

    /// Raw entry name bytes as stored by the archive family.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the entry name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Common member view plus family-specific detail.
pub struct ArchiveMember {
    /// Metadata shared across archive families.
    pub meta: ArchiveMemberMeta,
    /// Extra metadata that is meaningful only for one archive family.
    pub detail: ArchiveMemberDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Family-independent metadata for a file-like archive member.
pub struct ArchiveMemberMeta {
    /// Archive family that produced this member.
    pub family: ArchiveFamily,
    /// Raw entry name bytes as stored by the archive.
    pub name: Vec<u8>,
    /// Packed payload size in bytes.
    pub packed_size: u64,
    /// Unpacked file size in bytes.
    pub unpacked_size: u64,
    /// DOS local wall-clock fields for RAR 1.3-4.x, or Unix seconds for RAR5.
    /// RAR5 includes the extended modification-time fallback; `None` is distinct
    /// from an explicitly stored Unix epoch (`Some(0)`).
    pub file_time: Option<u32>,
    /// Odd-second and subsecond detail, kept separate from the raw time field.
    pub mtime_refinement: Option<TimeRefinement>,
    /// File attributes widened to a common integer type.
    pub file_attr: u64,
    /// Host OS discriminator when present in the archive format.
    pub host_os: Option<u64>,
    /// Whether the member is a directory.
    pub is_directory: bool,
    /// Whether the member carries a RAR5 link or other redirection record.
    pub is_redirection: bool,
    /// Whether the member payload is encrypted.
    pub is_encrypted: bool,
    /// Whether the member payload is stored without compression.
    pub is_stored: bool,
    /// Whether the member continues from a previous volume.
    pub is_split_before: bool,
    /// Whether the member continues into the next volume.
    pub is_split_after: bool,
}

impl ArchiveMemberMeta {
    /// Stored modification time with its encoding attached, before refinements.
    ///
    /// Legacy DOS values remain local wall-clock fields; RAR5 values are Unix
    /// seconds, including the existing extended-time fallback. This accessor
    /// does not validate or reinterpret the raw value. Absence stays `None`,
    /// and odd-second/subsecond detail remains in `mtime_refinement`.
    pub fn stored_modification_time(&self) -> Option<StoredTimestamp> {
        self.file_time
            .map(|raw| StoredTimestamp::from_family(self.family, raw))
    }

    /// Modification time as an instant. Legacy DOS values use the same local
    /// zone and refinement policy as CLI extraction; RAR5 values are absolute.
    pub fn modification_time(&self) -> Option<std::time::SystemTime> {
        let raw = self.file_time?;
        if self.family == ArchiveFamily::Rar50Plus {
            let nanos = self.mtime_refinement.map_or(0, |detail| detail.nanoseconds);
            return std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::new(u64::from(raw), nanos));
        }
        timestamp::extracted_system_time(self.family, Some(raw), self.mtime_refinement)
    }

    /// How to interpret this member's attributes, using the archive family's
    /// host numbering and the same compatibility rules as extraction.
    pub fn attr_source(&self) -> AttrSource {
        match self.family {
            ArchiveFamily::Rar13 => AttrSource::Dos,
            ArchiveFamily::Rar15To40 => self
                .host_os
                .and_then(|host| u8::try_from(host).ok())
                .map(AttrSource::rar15_40)
                .unwrap_or_default(),
            ArchiveFamily::Rar50Plus => self.host_os.map(AttrSource::rar50).unwrap_or_default(),
        }
    }

    /// Raw member name bytes as stored by the archive family.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the member name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Family-specific member metadata.
pub enum ArchiveMemberDetail {
    /// RAR 1.3/1.4 member fields.
    #[non_exhaustive]
    Rar13 {
        /// Compression method byte from the file header.
        method: u8,
        /// Minimum unpacker version byte from the file header.
        unpack_version: u8,
        /// Legacy 16-bit file checksum.
        file_checksum: u16,
        /// Whether the member carries a file-comment extension.
        has_file_comment: bool,
    },
    /// RAR 1.5 through RAR 4.x member fields.
    #[non_exhaustive]
    Rar15To40 {
        /// Compression method byte from the file header.
        method: u8,
        /// Minimum unpacker version byte from the file header.
        unpack_version: u8,
        /// Stored CRC-32 of the unpacked data.
        crc32: u32,
        /// Whether this member participates in a solid stream.
        solid: bool,
        /// Per-file salt when file encryption is used.
        salt: Option<[u8; 8]>,
        /// Whether the member carries a file-comment extension.
        has_file_comment: bool,
    },
    /// RAR 5.0 and later member fields.
    #[non_exhaustive]
    Rar50Plus {
        /// Raw compression-info field from the RAR5 file header.
        compression_info: u64,
        /// Stored CRC-32 when present.
        crc32: Option<u32>,
        /// Strong file hash when present.
        hash: Option<ArchiveMemberHash>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Strong hash metadata attached to an archive member.
pub enum ArchiveMemberHash {
    /// RAR5 BLAKE2sp file hash.
    Blake2sp([u8; 32]),
    /// Unknown hash record retained for inspection.
    Other { hash_type: u64, data: Vec<u8> },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Lazy iterator returned by [`Archive::members`].
pub struct ArchiveMembers<'a> {
    inner: ArchiveMembersInner<'a>,
    index: usize,
}

#[derive(Debug, Clone)]
enum ArchiveMembersInner<'a> {
    Rar13(&'a [rar13::Entry]),
    Rar15To40(&'a [rar15_40::Block]),
    Rar50Plus(&'a [rar50::Block]),
}

impl Iterator for ArchiveMembers<'_> {
    type Item = ArchiveMember;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            ArchiveMembersInner::Rar13(entries) => {
                let entry = entries.get(self.index)?;
                self.index += 1;
                Some(rar13_member(entry))
            }
            ArchiveMembersInner::Rar15To40(blocks) => {
                while let Some(block) = blocks.get(self.index) {
                    self.index += 1;
                    if let rar15_40::Block::File(file) = block {
                        return Some(rar15_40_member(file));
                    }
                }
                None
            }
            ArchiveMembersInner::Rar50Plus(blocks) => {
                while let Some(block) = blocks.get(self.index) {
                    self.index += 1;
                    if let rar50::Block::File(file) = block {
                        return Some(rar50_member(file));
                    }
                }
                None
            }
        }
    }
}

/// A `Write` that appends into a buffer someone else holds, for the extraction
/// callbacks that hand their writer away and need the bytes back.
struct SharedBuffer(std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);

impl SharedBuffer {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Vec<u8>>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.lock()
            .get_or_insert_with(Vec::new)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Archive {
    /// Returns the detected archive family.
    pub fn family(&self) -> ArchiveFamily {
        match self {
            Self::Rar13(_) => ArchiveFamily::Rar13,
            Self::Rar15To40(_) => ArchiveFamily::Rar15To40,
            Self::Rar50Plus(_) => ArchiveFamily::Rar50Plus,
        }
    }

    /// Returns the byte offset where the RAR archive begins after any SFX stub.
    pub fn sfx_offset(&self) -> usize {
        match self {
            Self::Rar13(archive) => archive.sfx_offset,
            Self::Rar15To40(archive) => archive.sfx_offset,
            Self::Rar50Plus(archive) => archive.sfx_offset,
        }
    }

    /// Iterates over file-like members using a common cross-version metadata view.
    pub fn members(&self) -> ArchiveMembers<'_> {
        match self {
            Self::Rar13(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar13(&archive.entries),
                index: 0,
            },
            Self::Rar15To40(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar15To40(&archive.blocks),
                index: 0,
            },
            Self::Rar50Plus(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar50Plus(&archive.blocks),
                index: 0,
            },
        }
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_with_options(read_options(password), open)
    }

    /// Streams extracted entries to caller-provided writers with read options.
    pub fn extract_to_with_options<F>(
        &self,
        options: ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        options.check_cancelled()?;
        match self {
            Self::Rar13(archive) => {
                archive.extract_to_with_options(options, |meta| open(&rar13_meta(meta)))
            }
            Self::Rar15To40(archive) => {
                archive.extract_to(options, |meta| open(&rar15_40_meta(meta)))
            }
            Self::Rar50Plus(archive) => archive.extract_to(options, |meta| open(&rar50_meta(meta))),
        }
    }

    /// Extracts independent non-solid members in parallel, buffering decoded
    /// file bytes before replaying writes in archive order.
    ///
    /// Solid archives, split members, multivolume sets, and RAR 1.3/1.4
    /// archives use the regular streaming extractor.
    pub fn extract_to_parallel_buffered<F>(&self, password: Option<&[u8]>, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_parallel_buffered_with_options(read_options(password), open)
    }

    /// Extracts independent non-solid members in parallel with read options.
    /// A configured total output ceiling selects sequential extraction.
    pub fn extract_to_parallel_buffered_with_options<F>(
        &self,
        options: ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        options.check_cancelled()?;
        match self {
            Self::Rar13(archive) => {
                archive.extract_to_with_options(options, |meta| open(&rar13_meta(meta)))
            }
            Self::Rar15To40(archive) => {
                archive.extract_to_parallel_buffered(options, |meta| open(&rar15_40_meta(meta)))
            }
            Self::Rar50Plus(archive) => {
                archive.extract_to_parallel_buffered(options, |meta| open(&rar50_meta(meta)))
            }
        }
    }

    /// Returns one member's decoded bytes, or `None` when the archive has no
    /// file of that name.
    ///
    /// Extraction runs over the whole archive either way, because a solid
    /// member is only decodable after the ones before it. Reading several
    /// members from a solid archive one call at a time therefore costs as many
    /// full passes; use [`extract_to`](Self::extract_to) to take them all in
    /// one.
    pub fn read_member(&self, name: &[u8], password: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        // The closure gives the writer away rather than returning bytes, so the
        // member arrives through a buffer shared with it.
        let collected = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
        self.extract_to_parallel_buffered(password, |meta| {
            if meta.name != name || meta.is_directory {
                return Ok(Box::new(std::io::sink()) as Box<dyn Write>);
            }
            let sink = SharedBuffer(std::sync::Arc::clone(&collected));
            *sink.lock() = Some(Vec::new());
            Ok(Box::new(sink) as Box<dyn Write>)
        })?;
        let taken = collected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        Ok(taken)
    }

    /// Returns one member's decoded bytes by archive-order index.
    ///
    /// Unlike name lookup this remains unambiguous when an archive contains
    /// duplicate names or names that are not valid UTF-8.
    pub fn read_member_at(&self, index: usize, password: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let collected = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
        let current = std::cell::Cell::new(0usize);
        self.extract_to(password, |meta| {
            let this = current.get();
            current.set(this.saturating_add(1));
            if this != index || meta.is_directory {
                return Ok(Box::new(std::io::sink()) as Box<dyn Write>);
            }
            let sink = SharedBuffer(std::sync::Arc::clone(&collected));
            *sink.lock() = Some(Vec::new());
            Ok(Box::new(sink) as Box<dyn Write>)
        })?;
        let taken = collected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        Ok(taken)
    }

    /// Decodes every member and discards the bytes, so a bad checksum or a
    /// wrong password is reported and nothing is written.
    pub fn test(&self, password: Option<&[u8]>) -> Result<()> {
        self.extract_to_parallel_buffered(password, |_| {
            Ok(Box::new(std::io::sink()) as Box<dyn Write>)
        })
    }

    /// The archive comment, decrypting it when the archive is RAR 5 or later
    /// and its headers are encrypted.
    pub fn comment(&self, password: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Rar13(archive) => archive.archive_comment(),
            Self::Rar15To40(archive) => archive.archive_comment(),
            Self::Rar50Plus(archive) => archive.archive_comment_with_password(password),
        }
    }

    /// Returns full repaired archive bytes using the archive's embedded
    /// recovery records.
    pub fn repair_recovery(&self) -> Result<Vec<u8>> {
        Ok(self.repair_recovery_with_report(None)?.data)
    }

    /// Repaired archive bytes together with what the repair had to change.
    ///
    /// `password` unlocks the recovery record of a header-encrypted RAR 5
    /// archive, and frames its replacement end-of-archive header.
    pub fn repair_recovery_with_report(
        &self,
        password: Option<&[u8]>,
    ) -> Result<RecoveryRepairResult> {
        match self {
            Self::Rar15To40(archive) => archive.repair_protect_head_with_report(),
            Self::Rar50Plus(archive) => archive.repair_recovery_with_report(password),
            Self::Rar13(_) => Err(Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            }),
        }
    }

    /// Streams full repaired archive bytes to `writer` using embedded recovery
    /// records.
    pub fn repair_recovery_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.repair_recovery_to_with_report(writer, None)
            .map(|_| ())
    }

    pub fn repair_recovery_to_with_report(
        &self,
        writer: &mut dyn Write,
        password: Option<&[u8]>,
    ) -> Result<RecoveryRepairReport> {
        match self {
            Self::Rar15To40(archive) => {
                let repaired = archive.repair_protect_head_with_report()?;
                writer.write_all(&repaired.data)?;
                Ok(repaired.report)
            }
            Self::Rar50Plus(archive) => archive.repair_recovery_to_with_report(writer, password),
            Self::Rar13(_) => Err(Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            }),
        }
    }

    /// Returns the concrete RAR 1.3/1.4 archive when this archive has that family.
    pub fn as_rar13(&self) -> Option<&rar13::Archive> {
        match self {
            Self::Rar13(archive) => Some(archive),
            Self::Rar15To40(_) => None,
            Self::Rar50Plus(_) => None,
        }
    }

    /// Returns the concrete RAR 1.5 through RAR 4.x archive when applicable.
    pub fn as_rar15_40(&self) -> Option<&rar15_40::Archive> {
        match self {
            Self::Rar13(_) => None,
            Self::Rar15To40(archive) => Some(archive),
            Self::Rar50Plus(_) => None,
        }
    }

    /// Returns the concrete RAR 5.0 or later archive when applicable.
    pub fn as_rar50(&self) -> Option<&rar50::Archive> {
        match self {
            Self::Rar13(_) | Self::Rar15To40(_) => None,
            Self::Rar50Plus(archive) => Some(archive),
        }
    }
}

fn rar13_member(entry: &rar13::Entry) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar13,
            name: entry.name.clone(),
            packed_size: u64::from(entry.header.pack_size),
            unpacked_size: u64::from(entry.header.unp_size),
            file_time: Some(entry.header.file_time),
            mtime_refinement: None,
            file_attr: u64::from(entry.header.file_attr),
            host_os: None,
            is_directory: entry.is_directory(),
            is_redirection: false,
            is_encrypted: entry.is_encrypted(),
            is_stored: entry.is_stored(),
            is_split_before: entry.is_split_before(),
            is_split_after: entry.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar13 {
            method: entry.header.method,
            unpack_version: entry.header.unp_ver,
            file_checksum: entry.header.file_crc,
            has_file_comment: entry.has_file_comment(),
        },
    }
}

fn rar15_40_member(file: &rar15_40::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar15To40,
            name: file.name.clone(),
            packed_size: file.pack_size,
            unpacked_size: file.unp_size,
            file_time: Some(file.file_time),
            mtime_refinement: file.mtime_refinement(),
            file_attr: u64::from(file.attr),
            host_os: Some(u64::from(file.host_os)),
            is_directory: file.is_directory(),
            is_redirection: false,
            is_encrypted: file.is_encrypted(),
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar15To40 {
            method: file.method,
            unpack_version: file.unp_ver,
            crc32: file.file_crc,
            solid: file.is_solid(),
            salt: file.salt,
            has_file_comment: file.has_file_comment(),
        },
    }
}

fn rar50_member(file: &rar50::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar50Plus,
            name: file.name.clone(),
            packed_size: file.packed_size(),
            unpacked_size: file.unpacked_size,
            file_time: file.modification_time(),
            mtime_refinement: file.modification_time_refinement(),
            file_attr: file.attributes,
            host_os: Some(file.host_os),
            is_directory: file.is_directory(),
            is_redirection: file.is_redirection(),
            is_encrypted: file.encrypted,
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar50Plus {
            compression_info: file.compression_info,
            crc32: file.data_crc32,
            hash: file.hash.as_ref().map(rar50_member_hash),
        },
    }
}

fn rar50_member_hash(hash: &rar50::FileHash) -> ArchiveMemberHash {
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut data = [0; 32];
            data.copy_from_slice(&hash.data);
            ArchiveMemberHash::Blake2sp(data)
        }
        _ => ArchiveMemberHash::Other {
            hash_type: hash.hash_type,
            data: hash.data.clone(),
        },
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Archive reader facade with signature-based dispatch.
pub struct ArchiveReader;

/// Describes what an embedded recovery repair changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryRepairReport {
    pub changed: bool,
    pub data_repaired: bool,
    pub recovery_record_rebuilt: bool,
    pub end_record_rebuilt: bool,
    pub available_recovery_shards: Option<u64>,
    pub expected_recovery_shards: Option<u64>,
}

/// Repaired archive bytes together with a precise repair report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRepairResult {
    pub data: Vec<u8>,
    pub report: RecoveryRepairReport,
}

impl ArchiveReader {
    /// Detects the archive signature in a byte slice.
    pub fn detect(input: &[u8]) -> Result<ArchiveSignature> {
        detect_archive_family(input).ok_or(Error::UnsupportedSignature)
    }

    /// Parses an archive from memory with default read options.
    pub fn read(input: &[u8]) -> Result<Archive> {
        Self::read_with_options(input, ArchiveReadOptions::default())
    }

    /// Parses an archive from an owned memory buffer with default read options.
    pub fn read_owned(input: Vec<u8>) -> Result<Archive> {
        Self::read_owned_with_options(input, ArchiveReadOptions::default())
    }

    /// Parses an archive from memory using explicit read options.
    pub fn read_with_options(input: &[u8], options: ArchiveReadOptions<'_>) -> Result<Archive> {
        options.check_cancelled()?;
        let signature =
            find_archive_start(input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_with_options(
                input, options,
            )?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_with_options(input, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(rar50::Archive::parse_with_options(
                input, options,
            )?)),
        }
    }

    /// Parses an archive from an owned memory buffer using explicit read options.
    pub fn read_owned_with_options(
        input: Vec<u8>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        options.check_cancelled()?;
        let signature =
            find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_owned_with_options(
                input, options,
            )?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_owned_with_options(input, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(
                rar50::Archive::parse_owned_with_options(input, options)?,
            )),
        }
    }

    /// Parses an archive from a path with default read options.
    pub fn read_path(path: impl AsRef<Path>) -> Result<Archive> {
        Self::read_path_with_options(path, ArchiveReadOptions::default())
    }

    /// Parses an archive from a path using explicit read options.
    pub fn read_path_with_options(
        path: impl AsRef<Path>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        options.check_cancelled()?;
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        let mut scan = vec![0; len.min(SFX_SCAN_LIMIT as u64) as usize];
        file.read_exact(&mut scan)?;
        options.check_cancelled()?;
        let signature =
            find_archive_start(&scan, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(
                rar13::Archive::parse_path_with_signature_and_options(path, signature, options)?,
            )),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_path_with_signature(path, signature, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(
                rar50::Archive::parse_path_with_signature(path, signature, options)?,
            )),
        }
    }
}

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(archives: &[Archive], password: Option<&[u8]>, open: F) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_with_options(archives, read_options(password), open)
}

/// Streams a multivolume archive set to caller-provided writers with read options.
pub fn extract_volumes_to_with_options<F>(
    archives: &[Archive],
    options: ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    options.check_cancelled()?;
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };

    match first.family() {
        ArchiveFamily::Rar13 => {
            let typed = rar13_volumes(archives)?;
            rar13::extract_volumes_to_with_options(&typed, options, |meta| open(&rar13_meta(meta)))
        }
        ArchiveFamily::Rar15To40 => {
            let typed = rar15_40_volumes(archives)?;
            rar15_40::extract_volumes_to(&typed, options, |meta| open(&rar15_40_meta(meta)))
        }
        ArchiveFamily::Rar50Plus => {
            let typed = rar50_volumes(archives)?;
            rar50::extract_volumes_to(&typed, options, |meta| open(&rar50_meta(meta)))
        }
    }
}

/// Returns the logical members in a volume set in archive order.
///
/// Continuation headers are folded into the member that began on an earlier
/// volume. Packed sizes are accumulated across all fragments.
pub fn volume_members(archives: &[Archive]) -> Result<Vec<ArchiveMember>> {
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };
    if archives
        .iter()
        .any(|archive| archive.family() != first.family())
    {
        return Err(Error::InvalidHeader("mixed archive families in volume set"));
    }

    let mut members: Vec<ArchiveMember> = Vec::new();
    for archive in archives {
        for member in archive.members() {
            if member.meta.is_split_before {
                let Some(previous) = members.last_mut() else {
                    return Err(Error::InvalidHeader(
                        "volume set starts with a continuation",
                    ));
                };
                previous.meta.packed_size = previous
                    .meta
                    .packed_size
                    .saturating_add(member.meta.packed_size);
                previous.meta.is_split_after = member.meta.is_split_after;
            } else {
                members.push(member);
            }
        }
    }
    Ok(members)
}

/// Returns one logical member from a volume set by archive-order index.
pub fn read_volume_member_at(
    archives: &[Archive],
    index: usize,
    password: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    let collected = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
    let current = std::cell::Cell::new(0usize);
    extract_volumes_to(archives, password, |meta| {
        let this = current.get();
        current.set(this.saturating_add(1));
        if this != index || meta.is_directory {
            return Ok(Box::new(std::io::sink()) as Box<dyn Write>);
        }
        let sink = SharedBuffer(std::sync::Arc::clone(&collected));
        *sink.lock() = Some(Vec::new());
        Ok(Box::new(sink) as Box<dyn Write>)
    })?;
    let taken = collected
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    Ok(taken)
}

/// Detail a coarse timestamp cannot hold, carried alongside it.
///
/// A DOS timestamp counts in two-second steps, so RAR 1.5-4.x archives put the
/// odd second and any sub-second precision in a separate extended field. This
/// is that field decoded: add [`add_second`](Self::add_second) whole seconds
/// and then [`nanoseconds`](Self::nanoseconds) to the base time.
/// RAR5 extended times also use this detail, with `add_second` always false.
///
/// Kept apart from the timestamp rather than folded into it because
/// [`ExtractedEntryMeta::file_time`] is the DOS value as stored, which has
/// nowhere to put either part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeRefinement {
    /// Whether the true time is one second later than the DOS value.
    pub add_second: bool,
    /// Sub-second remainder, below 1_000_000_000.
    pub nanoseconds: u32,
}

/// How to read [`ExtractedEntryMeta::file_attr`], which depends on the host
/// that wrote the entry.
///
/// The grouping is measured, not assumed, because it is not the obvious one.
/// Against RAR 7.12 on Linux at umask 022, extracting one file with only
/// `HOST_OS` and `ATTR` changed:
///
/// | RAR 1.5-4.x `HOST_OS` | attr `0x21` | reading |
/// |---|---|---|
/// | 0 MS-DOS, 1 OS/2, 2 Win32, 4 Mac OS | 444 | DOS attributes |
/// | 3 Unix, 5 BeOS | 041 | raw `st_mode` |
/// | 6 WinCE, 7+ | 644 | ignored |
///
/// Mac OS sits with the DOS hosts and BeOS with the Unix ones, the reverse of
/// how the two are usually grouped. RAR 5.0 numbers its hosts separately: 0 is
/// Windows, 1 is Unix, and RAR 7.12 ignores the attributes of anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AttrSource {
    /// Windows `FILE_ATTRIBUTE_*` bits.
    Dos,
    /// POSIX `st_mode`.
    Unix,
    /// A host this build does not know; attributes carry no meaning.
    #[default]
    Unknown,
}

impl AttrSource {
    fn rar15_40(host_os: u8) -> Self {
        match host_os {
            0 | 1 | 2 | 4 => Self::Dos,
            3 | 5 => Self::Unix,
            _ => Self::Unknown,
        }
    }

    fn rar50(host_os: u64) -> Self {
        match host_os {
            0 => Self::Dos,
            1 => Self::Unix,
            _ => Self::Unknown,
        }
    }
}

fn rar13_meta(meta: &rar13::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: Some(meta.file_time),
        file_attr: u64::from(meta.file_attr),
        // RAR 1.3/1.4 is MS-DOS only.
        attr_source: AttrSource::Dos,
        // RAR 1.3/1.4 predates the extended time field.
        mtime_refinement: None,
        is_directory: meta.is_directory,
    }
}

fn rar15_40_meta(meta: &rar15_40::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: Some(meta.file_time),
        file_attr: u64::from(meta.attr),
        attr_source: AttrSource::rar15_40(meta.host_os),
        mtime_refinement: meta.mtime_refinement,
        is_directory: meta.is_directory,
    }
}

/// Converts RAR 5.0 entry metadata into the common form, resolving the
/// attributes against the host OS as extraction needs them.
///
/// Public so a caller doing its own extraction gets the same resolution the
/// built-in paths do; getting it wrong loses the read-only bit or applies a
/// Windows attribute word as a Unix mode.
pub fn rar50_meta(meta: &rar50::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: meta.attr,
        attr_source: AttrSource::rar50(meta.host_os),
        mtime_refinement: meta.mtime_refinement,
        is_directory: meta.is_directory,
    }
}

fn rar13_volumes(archives: &[Archive]) -> Result<Vec<rar13::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar13(archive) => Ok(archive.clone()),
            Archive::Rar15To40(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar15_40_volumes(archives: &[Archive]) -> Result<Vec<rar15_40::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar15To40(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar50_volumes(archives: &[Archive]) -> Result<Vec<rar50::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar50Plus(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar15To40(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    #[test]
    fn member_mtime_matches_rar50_extraction_without_losing_absence() {
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"time".to_vec(), vec![], None, None)
            .unwrap();
        let archive = rar50::Archive::parse(&builder.to_bytes().unwrap()).unwrap();
        let mut file = archive.files().next().unwrap().clone();
        for (base, extended, expected) in [
            (None, None, None),
            (Some(0), None, Some(0)),
            (None, Some(0), Some(0)),
            (None, Some(1_700_000_002), Some(1_700_000_002)),
            (Some(123), Some(456), Some(123)),
            (Some(0), Some(456), Some(0)),
        ] {
            file.mtime = base;
            file.htime_mtime = extended;
            assert_eq!(rar50_member(&file).meta.file_time, expected);
            assert_eq!(
                rar50_member(&file).meta.stored_modification_time(),
                expected.map(StoredTimestamp::UnixSeconds)
            );
            assert_eq!(file.metadata().file_time, expected);
        }
    }

    struct CollectWriter {
        data: Rc<RefCell<Vec<u8>>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    // Historical numeric snapshots; timestamp presence has dedicated regression tests.
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        file_attr: u64,
        is_directory: bool,
    }

    fn deterministic_noise(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    fn rar15_40_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar15_40")
            .join(name)
    }

    /// Which hosts store DOS attributes and which store `st_mode` is measured
    /// against RAR 7.12, and the grouping is not the obvious one: Mac OS reads
    /// as a DOS host and BeOS as a Unix one.
    #[test]
    fn attr_source_follows_the_measured_host_grouping() {
        for host in [0u8, 1, 2, 4] {
            assert_eq!(AttrSource::rar15_40(host), AttrSource::Dos, "host {host}");
        }
        for host in [3u8, 5] {
            assert_eq!(AttrSource::rar15_40(host), AttrSource::Unix, "host {host}");
        }
        for host in [6u8, 7, 255] {
            assert_eq!(
                AttrSource::rar15_40(host),
                AttrSource::Unknown,
                "host {host}"
            );
        }

        assert_eq!(AttrSource::rar50(0), AttrSource::Dos);
        assert_eq!(AttrSource::rar50(1), AttrSource::Unix);
        for host in [2u64, 5, 99] {
            assert_eq!(AttrSource::rar50(host), AttrSource::Unknown, "host {host}");
        }

        // A caller building metadata by hand gets no host, and no host means
        // no attribute is applied rather than one guessed at.
        assert_eq!(
            ExtractedEntryMeta::new(b"x".to_vec(), 0, 0x21, false).attr_source,
            AttrSource::Unknown
        );
    }

    #[test]
    fn extracted_entry_meta_exposes_raw_and_lossy_names() {
        let meta = ExtractedEntryMeta {
            name: vec![0xff, b'.', b't', b'x', b't'],
            file_time: None,
            file_attr: 0,
            attr_source: AttrSource::Unknown,
            mtime_refinement: None,
            is_directory: false,
        };

        assert_eq!(meta.name_bytes(), [0xff, b'.', b't', b'x', b't']);
        assert_eq!(meta.name_lossy(), "\u{fffd}.txt");
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.data.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn collect_extract(archive: &Archive, password: Option<&[u8]>) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(password, |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time.unwrap_or(0),
                file_attr: meta.file_attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar15_40(archive: &rar15_40::Archive) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(ArchiveReadOptions::default(), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: u64::from(meta.attr),
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar15_40_volumes(
        archives: &[rar15_40::Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        rar15_40::extract_volumes_to(archives, read_options(password), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: u64::from(meta.attr),
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar50_volumes(
        archives: &[rar50::Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        rar50::extract_volumes_to(archives, read_options(password), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time.unwrap_or(0),
                file_attr: meta.attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar50_file(
        archive: &rar50::Archive,
        file: &rar50::FileHeader,
    ) -> Result<CollectedEntry> {
        let meta = file.metadata();
        let data = Rc::new(RefCell::new(Vec::new()));
        file.write_to(
            archive,
            None,
            &mut CollectWriter {
                data: Rc::clone(&data),
            },
        )?;
        let data = data.borrow().clone();
        Ok(CollectedEntry {
            name: meta.name,
            data,
            file_time: meta.file_time.unwrap_or(0),
            file_attr: meta.attr,
            is_directory: meta.is_directory,
        })
    }

    fn rar13_options(target: ArchiveVersion) -> rar13::WriterOptions {
        rar13::WriterOptions::new(target, FeatureSet::store_only())
    }

    fn rar15_options(target: ArchiveVersion) -> rar15_40::WriterOptions {
        rar15_options_with_features(target, FeatureSet::store_only())
    }

    fn rar15_options_with_features(
        target: ArchiveVersion,
        features: FeatureSet,
    ) -> rar15_40::WriterOptions {
        rar15_40::WriterOptions::new(target, features)
    }

    fn rar50_options(target: ArchiveVersion) -> rar50::WriterOptions {
        rar50_options_with_features(target, FeatureSet::store_only())
    }

    fn rar50_options_with_features(
        target: ArchiveVersion,
        features: FeatureSet,
    ) -> rar50::WriterOptions {
        rar50::WriterOptions::new(target, features)
    }

    /// Builds a member from bytes the test already holds.
    fn rar50_entry(name: &[u8], data: &[u8]) -> rar50::ArchiveEntry {
        rar50::ArchiveEntry::new(
            name.to_vec(),
            EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
        )
    }

    fn write_rar50_volume_set(
        entries: &[rar50::ArchiveEntry],
        options: rar50::WriterOptions,
        max_payload_per_volume: u64,
        recovery_percent: Option<u64>,
    ) -> Vec<Vec<u8>> {
        let mut sink = rar50::CollectedVolumes::new();
        rar50::write_streaming_volumes_to(
            entries,
            options,
            rar50::ArchiveExtras::default().with_recovery_percent(recovery_percent),
            max_payload_per_volume,
            &mut sink,
            &WriterResources::default(),
        )
        .unwrap();
        sink.take()
    }

    fn write_rar29_filter(
        options: rar15_40::WriterOptions,
        entries: &[rar15_40::FileEntry<'_>],
        kind: rar15_40::FilterKind,
    ) -> Result<Vec<u8>> {
        rar15_40::write_rar29_compressed_archive_with_filter_policy(
            entries,
            options,
            rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::whole(kind)),
        )
    }

    fn write_rar29_filter_range(
        options: rar15_40::WriterOptions,
        entries: &[rar15_40::FileEntry<'_>],
        kind: rar15_40::FilterKind,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<u8>> {
        rar15_40::write_rar29_compressed_archive_with_filter_policy(
            entries,
            options,
            rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::range(kind, range)),
        )
    }

    fn assert_rar50_volume_recovery_records(archives: &[rar50::Archive], percent: u64) {
        assert!(archives.iter().all(|archive| archive.main.is_volume()));
        assert!(archives
            .iter()
            .all(|archive| archive.main.has_recovery_record()));
        for archive in archives {
            let service = archive.services().next().unwrap();
            assert_eq!(service.name, b"RR");
            assert_eq!(service.recovery_record().unwrap().unwrap().percent, percent);
            let data = collect_rar50_file(archive, service).unwrap().data;
            assert!(data.starts_with(b"{RB}"));
            assert_eq!(
                u32::from_le_bytes(data[0x0c..0x10].try_into().unwrap()) as usize,
                data.len()
            );
        }
    }

    #[test]
    fn direct_writer_creates_rar15_stored_archive() {
        let bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"hello.txt",
                data: b"hello via facade\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, b"hello via facade\n");
    }

    #[test]
    fn archive_reader_accepts_owned_buffers_without_changing_dispatch() {
        let rar13_bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"owned rar13\n",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();
        let rar13_archive = ArchiveReader::read_owned(rar13_bytes).unwrap();
        assert_eq!(rar13_archive.family(), ArchiveFamily::Rar13);
        assert_eq!(
            collect_extract(&rar13_archive, None).unwrap()[0].data,
            b"owned rar13\n"
        );

        let rar15_bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"mid.txt",
                data: b"owned rar15\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();
        let rar15_archive = ArchiveReader::read_owned(rar15_bytes).unwrap();
        assert_eq!(rar15_archive.family(), ArchiveFamily::Rar15To40);
        assert_eq!(
            collect_extract(&rar15_archive, None).unwrap()[0].data,
            b"owned rar15\n"
        );

        let rar50_bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
                .entries(
                    [rar50_entry(b"new.txt", b"owned rar50\n")
                        .with_attributes(0x20)
                        .with_host_os(3)]
                    .to_vec(),
                )
                .finish()
                .unwrap();
        let rar50_archive = ArchiveReader::read_owned(rar50_bytes).unwrap();
        assert_eq!(rar50_archive.family(), ArchiveFamily::Rar50Plus);
        assert_eq!(
            collect_extract(&rar50_archive, None).unwrap()[0].data,
            b"owned rar50\n"
        );
    }

    #[test]
    fn direct_writer_keeps_rar13_methods_version_typed() {
        let err =
            rar13::write_stored_archive(&[], rar13_options(ArchiveVersion::Rar15)).unwrap_err();

        assert!(matches!(
            err,
            Error::UnsupportedVersion(ArchiveVersion::Rar15)
        ));
    }

    #[test]
    fn archive_members_exposes_rar13_common_metadata_and_typed_detail() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"old rar member",
                file_time: 0x1234_5678,
                file_attr: 0x20,
                password: None,
                file_comment: Some(b"note"),
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar13);
        assert_eq!(members[0].meta.name, b"old.txt");
        assert_eq!(members[0].meta.name_bytes(), b"old.txt");
        assert_eq!(members[0].meta.name_lossy(), "old.txt");
        assert_eq!(members[0].meta.packed_size, b"old rar member".len() as u64);
        assert_eq!(
            members[0].meta.unpacked_size,
            b"old rar member".len() as u64
        );
        assert_eq!(members[0].meta.file_time, Some(0x1234_5678));
        assert_eq!(members[0].meta.file_attr, 0x20);
        assert_eq!(members[0].meta.host_os, None);
        assert!(members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(!members[0].meta.is_split_before);
        assert!(!members[0].meta.is_split_after);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar13 {
                method: 0,
                unpack_version: _,
                file_checksum: _,
                has_file_comment: true,
            }
        ));
    }

    #[test]
    fn archive_members_exposes_rar15_40_common_metadata_and_typed_detail() {
        let features = FeatureSet::store_only();
        let payload = b"rar 2.9 member metadata ".repeat(32);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"newer.txt",
                data: &payload,
                file_time: 0x0102_0304,
                file_attr: 0x20,
                host_os: 2,
                password: None,
                file_comment: Some(b"rar29 note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar15To40);
        assert_eq!(members[0].meta.name, b"newer.txt");
        assert_eq!(members[0].meta.unpacked_size, payload.len() as u64);
        assert_eq!(members[0].meta.file_time, Some(0x0102_0304));
        assert_eq!(members[0].meta.file_attr, 0x20);
        assert_eq!(members[0].meta.host_os, Some(2));
        assert!(!members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar15To40 {
                method: 0x33 | 0x35,
                unpack_version: 29,
                crc32: _,
                solid: false,
                salt: None,
                has_file_comment: true,
            }
        ));
    }

    #[test]
    fn archive_members_exposes_rar50_common_metadata_and_typed_detail() {
        let bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
                .entries(
                    [rar50_entry(b"five.txt", b"rar 5 member metadata")
                        .with_mtime(Some(0x1111_2222))
                        .with_attributes(0x1_0000_0020)
                        .with_host_os(3)]
                    .to_vec(),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let members: Vec<_> = archive.members().collect();

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.family, ArchiveFamily::Rar50Plus);
        assert_eq!(members[0].meta.name, b"five.txt");
        assert_eq!(
            members[0].meta.packed_size,
            b"rar 5 member metadata".len() as u64
        );
        assert_eq!(
            members[0].meta.unpacked_size,
            b"rar 5 member metadata".len() as u64
        );
        assert_eq!(members[0].meta.file_time, Some(0x1111_2222));
        assert_eq!(members[0].meta.file_attr, 0x1_0000_0020);
        assert_eq!(members[0].meta.host_os, Some(3));
        assert!(members[0].meta.is_stored);
        assert!(!members[0].meta.is_encrypted);
        assert!(matches!(
            members[0].detail,
            ArchiveMemberDetail::Rar50Plus {
                compression_info: _,
                crc32: _,
                hash: _,
            }
        ));
    }

    #[test]
    fn extraction_metadata_preserves_rar50_u64_file_attributes() {
        let bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
                .entries(
                    [rar50_entry(b"wide-attrs.txt", b"wide RAR5 file attributes")
                        .with_mtime(Some(0))
                        .with_attributes(0x1_0000_0020)
                        .with_host_os(3)]
                    .to_vec(),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();

        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"wide-attrs.txt");
        assert_eq!(extracted[0].file_attr, 0x1_0000_0020);
    }

    #[test]
    fn direct_writer_creates_rar15_compressed_archive() {
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"text.txt",
                data: b"facade compressed facade compressed facade compressed\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade compressed facade compressed facade compressed\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar29_compressed_archive_with_default_auto_policy() {
        let payload =
            b"facade rar29 default auto text alpha beta gamma alpha beta gamma\n".repeat(256);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29-default-auto.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        // The byte is the level that was asked for, and nothing here asked for
        // one, so it is the default 0x33. Which engine answered is signalled in
        // the stream, which is why the round trip below is what proves PPMd
        // read back. WinRAR stamps 0x34 on the PPMd archive it writes at -m4.
        assert_eq!(raw.files().next().unwrap().method, 0x33);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 e8 filter payload\n".repeat(12);
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_auto_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 auto filter payload\n".repeat(12);
        let bytes = rar15_40::write_rar29_compressed_archive_with_filter_policy(
            &[rar15_40::FileEntry {
                name: b"rar29-auto.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29),
            rar15_40::FilterPolicy::Auto,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_ppmd_compressed_archive() {
        let payload = b"facade rar29 ppmd text payload alpha beta gamma\n".repeat(64);
        let bytes = rar15_40::write_rar29_compressed_archive_with_filter_policy(
            &[rar15_40::FileEntry {
                name: b"rar29-ppmd.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29).with_method(rar15_40::Rar29Method::Ppmd),
            rar15_40::FilterPolicy::None,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        // Forcing PPMd does not change the level, so this is still the default
        // 0x33; extracting it is what shows PPMd was used.
        assert_eq!(file.method, 0x33);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_e8_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before x86 segment ".to_vec();
        let filter_start = payload.len();
        payload.extend_from_slice(b"\xe8\0\0\0\0facade segmented e8 filter payload\n");
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after x86 segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_solid_e8_filtered_compressed_archive() {
        let first = b"\xe8\0\0\0\0facade rar29 solid e8 first payload\n".repeat(12);
        let second = b"\xe8\0\0\0\0facade rar29 solid e8 second payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = write_rar29_filter(
            rar15_options_with_features(ArchiveVersion::Rar29, features),
            &[
                rar15_40::FileEntry {
                    name: b"rar29-solid-e8-first.bin",
                    data: &first,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"rar29-solid-e8-second.bin",
                    data: &second,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar29_encrypted_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar29 encrypted e8 payload\n".repeat(12);
        let features = FeatureSet::store_only();
        let bytes = write_rar29_filter(
            rar15_options_with_features(ArchiveVersion::Rar29, features),
            &[rar15_40::FileEntry {
                name: b"rar29-encrypted-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.is_encrypted());
        assert!(file.salt.is_some());
        assert!(matches!(
            collect_extract(&archive, Some(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar30_header_encrypted_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar30 header encrypted e8 payload\n".repeat(12);
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = write_rar29_filter(
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            &[rar15_40::FileEntry {
                name: b"rar30-header-encrypted-e8.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_40::FilterKind::E8,
        )
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_encrypted_headers());
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_e8e9_filtered_compressed_archive() {
        let payload = b"\xe9\0\0\0\0facade rar29 e8e9 filter payload\n".repeat(12);
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-e8e9.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::E8E9,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_delta_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..384).map(|index| (index * 19 + 5) as u8).collect();
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-delta.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Delta { channels: 3 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_delta_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before delta segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..384).map(|index| (index * 19 + 5) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after delta segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-delta.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Delta { channels: 3 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_itanium_filtered_compressed_archive() {
        let mut payload = vec![0u8; 48];
        payload[16] = 22;
        payload[21] = 20;
        payload.extend_from_slice(b"facade rar29 itanium filter payload\n");
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-itanium.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Itanium,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_itanium_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before itanium segment ".to_vec();
        let filter_start = payload.len();
        payload.extend_from_slice(&[0; 48]);
        payload[filter_start + 16] = 22;
        payload[filter_start + 21] = 20;
        payload.extend_from_slice(b"facade segmented itanium filter payload\n");
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after itanium segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-itanium.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Itanium,
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_rgb_filtered_compressed_archive() {
        let width = 12;
        let payload: Vec<u8> = (0..96).map(|index| (index * 37 + 17) as u8).collect();
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-rgb.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Rgb { width, pos_r: 0 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_rgb_filtered_compressed_archive() {
        let width = 12;
        let mut payload = b"facade unfiltered prefix before rgb segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..96).map(|index| (index * 37 + 17) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after rgb segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-rgb.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Rgb { width, pos_r: 0 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_audio_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..160)
            .map(|index| (index * 11 + index / 7) as u8)
            .collect();
        let bytes = write_rar29_filter(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-audio.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Audio { channels: 2 },
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_segmented_audio_filtered_compressed_archive() {
        let mut payload = b"facade unfiltered prefix before audio segment ".to_vec();
        let filter_start = payload.len();
        payload.extend((0..160).map(|index| (index * 11 + index / 7) as u8));
        let filter_end = payload.len();
        payload.extend_from_slice(b"facade unfiltered suffix after audio segment\n");
        let bytes = write_rar29_filter_range(
            rar15_options(ArchiveVersion::Rar29),
            &[rar15_40::FileEntry {
                name: b"rar29-segmented-audio.bin",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_40::FilterKind::Audio { channels: 2 },
            filter_start..filter_end,
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar20_compressed_archive() {
        let payload = b"facade rar20 literal compressed payload\n".repeat(32);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar20.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar20),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert_eq!(file.method, 0x33);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_compressed_archive() {
        let payload = b"facade rar29 literal compressed payload\n".repeat(32);
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29.txt",
                data: &payload,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar29),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert!(matches!(file.method, 0x33 | 0x35));
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar29_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: b"facade rar29 solid one alpha beta\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: b"facade rar29 solid two alpha beta\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar29, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.is_solid());
        let files: Vec<_> = raw.files().collect();
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar29 solid one alpha beta\n");
        assert_eq!(extracted[1].data, b"facade rar29 solid two alpha beta\n");
    }

    #[test]
    fn direct_writer_creates_rar20_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar20 solid shared line alpha beta gamma\n".repeat(48);
        let second = b"facade rar20 solid shared line alpha beta gamma\nsecond\n".repeat(24);
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: &first,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: &second,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar20, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.is_solid());
        let files: Vec<_> = raw.files().collect();
        assert_eq!(files[0].unp_ver, 20);
        assert_eq!(files[1].unp_ver, 20);
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar15_archive_comment() {
        let features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"commented.txt",
                data: b"facade commented payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
            Some(b"facade note\n"),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let archive = archive.as_rar15_40().unwrap();
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"facade note\n"[..])
        );
        assert_eq!(
            collect_rar15_40(archive).unwrap()[0].data,
            b"facade commented payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar15_file_comment() {
        let features = FeatureSet::store_only();
        let bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"file-comment.txt",
                data: b"facade file comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade file note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let archive = archive.as_rar15_40().unwrap();
        let file = archive.files().next().unwrap();
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(&b"facade file note"[..])
        );
        assert_eq!(
            collect_rar15_40(archive).unwrap()[0].data,
            b"facade file comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar20_old_style_comments() {
        let archive_features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"rar20-commented.txt",
                data: b"facade rar20 archive comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar20, archive_features),
            Some(b"facade rar20 archive note"),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_archive_comment());
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar20 archive note".as_slice())
        );

        let file_features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar20-file-commented.txt",
                data: b"facade rar20 file comment payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade rar20 file note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar20, file_features),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(b"facade rar20 file note".as_slice())
        );
    }

    #[test]
    fn direct_writer_creates_rar29_old_style_comments() {
        let archive_features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"rar29-commented.txt",
                data: b"facade rar29 archive comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, archive_features),
            Some(b"facade rar29 archive note"),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_archive_comment());
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar29 archive note".as_slice())
        );

        let file_features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29-file-commented.txt",
                data: b"facade rar29 file comment payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: Some(b"facade rar29 file note"),
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, file_features),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert_eq!(
            file.file_comment().unwrap().as_deref(),
            Some(b"facade rar29 file note".as_slice())
        );
    }

    #[test]
    fn direct_writer_creates_rar30_newsub_archive_comment() {
        let features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive_with_comment(
            &[rar15_40::FileEntry {
                name: b"rar30-commented.txt",
                data: b"facade rar30 NEWSUB archive comment payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            Some(b"facade rar30 NEWSUB note"),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(!raw.main.has_archive_comment());
        let subblock = raw.new_subs().next().unwrap();
        assert_eq!(subblock.kind, rar15_40::NewSubKind::ArchiveComment);
        assert_eq!(subblock.file.name, b"CMT");
        assert_eq!(
            raw.archive_comment().unwrap().as_deref(),
            Some(b"facade rar30 NEWSUB note".as_slice())
        );
    }

    #[test]
    fn direct_writer_creates_rar15_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"one.txt",
                    data: b"shared facade prefix one\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"two.txt",
                    data: b"shared facade prefix two\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: None,
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"shared facade prefix one\n");
        assert_eq!(extracted[1].data, b"shared facade prefix two\n");
    }

    #[test]
    fn direct_writer_creates_rar15_encrypted_compressed_archive() {
        let features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"secret.txt",
                data: b"facade encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar15, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade encrypted payload\n");
    }

    #[test]
    fn direct_writer_creates_rar15_stored_volumes() {
        let parts = rar15_40::write_stored_volumes(
            rar15_40::StoredEntry {
                name: b"split.bin",
                data: b"abcdefghijklmnopqrstuvwxyz0123456789",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar15),
            10,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let extracted = collect_rar15_40_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split.bin");
        assert_eq!(extracted[0].data, b"abcdefghijklmnopqrstuvwxyz0123456789");
    }

    #[test]
    fn direct_writer_creates_rar20_compressed_volumes() {
        let data = b"facade rar20 split phrase alpha beta gamma\n".repeat(32);
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar20.txt",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar20),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let first_file = archives[0].files().next().unwrap();
        assert_eq!(first_file.unp_ver, 20);
        assert!(first_file.is_split_after());

        let extracted = collect_rar15_40_volumes(&archives, None).unwrap();
        assert_eq!(extracted[0].name, b"split-rar20.txt");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn direct_writer_creates_rar29_compressed_volumes() {
        let data = b"facade rar29 split phrase alpha beta gamma\n".repeat(32);
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar29.txt",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_options(ArchiveVersion::Rar29),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();
        let first_file = archives[0].files().next().unwrap();
        assert_eq!(first_file.unp_ver, 29);
        assert!(first_file.is_split_after());

        let extracted = collect_rar15_40_volumes(&archives, None).unwrap();
        assert_eq!(extracted[0].name, b"split-rar29.txt");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn direct_writer_creates_rar29_encrypted_compressed_volumes() {
        let features = FeatureSet::store_only();
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar29-secret.txt",
                data: b"facade rar29 encrypted split facade rar29 encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar29, features),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            collect_rar15_40_volumes(&archives, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar29-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar29 encrypted split facade rar29 encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar15_encrypted_compressed_volumes() {
        let features = FeatureSet::store_only();
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-secret.txt",
                data: b"facade encrypted split facade encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar15, features),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            collect_rar15_40_volumes(&archives, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade encrypted split facade encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_encrypted_compressed_volumes() {
        let features = FeatureSet::store_only();
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar30-secret.txt",
                data: b"facade rar30 encrypted split facade rar30 encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            8,
        )
        .unwrap();
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse(part).unwrap())
            .collect();

        assert!(matches!(
            collect_rar15_40_volumes(&archives, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar30-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar30 encrypted split facade rar30 encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_header_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let parts = rar15_40::write_compressed_volumes(
            rar15_40::FileEntry {
                name: b"split-rar30-header-secret.txt",
                data: b"facade rar30 header encrypted split facade rar30 header encrypted split\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_options_with_features(ArchiveVersion::Rar30, features),
            8,
        )
        .unwrap();
        assert!(matches!(
            rar15_40::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar15_40::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar15_40_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-rar30-header-secret.txt");
        assert_eq!(
            extracted[0].data,
            b"facade rar30 header encrypted split facade rar30 header encrypted split\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_aes_encrypted_compressed_archive() {
        let features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar30-secret.txt",
                data: b"facade rar30 aes encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar30 aes encrypted payload\n");
    }

    #[test]
    fn direct_writer_creates_rar29_aes_encrypted_compressed_archive() {
        let features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar29-secret.txt",
                data: b"facade rar29 aes encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar29, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 29);
        assert!(file.is_encrypted());
        assert!(file.salt.is_some());
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar29 aes encrypted payload\n");
    }

    #[test]
    fn direct_writer_creates_rar20_encrypted_compressed_archive() {
        let features = FeatureSet::store_only();
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar20-secret.txt",
                data: b"facade rar20 encrypted payload payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar20, features),
        )
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar15_40().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.unp_ver, 20);
        assert!(file.is_encrypted());
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar20 encrypted payload payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = rar15_40::write_compressed_archive(
            &[rar15_40::FileEntry {
                name: b"rar30-header-secret.txt",
                data: b"facade rar30 header encrypted payload\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            }],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
        )
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar15_40().unwrap();
        assert!(raw.main.has_encrypted_headers());
        assert_eq!(raw.files().next().unwrap().name, b"rar30-header-secret.txt");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar30 header encrypted payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar30_solid_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        features.solid = true;
        let bytes = rar15_40::write_compressed_archive(
            &[
                rar15_40::FileEntry {
                    name: b"solid-header-one.txt",
                    data: b"facade solid header encrypted one one one\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
                rar15_40::FileEntry {
                    name: b"solid-header-two.txt",
                    data: b"facade solid header encrypted two two two\n",
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                },
            ],
            rar15_options_with_features(ArchiveVersion::Rar30, features),
        )
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade solid header encrypted one one one\n"
        );
        assert_eq!(
            extracted[1].data,
            b"facade solid header encrypted two two two\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive() {
        let bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
                .entries(
                    [
                        rar50_entry(b"rar5-store.txt", b"facade rar5 stored payload\n")
                            .with_mtime(Some(0))
                            .with_attributes(0x20)
                            .with_host_os(3),
                    ]
                    .to_vec(),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar50Plus);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 stored payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_archive() {
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .entries(
                [rar50_entry(
                    b"rar5-compressed.txt",
                    b"facade rar5 compressed payload\nfacade rar5 compressed payload\n",
                )
                .with_mtime(Some(0))
                .with_attributes(0x20)
                .with_host_os(3)]
                .to_vec(),
            )
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.decoded_compression_info().unwrap().method, 3);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 compressed payload\nfacade rar5 compressed payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar50 solid shared phrase alpha beta gamma\n".repeat(16);
        let second = b"facade rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [
                        rar50_entry(b"rar5-solid-one.txt", &first)
                            .with_mtime(Some(0))
                            .with_attributes(0x20)
                            .with_host_os(3),
                        rar50_entry(b"rar5-solid-two.txt", &second)
                            .with_mtime(Some(0))
                            .with_attributes(0x20)
                            .with_host_os(3),
                    ]
                    .to_vec(),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar50_delta_filtered_compressed_archive() {
        let payload: Vec<u8> = (0..180)
            .map(|index| (index * 11 + index / 5) as u8)
            .collect();
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .entries(
                [rar50_entry(b"rar5-delta-filtered.bin", &payload)
                    .with_mtime(Some(0))
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .filter_policy(rar50::FilterPolicy::explicit(rar50::FilterKind::Delta {
                channels: 3,
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_e8_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar5 e8 filter payload".to_vec();
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .entries(
                [rar50_entry(b"rar5-e8-filtered.bin", &payload)
                    .with_mtime(Some(0))
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .filter_policy(rar50::FilterPolicy::explicit(rar50::FilterKind::E8))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_arm_filtered_compressed_archive() {
        let payload = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .entries(
                [rar50_entry(b"rar5-arm-filtered.bin", &payload)
                    .with_mtime(Some(0))
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .filter_policy(rar50::FilterPolicy::explicit(rar50::FilterKind::Arm))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_auto_filtered_compressed_archive() {
        let payload = b"\xe8\0\0\0\0facade rar5 auto filter payload\n".repeat(16);
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
            .entries(
                [rar50_entry(b"rar5-auto-filtered.bin", &payload)
                    .with_mtime(Some(0))
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .filter_policy(rar50::FilterPolicy::Auto)
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_comment_service() {
        let features = FeatureSet::store_only();
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [
                rar50_entry(b"rar5-commented.txt", b"facade rar5 comment payload\n")
                    .with_attributes(0x20)
                    .with_host_os(3),
            ]
            .to_vec(),
        )
        .archive_comment(Some(b"facade rar5 comment\n"))
        .finish()
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"CMT");
        assert_eq!(
            collect_rar50_file(raw, services[0]).unwrap().data,
            b"facade rar5 comment\n"
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 comment payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_stored_file_comment_service() {
        let bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
                .entry(
                    rar50_entry(
                        b"rar5-file-commented.txt",
                        b"facade rar5 file comment payload\n",
                    )
                    .with_attributes(0x20)
                    .with_host_os(3)
                    .with_service(rar50::ServiceEntry::new(
                        b"CMT".to_vec(),
                        b"facade rar5 file comment\n".to_vec(),
                    )),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"CMT");
        assert_eq!(
            collect_rar50_file(raw, services[0]).unwrap().data,
            b"facade rar5 file comment\n"
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 file comment payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_file_comment_service() {
        let features = FeatureSet::store_only();
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entry(
            rar50_entry(
                b"rar5-encrypted-file-commented.txt",
                b"facade encrypted rar5 file comment payload\n",
            )
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())
            .with_service(
                rar50::ServiceEntry::new(
                    b"CMT".to_vec(),
                    b"facade encrypted rar5 file comment\n".to_vec(),
                )
                .with_password(b"password".to_vec()),
            ),
        )
        .finish()
        .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let service = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(service.data, b"facade encrypted rar5 file comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade encrypted rar5 file comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_file_comment_service() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entry(
            rar50_entry(
                b"rar5-header-file-commented.txt",
                b"facade header encrypted rar5 file comment payload\n",
            )
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())
            .with_service(
                rar50::ServiceEntry::new(
                    b"CMT".to_vec(),
                    b"facade header encrypted rar5 file comment\n".to_vec(),
                )
                .with_password(b"password".to_vec()),
            ),
        )
        .finish()
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let service = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(service.data, b"facade header encrypted rar5 file comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade header encrypted rar5 file comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_quick_open_service() {
        let mut features = FeatureSet::store_only();
        features.quick_open = true;
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [
                rar50_entry(b"rar5-qo.txt", b"facade rar5 quick-open payload\n")
                    .with_attributes(0x20)
                    .with_host_os(3),
            ]
            .to_vec(),
        )
        .finish()
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.locator().unwrap().quick_open_offset.unwrap() > 0);
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, b"QO");
        assert!(!collect_rar50_file(raw, services[0])
            .unwrap()
            .data
            .is_empty());
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 quick-open payload\n");
    }

    #[test]
    fn rar50_quick_open_wrapper_checksums_the_block_size_vint() {
        // The wrapper is CRC32 || BlockSize || body and the checksum covers
        // BlockSize too, which is easy to miss because the length is written
        // after the checksum it belongs to. Checksumming the body alone is
        // invisible from inside rars: nothing here reads a quick-open index
        // back, and a reference reader that rejects the wrapper just walks the
        // block chain instead and calls the archive fine.
        let mut features = FeatureSet::store_only();
        features.quick_open = true;
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [
                rar50_entry(b"a.txt", b"one\n").with_host_os(3),
                rar50_entry(b"b.txt", b"two\n").with_host_os(3),
            ]
            .to_vec(),
        )
        .finish()
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"QO");
        let payload = collect_rar50_file(raw, service).unwrap().data;

        let mut pos = 0usize;
        let mut wrappers = 0usize;
        while pos + 4 < payload.len() {
            let stored = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
            let (block_size, size_len) = {
                let (mut value, mut shift, mut len) = (0u64, 0u32, 0usize);
                loop {
                    let byte = payload[pos + 4 + len];
                    value |= u64::from(byte & 0x7f) << shift;
                    shift += 7;
                    len += 1;
                    if byte & 0x80 == 0 {
                        break (value, len);
                    }
                }
            };
            let framed_start = pos + 4;
            let framed_end = framed_start + size_len + block_size as usize;
            let framed = &payload[framed_start..framed_end];

            assert_eq!(
                crate::crc32::crc32(framed),
                stored,
                "wrapper {wrappers}: checksum must span the BlockSize vint and the body"
            );
            assert_ne!(
                crate::crc32::crc32(&framed[size_len..]),
                stored,
                "wrapper {wrappers}: checksum must not be over the body alone"
            );

            pos = framed_end;
            wrappers += 1;
        }
        assert_eq!(wrappers, 2);
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_file_services() {
        let bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
                .entry(
                    rar50_entry(b"rar5-services.txt", b"facade rar5 service payload\n")
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_service(rar50::ServiceEntry::new(
                            b"ACL".to_vec(),
                            b"facade acl".to_vec(),
                        ))
                        .with_service(rar50::ServiceEntry::new(
                            b"STM".to_vec(),
                            b"facade stream".to_vec(),
                        )),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let services: Vec<_> = raw.services().collect();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, b"ACL");
        assert_eq!(services[1].name, b"STM");
        assert_eq!(
            collect_rar50_file(raw, services[0]).unwrap().data,
            b"facade acl"
        );
        assert_eq!(
            collect_rar50_file(raw, services[1]).unwrap().data,
            b"facade stream"
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 service payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_stored_archive_with_recovery_service() {
        let features = FeatureSet::store_only();
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [
                rar50_entry(b"rar5-recovery.txt", b"facade rar5 recovery payload\n")
                    .with_attributes(0x20)
                    .with_host_os(3),
            ]
            .to_vec(),
        )
        .recovery_percent(Some(9))
        .finish()
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        let recovery = service.recovery_record().unwrap().unwrap();
        assert_eq!(recovery.percent, 9);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 recovery payload\n");
    }

    #[test]
    fn archive_facade_repairs_rar50_inline_recovery_damage() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 repair payload\n".repeat(64);
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(b"rar5-repair.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)]
            .to_vec(),
        )
        .recovery_percent(Some(20))
        .finish()
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let data_range = archive
            .as_rar50()
            .unwrap()
            .files()
            .next()
            .unwrap()
            .block
            .data_range
            .clone();
        let mut damaged = bytes.clone();
        damaged[data_range.start + 4..data_range.start + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let mut repaired = Vec::new();
        damaged_archive.repair_recovery_to(&mut repaired).unwrap();

        assert_eq!(repaired, bytes);
        let repaired_archive = ArchiveReader::read(&repaired).unwrap();
        assert_eq!(
            collect_extract(&repaired_archive, None).unwrap()[0].data,
            payload
        );
    }

    #[test]
    fn archive_facade_reports_rar13_family_for_unsupported_recovery_repair() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"old rar payload",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar13),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let mut repaired = Vec::new();
        let err = archive.repair_recovery_to(&mut repaired).unwrap_err();

        assert_eq!(
            err,
            Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives"
            }
        );
    }

    #[test]
    fn archive_facade_repairs_rar15_40_recovery_as_full_archive_bytes() {
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let mut repaired = Vec::new();
        damaged_archive.repair_recovery_to(&mut repaired).unwrap();

        assert_eq!(repaired, bytes);
        let repaired_archive = ArchiveReader::read(&repaired).unwrap();
        assert_eq!(
            collect_extract(&repaired_archive, None).unwrap()[0].name,
            b"BIG.BIN"
        );
    }

    #[test]
    fn archive_facade_repairs_rar3_newsub_recovery_as_full_archive_bytes() {
        let bytes = std::fs::read(rar15_40_fixture("rar300/with_recovery_rar300.rar")).unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();
        assert!(collect_extract(&damaged_archive, None).is_err());

        let mut repaired = Vec::new();
        damaged_archive.repair_recovery_to(&mut repaired).unwrap();

        assert_eq!(repaired, bytes);
        let repaired_archive = ArchiveReader::read(&repaired).unwrap();
        assert_eq!(
            collect_extract(&repaired_archive, None).unwrap()[0].name,
            b"bigtext_64k.bin"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_archive_with_recovery_service() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 compressed recovery payload repeated repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [rar50_entry(b"rar5-compressed-recovery.txt", &payload)
                        .with_attributes(0x20)
                        .with_host_os(3)]
                    .to_vec(),
                )
                .recovery_percent(Some(9))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 9);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar70_stored_archive_with_metadata() {
        let bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar70).with_compression_level(0))
                .entries(
                    [
                        rar50_entry(b"rar7-metadata.txt", b"facade rar7 metadata payload\n")
                            .with_attributes(0x20)
                            .with_host_os(3),
                    ]
                    .to_vec(),
                )
                .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                    name: Some(b"facade-metadata.rar"),
                    creation_time: Some(0x01dcd60e_662d7a32),
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"facade rar7 metadata payload\n");
    }

    #[test]
    fn direct_writer_creates_rar70_compressed_archive_with_metadata() {
        let payload = b"facade rar7 compressed metadata payload repeated\n".repeat(8);
        let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar70))
            .entries(
                [rar50_entry(b"rar7-compressed-metadata.txt", &payload)
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-compressed-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-compressed-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_archive_with_comment() {
        let payload = b"facade rar5 compressed archive comment payload repeated\n".repeat(8);
        let features = FeatureSet::store_only();
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [rar50_entry(b"rar5-compressed-comment.txt", &payload)
                        .with_attributes(0x20)
                        .with_host_os(3)]
                    .to_vec(),
                )
                .archive_comment(Some(b"facade compressed comment\n"))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade compressed comment\n");
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar70_encrypted_stored_archive_with_metadata() {
        let features = FeatureSet::store_only();
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar70, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar7-encrypted-metadata.txt",
                b"facade rar7 encrypted metadata payload\n",
            )
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .archive_metadata(Some(rar50::ArchiveMetadataEntry {
            name: Some(b"facade-encrypted-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }))
        .finish()
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-encrypted-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar7 encrypted metadata payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar70_encrypted_compressed_archive_with_metadata() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar7 encrypted compressed metadata payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
                .entries(
                    [
                        rar50_entry(b"rar7-encrypted-compressed-metadata.txt", &payload)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                    name: Some(b"facade-encrypted-compressed-metadata.rar"),
                    creation_time: Some(0x01dcd60e_662d7a32),
                }))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-encrypted-compressed-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar70_header_encrypted_stored_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar70, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar7-header-metadata.txt",
                b"facade rar7 header encrypted metadata payload\n",
            )
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .archive_metadata(Some(rar50::ArchiveMetadataEntry {
            name: Some(b"facade-header-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }))
        .finish()
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-header-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar7 header encrypted metadata payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar70_header_encrypted_compressed_archive_with_metadata() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let payload =
            b"facade rar7 header encrypted compressed metadata payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
                .entries(
                    [
                        rar50_entry(b"rar7-header-compressed-metadata.txt", &payload)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                    name: Some(b"facade-header-compressed-metadata.rar"),
                    creation_time: Some(0x01dcd60e_662d7a32),
                }))
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
        assert_eq!(
            metadata.name.as_deref(),
            Some(b"facade-header-compressed-metadata.rar".as_slice())
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_archive() {
        let features = FeatureSet::store_only();
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar5-secret.txt",
                b"facade rar5 encrypted stored payload\n",
            )
            .with_mtime(Some(0))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .finish()
        .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::AtEntry { source, .. }) if matches!(*source, Error::NeedPassword)
        ));
        assert!(matches!(
            collect_extract(&archive, Some(b"wrong")),
            Err(Error::AtEntry { source, .. })
                if matches!(*source, Error::WrongPasswordOrCorruptData)
        ));
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 encrypted stored payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_archive() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 encrypted compressed\n".repeat(16);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [rar50_entry(b"rar5-secret-compressed.txt", &payload)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec())]
                    .to_vec(),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.encrypted);
        assert_eq!(file.decoded_compression_info().unwrap().method, 3);
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let first = b"facade rar50 encrypted solid shared phrase alpha beta gamma\n".repeat(12);
        let second =
            b"facade rar50 encrypted solid shared phrase alpha beta gamma\nsecond\n".repeat(6);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [
                        rar50_entry(b"rar5-encrypted-solid-one.txt", &first)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                        rar50_entry(b"rar5-encrypted-solid-two.txt", &second)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(files.iter().all(|file| file.encrypted));
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries([rar50_entry(b"rar5-header-secret-compressed.txt", b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n").with_attributes(0x20).with_host_os(3).with_password(b"password".to_vec())].to_vec())
            .finish()
            .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert!(file.encrypted);
        assert_eq!(file.decoded_compression_info().unwrap().method, 3);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_solid_compressed_archive() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        features.solid = true;
        let first =
            b"facade rar50 header encrypted solid shared phrase alpha beta gamma\n".repeat(12);
        let second =
            b"facade rar50 header encrypted solid shared phrase alpha beta gamma\nsecond\n"
                .repeat(6);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [
                        rar50_entry(b"rar5-header-solid-one.txt", &first)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                        rar50_entry(b"rar5-header-solid-two.txt", &second)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let files: Vec<_> = raw.files().collect();
        assert!(raw.main.is_solid());
        assert!(files.iter().all(|file| file.encrypted));
        assert!(!files[0].decoded_compression_info().unwrap().solid);
        assert!(files[1].decoded_compression_info().unwrap().solid);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_archive_with_comment() {
        let features = FeatureSet::store_only();
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar5-secret.txt",
                b"facade rar5 encrypted stored payload\n",
            )
            .with_mtime(Some(0))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .encrypted_archive_comment(b"facade encrypted comment\n", b"password")
        .finish()
        .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade encrypted comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, b"facade rar5 encrypted stored payload\n");
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_archive_with_comment() {
        let payload = b"facade rar5 encrypted compressed comment payload\n".repeat(8);
        let features = FeatureSet::store_only();
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [
                        rar50_entry(b"rar5-encrypted-compressed-comment.txt", &payload)
                            .with_mtime(Some(0))
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .encrypted_archive_comment(b"facade encrypted compressed comment\n", b"password")
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade encrypted compressed comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_archive() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar5-header-secret.txt",
                b"facade rar5 header encrypted stored payload\n",
            )
            .with_mtime(Some(0))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .finish()
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted stored payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_archive_with_comment() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar5-header-comment-secret.txt",
                b"facade rar5 header encrypted comment payload\n",
            )
            .with_mtime(Some(0))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .encrypted_archive_comment(b"facade header encrypted comment\n", b"password")
        .finish()
        .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(comment.data, b"facade header encrypted comment\n");
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted comment payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_archive_with_comment() {
        let payload = b"facade rar5 header encrypted compressed comment payload\n".repeat(8);
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [
                        rar50_entry(b"rar5-header-compressed-comment-secret.txt", &payload)
                            .with_mtime(Some(0))
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .encrypted_archive_comment(
                    b"facade header encrypted compressed comment\n",
                    b"password",
                )
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        let comment = collect_rar50_file(raw, raw.services().next().unwrap()).unwrap();
        assert_eq!(
            comment.data,
            b"facade header encrypted compressed comment\n"
        );
        let extracted = collect_extract(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_archive_with_recovery() {
        let features = FeatureSet::store_only();
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar5-encrypted-recovery.txt",
                b"facade rar5 encrypted recovery payload\n",
            )
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .recovery_percent(Some(6))
        .finish()
        .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
        let recovery_data = collect_rar50_file(raw, service).unwrap().data;
        assert!(recovery_data.starts_with(b"{RB}"));
        assert_eq!(
            u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
            recovery_data.len()
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 encrypted recovery payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_archive_with_recovery() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 encrypted compressed recovery payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [
                        rar50_entry(b"rar5-encrypted-compressed-recovery.txt", &payload)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .recovery_percent(Some(6))
                .finish()
                .unwrap();

        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let bytes = rar50::Rar50Writer::new(
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries(
            [rar50_entry(
                b"rar5-header-recovery.txt",
                b"facade rar5 header encrypted recovery payload\n",
            )
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())]
            .to_vec(),
        )
        .recovery_percent(Some(4))
        .finish()
        .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
        let recovery_data = collect_rar50_file(raw, service).unwrap().data;
        assert!(recovery_data.starts_with(b"{RB}"));
        assert_eq!(
            u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
            recovery_data.len()
        );
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(
            extracted[0].data,
            b"facade rar5 header encrypted recovery payload\n"
        );
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_archive_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let payload =
            b"facade rar5 header encrypted compressed recovery payload repeated\n".repeat(8);
        let bytes =
            rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
                .entries(
                    [
                        rar50_entry(b"rar5-header-compressed-recovery.txt", &payload)
                            .with_attributes(0x20)
                            .with_host_os(3)
                            .with_password(b"password".to_vec()),
                    ]
                    .to_vec(),
                )
                .recovery_percent(Some(4))
                .finish()
                .unwrap();

        assert!(matches!(
            ArchiveReader::read(&bytes),
            Err(Error::NeedPassword)
        ));
        let archive = ArchiveReader::read_with_options(
            &bytes,
            ArchiveReadOptions::with_password(b"password"),
        )
        .unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.has_recovery_record());
        let service = raw.services().next().unwrap();
        assert_eq!(service.name, b"RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_volumes() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 encrypted split payload\n".repeat(12);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split-secret50.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)
                .with_password(b"password".to_vec())],
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
            16,
            None,
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_stored_volumes_with_recovery() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 encrypted recovery split payload\n".repeat(12);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split-secret50-rr.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)
                .with_password(b"password".to_vec())],
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
            16,
            Some(8),
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let payload = b"facade rar5 header encrypted recovery split payload\n".repeat(4);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split-header-secret50-rr.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)
                .with_password(b"password".to_vec())],
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
            16,
            Some(8),
        );
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_stored_volumes() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let payload = b"facade rar5 header encrypted split payload\n".repeat(12);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split-header-secret50.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)
                .with_password(b"password".to_vec())],
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
            16,
            None,
        );
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_volumes() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 encrypted compressed split payload\n".repeat(12);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split-secret-compressed50.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)
                .with_password(b"password".to_vec())],
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            32,
            None,
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_compressed_volumes_with_recovery() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 encrypted compressed recovery split payload\n".repeat(12);
        let entries = [rar50_entry(b"split-secret-compressed50-rr.txt", &payload)
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec())];
        let parts = write_rar50_volume_set(
            &entries,
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            32,
            Some(8),
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-secret-compressed50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_volumes_with_recovery() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let payload =
            b"facade rar5 header encrypted compressed recovery split payload\n".repeat(12);
        let entries = [
            rar50_entry(b"split-header-secret-compressed50-rr.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)
                .with_password(b"password".to_vec()),
        ];
        let parts = write_rar50_volume_set(
            &entries,
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            32,
            Some(8),
        );
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(
            extracted[0].name,
            b"split-header-secret-compressed50-rr.txt"
        );
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_encrypted_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let payload = b"facade rar5 encrypted solid compressed split payload\n".repeat(12);
        let parts = write_rar50_volume_set(
            &[
                rar50_entry(b"split-solid-secret-compressed50.txt", &payload)
                    .with_attributes(0x20)
                    .with_host_os(3)
                    .with_password(b"password".to_vec()),
            ],
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            32,
            None,
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));

        let extracted = collect_rar50_volumes(&archives, Some(b"password")).unwrap();
        assert_eq!(extracted[0].name, b"split-solid-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let payload: Vec<u8> = (0..512).map(|index| (index * 37 + 11) as u8).collect();
        let parts = write_rar50_volume_set(
            &[
                rar50_entry(b"split-header-secret-compressed50.txt", &payload)
                    .with_attributes(0x20)
                    .with_host_os(3)
                    .with_password(b"password".to_vec()),
            ],
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            64,
            None,
        );
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();

        let extracted = collect_rar50_volumes(&archives, None).unwrap();
        assert_eq!(extracted[0].name, b"split-header-secret-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_header_encrypted_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        features.solid = true;
        let payload = b"facade rar5 header encrypted solid compressed split payload\n".repeat(12);
        let parts = write_rar50_volume_set(
            &[
                rar50_entry(b"split-header-solid-secret-compressed50.txt", &payload)
                    .with_attributes(0x20)
                    .with_host_os(3)
                    .with_password(b"password".to_vec()),
            ],
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            32,
            None,
        );
        assert!(matches!(
            rar50::Archive::parse(&parts[0]),
            Err(Error::NeedPassword)
        ));
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse_with_password(part, Some(b"password")).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));

        let extracted = collect_rar50_volumes(&archives, None).unwrap();
        assert_eq!(
            extracted[0].name,
            b"split-header-solid-secret-compressed50.txt"
        );
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_stored_volumes() {
        let payload = b"facade rar5 stored split payload\n".repeat(20);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split50.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)],
            rar50_options(ArchiveVersion::Rar50).with_compression_level(0),
            80,
            None,
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_stored_volumes_with_recovery() {
        let features = FeatureSet::store_only();
        let payload = b"facade rar5 stored recovery split payload\n".repeat(20);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split50-rr.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)],
            rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
            80,
            Some(8),
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_volumes() {
        let payload: Vec<u8> = (0..512).map(|index| (index * 53 + 17) as u8).collect();
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split-compressed50.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)],
            rar50_options(ArchiveVersion::Rar50),
            64,
            None,
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_compressed_volumes_with_recovery() {
        let features = FeatureSet::store_only();
        let payload: Vec<u8> = (0..512).map(|index| (index * 53 + 17) as u8).collect();
        let entries = [rar50_entry(b"split-compressed50-rr.txt", &payload)
            .with_attributes(0x20)
            .with_host_os(3)];
        let parts = write_rar50_volume_set(
            &entries,
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            64,
            Some(8),
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert_rar50_volume_recovery_records(&archives, 8);
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split-compressed50-rr.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let payload = b"facade rar5 solid compressed split payload\n".repeat(12);
        let parts = write_rar50_volume_set(
            &[rar50_entry(b"split-solid-compressed50.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)],
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            32,
            None,
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"split-solid-compressed50.txt");
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn direct_writer_creates_rar50_multi_file_solid_compressed_volumes() {
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let mut first = b"facade rar5 multi-file solid split shared phrase\n"
            .repeat(8)
            .to_vec();
        first.extend_from_slice(&deterministic_noise(2048));
        let mut second = b"facade rar5 multi-file solid split shared phrase\nsecond\n"
            .repeat(8)
            .to_vec();
        second.extend_from_slice(&deterministic_noise(2048));
        let entries = [
            rar50_entry(b"solid-volume-one.txt", &first)
                .with_attributes(0x20)
                .with_host_os(3),
            rar50_entry(b"solid-volume-two.txt", &second)
                .with_attributes(0x20)
                .with_host_os(3),
        ];
        let parts = write_rar50_volume_set(
            &entries,
            rar50_options_with_features(ArchiveVersion::Rar50, features),
            512,
            None,
        );
        let archives: Vec<_> = parts
            .iter()
            .map(|part| rar50::Archive::parse(part).unwrap())
            .collect();
        assert!(archives.iter().all(|archive| archive.main.is_solid()));
        let extracted = collect_rar50_volumes(&archives, None).unwrap();

        assert_eq!(extracted[0].name, b"solid-volume-one.txt");
        assert_eq!(extracted[0].data, first);
        assert_eq!(extracted[1].name, b"solid-volume-two.txt");
        assert_eq!(extracted[1].data, second);
    }

    #[test]
    fn archive_as_rar13_returns_some_only_for_rar13_family() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"r13 downcast",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        let raw = archive.as_rar13().unwrap();
        assert_eq!(raw.entries[0].name, b"old.txt");
        assert!(archive.as_rar15_40().is_none());
        assert!(archive.as_rar50().is_none());

        // Other-family archives should refuse the rar13 downcast.
        let rar15_bytes = rar15_40::write_stored_archive(
            &[rar15_40::StoredEntry {
                name: b"mid.txt",
                data: b"r15 downcast",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            }],
            rar15_options(ArchiveVersion::Rar15),
        )
        .unwrap();
        let rar15_archive = ArchiveReader::read(&rar15_bytes).unwrap();
        assert!(rar15_archive.as_rar13().is_none());

        let rar50_bytes =
            rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
                .entries(
                    [rar50_entry(b"new.txt", b"r50 downcast")
                        .with_attributes(0x20)
                        .with_host_os(3)]
                    .to_vec(),
                )
                .finish()
                .unwrap();
        let rar50_archive = ArchiveReader::read(&rar50_bytes).unwrap();
        assert!(rar50_archive.as_rar13().is_none());
    }

    #[test]
    fn archive_facade_repair_recovery_returns_full_repaired_archive_bytes() {
        let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        let mut damaged = bytes.clone();
        damaged[512 + 16..512 + 80].fill(0xa5);
        let damaged_archive = ArchiveReader::read(&damaged).unwrap();

        let repaired = damaged_archive.repair_recovery().unwrap();
        assert_eq!(repaired, bytes);
    }

    #[test]
    fn archive_facade_repair_recovery_rejects_rar13_archives() {
        let bytes = rar13::write_stored_archive(
            &[rar13::StoredEntry {
                name: b"old.txt",
                data: b"old data",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            }],
            rar13_options(ArchiveVersion::Rar14),
        )
        .unwrap();
        let archive = ArchiveReader::read(&bytes).unwrap();
        assert_eq!(
            archive.repair_recovery(),
            Err(Error::UnsupportedFamilyFeature {
                family: ArchiveFamily::Rar13,
                feature: "recovery repair for RAR 1.3/1.4 archives",
            })
        );
    }

    #[test]
    fn archive_reader_read_path_dispatches_to_default_options() {
        // Existing tests cover read_path_with_options; this ensures the
        // zero-arg convenience wrapper actually delegates to it.
        let archive =
            ArchiveReader::read_path(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
        assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
        assert!(archive.as_rar15_40().unwrap().main.has_recovery_record());
    }

    #[test]
    fn archive_member_can_be_read_by_index() {
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"first.txt".to_vec(), b"first".to_vec(), None, None)
            .unwrap();
        builder
            .add_bytes(b"second.txt".to_vec(), b"second".to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();

        assert_eq!(archive.read_member_at(1, None).unwrap().unwrap(), b"second");
        assert_eq!(archive.read_member_at(2, None).unwrap(), None);
    }

    #[test]
    fn volume_members_and_index_reads_fold_split_fragments() {
        let payload = vec![7; 200_000];
        let mut builder = Builder::new(ArchiveVersion::Rar50)
            .store(true)
            .volume_size(Some(64 * 1024));
        builder
            .add_bytes(b"big.bin".to_vec(), payload.clone(), None, None)
            .unwrap();
        let archives: Vec<_> = builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|part| ArchiveReader::read_owned(part).unwrap())
            .collect();

        let members = volume_members(&archives).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].meta.name, b"big.bin");
        assert_eq!(
            read_volume_member_at(&archives, 0, None).unwrap().unwrap(),
            payload
        );
    }
}
