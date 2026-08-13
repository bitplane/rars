use super::*;
use crate::codec::rar50::Unpack50Encoder;
use crate::crc32::Crc32;
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
pub use crate::filter::{FilterKind, FilterPolicy, FilterSpec};
use crate::recovery::rar5::build_structural_inline_recovery_data_with_progress;
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::{EntrySource, WriteOperation, WriteProgress, WriteProgressEvent, WriterResources};
use std::io::{Read, Write};

mod compress;
mod engine;
mod filter_policy;
mod headers;
mod layout;
mod volume;
#[cfg(test)]
use filter_policy::encode_member_with_filter_policy;
#[cfg(test)]
use filter_policy::encode_with_solid_reset_policy;
use filter_policy::{
    compression_info, compression_method_for_level, dictionary_size_for_options,
    encode_option_candidates_for_level, encode_options_for_level,
    encode_safe_lz_member_with_progress, encode_with_solid_reset_policy_and_progress,
    filter_policy_walk_bytes, rar50_algorithm_version, should_store_compressed_payload,
    validate_compression_level,
};
use headers::{
    encrypted_header_block, encrypted_main_header_block, file_specific, header_encryption_keys,
    header_encryption_password, stored_file_specific, write_block, write_extra_record,
    write_file_encryption_record, write_hash_record, write_hash_record_with_value,
    write_head_crypt, write_locator_record, write_main_header, write_vint, HeaderEncryptionKeys,
};
pub(super) use headers::{end_header_specific, write_end_header};
use volume::{
    write_compressed_volume_set_impl, write_encrypted_compressed_volume_set_impl,
    write_encrypted_stored_volumes_impl, write_stored_volumes_impl,
};

const MAX_MATCH_CANDIDATES_DEFAULT: usize = 256;
const DEFAULT_RAR50_DICTIONARY_SIZE: u64 = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriterOptions {
    pub target: crate::ArchiveVersion,
    pub features: crate::FeatureSet,
    pub compression_level: Option<u8>,
    pub dictionary_size: Option<u64>,
}

impl WriterOptions {
    pub const fn new(target: crate::ArchiveVersion, features: crate::FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
            dictionary_size: None,
        }
    }

    pub const fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = Some(level);
        self
    }

    pub const fn with_dictionary_size(mut self, size: u64) -> Self {
        self.dictionary_size = Some(size);
        self
    }
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: crate::ArchiveVersion::Rar50,
            features: crate::FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

#[derive(Debug, Clone)]
/// A non-encrypted member backed by a reopenable streaming source.
pub struct StreamingCompressedEntry {
    pub name: Vec<u8>,
    pub source: EntrySource,
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
}

#[derive(Debug, Clone)]
/// An encrypted member backed by a reopenable streaming source.
pub struct StreamingEncryptedCompressedEntry {
    pub name: Vec<u8>,
    pub source: EntrySource,
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub password: Vec<u8>,
}

/// An archive member, read from a reopenable source when it is needed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ArchiveEntry {
    pub name: Vec<u8>,
    pub source: EntrySource,
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    /// Encrypts this member's payload. With header encryption every member
    /// must use the same password.
    pub password: Option<Vec<u8>>,
    /// Service records attached to this member, such as a file comment.
    pub services: Vec<ServiceEntry>,
}

/// A small named record attached to an archive or a member.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServiceEntry {
    /// Service name, such as `CMT`, `ACL` or `STM`.
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub password: Option<Vec<u8>>,
}

impl ServiceEntry {
    pub fn new(name: impl Into<Vec<u8>>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            data: data.into(),
            password: None,
        }
    }

    pub fn with_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(password.into());
        self
    }
}

impl ArchiveEntry {
    pub fn new(name: impl Into<Vec<u8>>, source: EntrySource) -> Self {
        Self {
            name: name.into(),
            source,
            mtime: None,
            attributes: 0,
            host_os: 0,
            password: None,
            services: Vec::new(),
        }
    }

    pub fn with_service(mut self, service: ServiceEntry) -> Self {
        self.services.push(service);
        self
    }

    pub fn with_mtime(mut self, mtime: Option<u32>) -> Self {
        self.mtime = mtime;
        self
    }

    pub fn with_attributes(mut self, attributes: u64) -> Self {
        self.attributes = attributes;
        self
    }

    pub fn with_host_os(mut self, host_os: u64) -> Self {
        self.host_os = host_os;
        self
    }

    pub fn with_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(password.into());
        self
    }
}

/// Receives each volume of a multi-volume archive as it is finished.
pub trait VolumeSink {
    /// Opens the output for volume `index`, numbered from zero.
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn Write + Send>>;

    /// Called once volume `index` has been written and flushed.
    fn finish_volume(&mut self, index: u64, len: u64) -> Result<()> {
        let _ = (index, len);
        Ok(())
    }
}

/// Writes a multi-volume RAR 5 or RAR 7 archive, handing each volume to `sink`
/// as it completes so the set is never held in memory.
pub fn write_streaming_volumes_to(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
    max_payload_per_volume: u64,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
) -> Result<()> {
    let encrypted = entries.iter().any(|entry| entry.password.is_some());
    if encrypted && !entries.iter().all(|entry| entry.password.is_some()) {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 writer mixing encrypted and plain members",
        });
    }
    if extras.quick_open || extras.comment.is_some() || extras.metadata.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 volume writer comments, metadata or quick-open",
        });
    }
    match (encrypted, extras.recovery_percent.is_some()) {
        (true, true) => validate_encrypted_compressed_recovery_options(options)?,
        (true, false) => validate_encrypted_compressed_options(options)?,
        (false, true) => validate_compressed_recovery_options(options)?,
        (false, false) => validate_compressed_options(options)?,
    }
    if let Some(percent) = extras.recovery_percent {
        validate_recovery_percent(percent)?;
    }
    if options.features.header_encryption && !encrypted {
        return Err(Error::NeedPassword);
    }

    engine::write_volumes(
        entries,
        engine::EnginePlan {
            compress: {
                let mut compress = streaming_compress_plan(options)?;
                compress.filter_policy = extras.filter_policy;
                compress.candidates = encode_option_candidates_for_level(
                    options.compression_level,
                    compress.dictionary_size,
                )?;
                compress
            },
            method: compression_method_for_level(options.compression_level)?,
            recovery_percent: extras.recovery_percent,
            header_encrypted: options.features.header_encryption,
            archive_comment: None,
            archive_metadata: None,
            quick_open: false,
            progress: None,
        },
        max_payload_per_volume,
        sink,
        resources,
    )
}

/// Archive-level options that sit alongside the members.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ArchiveExtras<'a> {
    /// Archive comment, stored as a `CMT` service record.
    pub comment: Option<&'a [u8]>,
    /// Encrypts the comment. Without it the comment is stored in the clear.
    pub comment_password: Option<&'a [u8]>,
    pub metadata: Option<ArchiveMetadataEntry<'a>>,
    /// Writes a quick-open index so readers can list the archive without
    /// walking every header.
    pub quick_open: bool,
    /// Whether to look for a data filter that makes members compress better.
    pub filter_policy: FilterPolicy,
    /// Percentage of the archive to spend on a recovery record.
    pub recovery_percent: Option<u64>,
}

impl<'a> ArchiveExtras<'a> {
    pub fn with_comment(mut self, comment: &'a [u8]) -> Self {
        self.comment = Some(comment);
        self
    }

    pub fn with_encrypted_comment(mut self, comment: &'a [u8], password: &'a [u8]) -> Self {
        self.comment = Some(comment);
        self.comment_password = Some(password);
        self
    }

    pub fn with_metadata(mut self, metadata: ArchiveMetadataEntry<'a>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_quick_open(mut self, quick_open: bool) -> Self {
        self.quick_open = quick_open;
        self
    }

    pub fn with_filter_policy(mut self, policy: FilterPolicy) -> Self {
        self.filter_policy = policy;
        self
    }

    pub fn with_recovery_percent(mut self, percent: Option<u64>) -> Self {
        self.recovery_percent = percent;
        self
    }
}

/// Writes a RAR 5 or RAR 7 archive straight to `output`, keeping memory within
/// `resources` however large the members are.
///
/// Supports solid compression, per-member and header encryption, and recovery
/// records, in any combination.
pub fn write_streaming_archive_to(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
    resources: &WriterResources,
    output: &mut dyn Write,
) -> Result<()> {
    write_streaming_archive_with_progress(entries, options, extras, resources, None, output)
}

pub(crate) fn write_streaming_archive_with_progress(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
    output: &mut dyn Write,
) -> Result<()> {
    let encrypted = entries.iter().any(|entry| entry.password.is_some());
    if encrypted && !entries.iter().all(|entry| entry.password.is_some()) {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 writer mixing encrypted and plain members",
        });
    }
    let recovery_percent = extras.recovery_percent;
    match (encrypted, recovery_percent.is_some()) {
        (true, true) => validate_encrypted_compressed_recovery_options(options)?,
        (true, false) => validate_encrypted_compressed_options(options)?,
        (false, true) => validate_compressed_recovery_options(options)?,
        (false, false) => validate_compressed_options(options)?,
    }
    if let Some(percent) = recovery_percent {
        validate_recovery_percent(percent)?;
    }
    if options.features.header_encryption && !encrypted {
        return Err(Error::NeedPassword);
    }
    if extras.quick_open && options.features.header_encryption {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 quick-open index in a header-encrypted archive",
        });
    }

    engine::write_archive(
        entries,
        engine::EnginePlan {
            compress: {
                let mut compress = streaming_compress_plan(options)?;
                compress.filter_policy = extras.filter_policy;
                compress.candidates = encode_option_candidates_for_level(
                    options.compression_level,
                    compress.dictionary_size,
                )?;
                compress
            },
            method: compression_method_for_level(options.compression_level)?,
            recovery_percent,
            header_encrypted: options.features.header_encryption,
            archive_comment: match (extras.comment, extras.comment_password) {
                (Some(data), Some(password)) => {
                    Some(engine::ArchiveCommentPlan::Encrypted { data, password })
                }
                (Some(data), None) => Some(engine::ArchiveCommentPlan::Plain(data)),
                (None, _) => None,
            },
            archive_metadata: extras.metadata,
            quick_open: extras.quick_open,
            progress,
        },
        resources,
        output,
    )
}

/// Writes a RAR 5 or RAR 7 archive without retaining member payloads.
pub fn write_streaming_compressed_archive_to(
    entries: &[StreamingCompressedEntry],
    options: WriterOptions,
    resources: &WriterResources,
    output: &mut dyn Write,
) -> Result<()> {
    let entries: Vec<_> = entries
        .iter()
        .map(|entry| {
            ArchiveEntry::new(entry.name.clone(), entry.source.clone())
                .with_mtime(entry.mtime)
                .with_attributes(entry.attributes)
                .with_host_os(entry.host_os)
        })
        .collect();
    write_streaming_archive_to(
        &entries,
        options,
        ArchiveExtras::default(),
        resources,
        output,
    )
}

/// Compression settings shared by the streaming writers.
fn streaming_compress_plan(options: WriterOptions) -> Result<compress::CompressPlan> {
    let dictionary_size = dictionary_size_for_options(options)?;
    Ok(compress::CompressPlan {
        algorithm_version: rar50_algorithm_version(options)?,
        encode_options: encode_options_for_level(options.compression_level, dictionary_size)?,
        dictionary_size,
        block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
        solid: options.features.solid,
        method: compression_method_for_level(options.compression_level)?,
        filter_policy: FilterPolicy::None,
        candidates: vec![encode_options_for_level(
            options.compression_level,
            dictionary_size,
        )?],
    })
}

/// Writes an encrypted RAR 5 or RAR 7 archive with bounded memory.
pub fn write_streaming_encrypted_compressed_archive_to(
    entries: &[StreamingEncryptedCompressedEntry],
    options: WriterOptions,
    resources: &WriterResources,
    output: &mut dyn Write,
) -> Result<()> {
    let entries: Vec<_> = entries
        .iter()
        .map(|entry| {
            ArchiveEntry::new(entry.name.clone(), entry.source.clone())
                .with_mtime(entry.mtime)
                .with_attributes(entry.attributes)
                .with_host_os(entry.host_os)
                .with_password(entry.password.clone())
        })
        .collect();
    write_streaming_archive_to(
        &entries,
        options,
        ArchiveExtras::default(),
        resources,
        output,
    )
}

fn source_integrity(
    source: &EntrySource,
    expected_size: u64,
    block_size: usize,
) -> Result<(u32, [u8; 32])> {
    let mut crc = Crc32::new();
    let mut hash = blake2sp::Hasher::new();
    let mut reader = source.open()?;
    let mut buffer = vec![0u8; block_size];
    let mut observed = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed += read as u64;
        crc.update(&buffer[..read]);
        hash.update(&buffer[..read]);
    }
    if observed != expected_size {
        return Err(Error::InvalidHeader(
            "entry source size changed while reading",
        ));
    }
    Ok((crc.finish(), hash.finalize()))
}

fn streaming_lz_workspace(dictionary_size: u64, block_size: usize) -> u64 {
    // The hash-chain finder has one usize link per byte in history + input,
    // alongside byte buffers, worst-case literal tokens, parser candidates,
    // and allocations retained by the system allocator between block jobs.
    // Keep this deliberately conservative: it is the admission weight for
    // concurrent blocks, not a prediction of the final packed size.
    dictionary_size
        .saturating_mul(12)
        .saturating_add((block_size as u64).saturating_mul(112))
        .saturating_add(2 * 1024 * 1024)
}

fn encrypt_reader_to(
    reader: &mut dyn Read,
    input_size: u64,
    output: &mut dyn Write,
    keys: &Rar50Keys,
    iv: [u8; 16],
    block_size: usize,
) -> Result<()> {
    let mut cipher = Rar50Cipher::new(keys.key, iv);
    let chunk_size = block_size.max(16) & !15;
    let mut buffer = vec![0u8; chunk_size];
    let mut remaining = input_size;
    while remaining >= chunk_size as u64 {
        reader.read_exact(&mut buffer)?;
        cipher
            .encrypt_in_place(&mut buffer)
            .map_err(super::map_rar50_crypto_error)?;
        output.write_all(&buffer)?;
        remaining -= chunk_size as u64;
    }
    let final_plain = usize::try_from(remaining)
        .map_err(|_| Error::InvalidHeader("RAR 5 encrypted data size overflows"))?;
    let final_padded = final_plain
        .checked_add(15)
        .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
        & !15;
    if final_padded != 0 {
        buffer[..final_padded].fill(0);
        reader.read_exact(&mut buffer[..final_plain])?;
        cipher
            .encrypt_in_place(&mut buffer[..final_padded])
            .map_err(super::map_rar50_crypto_error)?;
        output.write_all(&buffer[..final_padded])?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredServiceEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntryWithServices<'a> {
    pub entry: StoredEntry<'a>,
    pub services: &'a [StoredServiceEntry<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredServiceEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredEntryWithServices<'a> {
    pub entry: EncryptedStoredEntry<'a>,
    pub services: &'a [EncryptedStoredServiceEntry<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveMetadataEntry<'a> {
    pub name: Option<&'a [u8]>,
    pub creation_time: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedStoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedCompressedEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub mtime: Option<u32>,
    pub attributes: u64,
    pub host_os: u64,
    pub password: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedArchiveCommentEntry<'a> {
    pub data: &'a [u8],
    pub password: &'a [u8],
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rar50Writer<'a> {
    options: WriterOptions,
    members: Vec<Rar50WriteMember<'a>>,
    archive_comment: Option<ArchiveComment<'a>>,
    archive_metadata: Option<ArchiveMetadataEntry<'a>>,
    filter_policy: FilterPolicy,
    recovery_percent: Option<u64>,
    recovery_password: Option<&'a [u8]>,
    progress: Option<ProgressReporter<'a>>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rar50VolumeWriter<'a> {
    options: WriterOptions,
    entries: Option<Rar50VolumeEntries<'a>>,
    max_payload_per_volume: Option<usize>,
    recovery_percent: Option<u64>,
    progress: Option<ProgressReporter<'a>>,
}

#[derive(Debug, Clone)]
enum Rar50VolumeEntries<'a> {
    Stored(StoredEntry<'a>),
    Compressed(&'a [CompressedEntry<'a>]),
    EncryptedStored(EncryptedStoredEntry<'a>),
    EncryptedCompressed(&'a [EncryptedCompressedEntry<'a>]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveComment<'a> {
    Plain(&'a [u8]),
    Encrypted(EncryptedArchiveCommentEntry<'a>),
}

impl<'a> ArchiveComment<'a> {}

impl<'a> Rar50VolumeWriter<'a> {
    pub fn new(options: WriterOptions) -> Self {
        Self {
            options,
            entries: None,
            max_payload_per_volume: None,
            recovery_percent: None,
            progress: None,
        }
    }

    pub fn stored_entry(mut self, entry: StoredEntry<'a>) -> Self {
        self.entries = Some(Rar50VolumeEntries::Stored(entry));
        self
    }

    pub fn compressed_entries(mut self, entries: &'a [CompressedEntry<'a>]) -> Self {
        self.entries = Some(Rar50VolumeEntries::Compressed(entries));
        self
    }

    pub fn encrypted_stored_entry(mut self, entry: EncryptedStoredEntry<'a>) -> Self {
        self.entries = Some(Rar50VolumeEntries::EncryptedStored(entry));
        self
    }

    pub fn encrypted_compressed_entries(
        mut self,
        entries: &'a [EncryptedCompressedEntry<'a>],
    ) -> Self {
        self.entries = Some(Rar50VolumeEntries::EncryptedCompressed(entries));
        self
    }

    pub fn max_payload_per_volume(mut self, size: usize) -> Self {
        self.max_payload_per_volume = Some(size);
        self
    }

    pub fn recovery_percent(mut self, percent: Option<u64>) -> Self {
        self.recovery_percent = percent;
        self
    }

    pub fn progress(mut self, progress: &'a dyn WriteProgress) -> Self {
        self.progress = Some(ProgressReporter(progress));
        self
    }

    pub fn finish(self) -> Result<Vec<Vec<u8>>> {
        let max_payload_per_volume = self.max_payload_per_volume.ok_or(Error::InvalidHeader(
            "RAR 5 volume payload size is required",
        ))?;
        let entries = self.entries.ok_or(Error::InvalidHeader(
            "RAR 5 volume writer needs an entry set",
        ))?;
        let (compressed, total_bytes, total_entries) = match &entries {
            Rar50VolumeEntries::Compressed(entries) => (
                true,
                entries.iter().map(|entry| entry.data.len() as u64).sum(),
                entries.len(),
            ),
            Rar50VolumeEntries::EncryptedCompressed(entries) => (
                true,
                entries.iter().map(|entry| entry.data.len() as u64).sum(),
                entries.len(),
            ),
            Rar50VolumeEntries::Stored(entry) => (false, entry.data.len() as u64, 1),
            Rar50VolumeEntries::EncryptedStored(entry) => (false, entry.data.len() as u64, 1),
        };
        let total_work = if compressed && self.options.features.solid {
            match &entries {
                Rar50VolumeEntries::Compressed(entries) => entries
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| entry.data.len() as u64 * if index == 0 { 1 } else { 2 })
                    .sum(),
                Rar50VolumeEntries::EncryptedCompressed(entries) => entries
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| entry.data.len() as u64 * if index == 0 { 1 } else { 2 })
                    .sum(),
                _ => total_bytes,
            }
        } else {
            total_bytes
        };
        if compressed {
            report_operation_started(
                self.progress,
                WriteOperation::Compression,
                total_work,
                total_entries,
                1,
            );
        }
        let work = WorkTracker::new(self.progress, WriteOperation::Compression, total_work);
        let result = match entries {
            Rar50VolumeEntries::Stored(entry) => write_stored_volumes_impl(
                entry,
                self.options,
                max_payload_per_volume,
                self.recovery_percent,
            ),
            Rar50VolumeEntries::Compressed(entries) => write_compressed_volume_set_impl(
                entries,
                self.options,
                max_payload_per_volume,
                self.recovery_percent,
                compressed.then_some(&work),
            ),
            Rar50VolumeEntries::EncryptedStored(entry) => write_encrypted_stored_volumes_impl(
                entry,
                self.options,
                max_payload_per_volume,
                self.recovery_percent,
            ),
            Rar50VolumeEntries::EncryptedCompressed(entries) => {
                write_encrypted_compressed_volume_set_impl(
                    entries,
                    self.options,
                    max_payload_per_volume,
                    self.recovery_percent,
                    compressed.then_some(&work),
                )
            }
        };
        if compressed {
            if result.is_ok() && !work.finish() {
                return Err(Error::Cancelled);
            }
            report_operation_finished(
                self.progress,
                WriteOperation::Compression,
                total_work,
                total_entries,
                1,
            );
        }
        result
    }
}

impl<'a> Rar50Writer<'a> {
    pub fn new(options: WriterOptions) -> Self {
        Self {
            options,
            members: Vec::new(),
            archive_comment: None,
            archive_metadata: None,
            filter_policy: FilterPolicy::None,
            recovery_percent: None,
            recovery_password: None,
            progress: None,
        }
    }

    pub fn stored_entries(mut self, entries: &[StoredEntry<'a>]) -> Self {
        self.members
            .extend(entries.iter().copied().map(Rar50WriteMember::Stored));
        self
    }

    pub fn compressed_entries(mut self, entries: &[CompressedEntry<'a>]) -> Self {
        self.members
            .extend(entries.iter().copied().map(Rar50WriteMember::Compressed));
        self
    }

    pub fn encrypted_stored_entries(mut self, entries: &[EncryptedStoredEntry<'a>]) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::EncryptedStored),
        );
        self
    }

    pub fn stored_entries_with_services(mut self, entries: &[StoredEntryWithServices<'a>]) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::StoredWithServices),
        );
        self
    }

    pub fn encrypted_compressed_entries(
        mut self,
        entries: &[EncryptedCompressedEntry<'a>],
    ) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::EncryptedCompressed),
        );
        self
    }

    pub fn encrypted_stored_entries_with_services(
        mut self,
        entries: &[EncryptedStoredEntryWithServices<'a>],
    ) -> Self {
        self.members.extend(
            entries
                .iter()
                .copied()
                .map(Rar50WriteMember::EncryptedStoredWithServices),
        );
        self
    }

    pub fn archive_comment(mut self, comment: Option<&'a [u8]>) -> Self {
        self.archive_comment = comment.map(ArchiveComment::Plain);
        self
    }

    pub fn encrypted_archive_comment(
        mut self,
        comment: Option<EncryptedArchiveCommentEntry<'a>>,
    ) -> Self {
        self.archive_comment = comment.map(ArchiveComment::Encrypted);
        self
    }

    pub fn archive_metadata(mut self, metadata: Option<ArchiveMetadataEntry<'a>>) -> Self {
        self.archive_metadata = metadata;
        self
    }

    pub fn filter_policy(mut self, policy: FilterPolicy) -> Self {
        self.filter_policy = policy;
        self
    }

    pub fn recovery_percent(mut self, percent: Option<u64>) -> Self {
        self.recovery_percent = percent;
        self
    }

    pub fn recovery_password(mut self, password: Option<&'a [u8]>) -> Self {
        self.recovery_password = password;
        self
    }

    pub fn progress(mut self, progress: &'a dyn WriteProgress) -> Self {
        self.progress = Some(ProgressReporter(progress));
        self
    }

    /// Builds the archive in memory. Prefer [`Rar50Writer::write_to`], which
    /// streams it instead.
    pub fn finish(self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.write_to(&mut out, &WriterResources::default())?;
        Ok(out)
    }

    /// Writes the archive straight to `output` without ever holding it.
    pub fn write_to(self, output: &mut dyn Write, resources: &WriterResources) -> Result<()> {
        let member_kind = self.members.iter().try_fold(None, |seen, member| {
            let kind = member.kind();
            if seen.is_some_and(|seen| seen != kind) {
                return Err(mixed_member_plan_error(self.options.target));
            }
            Ok(Some(kind))
        })?;

        let _encrypted = matches!(
            member_kind,
            Some(
                Rar50WriteMemberKind::EncryptedStored
                    | Rar50WriteMemberKind::EncryptedStoredWithServices
                    | Rar50WriteMemberKind::EncryptedCompressed
            )
        );
        let stored = matches!(
            member_kind,
            Some(
                Rar50WriteMemberKind::Stored
                    | Rar50WriteMemberKind::StoredWithServices
                    | Rar50WriteMemberKind::EncryptedStored
                    | Rar50WriteMemberKind::EncryptedStoredWithServices
            ) | None
        );

        // Stored and compressed writers reject different feature sets, and
        // say so differently.
        let recovery = self.recovery_percent.is_some();
        match member_kind {
            Some(Rar50WriteMemberKind::StoredWithServices) => {
                validate_file_service_options(self.options)?
            }
            Some(Rar50WriteMemberKind::EncryptedStoredWithServices) => {
                validate_encrypted_file_service_options(self.options)?
            }
            Some(Rar50WriteMemberKind::Stored) | None if recovery => {
                validate_recovery_options(self.options)?
            }
            Some(Rar50WriteMemberKind::Stored) | None => validate_options(self.options)?,
            Some(Rar50WriteMemberKind::EncryptedStored) if recovery => {
                validate_encrypted_recovery_options(self.options)?
            }
            Some(Rar50WriteMemberKind::EncryptedStored) => {
                validate_encrypted_options(self.options)?
            }
            Some(Rar50WriteMemberKind::Compressed) if recovery => {
                validate_compressed_recovery_options(self.options)?
            }
            Some(Rar50WriteMemberKind::Compressed) => validate_compressed_options(self.options)?,
            Some(Rar50WriteMemberKind::EncryptedCompressed) if recovery => {
                validate_encrypted_compressed_recovery_options(self.options)?
            }
            Some(Rar50WriteMemberKind::EncryptedCompressed) => {
                validate_encrypted_compressed_options(self.options)?
            }
        }
        if let Some(percent) = self.recovery_percent {
            validate_recovery_percent(percent)?;
        }
        if self.filter_policy != FilterPolicy::None && self.options.features.solid {
            return Err(Error::UnsupportedFeature {
                version: self.options.target,
                feature: "RAR 5 solid filtered compressed writer",
            });
        }
        for member in &self.members {
            member.validate_member()?;
        }

        // A stored member set is written verbatim whatever the level says.
        let mut options = self.options;
        if stored {
            options = options.with_compression_level(0);
        }

        let comment_password = match &self.archive_comment {
            Some(ArchiveComment::Encrypted(comment)) => Some(comment.password),
            _ => None,
        };
        let comment = match &self.archive_comment {
            Some(ArchiveComment::Plain(data)) => Some(*data),
            Some(ArchiveComment::Encrypted(comment)) => Some(comment.data),
            None => None,
        };
        let mut extras = ArchiveExtras::default()
            .with_recovery_percent(self.recovery_percent)
            .with_quick_open(self.options.features.quick_open)
            .with_filter_policy(self.filter_policy);
        if let Some(comment) = comment {
            extras = match comment_password {
                Some(password) => extras.with_encrypted_comment(comment, password),
                None => extras.with_comment(comment),
            };
        }
        if let Some(metadata) = self.archive_metadata {
            extras = extras.with_metadata(metadata);
        }

        let entries: Vec<_> = self
            .members
            .into_iter()
            .map(Rar50WriteMember::into_archive_entry)
            .collect();
        write_streaming_archive_with_progress(
            &entries,
            options,
            extras,
            resources,
            self.progress,
            output,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rar50WriteMemberKind {
    Stored,
    StoredWithServices,
    Compressed,
    EncryptedStored,
    EncryptedStoredWithServices,
    EncryptedCompressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rar50WriteMember<'a> {
    Stored(StoredEntry<'a>),
    StoredWithServices(StoredEntryWithServices<'a>),
    Compressed(CompressedEntry<'a>),
    EncryptedStored(EncryptedStoredEntry<'a>),
    EncryptedStoredWithServices(EncryptedStoredEntryWithServices<'a>),
    EncryptedCompressed(EncryptedCompressedEntry<'a>),
}

impl Rar50WriteMember<'_> {
    fn kind(&self) -> Rar50WriteMemberKind {
        match self {
            Self::Stored(_) => Rar50WriteMemberKind::Stored,
            Self::StoredWithServices(_) => Rar50WriteMemberKind::StoredWithServices,
            Self::Compressed(_) => Rar50WriteMemberKind::Compressed,
            Self::EncryptedStored(_) => Rar50WriteMemberKind::EncryptedStored,
            Self::EncryptedStoredWithServices(_) => {
                Rar50WriteMemberKind::EncryptedStoredWithServices
            }
            Self::EncryptedCompressed(_) => Rar50WriteMemberKind::EncryptedCompressed,
        }
    }

    fn validate_member(&self) -> Result<()> {
        match self {
            Self::Stored(entry) => validate_entry(entry),
            Self::Compressed(entry) => validate_compressed_entry(entry),
            Self::EncryptedStored(entry) => validate_encrypted_entry(entry),
            Self::EncryptedCompressed(entry) => validate_encrypted_compressed_entry(entry),
            Self::StoredWithServices(member) => {
                validate_entry(&member.entry)?;
                member.services.iter().try_for_each(validate_file_service)
            }
            Self::EncryptedStoredWithServices(member) => {
                validate_encrypted_entry(&member.entry)?;
                member
                    .services
                    .iter()
                    .try_for_each(validate_encrypted_file_service)
            }
        }
    }

    /// Converts a builder member into the engine's entry form. The data is
    /// copied because the engine reads members from reopenable sources; the
    /// caller already holds it in memory either way.
    fn into_archive_entry(self) -> ArchiveEntry {
        fn entry(
            name: &[u8],
            data: &[u8],
            mtime: Option<u32>,
            attributes: u64,
            host_os: u64,
        ) -> ArchiveEntry {
            ArchiveEntry::new(
                name.to_vec(),
                EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
            )
            .with_mtime(mtime)
            .with_attributes(attributes)
            .with_host_os(host_os)
        }

        match self {
            Self::Stored(member) => entry(
                member.name,
                member.data,
                member.mtime,
                member.attributes,
                member.host_os,
            ),
            Self::Compressed(member) => entry(
                member.name,
                member.data,
                member.mtime,
                member.attributes,
                member.host_os,
            ),
            Self::StoredWithServices(member) => {
                let mut built = entry(
                    member.entry.name,
                    member.entry.data,
                    member.entry.mtime,
                    member.entry.attributes,
                    member.entry.host_os,
                );
                for service in member.services {
                    built = built.with_service(ServiceEntry::new(
                        service.name.to_vec(),
                        service.data.to_vec(),
                    ));
                }
                built
            }
            Self::EncryptedStored(member) => entry(
                member.name,
                member.data,
                member.mtime,
                member.attributes,
                member.host_os,
            )
            .with_password(member.password.to_vec()),
            Self::EncryptedCompressed(member) => entry(
                member.name,
                member.data,
                member.mtime,
                member.attributes,
                member.host_os,
            )
            .with_password(member.password.to_vec()),
            Self::EncryptedStoredWithServices(member) => {
                let mut built = entry(
                    member.entry.name,
                    member.entry.data,
                    member.entry.mtime,
                    member.entry.attributes,
                    member.entry.host_os,
                )
                .with_password(member.entry.password.to_vec());
                for service in member.services {
                    built = built.with_service(
                        ServiceEntry::new(service.name.to_vec(), service.data.to_vec())
                            .with_password(service.password.to_vec()),
                    );
                }
                built
            }
        }
    }
}

impl<'a> Rar50WriteMember<'a> {}

fn mixed_member_plan_error(target: crate::ArchiveVersion) -> Error {
    Error::UnsupportedFeature {
        version: target,
        feature: "RAR 5 mixed stored/compressed writer plan",
    }
}

fn report_operation_started(
    progress: Option<ProgressReporter<'_>>,
    operation: WriteOperation,
    total_bytes: u64,
    total_entries: usize,
    pass: usize,
) {
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationStarted {
            operation,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass,
        });
    }
}

fn report_operation_finished(
    progress: Option<ProgressReporter<'_>>,
    operation: WriteOperation,
    total_bytes: u64,
    total_entries: usize,
    pass: usize,
) {
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationFinished {
            operation,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass,
        });
    }
}

fn validate_options(options: WriterOptions) -> Result<()> {
    validate_plain_options(options, false)
}

fn validate_recovery_options(options: WriterOptions) -> Result<()> {
    validate_plain_options(options, true)
}

fn validate_plain_options(options: WriterOptions, allow_recovery_record: bool) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.archive_comment = options.features.archive_comment;
    allowed.quick_open = options.features.quick_open;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 writer feature",
        });
    }
    Ok(())
}

fn validate_file_service_options(options: WriterOptions) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_comment = options.features.file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 stored file-service writer feature",
        });
    }
    Ok(())
}

fn validate_compressed_options(options: WriterOptions) -> Result<()> {
    validate_compressed_feature_options(options, false)
}

fn validate_compressed_recovery_options(options: WriterOptions) -> Result<()> {
    validate_compressed_feature_options(options, true)
}

fn validate_compressed_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.solid = options.features.solid;
    allowed.archive_comment = options.features.archive_comment;
    allowed.file_comment = options.features.file_comment;
    allowed.quick_open = options.features.quick_open;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 compressed writer feature",
        });
    }
    Ok(())
}

fn validate_encrypted_compressed_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_compressed_feature_options(options, false)
}

fn validate_encrypted_compressed_recovery_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_compressed_feature_options(options, true)
}

fn validate_encrypted_compressed_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.solid = options.features.solid;
    allowed.archive_comment = options.features.archive_comment;
    allowed.file_comment = options.features.file_comment;
    allowed.quick_open = options.features.quick_open;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted compressed writer feature",
        });
    }
    Ok(())
}

fn validate_encrypted_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_feature_options(options, false)
}

fn validate_encrypted_recovery_options(options: WriterOptions) -> Result<()> {
    validate_encrypted_feature_options(options, true)
}

fn validate_encrypted_feature_options(
    options: WriterOptions,
    allow_recovery_record: bool,
) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.archive_comment = options.features.archive_comment;
    if allow_recovery_record {
        allowed.recovery_record = options.features.recovery_record;
    }
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted stored writer feature",
        });
    }
    Ok(())
}

fn validate_encrypted_file_service_options(options: WriterOptions) -> Result<()> {
    validate_compression_level(options)?;
    if !matches!(
        options.target,
        crate::ArchiveVersion::Rar50 | crate::ArchiveVersion::Rar70
    ) {
        return Err(Error::UnsupportedVersion(options.target));
    }
    let mut allowed = crate::FeatureSet::store_only();
    allowed.file_encryption = true;
    allowed.header_encryption = options.features.header_encryption;
    allowed.file_comment = options.features.file_comment;
    if options.features != allowed {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 encrypted stored file-service writer feature",
        });
    }
    Ok(())
}

fn stored_entry_from_compressed_entry<'a>(entry: &CompressedEntry<'a>) -> StoredEntry<'a> {
    StoredEntry {
        name: entry.name,
        data: entry.data,
        mtime: entry.mtime,
        attributes: entry.attributes,
        host_os: entry.host_os,
    }
}

struct CompressedFragment<'a, 'b> {
    entry: &'a CompressedEntry<'b>,
    data: &'a [u8],
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
    split_before: bool,
    split_after: bool,
}

fn write_compressed_entry_fragment(
    out: &mut Vec<u8>,
    fragment: CompressedFragment<'_, '_>,
) -> Result<()> {
    let CompressedFragment {
        entry,
        data,
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
        split_before,
        split_after,
    } = fragment;

    let mut extra = Vec::new();
    if !split_after {
        write_hash_record(&mut extra, entry.data);
    }
    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(crc32(entry.data)),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let mut block_flags = HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }
    if !extra.is_empty() {
        block_flags |= HFL_EXTRA;
    }

    write_block(
        out,
        HEAD_FILE,
        block_flags,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

struct EncryptedStoredPayload {
    data: Vec<u8>,
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
    crc32_mac: u32,
    blake2sp_mac: [u8; 32],
}

fn encrypted_stored_payload(data: &[u8], password: &[u8]) -> Result<EncryptedStoredPayload> {
    encrypted_payload(data, data, password)
}

fn encrypted_payload(
    packed_data: &[u8],
    integrity_data: &[u8],
    password: &[u8],
) -> Result<EncryptedStoredPayload> {
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption salt"))?;
    getrandom::fill(&mut iv)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption IV"))?;
    let keys = Rar50Keys::derive(password, salt, 0).map_err(super::map_rar50_crypto_error)?;

    let mut encrypted_data = packed_data.to_vec();
    let padded_len = encrypted_data
        .len()
        .checked_add(15)
        .ok_or(Error::InvalidHeader("RAR 5 encrypted data size overflows"))?
        & !15;
    encrypted_data.resize(padded_len, 0);
    Rar50Cipher::new(keys.key, iv)
        .encrypt_in_place(&mut encrypted_data)
        .map_err(super::map_rar50_crypto_error)?;

    Ok(EncryptedStoredPayload {
        data: encrypted_data,
        salt,
        iv,
        check_value: keys.password_check_record(),
        crc32_mac: keys.mac_crc32(crc32(integrity_data)),
        blake2sp_mac: keys.mac_hash32(blake2sp::hash(integrity_data)),
    })
}

fn write_encrypted_stored_entry_fragment_with_header_keys(
    out: &mut Vec<u8>,
    entry: &EncryptedStoredEntry<'_>,
    data: &[u8],
    encrypted: &EncryptedStoredPayload,
    split_before: bool,
    split_after: bool,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    if !split_after {
        write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    }

    let specific = stored_file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    let mut block_flags = HFL_EXTRA | HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )
    }
}

fn encrypted_stored_entry_from_compressed_entry<'a>(
    entry: &EncryptedCompressedEntry<'a>,
) -> EncryptedStoredEntry<'a> {
    EncryptedStoredEntry {
        name: entry.name,
        data: entry.data,
        mtime: entry.mtime,
        attributes: entry.attributes,
        host_os: entry.host_os,
        password: entry.password,
    }
}

struct EncryptedCompressedFragment<'a, 'b> {
    entry: &'a EncryptedCompressedEntry<'b>,
    data: &'a [u8],
    encrypted: &'a EncryptedStoredPayload,
    algorithm_version: u8,
    compression_method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
    split_before: bool,
    split_after: bool,
}

fn write_encrypted_compressed_entry_fragment_with_header_keys(
    out: &mut Vec<u8>,
    fragment: EncryptedCompressedFragment<'_, '_>,
    header_keys: Option<&Rar50Keys>,
) -> Result<()> {
    let EncryptedCompressedFragment {
        entry,
        data,
        encrypted,
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
        split_before,
        split_after,
    } = fragment;

    let mut extra = Vec::new();
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    if !split_after {
        write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    }

    let compression_info = compression_info(
        algorithm_version,
        compression_method,
        dictionary_size,
        solid_continuation,
    )?;
    let specific = file_specific(
        entry.name,
        entry.data.len() as u64,
        (!split_after).then_some(encrypted.crc32_mac),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let mut block_flags = HFL_EXTRA | HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }

    if let Some(header_keys) = header_keys {
        out.extend_from_slice(&encrypted_header_block(
            header_keys,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )?);
        Ok(())
    } else {
        write_block(
            out,
            HEAD_FILE,
            block_flags,
            Some(data.len() as u64),
            &specific,
            &extra,
            data,
        )
    }
}

fn write_stored_entry_fragment(
    out: &mut Vec<u8>,
    entry: &StoredEntry<'_>,
    data: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    split_before: bool,
    split_after: bool,
) -> Result<()> {
    let mut extra = Vec::new();
    if !split_before && !split_after {
        write_hash_record(&mut extra, data);
    }
    let specific = stored_file_specific(
        entry.name,
        unpacked_size,
        data_crc32,
        entry.attributes,
        entry.mtime,
        entry.host_os,
    )?;
    let mut block_flags = HFL_DATA;
    if split_before {
        block_flags |= HFL_SPLIT_BEFORE;
    }
    if split_after {
        block_flags |= HFL_SPLIT_AFTER;
    }
    if !extra.is_empty() {
        block_flags |= HFL_EXTRA;
    }

    write_block(
        out,
        HEAD_FILE,
        block_flags,
        Some(data.len() as u64),
        &specific,
        &extra,
        data,
    )
}

fn write_recovery_service(
    out: &mut Vec<u8>,
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<()> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data);

    let data =
        build_structural_inline_recovery_data_with_progress(out, recovery_percent, progress, pass)?;
    let specific = stored_file_specific(b"RR", data.len() as u64, Some(crc32(&data)), 0, None, 0)?;
    write_block(
        out,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        &data,
    )
}

fn write_header_encrypted_recovery_service(
    out: &mut Vec<u8>,
    recovery_percent: u64,
    header_keys: &Rar50Keys,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<()> {
    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let data =
        build_structural_inline_recovery_data_with_progress(out, recovery_percent, progress, pass)?;
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data);
    let specific = stored_file_specific(b"RR", data.len() as u64, Some(crc32(&data)), 0, None, 0)?;
    out.extend_from_slice(&encrypted_header_block(
        header_keys,
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data.len() as u64),
        &specific,
        &extra,
        &data,
    )?);
    Ok(())
}

fn validate_entry(entry: &StoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)
}

fn validate_compressed_entry(entry: &CompressedEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)
}

fn validate_encrypted_entry(entry: &EncryptedStoredEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)?;
    if entry.password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_encrypted_compressed_entry(entry: &EncryptedCompressedEntry<'_>) -> Result<()> {
    validate_file_entry(entry.name)?;
    if entry.password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_file_service(service: &StoredServiceEntry<'_>) -> Result<()> {
    if !matches!(service.name, b"ACL" | b"STM" | b"CMT") {
        return Err(Error::UnsupportedFeature {
            version: crate::ArchiveVersion::Rar50,
            feature: "RAR 5 stored file service name",
        });
    }
    if service.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 stored file service data is empty",
        ));
    }
    Ok(())
}

fn validate_encrypted_file_service(service: &EncryptedStoredServiceEntry<'_>) -> Result<()> {
    if !matches!(service.name, b"CMT") {
        return Err(Error::UnsupportedFeature {
            version: crate::ArchiveVersion::Rar50,
            feature: "RAR 5 encrypted stored file service name",
        });
    }
    if service.data.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted stored file service data is empty",
        ));
    }
    validate_nonempty_password(service.password)
}

fn validate_recovery_percent(percent: u64) -> Result<()> {
    if !(1..=100).contains(&percent) {
        return Err(Error::InvalidHeader(
            "RAR 5 recovery percent must be in 1..=100",
        ));
    }
    Ok(())
}

fn validate_nonempty_password(password: &[u8]) -> Result<()> {
    if password.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 encrypted writer needs a non-empty password",
        ));
    }
    Ok(())
}

fn validate_file_entry(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::filter_policy::{
        encode_member_with_auto_size_filter, encode_member_with_filter_policy_candidates,
        encode_member_with_filter_spec, encode_member_with_filter_specs,
    };
    use super::*;
    use crate::codec::rar50::{encode_literal_only, encode_lz_member};
    use crate::codec::rar50::{encode_lz_member_with_options, EncodeOptions};
    use crate::filter_search::{
        auto_delta_filter_range, disjoint_filter_ranges, AUTO_DELTA_EDGE_SKIP,
    };
    use crate::x86_filter_scan::auto_x86_filter_ranges;
    use crate::{ArchiveVersion, FeatureSet};
    use std::cell::RefCell;
    use std::fs;
    use std::io::{Cursor, Result as IoResult, Write};
    use std::process::Command;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CollectWriter(Rc<RefCell<Vec<u8>>>);

    #[test]
    fn compressed_writer_reports_determinate_progress() {
        let data: Vec<u8> = (0usize..128 * 1024)
            .map(|i| (i.wrapping_mul(37) % 251) as u8)
            .collect();
        let entry = CompressedEntry {
            name: b"payload.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 1,
        };
        let last = std::sync::atomic::AtomicU64::new(0);
        let advances = AtomicUsize::new(0);
        let intermediate = std::sync::atomic::AtomicBool::new(false);
        let reporter = |event: WriteProgressEvent<'_>| {
            if let WriteProgressEvent::Advanced {
                operation: WriteOperation::Compression,
                completed_bytes,
                total_bytes,
                ..
            } = event
            {
                assert!(completed_bytes >= last.swap(completed_bytes, Ordering::Relaxed));
                assert!(completed_bytes <= total_bytes);
                if completed_bytes < total_bytes {
                    intermediate.store(true, Ordering::Relaxed);
                }
                advances.fetch_add(1, Ordering::Relaxed);
            }
        };

        Rar50Writer::new(WriterOptions::new(
            ArchiveVersion::Rar70,
            FeatureSet::default(),
        ))
        .compressed_entries(&[entry])
        .filter_policy(FilterPolicy::Auto)
        .progress(&reporter)
        .finish()
        .unwrap();

        assert!(advances.load(Ordering::Relaxed) >= 1);
        assert!(intermediate.load(Ordering::Relaxed));
        // Progress is now counted in input bytes, however many passes the
        // filter search makes over them.
        assert_eq!(last.load(Ordering::Relaxed), data.len() as u64);
    }

    #[test]
    fn recovery_writer_reports_determinate_pass_progress() {
        let entry = StoredEntry {
            name: b"payload.bin",
            data: b"recovery progress payload",
            mtime: None,
            attributes: 0x20,
            host_os: 1,
        };
        let starts = AtomicUsize::new(0);
        let advances = AtomicUsize::new(0);
        let finishes = AtomicUsize::new(0);
        let reporter = |event: WriteProgressEvent<'_>| match event {
            WriteProgressEvent::OperationStarted {
                operation: WriteOperation::Recovery,
                total_bytes: Some(total),
                ..
            } => {
                assert!(total > 0);
                starts.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::Advanced {
                operation: WriteOperation::Recovery,
                completed_bytes,
                total_bytes,
                ..
            } => {
                assert!(completed_bytes <= total_bytes);
                advances.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::OperationFinished {
                operation: WriteOperation::Recovery,
                ..
            } => {
                finishes.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        };
        let mut features = FeatureSet::store_only();
        features.recovery_record = true;

        Rar50Writer::new(WriterOptions::new(ArchiveVersion::Rar50, features))
            .stored_entries(&[entry])
            .recovery_percent(Some(10))
            .progress(&reporter)
            .finish()
            .unwrap();

        assert!(starts.load(Ordering::Relaxed) >= 1);
        assert!(advances.load(Ordering::Relaxed) >= 1);
        assert_eq!(
            starts.load(Ordering::Relaxed),
            finishes.load(Ordering::Relaxed)
        );
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        attr: u64,
        host_os: u64,
        is_directory: bool,
    }

    fn collect_extract(archive: &Archive) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(crate::ArchiveReadOptions::default(), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter(data)))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                attr: meta.attr,
                host_os: meta.host_os,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    #[test]
    fn streaming_writer_round_trips_across_input_blocks() {
        let data = b"bounded streaming member data\n".repeat(80_000);
        let entry = StreamingCompressedEntry {
            name: b"large.txt".to_vec(),
            source: EntrySource::from_bytes(Arc::<[u8]>::from(data.clone())),
            mtime: None,
            attributes: 0x20,
            host_os: 1,
        };
        let mut bytes = Vec::new();
        write_streaming_compressed_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
            &WriterResources::default(),
            &mut bytes,
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"large.txt");
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn streaming_writer_rejects_workspace_larger_than_budget() {
        let entry = StreamingCompressedEntry {
            name: b"small.txt".to_vec(),
            source: EntrySource::from_bytes(Arc::<[u8]>::from(&b"small"[..])),
            mtime: None,
            attributes: 0x20,
            host_os: 1,
        };
        let result = write_streaming_compressed_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
            &WriterResources::new(1024),
            &mut Vec::new(),
        );
        assert!(matches!(result, Err(Error::MemoryLimitExceeded { .. })));
    }

    #[test]
    fn parallel_streaming_blocks_are_byte_identical_to_serial_blocks() {
        let mut data = Vec::new();
        for index in 0..52_000u32 {
            data.extend_from_slice(b"parallel block identity payload ");
            data.extend_from_slice(&index.to_le_bytes());
        }
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
        let algorithm_version = rar50_algorithm_version(options).unwrap();
        let dictionary_size = dictionary_size_for_options(options).unwrap();
        let encode_options =
            encode_options_for_level(options.compression_level, dictionary_size).unwrap();
        let block_size = 1024 * 1024;
        let mut serial = Vec::new();
        crate::codec::rar50::encode_lz_reader_to(
            &mut Cursor::new(&data),
            data.len() as u64,
            &mut serial,
            algorithm_version,
            encode_options,
            block_size,
            None,
        )
        .unwrap();

        let source = EntrySource::from_bytes(Arc::<[u8]>::from(data));
        let required = streaming_lz_workspace(dictionary_size, block_size);
        let mut prepared = compress::compress_members(
            &[source],
            compress::CompressPlan {
                algorithm_version,
                encode_options,
                dictionary_size,
                block_size,
                solid: false,
                method: 1,
                filter_policy: FilterPolicy::None,
                candidates: vec![encode_options],
            },
            &WriterResources::new(required.saturating_mul(4)),
        )
        .unwrap();
        let mut parallel = Vec::new();
        prepared[0].packed.copy_to(&mut parallel).unwrap();
        assert_eq!(parallel, serial);
    }

    #[test]
    fn streaming_entry_order_is_identical_at_one_and_many_job_budgets() {
        let entries: Vec<_> = (0..4u8)
            .map(|index| {
                let mut data = vec![index; 1_300_000];
                data.extend((0..300_000).map(|offset| (offset as u8).wrapping_add(index)));
                StreamingCompressedEntry {
                    name: format!("entry-{index}.bin").into_bytes(),
                    source: EntrySource::from_bytes(Arc::<[u8]>::from(data)),
                    mtime: None,
                    attributes: 0x20,
                    host_os: 1,
                }
            })
            .collect();
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
        let dictionary_size = dictionary_size_for_options(options).unwrap();
        let required = streaming_lz_workspace(dictionary_size, 1024 * 1024);
        let mut one_job = Vec::new();
        write_streaming_compressed_archive_to(
            &entries,
            options,
            &WriterResources::new(required),
            &mut one_job,
        )
        .unwrap();
        let mut many_jobs = Vec::new();
        write_streaming_compressed_archive_to(
            &entries,
            options,
            &WriterResources::new(required.saturating_mul(4)),
            &mut many_jobs,
        )
        .unwrap();
        assert_eq!(many_jobs, one_job);
    }

    #[test]
    fn streaming_writer_rejects_a_source_that_grows_between_passes() {
        let opens = Arc::new(AtomicUsize::new(0));
        let source = EntrySource::from_opener(4, {
            let opens = Arc::clone(&opens);
            move || {
                let data = if opens.fetch_add(1, Ordering::SeqCst) == 0 {
                    b"data".to_vec()
                } else {
                    b"data!".to_vec()
                };
                Ok(Box::new(Cursor::new(data)))
            }
        });
        let entry = StreamingCompressedEntry {
            name: b"changing.bin".to_vec(),
            source,
            mtime: None,
            attributes: 0x20,
            host_os: 1,
        };
        let result = write_streaming_compressed_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
            &WriterResources::default(),
            &mut Vec::new(),
        );
        assert!(matches!(
            result,
            Err(Error::InvalidHeader(
                "entry source size changed while compressing"
            ))
        ));
    }

    #[test]
    fn encrypted_streaming_writer_round_trips_across_input_blocks() {
        let data = b"encrypted bounded streaming member data\n".repeat(40_000);
        let entry = StreamingEncryptedCompressedEntry {
            name: b"secret.txt".to_vec(),
            source: EntrySource::from_bytes(Arc::<[u8]>::from(data.clone())),
            mtime: None,
            attributes: 0x20,
            host_os: 1,
            password: b"password".to_vec(),
        };
        let mut features = FeatureSet::store_only();
        features.file_encryption = true;
        let mut bytes = Vec::new();
        write_streaming_encrypted_compressed_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, features),
            &WriterResources::default(),
            &mut bytes,
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let entries = RefCell::new(Vec::new());
        archive
            .extract_to(
                crate::ArchiveReadOptions::with_password(b"password"),
                |meta| {
                    let output = Rc::new(RefCell::new(Vec::new()));
                    entries
                        .borrow_mut()
                        .push((meta.name.clone(), Rc::clone(&output)));
                    Ok(Box::new(CollectWriter(output)))
                },
            )
            .unwrap();
        let entries = entries.into_inner();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, b"secret.txt");
        assert_eq!(*entries[0].1.borrow(), data);
    }

    #[test]
    fn internal_literal_only_compressed_member_round_trips_through_rar50_reader() {
        let data = b"RAR5 literal-only compressed format-layer experiment\n";
        let packed = encode_literal_only(data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, data);
        let compression_info = 1 << 7; // RAR5 v0, non-solid, method m1, 128 KiB dictionary.
        let specific = file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0x20,
            None,
            compression_info,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_end_header(&mut archive, 0).unwrap();

        let parsed = Archive::parse(&archive).unwrap();
        let file = parsed.files().next().unwrap();
        let info = file.decoded_compression_info().unwrap();
        assert_eq!(info.method, 1);
        assert_eq!(info.dictionary_size, 128 * 1024);

        let extracted = collect_extract(&parsed).unwrap();
        assert_eq!(extracted[0].name, name);
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn writer_stamps_requested_rar50_dictionary_size() {
        let data = b"RAR5 dictionary-size writer option fixture".repeat(64);
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default())
                .with_dictionary_size(512 * 1024);
        let entries = [CompressedEntry {
            name: b"dict.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let archive = Rar50Writer::new(options)
            .compressed_entries(&entries)
            .finish()
            .unwrap();

        let parsed = Archive::parse(&archive).unwrap();
        let info = parsed
            .files()
            .next()
            .unwrap()
            .decoded_compression_info()
            .unwrap();
        let extracted = collect_extract(&parsed).unwrap();

        assert_eq!(info.algorithm_version, 0);
        assert_eq!(info.dictionary_size, 512 * 1024);
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn writer_uses_rar7_dictionary_fields_when_size_needs_v1_encoding() {
        let data = b"RAR7 dictionary-size writer option fixture".repeat(64);
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar70, crate::FeatureSet::default())
                .with_dictionary_size(192 * 1024);
        let entries = [CompressedEntry {
            name: b"dict7.bin",
            data: &data,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let archive = Rar50Writer::new(options)
            .compressed_entries(&entries)
            .finish()
            .unwrap();

        let parsed = Archive::parse(&archive).unwrap();
        let info = parsed
            .files()
            .next()
            .unwrap()
            .decoded_compression_info()
            .unwrap();
        let extracted = collect_extract(&parsed).unwrap();

        assert_eq!(info.algorithm_version, 1);
        assert_eq!(info.dictionary_size, 192 * 1024);
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn writer_rejects_unencodable_rar50_dictionary_size() {
        let options =
            WriterOptions::new(crate::ArchiveVersion::Rar50, crate::FeatureSet::default())
                .with_dictionary_size(192 * 1024);
        let entries = [CompressedEntry {
            name: b"bad.bin",
            data: b"data data data data",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];

        assert!(matches!(
            Rar50Writer::new(options)
                .compressed_entries(&entries)
                .finish(),
            Err(Error::InvalidHeader(
                "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB"
            ))
        ));
    }

    #[test]
    fn non_solid_level_five_considers_lower_level_parse_fallbacks() {
        let long_tail = b"stable long match payload for RAR5 best-level search ".repeat(10);
        let mut data = Vec::new();
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&long_tail);
        for index in 0..320usize {
            data.extend_from_slice(b"abc");
            data.push((index as u8).wrapping_mul(37));
            data.extend_from_slice(b" near same-hash decoy ");
            data.extend_from_slice(&(index as u32).to_le_bytes());
        }
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&long_tail);

        let level_five = encode_options_for_level(Some(5), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
        let fallback_candidates =
            encode_option_candidates_for_level(Some(5), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
        assert!(fallback_candidates.len() > 1);

        let level_five_only =
            encode_member_with_filter_policy(&data, 0, &FilterPolicy::None, level_five).unwrap();
        let chosen = encode_member_with_filter_policy_candidates(
            &data,
            0,
            &FilterPolicy::None,
            &fallback_candidates,
        )
        .unwrap();

        assert!(
            chosen.len() <= level_five_only.len(),
            "candidate fallback should not choose a larger parse: level5={} chosen={}",
            level_five_only.len(),
            chosen.len()
        );

        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();
        let output = decoder
            .decode_member(
                &chosen,
                0,
                data.len(),
                false,
                crate::codec::rar50::DecodeMode::Lz,
            )
            .unwrap();
        assert_eq!(output, data);
    }

    #[test]
    fn auto_x86_filter_ranges_select_dense_opcode_clusters() {
        let mut data = vec![0u8; 100_000];
        data[1_000] = 0xe8;
        data[7_000] = 0xe9;
        for pos in [50_000, 50_064, 50_128, 50_192] {
            data[pos] = 0xe8;
        }
        for pos in [70_000, 70_064, 70_128, 70_192] {
            data[pos] = 0xe9;
        }

        let e8_ranges = auto_x86_filter_ranges(&data, false);
        assert!(e8_ranges
            .iter()
            .any(|range| range.start <= 50_000 && range.end >= 50_197));
        assert!(!e8_ranges
            .iter()
            .any(|range| range.start <= 1_000 && range.end >= 1_005));

        let e8e9_ranges = auto_x86_filter_ranges(&data, true);
        assert!(e8e9_ranges
            .iter()
            .any(|range| range.start <= 70_000 && range.end >= 70_197));
    }

    #[test]
    fn auto_x86_filter_policy_can_emit_multiple_disjoint_ranges() {
        let mut data = vec![0x41u8; 80_000];
        for cluster_start in [8_000, 60_000] {
            for index in 0..8 {
                let pos = cluster_start + index * 64;
                data[pos] = 0xe8;
                data[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
            }
        }
        let ranges = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false));
        let filters: Vec<_> = ranges
            .into_iter()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();

        let packed =
            encode_member_with_filter_specs(&data, 0, &filters, EncodeOptions::default()).unwrap();
        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();
        let output = decoder
            .decode_member(
                &packed,
                0,
                data.len(),
                false,
                crate::codec::rar50::DecodeMode::Lz,
            )
            .unwrap();

        assert_eq!(filters.len(), 2);
        assert_eq!(output, data);
    }

    #[test]
    fn auto_filter_policy_considers_ranged_delta_candidates() {
        let mut data = vec![0x55u8; AUTO_DELTA_EDGE_SKIP];
        for sample in 0..256u16 {
            let left = sample as u8;
            let right = left.wrapping_add(1);
            data.extend_from_slice(&[left, right]);
        }
        data.extend(std::iter::repeat_n(0xaa, AUTO_DELTA_EDGE_SKIP));
        let options = EncodeOptions::default();

        let plain = encode_lz_member_with_options(&data, 0, options).unwrap();
        let ranged = encode_member_with_filter_spec(
            &data,
            0,
            FilterSpec::range(
                FilterKind::Delta { channels: 2 },
                auto_delta_filter_range(&data, 2).unwrap(),
            ),
            options,
        )
        .unwrap();
        let auto = encode_member_with_auto_size_filter(&data, 0, options).unwrap();

        assert!(ranged.len() < plain.len());
        assert!(auto.len() <= ranged.len());
        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();
        let output = decoder
            .decode_member(
                &auto,
                0,
                data.len(),
                false,
                crate::codec::rar50::DecodeMode::Lz,
            )
            .unwrap();
        assert_eq!(output, data);
    }

    #[test]
    fn explicit_filters_accept_large_members_after_filter_ranges_are_split() {
        let data = vec![0u8; 4 * 1024 * 1024 + 1];
        let packed = encode_member_with_filter_policy(
            &data,
            0,
            &FilterPolicy::explicit(FilterKind::Delta { channels: 1 }),
            EncodeOptions::new(0),
        )
        .unwrap();
        let mut decoder = crate::codec::rar50::Unpack50Decoder::new();

        assert_eq!(
            decoder
                .decode_member(
                    &packed,
                    0,
                    data.len(),
                    false,
                    crate::codec::rar50::DecodeMode::Lz
                )
                .unwrap(),
            data
        );
    }

    #[test]
    fn solid_reset_policy_chooses_smaller_of_continued_and_fresh_streams() {
        let options = EncodeOptions::default();
        let first = b"solid reset policy unrelated prefix data\n".repeat(32);
        let second = b"second member second member second member\n".repeat(16);
        let mut encoder = Unpack50Encoder::with_options(options);
        encoder.encode_member(&first, 0).unwrap();

        let mut continued = encoder.clone();
        let continued_packed = continued.encode_member(&second, 0).unwrap();
        let mut fresh = Unpack50Encoder::with_options(options);
        let fresh_packed = fresh.encode_member(&second, 0).unwrap();
        let expected_fresh = fresh_packed.len() < continued_packed.len();
        let expected_len = continued_packed.len().min(fresh_packed.len());

        let (packed, solid_continuation) =
            encode_with_solid_reset_policy(&mut encoder, &second, 0, options, 1).unwrap();

        assert_eq!(packed.len(), expected_len);
        assert_eq!(solid_continuation, !expected_fresh);
    }

    #[test]
    #[ignore = "requires local rar command; used for reference-validating experimental RAR5 compressed output"]
    fn reference_rar_accepts_internal_literal_only_compressed_member() {
        let data = b"RAR5 literal-only compressed reference experiment\n";
        let packed = encode_literal_only(data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, data);
        let specific = file_specific(
            name,
            data.len() as u64,
            Some(crc32(data)),
            0x20,
            None,
            1 << 7,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_end_header(&mut archive, 0).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!(
            "rars-rar50-literal-only-{}.rar",
            std::process::id()
        ));
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping reference test: local `rar` command is not installed");
                return;
            }
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
            let _ = fs::remove_file(&path);
        }

        assert!(
            output.status.success(),
            "rar rejected experimental RAR5 compressed output\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires local rar command; used for reference-validating experimental RAR5 match output"]
    fn reference_rar_accepts_internal_match_compressed_member() {
        let data = b"RAR5 match compressed reference experiment\n".repeat(8);
        let packed = encode_lz_member(&data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record(&mut extra, &data);
        let specific = file_specific(
            name,
            data.len() as u64,
            Some(crc32(&data)),
            0x20,
            None,
            1 << 7,
            0,
        )
        .unwrap();
        write_block(
            &mut archive,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(packed.len() as u64),
            &specific,
            &extra,
            &packed,
        )
        .unwrap();
        write_end_header(&mut archive, 0).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("rars-rar50-match-{}.rar", std::process::id()));
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping reference test: local `rar` command is not installed");
                return;
            }
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
            let _ = fs::remove_file(&path);
        }

        assert!(
            output.status.success(),
            "rar rejected experimental RAR5 match output\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn writer_options_default_targets_rar50_with_store_only_features() {
        let options = WriterOptions::default();
        assert_eq!(options.target, crate::ArchiveVersion::Rar50);
        assert_eq!(options.features, crate::FeatureSet::store_only());
    }

    #[test]
    fn writer_rejects_mixed_member_kinds_without_panicking() {
        let stored = [StoredEntry {
            name: b"stored.txt",
            data: b"stored",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let compressed = [CompressedEntry {
            name: b"compressed.txt",
            data: b"compressed compressed compressed",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let result = Rar50Writer::new(WriterOptions::new(
            crate::ArchiveVersion::Rar50,
            crate::FeatureSet::store_only(),
        ))
        .stored_entries(&stored)
        .compressed_entries(&compressed)
        .finish();

        assert!(matches!(
            result,
            Err(Error::UnsupportedFeature {
                version: crate::ArchiveVersion::Rar50,
                feature: "RAR 5 mixed stored/compressed writer plan",
            })
        ));
    }
}
