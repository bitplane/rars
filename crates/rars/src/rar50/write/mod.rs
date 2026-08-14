use super::*;
use crate::crc32::Crc32;
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
pub use crate::filter::{FilterKind, FilterPolicy, FilterSpec};
use crate::write_plan::{PlanShape, WriterOption};
use crate::write_progress::ProgressReporter;
use crate::{EntrySource, WriteProgress, WriterResources};
use std::io::{Read, Write};

mod compress;
mod engine;
mod filter_policy;
mod headers;
mod layout;
use filter_policy::{
    compression_method_for_level, dictionary_size_for_options, encode_option_candidates_for_level,
    encode_options_for_level, filter_policy_walk_bytes, rar50_algorithm_version,
};
pub(super) use headers::end_header_specific;

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
    write_streaming_volumes_with_progress(
        entries,
        options,
        extras,
        max_payload_per_volume,
        sink,
        resources,
        None,
    )
}

/// As [`write_streaming_volumes_to`], reporting compression progress as it
/// goes.
pub fn write_streaming_volumes_with_progress(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
    max_payload_per_volume: u64,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    let encrypted = entries.iter().any(|entry| entry.password.is_some());
    if encrypted && !entries.iter().all(|entry| entry.password.is_some()) {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 writer mixing encrypted and plain members",
        });
    }
    let shape = PlanShape::new()
        .compressed(true)
        .volumes(true)
        .filtered(extras.filter_policy != FilterPolicy::None);
    // One option at a time, so a refusal names the one that was asked for.
    // This used to be a single check over all three, which reported a string
    // naming every option it covered whichever one the caller had set. Quick
    // open rides on the feature set, so `validate_plan` catches that one.
    validate_plan(options, shape)?;
    if extras.comment.is_some() {
        crate::write_plan::validate_option(options.target, WriterOption::ArchiveComment, shape)?;
    }
    if extras.metadata.is_some() {
        crate::write_plan::validate_option(options.target, WriterOption::ArchiveMetadata, shape)?;
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
            progress: progress.map(ProgressReporter),
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
    write_streaming_archive_reporting(entries, options, extras, resources, None, output)
}

/// As [`write_streaming_archive_to`], reporting compression progress as it
/// goes.
pub fn write_streaming_archive_with_progress(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: &mut dyn Write,
) -> Result<()> {
    write_streaming_archive_reporting(
        entries,
        options,
        extras,
        resources,
        progress.map(ProgressReporter),
        output,
    )
}

pub(crate) fn write_streaming_archive_reporting(
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
    validate_plan(
        options,
        PlanShape::new()
            .compressed(true)
            .filtered(extras.filter_policy != FilterPolicy::None),
    )?;
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
pub struct ArchiveMetadataEntry<'a> {
    pub name: Option<&'a [u8]>,
    pub creation_time: Option<u64>,
}

/// Builds a RAR 5 or RAR 7 archive from members held in memory.
///
/// [`write_streaming_archive_to`] is the same writer without the buffer; this
/// exists for callers that want the bytes back.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rar50Writer<'a> {
    options: WriterOptions,
    entries: Vec<ArchiveEntry>,
    archive_comment: Option<&'a [u8]>,
    archive_comment_password: Option<&'a [u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'a>>,
    filter_policy: FilterPolicy,
    recovery_percent: Option<u64>,
    progress: Option<ProgressReporter<'a>>,
}

impl<'a> Rar50Writer<'a> {
    pub fn new(options: WriterOptions) -> Self {
        Self {
            options,
            entries: Vec::new(),
            archive_comment: None,
            archive_comment_password: None,
            archive_metadata: None,
            filter_policy: FilterPolicy::None,
            recovery_percent: None,
            progress: None,
        }
    }

    pub fn entry(mut self, entry: ArchiveEntry) -> Self {
        self.entries.push(entry);
        self
    }

    pub fn entries(mut self, entries: impl IntoIterator<Item = ArchiveEntry>) -> Self {
        self.entries.extend(entries);
        self
    }

    pub fn archive_comment(mut self, comment: Option<&'a [u8]>) -> Self {
        self.archive_comment = comment;
        self.archive_comment_password = None;
        self
    }

    pub fn encrypted_archive_comment(mut self, comment: &'a [u8], password: &'a [u8]) -> Self {
        self.archive_comment = Some(comment);
        self.archive_comment_password = Some(password);
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
        let mut extras = ArchiveExtras::default()
            .with_recovery_percent(self.recovery_percent)
            .with_quick_open(self.options.features.quick_open)
            .with_filter_policy(self.filter_policy);
        if let Some(comment) = self.archive_comment {
            extras = match self.archive_comment_password {
                Some(password) => extras.with_encrypted_comment(comment, password),
                None => extras.with_comment(comment),
            };
        }
        if let Some(metadata) = self.archive_metadata {
            extras = extras.with_metadata(metadata);
        }

        write_streaming_archive_reporting(
            &self.entries,
            self.options,
            extras,
            resources,
            self.progress,
            output,
        )
    }
}

/// Everything this writer refuses, in one place, before anything is written.
///
/// This replaced a six-by-two matrix of near-identical checks, one per shape of
/// member the builder accepts. Each built a set of allowed features and compared
/// it with the request, and several built it by assigning a flag to itself,
/// which accepted the flag whatever it said.
fn validate_plan(options: WriterOptions, shape: PlanShape) -> Result<()> {
    if options.target.family() != crate::version::ArchiveFamily::Rar50Plus {
        return Err(Error::UnsupportedVersion(options.target));
    }
    crate::write_plan::validate_features(options.target, options.features, shape)?;
    crate::write_plan::validate_compression_level(options.target, options.compression_level)?;
    let _ = dictionary_size_for_options(options)?;
    // Quick-open is an index of the headers, so it has nothing to index once
    // they are encrypted.
    if options.features.quick_open && options.features.header_encryption {
        return Err(Error::UnsupportedWriterOption {
            target: options.target,
            option: WriterOption::Feature(crate::Feature::QuickOpen),
            because: Some("with header encryption"),
        });
    }
    // Solid members share one dictionary and are coded as one chain, so the
    // filter search never runs for them. Relations between two requests cannot
    // be expressed in the capability table, which is why this lives here rather
    // than in `supports`.
    if shape.filtered && options.features.solid {
        return Err(Error::UnsupportedWriterOption {
            target: options.target,
            option: WriterOption::Filter,
            because: Some("in a solid archive"),
        });
    }
    Ok(())
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

/// Checks one member and everything hanging off it.
///
/// Both entry points run this now. It used to be six near-identical validators,
/// one per shape of member the builder took, and the streaming path ran none of
/// them beyond the name.
fn validate_entry(entry: &ArchiveEntry) -> Result<()> {
    validate_file_entry(&entry.name)?;
    if let Some(password) = &entry.password {
        validate_nonempty_password(password)?;
    }
    entry.services.iter().try_for_each(validate_service)
}

fn validate_service(service: &ServiceEntry) -> Result<()> {
    // Encrypting a service record is only wired up for comments, so an
    // encrypted ACL or STM would be written in the clear.
    let allowed: &[&[u8]] = match service.password {
        Some(_) => &[b"CMT"],
        None => &[b"ACL", b"STM", b"CMT"],
    };
    if !allowed.contains(&service.name.as_slice()) {
        return Err(Error::UnsupportedFeature {
            version: crate::ArchiveVersion::Rar50,
            feature: "RAR 5 file service name",
        });
    }
    if service.data.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file service data is empty"));
    }
    match &service.password {
        Some(password) => validate_nonempty_password(password),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::filter_policy::{
        encode_member_with_auto_size_filter_progress, encode_member_with_filter_policy_and_progress,
    };
    use super::headers::{
        file_specific, write_block, write_end_header, write_hash_record_with_value,
        write_main_header,
    };
    use super::*;
    use crate::codec::rar50::{encode_literal_only, encode_lz_member};
    use crate::codec::rar50::{encode_lz_member_with_options, EncodeOptions, Unpack50Encoder};
    use crate::filter_search::{
        auto_delta_filter_range, disjoint_filter_ranges, AUTO_DELTA_EDGE_SKIP,
    };
    use crate::x86_filter_scan::auto_x86_filter_ranges;
    use crate::{ArchiveVersion, FeatureSet};
    use crate::{WriteOperation, WriteProgressEvent};
    use std::cell::RefCell;
    use std::fs;
    use std::io::{Cursor, Result as IoResult, Write};
    use std::process::Command;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CollectWriter(Rc<RefCell<Vec<u8>>>);

    fn encode_member_with_filter_policy(
        data: &[u8],
        algorithm_version: u8,
        policy: &FilterPolicy,
        options: EncodeOptions,
    ) -> Result<Vec<u8>> {
        encode_member_with_filter_policy_and_progress(
            data,
            algorithm_version,
            policy,
            options,
            None,
        )
    }

    /// Encodes with each candidate and keeps the smallest, which is what the
    /// writer does across a level's options.
    fn encode_member_with_filter_policy_candidates(
        data: &[u8],
        algorithm_version: u8,
        policy: &FilterPolicy,
        candidates: &[EncodeOptions],
    ) -> Result<Vec<u8>> {
        let mut candidates = candidates.iter().copied();
        let first = candidates.next().ok_or(Error::InvalidHeader(
            "RAR 5 compression level has no encoder options",
        ))?;
        let mut best = encode_member_with_filter_policy(data, algorithm_version, policy, first)?;
        for options in candidates {
            let packed =
                encode_member_with_filter_policy(data, algorithm_version, policy, options)?;
            if packed.len() < best.len() {
                best = packed;
            }
        }
        Ok(best)
    }

    fn encode_member_with_auto_size_filter(
        data: &[u8],
        algorithm_version: u8,
        options: EncodeOptions,
    ) -> Result<Vec<u8>> {
        encode_member_with_auto_size_filter_progress(data, algorithm_version, options, None)
    }

    fn encode_member_with_filter_spec(
        data: &[u8],
        algorithm_version: u8,
        filter: FilterSpec,
        options: EncodeOptions,
    ) -> crate::codec::Result<Vec<u8>> {
        Unpack50Encoder::with_options(options).encode_member_with_filter(
            data,
            algorithm_version,
            filter,
        )
    }

    fn encode_member_with_filter_specs(
        data: &[u8],
        algorithm_version: u8,
        filters: &[FilterSpec],
        options: EncodeOptions,
    ) -> crate::codec::Result<Vec<u8>> {
        Unpack50Encoder::with_options(options).encode_member_with_filters(
            data,
            algorithm_version,
            filters,
        )
    }

    /// Builds a member from bytes the test already holds.
    fn entry(name: &[u8], data: &[u8]) -> ArchiveEntry {
        ArchiveEntry::new(
            name.to_vec(),
            EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
        )
    }

    #[test]
    fn compressed_writer_reports_determinate_progress() {
        let data: Vec<u8> = (0usize..128 * 1024)
            .map(|i| (i.wrapping_mul(37) % 251) as u8)
            .collect();
        let entry = entry(b"payload.bin", &data)
            .with_attributes(0x20)
            .with_host_os(1);
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
        .entries([entry].to_vec())
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
        let entry = entry(b"payload.bin", b"recovery progress payload")
            .with_attributes(0x20)
            .with_host_os(1);
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
        let features = FeatureSet::store_only();

        Rar50Writer::new(
            WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(0),
        )
        .entries([entry].to_vec())
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
        let entry = ArchiveEntry::new(
            b"large.txt".to_vec(),
            EntrySource::from_bytes(Arc::<[u8]>::from(data.clone())),
        )
        .with_mtime(None)
        .with_attributes(0x20)
        .with_host_os(1);
        let mut bytes = Vec::new();
        write_streaming_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
            ArchiveExtras::default(),
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
        let entry = ArchiveEntry::new(
            b"small.txt".to_vec(),
            EntrySource::from_bytes(Arc::<[u8]>::from(&b"small"[..])),
        )
        .with_mtime(None)
        .with_attributes(0x20)
        .with_host_os(1);
        let result = write_streaming_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
            ArchiveExtras::default(),
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
        let mut prepared = compress::compress_members_reporting(
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
            &mut |_| true,
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
                ArchiveEntry::new(
                    format!("entry-{index}.bin").into_bytes(),
                    EntrySource::from_bytes(Arc::<[u8]>::from(data)),
                )
                .with_mtime(None)
                .with_attributes(0x20)
                .with_host_os(1)
            })
            .collect();
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
        let dictionary_size = dictionary_size_for_options(options).unwrap();
        let required = streaming_lz_workspace(dictionary_size, 1024 * 1024);
        let mut one_job = Vec::new();
        write_streaming_archive_to(
            &entries,
            options,
            ArchiveExtras::default(),
            &WriterResources::new(required),
            &mut one_job,
        )
        .unwrap();
        let mut many_jobs = Vec::new();
        write_streaming_archive_to(
            &entries,
            options,
            ArchiveExtras::default(),
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
        let entry = ArchiveEntry::new(b"changing.bin".to_vec(), source)
            .with_attributes(0x20)
            .with_host_os(1);
        let result = write_streaming_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
            ArchiveExtras::default(),
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
        let entry = ArchiveEntry::new(
            b"secret.txt".to_vec(),
            EntrySource::from_bytes(Arc::<[u8]>::from(data.clone())),
        )
        .with_mtime(None)
        .with_attributes(0x20)
        .with_host_os(1)
        .with_password(b"password".to_vec());
        let features = FeatureSet::store_only();
        let mut bytes = Vec::new();
        write_streaming_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, features),
            ArchiveExtras::default(),
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
        write_hash_record_with_value(&mut extra, blake2sp::hash(data));
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
        let entries = [entry(b"dict.bin", &data)
            .with_attributes(0x20)
            .with_host_os(3)];
        let archive = Rar50Writer::new(options)
            .entries(entries.to_vec())
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
        let entries = [entry(b"dict7.bin", &data)
            .with_attributes(0x20)
            .with_host_os(3)];
        let archive = Rar50Writer::new(options)
            .entries(entries.to_vec())
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
        let entries = [entry(b"bad.bin", b"data data data data")
            .with_attributes(0x20)
            .with_host_os(3)];

        assert!(matches!(
            Rar50Writer::new(options).entries(entries.to_vec()).finish(),
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
    #[ignore = "requires local rar command; used for reference-validating experimental RAR5 compressed output"]
    fn reference_rar_accepts_internal_literal_only_compressed_member() {
        let data = b"RAR5 literal-only compressed reference experiment\n";
        let packed = encode_literal_only(data, 0).unwrap();
        let name = b"compressed.txt";

        let mut archive = Vec::new();
        archive.extend_from_slice(RAR50_SIGNATURE);
        write_main_header(&mut archive, 0, None, &[]).unwrap();

        let mut extra = Vec::new();
        write_hash_record_with_value(&mut extra, blake2sp::hash(data));
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
        write_hash_record_with_value(&mut extra, blake2sp::hash(&data));
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
}
