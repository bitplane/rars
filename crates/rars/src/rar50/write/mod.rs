use super::*;
use crate::crc32::Crc32;
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys, WRITE_KDF_COUNT_LOG};
pub use crate::filter::{FilterKind, FilterPolicy, FilterSpec};
use crate::write_plan::{PlanShape, WriterOption};
use crate::write_progress::ProgressReporter;
use crate::{EntrySource, WriteProgress, WriterResources};
use std::io::{Read, Write};

mod compress;
mod engine;
mod filter_policy;
pub(crate) mod headers;
mod layout;
use filter_policy::{
    compression_method_for_level, dictionary_size_for_options, encode_option_candidates_for_level,
    encode_options_for_level, filter_policy_walk_bytes, rar50_algorithm_version,
};
pub(super) use headers::end_header_specific;

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

/// A [`VolumeSink`] that keeps the whole set in memory.
///
/// The point of the sink is that a caller need not, so this is for the callers
/// that want the bytes back anyway: the Python bindings hand Python a list, and
/// tests inspect what was written. Four hand-rolled copies of it had grown up,
/// and only two of them checked that volumes arrived in order.
#[derive(Debug, Default)]
pub struct CollectedVolumes {
    volumes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

struct CollectedVolume {
    volumes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    index: usize,
}

impl CollectedVolumes {
    pub fn new() -> Self {
        Self::default()
    }

    /// The finished set, in order. Takes the volumes rather than copying them,
    /// so a set that only just fitted in memory does not need twice the room.
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(
            &mut *self
                .volumes
                .lock()
                .expect("volume collector is not poisoned"),
        )
    }
}

impl Write for CollectedVolume {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.volumes
            .lock()
            .expect("volume collector is not poisoned")[self.index]
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl VolumeSink for CollectedVolumes {
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn Write + Send>> {
        let mut volumes = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned");
        if volumes.len() as u64 != index {
            return Err(Error::InvalidHeader("RAR 5 volumes arrived out of order"));
        }
        volumes.push(Vec::new());
        drop(volumes);
        Ok(Box::new(CollectedVolume {
            volumes: std::sync::Arc::clone(&self.volumes),
            index: index as usize,
        }))
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> Result<()> {
        let volumes = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned");
        if volumes[index as usize].len() as u64 != len {
            return Err(Error::InvalidHeader(
                "RAR 5 volume length does not match what was written",
            ));
        }
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
    // A member's services are validated with it and then had nowhere to go:
    // `prepare_volume_member` never reads them, so a file comment asked for on
    // a split set was accepted and then dropped without a word.
    if entries.iter().any(|entry| !entry.services.is_empty()) {
        crate::write_plan::validate_option(options.target, WriterOption::FileComment, shape)?;
    }
    // A set with no members produces no volumes at all: the writer would
    // return success having never asked the sink for a single one.
    if entries.is_empty() {
        return Err(Error::InvalidHeader(
            "RAR 5 volume writer needs at least one member",
        ));
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
                let mut compress = streaming_compress_plan(
                    options,
                    dictionary_reach(entries, options.features.solid),
                    resources.memory_limit(),
                )?;
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
            // No volume writer emits the index, and `validate_plan` refuses a
            // set that asks for one, so this is the only value that can get
            // here rather than a decision taken quietly on the caller's behalf.
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
    if options.features.quick_open && options.features.header_encryption {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "RAR 5 quick-open index in a header-encrypted archive",
        });
    }

    engine::write_archive(
        entries,
        engine::EnginePlan {
            compress: {
                let mut compress = streaming_compress_plan(
                    options,
                    dictionary_reach(entries, options.features.solid),
                    resources.memory_limit(),
                )?;
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
            quick_open: options.features.quick_open,
            progress,
        },
        resources,
        output,
    )
}

/// Writes a RAR 5 or RAR 7 archive without retaining member payloads.
/// Compression settings shared by the streaming writers.
/// How far one dictionary has to reach for these members.
///
/// Solid members are coded as one chain through a single window, so a match can
/// point back into an earlier member and the whole archive is in reach.
/// Otherwise each member starts afresh and only the largest one matters. A
/// source that cannot say how long it is takes the largest window the writer
/// fits on its own, rather than the smallest.
fn dictionary_reach(entries: &[ArchiveEntry], solid: bool) -> u64 {
    let sizes = entries
        .iter()
        .map(|entry| entry.source.len().unwrap_or(u64::MAX));
    if solid {
        sizes.fold(0u64, u64::saturating_add)
    } else {
        sizes.max().unwrap_or(0)
    }
}

fn streaming_compress_plan(
    options: WriterOptions,
    content: u64,
    memory_limit: u64,
) -> Result<compress::CompressPlan> {
    let method = compression_method_for_level(options.compression_level)?;
    // A stored member has no window to reach across, and the size still lands in
    // its header, so fitting one to the data would only inflate what the header
    // claims.
    let reach = if method == 0 { 0 } else { content };
    let dictionary_size = dictionary_size_for_options(options, reach, memory_limit)?;
    Ok(compress::CompressPlan {
        algorithm_version: rar50_algorithm_version(options, dictionary_size)?,
        encode_options: encode_options_for_level(options.compression_level, dictionary_size)?,
        dictionary_size,
        block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
        solid: options.features.solid,
        method,
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

/// What one compression job holds, for admitting jobs against the memory limit
/// and for shrinking a fitted dictionary until it fits.
///
/// Nearly all of it is the match finder's chain links: four bytes per byte of
/// window, and the window is a power of two, so a dictionary just over one costs
/// almost double the one just under. That rounding is why a flat multiple of the
/// dictionary never described this well. It used to charge twelve times the
/// dictionary, which is the middle of the eight-to-sixteen the rounding then
/// produced, so it over-charged a dictionary that was already a power of two and
/// came close to under-charging one that had just crossed.
///
/// Peak resident bytes for one member encode, over the member itself, taken on a
/// 16 MiB member so every window is filled:
///
/// ```text
/// dictionary    measured    links alone
///  256 KiB      6,197,248     1,048,576
///    1 MiB      9,170,944     4,194,304
///    3 MiB     20,152,320    16,777,216
///    4 MiB     20,234,240    16,777,216
///    8 MiB     36,941,824    33,554,432
/// ```
///
/// The links account for the whole shape; what is left is the hash heads, the
/// token buffer for one block, and the packed output. Three megabytes covers
/// those with room to spare, and the fifth byte per window position absorbs the
/// rest rather than pretending to predict it.
///
/// The optimal parse searches a binary tree instead of hash chains, and a tree
/// holds two links per window position where a chain holds one. So it is eight
/// bytes per byte of window rather than four, and the charge doubles the links
/// and keeps the one byte of slack. Measured on the same 16 MiB member, over
/// the member, against a 512-candidate parse:
///
/// ```text
/// dictionary    measured    tree links alone
///  256 KiB     19,668,992         2,097,152
///    1 MiB     21,794,816         8,388,608
///    4 MiB     47,030,272        33,554,432
///    8 MiB     75,390,976        67,108,864
///   16 MiB    109,412,352       134,217,728
/// ```
///
/// The last row measures under its links because a 16 MiB member cannot fill a
/// 16 MiB window: the pages behind the untouched slots never become resident.
/// The charge covers the allocation anyway, since data that does fill the
/// window will touch them.
///
/// `block_size` is the largest block the parse can be holding, not the size the
/// reader asks for: a block grows past that when the data it covers is not
/// moving, and the parse's arrays grow with it. See
/// [`crate::codec::rar50::MAX_LZ_BLOCK_SIZE`].
fn streaming_lz_workspace(dictionary_size: u64, block_size: usize, optimal_parse: bool) -> u64 {
    // Runs retain up to a dictionary of new input as well as history and
    // combined search bytes. Charge those buffers alongside finder links.
    let per_window_byte = if optimal_parse { 17 } else { 13 };
    dictionary_size
        .checked_next_power_of_two()
        .unwrap_or(dictionary_size)
        .saturating_mul(per_window_byte)
        .saturating_add((block_size as u64).saturating_mul(64))
        .saturating_add(3 * 1024 * 1024)
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
    let _ = dictionary_size_for_options(options, 0, u64::MAX)?;
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
    let keys = Rar50Keys::derive(password, salt, WRITE_KDF_COUNT_LOG)
        .map_err(super::map_rar50_crypto_error)?;

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

    #[test]
    fn the_writer_fits_the_dictionary_to_what_one_window_has_to_reach() {
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(3);
        let fitted = |content: u64| {
            dictionary_size_for_options(options, content, u64::MAX).expect("a legal dictionary")
        };

        // The smallest window that still reaches past the data, and never below
        // the format's floor or above the cap the writer picks on its own.
        assert_eq!(fitted(0), 128 * 1024);
        assert_eq!(fitted(130_000), 128 * 1024);
        assert_eq!(fitted(200_000), 256 * 1024);
        assert_eq!(fitted(700_000), 1024 * 1024);
        assert_eq!(fitted(64 * 1024 * 1024), 4 * 1024 * 1024);

        // What the caller asked for stands, in both directions.
        assert_eq!(
            dictionary_size_for_options(options.with_dictionary_size(4 * 1024 * 1024), 0, u64::MAX)
                .unwrap(),
            4 * 1024 * 1024
        );
    }

    #[test]
    fn the_cap_on_a_fitted_dictionary_climbs_with_the_level() {
        let plenty = 64 * 1024 * 1024;
        let capped = |level: u8| {
            let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                .with_compression_level(level);
            dictionary_size_for_options(options, plenty, u64::MAX).expect("a legal dictionary")
        };

        assert_eq!(capped(1), 1024 * 1024);
        assert_eq!(capped(2), 4 * 1024 * 1024);
        assert_eq!(capped(3), 4 * 1024 * 1024);
        assert_eq!(capped(4), 8 * 1024 * 1024);
        assert_eq!(capped(5), 16 * 1024 * 1024);

        // An absent level is the default level, and picks the same window it
        // would if the default had been spelled out.
        let absent = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
        assert_eq!(
            dictionary_size_for_options(absent, plenty, u64::MAX).unwrap(),
            capped(3),
        );
    }

    #[test]
    fn the_workspace_charge_covers_what_a_member_measured() {
        let block = crate::codec::rar50::LZ_BLOCK_SIZE;
        // Peak resident bytes over the member, one encode per row, taken with
        // `/proc/self/status` VmHWM so the allocator could not be involved.
        // Anything that raises what the encoder holds has to move these too.
        let measured: [(u64, u64); 5] = [
            (256 * 1024, 6_197_248),
            (1024 * 1024, 9_170_944),
            (3 * 1024 * 1024, 20_152_320),
            (4 * 1024 * 1024, 20_234_240),
            (8 * 1024 * 1024, 36_941_824),
        ];
        for (dictionary, peak) in measured {
            let charged = streaming_lz_workspace(dictionary, block, false);
            assert!(
                charged >= peak,
                "a {dictionary}-byte dictionary measured {peak} against a charge of {charged}",
            );
            // Streaming runs also retain input/history buffers not present in
            // these single-member measurements.
            assert!(
                charged < peak * 4,
                "a {dictionary}-byte dictionary is charged {charged} for a measured {peak}",
            );
        }
    }

    /// The same measurement for a parse that searches a tree, which holds two
    /// links per window position where a chain holds one. Charging the chain's
    /// four bytes for it let a fitted dictionary pick a window the budget could
    /// not hold: at a 32 MiB limit a 16 MiB member peaked at 43 MB.
    #[test]
    fn the_workspace_charge_covers_a_tree_search_too() {
        let block = crate::codec::rar50::LZ_BLOCK_SIZE;
        // Peak resident bytes over the member, 16 MiB of manpage text at
        // level 5, which is the only level that parses optimally.
        let measured: [(u64, u64); 4] = [
            (256 * 1024, 19_668_992),
            (1024 * 1024, 21_794_816),
            (4 * 1024 * 1024, 47_030_272),
            (8 * 1024 * 1024, 75_390_976),
        ];
        for (dictionary, peak) in measured {
            let charged = streaming_lz_workspace(dictionary, block, true);
            let chain = streaming_lz_workspace(dictionary, block, false);
            assert!(
                charged > chain,
                "a tree is charged {charged} against a chain's {chain}",
            );
            // The two smallest windows measure above their charge: what is over
            // is the member copies the whole-member path holds, which
            // `whole_member_workspace` charges for separately and which no
            // window size changes.
            let copies = 17 * 1024 * 1024;
            assert!(
                charged + copies >= peak,
                "a {dictionary}-byte dictionary measured {peak} against a charge of {charged}",
            );
        }
    }

    #[test]
    fn the_workspace_charge_never_falls_as_the_dictionary_grows() {
        let block = crate::codec::rar50::LZ_BLOCK_SIZE;
        let mut previous = 0;
        let mut dictionary = 128 * 1024u64;
        while dictionary <= 64 * 1024 * 1024 {
            for optimal_parse in [false, true] {
                let charged = streaming_lz_workspace(dictionary, block, optimal_parse);
                assert!(
                    charged >= previous,
                    "{dictionary} charged less than the size below it"
                );
                if !optimal_parse {
                    previous = charged;
                }
            }
            // Every size the format allows, not just the powers of two, because
            // the rounding inside is the whole reason this function exists.
            dictionary += 128 * 1024;
        }
    }

    #[test]
    fn a_fitted_dictionary_shrinks_to_the_workspace_budget() {
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(3);
        // Derived exactly as the writer derives it, so the budget below is the
        // one that admits a 256 KiB window and nothing larger. Spelling the
        // parameters out here instead would make this test pass or fail on
        // whether the ladder had moved since.
        let block = crate::codec::rar50::MAX_LZ_BLOCK_SIZE;
        let parse = encode_options_for_level(Some(3), DEFAULT_RAR50_DICTIONARY_SIZE)
            .unwrap()
            .optimal_parse;
        let room_for_256k = streaming_lz_workspace(256 * 1024, block, parse);

        // A budget that cannot hold the fitted window takes the largest one it
        // can, rather than failing a write the old 128 KiB default would have
        // finished.
        let fitted = dictionary_size_for_options(options, 8 * 1024 * 1024, room_for_256k).unwrap();

        assert_eq!(fitted, 256 * 1024);
        assert!(streaming_lz_workspace(fitted, block, parse) <= room_for_256k);
        // A dictionary the caller named is used as asked, so the write fails
        // later saying what it needed instead of quietly writing something else.
        assert_eq!(
            dictionary_size_for_options(
                options.with_dictionary_size(4 * 1024 * 1024),
                8 * 1024 * 1024,
                room_for_256k
            )
            .unwrap(),
            4 * 1024 * 1024
        );
    }

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
        // A stretch that does not move, so the two loops have to agree about
        // growing a block and not only about cutting one every block_size.
        data.extend(std::iter::repeat_n(0u8, 3 * 1024 * 1024));
        data.extend((0..400_000u32).map(|index| (index as u8).wrapping_mul(37)));
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
        let dictionary_size =
            dictionary_size_for_options(options, data.len() as u64, u64::MAX).unwrap();
        let algorithm_version = rar50_algorithm_version(options, dictionary_size).unwrap();
        let encode_options =
            encode_options_for_level(options.compression_level, dictionary_size).unwrap();
        let block_size = crate::codec::rar50::LZ_BLOCK_SIZE;
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
        let required = streaming_lz_workspace(
            dictionary_size,
            crate::codec::rar50::MAX_LZ_BLOCK_SIZE,
            encode_options.optimal_parse,
        );
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
            &|_| true,
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
        let dictionary_size =
            dictionary_size_for_options(options, dictionary_reach(&entries, false), u64::MAX)
                .unwrap();
        // Exactly what the writer charges itself, so the budget below admits one
        // job and no more. Derived rather than written down, because a charge
        // larger than the writer's would quietly make this a two-job test.
        let required = streaming_lz_workspace(
            dictionary_size,
            1024 * 1024,
            encode_options_for_level(options.compression_level, dictionary_size)
                .unwrap()
                .optimal_parse,
        );
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
    fn only_the_bottom_of_the_ladder_settles_for_a_greedy_parse() {
        // Level 1 is the rung that exists to be quick. Everything above it
        // parses by shortest path, because on this corpus nothing else closes
        // the distance to WinRAR at any rung: the parse is worth several
        // percent and the search depth around it is worth tenths.
        for level in 0..=1u8 {
            let options =
                encode_options_for_level(Some(level), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
            assert!(!options.optimal_parse, "level {level} priced every path");
        }
        for level in 2..=5u8 {
            let options =
                encode_options_for_level(Some(level), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
            assert!(options.optimal_parse, "level {level} settled for greedy");
        }
        assert!(
            encode_options_for_level(None, DEFAULT_RAR50_DICTIONARY_SIZE)
                .unwrap()
                .optimal_parse,
            "an absent level is the default level, which parses by shortest path",
        );
    }

    #[test]
    fn every_level_encodes_the_member_once() {
        // Level 5 used to try levels four down to one as well and keep the
        // smallest. Over the whole bench corpus that caught one byte, on one
        // member, for four extra whole-member encodes.
        for level in 0..=5u8 {
            let candidates =
                encode_option_candidates_for_level(Some(level), DEFAULT_RAR50_DICTIONARY_SIZE)
                    .unwrap();
            assert_eq!(candidates.len(), 1, "level {level} encodes more than once");
        }
    }

    #[test]
    fn a_filter_screen_does_not_pay_for_the_optimal_parse() {
        use crate::filter_search::FilterSearch;

        let search = crate::rar50::write::filter_policy::Rar50Search {
            algorithm_version: 0,
        };
        let five = encode_options_for_level(Some(5), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
        let screen = search.screen_options(five);

        assert!(!screen.optimal_parse);
        assert_eq!(screen.max_match_candidates, five.max_match_candidates);
        assert_eq!(screen.max_match_distance, five.max_match_distance);
    }

    #[test]
    fn the_ladder_never_packs_larger_as_it_climbs() {
        // A rung that costs more time and returns more bytes is a bug, and it
        // was one: level 4 used to return level 3's output for half again the
        // time, because the shortest-path parse only started at level 5.
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

        let mut previous: Option<(u8, usize)> = None;
        for level in 1..=5u8 {
            let options =
                encode_options_for_level(Some(level), DEFAULT_RAR50_DICTIONARY_SIZE).unwrap();
            let packed =
                encode_member_with_filter_policy(&data, 0, &FilterPolicy::None, options).unwrap();

            if let Some((lower, size)) = previous {
                assert!(
                    packed.len() <= size,
                    "level {level} packed larger than level {lower}: {} against {size}",
                    packed.len(),
                );
            }
            previous = Some((level, packed.len()));

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
            assert_eq!(output, data, "level {level} did not round trip");
        }
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

        let dir = crate::scratch::case("rars-rar50-literal-only");
        let path = dir.join("archive.rar");
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping reference test: local `rar` command is not installed");
                return;
            }
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_some() {
            eprintln!("kept reference archive: {}", path.display());
            std::mem::forget(dir);
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

        let dir = crate::scratch::case("rars-rar50-match");
        let path = dir.join("archive.rar");
        fs::write(&path, archive).unwrap();
        let output = match Command::new("rar").arg("t").arg(&path).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping reference test: local `rar` command is not installed");
                return;
            }
            Err(error) => panic!("failed to run rar: {error}"),
        };
        if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_some() {
            eprintln!("kept reference archive: {}", path.display());
            std::mem::forget(dir);
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
