use super::*;
use crate::codec::rar13::{
    unpack15_encode_with_options_and_progress, EncodeOptions as Rar15EncodeOptions, Unpack15Encoder,
};
use crate::codec::rar20::{
    unpack20_encode_auto_with_options_and_progress, unpack20_encode_streamed,
    EncodeOptions as Rar20EncodeOptions, Unpack20Encoder,
};
use crate::codec::rar29::{
    named_filter_segments, unpack29_encode_literals, unpack29_encode_literals_with_options,
    unpack29_encode_literals_with_options_and_progress, ChainEngine,
    EncodeOptions as Rar29EncodeOptions, PpmdModelSize, Unpack29Encoder,
};
use crate::crc32::Crc32;
pub use crate::filter::{FilterKind, FilterPolicy, FilterSpec};
pub use crate::streaming::EntrySource;
use crate::streaming::{MemoryPermit, WriterResources};
use crate::write_plan::{MemberCoding, PlanShape, WriterOption};
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::write_stream::{MemberBytes, MemberPayload};
use crate::FeatureSet;
use crate::{WriteOperation, WriteProgress, WriteProgressEvent};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::ControlFlow;

#[cfg(test)]
mod builder_path_tests;
mod volumes;
pub(crate) use volumes::write_retained_volumes_to;
pub use volumes::{write_stored_volumes_to, write_volumes_to, write_volumes_with_comment_to};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
    pub compression_level: Option<u8>,
    pub dictionary_size: Option<usize>,
    /// Which engine compresses a member. Only the RAR 2.9 family has more than
    /// one, so the other targets ignore anything but the default.
    pub method: Rar29Method,
    /// Retained NewSub comment DOS timestamp and host ID.
    pub(crate) archive_comment_metadata: Option<(u32, u8)>,
}

/// Which compression engine the RAR 2.9 family writer uses for a member.
///
/// PPMd is an alternative to LZ, not a filter, even though the writer used to
/// carry it as one. Keeping the two apart is what lets a filter be chosen
/// without also deciding the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Rar29Method {
    /// Let the content decide. Text-shaped members are measured against PPMd;
    /// anything else goes straight to LZ, so a binary member never pays for a
    /// PPMd encode it was always going to lose. Compression levels 1 to 4 skip
    /// the trial entirely, since those settings are asking for speed.
    #[default]
    Auto,
    Lz,
    Ppmd,
}

impl WriterOptions {
    pub const fn new(target: ArchiveVersion, features: FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
            dictionary_size: None,
            method: Rar29Method::Auto,
            archive_comment_metadata: None,
        }
    }

    pub const fn with_method(mut self, method: Rar29Method) -> Self {
        self.method = method;
        self
    }

    pub const fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = Some(level);
        self
    }

    pub const fn with_dictionary_size(mut self, size: usize) -> Self {
        self.dictionary_size = Some(size);
        self
    }
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar15,
            features: FeatureSet::store_only(),
            compression_level: None,
            dictionary_size: None,
            method: Rar29Method::Auto,
            archive_comment_metadata: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u32,
    pub host_os: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u32,
    pub host_os: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

/// One member of an archive written a member at a time.
///
/// The bytes are opened when the member is coded and dropped once it is
/// written, so an archive of many files never holds more than the members
/// being worked on. A stored member is copied straight from its source and
/// never lands on the heap at all.
#[derive(Debug, Clone)]
pub struct StreamingEntry {
    pub name: Vec<u8>,
    pub source: EntrySource,
    pub file_time: u32,
    pub file_attr: u32,
    pub host_os: u8,
    pub password: Option<Vec<u8>>,
    pub file_comment: Option<Vec<u8>>,
}

impl StreamingEntry {
    pub fn new(name: impl Into<Vec<u8>>, source: EntrySource) -> Self {
        Self {
            name: name.into(),
            source,
            file_time: 0,
            file_attr: 0,
            host_os: 3,
            password: None,
            file_comment: None,
        }
    }

    pub fn with_file_time(mut self, file_time: u32) -> Self {
        self.file_time = file_time;
        self
    }

    pub fn with_file_attr(mut self, file_attr: u32) -> Self {
        self.file_attr = file_attr;
        self
    }

    pub fn with_host_os(mut self, host_os: u8) -> Self {
        self.host_os = host_os;
        self
    }

    pub fn with_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn with_file_comment(mut self, comment: impl Into<Vec<u8>>) -> Self {
        self.file_comment = Some(comment.into());
        self
    }
}

#[cfg(any(test, feature = "encryption"))]
fn checked_align16(value: usize, message: &'static str) -> Result<usize> {
    value
        .checked_add(15)
        .map(|size| size & !15)
        .ok_or(Error::InvalidArgument(message))
}

const AUTO_RGB_WIDTHS: [usize; 4] = [24, 48, 96, 192];
const MIN_STORE_FALLBACK_SIZE: usize = 1024;
const RAR29_TEXT_SAMPLE_SIZE: usize = 8192;

/// How long a run of NUL has to be before the text screen reads it as padding
/// and stops counting it either way.
///
/// Sixteen is well past what falls out of text (a run of NUL in a source file
/// is already unusual) and well short of the 512 byte blocks tar pads to.
/// Measured across 400 binaries over 200 KB in `/usr/bin` and
/// `/usr/lib/x86_64-linux-gnu`, 8, 16 and 32 all give the same answer, so the
/// exact number is not load-bearing.
const RAR29_NUL_RUN_IS_PADDING: usize = 16;

/// The level an absent `--level` means for RAR 2.0, matching the method byte
/// `compression_method_for_level` writes for it.
const RAR20_DEFAULT_LEVEL: u8 = 3;
const RAR29_AUDIO_SAMPLE_SIZE: usize = 8192;
/// How much data one RAR 2.9 LZ block covers.
///
/// Every block carries its own Huffman tables, so this is the distance over
/// which the tables have to fit the data. A megabyte was far too long a lease:
/// a binary's code and its data want different tables, and one set fitted to
/// both is worse than either. Measured on `--level 5`, packed bytes:
///
/// ```text
/// block         16K      32K      64K     128K       1M
/// libc       686400   683942   684278   704689   797692
/// python     632452   628926   627862   648835   738624
/// mixed      136376   135530   135264   146831   149372
/// lorem       16186    16186    16186    16186    16186
/// ```
///
/// 64K is the best or within a rounding error of it on everything measured,
/// and text does not care either way. The curve turns back up below 32K, where
/// re-sending the tables starts to cost more than fitting them gains.
const RAR29_LZ_BLOCK_SIZE: usize = 64 * 1024;
/// Smaller members keep the whole-member engine and filter trials.
const STREAM_MEMBERS_ABOVE: u64 = 64 * 1024 * 1024;

/// The largest dictionary the format encodes, used when a memory estimate
/// cannot resolve the real one. It has to stay an upper bound, so it does not
/// follow the block size.
const RAR29_MAX_DICTIONARY_SIZE: usize = 4 * 1024 * 1024;
#[cfg(feature = "encryption")]
const RAR15_ALIGN_OVERFLOW: &str = "RAR 1.5 block size overflows usize";

pub fn write_stored_archive(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_stored_archive_with_comment(entries, options, None)
}

pub fn write_stored_archive_with_comment(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let members: Vec<_> = entries.iter().map(Member::from_stored).collect();
    collect_archive(
        &members,
        options,
        MemberCoding::Stored,
        archive_comment,
        None,
    )
}

pub(crate) struct RetainedMemberMetadata<'a> {
    pub(crate) unicode_name: Option<&'a [u8]>,
    pub(crate) unpack_version: Option<u8>,
    pub(crate) extended_times: Option<&'a [u8]>,
    pub(crate) is_directory: bool,
    pub(crate) is_symlink: bool,
}

pub(crate) struct RetainedFileEntry<'a> {
    pub(crate) file: FileEntry<'a>,
    pub(crate) source: Option<&'a EntrySource>,
    pub(crate) metadata: RetainedMemberMetadata<'a>,
}

/// Builder path for retained native metadata and entry kinds. Existing direct
/// entry structs keep their API.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_archive_with_retained_metadata(
    entries: &[RetainedFileEntry<'_>],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    header_password: Option<&[u8]>,
    archive_comment_password: Option<&[u8]>,
    output: ArchiveOutput<'_>,
) -> Result<()> {
    // Builder validates retained records at their setters and constructs each
    // file with its metadata, so neither record validity nor array length can
    // change at this private handoff.
    let members: Vec<_> = entries
        .iter()
        .map(|entry| {
            let mut member = Member::from_file(&entry.file);
            if let Some(source) = entry.source {
                member.bytes = MemberBytes::NamedSource(source, entry.file.name);
            }
            member.unicode_name = entry.metadata.unicode_name;
            member.unpack_version = entry.metadata.unpack_version;
            member.extended_times = entry.metadata.extended_times;
            member.is_directory = entry.metadata.is_directory;
            member.is_symlink = entry.metadata.is_symlink;
            member
        })
        .collect();
    write_archive_to(
        &members,
        options,
        coding,
        archive_comment,
        resources,
        progress,
        output,
        header_password,
        archive_comment_password,
    )
}

pub fn write_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment(entries, options, None)
}

pub fn write_compressed_archive_with_comment(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment_and_progress(entries, options, archive_comment, None)
}

pub fn write_compressed_archive_with_comment_and_progress(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    let members: Vec<_> = entries.iter().map(Member::from_file).collect();
    collect_archive(
        &members,
        options,
        MemberCoding::Compressed,
        archive_comment,
        progress,
    )
}

pub fn write_rar29_compressed_archive_with_filter_policy(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    policy: FilterPolicy,
) -> Result<Vec<u8>> {
    write_rar29_compressed_archive_with_filter_policy_and_progress(entries, options, policy, None)
}

pub fn write_rar29_compressed_archive_with_filter_policy_and_progress(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    policy: FilterPolicy,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    let members: Vec<_> = entries.iter().map(Member::from_file).collect();
    collect_archive(
        &members,
        options,
        MemberCoding::Filtered(policy),
        None,
        progress,
    )
}

/// Writes an archive straight to `output`, holding only the members being
/// compressed rather than every input at once.
///
/// `resources` bounds how many members are in flight, which is what keeps the
/// peak flat across an archive of many files. A RAR 2.0 to 4.x member over
/// 64 MiB is coded as it is read into a spool in the resources' temp directory,
/// then written behind a header carrying its sizes. Smaller members, and every
/// RAR 1.5 member, are compressed whole; one larger than the budget is
/// compressed on its own rather than refused.
pub fn write_streaming_archive_to(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: &mut dyn Write,
) -> Result<()> {
    let members: Vec<_> = entries.iter().map(Member::from_streaming).collect();
    write_archive_to(
        &members,
        options,
        coding,
        archive_comment,
        resources,
        progress,
        ArchiveOutput::stream(output),
        None,
        None,
    )
}

/// Like [`write_streaming_archive_to`], but a large member need not fit in memory.
#[doc(hidden)]
pub fn write_seekable_archive_to<W: Write + Seek>(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: &mut W,
) -> Result<()> {
    write_seekable_archive_with_threshold(
        entries,
        options,
        coding,
        archive_comment,
        resources,
        progress,
        output,
        STREAM_MEMBERS_ABOVE,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_seekable_archive_with_threshold(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: &mut dyn SeekWrite,
    stream_above: u64,
) -> Result<()> {
    let members: Vec<_> = entries.iter().map(Member::from_streaming).collect();
    write_archive_to(
        &members,
        options,
        coding,
        archive_comment,
        resources,
        progress,
        ArchiveOutput::Seekable {
            output,
            stream_above,
        },
        None,
        None,
    )
}

pub(crate) trait SeekWrite: Write + Seek {}

impl<T: Write + Seek + ?Sized> SeekWrite for T {}

pub(crate) enum ArchiveOutput<'a> {
    /// Members larger than `spool_above` are coded into a temporary spool, so
    /// their header can carry the sizes before the payload follows.
    Stream {
        output: &'a mut dyn Write,
        spool_above: Option<u64>,
    },
    Seekable {
        output: &'a mut dyn SeekWrite,
        stream_above: u64,
    },
}

impl<'a> ArchiveOutput<'a> {
    /// An output that cannot seek, large members spooled.
    pub(crate) fn stream(output: &'a mut dyn Write) -> Self {
        Self::Stream {
            output,
            spool_above: Some(STREAM_MEMBERS_ABOVE),
        }
    }

    pub(crate) fn seekable(output: &'a mut dyn SeekWrite) -> Self {
        // A test lowers the threshold on its own thread, so a member streams
        // through the builder without coding 64 MiB in a debug build.
        #[cfg(test)]
        let stream_above = builder_path_tests::STREAM_ABOVE.get();
        #[cfg(not(test))]
        let stream_above = STREAM_MEMBERS_ABOVE;
        Self::Seekable {
            output,
            stream_above,
        }
    }
}

/// The archive output with cancellation checked on every write.
enum Sink<'o, 'p> {
    Stream(
        crate::write_progress::CancellableIo<'p, &'o mut dyn Write>,
        Option<u64>,
    ),
    Seekable(
        crate::write_progress::CancellableIo<'p, &'o mut dyn SeekWrite>,
        u64,
    ),
}

impl Sink<'_, '_> {
    fn writer(&mut self) -> &mut dyn Write {
        match self {
            Self::Stream(output, _) => output,
            Self::Seekable(output, _) => output,
        }
    }

    /// Streams one member: patched in place, or spooled first.
    #[allow(clippy::too_many_arguments)]
    fn stream_member(
        &mut self,
        member: &Member<'_>,
        options: WriterOptions,
        coding: &MemberCoding,
        header_key: Option<&HeaderKey>,
        data_keys: &mut DataKeys,
        solid: Option<SolidLink<'_>>,
        resources: &WriterResources,
        admitted: Option<MemoryPermit>,
        progress: &WorkTracker<'_>,
    ) -> Result<u8> {
        progress.check()?;
        validate_member(member.name, options.target, member.unpacked_size()?)?;
        let continues = solid.as_ref().is_some_and(|link| link.continues);
        match self {
            Self::Seekable(output, _) => {
                let mut out = InPlace {
                    output,
                    member,
                    options,
                    header_key,
                    continues,
                    salt: None,
                    header_at: 0,
                    header_len: 0,
                };
                stream_member_admitted(
                    &mut out, member, options, coding, data_keys, solid, resources, admitted,
                    progress,
                )
            }
            Self::Stream(output, _) => {
                let mut out = Spooled {
                    output,
                    member,
                    options,
                    header_key,
                    continues,
                    salt: None,
                    spool: None,
                    resources,
                };
                stream_member_admitted(
                    &mut out, member, options, coding, data_keys, solid, resources, admitted,
                    progress,
                )
            }
        }
    }

    /// Members larger than this are streamed: patched in place on an output
    /// that seeks, spooled on one that doesn't. `None` holds every member.
    fn stream_above(&self) -> Option<u64> {
        match self {
            Self::Stream(_, above) => *above,
            Self::Seekable(_, above) => Some(*above),
        }
    }
}

/// Runs the streaming writer into a buffer, for the callers that want the
/// archive as bytes. The budget still applies, so a many-file archive holds one
/// window of members rather than all of them.
fn collect_archive(
    members: &[Member<'_>],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_archive_to(
        members,
        options,
        coding,
        archive_comment,
        &WriterResources::default(),
        progress,
        // The archive is held whole anyway, so its members are too.
        ArchiveOutput::Stream {
            output: &mut out,
            spool_above: None,
        },
        None,
        None,
    )?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn write_archive_to(
    members: &[Member<'_>],
    mut options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: ArchiveOutput<'_>,
    explicit_header_password: Option<&[u8]>,
    archive_comment_password: Option<&[u8]>,
) -> Result<()> {
    if explicit_header_password.is_some()
        || archive_comment_password.is_some()
        || members.iter().any(|member| member.password.is_some())
    {
        crate::crypto::require_encryption()?;
    }

    if resources.max_preparation_bytes().is_some() || resources.max_memory_bytes().is_some() {
        return Err(Error::UnsupportedFamilyFeature {
            family: options.target.family(),
            feature: if resources.max_memory_bytes().is_some() {
                "aggregate managed-memory limit"
            } else {
                "preparation memory quota"
            },
        });
    }

    if let Some(password) = archive_comment_password {
        if password.is_empty()
            || archive_comment.is_none()
            || !matches!(
                options.target,
                ArchiveVersion::Rar30 | ArchiveVersion::Rar40
            )
        {
            return Err(Error::InvalidArgument(
                "encrypted legacy archive comments require a password and RAR3/4 CMT output",
            ));
        }
    }
    let control =
        crate::write_progress::ResourceProgress::new(resources, progress.map(ProgressReporter));
    let reporting = &control as &dyn WriteProgress;
    let progress = Some(reporting);
    crate::write_progress::check_cancelled(progress.map(ProgressReporter))?;
    let reporter = progress.map(ProgressReporter);
    let mut output = match output {
        ArchiveOutput::Stream {
            output: inner,
            spool_above,
        } => Sink::Stream(
            crate::write_progress::CancellableIo {
                inner,
                progress: reporter,
            },
            spool_above,
        ),
        ArchiveOutput::Seekable {
            output: inner,
            stream_above,
        } => Sink::Seekable(
            crate::write_progress::CancellableIo {
                inner,
                progress: reporter,
            },
            stream_above,
        ),
    };
    let output = &mut output;
    let has_file_comment = members.iter().any(|member| member.file_comment.is_some());
    if has_file_comment && options.features.header_encryption {
        return Err(Error::UnsupportedWriterOption {
            target: options.target,
            option: WriterOption::FileComment,
            because: Some("embedded legacy file comments with header encryption are incompatible with reference readers"),
        });
    }
    validate_plan(
        options,
        coding.shape(),
        archive_comment.is_some(),
        has_file_comment,
    )?;
    if let MemberCoding::Filtered(policy) = &coding {
        validate_rar29_filter_policy(policy, options.method)?;
    }
    let header_password = if options.features.header_encryption {
        validate_header_encrypted_archive_options(
            options.target,
            explicit_header_password.is_some()
                || members.iter().any(|member| member.password.is_some()),
        )?;
        Some(if let Some(password) = explicit_header_password {
            header_encryption_password(
                std::iter::once(Some(password)).chain(
                    members
                        .iter()
                        .filter_map(|member| member.password)
                        .map(Some),
                ),
            )?
        } else {
            header_encryption_password(members.iter().map(|member| member.password))?
        })
    } else {
        None
    };

    let mut total_bytes = 0u64;
    let mut largest_member = 0u64;
    for member in members {
        let unpacked = member.unpacked_size().map_err(|error| {
            crate::write_stream::member_error(error, member.name, "reading source")
        })?;
        total_bytes = total_bytes.saturating_add(unpacked);
        largest_member = largest_member.max(unpacked);
    }
    if options.dictionary_size.is_none() {
        // A solid run is one stream, so its window has to reach back across the
        // members it already coded; independent members only ever look inside
        // themselves. Validation has already rejected solid stored coding.
        let reach = if options.features.solid {
            total_bytes
        } else {
            largest_member
        };
        options.dictionary_size = Some(fitted_dictionary_size(options.target, reach));
    }
    report_compression_operation(reporting, true, total_bytes, members.len());
    let work = WorkTracker::new(
        Some(ProgressReporter(reporting)),
        WriteOperation::Compression,
        total_bytes,
    );

    let header_key = header_password.map(HeaderKey::derive).transpose()?;
    let result = write_members_to(
        members,
        options,
        &coding,
        archive_comment,
        header_key.as_ref(),
        archive_comment_password.or(header_comment_password(options.target, header_password)),
        resources,
        &work,
        output,
    );
    result?;
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    report_compression_operation(reporting, false, total_bytes, members.len());
    work.check()
}

#[allow(clippy::too_many_arguments)]
fn write_members_to(
    members: &[Member<'_>],
    options: WriterOptions,
    coding: &MemberCoding,
    archive_comment: Option<&[u8]>,
    header_key: Option<&HeaderKey>,
    archive_comment_password: Option<&[u8]>,
    resources: &WriterResources,
    progress: &WorkTracker<'_>,
    sink: &mut Sink<'_, '_>,
) -> Result<()> {
    let coding = level_coding(options, coding);
    let stream_above = sink.stream_above();
    let mut data_keys = DataKeys::default();
    let output = sink.writer();
    output.write_all(RAR15_SIGNATURE)?;
    let mut main_flags = 0;
    if options.features.solid {
        main_flags |= MHD_SOLID;
    }
    if header_key.is_some() {
        main_flags |= MHD_PASSWORD;
    }
    if archive_comment.is_some() && uses_old_style_archive_comment(options.target) {
        main_flags |= MHD_COMMENT;
    }
    let mut head = Vec::new();
    write_main_header(&mut head, main_flags);
    output.write_all(&head)?;
    let comment = encode_archive_comment(
        archive_comment,
        options,
        header_key,
        archive_comment_password,
        &mut data_keys,
    )?;
    write_lead(
        output,
        options.target,
        &comment,
        header_key,
        progress.reporter(),
    )?;

    // Solid members share one encoder, so they are coded in order. Independent
    // ones are coded a window at a time and written as each window lands.
    if options.features.solid {
        let mut solid_encoder = Some(SolidEncoder::for_chain(
            members,
            options,
            coding,
            stream_above,
            resources,
            progress,
        )?);
        let mut solid_run_has_member = false;
        for member in members {
            let streams = match stream_above {
                Some(above) => streams_member(member, options, coding, above).map_err(|error| {
                    crate::write_stream::member_error(error, member.name, "preparing")
                })?,
                None => false,
            };
            if streams {
                let method = sink
                    .stream_member(
                        member,
                        options,
                        coding,
                        header_key,
                        &mut data_keys,
                        Some(SolidLink {
                            encoder: &mut solid_encoder,
                            continues: solid_run_has_member,
                        }),
                        resources,
                        None,
                        progress,
                    )
                    .map_err(|error| {
                        crate::write_stream::member_error(error, member.name, "writing")
                    })?;
                // A streamed member is never empty, so only storing it ends the run.
                solid_run_has_member = method != 0x30;
                member.bytes.release();
                continue;
            }
            let encoded = encode_member(
                member,
                options,
                coding,
                &mut solid_encoder,
                resources,
                progress,
            )
            .map_err(|error| crate::write_stream::member_error(error, member.name, "preparing"))?;
            // A directory header carries no data but still sits in the chain.
            // 7-Zip restarts its decoder at any header without FHD_SOLID,
            // directories included, so one inside a run must say the run goes
            // on; UnRAR passes over directory headers either way.
            let solid_continuation =
                (encoded.method != 0x30 || member.is_directory) && solid_run_has_member;
            solid_run_has_member = solid_chain_runs_on(
                solid_run_has_member,
                member.is_directory,
                encoded.method,
                encoded.unpacked_size,
                matches!(&encoded.payload, MemberPayload::Packed(data) if !data.is_empty()),
            );
            write_member(
                sink.writer(),
                member,
                encoded,
                options,
                solid_continuation,
                header_key,
                &mut data_keys,
                progress.reporter(),
            )
            .map_err(|error| crate::write_stream::member_error(error, member.name, "writing"))?;
            member.bytes.release();
        }
    } else {
        // Scoped rewrite sources retain plaintext until emission; their disk
        // quota may admit fewer inputs than the CPU pool can prepare at once.
        let window = members
            .iter()
            .filter_map(|member| member.bytes.source())
            .map(EntrySource::max_preparation_window)
            .fold(crate::parallel::default_window(), usize::min);
        // Each member is charged as it is let into a window, in order, and
        // keeps the charge until it is written: a coded member holds its
        // packed form until then, and a streamed one holds its coder while it
        // is written. Only the member opening a window waits for room, so a
        // window never waits on what its own members hold.
        crate::parallel::map_slice_windowed(
            members,
            window,
            |member, opens| {
                admit_to_window(
                    member,
                    options,
                    coding,
                    stream_above,
                    resources,
                    progress,
                    opens,
                )
                .map_err(|error| crate::write_stream::member_error(error, member.name, "preparing"))
            },
            |member, admitted| {
                match admitted.unpacked_size {
                    Some(unpacked_size) => encode_measured(
                        member,
                        options,
                        coding,
                        &mut None,
                        unpacked_size,
                        admitted.permit,
                        resources,
                        progress,
                    )
                    .map(Prepared::Coded),
                    None => Ok(Prepared::Streams(admitted.permit)),
                }
                .map_err(|error| crate::write_stream::member_error(error, member.name, "preparing"))
            },
            |member, prepared| {
                match prepared {
                    Prepared::Coded(encoded) => write_member(
                        sink.writer(),
                        member,
                        encoded,
                        options,
                        false,
                        header_key,
                        &mut data_keys,
                        progress.reporter(),
                    ),
                    Prepared::Streams(permit) => sink
                        .stream_member(
                            member,
                            options,
                            coding,
                            header_key,
                            &mut data_keys,
                            None,
                            resources,
                            permit,
                            progress,
                        )
                        .map(|_| ()),
                }
                .map_err(|error| {
                    crate::write_stream::member_error(error, member.name, "writing")
                })?;
                member.bytes.release();
                Ok(())
            },
        )?;
    }
    let output = sink.writer();
    if let Some(key) = header_key {
        write_encrypted_end_block(output, &end_block(ENDARC_FLAGS), key)?;
    } else if writes_end_block(options.target) {
        output.write_all(&end_block(ENDARC_FLAGS))?;
    }
    Ok(())
}

/// Level 0 stores every member, so it is written as a stored member is: from
/// the caller's bytes or its source, never from a copy of them.
fn level_coding(options: WriterOptions, coding: &MemberCoding) -> &MemberCoding {
    match coding {
        MemberCoding::Compressed if options.compression_level == Some(0) => &MemberCoding::Stored,
        coding => coding,
    }
}

/// A member let into a window: its size if it is coded whole, `None` if it
/// streams, and the charge it holds until it is written.
struct Admitted {
    unpacked_size: Option<u64>,
    permit: Option<MemoryPermit>,
}

/// A member of a window, ready to write.
enum Prepared<'a> {
    Coded(EncodedMember<'a>),
    Streams(Option<MemoryPermit>),
}

/// Charges the budget for a member about to join a window. The member that
/// opens one waits for room; any other gets `None` when there is none, which
/// closes the window, since the room it needs may be held by the members ahead
/// of it, and they are only written once the window is coded.
fn admit_to_window(
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    stream_above: Option<u64>,
    resources: &WriterResources,
    progress: &WorkTracker<'_>,
    opens: bool,
) -> Result<Option<Admitted>> {
    let streams = match stream_above {
        Some(above) => streams_member(member, options, coding, above)?,
        None => false,
    };
    let (unpacked_size, charge) = if streams {
        (None, Some(streamed_workspace(options, coding)))
    } else {
        let unpacked_size = measure_member(member, options, progress)?;
        (
            Some(unpacked_size),
            member_charge(member, options, coding, unpacked_size),
        )
    };
    let permit = match charge {
        None => None,
        Some(charge) if opens => {
            Some(resources.acquire_serialising_cancellable(charge, &|| progress.is_cancelled())?)
        }
        Some(charge) => match resources.try_acquire_serialising(charge)? {
            Some(permit) => Some(permit),
            None => return Ok(None),
        },
    };
    Ok(Some(Admitted {
        unpacked_size,
        permit,
    }))
}

/// Encodes one member, choosing an engine and a filter independently.
///
/// The two are separate questions: which engine compresses this content best,
/// and which transform makes it easier to compress. They used to be one enum,
/// which meant some combinations simply could not be asked for.
#[allow(clippy::too_many_arguments)]
fn encode_rar29_policy_filtered_payload(
    data: &[u8],
    policy: &FilterPolicy,
    method: Rar29Method,
    options: Rar29EncodeOptions,
    lz_method: u8,
    ppmd_trial: bool,
    progress: Option<&WorkTracker<'_>>,
    resources: Option<&WriterResources>,
) -> Result<EncodedPayload> {
    // An empty member is stored whatever was asked for. A filter over it is a
    // 0..0 range, which the codec refuses, so an archive holding one empty file
    // used to compress every other member and then fail at the last step. Only
    // the search path guarded this; every explicit policy walked into it.
    if lz_method == 0x30 || data.is_empty() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    // The method byte carries the level that was asked for, not which engine
    // answered. RAR 2.9 signals PPMd inside the stream (our own decoder takes
    // no method byte at all), and WinRAR 3.00 stamps 0x34 on the PPMd archive
    // it writes at -m4. Stamping 0x35 on every PPMd payload only looked right
    // while the trial ran at level 5, and made a level 3 archive claim to be a
    // level 5 one as soon as it ran anywhere else.
    let ppmd = |filter: Option<&FilterSpec>| -> Result<EncodedPayload> {
        Ok(EncodedPayload {
            data: encode_rar29_ppmd_member(
                data,
                filter,
                options.max_match_distance,
                ppmd_models_for_level(lz_method.saturating_sub(0x30)),
                progress,
            )?,
            method: lz_method,
        })
    };
    match (method, policy) {
        (Rar29Method::Ppmd, FilterPolicy::None) => ppmd(None),
        (Rar29Method::Ppmd, FilterPolicy::Explicit(filter)) => ppmd(Some(filter)),
        // Filtered writes are rejected before encoding; plain compressed writes
        // use FilterPolicy::None when PPMd is forced.
        (Rar29Method::Ppmd, FilterPolicy::Auto) => unreachable!(),
        (Rar29Method::Lz, FilterPolicy::None) => {
            encode_rar29_lz_member(data, options, lz_method, progress)
        }
        (Rar29Method::Lz, FilterPolicy::Auto) => encode_rar29_auto_filtered_member_with_progress(
            data, options, lz_method, false, progress, resources,
        ),
        (Rar29Method::Lz, FilterPolicy::Explicit(filter)) => Ok(EncodedPayload {
            data: with_codec_progress(progress, |report| {
                Unpack29Encoder::with_options(options).encode_member_with_filters_and_progress(
                    data,
                    std::slice::from_ref(filter),
                    Some(report),
                )
            })?,
            method: lz_method,
        }),
        (Rar29Method::Auto, FilterPolicy::Auto) => encode_rar29_auto_filtered_member_with_progress(
            data, options, lz_method, ppmd_trial, progress, resources,
        ),
        (Rar29Method::Auto, policy) => {
            let mut best = match policy {
                FilterPolicy::Explicit(filter) => EncodedPayload {
                    data: with_codec_progress(progress, |report| {
                        Unpack29Encoder::with_options(options)
                            .encode_member_with_filters_and_progress(
                                data,
                                std::slice::from_ref(filter),
                                Some(report),
                            )
                    })?,
                    method: lz_method,
                },
                _ => encode_rar29_lz_member(data, options, lz_method, progress)?,
            };
            // Gated on the content, so a binary member never pays for a PPMd
            // encode it was always going to lose.
            if ppmd_trial && is_text_ppmd_candidate(data) {
                let candidate = ppmd(None)?;
                if candidate.data.len() < best.data.len() {
                    best = candidate;
                }
            }
            Ok(best)
        }
    }
}

/// Codes a member as PPMd with escapes under each model in `sizes`, and keeps
/// the smallest, earlier on a tie.
///
/// Only the first model's pass moves the progress bar; the others poll for
/// cancellation, so the bar counts the member once.
fn encode_rar29_ppmd_member(
    data: &[u8],
    filter: Option<&FilterSpec>,
    max_match_distance: usize,
    sizes: &[PpmdModelSize],
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<u8>> {
    let mut best: Option<Vec<u8>> = None;
    for (index, &size) in sizes.iter().enumerate() {
        let encode = |report: &mut dyn FnMut(usize) -> bool| {
            crate::codec::rar29::unpack29_encode_ppmd_with_progress(
                data,
                true,
                filter.cloned(),
                max_match_distance,
                size,
                report,
            )
        };
        let packed = if index == 0 {
            with_codec_progress(progress, encode)?
        } else {
            encode(&mut |_| progress.is_none_or(|work| !work.is_cancelled()))
                .map_err(map_codec_cancel)?
        };
        if best.as_ref().is_none_or(|best| packed.len() < best.len()) {
            best = Some(packed);
        }
    }
    best.ok_or(Error::InvalidArgument("no PPMd model to code with"))
}

/// Whether this level is willing to encode the member twice to choose an engine.
///
/// Takes the resolved level, so an absent level and `--level 3` agree.
///
/// Levels 1 and 2 ask for speed and skip it. Level 3 is the default, and the
/// trial is worth about a fifth of the size on text for roughly twice the
/// encode. WinRAR turns PPMd on one level later, at m4: on 4 MiB of text WinRAR
/// 3.00 packs 657,294 bytes at m3 and 585,357 at m4, and rars 540,517 at both.
fn ppmd_trial_pays(level: u8) -> bool {
    level >= 3
}

fn validate_rar29_filter_policy(policy: &FilterPolicy, method: Rar29Method) -> Result<()> {
    // Searching for a filter means measuring candidates against each other,
    // and the search only knows how to measure them through LZ.
    if matches!(policy, FilterPolicy::Auto) && method == Rar29Method::Ppmd {
        return Err(Error::InvalidArgument(
            "RAR 2.9 cannot search for a filter while PPMd is forced",
        ));
    }
    let filter = match policy {
        FilterPolicy::Explicit(filter) => filter,
        FilterPolicy::None | FilterPolicy::Auto => return Ok(()),
    };
    match filter.kind {
        FilterKind::Delta { channels } => {
            if channels == 0 || channels > 32 {
                return Err(Error::InvalidArgument(
                    "RAR 2.9 DELTA filter channel count is invalid",
                ));
            }
        }
        FilterKind::Audio { channels } => {
            if channels == 0 || channels > 32 {
                return Err(Error::InvalidArgument(
                    "RAR 2.9 AUDIO filter channel count is invalid",
                ));
            }
        }
        FilterKind::Rgb { width, pos_r } => {
            if width == 0 || !width.is_multiple_of(3) || pos_r > 2 {
                return Err(Error::InvalidArgument(
                    "RAR 2.9 RGB filter parameters are invalid",
                ));
            }
        }
        FilterKind::E8 | FilterKind::E8E9 | FilterKind::Itanium => {}
        // Refused here rather than in the codec, so nothing is compressed
        // before the caller is told the filter cannot be written.
        FilterKind::Arm => {
            return Err(Error::UnsupportedFeature {
                version: ArchiveVersion::Rar29,
                feature: "ARM filter",
            })
        }
    }
    Ok(())
}

fn encode_rar29_lz_member(
    data: &[u8],
    options: Rar29EncodeOptions,
    method: u8,
    progress: Option<&WorkTracker<'_>>,
) -> Result<EncodedPayload> {
    let compressed = with_codec_progress(progress, |report| {
        unpack29_encode_literals_with_options_and_progress(data, options, report)
    })?;
    if compressed.len() >= data.len() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(EncodedPayload {
        data: compressed,
        method,
    })
}

#[cfg(test)]
fn encode_rar29_filtered_member(
    data: &[u8],
    filter: FilterSpec,
    options: Rar29EncodeOptions,
) -> Result<Vec<u8>> {
    Unpack29Encoder::with_options(options)
        .encode_member_with_filter(data, filter)
        .map_err(Error::from)
}

#[cfg(test)]
fn encode_rar29_filtered_members(
    data: &[u8],
    filters: &[FilterSpec],
    options: Rar29EncodeOptions,
) -> Result<Vec<u8>> {
    Unpack29Encoder::with_options(options)
        .encode_member_with_filters(data, filters)
        .map_err(Error::from)
}

/// How the RAR 2.9 family measures a filter candidate, for the shared search.
#[derive(Clone, Copy)]
struct Rar29Search;

impl crate::filter_search::FilterSearch for Rar29Search {
    type Options = Rar29EncodeOptions;

    fn screened_kinds(&self, data: &[u8]) -> Vec<FilterKind> {
        let mut kinds = vec![FilterKind::Itanium];
        for channels in 1..=4 {
            kinds.push(FilterKind::Delta { channels });
            // Free to ask, and it keeps the screened set from doubling.
            if is_audio_filter_candidate(data, channels) {
                kinds.push(FilterKind::Audio { channels });
            }
        }
        kinds.extend(
            AUTO_RGB_WIDTHS
                .into_iter()
                .filter(|&width| data.len() >= width)
                .map(|width| FilterKind::Rgb { width, pos_r: 0 }),
        );
        kinds
    }

    /// Unlike RAR 5, a greedy parse here really is cheaper. On a megabyte of
    /// binary it measured 59ms against 91ms at full effort, and it ranks
    /// candidates the same way, so the screens run reduced and only the
    /// finalists pay full price.
    fn screen_options(&self, options: Rar29EncodeOptions) -> Rar29EncodeOptions {
        let mut ranking = Rar29EncodeOptions::new(options.max_match_candidates.min(8))
            .with_lazy_matching(false)
            .with_max_match_distance(options.max_match_distance);
        if let Some(block_size) = options.block_size {
            ranking = ranking.with_block_size(block_size);
        }
        ranking
    }

    /// The VM filter splits a range into blocks it can address, and a delta
    /// block holds whole records, so the channel count is bounded by the block
    /// rather than by a field width the way RAR 5's is.
    fn max_delta_channels(&self) -> usize {
        crate::codec::rar29::MAX_VM_DELTA_FILTER_BLOCK_SIZE
    }

    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Vec<u8>> {
        crate::codec::rar29::filtered_members(data, filters)
            .map(|filtered| filtered.data)
            .map_err(Error::from)
    }

    fn encode_plain(
        &self,
        data: &[u8],
        options: Rar29EncodeOptions,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        match progress {
            Some(progress) => {
                unpack29_encode_literals_with_options_and_progress(data, options, progress)
                    .map_err(map_codec_cancel)
            }
            None => unpack29_encode_literals_with_options(data, options).map_err(Error::from),
        }
    }

    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: Rar29EncodeOptions,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        Unpack29Encoder::with_options(options)
            .encode_member_with_filters_and_progress(data, filters, progress)
            .map_err(map_codec_cancel)
    }
}

#[cfg(test)]
fn encode_rar29_auto_filtered_member(
    data: &[u8],
    options: Rar29EncodeOptions,
    lz_method: u8,
    include_ppmd: bool,
) -> Result<EncodedPayload> {
    encode_rar29_auto_filtered_member_with_progress(
        data,
        options,
        lz_method,
        include_ppmd,
        None,
        None,
    )
}

fn encode_rar29_auto_filtered_member_with_progress(
    data: &[u8],
    options: Rar29EncodeOptions,
    lz_method: u8,
    include_ppmd: bool,
    progress: Option<&WorkTracker<'_>>,
    resources: Option<&WriterResources>,
) -> Result<EncodedPayload> {
    // The search measures the unfiltered member as one of its own candidates
    // and returns the winner's bytes, so encoding the member plainly here as
    // well was a second full pass over every binary member on the default
    // settings. Text goes nowhere near the search, so it still needs one.
    let text = is_text_ppmd_candidate(data);
    if include_ppmd && text {
        return encode_rar29_text_member(data, options, lz_method, progress);
    }
    let searching = !text && crate::filter_search::search_applies(data);
    let best = EncodedPayload {
        data: if searching {
            // Every finalist is a full encode, so at the levels with a
            // shortest-path parse they are measured by the lazy parse that
            // seeds it, and only the winner is parsed the slow way. Which
            // filter suits the member does not depend on how hard the parse
            // tries, and the lazy encode stays in hand in case it codes smaller.
            let lazy = options.with_optimal_parse_passes(0);
            // The member's own charge holds one finalist's encode. Each one
            // encoded beside it is charged its own, and only while it runs.
            let each = crate::codec::rar29::member_encode_workspace(data.len(), lazy);
            let (filters, measured) = crate::filter_search::choose_filter_side_by_side(
                &Rar29Search,
                data,
                lazy,
                Some(&|walked| {
                    if walked == 0 {
                        !progress.is_some_and(WorkTracker::is_cancelled)
                    } else {
                        progress.is_none_or(|work| work.advance(walked as u64))
                    }
                }),
                &|| resources.and_then(|resources| resources.try_acquire(each)),
            )?;
            if options.optimal_parse_passes == 0 {
                measured
            } else {
                use crate::filter_search::FilterSearch;
                let mut poll = |_| !progress.is_some_and(WorkTracker::is_cancelled);
                let parsed = if filters.is_empty() {
                    Rar29Search.encode_plain(data, options, Some(&mut poll))?
                } else {
                    Rar29Search.encode_filtered(data, &filters, options, Some(&mut poll))?
                };
                if parsed.len() < measured.len() {
                    parsed
                } else {
                    measured
                }
            }
        } else {
            with_codec_progress(progress, |report| {
                unpack29_encode_literals_with_options_and_progress(data, options, report)
            })?
        },
        method: lz_method,
    };
    if best.data.len() >= data.len() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(best)
}

/// Codes text as LZ, PPMd with escapes and plain PPMd, the PPMd under each
/// model the level tries; the smallest wins.
fn encode_rar29_text_member(
    data: &[u8],
    options: Rar29EncodeOptions,
    lz_method: u8,
    progress: Option<&WorkTracker<'_>>,
) -> Result<EncodedPayload> {
    // Encode the whole member with both engines and keep the smaller. Neither
    // size nor a sample predicts the winner: 8 MiB of content that repeats
    // every 4 MiB packs to 843 KB under LZ and 1.44 MB under PPMd, and a sample
    // narrower than the repeat distance cannot see the repetition. On a small
    // sample archive overhead dominates, so 128 KiB of one phrase reads as a
    // 45% PPMd win (118 bytes against 213). PPMd costs about three times LZ on
    // the same bytes; `ppmd_trial_pays` decides which levels pay for both.
    let models = ppmd_models_for_level(lz_method.saturating_sub(0x30));
    // PPMd wins almost every text member, so the LZ side of the trial is the
    // lazy parse: on the bench's eight text classes at levels 4 and 5 the
    // shortest-path parse changed no packed byte and doubled the time on the
    // 4 MiB members.
    let options = options.with_optimal_parse_passes(0);
    let (_, best) = text_trial(data, options, models, &|encode| {
        with_codec_progress(progress, |report| encode(report))
    })?;
    if best.len() >= data.len() {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    Ok(EncodedPayload {
        data: best,
        method: lz_method,
    })
}

/// One way to run a trial's encode, which decides what its progress reports do.
type TrialRun<'a> = dyn Fn(
        &mut dyn FnMut(&mut dyn FnMut(usize) -> bool) -> crate::codec::Result<Vec<u8>>,
    ) -> Result<Vec<u8>>
    + Sync
    + 'a;

/// Codes text as LZ, then PPMd with escapes and plain PPMd under each model
/// size in turn; the smallest wins, earlier on a tie.
///
/// A PPMd engine names the model it won under, so a caller that codes the
/// member again from it starts the same one.
fn text_trial(
    data: &[u8],
    options: Rar29EncodeOptions,
    models: &[PpmdModelSize],
    run: &TrialRun<'_>,
) -> Result<(StreamedEngine, Vec<u8>)> {
    let ppmd = |size: PpmdModelSize, escapes: Option<usize>| {
        run(&mut |report| {
            crate::codec::rar29::unpack29_encode_ppmd_with_progress(
                data,
                escapes.is_some(),
                None,
                escapes.unwrap_or(0),
                size,
                report,
            )
        })
    };
    // The escape tokens price themselves against costs measured off the
    // stream they are shaping, so a member where every escape loses can still
    // ratify a few before the measurements catch up. A pure-literal stream is
    // the direct check.
    let pair = |size: PpmdModelSize| {
        crate::parallel::join(
            || ppmd(size, Some(options.max_match_distance)),
            || ppmd(size, None),
        )
    };
    let (&first, larger) = models
        .split_first()
        .expect("every level that trials PPMd names a model");
    let (lz, first_pair) = crate::parallel::join(
        || {
            run(&mut |report| {
                unpack29_encode_literals_with_options_and_progress(data, options, report)
            })
        },
        || pair(first),
    );
    let mut best = (
        StreamedEngine::Lz {
            filter_search: false,
        },
        lz?,
    );
    let mut consider = |size: PpmdModelSize,
                        (escaped, literals): (Result<Vec<u8>>, Result<Vec<u8>>)|
     -> Result<()> {
        for (escapes, candidate) in [
            (Some(options.max_match_distance), escaped?),
            (None, literals?),
        ] {
            if candidate.len() < best.1.len() {
                best = (StreamedEngine::Ppmd { escapes, size }, candidate);
            }
        }
        Ok(())
    };
    consider(first, first_pair)?;
    // One model at a time, so the trial holds two of them rather than all.
    for &size in larger {
        consider(size, pair(size))?;
    }
    Ok(best)
}

/// The bytes of the largest PPMd model the writer's level tries.
fn largest_ppmd_model(options: WriterOptions) -> u64 {
    ppmd_models_for_options(options)
        .iter()
        .map(|size| size.bytes())
        .max()
        .unwrap_or(crate::codec::rar29::PPMD_MODEL_BYTES)
}

/// The PPMd models the writer's level tries, smallest first.
fn ppmd_models_for_options(options: WriterOptions) -> &'static [PpmdModelSize] {
    ppmd_models_for_level(compression_method_for_level(options).saturating_sub(0x30))
}

/// The PPMd models a level tries on text, smallest first.
///
/// Each level tries everything the level below does and one model more, so a
/// higher level can only find a smaller stream. Order 8 in 25 MB is what rar
/// 3.00 declares at m5. A higher order needs the memory to hold its contexts:
/// order 16 in 40 MB restarts its model partway through 4 MiB of man pages and
/// loses to order 8, and in 64 MB it wins. Measured with escapes, packed bytes:
///
/// ```text
/// model           o8 25MB   o12 64MB   o16 64MB  o25 128MB
/// man pages       539,345    535,071    534,221    534,134
/// source tar      551,388    525,240    520,171    512,921
/// ```
///
/// Small members code best as plain literals, where order 16 is worth 0.1% to
/// 0.6% over order 8 on headers, logs and docs but loses 0.06% on the mixed
/// class, which is why order 8 stays in the trial rather than being replaced.
///
/// A streamed member is coded under the model that wins on a sample from its
/// middle, and past 64 MiB that sample still ranks the models the way the
/// whole member does. With escapes, a 16 MiB sample against the whole:
///
/// ```text
/// model                     o8 25MB     o16 64MB    o25 128MB
/// C headers, sample       1,187,996    1,133,289    1,126,435
/// C headers, 150 MB      14,203,877   13,672,734   13,581,772
/// man and docs, sample    2,389,131    2,365,099    2,333,977
/// man and docs, 120 MB   11,123,884   10,997,130   10,822,915
/// ```
fn ppmd_models_for_level(level: u8) -> &'static [PpmdModelSize] {
    const ORDER_16: PpmdModelSize = PpmdModelSize {
        order: 16,
        memory_mb: 64,
    };
    const ORDER_25: PpmdModelSize = PpmdModelSize {
        order: 25,
        memory_mb: 128,
    };
    match level {
        0..=3 => &[PpmdModelSize::DEFAULT],
        4 => &[PpmdModelSize::DEFAULT, ORDER_16],
        _ => &[PpmdModelSize::DEFAULT, ORDER_16, ORDER_25],
    }
}

fn is_text_ppmd_candidate(data: &[u8]) -> bool {
    windows_read_as_text(text_sample_offsets(data.len()).map(|start| {
        let end = start.saturating_add(RAR29_TEXT_SAMPLE_SIZE).min(data.len());
        &data[start..end]
    }))
}

fn windows_read_as_text<'a>(windows: impl IntoIterator<Item = &'a [u8]>) -> bool {
    let mut printable = 0usize;
    let mut nul = 0usize;
    let mut total = 0usize;
    for window in windows {
        let (window_printable, window_nul, window_total) = score_text_window(window);
        printable += window_printable;
        nul += window_nul;
        total += window_total;
    }
    total != 0 && nul * 100 <= total && printable * 100 >= total * 85
}

/// Counts one sampled window as printable, NUL and total bytes.
///
/// Counting only ASCII read every non-English member as binary. The bench's
/// text member is a set of translated man pages, 23% of it well-formed
/// multibyte UTF-8, and it scored 77% against the 85% bar and went to LZ. A
/// multibyte sequence is as much text as an ASCII letter. Accepting them costs
/// no precision either, because random binary almost never forms one: a lead
/// byte followed by a continuation byte is about 3% of positions, nowhere near
/// enough to carry a binary member over the bar.
fn score_text_window(window: &[u8]) -> (usize, usize, usize) {
    let mut printable = 0usize;
    let mut nul = 0usize;
    let mut total = 0usize;
    let mut index = 0usize;
    while index < window.len() {
        let byte = window[index];
        if byte == 0 {
            let run = window[index..]
                .iter()
                .take_while(|&&byte| byte == 0)
                .count();
            index += run;
            // A run this long is padding rather than content, and padding says
            // nothing about what surrounds it, so it is left out of the count
            // instead of counted against the member. A tar pads every file to a
            // 512 byte block and ends with a block of nothing, which put 27% NUL
            // in front of a 1% bar and sent a tar of source files to LZ as if it
            // were binary. What is left either side of the padding still decides
            // it: a tar of text reads 99.8% text, and an ELF only climbs from
            // 34% to 38%, nowhere near the bar.
            if run < RAR29_NUL_RUN_IS_PADDING {
                nul += run;
                total += run;
            }
        } else if byte.is_ascii_graphic() || matches!(byte, b'\n' | b'\r' | b'\t' | b' ') {
            printable += 1;
            total += 1;
            index += 1;
        } else if let Some(len) = utf8_sequence_len(window, index) {
            printable += len;
            total += len;
            index += len;
        } else if utf8_lead_len(byte).is_some_and(|len| index + len > window.len()) {
            // The window cut a sequence in half. That is an artefact of where
            // the sample lands, not evidence of binary, so the window ends here.
            break;
        } else {
            total += 1;
            index += 1;
        }
    }
    (printable, nul, total)
}

/// How many bytes the sequence starting with this byte claims, if it can start
/// one. Overlong forms (`0xc0`, `0xc1`) and anything past U+10FFFF cannot.
fn utf8_lead_len(byte: u8) -> Option<usize> {
    match byte {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

/// The length of the well-formed UTF-8 sequence at `index`, if there is one.
fn utf8_sequence_len(window: &[u8], index: usize) -> Option<usize> {
    let len = utf8_lead_len(window[index])?;
    if index + len > window.len() {
        return None;
    }
    window[index + 1..index + len]
        .iter()
        .all(|byte| (0x80..=0xbf).contains(byte))
        .then_some(len)
}

fn text_sample_offsets(len: usize) -> [usize; 3] {
    [
        0,
        len.saturating_sub(RAR29_TEXT_SAMPLE_SIZE) / 2,
        len.saturating_sub(RAR29_TEXT_SAMPLE_SIZE),
    ]
}

fn is_audio_filter_candidate(data: &[u8], channels: usize) -> bool {
    if channels == 0 || channels > 4 || data.len() < channels * 64 {
        return false;
    }

    let mut total_delta = 0usize;
    let mut small_delta = 0usize;
    let mut compared = 0usize;
    for start in text_sample_offsets(data.len()) {
        // The admission check leaves at least 64 samples per channel, even
        // for the shortest window, so every window has comparisons to make.
        let end = start
            .saturating_add(RAR29_AUDIO_SAMPLE_SIZE)
            .min(data.len());
        let aligned_start = start + ((channels - start % channels) % channels);
        for channel in 0..channels {
            let mut previous = None;
            let mut index = aligned_start + channel;
            while index < end {
                let byte = data[index];
                if let Some(previous) = previous {
                    let delta = usize::from(byte.abs_diff(previous));
                    let delta = delta.min(256 - delta);
                    total_delta += delta;
                    small_delta += usize::from(delta <= 8);
                    compared += 1;
                }
                previous = Some(byte);
                index += channels;
            }
        }
    }

    total_delta <= compared * 24 && small_delta * 100 >= compared * 55
}

/// One member, however the caller supplied it.
struct Member<'a> {
    unicode_name: Option<&'a [u8]>,
    unpack_version: Option<u8>,
    name: &'a [u8],
    bytes: MemberBytes<'a>,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    password: Option<&'a [u8]>,
    file_comment: Option<&'a [u8]>,
    extended_times: Option<&'a [u8]>,
    is_directory: bool,
    is_symlink: bool,
}

impl<'a> Member<'a> {
    fn from_stored(entry: &'a StoredEntry<'a>) -> Self {
        Self {
            name: entry.name,
            bytes: MemberBytes::Borrowed(entry.data),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password,
            file_comment: entry.file_comment,
            unicode_name: None,
            unpack_version: None,
            extended_times: None,
            is_directory: false,
            is_symlink: false,
        }
    }

    fn from_file(entry: &'a FileEntry<'a>) -> Self {
        Self {
            name: entry.name,
            bytes: MemberBytes::Borrowed(entry.data),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password,
            file_comment: entry.file_comment,
            unicode_name: None,
            unpack_version: None,
            extended_times: None,
            is_directory: false,
            is_symlink: false,
        }
    }

    fn from_streaming(entry: &'a StreamingEntry) -> Self {
        Self {
            name: &entry.name,
            bytes: MemberBytes::Source(&entry.source),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password.as_deref(),
            file_comment: entry.file_comment.as_deref(),
            unicode_name: None,
            unpack_version: None,
            extended_times: None,
            // Streaming callers have no retained metadata wrapper. The native
            // attribute word already distinguishes directory sources.
            is_directory: if entry.host_os == 3 {
                entry.file_attr & 0o170000 == 0o040000
            } else {
                entry.file_attr & 0x10 != 0
            },
            is_symlink: false,
        }
    }

    fn unpacked_size(&self) -> Result<u64> {
        self.bytes.len()
    }
}

struct EncodedMember<'a> {
    payload: MemberPayload<'a>,
    method: u8,
    unpacked_size: u64,
    file_crc: u32,
    /// The budget's charge for what waits to be written, released when the
    /// member has been. A directory holds nothing and has none.
    held: Option<MemoryPermit>,
}

/// What writing one member holds beyond its payload: the buffer a stored
/// member is copied and encrypted through.
const WRITE_WORKSPACE: u64 = 1024 * 1024;

/// Working memory one member needs while it is coded.
///
/// This is the admission weight that decides how many members run at once, not
/// a prediction: the encoder holds the member, its packed output, and a match
/// finder sized by the block it works in. Text at the levels that try PPMd
/// also holds two PPMd models at once, one per trial, and the escape search.
fn member_workspace(options: WriterOptions, unpacked: u64, compressing: bool) -> u64 {
    if !compressing {
        // A stored member is never loaded: it is written from the caller's
        // bytes or copied from its source, encrypted as it goes.
        return WRITE_WORKSPACE;
    }
    let dictionary =
        dictionary_size_for_options(options).unwrap_or(RAR29_MAX_DICTIONARY_SIZE) as u64;
    let rar29 = matches!(
        options.target,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
    );
    let level = compression_method_for_level(options).saturating_sub(0x30);
    let ppmd_models = if rar29 && (ppmd_trial_pays(level) || options.method == Rar29Method::Ppmd) {
        // A trial holds two models of one size at a time. A chain keeps its
        // own beside two copies: a short member's escaped coding is kept
        // while the same member codes again as literals.
        let models = if options.features.solid { 3 } else { 2 };
        (models * largest_ppmd_model(options)).saturating_add(
            crate::codec::rar29::ppmd_search_workspace(dictionary as usize),
        )
    } else {
        0
    };
    let optimal_parse = if rar29 {
        rar29_optimal_parse_workspace(options, unpacked)
    } else {
        0
    };
    unpacked
        .saturating_mul(held_per_byte(options))
        .saturating_add(dictionary.saturating_mul(12))
        .saturating_add(ppmd_models)
        .saturating_add(optimal_parse)
        .saturating_add(coder_workspace(options))
        .saturating_add(2 * 1024 * 1024)
}

/// What the shortest-path parse holds beyond the lazy one: a workspace for
/// each block that parses at once, which is one per thread up to the sixteen
/// a batch spreads over, and no more than the member has blocks.
fn rar29_optimal_parse_workspace(options: WriterOptions, unpacked: u64) -> u64 {
    let parses = rar29_encode_options_for_options(options)
        .ok()
        .filter(|options| options.optimal_parse_passes != 0)
        .map_or(0, |_| {
            let blocks = unpacked.div_ceil(RAR29_LZ_BLOCK_SIZE as u64).max(1);
            blocks.min(crate::parallel::threads().clamp(1, 16) as u64)
        });
    parses.saturating_mul(crate::codec::rar29::OPTIMAL_PARSE_WORKSPACE)
}

/// What the RAR 1.5 and 2.0 coders hold whatever the member's size: RAR 1.5's
/// match index over its 64 KiB window, and RAR 2.0's parse of one block.
fn coder_workspace(options: WriterOptions) -> u64 {
    match options.target {
        ArchiveVersion::Rar15 => crate::codec::rar13::ENCODER_WORKSPACE,
        ArchiveVersion::Rar20 => crate::codec::rar20::block_workspace(
            rar20_encode_options_for_options(options).is_ok_and(|options| options.optimal_parse),
        ),
        _ => 0,
    }
}

/// Bytes held per member byte while it is coded: the member and its packed
/// form. RAR 1.5 and 2.0 index and parse a bounded stretch of the member,
/// which [`coder_workspace`] charges.
fn held_per_byte(_options: WriterOptions) -> u64 {
    2
}

/// Codes one member, holding its bytes only while it is being coded.
fn encode_member<'a>(
    member: &Member<'a>,
    options: WriterOptions,
    coding: &MemberCoding,
    solid_encoder: &mut Option<SolidEncoder>,
    resources: &WriterResources,
    progress: &WorkTracker<'_>,
) -> Result<EncodedMember<'a>> {
    let unpacked_size = measure_member(member, options, progress)?;
    let permit = member_charge(member, options, coding, unpacked_size)
        .map(|charge| {
            resources.acquire_serialising_cancellable(charge, &|| progress.is_cancelled())
        })
        .transpose()?;
    encode_measured(
        member,
        options,
        coding,
        solid_encoder,
        unpacked_size,
        permit,
        resources,
        progress,
    )
}

/// A member's size, taken once so its header and its charge agree.
fn measure_member(
    member: &Member<'_>,
    options: WriterOptions,
    progress: &WorkTracker<'_>,
) -> Result<u64> {
    progress.check()?;
    let unpacked_size = member.unpacked_size()?;
    validate_member(member.name, options.target, unpacked_size)?;
    if member.is_directory && unpacked_size != 0 {
        return Err(Error::InvalidArgument("directory source must be empty"));
    }
    Ok(unpacked_size)
}

/// What coding a member and then writing it holds; a directory holds nothing.
fn member_charge(
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    unpacked_size: u64,
) -> Option<u64> {
    (!member.is_directory).then(|| member_workspace(options, unpacked_size, coding.compresses()))
}

/// [`encode_member`] once the member is measured and charged for. The charge
/// goes with the coded member and is cut to what it holds once coding is done.
#[allow(clippy::too_many_arguments)]
fn encode_measured<'a>(
    member: &Member<'a>,
    options: WriterOptions,
    coding: &MemberCoding,
    solid_encoder: &mut Option<SolidEncoder>,
    unpacked_size: u64,
    mut held: Option<MemoryPermit>,
    resources: &WriterResources,
    progress: &WorkTracker<'_>,
) -> Result<EncodedMember<'a>> {
    if member.is_directory {
        return Ok(EncodedMember {
            payload: MemberPayload::Packed(Vec::new()),
            method: 0x30,
            unpacked_size: 0,
            file_crc: 0,
            held,
        });
    }

    // Legacy link targets must not become dependencies of later solid data:
    // reference readers handle links separately from the solid unpacker.
    let coding = if member.is_symlink {
        if options.features.solid {
            *solid_encoder = Some(SolidEncoder::for_target(options)?);
        }
        &MemberCoding::Stored
    } else {
        coding
    };

    // A stored member never needs to be resident: checksum it from its source
    // and let the writer copy it straight through, encrypting as it goes.
    if let (MemberCoding::Stored, Some(source)) = (coding, member.bytes.source()) {
        return Ok(EncodedMember {
            payload: MemberPayload::Copied(source),
            method: 0x30,
            unpacked_size,
            file_crc: {
                let mut crc = Crc32::new();
                member.bytes.walk_exact_with_progress(
                    unpacked_size,
                    progress.reporter(),
                    |chunk| {
                        crc.update(chunk);
                        progress.advance(chunk.len() as u64);
                    },
                )?;
                crc.finish()
            },
            held,
        });
    }

    let data = member
        .bytes
        .load_exact_with_progress(unpacked_size, progress.reporter())?;
    let mut crc = Crc32::new();
    for chunk in data.chunks(64 * 1024) {
        progress.check()?;
        crc.update(chunk);
        if !coding.compresses() {
            progress.advance(chunk.len() as u64);
        }
    }
    let file_crc = crc.finish();
    progress.check()?;
    let payload = match coding {
        // The caller's bytes are written as they stand, encrypted as they go
        // out. A copy would hold the member a second time.
        MemberCoding::Stored => {
            return Ok(EncodedMember {
                payload: member.bytes.stored(),
                method: 0x30,
                unpacked_size,
                file_crc,
                held,
            })
        }
        MemberCoding::Compressed => encode_or_store_payload(
            &data,
            options,
            solid_encoder,
            Some(progress),
            Some(resources),
        )?,
        MemberCoding::Filtered(policy) => encode_filtered_payload(
            &data,
            policy,
            options,
            solid_encoder,
            Some(progress),
            Some(resources),
        )?,
    };
    drop(data);
    let mut packed = payload.data;
    if let Some(permit) = &mut held {
        // Encryption pads the packed form in place, so make room for that now,
        // while the coder's charge still covers moving it.
        if member.password.is_some() {
            packed.reserve_exact(15);
        }
        permit.shrink_to((packed.capacity() as u64).saturating_add(WRITE_WORKSPACE));
    }
    Ok(EncodedMember {
        payload: MemberPayload::Packed(packed),
        method: payload.method,
        unpacked_size,
        file_crc,
        held,
    })
}

/// What a header says about the payload, which a streamed member learns last.
#[derive(Clone, Copy)]
struct HeaderPayload {
    method: u8,
    unpacked_size: u64,
    file_crc: u32,
    packed_size: u64,
}

fn member_header(
    member: &Member<'_>,
    options: WriterOptions,
    solid_continuation: bool,
    salt: Option<[u8; 8]>,
    sizes: HeaderPayload,
) -> Result<Vec<u8>> {
    let target = options.target;
    let mut flags = writer_file_flags(member.password, member.file_comment, solid_continuation);
    if salt.is_some() {
        flags |= FHD_SALT;
    }
    let wire_name = member.unicode_name.unwrap_or(member.name);
    if member.unicode_name.is_some() {
        flags |= super::FHD_UNICODE;
    }
    let mut extra = encode_file_comment(member.file_comment)?;
    if let Some(raw) = member.extended_times {
        flags |= FHD_EXTTIME;
        extra.extend_from_slice(raw);
    }
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: FILE_HEAD,
            name: wire_name,
            unpacked_size: sizes.unpacked_size,
            file_crc: sizes.file_crc,
            packed_size: sizes.packed_size,
            file_time: member.file_time,
            file_attr: member.file_attr,
            host_os: member.host_os,
            target,
            method: sizes.method,
            dictionary_flags: if member.is_directory && target != ArchiveVersion::Rar15 {
                FHD_DIRECTORY_MASK
            } else {
                dictionary_flags_for_options(options)?
            },
            flags,
            salt,
            extra: &extra,
        },
    )?;
    if let Some(version) = member.unpack_version {
        header[24] = version;
        write_file_header_crc(&mut header, 0, wire_name.len(), flags);
    }
    Ok(header)
}

/// Whether a member is coded as it is read rather than held whole.
fn streams_member(
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    stream_above: u64,
) -> Result<bool> {
    let level = compression_method_for_level(options).saturating_sub(0x30);
    if member.is_directory
        || member.is_symlink
        || level == 0
        || !matches!(
            options.target,
            ArchiveVersion::Rar15
                | ArchiveVersion::Rar20
                | ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
        )
        || !match coding {
            MemberCoding::Compressed
            | MemberCoding::Filtered(FilterPolicy::None | FilterPolicy::Auto) => true,
            MemberCoding::Filtered(FilterPolicy::Explicit(_)) => {
                options.target != ArchiveVersion::Rar20
            }
            MemberCoding::Stored => false,
        }
    {
        return Ok(false);
    }
    Ok(member.unpacked_size()? > stream_above)
}

/// Decided before any of the member is coded, since nothing it codes can be taken back.
#[derive(Clone, Copy)]
enum StreamedEngine {
    Lz {
        filter_search: bool,
    },
    /// `escapes` is how far LZ escapes reach back, `None` for literals only;
    /// `size` is the model a member that starts one starts.
    Ppmd {
        escapes: Option<usize>,
        size: PpmdModelSize,
    },
}

/// A sample of four reaches stands in for the whole member in the in-memory trials.
///
/// That is enough output for the engines to be compared on, which a 128 KiB
/// screen is not, but repeats further apart than the sample stay invisible to
/// it, the other case [`encode_rar29_text_member`] records against sampling.
///
/// `models` is the PPMd models to measure, smallest first. A member that
/// continues a chain's model passes one, since its size is already fixed.
fn streamed_engine(
    member: &Member<'_>,
    len: usize,
    options: WriterOptions,
    coding: &MemberCoding,
    encode_options: Rar29EncodeOptions,
    models: &[PpmdModelSize],
    progress: &WorkTracker<'_>,
) -> Result<StreamedEngine> {
    let (&first, larger) = models
        .split_first()
        .ok_or(Error::InvalidArgument("no PPMd model to code with"))?;
    if options.method == Rar29Method::Ppmd {
        let escapes = encode_options.max_match_distance;
        if larger.is_empty() {
            return Ok(StreamedEngine::Ppmd {
                escapes: Some(escapes),
                size: first,
            });
        }
        // Forced PPMd codes with escapes, so that is all the sample measures,
        // under each model the level tries.
        let sample = engine_sample(member, len, options)?;
        let mut best: Option<(usize, PpmdModelSize)> = None;
        for &size in models {
            let packed = crate::codec::rar29::unpack29_encode_ppmd_with_progress(
                &sample,
                true,
                None,
                escapes,
                size,
                &mut |_| !progress.is_cancelled(),
            )
            .map_err(map_codec_cancel)?;
            if best.is_none_or(|(len, _)| packed.len() < len) {
                best = Some((packed.len(), size));
            }
        }
        return Ok(StreamedEngine::Ppmd {
            escapes: Some(escapes),
            size: best.map_or(first, |(_, size)| size),
        });
    }
    // A named filter in a chain is coded LZ, as it is in memory.
    let named = matches!(coding, MemberCoding::Filtered(FilterPolicy::Explicit(_)));
    if named && options.features.solid {
        return Ok(StreamedEngine::Lz {
            filter_search: false,
        });
    }
    let text = sampled_text(&member.bytes, len as u64)?;
    if !(text && trials_engines(options)) {
        let policy_searches = match coding {
            MemberCoding::Filtered(policy) => matches!(policy, FilterPolicy::Auto),
            _ => true,
        };
        return Ok(StreamedEngine::Lz {
            filter_search: policy_searches && !text,
        });
    }
    let sample = engine_sample(member, len, options)?;
    // LZ is measured by the lazy parse, as the in-memory trial measures it.
    let (engine, _) = text_trial(
        &sample,
        encode_options.with_optimal_parse_passes(0),
        models,
        &|encode| encode(&mut |_| !progress.is_cancelled()).map_err(map_codec_cancel),
    )?;
    Ok(engine)
}

/// The middle of the member, as much as one segment of the streamed LZ parse codes.
fn engine_sample(member: &Member<'_>, len: usize, options: WriterOptions) -> Result<Vec<u8>> {
    let sample_len = engine_sample_len(options).min(len);
    let mut sample = Vec::with_capacity(sample_len);
    let mut reader = member.bytes.open()?;
    reader.seek(SeekFrom::Start(((len - sample_len) / 2) as u64))?;
    reader
        .by_ref()
        .take(sample_len as u64)
        .read_to_end(&mut sample)?;
    if sample.len() != sample_len {
        return Err(Error::SourceChanged(
            "entry source size changed while compressing",
        ));
    }
    Ok(sample)
}

fn trials_engines(options: WriterOptions) -> bool {
    options.method == Rar29Method::Auto
        && ppmd_trial_pays(compression_method_for_level(options).saturating_sub(0x30))
}

/// As much as one segment of the streamed LZ parse codes.
fn engine_sample_len(options: WriterOptions) -> usize {
    dictionary_size_for_options(options)
        .unwrap_or(RAR29_MAX_DICTIONARY_SIZE)
        .saturating_mul(4)
}

/// [`is_text_ppmd_candidate`] on the same windows, read without loading the member.
fn sampled_text(bytes: &MemberBytes<'_>, len: u64) -> Result<bool> {
    let len = usize::try_from(len)
        .map_err(|_| Error::InvalidArgument("member is larger than this host can hold"))?;
    let mut reader = bytes.open()?;
    let mut windows = Vec::new();
    for start in text_sample_offsets(len) {
        let want = RAR29_TEXT_SAMPLE_SIZE.min(len - start);
        let mut window = Vec::with_capacity(want);
        reader.seek(SeekFrom::Start(start as u64))?;
        reader.by_ref().take(want as u64).read_to_end(&mut window)?;
        if window.len() != want {
            return Err(Error::SourceChanged(
                "entry source size changed while compressing",
            ));
        }
        windows.push(window);
    }
    Ok(windows_read_as_text(windows.iter().map(Vec::as_slice)))
}

/// A filter search holds a filtered segment and a candidate; a PPMd trial holds the sample and two models.
///
/// A chain also holds its history and model, which the member codes against.
fn streamed_workspace(options: WriterOptions, coding: &MemberCoding) -> u64 {
    let dictionary =
        dictionary_size_for_options(options).unwrap_or(RAR29_MAX_DICTIONARY_SIZE) as u64;
    if matches!(
        options.target,
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20
    ) {
        // One window and one block, and a chain's history.
        return dictionary
            .saturating_mul(2)
            .saturating_add(coder_workspace(options))
            .saturating_add(2 * 1024 * 1024);
    }
    let segment = engine_sample_len(options) as u64;
    let lz = dictionary
        .saturating_mul(12 + 6)
        .saturating_add(rar29_optimal_parse_workspace(options, u64::MAX))
        .saturating_add(2 * 1024 * 1024);
    // A named filter is applied in place, with no candidate to hold beside it.
    let searching = options.method != Rar29Method::Ppmd
        && matches!(
            coding,
            MemberCoding::Compressed | MemberCoding::Filtered(FilterPolicy::Auto)
        );
    let search = if searching {
        segment.saturating_mul(2)
    } else {
        0
    };
    let model = largest_ppmd_model(options);
    let ppmd = if options.method == Rar29Method::Ppmd || trials_engines(options) {
        segment.saturating_add(2 * model).saturating_add(
            crate::codec::rar29::ppmd_search_workspace(dictionary as usize),
        )
    } else {
        0
    };
    let chain = if options.features.solid {
        dictionary.saturating_add(model)
    } else {
        0
    };
    lz.saturating_add(search.max(ppmd)).saturating_add(chain)
}

/// Where a streamed member's packed bytes go: one archive, or the fragments of a volume set.
trait StreamedOut {
    /// Puts out what stands before the payload, with sizes still to be patched.
    fn begin(&mut self, salt: Option<[u8; 8]>, sizes: HeaderPayload) -> Result<()>;
    /// False stores the member instead; `coded` is how far into it the packed bytes reach with `block`.
    fn goes_on(&mut self, packed: u64, block: u64, coded: u64, unpacked: u64) -> bool;
    /// The member will not be stored instead, so nothing needs holding back to allow it.
    fn commit(&mut self) {}
    fn write_packed(&mut self, bytes: &[u8]) -> Result<()>;
    /// Back to the start of the payload; the stored copy is longer than the attempt, so it covers it.
    fn restart(&mut self) -> Result<()>;
    /// Patches the header now the payload's sizes and CRC are known.
    fn finish(&mut self, sizes: HeaderPayload) -> Result<()>;
}

/// A member in a single archive, its header written ahead and patched in place.
struct InPlace<'o, 'm> {
    output: &'o mut dyn SeekWrite,
    member: &'m Member<'m>,
    options: WriterOptions,
    header_key: Option<&'m HeaderKey>,
    continues: bool,
    salt: Option<[u8; 8]>,
    header_at: u64,
    header_len: u64,
}

impl InPlace<'_, '_> {
    fn write_header(&mut self, sizes: HeaderPayload) -> Result<u64> {
        let continuation = self.continues && sizes.method != 0x30;
        let header = member_header(self.member, self.options, continuation, self.salt, sizes)?;
        let from = self.output.stream_position()?;
        match self.header_key {
            Some(key) => write_encrypted_header(self.output, &header, key)?,
            None => self.output.write_all(&header)?,
        }
        Ok(self.output.stream_position()? - from)
    }
}

impl StreamedOut for InPlace<'_, '_> {
    fn begin(&mut self, salt: Option<[u8; 8]>, sizes: HeaderPayload) -> Result<()> {
        self.salt = salt;
        self.header_at = self.output.stream_position()?;
        self.header_len = self.write_header(sizes)?;
        Ok(())
    }

    fn goes_on(&mut self, packed: u64, block: u64, _coded: u64, unpacked: u64) -> bool {
        packed + block < unpacked
    }

    fn write_packed(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.output.write_all(bytes)?)
    }

    fn restart(&mut self) -> Result<()> {
        self.output
            .seek(SeekFrom::Start(self.header_at + self.header_len))?;
        Ok(())
    }

    fn finish(&mut self, sizes: HeaderPayload) -> Result<()> {
        let end = self.output.stream_position()?;
        self.output.seek(SeekFrom::Start(self.header_at))?;
        if self.write_header(sizes)? != self.header_len {
            return Err(Error::InvalidArgument(
                "legacy file header changed length when patched",
            ));
        }
        self.output.seek(SeekFrom::Start(end))?;
        Ok(())
    }
}

/// A member for an output that cannot seek. Its packed bytes go to a spool
/// on disk; once their sizes are known the header goes out, then the spool.
/// The header is the one [`InPlace`] patches in, so the archive is the same.
struct Spooled<'o, 'm> {
    output: &'o mut dyn Write,
    member: &'m Member<'m>,
    options: WriterOptions,
    header_key: Option<&'m HeaderKey>,
    continues: bool,
    salt: Option<[u8; 8]>,
    spool: Option<crate::streaming::Spool>,
    resources: &'m WriterResources,
}

impl Spooled<'_, '_> {
    fn spool(&mut self) -> Result<&mut crate::streaming::Spool> {
        self.spool.as_mut().ok_or(Error::InvalidArgument(
            "spooled member written before it began",
        ))
    }
}

impl StreamedOut for Spooled<'_, '_> {
    fn begin(&mut self, salt: Option<[u8; 8]>, _sizes: HeaderPayload) -> Result<()> {
        self.salt = salt;
        self.spool = Some(crate::streaming::Spool::create(self.resources)?);
        Ok(())
    }

    fn goes_on(&mut self, packed: u64, block: u64, _coded: u64, unpacked: u64) -> bool {
        packed + block < unpacked
    }

    fn write_packed(&mut self, bytes: &[u8]) -> Result<()> {
        Ok(self.spool()?.write_all(bytes)?)
    }

    fn restart(&mut self) -> Result<()> {
        // The stored copy is longer than the attempt, so it overwrites all of it.
        self.spool()?.rewind()
    }

    fn finish(&mut self, sizes: HeaderPayload) -> Result<()> {
        let continuation = self.continues && sizes.method != 0x30;
        let header = member_header(self.member, self.options, continuation, self.salt, sizes)?;
        match self.header_key {
            Some(key) => write_encrypted_header(self.output, &header, key)?,
            None => self.output.write_all(&header)?,
        }
        let mut spool = self.spool.take().ok_or(Error::InvalidArgument(
            "spooled member finished before it began",
        ))?;
        if spool.len() != sizes.packed_size {
            return Err(Error::InvalidArgument(
                "spooled member is not the size its header gives",
            ));
        }
        spool.copy_to(self.output)?;
        Ok(())
    }
}

/// Codes a member into `out` as it reads, storing it instead if the attempt doesn't pay.
#[allow(clippy::too_many_arguments)]
fn stream_member(
    out: &mut dyn StreamedOut,
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    data_keys: &mut DataKeys,
    solid: Option<SolidLink<'_>>,
    resources: &WriterResources,
    progress: &WorkTracker<'_>,
) -> Result<u8> {
    stream_member_admitted(
        out, member, options, coding, data_keys, solid, resources, None, progress,
    )
}

/// [`stream_member`], charged with `admitted` when the member was let into the
/// budget earlier and for [`streamed_workspace`] here otherwise.
#[allow(clippy::too_many_arguments)]
fn stream_member_admitted(
    out: &mut dyn StreamedOut,
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    data_keys: &mut DataKeys,
    mut solid: Option<SolidLink<'_>>,
    resources: &WriterResources,
    admitted: Option<MemoryPermit>,
    progress: &WorkTracker<'_>,
) -> Result<u8> {
    progress.check()?;
    let unpacked_size = member.unpacked_size()?;
    let len = usize::try_from(unpacked_size)
        .map_err(|_| Error::InvalidArgument("member is larger than this host can hold"))?;
    let _permit = match admitted {
        Some(permit) => permit,
        None => resources
            .acquire_serialising_cancellable(streamed_workspace(options, coding), &|| {
                progress.is_cancelled()
            })?,
    };
    // RAR 1.5 and 2.0 have one engine; RAR 2.9 chooses before coding anything.
    let rar29 = match options.target {
        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 => None,
        _ => {
            let encode_options = rar29_encode_options_for_options(options)?;
            // Forced PPMd with a named filter codes the member on its own, so
            // only it starts a model whatever the chain holds.
            let continues_model = !(options.method == Rar29Method::Ppmd
                && matches!(coding, MemberCoding::Filtered(FilterPolicy::Explicit(_))))
                && matches!(
                    solid.as_ref().and_then(|link| link.encoder.as_ref()),
                    Some(SolidEncoder::Rar29(encoder)) if encoder.has_ppmd_model()
                );
            let models = ppmd_models_for_options(options);
            let models = if continues_model {
                &models[..1]
            } else {
                models
            };
            let engine = streamed_engine(
                member,
                len,
                options,
                coding,
                encode_options,
                models,
                progress,
            )?;
            Some((encode_options, engine))
        }
    };
    let cipher = volumes::CipherPlan::new(options.target, member.password, data_keys)?;
    let mut sizes = HeaderPayload {
        method: compression_method_for_level(options),
        unpacked_size,
        file_crc: 0,
        packed_size: 0,
    };
    out.begin(cipher.salt(), sizes)?;
    // A RAR 1.5 solid member is never swapped for a stored copy, which would
    // break the chain (see `should_store_fallback`), so it goes out whatever
    // it packs to.
    let storable = !(options.target == ArchiveVersion::Rar15 && solid.is_some());
    if !storable {
        out.commit();
    }
    let mut sealed = Sealed::new(cipher.start()?);

    let mut crc = Crc32::new();
    let mut reader = crate::write_progress::CancellableIo {
        inner: member.bytes.open()?,
        progress: progress.reporter(),
    };
    let mut counted = CrcReader {
        inner: &mut reader,
        crc: &mut crc,
        ended: false,
    };
    let mut last = 0usize;
    let mut advance = |position: usize| {
        let delta = position.saturating_sub(last);
        last = last.max(position);
        progress.advance(delta as u64)
    };
    let mut write = |block: &[u8], coded: usize| -> crate::codec::Result<ControlFlow<()>> {
        let size = block.len() as u64;
        if !out.goes_on(sizes.packed_size, size, coded as u64, unpacked_size) && storable {
            return Ok(ControlFlow::Break(()));
        }
        sealed.write(out, block).map_err(|error| match error {
            Error::Cancelled => crate::codec::Error::Cancelled,
            error => crate::codec::Error::Io(Box::new(error)),
        })?;
        sizes.packed_size += size;
        Ok(ControlFlow::Continue(()))
    };
    let unchained_storable = storable && solid.is_none();
    let flow = match rar29 {
        None => match solid.as_mut().and_then(|link| link.encoder.as_mut()) {
            Some(SolidEncoder::Rar15(encoder)) => {
                encoder.encode_member_streamed(&mut counted, len, &mut advance, &mut write)
            }
            Some(SolidEncoder::Rar20(encoder)) => {
                encoder.encode_member_streamed(&mut counted, len, &mut advance, &mut write)
            }
            _ if options.target == ArchiveVersion::Rar15 => Unpack15Encoder::with_options(
                rar15_encode_options_for_level(options.compression_level)?,
            )
            .encode_member_streamed(&mut counted, len, &mut advance, &mut write),
            // Noise is stored without coding it first: the attempt would only
            // learn that at the end, which for gigabytes is half an hour.
            _ if unchained_storable && rar20_samples_expand(member, len, options, progress)? => {
                Ok(ControlFlow::Break(()))
            }
            _ => unpack20_encode_streamed(
                &mut counted,
                len,
                rar20_encode_options_for_options(options)?,
                &mut advance,
                &mut write,
            ),
        },
        Some((encode_options, engine)) => {
            let mut choose = |segment: &[u8]| -> crate::codec::Result<Vec<FilterSpec>> {
                if !crate::filter_search::search_applies(segment) {
                    return Ok(Vec::new());
                }
                let mut poll = |_| !progress.is_cancelled();
                // Only the choice is kept, so the lazy parse measures it.
                crate::filter_search::choose_filter(
                    &Rar29Search,
                    segment,
                    encode_options.with_optimal_parse_passes(0),
                    Some(&mut poll),
                )
                .map(|(specs, _)| specs)
                .map_err(|error| crate::codec::Error::Io(Box::new(error)))
            };
            let explicit = match coding {
                MemberCoding::Filtered(FilterPolicy::Explicit(filter)) => Some(filter),
                _ => None,
            };
            // A named filter is applied to every segment the search would have chosen for.
            let mut named = explicit
                .map(|filter| named_filter_segments(len, filter.clone()))
                .transpose()
                .map_err(map_codec_cancel)?;
            // Forced PPMd filters too, and codes the member on its own as it
            // does in memory, leaving a chain's history and model as they were.
            // A PPMd trial's winner is unfiltered, as its candidate in memory is.
            let ppmd_filter = explicit.filter(|_| options.method == Rar29Method::Ppmd);
            let mut own = None;
            let encoder = match solid
                .as_mut()
                .and_then(|link| link.encoder.as_mut())
                .filter(|_| ppmd_filter.is_none())
            {
                Some(SolidEncoder::Rar29(encoder)) => encoder,
                _ => own.insert(Box::new(Unpack29Encoder::with_options(encode_options))),
            };
            match engine {
                StreamedEngine::Lz { filter_search } => encoder.encode_lz_streamed(
                    &mut counted,
                    len,
                    match (named.as_mut(), filter_search) {
                        (Some(named), _) => Some(named),
                        (None, true) => Some(&mut choose),
                        (None, false) => None,
                    },
                    &mut advance,
                    &mut write,
                ),
                StreamedEngine::Ppmd { escapes, size } => encoder.encode_ppmd_streamed(
                    &mut counted,
                    len,
                    escapes,
                    ppmd_filter.cloned(),
                    size,
                    &mut advance,
                    &mut write,
                ),
            }
        }
    }
    .map_err(|error| match counted.ended {
        true => Error::SourceChanged("entry source size changed while compressing"),
        false => map_codec_cancel(error),
    })?;

    if flow.is_continue() {
        crate::write_stream::check_source_length(
            &mut reader,
            unpacked_size,
            unpacked_size,
            "entry source size changed while compressing",
        )?;
        sealed.finish(out)?;
        sizes.file_crc = crc.finish();
        sizes.packed_size = cipher.packed_len(sizes.packed_size)?;
    } else {
        // Storing a member ends the chain, as it does in memory.
        if let Some(link) = solid {
            *link.encoder = Some(SolidEncoder::for_target(options)?);
        }
        out.restart()?;
        let mut crc = Crc32::new();
        let mut source = member.bytes.open()?;
        let mut sealed = Sealed::new(cipher.start()?);
        let mut chunk = vec![0; 64 * 1024];
        let mut copied = 0u64;
        while copied < unpacked_size {
            let want = (unpacked_size - copied).min(chunk.len() as u64) as usize;
            let read = source.read(&mut chunk[..want])?;
            if read == 0 {
                break;
            }
            progress.check()?;
            crc.update(&chunk[..read]);
            sealed.write(out, &chunk[..read])?;
            copied += read as u64;
        }
        crate::write_stream::check_source_length(
            &mut source,
            copied,
            unpacked_size,
            "entry source size changed while writing",
        )?;
        sealed.finish(out)?;
        progress.advance(unpacked_size.saturating_sub(last as u64));
        sizes = HeaderPayload {
            method: 0x30,
            unpacked_size,
            file_crc: crc.finish(),
            packed_size: cipher.packed_len(unpacked_size)?,
        };
    }
    out.finish(sizes)?;
    Ok(sizes.method)
}

/// Samples a streamed RAR 2.0 member codes before it is coded whole.
const RAR20_PROBE_SAMPLES: usize = 4;

/// Whether every sample of a large RAR 2.0 member packs no smaller than it
/// is, so the member would be stored after coding it all.
///
/// Each sample is a dictionary long, so it holds every distance a match could
/// reach and data that repeats at long range still shrinks. They sit at the
/// middle of each quarter, so a compressible stretch after a noisy start is
/// still seen, and the first that shrinks ends the probe. A member under
/// sixteen samples' worth is coded whole, which costs little anyway.
fn rar20_samples_expand(
    member: &Member<'_>,
    len: usize,
    options: WriterOptions,
    progress: &WorkTracker<'_>,
) -> Result<bool> {
    let encode_options = rar20_encode_options_for_options(options)?;
    let sample = encode_options.max_match_distance.max(64 * 1024);
    if len < sample.saturating_mul(4 * RAR20_PROBE_SAMPLES) {
        return Ok(false);
    }
    let mut source = member.bytes.open()?;
    let mut bytes = vec![0; sample];
    let stride = len / RAR20_PROBE_SAMPLES;
    for index in 0..RAR20_PROBE_SAMPLES {
        progress.check()?;
        let start = index * stride + (stride - sample) / 2;
        source.seek(SeekFrom::Start(start as u64))?;
        source
            .read_exact(&mut bytes)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    Error::SourceChanged("entry source size changed while compressing")
                }
                _ => error.into(),
            })?;
        let packed =
            unpack20_encode_auto_with_options_and_progress(&bytes, encode_options, &mut |_| {
                !progress.is_cancelled()
            })
            .map_err(map_codec_cancel)?;
        if packed.len() < bytes.len() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A solid run a streamed member codes on from, and whether its header says so.
struct SolidLink<'a> {
    encoder: &'a mut Option<SolidEncoder>,
    continues: bool,
}

/// Encrypts whole cipher blocks as they arrive and pads the last one.
struct Sealed {
    cipher: Option<volumes::Cipher>,
    pending: Vec<u8>,
}

impl Sealed {
    fn new(cipher: Option<volumes::Cipher>) -> Self {
        Self {
            cipher,
            pending: Vec::new(),
        }
    }

    fn write(&mut self, output: &mut dyn StreamedOut, bytes: &[u8]) -> Result<()> {
        let Some(cipher) = &mut self.cipher else {
            return output.write_packed(bytes);
        };
        self.pending.extend_from_slice(bytes);
        let whole = self.pending.len() & !15;
        cipher.encrypt(&mut self.pending[..whole]);
        output.write_packed(&self.pending[..whole])?;
        self.pending.drain(..whole);
        Ok(())
    }

    fn finish(mut self, output: &mut dyn StreamedOut) -> Result<()> {
        if let Some(cipher) = &mut self.cipher {
            if !self.pending.is_empty() {
                if cipher.pads() {
                    self.pending.resize(16, 0);
                }
                cipher.encrypt(&mut self.pending);
                output.write_packed(&self.pending)?;
            }
        }
        Ok(())
    }
}

/// `ended` tells a source that shrank apart from any other read failure.
struct CrcReader<'a, R: Read + ?Sized> {
    inner: &'a mut R,
    crc: &'a mut Crc32,
    ended: bool,
}

impl<R: Read + ?Sized> Read for CrcReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.ended |= read == 0 && !buffer.is_empty();
        self.crc.update(&buffer[..read]);
        Ok(read)
    }
}

/// Writes one member's header and payload, encrypting either if asked.
#[allow(clippy::too_many_arguments)]
fn write_member(
    output: &mut dyn Write,
    member: &Member<'_>,
    encoded: EncodedMember<'_>,
    options: WriterOptions,
    solid_continuation: bool,
    header_key: Option<&HeaderKey>,
    data_keys: &mut DataKeys,
    progress: Option<ProgressReporter<'_>>,
) -> Result<()> {
    // The member's charge goes once it is written.
    let _held = encoded.held;
    let target = options.target;
    crate::write_progress::check_cancelled(progress)?;
    let (payload, salt) = match encoded.payload {
        MemberPayload::Packed(mut packed) => {
            let salt = encrypt_packed_data_with_progress(
                &mut packed,
                target,
                member.password,
                data_keys,
                progress,
            )?;
            (MemberPayload::Packed(packed), salt)
        }
        copied => (copied, None),
    };
    let cipher = match payload {
        MemberPayload::Copied(_) | MemberPayload::Borrowed(_) if member.password.is_some() => Some(
            volumes::CipherPlan::new(target, member.password, data_keys)?,
        ),
        _ => None,
    };
    let salt = salt.or(cipher.as_ref().and_then(volumes::CipherPlan::salt));
    let packed_size = match &cipher {
        // Padded to the cipher's block, as the in-memory path pads.
        Some(cipher) => cipher.packed_len(encoded.unpacked_size)?,
        None => payload.size(encoded.unpacked_size),
    };
    let header = member_header(
        member,
        options,
        solid_continuation,
        salt,
        HeaderPayload {
            method: encoded.method,
            unpacked_size: encoded.unpacked_size,
            file_crc: encoded.file_crc,
            packed_size,
        },
    )?;
    match header_key {
        Some(key) => write_encrypted_header(output, &header, key)?,
        None => output.write_all(&header)?,
    }
    match cipher {
        Some(cipher) => {
            let mut stream = volumes::PackedStream::open(
                &member.bytes,
                encoded.unpacked_size,
                &cipher,
                progress,
                None,
            )?;
            stream.copy(packed_size, output)?;
            if stream.unpacked_crc() != encoded.file_crc {
                return Err(Error::SourceChanged(
                    "entry source contents changed while writing",
                ));
            }
            Ok(())
        }
        None if matches!(payload, MemberPayload::Copied(_)) => {
            let mut checksum = Crc32::new();
            payload.write_to(
                &mut CrcWriter {
                    inner: output,
                    crc: &mut checksum,
                },
                packed_size,
            )?;
            if checksum.finish() != encoded.file_crc {
                return Err(Error::SourceChanged(
                    "entry source contents changed while writing",
                ));
            }
            Ok(())
        }
        None => payload.write_to(output, packed_size),
    }
}

/// Splits one member across a volume set. No volume is longer than
/// `volume_size` bytes, headers and end-of-archive block included, as RAR's
/// own `-v` switch counts them.
pub fn write_stored_volumes(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    volume_size: usize,
) -> Result<Vec<Vec<u8>>> {
    write_stored_volumes_with_progress(entry, options, None, volume_size, None)
}

pub(crate) fn write_stored_volumes_with_progress(
    entry: StoredEntry<'_>,
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    volume_size: usize,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<Vec<u8>>> {
    let mut sink = crate::volume_sink::CollectedVolumes::new();
    volumes::split_members(
        &[Member::from_stored(&entry)],
        options,
        &MemberCoding::Stored,
        archive_comment,
        volume_size,
        &mut sink,
        &WriterResources::default(),
        progress,
    )?;
    Ok(sink.take())
}

/// Splits one member across a volume set. No volume is longer than
/// `volume_size` bytes, headers and end-of-archive block included, as RAR's
/// own `-v` switch counts them.
pub fn write_compressed_volumes(
    entry: FileEntry<'_>,
    options: WriterOptions,
    volume_size: usize,
) -> Result<Vec<Vec<u8>>> {
    write_compressed_volumes_with_progress(entry, options, volume_size, None)
}

pub fn write_compressed_volumes_with_progress(
    entry: FileEntry<'_>,
    options: WriterOptions,
    volume_size: usize,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<Vec<u8>>> {
    write_compressed_volumes_with_comment_and_progress(entry, options, None, volume_size, progress)
}

pub(crate) fn write_compressed_volumes_with_comment_and_progress(
    entry: FileEntry<'_>,
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    volume_size: usize,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<Vec<u8>>> {
    let mut sink = crate::volume_sink::CollectedVolumes::new();
    volumes::split_members(
        &[Member::from_file(&entry)],
        options,
        &MemberCoding::Compressed,
        archive_comment,
        volume_size,
        &mut sink,
        &WriterResources::default(),
        progress,
    )?;
    Ok(sink.take())
}

/// Writes each volume to `sink` as it fills; a large RAR 2.9-4.x member's packed form is not held.
pub fn write_compressed_volumes_to(
    entry: FileEntry<'_>,
    options: WriterOptions,
    volume_size: usize,
    sink: &mut dyn crate::volume_sink::VolumeSink,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    volumes::split_members(
        &[Member::from_file(&entry)],
        options,
        &MemberCoding::Compressed,
        None,
        volume_size,
        sink,
        &WriterResources::default(),
        progress,
    )
}

fn report_compression_operation(
    progress: &dyn WriteProgress,
    started: bool,
    total_bytes: u64,
    total_entries: usize,
) {
    if started {
        progress.report(WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Compression,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass: 1,
        });
    } else {
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Compression,
            total_bytes: Some(total_bytes),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
}

/// Everything this writer refuses, in one place, before anything is written.
///
/// The three near-identical checks this replaced each built a set of allowed
/// features out of the target and the request together, compared it with the
/// request, and on a mismatch said only that some feature was unsupported.
fn validate_plan(
    options: WriterOptions,
    shape: PlanShape,
    has_archive_comment: bool,
    has_file_comment: bool,
) -> Result<()> {
    if options.archive_comment_metadata.is_some()
        && (!has_archive_comment || uses_old_style_archive_comment(options.target))
    {
        return Err(Error::InvalidArgument(
            "retained archive comment metadata requires a CMT archive comment",
        ));
    }
    if options.target.family() != crate::version::ArchiveFamily::Rar15To40 {
        return Err(Error::UnsupportedVersion(options.target));
    }
    crate::write_plan::validate_features(options.target, options.features, shape)?;
    crate::write_plan::validate_compression_level(options.target, options.compression_level)?;
    if options.method == Rar29Method::Ppmd {
        crate::write_plan::validate_option(options.target, WriterOption::CompressionMethod, shape)?;
    }
    // A filter policy routes the member through the RAR 2.9 engine, so the
    // formats without one have to be turned away here. This used to be
    // computed into the shape and then never asked about, which let RAR 1.5
    // accept a policy and write an archive that failed its own checksum.
    if shape.filtered {
        crate::write_plan::validate_option(options.target, WriterOption::Filter, shape)?;
    }
    let _ = dictionary_flags_for_options(options)?;
    if has_archive_comment {
        crate::write_plan::validate_option(options.target, WriterOption::ArchiveComment, shape)?;
    }
    if has_file_comment {
        crate::write_plan::validate_option(options.target, WriterOption::FileComment, shape)?;
    }
    Ok(())
}

/// Cross-flag rules: relations between options rather than per-option
/// capability, so they are checked after the capability table has had its say.
fn validate_header_encrypted_archive_options(
    target: ArchiveVersion,
    has_password: bool,
) -> Result<()> {
    if !has_password {
        return Err(Error::UnsupportedWriterOption {
            target,
            option: WriterOption::Feature(crate::Feature::HeaderEncryption),
            because: Some("without a password"),
        });
    }
    Ok(())
}

/// RAR 2.9 levels, as the LZ parse each one runs.
///
/// Each level parses at least as well as the one below. Measured on the bench
/// corpus's 4 MiB classes through LZ alone, no filter, packed bytes:
///
/// ```text
/// parse                    stripped ELF  unstripped ELF  man pages  source tar
/// greedy, 8 candidates        1,887,716       1,627,511    757,447     811,633
/// greedy, 32                  1,864,334       1,610,547    720,161     757,785
/// lazy, 16                    1,822,607       1,545,989    709,905     755,377
/// lazy, 64                    1,805,783       1,534,280    688,069     720,524
/// lazy, 128                   1,800,583       1,531,317    682,125     709,487
/// shortest path, 64, 1 pass   1,743,620       1,438,006    649,359     666,108
/// shortest path, 128, 3       1,727,188       1,411,736    642,330     655,801
/// ```
///
/// Lazy matching is worth 3-4% for well under a tenth more time, so it starts
/// at level 2. Greedy past eight candidates was the old level 2, and it lost
/// to level 1 on long repeats: the deeper search found a far match that scored
/// better than the repeat offset it displaced, and paid for it on every period
/// after. The shortest-path parse is worth another 3-7% and costs four to six
/// times the lazy parse, so it takes the top two levels, which differ in how
/// far they search and how often they re-price.
///
/// An absent level keeps the lazy parse at 128 candidates the writer has
/// always used, rather than paying for level 5's.
fn rar29_encode_options_for_level(level: Option<u8>) -> Result<Rar29EncodeOptions> {
    let options = match level {
        None => Rar29EncodeOptions::new(128).with_lazy_matching(true),
        Some(0) => Rar29EncodeOptions::new(0),
        Some(1) => Rar29EncodeOptions::new(8),
        Some(2) => Rar29EncodeOptions::new(16).with_lazy_matching(true),
        Some(3) => Rar29EncodeOptions::new(64).with_lazy_matching(true),
        Some(4) => Rar29EncodeOptions::new(64)
            .with_lazy_matching(true)
            .with_optimal_parse_passes(1),
        Some(5) => Rar29EncodeOptions::new(128)
            .with_lazy_matching(true)
            .with_optimal_parse_passes(3),
        Some(_) => {
            return Err(Error::InvalidArgument(
                "RAR compression level must be in the range 0..5",
            ))
        }
    };
    // Level 1 is the fast one and keeps one table per block.
    let split_blocks = level.is_none_or(|level| level >= 2);
    Ok(options
        .with_lazy_lookahead(1)
        .with_block_size(RAR29_LZ_BLOCK_SIZE)
        .with_split_blocks(split_blocks))
}

fn rar29_encode_options_for_options(options: WriterOptions) -> Result<Rar29EncodeOptions> {
    Ok(rar29_encode_options_for_level(options.compression_level)?
        .with_max_match_distance(dictionary_size_for_options(options)?))
}

/// RAR 2.0 levels, as candidates searched per position.
///
/// Each level searches more than the one below. Measured on 4 MiB of man
/// pages, packed bytes and seconds:
///
/// ```text
/// candidates       16       64      256      512     1024
/// lazy off    937,906  878,958  848,790  840,496  835,622
/// lazy on     886,854  837,531  813,252  806,728  803,006
/// seconds        2.37     4.41     8.67    12.78    17.43
/// ```
///
/// It is worth 4% on text and 3% on a stripped binary, at every count, for
/// about half again the time. Candidates cost more and give less: the last
/// doubling buys 0.5%. So lazy matching is on wherever anything is compressed,
/// and the level chooses how far to search.
fn rar20_encode_options_for_level(level: Option<u8>) -> Result<Rar20EncodeOptions> {
    let level = level.unwrap_or(RAR20_DEFAULT_LEVEL);
    let candidates = match level {
        0 => return Ok(Rar20EncodeOptions::new(0)),
        1 => 16,
        2 => 64,
        3 => 256,
        // Level 5 searches no further than 4. Under the shortest-path parse
        // 1,024 candidates packed larger than 512 on every 4 MiB class of the
        // bench and on its small binaries, so level 5 came out larger than
        // level 4. It spends its time on more priced passes instead, which
        // start from level 4's result and are kept only when smaller.
        4 | 5 => 512,
        _ => {
            return Err(Error::InvalidArgument(
                "RAR compression level must be in the range 0..5",
            ))
        }
    };
    Ok(Rar20EncodeOptions::new(candidates)
        .with_lazy_matching(true)
        // Look two positions ahead before committing to a match, not one. The
        // class this moves is downloads: docx, jpeg, png, gif, a ZX Spectrum
        // snapshot. High-entropy bytes with occasional short matches, where a
        // three byte match often costs more than the literal it replaces and
        // the better match starts two bytes later. Depth 1 cannot see that far.
        // Measured on the small corpus, packed bytes:
        //
        // ```text
        // depth        1        2        3        4
        // total  657,072  654,162  656,242  659,161
        // ```
        //
        // Worth 0.44% at every level for about a third more encode time. Depth
        // 3 and 4 give it back: on text, deferring that long skips matches
        // worth taking.
        .with_lazy_lookahead(2)
        // The shortest-path parse is worth another 1.5% and costs four times
        // the encode time, so it goes where the ladder already means "spend
        // whatever it takes". rar29 gates its lazy matching at the same rung.
        .with_optimal_parse(level >= 4)
        .with_extra_priced_passes(if level == 5 { 2 } else { 0 })
        // The audio trial is a second encode of the member, which is the one
        // thing level 1 is trying not to pay for.
        .with_try_audio(level > 1))
}

fn rar20_encode_options_for_options(options: WriterOptions) -> Result<Rar20EncodeOptions> {
    Ok(rar20_encode_options_for_level(options.compression_level)?
        .with_max_match_distance(dictionary_size_for_options(options)?))
}

fn rar15_encode_options_for_level(level: Option<u8>) -> Result<Rar15EncodeOptions> {
    let level = level.unwrap_or(5);
    match level {
        0 => Ok(Rar15EncodeOptions::new()
            .with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(0)),
        1 => Ok(Rar15EncodeOptions::new()
            .with_old_distance_tokens(false)
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(4 * 1024)),
        2 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_stmode_literal_runs(false)
            .with_max_long_match_distance(8 * 1024)),
        3 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(16 * 1024)),
        4 => Ok(Rar15EncodeOptions::new()
            .with_lazy_matching(false)
            .with_max_long_match_distance(24 * 1024)),
        5 => Ok(Rar15EncodeOptions::new().with_lazy_matching(false)),
        _ => Err(Error::InvalidArgument(
            "RAR compression level must be in the range 0..5",
        )),
    }
}

/// The smallest and largest dictionary worth declaring for a target.
///
/// RAR 1.5 and older ignore the field: their decoders have a fixed window, and
/// measuring confirms the packed size does not move with it, so those stay
/// pinned. WinRAR 1.54 writes 64K in every archive we have from it.
fn dictionary_range(target: ArchiveVersion) -> (usize, usize) {
    match target {
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
            (128 * 1024, RAR29_MAX_DICTIONARY_SIZE)
        }
        ArchiveVersion::Rar20 => (64 * 1024, RAR29_MAX_DICTIONARY_SIZE),
        _ => (64 * 1024, 64 * 1024),
    }
}

/// The smallest dictionary the format encodes that reaches past `content`, so a
/// match can span everything the window is meant to cover.
///
/// Picking one number for every archive is the wrong shape: too small loses
/// half the ratio on content whose repeats sit far apart, and too large costs a
/// decoder memory it never needs for a thirty byte file. WinRAR sizes it to the
/// data, and reading the dictionary bits out of its own archives against their
/// largest member shows exactly this rule:
///
/// ```text
/// content   130048   196608   262144   705644   1048576
/// declared    128K     256K     512K    1024K     2048K
/// ```
fn fitted_dictionary_size(target: ArchiveVersion, content: u64) -> usize {
    let (floor, cap) = dictionary_range(target);
    // A test caps the window on its own thread, so a member crosses a
    // segment of the streamed parse without coding 16 MiB in a debug build.
    #[cfg(test)]
    let cap = cap.min(builder_path_tests::DICTIONARY_CAP.get());
    let mut size = floor;
    while size < cap && size as u64 <= content {
        size *= 2;
    }
    size
}

fn rar29_default_dictionary_size(target: ArchiveVersion) -> usize {
    match target {
        ArchiveVersion::Rar29 => 1024 * 1024,
        ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => 128 * 1024,
        _ => 64 * 1024,
    }
}

fn dictionary_size_for_options(options: WriterOptions) -> Result<usize> {
    options
        .dictionary_size
        .map(Ok)
        .unwrap_or_else(|| Ok(rar29_default_dictionary_size(options.target)))
}

fn dictionary_flags_for_options(options: WriterOptions) -> Result<u16> {
    dictionary_flags_for_size(dictionary_size_for_options(options)?)
}

fn dictionary_flags_for_size(size: usize) -> Result<u16> {
    let bits =
        match size {
            0x1_0000 => 0,
            0x2_0000 => 1,
            0x4_0000 => 2,
            0x8_0000 => 3,
            0x10_0000 => 4,
            0x20_0000 => 5,
            0x40_0000 => 6,
            _ => return Err(Error::InvalidArgument(
                "RAR 1.5-4.x dictionary size must be one of 64K, 128K, 256K, 512K, 1M, 2M, or 4M",
            )),
        };
    Ok((bits as u16) << 5)
}

// Callers have passed `validate_plan`, including compression-level validation.
/// Whether a solid chain is running once this member is written, so the next
/// compressed one is flagged as continuing it.
///
/// Storing a member rebuilds the encoder, so the chain ends there. An empty
/// member that the encoder wrote nothing for leaves the chain as it was:
/// readers pass over an empty payload without advancing their decoder.
/// RAR 2.9 does code an empty member, though, and its bytes move the encoder
/// on, so like RAR's own writer the member after it continues the chain.
/// Flagging that member as a fresh start sent it as a continuation of tables
/// no reader had, whenever the empty member was the first in the chain.
pub(super) fn solid_chain_runs_on(
    running: bool,
    is_directory: bool,
    method: u8,
    unpacked_size: u64,
    wrote_bytes: bool,
) -> bool {
    if is_directory {
        running
    } else if method == 0x30 {
        false
    } else {
        running || unpacked_size != 0 || wrote_bytes
    }
}

fn compression_method_for_level(options: WriterOptions) -> u8 {
    let Some(level) = options.compression_level else {
        return 0x33;
    };
    0x30 + level
}

enum SolidEncoder {
    Rar15(Box<Unpack15Encoder>),
    Rar20(Unpack20Encoder),
    Rar29(Box<Unpack29Encoder>),
}

impl SolidEncoder {
    fn for_target(options: WriterOptions) -> Result<Self> {
        let encoder = match options.target {
            ArchiveVersion::Rar15 => Self::Rar15(Box::new(Unpack15Encoder::with_options(
                rar15_encode_options_for_level(options.compression_level)?,
            ))),
            ArchiveVersion::Rar20 => Self::Rar20(Unpack20Encoder::with_options(
                rar20_encode_options_for_options(options)?,
            )),
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
                Self::Rar29(Box::new(
                    Unpack29Encoder::with_options(rar29_encode_options_for_options(options)?)
                        .with_ppmd_sizes(ppmd_models_for_options(options)),
                ))
            }
            _ => return Err(Error::UnsupportedVersion(options.target)),
        };
        Ok(encoder)
    }

    /// The encoder a solid run starts with, its PPMd model already chosen.
    ///
    /// A chain keeps the model its first PPMd member starts, so a chain that
    /// let that member pick the model kept whatever suited the member: on the
    /// bench's logs the largest model coded the first file smallest and the
    /// whole run 23 bytes larger than the level below. So the start of the run,
    /// up to [`CHAIN_PPMD_TRIAL_BYTES`], is coded once under each model the
    /// level tries, and the run keeps the model that coded it smallest, earlier
    /// on a tie. A run that fits is coded exactly as its winner was, so a level
    /// that tries more models can't pack it larger. A run that starts with a
    /// member that size or larger leaves the choice to that member, which is
    /// the same choice, and so does a run with only one model to try.
    fn for_chain(
        members: &[Member<'_>],
        options: WriterOptions,
        coding: &MemberCoding,
        stream_above: Option<u64>,
        resources: &WriterResources,
        progress: &WorkTracker<'_>,
    ) -> Result<Self> {
        let encoder = Self::for_target(options)?;
        let models = ppmd_models_for_options(options);
        let codes_ppmd = options.method == Rar29Method::Ppmd || trials_engines(options);
        if !matches!(encoder, Self::Rar29(_))
            || models.len() < 2
            || !codes_ppmd
            || !coding.compresses()
        {
            return Ok(encoder);
        }
        let mut trial = 0usize;
        let mut trial_bytes = 0u64;
        for member in members {
            let streams = match stream_above {
                Some(above) => streams_member(member, options, coding, above)?,
                None => false,
            };
            let len = member.unpacked_size()?;
            if streams || trial_bytes >= CHAIN_PPMD_TRIAL_BYTES || len >= CHAIN_PPMD_TRIAL_BYTES {
                break;
            }
            trial_bytes += len;
            trial += 1;
        }
        if trial < 2 {
            return Ok(encoder);
        }
        // The trial's coding is thrown away, so it moves no progress bar, but
        // cancelling still stops it.
        struct CancelOnly<'a>(Option<ProgressReporter<'a>>);
        impl WriteProgress for CancelOnly<'_> {
            fn report(&self, _event: WriteProgressEvent<'_>) {}
            fn is_cancelled(&self) -> bool {
                self.0.is_some_and(ProgressReporter::is_cancelled)
            }
        }
        let quiet = CancelOnly(progress.reporter());
        let quiet = WorkTracker::new(
            Some(ProgressReporter(&quiet)),
            WriteOperation::Compression,
            u64::MAX,
        );
        let mut best: Option<(u64, usize)> = None;
        for index in 0..models.len() {
            let mut chain = Some(Self::Rar29(Box::new(
                Unpack29Encoder::with_options(rar29_encode_options_for_options(options)?)
                    .with_ppmd_sizes(&models[index..=index]),
            )));
            let mut packed = 0u64;
            for member in &members[..trial] {
                let encoded = encode_member(member, options, coding, &mut chain, resources, &quiet)
                    .map_err(|error| {
                        crate::write_stream::member_error(error, member.name, "preparing")
                    })?;
                packed += encoded.payload.size(encoded.unpacked_size);
            }
            if best.is_none_or(|(smallest, _)| packed < smallest) {
                best = Some((packed, index));
            }
            // A run no member of which went PPMd codes the same under any model.
            let ppmd = matches!(&chain, Some(Self::Rar29(chain)) if chain.has_ppmd_model());
            if index == 0 && !ppmd {
                return Ok(encoder);
            }
        }
        let index = best.map_or(0, |(_, index)| index);
        Ok(Self::Rar29(Box::new(
            Unpack29Encoder::with_options(rar29_encode_options_for_options(options)?)
                .with_ppmd_sizes(&models[index..=index]),
        )))
    }
}

/// How much of a solid run [`SolidEncoder::for_chain`] codes under each PPMd model.
const CHAIN_PPMD_TRIAL_BYTES: u64 = 1024 * 1024;

struct EncodedPayload {
    data: Vec<u8>,
    method: u8,
}

/// Codes a filtered member, continuing the solid chain when there is one.
///
/// A filtered member used to be coded on its own whatever the archive said,
/// while its header still claimed to continue the chain. That cost the whole
/// benefit of `--solid`: three 400 KB members went from 550 KB to 1.2 MB, and
/// the flag on the members was a plain lie about how they had been coded.
fn encode_filtered_payload(
    data: &[u8],
    policy: &FilterPolicy,
    options: WriterOptions,
    solid_encoder: &mut Option<SolidEncoder>,
    progress: Option<&WorkTracker<'_>>,
    resources: Option<&WriterResources>,
) -> Result<EncodedPayload> {
    let lz_method = compression_method_for_level(options);
    // A named filter under forced PPMd is the one request the chain cannot
    // take: its PPMd side codes no filters, and coding the member LZ instead
    // would quietly overrule a flag the caller set.
    let forced_ppmd_filter =
        options.method == Rar29Method::Ppmd && matches!(policy, FilterPolicy::Explicit(_));
    let encoder = match (
        lz_method != 0x30 && !forced_ppmd_filter,
        solid_encoder.as_mut(),
    ) {
        (true, Some(SolidEncoder::Rar29(encoder))) => encoder,
        _ => {
            let payload = encode_rar29_policy_filtered_payload(
                data,
                policy,
                options.method,
                rar29_encode_options_for_options(options)?,
                lz_method,
                ppmd_trial_pays(lz_method.saturating_sub(0x30)),
                progress,
                resources,
            )?;
            return stored_unless_smaller(data, payload, options, solid_encoder);
        }
    };

    // An empty member has no range to filter, and `--no-filter` asked for none,
    // but both still go through the chain's encoder like any other member.
    // Coding either one on its own would leave the encoder's history in place
    // while the headers said the chain had ended, so the member after it would
    // be coded against a dictionary its own flags told the decoder to discard.
    let mut last = 0usize;
    let mut advance = |position: usize| {
        let delta = position.saturating_sub(last);
        last = last.max(position);
        progress.is_none_or(|work| work.advance(delta as u64))
    };
    let packed = match policy {
        FilterPolicy::Explicit(filter) if !data.is_empty() => encoder
            .encode_member_with_filters_and_progress(
                data,
                std::slice::from_ref(filter),
                Some(&mut advance),
            )
            .map_err(map_codec_cancel)?,
        // Naming a filter, or none, says nothing about which engine should code
        // the member. `--no-filter` used to answer that question too, and answer
        // it LZ, so asking a solid archive not to filter its binaries also took
        // PPMd away from its text.
        FilterPolicy::Explicit(_) | FilterPolicy::None => {
            encode_rar29_chain_member(data, options, encoder, false, &mut advance)?
        }
        FilterPolicy::Auto => {
            encode_rar29_chain_member(data, options, encoder, true, &mut advance)?
        }
    };

    stored_unless_smaller(
        data,
        EncodedPayload {
            data: packed,
            method: lz_method,
        },
        options,
        solid_encoder,
    )
}

/// Stores a member its coding did not shrink, filtered or not, as the
/// streamed writer does once the packed bytes reach the member's size.
///
/// In a chain this rebuilds the encoder, so the chain ends here and the member
/// after it starts a new one.
fn stored_unless_smaller(
    data: &[u8],
    payload: EncodedPayload,
    options: WriterOptions,
    solid_encoder: &mut Option<SolidEncoder>,
) -> Result<EncodedPayload> {
    let solid = solid_encoder.is_some();
    if payload.method == 0x30
        || !should_store_fallback(options.target, solid, data.len(), payload.data.len())
    {
        return Ok(payload);
    }
    if solid {
        *solid_encoder = Some(SolidEncoder::for_target(options)?);
    }
    Ok(EncodedPayload {
        data: data.to_vec(),
        method: 0x30,
    })
}

fn encode_or_store_payload(
    data: &[u8],
    options: WriterOptions,
    solid_encoder: &mut Option<SolidEncoder>,
    progress: Option<&WorkTracker<'_>>,
    resources: Option<&WriterResources>,
) -> Result<EncodedPayload> {
    let target = options.target;
    if options.compression_level == Some(0) {
        return Ok(EncodedPayload {
            data: data.to_vec(),
            method: 0x30,
        });
    }
    let solid = solid_encoder.is_some();
    if !solid
        && matches!(
            target,
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
        )
    {
        let encode_options = rar29_encode_options_for_options(options)?;
        let lz_method = compression_method_for_level(options);
        // Forcing PPMd leaves nothing for a filter search to measure against.
        let policy = if options.method == Rar29Method::Ppmd {
            FilterPolicy::None
        } else {
            FilterPolicy::Auto
        };
        let payload = encode_rar29_policy_filtered_payload(
            data,
            &policy,
            options.method,
            encode_options,
            lz_method,
            ppmd_trial_pays(lz_method.saturating_sub(0x30)),
            progress,
            resources,
        )?;
        return stored_unless_smaller(data, payload, options, solid_encoder);
    }
    let compressed = encode_compressed_payload(data, options, solid_encoder.as_mut(), progress)?;
    stored_unless_smaller(
        data,
        EncodedPayload {
            data: compressed,
            method: compression_method_for_level(options),
        },
        options,
        solid_encoder,
    )
}

/// Codes one member into a RAR 2.9 solid chain, choosing both the engine and,
/// on the LZ side, the filter.
///
/// The engine question and the filter question meet here because they are
/// asked of the same member and only one answer gets written. In practice they
/// barely overlap: the filter search declines text and the PPMd trial only
/// wants text, so a member that reaches one usually walks past the other. That
/// is a fact about the two screens rather than a rule, so the trials are
/// measured against each other rather than sequenced on the assumption.
///
/// `search` is off for a caller who named a filter or asked for none, and for
/// PPMd, which leaves nothing for a filter to be measured through.
fn encode_rar29_chain_member(
    data: &[u8],
    options: WriterOptions,
    encoder: &mut Unpack29Encoder,
    search: bool,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    // A chain used to be LZ and nothing else, so a solid archive got no PPMd at
    // all and an explicit --method ppmd was quietly ignored. It is the same
    // content question here as in a non-solid archive, so it gets the same
    // answer and the same gate: a level willing to encode the member twice, and
    // content that looks like PPMd will win on it.
    let level = compression_method_for_level(options).saturating_sub(0x30);
    let engine = match options.method {
        Rar29Method::Lz => ChainEngine::Lz,
        Rar29Method::Ppmd => ChainEngine::Ppmd,
        Rar29Method::Auto if ppmd_trial_pays(level) && is_text_ppmd_candidate(data) => {
            ChainEngine::Smaller
        }
        Rar29Method::Auto => ChainEngine::Lz,
    };
    let candidates =
        if search && engine != ChainEngine::Ppmd && crate::filter_search::search_applies(data) {
            crate::filter_search::filter_candidates(
                &Rar29Search,
                data,
                rar29_encode_options_for_options(options)?,
            )?
        } else {
            Vec::new()
        };
    encoder
        .encode_member_with_engine(data, engine, &candidates, progress)
        .map_err(map_codec_cancel)
}

fn encode_compressed_payload(
    data: &[u8],
    options: WriterOptions,
    solid_encoder: Option<&mut SolidEncoder>,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<u8>> {
    let target = options.target;
    let mut last = 0usize;
    let mut advance = |position: usize| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        progress.is_none_or(|progress| progress.advance(delta as u64))
    };
    // Non-solid RAR 2.9 members take the policy path in
    // encode_or_store_payload before reaching this solid-chain encoder.
    match (target, solid_encoder) {
        (ArchiveVersion::Rar15, Some(SolidEncoder::Rar15(encoder))) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        (ArchiveVersion::Rar15, None) => unpack15_encode_with_options_and_progress(
            data,
            rar15_encode_options_for_level(options.compression_level)?,
            &mut advance,
        )
        .map_err(map_codec_cancel),
        (ArchiveVersion::Rar20, None) => unpack20_encode_auto_with_options_and_progress(
            data,
            rar20_encode_options_for_options(options)?,
            &mut advance,
        )
        .map_err(map_codec_cancel),
        (ArchiveVersion::Rar20, Some(SolidEncoder::Rar20(encoder))) => encoder
            .encode_member_with_progress(data, &mut advance)
            .map_err(map_codec_cancel),
        (
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40,
            Some(SolidEncoder::Rar29(encoder)),
        ) => encode_rar29_chain_member(data, options, encoder, true, &mut advance),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

fn map_codec_cancel(error: crate::codec::Error) -> Error {
    if error == crate::codec::Error::Cancelled {
        Error::Cancelled
    } else {
        Error::from(error)
    }
}

fn with_codec_progress(
    progress: Option<&WorkTracker<'_>>,
    encode: impl FnOnce(&mut dyn FnMut(usize) -> bool) -> crate::codec::Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    if let Some(work) = progress {
        work.check()?;
    }
    let mut last = 0usize;
    let result = encode(&mut |position| {
        if position < last {
            last = 0;
        }
        let delta = position.saturating_sub(last);
        last = position;
        progress.is_none_or(|work| work.advance(delta as u64))
    })
    .map_err(map_codec_cancel)?;
    if let Some(work) = progress {
        work.check()?;
    }
    Ok(result)
}

fn should_store_fallback(
    target: ArchiveVersion,
    solid: bool,
    unpacked_len: usize,
    packed_len: usize,
) -> bool {
    // RAR 2.0 onwards store any member compression did not help. RAR 1.5 pays
    // more header for a stored member, so a small one stays compressed.
    let stores_any_size = !solid
        && matches!(
            target,
            ArchiveVersion::Rar20
                | ArchiveVersion::Rar29
                | ArchiveVersion::Rar30
                | ArchiveVersion::Rar40
        );
    // Storing a member part way through a solid run rebuilds the encoder, so
    // the member after it has to say it starts a fresh chain. Only RAR 2.0
    // onwards can: RAR 1.5 file headers have no solid bit, and readers take
    // every member of a solid RAR 1.5 archive as a continuation whatever the
    // header says. Breaking the chain there writes an archive nothing can read.
    crate::write_plan::StoreFallback::new()
        .allow_solid(target != ArchiveVersion::Rar15)
        .min_size(if stores_any_size {
            0
        } else {
            MIN_STORE_FALLBACK_SIZE
        })
        .applies(solid, unpacked_len, packed_len)
}

fn writer_file_flags(
    password: Option<&[u8]>,
    file_comment: Option<&[u8]>,
    solid_continuation: bool,
) -> u16 {
    let mut flags = 0;
    if password.is_some() {
        flags |= FHD_PASSWORD;
    }
    if file_comment.is_some() {
        flags |= FHD_COMMENT;
    }
    if solid_continuation {
        flags |= FHD_SOLID;
    }
    flags
}

/// Builds the comment block that goes inside a file header.
///
/// RAR 1.3 and 1.4 wrote a bare size and the text, and this writer used to copy
/// that. From 1.5 on it is the same comment block the archive comment uses,
/// covered by the file header's size but not by its CRC.
fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_comment_header(&mut out, comment)?;
    Ok(out)
}

fn header_encryption_password<'a>(
    mut passwords: impl Iterator<Item = Option<&'a [u8]>>,
) -> Result<&'a [u8]> {
    let first = passwords.next().flatten().ok_or(Error::NeedPassword)?;
    for password in passwords {
        if password != Some(first) {
            return Err(Error::InvalidArgument(
                "RAR 3.x header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

fn encrypt_packed_data_for_writer(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: Option<&[u8]>,
    keys: &mut DataKeys,
) -> Result<Option<[u8; 8]>> {
    encrypt_packed_data_with_progress(data, target, password, keys, None)
}

fn encrypt_packed_data_with_progress(
    data: &mut Vec<u8>,
    target: ArchiveVersion,
    password: Option<&[u8]>,
    keys: &mut DataKeys,
    progress: Option<ProgressReporter<'_>>,
) -> Result<Option<[u8; 8]>> {
    #[cfg(not(feature = "encryption"))]
    {
        let _ = (data, target, keys);
        crate::write_progress::check_cancelled(progress)?;
        if password.is_none() {
            Ok(None)
        } else {
            Err(Error::FeatureDisabled {
                feature: "encryption",
            })
        }
    }
    #[cfg(feature = "encryption")]
    {
        crate::write_progress::check_cancelled(progress)?;
        let Some(password) = password else {
            return Ok(None);
        };
        match target {
            ArchiveVersion::Rar15 => {
                let mut cipher = Rar15Cipher::new(password);
                for chunk in data.chunks_mut(64 * 1024) {
                    crate::write_progress::check_cancelled(progress)?;
                    cipher.crypt_in_place(chunk);
                }
                Ok(None)
            }
            ArchiveVersion::Rar20 => {
                let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)
                    .expect("byte vector length plus padding fits usize");
                data.resize(padded_len, 0);
                let mut cipher = Rar20Cipher::new(password);
                for chunk in data.chunks_mut(64 * 1024) {
                    crate::write_progress::check_cancelled(progress)?;
                    cipher
                        .encrypt_in_place(chunk)
                        .expect("padded ciphertext and 64 KiB chunks are block aligned");
                }
                Ok(None)
            }
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
                let (salt, mut cipher) = keys.rar30(password)?;
                // Byte vectors are bounded by isize::MAX, so adding 15 fits usize.
                let padded_len = checked_align16(data.len(), RAR15_ALIGN_OVERFLOW)
                    .expect("byte vector length plus padding fits usize");
                data.resize(padded_len, 0);
                for chunk in data.chunks_mut(64 * 1024) {
                    crate::write_progress::check_cancelled(progress)?;
                    cipher
                        .encrypt_in_place(chunk)
                        .expect("padded ciphertext and 64 KiB chunks are block aligned");
                }
                Ok(Some(salt))
            }
            _ => Err(Error::UnsupportedFeature {
                version: target,
                feature: "RAR writer file encryption",
            }),
        }
    }
}

#[cfg(feature = "encryption")]
fn random_rar30_salt() -> Result<[u8; 8]> {
    let mut salt = [0; 8];
    crate::write_stream::fill_entropy(
        &mut salt,
        "RAR 3.x writer could not generate encryption salt",
    )?;
    Ok(salt)
}

#[cfg(feature = "encryption")]
fn salted_rar30_cipher(password: &[u8]) -> Result<([u8; 8], Rar30Cipher)> {
    let salt = random_rar30_salt()?;
    let cipher = Rar30Cipher::new(password, Some(salt)).map_err(super::map_rar30_crypto_error)?;
    Ok((salt, cipher))
}

/// One data salt per password across a write and its volumes, as RAR does.
#[derive(Default)]
struct DataKeys {
    #[cfg(feature = "encryption")]
    derived: Vec<(zeroize::Zeroizing<Vec<u8>>, [u8; 8], Rar30Cipher)>,
}

#[cfg(feature = "encryption")]
impl DataKeys {
    /// A clone, so every member restarts the CBC chain at the derived IV.
    fn rar30(&mut self, password: &[u8]) -> Result<([u8; 8], Rar30Cipher)> {
        if let Some((_, salt, cipher)) = self
            .derived
            .iter()
            .find(|(known, ..)| known.as_slice() == password)
        {
            return Ok((*salt, cipher.clone()));
        }
        let (salt, cipher) = salted_rar30_cipher(password)?;
        self.derived.push((
            zeroize::Zeroizing::new(password.to_vec()),
            salt,
            cipher.clone(),
        ));
        Ok((salt, cipher))
    }
}

/// Every encrypted header shares one salt, apart from the data salt, as RAR does.
struct HeaderKey {
    #[cfg(feature = "encryption")]
    salt: [u8; 8],
    #[cfg(feature = "encryption")]
    cipher: Rar30Cipher,
}

impl HeaderKey {
    fn derive(password: &[u8]) -> Result<Self> {
        #[cfg(not(feature = "encryption"))]
        {
            let _ = password;
            Err(Error::FeatureDisabled {
                feature: "encryption",
            })
        }
        #[cfg(feature = "encryption")]
        {
            let (salt, cipher) = salted_rar30_cipher(password)?;
            Ok(Self { salt, cipher })
        }
    }
}

/// What WinRAR writes on an end-of-archive block. The bit marks the block as
/// one a reader may skip without understanding it.
const ENDARC_FLAGS: u16 = 0x4000;
/// Set on every volume but the last, so a reader knows another follows.
const EARC_NEXT_VOLUME: u16 = 0x0001;
const END_HEADER_SIZE: usize = 7;

/// RAR 3.00 beta 2, the first build writing the 2.9 format, closes with this block; 2.90 did not.
fn writes_end_block(target: ArchiveVersion) -> bool {
    matches!(
        target,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
    )
}

fn volume_end_flags(more_volumes: bool) -> u16 {
    if more_volumes {
        ENDARC_FLAGS | EARC_NEXT_VOLUME
    } else {
        ENDARC_FLAGS
    }
}

/// Set when a volume's end block carries the CRC32 of the bytes before it.
const EARC_DATACRC: u16 = 0x0002;
/// Set when seven reserved bytes follow, room recovery volumes can use.
const EARC_REVSPACE: u16 = 0x0004;
/// Set when a volume's end block records its place in the set.
const EARC_VOLNUMBER: u16 = 0x0008;

/// The end block RAR 3.93 writes on every volume: the CRC32 of every byte
/// before the block (before its salt, under encrypted headers), the volume's
/// number from 0, and seven reserved bytes. The number lets a reader tell a
/// swapped or renamed volume. RAR 3.93 refuses an encrypted end block with the
/// number but without the other two, so all three go in.
fn volume_end_block(index: u64, more_volumes: bool, data_crc: u32) -> Vec<u8> {
    let size = END_HEADER_SIZE + 13;
    let mut header = Vec::with_capacity(size);
    header.extend_from_slice(&0u16.to_le_bytes());
    header.push(ENDARC_HEAD);
    let flags = volume_end_flags(more_volumes) | EARC_DATACRC | EARC_REVSPACE | EARC_VOLNUMBER;
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&(size as u16).to_le_bytes());
    header.extend_from_slice(&data_crc.to_le_bytes());
    // A 16-bit field, so a set past 65,536 volumes counts round again.
    header.extend_from_slice(&(index as u16).to_le_bytes());
    header.extend_from_slice(&[0; 7]);
    write_header_crc(&mut header, 0);
    header
}

fn end_block(flags: u16) -> [u8; END_HEADER_SIZE] {
    let mut header = Vec::with_capacity(END_HEADER_SIZE);
    header.extend_from_slice(&0u16.to_le_bytes());
    header.push(ENDARC_HEAD);
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&(END_HEADER_SIZE as u16).to_le_bytes());
    write_header_crc(&mut header, 0);
    header.try_into().expect("end block is seven bytes")
}

fn write_main_header(out: &mut Vec<u8>, flags: u16) {
    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(MAIN_HEAD);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&13u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    write_header_crc(out, start);
}

fn write_comment_header(out: &mut Vec<u8>, comment: Option<&[u8]>) -> Result<()> {
    let Some(comment) = comment else {
        return Ok(());
    };
    let unp_size = u16::try_from(comment.len())
        .map_err(|_| Error::InvalidArgument("RAR 1.5 comment is longer than 65535 bytes"))?;
    let head_size = 13usize
        .checked_add(comment.len())
        .ok_or(Error::InvalidArgument(
            "RAR 1.5 comment header size overflows",
        ))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidArgument("RAR 1.5 comment header size overflows"))?;

    let start = out.len();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(COMM_HEAD);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&unp_size.to_le_bytes());
    out.push(15);
    out.push(0x30);
    out.extend_from_slice(&((crc32(comment) & 0xffff) as u16).to_le_bytes());
    out.extend_from_slice(comment);
    write_comment_header_crc(out, start);
    Ok(())
}

// Archive-level advisory metadata: header encryption does not conceal its payload.
fn write_producer(
    out: &mut dyn Write,
    target: ArchiveVersion,
    header_key: Option<&HeaderKey>,
    progress: Option<ProgressReporter<'_>>,
) -> Result<()> {
    crate::write_progress::check_cancelled(progress)?;
    if !matches!(
        target,
        ArchiveVersion::Rar15
            | ArchiveVersion::Rar20
            | ArchiveVersion::Rar29
            | ArchiveVersion::Rar30
            | ArchiveVersion::Rar40
    ) {
        return Ok(());
    }
    let data = crate::producer::DATA;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: NEWSUB_HEAD,
            name: crate::producer::NAME,
            unpacked_size: data.len() as u64,
            file_crc: crc32(data),
            packed_size: data.len() as u64,
            file_time: 0,
            file_attr: 0,
            host_os: 0,
            target,
            method: 0x30,
            dictionary_flags: 0,
            flags: 0x4000,
            salt: None,
            extra: &[],
        },
    )?;
    if let Some(key) = header_key {
        write_encrypted_header(out, &header, key)?;
    } else {
        out.write_all(&header)?;
    }
    out.write_all(data)?;
    crate::write_progress::check_cancelled(progress)
}

fn uses_old_style_archive_comment(target: ArchiveVersion) -> bool {
    matches!(target, ArchiveVersion::Rar15 | ArchiveVersion::Rar20)
}

/// RAR 2.9-format builds encrypt the comment whenever headers are encrypted.
fn header_comment_password(
    target: ArchiveVersion,
    header_password: Option<&[u8]>,
) -> Option<&[u8]> {
    header_password.filter(|_| target == ArchiveVersion::Rar29)
}

/// RAR 2.9-format builds put CMT before anything else, as old-style comments must be.
fn write_lead(
    out: &mut dyn Write,
    target: ArchiveVersion,
    comment: &[u8],
    header_key: Option<&HeaderKey>,
    progress: Option<ProgressReporter<'_>>,
) -> Result<()> {
    if uses_old_style_archive_comment(target) || target == ArchiveVersion::Rar29 {
        out.write_all(comment)?;
        write_producer(out, target, header_key, progress)
    } else {
        write_producer(out, target, header_key, progress)?;
        out.write_all(comment)?;
        Ok(())
    }
}

fn encode_archive_comment(
    comment: Option<&[u8]>,
    options: WriterOptions,
    header_key: Option<&HeaderKey>,
    password: Option<&[u8]>,
    data_keys: &mut DataKeys,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let Some(comment) = comment else {
        return Ok(out);
    };
    if uses_old_style_archive_comment(options.target) {
        write_comment_header(&mut out, Some(comment))?;
        return Ok(out);
    }
    let mut packed = unpack29_encode_literals(comment)?;
    // RAR gives a 2.9 comment a data salt apart from the members' one.
    let mut own_keys = DataKeys::default();
    let keys = if options.target == ArchiveVersion::Rar29 {
        &mut own_keys
    } else {
        data_keys
    };
    let salt = encrypt_packed_data_for_writer(&mut packed, options.target, password, keys)?;
    let metadata = options.archive_comment_metadata;
    let mut header = Vec::new();
    write_file_header(
        &mut header,
        &FileRecord {
            head_type: NEWSUB_HEAD,
            name: b"CMT",
            unpacked_size: comment.len() as u64,
            file_crc: crc32(comment),
            packed_size: packed.len() as u64,
            file_time: metadata.map_or(0, |metadata| metadata.0),
            file_attr: 0,
            host_os: metadata.map_or(3, |metadata| metadata.1),
            target: ArchiveVersion::Rar30,
            method: 0x33,
            dictionary_flags: dictionary_flags_for_target(ArchiveVersion::Rar30),
            flags: if password.is_some() {
                FHD_PASSWORD | FHD_SALT
            } else {
                0
            },
            salt,
            extra: &[],
        },
    )?;
    if let Some(key) = header_key {
        write_encrypted_header(&mut out, &header, key)?;
    } else {
        out.extend_from_slice(&header);
    }
    out.extend_from_slice(&packed);
    Ok(out)
}

/// Closes a header-encrypted archive or volume with an end-of-archive block in a
/// group of its own.
///
/// Every encrypted header carries its own salt, so a reader that reaches the end
/// of the last member's payload reads eight more bytes looking for the next
/// group's salt. With nothing there it stops on a short read rather than on a
/// clean end, and 7-Zip treats that as a decryption failure and refuses to open
/// the archive at all. WinRAR closes the same way. unrar stops at the last
/// member and never looks, which is why nothing caught this.
fn write_encrypted_end_block(out: &mut dyn Write, end: &[u8], key: &HeaderKey) -> Result<()> {
    write_encrypted_header(out, end, key)
}

fn write_encrypted_header(out: &mut dyn Write, header: &[u8], key: &HeaderKey) -> Result<()> {
    #[cfg(not(feature = "encryption"))]
    {
        let _ = (out, header, key);
        Err(Error::FeatureDisabled {
            feature: "encryption",
        })
    }
    #[cfg(feature = "encryption")]
    {
        let encrypted_size = checked_align16(header.len(), RAR15_ALIGN_OVERFLOW)?;
        let mut encrypted_header = Vec::with_capacity(encrypted_size);
        encrypted_header.extend_from_slice(header);
        encrypted_header.resize(encrypted_size, 0);
        key.cipher
            .clone()
            .encrypt_in_place(&mut encrypted_header)
            .map_err(super::map_rar30_crypto_error)?;
        out.write_all(&key.salt)?;
        out.write_all(&encrypted_header)?;
        Ok(())
    }
}

/// Larger sizes need the FHD_LARGE high halves; 2.9-format members take them sooner.
const MAX_SHORT_SIZE: u64 = u32::MAX as u64;

/// RAR 3.0 onwards gives a 2.9-format member past this the high size fields, zero until 4 GiB.
const RAR29_LARGE_FROM: u64 = 1 << 31;

/// A short unpacked size of all ones reads as unknown to unrar, which then
/// fails a compressed member of exactly that size on its checksum. RAR 2.0
/// gives such a member the high size fields, zero, so the size reads as given.
const RAR20_LARGE_FROM: u64 = u32::MAX as u64;

/// The format spec gives RAR 2.0 members past this UNP_VER 26; RAR 2.9 members keep 29.
const MAX_RAR20_SIZE: u64 = i32::MAX as u64;

/// The high size fields came with UNP_VER 26, which a RAR 1.5 member cannot claim.
const RAR15_LARGE_MEMBER: Error =
    Error::InvalidArgument("RAR 1.5 archives cannot hold a member over 4 GiB");

fn validate_member(name: &[u8], target: ArchiveVersion, unpacked_size: u64) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidArgument("RAR 1.5 file name is empty"));
    }
    if name.len() > u16::MAX as usize {
        return Err(Error::InvalidArgument("RAR 1.5 file name is too long"));
    }
    if unpacked_size > MAX_SHORT_SIZE && target == ArchiveVersion::Rar15 {
        return Err(RAR15_LARGE_MEMBER);
    }
    Ok(())
}

fn validate_volume_member(name: &[u8], target: ArchiveVersion, unpacked_size: u64) -> Result<()> {
    validate_member(name, target, unpacked_size)?;
    if unpacked_size > MAX_SHORT_SIZE {
        return Err(Error::InvalidArgument(
            "compressed legacy volume sets cannot hold a member over 4 GiB",
        ));
    }
    Ok(())
}

struct FileRecord<'a> {
    head_type: u8,
    name: &'a [u8],
    unpacked_size: u64,
    file_crc: u32,
    packed_size: u64,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    target: ArchiveVersion,
    method: u8,
    dictionary_flags: u16,
    flags: u16,
    salt: Option<[u8; 8]>,
    extra: &'a [u8],
}

fn write_file_header(out: &mut Vec<u8>, record: &FileRecord<'_>) -> Result<()> {
    let start = out.len();
    // A streamed member's header goes out before its packed size is known and
    // must keep its length when patched. Cipher padding can take an encrypted
    // RAR 2.0 member just under 4 GiB past `u32::MAX` once stored, so it takes
    // the high fields from the unpacked size alone.
    let sealed_past_short = record.flags & FHD_PASSWORD != 0
        && (record.unpacked_size.saturating_add(15) & !15) > MAX_SHORT_SIZE;
    let large = record.packed_size > MAX_SHORT_SIZE
        || record.unpacked_size > MAX_SHORT_SIZE
        || (record.target == ArchiveVersion::Rar20
            && (record.unpacked_size >= RAR20_LARGE_FROM || sealed_past_short))
        || (matches!(
            record.target,
            ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40
        ) && record.unpacked_size > RAR29_LARGE_FROM);
    if large && record.target == ArchiveVersion::Rar15 {
        return Err(RAR15_LARGE_MEMBER);
    }
    let past_rar20_size = record.packed_size.max(record.unpacked_size) > MAX_RAR20_SIZE;
    let flags = record.flags | record.dictionary_flags | if large { FHD_LARGE } else { 0 };
    let (host_os, file_attr) =
        rar15_compatible_metadata(record.target, record.host_os, record.file_attr);
    let head_size = 32usize
        .checked_add(if large { 8 } else { 0 })
        .and_then(|size| size.checked_add(record.name.len()))
        .and_then(|size| size.checked_add(if record.salt.is_some() { 8 } else { 0 }))
        .and_then(|size| size.checked_add(record.extra.len()))
        .ok_or(Error::InvalidArgument("RAR 1.5 file header size overflows"))?;
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidArgument("RAR 1.5 file header size overflows"))?;
    let unp_ver = match record.target {
        ArchiveVersion::Rar15 => 15,
        ArchiveVersion::Rar20 if past_rar20_size => 26,
        ArchiveVersion::Rar20 => 20,
        ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => 29,
        _ => return Err(Error::UnsupportedVersion(record.target)),
    };
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(record.head_type);
    out.extend_from_slice(&(LONG_BLOCK | flags).to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&(record.packed_size as u32).to_le_bytes());
    out.extend_from_slice(&(record.unpacked_size as u32).to_le_bytes());
    out.push(host_os);
    out.extend_from_slice(&record.file_crc.to_le_bytes());
    out.extend_from_slice(&record.file_time.to_le_bytes());
    out.push(unp_ver);
    out.push(record.method);
    out.extend_from_slice(&(record.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&file_attr.to_le_bytes());
    if large {
        out.extend_from_slice(&((record.packed_size >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&((record.unpacked_size >> 32) as u32).to_le_bytes());
    }
    out.extend_from_slice(record.name);
    if let Some(salt) = record.salt {
        out.extend_from_slice(&salt);
    }
    out.extend_from_slice(record.extra);
    write_file_header_crc(out, start, record.name.len(), flags);
    Ok(())
}

fn rar15_compatible_metadata(target: ArchiveVersion, host_os: u8, file_attr: u32) -> (u8, u32) {
    const HOST_DOS: u8 = 0;
    const HOST_UNIX: u8 = 3;
    const DOS_ARCHIVE: u32 = 0x20;
    const DOS_DIRECTORY: u32 = 0x10;
    const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
    const UNIX_DIRECTORY: u32 = 0o040000;

    if target == ArchiveVersion::Rar15 && host_os == HOST_UNIX {
        let dos_attr = if file_attr & UNIX_FILE_TYPE_MASK == UNIX_DIRECTORY {
            DOS_DIRECTORY
        } else {
            DOS_ARCHIVE
        };
        return (HOST_DOS, dos_attr);
    }
    (host_os, file_attr)
}

fn dictionary_flags_for_target(target: ArchiveVersion) -> u16 {
    ((rar29_default_dictionary_size(target).trailing_zeros() - 16) as u16) << 5
}

fn write_header_crc(out: &mut [u8], start: usize) {
    let crc = (crc32(&out[start + 2..]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_file_header_crc(out: &mut [u8], start: usize, name_len: usize, flags: u16) {
    let end = if flags & FHD_COMMENT != 0 {
        // Readers stop the CRC where the fields they parse stop, which leaves
        // out the comment block. Miss the salt out of the range and an
        // encrypted member with a comment gets a CRC nothing agrees with.
        let salt_len = if flags & FHD_SALT != 0 { 8 } else { 0 };
        let large_len = if flags & FHD_LARGE != 0 { 8 } else { 0 };
        start + 32 + large_len + name_len + salt_len
    } else {
        out.len()
    };
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn write_comment_header_crc(out: &mut [u8], start: usize) {
    let end = start + 13;
    let crc = (crc32(&out[start + 2..end]) & 0xffff) as u16;
    out[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "encryption")]
    struct EncryptedWrite {
        target: crate::ArchiveVersion,
        store: bool,
        header_encryption: bool,
        volume_size: Option<usize>,
    }

    #[cfg(feature = "encryption")]
    impl EncryptedWrite {
        fn cases() -> Vec<Self> {
            let mut cases = Vec::new();
            for target in [
                crate::ArchiveVersion::Rar29,
                crate::ArchiveVersion::Rar30,
                crate::ArchiveVersion::Rar40,
            ] {
                for store in [true, false] {
                    for header_encryption in [false, true] {
                        for volume_size in [None, Some(4096)] {
                            cases.push(Self {
                                target,
                                store,
                                header_encryption,
                                volume_size,
                            });
                        }
                    }
                }
            }
            cases
        }

        fn has_comment(&self) -> bool {
            self.volume_size.is_none()
                && matches!(
                    self.target,
                    crate::ArchiveVersion::Rar30 | crate::ArchiveVersion::Rar40
                )
        }

        fn write(&self) -> Vec<Vec<u8>> {
            let names = [b"a", b"b", b"c", b"d", b"e", b"f"];
            let data = (0..names.len())
                .map(|index| {
                    let mut state = 0x9e37_79b9u32 + index as u32;
                    (0..1500)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 17;
                            state ^= state << 5;
                            state as u8
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let Some(volume_size) = self.volume_size else {
                let mut builder = crate::Builder::new(self.target)
                    .store(self.store)
                    .password(Some(b"password".to_vec()))
                    .header_encryption(self.header_encryption);
                if self.has_comment() {
                    builder = builder
                        .comment(Some(b"comment".to_vec()))
                        .archive_comment_password(Some(b"password".to_vec()));
                }
                for (name, data) in names.iter().zip(&data) {
                    builder
                        .add_bytes(name.to_vec(), data.clone(), None, None)
                        .unwrap();
                }
                return vec![builder.to_bytes().unwrap()];
            };
            // The public legacy volume writers take one member, so drive the splitter directly.
            let entries = names
                .iter()
                .zip(&data)
                .map(|(name, data)| super::FileEntry {
                    name: name.as_slice(),
                    data,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 3,
                    password: Some(b"password"),
                    file_comment: None,
                })
                .collect::<Vec<_>>();
            let members = entries
                .iter()
                .map(super::Member::from_file)
                .collect::<Vec<_>>();
            let mut features = crate::FeatureSet::store_only();
            features.header_encryption = self.header_encryption;
            let coding = if self.store {
                crate::MemberCoding::Stored
            } else {
                crate::MemberCoding::Compressed
            };
            let mut sink = crate::volume_sink::CollectedVolumes::new();
            super::volumes::split_members(
                &members,
                super::WriterOptions::new(self.target, features),
                &coding,
                None,
                volume_size,
                &mut sink,
                &crate::WriterResources::default(),
                None,
            )
            .unwrap();
            sink.take()
        }
    }

    #[cfg(feature = "encryption")]
    impl std::fmt::Display for EncryptedWrite {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{:?} store={} header_encryption={} volumes={:?}",
                self.target, self.store, self.header_encryption, self.volume_size
            )
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn one_password_derives_data_and_header_keys_once_per_write() {
        let derivations = || crate::crypto::rar30::DERIVATIONS.with(std::cell::Cell::get);
        for case in EncryptedWrite::cases() {
            let before = derivations();
            case.write();
            let expected = 1 + usize::from(case.header_encryption);
            assert_eq!(derivations() - before, expected, "{case}");
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn members_share_one_data_salt_and_headers_share_another() {
        for case in EncryptedWrite::cases() {
            let parts = case.write();
            assert_eq!(parts.len() > 1, case.volume_size.is_some(), "{case}");
            let volumes = parts
                .iter()
                .map(|part| crate::rar15_40::Archive::parse_with_password(part, Some(b"password")))
                .collect::<crate::Result<Vec<_>>>()
                .unwrap();
            let mut salts = std::collections::BTreeSet::new();
            let mut names = std::collections::BTreeSet::new();
            for volume in &volumes {
                for file in volume.files() {
                    salts.insert(file.salt.expect("RAR 3 members carry a salt"));
                    names.insert(file.name.clone());
                }
            }
            assert_eq!(names.len(), 6, "{case}");
            assert_eq!(salts.len(), 1, "{case}");
            let data_salt = salts.into_iter().next().unwrap();

            if case.header_encryption {
                // The first encrypted block's salt follows the 7-byte marker and 13-byte main header.
                let header_salts = parts
                    .iter()
                    .map(|part| <[u8; 8]>::try_from(&part[20..28]).unwrap())
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(header_salts.len(), 1, "{case}");
                let header_salt = header_salts.into_iter().next().unwrap();
                assert_ne!(header_salt, data_salt, "{case}");
                // One member header per member, plus at least the producer and end blocks.
                let blocks: usize = parts
                    .iter()
                    .map(|part| part.windows(8).filter(|w| *w == header_salt).count())
                    .sum();
                assert!(blocks >= 6 + 2, "{case}: {blocks} header blocks");
            }

            if case.has_comment() {
                let comment = volumes[0]
                    .archive_comment_with_password(Some(b"password"))
                    .unwrap();
                assert_eq!(comment.as_deref(), Some(&b"comment"[..]), "{case}");
            }

            let mut extracted = 0;
            crate::rar15_40::extract_volumes_to(
                &volumes,
                crate::ArchiveReadOptions::with_password(b"password"),
                |_| {
                    extracted += 1;
                    Ok(Box::new(std::io::sink()))
                },
            )
            .unwrap();
            assert_eq!(extracted, 6, "{case}");
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_payload_padding_preserves_cipher_state_across_chunks() {
        for target in [crate::ArchiveVersion::Rar20, crate::ArchiveVersion::Rar30] {
            for length in [0usize, 1, 15, 16, 17, 65535, 65536, 65537] {
                let plaintext: Vec<u8> = (0..length)
                    .map(|index| (index as u8).wrapping_mul(37))
                    .collect();
                let mut data = plaintext.clone();
                let salt = super::encrypt_packed_data_for_writer(
                    &mut data,
                    target,
                    Some(b"pw"),
                    &mut super::DataKeys::default(),
                )
                .unwrap();
                let padded = length.div_ceil(16) * 16;
                assert_eq!(data.len(), padded);
                match target {
                    crate::ArchiveVersion::Rar20 => {
                        assert_eq!(salt, None);
                        super::Rar20Cipher::new(b"pw")
                            .decrypt_in_place(&mut data)
                            .unwrap();
                    }
                    crate::ArchiveVersion::Rar30 => {
                        assert!(salt.is_some());
                        super::Rar30Cipher::new(b"pw", salt)
                            .unwrap()
                            .decrypt_in_place(&mut data)
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
                assert_eq!(&data[..length], plaintext);
                assert!(data[length..].iter().all(|&byte| byte == 0));
            }
        }
    }

    #[test]
    fn member_cancellation_during_workspace_admission_is_preserved() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CancelOnSecondPoll(AtomicUsize);
        impl crate::WriteProgress for CancelOnSecondPoll {
            fn report(&self, _: crate::WriteProgressEvent<'_>) {}

            fn is_cancelled(&self) -> bool {
                self.0.fetch_add(1, Ordering::Relaxed) != 0
            }
        }

        let entry = super::FileEntry {
            name: b"file",
            data: b"payload",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        };
        let callback = CancelOnSecondPoll(AtomicUsize::new(0));
        let work = super::WorkTracker::new(
            Some(super::ProgressReporter(&callback)),
            crate::WriteOperation::Compression,
            7,
        );
        let resources = crate::WriterResources::new(1);
        assert!(matches!(
            super::encode_member(
                &super::Member::from_file(&entry),
                super::WriterOptions::new(
                    crate::ArchiveVersion::Rar29,
                    crate::FeatureSet::store_only(),
                ),
                &crate::MemberCoding::Stored,
                &mut None,
                &resources,
                &work,
            ),
            Err(crate::Error::Cancelled)
        ));
        assert_eq!(callback.0.load(Ordering::Relaxed), 2);
        assert_eq!(resources.workspace_in_use(), 0);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn finalists_run_side_by_side_only_in_room_the_budget_grants() {
        use crate::atomic64::AtomicU64;
        use std::sync::atomic::Ordering;
        use std::sync::Arc;

        // Stereo 16-bit samples, so delta reaches the finalists beside the
        // plain member, and long enough that the plain one runs beside the screens.
        let mut data = Vec::with_capacity(1 << 20);
        let mut noise = 0x2545_f491_u32;
        for frame in 0..(1 << 18) {
            for channel in 0..2 {
                noise ^= noise << 13;
                noise ^= noise >> 17;
                noise ^= noise << 5;
                let wave = ((frame as f64 / (40.0 + 13.0 * channel as f64)).sin() * 12000.0) as i16;
                data.extend_from_slice(&wave.wrapping_add((noise % 64) as i16).to_le_bytes());
            }
        }
        let entry = super::FileEntry {
            name: b"pcm",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        };
        let mut options =
            super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only());
        options.compression_level = Some(1);
        let charge = super::member_workspace(options, data.len() as u64, true);
        let lazy = super::rar29_encode_options_for_options(options)
            .unwrap()
            .with_optimal_parse_passes(0);
        let pool = crate::parallel::private_pool(4);
        let room = pool.install(|| crate::codec::rar29::member_encode_workspace(data.len(), lazy));
        let encode = |limit: u64| {
            let resources = crate::WriterResources::new(limit);
            let peak = Arc::new(AtomicU64::new(0));
            let watch = {
                let (resources, peak) = (resources.clone(), peak.clone());
                move |_: crate::WriteProgressEvent<'_>| {
                    peak.fetch_max(resources.workspace_in_use(), Ordering::SeqCst);
                }
            };
            let work = super::WorkTracker::new(
                Some(super::ProgressReporter(&watch)),
                crate::WriteOperation::Compression,
                data.len() as u64,
            );
            let encoded = pool
                .install(|| {
                    super::encode_member(
                        &super::Member::from_file(&entry),
                        options,
                        &crate::MemberCoding::Compressed,
                        &mut None,
                        &resources,
                        &work,
                    )
                })
                .unwrap();
            // Every finalist's room is handed back; the member keeps a charge
            // for its packed form until it is written.
            let held = encoded.held.as_ref().map_or(0, |permit| permit.bytes());
            assert_eq!(resources.workspace_in_use(), held, "every room handed back");
            let super::MemberPayload::Packed(packed) = encoded.payload else {
                unreachable!("a member held in memory is packed in memory")
            };
            (packed, encoded.method, peak.load(Ordering::SeqCst))
        };
        // Room for nothing beside the member's own charge runs the finalists in turn.
        let (in_turn, method, peak) = encode(charge);
        assert_eq!(peak, charge);
        assert_eq!(method, 0x31);
        // Each encode beside the first is charged while it runs, and the
        // finalists choose and code the same bytes however many run at once.
        for (limit, most) in [(charge + room, charge + room), (u64::MAX, u64::MAX)] {
            let (side_by_side, method, peak) = encode(limit);
            assert!(side_by_side == in_turn, "limit {limit}");
            assert_eq!(method, 0x31);
            assert!(peak >= charge + room && peak <= most, "{peak} for {limit}");
        }
    }

    fn binary_member(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_u32;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            match state % 4 {
                0 if out.len() > 4096 => {
                    let from = out.len() - 1 - (state as usize >> 4) % 4096;
                    for index in 0..(8 + state as usize % 56) {
                        out.push(out[from + index % (out.len() - from)]);
                    }
                }
                1 => out.extend_from_slice(&[0, 0, 0xff, (state >> 8) as u8]),
                _ => out.extend_from_slice(&state.to_le_bytes()),
            }
        }
        out.truncate(len);
        out
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    #[derive(Default)]
    struct SeekCounting {
        inner: std::io::Cursor<Vec<u8>>,
        seeks: usize,
    }

    impl std::io::Write for SeekCounting {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buffer)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl std::io::Seek for SeekCounting {
        fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
            self.seeks += 1;
            self.inner.seek(from)
        }
    }

    fn entries(members: &[(&str, &[u8])]) -> Vec<super::StreamingEntry> {
        members
            .iter()
            .map(|(name, data)| {
                super::StreamingEntry::new(
                    name.as_bytes().to_vec(),
                    crate::EntrySource::from_bytes(data.to_vec()),
                )
            })
            .collect()
    }

    fn rar40() -> super::WriterOptions {
        super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
    }

    fn in_memory(entries: &[super::StreamingEntry], coding: crate::MemberCoding) -> Vec<u8> {
        in_memory_with(entries, rar40(), coding)
    }

    fn in_memory_with(
        entries: &[super::StreamingEntry],
        options: super::WriterOptions,
        coding: crate::MemberCoding,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        super::write_streaming_archive_to(
            entries,
            options,
            coding,
            None,
            &crate::WriterResources::default(),
            None,
            &mut out,
        )
        .unwrap();
        out
    }

    fn streamed(
        entries: &[super::StreamingEntry],
        coding: crate::MemberCoding,
        progress: Option<&dyn crate::WriteProgress>,
    ) -> crate::Result<SeekCounting> {
        streamed_with(entries, rar40(), coding, progress)
    }

    fn streamed_with(
        entries: &[super::StreamingEntry],
        options: super::WriterOptions,
        coding: crate::MemberCoding,
        progress: Option<&dyn crate::WriteProgress>,
    ) -> crate::Result<SeekCounting> {
        let mut out = SeekCounting::default();
        super::write_seekable_archive_with_threshold(
            entries,
            options,
            coding,
            None,
            &crate::WriterResources::default(),
            progress,
            &mut out,
            256 * 1024,
        )?;
        Ok(out)
    }

    #[test]
    fn a_streamed_member_writes_the_archive_the_in_memory_writer_does() {
        let large = binary_member(1024 * 1024 + 4321);
        let members = entries(&[
            ("small.txt", b"small and below the threshold\n"),
            ("large.bin", &large),
        ]);
        let coding = || crate::MemberCoding::Filtered(crate::FilterPolicy::None);

        let out = streamed(&members, coding(), None).unwrap();

        assert!(out.seeks > 0, "the large member was not streamed");
        let archive = out.inner.into_inner();
        assert_eq!(archive, in_memory(&members, coding()));
        let parsed = crate::rar15_40::Archive::parse(&archive).unwrap();
        let file = parsed.files().nth(1).unwrap();
        assert_eq!(file.method, 0x33);
        assert!(file.pack_size < large.len() as u64 / 2);
    }

    #[test]
    fn an_incompressible_streamed_member_is_stored_with_nothing_left_over() {
        let large = noise(1024 * 1024);
        let members = entries(&[
            ("noise.bin", &large),
            ("after.txt", b"after the stored member"),
        ]);

        let out = streamed(&members, crate::MemberCoding::Compressed, None).unwrap();

        assert!(out.seeks > 0, "the large member was not streamed");
        assert_eq!(
            out.inner.into_inner(),
            in_memory(&members, crate::MemberCoding::Compressed)
        );
    }

    fn word_text(len: usize) -> Vec<u8> {
        let words = [
            &b"model"[..],
            b"predicts",
            b"each",
            b"byte",
            b"from",
            b"context",
            b"escape",
            b"window",
            b"archive",
            b"the",
            b"of",
            b"and",
        ];
        let mut state = 0x2545_f491_u32;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.extend_from_slice(words[(state >> 7) as usize % words.len()]);
            out.push(if state.is_multiple_of(11) {
                b'\n'
            } else {
                b' '
            });
        }
        out.truncate(len);
        out
    }

    fn streamed_member(archive: &[u8], index: usize, data: &[u8]) -> Vec<u8> {
        let parsed = crate::rar15_40::Archive::parse(archive).unwrap();
        let file = parsed.files().nth(index).unwrap();
        let packed = file.packed_data(&parsed).unwrap();
        assert_eq!(file.method, 0x33);
        assert_eq!(unpack29_decode(&packed, data.len()).unwrap(), data);
        let mut crc = crate::crc32::Crc32::new();
        crc.update(data);
        assert_eq!(file.file_crc, crc.finish());
        packed
    }

    #[test]
    fn text_over_the_threshold_streams_with_the_engine_the_whole_member_trial_picks() {
        // RAR 2.9 opens a PPMd block with its top bit set and an LZ one without.
        let ppmd = |packed: &[u8]| packed[0] & 0x80 != 0;
        let words = word_text(600 * 1024);
        // The trial's answer is close here: plain PPMd against escapes.
        let repeated = word_text(200 * 1024).repeat(3);

        let mut engines = Vec::new();
        for text in [&words, &repeated] {
            let members = entries(&[("text.txt", text)]);
            let out = streamed(&members, crate::MemberCoding::Compressed, None).unwrap();

            assert!(out.seeks > 0, "the text member was not streamed");
            let packed = streamed_member(&out.inner.into_inner(), 0, text);
            let whole = in_memory(&members, crate::MemberCoding::Compressed);
            let whole_packed = streamed_member(&whole, 0, text);
            assert_eq!(ppmd(&packed), ppmd(&whole_packed));
            engines.push(ppmd(&packed));
        }
        assert_eq!(engines, [true, true]);
    }

    // A random walk per channel: no repeats for LZ, small steps for a filter.
    fn audio() -> Vec<u8> {
        let mut audio = Vec::new();
        let (mut state, mut left, mut right) = (0x2545_f491_u32, 0i16, 0i16);
        while audio.len() < 1536 * 1024 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            left = left.wrapping_add((state & 0x3f) as i16 - 32);
            right = right.wrapping_add((state >> 8 & 0x3f) as i16 - 32);
            audio.extend_from_slice(&left.to_le_bytes());
            audio.extend_from_slice(&right.to_le_bytes());
        }
        audio
    }

    #[test]
    fn a_filter_friendly_member_streams_close_to_the_in_memory_ratio() {
        let audio = audio();
        let members = entries(&[("audio.wav", &audio)]);

        let out = streamed(&members, crate::MemberCoding::Compressed, None).unwrap();

        assert!(out.seeks > 0, "the audio member was not streamed");
        let packed = streamed_member(&out.inner.into_inner(), 0, &audio);
        let whole = in_memory(&members, crate::MemberCoding::Compressed);
        let whole = crate::rar15_40::Archive::parse(&whole).unwrap();
        let whole = whole.files().next().unwrap().pack_size;
        let unfiltered = in_memory(
            &members,
            crate::MemberCoding::Filtered(crate::FilterPolicy::None),
        );
        let unfiltered = crate::rar15_40::Archive::parse(&unfiltered).unwrap();
        let unfiltered = unfiltered.files().next().unwrap().pack_size;
        // Cut into blocks by price, the unfiltered random walk packs a tenth
        // smaller than in one table per 64 KiB, so the filter's margin is
        // three fifths rather than a half.
        assert!(
            (packed.len() as u64) * 5 < unfiltered * 3,
            "{} streamed against {unfiltered} unfiltered",
            packed.len()
        );
        assert!(
            (packed.len() as u64) * 100 <= whole * 102,
            "{} streamed against {whole} in memory",
            packed.len()
        );
    }

    fn named(kind: crate::FilterKind) -> crate::MemberCoding {
        crate::MemberCoding::Filtered(crate::FilterPolicy::explicit(kind))
    }

    fn pack_size(archive: &[u8], index: usize) -> u64 {
        let parsed = crate::rar15_40::Archive::parse(archive).unwrap();
        let size = parsed.files().nth(index).unwrap().pack_size;
        size
    }

    #[test]
    fn a_member_with_a_named_filter_streams_what_the_in_memory_writer_writes() {
        use crate::FilterKind;
        let large = binary_member(1024 * 1024 + 4321);
        let audio = audio();
        let small: &[u8] = b"small and below the threshold\n";
        // Several segments a member, so records meet their boundaries.
        let mut segmented = rar40();
        segmented.dictionary_size = Some(128 * 1024);
        for (data, kind) in [
            (&large, FilterKind::E8),
            (&large, FilterKind::E8E9),
            (&audio, FilterKind::Delta { channels: 4 }),
            (&audio, FilterKind::Audio { channels: 4 }),
        ] {
            let members = entries(&[("small.txt", small), ("large.bin", data)]);
            for (window, options) in [("fitted", rar40()), ("128K", segmented)] {
                let out = streamed_with(&members, options, named(kind), None).unwrap();

                assert!(out.seeks > 0, "{kind:?} {window}: not streamed");
                let archive = out.inner.into_inner();
                assert_eq!(
                    extracted_set(std::slice::from_ref(&archive), None),
                    [
                        (b"small.txt".to_vec(), small.to_vec()),
                        (b"large.bin".to_vec(), data.to_vec()),
                    ],
                    "{kind:?} {window}"
                );
                let whole = in_memory_with(&members, options, named(kind));
                // An x86 record covers 128 KiB, so segment boundaries fall
                // between records; delta and audio records are cut at them.
                if matches!(kind, FilterKind::E8 | FilterKind::E8E9) || window == "fitted" {
                    assert_eq!(archive, whole, "{kind:?} {window}");
                } else {
                    let (streamed, whole) = (pack_size(&archive, 1), pack_size(&whole, 1));
                    assert!(
                        streamed * 1000 <= whole * 1002,
                        "{kind:?} {window}: {streamed} streamed against {whole} in memory"
                    );
                }
            }
        }
        // Forced PPMd declares each record as it reaches it, and reads a
        // record whole before coding any of it, so even a delta member read in
        // many segments codes what it does in memory. It reads at most 512 KiB
        // a segment at a 128 KiB window, whatever the thread count, so these
        // shorter members still cross a boundary there; PPMd costs ten times
        // what LZ does here.
        for (data, kind) in [
            (&large[..512 * 1024 + 4321], FilterKind::E8E9),
            (&audio[..768 * 1024], FilterKind::Delta { channels: 4 }),
        ] {
            let members = entries(&[("small.txt", small), ("large.bin", data)]);
            for (window, mut options) in [("fitted", rar40()), ("128K", segmented)] {
                options.method = super::Rar29Method::Ppmd;
                let out = streamed_with(&members, options, named(kind), None).unwrap();

                assert!(out.seeks > 0, "PPMd {kind:?} {window}: not streamed");
                let archive = out.inner.into_inner();
                assert_eq!(
                    archive,
                    in_memory_with(&members, options, named(kind)),
                    "PPMd {kind:?} {window}"
                );
                assert_eq!(
                    extracted_set(std::slice::from_ref(&archive), None),
                    [
                        (b"small.txt".to_vec(), small.to_vec()),
                        (b"large.bin".to_vec(), data.to_vec()),
                    ],
                    "PPMd {kind:?} {window}"
                );
            }
        }
        // The filter was applied, not just named.
        let members = entries(&[("audio.wav", &audio)]);
        let unfiltered = streamed_with(
            &members,
            segmented,
            crate::MemberCoding::Filtered(crate::FilterPolicy::None),
            None,
        )
        .unwrap();
        let filtered = streamed_with(
            &members,
            segmented,
            named(FilterKind::Delta { channels: 4 }),
            None,
        )
        .unwrap();
        assert!(
            pack_size(&filtered.inner.into_inner(), 0) * 5
                < pack_size(&unfiltered.inner.into_inner(), 0) * 3
        );
    }

    /// Each member's method and packed bytes.
    fn packed_members(archive: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let parsed = crate::rar15_40::Archive::parse(archive).unwrap();
        parsed
            .files()
            .map(|file| (file.method, file.packed_data(&parsed).unwrap()))
            .collect()
    }

    #[test]
    fn a_named_filter_streams_on_a_solid_chain_and_through_a_pipe() {
        // Each over the 256 KiB the large members stream and spool above, and
        // no larger: forced PPMd codes them at a few hundred KiB a second.
        let large = binary_member(512 * 1024 + 4321);
        let noise = noise(300 * 1024 + 7);
        let files: [(&str, &[u8]); 4] = [
            ("before.bin", &large[1000..41000]),
            ("large.bin", &large),
            ("after.bin", &large[large.len() - 40000..]),
            ("noise.bin", &noise),
        ];
        let members = entries(&files);
        let expected: Vec<_> = files
            .iter()
            .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
            .collect();
        let coding = || named(crate::FilterKind::E8E9);
        let mut solid40 = rar40();
        solid40.features.solid = true;
        // Unchained, forced PPMd is held to the in-memory bytes in
        // `a_member_with_a_named_filter_streams_what_the_in_memory_writer_writes`.
        let mut solid_ppmd = solid40;
        solid_ppmd.method = super::Rar29Method::Ppmd;
        for (name, options) in [
            ("rar40", rar40()),
            ("solid rar40", solid40),
            ("solid PPMd rar40", solid_ppmd),
        ] {
            let out = streamed_with(&members, options, coding(), None).unwrap();
            assert!(out.seeks > 0, "{name}: not streamed");
            let file = out.inner.into_inner();
            let (piped, spooled) = piped_with(&members, options, coding());
            assert!(spooled, "{name}: the large members were not spooled");
            assert_eq!(piped, file, "{name}");
            let whole = in_memory_with(&members, options, coding());
            // In a chain, forced PPMd codes a named filter's member on its own,
            // as it does in memory, so it streams the bytes it codes there.
            if options.method == super::Rar29Method::Ppmd {
                assert_eq!(file, whole, "{name}");
            }
            // Both store the noise once it outgrows itself, filter or not.
            for archive in [&file, &whole] {
                assert_eq!(
                    packed_members(archive)[3].0,
                    0x30,
                    "{name}: the noise was not stored"
                );
            }
            assert_eq!(extracted_set(&[file], None), expected, "{name}");
            assert_eq!(extracted_set(&[whole], None), expected, "{name}");
        }
    }

    #[test]
    fn a_source_that_shrinks_while_streaming_is_reported_as_changed() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for full_opens in [0, 1] {
            let opens = AtomicUsize::new(0);
            let members = vec![super::StreamingEntry::new(
                b"shrinks.bin".to_vec(),
                crate::EntrySource::from_opener(1024 * 1024, move || {
                    let len = match opens.fetch_add(1, Ordering::Relaxed) < full_opens {
                        true => 1024 * 1024,
                        false => 512 * 1024,
                    };
                    Ok(Box::new(std::io::Cursor::new(binary_member(len))))
                }),
            )];
            let coding = crate::MemberCoding::Filtered(crate::FilterPolicy::None);

            let Err(crate::Error::AtEntry { source, .. }) = streamed(&members, coding, None) else {
                panic!("a shrunken source was written");
            };
            assert!(
                matches!(*source, crate::Error::SourceChanged(_)),
                "{source}"
            );
        }
    }

    #[test]
    fn a_streamed_member_reports_progress_and_can_be_cancelled() {
        use crate::atomic64::AtomicU64;
        use std::sync::atomic::Ordering;

        struct CancelPast(u64, AtomicU64);
        impl crate::WriteProgress for CancelPast {
            fn report(&self, event: crate::WriteProgressEvent<'_>) {
                if let crate::WriteProgressEvent::Advanced {
                    completed_bytes, ..
                } = event
                {
                    self.1.fetch_max(completed_bytes, Ordering::Relaxed);
                }
            }

            fn is_cancelled(&self) -> bool {
                self.1.load(Ordering::Relaxed) > self.0
            }
        }

        let large = binary_member(2 * 1024 * 1024);
        let members = entries(&[("large.bin", &large)]);
        let coding = || crate::MemberCoding::Filtered(crate::FilterPolicy::None);

        let finished = CancelPast(u64::MAX, AtomicU64::new(0));
        streamed(&members, coding(), Some(&finished)).unwrap();
        assert_eq!(finished.1.load(Ordering::Relaxed), large.len() as u64);

        let cancelled = CancelPast(512 * 1024, AtomicU64::new(0));
        assert!(matches!(
            streamed(&members, coding(), Some(&cancelled)),
            Err(crate::Error::Cancelled)
        ));
        assert!(cancelled.1.load(Ordering::Relaxed) < large.len() as u64);
    }

    #[cfg(feature = "encryption")]
    fn extracted(archive: &[u8], password: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
        extracted_set(&[archive.to_vec()], password)
    }

    fn extracted_set(volumes: &[Vec<u8>], password: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
        use std::cell::RefCell;
        use std::rc::Rc;

        struct Capture(Rc<RefCell<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(buffer);
                Ok(buffer.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let parsed: Vec<_> = volumes
            .iter()
            .map(|volume| crate::rar15_40::Archive::parse_with_password(volume, password).unwrap())
            .collect();
        let mut out = Vec::new();
        crate::rar15_40::extract_volumes_to(
            &parsed,
            match password {
                Some(password) => crate::ArchiveReadOptions::with_password(password),
                None => crate::ArchiveReadOptions::default(),
            },
            |meta| {
                let data = Rc::new(RefCell::new(Vec::new()));
                out.push((meta.name.clone(), data.clone()));
                Ok(Box::new(Capture(data)))
            },
        )
        .unwrap();
        out.into_iter()
            .map(|(name, data)| (name, data.take()))
            .collect()
    }

    /// The archive written to an output that cannot seek, large members spooled
    /// above the same threshold [`streamed_with`] streams above, and whether a
    /// spool sat in the temp directory while the archive came out.
    fn piped_with(
        entries: &[super::StreamingEntry],
        options: super::WriterOptions,
        coding: crate::MemberCoding,
    ) -> (Vec<u8>, bool) {
        struct Piped {
            out: Vec<u8>,
            dir: std::path::PathBuf,
            saw_spool: bool,
        }
        impl std::io::Write for Piped {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.saw_spool |= std::fs::read_dir(&self.dir)?.next().is_some();
                self.out.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let dir = crate::scratch::case("rar15-40-piped");
        let resources = crate::WriterResources::default().with_temp_dir(dir.to_path_buf());
        let members: Vec<_> = entries.iter().map(super::Member::from_streaming).collect();
        let mut out = Piped {
            out: Vec::new(),
            dir: dir.to_path_buf(),
            saw_spool: false,
        };
        super::write_archive_to(
            &members,
            options,
            coding,
            None,
            &resources,
            None,
            super::ArchiveOutput::Stream {
                output: &mut out,
                spool_above: Some(256 * 1024),
            },
            None,
            None,
        )
        .unwrap();
        let left = std::fs::read_dir(&*dir).unwrap().count();
        assert_eq!(left, 0, "a spool was left behind");
        (out.out, out.saw_spool)
    }

    #[test]
    fn a_piped_member_is_spooled_into_the_archive_a_file_gets() {
        // Over the 256 KiB members are spooled above.
        let large = binary_member(512 * 1024 + 4321);
        // Noise doesn't pay to compress, so its attempt restarts as stored.
        let noise = noise(300 * 1024 + 7);
        let members = entries(&[
            ("small.txt", b"small and below the threshold\n"),
            ("large.bin", &large),
            ("noise.bin", &noise),
        ]);
        let coding = || crate::MemberCoding::Compressed;
        let mut solid40 = rar40();
        solid40.features.solid = true;
        for (name, options) in [
            ("rar40", rar40()),
            ("solid rar40", solid40),
            ("rar20", rar20(3, false)),
            ("solid rar20", rar20(3, true)),
        ] {
            let (piped, spooled) = piped_with(&members, options, coding());
            assert!(spooled, "{name}: the large members were not spooled");
            let file = streamed_with(&members, options, coding(), None)
                .unwrap()
                .inner
                .into_inner();
            assert_eq!(piped, file, "{name}");
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn a_piped_password_protected_member_is_spooled_and_encrypted() {
        // Over the 256 KiB members are spooled above.
        let large = binary_member(512 * 1024 + 4321);
        let noise = noise(300 * 1024 + 7);
        let members: Vec<_> = entries(&[("large.bin", &large), ("noise.bin", &noise)])
            .into_iter()
            .map(|entry| entry.with_password(b"password".to_vec()))
            .collect();
        let coding = || crate::MemberCoding::Compressed;
        let sizes = |archive: &[u8]| {
            crate::rar15_40::Archive::parse_with_password(archive, Some(b"password"))
                .unwrap()
                .files()
                .map(|file| (file.method, file.pack_size, file.file_crc))
                .collect::<Vec<_>>()
        };
        for header_encryption in [false, true] {
            let mut options = rar40();
            options.features.header_encryption = header_encryption;
            let (piped, spooled) = piped_with(&members, options, coding());
            assert!(spooled, "-hp {header_encryption}");
            let file = streamed_with(&members, options, coding(), None)
                .unwrap()
                .inner
                .into_inner();
            // Salts differ between runs, so compare what they decide.
            assert_eq!(sizes(&piped), sizes(&file), "-hp {header_encryption}");
            assert_eq!(piped.len(), file.len(), "-hp {header_encryption}");
            let expected = [
                (b"large.bin".to_vec(), large.clone()),
                (b"noise.bin".to_vec(), noise.clone()),
            ];
            assert_eq!(extracted(&piped, Some(b"password")), expected);
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn a_password_protected_member_streams_encrypted() {
        let large = binary_member(1024 * 1024 + 4321);
        let noise = noise(1024 * 1024 + 7);
        let members: Vec<_> = entries(&[
            ("small.txt", b"small and below the threshold\n"),
            ("large.bin", &large),
            ("noise.bin", &noise),
        ])
        .into_iter()
        .map(|entry| entry.with_password(b"password".to_vec()))
        .collect();
        let coding = || crate::MemberCoding::Filtered(crate::FilterPolicy::None);
        let sizes = |archive: &[u8]| {
            crate::rar15_40::Archive::parse_with_password(archive, Some(b"password"))
                .unwrap()
                .files()
                .map(|file| (file.method, file.pack_size, file.file_crc))
                .collect::<Vec<_>>()
        };

        for header_encryption in [false, true] {
            let mut options = rar40();
            options.features.header_encryption = header_encryption;

            let out = streamed_with(&members, options, coding(), None).unwrap();

            assert!(out.seeks > 0, "the large members were not streamed");
            let archive = out.inner.into_inner();
            let whole = in_memory_with(&members, options, coding());
            assert_eq!(sizes(&archive), sizes(&whole), "-hp {header_encryption}");
            assert_eq!(archive.len(), whole.len(), "-hp {header_encryption}");
            let stored = sizes(&archive)[2];
            assert_eq!(
                (stored.0, stored.1),
                (0x30, (noise.len() as u64).next_multiple_of(16))
            );
            let expected = [
                (
                    b"small.txt".to_vec(),
                    b"small and below the threshold\n".to_vec(),
                ),
                (b"large.bin".to_vec(), large.clone()),
                (b"noise.bin".to_vec(), noise.clone()),
            ];
            assert_eq!(extracted(&archive, Some(b"password")), expected);
        }
    }

    #[test]
    fn solid_members_stream_on_the_chain_and_leave_it_for_the_next() {
        let large = binary_member(1024 * 1024 + 4321);
        let noise = noise(1024 * 1024 + 7);
        let mut options = rar40();
        options.features.solid = true;
        let coding = || crate::MemberCoding::Filtered(crate::FilterPolicy::None);
        let members = entries(&[
            ("before.bin", &large[1000..41000]),
            ("large.bin", &large),
            ("after.bin", &large[large.len() - 40000..]),
            ("noise.bin", &noise),
            ("last.bin", &large[5000..45000]),
        ]);

        let out = streamed_with(&members, options, coding(), None).unwrap();

        assert!(out.seeks > 0, "the large members were not streamed");
        let archive = out.inner.into_inner();
        assert_eq!(archive, in_memory_with(&members, options, coding()));
        let parsed = crate::rar15_40::Archive::parse(&archive).unwrap();
        let after = parsed.files().nth(2).unwrap();
        assert!(after.pack_size < 1000, "{} bytes", after.pack_size);
    }

    fn rar20(level: u8, solid: bool) -> super::WriterOptions {
        let mut options =
            super::WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only());
        options.compression_level = Some(level);
        options.features.solid = solid;
        options
    }

    // Decodes each member in turn, as a solid chain if `solid`.
    fn rar20_members(archive: &[u8], solid: bool, members: &[&[u8]]) {
        let parsed = crate::rar15_40::Archive::parse(archive).unwrap();
        let mut decoder = crate::codec::rar20::Unpack20::new();
        for (file, data) in parsed.files().zip(members) {
            if !solid {
                decoder = crate::codec::rar20::Unpack20::new();
            }
            let packed = file.packed_data(&parsed).unwrap();
            if file.method == 0x30 {
                // A stored member ends a solid chain, as it does on the writer's side.
                assert_eq!(packed, *data);
                decoder = crate::codec::rar20::Unpack20::new();
                continue;
            }
            assert_eq!(decoder.decode_member(&packed, data.len()).unwrap(), *data);
        }
    }

    #[test]
    fn a_streamed_rar20_member_writes_the_archive_the_in_memory_writer_does() {
        // Over two blocks, so its tables change twice.
        let large = binary_member(2 * 1024 * 1024 + 4321);
        let small: &[u8] = b"small and below the threshold\n";
        let members = entries(&[("small.txt", small), ("large.bin", &large)]);
        let coding = || crate::MemberCoding::Compressed;

        let out = streamed_with(&members, rar20(3, false), coding(), None).unwrap();

        assert!(out.seeks > 0, "the large member was not streamed");
        let archive = out.inner.into_inner();
        assert_eq!(archive, in_memory_with(&members, rar20(3, false), coding()));
        rar20_members(&archive, false, &[small, &large]);
    }

    #[test]
    fn solid_rar20_members_stream_on_the_chain_and_leave_it_for_the_next() {
        let large = binary_member(1024 * 1024 + 4321);
        let members = [
            &large[1000..41000],
            &large[..],
            &large[large.len() - 40000..],
            &large[5000..45000],
        ];
        let named = entries(&[
            ("before.bin", members[0]),
            ("large.bin", members[1]),
            ("after.bin", members[2]),
            ("last.bin", members[3]),
        ]);
        let coding = || crate::MemberCoding::Compressed;

        let out = streamed_with(&named, rar20(3, true), coding(), None).unwrap();

        assert!(out.seeks > 0, "the large member was not streamed");
        let archive = out.inner.into_inner();
        assert_eq!(archive, in_memory_with(&named, rar20(3, true), coding()));
        rar20_members(&archive, true, &members);
        let parsed = crate::rar15_40::Archive::parse(&archive).unwrap();
        let after = parsed.files().nth(2).unwrap();
        assert!(after.pack_size < 1000, "{} bytes", after.pack_size);
    }

    fn rar15(level: u8, solid: bool) -> super::WriterOptions {
        let mut options =
            super::WriterOptions::new(ArchiveVersion::Rar15, FeatureSet::store_only());
        options.compression_level = Some(level);
        options.features.solid = solid;
        options
    }

    fn named_contents(contents: &[(&str, &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
        contents
            .iter()
            .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
            .collect()
    }

    #[test]
    fn a_streamed_rar15_member_writes_the_archive_the_in_memory_writer_does() {
        // Over a window, so the member is coded in two.
        let large = binary_member(1024 * 1024 + 4321);
        let noise = noise(300 * 1024);
        let contents = [
            ("small.txt", &b"small and below the threshold\n"[..]),
            ("large.bin", &large[..]),
            ("noise.bin", &noise[..]),
        ];
        let members = entries(&contents);
        let coding = || crate::MemberCoding::Compressed;
        let routed: Vec<_> = members.iter().map(super::Member::from_streaming).collect();
        assert!(super::streams_member(&routed[1], rar15(3, false), &coding(), 256 * 1024).unwrap());

        let out = streamed_with(&members, rar15(3, false), coding(), None).unwrap();

        assert!(out.seeks > 0, "the large member was not streamed");
        let archive = out.inner.into_inner();
        assert_eq!(archive, in_memory_with(&members, rar15(3, false), coding()));
        let parsed = crate::rar15_40::Archive::parse(&archive).unwrap();
        let methods: Vec<_> = parsed.files().map(|file| file.method).collect();
        assert_eq!(methods, [0x33, 0x33, 0x30]);
        // An output that cannot seek gets the same archive through a spool.
        let (piped, saw_spool) = piped_with(&members, rar15(3, false), coding());
        assert!(saw_spool, "the large member was not spooled");
        assert!(piped == archive);
        assert_eq!(extracted_set(&[archive], None), named_contents(&contents));
    }

    #[test]
    fn solid_rar15_members_stream_on_the_chain_and_are_never_stored() {
        let large = binary_member(1024 * 1024 + 4321);
        let noise = noise(300 * 1024);
        let contents = [
            ("before.bin", &large[1000..41000]),
            ("large.bin", &large[..]),
            ("noise.bin", &noise[..]),
            ("after.bin", &large[large.len() - 40000..]),
        ];
        let members = entries(&contents);
        let coding = || crate::MemberCoding::Compressed;

        let out = streamed_with(&members, rar15(3, true), coding(), None).unwrap();

        assert!(out.seeks > 0, "the large members were not streamed");
        let archive = out.inner.into_inner();
        assert_eq!(archive, in_memory_with(&members, rar15(3, true), coding()));
        // Storing one would break the chain RAR 1.5 readers follow.
        let parsed = crate::rar15_40::Archive::parse(&archive).unwrap();
        assert!(parsed.files().all(|file| file.method != 0x30));
        assert_eq!(extracted_set(&[archive], None), named_contents(&contents));
    }

    #[test]
    fn a_streamed_rar15_member_splits_into_the_volumes_the_in_memory_writer_does() {
        let large = binary_member(1024 * 1024 + 4321);
        let noise = noise(300 * 1024);
        let contents = [
            ("small.txt", &b"small and below the threshold\n"[..]),
            ("large.bin", &large[..]),
            ("noise.bin", &noise[..]),
        ];
        let members = entries(&contents);
        let coding = || crate::MemberCoding::Compressed;
        for solid in [false, true] {
            let routed: Vec<_> = members.iter().map(super::Member::from_streaming).collect();
            let streams = super::streams_member(&routed[1], rar15(3, solid), &coding(), 256 * 1024);
            assert!(streams.unwrap());

            let streamed = volume_set(
                &members,
                rar15(3, solid),
                coding(),
                100_000,
                256 * 1024,
                None,
            )
            .unwrap();

            let whole =
                volume_set(&members, rar15(3, solid), coding(), 100_000, u64::MAX, None).unwrap();
            assert!(streamed.len() > 2);
            assert!(streamed == whole, "solid: {solid}");
            assert_eq!(extracted_set(&streamed, None), named_contents(&contents));
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn a_password_protected_rar15_member_streams_without_padding() {
        let large = binary_member(1024 * 1024 + 4321);
        let noise = noise(300 * 1024 + 5);
        let contents = [("large.bin", &large[..]), ("noise.bin", &noise[..])];
        let members: Vec<_> = entries(&contents)
            .into_iter()
            .map(|entry| entry.with_password(b"password".to_vec()))
            .collect();
        let coding = || crate::MemberCoding::Compressed;
        for solid in [false, true] {
            let out = streamed_with(&members, rar15(3, solid), coding(), None).unwrap();

            assert!(out.seeks > 0, "the large members were not streamed");
            let archive = out.inner.into_inner();
            // The RAR 1.5 cipher works a byte at a time, so nothing is padded,
            // and with no salt the archive is the one written in memory.
            let whole = in_memory_with(&members, rar15(3, solid), coding());
            assert!(archive == whole, "solid: {solid}");
            assert_eq!(
                extracted(&archive, Some(b"password")),
                named_contents(&contents)
            );
        }
    }

    #[test]
    fn rar15_charges_an_index_whatever_the_member_size() {
        for level in [1, 3, 5] {
            let options = rar15(level, false);
            let small = super::member_workspace(options, 1 << 20, true);
            let large = super::member_workspace(options, 1 << 30, true);
            // Beyond the bytes it holds, a large member costs what a small one does.
            assert_eq!(large - small, 2 * ((1 << 30) - (1 << 20)));
            let streamed = super::streamed_workspace(options, &crate::MemberCoding::Compressed);
            assert!(streamed < 16 * 1024 * 1024, "{streamed}");
        }
    }

    #[test]
    fn rar20_charges_a_block_whatever_the_member_size() {
        for level in [3, 5] {
            let options = rar20(level, false);
            let small = super::member_workspace(options, 1 << 20, true);
            let large = super::member_workspace(options, 1 << 30, true);
            // Beyond the bytes it holds, a large member costs what a small one does.
            assert_eq!(large - small, 2 * ((1 << 30) - (1 << 20)));
            let streamed = super::streamed_workspace(options, &crate::MemberCoding::Compressed);
            assert!(streamed < 128 * 1024 * 1024, "{streamed}");
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn solid_text_streams_ppmd_on_the_chain_model() {
        let text = word_text(1024 * 1024);
        let mut options = rar40();
        options.features.solid = true;
        let members: Vec<_> = entries(&[
            ("before.txt", &text[..60000]),
            ("large.txt", &text),
            ("after.txt", &text[text.len() - 60000..]),
        ])
        .into_iter()
        .map(|entry| entry.with_password(b"password".to_vec()))
        .collect();

        let out = streamed_with(&members, options, crate::MemberCoding::Compressed, None).unwrap();

        assert!(out.seeks > 0, "the text member was not streamed");
        let archive = out.inner.into_inner();
        let parsed =
            crate::rar15_40::Archive::parse_with_password(&archive, Some(b"password")).unwrap();
        let after = parsed.files().nth(2).unwrap();
        assert!(after.pack_size < 2000, "{} bytes", after.pack_size);
        let expected = [
            (b"before.txt".to_vec(), text[..60000].to_vec()),
            (b"large.txt".to_vec(), text.clone()),
            (b"after.txt".to_vec(), text[text.len() - 60000..].to_vec()),
        ];
        assert_eq!(extracted(&archive, Some(b"password")), expected);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn a_solid_member_searches_filters_against_the_chain() {
        let audio = audio();
        let mut options = rar40();
        options.features.solid = true;
        options.features.header_encryption = true;
        let members: Vec<_> = entries(&[
            ("before.wav", &audio[..80000]),
            ("audio.wav", &audio),
            ("after.wav", &audio[audio.len() - 80000..]),
        ])
        .into_iter()
        .map(|entry| entry.with_password(b"password".to_vec()))
        .collect();

        let out = streamed_with(&members, options, crate::MemberCoding::Compressed, None).unwrap();

        assert!(out.seeks > 0, "the audio member was not streamed");
        let archive = out.inner.into_inner();
        let unfiltered = in_memory_with(
            &members,
            options,
            crate::MemberCoding::Filtered(crate::FilterPolicy::None),
        );
        assert!(archive.len() * 5 < unfiltered.len() * 3);
        let expected = [
            (b"before.wav".to_vec(), audio[..80000].to_vec()),
            (b"audio.wav".to_vec(), audio.clone()),
            (b"after.wav".to_vec(), audio[audio.len() - 80000..].to_vec()),
        ];
        assert_eq!(extracted(&archive, Some(b"password")), expected);
    }

    fn counted_entries(
        members: &[(&str, &[u8])],
    ) -> (
        Vec<super::StreamingEntry>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let opens = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let entries = members
            .iter()
            .map(|(name, data)| {
                let data = data.to_vec();
                let opens = opens.clone();
                super::StreamingEntry::new(
                    name.as_bytes().to_vec(),
                    crate::EntrySource::from_opener(data.len() as u64, move || {
                        opens.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(Box::new(std::io::Cursor::new(data.clone())))
                    }),
                )
            })
            .collect();
        (entries, opens)
    }

    fn volume_set(
        entries: &[super::StreamingEntry],
        options: super::WriterOptions,
        coding: crate::MemberCoding,
        volume_size: usize,
        stream_above: u64,
        progress: Option<&dyn crate::WriteProgress>,
    ) -> crate::Result<Vec<Vec<u8>>> {
        let members: Vec<_> = entries.iter().map(super::Member::from_streaming).collect();
        let mut sink = crate::volume_sink::CollectedVolumes::new();
        super::volumes::split_members_above(
            &members,
            options,
            &coding,
            None,
            volume_size,
            &mut sink,
            &crate::WriterResources::default(),
            progress,
            stream_above,
        )?;
        Ok(sink.take())
    }

    #[test]
    fn a_streamed_member_splits_into_the_volumes_the_in_memory_writer_does() {
        let large = binary_member(1024 * 1024 + 4321);
        let (members, opens) = counted_entries(&[
            ("small.txt", b"small and below the threshold\n"),
            ("large.bin", &large),
        ]);
        let coding = || crate::MemberCoding::Compressed;

        let streamed = volume_set(&members, rar40(), coding(), 100_000, 256 * 1024, None).unwrap();

        assert!(
            opens.load(std::sync::atomic::Ordering::Relaxed) > 2,
            "the large member was not streamed"
        );
        let whole = volume_set(&members, rar40(), coding(), 100_000, u64::MAX, None).unwrap();
        assert!(streamed.len() > 2);
        assert_eq!(streamed, whole);
    }

    #[test]
    fn a_streamed_rar20_member_splits_into_the_volumes_the_in_memory_writer_does() {
        // Over two blocks, so the set carries the table switches too.
        let large = binary_member(2 * 1024 * 1024 + 4321);
        let small: &[u8] = b"small and below the threshold\n";
        let contents = [("small.txt", small), ("large.bin", &large[..])];
        let (members, opens) = counted_entries(&contents);
        let coding = || crate::MemberCoding::Compressed;
        // RAR 2.0 has one engine, so it opens a member once either way.
        let routed: Vec<_> = members.iter().map(super::Member::from_streaming).collect();
        let streams = super::streams_member(&routed[1], rar20(3, false), &coding(), 256 * 1024);
        assert!(streams.unwrap());

        let streamed = volume_set(
            &members,
            rar20(3, false),
            coding(),
            100_000,
            256 * 1024,
            None,
        )
        .unwrap();

        assert_eq!(opens.load(std::sync::atomic::Ordering::Relaxed), 2);
        let whole =
            volume_set(&members, rar20(3, false), coding(), 100_000, u64::MAX, None).unwrap();
        assert!(streamed.len() > 2);
        assert_eq!(streamed, whole);
        let expected: Vec<_> = contents
            .iter()
            .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
            .collect();
        assert_eq!(extracted_set(&streamed, None), expected);
    }

    #[test]
    fn an_incompressible_member_in_a_set_is_stored_with_nothing_left_over() {
        let noise = noise(1024 * 1024 + 7);
        let large = binary_member(512 * 1024);
        let coding = || crate::MemberCoding::Compressed;
        // A stored lead leaves the noise most of a volume, or a few bytes, to start in.
        for lead_len in [100, 99_800] {
            let lead = super::tests::noise(lead_len);
            let contents = [
                ("lead.bin", &lead[..]),
                ("noise.bin", &noise[..]),
                ("large.bin", &large[..]),
            ];
            let (members, opens) = counted_entries(&contents);

            // Noise grows by less than the margin, so it is stored only where no growth is allowed.
            let streamed = super::volumes::with_commit_growth(u64::MAX, || {
                volume_set(&members, rar40(), coding(), 100_000, 256 * 1024, None)
            })
            .unwrap();

            assert!(
                opens.load(std::sync::atomic::Ordering::Relaxed) > 4,
                "the large members were not streamed"
            );
            let whole = volume_set(&members, rar40(), coding(), 100_000, u64::MAX, None).unwrap();
            assert_eq!(streamed, whole, "a {lead_len} byte lead");
            let expected: Vec<_> = contents
                .iter()
                .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
                .collect();
            assert_eq!(extracted_set(&streamed, None), expected);
        }
    }

    #[test]
    fn a_member_whose_first_volume_does_not_compress_still_compresses_in_a_set() {
        // The noise fills the volume the member starts in, so it is all the member is judged by.
        // RAR 1.5 hands its packed bytes on a 1 MiB window at a time, so it needs more.
        let mut mixed = noise(1_200_000);
        mixed.extend_from_slice(&word_text(1024 * 1024));
        let contents = [("mixed.bin", &mixed[..])];
        let (members, _) = counted_entries(&contents);
        let coding = || crate::MemberCoding::Compressed;
        // RAR 1.5 grows noise by about 1% at level 3, past the margin RAR 2.0 on gets.
        for options in [rar40(), rar20(3, false), rar15(3, false)] {
            let streamed =
                volume_set(&members, options, coding(), 100_000, 256 * 1024, None).unwrap();

            let whole = volume_set(&members, options, coding(), 100_000, u64::MAX, None).unwrap();
            assert_eq!(streamed, whole, "{:?}", options.target);
            let first = crate::rar15_40::Archive::parse(&streamed[0]).unwrap();
            assert_ne!(first.files().next().unwrap().method, 0x30);
            let expected = vec![(b"mixed.bin".to_vec(), mixed.clone())];
            assert_eq!(extracted_set(&streamed, None), expected);
        }
    }

    #[test]
    fn an_incompressible_member_in_a_set_grows_by_no_more_than_the_margin() {
        let noise = noise(1024 * 1024 + 7);
        let total = |set: &[Vec<u8>]| set.iter().map(Vec::len).sum::<usize>();
        for (options, margin) in [
            (rar40(), 128),
            (rar20(3, false), 128),
            (rar15(3, false), 48),
        ] {
            // The noise starts with most of a volume, or a few bytes, to be judged by.
            for lead_len in [100, 99_800] {
                let lead = super::tests::noise(lead_len);
                let contents = [("lead.bin", &lead[..]), ("noise.bin", &noise[..])];
                let (members, _) = counted_entries(&contents);
                let set = |coding| volume_set(&members, options, coding, 100_000, 256 * 1024, None);

                let compressed = set(crate::MemberCoding::Compressed).unwrap();

                let stored = set(crate::MemberCoding::Stored).unwrap();
                let case = format!("{:?}, a {lead_len} byte lead", options.target);
                assert!(
                    total(&compressed) <= total(&stored) + noise.len() / margin,
                    "{case}: {} bytes against {} stored",
                    total(&compressed),
                    total(&stored)
                );
                assert!(compressed.iter().all(|volume| volume.len() <= 100_000));
                let expected: Vec<_> = contents
                    .iter()
                    .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
                    .collect();
                assert_eq!(extracted_set(&compressed, None), expected, "{case}");
            }
        }
    }

    #[test]
    fn a_ppmd_member_starting_at_a_volume_end_waits_to_be_judged() {
        let lead = noise(99_800);
        let text = word_text(1024 * 1024);
        let contents = [("lead.bin", &lead[..]), ("text.txt", &text[..])];
        let (members, _) = counted_entries(&contents);

        let set = volume_set(
            &members,
            rar40(),
            crate::MemberCoding::Compressed,
            100_000,
            256 * 1024,
            None,
        )
        .unwrap();

        let first = crate::rar15_40::Archive::parse(&set[0]).unwrap();
        let start = first.files().nth(1).unwrap();
        assert!(start.pack_size < 34, "{} bytes", start.pack_size);
        assert_eq!(start.method, 0x33);
        let expected: Vec<_> = contents
            .iter()
            .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
            .collect();
        assert_eq!(extracted_set(&set, None), expected);
    }

    #[test]
    fn a_member_over_4_gib_streams_into_a_set_but_is_refused_in_memory() {
        use crate::atomic64::AtomicU64;
        use std::sync::atomic::Ordering;

        const SIZE: u64 = (4 << 30) + 4099;
        struct Pattern(u64);
        impl std::io::Read for Pattern {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = (SIZE - self.0).min(buffer.len() as u64) as usize;
                for (offset, byte) in buffer[..count].iter_mut().enumerate() {
                    let at = self.0 + offset as u64;
                    *byte = (at ^ (at >> 13)) as u8;
                }
                self.0 += count as u64;
                Ok(count)
            }
        }
        impl std::io::Seek for Pattern {
            fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0 = match from {
                    std::io::SeekFrom::Start(at) => at,
                    std::io::SeekFrom::End(delta) => SIZE.saturating_add_signed(delta),
                    std::io::SeekFrom::Current(delta) => self.0.saturating_add_signed(delta),
                }
                .min(SIZE);
                Ok(self.0)
            }
        }
        struct CancelPast(AtomicU64);
        impl crate::WriteProgress for CancelPast {
            fn report(&self, event: crate::WriteProgressEvent<'_>) {
                if let crate::WriteProgressEvent::Advanced {
                    completed_bytes, ..
                } = event
                {
                    self.0.fetch_max(completed_bytes, Ordering::Relaxed);
                }
            }

            fn is_cancelled(&self) -> bool {
                self.0.load(Ordering::Relaxed) > 1024 * 1024
            }
        }
        let members = [super::StreamingEntry::new(
            b"big.bin".to_vec(),
            crate::EntrySource::from_opener(SIZE, || Ok(Box::new(Pattern(0)))),
        )];
        // A small window keeps the segment coded before cancellation small.
        let mut options = rar40();
        options.dictionary_size = Some(64 * 1024);
        let set = |stream_above| {
            volume_set(
                &members,
                options,
                crate::MemberCoding::Compressed,
                64 << 20,
                stream_above,
                Some(&CancelPast(AtomicU64::new(0))),
            )
        };

        assert!(matches!(set(256 * 1024), Err(crate::Error::Cancelled)));
        let Err(crate::Error::AtEntry { source, .. }) = set(u64::MAX) else {
            panic!("a member over 4 GiB was coded in memory");
        };
        assert!(
            matches!(*source, crate::Error::InvalidArgument(_)),
            "{source}"
        );
    }

    #[test]
    fn solid_members_stream_into_a_set_on_the_chain() {
        let large = binary_member(1024 * 1024 + 4321);
        let noise = noise(1024 * 1024 + 7);
        let mut options = rar40();
        options.features.solid = true;
        let (members, opens) = counted_entries(&[
            ("before.bin", &large[1000..41000]),
            ("large.bin", &large),
            ("after.bin", &large[large.len() - 40000..]),
            ("noise.bin", &noise),
            ("last.bin", &large[5000..45000]),
        ]);
        let coding = || crate::MemberCoding::Compressed;

        // Allowed no growth, the noise is stored, as it is in memory.
        let streamed = super::volumes::with_commit_growth(u64::MAX, || {
            volume_set(&members, options, coding(), 100_000, 256 * 1024, None)
        })
        .unwrap();

        assert!(
            opens.load(std::sync::atomic::Ordering::Relaxed) > 5,
            "the large members were not streamed"
        );
        let whole = volume_set(&members, options, coding(), 100_000, u64::MAX, None).unwrap();
        assert_eq!(streamed, whole);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn password_protected_members_stream_into_a_set() {
        // Over the 256 KiB members stream above, and several volumes long.
        let large = binary_member(512 * 1024 + 4321);
        let noise = noise(300 * 1024 + 7);
        let contents = [
            ("small.txt", &b"small and below the threshold\n"[..]),
            ("large.bin", &large[..]),
            ("noise.bin", &noise[..]),
        ];
        let (members, opens) = counted_entries(&contents);
        let members: Vec<_> = members
            .into_iter()
            .map(|entry| entry.with_password(b"password".to_vec()))
            .collect();
        let sizes = |volumes: &[Vec<u8>]| {
            volumes
                .iter()
                .flat_map(|volume| {
                    crate::rar15_40::Archive::parse_with_password(volume, Some(b"password"))
                        .unwrap()
                        .files()
                        .map(|file| (file.method, file.pack_size))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        let expected: Vec<_> = contents
            .iter()
            .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
            .collect();

        for (header_encryption, solid) in [(false, false), (true, false), (true, true)] {
            let mut options = rar40();
            options.features.header_encryption = header_encryption;
            options.features.solid = solid;
            let coding = || crate::MemberCoding::Compressed;
            let case = format!("-hp {header_encryption}, solid {solid}");

            // Allowed no growth, the noise is stored, as it is in memory.
            let streamed = super::volumes::with_commit_growth(u64::MAX, || {
                volume_set(&members, options, coding(), 100_000, 256 * 1024, None)
            })
            .unwrap();

            let whole = volume_set(&members, options, coding(), 100_000, u64::MAX, None).unwrap();
            assert_eq!(sizes(&streamed), sizes(&whole), "{case}");
            assert_eq!(
                streamed.iter().map(Vec::len).collect::<Vec<_>>(),
                whole.iter().map(Vec::len).collect::<Vec<_>>(),
                "{case}"
            );
            assert_eq!(
                extracted_set(&streamed, Some(b"password")),
                expected,
                "{case}"
            );
        }
        assert!(
            opens.load(std::sync::atomic::Ordering::Relaxed) > 12,
            "the large members were not streamed"
        );
    }

    #[test]
    fn a_member_streaming_into_a_set_reports_progress_and_can_be_cancelled() {
        use crate::atomic64::AtomicU64;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Default)]
        struct CancelPast {
            limit: u64,
            done: AtomicU64,
            volumes: AtomicUsize,
        }
        impl crate::WriteProgress for CancelPast {
            fn report(&self, event: crate::WriteProgressEvent<'_>) {
                match event {
                    crate::WriteProgressEvent::Advanced {
                        completed_bytes, ..
                    } => {
                        self.done.fetch_max(completed_bytes, Ordering::Relaxed);
                    }
                    crate::WriteProgressEvent::VolumeFinished { .. } => {
                        self.volumes.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }

            fn is_cancelled(&self) -> bool {
                self.done.load(Ordering::Relaxed) > self.limit
            }
        }

        let large = binary_member(2 * 1024 * 1024);
        let members = entries(&[("large.bin", &large)]);
        let coding = || crate::MemberCoding::Compressed;

        let finished = CancelPast {
            limit: u64::MAX,
            ..CancelPast::default()
        };
        let set = volume_set(
            &members,
            rar40(),
            coding(),
            100_000,
            256 * 1024,
            Some(&finished),
        )
        .unwrap();
        assert_eq!(finished.done.load(Ordering::Relaxed), large.len() as u64);
        assert_eq!(finished.volumes.load(Ordering::Relaxed), set.len());

        let cancelled = CancelPast {
            limit: 512 * 1024,
            ..CancelPast::default()
        };
        assert!(matches!(
            volume_set(
                &members,
                rar40(),
                coding(),
                100_000,
                256 * 1024,
                Some(&cancelled)
            ),
            Err(crate::Error::Cancelled)
        ));
        assert!(cancelled.done.load(Ordering::Relaxed) < large.len() as u64);
    }

    #[test]
    fn a_streamed_member_is_charged_what_it_holds_not_its_size() {
        const MIB: u64 = 1024 * 1024;
        let coding = crate::MemberCoding::Compressed;
        let mut independent = rar40();
        independent.dictionary_size = Some(4 * MIB as usize);
        let mut solid = independent;
        solid.features.solid = true;

        for options in [independent, solid] {
            let charge = super::streamed_workspace(options, &coding);
            assert!(charge < 256 * MIB, "{} MiB", charge / MIB);
            assert!(charge < super::member_workspace(options, 1 << 30, true));
        }
    }

    #[test]
    fn retained_archive_comment_metadata_requires_rar3_or_4_comment() {
        let mut options = super::WriterOptions::new(
            crate::ArchiveVersion::Rar30,
            crate::FeatureSet::store_only(),
        );
        options.archive_comment_metadata = Some((123, 0));
        let shape = crate::write_plan::PlanShape::new();
        assert_eq!(
            super::validate_plan(options, shape, false, false).unwrap_err(),
            crate::Error::InvalidArgument(
                "retained archive comment metadata requires a CMT archive comment"
            )
        );
        options.target = crate::ArchiveVersion::Rar20;
        assert_eq!(
            super::validate_plan(options, shape, true, false).unwrap_err(),
            crate::Error::InvalidArgument(
                "retained archive comment metadata requires a CMT archive comment"
            )
        );
        options.target = crate::ArchiveVersion::Rar30;
        assert!(super::validate_plan(options, shape, true, false).is_ok());
    }

    #[test]
    fn writer_limits_and_invalid_options_are_not_archive_corruption() {
        for error in [
            super::validate_member(b"", ArchiveVersion::Rar40, 0).unwrap_err(),
            super::validate_member(&vec![b'a'; 65536], ArchiveVersion::Rar40, 0).unwrap_err(),
            super::checked_align16(usize::MAX, "padding overflow").unwrap_err(),
            super::write_comment_header(&mut Vec::new(), Some(&vec![0; 65536])).unwrap_err(),
            super::header_encryption_password([Some(&b"one"[..]), Some(&b"two"[..])].into_iter())
                .unwrap_err(),
            super::validate_rar29_filter_policy(
                &super::FilterPolicy::Auto,
                super::Rar29Method::Ppmd,
            )
            .unwrap_err(),
            super::rar29_encode_options_for_level(Some(6)).unwrap_err(),
            super::rar20_encode_options_for_level(Some(6)).unwrap_err(),
            super::rar15_encode_options_for_level(Some(6)).unwrap_err(),
        ] {
            assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument, "{error}");
        }
        assert_eq!(super::checked_align16(17, "padding overflow").unwrap(), 32);
        assert_eq!(
            super::header_encryption_password([None].into_iter()).unwrap_err(),
            crate::Error::NeedPassword
        );
        let large = u64::from(u32::MAX) + 1;
        assert_eq!(
            super::validate_member(b"large", ArchiveVersion::Rar15, large).unwrap_err(),
            crate::Error::InvalidArgument("RAR 1.5 archives cannot hold a member over 4 GiB")
        );
        for target in [
            ArchiveVersion::Rar20,
            ArchiveVersion::Rar29,
            ArchiveVersion::Rar30,
            ArchiveVersion::Rar40,
        ] {
            super::validate_member(b"large", target, large).unwrap();
        }
    }

    fn file_header_of_size(target: ArchiveVersion, size: u64, comment: Option<&[u8]>) -> Vec<u8> {
        file_header_of_sizes(target, size, size, comment)
    }

    fn file_header_of_sizes(
        target: ArchiveVersion,
        unpacked: u64,
        packed: u64,
        comment: Option<&[u8]>,
    ) -> Vec<u8> {
        let extra = super::encode_file_comment(comment).unwrap();
        let mut header = Vec::new();
        super::write_file_header(
            &mut header,
            &super::FileRecord {
                head_type: super::FILE_HEAD,
                name: b"big.bin",
                unpacked_size: unpacked,
                file_crc: 0x1234_5678,
                packed_size: packed,
                file_time: 0,
                file_attr: 0x20,
                host_os: 0,
                target,
                method: 0x30,
                dictionary_flags: 0,
                flags: super::writer_file_flags(None, comment, false),
                salt: None,
                extra: &extra,
            },
        )
        .unwrap();
        header
    }

    #[test]
    fn rar29_members_past_2_gib_carry_the_large_size_fields() {
        let large = |header: &[u8]| u16::from_le_bytes([header[3], header[4]]) & 0x0100 != 0;
        let two_gib = 1u64 << 31;
        for target in [
            ArchiveVersion::Rar29,
            ArchiveVersion::Rar30,
            ArchiveVersion::Rar40,
        ] {
            let header = file_header_of_size(target, two_gib, None);
            assert!(!large(&header), "{target} at 2 GiB");
            assert_eq!(header.len(), 32 + b"big.bin".len());

            for size in [two_gib + 1, 3 << 30, u64::from(u32::MAX)] {
                let header = file_header_of_size(target, size, None);
                assert!(large(&header), "{target} at {size}");
                assert_eq!(header.len(), 40 + b"big.bin".len());
                assert_eq!(header[7..11], (size as u32).to_le_bytes());
                assert_eq!(header[32..40], [0; 8]);
            }

            // Compressed or stored and padded past 4 GiB, a member's header is one length.
            let size = u64::from(u32::MAX) - 7;
            let compressed = file_header_of_sizes(target, size, 1000, None);
            let stored = file_header_of_sizes(target, size, size.next_multiple_of(16), None);
            assert_eq!(compressed.len(), stored.len(), "{target}");
        }
    }

    #[test]
    fn an_encrypted_rar20_member_near_4_gib_keeps_its_header_length_when_patched() {
        let header_for = |target: ArchiveVersion, unpacked: u64, packed: u64| {
            let mut header = Vec::new();
            super::write_file_header(
                &mut header,
                &super::FileRecord {
                    head_type: super::FILE_HEAD,
                    name: b"big.bin",
                    unpacked_size: unpacked,
                    file_crc: 0,
                    packed_size: packed,
                    file_time: 0,
                    file_attr: 0x20,
                    host_os: 0,
                    target,
                    method: 0x33,
                    dictionary_flags: 0,
                    flags: super::writer_file_flags(Some(b"secret"), None, false),
                    salt: None,
                    extra: &[],
                },
            )
            .unwrap();
            header
        };
        let header = |unpacked, packed| header_for(ArchiveVersion::Rar20, unpacked, packed);
        let large = |header: &[u8]| u16::from_le_bytes([header[3], header[4]]) & 0x0100 != 0;
        let max = u64::from(u32::MAX);

        // Begun with no packed size, then patched with a padded compressed or stored one.
        for size in max - 20..max {
            let begun = header(size, 0);
            for packed in [(size - 1).next_multiple_of(16), size.next_multiple_of(16)] {
                assert_eq!(header(size, packed).len(), begun.len(), "{size}: {packed}");
            }
            assert_eq!(large(&begun), size.next_multiple_of(16) > max, "{size}");
        }
        assert!(!large(&header(max - 15, 0)));
        assert!(large(&header(max - 14, 0)));

        // Unencrypted, nothing pads, so the short fields last up to `u32::MAX - 1`.
        assert!(!large(&file_header_of_sizes(
            ArchiveVersion::Rar20,
            max - 1,
            max - 1,
            None
        )));
        // RAR 1.5 encrypts without padding and has no high fields to take.
        assert!(!large(&header_for(ArchiveVersion::Rar15, max - 1, max - 1)));
    }

    /// A member handed over as bytes, for the charge tests below.
    fn handed_over<'a>(data: &'a [u8], password: Option<&'a [u8]>) -> super::FileEntry<'a> {
        super::FileEntry {
            name: b"member.bin",
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password,
            file_comment: None,
        }
    }

    /// The passwords a test can write with in this build.
    fn passwords() -> Vec<Option<&'static [u8]>> {
        let mut passwords: Vec<Option<&'static [u8]>> = vec![None];
        if cfg!(feature = "encryption") {
            passwords.push(Some(b"password"));
        }
        passwords
    }

    #[test]
    fn a_stored_member_is_written_from_the_bytes_it_was_handed() {
        let data = binary_member(300_000);
        for target in [
            ArchiveVersion::Rar15,
            ArchiveVersion::Rar20,
            ArchiveVersion::Rar40,
        ] {
            for password in passwords() {
                let case = format!("{target:?}, password {}", password.is_some());
                let options = super::WriterOptions::new(target, FeatureSet::store_only());
                let entry = handed_over(&data, password);
                let member = super::Member::from_file(&entry);
                let resources = crate::WriterResources::default();
                let work =
                    super::WorkTracker::new(None, crate::WriteOperation::Compression, u64::MAX);
                let encoded = super::encode_member(
                    &member,
                    options,
                    &crate::MemberCoding::Stored,
                    &mut None,
                    &resources,
                    &work,
                )
                .unwrap();
                // The payload is the caller's bytes, not a copy of them, so
                // the charge is the buffer it is written through.
                let super::MemberPayload::Borrowed(bytes) = encoded.payload else {
                    panic!("{case}: a stored member was copied");
                };
                assert_eq!(bytes.as_ptr(), data.as_ptr(), "{case}");
                assert_eq!(
                    resources.workspace_in_use(),
                    super::WRITE_WORKSPACE,
                    "{case}"
                );
                drop(encoded);
                assert_eq!(resources.workspace_in_use(), 0, "{case}");

                let archive = super::collect_archive(
                    &[member],
                    options,
                    crate::MemberCoding::Stored,
                    None,
                    None,
                )
                .unwrap();
                assert_eq!(
                    extracted_set(std::slice::from_ref(&archive), password),
                    [(b"member.bin".to_vec(), data.clone())],
                    "{case}"
                );
                // RAR 1.5 and 2.0 draw no salt, so the bytes must match the
                // ones a source copied through the same cipher gives.
                if target != ArchiveVersion::Rar40 {
                    let mut streaming = super::StreamingEntry::new(
                        b"member.bin".to_vec(),
                        super::EntrySource::from_bytes(data.clone()),
                    )
                    .with_file_attr(0x20)
                    .with_host_os(3);
                    if let Some(password) = password {
                        streaming = streaming.with_password(password.to_vec());
                    }
                    let from_source = super::collect_archive(
                        &[super::Member::from_streaming(&streaming)],
                        options,
                        crate::MemberCoding::Stored,
                        None,
                        None,
                    )
                    .unwrap();
                    assert_eq!(archive, from_source, "{case}");
                }
            }
        }
    }

    #[test]
    fn level_zero_writes_a_member_from_the_bytes_it_was_handed() {
        let data = binary_member(300_000);
        for target in [
            ArchiveVersion::Rar15,
            ArchiveVersion::Rar20,
            ArchiveVersion::Rar40,
        ] {
            let mut options = super::WriterOptions::new(target, FeatureSet::default());
            options.compression_level = Some(0);
            let entry = handed_over(&data, None);
            let member = super::Member::from_file(&entry);
            let coding = super::level_coding(options, &crate::MemberCoding::Compressed);
            assert!(matches!(coding, crate::MemberCoding::Stored), "{target:?}");
            let resources = crate::WriterResources::default();
            let work = super::WorkTracker::new(None, crate::WriteOperation::Compression, u64::MAX);
            let encoded =
                super::encode_member(&member, options, coding, &mut None, &resources, &work)
                    .unwrap();
            let super::MemberPayload::Borrowed(bytes) = encoded.payload else {
                panic!("{target:?}: a level 0 member was copied");
            };
            assert_eq!(bytes.as_ptr(), data.as_ptr(), "{target:?}");
            assert_eq!(resources.workspace_in_use(), super::WRITE_WORKSPACE);
            drop(encoded);

            // Writing it so is writing it stored, as level 0 always did.
            let write = |coding| {
                super::collect_archive(
                    &[super::Member::from_file(&entry)],
                    options,
                    coding,
                    None,
                    None,
                )
                .unwrap()
            };
            let archive = write(crate::MemberCoding::Compressed);
            assert_eq!(archive, write(crate::MemberCoding::Stored), "{target:?}");
            assert_eq!(
                extracted_set(&[archive], None),
                [(b"member.bin".to_vec(), data.clone())]
            );
        }
    }

    #[test]
    fn a_coded_member_is_charged_for_its_packed_form_until_it_is_written() {
        let data = binary_member(300_000);
        for target in [
            ArchiveVersion::Rar15,
            ArchiveVersion::Rar20,
            ArchiveVersion::Rar40,
        ] {
            for password in passwords() {
                let case = format!("{target:?}, password {}", password.is_some());
                let options = super::WriterOptions::new(target, FeatureSet::default());
                let entry = handed_over(&data, password);
                let member = super::Member::from_file(&entry);
                let resources = crate::WriterResources::default();
                let work =
                    super::WorkTracker::new(None, crate::WriteOperation::Compression, u64::MAX);
                let encoded = super::encode_member(
                    &member,
                    options,
                    &crate::MemberCoding::Compressed,
                    &mut None,
                    &resources,
                    &work,
                )
                .unwrap();
                let super::MemberPayload::Packed(packed) = &encoded.payload else {
                    panic!("{case}: a coded member is in memory");
                };
                assert!(packed.len() < data.len(), "{case}");
                if password.is_some() {
                    // Room for the cipher's padding, so encrypting it in
                    // place moves nothing.
                    assert!(packed.capacity() >= packed.len() + 15, "{case}");
                }
                // The coder's charge is cut to the packed form once it is done,
                // and that much stays charged until the member is written.
                let held = encoded.held.as_ref().unwrap().bytes();
                assert!(held >= packed.capacity() as u64, "{case}");
                assert!(
                    held < super::member_workspace(options, data.len() as u64, true),
                    "{case}"
                );
                assert_eq!(resources.workspace_in_use(), held, "{case}");
                let mut out = Vec::new();
                super::write_member(
                    &mut out,
                    &member,
                    encoded,
                    options,
                    false,
                    None,
                    &mut super::DataKeys::default(),
                    None,
                )
                .unwrap();
                assert_eq!(resources.workspace_in_use(), 0, "{case}");
            }
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn a_tight_budget_on_many_threads_writes_what_one_thread_writes() {
        /// Fails the test when a payload write isn't covered by the budget, which
        /// is what a member's charge holding until it is written promises.
        struct ChargedWrites<'a> {
            out: std::io::Cursor<Vec<u8>>,
            resources: &'a crate::WriterResources,
            payload_writes: usize,
        }

        impl std::io::Write for ChargedWrites<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                // Headers are written outside any charge; payloads aren't.
                if bytes.len() > 512 {
                    self.payload_writes += 1;
                    let charged = self.resources.workspace_in_use();
                    assert!(
                        charged >= bytes.len() as u64,
                        "{} bytes written with {charged} charged",
                        bytes.len()
                    );
                }
                self.out.write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl std::io::Seek for ChargedWrites<'_> {
            fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
                self.out.seek(from)
            }
        }

        const STREAM_ABOVE: u64 = 96 * 1024;
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Coded members, ones coding doesn't shrink, streamed ones, an
            // empty one and a directory, so every kind of member waits in a
            // window for the ones before it.
            let datas: Vec<Vec<u8>> = (0..30usize)
                .map(|index| match index % 5 {
                    _ if index == 7 || index == 12 => Vec::new(),
                    0 | 2 => binary_member(24_000 + index * 1_500),
                    1 => noise(8_000 + index * 700),
                    3 => binary_member(STREAM_ABOVE as usize + 4_000 + index * 900),
                    _ => b"several threads, a small budget\n".repeat(400 + index * 20),
                })
                .collect();
            let names: Vec<Vec<u8>> = (0..datas.len())
                .map(|index| format!("member-{index:02}").into_bytes())
                .collect();
            let entries: Vec<_> = datas
                .iter()
                .zip(&names)
                .map(|(data, name)| super::FileEntry {
                    name,
                    ..handed_over(data, None)
                })
                .collect();
            let members = || -> Vec<_> {
                entries
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| {
                        let mut member = super::Member::from_file(entry);
                        if index == 12 {
                            member.is_directory = true;
                            member.file_attr = 0x10;
                        }
                        member
                    })
                    .collect()
            };
            let mut written = Vec::new();
            for target in [ArchiveVersion::Rar20, ArchiveVersion::Rar40] {
                let mut options = super::WriterOptions::new(target, FeatureSet::default());
                let largest = datas.iter().map(Vec::len).max().unwrap() as u64;
                options.dictionary_size = Some(super::fitted_dictionary_size(target, largest));
                let coding = crate::MemberCoding::Compressed;
                let write = |resources: &crate::WriterResources| {
                    let mut out = ChargedWrites {
                        out: std::io::Cursor::new(Vec::new()),
                        resources,
                        payload_writes: 0,
                    };
                    super::write_archive_to(
                        &members(),
                        options,
                        coding.clone(),
                        None,
                        resources,
                        None,
                        super::ArchiveOutput::Seekable {
                            output: &mut out,
                            stream_above: STREAM_ABOVE,
                        },
                        None,
                        None,
                    )
                    .unwrap();
                    assert!(out.payload_writes > datas.len() / 2, "{target:?}");
                    out.out.into_inner()
                };
                let one = {
                    let _one = crate::parallel::ThreadCap::set(Some(1));
                    write(&crate::WriterResources::default())
                };
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(4)
                    .build()
                    .unwrap();
                let many = pool.install(|| {
                    // Room for two or three of the largest charges at once, so
                    // windows close early and members wait in them.
                    let largest_charge = members()
                        .iter()
                        .map(|member| {
                            let len = member.unpacked_size().unwrap();
                            super::member_charge(member, options, &coding, len)
                                .unwrap_or(0)
                                .max(super::streamed_workspace(options, &coding))
                        })
                        .max()
                        .unwrap();
                    let resources = crate::WriterResources::new(largest_charge * 5 / 2);
                    let archive = write(&resources);
                    assert_eq!(resources.workspace_in_use(), 0, "{target:?}");
                    archive
                });
                assert!(one == many, "{target:?}: threads changed the archive");
                let directory = b"member-12".as_slice();
                assert_eq!(
                    extracted_set(&[many], None)
                        .into_iter()
                        .filter(|(name, _)| name != directory)
                        .collect::<Vec<_>>(),
                    names
                        .iter()
                        .zip(&datas)
                        .enumerate()
                        .filter(|(index, _)| *index != 12)
                        .map(|(_, (name, data))| (name.clone(), data.clone()))
                        .collect::<Vec<_>>(),
                    "{target:?}"
                );
                written.push(target);
            }
            sender.send(written).unwrap();
        });
        let written = receiver
            .recv_timeout(std::time::Duration::from_secs(600))
            .expect("a window waited on what its own members hold");
        assert_eq!(written, [ArchiveVersion::Rar20, ArchiveVersion::Rar40]);
    }

    #[test]
    fn rar15_and_rar20_parse_levels_are_charged_for_what_they_hold() {
        let size = 8u64 << 20;
        let charge = |target, level| {
            let mut options = super::WriterOptions::new(target, FeatureSet::default());
            options.compression_level = Some(level);
            super::member_workspace(options, size, true)
        };
        // RAR 2.0 holds the member and its packed form, and parses a block at a time.
        for level in [3, 4, 5] {
            let block = crate::codec::rar20::block_workspace(level > 3);
            assert!(charge(ArchiveVersion::Rar20, level) >= 2 * size + block);
            assert!(charge(ArchiveVersion::Rar20, level) < 2 * size + block + (16 << 20));
        }
        // So does RAR 1.5, with a match index over its 64 KiB window.
        for level in [1, 3, 5] {
            let index = crate::codec::rar13::ENCODER_WORKSPACE;
            assert!(charge(ArchiveVersion::Rar15, level) >= 2 * size + index);
            assert!(charge(ArchiveVersion::Rar15, level) < 2 * size + index + (16 << 20));
        }
        // RAR 2.9 holds the member, its packed form and its window, and level 5
        // one shortest-path parse per block it parses at once: one per thread,
        // up to sixteen. Pin one thread for the per-byte bound, so it holds on
        // any machine.
        let one = {
            let _cap = crate::parallel::ThreadCap::set(Some(1));
            charge(ArchiveVersion::Rar29, 5)
        };
        assert!(one < 50 * size, "{one}");
        let parses = crate::parallel::threads().clamp(1, 16) as u64;
        assert_eq!(
            charge(ArchiveVersion::Rar29, 5) - one,
            (parses - 1) * crate::codec::rar29::OPTIMAL_PARSE_WORKSPACE
        );
    }

    #[test]
    fn a_rar20_member_of_all_ones_bytes_gives_its_size_in_full() {
        let large = |header: &[u8]| u16::from_le_bytes([header[3], header[4]]) & 0x100 != 0;
        let short = file_header_of_size(ArchiveVersion::Rar20, u64::from(u32::MAX) - 1, None);
        assert!(!large(&short));
        let header = file_header_of_size(ArchiveVersion::Rar20, u64::from(u32::MAX), None);
        assert!(large(&header));
        assert_eq!(header[7..11], [0xff; 4]);
        assert_eq!(header[32..40], [0; 8]);
    }

    #[test]
    fn rar20_members_past_2_gib_ask_for_a_large_file_reader() {
        let two_gib = 1u64 << 31;
        for (target, size, unp_ver) in [
            (ArchiveVersion::Rar20, two_gib - 1, 20),
            (ArchiveVersion::Rar20, two_gib, 26),
            (ArchiveVersion::Rar20, two_gib << 2, 26),
            (ArchiveVersion::Rar29, two_gib, 29),
            (ArchiveVersion::Rar40, two_gib << 2, 29),
        ] {
            let header = file_header_of_size(target, size, None);
            assert_eq!(header[24], unp_ver, "{target} at {size}");
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_member_past_4_gib_reads_back_at_its_full_size() {
        use std::io::{Seek, SeekFrom, Write};

        let size = u64::from(u32::MAX) + 2;
        for (target, comment) in [
            (ArchiveVersion::Rar20, None),
            (ArchiveVersion::Rar40, None),
            (ArchiveVersion::Rar40, Some(&b"note"[..])),
        ] {
            let dir = crate::scratch::case("rars-rar15-40-large-header");
            let path = dir.join("big.rar");
            let mut file = std::fs::File::create(&path).unwrap();
            let mut head = super::RAR15_SIGNATURE.to_vec();
            super::write_main_header(&mut head, 0);
            head.extend_from_slice(&file_header_of_size(target, size, comment));
            file.write_all(&head).unwrap();
            // Sparse: the payload is never written, only skipped over.
            file.seek(SeekFrom::Current(size as i64)).unwrap();
            file.write_all(&super::end_block(super::ENDARC_FLAGS))
                .unwrap();
            drop(file);

            let archive = crate::rar15_40::Archive::parse_path(&path).unwrap();
            let member = archive.files().next().unwrap();
            assert_eq!(member.name, b"big.bin");
            assert_eq!((member.pack_size, member.unp_size), (size, size));
            assert_eq!(member.file_crc, 0x1234_5678);
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_member_between_2_and_4_gib_can_be_rewritten() {
        use std::io::{Seek, SeekFrom, Write};

        let size = 3u64 << 30;
        let dir = crate::scratch::case("rars-rar15-40-2-to-4-gib-rewrite");
        let path = dir.join("big.rar");
        let mut file = std::fs::File::create(&path).unwrap();
        let mut head = super::RAR15_SIGNATURE.to_vec();
        super::write_main_header(&mut head, 0);
        head.extend_from_slice(&file_header_of_size(ArchiveVersion::Rar40, size, None));
        file.write_all(&head).unwrap();
        // Sparse: the payload is never written, only skipped over.
        file.seek(SeekFrom::Current(size as i64)).unwrap();
        file.write_all(&super::end_block(super::ENDARC_FLAGS))
            .unwrap();
        drop(file);

        let archive = crate::rar15_40::Archive::parse_path(&path).unwrap();
        assert_eq!(archive.files().next().unwrap().unp_size, size);
        assert_eq!(archive.rewrite_preservation_issues(), Vec::<String>::new());
    }

    use super::{
        encode_rar29_auto_filtered_member, encode_rar29_filtered_member,
        encode_rar29_filtered_members, is_audio_filter_candidate, rar20_encode_options_for_level,
        rar20_encode_options_for_options, rar29_encode_options_for_options, FilterKind, FilterSpec,
    };
    use crate::codec::rar29::{unpack29_decode, EncodeOptions};

    /// A member comfortably past the 1 MiB ceiling the PPMd trial used to have.
    /// Text this size kept the LZ bytes without PPMd ever being encoded to
    /// compare against, all the way up to 16 MiB.
    const OVER_THE_OLD_TRIAL_LIMIT: usize = 1024 * 1024 + 4096;
    use crate::filter_search::{
        auto_delta_filter_range, disjoint_filter_ranges, AUTO_DELTA_EDGE_SKIP,
    };
    use crate::x86_filter_scan::auto_x86_filter_ranges;
    use crate::{ArchiveVersion, FeatureSet};

    #[test]
    fn auto_x86_filter_ranges_select_dense_opcode_clusters() {
        let mut data = vec![0x41; 20_000];
        for pos in [1024, 1050, 1090, 1130] {
            data[pos] = 0xe8;
        }
        for pos in [12_000, 12_040, 12_080] {
            data[pos] = 0xe9;
        }

        let e8_ranges = auto_x86_filter_ranges(&data, false);
        assert_eq!(e8_ranges.len(), 1);
        assert!(e8_ranges[0].contains(&1024));
        assert!(e8_ranges[0].contains(&(1130 + 4)));
        assert!(!e8_ranges[0].contains(&12_000));

        let e8e9_ranges = auto_x86_filter_ranges(&data, true);
        assert_eq!(e8e9_ranges.len(), 3);
        assert!(e8e9_ranges[0].contains(&1024));
        assert!(e8e9_ranges[0].contains(&12_000));
        assert!(e8e9_ranges.iter().any(|range| range.contains(&1024)));
        assert!(e8e9_ranges.iter().any(|range| range.contains(&12_000)));
    }

    #[test]
    fn large_text_ppmd_candidate_accepts_html_like_payloads() {
        let mut data = vec![b'a'; OVER_THE_OLD_TRIAL_LIMIT];
        for index in (0..data.len()).step_by(79) {
            data[index] = b'\n';
        }
        data[..32].copy_from_slice(b"<html><body>RAR PPMd text sample");

        assert!(super::is_text_ppmd_candidate(&data));
    }

    /// Reading past padding leaves the question of a member that is nothing
    /// else. There is no evidence either way in it, and PPMd is not the answer
    /// to a member the store rule is about to take anyway.
    #[test]
    fn a_member_of_nothing_but_padding_is_not_text() {
        let data = vec![0u8; OVER_THE_OLD_TRIAL_LIMIT];

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// Scattered NULs are not padding and still count against the member: a
    /// run has to be long enough to be structure before it is discounted.
    #[test]
    fn scattered_nuls_still_read_as_binary() {
        let mut data = vec![b'A'; OVER_THE_OLD_TRIAL_LIMIT];
        for index in (0..data.len()).step_by(3) {
            data[index] = 0;
        }

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// The bench corpus is man pages in several languages, and counting only
    /// ASCII scored the sample 77% against an 85% bar and sent it to LZ.
    #[test]
    fn the_text_screen_reads_multibyte_utf8_as_text() {
        let line = "Überprüfen Sie die Größe der Datei — ändern Sie sie nicht. \
                    日本語のマニュアルページもテキストです。\n";
        let data = line.repeat(4096).into_bytes();

        let high = data.iter().filter(|&&byte| byte >= 0x80).count();
        assert!(
            high * 100 / data.len() > 15,
            "sample must be multibyte enough to have failed the ASCII-only test"
        );
        assert!(super::is_text_ppmd_candidate(&data));
    }

    /// Accepting multibyte sequences must not accept binary that happens to
    /// contain a few: a lead byte followed by a continuation byte turns up at
    /// random often enough to notice, nowhere near often enough to pass.
    #[test]
    fn the_text_screen_still_rejects_high_entropy_binary() {
        let mut state = 0x1234_5678u32;
        let data: Vec<_> = (0..64_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// A tar pads every member to a 512 byte block and closes with a block of
    /// nothing, which is 27% NUL in front of a 1% bar. The source tree in the
    /// bench corpus was read as binary and packed 22% behind WinRAR 3.00 for it.
    #[test]
    fn the_text_screen_reads_past_tar_padding() {
        let mut data = Vec::new();
        for index in 0..512 {
            let mut header = vec![0u8; 512];
            let name = format!("src/module{index}.rs");
            header[..name.len()].copy_from_slice(name.as_bytes());
            data.extend_from_slice(&header);
            let body = format!(
                "pub fn thing{index}(value: usize) -> usize {{\n    value.wrapping_mul({index})\n}}\n"
            );
            data.extend_from_slice(body.as_bytes());
            // Every member is padded out to the next block boundary.
            data.resize(data.len().next_multiple_of(512), 0);
        }
        data.extend_from_slice(&[0u8; 1024]);

        let nul = data.iter().filter(|&&byte| byte == 0).count();
        assert!(
            nul * 100 / data.len() > 15,
            "the padding has to be heavy enough to have failed the old rule"
        );
        assert!(super::is_text_ppmd_candidate(&data));
    }

    /// The other side of that: an object file is full of NUL runs too, and
    /// reading past them must not turn its code into text. A member wrongly
    /// called text skips the x86 filter search, so this one costs bytes.
    #[test]
    fn reading_past_padding_does_not_make_an_object_file_text() {
        let mut state = 0x8badf00du32;
        let mut data = Vec::new();
        for section in 0..64 {
            // Alignment padding, the way a linker leaves it.
            data.resize(data.len() + 64, 0);
            data.extend_from_slice(format!("_ZN4rars{section}E\0").as_bytes());
            for _ in 0..1024 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                data.push(state as u8);
            }
        }

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    /// Naming the level you were already getting must not change the archive.
    /// The default resolves to method 0x33, the same as `--level 3`, but the
    /// trial decision read the option rather than the level and the two came
    /// out 24% apart on the same text.
    #[test]
    fn the_default_level_and_level_three_agree_about_the_ppmd_trial() {
        let options = crate::rar15_40::WriterOptions {
            target: crate::ArchiveVersion::Rar30,
            ..Default::default()
        };
        let default_level = super::compression_method_for_level(options);
        let named_level = super::compression_method_for_level(crate::rar15_40::WriterOptions {
            compression_level: Some(3),
            ..options
        });

        assert_eq!(default_level, named_level);
        assert_eq!(
            super::ppmd_trial_pays(default_level - 0x30),
            super::ppmd_trial_pays(named_level - 0x30),
        );
        assert!(super::ppmd_trial_pays(3));
        assert!(!super::ppmd_trial_pays(2));
    }

    #[test]
    fn auto_ppmd_candidate_rejects_binary_audio_shaped_payloads() {
        let mut data = Vec::new();
        for sample in 0..8192i16 {
            let left = sample.wrapping_mul(5).wrapping_add(200);
            let right = sample.wrapping_mul(7).wrapping_sub(200);
            data.extend_from_slice(&left.to_le_bytes());
            data.extend_from_slice(&right.to_le_bytes());
        }

        assert!(!super::is_text_ppmd_candidate(&data));
    }

    #[test]
    fn auto_ppmd_candidate_accepts_text_payloads() {
        let data = b"fn main() {\n    println!(\"rar ppmd text candidate\");\n}\n".repeat(256);

        assert!(super::is_text_ppmd_candidate(&data));
    }

    #[test]
    fn audio_filter_candidate_accepts_interleaved_pcm_like_payloads() {
        let mut data = Vec::new();
        for sample in 0..4096i16 {
            let left = sample.wrapping_mul(3).wrapping_add(200);
            let right = sample.wrapping_mul(3).wrapping_sub(200);
            data.extend_from_slice(&left.to_le_bytes());
            data.extend_from_slice(&right.to_le_bytes());
        }

        assert!(is_audio_filter_candidate(&data, 4));
        assert!(!is_audio_filter_candidate(&data, 3));
        assert!(!is_audio_filter_candidate(&data, 0));
        assert!(!is_audio_filter_candidate(&data, 5));
    }

    #[test]
    fn audio_filter_candidate_checks_the_smallest_admitted_window() {
        for channels in 1..=4 {
            assert!(!is_audio_filter_candidate(
                &vec![0; channels * 64 - 1],
                channels
            ));
            assert!(is_audio_filter_candidate(&vec![0; channels * 64], channels));
        }
    }

    #[test]
    fn rar15_unix_directory_and_file_modes_become_dos_attributes() {
        use crate::ArchiveVersion;

        assert_eq!(
            super::rar15_compatible_metadata(ArchiveVersion::Rar15, 3, 0o040755),
            (0, 0x10)
        );
        assert_eq!(
            super::rar15_compatible_metadata(ArchiveVersion::Rar15, 3, 0o100644),
            (0, 0x20)
        );
        assert_eq!(
            super::rar15_compatible_metadata(ArchiveVersion::Rar20, 3, 0o040755),
            (3, 0o040755)
        );
    }

    #[test]
    fn codec_progress_restart_counts_new_work_and_preserves_codec_errors() {
        use crate::write_progress::{ProgressReporter, WorkTracker};
        use crate::{WriteOperation, WriteProgressEvent};
        use std::sync::Mutex;

        let advanced = Mutex::new(Vec::new());
        let reporter = |event: WriteProgressEvent<'_>| {
            if let WriteProgressEvent::Advanced {
                completed_bytes, ..
            } = event
            {
                advanced.lock().unwrap().push(completed_bytes);
            }
        };
        let work = WorkTracker::new(
            Some(ProgressReporter(&reporter)),
            WriteOperation::Compression,
            30,
        );
        let encoded = super::with_codec_progress(Some(&work), |progress| {
            assert!(progress(10));
            assert!(progress(3));
            assert!(progress(5));
            Ok(b"packed".to_vec())
        })
        .unwrap();
        assert_eq!(encoded, b"packed");
        assert_eq!(*advanced.lock().unwrap(), [10, 13, 15]);

        let error = super::with_codec_progress(None, |_| {
            Err(crate::codec::Error::InvalidData("injected codec failure"))
        })
        .unwrap_err();
        assert!(matches!(error, crate::Error::Codec(_)));
    }

    #[test]
    fn audio_filter_candidate_rejects_high_entropy_binary_payloads() {
        let mut state = 0xfeed_faceu32;
        let data: Vec<_> = (0..16_384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();

        for channels in 1..=4 {
            assert!(!is_audio_filter_candidate(&data, channels));
        }
    }

    /// Prose with no long repeats: PPMd's model has plenty to work with and LZ
    /// has little to match, which is the shape the engine choice exists for.
    fn prose_like_text(len: usize) -> Vec<u8> {
        const WORDS: [&str; 24] = [
            "archive",
            "compression",
            "dictionary",
            "encoder",
            "filter",
            "header",
            "member",
            "method",
            "offset",
            "payload",
            "reader",
            "solid",
            "stream",
            "volume",
            "window",
            "writer",
            "the",
            "of",
            "a",
            "and",
            "to",
            "in",
            "that",
            "with",
        ];
        let mut state = 0x9e37_79b9u32;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.extend_from_slice(WORDS[state as usize % WORDS.len()].as_bytes());
            out.push(if state.is_multiple_of(13) {
                b'\n'
            } else {
                b' '
            });
        }
        out.truncate(len);
        out
    }

    /// Text past the trial limit used to keep the LZ bytes without ever
    /// encoding PPMd to compare, which cost 24% on 2 MiB of man pages and 12%
    /// on 4 MiB. The method byte cannot tell the two engines apart (PPMd and
    /// `-m5` LZ both write 0x35), so ask for the member both ways instead.
    #[test]
    fn text_over_the_trial_limit_is_measured_against_ppmd() {
        let data = prose_like_text(OVER_THE_OLD_TRIAL_LIMIT);
        assert!(super::is_text_ppmd_candidate(&data));

        let offered =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, true).unwrap();
        let lz_only =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, false)
                .unwrap();

        assert!(
            offered.data.len() < lz_only.data.len(),
            "PPMd should have won this member: offered {} bytes, LZ alone {}",
            offered.data.len(),
            lz_only.data.len()
        );
    }

    /// The other half of the same rule: winning is measured, not assumed. Text
    /// that is one phrase repeating is all match and belongs to LZ, and the
    /// member has to come back no larger than LZ alone would have made it.
    #[test]
    fn text_ppmd_cannot_lose_to_the_engine_it_replaced() {
        let data = b"the quick brown fox jumps over the lazy dog. "
            .repeat(OVER_THE_OLD_TRIAL_LIMIT / 45 + 64);
        assert!(super::is_text_ppmd_candidate(&data));

        let offered =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, true).unwrap();
        let lz_only =
            encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, false)
                .unwrap();

        assert!(
            offered.data.len() <= lz_only.data.len(),
            "offering PPMd made the member bigger: {} bytes against {}",
            offered.data.len(),
            lz_only.data.len()
        );

        let plain_auto = super::encode_rar29_policy_filtered_payload(
            &data,
            &super::FilterPolicy::None,
            super::Rar29Method::Auto,
            EncodeOptions::default(),
            0x35,
            true,
            None,
            None,
        )
        .unwrap();
        let forced_ppmd = super::encode_rar29_policy_filtered_payload(
            &data,
            &super::FilterPolicy::None,
            super::Rar29Method::Ppmd,
            EncodeOptions::default(),
            0x35,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(plain_auto.data, forced_ppmd.data);
    }

    #[test]
    fn repeated_high_entropy_text_keeps_lz_when_ppmd_loses() {
        let mut state = 0x9e37_79b9u32;
        let mut block = Vec::with_capacity(64 * 1024);
        for _ in 0..64 * 1024 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            block.push(b' ' + (state % 95) as u8);
        }
        let mut data = block.clone();
        data.extend_from_slice(&block);
        assert!(super::is_text_ppmd_candidate(&data));
        let options = EncodeOptions::default();
        let offered = encode_rar29_auto_filtered_member(&data, options, 0x35, true).unwrap();
        let lz_only = encode_rar29_auto_filtered_member(&data, options, 0x35, false).unwrap();
        assert_eq!(offered.data, lz_only.data);

        let plain_offered = super::encode_rar29_policy_filtered_payload(
            &data,
            &super::FilterPolicy::None,
            super::Rar29Method::Auto,
            options,
            0x35,
            true,
            None,
            None,
        )
        .unwrap();
        let plain_lz = super::encode_rar29_policy_filtered_payload(
            &data,
            &super::FilterPolicy::None,
            super::Rar29Method::Auto,
            options,
            0x35,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(plain_offered.data, plain_lz.data);
    }

    #[test]
    fn auto_x86_filter_ranges_include_code_section_spans() {
        let mut data = vec![0x41; 32_000];
        for pos in [4096, 4128, 4160] {
            data[pos] = 0xe8;
        }
        for pos in [14_000, 14_032, 14_064] {
            data[pos] = 0xe8;
        }

        let ranges = auto_x86_filter_ranges(&data, false);

        assert!(ranges[0].contains(&4096));
        assert!(ranges[0].contains(&14_064));
        assert!(ranges.iter().any(|range| range.contains(&4096)));
        assert!(ranges.iter().any(|range| range.contains(&14_064)));
    }

    #[test]
    fn auto_x86_policy_can_encode_multiple_disjoint_ranges() {
        let mut data = vec![0x41u8; 80_000];
        for cluster_start in [8_000, 60_000] {
            for index in 0..8 {
                let pos = cluster_start + index * 64;
                data[pos] = 0xe8;
                data[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
            }
        }
        let filters: Vec<_> = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false))
            .into_iter()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();

        let packed = encode_rar29_filtered_members(&data, &filters, EncodeOptions::default())
            .expect("multi-filter RAR29 member should encode");
        let decoded = unpack29_decode(&packed, data.len()).unwrap();

        assert_eq!(filters.len(), 2);
        assert!(
            decoded == data,
            "RAR 2.9 auto multi-filter E8 round-trip failed"
        );
    }

    #[test]
    fn auto_x86_policy_considers_tight_ranges_inside_sparse_spans() {
        let mut data = Vec::new();
        data.extend((0..1024).map(|index| (index * 37 + 11) as u8));
        let first_cluster_start = data.len();
        for index in 0..16usize {
            data.extend_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, (index & 0x7f) as u8]);
            let call_pos = data.len();
            data.push(0xe8);
            let target = first_cluster_start + 0x500;
            let relative = (target as i64 - (call_pos + 5) as i64) as i32;
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5d, 0xc3]);
        }
        data.extend((0..3200).map(|index| (index * 251 + 17) as u8));
        let second_cluster_start = data.len();
        for index in 0..16usize {
            data.extend_from_slice(&[0x56, 0x8b, 0xf1, 0x83, 0xec, (index & 0x7f) as u8]);
            let call_pos = data.len();
            data.push(0xe8);
            let target = second_cluster_start + 0x500;
            let relative = (target as i64 - (call_pos + 5) as i64) as i32;
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5e, 0xc3]);
        }
        data.extend((0..1024).map(|index| (index * 53 + 7) as u8));

        let ranges = disjoint_filter_ranges(auto_x86_filter_ranges(&data, false));
        let filters: Vec<_> = ranges
            .iter()
            .cloned()
            .map(|range| FilterSpec::range(FilterKind::E8, range))
            .collect();
        let broad_range = first_cluster_start..second_cluster_start + 16 * 16;
        let broad = encode_rar29_filtered_member(
            &data,
            FilterSpec::range(FilterKind::E8, broad_range),
            EncodeOptions::default(),
        )
        .unwrap();
        let tight = encode_rar29_filtered_members(&data, &filters, EncodeOptions::default())
            .expect("tight sparse x86 filters should encode");
        let auto = encode_rar29_auto_filtered_member(&data, EncodeOptions::default(), 0x35, false)
            .unwrap();

        assert!(
            tight.len() < broad.len(),
            "tight x86 ranges should avoid filtering sparse data gaps"
        );
        assert!(auto.data.len() <= tight.len());
        assert_eq!(unpack29_decode(&auto.data, data.len()).unwrap(), data);
    }

    #[test]
    fn auto_delta_filter_range_skips_container_edges_and_aligns_channels() {
        let data = vec![0u8; 512];

        let range = auto_delta_filter_range(&data, 3).unwrap();

        assert!(range.start >= AUTO_DELTA_EDGE_SKIP);
        assert!(range.end <= data.len() - AUTO_DELTA_EDGE_SKIP);
        assert_eq!(range.start % 3, 0);
        assert_eq!((range.end - range.start) % 3, 0);
        assert!(auto_delta_filter_range(&data[..80], 3).is_none());
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

        let plain =
            crate::codec::rar29::unpack29_encode_literals_with_options(&data, options).unwrap();
        let ranged = encode_rar29_filtered_member(
            &data,
            FilterSpec::range(
                FilterKind::Delta { channels: 2 },
                auto_delta_filter_range(&data, 2).unwrap(),
            ),
            options,
        )
        .unwrap();
        let auto = encode_rar29_auto_filtered_member(&data, options, 0x35, true).unwrap();

        assert!(ranged.len() < plain.len());
        assert!(auto.data.len() <= ranged.len());
    }

    #[test]
    fn rar29_options_cap_match_distance_to_target_dictionary() {
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
                    .with_compression_level(5)
            )
            .unwrap()
            .max_match_distance,
            1024 * 1024
        );
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
                    .with_compression_level(5)
            )
            .unwrap()
            .max_match_distance,
            128 * 1024
        );
        assert_eq!(
            rar29_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
                    .with_compression_level(5)
                    .with_dictionary_size(4 * 1024 * 1024)
            )
            .unwrap()
            .max_match_distance,
            4 * 1024 * 1024
        );
    }

    #[test]
    fn rar20_options_cap_match_distance_to_header_dictionary() {
        assert_eq!(
            rar20_encode_options_for_options(super::WriterOptions::new(
                ArchiveVersion::Rar20,
                FeatureSet::store_only(),
            ))
            .unwrap()
            .max_match_distance,
            64 * 1024
        );
        assert_eq!(
            rar20_encode_options_for_options(
                super::WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only())
                    .with_dictionary_size(1024 * 1024),
            )
            .unwrap()
            .max_match_distance,
            1024 * 1024
        );
    }
    #[test]
    fn only_the_top_two_levels_pay_for_the_rar20_optimal_parse() {
        for level in 0..=3u8 {
            let options = rar20_encode_options_for_level(Some(level)).unwrap();
            assert!(!options.optimal_parse, "level {level} priced every path");
        }
        for level in 4..=5u8 {
            let options = rar20_encode_options_for_level(Some(level)).unwrap();
            assert!(options.optimal_parse, "level {level} settled for greedy");
        }
        assert!(
            !rar20_encode_options_for_level(None).unwrap().optimal_parse,
            "an absent level is the default level, which is not the top of the ladder",
        );
    }

    #[test]
    fn rar20_level_5_is_level_4_with_more_priced_passes() {
        let four = rar20_encode_options_for_level(Some(4)).unwrap();
        let five = rar20_encode_options_for_level(Some(5)).unwrap();
        // Each extra pass is kept only if it packs smaller, so level 5 can
        // never come out larger than level 4.
        assert!(five.extra_priced_passes > four.extra_priced_passes);
        assert_eq!(
            five.with_extra_priced_passes(four.extra_priced_passes),
            four
        );
    }

    #[test]
    fn every_rar20_level_looks_two_positions_ahead() {
        for level in 1..=5u8 {
            let options = rar20_encode_options_for_level(Some(level)).unwrap();
            assert!(options.lazy_matching, "level {level} stopped being lazy");
            assert_eq!(options.lazy_lookahead, 2, "level {level}");
        }
    }

    #[test]
    fn only_the_top_two_rar29_levels_pay_for_the_shortest_path() {
        for level in 0..=3u8 {
            let options = super::rar29_encode_options_for_level(Some(level)).unwrap();
            assert_eq!(options.optimal_parse_passes, 0, "level {level}");
        }
        for level in 4..=5u8 {
            let options = super::rar29_encode_options_for_level(Some(level)).unwrap();
            assert!(options.optimal_parse_passes > 0, "level {level}");
        }
        // An absent level keeps the parse the writer always used.
        let default = super::rar29_encode_options_for_level(None).unwrap();
        assert_eq!(default.optimal_parse_passes, 0);
        assert_eq!(
            (default.max_match_candidates, default.lazy_matching),
            (128, true)
        );
    }

    #[test]
    fn rar29_levels_from_two_cut_blocks_by_price() {
        let cuts = |level| {
            super::rar29_encode_options_for_level(level)
                .unwrap()
                .split_blocks
        };
        assert!(!cuts(Some(0)) && !cuts(Some(1)));
        assert!((2..=5u8).all(|level| cuts(Some(level))));
        assert!(cuts(None));
    }

    /// Each level tries every PPMd model the level below does, so text can
    /// only come out smaller further up.
    #[test]
    fn each_rar29_level_tries_the_ppmd_models_of_the_one_below() {
        for level in 3..5u8 {
            let below = super::ppmd_models_for_level(level);
            let above = super::ppmd_models_for_level(level + 1);
            assert!(above.starts_with(below), "level {}", level + 1);
        }
        assert_eq!(
            super::ppmd_models_for_level(3),
            &[crate::codec::rar29::PpmdModelSize::DEFAULT]
        );
    }

    #[test]
    fn rar29_levels_are_charged_for_the_models_and_parse_they_hold() {
        const MIB: u64 = 1024 * 1024;
        let at = |level: u8| {
            let mut options =
                super::WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only());
            options.compression_level = Some(level);
            options
        };
        let charge = |level| super::member_workspace(at(level), 8 * MIB, true);
        // Two models of the largest size a level tries, and a parse workspace
        // per block that runs at once.
        let parse = crate::codec::rar29::OPTIMAL_PARSE_WORKSPACE;
        assert_eq!(charge(2), charge(1));
        assert!(charge(4) >= charge(3) + 2 * (64 - 25) * MIB + parse);
        assert!(charge(5) >= charge(4) + 2 * (128 - 64) * MIB);
        // A member of one block parses one block at a time.
        assert_eq!(
            super::member_workspace(at(5), 1000, true) - super::member_workspace(at(3), 1000, true),
            2 * (128 - 25) * MIB + parse
        );
        // Streamed, the parse is charged by the block, not by the member.
        let coding = crate::MemberCoding::Compressed;
        let streamed = |options| super::streamed_workspace(options, &coding);
        assert!(streamed(at(5)) < super::member_workspace(at(5), 1 << 30, true));
        // A streamed trial holds two of the level's largest models, and a
        // chain keeps one between members.
        assert!(streamed(at(5)) >= streamed(at(3)) + 2 * (128 - 25) * MIB);
        let solid = |level| {
            let mut options = at(level);
            options.features.solid = true;
            options
        };
        assert!(streamed(solid(5)) >= streamed(at(5)) + 128 * MIB);
        // Forced PPMd holds models at every level, the trial's two at the top.
        let forced = |level| {
            let mut options = at(level);
            options.method = super::Rar29Method::Ppmd;
            options
        };
        assert!(super::member_workspace(forced(1), 8 * MIB, true) >= charge(1) + 2 * 25 * MIB);
        assert!(super::member_workspace(forced(5), 8 * MIB, true) >= charge(1) + 2 * 128 * MIB);
        assert!(streamed(forced(5)) >= streamed(forced(3)) + 2 * (128 - 25) * MIB);
    }

    /// Solid chains, forced PPMd and streamed members try the level's PPMd
    /// models too, so none of them packs text larger a level up.
    #[test]
    fn rar29_text_packs_no_larger_a_level_up_in_chains_forced_and_streamed() {
        let text = word_text(320 * 1024);
        let parts: [(&str, &[u8]); 3] = [
            ("one.txt", &text[..40 * 1024]),
            ("two.txt", &text[40 * 1024..100 * 1024]),
            ("three.txt", &text[100 * 1024..160 * 1024]),
        ];
        let whole: [(&str, &[u8]); 1] = [("text.txt", &text)];
        let at = |level: u8, solid: bool, method| {
            let mut options =
                super::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());
            options.compression_level = Some(level);
            options.features.solid = solid;
            options.method = method;
            options
        };
        for (name, files, streams, solid, method) in [
            ("solid", &parts[..], false, true, super::Rar29Method::Auto),
            (
                "solid PPMd",
                &parts[..],
                false,
                true,
                super::Rar29Method::Ppmd,
            ),
            ("PPMd", &parts[..], false, false, super::Rar29Method::Ppmd),
            (
                "streamed",
                &whole[..],
                true,
                false,
                super::Rar29Method::Auto,
            ),
            (
                "streamed PPMd",
                &whole[..],
                true,
                false,
                super::Rar29Method::Ppmd,
            ),
            (
                "streamed solid",
                &whole[..],
                true,
                true,
                super::Rar29Method::Auto,
            ),
        ] {
            let members = entries(files);
            let expected: Vec<_> = files
                .iter()
                .map(|(name, data)| (name.as_bytes().to_vec(), data.to_vec()))
                .collect();
            let mut below = usize::MAX;
            for level in 3..=5u8 {
                let options = at(level, solid, method);
                let coding = crate::MemberCoding::Compressed;
                let archive = if streams {
                    let out = streamed_with(&members, options, coding, None).unwrap();
                    assert!(out.seeks > 0, "{name}: not streamed");
                    out.inner.into_inner()
                } else {
                    in_memory_with(&members, options, coding)
                };
                assert!(
                    archive.len() <= below,
                    "{name}: level {level} packed {} bytes, the level below {below}",
                    archive.len()
                );
                below = archive.len();
                assert_eq!(
                    extracted_set(std::slice::from_ref(&archive), None),
                    expected,
                    "{name}: level {level}"
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn an_encrypted_stored_member_is_encrypted_as_it_is_copied() {
        let data = binary_member(4 * 1024 * 1024 + 7);
        for target in [
            ArchiveVersion::Rar15,
            ArchiveVersion::Rar20,
            ArchiveVersion::Rar29,
            ArchiveVersion::Rar40,
        ] {
            let options = super::WriterOptions::new(target, FeatureSet::store_only());
            let held = super::StoredEntry {
                name: b"held.bin",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            };
            let (source, watch) = crate::write_stream::watched_source(data.clone());
            let copied = super::StreamingEntry::new(b"copy.bin".to_vec(), source)
                .with_password(b"password".to_vec());
            // One write, so both members are encrypted under the same salt.
            let members = [
                super::Member::from_stored(&held),
                super::Member::from_streaming(&copied),
            ];
            let mut archive = Vec::new();
            super::write_archive_to(
                &members,
                options,
                crate::MemberCoding::Stored,
                None,
                &crate::WriterResources::default(),
                None,
                super::ArchiveOutput::stream(&mut watch.sink(&mut archive)),
                None,
                None,
            )
            .unwrap();

            let parsed =
                crate::rar15_40::Archive::parse_with_password(&archive, Some(b"password")).unwrap();
            let [held, copied]: [_; 2] = parsed.files().collect::<Vec<_>>().try_into().unwrap();
            assert_eq!(copied.pack_size, held.pack_size, "{target:?}");
            assert_eq!(copied.salt, held.salt, "{target:?}");
            assert_eq!(copied.file_crc, held.file_crc, "{target:?}");
            assert!(
                archive[copied.packed_range.clone()] == archive[held.packed_range.clone()],
                "{target:?}: the copied member's ciphertext differs"
            );
            // Read as it was written, so never held whole.
            let written = watch.written_while_reading();
            assert!(
                written + 1024 * 1024 >= data.len() as u64,
                "{target:?}: only {written} bytes were written while the member was read"
            );
            let extracted = extracted(&archive, Some(b"password"));
            assert_eq!(
                extracted[1],
                (b"copy.bin".to_vec(), data.clone()),
                "{target:?}"
            );
        }
    }

    /// Entries whose sources count every byte read from them.
    fn read_counted(
        members: &[(&str, &[u8])],
    ) -> (
        Vec<super::StreamingEntry>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        struct Counted(
            std::io::Cursor<Vec<u8>>,
            std::sync::Arc<std::sync::atomic::AtomicUsize>,
        );
        impl std::io::Read for Counted {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let read = self.0.read(buffer)?;
                self.1.fetch_add(read, std::sync::atomic::Ordering::Relaxed);
                Ok(read)
            }
        }
        impl std::io::Seek for Counted {
            fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0.seek(from)
            }
        }
        let read = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let entries = members
            .iter()
            .map(|(name, data)| {
                let data = data.to_vec();
                let read = read.clone();
                super::StreamingEntry::new(
                    name.as_bytes().to_vec(),
                    crate::EntrySource::from_opener(data.len() as u64, move || {
                        Ok(Box::new(Counted(
                            std::io::Cursor::new(data.clone()),
                            read.clone(),
                        )))
                    }),
                )
            })
            .collect();
        (entries, read)
    }

    #[test]
    fn streamed_rar20_noise_is_stored_without_coding_it_first() {
        // Sixteen dictionaries long, so the probe runs.
        let mut options = rar20(1, false);
        options.dictionary_size = Some(64 * 1024);
        let len = 16 * 64 * 1024 + 4321;
        let coding = || crate::MemberCoding::Compressed;

        let noise = noise(len);
        let (members, read) = read_counted(&[("noise.bin", &noise)]);
        let out = streamed_with(&members, options, coding(), None).unwrap();
        assert!(out.seeks > 0, "the member was not streamed");
        // Four samples and one copy, not a whole coding pass and a copy.
        let read = read.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            read < len + len / 2,
            "read {read} bytes of a {len} byte member"
        );
        let archive = out.inner.into_inner();
        // The archive the in-memory writer stores after coding it all.
        assert_eq!(archive, in_memory_with(&members, options, coding()));
        let parsed = crate::rar15_40::Archive::parse(&archive).unwrap();
        assert_eq!(parsed.files().next().unwrap().method, 0x30);

        // A noisy start is not the member: the second sample shrinks.
        let mut mixed = noise[..len / 4].to_vec();
        mixed.extend_from_slice(&binary_member(len - len / 4));
        let members = entries(&[("mixed.bin", &mixed)]);
        let archive = streamed_with(&members, options, coding(), None)
            .unwrap()
            .inner
            .into_inner();
        assert_eq!(archive, in_memory_with(&members, options, coding()));
        let parsed = crate::rar15_40::Archive::parse(&archive).unwrap();
        assert_ne!(parsed.files().next().unwrap().method, 0x30);
        rar20_members(&archive, false, &[&mixed]);
    }
}
