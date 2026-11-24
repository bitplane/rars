//! RAR 1.3/1.4 archive encoding and assembly.

use super::*;
use crate::codec::rar13::{
    unpack15_encode, unpack15_encode_with_options_and_progress,
    EncodeOptions as Rar15EncodeOptions, Unpack15, Unpack15Encoder,
};
use crate::features::FeatureSet;
pub use crate::streaming::{EntrySource, WriterResources};
pub use crate::write_plan::MemberCoding;
use crate::write_plan::{PlanShape, WriterOption};
use crate::write_progress::{ProgressReporter, WorkTracker};
use crate::write_stream::{CallerOutput, CancellableOutput, MemberBytes, MemberPayload};
use crate::ArchiveVersion;
use crate::{WriteOperation, WriteProgress, WriteProgressEvent};
use std::io::Seek;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
    pub compression_level: Option<u8>,
}

impl WriterOptions {
    pub const fn new(target: ArchiveVersion, features: FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
        }
    }

    pub const fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = Some(level);
        self
    }
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar14,
            features: FeatureSet::store_only(),
            compression_level: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

/// One member of an archive written a member at a time.
///
/// The bytes are opened when the member is coded and dropped once it is
/// written, so an archive of many files never holds more than one of them. A
/// stored member is copied straight from its source and never lands on the heap
/// at all.
#[derive(Debug, Clone)]
pub struct StreamingEntry {
    pub name: Vec<u8>,
    pub source: EntrySource,
    pub file_time: u32,
    pub file_attr: u8,
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
            password: None,
            file_comment: None,
        }
    }

    pub fn with_file_time(mut self, file_time: u32) -> Self {
        self.file_time = file_time;
        self
    }

    pub fn with_file_attr(mut self, file_attr: u8) -> Self {
        self.file_attr = file_attr;
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
    write_stored_archive_with_comment_and_progress(entries, options, archive_comment, None)
}

pub(crate) fn write_stored_archive_with_comment_and_progress(
    entries: &[StoredEntry<'_>],
    options: WriterOptions,
    archive_comment: Option<&[u8]>,
    progress: Option<&dyn WriteProgress>,
) -> Result<Vec<u8>> {
    let members: Vec<_> = entries.iter().map(Member::from_stored).collect();
    collect_archive(
        &members,
        options,
        MemberCoding::Stored,
        archive_comment,
        progress,
    )
}

pub fn write_compressed_archive(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
) -> Result<Vec<u8>> {
    write_compressed_archive_with_comment(entries, options, None)
}

/// Builder entries borrow either caller bytes or reopenable sources. This
/// keeps a source-backed archive from materializing every member up front.
pub(crate) struct BorrowedFileEntry<'a> {
    pub(crate) file: FileEntry<'a>,
    pub(crate) source: Option<&'a EntrySource>,
}

pub(crate) fn write_archive_with_sources(
    entries: &[BorrowedFileEntry<'_>],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: CallerOutput<'_>,
) -> Result<()> {
    let members: Vec<_> = entries
        .iter()
        .map(|entry| {
            let mut member = Member::from_file(&entry.file);
            if let Some(source) = entry.source {
                member.bytes = MemberBytes::NamedSource(source, entry.file.name);
            }
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
        STREAM_MEMBERS_ABOVE,
    )
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

/// Writes an archive straight to `output`, holding only the member being coded
/// rather than every input at once.
///
/// `resources` bounds the working set. A compressed member over 64 MiB is
/// packed into a spool in `resources`' temp directory, holding one window of
/// it; a smaller one is held while it is coded, and one larger than the budget
/// is coded on its own rather than refused.
pub fn write_streaming_archive_to(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: &mut dyn Write,
) -> Result<()> {
    crate::write_stream::refuse_managed_memory(resources, options.target.family())?;
    let members: Vec<_> = entries.iter().map(Member::from_streaming).collect();
    write_archive_to(
        &members,
        options,
        coding,
        archive_comment,
        resources,
        progress,
        CallerOutput::stream(output),
        STREAM_MEMBERS_ABOVE,
    )
}

/// Like [`write_streaming_archive_to`], but seeking lets a stored member be read once.
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
    crate::write_stream::refuse_managed_memory(resources, options.target.family())?;
    let members: Vec<_> = entries.iter().map(Member::from_streaming).collect();
    write_archive_to(
        &members,
        options,
        coding,
        archive_comment,
        resources,
        progress,
        CallerOutput::seekable(output),
        STREAM_MEMBERS_ABOVE,
    )
}

/// One member, however the caller supplied it.
struct Member<'a> {
    name: &'a [u8],
    bytes: MemberBytes<'a>,
    file_time: u32,
    file_attr: u8,
    password: Option<&'a [u8]>,
    file_comment: Option<&'a [u8]>,
}

impl<'a> Member<'a> {
    fn from_stored(entry: &'a StoredEntry<'a>) -> Self {
        Self {
            name: entry.name,
            bytes: MemberBytes::Borrowed(entry.data),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            password: entry.password,
            file_comment: entry.file_comment,
        }
    }

    fn from_file(entry: &'a FileEntry<'a>) -> Self {
        Self {
            name: entry.name,
            bytes: MemberBytes::Borrowed(entry.data),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            password: entry.password,
            file_comment: entry.file_comment,
        }
    }

    fn from_streaming(entry: &'a StreamingEntry) -> Self {
        Self {
            name: &entry.name,
            bytes: MemberBytes::Source(&entry.source),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            password: entry.password.as_deref(),
            file_comment: entry.file_comment.as_deref(),
        }
    }

    fn unpacked_size(&self) -> Result<usize> {
        usize::try_from(self.bytes.len()?)
            .map_err(|_| Error::InvalidArgument("RAR 1.3 file is larger than 32-bit size fields"))
    }
}

/// Runs the streaming writer into a buffer, for the callers that want the
/// archive as bytes.
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
        CallerOutput::stream(&mut out),
        STREAM_MEMBERS_ABOVE,
    )?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn write_archive_to(
    members: &[Member<'_>],
    options: WriterOptions,
    coding: MemberCoding,
    archive_comment: Option<&[u8]>,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    output: CallerOutput<'_>,
    stream_above: u64,
) -> Result<()> {
    if members.iter().any(|member| member.password.is_some()) {
        crate::crypto::require_encryption()?;
    }

    let control =
        crate::write_progress::ResourceProgress::new(resources, progress.map(ProgressReporter));
    let progress = Some(&control as &dyn WriteProgress);
    crate::write_progress::check_cancelled(progress.map(ProgressReporter))?;
    let mut output = output.cancellable(progress.map(ProgressReporter));
    // Stored members copied from a source have their checksum patched in.
    let patches = output.can_seek();
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    validate_plan(options, coding.shape())?;
    if coding.is_filtered() {
        return Err(Error::UnsupportedWriterOption {
            target: options.target,
            option: crate::write_plan::WriterOption::Filter,
            because: None,
        });
    }

    let mut head = Vec::new();
    write_main_header(&mut head, options.features, archive_comment)?;
    output.writer().write_all(&head)?;

    let encode_options = rar15_encode_options_for_level(options.compression_level);
    let mut solid_encoder = (options.features.solid && coding.compresses())
        .then(|| Unpack15Encoder::with_options(encode_options));

    let mut total_bytes = 0u64;
    for member in members {
        total_bytes = total_bytes.saturating_add(member.unpacked_size().map_err(|error| {
            crate::write_stream::member_error(error, member.name, "reading source")
        })? as u64);
    }
    // Without a solid chain the writer tries each fallback setting in turn, so
    // its progress total counts every byte once per attempt.
    let attempts =
        if !coding.compresses() || options.features.solid || options.compression_level == Some(0) {
            1
        } else {
            rar15_encode_fallback_options(encode_options).len() as u64
        };
    let total_work = total_bytes.saturating_mul(attempts);
    let reporting = &control as &dyn WriteProgress;
    report_compression_operation(reporting, true, total_work, members.len());
    let work = WorkTracker::new(
        Some(ProgressReporter(reporting)),
        WriteOperation::Compression,
        total_work,
    );

    for (index, member) in members.iter().enumerate() {
        work.check()?;
        let unpacked_size = member.unpacked_size().map_err(|error| {
            crate::write_stream::member_error(error, member.name, "reading source")
        })?;
        report_compression_entry(reporting, true, index, members.len(), member, unpacked_size);
        work.check()?;
        let encoded = encode_member(
            member,
            options,
            &coding,
            encode_options,
            solid_encoder.as_mut(),
            resources,
            &work,
            stream_above,
            patches,
        )
        .map_err(|error| crate::write_stream::member_error(error, member.name, "preparing"))?;
        write_member(&mut output, member, encoded, options, &work)
            .map_err(|error| crate::write_stream::member_error(error, member.name, "writing"))?;
        member.bytes.release();
        report_compression_entry(
            reporting,
            false,
            index,
            members.len(),
            member,
            unpacked_size,
        );
    }

    if !work.finish() {
        return Err(Error::Cancelled);
    }
    report_compression_operation(reporting, false, total_work, members.len());
    work.check()?;
    Ok(())
}

struct EncodedMember<'a> {
    payload: Payload<'a>,
    method: u8,
    unpacked_size: usize,
    /// `None` for a member summed as it is copied, its header patched after.
    file_crc: Option<u16>,
    /// The budget's charge for what waits to be written, released when the
    /// member has been. A directory holds nothing and has none.
    held: Option<crate::streaming::MemoryPermit>,
}

impl EncodedMember<'_> {
    /// Keeps `permit` until the member is written, cut to what it then holds:
    /// the packed form if it is in memory, and a buffer to copy through.
    fn holding(mut self, mut permit: crate::streaming::MemoryPermit) -> Self {
        let waiting = match &self.payload {
            Payload::Shared(MemberPayload::Packed(packed)) => packed.capacity() as u64,
            _ => 0,
        };
        permit.shrink_to(waiting.saturating_add(WRITE_WORKSPACE));
        self.held = Some(permit);
        self
    }
}

/// What writing one member holds beyond its payload: the buffer a stored or
/// spooled member is copied and encrypted through.
const WRITE_WORKSPACE: u64 = 1024 * 1024;

/// A member's bytes as they go into the archive, before any encryption.
enum Payload<'a> {
    Shared(MemberPayload<'a>),
    /// Packed into a spool in the temp directory, so neither the member nor
    /// its packed form is held.
    Spooled(crate::streaming::Spool),
}

/// Members larger than this are packed into a spool rather than in memory.
const STREAM_MEMBERS_ABOVE: u64 = 64 * 1024 * 1024;

/// What a member packed into a spool holds: the encoder's window and index,
/// and a verifying decoder.
fn streamed_workspace() -> u64 {
    crate::codec::rar13::ENCODER_WORKSPACE.saturating_add(2 * 1024 * 1024)
}

/// Working memory one member needs while it is coded. This is the admission
/// weight that keeps concurrent writers from piling up, not a prediction.
///
/// A compressed member is held with its packed form. The encoder's match
/// index and the verifying decoder are a fixed size whatever the member's.
fn member_workspace(unpacked: u64, compressing: bool) -> u64 {
    if !compressing {
        // Never loaded: written from the caller's bytes or copied from its source.
        return WRITE_WORKSPACE;
    }
    unpacked
        .saturating_mul(2)
        .saturating_add(crate::codec::rar13::ENCODER_WORKSPACE)
}

/// Codes one member, holding its bytes only while it is being coded.
#[allow(clippy::too_many_arguments)]
fn encode_member<'a>(
    member: &Member<'a>,
    options: WriterOptions,
    coding: &MemberCoding,
    encode_options: Rar15EncodeOptions,
    solid_encoder: Option<&mut Unpack15Encoder>,
    resources: &WriterResources,
    work: &WorkTracker<'_>,
    stream_above: u64,
    patches: bool,
) -> Result<EncodedMember<'a>> {
    work.check()?;
    let unpacked_size = member.unpacked_size()?;
    validate_member(member.name, unpacked_size)?;
    if member.file_attr & 0x10 != 0 {
        if unpacked_size != 0 {
            return Err(Error::InvalidArgument(
                "RAR1.3/1.4 directories must have no payload",
            ));
        }
        return Ok(EncodedMember {
            payload: Payload::Shared(MemberPayload::Packed(Vec::new())),
            method: METHOD_STORE,
            unpacked_size: 0,
            file_crc: Some(file_checksum(&[])),
            held: None,
        });
    }
    // A member its samples say will not compress is stored the way `--store`
    // stores it, never loaded or packed.
    let coding = if solid_encoder.is_none()
        && samples_say_store(member, options, coding, unpacked_size, resources, work)?
    {
        &MemberCoding::Stored
    } else {
        coding
    };
    // A large member read from a source is packed into a spool a window at a
    // time, and a stored fallback copied from the source.
    if let (true, Some(source)) = (
        coding.compresses()
            && options.compression_level != Some(0)
            && unpacked_size as u64 > stream_above,
        member.bytes.source(),
    ) {
        let permit = resources
            .acquire_serialising_cancellable(streamed_workspace(), &|| work.is_cancelled())?;
        return encode_spooled_member(
            member,
            source,
            unpacked_size,
            encode_options,
            solid_encoder,
            resources,
            work,
        )
        .map(|encoded| encoded.holding(permit));
    }
    let permit = resources.acquire_serialising_cancellable(
        member_workspace(unpacked_size as u64, coding.compresses()),
        &|| work.is_cancelled(),
    )?;

    // A stored member never needs to be resident: the writer copies it
    // straight through, encrypting as it goes. Its checksum is summed on the
    // way where the header can be patched, and read ahead for where it can't.
    if let (MemberCoding::Stored, Some(source)) = (coding, member.bytes.source()) {
        return Ok(EncodedMember {
            payload: Payload::Shared(MemberPayload::Copied(source)),
            method: METHOD_STORE,
            unpacked_size,
            file_crc: (!patches)
                .then(|| -> Result<u16> {
                    let mut checksum = Rar13Checksum::new();
                    member.bytes.walk_exact_with_progress(
                        unpacked_size as u64,
                        work.reporter(),
                        |chunk| {
                            checksum.update(chunk);
                            work.advance(chunk.len() as u64);
                        },
                    )?;
                    Ok(checksum.finish())
                })
                .transpose()?,
            held: None,
        }
        .holding(permit));
    }

    let data = member
        .bytes
        .load_exact_with_progress(unpacked_size as u64, work.reporter())?;
    let mut checksum = Rar13Checksum::new();
    for chunk in data.chunks(64 * 1024) {
        work.check()?;
        checksum.update(chunk);
        if !coding.compresses() {
            work.advance(chunk.len() as u64);
        }
    }
    let file_crc = checksum.finish();
    work.check()?;
    if !coding.compresses() {
        // The caller's bytes are written as they stand, encrypted as they go
        // out. A copy would hold the member a second time.
        return Ok(EncodedMember {
            payload: Payload::Shared(member.bytes.stored()),
            method: METHOD_STORE,
            unpacked_size,
            file_crc: Some(file_crc),
            held: None,
        }
        .holding(permit));
    }

    let solid = solid_encoder.is_some();
    let mut last = 0usize;
    let mut advance = |position: usize| advance_rar15_attempt(&mut last, work, position);
    // Every arm that ends up stored hands the payload back below, so none of
    // them builds a copy of the member to be thrown away. At level zero and
    // where the encoder gave nothing back, that copy was the whole member.
    let packed = if let Some(encoder) = solid_encoder {
        Some(encoder.encode_member_with_progress(&data, &mut advance)?)
    } else if options.compression_level == Some(0) {
        None
    } else {
        encode_verified_rar15_payload_with_progress(&data, encode_options, &mut advance)?
    };
    let (packed, method) = select_verified_payload(data, packed, solid);
    Ok(EncodedMember {
        payload: Payload::Shared(MemberPayload::Packed(packed)),
        method,
        unpacked_size,
        file_crc: Some(file_crc),
        held: None,
    }
    .holding(permit))
}

/// Whether to store an independent member without packing it, judged from
/// samples of it as the later formats judge theirs (#509).
///
/// A solid member is packed against the ones before it, so a sample packed
/// alone says nothing about it. A rewrite's sources are staged a window at a
/// time, in order, and opening one ahead to sample it can need staging the
/// members before it still hold.
fn samples_say_store(
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    unpacked_size: usize,
    resources: &WriterResources,
    work: &WorkTracker<'_>,
) -> Result<bool> {
    let len = unpacked_size as u64;
    if !coding.compresses()
        || options.features.solid
        || options.compression_level == Some(0)
        || crate::incompressible::sample_ranges(len).is_none()
        || member
            .bytes
            .source()
            .is_some_and(|source| source.max_preparation_window() != usize::MAX)
    {
        return Ok(false);
    }
    // A sample, what it packs to, and the coder's index.
    let sample = crate::incompressible::SAMPLE_LEN as u64;
    let _permit = resources.acquire_serialising_cancellable(
        (2 * sample).saturating_add(crate::codec::rar13::ENCODER_WORKSPACE),
        &|| work.is_cancelled(),
    )?;
    let mut reader = member.bytes.open()?;
    crate::incompressible::looks_incompressible(&mut *reader, len, |sample| {
        work.check()?;
        // Packed alone at level 1, the cheapest packing there is.
        match unpack15_encode_with_options_and_progress(
            sample,
            rar15_encode_options_for_level(Some(1)),
            &mut |_| !work.is_cancelled(),
        ) {
            Ok(packed) => Ok(packed.len()),
            Err(crate::codec::Error::Cancelled) => Err(Error::Cancelled),
            Err(error) => Err(error.into()),
        }
    })
}

/// [`encode_member`] for a member packed into a spool: the same attempts,
/// verification and stored fallback, reading the member from its source each
/// time instead of holding it.
fn encode_spooled_member<'a>(
    member: &Member<'a>,
    source: &'a EntrySource,
    unpacked_size: usize,
    encode_options: Rar15EncodeOptions,
    solid_encoder: Option<&mut Unpack15Encoder>,
    resources: &WriterResources,
    work: &WorkTracker<'_>,
) -> Result<EncodedMember<'a>> {
    let mut last = 0usize;
    let mut advance = |position: usize| advance_rar15_attempt(&mut last, work, position);
    // A solid member is not verified or stored, as in memory.
    if let Some(encoder) = solid_encoder {
        let mut checksum = Rar13Checksum::new();
        let spool = spool_attempt(
            member,
            unpacked_size,
            resources,
            work,
            Some(&mut checksum),
            &mut |input, out| {
                encoder.encode_member_streamed(input, unpacked_size, &mut advance, out)
            },
        )?;
        return Ok(EncodedMember {
            payload: Payload::Spooled(spool),
            method: METHOD_BEST,
            unpacked_size,
            file_crc: Some(checksum.finish()),
            held: None,
        });
    }
    // The first attempt reads the member for its checksum too.
    let mut file_crc = None;
    for candidate in rar15_encode_fallback_options(encode_options) {
        let mut sum = Rar13Checksum::new();
        let mut spool = spool_attempt(
            member,
            unpacked_size,
            resources,
            work,
            file_crc.is_none().then_some(&mut sum),
            &mut |input, out| {
                Unpack15Encoder::with_options(candidate).encode_member_streamed(
                    input,
                    unpacked_size,
                    &mut advance,
                    out,
                )
            },
        )?;
        let crc = *file_crc.get_or_insert_with(|| sum.finish());
        work.check()?;
        if spooled_payload_matches(&mut spool, member, unpacked_size)? {
            // Stored when packing did not help, as `select_verified_payload` does.
            if spool.len() < unpacked_size as u64 {
                return Ok(EncodedMember {
                    payload: Payload::Spooled(spool),
                    method: METHOD_BEST,
                    unpacked_size,
                    file_crc: Some(crc),
                    held: None,
                });
            }
            break;
        }
    }
    Ok(EncodedMember {
        payload: Payload::Shared(MemberPayload::Copied(source)),
        method: METHOD_STORE,
        unpacked_size,
        file_crc: Some(file_crc.expect("every attempt list has a first attempt")),
        held: None,
    })
}

type StreamedEncode<'e> = dyn FnMut(
        &mut dyn Read,
        &mut dyn FnMut(&[u8], usize) -> crate::codec::Result<std::ops::ControlFlow<()>>,
    ) -> crate::codec::Result<std::ops::ControlFlow<()>>
    + 'e;

/// Packs the member from its source into a new spool, adding what it reads to
/// `checksum` if given.
fn spool_attempt(
    member: &Member<'_>,
    len: usize,
    resources: &WriterResources,
    work: &WorkTracker<'_>,
    checksum: Option<&mut Rar13Checksum>,
    encode: &mut StreamedEncode<'_>,
) -> Result<crate::streaming::Spool> {
    let mut spool = crate::streaming::Spool::create(resources)?;
    let mut reader = crate::write_progress::CancellableIo {
        inner: member.bytes.open()?,
        progress: work.reporter(),
    };
    let mut counted = SummingReader {
        inner: &mut reader,
        checksum,
        read: 0,
    };
    let mut out = |bytes: &[u8], _: usize| -> crate::codec::Result<std::ops::ControlFlow<()>> {
        spool.write_all(bytes)?;
        Ok(std::ops::ControlFlow::Continue(()))
    };
    let coded = encode(&mut counted, &mut out);
    let read = counted.read;
    match coded {
        Err(crate::codec::Error::Cancelled) => return Err(Error::Cancelled),
        Err(_) if read < len as u64 => {
            return Err(Error::SourceChanged(
                "entry source size changed while compressing",
            ))
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    crate::write_stream::check_source_length(
        &mut reader,
        len as u64,
        len as u64,
        "entry source size changed while compressing",
    )?;
    Ok(spool)
}

/// Reads through to `inner`, counting the bytes and summing them if asked.
struct SummingReader<'r, 'c> {
    inner: &'r mut dyn Read,
    checksum: Option<&'c mut Rar13Checksum>,
    read: u64,
}

impl Read for SummingReader<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if let Some(checksum) = self.checksum.as_deref_mut() {
            checksum.update(&buffer[..read]);
        }
        self.read += read as u64;
        Ok(read)
    }
}

/// [`unpack15_payload_matches`] for a spooled payload, against the member
/// read again from its source.
fn spooled_payload_matches(
    spool: &mut crate::streaming::Spool,
    member: &Member<'_>,
    len: usize,
) -> Result<bool> {
    spool.rewind()?;
    let mut decoded = MatchesMember::new(member.bytes.open()?);
    let result = Unpack15::new().decode_member_from_reader(spool, len, false, &mut decoded);
    spool.park();
    Ok(result.is_ok() && decoded.at == len)
}

/// Writes one member's header and payload.
fn write_member(
    output: &mut CancellableOutput<'_, '_>,
    member: &Member<'_>,
    encoded: EncodedMember<'_>,
    options: WriterOptions,
    work: &WorkTracker<'_>,
) -> Result<()> {
    // The member's charge goes once it is written.
    let _held = encoded.held;
    let progress = work.reporter();
    crate::write_progress::check_cancelled(progress)?;
    // A payload in memory is encrypted in place; one copied from a source or
    // a spool is encrypted as it is copied.
    let mut cipher = match member.password {
        Some(password) => Some(Rar13Cipher::for_password(password)?),
        None => None,
    };
    let payload = match encoded.payload {
        Payload::Shared(MemberPayload::Packed(mut packed)) => {
            if let Some(mut cipher) = cipher.take() {
                for chunk in packed.chunks_mut(64 * 1024) {
                    crate::write_progress::check_cancelled(progress)?;
                    for byte in chunk {
                        *byte = cipher.encrypt_byte(*byte);
                    }
                }
            }
            Payload::Shared(MemberPayload::Packed(packed))
        }
        // Encrypted, if at all, as it is copied: the cipher keeps the size.
        other => other,
    };
    let packed_size = match &payload {
        Payload::Shared(shared) => shared.size(encoded.unpacked_size as u64),
        Payload::Spooled(spool) => spool.len(),
    };
    let packed_size = u32::try_from(packed_size)
        .map_err(|_| Error::InvalidArgument("RAR 1.3 file is larger than 32-bit size fields"))?;

    let mut flags = 0u8;
    if options.features.solid {
        flags |= LHD_SOLID;
    }
    if member.password.is_some() {
        flags |= LHD_PASSWORD;
    }
    if member.file_comment.is_some() {
        flags |= LHD_COMMENT;
    }
    let file_extra = encode_file_comment(member.file_comment)?;
    let build_header = |file_crc: u16| -> Result<Vec<u8>> {
        let mut header = Vec::new();
        write_file_header(
            &mut header,
            FileEntryRecord {
                name: member.name,
                unpacked_size: encoded.unpacked_size as u32,
                file_crc,
                packed_size,
                file_time: member.file_time,
                file_attr: member.file_attr,
                flags,
                unp_ver: DEFAULT_UNP_VER,
                method: encoded.method,
                extra: &file_extra,
            },
        )?;
        Ok(header)
    };
    let header = build_header(encoded.file_crc.unwrap_or(0))?;
    let header_at = match output.as_seekable() {
        Some(seekable) if encoded.file_crc.is_none() => seekable.stream_position()?,
        _ => 0,
    };
    output.writer().write_all(&header)?;
    let mut encrypting;
    let writer: &mut dyn Write = match cipher {
        Some(cipher) => {
            encrypting = Rar13EncryptingWriter {
                inner: output.writer(),
                cipher,
                buffer: Vec::new(),
            };
            &mut encrypting
        }
        None => output.writer(),
    };
    match payload {
        Payload::Shared(copied @ MemberPayload::Copied(_)) => {
            let mut checksum = Rar13Checksum::new();
            let mut advancing;
            let writer: &mut dyn Write = match encoded.file_crc {
                // Read ahead for its checksum, the member was counted then.
                Some(_) => writer,
                None => {
                    advancing = Advancing {
                        inner: writer,
                        work,
                    };
                    &mut advancing
                }
            };
            copied.write_to(
                &mut Rar13ChecksumWriter {
                    inner: writer,
                    checksum: &mut checksum,
                },
                u64::from(packed_size),
            )?;
            let summed = checksum.finish();
            match encoded.file_crc {
                Some(file_crc) if summed != file_crc => Err(Error::SourceChanged(
                    "entry source contents changed while writing",
                )),
                Some(_) => Ok(()),
                // A member summed as it is copied gets its checksum only once the header is out.
                None => {
                    let Some(output) = output.as_seekable() else {
                        return Err(Error::WriterFailure(
                            "RAR 1.3 member checksum left to patch on an output that cannot seek",
                        ));
                    };
                    crate::write_stream::patch_header(
                        output,
                        header_at,
                        header.len() as u64,
                        &build_header(summed)?,
                        Error::WriterFailure("RAR 1.3 file header changed length when patched"),
                    )
                }
            }
        }
        Payload::Shared(packed) => packed.write_to(writer, u64::from(packed_size)),
        Payload::Spooled(mut spool) => {
            if spool.copy_to(writer)? != u64::from(packed_size) {
                return Err(Error::WriterFailure(
                    "spooled member is not the size its header gives",
                ));
            }
            Ok(())
        }
    }
}

/// A member not read ahead for its checksum is counted as it is copied.
struct Advancing<'w, 't> {
    inner: &'w mut dyn Write,
    work: &'w WorkTracker<'t>,
}

impl Write for Advancing<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.work.advance(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Encrypts a copied member as it passes through, a chunk at a time.
struct Rar13EncryptingWriter<'a> {
    inner: &'a mut dyn Write,
    cipher: Rar13Cipher,
    buffer: Vec<u8>,
}

impl Write for Rar13EncryptingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let take = buf.len().min(64 * 1024);
        self.buffer.clear();
        self.buffer.extend(
            buf[..take]
                .iter()
                .map(|&byte| self.cipher.encrypt_byte(byte)),
        );
        self.inner.write_all(&self.buffer)?;
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
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
    let mut sink = crate::volume_sink::CollectedVolumes::new();
    split_member(
        &Member::from_stored(&entry),
        options,
        &MemberCoding::Stored,
        volume_size,
        &mut sink,
        &WriterResources::default(),
        None,
        STREAM_MEMBERS_ABOVE,
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
    let mut sink = crate::volume_sink::CollectedVolumes::new();
    split_member(
        &Member::from_file(&entry),
        options,
        &MemberCoding::Compressed,
        volume_size,
        &mut sink,
        &WriterResources::default(),
        progress,
        STREAM_MEMBERS_ABOVE,
    )?;
    Ok(sink.take())
}

/// Splits one member across a volume set, handing each volume to `sink` as it
/// fills. A RAR 1.3 set holds one member.
///
/// A stored member is copied from its source as the volumes are written. A
/// compressed one is packed first, in memory or, over 64 MiB, into a spool in
/// `resources`' temp directory: packing is checked by decoding it and can fall
/// back to other settings or to storing, which cannot be taken back once a
/// volume has gone out, and the packed size gives the number of volumes
/// before the first one is written.
pub fn write_volumes_to(
    entry: &StreamingEntry,
    options: WriterOptions,
    coding: MemberCoding,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    split_member(
        &Member::from_streaming(entry),
        options,
        &coding,
        volume_size,
        sink,
        resources,
        progress,
        STREAM_MEMBERS_ABOVE,
    )
}

/// [`write_volumes_to`] for a Builder entry, which borrows its bytes or a source.
pub(crate) fn write_volumes_with_source_to(
    entry: &BorrowedFileEntry<'_>,
    options: WriterOptions,
    coding: MemberCoding,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    let mut member = Member::from_file(&entry.file);
    if let Some(source) = entry.source {
        member.bytes = MemberBytes::NamedSource(source, entry.file.name);
    }
    split_member(
        &member,
        options,
        &coding,
        volume_size,
        sink,
        resources,
        progress,
        STREAM_MEMBERS_ABOVE,
    )
}

/// A volume member's bytes as they go into the set.
enum VolumePayload {
    /// The member itself, stored.
    Member,
    Packed(Vec<u8>),
    Spooled(crate::streaming::Spool),
}

struct PackedVolumeMember {
    payload: VolumePayload,
    len: u64,
    method: u8,
    /// Known once the member has been packed; a stored one is summed as it is copied.
    file_crc: Option<u16>,
    /// The budget's charge for what waits to be written, released once the
    /// last fragment has been.
    held: Option<crate::streaming::MemoryPermit>,
}

impl PackedVolumeMember {
    /// Keeps `permit` until the set is written, cut to what the member then
    /// holds, as [`EncodedMember::holding`] does.
    fn holding(mut self, mut permit: crate::streaming::MemoryPermit) -> Self {
        let waiting = match &self.payload {
            VolumePayload::Packed(packed) => packed.capacity() as u64,
            VolumePayload::Member | VolumePayload::Spooled(_) => 0,
        };
        permit.shrink_to(waiting.saturating_add(WRITE_WORKSPACE));
        self.held = Some(permit);
        self
    }
}

/// A member larger than `stream_above` and read from a source is packed into a spool.
#[allow(clippy::too_many_arguments)]
fn split_member(
    member: &Member<'_>,
    options: WriterOptions,
    coding: &MemberCoding,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
    stream_above: u64,
) -> Result<()> {
    crate::write_stream::refuse_managed_memory(resources, options.target.family())?;
    let control =
        crate::write_progress::ResourceProgress::new(resources, progress.map(ProgressReporter));
    let reporting = &control as &dyn WriteProgress;
    crate::write_progress::check_cancelled(Some(ProgressReporter(reporting)))?;
    if !options.target.is_rar13_family() {
        return Err(Error::UnsupportedVersion(options.target));
    }
    validate_plan(options, coding.shape())?;
    if coding.is_filtered() {
        return Err(Error::UnsupportedWriterOption {
            target: options.target,
            option: WriterOption::Filter,
            because: None,
        });
    }
    let unpacked_size = member
        .unpacked_size()
        .and_then(|size| validate_member(member.name, size).map(|()| size))
        .map_err(|error| {
            crate::write_stream::member_error(error, member.name, "preparing volume member")
        })?;
    validate_volume_writer_inputs(member, options)?;
    if unpacked_size == 0 {
        return Err(Error::InvalidArgument(
            "RAR 1.3 volume writer needs a non-empty packed payload",
        )
        .at_entry(member.name.to_vec(), "preparing volume member"));
    }
    let mut head = Vec::new();
    write_main_header_with_flags(&mut head, options.features, None, MHD_VOLUME)?;
    // Every volume repeats the same main header and a fragment header of the same length.
    let header_len = FILE_HEAD_BASE_SIZE + member.name.len();
    if volume_size == 0 {
        return Err(Error::InvalidArgument("volume size must be non-zero"));
    }
    let payload = volume_size
        .checked_sub(head.len() + header_len)
        .filter(|&payload| payload > 0)
        .ok_or(Error::InvalidArgument(
            "volume size is too small to hold the volume headers",
        ))? as u64;

    let compresses = coding.compresses();
    let encode_options = rar15_encode_options_for_level(options.compression_level);
    let (operation, total_work) = if compresses {
        (
            WriteOperation::Compression,
            (unpacked_size as u64)
                .saturating_mul(rar15_encode_fallback_options(encode_options).len() as u64),
        )
    } else {
        (WriteOperation::Emission, unpacked_size as u64)
    };
    report_volume_operation(reporting, operation, true, total_work);
    let work = WorkTracker::new(Some(ProgressReporter(reporting)), operation, total_work);
    report_volume_entry(reporting, operation, true, member, unpacked_size);
    let packed = if compresses {
        pack_volume_member(
            member,
            unpacked_size,
            encode_options,
            resources,
            &work,
            stream_above,
        )
        .map_err(|error| {
            crate::write_stream::member_error(error, member.name, "compressing volume member")
        })?
    } else {
        // Charged as a stored member in a single archive is: for the buffer
        // it is copied through.
        let permit = resources.acquire_serialising_cancellable(
            member_workspace(unpacked_size as u64, false),
            &|| work.is_cancelled(),
        )?;
        PackedVolumeMember {
            payload: VolumePayload::Member,
            len: unpacked_size as u64,
            method: METHOD_STORE,
            file_crc: None,
            held: None,
        }
        .holding(permit)
    };
    let result = write_volume_set(
        member,
        packed,
        VolumeLayout {
            head: &head,
            header_len,
            payload,
            unpacked_size: unpacked_size as u32,
            features: options.features,
        },
        sink,
        (!compresses).then_some(&work),
        ProgressReporter(reporting),
    )
    .map_err(|error| {
        crate::write_stream::member_error(error, member.name, "writing volume member")
    });
    report_volume_entry(reporting, operation, false, member, unpacked_size);
    result?;
    member.bytes.release();
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    report_volume_operation(reporting, operation, false, total_work);
    work.check()
}

/// Packs a volume member as the in-memory volume writer always did: on its
/// own even in a solid set, verified, and stored if packing did not help.
fn pack_volume_member(
    member: &Member<'_>,
    unpacked_size: usize,
    encode_options: Rar15EncodeOptions,
    resources: &WriterResources,
    work: &WorkTracker<'_>,
    stream_above: u64,
) -> Result<PackedVolumeMember> {
    work.check()?;
    if let (true, Some(source)) = (unpacked_size as u64 > stream_above, member.bytes.source()) {
        let permit = resources
            .acquire_serialising_cancellable(streamed_workspace(), &|| work.is_cancelled())?;
        let encoded = encode_spooled_member(
            member,
            source,
            unpacked_size,
            encode_options,
            None,
            resources,
            work,
        )?;
        let (payload, len) = match encoded.payload {
            Payload::Spooled(spool) => {
                let len = spool.len();
                (VolumePayload::Spooled(spool), len)
            }
            Payload::Shared(MemberPayload::Copied(_) | MemberPayload::Borrowed(_)) => {
                (VolumePayload::Member, unpacked_size as u64)
            }
            Payload::Shared(MemberPayload::Packed(packed)) => {
                let len = packed.len() as u64;
                (VolumePayload::Packed(packed), len)
            }
        };
        return Ok(PackedVolumeMember {
            payload,
            len,
            method: encoded.method,
            file_crc: encoded.file_crc,
            held: None,
        }
        .holding(permit));
    }
    let permit = resources
        .acquire_serialising_cancellable(member_workspace(unpacked_size as u64, true), &|| {
            work.is_cancelled()
        })?;
    let data = member
        .bytes
        .load_exact_with_progress(unpacked_size as u64, work.reporter())?;
    let file_crc = file_checksum(&data);
    let mut last = 0usize;
    let mut advance = |position: usize| advance_rar15_attempt(&mut last, work, position);
    let packed = encode_verified_rar15_payload_with_progress(&data, encode_options, &mut advance)?;
    let packed = match packed {
        Some(packed)
            if !crate::write_plan::StoreFallback::new().applies(
                false,
                data.len(),
                packed.len(),
            ) =>
        {
            PackedVolumeMember {
                len: packed.len() as u64,
                payload: VolumePayload::Packed(packed),
                method: METHOD_BEST,
                file_crc: Some(file_crc),
                held: None,
            }
        }
        // Stored: copied from the member again rather than from a copy of it.
        _ => PackedVolumeMember {
            payload: VolumePayload::Member,
            len: unpacked_size as u64,
            method: METHOD_STORE,
            file_crc: Some(file_crc),
            held: None,
        },
    };
    // The member is let go before the charge is cut to what is left.
    drop(data);
    Ok(packed.holding(permit))
}

/// What every volume of a set repeats around its slice of the member.
struct VolumeLayout<'a> {
    head: &'a [u8],
    header_len: usize,
    /// Packed bytes in each volume but the last.
    payload: u64,
    unpacked_size: u32,
    features: FeatureSet,
}

/// Writes the volumes, patching each fragment header once the bytes behind it
/// have been copied and summed. `stored_work` counts a stored member's bytes.
fn write_volume_set(
    member: &Member<'_>,
    packed: PackedVolumeMember,
    layout: VolumeLayout<'_>,
    sink: &mut dyn VolumeSink,
    stored_work: Option<&WorkTracker<'_>>,
    progress: ProgressReporter<'_>,
) -> Result<()> {
    let PackedVolumeMember {
        payload,
        len: packed_len,
        method,
        file_crc,
        held,
    } = packed;
    // The member's charge goes once its last fragment is written.
    let _held = held;
    u32::try_from(packed_len)
        .map_err(|_| Error::InvalidArgument("RAR 1.3 file is larger than 32-bit size fields"))?;
    let total = packed_len.div_ceil(layout.payload);
    // Told before the first volume, so a set that cannot be named is refused
    // before anything is written.
    sink.expect_volumes(total)?;

    let copies_member = matches!(payload, VolumePayload::Member);
    let mut member_reader;
    let mut packed_reader;
    let mut spool;
    let reader: &mut dyn Read = match payload {
        VolumePayload::Member => {
            member_reader = member.bytes.open()?;
            &mut member_reader
        }
        VolumePayload::Packed(packed) => {
            packed_reader = std::io::Cursor::new(packed);
            &mut packed_reader
        }
        VolumePayload::Spooled(spooled) => {
            spool = spooled;
            spool.rewind()?;
            &mut spool
        }
    };
    let mut whole = Rar13Checksum::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut start = 0u64;
    for index in 0..total {
        crate::write_progress::check_cancelled(Some(progress))?;
        let len = layout.payload.min(packed_len - start);
        let split_after = index + 1 < total;
        let bytes = layout.head.len() as u64 + layout.header_len as u64 + len;
        let mut out = sink.start_volume(index)?;
        out.write_all(layout.head)?;
        // A placeholder: the header gives the checksum of what follows it.
        let header_at = out.stream_position()?;
        out.write_all(&vec![0; layout.header_len])?;
        let mut fragment = Rar13Checksum::new();
        let mut left = len;
        while left > 0 {
            let take = left.min(buffer.len() as u64) as usize;
            let chunk = &mut buffer[..take];
            reader.read_exact(chunk).map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::SourceChanged("entry source size changed while writing")
                } else {
                    error.into()
                }
            })?;
            fragment.update(chunk);
            whole.update(chunk);
            out.write_all(chunk)?;
            left -= take as u64;
            match stored_work {
                Some(work) if !work.advance(take as u64) => return Err(Error::Cancelled),
                Some(_) => {}
                None => crate::write_progress::check_cancelled(Some(progress))?,
            }
        }
        if !split_after && copies_member {
            crate::write_stream::check_source_length(
                reader,
                packed_len,
                packed_len,
                "entry source size changed while writing",
            )?;
        }
        // The last fragment's header gives the whole member's checksum.
        let checksum = if split_after {
            fragment.finish()
        } else {
            let copied = std::mem::replace(&mut whole, Rar13Checksum::new()).finish();
            match file_crc {
                Some(crc) if copies_member && copied != crc => {
                    return Err(Error::SourceChanged(
                        "entry source contents changed while writing",
                    ))
                }
                Some(crc) => crc,
                None => copied,
            }
        };
        let mut flags = 0u8;
        if index > 0 {
            flags |= LHD_SPLIT_BEFORE;
        }
        if split_after {
            flags |= LHD_SPLIT_AFTER;
        }
        if layout.features.solid {
            flags |= LHD_SOLID;
        }
        let mut header = Vec::with_capacity(layout.header_len);
        write_file_header(
            &mut header,
            FileEntryRecord {
                name: member.name,
                unpacked_size: layout.unpacked_size,
                file_crc: checksum,
                packed_size: len as u32,
                file_time: member.file_time,
                file_attr: member.file_attr,
                flags,
                unp_ver: DEFAULT_UNP_VER,
                method,
                extra: &[],
            },
        )?;
        crate::write_stream::patch_header(
            &mut out,
            header_at,
            layout.header_len as u64,
            &header,
            Error::WriterFailure("RAR 1.3 volume header changed length when patched"),
        )?;
        out.flush()?;
        drop(out);
        sink.finish_volume(index, bytes)?;
        progress.report(WriteProgressEvent::VolumeFinished {
            volume_index: index as usize,
            total_volumes: usize::try_from(total).ok(),
            bytes,
        });
        crate::write_progress::check_cancelled(Some(progress))?;
        start += len;
    }
    Ok(())
}

fn report_volume_operation(
    progress: &dyn WriteProgress,
    operation: WriteOperation,
    started: bool,
    total_bytes: u64,
) {
    let (total_bytes, total_entries) = (Some(total_bytes), Some(1));
    progress.report(if started {
        WriteProgressEvent::OperationStarted {
            operation,
            total_bytes,
            total_entries,
            pass: 1,
        }
    } else {
        WriteProgressEvent::OperationFinished {
            operation,
            total_bytes,
            total_entries,
            pass: 1,
        }
    });
}

fn report_volume_entry(
    progress: &dyn WriteProgress,
    operation: WriteOperation,
    started: bool,
    member: &Member<'_>,
    input_bytes: usize,
) {
    let (name, input_bytes) = (member.name, input_bytes as u64);
    progress.report(if started {
        WriteProgressEvent::EntryStarted {
            operation,
            index: 0,
            total_entries: 1,
            name,
            input_bytes,
        }
    } else {
        WriteProgressEvent::EntryFinished {
            operation,
            index: 0,
            total_entries: 1,
            name,
            input_bytes,
        }
    });
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

fn report_compression_entry(
    progress: &dyn WriteProgress,
    started: bool,
    index: usize,
    total_entries: usize,
    member: &Member<'_>,
    input_bytes: usize,
) {
    let name = member.name;
    let input_bytes = input_bytes as u64;
    if started {
        progress.report(WriteProgressEvent::EntryStarted {
            operation: WriteOperation::Compression,
            index,
            total_entries,
            name,
            input_bytes,
        });
    } else {
        progress.report(WriteProgressEvent::EntryFinished {
            operation: WriteOperation::Compression,
            index,
            total_entries,
            name,
            input_bytes,
        });
    }
}

/// Everything this writer refuses, in one place, before anything is written.
fn validate_plan(options: WriterOptions, shape: PlanShape) -> Result<()> {
    crate::write_plan::validate_features(options.target, options.features, shape)?;
    crate::write_plan::validate_compression_level(options.target, options.compression_level)
}

fn validate_volume_writer_inputs(member: &Member<'_>, options: WriterOptions) -> Result<()> {
    if member.password.is_some() {
        return Err(Error::UnsupportedWriterOption {
            target: options.target,
            option: WriterOption::Password,
            because: Some("in a volume set"),
        });
    }
    if member.file_comment.is_some() {
        return Err(Error::UnsupportedWriterOption {
            target: options.target,
            option: WriterOption::FileComment,
            because: Some("in a volume set"),
        });
    }
    Ok(())
}

fn rar15_encode_options_for_level(level: Option<u8>) -> Rar15EncodeOptions {
    // Both callers have validated 0..=5 before resolving the encoder policy.
    let level = usize::from(level.unwrap_or(5));
    let options = Rar15EncodeOptions::new()
        .with_lazy_matching(level == 5)
        .with_priced_parse(level == 5)
        .with_stmode_literal_runs(level >= 3);
    let max_distance = [
        Some(0),
        Some(4 * 1024),
        Some(8 * 1024),
        Some(16 * 1024),
        Some(24 * 1024),
        None,
    ][level];
    match max_distance {
        Some(distance) => options.with_max_long_match_distance(distance),
        None => options,
    }
}

/// The encoder reports positions within each attempt, restarting at zero for
/// a verification fallback. Account only the new bytes in that attempt.
fn advance_rar15_attempt(last: &mut usize, work: &WorkTracker<'_>, position: usize) -> bool {
    if position < *last {
        *last = 0;
    }
    let delta = position.saturating_sub(*last);
    *last = position;
    work.advance(delta as u64)
}

fn select_verified_payload(
    data: std::borrow::Cow<'_, [u8]>,
    packed: Option<Vec<u8>>,
    solid: bool,
) -> (Vec<u8>, u8) {
    match packed {
        Some(packed)
            if !crate::write_plan::StoreFallback::new().applies(
                solid,
                data.len(),
                packed.len(),
            ) =>
        {
            (packed, METHOD_BEST)
        }
        _ => (data.into_owned(), METHOD_STORE),
    }
}

fn encode_verified_rar15_payload_with_progress(
    data: &[u8],
    options: Rar15EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Option<Vec<u8>>> {
    encode_verified_rar15_payload_using(
        data,
        options,
        progress,
        unpack15_encode_with_options_and_progress,
    )
}

fn encode_verified_rar15_payload_using(
    data: &[u8],
    options: Rar15EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
    mut encode: impl FnMut(
        &[u8],
        Rar15EncodeOptions,
        &mut dyn FnMut(usize) -> bool,
    ) -> crate::codec::Result<Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    for candidate_options in rar15_encode_fallback_options(options) {
        let packed = match encode(data, candidate_options, progress) {
            Err(crate::codec::Error::Cancelled) => return Err(Error::Cancelled),
            result => result?,
        };
        if unpack15_payload_matches(&packed, data)? {
            return Ok(Some(packed));
        }
    }
    Ok(None)
}

fn rar15_encode_fallback_options(options: Rar15EncodeOptions) -> Vec<Rar15EncodeOptions> {
    let mut candidates = vec![options];
    let distance_limited = options.with_max_long_match_distance(24 * 1024);
    if distance_limited != options {
        candidates.push(distance_limited);
    }
    let conservative = options
        .with_lazy_matching(false)
        .with_stmode_literal_runs(false)
        .with_max_long_match_distance(8 * 1024);
    if !candidates.contains(&conservative) {
        candidates.push(conservative);
    }
    candidates
}

/// Decodes `packed` and checks it against `data` as it comes out, so the check
/// holds a decoder window rather than a second copy of the member.
fn unpack15_payload_matches(packed: &[u8], data: &[u8]) -> Result<bool> {
    let mut decoded = MatchesMember::new(data);
    let result = Unpack15::new().decode_member_from_reader(
        &mut &packed[..],
        data.len(),
        false,
        &mut decoded,
    );
    Ok(result.is_ok() && decoded.at == data.len())
}

/// Takes decoded bytes only while they are the member's, read from its start.
struct MatchesMember<R> {
    member: R,
    at: usize,
    expected: Vec<u8>,
}

impl<R: Read> MatchesMember<R> {
    fn new(member: R) -> Self {
        Self {
            member,
            at: 0,
            expected: Vec::new(),
        }
    }
}

impl<R: Read> Write for MatchesMember<R> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.expected.resize(buf.len(), 0);
        self.member.read_exact(&mut self.expected)?;
        if self.expected != buf {
            return Err(std::io::Error::other(
                "decoded bytes differ from the member",
            ));
        }
        self.at += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_main_header(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
) -> Result<()> {
    write_main_header_with_flags(out, features, archive_comment, 0)
}

fn write_main_header_with_flags(
    out: &mut Vec<u8>,
    features: FeatureSet,
    archive_comment: Option<&[u8]>,
    extra_flags: u8,
) -> Result<()> {
    let comment_extra = encode_archive_comment(archive_comment)?;
    let mut flags = MHD_ALWAYS_SET | extra_flags;
    if archive_comment.is_some() {
        flags |= MHD_COMMENT;
        flags |= MHD_PACK_COMMENT;
    }
    if features.solid {
        flags |= MHD_SOLID;
    }
    let head_size = main_header_size(comment_extra.len())?;
    out.extend_from_slice(RAR13_SIGNATURE);
    out.extend_from_slice(&head_size.to_le_bytes());
    out.push(flags);
    out.extend_from_slice(&comment_extra);
    producer::append(out);
    Ok(())
}

fn main_header_size(comment_len: usize) -> Result<u16> {
    comment_len
        .checked_add(MAIN_HEAD_SIZE as usize + producer::RECORD_LEN)
        .and_then(|size| u16::try_from(size).ok())
        .ok_or(Error::InvalidArgument(
            "RAR 1.3 main header comment extension is too large",
        ))
}

#[test]
fn producer_main_header_size_bounds() {
    let max_comment = u16::MAX as usize - MAIN_HEAD_SIZE as usize - producer::RECORD_LEN;
    assert_eq!(main_header_size(max_comment).unwrap(), u16::MAX);
    assert!(main_header_size(max_comment + 1).is_err());
    assert!(main_header_size(usize::MAX).is_err());
}

struct FileEntryRecord<'a> {
    name: &'a [u8],
    unpacked_size: u32,
    file_crc: u16,
    packed_size: u32,
    file_time: u32,
    file_attr: u8,
    flags: u8,
    unp_ver: u8,
    method: u8,
    extra: &'a [u8],
}

fn write_file_header(out: &mut Vec<u8>, entry: FileEntryRecord<'_>) -> Result<()> {
    let head_size = FILE_HEAD_BASE_SIZE + entry.name.len() + entry.extra.len();
    let head_size = u16::try_from(head_size)
        .map_err(|_| Error::InvalidArgument("RAR 1.3 file header is longer than 65535 bytes"))?;
    out.extend_from_slice(&entry.packed_size.to_le_bytes());
    out.extend_from_slice(&entry.unpacked_size.to_le_bytes());
    out.extend_from_slice(&entry.file_crc.to_le_bytes());
    out.extend_from_slice(&head_size.to_le_bytes());
    out.extend_from_slice(&entry.file_time.to_le_bytes());
    out.push(entry.file_attr);
    out.push(entry.flags);
    out.push(entry.unp_ver);
    out.push(entry.name.len() as u8);
    out.push(entry.method);
    out.extend_from_slice(entry.name);
    out.extend_from_slice(entry.extra);
    Ok(())
}

fn encode_archive_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidArgument(
            "RAR 1.3 archive comment is longer than 65535 bytes",
        ));
    }
    let mut packed = unpack15_encode(comment)?;
    Rar13Cipher::new_comment().encrypt_in_place(&mut packed);
    let packed_field_len = packed.len().checked_add(2).ok_or(Error::InvalidArgument(
        "RAR 1.3 archive comment size overflows",
    ))?;
    if packed_field_len > u16::MAX as usize {
        return Err(Error::InvalidArgument(
            "RAR 1.3 packed archive comment is longer than 65535 bytes",
        ));
    }

    let mut out = Vec::with_capacity(4 + packed.len());
    out.extend_from_slice(&(packed_field_len as u16).to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(&packed);
    Ok(out)
}

fn encode_file_comment(comment: Option<&[u8]>) -> Result<Vec<u8>> {
    let Some(comment) = comment else {
        return Ok(Vec::new());
    };
    if comment.len() > u16::MAX as usize {
        return Err(Error::InvalidArgument(
            "RAR 1.3 file comment is longer than 65535 bytes",
        ));
    }
    let mut out = Vec::with_capacity(2 + comment.len());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

fn validate_member(name: &[u8], unpacked_size: usize) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidArgument("RAR 1.3 file name is empty"));
    }
    if name.len() > u8::MAX as usize {
        return Err(Error::InvalidArgument(
            "RAR 1.3 file name is longer than 255 bytes",
        ));
    }
    if unpacked_size > u32::MAX as usize {
        return Err(Error::InvalidArgument(
            "RAR 1.3 file is larger than 32-bit size fields",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The volume writer before it streamed, kept to check the streamed sets
    /// against: the member and its packed form whole in memory, cut into
    /// slices of what fits beside the headers.
    struct InMemorySet<'a> {
        name: &'a [u8],
        unpacked: &'a [u8],
        packed: &'a [u8],
        method: u8,
        features: FeatureSet,
        volume_size: usize,
    }

    fn in_memory_volumes(set: InMemorySet<'_>) -> Vec<Vec<u8>> {
        let render = |index: usize, split_after: bool, chunk: &[u8]| -> Vec<u8> {
            let mut flags = 0;
            if index > 0 {
                flags |= LHD_SPLIT_BEFORE;
            }
            if split_after {
                flags |= LHD_SPLIT_AFTER;
            }
            if set.features.solid {
                flags |= LHD_SOLID;
            }
            let mut out = Vec::new();
            write_main_header_with_flags(&mut out, set.features, None, MHD_VOLUME).unwrap();
            let checksum_data = if split_after { chunk } else { set.unpacked };
            write_file_header(
                &mut out,
                FileEntryRecord {
                    name: set.name,
                    unpacked_size: set.unpacked.len() as u32,
                    file_crc: file_checksum(checksum_data),
                    packed_size: chunk.len() as u32,
                    file_time: 0,
                    file_attr: 0x20,
                    flags,
                    unp_ver: DEFAULT_UNP_VER,
                    method: set.method,
                    extra: &[],
                },
            )
            .unwrap();
            out.extend_from_slice(chunk);
            out
        };
        let probe = &set.packed[..set.packed.len().min(set.volume_size)];
        let payload = set.volume_size - (render(0, true, probe).len() - probe.len());
        let chunks: Vec<&[u8]> = set.packed.chunks(payload).collect();
        chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| render(index, index + 1 < chunks.len(), chunk))
            .collect()
    }

    #[test]
    fn a_compressed_member_is_charged_itself_its_packed_form_and_a_fixed_index() {
        let small = super::member_workspace(1 << 20, true);
        let large = super::member_workspace(1 << 30, true);
        // Beyond the bytes it holds, a large member costs what a small one does.
        assert_eq!(large - small, 2 * ((1 << 30) - (1 << 20)));
        assert!(small < 16 << 20, "{small}");
    }

    #[test]
    fn a_member_is_charged_for_what_it_holds_until_it_is_written() {
        let data: Vec<u8> = (0..300_000u32)
            .map(|index| ((index * 7 / 5) ^ (index >> 9)) as u8)
            .collect();
        let mut passwords: Vec<Option<&[u8]>> = vec![None];
        if cfg!(feature = "encryption") {
            passwords.push(Some(b"password"));
        }
        for password in passwords {
            for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
                let case = format!("{coding:?}, password {}", password.is_some());
                let entry = FileEntry {
                    name: b"member.bin",
                    data: &data,
                    file_time: 0,
                    file_attr: 0x20,
                    password,
                    file_comment: None,
                };
                let member = Member::from_file(&entry);
                let options = WriterOptions::default();
                let resources = WriterResources::default();
                let work = WorkTracker::new(None, WriteOperation::Compression, u64::MAX);
                let encoded = encode_member(
                    &member,
                    options,
                    &coding,
                    rar15_encode_options_for_level(options.compression_level),
                    None,
                    &resources,
                    &work,
                    u64::MAX,
                    false,
                )
                .unwrap();
                let held = match &encoded.payload {
                    // A stored member is the caller's bytes, not a copy of
                    // them, so it holds only the buffer it is written through.
                    Payload::Shared(MemberPayload::Borrowed(bytes)) => {
                        assert!(matches!(coding, MemberCoding::Stored), "{case}");
                        assert_eq!(bytes.as_ptr(), data.as_ptr(), "{case}");
                        WRITE_WORKSPACE
                    }
                    // A packed one holds its packed form until it is written.
                    Payload::Shared(MemberPayload::Packed(packed)) => {
                        assert!(matches!(coding, MemberCoding::Compressed), "{case}");
                        assert!(packed.len() < data.len(), "{case}");
                        packed.capacity() as u64 + WRITE_WORKSPACE
                    }
                    _ => panic!("{case}: unexpected payload"),
                };
                assert_eq!(resources.workspace_in_use(), held, "{case}");
                let mut archive = Vec::new();
                write_main_header(&mut archive, options.features, None).unwrap();
                write_member(
                    &mut CallerOutput::stream(&mut archive).cancellable(None),
                    &member,
                    encoded,
                    options,
                    &work,
                )
                .unwrap();
                assert_eq!(resources.workspace_in_use(), 0, "{case}");
                let extracted =
                    collect_extract(&Archive::parse(&archive).unwrap(), password).unwrap();
                assert!(extracted.len() == 1 && extracted[0].data == data, "{case}");
            }
        }
    }

    #[test]
    fn a_stored_volume_member_is_charged_until_its_last_fragment_is_written() {
        let data: Vec<u8> = (0..300_000u32)
            .map(|index| ((index * 7 / 5) ^ (index >> 9)) as u8)
            .collect();
        let entry = StreamingEntry::new(
            b"member.bin".to_vec(),
            EntrySource::from_bytes(data.clone()),
        )
        .with_file_attr(0x20);
        // Stored, and level 0, which RAR 1.3 volume sets still code.
        for (coding, level) in [
            (MemberCoding::Stored, None),
            (MemberCoding::Compressed, Some(0)),
        ] {
            let options = WriterOptions {
                compression_level: level,
                ..WriterOptions::default()
            };
            let resources = WriterResources::default();
            let mut sink = crate::volume_sink::ChargedVolumes::new(&resources);
            split_member(
                &Member::from_streaming(&entry),
                options,
                &coding,
                20_000,
                &mut sink,
                &resources,
                None,
                STREAM_MEMBERS_ABOVE,
            )
            .unwrap();
            // Every fragment's payload went out while the member was charged
            // for the buffer it is copied through, as a stored member in a
            // single archive is.
            assert!(sink.payload_writes() > 2, "{level:?}");
            assert_eq!(resources.workspace_in_use(), 0, "{level:?}");

            let volumes = sink.collected.take();
            let extracted = collect_extract_volumes(&parse_volumes(&volumes), None).unwrap();
            assert!(
                extracted.len() == 1 && extracted[0].data == data,
                "{level:?}"
            );
        }
    }

    #[test]
    fn a_volume_member_is_charged_for_what_it_holds_until_its_last_fragment_is_written() {
        let data: Vec<u8> = (0..300_000u32)
            .map(|index| ((index * 7 / 5) ^ (index >> 9)) as u8)
            .collect();
        let entry = StreamingEntry::new(
            b"member.bin".to_vec(),
            EntrySource::from_bytes(data.clone()),
        )
        .with_file_attr(0x20);
        let options = WriterOptions::default();
        // Packed in memory, and packed into a spool.
        for stream_above in [u64::MAX, 1024] {
            let resources = WriterResources::default();
            let mut sink = crate::volume_sink::ChargedVolumes::new(&resources);
            split_member(
                &Member::from_streaming(&entry),
                options,
                &MemberCoding::Compressed,
                20_000,
                &mut sink,
                &resources,
                None,
                stream_above,
            )
            .unwrap();
            // Every fragment's payload went out while the member was charged.
            assert!(sink.payload_writes() > 2, "{stream_above}");
            assert_eq!(resources.workspace_in_use(), 0, "{stream_above}");

            let volumes = sink.collected.take();
            let extracted = collect_extract_volumes(&parse_volumes(&volumes), None).unwrap();
            assert!(
                extracted.len() == 1 && extracted[0].data == data,
                "{stream_above}"
            );
        }
    }

    /// The archive written with members over `stream_above` packed into a
    /// spool, and whether a spool sat in the temp directory while it was
    /// written out.
    fn written_above(
        entries: &[super::StreamingEntry],
        options: super::WriterOptions,
        stream_above: u64,
    ) -> (Vec<u8>, bool) {
        struct Watching {
            out: Vec<u8>,
            dir: std::path::PathBuf,
            saw_spool: bool,
        }
        impl std::io::Write for Watching {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.saw_spool |= std::fs::read_dir(&self.dir)?.next().is_some();
                self.out.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let dir = crate::scratch::case("rars-rar13-spooled");
        let resources = super::WriterResources::default().with_temp_dir(dir.to_path_buf());
        let members: Vec<_> = entries.iter().map(super::Member::from_streaming).collect();
        let mut out = Watching {
            out: Vec::new(),
            dir: dir.to_path_buf(),
            saw_spool: false,
        };
        super::write_archive_to(
            &members,
            options,
            super::MemberCoding::Compressed,
            None,
            &resources,
            None,
            super::CallerOutput::stream(&mut out),
            stream_above,
        )
        .unwrap();
        let left = std::fs::read_dir(&*dir).unwrap().count();
        assert_eq!(left, 0, "a spool was left behind");
        (out.out, out.saw_spool)
    }

    fn spooled_members() -> Vec<(&'static str, Vec<u8>)> {
        let mut state = 0x2545_f491_u32;
        let noise = (0..150_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        vec![
            ("small.txt", b"small and below the threshold\n".to_vec()),
            ("log.txt", synthetic_log_payload(1500)),
            ("noise.bin", noise),
        ]
    }

    fn check_spooled_archive(password: Option<&[u8]>) {
        let contents = spooled_members();
        let entries: Vec<_> = contents
            .iter()
            .map(|(name, data)| {
                let entry = super::StreamingEntry::new(
                    name.as_bytes().to_vec(),
                    super::EntrySource::from_bytes(data.clone()),
                );
                match password {
                    Some(password) => entry.with_password(password.to_vec()),
                    None => entry,
                }
            })
            .collect();
        for solid in [false, true] {
            let mut features = FeatureSet::store_only();
            features.solid = solid;
            let options = WriterOptions {
                target: ArchiveVersion::Rar14,
                features,
                compression_level: Some(3),
            };

            let (spooled, saw_spool) = written_above(&entries, options, 64 * 1024);

            assert!(saw_spool, "nothing was spooled");
            let (whole, saw_spool) = written_above(&entries, options, u64::MAX);
            assert!(!saw_spool);
            assert!(spooled == whole, "solid: {solid}");
            let archive = Archive::parse(&spooled).unwrap();
            let methods: Vec<_> = archive
                .entries
                .iter()
                .map(|entry| entry.header.method)
                .collect();
            // What packing does not shrink is stored, except in a solid run,
            // which a stored member would break.
            let stored = if solid { METHOD_BEST } else { METHOD_STORE };
            assert_eq!(methods, [stored, METHOD_BEST, stored]);
            let extracted = collect_extract(&archive, password).unwrap();
            let extracted: Vec<_> = extracted.into_iter().map(|entry| entry.data).collect();
            let expected: Vec<_> = contents.iter().map(|(_, data)| data.clone()).collect();
            assert!(extracted == expected, "solid: {solid}");
        }
    }

    #[test]
    fn a_spooled_member_writes_the_archive_the_in_memory_writer_does() {
        check_spooled_archive(None);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn a_spooled_member_is_encrypted_as_it_is_copied_out() {
        check_spooled_archive(Some(b"spooled"));
    }

    #[test]
    fn verification_decodes_against_the_member_without_a_copy() {
        let data = b"verification compares as it decodes, verification compares".repeat(40);
        let packed = super::unpack15_encode(&data).unwrap();
        assert!(super::unpack15_payload_matches(&packed, &data).unwrap());
        let mut changed = data.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(!super::unpack15_payload_matches(&packed, &changed).unwrap());
        changed = data.clone();
        changed[0] ^= 1;
        assert!(!super::unpack15_payload_matches(&packed, &changed).unwrap());
    }

    #[test]
    fn writer_cancellation_during_workspace_admission_is_preserved() {
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
        let options = super::WriterOptions::default();
        assert!(matches!(
            super::encode_member(
                &super::Member::from_file(&entry),
                options,
                &crate::MemberCoding::Stored,
                super::rar15_encode_options_for_level(options.compression_level),
                None,
                &resources,
                &work,
                u64::MAX,
                false,
            ),
            Err(crate::Error::Cancelled)
        ));
        assert_eq!(callback.0.load(Ordering::Relaxed), 2);
        assert_eq!(resources.workspace_in_use(), 0);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn encrypted_extraction_preserves_output_io_failures() {
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed output",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let data = b"encrypted output failure".repeat(64);
        let input = [FileEntry {
            name: b"encrypted.bin",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pw"),
            file_comment: None,
        }];
        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        assert!(!archive.entries[0].is_stored());
        let error = archive
            .extract_to(Some(b"pw"), |_| Ok(Box::new(FailingWriter)))
            .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert!(error.to_string().contains("closed output"));
    }

    #[test]
    fn volume_headers_accept_the_largest_legacy_name() {
        let name = vec![b'N'; 255];
        let payload = b"abcdef";
        let volumes = crate::volume_test_support::sized_for_payload(3, |volume_size| {
            write_stored_volumes(
                StoredEntry {
                    name: &name,
                    data: payload,
                    file_time: 0,
                    file_attr: 0x20,
                    password: None,
                    file_comment: None,
                },
                WriterOptions::default(),
                volume_size,
            )
        })
        .unwrap();
        assert_eq!(volumes.len(), 2);
        let archives: Vec<_> = volumes.iter().map(|v| Archive::parse(v).unwrap()).collect();
        for archive in &archives {
            assert_eq!(archive.entries[0].name, name);
        }
        assert_eq!(
            collect_extract_volumes(&archives, None).unwrap()[0].data,
            payload
        );
    }

    #[test]
    fn reader_workspace_rar13_stored_archives_need_no_dictionary_allocation() {
        for encrypted in crate::test_features::encryption_cases() {
            let password = encrypted.then_some(b"pw".as_slice());
            let input = [StoredEntry {
                name: b"stored.bin",
                data: b"stored payload",
                file_time: 0,
                file_attr: 0x20,
                password,
                file_comment: None,
            }];
            let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
            let archive = Archive::parse(&bytes).unwrap();
            let quota = Allowance::limited(0);
            archive
                .extract_with_allowance(
                    crate::ArchiveReadOptions::with_optional_password(password),
                    &mut |_| Ok(Box::new(std::io::sink())),
                    None,
                    None,
                    &quota,
                )
                .unwrap();
            assert_eq!(quota.used(), 0);
        }
    }

    #[test]
    fn reader_workspace_rar13_refusals_release_dictionary_input_and_stream_buffers() {
        use crate::codec::workspace::RefusingBudget;
        let data = b"abcabcabc".repeat(64);
        for encrypted in crate::test_features::encryption_cases() {
            let password = encrypted.then_some(b"pw".as_slice());
            let input = [FileEntry {
                name: b"compressed.bin",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                password,
                file_comment: None,
            }];
            let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
            let archive = Archive::parse(&bytes).unwrap();
            let entry = &archive.entries[0];
            assert!(!entry.is_stored());
            let run = |quota: &RefusingBudget| -> Result<()> {
                let mut decoder = Decoder15::with_allowance(quota);
                let mut out = Buffer::new(quota);
                entry.write_compressed_to(&archive, password, &mut decoder, false, &mut out)?;
                assert_eq!(&out[..], &data);
                Ok(())
            };
            let baseline = RefusingBudget::new(usize::MAX);
            run(&baseline).unwrap();
            assert_eq!(baseline.used(), 0);
            for index in 0..baseline.attempts() {
                let quota = RefusingBudget::new(index);
                let error = run(&quota).unwrap_err();
                assert_eq!(
                    entry.entry_error("extracting", error).kind(),
                    crate::ErrorKind::Cancelled,
                    "allocation {index}"
                );
                assert_eq!(quota.used(), 0);
            }
            let quota = Allowance::limited(1);
            let error = archive
                .extract_with_allowance(
                    crate::ArchiveReadOptions::with_optional_password(password),
                    &mut |_| Ok(Box::new(std::io::sink())),
                    None,
                    None,
                    &quota,
                )
                .unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
            assert_eq!(quota.used(), 0);
        }
    }

    #[test]
    fn writer_limits_are_invalid_arguments() {
        for error in [
            super::validate_member(b"", 0).unwrap_err(),
            super::validate_member(&[b'a'; 256], 0).unwrap_err(),
            super::encode_file_comment(Some(&vec![0; 65536])).unwrap_err(),
            super::encode_archive_comment(Some(&vec![0; 65536])).unwrap_err(),
        ] {
            assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument, "{error}");
        }
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            super::validate_member(b"large", u32::MAX as usize + 1)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::InvalidArgument
        );
    }

    #[test]
    fn header_budget_refuses_full_main_read_after_prefix() {
        let mut prefix = super::RAR13_SIGNATURE.to_vec();
        prefix.extend_from_slice(&64u16.to_le_bytes());
        prefix.push(0);
        let mut reader = crate::parse_budget::PrefixReader::new(prefix);
        let e = super::Archive::parse_seekable(
            &mut reader,
            128,
            0,
            super::ArchiveSource::Memory(std::sync::Arc::new([])),
            crate::ArchiveReadOptions::new().with_max_header_bytes(63),
        )
        .unwrap_err();
        assert!(matches!(
            e.root_cause(),
            crate::Error::HeaderBytesLimitExceeded { required: 64, .. }
        ));
        assert_eq!(reader.reads, [7]);
    }

    #[test]
    fn limited_header_admission_rejects_malformed_fixed_prefixes() {
        let options = crate::ArchiveReadOptions::new().with_max_header_count(2);
        let check = |prefix: &[u8], remaining, main| {
            let mut budget = crate::parse_budget::ParseBudget::new(options);
            super::admit_header(prefix, remaining, main, &mut budget, 0).unwrap_err()
        };

        let mut main = [0u8; super::MAIN_HEAD_SIZE as usize];
        main[..4].copy_from_slice(super::RAR13_SIGNATURE);
        main[4..6].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(check(&main[..6], 7, true), Error::TooShort);
        let mut wrong_signature = main;
        wrong_signature[0] = 0;
        assert_eq!(
            check(&wrong_signature, 7, true),
            Error::UnsupportedSignature
        );
        main[4..6].copy_from_slice(&6u16.to_le_bytes());
        assert_eq!(
            check(&main, 7, true),
            Error::InvalidHeader("RAR 1.3 main header is shorter than 7 bytes")
        );
        main[4..6].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(check(&main, 7, true), Error::TooShort);

        let mut file = [0u8; super::FILE_HEAD_BASE_SIZE];
        file[19] = 3;
        file[10..12].copy_from_slice(&24u16.to_le_bytes());
        assert_eq!(check(&file[..20], 24, false), Error::TooShort);
        file[10..12].copy_from_slice(&23u16.to_le_bytes());
        assert_eq!(
            check(&file, 24, false),
            Error::InvalidHeader("RAR 1.3 file header is shorter than its name")
        );
        file[10..12].copy_from_slice(&25u16.to_le_bytes());
        assert_eq!(check(&file, 24, false), Error::TooShort);
    }
    use super::*;
    use crate::atomic64::AtomicU64;
    use crate::codec::rar13::{find_long_lz, LongLz};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct CollectWriter(Rc<RefCell<Vec<u8>>>);

    #[test]
    fn compressed_writer_reports_balanced_progress_events() {
        let entries = [
            FileEntry {
                name: b"one.txt",
                data: b"one one one one",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"two.txt",
                data: b"two two two two",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let operation_starts = AtomicUsize::new(0);
        let operation_finishes = AtomicUsize::new(0);
        let entry_starts = AtomicUsize::new(0);
        let entry_finishes = AtomicUsize::new(0);
        let advances = AtomicUsize::new(0);
        let last_completed = AtomicU64::new(0);
        let expected_total = AtomicU64::new(0);
        let reporter = |event: WriteProgressEvent<'_>| match event {
            WriteProgressEvent::OperationStarted { total_bytes, .. } => {
                operation_starts.fetch_add(1, Ordering::Relaxed);
                expected_total.store(total_bytes.unwrap_or(0), Ordering::Relaxed);
            }
            WriteProgressEvent::OperationFinished { .. } => {
                operation_finishes.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::EntryStarted { .. } => {
                entry_starts.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::EntryFinished { .. } => {
                entry_finishes.fetch_add(1, Ordering::Relaxed);
            }
            WriteProgressEvent::Advanced {
                completed_bytes,
                total_bytes,
                ..
            } => {
                assert!(completed_bytes >= last_completed.swap(completed_bytes, Ordering::Relaxed));
                assert!(completed_bytes <= total_bytes);
                advances.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        };

        write_compressed_archive_with_comment_and_progress(
            &entries,
            WriterOptions::default(),
            None,
            Some(&reporter),
        )
        .unwrap();

        assert_eq!(operation_starts.load(Ordering::Relaxed), 1);
        assert_eq!(operation_finishes.load(Ordering::Relaxed), 1);
        assert_eq!(entry_starts.load(Ordering::Relaxed), entries.len());
        assert_eq!(entry_finishes.load(Ordering::Relaxed), entries.len());
        assert!(advances.load(Ordering::Relaxed) >= entries.len());
        assert_eq!(
            last_completed.load(Ordering::Relaxed),
            expected_total.load(Ordering::Relaxed)
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        file_attr: u8,
        is_directory: bool,
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
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
            Ok(Box::new(CollectWriter(data)))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: meta.file_attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_extract_volumes(
        volumes: &[Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        extract_volumes_to(volumes, password, |meta| {
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
                file_attr: meta.file_attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn synthetic_log_payload(lines: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for index in 0..lines {
            data.extend_from_slice(
                format!(
                    "2026-05-12T12:{:02}:{:02}.000Z INFO worker-{:02} request_id={:04x}-{:05} path=/api/v1/items/{} status={} elapsed_ms={} bytes={} message=processed archive chunk retry={} user=service-{}\n",
                    index % 60,
                    (index * 7) % 60,
                    index % 16,
                    index % 10000,
                    (index * 17) % 100000,
                    index % 2048,
                    200 + (index % 5),
                    (index * 37) % 5000,
                    (index * 911) % 65536,
                    index % 3,
                    index % 32
                )
                .as_bytes(),
            );
        }
        data
    }

    #[test]
    fn writes_and_reads_stored_archive() {
        let input = [
            StoredEntry {
                name: b"README.md",
                data: b"hello rar 1.3",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"docs",
                data: b"",
                file_time: 0,
                file_attr: 0x10,
                password: None,
                file_comment: None,
            },
        ];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].name_bytes(), b"README.md");
        assert_eq!(archive.entries[0].name_lossy(), "README.md");
        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"hello rar 1.3");
        assert!(archive.entries[1].is_directory());
        assert!(extracted[1].is_directory);
    }

    #[test]
    fn rejects_malformed_main_header_boundaries() {
        assert_eq!(MainHeader::parse(b"RE~"), Err(Error::TooShort));

        let mut too_small = Vec::from(&b"RE~^"[..]);
        too_small.extend_from_slice(&6u16.to_le_bytes());
        too_small.push(0x80);
        assert_eq!(
            MainHeader::parse(&too_small),
            Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes"
            ))
        );

        let mut truncated_extra = Vec::from(&b"RE~^"[..]);
        truncated_extra.extend_from_slice(&8u16.to_le_bytes());
        truncated_extra.push(0x80);
        assert_eq!(MainHeader::parse(&truncated_extra), Err(Error::TooShort));

        assert!(matches!(
            Archive::parse(b"Rar!\x1a\x07\x00"),
            Err(Error::UnsupportedSignature)
        ));
    }

    #[test]
    fn rejects_file_header_shorter_than_its_name() {
        let mut bytes = Vec::from(&b"RE~^"[..]);
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.push(0x80);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(FILE_HEAD_BASE_SIZE as u16).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0x20);
        bytes.push(0);
        bytes.push(DEFAULT_UNP_VER);
        bytes.push(10);
        bytes.push(METHOD_STORE);

        assert!(matches!(
            Archive::parse(&bytes),
            Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name"
            ))
        ));
    }

    #[test]
    fn rejects_truncated_file_payload_during_parse() {
        let input = [StoredEntry {
            name: b"hello.txt",
            data: b"hello",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        bytes.pop();

        assert!(matches!(Archive::parse(&bytes), Err(Error::TooShort)));
    }

    #[test]
    fn returns_none_for_absent_archive_comment() {
        let bytes = write_stored_archive(&[], WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.archive_comment().unwrap(), None);
    }

    #[test]
    fn rejects_normal_extract_on_split_entries() {
        let entry = StoredEntry {
            name: b"split.bin",
            data: b"abcdefghijklmnopqrstuvwxyz",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let volumes = crate::volume_test_support::sized_for_payload(8, |volume_size| {
            write_stored_volumes(entry, WriterOptions::default(), volume_size)
        })
        .unwrap();
        let first = Archive::parse(&volumes[0]).unwrap();

        assert_eq!(
            collect_extract(&first, None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
        assert_eq!(
            collect_extract(&first, None),
            Err(Error::InvalidHeader(
                "RAR 1.3 split entry requires multivolume extraction"
            ))
        );
    }

    #[test]
    fn controlled_extraction_rejects_split_member_without_volume_set() {
        let entry = StoredEntry {
            name: b"split.bin",
            data: b"abcdefghijklmnopqrstuvwxyz",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let volumes = crate::volume_test_support::sized_for_payload(8, |volume_size| {
            write_stored_volumes(entry, WriterOptions::default(), volume_size)
        })
        .unwrap();
        for volume in [&volumes[0], volumes.last().unwrap()] {
            let archive = crate::Archive::Rar13(Archive::parse(volume).unwrap());
            let error = archive
                .extract_with_control(crate::ArchiveReadOptions::new(), |_| {
                    Ok(crate::ExtractionDecision::Extract(Box::new(Vec::new())))
                })
                .unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::InvalidHeader("RAR 1.3 split entry requires multivolume extraction")
            );
        }
    }

    #[test]
    fn rejects_malformed_comment_extensions() {
        let packed_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT | MHD_PACK_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 1u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
            truncation: None,
        };
        assert_eq!(
            packed_too_short.archive_comment(),
            Err(Error::InvalidHeader(
                "RAR 1.3 packed archive comment is shorter than size field"
            ))
        );

        let unpacked_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 4u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
            truncation: None,
        };
        assert_eq!(unpacked_too_short.archive_comment(), Err(Error::TooShort));
    }

    #[test]
    fn rejects_malformed_av_extensions() {
        let too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: 5u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
            truncation: None,
        };
        assert_eq!(
            too_short.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"))
        );

        let bad_prefix = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: {
                    let mut extra = 6u16.to_le_bytes().to_vec();
                    extra.extend_from_slice(b"badbad");
                    extra
                },
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
            truncation: None,
        };
        assert_eq!(
            bad_prefix.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"))
        );

        let mut truncated_payload = bad_prefix;
        truncated_payload.main.extra[0..2].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(
            truncated_payload.authenticity_verification(),
            Err(Error::TooShort)
        );
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn writes_and_reads_encrypted_stored_archive() {
        let input = [StoredEntry {
            name: b"secret.txt",
            data: b"secret bytes",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        match collect_extract(&archive, None) {
            Err(Error::NeedPassword) => {}
            Err(Error::AtEntry { source, .. }) if matches!(*source, Error::NeedPassword) => {}
            other => panic!("expected missing password error, got {other:?}"),
        }

        let extracted = collect_extract(&archive, Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, b"secret bytes");
    }

    #[test]
    fn writes_and_reads_archive_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_stored_archive_with_comment(
            &input,
            WriterOptions::default(),
            Some(b"This is an archive comment."),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.has_archive_comment());
        assert!(archive.main.has_packed_comment());
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"This is an archive comment."[..])
        );
        assert_eq!(
            collect_extract(&archive, None).unwrap()[0].data,
            b"hello rar 1.3"
        );
    }

    #[test]
    fn writes_and_reads_file_comment() {
        let input = [StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"file comment\r\n"),
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].has_file_comment());
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"file comment\r\n"[..])
        );
        assert_eq!(
            collect_extract(&archive, None).unwrap()[0].data,
            b"hello rar 1.3"
        );

        let mut truncated_comment = archive.entries[0].clone();
        truncated_comment.extra = vec![5, 0, b'x'];
        assert_eq!(truncated_comment.file_comment(), Err(Error::TooShort));
        assert!(matches!(
            archive.entries[0].verify_checksum(b"wrong data"),
            Err(Error::CrcMismatch { .. })
        ));
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive() {
        let input = [FileEntry {
            name: b"tiny.txt",
            data: b"literal bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.flags, 0x80);
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, b"tiny.txt");
        assert!(archive.entries[0].is_stored());
        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(
            archive.entries[0].header.pack_size,
            input[0].data.len() as u32
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"literal bytes over sixteen");
    }

    #[test]
    fn writes_and_reads_literal_only_compressed_archive_with_repeated_stmode() {
        let data =
            b"this literal-only payload is long enough to enter and exit stmode more than once";
        let input = [FileEntry {
            name: b"long.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_BEST);

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_levels_control_rar15_encoder_policy() {
        let mut data: Vec<_> = (0..5000).map(|index| (index * 73 + 19) as u8).collect();
        data.extend_from_within(..256);
        let input = [FileEntry {
            name: b"level-policy.bin",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let level_one =
            write_compressed_archive(&input, WriterOptions::default().with_compression_level(1))
                .unwrap();
        let level_five =
            write_compressed_archive(&input, WriterOptions::default().with_compression_level(5))
                .unwrap();
        let level_one = Archive::parse(&level_one).unwrap();
        let level_five = Archive::parse(&level_five).unwrap();
        let level_one_file = &level_one.entries[0];
        let level_five_file = &level_five.entries[0];

        assert_eq!(level_one_file.header.method, METHOD_BEST);
        assert_eq!(level_five_file.header.method, METHOD_BEST);
        assert!(level_five_file.header.pack_size < level_one_file.header.pack_size);
        assert_eq!(collect_extract(&level_one, None).unwrap()[0].data, data);
        assert_eq!(collect_extract(&level_five, None).unwrap()[0].data, data);
    }

    #[test]
    fn rar14_writer_uses_old_distance_tokens() {
        for level in 0..=5 {
            let options = rar15_encode_options_for_level(Some(level));
            assert!(
                options.old_distance_tokens_enabled(),
                "RAR 1.4 level {level} should consider old-distance tokens"
            );
        }
    }

    #[test]
    fn rar14_level_five_uses_lazy_matching() {
        for level in 0..5 {
            assert!(!rar15_encode_options_for_level(Some(level)).lazy_matching_enabled());
        }
        assert!(rar15_encode_options_for_level(Some(5)).lazy_matching_enabled());
    }

    #[test]
    fn compressed_writer_keeps_adaptive_lz_planning_in_sync_after_literals() {
        let data = synthetic_log_payload(8000);
        let input = [FileEntry {
            name: b"synthetic.log",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes =
            write_compressed_archive(&input, WriterOptions::default().with_compression_level(2))
                .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted = collect_extract(&archive, None).unwrap();

        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_short_lz_matches() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabc";
        let input = [FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_BEST);
        assert!(
            archive.entries[0].header.pack_size < data.len() as u32,
            "ShortLZ should make the repeated payload smaller than stored data"
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_emits_long_lz_matches() {
        let mut data = short_lz_resistant_prefix(300);
        data.extend_from_within(..32);
        assert_eq!(
            find_long_lz(&data, 300, 0x8000),
            Some(LongLz {
                distance: 44,
                length: 32
            })
        );
        let input = [FileEntry {
            name: b"far.txt",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let literal_only = Unpack15Encoder::new()
            .encode_literals_only(&data)
            .unwrap()
            .len();
        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_BEST);
        assert!(
            (archive.entries[0].header.pack_size as usize) < literal_only,
            "LongLZ should make a >256-byte-distance repeat smaller than literal-only output"
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn compressed_writer_stores_incompressible_member_when_smaller() {
        let mut state = 0x8765_4321u32;
        let data: Vec<_> = (0..8192)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let input = [FileEntry {
            name: b"randomish.bin",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(archive.entries[0].header.pack_size, data.len() as u32);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, data);
    }

    #[test]
    fn compressed_writer_stores_tiny_incompressible_member_when_smaller() {
        let data = b"\x00\xff\x12\xed\x34\xcb\x56\xa9\x78\x87\x9a\x65\xbc\x43\xde\x21";
        let input = [FileEntry {
            name: b"tiny.bin",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(archive.entries[0].header.pack_size, data.len() as u32);
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, data);
    }

    #[test]
    fn writes_and_reads_solid_compressed_archive() {
        let input = [
            FileEntry {
                name: b"first.txt",
                data: b"first member primes the adaptive unpack15 state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"second.txt",
                data: b"second member is encoded without resetting that state",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
            ..WriterOptions::default()
        };

        let bytes = write_compressed_archive(&input, options).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.is_solid());
        assert_eq!(archive.entries.len(), 2);
        assert!(archive
            .entries
            .iter()
            .all(|entry| entry.header.flags & LHD_SOLID != 0));

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
        assert_eq!(extracted[1].data, input[1].data);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn writes_and_reads_encrypted_compressed_archive() {
        let input = [FileEntry {
            name: b"secret.txt",
            data: b"secret compressed bytes over sixteen",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pass"),
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_encrypted());
        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert!(matches!(
            collect_extract(&archive, None),
            Err(Error::NeedPassword)
        ));

        let extracted = collect_extract(&archive, Some(b"pass")).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_compressed_file_comment() {
        let input = [FileEntry {
            name: b"commented.txt",
            data: b"compressed member with file comment",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"compressed file comment"),
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(
            archive.entries[0].file_comment().unwrap().as_deref(),
            Some(&b"compressed file comment"[..])
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, input[0].data);
    }

    #[test]
    fn writes_and_reads_stored_multivolume_archive() {
        let entry = StoredEntry {
            name: b"random.bin",
            data: b"abcdefghijklmnopqrstuvwxyz0123456789",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = crate::volume_test_support::sized_for_payload(10, |volume_size| {
            write_stored_volumes(entry, WriterOptions::default(), volume_size)
        })
        .unwrap();
        assert_eq!(bytes.len(), 4);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_split_before());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes[1].entries[0].is_split_before());
        assert!(volumes[1].entries[0].is_split_after());
        assert!(volumes[3].entries[0].is_split_before());
        assert!(!volumes[3].entries[0].is_split_after());
        assert!(volumes.iter().all(|archive| archive.entries[0].is_stored()));

        let extracted = collect_extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"random.bin");
        assert_eq!(extracted[0].data, entry.data);
    }

    #[test]
    fn writes_and_reads_compressed_multivolume_archive() {
        let data = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
        let entry = FileEntry {
            name: b"repeat.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let bytes = crate::volume_test_support::sized_for_payload(8, |volume_size| {
            write_compressed_volumes(entry, WriterOptions::default(), volume_size)
        })
        .unwrap();
        assert!(bytes.len() >= 2);
        let volumes: Vec<_> = bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();
        assert!(volumes.iter().all(|archive| archive.main.is_volume()));
        assert!(!volumes[0].entries[0].is_stored());
        assert!(volumes[0].entries[0].is_split_after());
        assert!(volumes.last().unwrap().entries[0].is_split_before());
        assert!(!volumes.last().unwrap().entries[0].is_split_after());

        let extracted = collect_extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, b"repeat.txt");
        assert_eq!(extracted[0].data, data);
    }

    fn short_lz_resistant_prefix(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            let next = (0u8..=u8::MAX)
                .find(|&candidate| {
                    if data.len() < 2 {
                        return true;
                    }
                    let start = data.len().saturating_sub(256);
                    !data[start..].windows(3).any(|window| {
                        window == [data[data.len() - 2], data[data.len() - 1], candidate]
                    })
                })
                .expect("byte alphabet can avoid local 3-byte repeats");
            data.push(next);
        }
        data
    }

    #[test]
    fn writes_empty_compressed_archive_member() {
        let input = [FileEntry {
            name: b"empty.bin",
            data: b"",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(archive.entries[0].header.method, METHOD_STORE);
        assert_eq!(archive.entries[0].header.pack_size, 0);

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, b"");
    }

    #[test]
    fn rejects_rar5_only_features_for_rar13() {
        let mut features = FeatureSet::store_only();
        features.quick_open = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar13,
            features,
            ..WriterOptions::default()
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedWriterOption {
                target: ArchiveVersion::Rar13,
                option: WriterOption::Feature(crate::Feature::QuickOpen),
                because: None,
            }
        );
        assert_eq!(
            err.to_string(),
            "a quick-open index is not supported by rar13"
        );
    }

    #[test]
    fn rejects_header_encryption_for_rar13() {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;

        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
            ..WriterOptions::default()
        };
        let err = write_stored_archive(&[], options).unwrap_err();
        if cfg!(feature = "encryption") {
            assert_eq!(
                err.to_string(),
                "header encryption is not supported by rar14"
            );
        } else {
            assert_eq!(
                err,
                Error::FeatureDisabled {
                    feature: "encryption"
                }
            );
        }
    }

    #[test]
    fn file_checksum_matches_rar13_algorithm() {
        assert_eq!(file_checksum(b""), 0x0000);
        assert_eq!(file_checksum(b"123456789"), 0xc78a);
    }

    #[test]
    fn rar13_checksum_writer_flush_propagates_to_inner_writer() {
        struct FlushSpy {
            data: Vec<u8>,
            flushed: usize,
        }
        impl Write for FlushSpy {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.data.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushed += 1;
                Ok(())
            }
        }
        let mut inner = FlushSpy {
            data: Vec::new(),
            flushed: 0,
        };
        let mut checksum = Rar13Checksum::new();
        let mut writer = Rar13ChecksumWriter {
            inner: &mut inner,
            checksum: &mut checksum,
        };
        writer.write_all(b"hello").unwrap();
        writer.flush().unwrap();
        assert_eq!(inner.data, b"hello");
        assert_eq!(inner.flushed, 1);
    }

    #[test]
    fn entry_packed_data_returns_borrowed_slice_for_memory_archives() {
        let payload = b"packed_data direct accessor coverage";
        let input = [StoredEntry {
            name: b"slice.bin",
            data: payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let entry = &archive.entries[0];

        let packed = entry.packed_data(&archive).unwrap();
        assert_eq!(packed, payload);
        assert!(!packed.is_empty());
    }

    #[test]
    fn extract_volumes_to_annotates_failed_non_split_entry_with_at_entry() {
        let payload = b"corrupt-me-please";
        let input = [StoredEntry {
            name: b"plain.bin",
            data: payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let range = archive.entries[0].packed_range.clone();
        // Flip a byte in the stored payload so the checksum no longer matches.
        bytes[range.start] ^= 0xff;

        let corrupted = Archive::parse(&bytes).unwrap();
        let err = collect_extract_volumes(std::slice::from_ref(&corrupted), None).unwrap_err();
        match err {
            Error::AtEntry {
                name,
                operation,
                source,
            } => {
                assert_eq!(name, b"plain.bin");
                assert_eq!(operation, "extracting");
                assert!(matches!(*source, Error::CrcMismatch { .. }));
            }
            other => panic!("expected AtEntry annotation, got {other:?}"),
        }
    }

    #[test]
    fn extract_volumes_to_annotates_failed_split_completion_with_at_entry() {
        let entry = StoredEntry {
            name: b"split.bin",
            data: b"abcdefghijklmnopqrstuvwxyz0123456789",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };

        let mut volume_bytes = crate::volume_test_support::sized_for_payload(10, |volume_size| {
            write_stored_volumes(entry, WriterOptions::default(), volume_size)
        })
        .unwrap();
        assert!(
            volume_bytes.len() >= 2,
            "need at least two volumes to exercise the split-completion path"
        );

        // Corrupt the last fragment so PendingSplitRefs::write_to fails on assembly.
        let last_index = volume_bytes.len() - 1;
        let last_archive = Archive::parse(&volume_bytes[last_index]).unwrap();
        let last_range = last_archive.entries[0].packed_range.clone();
        volume_bytes[last_index][last_range.start] ^= 0x7f;

        let volumes: Vec<_> = volume_bytes
            .iter()
            .map(|bytes| Archive::parse(bytes).unwrap())
            .collect();

        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        match err {
            Error::AtEntry {
                name,
                operation,
                source,
            } => {
                assert_eq!(name, b"split.bin");
                assert_eq!(operation, "extracting");
                assert!(
                    matches!(*source, Error::CrcMismatch { .. }),
                    "expected CrcMismatch source, got {source:?}"
                );
            }
            other => panic!("expected AtEntry annotation, got {other:?}"),
        }
    }

    #[test]
    fn entry_packed_data_refuses_to_buffer_file_backed_archives() {
        let payload = b"packed_data refuses file-backed";
        let input = [StoredEntry {
            name: b"file.bin",
            data: payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();

        let dir = crate::scratch::case("rars-rar13-packed-data");
        let path = dir.join("entry.rar");
        std::fs::write(&path, &bytes).unwrap();

        let archive = Archive::parse_path(&path).unwrap();
        let result = archive.entries[0].packed_data(&archive);
        assert_eq!(
            result,
            Err(Error::InvalidHeader(
                "RAR 1.3 file-backed packed data requires owned read"
            ))
        );
    }

    fn parse_volumes(bytes: &[Vec<u8>]) -> Vec<Archive> {
        bytes.iter().map(|b| Archive::parse(b).unwrap()).collect()
    }

    fn split_volumes_for(name: &[u8], data: &[u8]) -> Vec<Vec<u8>> {
        crate::volume_test_support::sized_for_payload(10, |volume_size| {
            write_stored_volumes(
                StoredEntry {
                    name,
                    data,
                    file_time: 0,
                    file_attr: 0x20,
                    password: None,
                    file_comment: None,
                },
                WriterOptions::default(),
                volume_size,
            )
        })
        .unwrap()
    }

    #[test]
    fn extract_volumes_to_rejects_pending_split_interrupted_by_regular_entry() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let mut volumes = parse_volumes(&bytes);

        // After volume 0's split_after entry, append a regular entry to the
        // same volume so the loop sees pending=Some when it hits a non-split.
        let mut intruder = volumes[0].entries[0].clone();
        intruder.header.flags &= !(LHD_SPLIT_BEFORE | LHD_SPLIT_AFTER);
        intruder.name = b"intruder.bin".to_vec();
        volumes[0].entries.push(intruder);

        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry is interrupted by a regular entry"),
        );
    }

    #[test]
    fn extract_volumes_to_rejects_split_with_inconsistent_flags() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let volumes = parse_volumes(&bytes);

        // Take just the *middle* volume in isolation: it has split_before=true
        // but no preceding pending state, which the match arm treats as
        // structurally inconsistent.
        let middle = volumes.into_iter().nth(1).unwrap();
        let err = collect_extract_volumes(std::slice::from_ref(&middle), None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry flags are inconsistent"),
        );
    }

    #[test]
    fn extract_volumes_to_rejects_pending_split_left_incomplete_at_end() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let volumes = parse_volumes(&bytes);

        // Use only the first volume, which leaves pending=Some after the loop.
        let err = collect_extract_volumes(std::slice::from_ref(&volumes[0]), None).unwrap_err();
        assert_eq!(err.root_cause(), &Error::MissingVolume);
    }

    #[test]
    fn extract_volumes_to_rejects_split_fragments_with_drifted_attributes() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let mut volumes = parse_volumes(&bytes);

        // Mutate the second volume's entry name so PendingSplitRefs::append
        // refuses it on a name-mismatch.
        volumes[1].entries[0].name = b"different.bin".to_vec();

        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry name changed")
        );
    }

    #[test]
    fn extract_volumes_to_rejects_split_fragments_with_drifted_method() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let mut volumes = parse_volumes(&bytes);

        // Drift the compression method on the second fragment.
        volumes[1].entries[0].header.method = METHOD_BEST;
        let err = collect_extract_volumes(&volumes, None).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.3 split entry compression method changed"),
        );
    }

    #[test]
    fn extract_volumes_to_rejects_split_version_and_encryption_drift() {
        let bytes = split_volumes_for(b"split.bin", b"abcdefghijklmnopqrstuvwxyz");
        let mut volumes = parse_volumes(&bytes);
        volumes[1].entries[0].header.unp_ver += 1;
        assert_eq!(
            collect_extract_volumes(&volumes, None).unwrap_err(),
            Error::InvalidHeader("RAR 1.3 split entry unpack version changed")
        );

        let mut volumes = parse_volumes(&bytes);
        volumes[1].entries[0].header.flags ^= LHD_PASSWORD;
        assert_eq!(
            collect_extract_volumes(&volumes, None).unwrap_err(),
            Error::InvalidHeader("RAR 1.3 split entry encryption flag changed")
        );
    }

    #[test]
    fn extract_volumes_to_carries_directory_entries_across_volume_array() {
        // A directory entry has zero-length data and gets the open() callback
        // invoked but no payload write. Putting it in a volumes array keeps
        // the directory branch in extract_volumes_to (rather than extract_to)
        // exercised.
        let input = [StoredEntry {
            name: b"docs",
            data: b"",
            file_time: 0,
            file_attr: 0x10,
            password: None,
            file_comment: None,
        }];
        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        let extracted = collect_extract_volumes(std::slice::from_ref(&archive), None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].is_directory);
        assert_eq!(extracted[0].name, b"docs");
    }

    #[test]
    fn extract_volumes_to_routes_pending_split_reader_through_fragment_chain() {
        // Larger payload over more volumes guarantees that the split reader
        // reads from every volume at least once.
        let payload: Vec<u8> = (0..96).map(|i| ((i * 53) ^ 0xa5) as u8).collect();
        let bytes = split_volumes_for(b"chain.bin", &payload);
        assert!(
            bytes.len() >= 3,
            "need at least three volumes for the chain"
        );
        let volumes = parse_volumes(&bytes);

        let extracted = collect_extract_volumes(&volumes, None).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, payload);
    }

    #[test]
    fn write_compressed_archive_with_comment_round_trips_through_archive_comment() {
        let data = b"compressed archive comment payload payload payload";
        let comment = b"This is a compressed archive comment.";
        let input = [FileEntry {
            name: b"payload.txt",
            data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];

        let bytes =
            write_compressed_archive_with_comment(&input, WriterOptions::default(), Some(comment))
                .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.has_archive_comment());
        assert!(archive.main.has_packed_comment());
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&comment[..])
        );

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data);
    }

    #[test]
    fn write_compressed_archive_with_comment_emits_solid_compressed_archive() {
        let data1 = b"solid compressed payload one with overlap overlap overlap";
        let data2 = b"solid compressed payload two with overlap overlap overlap";
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let options = WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
            ..WriterOptions::default()
        };
        let input = [
            FileEntry {
                name: b"a.txt",
                data: data1,
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"b.txt",
                data: data2,
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];

        let bytes = write_compressed_archive_with_comment(&input, options, None).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.main.is_solid());
        assert_eq!(archive.entries.len(), 2);

        let extracted = collect_extract(&archive, None).unwrap();
        assert_eq!(extracted[0].data, data1);
        assert_eq!(extracted[1].data, data2);
    }

    #[test]
    fn write_compressed_archive_with_comment_rejects_non_rar13_target() {
        let options = WriterOptions {
            target: ArchiveVersion::Rar15,
            ..WriterOptions::default()
        };
        let err = write_compressed_archive_with_comment(&[], options, None).unwrap_err();
        assert_eq!(err, Error::UnsupportedVersion(ArchiveVersion::Rar15));
    }

    #[test]
    fn parse_path_round_trips_multi_entry_archive_via_file_backed_seekable_path() {
        // Two entries plus an archive comment forces parse_seekable to walk
        // through more than one file-header read iteration.
        let input = [
            StoredEntry {
                name: b"first.txt",
                data: b"first payload",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"second.txt",
                data: b"second payload",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let bytes = write_stored_archive_with_comment(
            &input,
            WriterOptions::default(),
            Some(b"file-backed comment"),
        )
        .unwrap();

        let dir = crate::scratch::case("rars-rar13-parse-seekable");
        let path = dir.join("multi.rar");
        std::fs::write(&path, &bytes).unwrap();

        let archive = Archive::parse_path(&path).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.entries[0].name, b"first.txt");
        assert_eq!(archive.entries[1].name, b"second.txt");
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(&b"file-backed comment"[..])
        );
    }

    #[test]
    fn parse_path_rejects_files_without_rar13_signature() {
        let dir = crate::scratch::case("rars-rar13-parse-path-bad");
        let path = dir.join("not_a_rar.bin");
        std::fs::write(&path, [0u8; 64]).unwrap();

        let err = Archive::parse_path(&path).unwrap_err();
        assert_eq!(err, Error::UnsupportedSignature);
    }

    #[test]
    fn controlled_extraction_uses_selected_directory_and_file_writers() {
        let entries = [
            StoredEntry {
                name: b"docs",
                data: b"",
                file_time: 0,
                file_attr: 0x10,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"docs/readme.txt",
                data: b"old archive data",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let bytes = write_stored_archive(&entries, WriterOptions::default()).unwrap();
        let archive = crate::Archive::Rar13(Archive::parse(&bytes).unwrap());
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut seen = Vec::new();
        let outcome = archive
            .extract_with_control(crate::ArchiveReadOptions::new(), |member| {
                seen.push(member.meta.name.clone());
                Ok(crate::ExtractionDecision::Extract(Box::new(CollectWriter(
                    Rc::clone(&output),
                ))))
            })
            .unwrap();

        assert_eq!(outcome, crate::ExtractionOutcome::Complete);
        assert_eq!(seen, [b"docs".to_vec(), b"docs/readme.txt".to_vec()]);
        assert_eq!(&*output.borrow(), b"old archive data");
    }

    #[test]
    fn directory_extraction_skips_payload_even_with_compressed_method() {
        let entries = [StoredEntry {
            name: b"DIR",
            data: b"",
            file_time: 0,
            file_attr: 0x10,
            password: None,
            file_comment: None,
        }];
        let bytes = write_stored_archive(&entries, WriterOptions::default()).unwrap();
        let mut archive = Archive::parse(&bytes).unwrap();
        archive.entries[0].header.method = METHOD_BEST;
        assert!(collect_extract(&archive, None).unwrap()[0].is_directory);
        assert!(
            collect_extract_volumes(std::slice::from_ref(&archive), None).unwrap()[0].is_directory
        );
    }

    #[test]
    fn empty_rar13_archive_cannot_supply_preservation_target_version() {
        let bytes = write_stored_archive(&[], WriterOptions::default()).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries.is_empty());
        assert!(archive
            .rewrite_preservation_issues()
            .iter()
            .any(|issue| issue.contains("empty legacy archive")));
    }

    #[test]
    fn streaming_writer_refuses_unsupported_aggregate_quotas_before_output() {
        for (resources, feature) in [
            (
                WriterResources::default().with_max_preparation_bytes(0),
                "preparation memory quota",
            ),
            (
                WriterResources::default().with_max_memory_bytes(0),
                "aggregate managed-memory limit",
            ),
        ] {
            let mut output = Vec::new();
            let error = write_streaming_archive_to(
                &[],
                WriterOptions::default(),
                MemberCoding::Stored,
                None,
                &resources,
                None,
                &mut output,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                Error::UnsupportedFamilyFeature { feature: actual, .. } if actual == feature
            ));
            assert!(output.is_empty());
        }
    }

    #[test]
    fn volume_writer_rejects_empty_payload_for_both_codings() {
        let stored = StoredEntry {
            name: b"empty",
            data: b"",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let compressed = FileEntry {
            name: stored.name,
            data: stored.data,
            file_time: stored.file_time,
            file_attr: stored.file_attr,
            password: None,
            file_comment: None,
        };
        for error in [
            write_stored_volumes(stored, WriterOptions::default(), 1024).unwrap_err(),
            write_compressed_volumes(compressed, WriterOptions::default(), 1024).unwrap_err(),
        ] {
            assert!(matches!(
                error.root_cause(),
                Error::InvalidArgument("RAR 1.3 volume writer needs a non-empty packed payload")
            ));
        }
    }

    #[test]
    fn archive_comment_rejects_packed_output_beyond_header_field() {
        let mut state = 0x1234_5678u32;
        let comment: Vec<_> = (0..u16::MAX)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let valid = write_stored_archive_with_comment(
            &[],
            WriterOptions::default(),
            Some(&comment[..64700]),
        )
        .unwrap();
        assert_eq!(
            Archive::parse(&valid)
                .unwrap()
                .archive_comment()
                .unwrap()
                .unwrap(),
            comment[..64700]
        );
        assert_eq!(
            encode_archive_comment(Some(&comment[..64760]))
                .unwrap()
                .len(),
            65530
        );
        assert_eq!(
            write_stored_archive_with_comment(
                &[],
                WriterOptions::default(),
                Some(&comment[..64760]),
            )
            .unwrap_err(),
            Error::InvalidArgument("RAR 1.3 main header comment extension is too large")
        );
        let error =
            write_stored_archive_with_comment(&[], WriterOptions::default(), Some(&comment))
                .unwrap_err();
        assert_eq!(
            error,
            Error::InvalidArgument("RAR 1.3 packed archive comment is longer than 65535 bytes")
        );
    }

    #[test]
    fn supplied_rar13_signature_and_file_length_are_checked() {
        let entries = [StoredEntry {
            name: b"member",
            data: b"payload",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let bytes = write_stored_archive(&entries, WriterOptions::default()).unwrap();
        let signature = crate::detect_archive_family(&bytes).unwrap();
        let dir = crate::scratch::case("rars-rar13-supplied-signature");
        let path = dir.join("archive.rar");
        std::fs::write(&path, &bytes).unwrap();

        assert_eq!(
            Archive::parse_owned(bytes.clone()).unwrap().entries.len(),
            1
        );
        assert_eq!(
            Archive::parse_path_with_signature(&path, signature)
                .unwrap()
                .entries
                .len(),
            1
        );
        assert_eq!(
            Archive::parse_path_with_signature_and_options(
                &path,
                crate::ArchiveSignature {
                    family: ArchiveFamily::Rar15To40,
                    ..signature
                },
                crate::ArchiveReadOptions::new(),
            )
            .unwrap_err(),
            Error::UnsupportedSignature
        );

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] = 0;
        std::fs::write(&path, &wrong_magic).unwrap();
        assert_eq!(
            Archive::parse_path_with_signature(&path, signature).unwrap_err(),
            Error::UnsupportedSignature
        );

        let mut oversized_payload = bytes;
        let file_start = u16::from_le_bytes([oversized_payload[4], oversized_payload[5]]) as usize;
        oversized_payload[file_start..file_start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &oversized_payload).unwrap();
        assert_eq!(
            Archive::parse_owned(oversized_payload).unwrap_err(),
            Error::TooShort
        );
        assert_eq!(
            Archive::parse_path_with_signature(&path, signature).unwrap_err(),
            Error::TooShort
        );

        std::fs::write(&path, crate::detect::RAR15_SIGNATURE).unwrap();
        assert_eq!(
            Archive::parse_path(&path).unwrap_err(),
            Error::UnsupportedSignature
        );
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn extract_to_encrypted_archive_reads_through_file_backed_decrypted_range() {
        // The Memory-backed path is already exercised; this test takes the
        // same encrypted archive out to disk so the stored copy reads a file.
        let input = [StoredEntry {
            name: b"secret.bin",
            data: b"file-backed secret payload",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pw"),
            file_comment: None,
        }];
        let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();

        let dir = crate::scratch::case("rars-rar13-decrypt-file");
        let path = dir.join("encrypted.rar");
        std::fs::write(&path, &bytes).unwrap();

        let archive = Archive::parse_path(&path).unwrap();
        let extracted = collect_extract(&archive, Some(b"pw")).unwrap();
        assert_eq!(extracted[0].data, b"file-backed secret payload");
    }

    #[test]
    fn write_stored_volumes_rejects_password_protected_entries() {
        let entry = StoredEntry {
            name: b"locked.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: Some(b"pw"),
            file_comment: None,
        };
        let err = write_stored_volumes(entry, WriterOptions::default(), 16).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedWriterOption {
                target: ArchiveVersion::Rar14,
                option: WriterOption::Password,
                because: Some("in a volume set"),
            }
        );
        assert_eq!(
            err.to_string(),
            "encryption is not supported by rar14 (in a volume set)"
        );
    }

    #[test]
    fn write_compressed_volumes_rejects_file_comments() {
        let entry = FileEntry {
            name: b"with-comment.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(b"note"),
        };
        let err = write_compressed_volumes(entry, WriterOptions::default(), 16).unwrap_err();
        assert_eq!(
            err.to_string(),
            "a per-file comment is not supported by rar14 (in a volume set)"
        );
    }

    #[test]
    fn write_compressed_volumes_rejects_non_rar13_target() {
        let options = WriterOptions {
            target: ArchiveVersion::Rar20,
            ..WriterOptions::default()
        };
        let entry = FileEntry {
            name: b"x.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let err = write_compressed_volumes(entry, options, 16).unwrap_err();
        assert_eq!(err, Error::UnsupportedVersion(ArchiveVersion::Rar20));
    }

    #[test]
    fn file_header_parse_rejects_input_below_base_size() {
        let err = FileHeader::parse(&[0u8; FILE_HEAD_BASE_SIZE - 1]).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }

    #[test]
    fn file_header_parse_rejects_truncated_input_against_declared_head_size() {
        // Build a syntactically OK FILE_HEAD_BASE_SIZE buffer that declares a
        // head_size larger than the slice we pass in — exercises the
        // post-name-size length check at the end of FileHeader::parse.
        let mut header = [0u8; FILE_HEAD_BASE_SIZE];
        // pack_size, unp_size, file_crc, file_time stay zero.
        let declared_head_size: u16 = (FILE_HEAD_BASE_SIZE + 32) as u16;
        header[10..12].copy_from_slice(&declared_head_size.to_le_bytes());
        // name_size = 0 keeps minimum_size == FILE_HEAD_BASE_SIZE so the
        // earlier "shorter than its name" branch is bypassed.
        header[19] = 0;
        let err = FileHeader::parse(&header).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }

    #[test]
    fn archive_comment_rejects_size_field_shorter_than_two_bytes() {
        // Build a valid stored archive then patch its main header so the
        // declared comment field is shorter than two bytes — exercises the
        // "packed archive comment is shorter than size field" arm.
        let input = [StoredEntry {
            name: b"file.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let bytes =
            write_stored_archive_with_comment(&input, WriterOptions::default(), Some(b"hi"))
                .unwrap();
        let mut archive = Archive::parse(&bytes).unwrap();
        // The first two bytes of `main.extra` are the comment_field length —
        // overwrite them with 1 to declare a sub-2-byte payload while keeping
        // the packed-comment flag set.
        archive.main.extra[0] = 1;
        archive.main.extra[1] = 0;
        assert_eq!(
            archive.archive_comment(),
            Err(Error::InvalidHeader(
                "RAR 1.3 packed archive comment is shorter than size field"
            ))
        );
    }

    #[test]
    fn archive_comment_rejects_packed_payload_extending_past_extra_buffer() {
        let input = [StoredEntry {
            name: b"file.bin",
            data: b"data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }];
        let bytes =
            write_stored_archive_with_comment(&input, WriterOptions::default(), Some(b"hi"))
                .unwrap();
        let mut archive = Archive::parse(&bytes).unwrap();
        // Pump the declared comment field length up so the packed range walks
        // past the end of `main.extra`.
        let inflated = (archive.main.extra.len() as u16 + 16).to_le_bytes();
        archive.main.extra[0] = inflated[0];
        archive.main.extra[1] = inflated[1];
        assert_eq!(archive.archive_comment(), Err(Error::TooShort));
    }

    #[test]
    fn streaming_writer_attributes_source_size_failures() {
        let missing = crate::scratch::case("rars-rar13-missing-source").join("absent");
        for (source, expected, operation) in [
            (
                EntrySource::from_path(missing),
                crate::ErrorKind::Io,
                "reading source",
            ),
            (
                EntrySource::from_opener(u64::from(u32::MAX) + 1, || {
                    unreachable!("oversized source must fail before opening")
                }),
                crate::ErrorKind::InvalidArgument,
                "preparing",
            ),
        ] {
            let entry = StreamingEntry::new(b"SOURCE.BIN".to_vec(), source);
            let mut output = Vec::new();
            let error = write_streaming_archive_to(
                &[entry],
                WriterOptions::default(),
                MemberCoding::Stored,
                None,
                &WriterResources::default(),
                None,
                &mut output,
            )
            .unwrap_err();
            assert_eq!(error.kind(), expected);
            assert_eq!(error.entry_context(), Some((&b"SOURCE.BIN"[..], operation)));
        }
    }

    #[test]
    fn file_comment_respects_the_total_file_header_limit() {
        let max_comment_len = u16::MAX as usize - FILE_HEAD_BASE_SIZE - 1 - 2;
        let comment = vec![b'x'; max_comment_len + 1];
        let entry = StoredEntry {
            name: b"f",
            data: b"payload",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: Some(&comment[..max_comment_len]),
        };
        let valid = write_stored_archive(&[entry], WriterOptions::default()).unwrap();
        let archive = Archive::parse(&valid).unwrap();
        assert_eq!(
            archive.entries[0].file_comment().unwrap(),
            Some(comment[..max_comment_len].to_vec())
        );

        let oversized = StoredEntry {
            file_comment: Some(&comment),
            ..entry
        };
        assert!(matches!(
            write_stored_archive(&[oversized], WriterOptions::default())
                .unwrap_err()
                .root_cause(),
            Error::InvalidArgument("RAR 1.3 file header is longer than 65535 bytes")
        ));
    }

    #[test]
    fn verified_encoder_retries_corrupt_payload_then_accepts_valid_fallback() {
        let data = b"legacy archive payload legacy archive payload";
        let valid = unpack15_encode(data).unwrap();
        let options = Rar15EncodeOptions::new();
        let mut attempts = 0;
        let packed =
            encode_verified_rar15_payload_using(data, options, &mut |_| true, |_, _, _| {
                attempts += 1;
                Ok(if attempts == 1 {
                    Vec::new()
                } else {
                    valid.clone()
                })
            })
            .unwrap();
        assert_eq!(packed, Some(valid));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn verified_encoder_progress_counts_each_retry_once() {
        let data = b"legacy fallback progress payload";
        let valid = unpack15_encode(data).unwrap();
        let completed = std::sync::Mutex::new(Vec::new());
        let reporter = |event: WriteProgressEvent<'_>| {
            if let WriteProgressEvent::Advanced {
                completed_bytes, ..
            } = event
            {
                completed.lock().unwrap().push(completed_bytes);
            }
        };
        let work = WorkTracker::new(
            Some(ProgressReporter(&reporter)),
            WriteOperation::Compression,
            (data.len() * 3) as u64,
        );
        let mut last = 0;
        let mut progress = |position| advance_rar15_attempt(&mut last, &work, position);
        let mut attempts = 0;
        let packed = encode_verified_rar15_payload_using(
            data,
            Rar15EncodeOptions::new(),
            &mut progress,
            |input, _, report| {
                attempts += 1;
                assert!(report(0));
                assert!(report(input.len() / 2));
                assert!(report(input.len()));
                Ok(if attempts == 1 {
                    Vec::new()
                } else {
                    valid.clone()
                })
            },
        )
        .unwrap();
        assert_eq!(packed, Some(valid));
        assert_eq!(attempts, 2);
        let half = (data.len() / 2) as u64;
        let full = data.len() as u64;
        assert_eq!(
            *completed.lock().unwrap(),
            [0, half, full, full, full + half, full * 2]
        );
    }

    #[test]
    fn verified_payload_selection_preserves_storage_and_solid_history() {
        let data = b"original payload";
        let (payload, method) =
            select_verified_payload(std::borrow::Cow::Borrowed(data), Some(vec![1, 2]), false);
        assert_eq!(payload, [1, 2]);
        assert_eq!(method, METHOD_BEST);

        let owned = data.to_vec();
        let allocation = owned.as_ptr();
        let (payload, method) = select_verified_payload(
            std::borrow::Cow::Owned(owned),
            Some(vec![0; data.len() + 1]),
            false,
        );
        assert_eq!(payload, data);
        assert_eq!(payload.as_ptr(), allocation);
        assert_eq!(method, METHOD_STORE);

        let packed = vec![0; data.len() + 1];
        let (payload, method) =
            select_verified_payload(std::borrow::Cow::Borrowed(data), Some(packed.clone()), true);
        assert_eq!(payload, packed);
        assert_eq!(method, METHOD_BEST);
    }

    #[test]
    fn verified_encoder_stores_when_every_candidate_fails_verification() {
        let data = b"legacy archive payload";
        let mut attempts = 0;
        let packed = encode_verified_rar15_payload_using(
            data,
            Rar15EncodeOptions::new(),
            &mut |_| true,
            |_, _, _| {
                attempts += 1;
                Ok(Vec::new())
            },
        )
        .unwrap();
        assert_eq!(packed, None);
        let (payload, method) =
            select_verified_payload(std::borrow::Cow::Borrowed(data), packed, false);
        assert_eq!(payload, data);
        assert_eq!(method, METHOD_STORE);
        assert_eq!(
            attempts,
            rar15_encode_fallback_options(Rar15EncodeOptions::new()).len()
        );
    }

    #[test]
    fn verified_encoder_propagates_cancellation_during_fallback() {
        let data = b"legacy archive payload";
        let mut attempts = 0;
        let error = encode_verified_rar15_payload_using(
            data,
            Rar15EncodeOptions::new(),
            &mut |_| true,
            |_, _, _| {
                attempts += 1;
                if attempts == 1 {
                    Ok(Vec::new())
                } else {
                    Err(crate::codec::Error::Cancelled)
                }
            },
        )
        .unwrap_err();
        assert_eq!(error, Error::Cancelled);
        assert_eq!(attempts, 2);
    }

    #[test]
    fn streaming_writer_detects_source_size_change_between_passes() {
        struct ChangingLength(AtomicUsize);
        impl crate::streaming::SourceFactory for ChangingLength {
            fn len(&self) -> Result<u64> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    Ok(3)
                } else {
                    Err(Error::SourceChanged("source size changed"))
                }
            }

            fn open(&self) -> Result<Box<dyn crate::EntryReader>> {
                unreachable!("changed source must fail before opening")
            }
        }
        let entry = StreamingEntry::new(
            b"CHANGED.BIN".to_vec(),
            EntrySource::from_factory(ChangingLength(AtomicUsize::new(0))),
        );
        let error = write_streaming_archive_to(
            &[entry],
            WriterOptions::default(),
            MemberCoding::Stored,
            None,
            &WriterResources::default(),
            None,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::SourceChanged);
        assert_eq!(
            error.entry_context(),
            Some((&b"CHANGED.BIN"[..], "reading source"))
        );
    }

    #[test]
    fn compression_level_zero_writes_a_stored_member() {
        let entry = FileEntry {
            name: b"ZERO.TXT",
            data: b"zero-level compression leaves these bytes stored",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let bytes =
            write_compressed_archive(&[entry], WriterOptions::default().with_compression_level(0))
                .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert!(archive.entries[0].is_stored());
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, entry.data);
    }

    #[test]
    fn level_four_uses_a_distinct_verified_fallback_plan() {
        let options = rar15_encode_options_for_level(Some(4));
        let candidates = rar15_encode_fallback_options(options);
        assert_eq!(candidates.len(), 2);

        let data = b"level four compressed legacy payload ".repeat(32);
        let entry = FileEntry {
            name: b"LEVEL4.TXT",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let bytes =
            write_compressed_archive(&[entry], WriterOptions::default().with_compression_level(4))
                .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(collect_extract(&archive, None).unwrap()[0].data, data);
    }

    #[test]
    fn stored_volume_writer_refuses_non_legacy_target() {
        let entry = StoredEntry {
            name: b"WRONG.TXT",
            data: b"contents",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
        assert_eq!(
            write_stored_volumes(entry, options, 8).unwrap_err(),
            Error::UnsupportedVersion(ArchiveVersion::Rar50)
        );
    }

    #[test]
    fn solid_volume_writer_marks_every_fragment() {
        let data = b"a stored member across several solid volumes".repeat(16);
        let entry = FileEntry {
            name: b"SOLID.TXT",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let options = WriterOptions::new(ArchiveVersion::Rar14, features);
        let volumes = crate::volume_test_support::sized_for_payload(8, |volume_size| {
            write_compressed_volumes(entry, options, volume_size)
        })
        .unwrap();
        assert!(volumes.len() > 1);
        let archives = parse_volumes(&volumes);
        assert!(archives
            .iter()
            .all(|archive| archive.entries[0].header.flags & LHD_SOLID != 0));
        assert_eq!(
            collect_extract_volumes(&archives, None).unwrap()[0].data,
            entry.data
        );
    }

    #[test]
    fn final_archive_progress_report_can_cancel() {
        struct CancelOnAdvance(AtomicBool);
        impl WriteProgress for CancelOnAdvance {
            fn report(&self, event: WriteProgressEvent<'_>) {
                if matches!(event, WriteProgressEvent::Advanced { .. }) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }

            fn is_cancelled(&self) -> bool {
                self.0.load(Ordering::Relaxed)
            }
        }
        let reporter = CancelOnAdvance(AtomicBool::new(false));
        let error = write_streaming_archive_to(
            &[],
            WriterOptions::default(),
            MemberCoding::Stored,
            None,
            &WriterResources::default(),
            Some(&reporter),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, Error::Cancelled);
    }

    #[test]
    fn final_volume_progress_report_can_cancel() {
        struct CancelOnFinalAdvance {
            entry_finished: AtomicBool,
            cancelled: AtomicBool,
        }
        impl WriteProgress for CancelOnFinalAdvance {
            fn report(&self, event: WriteProgressEvent<'_>) {
                match event {
                    WriteProgressEvent::EntryFinished { .. } => {
                        self.entry_finished.store(true, Ordering::Relaxed);
                    }
                    WriteProgressEvent::Advanced { .. }
                        if self.entry_finished.load(Ordering::Relaxed) =>
                    {
                        self.cancelled.store(true, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }

            fn is_cancelled(&self) -> bool {
                self.cancelled.load(Ordering::Relaxed)
            }
        }
        let reporter = CancelOnFinalAdvance {
            entry_finished: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        };
        let entry = FileEntry {
            name: b"FINAL.TXT",
            data: b"final progress cancellation final progress cancellation",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        // Size the volumes first: probing with the reporter would cancel it.
        let volume_size = crate::volume_test_support::smallest_volume_size(|volume_size| {
            write_compressed_volumes(entry, WriterOptions::default(), volume_size)
        }) + 15;
        let error = write_compressed_volumes_with_progress(
            entry,
            WriterOptions::default(),
            volume_size,
            Some(&reporter),
        )
        .unwrap_err();
        assert_eq!(error, Error::Cancelled);
        assert!(reporter.entry_finished.load(Ordering::Relaxed));
    }

    #[test]
    fn preservation_reports_unsupported_legacy_header_variants() {
        let entry = StoredEntry {
            name: b"DIR",
            data: b"",
            file_time: 0,
            file_attr: 0x10,
            password: None,
            file_comment: None,
        };
        let bytes = write_stored_archive(&[entry], WriterOptions::default()).unwrap();
        let base = Archive::parse(&bytes).unwrap();
        assert!(base.rewrite_preservation_issues().is_empty());

        for mutate in [
            (|archive: &mut Archive| archive.main.flags |= MHD_PACK_COMMENT) as fn(&mut Archive),
            |archive| archive.main.extra.push(0),
            |archive| archive.entries[0].header.method = METHOD_BEST + 1,
            |archive| archive.entries[0].header.flags |= LHD_SOLID,
            |archive| archive.entries[0].header.pack_size = 1,
            |archive| archive.entries[0].header.unp_size = 1,
        ] {
            let mut archive = base.clone();
            mutate(&mut archive);
            assert!(!archive.rewrite_preservation_issues().is_empty());
        }
    }

    #[test]
    fn volume_extraction_keeps_solid_history_across_regular_members() {
        let entries = [
            FileEntry {
                name: b"FIRST.TXT",
                data: b"first member establishes solid history first member",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"SECOND.TXT",
                data: b"first member establishes solid history plus a tail",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ];
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes = write_compressed_archive(
            &entries,
            WriterOptions::new(ArchiveVersion::Rar14, features),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted = collect_extract_volumes(std::slice::from_ref(&archive), None).unwrap();
        assert_eq!(extracted.len(), entries.len());
        for (actual, entry) in extracted.iter().zip(entries) {
            assert_eq!(actual.data, entry.data);
        }
    }

    #[test]
    fn streaming_writer_rejects_directory_payload() {
        let entry = StreamingEntry::new(
            b"directory".to_vec(),
            EntrySource::from_bytes(b"unexpected payload".to_vec()),
        )
        .with_file_attr(0x10);
        let error = write_streaming_archive_to(
            &[entry],
            WriterOptions::default(),
            MemberCoding::Stored,
            None,
            &WriterResources::default(),
            None,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            error.root_cause(),
            Error::InvalidArgument("RAR1.3/1.4 directories must have no payload")
        ));
        assert_eq!(
            error.entry_context(),
            Some((&b"directory"[..], "preparing"))
        );
    }

    #[test]
    fn compressed_volumes_report_each_volume_and_honor_cancellation() {
        let data = b"a repeated sequence of archive bytes ".repeat(64);
        let entry = FileEntry {
            name: b"VOL.TXT",
            data: &data,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        };
        let volume_count = AtomicUsize::new(0);
        let reporter = |event: WriteProgressEvent<'_>| {
            if let WriteProgressEvent::VolumeFinished { volume_index, .. } = event {
                assert_eq!(volume_index, volume_count.fetch_add(1, Ordering::Relaxed));
            }
        };
        // Size the volumes first, so the probing writes stay out of the count.
        let volume_size = crate::volume_test_support::smallest_volume_size(|volume_size| {
            write_compressed_volumes(entry, WriterOptions::default(), volume_size)
        }) + 31;
        let volumes = write_compressed_volumes_with_progress(
            entry,
            WriterOptions::default(),
            volume_size,
            Some(&reporter),
        )
        .unwrap();
        assert_eq!(volume_count.load(Ordering::Relaxed), volumes.len());
        assert!(volumes.len() > 1);

        struct CancelAfterFirstVolume(AtomicUsize);
        impl WriteProgress for CancelAfterFirstVolume {
            fn report(&self, event: WriteProgressEvent<'_>) {
                if matches!(event, WriteProgressEvent::VolumeFinished { .. }) {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }

            fn is_cancelled(&self) -> bool {
                self.0.load(Ordering::Relaxed) != 0
            }
        }
        let cancelling = CancelAfterFirstVolume(AtomicUsize::new(0));
        let error = write_compressed_volumes_with_progress(
            entry,
            WriterOptions::default(),
            volume_size,
            Some(&cancelling),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
        assert_eq!(cancelling.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn an_encrypted_stored_member_is_encrypted_as_it_is_copied() {
        let data: Vec<u8> = (0..4 * 1024 * 1024 + 7u32)
            .map(|at| (at ^ (at >> 11)) as u8)
            .collect();
        let options = WriterOptions::new(ArchiveVersion::Rar14, FeatureSet::store_only());
        let whole = write_stored_archive(
            &[StoredEntry {
                name: b"secret.bin",
                data: &data,
                file_time: 0,
                file_attr: 0x20,
                password: Some(b"password"),
                file_comment: None,
            }],
            options,
        )
        .unwrap();

        let (source, watch) = crate::write_stream::watched_source(data.clone());
        let mut entry = StreamingEntry::new(b"secret.bin".to_vec(), source);
        entry.file_attr = 0x20;
        entry.password = Some(b"password".to_vec());
        let mut streamed = Vec::new();
        write_streaming_archive_to(
            &[entry],
            options,
            MemberCoding::Stored,
            None,
            &WriterResources::default(),
            None,
            &mut watch.sink(&mut streamed),
        )
        .unwrap();

        assert_eq!(streamed, whole);
        // Read as it was written, so never held whole.
        let written = watch.written_while_reading();
        assert!(
            written + 1024 * 1024 >= data.len() as u64,
            "only {written} bytes were written while the member was read"
        );
    }

    fn volume_noise(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed.wrapping_mul(2_654_435_761) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    fn volume_text(len: usize) -> Vec<u8> {
        let mut text = Vec::with_capacity(len + 64);
        let mut line = 0u32;
        while text.len() < len {
            text.extend_from_slice(
                format!("line {line} of a set, {}\n", line.wrapping_mul(7919) % 613).as_bytes(),
            );
            line += 1;
        }
        text.truncate(len);
        text
    }

    #[test]
    fn streamed_volume_sets_are_the_sets_the_in_memory_writer_built() {
        let text = volume_text(96 * 1024);
        let noise = volume_noise(40 * 1024, 11);
        for data in [&text[..], &noise[..]] {
            for (solid, level) in [(false, None), (true, Some(2))] {
                let mut features = FeatureSet::store_only();
                features.solid = solid;
                let options = WriterOptions {
                    target: ArchiveVersion::Rar14,
                    features,
                    compression_level: level,
                };
                let packed = encode_verified_rar15_payload_with_progress(
                    data,
                    rar15_encode_options_for_level(level),
                    &mut |_| true,
                )
                .unwrap();
                let (packed, method) =
                    select_verified_payload(std::borrow::Cow::Borrowed(data), packed, false);
                let entry = StreamingEntry::new(
                    b"SET.BIN".to_vec(),
                    EntrySource::from_bytes(data.to_vec()),
                )
                .with_file_attr(0x20);
                for volume_size in [3000, 1 << 20] {
                    let set = |packed: &[u8], method| {
                        in_memory_volumes(InMemorySet {
                            name: b"SET.BIN",
                            unpacked: data,
                            packed,
                            method,
                            features,
                            volume_size,
                        })
                    };
                    let case = format!("{} bytes, solid {solid}, {volume_size}", data.len());

                    let compressed = set(&packed, method);
                    let file = FileEntry {
                        name: b"SET.BIN",
                        data,
                        file_time: 0,
                        file_attr: 0x20,
                        password: None,
                        file_comment: None,
                    };
                    assert!(
                        write_compressed_volumes(file, options, volume_size).unwrap() == compressed,
                        "{case}"
                    );
                    // From a source, in memory and packed into a spool.
                    for stream_above in [u64::MAX, 1024] {
                        let mut sink = CollectedVolumes::new();
                        split_member(
                            &Member::from_streaming(&entry),
                            options,
                            &MemberCoding::Compressed,
                            volume_size,
                            &mut sink,
                            &WriterResources::default(),
                            None,
                            stream_above,
                        )
                        .unwrap();
                        assert!(sink.take() == compressed, "{case}, {stream_above}");
                    }

                    // A stored set cannot be solid.
                    if solid {
                        continue;
                    }
                    let stored = set(data, METHOD_STORE);
                    let file = StoredEntry {
                        name: b"SET.BIN",
                        data,
                        file_time: 0,
                        file_attr: 0x20,
                        password: None,
                        file_comment: None,
                    };
                    assert!(
                        write_stored_volumes(file, options, volume_size).unwrap() == stored,
                        "{case}"
                    );
                    let mut sink = CollectedVolumes::new();
                    write_volumes_to(
                        &entry,
                        options,
                        MemberCoding::Stored,
                        volume_size,
                        &mut sink,
                        &WriterResources::default(),
                        None,
                    )
                    .unwrap();
                    let volumes = sink.take();
                    assert!(volumes == stored, "{case}");
                    let archives = parse_volumes(&volumes);
                    let extracted = collect_extract_volumes(&archives, None).unwrap();
                    assert!(extracted[0].data == data, "{case}");
                }
            }
        }
    }

    /// Refuses a set longer than the 901 volumes old-style names reach.
    struct NamedSet {
        started: usize,
    }

    impl VolumeSink for NamedSet {
        fn expect_volumes(&mut self, total: u64) -> Result<()> {
            if total > 901 {
                return Err(Error::InvalidArgument(
                    "old-style volume names run out after .z99",
                ));
            }
            Ok(())
        }

        fn start_volume(&mut self, _index: u64) -> Result<Box<dyn VolumeOutput>> {
            self.started += 1;
            Ok(Box::new(std::io::Cursor::new(Vec::new())))
        }
    }

    #[test]
    fn a_set_too_long_to_name_is_refused_before_a_volume_is_written() {
        let entry = StreamingEntry::new(
            b"LONG.BIN".to_vec(),
            EntrySource::from_bytes(volume_noise(64 * 1024, 5)),
        )
        .with_file_attr(0x20);
        // Noise is stored whichever way it is asked for, so both need over
        // a thousand 100-byte volumes.
        for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
            let mut sink = NamedSet { started: 0 };
            let error = write_volumes_to(
                &entry,
                WriterOptions::default(),
                coding.clone(),
                100,
                &mut sink,
                &WriterResources::default(),
                None,
            )
            .unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::InvalidArgument("old-style volume names run out after .z99")
            );
            assert_eq!(sink.started, 0, "{coding:?}");
        }
        let mut sink = NamedSet { started: 0 };
        write_volumes_to(
            &entry,
            WriterOptions::default(),
            MemberCoding::Stored,
            1000,
            &mut sink,
            &WriterResources::default(),
            None,
        )
        .unwrap();
        assert!((2..=901).contains(&sink.started), "{}", sink.started);
    }

    #[test]
    fn a_source_that_changes_size_under_a_streamed_set_is_refused() {
        for actual in [4000usize, 4200] {
            let entry = StreamingEntry::new(
                b"MOVING.BIN".to_vec(),
                EntrySource::from_opener(4096, move || {
                    Ok(Box::new(std::io::Cursor::new(vec![1u8; actual])))
                }),
            );
            let mut sink = CollectedVolumes::new();
            let error = write_volumes_to(
                &entry,
                WriterOptions::default(),
                MemberCoding::Stored,
                1024,
                &mut sink,
                &WriterResources::default(),
                None,
            )
            .unwrap_err();
            assert!(
                matches!(error.root_cause(), Error::SourceChanged(_)),
                "{actual}: {error:?}"
            );
        }
    }

    fn counted_source(data: Vec<u8>, read: Arc<AtomicU64>) -> EntrySource {
        struct Counted {
            inner: std::io::Cursor<Vec<u8>>,
            read: Arc<AtomicU64>,
        }
        impl Read for Counted {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = self.inner.read(buffer)?;
                self.read.fetch_add(count as u64, Ordering::Relaxed);
                Ok(count)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
                self.inner.seek(position)
            }
        }
        EntrySource::from_opener(data.len() as u64, move || {
            Ok(Box::new(Counted {
                inner: std::io::Cursor::new(data.clone()),
                read: read.clone(),
            }))
        })
    }

    fn seekable_archive(entries: &[StreamingEntry], coding: MemberCoding) -> Result<Vec<u8>> {
        let mut output = std::io::Cursor::new(Vec::new());
        write_seekable_archive_to(
            entries,
            WriterOptions::default(),
            coding,
            Some(b"note"),
            &WriterResources::default(),
            None,
            &mut output,
        )?;
        Ok(output.into_inner())
    }

    fn streamed_archive(entries: &[StreamingEntry], coding: MemberCoding) -> Vec<u8> {
        let mut output = Vec::new();
        write_streaming_archive_to(
            entries,
            WriterOptions::default(),
            coding,
            Some(b"note"),
            &WriterResources::default(),
            None,
            &mut output,
        )
        .unwrap();
        output
    }

    #[test]
    fn a_stored_member_to_a_seekable_output_is_read_once() {
        let data: Vec<u8> = (0..300_000u32).map(|at| (at ^ (at >> 7)) as u8).collect();
        let read = Arc::new(AtomicU64::new(0));
        let entries = [
            StreamingEntry::new(
                b"BIG.BIN".to_vec(),
                counted_source(data.clone(), read.clone()),
            ),
            StreamingEntry::new(b"EMPTY.TXT".to_vec(), EntrySource::from_bytes(Vec::new())),
        ];
        let archive = seekable_archive(&entries, MemberCoding::Stored).unwrap();
        assert_eq!(read.load(Ordering::Relaxed), data.len() as u64);
        assert_eq!(archive, streamed_archive(&entries, MemberCoding::Stored));
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn a_seekable_output_holds_the_archive_a_stream_does() {
        let text: Vec<u8> = b"legacy text, said twice. ".repeat(4000);
        for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
            let entries = [
                StreamingEntry::new(b"TEXT.TXT".to_vec(), EntrySource::from_bytes(text.clone()))
                    .with_file_comment(b"about".to_vec()),
                StreamingEntry::new(
                    b"SECRET.TXT".to_vec(),
                    EntrySource::from_bytes(text.clone()),
                )
                .with_password(b"pw".to_vec()),
                StreamingEntry::new(b"EMPTY.TXT".to_vec(), EntrySource::from_bytes(Vec::new()))
                    .with_password(b"pw".to_vec()),
                StreamingEntry::new(b"DIR".to_vec(), EntrySource::from_bytes(Vec::new()))
                    .with_file_attr(0x10),
            ];
            let archive = seekable_archive(&entries, coding.clone()).unwrap();
            assert_eq!(
                archive,
                streamed_archive(&entries, coding.clone()),
                "{coding:?}"
            );
            let parsed = Archive::parse(&archive).unwrap();
            let secret = collect_extract(&parsed, Some(b"pw")).unwrap();
            assert_eq!(secret[1].data, text, "{coding:?}");
        }
    }

    #[test]
    fn a_source_that_changes_size_under_a_seekable_output_is_refused() {
        for actual in [4000usize, 4200] {
            let entry = StreamingEntry::new(
                b"MOVING.BIN".to_vec(),
                EntrySource::from_opener(4096, move || {
                    Ok(Box::new(std::io::Cursor::new(vec![1u8; actual])))
                }),
            );
            let error = seekable_archive(&[entry], MemberCoding::Stored).unwrap_err();
            assert!(
                matches!(error.root_cause(), Error::SourceChanged(_)),
                "{actual}: {error:?}"
            );
            assert_eq!(
                error.entry_context(),
                Some((&b"MOVING.BIN"[..], "writing")),
                "{actual}"
            );
        }
    }

    #[test]
    fn a_stored_member_to_a_seekable_output_is_counted_as_it_is_copied() {
        let len = 1 << 20;
        let read = Arc::new(AtomicU64::new(0));
        let entry = StreamingEntry::new(
            b"BIG.BIN".to_vec(),
            counted_source(vec![7; len], read.clone()),
        );
        let reported = std::sync::Mutex::new(Vec::new());
        let progress = |event: WriteProgressEvent<'_>| {
            if let WriteProgressEvent::Advanced {
                completed_bytes, ..
            } = event
            {
                reported
                    .lock()
                    .unwrap()
                    .push((completed_bytes, read.load(Ordering::Relaxed)));
            }
        };
        write_seekable_archive_to(
            &[entry],
            WriterOptions::default(),
            MemberCoding::Stored,
            None,
            &WriterResources::default(),
            Some(&progress),
            &mut std::io::Cursor::new(Vec::new()),
        )
        .unwrap();
        let reported = reported.into_inner().unwrap();
        // Never ahead of what has been read, and moving while it is.
        assert!(
            reported.iter().all(|&(done, read)| done <= read),
            "{reported:?}"
        );
        assert!(reported
            .iter()
            .any(|&(done, _)| done > 0 && done < len as u64));
        assert_eq!(reported.last().map(|&(done, _)| done), Some(len as u64));
    }

    #[test]
    fn seekable_and_volume_archives_match_fingerprints_captured_from_master() {
        let text: Vec<u8> = b"legacy text, said twice. ".repeat(4000);
        let noise = crate::write_stream::noise(70_000);
        let entries = |password: Option<&[u8]>| {
            let entry = |name: &[u8], data: &Vec<u8>| {
                let entry =
                    StreamingEntry::new(name.to_vec(), EntrySource::from_bytes(data.clone()));
                match password {
                    Some(password) => entry.with_password(password.to_vec()),
                    None => entry,
                }
            };
            let letters = noise.iter().map(|byte| b'a' + byte % 16).collect();
            vec![
                entry(b"TEXT.TXT", &text),
                entry(b"NOISE.BIN", &noise),
                entry(b"EMPTY.TXT", &Vec::new()),
                entry(b"LETTERS.TXT", &letters),
            ]
        };
        let volumes = |entry: &StreamingEntry, coding: MemberCoding, size: usize| {
            let mut sink = crate::volume_sink::CollectedVolumes::new();
            write_volumes_to(
                entry,
                WriterOptions::default(),
                coding,
                size,
                &mut sink,
                &WriterResources::default(),
                None,
            )
            .unwrap();
            sink.take()
        };
        let mut cases = Vec::new();
        for (name, coding, member, size) in [
            ("stored", MemberCoding::Stored, 1, 30_000),
            ("compressed", MemberCoding::Compressed, 3, 15_000),
        ] {
            let archive = seekable_archive(&entries(None), coding.clone()).unwrap();
            cases.push((
                format!("seekable_{name}"),
                crate::write_stream::fingerprint([&archive[..]]),
            ));
            let parts = volumes(&entries(None)[member], coding, size);
            cases.push((
                format!("volumes_{name}"),
                crate::write_stream::fingerprint(parts.iter().map(Vec::as_slice)),
            ));
        }
        #[cfg(feature = "encryption")]
        {
            let archive = crate::entropy::seeded::with(|| {
                seekable_archive(&entries(Some(b"pw")), MemberCoding::Stored).unwrap()
            });
            cases.push((
                "seekable_encrypted".into(),
                crate::write_stream::fingerprint([&archive[..]]),
            ));
        }
        let expected = [
            ("seekable_stored", "240177:994e7518"),
            (
                "volumes_stored",
                "30000:8bae9d7e 30000:9377ff08 10225:5b128e3c",
            ),
            ("seekable_compressed", "111209:bd92de39"),
            (
                "volumes_compressed",
                "15000:646874aa 15000:a3a0bcef 11119:ed57eeac",
            ),
            ("seekable_encrypted", "240177:fcd81fc7"),
        ];
        crate::write_stream::assert_fingerprints(&cases, &expected);
    }
}
