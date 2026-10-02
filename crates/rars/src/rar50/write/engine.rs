//! Assembling a RAR 5 archive from prepared payloads.
//!
//! Native member spools use temporary files; bare-WASM spools retain bytes in
//! memory. Compression may load whole members; headers also allocate memory.
//! Service payloads borrow input and are encrypted in chunks during emission.
//! Quick-open data uses a quota-controlled spool. Once block lengths are known,
//! final archive output streams in one pass. The
//! workspace admission budget is not an aggregate RAM or disk quota; see
//! WRITER_EXECUTION.md in the repo.
//!
//! Stored payloads are reread and verified during emission. Recovery requires
//! a further pass over the preceding archive bytes, mirrored into a spool.

use super::compress::{self, CompressPlan, CompressedMember};
#[cfg(test)]
use super::headers::write_vint;
use super::headers::{
    block_header_image, encrypted_header_block, encrypted_main_header_block, file_specific,
    header_encryption_keys, header_encryption_password, prepared_header_image,
    stored_file_specific, write_end_header, write_extra_record, write_file_encryption_record,
    write_hash_record_with_value, write_head_crypt, write_main_header, HeaderEncryptionKeys,
    PreparedHeader,
};
use super::layout::{resolve_layout, LayoutInputs};
use super::{encrypt_reader_to, ArchiveEntry};
use crate::crypto::rar50::{Rar50Keys, WRITE_KDF_COUNT_LOG};
use crate::detect::RAR50_SIGNATURE;
use crate::rar50::{
    FHEXTRA_SUBDATA, HEAD_END, HEAD_FILE, HEAD_SERVICE, HFL_DATA, HFL_EXTRA, MHFL_RECOVERY,
    MHFL_SOLID,
};
#[cfg(feature = "recovery")]
use crate::recovery::rar5::{
    choose_recovery_memory_mode, plan_inline_recovery, streamed_recovery_with_allowance,
    ReadWriteSeek,
};
use crate::streaming::preparation::{Bytes, Owned, Records};
use crate::streaming::Spool;
use crate::write_progress::{check_cancelled, CancellableIo, ProgressReporter};
use crate::{Error, Result, WriterResources};
use std::io::{Read, Write};

pub(super) struct EnginePlan<'a> {
    pub(super) compress: CompressPlan,
    pub(super) recovery_percent: Option<u64>,
    pub(super) header_encrypted: bool,
    pub(super) header_password: Option<&'a [u8]>,
    pub(super) archive_comment: Option<ArchiveCommentPlan<'a>>,
    pub(super) archive_metadata: Option<crate::rar50::ArchiveMetadataEntry<'a>>,
    pub(super) metadata_record: Option<&'a crate::rar50::ArchiveMetadataRecord>,
    pub(super) locked: bool,
    pub(super) quick_open: bool,
    pub(super) progress: Option<ProgressReporter<'a>>,
}

pub(super) enum ArchiveCommentPlan<'a> {
    Plain(&'a [u8]),
    Encrypted { data: &'a [u8], password: &'a [u8] },
}

/// A block with its framing settled: the header bytes are final and the
/// payload only has to be copied.
struct PreparedBlock<'a> {
    header: PreparedHeader,
    payload: Payload<'a>,
    payload_len: u64,
    /// Quick-open repeats the headers of members and plain comments so a
    /// reader can list an archive without walking it.
    quick_open_cached: bool,
    /// Index into the caller's entries; names are cloned only on error.
    entry_index: Option<usize>,
}

impl PreparedBlock<'_> {
    fn len(&self) -> Result<u64> {
        (self.header.len() as u64)
            .checked_add(self.payload_len)
            .ok_or(Error::InvalidArgument("RAR 5 archive block size overflows"))
    }
}

enum Payload<'a> {
    /// Comments and services remain owned by the caller or builder.
    Borrowed(&'a [u8]),
    /// Copied straight from the source, which is re-read at write time.
    Stored(PreparedSource),
    Packed(Spool),
    /// Encrypted on the way out, so the ciphertext is never stored anywhere.
    Encrypted {
        plain: Owned<PlainPayload<'a>>,
        keys: Rar50Keys,
        iv: [u8; 16],
    },
}

enum PlainPayload<'a> {
    Borrowed(&'a [u8]),
    Stored(PreparedSource),
    Packed(Spool),
}

// Member payloads cannot borrow comment/service bytes. Keeping their two
// forms distinct avoids an impossible borrowed arm during plain emission.
enum MemberPlainPayload {
    Stored(PreparedSource),
    Packed(Spool),
}

impl From<MemberPlainPayload> for PlainPayload<'_> {
    fn from(member: MemberPlainPayload) -> Self {
        match member {
            MemberPlainPayload::Stored(source) => Self::Stored(source),
            MemberPlainPayload::Packed(packed) => Self::Packed(packed),
        }
    }
}

impl From<MemberPlainPayload> for Payload<'_> {
    fn from(member: MemberPlainPayload) -> Self {
        match member {
            MemberPlainPayload::Stored(source) => Self::Stored(source),
            MemberPlainPayload::Packed(packed) => Self::Packed(packed),
        }
    }
}

// A reopenable source is not a snapshot. Keep the size and integrity used by
// the header, and verify the actual emission read before reporting success.
struct PreparedSource {
    source: crate::EntrySource,
    len: u64,
    crc32: u32,
    hash: [u8; 32],
}

impl PreparedSource {
    fn new(source: &crate::EntrySource, member: &CompressedMember) -> Self {
        Self {
            source: source.clone(),
            len: member.input_size,
            crc32: member.crc32,
            hash: member.hash,
        }
    }

    fn open(&self) -> Result<CheckedReader> {
        Ok(CheckedReader {
            reader: self.source.open()?,
            integrity: ChecksumSink::default(),
        })
    }

    fn verify(&self, integrity: ChecksumSink) -> Result<()> {
        if integrity.crc.finish() != self.crc32 || integrity.hash.finalize() != self.hash {
            return Err(Error::SourceChanged(
                "entry source contents changed while writing",
            ));
        }
        Ok(())
    }
}

struct CheckedReader {
    reader: Box<dyn crate::EntryReader>,
    integrity: ChecksumSink,
}

impl Read for CheckedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(buffer)?;
        self.integrity.write_all(&buffer[..read])?;
        Ok(read)
    }
}

impl CheckedReader {
    fn finish(mut self, source: &PreparedSource, observed: u64) -> Result<()> {
        crate::write_stream::check_source_length(
            &mut *self.reader,
            observed,
            source.len,
            "entry source size changed while writing",
        )?;
        source.verify(self.integrity)
    }
}

// Both archive and volume emission report and account for one aggregate input
// length. Caller-provided source lengths need not fit that sum even when each
// length fits a member header. Reject overflow before any payload read.
fn total_input_size(entries: &[ArchiveEntry]) -> Result<u64> {
    entries.iter().try_fold(0u64, |total, entry| {
        let length = entry
            .source
            .len()
            .map_err(|error| member_error(error, &entry.name, "preparing"))?;
        total.checked_add(length).ok_or_else(|| {
            member_error(
                Error::InvalidArgument("RAR 5 writer total input size overflows"),
                &entry.name,
                "preparing",
            )
        })
    })
}

pub(super) fn write_archive(
    entries: &[ArchiveEntry],
    plan: EnginePlan<'_>,
    resources: &WriterResources,
    output: &mut dyn Write,
) -> Result<()> {
    let mut controlled_output = CancellableIo {
        inner: output,
        progress: plan.progress,
    };
    let output: &mut dyn Write = &mut controlled_output;
    for entry in entries {
        super::validate_entry(entry)?;
    }

    let header_keys = if plan.header_encrypted {
        let password = header_encryption_password(
            plan.header_password
                .into_iter()
                .chain(entries.iter().filter_map(|entry| entry.password.as_deref())),
        )?;
        Some(header_encryption_keys(password)?)
    } else {
        None
    };

    let mut sources = Records::new(entries.len(), resources)?;
    for entry in entries {
        sources.push(entry.source.clone())?;
    }
    let total_input = total_input_size(entries)?;
    let total_entries = entries.len();
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationStarted {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
    let work = crate::write_progress::WorkTracker::new(
        plan.progress,
        crate::WriteOperation::Compression,
        total_input,
    );
    let compressed = compress::compress_members_with_context(
        &sources,
        &plan.compress,
        resources,
        &MemberProgress {
            entries,
            work: &work,
        },
        &|index, error| member_error(error, &entries[index].name, "compressing"),
    )?;

    // Everything between the main header and the quick-open block, in order.
    // Entries and their owned service vectors contain records larger than a byte
    // in disjoint live storage. Their combined count fits usize, including
    // the single optional archive comment. This relies on services being owned
    // vectors, rather than shared or borrowed lists counted repeatedly.
    let block_count = entries.iter().fold(
        usize::from(plan.archive_comment.is_some()),
        |total, entry| total + 1 + entry.services.len(),
    );
    let mut blocks = Records::<PreparedBlock>::new(block_count, resources)?;
    if let Some(comment) = &plan.archive_comment {
        blocks.push(prepare_comment(comment, header_keys.as_ref(), resources)?)?;
    }
    for (index, (entry, member)) in entries.iter().zip(compressed).enumerate() {
        check_cancelled(plan.progress)?;
        let mut block = prepare_member(entry, member, &plan, header_keys.as_ref(), resources)
            .map_err(|error| member_error(error, &entry.name, "preparing"))?;
        block.entry_index = Some(index);
        blocks.push(block)?;
        for service in &entry.services {
            let mut block = prepare_service(service, header_keys.as_ref(), resources)
                .map_err(|error| member_error(error, &entry.name, "preparing service"))?;
            block.entry_index = Some(index);
            blocks.push(block)?;
        }
    }
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationFinished {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }

    let body_len = blocks.iter().try_fold(0u64, |total, block| {
        total
            .checked_add(block.len()?)
            .ok_or(Error::InvalidArgument("RAR 5 archive body size overflows"))
    })?;

    // Quick-open stores how far back each cached header sits from the
    // quick-open block itself. Both move together when the prefix grows, so
    // the distances only need positions within the body.
    let quick_open_payload = if plan.quick_open {
        let mut payload = Spool::create(resources)?;
        let mut checksum = crate::crc32::Crc32::new();
        let mut offset = 0u64;
        for block in &blocks {
            check_cancelled(plan.progress)?;
            if block.quick_open_cached {
                append_quick_open_entry(
                    &mut payload,
                    &mut checksum,
                    body_len - offset,
                    &block.header,
                )?;
            }
            offset += block.len()?;
        }
        let payload_len = payload.len();
        let header = stored_service_header(
            b"QO",
            payload_len,
            checksum.finish(),
            &[],
            header_keys.as_ref(),
            resources,
        )?;
        payload.park();
        Some(PreparedBlock {
            header,
            payload: Payload::Packed(payload),
            payload_len,
            quick_open_cached: false,
            entry_index: None,
        })
    } else {
        None
    };

    let head_crypt = match &header_keys {
        Some(keys) => {
            let mut block = Bytes::new(resources);
            write_head_crypt(&mut block, keys, resources)?;
            block
        }
        None => Bytes::new(resources),
    };

    let mut main_flags = if plan.locked {
        crate::rar50::MHFL_LOCKED
    } else {
        0
    };
    if plan.compress.solid {
        main_flags |= MHFL_SOLID;
    }
    if plan.recovery_percent.is_some() {
        main_flags |= MHFL_RECOVERY;
    }

    let layout = resolve_layout(
        &LayoutInputs {
            header_encrypted: plan.header_encrypted,
            head_crypt_len: head_crypt.len() as u64,
            main_flags,
            volume_number: None,
            archive_metadata: plan.archive_metadata,
            metadata_record: plan.metadata_record,
            body_len,
            quick_open_payload_len: quick_open_payload.as_ref().map(|block| block.payload_len),
            recovery_percent: plan.recovery_percent,
        },
        resources,
    )?;

    report_emission(plan.progress, true);
    // Only mirror the archive when a recovery record has to read it back.
    let mut mirror = match plan.recovery_percent {
        Some(_) => Some(Spool::create(resources)?),
        None => None,
    };
    {
        let mut sink = Tee {
            output,
            mirror: mirror.as_mut(),
        };

        let main = match &header_keys {
            Some(keys) => encrypted_main_header_block(
                &keys.keys,
                main_flags,
                None,
                &layout.main_extra,
                resources,
            )?,
            None => {
                let mut main = Bytes::new(resources);
                write_main_header(&mut main, main_flags, None, &layout.main_extra, resources)?;
                main
            }
        };
        // The layout predicted this before any of it existed. If the
        // prediction is off, every offset in the locator is off with it.
        debug_assert_eq!(
            main.len() as u64,
            layout.main_header_len,
            "main header size differs from the size its layout was built on"
        );

        sink.write_all(RAR50_SIGNATURE)?;
        sink.write_all(&head_crypt)?;
        sink.write_all(&main)?;

        for block in blocks {
            let entry_index = block.entry_index;
            let result = (|| {
                sink.write_all(&block.header)?;
                write_payload(block.payload, &mut sink, resources, plan.progress)
            })();
            result.map_err(|error| match entry_index {
                Some(index) => member_error(error, &entries[index].name, "writing"),
                None => error,
            })?;
        }

        if let Some(block) = quick_open_payload {
            sink.write_all(&block.header)?;
            write_payload(block.payload, &mut sink, resources, plan.progress)?;
        }
    }

    if let Some(recovery_percent) = plan.recovery_percent {
        let mirror = mirror.as_mut().expect("recovery mirrors the archive");
        // The recovery block has to start exactly where the locator in the
        // main header says it does.
        debug_assert_eq!(layout.recovery_prefix_len, Some(mirror.len()));
        debug_assert_eq!(
            layout.recovery_offset,
            Some(mirror.len() - RAR50_SIGNATURE.len() as u64),
            "recovery record is not where the locator points"
        );
        write_recovery_service(
            recovery_percent,
            mirror,
            header_keys.as_ref(),
            resources,
            plan.progress,
            output,
        )?;
    }

    match &header_keys {
        Some(keys) => output.write_all(&encrypted_header_block(
            &keys.keys,
            HEAD_END,
            0,
            None,
            &super::end_header_specific(0),
            &[],
            &[],
            resources,
        )?)?,
        None => {
            let mut end = Bytes::new(resources);
            write_end_header(&mut end, 0, resources)?;
            output.write_all(&end)?;
        }
    }
    check_cancelled(plan.progress)?;
    report_emission(plan.progress, false);
    Ok(())
}

/// Appends one quick-open record: how far back the header sits, then the
/// header itself.
///
/// The wrapper is `CRC32 || BlockSize || body`, and the checksum covers
/// `BlockSize` as well as the body. That is easy to get backwards, because the
/// length is written after the checksum it is part of. Checksumming the body
/// alone costs nothing visible: readers reject the wrapper, fall back to
/// walking the block chain, and report the archive as fine while the index
/// they were handed goes unused.
fn append_quick_open_entry(
    payload: &mut dyn Write,
    payload_crc: &mut crate::crc32::Crc32,
    distance: u64,
    header: &[u8],
) -> Result<()> {
    // At most three u64 vints. Keep framing on the stack and borrow the header
    // instead of cloning it into body and wrapper buffers.
    fn vint(out: &mut [u8], mut value: u64) -> usize {
        let mut len = 0;
        loop {
            out[len] = (value as u8 & 0x7f) | if value >= 0x80 { 0x80 } else { 0 };
            len += 1;
            value >>= 7;
            if value == 0 {
                return len;
            }
        }
    }
    let mut body_prefix = [0; 21];
    let mut len = 1; // Flags = 0.
    len += vint(&mut body_prefix[len..], distance);
    len += vint(&mut body_prefix[len..], header.len() as u64);
    let body_len = (header.len() as u64)
        .checked_add(len as u64)
        .ok_or(Error::InvalidArgument(
            "RAR 5 quick-open record size overflows",
        ))?;
    let mut size = [0; 10];
    let size_len = vint(&mut size, body_len);
    let parts = [&size[..size_len], &body_prefix[..len], header];
    let mut crc = crate::crc32::Crc32::new();
    for part in parts {
        crc.update(part);
    }
    // Combine the small framing fields into one write to the native spool.
    let mut framing = [0; 35];
    framing[..4].copy_from_slice(&crc.finish().to_le_bytes());
    framing[4..4 + size_len].copy_from_slice(&size[..size_len]);
    let framing_len = 4 + size_len + len;
    framing[4 + size_len..framing_len].copy_from_slice(&body_prefix[..len]);
    for part in [&framing[..framing_len], header] {
        payload.write_all(part)?;
        payload_crc.update(part);
    }
    Ok(())
}

/// A stored service block borrowing a named payload such as a comment.
fn stored_service_block<'a>(
    name: &[u8],
    data: &'a [u8],
    service_data: &[u8],
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    Ok(PreparedBlock {
        header: stored_service_header(
            name,
            data.len() as u64,
            crate::crc32::crc32(data),
            service_data,
            header_keys,
            resources,
        )?,
        payload: Payload::Borrowed(data),
        payload_len: data.len() as u64,
        quick_open_cached: false,
        entry_index: None,
    })
}

fn stored_service_header(
    name: &[u8],
    data_len: u64,
    crc32: u32,
    service_data: &[u8],
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedHeader> {
    let mut extra = Bytes::new(resources);
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data)?;
    let specific = stored_file_specific(name, data_len, crc32, 0, None, 0, resources)?;
    prepared_header_image(
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data_len),
        &specific,
        &extra,
        header_keys,
        resources,
    )
}

fn prepare_comment<'a>(
    comment: &ArchiveCommentPlan<'a>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    match comment {
        ArchiveCommentPlan::Plain(data) => {
            let mut block = stored_service_block(b"CMT", data, &[], header_keys, resources)?;
            // Plain comments are listed by quick-open; encrypted ones are not.
            block.quick_open_cached = header_keys.is_none();
            Ok(block)
        }
        ArchiveCommentPlan::Encrypted { data, password } => {
            encrypted_service_block(b"CMT", data, &[], password, header_keys, resources)
        }
    }
}

fn prepare_service<'a>(
    service: &'a super::ServiceEntry,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    match service.password.as_deref() {
        Some(password) => encrypted_service_block(
            &service.name,
            &service.data,
            &[],
            password,
            header_keys,
            resources,
        ),
        None => stored_service_block(&service.name, &service.data, &[], header_keys, resources),
    }
}

/// A service block whose borrowed payload is encrypted during emission.
fn encrypted_service_block<'a>(
    name: &[u8],
    data: &'a [u8],
    service_data: &[u8],
    password: &[u8],
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'a>> {
    super::validate_nonempty_password(password)?;
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    crate::write_stream::fill_entropy(
        &mut salt,
        "RAR 5 writer could not generate encryption salt",
    )?;
    crate::write_stream::fill_entropy(&mut iv, "RAR 5 writer could not generate encryption IV")?;
    let keys = Rar50Keys::derive(password, salt, WRITE_KDF_COUNT_LOG).map_err(Error::from)?;

    let mut extra = Bytes::new(resources);
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data)?;
    write_file_encryption_record(&mut extra, salt, iv, keys.checked_password_record()?)?;
    write_hash_record_with_value(
        &mut extra,
        keys.checked_hash_mac(crate::rar50::blake2sp::hash(data))?,
    )?;
    let specific = stored_file_specific(
        name,
        data.len() as u64,
        keys.checked_crc_mac(crate::crc32::crc32(data))?,
        0,
        None,
        0,
        resources,
    )?;
    let payload_len = (data.len() as u64)
        .checked_add(15)
        .ok_or(Error::InvalidArgument(
            "RAR 5 encrypted data size overflows",
        ))?
        & !15;
    let header = prepared_header_image(
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(payload_len),
        &specific,
        &extra,
        header_keys,
        resources,
    )?;
    Ok(PreparedBlock {
        header,
        payload: Payload::Encrypted {
            plain: Owned::new(PlainPayload::Borrowed(data), resources)?,
            keys,
            iv,
        },
        payload_len,
        quick_open_cached: false,
        entry_index: None,
    })
}

fn decoded_rar50_name_len(bytes: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return bytes.len();
    };
    if !text.contains('\u{fffe}') {
        return bytes.len();
    }
    text.chars()
        .map(|ch| match ch {
            '\u{fffe}' => 0,
            '\u{e080}'..='\u{e0ff}' => 1,
            _ => ch.len_utf8(),
        })
        .sum()
}

/// Builds a member's final header and decides how its payload will be written.
fn prepare_member(
    entry: &ArchiveEntry,
    member: CompressedMember,
    plan: &EnginePlan<'_>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<PreparedBlock<'static>> {
    let compression_info = compress::member_compression_info(&plan.compress, &member)?;
    let plain_len = if member.store {
        member.input_size
    } else {
        member.packed.len()
    };
    let plain = if member.store {
        MemberPlainPayload::Stored(PreparedSource::new(&entry.source, &member))
    } else {
        MemberPlainPayload::Packed(member.packed)
    };

    let mut extra = Bytes::new(resources);
    let (payload, payload_len, data_crc32, hash) = match entry.password.as_deref() {
        Some(password) => {
            let mut salt = [0u8; 16];
            let mut iv = [0u8; 16];
            crate::write_stream::fill_entropy(
                &mut salt,
                "RAR 5 writer could not generate encryption salt",
            )?;
            crate::write_stream::fill_entropy(
                &mut iv,
                "RAR 5 writer could not generate encryption IV",
            )?;
            let keys =
                Rar50Keys::derive(password, salt, WRITE_KDF_COUNT_LOG).map_err(Error::from)?;
            write_file_encryption_record(&mut extra, salt, iv, keys.checked_password_record()?)?;
            let crc32 = keys.checked_crc_mac(member.crc32)?;
            let hash = keys.checked_hash_mac(member.hash)?;
            (
                Payload::Encrypted {
                    plain: Owned::new(plain.into(), resources)?,
                    keys,
                    iv,
                },
                // Encryption pads the payload up to the cipher block size.
                plain_len.div_ceil(16) * 16,
                crc32,
                hash,
            )
        }
        None => (plain.into(), plain_len, member.crc32, member.hash),
    };
    // A link has no file payload to hash; its target is protected by the header CRC.
    if entry.redirection.is_none() {
        write_hash_record_with_value(&mut extra, hash)?;
    }
    super::headers::write_mtime_record(&mut extra, entry.mtime, entry.mtime_nanoseconds)?;
    if let Some(times) = entry.file_times {
        write_extra_record(&mut extra, super::super::FHEXTRA_HTIME, &times.encode()?)?;
    }
    if let Some(link) = &entry.redirection {
        let mut record = Bytes::new(resources);
        record.vint(link.redirection_type)?;
        record.vint(link.flags)?;
        record.vint(link.target_name.len() as u64)?;
        record.extend_from_slice(&link.target_name)?;
        write_extra_record(&mut extra, super::super::FHEXTRA_REDIR, &record)?;
    }

    let specific = file_specific(
        &entry.name,
        // Match Unix link stat size, while the packed payload remains empty.
        entry
            .redirection
            .as_ref()
            .map_or(member.input_size, |link| {
                entry
                    .redirection_size
                    .unwrap_or_else(|| decoded_rar50_name_len(&link.target_name) as u64)
            }),
        data_crc32,
        entry.attributes,
        entry.mtime.filter(|_| entry.mtime_nanoseconds.is_none()),
        compression_info,
        entry.host_os,
        entry.is_directory,
        resources,
    )?;
    let header = prepared_header_image(
        HEAD_FILE,
        HFL_EXTRA | HFL_DATA,
        Some(payload_len),
        &specific,
        &extra,
        header_keys,
        resources,
    )?;

    Ok(PreparedBlock {
        header,
        payload,
        payload_len,
        quick_open_cached: true,
        entry_index: None,
    })
}

fn write_payload(
    payload: Payload<'_>,
    output: &mut dyn Write,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
) -> Result<()> {
    check_cancelled(progress)?;
    match payload {
        Payload::Borrowed(data) => {
            output.write_all(data)?;
            Ok(())
        }
        Payload::Stored(source) => {
            let mut reader = source.open()?;
            let copied = std::io::copy(&mut reader.by_ref().take(source.len), output)?;
            reader.finish(&source, copied)?;
            source.source.release();
            Ok(())
        }
        Payload::Packed(mut packed) => {
            packed.copy_to(output)?;
            Ok(())
        }
        Payload::Encrypted { plain, keys, iv } => {
            const ENCRYPT_CHUNK: usize = 64 * 1024;
            let chunk_size = match &*plain {
                PlainPayload::Borrowed(data) => {
                    data.len().clamp(1, ENCRYPT_CHUNK).div_ceil(16) * 16
                }
                _ => ENCRYPT_CHUNK,
            };
            let _permit = resources.acquire_cancellable(chunk_size as u64, 0, &|| {
                progress.is_some_and(ProgressReporter::is_cancelled)
            })?;
            match plain.into_inner() {
                PlainPayload::Stored(source) => {
                    let mut reader = source.open()?;
                    encrypt_reader_to(
                        &mut reader,
                        source.len,
                        output,
                        &keys,
                        iv,
                        ENCRYPT_CHUNK,
                        progress,
                        resources,
                    )?;
                    reader.finish(&source, source.len)?;
                    source.source.release();
                    Ok(())
                }
                PlainPayload::Packed(mut packed) => {
                    let len = packed.len();
                    packed.rewind()?;
                    encrypt_reader_to(
                        &mut packed,
                        len,
                        output,
                        &keys,
                        iv,
                        ENCRYPT_CHUNK,
                        progress,
                        resources,
                    )
                }
                PlainPayload::Borrowed(mut data) => {
                    let len = data.len() as u64;
                    encrypt_reader_to(
                        &mut data, len, output, &keys, iv, chunk_size, progress, resources,
                    )
                }
            }
        }
    }
}

/// Computes the recovery record over `prefix` and writes its service block.
fn write_recovery_service(
    recovery_percent: u64,
    prefix: &mut Spool,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
    output: &mut dyn Write,
) -> Result<u64> {
    #[cfg(not(feature = "recovery"))]
    {
        let _ = (
            recovery_percent,
            prefix,
            header_keys,
            resources,
            progress,
            output,
        );
        Err(Error::FeatureDisabled {
            feature: "recovery",
        })
    }
    #[cfg(feature = "recovery")]
    {
        if let Some(allowance) = &resources.execution {
            return recovery_service_with_allowance(
                recovery_percent,
                prefix,
                header_keys,
                resources,
                progress,
                output,
                allowance,
            );
        }
        recovery_service_with_allowance(
            recovery_percent,
            prefix,
            header_keys,
            resources,
            progress,
            output,
            &crate::codec::workspace::Allowance::default(),
        )
    }
}

#[cfg(feature = "recovery")]
fn recovery_service_with_allowance<B: crate::codec::workspace::Budget>(
    recovery_percent: u64,
    prefix: &mut Spool,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
    progress: Option<ProgressReporter<'_>>,
    output: &mut dyn Write,
    allowance: &B,
) -> Result<u64> {
    let prefix_len = prefix.len();
    let plan = plan_inline_recovery(prefix_len, recovery_percent)?;
    let (mode, required) = choose_recovery_memory_mode(plan, resources.memory_limit())?;
    let (mode, required) = if let Some(allowance) = &resources.execution {
        crate::recovery::rar5::choose_recovery_capacity_mode(
            plan,
            resources.memory_limit(),
            allowance,
        )?
    } else {
        (mode, required)
    };
    let _permit = resources.acquire_cancellable(required, 0, &|| {
        progress.is_some_and(ProgressReporter::is_cancelled)
    })?;

    let mut scratch = match mode {
        crate::recovery::rar5::RecoveryMemoryMode::Striped { .. } => {
            Some(Spool::create(resources)?)
        }
        crate::recovery::rar5::RecoveryMemoryMode::Resident => None,
    };
    let mut payload = Spool::create(resources)?;
    prefix.rewind()?;
    let built = streamed_recovery_with_allowance(
        &mut CancellableIo {
            inner: prefix,
            progress,
        },
        prefix_len,
        plan,
        mode,
        scratch
            .as_mut()
            .map(|scratch| scratch as &mut dyn ReadWriteSeek),
        &mut CancellableIo {
            inner: &mut payload,
            progress,
        },
        progress,
        1,
        allowance,
    )
    .map_err(|error| {
        if check_cancelled(progress).is_err() {
            Error::Cancelled
        } else {
            error.into()
        }
    })?;

    debug_assert_eq!(built.plan.payload_size(), Ok(built.payload_len));

    let mut service_data = Bytes::new(resources);
    service_data.vint(recovery_percent)?;
    let mut extra = Bytes::new(resources);
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data)?;
    let specific = stored_file_specific(
        b"RR",
        built.payload_len,
        built.payload_crc32,
        0,
        None,
        0,
        resources,
    )?;
    let header = match header_keys {
        Some(keys) => encrypted_header_block(
            &keys.keys,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(built.payload_len),
            &specific,
            &extra,
            &[],
            resources,
        )?,
        None => block_header_image(
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(built.payload_len),
            &specific,
            &extra,
            resources,
        )?,
    };
    output.write_all(&header)?;
    payload.copy_to(output)?;
    Ok(header.len() as u64 + built.payload_len)
}

/// Writes to the archive and, when a recovery record is coming, keeps a copy
/// for the parity pass to read.
struct Tee<'a> {
    output: &'a mut dyn Write,
    mirror: Option<&'a mut Spool>,
}

impl Write for Tee<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.write_all(buffer)?;
        if let Some(mirror) = self.mirror.as_mut() {
            mirror.write_all(buffer)?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

/// Where a member's payload bytes come from when a volume set slices them up.
enum FragmentSource {
    Packed(Spool),
    Stored {
        prepared: PreparedSource,
        emitted: Owned<ChecksumSink>,
    },
}

impl FragmentSource {
    /// Checksums of the bytes a fragment will store, read ahead of writing them.
    ///
    /// The fragment's header carries these and the header goes out before the
    /// payload, so the range is read twice: once here and once to copy it. The
    /// alternative is patching the fields after the copy, which an encrypted
    /// header will not allow.
    fn checksums_range(
        &mut self,
        start: u64,
        len: u64,
        progress: Option<ProgressReporter<'_>>,
    ) -> Result<FragmentChecksums> {
        let mut sink = ChecksumSink::default();
        self.copy_range_unverified(
            start,
            len,
            &mut CancellableIo {
                inner: &mut sink,
                progress,
            },
        )?;
        Ok(FragmentChecksums {
            crc32: sink.crc.finish(),
            hash: sink.hash.finalize(),
        })
    }

    fn emit_range(
        &mut self,
        start: u64,
        len: u64,
        output: &mut dyn Write,
        expected_fragment: Option<FragmentChecksums>,
        resources: &WriterResources,
    ) -> Result<()> {
        let Self::Stored { prepared, emitted } = self else {
            return self.copy_range_unverified(start, len, output);
        };
        let mut buffer = Bytes::zeroed(64 * 1024, resources)?;
        let mut reader = prepared.source.open()?;
        reader.seek(std::io::SeekFrom::Start(start))?;
        let mut fragment = ChecksumSink::default();
        let mut remaining = len;
        while remaining != 0 {
            let want = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..want])?;
            output.write_all(&buffer[..want])?;
            emitted.write_all(&buffer[..want])?;
            if expected_fragment.is_some() {
                fragment.write_all(&buffer[..want])?;
            }
            remaining -= want as u64;
        }
        if let Some(expected) = expected_fragment {
            if fragment.crc.finish() != expected.crc32 || fragment.hash.finalize() != expected.hash
            {
                return Err(Error::SourceChanged(
                    "entry source contents changed while writing",
                ));
            }
        }
        if start + len == prepared.len {
            crate::write_stream::check_source_length(
                &mut *reader,
                start + len,
                prepared.len,
                "entry source size changed while writing",
            )?;
            prepared.verify(std::mem::take(&mut **emitted))?;
        }
        Ok(())
    }

    fn copy_range_unverified(
        &mut self,
        start: u64,
        len: u64,
        output: &mut dyn Write,
    ) -> Result<()> {
        match self {
            Self::Packed(spool) => {
                spool.copy_range_to(start, len, output)?;
            }
            Self::Stored { prepared, .. } => {
                let mut reader = prepared.source.open()?;
                reader.seek(std::io::SeekFrom::Start(start))?;
                let copied = std::io::copy(&mut reader.by_ref().take(len), output)?;
                if copied != len {
                    return Err(Error::SourceChanged(
                        "entry source size changed while writing",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// What a fragment that is not the last one reports about its own bytes.
#[derive(Clone, Copy)]
struct FragmentChecksums {
    crc32: u32,
    hash: [u8; 32],
}

/// Discards what it is given and keeps the running checksums.
struct ChecksumSink {
    crc: crate::crc32::Crc32,
    hash: crate::rar50::blake2sp::Hasher,
}

impl Default for ChecksumSink {
    fn default() -> Self {
        Self {
            crc: crate::crc32::Crc32::new(),
            hash: crate::rar50::blake2sp::Hasher::new(),
        }
    }
}

impl Write for ChecksumSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.crc.update(buf);
        self.hash.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A member ready to be sliced across volumes.
struct VolumeMember<'a> {
    name: &'a [u8],
    is_directory: bool,
    mtime: Option<u32>,
    mtime_nanoseconds: Option<u32>,
    file_times: Option<crate::FileTimes>,
    attributes: u64,
    host_os: u64,
    unpacked_size: u64,
    crc32: u32,
    hash: [u8; 32],
    compression_info: u64,
    payload_len: u64,
    source: FragmentSource,
    /// Encryption record for the file header, when the payload is encrypted.
    encryption: Option<([u8; 16], [u8; 16], [u8; 12])>,
}

struct MemberProgress<'a, 'p> {
    entries: &'a [ArchiveEntry],
    work: &'a crate::write_progress::WorkTracker<'p>,
}
impl compress::CompressionProgress for MemberProgress<'_, '_> {
    fn is_cancelled(&self) -> bool {
        self.work.is_cancelled()
    }
    fn advance(&self, bytes: u64) -> bool {
        self.work.advance(bytes)
    }
    fn started(&self, index: usize, size: u64) {
        self.work
            .entry_started(index, self.entries.len(), &self.entries[index].name, size);
    }
    fn finished(&self, index: usize, size: u64) {
        self.work
            .entry_finished(index, self.entries.len(), &self.entries[index].name, size);
    }
}

/// Writes a multi-volume archive, handing each volume to `sink` as it is
/// finished rather than keeping the set in memory.
pub(super) fn write_volumes(
    entries: &[ArchiveEntry],
    plan: EnginePlan<'_>,
    max_payload_per_volume: u64,
    sink: &mut dyn super::VolumeSink,
    resources: &WriterResources,
) -> Result<()> {
    if max_payload_per_volume == 0 {
        return Err(Error::InvalidArgument("RAR 5 volume payload size is zero"));
    }
    for entry in entries {
        super::validate_entry(entry)?;
    }

    let header_keys = if plan.header_encrypted {
        let password = header_encryption_password(
            plan.header_password
                .into_iter()
                .chain(entries.iter().filter_map(|entry| entry.password.as_deref())),
        )?;
        Some(header_encryption_keys(password)?)
    } else {
        None
    };

    let mut sources = Records::new(entries.len(), resources)?;
    for entry in entries {
        sources.push(entry.source.clone())?;
    }
    let total_input = total_input_size(entries)?;
    let total_entries = entries.len();
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationStarted {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }
    let work = crate::write_progress::WorkTracker::new(
        plan.progress,
        crate::WriteOperation::Compression,
        total_input,
    );
    let compressed = compress::compress_members_with_context(
        &sources,
        &plan.compress,
        resources,
        &MemberProgress {
            entries,
            work: &work,
        },
        &|index, error| member_error(error, &entries[index].name, "compressing"),
    )?;

    let mut members = Records::new(entries.len(), resources)?;
    for (entry, member) in entries.iter().zip(compressed) {
        check_cancelled(plan.progress)?;
        members.push(
            prepare_volume_member(entry, member, &plan, resources)
                .map_err(|error| member_error(error, &entry.name, "preparing volume payload"))?,
        )?;
    }
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    if let Some(progress) = plan.progress {
        progress.report(crate::WriteProgressEvent::OperationFinished {
            operation: crate::WriteOperation::Compression,
            total_bytes: Some(total_input),
            total_entries: Some(total_entries),
            pass: 1,
        });
    }

    report_emission(plan.progress, true);
    let mut writer = VolumeWriter {
        max_payload_per_volume,
        solid: plan.compress.solid,
        recovery_percent: plan.recovery_percent,
        header_keys: header_keys.as_ref(),
        progress: plan.progress,
        resources,
        sink,
        body: None,
        payload_in_volume: 0,
        volume_index: 0,
    };

    for mut member in members {
        writer
            .write_member(&mut member)
            .map_err(|error| member_error(error, member.name, "writing volume member"))?;
    }
    writer.finish()?;
    check_cancelled(plan.progress)?;
    report_emission(plan.progress, false);
    Ok(())
}

/// Compresses and, if needed, encrypts one member into a form that can be cut
/// at any byte boundary.
fn prepare_volume_member<'a>(
    entry: &'a ArchiveEntry,
    member: CompressedMember,
    plan: &EnginePlan<'_>,
    resources: &WriterResources,
) -> Result<VolumeMember<'a>> {
    let progress = plan.progress;
    check_cancelled(progress)?;
    let compression_info = compress::member_compression_info(&plan.compress, &member)?;
    let plain_len = if member.store {
        member.input_size
    } else {
        member.packed.len()
    };

    match entry.password.as_deref() {
        Some(password) => {
            let mut salt = [0u8; 16];
            let mut iv = [0u8; 16];
            crate::write_stream::fill_entropy(
                &mut salt,
                "RAR 5 writer could not generate encryption salt",
            )?;
            crate::write_stream::fill_entropy(
                &mut iv,
                "RAR 5 writer could not generate encryption IV",
            )?;
            let keys =
                Rar50Keys::derive(password, salt, WRITE_KDF_COUNT_LOG).map_err(Error::from)?;

            // A volume boundary can fall anywhere, and the cipher runs as one
            // chain over the member, so encrypt it up front into scratch
            // storage and slice the ciphertext.
            let mut encrypted = Spool::create(resources)?;
            const ENCRYPT_CHUNK: usize = 64 * 1024;
            let _permit = resources.acquire_cancellable(ENCRYPT_CHUNK as u64, 0, &|| {
                progress.is_some_and(ProgressReporter::is_cancelled)
            })?;
            if member.store {
                let source = PreparedSource::new(&entry.source, &member);
                let mut reader = source.open()?;
                encrypt_reader_to(
                    &mut reader,
                    plain_len,
                    &mut encrypted,
                    &keys,
                    iv,
                    ENCRYPT_CHUNK,
                    progress,
                    resources,
                )?;
                reader.finish(&source, source.len)?;
            } else {
                let mut packed = member.packed;
                packed.rewind()?;
                encrypt_reader_to(
                    &mut packed,
                    plain_len,
                    &mut encrypted,
                    &keys,
                    iv,
                    ENCRYPT_CHUNK,
                    progress,
                    resources,
                )?;
            }
            let payload_len = encrypted.len();
            encrypted.park();
            Ok(VolumeMember {
                name: &entry.name,
                is_directory: entry.is_directory,
                mtime: entry.mtime,
                mtime_nanoseconds: entry.mtime_nanoseconds,
                file_times: entry.file_times,
                attributes: entry.attributes,
                host_os: entry.host_os,
                unpacked_size: member.input_size,
                crc32: keys.checked_crc_mac(member.crc32)?,
                hash: keys.checked_hash_mac(member.hash)?,
                compression_info,
                payload_len,
                source: FragmentSource::Packed(encrypted),
                encryption: Some((salt, iv, keys.checked_password_record()?)),
            })
        }
        None => Ok(VolumeMember {
            name: &entry.name,
            is_directory: entry.is_directory,
            mtime: entry.mtime,
            mtime_nanoseconds: entry.mtime_nanoseconds,
            file_times: entry.file_times,
            attributes: entry.attributes,
            host_os: entry.host_os,
            unpacked_size: member.input_size,
            crc32: member.crc32,
            hash: member.hash,
            compression_info,
            payload_len: plain_len,
            source: if member.store {
                FragmentSource::Stored {
                    prepared: PreparedSource::new(&entry.source, &member),
                    emitted: Owned::new(ChecksumSink::default(), resources)?,
                }
            } else {
                FragmentSource::Packed(member.packed)
            },
            encryption: None,
        }),
    }
}

struct VolumeWriter<'a> {
    max_payload_per_volume: u64,
    solid: bool,
    recovery_percent: Option<u64>,
    header_keys: Option<&'a HeaderEncryptionKeys>,
    progress: Option<ProgressReporter<'a>>,
    resources: &'a WriterResources,
    sink: &'a mut dyn super::VolumeSink,
    /// Body of the volume being filled, held on disk rather than in memory.
    body: Option<Spool>,
    payload_in_volume: u64,
    volume_index: u64,
}

impl VolumeWriter<'_> {
    /// Cuts one member across as many volumes as it takes.
    fn write_member(&mut self, member: &mut VolumeMember) -> Result<()> {
        check_cancelled(self.progress)?;
        let mut start = 0u64;
        let mut split_before = false;
        // Zero-length members still need a header of their own.
        loop {
            // A volume that filled exactly is left open until something asks
            // for room, because until then we cannot say whether it is the last
            // one, and its end-of-archive block has to say which.
            if self.body.is_some() && self.payload_in_volume == self.max_payload_per_volume {
                self.finish_volume(true)?;
            }
            if self.body.is_none() {
                self.start_volume()?;
            }
            let room = self.max_payload_per_volume - self.payload_in_volume;
            let remaining = member.payload_len - start;
            let fragment_len = room.min(remaining);
            let split_after = start + fragment_len < member.payload_len;
            // A fragment that is not the last one has no whole-member checksum
            // to report, so the field carries the CRC32 of the bytes this
            // volume stores. That is what WinRAR puts there, and it lets a
            // single volume be checked on its own.
            let fragment_checksums = match split_after {
                true => Some(
                    member
                        .source
                        .checksums_range(start, fragment_len, self.progress)?,
                ),
                false => None,
            };

            let header = fragment_header(
                member,
                fragment_len,
                split_before,
                fragment_checksums,
                self.header_keys,
                self.resources,
            )?;
            let body = self.body.as_mut().expect("volume started");
            body.write_all(&header)?;
            member.source.emit_range(
                start,
                fragment_len,
                &mut CancellableIo {
                    inner: body,
                    progress: self.progress,
                },
                fragment_checksums,
                self.resources,
            )?;

            self.payload_in_volume += fragment_len;
            start += fragment_len;
            split_before = true;

            if start >= member.payload_len {
                return Ok(());
            }
        }
    }

    fn finish(mut self) -> Result<()> {
        // The public volume entry point rejects empty member lists; each
        // nonempty member starts a volume, even when its payload is empty.
        self.finish_volume(false)
    }

    fn start_volume(&mut self) -> Result<()> {
        self.body = Some(Spool::create(self.resources)?);
        self.payload_in_volume = 0;
        Ok(())
    }

    fn finish_volume(&mut self, more_volumes_follow: bool) -> Result<()> {
        let mut body = self.body.take().expect("volume started");
        let volume_number = self.volume_index;
        self.volume_index += 1;
        self.payload_in_volume = 0;

        let head_crypt = match self.header_keys {
            Some(keys) => {
                let mut block = Bytes::new(self.resources);
                write_head_crypt(&mut block, keys, self.resources)?;
                block
            }
            None => Bytes::new(self.resources),
        };

        let mut main_flags = crate::rar50::MHFL_VOLUME | crate::rar50::MHFL_VOLUME_NUMBER;
        if self.solid {
            main_flags |= MHFL_SOLID;
        }
        if self.recovery_percent.is_some() {
            main_flags |= MHFL_RECOVERY;
        }

        let layout = resolve_layout(
            &LayoutInputs {
                header_encrypted: self.header_keys.is_some(),
                head_crypt_len: head_crypt.len() as u64,
                main_flags,
                volume_number: Some(volume_number),
                archive_metadata: None,
                metadata_record: None,
                body_len: body.len(),
                quick_open_payload_len: None,
                recovery_percent: self.recovery_percent,
            },
            self.resources,
        )?;

        check_cancelled(self.progress)?;
        let raw_output = self.sink.start_volume(volume_number)?;
        let mut output = CancellableIo {
            inner: raw_output,
            progress: self.progress,
        };
        let mut mirror = match self.recovery_percent {
            Some(_) => Some(Spool::create(self.resources)?),
            None => None,
        };
        let mut written;
        {
            let mut tee = Tee {
                output: &mut output,
                mirror: mirror.as_mut(),
            };
            let main = match self.header_keys {
                Some(keys) => encrypted_main_header_block(
                    &keys.keys,
                    main_flags,
                    Some(volume_number),
                    &layout.main_extra,
                    self.resources,
                )?,
                None => {
                    let mut main = Bytes::new(self.resources);
                    write_main_header(
                        &mut main,
                        main_flags,
                        Some(volume_number),
                        &layout.main_extra,
                        self.resources,
                    )?;
                    main
                }
            };
            debug_assert_eq!(main.len() as u64, layout.main_header_len);

            tee.write_all(RAR50_SIGNATURE)?;
            tee.write_all(&head_crypt)?;
            tee.write_all(&main)?;
            body.rewind()?;
            std::io::copy(&mut body, &mut tee)?;
            written = RAR50_SIGNATURE.len() as u64
                + head_crypt.len() as u64
                + main.len() as u64
                + body.len();
        }

        if let Some(recovery_percent) = self.recovery_percent {
            let mirror = mirror.as_mut().expect("recovery mirrors the volume");
            debug_assert_eq!(layout.recovery_prefix_len, Some(mirror.len()));
            written += write_recovery_service(
                recovery_percent,
                mirror,
                self.header_keys,
                self.resources,
                self.progress,
                &mut output,
            )?;
        }

        let end_flags = if more_volumes_follow {
            crate::rar50::EFL_NEXT_VOLUME
        } else {
            0
        };
        let end = match self.header_keys {
            Some(keys) => encrypted_header_block(
                &keys.keys,
                HEAD_END,
                0,
                None,
                &super::end_header_specific(end_flags),
                &[],
                &[],
                self.resources,
            )?,
            None => {
                let mut end = Bytes::new(self.resources);
                write_end_header(&mut end, end_flags, self.resources)?;
                end
            }
        };
        output.write_all(&end)?;
        written += end.len() as u64;
        output.flush()?;
        drop(output);

        self.sink.finish_volume(volume_number, written)
    }
}

/// Builds the file header for one fragment of a member.
///
/// Every fragment repeats the member's metadata. The last one carries the
/// member's own checksum and hash; the rest carry `fragment` over the bytes
/// they store, which is what WinRAR puts there and lets one volume be checked
/// on its own. Encrypted fragments checksum the ciphertext, so that check needs
/// no password.
///
/// Both a CRC32 and a hash record go on every fragment. A reader takes the hash
/// record as the member's checksum type when it has one, and unrar picks that
/// type from the first fragment and compares it against the last, so a fragment
/// that offered only a CRC32 while the last offered a hash would fail a member
/// that is perfectly intact.
fn fragment_header(
    member: &VolumeMember,
    fragment_len: u64,
    split_before: bool,
    fragment: Option<FragmentChecksums>,
    header_keys: Option<&HeaderEncryptionKeys>,
    resources: &WriterResources,
) -> Result<Bytes> {
    let split_after = fragment.is_some();
    let mut extra = Bytes::new(resources);
    if let Some((salt, iv, check_value)) = member.encryption {
        write_file_encryption_record(&mut extra, salt, iv, check_value)?;
    }
    write_hash_record_with_value(&mut extra, fragment.map_or(member.hash, |f| f.hash))?;
    super::headers::write_mtime_record(&mut extra, member.mtime, member.mtime_nanoseconds)?;
    if let Some(times) = member.file_times {
        write_extra_record(&mut extra, super::super::FHEXTRA_HTIME, &times.encode()?)?;
    }
    let specific = file_specific(
        member.name,
        member.unpacked_size,
        fragment.map_or(member.crc32, |f| f.crc32),
        member.attributes,
        member.mtime.filter(|_| member.mtime_nanoseconds.is_none()),
        member.compression_info,
        member.host_os,
        member.is_directory,
        resources,
    )?;

    // Every fragment has a hash record, so its extra area is never empty.
    let mut flags = HFL_DATA | HFL_EXTRA;
    if split_before {
        flags |= crate::rar50::HFL_SPLIT_BEFORE;
    }
    if split_after {
        flags |= crate::rar50::HFL_SPLIT_AFTER;
    }
    match header_keys {
        Some(keys) => encrypted_header_block(
            &keys.keys,
            HEAD_FILE,
            flags,
            Some(fragment_len),
            &specific,
            &extra,
            &[],
            resources,
        ),
        None => block_header_image(
            HEAD_FILE,
            flags,
            Some(fragment_len),
            &specific,
            &extra,
            resources,
        ),
    }
}

fn report_emission(progress: Option<ProgressReporter<'_>>, started: bool) {
    use crate::{WriteOperation, WriteProgressEvent};
    if let Some(progress) = progress {
        progress.report(if started {
            WriteProgressEvent::OperationStarted {
                operation: WriteOperation::Emission,
                total_bytes: None,
                total_entries: None,
                pass: 1,
            }
        } else {
            WriteProgressEvent::OperationFinished {
                operation: WriteOperation::Emission,
                total_bytes: None,
                total_entries: None,
                pass: 1,
            }
        });
    }
}

fn member_error(error: Error, name: &[u8], operation: &'static str) -> Error {
    // Cancellation remains an operation-level result. A streaming fallback can
    // already have supplied the same member context; do not duplicate it.
    if error.kind() == crate::ErrorKind::Cancelled
        || error
            .entry_context()
            .is_some_and(|(existing, _)| existing == name)
    {
        error
    } else {
        error.at_entry(name.to_vec(), operation)
    }
}

#[cfg(test)]
mod input_size_tests {
    use super::*;

    #[test]
    fn writer_adapters_flush_the_output_and_preserve_checksums() {
        struct FlushingSink {
            bytes: Vec<u8>,
            flushes: usize,
            fail: bool,
        }

        impl Write for FlushingSink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                if self.fail {
                    Err(std::io::Error::other("injected flush failure"))
                } else {
                    Ok(())
                }
            }
        }

        let mut output = FlushingSink {
            bytes: Vec::new(),
            flushes: 0,
            fail: false,
        };
        {
            let mut tee = Tee {
                output: &mut output,
                mirror: None,
            };
            tee.write_all(b"payload").unwrap();
            tee.flush().unwrap();
        }
        assert_eq!(output.bytes, b"payload");
        assert_eq!(output.flushes, 1);
        output.fail = true;
        assert_eq!(
            Tee {
                output: &mut output,
                mirror: None,
            }
            .flush()
            .unwrap_err()
            .to_string(),
            "injected flush failure"
        );
        assert_eq!(output.flushes, 2);

        let mut checksum = ChecksumSink::default();
        checksum.write_all(b"payload").unwrap();
        checksum.flush().unwrap();
        assert_eq!(checksum.crc.finish(), crate::crc32::crc32(b"payload"));
    }

    fn virtual_entry(name: &[u8], length: u64) -> ArchiveEntry {
        ArchiveEntry::new(
            name.to_vec(),
            crate::EntrySource::from_opener(length, || panic!("measuring input opened a source")),
        )
    }

    #[test]
    fn total_input_size_accepts_empty_and_exact_u64_maximum() {
        assert_eq!(total_input_size(&[]).unwrap(), 0);
        let entries = [
            virtual_entry(b"first", u64::MAX - 1),
            virtual_entry(b"last", 1),
            virtual_entry(b"empty", 0),
        ];
        assert_eq!(total_input_size(&entries).unwrap(), u64::MAX);
    }

    #[test]
    fn total_input_size_preserves_source_errors_and_cancellation() {
        struct Broken(bool);
        impl crate::streaming::SourceFactory for Broken {
            fn len(&self) -> Result<u64> {
                if self.0 {
                    Err(Error::Cancelled)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "injected metadata failure",
                    )
                    .into())
                }
            }
            fn open(&self) -> Result<Box<dyn crate::EntryReader>> {
                panic!("measuring input opened a source")
            }
        }
        for cancelled in [false, true] {
            let entry = ArchiveEntry::new(
                b"broken".to_vec(),
                crate::EntrySource::from_factory(Broken(cancelled)),
            );
            let error = total_input_size(&[entry]).unwrap_err();
            if cancelled {
                assert_eq!(error, Error::Cancelled);
                assert!(error.entry_context().is_none());
            } else {
                assert_eq!(error.kind(), crate::ErrorKind::Io);
                assert_eq!(
                    error.entry_context().unwrap(),
                    (b"broken".as_slice(), "preparing")
                );
            }
        }
    }
}

#[cfg(test)]
mod quick_open_tests {
    use super::*;

    #[test]
    fn streamed_records_match_buffered_encoding_at_vint_boundaries() {
        for distance in [0, 127, 128, 16383, 16384, u64::MAX] {
            for size in [0, 1, 123, 127, 128, 16383, 16384] {
                let header = vec![0xa5; size];
                let mut body = Vec::new();
                write_vint(&mut body, 0);
                write_vint(&mut body, distance);
                write_vint(&mut body, size as u64);
                body.extend_from_slice(&header);
                let mut framed = Vec::new();
                write_vint(&mut framed, body.len() as u64);
                framed.extend_from_slice(&body);
                let mut expected = crate::crc32::crc32(&framed).to_le_bytes().to_vec();
                expected.extend_from_slice(&framed);
                let mut actual = Vec::new();
                let mut crc = crate::crc32::Crc32::new();
                append_quick_open_entry(&mut actual, &mut crc, distance, &header).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(crc.finish(), crate::crc32::crc32(&actual));
            }
        }
    }
}

#[cfg(test)]
mod service_payload_tests {
    use super::*;

    #[test]
    fn prepared_services_borrow_input_and_stream_identical_ciphertext() {
        for size in [0usize, 1, 15, 16, 65535, 65536, 65537, 131089] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let plain = stored_service_block(b"CMT", &data, &[], None, &WriterResources::default())
                .unwrap();
            let Payload::Borrowed(borrowed) = plain.payload else {
                panic!("expected borrowed service")
            };
            assert_eq!(borrowed.as_ptr(), data.as_ptr());
            assert_eq!(borrowed.len(), data.len());
            let encrypted = encrypted_service_block(
                b"CMT",
                &data,
                &[],
                b"secret",
                None,
                &WriterResources::default(),
            )
            .unwrap();
            let Payload::Encrypted { plain, keys, iv } = &encrypted.payload else {
                panic!("expected streaming encryption")
            };
            let PlainPayload::Borrowed(borrowed) = plain.as_ref() else {
                panic!("expected borrowed plaintext")
            };
            assert_eq!(borrowed.as_ptr(), data.as_ptr());
            let mut expected = data.clone();
            expected.resize(size.div_ceil(16) * 16, 0);
            crate::crypto::rar50::Rar50Cipher::new(keys.key, *iv)
                .encrypt_in_place(&mut expected)
                .unwrap();
            assert_eq!(encrypted.payload_len, expected.len() as u64);
            let mut actual = Vec::new();
            write_payload(
                encrypted.payload,
                &mut actual,
                &WriterResources::default(),
                None,
            )
            .unwrap();
            assert_eq!(actual, expected, "service size {size}");
        }
    }
}

#[cfg(test)]
mod preparation_name_tests {
    use super::*;
    #[test]
    fn allocation_free_target_length_preserves_rar50_mapping_rules() {
        for bytes in [
            b"plain".as_slice(),
            b"\xffinvalid",
            "é/名字".as_bytes(),
            "\u{e080}".as_bytes(),
            "\u{fffe}a\u{e080}\u{e0ff}é".as_bytes(),
            "\u{fffe}\u{fffe}".as_bytes(),
        ] {
            assert_eq!(
                decoded_rar50_name_len(bytes),
                crate::filename::decode_rar50(bytes).len()
            );
        }
    }
}

#[cfg(test)]
mod emission_ledger_tests {
    use super::*;
    use crate::codec::workspace::Allowance;

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn source_disappearing_at_compression_start_retains_member_context() {
        use std::sync::atomic::{AtomicBool, Ordering};
        for volumes in [false, true] {
            let scratch = crate::scratch::case("source-disappears-before-compression");
            let path = scratch.join("source");
            std::fs::write(&path, b"payload").unwrap();
            let entries = [ArchiveEntry::new(
                b"missing.bin".to_vec(),
                crate::EntrySource::from_path(&path),
            )];
            let resources = WriterResources::new(128 * 1024 * 1024)
                .with_max_memory_bytes(128 * 1024 * 1024)
                .with_temp_dir(&*scratch);
            let removed = AtomicBool::new(false);
            let callback = |event: crate::WriteProgressEvent<'_>| {
                if matches!(
                    event,
                    crate::WriteProgressEvent::OperationStarted {
                        operation: crate::WriteOperation::Compression,
                        ..
                    }
                ) && !removed.swap(true, Ordering::Relaxed)
                {
                    std::fs::remove_file(&path).unwrap();
                }
            };
            let mut plan = plan(false);
            plan.progress = Some(ProgressReporter(&callback));
            let error = if volumes {
                let mut output = super::super::CollectedVolumes::new();
                let error = write_volumes(&entries, plan, 64, &mut output, &resources).unwrap_err();
                assert!(output.take().is_empty());
                error
            } else {
                let mut output = Vec::new();
                let error = write_archive(&entries, plan, &resources, &mut output).unwrap_err();
                assert!(output.is_empty());
                error
            };
            assert!(removed.load(Ordering::Relaxed));
            assert_eq!(error.kind(), crate::ErrorKind::Io);
            assert_eq!(
                error.entry_context(),
                Some((b"missing.bin".as_slice(), "compressing"))
            );
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(resources.managed_memory_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn zero_volume_payload_is_rejected_before_opening_a_sink() {
        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let mut sink = super::super::CollectedVolumes::new();
        let error = write_volumes(
            &entries,
            plan(false),
            0,
            &mut sink,
            &WriterResources::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn prepared_record_counts_include_empty_archives_comments_and_services() {
        // The aggregate bound uses distinct live storage for owned records.
        assert!(std::mem::size_of::<ArchiveEntry>() >= 2);
        assert!(std::mem::size_of::<super::super::ServiceEntry>() >= 2);
        for count in 0..=2 {
            for comment in [false, true] {
                let entries: Vec<_> = (0..count)
                    .map(|index| {
                        let entry = ArchiveEntry::new(
                            format!("file{index}").into_bytes(),
                            crate::EntrySource::from_bytes(b"payload".to_vec()),
                        );
                        if index == 1 {
                            entry.with_service(super::super::ServiceEntry::new(b"CMT", b"note"))
                        } else {
                            entry
                        }
                    })
                    .collect();
                let mut settings = plan(false);
                settings.compress.method = 0;
                settings.quick_open = false;
                settings.recovery_percent = None;
                if !comment {
                    settings.archive_comment = None;
                }
                let mut bytes = Vec::new();
                write_archive(&entries, settings, &WriterResources::default(), &mut bytes).unwrap();
                let archive = crate::ArchiveReader::read_owned(bytes).unwrap();
                let raw = archive.as_rar50().unwrap();
                assert_eq!(raw.files().count(), count);
                assert_eq!(
                    raw.services().count(),
                    usize::from(comment) + usize::from(count == 2)
                );
                for index in 0..count {
                    assert_eq!(
                        archive
                            .read_member(format!("file{index}").as_bytes(), None)
                            .unwrap()
                            .unwrap(),
                        b"payload"
                    );
                }
            }
        }
    }

    #[test]
    fn compression_completion_cancellation_precedes_archive_and_volume_emission() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct CancelAtCompletion {
            armed: AtomicBool,
            cancelled: AtomicBool,
            finished: AtomicBool,
            emitted: AtomicBool,
        }
        impl crate::WriteProgress for CancelAtCompletion {
            fn report(&self, event: crate::WriteProgressEvent<'_>) {
                use crate::{WriteOperation, WriteProgressEvent};
                match event {
                    WriteProgressEvent::OperationStarted {
                        operation: WriteOperation::Compression,
                        total_entries: Some(0),
                        ..
                    }
                    | WriteProgressEvent::EntryFinished {
                        operation: WriteOperation::Compression,
                        ..
                    } => self.armed.store(true, Ordering::Relaxed),
                    WriteProgressEvent::Advanced {
                        operation: WriteOperation::Compression,
                        ..
                    } if self.armed.load(Ordering::Relaxed) => {
                        self.cancelled.store(true, Ordering::Relaxed);
                    }
                    WriteProgressEvent::OperationFinished {
                        operation: WriteOperation::Compression,
                        ..
                    } => self.finished.store(true, Ordering::Relaxed),
                    WriteProgressEvent::OperationStarted {
                        operation: WriteOperation::Emission,
                        ..
                    } => self.emitted.store(true, Ordering::Relaxed),
                    _ => {}
                }
            }
            fn is_cancelled(&self) -> bool {
                self.cancelled.load(Ordering::Relaxed)
            }
        }
        for empty in [false, true] {
            for volumes in [false, true] {
                let scratch = crate::scratch::case("completion-cancellation");
                let resources = WriterResources::default().with_temp_dir(&*scratch);
                let progress = CancelAtCompletion {
                    armed: AtomicBool::new(false),
                    cancelled: AtomicBool::new(false),
                    finished: AtomicBool::new(false),
                    emitted: AtomicBool::new(false),
                };
                let entries = if empty {
                    Vec::new()
                } else {
                    vec![ArchiveEntry::new(
                        b"file".to_vec(),
                        crate::EntrySource::from_bytes(b"payload".to_vec()),
                    )]
                };
                let mut settings = plan(false);
                settings.archive_comment = None;
                settings.recovery_percent = None;
                settings.progress = Some(ProgressReporter(&progress));
                let error = if volumes {
                    let mut sink = super::super::CollectedVolumes::new();
                    let error =
                        write_volumes(&entries, settings, 1024, &mut sink, &resources).unwrap_err();
                    assert!(sink.take().is_empty());
                    error
                } else {
                    let mut output = Vec::new();
                    let error =
                        write_archive(&entries, settings, &resources, &mut output).unwrap_err();
                    assert!(output.is_empty());
                    error
                };
                assert_eq!(error, Error::Cancelled);
                assert!(progress.armed.load(Ordering::Relaxed));
                assert!(progress.cancelled.load(Ordering::Relaxed));
                assert!(!progress.finished.load(Ordering::Relaxed));
                assert!(!progress.emitted.load(Ordering::Relaxed));
                assert_eq!(resources.workspace_in_use(), 0);
                assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
            }
        }
    }

    #[test]
    fn quick_open_skips_file_services_but_keeps_plain_comments() {
        let entry = ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )
        .with_service(super::super::ServiceEntry::new(b"CMT", b"file note"));
        let mut plan = plan(false);
        plan.quick_open = true;
        plan.recovery_percent = None;
        let mut bytes = Vec::new();
        write_archive(&[entry], plan, &WriterResources::default(), &mut bytes).unwrap();

        let archive = crate::ArchiveReader::read_owned(bytes).unwrap();
        let raw = archive.as_rar50().unwrap();
        assert!(raw.main.locator().unwrap().quick_open_offset.is_some());
        let quick_open = raw
            .services()
            .find(|service| service.name == b"QO")
            .unwrap();
        let payload = quick_open.packed_data(raw).unwrap();
        fn vint(data: &[u8], cursor: &mut usize) -> usize {
            let mut value = 0usize;
            for shift in (0..70).step_by(7) {
                let byte = data[*cursor];
                *cursor += 1;
                value |= ((byte & 0x7f) as usize) << shift;
                if byte & 0x80 == 0 {
                    return value;
                }
            }
            panic!("invalid quick-open record length")
        }
        let mut cursor = 0;
        let mut records = 0;
        while cursor < payload.len() {
            cursor += 4; // Per-record CRC32.
            let body_len = vint(&payload, &mut cursor);
            cursor += body_len;
            assert!(cursor <= payload.len());
            records += 1;
        }
        // The plain archive comment and file are cached; the attached service is not.
        assert_eq!(records, 2);
        assert_eq!(
            archive.member_comment_at(0, None).unwrap(),
            Some(b"file note".to_vec())
        );
        assert_eq!(
            archive.read_member(b"file", None).unwrap().unwrap(),
            b"payload"
        );
    }

    struct FailingSink;
    impl Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected emission failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn archive_emission_propagates_each_output_write_failure() {
        struct FailOnWrite {
            fail_at: usize,
            writes: usize,
        }
        impl Write for FailOnWrite {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                let call = self.writes;
                self.writes += 1;
                if call == self.fail_at {
                    Err(std::io::Error::other("injected output failure"))
                } else {
                    Ok(data.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let settings = || {
            let mut plan = plan(false);
            plan.recovery_percent = None;
            plan.quick_open = true;
            plan
        };
        let resources = WriterResources::default();
        let mut counting = FailOnWrite {
            fail_at: usize::MAX,
            writes: 0,
        };
        write_archive(&entries, settings(), &resources, &mut counting).unwrap();
        assert!(counting.writes >= 6);

        let mut member_failure = false;
        let mut archive_failure = false;
        for fail_at in 0..counting.writes {
            let mut sink = FailOnWrite { fail_at, writes: 0 };
            let error = write_archive(&entries, settings(), &resources, &mut sink).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Io, "write {fail_at}");
            assert_eq!(sink.writes, fail_at + 1);
            if error.entry_context() == Some((b"file".as_slice(), "writing")) {
                member_failure = true;
            } else {
                archive_failure = true;
            }
        }
        assert!(member_failure);
        assert!(archive_failure);
    }

    #[test]
    fn volume_emission_propagates_sink_failures_before_handoff() {
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct State {
            writes: usize,
            finishes: usize,
        }
        struct Sink {
            state: Arc<Mutex<State>>,
            fail_write: Option<usize>,
            fail_start: bool,
            fail_flush: bool,
            fail_finish: bool,
        }
        struct Volume {
            state: Arc<Mutex<State>>,
            fail_write: Option<usize>,
            fail_flush: bool,
        }
        impl Write for Volume {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let mut state = self.state.lock().unwrap();
                let call = state.writes;
                state.writes += 1;
                if self.fail_write == Some(call) {
                    Err(std::io::Error::other("injected volume write failure"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                if self.fail_flush {
                    Err(std::io::Error::other("injected volume flush failure"))
                } else {
                    Ok(())
                }
            }
        }
        impl super::super::VolumeSink for Sink {
            fn start_volume(&mut self, _: u64) -> Result<Box<dyn Write + Send>> {
                if self.fail_start {
                    return Err(std::io::Error::other("injected volume start failure").into());
                }
                Ok(Box::new(Volume {
                    state: self.state.clone(),
                    fail_write: self.fail_write,
                    fail_flush: self.fail_flush,
                }))
            }
            fn finish_volume(&mut self, _: u64, _: u64) -> Result<()> {
                self.state.lock().unwrap().finishes += 1;
                if self.fail_finish {
                    Err(std::io::Error::other("injected volume finish failure").into())
                } else {
                    Ok(())
                }
            }
        }

        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let settings = || {
            let mut plan = plan(false);
            plan.recovery_percent = None;
            plan
        };
        let resources = WriterResources::default();
        let make_sink = || Sink {
            state: Arc::new(Mutex::new(State::default())),
            fail_write: None,
            fail_start: false,
            fail_flush: false,
            fail_finish: false,
        };
        let mut success = make_sink();
        write_volumes(&entries, settings(), 4096, &mut success, &resources).unwrap();
        let writes = success.state.lock().unwrap().writes;
        assert!(writes >= 4);
        assert_eq!(success.state.lock().unwrap().finishes, 1);

        for fail_at in 0..writes {
            let mut sink = make_sink();
            sink.fail_write = Some(fail_at);
            let error =
                write_volumes(&entries, settings(), 4096, &mut sink, &resources).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Io, "write {fail_at}");
            assert_eq!(sink.state.lock().unwrap().writes, fail_at + 1);
            assert_eq!(sink.state.lock().unwrap().finishes, 0);
        }
        for failure in 0..3 {
            let mut sink = make_sink();
            sink.fail_start = failure == 0;
            sink.fail_flush = failure == 1;
            sink.fail_finish = failure == 2;
            let error =
                write_volumes(&entries, settings(), 4096, &mut sink, &resources).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Io);
            assert_eq!(
                sink.state.lock().unwrap().finishes,
                usize::from(failure == 2)
            );
        }
    }

    #[test]
    fn encryption_emission_counts_retained_preparation_and_releases_chunk() {
        let data = vec![7; 65537];
        for limit in [65536, 131072] {
            let ledger = Allowance::limited(limit);
            let resources = WriterResources::default().with_execution_allowance(ledger.clone());
            let retained = Bytes::zeroed(128, &resources).unwrap();
            for fail_sink in [false, true] {
                let keys = Rar50Keys::derive(b"secret", [1; 16], WRITE_KDF_COUNT_LOG).unwrap();
                let mut expected = data.clone();
                expected.resize(data.len().div_ceil(16) * 16, 0);
                crate::crypto::rar50::Rar50Cipher::new(keys.key, [2; 16])
                    .encrypt_in_place(&mut expected)
                    .unwrap();
                let payload = Payload::Encrypted {
                    plain: Owned::new(PlainPayload::Borrowed(&data), &resources).unwrap(),
                    keys,
                    iv: [2; 16],
                };
                let mut actual = Vec::new();
                let result = if fail_sink {
                    write_payload(payload, &mut FailingSink, &resources, None)
                } else {
                    write_payload(payload, &mut actual, &resources, None)
                };
                if limit == 65536 {
                    assert_eq!(result.unwrap_err().kind(), crate::ErrorKind::ResourceLimit);
                    assert!(actual.is_empty());
                } else if fail_sink {
                    assert!(result.is_err());
                } else {
                    result.unwrap();
                    assert_eq!(actual, expected);
                }
                assert_eq!(ledger.used(), 128);
                assert_eq!(resources.workspace_in_use(), 0);
            }
            drop(retained);
            assert_eq!(ledger.used(), 0);
        }
    }

    #[test]
    #[cfg(feature = "recovery")]
    fn recovery_emission_shares_ledger_in_resident_and_striped_modes() {
        let scratch = crate::scratch::case("recovery-emission-ledger");
        let data = vec![7; 131072];
        for estimated_limit in [16384, 8 * 1024 * 1024] {
            let base = WriterResources::new(estimated_limit).with_temp_dir(&*scratch);
            let mut prefix = Spool::create(&base).unwrap();
            prefix.write_all(&data).unwrap();
            let mut expected = Vec::new();
            write_recovery_service(10, &mut prefix, None, &base, None, &mut expected).unwrap();
            for limit in [131072, 8 * 1024 * 1024] {
                let ledger = Allowance::limited(limit);
                let resources = base.clone().with_execution_allowance(ledger.clone());
                let retained = Bytes::zeroed(128, &resources).unwrap();
                let mut actual = Vec::new();
                let result =
                    write_recovery_service(10, &mut prefix, None, &resources, None, &mut actual);
                if limit == 131072 {
                    assert_eq!(result.unwrap_err().kind(), crate::ErrorKind::ResourceLimit);
                    assert!(actual.is_empty());
                } else {
                    result.unwrap();
                    assert_eq!(actual, expected);
                    let cancel = CancelRecovery {
                        cancelled: std::sync::atomic::AtomicBool::new(false),
                    };
                    let error = write_recovery_service(
                        10,
                        &mut prefix,
                        None,
                        &resources,
                        Some(ProgressReporter(&cancel)),
                        &mut Vec::new(),
                    )
                    .unwrap_err();
                    assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
                    assert_eq!(ledger.used(), 128);

                    assert!(write_recovery_service(
                        10,
                        &mut prefix,
                        None,
                        &resources,
                        None,
                        &mut FailingSink
                    )
                    .is_err());
                }
                assert_eq!(ledger.used(), 128);
                assert_eq!(resources.workspace_in_use(), 0);
                drop(retained);
                assert_eq!(ledger.used(), 0);
                // The caller's prefix survives; temporary parity and payload files do not.
                assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 1);
            }
            drop(prefix);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[cfg(feature = "recovery")]
    struct CancelRecovery {
        cancelled: std::sync::atomic::AtomicBool,
    }
    #[cfg(feature = "recovery")]
    impl crate::WriteProgress for CancelRecovery {
        fn report(&self, event: crate::WriteProgressEvent<'_>) {
            if matches!(
                event,
                crate::WriteProgressEvent::Advanced {
                    operation: crate::WriteOperation::Recovery,
                    ..
                }
            ) {
                self.cancelled
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    fn plan<'a>(encrypted: bool) -> EnginePlan<'a> {
        let options = crate::codec::rar50::EncodeOptions::new(8).with_max_match_distance(131072);
        EnginePlan {
            compress: CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 131072,
                block_size: 4096,
                solid: false,
                method: 0,
                filter_policy: super::super::FilterPolicy::None,
                candidates: vec![options].into(),
            },
            recovery_percent: Some(10),
            header_encrypted: encrypted,
            header_password: encrypted.then_some(b"secret".as_slice()),
            archive_comment: Some(if encrypted {
                ArchiveCommentPlan::Encrypted {
                    data: b"comment",
                    password: b"secret",
                }
            } else {
                ArchiveCommentPlan::Plain(b"comment")
            }),
            archive_metadata: None,
            metadata_record: None,
            locked: false,
            quick_open: false,
            progress: None,
        }
    }

    #[test]
    fn volume_emission_reports_compression_completion() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let finished = AtomicBool::new(false);
        let report = |event: crate::WriteProgressEvent<'_>| {
            if matches!(
                event,
                crate::WriteProgressEvent::OperationFinished {
                    operation: crate::WriteOperation::Compression,
                    total_bytes: Some(7),
                    total_entries: Some(1),
                    ..
                }
            ) {
                finished.store(true, Ordering::Relaxed);
            }
        };
        let mut plan = plan(false);
        plan.progress = Some(ProgressReporter(&report));
        plan.recovery_percent = None;
        let entries = [ArchiveEntry::new(
            b"file".to_vec(),
            crate::EntrySource::from_bytes(b"payload".to_vec()),
        )];
        let mut sink = super::super::CollectedVolumes::new();
        write_volumes(&entries, plan, 4096, &mut sink, &WriterResources::default()).unwrap();
        assert!(finished.load(Ordering::Relaxed));
        assert_eq!(sink.take().len(), 1);
    }

    #[test]
    fn an_existing_member_context_is_not_wrapped_again() {
        let original =
            Error::InvalidArgument("source changed").at_entry(b"file".to_vec(), "reading");
        let error = member_error(original, b"file", "writing");
        assert_eq!(error.entry_context(), Some((b"file".as_slice(), "reading")));
    }

    #[test]
    fn archive_and_volume_emission_keep_the_ledger_reusable() {
        let scratch = crate::scratch::case("archive-emission-ledger");
        for encrypted in [false, true] {
            let mut entry = ArchiveEntry::new(
                b"payload".to_vec(),
                crate::EntrySource::from_bytes(vec![7; 16384]),
            );
            if encrypted {
                entry = entry.with_password(b"secret");
            }
            let entries = [entry];
            let base = WriterResources::default().with_temp_dir(&*scratch);
            let ledger = Allowance::limited(8 * 1024 * 1024);
            let resources = base.clone().with_execution_allowance(ledger.clone());
            let mut expected = Vec::new();
            write_archive(&entries, plan(encrypted), &base, &mut expected).unwrap();
            let mut actual = Vec::new();
            write_archive(&entries, plan(encrypted), &resources, &mut actual).unwrap();
            if !encrypted {
                assert_eq!(actual, expected);
            } else {
                assert_eq!(actual.len(), expected.len());
            }
            assert_eq!(ledger.used(), 0);
            assert!(
                write_archive(&entries, plan(encrypted), &resources, &mut FailingSink).is_err()
            );
            assert_eq!(ledger.used(), 0);
            let mut expected = super::super::CollectedVolumes::new();
            write_volumes(&entries, plan(encrypted), 4096, &mut expected, &base).unwrap();
            let small = Allowance::limited(32768);
            let constrained = base.clone().with_execution_allowance(small.clone());
            assert_eq!(
                write_volumes(
                    &entries,
                    plan(encrypted),
                    4096,
                    &mut super::super::CollectedVolumes::new(),
                    &constrained,
                )
                .unwrap_err()
                .kind(),
                crate::ErrorKind::ResourceLimit
            );
            assert_eq!(small.used(), 0);
            let mut actual = super::super::CollectedVolumes::new();
            write_volumes(&entries, plan(encrypted), 4096, &mut actual, &resources).unwrap();
            let expected = expected.take();
            let actual = actual.take();
            assert_eq!(actual.len(), 4);
            if !encrypted {
                assert_eq!(actual, expected);
            } else {
                assert_eq!(
                    actual.iter().map(Vec::len).collect::<Vec<_>>(),
                    expected.iter().map(Vec::len).collect::<Vec<_>>()
                );
            }
            assert_eq!(ledger.used(), 0);
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn archive_preparation_refusals_release_capacity_at_each_boundary() {
        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let mut limit = 0;
        let mut refusals = 0;
        loop {
            let resources = WriterResources::default().with_max_preparation_bytes(limit);
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            settings.quick_open = true;
            let mut output = Vec::new();
            match write_archive(&entries, settings, &resources, &mut output) {
                Ok(()) => {
                    assert!(!output.is_empty());
                    break;
                }
                Err(error) => match error.root_cause() {
                    Error::WriterPreparationLimitExceeded {
                        limit: actual_limit,
                        required,
                        ..
                    } => {
                        assert_eq!(*actual_limit, limit);
                        assert!(*required > limit);
                        refusals += 1;
                        drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                        limit = *required;
                        assert!(limit < 64 * 1024, "tiny archive used too much preparation");
                    }
                    _ => panic!("unexpected preparation failure: {error}"),
                },
            }
        }
        assert!(refusals > 3, "the test must cross several admission sites");
    }

    #[test]
    fn volume_preparation_refusals_release_capacity_at_each_boundary() {
        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let mut limit = 0;
        let mut refusals = 0;
        loop {
            let resources = WriterResources::default().with_max_preparation_bytes(limit);
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            let mut volumes = super::super::CollectedVolumes::new();
            match write_volumes(&entries, settings, 4096, &mut volumes, &resources) {
                Ok(()) => {
                    assert_eq!(volumes.take().len(), 1);
                    break;
                }
                Err(error) => match error.root_cause() {
                    Error::WriterPreparationLimitExceeded {
                        limit: actual_limit,
                        required,
                        ..
                    } => {
                        assert_eq!(*actual_limit, limit);
                        assert!(*required > limit);
                        refusals += 1;
                        drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                        limit = *required;
                        assert!(
                            limit < 1024 * 1024,
                            "tiny volumes used {limit} bytes of preparation"
                        );
                    }
                    _ => panic!("unexpected preparation failure: {error}"),
                },
            }
        }
        assert!(refusals > 3, "the test must cross several admission sites");
    }

    #[test]
    fn encrypted_archive_preparation_refusals_release_capacity() {
        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )
        .with_password(b"secret")];
        let mut limit = 0;
        let mut refusals = 0;
        loop {
            let resources = WriterResources::default().with_max_preparation_bytes(limit);
            let mut settings = plan(true);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            let mut output = Vec::new();
            match write_archive(&entries, settings, &resources, &mut output) {
                Ok(()) => {
                    assert!(!output.is_empty());
                    break;
                }
                Err(error) => match error.root_cause() {
                    Error::WriterPreparationLimitExceeded { required, .. } => {
                        assert!(*required > limit);
                        refusals += 1;
                        drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                        limit = *required;
                        assert!(
                            limit < 64 * 1024,
                            "encrypted archive used too much preparation"
                        );
                    }
                    _ => panic!("unexpected preparation failure: {error}"),
                },
            }
        }
        assert!(refusals > 3);
    }

    #[test]
    fn oversized_archive_metadata_is_refused_during_layout_before_output() {
        let name = vec![b'm'; 4096];
        let mut settings = plan(false);
        settings.archive_comment = None;
        settings.recovery_percent = None;
        settings.archive_metadata = Some(super::super::ArchiveMetadataEntry {
            name: Some(&name),
            creation_time: Some(1),
        });
        let resources = WriterResources::default().with_max_preparation_bytes(128);
        let mut output = Vec::new();
        let error = write_archive(&[], settings, &resources, &mut output).unwrap_err();
        assert!(matches!(
            error,
            Error::WriterPreparationLimitExceeded { limit: 128, .. }
        ));
        assert!(output.is_empty());
        drop(Records::<u8>::new(128, &resources).unwrap());
    }

    #[test]
    fn archive_service_preparation_failure_preserves_member_context() {
        for encrypted in [false, true] {
            let mut service = super::super::ServiceEntry::new(b"CMT", b"note");
            if encrypted {
                service = service.with_password(b"secret");
            }
            let mut entry = ArchiveEntry::new(
                b"member".to_vec(),
                crate::EntrySource::from_bytes(b"payload".to_vec()),
            );
            for _ in 0..8 {
                entry = entry.with_service(service.clone());
            }
            let mut limit = 0;
            let mut service_refused = false;
            loop {
                let mut settings = plan(false);
                settings.archive_comment = None;
                settings.recovery_percent = None;
                let resources = WriterResources::default().with_max_preparation_bytes(limit);
                let mut output = Vec::new();
                let result = write_archive(
                    std::slice::from_ref(&entry),
                    settings,
                    &resources,
                    &mut output,
                );
                assert_eq!(resources.workspace_in_use(), 0);
                drop(Records::<u8>::new(limit as usize, &resources).unwrap());
                match result {
                    Ok(()) => {
                        assert!(!output.is_empty());
                        assert!(service_refused);
                        break;
                    }
                    Err(error) => {
                        assert!(output.is_empty());
                        let Error::WriterPreparationLimitExceeded {
                            required,
                            limit: actual,
                            ..
                        } = error.root_cause()
                        else {
                            panic!("unexpected preparation failure: {error}");
                        };
                        assert_eq!(*actual, limit);
                        assert!(*required > limit);
                        service_refused |= error.entry_context()
                            == Some((b"member".as_slice(), "preparing service"));
                        limit = *required;
                        assert!(limit < 64 * 1024);
                    }
                }
            }
        }
    }

    #[test]
    fn encrypted_service_rejects_oversized_name_after_extra_preparation() {
        let name = vec![b'n'; 4096];
        let resources = WriterResources::default().with_max_preparation_bytes(512);
        let error = encrypted_service_block(&name, b"payload", &[], b"secret", None, &resources)
            .err()
            .expect("the service name exceeds the preparation quota");
        assert!(matches!(
            error,
            Error::WriterPreparationLimitExceeded { limit: 512, .. }
        ));
        drop(Records::<u8>::new(512, &resources).unwrap());
    }

    #[test]
    fn archive_releases_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<Vec<u8>> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            settings.quick_open = true;
            let mut output = Vec::new();
            write_archive(&entries, settings, resources, &mut output)?;
            Ok(output)
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert!(!run(&resources).unwrap().is_empty());
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(count < 200, "unexpectedly many preparation admissions");
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    fn volumes_release_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<usize> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            settings.recovery_percent = None;
            let mut volumes = super::super::CollectedVolumes::new();
            write_volumes(&entries, settings, 4096, &mut volumes, resources)?;
            Ok(volumes.take().len())
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert_eq!(run(&resources).unwrap(), 1);
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(count < 200, "unexpectedly many preparation admissions");
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    fn recovery_releases_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<Vec<u8>> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            let mut output = Vec::new();
            write_archive(&entries, settings, resources, &mut output)?;
            Ok(output)
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert!(!run(&resources).unwrap().is_empty());
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(count < 200, "unexpectedly many preparation admissions");
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    fn volume_recovery_releases_preparation_for_each_injected_admission_failure() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )];
        let run = |resources: &WriterResources| -> Result<usize> {
            let mut settings = plan(false);
            settings.compress.method = 0;
            let mut volumes = super::super::CollectedVolumes::new();
            write_volumes(&entries, settings, 4096, &mut volumes, resources)?;
            Ok(volumes.take().len())
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        assert!(run(&resources).unwrap() > 0);
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 10);
        assert!(count < 200, "unexpectedly many preparation admissions");
        assert_eq!(resources.preparation_in_use(), 0);

        for index in 0..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    fn encrypted_outputs_release_late_preparation_refusals() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )
        .with_password(b"secret")];
        for volumes in [false, true] {
            let run = |resources: &WriterResources| -> Result<()> {
                let mut settings = plan(true);
                settings.compress.method = 0;
                settings.recovery_percent = None;
                settings.archive_comment = None;
                if volumes {
                    write_volumes(
                        &entries,
                        settings,
                        4096,
                        &mut super::super::CollectedVolumes::new(),
                        resources,
                    )
                } else {
                    write_archive(&entries, settings, resources, &mut Vec::new())
                }
            };
            let (resources, attempts) =
                WriterResources::default().refuse_preparation_growth_at(usize::MAX);
            run(&resources).unwrap();
            let count = attempts.load(Ordering::Relaxed);
            assert!(count > 3);
            assert!(count < 200);
            assert_eq!(resources.preparation_in_use(), 0);

            for index in count - 3..count {
                let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
                let error = run(&resources).unwrap_err();
                assert_eq!(
                    error.root_cause(),
                    &Error::WriterFailure("injected preparation admission failure"),
                    "volume mode {volumes}, admission {index}"
                );
                assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
            }
        }
    }

    #[test]
    fn encrypted_recovery_releases_late_preparation_refusals() {
        use std::sync::atomic::Ordering;

        let entries = [ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(b"contents".to_vec()),
        )
        .with_password(b"secret")];
        let run = |resources: &WriterResources| -> Result<()> {
            let mut settings = plan(true);
            settings.compress.method = 0;
            settings.archive_comment = None;
            write_archive(&entries, settings, resources, &mut Vec::new())
        };
        let (resources, attempts) =
            WriterResources::default().refuse_preparation_growth_at(usize::MAX);
        run(&resources).unwrap();
        let count = attempts.load(Ordering::Relaxed);
        assert!(count > 5);
        assert_eq!(resources.preparation_in_use(), 0);

        for index in count - 5..count {
            let (resources, _) = WriterResources::default().refuse_preparation_growth_at(index);
            let error = run(&resources).unwrap_err();
            assert_eq!(
                error.root_cause(),
                &Error::WriterFailure("injected preparation admission failure"),
                "admission {index}"
            );
            assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
        }
    }

    #[test]
    fn encrypted_volume_reread_failure_keeps_member_context() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let opens = Arc::new(AtomicUsize::new(0));
        let source = crate::EntrySource::from_opener(8, {
            let opens = opens.clone();
            move || {
                if opens.fetch_add(1, Ordering::Relaxed) == 0 {
                    Ok(Box::new(std::io::Cursor::new(b"contents".to_vec())))
                } else {
                    Err(std::io::Error::other("injected encrypted reread failure").into())
                }
            }
        });
        let entries = [ArchiveEntry::new(b"payload".to_vec(), source).with_password(b"secret")];
        let mut settings = plan(false);
        settings.compress.method = 0;
        settings.archive_comment = None;
        settings.recovery_percent = None;
        let mut volumes = super::super::CollectedVolumes::new();
        let error = write_volumes(
            &entries,
            settings,
            4096,
            &mut volumes,
            &WriterResources::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(
            error.entry_context(),
            Some((b"payload".as_slice(), "preparing volume payload"))
        );
        assert_eq!(opens.load(Ordering::Relaxed), 2);
        assert!(volumes.take().is_empty());
    }

    #[test]
    fn encrypted_compressed_volume_payload_propagates_spool_refusal() {
        let scratch = crate::scratch::case("encrypted-volume-spool-refusal");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let entry = ArchiveEntry::new(
            b"payload".to_vec(),
            crate::EntrySource::from_bytes(vec![b'A'; 64 * 1024]),
        )
        .with_password(b"secret");
        let mut settings = plan(false);
        settings.compress.method = 1;
        settings.recovery_percent = None;
        let member = compress::compress_members_reporting(
            std::slice::from_ref(&entry.source),
            settings.compress.clone(),
            &resources,
            &|_| true,
        )
        .unwrap()
        .remove(0);
        assert!(!member.store);

        let constrained = resources.clone().with_max_spool_bytes(0);
        let error = prepare_volume_member(&entry, member, &settings, &constrained)
            .err()
            .expect("encrypted ciphertext must be charged to its spool");
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }
}
