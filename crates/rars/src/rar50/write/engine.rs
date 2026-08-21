//! Assembling a RAR 5 archive in bounded memory.
//!
//! Nothing here holds a member, or the archive, in memory. Members compress
//! into temporary files, and every block size is known before a byte is
//! written, so the archive streams out in one pass.
//!
//! The one thing that has to be read back is the recovery record, which is
//! parity over everything that precedes it. When one is requested the bytes
//! being written are mirrored into a temporary file, and the parity pass reads
//! that instead of the archive it just produced.

use super::compress::{self, CompressPlan, CompressedMember};
use super::headers::{
    block_header_image, encrypted_header_block, encrypted_main_header_block, file_specific,
    header_encryption_keys, header_encryption_password, stored_file_specific, write_end_header,
    write_extra_record, write_file_encryption_record, write_hash_record_with_value,
    write_head_crypt, write_main_header, write_vint, HeaderEncryptionKeys,
};
use super::layout::{resolve_layout, LayoutInputs};
use super::{encrypt_reader_to, ArchiveEntry};
use crate::crypto::rar50::{Rar50Keys, WRITE_KDF_COUNT_LOG};
use crate::detect::RAR50_SIGNATURE;
use crate::rar50::{
    FHEXTRA_SUBDATA, HEAD_END, HEAD_FILE, HEAD_SERVICE, HFL_DATA, HFL_EXTRA, MHFL_RECOVERY,
    MHFL_SOLID,
};
use crate::recovery::rar5::{
    build_streamed_inline_recovery, choose_recovery_memory_mode, plan_inline_recovery,
    ReadWriteSeek,
};
use crate::streaming::Spool;
use crate::write_progress::ProgressReporter;
use crate::{Error, Result, WriterResources};
use std::io::{Read, Write};

pub(super) struct EnginePlan<'a> {
    pub(super) compress: CompressPlan,
    pub(super) method: u8,
    pub(super) recovery_percent: Option<u64>,
    pub(super) header_encrypted: bool,
    pub(super) archive_comment: Option<ArchiveCommentPlan<'a>>,
    pub(super) archive_metadata: Option<crate::rar50::ArchiveMetadataEntry<'a>>,
    pub(super) quick_open: bool,
    pub(super) progress: Option<ProgressReporter<'a>>,
}

pub(super) enum ArchiveCommentPlan<'a> {
    Plain(&'a [u8]),
    Encrypted { data: &'a [u8], password: &'a [u8] },
}

/// A block with its framing settled: the header bytes are final and the
/// payload only has to be copied.
struct PreparedBlock {
    header: Vec<u8>,
    payload: Payload,
    payload_len: u64,
    /// Quick-open repeats the headers of members and plain comments so a
    /// reader can list an archive without walking it.
    quick_open_cached: bool,
}

impl PreparedBlock {
    fn len(&self) -> Result<u64> {
        (self.header.len() as u64)
            .checked_add(self.payload_len)
            .ok_or(Error::InvalidHeader("RAR 5 archive block size overflows"))
    }
}

enum Payload {
    /// Small enough to have been built in memory: comments and services.
    Inline(Vec<u8>),
    /// Copied straight from the source, which is re-read at write time.
    Stored(crate::EntrySource),
    Packed(Spool),
    /// Encrypted on the way out, so the ciphertext is never stored anywhere.
    Encrypted {
        plain: Box<Payload>,
        keys: Rar50Keys,
        iv: [u8; 16],
    },
}

pub(super) fn write_archive(
    entries: &[ArchiveEntry],
    plan: EnginePlan<'_>,
    resources: &WriterResources,
    output: &mut dyn Write,
) -> Result<()> {
    for entry in entries {
        super::validate_entry(entry)?;
    }

    let header_keys = if plan.header_encrypted {
        let password = header_encryption_password(
            entries.iter().filter_map(|entry| entry.password.as_deref()),
        )?;
        Some(header_encryption_keys(password)?)
    } else {
        None
    };

    let sources: Vec<_> = entries.iter().map(|entry| entry.source.clone()).collect();
    let total_input: u64 = sources
        .iter()
        .map(|source| source.len())
        .sum::<Result<u64>>()?;
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
    let compressed = compress::compress_members_reporting(
        &sources,
        plan.compress.clone(),
        resources,
        &mut |done| work.advance(done),
    )?;

    // Everything between the main header and the quick-open block, in order.
    let mut blocks: Vec<PreparedBlock> = Vec::with_capacity(entries.len() + 1);
    if let Some(comment) = &plan.archive_comment {
        blocks.push(prepare_comment(comment, header_keys.as_ref())?);
    }
    for (index, (entry, member)) in entries.iter().zip(compressed).enumerate() {
        work.entry_started(index, total_entries, &entry.name, member.input_size);
        let input_size = member.input_size;
        blocks.push(prepare_member(entry, member, &plan, header_keys.as_ref())?);
        for service in &entry.services {
            blocks.push(prepare_service(service, header_keys.as_ref())?);
        }
        work.entry_finished(index, total_entries, &entry.name, input_size);
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
            .ok_or(Error::InvalidHeader("RAR 5 archive body size overflows"))
    })?;

    // Quick-open stores how far back each cached header sits from the
    // quick-open block itself. Both move together when the prefix grows, so
    // the distances only need positions within the body.
    let quick_open_payload = if plan.quick_open {
        let mut payload = Vec::new();
        let mut offset = 0u64;
        for block in &blocks {
            if block.quick_open_cached {
                append_quick_open_entry(&mut payload, body_len - offset, &block.header)?;
            }
            offset += block.len()?;
        }
        Some(payload)
    } else {
        None
    };

    let head_crypt = match &header_keys {
        Some(keys) => {
            let mut block = Vec::new();
            write_head_crypt(&mut block, keys)?;
            block
        }
        None => Vec::new(),
    };

    let mut main_flags = 0;
    if plan.compress.solid {
        main_flags |= MHFL_SOLID;
    }
    if plan.recovery_percent.is_some() {
        main_flags |= MHFL_RECOVERY;
    }

    let layout = resolve_layout(&LayoutInputs {
        header_encrypted: plan.header_encrypted,
        head_crypt_len: head_crypt.len() as u64,
        main_flags,
        volume_number: None,
        archive_metadata: plan.archive_metadata,
        body_len,
        quick_open_payload_len: quick_open_payload
            .as_ref()
            .map(|payload| payload.len() as u64),
        recovery_percent: plan.recovery_percent,
    })?;

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
            Some(keys) => {
                encrypted_main_header_block(&keys.keys, main_flags, None, &layout.main_extra)?
            }
            None => {
                let mut main = Vec::new();
                write_main_header(&mut main, main_flags, None, &layout.main_extra)?;
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
            sink.write_all(&block.header)?;
            write_payload(block.payload, block.payload_len, &mut sink, resources)?;
        }

        if let Some(payload) = &quick_open_payload {
            let block = stored_service_block(b"QO", payload, &[], header_keys.as_ref())?;
            sink.write_all(&block.header)?;
            write_payload(block.payload, block.payload_len, &mut sink, resources)?;
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
        )?)?,
        None => {
            let mut end = Vec::new();
            write_end_header(&mut end, 0)?;
            output.write_all(&end)?;
        }
    }
    Ok(())
}

/// Appends one quick-open record: how far back the header sits, then the
/// header itself.
fn append_quick_open_entry(payload: &mut Vec<u8>, distance: u64, header: &[u8]) -> Result<()> {
    let mut body = Vec::new();
    write_vint(&mut body, 0);
    write_vint(&mut body, distance);
    write_vint(&mut body, header.len() as u64);
    body.extend_from_slice(header);

    payload.extend_from_slice(&crate::crc32::crc32(&body).to_le_bytes());
    write_vint(payload, body.len() as u64);
    payload.extend_from_slice(&body);
    Ok(())
}

/// A stored service block: a small named payload such as a comment or the
/// quick-open index.
fn stored_service_block(
    name: &[u8],
    data: &[u8],
    service_data: &[u8],
    header_keys: Option<&HeaderEncryptionKeys>,
) -> Result<PreparedBlock> {
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data);
    let specific = stored_file_specific(
        name,
        data.len() as u64,
        Some(crate::crc32::crc32(data)),
        0,
        None,
        0,
    )?;
    let header = match header_keys {
        Some(keys) => encrypted_header_block(
            &keys.keys,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(data.len() as u64),
            &specific,
            &extra,
            &[],
        )?,
        None => block_header_image(
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(data.len() as u64),
            &specific,
            &extra,
        )?,
    };
    Ok(PreparedBlock {
        header,
        payload: Payload::Inline(data.to_vec()),
        payload_len: data.len() as u64,
        quick_open_cached: false,
    })
}

fn prepare_comment(
    comment: &ArchiveCommentPlan<'_>,
    header_keys: Option<&HeaderEncryptionKeys>,
) -> Result<PreparedBlock> {
    match comment {
        ArchiveCommentPlan::Plain(data) => {
            let mut block = stored_service_block(b"CMT", data, &[], header_keys)?;
            // Plain comments are listed by quick-open; encrypted ones are not.
            block.quick_open_cached = header_keys.is_none();
            Ok(block)
        }
        ArchiveCommentPlan::Encrypted { data, password } => {
            encrypted_service_block(b"CMT", data, &[], password, header_keys)
        }
    }
}

fn prepare_service(
    service: &super::ServiceEntry,
    header_keys: Option<&HeaderEncryptionKeys>,
) -> Result<PreparedBlock> {
    match service.password.as_deref() {
        Some(password) => {
            encrypted_service_block(&service.name, &service.data, &[], password, header_keys)
        }
        None => stored_service_block(&service.name, &service.data, &[], header_keys),
    }
}

/// A service block whose payload is encrypted with its own password.
fn encrypted_service_block(
    name: &[u8],
    data: &[u8],
    service_data: &[u8],
    password: &[u8],
    header_keys: Option<&HeaderEncryptionKeys>,
) -> Result<PreparedBlock> {
    super::validate_nonempty_password(password)?;
    let encrypted = super::encrypted_stored_payload(data, password)?;

    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data);
    write_file_encryption_record(
        &mut extra,
        encrypted.salt,
        encrypted.iv,
        encrypted.check_value,
    );
    write_hash_record_with_value(&mut extra, encrypted.blake2sp_mac);
    let specific = stored_file_specific(
        name,
        data.len() as u64,
        Some(encrypted.crc32_mac),
        0,
        None,
        0,
    )?;
    let payload_len = encrypted.data.len() as u64;
    let header = match header_keys {
        Some(keys) => encrypted_header_block(
            &keys.keys,
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(payload_len),
            &specific,
            &extra,
            &[],
        )?,
        None => block_header_image(
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(payload_len),
            &specific,
            &extra,
        )?,
    };
    Ok(PreparedBlock {
        header,
        payload: Payload::Inline(encrypted.data),
        payload_len,
        quick_open_cached: false,
    })
}

/// Builds a member's final header and decides how its payload will be written.
fn prepare_member(
    entry: &ArchiveEntry,
    member: CompressedMember,
    plan: &EnginePlan<'_>,
    header_keys: Option<&HeaderEncryptionKeys>,
) -> Result<PreparedBlock> {
    let compression_info = compress::member_compression_info(&plan.compress, &member, plan.method)?;
    let plain_len = if member.store {
        member.input_size
    } else {
        member.packed.len()
    };
    let plain = if member.store {
        Payload::Stored(entry.source.clone())
    } else {
        Payload::Packed(member.packed)
    };

    let mut extra = Vec::new();
    let (payload, payload_len, data_crc32, hash) = match entry.password.as_deref() {
        Some(password) => {
            let mut salt = [0u8; 16];
            let mut iv = [0u8; 16];
            getrandom::fill(&mut salt).map_err(|_| {
                Error::InvalidHeader("RAR 5 writer could not generate encryption salt")
            })?;
            getrandom::fill(&mut iv).map_err(|_| {
                Error::InvalidHeader("RAR 5 writer could not generate encryption IV")
            })?;
            let keys = Rar50Keys::derive(password, salt, WRITE_KDF_COUNT_LOG)
                .map_err(crate::rar50::map_rar50_crypto_error)?;
            write_file_encryption_record(&mut extra, salt, iv, keys.password_check_record());
            let crc32 = keys.mac_crc32(member.crc32);
            let hash = keys.mac_hash32(member.hash);
            (
                Payload::Encrypted {
                    plain: Box::new(plain),
                    keys,
                    iv,
                },
                // Encryption pads the payload up to the cipher block size.
                plain_len.div_ceil(16) * 16,
                crc32,
                hash,
            )
        }
        None => (plain, plain_len, member.crc32, member.hash),
    };
    write_hash_record_with_value(&mut extra, hash);

    let specific = file_specific(
        &entry.name,
        member.input_size,
        Some(data_crc32),
        entry.attributes,
        entry.mtime,
        compression_info,
        entry.host_os,
    )?;
    let header = match header_keys {
        Some(keys) => encrypted_header_block(
            &keys.keys,
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(payload_len),
            &specific,
            &extra,
            &[],
        )?,
        None => block_header_image(
            HEAD_FILE,
            HFL_EXTRA | HFL_DATA,
            Some(payload_len),
            &specific,
            &extra,
        )?,
    };

    Ok(PreparedBlock {
        header,
        payload,
        payload_len,
        quick_open_cached: true,
    })
}

fn write_payload(
    payload: Payload,
    payload_len: u64,
    output: &mut dyn Write,
    resources: &WriterResources,
) -> Result<()> {
    match payload {
        Payload::Inline(data) => {
            output.write_all(&data)?;
            Ok(())
        }
        Payload::Stored(source) => {
            let mut reader = source.open()?;
            let copied = std::io::copy(&mut reader.by_ref().take(payload_len), output)?;
            if copied != payload_len {
                return Err(Error::InvalidHeader(
                    "entry source size changed while writing",
                ));
            }
            let mut trailing = [0u8; 1];
            if reader.read(&mut trailing)? != 0 {
                return Err(Error::InvalidHeader(
                    "entry source size changed while writing",
                ));
            }
            Ok(())
        }
        Payload::Packed(mut packed) => {
            packed.copy_to(output)?;
            Ok(())
        }
        Payload::Encrypted { plain, keys, iv } => {
            const ENCRYPT_CHUNK: usize = 64 * 1024;
            let _permit = resources.acquire(ENCRYPT_CHUNK as u64, 0)?;
            match *plain {
                Payload::Stored(source) => {
                    let mut reader = source.open()?;
                    let len = source.len()?;
                    encrypt_reader_to(&mut *reader, len, output, &keys, iv, ENCRYPT_CHUNK)
                }
                Payload::Packed(mut packed) => {
                    let len = packed.len();
                    packed.rewind()?;
                    encrypt_reader_to(&mut packed, len, output, &keys, iv, ENCRYPT_CHUNK)
                }
                // Inline payloads are encrypted where they are built, and
                // nothing is encrypted twice.
                Payload::Inline(_) | Payload::Encrypted { .. } => Err(Error::InvalidHeader(
                    "RAR 5 payload cannot be encrypted here",
                )),
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
    let prefix_len = prefix.len();
    let plan = plan_inline_recovery(prefix_len, recovery_percent)?;
    let (mode, required) = choose_recovery_memory_mode(plan, resources.memory_limit())?;
    let _permit = resources.acquire(required, 0)?;

    let mut scratch = match mode {
        crate::recovery::rar5::RecoveryMemoryMode::Striped { .. } => {
            Some(Spool::create(resources)?)
        }
        crate::recovery::rar5::RecoveryMemoryMode::Resident => None,
    };
    let mut payload = Spool::create(resources)?;
    prefix.rewind()?;
    let built = build_streamed_inline_recovery(
        prefix,
        prefix_len,
        recovery_percent,
        mode,
        scratch
            .as_mut()
            .map(|scratch| scratch as &mut dyn ReadWriteSeek),
        &mut payload,
        progress,
        1,
    )?;

    debug_assert_eq!(built.plan.payload_size(), Ok(built.payload_len));

    let mut service_data = Vec::new();
    write_vint(&mut service_data, recovery_percent);
    let mut extra = Vec::new();
    write_extra_record(&mut extra, FHEXTRA_SUBDATA, &service_data);
    let specific = stored_file_specific(
        b"RR",
        built.payload_len,
        Some(built.payload_crc32),
        0,
        None,
        0,
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
        )?,
        None => block_header_image(
            HEAD_SERVICE,
            HFL_EXTRA | HFL_DATA,
            Some(built.payload_len),
            &specific,
            &extra,
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
    Stored(crate::EntrySource),
}

impl FragmentSource {
    /// Checksums of the bytes a fragment will store, read ahead of writing them.
    ///
    /// The fragment's header carries these and the header goes out before the
    /// payload, so the range is read twice: once here and once to copy it. The
    /// alternative is patching the fields after the copy, which an encrypted
    /// header will not allow.
    fn checksums_range(&mut self, start: u64, len: u64) -> Result<FragmentChecksums> {
        let mut sink = ChecksumSink::default();
        self.copy_range(start, len, &mut sink)?;
        Ok(FragmentChecksums {
            crc32: sink.crc.finish(),
            hash: sink.hash.finalize(),
        })
    }

    fn copy_range(&mut self, start: u64, len: u64, output: &mut dyn Write) -> Result<()> {
        match self {
            Self::Packed(spool) => {
                spool.copy_range_to(start, len, output)?;
            }
            Self::Stored(source) => {
                let mut reader = source.open()?;
                reader.seek(std::io::SeekFrom::Start(start))?;
                let copied = std::io::copy(&mut reader.by_ref().take(len), output)?;
                if copied != len {
                    return Err(Error::InvalidHeader(
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
struct VolumeMember {
    name: Vec<u8>,
    mtime: Option<u32>,
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
        return Err(Error::InvalidHeader("RAR 5 volume payload size is zero"));
    }
    for entry in entries {
        super::validate_entry(entry)?;
    }

    let header_keys = if plan.header_encrypted {
        let password = header_encryption_password(
            entries.iter().filter_map(|entry| entry.password.as_deref()),
        )?;
        Some(header_encryption_keys(password)?)
    } else {
        None
    };

    let sources: Vec<_> = entries.iter().map(|entry| entry.source.clone()).collect();
    let total_input: u64 = sources
        .iter()
        .map(|source| source.len())
        .sum::<Result<u64>>()?;
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
    let compressed = compress::compress_members_reporting(
        &sources,
        plan.compress.clone(),
        resources,
        &mut |done| work.advance(done),
    )?;

    let mut members = Vec::with_capacity(entries.len());
    for (index, (entry, member)) in entries.iter().zip(compressed).enumerate() {
        work.entry_started(index, total_entries, &entry.name, member.input_size);
        let input_size = member.input_size;
        members.push(prepare_volume_member(entry, member, &plan, resources)?);
        work.entry_finished(index, total_entries, &entry.name, input_size);
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
        writer.write_member(&mut member)?;
    }
    writer.finish()
}

/// Compresses and, if needed, encrypts one member into a form that can be cut
/// at any byte boundary.
fn prepare_volume_member(
    entry: &ArchiveEntry,
    member: CompressedMember,
    plan: &EnginePlan<'_>,
    resources: &WriterResources,
) -> Result<VolumeMember> {
    let compression_info = compress::member_compression_info(&plan.compress, &member, plan.method)?;
    let plain_len = if member.store {
        member.input_size
    } else {
        member.packed.len()
    };

    match entry.password.as_deref() {
        Some(password) => {
            let mut salt = [0u8; 16];
            let mut iv = [0u8; 16];
            getrandom::fill(&mut salt).map_err(|_| {
                Error::InvalidHeader("RAR 5 writer could not generate encryption salt")
            })?;
            getrandom::fill(&mut iv).map_err(|_| {
                Error::InvalidHeader("RAR 5 writer could not generate encryption IV")
            })?;
            let keys = Rar50Keys::derive(password, salt, WRITE_KDF_COUNT_LOG)
                .map_err(crate::rar50::map_rar50_crypto_error)?;

            // A volume boundary can fall anywhere, and the cipher runs as one
            // chain over the member, so encrypt it up front into scratch
            // storage and slice the ciphertext.
            let mut encrypted = Spool::create(resources)?;
            const ENCRYPT_CHUNK: usize = 64 * 1024;
            let _permit = resources.acquire(ENCRYPT_CHUNK as u64, 0)?;
            if member.store {
                let mut reader = entry.source.open()?;
                encrypt_reader_to(
                    &mut *reader,
                    plain_len,
                    &mut encrypted,
                    &keys,
                    iv,
                    ENCRYPT_CHUNK,
                )?;
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
                )?;
            }
            let payload_len = encrypted.len();
            Ok(VolumeMember {
                name: entry.name.clone(),
                mtime: entry.mtime,
                attributes: entry.attributes,
                host_os: entry.host_os,
                unpacked_size: member.input_size,
                crc32: keys.mac_crc32(member.crc32),
                hash: keys.mac_hash32(member.hash),
                compression_info,
                payload_len,
                source: FragmentSource::Packed(encrypted),
                encryption: Some((salt, iv, keys.password_check_record())),
            })
        }
        None => Ok(VolumeMember {
            name: entry.name.clone(),
            mtime: entry.mtime,
            attributes: entry.attributes,
            host_os: entry.host_os,
            unpacked_size: member.input_size,
            crc32: member.crc32,
            hash: member.hash,
            compression_info,
            payload_len: plain_len,
            source: if member.store {
                FragmentSource::Stored(entry.source.clone())
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
                true => Some(member.source.checksums_range(start, fragment_len)?),
                false => None,
            };

            let header = fragment_header(
                member,
                fragment_len,
                split_before,
                fragment_checksums,
                self.header_keys,
            )?;
            let body = self.body.as_mut().expect("volume started");
            body.write_all(&header)?;
            if fragment_len != 0 {
                member.source.copy_range(start, fragment_len, body)?;
            }

            self.payload_in_volume += fragment_len;
            start += fragment_len;
            split_before = true;

            if start >= member.payload_len {
                return Ok(());
            }
        }
    }

    fn finish(mut self) -> Result<()> {
        if self.body.is_some() {
            self.finish_volume(false)?;
        }
        Ok(())
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
                let mut block = Vec::new();
                write_head_crypt(&mut block, keys)?;
                block
            }
            None => Vec::new(),
        };

        let mut main_flags = crate::rar50::MHFL_VOLUME | crate::rar50::MHFL_VOLUME_NUMBER;
        if self.solid {
            main_flags |= MHFL_SOLID;
        }
        if self.recovery_percent.is_some() {
            main_flags |= MHFL_RECOVERY;
        }

        let layout = resolve_layout(&LayoutInputs {
            header_encrypted: self.header_keys.is_some(),
            head_crypt_len: head_crypt.len() as u64,
            main_flags,
            volume_number: Some(volume_number),
            archive_metadata: None,
            body_len: body.len(),
            quick_open_payload_len: None,
            recovery_percent: self.recovery_percent,
        })?;

        let mut output = self.sink.start_volume(volume_number)?;
        let mut mirror = match self.recovery_percent {
            Some(_) => Some(Spool::create(self.resources)?),
            None => None,
        };
        let mut written;
        {
            let mut tee = Tee {
                output: &mut *output,
                mirror: mirror.as_mut(),
            };
            let main = match self.header_keys {
                Some(keys) => encrypted_main_header_block(
                    &keys.keys,
                    main_flags,
                    Some(volume_number),
                    &layout.main_extra,
                )?,
                None => {
                    let mut main = Vec::new();
                    write_main_header(
                        &mut main,
                        main_flags,
                        Some(volume_number),
                        &layout.main_extra,
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
                &mut *output,
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
            )?,
            None => {
                let mut end = Vec::new();
                write_end_header(&mut end, end_flags)?;
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
) -> Result<Vec<u8>> {
    let split_after = fragment.is_some();
    let mut extra = Vec::new();
    if let Some((salt, iv, check_value)) = member.encryption {
        write_file_encryption_record(&mut extra, salt, iv, check_value);
    }
    write_hash_record_with_value(&mut extra, fragment.map_or(member.hash, |f| f.hash));
    let specific = file_specific(
        &member.name,
        member.unpacked_size,
        Some(fragment.map_or(member.crc32, |f| f.crc32)),
        member.attributes,
        member.mtime,
        member.compression_info,
        member.host_os,
    )?;

    let mut flags = HFL_DATA;
    if split_before {
        flags |= crate::rar50::HFL_SPLIT_BEFORE;
    }
    if split_after {
        flags |= crate::rar50::HFL_SPLIT_AFTER;
    }
    if !extra.is_empty() {
        flags |= HFL_EXTRA;
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
        ),
        None => block_header_image(HEAD_FILE, flags, Some(fragment_len), &specific, &extra),
    }
}
