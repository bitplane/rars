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
use super::{encrypt_reader_to, validate_file_entry, ArchiveEntry};
use crate::crypto::rar50::Rar50Keys;
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
    pub(super) progress: Option<ProgressReporter<'a>>,
}

/// A member with its framing settled: the header bytes are final and the
/// payload only has to be copied.
struct PreparedMember {
    header: Vec<u8>,
    payload: Payload,
    payload_len: u64,
}

enum Payload {
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
        validate_file_entry(&entry.name)?;
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
    let compressed = compress::compress_members(&sources, plan.compress, resources)?;

    let mut members = Vec::with_capacity(entries.len());
    for (entry, member) in entries.iter().zip(compressed) {
        members.push(prepare_member(entry, member, &plan, header_keys.as_ref())?);
    }

    let body_len = members.iter().try_fold(0u64, |total, member| {
        total
            .checked_add(member.header.len() as u64)
            .and_then(|value| value.checked_add(member.payload_len))
            .ok_or(Error::InvalidHeader("RAR 5 archive body size overflows"))
    })?;

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
        archive_metadata: None,
        body_len,
        quick_open_payload_len: None,
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

        sink.write_all(RAR50_SIGNATURE)?;
        sink.write_all(&head_crypt)?;
        match &header_keys {
            Some(keys) => sink.write_all(&encrypted_main_header_block(
                &keys.keys,
                main_flags,
                None,
                &layout.main_extra,
            )?)?,
            None => {
                let mut main = Vec::new();
                write_main_header(&mut main, main_flags, None, &layout.main_extra)?;
                sink.write_all(&main)?;
            }
        }

        for member in members {
            sink.write_all(&member.header)?;
            write_payload(member.payload, member.payload_len, &mut sink, resources)?;
        }
    }

    if let Some(recovery_percent) = plan.recovery_percent {
        let mirror = mirror.as_mut().expect("recovery mirrors the archive");
        debug_assert_eq!(layout.recovery_prefix_len, Some(mirror.len()));
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

/// Builds a member's final header and decides how its payload will be written.
fn prepare_member(
    entry: &ArchiveEntry,
    member: CompressedMember,
    plan: &EnginePlan<'_>,
    header_keys: Option<&HeaderEncryptionKeys>,
) -> Result<PreparedMember> {
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
            let keys = Rar50Keys::derive(password, salt, 0)
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

    Ok(PreparedMember {
        header,
        payload,
        payload_len,
    })
}

fn write_payload(
    payload: Payload,
    payload_len: u64,
    output: &mut dyn Write,
    resources: &WriterResources,
) -> Result<()> {
    match payload {
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
                Payload::Encrypted { .. } => Err(Error::InvalidHeader(
                    "RAR 5 payload cannot be encrypted twice",
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
) -> Result<()> {
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
    Ok(())
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
