//! Pure RAR 5 header serialization.
//!
//! Everything here is a deterministic function of its arguments: given the
//! same inputs it produces the same bytes, with no I/O and no writer state.
//! That is what lets the layout resolver predict block sizes before any bytes
//! are emitted.

use super::ArchiveMetadataEntry;
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys, WRITE_KDF_COUNT_LOG};
use crate::rar50::{
    map_rar50_crypto_error, FHEXTRA_CRYPT, FHEXTRA_HASH, FHFL_CRC32, FHFL_DIRECTORY, FHFL_MTIME,
    HEAD_CRYPT, HEAD_END, HEAD_MAIN, HFL_EXTRA, MHEXTRA_ARCHIVE_METADATA,
    MHEXTRA_ARCHIVE_METADATA_NAME, MHEXTRA_ARCHIVE_METADATA_TIME, MHEXTRA_LOCATOR,
    MHEXTRA_LOCATOR_QUICK_OPEN, MHEXTRA_LOCATOR_RECOVERY,
};
use crate::{crc32::crc32, Error, Result};

pub(super) fn write_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(super) fn write_extra_record(out: &mut Vec<u8>, record_type: u64, data: &[u8]) {
    let mut body = Vec::new();
    write_vint(&mut body, record_type);
    body.extend_from_slice(data);
    write_vint(out, body.len() as u64);
    out.extend_from_slice(&body);
}

pub(super) fn write_hash_record_with_value(out: &mut Vec<u8>, hash: [u8; 32]) {
    let mut record = Vec::new();
    write_vint(&mut record, 0);
    record.extend_from_slice(&hash);
    write_extra_record(out, FHEXTRA_HASH, &record);
}

pub(super) fn write_file_encryption_record(
    out: &mut Vec<u8>,
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
) {
    let mut record = Vec::new();
    write_vint(&mut record, 0);
    write_vint(&mut record, 0x0003);
    record.push(WRITE_KDF_COUNT_LOG);
    record.extend_from_slice(&salt);
    record.extend_from_slice(&iv);
    record.extend_from_slice(&check_value);
    write_extra_record(out, FHEXTRA_CRYPT, &record);
}

pub(super) fn block_header_image(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    write_vint(&mut body, header_type);
    write_vint(&mut body, flags);
    if flags & HFL_EXTRA != 0 {
        write_vint(&mut body, extra.len() as u64);
    }
    if let Some(data_size) = data_size {
        write_vint(&mut body, data_size);
    }
    body.extend_from_slice(type_specific);
    body.extend_from_slice(extra);

    let mut header_size = Vec::new();
    write_vint(&mut header_size, body.len() as u64);

    let mut header = Vec::with_capacity(4 + header_size.len() + body.len());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&header_size);
    header.extend_from_slice(&body);
    let header_crc = crc32(&header[4..]);
    header[..4].copy_from_slice(&header_crc.to_le_bytes());
    Ok(header)
}

pub(super) fn write_block(
    out: &mut Vec<u8>,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Result<()> {
    let header = block_header_image(header_type, flags, data_size, type_specific, extra)?;
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    Ok(())
}

/// Encrypts a header block under `keys`, returning `iv || ciphertext || data`.
///
/// Each block gets its own IV and its own CBC chain, so headers can be built
/// and emitted one at a time without any cross-block state.
pub(crate) fn encrypted_header_block(
    keys: &Rar50Keys,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let header = block_header_image(header_type, flags, data_size, type_specific, extra)?;
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption IV"))?;
    let padded_len = header.len().checked_add(15).ok_or(Error::InvalidHeader(
        "RAR 5 encrypted header size overflows",
    ))? & !15;
    let mut encrypted_header = header;
    encrypted_header.resize(padded_len, 0);
    Rar50Cipher::new(keys.key, iv)
        .encrypt_in_place(&mut encrypted_header)
        .map_err(map_rar50_crypto_error)?;
    let mut out = Vec::with_capacity(16 + encrypted_header.len() + data.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&encrypted_header);
    out.extend_from_slice(data);
    Ok(out)
}

pub(super) fn stored_file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    host_os: u64,
) -> Result<Vec<u8>> {
    file_specific(
        name,
        unpacked_size,
        data_crc32,
        attributes,
        mtime,
        0,
        host_os,
        false,
    )
}

// Keep the on-disk file header fields explicit at this serialization boundary.
#[allow(clippy::too_many_arguments)]
pub(super) fn file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    compression_info: u64,
    host_os: u64,
    is_directory: bool,
) -> Result<Vec<u8>> {
    if name.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 file name is empty"));
    }
    let mut file_flags = if data_crc32.is_some() { FHFL_CRC32 } else { 0 };
    if is_directory {
        file_flags |= FHFL_DIRECTORY;
    }
    if mtime.is_some() {
        file_flags |= FHFL_MTIME;
    }

    let mut specific = Vec::new();
    write_vint(&mut specific, file_flags);
    write_vint(&mut specific, unpacked_size);
    write_vint(&mut specific, attributes);
    if let Some(mtime) = mtime {
        specific.extend_from_slice(&mtime.to_le_bytes());
    }
    if let Some(data_crc32) = data_crc32 {
        specific.extend_from_slice(&data_crc32.to_le_bytes());
    }
    write_vint(&mut specific, compression_info);
    write_vint(&mut specific, host_os);
    write_vint(&mut specific, name.len() as u64);
    specific.extend_from_slice(name);
    Ok(specific)
}

pub(super) fn write_mtime_record(extra: &mut Vec<u8>, seconds: Option<u32>, nanos: Option<u32>) {
    if let (Some(seconds), Some(nanos)) = (seconds, nanos) {
        // Unix time + mtime + nanoseconds. Emit the complete timestamp here,
        // with no base-header time competing with the higher precision record.
        let mut record = vec![0x13];
        record.extend_from_slice(&seconds.to_le_bytes());
        record.extend_from_slice(&nanos.to_le_bytes());
        write_extra_record(extra, super::super::FHEXTRA_HTIME, &record);
    }
}

pub(super) fn archive_metadata_record(metadata: ArchiveMetadataEntry<'_>) -> Result<Vec<u8>> {
    if metadata.name.is_none() && metadata.creation_time.is_none() {
        return Err(Error::InvalidHeader(
            "RAR 5 archive metadata writer needs a name or creation time",
        ));
    }
    if metadata.name.is_some() && metadata.creation_time.is_none() {
        return Err(Error::InvalidHeader(
            "RAR 5 archive metadata name needs a creation time",
        ));
    }
    let mut flags = 0;
    if metadata.name.is_some() {
        flags |= MHEXTRA_ARCHIVE_METADATA_NAME;
    }
    if metadata.creation_time.is_some() {
        flags |= MHEXTRA_ARCHIVE_METADATA_TIME;
    }

    let mut record = Vec::new();
    write_vint(&mut record, flags);
    if let Some(name) = metadata.name {
        if name.is_empty() {
            return Err(Error::InvalidHeader("RAR 5 archive metadata name is empty"));
        }
        write_vint(&mut record, name.len() as u64);
        record.extend_from_slice(name);
    }
    if let Some(creation_time) = metadata.creation_time {
        record.extend_from_slice(&creation_time.to_le_bytes());
    }

    let mut extra = Vec::new();
    write_extra_record(&mut extra, MHEXTRA_ARCHIVE_METADATA, &record);
    Ok(extra)
}

pub(super) fn write_locator_record(
    out: &mut Vec<u8>,
    quick_open_offset: Option<u64>,
    recovery_record_offset: Option<u64>,
) {
    let mut flags = 0;
    if quick_open_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_QUICK_OPEN;
    }
    if recovery_record_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_RECOVERY;
    }

    let mut record = Vec::new();
    write_vint(&mut record, flags);
    if let Some(quick_open_offset) = quick_open_offset {
        write_vint(&mut record, quick_open_offset);
    }
    if let Some(recovery_record_offset) = recovery_record_offset {
        write_vint(&mut record, recovery_record_offset);
    }
    write_extra_record(out, MHEXTRA_LOCATOR, &record);
}

pub(super) fn resolved_main_extra(
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
    quick_open_offset: Option<u64>,
    recovery_offset: Option<u64>,
) -> Result<Vec<u8>> {
    let mut main_extra = Vec::new();
    let locator_quick_open_offset = quick_open_offset.or_else(|| archive_metadata.map(|_| 0));
    if locator_quick_open_offset.is_some() || recovery_offset.is_some() {
        write_locator_record(&mut main_extra, locator_quick_open_offset, recovery_offset);
    }
    if let Some(archive_metadata) = archive_metadata {
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata)?);
    }
    Ok(main_extra)
}

pub(super) fn write_main_header(
    out: &mut Vec<u8>,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
) -> Result<()> {
    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if let Some(volume_number) = volume_number {
        write_vint(&mut specific, volume_number);
    }
    write_block(
        out,
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        &specific,
        extra,
        &[],
    )
}

pub(super) fn encrypted_main_header_block(
    keys: &Rar50Keys,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
) -> Result<Vec<u8>> {
    let mut specific = Vec::new();
    write_vint(&mut specific, archive_flags);
    if let Some(volume_number) = volume_number {
        write_vint(&mut specific, volume_number);
    }
    encrypted_header_block(
        keys,
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        &specific,
        extra,
        &[],
    )
}

pub(crate) struct HeaderEncryptionKeys {
    pub(super) keys: Rar50Keys,
    pub(super) salt: [u8; 16],
}

pub(super) fn header_encryption_keys(password: &[u8]) -> Result<HeaderEncryptionKeys> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|_| Error::InvalidHeader("RAR 5 writer could not generate encryption salt"))?;
    let keys =
        Rar50Keys::derive(password, salt, WRITE_KDF_COUNT_LOG).map_err(map_rar50_crypto_error)?;
    Ok(HeaderEncryptionKeys { keys, salt })
}

/// Header encryption covers the whole archive, so every member, service and
/// comment has to be locked with the same password.
pub(super) fn header_encryption_password<'a>(
    mut passwords: impl Iterator<Item = &'a [u8]>,
) -> Result<&'a [u8]> {
    let first = passwords.next().ok_or(Error::NeedPassword)?;
    for password in passwords {
        if password != first {
            return Err(Error::InvalidHeader(
                "RAR 5 header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

pub(super) fn write_head_crypt(
    out: &mut Vec<u8>,
    header_keys: &HeaderEncryptionKeys,
) -> Result<()> {
    let mut specific = Vec::new();
    write_vint(&mut specific, 0);
    write_vint(&mut specific, 0x0001);
    specific.push(WRITE_KDF_COUNT_LOG);
    specific.extend_from_slice(&header_keys.salt);
    specific.extend_from_slice(&header_keys.keys.password_check_record());
    write_block(out, HEAD_CRYPT, 0, None, &specific, &[], &[])
}

pub(crate) fn write_end_header(out: &mut Vec<u8>, end_flags: u64) -> Result<()> {
    write_block(
        out,
        HEAD_END,
        0,
        None,
        &end_header_specific(end_flags),
        &[],
        &[],
    )
}

pub(crate) fn end_header_specific(end_flags: u64) -> Vec<u8> {
    let mut specific = Vec::new();
    write_vint(&mut specific, end_flags);
    specific
}
