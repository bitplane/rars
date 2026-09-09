//! RAR 5 header serialization.
//!
//! Plain header encodings and lengths depend only on their inputs, letting the
//! layout resolver predict positions before emission. Encrypted headers obtain
//! fresh IVs. Prepared images additionally reserve their allocation capacity
//! against the writer resource policy.

use super::ArchiveMetadataEntry;
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys, WRITE_KDF_COUNT_LOG};
use crate::rar50::{
    map_rar50_crypto_error, FHEXTRA_CRYPT, FHEXTRA_HASH, FHFL_CRC32, FHFL_DIRECTORY, FHFL_MTIME,
    HEAD_CRYPT, HEAD_END, HEAD_MAIN, HFL_EXTRA, MHEXTRA_ARCHIVE_METADATA,
    MHEXTRA_ARCHIVE_METADATA_NAME, MHEXTRA_ARCHIVE_METADATA_TIME, MHEXTRA_LOCATOR,
    MHEXTRA_LOCATOR_QUICK_OPEN, MHEXTRA_LOCATOR_RECOVERY,
};
use crate::streaming::preparation::Bytes;
use crate::WriterResources;
use crate::{crc32::crc32, Error, Result};

/// Bounded framing scratch; callers choose capacities from the on-disk fields.
pub(crate) struct HeaderScratch<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> HeaderScratch<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }
    fn vint(&mut self, mut value: u64) {
        loop {
            self.extend_from_slice(&[(value as u8 & 0x7f) | if value >= 0x80 { 0x80 } else { 0 }]);
            value >>= 7;
            if value == 0 {
                break;
            }
        }
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn len(&self) -> usize {
        self.len
    }
}

impl<const N: usize> std::ops::Deref for HeaderScratch<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub(crate) trait HeaderOutput {
    fn append(&mut self, bytes: &[u8]) -> Result<()>;
    fn vint(&mut self, value: u64) -> Result<()>;
}
impl HeaderOutput for Bytes {
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes)
    }
    fn vint(&mut self, value: u64) -> Result<()> {
        self.vint(value)
    }
}
#[cfg(test)]
impl HeaderOutput for Vec<u8> {
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
    fn vint(&mut self, value: u64) -> Result<()> {
        write_vint(self, value);
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn write_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(super) fn write_extra_record(
    out: &mut impl HeaderOutput,
    record_type: u64,
    data: &[u8],
) -> Result<()> {
    let mut kind = HeaderScratch::<10>::new();
    kind.vint(record_type);
    // A slice length is at most isize::MAX, so adding a ten-byte vint fits u64.
    out.vint(data.len() as u64 + kind.len() as u64)?;
    out.append(kind.as_slice())?;
    out.append(data)?;

    Ok(())
}

pub(super) fn write_hash_record_with_value(
    out: &mut impl HeaderOutput,
    hash: [u8; 32],
) -> Result<()> {
    let mut record = HeaderScratch::<33>::new();
    record.vint(0);
    record.extend_from_slice(&hash);
    write_extra_record(out, FHEXTRA_HASH, record.as_slice())?;

    Ok(())
}

pub(super) fn write_file_encryption_record(
    out: &mut impl HeaderOutput,
    salt: [u8; 16],
    iv: [u8; 16],
    check_value: [u8; 12],
) -> Result<()> {
    let mut record = HeaderScratch::<47>::new();
    record.vint(0);
    record.vint(0x0003);
    record.extend_from_slice(&[WRITE_KDF_COUNT_LOG]);
    record.extend_from_slice(&salt);
    record.extend_from_slice(&iv);
    record.extend_from_slice(&check_value);
    write_extra_record(out, FHEXTRA_CRYPT, record.as_slice())?;

    Ok(())
}

fn image_size_error() -> Error {
    Error::InvalidArgument("RAR 5 header size overflows")
}

fn checked_image_len(parts: &[usize]) -> Result<usize> {
    let len = parts
        .iter()
        .try_fold(0usize, |total, &size| total.checked_add(size))
        .ok_or_else(image_size_error)?;
    if len > isize::MAX as usize {
        return Err(image_size_error());
    }
    Ok(len)
}

fn join_record(parts: &[&[u8]], resources: &WriterResources) -> Result<Bytes> {
    let len = parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(part.len()))
        .ok_or_else(image_size_error)?;
    let mut out = Bytes::zeroed(checked_image_len(&[len])?, resources)?;
    let mut offset = 0;
    for part in parts {
        out[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    Ok(out)
}

/// Computes framing without copying variable-length fields. All header paths
/// render into their final allocation, including IV, padding and trailing data.
struct HeaderImage<'a> {
    prefix: HeaderScratch<40>,
    size: HeaderScratch<10>,
    specific: &'a [u8],
    extra: &'a [u8],
    plain_len: usize,
}

impl<'a> HeaderImage<'a> {
    fn new(
        kind: u64,
        flags: u64,
        data_size: Option<u64>,
        specific: &'a [u8],
        extra: &'a [u8],
    ) -> Result<Self> {
        let mut prefix = HeaderScratch::new();
        prefix.vint(kind);
        prefix.vint(flags);
        if flags & HFL_EXTRA != 0 {
            prefix.vint(extra.len() as u64);
        }
        if let Some(data_size) = data_size {
            prefix.vint(data_size);
        }
        let body_len = checked_image_len(&[prefix.len(), specific.len(), extra.len()])?;
        let mut size = HeaderScratch::new();
        size.vint(body_len as u64);
        let plain_len = checked_image_len(&[4, size.len(), body_len])?;
        Ok(Self {
            prefix,
            size,
            specific,
            extra,
            plain_len,
        })
    }

    fn header_len(&self, encrypted: bool) -> Result<usize> {
        if encrypted {
            let padded = self
                .plain_len
                .checked_add(15)
                .ok_or_else(image_size_error)?
                & !15;
            checked_image_len(&[16, padded])
        } else {
            Ok(self.plain_len)
        }
    }

    fn render(
        &self,
        keys: Option<&Rar50Keys>,
        data: &[u8],
        resources: &WriterResources,
    ) -> Result<Bytes> {
        let header_len = self.header_len(keys.is_some())?;
        let mut out = Bytes::zeroed(checked_image_len(&[header_len, data.len()])?, resources)?;
        let start = if keys.is_some() { 16 } else { 0 };
        let mut offset = start + 4;
        for part in [
            self.size.as_slice(),
            self.prefix.as_slice(),
            self.specific,
            self.extra,
        ] {
            out[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        let crc = crc32(&out[start + 4..start + self.plain_len]);
        out[start..start + 4].copy_from_slice(&crc.to_le_bytes());
        if let Some(keys) = keys {
            let mut iv = [0; 16];
            getrandom::fill(&mut iv).map_err(|error| {
                crate::write_stream::entropy_error(
                    error,
                    "RAR 5 writer could not generate encryption IV",
                )
            })?;
            out[..16].copy_from_slice(&iv);
            Rar50Cipher::new(keys.key, iv)
                .encrypt_in_place(&mut out[16..header_len])
                .map_err(map_rar50_crypto_error)?;
        }
        out[header_len..].copy_from_slice(data);
        Ok(out)
    }
}

pub(super) fn block_header_image(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    resources: &WriterResources,
) -> Result<Bytes> {
    HeaderImage::new(header_type, flags, data_size, type_specific, extra)?.render(
        None,
        &[],
        resources,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_block(
    out: &mut impl HeaderOutput,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
    resources: &WriterResources,
) -> Result<()> {
    let header = block_header_image(
        header_type,
        flags,
        data_size,
        type_specific,
        extra,
        resources,
    )?;
    out.append(&header)?;
    out.append(data)?;
    Ok(())
}

/// Encrypts a header block under `keys`, returning `iv || ciphertext || data`.
///
/// Each block gets its own IV and its own CBC chain, so headers can be built
/// and emitted one at a time without any cross-block state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypted_header_block(
    keys: &Rar50Keys,
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    data: &[u8],
    resources: &WriterResources,
) -> Result<Bytes> {
    HeaderImage::new(header_type, flags, data_size, type_specific, extra)?.render(
        Some(keys),
        data,
        resources,
    )
}

pub(super) fn stored_file_specific(
    name: &[u8],
    unpacked_size: u64,
    data_crc32: Option<u32>,
    attributes: u64,
    mtime: Option<u32>,
    host_os: u64,
    resources: &WriterResources,
) -> Result<Bytes> {
    file_specific(
        name,
        unpacked_size,
        data_crc32,
        attributes,
        mtime,
        0,
        host_os,
        false,
        resources,
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
    resources: &WriterResources,
) -> Result<Bytes> {
    if name.is_empty() {
        return Err(Error::InvalidArgument("RAR 5 file name is empty"));
    }
    let mut file_flags = if data_crc32.is_some() { FHFL_CRC32 } else { 0 };
    if is_directory {
        file_flags |= FHFL_DIRECTORY;
    }
    if mtime.is_some() {
        file_flags |= FHFL_MTIME;
    }

    let mut specific = HeaderScratch::<68>::new();
    specific.vint(file_flags);
    specific.vint(unpacked_size);
    specific.vint(attributes);
    if let Some(mtime) = mtime {
        specific.extend_from_slice(&mtime.to_le_bytes());
    }
    if let Some(data_crc32) = data_crc32 {
        specific.extend_from_slice(&data_crc32.to_le_bytes());
    }
    specific.vint(compression_info);
    specific.vint(host_os);
    specific.vint(name.len() as u64);
    join_record(&[specific.as_slice(), name], resources)
}

pub(super) fn write_mtime_record(
    extra: &mut impl HeaderOutput,
    seconds: Option<u32>,
    nanos: Option<u32>,
) -> Result<()> {
    if let (Some(seconds), Some(nanos)) = (seconds, nanos) {
        // Unix time + mtime + nanoseconds. Emit the complete timestamp here,
        // with no base-header time competing with the higher precision record.
        let mut record = HeaderScratch::<9>::new();
        record.extend_from_slice(&[0x13]);
        record.extend_from_slice(&seconds.to_le_bytes());
        record.extend_from_slice(&nanos.to_le_bytes());
        write_extra_record(extra, super::super::FHEXTRA_HTIME, record.as_slice())?;
    }

    Ok(())
}

fn metadata_image(
    flags: u64,
    name: Option<&[u8]>,
    time: &[u8],
    resources: &WriterResources,
) -> Result<Bytes> {
    let mut fields = HeaderScratch::<20>::new();
    fields.vint(flags);
    if let Some(name) = name {
        fields.vint(name.len() as u64);
    }
    let name = name.unwrap_or_default();
    let mut kind = HeaderScratch::<10>::new();
    kind.vint(MHEXTRA_ARCHIVE_METADATA);
    let body_len = checked_image_len(&[kind.len(), fields.len(), name.len(), time.len()])?;
    let mut size = HeaderScratch::<10>::new();
    size.vint(body_len as u64);
    join_record(
        &[
            size.as_slice(),
            kind.as_slice(),
            fields.as_slice(),
            name,
            time,
        ],
        resources,
    )
}

pub(super) fn archive_metadata_record(
    metadata: ArchiveMetadataEntry<'_>,
    resources: &WriterResources,
) -> Result<Bytes> {
    if metadata.name.is_none() && metadata.creation_time.is_none() {
        return Err(Error::InvalidArgument(
            "RAR 5 archive metadata writer needs a name or creation time",
        ));
    }
    if metadata.name.is_some() && metadata.creation_time.is_none() {
        return Err(Error::InvalidArgument(
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

    if metadata.name.is_some_and(|name| name.is_empty()) {
        return Err(Error::InvalidArgument(
            "RAR 5 archive metadata name is empty",
        ));
    }
    let time = metadata.creation_time.map(u64::to_le_bytes);
    metadata_image(
        flags,
        metadata.name,
        time.as_ref().map_or(&[], |bytes| bytes.as_slice()),
        resources,
    )
}

pub(super) fn write_locator_record(
    out: &mut impl HeaderOutput,
    quick_open_offset: Option<u64>,
    recovery_record_offset: Option<u64>,
) -> Result<()> {
    let mut flags = 0;
    if quick_open_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_QUICK_OPEN;
    }
    if recovery_record_offset.is_some() {
        flags |= MHEXTRA_LOCATOR_RECOVERY;
    }

    let mut record = HeaderScratch::<21>::new();
    record.vint(flags);
    if let Some(quick_open_offset) = quick_open_offset {
        record.vint(quick_open_offset);
    }
    if let Some(recovery_record_offset) = recovery_record_offset {
        record.vint(recovery_record_offset);
    }
    write_extra_record(out, MHEXTRA_LOCATOR, record.as_slice())?;

    Ok(())
}

pub(super) fn resolved_main_extra(
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
    quick_open_offset: Option<u64>,
    recovery_offset: Option<u64>,
    resources: &WriterResources,
) -> Result<Bytes> {
    let mut main_extra = Bytes::new(resources);
    let locator_quick_open_offset = quick_open_offset.or_else(|| archive_metadata.map(|_| 0));
    if locator_quick_open_offset.is_some() || recovery_offset.is_some() {
        write_locator_record(&mut main_extra, locator_quick_open_offset, recovery_offset)?;
    }
    if let Some(archive_metadata) = archive_metadata {
        main_extra.extend_from_slice(&archive_metadata_record(archive_metadata, resources)?)?;
    }
    Ok(main_extra)
}

pub(super) fn write_main_header(
    out: &mut impl HeaderOutput,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
    resources: &WriterResources,
) -> Result<()> {
    let mut specific = HeaderScratch::<20>::new();
    specific.vint(archive_flags);
    if let Some(volume_number) = volume_number {
        specific.vint(volume_number);
    }
    write_block(
        out,
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        specific.as_slice(),
        extra,
        &[],
        resources,
    )
}

pub(super) fn encrypted_main_header_block(
    keys: &Rar50Keys,
    archive_flags: u64,
    volume_number: Option<u64>,
    extra: &[u8],
    resources: &WriterResources,
) -> Result<Bytes> {
    let mut specific = HeaderScratch::<20>::new();
    specific.vint(archive_flags);
    if let Some(volume_number) = volume_number {
        specific.vint(volume_number);
    }
    encrypted_header_block(
        keys,
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        specific.as_slice(),
        extra,
        &[],
        resources,
    )
}

pub(crate) struct HeaderEncryptionKeys {
    pub(super) keys: Rar50Keys,
    pub(super) salt: [u8; 16],
}

pub(super) fn header_encryption_keys(password: &[u8]) -> Result<HeaderEncryptionKeys> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|error| {
        crate::write_stream::entropy_error(error, "RAR 5 writer could not generate encryption salt")
    })?;
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
            return Err(Error::InvalidArgument(
                "RAR 5 header-encrypted writer needs one shared password",
            ));
        }
    }
    Ok(first)
}

pub(super) fn write_head_crypt(
    out: &mut impl HeaderOutput,
    header_keys: &HeaderEncryptionKeys,
    resources: &WriterResources,
) -> Result<()> {
    let mut specific = HeaderScratch::<31>::new();
    specific.vint(0);
    specific.vint(0x0001);
    specific.extend_from_slice(&[WRITE_KDF_COUNT_LOG]);
    specific.extend_from_slice(&header_keys.salt);
    specific.extend_from_slice(&header_keys.keys.password_check_record());
    write_block(
        out,
        HEAD_CRYPT,
        0,
        None,
        specific.as_slice(),
        &[],
        &[],
        resources,
    )
}

pub(crate) fn write_end_header(
    out: &mut impl HeaderOutput,
    end_flags: u64,
    resources: &WriterResources,
) -> Result<()> {
    write_block(
        out,
        HEAD_END,
        0,
        None,
        &end_header_specific(end_flags),
        &[],
        &[],
        resources,
    )
}

pub(crate) fn end_header_specific(end_flags: u64) -> HeaderScratch<10> {
    let mut specific = HeaderScratch::new();
    specific.vint(end_flags);
    specific
}

pub(crate) fn retained_archive_metadata(
    metadata: &crate::rar50::ArchiveMetadataRecord,
    resources: &WriterResources,
) -> Result<Bytes> {
    if metadata.flags & !15 != 0
        || (metadata.flags & 8 != 0 && metadata.flags & 4 == 0)
        || (metadata.flags & 1 != 0) != metadata.name.is_some()
        || (metadata.flags & 2 != 0) != metadata.creation_time.is_some()
        || metadata.flags & 3 == 0
        || metadata
            .name
            .as_ref()
            .is_some_and(|name| name.is_empty() || std::str::from_utf8(name).is_err())
    {
        return Err(Error::InvalidArgument(
            "unsupported archive metadata record",
        ));
    }
    let mut time_bytes = HeaderScratch::<8>::new();
    if let Some(time) = metadata.creation_time {
        if metadata.flags & 4 != 0 && metadata.flags & 8 == 0 {
            time_bytes.extend_from_slice(
                &u32::try_from(time)
                    .map_err(|_| Error::InvalidArgument("archive Unix timestamp exceeds 32 bits"))?
                    .to_le_bytes(),
            );
        } else {
            time_bytes.extend_from_slice(&time.to_le_bytes());
        }
    }
    metadata_image(
        metadata.flags,
        metadata.name.as_deref(),
        time_bytes.as_slice(),
        resources,
    )
}

/// An immutable final header image. Free bytes before releasing admission.
pub(super) struct PreparedHeader {
    bytes: Bytes,
    _charge: Option<crate::streaming::StorageCharge>,
}

impl std::ops::Deref for PreparedHeader {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) fn prepared_header_image(
    header_type: u64,
    flags: u64,
    data_size: Option<u64>,
    type_specific: &[u8],
    extra: &[u8],
    keys: Option<&HeaderEncryptionKeys>,
    resources: &crate::WriterResources,
) -> Result<PreparedHeader> {
    let image = HeaderImage::new(header_type, flags, data_size, type_specific, extra)?;
    let length = image.header_len(keys.is_some())?;
    let charge = resources.reserve_prepared_header(length as u64)?;
    let bytes = image.render(keys.map(|keys| &keys.keys), &[], resources)?;
    Ok(PreparedHeader {
        bytes,
        _charge: charge,
    })
}

#[cfg(test)]
mod prepared_header_tests {
    use super::*;
    use crate::{ErrorKind, WriterResources};

    #[test]
    fn exact_images_match_existing_serialization_and_include_encryption_padding() {
        let keys = header_encryption_keys(b"secret").unwrap();
        for len in [0, 1, 15, 16, 120, 127, 128, 16384] {
            let specific = vec![0x51; len];
            for encrypted in [false, true] {
                let key = encrypted.then_some(&keys);
                let expected = block_header_image(
                    2,
                    HFL_EXTRA,
                    Some(u64::MAX),
                    &specific,
                    b"extra",
                    &crate::WriterResources::default(),
                )
                .unwrap();
                let size = if encrypted {
                    16 + expected.len().div_ceil(16) * 16
                } else {
                    expected.len()
                };
                let limited =
                    WriterResources::default().with_max_prepared_header_bytes(size as u64 - 1);
                let error = prepared_header_image(
                    2,
                    HFL_EXTRA,
                    Some(u64::MAX),
                    &specific,
                    b"extra",
                    key,
                    &limited,
                )
                .err()
                .unwrap();
                assert_eq!(error.kind(), ErrorKind::ResourceLimit);
                assert_eq!(
                    error,
                    Error::WriterPreparedHeaderLimitExceeded {
                        limit: size as u64 - 1,
                        required: size as u64,
                        used: 0
                    }
                );
                let resources =
                    WriterResources::default().with_max_prepared_header_bytes(size as u64);
                let header = prepared_header_image(
                    2,
                    HFL_EXTRA,
                    Some(u64::MAX),
                    &specific,
                    b"extra",
                    key,
                    &resources,
                )
                .unwrap();
                assert_eq!(header.bytes.capacity(), size);
                assert!(resources.clone().reserve_prepared_header(1).is_err());
                if encrypted {
                    let iv = header[..16].try_into().unwrap();
                    let mut plain = header[16..].to_vec();
                    Rar50Cipher::new(keys.keys.key, iv)
                        .decrypt_in_place(&mut plain)
                        .unwrap();
                    assert_eq!(&plain[..expected.len()], expected.as_slice());
                    assert!(plain[expected.len()..].iter().all(|byte| *byte == 0));
                } else {
                    assert_eq!(&*header, expected.as_slice());
                }
                drop(header);
                assert!(resources.reserve_prepared_header(size as u64).is_ok());
            }
        }
    }

    #[test]
    fn shared_header_quota_is_released_on_unwind() {
        let resources = WriterResources::default().with_max_prepared_header_bytes(1024);
        let failure = std::panic::catch_unwind(|| {
            let _header =
                prepared_header_image(2, 0, None, b"data", &[], None, &resources).unwrap();
            assert!(resources.reserve_prepared_header(1024).is_err());
            panic!("injected failure");
        });
        assert!(failure.is_err());
        assert!(resources.reserve_prepared_header(1024).is_ok());
    }
}

#[cfg(test)]
mod scratch_tests {
    use super::*;

    fn buffered_record(kind: u64, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        write_vint(&mut body, kind);
        body.extend_from_slice(data);
        let mut out = Vec::new();
        write_vint(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn stack_framing_matches_buffered_encoding_at_vint_boundaries() {
        for len in [0, 1, 127, 128, 16384] {
            let data = vec![0xa5; len];
            for kind in [0, 127, 128, u64::MAX] {
                let mut record = vec![0x5a];
                write_extra_record(&mut record, kind, &data).unwrap();
                let mut expected = vec![0x5a];
                expected.extend(buffered_record(kind, &data));
                assert_eq!(record, expected);
                for flags in [0, HFL_EXTRA, u64::MAX] {
                    for size in [None, Some(u64::MAX)] {
                        let mut body = Vec::new();
                        write_vint(&mut body, kind);
                        write_vint(&mut body, flags);
                        if flags & HFL_EXTRA != 0 {
                            write_vint(&mut body, data.len() as u64);
                        }
                        if let Some(size) = size {
                            write_vint(&mut body, size);
                        }
                        body.extend_from_slice(b"specific");
                        body.extend_from_slice(&data);
                        let mut expected = vec![0; 4];
                        write_vint(&mut expected, body.len() as u64);
                        expected.extend_from_slice(&body);
                        let crc = crc32(&expected[4..]);
                        expected[..4].copy_from_slice(&crc.to_le_bytes());
                        assert_eq!(
                            block_header_image(
                                kind,
                                flags,
                                size,
                                b"specific",
                                &data,
                                &crate::WriterResources::default()
                            )
                            .unwrap(),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn fixed_records_fit_their_stack_capacity_and_keep_wire_bytes() {
        let mut actual = Vec::new();
        write_file_encryption_record(&mut actual, [1; 16], [2; 16], [3; 12]).unwrap();
        let mut body = vec![0, 3, WRITE_KDF_COUNT_LOG];
        body.extend_from_slice(&[1; 16]);
        body.extend_from_slice(&[2; 16]);
        body.extend_from_slice(&[3; 12]);
        assert_eq!(actual, buffered_record(FHEXTRA_CRYPT, &body));
        actual.clear();
        write_hash_record_with_value(&mut actual, [7; 32]).unwrap();
        let mut body = vec![0];
        body.extend_from_slice(&[7; 32]);
        assert_eq!(actual, buffered_record(FHEXTRA_HASH, &body));
        actual.clear();
        write_mtime_record(&mut actual, Some(u32::MAX), Some(u32::MAX)).unwrap();
        let mut body = vec![0x13];
        body.extend_from_slice(&[0xff; 8]);
        assert_eq!(
            actual,
            buffered_record(super::super::super::FHEXTRA_HTIME, &body)
        );
        actual.clear();
        write_locator_record(&mut actual, Some(u64::MAX), Some(u64::MAX)).unwrap();
        let mut body = Vec::new();
        write_vint(
            &mut body,
            MHEXTRA_LOCATOR_QUICK_OPEN | MHEXTRA_LOCATOR_RECOVERY,
        );
        write_vint(&mut body, u64::MAX);
        write_vint(&mut body, u64::MAX);
        assert_eq!(actual, buffered_record(MHEXTRA_LOCATOR, &body));
    }
}

#[cfg(test)]
mod image_tests {
    use super::*;

    #[test]
    fn encrypted_images_match_buffered_ciphertext_and_leave_trailing_data_plain() {
        let keys = header_encryption_keys(b"secret").unwrap();
        for size in [0, 1, 15, 16, 17, 127, 128, 16384] {
            let specific = vec![0x35; size];
            let data = b"unencrypted trailing payload";
            let actual = encrypted_header_block(
                &keys.keys,
                u64::MAX,
                HFL_EXTRA,
                Some(data.len() as u64),
                &specific,
                b"extra",
                data,
                &crate::WriterResources::default(),
            )
            .unwrap();
            let iv = actual[..16].try_into().unwrap();
            let expected = block_header_image(
                u64::MAX,
                HFL_EXTRA,
                Some(data.len() as u64),
                &specific,
                b"extra",
                &crate::WriterResources::default(),
            )
            .unwrap();
            let mut expected = expected.to_vec();
            expected.resize(expected.len().div_ceil(16) * 16, 0);
            Rar50Cipher::new(keys.keys.key, iv)
                .encrypt_in_place(&mut expected)
                .unwrap();
            assert_eq!(&actual[16..16 + expected.len()], expected.as_slice());
            assert_eq!(&actual[16 + expected.len()..], data);
            assert_eq!(actual.capacity(), actual.len());
        }
    }

    #[test]
    fn metadata_images_keep_all_supported_time_encodings_and_name_lengths() {
        for length in [1, 127, 128, 16384] {
            let name = vec![b'n'; length];
            for flags in [1, 2, 3, 6, 7, 14, 15] {
                let time = if flags & 4 != 0 && flags & 8 == 0 {
                    u32::MAX as u64
                } else {
                    u64::MAX
                };
                let record = crate::rar50::ArchiveMetadataRecord {
                    flags,
                    name: (flags & 1 != 0).then(|| name.clone()),
                    creation_time: (flags & 2 != 0).then_some(time),
                };
                let mut body = Vec::new();
                write_vint(&mut body, flags);
                if let Some(name) = &record.name {
                    write_vint(&mut body, name.len() as u64);
                    body.extend_from_slice(name);
                }
                if record.creation_time.is_some() {
                    if flags & 4 != 0 && flags & 8 == 0 {
                        body.extend_from_slice(&(time as u32).to_le_bytes());
                    } else {
                        body.extend_from_slice(&time.to_le_bytes());
                    }
                }
                let mut expected = Vec::new();
                write_extra_record(&mut expected, MHEXTRA_ARCHIVE_METADATA, &body).unwrap();
                let actual =
                    retained_archive_metadata(&record, &crate::WriterResources::default()).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(actual.capacity(), actual.len());
                if flags == 2 || flags == 3 {
                    assert_eq!(
                        archive_metadata_record(
                            ArchiveMetadataEntry {
                                name: record.name.as_deref(),
                                creation_time: record.creation_time,
                            },
                            &crate::WriterResources::default()
                        )
                        .unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn file_specific_fields_keep_maximum_widths_without_growing_the_record() {
        let name = vec![b'n'; 16384];
        let actual = file_specific(
            &name,
            u64::MAX,
            Some(u32::MAX),
            u64::MAX,
            Some(u32::MAX),
            u64::MAX,
            u64::MAX,
            true,
            &crate::WriterResources::default(),
        )
        .unwrap();
        let mut expected = Vec::new();
        for value in [FHFL_CRC32 | FHFL_DIRECTORY | FHFL_MTIME, u64::MAX, u64::MAX] {
            write_vint(&mut expected, value);
        }
        expected.extend_from_slice(&[0xff; 8]);
        for value in [u64::MAX, u64::MAX, name.len() as u64] {
            write_vint(&mut expected, value);
        }
        expected.extend_from_slice(&name);
        assert_eq!(actual, expected);
        assert_eq!(actual.capacity(), actual.len());
    }
}
