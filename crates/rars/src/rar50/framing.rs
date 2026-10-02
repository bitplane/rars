//! Header framing shared by writers and recovery repair.

use super::{map_rar50_crypto_error, HFL_EXTRA};
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::{crc32::crc32, Error, Result};

/// Bounded framing scratch; callers choose capacities from the on-disk fields.
pub(crate) struct HeaderScratch<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> HeaderScratch<N> {
    pub(crate) fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }
    pub(crate) fn vint(&mut self, mut value: u64) {
        loop {
            self.extend_from_slice(&[(value as u8 & 0x7f) | if value >= 0x80 { 0x80 } else { 0 }]);
            value >>= 7;
            if value == 0 {
                break;
            }
        }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl<const N: usize> std::ops::Deref for HeaderScratch<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub(crate) fn image_size_error() -> Error {
    Error::InvalidArgument("RAR 5 header size overflows")
}

pub(crate) fn checked_image_len(parts: &[usize]) -> Result<usize> {
    let len = parts
        .iter()
        .try_fold(0usize, |total, &size| total.checked_add(size))
        .ok_or_else(image_size_error)?;
    if len > isize::MAX as usize {
        return Err(image_size_error());
    }
    Ok(len)
}

/// Computes framing without copying variable-length fields. All header paths
/// render into their final allocation, including IV, padding and trailing data.
pub(crate) struct HeaderImage<'a> {
    prefix: HeaderScratch<40>,
    size: HeaderScratch<10>,
    specific: &'a [u8],
    extra: &'a [u8],
    plain_len: usize,
}

impl<'a> HeaderImage<'a> {
    pub(crate) fn new(
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

    pub(crate) fn header_len(&self, encrypted: bool) -> Result<usize> {
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

    pub(crate) fn image_len(&self, encrypted: bool, data_len: usize) -> Result<usize> {
        checked_image_len(&[self.header_len(encrypted)?, data_len])
    }

    /// Render into a zeroed buffer of exactly `image_len` bytes. Allocation and
    /// admission belong to the caller; salts, framing and encryption are shared.
    pub(crate) fn render_into(
        &self,
        keys: Option<&Rar50Keys>,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        let header_len = self.header_len(keys.is_some())?;
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
            crate::entropy::fill_entropy(&mut iv, "RAR 5 writer could not generate encryption IV")?;
            out[..16].copy_from_slice(&iv);
            Rar50Cipher::new(keys.key, iv)
                .encrypt_in_place(&mut out[16..header_len])
                .map_err(map_rar50_crypto_error)?;
        }
        out[header_len..].copy_from_slice(data);
        Ok(())
    }
}
