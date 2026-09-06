//! Where each archive block lands, worked out before anything is written.
//!
//! The main header carries a locator record holding the offsets of the
//! quick-open and recovery blocks, and those offsets are stored as variable
//! length integers. So the main header's own size depends on values that
//! depend on the main header's size. The writer used to break that circle by
//! emitting the entire archive up to four times until the offsets stopped
//! moving, which meant recomputing every recovery record from scratch on each
//! attempt.
//!
//! It is only a circle over two integers, though. Everything else in the
//! archive has a size that is already known: block headers are a pure function
//! of their fields, and the quick-open payload stores offsets *relative* to
//! itself, so growing the prefix shifts its position and its targets equally
//! and leaves its length alone. That makes the fixed point cheap to solve here,
//! over a few dozen bytes, instead of over the whole archive.

use super::headers::{block_header_image, resolved_main_extra, stored_file_specific, write_vint};
use super::ArchiveMetadataEntry;
use crate::detect::RAR50_SIGNATURE;
use crate::rar50::{FHEXTRA_SUBDATA, HEAD_MAIN, HEAD_SERVICE, HFL_DATA, HFL_EXTRA};
use crate::{Error, Result};

/// Offsets only ever grow as the header grows, and a vint is at most 10 bytes
/// wide, so this is far more headroom than the fixed point can need.
const MAX_LAYOUT_PASSES: usize = 16;

#[derive(Debug, Clone, Copy)]
pub(super) struct LayoutInputs<'a> {
    /// Header encryption pads every header to a 16-byte boundary and prefixes
    /// an IV, which changes sizes but keeps them predictable.
    pub(super) header_encrypted: bool,
    /// Size of the plaintext HEAD_CRYPT block, or zero when absent.
    pub(super) head_crypt_len: u64,
    /// Archive flags, including MHFL_RECOVERY and any volume flags.
    pub(super) main_flags: u64,
    pub(super) volume_number: Option<u64>,
    pub(super) archive_metadata: Option<ArchiveMetadataEntry<'a>>,
    pub(super) metadata_record: Option<&'a crate::rar50::ArchiveMetadataRecord>,
    /// Everything between the main header and the quick-open block: comments,
    /// members and their services.
    pub(super) body_len: u64,
    pub(super) quick_open_payload_len: Option<u64>,
    pub(super) recovery_percent: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedLayout {
    /// The extra area to put in the main header, with settled offsets.
    pub(super) main_extra: Vec<u8>,
    pub(super) main_header_len: u64,
    /// Value stored in the locator: the block's position measured from the end
    /// of the signature. The quick-open offset is settled the same way but is
    /// only ever written into `main_extra`, so it is not repeated here.
    pub(super) recovery_offset: Option<u64>,
    /// Bytes the recovery record protects, i.e. everything before it.
    pub(super) recovery_prefix_len: Option<u64>,
}

pub(super) fn resolve_layout(inputs: &LayoutInputs<'_>) -> Result<ResolvedLayout> {
    let signature_len = RAR50_SIGNATURE.len() as u64;
    let quick_open_block_len = match inputs.quick_open_payload_len {
        Some(payload_len) => {
            stored_service_block_len(b"QO", payload_len, &[], inputs.header_encrypted)?
        }
        None => 0,
    };

    let mut quick_open_offset = inputs.quick_open_payload_len.map(|_| 0);
    let mut recovery_offset = inputs.recovery_percent.map(|_| 0);

    for _ in 0..MAX_LAYOUT_PASSES {
        let mut main_extra =
            resolved_main_extra(inputs.archive_metadata, quick_open_offset, recovery_offset)?;
        if let Some(metadata) = inputs.metadata_record {
            main_extra.extend(super::headers::retained_archive_metadata(metadata)?);
        }
        let main_header_len = main_header_len(inputs, &main_extra)?;

        let quick_open_position = signature_len
            .checked_add(inputs.head_crypt_len)
            .and_then(|value| value.checked_add(main_header_len))
            .and_then(|value| value.checked_add(inputs.body_len))
            .ok_or(Error::InvalidHeader("RAR 5 archive layout overflows"))?;
        let recovery_position = quick_open_position
            .checked_add(quick_open_block_len)
            .ok_or(Error::InvalidHeader("RAR 5 archive layout overflows"))?;

        let next_quick_open = quick_open_offset.map(|_| quick_open_position - signature_len);
        let next_recovery = recovery_offset.map(|_| recovery_position - signature_len);

        if next_quick_open == quick_open_offset && next_recovery == recovery_offset {
            return Ok(ResolvedLayout {
                main_extra,
                main_header_len,
                recovery_offset,
                recovery_prefix_len: inputs.recovery_percent.map(|_| recovery_position),
            });
        }

        quick_open_offset = next_quick_open;
        recovery_offset = next_recovery;
    }

    Err(Error::InvalidHeader(
        "RAR 5 writer could not resolve archive layout offsets",
    ))
}

/// Size of a main header carrying `extra`, as it will appear in the archive.
fn main_header_len(inputs: &LayoutInputs<'_>, extra: &[u8]) -> Result<u64> {
    let mut specific = Vec::new();
    write_vint(&mut specific, inputs.main_flags);
    if let Some(volume_number) = inputs.volume_number {
        write_vint(&mut specific, volume_number);
    }
    let header = block_header_image(
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        &specific,
        extra,
    )?;
    Ok(emitted_header_len(
        header.len() as u64,
        inputs.header_encrypted,
    ))
}

/// Size of a stored service block, header and payload together.
pub(super) fn stored_service_block_len(
    name: &[u8],
    data_len: u64,
    service_data: &[u8],
    header_encrypted: bool,
) -> Result<u64> {
    let mut extra = Vec::new();
    super::headers::write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data);
    // The CRC is a fixed-width field, so any value gives the right size.
    let specific = stored_file_specific(name, data_len, Some(0), 0, None, 0)?;
    let header = block_header_image(
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data_len),
        &specific,
        &extra,
    )?;
    emitted_header_len(header.len() as u64, header_encrypted)
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader("RAR 5 service block size overflows"))
}

/// An encrypted header is a 16-byte IV followed by the plaintext padded up to
/// the AES block size.
fn emitted_header_len(plain_len: u64, header_encrypted: bool) -> u64 {
    if header_encrypted {
        16 + plain_len.div_ceil(16) * 16
    } else {
        plain_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(body_len: u64) -> LayoutInputs<'static> {
        LayoutInputs {
            header_encrypted: false,
            head_crypt_len: 0,
            main_flags: 0,
            volume_number: None,
            archive_metadata: None,
            metadata_record: None,
            body_len,
            quick_open_payload_len: None,
            recovery_percent: Some(5),
        }
    }

    /// The offsets a layout reports must be exactly where the blocks land when
    /// the archive is assembled from the sizes it computed.
    fn assert_self_consistent(inputs: &LayoutInputs<'_>, layout: &ResolvedLayout) {
        let signature_len = RAR50_SIGNATURE.len() as u64;
        let quick_open_position =
            signature_len + inputs.head_crypt_len + layout.main_header_len + inputs.body_len;

        // Rebuilding the header with the settled offsets must not resize it.
        let rebuilt = super::main_header_len(inputs, &layout.main_extra).unwrap();
        assert_eq!(rebuilt, layout.main_header_len, "main header size moved");

        if let Some(offset) = layout.recovery_offset {
            let quick_open_block_len = match inputs.quick_open_payload_len {
                Some(len) => {
                    stored_service_block_len(b"QO", len, &[], inputs.header_encrypted).unwrap()
                }
                None => 0,
            };
            assert_eq!(
                offset,
                quick_open_position + quick_open_block_len - signature_len
            );
            assert_eq!(
                layout.recovery_prefix_len,
                Some(offset + signature_len),
                "recovery protects everything before its own block"
            );
        }
    }

    #[test]
    fn layout_settles_across_vint_width_boundaries() {
        // Body sizes chosen so the resulting offsets sit either side of each
        // vint width step, which is where a naive single pass gets it wrong.
        for boundary in [0x7fu64, 0x3fff, 0x1f_ffff, 0x0fff_ffff] {
            for delta in [-3i64, -2, -1, 0, 1, 2, 3] {
                let body_len = (boundary as i64 + delta).max(0) as u64;
                let inputs = inputs(body_len);
                let layout = resolve_layout(&inputs).unwrap();
                assert_self_consistent(&inputs, &layout);
            }
        }
    }

    #[test]
    fn layout_settles_with_quick_open_and_recovery_together() {
        for body_len in [0u64, 100, 0x3ffe, 0x4001, 1 << 20] {
            let mut inputs = inputs(body_len);
            inputs.quick_open_payload_len = Some(4096);
            let layout = resolve_layout(&inputs).unwrap();

            // assert_self_consistent checks that the recovery offset leaves
            // room for the whole quick-open block ahead of it.
            assert!(layout.recovery_offset.is_some());
            assert_self_consistent(&inputs, &layout);
        }
    }

    #[test]
    fn layout_accounts_for_encrypted_header_padding() {
        let mut inputs = inputs(1024);
        inputs.header_encrypted = true;
        inputs.head_crypt_len = 60;
        let layout = resolve_layout(&inputs).unwrap();

        assert_eq!(
            layout.main_header_len % 16,
            0,
            "an IV plus padded ciphertext is a multiple of the block size"
        );
        assert_self_consistent(&inputs, &layout);
    }

    #[test]
    fn layout_without_locator_features_has_no_offsets() {
        let mut inputs = inputs(4096);
        inputs.recovery_percent = None;
        let layout = resolve_layout(&inputs).unwrap();

        assert_eq!(layout.recovery_offset, None);
        assert_eq!(layout.recovery_prefix_len, None);
        assert!(layout.main_extra.is_empty());
    }
}
