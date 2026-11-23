//! Where each archive block lands, worked out before anything is written.
//!
//! The main header carries a locator record holding the offsets of the
//! quick-open and recovery blocks, and those offsets are stored as variable
//! length integers. So the main header's own size depends on values that
//! depend on the main header's size.
//!
//! It is only a circle over two integers. Everything else in the
//! archive has a size that is already known: block headers are a pure function
//! of their fields, and the quick-open payload stores offsets *relative* to
//! itself, so growing the prefix shifts its position and its targets equally
//! and leaves its length alone. That makes the fixed point cheap to solve here,
//! over a few dozen bytes, instead of over the whole archive.

use super::headers::{block_header_image, resolved_main_extra, stored_file_specific};
use super::ArchiveMetadataEntry;
use crate::detect::RAR50_SIGNATURE;
use crate::rar50::{FHEXTRA_SUBDATA, HEAD_MAIN, HEAD_SERVICE, HFL_DATA, HFL_EXTRA};
use crate::streaming::preparation::Bytes;
use crate::{Error, Result, WriterResources};

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
    /// Bytes the quick-open offset takes at least, so it can be patched in place.
    pub(super) quick_open_width: usize,
    pub(super) recovery_percent: Option<u64>,
    /// Bytes the recovery offset takes at least, so it can be patched in place.
    pub(super) recovery_width: usize,
}

#[derive(Debug)]
pub(super) struct ResolvedLayout {
    /// The extra area to put in the main header, with settled offsets.
    pub(super) main_extra: Bytes,
    pub(super) main_header_len: u64,
    /// Value stored in the locator: the block's position measured from the end
    /// of the signature. The quick-open offset is settled the same way but is
    /// only ever written into `main_extra`, so it is not repeated here.
    pub(super) recovery_offset: Option<u64>,
    /// Bytes the recovery record protects, i.e. everything before it.
    pub(super) recovery_prefix_len: Option<u64>,
}

/// Refused when a recovery record could not cover everything before it.
const RECOVERY_PREFIX_TOO_LARGE: &str =
    "RAR 5 recovery record cannot protect more than 858,993,124,400 bytes";

/// Settles the layout, and refuses one whose recovery record could not be
/// built, so an archive too large for one fails before any of it is written.
pub(super) fn resolve_layout(
    inputs: &LayoutInputs<'_>,
    resources: &WriterResources,
) -> Result<ResolvedLayout> {
    let layout = settle_layout(inputs, resources)?;
    if let (Some(percent), Some(prefix)) = (inputs.recovery_percent, layout.recovery_prefix_len) {
        if !recovery_covers(prefix, percent) {
            return Err(Error::InvalidArgument(RECOVERY_PREFIX_TOO_LARGE));
        }
    }
    Ok(layout)
}

/// Whether a recovery record can be built over `prefix_len` bytes. Its shard
/// size is a 32-bit field, which caps a record at about 859 GB.
pub(super) fn recovery_covers(prefix_len: u64, percent: u64) -> bool {
    #[cfg(feature = "recovery")]
    {
        crate::recovery::rar5::plan_inline_recovery(prefix_len, percent)
            .and_then(crate::recovery::rar5::check_streamable_plan)
            .is_ok()
    }
    #[cfg(not(feature = "recovery"))]
    {
        // Writing the record is refused as a disabled feature instead.
        let _ = (prefix_len, percent);
        true
    }
}

/// The layout [`resolve_layout`] returns, without its recovery check, for a
/// volume writer that sizes each volume to what its record can cover.
pub(super) fn settle_layout(
    inputs: &LayoutInputs<'_>,
    resources: &WriterResources,
) -> Result<ResolvedLayout> {
    let signature_len = RAR50_SIGNATURE.len() as u64;
    let quick_open_block_len = match inputs.quick_open_payload_len {
        Some(payload_len) => {
            stored_service_block_len(b"QO", payload_len, &[], inputs.header_encrypted, resources)?
        }
        None => 0,
    };

    let mut quick_open_offset = inputs.quick_open_payload_len.map(|_| 0);
    let mut recovery_offset = inputs.recovery_percent.map(|_| 0);

    // Starting with zero offsets makes header sizes and offsets monotone.
    // The two locator vints can grow by at most 18 bytes altogether; their
    // record-size vint stays one byte. The extra-size and header-size vints
    // can each grow by one byte, so the plaintext header grows by at most 20
    // bytes, or 32 after encryption padding. After the first offset update,
    // each offset can therefore cross at most one further vint boundary
    // (consecutive boundaries are at least 16,256 bytes apart). Those two
    // possible width changes, plus the initial update and propagation, settle
    // within five passes. Allocation or arithmetic failures return via `?`.
    loop {
        let mut main_extra = resolved_main_extra(
            inputs.archive_metadata,
            quick_open_offset,
            inputs.quick_open_width,
            recovery_offset,
            inputs.recovery_width,
            resources,
        )?;
        if let Some(metadata) = inputs.metadata_record {
            main_extra.extend_from_slice(&super::headers::retained_archive_metadata(
                metadata, resources,
            )?)?;
        }
        let main_header_len = main_header_len(inputs, &main_extra, resources)?;

        let quick_open_position = signature_len
            .checked_add(inputs.head_crypt_len)
            .and_then(|value| value.checked_add(main_header_len))
            .and_then(|value| value.checked_add(inputs.body_len))
            .ok_or(Error::InvalidArgument("RAR 5 archive layout overflows"))?;
        let recovery_position = quick_open_position
            .checked_add(quick_open_block_len)
            .ok_or(Error::InvalidArgument("RAR 5 archive layout overflows"))?;

        // Locator offsets count from the main header, which follows the
        // encryption header when there is one.
        let main_position = signature_len + inputs.head_crypt_len;
        let next_quick_open = quick_open_offset.map(|_| quick_open_position - main_position);
        let next_recovery = recovery_offset.map(|_| recovery_position - main_position);

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
}

/// Size of a main header carrying `extra`, as it will appear in the archive.
fn main_header_len(
    inputs: &LayoutInputs<'_>,
    extra: &[u8],
    resources: &WriterResources,
) -> Result<u64> {
    let mut specific = Bytes::new(resources);
    specific.vint(inputs.main_flags)?;
    if let Some(volume_number) = inputs.volume_number {
        specific.vint(volume_number)?;
    }
    let header = block_header_image(
        HEAD_MAIN,
        if extra.is_empty() { 0 } else { HFL_EXTRA },
        None,
        &specific,
        extra,
        resources,
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
    resources: &WriterResources,
) -> Result<u64> {
    let mut extra = Bytes::new(resources);
    super::headers::write_extra_record(&mut extra, FHEXTRA_SUBDATA, service_data)?;
    // The CRC is a fixed-width field, so any value gives the right size.
    let specific = stored_file_specific(name, data_len, 0, 0, None, 0, resources)?;
    let header = block_header_image(
        HEAD_SERVICE,
        HFL_EXTRA | HFL_DATA,
        Some(data_len),
        &specific,
        &extra,
        resources,
    )?;
    emitted_header_len(header.len() as u64, header_encrypted)
        .checked_add(data_len)
        .ok_or(Error::InvalidArgument("RAR 5 service block size overflows"))
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

    #[test]
    fn layout_header_sizes_release_preparation_charge_at_every_limit() {
        for measure in [
            &(|resources: &WriterResources| main_header_len(&inputs(0), &[], resources))
                as &dyn Fn(&WriterResources) -> Result<u64>,
            &(|resources: &WriterResources| {
                stored_service_block_len(b"QO", 16, &[], false, resources)
            }),
        ] {
            let mut succeeded = false;
            let mut failed_after_admission = false;
            for limit in 0..512 {
                let resources = WriterResources::default().with_max_preparation_bytes(limit);
                match measure(&resources) {
                    Ok(_) => {
                        succeeded = true;
                        break;
                    }
                    Err(Error::WriterPreparationLimitExceeded { used, .. }) => {
                        failed_after_admission |= used > 0;
                        drop(Bytes::zeroed(limit as usize, &resources).unwrap());
                    }
                    Err(error) => panic!("unexpected limit {limit} failure: {error}"),
                }
            }
            assert!(failed_after_admission);
            assert!(succeeded);
        }
    }

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
            quick_open_width: 0,
            recovery_percent: Some(5),
            recovery_width: 0,
        }
    }

    /// The offsets a layout reports must be exactly where the blocks land when
    /// the archive is assembled from the sizes it computed.
    fn assert_self_consistent(inputs: &LayoutInputs<'_>, layout: &ResolvedLayout) {
        let signature_len = RAR50_SIGNATURE.len() as u64;
        let main_position = signature_len + inputs.head_crypt_len;
        let quick_open_position = main_position + layout.main_header_len + inputs.body_len;

        // Rebuilding the header with the settled offsets must not resize it.
        let rebuilt = super::main_header_len(
            inputs,
            &layout.main_extra,
            &crate::WriterResources::default(),
        )
        .unwrap();
        assert_eq!(rebuilt, layout.main_header_len, "main header size moved");

        let (records, complete) = crate::rar50::parse_main_extra_area(
            &layout.main_extra,
            0..layout.main_extra.len(),
            &crate::read_control::ReadControl::new(None),
        )
        .unwrap();
        assert!(complete);
        for record in records {
            if let crate::rar50::MainExtraRecord::Locator(locator) = record {
                assert_eq!(
                    locator.quick_open_offset,
                    inputs
                        .quick_open_payload_len
                        .map(|_| quick_open_position - main_position)
                        .or_else(|| inputs.archive_metadata.map(|_| 0))
                );
                assert_eq!(locator.recovery_record_offset, layout.recovery_offset);
            }
        }

        if let Some(offset) = layout.recovery_offset {
            let quick_open_block_len = match inputs.quick_open_payload_len {
                Some(len) => stored_service_block_len(
                    b"QO",
                    len,
                    &[],
                    inputs.header_encrypted,
                    &crate::WriterResources::default(),
                )
                .unwrap(),
                None => 0,
            };
            assert_eq!(
                offset,
                quick_open_position + quick_open_block_len - main_position
            );
            assert_eq!(
                layout.recovery_prefix_len,
                Some(offset + main_position),
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
                let layout = resolve_layout(&inputs, &crate::WriterResources::default()).unwrap();
                assert_self_consistent(&inputs, &layout);
            }
        }
    }

    #[test]
    fn layout_settles_at_every_u64_offset_width_with_metadata_and_padding() {
        let resources = WriterResources::default();
        for name_len in [0, 104, 120, 16_360] {
            let metadata = crate::rar50::ArchiveMetadataRecord {
                flags: 1,
                name: Some(vec![b'x'; name_len]),
                creation_time: None,
            };
            for encrypted in [false, true] {
                for features in 1..=3 {
                    let mut inputs = inputs(0);
                    inputs.header_encrypted = encrypted;
                    inputs.head_crypt_len = if encrypted { 60 } else { 0 };
                    inputs.quick_open_payload_len = (features & 1 != 0).then_some(17);
                    inputs.recovery_percent = (features & 2 != 0).then_some(5);
                    inputs.metadata_record = (name_len != 0).then_some(&metadata);
                    let initial = resolve_layout(&inputs, &resources).unwrap();
                    for bits in (7..=63).step_by(7) {
                        let boundary = 1u64 << bits;
                        let base = boundary.saturating_sub(initial.main_header_len);
                        for delta in -32i64..=32 {
                            inputs.body_len = base.saturating_add_signed(delta);
                            // Past about 859 GB a recovery record is refused,
                            // so settle without that check to reach every width.
                            let layout = settle_layout(&inputs, &resources).unwrap();
                            assert_self_consistent(&inputs, &layout);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn layout_settles_with_quick_open_and_recovery_together() {
        for body_len in [0u64, 100, 0x3ffe, 0x4001, 1 << 20] {
            let mut inputs = inputs(body_len);
            inputs.quick_open_payload_len = Some(4096);
            let layout = resolve_layout(&inputs, &crate::WriterResources::default()).unwrap();

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
        let layout = resolve_layout(&inputs, &crate::WriterResources::default()).unwrap();

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
        let layout = resolve_layout(&inputs, &crate::WriterResources::default()).unwrap();

        assert_eq!(layout.recovery_offset, None);
        assert_eq!(layout.recovery_prefix_len, None);
        assert!(layout.main_extra.is_empty());
    }

    #[test]
    fn layout_includes_retained_metadata_before_solving_offsets() {
        let metadata = crate::rar50::ArchiveMetadataRecord {
            flags: 2,
            name: None,
            creation_time: Some(123),
        };
        let mut inputs = inputs(4096);
        inputs.metadata_record = Some(&metadata);
        inputs.quick_open_payload_len = Some(17);
        let layout = resolve_layout(&inputs, &crate::WriterResources::default()).unwrap();
        assert!(!layout.main_extra.is_empty());
        assert_self_consistent(&inputs, &layout);
    }

    #[test]
    fn retained_layout_metadata_obeys_preparation_limit() {
        let metadata = crate::rar50::ArchiveMetadataRecord {
            flags: 2,
            name: None,
            creation_time: Some(123),
        };
        let mut inputs = inputs(0);
        inputs.quick_open_payload_len = None;
        inputs.recovery_percent = None;
        inputs.metadata_record = Some(&metadata);
        let resources = crate::WriterResources::default().with_max_preparation_bytes(0);
        assert!(matches!(
            resolve_layout(&inputs, &resources),
            Err(Error::WriterPreparationLimitExceeded { limit: 0, .. })
        ));
    }

    #[test]
    fn layout_rejects_offset_and_service_length_overflow() {
        let resources = crate::WriterResources::default();
        for (body_len, head_crypt_len, quick_open_payload_len) in
            [(u64::MAX, 0, None), (0, u64::MAX, None)]
        {
            let mut inputs = inputs(body_len);
            inputs.head_crypt_len = head_crypt_len;
            inputs.quick_open_payload_len = quick_open_payload_len;
            assert_eq!(
                resolve_layout(&inputs, &resources).unwrap_err(),
                Error::InvalidArgument("RAR 5 archive layout overflows")
            );
        }
        assert_eq!(
            stored_service_block_len(b"QO", u64::MAX, &[], false, &resources).unwrap_err(),
            Error::InvalidArgument("RAR 5 service block size overflows")
        );
    }

    #[cfg(feature = "recovery")]
    #[test]
    fn a_layout_whose_recovery_record_cannot_be_built_is_refused() {
        let resources = crate::WriterResources::default();
        let largest = crate::recovery::rar5::MAX_STREAMED_RECOVERY_PREFIX;
        // Find the body that puts the recovery block at the largest prefix a
        // record covers. Only the main header's vints move it off by a few.
        let mut body_len = largest;
        while settle_layout(&inputs(body_len), &resources)
            .unwrap()
            .recovery_prefix_len
            .unwrap()
            > largest
        {
            body_len -= 1;
        }
        let layout = resolve_layout(&inputs(body_len), &resources).unwrap();
        assert_eq!(layout.recovery_prefix_len, Some(largest));
        assert_self_consistent(&inputs(body_len), &layout);
        assert!(recovery_covers(largest, 5));
        assert!(!recovery_covers(largest + 1, 5));
        for over in [body_len + 1, u64::MAX / 2] {
            assert_eq!(
                resolve_layout(&inputs(over), &resources).unwrap_err(),
                Error::InvalidArgument(RECOVERY_PREFIX_TOO_LARGE)
            );
            // Without a recovery record the same body is fine.
            let mut plain = inputs(over);
            plain.recovery_percent = None;
            assert!(resolve_layout(&plain, &resources).is_ok());
        }
    }

    #[test]
    fn layout_and_service_sizing_release_refused_admission() {
        let ledger = crate::codec::workspace::Allowance::limited(0);
        let resources = WriterResources::default().with_execution_allowance(ledger.clone());
        assert_eq!(
            resolve_layout(&inputs(0), &resources).err().unwrap().kind(),
            crate::ErrorKind::ResourceLimit
        );
        assert_eq!(ledger.used(), 0);
        assert_eq!(
            stored_service_block_len(b"QO", 1, &[], false, &resources)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ResourceLimit
        );
        assert_eq!(ledger.used(), 0);
    }
}
