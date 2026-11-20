use super::support::rar50_entry;
use rars::rar50::*;

use rars::Error;

#[test]
fn combined_integrity_check_uses_authoritative_blake2sp_record() {
    // The fixture is independently accepted by RAR and UnRAR despite its
    // deliberately wrong CRC32 beside the valid BLAKE2sp record.
    let archive = Archive::parse(include_bytes!(
        "../fixtures/rar50/crc32_wrong_beside_blake2sp.rar"
    ))
    .unwrap();
    let file = archive.files().next().unwrap();
    let data = file.packed_data(&archive).unwrap();
    assert!(matches!(
        file.verify_crc32(&data),
        Err(Error::Crc32Mismatch { .. })
    ));
    file.verify_hash(&data).unwrap();
    file.verify_integrity(&data).unwrap();
}

#[test]
fn recovery_record_distinguishes_other_services_and_rejects_missing_or_extra_data() {
    let archive = build_archive_with_optional_comment(None);
    let mut file = archive.files().next().unwrap().clone();
    assert_eq!(file.recovery_record().unwrap(), None);

    file.name = b"RR".to_vec();
    assert!(matches!(
        file.recovery_record(),
        Err(Error::InvalidHeader(
            "RAR 5 recovery service is missing service data"
        ))
    ));
    file.service_data = Some(Vec::new());
    assert_eq!(file.recovery_record(), Err(Error::TooShort));
    file.service_data = Some(vec![5, 0]);
    assert!(matches!(
        file.recovery_record(),
        Err(Error::InvalidHeader(
            "RAR 5 recovery service data has trailing bytes"
        ))
    ));
    file.service_data = Some(vec![5]);
    let record = file.recovery_record().unwrap().unwrap();
    assert_eq!(record.percent, 5);
    assert_eq!(record.payload_size, file.packed_size());
}

fn build_archive_with_optional_comment(comment: Option<&[u8]>) -> Archive {
    use rars::FeatureSet;
    let features = FeatureSet::store_only();
    let entries = [rar50_entry(b"payload.txt", b"payload bytes")
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = rars::rar50::Rar50Writer::new(
        rars::rar50::WriterOptions::new(rars::version::ArchiveVersion::Rar50, features)
            .with_compression_level(0),
    )
    .entries(entries.to_vec())
    .archive_comment(comment)
    .finish()
    .unwrap();
    Archive::parse(&bytes).unwrap()
}

#[test]
fn archive_comment_returns_none_for_archive_without_a_cmt_service() {
    let mut archive = build_archive_with_optional_comment(None);
    assert!(archive.archive_comment().unwrap().is_none());
    for block in &mut archive.blocks {
        if let Block::File(file) = block {
            let mut service = file.clone();
            service.name = b"STM".to_vec();
            *block = Block::Service(service);
        }
    }
    assert!(archive.archive_comment().unwrap().is_none());
}

#[test]
fn archive_comment_decodes_the_cmt_service_payload_text() {
    let comment_text = b"archive comment from rars unit test\n";
    let archive = build_archive_with_optional_comment(Some(comment_text));
    let comment = archive.archive_comment().unwrap();
    assert_eq!(comment.as_deref(), Some(&comment_text[..]));
}

#[test]
fn archive_comment_ignores_cmt_services_attached_to_files() {
    // Service blocks that follow a File block belong to that file, not the
    // archive — archive_comment should not surface them.
    use rars::FeatureSet;
    let entry = rar50_entry(b"payload.txt", b"payload bytes")
        .with_attributes(0x20)
        .with_host_os(3)
        .with_service(rars::rar50::ServiceEntry::new(
            b"CMT".to_vec(),
            b"per-file comment".to_vec(),
        ));
    let features = FeatureSet::store_only();
    let bytes = rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::new(
        rars::version::ArchiveVersion::Rar50,
        features,
    ))
    .entry(entry)
    .finish()
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(archive.archive_comment().unwrap().is_none());
}
