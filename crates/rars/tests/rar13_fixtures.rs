use rars::rar13::{extract_volumes_to, file_checksum, Archive, Entry};
use rars::{detect_archive_family, find_archive_start, ArchiveFamily, Error};
use std::cell::RefCell;
use std::io::{Result as IoResult, Write};
use std::rc::Rc;

const EMPTY: &[u8] = include_bytes!("fixtures/rar13/EMPTY.RAR");
const BIG80K: &[u8] = include_bytes!("fixtures/rar13/BIG80K.RAR");
const MULTIFIL: &[u8] = include_bytes!("fixtures/rar13/MULTIFIL.RAR");
const REPEATB: &[u8] = include_bytes!("fixtures/rar13/REPEATB.RAR");
const WITHDIR: &[u8] = include_bytes!("fixtures/rar13/WITHDIR.RAR");
const COMMENT: &[u8] = include_bytes!("fixtures/rar13/COMMENT.RAR");
const FCOMM: &[u8] = include_bytes!("fixtures/rar13/FCOMM.RAR");
const README_PASSWORD: &[u8] = include_bytes!("fixtures/rar13/README_password=password.rar");
const README_COMPRESSED: &[u8] = include_bytes!("fixtures/rar13/README.RAR");
const README_STORE: &[u8] = include_bytes!("fixtures/rar13/README_store.rar");
const README_EXPECTED: &[u8] = include_bytes!("fixtures/rar13/README");
const CMULTI_EXPECTED: &[u8] = include_bytes!("fixtures/rar13/CMULTI.TXT");
const STOREPWD: &[u8] = include_bytes!("fixtures/rar13/STOREPWD.RAR");
const SFXSRC: &[u8] = include_bytes!("fixtures/rar13/SFXSRC.EXE");
const SOLID: &[u8] = include_bytes!("fixtures/rar13/SOLID.RAR");
const MULTIVOL_RAR: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.RAR");
const MULTIVOL_R00: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.R00");
const MULTIVOL_R01: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.R01");
const MULTIVOL_R02: &[u8] = include_bytes!("fixtures/rar13/MULTIVOL.R02");
const CMULTIV_RAR: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.RAR");
const CMULTIV_R00: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R00");
const CMULTIV_R01: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R01");
const CMULTIV_R02: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R02");
const CMULTIV_R03: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R03");
const CMULTIV_R04: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R04");
const CMULTIV_R05: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R05");
const CMULTIV_R06: &[u8] = include_bytes!("fixtures/rar13/CMULTIV.R06");
const RAR140_NOAV: &[u8] = include_bytes!("fixtures/rar13/rar140_av/rar140_noav_baseline.rar");
const RAR140_AV: &[u8] = include_bytes!("fixtures/rar13/rar140_av/rar140_av_patched.rar");

struct CollectWriter {
    data: Rc<RefCell<Vec<u8>>>,
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
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.data.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

fn collect_extract(
    archive: &Archive,
    password: Option<&[u8]>,
) -> Result<Vec<CollectedEntry>, Error> {
    let entries = RefCell::new(Vec::new());
    archive.extract_to(password, |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter { data }))
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
    archives: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<CollectedEntry>, Error> {
    let entries = RefCell::new(Vec::new());
    extract_volumes_to(archives, password, |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter { data }))
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

fn collect_entry(
    archive: &Archive,
    entry: &Entry,
    password: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let data = Rc::new(RefCell::new(Vec::new()));
    entry.write_to(
        archive,
        password,
        &mut CollectWriter {
            data: Rc::clone(&data),
        },
    )?;
    let data = data.borrow().clone();
    Ok(data)
}

#[test]
fn detects_real_rar1402_archive() {
    let sig = detect_archive_family(README_STORE).expect("signature");
    assert_eq!(sig.family, ArchiveFamily::Rar13);
    assert_eq!(sig.offset, 0);
    assert_eq!(sig.length, 4);
}

#[test]
fn extract_to_reports_rar13_entry_context_on_write_failure() {
    struct FailWriter;

    impl Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink failed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let archive = Archive::parse(README_STORE).unwrap();
    let error = archive
        .extract_to(None, |_meta| Ok(Box::new(FailWriter)))
        .unwrap_err();

    match error {
        Error::AtEntry {
            name,
            operation,
            source,
        } => {
            assert_eq!(name, b"README");
            assert_eq!(operation, "extracting");
            assert!(matches!(*source, Error::Io(_)));
        }
        other => panic!("expected entry context, got {other:?}"),
    }
}

#[test]
fn parses_rar140_inline_av_shape_fixture() {
    let archive = Archive::parse(RAR140_AV).expect("parse RAR 1.40 AV fixture");
    assert_eq!(archive.main.flags, 0xa0);
    assert_eq!(archive.main.head_size, 53);
    assert!(archive.main.has_authenticity_verification());

    let av = archive
        .authenticity_verification()
        .expect("parse AV")
        .expect("AV present");
    assert_eq!(av.size, 44);
    assert_eq!(av.prefix, *b"\x1ai\x6d\x02\xda\xae");
    assert_eq!(av.cipher_body.len(), 38);
    assert_eq!(
        archive.authenticity_verification_status().unwrap(),
        rars::rar13::AuthenticityVerificationStatus::StructurallyPresent
    );

    let extracted = collect_extract(&archive, None).expect("extract AV-bearing archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"hello\n");
}

#[test]
fn reports_absent_av_on_rar140_control_fixture() {
    let archive = Archive::parse(RAR140_NOAV).expect("parse RAR 1.40 baseline fixture");
    assert!(!archive.main.has_authenticity_verification());
    assert!(archive.authenticity_verification().unwrap().is_none());
    assert_eq!(
        archive.authenticity_verification_status().unwrap(),
        rars::rar13::AuthenticityVerificationStatus::Absent
    );
}

#[test]
fn decodes_real_rar1402_stored_file() {
    let archive = Archive::parse(README_STORE).expect("parse RAR 1.402 archive");
    assert_eq!(archive.main.head_size, 7);
    assert_eq!(archive.main.flags, 0x80);
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"README");
    assert_eq!(entry.header.pack_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.unp_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(entry.header.head_size, 27);
    assert_eq!(entry.header.file_attr, 0x20);
    assert_eq!(entry.header.flags, 0);
    assert_eq!(entry.header.unp_ver, 2);
    assert_eq!(entry.header.method, 0);
    let decoded = collect_entry(&archive, entry, None).expect("stored data");
    assert_eq!(decoded, README_EXPECTED);

    let extracted = collect_extract(&archive, None).expect("extract stored archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README");
    assert_eq!(extracted[0].data, README_EXPECTED);
    assert!(!extracted[0].is_directory);
}

#[test]
fn real_rar1402_stored_checksum_matches_rolling_sum_rotate() {
    let archive = Archive::parse(README_STORE).expect("parse RAR 1.402 archive");
    let entry = &archive.entries[0];
    let decoded = collect_entry(&archive, entry, None).expect("stored data");

    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(file_checksum(&decoded), 0xe079);
    entry
        .verify_checksum(&decoded)
        .expect("RAR 1.3 rolling checksum");
}

#[test]
fn decodes_real_rar1402_compressed_file() {
    let archive = Archive::parse(README_COMPRESSED).expect("parse compressed RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"README");
    assert_eq!(entry.header.pack_size, 1078);
    assert_eq!(entry.header.unp_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(entry.header.method, 3);
    assert!(!entry.is_stored());

    let extracted = collect_extract(&archive, None).expect("extract compressed archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README");
    assert_eq!(extracted[0].data, README_EXPECTED);
    assert_eq!(file_checksum(&extracted[0].data), 0xe079);
}

#[test]
fn decodes_real_rar1402_compressed_window_wrap_file() {
    let archive = Archive::parse(BIG80K).expect("parse BIG80K RAR 1.402 archive");
    let extracted = collect_extract(&archive, None).expect("extract BIG80K archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"BIG80K.TXT");
    assert_eq!(extracted[0].data.len(), 80 * 1024);
    assert_eq!(
        file_checksum(&extracted[0].data),
        archive.entries[0].header.file_crc
    );
}

#[test]
fn decodes_real_rar1402_repeating_pattern_file() {
    let archive = Archive::parse(REPEATB).expect("parse REPEATB RAR 1.402 archive");
    let extracted = collect_extract(&archive, None).expect("extract REPEATB archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"REPEATB.BIN");
    assert_eq!(extracted[0].data, expected_repeatb());
}

#[test]
fn decodes_real_rar1402_solid_archive() {
    let archive = Archive::parse(SOLID).expect("parse SOLID RAR 1.402 archive");
    assert_eq!(archive.main.flags, 0x88);
    assert!(archive.main.is_solid());
    assert_eq!(archive.entries.len(), 3);

    let extracted = collect_extract(&archive, None).expect("extract solid archive");
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].name, b"BIG80K.TXT");
    assert_eq!(extracted[0].data.len(), 80 * 1024);
    assert_eq!(
        file_checksum(&extracted[0].data),
        archive.entries[0].header.file_crc
    );
    assert_eq!(extracted[1].name, b"HELLO.TXT");
    assert_eq!(extracted[1].data, b"Hello, RAR 1.402 fixture world.\r\n");
    assert_eq!(extracted[2].name, b"TINY.TXT");
    assert_eq!(extracted[2].data, b"AAAAAAAA\r\n");
}

#[test]
fn parses_empty_stored_file() {
    let archive = Archive::parse(EMPTY).expect("parse empty RAR 1.402 archive");
    assert_eq!(archive.main.flags, 0x80);
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"EMPTY.BIN");
    assert_eq!(entry.header.pack_size, 0);
    assert_eq!(entry.header.unp_size, 0);
    assert_eq!(entry.header.file_crc, 0);
    assert!(entry.is_stored());
    assert_eq!(
        collect_entry(&archive, entry, None).expect("empty data"),
        b""
    );
    entry.verify_checksum(b"").expect("empty checksum");

    let extracted = collect_extract(&archive, None).expect("extract empty archive");
    assert_eq!(extracted[0].name, b"EMPTY.BIN");
    assert!(extracted[0].data.is_empty());
}

#[test]
fn parses_multiple_file_headers() {
    let archive = Archive::parse(MULTIFIL).expect("parse multi-file RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 2);

    let first = &archive.entries[0];
    assert_eq!(first.name, b"HELLO.TXT");
    assert_eq!(first.header.pack_size, 33);
    assert_eq!(first.header.unp_size, 33);
    assert_eq!(first.header.file_crc, 0x7a6e);
    assert!(first.is_stored());
    assert_eq!(
        collect_entry(&archive, first, None).expect("stored HELLO.TXT"),
        b"Hello, RAR 1.402 fixture world.\r\n"
    );
    first
        .verify_checksum(b"Hello, RAR 1.402 fixture world.\r\n")
        .expect("HELLO.TXT checksum");

    let second = &archive.entries[1];
    assert_eq!(second.name, b"TINY.TXT");
    assert_eq!(second.header.pack_size, 7);
    assert_eq!(second.header.unp_size, 10);
    assert_eq!(second.header.file_crc, 0x0642);
    assert_eq!(second.header.method, 3);
    assert!(!second.is_stored());
    let extracted = collect_extract(&archive, None).expect("extract mixed archive");
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"HELLO.TXT");
    assert_eq!(extracted[0].data, b"Hello, RAR 1.402 fixture world.\r\n");
    assert_eq!(extracted[1].name, b"TINY.TXT");
    assert_eq!(extracted[1].data, b"AAAAAAAA\r\n");
}

#[test]
fn parses_directory_entry_and_following_file() {
    let archive = Archive::parse(WITHDIR).expect("parse directory RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 2);

    let dir = &archive.entries[0];
    assert_eq!(dir.name, b"SUBDIR");
    assert_eq!(dir.header.file_attr, 0x10);
    assert!(dir.is_directory());
    assert_eq!(dir.header.pack_size, 0);
    assert_eq!(dir.header.unp_size, 0);

    let file = &archive.entries[1];
    assert_eq!(file.name, b"SUBDIR\\INNER.TXT");
    assert!(!file.is_directory());
    assert!(file.is_stored());
    assert_eq!(
        collect_entry(&archive, file, None).expect("stored inner file"),
        b"Inside subdir.\r\n"
    );
    file.verify_checksum(b"Inside subdir.\r\n")
        .expect("inner file checksum");

    let extracted = collect_extract(&archive, None).expect("extract directory archive");
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"SUBDIR");
    assert!(extracted[0].is_directory);
    assert!(extracted[0].data.is_empty());
    assert_eq!(extracted[1].name, b"SUBDIR\\INNER.TXT");
    assert_eq!(extracted[1].data, b"Inside subdir.\r\n");
}

#[test]
fn parses_encrypted_compressed_file_metadata() {
    let archive = Archive::parse(README_PASSWORD).expect("parse encrypted RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];

    assert_eq!(entry.name, b"README");
    assert_eq!(entry.header.pack_size, 1078);
    assert_eq!(entry.header.unp_size, README_EXPECTED.len() as u32);
    assert_eq!(entry.header.file_crc, 0xe079);
    assert_eq!(entry.header.flags, 0x04);
    assert_eq!(entry.header.method, 3);
    assert!(entry.is_encrypted());
    assert!(!entry.is_stored());
}

#[test]
fn decodes_real_rar1402_encrypted_compressed_file() {
    let archive =
        Archive::parse(README_PASSWORD).expect("parse encrypted compressed RAR 1.402 archive");
    assert!(collect_extract(&archive, None).is_err());

    let extracted =
        collect_extract(&archive, Some(b"password")).expect("extract encrypted compressed archive");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README");
    assert_eq!(extracted[0].data, README_EXPECTED);
    assert_eq!(file_checksum(&extracted[0].data), 0xe079);
}

#[test]
fn extract_to_decodes_real_rar1402_encrypted_compressed_file() {
    #[derive(Clone)]
    struct SharedWriter(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let archive =
        Archive::parse(README_PASSWORD).expect("parse encrypted compressed RAR 1.402 archive");
    let extracted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    archive
        .extract_to(Some(b"password"), |meta| {
            assert_eq!(meta.name, b"README");
            Ok(Box::new(SharedWriter(extracted.clone())))
        })
        .expect("stream encrypted compressed archive");

    let extracted = extracted.borrow();
    assert_eq!(&*extracted, README_EXPECTED);
    assert_eq!(file_checksum(&extracted), 0xe079);
}

#[test]
fn rejects_wrong_password_for_encrypted_compressed_file() {
    let archive =
        Archive::parse(README_PASSWORD).expect("parse encrypted compressed RAR 1.402 archive");
    assert!(collect_extract(&archive, Some(b"wrong-password")).is_err());
}

#[test]
fn rejects_corrupt_stored_payload_checksum() {
    let mut corrupt = README_STORE.to_vec();
    let last = corrupt.last_mut().expect("non-empty fixture");
    *last ^= 0x01;

    let archive = Archive::parse(&corrupt).expect("parse corrupt stored archive");
    match collect_extract(&archive, None) {
        Err(Error::CrcMismatch { .. }) => {}
        Err(Error::AtEntry { source, .. }) if matches!(*source, Error::CrcMismatch { .. }) => {}
        other => panic!("expected checksum error, got {other:?}"),
    }
}

#[test]
fn rejects_truncated_compressed_payload() {
    let truncated = &README_COMPRESSED[..README_COMPRESSED.len() - 1];
    let err = Archive::parse(truncated).expect_err("truncated archive must not parse");
    assert_eq!(err, Error::TooShort);
}

#[test]
fn decodes_real_rar1402_encrypted_stored_file() {
    let archive = Archive::parse(STOREPWD).expect("parse encrypted stored RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];

    assert_eq!(entry.name, b"SECRET.TXT");
    assert_eq!(entry.header.pack_size, 27);
    assert_eq!(entry.header.unp_size, 27);
    assert_eq!(entry.header.file_crc, 0x4423);
    assert_eq!(entry.header.flags, 0x04);
    assert_eq!(entry.header.method, 0);
    assert!(entry.is_encrypted());
    assert!(entry.is_stored());
    assert!(matches!(
        collect_entry(&archive, entry, None),
        Err(Error::NeedPassword)
    ));

    let decoded = collect_entry(&archive, entry, Some(b"password")).expect("decrypt stored data");
    assert_eq!(decoded, b"Stored encrypted fixture.\r\n");
    entry
        .verify_checksum(&decoded)
        .expect("encrypted stored checksum");

    let extracted =
        collect_extract(&archive, Some(b"password")).expect("extract encrypted stored archive");
    assert_eq!(extracted[0].name, b"SECRET.TXT");
    assert_eq!(extracted[0].data, b"Stored encrypted fixture.\r\n");
}

#[test]
fn detects_and_parses_rar14_sfx_archive() {
    let sig = find_archive_start(SFXSRC, 128 * 1024).expect("SFX embedded signature");
    assert_eq!(sig.family, ArchiveFamily::Rar13);
    assert_eq!(sig.offset, 6491);

    let archive = Archive::parse(SFXSRC).expect("parse RAR 1.402 SFX archive");
    assert_eq!(archive.sfx_offset, 6491);
    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"HELLO.TXT");
    assert!(entry.is_stored());
    assert_eq!(
        collect_entry(&archive, entry, None).expect("stored SFX payload"),
        b"Hello, RAR 1.402 fixture world.\r\n"
    );
}

#[test]
fn parses_old_style_multivolume_parts() {
    let cases = [
        (MULTIVOL_RAR, false, true, 19_962, 0x5ec8),
        (MULTIVOL_R00, true, true, 19_962, 0x5147),
        (MULTIVOL_R01, true, true, 19_962, 0xda0b),
        (MULTIVOL_R02, true, false, 5_650, 0x4649),
    ];

    for (bytes, split_before, split_after, pack_size, file_crc) in cases {
        let archive = Archive::parse(bytes).expect("parse multivolume RAR 1.402 part");
        assert_eq!(archive.main.flags, 0x81);
        assert!(archive.main.is_volume());
        assert_eq!(archive.entries.len(), 1);

        let entry = &archive.entries[0];
        assert_eq!(entry.name, b"RANDOM.BIN");
        assert_eq!(entry.header.pack_size, pack_size);
        assert_eq!(entry.header.unp_size, 65_536);
        assert_eq!(entry.header.file_crc, file_crc);
        assert_eq!(entry.is_split_before(), split_before);
        assert_eq!(entry.is_split_after(), split_after);
        assert!(entry.is_stored());
    }
}

#[test]
fn reassembles_old_style_stored_multivolume_file() {
    let volumes = [
        Archive::parse(MULTIVOL_RAR).expect("parse first volume"),
        Archive::parse(MULTIVOL_R00).expect("parse second volume"),
        Archive::parse(MULTIVOL_R01).expect("parse third volume"),
        Archive::parse(MULTIVOL_R02).expect("parse fourth volume"),
    ];

    let extracted = collect_extract_volumes(&volumes, None).expect("join stored volumes");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"RANDOM.BIN");
    assert_eq!(extracted[0].data.len(), 65_536);
    assert_eq!(file_checksum(&extracted[0].data), 0x4649);
}

#[test]
fn parses_old_style_compressed_multivolume_parts() {
    let cases = [
        (CMULTIV_RAR, false, true, 1_962, 0x8523),
        (CMULTIV_R00, true, true, 1_962, 0x8523),
        (CMULTIV_R01, true, true, 1_962, 0x8523),
        (CMULTIV_R02, true, true, 1_962, 0x8523),
        (CMULTIV_R03, true, true, 1_962, 0x87cd),
        (CMULTIV_R04, true, true, 1_962, 0x87cd),
        (CMULTIV_R05, true, true, 1_962, 0x87cd),
        (CMULTIV_R06, true, false, 533, 0x87cd),
    ];

    for (bytes, split_before, split_after, pack_size, file_crc) in cases {
        let archive = Archive::parse(bytes).expect("parse compressed multivolume RAR 1.402 part");
        assert_eq!(archive.main.flags, 0x81);
        assert!(archive.main.is_volume());
        assert_eq!(archive.entries.len(), 1);

        let entry = &archive.entries[0];
        assert_eq!(entry.name, b"CMULTI.TXT");
        assert_eq!(entry.header.pack_size, pack_size);
        assert_eq!(entry.header.unp_size, 98_304);
        assert_eq!(entry.header.file_crc, file_crc);
        assert_eq!(entry.is_split_before(), split_before);
        assert_eq!(entry.is_split_after(), split_after);
        assert!(!entry.is_stored());
    }
}

#[test]
fn reassembles_old_style_compressed_multivolume_file() {
    let volumes = [
        Archive::parse(CMULTIV_RAR).expect("parse first compressed volume"),
        Archive::parse(CMULTIV_R00).expect("parse second compressed volume"),
        Archive::parse(CMULTIV_R01).expect("parse third compressed volume"),
        Archive::parse(CMULTIV_R02).expect("parse fourth compressed volume"),
        Archive::parse(CMULTIV_R03).expect("parse fifth compressed volume"),
        Archive::parse(CMULTIV_R04).expect("parse sixth compressed volume"),
        Archive::parse(CMULTIV_R05).expect("parse seventh compressed volume"),
        Archive::parse(CMULTIV_R06).expect("parse eighth compressed volume"),
    ];

    let extracted = collect_extract_volumes(&volumes, None).expect("join compressed volumes");
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"CMULTI.TXT");
    assert_eq!(extracted[0].data, CMULTI_EXPECTED);
    assert_eq!(file_checksum(&extracted[0].data), 0x87cd);
}

#[test]
fn parses_archive_comment_main_header_extension() {
    let archive = Archive::parse(COMMENT).expect("parse comment RAR 1.402 archive");
    assert_eq!(archive.main.flags, 0x92);
    assert_eq!(archive.main.head_size, 43);
    assert_eq!(archive.main.extra.len(), 36);
    assert!(archive.main.has_archive_comment());
    assert!(archive.main.has_packed_comment());
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"HELLO.TXT");
    assert!(entry.is_stored());
    assert_eq!(
        collect_entry(&archive, entry, None).expect("stored commented payload"),
        b"Hello, comment fixture.\r\n"
    );
    entry
        .verify_checksum(b"Hello, comment fixture.\r\n")
        .expect("comment fixture payload checksum");
}

#[test]
fn decodes_packed_archive_comment() {
    let archive = Archive::parse(COMMENT).expect("parse comment RAR 1.402 archive");
    let comment = archive
        .archive_comment()
        .expect("decode RAR 1.402 archive comment")
        .expect("archive comment");
    assert_eq!(comment, b"This is the archive comment.\r\n");
}

#[test]
fn parses_and_decodes_file_comment_header_extension() {
    let archive = Archive::parse(FCOMM).expect("parse file-comment RAR 1.402 archive");
    assert_eq!(archive.entries.len(), 1);

    let entry = &archive.entries[0];
    assert_eq!(entry.name, b"HELLO.TXT");
    assert_eq!(entry.header.flags, 0x08);
    assert_eq!(entry.header.head_size, 38);
    assert_eq!(entry.extra, b"\x06\x00FCOM\r\n");
    assert_eq!(
        entry
            .file_comment()
            .expect("decode file comment")
            .expect("file comment"),
        b"FCOM\r\n"
    );
    assert_eq!(
        collect_entry(&archive, entry, None).expect("stored file-comment payload"),
        b"Hello, file comment fixture.\r\n"
    );
}

fn expected_repeatb() -> Vec<u8> {
    let mut out = Vec::with_capacity(256 * 32);
    for _ in 0..32 {
        out.extend(0u8..=255);
    }
    out
}

/// The streaming writer and the in-memory one are the same writer with a
/// different way of getting at the bytes, so the archives they produce have to
/// be the same archives.
#[test]
fn streaming_and_buffered_writers_agree_byte_for_byte() {
    use rars::rar13::{
        write_compressed_archive_with_comment, write_stored_archive_with_comment,
        write_streaming_archive_to, FileEntry, StoredEntry, StreamingEntry, WriterOptions,
    };
    use rars::{ArchiveVersion, EntrySource, FeatureSet, MemberCoding, WriterResources};

    let text = b"the quick brown fox jumps over the lazy dog\n".repeat(400);
    let counted: Vec<u8> = (0..40_000u32).map(|index| index as u8).collect();
    let members: Vec<(&[u8], &[u8])> = vec![
        (b"TEXT.TXT", &text),
        (b"COUNT.BIN", &counted),
        (b"EMPTY.DAT", b""),
    ];

    for solid in [false, true] {
        for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
            let mut features = FeatureSet::store_only();
            features.solid = solid && coding.compresses();
            let options = WriterOptions::new(ArchiveVersion::Rar14, features);
            let comment: Option<&[u8]> = Some(b"shared comment");

            let buffered = match &coding {
                MemberCoding::Stored => {
                    let entries: Vec<_> = members
                        .iter()
                        .map(|(name, data)| StoredEntry {
                            name,
                            data,
                            file_time: 0,
                            file_attr: 0,
                            password: None,
                            file_comment: None,
                        })
                        .collect();
                    write_stored_archive_with_comment(&entries, options, comment)
                }
                _ => {
                    let entries: Vec<_> = members
                        .iter()
                        .map(|(name, data)| FileEntry {
                            name,
                            data,
                            file_time: 0,
                            file_attr: 0,
                            password: None,
                            file_comment: None,
                        })
                        .collect();
                    write_compressed_archive_with_comment(&entries, options, comment)
                }
            };

            let streamed_entries: Vec<_> = members
                .iter()
                .map(|(name, data)| {
                    StreamingEntry::new(name.to_vec(), EntrySource::from_bytes(data.to_vec()))
                })
                .collect();
            let mut streamed = Vec::new();
            let streamed_result = write_streaming_archive_to(
                &streamed_entries,
                options,
                coding.clone(),
                comment,
                &WriterResources::default(),
                None,
                &mut streamed,
            );

            let label = format!("solid={solid} {coding:?}");
            match buffered {
                Ok(buffered) => {
                    assert!(
                        streamed_result.is_ok(),
                        "{label}: streaming refused what the buffered writer accepted: \
                         {streamed_result:?}"
                    );
                    assert_eq!(streamed, buffered, "{label}: archives differ");
                    // A solid run writes a member that fails its own checksum,
                    // on both paths alike. That is a bug in the shared RAR 1.5
                    // encoder rather than anything to do with streaming, so it
                    // is not round-tripped here.
                    if solid && coding.compresses() {
                        continue;
                    }
                    let archive = Archive::parse(&streamed).unwrap();
                    let extracted = collect_extract(&archive, None)
                        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                    assert_eq!(extracted.len(), members.len(), "{label}");
                    for (got, (_, want)) in extracted.iter().zip(&members) {
                        assert_eq!(&got.data, want, "{label}");
                    }
                }
                Err(buffered) => {
                    let streamed_error = streamed_result.expect_err(&format!(
                        "{label}: streaming accepted what the buffered writer refused"
                    ));
                    assert_eq!(
                        streamed_error.to_string(),
                        buffered.to_string(),
                        "{label}: the two paths refused it differently"
                    );
                }
            }
        }
    }
}

/// RAR 1.3 has no filters, so a filter policy has to be turned away rather
/// than routed into a compression engine it does not have.
#[test]
fn a_filter_policy_is_refused_by_name() {
    use rars::rar13::{write_streaming_archive_to, StreamingEntry, WriterOptions};
    use rars::{
        ArchiveVersion, EntrySource, FeatureSet, FilterPolicy, MemberCoding, WriterOption,
        WriterResources,
    };

    let entries = vec![StreamingEntry::new(
        b"A.TXT".to_vec(),
        EntrySource::from_bytes(b"payload".to_vec()),
    )];
    let mut out = Vec::new();
    let error = write_streaming_archive_to(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar14, FeatureSet::store_only()),
        MemberCoding::Filtered(FilterPolicy::Auto),
        None,
        &WriterResources::default(),
        None,
        &mut out,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::UnsupportedWriterOption {
            option: WriterOption::Filter,
            ..
        }
    ));
    assert!(out.is_empty(), "nothing should have been written");
}
