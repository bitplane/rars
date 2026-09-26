#[path = "support/scratch.rs"]
mod scratch;

use rars::{detect_archive_family, find_archive_start, rar15_40, rar50, ArchiveReadOptions, Error};

#[test]
fn typed_path_parsers_validate_explicit_signatures_and_sfx_offsets() {
    let legacy = include_bytes!("fixtures/rar15_40/rar300/stored_multivol_rar300.rar");
    let modern = include_bytes!("fixtures/rar50/stored.rar");
    let root = scratch::case("reader-signature-boundaries");
    let prefix = b"an SFX stub without a RAR signature";
    for (is_modern, bytes) in [(false, legacy.as_slice()), (true, modern.as_slice())] {
        let mut image = prefix.to_vec();
        image.extend_from_slice(bytes);
        let path = root.join(if is_modern {
            "modern.rar"
        } else {
            "legacy.rar"
        });
        std::fs::write(&path, &image).unwrap();
        let signature = find_archive_start(&image, image.len()).unwrap();
        assert_eq!(signature.offset, prefix.len());
        if is_modern {
            for archive in [
                rar50::Archive::parse_path(&path).unwrap(),
                rar50::Archive::parse_path_with_signature_and_password(&path, signature, None)
                    .unwrap(),
            ] {
                assert_eq!(archive.sfx_offset, prefix.len());
                let file = archive.files().next().unwrap();
                assert_eq!(
                    file.packed_data(&archive).unwrap(),
                    b"Hello, RAR 5.0 fixture world.\n"
                );
            }
            assert!(matches!(
                rar50::Archive::parse(legacy),
                Err(Error::UnsupportedSignature)
            ));
            let wrong = detect_archive_family(legacy).unwrap();
            assert!(matches!(
                rar50::Archive::parse_path_with_signature(&path, wrong, ArchiveReadOptions::new()),
                Err(Error::UnsupportedSignature)
            ));
        } else {
            for archive in [
                rar15_40::Archive::parse_path(&path).unwrap(),
                rar15_40::Archive::parse_path_with_signature_and_password(&path, signature, None)
                    .unwrap(),
            ] {
                assert_eq!(archive.sfx_offset, prefix.len());
                assert!(archive.files().next().is_some());
            }
            assert!(matches!(
                rar15_40::Archive::parse(modern),
                Err(Error::UnsupportedSignature)
            ));
            let wrong = detect_archive_family(modern).unwrap();
            assert!(matches!(
                rar15_40::Archive::parse_path_with_signature(
                    &path,
                    wrong,
                    ArchiveReadOptions::new()
                ),
                Err(Error::UnsupportedSignature)
            ));
        }
        for offset in [prefix.len() + 1, image.len(), image.len() + 1, usize::MAX] {
            let mut invalid = signature;
            invalid.offset = offset;
            let result = if is_modern {
                rar50::Archive::parse_path_with_signature(&path, invalid, ArchiveReadOptions::new())
                    .map(|_| ())
            } else {
                rar15_40::Archive::parse_path_with_signature(
                    &path,
                    invalid,
                    ArchiveReadOptions::new(),
                )
                .map(|_| ())
            };
            assert!(result.is_err(), "offset {offset}");
        }
        std::fs::write(
            &path,
            if is_modern {
                legacy.as_slice()
            } else {
                modern.as_slice()
            },
        )
        .unwrap();
        let result = if is_modern {
            rar50::Archive::parse_path(&path).map(|_| ())
        } else {
            rar15_40::Archive::parse_path(&path).map(|_| ())
        };
        assert!(matches!(result, Err(Error::UnsupportedSignature)));
    }
}

#[test]
fn legacy_stored_member_reports_source_truncation_after_header_read() {
    let root = scratch::case("legacy-source-truncation");
    let path = root.join("truncated.rar");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar30).compression_level(Some(0));
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    std::fs::write(&path, builder.to_bytes().unwrap()).unwrap();
    let archive = rar15_40::Archive::parse_path(&path).unwrap();
    let file = archive.files().next().unwrap();
    assert!(file.is_stored());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len((file.packed_range.start + 2) as u64)
        .unwrap();
    let mut output = Vec::new();
    let error = file.write_to(&archive, None, &mut output).unwrap_err();
    assert!(matches!(
        error.root_cause(),
        Error::InvalidHeader("RAR 1.5 stored file ended before unpacked size")
    ));
    assert_eq!(output, b"pa");
}

#[test]
fn explicit_legacy_signatures_still_require_the_exact_marker_block() {
    let root = scratch::case("legacy-marker-admission");
    let path = root.join("marker.rar");
    let legacy = include_bytes!("fixtures/rar15_40/rar300/stored_multivol_rar300.rar");
    let signature = detect_archive_family(legacy).unwrap();
    let mut wrong_size = legacy[..7].to_vec();
    wrong_size[5] = 8;
    wrong_size.push(0);
    for bytes in [legacy[7..20].to_vec(), wrong_size] {
        std::fs::write(&path, bytes).unwrap();
        let error = rar15_40::Archive::parse_path_with_signature(
            &path,
            signature,
            ArchiveReadOptions::new(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidHeader("RAR 1.5 marker block is invalid")
        ));
    }
}

#[test]
fn seekable_legacy_parser_retains_historical_protection_headers() {
    let root = scratch::case("legacy-protect-header");
    let path = root.join("protected.rar");
    let bytes = include_bytes!("fixtures/rar15_40/rar250_protect_head_rr5.rar");
    std::fs::write(&path, bytes).unwrap();
    let memory = rar15_40::Archive::parse(bytes).unwrap();
    let seekable = rar15_40::Archive::parse_path(&path).unwrap();
    assert!(memory
        .blocks
        .iter()
        .any(|b| matches!(b, rar15_40::Block::Protect(_))));
    assert_eq!(memory.blocks, seekable.blocks);
}

#[test]
fn source_failure_while_rereading_legacy_main_header_stays_an_io_error() {
    struct Reader {
        bytes: std::io::Cursor<Vec<u8>>,
        main_reads: usize,
    }
    impl std::io::Read for Reader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.bytes.position() == 7 {
                self.main_reads += 1;
                if self.main_reads == 3 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "main header read failed",
                    ));
                }
            }
            std::io::Read::read(&mut self.bytes, output)
        }
    }
    impl std::io::Seek for Reader {
        fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
            std::io::Seek::seek(&mut self.bytes, from)
        }
    }
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar30);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let error = rars::ArchiveReader::read_reader(Reader {
        bytes: std::io::Cursor::new(builder.to_bytes().unwrap()),
        main_reads: 0,
    })
    .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
    assert!(error.to_string().contains("main header read failed"));
}
