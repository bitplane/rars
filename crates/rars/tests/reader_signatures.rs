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
        for offset in [prefix.len() + 1, image.len(), image.len() + 1] {
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
