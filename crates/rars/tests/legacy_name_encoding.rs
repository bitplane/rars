use rars::{
    filename::{decoded_name, LegacyNameEncoding},
    ArchiveReader, ArchiveVersion, Builder,
};

#[test]
fn strict_code_pages_are_explicit_and_locale_independent() {
    for (label, bytes, expected) in [
        ("cp437", b"caf\x82".as_slice(), "café"),
        ("CP850", b"\x9b".as_slice(), "ø"),
        ("cp852", b"\x88".as_slice(), "ł"),
        ("cp866", b"\x80".as_slice(), "А"),
        ("windows-1251", b"\xc0".as_slice(), "А"),
        ("windows-1252", b"\x80".as_slice(), "€"),
        ("utf-8", "日本語".as_bytes(), "日本語"),
    ] {
        let encoding: LegacyNameEncoding = label.parse().unwrap();
        assert_eq!(encoding.decode(bytes).unwrap(), expected);
    }
    assert!("auto".parse::<LegacyNameEncoding>().is_err());
    assert!(LegacyNameEncoding::Windows1252.decode(b"\x81").is_err());
    assert!(LegacyNameEncoding::Windows1251.decode(b"\x98").is_err());
    assert!(LegacyNameEncoding::Utf8.decode(b"\xff").is_err());
    assert_eq!(
        decoded_name(b"\x82", false, None).unwrap().as_ref(),
        b"\x82"
    );
    assert_eq!(
        decoded_name("café".as_bytes(), true, Some(LegacyNameEncoding::Cp850))
            .unwrap()
            .as_ref(),
        "café".as_bytes()
    );
}

#[test]
fn legacy_views_and_callbacks_preserve_original_identity() {
    for format in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"caf\x82.txt".to_vec(), b"data".to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let member = archive.members().next().unwrap();
        assert!(!member.name_is_unicode());
        assert_eq!(
            member
                .decoded_name(Some(LegacyNameEncoding::Cp850))
                .unwrap()
                .as_ref(),
            "café.txt".as_bytes()
        );
        assert_eq!(member.meta.name, b"caf\x82.txt");
        archive
            .extract_to(None, |meta| {
                assert!(!meta.name_is_unicode);
                assert_eq!(meta.name, b"caf\x82.txt");
                Ok(Box::new(std::io::sink()))
            })
            .unwrap();
    }
}

#[test]
fn unicode_names_take_precedence_in_metadata_and_extraction() {
    for format in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes("café.txt".as_bytes().to_vec(), b"data".to_vec(), None, None)
            .unwrap();
        if format == ArchiveVersion::Rar29 {
            // Explicit full UTF-16 commands for café.txt, independent of fallback.
            let mut wire = b"cafe.txt\0\0".to_vec();
            let units: Vec<_> = "café.txt".encode_utf16().collect();
            for group in units.chunks(4) {
                wire.push(0xaa);
                for unit in group {
                    wire.extend_from_slice(&unit.to_le_bytes());
                }
            }
            builder.set_legacy_unicode_name_by_id(0, wire).unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let member = archive.members().next().unwrap();
        assert!(member.name_is_unicode());
        assert_eq!(
            member
                .decoded_name(Some(LegacyNameEncoding::Cp850))
                .unwrap()
                .as_ref(),
            "café.txt".as_bytes()
        );
        archive
            .extract_to(None, |meta| {
                assert!(meta.name_is_unicode);
                Ok(Box::new(std::io::sink()))
            })
            .unwrap();
    }
}

#[test]
fn split_legacy_names_keep_their_encoding_classification() {
    let mut builder = Builder::new(ArchiveVersion::Rar29)
        .store(true)
        .volume_size(Some(512));
    builder
        .add_bytes(b"caf\x82.txt".to_vec(), vec![42; 4096], None, None)
        .unwrap();
    let archives: Vec<_> = builder
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect();
    rars::extract_volumes_to(&archives, None, |meta| {
        assert!(!meta.name_is_unicode);
        assert_eq!(
            decoded_name(
                &meta.name,
                meta.name_is_unicode,
                Some(LegacyNameEncoding::Cp850)
            )
            .unwrap()
            .as_ref(),
            "café.txt".as_bytes()
        );
        Ok(Box::new(std::io::sink()))
    })
    .unwrap();
}
