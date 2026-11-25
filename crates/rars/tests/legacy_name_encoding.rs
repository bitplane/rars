#![cfg(feature = "write")]

use rars::{
    filename::{decoded_name, LegacyNameEncoding},
    ArchiveReader, ArchiveVersion, Builder, Error,
};

#[cfg(feature = "cjk-names")]
#[test]
fn cjk_code_pages_decode_legacy_names_in_listing_and_extraction() {
    for (encoding, codec, name) in [
        (
            LegacyNameEncoding::Cp932,
            encoding_rs::SHIFT_JIS,
            "漫画/第1話/ページ01.jpg",
        ),
        (
            LegacyNameEncoding::Cp936,
            encoding_rs::GBK,
            "漫画/第1话/第01页.jpg",
        ),
        (
            LegacyNameEncoding::Cp949,
            encoding_rs::EUC_KR,
            "만화/제1화/페이지01.jpg",
        ),
        (
            LegacyNameEncoding::Cp950,
            encoding_rs::BIG5,
            "漫畫/第1話/第01頁.jpg",
        ),
    ] {
        let (raw, _, had_errors) = codec.encode(name);
        assert!(!had_errors, "{encoding:?} could not encode {name}");
        assert_eq!(
            decoded_name(name.as_bytes(), true, Some(encoding))
                .unwrap()
                .as_ref(),
            name.as_bytes()
        );

        for format in [ArchiveVersion::Rar29, ArchiveVersion::Rar15] {
            let mut builder = Builder::new(format).store(true);
            builder
                .add_bytes(raw.to_vec(), b"data".to_vec(), None, None)
                .unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let member = archive.members().next().unwrap();
            assert!(!member.name_is_unicode());
            assert_eq!(member.meta.name, raw.as_ref());
            assert_eq!(
                member.decoded_name(Some(encoding)).unwrap().as_ref(),
                name.as_bytes()
            );

            let mut extracted = Vec::new();
            archive
                .extract_to(None, |meta| {
                    assert!(!meta.name_is_unicode);
                    assert_eq!(meta.name, raw.as_ref());
                    extracted.push(
                        decoded_name(&meta.name, meta.name_is_unicode, Some(encoding))?
                            .into_owned(),
                    );
                    Ok(Box::new(std::io::sink()))
                })
                .unwrap();
            assert_eq!(extracted, [name.as_bytes()]);
        }
    }
}

#[cfg(feature = "cjk-names")]
#[test]
fn malformed_cjk_names_fail_like_undefined_single_byte_names() {
    let name = b"bad-\x81";
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(name.to_vec(), b"data".to_vec(), None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let member = archive.members().next().unwrap();
    let single_byte = member
        .decoded_name(Some(LegacyNameEncoding::Windows1252))
        .unwrap_err();
    let cjk = member
        .decoded_name(Some(LegacyNameEncoding::Cp932))
        .unwrap_err();
    assert_eq!(cjk.kind(), single_byte.kind());
    assert_eq!(cjk.to_string(), single_byte.to_string());
    assert!(matches!(cjk.root_cause(), Error::InvalidArgument(_)));
}

#[cfg(feature = "cjk-names")]
#[test]
fn cjk_code_page_aliases_are_case_insensitive() {
    for (encoding, aliases) in [
        (
            LegacyNameEncoding::Cp932,
            ["cp932", "shift_jis", "shift-jis", "sjis", "windows-31j"].as_slice(),
        ),
        (LegacyNameEncoding::Cp936, &["cp936", "gbk"]),
        (LegacyNameEncoding::Cp949, &["cp949", "euc-kr", "uhc"]),
        (LegacyNameEncoding::Cp950, &["cp950", "big5"]),
        (LegacyNameEncoding::Detect, &["detect", "auto"]),
    ] {
        for alias in aliases {
            assert_eq!(alias.parse::<LegacyNameEncoding>().unwrap(), encoding);
            assert_eq!(
                alias
                    .to_ascii_uppercase()
                    .parse::<LegacyNameEncoding>()
                    .unwrap(),
                encoding
            );
        }
    }
    assert!(matches!(
        "cp999".parse::<LegacyNameEncoding>(),
        Err(Error::InvalidArgument(_))
    ));
}

#[cfg(not(feature = "cjk-names"))]
#[test]
fn cjk_code_pages_report_the_disabled_feature() {
    for label in ["detect", "auto"] {
        assert!(matches!(
            label.parse::<LegacyNameEncoding>(),
            Err(Error::FeatureDisabled {
                feature: "cjk-names"
            })
        ));
    }
    for (label, encoding) in [
        ("shift_jis", LegacyNameEncoding::Cp932),
        ("gbk", LegacyNameEncoding::Cp936),
        ("euc-kr", LegacyNameEncoding::Cp949),
        ("big5", LegacyNameEncoding::Cp950),
    ] {
        for error in [
            label.parse::<LegacyNameEncoding>().unwrap_err(),
            encoding.decode(b"ascii").unwrap_err(),
        ] {
            assert!(matches!(
                error,
                Error::FeatureDisabled {
                    feature: "cjk-names"
                }
            ));
            assert_eq!(error.kind(), rars::ErrorKind::UnsupportedFeature);
            assert_eq!(error.to_string(), "Cargo feature cjk-names is disabled");
        }
    }
}

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
    assert!("bogus".parse::<LegacyNameEncoding>().is_err());
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
            builder
                .set_legacy_unicode_name("café.txt".as_bytes(), wire)
                .unwrap();
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
fn rar3_direct_utf8_unicode_name_round_trips_without_a_separator() {
    let name = "café.txt".as_bytes();
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(name.to_vec(), b"data".to_vec(), None, None)
        .unwrap();
    builder
        .set_legacy_unicode_name(name, name.to_vec())
        .unwrap();

    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let member = archive.members().next().unwrap();
    assert_eq!(member.meta.name, name);
    assert!(member.name_is_unicode());
    assert_eq!(member.decoded_name(None).unwrap().as_ref(), name);

    let invalid = b"\xff.txt";
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(invalid.to_vec(), b"data".to_vec(), None, None)
        .unwrap();
    assert!(builder
        .set_legacy_unicode_name(invalid, invalid.to_vec())
        .is_err());
}

#[test]
fn legacy_unicode_metadata_is_validated_and_renamed_with_its_member() {
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(b"old.txt".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let before = builder.to_bytes().unwrap();
    assert!(builder
        .set_legacy_unicode_name(b"old.txt", b"bad".to_vec())
        .is_err());
    assert_eq!(builder.to_bytes().unwrap(), before);

    let mut wire = b"old.txt\0\0".to_vec();
    for group in "old.txt".encode_utf16().collect::<Vec<_>>().chunks(4) {
        wire.push(0xaa);
        for unit in group {
            wire.extend_from_slice(&unit.to_le_bytes());
        }
    }
    builder
        .set_legacy_unicode_name(b"old.txt", wire.clone())
        .unwrap();
    builder.rename(b"old.txt", b"new.txt".to_vec()).unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let member = archive.members().next().unwrap();
    assert_eq!(member.meta.name, b"new.txt");
    assert!(member.name_is_unicode());

    let mut old = Builder::new(ArchiveVersion::Rar15).store(true);
    old.add_bytes(b"old.txt".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    assert!(old.set_legacy_unicode_name(b"old.txt", wire).is_err());

    let mut volume = Builder::new(ArchiveVersion::Rar29)
        .store(true)
        .volume_size(Some(512));
    volume
        .add_bytes(b"old.txt".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    assert!(volume
        .set_legacy_unicode_name(b"old.txt", b"old.txt\0\0".to_vec())
        .is_err());
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

#[test]
fn unresolved_detection_cannot_decode_names() {
    let error =
        Error::InvalidArgument("resolve Detect with Archive::detect_legacy_name_encoding first");
    assert_eq!(
        LegacyNameEncoding::Detect.decode(b"page.jpg"),
        Err(error.clone())
    );
    for unicode in [false, true] {
        assert_eq!(
            decoded_name(b"page.jpg", unicode, Some(LegacyNameEncoding::Detect)),
            Err(error.clone())
        );
    }
}

#[cfg(feature = "cjk-names")]
#[test]
fn detects_legacy_page_names_in_archives_and_volume_sets() {
    use encoding_rs::{BIG5, EUC_KR, GBK, SHIFT_JIS, WINDOWS_1251};
    use LegacyNameEncoding::*;

    for (expected, codec, book, prefix, suffix) in [
        (Cp932, SHIFT_JIS, "漫画の冒険と旅の物語", "ページ", ""),
        (Cp936, GBK, "漫画故事与旅行见闻", "第", "页"),
        (Cp949, EUC_KR, "만화로 보는 여행 이야기", "페이지", ""),
        (Cp950, BIG5, "漫畫故事與旅行見聞", "第", "頁"),
        (
            Windows1251,
            WINDOWS_1251,
            "Приключения и путешествия",
            "Страница",
            "",
        ),
    ] {
        let names: Vec<_> = (1..=20)
            .map(|index| format!("{book}/{prefix}{index:02}{suffix}.jpg"))
            .collect();
        for format in [ArchiveVersion::Rar29, ArchiveVersion::Rar15] {
            let mut builder = Builder::new(format).store(true);
            for name in &names {
                let (raw, _, errors) = codec.encode(name);
                assert!(!errors, "{name}");
                builder
                    .add_bytes(raw.into_owned(), vec![42; 128], None, None)
                    .unwrap();
            }
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let encoding = archive.detect_legacy_name_encoding();
            assert_eq!(encoding, Some(expected), "{format:?} {book}");
            let listed: Vec<_> = archive
                .member_refs()
                .map(|member| {
                    assert!(!member.name_is_unicode());
                    String::from_utf8(member.decoded_name(encoding).unwrap().into_owned()).unwrap()
                })
                .collect();
            assert_eq!(listed, names);
            let mut extracted = Vec::new();
            archive
                .extract_to(None, |meta| {
                    let bytes =
                        decoded_name(&meta.name, meta.name_is_unicode, encoding)?.into_owned();
                    extracted.push(String::from_utf8(bytes).unwrap());
                    Ok(Box::new(std::io::sink()))
                })
                .unwrap();
            assert_eq!(extracted, names);

            let archives: Vec<_> = builder
                .volume_size(Some(512))
                .build_volumes(None)
                .unwrap()
                .into_iter()
                .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
                .collect();
            assert!(archives.len() > 1);
            assert_eq!(
                rars::detect_volume_legacy_name_encoding(&archives),
                encoding
            );
        }
    }
}

#[test]
fn ascii_only_names_need_no_detected_encoding() {
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    for name in [b"page01.jpg", b"page02.jpg"] {
        builder
            .add_bytes(name.to_vec(), vec![], None, None)
            .unwrap();
    }
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let encoding = archive.detect_legacy_name_encoding();
    assert_eq!(encoding, None);
    assert_eq!(
        archive
            .member_refs()
            .map(|member| member.decoded_name(encoding).unwrap())
            .collect::<Vec<_>>(),
        [b"page01.jpg".as_slice(), b"page02.jpg".as_slice()]
    );
}

#[cfg(feature = "cjk-names")]
#[test]
fn detection_rejects_a_guess_with_undefined_bytes() {
    let names = [b"caf\xe9.jpg".as_slice(), b"bad-\x81.jpg"];
    let mut detector = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Allow);
    detector.feed(&names.join(&0), true);
    assert_eq!(
        detector.guess(None, chardetng::Utf8Detection::Allow),
        encoding_rs::WINDOWS_1252
    );
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    for name in names {
        builder
            .add_bytes(name.to_vec(), vec![], None, None)
            .unwrap();
    }
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(archive.detect_legacy_name_encoding(), None);
}
