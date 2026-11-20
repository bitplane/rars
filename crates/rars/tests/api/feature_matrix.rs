#[test]
fn plain_readers_and_fixed_key_comments_remain_available() {
    use rars::ArchiveReader;
    let cases: &[(&[u8], &[&[u8]])] = &[
        (
            include_bytes!("../fixtures/rar13/README.RAR"),
            &[include_bytes!("../fixtures/rar13/README")],
        ),
        (
            include_bytes!("../fixtures/rar15_40/rar300/solid_simple_rar300.rar"),
            &[
                b"shared prefix shared prefix shared prefix alpha\n",
                b"shared prefix shared prefix shared prefix beta\n",
            ],
        ),
        (
            include_bytes!("../fixtures/rar50/stored.rar"),
            &[b"Hello, RAR 5.0 fixture world.\n"],
        ),
    ];
    for &(data, expected) in cases {
        let archive = ArchiveReader::read(data).unwrap();
        assert_eq!(archive.members().count(), expected.len());
        for (index, bytes) in expected.iter().enumerate() {
            assert_eq!(
                &archive
                    .read_member_at(index, None)
                    .unwrap()
                    .expect("indexed member"),
                bytes
            );
        }
    }
    let archive = ArchiveReader::read(include_bytes!("../fixtures/rar13/COMMENT.RAR")).unwrap();
    assert_eq!(
        archive.comment(None).unwrap().unwrap(),
        b"This is the archive comment.\r\n"
    );
}

#[cfg(not(feature = "encryption"))]
#[test]
fn disabled_crypto_retains_metadata_and_typed_payload_and_header_refusals() {
    use rars::{ArchiveReadOptions, ArchiveReader, Error};
    for data in [
        include_bytes!("../fixtures/rar13/README_password=password.rar").as_slice(),
        include_bytes!("../fixtures/rar15_40/rar154/readme_154_password.rar").as_slice(),
        include_bytes!("../fixtures/rar15_40/encrypted/per_file_rar300_password.rar").as_slice(),
        include_bytes!("../fixtures/rar50/password_aes.rar").as_slice(),
    ] {
        for password in [None, Some(b"password".as_slice())] {
            let archive = ArchiveReader::read_with_options(
                data,
                ArchiveReadOptions::with_optional_password(password),
            )
            .unwrap();
            let index = archive.members().position(|m| m.meta.is_encrypted).unwrap();
            assert_eq!(
                archive
                    .read_member_at(index, password)
                    .unwrap_err()
                    .root_cause(),
                &Error::FeatureDisabled {
                    feature: "encryption"
                }
            );
        }
    }
    for data in [
        include_bytes!("../fixtures/rar15_40/encrypted/header_rar300_password.rar").as_slice(),
        include_bytes!("../fixtures/rar50/header_encrypted.rar").as_slice(),
    ] {
        for password in [None, Some(b"password".as_slice())] {
            assert_eq!(
                ArchiveReader::read_with_options(
                    data,
                    ArchiveReadOptions::with_optional_password(password)
                )
                .unwrap_err()
                .root_cause(),
                &Error::FeatureDisabled {
                    feature: "encryption"
                }
            );
        }
    }
    assert!(matches!(
        rars::crypto::rar50::Rar50Keys::derive(b"password", [0; 16], 255),
        Err(rars::crypto::rar50::Error::FeatureDisabled)
    ));
}

#[cfg(not(feature = "recovery"))]
#[test]
fn disabled_recovery_keeps_record_metadata_and_preserves_output() {
    use rars::{ArchiveReadOptions, ArchiveReader, Error, ReadCancellation};
    let data = include_bytes!("../fixtures/rar50/with_recovery.rar");
    let archive = ArchiveReader::read(data).unwrap();
    assert!(archive
        .as_rar50()
        .unwrap()
        .services()
        .any(|s| s.recovery_record().unwrap().is_some()));
    let mut output = b"untouched".to_vec();
    assert_eq!(
        archive
            .repair_recovery_to(&mut output)
            .unwrap_err()
            .root_cause(),
        &Error::FeatureDisabled {
            feature: "recovery"
        }
    );
    assert_eq!(output, b"untouched");
    let token = ReadCancellation::new();
    token.cancel();
    assert_eq!(
        archive
            .repair_recovery_with_options(ArchiveReadOptions::new().with_cancellation(&token))
            .unwrap_err()
            .root_cause(),
        &Error::FeatureDisabled {
            feature: "recovery"
        }
    );
}

#[cfg(all(feature = "write", not(feature = "encryption")))]
#[test]
fn disabled_encrypted_writers_refuse_before_source_access_or_output() {
    use rars::{ArchiveVersion, Builder, EntrySource, Error, WriterResources};
    for version in ArchiveVersion::ALL {
        let mut builder = Builder::new(version)
            .store(true)
            .password(Some(b"password".to_vec()));
        builder
            .add_source(
                b"file".to_vec(),
                EntrySource::from_opener(1, || panic!("crypto refusal must precede source access")),
                None,
                None,
            )
            .unwrap();
        let mut output = b"untouched".to_vec();
        assert_eq!(
            builder
                .write_to(&mut output, &WriterResources::default(), None)
                .unwrap_err()
                .root_cause(),
            &Error::FeatureDisabled {
                feature: "encryption"
            }
        );
        assert_eq!(output, b"untouched");
    }
}

#[cfg(all(feature = "write", not(feature = "recovery")))]
#[test]
fn disabled_recovery_writers_refuse_before_source_access_or_output() {
    use rars::{ArchiveVersion, Builder, EntrySource, Error, WriterResources};
    let mut builder = Builder::new(ArchiveVersion::Rar50).recovery_percent(Some(1));
    builder
        .add_source(
            b"file".to_vec(),
            EntrySource::from_opener(1, || panic!("recovery refusal must precede source access")),
            None,
            None,
        )
        .unwrap();
    let mut output = b"untouched".to_vec();
    assert_eq!(
        builder
            .write_to(&mut output, &WriterResources::default(), None)
            .unwrap_err()
            .root_cause(),
        &Error::FeatureDisabled {
            feature: "recovery"
        }
    );
    assert_eq!(output, b"untouched");
}

#[cfg(feature = "write")]
#[test]
fn small_explicit_delta_decodes_without_crypto_or_recovery() {
    use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions};
    use rars::{
        ArchiveReadOptions, ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, FilterKind,
        FilterPolicy, FilterSpec,
    };
    let data: Vec<u8> = (0..512).map(|i| (i / 4) as u8).collect();
    let bytes = Rar50Writer::new(
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(1)
            .with_dictionary_size(128 * 1024),
    )
    .entry(ArchiveEntry::new(
        b"small-delta".to_vec(),
        EntrySource::from_bytes(data.clone()),
    ))
    .filter_policy(FilterPolicy::Explicit(FilterSpec::whole(
        FilterKind::Delta { channels: 4 },
    )))
    .finish()
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    assert!(!archive
        .as_rar50()
        .unwrap()
        .files()
        .next()
        .unwrap()
        .is_stored());
    assert_eq!(archive.read_member_at(0, None).unwrap().unwrap(), data);
    // The streaming route applies the filter too.
    archive
        .test_with_options(ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0))
        .unwrap();
    let plain_bytes = Rar50Writer::new(
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(1)
            .with_dictionary_size(128 * 1024),
    )
    .entry(ArchiveEntry::new(
        b"small-plain".to_vec(),
        EntrySource::from_bytes(data.clone()),
    ))
    .filter_policy(FilterPolicy::None)
    .finish()
    .unwrap();
    let plain = ArchiveReader::read(&plain_bytes).unwrap();
    assert!(!plain
        .as_rar50()
        .unwrap()
        .files()
        .next()
        .unwrap()
        .is_stored());
    plain
        .test_with_options(ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0))
        .unwrap();
    assert_eq!(plain.read_member_at(0, None).unwrap().unwrap(), data);
    // The same bytes without the filter policy pack differently, so the
    // member above carries a filter command.
    assert_ne!(
        archive
            .as_rar50()
            .unwrap()
            .files()
            .next()
            .unwrap()
            .packed_size(),
        plain
            .as_rar50()
            .unwrap()
            .files()
            .next()
            .unwrap()
            .packed_size()
    );
}
