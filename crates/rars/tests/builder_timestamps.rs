use rars::{ArchiveReader, ArchiveVersion, Builder};
use std::time::{Duration, UNIX_EPOCH};

#[path = "support/scratch.rs"]
mod scratch;

#[test]
fn fractional_mtime_survives_all_rar5_output_paths() {
    let root = scratch::case("fractional-mtime");
    for (format, encrypted) in [
        (ArchiveVersion::Rar50, false),
        (ArchiveVersion::Rar70, true),
    ] {
        let password = encrypted.then_some(b"secret".to_vec());
        let mut builder = Builder::new(format)
            .password(password.clone())
            .header_encryption(encrypted);
        builder
            .add_bytes(
                b"file".to_vec(),
                b"timestamp payload".repeat(100),
                Some(1_700_000_002),
                None,
            )
            .unwrap();
        builder.set_mtime_nanoseconds(b"file", 704_088_300).unwrap();
        let path = root.join(format!("{format}.rar"));
        builder.write_to_path(&path, None).unwrap();
        let mut outputs = vec![builder.to_bytes().unwrap(), std::fs::read(path).unwrap()];
        outputs.extend(builder.volume_size(Some(4096)).build_volumes(None).unwrap());
        for bytes in outputs {
            let archive = ArchiveReader::read_with_options(
                &bytes,
                password.as_deref().map_or_else(
                    rars::ArchiveReadOptions::default,
                    rars::ArchiveReadOptions::with_password,
                ),
            )
            .unwrap();
            let meta = archive.members().next().unwrap().meta;
            assert_eq!(
                meta.modification_time(),
                Some(UNIX_EPOCH + Duration::new(1_700_000_002, 704_088_300))
            );
            archive
                .extract_to(password.as_deref(), |meta| {
                    assert_eq!(meta.mtime_refinement.unwrap().nanoseconds, 704_088_300);
                    Ok(Box::new(std::io::sink()))
                })
                .unwrap();
        }
    }
}

#[test]
fn split_volume_extraction_retains_fractional_mtime() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .volume_size(Some(512));
    builder
        .add_bytes(b"file".to_vec(), vec![42; 2048], Some(123), None)
        .unwrap();
    builder.set_mtime_nanoseconds(b"file", 987_654_321).unwrap();
    let volumes: Vec<_> = builder
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect();
    assert!(volumes.len() > 1);
    let mut opened = 0;
    rars::extract_volumes_to(&volumes, None, |meta| {
        opened += 1;
        assert_eq!(meta.file_time, 123);
        assert_eq!(meta.mtime_refinement.unwrap().nanoseconds, 987_654_321);
        Ok(Box::new(std::io::sink()))
    })
    .unwrap();
    assert_eq!(opened, 1);
}

#[test]
fn an_epoch_fraction_is_not_treated_as_missing_time() {
    let detail = rars::TimeRefinement {
        add_second: false,
        nanoseconds: 123,
    };
    assert_eq!(
        rars::timestamp::extracted_system_time(rars::ArchiveFamily::Rar50Plus, 0, Some(detail)),
        Some(UNIX_EPOCH + Duration::from_nanos(123))
    );
    assert_eq!(
        rars::timestamp::extracted_system_time(rars::ArchiveFamily::Rar50Plus, 0, None),
        None
    );
}

#[test]
fn invalid_fractional_mtime_leaves_queued_metadata_unchanged() {
    for (format, seconds) in [
        (ArchiveVersion::Rar29, Some(123)),
        (ArchiveVersion::Rar50, None),
        (ArchiveVersion::Rar50, Some(123)),
    ] {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"file".to_vec(), vec![], seconds, None)
            .unwrap();
        let before = builder.to_bytes().unwrap();
        assert!(builder
            .set_mtime_nanoseconds(b"file", 1_000_000_000)
            .is_err());
        assert!(builder.set_mtime_nanoseconds(b"missing", 100).is_err());
        if seconds.is_none() || format == ArchiveVersion::Rar29 {
            assert!(builder.set_mtime_nanoseconds(b"file", 100).is_err());
        }
        assert_eq!(builder.to_bytes().unwrap(), before);
    }
}
