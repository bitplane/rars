#![cfg(feature = "write")]

use rars::{ArchiveReader, ArchiveVersion, Builder, FileTimes, Timestamp};
use std::time::{Duration, UNIX_EPOCH};

#[path = "support/scratch.rs"]
mod scratch;

#[test]
fn source_metadata_preserves_unix_epoch_and_refuses_unrepresentable_seconds() {
    let root = scratch::case("source-timestamp-boundaries");
    let file = std::fs::File::create(root.join("source")).unwrap();
    for (instant, expected_unix, expected_dos_year) in [
        (UNIX_EPOCH - Duration::from_secs(1), None, None),
        (UNIX_EPOCH, Some(0), None),
        (
            UNIX_EPOCH + Duration::from_secs(1_594_771_200),
            Some(1_594_771_200),
            Some(2020),
        ),
        (
            UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX)),
            Some(u32::MAX),
            Some(2106),
        ),
        (
            UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) + 1),
            None,
            Some(2106),
        ),
    ] {
        file.set_modified(instant).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.modified().unwrap(), instant);
        assert_eq!(rars::timestamp::source_unix_mtime(&metadata), expected_unix);
        let packed = rars::timestamp::source_dos_mtime(&metadata);
        assert_eq!(
            (packed != 0).then_some(1980 + (packed >> 25)),
            expected_dos_year
        );
    }
    let current = rars::timestamp::current_filetime();
    assert!(current >= 116_444_736_000_000_000);
    assert!(!rars::timestamp::format_filetime_utc(current).starts_with("0x"));
}

#[test]
fn stored_timestamp_view_retains_family_presence_and_refinements() {
    use rars::{ArchiveFamily, StoredTimestamp, TimeRefinement};
    for format in ArchiveVersion::ALL {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"time".to_vec(), vec![], None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let mut meta = archive.members().next().unwrap().meta;
        for raw in [0, 0x5022_1882] {
            meta.file_time = Some(raw);
            meta.mtime_refinement = Some(TimeRefinement {
                add_second: true,
                nanoseconds: 123,
            });
            let before = meta.clone();
            let expected = match archive.family() {
                ArchiveFamily::Rar50Plus => StoredTimestamp::UnixSeconds(raw),
                _ => StoredTimestamp::DosLocal(raw),
            };
            assert_eq!(meta.stored_modification_time(), Some(expected), "{format}");
            assert_eq!(meta, before);
        }
        meta.file_time = None;
        assert_eq!(meta.stored_modification_time(), None);
    }
}

fn at(seconds: i64, nanoseconds: u32) -> Option<Timestamp> {
    Some(Timestamp::new(seconds, nanoseconds).unwrap())
}

/// A FILETIME tick count as the Unix time it names.
fn filetime(ticks: u64) -> Option<Timestamp> {
    Timestamp::from_unix_nanoseconds((i128::from(ticks) - 116_444_736_000_000_000) * 100)
}

fn only_member(bytes: Vec<u8>) -> rars::ArchiveMember {
    ArchiveReader::read_owned(bytes)
        .unwrap()
        .members()
        .next()
        .unwrap()
}

#[test]
fn one_unix_mtime_reads_back_the_same_in_every_format() {
    for format in ArchiveVersion::ALL {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(
                b"file".to_vec(),
                b"payload".to_vec(),
                at(1_700_000_000, 0),
                None,
            )
            .unwrap();
        let member = only_member(builder.to_bytes().unwrap());
        assert_eq!(
            member.meta.modification_time(),
            at(1_700_000_000, 0),
            "{format}"
        );
        assert_eq!(
            member.times().unwrap().modified,
            at(1_700_000_000, 0),
            "{format}"
        );
    }
}

#[test]
fn times_an_old_format_cannot_store_are_refused_and_change_nothing() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
    ] {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(
                b"file".to_vec(),
                b"payload".to_vec(),
                at(1_700_000_000, 0),
                None,
            )
            .unwrap();
        let before = builder.to_bytes().unwrap();
        for early in [0, 315_000_000] {
            assert!(builder
                .add_bytes(b"other".to_vec(), vec![], at(early, 0), None)
                .is_err());
        }
        let created = FileTimes {
            created: at(1_700_000_000, 0),
            ..FileTimes::default()
        };
        assert!(builder.set_times(b"file", created).is_err());
        assert!(builder.set_times(b"missing", FileTimes::default()).is_err());
        assert_eq!(builder.to_bytes().unwrap(), before, "{format}");
    }
}

#[test]
fn an_old_format_rounds_a_modification_time_down_to_two_seconds() {
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(b"file".to_vec(), vec![], at(1_700_000_001, 500), None)
        .unwrap();
    let member = only_member(builder.to_bytes().unwrap());
    assert_eq!(member.meta.modification_time(), at(1_700_000_000, 0));
}

#[test]
fn add_path_keeps_each_files_modification_time() {
    let root = scratch::case("add-path-mtime");
    let path = root.join("source.txt");
    std::fs::write(&path, b"payload").unwrap();
    let file = std::fs::File::options().write(true).open(&path).unwrap();
    file.set_modified(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        .unwrap();
    drop(file);
    for format in ArchiveVersion::ALL {
        let mut builder = Builder::new(format).store(true);
        builder.add_path(&path, b"source.txt").unwrap();
        let member = only_member(builder.to_bytes().unwrap());
        assert_eq!(
            member.meta.modification_time(),
            at(1_700_000_000, 0),
            "{format}"
        );
    }
}

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
                at(1_700_000_002, 704_088_300),
                None,
            )
            .unwrap();
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
            assert_eq!(meta.modification_time(), at(1_700_000_002, 704_088_300));
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
        .add_bytes(b"file".to_vec(), vec![42; 2048], at(123, 987_654_321), None)
        .unwrap();
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
        assert_eq!(meta.file_time, Some(123));
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
        rars::timestamp::extracted_system_time(
            rars::ArchiveFamily::Rar50Plus,
            Some(0),
            Some(detail)
        ),
        Some(UNIX_EPOCH + Duration::from_nanos(123))
    );
    assert_eq!(
        rars::timestamp::extracted_system_time(rars::ArchiveFamily::Rar50Plus, Some(0), None),
        Some(UNIX_EPOCH)
    );
    assert_eq!(
        rars::timestamp::extracted_system_time(rars::ArchiveFamily::Rar50Plus, None, Some(detail)),
        None
    );
}

#[test]
fn extraction_retains_missing_and_epoch_times_in_single_and_split_archives() {
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for time in [None, Some(0)] {
            let mut builder = Builder::new(format).store(true);
            builder
                .add_bytes(
                    b"file".to_vec(),
                    vec![42; 2048],
                    time.map(Timestamp::from_unix_seconds),
                    None,
                )
                .unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let check = |meta: &rars::ExtractedEntryMeta| {
                assert_eq!(meta.file_time, time.map(|seconds| seconds as u32));
                assert_eq!(meta.mtime_refinement, None);
                assert_eq!(
                    rars::timestamp::extracted_system_time(
                        rars::ArchiveFamily::Rar50Plus,
                        meta.file_time,
                        meta.mtime_refinement,
                    ),
                    time.map(|_| UNIX_EPOCH),
                );
            };
            archive
                .extract_to(None, |meta| {
                    check(meta);
                    Ok(Box::new(std::io::sink()))
                })
                .unwrap();
            let volumes: Vec<_> = builder
                .volume_size(Some(512))
                .build_volumes(None)
                .unwrap()
                .into_iter()
                .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
                .collect();
            assert!(volumes.len() > 1);
            let mut opened = 0;
            rars::extract_volumes_to(&volumes, None, |meta| {
                opened += 1;
                check(meta);
                Ok(Box::new(std::io::sink()))
            })
            .unwrap();
            assert_eq!(opened, 1);
        }
    }
}

#[test]
fn complete_file_times_survive_streaming_and_volume_paths() {
    for (times, expected) in [
        (
            FileTimes {
                modified: filetime(0),
                created: filetime(u64::MAX),
                accessed: filetime(116_444_736_000_000_001),
            },
            None,
        ),
        (
            FileTimes {
                modified: None,
                created: at(0, 123),
                accessed: at(i64::from(u32::MAX), 999_999_999),
            },
            Some(FileTimes {
                modified: at(123, 0),
                created: at(0, 123),
                accessed: at(i64::from(u32::MAX), 999_999_999),
            }),
        ),
    ] {
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), at(123, 0), None)
            .unwrap();
        builder.set_times(b"file", times).unwrap();
        let mut outputs = vec![builder.to_bytes().unwrap()];
        outputs.extend(builder.volume_size(Some(4096)).build_volumes(None).unwrap());
        for bytes in outputs {
            let archive = ArchiveReader::read_owned(bytes).unwrap();
            assert_eq!(
                archive.members().next().unwrap().times().unwrap(),
                expected.unwrap_or(times)
            );
            assert_eq!(
                archive.read_member(b"file", None).unwrap().unwrap(),
                b"payload"
            );
        }
    }
}

#[test]
fn adding_creation_time_preserves_an_existing_fractional_modification_time() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(
            b"file".to_vec(),
            b"payload".to_vec(),
            at(123, 456_789_123),
            None,
        )
        .unwrap();
    let before = builder.to_bytes().unwrap();
    // A creation time before 1970 needs FILETIME, which can't hold the
    // modification time's last two digits of nanoseconds.
    let unstorable = FileTimes {
        created: at(-1, 0),
        ..FileTimes::default()
    };
    assert!(builder.set_times(b"file", unstorable).is_err());
    assert_eq!(builder.to_bytes().unwrap(), before);
    let created = FileTimes {
        created: at(456, 0),
        ..FileTimes::default()
    };
    builder.set_times(b"file", created).unwrap();
    assert_eq!(
        only_member(builder.to_bytes().unwrap()).times().unwrap(),
        FileTimes {
            modified: at(123, 456_789_123),
            created: at(456, 0),
            accessed: None,
        }
    );
}

#[test]
fn copied_times_keep_their_stored_form_and_stay_in_one_family() {
    let mut source = Builder::new(ArchiveVersion::Rar50).store(true);
    source
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let times = FileTimes {
        modified: filetime(0),
        created: filetime(1),
        accessed: None,
    };
    source.set_times(b"file", times).unwrap();
    let member = only_member(source.to_bytes().unwrap());

    let mut copy = Builder::new(ArchiveVersion::Rar50).store(true);
    copy.add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let id = copy.member_ids().next().unwrap();
    copy.copy_times_by_id(id, &member).unwrap();
    let copied = only_member(copy.to_bytes().unwrap());
    assert_eq!(copied.times().unwrap(), times);
    assert_eq!(copied.meta.file_time, member.meta.file_time);

    let mut legacy = Builder::new(ArchiveVersion::Rar29).store(true);
    legacy
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let id = legacy.member_ids().next().unwrap();
    assert!(legacy.copy_times_by_id(id, &member).is_err());
}
