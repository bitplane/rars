use rars::{ArchiveReader, ArchiveVersion, Builder, FileTimes, Timestamp};
use std::time::{Duration, UNIX_EPOCH};

use crate::scratch;

#[test]
fn timestamps_convert_to_and_from_system_time_on_both_sides_of_the_epoch() {
    for (instant, expected) in [
        (UNIX_EPOCH - Duration::new(1, 0), Timestamp::new(-1, 0)),
        (
            UNIX_EPOCH - Duration::new(0, 1),
            Timestamp::new(-1, 999_999_999),
        ),
        (UNIX_EPOCH, Timestamp::new(0, 0)),
        (
            UNIX_EPOCH + Duration::new(1_594_771_200, 5),
            Timestamp::new(1_594_771_200, 5),
        ),
    ] {
        let time = Timestamp::try_from(instant).unwrap();
        assert_eq!(Some(time), expected);
        assert_eq!(std::time::SystemTime::try_from(time).unwrap(), instant);
    }
    assert_eq!(Timestamp::new(0, 1_000_000_000), None);
    let current = rars::timestamp::current_filetime();
    assert!(current >= 116_444_736_000_000_000);
    assert!(!rars::timestamp::format_filetime_utc(current).starts_with("0x"));
}

#[test]
fn dos_times_cover_1980_to_2107_only() {
    let local = |year| {
        let mut seconds = (i64::from(year) - 1970) * 365 * 86_400;
        // Well inside the year whatever the local zone.
        seconds += 180 * 86_400;
        Timestamp::from_unix_seconds(seconds)
    };
    assert_eq!(rars::timestamp::dos_time(local(1979)), None);
    assert!(rars::timestamp::dos_time(local(1981)).is_some());
    assert!(rars::timestamp::dos_time(local(2107)).is_some());
    assert_eq!(rars::timestamp::dos_time(local(2109)), None);
}

#[test]
fn the_stored_view_names_each_familys_own_form() {
    use rars::{ArchiveFamily, StoredTimestamp};
    let time = Timestamp::from_unix_seconds(1_700_000_000);
    for format in ArchiveVersion::ALL {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"time".to_vec(), vec![], Some(time), None)
            .unwrap();
        builder
            .add_bytes(b"none".to_vec(), vec![], None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let members: Vec<_> = archive.members().collect();
        let expected = match archive.family() {
            ArchiveFamily::Rar50Plus => StoredTimestamp::UnixSeconds(1_700_000_000),
            _ => StoredTimestamp::DosLocal(rars::timestamp::dos_time(time).unwrap()),
        };
        assert_eq!(
            members[0].meta.stored_modification_time(),
            Some(expected),
            "{format}"
        );
        if archive.family() == ArchiveFamily::Rar50Plus {
            assert_eq!(members[1].meta.stored_modification_time(), None);
        }
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
                    assert_eq!(meta.modified, at(1_700_000_002, 704_088_300));
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
        assert_eq!(meta.modified, at(123, 987_654_321));
        Ok(Box::new(std::io::sink()))
    })
    .unwrap();
    assert_eq!(opened, 1);
}

#[test]
fn an_epoch_fraction_is_not_treated_as_missing_time() {
    for time in [at(0, 123), at(0, 0)] {
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"file".to_vec(), vec![], time, None)
            .unwrap();
        let member = only_member(builder.to_bytes().unwrap());
        assert_eq!(member.meta.modification_time(), time);
    }
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
                assert_eq!(meta.modified, time.map(Timestamp::from_unix_seconds));
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
    assert_eq!(
        copied.meta.stored_modification_time(),
        member.meta.stored_modification_time()
    );

    let mut legacy = Builder::new(ArchiveVersion::Rar29).store(true);
    legacy
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let id = legacy.member_ids().next().unwrap();
    assert!(legacy.copy_times_by_id(id, &member).is_err());
}
