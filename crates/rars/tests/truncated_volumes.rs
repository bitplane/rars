#![cfg(feature = "write")]

use rars::{Archive, ArchiveReader, ArchiveVersion, Builder};
#[path = "support/scratch.rs"]
mod scratch;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const VOLUME_SIZE: usize = 4096;

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2654435761) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn write_set(
    name: &str,
    version: ArchiveVersion,
    stored: bool,
) -> (scratch::Scratch, Vec<PathBuf>) {
    let mut builder = Builder::new(version)
        .store(stored)
        .volume_size(Some(VOLUME_SIZE));
    let (count, len) = if version == ArchiveVersion::Rar50 {
        (4, 6000)
    } else {
        (1, 16000)
    };
    for index in 0..count {
        builder
            .add_bytes(
                format!("m{index}").into_bytes(),
                noise(index, len),
                None,
                None,
            )
            .unwrap();
    }
    let dir = scratch::case(name);
    let paths = builder
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let path = dir.join(format!("set.part{}.rar", index + 1));
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect::<Vec<_>>();
    assert!(
        paths.len() > 2,
        "{version:?} stored={stored}: need a middle volume"
    );
    (dir, paths)
}

fn truncate(path: &Path) {
    let len = std::fs::metadata(path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(len / 2)
        .unwrap();
}

fn member_names(volumes: &[Archive]) -> Vec<Vec<u8>> {
    volumes
        .iter()
        .flat_map(|volume| {
            volume
                .members()
                .map(|member| member.meta.name_bytes().to_vec())
        })
        .collect()
}

fn assert_short_read(error: &rars::Error, context: &str) {
    match error.root_cause() {
        rars::Error::Io(io) => assert_eq!(
            io.kind,
            std::io::ErrorKind::UnexpectedEof,
            "{context}: {error}"
        ),
        _ => panic!("{context}: expected a short-read error, got {error:?}"),
    }
}

const CASES: [(ArchiveVersion, bool); 4] = [
    (ArchiveVersion::Rar29, true),
    (ArchiveVersion::Rar29, false),
    (ArchiveVersion::Rar50, true),
    (ArchiveVersion::Rar50, false),
];

#[test]
fn extracting_a_volume_set_with_a_truncated_volume_fails_with_a_short_read() {
    for (version, stored) in CASES {
        let context = format!("{version:?} stored={stored}");
        let (_dir, paths) = write_set("truncated-extract", version, stored);
        let volumes: Vec<_> = paths
            .iter()
            .map(|path| ArchiveReader::read_path(path).unwrap())
            .collect();
        let cut = 1;
        truncate(&paths[cut]);

        let opened = Arc::new(Mutex::new(Vec::new()));
        let record = opened.clone();
        let error = rars::extract_volumes_to(&volumes, None, move |meta| {
            record.lock().unwrap().push(meta.name.clone());
            Ok(Box::new(std::io::sink()))
        })
        .unwrap_err();

        assert_short_read(&error, &context);
        let reachable = member_names(&volumes[..=cut]);
        for name in opened.lock().unwrap().iter() {
            assert!(
                reachable.contains(name),
                "{context}: {} starts after the truncation but was extracted",
                String::from_utf8_lossy(name)
            );
        }
    }
}

#[test]
fn a_truncated_volume_behind_a_caller_reader_fails_with_a_short_read() {
    for (version, stored) in CASES {
        let context = format!("{version:?} stored={stored}");
        let (_dir, paths) = write_set("truncated-reader", version, stored);
        let volumes: Vec<_> = paths
            .iter()
            .map(|path| ArchiveReader::read_reader(std::fs::File::open(path).unwrap()).unwrap())
            .collect();
        let cut = 1;
        truncate(&paths[cut]);

        let error = rars::extract_volumes_to(&volumes, None, |_| Ok(Box::new(std::io::sink())))
            .unwrap_err();

        assert_short_read(&error, &context);
    }
}

#[test]
fn reading_a_member_from_a_truncated_archive_fails_with_a_short_read() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        for stored in [true, false] {
            let context = format!("{version:?} stored={stored}");
            let mut builder = Builder::new(version).store(stored);
            builder
                .add_bytes(b"member".to_vec(), noise(7, 16000), None, None)
                .unwrap();
            let dir = scratch::case("truncated-member");
            let path = dir.join("single.rar");
            std::fs::write(&path, builder.to_bytes().unwrap()).unwrap();
            let archive = ArchiveReader::read_path(&path).unwrap();
            truncate(&path);

            let error = archive.read_member(b"member", None).unwrap_err();
            assert_short_read(&error, &format!("{context} read_member"));
            let error = archive
                .extract_to_parallel_buffered(None, |_| Ok(Box::new(std::io::sink())))
                .unwrap_err();
            assert_short_read(&error, &format!("{context} parallel"));
        }
    }
}

#[test]
fn copying_packed_data_from_a_truncated_file_fails_with_a_short_read() {
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(b"member".to_vec(), noise(9, 16000), None, None)
        .unwrap();
    let dir = scratch::case("truncated-copy");
    let path = dir.join("single.rar");
    std::fs::write(&path, builder.to_bytes().unwrap()).unwrap();
    let archive = rars::rar15_40::Archive::parse_path(&path).unwrap();
    let file = archive.files().next().unwrap();
    truncate(&path);

    let mut copied = Vec::new();
    let error = file.write_packed_data(&archive, &mut copied).unwrap_err();

    assert_short_read(&error, "write_packed_data");
    assert!(!copied.is_empty() && copied.len() < 16000);
}
