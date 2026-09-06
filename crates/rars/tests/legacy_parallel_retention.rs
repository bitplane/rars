#![cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]

use rars::{rar15_40, ArchiveReadOptions, ArchiveVersion, Builder, Error};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

const VERSIONS: [ArchiveVersion; 5] = [
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
];

fn archive(version: ArchiveVersion, stored: bool) -> rar15_40::Archive {
    let mut builder = Builder::new(version).store(stored);
    for index in 0..5 {
        builder
            .add_bytes(
                index.to_string().into_bytes(),
                vec![index as u8; index * 64],
                None,
                None,
            )
            .unwrap();
    }
    rar15_40::Archive::parse_owned(builder.to_bytes().unwrap()).unwrap()
}

fn corrupt_member(archive: &mut rar15_40::Archive, index: usize) {
    let file = archive
        .blocks
        .iter_mut()
        .filter_map(|block| match block {
            rar15_40::Block::File(file) => Some(file),
            _ => None,
        })
        .nth(index)
        .unwrap();
    file.file_crc ^= 1;
}

#[test]
fn publishes_one_worker_window_before_a_later_decode_failure() {
    for workers in [1, 2] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.install(|| {
            for version in VERSIONS {
                for stored in [true, false] {
                    let mut archive = archive(version, stored);
                    corrupt_member(&mut archive, workers);
                    let mut opened = Vec::new();
                    let error = archive
                        .extract_to_parallel_buffered(ArchiveReadOptions::new(), |meta| {
                            opened.push(meta.name.clone());
                            Ok(Box::new(io::sink()))
                        })
                        .unwrap_err();
                    assert!(matches!(error.root_cause(), Error::Crc32Mismatch { .. }));
                    assert_eq!(
                        opened,
                        (0..workers)
                            .map(|index| index.to_string().into_bytes())
                            .collect::<Vec<_>>()
                    );
                }
            }
        });
    }
}

struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn preserves_order_and_content_across_windows_including_empty_members() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    pool.install(|| {
        for version in VERSIONS {
            for stored in [true, false] {
                let archive = archive(version, stored);
                let mut opened = Vec::new();
                let data = Arc::new(Mutex::new(Vec::new()));
                archive
                    .extract_to_parallel_buffered(ArchiveReadOptions::new(), |meta| {
                        opened.push(meta.name.clone());
                        Ok(Box::new(Capture(data.clone())))
                    })
                    .unwrap();
                assert_eq!(opened, [b"0", b"1", b"2", b"3", b"4"]);
                assert_eq!(
                    *data.lock().unwrap(),
                    (0..5)
                        .flat_map(|i| vec![i as u8; i * 64])
                        .collect::<Vec<_>>()
                );
            }
        }
    });
}

#[test]
fn publication_failure_stops_before_a_later_batch_is_decoded() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    pool.install(|| {
        for version in VERSIONS {
            let mut archive = archive(version, true);
            corrupt_member(&mut archive, 2);
            let mut opened = 0;
            let error = archive
                .extract_to_parallel_buffered(ArchiveReadOptions::new(), |_| {
                    opened += 1;
                    Err(io::Error::other("destination unavailable").into())
                })
                .unwrap_err();
            assert!(matches!(error.root_cause(), Error::Io(_)));
            assert_eq!(opened, 1);
        }
    });
}
