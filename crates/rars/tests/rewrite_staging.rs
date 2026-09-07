#![cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]

use rars::{
    ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error, ErrorKind,
    ExtractionDecision, RewriteStaging,
};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[path = "support/scratch.rs"]
mod scratch;

#[test]
fn staging_finished_events_require_verified_payloads() {
    use rars::{WriteOperation, WriteProgressEvent};
    use std::sync::Mutex;
    let root = scratch::case("rewrite-progress-integrity");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"first".to_vec(), b"first payload".to_vec(), None, None)
        .unwrap();
    builder
        .add_bytes(b"fault".to_vec(), b"fault payload".to_vec(), None, None)
        .unwrap();
    let mut bytes = builder.to_bytes().unwrap();
    let offset = bytes
        .windows(13)
        .position(|bytes| bytes == b"fault payload")
        .unwrap();
    bytes[offset] ^= 1;
    let archive = ArchiveReader::read_owned(bytes).unwrap();
    let finished = Arc::new(Mutex::new(Vec::new()));
    let recorded = finished.clone();
    let progress = Arc::new(move |event: WriteProgressEvent<'_>| match event {
        WriteProgressEvent::EntryFinished {
            operation: WriteOperation::Staging,
            name,
            ..
        } => {
            recorded.lock().unwrap().push(name.to_vec());
        }
        WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Staging,
            ..
        } => {
            panic!("failed staging must not finish");
        }
        _ => {}
    });
    let error = archive
        .stage_rewrite_sources_with_progress(
            &[0, 1],
            ArchiveReadOptions::default(),
            &RewriteStaging {
                directory: root.to_path_buf(),
                max_staged_bytes: 26,
            },
            Some(progress),
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ChecksumMismatch);
    assert_eq!(*finished.lock().unwrap(), vec![b"first".to_vec()]);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

struct Counted {
    data: Cursor<Vec<u8>>,
    count: Arc<AtomicU64>,
}

impl Read for Counted {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let read = self.data.read(bytes)?;
        self.count.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

impl Seek for Counted {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.data.seek(from)
    }
}

#[test]
fn solid_staging_reads_once_and_reopens_without_touching_archive() {
    let root = scratch::case("rewrite-once");
    for format in ArchiveVersion::ALL {
        let mut builder = Builder::new(format).solid(true);
        for index in 0..3 {
            builder
                .add_bytes(
                    format!("file{index}").into_bytes(),
                    vec![b'a' + index; 2048],
                    None,
                    None,
                )
                .unwrap();
        }
        let count = Arc::new(AtomicU64::new(0));
        let archive = ArchiveReader::read_reader(Counted {
            data: Cursor::new(builder.to_bytes().unwrap()),
            count: count.clone(),
        })
        .unwrap();
        count.store(0, Ordering::Relaxed);
        archive
            .extract_with_control(ArchiveReadOptions::default(), |_| {
                Ok(ExtractionDecision::Extract(Box::new(std::io::sink())))
            })
            .unwrap();
        let one_pass = count.swap(0, Ordering::Relaxed);
        let sources = archive
            .stage_rewrite_sources(
                &[2, 0],
                ArchiveReadOptions::default(),
                &RewriteStaging {
                    directory: root.to_path_buf(),
                    max_staged_bytes: 4096,
                },
            )
            .unwrap();
        assert_eq!(count.load(Ordering::Relaxed), one_pass, "{format}");
        for _ in 0..2 {
            for (source, expected) in sources.iter().zip([b'c', b'a']) {
                let mut data = Vec::new();
                source.open().unwrap().read_to_end(&mut data).unwrap();
                assert_eq!(data, vec![expected; 2048]);
            }
        }
        assert_eq!(count.load(Ordering::Relaxed), one_pass);
        drop(sources);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }
}

#[test]
fn sources_and_independent_readers_own_the_staged_files() {
    let root = scratch::case("rewrite-lifetime");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"abcdef".to_vec(), None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let sources = archive
        .stage_rewrite_sources(
            &[0],
            ArchiveReadOptions::default(),
            &RewriteStaging {
                directory: root.to_path_buf(),
                max_staged_bytes: 6,
            },
        )
        .unwrap();
    let clone = sources[0].clone();
    let mut a = clone.open().unwrap();
    let mut b = clone.open().unwrap();
    a.seek(SeekFrom::Start(3)).unwrap();
    drop(sources);
    drop(clone);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    let mut data = Vec::new();
    a.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"def");
    data.clear();
    b.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"abcdef");
    drop(a);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    drop(b);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn encrypted_sources_require_password_and_respect_cancellation() {
    let root = scratch::case("rewrite-password");
    for format in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        let mut builder = Builder::new(format)
            .store(true)
            .password(Some(b"secret".to_vec()));
        builder
            .add_bytes(b"file".to_vec(), b"secret content".to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let staging = RewriteStaging {
            directory: root.to_path_buf(),
            max_staged_bytes: 14,
        };
        assert!(archive
            .stage_rewrite_sources(&[0], ArchiveReadOptions::default(), &staging)
            .is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let options = ArchiveReadOptions::with_password(b"secret");
        let sources = archive
            .stage_rewrite_sources(&[0], options, &staging)
            .unwrap();
        let mut data = Vec::new();
        sources[0].open().unwrap().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"secret content");
        drop(sources);
        let token = rars::ReadCancellation::new();
        token.cancel();
        assert_eq!(
            archive
                .stage_rewrite_sources(&[0], options.with_cancellation(&token), &staging)
                .unwrap_err(),
            Error::Cancelled
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }
}

#[test]
fn admission_fails_before_io_and_indices_include_directories() {
    let root = scratch::case("rewrite-admission");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    builder
        .add_bytes(b"file".to_vec(), b"abc".to_vec(), None, None)
        .unwrap();
    let count = Arc::new(AtomicU64::new(0));
    let archive = ArchiveReader::read_reader(Counted {
        data: Cursor::new(builder.to_bytes().unwrap()),
        count: count.clone(),
    })
    .unwrap();
    count.store(0, Ordering::Relaxed);
    let staging = RewriteStaging {
        directory: root.join("does-not-exist"),
        max_staged_bytes: 2,
    };
    assert!(matches!(
        archive.stage_rewrite_sources(&[1], ArchiveReadOptions::default(), &staging),
        Err(Error::RewriteStagingLimitExceeded {
            limit: 2,
            required: 3
        })
    ));
    assert!(matches!(
        archive.stage_rewrite_sources(&[1, 1], ArchiveReadOptions::default(), &staging),
        Err(Error::DuplicateEntry)
    ));
    assert!(matches!(
        archive.stage_rewrite_sources(&[2], ArchiveReadOptions::default(), &staging),
        Err(Error::EntryNotFound)
    ));
    assert!(matches!(
        archive.stage_rewrite_sources(&[0], ArchiveReadOptions::default(), &staging),
        Err(Error::InvalidArgument(_))
    ));
    assert!(archive
        .stage_rewrite_sources(&[], ArchiveReadOptions::default(), &staging)
        .unwrap()
        .is_empty());
    assert_eq!(count.load(Ordering::Relaxed), 0);
    let sources = archive
        .stage_rewrite_sources(
            &[1],
            ArchiveReadOptions::default(),
            &RewriteStaging {
                directory: root.to_path_buf(),
                max_staged_bytes: 3,
            },
        )
        .unwrap();
    let mut output = Builder::new(ArchiveVersion::Rar50).store(true);
    output
        .add_source(b"renamed".to_vec(), sources[0].clone(), None, None)
        .unwrap();
    let path = root.join("output.rar");
    output.write_to_path(&path, None).unwrap();
    let rewritten = ArchiveReader::read_owned(std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        rewritten.read_member(b"renamed", None).unwrap().unwrap(),
        b"abc"
    );
}

#[test]
fn corrupt_dependencies_fail_cleanly_but_independent_omissions_are_skipped() {
    let root = scratch::case("rewrite-corruption");
    for solid in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true).solid(solid);
        for name in [b"first", b"fault", b"final"] {
            builder
                .add_bytes(name.to_vec(), name.repeat(5), None, None)
                .unwrap();
        }
        let mut bytes = builder.to_bytes().unwrap();
        let offset = bytes
            .windows(25)
            .position(|bytes| bytes == b"fault".repeat(5))
            .unwrap();
        bytes[offset] ^= 1;
        let archive = ArchiveReader::read_owned(bytes).unwrap();
        let staging = RewriteStaging {
            directory: root.to_path_buf(),
            max_staged_bytes: 75,
        };
        let error = archive
            .stage_rewrite_sources(&[0, 1], ArchiveReadOptions::default(), &staging)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ChecksumMismatch);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let prefix = archive
            .stage_rewrite_sources(&[0], ArchiveReadOptions::default(), &staging)
            .unwrap();
        drop(prefix);
        let suffix = archive.stage_rewrite_sources(&[2], ArchiveReadOptions::default(), &staging);
        if solid {
            assert_eq!(suffix.unwrap_err().kind(), ErrorKind::ChecksumMismatch);
        } else {
            drop(suffix.unwrap());
        }
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }
}
