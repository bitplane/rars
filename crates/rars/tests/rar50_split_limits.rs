#![cfg(feature = "write")]

#[path = "support/volume_size.rs"]
mod volume_size;
use rars::rar50::{self, Archive, Block};
use rars::{ArchiveReadOptions, Error};
use std::cell::RefCell;
use std::io::{self, Write};
use std::path::Path;
use std::rc::Rc;

#[path = "support/scratch.rs"]
mod scratch;

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn options(limit: u64, password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    password
        .map_or_else(
            ArchiveReadOptions::default,
            ArchiveReadOptions::with_password,
        )
        .with_rar50_buffered_decode_limit(limit)
}

fn fixtures(prefix: &str, count: usize, padded: bool, password: Option<&[u8]>) -> Vec<Archive> {
    (1..=count)
        .map(|index| {
            let number = if padded {
                format!("{index:02}")
            } else {
                index.to_string()
            };
            Archive::parse_path_with_password(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/rar50")
                    .join(format!("{prefix}.part{number}.rar")),
                password,
            )
            .unwrap()
        })
        .collect()
}

fn collect(
    volumes: &[Archive],
    limit: u64,
    password: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut outputs = Vec::new();
    rar50::extract_volumes_to(volumes, options(limit, password), |_| {
        let data = Rc::new(RefCell::new(Vec::new()));
        outputs.push(data.clone());
        Ok(Box::new(Capture(data)))
    })?;
    Ok(outputs
        .into_iter()
        .map(|data| data.borrow().clone())
        .collect())
}

fn cause(error: &Error) -> &Error {
    match error {
        Error::AtEntry { source, .. }
        | Error::AtArchiveOffset { source, .. }
        | Error::InVolume { source, .. } => cause(source),
        error => error,
    }
}

#[test]
fn streamed_split_members_match_buffered_plain_encrypted_and_solid_fixtures() {
    for (prefix, count, padded, password) in [
        ("multivol", 3, false, None),
        ("encrypted_multivol", 3, false, Some(b"password".as_slice())),
        ("solid_multivol", 6, true, None),
    ] {
        let volumes = fixtures(prefix, count, padded, password);
        let expected = collect(&volumes, u64::MAX, password).unwrap();
        let streamed = collect(&volumes, 1, password).unwrap();
        assert_eq!(streamed, expected, "{prefix}");
        assert!(!streamed.is_empty());
    }
}

#[test]
fn oversized_filtered_split_member_streams_like_unsplit() {
    let payload = b"\xe8\0\0\0\0filtered payload block\n".repeat(256);
    let entry = rar50::ArchiveEntry::new(
        b"filtered".to_vec(),
        rars::EntrySource::from_bytes(payload.clone()),
    );
    let root = scratch::case("filtered-split-limit");
    let volumes = volume_size::sized_for_payload(32, |volume_size| {
        let mut sink = rar50::CollectedVolumes::new();
        rar50::write_streaming_volumes_to(
            std::slice::from_ref(&entry),
            rar50::WriterOptions::new(rars::ArchiveVersion::Rar50, rars::FeatureSet::store_only()),
            rar50::ArchiveExtras::default()
                .with_filter_policy(rar50::FilterPolicy::explicit(rar50::FilterKind::E8)),
            volume_size as u64,
            &mut sink,
            &rars::WriterResources::new(128 * 1024 * 1024).with_temp_dir(root.to_path_buf()),
        )?;
        Ok::<_, rars::Error>(sink.take())
    })
    .unwrap();
    let volumes: Vec<_> = volumes
        .into_iter()
        .map(|bytes| Archive::parse_owned(bytes).unwrap())
        .collect();
    assert!(volumes.len() > 1);
    assert!(volumes[0].files().next().unwrap().is_split_after());
    assert_eq!(
        collect(&volumes, payload.len() as u64, None).unwrap(),
        vec![payload.clone()]
    );
    assert_eq!(
        collect(&volumes, payload.len() as u64 - 1, None).unwrap(),
        vec![payload]
    );
}

#[test]
fn split_streaming_integrity_failure_can_follow_partial_emission() {
    let mut volumes = fixtures("multivol", 3, false, None);
    let expected = collect(&volumes, u64::MAX, None).unwrap();
    for block in &mut volumes.last_mut().unwrap().blocks {
        if let Block::File(file) = block {
            file.hash = None;
            file.data_crc32 = Some(0);
        }
    }
    for limit in [1, u64::MAX] {
        let emitted = Rc::new(RefCell::new(Vec::new()));
        let error = rar50::extract_volumes_to(&volumes, options(limit, None), |_| {
            Ok(Box::new(Capture(emitted.clone())))
        })
        .unwrap_err();
        assert!(
            matches!(cause(&error), Error::Crc32Mismatch { .. }),
            "{error:?}"
        );
        if limit == 1 {
            assert_eq!(*emitted.borrow(), expected[0]);
        } else {
            assert!(emitted.borrow().is_empty());
        }
    }
}

#[test]
fn split_streaming_preserves_sink_io_failure() {
    struct Refuse;
    impl Write for Refuse {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sink refused",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let volumes = fixtures("multivol", 3, false, None);
    let error = rar50::extract_volumes_to(&volumes, options(1, None), |_| Ok(Box::new(Refuse)))
        .unwrap_err();
    assert!(
        matches!(cause(&error), Error::Io(error) if error.kind == io::ErrorKind::PermissionDenied),
        "{error:?}"
    );
}

#[test]
fn stored_split_member_reads_its_source_at_most_twice() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    struct Counted(io::Cursor<Vec<u8>>, Arc<AtomicUsize>);
    impl io::Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let read = self.0.read(buf)?;
            self.1.fetch_add(read, Ordering::SeqCst);
            Ok(read)
        }
    }
    impl io::Seek for Counted {
        fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
            self.0.seek(from)
        }
    }
    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i * 31 + i / 7) as u8).collect();
    let read = Arc::new(AtomicUsize::new(0));
    let source = {
        let (payload, read) = (payload.clone(), read.clone());
        rars::EntrySource::from_opener(payload.len() as u64, move || {
            Ok(Box::new(Counted(
                io::Cursor::new(payload.clone()),
                read.clone(),
            )))
        })
    };
    let root = scratch::case("stored-split-reads");
    let mut sink = rar50::CollectedVolumes::new();
    rar50::write_streaming_volumes_to(
        &[rar50::ArchiveEntry::new(b"stored".to_vec(), source)],
        rar50::WriterOptions::new(rars::ArchiveVersion::Rar50, rars::FeatureSet::store_only())
            .with_compression_level(0),
        rar50::ArchiveExtras::default(),
        4096,
        &mut sink,
        &rars::WriterResources::default().with_temp_dir(root.to_path_buf()),
    )
    .unwrap();
    let volumes: Vec<_> = sink
        .take()
        .into_iter()
        .map(|bytes| Archive::parse_owned(bytes).unwrap())
        .collect();
    assert!(volumes.len() > 10);
    assert_eq!(
        collect(&volumes, payload.len() as u64, None).unwrap(),
        vec![payload.clone()]
    );
    assert!(read.load(Ordering::SeqCst) <= 2 * payload.len() + 1);
}
