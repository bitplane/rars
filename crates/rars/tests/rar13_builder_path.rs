#![cfg(feature = "write")]

use rars::atomic64::AtomicU64;
use rars::{ArchiveVersion, Builder, EntrySource, WriterResources};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[path = "support/scratch.rs"]
mod scratch;

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

struct Counting {
    data: Cursor<Vec<u8>>,
    served: Arc<AtomicU64>,
}

impl Read for Counting {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.data.read(buffer)?;
        self.served.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

impl Seek for Counting {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.data.seek(position)
    }
}

fn counted(data: Vec<u8>) -> (EntrySource, Arc<AtomicU64>) {
    let served = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&served);
    let source = EntrySource::from_opener(data.len() as u64, move || {
        Ok(Box::new(Counting {
            data: Cursor::new(data.clone()),
            served: Arc::clone(&counter),
        }))
    });
    (source, served)
}

#[test]
fn write_to_path_reads_a_stored_rar14_member_once() {
    let dir = scratch::case("rar13-builder-path-read-once");
    let sizes = [256 * 1024 + 17, 0, 1];
    let mut builder = Builder::new(ArchiveVersion::Rar14).store(true);
    let mut counters = Vec::new();
    for (index, size) in sizes.into_iter().enumerate() {
        let (source, served) = counted(bytes(size, index as u8));
        builder
            .add_source(
                format!("member{index}.bin").into_bytes(),
                source,
                None,
                None,
            )
            .unwrap();
        counters.push(served);
    }

    let path = dir.join("stored.rar");
    builder.write_to_path(&path, None).unwrap();
    for (served, size) in counters.iter().zip(sizes) {
        assert_eq!(served.swap(0, Ordering::Relaxed), size as u64);
    }

    let mut streamed = Vec::new();
    builder
        .write_to(&mut streamed, &WriterResources::default(), None)
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), streamed);
}

#[test]
fn write_to_path_matches_write_to_for_rar13_archives() {
    let dir = scratch::case("rar13-builder-path-matches");
    let payload = b"legacy payload through a seekable file\n".repeat(200);
    let mut cases = vec![("stored", true, None), ("compressed", false, None)];
    if cfg!(feature = "encryption") {
        cases.push(("stored-encrypted", true, Some(b"secret".to_vec())));
        cases.push(("compressed-encrypted", false, Some(b"secret".to_vec())));
    }
    for format in [ArchiveVersion::Rar13, ArchiveVersion::Rar14] {
        for (name, store, password) in &cases {
            let mut builder = Builder::new(format)
                .store(*store)
                .password(password.clone())
                .comment(Some(b"archive comment".to_vec()));
            builder
                .add_source(
                    b"first".to_vec(),
                    EntrySource::from_bytes(payload.clone()),
                    None,
                    None,
                )
                .unwrap();
            builder
                .add_bytes(b"second".to_vec(), payload[..100].to_vec(), None, None)
                .unwrap();
            builder
                .add_source(
                    b"empty".to_vec(),
                    EntrySource::from_bytes(Vec::new()),
                    None,
                    None,
                )
                .unwrap();

            let path = dir.join(format!("{format:?}-{name}.rar"));
            builder.write_to_path(&path, None).unwrap();
            let mut streamed = Vec::new();
            builder
                .write_to(&mut streamed, &WriterResources::default(), None)
                .unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), streamed, "{format:?} {name}");
        }
    }
}
