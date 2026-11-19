#![cfg(feature = "write")]

use rars::rar15_40::{write_seekable_archive_to, StreamingEntry, WriterOptions};
use rars::{
    ArchiveReader, ArchiveVersion, Builder, EntrySource, FeatureSet, MemberCoding, WriterResources,
};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[path = "support/scratch.rs"]
mod scratch;

const MODE: u32 = 0o100644;

fn large_member() -> Arc<[u8]> {
    let mut data = Vec::with_capacity(65 << 20);
    let mut line = 0u64;
    while data.len() < 65 << 20 {
        data.extend_from_slice(
            format!("line {line} of {}\n", line.wrapping_mul(2654435761) % 977).as_bytes(),
        );
        line += 1;
    }
    data.into()
}

struct Watched {
    inner: Cursor<Arc<[u8]>>,
    read: u64,
    dir: PathBuf,
    seen: Arc<Mutex<Option<u64>>>,
}

impl Read for Watched {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.read += read as u64;
        if self.read + (1 << 20) >= self.inner.get_ref().len() as u64 {
            self.seen
                .lock()
                .unwrap()
                .get_or_insert_with(|| bytes_in(&self.dir));
        }
        Ok(read)
    }
}

impl Seek for Watched {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(position)
    }
}

fn bytes_in(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum()
}

#[test]
fn write_to_path_streams_a_large_member_as_a_seekable_archive_does() {
    let dir = scratch::case("builder-path-streams-legacy");
    let data = large_member();

    let out = dir.join("out");
    std::fs::create_dir(&out).unwrap();
    let built = out.join("built.rar");
    let seen = Arc::new(Mutex::new(None));
    let source = {
        let (data, dir, seen) = (data.clone(), out.clone(), seen.clone());
        EntrySource::from_opener(data.len() as u64, move || {
            Ok(Box::new(Watched {
                inner: Cursor::new(data.clone()),
                read: 0,
                dir: dir.clone(),
                seen: seen.clone(),
            }))
        })
    };
    let mut builder = Builder::new(ArchiveVersion::Rar40);
    builder
        .add_source(b"large.txt".to_vec(), source, None, Some(MODE))
        .unwrap();
    builder.write_to_path(&built, None).unwrap();

    let seekable = dir.join("seekable.rar");
    let entry = StreamingEntry::new(b"large.txt".to_vec(), EntrySource::from_bytes(data.clone()))
        .with_file_attr(MODE);
    let mut file = std::fs::File::create(&seekable).unwrap();
    write_seekable_archive_to(
        &[entry],
        WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only()),
        MemberCoding::Compressed,
        None,
        &WriterResources::default(),
        None,
        &mut file,
    )
    .unwrap();
    drop(file);

    let written = seen.lock().unwrap().unwrap();
    assert!(
        written > 1 << 20,
        "{written} bytes written before the member was read"
    );
    let built = std::fs::read(&built).unwrap();
    assert!(built == std::fs::read(&seekable).unwrap());
    let archive = ArchiveReader::read_owned(built).unwrap();
    assert!(archive.read_member(b"large.txt", None).unwrap().unwrap() == *data);
}

#[cfg(feature = "encryption")]
#[test]
fn write_to_path_round_trips_encrypted_and_solid_legacy_archives() {
    let dir = scratch::case("builder-path-legacy-encrypted");
    let payload = b"legacy payload through a seekable file\n".repeat(64);
    for (index, (header_encryption, solid)) in [(false, false), (true, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        let mut builder = Builder::new(ArchiveVersion::Rar40)
            .password(Some(b"secret".to_vec()))
            .header_encryption(header_encryption)
            .solid(solid);
        for name in [b"first".as_slice(), b"second"] {
            builder
                .add_source(
                    name.to_vec(),
                    EntrySource::from_bytes(payload.clone()),
                    None,
                    None,
                )
                .unwrap();
        }
        let path = dir.join(format!("{index}.rar"));
        builder.write_to_path(&path, None).unwrap();
        let archive = ArchiveReader::read_path_with_options(
            &path,
            rars::ArchiveReadOptions::with_password(b"secret"),
        )
        .unwrap();
        for name in [b"first".as_slice(), b"second"] {
            assert_eq!(
                archive.read_member(name, Some(b"secret")).unwrap().unwrap(),
                payload,
                "header_encryption={header_encryption} solid={solid}"
            );
        }
    }
}
