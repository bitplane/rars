//! `Builder::write_to_path` streams a large RAR 2.0-4.x member into the file.
//!
//! Inside the crate so the test can lower the size members stream above, and
//! the window that sets a segment of the streamed parse: crossing the real
//! 64 MiB took a debug build most of a CI run's test time.

use super::{write_seekable_archive_with_threshold, StreamingEntry, WriterOptions};
use crate::{
    ArchiveReader, ArchiveVersion, Builder, EntrySource, FeatureSet, MemberCoding, WriterResources,
};
use std::cell::Cell;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

thread_local! {
    /// What `ArchiveOutput::seekable` streams members above on this thread.
    pub(super) static STREAM_ABOVE: Cell<u64> = const { Cell::new(super::STREAM_MEMBERS_ABOVE) };
    /// The largest window a member is fitted on this thread.
    pub(super) static DICTIONARY_CAP: Cell<usize> = const { Cell::new(usize::MAX) };
}

const MODE: u32 = 0o100644;
const MIB: usize = 1024 * 1024;
const STREAMS_ABOVE: u64 = 256 * 1024;
/// The window members are fitted to here, in place of 4 MiB.
const DICTIONARY: usize = MIB;
/// A member over 1 MiB gets the capped dictionary, and one segment of the
/// streamed parse reads four of them at up to 8 threads; more round it up to
/// a whole batch of their blocks. A member a little longer than that has its
/// first segment coded and written before its last quarter megabyte is read.
const MEMBER: usize = 4 * DICTIONARY + DICTIONARY / 2;
/// How close to the member's end the archive is measured.
const LAST: u64 = DICTIONARY as u64 / 4;

/// Numbered lines with the top bit set. Not text, so the member is coded LZ
/// without first trying PPMd on a sample as large as a segment, which would
/// take as long again.
fn large_member() -> Arc<[u8]> {
    let mut data = Vec::with_capacity(MEMBER);
    let mut line = 0u64;
    while data.len() < MEMBER {
        data.extend_from_slice(
            format!("line {line} of {}\n", line.wrapping_mul(2654435761) % 977).as_bytes(),
        );
        line += 1;
    }
    data.iter_mut().for_each(|byte| *byte |= 0x80);
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
        if self.read + LAST >= self.inner.get_ref().len() as u64 {
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
    STREAM_ABOVE.set(STREAMS_ABOVE);
    DICTIONARY_CAP.set(DICTIONARY);
    // At 9 threads a segment holds the whole member.
    let _threads = crate::parallel::ThreadCap::set(Some(4));
    let dir = crate::scratch::case("builder-path-streams-legacy");
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
        .add_source(b"large.bin".to_vec(), source, None, Some(MODE))
        .unwrap();
    builder.write_to_path(&built, None).unwrap();

    let seekable = dir.join("seekable.rar");
    let entry = StreamingEntry::new(b"large.bin".to_vec(), EntrySource::from_bytes(data.clone()))
        .with_file_attr(MODE);
    let mut file = std::fs::File::create(&seekable).unwrap();
    write_seekable_archive_with_threshold(
        &[entry],
        WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only()),
        MemberCoding::Compressed,
        None,
        &WriterResources::default(),
        None,
        &mut file,
        STREAMS_ABOVE,
    )
    .unwrap();
    drop(file);

    let built = std::fs::read(&built).unwrap();
    let written = seen.lock().unwrap().unwrap();
    assert!(
        written * 2 > built.len() as u64,
        "{written} of {} bytes written before the member was read",
        built.len()
    );
    assert!(built == std::fs::read(&seekable).unwrap());
    let archive = ArchiveReader::read_owned(built).unwrap();
    assert!(archive.read_member(b"large.bin", None).unwrap().unwrap() == *data);
}

#[test]
fn seekable_archives_match_fingerprints_captured_from_master() {
    let noise = crate::write_stream::noise(70_000);
    let letters: Vec<u8> = noise.iter().map(|byte| b'a' + byte % 16).collect();
    let entries = |password: Option<&[u8]>| {
        [
            (&b"letters.txt"[..], &letters),
            (b"noise.bin", &noise),
            (b"empty", &Vec::new()),
        ]
        .into_iter()
        .map(|(name, data)| {
            let entry = StreamingEntry::new(name.to_vec(), EntrySource::from_bytes(data.clone()))
                .with_file_attr(MODE);
            match password {
                Some(password) => entry.with_password(password.to_vec()),
                None => entry,
            }
        })
        .collect::<Vec<_>>()
    };
    let seekable = |entries: &[StreamingEntry], options: WriterOptions, coding: MemberCoding| {
        let mut output = Cursor::new(Vec::new());
        write_seekable_archive_with_threshold(
            entries,
            options,
            coding,
            None,
            &WriterResources::default(),
            None,
            &mut output,
            1024,
        )
        .unwrap();
        output.into_inner()
    };
    let mut cases = Vec::new();
    for target in [ArchiveVersion::Rar15, ArchiveVersion::Rar40] {
        for (name, coding) in [
            ("stored", MemberCoding::Stored),
            ("compressed", MemberCoding::Compressed),
        ] {
            let options = WriterOptions::new(target, FeatureSet::store_only());
            let archive = seekable(&entries(None), options, coding);
            cases.push((
                format!("{target:?}_{name}"),
                crate::write_stream::fingerprint([&archive[..]]),
            ));
        }
    }
    #[cfg(feature = "encryption")]
    {
        let mut headers = FeatureSet::store_only();
        headers.header_encryption = true;
        let options = WriterOptions::new(ArchiveVersion::Rar40, headers);
        let archive = crate::entropy::seeded::with(|| {
            seekable(&entries(Some(b"pw")), options, MemberCoding::Compressed)
        });
        cases.push((
            "Rar40_encrypted_headers".into(),
            crate::write_stream::fingerprint([&archive[..]]),
        ));
        let mut sink = crate::volume_sink::CollectedVolumes::new();
        crate::entropy::seeded::with(|| {
            super::write_volumes_to(
                &entries(Some(b"pw")),
                options,
                MemberCoding::Stored,
                30_000,
                &mut sink,
                &WriterResources::default(),
                None,
            )
        })
        .unwrap();
        cases.push((
            "Rar40_volumes_encrypted_headers".into(),
            crate::write_stream::fingerprint(sink.take().iter().map(Vec::as_slice)),
        ));
    }
    let expected = [
        ("Rar15_stored", "140205:92f2a959"),
        ("Rar15_compressed", "112488:a05f666f"),
        ("Rar40_stored", "140212:db64ba84"),
        ("Rar40_compressed", "106764:65dd24f6"),
        ("Rar40_encrypted_headers", "106888:17bc5604"),
        (
            "Rar40_volumes_encrypted_headers",
            "30000:1cbe6415 30000:cb5d28ff 30000:52c3702c 30000:3532be9b 21208:eb107e2c",
        ),
    ];
    crate::write_stream::assert_fingerprints(&cases, &expected);
}
