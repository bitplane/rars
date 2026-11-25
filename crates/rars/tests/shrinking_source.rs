#![cfg(feature = "write")]

use rars::atomic64::AtomicU64;
use rars::{
    Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ExtractionDecision,
    ExtractionOutcome,
};
use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::rc::Rc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

#[path = "support/scratch.rs"]
mod scratch;

struct Truncating {
    data: Arc<Vec<u8>>,
    end: Arc<AtomicU64>,
    pos: u64,
}

impl Read for Truncating {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let end = self.end.load(Relaxed);
        let requested_end = self.pos + buf.len() as u64;
        if requested_end > end && !buf.is_empty() {
            return Err(io::Error::other(format!(
                "source read {}..{requested_end} exceeds truncated end {end}",
                self.pos
            )));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        buf.copy_from_slice(&self.data[self.pos as usize..requested_end as usize]);
        self.pos = requested_end;
        Ok(buf.len())
    }
}

impl Seek for Truncating {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.pos = match from {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::Current(offset) => self.pos.checked_add_signed(offset),
            SeekFrom::End(offset) => self.end.load(Relaxed).checked_add_signed(offset),
        }
        .ok_or(io::ErrorKind::InvalidInput)?;
        Ok(self.pos)
    }
}

#[derive(Clone, Default)]
struct Output(Rc<RefCell<Vec<u8>>>);

impl Write for Output {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn extract_single_members_from_a_shrinking_reader() {
    use ArchiveVersion::{Rar13, Rar14, Rar15, Rar20, Rar29, Rar50};

    let members = [
        (b"first".as_slice(), b"first member\n".repeat(512)),
        (b"second".as_slice(), b"second member\n".repeat(521)),
        (b"third".as_slice(), b"third member\n".repeat(530)),
    ];

    for version in [Rar13, Rar14, Rar15, Rar20, Rar29, Rar50] {
        for stored in [true, false] {
            check_reader(version, stored, None, false, &members);
            #[cfg(feature = "encryption")]
            {
                let password = Some(b"shrinking source".as_slice());
                check_reader(version, stored, password, false, &members);
                if matches!(version, Rar29 | Rar50) {
                    check_reader(version, stored, password, true, &members);
                }
            }
        }
    }
    check_path(&members);

    let docs = include_str!("../src/lib.rs");
    assert!(
        docs.contains("For solid archives, the source's contents and length must remain unchanged")
    );
}

fn check_reader(
    version: ArchiveVersion,
    stored: bool,
    password: Option<&[u8]>,
    encrypted_headers: bool,
    members: &[(&[u8], Vec<u8>)],
) {
    let case = format!(
        "{version:?}, stored={stored}, password={}, encrypted_headers={encrypted_headers}",
        password.is_some()
    );
    let comment = b"Synthetic archive comment";
    let mut builder = Builder::new(version)
        .store(stored)
        .password(password.map(<[u8]>::to_vec))
        .header_encryption(encrypted_headers)
        .comment(Some(comment.to_vec()));
    if version == ArchiveVersion::Rar50 {
        builder = builder
            .archive_metadata(None, false, !encrypted_headers)
            .unwrap();
        #[cfg(feature = "recovery")]
        {
            builder = builder.recovery_percent(Some(5));
        }
    }
    for (name, data) in members {
        builder
            .add_bytes(name.to_vec(), data.clone(), None, None)
            .unwrap();
    }
    let data = Arc::new(
        builder
            .to_bytes()
            .unwrap_or_else(|error| panic!("{case}: build: {error}")),
    );
    let end = Arc::new(AtomicU64::new(data.len() as u64));
    let source = Truncating {
        data,
        end: end.clone(),
        pos: 0,
    };
    let options = password.map_or_else(ArchiveReadOptions::new, ArchiveReadOptions::with_password);
    let archive = if encrypted_headers {
        ArchiveReader::read_reader_with_options(source, options)
    } else {
        ArchiveReader::read_reader(source)
    }
    .unwrap_or_else(|error| panic!("{case}: parse: {error}"));

    assert_eq!(
        archive.comment(password).unwrap().as_deref(),
        Some(comment.as_slice()),
        "{case}"
    );
    let packed: Vec<_> = match &archive {
        Archive::Rar13(raw) => raw
            .entries
            .iter()
            .map(|entry| (entry.packed_range.end, entry.is_stored()))
            .collect(),
        Archive::Rar15To40(raw) => {
            assert_eq!(
                raw.main.has_encrypted_headers(),
                encrypted_headers,
                "{case}"
            );
            raw.files()
                .map(|file| (file.packed_range.end, file.is_stored()))
                .collect()
        }
        Archive::Rar50Plus(raw) => {
            assert_eq!(raw.main.encrypted_headers, encrypted_headers, "{case}");
            let locator = raw.main.locator().unwrap();
            assert_eq!(
                locator.quick_open_offset.is_some_and(|offset| offset > 0),
                !encrypted_headers,
                "{case}"
            );
            #[cfg(feature = "recovery")]
            assert!(
                locator
                    .recovery_record_offset
                    .is_some_and(|offset| offset > 0),
                "{case}"
            );
            raw.files()
                .map(|file| (file.block.data_range.end, file.is_stored()))
                .collect()
        }
        _ => unreachable!("unexpected archive family"),
    };
    assert_eq!(packed.len(), members.len(), "{case}");
    for ((name, expected), &(packed_end, is_stored)) in members.iter().zip(&packed).rev() {
        assert_eq!(is_stored, stored, "{case}");
        end.store(packed_end as u64, Relaxed);
        assert_eq!(extract(&archive, options, name, &case), *expected, "{case}");
    }
}

fn extract(archive: &Archive, options: ArchiveReadOptions<'_>, name: &[u8], case: &str) -> Vec<u8> {
    let output = Output::default();
    let outcome = archive
        .extract_with_control(options, |member| {
            if member.meta.name == name {
                Ok(ExtractionDecision::Extract(Box::new(output.clone())))
            } else {
                Ok(ExtractionDecision::Skip)
            }
        })
        .unwrap_or_else(|error| panic!("{case}, member {name:?}: {error}"));
    assert_eq!(outcome, ExtractionOutcome::Complete, "{case}");
    output.0.take()
}

fn check_path(members: &[(&[u8], Vec<u8>)]) {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .archive_metadata(None, false, true)
        .unwrap();
    for (name, data) in members {
        builder
            .add_bytes(name.to_vec(), data.clone(), None, None)
            .unwrap();
    }
    let dir = scratch::case("shrinking-source");
    let path = dir.join("archive.rar");
    std::fs::write(&path, builder.to_bytes().unwrap()).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let archive = ArchiveReader::read_path(path).unwrap();
    let packed_ends: Vec<_> = archive
        .as_rar50()
        .unwrap()
        .files()
        .map(|file| file.block.data_range.end as u64)
        .collect();
    assert_eq!(packed_ends.len(), members.len());
    let options = ArchiveReadOptions::new();

    // Probe a full-length file so a successful short read at EOF cannot hide
    // speculative reads into the next member. Linux counts bytes per thread.
    #[cfg(target_os = "linux")]
    if let Some((before, sample_len)) = thread_bytes_read() {
        let (name, expected) = &members[0];
        let output = extract(&archive, options, name, "read_path");
        let (after, _) = thread_bytes_read().unwrap();
        let read = after - before - sample_len;
        let packed_end = packed_ends[0];
        assert!(
            read <= packed_end,
            "read_path: read {read} bytes for a member ending at {packed_end}"
        );
        assert_eq!(&output, expected);
    }

    for ((name, expected), packed_end) in members.iter().zip(packed_ends).rev() {
        file.set_len(packed_end).unwrap();
        assert_eq!(extract(&archive, options, name, "read_path"), *expected);
    }
}

#[cfg(all(
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
#[test]
fn extract_large_member_from_a_truncated_path_in_rayon_pools() {
    // Exceed the 16 MiB buffered decode threshold, with enough variation
    // to give the streaming decoder multiple 256 KiB packed batches.
    const SIZE: usize = 24 << 20;
    let mut expected = Vec::with_capacity(SIZE + 64);
    let mut state = 1u32;
    while expected.len() < SIZE {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        writeln!(expected, "record {state:08x} accepted by synthetic worker").unwrap();
    }
    expected.truncate(SIZE);

    let dir = scratch::case("shrinking-parallel-source");
    let path = dir.join("archive.rar");
    let mut builder = Builder::new(ArchiveVersion::Rar50).compression_level(Some(1));
    builder
        .add_bytes(b"large.txt".to_vec(), expected.clone(), None, None)
        .unwrap();
    builder
        .add_bytes(b"later.txt".to_vec(), b"discarded".to_vec(), None, None)
        .unwrap();
    builder.write_to_path(&path, None).unwrap();
    drop(builder);

    let archive = ArchiveReader::read_path(&path).unwrap();
    let mut files = archive.as_rar50().unwrap().files();
    let first = files.next().unwrap();
    assert!(!first.is_stored());
    assert!(first.block.data_range.len() > 2 * (256 << 10));
    let packed_end = first.block.data_range.end;
    assert!(files.next().unwrap().block.data_range.start > packed_end);
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(packed_end as u64)
        .unwrap();

    for threads in [1, 2, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let options = ArchiveReadOptions::new()
            .with_threads(threads)
            .with_rar50_decode_workers(threads);
        let output = pool.install(|| extract(&archive, options, b"large.txt", "truncated path"));
        assert!(output == expected, "truncated path with {threads} threads");
    }
}

#[cfg(target_os = "linux")]
fn thread_bytes_read() -> Option<(u64, u64)> {
    let stats = std::fs::read_to_string("/proc/thread-self/io").ok()?;
    let rchar = stats
        .lines()
        .next()?
        .strip_prefix("rchar: ")?
        .parse()
        .ok()?;
    Some((rchar, stats.len() as u64))
}
