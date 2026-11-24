use super::{write_archive_reporting, ArchiveEntry, ArchiveExtras, WriterOptions};
use crate::atomic64::AtomicU64;
use crate::write_stream::CallerOutput;
use crate::{ArchiveReadOptions, ArchiveReader, EntrySource, FeatureSet, WriterResources};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const NOISE: usize = 4 * 1024 * 1024;

fn text(len: usize) -> Vec<u8> {
    (0..len).map(|at| b'a' + (at % 23) as u8).collect()
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

#[derive(Default)]
struct Reads {
    opens: AtomicUsize,
    bytes: AtomicU64,
}

struct Counted {
    inner: Cursor<Vec<u8>>,
    reads: Arc<Reads>,
}

impl Read for Counted {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.reads.bytes.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

impl Seek for Counted {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(position)
    }
}

fn counted(data: Vec<u8>) -> (EntrySource, Arc<Reads>) {
    let reads = Arc::new(Reads::default());
    let opened = reads.clone();
    let source = EntrySource::from_opener(data.len() as u64, move || {
        opened.opens.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(Counted {
            inner: Cursor::new(data.clone()),
            reads: opened.clone(),
        }))
    });
    (source, reads)
}

fn options(features: FeatureSet) -> WriterOptions {
    WriterOptions::new(crate::ArchiveVersion::Rar50, features).with_compression_level(1)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Output {
    Stream,
    /// Seekable but write-only, so recovery mirrors the archive.
    Seekable,
    Readable,
}

fn write(
    entries: &[ArchiveEntry],
    features: FeatureSet,
    extras: ArchiveExtras<'_>,
    output: Output,
) -> crate::Result<Vec<u8>> {
    let resources = WriterResources::default();
    let mut written = Cursor::new(Vec::new());
    let caller = match output {
        Output::Stream => CallerOutput::stream(written.get_mut()),
        Output::Seekable => CallerOutput::seekable(&mut written),
        Output::Readable => CallerOutput::readable(&mut written),
    };
    write_archive_reporting(entries, options(features), extras, &resources, None, caller)?;
    Ok(written.into_inner())
}

fn seeded<T>(run: impl FnOnce() -> T) -> T {
    #[cfg(feature = "encryption")]
    return crate::entropy::seeded::with(run);
    #[cfg(not(feature = "encryption"))]
    run()
}

fn read_back(archive: &[u8], members: &[(&[u8], &[u8])], password: Option<&[u8]>) {
    let options = match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    };
    let reader = ArchiveReader::read_with_options(archive, options).unwrap();
    reader.test(password).unwrap();
    for (name, data) in members {
        let read = reader.read_member(name, password).unwrap();
        assert_eq!(read.as_deref(), Some(*data));
    }
}

#[test]
fn stored_members_beside_compressed_ones_are_read_once_on_a_seekable_output() {
    let quiet = text(256 * 1024);
    let loud = noise(NOISE, 7);
    let louder = noise(NOISE, 9);
    let features = FeatureSet {
        blake2sp: true,
        ..FeatureSet::store_only()
    };
    for output in [Output::Seekable, Output::Readable] {
        let (first, first_reads) = counted(loud.clone());
        let (second, second_reads) = counted(louder.clone());
        let entries = [
            ArchiveEntry::new(b"loud".to_vec(), first),
            ArchiveEntry::new(b"quiet".to_vec(), EntrySource::from_bytes(quiet.clone())),
            ArchiveEntry::new(b"louder".to_vec(), second),
        ];
        let archive = write(&entries, features, ArchiveExtras::default(), output).unwrap();
        read_back(
            &archive,
            &[(b"loud", &loud), (b"quiet", &quiet), (b"louder", &louder)],
            None,
        );
        for reads in [first_reads, second_reads] {
            // Its samples, then the copy: never a whole read just to hash it.
            assert_eq!(reads.opens.load(Ordering::Relaxed), 2, "{output:?}");
            let read = reads.bytes.load(Ordering::Relaxed);
            assert!(read < 2 * NOISE as u64, "{output:?}: {read} bytes read");
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Case {
    headers: bool,
    passwords: bool,
    quick_open: bool,
    solid: bool,
    recovery: Option<u64>,
}

fn identity_cases() -> Vec<Case> {
    let plain = Case::default();
    let mut cases = vec![
        plain,
        Case {
            quick_open: true,
            ..plain
        },
        Case {
            solid: true,
            ..plain
        },
    ];
    if cfg!(feature = "recovery") {
        cases.push(Case {
            quick_open: true,
            recovery: Some(5),
            ..plain
        });
    }
    if cfg!(feature = "encryption") {
        cases.extend([
            Case {
                headers: true,
                ..plain
            },
            Case {
                passwords: true,
                quick_open: true,
                ..plain
            },
            Case {
                headers: true,
                passwords: true,
                recovery: cfg!(feature = "recovery").then_some(5),
                ..plain
            },
        ]);
    }
    cases
}

#[test]
fn seekable_and_stream_outputs_write_the_same_mixed_archive() {
    let quiet = text(32 * 1024);
    let loud = noise(1536 * 1024, 11);
    let after = text(64 * 1024);
    let members: [(&[u8], &[u8]); 3] = [(b"quiet", &quiet), (b"loud", &loud), (b"after", &after)];
    for case in identity_cases() {
        let features = FeatureSet {
            solid: case.solid,
            header_encryption: case.headers,
            quick_open: case.quick_open,
            blake2sp: true,
        };
        let run = |output| {
            let (source, reads) = counted(loud.clone());
            let entries: Vec<_> = members
                .iter()
                .map(|(name, data)| {
                    let source = match *name {
                        b"loud" => source.clone(),
                        _ => EntrySource::from_bytes(data.to_vec()),
                    };
                    let entry = ArchiveEntry::new(name.to_vec(), source);
                    match case.passwords {
                        true => entry.with_password(b"secret"),
                        false => entry,
                    }
                })
                .collect();
            let mut extras = ArchiveExtras::default().with_recovery_percent(case.recovery);
            if case.headers {
                extras.header_password = Some(b"secret");
            }
            let archive = seeded(|| write(&entries, features, extras, output)).unwrap();
            (archive, reads.opens.load(Ordering::Relaxed))
        };
        let (streamed, stream_opens) = run(Output::Stream);
        let password = (case.headers || case.passwords).then_some(b"secret".as_slice());
        read_back(&streamed, &members, password);
        for output in [Output::Seekable, Output::Readable] {
            let (archive, opens) = run(output);
            assert!(archive == streamed, "{case:?} {output:?}");
            // A solid chain is coded whole; otherwise the hashing read is saved.
            let saved = usize::from(!case.solid);
            assert_eq!(opens + saved, stream_opens, "{case:?} {output:?}");
        }
    }
}

#[test]
fn a_stored_member_that_shrinks_before_its_copy_is_reported_against_it() {
    let loud = noise(1536 * 1024, 13);
    let opens = Arc::new(AtomicUsize::new(0));
    let source = EntrySource::from_opener(loud.len() as u64, {
        let opens = opens.clone();
        move || {
            // Whole for its samples, cut short by the time it is copied.
            let len = match opens.fetch_add(1, Ordering::Relaxed) {
                0 => loud.len(),
                _ => loud.len() / 2,
            };
            Ok(Box::new(Cursor::new(loud[..len].to_vec())))
        }
    });
    let entries = [
        ArchiveEntry::new(b"quiet".to_vec(), EntrySource::from_bytes(text(32 * 1024))),
        ArchiveEntry::new(b"loud".to_vec(), source),
    ];
    let error = write(
        &entries,
        FeatureSet::store_only(),
        ArchiveExtras::default(),
        Output::Seekable,
    )
    .unwrap_err();
    assert!(
        matches!(error.root_cause(), crate::Error::SourceChanged(_)),
        "{error}"
    );
    assert_eq!(error.entry_context(), Some((b"loud".as_slice(), "writing")));
}
