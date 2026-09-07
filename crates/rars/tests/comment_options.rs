use rars::{
    Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ErrorKind,
    ReadCancellation,
};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

const FORMATS: [ArchiveVersion; 9] = [
    ArchiveVersion::Rar13,
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
    ArchiveVersion::Rar50,
    ArchiveVersion::Rar70,
];

fn bytes(format: ArchiveVersion, comment: Option<&[u8]>, encrypted: bool) -> Vec<u8> {
    let mut builder = Builder::new(format).comment(comment.map(Vec::from));
    if encrypted {
        builder = builder.archive_comment_password(Some(b"secret".to_vec()));
    }
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    builder.to_bytes().unwrap()
}

fn assert_limits(archive: &Archive, expected: &[u8], password: Option<&[u8]>) {
    let defaults = ArchiveReadOptions::with_optional_password(password);
    assert_eq!(
        archive.comment(password).unwrap().as_deref(),
        Some(expected)
    );
    for total in [false, true] {
        let mut options = defaults;
        if total {
            options.max_total_output_bytes = Some(expected.len() as u64);
        } else {
            options.max_member_output_bytes = Some(expected.len() as u64);
        }
        for _ in 0..2 {
            assert_eq!(
                archive.comment_with_options(options).unwrap().as_deref(),
                Some(expected)
            );
        }
        if !expected.is_empty() {
            if total {
                options.max_total_output_bytes = Some(expected.len() as u64 - 1);
            } else {
                options.max_member_output_bytes = Some(expected.len() as u64 - 1);
            }
            assert_eq!(
                archive.comment_with_options(options).unwrap_err().kind(),
                ErrorKind::ResourceLimit
            );
        }
    }
    let token = ReadCancellation::new();
    token.cancel();
    assert_eq!(
        archive
            .comment_with_options(defaults.with_cancellation(&token))
            .unwrap_err()
            .kind(),
        ErrorKind::Cancelled
    );
    assert_eq!(
        archive.comment(password).unwrap().as_deref(),
        Some(expected)
    );
}

#[test]
fn comment_limits_cover_all_versions_empty_comments_and_fresh_budgets() {
    for format in FORMATS {
        for comment in [b"archive comment\n".as_slice(), b""] {
            let archive = ArchiveReader::read_owned(bytes(format, Some(comment), false)).unwrap();
            assert_limits(&archive, comment, None);
        }
        let archive = ArchiveReader::read_owned(bytes(format, None, false)).unwrap();
        let options = ArchiveReadOptions::new().with_max_member_output_bytes(0);
        assert_eq!(archive.comment_with_options(options).unwrap(), None);
        let token = ReadCancellation::new();
        token.cancel();
        assert_eq!(
            archive
                .comment_with_options(options.with_cancellation(&token))
                .unwrap_err()
                .kind(),
            ErrorKind::Cancelled
        );
    }
}

#[test]
fn encrypted_comment_admission_precedes_password_work() {
    for format in [
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        let archive =
            ArchiveReader::read_owned(bytes(format, Some(b"encrypted comment"), true)).unwrap();
        assert_eq!(
            archive.comment(None).unwrap_err().kind(),
            ErrorKind::PasswordRequired
        );
        assert_eq!(
            archive
                .comment_with_options(ArchiveReadOptions::new().with_max_member_output_bytes(0))
                .unwrap_err()
                .kind(),
            ErrorKind::ResourceLimit
        );
        assert_limits(&archive, b"encrypted comment", Some(b"secret"));
    }
}

#[test]
fn historical_comment_fixtures_keep_their_contents_under_limits() {
    for data in [
        include_bytes!("fixtures/rar13/COMMENT.RAR").as_slice(),
        include_bytes!("fixtures/rar15_40/rar202/comment_nopsw.rar"),
        include_bytes!("fixtures/rar15_40/rar300/with_comment_rar300.rar"),
        include_bytes!("fixtures/rar50/with_comment.rar"),
    ] {
        let archive = ArchiveReader::read(data).unwrap();
        let expected = archive
            .comment(None)
            .unwrap()
            .expect("fixture has archive comment");
        assert!(!expected.is_empty());
        assert_limits(&archive, &expected, None);
    }
}

#[test]
fn modern_comments_apply_dictionary_and_buffering_policy() {
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for encrypted in [false, true] {
            let comment = b"repeatable text\n".repeat(100);
            let stored =
                ArchiveReader::read_owned(bytes(format, Some(&comment), encrypted)).unwrap();
            let password = encrypted.then_some(b"secret".as_slice());
            let defaults = ArchiveReadOptions::with_optional_password(password);
            assert_eq!(
                stored
                    .comment_with_options(defaults.with_rar50_dictionary_size_limit(0))
                    .unwrap(),
                Some(comment.clone())
            );
            // The writer emits stored comments. Exercise the shared compressed
            // service payload representation using a normally encoded member.
            let mut builder = Builder::new(format).password(password.map(Vec::from));
            builder
                .add_bytes(b"CMT".to_vec(), comment.clone(), None, None)
                .unwrap();
            let mut archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            if let Archive::Rar50Plus(raw) = &mut archive {
                for block in &mut raw.blocks {
                    if let rars::rar50::Block::File(file) = block {
                        assert!(!file.is_stored());
                        *block = rars::rar50::Block::Service(file.clone());
                    }
                }
            }
            assert_limits(&archive, &comment, password);
            assert_eq!(
                archive
                    .comment_with_options(defaults.with_rar50_dictionary_size_limit(0))
                    .unwrap_err()
                    .kind(),
                ErrorKind::ResourceLimit
            );
            let options = defaults
                .with_rar50_buffered_decode_limit(0)
                .with_max_member_output_bytes(comment.len() as u64);
            assert_eq!(
                archive.comment_with_options(options).unwrap(),
                Some(comment)
            );
        }
    }
}

struct ObservedReader {
    data: Cursor<Vec<u8>>,
    armed: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
    cancellation: Option<ReadCancellation>,
}
impl Read for ObservedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.armed.load(Ordering::Relaxed) {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if let Some(token) = &self.cancellation {
                token.cancel();
            }
        }
        self.data.read(output)
    }
}
impl Seek for ObservedReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.data.seek(from)
    }
}

#[test]
fn admission_precedes_source_reads_and_cancellation_survives_decoder_adapters() {
    for format in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar50,
    ] {
        let token = ReadCancellation::new();
        let armed = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let archive = ArchiveReader::read_reader(ObservedReader {
            data: Cursor::new(bytes(format, Some(b"comment"), false)),
            armed: armed.clone(),
            reads: reads.clone(),
            cancellation: Some(token.clone()),
        })
        .unwrap();
        armed.store(true, Ordering::Relaxed);
        assert_eq!(
            archive
                .comment_with_options(ArchiveReadOptions::new().with_max_total_output_bytes(0))
                .unwrap_err()
                .kind(),
            ErrorKind::ResourceLimit
        );
        assert_eq!(reads.load(Ordering::Relaxed), 0);
        assert_eq!(
            archive
                .comment_with_options(ArchiveReadOptions::new().with_cancellation(&token))
                .unwrap_err()
                .kind(),
            ErrorKind::Cancelled
        );
        assert!(reads.load(Ordering::Relaxed) > 0);
    }
}

#[test]
fn unpacked_rar13_comment_uses_the_same_output_policy() {
    let comment = b"plain legacy comment";
    let mut archive =
        ArchiveReader::read_owned(bytes(ArchiveVersion::Rar13, Some(comment), false)).unwrap();
    if let Archive::Rar13(raw) = &mut archive {
        // The writer chooses packed comments; construct the alternate plain
        // comment representation in the parsed main header.
        raw.main.flags &= !0x10;
        raw.main.extra = (comment.len() as u16).to_le_bytes().to_vec();
        raw.main.extra.extend_from_slice(comment);
        assert!(!raw.main.has_packed_comment());
    }
    assert_limits(&archive, comment, None);
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[path = "support/scratch.rs"]
mod scratch;

#[test]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn filtered_comment_uses_bounded_scratch_and_cleans_up() {
    use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions};
    use rars::{EntrySource, FeatureSet, FilterKind, FilterPolicy, Rar50Scratch};
    let comment: Vec<u8> = [0xe8, 1, 0, 0, 0, 0xe9, 3, 0, 0, 0].repeat(1000);
    let data = Rar50Writer::new(WriterOptions::new(
        ArchiveVersion::Rar50,
        FeatureSet::store_only(),
    ))
    .entries([ArchiveEntry::new(
        b"CMT".to_vec(),
        EntrySource::from_bytes(Arc::<[u8]>::from(comment.clone())),
    )])
    .filter_policy(FilterPolicy::explicit(FilterKind::E8E9))
    .finish()
    .unwrap();
    let mut archive = ArchiveReader::read_owned(data).unwrap();
    if let Archive::Rar50Plus(raw) = &mut archive {
        for block in &mut raw.blocks {
            if let rars::rar50::Block::File(file) = block {
                *block = rars::rar50::Block::Service(file.clone());
            }
        }
    }
    let options = ArchiveReadOptions::new()
        .with_rar50_buffered_decode_limit(0)
        .with_max_total_output_bytes(comment.len() as u64);
    assert_eq!(
        archive.comment_with_options(options).unwrap_err().kind(),
        ErrorKind::ResourceLimit
    );
    let dir = scratch::case("comment-scratch");
    let policy = Rar50Scratch::new(&*dir, 100_000).with_filter_memory_limit(64 * 1024);
    assert_eq!(
        archive
            .comment_with_options(options.with_rar50_scratch(&policy))
            .unwrap(),
        Some(comment)
    );
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
    let refused = Rar50Scratch::new(&*dir, 1);
    assert_eq!(
        archive
            .comment_with_options(options.with_rar50_scratch(&refused))
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
}
