#![cfg(feature = "write")]

#[path = "support/volume_size.rs"]
mod volume_size;
use rars::{ArchiveReader, ArchiveVersion, Builder};

const DATA: &[u8] = concat!("rars/", env!("CARGO_PKG_VERSION"), "\nmarker-schema=1\n").as_bytes();

fn record(data: &[u8]) -> Vec<u8> {
    let mut result = b"RARS".to_vec();
    result.extend_from_slice(&(data.len() as u16).to_le_bytes());
    result.extend_from_slice(data);
    result.extend_from_slice(&rars::crc32::crc32(data).to_le_bytes());
    result
}

fn builder(store: bool, comment: bool) -> Builder {
    let mut builder = Builder::new(ArchiveVersion::Rar14)
        .store(store)
        .comment(comment.then(|| b"user comment".to_vec()));
    builder
        .add_bytes(b"file".to_vec(), (0..128).collect(), None, None)
        .unwrap();
    builder
}

fn replace(bytes: &[u8], replacement: &[u8]) -> Vec<u8> {
    let end = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let start = end - record(DATA).len();
    assert_eq!(&bytes[start..end], record(DATA));
    let mut out = bytes[..start].to_vec();
    out.extend_from_slice(replacement);
    let size = out.len() as u16;
    out[4..6].copy_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&bytes[end..]);
    out
}

fn check(bytes: &[u8]) {
    let end = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    assert_eq!(&bytes[end - record(DATA).len()..end], record(DATA));
    assert_eq!(bytes[6] & 0x20, 0);
}

#[test]
fn old_producer_preserves_files_comments_and_rewrites() {
    for store in [false, true] {
        for comment in [false, true] {
            let bytes = builder(store, comment).to_bytes().unwrap();
            check(&bytes);
            let archive = ArchiveReader::read_owned(bytes.clone()).unwrap();
            assert_eq!(archive.members().count(), 1);
            assert_eq!(
                archive.comment(None).unwrap(),
                comment.then(|| b"user comment".to_vec())
            );
            archive.test(None).unwrap();
            for previous in [vec![], record(b"rars/0.1.0\nmarker-schema=1\n")] {
                let old = ArchiveReader::read_owned(replace(&bytes, &previous)).unwrap();
                let mut rewrite = old
                    .preserving_builder(None)
                    .unwrap()
                    .comment(old.comment(None).unwrap());
                rewrite
                    .add_bytes(b"file".to_vec(), (0..128).collect(), None, None)
                    .unwrap();
                let rewritten = rewrite.to_bytes().unwrap();
                check(&rewritten);
                let parsed = ArchiveReader::read_owned(rewritten).unwrap();
                parsed.test(None).unwrap();
                assert_eq!(
                    parsed.comment(None).unwrap(),
                    archive.comment(None).unwrap()
                );
            }
        }
    }
}

#[test]
fn old_rewrite_refuses_unknown_damaged_and_duplicate_records() {
    let mut bad_crc = record(DATA);
    *bad_crc.last_mut().unwrap() ^= 1;
    let mut bad_length = record(DATA);
    bad_length[4] = 255;
    let mut padding = record(DATA);
    padding.push(0);
    let mut duplicate = record(DATA);
    duplicate.extend(record(DATA));
    for comment in [false, true] {
        let bytes = builder(true, comment).to_bytes().unwrap();
        for extra in [
            bad_crc.clone(),
            bad_length.clone(),
            padding.clone(),
            duplicate.clone(),
            record(b"rars/0.1.0\nmarker-schema=2\n"),
            record(b"rars/\nmarker-schema=1\n"),
            record(&[b'a'; 129]),
            b"unknown".to_vec(),
        ] {
            let archive = ArchiveReader::read_owned(replace(&bytes, &extra)).unwrap();
            assert!(archive.preserving_builder(None).is_err());
        }
    }
}

#[test]
fn every_old_volume_has_a_producer() {
    for store in [false, true] {
        let volumes = volume_size::sized_for_payload(16, |size| {
            builder(store, false)
                .volume_size(Some(size))
                .build_volumes(None)
        })
        .unwrap();
        assert!(volumes.len() > 1);
        for bytes in volumes {
            check(&bytes);
        }
    }
}

#[cfg(feature = "encryption")]
#[test]
fn old_password_archives_keep_marker_public() {
    for store in [false, true] {
        let bytes = builder(store, true)
            .password(Some(b"secret".to_vec()))
            .to_bytes()
            .unwrap();
        check(&bytes);
        ArchiveReader::read_owned(bytes)
            .unwrap()
            .test(Some(b"secret"))
            .unwrap();
    }
}

#[test]
fn empty_old_archive_has_only_header_metadata() {
    for comment in [None, Some(b"user comment".as_slice())] {
        let bytes = rars::rar13::write_stored_archive_with_comment(
            &[],
            rars::rar13::WriterOptions::default(),
            comment,
        )
        .unwrap();
        check(&bytes);
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]) as usize,
            bytes.len()
        );
        let archive = ArchiveReader::read_owned(bytes).unwrap();
        assert_eq!(archive.members().count(), 0);
        assert_eq!(archive.comment(None).unwrap().as_deref(), comment);
    }
}

#[test]
fn marker_must_follow_a_complete_comment_and_cannot_mask_authenticity() {
    let bytes = builder(true, true).to_bytes().unwrap();
    let end = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let mut misplaced = bytes.clone();
    misplaced[7..end].rotate_right(record(DATA).len());
    let mut truncated_comment = bytes.clone();
    truncated_comment[7..9].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut authenticity = bytes;
    authenticity[6] |= 0x20;
    for bytes in [misplaced, truncated_comment, authenticity] {
        let archive = ArchiveReader::read_owned(bytes).unwrap();
        assert!(archive.preserving_builder(None).is_err());
    }
}
