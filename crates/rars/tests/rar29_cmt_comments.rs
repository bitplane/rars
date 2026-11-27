#![cfg(all(feature = "write", feature = "encryption"))]

#[path = "support/data.rs"]
mod data;
#[path = "support/sinks.rs"]
mod sinks;
use data::half_noise;
use sinks::Capture;

use rars::rar15_40::{
    extract_volumes_to, write_compressed_archive_with_comment, write_stored_archive_with_comment,
    write_volumes_with_comment_to, Archive, Block, CollectedVolumes, EntrySource, FileEntry,
    MemberCoding, NewSubHeader, NewSubKind, StoredEntry, StreamingEntry, WriterOptions,
};
use rars::{ArchiveReadOptions, ArchiveVersion, FeatureSet, WriterResources};
use std::cell::RefCell;
use std::rc::Rc;

const COMMENT: &[u8] = b"rar29 archive note\r\n";
const PASSWORD: &[u8] = b"secret";
const MHD_COMMENT: u16 = 0x0002;
const FHD_PASSWORD: u16 = 0x0004;
const MARK_AND_MAIN: usize = 7 + 13;

fn noise(len: usize) -> Vec<u8> {
    half_noise(len, 0x9e37_79b9, b"cmt comment volumes ")
}

fn options(target: ArchiveVersion, header_encryption: bool) -> WriterOptions {
    let mut features = FeatureSet::store_only();
    features.header_encryption = header_encryption;
    WriterOptions::new(target, features)
}

fn single_archives(
    target: ArchiveVersion,
    password: Option<&'static [u8]>,
    header_encryption: bool,
    data: &[u8],
) -> Vec<Vec<u8>> {
    let stored = [StoredEntry {
        name: b"member.bin",
        data,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password,
        file_comment: None,
    }];
    let compressed = [FileEntry {
        name: b"member.bin",
        data,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password,
        file_comment: None,
    }];
    let options = options(target, header_encryption);
    vec![
        write_stored_archive_with_comment(&stored, options, Some(COMMENT)).unwrap(),
        write_compressed_archive_with_comment(&compressed, options, Some(COMMENT)).unwrap(),
    ]
}

fn volumes(
    target: ArchiveVersion,
    password: Option<&[u8]>,
    header_encryption: bool,
    coding: MemberCoding,
    data: &[u8],
) -> rars::Result<Vec<Vec<u8>>> {
    let mut entry = StreamingEntry::new(
        b"member.bin".to_vec(),
        EntrySource::from_bytes(data.to_vec()),
    )
    .with_file_time(0x5a21_0000)
    .with_file_attr(0x20)
    .with_host_os(3);
    if let Some(password) = password {
        entry = entry.with_password(password.to_vec());
    }
    let mut sink = CollectedVolumes::new();
    write_volumes_with_comment_to(
        &[entry],
        options(target, header_encryption),
        coding,
        Some(COMMENT),
        2048,
        &mut sink,
        &WriterResources::default(),
        None,
    )?;
    Ok(sink.take())
}

fn first_block_cmt(archive: &Archive) -> &NewSubHeader {
    match archive.blocks.first() {
        Some(Block::NewSub(sub)) if sub.kind == NewSubKind::ArchiveComment => sub,
        other => panic!("expected CMT straight after the main header, found {other:?}"),
    }
}

fn comment_subblocks(archive: &Archive) -> usize {
    archive
        .new_subs()
        .filter(|sub| sub.kind == NewSubKind::ArchiveComment)
        .count()
}

fn extract_only_member(archives: &[Archive], password: Option<&[u8]>) -> Vec<u8> {
    let data = Rc::new(RefCell::new(Vec::new()));
    let options = ArchiveReadOptions::with_optional_password(password);
    extract_volumes_to(archives, options, |_| {
        Ok(Box::new(Capture(Rc::clone(&data))))
    })
    .unwrap();
    let out = data.borrow().clone();
    out
}

#[test]
fn rar29_comments_are_plain_cmt_blocks_without_header_encryption() {
    let data = noise(3000);
    for password in [None, Some(PASSWORD)] {
        for bytes in single_archives(ArchiveVersion::Rar29, password, false, &data) {
            let archive = Archive::parse(&bytes).unwrap();
            assert_eq!(archive.main.flags & MHD_COMMENT, 0);
            let cmt = first_block_cmt(&archive);
            assert_eq!(cmt.file.block.flags & FHD_PASSWORD, 0);
            assert_eq!(cmt.file.salt, None);
            assert_eq!(cmt.file.unp_ver, 29);
            assert_eq!(archive.archive_comment().unwrap().as_deref(), Some(COMMENT));
            let member = archive.files().next().unwrap();
            assert_eq!(member.salt.is_some(), password.is_some());
            assert_eq!(extract_only_member(&[archive], password), data);
        }
    }
}

#[test]
fn rar29_header_encrypted_comment_has_a_data_salt_of_its_own() {
    let data = noise(3000);
    for bytes in single_archives(ArchiveVersion::Rar29, Some(PASSWORD), true, &data) {
        let archive = Archive::parse_with_password(&bytes, Some(PASSWORD)).unwrap();
        assert!(archive.main.has_encrypted_headers());
        assert_eq!(archive.main.flags & MHD_COMMENT, 0);
        let cmt = first_block_cmt(&archive);
        assert_ne!(cmt.file.block.flags & FHD_PASSWORD, 0);
        let comment_salt = cmt.file.salt.expect("the comment data is encrypted");
        let header_salt = &bytes[MARK_AND_MAIN..MARK_AND_MAIN + 8];
        let member_salt = archive.files().next().unwrap().salt.unwrap();
        assert_ne!(comment_salt.as_slice(), header_salt);
        assert_ne!(comment_salt, member_salt);
        assert_ne!(member_salt.as_slice(), header_salt);
        assert_eq!(
            archive
                .archive_comment_with_password(Some(PASSWORD))
                .unwrap()
                .as_deref(),
            Some(COMMENT)
        );
        assert_eq!(extract_only_member(&[archive], Some(PASSWORD)), data);
    }
}

#[test]
fn legacy_cmt_comments_go_in_the_first_volume_only() {
    let data = noise(6000);
    let cases = [
        (ArchiveVersion::Rar29, None, false),
        (ArchiveVersion::Rar29, Some(PASSWORD), false),
        (ArchiveVersion::Rar29, Some(PASSWORD), true),
        (ArchiveVersion::Rar30, None, false),
        (ArchiveVersion::Rar40, Some(PASSWORD), true),
    ];
    for (target, password, header_encryption) in cases {
        for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
            let label = format!("{target:?} {password:?} hp={header_encryption}");
            let set = volumes(target, password, header_encryption, coding, &data).unwrap();
            assert!(set.len() > 1, "{label}");
            let archives: Vec<_> = set
                .iter()
                .map(|volume| Archive::parse_with_password(volume, password).unwrap())
                .collect();
            assert_eq!(archives[0].main.flags & MHD_COMMENT, 0, "{label}");
            let cmt = if target == ArchiveVersion::Rar29 {
                first_block_cmt(&archives[0])
            } else {
                archives[0]
                    .new_subs()
                    .find(|sub| sub.kind == NewSubKind::ArchiveComment)
                    .expect("a CMT block in the first volume")
            };
            let rar29_hp = target == ArchiveVersion::Rar29 && header_encryption;
            assert_eq!(cmt.file.salt.is_some(), rar29_hp, "{label}");
            if rar29_hp {
                let header_salt = &set[0][MARK_AND_MAIN..MARK_AND_MAIN + 8];
                let member_salt = archives[0].files().next().unwrap().salt.unwrap();
                let comment_salt = cmt.file.salt.unwrap();
                assert_ne!(comment_salt.as_slice(), header_salt, "{label}");
                assert_ne!(comment_salt, member_salt, "{label}");
            }
            for later in &archives[1..] {
                assert_eq!(comment_subblocks(later), 0, "{label}");
            }
            assert_eq!(
                archives[0]
                    .archive_comment_with_password(password)
                    .unwrap()
                    .as_deref(),
                Some(COMMENT),
                "{label}"
            );
            assert_eq!(extract_only_member(&archives, password), data, "{label}");
        }
    }
}

#[test]
fn old_style_comment_volumes_are_refused() {
    let data = noise(6000);
    for target in [ArchiveVersion::Rar15, ArchiveVersion::Rar20] {
        let error = volumes(target, None, false, MemberCoding::Compressed, &data).unwrap_err();
        assert!(
            matches!(
                error,
                rars::Error::UnsupportedWriterOption {
                    option: rars::WriterOption::ArchiveComment,
                    ..
                }
            ),
            "{target:?}: {error:?}"
        );
    }
}
