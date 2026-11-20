use rars::rar15_40::*;

use rars::{ArchiveVersion, Error, FeatureSet, Result};
use std::io::Write;

#[test]
#[cfg(feature = "recovery")]
fn rev3_repair_preserves_reconstruction_and_publication_failures() {
    let mut calls = 0;
    let error = repair_rev3_volumes_to(&[], 1, &[(0, b"data")], |_, _| {
        calls += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(
        error,
        Error::Rar3Recovery(rars::recovery::rar3::Error::InvalidCodewordSize)
    ));
    assert_eq!(calls, 0);

    let volumes: &[Option<&[u8]>] = &[Some(b"data"), Some(b"next")];
    let error = repair_rev3_volumes_to(volumes, 1, &[(0, b"0000")], |index, bytes| {
        calls += 1;
        assert_eq!(index, 0);
        assert_eq!(bytes, b"data");
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "publication denied").into())
    })
    .unwrap_err();
    assert!(
        matches!(error, Error::Io(ref source) if source.kind == std::io::ErrorKind::PermissionDenied && source.message == "publication denied")
    );
    assert_eq!(calls, 1, "publication stops at the failing volume");
    let mut published = Vec::new();
    repair_rev3_volumes_to(volumes, 1, &[(0, b"0000")], |index, bytes| {
        published.push((index, bytes.to_vec()));
        Ok(())
    })
    .unwrap();
    assert_eq!(published, [(0, b"data".to_vec()), (1, b"next".to_vec())]);
}

#[test]
fn edited_archive_comment_range_preserves_source_refusal() {
    let mut builder = rars::Builder::new(ArchiveVersion::Rar15)
        .store(true)
        .comment(Some(b"note".to_vec()));
    builder
        .add_bytes(b"entry".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let mut archive = Archive::parse_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(&b"note"[..])
    );
    let comment = archive
        .blocks
        .iter_mut()
        .find_map(|block| match block {
            Block::Comment(comment) => Some(comment),
            _ => None,
        })
        .unwrap();
    comment.packed_range = usize::MAX..usize::MAX;
    assert!(matches!(archive.archive_comment(), Err(Error::TooShort)));
}

#[test]
#[cfg(feature = "recovery")]
fn edited_public_recovery_ranges_keep_typed_refusals() {
    let old = Archive::parse(include_bytes!(
        "../fixtures/rar15_40/rar250_protect_head_rr1.rar"
    ))
    .unwrap();
    let mut out_of_source = old.clone();
    let protect = out_of_source
        .blocks
        .iter_mut()
        .find_map(|block| match block {
            Block::Protect(protect) => Some(protect),
            _ => None,
        })
        .unwrap();
    protect.data_range = usize::MAX..usize::MAX;
    assert!(matches!(
        out_of_source.repair_protect_head(),
        Err(Error::TooShort)
    ));
    let mut overflow = old;
    overflow.sfx_offset = usize::MAX;
    assert!(matches!(
        overflow.repair_protect_head(),
        Err(Error::InvalidHeader(
            "RAR 2.x protected sector range overflows"
        ))
    ));

    let mut modern = Archive::parse(include_bytes!(
        "../fixtures/rar15_40/rar300/with_recovery_rar300.rar"
    ))
    .unwrap();
    modern.sfx_offset = 1;
    let recovery = modern
        .blocks
        .iter_mut()
        .find_map(|block| match block {
            Block::NewSub(sub) if sub.kind == NewSubKind::RecoveryRecord => Some(sub),
            _ => None,
        })
        .unwrap();
    recovery.file.block.offset = usize::MAX;
    assert!(matches!(
        modern.repair_protect_head(),
        Err(Error::InvalidHeader(
            "RAR 3.x recovery protected range overflows"
        ))
    ));
}

#[test]
fn directory_callbacks_preserve_failure_and_cancellation_in_both_extractors() {
    let mut builder = rars::Builder::new(ArchiveVersion::Rar29);
    builder
        .add_directory(b"directory".to_vec(), None, None)
        .unwrap();
    let archive = Archive::parse_owned(builder.to_bytes().unwrap()).unwrap();
    for parallel in [false, true] {
        for cancel in [false, true] {
            let token = rars::ReadCancellation::new();
            let mut calls = 0;
            let open = |meta: &ExtractedEntryMeta| -> Result<Box<dyn Write>> {
                calls += 1;
                assert!(meta.is_directory);
                assert_eq!(meta.name, b"directory");
                if cancel {
                    token.cancel();
                    Ok(Box::new(std::io::sink()))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "directory refused",
                    )
                    .into())
                }
            };
            let options = rars::ArchiveReadOptions::new().with_cancellation(&token);
            let error = if parallel {
                archive.extract_to_parallel_buffered(options, open)
            } else {
                archive.extract_to(options, open)
            }
            .unwrap_err();
            if cancel {
                assert!(matches!(error.root_cause(), Error::Cancelled));
            } else {
                assert!(
                    matches!(error.root_cause(), Error::Io(error) if error.kind == std::io::ErrorKind::PermissionDenied && error.message == "directory refused")
                );
            }
            assert_eq!(calls, 1);
        }
    }
}

#[test]
fn writer_options_constructor_and_default_match_documented_targets() {
    let default = WriterOptions::default();
    assert_eq!(default.target, ArchiveVersion::Rar15);
    assert_eq!(default.features, FeatureSet::store_only());

    let explicit = WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only());
    assert_eq!(explicit.target, ArchiveVersion::Rar20);
    assert_eq!(explicit.features, FeatureSet::store_only());
}

fn stored_archive_bytes(name: &[u8], data: &[u8]) -> Vec<u8> {
    write_stored_archive(
        &[StoredEntry {
            name,
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap()
}

#[test]
fn archive_parse_owned_consumes_buffer_without_changing_dispatch() {
    let bytes = stored_archive_bytes(b"owned.txt", b"hello rar15 owned");
    let archive = Archive::parse_owned(bytes.clone()).unwrap();
    assert_eq!(archive.files().count(), 1);
    let file = archive.files().next().unwrap();
    assert_eq!(file.name, b"owned.txt");

    // Default ArchiveReadOptions delegate also drives the same code path.
    let with_options =
        Archive::parse_owned_with_options(bytes.clone(), rars::ArchiveReadOptions::default())
            .unwrap();
    assert_eq!(with_options.files().count(), 1);

    let no_password = Archive::parse_owned_with_password(bytes, None).unwrap();
    assert_eq!(no_password.files().count(), 1);
}

#[test]
fn file_header_write_packed_data_streams_through_writer() {
    let payload = b"write_packed_data direct dump";
    let bytes = stored_archive_bytes(b"dump.bin", payload);
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    let mut sink = Vec::new();
    file.write_packed_data(&archive, &mut sink).unwrap();
    assert_eq!(sink, payload);
}

#[test]
fn direct_stored_writer_rejects_inconsistent_and_short_payloads() {
    let bytes = stored_archive_bytes(b"entry", b"payload");
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    let mut inconsistent = file.clone();
    inconsistent.unp_size += 1;
    let mut output = Vec::new();
    assert!(matches!(
        inconsistent.write_to(&archive, None, &mut output),
        Err(Error::InvalidHeader(
            "RAR 1.5 stored file has mismatched packed and unpacked sizes"
        ))
    ));
    assert!(output.is_empty());

    // A valid header can still name a short range when its source is damaged.
    let mut short = file.clone();
    short.packed_range.end -= 1;
    assert!(matches!(
        short.write_to(&archive, None, &mut output),
        Err(Error::InvalidHeader(
            "RAR 1.5 stored file ended before unpacked size"
        ))
    ));
    assert_eq!(output, b"payloa");

    let mut directory = file.clone();
    directory.attr |= 0x10;
    let mut output = Vec::new();
    directory.write_to(&archive, None, &mut output).unwrap();
    assert!(output.is_empty());
}
