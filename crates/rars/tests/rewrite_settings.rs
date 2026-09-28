use rars::{ArchiveReader, ArchiveVersion, Builder};

#[test]
fn preserving_builder_accepts_native_unix_directories() {
    for version in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_directory(b"directory".to_vec(), None, Some(0o750))
            .unwrap();
        let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(
            source.rewrite_preservation_issues().is_empty(),
            "{version:?}: {:?}",
            source.rewrite_preservation_issues()
        );

        let mut preserving = source.preserving_builder(None).unwrap();
        preserving
            .add_directory(b"renamed".to_vec(), None, Some(0o750))
            .unwrap();
        let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
        assert!(output.rewrite_preservation_issues().is_empty());
        let directory = output.members().next().unwrap();
        assert!(directory.meta.is_directory);
        assert_eq!(directory.meta.attr_source(), rars::AttrSource::Unix);
        assert_eq!(directory.meta.file_attr & 0o170777, 0o040750);
    }
}

#[test]
fn preserving_builder_refuses_unix_device_entries() {
    for version in [ArchiveVersion::Rar20, ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"device".to_vec(), Vec::new(), None, Some(0o020600))
            .unwrap();
        let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let member = source.members().next().unwrap();
        assert_eq!(member.meta.attr_source(), rars::AttrSource::Unix);
        assert!(!member.meta.is_directory);
        assert!(
            source
                .rewrite_preservation_issues()
                .iter()
                .any(|issue| issue.contains("special entry type or directory contents")),
            "{version:?}: attr={:o}, issues={:?}",
            member.meta.file_attr,
            source.rewrite_preservation_issues()
        );
        assert!(source.preserving_builder(None).is_err());
    }
}

#[test]
fn preserving_builder_refuses_directory_flag_with_unix_device_mode() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_directory(b"directory".to_vec(), None, Some(0o750))
        .unwrap();
    let mut source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let rars::Archive::Rar50Plus(archive) = &mut source else {
        unreachable!()
    };
    let file = archive
        .blocks
        .iter_mut()
        .find_map(|block| match block {
            rars::rar50::Block::File(file) => Some(file),
            _ => None,
        })
        .unwrap();
    file.attributes = 0o020600;

    let meta = source.members().next().unwrap().meta;
    assert!(meta.is_directory);
    assert_eq!(meta.attr_source(), rars::AttrSource::Unix);
    assert!(source
        .rewrite_preservation_issues()
        .iter()
        .any(|issue| issue.contains("special entry type or directory contents")));
    assert!(source.preserving_builder(None).is_err());
}

#[test]
fn preserving_builder_accepts_rar13_family_and_rar7_sources() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar70,
    ] {
        let mut builder = Builder::new(version).store(false);
        builder
            .add_bytes(
                b"source".to_vec(),
                b"payload payload payload".repeat(8),
                None,
                None,
            )
            .unwrap();
        let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(
            source.rewrite_preservation_issues().is_empty(),
            "{version:?}: {:?}",
            source.rewrite_preservation_issues()
        );
        let mut preserving = source.preserving_builder(None).unwrap();
        preserving
            .add_bytes(
                b"source".to_vec(),
                b"payload payload payload".repeat(8),
                None,
                None,
            )
            .unwrap();
        preserving
            .add_bytes(b"added".to_vec(), b"new payload".to_vec(), None, None)
            .unwrap();
        let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
        assert!(output.rewrite_preservation_issues().is_empty());
        assert_eq!(
            output.read_member_at(0, None).unwrap().unwrap(),
            b"payload payload payload".repeat(8)
        );
        assert_eq!(
            output.read_member_at(1, None).unwrap().unwrap(),
            b"new payload"
        );
    }
}

#[test]
fn preserving_builder_keeps_rar20_unpacker_26() {
    let payload = b"older RAR 2.x payload ".repeat(64);
    let mut builder = Builder::new(ArchiveVersion::Rar20).store(true);
    builder
        .add_bytes(b"source".to_vec(), payload.clone(), None, None)
        .unwrap();
    let mut bytes = builder.to_bytes().unwrap();
    let original = ArchiveReader::read_owned(bytes.clone()).unwrap();
    let rars::Archive::Rar15To40(original) = original else {
        unreachable!()
    };
    let file = original.files().next().unwrap();
    let start = file.block.offset;
    let end = start + usize::from(file.block.head_size);
    bytes[start + 24] = 26;
    let crc = (rars::crc32::crc32(&bytes[start + 2..end]) as u16).to_le_bytes();
    bytes[start..start + 2].copy_from_slice(&crc);

    let source = ArchiveReader::read_owned(bytes).unwrap();
    assert!(source.rewrite_preservation_issues().is_empty());
    assert_eq!(source.read_member_at(0, None).unwrap().unwrap(), payload);
    let mut preserving = source.preserving_builder(None).unwrap();
    preserving
        .add_bytes(b"source".to_vec(), payload.clone(), None, None)
        .unwrap();
    let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
    let rars::Archive::Rar15To40(ref archive) = output else {
        unreachable!()
    };
    assert_eq!(archive.files().next().unwrap().unp_ver, 26);
    assert_eq!(output.read_member_at(0, None).unwrap().unwrap(), payload);
}

#[test]
fn retained_legacy_comment_metadata_requires_the_comment_to_be_copied() {
    let mut builder = Builder::new(ArchiveVersion::Rar30)
        .store(true)
        .comment(Some(b"archive note".to_vec()));
    builder
        .add_bytes(b"source".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert!(source.rewrite_preservation_issues().is_empty());

    let mut preserving = source.preserving_builder(None).unwrap();
    preserving
        .add_bytes(b"source".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    assert!(matches!(
        preserving.to_bytes(),
        Err(rars::Error::InvalidArgument(
            "retained archive comment metadata requires a RAR3/4 archive comment"
        ))
    ));
    let output = ArchiveReader::read_owned(
        preserving
            .comment(Some(b"archive note".to_vec()))
            .to_bytes()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output.comment(None).unwrap(), Some(b"archive note".to_vec()));
}

#[test]
fn preserving_builder_requires_password_for_encrypted_legacy_archive_comment() {
    let mut builder = Builder::new(ArchiveVersion::Rar30)
        .store(true)
        .comment(Some(b"private note".to_vec()))
        .archive_comment_password(Some(b"secret".to_vec()));
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert!(source.rewrite_preservation_issues().is_empty());
    assert!(matches!(source.preserving_builder(None), Err(rars::Error::NeedPassword)));

    let mut preserving = source
        .preserving_builder(Some(b"secret"))
        .unwrap()
        .store(true)
        .comment(Some(b"private note".to_vec()));
    preserving
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    preserving.set_entry_encryption(b"file", None, None).unwrap();
    let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
    assert!(matches!(output.comment(None), Err(rars::Error::NeedPassword)));
    assert_eq!(output.comment(Some(b"secret")).unwrap(), Some(b"private note".to_vec()));
    assert_eq!(output.read_member(b"file", None).unwrap().unwrap(), b"payload");
}

#[test]
fn preserving_builder_keeps_rar7_compression_version() {
    use rars::{rar50, EntrySource, FeatureSet};

    let payload = b"RAR7 compression payload ".repeat(256);
    let entry = rar50::ArchiveEntry::new(
        b"source".to_vec(),
        EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(payload.clone())),
    );
    let bytes = rar50::Rar50Writer::new(
        rar50::WriterOptions::new(ArchiveVersion::Rar70, FeatureSet::default())
            .with_dictionary_size(192 * 1024),
    )
    .entry(entry)
    .finish()
    .unwrap();
    let source = ArchiveReader::read_owned(bytes).unwrap();
    let rars::Archive::Rar50Plus(ref archive) = source else {
        unreachable!()
    };
    assert_eq!(archive.files().next().unwrap().compression_info & 0x3f, 1);
    let mut preserving = source.preserving_builder(None).unwrap();
    assert_eq!(preserving.format(), ArchiveVersion::Rar70);
    preserving
        .add_bytes(b"source".to_vec(), payload.clone(), None, None)
        .unwrap();
    let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
    let rars::Archive::Rar50Plus(ref archive) = output else {
        unreachable!()
    };
    assert_eq!(archive.files().next().unwrap().compression_info & 0x3f, 1);
    assert_eq!(output.read_member_at(0, None).unwrap().unwrap(), payload);
}

#[test]
fn preserving_builder_requires_password_for_encrypted_legacy_members() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        let mut builder = Builder::new(version)
            .store(true)
            .password(Some(b"secret".to_vec()));
        builder
            .add_bytes(b"encrypted".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(source.rewrite_preservation_issues().is_empty(), "{version:?}");
        assert!(matches!(
            source.preserving_builder(None),
            Err(rars::Error::NeedPassword)
        ));
        assert!(matches!(
            source.preserving_builder(Some(b"")),
            Err(rars::Error::NeedPassword)
        ));
        let mut preserving = source.preserving_builder(Some(b"secret")).unwrap();
        preserving
            .add_bytes(b"encrypted".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
        assert_eq!(
            output.read_member_at(0, Some(b"secret")).unwrap().unwrap(),
            b"payload",
            "{version:?}"
        );
    }
}

#[test]
fn preserving_builder_refuses_an_sfx_prefix_it_cannot_preserve() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let mut prefixed = b"MZ-stub".to_vec();
    prefixed.extend(builder.to_bytes().unwrap());
    let source = ArchiveReader::read_owned(prefixed).unwrap();
    assert!(source
        .rewrite_preservation_issues()
        .contains(&"SFX executable prefix".to_string()));
    assert!(matches!(
        source.preserving_builder(None),
        Err(rars::Error::InvalidArgument(
            "archive has unsupported preservation settings"
        ))
    ));
}

#[test]
fn preservation_preflight_refuses_metadata_it_cannot_rewrite() {
    use rars::{rar50, Archive};

    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let Archive::Rar50Plus(seed) = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
    else {
        unreachable!()
    };
    assert!(Archive::Rar50Plus(seed.clone())
        .rewrite_preservation_issues()
        .is_empty());
    let check = |mutate: fn(&mut rar50::Archive), expected: &str| {
        let mut candidate = seed.clone();
        mutate(&mut candidate);
        let archive = Archive::Rar50Plus(candidate);
        let issues = archive.rewrite_preservation_issues();
        assert!(
            issues.iter().any(|issue| issue.contains(expected)),
            "missing {expected:?}: {issues:?}"
        );
        assert!(archive.preserving_builder(None).is_err());
    };
    check(
        |archive| archive.main.archive_flags |= 1 << 20,
        "main header metadata",
    );
    check(|archive| archive.main.archive_flags |= 1, "volume layout");
    check(|archive| archive.main.volume_number = Some(1), "volume layout");
    check(
        |archive| archive.main.block.flags |= 2,
        "main header metadata",
    );
    check(
        |archive| archive.main.block.data_size = Some(1),
        "main header metadata",
    );
    check(
        |archive| archive.main.archive_flags |= 8,
        "recovery flag and service disagree",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.name = b"../file".to_vec();
            }
        },
        "unsupported output name",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.host_os = 99;
            }
        },
        "unknown host attributes",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.block.flags |= 8;
            }
        },
        "split-volume layout",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.host_os = 1;
                file.attributes = 1 << 20;
            }
        },
        "unsupported or inconsistent attributes",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.host_os = 1;
                file.file_flags |= 1;
                file.attributes = 0o100644;
            }
        },
        "unsupported or inconsistent attributes",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.host_os = 0;
                file.attributes = 0x10;
            }
        },
        "unsupported or inconsistent attributes",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.block.flags |= 0x100;
            }
        },
        "unsupported, duplicate or incomplete metadata",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.file_flags |= 8;
            }
        },
        "unsupported, duplicate or incomplete metadata",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.compression_info |= 1 << 21;
            }
        },
        "unsupported, duplicate or incomplete metadata",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.compression_info = (file.compression_info & !0x3f) | 2;
            }
        },
        "unsupported compression algorithm",
    );
    check(
        |archive| {
            if let rar50::Block::File(file) = &mut archive.blocks[0] {
                file.compression_info |= 0x40;
            }
        },
        "solid dependency without a solid archive",
    );
    check(
        |archive| {
            if let rar50::Block::End(end) = archive.blocks.last_mut().unwrap() {
                end.flags = 1;
            }
        },
        "end header flags",
    );
    check(
        |archive| {
            if let rar50::Block::End(end) = archive.blocks.last_mut().unwrap() {
                end.block.flags = 1;
            }
        },
        "end header flags",
    );
    check(
        |archive| {
            if let rar50::Block::End(end) = archive.blocks.last_mut().unwrap() {
                end.block.header_size = 4;
            }
        },
        "end header flags",
    );
    check(
        |archive| {
            let mut unknown = archive.main.block.clone();
            unknown.header_type = 99;
            archive.blocks.push(rar50::Block::Unknown(unknown));
        },
        "unknown archive block",
    );
}

#[test]
fn preservation_preflight_checks_derived_service_and_locator_consistency() {
    use rars::{rar50, Archive};

    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(5))
        .archive_metadata(None, false, true)
        .unwrap();
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let Archive::Rar50Plus(seed) = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
    else {
        unreachable!()
    };
    assert!(Archive::Rar50Plus(seed.clone())
        .rewrite_preservation_issues()
        .is_empty());

    let mut invalid_service = seed.clone();
    let service = invalid_service
        .blocks
        .iter_mut()
        .find_map(|block| match block {
            rar50::Block::Service(service) if service.name == b"QO" => Some(service),
            _ => None,
        })
        .unwrap();
    service.attributes = 1;
    assert!(Archive::Rar50Plus(invalid_service)
        .rewrite_preservation_issues()
        .iter()
        .any(|issue| issue.contains("unsupported derived service")));

    let mut missing_service = seed.clone();
    missing_service
        .blocks
        .retain(|block| !matches!(block, rar50::Block::Service(service) if service.name == b"QO"));
    assert!(Archive::Rar50Plus(missing_service)
        .rewrite_preservation_issues()
        .iter()
        .any(|issue| issue.contains("locator refers to a missing service")));

    let mut missing_recovery = seed.clone();
    missing_recovery
        .blocks
        .retain(|block| !matches!(block, rar50::Block::Service(service) if service.name == b"RR"));
    let issues = Archive::Rar50Plus(missing_recovery).rewrite_preservation_issues();
    assert!(issues
        .iter()
        .any(|issue| issue.contains("recovery flag and service disagree")));
    assert!(issues
        .iter()
        .any(|issue| issue.contains("locator refers to a missing service")));

    let mut conflicting_encryption = seed;
    conflicting_encryption.main.encrypted_headers = true;
    assert!(Archive::Rar50Plus(conflicting_encryption)
        .rewrite_preservation_issues()
        .iter()
        .any(|issue| issue.contains("quick-open index with encrypted headers")));
}

#[test]
fn preservation_preflight_checks_every_derived_service_field() {
    use rars::{rar50, Archive, FileTimes, FileTimestamp};

    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(5))
        .archive_metadata(None, false, true)
        .unwrap();
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let Archive::Rar50Plus(seed) = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
    else {
        unreachable!()
    };
    let check = |name: &[u8], mutate: fn(&mut rar50::FileHeader)| {
        let mut candidate = seed.clone();
        let service = candidate
            .blocks
            .iter_mut()
            .find_map(|block| match block {
                rar50::Block::Service(service) if service.name == name => Some(service),
                _ => None,
            })
            .unwrap();
        mutate(service);
        let issues = Archive::Rar50Plus(candidate).rewrite_preservation_issues();
        assert!(
            issues.iter().any(|issue| issue.contains("unsupported derived service")),
            "{name:?}: {issues:?}"
        );
    };
    let q = b"QO";
    check(q, |service| service.encrypted = true);
    check(q, |service| service.mtime = Some(1));
    check(q, |service| {
        service.file_times = Some(FileTimes {
            modified: Some(FileTimestamp::Unix {
                seconds: 1,
                nanoseconds: 0,
            }),
            ..FileTimes::default()
        });
    });
    check(q, |service| service.file_flags |= 8);
    check(q, |service| service.block.flags |= 4);
    check(q, |service| service.attributes = 1);
    check(q, |service| service.host_os = 1);
    check(q, |service| service.compression_info = 1);
    check(b"RR", |service| service.service_data = Some(vec![0]));

    let mut duplicate = seed.clone();
    let service = duplicate
        .blocks
        .iter()
        .find(|block| matches!(block, rar50::Block::Service(service) if service.name == q))
        .unwrap()
        .clone();
    duplicate.blocks.push(service);
    assert!(Archive::Rar50Plus(duplicate)
        .rewrite_preservation_issues()
        .iter()
        .any(|issue| issue.contains("unsupported derived service")));
}

#[test]
fn preservation_preflight_checks_comment_service_metadata_and_duplicates() {
    use rars::{rar50, Archive, FileTimes, FileTimestamp};

    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .comment(Some(b"comment".to_vec()));
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let Archive::Rar50Plus(seed) = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
    else {
        unreachable!()
    };
    assert!(Archive::Rar50Plus(seed.clone())
        .rewrite_preservation_issues()
        .is_empty());
    let check = |mutate: fn(&mut rar50::FileHeader)| {
        let mut candidate = seed.clone();
        let service = candidate
            .blocks
            .iter_mut()
            .find_map(|block| match block {
                rar50::Block::Service(service) if service.name == b"CMT" => Some(service),
                _ => None,
            })
            .unwrap();
        mutate(service);
        let issues = Archive::Rar50Plus(candidate).rewrite_preservation_issues();
        assert!(
            issues.iter().any(|issue| issue.contains("service record")),
            "{issues:?}"
        );
    };
    check(|service| service.name = b"OTHER".to_vec());
    check(|service| service.mtime = Some(1));
    check(|service| {
        service.file_times = Some(FileTimes {
            modified: Some(FileTimestamp::Unix {
                seconds: 1,
                nanoseconds: 0,
            }),
            ..FileTimes::default()
        });
    });
    check(|service| service.file_flags |= 8);
    check(|service| service.block.flags |= 4);
    check(|service| service.attributes = 1);
    check(|service| service.host_os = 1);
    check(|service| service.compression_info |= 1 << 15);
    check(|service| service.compression_info |= 1);

    let mut duplicate = seed;
    let index = duplicate
        .blocks
        .iter()
        .position(|block| matches!(block, rar50::Block::Service(service) if service.name == b"CMT"))
        .unwrap();
    let service = duplicate.blocks[index].clone();
    duplicate.blocks.insert(index + 1, service);
    assert!(Archive::Rar50Plus(duplicate)
        .rewrite_preservation_issues()
        .iter()
        .any(|issue| issue.contains("service record")));
}

#[test]
fn legacy_rewrite_helpers_leave_regular_files_without_link_or_modern_metadata() {
    let mut builder = Builder::new(ArchiveVersion::Rar14).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(archive.member_comment_encryption(), [false]);
    assert_eq!(archive.legacy_symlink_targets(None).unwrap(), [None]);
    let member = archive.members().next().unwrap();
    assert!(member.file_times().unwrap().is_none());
    assert!(member.unix_symlink().is_none());
}

#[test]
fn preserving_builder_retains_encrypted_rar5_archive_comment_settings() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .comment(Some(b"private comment".to_vec()))
        .archive_comment_password(Some(b"secret".to_vec()));
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert!(archive.rewrite_preservation_issues().is_empty());
    assert!(matches!(
        archive.preserving_builder(None),
        Err(rars::Error::NeedPassword)
    ));
    let mut preserving = archive
        .preserving_builder(Some(b"secret"))
        .unwrap()
        .comment(Some(b"private comment".to_vec()));
    preserving
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        output.comment(None),
        Err(rars::Error::NeedPassword)
    ));
    assert_eq!(
        output.comment(Some(b"secret")).unwrap(),
        Some(b"private comment".to_vec())
    );
}

#[test]
fn preservation_preflight_refuses_volume_layout() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .volume_size(Some(64));
    builder
        .add_bytes(b"file".to_vec(), vec![42; 1024], None, None)
        .unwrap();
    let parts = builder.build_volumes(None).unwrap();
    assert!(parts.len() > 1);
    let first = ArchiveReader::read_owned(parts[0].clone()).unwrap();
    assert!(first
        .rewrite_preservation_issues()
        .iter()
        .any(|issue| issue.contains("volume layout")));
    assert!(first.preserving_builder(None).is_err());
}

#[test]
fn mixed_data_and_comment_encryption_are_independent() {
    for solid in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar50)
            .solid(solid)
            .password(Some(b"secret".to_vec()));
        for name in [b"plain".as_slice(), b"encrypted"] {
            builder
                .add_bytes(name.to_vec(), b"payload".repeat(100), None, None)
                .unwrap();
            builder
                .set_file_comment(name, Some(b"comment".to_vec()))
                .unwrap();
        }
        builder
            .set_entry_encryption(b"plain", None, Some(b"secret".to_vec()))
            .unwrap();
        builder
            .set_entry_encryption(b"encrypted", Some(b"secret".to_vec()), None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let members: Vec<_> = archive.members().collect();
        assert!(!members[0].meta.is_encrypted);
        assert!(members[1].meta.is_encrypted);
        assert_eq!(archive.member_comment_encryption(), [true, false]);
        assert!(archive.rewrite_preservation_issues().is_empty());
        assert!(archive.preserving_builder(None).is_err());
        assert!(archive.preserving_builder(Some(b"secret")).is_ok());
        assert_eq!(
            archive.read_member_at(1, Some(b"secret")).unwrap().unwrap(),
            b"payload".repeat(100)
        );
        assert_eq!(
            archive.member_comments(Some(b"secret")).unwrap(),
            [Some(b"comment".to_vec()), Some(b"comment".to_vec())]
        );
    }
}

#[test]
fn metadata_lock_indexes_and_recovery_are_retained_and_regenerated() {
    use rars::rar50::{
        ArchiveEntry, ArchiveMetadataEntry, MainExtraRecord, Rar50Writer, WriterOptions,
    };
    let bytes = Rar50Writer::new(WriterOptions::new(
        ArchiveVersion::Rar50,
        rars::FeatureSet::store_only(),
    ))
    .entries([ArchiveEntry::new(
        b"file".to_vec(),
        rars::EntrySource::from_bytes(b"payload".as_slice()),
    )
    .with_attributes(0x20)])
    .archive_metadata(Some(ArchiveMetadataEntry {
        name: Some(b"original.rar"),
        creation_time: Some(123),
    }))
    .finish()
    .unwrap();
    let seed = ArchiveReader::read_owned(bytes).unwrap();
    let rars::Archive::Rar50Plus(seed) = seed else {
        unreachable!()
    };
    let metadata = seed
        .main
        .extras
        .into_iter()
        .find_map(|extra| match extra {
            MainExtraRecord::ArchiveMetadata(value) => Some(value),
            _ => None,
        })
        .unwrap();
    for flags in [3, 7, 15] {
        let mut metadata = metadata.clone();
        metadata.flags = flags;
        let mut builder = Builder::new(ArchiveVersion::Rar50)
            .store(true)
            .recovery_percent(Some(5))
            .archive_metadata(Some(metadata.clone()), true, true)
            .unwrap();
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(
            source.rewrite_preservation_issues().is_empty(),
            "{:?}",
            source.rewrite_preservation_issues()
        );
        if flags == 3 {
            let mut invalid = source.clone();
            if let rars::Archive::Rar50Plus(archive) = &mut invalid {
                for extra in &mut archive.main.extras {
                    if let MainExtraRecord::ArchiveMetadata(metadata) = extra {
                        metadata.flags |= 1 << 20;
                    }
                }
            }
            assert!(invalid
                .rewrite_preservation_issues()
                .iter()
                .any(|issue| issue.contains("unsupported archive metadata")));
        }
        let mut rewritten = source.preserving_builder(None).unwrap();
        rewritten
            .add_bytes(b"renamed".to_vec(), b"new payload".to_vec(), None, None)
            .unwrap();
        let output = ArchiveReader::read_owned(rewritten.to_bytes().unwrap()).unwrap();
        assert!(
            output.rewrite_preservation_issues().is_empty(),
            "{:?}",
            output.rewrite_preservation_issues()
        );
        let rars::Archive::Rar50Plus(output) = output else {
            unreachable!()
        };
        assert!(output.main.is_locked());
        assert!(output.main.has_recovery_record());
        assert!(output.main.extras.iter().any(
            |extra| matches!(extra, MainExtraRecord::ArchiveMetadata(value) if value == &metadata)
        ));
        assert!(output.blocks.iter().any(
            |block| matches!(block, rars::rar50::Block::Service(service) if service.name == b"QO")
        ));
    }
}
