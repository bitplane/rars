use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error, ErrorKind};
#[path = "support/scratch.rs"]
mod scratch;

fn headers(a: &Archive, raw: &[u8]) -> Vec<u64> {
    match a {
        Archive::Rar13(a) => std::iter::once(a.main.head_size as u64)
            .chain(a.entries.iter().map(|e| e.header.head_size as u64))
            .collect(),
        Archive::Rar15To40(a) => {
            let mut sizes = vec![a.main.head_size as u64];
            for b in &a.blocks {
                let h = match b {
                    rars::rar15_40::Block::File(f) => &f.block,
                    rars::rar15_40::Block::NewSub(s) => &s.file.block,
                    rars::rar15_40::Block::Comment(c) => &c.block,
                    rars::rar15_40::Block::Protect(p) => &p.block,
                    rars::rar15_40::Block::End(h) | rars::rar15_40::Block::Unknown(h) => h,
                    _ => unreachable!(),
                };
                // A nested main comment is represented separately in blocks.
                if h.offset >= 7 + a.main.head_size as usize {
                    sizes.push(h.head_size as u64);
                }
            }
            sizes
        }
        Archive::Rar50Plus(a) => {
            let size = |h: &rars::rar50::BlockHeader| {
                4 + u64::from((64 - h.header_size.leading_zeros()).div_ceil(7).max(1))
                    + h.header_size
            };
            let mut sizes = Vec::new();
            if a.main.encrypted_headers {
                // Generated archive-encryption headers have a one-byte size.
                let declared = raw[a.sfx_offset + 12];
                assert!(declared < 128);
                sizes.push(5 + u64::from(declared));
            }
            sizes.push(size(&a.main.block));
            sizes.extend(a.blocks.iter().map(|b| {
                size(match b {
                    rars::rar50::Block::File(f) | rars::rar50::Block::Service(f) => &f.block,
                    rars::rar50::Block::End(e) => &e.block,
                    rars::rar50::Block::Unknown(h) => h,
                    _ => unreachable!(),
                })
            }));
            sizes
        }
        _ => unreachable!(),
    }
}

fn typed_read(raw: &[u8], options: ArchiveReadOptions<'_>, owned: bool) -> rars::Result<Archive> {
    match rars::find_archive_start(raw, rars::SFX_SCAN_LIMIT)
        .unwrap()
        .family
    {
        rars::ArchiveFamily::Rar13 => {
            if owned {
                rars::rar13::Archive::parse_owned_with_options(raw.to_vec(), options)
                    .map(Archive::Rar13)
            } else {
                rars::rar13::Archive::parse_with_options(raw, options).map(Archive::Rar13)
            }
        }
        rars::ArchiveFamily::Rar15To40 => {
            if owned {
                rars::rar15_40::Archive::parse_owned_with_options(raw.to_vec(), options)
                    .map(Archive::Rar15To40)
            } else {
                rars::rar15_40::Archive::parse_with_options(raw, options).map(Archive::Rar15To40)
            }
        }
        rars::ArchiveFamily::Rar50Plus => {
            if owned {
                rars::rar50::Archive::parse_owned_with_options(raw.to_vec(), options)
                    .map(Archive::Rar50Plus)
            } else {
                rars::rar50::Archive::parse_with_options(raw, options).map(Archive::Rar50Plus)
            }
        }
        _ => unreachable!(),
    }
}

#[test]
fn header_limits_cover_families_entry_points_sfx_and_fresh_calls() {
    let dir = scratch::case("header-limits");
    let path = dir.join("archive.rar");
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        let mut b = Builder::new(format).store(true);
        for name in [b"first".as_slice(), b"second".as_slice()] {
            b.add_bytes(name.to_vec(), vec![42; 64], None, None)
                .unwrap();
        }
        let original = b.to_bytes().unwrap();
        let expected = ArchiveReader::read(&original).unwrap();
        let sizes = headers(&expected, &original);
        let count = sizes.len() as u64;
        let bytes = sizes.iter().sum::<u64>();
        for sfx in [false, true] {
            let mut raw = if sfx {
                b"MZ small test stub".to_vec()
            } else {
                vec![]
            };
            raw.extend_from_slice(&original);
            std::fs::write(&path, &raw).unwrap();
            for options in [
                ArchiveReadOptions::new(),
                ArchiveReadOptions::new()
                    .with_max_header_count(count)
                    .with_max_header_bytes(bytes),
                ArchiveReadOptions::new()
                    .with_max_header_count(u64::MAX)
                    .with_max_header_bytes(u64::MAX),
                ArchiveReadOptions::new().with_max_header_count(count - 1),
                ArchiveReadOptions::new().with_max_header_bytes(bytes - 1),
                ArchiveReadOptions::new()
                    .with_max_header_count(0)
                    .with_max_header_bytes(0),
                ArchiveReadOptions::new().with_max_header_bytes(0),
            ] {
                let reject_count = options.max_header_count.is_some_and(|n| n < count);
                let reject_bytes = options.max_header_bytes.is_some_and(|n| n < bytes);
                let typed_path = match &expected {
                    Archive::Rar13(_) => {
                        rars::rar13::Archive::parse_path_with_options(&path, options)
                            .map(Archive::Rar13)
                    }
                    Archive::Rar15To40(_) => {
                        rars::rar15_40::Archive::parse_path_with_options(&path, options)
                            .map(Archive::Rar15To40)
                    }
                    Archive::Rar50Plus(_) => {
                        rars::rar50::Archive::parse_path_with_options(&path, options)
                            .map(Archive::Rar50Plus)
                    }
                    _ => unreachable!(),
                };
                let results = [
                    ArchiveReader::read_with_options(&raw, options),
                    ArchiveReader::read_owned_with_options(raw.clone(), options),
                    ArchiveReader::read_path_with_options(&path, options),
                    typed_read(&raw, options, false),
                    typed_read(&raw, options, true),
                    typed_path,
                    // Options are configuration, not mutable shared accounting.
                    ArchiveReader::read_with_options(&raw, options),
                ];
                for result in results {
                    if reject_count || reject_bytes {
                        let e = result.unwrap_err();
                        assert_eq!(e.kind(), ErrorKind::ResourceLimit, "{format:?}: {e}");
                        assert!(matches!(e, Error::AtArchiveOffset { .. }));
                        if reject_count {
                            assert!(
                                matches!(e.root_cause(), Error::HeaderCountLimitExceeded {limit,required}
                                if *required == limit+1)
                            );
                        } else {
                            let required = if options.max_header_bytes == Some(0) {
                                sizes[0]
                            } else {
                                bytes
                            };
                            assert!(
                                matches!(e.root_cause(), Error::HeaderBytesLimitExceeded {required:r,..} if *r==required)
                            );
                        }
                    } else {
                        let a = result.unwrap();
                        assert_eq!(a.members().count(), 2);
                        // Parser policy must not become an extraction-output quota.
                        a.test(None).unwrap();
                    }
                }
            }
        }
    }
}

#[test]
fn comments_and_encrypted_headers_are_charged_once_by_plaintext_size() {
    let dir = scratch::case("encrypted-header-limits");
    let path = dir.join("archive.rar");
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        for encrypted in [false, true] {
            if encrypted && matches!(format, ArchiveVersion::Rar14 | ArchiveVersion::Rar29) {
                continue;
            }
            let comment =
                (!(encrypted && format == ArchiveVersion::Rar30)).then(|| b"comment".repeat(30));
            let mut b = Builder::new(format)
                .store(true)
                .comment(comment.clone())
                .password(encrypted.then(|| b"secret".to_vec()))
                .header_encryption(encrypted);
            b.add_bytes(b"file".to_vec(), vec![42; 16], None, None)
                .unwrap();
            let raw = b.to_bytes().unwrap();
            std::fs::write(&path, &raw).unwrap();
            let options = ArchiveReadOptions::with_password(b"secret");
            let a = ArchiveReader::read_with_options(&raw, options).unwrap();
            let sizes = headers(&a, &raw);
            let bytes = sizes.iter().sum::<u64>();
            let count = sizes.len() as u64;
            for options in [
                options
                    .with_max_header_count(count)
                    .with_max_header_bytes(bytes),
                options.with_max_header_count(count - 1),
                options.with_max_header_bytes(bytes - 1),
            ] {
                for result in [
                    ArchiveReader::read_with_options(&raw, options),
                    ArchiveReader::read_path_with_options(&path, options),
                ] {
                    if options.max_header_count == Some(count - 1)
                        || options.max_header_bytes == Some(bytes - 1)
                    {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::ResourceLimit);
                    } else {
                        let a = result.unwrap();
                        assert_eq!(a.comment(Some(b"secret")).unwrap(), comment);
                        a.test(Some(b"secret")).unwrap();
                    }
                }
            }
        }
    }
}

#[test]
fn unknown_headers_count_and_existing_tail_handling_stays_tolerant() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut b = Builder::new(format).store(true);
        b.add_bytes(b"file".to_vec(), vec![42; 32], None, None)
            .unwrap();
        let mut raw = b.to_bytes().unwrap();
        let a = ArchiveReader::read(&raw).unwrap();
        match &a {
            Archive::Rar15To40(a) => {
                let h = &a.files().next().unwrap().block;
                raw[h.offset + 2] = 0x7f;
                let crc =
                    rars::crc32::crc32(&raw[h.offset + 2..h.offset + h.head_size as usize]) as u16;
                raw[h.offset..h.offset + 2].copy_from_slice(&crc.to_le_bytes());
            }
            Archive::Rar50Plus(a) => {
                let h = &a.files().next().unwrap().block;
                assert!(h.header_size < 128);
                raw[h.offset + 5] = 0x7f;
                let crc =
                    rars::crc32::crc32(&raw[h.offset + 4..h.offset + 5 + h.header_size as usize]);
                raw[h.offset..h.offset + 4].copy_from_slice(&crc.to_le_bytes());
            }
            Archive::Rar13(_) => {}
            _ => unreachable!(),
        }
        let a = ArchiveReader::read(&raw).unwrap();
        if format != ArchiveVersion::Rar14 {
            assert_eq!(a.members().count(), 0);
        }
        let sizes = headers(&a, &raw);
        let count = sizes.len() as u64;
        let bytes = sizes.iter().sum();
        // Short tails are ignored by legacy iteration; RAR5 stops at its end
        // record. Neither should consume an extra header allowance.
        raw.extend_from_slice(&[0x12, 0x34]);
        ArchiveReader::read_with_options(
            &raw,
            ArchiveReadOptions::new()
                .with_max_header_count(count)
                .with_max_header_bytes(bytes),
        )
        .unwrap();
        let e = ArchiveReader::read_with_options(
            &raw,
            ArchiveReadOptions::new().with_max_header_count(count - 1),
        )
        .unwrap_err();
        assert!(
            matches!(e.root_cause(),Error::HeaderCountLimitExceeded {required,..} if *required==count)
        );
    }
}

#[test]
fn physical_volume_parses_have_independent_allowances() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut b = Builder::new(format).store(true).volume_size(Some(512));
        b.add_bytes(b"split".to_vec(), vec![42; 2048], None, None)
            .unwrap();
        let raw_volumes = b.build_volumes(None).unwrap();
        assert!(raw_volumes.len() > 1);
        let mut volumes = Vec::new();
        for raw in raw_volumes {
            let a = ArchiveReader::read(&raw).unwrap();
            let sizes = headers(&a, &raw);
            volumes.push(
                ArchiveReader::read_owned_with_options(
                    raw,
                    ArchiveReadOptions::new()
                        .with_max_header_count(sizes.len() as u64)
                        .with_max_header_bytes(sizes.iter().sum()),
                )
                .unwrap(),
            );
        }
        rars::extract_volumes_to_with_options(
            &volumes,
            ArchiveReadOptions::new()
                .with_max_header_count(0)
                .with_max_header_bytes(0),
            |_| Ok(Box::new(std::io::sink())),
        )
        .unwrap();
    }
}

#[test]
fn directories_and_empty_members_still_consume_header_allowance() {
    let mut b = Builder::new(ArchiveVersion::Rar50).store(true);
    b.add_directory(b"dir".to_vec(), None, None).unwrap();
    b.add_bytes(b"empty".to_vec(), vec![], None, None).unwrap();
    let raw = b.to_bytes().unwrap();
    assert_eq!(ArchiveReader::read(&raw).unwrap().members().count(), 2);
    let e =
        ArchiveReader::read_with_options(&raw, ArchiveReadOptions::new().with_max_header_count(2))
            .unwrap_err();
    assert!(matches!(
        e.root_cause(),
        Error::HeaderCountLimitExceeded {
            limit: 2,
            required: 3
        }
    ));
}
