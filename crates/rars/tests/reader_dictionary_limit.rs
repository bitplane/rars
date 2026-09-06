use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ErrorKind};

#[test]
fn dictionary_limit_covers_streaming_and_encrypted_split_members() {
    let mut state = 0x1234_5678u32;
    let noise: Vec<u8> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let mut builder = Builder::new(format).password(Some(b"secret".to_vec()));
        builder
            .add_bytes(b"file".to_vec(), noise.repeat(3), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let required = match &archive {
            Archive::Rar50Plus(a) => {
                let f = a.files().next().unwrap();
                assert!(!f.is_stored());
                f.decoded_compression_info().unwrap().dictionary_size
            }
            _ => unreachable!(),
        };
        let volumes: Vec<_> = builder
            .volume_size(Some(512))
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
            .collect();
        assert!(volumes.len() > 1);
        for buffered in [0, u64::MAX] {
            for split in [false, true] {
                for reject in [false, true] {
                    // A missing password on refusal proves admission precedes decryption.
                    let options = ArchiveReadOptions::with_optional_password(if reject {
                        None
                    } else {
                        Some(b"secret".as_slice())
                    })
                    .with_rar50_buffered_decode_limit(buffered)
                    .with_rar50_dictionary_size_limit(if reject { 0 } else { required });
                    let mut opened = 0;
                    let open = |_: &rars::ExtractedEntryMeta| {
                        opened += 1;
                        Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>)
                    };
                    let result = if split {
                        rars::extract_volumes_to_with_options(&volumes, options, open)
                    } else {
                        archive.extract_to_with_options(options, open)
                    };
                    if reject {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), ErrorKind::ResourceLimit);
                        assert_eq!(error.entry_context().unwrap().0, b"file");
                        assert_eq!(opened, 0);
                    } else {
                        result.unwrap();
                        assert_eq!(opened, 1);
                    }
                }
            }
        }
    }
}

#[test]
fn zero_dictionary_limit_allows_stored_members_and_directories() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    builder
        .add_bytes(b"dir/file".to_vec(), vec![42; 32], None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let mut opened = 0;
    archive
        .extract_to_with_options(
            ArchiveReadOptions::new().with_rar50_dictionary_size_limit(0),
            |_| {
                opened += 1;
                Ok(Box::new(std::io::sink()))
            },
        )
        .unwrap();
    assert_eq!(opened, 2);
}
