use rars::{Archive, ArchiveReader, ArchiveVersion, Builder};

fn archive(size: usize) -> rars::rar50::Archive {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), vec![42; size], None, None)
        .unwrap();
    match ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap() {
        Archive::Rar50Plus(a) => a,
        _ => unreachable!(),
    }
}

#[test]
fn unknown_size_flag_does_not_mean_zero_or_the_placeholder_value() {
    for size in [0, 32] {
        let a = archive(size);
        let mut file = a.files().next().unwrap().clone();
        assert_eq!(file.known_unpacked_size(), Some(size as u64));
        file.file_flags |= 0x0008;
        for placeholder in [0, 1, u64::MAX] {
            file.unpacked_size = placeholder;
            assert_eq!(file.known_unpacked_size(), None);
        }
        file.file_flags &= !0x0008;
        assert_eq!(file.known_unpacked_size(), Some(u64::MAX));
    }
}
