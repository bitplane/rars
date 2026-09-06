use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error};
use std::{cell::RefCell, io, io::Write, rc::Rc};

const VERSIONS: [ArchiveVersion; 7] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
    ArchiveVersion::Rar50,
];

struct Capture {
    bytes: Rc<RefCell<Vec<u8>>>,
    remaining: usize,
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let count = bytes.len().min(self.remaining);
        self.bytes.borrow_mut().extend_from_slice(&bytes[..count]);
        self.remaining -= count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn archive(version: ArchiveVersion, stored: bool) -> Archive {
    let mut builder = Builder::new(version).store(stored);
    for (name, data) in [
        (b"first".as_slice(), b"earlier output".to_vec()),
        (b"failing", vec![42; 4096]),
        (b"later", b"must not be opened".to_vec()),
    ] {
        builder.add_bytes(name.to_vec(), data, None, None).unwrap();
    }
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

fn corrupt_second_checksum(archive: &mut Archive) {
    match archive {
        Archive::Rar13(a) => a.entries[1].header.file_crc ^= 1,
        Archive::Rar15To40(a) => {
            for block in &mut a.blocks {
                if let rars::rar15_40::Block::File(file) = block {
                    if file.name == b"failing" {
                        file.file_crc ^= 1;
                    }
                }
            }
        }
        Archive::Rar50Plus(a) => {
            for block in &mut a.blocks {
                if let rars::rar50::Block::File(file) = block {
                    if file.name == b"failing" {
                        file.hash = None;
                        file.data_crc32 = Some(file.data_crc32.unwrap() ^ 1);
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

#[test]
fn integrity_failure_can_leave_the_entire_unverified_member_written() {
    for version in VERSIONS {
        for stored in [true, false] {
            let mut archive = archive(version, stored);
            corrupt_second_checksum(&mut archive);
            let bytes = Rc::new(RefCell::new(Vec::new()));
            let mut opened = Vec::new();
            let error = archive
                .extract_to_with_options(
                    ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
                    |meta| {
                        opened.push(meta.name.clone());
                        Ok(Box::new(Capture {
                            bytes: bytes.clone(),
                            remaining: usize::MAX,
                        }))
                    },
                )
                .unwrap_err();
            assert_eq!(error.entry_context().unwrap().0, b"failing");
            assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
            assert_eq!(opened, [b"first".to_vec(), b"failing".to_vec()]);
            let mut expected = b"earlier output".to_vec();
            expected.extend_from_slice(&[42; 4096]);
            assert_eq!(*bytes.borrow(), expected, "{version:?}, stored={stored}");
        }
    }
}

#[test]
fn sink_failure_keeps_the_accepted_prefix_and_stops_later_members() {
    for version in VERSIONS {
        for stored in [true, false] {
            let archive = archive(version, stored);
            let bytes = Rc::new(RefCell::new(Vec::new()));
            let mut opened = Vec::new();
            let error = archive
                .extract_to_with_options(
                    ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
                    |meta| {
                        opened.push(meta.name.clone());
                        Ok(Box::new(Capture {
                            bytes: bytes.clone(),
                            remaining: if meta.name == b"failing" {
                                17
                            } else {
                                usize::MAX
                            },
                        }))
                    },
                )
                .unwrap_err();
            assert!(
                matches!(error.root_cause(), Error::Io(e)
                if e.kind == io::ErrorKind::PermissionDenied),
                "{version:?}, stored={stored}: {error:?}"
            );
            assert_eq!(error.entry_context().unwrap().0, b"failing");
            assert_eq!(opened, [b"first".to_vec(), b"failing".to_vec()]);
            let mut expected = b"earlier output".to_vec();
            expected.extend_from_slice(&[42; 17]);
            assert_eq!(*bytes.borrow(), expected, "{version:?}, stored={stored}");
        }
    }
}
