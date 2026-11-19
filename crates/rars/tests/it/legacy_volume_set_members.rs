use rars::rar15_40::{
    extract_volumes_to, write_volumes_to, Archive, CollectedVolumes, EntrySource, MemberCoding,
    StreamingEntry, WriterOptions,
};
use rars::{ArchiveReadOptions, ArchiveVersion, FeatureSet, WriterResources};
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

fn bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|i| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            if i % 3 == 0 {
                (state >> 24) as u8
            } else {
                b"several members, one set "[i % 25]
            }
        })
        .collect()
}

fn file(name: &str, data: Vec<u8>) -> StreamingEntry {
    StreamingEntry::new(name.as_bytes().to_vec(), EntrySource::from_bytes(data))
        .with_file_time(0x5a21_3c4d)
        .with_file_attr(0x20)
        .with_host_os(2)
}

fn directory(name: &str) -> StreamingEntry {
    StreamingEntry::new(
        name.as_bytes().to_vec(),
        EntrySource::from_bytes(Vec::new()),
    )
    .with_file_time(0x5a21_3c4d)
    .with_file_attr(0x10)
    .with_host_os(2)
}

fn write(
    entries: &[StreamingEntry],
    options: WriterOptions,
    coding: MemberCoding,
    volume_size: usize,
) -> rars::Result<Vec<Vec<u8>>> {
    let mut sink = CollectedVolumes::new();
    write_volumes_to(
        entries,
        options,
        coding,
        volume_size,
        &mut sink,
        &WriterResources::default(),
        None,
    )?;
    Ok(sink.take())
}

#[derive(Debug, PartialEq)]
struct Extracted {
    name: Vec<u8>,
    is_directory: bool,
    data: Vec<u8>,
}

struct Collect(Rc<RefCell<Vec<u8>>>);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn extract(volumes: &[Vec<u8>], password: Option<&[u8]>) -> Vec<Extracted> {
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| Archive::parse_with_password(volume, password).unwrap())
        .collect();
    let options = match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::default(),
    };
    let found = RefCell::new(Vec::new());
    extract_volumes_to(&archives, options, |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        found
            .borrow_mut()
            .push((meta.name.clone(), meta.is_directory, Rc::clone(&data)));
        Ok(Box::new(Collect(data)))
    })
    .unwrap();
    found
        .into_inner()
        .into_iter()
        .map(|(name, is_directory, data)| Extracted {
            name,
            is_directory,
            data: data.borrow().clone(),
        })
        .collect()
}

fn expected(entries: &[(&str, Option<Vec<u8>>)]) -> Vec<Extracted> {
    entries
        .iter()
        .map(|(name, data)| Extracted {
            name: name.as_bytes().to_vec(),
            is_directory: data.is_none(),
            data: data.clone().unwrap_or_default(),
        })
        .collect()
}

#[test]
fn stored_members_pack_one_after_another_across_volumes() {
    let a = bytes(7_000, 1);
    let b = bytes(300, 2);
    let c = bytes(5_000, 3);
    let entries = [
        file("a.bin", a.clone()),
        file("b.nfo", b.clone()),
        file("c.bin", c.clone()),
    ];
    for target in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        let options = WriterOptions::new(target, FeatureSet::store_only());
        let volumes = write(&entries, options, MemberCoding::Stored, 3000).unwrap();
        assert!(volumes.iter().all(|volume| volume.len() <= 3000));
        // 12,300 bytes in 3,000-byte volumes: had each member started a fresh
        // volume, the set would need seven.
        assert_eq!(volumes.len(), 5, "{target:?}");
        assert_eq!(
            extract(&volumes, None),
            expected(&[
                ("a.bin", Some(a.clone())),
                ("b.nfo", Some(b.clone())),
                ("c.bin", Some(c.clone()))
            ]),
            "{target:?}"
        );
    }
}

fn tree() -> (Vec<StreamingEntry>, Vec<Extracted>) {
    let a = bytes(9_000, 4);
    let c = bytes(2_500, 5);
    let entries = vec![
        directory("dir"),
        file("dir/a.txt", a.clone()),
        file("dir/empty", Vec::new()),
        directory("dir/sub"),
        file("dir/sub/c.txt", c.clone()),
    ];
    let expected = expected(&[
        ("dir", None),
        ("dir/a.txt", Some(a)),
        ("dir/empty", Some(Vec::new())),
        ("dir/sub", None),
        ("dir/sub/c.txt", Some(c)),
    ]);
    (entries, expected)
}

#[test]
fn directories_and_empty_files_sit_between_split_members() {
    let (entries, expected) = tree();
    for target in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
            let options = WriterOptions::new(target, FeatureSet::store_only());
            let volumes = write(&entries, options, coding.clone(), 2000).unwrap();
            assert!(volumes.len() > 1, "{target:?} {coding:?}");
            assert!(volumes.iter().all(|volume| volume.len() <= 2000));
            assert_eq!(extract(&volumes, None), expected, "{target:?} {coding:?}");
        }
    }
}

#[test]
fn compressed_sets_can_be_solid_encrypted_or_both() {
    let (entries, expected) = tree();
    let with_password: Vec<_> = entries
        .iter()
        .cloned()
        .map(|entry| entry.with_password(b"secret".to_vec()))
        .collect();
    for target in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        for (solid, header_encryption, password) in [
            (true, false, None),
            (false, false, Some(&b"secret"[..])),
            (true, false, Some(&b"secret"[..])),
            (false, true, Some(&b"secret"[..])),
        ] {
            if header_encryption && target == ArchiveVersion::Rar20 {
                continue;
            }
            let mut features = FeatureSet::store_only();
            features.solid = solid;
            features.header_encryption = header_encryption;
            let entries = if password.is_some() {
                &with_password
            } else {
                &entries
            };
            let options = WriterOptions::new(target, features);
            let volumes = write(entries, options, MemberCoding::Compressed, 2000).unwrap();
            assert_eq!(
                extract(&volumes, password),
                expected,
                "{target:?} solid={solid} headers={header_encryption}"
            );
        }
    }
}

#[test]
fn old_volumes_end_mid_member_so_readers_move_on() {
    // RAR 1.5 and 2.0 volumes have no end block: RAR and UnRAR open the next
    // volume only when the last member in this one continues there, and
    // otherwise stop, reporting success, with members still unread.
    let a = bytes(700, 6);
    let b = bytes(900, 7);
    let entries = [
        file("a.bin", a.clone()),
        file("one", vec![b'z']),
        directory("dir"),
        file("b.bin", b.clone()),
    ];
    let expected = expected(&[
        ("a.bin", Some(a)),
        ("one", Some(vec![b'z'])),
        ("dir", None),
        ("b.bin", Some(b)),
    ]);
    for target in [ArchiveVersion::Rar15, ArchiveVersion::Rar20] {
        let options = WriterOptions::new(target, FeatureSet::store_only());
        for volume_size in 300..=900 {
            let volumes = write(&entries, options, MemberCoding::Stored, volume_size).unwrap();
            let (last, rest) = volumes.split_last().unwrap();
            for volume in rest {
                assert!(volume.len() <= volume_size);
                let archive = Archive::parse(volume).unwrap();
                let tail = archive.files().last().unwrap();
                assert!(
                    tail.is_split_after(),
                    "{target:?} at {volume_size}: a volume ends after {}",
                    tail.name_lossy()
                );
            }
            assert!(last.len() <= volume_size);
            assert_eq!(
                extract(&volumes, None),
                expected,
                "{target:?} {volume_size}"
            );
        }
    }
}

/// The Builder takes any number of members into a legacy set, reads each as
/// it is packed, and writes the set the streaming writer the CLI uses does.
#[test]
fn the_builder_writes_the_set_the_streaming_writer_does() {
    const MODE: u32 = 0o100644;
    let members = [
        ("a.bin", bytes(7_000, 1)),
        ("b.nfo", bytes(300, 2)),
        ("c.bin", bytes(5_000, 3)),
    ];
    let wanted: Vec<_> = members
        .iter()
        .map(|(name, data)| (*name, Some(data.clone())))
        .collect();
    for target in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        for (coding, solid) in [
            (MemberCoding::Stored, false),
            (MemberCoding::Compressed, false),
            (MemberCoding::Compressed, true),
        ] {
            let case = format!("{target:?} {coding:?} solid {solid}");
            let mut builder = rars::Builder::new(target)
                .store(coding == MemberCoding::Stored)
                .solid(solid)
                .volume_size(Some(3000));
            for (index, (name, data)) in members.iter().enumerate() {
                let name = name.as_bytes().to_vec();
                if index == 0 {
                    builder
                        .add_bytes(name, data.clone(), None, Some(MODE))
                        .unwrap();
                } else {
                    let source = EntrySource::from_bytes(data.clone());
                    builder.add_source(name, source, None, Some(MODE)).unwrap();
                }
            }
            let mut sink = CollectedVolumes::new();
            builder
                .write_volumes_to(&mut sink, &WriterResources::default(), None)
                .unwrap();
            let built = sink.take();
            assert!(built.len() > 1, "{case}");
            assert!(builder.build_volumes(None).unwrap() == built, "{case}");

            let entries: Vec<_> = members
                .iter()
                .map(|(name, data)| {
                    StreamingEntry::new(
                        name.as_bytes().to_vec(),
                        EntrySource::from_bytes(data.clone()),
                    )
                    .with_file_attr(MODE)
                })
                .collect();
            let mut features = FeatureSet::store_only();
            features.solid = solid;
            let streamed = write(
                &entries,
                WriterOptions::new(target, features),
                coding.clone(),
                3000,
            )
            .unwrap();
            assert!(built == streamed, "{case}");
            assert_eq!(extract(&built, None), expected(&wanted), "{case}");
        }
    }
}
