use rars::ArchiveReader;
use rars::{
    read_volume_member_at, read_volume_member_at_with_options, Archive, ArchiveReadOptions,
};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct Reads {
    refused: AtomicBool,
    calls: AtomicUsize,
}

struct GuardedSource {
    bytes: Cursor<Vec<u8>>,
    reads: Arc<Reads>,
}

impl Read for GuardedSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads.calls.fetch_add(1, Ordering::Relaxed);
        if self.reads.refused.load(Ordering::Relaxed) {
            return Err(io::Error::other("unexpected volume read"));
        }
        self.bytes.read(buf)
    }
}

impl Seek for GuardedSource {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(from)
    }
}

fn guarded_set(volumes: Vec<Vec<u8>>) -> (Vec<Archive>, Vec<Arc<Reads>>) {
    volumes
        .into_iter()
        .map(|bytes| {
            let reads = Arc::new(Reads::default());
            let archive = ArchiveReader::read_reader(GuardedSource {
                bytes: Cursor::new(bytes),
                reads: reads.clone(),
            })
            .unwrap();
            reads.calls.store(0, Ordering::Relaxed);
            (archive, reads)
        })
        .unzip()
}

#[cfg(feature = "write")]
fn restrict_reads(archives: &[Archive], reads: &[Arc<Reads>], name: &[u8]) -> usize {
    let mut allowed = 0;
    for (archive, reads) in archives.iter().zip(reads) {
        let contains = archive
            .member_refs()
            .any(|member| member.name_bytes() == name);
        allowed += usize::from(contains);
        reads.refused.store(!contains, Ordering::Relaxed);
        reads.calls.store(0, Ordering::Relaxed);
    }
    assert!((1..archives.len()).contains(&allowed));
    allowed
}

#[cfg(feature = "write")]
fn assert_reads(reads: &[Arc<Reads>]) {
    for (volume, reads) in reads.iter().enumerate() {
        assert_eq!(
            reads.calls.load(Ordering::Relaxed) == 0,
            reads.refused.load(Ordering::Relaxed),
            "volume {volume}",
        );
    }
}

#[test]
fn reads_a_split_member_in_the_reader_only_build() {
    let volumes = [
        include_bytes!("fixtures/rar50/multivol.part1.rar").as_slice(),
        include_bytes!("fixtures/rar50/multivol.part2.rar"),
        include_bytes!("fixtures/rar50/multivol.part3.rar"),
    ];
    let (archives, _) = guarded_set(volumes.into_iter().map(<[u8]>::to_vec).collect());
    let expected = rars::read_volume_members_at(&archives, &[0], None)
        .unwrap()
        .pop()
        .unwrap();

    assert_eq!(
        read_volume_member_at_with_options(&archives, 0, ArchiveReadOptions::new()).unwrap(),
        expected,
    );
    assert_eq!(
        read_volume_member_at(&archives, usize::MAX, None).unwrap(),
        None
    );
}

#[test]
fn rejects_volumes_out_of_order() {
    let part = |bytes: &[u8]| ArchiveReader::read_reader(Cursor::new(bytes.to_vec())).unwrap();
    let part1 = part(include_bytes!("fixtures/rar50/multivol.part1.rar"));
    let part2 = part(include_bytes!("fixtures/rar50/multivol.part2.rar"));
    let part3 = part(include_bytes!("fixtures/rar50/multivol.part3.rar"));

    assert!(read_volume_member_at(&[part1, part3, part2], 0, None).is_err());
}

#[cfg(feature = "write")]
mod writer {
    use super::*;
    use rars::{ArchiveVersion, Builder, ErrorKind};

    const VOLUME_SIZE: usize = 4096;
    const NAMES: [&[u8]; 4] = [b"first", b"middle", b"split", b"last"];

    fn payload(seed: u32, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|index| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                if index % 8 < 6 {
                    state as u8
                } else {
                    b'a'
                }
            })
            .collect()
    }

    fn add(builder: &mut Builder, index: usize, data: &[u8]) {
        builder
            .add_bytes(NAMES[index].to_vec(), data.to_vec(), None, None)
            .unwrap();
    }

    fn build_set(
        version: ArchiveVersion,
        stored: bool,
        password: Option<&[u8]>,
        data: &[Vec<u8>; 4],
    ) -> Vec<Vec<u8>> {
        let mut builder = Builder::new(version)
            .store(stored)
            .password(password.map(<[u8]>::to_vec))
            .volume_size(Some(VOLUME_SIZE));
        for (index, bytes) in data.iter().enumerate() {
            add(&mut builder, index, bytes);
        }
        builder.build_volumes(None).unwrap()
    }

    fn select_independent_members(password: Option<&[u8]>) {
        let data = [
            payload(1, 15_000),
            vec![b'm'; 320],
            payload(3, 29_000),
            vec![b'l'; 640],
        ];
        for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
            for stored in [false, true] {
                let (archives, reads) = guarded_set(build_set(version, stored, password, &data));
                let members = rars::volume_members(&archives).unwrap();
                assert_eq!(members.len(), NAMES.len());
                assert!(archives.iter().all(|archive| !archive.is_solid()));
                for index in [1, 2, 3] {
                    let meta = &members[index].meta;
                    assert_eq!(meta.name, NAMES[index]);
                    assert_eq!(meta.is_stored, stored, "{version:?}, index {index}");
                    assert_eq!(meta.is_encrypted, password.is_some());
                    let occupied = restrict_reads(&archives, &reads, NAMES[index]);
                    if index == 2 {
                        assert!(occupied > 1);
                        assert_eq!(
                            read_volume_member_at(&archives, index, password)
                                .unwrap()
                                .as_deref(),
                            Some(data[index].as_slice()),
                        );
                    } else {
                        assert_eq!(occupied, 1, "{version:?}, stored={stored}, index {index}");
                        let options = ArchiveReadOptions::with_optional_password(password)
                            .with_max_total_output_bytes(data[index].len() as u64 + 1);
                        assert_eq!(
                            read_volume_member_at_with_options(&archives, index, options)
                                .unwrap()
                                .as_deref(),
                            Some(data[index].as_slice()),
                        );
                    }
                    assert_reads(&reads);
                }
            }
        }
    }

    #[test]
    fn reads_only_the_non_solid_members_fragment_volumes() {
        select_independent_members(None);
    }

    #[test]
    #[cfg(feature = "encryption")]
    fn reads_only_the_encrypted_members_fragment_volumes() {
        select_independent_members(Some(b"secret"));
    }

    #[test]
    fn solid_lookup_decodes_and_charges_the_prefix() {
        let first = payload(1, 30_000);
        let selected = first[5_000..25_000].to_vec();
        let suffix = payload(2, 20_000);
        let mut builder = Builder::new(ArchiveVersion::Rar50)
            .solid(true)
            .volume_size(Some(VOLUME_SIZE));
        for (index, bytes) in [&first, &selected, &suffix].into_iter().enumerate() {
            add(&mut builder, index, bytes);
        }
        let (archives, reads) = guarded_set(builder.build_volumes(None).unwrap());
        let members = rars::volume_members(&archives).unwrap();
        assert!(members[1].is_solid());
        assert!(!members[1].meta.is_stored);
        reads[0].refused.store(true, Ordering::Relaxed);
        assert_eq!(
            read_volume_member_at(&archives, 1, None)
                .unwrap_err()
                .kind(),
            ErrorKind::Io,
        );
        reads[0].refused.store(false, Ordering::Relaxed);
        let limit = (first.len() + selected.len()) as u64;
        let options = ArchiveReadOptions::new().with_max_total_output_bytes(limit);
        assert_eq!(
            read_volume_member_at_with_options(&archives, 1, options).unwrap(),
            Some(selected),
        );
        assert_eq!(
            read_volume_member_at_with_options(
                &archives,
                1,
                options.with_max_total_output_bytes(limit - 1),
            )
            .unwrap_err()
            .kind(),
            ErrorKind::ResourceLimit,
        );
    }
}
