#![cfg(feature = "write")]

use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder};
use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const VOLUME_SIZE: usize = 4096;

const VERSIONS: [ArchiveVersion; 5] = [
    ArchiveVersion::Rar13,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];

fn cases() -> impl Iterator<Item = (ArchiveVersion, bool)> {
    VERSIONS
        .into_iter()
        .flat_map(|version| [(version, true), (version, false)])
}

type Members = BTreeMap<Vec<u8>, Vec<u8>>;
type Outputs = Arc<Mutex<Members>>;

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2654435761) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn build_set(version: ArchiveVersion, stored: bool) -> (Members, Vec<Vec<u8>>) {
    let mut builder = Builder::new(version)
        .store(stored)
        .volume_size(Some(VOLUME_SIZE));
    let mut expected = BTreeMap::new();
    // Legacy volume writing takes one member, so those sets are one long split.
    let lengths: &[usize] = if version.family() == rars::ArchiveFamily::Rar50Plus {
        &[200, 30_000, 900, 9_000]
    } else {
        &[30_000]
    };
    for (index, &len) in lengths.iter().enumerate() {
        let name = format!("m{index}").into_bytes();
        let data = noise(index as u32, len);
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
        expected.insert(name, data);
    }
    let volumes = builder.build_volumes(None).unwrap();
    assert!(volumes.len() > 4, "{version:?}: need many volumes");
    (expected, volumes)
}

struct Collect(Outputs, Vec<u8>);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .entry(self.1.clone())
            .or_default()
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn recording<'a>(
    pulled: &'a mut Vec<usize>,
    mut next: impl FnMut(usize) -> Option<rars::Result<Archive>> + Send + 'a,
) -> impl Iterator<Item = rars::Result<Archive>> + Send + 'a {
    let mut index = 0;
    std::iter::from_fn(move || {
        index += 1;
        pulled.push(index);
        next(index)
    })
}

fn collector() -> (
    Outputs,
    impl FnMut(&rars::ExtractedEntryMeta) -> rars::Result<Box<dyn Write>>,
) {
    let outputs: Outputs = Arc::default();
    let sink = outputs.clone();
    (outputs, move |meta| {
        sink.lock().unwrap().insert(meta.name.clone(), Vec::new());
        Ok(Box::new(Collect(sink.clone(), meta.name.clone())) as Box<dyn Write>)
    })
}

#[test]
fn extracts_a_set_pulling_each_later_volume_in_order() {
    for (version, stored) in cases() {
        let (expected, volumes) = build_set(version, stored);
        let first = ArchiveReader::read_owned(volumes[0].clone()).unwrap();
        let mut pulled = Vec::new();
        let (outputs, open) = collector();

        first
            .extract_with_volumes(
                recording(&mut pulled, |index| {
                    volumes
                        .get(index)
                        .map(|bytes| ArchiveReader::read_owned(bytes.clone()))
                }),
                ArchiveReadOptions::new(),
                open,
            )
            .unwrap();

        assert_eq!(
            *outputs.lock().unwrap(),
            expected,
            "{version:?} stored={stored}"
        );
        // RAR 1.3 to 2.0 volumes have no end block to mark the last, so the iterator ending ends the set.
        let mut wanted: Vec<_> = (1..volumes.len()).collect();
        if matches!(
            version,
            ArchiveVersion::Rar13 | ArchiveVersion::Rar15 | ArchiveVersion::Rar20
        ) {
            wanted.push(volumes.len());
        }
        assert_eq!(pulled, wanted, "{version:?} stored={stored}");
    }
}

struct Retirable {
    data: std::io::Cursor<Vec<u8>>,
    retired: Arc<AtomicBool>,
}

impl Read for Retirable {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.retired.load(Ordering::SeqCst) {
            return Err(std::io::Error::other(
                "volume read after a later one was pulled",
            ));
        }
        self.data.read(buf)
    }
}

impl Seek for Retirable {
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        self.data.seek(from)
    }
}

fn retirable(bytes: &[u8]) -> (Archive, Arc<AtomicBool>) {
    let retired = Arc::new(AtomicBool::new(false));
    let archive = ArchiveReader::read_reader(Retirable {
        data: std::io::Cursor::new(bytes.to_vec()),
        retired: retired.clone(),
    })
    .unwrap();
    (archive, retired)
}

#[test]
fn never_reads_a_volume_again_once_the_next_is_pulled() {
    for (version, stored) in cases() {
        let (expected, volumes) = build_set(version, stored);
        let (first, first_retired) = retirable(&volumes[0]);
        let mut retired = vec![first_retired];
        let mut pulled = Vec::new();
        let (outputs, open) = collector();

        first
            .extract_with_volumes(
                recording(&mut pulled, |index| {
                    retired[index - 1].store(true, Ordering::SeqCst);
                    let (volume, flag) = retirable(volumes.get(index)?);
                    retired.push(flag);
                    Some(Ok(volume))
                }),
                ArchiveReadOptions::new(),
                open,
            )
            .unwrap();

        assert_eq!(
            *outputs.lock().unwrap(),
            expected,
            "{version:?} stored={stored}"
        );
    }
}

fn extract_from_bytes(
    volumes: &[Vec<u8>],
    options: ArchiveReadOptions<'_>,
    mut deliver: impl FnMut(usize, Archive) -> Option<Archive> + Send,
) -> (rars::Result<()>, Vec<usize>) {
    let first = ArchiveReader::read_owned(volumes[0].clone()).unwrap();
    let mut pulled = Vec::new();
    let (_, open) = collector();
    let result = first.extract_with_volumes(
        recording(&mut pulled, |index| {
            let volume = ArchiveReader::read_owned(volumes.get(index)?.clone()).unwrap();
            deliver(index, volume).map(Ok)
        }),
        options,
        open,
    );
    (result, pulled)
}

#[test]
fn volumes_ending_early_abort_the_set() {
    for (version, stored) in cases() {
        let (_, volumes) = build_set(version, stored);
        let (result, pulled) =
            extract_from_bytes(&volumes, ArchiveReadOptions::new(), |index, volume| {
                (index != 2).then_some(volume)
            });

        assert!(result.is_err(), "{version:?} stored={stored}");
        assert_eq!(pulled, [1, 2], "{version:?} stored={stored}");
    }
}

#[test]
fn cancelling_while_waiting_for_a_volume_stops_before_the_next() {
    for (version, stored) in cases() {
        let (_, volumes) = build_set(version, stored);
        let token = rars::ReadCancellation::new();
        let mut options = ArchiveReadOptions::new();
        options.cancellation = Some(&token);
        let (result, pulled) = extract_from_bytes(&volumes, options, |index, volume| {
            if index == 2 {
                token.cancel();
            }
            Some(volume)
        });

        assert_eq!(
            result.unwrap_err().kind(),
            rars::ErrorKind::Cancelled,
            "{version:?} stored={stored}"
        );
        assert_eq!(pulled, [1, 2], "{version:?} stored={stored}");
    }
}

fn fixture(path: &str) -> Archive {
    ArchiveReader::read_path(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(path),
    )
    .unwrap()
}

#[test]
fn extracts_sets_made_by_rar_without_pulling_past_the_last_volume() {
    let sets: [&[&str]; 2] = [
        &[
            "rar50/multivol.part1.rar",
            "rar50/multivol.part2.rar",
            "rar50/multivol.part3.rar",
        ],
        &[
            "rar15_40/rar300/compressed_multivol_prng_rar300.rar",
            "rar15_40/rar300/compressed_multivol_prng_rar300.r00",
            "rar15_40/rar300/compressed_multivol_prng_rar300.r01",
            "rar15_40/rar300/compressed_multivol_prng_rar300.r02",
            "rar15_40/rar300/compressed_multivol_prng_rar300.r03",
        ],
    ];
    for set in sets {
        let volumes: Vec<_> = set.iter().map(|path| fixture(path)).collect();
        let (expected, open) = collector();
        rars::extract_volumes_to(&volumes, None, open).unwrap();
        let (outputs, open) = collector();
        let mut pulled = Vec::new();

        volumes[0]
            .extract_with_volumes(
                recording(&mut pulled, |index| volumes.get(index).cloned().map(Ok)),
                ArchiveReadOptions::new(),
                open,
            )
            .unwrap();

        assert_eq!(
            *outputs.lock().unwrap(),
            *expected.lock().unwrap(),
            "{}",
            set[0]
        );
        assert_eq!(pulled, (1..volumes.len()).collect::<Vec<_>>(), "{}", set[0]);
    }
}

#[test]
fn waits_for_volumes_delivered_by_another_thread() {
    for (version, stored) in cases() {
        let (expected, volumes) = build_set(version, stored);
        let (send, receive) = std::sync::mpsc::channel();
        let feeder = {
            let volumes = volumes.clone();
            std::thread::spawn(move || {
                for bytes in &volumes[1..] {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    send.send(bytes.clone()).unwrap();
                }
            })
        };
        let first = ArchiveReader::read_owned(volumes[0].clone()).unwrap();
        let (outputs, open) = collector();

        first
            .extract_with_volumes(
                receive.into_iter().map(ArchiveReader::read_owned),
                ArchiveReadOptions::new(),
                open,
            )
            .unwrap();
        feeder.join().unwrap();

        assert_eq!(
            *outputs.lock().unwrap(),
            expected,
            "{version:?} stored={stored}"
        );
    }
}

#[test]
fn refuses_a_rar5_volume_out_of_order() {
    let (_, volumes) = build_set(ArchiveVersion::Rar50, true);
    let (result, pulled) =
        extract_from_bytes(&volumes, ArchiveReadOptions::new(), |index, volume| {
            if index == 2 {
                Some(ArchiveReader::read_owned(volumes[3].clone()).unwrap())
            } else {
                Some(volume)
            }
        });

    assert!(
        matches!(result, Err(rars::Error::InVolume { number: 3, .. })),
        "{result:?}"
    );
    assert_eq!(pulled, [1, 2]);
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| {
            (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1))
        })
    })
}

/// Swaps each volume's seven-byte end block for the twenty-byte one RAR 3.93
/// writes: a data CRC, the volume number from 0, and seven reserved bytes.
fn with_volume_numbers(volumes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    volumes
        .iter()
        .enumerate()
        .map(|(index, volume)| {
            let (body, end) = volume.split_at(volume.len() - 7);
            assert_eq!(end[2], 0x7b, "the volume ends in its end block");
            let flags = u16::from_le_bytes([end[3], end[4]]) | 0x000e;
            let mut header = vec![0, 0, 0x7b];
            header.extend_from_slice(&flags.to_le_bytes());
            header.extend_from_slice(&20u16.to_le_bytes());
            header.extend_from_slice(&[0; 4]);
            header.extend_from_slice(&(index as u16).to_le_bytes());
            header.extend_from_slice(&[0; 7]);
            let crc = crc32(&header[2..]) as u16;
            header[..2].copy_from_slice(&crc.to_le_bytes());
            [body, &header].concat()
        })
        .collect()
}

#[test]
fn reads_rar3_end_block_volume_numbers_and_refuses_a_volume_out_of_order() {
    let (expected, volumes) = build_set(ArchiveVersion::Rar29, true);
    let volumes = with_volume_numbers(&volumes);
    let last = ArchiveReader::read_owned(volumes[3].clone()).unwrap();
    let rars::Archive::Rar15To40(archive) = &last else {
        panic!("a RAR 2.9 volume");
    };
    assert_eq!(archive.end_volume_number(), Some(3));

    let first = ArchiveReader::read_owned(volumes[0].clone()).unwrap();
    let (outputs, open) = collector();
    first
        .extract_with_volumes(
            volumes[1..]
                .iter()
                .map(|volume| ArchiveReader::read_owned(volume.clone())),
            ArchiveReadOptions::new(),
            open,
        )
        .unwrap();
    assert_eq!(*outputs.lock().unwrap(), expected);

    let (result, pulled) =
        extract_from_bytes(&volumes, ArchiveReadOptions::new(), |index, volume| {
            if index == 2 {
                Some(ArchiveReader::read_owned(volumes[3].clone()).unwrap())
            } else {
                Some(volume)
            }
        });
    assert!(
        matches!(&result, Err(error @ rars::Error::InVolume { number: 3, .. })
            if error.root_cause() == &rars::Error::InvalidHeader("volume is out of order")),
        "{result:?}"
    );
    assert_eq!(pulled, [1, 2]);
}

#[test]
fn a_missing_volume_is_reported_the_same_inside_and_between_members() {
    let (_, volumes) = build_set(ArchiveVersion::Rar50, true);
    for missing in 1..volumes.len() {
        let (result, _) =
            extract_from_bytes(&volumes, ArchiveReadOptions::new(), |index, volume| {
                (index != missing).then_some(volume)
            });
        assert!(
            matches!(&result, Err(error @ rars::Error::InVolume { number, .. })
                if *number == missing + 1 && error.root_cause() == &rars::Error::MissingVolume),
            "volume {missing}: {result:?}"
        );
    }
}
