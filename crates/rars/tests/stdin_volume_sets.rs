#![cfg(feature = "write")]

//! Volume sets written from stdin (`rar a -v... -si`): every fragment but
//! the last says its member's size is unknown, and the last says what it is.
//! The sets here are built by our writer and patched to match.

use rars::{
    drop_incomplete_members, extract_volumes_to_with_options, Archive, ArchiveReadOptions,
    ArchiveReader, ArchiveVersion, Builder, ExtractedEntryMeta, MissingPart,
};
use std::io::Write;
use std::sync::{Arc, Mutex};

const NAME: &[u8] = b"data.txt";

fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// One member split across every volume of the set.
fn build_set(version: ArchiveVersion, stored: bool, data: &[u8]) -> Vec<Vec<u8>> {
    let mut builder = Builder::new(version).store(stored).volume_size(Some(4096));
    builder
        .add_bytes(NAME.to_vec(), data.to_vec(), None, None)
        .unwrap();
    let volumes = builder.build_volumes(None).unwrap();
    assert!(volumes.len() >= 3, "{version:?}: need a middle volume");
    volumes
}

/// What each patch does to a volume's one file header.
#[derive(Clone, Copy)]
enum Size {
    Unknown,
    Known(u64),
}

fn set_size(volume: &mut Vec<u8>, size: Size) {
    let archive = ArchiveReader::read(volume).unwrap();
    match archive {
        Archive::Rar15To40(archive) => {
            let mut files = archive.files();
            let file = files.next().unwrap();
            assert!(files.next().is_none());
            set_rar4_size(volume, file, size);
        }
        Archive::Rar50Plus(archive) => {
            let mut files = archive.files();
            let file = files.next().unwrap();
            assert!(files.next().is_none());
            set_rar5_size(volume, file.block.offset, size);
        }
        _ => unreachable!("only RAR 2.9 and RAR 5 are under test"),
    }
}

const FHD_LARGE: u16 = 0x0100;
const FLAGS_AT: usize = 3;
const HEAD_SIZE_AT: usize = 5;
const UNP_SIZE_AT: usize = 11;
const HIGH_SIZES_AT: usize = 32;

/// RAR 4 marks an unknown size with all ones in both size words.
fn set_rar4_size(volume: &mut Vec<u8>, file: &rars::rar15_40::FileHeader, size: Size) {
    let start = file.block.offset;
    let mut head_size = usize::from(file.block.head_size);
    if file.block.flags & FHD_LARGE == 0 {
        let high_pack = u32::try_from(file.pack_size >> 32).unwrap();
        let at = start + HIGH_SIZES_AT;
        volume.splice(at..at, high_pack.to_le_bytes().into_iter().chain([0; 4]));
        head_size += 8;
        let flags = file.block.flags | FHD_LARGE;
        volume[start + FLAGS_AT..start + FLAGS_AT + 2].copy_from_slice(&flags.to_le_bytes());
        volume[start + HEAD_SIZE_AT..start + HEAD_SIZE_AT + 2]
            .copy_from_slice(&u16::try_from(head_size).unwrap().to_le_bytes());
    }
    let unp_size = match size {
        Size::Unknown => u64::MAX,
        Size::Known(size) => size,
    };
    volume[start + UNP_SIZE_AT..start + UNP_SIZE_AT + 4]
        .copy_from_slice(&(unp_size as u32).to_le_bytes());
    let high_unp = start + HIGH_SIZES_AT + 4;
    volume[high_unp..high_unp + 4].copy_from_slice(&((unp_size >> 32) as u32).to_le_bytes());
    let crc = rars::crc32::crc32(&volume[start + 2..start + head_size]) as u16;
    volume[start..start + 2].copy_from_slice(&crc.to_le_bytes());
}

fn read_vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0;
    for shift in (0..).step_by(7) {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
    }
    value
}

fn vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

const HFL_EXTRA: u64 = 0x01;
const HFL_DATA: u64 = 0x02;
const FHFL_UNP_SIZE_UNKNOWN: u64 = 0x08;
/// What RAR writes in the size field it marks unknown.
const RAR5_UNKNOWN_SIZE: u64 = 0x7fff_ffff_7fff_ffff;

/// RAR 5 marks an unknown size with a file flag.
fn set_rar5_size(volume: &mut Vec<u8>, start: usize, size: Size) {
    let mut at = start + 4;
    let head_size = read_vint(volume, &mut at) as usize;
    let body_start = at;
    let body_end = body_start + head_size;
    read_vint(volume, &mut at);
    let flags = read_vint(volume, &mut at);
    if flags & HFL_EXTRA != 0 {
        read_vint(volume, &mut at);
    }
    if flags & HFL_DATA != 0 {
        read_vint(volume, &mut at);
    }
    let file_flags_at = at;
    let file_flags = read_vint(volume, &mut at);
    read_vint(volume, &mut at);
    let (file_flags, unp_size) = match size {
        Size::Unknown => (file_flags | FHFL_UNP_SIZE_UNKNOWN, RAR5_UNKNOWN_SIZE),
        Size::Known(size) => (file_flags & !FHFL_UNP_SIZE_UNKNOWN, size),
    };
    let mut body = volume[body_start..file_flags_at].to_vec();
    body.extend(vint(file_flags));
    body.extend(vint(unp_size));
    body.extend_from_slice(&volume[at..body_end]);
    let mut header = vint(body.len() as u64);
    header.extend(body);
    let crc = rars::crc32::crc32(&header);
    let mut sealed = crc.to_le_bytes().to_vec();
    sealed.extend(header);
    volume.splice(start..body_end, sealed);
}

/// Patches the set as `rar -si` writes it: every fragment that runs on has
/// an unknown size.
fn from_stdin(mut volumes: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let last = volumes.len() - 1;
    for volume in &mut volumes[..last] {
        set_size(volume, Size::Unknown);
    }
    volumes
}

fn parse(volumes: &[Vec<u8>]) -> Vec<Archive> {
    volumes
        .iter()
        .map(|bytes| ArchiveReader::read_owned(bytes.clone()).unwrap())
        .collect()
}

type Outputs = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;

struct Collect(Outputs);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut outputs = self.0.lock().unwrap();
        outputs.last_mut().unwrap().1.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn extract(archives: &[Archive]) -> rars::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let outputs: Outputs = Arc::default();
    let sink = outputs.clone();
    extract_volumes_to_with_options(
        archives,
        ArchiveReadOptions::new(),
        move |meta: &ExtractedEntryMeta| {
            sink.lock().unwrap().push((meta.name.clone(), Vec::new()));
            Ok(Box::new(Collect(sink.clone())) as Box<dyn Write>)
        },
    )?;
    let outputs = outputs.lock().unwrap().clone();
    Ok(outputs)
}

fn cases() -> impl Iterator<Item = (ArchiveVersion, bool)> {
    [ArchiveVersion::Rar29, ArchiveVersion::Rar50]
        .into_iter()
        .flat_map(|version| [true, false].map(|stored| (version, stored)))
}

#[test]
fn a_set_written_from_stdin_is_complete() {
    let data = noise(30_000);
    for (version, stored) in cases() {
        let case = format!("{version:?} stored={stored}");
        let volumes = from_stdin(build_set(version, stored, &data));
        let mut archives = parse(&volumes);

        assert_eq!(drop_incomplete_members(&mut archives), [], "{case}");
        let extracted = extract(&archives).unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_eq!(extracted, [(NAME.to_vec(), data.clone())], "{case}");

        let mut tested = Vec::new();
        rars::test_volumes_with_options_and_callback(
            &archives,
            ArchiveReadOptions::new(),
            |meta| {
                tested.push(meta.name.clone());
                Ok(())
            },
        )
        .unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_eq!(tested, [NAME.to_vec()], "{case}");
    }
}

#[test]
fn a_set_from_stdin_missing_its_last_volume_is_still_incomplete() {
    let data = noise(30_000);
    for (version, stored) in cases() {
        let case = format!("{version:?} stored={stored}");
        let volumes = from_stdin(build_set(version, stored, &data));
        let mut archives = parse(&volumes[..volumes.len() - 1]);

        let incomplete = drop_incomplete_members(&mut archives);
        let reported: Vec<_> = incomplete
            .iter()
            .map(|member| (member.name.clone(), member.volume, member.missing))
            .collect();
        assert_eq!(reported, [(NAME.to_vec(), 0, MissingPart::End)], "{case}");
    }
}

/// The member as `drop_incomplete_members` reports a break before the last volume.
fn broken_before_last(volumes: &[Vec<u8>]) -> Vec<(Vec<u8>, usize, MissingPart)> {
    let last = volumes.len() - 1;
    vec![
        (NAME.to_vec(), 0, MissingPart::End),
        (NAME.to_vec(), last, MissingPart::Start),
    ]
}

#[test]
fn a_known_size_that_changes_still_breaks_the_set() {
    let data = noise(30_000);
    let wrong = Size::Known(data.len() as u64 + 1);
    for (version, stored) in cases() {
        let case = format!("{version:?} stored={stored}");
        let mut sized = build_set(version, stored, &data);
        let last = sized.len() - 1;
        set_size(&mut sized[last], wrong);

        // Every fragment states its size and the last one disagrees.
        // From stdin, a middle fragment states one size and the last another.
        let mut from_stdin = from_stdin(build_set(version, stored, &data));
        set_size(&mut from_stdin[1], Size::Known(data.len() as u64));
        set_size(&mut from_stdin[last], wrong);

        for (variant, volumes) in [("sized", sized), ("from stdin", from_stdin)] {
            let case = format!("{case} {variant}");
            let mut archives = parse(&volumes);
            let incomplete = drop_incomplete_members(&mut archives);
            let reported: Vec<_> = incomplete
                .iter()
                .map(|member| (member.name.clone(), member.volume, member.missing))
                .collect();
            assert_eq!(reported, broken_before_last(&volumes), "{case}");

            assert!(
                extract(&parse(&volumes)).is_err(),
                "{case}: the reader took the changed size"
            );
        }
    }
}

/// Issues #582 and #602: a member whose first part doesn't record its size
/// is decoded as its volumes arrive, so a caller asked for each volume in
/// turn, as `unrars -vp` asks, sees output before the last one, as with a
/// known size. An encrypted stored member still fetches them all first: only
/// its size tells its data from the cipher padding. So does a compressed
/// RAR 2.0 one, whose stream has no end-of-file marker to stop at.
#[test]
fn a_set_from_stdin_is_decoded_as_its_volumes_arrive() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // Past the size at which output goes out a chunk at a time, and
    // compressible, so that it isn't stored instead, but not so much that it
    // packs into the megabyte a RAR 1.5-4 decoder reads ahead.
    let data: Vec<u8> = noise(3 << 20)
        .into_iter()
        .enumerate()
        .map(|(at, byte)| if at % 2 == 0 { byte } else { b"text "[at % 5] })
        .collect();
    let password = b"secret".as_slice();
    let rar20 = [
        (ArchiveVersion::Rar20, true, None),
        (ArchiveVersion::Rar20, false, None),
    ];
    for (version, stored, password) in [ArchiveVersion::Rar29, ArchiveVersion::Rar50]
        .into_iter()
        .flat_map(|version| {
            [
                (version, true, None),
                (version, false, None),
                (version, false, Some(password)),
                (version, true, Some(password)),
            ]
        })
        .chain(rar20)
    {
        let case = format!(
            "{version:?} stored={stored} encrypted={}",
            password.is_some()
        );
        let mut builder = Builder::new(version)
            .store(stored)
            .password(password.map(<[u8]>::to_vec))
            .volume_size(Some(128 << 10));
        builder
            .add_bytes(NAME.to_vec(), data.clone(), None, None)
            .unwrap();
        let volumes = from_stdin(builder.build_volumes(None).unwrap());
        assert!(volumes.len() >= 4, "{case}");
        let archives = parse(&volumes);

        let written = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&written);
        // How much was written by the time each later volume was asked for.
        let asked = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&asked);
        let count = archives.len() - 1;
        let later = archives[1..].iter().cloned().map(move |volume| {
            // A caller asked for the last volume waits a while for it, as a
            // person at a prompt does, which gives output written on another
            // thread time to arrive.
            let start = std::time::Instant::now();
            let mut record = record.lock().unwrap();
            while record.len() + 1 == count
                && seen.load(Ordering::Relaxed) == 0
                && start.elapsed() < std::time::Duration::from_secs(1)
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            record.push(seen.load(Ordering::Relaxed));
            Ok(volume)
        });
        let output = Arc::new(Mutex::new(Vec::new()));
        rars::output_links::extract_arriving_with_links(
            &archives[0],
            later,
            // On one thread the decoder writes as it goes. With more, the
            // compressed member's output reaches the writer in larger pieces,
            // later, as it does for a member whose size is known.
            ArchiveReadOptions::with_optional_password(password).with_threads(1),
            |_| {
                struct Counted(Arc<AtomicUsize>, Arc<Mutex<Vec<u8>>>);
                impl Write for Counted {
                    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                        self.0.fetch_add(buf.len(), Ordering::Relaxed);
                        self.1.lock().unwrap().extend_from_slice(buf);
                        Ok(buf.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                Ok(Box::new(Counted(Arc::clone(&written), Arc::clone(&output))))
            },
            |_, _| Ok(()),
        )
        .unwrap_or_else(|error| panic!("{case}: {error}"));
        assert!(*output.lock().unwrap() == data, "{case}");
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), volumes.len() - 1, "{case}");
        let lazy = if stored {
            password.is_none()
        } else {
            version != ArchiveVersion::Rar20
        };
        assert_eq!(*asked.last().unwrap() > 0, lazy, "{case}: {asked:?}");
    }
}

/// Issues #582 and #602: decoded as its volumes arrive, a member from stdin
/// still has to come to the size its last part gives.
#[test]
fn a_set_from_stdin_must_match_the_size_its_last_part_gives() {
    let data = noise(30_000);
    for (version, stored) in [ArchiveVersion::Rar29, ArchiveVersion::Rar50]
        .into_iter()
        .flat_map(|version| [(version, true), (version, false)])
    {
        for wrong in [data.len() as u64 - 1, data.len() as u64 + 1] {
            let case = format!("{version:?} stored={stored} size={wrong}");
            let mut volumes = from_stdin(build_set(version, stored, &data));
            let last = volumes.len() - 1;
            set_size(&mut volumes[last], Size::Known(wrong));
            let error = extract(&parse(&volumes)).expect_err(&case);
            assert_eq!(
                error.kind(),
                rars::ErrorKind::InvalidArchive,
                "{case}: {error}"
            );
        }
    }
}

/// Issue #611: salvaging an encrypted split member that a missing volume
/// cuts short keeps what decoded before the gap, whether or not its first
/// part records its size, though the gap falls inside a cipher block. The
/// call fails as it does without salvage. RAR 5 is checked alongside.
#[cfg(feature = "encryption")]
#[test]
fn salvage_keeps_an_encrypted_split_member_up_to_a_missing_volume() {
    let data: Vec<u8> = noise(60_000)
        .into_iter()
        .enumerate()
        .map(|(at, byte)| if at % 7 == 0 { byte } else { b"text "[at % 5] })
        .collect();
    let password = b"secret".as_slice();
    for (version, stored) in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ]
    .into_iter()
    .flat_map(|version| [(version, false), (version, true)])
    {
        let mut builder = Builder::new(version)
            .store(stored)
            .password(Some(password.to_vec()))
            .volume_size(Some(2048));
        builder
            .add_bytes(NAME.to_vec(), data.clone(), None, None)
            .unwrap();
        let sized = builder.build_volumes(None).unwrap();
        assert!(sized.len() >= 4, "{version:?}: {}", sized.len());
        // A RAR 2.0 stream has no end marker to decode an unknown size to.
        let unknown = (version != ArchiveVersion::Rar20).then(|| from_stdin(sized.clone()));
        for (variant, volumes) in [("sized", Some(sized)), ("from stdin", unknown)] {
            let Some(volumes) = volumes else { continue };
            for gap in 1..volumes.len() - 1 {
                let case = format!("{version:?} stored={stored} {variant} gap={gap}");
                let archives = parse(&volumes[..gap]);
                let run = |salvage| {
                    let outputs: Outputs = Arc::default();
                    let sink = outputs.clone();
                    let error = extract_volumes_to_with_options(
                        &archives,
                        ArchiveReadOptions::with_optional_password(Some(password))
                            .with_salvage(salvage),
                        move |meta: &ExtractedEntryMeta| {
                            sink.lock().unwrap().push((meta.name.clone(), Vec::new()));
                            Ok(Box::new(Collect(sink.clone())) as Box<dyn Write>)
                        },
                    )
                    .expect_err(&case);
                    let kept = outputs.lock().unwrap().pop().map(|(_, kept)| kept);
                    (error, kept.unwrap_or_default())
                };
                let (strict, _) = run(false);
                let (error, kept) = run(true);
                assert_eq!(error, strict, "{case}");
                // A compressed RAR 5 member this small is decoded whole
                // before any of it is written, encrypted or not.
                if version != ArchiveVersion::Rar50 || stored {
                    assert!(!kept.is_empty(), "{case}");
                }
                assert!(kept.len() < data.len(), "{case}: kept {}", kept.len());
                assert!(kept == data[..kept.len()], "{case}: not a prefix");
            }
        }
    }
}
