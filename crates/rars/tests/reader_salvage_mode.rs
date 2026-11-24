#![cfg(feature = "write")]
//! `ArchiveReadOptions::with_salvage`: a damaged archive delivers what it
//! still holds, with each problem reported beside the bytes. Every archive
//! here is written by rars and then damaged.

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[path = "support/scratch.rs"]
mod scratch;

use rars::rar15_40::{write_compressed_archive, FileEntry, Rar29Method, WriterOptions};
use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions as Rar50WriterOptions};
use rars::{
    Archive, ArchiveMember, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder,
    EntrySource, Error, ExtractionErrorAction, FeatureSet, FilterKind, FilterPolicy, FilterSpec,
    HeaderDamageKind, Rar50Scratch,
};
use std::io::{self, Write};
use std::ops::Range;
use std::sync::{Arc, Mutex};

/// Every family with a header checksum and a member checksum.
const VERSIONS: [ArchiveVersion; 4] = [
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];

/// Five members of text from one vocabulary, `size` bytes each.
fn members(size: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut seed = 365u32;
    let mut next = move || {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        (seed >> 16) as usize
    };
    let words: Vec<Vec<u8>> = (0..300)
        .map(|_| {
            (0..2 + next() % 8)
                .map(|_| b'a' + (next() % 26) as u8)
                .collect()
        })
        .collect();
    (0..5)
        .map(|index| {
            let mut text = Vec::new();
            while text.len() < size {
                text.extend_from_slice(&words[next() % words.len()]);
                text.push(b' ');
                if next() % 64 == 0 {
                    // Some bytes no word has, so blocks keep changing.
                    text.extend((0..next() % 16).map(|_| (next() % 256) as u8));
                }
            }
            (format!("m{index}.txt").into_bytes(), text)
        })
        .collect()
}

fn build(version: ArchiveVersion, solid: bool, members: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut builder = Builder::new(version).solid(solid);
    for (name, data) in members {
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
    }
    builder.to_bytes().unwrap()
}

/// Member `index`'s header and packed data in the file.
fn member_ranges(bytes: &[u8], index: usize) -> (Range<usize>, Range<usize>) {
    match ArchiveReader::read(bytes).unwrap() {
        Archive::Rar15To40(archive) => {
            let file = archive.files().nth(index).unwrap();
            let start = file.block.offset;
            (
                start..start + usize::from(file.block.head_size),
                file.packed_range.clone(),
            )
        }
        Archive::Rar50Plus(archive) => {
            let file = archive.files().nth(index).unwrap();
            (
                file.block.offset..file.block.data_range.start,
                file.block.data_range.clone(),
            )
        }
        Archive::Rar13(archive) => {
            let entry = &archive.entries[index];
            let head = usize::from(entry.header.head_size);
            (
                entry.packed_range.start - head..entry.packed_range.start,
                entry.packed_range.clone(),
            )
        }
        _ => unreachable!("a RAR 1.3-5 archive"),
    }
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

/// Recomputes the header CRC of the block at `start`.
fn reseal(bytes: &mut [u8], start: usize, rar50: bool) {
    if rar50 {
        let mut end = start + 4;
        let size = read_vint(bytes, &mut end);
        let end = end + usize::try_from(size).unwrap();
        let crc = rars::crc32::crc32(&bytes[start + 4..end]);
        bytes[start..start + 4].copy_from_slice(&crc.to_le_bytes());
    } else {
        let size = usize::from(u16::from_le_bytes([bytes[start + 5], bytes[start + 6]]));
        let crc = rars::crc32::crc32(&bytes[start + 2..start + size]) as u16;
        bytes[start..start + 2].copy_from_slice(&crc.to_le_bytes());
    }
}

/// Where member `index`'s stored data CRC32 sits.
fn data_crc_at(bytes: &[u8], version: ArchiveVersion, index: usize) -> usize {
    let (header, _) = member_ranges(bytes, index);
    if version != ArchiveVersion::Rar50 {
        return header.start + 16;
    }
    let mut at = header.start + 4;
    read_vint(bytes, &mut at); // header size
    read_vint(bytes, &mut at); // type
    let flags = read_vint(bytes, &mut at);
    if flags & 1 != 0 {
        read_vint(bytes, &mut at);
    }
    if flags & 2 != 0 {
        read_vint(bytes, &mut at);
    }
    let file_flags = read_vint(bytes, &mut at);
    read_vint(bytes, &mut at); // unpacked size
    read_vint(bytes, &mut at); // attributes
    if file_flags & 2 != 0 {
        at += 4;
    }
    assert!(file_flags & 4 != 0, "the member has a CRC32");
    at
}

/// Adds `record` to the extra area of RAR 5 member `index`'s header, and
/// reseals it.
fn add_rar50_record(bytes: &[u8], index: usize, record: &[u8]) -> Vec<u8> {
    let (header, _) = member_ranges(bytes, index);
    let mut at = header.start + 4;
    let size = read_vint(bytes, &mut at);
    let body = at..at + usize::try_from(size).unwrap();
    let mut fields = body.start;
    let kind = read_vint(bytes, &mut fields);
    let flags = read_vint(bytes, &mut fields);
    let extra = if flags & 1 != 0 {
        read_vint(bytes, &mut fields)
    } else {
        0
    };
    let data = (flags & 2 != 0).then(|| read_vint(bytes, &mut fields));
    let record = [vint(record.len() as u64), record.to_vec()].concat();
    let mut new = [
        vint(kind),
        vint(flags | 1),
        vint(extra + record.len() as u64),
    ]
    .concat();
    if let Some(data) = data {
        new.extend(vint(data));
    }
    new.extend_from_slice(&bytes[fields..body.end]);
    new.extend(record);
    let mut out = bytes[..header.start].to_vec();
    out.extend([0; 4]);
    out.extend(vint(new.len() as u64));
    out.extend(new);
    out.extend_from_slice(&bytes[body.end..]);
    reseal(&mut out, header.start, true);
    out
}

/// Records each member the handler is called for, with its error.
#[derive(Default)]
struct Failures(Mutex<Vec<(Vec<u8>, String)>>);

impl Failures {
    fn handle(&self, member: &ArchiveMember, error: &Error) -> rars::Result<ExtractionErrorAction> {
        let root = format!("{:?}", error.root_cause());
        self.0
            .lock()
            .unwrap()
            .push((member.meta.name.clone(), root));
        Ok(ExtractionErrorAction::Continue)
    }

    fn take(&self) -> Vec<(Vec<u8>, String)> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Extracts every member, returning each output opened, by name.
fn extract(
    archive: &Archive,
    options: ArchiveReadOptions<'_>,
) -> rars::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let outputs = Mutex::new(Vec::new());
    archive.extract_with_links(
        options,
        |meta| {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            outputs
                .lock()
                .unwrap()
                .push((meta.name.clone(), Arc::clone(&buffer)));
            Ok(Box::new(Shared(buffer)) as Box<dyn Write>)
        },
        |_, _| Ok(()),
    )?;
    Ok(outputs
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|(name, buffer)| (name, buffer.lock().unwrap().clone()))
        .collect())
}

fn output<'a>(outputs: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> &'a [u8] {
    &outputs
        .iter()
        .find(|(seen, _)| seen == name)
        .unwrap_or_else(|| panic!("{name:?} was not opened"))
        .1
}

/// Each output opened, by name.
type Outputs = Vec<(Vec<u8>, Vec<u8>)>;

/// Whether `name` got no bytes: unopened, or opened and left empty.
fn opened_empty(outputs: &[(Vec<u8>, Vec<u8>)], name: &[u8]) -> bool {
    outputs
        .iter()
        .find(|(seen, _)| seen == name)
        .is_none_or(|(_, data)| data.is_empty())
}

/// Parses and extracts `bytes` with salvage and a handler that carries on.
/// `buffered_limit` sets the RAR 5 buffered decode limit, to stream members.
fn salvage(
    bytes: &[u8],
    buffered_limit: Option<u64>,
) -> (Archive, Outputs, Vec<(Vec<u8>, String)>) {
    salvage_with(bytes, buffered_limit, None)
}

/// [`salvage`], decoding RAR 5 members past the buffered limit through
/// `scratch` if given.
fn salvage_with(
    bytes: &[u8],
    buffered_limit: Option<u64>,
    scratch: Option<&Rar50Scratch>,
) -> (Archive, Outputs, Vec<(Vec<u8>, String)>) {
    let failures = Failures::default();
    let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
    let mut options = ArchiveReadOptions::new()
        .with_salvage(true)
        .with_member_error_handler(&handler);
    if let Some(limit) = buffered_limit {
        options = options.with_rar50_buffered_decode_limit(limit);
    }
    if let Some(scratch) = scratch {
        options = options.with_rar50_scratch(scratch);
    }
    let archive = ArchiveReader::read_with_options(bytes, options).unwrap();
    let outputs = extract(&archive, options).unwrap();
    // Testing reports the same members.
    let extracted = failures.take();
    archive
        .test_with_options_and_callback(options, |_| Ok(()))
        .unwrap();
    let tested = failures.take();
    let names = |list: &[(Vec<u8>, String)]| {
        list.iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&tested), names(&extracted), "test and extract agree");
    (archive, outputs, extracted)
}

#[test]
fn a_member_that_fails_its_checksum_is_delivered_whole_with_the_failure() {
    let members = members(6000);
    for version in VERSIONS {
        for solid in [false, true] {
            let case = format!("{version:?} solid={solid}");
            let mut bytes = build(version, solid, &members);
            let at = data_crc_at(&bytes, version, 2);
            let (header, _) = member_ranges(&bytes, 2);
            bytes[at] ^= 0x01;
            reseal(&mut bytes, header.start, version == ArchiveVersion::Rar50);

            // Without salvage the member fails and a buffered RAR 5 member
            // gets none of its bytes.
            let failures = Failures::default();
            let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
            let strict = ArchiveReadOptions::new().with_member_error_handler(&handler);
            let archive = ArchiveReader::read_with_options(&bytes, strict).unwrap();
            let outputs = extract(&archive, strict).unwrap();
            assert_eq!(failures.take().len(), 1, "{case}");
            if version == ArchiveVersion::Rar50 {
                assert!(opened_empty(&outputs, b"m2.txt"), "{case}");
            }

            let (archive, outputs, failed) = salvage(&bytes, None);
            assert!(archive.header_damage().is_empty(), "{case}");
            assert_eq!(failed.len(), 1, "{case}: {failed:?}");
            assert_eq!(failed[0].0, b"m2.txt", "{case}");
            assert!(failed[0].1.contains("Crc32Mismatch"), "{case}: {failed:?}");
            for (name, data) in &members {
                assert_eq!(output(&outputs, name), data, "{case}: {name:?}");
            }
        }
    }
}

/// The RAR 5 compressed blocks in a member's packed data.
fn rar50_blocks(packed: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut at = 0;
    while at + 3 <= packed.len() {
        starts.push(at);
        let flags = packed[at];
        let size_bytes = usize::from((flags >> 3) & 3) + 1;
        let size = packed[at + 2..at + 2 + size_bytes]
            .iter()
            .rev()
            .fold(0usize, |size, &byte| size << 8 | usize::from(byte));
        if flags & 0x40 != 0 {
            break;
        }
        at += 2 + size_bytes + size;
    }
    starts
}

#[test]
fn a_member_that_fails_partway_delivers_what_decoded_before_the_failure() {
    let members = members(150_000);
    for solid in [false, true] {
        for &path in RAR50_PATHS {
            let case = format!("solid={solid} {path:?}");
            let mut bytes = build(ArchiveVersion::Rar50, solid, &members);
            let (_, packed) = member_ranges(&bytes, 2);
            let blocks = rar50_blocks(&bytes[packed.clone()]);
            assert!(blocks.len() > 1, "{case}: m2 needs a second block");
            // The second block's header checksum no longer matches, so the
            // decoder fails once the first block is out.
            bytes[packed.start + blocks[1] + 1] ^= 0x01;

            if path == Rar50Path::Buffered {
                let failures = Failures::default();
                let handler =
                    |member: &ArchiveMember, error: &Error| failures.handle(member, error);
                let strict = ArchiveReadOptions::new().with_member_error_handler(&handler);
                let archive = ArchiveReader::read(&bytes).unwrap();
                let outputs = extract(&archive, strict).unwrap();
                assert!(opened_empty(&outputs, b"m2.txt"), "{case}");
            }

            let (_, outputs, failed) = salvage_on(&bytes, path, 1024);
            assert_eq!(failed[0].0, b"m2.txt", "{case}");
            assert!(
                failed[0].1.contains("checksum mismatch"),
                "{case}: {failed:?}"
            );
            let delivered = output(&outputs, b"m2.txt");
            let whole = &members[2].1;
            assert!(!delivered.is_empty(), "{case}");
            assert!(delivered.len() < whole.len(), "{case}");
            assert!(whole.starts_with(delivered), "{case}");
            for (name, data) in &members[..2] {
                assert_eq!(output(&outputs, name), data, "{case}: {name:?}");
            }
            if !solid {
                assert_eq!(failed.len(), 1, "{case}: {failed:?}");
                for (name, data) in &members[3..] {
                    assert_eq!(output(&outputs, name), data, "{case}: {name:?}");
                }
            }
        }
    }
}

#[test]
fn a_damaged_member_delivers_the_bytes_before_the_damage() {
    let members = members(30_000);
    for version in [ArchiveVersion::Rar14, ArchiveVersion::Rar15]
        .into_iter()
        .chain(VERSIONS)
    {
        for solid in [false, true] {
            let case = format!("{version:?} solid={solid}");
            let mut bytes = build(version, solid, &members);
            let packed = match ArchiveReader::read(&bytes).unwrap() {
                Archive::Rar13(archive) => archive.entries[2].packed_range.clone(),
                _ => member_ranges(&bytes, 2).1,
            };
            bytes[packed.start + packed.len() / 2] ^= 0x55;
            let (_, outputs, failed) = salvage(&bytes, None);
            assert_eq!(failed[0].0, b"m2.txt", "{case}");
            let delivered = output(&outputs, b"m2.txt");
            let whole = &members[2].1;
            let agree = delivered
                .iter()
                .zip(whole)
                .take_while(|(left, right)| left == right)
                .count();
            // The damage is halfway through the packed data, and nothing
            // before it is lost.
            assert!(agree >= whole.len() / 8, "{case}: {agree} bytes agree");
            for (name, data) in &members[..2] {
                assert_eq!(output(&outputs, name), data, "{case}: {name:?}");
            }
        }
    }
}

/// Lowers RAR 5 member `index`'s declared size to `size`, in the same
/// number of bytes, and reseals its header.
fn declare_rar50_size(bytes: &mut [u8], index: usize, size: u64) {
    let (header, _) = member_ranges(bytes, index);
    let mut at = header.start + 4;
    read_vint(bytes, &mut at);
    read_vint(bytes, &mut at);
    let flags = read_vint(bytes, &mut at);
    if flags & 1 != 0 {
        read_vint(bytes, &mut at);
    }
    if flags & 2 != 0 {
        read_vint(bytes, &mut at);
    }
    read_vint(bytes, &mut at);
    let start = at;
    read_vint(bytes, &mut at);
    let width = at - start;
    let mut size = size;
    for (index, byte) in bytes[start..at].iter_mut().enumerate() {
        *byte = (size & 0x7f) as u8 | if index + 1 < width { 0x80 } else { 0 };
        size >>= 7;
    }
    assert_eq!(size, 0);
    reseal(bytes, header.start, true);
}

/// How a RAR 5 member is decoded: whole in memory, streamed, or streamed
/// through a scratch file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rar50Path {
    Buffered,
    Streaming,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    Scratch,
}

const RAR50_PATHS: &[Rar50Path] = &[
    Rar50Path::Buffered,
    Rar50Path::Streaming,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    Rar50Path::Scratch,
];

/// [`salvage`] down `path`, for members larger than `streamed_above`.
fn salvage_on(
    bytes: &[u8],
    path: Rar50Path,
    streamed_above: u64,
) -> (Archive, Outputs, Vec<(Vec<u8>, String)>) {
    match path {
        Rar50Path::Buffered => salvage(bytes, None),
        Rar50Path::Streaming => salvage(bytes, Some(streamed_above)),
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        Rar50Path::Scratch => {
            let dir = scratch::case("reader-salvage-mode");
            let policy = Rar50Scratch::new(&*dir, 64 * 1024 * 1024);
            salvage_with(bytes, Some(streamed_above), Some(&policy))
        }
    }
}

/// A solid successor starts where the stream ended, not at the declared
/// size, as it does in unrar: the rest of the stream is decoded into the
/// window only.
#[test]
fn a_rar50_member_that_runs_past_its_declared_size_delivers_the_declared_bytes() {
    let members = members(6000);
    for &path in RAR50_PATHS {
        for solid in [false, true] {
            let case = format!("{path:?} solid={solid}");
            let mut bytes = build(ArchiveVersion::Rar50, solid, &members);
            declare_rar50_size(&mut bytes, 2, 1000);

            let archive = ArchiveReader::read(&bytes).unwrap();
            assert!(extract(&archive, ArchiveReadOptions::new()).is_err());

            let (_, outputs, failed) = salvage_on(&bytes, path, 100);
            assert_eq!(
                failed,
                [(
                    b"m2.txt".to_vec(),
                    "MemberRanPastDeclaredSize { declared: 1000 }".to_string()
                )],
                "{case}"
            );
            assert_eq!(output(&outputs, b"m2.txt"), &members[2].1[..1000], "{case}");
            for (name, data) in members.iter().filter(|(name, _)| name != b"m2.txt") {
                assert_eq!(output(&outputs, name), data, "{case}: {name:?}");
            }
        }
    }
}

/// The member output ceiling bounds how far the stream is decoded on: past
/// it, the successor decodes from wherever the run-on stopped.
#[test]
fn the_member_output_ceiling_bounds_a_rar50_run_on() {
    let mut members = members(60_000);
    for (index, (_, data)) in members.iter_mut().enumerate() {
        if index != 2 {
            data.truncate(800);
        }
    }
    let mut bytes = build(ArchiveVersion::Rar50, true, &members);
    declare_rar50_size(&mut bytes, 2, 1000);
    for limit in [1000, 100_000] {
        let failures = Failures::default();
        let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
        let options = ArchiveReadOptions::new()
            .with_salvage(true)
            .with_member_error_handler(&handler)
            .with_max_member_output_bytes(limit);
        let archive = ArchiveReader::read_with_options(&bytes, options).unwrap();
        let outputs = extract(&archive, options).unwrap();
        let failed = failures.take();
        assert_eq!(output(&outputs, b"m2.txt"), &members[2].1[..1000]);
        let names: Vec<_> = failed.iter().map(|(name, _)| name.as_slice()).collect();
        if limit == 1000 {
            // Not run on at all, so the successor can't be read.
            assert_eq!(names[..2], [b"m2.txt".as_slice(), b"m3.txt"], "{failed:?}");
        } else {
            assert_eq!(names, [b"m2.txt"], "{failed:?}");
            assert_eq!(output(&outputs, b"m3.txt"), members[3].1);
        }
    }
}

#[test]
fn a_header_that_fails_its_checksum_is_read_as_stored_and_reported() {
    let members = members(6000);
    for version in VERSIONS {
        for solid in [false, true] {
            let case = format!("{version:?} solid={solid}");
            let bytes = build(version, solid, &members);
            let (header, _) = member_ranges(&bytes, 2);
            // The member's name is the last field before RAR 5's extra
            // area, and the first after RAR 1.5-4's fixed fields.
            let name_at = if version == ArchiveVersion::Rar50 {
                let extra = match ArchiveReader::read(&bytes).unwrap() {
                    Archive::Rar50Plus(archive) => archive
                        .files()
                        .nth(2)
                        .unwrap()
                        .block
                        .extra_area_size
                        .unwrap_or(0),
                    _ => unreachable!(),
                };
                header.end - usize::try_from(extra).unwrap() - 1
            } else {
                header.start + 32 + 1
            };
            let mut damaged = bytes.clone();
            damaged[name_at] ^= 0x01;
            assert!(ArchiveReader::read(&damaged).is_err(), "{case}");

            let (archive, outputs, failed) = salvage(&damaged, None);
            assert_eq!(archive.header_damage().len(), 1, "{case}");
            let damage = &archive.header_damage()[0];
            assert_eq!(damage.offset, header.start as u64, "{case}");
            assert!(
                matches!(damage.kind, HeaderDamageKind::Checksum { .. }),
                "{case}"
            );
            assert!(failed.is_empty(), "{case}: {failed:?}");
            assert_eq!(outputs.len(), members.len(), "{case}");
            for ((name, data), (seen, output)) in members.iter().zip(&outputs) {
                assert_eq!(output, data, "{case}: {name:?}");
                if name != b"m2.txt" {
                    assert_eq!(seen, name, "{case}");
                }
            }
        }
    }
}

#[test]
fn a_rar50_header_that_does_not_parse_ends_the_walk_with_the_members_before_it() {
    let members = members(6000);
    let mut bytes = build(ArchiveVersion::Rar50, false, &members);
    let (header, _) = member_ranges(&bytes, 2);
    // A header size that never ends, and no header after it to resync to.
    bytes[header.start + 4..].fill(0xff);
    assert!(ArchiveReader::read(&bytes).is_err());

    let (archive, outputs, failed) = salvage(&bytes, None);
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(archive.header_damage().len(), 1);
    assert_eq!(archive.header_damage()[0].offset, header.start as u64);
    assert!(matches!(
        archive.header_damage()[0].kind,
        HeaderDamageKind::Unreadable { .. }
    ));
    assert_eq!(outputs, members[..2]);
}

#[test]
fn a_malformed_optional_rar50_record_is_dropped_and_the_member_read() {
    let members = members(6000);
    let records: [(&str, Vec<u8>, u64); 5] = [
        ("redirection, type only", [vint(5), vint(1)].concat(), 5),
        (
            "redirection, target past the record",
            [vint(5), vint(1), vint(0), vint(40), b"abc".to_vec()].concat(),
            5,
        ),
        (
            "redirection, empty target",
            [vint(5), vint(1), vint(0), vint(0)].concat(),
            5,
        ),
        (
            "hash record too short",
            [vint(2), vint(0), vec![1; 8]].concat(),
            2,
        ),
        ("hash record type only", vint(2), 2),
    ];
    for solid in [false, true] {
        let bytes = build(ArchiveVersion::Rar50, solid, &members);
        for (what, record, kind) in &records {
            let case = format!("{what} solid={solid}");
            let damaged = add_rar50_record(&bytes, 2, record);
            // Without salvage the archive or the member fails, or the
            // member is taken for a link.
            let strict = ArchiveReader::read(&damaged)
                .ok()
                .and_then(|archive| extract(&archive, ArchiveReadOptions::new()).ok());
            let delivered = strict.is_some_and(|outputs| {
                outputs
                    .iter()
                    .any(|(name, data)| name == b"m2.txt" && *data == members[2].1)
            });
            assert!(!delivered, "{case}");

            let (archive, outputs, failed) = salvage(&damaged, None);
            assert!(failed.is_empty(), "{case}: {failed:?}");
            assert_eq!(archive.header_damage().len(), 1, "{case}");
            assert!(
                matches!(
                    archive.header_damage()[0].kind,
                    HeaderDamageKind::DroppedRecord { record, .. } if record == *kind
                ),
                "{case}: {:?}",
                archive.header_damage()
            );
            assert_eq!(outputs, members, "{case}");
        }
    }
}

#[test]
fn salvage_changes_nothing_for_a_whole_archive() {
    let members = members(6000);
    for version in VERSIONS {
        for solid in [false, true] {
            let bytes = build(version, solid, &members);
            let (archive, outputs, failed) = salvage(&bytes, None);
            assert!(archive.header_damage().is_empty());
            assert!(failed.is_empty());
            assert_eq!(outputs, members);
        }
    }
}

/// The scratch path writes a member that fails its checksum whole, and a
/// filtered member that fails partway up to the first filter it didn't
/// finish, with the filters before it applied.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[test]
fn the_rar50_scratch_path_delivers_a_failed_member() {
    let members = members(6000);
    for solid in [false, true] {
        let case = format!("solid={solid}");
        let mut bytes = build(ArchiveVersion::Rar50, solid, &members);
        let at = data_crc_at(&bytes, ArchiveVersion::Rar50, 2);
        let (header, _) = member_ranges(&bytes, 2);
        bytes[at] ^= 0x01;
        reseal(&mut bytes, header.start, true);
        let (_, outputs, failed) = salvage_on(&bytes, Rar50Path::Scratch, 100);
        assert_eq!(failed.len(), 1, "{case}: {failed:?}");
        assert!(failed[0].1.contains("Crc32Mismatch"), "{case}: {failed:?}");
        assert_eq!(outputs, members, "{case}");
    }

    // E8 filters over all but the start of the member, so one is still open
    // when a later block fails: the bytes before it are final, and its own
    // aren't, until it is applied.
    let mut seed = 488u32;
    let mut code = members[0].1.clone();
    code.extend((0..1_000_000).map(|index| {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        match index % 7 {
            0 => 0xe8,
            1 | 2 => (seed >> 16) as u8 & 0x0f,
            _ => (seed >> 24) as u8 & 0x3f,
        }
    }));
    let entry = ArchiveEntry::new(
        b"code.bin".to_vec(),
        EntrySource::from_bytes(Arc::<[u8]>::from(code.clone())),
    );
    let mut bytes = Rar50Writer::new(
        Rar50WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(1),
    )
    .entries([entry])
    .filter_policy(FilterPolicy::Explicit(FilterSpec::range(
        FilterKind::E8,
        6000..code.len(),
    )))
    .finish()
    .unwrap();
    let (_, packed) = member_ranges(&bytes, 0);
    let blocks = rar50_blocks(&bytes[packed.clone()]);
    assert!(blocks.len() > 2, "the member needs a later block to damage");
    // The last block, cut to half its size, ends partway through a filter.
    // Its header still checks out.
    let last = packed.start + blocks[blocks.len() - 1];
    let flags = bytes[last];
    let width = usize::from((flags >> 3) & 3) + 1;
    let size_at = last + 2..last + 2 + width;
    let size = bytes[size_at.clone()]
        .iter()
        .rev()
        .fold(0usize, |size, &byte| size << 8 | usize::from(byte));
    bytes[size_at.clone()].copy_from_slice(&(size / 2).to_le_bytes()[..width]);
    bytes[last + 1] = bytes[size_at]
        .iter()
        .fold(0x5a ^ flags, |sum, &byte| sum ^ byte);
    // The streaming decoder can't hold filters this long.
    let mut first = None;
    for path in [Rar50Path::Buffered, Rar50Path::Scratch] {
        let (_, outputs, failed) = salvage_on(&bytes, path, 1024);
        assert_eq!(failed.len(), 1, "{path:?}: {failed:?}");
        let delivered = output(&outputs, b"code.bin");
        assert!(delivered.len() > 6000, "{path:?}");
        assert!(delivered.len() < code.len(), "{path:?}");
        assert!(code.starts_with(delivered), "{path:?}");
        // Both stop at the same filter.
        match &first {
            None => first = Some(delivered.to_vec()),
            Some(first) => assert_eq!(delivered, first, "{path:?}"),
        }
    }
}

/// Lowers RAR 1.5-4 member `index`'s declared size to `size`, and reseals
/// its header.
fn declare_legacy_size(bytes: &mut [u8], index: usize, size: u32) {
    let (header, _) = member_ranges(bytes, index);
    bytes[header.start + 11..header.start + 15].copy_from_slice(&size.to_le_bytes());
    reseal(bytes, header.start, false);
}

/// A RAR 2.9 archive of `members` written with `method`.
fn build_rar29(method: Rar29Method, solid: bool, members: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let entries: Vec<_> = members
        .iter()
        .map(|(name, data)| FileEntry {
            name,
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        })
        .collect();
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let options = WriterOptions::new(ArchiveVersion::Rar29, features).with_method(method);
    write_compressed_archive(&entries, options).unwrap()
}

/// RAR 1.5 to 2.9 report a stream that runs past its declared size as RAR 5
/// does, under salvage only. RAR 2.9 knows it by the end-of-file marker that
/// doesn't follow the last byte; RAR 1.5 and 2.0, which have none, by the
/// rest of the packed data decoding on cleanly. Either way the declared bytes
/// are delivered and a solid successor reads whole.
#[test]
fn a_legacy_member_that_runs_past_its_declared_size_is_reported_as_such() {
    let members = members(6000);
    let cases = [
        ("RAR 1.5", ArchiveVersion::Rar15, None),
        ("RAR 2.0", ArchiveVersion::Rar20, None),
        ("RAR 2.9 LZ", ArchiveVersion::Rar29, Some(Rar29Method::Lz)),
        (
            "RAR 2.9 PPMd",
            ArchiveVersion::Rar29,
            Some(Rar29Method::Ppmd),
        ),
    ];
    for (format, version, method) in cases {
        for solid in [false, true] {
            let case = format!("{format} solid={solid}");
            let mut bytes = match method {
                Some(method) => build_rar29(method, solid, &members),
                None => build(version, solid, &members),
            };
            declare_legacy_size(&mut bytes, 2, 1000);

            // Without salvage, the error it always had.
            let failures = Failures::default();
            let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
            let strict = ArchiveReadOptions::new().with_member_error_handler(&handler);
            let archive = ArchiveReader::read_with_options(&bytes, strict).unwrap();
            extract(&archive, strict).unwrap();
            let failed = failures.take();
            assert_eq!(failed.len(), 1, "{case}: {failed:?}");
            let expected = if version == ArchiveVersion::Rar29 {
                "has trailing data"
            } else {
                "Crc32Mismatch"
            };
            assert!(failed[0].1.contains(expected), "{case}: {failed:?}");

            let (_, outputs, failed) = salvage(&bytes, None);
            assert_eq!(
                failed,
                [(
                    b"m2.txt".to_vec(),
                    "MemberRanPastDeclaredSize { declared: 1000 }".to_string()
                )],
                "{case}"
            );
            assert_eq!(output(&outputs, b"m2.txt"), &members[2].1[..1000], "{case}");
            for (name, data) in members.iter().filter(|(name, _)| name != b"m2.txt") {
                assert_eq!(output(&outputs, name), data, "{case}: {name:?}");
            }
        }
    }
}

/// A file cut partway through a member's data: salvage offers the member,
/// delivers what decodes from the bytes there are, and reports the cut.
/// Without salvage the parse ends before it, as before.
#[test]
fn a_member_the_file_ends_partway_through_delivers_what_is_there() {
    let members = members(30_000);
    let cases = [
        ("RAR 1.3", ArchiveVersion::Rar13, None),
        ("RAR 1.5", ArchiveVersion::Rar15, None),
        ("RAR 2.0", ArchiveVersion::Rar20, None),
        ("RAR 2.9 LZ", ArchiveVersion::Rar29, Some(Rar29Method::Lz)),
        (
            "RAR 2.9 PPMd",
            ArchiveVersion::Rar29,
            Some(Rar29Method::Ppmd),
        ),
        ("RAR 5", ArchiveVersion::Rar50, None),
    ];
    for (format, version, method) in cases {
        for solid in [false, true] {
            let bytes = match method {
                Some(method) => build_rar29(method, solid, &members),
                None => build(version, solid, &members),
            };
            let (_, packed) = member_ranges(&bytes, 2);
            let cut = &bytes[..packed.start + packed.len() / 2];
            let present = (packed.len() / 2) as u64;

            // Without salvage the member is lost.
            let failures = Failures::default();
            let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
            let strict = ArchiveReadOptions::new().with_member_error_handler(&handler);
            let archive = ArchiveReader::read_with_options(cut, strict).unwrap();
            let outputs = extract(&archive, strict).unwrap();
            assert_eq!(outputs, members[..2], "{format} solid={solid}");

            let paths: &[Rar50Path] = if version == ArchiveVersion::Rar50 {
                RAR50_PATHS
            } else {
                &[Rar50Path::Buffered]
            };
            for &path in paths {
                let case = format!("{format} solid={solid} {path:?}");
                let (archive, outputs, failed) = salvage_on(cut, path, 1024);
                assert!(archive.truncation().is_some(), "{case}");
                assert_eq!(
                    failed,
                    [(
                        b"m2.txt".to_vec(),
                        format!(
                            "MemberCutShort {{ packed: {}, present: {present} }}",
                            packed.len()
                        )
                    )],
                    "{case}"
                );
                assert_eq!(outputs[..2], members[..2], "{case}");
                let delivered = output(&outputs, b"m2.txt");
                let whole = &members[2].1;
                assert!(
                    delivered.len() > whole.len() / 8,
                    "{case}: {}",
                    delivered.len()
                );
                assert!(delivered.len() < whole.len(), "{case}");
                assert!(whole.starts_with(delivered), "{case}");
                assert_eq!(outputs.len(), 3, "{case}");
            }
        }
    }
}

/// RAR 1.3 the same, stored and compressed, read from bytes and from a
/// seekable reader, which parse apart.
#[test]
fn a_rar13_member_the_file_ends_partway_through_delivers_what_is_there() {
    let members = members(30_000);
    for store in [false, true] {
        // RAR 1.3 has no solid stored archives.
        for solid in [false, true].into_iter().filter(|&solid| !(store && solid)) {
            let mut builder = Builder::new(ArchiveVersion::Rar13)
                .store(store)
                .solid(solid);
            for (name, data) in &members {
                builder
                    .add_bytes(name.clone(), data.clone(), None, None)
                    .unwrap();
            }
            let bytes = builder.to_bytes().unwrap();
            let (_, packed) = member_ranges(&bytes, 2);
            let cut = bytes[..packed.start + packed.len() / 2].to_vec();
            let present = (packed.len() / 2) as u64;
            for from_reader in [false, true] {
                let case = format!("store={store} solid={solid} from_reader={from_reader}");
                let failures = Failures::default();
                let handler =
                    |member: &ArchiveMember, error: &Error| failures.handle(member, error);
                let options = ArchiveReadOptions::new()
                    .with_salvage(true)
                    .with_member_error_handler(&handler);
                let archive = if from_reader {
                    ArchiveReader::read_reader_with_options(io::Cursor::new(cut.clone()), options)
                } else {
                    ArchiveReader::read_with_options(&cut, options)
                }
                .unwrap();
                assert!(archive.truncation().is_some(), "{case}");
                let outputs = extract(&archive, options).unwrap();
                let failed = failures.take();
                assert_eq!(
                    failed,
                    [(
                        b"m2.txt".to_vec(),
                        format!(
                            "MemberCutShort {{ packed: {}, present: {present} }}",
                            packed.len()
                        )
                    )],
                    "{case}"
                );
                archive
                    .test_with_options_and_callback(options, |_| Ok(()))
                    .unwrap();
                assert_eq!(failures.take(), failed, "{case}: test and extract agree");
                assert_eq!(outputs.len(), 3, "{case}");
                assert_eq!(outputs[..2], members[..2], "{case}");
                let delivered = output(&outputs, b"m2.txt");
                let whole = &members[2].1;
                assert!(
                    delivered.len() > whole.len() / 8,
                    "{case}: {}",
                    delivered.len()
                );
                assert!(delivered.len() < whole.len(), "{case}");
                assert!(whole.starts_with(delivered), "{case}");
                if store {
                    assert_eq!(delivered.len() as u64, present, "{case}");
                }
            }
        }
    }
}

/// Where each member's block header starts.
fn header_starts(bytes: &[u8]) -> Vec<usize> {
    (0..5)
        .map(|index| member_ranges(bytes, index).0.start)
        .collect()
}

/// Makes the block header at `start` unreadable: its size says less than the
/// fixed fields (RAR 1.5-4), or never ends (RAR 5).
fn break_header(bytes: &mut [u8], version: ArchiveVersion, start: usize) {
    if version == ArchiveVersion::Rar50 {
        bytes[start + 4..start + 16].fill(0xff);
    } else {
        bytes[start + 5..start + 7].copy_from_slice(&3u16.to_le_bytes());
    }
}

/// [`salvage`], parsing from bytes or from a seekable reader, which take
/// apart paths through the walk.
fn salvage_from(bytes: &[u8], from_reader: bool) -> (Archive, Outputs, Vec<(Vec<u8>, String)>) {
    if !from_reader {
        return salvage(bytes, None);
    }
    let failures = Failures::default();
    let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
    let options = ArchiveReadOptions::new()
        .with_salvage(true)
        .with_member_error_handler(&handler);
    let archive =
        ArchiveReader::read_reader_with_options(io::Cursor::new(bytes.to_vec()), options).unwrap();
    let outputs = extract(&archive, options).unwrap();
    let extracted = failures.take();
    archive
        .test_with_options_and_callback(options, |_| Ok(()))
        .unwrap();
    assert_eq!(failures.take(), extracted, "test and extract agree");
    (archive, outputs, extracted)
}

fn resyncs(archive: &Archive) -> Vec<(u64, u64)> {
    archive
        .header_damage()
        .iter()
        .filter_map(|damage| match damage.kind {
            HeaderDamageKind::Resynced { next, .. } => Some((damage.offset, next)),
            _ => None,
        })
        .collect()
}

/// A block header that doesn't parse does not end the walk: it goes on at
/// the next header that checks out, and the members after it are read.
#[test]
fn the_walk_resyncs_past_a_header_that_does_not_parse() {
    let members = members(6000);
    for version in VERSIONS {
        for from_reader in [false, true] {
            let case = format!("{version:?} from_reader={from_reader}");
            let mut bytes = build(version, false, &members);
            let starts = header_starts(&bytes);
            break_header(&mut bytes, version, starts[2]);
            assert!(ArchiveReader::read(&bytes).is_err(), "{case}");

            let (archive, outputs, failed) = salvage_from(&bytes, from_reader);
            assert!(failed.is_empty(), "{case}: {failed:?}");
            assert_eq!(
                resyncs(&archive),
                [(starts[2] as u64, starts[3] as u64)],
                "{case}"
            );
            assert_eq!(archive.header_damage().len(), 1, "{case}");
            let expected: Vec<_> = members
                .iter()
                .enumerate()
                .filter(|&(index, _)| index != 2)
                .map(|(_, member)| member.clone())
                .collect();
            assert_eq!(outputs, expected, "{case}");
        }
    }
}

/// In a solid archive the members after the gap have lost their history:
/// what decodes is delivered, and each is reported, never verified.
#[test]
fn solid_members_after_a_resync_are_never_verified() {
    let members = members(6000);
    for version in VERSIONS {
        let case = format!("{version:?}");
        let mut bytes = build(version, true, &members);
        let starts = header_starts(&bytes);
        break_header(&mut bytes, version, starts[2]);

        let (archive, outputs, failed) = salvage(&bytes, None);
        assert_eq!(resyncs(&archive).len(), 1, "{case}");
        assert_eq!(outputs[..2], members[..2], "{case}");
        assert_eq!(outputs.len(), 4, "{case}");
        assert_eq!(
            failed,
            [
                (b"m3.txt".to_vec(), "SolidHistoryLost".to_string()),
                (b"m4.txt".to_vec(), "SolidHistoryLost".to_string()),
            ],
            "{case}"
        );
    }
}

/// Sets the packed size in member `index`'s header to `size`, keeping the
/// field's width and leaving the header's checksum stale.
fn damage_packed_size(bytes: &mut [u8], version: ArchiveVersion, start: usize, size: u64) {
    if version != ArchiveVersion::Rar50 {
        bytes[start + 7..start + 11].copy_from_slice(&(size as u32).to_le_bytes());
        return;
    }
    let mut at = start + 4;
    read_vint(bytes, &mut at);
    read_vint(bytes, &mut at);
    let flags = read_vint(bytes, &mut at);
    if flags & 1 != 0 {
        read_vint(bytes, &mut at);
    }
    assert!(flags & 2 != 0, "the member has data");
    let field = at;
    read_vint(bytes, &mut at);
    let width = at - field;
    let size = size.min((1u64 << (7 * width)) - 1);
    let mut left = size;
    for (index, byte) in bytes[field..at].iter_mut().enumerate() {
        *byte = (left & 0x7f) as u8 | if index + 1 < width { 0x80 } else { 0 };
        left >>= 7;
    }
}

/// A header whose packed size is damaged, so whose checksum fails, sends the
/// walk to the wrong place. The resync goes back to just after that header,
/// so the members after it are kept. When the size grew, the member's data
/// is taken to end at the next header, and verifies.
#[test]
fn a_damaged_packed_size_is_resynced_from_the_header_it_damaged() {
    let members = members(6000);
    for version in VERSIONS {
        // A grown size loses no member, so even a solid stream stays whole.
        let cases = [
            ("shrunk", false, false),
            ("grown", true, false),
            ("grown", true, true),
        ];
        for (what, grow, solid) in cases {
            for from_reader in [false, true] {
                let case = format!("{version:?} {what} solid={solid} from_reader={from_reader}");
                let mut bytes = build(version, solid, &members);
                let starts = header_starts(&bytes);
                let (_, packed) = member_ranges(&bytes, 2);
                let size = if grow {
                    u64::from(u32::MAX)
                } else {
                    packed.len() as u64 / 2
                };
                damage_packed_size(&mut bytes, version, starts[2], size);

                let (archive, outputs, failed) = salvage_from(&bytes, from_reader);
                assert_eq!(
                    resyncs(&archive),
                    [(starts[2] as u64, starts[3] as u64)],
                    "{case}: {:?}",
                    archive.header_damage()
                );
                assert!(
                    archive
                        .header_damage()
                        .iter()
                        .any(|damage| damage.offset == starts[2] as u64
                            && matches!(damage.kind, HeaderDamageKind::Checksum { .. })),
                    "{case}"
                );
                for (name, data) in members.iter().filter(|(name, _)| name != b"m2.txt") {
                    assert_eq!(output(&outputs, name), data, "{case}");
                }
                let names: Vec<_> = failed.iter().map(|(name, _)| name.clone()).collect();
                if grow {
                    assert_eq!(outputs, members, "{case}");
                    assert!(failed.is_empty(), "{case}: {failed:?}");
                } else {
                    assert_eq!(names, [b"m2.txt".to_vec()], "{case}");
                }
            }
        }
    }
}

/// Random bytes over a stretch of an archive, header or data, never give a
/// member that passes as verified but doesn't hold what was stored. A resync can
/// land on a false header, but its member then fails its checksum.
#[test]
fn random_damage_never_passes_as_verified() {
    let members = members(3000);
    let mut seed = 526u32;
    let mut next = move || {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        (seed >> 8) as usize
    };
    for version in VERSIONS {
        for solid in [false, true] {
            let bytes = build(version, solid, &members);
            let first = header_starts(&bytes)[0];
            for trial in 0..40 {
                let case = format!("{version:?} solid={solid} trial={trial}");
                let mut damaged = bytes.clone();
                let start = first + next() % (bytes.len() - first);
                let len = (1 + next() % 2048).min(bytes.len() - start);
                for byte in &mut damaged[start..start + len] {
                    *byte = next() as u8;
                }
                let failures = Failures::default();
                let handler =
                    |member: &ArchiveMember, error: &Error| failures.handle(member, error);
                let options = ArchiveReadOptions::new()
                    .with_salvage(true)
                    .with_member_error_handler(&handler);
                let Ok(archive) = ArchiveReader::read_with_options(&damaged, options) else {
                    continue;
                };
                let Ok(outputs) = extract(&archive, options) else {
                    continue;
                };
                let failed = failures.take();
                for (name, data) in &outputs {
                    // A damaged header read as stored can name a directory
                    // or an empty file, which has nothing to verify; the
                    // header is listed as damaged.
                    if data.is_empty() || failed.iter().any(|(failed, _)| failed == name) {
                        continue;
                    }
                    // A name can be damaged and read as stored; the bytes
                    // passed their checksum, so are a stored member's.
                    assert!(
                        members.iter().any(|member| member.1 == *data),
                        "{case}: {name:?} passed but isn't a stored member: {} bytes, {:?}",
                        data.len(),
                        archive.header_damage()
                    );
                }
            }
        }
    }
}

fn build_quick_open(solid: bool, members: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .solid(solid)
        .archive_metadata(None, false, true)
        .unwrap();
    for (name, data) in members {
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
    }
    builder.to_bytes().unwrap()
}

fn quick_open_copies(archive: &Archive) -> Vec<(u64, Vec<u8>)> {
    archive
        .header_damage()
        .iter()
        .filter_map(|damage| match &damage.kind {
            HeaderDamageKind::QuickOpenCopy { name } => Some((damage.offset, name.clone())),
            _ => None,
        })
        .collect()
}

/// A RAR 5 member whose own header is lost is read from its copy in the
/// quick-open block, and reported as such. Its data still has to pass its
/// checksum, and with it a solid stream is whole again.
#[test]
fn the_quick_open_copy_stands_in_for_a_lost_rar50_header() {
    let members = members(6000);
    for solid in [false, true] {
        for from_reader in [false, true] {
            let case = format!("solid={solid} from_reader={from_reader}");
            let mut bytes = build_quick_open(solid, &members);
            let starts = header_starts(&bytes);
            break_header(&mut bytes, ArchiveVersion::Rar50, starts[2]);
            assert!(ArchiveReader::read(&bytes).is_err(), "{case}");

            let (archive, outputs, failed) = salvage_from(&bytes, from_reader);
            assert_eq!(
                resyncs(&archive),
                [(starts[2] as u64, starts[3] as u64)],
                "{case}"
            );
            assert_eq!(
                quick_open_copies(&archive),
                [(starts[2] as u64, b"m2.txt".to_vec())],
                "{case}"
            );
            assert!(failed.is_empty(), "{case}: {failed:?}");
            assert_eq!(outputs, members, "{case}");
        }
    }
}

/// A RAR 5 main header that doesn't parse is resynced past too, the archive
/// read as a plain one. The quick-open block is then found by the walk.
#[test]
fn a_lost_rar50_main_header_is_resynced_past() {
    let members = members(6000);
    for quick_open in [false, true] {
        for solid in [false, true] {
            let case = format!("quick_open={quick_open} solid={solid}");
            let mut bytes = if quick_open {
                build_quick_open(solid, &members)
            } else {
                build(ArchiveVersion::Rar50, solid, &members)
            };
            let starts = header_starts(&bytes);
            // The main header follows the eight-byte signature.
            break_header(&mut bytes, ArchiveVersion::Rar50, 8);
            if quick_open {
                break_header(&mut bytes, ArchiveVersion::Rar50, starts[2]);
            }
            assert!(ArchiveReader::read(&bytes).is_err(), "{case}");

            let (archive, outputs, failed) = salvage(&bytes, None);
            let mut expected_resyncs = vec![(8, starts[0] as u64)];
            if quick_open {
                expected_resyncs.push((starts[2] as u64, starts[3] as u64));
            }
            assert_eq!(resyncs(&archive), expected_resyncs, "{case}");
            assert!(failed.is_empty(), "{case}: {failed:?}");
            assert_eq!(outputs, members, "{case}");
        }
    }
}

/// Without salvage the quick-open copies are never read: the damaged
/// archive fails as it did.
#[test]
fn quick_open_copies_are_unused_without_salvage() {
    let members = members(6000);
    let mut bytes = build_quick_open(false, &members);
    let starts = header_starts(&bytes);
    break_header(&mut bytes, ArchiveVersion::Rar50, starts[2]);
    let failures = Failures::default();
    let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
    let options = ArchiveReadOptions::new().with_member_error_handler(&handler);
    assert!(ArchiveReader::read_with_options(&bytes, options).is_err());
}
