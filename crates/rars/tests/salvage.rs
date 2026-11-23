#![cfg(feature = "write")]
//! Reading past damage with a member error handler: a corrupt member, and a
//! file cut short through a member or its header.

#[path = "support/scratch.rs"]
mod scratch;

use rars::rar15_40::{write_compressed_archive, FileEntry, Rar29Method, WriterOptions};
use rars::{
    Archive, ArchiveMember, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error,
    ExtractionErrorAction, FeatureSet, TruncatedBlock,
};
use std::io::{self, Write};
use std::ops::Range;
use std::sync::{Arc, Mutex};

const VERSIONS: [ArchiveVersion; 5] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];

/// Five members of text from one vocabulary, so solid members refer back.
fn members() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut seed = 436u32;
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
            while text.len() < 6000 {
                text.extend_from_slice(&words[next() % words.len()]);
                text.push(b' ');
            }
            (format!("m{index}.txt").into_bytes(), text)
        })
        .collect()
}

fn build(version: ArchiveVersion, solid: bool) -> Vec<u8> {
    let mut builder = Builder::new(version).solid(solid);
    for (name, data) in members() {
        builder.add_bytes(name, data, None, None).unwrap();
    }
    builder.to_bytes().unwrap()
}

/// Each member's packed data in the file.
fn data_ranges(archive: &Archive) -> Vec<Range<usize>> {
    match archive {
        Archive::Rar13(archive) => archive
            .entries
            .iter()
            .map(|entry| entry.packed_range.clone())
            .collect(),
        Archive::Rar15To40(archive) => archive
            .files()
            .map(|file| file.packed_range.clone())
            .collect(),
        Archive::Rar50Plus(archive) => archive
            .files()
            .map(|file| file.block.data_range.clone())
            .collect(),
        _ => unreachable!("every family is listed"),
    }
}

/// Records the members a handler is called for, and carries on past them.
#[derive(Default)]
struct Failures(Mutex<Vec<Vec<u8>>>);

impl Failures {
    fn handle(&self, member: &ArchiveMember, _: &Error) -> rars::Result<ExtractionErrorAction> {
        self.0.lock().unwrap().push(member.meta.name.clone());
        Ok(ExtractionErrorAction::Continue)
    }

    fn names(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
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

/// Extracts every member as the CLI does, returning each output by name.
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

/// Tests every member as the CLI does, returning the names called back.
fn test(archive: &Archive, options: ArchiveReadOptions<'_>) -> rars::Result<Vec<Vec<u8>>> {
    let mut tested = Vec::new();
    archive.test_with_options_and_callback(options, |meta| {
        tested.push(meta.name.clone());
        Ok(())
    })?;
    Ok(tested)
}

#[test]
fn a_damaged_member_is_reported_and_the_others_still_read() {
    let expected = members();
    for version in VERSIONS {
        for solid in [false, true] {
            let case = format!("{version:?} solid={solid}");
            let mut bytes = build(version, solid);
            let archive = ArchiveReader::read(&bytes).unwrap();
            let damaged = data_ranges(&archive)[2].clone();
            bytes[damaged.start + damaged.len() / 2] ^= 0x55;
            let archive = ArchiveReader::read_owned(bytes).unwrap();

            // By default the first failure is the result.
            let error = extract(&archive, ArchiveReadOptions::new()).unwrap_err();
            assert_eq!(error.entry_context().unwrap().0, b"m2.txt", "{case}");
            assert!(archive.test(None).is_err(), "{case}");

            for read in ["test", "extract"] {
                let failures = Failures::default();
                let handler =
                    |member: &ArchiveMember, error: &Error| failures.handle(member, error);
                let options = ArchiveReadOptions::new().with_member_error_handler(&handler);
                let outputs = if read == "test" {
                    test(&archive, options)
                        .unwrap()
                        .into_iter()
                        .map(|name| (name, None))
                        .collect::<Vec<_>>()
                } else {
                    extract(&archive, options)
                        .unwrap()
                        .into_iter()
                        .map(|(name, data)| (name, Some(data)))
                        .collect()
                };
                let failed = failures.names();
                assert_eq!(
                    failed.first().map(Vec::as_slice),
                    Some(&b"m2.txt"[..]),
                    "{case} {read}"
                );
                if !solid {
                    // Independent members are unaffected.
                    assert_eq!(failed, [b"m2.txt"], "{case} {read}");
                }
                // Every member is visited, and each one not reported is whole.
                for (name, data) in &expected {
                    if failed.contains(name) {
                        continue;
                    }
                    let output = outputs.iter().find(|(seen, _)| seen == name);
                    let output =
                        output.unwrap_or_else(|| panic!("{case} {read}: {name:?} missing"));
                    if let Some(output) = &output.1 {
                        assert_eq!(output, data, "{case} {read}: {name:?}");
                    }
                }
                let reached = outputs.iter().any(|(name, _)| name == b"m4.txt")
                    || failed.contains(&b"m4.txt".to_vec());
                assert!(reached, "{case} {read}: stopped early");
            }
        }
    }
}

/// Parses `bytes` from memory and from a file, with and without a handler,
/// and checks a cut through member 2 at `header`.
fn check_cut_through_member_two(case: &str, bytes: &[u8], header: usize, dir: &std::path::Path) {
    let expected = members();
    let path = dir.join("cut.rar");
    std::fs::write(&path, bytes).unwrap();
    // By default a cut member is still an error.
    let error = ArchiveReader::read(bytes).unwrap_err();
    assert_eq!(error.root_cause(), &Error::TooShort, "{case}");
    assert!(ArchiveReader::read_path(&path).is_err(), "{case}");

    let failures = Failures::default();
    let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
    let options = ArchiveReadOptions::new().with_member_error_handler(&handler);
    for archive in [
        ArchiveReader::read_with_options(bytes, options).unwrap(),
        ArchiveReader::read_path_with_options(&path, options).unwrap(),
    ] {
        let truncation = archive.truncation().unwrap_or_else(|| panic!("{case}"));
        assert!(
            matches!(&truncation.block, TruncatedBlock::Member(name) if name.is_empty() || name == b"m2.txt"),
            "{case}: {truncation:?}"
        );
        assert_eq!(truncation.offset, header as u64, "{case}");
        assert!(truncation.started, "{case}");
        let names: Vec<_> = archive.members().map(|member| member.meta.name).collect();
        assert_eq!(names, [b"m0.txt".to_vec(), b"m1.txt".to_vec()], "{case}");
        let outputs = extract(&archive, options).unwrap();
        assert_eq!(outputs, expected[..2], "{case}");
        assert_eq!(test(&archive, options).unwrap(), names, "{case}");
    }
    assert!(failures.names().is_empty(), "{case}");
}

#[test]
fn a_file_cut_through_a_member_reads_the_members_before_it() {
    let dir = scratch::case("salvage-cut-member");
    for version in VERSIONS {
        for solid in [false, true] {
            let bytes = build(version, solid);
            let archive = ArchiveReader::read(&bytes).unwrap();
            let ranges = data_ranges(&archive);
            // Nothing sits between one member's data and the next header.
            let header = ranges[1].end;
            let data = ranges[2].clone();
            let case = format!("{version:?} solid={solid}");
            check_cut_through_member_two(
                &format!("{case} cut in data"),
                &bytes[..data.start + data.len() / 2],
                header,
                &dir,
            );
            check_cut_through_member_two(
                &format!("{case} cut in header"),
                &bytes[..data.start - 1],
                header,
                &dir,
            );
        }
    }
}

/// `members()` with m3's text in capitals added to m2, and m4's in capitals
/// as m3. The capitals' statistics differ enough that the LZ coder starts new
/// tables partway through m2.
fn rar29_members() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut members = members();
    let capitals = |index: usize| members[index].1.to_ascii_uppercase();
    let (three, four) = (capitals(3), capitals(4));
    members[2].1.extend_from_slice(&three);
    members[3].1 = four;
    members
}

/// A solid RAR 2.9 archive of `rar29_members()` written with `method`.
fn build_rar29(method: Rar29Method) -> Vec<u8> {
    let members = rar29_members();
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
    features.solid = true;
    let options = WriterOptions::new(ArchiveVersion::Rar29, features).with_method(method);
    write_compressed_archive(&entries, options).unwrap()
}

/// Moves member `index`'s declared unpacked size by `delta` and reseals its
/// header.
fn shift_declared_size(bytes: &mut [u8], index: usize, delta: i64) {
    let archive = match ArchiveReader::read(bytes).unwrap() {
        Archive::Rar15To40(archive) => archive,
        Archive::Rar50Plus(archive) => {
            let file = archive.files().nth(index).unwrap();
            return shift_rar50_declared_size(bytes, &file.block, delta);
        }
        _ => unreachable!("a RAR 1.5-5 archive"),
    };
    let file = archive.files().nth(index).unwrap();
    let header = file.block.offset..file.block.offset + usize::from(file.block.head_size);
    let size = u32::try_from(file.unp_size as i64 + delta).unwrap();
    bytes[header.start + 11..header.start + 15].copy_from_slice(&size.to_le_bytes());
    let crc = rars::crc32::crc32(&bytes[header.start + 2..header.end]) as u16;
    bytes[header.start..header.start + 2].copy_from_slice(&crc.to_le_bytes());
}

/// RAR 5 keeps the size as a variable-length number after the file flags.
/// The new size is written in as many bytes as the old one took.
fn shift_rar50_declared_size(bytes: &mut [u8], block: &rars::rar50::BlockHeader, delta: i64) {
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
    let mut at = block.header_range.start;
    read_vint(bytes, &mut at);
    let start = at;
    let size = read_vint(bytes, &mut at);
    let width = at - start;
    let mut size = u64::try_from(size as i64 + delta).unwrap();
    for (index, byte) in bytes[start..at].iter_mut().enumerate() {
        *byte = (size & 0x7f) as u8 | if index + 1 < width { 0x80 } else { 0 };
        size >>= 7;
    }
    assert_eq!(size, 0, "the new size needs more bytes");
    let mut end = block.offset + 4;
    let header_size = read_vint(bytes, &mut end);
    let end = end + usize::try_from(header_size).unwrap();
    let crc = rars::crc32::crc32(&bytes[block.offset + 4..end]);
    bytes[block.offset..block.offset + 4].copy_from_slice(&crc.to_le_bytes());
}

/// Reads `archive`, whose member 2 has had its declared size moved by `delta`,
/// with a handler. A declared size short of the stream cuts member 2's output
/// there and fails it. A declared size past the end of the stream leaves the
/// stream to end member 2, which then passes, because its CRC matches. Either
/// way every other member is read whole.
fn check_shifted_member_two(
    case: &str,
    archive: &Archive,
    expected: &[(Vec<u8>, Vec<u8>)],
    delta: i64,
) {
    let failed: &[&[u8]] = if delta < 0 { &[b"m2.txt"] } else { &[] };
    for read in ["test", "extract"] {
        let failures = Failures::default();
        let handler = |member: &ArchiveMember, error: &Error| failures.handle(member, error);
        let options = ArchiveReadOptions::new().with_member_error_handler(&handler);
        if read == "test" {
            let tested = test(archive, options).unwrap();
            for (name, _) in expected {
                assert!(tested.contains(name), "{case} {read}: {name:?} missing");
            }
        } else {
            let outputs = extract(archive, options).unwrap();
            for (name, data) in expected {
                let output = outputs.iter().find(|(seen, _)| seen == name);
                let output = output.unwrap_or_else(|| panic!("{case}: {name:?} missing"));
                let len = if name == b"m2.txt" && delta < 0 {
                    (data.len() as i64 + delta) as usize
                } else {
                    data.len()
                };
                assert_eq!(output.1, data[..len], "{case} {read}: {name:?}");
            }
        }
        assert_eq!(failures.names(), failed, "{case} {read}");
    }
}

/// Damage in a solid RAR 2.9 member can leave its stream decoding to more
/// bytes than it declares, or fewer. The next member starts from the tables,
/// PPMd model and window at the stream's end-of-file marker, as with unrar.
/// Editing the declared size gives the same mismatch without depending on
/// where a flipped byte lands.
#[test]
fn a_solid_rar29_member_that_ends_away_from_its_declared_size_leaves_the_next_in_step() {
    let expected = rar29_members();
    // Cut to a quarter, the stream runs on past the capitals' new tables.
    let len = expected[2].1.len() as i64;
    for method in [Rar29Method::Lz, Rar29Method::Ppmd] {
        let whole = build_rar29(method);
        for delta in [-1, -len * 3 / 4, 1, len / 2] {
            let mut bytes = whole.clone();
            shift_declared_size(&mut bytes, 2, delta);
            let archive = ArchiveReader::read_owned(bytes).unwrap();
            let case = format!("{method:?} declared size {delta:+}");
            check_shifted_member_two(&case, &archive, &expected, delta);
        }
    }
}

/// RAR 1.5 and 2.0 streams have no end-of-file marker: a member's stream ends
/// with its packed data. A member whose declared size is short of that is
/// decoded on to the end of its packed data, into the window only, so the next
/// solid member starts in step. RAR 2.9 does the same up to its marker.
#[test]
fn a_solid_member_whose_declared_size_is_wrong_leaves_the_rest_readable() {
    let expected = members();
    let len = expected[2].1.len() as i64;
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
    ] {
        let whole = build(version, true);
        for delta in [-len / 2, -10, -1, 1, 10, len / 2] {
            let mut bytes = whole.clone();
            shift_declared_size(&mut bytes, 2, delta);
            let archive = ArchiveReader::read_owned(bytes).unwrap();
            let case = format!("{version:?} declared size {delta:+}");
            check_shifted_member_two(&case, &archive, &expected, delta);
        }
    }
}

/// Issue #488: a member whose stream ends before its declared size, but whose
/// checksum matches what it produced, passes. With strict sizes, as `rars
/// test` asks for, it is reported with what it decoded, and the members after
/// it, solid or not, still read.
#[test]
fn strict_sizes_report_a_member_whose_stream_ends_before_its_declared_size() {
    let expected = members();
    let len = expected[2].1.len() as u64;
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        for solid in [false, true] {
            let mut bytes = build(version, solid);
            shift_declared_size(&mut bytes, 2, 10);
            let archive = ArchiveReader::read_owned(bytes).unwrap();
            let case = format!("{version:?} solid={solid}");
            for strict in [false, true] {
                let errors = Mutex::new(Vec::new());
                let handler = |member: &ArchiveMember, error: &Error| {
                    let error = error.root_cause().clone();
                    errors
                        .lock()
                        .unwrap()
                        .push((member.meta.name.clone(), error));
                    Ok(ExtractionErrorAction::Continue)
                };
                let options = ArchiveReadOptions::new()
                    .with_strict_member_sizes(strict)
                    .with_member_error_handler(&handler);
                let tested = test(&archive, options).unwrap();
                let errors = errors.into_inner().unwrap();
                if strict {
                    let ended_early = Error::MemberEndedEarly {
                        declared: len + 10,
                        decoded: len,
                    };
                    assert_eq!(errors, [(b"m2.txt".to_vec(), ended_early)], "{case}");
                } else {
                    assert_eq!(errors, [], "{case}");
                }
                for (name, _) in &expected {
                    if strict && name == b"m2.txt" {
                        continue;
                    }
                    assert!(tested.contains(name), "{case} strict={strict}: {name:?}");
                }
            }
            let outputs = extract(&archive, ArchiveReadOptions::new()).unwrap();
            assert_eq!(outputs, expected, "{case}");
        }
    }
}
