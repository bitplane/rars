#![cfg(feature = "write")]
//! Reading past damage with a member error handler: a corrupt member, and a
//! file cut short through a member or its header.

#[path = "support/scratch.rs"]
mod scratch;

use rars::{
    Archive, ArchiveMember, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error,
    ExtractionErrorAction, TruncatedBlock,
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
