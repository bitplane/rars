#[path = "support/scratch.rs"]
mod scratch;

use rars::crc32::crc32;
use rars::rar13::{write_stored_archive, StoredEntry, WriterOptions};
use rars::rar15_40;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars/tests/fixtures/rar13")
        .join(name)
}

fn fixture_rar15_40(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars/tests/fixtures/rar15_40")
        .join(name)
}

fn fixture_rar50(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars/tests/fixtures/rar50")
        .join(name)
}

fn scratch(name: &str) -> scratch::Scratch {
    scratch::case(&format!("rars-cli-{name}"))
}

fn deterministic_noise(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

fn rar50_level_sensitive_payload() -> Vec<u8> {
    let long_match = [b"abc".as_slice(), &[b'Z'; 256]].concat();
    let mut data = long_match.clone();
    for index in 0..32u8 {
        data.extend_from_slice(b"abc");
        data.push(index);
        data.extend_from_slice(&deterministic_noise(24));
    }
    data.extend_from_slice(&long_match);
    // Level 1 looks two bytes ahead, which finds the long match above on its
    // own and leaves level 5 nothing to win there. Words from a dozen-word
    // vocabulary in a jumbled order are where the shortest-path parse still
    // packs well ahead of it.
    const WORDS: [&[u8]; 12] = [
        b"the ", b"quick ", b"brown ", b"fox ", b"jumps ", b"over ", b"lazy ", b"dog ", b"and ",
        b"then ", b"runs ", b"away ",
    ];
    let mut state = 0x1234_5678u32;
    let mut words = Vec::new();
    while words.len() < 2048 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        words.extend_from_slice(WORDS[(state >> 24) as usize % WORDS.len()]);
    }
    words.truncate(2048);
    data.extend_from_slice(&words);
    data
}

fn dos_time(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u32 {
    ((year - 1980) << 25)
        | (month << 21)
        | (day << 16)
        | (hour << 11)
        | (minute << 5)
        | (second / 2)
}

fn rars() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rars"))
}

#[test]
fn info_lists_rar13_entries() {
    let output = rars()
        .args(["info", "-v"])
        .arg(fixture("README_store.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Rar13"));
    assert!(stdout.contains("README"));
    assert!(stdout.contains("checksum=0x0fd8"));
}

/// Issue #433: test and extract finish every member of an archive cut after
/// its last one and warn where it ends. Issue #489: a cut that can't have lost
/// a member, as one inside the recovery record, is only a warning; one that
/// may have, as one at a block boundary nothing names, fails. info warns and
/// succeeds.
#[test]
fn truncated_archive_tests_and_extracts_its_members_then_fails() {
    let dir = scratch("truncated-archive");
    let first = b"issue 433 cli payload\n".repeat(200);
    let second = deterministic_noise(5000);
    let path = dir.join("cut.rar");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(10));
    builder
        .add_bytes(b"first.txt".to_vec(), first.clone(), None, None)
        .unwrap();
    builder
        .add_bytes(b"second.bin".to_vec(), second.clone(), None, None)
        .unwrap();
    builder.write_to_path(&path, None).unwrap();
    let archive = rars::rar50::Archive::parse_path(&path).unwrap();
    let recovery = archive.services().find(|service| service.name == b"RR");
    let recovery = recovery.unwrap().block.clone();
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..recovery.data_range.start + 100]).unwrap();
    let warning = format!(
        "warning: {}: archive is truncated inside the recovery record, which starts at offset {}",
        path.display(),
        recovery.offset
    );

    let output = rars().arg("test").arg(&path).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let errors = stderr(&output);
    assert!(errors.contains(&warning), "{errors}");
    assert!(!errors.contains("error"), "{errors}");
    let text = stdout(&output);
    assert!(
        text.contains("first.txt") && text.contains("second.bin"),
        "{text}"
    );

    let out = dir.join("out");
    let output = rars().arg("x").arg(&path).arg(&out).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains(&warning), "{}", stderr(&output));
    assert_eq!(fs::read(out.join("first.txt")).unwrap(), first);
    assert_eq!(fs::read(out.join("second.bin")).unwrap(), second);

    let output = rars().arg("info").arg(&path).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains(&warning), "{}", stderr(&output));

    // With no recovery record or quick-open block before it, a file that
    // stops where the end block was due may have lost a member there too.
    let plain = dir.join("plain.rar");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"first.txt".to_vec(), first.clone(), None, None)
        .unwrap();
    builder.write_to_path(&plain, None).unwrap();
    let plain_bytes = fs::read(&plain).unwrap();
    // RAR 5's end block is eight bytes here: CRC, size, type, flags and end flags.
    let end = plain_bytes.len() - 8;
    fs::write(&plain, &plain_bytes[..end]).unwrap();
    let output = rars().arg("test").arg(&plain).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let errors = stderr(&output);
    assert!(
        errors.contains(&format!(
            "archive is truncated at offset {end}, before the end of archive block"
        )),
        "{errors}"
    );
    assert!(errors.contains("is truncated"), "{errors}");
    assert_eq!(stdout(&output), "OK first.txt\n");

    // A cut through member data loses that member, and the one before it still tests.
    let last = archive.files().last().unwrap().block.clone();
    fs::write(&path, &bytes[..last.data_range.end - 10]).unwrap();
    let output = rars().arg("test").arg(&path).output().unwrap();
    assert!(!output.status.success());
    let warning = format!(
        "warning: {}: archive is truncated inside member 'second.bin', which starts at offset {}",
        path.display(),
        last.offset
    );
    assert!(stderr(&output).contains(&warning), "{}", stderr(&output));
    assert_eq!(stdout(&output), "OK first.txt\n");
}

/// Issue #489: zero padding after a RAR 2.9 member's last code tests clean,
/// and a malformed old authenticity block is skipped with a warning.
#[test]
fn zero_padding_and_a_short_old_block_test_clean() {
    let output = rars()
        .arg("test")
        .arg(fixture_rar15_40("zero_padding/rar29.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "OK first.bin\nOK second.txt\n");

    let dir = scratch("short-old-block");
    let path = dir.join("av.rar");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar20);
    builder
        .add_bytes(b"a.txt".to_vec(), b"issue 489\n".repeat(50), None, None)
        .unwrap();
    let mut bytes = builder.to_bytes().unwrap();
    // A 20-byte authenticity block after the main header, one byte short.
    let at = 7 + usize::from(u16::from_le_bytes([bytes[12], bytes[13]]));
    let mut block = vec![0u8; 20];
    block[2] = 0x76;
    block[5] = 20;
    let crc = (crc32(&block[2..]) & 0xffff) as u16;
    block[..2].copy_from_slice(&crc.to_le_bytes());
    bytes.splice(at..at, block);
    fs::write(&path, &bytes).unwrap();

    let output = rars().arg("test").arg(&path).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "OK a.txt\n");
    let warning = format!(
        "warning: {}: skipped malformed block 0x76 at offset {at}: RAR legacy authenticity block is too short",
        path.display()
    );
    assert!(stderr(&output).contains(&warning), "{}", stderr(&output));
}

/// Members by name, in archive order.
type Members = Vec<(String, Vec<u8>)>;

/// Five text members from one vocabulary, so solid ones refer back.
fn salvage_members() -> Members {
    let words: Vec<String> = (0..300)
        .map(|index| format!("w{}x{}", index * 7 % 113, index % 17))
        .collect();
    let noise = deterministic_noise(5 * 1200);
    (0..5)
        .map(|member| {
            let picks = &noise[member * 1200..(member + 1) * 1200];
            let text = picks
                .iter()
                .map(|&pick| words[pick as usize % words.len()].as_str())
                .collect::<Vec<_>>()
                .join(" ");
            (format!("m{member}.txt"), text.into_bytes())
        })
        .collect()
}

/// Writes [`salvage_members`] to `path`, returning them and where each one's
/// packed data is in the archive.
fn salvage_fixture(
    path: &Path,
    version: rars::ArchiveVersion,
    solid: bool,
) -> (Members, Vec<std::ops::Range<usize>>) {
    let members = salvage_members();
    let mut builder = rars::Builder::new(version).solid(solid);
    for (name, data) in &members {
        builder
            .add_bytes(name.as_bytes().to_vec(), data.clone(), None, None)
            .unwrap();
    }
    builder.write_to_path(path, None).unwrap();
    let ranges = match rars::ArchiveReader::read_path(path).unwrap() {
        rars::Archive::Rar15To40(archive) => archive
            .files()
            .map(|file| file.packed_range.clone())
            .collect(),
        rars::Archive::Rar50Plus(archive) => archive
            .files()
            .map(|file| file.block.data_range.clone())
            .collect(),
        _ => unreachable!("only RAR 2.9 and 5 are written here"),
    };
    (members, ranges)
}

/// Issue #436: a damaged member is reported, every other member is still
/// tested and extracted, and the command fails at the end.
#[test]
fn a_damaged_member_is_reported_and_the_others_test_and_extract() {
    let dir = scratch("damaged-member");
    for (version, solid) in [
        (rars::ArchiveVersion::Rar29, false),
        (rars::ArchiveVersion::Rar29, true),
        (rars::ArchiveVersion::Rar50, false),
        (rars::ArchiveVersion::Rar50, true),
    ] {
        let case = format!("{version:?} solid={solid}");
        let path = dir.join(format!("{version:?}-{solid}.rar"));
        let (members, ranges) = salvage_fixture(&path, version, solid);
        let mut bytes = fs::read(&path).unwrap();
        bytes[ranges[2].start + ranges[2].len() / 2] ^= 0x55;
        fs::write(&path, &bytes).unwrap();

        let output = rars().arg("test").arg(&path).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));
        let errors = stderr(&output);
        let warning = format!("warning: {}: while ", path.display());
        assert!(errors.contains(&warning), "{case}: {errors}");
        assert!(errors.contains("entry 'm2.txt'"), "{case}: {errors}");
        assert!(errors.contains("damaged member(s)"), "{case}: {errors}");
        let tested = stdout(&output);
        let tested: Vec<_> = tested.lines().collect();
        if solid {
            // Later members need the damaged one's output, so they may fail too.
            assert_eq!(tested[..2], ["OK m0.txt", "OK m1.txt"], "{case}");
            assert!(!tested.contains(&"OK m2.txt"), "{case}");
        } else {
            assert_eq!(
                tested,
                ["OK m0.txt", "OK m1.txt", "OK m3.txt", "OK m4.txt"],
                "{case}"
            );
        }

        let out = dir.join(format!("out-{version:?}-{solid}"));
        let output = rars().arg("x").arg(&path).arg(&out).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));
        assert!(stderr(&output).contains("entry 'm2.txt'"), "{case}");
        assert!(!out.join("m2.txt").exists(), "{case}");
        for (index, (name, data)) in members.iter().enumerate() {
            match fs::read(out.join(name)) {
                Ok(written) => assert_eq!(&written, data, "{case}: {name}"),
                Err(_) => assert!(index == 2 || solid && index > 2, "{case}: {name} missing"),
            }
        }
    }
}

/// The time and mode `keep_broken_fixture` stores: member `index` has
/// `KEPT_MTIME + 2 * index`, even for DOS times.
const KEPT_MTIME: u64 = 1_600_000_000;
const KEPT_MODE: u32 = 0o640;

/// Writes [`salvage_members`] to `path` with stored times and modes,
/// returning them and where each one's packed data is in the archive.
fn keep_broken_fixture(
    path: &Path,
    version: rars::ArchiveVersion,
    store: bool,
) -> (Members, Vec<std::ops::Range<usize>>) {
    let members = salvage_members();
    let mut builder = rars::Builder::new(version).store(store);
    for (index, (name, data)) in members.iter().enumerate() {
        builder
            .add_bytes(
                name.as_bytes().to_vec(),
                data.clone(),
                Some(rars::Timestamp::from_unix_seconds(
                    (KEPT_MTIME + 2 * index as u64) as i64,
                )),
                Some(KEPT_MODE),
            )
            .unwrap();
    }
    builder.write_to_path(path, None).unwrap();
    let ranges = match rars::ArchiveReader::read_path(path).unwrap() {
        rars::Archive::Rar15To40(archive) => archive
            .files()
            .map(|file| file.packed_range.clone())
            .collect(),
        rars::Archive::Rar50Plus(archive) => archive
            .files()
            .map(|file| file.block.data_range.clone())
            .collect(),
        _ => unreachable!("only RAR 2.9 and 5 are written here"),
    };
    (members, ranges)
}

/// Asserts the file has the time, and on Unix the mode, member `index` stored.
fn assert_kept_metadata(path: &Path, index: usize) {
    let metadata = fs::metadata(path).unwrap();
    let modified = metadata
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(
        modified,
        KEPT_MTIME + 2 * index as u64,
        "{}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            KEPT_MODE,
            "{}",
            path.display()
        );
    }
}

/// Issue #365: `x --keep-broken` keeps a member that fails its checksum with
/// every byte read for it, under its own name and with its stored time and
/// mode, warns, extracts the rest and fails as a damaged member does. With
/// `--in-place` it is the same; flattened too.
#[test]
fn keep_broken_keeps_a_member_that_fails_its_checksum() {
    let dir = scratch("keep-broken-checksum");
    for version in [rars::ArchiveVersion::Rar29, rars::ArchiveVersion::Rar50] {
        let path = dir.join(format!("{version:?}.rar"));
        let (members, ranges) = keep_broken_fixture(&path, version, true);
        let mut bytes = fs::read(&path).unwrap();
        let at = ranges[2].start + ranges[2].len() / 2;
        bytes[at] ^= 0x20;
        fs::write(&path, &bytes).unwrap();
        let mut damaged = members[2].1.clone();
        damaged[at - ranges[2].start] ^= 0x20;

        for extra in [&[][..], &["--in-place"], &["--flatten"]] {
            let case = format!("{version:?} {extra:?}");
            let out = dir.join(format!("out-{version:?}-{}", extra.join("")));
            let output = rars()
                .args(["x", "--keep-broken"])
                .args(extra)
                .arg(&path)
                .arg(&out)
                .output()
                .unwrap();
            let errors = stderr(&output);
            assert_eq!(output.status.code(), Some(1), "{case}: {errors}");
            let warning = format!("warning: {}: 'm2.txt': kept broken: ", path.display());
            assert!(errors.contains(&warning), "{case}: {errors}");
            assert_eq!(errors.matches("kept broken").count(), 1, "{case}: {errors}");
            assert!(errors.contains("1 damaged member(s)"), "{case}: {errors}");
            assert!(stdout(&output).contains("x m2.txt"), "{case}");
            for (index, (name, data)) in members.iter().enumerate() {
                let written = fs::read(out.join(name)).unwrap();
                let expected = if index == 2 { &damaged } else { data };
                assert!(written == *expected, "{case}: {name}");
                assert_kept_metadata(&out.join(name), index);
            }
        }
    }
}

/// Issue #365: a member whose stream fails partway is kept with the bytes
/// decoded before the failure, and the members after it still extract.
#[test]
fn keep_broken_keeps_what_decoded_of_a_member_damaged_partway() {
    let dir = scratch("keep-broken-partway");
    for version in [rars::ArchiveVersion::Rar29, rars::ArchiveVersion::Rar50] {
        let case = format!("{version:?}");
        let path = dir.join(format!("{version:?}.rar"));
        let (members, ranges) = keep_broken_fixture(&path, version, false);
        let mut bytes = fs::read(&path).unwrap();
        let middle = ranges[2].start + ranges[2].len() / 2;
        for byte in &mut bytes[middle..middle + 16] {
            *byte ^= 0xa5;
        }
        fs::write(&path, &bytes).unwrap();

        let out = dir.join(format!("out-{version:?}"));
        let output = rars()
            .args(["x", "--keep-broken"])
            .arg(&path)
            .arg(&out)
            .output()
            .unwrap();
        let errors = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{case}: {errors}");
        assert!(
            errors.contains("'m2.txt': kept broken: "),
            "{case}: {errors}"
        );
        let kept = fs::read(out.join("m2.txt")).unwrap();
        let data = &members[2].1;
        assert_ne!(&kept, data, "{case}");
        let whole = kept
            .iter()
            .zip(data)
            .take_while(|(kept, data)| kept == data)
            .count();
        // The damage is halfway through the packed data.
        assert!(whole >= data.len() / 4, "{case}: {whole} of {}", data.len());
        assert_kept_metadata(&out.join("m2.txt"), 2);
        for (name, data) in members.iter().filter(|(name, _)| name != "m2.txt") {
            assert_eq!(&fs::read(out.join(name)).unwrap(), data, "{case}: {name}");
        }
    }
}

/// Issue #365: a file header whose checksum fails is read as stored with
/// `--keep-broken`, warned about, and its member and those after it extract.
#[test]
fn keep_broken_reads_past_a_damaged_header() {
    let dir = scratch("keep-broken-header");
    for version in [rars::ArchiveVersion::Rar29, rars::ArchiveVersion::Rar50] {
        let case = format!("{version:?}");
        let path = dir.join(format!("{version:?}.rar"));
        let (members, _) = keep_broken_fixture(&path, version, false);
        let mut bytes = fs::read(&path).unwrap();
        let name = bytes.windows(6).position(|v| v == b"m2.txt").unwrap();
        // Renames it to l2.txt, so the header fails its checksum.
        bytes[name] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let out = dir.join(format!("out-{version:?}"));
        let output = rars()
            .args(["x", "--keep-broken"])
            .arg(&path)
            .arg(&out)
            .output()
            .unwrap();
        let errors = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{case}: {errors}");
        let warning = format!("warning: {}: header at offset ", path.display());
        assert!(errors.contains(&warning), "{case}: {errors}");
        assert!(errors.contains("fails its checksum"), "{case}: {errors}");
        assert!(errors.contains("1 damaged header(s)"), "{case}: {errors}");
        for (index, (name, data)) in members.iter().enumerate() {
            let name = if index == 2 { "l2.txt" } else { name };
            assert_eq!(&fs::read(out.join(name)).unwrap(), data, "{case}: {name}");
            assert_kept_metadata(&out.join(name), index);
        }

        // Without it, the damaged header still fails the archive.
        let out = dir.join(format!("plain-{version:?}"));
        let output = rars().arg("x").arg(&path).arg(&out).output().unwrap();
        assert_ne!(output.status.code(), Some(0), "{case}");
        assert!(!out.join("l2.txt").exists(), "{case}");
        assert!(!stderr(&output).contains("header at offset"), "{case}");
    }
}

/// Issue #365: a salvaged extraction never exits as a clean one does: it
/// gives the status a damaged member gives without `--keep-broken`, and
/// without it nothing damaged is kept and the errors are unchanged.
#[test]
fn keep_broken_fails_as_a_damaged_member_does_and_is_off_by_default() {
    let dir = scratch("keep-broken-exit");
    let path = dir.join("damaged.rar");
    let (members, ranges) = keep_broken_fixture(&path, rars::ArchiveVersion::Rar50, true);
    let mut bytes = fs::read(&path).unwrap();
    bytes[ranges[1].start + 7] ^= 0x01;
    fs::write(&path, &bytes).unwrap();

    let run = |out: &Path, flag: Option<&str>| {
        rars()
            .arg("x")
            .args(flag)
            .arg(&path)
            .arg(out)
            .output()
            .unwrap()
    };
    let plain = run(&dir.join("plain"), None);
    let kept = run(&dir.join("kept"), Some("--keep-broken"));
    let in_place = run(&dir.join("in-place"), Some("--in-place"));
    assert_ne!(kept.status.code(), Some(0), "{}", stderr(&kept));
    assert_eq!(kept.status.code(), plain.status.code(), "{}", stderr(&kept));

    // Without the flag the damaged member's output is never published, and
    // the error is the one it always was.
    let errors = stderr(&plain);
    assert!(!dir.join("plain/m1.txt").exists());
    assert!(!errors.contains("kept broken"), "{errors}");
    let warning = format!("warning: {}: while ", path.display());
    assert!(errors.contains(&warning), "{errors}");
    assert!(errors.contains("entry 'm1.txt'"), "{errors}");
    assert!(errors.contains("1 damaged member(s)"), "{errors}");
    assert!(!stdout(&plain).contains("x m1.txt"));
    assert!(!stderr(&in_place).contains("kept broken"));
    assert_eq!(in_place.status.code(), plain.status.code());
    for (name, data) in members.iter().filter(|(name, _)| name != "m1.txt") {
        assert_eq!(&fs::read(dir.join("plain").join(name)).unwrap(), data);
    }
}

/// Edits the RAR 1.5-4 file header of the member named `name`, then reseals
/// the header's CRC, so only the edit is odd. `edit` gets the header and the
/// offset of the name in it.
fn edit_rar15_40_header(bytes: &mut [u8], name: &[u8], edit: impl FnOnce(&mut [u8], usize)) {
    let at_name = bytes.windows(name.len()).position(|v| v == name).unwrap();
    let mut at = 7;
    loop {
        let flags = u16::from_le_bytes([bytes[at + 3], bytes[at + 4]]);
        let size = usize::from(u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]));
        if (at..at + size).contains(&at_name) {
            edit(&mut bytes[at..at + size], at_name - at);
            let crc = crc32(&bytes[at + 2..at + size]) as u16;
            bytes[at..at + 2].copy_from_slice(&crc.to_le_bytes());
            return;
        }
        let packed = if flags & 0x8000 != 0 {
            u32::from_le_bytes(bytes[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        at += size + packed;
    }
}

fn rar50_vint(mut value: u64) -> Vec<u8> {
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

fn read_rar50_vint(bytes: &[u8], at: &mut usize) -> u64 {
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

/// The fields of a RAR 5 file header that the edits below touch, as offsets
/// into the header after its size field.
struct Rar50FileFields {
    flags: u64,
    extra_size: Option<std::ops::Range<usize>>,
    unpacked_size: std::ops::Range<usize>,
}

fn rar50_file_fields(header: &[u8]) -> Rar50FileFields {
    let mut at = 0;
    read_rar50_vint(header, &mut at);
    let flags = read_rar50_vint(header, &mut at);
    let extra_size = (flags & 1 != 0).then(|| {
        let start = at;
        read_rar50_vint(header, &mut at);
        start..at
    });
    if flags & 2 != 0 {
        read_rar50_vint(header, &mut at);
    }
    read_rar50_vint(header, &mut at);
    let start = at;
    read_rar50_vint(header, &mut at);
    Rar50FileFields {
        flags,
        extra_size,
        unpacked_size: start..at,
    }
}

/// Rewrites the header of RAR 5 member `index` with `edit`, which gets the
/// header after its size field, and reseals it.
fn edit_rar50_header(path: &Path, index: usize, edit: impl FnOnce(&mut Vec<u8>)) {
    let rars::Archive::Rar50Plus(archive) = rars::ArchiveReader::read_path(path).unwrap() else {
        unreachable!("a RAR 5 archive");
    };
    let offset = archive.files().nth(index).unwrap().block.offset;
    let bytes = fs::read(path).unwrap();
    let mut at = offset + 4;
    let size = read_rar50_vint(&bytes, &mut at) as usize;
    let mut header = bytes[at..at + size].to_vec();
    edit(&mut header);
    let mut sealed = rar50_vint(header.len() as u64);
    sealed.extend_from_slice(&header);
    let crc = crc32(&sealed).to_le_bytes();
    fs::write(
        path,
        [&bytes[..offset], &crc, &sealed, &bytes[at + size..]].concat(),
    )
    .unwrap();
}

/// Raises member `index`'s declared size by `delta`, in either family.
fn raise_declared_size(path: &Path, index: usize, delta: u64) {
    match rars::ArchiveReader::read_path(path).unwrap() {
        rars::Archive::Rar50Plus(_) => edit_rar50_header(path, index, |header| {
            let fields = rar50_file_fields(header);
            let mut at = fields.unpacked_size.start;
            let size = read_rar50_vint(header, &mut at);
            header.splice(fields.unpacked_size, rar50_vint(size + delta));
        }),
        _ => {
            let name = format!("m{index}.txt");
            let mut bytes = fs::read(path).unwrap();
            edit_rar15_40_header(&mut bytes, name.as_bytes(), |header, _| {
                let size = u32::from_le_bytes(header[11..15].try_into().unwrap());
                let size = size + u32::try_from(delta).unwrap();
                header[11..15].copy_from_slice(&size.to_le_bytes());
            });
            fs::write(path, bytes).unwrap();
        }
    }
}

/// Issue #444: a header whose name field starts with a NUL gives its member
/// no name. Extraction leaves that member out, as UnRAR does, and still
/// decodes it, so the solid members after it come out whole. Issue #488:
/// `test` reports it too, and fails as `x` does.
#[test]
fn a_member_with_no_name_is_skipped_and_the_solid_stream_stays_in_step() {
    let dir = scratch("unnamed-member");
    let path = dir.join("solid.rar");
    let (members, _) = salvage_fixture(&path, rars::ArchiveVersion::Rar29, true);
    let mut bytes = fs::read(&path).unwrap();
    // Blank m1's name: its header CRC is repaired, so only the name is odd.
    edit_rar15_40_header(&mut bytes, b"m1.txt", |header, name| header[name] = 0);
    fs::write(&path, &bytes).unwrap();

    let output = rars().arg("test").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let errors = stderr(&output);
    assert!(errors.contains("a member has no name"), "{errors}");
    assert!(errors.contains("1 member(s) with no name"), "{errors}");
    assert_eq!(
        stdout(&output),
        "OK m0.txt\nOK m2.txt\nOK m3.txt\nOK m4.txt\n"
    );

    let out = dir.join("out");
    let output = rars().arg("x").arg(&path).arg(&out).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let errors = stderr(&output);
    assert!(
        errors.contains("warning: skipping a member with no name"),
        "{errors}"
    );
    assert!(
        errors.contains("skipped 1 member(s) with no name"),
        "{errors}"
    );
    let mut written: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    assert_eq!(written, ["m0.txt", "m2.txt", "m3.txt", "m4.txt"]);
    for (name, data) in &members {
        if name != "m1.txt" {
            assert_eq!(&fs::read(out.join(name)).unwrap(), data, "{name}");
        }
    }
}

/// Issue #488: `test` checks the archive comment, and fails on a damaged one,
/// as unrar does. A RAR 5 comment's checksum is checked too. `info` still
/// shows a RAR 5 comment whose checksum is wrong, with a warning.
#[test]
fn test_fails_on_a_damaged_archive_comment() {
    let dir = scratch("damaged-comment");
    let comment = "a comment long enough to be packed, a comment long enough to be packed";
    for version in [rars::ArchiveVersion::Rar29, rars::ArchiveVersion::Rar50] {
        let path = dir.join(format!("{version:?}.rar"));
        let mut builder = rars::Builder::new(version).comment(Some(comment.as_bytes().to_vec()));
        for (name, data) in salvage_members() {
            builder
                .add_bytes(name.into_bytes(), data, None, None)
                .unwrap();
        }
        builder.write_to_path(&path, None).unwrap();
        let output = rars().arg("test").arg(&path).output().unwrap();
        assert!(output.status.success(), "{version:?}: {}", stderr(&output));

        let comment_data = match rars::ArchiveReader::read_path(&path).unwrap() {
            rars::Archive::Rar15To40(archive) => archive
                .new_subs()
                .find(|sub| sub.kind == rar15_40::NewSubKind::ArchiveComment)
                .map(|sub| sub.file.packed_range.clone()),
            rars::Archive::Rar50Plus(archive) => {
                archive.blocks.iter().find_map(|block| match block {
                    rars::rar50::Block::Service(service) if service.name == b"CMT" => {
                        Some(service.block.data_range.clone())
                    }
                    _ => None,
                })
            }
            _ => unreachable!("only RAR 2.9 and 5 are written here"),
        }
        .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[comment_data.start + comment_data.len() / 2] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let output = rars().arg("test").arg(&path).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{version:?}: {}",
            stderr(&output)
        );
        let errors = stderr(&output);
        assert!(
            errors.contains("archive comment: "),
            "{version:?}: {errors}"
        );
        assert!(
            errors.contains("a damaged archive comment in"),
            "{version:?}: {errors}"
        );
        assert_eq!(stdout(&output).lines().count(), 5, "{version:?}");

        if version == rars::ArchiveVersion::Rar50 {
            let output = rars().arg("info").arg(&path).output().unwrap();
            assert!(output.status.success(), "{}", stderr(&output));
            assert!(stdout(&output).contains("a comment long enough"));
            let errors = stderr(&output);
            assert!(errors.contains("archive comment in"), "{errors}");
            assert!(errors.contains("checksum mismatch"), "{errors}");
        }
    }
}

/// Issue #488: a member whose data ends before its declared size, but matches
/// its checksum, passes in every family (#451), and `test` warns about it.
/// The solid members after it read whole, and `x` writes it.
#[test]
fn test_warns_about_a_member_whose_data_ends_before_its_declared_size() {
    let dir = scratch("ends-early");
    for (version, solid) in [
        (rars::ArchiveVersion::Rar20, true),
        (rars::ArchiveVersion::Rar29, true),
        (rars::ArchiveVersion::Rar50, false),
        (rars::ArchiveVersion::Rar50, true),
    ] {
        let case = format!("{version:?} solid={solid}");
        let path = dir.join(format!("{version:?}-{solid}.rar"));
        let members = if version == rars::ArchiveVersion::Rar20 {
            // RAR 2.0 has no end-of-member code. m2's three literals end on
            // a byte boundary, so an oversized header cannot turn padding
            // into a token. m3 and m4 each copy three bytes from distance 3.
            fs::copy(fixture_rar15_40("solid_early_end_rar20.rar"), &path).unwrap();
            [b"a".as_slice(), b"b", b"abc", b"abc", b"abc"]
                .into_iter()
                .enumerate()
                .map(|(index, data)| (format!("m{index}.txt"), data.to_vec()))
                .collect()
        } else {
            salvage_fixture(&path, version, solid).0
        };
        raise_declared_size(&path, 2, 10);
        let len = members[2].1.len();
        for threads in ["1", "4"] {
            let output = rars()
                .args(["test", "--threads", threads])
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success(), "{case}: {}", stderr(&output));
            assert_eq!(
                stdout(&output),
                "OK m0.txt\nOK m1.txt\nOK m2.txt\nOK m3.txt\nOK m4.txt\n",
                "{case}"
            );
            let errors = stderr(&output);
            let warning = format!(
                "'m2.txt': its data ends after {len} of its declared {} bytes",
                len + 10
            );
            assert!(errors.contains(&warning), "{case}: {errors}");
        }

        let out = dir.join(format!("out-{version:?}-{solid}"));
        let output = rars().arg("x").arg(&path).arg(&out).output().unwrap();
        assert!(output.status.success(), "{case}: {}", stderr(&output));
        for (name, data) in &members {
            assert_eq!(&fs::read(out.join(name)).unwrap(), data, "{case}: {name}");
        }
    }
}

/// Issue #488: a RAR 5 redirection that carries a data area has that data
/// checked by `test`, though extraction never writes it.
#[test]
fn test_checks_the_data_area_of_a_redirection() {
    let dir = scratch("redirection-data");
    for solid in [false, true] {
        let path = dir.join(format!("solid-{solid}.rar"));
        salvage_fixture(&path, rars::ArchiveVersion::Rar50, solid);
        // Make m1 a symbolic link to `target`, keeping its data.
        edit_rar50_header(&path, 1, |header| {
            let fields = rar50_file_fields(header);
            let target = b"target";
            let mut record = rar50_vint(5);
            record.extend(rar50_vint(1));
            record.extend(rar50_vint(0));
            record.extend(rar50_vint(target.len() as u64));
            record.extend_from_slice(target);
            let mut sized = rar50_vint(record.len() as u64);
            sized.extend(record);
            let extra = match &fields.extra_size {
                Some(range) => {
                    let mut at = range.start;
                    read_rar50_vint(header, &mut at)
                }
                None => 0,
            };
            let new_extra = rar50_vint(extra + sized.len() as u64);
            header.extend_from_slice(&sized);
            match fields.extra_size {
                Some(range) => {
                    header.splice(range, new_extra);
                }
                None => {
                    let mut at = 0;
                    read_rar50_vint(header, &mut at);
                    let flags_at = at;
                    read_rar50_vint(header, &mut at);
                    header.splice(flags_at..at, rar50_vint(fields.flags | 1));
                    let after_flags = flags_at + rar50_vint(fields.flags | 1).len();
                    header.splice(after_flags..after_flags, new_extra);
                }
            }
        });
        let output = rars().arg("test").arg(&path).output().unwrap();
        assert!(
            output.status.success(),
            "solid={solid}: {}",
            stderr(&output)
        );
        assert!(stdout(&output).contains("OK m1.txt\n"), "solid={solid}");
        assert!(stderr(&output).contains("redirection entry 'm1.txt'"));

        let data = match rars::ArchiveReader::read_path(&path).unwrap() {
            rars::Archive::Rar50Plus(archive) => {
                let file = archive.files().nth(1).unwrap();
                assert!(file.redirection.is_some(), "solid={solid}");
                file.block.data_range.clone()
            }
            _ => unreachable!("a RAR 5 archive"),
        };
        let mut bytes = fs::read(&path).unwrap();
        bytes[data.start + data.len() / 2] ^= 0x55;
        fs::write(&path, &bytes).unwrap();
        let output = rars().arg("test").arg(&path).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "solid={solid}");
        assert!(!stdout(&output).contains("OK m1.txt"), "solid={solid}");
        let errors = stderr(&output);
        assert!(errors.contains("entry 'm1.txt'"), "solid={solid}: {errors}");
        assert!(
            errors.contains("damaged member(s)"),
            "solid={solid}: {errors}"
        );
    }
}

/// Issue #436: in a volume set, a damaged member that sits in one volume is
/// reported and the members around it, split ones included, still read.
#[test]
fn a_damaged_member_in_a_volume_set_is_reported_and_the_others_read() {
    for format in ["rar29", "rar50"] {
        let dir = scratch(&format!("damaged-volume-member-{format}"));
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        let members = salvage_members();
        for (name, data) in &members {
            fs::write(tree.join(name), data).unwrap();
        }
        let set = dir.join("set").join("set.rar");
        fs::create_dir_all(set.parent().unwrap()).unwrap();
        let mut add = rars();
        add.args(["a", "--format", format, "--volume-size", "3k"])
            .arg(&set)
            .current_dir(&tree);
        for (name, _) in &members {
            add.arg(name);
        }
        let output = add.output().unwrap();
        assert!(output.status.success(), "{format}: {}", stderr(&output));
        // The first member that starts and ends in one volume, and where its data is.
        let mut volumes: Vec<_> = fs::read_dir(set.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        volumes.sort();
        let damaged = volumes
            .iter()
            .find_map(|volume| {
                let whole = match rars::ArchiveReader::read_path(volume).unwrap() {
                    rars::Archive::Rar15To40(archive) => archive
                        .files()
                        .find(|file| !file.is_split_before() && !file.is_split_after())
                        .map(|file| (file.name.clone(), file.packed_range.clone())),
                    rars::Archive::Rar50Plus(archive) => archive
                        .files()
                        .find(|file| !file.is_split_before() && !file.is_split_after())
                        .map(|file| (file.name.clone(), file.block.data_range.clone())),
                    _ => unreachable!("only RAR 2.9 and 5 are written here"),
                };
                whole.map(|(name, range)| (volume.clone(), name, range))
            })
            .unwrap_or_else(|| panic!("{format}: no member fits in one volume"));
        let (volume, name, range) = damaged;
        let name = String::from_utf8(name).unwrap();
        let mut bytes = fs::read(&volume).unwrap();
        bytes[range.start + range.len() / 2] ^= 0x55;
        fs::write(&volume, &bytes).unwrap();

        let first = volumes[0].clone();
        let output = rars().arg("test").arg(&first).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{format}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(&format!("entry '{name}'")),
            "{format}: {}",
            stderr(&output)
        );
        let expected: Vec<_> = members
            .iter()
            .filter(|(member, _)| *member != name)
            .map(|(member, _)| format!("OK {member}"))
            .collect();
        assert_eq!(
            stdout(&output).lines().collect::<Vec<_>>(),
            expected,
            "{format}"
        );

        let out = dir.join("out");
        let output = rars().arg("x").arg(&first).arg(&out).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{format}: {}",
            stderr(&output)
        );
        for (member, data) in &members {
            if *member == name {
                assert!(!out.join(member).exists(), "{format}: {member}");
            } else {
                assert_eq!(
                    &fs::read(out.join(member)).unwrap(),
                    data,
                    "{format}: {member}"
                );
            }
        }
    }
}

/// Issue #436: a file cut through a member's data or its file header keeps
/// every member before it, reports the cut and fails at the end.
#[test]
fn an_archive_cut_through_a_member_tests_and_extracts_what_is_before_it() {
    let dir = scratch("cut-member");
    for (version, solid) in [
        (rars::ArchiveVersion::Rar29, true),
        (rars::ArchiveVersion::Rar50, false),
    ] {
        let whole = dir.join("whole.rar");
        let (members, ranges) = salvage_fixture(&whole, version, solid);
        let bytes = fs::read(&whole).unwrap();
        // Nothing sits between one member's data and the next header.
        let header = ranges[1].end;
        for (cut, block) in [
            (ranges[2].start + ranges[2].len() / 2, "member 'm2.txt'"),
            (ranges[2].start - 1, ""),
        ] {
            let case = format!("{version:?} solid={solid} cut at {cut}");
            let path = dir.join(format!("cut-{version:?}-{cut}.rar"));
            fs::write(&path, &bytes[..cut]).unwrap();
            let warning = format!(
                "warning: {}: archive is truncated inside {block}",
                path.display()
            );
            let offset = format!("which starts at offset {header}");

            let output = rars().arg("test").arg(&path).output().unwrap();
            assert_eq!(output.status.code(), Some(1), "{case}");
            let errors = stderr(&output);
            assert!(errors.contains(&warning), "{case}: {errors}");
            assert!(errors.contains(&offset), "{case}: {errors}");
            assert!(errors.contains("is truncated"), "{case}: {errors}");
            assert_eq!(stdout(&output), "OK m0.txt\nOK m1.txt\n", "{case}");

            let out = dir.join(format!("out-{version:?}-{cut}"));
            let output = rars().arg("x").arg(&path).arg(&out).output().unwrap();
            assert_eq!(output.status.code(), Some(1), "{case}");
            assert!(stderr(&output).contains(&warning), "{case}");
            let mut written: Vec<_> = fs::read_dir(&out)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            written.sort();
            assert_eq!(written, ["m0.txt", "m1.txt"], "{case}");
            for (name, data) in &members[..2] {
                assert_eq!(&fs::read(out.join(name)).unwrap(), data, "{case}");
            }

            let output = rars().arg("info").arg(&path).output().unwrap();
            assert!(output.status.success(), "{case}: {}", stderr(&output));
            assert!(stderr(&output).contains(&warning), "{case}");
        }
    }
}

#[test]
fn info_lists_packed_archive_comment() {
    let output = rars()
        .args(["info", "-v"])
        .arg(fixture("COMMENT.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("comment: This is the archive comment."));
}

#[test]
fn info_lists_file_comment() {
    let output = rars()
        .args(["info", "-v"])
        .arg(fixture("FCOMM.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("comment: FCOM"));
}

#[test]
fn info_reports_inline_av_shape_fixture() {
    let output = rars()
        .args(["info", "-v"])
        .arg(fixture("rar140_av/rar140_av_patched.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("authenticity verification: structural"));
    assert!(stdout.contains("status=not-cryptographically-verified"));
}

#[test]
fn info_lists_rar15_40_metadata() {
    let output = rars()
        .args(["info", "-v"])
        .arg(fixture_rar15_40("rar300/with_comment_rar300.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Rar15To40"));
    assert!(stdout.contains("rar15-40 main"));
    assert!(stdout.contains("hello.txt"));
    assert!(stdout.contains("comment: This is the archive comment."));
    assert!(stdout.contains("subblock: ArchiveComment CMT"));
}

#[test]
fn info_displays_services_redirections_and_legacy_comments_in_both_modes() {
    for (path, terse, verbose) in [
        (
            fixture_rar50("with_all_services.rar"),
            vec![
                "Comment: This is the archive comment.",
                "Services: quick-open, recovery",
                "hello.txt",
            ],
            vec!["service: QO", "service: RR", "crc=none", "hello.txt"],
        ),
        (
            fixture_rar50("wild/symlink.rar"),
            vec!["symlink.txt → file.txt", "dirlink → dir"],
            vec!["redirection: type=1", "target=file.txt"],
        ),
        (
            fixture_rar15_40("rar300/with_comment_rar300.rar"),
            vec![
                "Comment: This is the archive comment.",
                "Subblocks: ArchiveComment",
                "hello.txt",
            ],
            vec![
                "comment: This is the archive comment.",
                "subblock: ArchiveComment CMT",
            ],
        ),
        (
            fixture("COMMENT.RAR"),
            vec!["Comment: This is the archive comment."],
            vec!["archive comment extension:", "(packed)"],
        ),
    ] {
        for (is_verbose, expected) in [(false, terse), (true, verbose)] {
            let mut command = rars();
            command.arg("info");
            if is_verbose {
                command.arg("--verbose");
            }
            let output = command.arg(&path).output().unwrap();
            assert!(
                output.status.success(),
                "{}: {}",
                path.display(),
                stderr(&output)
            );
            let text = stdout(&output);
            for expected in expected {
                assert!(text.contains(expected), "missing {expected:?}: {text}");
            }
            if path == fixture_rar50("with_all_services.rar") {
                // The archive CMT is displayed once as a comment, rather than
                // again in the remaining service list.
                assert!(!text.contains("service: CMT"));
                assert!(!text.contains("Services: comment"));
            }
        }
    }
}

#[test]
fn extraction_volume_failures_preserve_existing_files_and_legacy_encoding() {
    let root = scratch("extract-volume-boundaries");
    let output_directory = root.join("out");
    let parts: Vec<_> = [
        "rar300/stored_multivol_rar300.rar",
        "rar300/stored_multivol_rar300.r00",
        "rar300/stored_multivol_rar300.r01",
        "rar300/stored_multivol_rar300.r02",
    ]
    .into_iter()
    .map(fixture_rar15_40)
    .collect();
    let extract = rars()
        .args(["extract", "--legacy-name-encoding", "cp850"])
        .args(&parts)
        .arg(&output_directory)
        .output()
        .unwrap();
    assert!(extract.status.success(), "{}", stderr(&extract));
    let destination = output_directory.join("stored-volume.txt");
    assert_eq!(
        fs::read(&destination).unwrap(),
        expected_rar15_40_stored_volume_payload()
    );
    fs::write(&destination, b"keep existing contents").unwrap();
    let refusal = rars()
        .args(["extract", "--legacy-name-encoding", "cp850"])
        .args(&parts)
        .arg(&output_directory)
        .output()
        .unwrap();
    assert!(!refusal.status.success());
    assert!(stderr(&refusal).contains("failed to extract volume set"));
    assert_eq!(fs::read(&destination).unwrap(), b"keep existing contents");
    let incomplete = rars()
        .arg("extract")
        .args(&parts[..2])
        .arg(root.join("incomplete"))
        .output()
        .unwrap();
    // The member runs on into the volumes left out, so it is skipped, not extracted.
    assert!(!incomplete.status.success());
    let errors = stderr(&incomplete);
    assert!(
        errors.contains("its end is in a missing later volume"),
        "{errors}"
    );
    assert!(errors.contains("incomplete volume set"), "{errors}");
    assert!(!root.join("incomplete/stored-volume.txt").exists());

    let single = rars()
        .args(["extract", "--legacy-name-encoding", "cp850"])
        .arg(fixture("README_store.rar"))
        .arg(root.join("single"))
        .output()
        .unwrap();
    assert!(single.status.success(), "{}", stderr(&single));
    assert!(root.join("single/README").is_file());
}

#[test]
fn info_displays_archive_name_and_creation_time_in_both_modes() {
    let root = scratch("info-archive-metadata");
    let source = root.join("file.txt");
    let archive = root.join("named.rar");
    fs::write(&source, b"metadata payload").unwrap();
    let create = rars()
        .args([
            "add",
            "--format",
            "rar70",
            "--store",
            "--archive-name",
            "original.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "{}", stderr(&create));
    for (arguments, name, time) in [
        (vec!["info"], "Archive name: original.rar", "Created:"),
        (
            vec!["info", "--verbose"],
            "archive name: original.rar",
            "archive creation time:",
        ),
    ] {
        let info = rars().args(arguments).arg(&archive).output().unwrap();
        assert!(info.status.success(), "{}", stderr(&info));
        let text = stdout(&info);
        assert!(text.contains(name), "{text}");
        assert!(text.contains(time), "{text}");
    }
}

#[test]
fn extracts_rar50_volume_fixture_through_the_cli() {
    let root = scratch("extract-rar50-volumes");
    let parts: Vec<_> = (1..=3)
        .map(|part| fixture_rar50(&format!("stored_multivol.part{part}.rar")))
        .collect();
    let output = rars()
        .arg("extract")
        .args(&parts)
        .arg(&root)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let data = fs::read(root.join("random_4k.bin")).unwrap();
    assert_eq!(data.len(), 4096);
    assert_eq!(crc32(&data), 0xb9c5_4415);
    assert!(stdout(&output).contains("x random_4k.bin"));
}

#[test]
fn creates_legacy_volumes_with_explicit_compression_settings() {
    for (format, flags) in [
        ("rar14", vec!["--store"]),
        ("rar14", vec!["--level", "3"]),
        ("rar20", vec!["--level", "3", "--dict-size", "64k"]),
        ("rar29", vec!["--level", "3", "--dict-size", "64k"]),
    ] {
        let root = scratch("legacy-volume-options");
        let source = root.join("payload.bin");
        let archive = root.join("split.rar");
        let payload = deterministic_noise(1024);
        fs::write(&source, &payload).unwrap();
        let create = rars()
            .args(["add", "--format", format, "--volume-size", "256"])
            .args(flags)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();
        assert!(create.status.success(), "{format}: {}", stderr(&create));
        let extract = rars()
            .arg("extract")
            .arg(&archive)
            .arg(root.join("out"))
            .output()
            .unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        assert_eq!(fs::read(root.join("out/payload.bin")).unwrap(), payload);
    }
}

#[test]
fn stored_legacy_volumes_stream_without_the_in_memory_warning() {
    let root = scratch("legacy-stored-volume-stream");
    let source = root.join("sparse.bin");
    let archive = root.join("split.rar");
    // Large enough to have drawn the in-memory warning, sparse so it costs no disk.
    fs::File::create(&source)
        .unwrap()
        .set_len(256 * 1024 * 1024)
        .unwrap();
    let create = rars()
        .args([
            "add",
            "--format",
            "rar40",
            "--store",
            "--volume-size",
            "100m",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "{}", stderr(&create));
    assert!(
        !stderr(&create).contains("in memory"),
        "{}",
        stderr(&create)
    );
    for name in ["split.rar", "split.r00", "split.r01"] {
        assert!(root.join(name).is_file(), "{name} missing");
    }
    assert!(!root.join("split.r02").exists());
    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "{}", stderr(&test));
}

#[test]
fn stored_legacy_volumes_refuse_unnameable_sets_before_writing() {
    let root = scratch("legacy-stored-volume-names");
    let source = root.join("payload.bin");
    let archive = root.join("split.rar");
    fs::write(&source, deterministic_noise(1_000_000)).unwrap();
    let create = rars()
        .args(["add", "--format", "rar40", "--store", "--volume-size", "1k"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(!create.status.success());
    assert!(stderr(&create).contains(".z99"), "{}", stderr(&create));
    let left: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["payload.bin"]);
}

#[test]
fn info_reports_comment_output_limits_for_every_archive_family() {
    for path in [
        fixture("COMMENT.RAR"),
        fixture_rar15_40("rar300/with_comment_rar300.rar"),
        fixture_rar50("with_comment.rar"),
    ] {
        for verbose in [false, true] {
            let mut command = rars();
            command.args(["info", "--max-member-output-bytes", "0"]);
            if verbose {
                command.arg("--verbose");
            }
            let output = command.arg(&path).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(1),
                "{}: {}",
                path.display(),
                stderr(&output)
            );
            let text = stderr(&output);
            assert!(text.contains("failed to decode archive comment"), "{text}");
            assert!(text.contains(&path.display().to_string()), "{text}");
        }
    }
}

#[test]
fn add_refuses_header_encryption_without_password_and_stdout_volume_sets() {
    let root = scratch("add-invalid-destinations");
    let source = root.join("file.txt");
    let archive = root.join("output.rar");
    fs::write(&source, b"small payload").unwrap();
    let no_password = rars()
        .args(["add", "--format", "rar50", "--encrypt-headers"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(no_password.status.code(), Some(2));
    assert!(stderr(&no_password).contains("--encrypt-headers needs a --password"));
    assert!(!archive.exists());
    for destination in ["-", "/dev/stdout"] {
        let output = rars()
            .args([
                "add",
                "--format",
                "rar50",
                "--store",
                "--volume-size",
                "256",
                destination,
            ])
            .arg(&source)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("volume sets cannot be written to stdout"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn info_identifies_self_extracting_archives_and_unpacked_legacy_comments() {
    let sfx = rars()
        .arg("info")
        .arg(fixture("SFXSRC.EXE"))
        .output()
        .unwrap();
    assert!(sfx.status.success(), "{}", stderr(&sfx));
    assert!(stdout(&sfx).contains("(SFX, payload at offset "));
    let root = scratch("info-unpacked-comment");
    let archive = root.join("comment.rar");
    // Current writers pack archive comments. The legacy reader also accepts
    // the original uncompressed extension: length followed by comment bytes.
    let comment = b"unpacked note";
    let mut bytes = b"RE~^".to_vec();
    bytes.extend_from_slice(&(7u16 + 2 + comment.len() as u16).to_le_bytes());
    bytes.push(0x82); // required flag and archive-comment flag, no packed flag
    bytes.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    bytes.extend_from_slice(comment);
    fs::write(&archive, bytes).unwrap();
    let output = rars()
        .args(["info", "--verbose"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("archive comment extension:"));
    assert!(text.contains("comment: unpacked note"));
    assert!(!text.contains("(packed)"));
}

#[test]
fn legacy_stdout_aliases_emit_archives_and_quick_open_refuses_encrypted_headers() {
    let root = scratch("stdout-aliases-and-header-conflict");
    let source = root.join("payload.txt");
    fs::write(&source, b"stdout payload").unwrap();
    for destination in ["-", "/dev/stdout"] {
        let output = rars()
            .args(["add", "--format", "rar14", "--store", destination])
            .arg(&source)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let archive = rars::rar13::Archive::parse(&output.stdout).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, b"payload.txt");
        let saved = root.join("captured.rar");
        fs::write(&saved, &output.stdout).unwrap();
        assert_archive_tests_and_extracts_file(&saved, None, "payload.txt", b"stdout payload");
    }
    let archive = root.join("conflict.rar");
    let conflict = rars()
        .args([
            "add",
            "--format",
            "rar50",
            "--store",
            "--quick-open",
            "--encrypt-headers",
            "--password",
            "pass",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    assert!(stderr(&conflict).contains("quick-open cannot be combined with header encryption"));
    assert!(!archive.exists());
}

#[test]
fn info_keeps_file_comment_services_separate_from_archive_comments() {
    let root = scratch("info-file-comment-services");
    let source = root.join("payload.txt");
    let archive = root.join("services.rar");
    fs::write(&source, b"service payload").unwrap();
    let create = rars()
        .args([
            "add",
            "--format",
            "rar50",
            "--store",
            "--quick-open",
            "--file-comment",
            "member note",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "{}", stderr(&create));
    for verbose in [false, true] {
        let mut command = rars();
        command.arg("info");
        if verbose {
            command.arg("--verbose");
        }
        let output = command.arg(&archive).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        if verbose {
            assert!(text.contains("service: CMT"), "{text}");
            assert!(text.contains("service: QO"), "{text}");
        } else {
            assert!(text.contains("Services:"), "{text}");
            assert!(text.contains("comment"), "{text}");
            assert!(text.contains("quick-open"), "{text}");
        }
        assert!(!text.contains("Comment:"), "{text}");
        assert!(!text.contains("  comment:"), "{text}");
    }
}

#[test]
fn explicit_utf8_legacy_decoding_refuses_invalid_names_without_outputs() {
    let root = scratch("legacy-name-decoding-errors");
    let legacy13 = write_stored_archive(
        &[StoredEntry {
            name: b"\xff.txt",
            data: b"payload",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    let legacy15 = rar15_40::write_stored_archive(
        &[rar15_40::StoredEntry {
            name: b"\xff.txt",
            data: b"payload",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::WriterOptions::new(rars::ArchiveVersion::Rar15, rars::FeatureSet::store_only()),
    )
    .unwrap();
    for (index, bytes) in [legacy13, legacy15].into_iter().enumerate() {
        let archive = root.join(format!("legacy-{index}.rar"));
        fs::write(&archive, bytes).unwrap();
        for verbose in [false, true] {
            let mut command = rars();
            command.args(["info", "--legacy-name-encoding", "utf-8"]);
            if verbose {
                command.arg("--verbose");
            }
            let output = command.arg(&archive).output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr(&output).contains("legacy name is not valid UTF-8"));
        }
        let destination = root.join(format!("out-{index}"));
        let extract = rars()
            .args(["extract", "--legacy-name-encoding", "utf-8"])
            .arg(&archive)
            .arg(&destination)
            .output()
            .unwrap();
        assert_eq!(extract.status.code(), Some(1));
        assert!(stderr(&extract).contains("legacy name is not valid UTF-8"));
        assert!(!destination.exists());
    }
}

#[test]
fn split_legacy_name_decoding_errors_do_not_create_output() {
    let root = scratch("split-legacy-name-decoding-error");
    let payload = [b'x'; 512];
    let parts = rars::rar13::write_stored_volumes(
        StoredEntry {
            name: b"\xff.txt",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
        WriterOptions::default(),
        256,
    )
    .unwrap();
    assert!(parts.len() > 1);
    let paths: Vec<_> = parts
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let path = root.join(format!("invalid.part{:02}.rar", index + 1));
            fs::write(&path, bytes).unwrap();
            path
        })
        .collect();
    let destination = root.join("out");
    let output = rars()
        .args(["extract", "--legacy-name-encoding", "utf-8"])
        .args(&paths)
        .arg(&destination)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("legacy name is not valid UTF-8"),
        "{}",
        stderr(&output)
    );
    assert!(!destination.exists());
}

#[test]
fn unicode_archive_names_override_explicit_legacy_encoding() {
    let root = scratch("unicode-overrides-legacy-encoding");
    let output = rars()
        .args([
            "extract",
            "--legacy-name-encoding",
            "cp850",
            "--password",
            "test",
        ])
        .arg(fixture_rar15_40(
            "encrypted/rar4_unicode_name_encrypted.rar",
        ))
        .arg(&root)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read(root.join("新建文本文档.txt")).unwrap(),
        b"aaaaaaaaaa"
    );
}

#[test]
fn creates_encrypted_rar14_archives_through_the_streaming_cli() {
    for stored in [false, true] {
        let root = scratch("rar14-encrypted-streaming");
        let source = root.join("secret.txt");
        let archive = root.join("encrypted.rar");
        fs::write(&source, b"legacy secret").unwrap();
        let mut command = rars();
        command.args(["add", "--format", "rar14", "--password", "pass"]);
        command.args(["--level", if stored { "0" } else { "3" }]);
        if stored {
            command.arg("--store");
        }
        let output = command.arg(&archive).arg(&source).output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        let parsed = rars::rar13::Archive::parse_path(&archive).unwrap();
        assert!(parsed.entries[0].is_encrypted());
        let missing_password = rars().arg("test").arg(&archive).output().unwrap();
        assert_password_required(&missing_password);
        assert_archive_tests_and_extracts_file(
            &archive,
            Some("pass"),
            "secret.txt",
            b"legacy secret",
        );
    }
}

#[test]
fn legacy_volume_output_creation_failure_has_context_and_leaves_no_archive() {
    let root = scratch("legacy-volume-output-error");
    let source = root.join("payload.txt");
    let archive = root.join("missing/split.rar");
    fs::write(&source, b"volume output error payload").unwrap();
    let output = rars()
        .args([
            "add",
            "--format",
            "rar14",
            "--store",
            "--volume-size",
            "256",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    // Each volume is staged beside the set as it is written.
    let text = stderr(&output);
    assert!(
        text.contains("failed to create temporary archive"),
        "{text}"
    );
    let missing = root.join("missing");
    assert!(text.contains(&missing.display().to_string()), "{text}");
    assert!(!archive.exists());
    assert!(!missing.exists());
}

#[test]
fn modern_volume_staging_failure_preserves_the_output_directory() {
    let root = scratch("modern-volume-staging-error");
    let source = root.join("payload.txt");
    let archive = root.join("missing/split.rar");
    fs::write(&source, b"volume staging error payload").unwrap();
    let output = rars()
        .args([
            "add",
            "--format",
            "rar50",
            "--store",
            "--volume-size",
            "256",
        ])
        .arg("--temp-dir")
        .arg(&root)
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("failed to create temporary archive"),
        "{}",
        stderr(&output)
    );
    assert!(!root.join("missing").exists());
    assert_eq!(fs::read(&source).unwrap(), b"volume staging error payload");
}

#[cfg(unix)]
#[test]
fn streaming_input_permission_failures_preserve_existing_archives() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("streaming-input-permission-errors");
    let source = root.join("private.txt");
    let archive = root.join("existing.rar");
    fs::write(&source, b"private payload").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o0)).unwrap();
    if fs::File::open(&source).is_ok() {
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        return; // privileged runners bypass Unix file permissions
    }
    for (format, volume) in [("rar14", false), ("rar50", false), ("rar14", true)] {
        fs::write(&archive, b"existing archive").unwrap();
        let mut command = rars();
        command.args(["add", "--format", format, "--store"]);
        if volume {
            command.args(["--volume-size", "256"]);
        }
        let output = command.arg(&archive).arg(&source).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(
            stderr(&output).contains("private.txt"),
            "{}",
            stderr(&output)
        );
        assert_eq!(fs::read(&archive).unwrap(), b"existing archive");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    }
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn modern_writer_memory_limit_is_forwarded_for_success_and_refusal() {
    let root = scratch("modern-explicit-memory-limit");
    let source = root.join("payload.txt");
    let archive = root.join("bounded.rar");
    fs::write(&source, b"bounded writer payload").unwrap();
    let stored = rars()
        .args([
            "add",
            "--format",
            "rar50",
            "--store",
            "--memory-limit",
            "64m",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(stored.status.success(), "{}", stderr(&stored));
    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "payload.txt",
        b"bounded writer payload",
    );
    let original = fs::read(&archive).unwrap();
    let refused = rars()
        .args(["add", "--format", "rar50", "--memory-limit", "1"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("memory"), "{}", stderr(&refused));
    assert_eq!(fs::read(&archive).unwrap(), original);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
}

#[test]
fn raising_the_memory_limit_never_changes_the_archive() {
    // A member too large to code whole in the default limit is coded in
    // blocks.
    let root = scratch("raised-memory-limit");
    let source = root.join("payload.bin");
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut payload = Vec::with_capacity(8 << 20);
    while payload.len() < 8 << 20 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        // Calls and short runs of a few symbols, as in machine code.
        let call = (state >> 40) as u32 & 0xffff;
        payload.push(0xe8);
        payload.extend_from_slice(&call.to_le_bytes());
        payload.extend((0..(state & 15)).map(|i| b"\x48\x89\xc7\x00"[(i as usize) & 3]));
    }
    fs::write(&source, &payload).unwrap();
    let archives = [&[][..], &["--memory-limit", "8G"][..]].map(|extra| {
        let archive = root.join(format!("limit{}.rar", extra.len()));
        let output = rars()
            .args([
                "a",
                "--progress",
                "never",
                "--format",
                "rar50",
                "--level",
                "5",
            ])
            .args(extra)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        fs::read(&archive).unwrap()
    });
    assert!(
        archives[0] == archives[1],
        "the raised limit changed the archive"
    );
}

#[test]
fn coding_conflict_diagnostics_refuse_before_replacing_an_archive() {
    let root = scratch("coding-conflict-diagnostics");
    let source = root.join("payload.txt");
    let archive = root.join("existing.rar");
    fs::write(&source, b"payload").unwrap();
    fs::write(&archive, b"existing archive").unwrap();
    for (arguments, message) in [
        (
            vec!["--format", "rar50", "--solid", "--delta-filter", "1"],
            "cannot be used with --solid",
        ),
        (
            vec!["--format", "rar29", "--store", "--auto-filter"],
            "needs something to compress",
        ),
        (
            vec!["--format", "rar29", "--store", "--ppmd"],
            "needs something to compress",
        ),
        (
            vec!["--format", "rar29", "--level", "0", "--delta-filter", "1"],
            "needs something to compress",
        ),
    ] {
        let output = rars()
            .arg("add")
            .args(arguments)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains(message), "{}", stderr(&output));
        assert_eq!(fs::read(&archive).unwrap(), b"existing archive");
    }
}

#[test]
fn duplicate_archive_entries_are_refused_even_when_overwriting_is_allowed() {
    let root = scratch("duplicate-archive-entry-paths");
    let entries = [
        StoredEntry {
            name: b"duplicate.txt",
            data: b"first contents",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
        StoredEntry {
            name: b"duplicate.txt",
            data: b"second contents",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
    ];
    let legacy = write_stored_archive(&entries, WriterOptions::default()).unwrap();
    let modern_entries: Vec<_> = entries
        .iter()
        .map(|entry| {
            rars::rar50::ArchiveEntry::new(
                entry.name.to_vec(),
                rars::EntrySource::from_bytes(entry.data),
            )
        })
        .collect();
    let mut modern = Vec::new();
    rars::rar50::write_streaming_archive_to(
        &modern_entries,
        rars::rar50::WriterOptions::new(
            rars::ArchiveVersion::Rar50,
            rars::FeatureSet::store_only(),
        )
        .with_compression_level(0),
        rars::rar50::ArchiveExtras::default(),
        &rars::WriterResources::new(64 * 1024 * 1024),
        &mut modern,
    )
    .unwrap();
    for (format, bytes) in [("legacy", legacy), ("modern", modern)] {
        let archive = root.join(format!("duplicates-{format}.rar"));
        fs::write(&archive, bytes).unwrap();
        let destination = root.join(format!("out-{format}"));
        let output = rars()
            .args(["extract", "--overwrite", "always"])
            .arg(&archive)
            .arg(&destination)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr(&output).contains("multiple archive entries map to the same output path"),
            "{}",
            stderr(&output)
        );
        // The first copy was verified before its duplicate was refused.
        assert_eq!(
            fs::read(destination.join("duplicate.txt")).unwrap(),
            b"first contents"
        );
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    }
}

#[test]
fn encrypted_volume_sets_require_a_password_before_testing_or_extraction() {
    for parts in [
        (1..=3)
            .map(|i| fixture_rar50(&format!("encrypted_multivol.part{i}.rar")))
            .collect::<Vec<_>>(),
        [
            "encrypted_split/ESPLIT.RAR",
            "encrypted_split/ESPLIT.R00",
            "encrypted_split/ESPLIT.R01",
        ]
        .into_iter()
        .map(fixture)
        .collect(),
    ] {
        let root = scratch("encrypted-volume-missing-password");
        let test = rars()
            .arg("test")
            .args(&parts)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_password_required(&test);
        let destination = root.join("out");
        let extract = rars()
            .arg("extract")
            .args(&parts)
            .arg(&destination)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_password_required(&extract);
        assert!(!destination.exists());
    }
}

#[test]
fn missing_password_file_refuses_add_without_replacing_the_archive() {
    let root = scratch("add-missing-password-file");
    let source = root.join("payload.txt");
    let archive = root.join("existing.rar");
    let missing = root.join("missing-password");
    fs::write(&source, b"payload").unwrap();
    fs::write(&archive, b"existing archive").unwrap();
    let output = rars()
        .args(["add", "--password-file"])
        .arg(&missing)
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains(&missing.display().to_string()));
    assert_eq!(fs::read(&archive).unwrap(), b"existing archive");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
}

#[test]
fn legacy_volume_name_exhaustion_preserves_existing_archives() {
    let root = scratch("legacy-volume-name-exhaustion");
    let source = root.join("p");
    let archive = root.join("archive.rar");
    let second = root.join("archive.r00");
    fs::write(&source, deterministic_noise(200_000)).unwrap();
    fs::write(&archive, b"existing archive").unwrap();
    fs::write(&second, b"existing second volume").unwrap();
    let output = rars()
        .args([
            "add",
            "--format",
            "rar14",
            "--store",
            "--volume-size",
            "150",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("run out after .z99"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fs::read(&archive).unwrap(), b"existing archive");
    assert_eq!(fs::read(&second).unwrap(), b"existing second volume");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
}

#[test]
fn test_verifies_rar15_40_stored_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture_rar15_40("rar300/with_comment_rar300.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK hello.txt"));
}

#[test]
fn test_verifies_rar15_40_header_encrypted_fixture() {
    for fixture in [
        "encrypted/header_rar300_password.rar",
        "encrypted/header_rar420_password.rar",
    ] {
        let output = rars()
            .args(["test", "--password", "password"])
            .arg(fixture_rar15_40(fixture))
            .output()
            .unwrap();
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(stdout(&output).contains("OK hello.txt"));
    }
}

#[test]
fn rejects_wrong_password_for_rar15_40_encrypted_fixture() {
    let output = rars()
        .args(["test", "--password", "wrong-password"])
        .arg(fixture_rar15_40("encrypted/per_file_rar300_password.rar"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to test archive"));
    assert!(stderr.contains("wrong password or corrupt encrypted data"));
}

#[test]
fn extracts_rar15_40_stored_fixture() {
    let out_dir = scratch("extract-rar15-40");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40("rar300/with_comment_rar300.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("hello.txt")).unwrap(),
        b"Hello, RAR 3.x fixture world.\n"
    );
}

#[test]
fn extracts_rar15_40_header_encrypted_fixture() {
    for (case, fixture) in [
        (
            "extract-rar15-40-header-encrypted-rar300",
            "encrypted/header_rar300_password.rar",
        ),
        (
            "extract-rar15-40-header-encrypted-rar420",
            "encrypted/header_rar420_password.rar",
        ),
    ] {
        let out_dir = scratch(case);
        let output = rars()
            .args(["x", "--password", "password"])
            .arg(fixture_rar15_40(fixture))
            .arg(&out_dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert_eq!(
            fs::read(out_dir.join("hello.txt")).unwrap(),
            b"Hello, RAR 3.x fixture world.\n"
        );
    }
}

#[test]
fn extracts_rar15_40_compressed_fixture() {
    let out_dir = scratch("extract-rar15-40-compressed");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40("rar300/compressed_text_rar300.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("text.txt")).unwrap(),
        expected_rar15_40_compressed_text_payload()
    );
}

#[test]
fn test_verifies_encrypted_stored_fixture() {
    let output = rars()
        .args(["test", "--password", "password"])
        .arg(fixture("STOREPWD.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK SECRET.TXT"));
}

#[test]
fn test_reassembles_multivolume_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("MULTIVOL.RAR"))
        .arg(fixture("MULTIVOL.R00"))
        .arg(fixture("MULTIVOL.R01"))
        .arg(fixture("MULTIVOL.R02"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK RANDOM.BIN"));
}

#[test]
fn test_reassembles_compressed_multivolume_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("CMULTIV.RAR"))
        .arg(fixture("CMULTIV.R00"))
        .arg(fixture("CMULTIV.R01"))
        .arg(fixture("CMULTIV.R02"))
        .arg(fixture("CMULTIV.R03"))
        .arg(fixture("CMULTIV.R04"))
        .arg(fixture("CMULTIV.R05"))
        .arg(fixture("CMULTIV.R06"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK CMULTI.TXT"));
}

#[test]
fn test_reassembles_rar15_40_stored_multivolume_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.rar"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r00"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r01"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r02"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK stored-volume.txt"));
}

#[test]
fn extracts_rar15_40_stored_multivolume_fixture() {
    let out_dir = scratch("extract-rar15-40-multivol");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.rar"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r00"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r01"))
        .arg(fixture_rar15_40("rar300/stored_multivol_rar300.r02"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("stored-volume.txt")).unwrap(),
        expected_rar15_40_stored_volume_payload()
    );
}

#[test]
fn extracts_rar15_40_compressed_multivolume_fixture() {
    let out_dir = scratch("extract-rar15-40-compressed-multivol");
    let output = rars()
        .arg("x")
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.rar",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r00",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r01",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r02",
        ))
        .arg(fixture_rar15_40(
            "rar300/compressed_multivol_prng_rar300.r03",
        ))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let data = fs::read(out_dir.join("cvolume.bin")).unwrap();
    assert_eq!(data.len(), 4096);
    assert_eq!(crc32(&data), 0x96de2bef);
}

#[test]
fn test_verifies_compressed_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("README.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK README"));
}

#[test]
fn test_verifies_solid_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("SOLID.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("OK BIG80K.TXT"));
    assert!(stdout.contains("OK HELLO.TXT"));
    assert!(stdout.contains("OK TINY.TXT"));
}

#[test]
fn test_verifies_sfx_prefixed_fixture() {
    let output = rars()
        .arg("test")
        .arg(fixture("SFXSRC.EXE"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK HELLO.TXT"));
}

#[test]
fn extracts_compressed_multivolume_fixture() {
    let out_dir = scratch("extract-compressed-multivolume");
    let output = rars()
        .arg("x")
        .arg(fixture("CMULTIV.RAR"))
        .arg(fixture("CMULTIV.R00"))
        .arg(fixture("CMULTIV.R01"))
        .arg(fixture("CMULTIV.R02"))
        .arg(fixture("CMULTIV.R03"))
        .arg(fixture("CMULTIV.R04"))
        .arg(fixture("CMULTIV.R05"))
        .arg(fixture("CMULTIV.R06"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("CMULTI.TXT")).unwrap(),
        fs::read(fixture("CMULTI.TXT")).unwrap()
    );
}

#[test]
fn extracts_stored_fixture() {
    let out_dir = scratch("extract");
    let output = rars()
        .arg("x")
        .arg(fixture("WITHDIR.RAR"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("SUBDIR").join("INNER.TXT")).unwrap(),
        b"Inside subdir.\r\n"
    );
}

#[test]
fn extracts_encrypted_compressed_fixture() {
    let out_dir = scratch("extract-compressed");
    let output = rars()
        .args(["x", "--password", "password"])
        .arg(fixture("README_password=password.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(fs::read(out_dir.join("README")).unwrap().len(), 1514);
}

#[test]
fn rejects_wrong_password() {
    let output = rars()
        .args(["test", "--password", "wrong-password"])
        .arg(fixture("README_password=password.rar"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to test archive"));
    assert!(stderr.contains("wrong password or corrupt encrypted data"));
}

#[test]
fn rejects_unsafe_output_path() {
    let dir = scratch("unsafe-extract");
    let archive = dir.join("unsafe.rar");
    let out_dir = dir.join("out");
    let bytes = write_stored_archive(
        &[StoredEntry {
            name: b"../evil.txt",
            data: b"unsafe path fixture\n",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    let extract = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(!extract.status.success());
    let stderr = stderr(&extract);
    assert!(stderr.contains("failed to write extracted entry"));
    assert!(stderr.contains("unsafe archive path"));
}

#[test]
fn extracts_non_utf8_output_path_where_native_names_support_bytes() {
    let dir = scratch("non-utf8-extract");
    let archive = dir.join("non-utf8.rar");
    let out_dir = dir.join("out");
    let bytes = write_stored_archive(
        &[StoredEntry {
            name: b"\xff.txt",
            data: b"non utf8 path fixture\n",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    let extract = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();

    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        if !scratch::supports_raw_byte_names(&dir) {
            assert!(!extract.status.success());
            assert!(
                stderr(&extract).contains("failed to write extracted entry"),
                "{}",
                stderr(&extract)
            );
            assert!(!out_dir.join("\u{fffd}.txt").exists());
            return;
        }
        assert!(extract.status.success(), "{}", stderr(&extract));
        assert_eq!(
            fs::read(out_dir.join(OsStr::from_bytes(b"\xff.txt"))).unwrap(),
            b"non utf8 path fixture\n"
        );
    }
    #[cfg(not(unix))]
    assert!(!extract.status.success());
}

#[cfg(unix)]
#[test]
fn rejects_output_path_that_is_existing_symlink() {
    let dir = scratch("symlink-extract");
    let archive = dir.join("symlink.rar");
    let out_dir = dir.join("out");
    let target = dir.join("target.txt");
    fs::create_dir_all(&out_dir).unwrap();
    fs::write(&target, b"do not overwrite\n").unwrap();
    std::os::unix::fs::symlink(&target, out_dir.join("link.txt")).unwrap();
    // Same path on a case insensitive filesystem, so EEXIST is fine here:
    // the entry still extracts onto a symlink.
    match std::os::unix::fs::symlink(&target, out_dir.join("LINK.TXT")) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => panic!("failed to create upper case symlink: {err}"),
    }
    let bytes = write_stored_archive(
        &[StoredEntry {
            name: b"link.txt",
            data: b"symlink path fixture\n",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    let extract = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();

    assert!(!extract.status.success());
    let stderr = stderr(&extract);
    assert!(
        stderr.contains("unsafe archive path crosses symlink")
            || stderr.contains("Too many levels of symbolic links"),
        "{stderr}"
    );
    assert_eq!(fs::read(&target).unwrap(), b"do not overwrite\n");
}

#[cfg(unix)]
#[test]
fn a_refused_member_is_named_in_the_error() {
    let dir = scratch("refused-member-name");
    let archive = dir.join("refused.rar");
    let out_dir = dir.join("out");
    fs::create_dir_all(dir.join("outside")).unwrap();
    fs::create_dir_all(&out_dir).unwrap();
    std::os::unix::fs::symlink("../outside", out_dir.join("sub")).unwrap();
    let bytes = write_stored_archive(
        &[StoredEntry {
            name: b"sub\\file.txt",
            data: b"payload\n",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    let extract = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();

    assert!(!extract.status.success());
    let stderr = stderr(&extract);
    assert!(
        stderr.contains("while extracting entry 'sub\\file.txt': ")
            && stderr.contains("unsafe archive path crosses symlink"),
        "{stderr}"
    );
    assert!(!dir.join("outside/file.txt").exists());
}

#[test]
fn test_reports_directory_entries_and_redirection_warnings() {
    let output = rars()
        .arg("test")
        .arg(fixture_rar50("wild/symlink.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = stdout(&output);
    let stderr = stderr(&output);
    assert!(stdout.contains("OK dir/"), "{stdout}");
    for name in ["symlink.txt", "dirlink"] {
        assert!(
            stderr.contains(&format!("redirection entry '{name}' is not recreated")),
            "{stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn extracts_rar50_symlink_redirection_entries() {
    let dir = scratch("rar50-symlink-redirection");
    let out_dir = dir.join("out");
    let extract = rars()
        .arg("x")
        .arg(fixture_rar50("wild/symlink.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();

    assert!(extract.status.success(), "stderr: {}", stderr(&extract));
    assert_eq!(fs::read(out_dir.join("file.txt")).unwrap(), b"1234\n");
    assert_eq!(
        fs::read_link(out_dir.join("symlink.txt")).unwrap(),
        PathBuf::from("file.txt")
    );
    assert_eq!(
        fs::read_link(out_dir.join("dirlink")).unwrap(),
        PathBuf::from("dir")
    );
    assert!(out_dir.join("dir").is_dir());
}

#[cfg(unix)]
#[test]
fn extracts_rar50_hardlink_redirection_entries() {
    use std::os::unix::fs::MetadataExt;

    let dir = scratch("rar50-hardlink-redirection");
    let out_dir = dir.join("out");
    let extract = rars()
        .arg("x")
        .arg(fixture_rar50("wild/hardlink.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();

    assert!(extract.status.success(), "stderr: {}", stderr(&extract));
    assert_eq!(fs::read(out_dir.join("hardlink.txt")).unwrap(), b"1234\n");
    let original = fs::metadata(out_dir.join("file.txt")).unwrap();
    let linked = fs::metadata(out_dir.join("hardlink.txt")).unwrap();
    assert_eq!(original.dev(), linked.dev());
    assert_eq!(original.ino(), linked.ino());
}

#[cfg(unix)]
#[test]
fn create_and_extract_preserve_mtime_and_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("metadata-roundtrip");
    let source = dir.join("metadata.txt");
    let archive = dir.join("metadata.rar");
    let out_dir = dir.join("out");
    let source_mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_002);
    fs::write(&source, b"metadata roundtrip\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
    fs::File::options()
        .write(true)
        .open(&source)
        .unwrap()
        .set_modified(source_mtime)
        .unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let archive = rars::ArchiveReader::read_path(&archive).unwrap();
    let members: Vec<_> = archive.members().collect();
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].meta.modification_time(),
        Some(rars::Timestamp::from_unix_seconds(1_700_000_002))
    );
    assert_eq!(members[0].meta.file_attr & 0o777, 0o640);

    let extract = rars()
        .arg("x")
        .arg(dir.join("metadata.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(extract.status.success(), "stderr: {}", stderr(&extract));
    let extracted = out_dir.join("metadata.txt");
    assert_eq!(fs::read(&extracted).unwrap(), b"metadata roundtrip\n");
    let extracted_meta = fs::metadata(&extracted).unwrap();
    assert_eq!(extracted_meta.permissions().mode() & 0o777, 0o640);
    assert_eq!(
        extracted_meta
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1_700_000_002
    );
}

#[cfg(unix)]
/// A DOS timestamp is a wall-clock reading with no zone, and every RAR reader
/// resolves it against the extracting machine's local zone. Reading it as UTC
/// instead puts the file an offset away from where every other tool puts it.
///
/// The zone comes from the shipped fixtures rather than the machine, so this
/// asserts a fixed answer wherever it runs. `Asia/Kolkata` is chosen because
/// its +05:30 makes a half-hour error as visible as a whole-hour one.
#[test]
fn extract_reads_dos_timestamps_in_the_local_zone() {
    let dir = scratch("dos-timestamp-zone");
    let archive = dir.join("stamped.rar");
    let tzdir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rars/tests/fixtures/tz");

    let bytes = write_stored_archive(
        &[StoredEntry {
            name: b"stamped.txt",
            data: b"stamped\n",
            file_time: dos_time(2026, 7, 15, 15, 0, 0),
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    // The reading is 15:00. In Kolkata that names 09:30 UTC; read as UTC it
    // would name 15:00 UTC, five and a half hours adrift.
    for (zone, expected) in [
        ("Asia_Kolkata", 1_784_107_800),
        ("Etc_GMT_5", 1_784_145_600),
    ] {
        let out_dir = dir.join(format!("out-{zone}"));
        let extract = rars()
            .env("TZDIR", &tzdir)
            .env("TZ", zone)
            .arg("x")
            .arg(&archive)
            .arg(&out_dir)
            .output()
            .unwrap();
        assert!(extract.status.success(), "stderr: {}", stderr(&extract));
        assert_eq!(
            fs::metadata(out_dir.join("stamped.txt"))
                .unwrap()
                .modified()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expected,
            "zone {zone}"
        );
    }
}

#[test]
fn extract_restores_directory_mtime_after_child_files() {
    let dir = scratch("directory-metadata");
    let archive = dir.join("directory.rar");
    let out_dir = dir.join("out");
    let directory_time = dos_time(2021, 5, 6, 7, 8, 10);
    let file_time = dos_time(2024, 1, 2, 3, 4, 6);
    let bytes = write_stored_archive(
        &[
            StoredEntry {
                name: b"subdir",
                data: b"",
                file_time: directory_time,
                file_attr: 0x10,
                password: None,
                file_comment: None,
            },
            StoredEntry {
                name: b"subdir/child.txt",
                data: b"child data\n",
                file_time,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            },
        ],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    // A DOS timestamp is a wall-clock reading, so what instant it names
    // depends on the zone. Pin the zone or these constants only hold in UTC.
    let extract = rars()
        .env("TZ", "UTC")
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(extract.status.success(), "stderr: {}", stderr(&extract));
    assert_eq!(
        fs::read(out_dir.join("subdir/child.txt")).unwrap(),
        b"child data\n"
    );

    assert_eq!(
        fs::metadata(out_dir.join("subdir"))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1_620_284_890
    );
    assert_eq!(
        fs::metadata(out_dir.join("subdir/child.txt"))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1_704_164_646
    );
}

#[test]
fn rejects_extract_when_final_argument_looks_like_archive() {
    let output = rars()
        .arg("x")
        .arg(fixture("README_store.rar"))
        .arg(fixture("COMMENT.RAR"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("ambiguous extract arguments"));
}

#[test]
fn reports_missing_archive_path_with_context() {
    let dir = scratch("missing-archive");
    let missing = dir.join("missing.rar");

    let output = rars().args(["info", "-v"]).arg(&missing).output().unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to read archive"));
    assert!(stderr.contains("missing.rar"));
}

#[test]
fn reports_missing_input_path_with_context() {
    let dir = scratch("missing-input");
    let archive = dir.join("out.rar");
    let missing = dir.join("missing.txt");

    let output = rars()
        .args(["a", "--format", "rar14"])
        .arg(&archive)
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to stat input"));
    assert!(stderr.contains("missing.txt"));
}

#[test]
fn password_file_and_stdin_password_unlock_encrypted_archives() {
    let dir = scratch("password-file-and-stdin");
    let source = dir.join("secret.txt");
    let archive = dir.join("secret.rar");
    let password_file = dir.join("password.txt");
    fs::write(&source, b"password-file cli payload\n").unwrap();
    fs::write(&password_file, b"pass\n").unwrap();

    let create = rars()
        .args(["a", "--password-file"])
        .arg(&password_file)
        .args(["--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    for flag in ["--password", "--password-file"] {
        let mut command = rars();
        command
            .args(["test", flag, "-"])
            .arg(&archive)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.as_mut().unwrap().write_all(b"pass\n").unwrap();
        let test = child.wait_with_output().unwrap();
        assert!(test.status.success(), "stderr: {}", stderr(&test));
        assert!(stdout(&test).contains("OK secret.txt"));
    }
}

#[test]
fn missing_passwords_fail_without_prompting_when_stdin_is_not_a_terminal() {
    for name in [
        "encrypted/header_rar300_password.rar",
        "encrypted/per_file_rar300_password.rar",
    ] {
        let output = rars()
            .arg("test")
            .arg(fixture_rar15_40(name))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert!(!stderr(&output).contains("password: "));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn stdin_password_read_errors_are_reported_for_both_flags() {
    let dir = scratch("stdin-password-read-error");
    for flag in ["--password", "--password-file"] {
        let output = rars()
            .args(["test", flag, "-"])
            .arg(fixture_rar15_40("encrypted/header_rar300_password.rar"))
            .stdin(Stdio::from(fs::File::open(&dir).unwrap()))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(stderr(&output).contains("error:"));
    }
}

#[cfg(unix)]
#[test]
fn password_prompts_use_real_controlling_terminals() {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/test_cli_tty.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_rars"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn password_options_reject_missing_and_duplicate_sources() {
    let missing_value = rars().args(["test", "--password-file"]).output().unwrap();
    assert!(!missing_value.status.success());
    assert!(stderr(&missing_value).contains("--password-file"));

    let duplicate = rars()
        .args(["test", "--password", "one", "--password", "two"])
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(stderr(&duplicate).contains("cannot be used multiple times"));
}

#[test]
fn prints_usage_without_command() {
    let output = rars().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("Usage:"));
}

#[test]
fn prints_usage_for_help_command() {
    let output = rars().arg("--help").output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    let binary_name = Path::new(env!("CARGO_BIN_EXE_rars"))
        .file_name()
        .unwrap()
        .to_string_lossy();
    assert!(
        stdout.contains(&format!("Usage: {binary_name} [OPTIONS] <COMMAND>")),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("--threads <N>"));
    assert!(stdout.contains("Exit codes:"));
    assert!(stdout.contains("info"));
    assert!(stdout.contains("extract"));
    assert!(stdout.contains("add"));
}

#[test]
fn threads_flag_is_accepted() {
    let output = rars()
        .args(["--threads", "1", "info"])
        .arg(fixture("README_store.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
}

#[test]
fn rejects_unknown_command() {
    let output = rars().arg("wat").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unrecognized subcommand 'wat'"));
}

#[test]
fn rejects_missing_subcommand_arguments() {
    for args in [&["info"][..], &["test"][..], &["x"][..]] {
        let output = rars().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(stderr(&output).contains("Usage:"), "args: {args:?}");
    }
}

#[test]
fn rejects_non_rar_input_to_info() {
    let dir = scratch("non-rar-info");
    let input = dir.join("plain.txt");
    fs::write(&input, b"not a rar archive").unwrap();

    let output = rars().args(["info", "-v"]).arg(&input).output().unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to identify archive"));
    assert!(stderr.contains("unsupported archive signature"));
}

#[test]
fn rejects_bad_add_invocation_shape() {
    let output = rars().args(["a", "--format", "rar5"]).output().unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("invalid value 'rar5'"));
    assert!(stderr.contains("--format"));
}

#[test]
fn rejects_missing_add_option_values() {
    for args in [
        &["a", "--format", "rar14", "--comment"][..],
        &["a", "--format", "rar14", "--file-comment"][..],
        &["a", "--format", "rar50", "--recovery-percent"][..],
        &["a", "--format", "rar14", "--volume-size"][..],
        &["a", "--password"][..],
        &["a", "--password-file"][..],
    ] {
        let output = rars().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(
            stderr(&output).contains("a value is required for"),
            "args: {args:?}"
        );
    }
}

#[test]
fn rejects_invalid_volume_size() {
    let dir = scratch("invalid-volume-size");
    let source = dir.join("hello.txt");
    let archive = dir.join("bad.rar");
    fs::write(&source, b"hello").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--volume-size", "nope"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("invalid size value"));
}

#[test]
fn subcommands_print_help_and_version() {
    let version = rars().arg("--version").output().unwrap();
    assert!(version.status.success(), "stderr: {}", stderr(&version));
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));

    for args in [
        &["info", "--help"][..],
        &["test", "--help"][..],
        &["x", "--help"][..],
        &["repair", "--help"][..],
        &["a", "--help"][..],
    ] {
        let help = rars().args(args).output().unwrap();
        assert!(
            help.status.success(),
            "args: {args:?}, stderr: {}",
            stderr(&help)
        );
        assert!(stdout(&help).contains("Usage:"), "args: {args:?}");
    }
}

#[test]
fn add_accepts_equals_flags_and_double_dash_input() {
    let dir = scratch("add-equals-flags");
    let source = dir.join("--literal-name.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"equals flag cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--format=rar50"])
        .arg(&archive)
        .arg("--")
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "--literal-name.txt",
        b"equals flag cli payload\n",
    );
}

#[cfg(unix)]
#[test]
fn add_progress_renders_on_real_terminals() {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/test_cli_tty.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_rars"))
        .arg("progress")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn add_progress_modes_are_plain_when_stderr_is_captured() {
    let dir = scratch("add-progress-modes");
    let source = dir.join("payload.txt");
    fs::write(&source, b"progress reporting payload payload payload\n").unwrap();

    let auto_archive = dir.join("auto.rar");
    let auto = rars()
        .args(["--progress", "auto", "add"])
        .arg(&auto_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(auto.status.success(), "stderr: {}", stderr(&auto));
    let auto_stderr = stderr(&auto);
    assert!(auto_stderr.contains("progress: Scanning inputs"));
    assert!(auto_stderr.contains("progress: Preparing compression"));
    assert!(auto_stderr.contains("progress: Compressing archive"));
    assert!(auto_stderr.contains("progress: 100%"));
    assert!(auto_stderr.contains("progress: Writing archive"));
    assert!(!auto_stderr.contains('\x1b'));
    assert!(!auto_stderr.contains('\r'));
    assert!(!auto_stderr.contains('\x08'));

    let quiet_archive = dir.join("quiet.rar");
    let quiet = rars()
        .args(["--progress", "never", "add"])
        .arg(&quiet_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(quiet.status.success(), "stderr: {}", stderr(&quiet));
    assert!(!stderr(&quiet).contains("progress:"));

    let always_archive = dir.join("always.rar");
    let always = rars()
        .args(["--progress", "always", "add"])
        .arg(&always_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(always.status.success(), "stderr: {}", stderr(&always));
    let always_stderr = stderr(&always);
    assert!(always_stderr.contains("progress: Scanning inputs"));
    assert!(!always_stderr.contains('\x1b'));
    assert!(!always_stderr.contains('\r'));
}

#[test]
fn rar50_add_uses_rar5_host_os_values() {
    let dir = scratch("rar50-host-os");
    let source = dir.join("foo.txt");
    let archive = dir.join("foo.rar");
    fs::write(&source, b"rar50 host os compatibility\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let parsed = rars::rar50::Archive::parse_path(&archive).unwrap();
    let file = parsed.files().next().unwrap();
    assert_eq!(file.host_os, u64::from(cfg!(unix)));

    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "foo.txt",
        b"rar50 host os compatibility\n",
    );
}

#[test]
fn rejects_multivolume_with_multiple_inputs() {
    let dir = scratch("multivolume-multiple-inputs");
    let first = dir.join("first.txt");
    let second = dir.join("second.txt");
    let archive = dir.join("bad.rar");
    fs::write(&first, b"first").unwrap();
    fs::write(&second, b"second").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--volume-size", "10"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("RAR 1.3 volume sets hold one regular input file"));
}

#[test]
fn creates_rar50_header_encrypted_recovery_volumes() {
    let dir = scratch("rar50-header-encrypted-recovery-volume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(12000)).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--encrypt-headers",
            "--recovery-percent",
            "8",
            "--volume-size",
            "4k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let missing = rars().arg("test").args(&parts).output().unwrap();
    assert_password_required(&missing);

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&parts)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_stored_archive_that_can_be_tested() {
    let dir = scratch("create");
    let source = dir.join("hello.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"hello from cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    assert_archive_tests_and_extracts_file(&archive, None, "hello.txt", b"hello from cli\n");
}

#[test]
fn archive_output_to_stdout_keeps_status_on_stderr() {
    let dir = scratch("archive-stdout");
    let source = dir.join("hello.txt");
    fs::write(&source, b"stdout archive payload\n").unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--store", "-"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(output.stdout.starts_with(b"Rar!\x1a\x07\x01\0"));
    assert!(!output
        .stdout
        .windows(b"created".len())
        .any(|window| window == b"created"));
    assert!(stderr(&output).contains("created -"));
}

#[test]
fn extraction_refuses_overwrite_unless_explicitly_allowed() {
    let dir = scratch("extract-overwrite-policy");
    let source = dir.join("hello.txt");
    let archive = dir.join("created.rar");
    let out_dir = dir.join("out");
    fs::write(&source, b"overwrite policy payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let first = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(first.status.success(), "stderr: {}", stderr(&first));

    let destination = out_dir.join("hello.txt");
    let existing = b"existing output must survive\n";
    fs::write(&destination, existing).unwrap();
    let native_error = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .unwrap_err();
    assert_eq!(native_error.kind(), io::ErrorKind::AlreadyExists);

    let second = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(1));
    let diagnostic = stderr(&second);
    assert!(
        diagnostic.contains("failed to write extracted entry")
            && diagnostic.contains("I/O error:")
            && diagnostic.contains(&out_dir.display().to_string()),
        "stderr: {diagnostic}"
    );
    assert_eq!(fs::read(&destination).unwrap(), existing);

    let overwrite = rars()
        .args(["x", "--overwrite=always"])
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(overwrite.status.success(), "stderr: {}", stderr(&overwrite));
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"overwrite policy payload\n"
    );
}

#[test]
fn extraction_rejects_destination_that_is_not_a_directory() {
    let dir = scratch("extract-destination-file");
    let source = dir.join("hello.txt");
    let archive = dir.join("created.rar");
    let dest = dir.join("not-a-directory");
    fs::write(&source, b"payload\n").unwrap();
    fs::write(&dest, b"not a directory\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let extract = rars().arg("x").arg(&archive).arg(&dest).output().unwrap();
    assert!(!extract.status.success());
    assert!(stderr(&extract).contains("extract destination"));
    assert!(stderr(&extract).contains("is not a directory"));
}

#[cfg(unix)]
#[test]
fn add_rejects_symlink_input() {
    let dir = scratch("add-symlink-input");
    let target = dir.join("target.txt");
    let link = dir.join("link.txt");
    let archive = dir.join("created.rar");
    fs::write(&target, b"target\n").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&link)
        .output()
        .unwrap();
    assert!(!create.status.success());
    assert!(stderr(&create).contains("is a symlink; refusing to follow it"));
}

#[test]
fn add_rejects_directory_archive_path_before_scanning_inputs() {
    let dir = scratch("add-directory-archive-path");
    let source = dir.join("source.txt");
    fs::write(&source, b"source\n").unwrap();

    let existing = dir.join("existing-directory");
    fs::create_dir(&existing).unwrap();
    let missing_with_separator = format!(
        "{}{}",
        dir.join("missing-directory").display(),
        std::path::MAIN_SEPARATOR
    );

    for archive in [existing.display().to_string(), missing_with_separator] {
        let create = rars()
            .args(["a", "--format", "rar50", "--store"])
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();

        assert!(!create.status.success());
        let stderr = stderr(&create);
        assert!(
            stderr.contains("is a directory; provide an archive filename"),
            "stderr: {stderr}"
        );
        assert!(!stderr.contains("Scanning inputs"), "stderr: {stderr}");
    }
}

#[test]
fn add_recurses_directory_inputs_and_preserves_relative_paths() {
    let dir = scratch("add-recursive-relative");
    let tree = dir.join("tree");
    fs::create_dir_all(tree.join("sub")).unwrap();
    fs::write(tree.join("root.txt"), b"root\n").unwrap();
    fs::write(tree.join("sub").join("leaf.txt"), b"leaf\n").unwrap();
    let archive = dir.join("created.rar");

    let create = rars()
        .current_dir(&dir)
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg("tree")
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    assert_archive_tests_and_extracts_files(
        &archive,
        None,
        &[
            ("tree/root.txt", b"root\n"),
            ("tree/sub/leaf.txt", b"leaf\n"),
        ],
    );
}

#[test]
fn add_base_dir_stores_relative_names_and_writes_archive_in_current_directory() {
    let root = scratch("base-dir-relative-names");
    let tree = root.join("src/dir");
    fs::create_dir_all(tree.join("sub")).unwrap();
    fs::write(tree.join("a.txt"), b"first\n").unwrap();
    fs::write(tree.join("sub/b.txt"), b"second\n").unwrap();

    for format in ["rar50", "rar29"] {
        for (base_args, input, prefix) in [
            (&["-C", "src"][..], "dir", "dir"),
            (&[][..], "src/dir", "src/dir"),
        ] {
            let create = rars()
                .current_dir(&root)
                .args(["a", "--format", format])
                .args(base_args)
                .args(["out.rar", input])
                .output()
                .unwrap();
            assert!(create.status.success(), "{format}: {}", stderr(&create));
            assert!(!root.join("src/out.rar").exists());
            let path = root.join("out.rar");
            let archive = rars::ArchiveReader::read_path(&path).unwrap();
            let names: Vec<_> = archive
                .members()
                .map(|member| {
                    String::from_utf8(member.meta.name)
                        .unwrap()
                        .replace('\\', "/")
                })
                .collect();
            assert_eq!(
                names,
                [
                    prefix.to_owned(),
                    format!("{prefix}/a.txt"),
                    format!("{prefix}/sub"),
                    format!("{prefix}/sub/b.txt"),
                ],
                "{format}"
            );
            assert_eq!(
                archive.read_member_at(1, None).unwrap().unwrap(),
                b"first\n",
                "{format}"
            );
            assert_eq!(
                archive.read_member_at(3, None).unwrap().unwrap(),
                b"second\n",
                "{format}"
            );
            fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn add_base_dir_rejects_absolute_and_parent_inputs() {
    let root = scratch("base-dir-unsafe-input");
    fs::create_dir(root.join("src")).unwrap();
    let file = root.join("file.txt");
    fs::write(&file, b"payload").unwrap();

    for (input, error) in [
        (
            file.as_path(),
            "inputs must be relative when --base-dir is given",
        ),
        (Path::new("../file.txt"), "unsafe input archive path"),
    ] {
        let create = rars()
            .current_dir(&root)
            .args(["a", "-C", "src", "out.rar"])
            .arg(input)
            .output()
            .unwrap();
        assert!(!create.status.success());
        assert!(stderr(&create).contains(error), "{}", stderr(&create));
        assert!(!root.join("out.rar").exists());
    }
}

#[test]
fn add_base_dir_requires_an_existing_directory() {
    let root = scratch("base-dir-invalid-base");
    fs::write(root.join("regular-file"), b"payload").unwrap();

    for (base, error) in [
        ("missing", "failed to stat base directory 'missing'"),
        (
            "regular-file",
            "base path 'regular-file' is not a directory",
        ),
    ] {
        let create = rars()
            .current_dir(&root)
            .args(["a", "-C", base, "out.rar", "file.txt"])
            .output()
            .unwrap();
        assert!(!create.status.success());
        assert!(stderr(&create).contains(error), "{}", stderr(&create));
        assert!(!root.join("out.rar").exists());
    }
}

#[cfg(unix)]
#[test]
fn add_base_dir_rejects_symlink_inputs() {
    let root = scratch("base-dir-symlink-input");
    let source = root.join("src");
    fs::create_dir(&source).unwrap();
    fs::write(root.join("target"), b"payload").unwrap();
    std::os::unix::fs::symlink("../target", source.join("link")).unwrap();

    let create = rars()
        .current_dir(&root)
        .args(["a", "-C", "src", "out.rar", "link"])
        .output()
        .unwrap();
    assert!(!create.status.success());
    assert!(stderr(&create).contains("is a symlink; refusing to follow it"));
    assert!(!root.join("out.rar").exists());
}

#[test]
fn add_base_dir_stores_relative_names_in_volume_sets() {
    let root = scratch("base-dir-volumes");
    let source = root.join("src");
    fs::create_dir_all(source.join("dir")).unwrap();
    let payload = deterministic_noise(1500);
    fs::write(source.join("dir/file.txt"), &payload).unwrap();

    for (format, first, second) in [
        ("rar50", "rar50.part01.rar", "rar50.part02.rar"),
        ("rar29", "rar29.rar", "rar29.r00"),
    ] {
        let create = rars()
            .current_dir(&root)
            .args(["a", "--format", format, "--store", "--volume-size", "1k"])
            .arg("--base-dir")
            .arg(&source)
            .arg(format!("{format}.rar"))
            .arg("dir/file.txt")
            .output()
            .unwrap();
        assert!(create.status.success(), "{format}: {}", stderr(&create));
        let volumes =
            [first, second].map(|name| rars::ArchiveReader::read_path(root.join(name)).unwrap());
        let members = rars::volume_members(&volumes).unwrap();
        assert_eq!(members.len(), 1, "{format}");
        let name = String::from_utf8_lossy(&members[0].meta.name).replace('\\', "/");
        assert_eq!(name, "dir/file.txt", "{format}");
        assert_eq!(
            rars::read_volume_member_at(&volumes, 0, None)
                .unwrap()
                .unwrap(),
            payload,
            "{format}"
        );
    }
}

#[test]
fn add_preserves_empty_directories_across_archive_generations() {
    let dir = scratch("add-empty-directories");
    for with_file in [false, true] {
        let tree = dir.join(if with_file { "mixed" } else { "empty" });
        fs::create_dir_all(tree.join("nested/empty-child")).unwrap();
        fs::create_dir(tree.join("sibling")).unwrap();
        if with_file {
            fs::write(tree.join("nested/leaf.txt"), b"leaf").unwrap();
        }
        for format in [
            "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
        ] {
            for stored in [false, true] {
                let name = format!("{format}-{with_file}-{stored}");
                let archive = dir.join(format!("{name}.rar"));
                let out = dir.join(format!("{name}-out"));
                let mut add = rars();
                add.args(["a", "--format", format]);
                if stored {
                    add.arg("--store");
                }
                let result = add.arg(&archive).arg(&tree).output().unwrap();
                assert!(result.status.success(), "{name}: {}", stderr(&result));
                let test = rars().arg("test").arg(&archive).output().unwrap();
                assert!(test.status.success(), "{name}: {}", stderr(&test));
                let extract = rars().arg("x").arg(&archive).arg(&out).output().unwrap();
                assert!(extract.status.success(), "{name}: {}", stderr(&extract));
                let extracted = out.join(tree.file_name().unwrap());
                for path in ["", "nested", "nested/empty-child", "sibling"] {
                    assert!(
                        extracted.join(path).is_dir(),
                        "{name}: missing directory {path}"
                    );
                }
                assert_eq!(
                    fs::read_dir(extracted.join("nested/empty-child"))
                        .unwrap()
                        .count(),
                    0
                );
                if with_file {
                    assert_eq!(
                        fs::read(extracted.join("nested/leaf.txt")).unwrap(),
                        b"leaf"
                    );
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn add_preserves_directory_metadata_across_archive_generations() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("add-directory-metadata");
    let input = dir.join("tree");
    fs::create_dir_all(input.join("empty")).unwrap();
    fs::write(input.join("child"), b"payload").unwrap();
    let timestamp = UNIX_EPOCH + Duration::from_secs(1_700_000_002);
    for path in [&input, &input.join("empty")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o750)).unwrap();
        fs::File::open(path)
            .unwrap()
            .set_modified(timestamp)
            .unwrap();
    }
    for format in [
        "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
    ] {
        let archive = dir.join(format!("{format}.rar"));
        let out = dir.join(format!("{format}-out"));
        let add = rars()
            .args(["a", "--store", "--format", format])
            .arg(&archive)
            .arg(&input)
            .output()
            .unwrap();
        assert!(add.status.success(), "{format}: {}", stderr(&add));
        let extract = rars().arg("x").arg(&archive).arg(&out).output().unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        for path in ["tree", "tree/empty"] {
            let metadata = fs::metadata(out.join(path)).unwrap();
            assert_eq!(metadata.modified().unwrap(), timestamp, "{format} {path}");
            // RAR1.x directory headers carry DOS attributes, which have no Unix mode.
            if !["rar14", "rar15"].contains(&format) {
                assert_eq!(
                    metadata.permissions().mode() & 0o777,
                    0o750,
                    "{format} {path}"
                );
            }
        }
    }
}

#[test]
fn modern_volumes_preserve_empty_directories_alongside_split_files() {
    let dir = scratch("modern-volume-directories");
    let tree = dir.join("tree");
    fs::create_dir_all(tree.join("empty/nested")).unwrap();
    let payload = deterministic_noise(4096);
    fs::write(tree.join("payload"), &payload).unwrap();
    for format in ["rar50", "rar70"] {
        let archive = dir.join(format!("tree-{format}.rar"));
        let add = rars()
            .args(["a", "--store", "--volume-size", "1k", "--format", format])
            .arg(&archive)
            .arg(&tree)
            .output()
            .unwrap();
        assert!(add.status.success(), "{format}: {}", stderr(&add));
        let first = dir.join(format!("tree-{format}.part01.rar"));
        assert!(dir.join(format!("tree-{format}.part02.rar")).is_file());
        let out = dir.join(format!("{format}-out"));
        let extract = rars().arg("x").arg(&first).arg(&out).output().unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        assert!(out.join("tree/empty/nested").is_dir());
        assert_eq!(fs::read(out.join("tree/payload")).unwrap(), payload);
    }
}

#[test]
fn rar13_volumes_reject_directory_inputs_before_writing_any_members() {
    let dir = scratch("legacy-volume-directory");
    let input = dir.join("tree");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("one"), b"first").unwrap();
    fs::write(input.join("two"), b"second").unwrap();
    let archive = dir.join("rar14.rar");
    let add = rars()
        .args(["a", "--store", "--volume-size", "1k", "--format", "rar14"])
        .arg(&archive)
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        !add.status.success(),
        "rar14 must reject a tree rather than discard its members"
    );
    assert!(
        stderr(&add).contains("one regular input file"),
        "{}",
        stderr(&add)
    );
    assert!(!archive.exists());
}

#[test]
fn legacy_volumes_keep_every_member_of_a_directory_input() {
    let dir = scratch("legacy-volume-tree");
    let input = dir.join("tree");
    fs::create_dir_all(input.join("empty")).unwrap();
    let payload = deterministic_noise(4096);
    fs::write(input.join("one"), &payload).unwrap();
    fs::write(input.join("two"), b"second").unwrap();
    for format in ["rar15", "rar20", "rar29", "rar30", "rar40"] {
        let archive = dir.join(format!("{format}.rar"));
        let add = rars()
            .args(["a", "--store", "--volume-size", "1k", "--format", format])
            .arg(&archive)
            .arg(&input)
            .output()
            .unwrap();
        assert!(add.status.success(), "{format}: {}", stderr(&add));
        let out = dir.join(format!("{format}-out"));
        let extract = rars().arg("x").arg(&archive).arg(&out).output().unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        assert!(out.join("tree/empty").is_dir(), "{format}");
        assert_eq!(fs::read(out.join("tree/one")).unwrap(), payload, "{format}");
        assert_eq!(
            fs::read(out.join("tree/two")).unwrap(),
            b"second",
            "{format}"
        );
    }
}

/// Writes a tree of files of mixed sizes as a volume set and returns the
/// volumes in order, with each file's contents by name.
fn partial_set_fixture(root: &Path, format: &str) -> (Vec<PathBuf>, Vec<(String, Vec<u8>)>) {
    let tree = root.join("tree");
    fs::create_dir_all(&tree).unwrap();
    let mut files = Vec::new();
    for (index, len) in [100, 2_500, 60, 700, 30, 3_000, 200, 900, 50]
        .into_iter()
        .enumerate()
    {
        let name = format!("f{index}");
        let data = deterministic_noise(len + index);
        fs::write(tree.join(&name), &data).unwrap();
        files.push((name, data));
    }
    let archive = root.join("set.rar");
    let add = rars()
        .args(["a", "--store", "--volume-size", "1k", "--format", format])
        .arg(&archive)
        .arg(&tree)
        .output()
        .unwrap();
    assert!(add.status.success(), "{format}: {}", stderr(&add));
    let mut volumes: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .collect();
    // set.rar, set.r00, ... and set.part01.rar, ... both sort by name once
    // the old-style first volume goes first.
    volumes.sort_by_key(|path| {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        (name != "set.rar", name)
    });
    assert!(volumes.len() >= 5, "{format}: {volumes:?}");
    (volumes, files)
}

/// The volumes holding part of each member, by the member's file name.
fn member_volumes(volumes: &[PathBuf]) -> Vec<(String, Vec<usize>)> {
    let mut placement: Vec<(String, Vec<usize>)> = Vec::new();
    for (index, path) in volumes.iter().enumerate() {
        let archive = rars::ArchiveReader::read_path(path).unwrap();
        for member in archive.members() {
            let name = String::from_utf8_lossy(&member.meta.name).into_owned();
            match placement.iter_mut().find(|(known, _)| *known == name) {
                Some((_, held)) => held.push(index),
                None => placement.push((name, vec![index])),
            }
        }
    }
    placement
}

#[test]
fn partial_volume_sets_test_and_extract_the_whole_members() {
    for format in ["rar15", "rar29", "rar50"] {
        let source = scratch("partial-set-source");
        let (volumes, files) = partial_set_fixture(&source, format);
        let placement = member_volumes(&volumes);
        let count = volumes.len();
        for missing in [0, count / 2, count - 1] {
            let case = format!("{format}, volume {missing} of {count} missing");
            let root = scratch("partial-set");
            let mut present = Vec::new();
            for (index, volume) in volumes.iter().enumerate() {
                if index != missing {
                    let copy = root.join(volume.file_name().unwrap());
                    fs::copy(volume, &copy).unwrap();
                    present.push(copy);
                }
            }
            // A member is whole when no part of it is in the missing volume
            // and it does not run from one side of it to the other.
            let whole = |held: &[usize]| {
                held.iter().all(|&index| index < missing)
                    || held.iter().all(|&index| index > missing)
            };
            let named = |predicate: &dyn Fn(&[usize]) -> bool| -> Vec<String> {
                placement
                    .iter()
                    .filter(|(_, held)| predicate(held))
                    .map(|(name, _)| name.clone())
                    .collect()
            };
            let mut expected_ok = named(&|held| whole(held));
            let expected_split =
                named(&|held| !whole(held) && held.iter().any(|&index| index != missing));
            assert!(!expected_split.is_empty(), "{case}: nothing split");

            let test = rars().arg("test").arg(&present[0]).output().unwrap();
            assert!(!test.status.success(), "{case}: {}", stdout(&test));
            let mut tested: Vec<String> = stdout(&test)
                .lines()
                .filter_map(|line| line.strip_prefix("OK "))
                .map(|name| name.trim_end_matches('/').to_owned())
                .collect();
            tested.sort();
            expected_ok.sort();
            assert_eq!(tested, expected_ok, "{case}: {}", stderr(&test));
            let errors = stderr(&test);
            for name in &expected_split {
                assert!(
                    errors.contains(&format!("skipped split member '{name}'")),
                    "{case}: {name}: {errors}"
                );
            }
            assert!(errors.contains("incomplete volume set"), "{case}: {errors}");
            if missing != 0 && missing != count - 1 {
                let gap = root.join(volumes[missing].file_name().unwrap());
                assert!(
                    errors.contains(&format!("volume '{}' is missing", gap.display())),
                    "{case}: {errors}"
                );
            }

            let out = root.join("out");
            let extract = rars().arg("x").arg(&present[0]).arg(&out).output().unwrap();
            assert!(!extract.status.success(), "{case}: {}", stdout(&extract));
            for (name, data) in &files {
                let member = placement
                    .iter()
                    .find(|(member, _)| member.ends_with(name.as_str()))
                    .unwrap();
                let path = out.join("tree").join(name);
                if whole(&member.1) {
                    assert_eq!(&fs::read(&path).unwrap(), data, "{case}: {name}");
                } else {
                    assert!(!path.exists(), "{case}: {name}");
                }
            }
        }
    }
}

#[test]
fn a_gap_in_old_style_volume_names_is_reported_as_the_volumes_missing() {
    let source = scratch("partial-set-gap-source");
    let (volumes, _) = partial_set_fixture(&source, "rar15");
    let root = scratch("partial-set-gap");
    // set.r00 and set.r03 survive; set.r01 and set.r02 between them do not.
    for name in ["set.r00", "set.r03"] {
        assert!(volumes.contains(&source.join(name)), "{volumes:?}");
        fs::copy(source.join(name), root.join(name)).unwrap();
    }
    let test = rars()
        .arg("test")
        .arg(root.join("set.r03"))
        .output()
        .unwrap();
    assert!(!test.status.success(), "{}", stdout(&test));
    let errors = stderr(&test);
    assert!(
        errors.contains(&format!(
            "volumes '{}' to '{}' are missing",
            root.join("set.r01").display(),
            root.join("set.r02").display()
        )),
        "{errors}"
    );
    assert!(!errors.contains("missing its first part"), "{errors}");
    assert!(
        errors.contains("incomplete volume set: 1 gap(s) in the volume names"),
        "{errors}"
    );
}

#[test]
fn a_gap_that_no_member_crosses_only_warns() {
    for format in ["rar15", "rar29", "rar50"] {
        let root = scratch("partial-set-clean-gap");
        let set = root.join("set");
        fs::create_dir_all(&set).unwrap();
        // Two one-member archives written as volumes, named as the first and
        // third volumes of one set: the second is missing, and nothing spans it.
        let names = if format == "rar50" {
            ["set.part1.rar", "set.part3.rar"]
        } else {
            ["set.rar", "set.r01"]
        };
        for (name, member) in names.into_iter().zip(["one.txt", "two.txt"]) {
            let source = root.join(member);
            fs::write(&source, member).unwrap();
            let written = root.join(format!("written-{member}"));
            fs::create_dir_all(&written).unwrap();
            let add = rars()
                .args(["a", "--store", "--volume-size", "1k", "--format", format])
                .arg(written.join("volume.rar"))
                .arg(&source)
                .output()
                .unwrap();
            assert!(add.status.success(), "{format}: {}", stderr(&add));
            let mut volumes: Vec<_> = fs::read_dir(&written)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(volumes.len(), 1, "{format}: {volumes:?}");
            fs::copy(volumes.pop().unwrap(), set.join(name)).unwrap();
        }
        let missing = set.join(if format == "rar50" {
            "set.part2.rar"
        } else {
            "set.r00"
        });

        let test = rars().arg("test").arg(set.join(names[0])).output().unwrap();
        assert!(test.status.success(), "{format}: {}", stderr(&test));
        assert!(stdout(&test).contains("OK one.txt"), "{format}");
        assert!(stdout(&test).contains("OK two.txt"), "{format}");
        assert!(
            stderr(&test).contains(&format!("volume '{}' is missing", missing.display())),
            "{format}: {}",
            stderr(&test)
        );

        let out = root.join("out");
        let extract = rars()
            .arg("x")
            .arg(set.join(names[0]))
            .arg(&out)
            .output()
            .unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        assert_eq!(fs::read(out.join("one.txt")).unwrap(), b"one.txt");
        assert_eq!(fs::read(out.join("two.txt")).unwrap(), b"two.txt");
    }
}

#[test]
fn add_rejects_duplicate_archive_names() {
    let dir = scratch("add-duplicate-names");
    let source = dir.join("same.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"same\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .arg(&source)
        .output()
        .unwrap();
    assert!(!create.status.success());
    assert!(stderr(&create).contains("multiple input entries map to archive name"));
}

#[test]
fn info_and_test_escape_control_characters_in_archive_names() {
    let dir = scratch("escaped-display-names");
    let archive = dir.join("created.rar");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(
            b"line\nname.txt".to_vec(),
            b"escaped display payload\n".to_vec(),
            None,
            None,
        )
        .unwrap();
    builder.write_to_path(&archive, None).unwrap();

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("line\\nname.txt"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK line\\nname.txt"));
}

#[test]
fn creates_rar15_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-store");
    let source = dir.join("hello.txt");
    let archive = dir.join("created15.rar");
    fs::write(&source, b"hello from rar15 cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("Rar15To40"));
    assert!(info_stdout.contains("method=0x30"));

    assert_archive_tests_and_extracts_file(&archive, None, "hello.txt", b"hello from rar15 cli\n");
}

#[test]
fn creates_rar15_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-compressed");
    let source = dir.join("hello.txt");
    let archive = dir.join("created15.rar");
    fs::write(&source, b"hello from rar15 cli hello from rar15 cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0x33"));

    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "hello.txt",
        b"hello from rar15 cli hello from rar15 cli\n",
    );
}

#[test]
fn creates_rar20_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar20-compressed");
    let source = dir.join("hello.txt");
    let archive = dir.join("created20.rar");
    let payload = b"hello from rar20 cli hello from rar20 cli\n".repeat(32);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar20"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("method=0x33"));
    assert!(info_stdout.contains("ver=20"));

    assert_archive_tests_and_extracts_file(&archive, None, "hello.txt", &payload);
}

#[test]
fn creates_rar20_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar20-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("created20-secret.rar");
    fs::write(
        &source,
        b"hello from encrypted rar20 cli hello from encrypted rar20 cli\n",
    )
    .unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar20"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    assert_archive_tests_and_extracts_file(
        &archive,
        Some("pass"),
        "secret.txt",
        b"hello from encrypted rar20 cli hello from encrypted rar20 cli\n",
    );
}

#[test]
fn creates_rar29_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-compressed");
    let source = dir.join("hello.txt");
    let archive = dir.join("created29.rar");
    fs::write(&source, b"hello from rar29 cli hello from rar29 cli\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar29"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("method=0x33") || info_stdout.contains("method=0x35"));
    assert!(info_stdout.contains("ver=29"));

    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "hello.txt",
        b"hello from rar29 cli hello from rar29 cli\n",
    );
}

#[test]
fn creates_rar29_archives_with_distinct_compression_levels() {
    let dir = scratch("create-rar29-levels");
    let source = dir.join("source.txt");
    let level_three = dir.join("level3.rar");
    let level_five = dir.join("level5.rar");
    fs::write(
        &source,
        b"fn alpha() { beta(gamma); }\nlet words = alpha beta gamma delta;\n".repeat(512),
    )
    .unwrap();

    let create_lz = rars()
        .args(["a", "--format", "rar29", "--level", "3"])
        .arg(&level_three)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create_lz.status.success(), "stderr: {}", stderr(&create_lz));

    let create_auto = rars()
        .args(["a", "--format", "rar29", "--level", "5"])
        .arg(&level_five)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        create_auto.status.success(),
        "stderr: {}",
        stderr(&create_auto)
    );

    let lz_info = rars()
        .args(["info", "-v"])
        .arg(&level_three)
        .output()
        .unwrap();
    assert!(lz_info.status.success(), "stderr: {}", stderr(&lz_info));
    assert!(stdout(&lz_info).contains("method=0x33"));

    let auto_info = rars()
        .args(["info", "-v"])
        .arg(&level_five)
        .output()
        .unwrap();
    assert!(auto_info.status.success(), "stderr: {}", stderr(&auto_info));
    assert!(stdout(&auto_info).contains("method=0x35"));

    assert_archive_tests_and_extracts_file(
        &level_three,
        None,
        "source.txt",
        b"fn alpha() { beta(gamma); }\nlet words = alpha beta gamma delta;\n"
            .repeat(512)
            .as_slice(),
    );
    assert_archive_tests_and_extracts_file(
        &level_five,
        None,
        "source.txt",
        b"fn alpha() { beta(gamma); }\nlet words = alpha beta gamma delta;\n"
            .repeat(512)
            .as_slice(),
    );
}

#[test]
fn rar29_lz_compression_levels_change_output_size() {
    let dir = scratch("rar29-lz-level-size");
    let source = dir.join("source.bin");
    let low = dir.join("level1.rar");
    let high = dir.join("level3.rar");
    let pattern: Vec<u8> = (0..=255).collect();
    let mut data = Vec::new();
    for round in 0..8u8 {
        data.extend_from_slice(&pattern);
        for index in 0..32u8 {
            let mut decoy = pattern.clone();
            for byte in decoy.iter_mut().skip(7).step_by(11) {
                *byte = byte.wrapping_add(index).wrapping_add(round).wrapping_add(1);
            }
            data.extend_from_slice(&decoy);
        }
        data.extend_from_slice(&pattern);
    }
    fs::write(&source, &data).unwrap();

    let create_low = rars()
        .args(["a", "--format", "rar29", "--level", "1"])
        .arg(&low)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        create_low.status.success(),
        "stderr: {}",
        stderr(&create_low)
    );
    let create_high = rars()
        .args(["a", "--format", "rar29", "--level", "3"])
        .arg(&high)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        create_high.status.success(),
        "stderr: {}",
        stderr(&create_high)
    );

    assert!(fs::metadata(&high).unwrap().len() < fs::metadata(&low).unwrap().len());
    assert_archive_tests_and_extracts_file(&low, None, "source.bin", &data);
    assert_archive_tests_and_extracts_file(&high, None, "source.bin", &data);
}

#[test]
fn accepts_rar50_compression_level() {
    let dir = scratch("accept-rar50-level");
    let source = dir.join("source.txt");
    let archive = dir.join("level.rar");
    let payload = b"rar50 level accepted by cli\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--level", "5"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert!(create.status.success(), "stderr: {}", stderr(&create));
    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=5"));
    assert_archive_tests_and_extracts_file(&archive, None, "source.txt", &payload);
}

#[test]
fn accepts_rar50_dictionary_size() {
    let dir = scratch("accept-rar50-dict-size");
    let source = dir.join("source.txt");
    let archive = dir.join("dict.rar");
    let payload = b"rar50 dictionary size accepted by cli\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--dict-size", "512k"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert!(create.status.success(), "stderr: {}", stderr(&create));
    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("dict=524288"));
    assert_archive_tests_and_extracts_file(&archive, None, "source.txt", &payload);
}

#[test]
fn rar70_default_dictionary_keeps_rar5_compatible_algorithm() {
    let dir = scratch("rar70-default-dict-uses-v0");
    let source = dir.join("source.txt");
    let archive = dir.join("dict.rar");
    let payload = b"rar70 default dictionary remains rar5-compatible\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar70"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert!(create.status.success(), "stderr: {}", stderr(&create));
    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("algo=0"));
    assert!(info_stdout.contains("dict=131072"));

    let parsed = rars::rar50::Archive::parse_path(&archive).unwrap();
    let file = parsed.files().next().unwrap();
    let compression_info = file.decoded_compression_info().unwrap();
    assert_eq!(compression_info.algorithm_version, 0);
    assert_eq!(compression_info.dictionary_size, 128 * 1024);
    assert_archive_tests_and_extracts_file(&archive, None, "source.txt", &payload);
}

#[test]
fn accepts_rar70_v1_dictionary_size() {
    let dir = scratch("accept-rar70-v1-dict-size");
    let source = dir.join("source.txt");
    let archive = dir.join("dict.rar");
    let payload = b"rar70 v1 dictionary size accepted by cli\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar70", "--dict-size", "192k"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert!(create.status.success(), "stderr: {}", stderr(&create));
    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("algo=1"));
    assert!(info_stdout.contains("dict=196608"));

    let parsed = rars::rar50::Archive::parse_path(&archive).unwrap();
    let file = parsed.files().next().unwrap();
    let compression_info = file.decoded_compression_info().unwrap();
    assert_eq!(compression_info.algorithm_version, 1);
    assert_eq!(compression_info.dictionary_size, 192 * 1024);
    assert_archive_tests_and_extracts_file(&archive, None, "source.txt", &payload);
}

#[test]
fn accepts_rar15_40_dictionary_size() {
    let dir = scratch("accept-rar15-40-dict-size");
    let source = dir.join("source.txt");
    let archive = dir.join("dict.rar");
    let payload = b"rar15-40 dictionary size accepted by cli\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar40", "--dict-size", "512k"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert!(create.status.success(), "stderr: {}", stderr(&create));
    let parsed = rars::rar15_40::Archive::parse_path(&archive).unwrap();
    let file = parsed.files().next().unwrap();
    assert_eq!(file.block.flags & 0x00e0, 0x0060);
    assert_archive_tests_and_extracts_file(&archive, None, "source.txt", &payload);
}

#[test]
fn rejects_dictionary_size_for_rar13_writer() {
    let dir = scratch("reject-rar13-dict-size");
    let source = dir.join("source.txt");
    let archive = dir.join("legacy.rar");
    fs::write(&source, b"legacy dictionary size rejection\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--dict-size", "512k"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert!(!create.status.success());
    assert!(stderr(&create)
        .contains("--dict-size is not supported by --format rar14; use --format rar15"));
}

#[test]
fn rar50_compression_levels_change_output_size() {
    let dir = scratch("rar50-level-size");
    let source = dir.join("source.bin");
    let low = dir.join("level1.rar");
    let high = dir.join("level5.rar");
    let data = rar50_level_sensitive_payload();
    fs::write(&source, &data).unwrap();

    let create_low = rars()
        .args(["a", "--format", "rar50", "--level", "1"])
        .arg(&low)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        create_low.status.success(),
        "stderr: {}",
        stderr(&create_low)
    );
    let create_high = rars()
        .args(["a", "--format", "rar50", "--level", "5"])
        .arg(&high)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        create_high.status.success(),
        "stderr: {}",
        stderr(&create_high)
    );

    assert!(fs::metadata(&high).unwrap().len() < fs::metadata(&low).unwrap().len());
    assert_archive_tests_and_extracts_file(&low, None, "source.bin", &data);
    assert_archive_tests_and_extracts_file(&high, None, "source.bin", &data);
}

#[test]
fn level_zero_stores_payload_for_rar50() {
    let dir = scratch("level-zero-rar50");
    let source = dir.join("source.txt");
    let archive = dir.join("level0.rar");
    fs::write(&source, b"rar50 level zero store\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--level", "0"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0"));
    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "source.txt",
        b"rar50 level zero store\n",
    );
}

#[test]
fn creates_rar29_solid_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-solid");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("rar29-solid.rar");
    fs::write(&first, b"solid cli baseline one alpha beta gamma\n").unwrap();
    fs::write(&second, b"solid cli baseline two alpha beta gamma\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar29", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar15-40 main: flags=0x0008"));

    assert_archive_tests_and_extracts_files(
        &archive,
        None,
        &[
            ("one.txt", b"solid cli baseline one alpha beta gamma\n"),
            ("two.txt", b"solid cli baseline two alpha beta gamma\n"),
        ],
    );
}

#[test]
fn creates_rar20_solid_archive_that_tests() {
    let dir = scratch("create-rar20-solid");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("rar20-solid.rar");
    fs::write(&first, b"rar20 shared phrase alpha beta gamma\n".repeat(64)).unwrap();
    fs::write(
        &second,
        b"rar20 shared phrase alpha beta gamma\nsecond member\n".repeat(32),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar20", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("rar15-40 main: flags=0x0008"));

    assert_archive_tests_and_extracts_files(
        &archive,
        None,
        &[
            (
                "one.txt",
                b"rar20 shared phrase alpha beta gamma\n"
                    .repeat(64)
                    .as_slice(),
            ),
            (
                "two.txt",
                b"rar20 shared phrase alpha beta gamma\nsecond member\n"
                    .repeat(32)
                    .as_slice(),
            ),
        ],
    );
}

#[test]
fn creates_rar15_archive_comment() {
    let dir = scratch("create-rar15-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented.rar");
    fs::write(&source, b"rar15 commented payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--comment", "rar15 note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar15 note"));

    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "commented.txt",
        b"rar15 commented payload\n",
    );
}

#[test]
fn creates_legacy_file_comment() {
    let dir = scratch("create-legacy-file-comment");
    let source = dir.join("commented.txt");
    fs::write(&source, b"file commented payload\n").unwrap();

    for format in ["rar15", "rar30", "rar40"] {
        let archive = dir.join(format!("file-comment-{format}.rar"));
        let create = rars()
            .args(["a", "--format", format, "--file-comment", "file note"])
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();
        assert!(create.status.success(), "stderr: {}", stderr(&create));

        let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
        assert!(info.status.success(), "stderr: {}", stderr(&info));
        assert!(stdout(&info).contains("comment: file note"));

        let test = rars().arg("test").arg(&archive).output().unwrap();
        assert!(test.status.success(), "stderr: {}", stderr(&test));
        assert!(stdout(&test).contains("OK commented.txt"));
    }
}

#[test]
fn creates_rar20_archive_and_file_comments() {
    let dir = scratch("create-rar20-comments");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented20.rar");
    fs::write(&source, b"rar20 commented payload\n").unwrap();

    let archive_comment = rars()
        .args(["a", "--format", "rar20", "--comment", "rar20 note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        archive_comment.status.success(),
        "stderr: {}",
        stderr(&archive_comment)
    );
    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar20 note"));

    let file_comment_archive = dir.join("file-comment20.rar");
    let file_comment = rars()
        .args([
            "a",
            "--format",
            "rar20",
            "--file-comment",
            "rar20 file note",
        ])
        .arg(&file_comment_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        file_comment.status.success(),
        "stderr: {}",
        stderr(&file_comment)
    );
    let info = rars()
        .args(["info", "-v"])
        .arg(&file_comment_archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar20 file note"));

    assert_archive_tests_and_extracts_file(
        &file_comment_archive,
        None,
        "commented.txt",
        b"rar20 commented payload\n",
    );
}

#[test]
fn creates_rar29_archive_and_file_comments() {
    let dir = scratch("create-rar29-comments");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented29.rar");
    fs::write(&source, b"rar29 commented payload\n").unwrap();

    let archive_comment = rars()
        .args(["a", "--format", "rar29", "--comment", "rar29 note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        archive_comment.status.success(),
        "stderr: {}",
        stderr(&archive_comment)
    );
    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar29 note"));

    let file_comment_archive = dir.join("file-comment29.rar");
    let file_comment = rars()
        .args([
            "a",
            "--format",
            "rar29",
            "--file-comment",
            "rar29 file note",
        ])
        .arg(&file_comment_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        file_comment.status.success(),
        "stderr: {}",
        stderr(&file_comment)
    );
    let info = rars()
        .args(["info", "-v"])
        .arg(&file_comment_archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar29 file note"));

    assert_archive_tests_and_extracts_file(
        &file_comment_archive,
        None,
        "commented.txt",
        b"rar29 commented payload\n",
    );
}

#[test]
fn creates_rar30_newsub_archive_comment() {
    let dir = scratch("create-rar30-newsub-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("commented30.rar");
    fs::write(&source, b"rar30 NEWSUB commented payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar30", "--comment", "rar30 NEWSUB note"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("comment: rar30 NEWSUB note"));
    assert!(info_stdout.contains("subblock: ArchiveComment CMT"));

    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "commented.txt",
        b"rar30 NEWSUB commented payload\n",
    );
}

#[test]
fn creates_literal_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-compressed");
    let source = dir.join("tiny.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"tiny payload over sixteen").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0"));

    assert_archive_tests_and_extracts_file(
        &archive,
        None,
        "tiny.txt",
        b"tiny payload over sixteen",
    );
}

#[test]
fn creates_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-solid-compressed");
    let first = dir.join("first.txt");
    let second = dir.join("second.txt");
    let archive = dir.join("solid.rar");
    fs::write(&first, b"first member primes the adaptive unpack15 state").unwrap();
    fs::write(
        &second,
        b"second member is encoded without resetting that state",
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar13 main: flags=0x88"));
    assert!(info_stdout.contains("flags=0x10"));

    assert_archive_tests_and_extracts_files(
        &archive,
        None,
        &[
            (
                "first.txt",
                b"first member primes the adaptive unpack15 state",
            ),
            (
                "second.txt",
                b"second member is encoded without resetting that state",
            ),
        ],
    );
}

#[test]
fn creates_rar15_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-solid-compressed");
    let first = dir.join("first.txt");
    let second = dir.join("second.txt");
    let archive = dir.join("solid15.rar");
    fs::write(&first, b"shared prefix shared prefix alpha").unwrap();
    fs::write(&second, b"shared prefix shared prefix beta").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar15-40 main: flags=0x0008"));
    assert!(info_stdout.contains("flags=0x8010"));

    assert_archive_tests_and_extracts_files(
        &archive,
        None,
        &[
            ("first.txt", b"shared prefix shared prefix alpha"),
            ("second.txt", b"shared prefix shared prefix beta"),
        ],
    );
}

#[test]
fn creates_rar15_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("secret15.rar");
    fs::write(&source, b"secret rar15 compressed payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar15"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let without_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&without_password);

    assert_archive_tests_and_extracts_file(
        &archive,
        Some("pass"),
        "secret.txt",
        b"secret rar15 compressed payload\n",
    );
}

#[test]
fn creates_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("secret.rar");
    fs::write(&source, b"secret compressed payload over sixteen").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar14"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let without_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&without_password);

    assert_archive_tests_and_extracts_file(
        &archive,
        Some("pass"),
        "secret.txt",
        b"secret compressed payload over sixteen",
    );
}

#[test]
fn creates_archive_and_file_comments() {
    let dir = scratch("create-comments");
    let source = dir.join("commented.txt");
    let archive = dir.join("comments.rar");
    fs::write(&source, b"commented payload over sixteen").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar14",
            "--comment",
            "archive note",
            "--file-comment",
            "file note",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let stdout = stdout(&info);
    assert!(stdout.contains("comment: archive note"));
    assert!(stdout.contains("comment: file note"));
}

#[test]
fn creates_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-stored-multivolume");
    let source = dir.join("payload.bin");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--store", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    assert!(dir.join("split.r01").exists());
    assert!(dir.join("split.r02").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .arg(dir.join("split.r01"))
        .arg(dir.join("split.r02"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(600)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar15_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-stored-multivolume");
    let source = dir.join("payload.bin");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--store", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    assert!(dir.join("split.r01").exists());
    assert!(dir.join("split.r02").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .arg(dir.join("split.r01"))
        .arg(dir.join("split.r02"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar15_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(600)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let test = rars()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar20_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar20-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar20", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let mut volume_args = vec![archive];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }
    let test = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar29_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-compressed-multivolume");
    let source = dir.join("repeat.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar29", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());

    let mut volume_args = vec![archive];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }
    let test = rars().arg("test").args(&volume_args).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK repeat.txt"));
}

#[test]
fn creates_rar15_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar15-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar15",
            "--volume-size",
            "512",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--volume-size",
            "512",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar29_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar29",
            "--volume-size",
            "512",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_header_encrypted_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-header-encrypted-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--encrypt-headers",
            "--volume-size",
            "512",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    let mut volume_args = vec![archive.clone()];
    for index in 0.. {
        let path = dir.join(format!("split.r{index:02}"));
        if !path.exists() {
            break;
        }
        volume_args.push(path);
    }

    let missing_password = rars().arg("test").args(&volume_args).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .args(&volume_args)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_aes_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-aes-encrypted");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar30 aes encrypted cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar30"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar29_aes_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-aes-encrypted");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar29 aes encrypted cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar29"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_header_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-header-encrypted");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar30 header encrypted cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar30_solid_header_encrypted_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-solid-header-encrypted");
    let one = dir.join("one.txt");
    let two = dir.join("two.txt");
    let archive = dir.join("created.rar");
    fs::write(&one, b"rar30 solid header encrypted one one one\n").unwrap();
    fs::write(&two, b"rar30 solid header encrypted two two two\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--solid",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&one)
        .arg(&two)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    let stdout = stdout(&test);
    assert!(stdout.contains("OK one.txt"));
    assert!(stdout.contains("OK two.txt"));
}

#[test]
fn creates_rar50_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-stored");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 stored cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_quick_open_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-quick-open");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 quick-open cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store", "--quick-open"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: QO"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn rar50_members_carry_a_blake2sp_hash_only_when_asked_for() {
    let dir = scratch("create-rar50-checksum");
    let source = dir.join("payload.txt");
    let payload = b"rar50 checksum cli payload\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    for blake2sp in [false, true] {
        let archive = dir.join(format!("created-{blake2sp}.rar"));
        let mut create = rars();
        create.args(["a", "--store"]);
        if blake2sp {
            create.arg("--blake2sp");
        }
        let create = create.arg(&archive).arg(&source).output().unwrap();
        assert!(create.status.success(), "stderr: {}", stderr(&create));

        let mut bytes = fs::read(&archive).unwrap();
        let parsed = rars::rar50::Archive::parse(&bytes).unwrap();
        let file = parsed.files().next().unwrap();
        assert_eq!(file.hash.is_some(), blake2sp);
        assert_eq!(file.data_crc32, Some(crc32(&payload)));
        let middle = file.block.data_range.start + payload.len() / 2;

        let test = rars().arg("test").arg(&archive).output().unwrap();
        assert!(test.status.success(), "stderr: {}", stderr(&test));
        assert!(stdout(&test).contains("OK payload.txt"));

        bytes[middle] ^= 0x20;
        fs::write(&archive, &bytes).unwrap();
        let test = rars().arg("test").arg(&archive).output().unwrap();
        assert!(!test.status.success(), "blake2sp={blake2sp}");
    }

    let refused = rars()
        .args(["a", "--format", "rar40", "--blake2sp"])
        .arg(dir.join("legacy.rar"))
        .arg(&source)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("--blake2sp"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn creates_rar50_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 recovery cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "8",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar50 main: flags=0x0008"));
    assert!(info_stdout.contains("service: RR"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_compressed_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-compressed-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 compressed recovery cli payload repeated repeated repeated\n",
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--recovery-percent", "8"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar50 main: flags=0x0008"));
    assert!(info_stdout.contains("service: RR"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_encrypted_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-encrypted-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted recovery cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "5",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info_without_password.status.success());
    assert!(stdout(&info_without_password).contains("service: RR"));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-encrypted-compressed-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 encrypted compressed recovery cli payload repeated repeated\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--recovery-percent",
            "5",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info_without_password.status.success());
    assert!(stdout(&info_without_password).contains("service: RR"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_header_encrypted_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-header-encrypted-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 header encrypted recovery cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--recovery-percent",
            "4",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&info_without_password);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    let info_stdout = stdout(&info);
    assert!(info_stdout.contains("rar50 main: flags=0x0008"));
    assert!(info_stdout.contains("service: RR"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_header_encrypted_compressed_recovery_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-header-encrypted-compressed-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 header encrypted compressed recovery cli payload repeated repeated\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
            "--recovery-percent",
            "4",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));

    let info_without_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&info_without_password);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-stored");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted stored cli payload\n").unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_wrong_password(&wrong);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    let payload = b"rar50 encrypted compressed cli payload\n".repeat(16);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar50"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=3"));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_wrong_password(&wrong);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-solid-compressed");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &first,
        b"rar50 encrypted solid compressed cli shared phrase alpha beta gamma\n".repeat(12),
    )
    .unwrap();
    fs::write(
        &second,
        b"rar50 encrypted solid compressed cli shared phrase alpha beta gamma\nsecond\n".repeat(6),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--password", "pass", "--format", "rar50", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_wrong_password(&wrong);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK one.txt"));
    assert!(stdout(&test).contains("OK two.txt"));
}

#[test]
fn creates_rar50_header_encrypted_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-compressed");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 header encrypted compressed cli payload\nrar50 header encrypted compressed cli payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=3"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-solid-compressed");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &first,
        b"rar50 header encrypted solid compressed cli shared phrase alpha beta gamma\n".repeat(12),
    )
    .unwrap();
    fs::write(
        &second,
        b"rar50 header encrypted solid compressed cli shared phrase alpha beta gamma\nsecond\n"
            .repeat(6),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
            "--solid",
        ])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK one.txt"));
    assert!(stdout(&test).contains("OK two.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_archive_comment_service() {
    let dir = scratch("create-rar50-encrypted-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--comment",
            "Encrypted RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: Encrypted RAR5 CLI comment"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_archive_comment_service() {
    let dir = scratch("create-rar50-encrypted-compressed-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 encrypted compressed comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--comment",
            "Encrypted compressed RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: Encrypted compressed RAR5 CLI comment"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-stored");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 header encrypted stored cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_wrong_password(&wrong);

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_archive_comment_service() {
    let dir = scratch("create-rar50-header-encrypted-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 header encrypted comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--comment",
            "Header encrypted RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: Header encrypted RAR5 CLI comment"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_compressed_archive_comment_service() {
    let dir = scratch("create-rar50-header-encrypted-compressed-comment");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar50 header encrypted compressed comment cli payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--encrypt-headers",
            "--comment",
            "Header encrypted compressed RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: Header encrypted compressed RAR5 CLI comment"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-stored-volume");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, deterministic_noise(3000)).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--volume-size",
            "1k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let part = dir.join(format!("created.part{index:02}.rar"));
        if !part.exists() {
            break;
        }
        parts.push(part);
    }
    assert!(parts.len() > 1);

    let mut command = rars();
    command.args(["test", "--password", "pass"]);
    for part in &parts {
        command.arg(part);
    }
    let test = command.output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-stored-volume");
    let source = dir.join("secret.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, deterministic_noise(3000)).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--volume-size",
            "1k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let part = dir.join(format!("created.part{index:02}.rar"));
        if !part.exists() {
            break;
        }
        parts.push(part);
    }
    assert!(parts.len() > 1);

    let missing_password = rars().arg("test").arg(&parts[0]).output().unwrap();
    assert_password_required(&missing_password);

    let mut command = rars();
    command.args(["test", "--password", "pass"]);
    for part in &parts {
        command.arg(part);
    }
    let test = command.output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK secret.txt"));
}

#[test]
fn creates_rar50_stored_archive_comment_service() {
    let dir = scratch("create-rar50-comment");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--comment",
            "RAR5 CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: RAR5 CLI comment"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_compressed_archive_comment_service() {
    let dir = scratch("create-rar50-compressed-comment");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar50 compressed comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--comment",
            "RAR5 compressed CLI comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: RAR5 compressed CLI comment"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_stored_file_comment_service() {
    let dir = scratch("create-rar50-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(&source, b"rar50 file comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--file-comment",
            "RAR5 CLI file comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar50_encrypted_stored_file_comment_service() {
    let dir = scratch("create-rar50-encrypted-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(&source, b"rar50 encrypted file comment cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--file-comment",
            "Encrypted RAR5 CLI file comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar50_header_encrypted_stored_file_comment_service() {
    let dir = scratch("create-rar50-header-encrypted-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(
        &source,
        b"rar50 header encrypted file comment cli payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar50",
            "--store",
            "--encrypt-headers",
            "--file-comment",
            "Header encrypted RAR5 CLI file comment",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: CMT"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
}

#[test]
fn creates_rar70_stored_archive_metadata() {
    let dir = scratch("create-rar70-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar70 metadata cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--store",
            "--archive-name",
            "cli-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-metadata.rar"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_compressed_archive_metadata() {
    let dir = scratch("create-rar70-compressed-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar70 compressed metadata cli payload repeated\n".repeat(8),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--archive-name",
            "cli-compressed-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-compressed-metadata.rar"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_encrypted_stored_archive_metadata() {
    let dir = scratch("create-rar70-encrypted-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar70 encrypted metadata cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--store",
            "--password",
            "pass",
            "--archive-name",
            "cli-encrypted-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-encrypted-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_encrypted_compressed_archive_metadata() {
    let dir = scratch("create-rar70-encrypted-compressed-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar70 encrypted compressed metadata cli payload repeated\n".repeat(8),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--password",
            "pass",
            "--archive-name",
            "cli-encrypted-compressed-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-encrypted-compressed-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_header_encrypted_stored_archive_metadata() {
    let dir = scratch("create-rar70-header-encrypted-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar70 header encrypted metadata cli payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--store",
            "--password",
            "pass",
            "--encrypt-headers",
            "--archive-name",
            "cli-header-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-header-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar70_header_encrypted_compressed_archive_metadata() {
    let dir = scratch("create-rar70-header-encrypted-compressed-metadata");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar70 header encrypted compressed metadata cli payload repeated\n".repeat(8),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar70",
            "--password",
            "pass",
            "--encrypt-headers",
            "--archive-name",
            "cli-header-compressed-metadata.rar",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars()
        .args(["info", "-v", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("archive name: cli-header-compressed-metadata.rar"));

    let test = rars()
        .args(["test", "--password", "pass"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-stored-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(1500)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(dir.join("split.part01.rar").exists());
    assert!(dir.join("split.part02.rar").exists());
    let create_stdout = stdout(&create);
    assert!(create_stdout.contains("created"));
    assert!(create_stdout.contains("split.part01.rar"));
    assert!(create_stdout.contains("split.part02.rar"));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }

    let discovered = rars().arg("test").arg(&parts[0]).output().unwrap();
    assert!(
        discovered.status.success(),
        "stderr: {}",
        stderr(&discovered)
    );
    assert!(stdout(&discovered).contains("OK payload.txt"));

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_stored_recovery_multivolume_archive_that_can_be_tested_and_listed() {
    let dir = scratch("create-rar50-stored-recovery-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(8000)).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "8",
            "--volume-size",
            "2k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(stderr(&create).contains("validation-ready RR metadata"));
    assert!(dir.join("split.part01.rar").exists());
    assert!(dir.join("split.part02.rar").exists());

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }

    let info = rars().args(["info", "-v"]).arg(&parts[0]).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("service: RR"));

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn repairs_rar50_stored_archive_with_inline_recovery_record() {
    let dir = scratch("repair-rar50-inline-recovery");
    let source = dir.join("payload.txt");
    let archive = dir.join("recoverable.rar");
    let repaired = dir.join("repaired.rar");
    let payload = b"rar50 repair cli payload with enough bytes for shard damage\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "20",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut damaged = fs::read(&archive).unwrap();
    let payload_at = damaged
        .windows(32)
        .position(|window| window == &payload[..32])
        .expect("stored payload is visible in archive");
    damaged[payload_at + 10..payload_at + 90].fill(0xa5);
    fs::write(&archive, damaged).unwrap();

    let broken = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!broken.status.success());

    let repair = rars()
        .arg("repair")
        .arg(&archive)
        .arg(&repaired)
        .output()
        .unwrap();
    assert!(repair.status.success(), "stderr: {}", stderr(&repair));
    assert!(stdout(&repair).contains("repaired"));

    let test = rars().arg("test").arg(&repaired).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn repair_rejects_non_rar_input_without_raw_inline_scan() {
    let dir = scratch("repair-non-rar");
    let input = dir.join("image.jpg");
    let repaired = dir.join("repaired.rar");
    fs::write(&input, b"not a rar archive with lots of bytes").unwrap();

    let output = rars()
        .arg("repair")
        .arg(&input)
        .arg(&repaired)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to identify archive"));
    assert!(!stderr.contains("raw inline recovery repair"));
    assert!(!repaired.exists());
}

#[test]
fn repair_reports_rebuilt_recovery_and_end_records() {
    let dir = scratch("repair-rebuilt-record-reports");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(20));
    builder
        .add_bytes(b"file".to_vec(), vec![b'p'; 32 * 1024], None, None)
        .unwrap();
    let original = builder.to_bytes().unwrap();
    let archive = rars::rar50::Archive::parse(&original).unwrap();
    let recovery = archive
        .services()
        .find(|service| service.name == b"RR")
        .unwrap()
        .block
        .data_range
        .start;
    for (end_damaged, message) in [
        (false, "rebuilt recovery record"),
        (true, "rebuilt archive end"),
    ] {
        let mut damaged = original.clone();
        if end_damaged {
            // Truncate the recovery tail, leaving enough redundancy to rebuild
            // both the recovery record and the archive end.
            damaged.truncate(damaged.len() - 4096);
        } else {
            damaged[recovery + 0x48] ^= 0xff;
        }
        let input = dir.join("damaged.rar");
        let output = dir.join("repaired.rar");
        fs::write(&input, damaged).unwrap();
        let command = rars()
            .arg("repair")
            .arg(&input)
            .arg(&output)
            .output()
            .unwrap();
        assert!(command.status.success(), "{}", stderr(&command));
        assert!(stdout(&command).contains(message), "{}", stdout(&command));
        assert_eq!(fs::read(&output).unwrap(), original);
    }
}

#[test]
fn repairs_rar250_protect_head_archive() {
    let dir = scratch("repair-rar250-protect-head");
    let archive = dir.join("damaged.rar");
    let repaired = dir.join("repaired.rar");
    let original = fs::read(fixture_rar15_40("rar250_protect_head_rr5.rar")).unwrap();
    let mut damaged = original.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);
    fs::write(&archive, damaged).unwrap();

    let broken = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!broken.status.success());

    let repair = rars()
        .arg("repair")
        .arg(&archive)
        .arg(&repaired)
        .output()
        .unwrap();
    assert!(repair.status.success(), "stderr: {}", stderr(&repair));
    assert!(stdout(&repair).contains("repaired"));
    assert_eq!(fs::read(&repaired).unwrap(), original);

    let test = rars().arg("test").arg(&repaired).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK BIG.BIN"));
}

#[test]
fn repairs_rar300_newsub_recovery_archive() {
    let dir = scratch("repair-rar300-newsub-recovery");
    let archive = dir.join("damaged.rar");
    let repaired = dir.join("repaired.rar");
    let original = fs::read(fixture_rar15_40("rar300/with_recovery_rar300.rar")).unwrap();
    let mut damaged = original.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);
    fs::write(&archive, damaged).unwrap();

    let broken = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!broken.status.success());

    let repair = rars()
        .arg("repair")
        .arg(&archive)
        .arg(&repaired)
        .output()
        .unwrap();
    assert!(repair.status.success(), "stderr: {}", stderr(&repair));
    assert!(stdout(&repair).contains("repaired"));
    assert_eq!(fs::read(&repaired).unwrap(), original);

    let test = rars().arg("test").arg(&repaired).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK bigtext_64k.bin"));
}

#[test]
fn repairs_rar50_rev5_missing_data_volume_set() {
    let dir = scratch("repair-rar50-rev5");
    let out_dir = dir.join("out");
    let mut command = rars();
    command.arg("repair");
    for name in [
        "multivol_rev.part1.rar",
        "multivol_rev.part3.rar",
        "multivol_rev.part4.rar",
        "multivol_rev.part5.rar",
        "multivol_rev.part1.rev",
    ] {
        command.arg(fixture_rar50(name));
    }
    let output = command.arg(&out_dir).output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("repaired"));

    for index in 1..=5 {
        assert_eq!(
            fs::read(out_dir.join(format!("multivol_rev.part{index}.rar"))).unwrap(),
            fs::read(fixture_rar50(&format!("multivol_rev.part{index}.rar"))).unwrap()
        );
    }
}

#[test]
fn repairs_rar300_old_style_rev_missing_data_volume_set() {
    let dir = scratch("repair-rar300-rev3");
    let out_dir = dir.join("out");
    let mut command = rars();
    command.arg("repair");
    for name in [
        "rar300/rev_oldstyle.part1.rar",
        "rar300/rev_oldstyle.part3.rar",
        "rar300/rev_oldstyle.part4.rar",
        "rar300/rev_oldstyle.part4_2_1.rev",
    ] {
        command.arg(fixture_rar15_40(name));
    }
    let output = command.arg(&out_dir).output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("repaired"));
    assert_eq!(
        fs::read(out_dir.join("rev_oldstyle.part2.rar")).unwrap(),
        fs::read(fixture_rar15_40("rar300/rev_oldstyle.part2.rar")).unwrap()
    );

    let test = rars()
        .arg("test")
        .arg(out_dir.join("rev_oldstyle.part1.rar"))
        .arg(out_dir.join("rev_oldstyle.part2.rar"))
        .arg(out_dir.join("rev_oldstyle.part3.rar"))
        .arg(out_dir.join("rev_oldstyle.part4.rar"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK tmp\\rars-rar3-rev-gen\\payload.bin"));
}

#[test]
fn repairs_rar4_new_style_rev_missing_data_volume_set() {
    let dir = scratch("repair-rar4-rev3-new-style");
    let out_dir = dir.join("out");
    let mut command = rars();
    command.arg("repair");
    for name in [
        "rar300/rev_newstyle.part1.rar",
        "rar300/rev_newstyle.part3.rar",
        "rar300/rev_newstyle.part4.rar",
        "rar300/rev_newstyle.part1.rev",
    ] {
        command.arg(fixture_rar15_40(name));
    }
    let output = command.arg(&out_dir).output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("repaired"));
    assert_eq!(
        fs::read(out_dir.join("rev_newstyle.part2.rar")).unwrap(),
        fs::read(fixture_rar15_40("rar300/rev_newstyle.part2.rar")).unwrap()
    );

    let test = rars()
        .arg("test")
        .arg(out_dir.join("rev_newstyle.part1.rar"))
        .arg(out_dir.join("rev_newstyle.part2.rar"))
        .arg(out_dir.join("rev_newstyle.part3.rar"))
        .arg(out_dir.join("rev_newstyle.part4.rar"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK tmp\\rars-rar4-rev-gen\\payload.bin"));
}

#[test]
fn creates_rar50_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-compressed");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    let payload = b"rar50 compressed cli payload\n".repeat(16);
    fs::write(&source, &payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar50"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=3"));

    assert_archive_tests_and_extracts_file(&archive, None, "payload.txt", &payload);
}

#[test]
fn creates_rar50_solid_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-solid-compressed");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("solid.rar");
    let first_payload = b"rar50 solid compressed cli shared phrase alpha beta gamma\n".repeat(16);
    let second_payload =
        b"rar50 solid compressed cli shared phrase alpha beta gamma\nsecond\n".repeat(8);
    fs::write(&first, &first_payload).unwrap();
    fs::write(&second, &second_payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--solid"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("rar50 main: flags=0x0004"));
    assert!(stdout(&info).contains("solid=false"));
    assert!(stdout(&info).contains("solid=true"));

    assert_archive_tests_and_extracts_files(
        &archive,
        None,
        &[
            ("one.txt", first_payload.as_slice()),
            ("two.txt", second_payload.as_slice()),
        ],
    );
}

#[test]
fn creates_rar50_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-compressed-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    let payload = deterministic_noise(1500);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--volume-size", "512"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(dir.join("split.part01.rar").exists());
    assert!(dir.join("split.part02.rar").exists());

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }

    assert_archive_set_tests_and_extracts_file(&parts, None, "payload.txt", &payload);
}

#[test]
fn creates_rar50_delta_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-delta-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..180)
        .map(|index| (index * 5 + index / 2) as u8)
        .collect();
    fs::write(&source, &payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--delta-filter", "3"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=3"));

    assert_archive_tests_and_extracts_file(&archive, None, "payload.bin", &payload);
}

#[test]
fn creates_rar50_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-e8-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload = b"\xe8\0\0\0\0rar50 e8 filtered cli payload";
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--e8-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    assert_archive_tests_and_extracts_file(&archive, None, "payload.bin", payload);
}

#[test]
fn creates_rar29_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-e8-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload = b"\xe8\0\0\0\0rar29 e8 filtered cli payload\n".repeat(12);
    fs::write(&source, &payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--e8-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    assert_archive_tests_and_extracts_file(&archive, None, "payload.bin", &payload);
}

#[test]
fn creates_rar29_solid_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-solid-e8-filtered-compressed");
    let first = dir.join("first.bin");
    let second = dir.join("second.bin");
    let archive = dir.join("created.rar");
    let first_payload = b"\xe8\0\0\0\0rar29 solid e8 filtered first cli payload\n".repeat(12);
    let second_payload = b"\xe8\0\0\0\0rar29 solid e8 filtered second cli payload\n".repeat(12);
    fs::write(&first, &first_payload).unwrap();
    fs::write(&second, &second_payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--solid", "--e8-filter"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    assert_archive_tests_and_extracts_files(
        &archive,
        None,
        &[
            ("first.bin", first_payload.as_slice()),
            ("second.bin", second_payload.as_slice()),
        ],
    );
}

#[test]
fn creates_rar29_encrypted_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-encrypted-e8-filtered-compressed");
    let source = dir.join("secret.bin");
    let archive = dir.join("created.rar");
    let payload = b"\xe8\0\0\0\0rar29 encrypted e8 filtered cli payload\n".repeat(12);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar29",
            "--e8-filter",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().arg("test").arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    let wrong = rars()
        .args(["test", "--password", "wrong"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_wrong_password(&wrong);

    assert_archive_tests_and_extracts_file(&archive, Some("pass"), "secret.bin", &payload);
}

#[test]
fn creates_rar30_header_encrypted_e8_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar30-header-encrypted-e8-filtered-compressed");
    let source = dir.join("secret.bin");
    let archive = dir.join("created.rar");
    let payload = b"\xe8\0\0\0\0rar30 header encrypted e8 filtered cli payload\n".repeat(12);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--encrypt-headers",
            "--e8-filter",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let missing_password = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert_password_required(&missing_password);

    assert_archive_tests_and_extracts_file(&archive, Some("pass"), "secret.bin", &payload);
}

#[test]
fn creates_rar29_e8e9_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-e8e9-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload = b"\xe9\0\0\0\0rar29 e8e9 filtered cli payload\n".repeat(12);
    fs::write(&source, &payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--e8e9-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    assert_archive_tests_and_extracts_file(&archive, None, "payload.bin", &payload);
}

#[test]
fn creates_rar29_delta_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-delta-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..384).map(|index| (index * 23 + 9) as u8).collect();
    fs::write(&source, &payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--delta-filter", "3"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    assert_archive_tests_and_extracts_file(&archive, None, "payload.bin", &payload);
}

#[test]
fn creates_rar29_itanium_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-itanium-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let mut payload = vec![0u8; 48];
    payload[16] = 22;
    payload[21] = 20;
    payload.extend_from_slice(b"rar29 itanium filtered cli payload\n");
    fs::write(&source, &payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--itanium-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    assert_archive_tests_and_extracts_file(&archive, None, "payload.bin", &payload);
}

#[test]
fn creates_rar29_rgb_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-rgb-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..96).map(|index| (index * 41 + 19) as u8).collect();
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--rgb-filter", "12"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_audio_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-audio-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    let payload: Vec<u8> = (0..160)
        .map(|index| (index * 13 + index / 11) as u8)
        .collect();
    fs::write(&source, payload).unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--audio-filter", "2"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_e8e9_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-e8e9-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(&source, b"\xe9\0\0\0\0rar50 e8e9 filtered cli payload").unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--e8e9-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_arm_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-arm-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(&source, [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!']).unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--arm-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_auto_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-auto-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar50 auto filtered cli payload\n".repeat(16),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--auto-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar50_default_compressed_archive_with_auto_policy() {
    let dir = scratch("create-rar50-default-auto-compressed");
    let source = dir.join("payload.bin");
    let auto_archive = dir.join("auto.rar");
    let default_archive = dir.join("default.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar50 default auto filtered cli payload\n".repeat(16),
    )
    .unwrap();

    let auto = rars()
        .args(["a", "--format", "rar50", "--auto-filter"])
        .arg(&auto_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(auto.status.success(), "stderr: {}", stderr(&auto));
    let default = rars()
        .args(["a", "--format", "rar50"])
        .arg(&default_archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(default.status.success(), "stderr: {}", stderr(&default));

    let auto_parsed = rars::rar50::Archive::parse_path(&auto_archive).unwrap();
    let default_parsed = rars::rar50::Archive::parse_path(&default_archive).unwrap();
    assert_eq!(
        default_parsed.files().next().unwrap().packed_size(),
        auto_parsed.files().next().unwrap().packed_size()
    );

    let test = rars().arg("test").arg(&default_archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_auto_filtered_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-auto-filtered-compressed");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar29 auto filtered cli payload\n".repeat(16),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--auto-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn creates_rar29_default_compressed_archive_with_auto_policy() {
    let dir = scratch("create-rar29-default-auto-compressed");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar29 default auto cli text alpha beta gamma alpha beta gamma\n".repeat(256),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let parsed = rar15_40::Archive::parse_path(&archive).unwrap();
    let file = parsed.files().next().unwrap();
    // The method byte is the level, and no level was asked for, so it is the
    // default 0x33 whether the writer settled on LZ or PPMd. `test` below is
    // what proves the member reads back.
    assert_eq!(file.method, 0x33);

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar29_ppmd_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-ppmd-compressed");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"rar29 ppmd cli text alpha beta gamma\n".repeat(96),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--ppmd"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0x33"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar29_ppmd_filtered_archive_that_can_be_tested() {
    let dir = scratch("create-rar29-ppmd-filtered");
    let source = dir.join("payload.bin");
    let archive = dir.join("created.rar");
    fs::write(
        &source,
        b"\xe8\0\0\0\0rar29 ppmd embedded e8 filter cli payload\n".repeat(16),
    )
    .unwrap();

    let output = rars()
        .args(["a", "--format", "rar29", "--ppmd", "--e8-filter"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("method=0x33"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn rejects_ppmd_for_rar5_writer() {
    let dir = scratch("reject-rar5-ppmd");
    let source = dir.join("payload.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"rar5 cannot write ppmd\n").unwrap();

    let output = rars()
        .args(["a", "--format", "rar50", "--ppmd"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stderr(&output).trim(),
        "error: --ppmd is not supported by --format rar50; use --format rar29, \
         --format rar30 or --format rar40"
    );
}

/// These three name RAR 2.9 RarVM programs that RAR 5 has no filter type for.
#[test]
fn rejects_rar29_only_filters_for_rar5_writer() {
    let dir = scratch("reject-rar5-rar29-filters");
    let source = dir.join("payload.bin");
    fs::write(&source, vec![0xe8u8; 4096]).unwrap();

    for (flag, value) in [
        ("--itanium-filter", None),
        ("--rgb-filter", Some("3")),
        ("--audio-filter", Some("2")),
    ] {
        let archive = dir.join(format!("created{}.rar", flag.trim_start_matches('-')));
        let mut command = rars();
        command.args(["a", "--format", "rar50", flag]);
        if let Some(value) = value {
            command.arg(value);
        }
        let output = command.arg(&archive).arg(&source).output().unwrap();

        assert!(!output.status.success(), "{flag} was accepted");
        assert!(
            stderr(&output).contains(&format!(
                "{flag} is not supported by --format rar50; \
                 use --format rar29, --format rar30 or --format rar40"
            )),
            "{flag}: {}",
            stderr(&output)
        );
        assert!(!archive.exists(), "{flag} still wrote an archive");
    }
}

#[test]
fn creates_rar50_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-solid-compressed-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(&source, deterministic_noise(3000)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--solid", "--volume-size", "1k"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let info = rars().args(["info", "-v"]).arg(&parts[0]).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    // Volume and solid; only later volumes carry a volume number.
    assert!(stdout(&info).contains("rar50 main: flags=0x0005"));

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.txt"));
}

#[test]
fn creates_rar50_multi_file_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-multi-file-solid-compressed-multivolume");
    let first = dir.join("one.txt");
    let second = dir.join("two.txt");
    let archive = dir.join("split.rar");
    let mut first_payload = b"rar50 multi-file solid split cli shared phrase\n"
        .repeat(8)
        .to_vec();
    first_payload.extend_from_slice(&deterministic_noise(2048));
    let mut second_payload = b"rar50 multi-file solid split cli shared phrase\nsecond\n"
        .repeat(8)
        .to_vec();
    second_payload.extend_from_slice(&deterministic_noise(2048));
    fs::write(&first, first_payload).unwrap();
    fs::write(&second, second_payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--solid", "--volume-size", "512"])
        .arg(&archive)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let info = rars().args(["info", "-v"]).args(&parts).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("solid=true"));

    let test = rars().arg("test").args(&parts).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK one.txt"));
    assert!(stdout(&test).contains("OK two.txt"));
}

#[test]
fn creates_rar50_encrypted_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    let payload = deterministic_noise(3000);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--volume-size",
            "1k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    assert_archive_set_tests_and_extracts_file(&parts, Some("pass"), "secret.txt", &payload);
}

#[test]
fn creates_rar50_encrypted_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-encrypted-solid-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    let payload = deterministic_noise(3000);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--solid",
            "--volume-size",
            "1k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    assert_archive_set_tests_and_extracts_file(&parts, Some("pass"), "secret.txt", &payload);
}

#[test]
fn creates_rar50_header_encrypted_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    let payload = deterministic_noise(3000);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--encrypt-headers",
            "--volume-size",
            "1k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let missing = rars().arg("test").args(&parts).output().unwrap();
    assert_password_required(&missing);

    assert_archive_set_tests_and_extracts_file(&parts, Some("pass"), "secret.txt", &payload);
}

#[test]
fn creates_rar50_header_encrypted_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-header-encrypted-solid-compressed-multivolume");
    let source = dir.join("secret.txt");
    let archive = dir.join("split.rar");
    let payload = deterministic_noise(3000);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--encrypt-headers",
            "--solid",
            "--volume-size",
            "1k",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let mut parts = Vec::new();
    for index in 1.. {
        let path = dir.join(format!("split.part{index:02}.rar"));
        if !path.exists() {
            break;
        }
        parts.push(path);
    }
    assert!(parts.len() >= 2);

    let missing = rars().arg("test").args(&parts).output().unwrap();
    assert_password_required(&missing);

    assert_archive_set_tests_and_extracts_file(&parts, Some("pass"), "secret.txt", &payload);
}

#[test]
fn rejects_solid_store_output() {
    let dir = scratch("reject-solid-store");
    let source = dir.join("hello.txt");
    let archive = dir.join("bad.rar");
    fs::write(&source, b"hello").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--store", "--solid"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("solid output requires compression"));
}

#[test]
fn rejects_add_without_inputs() {
    let dir = scratch("reject-no-inputs");
    let archive = dir.join("empty.rar");

    let output = rars()
        .args(["a", "--format", "rar14"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("required"));
    assert!(stderr.contains("<FILE>"));
}

#[test]
fn rejects_unknown_add_option() {
    let dir = scratch("reject-unknown-add-option");
    let source = dir.join("hello.txt");
    let archive = dir.join("bad.rar");
    fs::write(&source, b"hello").unwrap();

    let output = rars()
        .args(["a", "--format", "rar14", "--not-a-real-option"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unexpected argument '--not-a-real-option'"));
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_password_required(output: &std::process::Output) {
    assert!(!output.status.success());
    let stderr = stderr(output);
    assert!(
        stderr.contains("password is required"),
        "stderr did not report a missing password: {stderr}"
    );
}

fn assert_wrong_password(output: &std::process::Output) {
    assert!(!output.status.success());
    let stderr = stderr(output);
    assert!(
        stderr.contains("wrong password or corrupt encrypted data"),
        "stderr did not report a bad password: {stderr}"
    );
}

fn assert_archive_tests_and_extracts_file(
    archive: &Path,
    password: Option<&str>,
    name: &str,
    expected: &[u8],
) {
    assert_archive_tests_and_extracts_files(archive, password, &[(name, expected)]);
}

fn assert_archive_tests_and_extracts_files(
    archive: &Path,
    password: Option<&str>,
    expected_files: &[(&str, &[u8])],
) {
    let mut test_command = rars();
    test_command.arg("test");
    if let Some(password) = password {
        test_command.args(["--password", password]);
    }
    let test = test_command.arg(archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    let test_stdout = stdout(&test);
    for (name, _) in expected_files {
        assert!(test_stdout.contains(&format!("OK {name}")));
    }

    let out_dir = scratch("assert-extract");
    let mut extract_command = rars();
    extract_command.arg("x");
    if let Some(password) = password {
        extract_command.args(["--password", password]);
    }
    let extract = extract_command.arg(archive).arg(&out_dir).output().unwrap();
    assert!(extract.status.success(), "stderr: {}", stderr(&extract));
    for (name, expected) in expected_files {
        assert_eq!(fs::read(out_dir.join(name)).unwrap(), *expected);
    }
}

fn assert_archive_set_tests_and_extracts_file(
    archives: &[PathBuf],
    password: Option<&str>,
    name: &str,
    expected: &[u8],
) {
    let mut test_command = rars();
    test_command.arg("test");
    if let Some(password) = password {
        test_command.args(["--password", password]);
    }
    let test = test_command.args(archives).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains(&format!("OK {name}")));

    let out_dir = scratch("assert-extract-volumes");
    let mut extract_command = rars();
    extract_command.arg("x");
    if let Some(password) = password {
        extract_command.args(["--password", password]);
    }
    let extract = extract_command
        .args(archives)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(extract.status.success(), "stderr: {}", stderr(&extract));
    assert_eq!(fs::read(out_dir.join(name)).unwrap(), expected);
}

fn expected_rar15_40_stored_volume_payload() -> Vec<u8> {
    "RAR 3.00 stored multivolume fixture line.\n"
        .repeat(80)
        .into_bytes()
}

fn expected_rar15_40_compressed_text_payload() -> Vec<u8> {
    "Hello, RAR 3.x fixture world.\n".repeat(80).into_bytes()
}

/// `--store` must not compress.
#[test]
fn stored_rar50_members_hold_their_payload_verbatim() {
    let dir = scratch("rar50-store-verbatim");
    let source = dir.join("payload.txt");
    let archive = dir.join("stored.rar");
    // Compressible enough that an encoder would happily shrink it.
    let payload = b"stored payload that compresses very well indeed\n".repeat(64);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let bytes = fs::read(&archive).unwrap();
    assert!(
        bytes
            .windows(payload.len())
            .any(|window| window == payload.as_slice()),
        "a stored member must appear in the archive unchanged"
    );

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
}

/// RAR 5 looks for a data filter by default, which is what makes executables
/// compress well. `--no-filter` opts out.
#[test]
fn rar50_looks_for_a_data_filter_by_default() {
    let dir = scratch("rar50-default-filter");
    let source = dir.join("program.bin");
    // x86-shaped: call instructions with absolute targets, which the E8
    // filter rewrites into something far more repetitive.
    let mut data = Vec::new();
    for index in 0..40_000u32 {
        data.push(0xe8);
        data.extend_from_slice(&index.wrapping_mul(4).to_le_bytes());
        data.extend_from_slice(b"\x55\x89\xe5\x83\xec");
    }
    fs::write(&source, &data).unwrap();

    let filtered = dir.join("filtered.rar");
    let plain = dir.join("plain.rar");
    for (path, extra) in [(&filtered, None), (&plain, Some("--no-filter"))] {
        let mut command = rars();
        command.args(["a", "--format", "rar50"]);
        if let Some(extra) = extra {
            command.arg(extra);
        }
        let output = command.arg(path).arg(&source).output().unwrap();
        assert!(output.status.success(), "stderr: {}", stderr(&output));
    }

    let filtered_len = fs::metadata(&filtered).unwrap().len();
    let plain_len = fs::metadata(&plain).unwrap().len();
    assert!(
        filtered_len < plain_len,
        "the default should find the filter: {filtered_len} vs {plain_len} unfiltered"
    );

    let test = rars().arg("test").arg(&filtered).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
}

/// An explicit filter combines with encryption, recovery records, comments,
/// metadata, volumes and solid mode. None of those is a format limit.
#[test]
fn rar5_explicit_filters_combine_with_the_rest_of_the_writer() {
    let dir = scratch("rar5-filters-combine");
    let source = dir.join("payload.bin");
    let mut payload = vec![0x41u8; 300_000];
    for index in 0..4_000u32 {
        let pos = 8_000 + index as usize * 64;
        payload[pos] = 0xe8;
        payload[pos + 1..pos + 5].copy_from_slice(&(0x3000u32 + index).to_le_bytes());
    }
    fs::write(&source, &payload).unwrap();

    for (name, extra) in [
        ("password", vec!["--password", "pw"]),
        ("recovery", vec!["--recovery-percent", "5"]),
        ("comment", vec!["--comment", "hello"]),
        ("metadata", vec!["--archive-name", "set.rar"]),
        ("file-comment", vec!["--file-comment", "note"]),
    ] {
        let archive = dir.join(format!("{name}.rar"));
        // The fastest level still applies the filter, and what is under test
        // is whether the writer takes the combination at all. The default
        // level's match search on this run-heavy payload was nearly all of
        // the test's time.
        let output = rars()
            .args(["a", "--format", "rar50", "--e8-filter", "--level", "1"])
            .args(&extra)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "--e8-filter with {name} was refused: {}",
            stderr(&output)
        );
        assert!(archive.exists(), "{name} wrote no archive");
    }
}

/// Every flag-and-format pair the add path refuses, with its exact wording.
///
/// Full equality rather than `contains`, because the convention of matching a
/// prefix is why these messages grew three different openers and two tense
/// conventions without anyone noticing.
const REJECTED_COMBINATIONS: &[(&[&str], &str)] = &[
    (
        &["--format", "rar14", "--dict-size", "512k"],
        "error: --dict-size is not supported by --format rar14; use --format rar15, \
         --format rar20, --format rar29, --format rar30, --format rar40, --format rar50 \
         or --format rar70",
    ),
    (
        &["--format", "rar14", "--quick-open"],
        "error: --quick-open is not supported by --format rar14; use --format rar50 \
         or --format rar70",
    ),
    (
        &["--format", "rar29", "--recovery-percent", "5"],
        "error: --recovery-percent is not supported by --format rar29; use --format rar50 \
         or --format rar70",
    ),
    (
        &["--format", "rar29", "--archive-name", "set.rar"],
        "error: --archive-name is not supported by --format rar29; use --format rar50 \
         or --format rar70",
    ),
    (
        &["--format", "rar15", "--encrypt-headers", "--password", "pw"],
        "error: --encrypt-headers is not supported by --format rar15; use --format rar29, \
         --format rar30, --format rar40, --format rar50 or --format rar70",
    ),
    (
        &["--format", "rar50", "--rgb-filter", "3"],
        "error: --rgb-filter is not supported by --format rar50; use --format rar29, \
         --format rar30 or --format rar40",
    ),
    (
        &["--format", "rar50", "--itanium-filter"],
        "error: --itanium-filter is not supported by --format rar50; use --format rar29, \
         --format rar30 or --format rar40",
    ),
    (
        &["--format", "rar29", "--arm-filter"],
        "error: --arm-filter is not supported by --format rar29; use --format rar50 \
         or --format rar70",
    ),
    (
        &["--format", "rar14", "--volume-size", "1m", "--password", "pw"],
        "error: --password is not supported by --format rar14 (in a volume set); use --format rar15, \
         --format rar20, --format rar29, --format rar30, --format rar40, --format rar50 \
         or --format rar70",
    ),
    (
        &["--format", "rar15", "--volume-size", "1m", "--temp-dir", "."],
        "error: --temp-dir is not supported by --format rar15 (in a volume set); use --format rar14, \
         --format rar50 or --format rar70",
    ),
    // Two filters have to be reported as the conflict they are. Asking which
    // one the format supports has no answer, and the two checks rank the flags
    // differently, so the format check would name a flag it never looked at.
    (
        &[
            "--format",
            "rar50",
            "--delta-filter",
            "1",
            "--itanium-filter",
        ],
        "error: only one filter can be asked for at a time",
    ),
    (
        &["--format", "rar29", "--e8-filter", "--audio-filter", "2"],
        "error: only one filter can be asked for at a time",
    ),
];

#[test]
fn add_refuses_unsupported_flags_by_name_and_says_where_to_go() {
    let dir = scratch("add-rejections");
    let source = dir.join("payload.txt");
    fs::write(&source, b"payload\n").unwrap();

    for (extra, expected) in REJECTED_COMBINATIONS {
        let archive = dir.join("created.rar");
        let _ = fs::remove_file(&archive);
        let output = rars()
            .arg("a")
            .args(*extra)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();

        assert_eq!(
            output.status.code(),
            Some(2),
            "{extra:?} should be a usage error\n{}",
            stderr(&output)
        );
        assert_eq!(stderr(&output).trim(), *expected, "{extra:?}");
        assert!(!archive.exists(), "{extra:?} still wrote an archive");
    }
}

/// The mirror of the table above. A flag asking for what the format already
/// does has to stay silent, or refusing things becomes its own kind of noise.
#[test]
fn add_accepts_flags_that_ask_for_what_already_happens() {
    let dir = scratch("add-silent-acceptance");
    let source = dir.join("payload.txt");
    fs::write(&source, b"payload that compresses a little\n".repeat(64)).unwrap();

    for (index, extra) in [
        // Neither format looks for a filter, so asking it not to changes nothing.
        vec!["--format", "rar14", "--no-filter"],
        vec!["--format", "rar20", "--no-filter"],
        // RAR 5 already searches by default.
        vec!["--format", "rar50", "--auto-filter"],
        // RAR 1.3 does write solid archives.
        vec!["--format", "rar14", "--solid"],
        // The legacy writers stream, so a budget bounds them too.
        vec!["--format", "rar29", "--memory-limit", "64m"],
        // RAR 2.9 does search, so turning it off is a real request.
        vec!["--format", "rar29", "--no-filter"],
    ]
    .into_iter()
    .enumerate()
    {
        let archive = dir.join(format!("quiet{index}.rar"));
        let output = rars()
            .arg("a")
            .args(&extra)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{extra:?} was refused: {}",
            stderr(&output)
        );
        assert!(
            !stderr(&output).contains("warning"),
            "{extra:?} warned: {}",
            stderr(&output)
        );
    }
}

#[test]
fn no_filter_turns_off_the_rar29_search() {
    let dir = scratch("rar29-no-filter");
    let source = dir.join("payload.bin");
    // x86 calls to a fixed target, which is what an E8 filter is for. Without
    // the filter the displacements stay different from each other and the
    // member compresses worse.
    const TARGET: u32 = 0x0020_1000;
    let mut payload = Vec::new();
    while payload.len() < 400_000 {
        let position = payload.len() as u32;
        payload.push(0xe8);
        payload.extend_from_slice(&TARGET.wrapping_sub(position).to_le_bytes());
        payload.extend_from_slice(&[0x90; 11]);
    }
    fs::write(&source, &payload).unwrap();

    let mut sizes = Vec::new();
    for extra in [&[][..], &["--no-filter"][..]] {
        let archive = dir.join(format!("out{}.rar", extra.len()));
        let output = rars()
            .args(["a", "--format", "rar29"])
            .args(extra)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();
        assert!(output.status.success(), "stderr: {}", stderr(&output));

        let test = rars().arg("test").arg(&archive).output().unwrap();
        assert!(test.status.success(), "stderr: {}", stderr(&test));
        sizes.push(fs::metadata(&archive).unwrap().len());
    }

    assert!(
        sizes[0] < sizes[1],
        "--no-filter did not turn the search off: {} filtered against {} unfiltered",
        sizes[0],
        sizes[1]
    );
}

#[cfg(unix)]
#[test]
fn extract_distinguishes_missing_mtime_from_epoch_for_files_and_directories() {
    let dir = scratch("missing-and-epoch-mtime");
    let archive = dir.join("times.rar");
    let out = dir.join("out");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50).store(true);
    for (name, time) in [
        ("missing", None),
        ("epoch", Some(rars::Timestamp::from_unix_seconds(0))),
    ] {
        builder
            .add_directory(name.as_bytes().to_vec(), time, None)
            .unwrap();
        builder
            .add_bytes(
                format!("{name}/file").into_bytes(),
                b"payload".to_vec(),
                time,
                None,
            )
            .unwrap();
    }
    builder.write_to_path(&archive, None).unwrap();
    // Pre-existing destinations give missing timestamps a deterministic value:
    // directory creation leaves it alone, and file writes set a current time.
    let retained = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fs::create_dir_all(out.join("missing")).unwrap();
    fs::write(out.join("missing/file"), b"old").unwrap();
    fs::File::open(out.join("missing"))
        .unwrap()
        .set_modified(retained)
        .unwrap();
    let result = rars()
        .arg("x")
        .arg("--overwrite=always")
        .arg(&archive)
        .arg(&out)
        .output()
        .unwrap();
    assert!(result.status.success(), "stderr: {}", stderr(&result));
    for path in ["epoch", "epoch/file"] {
        assert_eq!(
            fs::metadata(out.join(path)).unwrap().modified().unwrap(),
            UNIX_EPOCH
        );
    }
    assert_eq!(
        fs::metadata(out.join("missing"))
            .unwrap()
            .modified()
            .unwrap(),
        retained
    );
    assert!(
        fs::metadata(out.join("missing/file"))
            .unwrap()
            .modified()
            .unwrap()
            > retained
    );
}

#[cfg(unix)]
#[test]
fn native_filename_round_trip_across_archive_generations() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("native-filenames");
    let raw_names = scratch::supports_raw_byte_names(&dir);
    let input = dir.join(OsStr::from_bytes(if raw_names {
        b"tree-\xfe"
    } else {
        "tree-日本語".as_bytes()
    }));
    fs::create_dir(&input).unwrap();
    let all_names: &[&[u8]] = &[
        b"file-\xff",
        b"file-\xfe",
        "file-\u{fffd}".as_bytes(),
        "private-\u{e0ff}".as_bytes(),
        "marker-\u{fffe}".as_bytes(),
    ];
    let mut names = Vec::new();
    for &name in all_names {
        match fs::write(input.join(OsStr::from_bytes(name)), name) {
            Ok(()) => names.push(name),
            Err(error)
                if error.kind() == io::ErrorKind::InvalidInput
                    || error.raw_os_error() == Some(libc::EILSEQ) =>
            {
                // Unrepresentable names are covered by the rejection test below.
            }
            Err(error) => panic!("failed to create filename fixture {name:?}: {error}"),
        }
    }
    let direct = dir.join(OsStr::from_bytes(if raw_names {
        b"direct-\xfd"
    } else {
        "direct-кириллица".as_bytes()
    }));
    fs::write(&direct, b"direct").unwrap();
    for format in [
        "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
    ] {
        let archive = dir
            .join(OsStr::from_bytes(format!("{format}-").as_bytes()))
            .with_extension(OsStr::from_bytes(if raw_names {
                b"\xff.rar"
            } else {
                b"rar"
            }));
        let out = dir
            .join(OsStr::from_bytes(format!("out-{format}-").as_bytes()))
            .with_extension(OsStr::from_bytes(if raw_names {
                b"\xfe"
            } else {
                b"unicode"
            }));
        let add = rars()
            .args(["a", "--store", "--format", format])
            .arg(&archive)
            .arg(&input)
            .arg(&direct)
            .output()
            .unwrap();
        assert!(add.status.success(), "{format}: {}", stderr(&add));
        for command in ["info", "test"] {
            let result = rars().arg(command).arg(&archive).output().unwrap();
            assert!(
                result.status.success(),
                "{format} {command}: {}",
                stderr(&result)
            );
        }
        let extract = rars().arg("x").arg(&archive).arg(&out).output().unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        for name in &names {
            assert_eq!(
                fs::read(
                    out.join(input.file_name().unwrap())
                        .join(OsStr::from_bytes(name))
                )
                .unwrap(),
                **name,
                "{format}"
            );
        }
        assert_eq!(
            fs::read(out.join(direct.file_name().unwrap())).unwrap(),
            b"direct"
        );
        if ["rar50", "rar70"].contains(&format) {
            let reference_out = dir.join(format!("unrar-{format}"));
            fs::create_dir(&reference_out).unwrap();
            match Command::new("unrar")
                .env("LC_ALL", "C.UTF-8")
                .args(["x", "-idq", "-o+"])
                .arg(&archive)
                .current_dir(&reference_out)
                .output()
            {
                Ok(result) => {
                    assert!(result.status.success(), "{}", stderr(&result));
                    for name in &names {
                        assert_eq!(
                            fs::read(
                                reference_out
                                    .join(input.file_name().unwrap())
                                    .join(OsStr::from_bytes(name))
                            )
                            .unwrap(),
                            **name
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    eprintln!("unrar unavailable; reference check skipped")
                }
                Err(error) => panic!("unrar: {error}"),
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn native_archive_names_unsupported_by_the_filesystem_are_rejected() {
    use rars::ArchiveVersion;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("unrepresentable-native-names");
    for (index, name) in [b"file-\xff".as_slice(), "marker-\u{fffe}".as_bytes()]
        .into_iter()
        .enumerate()
    {
        let probe = dir.join(OsStr::from_bytes(name));
        match fs::write(&probe, b"probe") {
            Ok(()) => {
                fs::remove_file(probe).unwrap();
                continue;
            }
            Err(error)
                if error.kind() == io::ErrorKind::InvalidInput
                    || error.raw_os_error() == Some(libc::EILSEQ) => {}
            Err(error) => panic!("filename probe failed unexpectedly: {error}"),
        }
        for version in [
            ArchiveVersion::Rar14,
            ArchiveVersion::Rar15,
            ArchiveVersion::Rar20,
            ArchiveVersion::Rar29,
            ArchiveVersion::Rar30,
            ArchiveVersion::Rar40,
            ArchiveVersion::Rar50,
            ArchiveVersion::Rar70,
        ] {
            let modern = matches!(version, ArchiveVersion::Rar50 | ArchiveVersion::Rar70);
            let archive_name = if modern {
                rars::filename::encode_rar50(name).into_owned()
            } else {
                name.to_vec()
            };
            let mut builder = rars::Builder::new(version).store(true);
            builder
                .add_bytes(
                    archive_name,
                    b"payload".to_vec(),
                    None,
                    modern.then_some(0o644),
                )
                .unwrap();
            let archive = dir.join(format!("{version}-{index}.rar"));
            builder.write_to_path(&archive, None).unwrap();
            let out = dir.join(format!("{version}-{index}-out"));
            let extract = rars().arg("x").arg(&archive).arg(&out).output().unwrap();
            assert!(
                !extract.status.success(),
                "{version}: unrepresentable name must not be substituted"
            );
            assert!(
                stderr(&extract).contains("failed to write extracted entry"),
                "{version}: {}",
                stderr(&extract)
            );
            if out.exists() {
                assert_eq!(
                    fs::read_dir(&out).unwrap().count(),
                    0,
                    "{version}: no replacement filenames"
                );
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn native_filename_encrypted_volume_round_trip() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = scratch("native-encrypted-volumes");
    let raw_names = scratch::supports_raw_byte_names(&dir);
    let source = dir.join(OsStr::from_bytes(if raw_names {
        b"member-\xff"
    } else {
        "member-日本語".as_bytes()
    }));
    let password = dir.join(OsStr::from_bytes(if raw_names {
        b"password-\xfe"
    } else {
        "password-кириллица".as_bytes()
    }));
    let payload = deterministic_noise(4096);
    fs::write(&source, &payload).unwrap();
    fs::write(&password, b"password").unwrap();
    for format in ["rar30", "rar50"] {
        let root = dir.join(format);
        fs::create_dir(&root).unwrap();
        let archive = root.join(OsStr::from_bytes(if raw_names {
            b"archive-\xff.rar"
        } else {
            "archive-日本語.rar".as_bytes()
        }));
        let add = rars()
            .args([
                "a",
                "--format",
                format,
                "--encrypt-headers",
                "--volume-size",
                "1k",
                "--password-file",
            ])
            .arg(&password)
            .arg(&archive)
            .arg(&source)
            .output()
            .unwrap();
        assert!(add.status.success(), "{format}: {}", stderr(&add));
        let first = if format == "rar50" {
            root.join(OsStr::from_bytes(if raw_names {
                b"archive-\xff.part01.rar"
            } else {
                "archive-日本語.part01.rar".as_bytes()
            }))
        } else {
            archive
        };
        let out = root.join(OsStr::from_bytes(if raw_names {
            b"out-\xfe"
        } else {
            "out-日本語".as_bytes()
        }));
        let extract = rars()
            .args(["x", "--password-file"])
            .arg(&password)
            .arg(first.file_name().unwrap())
            .arg(&out)
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        assert_eq!(
            fs::read(out.join(source.file_name().unwrap())).unwrap(),
            payload
        );
    }
}

#[test]
fn reader_policy_flags_apply_to_parsing_comments_and_extraction() {
    let dir = scratch::case("cli-reader-policies");
    for format in [
        rars::ArchiveVersion::Rar14,
        rars::ArchiveVersion::Rar29,
        rars::ArchiveVersion::Rar50,
    ] {
        let mut builder = rars::Builder::new(format)
            .store(true)
            .comment(Some(b"comment".to_vec()));
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let archive = dir.join(format!("{format}.rar"));
        fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
        let output = dir.join(format!("{format}-out"));
        fs::create_dir(&output).unwrap();
        fs::write(output.join("file"), b"keep").unwrap();
        for flag in [
            "--max-header-count",
            "--max-header-bytes",
            "--max-member-output-bytes",
            "--max-total-output-bytes",
        ] {
            for command in ["info", "test", "extract"] {
                let mut child = rars();
                child.args([command, flag, "0"]).arg(&archive);
                if command == "extract" {
                    child.arg(&output);
                }
                let result = child.output().unwrap();
                assert!(!result.status.success(), "{format} {command} {flag}");
                assert!(stderr(&result).contains("limit"), "{}", stderr(&result));
                assert_eq!(fs::read(output.join("file")).unwrap(), b"keep");
            }
        }
        assert!(rars()
            .arg("test")
            .arg(&archive)
            .output()
            .unwrap()
            .status
            .success());
    }
}

#[test]
fn reader_workspace_flag_reaches_comment_and_extraction_decoders() {
    let dir = scratch::case("cli-reader-workspace");
    let mut builder = rars::Builder::new(rars::ArchiveVersion::Rar50)
        .comment(Some(b"compressed comment".repeat(32)));
    builder
        .add_bytes(
            b"file".to_vec(),
            b"compressed payload".repeat(32),
            None,
            None,
        )
        .unwrap();
    let archive = dir.join("workspace.rar");
    fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
    for command in ["info", "test", "extract"] {
        for limit in ["1", "64m"] {
            let mut child = rars();
            child
                .args([command, "--max-reader-workspace-bytes", limit])
                .arg(&archive);
            if command == "extract" {
                child.arg(dir.join(format!("out-{limit}")));
            }
            let result = child.output().unwrap();
            assert_eq!(
                result.status.success(),
                limit == "64m",
                "{command}: {}",
                stderr(&result)
            );
            if limit == "1" {
                assert!(stderr(&result).contains("workspace"));
            }
        }
    }
}

#[test]
fn cli_scratch_policy_decodes_filtered_members_and_cleans_up() {
    use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions};
    use rars::{ArchiveVersion, EntrySource, FeatureSet, FilterKind, FilterPolicy};
    let dir = scratch::case("cli-reader-scratch");
    let payload = [0xe8, 1, 0, 0, 0, 0xe9, 3, 0, 0, 0].repeat(1000);
    let data = Rar50Writer::new(WriterOptions::new(
        ArchiveVersion::Rar50,
        FeatureSet::store_only(),
    ))
    .entries([ArchiveEntry::new(
        b"file".to_vec(),
        EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(payload)),
    )])
    .filter_policy(FilterPolicy::explicit(FilterKind::E8E9))
    .finish()
    .unwrap();
    let archive = dir.join("archive.rar");
    fs::write(&archive, data).unwrap();
    let scratch_dir = dir.join("scratch");
    fs::create_dir(&scratch_dir).unwrap();
    let rejected = rars()
        .args(["test", "--rar50-dictionary-size-limit", "0"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let result = rars()
        .args([
            "test",
            "--rar50-buffered-decode-limit",
            "0",
            "--rar50-scratch-bytes",
            "100k",
            "--rar50-filter-memory-limit",
            "64k",
            "--rar50-scratch-dir",
        ])
        .arg(&scratch_dir)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", stderr(&result));
    assert_eq!(fs::read_dir(&scratch_dir).unwrap().count(), 0);
}

#[test]
fn legacy_name_encoding_controls_listing_and_extraction() {
    for format in [
        rars::ArchiveVersion::Rar14,
        rars::ArchiveVersion::Rar29,
        rars::ArchiveVersion::Rar40,
    ] {
        let work = scratch("legacy-name-encoding");
        let archive = work.join("input.rar");
        let mut builder = rars::Builder::new(format).store(true);
        builder
            .add_bytes(b"caf\x82.txt".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
        for verbose in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_rars"));
            command.args(["info", "--legacy-name-encoding", "cp850"]);
            if verbose {
                command.arg("--verbose");
            }
            let result = command.arg(&archive).output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8_lossy(&result.stdout).contains("café.txt"));
        }
        let out = work.join("out");
        let result = Command::new(env!("CARGO_BIN_EXE_rars"))
            .args(["x", "--legacy-name-encoding", "cp850"])
            .arg(&archive)
            .arg(&out)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(out.join("café.txt")).unwrap(), b"payload");
    }
}

#[test]
fn legacy_name_encoding_rejects_undefined_bytes_and_preserves_unicode() {
    let work = scratch("name-encoding-refusal");
    for (format, name, success) in [
        (rars::ArchiveVersion::Rar29, b"bad-\x81".as_slice(), false),
        (rars::ArchiveVersion::Rar50, "café.txt".as_bytes(), true),
    ] {
        let mut builder = rars::Builder::new(format).store(true);
        builder
            .add_bytes(name.to_vec(), b"data".to_vec(), None, None)
            .unwrap();
        let archive = work.join("input.rar");
        fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
        let out = work.join("out");
        let result = Command::new(env!("CARGO_BIN_EXE_rars"))
            .args(["x", "--legacy-name-encoding", "windows-1252"])
            .arg(&archive)
            .arg(&out)
            .output()
            .unwrap();
        assert_eq!(
            result.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if success {
            assert_eq!(fs::read(out.join("café.txt")).unwrap(), b"data");
        } else {
            assert!(!out.exists() || fs::read_dir(&out).unwrap().next().is_none());
        }
    }
}

#[test]
fn aggregate_memory_policy_refuses_without_replacing_output() {
    let root = scratch("aggregate-memory");
    fs::write(root.join("input"), vec![42; 8192]).unwrap();
    fs::write(root.join("archive.rar"), b"original").unwrap();
    for (format, limit, success) in [
        ("rar50", "0", false),
        ("rar29", "16m", false),
        ("rar50", "16m", true),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rars"))
            .current_dir(&*root)
            .args([
                "a",
                "archive.rar",
                "input",
                "--format",
                format,
                "--store",
                "--max-memory",
                limit,
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !success {
            assert_eq!(fs::read(root.join("archive.rar")).unwrap(), b"original");
            assert_eq!(fs::read_dir(&*root).unwrap().count(), 2);
        } else {
            rars::ArchiveReader::read(&fs::read(root.join("archive.rar")).unwrap())
                .unwrap()
                .test(None)
                .unwrap();
        }
    }
}

#[test]
fn custom_rar3_vm_programs_need_the_allow_flag() {
    let archive = fixture_rar15_40("rarvm/generic_delta_padding_mutation.rar");
    let refused = rars().arg("test").arg(&archive).output().unwrap();
    assert!(!refused.status.success());
    let message = stderr(&refused);
    assert!(
        message.contains("custom RAR 3 VM filter program"),
        "{message}"
    );
    assert!(message.contains("--allow-rar3-vm"), "{message}");

    let allowed = rars()
        .args(["test", "--allow-rar3-vm"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(allowed.status.success(), "stderr: {}", stderr(&allowed));
}

#[test]
fn volume_names_follow_the_case_of_the_first_volume() {
    // RAR names the volumes after SPLIT.RAR SPLIT.R00, SPLIT.R01, and new-style
    // ones SPLIT.part01.RAR. On a case-sensitive filesystem unrar looks for
    // exactly those names, so lowercase ones broke the set.
    let dir = scratch("volume-name-case");
    let source = dir.join("noise.bin");
    fs::write(&source, deterministic_noise(1500)).unwrap();
    for (format, first, later) in [
        ("rar29", "SPLIT.RAR", "SPLIT.R00"),
        ("rar50", "SPLIT.RAR", "SPLIT.part02.RAR"),
    ] {
        let out = dir.join(format);
        fs::create_dir_all(&out).unwrap();
        let create = rars()
            .args(["a", "--format", format, "--volume-size", "512"])
            .arg(out.join(first))
            .arg(&source)
            .output()
            .unwrap();
        assert!(create.status.success(), "stderr: {}", stderr(&create));
        let names: Vec<_> = fs::read_dir(&out)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names.iter().any(|name| name == later),
            "{format}: {names:?}"
        );
        assert!(
            names
                .iter()
                .all(|name| !name.ends_with(".rar") && !name.contains(".r0")),
            "{format}: {names:?}"
        );
        let first_path = if format == "rar50" {
            out.join("SPLIT.part01.RAR")
        } else {
            out.join(first)
        };
        let test = rars().arg("test").arg(first_path).output().unwrap();
        assert!(test.status.success(), "{format}: {}", stderr(&test));
    }
}

#[test]
fn legacy_volume_sets_hold_several_inputs_including_rar_sets() {
    let root = scratch("legacy-volume-set-members");
    let inner = root.join("inner");
    fs::create_dir(&inner).unwrap();
    let inner_source = root.join("inner.bin");
    fs::write(&inner_source, deterministic_noise(5_000)).unwrap();
    let create_inner = rars()
        .args(["add", "--format", "rar40", "--store", "--volume-size", "2k"])
        .arg(inner.join("release.rar"))
        .arg(&inner_source)
        .output()
        .unwrap();
    assert!(create_inner.status.success(), "{}", stderr(&create_inner));
    fs::create_dir(inner.join("empty")).unwrap();
    let movie = root.join("a.mkv");
    let notes = root.join("c.nfo");
    fs::write(&movie, deterministic_noise(9_000)).unwrap();
    fs::write(&notes, b"several members in one legacy set\n".repeat(40)).unwrap();
    let mut inputs: Vec<_> = fs::read_dir(&inner)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name != "empty")
        .collect();
    inputs.sort();
    assert!(inputs.len() > 1, "inner set should span volumes");

    let cases: [(&str, &[&str]); 6] = [
        ("rar40", &["--store"]),
        ("rar40", &[]),
        ("rar29", &[]),
        ("rar20", &["--store"]),
        ("rar40", &["--solid"]),
        ("rar40", &["--password", "secret", "--encrypt-headers"]),
    ];
    for (index, (format, flags)) in cases.into_iter().enumerate() {
        let case = root.join(format!("{index}-{format}"));
        fs::create_dir(&case).unwrap();
        let archive = case.join("out.rar");
        let password = flags.contains(&"--password");
        let mut create = rars();
        create.args(["add", "--format", format, "--volume-size", "3k"]);
        create.args(flags);
        let create = create
            .arg(&archive)
            .arg(&movie)
            .arg(&inner)
            .arg(&notes)
            .output()
            .unwrap();
        assert!(create.status.success(), "{format}: {}", stderr(&create));
        let out = case.join("x");
        let mut extract = rars();
        extract.arg("extract");
        if password {
            extract.args(["--password", "secret"]);
        }
        let extract = extract.arg(&archive).arg(&out).output().unwrap();
        assert!(extract.status.success(), "{format}: {}", stderr(&extract));
        assert_eq!(
            fs::read(out.join("a.mkv")).unwrap(),
            fs::read(&movie).unwrap()
        );
        assert_eq!(
            fs::read(out.join("c.nfo")).unwrap(),
            fs::read(&notes).unwrap()
        );
        assert!(out.join("inner/empty").is_dir());
        for name in &inputs {
            assert_eq!(
                fs::read(out.join("inner").join(name)).unwrap(),
                fs::read(inner.join(name)).unwrap(),
                "{format}: {name:?}"
            );
        }
        let mut test = rars();
        test.arg("test");
        if password {
            test.args(["--password", "secret"]);
        }
        let test = test.arg(&archive).output().unwrap();
        assert!(test.status.success(), "{format}: {}", stderr(&test));
        match Command::new("unrar")
            .args(["t", "-idq", if password { "-psecret" } else { "-p-" }])
            .arg(&archive)
            .output()
        {
            Ok(result) => assert!(result.status.success(), "{format}: {}", stderr(&result)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("unrar unavailable; reference check skipped")
            }
            Err(error) => panic!("unrar: {error}"),
        }
    }
}
