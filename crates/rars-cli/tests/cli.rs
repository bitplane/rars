use rars::crc32::crc32;
use rars::rar13::{write_stored_archive, StoredEntry, WriterOptions};
use rars::rar15_40;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rars-cli-{name}-{nonce}"));
    fs::create_dir_all(&path).unwrap();
    path
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
    assert!(stdout.contains("checksum=0xe079"));
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
    assert_eq!(fs::read(out_dir.join("README")).unwrap().len(), 2016);
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
fn rejects_non_utf8_output_path() {
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

    assert!(!extract.status.success());
    assert!(stderr(&extract).contains("unsafe archive path"));
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
    std::os::unix::fs::symlink(&target, out_dir.join("LINK.TXT")).unwrap();
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
    assert_eq!(members[0].meta.file_time, Some(1_700_000_002));
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

    let extract = rars()
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

    let mut command = rars();
    command
        .args(["test", "--password", "-"])
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
    assert!(stdout.contains("Usage: rars [OPTIONS] <COMMAND>"));
    assert!(stdout.contains("--threads <N>"));
    assert!(stdout.contains("Exit codes:"));
    assert!(stdout.contains("info"));
    assert!(stdout.contains("extract"));
    assert!(stdout.contains("add"));
}

#[test]
#[cfg(feature = "parallel")]
fn threads_flag_is_accepted_with_parallel_feature() {
    let output = rars()
        .args(["--threads", "1", "info"])
        .arg(fixture("README_store.rar"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
}

#[test]
#[cfg(not(feature = "parallel"))]
fn threads_flag_requires_parallel_feature() {
    let output = rars()
        .args(["--threads", "1", "info"])
        .arg(fixture("README_store.rar"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("--threads requires building rars-cli with --features parallel")
    );
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
    assert_eq!(file.host_os, 1);

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
    assert!(stderr(&output).contains("multivolume writer currently supports one input file"));
}

#[test]
fn creates_rar50_header_encrypted_recovery_volumes() {
    let dir = scratch("rar50-header-encrypted-recovery-volume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 header encrypted recovery volume cli payload\n".repeat(10),
    )
    .unwrap();

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
            "16",
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

    let second = rars()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(stderr(&second).contains("File exists"));

    let overwrite = rars()
        .args(["x", "--overwrite=always"])
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(overwrite.status.success(), "stderr: {}", stderr(&overwrite));
    assert_eq!(
        fs::read(out_dir.join("hello.txt")).unwrap(),
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
    let source = dir.join("line\nname.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"escaped display payload\n").unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

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
    assert!(stderr(&create).contains("--dict-size is available only for RAR 1.5+"));
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
fn creates_rar15_file_comment() {
    let dir = scratch("create-rar15-file-comment");
    let source = dir.join("commented.txt");
    let archive = dir.join("file-comment.rar");
    fs::write(&source, b"rar15 file commented payload\n").unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar15",
            "--file-comment",
            "rar15 file note",
        ])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let info = rars().args(["info", "-v"]).arg(&archive).output().unwrap();
    assert!(info.status.success(), "stderr: {}", stderr(&info));
    assert!(stdout(&info).contains("comment: rar15 file note"));

    let test = rars().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK commented.txt"));
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
    fs::write(&source, b"abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--store", "--volume-size", "10"])
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
    fs::write(&source, b"abcabcabcabcabcabcabcabcabcabcabcabcabcabc").unwrap();

    let create = rars()
        .args(["a", "--format", "rar14", "--volume-size", "8"])
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
    fs::write(&source, b"abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--store", "--volume-size", "10"])
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
    fs::write(&source, b"abcabcabcabcabcabcabcabcabcabcabcabcabcabc").unwrap();

    let create = rars()
        .args(["a", "--format", "rar15", "--volume-size", "8"])
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
    fs::write(
        &source,
        b"rar20 split phrase alpha beta gamma rar20 split phrase alpha beta gamma\n".repeat(24),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar20", "--volume-size", "8"])
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
    fs::write(
        &source,
        b"rar29 split phrase alpha beta gamma rar29 split phrase alpha beta gamma\n".repeat(24),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar29", "--volume-size", "8"])
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
    fs::write(
        &source,
        b"secret split compressed secret split compressed\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar15",
            "--volume-size",
            "8",
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
    fs::write(
        &source,
        b"rar30 secret split compressed rar30 secret split compressed\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--volume-size",
            "8",
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
    fs::write(
        &source,
        b"rar29 secret split compressed rar29 secret split compressed\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar29",
            "--volume-size",
            "8",
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
    fs::write(
        &source,
        b"rar30 header encrypted split compressed payload payload payload\n",
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--password",
            "pass",
            "--format",
            "rar30",
            "--encrypt-headers",
            "--volume-size",
            "8",
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
    assert!(stdout(&info).contains("method=1"));

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
    assert!(stdout(&info).contains("method=1"));

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
    fs::write(
        &source,
        b"rar50 encrypted stored volume cli payload\n".repeat(12),
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
            "--volume-size",
            "97",
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
    fs::write(
        &source,
        b"rar50 header encrypted stored volume cli payload\n".repeat(12),
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
            "--volume-size",
            "97",
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
    fs::write(&source, b"rar50 stored volume cli payload\n".repeat(20)).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--store", "--volume-size", "90"])
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
    fs::write(
        &source,
        b"rar50 stored recovery volume cli payload\n".repeat(20),
    )
    .unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--store",
            "--recovery-percent",
            "8",
            "--volume-size",
            "90",
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
    assert!(stdout(&test).contains("OK tmp\\\\rars-rar3-rev-gen\\\\payload.bin"));
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
    assert!(stdout(&test).contains("OK tmp\\\\rars-rar4-rev-gen\\\\payload.bin"));
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
    assert!(stdout(&info).contains("method=1"));

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
    let payload =
        b"rar50 compressed split cli payload\nrar50 compressed split cli payload\n".repeat(16);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--volume-size", "32"])
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
    assert!(stdout(&info).contains("method=1"));

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
    assert_eq!(file.method, 0x35);

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
    assert!(stdout(&info).contains("method=0x35"));

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
    assert!(stdout(&info).contains("method=0x35"));

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

    assert!(!output.status.success());
    assert!(stderr(&output).contains("--ppmd is only available"));
}

#[test]
fn creates_rar50_solid_compressed_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-rar50-solid-compressed-multivolume");
    let source = dir.join("payload.txt");
    let archive = dir.join("split.rar");
    fs::write(
        &source,
        b"rar50 solid compressed split cli payload\nrar50 solid compressed split cli payload\n"
            .repeat(16),
    )
    .unwrap();

    let create = rars()
        .args(["a", "--format", "rar50", "--solid", "--volume-size", "32"])
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
    assert!(stdout(&info).contains("rar50 main: flags=0x0007"));

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
    let payload =
        b"rar50 encrypted compressed split cli payload\nrar50 encrypted compressed split cli payload\n"
            .repeat(16);
    fs::write(&source, &payload).unwrap();

    let create = rars()
        .args([
            "a",
            "--format",
            "rar50",
            "--password",
            "pass",
            "--volume-size",
            "32",
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
    let payload =
        b"rar50 encrypted solid compressed split cli payload\nrar50 encrypted solid compressed split cli payload\n"
            .repeat(16);
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
            "32",
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
    let payload =
        b"rar50 header encrypted compressed split cli payload\nrar50 header encrypted compressed split cli payload\n"
            .repeat(16);
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
            "32",
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
    let payload =
        b"rar50 header encrypted solid compressed split cli payload\nrar50 header encrypted solid compressed split cli payload\n"
            .repeat(16);
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
            "32",
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
