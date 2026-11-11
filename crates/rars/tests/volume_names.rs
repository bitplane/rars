#![cfg(feature = "write")]

use rars::{ArchiveReader, ArchiveVersion, Builder};
use std::path::{Path, PathBuf};

/// A stand-in for an SFX module: it only has to put the archive at an offset.
fn stub() -> Vec<u8> {
    let mut stub = vec![0; 4096];
    stub[..2].copy_from_slice(b"MZ");
    stub
}

/// Writes a set whose first volume carries a stub and is named `first`; the rest follow `rest(index)`.
fn write_set(
    dir: &Path,
    version: ArchiveVersion,
    first: &str,
    rest: impl Fn(usize) -> String,
) -> Vec<PathBuf> {
    std::fs::create_dir_all(dir).unwrap();
    let mut builder = Builder::new(version).store(true).volume_size(Some(4096));
    builder
        .add_bytes(b"large.bin".to_vec(), vec![7; 20_000], None, None)
        .unwrap();
    let volumes = builder.build_volumes(None).unwrap();
    assert!(volumes.len() > 2);
    volumes
        .into_iter()
        .enumerate()
        .map(|(index, mut bytes)| {
            let path = if index == 0 {
                bytes.splice(0..0, stub());
                dir.join(first)
            } else {
                dir.join(rest(index))
            };
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect()
}

fn assert_found_by_name(paths: &[PathBuf]) {
    let archive = ArchiveReader::read_path(&paths[0]).unwrap();
    assert!(archive.sfx_offset() > 0);
    for (index, path) in paths.iter().enumerate() {
        assert_eq!(
            archive.volume_path(&paths[0], index).as_ref(),
            Some(path),
            "{index}"
        );
    }
}

fn scratch(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("volume_names")
        .join(name)
}

#[test]
fn a_self_extracting_rar5_first_volume_is_followed_by_rar_parts() {
    for (first, base) in [("set.part1.exe", "set"), ("SET.part1.sfx", "SET")] {
        let dir = scratch(&format!("rar50-{first}"));
        let paths = write_set(&dir, ArchiveVersion::Rar50, first, |index| {
            format!("{base}.part{}.rar", index + 1)
        });
        assert_found_by_name(&paths);
    }
}

#[test]
fn a_self_extracting_rar3_first_volume_is_followed_by_rar_parts() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar15_40/rar300");
    let dir = scratch("rar300");
    std::fs::create_dir_all(&dir).unwrap();
    let mut first = stub();
    first.extend(std::fs::read(fixtures.join("multivol_newnaming_rar300.part01.rar")).unwrap());
    let paths = [dir.join("set.part01.exe"), dir.join("set.part02.rar")];
    std::fs::write(&paths[0], first).unwrap();
    std::fs::copy(
        fixtures.join("multivol_newnaming_rar300.part02.rar"),
        &paths[1],
    )
    .unwrap();
    assert_found_by_name(&paths);
}

#[test]
fn an_old_style_self_extracting_first_volume_is_followed_by_r00() {
    for (first, ext) in [("set.exe", "r"), ("set.sfx", "r"), ("SET.EXE", "R")] {
        let dir = scratch(&format!("rar20-{first}"));
        let stem = &first[..first.len() - 4];
        let paths = write_set(&dir, ArchiveVersion::Rar20, first, |index| {
            format!("{stem}.{ext}{:02}", index - 1)
        });
        assert_found_by_name(&paths);
    }
}
