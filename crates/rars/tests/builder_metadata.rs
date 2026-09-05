#[path = "support/scratch.rs"]
mod scratch;

use rars::{ArchiveFamily, ArchiveReader, ArchiveVersion, Builder};

const MODES: [Option<u32>; 4] = [None, Some(0o640), Some(0o100750), Some(0)];

#[test]
fn member_attribute_source_uses_family_specific_host_rules() {
    use rars::AttrSource::{Dos, Unix, Unknown};

    let archive =
        ArchiveReader::read_owned(builder(ArchiveVersion::Rar50, true).to_bytes().unwrap())
            .unwrap();
    let mut meta = archive.members().next().unwrap().meta;
    for (family, host, expected) in [
        (ArchiveFamily::Rar13, None, Dos),
        (ArchiveFamily::Rar15To40, Some(0), Dos),
        (ArchiveFamily::Rar15To40, Some(1), Dos),
        (ArchiveFamily::Rar15To40, Some(2), Dos),
        (ArchiveFamily::Rar15To40, Some(3), Unix),
        (ArchiveFamily::Rar15To40, Some(4), Dos),
        (ArchiveFamily::Rar15To40, Some(5), Unix),
        (ArchiveFamily::Rar15To40, Some(6), Unknown),
        (ArchiveFamily::Rar15To40, Some(259), Unknown),
        (ArchiveFamily::Rar15To40, None, Unknown),
        (ArchiveFamily::Rar50Plus, Some(0), Dos),
        (ArchiveFamily::Rar50Plus, Some(1), Unix),
        (ArchiveFamily::Rar50Plus, Some(2), Unknown),
        (ArchiveFamily::Rar50Plus, None, Unknown),
    ] {
        meta.family = family;
        meta.host_os = host;
        assert_eq!(meta.attr_source(), expected, "{family:?}, {host:?}");
    }
}

fn builder(format: ArchiveVersion, store: bool) -> Builder {
    let mut builder = Builder::new(format).store(store);
    for (index, mode) in MODES.into_iter().enumerate() {
        builder
            .add_bytes(
                format!("file{index}").into_bytes(),
                b"payload".repeat(64),
                None,
                mode,
            )
            .unwrap();
    }
    builder
}

fn check_metadata(bytes: Vec<u8>, format: ArchiveVersion) {
    let archive = ArchiveReader::read_owned(bytes).unwrap();
    let members: Vec<_> = archive.members().collect();
    assert_eq!(members.len(), MODES.len());
    for (member, mode) in members.iter().zip(MODES) {
        // RAR 1.5 deliberately converts Unix metadata to DOS for compatibility.
        let mode = if format == ArchiveVersion::Rar15 {
            None
        } else {
            mode
        };
        let (host, attr) = match mode {
            None => (0, 0x20),
            Some(mode) => (
                if format.family() == ArchiveFamily::Rar50Plus {
                    1
                } else {
                    3
                },
                u64::from(mode | 0o100000),
            ),
        };
        assert_eq!(member.meta.host_os, Some(host));
        assert_eq!(member.meta.file_attr, attr);
        assert_eq!(
            archive
                .read_member(&member.meta.name, None)
                .unwrap()
                .unwrap(),
            b"payload".repeat(64)
        );
    }
}

#[test]
fn builder_pairs_host_ids_with_dos_or_unix_attributes() {
    for format in ArchiveVersion::ALL {
        if format.family() == ArchiveFamily::Rar13 {
            continue; // This family has no host field or Unix modes.
        }
        for store in [true, false] {
            check_metadata(builder(format, store).to_bytes().unwrap(), format);
        }
    }
}

#[test]
fn builder_volume_metadata_matches_single_archive_metadata() {
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for store in [true, false] {
            let volumes = builder(format, store)
                .volume_size(Some(4096))
                .build_volumes(None)
                .unwrap();
            assert_eq!(volumes.len(), 1);
            check_metadata(volumes.into_iter().next().unwrap(), format);
        }
    }
}

#[cfg(unix)]
#[test]
#[ignore = "requires the external unrar executable"]
fn reference_unrar_restores_builder_permissions() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let root = scratch::case("builder-host-attributes");
    let control = root.join("default-permissions");
    fs::write(&control, b"control").unwrap();
    let default_mode = fs::metadata(control).unwrap().permissions().mode() & 0o777;
    for format in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        for store in [true, false] {
            let archive = root.join(format!("{format}-{store}.rar"));
            let output = root.join(format!("{format}-{store}"));
            fs::create_dir(&output).unwrap();
            builder(format, store)
                .write_to_path(&archive, None)
                .unwrap();
            let result = Command::new("unrar")
                .args(["x", "-idq", "-o+"])
                .arg(&archive)
                .arg(format!("{}/", output.display()))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{format}: {} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            for (index, expected) in [default_mode, 0o640, 0o750, 0].into_iter().enumerate() {
                let expected = if format == ArchiveVersion::Rar15 {
                    default_mode
                } else {
                    expected
                };
                let path = output.join(format!("file{index}"));
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    expected,
                    "{format}, store={store}, file{index}"
                );
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                assert_eq!(fs::read(&path).unwrap(), b"payload".repeat(64));
            }
        }
    }
}
