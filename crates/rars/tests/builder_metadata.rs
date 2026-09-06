#[path = "support/scratch.rs"]
mod scratch;

use rars::{ArchiveFamily, ArchiveReader, ArchiveVersion, Builder};

const MODES: [Option<u32>; 4] = [None, Some(0o640), Some(0o100750), Some(0)];

#[test]
fn builder_preserves_explicit_dos_attributes_in_all_writer_paths() {
    let flags = [0, 1, 2, 4, 0x20, 0x27, 0x80];
    let root = scratch::case("builder-dos-attributes");
    for format in ArchiveVersion::ALL {
        for store in [false, true] {
            let mut builder = Builder::new(format).store(store);
            for (index, attr) in flags.iter().enumerate() {
                let name = format!("file{index}").into_bytes();
                builder
                    .add_source(
                        name.clone(),
                        rars::EntrySource::from_bytes(b"DOS payload".to_vec()),
                        None,
                        Some(0o640),
                    )
                    .unwrap();
                builder.set_dos_attributes(&name, *attr).unwrap();
            }
            let path = root.join(format!("{format}-{store}.rar"));
            builder.write_to_path(&path, None).unwrap();
            let mut outputs = vec![builder.to_bytes().unwrap(), std::fs::read(path).unwrap()];
            if format.family() == ArchiveFamily::Rar50Plus {
                outputs.extend(builder.volume_size(Some(4096)).build_volumes(None).unwrap());
            }
            for bytes in outputs {
                let archive = ArchiveReader::read_owned(bytes).unwrap();
                let members: Vec<_> = archive.members().collect();
                assert_eq!(members.len(), flags.len());
                for (member, attr) in members.iter().zip(flags) {
                    assert_eq!(member.meta.attr_source(), rars::AttrSource::Dos);
                    assert_eq!(member.meta.file_attr, attr, "{format}, store={store}");
                    assert!(!member.meta.is_directory);
                    assert_eq!(
                        archive
                            .read_member(&member.meta.name, None)
                            .unwrap()
                            .unwrap(),
                        b"DOS payload"
                    );
                }
            }
        }
    }
}

#[test]
fn invalid_dos_attributes_leave_builder_metadata_unchanged() {
    for (format, oversized) in [
        (ArchiveVersion::Rar14, Some(256)),
        (ArchiveVersion::Rar29, Some(u64::from(u32::MAX) + 1)),
        (ArchiveVersion::Rar50, None),
    ] {
        let mut builder = builder(format, true);
        let before = builder.to_bytes().unwrap();
        assert!(builder.set_dos_attributes(b"missing", 0x20).is_err());
        assert!(builder.set_dos_attributes(b"file1", 0x10).is_err());
        if let Some(oversized) = oversized {
            assert!(builder.set_dos_attributes(b"file1", oversized).is_err());
        }
        assert_eq!(builder.to_bytes().unwrap(), before);
    }
}

#[test]
fn dos_attribute_field_width_is_not_truncated() {
    for (format, attr) in [
        (ArchiveVersion::Rar14, 0xef),
        (ArchiveVersion::Rar29, u64::from(u32::MAX) & !0x10),
        (ArchiveVersion::Rar50, !0x10u64),
    ] {
        let mut builder = builder(format, true);
        builder.set_dos_attributes(b"file1", attr).unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(archive.members().nth(1).unwrap().meta.file_attr, attr);
    }
}

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
