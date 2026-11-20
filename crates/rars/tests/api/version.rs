use rars::{ArchiveFamily, ArchiveVersion};

#[test]
fn maps_versions_to_archive_families() {
    let cases = [
        (ArchiveVersion::Rar13, ArchiveFamily::Rar13),
        (ArchiveVersion::Rar14, ArchiveFamily::Rar13),
        (ArchiveVersion::Rar15, ArchiveFamily::Rar15To40),
        (ArchiveVersion::Rar20, ArchiveFamily::Rar15To40),
        (ArchiveVersion::Rar29, ArchiveFamily::Rar15To40),
        (ArchiveVersion::Rar30, ArchiveFamily::Rar15To40),
        (ArchiveVersion::Rar40, ArchiveFamily::Rar15To40),
        (ArchiveVersion::Rar50, ArchiveFamily::Rar50Plus),
        (ArchiveVersion::Rar70, ArchiveFamily::Rar50Plus),
    ];

    for (version, family) in cases {
        assert_eq!(version.family(), family);
    }
}

#[test]
fn identifies_rar13_family_versions() {
    let cases = [
        (ArchiveVersion::Rar13, true),
        (ArchiveVersion::Rar14, true),
        (ArchiveVersion::Rar15, false),
        (ArchiveVersion::Rar20, false),
        (ArchiveVersion::Rar29, false),
        (ArchiveVersion::Rar30, false),
        (ArchiveVersion::Rar40, false),
        (ArchiveVersion::Rar50, false),
        (ArchiveVersion::Rar70, false),
    ];

    for (version, expected) in cases {
        assert_eq!(version.is_rar13_family(), expected);
    }
}
