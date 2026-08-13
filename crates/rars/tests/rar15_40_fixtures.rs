use rars::crc32::crc32;
use rars::rar15_40::{
    extract_volumes_to, repair_rev3_volumes_to, write_compressed_archive,
    write_compressed_archive_with_comment, write_compressed_volumes,
    write_rar29_compressed_archive_with_filter_policy, write_stored_archive,
    write_stored_archive_with_comment, write_stored_volumes, Archive, Block, FileEntry, FilterKind,
    FilterPolicy, FilterSpec, NewSubKind, ProtectHeader, Rar29Method, StoredEntry, WriterOptions,
};
use rars::{
    detect_archive_family, ArchiveFamily, ArchiveReadOptions, ArchiveVersion, Error, FeatureSet,
};
use std::cell::RefCell;
use std::io::{Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40")
        .join(name)
}

const RARS_GENERATED_PAYLOAD: &[u8] = b"rar15 oracle payload\n";
const RARS_GENERATED_SECOND: &[u8] = b"rar15 oracle second file\n";

fn level_sensitive_payload() -> Vec<u8> {
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
    data
}

const RARS_GENERATED_FIXTURE_BYTES: &[(&str, usize, u32)] = &[
    ("comments.rar", 122, 0x23ef_1c79),
    ("compressed.rar", 87, 0x13ca_0571),
    ("encrypted.rar", 87, 0x04af_0eb7),
    ("solid.rar", 153, 0x8deb_98d1),
    ("split-encrypted.r00", 73, 0xf109_611e),
    ("split-encrypted.r01", 67, 0x43b5_c214),
    ("split-encrypted.rar", 73, 0x5989_8212),
    ("split-store.r00", 73, 0x6926_da6f),
    ("split-store.r01", 64, 0x1f25_c044),
    ("split-store.rar", 73, 0x5440_b247),
    ("stored.rar", 84, 0x470d_272b),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectedEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    file_time: u32,
    attr: u32,
    host_os: u8,
    is_directory: bool,
}

struct CollectWriter {
    data: Rc<RefCell<Vec<u8>>>,
}

impl Write for CollectWriter {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.data.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

fn collect_extract(archive: &Archive) -> Result<Vec<CollectedEntry>, Error> {
    collect_extract_with_password(archive, None)
}

fn collect_extract_with_password(
    archive: &Archive,
    password: Option<&[u8]>,
) -> Result<Vec<CollectedEntry>, Error> {
    let entries = RefCell::new(Vec::new());
    archive.extract_to(read_options(password), |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter { data }))
    })?;
    Ok(entries
        .into_inner()
        .into_iter()
        .map(|(meta, data)| CollectedEntry {
            name: meta.name,
            data: data.borrow().clone(),
            file_time: meta.file_time,
            attr: meta.attr,
            host_os: meta.host_os,
            is_directory: meta.is_directory,
        })
        .collect())
}

fn collect_file(
    archive: &Archive,
    file: &rars::rar15_40::FileHeader,
) -> Result<CollectedEntry, Error> {
    collect_file_with_password(archive, file, None)
}

fn collect_file_with_password(
    archive: &Archive,
    file: &rars::rar15_40::FileHeader,
    password: Option<&[u8]>,
) -> Result<CollectedEntry, Error> {
    let meta = file.metadata();
    let data = Rc::new(RefCell::new(Vec::new()));
    file.write_to(
        archive,
        password,
        &mut CollectWriter {
            data: Rc::clone(&data),
        },
    )?;
    let data = data.borrow().clone();
    Ok(CollectedEntry {
        name: meta.name,
        data,
        file_time: meta.file_time,
        attr: meta.attr,
        host_os: meta.host_os,
        is_directory: meta.is_directory,
    })
}

fn collect_extract_volumes(archives: &[Archive]) -> Result<Vec<CollectedEntry>, Error> {
    collect_extract_volumes_with_password(archives, None)
}

fn collect_extract_volumes_with_password(
    archives: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<CollectedEntry>, Error> {
    let entries = RefCell::new(Vec::new());
    extract_volumes_to(archives, read_options(password), |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter { data }))
    })?;
    Ok(entries
        .into_inner()
        .into_iter()
        .map(|(meta, data)| CollectedEntry {
            name: meta.name,
            data: data.borrow().clone(),
            file_time: meta.file_time,
            attr: meta.attr,
            host_os: meta.host_os,
            is_directory: meta.is_directory,
        })
        .collect())
}

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::default(),
    }
}

#[derive(Debug, Clone)]
struct ReferenceUnrar {
    wineprefix: String,
    unrar: String,
}

fn reference_unrar(prefix_env: &str, unrar_env: &str) -> Option<ReferenceUnrar> {
    let wineprefix = match std::env::var(prefix_env) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("skipping reference test: set {prefix_env} to the WinRAR Wine prefix");
            return None;
        }
    };
    let unrar = std::env::var(unrar_env)
        .unwrap_or_else(|_| format!("{wineprefix}/drive_c/Program Files (x86)/WinRAR/UnRAR.exe"));
    if !Path::new(&unrar).is_file() {
        eprintln!("skipping reference test: missing reference tool {unrar}");
        return None;
    }
    Some(ReferenceUnrar { wineprefix, unrar })
}

fn reference_unrar300() -> Option<ReferenceUnrar> {
    reference_unrar("RARS_WINRAR300_PREFIX", "RARS_UNRAR300")
}

fn reference_unrar420() -> Option<ReferenceUnrar> {
    reference_unrar("RARS_WINRAR420_PREFIX", "RARS_UNRAR420")
}

fn run_reference_unrar(reference: &ReferenceUnrar, archive_path: &Path) -> std::process::Output {
    let wine_archive = format!("Z:{}", archive_path.to_string_lossy().replace('/', "\\"));
    Command::new("env")
        .arg(format!("WINEPREFIX={}", reference.wineprefix))
        .arg("wine")
        .arg(&reference.unrar)
        .arg("t")
        .arg("-inul")
        .arg(wine_archive)
        .output()
        .unwrap()
}

fn repair_rev3_volumes(
    data_volumes: &[Option<&[u8]>],
    recovery_count: usize,
    recovery_volumes: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>, Error> {
    let mut repaired = Vec::new();
    repair_rev3_volumes_to(
        data_volumes,
        recovery_count,
        recovery_volumes,
        |_, bytes| {
            repaired.push(bytes.to_vec());
            Ok(())
        },
    )?;
    Ok(repaired)
}

fn write_rar29_auto(entries: &[FileEntry<'_>], options: WriterOptions) -> Vec<u8> {
    write_rar29_compressed_archive_with_filter_policy(entries, options, FilterPolicy::Auto).unwrap()
}

fn write_rar29_filter(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    kind: FilterKind,
) -> Vec<u8> {
    write_rar29_compressed_archive_with_filter_policy(
        entries,
        options,
        FilterPolicy::Explicit(FilterSpec::whole(kind)),
    )
    .unwrap()
}

fn write_rar29_filter_range(
    entries: &[FileEntry<'_>],
    options: WriterOptions,
    kind: FilterKind,
    range: std::ops::Range<usize>,
) -> Vec<u8> {
    write_rar29_compressed_archive_with_filter_policy(
        entries,
        options,
        FilterPolicy::Explicit(FilterSpec::range(kind, range)),
    )
    .unwrap()
}

#[test]
fn detects_rar15_40_signature_family() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let sig = detect_archive_family(&bytes).unwrap();

    assert_eq!(sig.family, ArchiveFamily::Rar15To40);
    assert_eq!(sig.offset, 0);
    assert_eq!(sig.length, 7);
}

#[test]
fn generated_rar29_e8_filtered_archive_round_trips() {
    let payload = b"\xe8\0\0\0\0rar29 e8 filter payload\n".repeat(16);
    let entries = [FileEntry {
        name: b"rar29-e8-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::E8,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    assert!(file.pack_size < file.unp_size);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-e8-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_auto_filtered_archive_round_trips() {
    let payload = b"\xe8\0\0\0\0rar29 auto filtered payload\n".repeat(16);
    let entries = [FileEntry {
        name: b"rar29-auto-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_auto(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    let plain = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .unwrap();
    let plain_archive = Archive::parse(&plain).unwrap();
    let plain_file = plain_archive.files().next().unwrap();
    assert!(file.pack_size <= plain_file.pack_size);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-auto-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_auto_filtered_archive_considers_delta_candidates() {
    let payload: Vec<u8> = (0..768).map(|index| (index / 3) as u8).collect();
    let entries = [FileEntry {
        name: b"rar29-auto-delta-candidate.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let auto = write_rar29_auto(&entries, options);
    let explicit = write_rar29_filter(&entries, options, FilterKind::Delta { channels: 3 });
    let auto_archive = Archive::parse(&auto).unwrap();
    let explicit_archive = Archive::parse(&explicit).unwrap();
    let auto_file = auto_archive.files().next().unwrap();
    let explicit_file = explicit_archive.files().next().unwrap();

    assert!(auto_file.pack_size <= explicit_file.pack_size);
    let extracted = collect_extract(&auto_archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-auto-delta-candidate.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_auto_filtered_archive_considers_audio_candidates() {
    let payload: Vec<u8> = (0..512)
        .map(|index| (128 + ((index * 9) % 73) - ((index * 5) % 41)) as u8)
        .collect();
    let entries = [FileEntry {
        name: b"rar29-auto-audio-candidate.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let auto = write_rar29_auto(&entries, options);
    let explicit = write_rar29_filter(&entries, options, FilterKind::Audio { channels: 2 });
    let auto_archive = Archive::parse(&auto).unwrap();
    let explicit_archive = Archive::parse(&explicit).unwrap();
    let auto_file = auto_archive.files().next().unwrap();
    let explicit_file = explicit_archive.files().next().unwrap();

    assert!(auto_file.pack_size <= explicit_file.pack_size);
    let extracted = collect_extract(&auto_archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-auto-audio-candidate.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_auto_filtered_archive_considers_rgb_candidates() {
    let width = 24;
    let mut payload = Vec::new();
    for y in 0..32 {
        for x in 0..8 {
            payload.extend_from_slice(&[
                (x * 23 + y * 3) as u8,
                (x * 5 + y * 17) as u8,
                (x * 13 + y * 19) as u8,
            ]);
        }
    }
    let entries = [FileEntry {
        name: b"rar29-auto-rgb-candidate.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let auto = write_rar29_auto(&entries, options);
    let explicit = write_rar29_filter(&entries, options, FilterKind::Rgb { width, pos_r: 0 });
    let auto_archive = Archive::parse(&auto).unwrap();
    let explicit_archive = Archive::parse(&explicit).unwrap();
    let auto_file = auto_archive.files().next().unwrap();
    let explicit_file = explicit_archive.files().next().unwrap();

    assert!(auto_file.pack_size <= explicit_file.pack_size);
    let extracted = collect_extract(&auto_archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-auto-rgb-candidate.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_auto_filtered_archive_considers_itanium_candidates() {
    let payload = bytearray_like_itanium_payload(512);
    let entries = [FileEntry {
        name: b"rar29-auto-itanium-candidate.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let auto = write_rar29_auto(&entries, options);
    let explicit = write_rar29_filter(&entries, options, FilterKind::Itanium);
    let auto_archive = Archive::parse(&auto).unwrap();
    let explicit_archive = Archive::parse(&explicit).unwrap();
    let auto_file = auto_archive.files().next().unwrap();
    let explicit_file = explicit_archive.files().next().unwrap();

    assert!(auto_file.pack_size <= explicit_file.pack_size);
    let extracted = collect_extract(&auto_archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-auto-itanium-candidate.bin");
    assert_eq!(extracted[0].data, payload);
}

fn bytearray_like_itanium_payload(len: usize) -> Vec<u8> {
    let mut payload = vec![0u8; len];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index * 11 + 5) as u8;
    }
    for chunk in payload.chunks_mut(32) {
        if chunk.len() > 21 {
            chunk[16] = 22;
            chunk[21] = 20;
        }
    }
    payload
}

#[test]
fn generated_rar29_segmented_e8_filtered_archive_round_trips() {
    let mut payload = b"unfiltered prefix before x86 segment ".to_vec();
    let filter_start = payload.len();
    payload.extend_from_slice(b"\xe8\0\0\0\0rar29 segmented e8 filter payload\n");
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after x86 segment\n");
    let entries = [FileEntry {
        name: b"rar29-segmented-e8-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::E8,
        filter_start..filter_end,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-segmented-e8-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_solid_e8_filtered_archive_round_trips() {
    let first = b"\xe8\0\0\0\0rar29 solid e8 filtered first payload\n".repeat(12);
    let second = b"\xe8\0\0\0\0rar29 solid e8 filtered second payload\n".repeat(12);
    let entries = [
        FileEntry {
            name: b"rar29-solid-e8-first.bin",
            data: &first,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"rar29-solid-e8-second.bin",
            data: &second,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, features),
        FilterKind::E8,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-solid-e8-first.bin");
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].name, b"rar29-solid-e8-second.bin");
    assert_eq!(extracted[1].data, second);
}

#[test]
fn generated_rar29_encrypted_e8_filtered_archive_round_trips() {
    let payload = b"\xe8\0\0\0\0rar29 encrypted e8 filtered payload\n".repeat(12);
    let entries = [FileEntry {
        name: b"rar29-encrypted-e8-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let features = FeatureSet::store_only();

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, features),
        FilterKind::E8,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert!(file.is_encrypted());
    assert!(file.salt.is_some());
    assert!(matches!(
        collect_extract_with_password(&archive, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].name, b"rar29-encrypted-e8-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar30_header_encrypted_e8_filtered_archive_round_trips() {
    let payload = b"\xe8\0\0\0\0rar30 header encrypted e8 filtered payload\n".repeat(12);
    let entries = [FileEntry {
        name: b"rar30-header-encrypted-e8-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar30, features),
        FilterKind::E8,
    );

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    assert!(archive.main.has_encrypted_headers());
    let file = archive.files().next().unwrap();
    assert_eq!(file.name, b"rar30-header-encrypted-e8-filtered.bin");
    assert!(file.is_encrypted());
    assert!(file.salt.is_some());
    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[ignore = "requires WinRAR/UnRAR 3.00 and 4.20 Wine prefixes"]
fn reference_unrar_accepts_rar29_solid_e8_filter_record() {
    let Some(unrar300) = reference_unrar300() else {
        return;
    };
    let Some(unrar420) = reference_unrar420() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!("rars-rar29-solid-e8-ref-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("solid-e8.rar");
    let first = b"\xe8\0\0\0\0rar29 solid e8 first reference payload\n".repeat(12);
    let second = b"\xe8\0\0\0\0rar29 solid e8 second reference payload\n".repeat(12);
    let entries = [
        FileEntry {
            name: b"solid-e8-first.bin",
            data: &first,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-e8-second.bin",
            data: &second,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, features),
        FilterKind::E8,
    );
    std::fs::write(&archive_path, bytes).unwrap();

    for reference in [&unrar300, &unrar420] {
        let output = run_reference_unrar(reference, &archive_path);
        assert!(
            output.status.success(),
            "{} rejected solid E8 archive: status={:?}\nstdout={}\nstderr={}",
            reference.unrar,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "requires WinRAR/UnRAR 4.20 Wine prefix"]
fn reference_unrar_accepts_rar29_segmented_e8_filter_record() {
    let Some(reference) = reference_unrar420() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "rars-rar29-segmented-e8-ref-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("segmented-e8.rar");
    let mut payload = b"unfiltered prefix before x86 segment ".to_vec();
    let filter_start = payload.len();
    payload.extend_from_slice(b"\xe8\0\0\0\0rar29 segmented e8 reference payload\n");
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after x86 segment\n");
    let entries = [FileEntry {
        name: b"segmented-e8.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::E8,
        filter_start..filter_end,
    );
    std::fs::write(&archive_path, bytes).unwrap();

    let output = run_reference_unrar(&reference, &archive_path);
    assert!(
        output.status.success(),
        "UnRAR 4.20 rejected segmented E8 archive: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires WinRAR/UnRAR 4.20 Wine prefix"]
fn reference_unrar_accepts_rar29_segmented_e8e9_filter_record() {
    let Some(reference) = reference_unrar420() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "rars-rar29-segmented-e8e9-ref-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("segmented-e8e9.rar");
    let mut payload = b"unfiltered prefix before x86 segment ".to_vec();
    let filter_start = payload.len();
    payload.extend_from_slice(b"\xe9\0\0\0\0rar29 segmented e8e9 reference payload\n");
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after x86 segment\n");
    let entries = [FileEntry {
        name: b"segmented-e8e9.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::E8E9,
        filter_start..filter_end,
    );
    std::fs::write(&archive_path, bytes).unwrap();

    let output = run_reference_unrar(&reference, &archive_path);
    assert!(
        output.status.success(),
        "UnRAR 4.20 rejected segmented E8E9 archive: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generated_rar29_e8e9_filtered_archive_round_trips() {
    let payload = b"\xe9\0\0\0\0rar29 e8e9 filter payload\n".repeat(16);
    let entries = [FileEntry {
        name: b"rar29-e8e9-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::E8E9,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    assert!(file.pack_size < file.unp_size);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-e8e9-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_delta_filtered_archive_round_trips() {
    let payload: Vec<u8> = (0..384).map(|index| (index * 17 + 3) as u8).collect();
    let entries = [FileEntry {
        name: b"rar29-delta-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Delta { channels: 3 },
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-delta-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_segmented_delta_filtered_archive_round_trips() {
    let mut payload = b"unfiltered prefix before delta segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..384).map(|index| (index * 17 + 3) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after delta segment\n");
    let entries = [FileEntry {
        name: b"rar29-segmented-delta-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Delta { channels: 3 },
        filter_start..filter_end,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-segmented-delta-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[ignore = "requires WinRAR/UnRAR 4.20 Wine prefix"]
fn reference_unrar_accepts_rar29_segmented_delta_filter_record() {
    let Some(reference) = reference_unrar420() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "rars-rar29-segmented-delta-ref-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("segmented-delta.rar");
    let mut payload = b"unfiltered prefix before delta segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..384).map(|index| (index * 17 + 3) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after delta segment\n");
    let entries = [FileEntry {
        name: b"segmented-delta.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Delta { channels: 3 },
        filter_start..filter_end,
    );
    std::fs::write(&archive_path, bytes).unwrap();

    let output = run_reference_unrar(&reference, &archive_path);
    assert!(
        output.status.success(),
        "UnRAR 4.20 rejected segmented DELTA archive: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generated_rar29_itanium_filtered_archive_round_trips() {
    let mut payload = vec![0u8; 48];
    payload[16] = 22;
    payload[21] = 20;
    payload.extend_from_slice(b"rar29 itanium format payload\n");
    let entries = [FileEntry {
        name: b"rar29-itanium-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Itanium,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-itanium-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_segmented_itanium_filtered_archive_round_trips() {
    let mut payload = b"unfiltered prefix before itanium segment ".to_vec();
    let filter_start = payload.len();
    payload.extend_from_slice(&[0; 48]);
    payload[filter_start + 16] = 22;
    payload[filter_start + 21] = 20;
    payload.extend_from_slice(b"rar29 segmented itanium format payload\n");
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after itanium segment\n");
    let entries = [FileEntry {
        name: b"rar29-segmented-itanium-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Itanium,
        filter_start..filter_end,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-segmented-itanium-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[ignore = "requires WinRAR/UnRAR 4.20 Wine prefix"]
fn reference_unrar_accepts_rar29_segmented_itanium_filter_record() {
    let Some(reference) = reference_unrar420() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "rars-rar29-segmented-itanium-ref-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("segmented-itanium.rar");
    let mut payload = b"unfiltered prefix before itanium segment ".to_vec();
    let filter_start = payload.len();
    payload.extend_from_slice(&[0; 48]);
    payload[filter_start + 16] = 22;
    payload[filter_start + 21] = 20;
    payload.extend_from_slice(b"rar29 segmented itanium reference payload\n");
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after itanium segment\n");
    let entries = [FileEntry {
        name: b"segmented-itanium.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Itanium,
        filter_start..filter_end,
    );
    std::fs::write(&archive_path, bytes).unwrap();

    let output = run_reference_unrar(&reference, &archive_path);
    assert!(
        output.status.success(),
        "UnRAR 4.20 rejected segmented ITANIUM archive: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generated_rar29_rgb_filtered_archive_round_trips() {
    let width = 12;
    let payload: Vec<u8> = (0..96).map(|index| (index * 31 + 13) as u8).collect();
    let entries = [FileEntry {
        name: b"rar29-rgb-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Rgb { width, pos_r: 0 },
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-rgb-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_segmented_rgb_filtered_archive_round_trips() {
    let width = 12;
    let mut payload = b"unfiltered prefix before rgb segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..96).map(|index| (index * 31 + 13) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after rgb segment\n");
    let entries = [FileEntry {
        name: b"rar29-segmented-rgb-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Rgb { width, pos_r: 0 },
        filter_start..filter_end,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-segmented-rgb-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[ignore = "requires WinRAR/UnRAR 4.20 Wine prefix"]
fn reference_unrar_accepts_rar29_segmented_rgb_filter_record() {
    let Some(reference) = reference_unrar420() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "rars-rar29-segmented-rgb-ref-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("segmented-rgb.rar");
    let width = 12;
    let mut payload = b"unfiltered prefix before rgb segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..96).map(|index| (index * 31 + 13) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after rgb segment\n");
    let entries = [FileEntry {
        name: b"segmented-rgb.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Rgb { width, pos_r: 0 },
        filter_start..filter_end,
    );
    std::fs::write(&archive_path, bytes).unwrap();

    let output = run_reference_unrar(&reference, &archive_path);
    assert!(
        output.status.success(),
        "UnRAR 4.20 rejected segmented RGB archive: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generated_rar29_audio_filtered_archive_round_trips() {
    let payload: Vec<u8> = (0..160)
        .map(|index| (index * 9 + index / 5) as u8)
        .collect();
    let entries = [FileEntry {
        name: b"rar29-audio-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Audio { channels: 2 },
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-audio-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_segmented_audio_filtered_archive_round_trips() {
    let mut payload = b"unfiltered prefix before audio segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..160).map(|index| (index * 9 + index / 5) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after audio segment\n");
    let entries = [FileEntry {
        name: b"rar29-segmented-audio-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Audio { channels: 2 },
        filter_start..filter_end,
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"rar29-segmented-audio-filtered.bin");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_large_delta_filter_uses_multiple_vm_records() {
    let payload: Vec<u8> = (0..240_064)
        .map(|index| (index * 11 + index / 5 + index / 251) as u8)
        .collect();
    let entries = [FileEntry {
        name: b"rar29-large-delta-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Delta { channels: 4 },
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn generated_rar29_large_audio_filter_uses_multiple_redeclared_vm_records() {
    let payload: Vec<u8> = (0..240_064)
        .map(|index| (index * 7 + index / 3 + index / 257) as u8)
        .collect();
    let entries = [FileEntry {
        name: b"rar29-large-audio-filtered.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_filter(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Audio { channels: 4 },
    );
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[ignore = "requires WinRAR/UnRAR 3.00 Wine prefix"]
fn reference_unrar300_accepts_rar29_segmented_filter_records() {
    let Some(reference) = reference_unrar300() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "rars-rar29-segmented-unrar300-ref-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let mut e8 = b"unfiltered prefix before x86 segment ".to_vec();
    let e8_start = e8.len();
    e8.extend_from_slice(b"\xe8\0\0\0\0rar29 segmented e8 reference payload\n");
    let e8_end = e8.len();
    e8.extend_from_slice(b"unfiltered suffix after x86 segment\n");
    write_reference_segmented_archive(
        &dir.join("segmented-e8.rar"),
        b"segmented-e8.bin",
        &e8,
        |entries| {
            write_rar29_compressed_archive_with_filter_policy(
                entries,
                reference_rar29_options(),
                FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8, e8_start..e8_end)),
            )
        },
    );

    let mut e8e9 = b"unfiltered prefix before x86 segment ".to_vec();
    let e8e9_start = e8e9.len();
    e8e9.extend_from_slice(b"\xe9\0\0\0\0rar29 segmented e8e9 reference payload\n");
    let e8e9_end = e8e9.len();
    e8e9.extend_from_slice(b"unfiltered suffix after x86 segment\n");
    write_reference_segmented_archive(
        &dir.join("segmented-e8e9.rar"),
        b"segmented-e8e9.bin",
        &e8e9,
        |entries| {
            write_rar29_compressed_archive_with_filter_policy(
                entries,
                reference_rar29_options(),
                FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8E9, e8e9_start..e8e9_end)),
            )
        },
    );

    let mut delta = b"unfiltered prefix before delta segment ".to_vec();
    let delta_start = delta.len();
    delta.extend((0..384).map(|index| (index * 17 + 3) as u8));
    let delta_end = delta.len();
    delta.extend_from_slice(b"unfiltered suffix after delta segment\n");
    write_reference_segmented_archive(
        &dir.join("segmented-delta.rar"),
        b"segmented-delta.bin",
        &delta,
        |entries| {
            write_rar29_compressed_archive_with_filter_policy(
                entries,
                reference_rar29_options(),
                FilterPolicy::Explicit(FilterSpec::range(
                    FilterKind::Delta { channels: 3 },
                    delta_start..delta_end,
                )),
            )
        },
    );

    let mut itanium = b"unfiltered prefix before itanium segment ".to_vec();
    let itanium_start = itanium.len();
    itanium.extend_from_slice(&[0; 48]);
    itanium[itanium_start + 16] = 22;
    itanium[itanium_start + 21] = 20;
    itanium.extend_from_slice(b"rar29 segmented itanium reference payload\n");
    let itanium_end = itanium.len();
    itanium.extend_from_slice(b"unfiltered suffix after itanium segment\n");
    write_reference_segmented_archive(
        &dir.join("segmented-itanium.rar"),
        b"segmented-itanium.bin",
        &itanium,
        |entries| {
            write_rar29_compressed_archive_with_filter_policy(
                entries,
                reference_rar29_options(),
                FilterPolicy::Explicit(FilterSpec::range(
                    FilterKind::Itanium,
                    itanium_start..itanium_end,
                )),
            )
        },
    );

    let mut rgb = b"unfiltered prefix before rgb segment ".to_vec();
    let rgb_start = rgb.len();
    rgb.extend((0..96).map(|index| (index * 31 + 13) as u8));
    let rgb_end = rgb.len();
    rgb.extend_from_slice(b"unfiltered suffix after rgb segment\n");
    write_reference_segmented_archive(
        &dir.join("segmented-rgb.rar"),
        b"segmented-rgb.bin",
        &rgb,
        |entries| {
            write_rar29_compressed_archive_with_filter_policy(
                entries,
                reference_rar29_options(),
                FilterPolicy::Explicit(FilterSpec::range(
                    FilterKind::Rgb {
                        width: 12,
                        pos_r: 0,
                    },
                    rgb_start..rgb_end,
                )),
            )
        },
    );

    let mut audio = b"unfiltered prefix before audio segment ".to_vec();
    let audio_start = audio.len();
    audio.extend((0..160).map(|index| (index * 9 + index / 5) as u8));
    let audio_end = audio.len();
    audio.extend_from_slice(b"unfiltered suffix after audio segment\n");
    write_reference_segmented_archive(
        &dir.join("segmented-audio.rar"),
        b"segmented-audio.bin",
        &audio,
        |entries| {
            write_rar29_compressed_archive_with_filter_policy(
                entries,
                reference_rar29_options(),
                FilterPolicy::Explicit(FilterSpec::range(
                    FilterKind::Audio { channels: 2 },
                    audio_start..audio_end,
                )),
            )
        },
    );

    for archive_path in [
        "segmented-e8.rar",
        "segmented-e8e9.rar",
        "segmented-delta.rar",
        "segmented-itanium.rar",
        "segmented-rgb.rar",
        "segmented-audio.rar",
    ] {
        let archive_path = dir.join(archive_path);
        let output = run_reference_unrar(&reference, &archive_path);
        assert!(
            output.status.success(),
            "UnRAR 3.00 rejected {}: status={:?}\nstdout={}\nstderr={}",
            archive_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn reference_rar29_options() -> WriterOptions {
    WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
}

fn write_reference_segmented_archive(
    archive_path: &Path,
    name: &'static [u8],
    payload: &[u8],
    write: impl FnOnce(&[FileEntry<'_>]) -> rars::Result<Vec<u8>>,
) {
    let entries = [FileEntry {
        name,
        data: payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write(&entries).unwrap();
    std::fs::write(archive_path, bytes).unwrap();
}

#[test]
#[ignore = "requires WinRAR/UnRAR 4.20 Wine prefix"]
fn reference_unrar_accepts_rar29_segmented_audio_filter_record() {
    let Some(reference) = reference_unrar420() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!(
        "rars-rar29-segmented-audio-ref-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("segmented-audio.rar");
    let mut payload = b"unfiltered prefix before audio segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..160).map(|index| (index * 9 + index / 5) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"unfiltered suffix after audio segment\n");
    let entries = [FileEntry {
        name: b"segmented-audio.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write_rar29_filter_range(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterKind::Audio { channels: 2 },
        filter_start..filter_end,
    );
    std::fs::write(&archive_path, bytes).unwrap();

    let output = run_reference_unrar(&reference, &archive_path);
    assert!(
        output.status.success(),
        "UnRAR 4.20 rejected segmented AUDIO archive: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn extract_to_reports_rar15_entry_context_on_write_failure() {
    struct FailWriter;

    impl Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink failed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let bytes = std::fs::read(fixture("rars_generated/stored.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let error = archive
        .extract_to(ArchiveReadOptions::default(), |_meta| {
            Ok(Box::new(FailWriter))
        })
        .unwrap_err();

    match error {
        Error::AtEntry {
            name,
            operation,
            source,
        } => {
            assert_eq!(name, b"payload.txt");
            assert_eq!(operation, "extracting");
            assert!(matches!(*source, Error::Io(_)));
        }
        other => panic!("expected entry context, got {other:?}"),
    }
}

#[test]
fn writes_store_only_rar15_archive_that_reader_extracts() {
    let entries = [
        StoredEntry {
            name: b"hello.txt",
            data: b"Hello from a generated RAR 1.5 archive.\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        StoredEntry {
            name: b"tiny.bin",
            data: b"\x00\x01\x02\x03",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];

    let bytes = write_stored_archive(&entries, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[0].unp_ver, 15);
    assert_eq!(files[0].method, 0x30);
    assert_eq!(files[0].file_crc, crc32(entries[0].data));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[1].data, entries[1].data);
}

#[test]
fn writes_stored_rar15_archive_comment_that_reader_decodes() {
    let features = FeatureSet::store_only();
    let entries = [StoredEntry {
        name: b"hello.txt",
        data: b"hello with comment\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_stored_archive_with_comment(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar15, features),
        Some(b"archive note\n"),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(archive.main.has_archive_comment());
    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(&b"archive note\n"[..])
    );
    assert_eq!(collect_extract(&archive).unwrap()[0].data, entries[0].data);
}

#[test]
fn writes_rar15_file_comments_that_reader_decodes() {
    let features = FeatureSet::store_only();

    let stored = [StoredEntry {
        name: b"stored-comment.txt",
        data: b"stored file comment payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: Some(b"stored note\r\n"),
    }];
    let stored_bytes =
        write_stored_archive(&stored, WriterOptions::new(ArchiveVersion::Rar15, features)).unwrap();
    let stored_archive = Archive::parse(&stored_bytes).unwrap();
    let stored_file = stored_archive.files().next().unwrap();
    assert!(stored_file.has_file_comment());
    assert_eq!(
        stored_file.file_comment().unwrap().as_deref(),
        Some(&b"stored note\r\n"[..])
    );
    assert_eq!(
        collect_extract(&stored_archive).unwrap()[0].data,
        stored[0].data
    );

    let compressed = [FileEntry {
        name: b"compressed-comment.txt",
        data: b"compressed file comment payload compressed file comment payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: Some(b"compressed note"),
    }];
    let compressed_bytes = write_compressed_archive(
        &compressed,
        WriterOptions::new(ArchiveVersion::Rar15, features),
    )
    .unwrap();
    let compressed_archive = Archive::parse(&compressed_bytes).unwrap();
    let compressed_file = compressed_archive.files().next().unwrap();
    assert!(compressed_file.has_file_comment());
    assert_eq!(
        compressed_file.file_comment().unwrap().as_deref(),
        Some(&b"compressed note"[..])
    );
    assert_eq!(
        collect_extract(&compressed_archive).unwrap()[0].data,
        compressed[0].data
    );
}

#[test]
fn writes_rar20_old_style_comments_that_reader_decodes() {
    let archive_features = FeatureSet::store_only();
    let stored = [StoredEntry {
        name: b"rar20-commented.txt",
        data: b"rar20 archive comment payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let archive_bytes = write_stored_archive_with_comment(
        &stored,
        WriterOptions::new(ArchiveVersion::Rar20, archive_features),
        Some(b"rar20 archive note\r\n"),
    )
    .unwrap();
    let archive = Archive::parse(&archive_bytes).unwrap();
    assert!(archive.main.has_archive_comment());
    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(b"rar20 archive note\r\n".as_slice())
    );
    assert_eq!(collect_extract(&archive).unwrap()[0].data, stored[0].data);

    let file_features = FeatureSet::store_only();
    let compressed = [FileEntry {
        name: b"rar20-file-commented.txt",
        data: b"rar20 compressed file comment payload payload payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: Some(b"rar20 file note"),
    }];
    let file_bytes = write_compressed_archive_with_comment(
        &compressed,
        WriterOptions::new(ArchiveVersion::Rar20, file_features),
        None,
    )
    .unwrap();
    let archive = Archive::parse(&file_bytes).unwrap();
    let file = archive.files().next().unwrap();
    assert_eq!(file.unp_ver, 20);
    assert!(file.has_file_comment());
    assert_eq!(
        file.file_comment().unwrap().as_deref(),
        Some(b"rar20 file note".as_slice())
    );
    assert_eq!(
        collect_extract(&archive).unwrap()[0].data,
        compressed[0].data
    );
}

#[test]
fn writes_rar29_old_style_comments_that_reader_decodes() {
    let archive_features = FeatureSet::store_only();
    let stored = [StoredEntry {
        name: b"rar29-commented.txt",
        data: b"rar29 archive comment payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let archive_bytes = write_stored_archive_with_comment(
        &stored,
        WriterOptions::new(ArchiveVersion::Rar29, archive_features),
        Some(b"rar29 archive note\r\n"),
    )
    .unwrap();
    let archive = Archive::parse(&archive_bytes).unwrap();
    assert!(archive.main.has_archive_comment());
    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(b"rar29 archive note\r\n".as_slice())
    );
    assert_eq!(collect_extract(&archive).unwrap()[0].data, stored[0].data);

    let file_features = FeatureSet::store_only();
    let compressed = [FileEntry {
        name: b"rar29-file-commented.txt",
        data: b"rar29 compressed file comment payload payload payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: Some(b"rar29 file note"),
    }];
    let file_bytes = write_compressed_archive_with_comment(
        &compressed,
        WriterOptions::new(ArchiveVersion::Rar29, file_features),
        None,
    )
    .unwrap();
    let archive = Archive::parse(&file_bytes).unwrap();
    let file = archive.files().next().unwrap();
    assert_eq!(file.unp_ver, 29);
    assert!(file.has_file_comment());
    assert_eq!(
        file.file_comment().unwrap().as_deref(),
        Some(b"rar29 file note".as_slice())
    );
    assert_eq!(
        collect_extract(&archive).unwrap()[0].data,
        compressed[0].data
    );
}

#[test]
fn writes_rar29_archive_comment_with_empty_auto_members() {
    let features = FeatureSet::store_only();
    let entries = [
        FileEntry {
            name: b"file1.txt",
            data: b"",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"file2.txt",
            data: b"",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];

    let bytes = write_compressed_archive_with_comment(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, features),
        Some(b"RARcomment"),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(b"RARcomment".as_slice())
    );
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|file| file.method == 0x30));
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert!(extracted.iter().all(|entry| entry.data.is_empty()));
}

#[test]
fn writes_rar3_newsub_archive_comment_that_reader_decodes() {
    for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        let features = FeatureSet::store_only();
        let entries = [FileEntry {
            name: b"rar3-commented.txt",
            data: b"rar3 NEWSUB comment payload payload payload\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }];
        let bytes = write_compressed_archive_with_comment(
            &entries,
            WriterOptions::new(target, features),
            Some(b"rar3 NEWSUB archive note\r\n"),
        )
        .unwrap();

        let archive = Archive::parse(&bytes).unwrap();
        assert!(!archive.main.has_archive_comment());
        let subblocks: Vec<_> = archive.new_subs().collect();
        assert_eq!(subblocks.len(), 1);
        assert_eq!(subblocks[0].kind, NewSubKind::ArchiveComment);
        assert_eq!(subblocks[0].file.name, b"CMT");
        assert_eq!(subblocks[0].file.unp_ver, 29);
        assert_eq!(subblocks[0].file.method, 0x33);
        assert_eq!(
            archive.archive_comment().unwrap().as_deref(),
            Some(b"rar3 NEWSUB archive note\r\n".as_slice())
        );
        assert_eq!(collect_extract(&archive).unwrap()[0].data, entries[0].data);
    }
}

#[test]
fn rar15_writer_downgrades_unix_metadata_for_unrar_compatibility() {
    let unix_regular_file = 0o100664;
    let entries = [StoredEntry {
        name: b"unix-mode.txt",
        data: b"RAR15 stored data\n",
        file_time: 0x5a21_0000,
        file_attr: unix_regular_file,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let rar15 = write_stored_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar15, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&rar15).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 15);
    assert_eq!(file.host_os, 0);
    assert_eq!(file.attr, 0x20);
    assert!(!file.is_directory());
    assert_eq!(collect_extract(&archive).unwrap()[0].data, entries[0].data);

    let rar20 = write_stored_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&rar20).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.host_os, 3);
    assert_eq!(file.attr, unix_regular_file);
}

#[test]
fn writes_compressed_rar15_archive_that_reader_extracts() {
    let entries = [
        FileEntry {
            name: b"alpha.txt",
            data: b"alpha beta gamma alpha beta gamma alpha beta gamma\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"binary.bin",
            data: b"\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01\x02\x03",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];

    let bytes = write_compressed_archive(&entries, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"alpha.txt");
    assert_eq!(files[0].unp_ver, 15);
    assert_eq!(files[0].method, 0x33);
    assert_eq!(files[0].file_crc, crc32(entries[0].data));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[1].data, entries[1].data);
}

#[test]
fn rar15_writer_levels_control_unpack15_encoder_policy() {
    let mut data: Vec<_> = (0..5000).map(|index| (index * 73 + 19) as u8).collect();
    data.extend_from_within(..256);
    let entries = [FileEntry {
        name: b"rar15-level-policy.bin",
        data: &data,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let level_one = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar15, FeatureSet::store_only())
            .with_compression_level(1),
    )
    .unwrap();
    let level_five = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar15, FeatureSet::store_only())
            .with_compression_level(5),
    )
    .unwrap();
    let level_one = Archive::parse(&level_one).unwrap();
    let level_five = Archive::parse(&level_five).unwrap();
    let level_one_file = level_one.files().next().unwrap();
    let level_five_file = level_five.files().next().unwrap();

    assert_eq!(level_one_file.method, 0x31);
    assert_eq!(level_five_file.method, 0x35);
    assert!(level_five_file.pack_size < level_one_file.pack_size);
    assert_eq!(collect_extract(&level_one).unwrap()[0].data, data);
    assert_eq!(collect_extract(&level_five).unwrap()[0].data, data);
}

#[test]
fn writes_literal_compressed_rar20_archive_that_reader_extracts() {
    let entries = [
        FileEntry {
            name: b"rar20-alpha.txt",
            data: b"RAR 2.0 literal writer baseline alpha alpha alpha\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"rar20-binary.bin",
            data: b"\x00\xff\x00\xff\x10\x20\x30\x40\x00\xff",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"rar20-run.bin",
            data: &[b'A'; 1024],
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"rar20-repeat.bin",
            data: &b"abc123xyz-"[..].repeat(128),
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 4);
    assert!(files.iter().all(|file| file.unp_ver == 20));
    assert_eq!(files[0].method, 0x30);
    assert_eq!(files[1].method, 0x30);
    assert_eq!(files[2].method, 0x33);
    assert_eq!(files[3].method, 0x33);
    assert_eq!(files[0].file_crc, crc32(entries[0].data));
    assert_eq!(files[1].file_crc, crc32(entries[1].data));
    assert_eq!(files[2].file_crc, crc32(entries[2].data));
    assert_eq!(files[3].file_crc, crc32(entries[3].data));
    assert!(files.iter().all(|file| !file.is_solid()));
    assert!(files[2].pack_size < files[2].unp_size / 4);
    assert!(files[3].pack_size < files[3].unp_size / 2);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 4);
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[1].data, entries[1].data);
    assert_eq!(extracted[2].data, entries[2].data);
    assert_eq!(extracted[3].data, entries[3].data);
}

#[test]
fn rar20_writer_uses_audio_block_for_pcm_like_payload_when_smaller() {
    let mut payload = Vec::new();
    for sample in 0..8192i16 {
        let left = sample.wrapping_mul(3).wrapping_add(200);
        let right = sample.wrapping_mul(3).wrapping_sub(200);
        payload.extend_from_slice(&left.to_le_bytes());
        payload.extend_from_slice(&right.to_le_bytes());
    }
    let lz_packed = rars::codec::rar20::unpack20_encode_literals(&payload).unwrap();
    let entries = [FileEntry {
        name: b"rar20-audio.wav",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.method, 0x33);
    assert!(file.pack_size < lz_packed.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn rar20_writer_uses_audio_block_for_boat_modern_english_fixture() {
    let source = std::fs::read(fixture("rar250/unpack20_audio_text.rar")).unwrap();
    let source_archive = Archive::parse(&source).unwrap();
    let source_entries = collect_extract(&source_archive).unwrap();
    let payload = &source_entries[0].data;
    let lz_packed = rars::codec::rar20::unpack20_encode_literals(payload).unwrap();
    let entries = [FileEntry {
        name: b"BoatModernEnglish.wav",
        data: payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.method, 0x33);
    assert!(file.pack_size < lz_packed.len() as u64);
    assert!(file.pack_size < file.unp_size / 2);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, *payload);
}

#[test]
fn rar20_writer_uses_repeat_last_for_regular_pcm_fixture() {
    let source = std::fs::read(fixture("rar250/AUDIO.RAR")).unwrap();
    let source_archive = Archive::parse(&source).unwrap();
    let source_file = source_archive.files().next().unwrap();
    let source_entries = collect_extract(&source_archive).unwrap();
    let payload = &source_entries[0].data;
    let entries = [FileEntry {
        name: b"PCM_LR.WAV",
        data: payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.method, 0x33);
    assert!(file.pack_size < file.unp_size / 8);
    assert!(file.pack_size < source_file.pack_size * 2);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, *payload);
}

#[test]
fn rar20_writer_stamps_requested_method_levels() {
    let payload = b"rar20 level method payload alpha beta gamma\n".repeat(64);
    let entries = [FileEntry {
        name: b"rar20-level.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for level in 1..=5 {
        let bytes = write_compressed_archive(
            &entries,
            WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only())
                .with_compression_level(level),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();

        assert_eq!(file.method, 0x30 + level);
        assert_eq!(file.block.flags & 0x00e0, 0);
        assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
    }
}

#[test]
fn rar20_writer_stores_member_when_lz_payload_would_grow() {
    let payload = (0..41u16)
        .map(|index| {
            let value = index.wrapping_mul(73).wrapping_add(index >> 3);
            value as u8
        })
        .collect::<Vec<_>>();
    let entries = [FileEntry {
        name: b"rar20-randomish.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only())
            .with_compression_level(5),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert!(matches!(file.method, 0x30 | 0x35));
    assert!(file.pack_size <= payload.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn writes_encrypted_rar20_archives_that_reader_extracts_with_password() {
    let features = FeatureSet::store_only();
    let options = WriterOptions::new(ArchiveVersion::Rar20, features);

    let stored = [StoredEntry {
        name: b"rar20-secret-store.txt",
        data: b"RAR 2.0 encrypted stored payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let stored_bytes = write_stored_archive(&stored, options).unwrap();
    let stored_archive = Archive::parse(&stored_bytes).unwrap();
    let stored_file = stored_archive.files().next().unwrap();
    assert_eq!(stored_file.unp_ver, 20);
    assert!(stored_file.is_encrypted());
    assert_eq!(stored_file.pack_size % 16, 0);
    assert!(matches!(
        collect_extract(&stored_archive),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_with_password(&stored_archive, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract_with_password(&stored_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored[0].data);

    let compressed = [FileEntry {
        name: b"rar20-secret-compressed.txt",
        data: b"RAR 2.0 encrypted compressed payload payload payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let compressed_bytes = write_compressed_archive(&compressed, options).unwrap();
    let compressed_archive = Archive::parse(&compressed_bytes).unwrap();
    let compressed_file = compressed_archive.files().next().unwrap();
    assert_eq!(compressed_file.unp_ver, 20);
    assert!(compressed_file.is_encrypted());
    assert_eq!(compressed_file.pack_size % 16, 0);
    assert!(matches!(
        collect_extract(&compressed_archive),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_with_password(&compressed_archive, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract_with_password(&compressed_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed[0].data);
}

#[test]
fn writes_encrypted_rar29_archives_that_reader_extracts_with_password() {
    let features = FeatureSet::store_only();
    let options = WriterOptions::new(ArchiveVersion::Rar29, features);

    let stored = [StoredEntry {
        name: b"rar29-secret-store.txt",
        data: b"RAR 2.9 encrypted stored payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let stored_bytes = write_stored_archive(&stored, options).unwrap();
    let stored_archive = Archive::parse(&stored_bytes).unwrap();
    let stored_file = stored_archive.files().next().unwrap();
    assert_eq!(stored_file.unp_ver, 29);
    assert!(stored_file.is_encrypted());
    assert!(stored_file.salt.is_some());
    assert_eq!(stored_file.pack_size % 16, 0);
    assert!(matches!(
        collect_extract(&stored_archive),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_with_password(&stored_archive, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract_with_password(&stored_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored[0].data);

    let compressed = [FileEntry {
        name: b"rar29-secret-compressed.txt",
        data: b"RAR 2.9 encrypted compressed payload payload payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let compressed_bytes = write_compressed_archive(&compressed, options).unwrap();
    let compressed_archive = Archive::parse(&compressed_bytes).unwrap();
    let compressed_file = compressed_archive.files().next().unwrap();
    assert_eq!(compressed_file.unp_ver, 29);
    assert!(compressed_file.is_encrypted());
    assert!(compressed_file.salt.is_some());
    assert_eq!(compressed_file.pack_size % 16, 0);
    assert!(matches!(
        collect_extract(&compressed_archive),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_with_password(&compressed_archive, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract_with_password(&compressed_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed[0].data);
}

#[test]
fn writes_literal_compressed_rar29_archive_that_reader_extracts() {
    let entries = [
        FileEntry {
            name: b"rar29-alpha.txt",
            data: b"RAR 2.9 literal writer baseline alpha alpha alpha\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"rar29-binary.bin",
            data: b"\x00\xff\x00\xff\x10\x20\x30\x40\x00\xff",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"rar29-run.bin",
            data: &[b'Z'; 1024],
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"rar29-repeat.bin",
            data: &b"abc123xyz-"[..].repeat(128),
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 4);
    assert!(files.iter().all(|file| file.unp_ver == 29));
    assert!(files
        .iter()
        .all(|file| matches!(file.method, 0x30 | 0x33 | 0x35)));
    assert_eq!(files[0].file_crc, crc32(entries[0].data));
    assert_eq!(files[1].file_crc, crc32(entries[1].data));
    assert_eq!(files[2].file_crc, crc32(entries[2].data));
    assert_eq!(files[3].file_crc, crc32(entries[3].data));
    assert!(files.iter().all(|file| !file.is_solid()));
    assert!(files[2].pack_size < files[2].unp_size / 4);
    assert!(files[3].pack_size < files[3].unp_size / 2);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 4);
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[1].data, entries[1].data);
    assert_eq!(extracted[2].data, entries[2].data);
    assert_eq!(extracted[3].data, entries[3].data);
}

#[test]
fn writes_solid_compressed_rar29_rar30_and_rar40_archives_that_reader_extracts() {
    for target in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let entries = [
            FileEntry {
                name: b"solid-one.txt",
                data: b"solid writer baseline alpha beta gamma alpha beta gamma\n",
                file_time: 0x5a21_0000,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            FileEntry {
                name: b"solid-two.txt",
                data: b"solid writer baseline alpha beta gamma delta epsilon\n",
                file_time: 0x5a21_0000,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
        ];
        let mut features = FeatureSet::store_only();
        features.solid = true;
        let bytes =
            write_compressed_archive(&entries, WriterOptions::new(target, features)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let files: Vec<_> = archive.files().collect();

        assert!(archive.main.is_solid());
        assert_eq!(files.len(), 2);
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        let independent_lz = rars::codec::rar29::unpack29_encode_literals(entries[1].data).unwrap();
        assert!(files[1].pack_size < independent_lz.len() as u64);

        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted.len(), 2);
        assert_eq!(extracted[0].data, entries[0].data);
        assert_eq!(extracted[1].data, entries[1].data);
    }
}

#[test]
fn writes_solid_compressed_rar20_archive_that_reader_extracts() {
    let shared = b"RAR 2.0 solid writer shared dictionary phrase alpha beta gamma.\n";
    let first_data = shared.repeat(64);
    let mut second_data = shared.repeat(32);
    second_data.extend_from_slice(b"second member tail\n");
    let entries = [
        FileEntry {
            name: b"solid-rar20-one.txt",
            data: &first_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-rar20-two.txt",
            data: &second_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, features),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    assert!(files.iter().all(|file| file.unp_ver == 20));
    assert!(files[1].pack_size < files[0].pack_size);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, first_data);
    assert_eq!(extracted[1].data, second_data);
}

#[test]
fn writes_solid_rar20_archive_across_table_boundary_and_multiple_history_members() {
    let first_data: Vec<_> = (0u8..=255).cycle().take(4096).collect();
    let phrase = b"RAR 2.0 solid table boundary phrase alpha beta gamma.\n";
    let second_data = phrase.repeat(96);
    let mut third_data = phrase.repeat(24);
    third_data.extend_from_slice(b"third member literal tail after history matches\n");
    let entries = [
        FileEntry {
            name: b"solid-rar20-table.bin",
            data: &first_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-rar20-boundary.txt",
            data: &second_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-rar20-third.txt",
            data: &third_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar20, features),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 3);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    assert!(files[2].is_solid());
    assert!(files.iter().all(|file| file.unp_ver == 20));

    let independent_third = write_compressed_archive(
        &[entries[2]],
        WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only()),
    )
    .unwrap();
    let independent_third = Archive::parse(&independent_third).unwrap();
    let independent_third = independent_third.files().next().unwrap();
    assert!(files[2].pack_size < independent_third.pack_size);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].data, first_data);
    assert_eq!(extracted[1].data, second_data);
    assert_eq!(extracted[2].data, third_data);
}

#[test]
fn compressed_rar29_writer_stores_incompressible_member_when_smaller() {
    let mut state = 0x1234_5678u32;
    let data: Vec<_> = (0..8192)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let entries = [FileEntry {
        name: b"randomish.bin",
        data: &data,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.method, 0x30);
    assert_eq!(file.pack_size, data.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
}

#[test]
fn solid_rar29_writer_stores_incompressible_member_and_resets_solid_run() {
    let first_data = b"solid reset phrase alpha beta gamma ".repeat(96);
    let mut state = 0x2468_ace0u32;
    let randomish: Vec<_> = (0..8192)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let second_data = b"solid reset phrase alpha beta gamma ".repeat(64);
    let entries = [
        FileEntry {
            name: b"solid-before.txt",
            data: &first_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-random.bin",
            data: &randomish,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-after.txt",
            data: &second_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, features),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 3);
    assert_eq!(files[1].method, 0x30);
    assert_eq!(files[1].pack_size, randomish.len() as u64);
    assert!(!files[0].is_solid());
    assert!(!files[1].is_solid());
    assert!(!files[2].is_solid());

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, first_data);
    assert_eq!(extracted[1].data, randomish);
    assert_eq!(extracted[2].data, second_data);
}

#[test]
fn solid_auto_filtered_rar29_writer_stores_incompressible_member_and_resets_solid_run() {
    let first_data = b"solid auto filtered phrase alpha beta gamma ".repeat(96);
    let mut state = 0x1357_9bdfu32;
    let randomish: Vec<_> = (0..8192)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let second_data = b"solid auto filtered phrase alpha beta gamma ".repeat(64);
    let entries = [
        FileEntry {
            name: b"solid-auto-before.txt",
            data: &first_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-auto-random.bin",
            data: &randomish,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"solid-auto-after.txt",
            data: &second_data,
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;

    let bytes = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, features),
        FilterPolicy::Auto,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 3);
    assert_eq!(files[1].method, 0x30);
    assert_eq!(files[1].pack_size, randomish.len() as u64);
    assert!(!files[0].is_solid());
    assert!(!files[1].is_solid());
    assert!(!files[2].is_solid());

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, first_data);
    assert_eq!(extracted[1].data, randomish);
    assert_eq!(extracted[2].data, second_data);
}

#[test]
fn auto_filtered_rar29_writer_stores_incompressible_member_when_smaller() {
    let mut state = 0x8765_4321u32;
    let data: Vec<_> = (0..8192)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let entries = [FileEntry {
        name: b"auto-randomish.bin",
        data: &data,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterPolicy::Auto,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.method, 0x30);
    assert_eq!(file.pack_size, data.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
}

#[test]
fn auto_filtered_rar29_writer_chooses_ppmd_for_text_when_smaller() {
    let mut payload = Vec::new();
    for index in 0..512 {
        payload.extend_from_slice(b"rar29 auto ppmd text with repeated words and punctuation. ");
        payload.extend_from_slice(
            format!("line {index:04}: alpha beta gamma alpha beta gamma\n").as_bytes(),
        );
    }
    let lz_packed = rars::codec::rar29::unpack29_encode_literals(&payload).unwrap();
    let ppmd_packed = rars::codec::rar29::unpack29_encode_ppmd(&payload).unwrap();
    assert!(
        ppmd_packed.len() < lz_packed.len(),
        "fixture must exercise the auto-policy PPMd candidate"
    );

    let entries = [FileEntry {
        name: b"auto-ppmd.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterPolicy::Auto,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.method, 0x35);
    assert_eq!(file.pack_size, ppmd_packed.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn default_rar29_writer_uses_auto_policy_for_text() {
    let payload = b"rar29 default auto text alpha beta gamma alpha beta gamma\n".repeat(512);
    let entries = [FileEntry {
        name: b"default-auto-text.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();
    let ppmd_packed = rars::codec::rar29::unpack29_encode_ppmd(&payload).unwrap();

    assert_eq!(file.method, 0x35);
    assert_eq!(file.pack_size, ppmd_packed.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn auto_filtered_rar29_writer_improves_x86_relative_calls() {
    let mut payload = Vec::new();
    payload.extend((0..2048).map(|index| (index * 37 + 11) as u8));
    let code_start = payload.len();
    let call_target = code_start + 0x1800;
    for index in 0..512usize {
        payload.extend_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, (index & 0x7f) as u8]);
        let call_pos = payload.len();
        payload.push(0xe8);
        let next = call_pos + 5;
        let relative = (call_target as i64 - next as i64) as i32;
        payload.extend_from_slice(&relative.to_le_bytes());
        payload.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5d, 0xc3]);
    }
    payload.extend((0..2048).map(|index| (index * 53 + 7) as u8));
    let entries = [FileEntry {
        name: b"x86-calls.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let plain_packed = rars::codec::rar29::unpack29_encode_literals(&payload).unwrap();
    let auto = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterPolicy::Auto,
    )
    .unwrap();
    let auto = Archive::parse(&auto).unwrap();
    let auto_file = auto.files().next().unwrap();

    assert_eq!(auto_file.method, 0x33);
    assert!(
        auto_file.pack_size * 2 < plain_packed.len() as u64,
        "auto-filtered x86 payload should be much smaller than plain RAR29 LZ"
    );
    assert_eq!(collect_extract(&auto).unwrap()[0].data, payload);
}

#[test]
fn default_rar29_writer_uses_auto_policy_for_x86() {
    let mut payload = Vec::new();
    payload.extend((0..2048).map(|index| (index * 37 + 11) as u8));
    let code_start = payload.len();
    let call_target = code_start + 0x1800;
    for index in 0..512usize {
        payload.extend_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, (index & 0x7f) as u8]);
        let call_pos = payload.len();
        payload.push(0xe8);
        let next = call_pos + 5;
        let relative = (call_target as i64 - next as i64) as i32;
        payload.extend_from_slice(&relative.to_le_bytes());
        payload.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5d, 0xc3]);
    }
    payload.extend((0..2048).map(|index| (index * 53 + 7) as u8));
    let entries = [FileEntry {
        name: b"default-auto-x86.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let default = write_compressed_archive(&entries, options).unwrap();
    let explicit_auto =
        write_rar29_compressed_archive_with_filter_policy(&entries, options, FilterPolicy::Auto)
            .unwrap();
    let default_archive = Archive::parse(&default).unwrap();
    let auto_archive = Archive::parse(&explicit_auto).unwrap();

    assert_eq!(default, explicit_auto);
    assert_eq!(default_archive.files().next().unwrap().method, 0x33);
    assert_eq!(collect_extract(&auto_archive).unwrap()[0].data, payload);
}

#[test]
fn rar29_family_writer_levels_increase_lz_match_effort() {
    let payload = level_sensitive_payload();
    let entries = [FileEntry {
        name: b"rar29-level-effort.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for target in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let level_one = write_compressed_archive(
            &entries,
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(1),
        )
        .unwrap();
        let level_three = write_compressed_archive(
            &entries,
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(3),
        )
        .unwrap();
        let level_one_archive = Archive::parse(&level_one).unwrap();
        let level_three_archive = Archive::parse(&level_three).unwrap();
        let level_one_file = level_one_archive.files().next().unwrap();
        let level_three_file = level_three_archive.files().next().unwrap();

        assert_eq!(level_one_file.method, 0x31, "{target:?} level 1");
        assert_eq!(level_three_file.method, 0x33, "{target:?} level 3");
        assert!(
            level_three_file.pack_size < level_one_file.pack_size,
            "{target:?}"
        );
        assert_eq!(
            collect_extract(&level_one_archive).unwrap()[0].data,
            payload
        );
        assert_eq!(
            collect_extract(&level_three_archive).unwrap()[0].data,
            payload
        );
    }
}

#[test]
fn rar29_family_writer_stamps_oracle_dict_bits_by_target() {
    let entries = [StoredEntry {
        name: b"stored-dict.txt",
        data: b"stored dict stamp payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for (target, expected_dict_flags) in [
        (ArchiveVersion::Rar29, 0x0080),
        (ArchiveVersion::Rar30, 0x0020),
        (ArchiveVersion::Rar40, 0x0020),
    ] {
        let bytes = write_stored_archive(
            &entries,
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(0),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();

        assert_eq!(file.method, 0x30, "{target:?}");
        assert_eq!(file.block.flags & 0x00e0, expected_dict_flags, "{target:?}");
        assert_eq!(collect_extract(&archive).unwrap()[0].data, entries[0].data);
    }
}

#[test]
fn rar29_family_writer_stamps_requested_dictionary_size() {
    let entries = [FileEntry {
        name: b"dict4m.txt",
        data: b"dictionary override payload\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
            .with_compression_level(3)
            .with_dictionary_size(4 * 1024 * 1024),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.block.flags & 0x00e0, 0x00c0);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, entries[0].data);
}

#[test]
fn rar29_family_compressed_writer_level_zero_stores_member() {
    let payload = b"level zero should store even through compressed writer\n".repeat(8);
    let entries = [FileEntry {
        name: b"level-zero.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for target in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let bytes = write_compressed_archive(
            &entries,
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(0),
        )
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();

        assert_eq!(file.method, 0x30, "{target:?}");
        assert_eq!(file.pack_size, payload.len() as u64, "{target:?}");
        assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
    }
}

#[test]
fn rar29_family_writer_stamps_requested_lz_method_levels() {
    let payload = b"level method stamp payload alpha beta gamma delta\n".repeat(128);
    let entries = [FileEntry {
        name: b"method-level.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for target in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        for level in 1..=5 {
            let bytes = write_compressed_archive(
                &entries,
                WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(level),
            )
            .unwrap();
            let archive = Archive::parse(&bytes).unwrap();
            let file = archive.files().next().unwrap();

            assert_eq!(file.method, 0x30 + level, "{target:?} level {level}");
            assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
        }
    }
}

#[test]
fn rar29_family_writer_stores_small_incompressible_member_when_smaller() {
    let data: Vec<_> = (0..41u8)
        .map(|index| index.wrapping_mul(37).wrapping_add(11))
        .collect();
    let entries = [FileEntry {
        name: b"fgrep",
        data: &data,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only())
            .with_compression_level(5),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.method, 0x30);
    assert_eq!(file.pack_size, data.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
}

#[test]
fn rar29_family_writer_level_three_uses_lz_and_level_five_uses_auto_policy() {
    let payload = b"fn alpha() { beta(gamma); }\nlet words = alpha beta gamma delta;\n".repeat(512);
    let entries = [FileEntry {
        name: b"rar29-level-policy.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    for target in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let level_three =
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(3);
        let level_five =
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(5);

        let lz = write_compressed_archive(&entries, level_three).unwrap();
        let auto = write_compressed_archive(&entries, level_five).unwrap();
        let lz_archive = Archive::parse(&lz).unwrap();
        let auto_archive = Archive::parse(&auto).unwrap();
        let lz_file = lz_archive.files().next().unwrap();
        let auto_file = auto_archive.files().next().unwrap();

        assert_eq!(lz_file.method, 0x33, "{target:?} level 3");
        assert!(
            matches!(auto_file.method, 0x33 | 0x35),
            "{target:?} level 5"
        );
        assert!(auto_file.pack_size <= lz_file.pack_size, "{target:?}");
        assert_eq!(collect_extract(&lz_archive).unwrap()[0].data, payload);
        assert_eq!(collect_extract(&auto_archive).unwrap()[0].data, payload);
    }
}

#[test]
fn rar29_family_writer_middle_levels_use_lz_filter_policy_without_ppmd() {
    let mut payload = Vec::new();
    payload.extend((0..2048).map(|index| (index * 37 + 11) as u8));
    let code_start = payload.len();
    let call_target = code_start + 0x1800;
    for index in 0..512usize {
        payload.extend_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, (index & 0x7f) as u8]);
        let call_pos = payload.len();
        payload.push(0xe8);
        let next = call_pos + 5;
        let relative = (call_target as i64 - next as i64) as i32;
        payload.extend_from_slice(&relative.to_le_bytes());
        payload.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5d, 0xc3]);
    }
    payload.extend((0..2048).map(|index| (index * 53 + 7) as u8));
    let entries = [FileEntry {
        name: b"rar29-level-four-x86.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for target in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let plain_lz_size = rars::codec::rar29::unpack29_encode_literals(&payload)
            .unwrap()
            .len() as u64;

        for (level, expected_method) in [(1, 0x31), (2, 0x32), (3, 0x33), (4, 0x34)] {
            let bytes = write_compressed_archive(
                &entries,
                WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(level),
            )
            .unwrap();
            let archive = Archive::parse(&bytes).unwrap();
            let file = archive.files().next().unwrap();

            assert_eq!(file.method, expected_method, "{target:?} level {level}");
            assert!(file.pack_size < plain_lz_size, "{target:?} level {level}");
            assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
        }
    }
}

#[test]
fn rar29_family_level_four_stamps_method_and_round_trips_lazy_payload() {
    let payload = b"abcdXbcdYYYYYYYYYYYYabcdYYYYYYYYYYYY".repeat(64);
    let entries = [FileEntry {
        name: b"lazy-lz.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for target in [
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let level_three = write_compressed_archive(
            &entries,
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(3),
        )
        .unwrap();
        let level_four = write_compressed_archive(
            &entries,
            WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(4),
        )
        .unwrap();
        let level_three_archive = Archive::parse(&level_three).unwrap();
        let level_four_archive = Archive::parse(&level_four).unwrap();
        let level_three_file = level_three_archive.files().next().unwrap();
        let level_four_file = level_four_archive.files().next().unwrap();

        assert_eq!(level_three_file.method, 0x33, "{target:?}");
        assert_eq!(level_four_file.method, 0x34, "{target:?}");
        assert_eq!(
            collect_extract(&level_four_archive).unwrap()[0].data,
            payload
        );
    }
}

#[test]
fn default_rar29_writer_uses_auto_policy_for_audio_shaped_data() {
    let mut payload = Vec::new();
    for sample in 0..16_384i16 {
        let left = sample.wrapping_mul(3).wrapping_add(200);
        let right = sample.wrapping_mul(3).wrapping_sub(200);
        payload.extend_from_slice(&left.to_le_bytes());
        payload.extend_from_slice(&right.to_le_bytes());
    }
    let entries = [FileEntry {
        name: b"default-auto-audio.wav",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let default = write_compressed_archive(&entries, options).unwrap();
    let explicit_audio = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        options,
        FilterPolicy::Explicit(FilterSpec::whole(FilterKind::Audio { channels: 4 })),
    )
    .unwrap();
    let ppmd = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        options.with_method(Rar29Method::Ppmd),
        FilterPolicy::None,
    )
    .unwrap();
    let default_archive = Archive::parse(&default).unwrap();
    let audio_archive = Archive::parse(&explicit_audio).unwrap();
    let ppmd_archive = Archive::parse(&ppmd).unwrap();
    let default_file = default_archive.files().next().unwrap();
    let audio_file = audio_archive.files().next().unwrap();
    let ppmd_file = ppmd_archive.files().next().unwrap();

    assert_eq!(default_file.method, 0x33);
    assert!(default_file.pack_size <= audio_file.pack_size);
    assert!(default_file.pack_size < ppmd_file.pack_size);
    assert_eq!(collect_extract(&default_archive).unwrap()[0].data, payload);
}

#[test]
fn auto_filtered_rar29_writer_spans_separated_x86_call_clusters() {
    let mut payload = Vec::new();
    payload.extend((0..12_000).map(|index| (index * 37 + 11) as u8));
    let code_start = payload.len();
    let call_target = code_start + 0x5000;
    for index in 0..128usize {
        payload.extend_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, (index & 0x7f) as u8]);
        let call_pos = payload.len();
        payload.push(0xe8);
        let next = call_pos + 5;
        let relative = (call_target as i64 - next as i64) as i32;
        payload.extend_from_slice(&relative.to_le_bytes());
        payload.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5d, 0xc3]);
    }
    payload.extend((0..8192).map(|index| (index * 17 + 5) as u8));
    for index in 0..128usize {
        payload.extend_from_slice(&[0x56, 0x8b, 0xf1, 0x83, 0xec, (index & 0x7f) as u8]);
        let call_pos = payload.len();
        payload.push(0xe8);
        let next = call_pos + 5;
        let relative = (call_target as i64 - next as i64) as i32;
        payload.extend_from_slice(&relative.to_le_bytes());
        payload.extend_from_slice(&[0x83, 0xc4, 0x04, 0x5e, 0xc3]);
    }
    let code_end = payload.len();
    payload.extend((0..12_000).map(|index| (index * 53 + 7) as u8));
    let entries = [FileEntry {
        name: b"x86-call-clusters.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let auto =
        write_rar29_compressed_archive_with_filter_policy(&entries, options, FilterPolicy::Auto)
            .unwrap();
    let span = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        options,
        FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8, code_start..code_end)),
    )
    .unwrap();
    let auto = Archive::parse(&auto).unwrap();
    let span = Archive::parse(&span).unwrap();
    let auto_file = auto.files().next().unwrap();
    let span_file = span.files().next().unwrap();

    assert_eq!(auto_file.method, 0x33);
    assert!(
        auto_file.pack_size <= span_file.pack_size,
        "auto filter should consider the whole code-section span"
    );
    assert_eq!(collect_extract(&auto).unwrap()[0].data, payload);
}

#[test]
fn ppmd_rar29_writer_emits_method_35_member() {
    let mut payload = b"rar29 ppmd writer text alpha beta gamma delta\n".repeat(128);
    payload.extend_from_slice(&[2, 2, 2, b'p', b'p', b'm', b'd']);
    let entries = [FileEntry {
        name: b"rar29-ppmd.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
            .with_method(Rar29Method::Ppmd),
        FilterPolicy::None,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 29);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn ppmd_rar29_writer_uses_period_compatible_lz_escapes_for_repeated_data() {
    let phrase = b"rar29 ppmd writer repeated distance phrase ";
    let mut payload = b"seed "
        .iter()
        .copied()
        .chain(std::iter::repeat_n(b'Q', 512))
        .collect::<Vec<_>>();
    payload.extend_from_slice(phrase);
    payload.extend_from_slice(b"middle gap for offset greater than one ");
    payload.extend_from_slice(phrase);
    payload.extend_from_slice(phrase);
    let entries = [FileEntry {
        name: b"rar29-ppmd-lz.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let ppmd = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        options.with_method(Rar29Method::Ppmd),
        FilterPolicy::None,
    )
    .unwrap();
    let codec_packed = rars::codec::rar29::unpack29_encode_ppmd(&payload).unwrap();
    let archive = Archive::parse(&ppmd).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.method, 0x35);
    assert_eq!(file.pack_size, codec_packed.len() as u64);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn ppmd_rar29_writer_embeds_vm_filter_record() {
    let payload = b"\xe8\0\0\0\0rar29 ppmd embedded e8 filter payload\n".repeat(16);
    let entries = [FileEntry {
        name: b"rar29-ppmd-e8.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
            .with_method(Rar29Method::Ppmd),
        FilterPolicy::explicit(FilterKind::E8),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.method, 0x35);
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn writes_solid_compressed_rar15_archive_that_reader_extracts() {
    let entries = [
        FileEntry {
            name: b"one.txt",
            data: b"shared prefix shared prefix shared prefix alpha\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"two.txt",
            data: b"shared prefix shared prefix shared prefix beta\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar15, features),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[1].data, entries[1].data);
}

#[test]
fn writes_encrypted_rar15_archives_that_reader_extracts_with_password() {
    let features = FeatureSet::store_only();

    let stored = [StoredEntry {
        name: b"secret-store.txt",
        data: b"stored secret\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let stored_bytes =
        write_stored_archive(&stored, WriterOptions::new(ArchiveVersion::Rar15, features)).unwrap();
    let stored_archive = Archive::parse(&stored_bytes).unwrap();
    let stored_file = stored_archive.files().next().unwrap();
    assert!(stored_file.is_encrypted());
    assert!(matches!(
        collect_extract(&stored_archive),
        Err(Error::NeedPassword)
    ));
    let extracted = collect_extract_with_password(&stored_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored[0].data);

    let compressed = [FileEntry {
        name: b"secret-compressed.txt",
        data: b"compressed secret compressed secret\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];
    let compressed_bytes = write_compressed_archive(
        &compressed,
        WriterOptions::new(ArchiveVersion::Rar15, features),
    )
    .unwrap();
    let compressed_archive = Archive::parse(&compressed_bytes).unwrap();
    let compressed_file = compressed_archive.files().next().unwrap();
    assert!(compressed_file.is_encrypted());
    assert!(matches!(
        collect_extract_with_password(&compressed_archive, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract_with_password(&compressed_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed[0].data);
}

#[test]
fn writes_aes_encrypted_rar3_and_rar4_archives_that_reader_extracts_with_password() {
    let features = FeatureSet::store_only();

    for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        let stored = [StoredEntry {
            name: b"aes-store.txt",
            data: b"stored aes secret\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }];
        let stored_bytes = write_stored_archive(&stored, WriterOptions::new(target, features))
            .unwrap_or_else(|error| panic!("{target:?} stored AES writer failed: {error}"));
        let stored_archive = Archive::parse(&stored_bytes).unwrap();
        let stored_file = stored_archive.files().next().unwrap();
        assert!(stored_file.is_encrypted());
        assert_eq!(stored_file.unp_ver, 29);
        assert!(stored_file.salt.is_some());
        assert_eq!(stored_file.pack_size % 16, 0);
        assert!(matches!(
            collect_extract(&stored_archive),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            collect_extract_with_password(&stored_archive, Some(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let extracted = collect_extract_with_password(&stored_archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, stored[0].data);

        let compressed = [FileEntry {
            name: b"aes-compressed.txt",
            data: b"compressed aes secret compressed aes secret\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }];
        let compressed_bytes =
            write_compressed_archive(&compressed, WriterOptions::new(target, features))
                .unwrap_or_else(|error| panic!("{target:?} compressed AES writer failed: {error}"));
        let compressed_archive = Archive::parse(&compressed_bytes).unwrap();
        let compressed_file = compressed_archive.files().next().unwrap();
        assert!(compressed_file.is_encrypted());
        assert_eq!(compressed_file.unp_ver, 29);
        assert!(compressed_file.salt.is_some());
        assert_eq!(compressed_file.pack_size % 16, 0);
        assert!(matches!(
            collect_extract(&compressed_archive),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            collect_extract_with_password(&compressed_archive, Some(b"wrong")),
            Err(Error::WrongPasswordOrCorruptData)
        ));
        let extracted =
            collect_extract_with_password(&compressed_archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, compressed[0].data);
    }
}

#[test]
fn writes_header_encrypted_rar3_and_rar4_archives_that_reader_extracts_with_password() {
    for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        let entries = [FileEntry {
            name: b"header-secret.txt",
            data: b"RAR 3.x header encrypted writer payload\n",
            file_time: 0x5a21_0000,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }];
        let bytes =
            write_compressed_archive(&entries, WriterOptions::new(target, features)).unwrap();

        assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
        let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
        assert!(archive.main.has_encrypted_headers());
        let files: Vec<_> = archive.files().collect();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, b"header-secret.txt");
        assert!(files[0].is_encrypted());

        let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].data, entries[0].data);
    }
}

#[test]
fn writes_solid_header_encrypted_rar3_and_rar4_archives_that_reader_extracts_with_password() {
    for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        let mut features = FeatureSet::store_only();
        features.header_encryption = true;
        features.solid = true;
        let entries = [
            FileEntry {
                name: b"solid-header-one.txt",
                data: b"solid header encrypted common prefix one one one\n",
                file_time: 0x5a21_0000,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            FileEntry {
                name: b"solid-header-two.txt",
                data: b"solid header encrypted common prefix two two two\n",
                file_time: 0x5a21_0000,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
        ];
        let bytes =
            write_compressed_archive(&entries, WriterOptions::new(target, features)).unwrap();

        assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
        let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
        assert!(archive.main.has_encrypted_headers());
        assert!(archive.main.is_solid());
        let files: Vec<_> = archive.files().collect();
        assert_eq!(files.len(), 2);
        assert!(!files[0].is_solid());
        assert!(files[1].is_solid());
        assert!(files.iter().all(|file| file.is_encrypted()));

        let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
        assert_eq!(extracted[0].data, entries[0].data);
        assert_eq!(extracted[1].data, entries[1].data);
    }
}

#[test]
fn rar3_and_rar4_aes_writer_uses_fresh_salts() {
    let features = FeatureSet::store_only();
    let entry = [FileEntry {
        name: b"aes-salt.txt",
        data: b"same plaintext same password\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    }];

    let first =
        write_compressed_archive(&entry, WriterOptions::new(ArchiveVersion::Rar30, features))
            .unwrap();
    let second =
        write_compressed_archive(&entry, WriterOptions::new(ArchiveVersion::Rar30, features))
            .unwrap();
    let first_archive = Archive::parse(&first).unwrap();
    let second_archive = Archive::parse(&second).unwrap();
    let first_file = first_archive.files().next().unwrap();
    let second_file = second_archive.files().next().unwrap();

    assert_ne!(first, second);
    assert_ne!(first_file.salt, second_file.salt);
    assert_eq!(
        collect_extract_with_password(&first_archive, Some(b"password")).unwrap()[0].data,
        entry[0].data
    );
    assert_eq!(
        collect_extract_with_password(&second_archive, Some(b"password")).unwrap()[0].data,
        entry[0].data
    );
}

#[test]
fn writes_stored_rar15_volume_set_that_reader_reassembles() {
    let entry = StoredEntry {
        name: b"split-store.bin",
        data: b"abcdefghijklmnopqrstuvwxyz0123456789",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };

    let parts = write_stored_volumes(entry, WriterOptions::default(), 10).unwrap();
    assert_eq!(parts.len(), 4);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives[0].main.is_volume());
    assert!(archives[0].main.is_first_volume());
    assert!(archives[0].files().next().unwrap().is_split_after());
    assert!(archives[1].files().next().unwrap().is_split_before());
    assert!(archives[1].files().next().unwrap().is_split_after());
    assert!(archives[3].files().next().unwrap().is_split_before());
    assert!(!archives[3].files().next().unwrap().is_split_after());

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, entry.name);
    assert_eq!(extracted[0].data, entry.data);
}

#[test]
fn writes_compressed_rar15_volume_set_that_reader_reassembles() {
    let entry = FileEntry {
        name: b"split-compressed.txt",
        data: b"abcabcabcabcabcabcabcabcabcabcabcabcabcabc",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };

    let parts = write_compressed_volumes(entry, WriterOptions::default(), 8).unwrap();
    assert!(parts.len() >= 2);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives[0].main.is_volume());
    assert!(archives[0].main.is_first_volume());
    assert!(archives[0].files().next().unwrap().is_split_after());

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, entry.name);
    assert_eq!(extracted[0].data, entry.data);
}

#[test]
fn writes_compressed_rar20_volume_set_that_reader_reassembles() {
    let entry = FileEntry {
        name: b"split-rar20-compressed.txt",
        data: &b"rar20 split compressed phrase alpha beta gamma "[..].repeat(32),
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };
    let options = WriterOptions::new(ArchiveVersion::Rar20, FeatureSet::store_only());

    let parts = write_compressed_volumes(entry, options, 8).unwrap();
    assert!(parts.len() >= 2);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives[0].main.is_volume());
    assert!(archives[0].main.is_first_volume());
    let first_file = archives[0].files().next().unwrap();
    assert_eq!(first_file.unp_ver, 20);
    assert!(first_file.is_split_after());

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, entry.name);
    assert_eq!(extracted[0].data, entry.data);
}

#[test]
fn writes_compressed_rar29_volume_set_that_reader_reassembles() {
    let entry = FileEntry {
        name: b"split-rar29-compressed.txt",
        data: &b"rar29 split compressed phrase alpha beta gamma "[..].repeat(32),
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let parts = write_compressed_volumes(entry, options, 8).unwrap();
    assert!(parts.len() >= 2);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives[0].main.is_volume());
    assert!(archives[0].main.is_first_volume());
    let first_file = archives[0].files().next().unwrap();
    assert_eq!(first_file.unp_ver, 29);
    assert!(first_file.is_split_after());

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, entry.name);
    assert_eq!(extracted[0].data, entry.data);
}

#[test]
fn writes_encrypted_rar15_volume_sets_that_reader_reassembles_with_password() {
    let features = FeatureSet::store_only();
    let options = WriterOptions::new(ArchiveVersion::Rar15, features);

    let stored = StoredEntry {
        name: b"split-secret-store.bin",
        data: b"abcdefghijklmnopqrstuvwxyz0123456789",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let stored_parts = write_stored_volumes(stored, options, 24).unwrap();
    let stored_archives: Vec<_> = stored_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(stored_archives[0].files().next().unwrap().is_encrypted());
    assert!(matches!(
        collect_extract_volumes(&stored_archives),
        Err(Error::NeedPassword)
    ));
    let extracted =
        collect_extract_volumes_with_password(&stored_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored.data);

    let compressed = FileEntry {
        name: b"split-secret-compressed.txt",
        data: b"secret compressed secret compressed secret compressed\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let compressed_parts = write_compressed_volumes(compressed, options, 24).unwrap();
    let compressed_archives: Vec<_> = compressed_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(compressed_archives[0]
        .files()
        .next()
        .unwrap()
        .is_encrypted());
    assert!(matches!(
        collect_extract_volumes_with_password(&compressed_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&compressed_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed.data);
}

#[test]
fn writes_encrypted_rar20_volume_sets_that_reader_reassembles_with_password() {
    let features = FeatureSet::store_only();
    let options = WriterOptions::new(ArchiveVersion::Rar20, features);

    let stored = StoredEntry {
        name: b"split-rar20-secret-store.bin",
        data: b"abcdefghijklmnopqrstuvwxyz0123456789",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let stored_parts = write_stored_volumes(stored, options, 24).unwrap();
    let stored_archives: Vec<_> = stored_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let first_stored = stored_archives[0].files().next().unwrap();
    assert_eq!(first_stored.unp_ver, 20);
    assert!(first_stored.is_encrypted());
    assert!(matches!(
        collect_extract_volumes(&stored_archives),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_volumes_with_password(&stored_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&stored_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored.data);

    let compressed = FileEntry {
        name: b"split-rar20-secret-compressed.txt",
        data: b"secret rar20 compressed secret rar20 compressed secret rar20 compressed\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let compressed_parts = write_compressed_volumes(compressed, options, 24).unwrap();
    let compressed_archives: Vec<_> = compressed_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let first_compressed = compressed_archives[0].files().next().unwrap();
    assert_eq!(first_compressed.unp_ver, 20);
    assert!(first_compressed.is_encrypted());
    assert!(matches!(
        collect_extract_volumes_with_password(&compressed_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&compressed_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed.data);
}

#[test]
fn writes_encrypted_rar29_volume_sets_that_reader_reassembles_with_password() {
    let features = FeatureSet::store_only();
    let options = WriterOptions::new(ArchiveVersion::Rar29, features);

    let stored = StoredEntry {
        name: b"split-rar29-secret-store.bin",
        data: b"abcdefghijklmnopqrstuvwxyz0123456789",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let stored_parts = write_stored_volumes(stored, options, 24).unwrap();
    let stored_archives: Vec<_> = stored_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let first_stored = stored_archives[0].files().next().unwrap();
    assert_eq!(first_stored.unp_ver, 29);
    assert!(first_stored.is_encrypted());
    assert!(first_stored.salt.is_some());
    for archive in &stored_archives[1..] {
        assert_eq!(archive.files().next().unwrap().salt, first_stored.salt);
    }
    assert!(matches!(
        collect_extract_volumes(&stored_archives),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_volumes_with_password(&stored_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&stored_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored.data);

    let compressed = FileEntry {
        name: b"split-rar29-secret-compressed.txt",
        data: b"secret rar29 compressed secret rar29 compressed secret rar29 compressed\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let compressed_parts = write_compressed_volumes(compressed, options, 24).unwrap();
    let compressed_archives: Vec<_> = compressed_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let first_compressed = compressed_archives[0].files().next().unwrap();
    assert_eq!(first_compressed.unp_ver, 29);
    assert!(first_compressed.is_encrypted());
    assert!(first_compressed.salt.is_some());
    for archive in &compressed_archives[1..] {
        assert_eq!(archive.files().next().unwrap().salt, first_compressed.salt);
    }
    assert!(matches!(
        collect_extract_volumes_with_password(&compressed_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&compressed_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed.data);
}

#[test]
fn writes_encrypted_rar3_and_rar4_volume_sets_that_reader_reassembles_with_password() {
    for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        assert_encrypted_rar3_volume_sets_round_trip(target);
    }
}

#[test]
fn writes_header_encrypted_rar3_and_rar4_volume_sets_that_reader_reassembles_with_password() {
    for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        assert_header_encrypted_rar3_volume_sets_round_trip(target);
    }
}

fn assert_encrypted_rar3_volume_sets_round_trip(target: ArchiveVersion) {
    let features = FeatureSet::store_only();
    let options = WriterOptions::new(target, features);

    let stored = StoredEntry {
        name: b"rar30-split-secret-store.bin",
        data: b"abcdefghijklmnopqrstuvwxyz0123456789",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let stored_parts = write_stored_volumes(stored, options, 10).unwrap();
    let stored_archives: Vec<_> = stored_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let first_stored = stored_archives[0].files().next().unwrap();
    assert!(first_stored.is_encrypted());
    assert!(first_stored.salt.is_some());
    assert_eq!(
        first_stored.file_crc,
        crc32(&first_stored.packed_data(&stored_archives[0]).unwrap())
    );
    for archive in &stored_archives[1..] {
        assert_eq!(archive.files().next().unwrap().salt, first_stored.salt);
    }
    assert!(matches!(
        collect_extract_volumes(&stored_archives),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_volumes_with_password(&stored_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&stored_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored.data);

    let compressed = FileEntry {
        name: b"rar30-split-secret-compressed.txt",
        data: b"secret compressed secret compressed secret compressed\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let compressed_parts = write_compressed_volumes(compressed, options, 8).unwrap();
    let compressed_archives: Vec<_> = compressed_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let first_compressed = compressed_archives[0].files().next().unwrap();
    assert!(first_compressed.is_encrypted());
    assert!(first_compressed.salt.is_some());
    assert_eq!(
        first_compressed.file_crc,
        crc32(
            &first_compressed
                .packed_data(&compressed_archives[0])
                .unwrap()
        )
    );
    for archive in &compressed_archives[1..] {
        assert_eq!(archive.files().next().unwrap().salt, first_compressed.salt);
    }
    assert!(matches!(
        collect_extract_volumes_with_password(&compressed_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&compressed_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed.data);
}

fn assert_header_encrypted_rar3_volume_sets_round_trip(target: ArchiveVersion) {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let options = WriterOptions::new(target, features);

    let stored = StoredEntry {
        name: b"rar30-header-split-secret-store.bin",
        data: b"header encrypted stored split data repeats repeats",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let stored_parts = write_stored_volumes(stored, options, 24).unwrap();
    assert!(matches!(
        Archive::parse(&stored_parts[0]),
        Err(Error::NeedPassword)
    ));
    let stored_archives: Vec<_> = stored_parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    assert!(stored_archives[0].main.has_encrypted_headers());
    assert!(stored_archives[0].files().next().unwrap().is_encrypted());
    assert!(matches!(
        collect_extract_volumes_with_password(&stored_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&stored_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, stored.data);

    let compressed = FileEntry {
        name: b"rar30-header-split-secret-compressed.txt",
        data: b"header encrypted compressed split data repeats repeats repeats\n",
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let compressed_parts = write_compressed_volumes(compressed, options, 24).unwrap();
    assert!(matches!(
        Archive::parse(&compressed_parts[0]),
        Err(Error::NeedPassword)
    ));
    let compressed_archives: Vec<_> = compressed_parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    assert!(compressed_archives[0].main.has_encrypted_headers());
    assert!(compressed_archives[0]
        .files()
        .next()
        .unwrap()
        .is_encrypted());
    assert!(matches!(
        collect_extract_volumes_with_password(&compressed_archives, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted =
        collect_extract_volumes_with_password(&compressed_archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, compressed.data);
}

#[test]
fn pins_rars_generated_rar15_writer_oracle_bytes() {
    for (name, expected_len, expected_crc) in RARS_GENERATED_FIXTURE_BYTES {
        let bytes = std::fs::read(fixture(&format!("rars_generated/{name}"))).unwrap();

        assert_eq!(bytes.len(), *expected_len, "{name} length");
        assert_eq!(crc32(&bytes), *expected_crc, "{name} crc32");
    }
}

#[test]
fn extracts_rars_generated_rar15_writer_oracles() {
    for fixture_name in [
        "rars_generated/stored.rar",
        "rars_generated/compressed.rar",
        "rars_generated/solid.rar",
    ] {
        let bytes = std::fs::read(fixture(fixture_name)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted = collect_extract(&archive).unwrap();

        assert_eq!(extracted[0].name, b"payload.txt");
        assert_eq!(extracted[0].data, RARS_GENERATED_PAYLOAD);
        if fixture_name.ends_with("solid.rar") {
            assert_eq!(extracted[1].name, b"second.txt");
            assert_eq!(extracted[1].data, RARS_GENERATED_SECOND);
        }
    }
}

#[test]
fn extracts_rars_generated_rar15_comments_and_encryption_oracles() {
    let comment_bytes = std::fs::read(fixture("rars_generated/comments.rar")).unwrap();
    let comment_archive = Archive::parse(&comment_bytes).unwrap();
    assert_eq!(
        comment_archive.archive_comment().unwrap().as_deref(),
        Some(&b"oracle-note"[..])
    );
    let comment_file = comment_archive.files().next().unwrap();
    assert_eq!(
        comment_file.file_comment().unwrap().as_deref(),
        Some(&b"file-note"[..])
    );
    assert_eq!(
        collect_extract(&comment_archive).unwrap()[0].data,
        RARS_GENERATED_PAYLOAD
    );

    let encrypted_bytes = std::fs::read(fixture("rars_generated/encrypted.rar")).unwrap();
    let encrypted_archive = Archive::parse(&encrypted_bytes).unwrap();
    assert!(matches!(
        collect_extract(&encrypted_archive),
        Err(Error::NeedPassword)
    ));
    assert_eq!(
        collect_extract_with_password(&encrypted_archive, Some(b"pass")).unwrap()[0].data,
        RARS_GENERATED_PAYLOAD
    );
}

#[test]
fn extracts_rars_generated_rar15_writer_volume_oracles() {
    let stored_archives: Vec<_> = [
        "rars_generated/split-store.rar",
        "rars_generated/split-store.r00",
        "rars_generated/split-store.r01",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();
    let stored = collect_extract_volumes(&stored_archives).unwrap();
    assert_eq!(stored[0].name, b"payload.txt");
    assert_eq!(stored[0].data, RARS_GENERATED_PAYLOAD);

    let encrypted_archives: Vec<_> = [
        "rars_generated/split-encrypted.rar",
        "rars_generated/split-encrypted.r00",
        "rars_generated/split-encrypted.r01",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();
    assert!(matches!(
        collect_extract_volumes(&encrypted_archives),
        Err(Error::NeedPassword)
    ));
    let encrypted =
        collect_extract_volumes_with_password(&encrypted_archives, Some(b"pass")).unwrap();
    assert_eq!(encrypted[0].name, b"payload.txt");
    assert_eq!(encrypted[0].data, RARS_GENERATED_PAYLOAD);
}

/// RAR 1.5 has no header encryption, and used to be told so only by a message
/// naming neither the option nor a format that does support it.
#[test]
fn rar15_writer_rejects_header_encryption_by_name() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let options = WriterOptions::new(ArchiveVersion::Rar15, features);
    let entry = StoredEntry {
        name: b"hello.txt",
        data: b"hello",
        file_time: 0,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };

    let error = write_stored_archive(&[entry], options).unwrap_err();
    assert_eq!(
        error.to_string(),
        "header encryption is not supported by rar15"
    );
    assert_eq!(
        rars::formats_supporting(
            rars::WriterOption::Feature(rars::Feature::HeaderEncryption),
            rars::PlanShape::new(),
        ),
        vec![
            ArchiveVersion::Rar30,
            ArchiveVersion::Rar40,
            ArchiveVersion::Rar50,
            ArchiveVersion::Rar70,
        ]
    );
}

#[test]
fn parses_rar300_comment_subblock_and_stored_file() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.sfx_offset, 0);
    assert_eq!(archive.main.flags, 0);

    let subblocks: Vec<_> = archive.new_subs().collect();
    assert_eq!(subblocks.len(), 1);
    assert_eq!(subblocks[0].kind, NewSubKind::ArchiveComment);
    assert_eq!(subblocks[0].file.name, b"CMT");
    assert_eq!(subblocks[0].file.method, 0x33);
    assert_eq!(subblocks[0].file.unp_ver, 29);
    assert_eq!(subblocks[0].file.pack_size, 42);
    assert_eq!(subblocks[0].file.unp_size, 29);

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].is_stored());
    assert_eq!(files[0].method, 0x30);
    assert_eq!(files[0].unp_ver, 29);
    assert_eq!(files[0].pack_size, 30);
    assert_eq!(files[0].unp_size, 30);
    assert_eq!(files[0].file_crc, 0xa538535e);
    assert_eq!(
        files[0].packed_data(&archive).unwrap(),
        b"Hello, RAR 3.x fixture world.\n"
    );
}

#[test]
fn parses_rar202_main_header_with_embedded_comment_subblock() {
    let bytes = std::fs::read(fixture("rar202/comment_nopsw.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.main.head_crc, 0x01bd);
    assert_eq!(archive.main.head_size, 51);
    assert!(archive.main.flags & 0x0002 != 0);
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"FILE1.TXT");
    assert_eq!(files[1].name, b"FILE2.TXT");
    assert_eq!(files[0].unp_ver, 20);
    assert_eq!(files[1].unp_ver, 20);
    assert!(files.iter().all(|file| file.block.flags & 0x0008 != 0));
}

#[test]
fn extracts_rar202_encrypted_files_with_rar20_cipher() {
    let bytes = std::fs::read(fixture("rar202/comment_psw.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|file| file.is_encrypted()));
    assert!(matches!(
        collect_extract(&archive),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"FILE1.TXT");
    assert_eq!(extracted[0].data, b"file1\r\n");
    assert_eq!(extracted[1].name, b"FILE2.TXT");
    assert_eq!(extracted[1].data, b"file2\r\n");
    assert_eq!(crc32(&extracted[0].data), files[0].file_crc);
    assert_eq!(crc32(&extracted[1].data), files[1].file_crc);
}

#[test]
fn rejects_wrong_password_for_rar20_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("rar202/comment_psw.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        collect_extract_with_password(&archive, Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn header_encrypted_rar3_archive_requires_password_to_parse() {
    let bytes = std::fs::read(fixture("encrypted/header_enc_1234.rar")).unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
}

#[test]
fn extracts_rar300_header_encrypted_archive_with_password() {
    let bytes = std::fs::read(fixture("encrypted/header_rar300_password.rar")).unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let file = archive.files().next().unwrap();

    assert!(archive.main.has_encrypted_headers());
    assert_eq!(file.name, b"hello.txt");
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);

    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn parses_rar300_header_encrypted_archive_from_path_with_password() {
    let archive = Archive::parse_path_with_password(
        fixture("encrypted/header_rar300_password.rar"),
        Some(b"password"),
    )
    .unwrap();
    let file = archive.files().next().unwrap();

    assert!(archive.main.has_encrypted_headers());
    assert_eq!(file.name, b"hello.txt");
    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
}

#[test]
fn extracts_rar420_header_encrypted_archive_with_password() {
    let bytes = std::fs::read(fixture("encrypted/header_rar420_password.rar")).unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let file = archive.files().next().unwrap();

    assert!(archive.main.has_encrypted_headers());
    assert_eq!(file.name, b"hello.txt");
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);

    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn parses_rar420_header_encrypted_archive_from_path_with_password() {
    let archive = Archive::parse_path_with_password(
        fixture("encrypted/header_rar420_password.rar"),
        Some(b"password"),
    )
    .unwrap();
    let file = archive.files().next().unwrap();

    assert!(archive.main.has_encrypted_headers());
    assert_eq!(file.name, b"hello.txt");
    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
}

#[test]
fn extracts_rar300_aes_encrypted_file_with_password() {
    let bytes = std::fs::read(fixture("encrypted/per_file_rar300_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"hello.txt");
    assert!(file.is_encrypted());
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.method, 0x33);
    assert_eq!(
        file.salt,
        Some([0x4a, 0x81, 0x67, 0x7d, 0xc0, 0x3d, 0x5f, 0x83])
    );
    assert!(matches!(
        collect_extract(&archive),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn rejects_wrong_password_for_rar3_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("encrypted/per_file_rar300_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        collect_extract_with_password(&archive, Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn extracts_rar4_aes_encrypted_compressed_member() {
    let bytes = std::fs::read(fixture("encrypted/per_file_rar4_libarchive_mixed.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 4);
    assert_eq!(files[1].name, b"b.txt");
    assert!(files[1].is_encrypted());
    assert_eq!(files[1].unp_ver, 29);
    assert_eq!(files[1].method, 0x33);

    let data = collect_file_with_password(&archive, files[1], Some(b"password"))
        .unwrap()
        .data;
    assert_eq!(data, b"This is from b.txt");
    assert_eq!(crc32(&data), 0xa9fa1485);
}

#[test]
fn extracts_rar4_junrar_encrypted_member_with_correct_password() {
    let bytes = std::fs::read(fixture("encrypted/rar4_junrar_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"file1.txt");
    assert!(file.is_encrypted());
    assert_eq!(file.method, 0x33);
    assert_eq!(file.unp_ver, 29);
    assert!(matches!(
        collect_extract(&archive),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_with_password(&archive, Some(b"junrar")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"file1.txt");
    assert_eq!(extracted[0].data, b"file1\n");
    assert_eq!(crc32(&extracted[0].data), 0xe229f704);
}

#[test]
fn rejects_wrong_password_for_rar4_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("encrypted/rar4_junrar_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        collect_extract_with_password(&archive, Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn extracts_rar4_junrar_header_encrypted_member_with_correct_password() {
    let bytes = std::fs::read(fixture("encrypted/rar4_junrar_header_encrypted.rar")).unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"junrar")).unwrap();
    assert!(archive.main.has_encrypted_headers());

    let extracted = collect_extract_with_password(&archive, Some(b"junrar")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"file1.txt");
    assert_eq!(extracted[0].data, b"file1\n");
    assert_eq!(crc32(&extracted[0].data), 0xe229f704);
}

#[test]
fn decodes_rar4_compact_unicode_name_before_extraction() {
    let bytes = std::fs::read(fixture(
        "encrypted/rar4_junrar_file_content_encrypted_unicode.rar",
    ))
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, "新建文本文档.txt".as_bytes());
    assert!(file.is_encrypted());

    let extracted = collect_extract_with_password(&archive, Some(b"test")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, "新建文本文档.txt".as_bytes());
    assert_eq!(extracted[0].data, b"aaaaaaaaaa");
    assert_eq!(crc32(&extracted[0].data), 0x4c11cdf0);
}

#[test]
fn extracts_rar4_sharpcompress_encrypted_files_only_archive() {
    let bytes = std::fs::read(fixture("encrypted/rar4_sharpcompress_files_only.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 6);
    assert_eq!(files[0].name, b"exe\\test.exe");
    assert_eq!(files[1].name, b"jpg\\test.jpg");
    assert_eq!(files[2].name, "тест.txt".as_bytes());
    assert_eq!(files[3].name, b"Empty");
    assert_eq!(files[4].name, b"exe");
    assert_eq!(files[5].name, b"jpg");
    assert!(files[..3].iter().all(|file| file.is_encrypted()));
    assert!(files[3..].iter().all(|file| file.is_directory()));

    let extracted = collect_extract_with_password(&archive, Some(b"test")).unwrap();
    assert_eq!(extracted.len(), 6);
    assert_eq!(extracted[0].name, b"exe\\test.exe");
    assert_eq!(extracted[0].data.len(), 45056);
    assert_eq!(crc32(&extracted[0].data), 0xcfb109c8);
    assert_eq!(extracted[1].name, b"jpg\\test.jpg");
    assert_eq!(extracted[1].data.len(), 40372);
    assert_eq!(crc32(&extracted[1].data), 0x088814e3);
    assert_eq!(extracted[2].name, "тест.txt".as_bytes());
    assert_eq!(extracted[2].data.len(), 15498);
    assert_eq!(crc32(&extracted[2].data), 0x9bd160fa);
    assert!(extracted[3..].iter().all(|entry| entry.is_directory));
}

#[test]
fn extracts_rar4_mixed_visible_names_known_password_fixture() {
    let bytes = std::fs::read(fixture("encrypted/rar4_mixed_visible_names_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, b"1File.txt");
    assert_eq!(files[1].name, "2中文.txt".as_bytes());
    assert_eq!(files[2].name, b"3Sec.txt");
    assert!(!files[0].is_encrypted());
    assert!(files[1].is_encrypted());
    assert!(files[2].is_encrypted());

    let stored = collect_file(&archive, files[0]).unwrap();
    assert_eq!(stored.data, b"1File");
    assert_eq!(crc32(&stored.data), 0x578a2019);

    assert!(matches!(
        collect_extract(&archive),
        Err(Error::NeedPassword)
    ));
    assert_eq!(
        collect_extract_with_password(&archive, Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );

    let extracted = collect_extract_with_password(&archive, Some(b"known-pass")).unwrap();
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].name, b"1File.txt");
    assert_eq!(extracted[0].data, b"1File");
    assert_eq!(extracted[1].name, "2中文.txt".as_bytes());
    assert_eq!(extracted[1].data, b"known encrypted unicode payload\n");
    assert_eq!(crc32(&extracted[1].data), 0x1e180200);
    assert_eq!(extracted[2].name, b"3Sec.txt");
    assert_eq!(extracted[2].data, b"known encrypted ascii payload\n");
    assert_eq!(crc32(&extracted[2].data), 0xbef64217);
}

#[test]
fn extracts_rar300_stored_file_and_verifies_crc32() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(extracted[0].host_os, 2);
    assert!(!extracted[0].is_directory);

    let file = archive.files().next().unwrap();
    file.verify_crc32(&extracted[0].data).unwrap();
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
}

#[test]
fn rejects_corrupt_rar15_40_header_checksum() {
    let mut bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let main_flags_offset = 7 + 3;
    bytes[main_flags_offset] ^= 0x01;

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::CrcMismatch { .. })
    ));
}

#[test]
fn rejects_corrupt_rar15_40_stored_payload_checksum() {
    let mut bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let needle = b"Hello, RAR 3.x fixture world.\n";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("stored payload in fixture");
    bytes[offset] ^= 0x01;
    let archive = Archive::parse(&bytes).unwrap();

    match collect_extract(&archive) {
        Err(Error::Crc32Mismatch { .. }) => {}
        Err(Error::AtEntry { source, .. }) if matches!(*source, Error::Crc32Mismatch { .. }) => {}
        other => panic!("expected checksum error, got {other:?}"),
    }
}

#[test]
fn extracts_large_solid_rar300_with_reused_tables() {
    let bytes = std::fs::read(fixture("rar300/solid_rar300.rar")).unwrap();
    let expected_big = std::fs::read(fixture("rar300/bigtext_64k.bin")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[1].name, b"tiny.txt");
    assert_eq!(files[2].name, b"bigtext_64k.bin");
    assert_eq!(files[0].pack_size, 45);
    assert_eq!(files[1].pack_size, 3);
    assert_eq!(files[2].pack_size, 9_753);
    assert_eq!(files[0].unp_size, 30);
    assert_eq!(files[1].unp_size, 9);
    assert_eq!(files[2].unp_size, 65_536);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    assert!(files[2].is_solid());
    assert!(files.iter().all(|file| file.method == 0x33));
    assert!(files.iter().all(|file| file.unp_ver == 29));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 3.x fixture world.\n");
    assert_eq!(crc32(&extracted[0].data), 0xa538535e);
    assert_eq!(extracted[1].name, b"tiny.txt");
    assert_eq!(extracted[1].data, b"AAAAAAAA\n");
    assert_eq!(crc32(&extracted[1].data), 0xd27b5891);
    assert_eq!(extracted[2].name, b"bigtext_64k.bin");
    assert_eq!(extracted[2].data, expected_big);
    assert_eq!(crc32(&extracted[2].data), 0xddc95682);
}

#[test]
fn extracts_simple_solid_rar300_entries_with_codec_state() {
    let bytes = std::fs::read(fixture("rar300/solid_simple_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"one.txt");
    assert_eq!(
        extracted[0].data,
        b"shared prefix shared prefix shared prefix alpha\n"
    );
    assert_eq!(crc32(&extracted[0].data), 0x11cc9fbb);
    assert_eq!(extracted[1].name, b"two.txt");
    assert_eq!(
        extracted[1].data,
        b"shared prefix shared prefix shared prefix beta\n"
    );
    assert_eq!(crc32(&extracted[1].data), 0xf4fd09e8);
}

#[test]
fn extracts_compressed_rar300_lz_file() {
    let bytes = std::fs::read(fixture("rar300/compressed_text_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"text.txt");
    assert_eq!(extracted[0].data, expected_compressed_text_payload());
    assert_eq!(crc32(&extracted[0].data), 0x6a0d746d);
}

#[test]
fn extracts_rar154_unp15_compressed_file() {
    let bytes = std::fs::read(fixture("rar154/readme_154_normal.rar")).unwrap();
    let expected = std::fs::read(fixture("rar154/expected/README.md")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"README.md");
    assert_eq!(file.method, 0x33);
    assert_eq!(file.unp_ver, 15);
    assert_eq!(file.pack_size, 2068);
    assert_eq!(file.unp_size, 4198);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README.md");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x509e5e3c);
}

#[test]
fn extracts_rar154_crypt15_encrypted_compressed_file() {
    let bytes = std::fs::read(fixture("rar154/readme_154_password.rar")).unwrap();
    let expected = std::fs::read(fixture("rar154/expected/README.md")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"README.md");
    assert!(file.is_encrypted());
    assert_eq!(file.method, 0x33);
    assert_eq!(file.unp_ver, 15);
    assert!(matches!(
        collect_extract(&archive),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README.md");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x509e5e3c);
}

#[test]
fn rejects_wrong_password_for_rar15_encrypted_file_as_password_error() {
    let bytes = std::fs::read(fixture("rar154/readme_154_password.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        collect_extract_with_password(&archive, Some(b"wrong-password")),
        Err(Error::WrongPasswordOrCorruptData)
    );
}

#[test]
fn extracts_rar154_unp15_solid_flagged_file() {
    let bytes = std::fs::read(fixture("rar154/readme_154_store_solid.rar")).unwrap();
    let expected = std::fs::read(fixture("rar154/expected/README.md")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(archive.main.is_solid());
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"README.md");
    assert_eq!(extracted[0].data, expected);
}

#[test]
fn extracts_rar154_unp15_multi_file_archive() {
    let bytes = std::fs::read(fixture("rar154/doc_154_best.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 17);
    assert!(files.iter().all(|file| file.unp_ver == 15));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 17);
    let expected = expected_doc_154_best_manifest();
    for (entry, (name, size, crc)) in extracted.iter().zip(expected) {
        assert_eq!(entry.name, name.as_bytes());
        assert_eq!(entry.data.len(), size);
        assert_eq!(crc32(&entry.data), crc, "{name}");
    }
}

#[test]
fn extracts_rar154_unp15_audio_shaped_windows_archive() {
    let bytes = std::fs::read(fixture("rar154/audio_win_names_unpack15.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"BoatModernEnglish.wav");
    assert_eq!(extracted[0].data.len(), 56_464);
    assert_eq!(crc32(&extracted[0].data), 0x82d2ed89);
    assert_eq!(extracted[1].name, b"LICENSE.txt");
    assert_eq!(extracted[1].data.len(), 107);
    assert_eq!(crc32(&extracted[1].data), 0x8eaf20c4);
}

#[test]
fn extracts_rar154_unp15_audio_shaped_dos_archive() {
    let bytes = std::fs::read(fixture("rar154/audio_dos_names_unpack15.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"BOATMO~1.WAV");
    assert_eq!(extracted[0].data.len(), 56_464);
    assert_eq!(crc32(&extracted[0].data), 0x82d2ed89);
    assert_eq!(extracted[1].name, b"LICENSE.TXT");
    assert_eq!(extracted[1].data.len(), 107);
    assert_eq!(crc32(&extracted[1].data), 0x8eaf20c4);
}

#[test]
fn extracts_rar250_unp20_lz_file() {
    let bytes = std::fs::read(fixture("rar250/AUTOREJ.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"PLAIN.TXT");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.pack_size, 54);
    assert_eq!(file.unp_size, 2300);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"PLAIN.TXT");
    assert_eq!(extracted[0].data.len(), 2300);
    assert_eq!(crc32(&extracted[0].data), 0xafc0db74);
}

#[test]
fn parses_rar250_protect_head_recovery_record() {
    let bytes = std::fs::read(fixture("rar250_protect_head_rr5.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let protect = archive.protect_records().next().unwrap();

    assert_eq!(protect.version, 0x14);
    assert_eq!(protect.rec_sectors, 5);
    assert_eq!(protect.total_blocks, 201);
    assert_eq!(protect.mark, *b"Protect!");
    assert_eq!(
        protect.data_range.len(),
        protect.total_blocks as usize * 2 + protect.rec_sectors as usize * 512
    );
    assert_eq!(
        protect.total_blocks as usize,
        protect.block.offset.div_ceil(512)
    );
    assert_eq!(protect.block.offset % 512, 59);
}

#[test]
fn rar250_protect_head_declares_final_sector_that_overlaps_record() {
    for (path, rec_sectors) in [
        ("rar250_protect_head_rr1.rar", 1),
        ("rar250_protect_head_rr5.rar", 5),
    ] {
        let bytes = std::fs::read(fixture(path)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let protect = archive.protect_records().next().unwrap();

        assert_eq!(protect.rec_sectors, rec_sectors);
        assert_ne!(protect.block.offset % 512, 0);
        assert_eq!(
            protect.total_blocks as usize,
            protect.block.offset.div_ceil(512)
        );
        assert_eq!(
            protect.total_blocks as usize,
            protect.block.offset / 512 + 1
        );
        assert_eq!(
            protect.data_range.len(),
            protect.total_blocks as usize * 2 + protect.rec_sectors as usize * 512
        );
    }
}

#[test]
fn parses_rar300_newsub_recovery_record() {
    let bytes = std::fs::read(fixture("rar300/with_recovery_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.main.has_recovery_record());

    let recovery = archive
        .new_subs()
        .find(|sub| sub.kind == NewSubKind::RecoveryRecord)
        .unwrap();
    assert_eq!(recovery.file.name, b"RR");
    assert_eq!(recovery.file.method, 0x30);
    assert_eq!(recovery.file.pack_size, 5672);
    assert_eq!(recovery.file.unp_size, 5672);
}

#[test]
fn parses_compressed_rar300_newsub_recovery_record_fixture() {
    let bytes = std::fs::read(fixture("rar300/with_compressed_recovery_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.main.has_recovery_record());

    let recovery = archive
        .new_subs()
        .find(|sub| sub.kind == NewSubKind::RecoveryRecord)
        .unwrap();
    assert_eq!(recovery.file.name, b"RR");
    assert_eq!(recovery.file.method, 0x33);
    assert_eq!(recovery.file.pack_size, 6443);
    assert_eq!(recovery.file.unp_size, 5672);
}

#[test]
fn rejects_corrupt_compressed_rar300_newsub_recovery_record_fixture() {
    let bytes = std::fs::read(fixture(
        "rar300/with_compressed_recovery_header_synthetic.rar",
    ))
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.main.has_recovery_record());

    let recovery = archive
        .new_subs()
        .find(|sub| sub.kind == NewSubKind::RecoveryRecord)
        .unwrap();
    assert_eq!(recovery.file.name, b"RR");
    assert_eq!(recovery.file.method, 0x33);

    let err = archive.repair_protect_head().unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidHeader(_)
            | Error::Codec(_)
            | Error::Crc32Mismatch { .. }
            | Error::CrcMismatch { .. }
    ));
}

#[test]
fn repairs_rar250_protect_head_single_damaged_sector() {
    let bytes = std::fs::read(fixture("rar250_protect_head_rr5.rar")).unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let _file = clean.files().next().unwrap();
    let damage_offset = 512 + 16;
    let mut damaged = bytes.clone();
    damaged[damage_offset..damage_offset + 64].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let repaired = damaged_archive.repair_protect_head().unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = Archive::parse(&repaired).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"BIG.BIN");
    assert_eq!(crc32(&extracted[0].data), 0x9a0e0c8c);
}

#[test]
fn protect_head_does_not_repair_trailing_partial_sector_before_record() {
    let bytes = std::fs::read(fixture("rar250_protect_head_rr5.rar")).unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let protect: &ProtectHeader = clean.protect_records().next().unwrap();
    assert_ne!(protect.block.offset % 512, 0);

    let mut damaged = bytes.clone();
    let damage_offset = protect.block.offset - 16;
    damaged[damage_offset..damage_offset + 8].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let repaired = damaged_archive.repair_protect_head().unwrap();

    assert_eq!(repaired, damaged);
    assert_ne!(repaired, bytes);
    assert!(collect_extract(&Archive::parse(&repaired).unwrap()).is_err());
}

#[test]
fn protect_head_repairs_last_stable_sector_before_metadata_overlap() {
    let bytes = std::fs::read(fixture("rar250_protect_head_rr5.rar")).unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let protect: &ProtectHeader = clean.protect_records().next().unwrap();
    let stable_blocks = protect.block.offset / 512;
    assert!(stable_blocks > 0);
    assert!(usize::try_from(protect.total_blocks).unwrap() > stable_blocks);
    assert_ne!(protect.block.offset % 512, 0);

    let damage_offset = (stable_blocks - 1) * 512 + 16;
    assert!(damage_offset + 64 <= protect.block.offset);
    let mut damaged = bytes.clone();
    damaged[damage_offset..damage_offset + 64].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let repaired = damaged_archive.repair_protect_head().unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = Archive::parse(&repaired).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"BIG.BIN");
    assert_eq!(crc32(&extracted[0].data), 0x9a0e0c8c);
}

#[test]
fn repairs_rar300_newsub_recovery_single_damaged_sector() {
    let bytes = std::fs::read(fixture("rar300/with_recovery_rar300.rar")).unwrap();
    let mut damaged = bytes.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let repaired = damaged_archive.repair_protect_head().unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = Archive::parse(&repaired).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);
}

#[test]
fn repairs_compressed_rar300_newsub_recovery_single_damaged_sector() {
    let compressed = std::fs::read(fixture("rar300/with_compressed_recovery_rar300.rar")).unwrap();
    let expected = std::fs::read(fixture("rar300/with_recovery_rar300.rar")).unwrap();
    let mut damaged = compressed.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let repaired = damaged_archive.repair_protect_head().unwrap();

    assert_eq!(repaired, compressed);
    let repaired_archive = Archive::parse(&repaired).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);

    let expected_archive = Archive::parse(&expected).unwrap();
    let expected_extracted = collect_extract(&expected_archive).unwrap();
    assert_eq!(extracted[0].data, expected_extracted[0].data);
}

#[test]
fn newsub_recovery_repairs_trailing_partial_sector_before_record() {
    let bytes = std::fs::read(fixture("rar300/with_recovery_rar300.rar")).unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let recovery = clean
        .new_subs()
        .find(|sub| sub.kind == NewSubKind::RecoveryRecord)
        .unwrap();
    assert_ne!(recovery.file.block.offset % 512, 0);

    let mut damaged = bytes.clone();
    let damage_offset = recovery.file.block.offset - 16;
    damaged[damage_offset..damage_offset + 8].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let repaired = damaged_archive.repair_protect_head().unwrap();

    assert_eq!(repaired, bytes);
    let extracted = collect_extract(&Archive::parse(&repaired).unwrap()).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);
}

#[test]
fn rejects_rar250_protect_head_same_group_damage() {
    let bytes = std::fs::read(fixture("rar250_protect_head_rr5.rar")).unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let protect: &ProtectHeader = clean.protect_records().next().unwrap();
    assert_eq!(protect.rec_sectors, 5);
    let mut damaged = bytes.clone();
    damaged[512 + 10] ^= 0x55;
    damaged[512 * 6 + 10] ^= 0x55;

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(damaged_archive.repair_protect_head().is_err());
}

#[test]
fn repairs_rar300_old_style_recovery_volume_set() {
    let part1 = std::fs::read(fixture("rar300/rev_oldstyle.part1.rar")).unwrap();
    let part2 = std::fs::read(fixture("rar300/rev_oldstyle.part2.rar")).unwrap();
    let part3 = std::fs::read(fixture("rar300/rev_oldstyle.part3.rar")).unwrap();
    let part4 = std::fs::read(fixture("rar300/rev_oldstyle.part4.rar")).unwrap();
    let rev1 = std::fs::read(fixture("rar300/rev_oldstyle.part4_2_1.rev")).unwrap();

    let repaired = repair_rev3_volumes(
        &[Some(&part1), None, Some(&part3), Some(&part4)],
        2,
        &[(0, rev1.as_slice())],
    )
    .unwrap();

    assert_eq!(repaired[1], part2);
    let extracted = collect_extract_volumes(&[
        Archive::parse(&repaired[0]).unwrap(),
        Archive::parse(&repaired[1]).unwrap(),
        Archive::parse(&repaired[2]).unwrap(),
        Archive::parse(&repaired[3]).unwrap(),
    ])
    .unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(crc32(&extracted[0].data), 0xf3a82e44);
}

#[test]
fn repairs_rar4_new_style_recovery_volume_set_with_zeroed_rev_trailer() {
    let part1 = std::fs::read(fixture("rar300/rev_newstyle.part1.rar")).unwrap();
    let part2 = std::fs::read(fixture("rar300/rev_newstyle.part2.rar")).unwrap();
    let part3 = std::fs::read(fixture("rar300/rev_newstyle.part3.rar")).unwrap();
    let part4 = std::fs::read(fixture("rar300/rev_newstyle.part4.rar")).unwrap();
    let mut rev1 = std::fs::read(fixture("rar300/rev_newstyle.part1.rev")).unwrap();
    let len = rev1.len();
    rev1[len - 7..].fill(0);

    let repaired = repair_rev3_volumes(
        &[Some(&part1), None, Some(&part3), Some(&part4)],
        2,
        &[(0, rev1.as_slice())],
    )
    .unwrap();

    assert_eq!(repaired[1], part2);
    let extracted = collect_extract_volumes(&[
        Archive::parse(&repaired[0]).unwrap(),
        Archive::parse(&repaired[1]).unwrap(),
        Archive::parse(&repaired[2]).unwrap(),
        Archive::parse(&repaired[3]).unwrap(),
    ])
    .unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(crc32(&extracted[0].data), 0x442c5489);
}

#[test]
fn extracts_rar250_unp20_multimedia_switch_lz_file() {
    let bytes = std::fs::read(fixture("rar250/AUDIO.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"PCM_LR.WAV");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.pack_size, 1938);
    assert_eq!(file.unp_size, 32768);
    assert_eq!(rar15_first_file_data_peek(&bytes), 0x0040);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"PCM_LR.WAV");
    assert_eq!(extracted[0].data, expected_rar250_multimedia_payload());
    assert_eq!(crc32(&extracted[0].data), 0x713ef34b);
}

#[test]
fn extracts_synthetic_unp20_audio_block_archive() {
    for channels in 1..=4 {
        let samples = channels * 4;
        let bytes = synthetic_rar20_audio_archive(channels, samples);
        let peek = rar15_first_file_data_peek(&bytes);
        assert_eq!(peek & 0x8000, 0x8000);
        assert_eq!(((peek >> 12) & 3) + 1, channels as u16);

        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();
        assert_eq!(file.name, format!("AUDIO{channels}.BIN").as_bytes());
        assert_eq!(file.method, 0x35);
        assert_eq!(file.unp_ver, 20);
        assert_eq!(file.unp_size, samples as u64);

        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, format!("AUDIO{channels}.BIN").as_bytes());
        assert_eq!(extracted[0].data, vec![0; samples]);
    }
}

#[test]
fn extracts_rar250_unp20_audio_shaped_and_text_lz_archive() {
    let bytes = std::fs::read(fixture("rar250/unpack20_audio_text.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"BoatModernEnglish.wav");
    assert_eq!(files[1].name, b"LICENSE.txt");
    assert!(files.iter().all(|file| file.unp_ver == 20));
    assert_eq!(rar15_first_file_data_peek(&bytes), 0x2221);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"BoatModernEnglish.wav");
    assert_eq!(crc32(&extracted[0].data), files[0].file_crc);
    assert_eq!(extracted[1].name, b"LICENSE.txt");
    assert_eq!(crc32(&extracted[1].data), files[1].file_crc);
}

#[test]
fn extracts_rar250_unp20_solid_members() {
    let bytes = std::fs::read(fixture("rar250/SOLID.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"SOLID1.TXT");
    assert_eq!(files[1].name, b"SOLID2.TXT");
    assert_eq!(files[0].unp_ver, 20);
    assert_eq!(files[1].unp_ver, 20);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    assert_eq!(rar15_file_data_peeks(&bytes), [0x0dcd, 0xdfbe]);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_rar250_solid1_payload());
    assert_eq!(extracted[1].data, expected_rar250_solid2_payload());
    assert_eq!(crc32(&extracted[0].data), 0x97668cf2);
    assert_eq!(crc32(&extracted[1].data), 0x28833332);
}

#[test]
fn extracts_rar250_unp20_large_lz_file() {
    let bytes = std::fs::read(fixture("rar250/BIGLZ.RAR")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"BIGLZ.BIN");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.unp_size, 167_936);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"BIGLZ.BIN");
    assert_eq!(extracted[0].data, expected_rar250_big_lz_payload());
    assert_eq!(crc32(&extracted[0].data), 0x46ce9077);
}

#[test]
fn extracts_rar250_unp20_keep_tables_archive() {
    let bytes = std::fs::read(fixture("rar250/unpack20_keep_tables.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"unrar");
    assert_eq!(files[0].method, 0x33);
    assert_eq!(files[0].unp_ver, 20);
    assert_eq!(files[0].pack_size, 25_077);
    assert_eq!(files[0].unp_size, 54_212);
    assert_eq!(files[0].file_crc, 0xbf94ba22);
    assert_eq!(files[1].name, b"file_id.diz");
    assert_eq!(files[1].method, 0x33);
    assert_eq!(files[1].unp_ver, 20);
    assert_eq!(files[1].pack_size, 85);
    assert_eq!(files[1].unp_size, 76);
    assert_eq!(files[1].file_crc, 0x497a718f);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(crc32(&extracted[0].data), 0xbf94ba22);
    assert_eq!(crc32(&extracted[1].data), 0x497a718f);
}

#[test]
fn extracts_rar250_unp20_explicit_multiblock_archive() {
    let bytes = std::fs::read(fixture("rar250/unpack20_multiblock.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"multiblock.bin");
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.method, 0x35);
    assert_eq!(file.pack_size, 4_761);
    assert_eq!(file.unp_size, 16_384);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data.len(), 16_384);
    assert_eq!(crc32(&extracted[0].data), 0xa24d_a8f8);
}

#[test]
fn extracts_rar300_standard_rarvm_filter_fixtures() {
    for (name, entry_name, size, expected_crc) in [
        (
            "rar300/rarvm_x86_e8_rar300.rar",
            b"x86_e8_stream.bin".as_slice(),
            196_608,
            0xe0f3971f,
        ),
        (
            "rar300/rarvm_x86_e8e9_rar300.rar",
            b"x86_e8e9_stream.bin".as_slice(),
            196_608,
            0xdc573e1b,
        ),
        (
            "rar300/rarvm_delta_4ch_rar300.rar",
            b"delta_4ch_ramp.bin".as_slice(),
            262_144,
            0xa303b91f,
        ),
        (
            "rar300/rarvm_itanium_synthetic_rar300.rar",
            b"itanium_synthetic_bundles.bin".as_slice(),
            1_048_576,
            0x39086451,
        ),
        (
            "rar300/rarvm_rgb_gradient_rar300.rar",
            b"rgb_gradient_24bit.bmp".as_slice(),
            196_662,
            0xbf03aa49,
        ),
        (
            "rar300/rarvm_audio_stereo_rar300.rar",
            b"audio_stereo_pcm.wav".as_slice(),
            705_644,
            0x8ad44141,
        ),
    ] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted.len(), 1, "{name}");
        assert_eq!(extracted[0].name, entry_name, "{name}");
        assert_eq!(extracted[0].data.len(), size, "{name}");
        assert_eq!(crc32(&extracted[0].data), expected_crc, "{name}");
    }
}

#[test]
fn extracts_rar300_ppmd_text_file() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_lorem_rar300.rar")).unwrap();
    let expected = std::fs::read(fixture("ppmd/lorem_127k.txt")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"lorem_127k.txt");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.pack_size, 13_276);
    assert_eq!(file.unp_size, 130_048);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"lorem_127k.txt");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0xc119b4e5);
}

#[test]
fn extracts_rar300_ppmd_escape_literal_file() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_escape_rar300.rar")).unwrap();
    let expected = std::fs::read(fixture("ppmd/escape_64k.bin")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"escape_64k.bin");
    assert_eq!(file.method, 0x35);
    assert_eq!(file.unp_ver, 29);
    assert_eq!(file.unp_size, 65_536);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"escape_64k.bin");
    assert_eq!(extracted[0].data, expected);
    assert_eq!(crc32(&extracted[0].data), 0x9a945756);
}

#[test]
fn extracts_rar300_ppmd_mixed_archive() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_mixed_rar300.rar")).unwrap();
    let expected_text = std::fs::read(fixture("ppmd/lorem_127k.txt")).unwrap();
    let expected_binary = std::fs::read(fixture("ppmd/binary_64k.bin")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"lorem_127k.txt");
    assert_eq!(files[1].name, b"binary_64k.bin");
    assert_eq!(files[0].unp_ver, 29);
    assert_eq!(files[1].unp_ver, 29);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_text);
    assert_eq!(extracted[1].data, expected_binary);
    assert_eq!(crc32(&extracted[0].data), 0xc119b4e5);
    assert_eq!(crc32(&extracted[1].data), 0x9d672acd);
}

#[test]
fn extracts_rar300_solid_ppmd_archive() {
    let bytes = std::fs::read(fixture("ppmd/ppmd_solid_rar300.rar")).unwrap();
    let expected_a = std::fs::read(fixture("ppmd/solid_lorem_a.txt")).unwrap();
    let expected_b = std::fs::read(fixture("ppmd/solid_lorem_b.txt")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert!(archive.main.is_solid());
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].name, b"solid_lorem_a.txt");
    assert_eq!(files[1].name, b"solid_lorem_b.txt");
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, expected_a);
    assert_eq!(extracted[1].data, expected_b);
    assert_eq!(crc32(&extracted[0].data), 0x14284201);
    assert_eq!(crc32(&extracted[1].data), 0xca4cac47);
}

#[test]
fn extracts_wild_solid_ppmd_farmanager_archive() {
    let bytes = std::fs::read(fixture("ppmd/farmanager170.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let opened = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

    assert!(archive.main.is_solid());
    assert!(archive
        .files()
        .any(|file| file.unp_ver >= 29 && file.method == 0x35));

    let result = archive.extract_to(ArchiveReadOptions::default(), {
        let opened = Rc::clone(&opened);
        move |meta| {
            opened.borrow_mut().push(meta.name.clone());
            if meta.name == b"Far.exe" {
                return Err(Error::InvalidHeader("stopped after PPMd regression target"));
            }
            Ok(Box::new(std::io::sink()))
        }
    });

    assert!(matches!(
        result,
        Err(Error::InvalidHeader("stopped after PPMd regression target"))
    ));
    let opened = opened.borrow();
    assert!(opened
        .iter()
        .any(|name| name == b"Addons\\Shell\\FARHere.inf"));
    assert!(opened.iter().any(|name| name == b"Far.exe"));
}

#[test]
fn decodes_rar300_compressed_archive_comment() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(b"This is the archive comment.\n".as_slice())
    );
}

#[test]
fn decodes_node_unrar_js_utf16_archive_comment() {
    let bytes = std::fs::read(fixture("node_unrar_js/with_comment.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let comment = archive.archive_comment().unwrap().unwrap();
    let expected: Vec<u8> = "Test Comments for rar files.\r\n\r\n测试一下中文注释。\r\n日本語のコメントもテストしていまし。"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();

    assert_eq!(comment, expected);
    assert_eq!(crc32(&comment), 0xe96e8fcf);
    assert_eq!(comment.len(), 122);
}

#[test]
fn rejects_split_rar15_40_entries_until_volume_reassembly_exists() {
    let bytes = std::fs::read(fixture("rar300/multivol_oldnaming_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        collect_extract(&archive),
        Err(Error::InvalidHeader(
            "RAR 1.5 split entry requires multivolume extraction"
        ))
    ));
}

#[test]
fn extracts_stored_rar300_old_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/stored_multivol_rar300.rar",
        "rar300/stored_multivol_rar300.r00",
        "rar300/stored_multivol_rar300.r01",
        "rar300/stored_multivol_rar300.r02",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"stored-volume.txt");
    assert_eq!(extracted[0].data, expected_stored_volume_payload());
    assert_eq!(crc32(&extracted[0].data), 0x4a832ebd);
}

#[test]
fn rejects_incomplete_rar300_stored_volume_set() {
    let archives: Vec<_> = [
        "rar300/stored_multivol_rar300.rar",
        "rar300/stored_multivol_rar300.r00",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    assert!(matches!(
        collect_extract_volumes(&archives),
        Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"))
    ));
}

#[test]
fn extracts_compressed_rar300_old_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/compressed_multivol_prng_rar300.rar",
        "rar300/compressed_multivol_prng_rar300.r00",
        "rar300/compressed_multivol_prng_rar300.r01",
        "rar300/compressed_multivol_prng_rar300.r02",
        "rar300/compressed_multivol_prng_rar300.r03",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"cvolume.bin");
    assert_eq!(extracted[0].data.len(), 4096);
    assert_eq!(crc32(&extracted[0].data), 0x96de2bef);
}

#[test]
fn extracts_compressed_rar300_new_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/multivol_newnaming_rar300.part01.rar",
        "rar300/multivol_newnaming_rar300.part02.rar",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert!(archives
        .iter()
        .all(|archive| archive.main.uses_new_numbering()));
    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(extracted[0].data.len(), 65_536);
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);
}

#[test]
fn extracts_encrypted_rar300_old_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/encrypted_multivol_rar300.rar",
        "rar300/encrypted_multivol_rar300.r00",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();
    let first = archives[0].files().next().unwrap();
    let second = archives[1].files().next().unwrap();

    assert!(first.is_encrypted());
    assert!(second.is_encrypted());
    assert_eq!(first.salt, second.salt);
    assert!(matches!(
        collect_extract_volumes(&archives),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(extracted[0].data.len(), 65_536);
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);
}

#[test]
fn extracts_encrypted_rar300_new_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/encrypted_newnaming_rar300.part01.rar",
        "rar300/encrypted_newnaming_rar300.part02.rar",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    assert!(archives
        .iter()
        .all(|archive| archive.main.uses_new_numbering()));
    assert!(archives
        .iter()
        .all(|archive| archive.files().next().unwrap().is_encrypted()));
    assert!(matches!(
        collect_extract_volumes(&archives),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(extracted[0].data.len(), 65_536);
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);
}

#[test]
fn extracts_header_encrypted_rar300_old_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/header_encrypted_multivol_rar300.rar",
        "rar300/header_encrypted_multivol_rar300.r00",
    ]
    .into_iter()
    .map(|name| {
        Archive::parse_with_password(&std::fs::read(fixture(name)).unwrap(), Some(b"password"))
            .unwrap()
    })
    .collect();
    let first = archives[0].files().next().unwrap();
    let second = archives[1].files().next().unwrap();

    assert!(archives
        .iter()
        .all(|archive| archive.main.has_encrypted_headers()));
    assert!(first.is_encrypted());
    assert!(second.is_encrypted());
    assert!(matches!(
        collect_extract_volumes(&archives),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(extracted[0].data.len(), 65_536);
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);
}

#[test]
fn extracts_header_encrypted_rar300_new_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar300/header_encrypted_newnaming_rar300.part01.rar",
        "rar300/header_encrypted_newnaming_rar300.part02.rar",
    ]
    .into_iter()
    .map(|name| {
        Archive::parse_with_password(&std::fs::read(fixture(name)).unwrap(), Some(b"password"))
            .unwrap()
    })
    .collect();

    assert!(archives
        .iter()
        .all(|archive| archive.main.has_encrypted_headers()));
    assert!(archives
        .iter()
        .all(|archive| archive.main.uses_new_numbering()));
    assert!(matches!(
        collect_extract_volumes(&archives),
        Err(Error::NeedPassword)
    ));

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"bigtext_64k.bin");
    assert_eq!(extracted[0].data.len(), 65_536);
    assert_eq!(crc32(&extracted[0].data), 0xddc95682);
}

#[test]
fn extracts_rar154_unp15_old_numbered_volume_set() {
    let archives: Vec<_> = [
        "rar154/random.rar",
        "rar154/random.r00",
        "rar154/random.r01",
    ]
    .into_iter()
    .map(|name| Archive::parse(&std::fs::read(fixture(name)).unwrap()).unwrap())
    .collect();

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"random.bin");
    assert_eq!(extracted[0].data.len(), 2_097_152);
    assert_eq!(crc32(&extracted[0].data), 0x1c9e_b697);
}

#[test]
fn parses_rar300_solid_flags() {
    let bytes = std::fs::read(fixture("rar300/solid_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(archive.main.is_solid());
    let files: Vec<_> = archive.files().collect();
    assert!(files.len() >= 2);
    assert!(!files[0].is_solid());
    assert!(files[1..].iter().all(|file| file.is_solid()));
}

#[test]
fn parses_old_and_new_volume_numbering_flags() {
    let old_bytes = std::fs::read(fixture("rar300/multivol_oldnaming_rar300.rar")).unwrap();
    let old = Archive::parse(&old_bytes).unwrap();
    assert!(old.main.is_volume());
    assert!(old.main.is_first_volume());
    assert!(!old.main.uses_new_numbering());
    assert!(old.files().any(|file| file.is_split_after()));

    let new_bytes = std::fs::read(fixture("rar300/multivol_newnaming_rar300.part01.rar")).unwrap();
    let new = Archive::parse(&new_bytes).unwrap();
    assert!(new.main.is_volume());
    assert!(new.main.is_first_volume());
    assert!(new.main.uses_new_numbering());
    assert!(new.files().any(|file| file.is_split_after()));
}

#[test]
fn parses_rar420_extended_time_header_bytes() {
    let bytes = std::fs::read(fixture("rar420/ext_time_rar420.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 1);
    assert!(files.iter().all(|file| file.has_ext_time()));
    assert!(files.iter().all(|file| !file.ext_time.is_empty()));
    assert_eq!(files[0].unp_ver, 29);
}

#[test]
fn parses_end_of_archive_block() {
    let bytes = std::fs::read(fixture("rar300/with_comment_rar300.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(archive.blocks.last(), Some(Block::End(_))));
}

#[test]
fn crc32_matches_standard_check_value() {
    assert_eq!(crc32(b""), 0x00000000);
    assert_eq!(crc32(b"123456789"), 0xcbf43926);
}

#[test]
fn rejects_file_header_salt_that_extends_beyond_head_size_without_panicking() {
    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&rar15_header(0x73, 0, &[0; 6]));

    let mut file_body = Vec::new();
    push_u32(&mut file_body, 0);
    push_u32(&mut file_body, 0);
    file_body.push(2);
    push_u32(&mut file_body, 0);
    push_u32(&mut file_body, 0);
    file_body.push(29);
    file_body.push(0x30);
    push_u16(&mut file_body, 0);
    push_u32(&mut file_body, 0x20);

    archive.extend_from_slice(&rar15_header(0x74, 0x0400 | 0x1000, &file_body));
    archive.extend_from_slice(&[0xaa; 8]);

    assert!(Archive::parse(&archive).is_err());
}

fn expected_stored_volume_payload() -> Vec<u8> {
    "RAR 3.00 stored multivolume fixture line.\n"
        .repeat(80)
        .into_bytes()
}

fn expected_compressed_text_payload() -> Vec<u8> {
    "Hello, RAR 3.x fixture world.\n".repeat(80).into_bytes()
}

fn expected_doc_154_best_manifest() -> [(&'static str, usize, u32); 17] {
    [
        ("ARCH~Y3X.MD", 53_262, 0x5ab9_a7da),
        ("CRC3~F4U.MD", 5_271, 0xad7e_2a11),
        ("ENCR~BXO.MD", 30_796, 0xc5d3_da4f),
        ("FILT~XX0.MD", 27_069, 0x89e6_3874),
        ("HUFF~BID.MD", 11_958, 0xc4b2_3356),
        ("IMPL~KS0.MD", 8_846, 0x0def_58b4),
        ("INTE~BSL.MD", 32_722, 0xcb56_7947),
        ("LZ_M~HYW.MD", 14_181, 0xf5e6_4896),
        ("PATH~EJS.MD", 13_819, 0x3c0d_6e22),
        ("PPMD~D4Q.MD", 38_140, 0xffd9_b31f),
        ("RAR1~FHU.MD", 40_371, 0xaac1_91a8),
        ("RAR1~OEK.MD", 101_788, 0x292f_35d1),
        ("RAR5~YP0.MD", 71_276, 0xe52c_f5ec),
        ("RARV~0F3.MD", 12_429, 0xab07_a4a6),
        ("README.md", 4_198, 0x509e_5e3c),
        ("READ~0WB.MD", 22_024, 0xd987_5535),
        ("TEST~FAD.MD", 14_811, 0xb55b_a84a),
    ]
}

fn expected_rar250_multimedia_payload() -> Vec<u8> {
    let mut pcm = Vec::with_capacity(32 * 1024);
    for i in 0..8192 {
        let left = (20000.0 * ((i as f64) * 2.0 * std::f64::consts::PI / 256.0).sin()) as i32;
        let right =
            (15000.0 * ((i as f64) * 2.0 * std::f64::consts::PI / 384.0 + 1.0).sin()) as i32;
        pcm.extend_from_slice(&(left as u16).to_le_bytes());
        pcm.extend_from_slice(&(right as u16).to_le_bytes());
    }
    pcm
}

fn rar15_first_file_data_peek(bytes: &[u8]) -> u16 {
    rar15_file_data_peeks(bytes)[0]
}

fn rar15_file_data_peeks(bytes: &[u8]) -> Vec<u16> {
    let mut pos = 7 + 13;
    let mut peeks = Vec::new();
    while pos + 7 <= bytes.len() {
        let head_type = bytes[pos + 2];
        let flags = u16::from_le_bytes([bytes[pos + 3], bytes[pos + 4]]);
        let head_size = u16::from_le_bytes([bytes[pos + 5], bytes[pos + 6]]) as usize;
        if head_size < 7 || pos + head_size > bytes.len() {
            break;
        }
        let add_size = if flags & 0x8000 != 0 {
            u32::from_le_bytes([
                bytes[pos + 7],
                bytes[pos + 8],
                bytes[pos + 9],
                bytes[pos + 10],
            ]) as usize
        } else {
            0
        };
        if head_type == 0x74 {
            let data = pos + head_size;
            peeks.push(u16::from_be_bytes([bytes[data], bytes[data + 1]]));
        }
        pos += head_size + add_size;
    }
    peeks
}

fn synthetic_rar20_audio_archive(channels: usize, samples: usize) -> Vec<u8> {
    let packed = synthetic_rar20_audio_block(channels, samples);
    let unpacked = vec![0; samples];
    let name = format!("AUDIO{channels}.BIN").into_bytes();

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&rar15_header(0x73, 0, &[0; 6]));

    let mut file_body = Vec::new();
    push_u32(&mut file_body, packed.len() as u32);
    push_u32(&mut file_body, samples as u32);
    file_body.push(2); // host OS: Win32.
    push_u32(&mut file_body, crc32(&unpacked));
    push_u32(&mut file_body, 0x4a83_a11d);
    file_body.push(20);
    file_body.push(0x35);
    push_u16(&mut file_body, name.len() as u16);
    push_u32(&mut file_body, 0x20);
    file_body.extend_from_slice(&name);

    archive.extend_from_slice(&rar15_header(0x74, 0x8000, &file_body));
    archive.extend_from_slice(&packed);
    archive
}

fn rar15_header(head_type: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    push_u16(&mut header, 0);
    header.push(head_type);
    push_u16(&mut header, flags);
    push_u16(&mut header, (7 + body.len()) as u16);
    header.extend_from_slice(body);

    let crc = (crc32(&header[2..]) & 0xffff) as u16;
    header[0..2].copy_from_slice(&crc.to_le_bytes());
    header
}

fn synthetic_rar20_audio_block(channels: usize, samples: usize) -> Vec<u8> {
    let mut bits = TestBitWriter::default();

    bits.write_bits(0b10, 2); // audio block, do not keep previous tables.
    bits.write_bits((channels - 1) as u32, 2);

    for symbol in 0..19 {
        let len = if symbol == 1 || symbol == 18 { 1 } else { 0 };
        bits.write_bits(len, 4);
    }

    for _ in 0..channels {
        bits.write_bit(false); // level symbol 1: audio delta 0 has code length 1.
        bits.write_bit(true); // level symbol 18: 138 zeros.
        bits.write_bits(127, 7);
        bits.write_bit(true); // level symbol 18: 118 zeros.
        bits.write_bits(107, 7);
    }

    for _ in 0..samples {
        bits.write_bit(false); // audio delta 0.
    }

    bits.finish()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[derive(Default)]
struct TestBitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl TestBitWriter {
    fn write_bit(&mut self, bit: bool) {
        if self.bit_pos.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit {
            let shift = 7 - (self.bit_pos % 8);
            *self.bytes.last_mut().unwrap() |= 1 << shift;
        }
        self.bit_pos += 1;
    }

    fn write_bits(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            self.write_bit(((value >> shift) & 1) != 0);
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn expected_rar250_solid1_payload() -> Vec<u8> {
    rar250_solid_shared_line().repeat(180).into_bytes()
}

fn expected_rar250_solid2_payload() -> Vec<u8> {
    let mut data = rar250_solid_shared_line().repeat(90).into_bytes();
    data.extend_from_slice(
        "second member unique tail after shared history.\r\n"
            .repeat(120)
            .as_bytes(),
    );
    data
}

fn rar250_solid_shared_line() -> &'static str {
    "RAR 2.50 solid dictionary carry-over line with repeated tokens alpha beta gamma delta.\r\n"
}

fn expected_rar250_big_lz_payload() -> Vec<u8> {
    let mut data = Vec::with_capacity(167_936);
    for i in 0..4096 {
        data.extend_from_slice(format!("{i:04x}: unpack20 block refresh fixture ").as_bytes());
        data.extend_from_slice(&[(i * 17) as u8, (i * 31) as u8, b'\r', b'\n']);
    }
    data
}

/// The engine and the filter used to be one five-variant enum, so some pairings
/// could not be asked for at all. These are the ones that were missing.
#[test]
fn rar29_chooses_engine_and_filter_independently() {
    // Text, so the PPMd trial is worth taking; the delta filter below is asked
    // for explicitly rather than because it suits the content.
    let payload = b"rar29 two axis payload alpha beta gamma delta epsilon\n".repeat(400);
    let entries = [FileEntry {
        name: b"two-axis.txt",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];
    let options = WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());

    let method_of = |options: WriterOptions, policy: FilterPolicy| {
        let bytes =
            write_rar29_compressed_archive_with_filter_policy(&entries, options, policy).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let method = archive.files().next().unwrap().method;
        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(
            extracted[0].data, payload,
            "round trip failed for {method:#x}"
        );
        method
    };

    // Searching for a filter with PPMd off: new, and the search must not reach
    // for PPMd behind the caller's back.
    assert_ne!(
        method_of(options.with_method(Rar29Method::Lz), FilterPolicy::Auto),
        0x35,
        "forcing LZ must not produce a PPMd member"
    );
    // Weighing an explicitly named filter against PPMd: also new.
    assert_eq!(
        method_of(
            options.with_method(Rar29Method::Auto),
            FilterPolicy::explicit(FilterKind::Delta { channels: 2 })
        ),
        0x35,
        "text with an explicit filter should still be allowed to pick PPMd"
    );
    // Forcing PPMd leaves the filter search nothing to measure against.
    let refused = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        options.with_method(Rar29Method::Ppmd),
        FilterPolicy::Auto,
    );
    assert!(
        refused.is_err(),
        "PPMd plus a filter search must be refused"
    );
}

/// The automatic search now emits one filter per merged code region, which is a
/// shape the RarVM program emitter never saw while the two copies of the range
/// merger disagreed and this one dropped overlaps instead of merging them.
#[test]
fn rar29_auto_filter_round_trips_a_member_with_two_distant_code_regions() {
    let mut payload = vec![0x41u8; 900_000];
    for region_start in [40_000, 700_000] {
        for index in 0..2_000u32 {
            let pos = region_start + index as usize * 32;
            payload[pos] = 0xe8;
            payload[pos + 1..pos + 5].copy_from_slice(&(0x4000u32 + index).to_le_bytes());
        }
    }
    let entries = [FileEntry {
        name: b"two-regions.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        FilterPolicy::Auto,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

/// A filter whose chunking left a remainder shorter than its own scanline width
/// used to fail the whole write. Those bytes are simply left unfiltered now.
#[test]
fn rar29_rgb_filter_handles_a_length_that_leaves_a_short_trailing_chunk() {
    // 131_072 splits into one 131_064-byte chunk and an 8-byte remainder, which
    // is shorter than the 24-byte scanline.
    let payload = vec![0x40u8; 131_072];
    let entries = [FileEntry {
        name: b"short-tail.rgb",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    let bytes = write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
            .with_method(Rar29Method::Lz),
        FilterPolicy::Explicit(FilterSpec::whole(FilterKind::Rgb {
            width: 24,
            pos_r: 0,
        })),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

/// A filter record's start is read relative to the head of the block that
/// declares it, and the decoder masks that offset against its window. Declaring
/// every record at the head of the member wrote offsets the window could not
/// express, so a filter aimed past the first window landed somewhere else and
/// the member came out corrupt. Our own decoder made the same mistake, so it
/// agreed with the writer and only an external tool disagreed.
#[test]
fn rar29_applies_a_filter_that_starts_beyond_the_dictionary() {
    // Calls to one address, written as the relative displacements a compiler
    // would emit. The filter turns them back into the same absolute address, so
    // it pays off only if it reaches them. The default RAR 2.9 dictionary is
    // 1 MiB, and the calls start past it.
    let mut payload: Vec<u8> = (0..3_000_000u32).map(|index| (index % 251) as u8).collect();
    const TARGET: u32 = 0x0020_1000;
    for pos in (1_500_000..2_800_000).step_by(16) {
        payload[pos] = 0xe8;
        let displacement = TARGET.wrapping_sub(pos as u32);
        payload[pos + 1..pos + 5].copy_from_slice(&displacement.to_le_bytes());
    }
    let entries = [FileEntry {
        name: b"late-filter.bin",
        data: &payload,
        file_time: 0x5a21_0000,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    }];

    for policy in [
        FilterPolicy::Auto,
        FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8E9, 1_500_000..2_800_000)),
    ] {
        let bytes = write_rar29_compressed_archive_with_filter_policy(
            &entries,
            WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
                .with_method(Rar29Method::Lz),
            policy.clone(),
        )
        .unwrap();

        let archive = Archive::parse(&bytes).unwrap();
        assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);

        // A round trip alone would not have caught this, because the decoder
        // read the offsets back the same way the writer wrote them. The size
        // is what shows the filter reached the bytes it was aimed at, so the
        // named one has to pay off. The automatic policy is free to decline.
        if matches!(policy, FilterPolicy::Explicit(_)) {
            let unfiltered = write_rar29_compressed_archive_with_filter_policy(
                &entries,
                WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
                    .with_method(Rar29Method::Lz),
                FilterPolicy::None,
            )
            .unwrap();
            assert!(
                bytes.len() < unfiltered.len(),
                "the filter did not reach its bytes: {} against {} unfiltered",
                bytes.len(),
                unfiltered.len()
            );
        }
    }
}

/// The streaming writer and the in-memory one are the same writer with a
/// different way of getting at the bytes, so the archives they produce have to
/// be the same archives. Anything else means the streaming path has quietly
/// grown its own behaviour.
#[test]
fn streaming_and_buffered_writers_agree_byte_for_byte() {
    use rars::rar15_40::{write_streaming_archive_to, StreamingEntry};
    use rars::{EntrySource, MemberCoding, WriterResources};

    let text = b"the quick brown fox jumps over the lazy dog\n".repeat(400);
    let binary = level_sensitive_payload();
    let members: Vec<(&[u8], &[u8])> = vec![
        (b"text.txt", &text),
        (b"binary.bin", &binary),
        (b"empty.dat", b""),
    ];

    for target in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        for solid in [false, true] {
            for coding in [
                MemberCoding::Stored,
                MemberCoding::Compressed,
                MemberCoding::Filtered(FilterPolicy::Auto),
                MemberCoding::Filtered(FilterPolicy::None),
            ] {
                let mut features = FeatureSet::store_only();
                features.solid = solid && coding.compresses();
                let options = WriterOptions::new(target, features);
                let comment: Option<&[u8]> = Some(b"shared comment");

                let buffered = match &coding {
                    MemberCoding::Stored => {
                        let entries: Vec<_> = members
                            .iter()
                            .map(|(name, data)| StoredEntry {
                                name,
                                data,
                                file_time: 0,
                                file_attr: 0,
                                host_os: 3,
                                password: None,
                                file_comment: None,
                            })
                            .collect();
                        write_stored_archive_with_comment(&entries, options, comment)
                    }
                    coding => {
                        let entries: Vec<_> = members
                            .iter()
                            .map(|(name, data)| FileEntry {
                                name,
                                data,
                                file_time: 0,
                                file_attr: 0,
                                host_os: 3,
                                password: None,
                                file_comment: None,
                            })
                            .collect();
                        match coding {
                            MemberCoding::Filtered(policy) => {
                                write_rar29_compressed_archive_with_filter_policy(
                                    &entries,
                                    options,
                                    policy.clone(),
                                )
                            }
                            _ => write_compressed_archive_with_comment(&entries, options, comment),
                        }
                    }
                };

                let streamed_entries: Vec<_> = members
                    .iter()
                    .map(|(name, data)| {
                        StreamingEntry::new(name.to_vec(), EntrySource::from_bytes(data.to_vec()))
                            .with_host_os(3)
                    })
                    .collect();
                // The filtered entry point takes no comment, so neither does
                // the comparison.
                let streamed_comment = if coding.is_filtered() { None } else { comment };
                let mut streamed = Vec::new();
                let streamed_result = write_streaming_archive_to(
                    &streamed_entries,
                    options,
                    coding.clone(),
                    streamed_comment,
                    &WriterResources::default(),
                    None,
                    &mut streamed,
                );

                let label = format!("{target} solid={solid} {coding:?}");
                match buffered {
                    Ok(buffered) => {
                        assert!(streamed_result.is_ok(), "{label}: streaming refused what the buffered writer accepted: {streamed_result:?}");
                        assert_eq!(streamed, buffered, "{label}: archives differ");
                        let archive = Archive::parse(&streamed).unwrap();
                        let extracted = collect_extract(&archive)
                            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
                        assert_eq!(extracted.len(), members.len(), "{label}");
                        for (got, (_, want)) in extracted.iter().zip(&members) {
                            assert_eq!(&got.data, want, "{label}");
                        }
                    }
                    Err(buffered) => {
                        let streamed_error = streamed_result.expect_err(&format!(
                            "{label}: streaming accepted what the buffered writer refused"
                        ));
                        assert_eq!(
                            streamed_error.to_string(),
                            buffered.to_string(),
                            "{label}: the two paths refused it differently"
                        );
                    }
                }
            }
        }
    }
}

/// A stored member is copied straight from its source rather than read into
/// memory, which is a different code path from the one that holds the bytes.
#[test]
fn a_stored_member_round_trips_from_a_file_on_disk() {
    use rars::rar15_40::{write_streaming_archive_to, StreamingEntry};
    use rars::{EntrySource, MemberCoding, WriterResources};

    let directory = std::env::temp_dir().join(format!("rars-stream-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("payload.bin");
    // Larger than the walk chunk, so the checksum really is taken in pieces.
    let payload: Vec<u8> = (0..700_000u32).map(|index| index as u8).collect();
    std::fs::write(&path, &payload).unwrap();

    let entries = vec![StreamingEntry::new(
        b"payload.bin".to_vec(),
        EntrySource::from_path(path.clone()),
    )];
    let mut bytes = Vec::new();
    write_streaming_archive_to(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        MemberCoding::Stored,
        None,
        &WriterResources::default(),
        None,
        &mut bytes,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, payload);
    assert_eq!(crc32(&extracted[0].data), crc32(&payload));

    std::fs::remove_dir_all(&directory).unwrap();
}

/// A member larger than the whole budget still gets written: the legacy codecs
/// have no smaller unit to fall back to, so the budget serialises them rather
/// than refusing the job.
#[test]
fn a_member_larger_than_the_budget_is_written_anyway() {
    use rars::rar15_40::{write_streaming_archive_to, StreamingEntry};
    use rars::{EntrySource, MemberCoding, WriterResources};

    let payload = b"a budget this small cannot hold one member\n".repeat(500);
    let entries: Vec<_> = (0..4)
        .map(|index| {
            StreamingEntry::new(
                format!("member{index}.txt").into_bytes(),
                EntrySource::from_bytes(payload.clone()),
            )
        })
        .collect();

    let mut bytes = Vec::new();
    write_streaming_archive_to(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        MemberCoding::Compressed,
        None,
        &WriterResources::new(4096),
        None,
        &mut bytes,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 4);
    for entry in &extracted {
        assert_eq!(entry.data, payload);
    }
}

/// Tests an archive with a locally installed reference tool, returning `None`
/// when there is not one.
fn local_reference_test(label: &str, archive: &[u8]) -> Option<std::process::Output> {
    let mut path = std::env::temp_dir();
    path.push(format!("rars-{label}-{}.rar", std::process::id()));
    std::fs::write(&path, archive).unwrap();
    let mut result = None;
    for tool in ["unrar", "rar"] {
        if let Ok(output) = Command::new(tool).arg("t").arg(&path).output() {
            result = Some(output);
            break;
        }
    }
    let _ = std::fs::remove_file(&path);
    result
}

fn solid_options(target: ArchiveVersion) -> WriterOptions {
    let mut features = FeatureSet::store_only();
    features.solid = true;
    WriterOptions::new(target, features)
}

fn file_entries<'a>(members: &'a [(&'a [u8], Vec<u8>)]) -> Vec<FileEntry<'a>> {
    members
        .iter()
        .map(|(name, data)| FileEntry {
            name,
            data,
            file_time: 0,
            file_attr: 0,
            host_os: 3,
            password: None,
            file_comment: None,
        })
        .collect()
}

/// A member compression cannot shrink is stored instead, which rebuilds the
/// encoder and so starts a fresh solid chain. Only RAR 2.0 onwards can say so:
/// its file headers carry a solid bit. RAR 1.5 has none, and readers take every
/// member of a solid RAR 1.5 archive as a continuation whatever the header
/// says, so breaking the chain there wrote an archive nothing could read.
#[test]
fn a_solid_rar15_run_survives_a_member_that_does_not_compress() {
    let compressible = b"solid chain payload that repeats and repeats\n".repeat(400);
    // Incompressible, and past the 1 KiB floor, so the store fallback wants it.
    let incompressible: Vec<u8> = (0..90_000u32)
        .map(|index| {
            let mixed = index
                .wrapping_mul(2_654_435_761)
                .rotate_left(index % 17);
            (mixed >> 13) as u8
        })
        .collect();
    let tail = b"and a short tail afterwards\n".repeat(50);
    let members: Vec<(&[u8], Vec<u8>)> = vec![
        (b"first.txt", compressible),
        (b"middle.bin", incompressible),
        (b"last.txt", tail),
    ];
    let entries = file_entries(&members);

    let bytes = write_compressed_archive(&entries, solid_options(ArchiveVersion::Rar15)).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), members.len());
    for (got, (_, want)) in extracted.iter().zip(&members) {
        assert_eq!(&got.data, want);
    }

    if let Some(output) = local_reference_test("rar15-solid-store", &bytes) {
        assert!(
            output.status.success(),
            "the reference tool rejected a solid RAR 1.5 archive\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// An empty member neither carries the solid chain nor breaks it: it feeds the
/// encoder nothing, and a reader passes over an empty payload without advancing
/// its decoder. Counting one as a member left the member after it flagged as
/// continuing a chain that a stored member two places back had already broken.
#[test]
fn an_empty_member_does_not_restart_a_broken_solid_chain() {
    let opener = b"a short opening member\n".repeat(3);
    let incompressible: Vec<u8> = (0..40_000u32)
        .map(|index| {
            let mixed = index
                .wrapping_mul(0x9e37_79b9)
                .rotate_left(index % 23);
            (mixed >> 11) as u8
        })
        .collect();
    let members: Vec<(&[u8], Vec<u8>)> = vec![
        (b"opener.txt", opener),
        (b"incompressible.bin", incompressible),
        (b"empty.dat", Vec::new()),
        (b"after.txt", b"the member after the empty one\n".repeat(4)),
    ];
    let entries = file_entries(&members);

    for target in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let bytes = write_compressed_archive(&entries, solid_options(target)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let extracted =
            collect_extract(&archive).unwrap_or_else(|error| panic!("{target}: {error:?}"));
        assert_eq!(extracted.len(), members.len(), "{target}");
        for (got, (_, want)) in extracted.iter().zip(&members) {
            assert_eq!(&got.data, want, "{target}");
        }

        if let Some(output) = local_reference_test("solid-empty-member", &bytes) {
            assert!(
                output.status.success(),
                "{target}: the reference tool rejected it\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
