use super::support::{rar50_entry, CollectWriter};
use rars::*;
use std::{
    cell::RefCell,
    io::Write,
    path::{Path, PathBuf},
    rc::Rc,
};

#[derive(Debug, Clone, PartialEq, Eq)]
// Historical numeric snapshots; timestamp presence has dedicated regression tests.
struct CollectedEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    modified: Option<Timestamp>,
    file_attr: u64,
    is_directory: bool,
}

fn rar15_40_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40")
        .join(name)
}

fn collect_extract(archive: &Archive, password: Option<&[u8]>) -> Result<Vec<CollectedEntry>> {
    let entries = RefCell::new(Vec::new());
    archive.extract_to(password, |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter(data)))
    })?;
    Ok(entries
        .into_inner()
        .into_iter()
        .map(|(meta, data)| CollectedEntry {
            name: meta.name,
            data: data.borrow().clone(),
            modified: meta.modified,
            file_attr: meta.file_attr,
            is_directory: meta.is_directory,
        })
        .collect())
}

fn rar13_options(target: ArchiveVersion) -> rar13::WriterOptions {
    rar13::WriterOptions::new(target, FeatureSet::store_only())
}

fn rar15_options(target: ArchiveVersion) -> rar15_40::WriterOptions {
    rar15_options_with_features(target, FeatureSet::store_only())
}

fn rar15_options_with_features(
    target: ArchiveVersion,
    features: FeatureSet,
) -> rar15_40::WriterOptions {
    rar15_40::WriterOptions::new(target, features)
}

fn rar50_options(target: ArchiveVersion) -> rar50::WriterOptions {
    rar50_options_with_features(target, FeatureSet::store_only())
}

fn rar50_options_with_features(
    target: ArchiveVersion,
    features: FeatureSet,
) -> rar50::WriterOptions {
    rar50::WriterOptions::new(target, features)
}

fn write_rar29_filter(
    options: rar15_40::WriterOptions,
    entries: &[rar15_40::FileEntry<'_>],
    kind: rar15_40::FilterKind,
) -> Result<Vec<u8>> {
    rar15_40::write_rar29_compressed_archive_with_filter_policy(
        entries,
        options,
        rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::whole(kind)),
    )
}

fn write_rar29_filter_range(
    options: rar15_40::WriterOptions,
    entries: &[rar15_40::FileEntry<'_>],
    kind: rar15_40::FilterKind,
    range: std::ops::Range<usize>,
) -> Result<Vec<u8>> {
    rar15_40::write_rar29_compressed_archive_with_filter_policy(
        entries,
        options,
        rar15_40::FilterPolicy::Explicit(rar15_40::FilterSpec::range(kind, range)),
    )
}

#[test]
fn direct_writer_creates_rar15_stored_archive() {
    let bytes = rar15_40::write_stored_archive(
        &[rar15_40::StoredEntry {
            name: b"hello.txt",
            data: b"hello via facade\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar15),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"hello via facade\n");
}

#[test]
fn archive_reader_accepts_owned_buffers_without_changing_dispatch() {
    let rar13_bytes = rar13::write_stored_archive(
        &[rar13::StoredEntry {
            name: b"old.txt",
            data: b"owned rar13\n",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        rar13_options(ArchiveVersion::Rar14),
    )
    .unwrap();
    let rar13_archive = ArchiveReader::read_owned(rar13_bytes).unwrap();
    assert_eq!(rar13_archive.family(), ArchiveFamily::Rar13);
    assert_eq!(
        collect_extract(&rar13_archive, None).unwrap()[0].data,
        b"owned rar13\n"
    );

    let rar15_bytes = rar15_40::write_stored_archive(
        &[rar15_40::StoredEntry {
            name: b"mid.txt",
            data: b"owned rar15\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar15),
    )
    .unwrap();
    let rar15_archive = ArchiveReader::read_owned(rar15_bytes).unwrap();
    assert_eq!(rar15_archive.family(), ArchiveFamily::Rar15To40);
    assert_eq!(
        collect_extract(&rar15_archive, None).unwrap()[0].data,
        b"owned rar15\n"
    );

    let rar50_bytes =
        rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
            .entries(
                [rar50_entry(b"new.txt", b"owned rar50\n")
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .finish()
            .unwrap();
    let rar50_archive = ArchiveReader::read_owned(rar50_bytes).unwrap();
    assert_eq!(rar50_archive.family(), ArchiveFamily::Rar50Plus);
    assert_eq!(
        collect_extract(&rar50_archive, None).unwrap()[0].data,
        b"owned rar50\n"
    );
}

#[test]
fn direct_writer_keeps_rar13_methods_version_typed() {
    let err = rar13::write_stored_archive(&[], rar13_options(ArchiveVersion::Rar15)).unwrap_err();

    assert!(matches!(
        err,
        Error::UnsupportedVersion(ArchiveVersion::Rar15)
    ));
}

#[test]
fn extraction_metadata_preserves_rar50_u64_file_attributes() {
    let bytes =
        rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
            .entries(
                [rar50_entry(b"wide-attrs.txt", b"wide RAR5 file attributes")
                    .with_mtime(Some(0))
                    .with_attributes(0x1_0000_0020)
                    .with_host_os(3)]
                .to_vec(),
            )
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"wide-attrs.txt");
    assert_eq!(extracted[0].file_attr, 0x1_0000_0020);
}

#[test]
fn direct_writer_creates_rar15_compressed_archive() {
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"text.txt",
            data: b"facade compressed facade compressed facade compressed\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar15),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade compressed facade compressed facade compressed\n"
    );
}

#[test]
fn direct_writer_creates_rar29_compressed_archive_with_default_auto_policy() {
    let payload = b"facade rar29 default auto text alpha beta gamma alpha beta gamma\n".repeat(256);
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar29-default-auto.txt",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar29),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    // The byte is the level that was asked for, and nothing here asked for
    // one, so it is the default 0x33. Which engine answered is signalled in
    // the stream, which is why the round trip below is what proves PPMd
    // read back. WinRAR stamps 0x34 on the PPMd archive it writes at -m4.
    assert_eq!(raw.files().next().unwrap().method, 0x33);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_e8_filtered_compressed_archive() {
    let payload = b"\xe8\0\0\0\0facade rar29 e8 filter payload\n".repeat(12);
    let bytes = write_rar29_filter(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-e8.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::E8,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_auto_filtered_compressed_archive() {
    let payload = b"\xe8\0\0\0\0facade rar29 auto filter payload\n".repeat(12);
    let bytes = rar15_40::write_rar29_compressed_archive_with_filter_policy(
        &[rar15_40::FileEntry {
            name: b"rar29-auto.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar29),
        rar15_40::FilterPolicy::Auto,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_ppmd_compressed_archive() {
    let payload = b"facade rar29 ppmd text payload alpha beta gamma\n".repeat(64);
    let bytes = rar15_40::write_rar29_compressed_archive_with_filter_policy(
        &[rar15_40::FileEntry {
            name: b"rar29-ppmd.txt",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar29).with_method(rar15_40::Rar29Method::Ppmd),
        rar15_40::FilterPolicy::None,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    // Forcing PPMd does not change the level, so this is still the default
    // 0x33; extracting it is what shows PPMd was used.
    assert_eq!(file.method, 0x33);
    assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_segmented_e8_filtered_compressed_archive() {
    let mut payload = b"facade unfiltered prefix before x86 segment ".to_vec();
    let filter_start = payload.len();
    payload.extend_from_slice(b"\xe8\0\0\0\0facade segmented e8 filter payload\n");
    let filter_end = payload.len();
    payload.extend_from_slice(b"facade unfiltered suffix after x86 segment\n");
    let bytes = write_rar29_filter_range(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-segmented-e8.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::E8,
        filter_start..filter_end,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_solid_e8_filtered_compressed_archive() {
    let first = b"\xe8\0\0\0\0facade rar29 solid e8 first payload\n".repeat(12);
    let second = b"\xe8\0\0\0\0facade rar29 solid e8 second payload\n".repeat(12);
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let bytes = write_rar29_filter(
        rar15_options_with_features(ArchiveVersion::Rar29, features),
        &[
            rar15_40::FileEntry {
                name: b"rar29-solid-e8-first.bin",
                data: &first,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_40::FileEntry {
                name: b"rar29-solid-e8-second.bin",
                data: &second,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
        ],
        rar15_40::FilterKind::E8,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    let files: Vec<_> = raw.files().collect();
    assert!(raw.main.is_solid());
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar29_encrypted_e8_filtered_compressed_archive() {
    let payload = b"\xe8\0\0\0\0facade rar29 encrypted e8 payload\n".repeat(12);
    let features = FeatureSet::store_only();
    let bytes = write_rar29_filter(
        rar15_options_with_features(ArchiveVersion::Rar29, features),
        &[rar15_40::FileEntry {
            name: b"rar29-encrypted-e8.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }],
        rar15_40::FilterKind::E8,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    assert!(file.is_encrypted());
    assert!(file.salt.is_some());
    assert!(matches!(
        collect_extract(&archive, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar30_header_encrypted_e8_filtered_compressed_archive() {
    let payload = b"\xe8\0\0\0\0facade rar30 header encrypted e8 payload\n".repeat(12);
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_rar29_filter(
        rar15_options_with_features(ArchiveVersion::Rar30, features),
        &[rar15_40::FileEntry {
            name: b"rar30-header-encrypted-e8.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }],
        rar15_40::FilterKind::E8,
    )
    .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let raw = archive.as_rar15_40().unwrap();
    assert!(raw.main.has_encrypted_headers());
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_e8e9_filtered_compressed_archive() {
    let payload = b"\xe9\0\0\0\0facade rar29 e8e9 filter payload\n".repeat(12);
    let bytes = write_rar29_filter(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-e8e9.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::E8E9,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_delta_filtered_compressed_archive() {
    let payload: Vec<u8> = (0..384).map(|index| (index * 19 + 5) as u8).collect();
    let bytes = write_rar29_filter(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-delta.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Delta { channels: 3 },
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_segmented_delta_filtered_compressed_archive() {
    let mut payload = b"facade unfiltered prefix before delta segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..384).map(|index| (index * 19 + 5) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"facade unfiltered suffix after delta segment\n");
    let bytes = write_rar29_filter_range(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-segmented-delta.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Delta { channels: 3 },
        filter_start..filter_end,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_itanium_filtered_compressed_archive() {
    let mut payload = vec![0u8; 48];
    payload[16] = 22;
    payload[21] = 20;
    payload.extend_from_slice(b"facade rar29 itanium filter payload\n");
    let bytes = write_rar29_filter(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-itanium.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Itanium,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_segmented_itanium_filtered_compressed_archive() {
    let mut payload = b"facade unfiltered prefix before itanium segment ".to_vec();
    let filter_start = payload.len();
    payload.extend_from_slice(&[0; 48]);
    payload[filter_start + 16] = 22;
    payload[filter_start + 21] = 20;
    payload.extend_from_slice(b"facade segmented itanium filter payload\n");
    let filter_end = payload.len();
    payload.extend_from_slice(b"facade unfiltered suffix after itanium segment\n");
    let bytes = write_rar29_filter_range(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-segmented-itanium.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Itanium,
        filter_start..filter_end,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_rgb_filtered_compressed_archive() {
    let width = 12;
    let payload: Vec<u8> = (0..96).map(|index| (index * 37 + 17) as u8).collect();
    let bytes = write_rar29_filter(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-rgb.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Rgb { width, pos_r: 0 },
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_segmented_rgb_filtered_compressed_archive() {
    let width = 12;
    let mut payload = b"facade unfiltered prefix before rgb segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..96).map(|index| (index * 37 + 17) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"facade unfiltered suffix after rgb segment\n");
    let bytes = write_rar29_filter_range(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-segmented-rgb.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Rgb { width, pos_r: 0 },
        filter_start..filter_end,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_audio_filtered_compressed_archive() {
    let payload: Vec<u8> = (0..160)
        .map(|index| (index * 11 + index / 7) as u8)
        .collect();
    let bytes = write_rar29_filter(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-audio.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Audio { channels: 2 },
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_segmented_audio_filtered_compressed_archive() {
    let mut payload = b"facade unfiltered prefix before audio segment ".to_vec();
    let filter_start = payload.len();
    payload.extend((0..160).map(|index| (index * 11 + index / 7) as u8));
    let filter_end = payload.len();
    payload.extend_from_slice(b"facade unfiltered suffix after audio segment\n");
    let bytes = write_rar29_filter_range(
        rar15_options(ArchiveVersion::Rar29),
        &[rar15_40::FileEntry {
            name: b"rar29-segmented-audio.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_40::FilterKind::Audio { channels: 2 },
        filter_start..filter_end,
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar20_compressed_archive() {
    let payload = b"facade rar20 literal compressed payload\n".repeat(32);
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar20.txt",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar20),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    assert_eq!(file.unp_ver, 20);
    assert_eq!(file.method, 0x33);
    assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_compressed_archive() {
    let payload = b"facade rar29 literal compressed payload\n".repeat(32);
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar29.txt",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar29),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    assert_eq!(file.unp_ver, 29);
    assert!(matches!(file.method, 0x33 | 0x35));
    assert_eq!(collect_extract(&archive, None).unwrap()[0].data, payload);
}

#[test]
fn direct_writer_creates_rar29_solid_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let bytes = rar15_40::write_compressed_archive(
        &[
            rar15_40::FileEntry {
                name: b"one.txt",
                data: b"facade rar29 solid one alpha beta\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_40::FileEntry {
                name: b"two.txt",
                data: b"facade rar29 solid two alpha beta\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
        ],
        rar15_options_with_features(ArchiveVersion::Rar29, features),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    assert!(raw.main.is_solid());
    let files: Vec<_> = raw.files().collect();
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, b"facade rar29 solid one alpha beta\n");
    assert_eq!(extracted[1].data, b"facade rar29 solid two alpha beta\n");
}

#[test]
fn direct_writer_creates_rar20_solid_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let first = b"facade rar20 solid shared line alpha beta gamma\n".repeat(48);
    let second = b"facade rar20 solid shared line alpha beta gamma\nsecond\n".repeat(24);
    let bytes = rar15_40::write_compressed_archive(
        &[
            rar15_40::FileEntry {
                name: b"one.txt",
                data: &first,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_40::FileEntry {
                name: b"two.txt",
                data: &second,
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
        ],
        rar15_options_with_features(ArchiveVersion::Rar20, features),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    assert!(raw.main.is_solid());
    let files: Vec<_> = raw.files().collect();
    assert_eq!(files[0].unp_ver, 20);
    assert_eq!(files[1].unp_ver, 20);
    assert!(!files[0].is_solid());
    assert!(files[1].is_solid());
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
fn direct_writer_creates_rar20_old_style_comments() {
    let archive_features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive_with_comment(
        &[rar15_40::FileEntry {
            name: b"rar20-commented.txt",
            data: b"facade rar20 archive comment payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar20, archive_features),
        Some(b"facade rar20 archive note"),
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    assert!(raw.main.has_archive_comment());
    assert_eq!(
        raw.archive_comment().unwrap().as_deref(),
        Some(b"facade rar20 archive note".as_slice())
    );

    let file_features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar20-file-commented.txt",
            data: b"facade rar20 file comment payload payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: Some(b"facade rar20 file note"),
        }],
        rar15_options_with_features(ArchiveVersion::Rar20, file_features),
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    assert_eq!(file.unp_ver, 20);
    assert_eq!(
        file.file_comment().unwrap().as_deref(),
        Some(b"facade rar20 file note".as_slice())
    );
}

#[test]
fn direct_writer_creates_rar29_comments() {
    let archive_features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive_with_comment(
        &[rar15_40::FileEntry {
            name: b"rar29-commented.txt",
            data: b"facade rar29 archive comment payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar29, archive_features),
        Some(b"facade rar29 archive note"),
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    assert!(!raw.main.has_archive_comment());
    assert_eq!(
        raw.archive_comment().unwrap().as_deref(),
        Some(b"facade rar29 archive note".as_slice())
    );

    let file_features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar29-file-commented.txt",
            data: b"facade rar29 file comment payload payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: Some(b"facade rar29 file note"),
        }],
        rar15_options_with_features(ArchiveVersion::Rar29, file_features),
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    assert_eq!(file.unp_ver, 29);
    assert_eq!(
        file.file_comment().unwrap().as_deref(),
        Some(b"facade rar29 file note".as_slice())
    );
}

#[test]
fn direct_writer_creates_rar30_newsub_archive_comment() {
    let features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive_with_comment(
        &[rar15_40::FileEntry {
            name: b"rar30-commented.txt",
            data: b"facade rar30 NEWSUB archive comment payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar30, features),
        Some(b"facade rar30 NEWSUB note"),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    assert!(!raw.main.has_archive_comment());
    let subblock = raw.new_subs().find(|sub| sub.file.name == b"CMT").unwrap();
    assert_eq!(subblock.kind, rar15_40::NewSubKind::ArchiveComment);
    assert_eq!(subblock.file.name, b"CMT");
    assert_eq!(
        raw.archive_comment().unwrap().as_deref(),
        Some(b"facade rar30 NEWSUB note".as_slice())
    );
}

#[test]
fn direct_writer_creates_rar15_solid_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let bytes = rar15_40::write_compressed_archive(
        &[
            rar15_40::FileEntry {
                name: b"one.txt",
                data: b"shared facade prefix one\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
            rar15_40::FileEntry {
                name: b"two.txt",
                data: b"shared facade prefix two\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            },
        ],
        rar15_options_with_features(ArchiveVersion::Rar15, features),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, b"shared facade prefix one\n");
    assert_eq!(extracted[1].data, b"shared facade prefix two\n");
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar15_encrypted_compressed_archive() {
    let features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"secret.txt",
            data: b"facade encrypted payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar15, features),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert!(matches!(
        collect_extract(&archive, None),
        Err(Error::NeedPassword)
    ));
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, b"facade encrypted payload\n");
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar30_aes_encrypted_compressed_archive() {
    let features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar30-secret.txt",
            data: b"facade rar30 aes encrypted payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar30, features),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert!(matches!(
        collect_extract(&archive, None),
        Err(Error::NeedPassword)
    ));
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, b"facade rar30 aes encrypted payload\n");
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar29_aes_encrypted_compressed_archive() {
    let features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar29-secret.txt",
            data: b"facade rar29 aes encrypted payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar29, features),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    assert_eq!(file.unp_ver, 29);
    assert!(file.is_encrypted());
    assert!(file.salt.is_some());
    assert!(matches!(
        collect_extract(&archive, None),
        Err(Error::NeedPassword)
    ));
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, b"facade rar29 aes encrypted payload\n");
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar20_encrypted_compressed_archive() {
    let features = FeatureSet::store_only();
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar20-secret.txt",
            data: b"facade rar20 encrypted payload payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar20, features),
    )
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar15_40().unwrap();
    let file = raw.files().next().unwrap();
    assert_eq!(file.unp_ver, 20);
    assert!(file.is_encrypted());
    assert!(matches!(
        collect_extract(&archive, None),
        Err(Error::NeedPassword)
    ));
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade rar20 encrypted payload payload\n"
    );
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar30_header_encrypted_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = rar15_40::write_compressed_archive(
        &[rar15_40::FileEntry {
            name: b"rar30-header-secret.txt",
            data: b"facade rar30 header encrypted payload\n",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(b"password"),
            file_comment: None,
        }],
        rar15_options_with_features(ArchiveVersion::Rar30, features),
    )
    .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let raw = archive.as_rar15_40().unwrap();
    assert!(raw.main.has_encrypted_headers());
    assert_eq!(raw.files().next().unwrap().name, b"rar30-header-secret.txt");
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade rar30 header encrypted payload\n"
    );
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar30_solid_header_encrypted_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    features.solid = true;
    let bytes = rar15_40::write_compressed_archive(
        &[
            rar15_40::FileEntry {
                name: b"solid-header-one.txt",
                data: b"facade solid header encrypted one one one\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
            rar15_40::FileEntry {
                name: b"solid-header-two.txt",
                data: b"facade solid header encrypted two two two\n",
                file_time: 0,
                file_attr: 0x20,
                host_os: 3,
                password: Some(b"password"),
                file_comment: None,
            },
        ],
        rar15_options_with_features(ArchiveVersion::Rar30, features),
    )
    .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade solid header encrypted one one one\n"
    );
    assert_eq!(
        extracted[1].data,
        b"facade solid header encrypted two two two\n"
    );
}

#[test]
fn direct_writer_creates_rar50_stored_archive() {
    let bytes =
        rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
            .entries(
                [
                    rar50_entry(b"rar5-store.txt", b"facade rar5 stored payload\n")
                        .with_mtime(Some(0))
                        .with_attributes(0x20)
                        .with_host_os(3),
                ]
                .to_vec(),
            )
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert_eq!(archive.family(), ArchiveFamily::Rar50Plus);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, b"facade rar5 stored payload\n");
}

#[test]
fn direct_writer_creates_rar50_compressed_archive() {
    let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
        .entries(
            [rar50_entry(
                b"rar5-compressed.txt",
                b"facade rar5 compressed payload\nfacade rar5 compressed payload\n",
            )
            .with_mtime(Some(0))
            .with_attributes(0x20)
            .with_host_os(3)]
            .to_vec(),
        )
        .finish()
        .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar50().unwrap();
    let file = raw.files().next().unwrap();
    assert_eq!(file.decoded_compression_info().unwrap().method, 3);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade rar5 compressed payload\nfacade rar5 compressed payload\n"
    );
}

#[test]
fn direct_writer_creates_rar50_solid_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let first = b"facade rar50 solid shared phrase alpha beta gamma\n".repeat(16);
    let second = b"facade rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries(
                [
                    rar50_entry(b"rar5-solid-one.txt", &first)
                        .with_mtime(Some(0))
                        .with_attributes(0x20)
                        .with_host_os(3),
                    rar50_entry(b"rar5-solid-two.txt", &second)
                        .with_mtime(Some(0))
                        .with_attributes(0x20)
                        .with_host_os(3),
                ]
                .to_vec(),
            )
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar50().unwrap();
    let files: Vec<_> = raw.files().collect();
    assert!(raw.main.is_solid());
    assert!(!files[0].decoded_compression_info().unwrap().solid);
    assert!(files[1].decoded_compression_info().unwrap().solid);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
fn direct_writer_creates_rar50_delta_filtered_compressed_archive() {
    let payload: Vec<u8> = (0..180)
        .map(|index| (index * 11 + index / 5) as u8)
        .collect();
    let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
        .entries(
            [rar50_entry(b"rar5-delta-filtered.bin", &payload)
                .with_mtime(Some(0))
                .with_attributes(0x20)
                .with_host_os(3)]
            .to_vec(),
        )
        .filter_policy(rar50::FilterPolicy::explicit(rar50::FilterKind::Delta {
            channels: 3,
        }))
        .finish()
        .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar50_e8_filtered_compressed_archive() {
    let payload = b"\xe8\0\0\0\0facade rar5 e8 filter payload".to_vec();
    let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
        .entries(
            [rar50_entry(b"rar5-e8-filtered.bin", &payload)
                .with_mtime(Some(0))
                .with_attributes(0x20)
                .with_host_os(3)]
            .to_vec(),
        )
        .filter_policy(rar50::FilterPolicy::explicit(rar50::FilterKind::E8))
        .finish()
        .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar50_arm_filtered_compressed_archive() {
    let payload = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
    let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
        .entries(
            [rar50_entry(b"rar5-arm-filtered.bin", &payload)
                .with_mtime(Some(0))
                .with_attributes(0x20)
                .with_host_os(3)]
            .to_vec(),
        )
        .filter_policy(rar50::FilterPolicy::explicit(rar50::FilterKind::Arm))
        .finish()
        .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar50_auto_filtered_compressed_archive() {
    let payload = b"\xe8\0\0\0\0facade rar5 auto filter payload\n".repeat(16);
    let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50))
        .entries(
            [rar50_entry(b"rar5-auto-filtered.bin", &payload)
                .with_mtime(Some(0))
                .with_attributes(0x20)
                .with_host_os(3)]
            .to_vec(),
        )
        .filter_policy(rar50::FilterPolicy::Auto)
        .finish()
        .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[cfg(feature = "recovery")]
fn direct_writer_creates_rar50_stored_archive_with_recovery_service() {
    let features = FeatureSet::store_only();
    let bytes = rar50::Rar50Writer::new(
        rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
    )
    .entries(
        [
            rar50_entry(b"rar5-recovery.txt", b"facade rar5 recovery payload\n")
                .with_attributes(0x20)
                .with_host_os(3),
        ]
        .to_vec(),
    )
    .recovery_percent(Some(9))
    .finish()
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar50().unwrap();
    assert!(raw.main.has_recovery_record());
    let service = raw
        .services()
        .find(|service| service.name != b"RARS")
        .unwrap();
    assert_eq!(service.name, b"RR");
    let recovery = service.recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 9);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, b"facade rar5 recovery payload\n");
}

#[test]
#[cfg(feature = "recovery")]
fn archive_facade_repairs_rar50_inline_recovery_damage() {
    let features = FeatureSet::store_only();
    let payload = b"facade rar5 repair payload\n".repeat(64);
    let bytes = rar50::Rar50Writer::new(
        rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
    )
    .entries(
        [rar50_entry(b"rar5-repair.txt", &payload)
            .with_attributes(0x20)
            .with_host_os(3)]
        .to_vec(),
    )
    .recovery_percent(Some(20))
    .finish()
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let data_range = archive
        .as_rar50()
        .unwrap()
        .files()
        .next()
        .unwrap()
        .block
        .data_range
        .clone();
    let mut damaged = bytes.clone();
    damaged[data_range.start + 4..data_range.start + 80].fill(0xa5);
    let damaged_archive = ArchiveReader::read(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive, None).is_err());

    let mut repaired = Vec::new();
    damaged_archive.repair_recovery_to(&mut repaired).unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = ArchiveReader::read(&repaired).unwrap();
    assert_eq!(
        collect_extract(&repaired_archive, None).unwrap()[0].data,
        payload
    );
}

#[test]
#[cfg(feature = "recovery")]
fn archive_facade_reports_rar13_family_for_unsupported_recovery_repair() {
    let bytes = rar13::write_stored_archive(
        &[rar13::StoredEntry {
            name: b"old.txt",
            data: b"old rar payload",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        rar13_options(ArchiveVersion::Rar13),
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let mut repaired = Vec::new();
    let err = archive.repair_recovery_to(&mut repaired).unwrap_err();

    assert_eq!(
        err,
        Error::UnsupportedFamilyFeature {
            family: ArchiveFamily::Rar13,
            feature: "recovery repair for RAR 1.3/1.4 archives"
        }
    );
}

#[test]
#[cfg(feature = "recovery")]
fn archive_facade_repairs_rar15_40_recovery_as_full_archive_bytes() {
    let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
    let mut damaged = bytes.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);
    let damaged_archive = ArchiveReader::read(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive, None).is_err());

    let mut repaired = Vec::new();
    damaged_archive.repair_recovery_to(&mut repaired).unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = ArchiveReader::read(&repaired).unwrap();
    assert_eq!(
        collect_extract(&repaired_archive, None).unwrap()[0].name,
        b"BIG.BIN"
    );
}

#[test]
#[cfg(feature = "recovery")]
fn archive_facade_repairs_rar3_newsub_recovery_as_full_archive_bytes() {
    let bytes = std::fs::read(rar15_40_fixture("rar300/with_recovery_rar300.rar")).unwrap();
    let mut damaged = bytes.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);
    let damaged_archive = ArchiveReader::read(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive, None).is_err());

    let mut repaired = Vec::new();
    damaged_archive.repair_recovery_to(&mut repaired).unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = ArchiveReader::read(&repaired).unwrap();
    assert_eq!(
        collect_extract(&repaired_archive, None).unwrap()[0].name,
        b"bigtext_64k.bin"
    );
}

#[test]
#[cfg(feature = "recovery")]
fn direct_writer_creates_rar50_compressed_archive_with_recovery_service() {
    let features = FeatureSet::store_only();
    let payload = b"facade rar5 compressed recovery payload repeated repeated\n".repeat(8);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries(
                [rar50_entry(b"rar5-compressed-recovery.txt", &payload)
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .recovery_percent(Some(9))
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar50().unwrap();
    assert!(raw.main.has_recovery_record());
    let service = raw
        .services()
        .find(|service| service.name != b"RARS")
        .unwrap();
    assert_eq!(service.name, b"RR");
    assert_eq!(service.recovery_record().unwrap().unwrap().percent, 9);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn direct_writer_creates_rar70_stored_archive_with_metadata() {
    let bytes =
        rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar70).with_compression_level(0))
            .entries(
                [
                    rar50_entry(b"rar7-metadata.txt", b"facade rar7 metadata payload\n")
                        .with_attributes(0x20)
                        .with_host_os(3),
                ]
                .to_vec(),
            )
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"facade-metadata.rar".as_slice())
    );
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, b"facade rar7 metadata payload\n");
}

#[test]
fn direct_writer_creates_rar70_compressed_archive_with_metadata() {
    let payload = b"facade rar7 compressed metadata payload repeated\n".repeat(8);
    let bytes = rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar70))
        .entries(
            [rar50_entry(b"rar7-compressed-metadata.txt", &payload)
                .with_attributes(0x20)
                .with_host_os(3)]
            .to_vec(),
        )
        .archive_metadata(Some(rar50::ArchiveMetadataEntry {
            name: Some(b"facade-compressed-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }))
        .finish()
        .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"facade-compressed-metadata.rar".as_slice())
    );
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar70_encrypted_stored_archive_with_metadata() {
    let features = FeatureSet::store_only();
    let bytes = rar50::Rar50Writer::new(
        rar50_options_with_features(ArchiveVersion::Rar70, features).with_compression_level(0),
    )
    .entries(
        [rar50_entry(
            b"rar7-encrypted-metadata.txt",
            b"facade rar7 encrypted metadata payload\n",
        )
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())]
        .to_vec(),
    )
    .archive_metadata(Some(rar50::ArchiveMetadataEntry {
        name: Some(b"facade-encrypted-metadata.rar"),
        creation_time: Some(0x01dcd60e_662d7a32),
    }))
    .finish()
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"facade-encrypted-metadata.rar".as_slice())
    );
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade rar7 encrypted metadata payload\n"
    );
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar70_encrypted_compressed_archive_with_metadata() {
    let features = FeatureSet::store_only();
    let payload = b"facade rar7 encrypted compressed metadata payload repeated\n".repeat(8);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
            .entries(
                [
                    rar50_entry(b"rar7-encrypted-compressed-metadata.txt", &payload)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                ]
                .to_vec(),
            )
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-encrypted-compressed-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"facade-encrypted-compressed-metadata.rar".as_slice())
    );
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar70_header_encrypted_stored_archive_with_metadata() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = rar50::Rar50Writer::new(
        rar50_options_with_features(ArchiveVersion::Rar70, features).with_compression_level(0),
    )
    .entries(
        [rar50_entry(
            b"rar7-header-metadata.txt",
            b"facade rar7 header encrypted metadata payload\n",
        )
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())]
        .to_vec(),
    )
    .archive_metadata(Some(rar50::ArchiveMetadataEntry {
        name: Some(b"facade-header-metadata.rar"),
        creation_time: Some(0x01dcd60e_662d7a32),
    }))
    .finish()
    .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"facade-header-metadata.rar".as_slice())
    );
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade rar7 header encrypted metadata payload\n"
    );
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar70_header_encrypted_compressed_archive_with_metadata() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let payload = b"facade rar7 header encrypted compressed metadata payload repeated\n".repeat(8);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar70, features))
            .entries(
                [
                    rar50_entry(b"rar7-header-compressed-metadata.txt", &payload)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                ]
                .to_vec(),
            )
            .archive_metadata(Some(rar50::ArchiveMetadataEntry {
                name: Some(b"facade-header-compressed-metadata.rar"),
                creation_time: Some(0x01dcd60e_662d7a32),
            }))
            .finish()
            .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let metadata = archive.as_rar50().unwrap().main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"facade-header-compressed-metadata.rar".as_slice())
    );
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_encrypted_stored_archive() {
    let features = FeatureSet::store_only();
    let bytes = rar50::Rar50Writer::new(
        rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
    )
    .entries(
        [rar50_entry(
            b"rar5-secret.txt",
            b"facade rar5 encrypted stored payload\n",
        )
        .with_mtime(Some(0))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())]
        .to_vec(),
    )
    .finish()
    .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    assert!(matches!(
        collect_extract(&archive, None),
        Err(Error::AtEntry { source, .. }) if matches!(*source, Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract(&archive, Some(b"wrong")),
        Err(Error::AtEntry { source, .. })
            if matches!(*source, Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, b"facade rar5 encrypted stored payload\n");
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_encrypted_compressed_archive() {
    let features = FeatureSet::store_only();
    let payload = b"facade rar5 encrypted compressed\n".repeat(16);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries(
                [rar50_entry(b"rar5-secret-compressed.txt", &payload)
                    .with_attributes(0x20)
                    .with_host_os(3)
                    .with_password(b"password".to_vec())]
                .to_vec(),
            )
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar50().unwrap();
    let file = raw.files().next().unwrap();
    assert!(file.encrypted);
    assert_eq!(file.decoded_compression_info().unwrap().method, 3);
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_encrypted_solid_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let first = b"facade rar50 encrypted solid shared phrase alpha beta gamma\n".repeat(12);
    let second = b"facade rar50 encrypted solid shared phrase alpha beta gamma\nsecond\n".repeat(6);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries(
                [
                    rar50_entry(b"rar5-encrypted-solid-one.txt", &first)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                    rar50_entry(b"rar5-encrypted-solid-two.txt", &second)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                ]
                .to_vec(),
            )
            .finish()
            .unwrap();

    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar50().unwrap();
    let files: Vec<_> = raw.files().collect();
    assert!(raw.main.is_solid());
    assert!(files.iter().all(|file| file.encrypted));
    assert!(!files[0].decoded_compression_info().unwrap().solid);
    assert!(files[1].decoded_compression_info().unwrap().solid);
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_header_encrypted_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = rar50::Rar50Writer::new(rar50_options_with_features(
        ArchiveVersion::Rar50,
        features,
    ))
    .entries(
        [rar50_entry(
            b"rar5-header-secret-compressed.txt",
            b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n",
        )
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())]
        .to_vec(),
    )
    .finish()
    .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let raw = archive.as_rar50().unwrap();
    let file = raw.files().next().unwrap();
    assert!(file.encrypted);
    assert_eq!(file.decoded_compression_info().unwrap().method, 3);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade rar5 header encrypted compressed\nfacade rar5 header encrypted compressed\n"
    );
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_header_encrypted_solid_compressed_archive() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    features.solid = true;
    let first = b"facade rar50 header encrypted solid shared phrase alpha beta gamma\n".repeat(12);
    let second =
        b"facade rar50 header encrypted solid shared phrase alpha beta gamma\nsecond\n".repeat(6);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries(
                [
                    rar50_entry(b"rar5-header-solid-one.txt", &first)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                    rar50_entry(b"rar5-header-solid-two.txt", &second)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                ]
                .to_vec(),
            )
            .finish()
            .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let raw = archive.as_rar50().unwrap();
    let files: Vec<_> = raw.files().collect();
    assert!(raw.main.is_solid());
    assert!(files.iter().all(|file| file.encrypted));
    assert!(!files[0].decoded_compression_info().unwrap().solid);
    assert!(files[1].decoded_compression_info().unwrap().solid);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_header_encrypted_stored_archive() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = rar50::Rar50Writer::new(
        rar50_options_with_features(ArchiveVersion::Rar50, features).with_compression_level(0),
    )
    .entries(
        [rar50_entry(
            b"rar5-header-secret.txt",
            b"facade rar5 header encrypted stored payload\n",
        )
        .with_mtime(Some(0))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())]
        .to_vec(),
    )
    .finish()
    .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    assert!(matches!(
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let extracted = collect_extract(&archive, Some(b"password")).unwrap();
    assert_eq!(
        extracted[0].data,
        b"facade rar5 header encrypted stored payload\n"
    );
}

#[test]
#[cfg(feature = "recovery")]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_encrypted_compressed_archive_with_recovery() {
    let features = FeatureSet::store_only();
    let payload = b"facade rar5 encrypted compressed recovery payload repeated\n".repeat(8);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries(
                [
                    rar50_entry(b"rar5-encrypted-compressed-recovery.txt", &payload)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                ]
                .to_vec(),
            )
            .recovery_percent(Some(6))
            .finish()
            .unwrap();

    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let raw = archive.as_rar50().unwrap();
    assert!(raw.main.has_recovery_record());
    let service = raw
        .services()
        .find(|service| service.name != b"RARS")
        .unwrap();
    assert_eq!(service.name, b"RR");
    assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
#[cfg(feature = "recovery")]
#[cfg(feature = "encryption")]
fn direct_writer_creates_rar50_header_encrypted_compressed_archive_with_recovery() {
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let payload = b"facade rar5 header encrypted compressed recovery payload repeated\n".repeat(8);
    let bytes =
        rar50::Rar50Writer::new(rar50_options_with_features(ArchiveVersion::Rar50, features))
            .entries(
                [
                    rar50_entry(b"rar5-header-compressed-recovery.txt", &payload)
                        .with_attributes(0x20)
                        .with_host_os(3)
                        .with_password(b"password".to_vec()),
                ]
                .to_vec(),
            )
            .recovery_percent(Some(4))
            .finish()
            .unwrap();

    assert!(matches!(
        ArchiveReader::read(&bytes),
        Err(Error::NeedPassword)
    ));
    let archive =
        ArchiveReader::read_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    let raw = archive.as_rar50().unwrap();
    assert!(raw.main.has_recovery_record());
    let service = raw
        .services()
        .find(|service| service.name != b"RARS")
        .unwrap();
    assert_eq!(service.name, b"RR");
    assert!(!service.encrypted);
    assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn archive_as_rar13_returns_some_only_for_rar13_family() {
    let bytes = rar13::write_stored_archive(
        &[rar13::StoredEntry {
            name: b"old.txt",
            data: b"r13 downcast",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        rar13_options(ArchiveVersion::Rar14),
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let raw = archive.as_rar13().unwrap();
    assert_eq!(raw.entries[0].name, b"old.txt");
    assert!(archive.as_rar15_40().is_none());
    assert!(archive.as_rar50().is_none());

    // Other-family archives should refuse the rar13 downcast.
    let rar15_bytes = rar15_40::write_stored_archive(
        &[rar15_40::StoredEntry {
            name: b"mid.txt",
            data: b"r15 downcast",
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        rar15_options(ArchiveVersion::Rar15),
    )
    .unwrap();
    let rar15_archive = ArchiveReader::read(&rar15_bytes).unwrap();
    assert!(rar15_archive.as_rar13().is_none());

    let rar50_bytes =
        rar50::Rar50Writer::new(rar50_options(ArchiveVersion::Rar50).with_compression_level(0))
            .entries(
                [rar50_entry(b"new.txt", b"r50 downcast")
                    .with_attributes(0x20)
                    .with_host_os(3)]
                .to_vec(),
            )
            .finish()
            .unwrap();
    let rar50_archive = ArchiveReader::read(&rar50_bytes).unwrap();
    assert!(rar50_archive.as_rar13().is_none());
}

#[test]
#[cfg(feature = "recovery")]
fn archive_facade_repair_recovery_returns_full_repaired_archive_bytes() {
    let bytes = std::fs::read(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
    let mut damaged = bytes.clone();
    damaged[512 + 16..512 + 80].fill(0xa5);
    let damaged_archive = ArchiveReader::read(&damaged).unwrap();

    let repaired = damaged_archive.repair_recovery().unwrap();
    assert_eq!(repaired, bytes);
}

#[test]
#[cfg(feature = "recovery")]
fn archive_facade_repair_recovery_rejects_rar13_archives() {
    let bytes = rar13::write_stored_archive(
        &[rar13::StoredEntry {
            name: b"old.txt",
            data: b"old data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        rar13_options(ArchiveVersion::Rar14),
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    assert_eq!(
        archive.repair_recovery(),
        Err(Error::UnsupportedFamilyFeature {
            family: ArchiveFamily::Rar13,
            feature: "recovery repair for RAR 1.3/1.4 archives",
        })
    );
}

#[test]
fn archive_reader_read_path_dispatches_to_default_options() {
    // Existing tests cover read_path_with_options; this ensures the
    // zero-arg convenience wrapper actually delegates to it.
    let archive =
        ArchiveReader::read_path(rar15_40_fixture("rar250_protect_head_rr5.rar")).unwrap();
    assert_eq!(archive.family(), ArchiveFamily::Rar15To40);
    assert!(archive.as_rar15_40().unwrap().main.has_recovery_record());
}

#[test]
fn archive_member_can_be_read_by_index() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"first.txt".to_vec(), b"first".to_vec(), None, None)
        .unwrap();
    builder
        .add_bytes(b"second.txt".to_vec(), b"second".to_vec(), None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();

    assert_eq!(archive.read_member_at(1, None).unwrap().unwrap(), b"second");
    assert_eq!(archive.read_member_at(2, None).unwrap(), None);
}

#[test]
fn volume_facade_rejects_empty_and_every_mixed_family_ordering() {
    let never_open = |_: &ExtractedEntryMeta| -> Result<Box<dyn Write>> {
        panic!("invalid volume set must be rejected before opening output")
    };
    let empty = Error::InvalidHeader("volume set is empty");
    assert_eq!(volume_members(&[]).unwrap_err(), empty);
    assert_eq!(read_volume_members_at(&[], &[], None).unwrap_err(), empty);
    assert_eq!(
        extract_volumes_to(&[], None, never_open).unwrap_err(),
        empty
    );
    let cancellation = ReadCancellation::new();
    cancellation.cancel();
    assert_eq!(
        extract_volumes_to_with_options(
            &[],
            ArchiveReadOptions::new().with_cancellation(&cancellation),
            never_open,
        )
        .unwrap_err(),
        Error::Cancelled
    );

    let archives: Vec<_> = [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ]
    .into_iter()
    .map(|version| {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
    })
    .collect();
    for first in 0..archives.len() {
        for second in 0..archives.len() {
            if first == second {
                continue;
            }
            let mixed = [archives[first].clone(), archives[second].clone()];
            let error = Error::InvalidHeader("mixed archive families in volume set");
            assert_eq!(volume_members(&mixed).unwrap_err(), error);
            assert_eq!(
                extract_volumes_to(&mixed, None, never_open).unwrap_err(),
                error
            );
        }
    }
}

#[test]
fn volume_index_reads_skip_directories_and_absent_indices_in_each_family() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder.add_directory(b"dir".to_vec(), None, None).unwrap();
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let archives = [ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()];
        assert_eq!(read_volume_member_at(&archives, 0, None).unwrap(), None);
        assert_eq!(
            read_volume_member_at(&archives, 1, None).unwrap(),
            Some(b"payload".to_vec())
        );
        assert_eq!(read_volume_member_at(&archives, 2, None).unwrap(), None);
    }
}

#[test]
fn volume_members_and_index_reads_fold_split_fragments() {
    let payload = vec![7; 200_000];
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .volume_size(Some(64 * 1024));
    builder
        .add_bytes(b"big.bin".to_vec(), payload.clone(), None, None)
        .unwrap();
    let archives: Vec<_> = builder
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .map(|part| ArchiveReader::read_owned(part).unwrap())
        .collect();

    let members = volume_members(&archives).unwrap();
    assert_eq!(
        volume_members(&archives[1..]).unwrap_err(),
        Error::InvalidHeader("volume set starts with a continuation")
    );
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].meta.name, b"big.bin");
    assert_eq!(
        read_volume_member_at(&archives, 0, None).unwrap().unwrap(),
        payload
    );
    assert_eq!(
        read_volume_members_at(&archives, &[0, 0, usize::MAX], None).unwrap(),
        vec![Some(payload.clone()), Some(payload), None]
    );
}

#[cfg(feature = "encryption")]
fn rar50_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar50")
        .join(name)
}

#[cfg(feature = "encryption")]
#[test]
fn read_session_reports_a_wrong_password_on_every_volume() {
    for stem in ["encrypted_multivol", "header_encrypted_stored_multivol"] {
        let mut session =
            rars::read_session::ReadSession::new(ArchiveReadOptions::with_password(b"wrong"));
        for part in 1..=3 {
            let error = session
                .read_path(rar50_fixture(&format!("{stem}.part{part}.rar")))
                .unwrap_err();
            assert!(
                matches!(error.root_cause(), Error::WrongPasswordOrCorruptData),
                "{stem} part {part}: {error:?}"
            );
        }
    }
}
