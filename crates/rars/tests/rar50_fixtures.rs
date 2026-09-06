#[path = "support/scratch.rs"]
mod scratch;

use rars::codec::rar50::{
    decode_lz, encode_lz_member, parse_compressed_block, read_table_lengths, DecodeTables,
};
use rars::crc32::crc32;
use rars::crypto::rar50::{Rar50Cipher, Rar50Keys};
use rars::rar50::{
    extract_volumes_to, repair_inline_recovery_bytes, repair_rev5_volumes_to, Archive,
    ArchiveMetadataEntry, Block, FilterKind, FilterPolicy, Rev5Volume, Rev5VolumeMeta,
    ServiceEntry,
};
use rars::recovery::rar5::crc64_xz;
use rars::{
    detect_archive_family, rar50, ArchiveFamily, ArchiveReadOptions, ArchiveVersion, Error,
    FeatureSet,
};
use std::cell::RefCell;
use std::fs;
use std::io::{Read, Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar50")
        .join(name)
}

fn service_names(archive: &Archive) -> Vec<String> {
    archive
        .services()
        .map(|service| service.name_lossy())
        .collect()
}

struct CollectWriter {
    data: Rc<RefCell<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Historical numeric snapshots; timestamp presence has dedicated regression tests.
struct CollectedEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    file_time: u32,
    attr: u64,
    host_os: u64,
    is_directory: bool,
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

fn assert_rar50_end_header_has_flags_vint(archive: &Archive) {
    let end = archive
        .blocks
        .iter()
        .find_map(|block| match block {
            Block::End(header) => Some(header),
            _ => None,
        })
        .expect("archive has end header");
    assert_eq!(end.block.header_type, 5);
    assert_eq!(
        end.block.header_size, 3,
        "RAR 5 end header must include End of Archive Flags vint"
    );
}

/// Every volume but the last has to say another one follows. unrar guesses
/// from the file names and does not care, but 7-Zip believes the flag: with it
/// clear it stops at the volume it was handed, and a member continuing into the
/// next one comes out truncated as a data error.
fn assert_volume_set_links_its_parts(parts: &[Vec<u8>], password: Option<&[u8]>) {
    for (index, part) in parts.iter().enumerate() {
        let archive = match password {
            Some(password) => {
                Archive::parse_with_options(part, ArchiveReadOptions::with_password(password))
                    .unwrap()
            }
            None => Archive::parse(part).unwrap(),
        };
        let end = archive
            .blocks
            .iter()
            .find_map(|block| match block {
                Block::End(header) => Some(header),
                _ => None,
            })
            .expect("a volume ends with an end header");
        let last = index + 1 == parts.len();
        assert_eq!(
            end.has_next_volume(),
            !last,
            "volume {} of {} has the wrong next-volume flag",
            index + 1,
            parts.len()
        );
    }
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
            file_time: meta.file_time.unwrap_or(0),
            attr: meta.attr,
            host_os: meta.host_os,
            is_directory: meta.is_directory,
        })
        .collect())
}

fn collect_file(archive: &Archive, file: &rar50::FileHeader) -> Result<CollectedEntry, Error> {
    let meta = file.metadata();
    let data = Rc::new(RefCell::new(Vec::new()));
    file.write_to(
        archive,
        None,
        &mut CollectWriter {
            data: Rc::clone(&data),
        },
    )?;
    let data = data.borrow().clone();
    Ok(CollectedEntry {
        name: meta.name,
        data,
        file_time: meta.file_time.unwrap_or(0),
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
            file_time: meta.file_time.unwrap_or(0),
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

fn deterministic_noise(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

fn corrupt_encrypted_stored_padding(bytes: &mut [u8], password: &[u8]) {
    let archive = Archive::parse(bytes).unwrap();
    let file = archive.files().next().unwrap();
    let encryption = file.encryption.as_ref().unwrap();
    let keys = Rar50Keys::derive(password, encryption.salt, encryption.kdf_count).unwrap();
    let range = file.block.data_range.clone();
    let mut plaintext = bytes[range.clone()].to_vec();
    Rar50Cipher::new(keys.key, encryption.iv)
        .decrypt_in_place(&mut plaintext)
        .unwrap();
    assert!(file.unpacked_size < plaintext.len() as u64);
    plaintext[file.unpacked_size as usize] = 1;
    Rar50Cipher::new(keys.key, encryption.iv)
        .encrypt_in_place(&mut plaintext)
        .unwrap();
    bytes[range].copy_from_slice(&plaintext);
}

fn corrupt_encrypted_stored_split_padding(volumes: &mut [Vec<u8>], password: &[u8]) {
    let archives = volumes
        .iter()
        .map(|bytes| Archive::parse(bytes).unwrap())
        .collect::<Vec<_>>();
    let first_file = archives[0].files().next().unwrap();
    let final_file = archives.last().unwrap().files().next().unwrap();
    let encryption = first_file.encryption.as_ref().unwrap();
    let keys = Rar50Keys::derive(password, encryption.salt, encryption.kdf_count).unwrap();
    let mut ranges = Vec::with_capacity(archives.len());
    let mut encrypted = Vec::new();
    for (volume_index, archive) in archives.iter().enumerate() {
        let file = archive.files().next().unwrap();
        let range = file.block.data_range.clone();
        encrypted.extend_from_slice(&volumes[volume_index][range.clone()]);
        ranges.push(range);
    }
    let mut plaintext = encrypted;
    Rar50Cipher::new(keys.key, encryption.iv)
        .decrypt_in_place(&mut plaintext)
        .unwrap();
    assert!(final_file.unpacked_size < plaintext.len() as u64);
    plaintext[final_file.unpacked_size as usize] = 1;
    Rar50Cipher::new(keys.key, encryption.iv)
        .encrypt_in_place(&mut plaintext)
        .unwrap();

    let mut offset = 0;
    for (volume, range) in volumes.iter_mut().zip(ranges) {
        let len = range.len();
        volume[range].copy_from_slice(&plaintext[offset..offset + len]);
        offset += len;
    }
}

fn level_sensitive_payload() -> Vec<u8> {
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

fn repair_rev5_volumes(
    data_volumes: &[Option<&[u8]>],
    recovery_volumes: &[Rev5Volume],
) -> Result<Vec<Vec<u8>>, Error> {
    let mut repaired = Vec::new();
    repair_rev5_volumes_to(data_volumes, recovery_volumes, |_, bytes| {
        repaired.push(bytes.to_vec());
        Ok(())
    })?;
    Ok(repaired)
}

/// Reads a member's bytes back out, for tests that assert on what they wrote.
fn entry_data(entry: &rar50::ArchiveEntry) -> Vec<u8> {
    let mut data = Vec::new();
    entry.source.open().unwrap().read_to_end(&mut data).unwrap();
    data
}

/// Builds a member from bytes the test already holds.
fn entry(name: &[u8], data: &[u8]) -> rar50::ArchiveEntry {
    rar50::ArchiveEntry::new(
        name.to_vec(),
        rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
    )
}

/// Storing is a compression level, not a kind of member.
fn stored(options: rar50::WriterOptions) -> rar50::WriterOptions {
    options.with_compression_level(0)
}

fn write_stored_archive(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(stored(options))
        .entries(entries.to_vec())
        .finish()
}

fn write_stored_archive_with_comment(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(stored(options))
        .entries(entries.to_vec())
        .archive_comment(archive_comment)
        .finish()
}

fn write_stored_archive_with_comment_and_metadata(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    archive_comment: Option<&[u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(stored(options))
        .entries(entries.to_vec())
        .archive_comment(archive_comment)
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_stored_archive_with_recovery(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(stored(options))
        .entries(entries.to_vec())
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_compressed_archive(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .entries(entries.to_vec())
        .finish()
}

fn write_compressed_archive_with_metadata(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .entries(entries.to_vec())
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_compressed_archive_with_comment(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .entries(entries.to_vec())
        .archive_comment(archive_comment)
        .finish()
}

fn write_compressed_archive_with_recovery(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .entries(entries.to_vec())
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_compressed_archive_with_filter_policy(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    policy: FilterPolicy,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .entries(entries.to_vec())
        .filter_policy(policy)
        .finish()
}

fn write_encrypted_archive_with_comment(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    archive_comment: Option<(&[u8], &[u8])>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    let writer = rar50::Rar50Writer::new(options)
        .entries(entries.to_vec())
        .archive_metadata(archive_metadata);
    let writer = match archive_comment {
        Some((comment, password)) => writer.encrypted_archive_comment(comment, password),
        None => writer,
    };
    writer.finish()
}

/// Collects a volume set in memory. The writer still holds one volume at a
/// time; only the test keeps them all.
fn write_volumes(
    entries: &[rar50::ArchiveEntry],
    options: rar50::WriterOptions,
    max_payload_per_volume: u64,
    recovery_percent: Option<u64>,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut sink = rar50::CollectedVolumes::new();
    rar50::write_streaming_volumes_to(
        entries,
        options,
        rar50::ArchiveExtras::default().with_recovery_percent(recovery_percent),
        max_payload_per_volume,
        &mut sink,
        &rars::WriterResources::default(),
    )?;
    let volumes = sink.take();
    Ok(volumes)
}

fn assert_rar5_inline_recovery_chunks(data: &[u8]) {
    let mut offset = 0;
    let mut chunks = 0;
    let mut expected_recovery_shards = None;
    while offset < data.len() {
        assert!(data[offset..].starts_with(b"{RB}"));
        let total_size =
            u32::from_le_bytes(data[offset + 0x0c..offset + 0x10].try_into().unwrap()) as usize;
        let header_size =
            u32::from_le_bytes(data[offset + 0x10..offset + 0x14].try_into().unwrap()) as usize;
        assert!(total_size >= header_size);
        assert!(header_size >= 0x48);
        assert!(offset + total_size <= data.len());

        let chunk = &data[offset..offset + total_size];
        assert_eq!(
            u64::from_le_bytes(chunk[0x04..0x0c].try_into().unwrap()),
            crc64_xz(&chunk[0x0c..])
        );
        assert_eq!(chunk[0x14], 1);
        assert_eq!(chunk[0x15], 1);

        let data_shards = u16::from_le_bytes(chunk[0x3a..0x3c].try_into().unwrap()) as usize;
        let recovery_shards = u16::from_le_bytes(chunk[0x3c..0x3e].try_into().unwrap()) as usize;
        let shard_index = u16::from_le_bytes(chunk[0x3e..0x40].try_into().unwrap()) as usize;
        assert_eq!(header_size, data_shards * 8 + 0x48);
        assert_eq!(shard_index, chunks);
        assert_eq!(
            expected_recovery_shards.get_or_insert(recovery_shards),
            &recovery_shards
        );

        chunks += 1;
        offset += total_size;
    }
    assert_eq!(Some(chunks), expected_recovery_shards);
}

fn read_test_vint(input: &[u8], offset: &mut usize) -> u64 {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = input[*offset];
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
    }
    panic!("overlong test vint");
}

fn count_verified_quick_open_wrappers(data: &[u8]) -> usize {
    let mut offset = 0;
    let mut count = 0;
    while offset < data.len() {
        let expected = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let framed_start = offset;
        let body_size = read_test_vint(data, &mut offset) as usize;
        let body = &data[offset..offset + body_size];
        // The checksum spans the BlockSize vint as well as the body.
        assert_eq!(crc32(&data[framed_start..offset + body_size]), expected);
        let mut body_offset = 0;
        assert_eq!(read_test_vint(body, &mut body_offset), 0);
        assert_ne!(read_test_vint(body, &mut body_offset), 0);
        let header_size = read_test_vint(body, &mut body_offset) as usize;
        assert_eq!(body.len() - body_offset, header_size);
        offset += body_size;
        count += 1;
    }
    count
}

fn header_encryption_salt_and_first_header_iv(data: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut offset = b"Rar!\x1a\x07\x01\x00".len() + 4;
    let header_size = read_test_vint(data, &mut offset) as usize;
    let body_start = offset;
    let body_end = body_start + header_size;

    assert_eq!(read_test_vint(data, &mut offset), 4);
    assert_eq!(read_test_vint(data, &mut offset), 0);
    assert_eq!(read_test_vint(data, &mut offset), 0);
    assert_eq!(read_test_vint(data, &mut offset), 0x0001);
    offset += 1;

    let salt = data[offset..offset + 16].try_into().unwrap();
    let first_header_iv = data[body_end..body_end + 16].try_into().unwrap();
    (salt, first_header_iv)
}

#[test]
fn detects_rar50_signature_family() {
    let bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let sig = detect_archive_family(&bytes).unwrap();

    assert_eq!(sig.family, ArchiveFamily::Rar50Plus);
    assert_eq!(sig.offset, 0);
    assert_eq!(sig.length, 8);
}

#[test]
fn parses_rar7_archive_metadata_main_extra_record() {
    let archive = Archive::parse_path(fixture("ams_archive_name_rar721.rar")).unwrap();

    let metadata = archive.main.archive_metadata().unwrap();
    assert_eq!(metadata.flags, 0x0003);
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"ams_archive_name_rar721.rar".as_slice())
    );
    assert_eq!(metadata.creation_time, Some(0x01dcd60e_662d7a32));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"hello7.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 7.21 fixture world.\n");
}

#[test]
fn parses_and_extracts_rar50_stored_file() {
    let bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.sfx_offset, 0);
    assert_eq!(archive.main.archive_flags, 0);
    assert_eq!(archive.main.extras.len(), 1);
    let locator = archive.main.locator().unwrap();
    assert_eq!(locator.flags, 0x0001);
    assert_eq!(locator.quick_open_offset, Some(0));
    assert_eq!(locator.recovery_record_offset, None);

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].is_stored());
    assert_eq!(files[0].packed_size(), 30);
    assert_eq!(files[0].unpacked_size, 30);
    assert_eq!(files[0].data_crc32, Some(0x83b2_7227));
    assert_eq!(files[0].attributes, 0x20);
    assert_eq!(files[0].host_os, 0);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"hello.txt");
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn writes_store_only_rar50_archive_that_reader_extracts() {
    let entries = [
        entry(b"hello5.txt", b"hello from rars rar5 writer\n")
            .with_mtime(Some(0x5a21_0000))
            .with_attributes(0x20)
            .with_host_os(3),
        entry(b"empty.bin", b"")
            .with_attributes(0x20)
            .with_host_os(3),
    ];
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    assert_eq!(&bytes[..8], b"Rar!\x1a\x07\x01\0");
    let archive = Archive::parse(&bytes).unwrap();
    assert_eq!(archive.main.archive_flags, 0);
    assert_rar50_end_header_has_flags_vint(&archive);
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|file| file.is_stored()));
    assert!(files.iter().all(|file| file.hash.is_some()));
    assert_eq!(files[0].data_crc32, Some(crc32(&entry_data(&entries[0]))));
    assert_eq!(files[1].data_crc32, Some(crc32(&entry_data(&entries[1]))));
    assert_eq!(files[0].hash.as_ref().unwrap().hash_type, 0);
    assert_eq!(files[0].hash.as_ref().unwrap().data.len(), 32);
    files[0].verify_hash(&entry_data(&entries[0])).unwrap();

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, entries[0].name);
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
    assert_eq!(extracted[0].file_time, 0x5a21_0000);
    assert_eq!(extracted[1].name, entries[1].name);
    assert_eq!(extracted[1].data, entry_data(&entries[1]));
}

#[test]
fn rar50_writer_builder_writes_stored_archive_with_comment_and_metadata() {
    let entries = [entry(
        b"builder-stored.txt",
        b"stored through the resolved writer builder\n",
    )
    .with_attributes(0x20)
    .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = rar50::Rar50Writer::new(rar50::WriterOptions::new(ArchiveVersion::Rar70, features))
        .entries(entries.to_vec())
        .archive_comment(Some(b"builder archive comment"))
        .archive_metadata(Some(ArchiveMetadataEntry {
            name: Some(b"builder-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }))
        .finish()
        .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, b"CMT");
    assert_eq!(
        collect_file(&archive, services[0]).unwrap().data,
        b"builder archive comment"
    );
    assert_eq!(
        archive.main.archive_metadata().unwrap().name.as_deref(),
        Some(b"builder-metadata.rar".as_slice())
    );
    assert_eq!(
        collect_extract(&archive).unwrap()[0].data,
        entry_data(&entries[0])
    );
}

#[test]
fn writes_compressed_rar50_archive_that_reader_extracts() {
    let entries = [
        entry(
            b"compressed.txt",
            b"hello from rars rar5 compressed writer\nhello again\n",
        )
        .with_mtime(Some(0x5a21_0001))
        .with_attributes(0x20)
        .with_host_os(3),
        entry(b"empty.bin", b"")
            .with_attributes(0x20)
            .with_host_os(3),
    ];
    let bytes = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|file| file.hash.is_some()));
    assert_eq!(files[0].data_crc32, Some(crc32(&entry_data(&entries[0]))));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, entries[0].name);
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
    assert_eq!(extracted[0].file_time, 0x5a21_0001);
    assert_eq!(extracted[1].name, entries[1].name);
    assert_eq!(extracted[1].data, entry_data(&entries[1]));
}

#[test]
fn compressed_rar50_writer_stores_member_when_lz_payload_would_grow() {
    let data = deterministic_noise(8192);
    assert!(encode_lz_member(&data, 0).unwrap().len() >= data.len());
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let entries = [entry(b"incompressible.bin", &data)
            .with_mtime(Some(0x5a21_00a0))
            .with_attributes(0x20)
            .with_host_os(3)];
        let bytes = write_compressed_archive(
            &entries,
            rar50::WriterOptions::new(target, FeatureSet::store_only()),
        )
        .unwrap();

        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();
        assert!(file.is_stored(), "{target:?}");
        assert_eq!(file.packed_size(), data.len() as u64);
        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted[0].name, b"incompressible.bin");
        assert_eq!(extracted[0].data, data);
        assert_eq!(extracted[0].file_time, 0x5a21_00a0);
    }
}

#[test]
fn compressed_rar50_writer_level_zero_stores_member() {
    let data = b"level zero stores through compressed writer\n".repeat(64);
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let entries = [entry(b"level-zero.txt", &data)
            .with_mtime(Some(0x5a21_00a2))
            .with_attributes(0x20)
            .with_host_os(3)];
        let bytes = write_compressed_archive(
            &entries,
            rar50::WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(0),
        )
        .unwrap();

        let archive = Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();
        assert!(file.is_stored(), "{target:?}");
        assert_eq!(file.packed_size(), data.len() as u64);
        assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
    }
}

#[test]
fn compressed_rar50_writer_uses_compression_level_for_match_effort() {
    let data = level_sensitive_payload();
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let entries = [entry(b"level-sensitive.bin", &data)
            .with_mtime(Some(0x5a21_00a4))
            .with_attributes(0x20)
            .with_host_os(3)];
        let low = write_compressed_archive(
            &entries,
            rar50::WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(1),
        )
        .unwrap();
        let high = write_compressed_archive(
            &entries,
            rar50::WriterOptions::new(target, FeatureSet::store_only()).with_compression_level(5),
        )
        .unwrap();

        let low_archive = Archive::parse(&low).unwrap();
        let high_archive = Archive::parse(&high).unwrap();
        let low_file = low_archive.files().next().unwrap();
        let high_file = high_archive.files().next().unwrap();
        assert!(
            high_file.packed_size() < low_file.packed_size(),
            "{target:?}"
        );
        assert_eq!(collect_extract(&low_archive).unwrap()[0].data, data);
        assert_eq!(collect_extract(&high_archive).unwrap()[0].data, data);
    }
}

#[test]
fn compressed_rar50_writer_stamps_requested_method_levels() {
    let data = level_sensitive_payload();
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for level in 1..=5 {
            let entries = [entry(b"level-method.bin", &data)
                .with_mtime(Some(0x5a21_00a4))
                .with_attributes(0x20)
                .with_host_os(3)];
            let bytes = write_compressed_archive(
                &entries,
                rar50::WriterOptions::new(target, FeatureSet::store_only())
                    .with_compression_level(level),
            )
            .unwrap();

            let archive = Archive::parse(&bytes).unwrap();
            let file = archive.files().next().unwrap();
            let info = file.decoded_compression_info().unwrap();
            assert_eq!(info.algorithm_version, 0, "{target:?} level {level}");
            assert_eq!(info.method, level, "{target:?} level {level}");
            assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
        }
    }
}

#[test]
fn rar50_writer_builder_writes_filtered_compressed_archive() {
    let payload = b"\xe8\0\0\0\0builder filtered payload\n".repeat(8);
    let entries = [entry(b"builder-filtered.bin", &payload)
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = rar50::Rar50Writer::new(rar50::WriterOptions::new(
        ArchiveVersion::Rar50,
        FeatureSet::store_only(),
    ))
    .entries(entries.to_vec())
    .filter_policy(FilterPolicy::explicit(rar50::FilterKind::E8))
    .finish()
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    assert_eq!(
        collect_extract(&archive).unwrap()[0].data,
        entry_data(&entries[0])
    );
}

#[test]
fn writes_solid_compressed_rar50_archive_that_reader_extracts() {
    let first = b"rar50 solid shared phrase alpha beta gamma\n".repeat(32);
    let second = b"rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
    let entries = [
        entry(b"solid-one.txt", &first)
            .with_mtime(Some(0x5a21_0021))
            .with_attributes(0x20)
            .with_host_os(3),
        entry(b"solid-two.txt", &second)
            .with_mtime(Some(0x5a21_0022))
            .with_attributes(0x20)
            .with_host_os(3),
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let solid = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let standalone_second = write_compressed_archive(
        std::slice::from_ref(&entries[1]),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    let archive = Archive::parse(&solid).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert!(archive.main.is_solid());
    assert!(!files[0].decoded_compression_info().unwrap().solid);
    assert!(files[1].decoded_compression_info().unwrap().solid);
    assert!(
        files[1].packed_size()
            < Archive::parse(&standalone_second)
                .unwrap()
                .files()
                .next()
                .unwrap()
                .packed_size()
    );

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
fn writes_delta_filtered_compressed_rar50_archive_that_reader_extracts() {
    let data: Vec<u8> = (0..180)
        .map(|index| (index * 5 + index / 2) as u8)
        .collect();
    let entries = [entry(b"delta-filtered.bin", &data)
        .with_mtime(Some(0x5a21_0023))
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::explicit(FilterKind::Delta { channels: 3 }),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();
    assert_eq!(file.decoded_compression_info().unwrap().method, 3);
    let packed = file.packed_data(&archive).unwrap();
    let block = parse_compressed_block(&packed).unwrap();
    let (lengths, _) = read_table_lengths(&packed[block.payload], 0).unwrap();
    assert_ne!(lengths.main[256], 0);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"delta-filtered.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_0023);
}

#[test]
fn writes_e8_filtered_compressed_rar50_archive_that_reader_extracts() {
    let data = b"\xe8\0\0\0\0rar5 e8 filtered call payload".to_vec();
    let entries = [entry(b"e8-filtered.bin", &data)
        .with_mtime(Some(0x5a21_0024))
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::explicit(FilterKind::E8),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();
    let packed = file.packed_data(&archive).unwrap();
    let block = parse_compressed_block(&packed).unwrap();
    let (lengths, _) = read_table_lengths(&packed[block.payload], 0).unwrap();
    assert_ne!(lengths.main[256], 0);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"e8-filtered.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_0024);
}

#[test]
fn writes_e8e9_filtered_compressed_rar50_archive_that_reader_extracts() {
    let data = b"\xe9\0\0\0\0rar5 e8e9 filtered jump payload".to_vec();
    let entries = [entry(b"e8e9-filtered.bin", &data)
        .with_mtime(Some(0x5a21_0025))
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::explicit(FilterKind::E8E9),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"e8e9-filtered.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_0025);
}

#[test]
fn writes_arm_filtered_compressed_rar50_archive_that_reader_extracts() {
    let data = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
    let entries = [entry(b"arm-filtered.bin", &data)
        .with_mtime(Some(0x5a21_0026))
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::explicit(FilterKind::Arm),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();
    let packed = file.packed_data(&archive).unwrap();
    let block = parse_compressed_block(&packed).unwrap();
    let (lengths, _) = read_table_lengths(&packed[block.payload], 0).unwrap();
    assert_ne!(lengths.main[256], 0);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"arm-filtered.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_0026);
}

#[test]
fn writes_auto_filtered_compressed_rar50_archive_that_reader_extracts() {
    let mut data = Vec::new();
    for _ in 0..48 {
        data.extend_from_slice(b"\xe8\0\0\0\0rar5 auto filter policy payload\n");
    }
    let entries = [entry(b"auto-filtered.bin", &data)
        .with_mtime(Some(0x5a21_0027))
        .with_attributes(0x20)
        .with_host_os(3)];
    let options = rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
    let plain = write_compressed_archive(&entries, options).unwrap();
    let auto =
        write_compressed_archive_with_filter_policy(&entries, options, FilterPolicy::Auto).unwrap();

    let plain_archive = Archive::parse(&plain).unwrap();
    let auto_archive = Archive::parse(&auto).unwrap();
    assert!(
        auto_archive.files().next().unwrap().packed_size()
            <= plain_archive.files().next().unwrap().packed_size()
    );
    let extracted = collect_extract(&auto_archive).unwrap();
    assert_eq!(extracted[0].name, b"auto-filtered.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_0027);
}

#[test]
fn auto_filtered_compressed_rar50_writer_accepts_empty_member() {
    let entries = [entry(b"afile.txt", b"")
        .with_mtime(Some(0x5a21_0028))
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::Auto,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();
    assert_eq!(file.name, b"afile.txt");
    assert!(file.is_stored());
    assert_eq!(file.unpacked_size, 0);
    assert_eq!(file.packed_size(), 0);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"afile.txt");
    assert!(extracted[0].data.is_empty());
}

#[test]
fn writes_compressed_rar50_volume_set_that_reader_reassembles() {
    let payload = b"rar5 compressed split payload from rars\n".repeat(24);
    let entry = entry(b"compressed-split.txt", &payload)
        .with_mtime(Some(0x5a21_0002))
        .with_attributes(0x20)
        .with_host_os(3);
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        32,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    assert!(parts.len() >= 2);
    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    for archive in &archives {
        assert_rar50_end_header_has_flags_vint(archive);
    }
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    let first = archives[0].files().next().unwrap();
    let last = archives.last().unwrap().files().next().unwrap();
    assert!(first.is_split_after());
    assert!(last.is_split_before());
    assert!(!last.is_split_after());
    assert_eq!(last.decoded_compression_info().unwrap().method, 3);
    assert!(last.hash.is_some());

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].name, b"compressed-split.txt");
    assert_eq!(extracted[0].data, payload);
    assert_eq!(extracted[0].file_time, 0x5a21_0002);
}

/// A fragment that is not the last one has no whole-member checksum to report,
/// so it reports the bytes it stores instead, the way WinRAR does. Both a CRC32
/// and a hash record go on every fragment: a reader takes the hash record as
/// the member's checksum type, and unrar reads that type from the first
/// fragment and compares it against the last, so a first fragment offering only
/// a CRC32 fails a member that is perfectly intact.
#[test]
fn every_rar50_volume_fragment_checksums_the_bytes_it_stores() {
    let payload = deterministic_noise(4096);
    let entry = entry(b"fragment-checksums.bin", &payload).with_mtime(Some(0x5a21_0031));
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        1024,
        None,
    )
    .unwrap();
    assert!(parts.len() >= 3);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let member_crc = crc32(&payload);
    for (index, archive) in archives.iter().enumerate() {
        let file = archive.files().next().unwrap();
        assert!(
            file.hash.is_some(),
            "volume {} has no hash record",
            index + 1
        );
        let stored = &parts[index][file.block.data_range.clone()];
        match file.is_split_after() {
            true => {
                assert_eq!(
                    file.data_crc32,
                    Some(crc32(stored)),
                    "volume {} does not checksum its own bytes",
                    index + 1
                );
                assert_ne!(file.data_crc32, Some(member_crc));
            }
            false => assert_eq!(file.data_crc32, Some(member_crc)),
        }
    }
}

/// unrar and RAR 7.12 both read a set with a damaged middle volume to the end
/// and then report one checksum error for the member, which says nothing about
/// where the damage is. The fragment checksums are enough to say, so say it.
#[test]
fn a_damaged_rar50_volume_is_reported_by_its_number() {
    // Compressible enough that the member is packed rather than stored, and
    // large enough that the packed bytes still need several volumes.
    let payload = deterministic_noise(2048).repeat(8);
    let entry = entry(b"damaged-volume.bin", &payload).with_mtime(Some(0x5a21_0032));
    let mut parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        512,
        None,
    )
    .unwrap();
    assert!(parts.len() >= 3);
    let last = Archive::parse(parts.last().unwrap()).unwrap();
    assert_eq!(
        last.files()
            .next()
            .unwrap()
            .decoded_compression_info()
            .unwrap()
            .method,
        3
    );

    let damaged = 1;
    let range = Archive::parse(&parts[damaged])
        .unwrap()
        .files()
        .next()
        .unwrap()
        .block
        .data_range
        .clone();
    parts[damaged][range.start] ^= 0xff;

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let error = collect_extract_volumes(&archives).unwrap_err();
    let mut source = &error;
    while let Error::AtEntry { source: inner, .. } | Error::AtArchiveOffset { source: inner, .. } =
        source
    {
        source = inner;
    }
    assert!(
        matches!(source, Error::InVolume { number, source }
            if *number == damaged + 1 && matches!(**source, Error::Crc32Mismatch { .. })),
        "expected volume {} to be named, got {error}",
        damaged + 1
    );
}

#[test]
fn compressed_rar50_volume_writer_stores_member_when_lz_payload_would_grow() {
    let data = deterministic_noise(8192);
    assert!(encode_lz_member(&data, 0).unwrap().len() >= data.len());
    let entry = entry(b"incompressible-split.bin", &data)
        .with_mtime(Some(0x5a21_00a2))
        .with_attributes(0x20)
        .with_host_os(3);
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        1024,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    assert!(parts.len() >= 2);
    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives
        .iter()
        .all(|archive| archive.files().next().unwrap().is_stored()));
    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"incompressible-split.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_00a2);
}

#[test]
fn writes_compressed_rar50_volume_set_with_recovery_records() {
    let payload = b"rar5 compressed recovery split payload from rars\n".repeat(24);
    let entry = entry(b"compressed-split-rr.txt", &payload)
        .with_mtime(Some(0x5a21_0002))
        .with_attributes(0x20)
        .with_host_os(3);
    let features = FeatureSet::store_only();
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        Some(8),
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    assert!(parts.len() >= 2);
    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert!(archives
        .iter()
        .all(|archive| archive.main.has_recovery_record()));
    for archive in &archives {
        let service = archive.services().next().unwrap();
        assert_eq!(service.name_lossy(), "RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 8);
        assert_rar5_inline_recovery_chunks(&service.packed_data(archive).unwrap());
    }

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"compressed-split-rr.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_solid_compressed_rar50_volume_set_that_reader_reassembles() {
    let payload = b"rar5 solid compressed split payload from rars\n".repeat(24);
    let entry = entry(b"solid-compressed-split.txt", &payload)
        .with_mtime(Some(0x5a21_0003))
        .with_attributes(0x20)
        .with_host_os(3);
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    assert!(parts.len() >= 2);
    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert!(archives.iter().all(|archive| archive.main.is_solid()));
    let first = archives[0].files().next().unwrap();
    let last = archives.last().unwrap().files().next().unwrap();
    assert!(first.is_split_after());
    assert!(last.is_split_before());
    assert!(!last.is_split_after());
    assert!(!last.decoded_compression_info().unwrap().solid);

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"solid-compressed-split.txt");
    assert_eq!(extracted[0].data, payload);
    assert_eq!(extracted[0].file_time, 0x5a21_0003);
}

#[test]
fn writes_multi_file_solid_compressed_rar50_volume_set_that_reader_reassembles() {
    let first = b"rar5 multi-file solid split shared phrase alpha beta gamma\n".repeat(20);
    let second = b"rar5 multi-file solid split shared phrase alpha beta gamma\nsecond\n".repeat(16);
    let entries = [
        entry(b"solid-split-one.txt", &first)
            .with_mtime(Some(0x5a21_0011))
            .with_attributes(0x20)
            .with_host_os(3),
        entry(b"solid-split-two.txt", &second)
            .with_mtime(Some(0x5a21_0012))
            .with_attributes(0x20)
            .with_host_os(3),
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let parts = write_volumes(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    assert!(parts.len() >= 2);
    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert!(archives.iter().all(|archive| archive.main.is_solid()));
    let files: Vec<_> = archives
        .iter()
        .flat_map(|archive| archive.files())
        .collect();
    assert!(files.iter().any(|file| file.name == b"solid-split-two.txt"
        && file.decoded_compression_info().unwrap().solid));

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"solid-split-one.txt");
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[0].file_time, 0x5a21_0011);
    assert_eq!(extracted[1].name, b"solid-split-two.txt");
    assert_eq!(extracted[1].data, second);
    assert_eq!(extracted[1].file_time, 0x5a21_0012);
}

#[test]
fn writes_rar50_archive_comment_service_record() {
    let entries = [entry(b"payload.txt", b"payload with comment service\n")
        .with_attributes(0x20)
        .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(b"RAR5 comment from rars\n"),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, b"CMT");
    assert!(services[0].is_stored());
    assert_eq!(services[0].service_data, Some(Vec::new()));
    let comment = collect_file(&archive, services[0]).unwrap();
    assert_eq!(comment.name, b"CMT");
    assert_eq!(comment.data, b"RAR5 comment from rars\n");

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, entries[0].name);
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_compressed_rar50_archive_comment_service_record() {
    let payload = b"compressed payload with archive comment\n".repeat(8);
    let entries = [entry(b"compressed-comment.txt", &payload)
        .with_attributes(0x20)
        .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_compressed_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(b"compressed RAR5 comment from rars\n"),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(service_names(&archive), ["CMT"]);
    assert_eq!(
        collect_file(&archive, services[0]).unwrap().data,
        b"compressed RAR5 comment from rars\n"
    );
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, b"compressed-comment.txt");
    assert_eq!(extracted[0].data, payload);
}

/// What `supports` promises for the quick-open index is what each writer does
/// with it, for every shape RAR 5 has.
///
/// The capability conformance test in `write_plan.rs` proves the table and
/// `validate_plan` agree, which is not the same as proving the writer agrees
/// with either. Quick open was said in two places, `FeatureSet::quick_open` and
/// an `ArchiveExtras` field, and validation only ever read the first: an archive
/// asking through the feature set passed validation and then had its index
/// dropped, and a volume set asking through the extras got past validation
/// entirely and was dropped too. Both looked like success.
///
/// So this asks each writer for the index and goes looking for the block,
/// rather than asking the table what it thinks.
#[test]
fn every_rar50_writer_agrees_with_the_table_about_quick_open() {
    fn wrote_the_index(bytes: &[u8]) -> bool {
        let archive = Archive::parse(bytes).unwrap();
        let located = archive
            .main
            .locator()
            .and_then(|locator| locator.quick_open_offset)
            .is_some_and(|offset| offset > 0);
        let stored = archive.services().any(|service| service.name == b"QO");
        assert_eq!(
            located, stored,
            "a locator pointing at no QO record, or a QO record nothing points at"
        );
        located
    }

    let mut features = FeatureSet::store_only();
    features.quick_open = true;
    let options = rar50::WriterOptions::new(ArchiveVersion::Rar50, features);
    let entries = [entry(b"qo.txt", b"quick-open conformance payload\n")
        .with_attributes(0x20)
        .with_host_os(3)];

    let one_archive = rars::PlanShape::new().compressed(true);
    assert!(rars::supports(
        ArchiveVersion::Rar50,
        rars::WriterOption::Feature(rars::Feature::QuickOpen),
        one_archive,
    ));
    let bytes = write_stored_archive(&entries, options).unwrap();
    assert!(wrote_the_index(&bytes), "the buffered writer dropped it");

    let mut streamed = Vec::new();
    rar50::write_streaming_archive_to(
        &entries,
        stored(options),
        rar50::ArchiveExtras::default(),
        &rars::WriterResources::default(),
        &mut streamed,
    )
    .unwrap();
    assert!(
        wrote_the_index(&streamed),
        "the streaming writer accepted the feature and wrote no index"
    );

    let volumes = rars::PlanShape::new().compressed(true).volumes(true);
    assert!(!rars::supports(
        ArchiveVersion::Rar50,
        rars::WriterOption::Feature(rars::Feature::QuickOpen),
        volumes,
    ));
    let mut sink = rar50::CollectedVolumes::new();
    let refused = rar50::write_streaming_volumes_to(
        &entries,
        stored(options),
        rar50::ArchiveExtras::default(),
        4096,
        &mut sink,
        &rars::WriterResources::default(),
    )
    .unwrap_err();
    assert!(
        refused.to_string().contains("quick-open"),
        "a volume set has to say which option it cannot carry: {refused}"
    );
}

#[test]
fn writes_rar50_quick_open_service_record() {
    let entries = [
        entry(b"first.txt", b"first quick-open payload\n")
            .with_attributes(0x20)
            .with_host_os(3),
        entry(b"second.txt", b"second quick-open payload\n")
            .with_attributes(0x20)
            .with_host_os(3),
    ];
    let mut features = FeatureSet::store_only();
    features.quick_open = true;
    let bytes = write_stored_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(b"QO comment from rars\n"),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let locator = archive.main.locator().unwrap();
    assert!(locator.quick_open_offset.unwrap() > 0);
    assert_eq!(service_names(&archive), ["CMT", "QO"]);
    let quick_open = archive
        .services()
        .find(|service| service.name == b"QO")
        .unwrap();
    assert!(quick_open.is_stored());
    let quick_open = collect_file(&archive, quick_open).unwrap();
    assert_eq!(count_verified_quick_open_wrappers(&quick_open.data), 3);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
    assert_eq!(extracted[1].data, entry_data(&entries[1]));
}

#[test]
fn writes_rar50_acl_and_stream_file_service_records() {
    let entries = [entry(b"serviced.txt", b"payload with attached services\n")
        .with_attributes(0x20)
        .with_host_os(3)
        .with_service(ServiceEntry::new(
            b"ACL".to_vec(),
            b"opaque acl descriptor".to_vec(),
        ))
        .with_service(ServiceEntry::new(
            b"STM".to_vec(),
            b"named stream bytes".to_vec(),
        ))];
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(service_names(&archive), ["ACL", "STM"]);
    assert!(services.iter().all(|service| service.is_stored()));
    assert_eq!(
        collect_file(&archive, services[0]).unwrap().data,
        b"opaque acl descriptor"
    );
    assert_eq!(
        collect_file(&archive, services[1]).unwrap().data,
        b"named stream bytes"
    );

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"serviced.txt");
    assert_eq!(extracted[0].data, b"payload with attached services\n");
}

#[test]
fn writes_rar50_file_comment_service_record() {
    let entries = [entry(
        b"file-commented.txt",
        b"payload with attached file comment\n",
    )
    .with_attributes(0x20)
    .with_host_os(3)
    .with_service(ServiceEntry::new(
        b"CMT".to_vec(),
        b"RAR5 file comment from rars\n".to_vec(),
    ))];
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(service_names(&archive), ["CMT"]);
    assert!(services[0].is_stored());
    assert_eq!(
        collect_file(&archive, services[0]).unwrap().data,
        b"RAR5 file comment from rars\n"
    );

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"file-commented.txt");
    assert_eq!(extracted[0].data, b"payload with attached file comment\n");
}

/// When a file header carries both a `Data CRC32` and a BLAKE2sp record, the
/// hash is the authoritative check and the CRC32 is not evaluated beside it.
///
/// Measured on RAR 7.12 and UnRAR 7.20: the fixture's CRC32 is wrong by one bit
/// while its BLAKE2sp is correct, and both readers test it clean. Corrupt the
/// digest instead and both reject it, which is what the second half pins.
#[test]
fn rar50_blake2sp_supersedes_a_wrong_crc32() {
    let data = fs::read(fixture("crc32_wrong_beside_blake2sp.rar")).unwrap();
    let archive = Archive::parse(&data).unwrap();

    let file = archive.files().next().unwrap();
    assert_eq!(file.data_crc32, Some(0x83b2_7226));
    assert!(file.hash.is_some());

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");

    // The digest still has to be right. Flip a byte of it and the archive must
    // fail, otherwise the fix would have turned off checking altogether.
    const HEAD_CRC: usize = 0x17;
    const HEAD_SIZE: usize = 0x1b;
    const BODY: usize = 0x1c;
    const DIGEST: usize = 0x39;

    let mut corrupted = data.clone();
    corrupted[DIGEST] ^= 0xff;
    let header_end = BODY + corrupted[HEAD_SIZE] as usize;
    let header_crc = crc32(&corrupted[HEAD_SIZE..header_end]);
    corrupted[HEAD_CRC..HEAD_CRC + 4].copy_from_slice(&header_crc.to_le_bytes());
    let archive = Archive::parse(&corrupted).unwrap();
    assert!(matches!(
        collect_extract(&archive),
        Err(Error::AtEntry { source, .. }) if matches!(*source, Error::HashMismatch { .. })
    ));
}

/// Reference builds keep 127 characters of the password and drop the rest, so
/// rars has to as well: measured against RAR 7.12, an archive rars wrote with a
/// 128-character password could not be opened with that password or with any
/// prefix of it, and rars could not open WinRAR's when handed the same long one.
///
/// The archive here is written with a 200-character password and opened with
/// its first 127 characters. Both must derive the same key, and 126 must not.
#[test]
fn rar50_password_is_clamped_to_127_characters() {
    let long = "A".repeat(197) + "ZZZ";
    let kept = &long[..127];
    let short = &long[..126];

    let entries = [entry(b"secret.txt", b"clamped password payload\n")
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(long.as_bytes().to_vec())];
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    for password in [long.as_str(), kept] {
        let archive = Archive::parse_with_password(&bytes, Some(password.as_bytes())).unwrap();
        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted[0].data, b"clamped password payload\n");
    }

    assert!(
        Archive::parse_with_password(&bytes, Some(short.as_bytes())).is_err(),
        "126 characters must not open an archive written with 127 or more"
    );
}

#[test]
fn writes_encrypted_rar50_file_comment_service_record() {
    let entries = [entry(
        b"encrypted-file-commented.txt",
        b"encrypted payload with attached file comment\n",
    )
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"secret".to_vec())
    .with_service(
        ServiceEntry::new(
            b"CMT".to_vec(),
            b"encrypted RAR5 file comment from rars\n".to_vec(),
        )
        .with_password(b"secret".to_vec()),
    )];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(service_names(&archive), ["CMT"]);
    assert!(services[0].encrypted);
    assert!(matches!(
        collect_file(&archive, services[0]),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"CMT" && matches!(*source, Error::NeedPassword)
    ));

    let archive = Archive::parse_with_password(&bytes, Some(b"secret")).unwrap();
    let service = collect_file(&archive, archive.services().next().unwrap()).unwrap();
    assert_eq!(service.data, b"encrypted RAR5 file comment from rars\n");
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"encrypted-file-commented.txt");
    assert_eq!(
        extracted[0].data,
        b"encrypted payload with attached file comment\n"
    );
}

#[test]
fn writes_header_encrypted_rar50_file_comment_service_record() {
    let entries = [entry(
        b"header-encrypted-file-commented.txt",
        b"header encrypted payload with attached file comment\n",
    )
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"secret".to_vec())
    .with_service(
        ServiceEntry::new(
            b"CMT".to_vec(),
            b"header encrypted RAR5 file comment from rars\n".to_vec(),
        )
        .with_password(b"secret".to_vec()),
    )];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    // The HEAD_CRYPT block is in the clear and carries its own KDF count,
    // which has to be the same 2^15 as the per-file records below.
    assert_eq!(head_crypt_kdf_count(&bytes), 15);
    let archive = Archive::parse_with_password(&bytes, Some(b"secret")).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(service_names(&archive), ["CMT"]);
    assert!(services[0].encrypted);
    assert_eq!(
        collect_file(&archive, services[0]).unwrap().data,
        b"header encrypted RAR5 file comment from rars\n"
    );
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(
        extracted[0].data,
        b"header encrypted payload with attached file comment\n"
    );
}

#[test]
#[ignore = "requires local rar command; used by scripts/reference-rar5-writer.sh"]
fn reference_rar_accepts_rar50_acl_and_stream_file_service_records() {
    let entries = [entry(b"serviced.txt", b"payload with attached services\n")
        .with_attributes(0x20)
        .with_host_os(3)
        .with_service(ServiceEntry::new(
            b"ACL".to_vec(),
            b"opaque acl descriptor".to_vec(),
        ))
        .with_service(ServiceEntry::new(
            b"STM".to_vec(),
            b"named stream bytes".to_vec(),
        ))];
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    let dir = scratch::case("rars-rar50-file-services");
    let path = dir.join("archive.rar");
    fs::write(&path, bytes).unwrap();
    let output = match Command::new("rar").arg("t").arg(&path).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping reference test: local `rar` command is not installed");
            return;
        }
        Err(error) => panic!("failed to run rar: {error}"),
    };
    if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_some() {
        eprintln!("kept reference archive: {}", path.display());
        std::mem::forget(dir);
    }

    assert!(
        output.status.success(),
        "rar rejected RAR5 ACL/STM service output\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires RARS_RAR50_LARGE_STREAM_FIXTURE pointing at an external >512 MiB sparse unfiltered RAR5 fixture"]
fn external_sparse_rar50_large_member_streams_to_sink() {
    let Some(path) = std::env::var_os("RARS_RAR50_LARGE_STREAM_FIXTURE") else {
        eprintln!(
            "skipping reference test: set RARS_RAR50_LARGE_STREAM_FIXTURE to an external sparse RAR5 fixture"
        );
        return;
    };
    let archive = Archive::parse_path(path).unwrap();
    let largest = archive
        .files()
        .map(|file| file.unpacked_size)
        .max()
        .unwrap_or(0);
    assert!(
        largest > 512 * 1024 * 1024,
        "fixture must contain a member larger than the filtered-buffer fallback"
    );

    archive
        .extract_to(read_options(None), |_meta| Ok(Box::new(std::io::sink())))
        .unwrap();
}

#[test]
fn writes_rar50_recovery_service_record() {
    let entries = [entry(
        b"recoverable.txt",
        b"payload with structural recovery service\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        7,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.main.has_recovery_record());
    let locator = archive.main.locator().unwrap();
    let recovery_offset = locator.recovery_record_offset.unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(service_names(&archive), ["RR"]);
    assert_eq!(
        recovery_offset,
        (services[0].block.offset - b"Rar!\x1a\x07\x01\x00".len()) as u64
    );
    let recovery = services[0].recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 7);
    assert_eq!(recovery.payload_size, services[0].packed_size());
    let recovery_data = services[0].packed_data(&archive).unwrap();
    assert!(recovery_data.starts_with(b"{RB}"));
    assert_eq!(
        u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
        recovery_data.len()
    );
    assert_eq!(
        u32::from_le_bytes(recovery_data[0x10..0x14].try_into().unwrap()) as usize,
        0x48 + 8
    );
    assert_eq!(recovery_data[0x14], 1);
    assert_eq!(recovery_data[0x15], 1);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"recoverable.txt");
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn repairs_rar50_inline_recovery_payload_damage() {
    let payload = b"payload with structural recovery service\n".repeat(64);
    let entries = [entry(b"recoverable.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let data_range = clean.files().next().unwrap().block.data_range.clone();
    let mut damaged = bytes.clone();
    damaged[data_range.start + 10..data_range.start + 80].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let mut repaired = Vec::new();
    damaged_archive.repair_recovery_to(&mut repaired).unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = Archive::parse(&repaired).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn repairs_rar50_inline_recovery_header_damage_without_parsing() {
    let payload = b"payload protected by raw inline recovery fallback\n".repeat(64);
    let entries = [entry(b"header-damaged.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let file_header_offset = clean.files().next().unwrap().block.offset;
    let mut damaged = bytes.clone();
    damaged[file_header_offset] ^= 0xff;

    assert!(Archive::parse(&damaged).is_err());

    let repaired = repair_inline_recovery_bytes(&damaged).unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = Archive::parse(&repaired).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn rejects_rar50_inline_recovery_service_header_damage_without_prefix_damage() {
    let payload = b"payload with only the recovery service header damaged\n".repeat(64);
    let entries = [entry(b"rr-header-damaged.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let service_offset = clean.services().next().unwrap().block.offset;
    let mut damaged = bytes.clone();
    damaged[service_offset] ^= 0xff;

    assert!(Archive::parse(&damaged).is_err());
    assert!(repair_inline_recovery_bytes(&damaged).is_err());
}

#[test]
fn repairs_rar50_inline_recovery_with_damaged_recovery_chunk() {
    let payload = b"payload with a damaged recovery shard still recoverable\n".repeat(512);
    let entries = [entry(b"recoverable-with-bad-rr.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let clean = Archive::parse(&bytes).unwrap();
    let data_range = clean.files().next().unwrap().block.data_range.clone();
    let recovery_range = clean.services().next().unwrap().block.data_range.clone();
    let mut damaged = bytes.clone();
    damaged[data_range.start + 10..data_range.start + 80].fill(0xa5);
    damaged[recovery_range.start + 0x48] ^= 0xff;

    let damaged_archive = Archive::parse(&damaged).unwrap();
    assert!(collect_extract(&damaged_archive).is_err());

    let repaired = damaged_archive.repair_recovery_with_report(None).unwrap();

    assert!(repaired.report.data_repaired);
    assert!(repaired.report.recovery_record_rebuilt);
    assert_eq!(
        repaired.report.available_recovery_shards,
        repaired
            .report
            .expected_recovery_shards
            .map(|count| count - 1)
    );
    assert_eq!(repaired.data, bytes);
    let repaired_archive = Archive::parse(&repaired.data).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn rebuilds_damaged_recovery_chunk_without_claiming_data_repair() {
    let payload = b"healthy data with one damaged recovery row\n".repeat(1024);
    let entries = [entry(b"healthy-data.txt", &payload)];
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        20,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let recovery_range = archive.services().next().unwrap().block.data_range.clone();
    let mut damaged = bytes.clone();
    damaged[recovery_range.start + 0x48] ^= 0xff;

    let result = Archive::parse(&damaged)
        .unwrap()
        .repair_recovery_with_report(None)
        .unwrap();

    assert!(!result.report.data_repaired);
    assert!(result.report.recovery_record_rebuilt);
    assert!(result.report.changed);
    assert_eq!(result.data, bytes);
}

#[test]
fn rebuilds_truncated_rar50_inline_recovery_tail() {
    let payload = b"payload protected when the recovery tail is truncated\n".repeat(4096);
    let entries = [entry(b"truncated-recovery.txt", &payload)];
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        20,
    )
    .unwrap();
    let mut damaged = bytes.clone();
    damaged.truncate(damaged.len() - 4096);

    assert!(Archive::parse(&damaged).is_err());
    let repaired = repair_inline_recovery_bytes(&damaged).unwrap();

    assert_eq!(repaired, bytes);
    let archive = Archive::parse(&repaired).unwrap();
    assert_eq!(collect_extract(&archive).unwrap()[0].data, payload);
}

#[test]
fn rebuilds_a_damaged_chunk_in_an_archive_storing_a_recovery_archive() {
    // The stored inner archive carries its own {RB} chunks, which sit earlier
    // in the file than the outer record's.
    let inner = write_stored_archive_with_recovery(
        &[entry(
            b"inner-payload.txt",
            &b"nested archive payload\n".repeat(2048),
        )],
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        20,
    )
    .unwrap();
    let bytes = write_stored_archive_with_recovery(
        &[entry(b"inner.rar", &inner)],
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        20,
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let recovery_range = archive.services().next().unwrap().block.data_range.clone();
    let mut damaged = bytes.clone();
    damaged[recovery_range.start + 0x48] ^= 0xff;

    let repaired = Archive::parse(&damaged)
        .unwrap()
        .repair_recovery_with_report(None)
        .unwrap();

    assert!(repaired.report.recovery_record_rebuilt);
    assert_eq!(repaired.data, bytes);
}

#[test]
fn rebuilds_a_header_encrypted_archive_end_from_a_parsed_archive() {
    // Framing a replacement end-of-archive header for a header-encrypted
    // archive needs the key, so the repair has to be given the password even
    // though the archive itself parsed.
    let payload = b"header encrypted, damaged row, missing tail\n".repeat(2048);
    let entries = [entry(b"secret-recovery.txt", &payload).with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let recovery_range = archive.services().next().unwrap().block.data_range.clone();
    let mut damaged = bytes.clone();
    damaged.truncate(recovery_range.end);
    damaged[recovery_range.start + 0x48] ^= 0xff;

    let repaired = Archive::parse_with_password(&damaged, Some(b"password"))
        .unwrap()
        .repair_recovery_with_report(Some(b"password"))
        .unwrap();

    assert!(repaired.report.recovery_record_rebuilt);
    assert!(repaired.report.end_record_rebuilt);
    // Everything up to the end of the record comes back byte for byte. The
    // replacement end header cannot, since each encrypted block is framed with
    // a fresh initialisation vector.
    assert_eq!(
        repaired.data[..recovery_range.end],
        bytes[..recovery_range.end]
    );
    let archive = Archive::parse_with_password(&repaired.data, Some(b"password")).unwrap();
    assert_eq!(
        collect_extract_with_password(&archive, Some(b"password")).unwrap()[0].data,
        payload
    );
}

#[test]
fn rebuilds_truncated_header_encrypted_rar50_recovery_tail() {
    let payload = b"encrypted headers with a truncated recovery tail\n".repeat(4096);
    let entries =
        [entry(b"secret-truncated-recovery.txt", &payload).with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let mut damaged = bytes.clone();
    damaged.truncate(damaged.len() - 4096);

    let repaired = rars::rar50::repair_inline_recovery_bytes_with_options(
        &damaged,
        rars::ArchiveReadOptions::with_password(b"password"),
    )
    .unwrap();

    assert!(repaired.report.recovery_record_rebuilt);
    assert!(repaired.report.end_record_rebuilt);
    let archive = Archive::parse_with_password(&repaired.data, Some(b"password")).unwrap();
    assert_eq!(
        collect_extract_with_password(&archive, Some(b"password")).unwrap()[0].data,
        payload
    );
}

#[test]
fn repairs_encrypted_rar50_inline_recovery_payload_damage_with_password() {
    let payload = b"encrypted payload with structural recovery service\n".repeat(64);
    let entries = [entry(b"secret-recoverable.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let clean = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let data_range = clean.files().next().unwrap().block.data_range.clone();
    let mut damaged = bytes.clone();
    damaged[data_range.start + 16..data_range.start + 96].fill(0xa5);

    let damaged_archive = Archive::parse_with_password(&damaged, Some(b"password")).unwrap();
    assert!(collect_extract_with_password(&damaged_archive, Some(b"password")).is_err());

    let repaired = damaged_archive.repair_recovery().unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = Archive::parse_with_password(&repaired, Some(b"password")).unwrap();
    let extracted = collect_extract_with_password(&repaired_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn repairs_header_encrypted_rar50_inline_recovery_payload_damage_with_password() {
    let payload = b"header encrypted payload with structural recovery service\n".repeat(64);
    let entries = [entry(b"header-secret-recoverable.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
    )
    .unwrap();
    let clean = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let data_range = clean.files().next().unwrap().block.data_range.clone();
    let mut damaged = bytes.clone();
    damaged[data_range.start + 16..data_range.start + 96].fill(0xa5);

    assert!(matches!(Archive::parse(&damaged), Err(Error::NeedPassword)));
    let damaged_archive = Archive::parse_with_password(&damaged, Some(b"password")).unwrap();
    assert!(collect_extract_with_password(&damaged_archive, Some(b"password")).is_err());

    let repaired = damaged_archive.repair_recovery().unwrap();

    assert_eq!(repaired, bytes);
    let repaired_archive = Archive::parse_with_password(&repaired, Some(b"password")).unwrap();
    let extracted = collect_extract_with_password(&repaired_archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_compressed_rar50_recovery_service_record() {
    let payload = b"compressed recovery payload with repeated phrase. ".repeat(32);
    let entries = [entry(b"compressed-recoverable.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)];
    let features = FeatureSet::store_only();
    let bytes = write_compressed_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        7,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.main.has_recovery_record());
    let locator = archive.main.locator().unwrap();
    let recovery_offset = locator.recovery_record_offset.unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(service_names(&archive), ["RR"]);
    assert_eq!(
        recovery_offset,
        (services[0].block.offset - b"Rar!\x1a\x07\x01\x00".len()) as u64
    );
    let recovery = services[0].recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 7);
    let recovery_data = services[0].packed_data(&archive).unwrap();
    assert!(recovery_data.starts_with(b"{RB}"));
    assert_eq!(
        u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
        recovery_data.len()
    );

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"compressed-recoverable.txt");
    assert_eq!(extracted[0].data, payload);
}

/// A recovery record used to be asked for twice: once as a feature flag and
/// once as a percentage, and the writer had to reject the case where the two
/// disagreed. Only the percentage is asked for now, so they cannot.
#[test]
fn a_recovery_record_is_asked_for_by_percentage_alone() {
    let entries = [entry(b"payload.txt", b"payload without recovery writer\n")
        .with_attributes(0x20)
        .with_host_os(3)];
    let options = rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
    let without = write_stored_archive(&entries, options).unwrap();
    let with = rar50::Rar50Writer::new(options)
        .entries(entries.to_vec())
        .recovery_percent(Some(5))
        .finish()
        .unwrap();
    assert!(
        with.len() > without.len(),
        "the percentage alone decides whether a recovery record is written"
    );

    // And a format with no recovery record at all says which one to use.
    assert!(!rars::supports(
        ArchiveVersion::Rar29,
        rars::WriterOption::RecoveryRecord,
        rars::PlanShape::new(),
    ));
}

#[test]
fn writes_stored_rar50_volume_set_that_reader_reassembles() {
    let payload = b"RAR5 stored volume payload split across generated parts.\n".repeat(12);
    let entry = entry(b"split50.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3);
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(
            ArchiveVersion::Rar50,
            FeatureSet::store_only(),
        )),
        97,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);
    assert!(parts.len() > 2);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert_eq!(archives[0].main.volume_number, Some(0));
    assert_eq!(archives[1].main.volume_number, Some(1));
    assert!(archives[0].files().next().unwrap().is_split_after());
    // A fragment that is not the last one checksums the bytes it stores rather
    // than the member, which it has no way to checksum yet.
    assert_eq!(
        archives[0].files().next().unwrap().data_crc32,
        Some(crc32(
            &parts[0][archives[0].files().next().unwrap().block.data_range.clone()]
        ))
    );
    assert!(archives[1].files().next().unwrap().is_split_before());
    assert!(!archives
        .last()
        .unwrap()
        .files()
        .next()
        .unwrap()
        .is_split_after());

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"split50.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_stored_rar50_volume_set_with_recovery_records() {
    let payload = b"RAR5 stored recovery volume payload split across generated parts.\n".repeat(12);
    let entry = entry(b"split50-rr.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3);
    let features = FeatureSet::store_only();
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(ArchiveVersion::Rar50, features)),
        97,
        Some(8),
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);
    assert!(parts.len() > 2);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    for archive in &archives {
        assert!(archive.main.has_recovery_record());
        let service = archive.services().next().unwrap();
        assert_eq!(service.name_lossy(), "RR");
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 8);
        let locator = archive.main.locator().unwrap();
        assert_eq!(
            locator.recovery_record_offset,
            Some((service.block.offset - b"Rar!\x1a\x07\x01\x00".len()) as u64)
        );
        assert_rar5_inline_recovery_chunks(&service.packed_data(archive).unwrap());
    }

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"split50-rr.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_rar50_archive_metadata_main_extra_record() {
    let entries = [entry(b"payload.txt", b"payload with archive metadata\n")
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = write_stored_archive_with_comment_and_metadata(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar70, FeatureSet::store_only()),
        None,
        Some(ArchiveMetadataEntry {
            name: Some(b"metadata-name.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let locator = archive.main.locator().unwrap();
    assert_eq!(locator.flags, 0x0001);
    assert_eq!(locator.quick_open_offset, Some(0));
    let metadata = archive.main.archive_metadata().unwrap();
    assert_eq!(metadata.flags, 0x0003);
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"metadata-name.rar".as_slice())
    );
    assert_eq!(metadata.creation_time, Some(0x01dcd60e_662d7a32));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_compressed_rar50_archive_metadata_main_extra_record() {
    let payload = b"compressed payload with archive metadata\n".repeat(8);
    let entries = [entry(b"compressed-metadata.txt", &payload)
        .with_attributes(0x20)
        .with_host_os(3)];
    let bytes = write_compressed_archive_with_metadata(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar70, FeatureSet::store_only()),
        Some(ArchiveMetadataEntry {
            name: Some(b"compressed-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let metadata = archive.main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"compressed-metadata.rar".as_slice())
    );
    assert_eq!(metadata.creation_time, Some(0x01dcd60e_662d7a32));
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_stored_rar50_archive_that_reader_extracts_with_password() {
    let entries = [
        entry(b"secret.txt", b"encrypted stored RAR5 payload from rars\n")
            .with_mtime(Some(0x5a21_0000))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec()),
    ];
    let features = FeatureSet::store_only();
    let first = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    assert_ne!(first, second);
    let archive = Archive::parse(&first).unwrap();
    let second_archive = Archive::parse(&second).unwrap();
    let file = archive.files().next().unwrap();
    let second_file = second_archive.files().next().unwrap();
    assert!(file.encrypted);
    let encryption = file.encryption.as_ref().unwrap();
    let second_encryption = second_file.encryption.as_ref().unwrap();
    assert!(encryption.check_value.is_some());
    // 2^15 PBKDF2 iterations, the count WinRAR writes. Anything smaller is a
    // free speedup for an offline password guess against our archives.
    assert_eq!(encryption.kdf_count, 15);
    assert_ne!(encryption.salt, second_encryption.salt);
    assert_ne!(encryption.iv, second_encryption.iv);
    assert_eq!(file.packed_size() % 16, 0);
    assert!(matches!(
        collect_extract(&archive),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"secret.txt" && matches!(*source, Error::NeedPassword)
    ));
    assert!(matches!(
        collect_extract_with_password(&archive, Some(b"wrong")),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"secret.txt" && matches!(*source, Error::WrongPasswordOrCorruptData)
    ));

    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"secret.txt");
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
    assert!(matches!(
        file.verify_crc32(&extracted[0].data),
        Err(Error::InvalidHeader(
            "RAR 5 encrypted CRC32 verification needs encryption keys"
        ))
    ));
    assert!(matches!(
        file.verify_integrity(&extracted[0].data),
        Err(Error::InvalidHeader(
            "RAR 5 encrypted CRC32 verification needs encryption keys"
        ))
    ));
    assert!(matches!(
        file.verify_hash(&extracted[0].data),
        Err(Error::InvalidHeader(
            "RAR 5 encrypted hash verification needs encryption keys"
        ))
    ));
}

#[test]
fn writes_encrypted_stored_rar50_archive_metadata_record() {
    let entries = [entry(
        b"metadata-secret.txt",
        b"encrypted stored payload with archive metadata\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"password".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_encrypted_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar70, features),
        None,
        Some(ArchiveMetadataEntry {
            name: Some(b"encrypted-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let metadata = archive.main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"encrypted-metadata.rar".as_slice())
    );
    assert_eq!(metadata.creation_time, Some(0x01dcd60e_662d7a32));
    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_encrypted_compressed_rar50_archive_that_reader_extracts_with_password() {
    let entries = [entry(b"secret-compressed.txt", b"encrypted compressed RAR5 payload from rars\nencrypted compressed RAR5 payload from rars\n").with_mtime(Some(0x5a21_0055)).with_attributes(0x20).with_host_os(3).with_password(b"secret".to_vec())];
    let features = FeatureSet::store_only();
    let first = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    let archive = Archive::parse(&first).unwrap();
    let second_archive = Archive::parse(&second).unwrap();
    let file = archive.files().next().unwrap();
    let second_file = second_archive.files().next().unwrap();
    assert!(file.encrypted);
    assert_eq!(file.decoded_compression_info().unwrap().method, 3);
    let encryption = file.encryption.as_ref().unwrap();
    let second_encryption = second_file.encryption.as_ref().unwrap();
    assert_ne!(encryption.salt, second_encryption.salt);
    assert_ne!(encryption.iv, second_encryption.iv);
    assert_eq!(file.packed_size() % 16, 0);

    assert!(matches!(
        collect_extract_with_password(&archive, Some(b"wrong")),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"secret-compressed.txt"
            && matches!(*source, Error::WrongPasswordOrCorruptData)
    ));
    let extracted = collect_extract_with_password(&archive, Some(b"secret")).unwrap();
    assert_eq!(extracted[0].name, b"secret-compressed.txt");
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
    assert_eq!(extracted[0].file_time, 0x5a21_0055);
}

#[test]
fn encrypted_compressed_rar50_writer_stores_member_when_lz_payload_would_grow() {
    let data = deterministic_noise(8192);
    assert!(encode_lz_member(&data, 0).unwrap().len() >= data.len());
    let entries = [entry(b"secret-incompressible.bin", &data)
        .with_mtime(Some(0x5a21_00a1))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"secret".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();
    assert!(file.encrypted);
    assert!(file.is_stored());
    let extracted = collect_extract_with_password(&archive, Some(b"secret")).unwrap();
    assert_eq!(extracted[0].name, b"secret-incompressible.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_00a1);
}

#[test]
fn writes_encrypted_compressed_rar50_archive_metadata_record() {
    let payload = b"encrypted compressed metadata payload repeated repeated\n".repeat(8);
    let entries = [entry(b"secret-compressed-metadata.txt", &payload)
        .with_mtime(Some(0x5a21_0055))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"secret".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_compressed_archive_with_metadata(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar70, features),
        Some(ArchiveMetadataEntry {
            name: Some(b"encrypted-compressed-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let metadata = archive.main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"encrypted-compressed-metadata.rar".as_slice())
    );
    let extracted = collect_extract_with_password(&archive, Some(b"secret")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_solid_compressed_rar50_archive_that_reader_extracts_with_password() {
    let first = b"encrypted rar50 solid shared phrase alpha beta gamma\n".repeat(16);
    let second = b"encrypted rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
    let entries = [
        entry(b"encrypted-solid-one.txt", &first)
            .with_mtime(Some(0x5a21_0061))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"secret".to_vec()),
        entry(b"encrypted-solid-two.txt", &second)
            .with_mtime(Some(0x5a21_0062))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"secret".to_vec()),
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let bytes = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert!(archive.main.is_solid());
    assert!(files.iter().all(|file| file.encrypted));
    assert!(!files[0].decoded_compression_info().unwrap().solid);
    assert!(files[1].decoded_compression_info().unwrap().solid);
    let extracted = collect_extract_with_password(&archive, Some(b"secret")).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
fn writes_encrypted_rar50_archive_comment_service_that_reader_extracts_with_password() {
    let entries = [entry(
        b"secret.txt",
        b"encrypted stored payload with encrypted comment\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"password".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_encrypted_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some((b"encrypted CMT from rars\n", b"password")),
        None,
    )
    .unwrap();
    let second = write_encrypted_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some((b"encrypted CMT from rars\n", b"password")),
        None,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let second_archive = Archive::parse(&second).unwrap();
    let services: Vec<_> = archive.services().collect();
    let second_services: Vec<_> = second_archive.services().collect();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, b"CMT");
    assert!(services[0].encrypted);
    let service_encryption = services[0].encryption.as_ref().unwrap();
    let second_service_encryption = second_services[0].encryption.as_ref().unwrap();
    assert_ne!(service_encryption.salt, second_service_encryption.salt);
    assert_ne!(service_encryption.iv, second_service_encryption.iv);
    assert!(matches!(
        collect_file(&archive, services[0]),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"CMT" && matches!(*source, Error::NeedPassword)
    ));

    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let comment = collect_file(&archive, archive.services().next().unwrap()).unwrap();
    assert_eq!(comment.data, b"encrypted CMT from rars\n");
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_encrypted_compressed_rar50_archive_comment_service_with_password() {
    let payload = b"encrypted compressed payload with encrypted comment\n".repeat(8);
    let entries = [entry(b"encrypted-compressed-comment.txt", &payload)
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"secret".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_encrypted_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some((b"encrypted compressed CMT from rars\n", b"secret")),
        None,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, b"CMT");
    assert!(services[0].encrypted);
    assert!(matches!(
        collect_file(&archive, services[0]),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"CMT" && matches!(*source, Error::NeedPassword)
    ));

    let archive = Archive::parse_with_password(&bytes, Some(b"secret")).unwrap();
    let comment = collect_file(&archive, archive.services().next().unwrap()).unwrap();
    assert_eq!(comment.data, b"encrypted compressed CMT from rars\n");
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_rar50_recovery_service_that_reader_extracts_with_password() {
    let entries = [entry(
        b"secret-recovery.txt",
        b"encrypted stored payload with encrypted recovery\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"password".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        6,
    )
    .unwrap();
    let second = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        6,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let second_archive = Archive::parse(&second).unwrap();
    assert!(archive.main.has_recovery_record());
    let file_encryption = archive.files().next().unwrap().encryption.as_ref().unwrap();
    let second_file_encryption = second_archive
        .files()
        .next()
        .unwrap()
        .encryption
        .as_ref()
        .unwrap();
    assert_ne!(file_encryption.salt, second_file_encryption.salt);
    assert_ne!(file_encryption.iv, second_file_encryption.iv);
    let service = archive.services().next().unwrap();
    assert_eq!(service.name, b"RR");
    assert!(!service.encrypted);
    let recovery = service.recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 6);

    let recovery_data = collect_file(&archive, service).unwrap().data;
    assert!(recovery_data.starts_with(b"{RB}"));
    assert_eq!(
        u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
        recovery_data.len()
    );
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_encrypted_compressed_rar50_recovery_service_that_reader_extracts_with_password() {
    let payload = b"encrypted compressed recovery payload repeated repeated. ".repeat(24);
    let entries = [entry(b"secret-compressed-recovery.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())];
    let features = FeatureSet::store_only();
    let bytes = write_compressed_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        6,
    )
    .unwrap();
    let second = write_compressed_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        6,
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let second_archive = Archive::parse(&second).unwrap();
    assert!(archive.main.has_recovery_record());
    let file_encryption = archive.files().next().unwrap().encryption.as_ref().unwrap();
    let second_file_encryption = second_archive
        .files()
        .next()
        .unwrap()
        .encryption
        .as_ref()
        .unwrap();
    assert_ne!(file_encryption.salt, second_file_encryption.salt);
    assert_ne!(file_encryption.iv, second_file_encryption.iv);
    let service = archive.services().next().unwrap();
    assert_eq!(service.name, b"RR");
    assert!(!service.encrypted);
    assert_eq!(service.recovery_record().unwrap().unwrap().percent, 6);
    let recovery_data = collect_file(&archive, service).unwrap().data;
    assert!(recovery_data.starts_with(b"{RB}"));

    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_header_encrypted_rar50_archive_that_reader_extracts_with_password() {
    let entries = [entry(
        b"header-secret.txt",
        b"RAR5 header encrypted stored payload from rars\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let (salt, first_header_iv) = header_encryption_salt_and_first_header_iv(&bytes);
    let (second_salt, second_first_header_iv) = header_encryption_salt_and_first_header_iv(&second);
    assert_ne!(salt, second_salt);
    assert_ne!(first_header_iv, second_first_header_iv);

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    assert!(matches!(
        Archive::parse_with_password(&bytes, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    assert_eq!(archive.files().next().unwrap().name, b"header-secret.txt");
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_header_encrypted_compressed_rar50_archive_that_reader_extracts_with_password() {
    let entries = [entry(b"header-compressed-secret.txt", b"RAR5 header encrypted compressed payload from rars\nRAR5 header encrypted compressed payload from rars\n").with_mtime(Some(0x5a21_0056)).with_attributes(0x20).with_host_os(3).with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let (salt, first_header_iv) = header_encryption_salt_and_first_header_iv(&bytes);
    let (second_salt, second_first_header_iv) = header_encryption_salt_and_first_header_iv(&second);
    assert_ne!(salt, second_salt);
    assert_ne!(first_header_iv, second_first_header_iv);

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    assert!(matches!(
        Archive::parse_with_password(&bytes, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let file = archive.files().next().unwrap();
    assert_eq!(file.name, b"header-compressed-secret.txt");
    assert_eq!(file.decoded_compression_info().unwrap().method, 3);
    assert!(file.encrypted);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
    assert_eq!(extracted[0].file_time, 0x5a21_0056);
}

#[test]
fn writes_header_encrypted_solid_compressed_rar50_archive_that_reader_extracts_with_password() {
    let first = b"header encrypted rar50 solid shared phrase alpha beta gamma\n".repeat(16);
    let second = b"header encrypted rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
    let entries = [
        entry(b"header-solid-one.txt", &first)
            .with_mtime(Some(0x5a21_0063))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec()),
        entry(b"header-solid-two.txt", &second)
            .with_mtime(Some(0x5a21_0064))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec()),
    ];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    features.solid = true;
    let bytes = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert!(archive.main.is_solid());
    assert!(files.iter().all(|file| file.encrypted));
    assert!(!files[0].decoded_compression_info().unwrap().solid);
    assert!(files[1].decoded_compression_info().unwrap().solid);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].data, second);
}

#[test]
fn writes_header_encrypted_rar50_archive_comment_service_that_reader_extracts_with_password() {
    let entries = [entry(
        b"header-comment-secret.txt",
        b"RAR5 header encrypted archive comment payload from rars\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_encrypted_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some((b"header encrypted CMT from rars\n", b"password")),
        None,
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, b"CMT");
    assert!(services[0].encrypted);
    let comment = collect_file(&archive, services[0]).unwrap();
    assert_eq!(comment.data, b"header encrypted CMT from rars\n");
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_header_encrypted_compressed_rar50_archive_comment_service_with_password() {
    let payload = b"header encrypted compressed payload with archive comment\n".repeat(8);
    let entries = [entry(b"header-compressed-comment-secret.txt", &payload)
        .with_mtime(Some(0x5a21_0067))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_encrypted_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some((b"header encrypted compressed CMT from rars\n", b"password")),
        None,
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, b"CMT");
    assert!(services[0].encrypted);
    let comment = collect_file(&archive, services[0]).unwrap();
    assert_eq!(comment.data, b"header encrypted compressed CMT from rars\n");
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_header_encrypted_rar50_archive_metadata_record() {
    let entries = [entry(
        b"header-metadata-secret.txt",
        b"header encrypted stored payload with archive metadata\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_encrypted_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar70, features),
        None,
        Some(ArchiveMetadataEntry {
            name: Some(b"header-encrypted-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }),
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let metadata = archive.main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"header-encrypted-metadata.rar".as_slice())
    );
    assert_eq!(metadata.creation_time, Some(0x01dcd60e_662d7a32));
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_header_encrypted_rar50_recovery_service_that_reader_extracts_with_password() {
    let entries = [entry(
        b"header-recovery-secret.txt",
        b"RAR5 header encrypted recovery payload from rars\n",
    )
    .with_mtime(Some(0x5a21_0000))
    .with_attributes(0x20)
    .with_host_os(3)
    .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        4,
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    assert!(archive.main.has_recovery_record());
    let service = archive.services().next().unwrap();
    assert_eq!(service.name, b"RR");
    assert!(!service.encrypted);
    let recovery = service.recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 4);
    let recovery_data = collect_file(&archive, service).unwrap().data;
    assert!(recovery_data.starts_with(b"{RB}"));
    assert_eq!(
        u32::from_le_bytes(recovery_data[0x0c..0x10].try_into().unwrap()) as usize,
        recovery_data.len()
    );
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entry_data(&entries[0]));
}

#[test]
fn writes_header_encrypted_compressed_rar50_recovery_service_that_reader_extracts_with_password() {
    let payload = b"header encrypted compressed recovery payload repeated repeated. ".repeat(24);
    let entries = [entry(b"header-secret-compressed-recovery.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_compressed_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        4,
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    assert!(archive.main.has_recovery_record());
    let service = archive.services().next().unwrap();
    assert_eq!(service.name, b"RR");
    assert!(!service.encrypted);
    assert_eq!(service.recovery_record().unwrap().unwrap().percent, 4);
    let recovery_data = collect_file(&archive, service).unwrap().data;
    assert!(recovery_data.starts_with(b"{RB}"));
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_header_encrypted_compressed_rar50_archive_metadata_record() {
    let payload = b"header encrypted compressed metadata payload repeated repeated\n".repeat(8);
    let entries = [entry(b"header-secret-compressed-metadata.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let bytes = write_compressed_archive_with_metadata(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar70, features),
        Some(ArchiveMetadataEntry {
            name: Some(b"header-encrypted-compressed-metadata.rar"),
            creation_time: Some(0x01dcd60e_662d7a32),
        }),
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let metadata = archive.main.archive_metadata().unwrap();
    assert_eq!(
        metadata.name.as_deref(),
        Some(b"header-encrypted-compressed-metadata.rar".as_slice())
    );
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_stored_rar50_volume_set_that_reader_reassembles_with_password() {
    let payload = b"RAR5 encrypted stored split payload from rars.\n".repeat(16);
    let entry = entry(b"split-secret.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let features = FeatureSet::store_only();
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(ArchiveVersion::Rar50, features)),
        97,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);
    let second_parts = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(ArchiveVersion::Rar50, features)),
        97,
        None,
    )
    .unwrap();
    assert!(parts.len() > 2);
    assert_eq!(parts.len(), second_parts.len());

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let second_archives: Vec<_> = second_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert!(archives
        .iter()
        .all(|archive| archive.files().next().is_some_and(|file| file.encrypted)));
    let first_encryption = archives[0]
        .files()
        .next()
        .unwrap()
        .encryption
        .as_ref()
        .unwrap();
    let second_encryption = second_archives[0]
        .files()
        .next()
        .unwrap()
        .encryption
        .as_ref()
        .unwrap();
    assert_ne!(first_encryption.salt, second_encryption.salt);
    assert_ne!(first_encryption.iv, second_encryption.iv);
    assert!(matches!(
        collect_extract_volumes(&archives),
        Err(Error::NeedPassword)
    ));

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"split-secret.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_stored_rar50_volume_set_with_recovery_records() {
    let payload = b"RAR5 encrypted stored recovery split payload from rars.\n".repeat(16);
    let entry = entry(b"split-secret-rr.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let features = FeatureSet::store_only();
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(ArchiveVersion::Rar50, features)),
        97,
        Some(8),
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert!(archives
        .iter()
        .all(|archive| archive.main.has_recovery_record()));
    for archive in &archives {
        let service = archive.services().next().unwrap();
        assert_eq!(service.name_lossy(), "RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 8);
        assert_rar5_inline_recovery_chunks(&collect_file(archive, service).unwrap().data);
    }

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"split-secret-rr.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_header_encrypted_stored_rar50_volume_set_that_reader_reassembles_with_password() {
    let payload = b"RAR5 header encrypted stored split payload from rars.\n".repeat(16);
    let entry = entry(b"split-header-secret.txt", &payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(ArchiveVersion::Rar50, features)),
        97,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, Some(b"password"));
    let second_parts = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(ArchiveVersion::Rar50, features)),
        97,
        None,
    )
    .unwrap();
    assert!(parts.len() > 2);
    assert_eq!(parts.len(), second_parts.len());
    let (salt, first_header_iv) = header_encryption_salt_and_first_header_iv(&parts[0]);
    let (second_salt, second_first_header_iv) =
        header_encryption_salt_and_first_header_iv(&second_parts[0]);
    assert_ne!(salt, second_salt);
    assert_ne!(first_header_iv, second_first_header_iv);
    assert!(parts
        .iter()
        .all(|part| matches!(Archive::parse(part), Err(Error::NeedPassword))));
    assert!(parts.iter().all(|part| matches!(
        Archive::parse_with_password(part, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    )));

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"split-header-secret.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_compressed_rar50_volume_set_that_reader_reassembles_with_password() {
    let payload = b"RAR5 encrypted compressed split payload from rars.\n".repeat(18);
    let entry = entry(b"split-secret-compressed50.txt", &payload)
        .with_mtime(Some(0x5a21_0057))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let features = FeatureSet::store_only();
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);
    let second_parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();

    assert!(parts.len() >= 2);
    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let second_archives: Vec<_> = second_parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    let first = archives[0].files().next().unwrap();
    let second_first = second_archives[0].files().next().unwrap();
    assert!(first.encrypted);
    assert_eq!(first.decoded_compression_info().unwrap().method, 3);
    let encryption = first.encryption.as_ref().unwrap();
    let second_encryption = second_first.encryption.as_ref().unwrap();
    assert_ne!(encryption.salt, second_encryption.salt);
    assert_ne!(encryption.iv, second_encryption.iv);

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].name, b"split-secret-compressed50.txt");
    assert_eq!(extracted[0].data, payload);
    assert_eq!(extracted[0].file_time, 0x5a21_0057);
}

#[test]
fn encrypted_compressed_rar50_volume_writer_stores_member_when_lz_payload_would_grow() {
    let data = deterministic_noise(8192);
    assert!(encode_lz_member(&data, 0).unwrap().len() >= data.len());
    let entry = entry(b"secret-incompressible-split.bin", &data)
        .with_mtime(Some(0x5a21_00a3))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let features = FeatureSet::store_only();
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        1024,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    assert!(parts.len() >= 2);
    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| {
        let file = archive.files().next().unwrap();
        file.encrypted && file.is_stored()
    }));
    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].name, b"secret-incompressible-split.bin");
    assert_eq!(extracted[0].data, data);
    assert_eq!(extracted[0].file_time, 0x5a21_00a3);
}

#[test]
fn writes_encrypted_compressed_rar50_volume_set_with_recovery_records() {
    let payload = b"RAR5 encrypted compressed recovery split payload from rars.\n".repeat(18);
    let entry = entry(b"split-secret-compressed-rr.txt", &payload)
        .with_mtime(Some(0x5a21_0057))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let features = FeatureSet::store_only();
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        Some(8),
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert!(archives
        .iter()
        .all(|archive| archive.main.has_recovery_record()));
    for archive in &archives {
        let service = archive.services().next().unwrap();
        assert_eq!(service.name_lossy(), "RR");
        assert!(!service.encrypted);
        assert_eq!(service.recovery_record().unwrap().unwrap().percent, 8);
        assert_rar5_inline_recovery_chunks(&collect_file(archive, service).unwrap().data);
    }

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"split-secret-compressed-rr.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_solid_compressed_rar50_volume_set_that_reader_reassembles_with_password() {
    let payload = b"RAR5 encrypted solid compressed split payload from rars.\n".repeat(18);
    let entry = entry(b"split-solid-secret-compressed50.txt", &payload)
        .with_mtime(Some(0x5a21_0058))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_solid()));
    let first = archives[0].files().next().unwrap();
    assert!(first.encrypted);
    assert!(!first.decoded_compression_info().unwrap().solid);

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].name, b"split-solid-secret-compressed50.txt");
    assert_eq!(extracted[0].data, payload);
    assert_eq!(extracted[0].file_time, 0x5a21_0058);
}

#[test]
fn writes_header_encrypted_compressed_rar50_volume_set_that_reader_reassembles_with_password() {
    let payload = b"RAR5 header encrypted compressed split payload from rars.\n".repeat(18);
    let entry = entry(b"split-header-secret-compressed50.txt", &payload)
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, Some(b"password"));
    let second_parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();
    let (salt, first_header_iv) = header_encryption_salt_and_first_header_iv(&parts[0]);
    let (second_salt, second_first_header_iv) =
        header_encryption_salt_and_first_header_iv(&second_parts[0]);
    assert_ne!(salt, second_salt);
    assert_ne!(first_header_iv, second_first_header_iv);
    assert!(matches!(
        Archive::parse(&parts[0]),
        Err(Error::NeedPassword)
    ));

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    let first = archives[0].files().next().unwrap();
    assert!(first.encrypted);
    assert_eq!(first.decoded_compression_info().unwrap().method, 3);

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"split-header-secret-compressed50.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_header_encrypted_solid_compressed_rar50_volume_set_that_reader_reassembles_with_password()
{
    let payload = b"RAR5 header encrypted solid compressed split payload from rars.\n".repeat(18);
    let entry = entry(b"split-header-solid-secret-compressed50.txt", &payload)
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    features.solid = true;
    let parts = write_volumes(
        std::slice::from_ref(&entry),
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, Some(b"password"));
    assert!(matches!(
        Archive::parse(&parts[0]),
        Err(Error::NeedPassword)
    ));

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_solid()));
    let first = archives[0].files().next().unwrap();
    assert!(first.encrypted);
    assert!(!first.decoded_compression_info().unwrap().solid);

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(
        extracted[0].name,
        b"split-header-solid-secret-compressed50.txt"
    );
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_encrypted_multi_file_solid_compressed_rar50_volume_set_that_reader_reassembles() {
    let first = b"RAR5 encrypted multi-file solid split shared phrase.\n".repeat(14);
    let second = b"RAR5 encrypted multi-file solid split shared phrase.\nsecond\n".repeat(12);
    let entries = [
        entry(b"encrypted-solid-split-one.txt", &first)
            .with_mtime(Some(0x5a21_0061))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec()),
        entry(b"encrypted-solid-split-two.txt", &second)
            .with_mtime(Some(0x5a21_0062))
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec()),
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let parts = write_volumes(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        96,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, None);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_solid()));
    assert!(archives
        .iter()
        .flat_map(|archive| archive.files())
        .any(|file| file.name == b"encrypted-solid-split-two.txt"
            && file.decoded_compression_info().unwrap().solid));

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].name, b"encrypted-solid-split-one.txt");
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].name, b"encrypted-solid-split-two.txt");
    assert_eq!(extracted[1].data, second);
}

#[test]
fn writes_header_encrypted_multi_file_solid_compressed_rar50_volume_set_that_reader_reassembles() {
    let first = b"RAR5 header encrypted multi-file solid split shared phrase.\n".repeat(14);
    let second =
        b"RAR5 header encrypted multi-file solid split shared phrase.\nsecond\n".repeat(12);
    let entries = [
        entry(b"header-encrypted-solid-split-one.txt", &first)
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec()),
        entry(b"header-encrypted-solid-split-two.txt", &second)
            .with_attributes(0x20)
            .with_host_os(3)
            .with_password(b"password".to_vec()),
    ];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    features.solid = true;
    let parts = write_volumes(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        96,
        None,
    )
    .unwrap();
    assert_volume_set_links_its_parts(&parts, Some(b"password"));
    assert!(matches!(
        Archive::parse(&parts[0]),
        Err(Error::NeedPassword)
    ));

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse_with_password(part, Some(b"password")).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_solid()));
    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"header-encrypted-solid-split-one.txt");
    assert_eq!(extracted[0].data, first);
    assert_eq!(extracted[1].name, b"header-encrypted-solid-split-two.txt");
    assert_eq!(extracted[1].data, second);
}

#[test]
fn decrypts_rar50_crc32_mac_file_with_password() {
    let bytes = std::fs::read(fixture("password_crc32.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].encrypted);
    assert_eq!(files[0].packed_size(), 48);
    assert!(matches!(
        collect_extract(&archive),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::NeedPassword)
    ));

    let extracted = collect_extract_with_password(&archive, Some(b"password")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");

    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn decrypts_rar50_blake2_mac_file_with_password() {
    let bytes = std::fs::read(fixture("password_aes.rar")).unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].encrypted);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn rejects_wrong_password_for_rar50_encrypted_file() {
    let bytes = std::fs::read(fixture("password_crc32.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        collect_extract_with_password(&archive, Some(b"wrong")),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::WrongPasswordOrCorruptData)
    ));
}

#[test]
fn rejects_rar50_header_encrypted_archive_without_or_with_wrong_password() {
    let bytes = std::fs::read(fixture("header_encrypted.rar")).unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    assert!(matches!(
        Archive::parse_with_password(&bytes, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));
}

#[test]
fn parses_and_extracts_rar50_header_encrypted_archive_with_password() {
    let bytes = std::fs::read(fixture("header_encrypted.rar")).unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert!(files[0].encrypted);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn parses_rar50_header_encrypted_archive_from_path_with_password() {
    let archive =
        Archive::parse_path_with_password(fixture("header_encrypted.rar"), Some(b"password"))
            .unwrap();
    let files: Vec<_> = archive.files().collect();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn parses_winrar721_header_encrypted_quick_open_archive_with_password() {
    let bytes = std::fs::read(fixture("winrar721_header_encrypted_quickopen.rar")).unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    assert!(matches!(
        Archive::parse_with_password(&bytes, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));

    let archive = Archive::parse_with_password(&bytes, Some(b"Password")).unwrap();
    let locator = archive.main.locator().unwrap();
    assert!(locator.quick_open_offset.is_some_and(|offset| offset > 0));
    assert_eq!(service_names(&archive), ["QO"]);
    assert!(archive.services().next().unwrap().encrypted);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"tmp/rars-threshold2-8191/random.bin");
    assert_eq!(extracted[0].data.len(), 8191);
}

#[test]
fn extracts_rar50_header_encrypted_comment_service_with_password() {
    let bytes = std::fs::read(fixture("header_encrypted_comment.rar")).unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
    assert!(matches!(
        Archive::parse_with_password(&bytes, Some(b"wrong")),
        Err(Error::WrongPasswordOrCorruptData)
    ));

    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, b"CMT");
    assert!(services[0].encrypted);

    let comment = collect_file(&archive, services[0]).unwrap();
    assert_eq!(comment.name, b"CMT");
    assert_eq!(comment.data.len(), 48);
    assert!(comment
        .data
        .starts_with(b"Encrypted archive comment fixture.\n"));

    let files = collect_extract(&archive).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[0].data, b"Hello, RAR 5 encrypted service fixture.\n");
}

#[test]
fn extract_to_reports_rar50_entry_context_on_write_failure() {
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink failed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        archive.extract_to(ArchiveReadOptions::default(), |_| Ok(Box::new(FailingWriter))),
        Err(Error::AtEntry {
            name,
            operation: "writing",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::Io(_))
    ));
}

#[test]
fn parses_and_extracts_rar50_stored_file_from_path() {
    let archive = Archive::parse_path(fixture("stored.rar")).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[0].packed_size(), 30);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn parses_rar50_sfx_prefixed_stored_file() {
    let mut bytes = b"small fake sfx prefix".to_vec();
    bytes.extend_from_slice(&std::fs::read(fixture("stored.rar")).unwrap());
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.sfx_offset, b"small fake sfx prefix".len());
    assert_eq!(archive.main.block.offset, archive.sfx_offset + 8);
    assert_eq!(archive.main.locator().unwrap().quick_open_offset, Some(0));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn extracts_rar50_empty_file_with_blake2_hash_record() {
    let bytes = std::fs::read(fixture("empty_file.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"empty.bin");
    assert!(file.is_stored());
    assert_eq!(file.packed_size(), 0);
    assert_eq!(file.unpacked_size, 0);
    assert_eq!(file.data_crc32, None);
    assert_eq!(file.hash.as_ref().unwrap().hash_type, 0);
    assert_eq!(file.hash.as_ref().unwrap().data.len(), 32);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"empty.bin");
    assert!(extracted[0].data.is_empty());
}

#[test]
fn verifies_rar50_blake2_hash_record_on_stored_file() {
    let archive = Archive::parse_path(fixture("stored_blake2.rar")).unwrap();
    let file = archive.files().next().unwrap();

    assert_eq!(file.name, b"hello.txt");
    assert_eq!(file.data_crc32, None);
    assert_eq!(file.hash.as_ref().unwrap().hash_type, 0);
    assert_eq!(file.hash.as_ref().unwrap().data.len(), 32);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

#[test]
fn rejects_corrupt_rar50_stored_payload_hash_when_blake2_is_present() {
    let mut bytes = std::fs::read(fixture("stored_blake2.rar")).unwrap();
    let needle = b"Hello, RAR 5.0 fixture world.\n";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("stored payload in fixture");
    bytes[offset] ^= 0x01;
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        collect_extract(&archive),
        Err(Error::AtEntry {
            name,
            operation: "verifying",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::HashMismatch { hash_type: 0 })
    ));
}

#[test]
fn ignores_unknown_rar50_file_hash_records_when_extracting() {
    let bytes = std::fs::read(fixture("wild/invalid_hash_valid_htime_exfld.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"file.txt");
    assert_eq!(
        extracted[0].data,
        b"invalid HASH extra, and later a valid HTIME extra"
    );
}

#[test]
fn skips_rar50_redirection_entries_when_extracting() {
    for fixture_name in [
        "wild/hardlink.rar",
        "wild/symlink.rar",
        "wild/rarfile_hlink.rar",
    ] {
        let bytes = std::fs::read(fixture(fixture_name)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        let extracted = collect_extract(&archive).unwrap();

        assert!(
            archive.files().any(|file| file.redirection.is_some()),
            "{fixture_name}"
        );
        assert!(
            extracted.iter().all(|entry| archive
                .files()
                .find(|file| file.name == entry.name)
                .is_some_and(|file| file.redirection.is_none())),
            "{fixture_name}"
        );
    }
}

#[test]
fn reports_rar50_redirection_entries_when_requested() {
    for fixture_name in [
        "wild/hardlink.rar",
        "wild/symlink.rar",
        "wild/rarfile_hlink.rar",
    ] {
        let bytes = std::fs::read(fixture(fixture_name)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();
        let redirections = RefCell::new(Vec::new());

        archive
            .extract_to_with_redirections(
                read_options(None),
                |_meta| {
                    let data = Rc::new(RefCell::new(Vec::new()));
                    let writer: Box<dyn Write> = Box::new(CollectWriter { data });
                    Ok(writer)
                },
                |meta, redirection| {
                    redirections.borrow_mut().push((
                        meta.name.clone(),
                        redirection.redirection_type,
                        redirection.flags,
                        redirection.target_name.clone(),
                    ));
                    Ok(())
                },
            )
            .unwrap();

        let expected: Vec<_> = archive
            .files()
            .filter_map(|file| {
                file.redirection.as_ref().map(|redirection| {
                    (
                        file.name.clone(),
                        redirection.redirection_type,
                        redirection.flags,
                        redirection.target_name.clone(),
                    )
                })
            })
            .collect();
        assert_eq!(redirections.into_inner(), expected, "{fixture_name}");
    }
}

#[test]
fn extracts_wild_rar50_solid_archives_with_redundant_filter_records() {
    for fixture_name in [
        "wild/rarfile_solid.rar",
        "wild/rarfile_solid_qo.rar",
        "wild/libarchive_solid.rar",
        "wild/libarchive_multiple_files_solid.rar",
    ] {
        let bytes = std::fs::read(fixture(fixture_name)).unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        let extracted = collect_extract(&archive).unwrap();

        assert!(!extracted.is_empty(), "{fixture_name}");
        assert!(
            archive
                .files()
                .filter(|file| !file.is_directory() && file.redirection.is_none())
                .any(|file| file.decoded_compression_info().is_ok_and(|info| info.solid)),
            "{fixture_name}"
        );
    }
}

#[test]
fn extracts_wild_rar50_loop_fixture_as_empty_file() {
    let bytes = std::fs::read(fixture("wild/libarchive_loop_bug.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"a");
    assert!(extracted[0].data.is_empty());
}

#[test]
fn parses_rar50_multifile_stored_archive() {
    let bytes = std::fs::read(fixture("multifile.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].name, b"hello.txt");
    assert_eq!(files[1].name, b"tiny.txt");
    assert_eq!(files[2].name, b"random_4k.bin");
    assert!(files.iter().all(|file| file.is_stored()));
    assert_eq!(files[0].packed_size(), 30);
    assert_eq!(files[1].packed_size(), 9);
    assert_eq!(files[2].packed_size(), 4096);

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 3);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
    assert_eq!(extracted[1].data, b"AAAAAAAA\n");
    assert_eq!(extracted[2].data.len(), 4096);
}

#[test]
fn extracts_rar50_solid_archive() {
    let archive = Archive::parse_path(fixture("solid.rar")).unwrap();

    assert!(archive.main.is_solid());
    let files: Vec<_> = archive.files().collect();
    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .any(|file| file.decoded_compression_info().unwrap().solid));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert!(extracted.iter().all(|entry| !entry.data.is_empty()));
}

#[test]
fn rejects_nonzero_encrypted_stored_padding_in_streaming_extraction() {
    let payload = b"encrypted stored RAR5 padding check";
    let entries = [entry(b"secret.txt", payload)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec())];
    let features = FeatureSet::store_only();
    let mut bytes = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    corrupt_encrypted_stored_padding(&mut bytes, b"password");

    let archive = Archive::parse(&bytes).unwrap();
    assert!(matches!(
        collect_extract_with_password(&archive, Some(b"password")),
        Err(Error::AtEntry {
            name,
            operation: "decoding",
            source
        }) if name == b"secret.txt"
            && matches!(*source, Error::InvalidHeader(
                "RAR 5 encrypted stored file has non-zero padding"
            ))
    ));
}

#[test]
fn rar50_solid_extraction_uses_file_compression_info_flag() {
    let mut archive = Archive::parse_path(fixture("solid.rar")).unwrap();
    archive.main.archive_flags = 0;

    assert!(!archive.main.is_solid());
    assert!(archive
        .files()
        .any(|file| file.decoded_compression_info().unwrap().solid));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert!(extracted.iter().all(|entry| !entry.data.is_empty()));
}

#[test]
fn extracts_rar50_compressed_multivolume_archive() {
    let volumes = [
        Archive::parse_path(fixture("multivol.part1.rar")).unwrap(),
        Archive::parse_path(fixture("multivol.part2.rar")).unwrap(),
        Archive::parse_path(fixture("multivol.part3.rar")).unwrap(),
    ];

    assert!(volumes.iter().all(|archive| archive.main.is_volume()));
    assert!(volumes[0].files().next().unwrap().is_split_after());
    assert!(volumes[1].files().next().unwrap().is_split_before());
    assert!(volumes[1].files().next().unwrap().is_split_after());
    assert!(volumes[2].files().next().unwrap().is_split_before());
    assert!(!volumes[2].files().next().unwrap().is_split_after());

    let extracted = collect_extract_volumes(&volumes).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"random_4k.bin");
    assert_eq!(extracted[0].data.len(), 4096);
}

#[test]
fn extracts_rar50_stored_multivolume_archive() {
    let volumes = [
        Archive::parse_path(fixture("stored_multivol.part1.rar")).unwrap(),
        Archive::parse_path(fixture("stored_multivol.part2.rar")).unwrap(),
        Archive::parse_path(fixture("stored_multivol.part3.rar")).unwrap(),
    ];

    let extracted = collect_extract_volumes(&volumes).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"random_4k.bin");
    assert_eq!(extracted[0].data.len(), 4096);
    assert_eq!(crc32(&extracted[0].data), 0xb9c5_4415);
}

#[test]
fn extracts_rar50_solid_multivolume_archive() {
    let volumes = [
        Archive::parse_path(fixture("solid_multivol.part01.rar")).unwrap(),
        Archive::parse_path(fixture("solid_multivol.part02.rar")).unwrap(),
        Archive::parse_path(fixture("solid_multivol.part03.rar")).unwrap(),
        Archive::parse_path(fixture("solid_multivol.part04.rar")).unwrap(),
        Archive::parse_path(fixture("solid_multivol.part05.rar")).unwrap(),
        Archive::parse_path(fixture("solid_multivol.part06.rar")).unwrap(),
    ];

    let extracted = collect_extract_volumes(&volumes).unwrap();

    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].name, b"tiny.txt");
    assert_eq!(extracted[0].data, b"AAAAAAAA\n");
    assert_eq!(extracted[1].name, b"bigtext_64k.bin");
    assert_eq!(extracted[1].data.len(), 65_536);
    assert_eq!(crc32(&extracted[1].data), 0xddc9_5682);
}

/// A volume set must agree on header encryption throughout. Splicing a
/// plaintext volume into an encrypted set is a substitution attack: header
/// encryption is what hides the file names, so an attacker who can replace one
/// volume otherwise injects entries into an extraction the user believes is
/// protected end to end.
///
/// RAR 7.12 and UnRAR 7.20 both abort with a bad-archive error rather than
/// extract. rars refuses too, and must write nothing while doing so.
#[test]
fn rar50_refuses_a_volume_set_that_changes_encryption_partway() {
    let volumes: Vec<_> = [
        "header_encrypted_stored_multivol.part1.rar",
        "plaintext_stored_multivol.part2.rar",
        "header_encrypted_stored_multivol.part3.rar",
    ]
    .iter()
    .filter_map(|name| Archive::parse_path_with_password(fixture(name), Some(b"password")).ok())
    .collect();

    assert_eq!(
        volumes.len(),
        3,
        "every volume should still parse on its own"
    );
    assert!(matches!(
        collect_extract_volumes_with_password(&volumes, Some(b"password")),
        Err(Error::InvalidHeader(
            "RAR 5 split entry encryption flag changed"
        ))
    ));
}

/// Bits 0-5 of CompInfo hold six bits and only two values are assigned, so a
/// decoder must refuse the rest rather than falling through to Unpack50 and
/// misreading a stream it cannot decode. RAR 7.12 and UnRAR 7.20 answer
/// `Unknown method` for version 2 on a compressed member.
///
/// A stored member is the exception and extracts on both, because nothing is
/// decompressed and the version never comes up. So the refusal belongs on the
/// decompressor, not at header parse time, and that is the half worth pinning:
/// a reader that rejects too early breaks archives the reference reads.
#[test]
fn rar50_refuses_an_unknown_algorithm_version_only_when_it_must_decompress() {
    let compressed = Archive::parse_path(fixture("algorithm_version_2.rar")).unwrap();
    assert!(matches!(
        collect_extract(&compressed),
        Err(Error::AtEntry { source, .. })
            if matches!(*source, Error::UnsupportedFeature { .. })
    ));

    let stored = Archive::parse_path(fixture("algorithm_version_2_stored.rar")).unwrap();
    let extracted = collect_extract(&stored).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
}

/// A non-solid stream starts with no Huffman tables loaded, so a first block
/// that clears `table_present` has nothing to reuse.
///
/// RAR 7.12 and UnRAR 7.20 fail the member too, but by a different route: they
/// appear to decode against whatever their table memory holds and emit wrong
/// bytes until the checksum catches it. Refusing the block outright reaches the
/// same verdict without decoding anything.
#[test]
fn rar50_refuses_a_first_block_that_reuses_absent_tables() {
    let archive = Archive::parse_path(fixture("first_block_without_tables.rar")).unwrap();
    assert!(collect_extract(&archive).is_err());
}

/// Modern WinRAR writes the modification time into `FHEXTRA_HTIME` and leaves
/// the base-header field out, so a reader that only looks at the header field
/// restores nothing. 39 of the 40 RAR 5 fixtures here carry the record and one
/// carries the header field, which is how far from an edge case this is.
#[test]
fn rar50_reads_the_modification_time_from_the_htime_record() {
    let mut with_record = 0;
    let mut with_header_field = 0;

    for entry in fs::read_dir(fixture(".")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "rar") {
            continue;
        }
        let Ok(archive) = Archive::parse_path(&path) else {
            continue;
        };
        let common = rars::Archive::Rar50Plus(archive.clone());
        for (member, file) in common.members().zip(archive.files()) {
            assert_eq!(member.meta.file_time, file.mtime.or(file.htime_mtime));
        }
        for file in archive.files() {
            if file.mtime.is_some() {
                with_header_field += 1;
            }
            if file.htime_mtime.is_some() {
                with_record += 1;
            }
            // Whichever carries it, the entry must report a time.
            if file.mtime.is_some() || file.htime_mtime.is_some() {
                assert_ne!(
                    file.metadata().file_time,
                    None,
                    "{} reports no time despite carrying one",
                    path.display()
                );
            }
        }
    }

    assert!(
        with_record > with_header_field,
        "expected the extra record to dominate: record={with_record} header={with_header_field}"
    );
}

/// WinRAR 5.21 and earlier set the password-check flag and then wrote eight
/// zero bytes into the field, so a reader that verifies it rejects the correct
/// password and the archive cannot be opened at all. RAR 7.12 treats an
/// all-zero field as no check available and lets the data checksum decide.
///
/// A wrong password must still be refused, just later and by a different
/// mechanism, which is the second half of this test.
#[test]
fn opens_rar50_archive_whose_password_check_is_all_zeroes() {
    let data = fs::read(fixture("zeroed_password_check.rar")).unwrap();

    let archive = Archive::parse_with_password(&data, Some(b"secret")).unwrap();
    let extracted = collect_extract_with_password(&archive, Some(b"secret")).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"s.txt");

    assert!(
        Archive::parse_with_password(&data, Some(b"wrongpw"))
            .and_then(|archive| collect_extract_with_password(&archive, Some(b"wrongpw")))
            .is_err(),
        "a wrong password must still be refused, via the data checksum"
    );
}

/// A stored, header-encrypted, split member reaches a verification path of its
/// own, and that path used to apply the encrypted-checksum transform to any
/// encrypted file rather than only to one whose crypt record sets the tweaked
/// checksum flag. The archive extracted the right bytes and then failed on a
/// checksum that had been transformed when the stored one had not been.
///
/// Compressed volume sets verify elsewhere, which is why the sibling
/// `encrypted_multivol` fixtures never caught this.
#[test]
fn extracts_rar50_header_encrypted_stored_multivolume_archive() {
    let volumes: Vec<_> = (1..=3)
        .map(|part| {
            Archive::parse_path_with_password(
                fixture(&format!("header_encrypted_stored_multivol.part{part}.rar")),
                Some(b"password"),
            )
            .unwrap()
        })
        .collect();

    assert!(volumes.iter().all(|archive| archive.main.is_volume()));

    let extracted = collect_extract_volumes(&volumes).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"stored_4k.bin");
    assert_eq!(extracted[0].data.len(), 4096);
    assert_eq!(crc32(&extracted[0].data), 0xa087_a9af);
}

#[test]
fn extracts_rar50_encrypted_compressed_multivolume_archive() {
    let volumes = [
        Archive::parse_path_with_password(
            fixture("encrypted_multivol.part1.rar"),
            Some(b"password"),
        )
        .unwrap(),
        Archive::parse_path_with_password(
            fixture("encrypted_multivol.part2.rar"),
            Some(b"password"),
        )
        .unwrap(),
        Archive::parse_path_with_password(
            fixture("encrypted_multivol.part3.rar"),
            Some(b"password"),
        )
        .unwrap(),
    ];

    assert!(volumes.iter().all(|archive| archive.main.is_volume()));
    assert!(volumes
        .iter()
        .all(|archive| { archive.files().next().is_some_and(|file| file.encrypted) }));

    let extracted = collect_extract_volumes(&volumes).unwrap();

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].name, b"random_4k.bin");
    assert_eq!(extracted[0].data.len(), 4096);
    assert_eq!(crc32(&extracted[0].data), 0xb9c5_4415);
}

#[test]
fn rejects_nonzero_encrypted_stored_padding_in_split_streaming_extraction() {
    let data = b"encrypted stored split RAR5 padding check".repeat(3);
    let entry = entry(b"split-secret.txt", &data)
        .with_mtime(Some(0x5a21_0000))
        .with_attributes(0x20)
        .with_host_os(3)
        .with_password(b"password".to_vec());
    let features = FeatureSet::store_only();
    let mut volumes = write_volumes(
        std::slice::from_ref(&entry),
        stored(rar50::WriterOptions::new(ArchiveVersion::Rar50, features)),
        32,
        None,
    )
    .unwrap();
    corrupt_encrypted_stored_split_padding(&mut volumes, b"password");
    let archives = volumes
        .iter()
        .map(|bytes| Archive::parse(bytes).unwrap())
        .collect::<Vec<_>>();

    assert!(matches!(
        collect_extract_volumes_with_password(&archives, Some(b"password")),
        Err(Error::AtEntry {
            name,
            operation: "extracting",
            source
        }) if name == b"split-secret.txt"
            && matches!(*source, Error::InvalidHeader(
                "RAR 5 encrypted stored split file has non-zero padding"
            ))
    ));
}

#[test]
fn decodes_rar50_compression_info_bitfield() {
    let stored = Archive::parse_path(fixture("stored.rar")).unwrap();
    let stored_file = stored.files().next().unwrap();
    let info = stored_file.decoded_compression_info().unwrap();
    assert_eq!(info.algorithm_version, 0);
    assert_eq!(info.method, 0);
    assert!(!info.solid);
    assert_eq!(info.dictionary_fraction, 0);
    assert!(!info.rar5_compat);

    for (name, method) in [
        ("m1_fastest.rar", 1),
        ("m3_default.rar", 3),
        ("m5_max.rar", 5),
    ] {
        let archive = Archive::parse_path(fixture(name)).unwrap();
        let file = archive.files().next().unwrap();
        let info = file.decoded_compression_info().unwrap();
        assert_eq!(info.algorithm_version, 0, "{name}");
        assert_eq!(info.method, method, "{name}");
        assert!(!info.solid, "{name}");
        assert_eq!(info.dictionary_fraction, 0, "{name}");
        assert!(!info.rar5_compat, "{name}");
        assert!(info.dictionary_size >= 128 * 1024, "{name}");
    }
}

#[test]
fn parses_rar50_comment_service_archive() {
    let archive = Archive::parse_path(fixture("with_comment.rar")).unwrap();

    assert_eq!(archive.files().count(), 1);
    assert_eq!(service_names(&archive), ["CMT"]);
    let comment = archive.services().next().unwrap();
    assert_eq!(comment.packed_size(), 30);
    assert_eq!(comment.unpacked_size, 30);
    assert!(comment.is_stored());
}

#[test]
fn parses_rar50_quick_open_service_archive() {
    let archive = Archive::parse_path(fixture("with_quickopen.rar")).unwrap();

    assert_eq!(archive.files().count(), 2);
    assert_eq!(service_names(&archive), ["QO"]);
    let quick_open = archive.services().next().unwrap();
    assert_eq!(quick_open.packed_size(), 162);
    assert_eq!(quick_open.unpacked_size, 162);
    assert!(quick_open.is_stored());
}

#[test]
fn parses_rar50_recovery_service_archive() {
    let archive = Archive::parse_path(fixture("with_recovery.rar")).unwrap();

    assert!(archive.main.has_recovery_record());
    assert_eq!(archive.files().count(), 1);
    assert_eq!(service_names(&archive), ["RR"]);
    let recovery = archive.services().next().unwrap();
    assert_eq!(recovery.packed_size(), 210);
    assert_eq!(recovery.unpacked_size, 210);
    assert_rar5_inline_recovery_chunks(&recovery.packed_data(&archive).unwrap());
    let recovery = recovery.recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 10);
    assert_eq!(recovery.payload_size, 210);
}

/// Rewrites the `RR` service header's extra area in `with_recovery.rar` and
/// fixes up the two sizes and the header CRC32 that describe it.
///
/// The header's `ExtraSize`, `HeadSize` and every extra record here fit in a
/// one-byte vint, so splicing is a byte-for-byte substitution.
fn with_recovery_extra_area(extra: &[u8]) -> Vec<u8> {
    const CRC_POS: usize = 0x81;
    const BODY: usize = 0x86;
    const HEAD_SIZE_POS: usize = 0x85;
    const EXTRA_SIZE_POS: usize = 0x88;
    const EXTRA_START: usize = 0x95;
    const EXTRA_END: usize = 0x98;

    let mut data = fs::read(fixture("with_recovery.rar")).unwrap();
    assert_eq!(&data[EXTRA_START..EXTRA_END], b"\x02\x07\x0a");
    assert!(extra.len() < 0x80);

    data.splice(EXTRA_START..EXTRA_END, extra.iter().copied());
    data[EXTRA_SIZE_POS] = extra.len() as u8;
    data[HEAD_SIZE_POS] =
        (data[HEAD_SIZE_POS] as usize + extra.len() - (EXTRA_END - EXTRA_START)) as u8;
    let header_end = BODY + data[HEAD_SIZE_POS] as usize;
    let header_crc = crc32(&data[CRC_POS + 4..header_end]);
    data[CRC_POS..CRC_POS + 4].copy_from_slice(&header_crc.to_le_bytes());
    data
}

/// WinRAR 5.21 and earlier stored the `FHEXTRA_SUBDATA` size one less than the
/// payload they wrote. `SUBDATA` is the last record in a service header, so the
/// shortfall leaves exactly one byte dangling, and a reader that drops it loses
/// the recovery percent.
#[test]
fn reads_rar50_service_subdata_whose_size_underflows_by_one() {
    let archive = Archive::parse_path(fixture("subdata_size_underflow.rar")).unwrap();

    assert_eq!(service_names(&archive), ["RR"]);
    let recovery = archive.services().next().unwrap();
    assert_eq!(recovery.service_data, Some(vec![0x0a]));
    let recovery = recovery.recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 10);
    assert_eq!(recovery.payload_size, 210);
}

/// The fold is deliberately narrow: it fires only for `SUBDATA` on a service
/// header, since that is the record WinRAR undersized. A stray byte after any
/// other record just ends the walk.
#[test]
fn rar50_one_byte_fold_is_limited_to_service_subdata() {
    // 0x03 is FHEXTRA_HTIME: same shape, wrong record type, so no fold.
    let archive = Archive::parse(&with_recovery_extra_area(b"\x01\x03\x0a")).unwrap();
    let service = archive.services().next().unwrap();
    assert_eq!(service.service_data, None);
    assert!(service.recovery_record().is_err());
}

/// A record that does not fit its extra area ends the walk. RAR 7.12 and UnRAR
/// 7.20 extract from all four of these shapes, so failing the archive over one
/// would discard file data that is intact.
#[test]
fn rar50_stops_on_a_malformed_extra_record_instead_of_failing_the_archive() {
    let cases: [(&str, &[u8]); 4] = [
        ("two bytes dangle after the record", b"\x01\x07\x0a\x0b"),
        ("size vint runs past the extra area", b"\x02\x07\x0a\xff"),
        ("first record claims 127 bytes", b"\x7f\x07\x0a\x0b"),
        ("record too small for its type vint", b"\x00\x07\x0a\x0b"),
    ];

    for (name, extra) in cases {
        let data = with_recovery_extra_area(extra);
        let archive = Archive::parse(&data).unwrap_or_else(|error| panic!("{name}: {error}"));
        let extracted = collect_extract(&archive).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(extracted.len(), 1, "{name}");
        assert_eq!(extracted[0].name, b"hello.txt", "{name}");
    }
}

#[test]
fn parses_rar50_mixed_service_archive() {
    let archive = Archive::parse_path(fixture("with_all_services.rar")).unwrap();

    assert!(archive.main.has_recovery_record());
    assert_eq!(archive.files().count(), 2);
    assert_eq!(service_names(&archive), ["CMT", "QO", "RR"]);
    let services: Vec<_> = archive.services().collect();
    assert_eq!(services[0].packed_size(), 30);
    assert_eq!(services[1].packed_size(), 162);
    assert_eq!(services[2].packed_size(), 526);
    let recovery = services[2].recovery_record().unwrap().unwrap();
    assert_eq!(recovery.percent, 5);
    assert_eq!(recovery.payload_size, 526);
    assert_rar5_inline_recovery_chunks(&services[2].packed_data(&archive).unwrap());

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].data, b"Hello, RAR 5.0 fixture world.\n");
    assert_eq!(extracted[1].data, b"AAAAAAAA\n");
}

#[test]
fn parses_rar50_rev5_recovery_volume_metadata() {
    let bytes = std::fs::read(fixture("multivol_rev.part1.rev")).unwrap();
    let rev = Rev5Volume::parse(&bytes).unwrap();

    assert_eq!(rev.version, 1);
    assert_eq!(rev.data_count, 5);
    assert_eq!(rev.recovery_count, 2);
    assert_eq!(rev.recovery_number, 5);
    assert_eq!(rev.payload_size, 4096);
    assert_eq!(rev.payload.len(), 4096);
    assert_eq!(rev.payload_crc32, 0xfd0b_7e3f);
    assert_eq!(rev.data_volumes.len(), 5);
    assert_eq!(rev.data_volumes[0].file_size, 4096);
    assert_eq!(rev.data_volumes[4].file_size, 1032);
}

#[test]
fn parses_rar50_rev5_metadata_without_validating_payload_crc() {
    let mut bytes = std::fs::read(fixture("multivol_rev.part1.rev")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    let meta = Rev5VolumeMeta::parse(&bytes).unwrap();

    assert_eq!(meta.version, 1);
    assert_eq!(meta.data_count, 5);
    assert_eq!(meta.recovery_count, 2);
    assert_eq!(meta.recovery_number, 5);
    assert_eq!(meta.payload_size, 4096);
    assert_eq!(meta.payload_crc32, 0xfd0b_7e3f);
    assert_eq!(meta.data_volumes.len(), 5);
}

fn update_rev5_header_crc(bytes: &mut [u8]) {
    let header_size = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let header_end = 16 + header_size;
    let header_crc = crc32(&bytes[12..header_end]);
    bytes[8..12].copy_from_slice(&header_crc.to_le_bytes());
}

#[test]
fn parses_rar50_rev5_metadata_with_forward_compatible_trailing_bytes() {
    let mut bytes = std::fs::read(fixture("multivol_rev.part1.rev")).unwrap();
    let header_size = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let header_end = 16 + header_size;
    bytes[12..16].copy_from_slice(&(header_size as u32 + 3).to_le_bytes());
    bytes.splice(header_end..header_end, [0xa5, 0x5a, 0x7e]);
    update_rev5_header_crc(&mut bytes);

    let meta = Rev5VolumeMeta::parse(&bytes).unwrap();

    assert_eq!(meta.data_count, 5);
    assert_eq!(meta.data_volumes.len(), 5);
    assert_eq!(meta.payload_size, 4096);
}

#[test]
fn rejects_rar50_rev5_metadata_with_truncated_table() {
    let mut bytes = std::fs::read(fixture("multivol_rev.part1.rev")).unwrap();
    let header_size = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let header_end = 16 + header_size;
    bytes[12..16].copy_from_slice(&(header_size as u32 - 1).to_le_bytes());
    bytes.remove(header_end - 1);
    update_rev5_header_crc(&mut bytes);

    assert!(matches!(
        Rev5VolumeMeta::parse(&bytes),
        Err(Error::InvalidHeader(
            "RAR 5 REV metadata table size is invalid"
        ))
    ));
}

#[test]
fn repairs_missing_rar50_data_volume_from_rev5_recovery_volume() {
    let data: Vec<_> = (1..=5)
        .map(|index| std::fs::read(fixture(&format!("multivol_rev.part{index}.rar"))).unwrap())
        .collect();
    let first_rev =
        Rev5Volume::parse(&std::fs::read(fixture("multivol_rev.part1.rev")).unwrap()).unwrap();
    let inputs = [
        Some(data[0].as_slice()),
        None,
        Some(data[2].as_slice()),
        Some(data[3].as_slice()),
        Some(data[4].as_slice()),
    ];

    let repaired = repair_rev5_volumes(&inputs, &[first_rev]).unwrap();

    assert_eq!(repaired, data);
}

#[test]
fn repairs_two_missing_rar50_data_volumes_from_rev5_recovery_volumes() {
    let data: Vec<_> = (1..=5)
        .map(|index| std::fs::read(fixture(&format!("multivol_rev.part{index}.rar"))).unwrap())
        .collect();
    let revs = [
        Rev5Volume::parse(&std::fs::read(fixture("multivol_rev.part1.rev")).unwrap()).unwrap(),
        Rev5Volume::parse(&std::fs::read(fixture("multivol_rev.part2.rev")).unwrap()).unwrap(),
    ];
    let inputs = [
        Some(data[0].as_slice()),
        None,
        Some(data[2].as_slice()),
        None,
        Some(data[4].as_slice()),
    ];

    let repaired = repair_rev5_volumes(&inputs, &revs).unwrap();

    assert_eq!(repaired, data);
}

#[test]
fn rejects_duplicate_rar50_rev5_recovery_rows() {
    let data: Vec<_> = (1..=5)
        .map(|index| std::fs::read(fixture(&format!("multivol_rev.part{index}.rar"))).unwrap())
        .collect();
    let rev =
        Rev5Volume::parse(&std::fs::read(fixture("multivol_rev.part1.rev")).unwrap()).unwrap();
    let inputs = [
        Some(data[0].as_slice()),
        None,
        Some(data[2].as_slice()),
        None,
        Some(data[4].as_slice()),
    ];

    assert!(matches!(
        repair_rev5_volumes(&inputs, &[rev.clone(), rev]),
        Err(Error::InvalidHeader(
            "RAR 5 REV recovery volume set contains duplicate recovery rows"
        ))
    ));
}

#[test]
fn repairs_corrupt_rar50_data_volume_from_rev5_recovery_volume() {
    let mut data: Vec<_> = (1..=5)
        .map(|index| std::fs::read(fixture(&format!("multivol_rev.part{index}.rar"))).unwrap())
        .collect();
    let expected = data.clone();
    data[1][10..60].fill(0xa5);
    let first_rev =
        Rev5Volume::parse(&std::fs::read(fixture("multivol_rev.part1.rev")).unwrap()).unwrap();
    let inputs = [
        Some(data[0].as_slice()),
        Some(data[1].as_slice()),
        Some(data[2].as_slice()),
        Some(data[3].as_slice()),
        Some(data[4].as_slice()),
    ];

    let repaired = repair_rev5_volumes(&inputs, &[first_rev]).unwrap();

    assert_eq!(repaired, expected);
}

#[test]
fn rejects_corrupt_rar50_rev5_recovery_volume_checksum() {
    let mut bytes = std::fs::read(fixture("multivol_rev.part1.rev")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    assert!(matches!(
        Rev5Volume::parse(&bytes),
        Err(Error::Crc32Mismatch { .. })
    ));
}

#[test]
fn rejects_rar50_rev5_volume_number_outside_recovery_range() {
    let mut bytes = std::fs::read(fixture("multivol_rev.part1.rev")).unwrap();
    bytes[21] = 0;
    bytes[22] = 0;
    update_rev5_header_crc(&mut bytes);

    assert!(matches!(
        Rev5Volume::parse(&bytes),
        Err(Error::InvalidHeader("RAR 5 REV volume number is invalid"))
    ));
}

#[test]
fn extracts_rar50_compressed_members() {
    for name in ["m1_fastest.rar", "m3_default.rar", "m5_max.rar"] {
        let archive = Archive::parse_path(fixture(name)).unwrap();
        let files: Vec<_> = archive.files().collect();

        assert_eq!(files.len(), 1, "{name}");
        assert!(!files[0].is_stored(), "{name}");
        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted.len(), 1, "{name}");
        assert_eq!(
            extracted[0].data.len(),
            files[0].unpacked_size as usize,
            "{name}"
        );
    }
}

#[test]
fn parses_real_rar50_compressed_block_framing() {
    let archive = Archive::parse_path(fixture("m1_fastest.rar")).unwrap();
    let file = archive.files().next().unwrap();
    let packed = file.packed_data(&archive).unwrap();

    let block = parse_compressed_block(&packed).unwrap();

    assert_eq!(block.payload.start, block.header_len);
    assert!(block.payload.end <= packed.len());
    assert!(block.header.has_tables);
    assert!(block.header.payload_size > 0);
    assert!(block.header.payload_bits <= block.header.payload_size * 8);
}

#[test]
fn parses_real_rar50_compressed_block_tables() {
    let archive = Archive::parse_path(fixture("m1_fastest.rar")).unwrap();
    let file = archive.files().next().unwrap();
    let info = file.decoded_compression_info().unwrap();
    let packed = file.packed_data(&archive).unwrap();
    let block = parse_compressed_block(&packed).unwrap();
    let payload = &packed[block.payload];

    assert!(block.header.has_tables);
    let (lengths, table_bits) = read_table_lengths(payload, info.algorithm_version).unwrap();
    let tables = DecodeTables::from_lengths(&lengths).unwrap();

    assert!(table_bits < block.header.payload_bits);
    assert!(!tables.main.is_empty());
    assert!(!tables.distance.is_empty());
    assert!(!tables.length.is_empty());
}

#[test]
fn decodes_rar50_m1_fastest_with_lz_codec() {
    let archive = Archive::parse_path(fixture("m1_fastest.rar")).unwrap();
    let file = archive.files().next().unwrap();
    let info = file.decoded_compression_info().unwrap();
    let packed = file.packed_data(&archive).unwrap();

    let decoded = decode_lz(&packed, info.algorithm_version, file.unpacked_size as usize).unwrap();

    file.verify_integrity(&decoded).unwrap();
}

#[test]
fn extracts_rar50_filter_candidate_members() {
    for name in [
        "filter_arm.rar",
        "filter_delta.rar",
        "filter_e8.rar",
        "filter_e8e9.rar",
    ] {
        let archive = Archive::parse_path(fixture(name)).unwrap();
        let files: Vec<_> = archive.files().collect();

        assert_eq!(files.len(), 1, "{name}");
        assert!(!files[0].is_stored(), "{name}");
        let extracted = collect_extract(&archive).unwrap();
        assert_eq!(extracted.len(), 1, "{name}");
        assert_eq!(
            extracted[0].data.len(),
            files[0].unpacked_size as usize,
            "{name}"
        );
    }
}

#[test]
fn rejects_corrupt_rar50_header_checksum() {
    let mut bytes = std::fs::read(fixture("stored.rar")).unwrap();
    bytes[13] ^= 0x01;

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::AtArchiveOffset {
            offset: 8,
            source
        }) if matches!(*source, Error::Crc32Mismatch { .. })
    ));
}

#[test]
fn rejects_overlong_rar50_header_size_vint() {
    let mut bytes = std::fs::read(fixture("stored.rar")).unwrap();
    bytes[12..22].fill(0x80);

    assert!(matches!(
        Archive::parse(&bytes),
        Err(Error::AtArchiveOffset {
            offset: 8,
            source
        }) if matches!(*source, Error::InvalidHeader("RAR 5 vint is too long"))
    ));
}

#[test]
fn rejects_corrupt_rar50_stored_payload_checksum_when_crc32_is_present() {
    let mut bytes = std::fs::read(fixture("stored.rar")).unwrap();
    let needle = b"Hello, RAR 5.0 fixture world.\n";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("stored payload in fixture");
    bytes[offset] ^= 0x01;
    let archive = Archive::parse(&bytes).unwrap();

    assert!(matches!(
        collect_extract(&archive),
        Err(Error::AtEntry {
            name,
            operation: "verifying",
            source
        }) if name == b"hello.txt" && matches!(*source, Error::Crc32Mismatch { .. })
    ));
}

#[test]
fn parse_owned_takes_input_buffer_by_value() {
    let bytes = fs::read(fixture("empty_file.rar")).unwrap();
    let archive = Archive::parse_owned(bytes.clone()).unwrap();
    assert_eq!(archive.files().count(), 1);

    let with_options =
        Archive::parse_owned_with_options(bytes.clone(), ArchiveReadOptions::default()).unwrap();
    assert_eq!(with_options.files().count(), 1);

    let no_password = Archive::parse_owned_with_password(bytes, None).unwrap();
    assert_eq!(no_password.files().count(), 1);
}

#[test]
fn parse_owned_with_password_unlocks_header_encrypted_archive() {
    let bytes = fs::read(fixture("header_encrypted.rar")).unwrap();

    assert!(matches!(
        Archive::parse_owned(bytes.clone()),
        Err(Error::NeedPassword)
    ));

    let archive = Archive::parse_owned_with_password(bytes.clone(), Some(b"password")).unwrap();
    assert_eq!(archive.files().next().unwrap().name, b"hello.txt");

    let with_options =
        Archive::parse_owned_with_options(bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    assert_eq!(with_options.files().next().unwrap().name, b"hello.txt");
}

#[test]
fn parse_with_options_accepts_borrowed_bytes_and_options() {
    let bytes = fs::read(fixture("header_encrypted.rar")).unwrap();
    let archive =
        Archive::parse_with_options(&bytes, ArchiveReadOptions::with_password(b"password"))
            .unwrap();
    assert_eq!(archive.files().next().unwrap().name, b"hello.txt");
}

#[test]
fn parse_path_family_accepts_os_string_paths() {
    let path: std::ffi::OsString = fixture("empty_file.rar").into_os_string();
    let archive = Archive::parse_path(path.clone()).unwrap();
    assert_eq!(archive.files().count(), 1);

    let with_options =
        Archive::parse_path_with_options(path.clone(), ArchiveReadOptions::default()).unwrap();
    assert_eq!(with_options.files().count(), 1);

    let no_password = Archive::parse_path_with_password(path, None).unwrap();
    assert_eq!(no_password.files().count(), 1);
}

/// Members whose contents overlap heavily, and which together fit inside the
/// default dictionary, so a shared dictionary has something obvious to find.
fn solid_test_entries() -> Vec<rar50::ArchiveEntry> {
    let base: Vec<u8> = (0..800u32)
        .flat_map(|index| {
            let mut bytes = b"solid dictionary sharing payload ".to_vec();
            bytes.extend_from_slice(&index.to_le_bytes());
            bytes
        })
        .collect();

    (0..3u8)
        .map(|index| {
            rar50::ArchiveEntry::new(
                format!("member-{index}.bin").into_bytes(),
                rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(base.clone())),
            )
            .with_mtime(Some(0x5000_0000))
            .with_attributes(0x20)
        })
        .collect()
}

fn write_streaming(entries: &[rar50::ArchiveEntry], solid: bool) -> Vec<u8> {
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let mut out = Vec::new();
    rar50::write_streaming_archive_to(
        entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(3),
        rar50::ArchiveExtras::default(),
        &rars::WriterResources::default(),
        &mut out,
    )
    .unwrap();
    out
}

#[test]
fn streaming_solid_members_share_one_dictionary() {
    let entries = solid_test_entries();
    let solid = write_streaming(&entries, true);
    let independent = write_streaming(&entries, false);

    // Members two and three repeat member one, so a dictionary that carries
    // across members should collapse them almost entirely.
    assert!(
        solid.len() * 2 < independent.len(),
        "solid archive ({}) should be far smaller than independent members ({})",
        solid.len(),
        independent.len()
    );

    let archive = Archive::parse(&solid).unwrap();
    assert!(archive.main.is_solid(), "archive must be flagged solid");
    let solid_flags: Vec<bool> = archive
        .files()
        .map(|file| file.decoded_compression_info().unwrap().solid)
        .collect();
    assert_eq!(
        solid_flags,
        vec![false, true, true],
        "the first member starts the chain and the rest continue it"
    );
}

#[test]
fn streaming_solid_archives_round_trip() {
    let entries = solid_test_entries();
    let archive_bytes = write_streaming(&entries, true);
    let archive = Archive::parse(&archive_bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), entries.len());
    let expected = {
        let mut buffer = Vec::new();
        entries[0]
            .source
            .open()
            .unwrap()
            .read_to_end(&mut buffer)
            .unwrap();
        buffer
    };
    for (index, entry) in extracted.iter().enumerate() {
        assert_eq!(entry.name, format!("member-{index}.bin").into_bytes());
        assert_eq!(entry.data, expected, "member {index} did not survive");
    }
}

#[test]
fn streaming_solid_chains_history_across_block_and_member_boundaries() {
    // Members larger than the 1 MiB block size, so the dictionary has to carry
    // both from block to block and from member to member.
    let entries: Vec<_> = (0..3u8)
        .map(|index| {
            let mut data: Vec<u8> = (0..1_600_000u32)
                .map(|offset| (offset.wrapping_mul(2_654_435_761) >> 24) as u8)
                .collect();
            data[0] = index;
            rar50::ArchiveEntry::new(
                format!("big-{index}.bin").into_bytes(),
                rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data)),
            )
            .with_attributes(0x20)
        })
        .collect();

    let archive_bytes = write_streaming(&entries, true);
    let archive = Archive::parse(&archive_bytes).unwrap();
    let extracted = collect_extract(&archive).unwrap();

    assert_eq!(extracted.len(), 3);
    for (index, entry) in extracted.iter().enumerate() {
        let mut expected = Vec::new();
        entries[index]
            .source
            .open()
            .unwrap()
            .read_to_end(&mut expected)
            .unwrap();
        assert_eq!(entry.data, expected, "member {index} did not survive");
    }

    if let Some(output) = reference_test_archive("solid-multiblock", &archive_bytes) {
        assert!(
            output.status.success(),
            "the reference tool rejected a multi-block solid archive\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn streaming_solid_output_does_not_depend_on_the_memory_budget() {
    let entries = solid_test_entries();
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let options = rar50::WriterOptions::new(ArchiveVersion::Rar50, features);

    // The default budget compresses a couple of blocks at a time; the larger
    // one lets every core work at once.
    let mut tight = Vec::new();
    rar50::write_streaming_archive_to(
        &entries,
        options,
        rar50::ArchiveExtras::default(),
        &rars::WriterResources::default(),
        &mut tight,
    )
    .unwrap();

    let mut roomy = Vec::new();
    rar50::write_streaming_archive_to(
        &entries,
        options,
        rar50::ArchiveExtras::default(),
        &rars::WriterResources::new(4 * 1024 * 1024 * 1024),
        &mut roomy,
    )
    .unwrap();

    assert_eq!(
        tight, roomy,
        "the number of blocks compressed at once must not change the output"
    );
}

/// Tests an archive with whichever reference tool is installed, returning
/// `None` when neither is.
fn reference_test_archive(label: &str, archive: &[u8]) -> Option<std::process::Output> {
    let dir = scratch::case(&format!("rars-{label}"));
    let path = dir.join("archive.rar");
    fs::write(&path, archive).unwrap();

    let mut result = None;
    for tool in ["unrar", "rar"] {
        match Command::new(tool).arg("t").arg(&path).output() {
            Ok(output) => {
                result = Some(output);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("failed to run {tool}: {error}"),
        }
    }
    result
}

#[test]
#[ignore = "requires a local unrar or rar command"]
fn reference_rar_accepts_streaming_solid_archive() {
    let archive = write_streaming(&solid_test_entries(), true);
    let Some(output) = reference_test_archive("streaming-solid", &archive) else {
        eprintln!("skipping reference test: no unrar or rar command is installed");
        return;
    };

    assert!(
        output.status.success(),
        "the reference tool rejected the streaming solid archive\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The exact flag combination from issue #29, which used to abort trying to
/// allocate more than ten gigabytes.
#[test]
fn streaming_writer_handles_solid_encrypted_headers_and_recovery_together() {
    let entries: Vec<_> = (0..3u8)
        .map(|index| {
            let data: Vec<u8> = (0..900_000u32)
                .map(|offset| (offset.wrapping_mul(2_654_435_761) >> 25) as u8)
                .chain(std::iter::once(index))
                .collect();
            rar50::ArchiveEntry::new(
                format!("member-{index}.bin"),
                rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data)),
            )
            .with_attributes(0x20)
            .with_password(b"issue-29".to_vec())
        })
        .collect();

    let mut features = FeatureSet::store_only();
    features.solid = true;
    features.header_encryption = true;
    let options =
        rar50::WriterOptions::new(ArchiveVersion::Rar70, features).with_compression_level(5);

    // A budget far below the archive size: if anything buffered a member or
    // the archive, this could not succeed.
    let resources = rars::WriterResources::new(192 * 1024 * 1024);
    let mut archive_bytes = Vec::new();
    rar50::write_streaming_archive_to(
        &entries,
        options,
        rar50::ArchiveExtras::default().with_recovery_percent(Some(10)),
        &resources,
        &mut archive_bytes,
    )
    .unwrap();

    let archive = Archive::parse_with_options(
        &archive_bytes,
        ArchiveReadOptions::with_password(b"issue-29"),
    )
    .unwrap();
    assert!(archive.main.is_solid());
    assert!(archive.main.has_recovery_record());

    let extracted = collect_extract_with_password(&archive, Some(b"issue-29")).unwrap();
    assert_eq!(extracted.len(), 3);
    for (index, entry) in extracted.iter().enumerate() {
        let mut expected = Vec::new();
        entries[index]
            .source
            .open()
            .unwrap()
            .read_to_end(&mut expected)
            .unwrap();
        assert_eq!(entry.data, expected, "member {index} did not survive");
    }

    if let Some(output) =
        reference_test_archive_with_password("issue-29", &archive_bytes, "issue-29")
    {
        assert!(
            output.status.success(),
            "the reference tool rejected the archive\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // The recovery record has to be usable, not merely present.
    let data_range = archive.files().next().unwrap().block.data_range.clone();
    let mut damaged = archive_bytes.clone();
    damaged[data_range.start + 32..data_range.start + 512].fill(0xa5);

    let damaged_archive =
        Archive::parse_with_options(&damaged, ArchiveReadOptions::with_password(b"issue-29"))
            .unwrap();
    let mut repaired = Vec::new();
    damaged_archive.repair_recovery_to(&mut repaired).unwrap();
    assert_eq!(
        repaired, archive_bytes,
        "the recovery record should restore the archive exactly"
    );
}

fn reference_test_archive_with_password(
    label: &str,
    archive: &[u8],
    password: &str,
) -> Option<std::process::Output> {
    let dir = scratch::case(&format!("rars-{label}"));
    let path = dir.join("archive.rar");
    fs::write(&path, archive).unwrap();

    let mut result = None;
    for tool in ["unrar", "rar"] {
        match Command::new(tool)
            .arg("t")
            .arg(format!("-p{password}"))
            .arg(&path)
            .output()
        {
            Ok(output) => {
                result = Some(output);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("failed to run {tool}: {error}"),
        }
    }
    result
}

/// Generates deterministic incompressible bytes without holding them, so the
/// source itself does not dominate the memory being measured.
struct GeneratedSource {
    remaining: u64,
    state: u64,
}

impl std::io::Read for GeneratedSource {
    fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        let want = buffer.len().min(self.remaining as usize);
        for slot in buffer.iter_mut().take(want) {
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *slot = (self.state >> 33) as u8;
        }
        self.remaining -= want as u64;
        Ok(want)
    }
}

impl std::io::Seek for GeneratedSource {
    fn seek(&mut self, _: std::io::SeekFrom) -> IoResult<u64> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "generated sources are read once per pass",
        ))
    }
}

/// Writes an archive far larger than the memory budget it is given, with a
/// recovery record whose parity also exceeds that budget. Run with
/// `/usr/bin/time -v` to see the peak resident size.
#[test]
#[ignore = "writes a 300 MiB archive; run manually to measure peak memory"]
fn streaming_writer_stays_within_its_memory_budget_on_a_large_archive() {
    const MEMBER_BYTES: u64 = 300 * 1024 * 1024;
    const BUDGET: u64 = 128 * 1024 * 1024;

    let entry = rar50::ArchiveEntry::new(
        "large.bin",
        rars::EntrySource::from_opener(MEMBER_BYTES, || {
            Ok(Box::new(GeneratedSource {
                remaining: MEMBER_BYTES,
                state: 0x2545_f491_4f6c_dd1d,
            }))
        }),
    )
    .with_password(b"issue-29".to_vec());

    let mut features = FeatureSet::store_only();
    features.solid = true;
    features.header_encryption = true;
    let options =
        rar50::WriterOptions::new(ArchiveVersion::Rar70, features).with_compression_level(1);

    let dir = scratch::case("rars-large");
    let temp = dir.join("archive.rar");
    let mut output = fs::File::create(&temp).unwrap();
    // 50% recovery over a ~300 MiB archive needs more parity than the budget
    // allows to hold at once, which forces the striped recovery pass.
    rar50::write_streaming_archive_to(
        std::slice::from_ref(&entry),
        options,
        rar50::ArchiveExtras::default().with_recovery_percent(Some(50)),
        &rars::WriterResources::new(BUDGET).with_temp_dir(&*dir),
        &mut output,
    )
    .unwrap();
    drop(output);

    let written = fs::metadata(&temp).unwrap().len();
    assert!(
        written > MEMBER_BYTES,
        "a 50% recovery record should make the archive larger than its input"
    );
}

fn streaming_entry(name: &str, data: &[u8]) -> rar50::ArchiveEntry {
    rar50::ArchiveEntry::new(
        name,
        rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
    )
    .with_attributes(0x20)
}

fn write_with_extras(
    entries: &[rar50::ArchiveEntry],
    features: FeatureSet,
    extras: rar50::ArchiveExtras<'_>,
) -> Vec<u8> {
    let mut out = Vec::new();
    rar50::write_streaming_archive_to(
        entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(1),
        extras,
        &rars::WriterResources::default(),
        &mut out,
    )
    .unwrap();
    out
}

#[test]
fn streaming_writer_stores_an_archive_comment() {
    let entries = [streaming_entry("member.txt", b"comment carrier payload\n")];
    let features = FeatureSet::store_only();

    let bytes = write_with_extras(
        &entries,
        features,
        rar50::ArchiveExtras::default().with_comment(b"streamed archive comment"),
    );

    let archive = Archive::parse(&bytes).unwrap();
    let comment = archive
        .blocks
        .iter()
        .find_map(|block| match block {
            Block::Service(header) if header.name == b"CMT" => Some(header),
            _ => None,
        })
        .expect("archive has a comment service record");
    assert_eq!(comment.unpacked_size, 24);
    assert_eq!(collect_extract(&archive).unwrap().len(), 1);
}

#[test]
fn streaming_writer_records_archive_metadata() {
    let entries = [streaming_entry("member.txt", b"metadata carrier\n")];
    let bytes = write_with_extras(
        &entries,
        FeatureSet::store_only(),
        rar50::ArchiveExtras::default().with_metadata(rar50::ArchiveMetadataEntry {
            name: Some(b"original.rar"),
            creation_time: Some(0x01D9_0000_0000_0000),
        }),
    );

    let archive = Archive::parse(&bytes).unwrap();
    let metadata = archive
        .main
        .extras
        .iter()
        .find_map(|extra| match extra {
            rar50::MainExtraRecord::ArchiveMetadata(record) => Some(record),
            _ => None,
        })
        .expect("main header carries archive metadata");
    assert_eq!(metadata.name.as_deref(), Some(b"original.rar".as_slice()));
}

#[test]
fn streaming_writer_attaches_file_services() {
    let entries = [streaming_entry("member.txt", b"service carrier payload\n")
        .with_service(rar50::ServiceEntry::new("CMT", "a file comment"))];
    let features = FeatureSet::store_only();

    let bytes = write_with_extras(&entries, features, rar50::ArchiveExtras::default());
    let archive = Archive::parse(&bytes).unwrap();

    let services: Vec<_> = archive
        .blocks
        .iter()
        .filter_map(|block| match block {
            Block::Service(header) => Some(header.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(services, vec![b"CMT".to_vec()]);
    assert_eq!(collect_extract(&archive).unwrap().len(), 1);
}

#[test]
fn streaming_writer_writes_a_usable_quick_open_index() {
    let entries: Vec<_> = (0..4u8)
        .map(|index| {
            streaming_entry(
                &format!("member-{index}.txt"),
                format!("quick open payload {index}\n").repeat(8).as_bytes(),
            )
        })
        .collect();
    let mut features = FeatureSet::store_only();
    features.quick_open = true;

    // Asked for through the feature set alone, which is the only way to ask.
    // This used to say it twice, through an `ArchiveExtras` field as well, and
    // that is why it passed while the feature set on its own was being dropped.
    let bytes = write_with_extras(&entries, features, rar50::ArchiveExtras::default());

    let archive = Archive::parse(&bytes).unwrap();
    assert!(
        archive
            .blocks
            .iter()
            .any(|block| matches!(block, Block::Service(header) if header.name == b"QO")),
        "archive has a quick-open index"
    );
    assert_eq!(collect_extract(&archive).unwrap().len(), 4);

    if let Some(output) = reference_test_archive("streaming-quick-open", &bytes) {
        assert!(
            output.status.success(),
            "the reference tool rejected the quick-open archive\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn streaming_writer_applies_filters_when_asked() {
    // x86-shaped data, which the E8 filter is meant to help with.
    let mut data = Vec::new();
    for index in 0..20_000u32 {
        data.push(0xe8);
        data.extend_from_slice(&index.to_le_bytes());
        data.extend_from_slice(b"\x55\x89\xe5");
    }
    let entries = [streaming_entry("program.bin", &data)];

    let plain = write_with_extras(
        &entries,
        FeatureSet::store_only(),
        rar50::ArchiveExtras::default(),
    );
    let filtered = write_with_extras(
        &entries,
        FeatureSet::store_only(),
        rar50::ArchiveExtras::default().with_filter_policy(rar50::FilterPolicy::Auto),
    );

    assert!(
        filtered.len() < plain.len(),
        "the filter should pay for itself: {} filtered vs {} plain",
        filtered.len(),
        plain.len()
    );

    let archive = Archive::parse(&filtered).unwrap();
    assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
}

#[test]
fn streaming_writer_drops_an_automatic_filter_it_cannot_afford() {
    // Too large to hold whole under this budget, so the filter is skipped
    // rather than the write failing.
    let data = vec![0xe8u8; 8 * 1024 * 1024];
    let entries = [streaming_entry("large.bin", &data)];

    let mut out = Vec::new();
    rar50::write_streaming_archive_to(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(1),
        rar50::ArchiveExtras::default().with_filter_policy(rar50::FilterPolicy::Auto),
        &rars::WriterResources::new(160 * 1024 * 1024),
        &mut out,
    )
    .unwrap();

    let archive = Archive::parse(&out).unwrap();
    assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
}

/// Barely compressible bytes, so the packed payload stays big enough to span
/// several volumes.
fn volume_payload(len: u32) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

/// What the capability table says about a RAR 5 volume set has to be what the
/// volume writer does.
///
/// The table used to promise comments, metadata and quick-open for split RAR 5
/// sets while the writer refused all three, so refusals for other formats sent
/// people to rar50 and rar50 failed too. The matrix test in write_plan.rs
/// compares `supports` with `validate_plan`, which are two halves of the same
/// table; nothing compared either with the writer.
#[test]
fn the_volume_writer_refuses_exactly_what_the_table_refuses() {
    use rars::WriterOption;

    let payload = volume_payload(40_000);
    let entries = [streaming_entry("member.bin", &payload)];
    let shape = rars::PlanShape::new().compressed(true).volumes(true);

    for option in [
        WriterOption::ArchiveComment,
        WriterOption::ArchiveMetadata,
        WriterOption::FileComment,
        WriterOption::Feature(rars::Feature::QuickOpen),
        WriterOption::RecoveryRecord,
    ] {
        let mut features = FeatureSet::store_only();
        let mut extras = rar50::ArchiveExtras::default();
        let mut entries = entries.clone();
        match option {
            WriterOption::ArchiveComment => extras = extras.with_comment(b"comment"),
            WriterOption::ArchiveMetadata => {
                extras = extras.with_metadata(rar50::ArchiveMetadataEntry {
                    name: Some(b"set.rar"),
                    creation_time: Some(0x01dc_d60e_662d_7a32),
                })
            }
            WriterOption::FileComment => {
                entries[0] = entries[0]
                    .clone()
                    .with_service(rar50::ServiceEntry::new(b"CMT".to_vec(), b"note".to_vec()))
            }
            WriterOption::Feature(rars::Feature::QuickOpen) => features.quick_open = true,
            WriterOption::RecoveryRecord => extras = extras.with_recovery_percent(Some(5)),
            _ => unreachable!("every option in the list above is handled"),
        }

        let mut sink = rar50::CollectedVolumes::new();
        let result = rar50::write_streaming_volumes_to(
            &entries,
            rar50::WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(1),
            extras,
            20_000,
            &mut sink,
            &rars::WriterResources::default(),
        );

        assert_eq!(
            result.is_ok(),
            rars::supports(ArchiveVersion::Rar50, option, shape),
            "{option:?}: the table and the volume writer disagree, writer said {result:?}"
        );
    }
}

/// A file comment on a volume set was validated with the member and then
/// dropped: `prepare_volume_member` never reads an entry's services, so the
/// comment appeared in no volume and the write reported success.
///
/// Asserting the refusal alone would not have caught it, because the
/// capability table agreed with the writer that it was supported. What the
/// writer must never do is accept the request and lose it.
#[test]
fn a_file_comment_on_a_volume_set_is_refused_or_written() {
    let payload = volume_payload(40_000);
    let entries = [
        streaming_entry("member.bin", &payload).with_service(rar50::ServiceEntry::new(
            b"CMT".to_vec(),
            b"volume note".to_vec(),
        )),
    ];

    let mut sink = rar50::CollectedVolumes::new();
    let result = rar50::write_streaming_volumes_to(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(1),
        rar50::ArchiveExtras::default(),
        20_000,
        &mut sink,
        &rars::WriterResources::default(),
    );

    if result.is_err() {
        return;
    }
    let volumes = sink.take();
    let found = volumes.iter().any(|volume| {
        Archive::parse(volume)
            .is_ok_and(|archive| archive.services().any(|service| service.name == b"CMT"))
    });
    assert!(
        found,
        "the write was accepted, so the comment has to be in one of the {} volumes",
        volumes.len()
    );
}

/// A set with no members used to report success while writing no volumes at
/// all: the member loop never ran, and the writer finished without asking the
/// sink to start one. The volume writer that was deleted refused this.
#[test]
fn a_volume_set_with_no_members_is_refused() {
    let mut sink = rar50::CollectedVolumes::new();
    let result = rar50::write_streaming_volumes_to(
        &[],
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        rar50::ArchiveExtras::default(),
        20_000,
        &mut sink,
        &rars::WriterResources::default(),
    );

    assert!(result.is_err(), "an empty set reported success");
    assert!(sink.take().is_empty());
}

/// Solid members are coded as one chain, so the filter search never runs for
/// them. Both entry points have to say so; the archive path used to and the
/// volume path silently dropped the request.
#[test]
fn both_rar50_entry_points_refuse_a_filter_with_solid() {
    let payload = volume_payload(40_000);
    let entries = [streaming_entry("member.bin", &payload)];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let options =
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(1);
    let extras = || {
        rar50::ArchiveExtras::default().with_filter_policy(rar50::FilterPolicy::Explicit(
            rars::FilterSpec::whole(rars::FilterKind::E8),
        ))
    };

    let mut sink = rar50::CollectedVolumes::new();
    let volumes = rar50::write_streaming_volumes_to(
        &entries,
        options,
        extras(),
        20_000,
        &mut sink,
        &rars::WriterResources::default(),
    );
    let mut out = Vec::new();
    let archive = rar50::write_streaming_archive_to(
        &entries,
        options,
        extras(),
        &rars::WriterResources::default(),
        &mut out,
    );

    assert!(
        volumes.is_err(),
        "the volume path took the filter and dropped it"
    );
    assert!(archive.is_err());
}

fn write_volume_set(
    entries: &[rar50::ArchiveEntry],
    features: FeatureSet,
    extras: rar50::ArchiveExtras<'_>,
    max_payload: u64,
) -> Vec<Vec<u8>> {
    let mut sink = rar50::CollectedVolumes::new();
    rar50::write_streaming_volumes_to(
        entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(1),
        extras,
        max_payload,
        &mut sink,
        &rars::WriterResources::default(),
    )
    .unwrap();
    sink.take()
}

/// A volume set used to report nothing at all: the writer built its plan with
/// `progress: None` and its compression stage was called without the callback
/// the single-archive path uses.
#[test]
fn a_volume_set_reports_compression_progress() {
    use rars::{WriteOperation, WriteProgressEvent};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    // Blocks are a megabyte, so three of them is what proves the reporting is
    // incremental rather than one jump at the end.
    let payload = volume_payload(3 * 1024 * 1024);
    let entries = [streaming_entry("progress.bin", &payload)];

    let started = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let last = AtomicU64::new(0);
    let advances = AtomicU64::new(0);
    let reporter = |event: WriteProgressEvent<'_>| match event {
        WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Compression,
            total_bytes,
            ..
        } => {
            assert_eq!(total_bytes, Some(payload.len() as u64));
            started.store(true, Ordering::Relaxed);
        }
        WriteProgressEvent::Advanced {
            operation: WriteOperation::Compression,
            completed_bytes,
            total_bytes,
            ..
        } => {
            assert!(completed_bytes >= last.swap(completed_bytes, Ordering::Relaxed));
            assert!(completed_bytes <= total_bytes);
            advances.fetch_add(1, Ordering::Relaxed);
        }
        WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Compression,
            ..
        } => finished.store(true, Ordering::Relaxed),
        _ => {}
    };

    let mut sink = rar50::CollectedVolumes::new();
    rar50::write_streaming_volumes_with_progress(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(1),
        rar50::ArchiveExtras::default(),
        900_000,
        &mut sink,
        &rars::WriterResources::default(),
        Some(&reporter),
    )
    .unwrap();

    assert!(started.load(Ordering::Relaxed), "no operation start");
    assert!(finished.load(Ordering::Relaxed), "no operation finish");
    assert!(
        advances.load(Ordering::Relaxed) >= 3,
        "expected a report per block, got {}",
        advances.load(Ordering::Relaxed)
    );
    assert_eq!(last.load(Ordering::Relaxed), payload.len() as u64);
    assert!(sink.take().len() > 1);
}

#[test]
fn streaming_volume_set_round_trips() {
    let payload = volume_payload(120_000);
    let entries = [streaming_entry("split.bin", &payload)];

    let volumes = write_volume_set(
        &entries,
        FeatureSet::store_only(),
        rar50::ArchiveExtras::default(),
        20_000,
    );
    assert!(volumes.len() > 2, "expected several volumes");

    let archives: Vec<_> = volumes
        .iter()
        .map(|bytes| Archive::parse(bytes).unwrap())
        .collect();
    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn streaming_volume_set_carries_encryption_across_splits() {
    let payload = volume_payload(90_000);
    let entries = [streaming_entry("secret.bin", &payload).with_password(b"volume-pass".to_vec())];
    let features = FeatureSet::store_only();

    // A payload size that is not a multiple of the cipher block, so splits
    // land mid-block.
    let volumes = write_volume_set(&entries, features, rar50::ArchiveExtras::default(), 12_345);
    assert!(volumes.len() > 2);

    let archives: Vec<_> = volumes
        .iter()
        .map(|bytes| {
            Archive::parse_with_options(bytes, ArchiveReadOptions::with_password(b"volume-pass"))
                .unwrap()
        })
        .collect();
    let extracted = collect_extract_volumes_with_password(&archives, Some(b"volume-pass")).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn streaming_volume_set_recovers_each_volume() {
    let payload = volume_payload(80_000);
    let entries = [streaming_entry("protected.bin", &payload)];
    let features = FeatureSet::store_only();

    let volumes = write_volume_set(
        &entries,
        features,
        rar50::ArchiveExtras::default().with_recovery_percent(Some(20)),
        30_000,
    );
    assert!(volumes.len() > 1);

    // Damage the first volume's payload and repair it from its own record.
    let clean = Archive::parse(&volumes[0]).unwrap();
    let data_range = clean.files().next().unwrap().block.data_range.clone();
    let mut damaged = volumes[0].clone();
    damaged[data_range.start + 16..data_range.start + 200].fill(0xa5);

    let damaged_archive = Archive::parse(&damaged).unwrap();
    let mut repaired = Vec::new();
    damaged_archive.repair_recovery_to(&mut repaired).unwrap();
    assert_eq!(repaired, volumes[0]);
}

#[test]
#[ignore = "requires a local unrar or rar command"]
fn reference_rar_accepts_a_streaming_volume_set() {
    let payload = volume_payload(150_000);
    let entries = [streaming_entry("split.bin", &payload)];
    let volumes = write_volume_set(
        &entries,
        FeatureSet::store_only(),
        rar50::ArchiveExtras::default(),
        25_000,
    );
    assert!(volumes.len() > 2);

    let dir = scratch::case("rars-volset");
    for (index, volume) in volumes.iter().enumerate() {
        fs::write(dir.join(format!("set.part{:02}.rar", index + 1)), volume).unwrap();
    }

    let first = dir.join("set.part01.rar");
    let mut result = None;
    for tool in ["unrar", "rar"] {
        match Command::new(tool).arg("t").arg(&first).output() {
            Ok(output) => {
                result = Some(output);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("failed to run {tool}: {error}"),
        }
    }
    let Some(output) = result else {
        eprintln!("skipping reference test: no unrar or rar command is installed");
        return;
    };
    assert!(
        output.status.success(),
        "the reference tool rejected the volume set\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn zero_fill_payload() -> Vec<u8> {
    let mut expected = vec![0u8; 8];
    for _ in 0..8 {
        expected.extend_from_slice(b"zero-fill regression payload ");
    }
    expected
}

#[test]
fn extracts_rar50_match_that_reaches_past_the_start_of_the_window() {
    let bytes = std::fs::read(fixture("zero_fill_out_of_window.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();

    let entry = collect_file(&archive, file).unwrap();

    assert_eq!(entry.name, b"zerofill.bin");
    assert_eq!(entry.data, zero_fill_payload());
}

#[test]
fn streams_rar50_match_that_reaches_past_the_start_of_the_window() {
    let bytes = std::fs::read(fixture("zero_fill_out_of_window.rar")).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let entries = RefCell::new(Vec::new());

    extract_volumes_to(
        std::slice::from_ref(&archive),
        ArchiveReadOptions::default().with_rar50_buffered_decode_limit(0),
        |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries
                .borrow_mut()
                .push((meta.name.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        },
    )
    .unwrap();

    let entries = entries.into_inner();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, b"zerofill.bin");
    assert_eq!(*entries[0].1.borrow(), zero_fill_payload());
}

/// The KDF count byte from the archive encryption header, which sits in the
/// clear right after the marker: CRC32, then vints for header size, type 4,
/// header flags, encryption version and encryption flags, then the byte.
fn head_crypt_kdf_count(bytes: &[u8]) -> u8 {
    let mut pos = 8 + 4;
    let read_vint = |pos: &mut usize| {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = bytes[*pos];
            *pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return value;
            }
        }
    };
    read_vint(&mut pos); // header size
    assert_eq!(read_vint(&mut pos), 4, "first block is not HEAD_CRYPT");
    read_vint(&mut pos); // header flags
    assert_eq!(read_vint(&mut pos), 0, "unexpected encryption version");
    read_vint(&mut pos); // encryption flags
    bytes[pos]
}
