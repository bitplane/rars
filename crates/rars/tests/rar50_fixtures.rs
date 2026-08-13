use rars::codec::rar50::{
    decode_lz, encode_lz_member, parse_compressed_block, read_table_lengths, DecodeTables,
};
use rars::crc32::crc32;
use rars::crypto::rar50::{Rar50Cipher, Rar50Keys};
use rars::rar50::{
    extract_volumes_to, repair_inline_recovery_bytes, repair_rev5_volumes_to, Archive,
    ArchiveMetadataEntry, Block, EncryptedArchiveCommentEntry, EncryptedCompressedEntry,
    EncryptedStoredEntry, EncryptedStoredEntryWithServices, EncryptedStoredServiceEntry,
    FilterKind, FilterPolicy, Rev5Volume, Rev5VolumeMeta, StoredEntryWithServices,
    StoredServiceEntry,
};
use rars::recovery::rar5::crc64_xz;
use rars::{
    detect_archive_family, rar50, ArchiveFamily, ArchiveReadOptions, ArchiveVersion, Error,
    FeatureSet,
};
use std::cell::RefCell;
use std::fs;
use std::io::{Result as IoResult, Write};
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
    assert_eq!(end.header_type, 5);
    assert_eq!(
        end.header_size, 3,
        "RAR 5 end header must include End of Archive Flags vint"
    );
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

fn write_stored_archive(
    entries: &[rar50::StoredEntry<'_>],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .stored_entries(entries)
        .finish()
}

fn write_stored_archive_with_comment(
    entries: &[rar50::StoredEntry<'_>],
    options: rar50::WriterOptions,
    archive_comment: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .stored_entries(entries)
        .archive_comment(archive_comment)
        .finish()
}

fn write_stored_archive_with_comment_and_metadata(
    entries: &[rar50::StoredEntry<'_>],
    options: rar50::WriterOptions,
    archive_comment: Option<&[u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .stored_entries(entries)
        .archive_comment(archive_comment)
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_stored_archive_with_recovery(
    entries: &[rar50::StoredEntry<'_>],
    options: rar50::WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .stored_entries(entries)
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_stored_archive_with_file_services(
    entries: &[StoredEntryWithServices<'_>],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .stored_entries_with_services(entries)
        .finish()
}

fn write_compressed_archive(
    entries: &[rar50::CompressedEntry<'_>],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .compressed_entries(entries)
        .finish()
}

fn write_compressed_archive_with_metadata(
    entries: &[rar50::CompressedEntry<'_>],
    options: rar50::WriterOptions,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .compressed_entries(entries)
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_compressed_archive_with_comment_and_metadata(
    entries: &[rar50::CompressedEntry<'_>],
    options: rar50::WriterOptions,
    archive_comment: Option<&[u8]>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .compressed_entries(entries)
        .archive_comment(archive_comment)
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_compressed_archive_with_recovery(
    entries: &[rar50::CompressedEntry<'_>],
    options: rar50::WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .compressed_entries(entries)
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_compressed_archive_with_filter_policy(
    entries: &[rar50::CompressedEntry<'_>],
    options: rar50::WriterOptions,
    policy: FilterPolicy,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .compressed_entries(entries)
        .filter_policy(policy)
        .finish()
}

fn write_encrypted_stored_archive(
    entries: &[EncryptedStoredEntry<'_>],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_stored_entries(entries)
        .finish()
}

fn write_encrypted_stored_archive_with_comment(
    entries: &[EncryptedStoredEntry<'_>],
    options: rar50::WriterOptions,
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_stored_entries(entries)
        .encrypted_archive_comment(archive_comment)
        .finish()
}

fn write_encrypted_stored_archive_with_comment_and_metadata(
    entries: &[EncryptedStoredEntry<'_>],
    options: rar50::WriterOptions,
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_stored_entries(entries)
        .encrypted_archive_comment(archive_comment)
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_encrypted_stored_archive_with_file_services(
    entries: &[EncryptedStoredEntryWithServices<'_>],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_stored_entries_with_services(entries)
        .finish()
}

fn write_encrypted_stored_archive_with_recovery(
    entries: &[EncryptedStoredEntry<'_>],
    options: rar50::WriterOptions,
    recovery_percent: u64,
    recovery_password: &[u8],
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_stored_entries(entries)
        .recovery_percent(Some(recovery_percent))
        .recovery_password(Some(recovery_password))
        .finish()
}

fn write_encrypted_compressed_archive(
    entries: &[EncryptedCompressedEntry<'_>],
    options: rar50::WriterOptions,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_compressed_entries(entries)
        .finish()
}

fn write_encrypted_compressed_archive_with_metadata(
    entries: &[EncryptedCompressedEntry<'_>],
    options: rar50::WriterOptions,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_compressed_entries(entries)
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_encrypted_compressed_archive_with_comment_and_metadata(
    entries: &[EncryptedCompressedEntry<'_>],
    options: rar50::WriterOptions,
    archive_comment: Option<EncryptedArchiveCommentEntry<'_>>,
    archive_metadata: Option<ArchiveMetadataEntry<'_>>,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_compressed_entries(entries)
        .encrypted_archive_comment(archive_comment)
        .archive_metadata(archive_metadata)
        .finish()
}

fn write_encrypted_compressed_archive_with_recovery(
    entries: &[EncryptedCompressedEntry<'_>],
    options: rar50::WriterOptions,
    recovery_percent: u64,
) -> Result<Vec<u8>, Error> {
    rar50::Rar50Writer::new(options)
        .encrypted_compressed_entries(entries)
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_stored_volumes(
    entry: rar50::StoredEntry<'_>,
    options: rar50::WriterOptions,
    max_data_per_volume: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .stored_entry(entry)
        .max_payload_per_volume(max_data_per_volume)
        .finish()
}

fn write_stored_volumes_with_recovery(
    entry: rar50::StoredEntry<'_>,
    options: rar50::WriterOptions,
    max_data_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .stored_entry(entry)
        .max_payload_per_volume(max_data_per_volume)
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_compressed_volumes(
    entry: rar50::CompressedEntry<'_>,
    options: rar50::WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .compressed_entries(std::slice::from_ref(&entry))
        .max_payload_per_volume(max_packed_per_volume)
        .finish()
}

fn write_compressed_volume_set(
    entries: &[rar50::CompressedEntry<'_>],
    options: rar50::WriterOptions,
    max_packed_per_volume: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .compressed_entries(entries)
        .max_payload_per_volume(max_packed_per_volume)
        .finish()
}

fn write_compressed_volume_set_with_recovery(
    entries: &[rar50::CompressedEntry<'_>],
    options: rar50::WriterOptions,
    max_packed_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .compressed_entries(entries)
        .max_payload_per_volume(max_packed_per_volume)
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_encrypted_stored_volumes(
    entry: EncryptedStoredEntry<'_>,
    options: rar50::WriterOptions,
    max_encrypted_per_volume: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .encrypted_stored_entry(entry)
        .max_payload_per_volume(max_encrypted_per_volume)
        .finish()
}

fn write_encrypted_stored_volumes_with_recovery(
    entry: EncryptedStoredEntry<'_>,
    options: rar50::WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .encrypted_stored_entry(entry)
        .max_payload_per_volume(max_encrypted_per_volume)
        .recovery_percent(Some(recovery_percent))
        .finish()
}

fn write_encrypted_compressed_volumes(
    entry: EncryptedCompressedEntry<'_>,
    options: rar50::WriterOptions,
    max_encrypted_per_volume: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .encrypted_compressed_entries(std::slice::from_ref(&entry))
        .max_payload_per_volume(max_encrypted_per_volume)
        .finish()
}

fn write_encrypted_compressed_volume_set(
    entries: &[EncryptedCompressedEntry<'_>],
    options: rar50::WriterOptions,
    max_encrypted_per_volume: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .encrypted_compressed_entries(entries)
        .max_payload_per_volume(max_encrypted_per_volume)
        .finish()
}

fn write_encrypted_compressed_volume_set_with_recovery(
    entries: &[EncryptedCompressedEntry<'_>],
    options: rar50::WriterOptions,
    max_encrypted_per_volume: usize,
    recovery_percent: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    rar50::Rar50VolumeWriter::new(options)
        .encrypted_compressed_entries(entries)
        .max_payload_per_volume(max_encrypted_per_volume)
        .recovery_percent(Some(recovery_percent))
        .finish()
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
        let body_size = read_test_vint(data, &mut offset) as usize;
        let body = &data[offset..offset + body_size];
        assert_eq!(crc32(body), expected);
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
        rar50::StoredEntry {
            name: b"hello5.txt",
            data: b"hello from rars rar5 writer\n",
            mtime: Some(0x5a21_0000),
            attributes: 0x20,
            host_os: 3,
        },
        rar50::StoredEntry {
            name: b"empty.bin",
            data: b"",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        },
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
    assert_eq!(files[0].data_crc32, Some(crc32(entries[0].data)));
    assert_eq!(files[1].data_crc32, Some(crc32(entries[1].data)));
    assert_eq!(files[0].hash.as_ref().unwrap().hash_type, 0);
    assert_eq!(files[0].hash.as_ref().unwrap().data.len(), 32);
    files[0].verify_hash(entries[0].data).unwrap();

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, entries[0].name);
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[0].file_time, 0x5a21_0000);
    assert_eq!(extracted[1].name, entries[1].name);
    assert_eq!(extracted[1].data, entries[1].data);
}

#[test]
fn rar50_writer_builder_writes_stored_archive_with_comment_and_metadata() {
    let entries = [rar50::StoredEntry {
        name: b"builder-stored.txt",
        data: b"stored through the resolved writer builder\n",
        mtime: None,
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.archive_comment = true;
    let bytes = rar50::Rar50Writer::new(rar50::WriterOptions::new(ArchiveVersion::Rar70, features))
        .stored_entries(&entries)
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
    assert_eq!(collect_extract(&archive).unwrap()[0].data, entries[0].data);
}

#[test]
fn writes_compressed_rar50_archive_that_reader_extracts() {
    let entries = [
        rar50::CompressedEntry {
            name: b"compressed.txt",
            data: b"hello from rars rar5 compressed writer\nhello again\n",
            mtime: Some(0x5a21_0001),
            attributes: 0x20,
            host_os: 3,
        },
        rar50::CompressedEntry {
            name: b"empty.bin",
            data: b"",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        },
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
    assert_eq!(files[0].data_crc32, Some(crc32(entries[0].data)));

    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].name, entries[0].name);
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[0].file_time, 0x5a21_0001);
    assert_eq!(extracted[1].name, entries[1].name);
    assert_eq!(extracted[1].data, entries[1].data);
}

#[test]
fn compressed_rar50_writer_stores_member_when_lz_payload_would_grow() {
    let data = deterministic_noise(8192);
    assert!(encode_lz_member(&data, 0).unwrap().len() >= data.len());
    for target in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let entries = [rar50::CompressedEntry {
            name: b"incompressible.bin",
            data: &data,
            mtime: Some(0x5a21_00a0),
            attributes: 0x20,
            host_os: 3,
        }];
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
        let entries = [rar50::CompressedEntry {
            name: b"level-zero.txt",
            data: &data,
            mtime: Some(0x5a21_00a2),
            attributes: 0x20,
            host_os: 3,
        }];
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
        let entries = [rar50::CompressedEntry {
            name: b"level-sensitive.bin",
            data: &data,
            mtime: Some(0x5a21_00a4),
            attributes: 0x20,
            host_os: 3,
        }];
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
            let entries = [rar50::CompressedEntry {
                name: b"level-method.bin",
                data: &data,
                mtime: Some(0x5a21_00a4),
                attributes: 0x20,
                host_os: 3,
            }];
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
    let entries = [rar50::CompressedEntry {
        name: b"builder-filtered.bin",
        data: &payload,
        mtime: None,
        attributes: 0x20,
        host_os: 3,
    }];
    let bytes = rar50::Rar50Writer::new(rar50::WriterOptions::new(
        ArchiveVersion::Rar50,
        FeatureSet::store_only(),
    ))
    .compressed_entries(&entries)
    .filter_policy(FilterPolicy::Explicit(rar50::FilterKind::E8))
    .finish()
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    assert_eq!(collect_extract(&archive).unwrap()[0].data, entries[0].data);
}

#[test]
fn writes_solid_compressed_rar50_archive_that_reader_extracts() {
    let first = b"rar50 solid shared phrase alpha beta gamma\n".repeat(32);
    let second = b"rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
    let entries = [
        rar50::CompressedEntry {
            name: b"solid-one.txt",
            data: &first,
            mtime: Some(0x5a21_0021),
            attributes: 0x20,
            host_os: 3,
        },
        rar50::CompressedEntry {
            name: b"solid-two.txt",
            data: &second,
            mtime: Some(0x5a21_0022),
            attributes: 0x20,
            host_os: 3,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let solid = write_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let standalone_second = write_compressed_archive(
        &[entries[1]],
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
    let entries = [rar50::CompressedEntry {
        name: b"delta-filtered.bin",
        data: &data,
        mtime: Some(0x5a21_0023),
        attributes: 0x20,
        host_os: 3,
    }];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::Explicit(FilterKind::Delta { channels: 3 }),
    )
    .unwrap();

    let archive = Archive::parse(&bytes).unwrap();
    let file = archive.files().next().unwrap();
    assert_eq!(file.decoded_compression_info().unwrap().method, 1);
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
    let entries = [rar50::CompressedEntry {
        name: b"e8-filtered.bin",
        data: &data,
        mtime: Some(0x5a21_0024),
        attributes: 0x20,
        host_os: 3,
    }];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::Explicit(FilterKind::E8),
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
    let entries = [rar50::CompressedEntry {
        name: b"e8e9-filtered.bin",
        data: &data,
        mtime: Some(0x5a21_0025),
        attributes: 0x20,
        host_os: 3,
    }];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::Explicit(FilterKind::E8E9),
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
    let entries = [rar50::CompressedEntry {
        name: b"arm-filtered.bin",
        data: &data,
        mtime: Some(0x5a21_0026),
        attributes: 0x20,
        host_os: 3,
    }];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::Explicit(FilterKind::Arm),
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
    let entries = [rar50::CompressedEntry {
        name: b"auto-filtered.bin",
        data: &data,
        mtime: Some(0x5a21_0027),
        attributes: 0x20,
        host_os: 3,
    }];
    let options = rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
    let plain = write_compressed_archive(&entries, options).unwrap();
    let auto =
        write_compressed_archive_with_filter_policy(&entries, options, FilterPolicy::AutoSize)
            .unwrap();

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
    let entries = [rar50::CompressedEntry {
        name: b"afile.txt",
        data: b"",
        mtime: Some(0x5a21_0028),
        attributes: 0x20,
        host_os: 3,
    }];
    let bytes = write_compressed_archive_with_filter_policy(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        FilterPolicy::AutoSize,
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
    let entry = rar50::CompressedEntry {
        name: b"compressed-split.txt",
        data: &payload,
        mtime: Some(0x5a21_0002),
        attributes: 0x20,
        host_os: 3,
    };
    let parts = write_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        32,
    )
    .unwrap();

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
    assert_eq!(last.decoded_compression_info().unwrap().method, 1);
    assert!(last.hash.is_some());

    let extracted = collect_extract_volumes_with_password(&archives, Some(b"password")).unwrap();
    assert_eq!(extracted[0].name, b"compressed-split.txt");
    assert_eq!(extracted[0].data, payload);
    assert_eq!(extracted[0].file_time, 0x5a21_0002);
}

#[test]
fn compressed_rar50_volume_writer_stores_member_when_lz_payload_would_grow() {
    let data = deterministic_noise(8192);
    assert!(encode_lz_member(&data, 0).unwrap().len() >= data.len());
    let entry = rar50::CompressedEntry {
        name: b"incompressible-split.bin",
        data: &data,
        mtime: Some(0x5a21_00a2),
        attributes: 0x20,
        host_os: 3,
    };
    let parts = write_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        1024,
    )
    .unwrap();

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
    let entry = rar50::CompressedEntry {
        name: b"compressed-split-rr.txt",
        data: &payload,
        mtime: Some(0x5a21_0002),
        attributes: 0x20,
        host_os: 3,
    };
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
    let parts = write_compressed_volume_set_with_recovery(
        &[entry],
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        8,
    )
    .unwrap();

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
    let entry = rar50::CompressedEntry {
        name: b"solid-compressed-split.txt",
        data: &payload,
        mtime: Some(0x5a21_0003),
        attributes: 0x20,
        host_os: 3,
    };
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let parts = write_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
    )
    .unwrap();

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
        rar50::CompressedEntry {
            name: b"solid-split-one.txt",
            data: &first,
            mtime: Some(0x5a21_0011),
            attributes: 0x20,
            host_os: 3,
        },
        rar50::CompressedEntry {
            name: b"solid-split-two.txt",
            data: &second,
            mtime: Some(0x5a21_0012),
            attributes: 0x20,
            host_os: 3,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let parts = write_compressed_volume_set(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
    )
    .unwrap();

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
    let entries = [rar50::StoredEntry {
        name: b"payload.txt",
        data: b"payload with comment service\n",
        mtime: None,
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.archive_comment = true;
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_compressed_rar50_archive_comment_service_record() {
    let payload = b"compressed payload with archive comment\n".repeat(8);
    let entries = [rar50::CompressedEntry {
        name: b"compressed-comment.txt",
        data: &payload,
        mtime: None,
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.archive_comment = true;
    let bytes = write_compressed_archive_with_comment_and_metadata(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(b"compressed RAR5 comment from rars\n"),
        None,
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

#[test]
fn writes_rar50_quick_open_service_record() {
    let entries = [
        rar50::StoredEntry {
            name: b"first.txt",
            data: b"first quick-open payload\n",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        },
        rar50::StoredEntry {
            name: b"second.txt",
            data: b"second quick-open payload\n",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.archive_comment = true;
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
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[1].data, entries[1].data);
}

#[test]
fn writes_rar50_acl_and_stream_file_service_records() {
    let services = [
        StoredServiceEntry {
            name: b"ACL",
            data: b"opaque acl descriptor",
        },
        StoredServiceEntry {
            name: b"STM",
            data: b"named stream bytes",
        },
    ];
    let entries = [StoredEntryWithServices {
        entry: rar50::StoredEntry {
            name: b"serviced.txt",
            data: b"payload with attached services\n",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        },
        services: &services,
    }];
    let bytes = write_stored_archive_with_file_services(
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
    let services = [StoredServiceEntry {
        name: b"CMT",
        data: b"RAR5 file comment from rars\n",
    }];
    let entries = [StoredEntryWithServices {
        entry: rar50::StoredEntry {
            name: b"file-commented.txt",
            data: b"payload with attached file comment\n",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        },
        services: &services,
    }];
    let bytes = write_stored_archive_with_file_services(
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

#[test]
fn writes_encrypted_rar50_file_comment_service_record() {
    let services = [EncryptedStoredServiceEntry {
        name: b"CMT",
        data: b"encrypted RAR5 file comment from rars\n",
        password: b"secret",
    }];
    let entries = [EncryptedStoredEntryWithServices {
        entry: EncryptedStoredEntry {
            name: b"encrypted-file-commented.txt",
            data: b"encrypted payload with attached file comment\n",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"secret",
        },
        services: &services,
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.file_comment = true;
    let bytes = write_encrypted_stored_archive_with_file_services(
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
    let services = [EncryptedStoredServiceEntry {
        name: b"CMT",
        data: b"header encrypted RAR5 file comment from rars\n",
        password: b"secret",
    }];
    let entries = [EncryptedStoredEntryWithServices {
        entry: EncryptedStoredEntry {
            name: b"header-encrypted-file-commented.txt",
            data: b"header encrypted payload with attached file comment\n",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"secret",
        },
        services: &services,
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.file_comment = true;
    let bytes = write_encrypted_stored_archive_with_file_services(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    assert!(matches!(Archive::parse(&bytes), Err(Error::NeedPassword)));
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
    let services = [
        StoredServiceEntry {
            name: b"ACL",
            data: b"opaque acl descriptor",
        },
        StoredServiceEntry {
            name: b"STM",
            data: b"named stream bytes",
        },
    ];
    let entries = [StoredEntryWithServices {
        entry: rar50::StoredEntry {
            name: b"serviced.txt",
            data: b"payload with attached services\n",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        },
        services: &services,
    }];
    let bytes = write_stored_archive_with_file_services(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
    )
    .unwrap();

    let path = std::env::temp_dir().join(format!(
        "rars-rar50-file-services-{}.rar",
        std::process::id()
    ));
    fs::write(&path, bytes).unwrap();
    let output = match Command::new("rar").arg("t").arg(&path).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping reference test: local `rar` command is not installed");
            return;
        }
        Err(error) => panic!("failed to run rar: {error}"),
    };
    if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
        let _ = fs::remove_file(&path);
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
    let entries = [rar50::StoredEntry {
        name: b"recoverable.txt",
        data: b"payload with structural recovery service\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn repairs_rar50_inline_recovery_payload_damage() {
    let payload = b"payload with structural recovery service\n".repeat(64);
    let entries = [rar50::StoredEntry {
        name: b"recoverable.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
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
    let entries = [rar50::StoredEntry {
        name: b"header-damaged.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
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
    let entries = [rar50::StoredEntry {
        name: b"rr-header-damaged.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
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
    let entries = [rar50::StoredEntry {
        name: b"recoverable-with-bad-rr.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
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

    let repaired = damaged_archive.repair_recovery().unwrap();

    assert_eq!(
        repaired[..recovery_range.start],
        bytes[..recovery_range.start]
    );
    let repaired_archive = Archive::parse(&repaired).unwrap();
    let extracted = collect_extract(&repaired_archive).unwrap();
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn repairs_encrypted_rar50_inline_recovery_payload_damage_with_password() {
    let payload = b"encrypted payload with structural recovery service\n".repeat(64);
    let entries = [EncryptedStoredEntry {
        name: b"secret-recoverable.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.recovery_record = true;
    let bytes = write_encrypted_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
        b"password",
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
    let entries = [EncryptedStoredEntry {
        name: b"header-secret-recoverable.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.recovery_record = true;
    let bytes = write_encrypted_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        20,
        b"password",
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
    let entries = [rar50::CompressedEntry {
        name: b"compressed-recoverable.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
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

#[test]
fn rejects_rar50_recovery_feature_without_recovery_writer() {
    let entries = [rar50::StoredEntry {
        name: b"payload.txt",
        data: b"payload without recovery writer\n",
        mtime: None,
        attributes: 0x20,
        host_os: 3,
    }];
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
    let err = write_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        Error::UnsupportedFeature {
            version: ArchiveVersion::Rar50,
            feature: "RAR 5 writer feature"
        }
    ));
}

#[test]
fn writes_stored_rar50_volume_set_that_reader_reassembles() {
    let payload = b"RAR5 stored volume payload split across generated parts.\n".repeat(12);
    let entry = rar50::StoredEntry {
        name: b"split50.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    };
    let parts = write_stored_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        97,
    )
    .unwrap();
    assert!(parts.len() > 2);

    let archives: Vec<_> = parts
        .iter()
        .map(|part| Archive::parse(part).unwrap())
        .collect();
    assert!(archives.iter().all(|archive| archive.main.is_volume()));
    assert_eq!(archives[0].main.volume_number, Some(0));
    assert_eq!(archives[1].main.volume_number, Some(1));
    assert!(archives[0].files().next().unwrap().is_split_after());
    assert_eq!(archives[0].files().next().unwrap().data_crc32, None);
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
    let entry = rar50::StoredEntry {
        name: b"split50-rr.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
    };
    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
    let parts = write_stored_volumes_with_recovery(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        97,
        8,
    )
    .unwrap();
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
    let entries = [rar50::StoredEntry {
        name: b"payload.txt",
        data: b"payload with archive metadata\n",
        mtime: None,
        attributes: 0x20,
        host_os: 3,
    }];
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_compressed_rar50_archive_metadata_main_extra_record() {
    let payload = b"compressed payload with archive metadata\n".repeat(8);
    let entries = [rar50::CompressedEntry {
        name: b"compressed-metadata.txt",
        data: &payload,
        mtime: None,
        attributes: 0x20,
        host_os: 3,
    }];
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
    let entries = [EncryptedStoredEntry {
        name: b"secret.txt",
        data: b"encrypted stored RAR5 payload from rars\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let first = write_encrypted_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_encrypted_stored_archive(
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
    assert_eq!(extracted[0].data, entries[0].data);
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
    let entries = [EncryptedStoredEntry {
        name: b"metadata-secret.txt",
        data: b"encrypted stored payload with archive metadata\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let bytes = write_encrypted_stored_archive_with_comment_and_metadata(
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_encrypted_compressed_rar50_archive_that_reader_extracts_with_password() {
    let entries = [EncryptedCompressedEntry {
        name: b"secret-compressed.txt",
        data: b"encrypted compressed RAR5 payload from rars\nencrypted compressed RAR5 payload from rars\n",
        mtime: Some(0x5a21_0055),
        attributes: 0x20,
        host_os: 3,
        password: b"secret",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let first = write_encrypted_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_encrypted_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();

    let archive = Archive::parse(&first).unwrap();
    let second_archive = Archive::parse(&second).unwrap();
    let file = archive.files().next().unwrap();
    let second_file = second_archive.files().next().unwrap();
    assert!(file.encrypted);
    assert_eq!(file.decoded_compression_info().unwrap().method, 1);
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
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[0].file_time, 0x5a21_0055);
}

#[test]
fn encrypted_compressed_rar50_writer_stores_member_when_lz_payload_would_grow() {
    let data = deterministic_noise(8192);
    assert!(encode_lz_member(&data, 0).unwrap().len() >= data.len());
    let entries = [EncryptedCompressedEntry {
        name: b"secret-incompressible.bin",
        data: &data,
        mtime: Some(0x5a21_00a1),
        attributes: 0x20,
        host_os: 3,
        password: b"secret",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let bytes = write_encrypted_compressed_archive(
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
    let entries = [EncryptedCompressedEntry {
        name: b"secret-compressed-metadata.txt",
        data: &payload,
        mtime: Some(0x5a21_0055),
        attributes: 0x20,
        host_os: 3,
        password: b"secret",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let bytes = write_encrypted_compressed_archive_with_metadata(
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
        EncryptedCompressedEntry {
            name: b"encrypted-solid-one.txt",
            data: &first,
            mtime: Some(0x5a21_0061),
            attributes: 0x20,
            host_os: 3,
            password: b"secret",
        },
        EncryptedCompressedEntry {
            name: b"encrypted-solid-two.txt",
            data: &second,
            mtime: Some(0x5a21_0062),
            attributes: 0x20,
            host_os: 3,
            password: b"secret",
        },
    ];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.solid = true;
    let bytes = write_encrypted_compressed_archive(
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
    let entries = [EncryptedStoredEntry {
        name: b"secret.txt",
        data: b"encrypted stored payload with encrypted comment\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.archive_comment = true;
    let bytes = write_encrypted_stored_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(EncryptedArchiveCommentEntry {
            data: b"encrypted CMT from rars\n",
            password: b"password",
        }),
    )
    .unwrap();
    let second = write_encrypted_stored_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(EncryptedArchiveCommentEntry {
            data: b"encrypted CMT from rars\n",
            password: b"password",
        }),
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_encrypted_compressed_rar50_archive_comment_service_with_password() {
    let payload = b"encrypted compressed payload with encrypted comment\n".repeat(8);
    let entries = [EncryptedCompressedEntry {
        name: b"encrypted-compressed-comment.txt",
        data: &payload,
        mtime: None,
        attributes: 0x20,
        host_os: 3,
        password: b"secret",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.archive_comment = true;
    let bytes = write_encrypted_compressed_archive_with_comment_and_metadata(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(EncryptedArchiveCommentEntry {
            data: b"encrypted compressed CMT from rars\n",
            password: b"secret",
        }),
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
    let entries = [EncryptedStoredEntry {
        name: b"secret-recovery.txt",
        data: b"encrypted stored payload with encrypted recovery\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.recovery_record = true;
    let bytes = write_encrypted_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        6,
        b"password",
    )
    .unwrap();
    let second = write_encrypted_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        6,
        b"password",
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_encrypted_compressed_rar50_recovery_service_that_reader_extracts_with_password() {
    let payload = b"encrypted compressed recovery payload repeated repeated. ".repeat(24);
    let entries = [EncryptedCompressedEntry {
        name: b"secret-compressed-recovery.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.recovery_record = true;
    let bytes = write_encrypted_compressed_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        6,
    )
    .unwrap();
    let second = write_encrypted_compressed_archive_with_recovery(
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
    let entries = [EncryptedStoredEntry {
        name: b"header-secret.txt",
        data: b"RAR5 header encrypted stored payload from rars\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    let bytes = write_encrypted_stored_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_encrypted_stored_archive(
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_header_encrypted_compressed_rar50_archive_that_reader_extracts_with_password() {
    let entries = [EncryptedCompressedEntry {
        name: b"header-compressed-secret.txt",
        data: b"RAR5 header encrypted compressed payload from rars\nRAR5 header encrypted compressed payload from rars\n",
        mtime: Some(0x5a21_0056),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    let bytes = write_encrypted_compressed_archive(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
    )
    .unwrap();
    let second = write_encrypted_compressed_archive(
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
    assert_eq!(file.decoded_compression_info().unwrap().method, 1);
    assert!(file.encrypted);
    let extracted = collect_extract(&archive).unwrap();
    assert_eq!(extracted[0].data, entries[0].data);
    assert_eq!(extracted[0].file_time, 0x5a21_0056);
}

#[test]
fn writes_header_encrypted_solid_compressed_rar50_archive_that_reader_extracts_with_password() {
    let first = b"header encrypted rar50 solid shared phrase alpha beta gamma\n".repeat(16);
    let second = b"header encrypted rar50 solid shared phrase alpha beta gamma\nsecond\n".repeat(8);
    let entries = [
        EncryptedCompressedEntry {
            name: b"header-solid-one.txt",
            data: &first,
            mtime: Some(0x5a21_0063),
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        },
        EncryptedCompressedEntry {
            name: b"header-solid-two.txt",
            data: &second,
            mtime: Some(0x5a21_0064),
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        },
    ];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.solid = true;
    let bytes = write_encrypted_compressed_archive(
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
    let entries = [EncryptedStoredEntry {
        name: b"header-comment-secret.txt",
        data: b"RAR5 header encrypted archive comment payload from rars\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.archive_comment = true;
    let bytes = write_encrypted_stored_archive_with_comment(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(EncryptedArchiveCommentEntry {
            data: b"header encrypted CMT from rars\n",
            password: b"password",
        }),
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_header_encrypted_compressed_rar50_archive_comment_service_with_password() {
    let payload = b"header encrypted compressed payload with archive comment\n".repeat(8);
    let entries = [EncryptedCompressedEntry {
        name: b"header-compressed-comment-secret.txt",
        data: &payload,
        mtime: Some(0x5a21_0067),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.archive_comment = true;
    let bytes = write_encrypted_compressed_archive_with_comment_and_metadata(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        Some(EncryptedArchiveCommentEntry {
            data: b"header encrypted compressed CMT from rars\n",
            password: b"password",
        }),
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
    let entries = [EncryptedStoredEntry {
        name: b"header-metadata-secret.txt",
        data: b"header encrypted stored payload with archive metadata\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    let bytes = write_encrypted_stored_archive_with_comment_and_metadata(
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_header_encrypted_rar50_recovery_service_that_reader_extracts_with_password() {
    let entries = [EncryptedStoredEntry {
        name: b"header-recovery-secret.txt",
        data: b"RAR5 header encrypted recovery payload from rars\n",
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.recovery_record = true;
    let bytes = write_encrypted_stored_archive_with_recovery(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        4,
        b"password",
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
    assert_eq!(extracted[0].data, entries[0].data);
}

#[test]
fn writes_header_encrypted_compressed_rar50_recovery_service_that_reader_extracts_with_password() {
    let payload = b"header encrypted compressed recovery payload repeated repeated. ".repeat(24);
    let entries = [EncryptedCompressedEntry {
        name: b"header-secret-compressed-recovery.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.recovery_record = true;
    let bytes = write_encrypted_compressed_archive_with_recovery(
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
    let entries = [EncryptedCompressedEntry {
        name: b"header-secret-compressed-metadata.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    let bytes = write_encrypted_compressed_archive_with_metadata(
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
    let entry = EncryptedStoredEntry {
        name: b"split-secret.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let parts = write_encrypted_stored_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        97,
    )
    .unwrap();
    let second_parts = write_encrypted_stored_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        97,
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
    let entry = EncryptedStoredEntry {
        name: b"split-secret-rr.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.recovery_record = true;
    let parts = write_encrypted_stored_volumes_with_recovery(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        97,
        8,
    )
    .unwrap();

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
    let entry = EncryptedStoredEntry {
        name: b"split-header-secret.txt",
        data: &payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    let parts = write_encrypted_stored_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        97,
    )
    .unwrap();
    let second_parts = write_encrypted_stored_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        97,
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
    let entry = EncryptedCompressedEntry {
        name: b"split-secret-compressed50.txt",
        data: &payload,
        mtime: Some(0x5a21_0057),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let parts = write_encrypted_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
    )
    .unwrap();
    let second_parts = write_encrypted_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
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
    assert_eq!(first.decoded_compression_info().unwrap().method, 1);
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
    let entry = EncryptedCompressedEntry {
        name: b"secret-incompressible-split.bin",
        data: &data,
        mtime: Some(0x5a21_00a3),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let parts = write_encrypted_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        1024,
    )
    .unwrap();

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
    let entry = EncryptedCompressedEntry {
        name: b"split-secret-compressed-rr.txt",
        data: &payload,
        mtime: Some(0x5a21_0057),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.recovery_record = true;
    let parts = write_encrypted_compressed_volume_set_with_recovery(
        &[entry],
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
        8,
    )
    .unwrap();

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
    let entry = EncryptedCompressedEntry {
        name: b"split-solid-secret-compressed50.txt",
        data: &payload,
        mtime: Some(0x5a21_0058),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.solid = true;
    let parts = write_encrypted_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
    )
    .unwrap();

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
    let entry = EncryptedCompressedEntry {
        name: b"split-header-secret-compressed50.txt",
        data: &payload,
        mtime: None,
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    let parts = write_encrypted_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
    )
    .unwrap();
    let second_parts = write_encrypted_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
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
    assert_eq!(first.decoded_compression_info().unwrap().method, 1);

    let extracted = collect_extract_volumes(&archives).unwrap();
    assert_eq!(extracted[0].name, b"split-header-secret-compressed50.txt");
    assert_eq!(extracted[0].data, payload);
}

#[test]
fn writes_header_encrypted_solid_compressed_rar50_volume_set_that_reader_reassembles_with_password()
{
    let payload = b"RAR5 header encrypted solid compressed split payload from rars.\n".repeat(18);
    let entry = EncryptedCompressedEntry {
        name: b"split-header-solid-secret-compressed50.txt",
        data: &payload,
        mtime: None,
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.solid = true;
    let parts = write_encrypted_compressed_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
    )
    .unwrap();
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
        EncryptedCompressedEntry {
            name: b"encrypted-solid-split-one.txt",
            data: &first,
            mtime: Some(0x5a21_0061),
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        },
        EncryptedCompressedEntry {
            name: b"encrypted-solid-split-two.txt",
            data: &second,
            mtime: Some(0x5a21_0062),
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        },
    ];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.solid = true;
    let parts = write_encrypted_compressed_volume_set(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        96,
    )
    .unwrap();

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
        EncryptedCompressedEntry {
            name: b"header-encrypted-solid-split-one.txt",
            data: &first,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        },
        EncryptedCompressedEntry {
            name: b"header-encrypted-solid-split-two.txt",
            data: &second,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"password",
        },
    ];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = true;
    features.solid = true;
    let parts = write_encrypted_compressed_volume_set(
        &entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        96,
    )
    .unwrap();
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
    let entries = [EncryptedStoredEntry {
        name: b"secret.txt",
        data: payload,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    }];
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let mut bytes = write_encrypted_stored_archive(
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
    let entry = EncryptedStoredEntry {
        name: b"split-secret.txt",
        data: &data,
        mtime: Some(0x5a21_0000),
        attributes: 0x20,
        host_os: 3,
        password: b"password",
    };
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    let mut volumes = write_encrypted_stored_volumes(
        entry,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features),
        32,
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
fn solid_test_entries() -> Vec<rar50::StreamingCompressedEntry> {
    let base: Vec<u8> = (0..800u32)
        .flat_map(|index| {
            let mut bytes = b"solid dictionary sharing payload ".to_vec();
            bytes.extend_from_slice(&index.to_le_bytes());
            bytes
        })
        .collect();

    (0..3u8)
        .map(|index| rar50::StreamingCompressedEntry {
            name: format!("member-{index}.bin").into_bytes(),
            source: rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(base.clone())),
            mtime: Some(0x5000_0000),
            attributes: 0x20,
            host_os: 0,
        })
        .collect()
}

fn write_streaming(entries: &[rar50::StreamingCompressedEntry], solid: bool) -> Vec<u8> {
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let mut out = Vec::new();
    rar50::write_streaming_compressed_archive_to(
        entries,
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(3),
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
            rar50::StreamingCompressedEntry {
                name: format!("big-{index}.bin").into_bytes(),
                source: rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data)),
                mtime: None,
                attributes: 0x20,
                host_os: 0,
            }
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
    rar50::write_streaming_compressed_archive_to(
        &entries,
        options,
        &rars::WriterResources::default(),
        &mut tight,
    )
    .unwrap();

    let mut roomy = Vec::new();
    rar50::write_streaming_compressed_archive_to(
        &entries,
        options,
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
    let mut path = std::env::temp_dir();
    path.push(format!("rars-{label}-{}.rar", std::process::id()));
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
    let _ = fs::remove_file(&path);
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
    features.file_encryption = true;
    features.header_encryption = true;
    features.recovery_record = true;
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
    let mut path = std::env::temp_dir();
    path.push(format!("rars-{label}-{}.rar", std::process::id()));
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
    let _ = fs::remove_file(&path);
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
    features.file_encryption = true;
    features.header_encryption = true;
    features.recovery_record = true;
    let options =
        rar50::WriterOptions::new(ArchiveVersion::Rar70, features).with_compression_level(1);

    let temp = std::env::temp_dir().join(format!("rars-large-{}.rar", std::process::id()));
    let mut output = fs::File::create(&temp).unwrap();
    // 50% recovery over a ~300 MiB archive needs more parity than the budget
    // allows to hold at once, which forces the striped recovery pass.
    rar50::write_streaming_archive_to(
        std::slice::from_ref(&entry),
        options,
        rar50::ArchiveExtras::default().with_recovery_percent(Some(50)),
        &rars::WriterResources::new(BUDGET).with_temp_dir(std::env::temp_dir()),
        &mut output,
    )
    .unwrap();
    drop(output);

    let written = fs::metadata(&temp).unwrap().len();
    let _ = fs::remove_file(&temp);
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
    let mut features = FeatureSet::store_only();
    features.archive_comment = true;

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
    let mut features = FeatureSet::store_only();
    features.file_comment = true;

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

    let bytes = write_with_extras(
        &entries,
        features,
        rar50::ArchiveExtras::default().with_quick_open(true),
    );

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
        rar50::ArchiveExtras::default().with_filter_policy(rar50::FilterPolicy::AutoSize),
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
        rar50::ArchiveExtras::default().with_filter_policy(rar50::FilterPolicy::AutoSize),
        &rars::WriterResources::new(160 * 1024 * 1024),
        &mut out,
    )
    .unwrap();

    let archive = Archive::parse(&out).unwrap();
    assert_eq!(collect_extract(&archive).unwrap()[0].data, data);
}
