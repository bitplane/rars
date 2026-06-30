use crate::crc32::crc32;
use crate::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::detect::{find_archive_start, ArchiveSignature, RAR50_SIGNATURE, SFX_SCAN_LIMIT};
use crate::error::{Error, Result};
use crate::io_util::{align16 as checked_align16, read_exact_at, read_u32};
pub(crate) use crate::source::ArchiveSource;
use crate::version::ArchiveFamily;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

mod blake2sp;
mod extract;
mod write;

pub use extract::{extract_volumes_to, extract_volumes_to_with_redirections};
pub use write::{
    ArchiveMetadataEntry, CompressedEntry, EncryptedArchiveCommentEntry, EncryptedCompressedEntry,
    EncryptedStoredEntry, EncryptedStoredEntryWithServices, EncryptedStoredServiceEntry,
    FilterKind, FilterPolicy, Rar50VolumeWriter, Rar50Writer, StoredEntry, StoredEntryWithServices,
    StoredServiceEntry, WriterOptions,
};

const HEAD_MAIN: u64 = 1;
const HEAD_FILE: u64 = 2;
const HEAD_SERVICE: u64 = 3;
const HEAD_CRYPT: u64 = 4;
const HEAD_END: u64 = 5;
const REV5_SIGNATURE: &[u8] = b"Rar!\x1aRev";

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;
const HFL_SPLIT_BEFORE: u64 = 0x0008;
const HFL_SPLIT_AFTER: u64 = 0x0010;

const MHFL_VOLUME: u64 = 0x0001;
const MHFL_VOLUME_NUMBER: u64 = 0x0002;
const MHFL_SOLID: u64 = 0x0004;
const MHFL_RECOVERY: u64 = 0x0008;
const MHFL_LOCKED: u64 = 0x0010;

const FHFL_DIRECTORY: u64 = 0x0001;
const FHFL_MTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;

const MHEXTRA_LOCATOR: u64 = 0x01;
const MHEXTRA_LOCATOR_QUICK_OPEN: u64 = 0x0001;
const MHEXTRA_LOCATOR_RECOVERY: u64 = 0x0002;

const FHEXTRA_CRYPT: u64 = 0x01;
const FHEXTRA_HASH: u64 = 0x02;
const FHEXTRA_REDIR: u64 = 0x05;
const FHEXTRA_SUBDATA: u64 = 0x07;
const MHEXTRA_ARCHIVE_METADATA: u64 = 0x02;
const MHEXTRA_ARCHIVE_METADATA_NAME: u64 = 0x0001;
const MHEXTRA_ARCHIVE_METADATA_TIME: u64 = 0x0002;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub blocks: Vec<Block>,
    source: ArchiveSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub block: BlockHeader,
    pub archive_flags: u64,
    pub volume_number: Option<u64>,
    pub extras: Vec<MainExtraRecord>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.archive_flags & MHFL_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.archive_flags & MHFL_SOLID != 0
    }

    pub fn has_recovery_record(&self) -> bool {
        self.archive_flags & MHFL_RECOVERY != 0
    }

    pub fn is_locked(&self) -> bool {
        self.archive_flags & MHFL_LOCKED != 0
    }

    pub fn locator(&self) -> Option<&LocatorRecord> {
        self.extras.iter().find_map(|record| match record {
            MainExtraRecord::Locator(locator) => Some(locator),
            _ => None,
        })
    }

    pub fn archive_metadata(&self) -> Option<&ArchiveMetadataRecord> {
        self.extras.iter().find_map(|record| match record {
            MainExtraRecord::ArchiveMetadata(metadata) => Some(metadata),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MainExtraRecord {
    Locator(LocatorRecord),
    ArchiveMetadata(ArchiveMetadataRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocatorRecord {
    pub flags: u64,
    pub quick_open_offset: Option<u64>,
    pub recovery_record_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveMetadataRecord {
    pub flags: u64,
    pub name: Option<Vec<u8>>,
    pub creation_time: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    File(FileHeader),
    Service(FileHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockHeader {
    pub header_crc: u32,
    pub header_size: u64,
    pub header_type: u64,
    pub flags: u64,
    pub extra_area_size: Option<u64>,
    pub data_size: Option<u64>,
    pub offset: usize,
    // Type-specific header bytes are archive-relative. Payload bytes are
    // source-absolute so SFX-prefixed archives can be read directly.
    pub header_range: Range<usize>,
    pub data_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub block: BlockHeader,
    pub file_flags: u64,
    pub unpacked_size: u64,
    pub attributes: u64,
    pub mtime: Option<u32>,
    pub data_crc32: Option<u32>,
    pub compression_info: u64,
    pub host_os: u64,
    pub name: Vec<u8>,
    pub hash: Option<FileHash>,
    pub redirection: Option<FileRedirection>,
    pub service_data: Option<Vec<u8>>,
    pub encrypted: bool,
    pub encryption: Option<FileEncryption>,
    crypto: Option<FileCryptoState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileRedirection {
    pub redirection_type: u64,
    pub flags: u64,
    pub target_name: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHash {
    pub hash_type: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryRecord {
    pub percent: u64,
    pub payload_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileEncryption {
    pub version: u64,
    pub flags: u64,
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub check_value: Option<[u8; 12]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileCryptoState {
    keys: Rar50Keys,
    iv: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rev5Volume {
    pub version: u8,
    pub data_count: u16,
    pub recovery_count: u16,
    pub recovery_number: u16,
    pub payload_crc32: u32,
    pub payload_size: u64,
    pub payload: Vec<u8>,
    pub data_volumes: Vec<Rev5DataVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rev5VolumeMeta {
    pub version: u8,
    pub data_count: u16,
    pub recovery_count: u16,
    pub recovery_number: u16,
    pub payload_crc32: u32,
    pub payload_size: u64,
    pub data_volumes: Vec<Rev5DataVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rev5DataVolume {
    pub file_size: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompressionInfo {
    pub algorithm_version: u8,
    pub solid: bool,
    pub method: u8,
    pub dictionary_power: u8,
    pub dictionary_fraction: u8,
    pub rar5_compat: bool,
    pub dictionary_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub attr: u64,
    pub host_os: u64,
    pub is_directory: bool,
}

impl FileHeader {
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the file name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_split_before(&self) -> bool {
        self.block.flags & HFL_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.block.flags & HFL_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.file_flags & FHFL_DIRECTORY != 0
    }

    pub fn is_stored(&self) -> bool {
        compression_method(self.compression_info) == 0
    }

    pub fn is_redirection(&self) -> bool {
        self.redirection.is_some()
    }

    pub fn decoded_compression_info(&self) -> Result<CompressionInfo> {
        decode_compression_info(self.compression_info)
    }

    pub fn packed_size(&self) -> u64 {
        self.block.data_size.unwrap_or(0)
    }

    pub fn packed_data(&self, archive: &Archive) -> Result<Vec<u8>> {
        archive.read_range(self.block.data_range.clone())
    }

    pub fn verify_crc32(&self, data: &[u8]) -> Result<()> {
        let Some(expected) = self.data_crc32 else {
            return Ok(());
        };
        if self.uses_hash_mac() {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted CRC32 verification needs encryption keys",
            ));
        }
        let actual = crc32(data);
        if actual == expected {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch { expected, actual })
        }
    }

    pub fn verify_hash(&self, data: &[u8]) -> Result<()> {
        let Some(hash) = &self.hash else {
            return Ok(());
        };
        if self.uses_hash_mac() {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted hash verification needs encryption keys",
            ));
        }
        match hash.hash_type {
            0 if hash.data.len() == 32 => {
                let actual = blake2sp::hash(data);
                if hash.data == actual {
                    Ok(())
                } else {
                    Err(Error::HashMismatch { hash_type: 0 })
                }
            }
            0 => Err(Error::InvalidHeader(
                "RAR 5 BLAKE2sp hash record has invalid length",
            )),
            _ => Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 unknown file hash type",
            }),
        }
    }

    pub fn verify_integrity(&self, data: &[u8]) -> Result<()> {
        self.verify_crc32(data)?;
        self.verify_hash(data)
    }

    fn uses_hash_mac(&self) -> bool {
        self.encryption
            .as_ref()
            .is_some_and(|encryption| encryption.flags & 0x0002 != 0)
    }

    pub fn recovery_record(&self) -> Result<Option<RecoveryRecord>> {
        if self.name != b"RR" {
            return Ok(None);
        }
        let Some(data) = &self.service_data else {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery service is missing service data",
            ));
        };
        let (percent, len) = read_vint_at(data, 0, data.len())?;
        if len != data.len() {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery service data has trailing bytes",
            ));
        }
        Ok(Some(RecoveryRecord {
            percent,
            payload_size: self.packed_size(),
        }))
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        Self::parse_with_options(input, crate::ArchiveReadOptions::default())
    }

    pub fn parse_owned(input: Vec<u8>) -> Result<Self> {
        Self::parse_owned_with_options(input, crate::ArchiveReadOptions::default())
    }

    pub fn parse_with_options(
        input: &[u8],
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data, options.password)
    }

    pub fn parse_owned_with_options(
        input: Vec<u8>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_shared(Arc::from(input.into_boxed_slice()), options.password)
    }

    pub fn parse_with_password(input: &[u8], password: Option<&[u8]>) -> Result<Self> {
        Self::parse_with_options(
            input,
            crate::ArchiveReadOptions::with_optional_password(password),
        )
    }

    pub fn parse_owned_with_password(input: Vec<u8>, password: Option<&[u8]>) -> Result<Self> {
        Self::parse_owned_with_options(
            input,
            crate::ArchiveReadOptions::with_optional_password(password),
        )
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse_path_with_options(path, crate::ArchiveReadOptions::default())
    }

    pub fn parse_path_with_options(
        path: impl AsRef<Path>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_path_with_password(path, options.password)
    }

    pub fn parse_path_with_password(
        path: impl AsRef<Path>,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let scan_len = len.min(SFX_SCAN_LIMIT as u64) as usize;
        let mut scan = vec![0; scan_len];
        file.read_exact(&mut scan)?;
        let sig = find_archive_start(&scan, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let archive_len = usize::try_from(len)
            .map_err(|_| Error::InvalidHeader("RAR 5 archive size overflows usize"))?
            .checked_sub(sig.offset)
            .ok_or(Error::TooShort)?;
        Self::parse_file_backed(
            &mut file,
            archive_len,
            sig.offset,
            ArchiveSource::File(path),
            password,
        )
    }

    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_path_with_signature_and_password(path, signature, options.password)
    }

    pub fn parse_path_with_signature_and_password(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        if signature.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let archive_len = usize::try_from(len)
            .map_err(|_| Error::InvalidHeader("RAR 5 archive size overflows usize"))?
            .checked_sub(signature.offset)
            .ok_or(Error::TooShort)?;
        Self::parse_file_backed(
            &mut file,
            archive_len,
            signature.offset,
            ArchiveSource::File(path),
            password,
        )
    }

    fn parse_shared(input: Arc<[u8]>, password: Option<&[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let archive = input.get(sig.offset..).ok_or(Error::TooShort)?;
        let mut parsed = Self::parse_seekable(
            archive,
            sig.offset,
            ArchiveSource::Memory(Arc::clone(&input)),
            password,
        )?;
        parsed.sfx_offset = sig.offset;
        Ok(parsed)
    }

    fn parse_seekable(
        input: &[u8],
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        if !input.starts_with(RAR50_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let archive_len = input.len();
        let (main, blocks) = parse_archive_blocks(
            archive_len,
            password,
            |offset| parse_block_header_bytes(input, offset, archive_len, sfx_offset),
            |offset, keys| {
                parse_encrypted_block_header_bytes(input, offset, archive_len, sfx_offset, keys)
            },
        )?;

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
        })
    }

    fn parse_file_backed(
        file: &mut File,
        archive_len: usize,
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let signature = read_exact_at(file, sfx_offset, RAR50_SIGNATURE.len())?;
        if signature != RAR50_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }

        let file_cell = std::cell::RefCell::new(file);
        let (main, blocks) = parse_archive_blocks(
            archive_len,
            password,
            |offset| {
                read_block_header_at(&mut file_cell.borrow_mut(), offset, archive_len, sfx_offset)
            },
            |offset, keys| {
                read_encrypted_block_header_at(
                    &mut file_cell.borrow_mut(),
                    offset,
                    archive_len,
                    sfx_offset,
                    keys,
                )
            },
        )?;

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
        })
    }

    fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        self.source.read_range(range)
    }

    fn source_len(&self) -> Result<usize> {
        self.source.len()
    }

    fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + '_>> {
        self.source.range_reader(range)
    }

    fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        let source_len = self.source_len()?;
        if range.start > range.end || range.end > source_len {
            return Err(Error::InvalidHeader("RAR 5 repair range is out of bounds"));
        }
        let mut reader = self.range_reader(range)?;
        std::io::copy(&mut reader, writer)?;
        Ok(())
    }

    pub fn files(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::File(file) => Some(file),
            _ => None,
        })
    }

    pub fn services(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::Service(service) => Some(service),
            _ => None,
        })
    }

    /// Decodes the archive-level `CMT` service payload, if any.
    ///
    /// RAR 5 stores comments as `Service` blocks named `CMT`. Archive-level
    /// comments appear before any `File` block; service blocks attached to a
    /// specific file follow that file. This returns only the former.
    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        self.archive_comment_with_password(None)
    }

    /// Same as [`Self::archive_comment`] but supplies a password for
    /// individually-encrypted comment services.
    pub fn archive_comment_with_password(
        &self,
        password: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        for block in &self.blocks {
            match block {
                Block::File(_) => return Ok(None),
                Block::Service(service) if service.name == b"CMT" => {
                    return service.decoded_data_unverified(self, password).map(Some);
                }
                _ => {}
            }
        }
        Ok(None)
    }

    pub fn repair_recovery(&self) -> Result<Vec<u8>> {
        let mut repaired = Vec::new();
        self.repair_recovery_to(&mut repaired)?;
        Ok(repaired)
    }

    pub fn repair_recovery_to(&self, writer: &mut dyn Write) -> Result<()> {
        let recovery = self
            .services()
            .find(|service| matches!(service.recovery_record(), Ok(Some(_))))
            .ok_or(Error::InvalidHeader(
                "RAR 5 archive does not contain an inline recovery record",
            ))?;
        let prefix_start = self.sfx_offset;
        let prefix_end = recovery
            .block
            .offset
            .checked_sub(prefix_start)
            .and_then(|relative| prefix_start.checked_add(relative))
            .ok_or(Error::InvalidHeader(
                "RAR 5 recovery prefix range overflows archive bounds",
            ))?;
        let source_len = self.source_len()?;
        if prefix_end > source_len {
            return Err(Error::InvalidHeader(
                "RAR 5 recovery prefix is out of bounds",
            ));
        }
        let recovery_data = recovery
            .decoded_data_unverified(self, None)
            .map_err(|error| error.at_entry(recovery.name.clone(), "reading recovery data"))?;
        let prefix_len = prefix_end
            .checked_sub(prefix_start)
            .ok_or(Error::InvalidHeader(
                "RAR 5 recovery prefix range overflows archive bounds",
            ))?;
        let repaired_shards = crate::recovery::rar5::repair_inline_recovery_prefix_shards(
            prefix_len,
            &recovery_data,
            |range| {
                let start = prefix_start
                    .checked_add(range.start)
                    .ok_or(crate::recovery::rar5::Error::PlanOverflow)?;
                let end = prefix_start
                    .checked_add(range.end)
                    .ok_or(crate::recovery::rar5::Error::PlanOverflow)?;
                self.read_range(start..end)
                    .map_err(|_| crate::recovery::rar5::Error::BadRecoveryChunk)
            },
        )?;

        self.copy_range_to(0..prefix_start, writer)?;
        let mut cursor = 0usize;
        for (range, data) in repaired_shards {
            if range.start < cursor || range.end > prefix_len || range.len() != data.len() {
                return Err(Error::InvalidHeader(
                    "RAR 5 recovery shard range is invalid",
                ));
            }
            self.copy_range_to(prefix_start + cursor..prefix_start + range.start, writer)?;
            writer.write_all(&data)?;
            cursor = range.end;
        }
        self.copy_range_to(prefix_start + cursor..prefix_end, writer)?;
        self.copy_range_to(prefix_end..source_len, writer)?;
        Ok(())
    }
}

impl Rev5Volume {
    pub fn parse(input: &[u8]) -> Result<Self> {
        let (meta, payload_range) = Rev5VolumeMeta::parse_with_payload_range(input)?;
        let payload = &input[payload_range];
        let actual_payload_crc = crc32(payload);
        if actual_payload_crc != meta.payload_crc32 {
            return Err(Error::Crc32Mismatch {
                expected: meta.payload_crc32,
                actual: actual_payload_crc,
            });
        }

        Ok(Self {
            version: meta.version,
            data_count: meta.data_count,
            recovery_count: meta.recovery_count,
            recovery_number: meta.recovery_number,
            payload_crc32: meta.payload_crc32,
            payload_size: meta.payload_size,
            payload: payload.to_vec(),
            data_volumes: meta.data_volumes,
        })
    }
}

impl Rev5VolumeMeta {
    pub fn parse(input: &[u8]) -> Result<Self> {
        Self::parse_with_payload_range(input).map(|(meta, _)| meta)
    }

    fn parse_with_payload_range(input: &[u8]) -> Result<(Self, Range<usize>)> {
        if !input.starts_with(REV5_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }
        if input.len() < 16 {
            return Err(Error::TooShort);
        }
        let header_crc = read_u32(input, 8)?;
        let header_size = read_u32(input, 12)? as usize;
        if header_size <= 5 || header_size > 0x100000 {
            return Err(Error::InvalidHeader("RAR 5 REV header size is invalid"));
        }
        let header_end = 16usize
            .checked_add(header_size)
            .ok_or(Error::InvalidHeader("RAR 5 REV header size overflows"))?;
        if header_end > input.len() {
            return Err(Error::TooShort);
        }
        let actual_header_crc = crc32(&input[12..header_end]);
        if actual_header_crc != header_crc {
            return Err(Error::Crc32Mismatch {
                expected: header_crc,
                actual: actual_header_crc,
            });
        }

        let body = &input[16..header_end];
        if body.len() < 11 {
            return Err(Error::TooShort);
        }
        let mut reader = SliceReader::new(body, 0, body.len());
        let version = reader.read_byte()?;
        if version != 1 {
            return Err(Error::UnsupportedFeature {
                version: crate::version::ArchiveVersion::Rar50,
                feature: "RAR 5 REV version",
            });
        }
        let data_count = reader.read_u16()?;
        let recovery_count = reader.read_u16()?;
        let recovery_number = reader.read_u16()?;
        let payload_crc32 = reader.read_u32()?;
        let first_recovery_number = u32::from(data_count);
        let recovery_end = first_recovery_number + u32::from(recovery_count);
        let recovery_number = u32::from(recovery_number);
        if recovery_count == 0
            || recovery_number < first_recovery_number
            || recovery_number >= recovery_end
        {
            return Err(Error::InvalidHeader("RAR 5 REV volume number is invalid"));
        }

        let expected_table_len = data_count as usize * 12;
        let expected_table_end =
            11usize
                .checked_add(expected_table_len)
                .ok_or(Error::InvalidHeader(
                    "RAR 5 REV metadata table size overflows",
                ))?;
        if body.len() < expected_table_end {
            return Err(Error::InvalidHeader(
                "RAR 5 REV metadata table size is invalid",
            ));
        }
        let mut data_volumes = Vec::with_capacity(data_count as usize);
        for _ in 0..data_count {
            let file_size = reader.read_u64()?;
            let crc = reader.read_u32()?;
            data_volumes.push(Rev5DataVolume {
                file_size,
                crc32: crc,
            });
        }

        Ok((
            Self {
                version,
                data_count,
                recovery_count,
                recovery_number: recovery_number as u16,
                payload_crc32,
                payload_size: (input.len() - header_end) as u64,
                data_volumes,
            },
            header_end..input.len(),
        ))
    }
}

impl From<&Rev5Volume> for Rev5VolumeMeta {
    fn from(volume: &Rev5Volume) -> Self {
        Self {
            version: volume.version,
            data_count: volume.data_count,
            recovery_count: volume.recovery_count,
            recovery_number: volume.recovery_number,
            payload_crc32: volume.payload_crc32,
            payload_size: volume.payload_size,
            data_volumes: volume.data_volumes.clone(),
        }
    }
}

impl From<Rev5Volume> for Rev5VolumeMeta {
    fn from(volume: Rev5Volume) -> Self {
        Self {
            version: volume.version,
            data_count: volume.data_count,
            recovery_count: volume.recovery_count,
            recovery_number: volume.recovery_number,
            payload_crc32: volume.payload_crc32,
            payload_size: volume.payload_size,
            data_volumes: volume.data_volumes,
        }
    }
}

pub fn repair_rev5_volumes_to<F>(
    data_volumes: &[Option<&[u8]>],
    recovery_volumes: &[Rev5Volume],
    mut write: F,
) -> Result<()>
where
    F: FnMut(usize, &[u8]) -> Result<()>,
{
    let first = recovery_volumes.first().ok_or(Error::InvalidHeader(
        "RAR 5 REV recovery volume set is empty",
    ))?;
    let data_count = usize::from(first.data_count);
    if data_volumes.len() != data_count {
        return Err(Error::InvalidHeader(
            "RAR 5 REV data volume count does not match metadata",
        ));
    }
    if recovery_volumes.iter().any(|rev| {
        rev.version != first.version
            || rev.data_count != first.data_count
            || rev.recovery_count != first.recovery_count
            || rev.data_volumes != first.data_volumes
            || rev.payload.len() != first.payload.len()
    }) {
        return Err(Error::InvalidHeader(
            "RAR 5 REV recovery volume metadata differs across files",
        ));
    }

    let mut shards = Vec::with_capacity(data_count);
    for (index, data) in data_volumes.iter().enumerate() {
        let Some(data) = data else {
            shards.push(None);
            continue;
        };
        let meta = &first.data_volumes[index];
        if data.len() as u64 != meta.file_size || crc32(data) != meta.crc32 {
            shards.push(None);
        } else {
            shards.push(Some(*data));
        }
    }

    let recovery_rows: Vec<_> = recovery_volumes
        .iter()
        .map(|rev| {
            let row = usize::from(rev.recovery_number)
                .checked_sub(data_count)
                .ok_or(Error::InvalidHeader("RAR 5 REV recovery number is invalid"))?;
            Ok((row, rev.payload.as_slice()))
        })
        .collect::<Result<_>>()?;
    let mut seen_recovery_rows = std::collections::HashSet::with_capacity(recovery_rows.len());
    if recovery_rows
        .iter()
        .any(|(row, _)| !seen_recovery_rows.insert(*row))
    {
        return Err(Error::InvalidHeader(
            "RAR 5 REV recovery volume set contains duplicate recovery rows",
        ));
    }
    let repaired = crate::recovery::rar5::reconstruct_data_shards(&shards, &recovery_rows)?;

    for (index, (mut shard, meta)) in repaired.into_iter().zip(&first.data_volumes).enumerate() {
        let file_size = usize::try_from(meta.file_size)
            .map_err(|_| Error::InvalidHeader("RAR 5 REV data volume size overflows usize"))?;
        if shard.len() < file_size {
            return Err(Error::InvalidHeader(
                "RAR 5 REV repaired shard is shorter than data volume size",
            ));
        }
        shard.truncate(file_size);
        let actual = crc32(&shard);
        if actual != meta.crc32 {
            return Err(Error::Crc32Mismatch {
                expected: meta.crc32,
                actual,
            });
        }
        write(index, &shard)?;
    }
    Ok(())
}

pub fn repair_inline_recovery_bytes(input: &[u8]) -> Result<Vec<u8>> {
    if !input.starts_with(RAR50_SIGNATURE) {
        return Err(Error::UnsupportedSignature);
    }
    let repaired =
        crate::recovery::rar5::repair_inline_recovery_archive(input).map_err(Error::from)?;
    let parse_target = if repaired == input { input } else { &repaired };
    let _ = Archive::parse(parse_target)?;
    Ok(repaired)
}

fn parse_main_header_bytes(parsed: &ParsedBlockHeader) -> Result<MainHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let archive_flags = reader.read_vint()?;
    let volume_number = if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extras = parse_main_extra_area(&parsed.header, parsed.extra_range.clone())?;
    Ok(MainHeader {
        block: parsed.block.clone(),
        archive_flags,
        volume_number,
        extras,
    })
}

fn parse_main_extra_area(input: &[u8], range: Range<usize>) -> Result<Vec<MainExtraRecord>> {
    let mut records = Vec::new();
    parse_extra_records(input, range, |record_type, data| match record_type {
        MHEXTRA_LOCATOR => {
            let mut reader = SliceReader::new(input, data.start, data.end);
            let flags = reader.read_vint()?;
            let quick_open_offset = if flags & MHEXTRA_LOCATOR_QUICK_OPEN != 0 {
                Some(reader.read_vint()?)
            } else {
                None
            };
            let recovery_record_offset = if flags & MHEXTRA_LOCATOR_RECOVERY != 0 {
                Some(reader.read_vint()?)
            } else {
                None
            };
            // LOCATOR records are intentionally forward-compatible: known
            // offsets are parsed and any trailing bytes remain reserved for
            // future flags.
            records.push(MainExtraRecord::Locator(LocatorRecord {
                flags,
                quick_open_offset,
                recovery_record_offset,
            }));
            Ok(())
        }
        MHEXTRA_ARCHIVE_METADATA => {
            let mut reader = SliceReader::new(input, data.start, data.end);
            let flags = reader.read_vint()?;
            let name = if flags & MHEXTRA_ARCHIVE_METADATA_NAME != 0 {
                let name_len = usize_from_u64(
                    reader.read_vint()?,
                    "RAR 5 archive metadata name length overflows usize",
                )?;
                Some(reader.read_bytes(name_len)?.to_vec())
            } else {
                None
            };
            let creation_time = if flags & MHEXTRA_ARCHIVE_METADATA_TIME != 0 {
                Some(reader.read_u64()?)
            } else {
                None
            };
            if reader.pos != reader.end {
                return Err(Error::InvalidHeader(
                    "RAR 5 archive metadata record has trailing bytes",
                ));
            }
            records.push(MainExtraRecord::ArchiveMetadata(ArchiveMetadataRecord {
                flags,
                name,
                creation_time,
            }));
            Ok(())
        }
        _ => Ok(()),
    })?;
    Ok(records)
}

fn parse_file_header_bytes(parsed: &ParsedBlockHeader) -> Result<FileHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let file_flags = reader.read_vint()?;
    let unpacked_size = reader.read_vint()?;
    let attributes = reader.read_vint()?;
    let mtime = if file_flags & FHFL_MTIME != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let data_crc32 = if file_flags & FHFL_CRC32 != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let compression_info = reader.read_vint()?;
    let host_os = reader.read_vint()?;
    let name_len = usize_from_u64(
        reader.read_vint()?,
        "RAR 5 file name length overflows usize",
    )?;
    let name = reader.read_bytes(name_len)?.to_vec();
    let mut file = FileHeader {
        block: parsed.block.clone(),
        file_flags,
        unpacked_size,
        attributes,
        mtime,
        data_crc32,
        compression_info,
        host_os,
        name,
        hash: None,
        redirection: None,
        service_data: None,
        encrypted: false,
        encryption: None,
        crypto: None,
    };
    parse_file_extra_area(&parsed.header, parsed.extra_range.clone(), &mut file)?;
    Ok(file)
}

fn parse_file_extra_area(input: &[u8], range: Range<usize>, file: &mut FileHeader) -> Result<()> {
    if file.block.extra_area_size.is_none() {
        return Ok(());
    }
    parse_extra_records(input, range, |record_type, data| {
        match record_type {
            FHEXTRA_CRYPT => {
                file.encrypted = true;
                file.encryption = Some(parse_file_encryption_record(input, data)?);
            }
            FHEXTRA_HASH => {
                let (hash_type, hash_type_len) = read_vint_at(input, data.start, data.end)?;
                file.hash = Some(FileHash {
                    hash_type,
                    data: input[data.start + hash_type_len..data.end].to_vec(),
                });
            }
            FHEXTRA_REDIR => {
                file.redirection = Some(parse_file_redirection_record(input, data)?);
            }
            FHEXTRA_SUBDATA => {
                file.service_data = Some(input[data].to_vec());
            }
            _ => {}
        }
        Ok(())
    })
}

fn parse_file_redirection_record(input: &[u8], range: Range<usize>) -> Result<FileRedirection> {
    let (redirection_type, type_len) = read_vint_at(input, range.start, range.end)?;
    let flags_start = range.start + type_len;
    let (flags, flags_len) = read_vint_at(input, flags_start, range.end)?;
    let name_len_start = flags_start + flags_len;
    let (name_len, name_len_len) = read_vint_at(input, name_len_start, range.end)?;
    let name_start = name_len_start + name_len_len;
    let name_len = usize::try_from(name_len).map_err(|_| {
        Error::InvalidHeader("RAR 5 file redirection target length overflows host address size")
    })?;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 file redirection target length overflows",
        ))?;
    if name_end != range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 file redirection record has trailing bytes",
        ));
    }
    Ok(FileRedirection {
        redirection_type,
        flags,
        target_name: input[name_start..name_end].to_vec(),
    })
}

fn parse_file_encryption_record(input: &[u8], range: Range<usize>) -> Result<FileEncryption> {
    let (version, version_len) = read_vint_at(input, range.start, range.end)?;
    let flags_pos = range.start + version_len;
    let (flags, flags_len) = read_vint_at(input, flags_pos, range.end)?;
    let mut pos = flags_pos + flags_len;
    if pos >= range.end {
        return Err(Error::TooShort);
    }
    let kdf_count = input[pos];
    pos += 1;
    let salt = read_array_at::<16>(input, &mut pos, range.end)?;
    let iv = read_array_at::<16>(input, &mut pos, range.end)?;
    let check_value = if flags & 0x0001 != 0 {
        Some(read_array_at::<12>(input, &mut pos, range.end)?)
    } else {
        None
    };
    if pos != range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 file encryption record has trailing bytes",
        ));
    }
    Ok(FileEncryption {
        version,
        flags,
        kdf_count,
        salt,
        iv,
        check_value,
    })
}

fn parse_archive_encryption_header(
    parsed: &ParsedBlockHeader,
    password: Option<&[u8]>,
) -> Result<Rar50Keys> {
    let password = password.ok_or(Error::NeedPassword)?;
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let version = reader.read_vint()?;
    if version != 0 {
        return Err(Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown header encryption version",
        });
    }
    let flags = reader.read_vint()?;
    let kdf_count = reader.read_byte()?;
    let salt = reader.read_array::<16>()?;
    let check_value = if flags & 0x0001 != 0 {
        Some(reader.read_array::<12>()?)
    } else {
        None
    };
    if reader.pos != reader.range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 archive encryption header has trailing bytes",
        ));
    }
    let keys = Rar50Keys::derive(password, salt, kdf_count).map_err(map_rar50_crypto_error)?;
    if let Some(check_value) = check_value {
        keys.check_password(&check_value)
            .map_err(map_rar50_crypto_error)?;
    }
    Ok(keys)
}

fn attach_file_crypto(file: &mut FileHeader, password: Option<&[u8]>) -> Result<()> {
    if !file.encrypted || file.crypto.is_some() {
        return Ok(());
    }
    let Some(password) = password else {
        return Ok(());
    };
    let encryption = file.encryption.as_ref().ok_or(Error::InvalidHeader(
        "RAR 5 encrypted file is missing encryption record",
    ))?;
    if encryption.version != 0 {
        return Err(Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown file encryption version",
        });
    }
    let keys = Rar50Keys::derive(password, encryption.salt, encryption.kdf_count)
        .map_err(map_rar50_crypto_error)?;
    if let Some(check_value) = encryption.check_value {
        keys.check_password(&check_value)
            .map_err(map_rar50_crypto_error)?;
    }
    file.crypto = Some(FileCryptoState {
        keys,
        iv: encryption.iv,
    });
    Ok(())
}

fn attach_service_crypto(service: &mut FileHeader, password: Option<&[u8]>) -> Result<()> {
    // WinRAR can emit encrypted QO metadata whose service-local password
    // check does not validate with the archive password. QuickOpen is an
    // optional cache, so keep archive parsing and file extraction independent
    // from that service.
    if service.name == b"QO" {
        return Ok(());
    }
    attach_file_crypto(service, password)
}

fn map_rar50_crypto_error(error: crate::crypto::rar50::Error) -> Error {
    match error {
        crate::crypto::rar50::Error::KdfCountTooLarge => Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 KDF count",
        },
        crate::crypto::rar50::Error::BadPassword => Error::WrongPasswordOrCorruptData,
        crate::crypto::rar50::Error::UnalignedInput => {
            Error::InvalidHeader("RAR 5 AES input is not block aligned")
        }
    }
}

fn read_array_at<const N: usize>(input: &[u8], pos: &mut usize, end: usize) -> Result<[u8; N]> {
    if pos.checked_add(N).is_none_or(|next| next > end) {
        return Err(Error::TooShort);
    }
    let mut out = [0; N];
    out.copy_from_slice(&input[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

fn parse_archive_blocks<F, G>(
    archive_len: usize,
    password: Option<&[u8]>,
    mut read_block: F,
    mut read_encrypted_block: G,
) -> Result<(MainHeader, Vec<Block>)>
where
    F: FnMut(usize) -> Result<ParsedBlockHeader>,
    G: FnMut(usize, &Rar50Keys) -> Result<ParsedBlockHeader>,
{
    let mut pos = RAR50_SIGNATURE.len();
    let first = read_block(pos).map_err(|error| error.at_archive_offset(pos))?;
    let header_keys = if first.block.header_type == HEAD_CRYPT {
        pos = first.next_offset;
        Some(parse_archive_encryption_header(&first, password)?)
    } else {
        None
    };

    let main_pos = pos;
    let main_block;
    let first = if let Some(keys) = &header_keys {
        main_block =
            read_encrypted_block(pos, keys).map_err(|error| error.at_archive_offset(pos))?;
        &main_block
    } else {
        &first
    };
    if first.block.header_type != HEAD_MAIN {
        return Err(Error::InvalidHeader("RAR 5 main header is missing"));
    }
    let main = parse_main_header_bytes(first).map_err(|error| error.at_archive_offset(main_pos))?;
    pos = first.next_offset;

    let mut blocks = Vec::new();
    while pos < archive_len {
        let parsed = if let Some(keys) = &header_keys {
            read_encrypted_block(pos, keys).map_err(|error| error.at_archive_offset(pos))?
        } else {
            read_block(pos).map_err(|error| error.at_archive_offset(pos))?
        };
        let next = parsed.next_offset;
        match parsed.block.header_type {
            HEAD_FILE => {
                let mut file = parse_file_header_bytes(&parsed)
                    .map_err(|error| error.at_archive_offset(pos))?;
                attach_file_crypto(&mut file, password)
                    .map_err(|error| error.at_archive_offset(pos))?;
                blocks.push(Block::File(file));
            }
            HEAD_SERVICE => {
                let mut service = parse_file_header_bytes(&parsed)
                    .map_err(|error| error.at_archive_offset(pos))?;
                attach_service_crypto(&mut service, password)
                    .map_err(|error| error.at_archive_offset(pos))?;
                blocks.push(Block::Service(service));
            }
            HEAD_CRYPT => {
                return Err(Error::UnsupportedFeature {
                    version: crate::version::ArchiveVersion::Rar50,
                    feature: "RAR 5 encrypted headers",
                });
            }
            HEAD_END => {
                blocks.push(Block::End(parsed.block));
                break;
            }
            _ => blocks.push(Block::Unknown(parsed.block)),
        }
        pos = next;
    }

    Ok((main, blocks))
}

fn parse_extra_records<F>(input: &[u8], range: Range<usize>, mut handle: F) -> Result<()>
where
    F: FnMut(u64, Range<usize>) -> Result<()>,
{
    let mut pos = range.start;
    while pos < range.end {
        let record_start = pos;
        let (record_size, size_len) = read_vint_at(input, pos, range.end)?;
        pos += size_len;
        let record_payload_len =
            usize_from_u64(record_size, "RAR 5 extra record size overflows usize")?;
        let record_end = pos
            .checked_add(record_payload_len)
            .ok_or(Error::InvalidHeader(
                "RAR 5 extra record size overflows usize",
            ))?;
        if record_end > range.end {
            return Err(Error::TooShort);
        }
        let (record_type, type_len) = read_vint_at(input, pos, record_end)?;
        let data_start = pos + type_len;
        handle(record_type, data_start..record_end)?;
        if record_end <= record_start {
            return Err(Error::InvalidHeader("RAR 5 extra record does not advance"));
        }
        pos = record_end;
    }
    Ok(())
}

struct ParsedBlockHeader {
    block: BlockHeader,
    header: Vec<u8>,
    type_specific_range: Range<usize>,
    extra_range: Range<usize>,
    next_offset: usize,
}

fn parse_block_header_bytes(
    input: &[u8],
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 5 {
        return Err(Error::TooShort);
    }
    let header_crc = read_u32(input, offset)?;
    let after_crc = offset
        .checked_add(4)
        .ok_or(Error::InvalidHeader("RAR 5 header offset overflows usize"))?;
    let (header_size, header_size_len) = read_vint_at(input, after_crc, archive_len)?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_total > remaining {
        return Err(Error::TooShort);
    }
    let header_end = offset
        .checked_add(header_total)
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let header = input
        .get(offset..header_end)
        .ok_or(Error::TooShort)?
        .to_vec();
    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        header_total,
    )
}

fn parse_encrypted_block_header_bytes(
    input: &[u8],
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    let first = input.get(offset..offset + 32).ok_or(Error::TooShort)?;
    let mut iv = [0; 16];
    iv.copy_from_slice(&first[..16]);
    let mut first_plain = first[16..32].to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut first_plain)
        .map_err(map_rar50_crypto_error)?;
    let header_crc = read_u32(&first_plain, 0)?;
    let (header_size, header_size_len) = read_vint_at(&first_plain, 4, first_plain.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let encrypted_len = checked_align16(header_total, "RAR 5 encrypted header size overflows")?;
    let disk_header_len = 16usize
        .checked_add(encrypted_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 encrypted header size overflows",
        ))?;
    if disk_header_len > remaining {
        return Err(Error::TooShort);
    }
    let encrypted = input
        .get(offset + 16..offset + disk_header_len)
        .ok_or(Error::TooShort)?;
    let mut header = encrypted.to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut header)
        .map_err(map_rar50_crypto_error)?;
    header.truncate(header_total);

    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        disk_header_len,
    )
}

fn read_block_header_at(
    file: &mut File,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 5 {
        return Err(Error::TooShort);
    }
    let prefix_len = remaining.min(14);
    let prefix = read_exact_at(file, sfx_offset + offset, prefix_len)?;
    let header_crc = read_u32(&prefix, 0)?;
    let (header_size, header_size_len) = read_vint_at(&prefix, 4, prefix.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_total > remaining {
        return Err(Error::TooShort);
    }

    let header = read_exact_at(file, sfx_offset + offset, header_total)?;
    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        header_total,
    )
}

fn read_encrypted_block_header_at(
    file: &mut File,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    let first = read_exact_at(file, sfx_offset + offset, 32)?;
    let mut iv = [0; 16];
    iv.copy_from_slice(&first[..16]);
    let mut first_plain = first[16..32].to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut first_plain)
        .map_err(map_rar50_crypto_error)?;
    let header_crc = read_u32(&first_plain, 0)?;
    let (header_size, header_size_len) = read_vint_at(&first_plain, 4, first_plain.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let encrypted_len = checked_align16(header_total, "RAR 5 encrypted header size overflows")?;
    let disk_header_len = 16usize
        .checked_add(encrypted_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 encrypted header size overflows",
        ))?;
    if disk_header_len > remaining {
        return Err(Error::TooShort);
    }
    let encrypted = read_exact_at(file, sfx_offset + offset + 16, encrypted_len)?;
    let mut header = encrypted;
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut header)
        .map_err(map_rar50_crypto_error)?;
    header.truncate(header_total);

    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        disk_header_len,
    )
}

fn parse_block_header_image(
    header: Vec<u8>,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    header_crc: u32,
    disk_header_len: usize,
) -> Result<ParsedBlockHeader> {
    let header_total = header.len();
    let (decoded_header_size, header_size_len) = read_vint_at(&header, 4, header_total)?;
    validate_block_header_crc(&header, header_crc)?;
    let type_start = 4 + header_size_len;
    let mut reader = SliceReader::new(&header, type_start, header_total);
    let header_type = reader.read_vint()?;
    let flags = reader.read_vint()?;
    let extra_area_size = if flags & HFL_EXTRA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let data_size = if flags & HFL_DATA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extra_len = extra_area_size
        .map(|size| usize_from_u64(size, "RAR 5 extra area size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    if extra_len > header_total.saturating_sub(reader.pos) {
        return Err(Error::TooShort);
    }
    let type_specific_end = header_total - extra_len;
    let data_len = data_size
        .map(|size| usize_from_u64(size, "RAR 5 data size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    let next_offset = offset
        .checked_add(disk_header_len)
        .and_then(|pos| pos.checked_add(data_len))
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;
    if next_offset > archive_len {
        return Err(Error::TooShort);
    }
    let type_specific_start = reader.pos;
    let data_start = sfx_offset
        .checked_add(offset)
        .and_then(|pos| pos.checked_add(disk_header_len))
        .ok_or(Error::InvalidHeader("RAR 5 data offset overflows usize"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;

    Ok(ParsedBlockHeader {
        block: BlockHeader {
            header_crc,
            header_size: decoded_header_size,
            header_type,
            flags,
            extra_area_size,
            data_size,
            offset: sfx_offset + offset,
            header_range: (offset + type_specific_start)..(offset + type_specific_end),
            data_range: data_start..data_end,
        },
        header,
        type_specific_range: type_specific_start..type_specific_end,
        extra_range: type_specific_end..header_total,
        next_offset,
    })
}

fn validate_block_header_crc(header: &[u8], expected: u32) -> Result<()> {
    let actual = crc32(header.get(4..).ok_or(Error::TooShort)?);
    if actual != expected {
        return Err(Error::Crc32Mismatch { expected, actual });
    }
    Ok(())
}

struct HeaderReader<'a> {
    input: &'a [u8],
    range: Range<usize>,
    pos: usize,
}

impl<'a> HeaderReader<'a> {
    fn new(input: &'a [u8], range: Range<usize>) -> Result<Self> {
        if range.end > input.len() {
            return Err(Error::TooShort);
        }
        Ok(Self {
            input,
            pos: range.start,
            range,
        })
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.range.end)?;
        self.pos += len;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let value = read_u32(self.input, self.pos)?;
        self.pos += 4;
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.range.end {
            return Err(Error::TooShort);
        }
        let value = self.input[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        read_array_at::<N>(self.input, &mut self.pos, self.range.end)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 5 field size overflows usize"))?;
        if end > self.range.end {
            return Err(Error::TooShort);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

struct SliceReader<'a> {
    input: &'a [u8],
    end: usize,
    pos: usize,
}

impl<'a> SliceReader<'a> {
    fn new(input: &'a [u8], pos: usize, end: usize) -> Self {
        Self { input, pos, end }
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.end)?;
        self.pos += len;
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 5 field size overflows usize"))?;
        if end > self.end {
            return Err(Error::TooShort);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

fn read_vint_at(input: &[u8], offset: usize, end: usize) -> Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for i in 0..10 {
        let pos = offset.checked_add(i).ok_or(Error::TooShort)?;
        if pos >= end {
            return Err(Error::TooShort);
        }
        let byte = *input.get(pos).ok_or(Error::TooShort)?;
        if shift == 63 && byte & 0x7e != 0 {
            return Err(Error::InvalidHeader("RAR 5 vint overflows u64"));
        }
        value = value
            .checked_add(((byte & 0x7f) as u64) << shift)
            .ok_or(Error::InvalidHeader("RAR 5 vint overflows u64"))?;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(Error::InvalidHeader("RAR 5 vint is too long"))
}

fn usize_from_u64(value: u64, message: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::InvalidHeader(message))
}

fn compression_method(compression_info: u64) -> u64 {
    (compression_info >> 7) & 0x07
}

fn decode_compression_info(raw: u64) -> Result<CompressionInfo> {
    let algorithm_version = (raw & 0x3f) as u8;
    if algorithm_version > 1 {
        return Err(Error::UnsupportedFeature {
            version: crate::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown compression algorithm version",
        });
    }

    let dictionary_power = ((raw >> 10) & 0x1f) as u8;
    let dictionary_fraction = ((raw >> 15) & 0x1f) as u8;
    let rar5_compat = raw & 0x100000 != 0;
    if algorithm_version == 0 && (dictionary_fraction != 0 || rar5_compat) {
        return Err(Error::InvalidHeader(
            "RAR 5 v0 compression info uses v1 dictionary fields",
        ));
    }
    if algorithm_version == 0 && dictionary_power > 15 {
        return Err(Error::InvalidHeader(
            "RAR 5 v0 dictionary power exceeds 4 GiB limit",
        ));
    }

    let dictionary_size = if algorithm_version == 1 {
        u64::from(dictionary_fraction + 32)
            .checked_shl(u32::from(dictionary_power) + 12)
            .ok_or(Error::InvalidHeader("RAR 5 dictionary size overflows u64"))?
    } else {
        (128 * 1024_u64)
            .checked_shl(u32::from(dictionary_power))
            .ok_or(Error::InvalidHeader("RAR 5 dictionary size overflows u64"))?
    };

    Ok(CompressionInfo {
        algorithm_version,
        solid: raw & 0x40 != 0,
        method: ((raw >> 7) & 0x07) as u8,
        dictionary_power,
        dictionary_fraction,
        rar5_compat,
        dictionary_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_vint_at_honors_logical_end_before_decoding() {
        assert_eq!(read_vint_at(&[0x01], 0, 0), Err(Error::TooShort));
        assert_eq!(read_vint_at(&[0x81, 0x01], 0, 1), Err(Error::TooShort));
        assert_eq!(read_vint_at(&[0x81, 0x01], 0, 2).unwrap(), (129, 2));
    }

    #[test]
    fn read_vint_at_rejects_values_wider_than_u64() {
        let max = [0xff; 9].into_iter().chain([0x01]).collect::<Vec<_>>();
        assert_eq!(read_vint_at(&max, 0, max.len()).unwrap(), (u64::MAX, 10));

        let overflow = [0xff; 9].into_iter().chain([0x02]).collect::<Vec<_>>();
        assert_eq!(
            read_vint_at(&overflow, 0, overflow.len()),
            Err(Error::InvalidHeader("RAR 5 vint overflows u64"))
        );
    }

    #[test]
    fn parses_file_redirection_extra_record() {
        let input = [1, 1, 6, b't', b'a', b'r', b'g', b'e', b't'];
        let record = parse_file_redirection_record(&input, 0..input.len()).unwrap();

        assert_eq!(record.redirection_type, 1);
        assert_eq!(record.flags, 1);
        assert_eq!(record.target_name, b"target");
    }

    #[test]
    fn rejects_file_redirection_record_with_trailing_bytes() {
        let input = [1, 0, 3, b'f', b'o', b'o', 0];

        assert!(matches!(
            parse_file_redirection_record(&input, 0..input.len()),
            Err(Error::InvalidHeader(
                "RAR 5 file redirection record has trailing bytes"
            ))
        ));
    }

    #[test]
    fn file_header_name_bytes_preserve_non_utf8_names() {
        let file = FileHeader {
            block: BlockHeader {
                header_crc: 0,
                header_size: 0,
                header_type: HEAD_FILE,
                flags: 0,
                extra_area_size: None,
                data_size: Some(0),
                offset: 0,
                header_range: 0..0,
                data_range: 0..0,
            },
            file_flags: 0,
            unpacked_size: 0,
            attributes: 0,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 0,
            name: vec![0xff, b'.', b'b', b'i', b'n'],
            hash: None,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        };

        assert_eq!(file.name_bytes(), [0xff, b'.', b'b', b'i', b'n']);
        assert_eq!(file.name_lossy(), "\u{fffd}.bin");
    }

    fn build_archive_with_optional_comment(comment: Option<&[u8]>) -> Archive {
        use crate::FeatureSet;
        let mut features = FeatureSet::store_only();
        features.archive_comment = comment.is_some();
        let entries = [crate::rar50::StoredEntry {
            name: b"payload.txt",
            data: b"payload bytes",
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        }];
        let bytes = crate::rar50::Rar50Writer::new(crate::rar50::WriterOptions::new(
            crate::version::ArchiveVersion::Rar50,
            features,
        ))
        .stored_entries(&entries)
        .archive_comment(comment)
        .finish()
        .unwrap();
        Archive::parse(&bytes).unwrap()
    }

    #[test]
    fn archive_comment_returns_none_for_archive_without_a_cmt_service() {
        let archive = build_archive_with_optional_comment(None);
        assert!(archive.archive_comment().unwrap().is_none());
    }

    #[test]
    fn archive_comment_decodes_the_cmt_service_payload_text() {
        let comment_text = b"archive comment from rars unit test\n";
        let archive = build_archive_with_optional_comment(Some(comment_text));
        let comment = archive.archive_comment().unwrap();
        assert_eq!(comment.as_deref(), Some(&comment_text[..]));
    }

    #[test]
    fn archive_comment_ignores_cmt_services_attached_to_files() {
        // Service blocks that follow a File block belong to that file, not the
        // archive — archive_comment should not surface them.
        use crate::FeatureSet;
        let services = [crate::rar50::StoredServiceEntry {
            name: b"CMT",
            data: b"per-file comment",
        }];
        let entry = crate::rar50::StoredEntryWithServices {
            entry: crate::rar50::StoredEntry {
                name: b"payload.txt",
                data: b"payload bytes",
                mtime: None,
                attributes: 0x20,
                host_os: 3,
            },
            services: &services,
        };
        let mut features = FeatureSet::store_only();
        features.file_comment = true;
        let bytes = crate::rar50::Rar50Writer::new(crate::rar50::WriterOptions::new(
            crate::version::ArchiveVersion::Rar50,
            features,
        ))
        .stored_entries_with_services(std::slice::from_ref(&entry))
        .finish()
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert!(archive.archive_comment().unwrap().is_none());
    }
}
