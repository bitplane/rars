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
pub(crate) mod write;

pub use extract::{extract_volumes_to, extract_volumes_to_with_redirections};
pub use write::{
    write_streaming_archive_to, write_streaming_archive_with_progress, write_streaming_volumes_to,
    write_streaming_volumes_with_progress, ArchiveEntry, ArchiveExtras, ArchiveMetadataEntry,
    CollectedVolumes, FilterKind, FilterPolicy, FilterSpec, Rar50Writer, ServiceEntry, VolumeSink,
    WriterOptions,
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

/// Set on the end-of-archive block of every volume that is not the last, so a
/// reader knows to look for the next one rather than stopping where the file
/// does.
const EFL_NEXT_VOLUME: u64 = 0x0001;

const MHFL_VOLUME: u64 = 0x0001;
const MHFL_VOLUME_NUMBER: u64 = 0x0002;
const MHFL_SOLID: u64 = 0x0004;
const MHFL_RECOVERY: u64 = 0x0008;
const MHFL_LOCKED: u64 = 0x0010;

const FHFL_DIRECTORY: u64 = 0x0001;
const FHFL_MTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;
const FHFL_UNP_SIZE_UNKNOWN: u64 = 0x0008;

const MHEXTRA_LOCATOR: u64 = 0x01;
const MHEXTRA_LOCATOR_QUICK_OPEN: u64 = 0x0001;
const MHEXTRA_LOCATOR_RECOVERY: u64 = 0x0002;

const FHEXTRA_CRYPT: u64 = 0x01;
const FHEXTRA_HASH: u64 = 0x02;
const FHEXTRA_HTIME: u64 = 0x03;
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
    /// Whether the archive uses encrypted headers.
    pub encrypted_headers: bool,
    pub(crate) rewrite_metadata_complete: bool,
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
    End(EndHeader),
    Unknown(BlockHeader),
}

/// The block that closes an archive. Its one field says whether the set carries
/// on into another volume, which a reader has to honour: a volume set is not
/// over because the file is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndHeader {
    pub block: BlockHeader,
    pub flags: u64,
}

impl EndHeader {
    pub fn has_next_volume(&self) -> bool {
        self.flags & EFL_NEXT_VOLUME != 0
    }
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
    pub(crate) rewrite_metadata_complete: bool,
    pub unpacked_size: u64,
    pub attributes: u64,
    pub mtime: Option<u32>,
    /// Modification time from the `FHEXTRA_HTIME` record, in Unix seconds.
    ///
    /// Separate from `mtime`, which is the optional base-header field. Modern
    /// WinRAR writes the time here and leaves that field out: 39 of the 40
    /// RAR 5 fixtures in this tree carry `FHEXTRA_HTIME` and one carries the
    /// header field, so a reader that only looks at `mtime` restores nothing
    /// on almost every real archive.
    pub htime_mtime: Option<u32>,
    /// Fractional detail belonging to the extended modification time.
    pub htime_mtime_refinement: Option<crate::TimeRefinement>,
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

impl FileRedirection {
    /// Validates the redirection kinds whose metadata the writer can retain.
    pub fn is_supported(&self) -> bool {
        (1..=5).contains(&self.redirection_type)
            && self.flags & !1 == 0
            && (self.redirection_type < 4 || self.flags == 0)
            && !self.target_name.is_empty()
            && !self.target_name.contains(&0)
            && std::str::from_utf8(&self.target_name).is_ok()
    }

    pub(crate) fn supports_header(&self, host: u64, attr: u64, directory: bool) -> bool {
        if !self.is_supported() {
            return false;
        }
        match self.redirection_type {
            1 => host == 1 && attr & !0o7777 == 0o120000 && !directory,
            2 | 3 => {
                host == 0
                    && attr & 0x400 != 0
                    && (attr & 0x10 != 0) == directory
                    && (self.redirection_type != 3 || self.flags == 1)
                    && directory == (self.flags & 1 != 0)
            }
            4 | 5 => {
                !directory
                    && match host {
                        0 => attr & (0x400 | 0x10) == 0,
                        1 => attr & !0o7777 == 0o100000,
                        _ => false,
                    }
            }
            _ => false,
        }
    }

    /// Whether this target can be emitted by the Unix symbolic link writer.
    /// Targets use RAR5 wire bytes and are never resolved against the filesystem.
    pub fn is_supported_unix_symlink(&self) -> bool {
        self.redirection_type == 1
            && self.flags & !1 == 0
            && !self.target_name.is_empty()
            && !self.target_name.contains(&0)
            && std::str::from_utf8(&self.target_name).is_ok()
    }
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
    /// Unix modification time in seconds; absence is distinct from epoch.
    pub file_time: Option<u32>,
    pub mtime_refinement: Option<crate::TimeRefinement>,
    pub attr: u64,
    pub host_os: u64,
    pub is_directory: bool,
}

impl FileHeader {
    /// Declared logical output size, unless the format marks it unknown.
    /// Early split fragments can have unknown sizes while the final one is known.
    /// This does not imply that the decoder supports unknown-size streams.
    pub fn known_unpacked_size(&self) -> Option<u64> {
        (self.file_flags & FHFL_UNP_SIZE_UNKNOWN == 0).then_some(self.unpacked_size)
    }

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
        options.check_cancelled()?;
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data, options)
    }

    pub fn parse_owned_with_options(
        input: Vec<u8>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        Self::parse_shared(Arc::from(input.into_boxed_slice()), options)
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

    pub fn parse_path_with_password(
        path: impl AsRef<Path>,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        Self::parse_path_with_options(
            path,
            crate::ArchiveReadOptions::with_optional_password(password),
        )
    }

    pub fn parse_path_with_options(
        path: impl AsRef<Path>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let scan_len = len.min(SFX_SCAN_LIMIT as u64) as usize;
        let mut scan = vec![0; scan_len];
        file.read_exact(&mut scan)?;
        options.check_cancelled()?;
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
            options,
        )
    }

    pub fn parse_path_with_signature_and_password(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        Self::parse_path_with_signature(
            path,
            signature,
            crate::ArchiveReadOptions::with_optional_password(password),
        )
    }

    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
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
            options,
        )
    }

    fn parse_shared(input: Arc<[u8]>, options: crate::ArchiveReadOptions<'_>) -> Result<Self> {
        options.check_cancelled()?;
        let sig = find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let archive = input.get(sig.offset..).ok_or(Error::TooShort)?;
        let mut parsed = Self::parse_seekable(
            archive,
            sig.offset,
            ArchiveSource::Memory(Arc::clone(&input)),
            options,
        )?;
        parsed.sfx_offset = sig.offset;
        Ok(parsed)
    }

    fn parse_seekable(
        input: &[u8],
        sfx_offset: usize,
        source: ArchiveSource,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        if !input.starts_with(RAR50_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let archive_len = input.len();
        let (main, blocks) = parse_archive_blocks(
            archive_len,
            options,
            |offset, budget| {
                parse_block_header_bytes(input, offset, archive_len, sfx_offset, budget)
            },
            |offset, keys, budget| {
                parse_encrypted_block_header_bytes(
                    input,
                    offset,
                    archive_len,
                    sfx_offset,
                    keys,
                    budget,
                )
            },
        )?;

        options.check_cancelled()?;
        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
        })
    }

    pub(crate) fn parse_file_backed(
        file: &mut (impl Read + std::io::Seek),
        archive_len: usize,
        sfx_offset: usize,
        source: ArchiveSource,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        let signature = read_exact_at(file, sfx_offset, RAR50_SIGNATURE.len())?;
        if signature != RAR50_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }

        let control = crate::read_control::ReadControl::new(options.cancellation);
        let file_cell = std::cell::RefCell::new(control.reader(file));
        let (main, blocks) = parse_archive_blocks(
            archive_len,
            options,
            |offset, budget| {
                read_block_header_at(
                    &mut *file_cell.borrow_mut(),
                    offset,
                    archive_len,
                    sfx_offset,
                    budget,
                )
            },
            |offset, keys, budget| {
                read_encrypted_block_header_at(
                    &mut *file_cell.borrow_mut(),
                    offset,
                    archive_len,
                    sfx_offset,
                    keys,
                    budget,
                )
            },
        )?;

        options.check_cancelled()?;
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
        Ok(self.repair_recovery_with_report(None)?.data)
    }

    pub fn repair_recovery_with_report(
        &self,
        password: Option<&[u8]>,
    ) -> Result<crate::RecoveryRepairResult> {
        let mut data = Vec::new();
        let report = self.repair_recovery_to_with_report(&mut data, password)?;
        Ok(crate::RecoveryRepairResult { data, report })
    }

    pub fn repair_recovery_to(&self, writer: &mut dyn Write) -> Result<()> {
        self.repair_recovery_to_with_report(writer, None)
            .map(|_| ())
    }

    pub fn repair_recovery_to_with_report(
        &self,
        writer: &mut dyn Write,
        password: Option<&[u8]>,
    ) -> Result<crate::RecoveryRepairReport> {
        let recovery = self.recovery_service()?;
        let recovery_data = recovery.decoded_data_unverified(self, password)?;
        let (available, expected) =
            crate::recovery::rar5::inline_recovery_chunk_counts(&recovery_data)?;
        if available == expected || self.sfx_offset != 0 {
            return self.repair_recovery_to_legacy(writer, password, available, expected);
        }
        let bytes = self.read_range(0..self.source_len()?)?;
        let options = crate::recovery::rar5::InlineRepairOptions {
            password,
            record_range: Some(recovery.block.data_range.clone()),
        };
        let (data, report) =
            crate::recovery::rar5::repair_inline_recovery_archive_with_report(&bytes, &options)?;
        writer.write_all(&data)?;
        Ok(report)
    }

    fn recovery_service(&self) -> Result<&FileHeader> {
        self.services()
            .find(|service| matches!(service.recovery_record(), Ok(Some(_))))
            .ok_or(Error::InvalidHeader(
                "RAR 5 archive does not contain an inline recovery record",
            ))
    }

    fn repair_recovery_to_legacy(
        &self,
        writer: &mut dyn Write,
        password: Option<&[u8]>,
        available: u64,
        expected: u64,
    ) -> Result<crate::RecoveryRepairReport> {
        let recovery = self.recovery_service()?;
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
            .decoded_data_unverified(self, password)
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
        let data_repaired = !repaired_shards.is_empty();
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
        Ok(crate::RecoveryRepairReport {
            changed: data_repaired,
            data_repaired,
            recovery_record_rebuilt: false,
            end_record_rebuilt: false,
            available_recovery_shards: Some(available),
            expected_recovery_shards: Some(expected),
        })
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
    Ok(repair_inline_recovery_bytes_with_report(input)?.data)
}

pub fn repair_inline_recovery_bytes_with_report(
    input: &[u8],
) -> Result<crate::RecoveryRepairResult> {
    repair_inline_recovery_bytes_with_options(input, crate::ArchiveReadOptions::new())
}

pub fn repair_inline_recovery_bytes_with_options(
    input: &[u8],
    options: crate::ArchiveReadOptions<'_>,
) -> Result<crate::RecoveryRepairResult> {
    options.check_cancelled()?;
    if !input.starts_with(RAR50_SIGNATURE) {
        return Err(Error::UnsupportedSignature);
    }
    let repair_options = crate::recovery::rar5::InlineRepairOptions {
        password: options.password,
        ..Default::default()
    };
    let (repaired, report) =
        crate::recovery::rar5::repair_inline_recovery_archive_with_report(input, &repair_options)
            .map_err(Error::from)?;
    let parse_target = if repaired == input { input } else { &repaired };
    let _ = Archive::parse_with_options(parse_target, options)?;
    Ok(crate::RecoveryRepairResult {
        data: repaired,
        report,
    })
}

/// Frames a replacement end-of-archive header for an archive that lost its
/// own.
///
/// A volume whose last entry runs into the next part has to keep saying so,
/// and only the parsed blocks show that, so `input` is read back here. It is
/// the repaired archive rather than the damaged one, so the blocks it walks
/// are the ones the caller is about to write. A volume that splits cleanly on
/// an entry boundary is indistinguishable from a final one and loses the flag;
/// unrar and WinRAR both walk such a set from the main header anyway.
pub(crate) fn recovery_end_header(input: &[u8], password: Option<&[u8]>) -> Result<Vec<u8>> {
    let end_flags = match Archive::parse_with_password(input, password) {
        Ok(archive)
            if archive
                .files()
                .last()
                .is_some_and(|file| file.is_split_after()) =>
        {
            EFL_NEXT_VOLUME
        }
        _ => 0,
    };
    let first = parse_block_header_bytes(
        input,
        RAR50_SIGNATURE.len(),
        input.len(),
        0,
        &mut crate::parse_budget::ParseBudget::new(crate::ArchiveReadOptions::default()),
    )?;
    if first.block.header_type != HEAD_CRYPT {
        let mut end = Vec::new();
        write::headers::write_end_header(&mut end, end_flags)?;
        return Ok(end);
    }
    let keys = parse_archive_encryption_header(&first, password)?;
    write::headers::encrypted_header_block(
        &keys,
        HEAD_END,
        0,
        None,
        &write::end_header_specific(end_flags),
        &[],
        &[],
    )
}

fn parse_main_header_bytes(parsed: &ParsedBlockHeader) -> Result<MainHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let archive_flags = reader.read_vint()?;
    let volume_number = if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extras =
        parse_main_extra_area(&parsed.header, parsed.extra_range.clone(), &parsed.control)?;
    Ok(MainHeader {
        block: parsed.block.clone(),
        archive_flags,
        volume_number,
        extras,
        encrypted_headers: false,
        rewrite_metadata_complete: parsed.extra_range.is_empty() && reader.pos == reader.range.end,
    })
}

fn parse_main_extra_area(
    input: &[u8],
    range: Range<usize>,
    control: &crate::read_control::ReadControl,
) -> Result<Vec<MainExtraRecord>> {
    let mut records = Vec::new();
    parse_extra_records(
        input,
        range,
        false,
        control,
        |record_type, data| match record_type {
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
        },
    )?;
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
        rewrite_metadata_complete: reader.pos == reader.range.end,
        unpacked_size,
        attributes,
        mtime,
        htime_mtime: None,
        htime_mtime_refinement: None,
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
    parse_file_extra_area(
        &parsed.header,
        parsed.extra_range.clone(),
        parsed.block.header_type == HEAD_SERVICE,
        &mut file,
        &parsed.control,
    )?;
    Ok(file)
}

fn parse_file_extra_area(
    input: &[u8],
    range: Range<usize>,
    is_service: bool,
    file: &mut FileHeader,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    if file.block.extra_area_size.is_none() {
        return Ok(());
    }
    let mut seen = 0u64;
    let complete = parse_extra_records(input, range, is_service, control, |record_type, data| {
        let bit = 1u64
            .checked_shl(record_type as u32)
            .filter(|_| record_type < 64)
            .unwrap_or(0);
        if bit == 0 || seen & bit != 0 {
            file.rewrite_metadata_complete = false;
        }
        seen |= bit;
        match record_type {
            FHEXTRA_CRYPT => {
                file.rewrite_metadata_complete = false;
                file.encrypted = true;
                file.encryption = Some(parse_file_encryption_record(input, data)?);
            }
            FHEXTRA_HASH => {
                let (hash_type, hash_type_len) = read_vint_at(input, data.start, data.end)?;
                file.rewrite_metadata_complete &=
                    hash_type == 0 && data.len() == hash_type_len + 32;
                file.hash = Some(FileHash {
                    hash_type,
                    data: input[data.start + hash_type_len..data.end].to_vec(),
                });
            }
            FHEXTRA_REDIR => {
                let link = parse_file_redirection_record(input, data)?;
                file.rewrite_metadata_complete &= !is_service && link.is_supported();
                file.redirection = Some(link);
            }
            FHEXTRA_HTIME => {
                let flags = read_vint_at(input, data.start, data.end).ok();
                let exact_mtime = flags.is_some_and(|(flags, len)| match flags {
                    2 => data.len() == len + 8,
                    3 => data.len() == len + 4,
                    0x13 => data.len() == len + 8,
                    _ => false,
                });
                let parsed = parse_htime_mtime(input, data);
                file.rewrite_metadata_complete &= exact_mtime
                    && file.mtime.is_none()
                    && parsed.is_some()
                    && (flags.map(|f| f.0) != Some(0x13) || parsed.and_then(|p| p.1).is_some());
                file.htime_mtime = parsed.map(|(seconds, _)| seconds);
                file.htime_mtime_refinement = parsed.and_then(|(_, detail)| detail);
            }
            FHEXTRA_SUBDATA => {
                file.rewrite_metadata_complete &= is_service && data.is_empty();
                file.service_data = Some(input[data].to_vec());
            }
            _ => {
                file.rewrite_metadata_complete = false;
            }
        }
        Ok(())
    })?;
    file.rewrite_metadata_complete &= complete;
    Ok(())
}

/// Reads the modification time out of an `FHEXTRA_HTIME` record.
///
/// Layout is flags, then the present times in the order mtime, ctime, atime,
/// then, when flag `0x0010` is set, one sub-second remainder per time in that
/// same order. Under flag `0x0001` a time is `uint32` Unix seconds; without it
/// a time is a `uint64` Windows FILETIME. Unix modification-time fractions follow
/// all the present whole-second values; FILETIME embeds its fraction in the ticks.
///
/// A malformed whole-second value yields `None`; malformed fractional detail is
/// ignored while retaining valid seconds. The reference
/// readers do not fail an archive over a time they cannot read, and neither
/// should we lose the file over it.
fn parse_htime_mtime(
    input: &[u8],
    range: Range<usize>,
) -> Option<(u32, Option<crate::TimeRefinement>)> {
    // Slice to the record first: malformed time fields must not borrow bytes
    // from a following extra record or the file payload.
    let data = input.get(range)?;
    let (flags, at) = read_vint_at(data, 0, data.len()).ok()?;
    if flags & 2 == 0 {
        return None;
    }
    let (seconds, nanos) = if flags & 1 != 0 {
        let seconds = u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?);
        // Unix fractions follow ALL present whole-second values, not each value.
        let count = (flags & 0x0e).count_ones() as usize;
        let fraction_at = at.checked_add(count.checked_mul(4)?)?;
        let nanos = if flags & 0x10 != 0 {
            data.get(fraction_at..fraction_at.checked_add(4)?)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .filter(|nanos| *nanos < 1_000_000_000)
        } else {
            None
        };
        (seconds, nanos)
    } else {
        let ticks = u64::from_le_bytes(data.get(at..at.checked_add(8)?)?.try_into().ok()?);
        let seconds = u32::try_from((ticks / 10_000_000).checked_sub(11_644_473_600)?).ok()?;
        (seconds, Some(((ticks % 10_000_000) * 100) as u32))
    };
    Some((
        seconds,
        nanos.map(|nanoseconds| crate::TimeRefinement {
            add_second: false,
            nanoseconds,
        }),
    ))
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
    options: crate::ArchiveReadOptions<'_>,
    mut read_block: F,
    mut read_encrypted_block: G,
) -> Result<(MainHeader, Vec<Block>)>
where
    F: FnMut(usize, &mut crate::parse_budget::ParseBudget) -> Result<ParsedBlockHeader>,
    G: FnMut(usize, &Rar50Keys, &mut crate::parse_budget::ParseBudget) -> Result<ParsedBlockHeader>,
{
    options.check_cancelled()?;
    // Budget refusals already identify the header; do not duplicate its context.
    let at_offset = |error: Error, offset| match error {
        Error::AtArchiveOffset { .. } => error,
        error => error.at_archive_offset(offset),
    };
    let password = options.password;
    let mut budget = crate::parse_budget::ParseBudget::new(options);
    let mut pos = RAR50_SIGNATURE.len();
    let first = read_block(pos, &mut budget).map_err(|error| at_offset(error, pos))?;
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
            read_encrypted_block(pos, keys, &mut budget).map_err(|error| at_offset(error, pos))?;
        &main_block
    } else {
        &first
    };
    if first.block.header_type != HEAD_MAIN {
        return Err(Error::InvalidHeader("RAR 5 main header is missing"));
    }
    let mut main = parse_main_header_bytes(first).map_err(|error| at_offset(error, main_pos))?;
    main.encrypted_headers = header_keys.is_some();
    pos = first.next_offset;

    let mut blocks = Vec::new();
    while pos < archive_len {
        let parsed = if let Some(keys) = &header_keys {
            read_encrypted_block(pos, keys, &mut budget).map_err(|error| at_offset(error, pos))?
        } else {
            read_block(pos, &mut budget).map_err(|error| at_offset(error, pos))?
        };
        let next = parsed.next_offset;
        match parsed.block.header_type {
            HEAD_FILE => {
                let mut file =
                    parse_file_header_bytes(&parsed).map_err(|error| at_offset(error, pos))?;
                attach_file_crypto(&mut file, password).map_err(|error| at_offset(error, pos))?;
                blocks.push(Block::File(file));
            }
            HEAD_SERVICE => {
                let mut service =
                    parse_file_header_bytes(&parsed).map_err(|error| at_offset(error, pos))?;
                attach_service_crypto(&mut service, password)
                    .map_err(|error| at_offset(error, pos))?;
                blocks.push(Block::Service(service));
            }
            HEAD_CRYPT => {
                return Err(Error::UnsupportedFeature {
                    version: crate::version::ArchiveVersion::Rar50,
                    feature: "RAR 5 encrypted headers",
                });
            }
            HEAD_END => {
                main.rewrite_metadata_complete &= next == archive_len;
                // A block with no room for the vint reads as no flags rather
                // than as a broken archive. Hand-built and truncated archives
                // do turn up with an empty end block, and the field only says
                // whether to look for another volume.
                let flags = read_vint_at(
                    &parsed.header,
                    parsed.type_specific_range.start,
                    parsed.type_specific_range.end,
                )
                .map(|(flags, _)| flags)
                .unwrap_or(0);
                blocks.push(Block::End(EndHeader {
                    block: parsed.block,
                    flags,
                }));
                break;
            }
            _ => blocks.push(Block::Unknown(parsed.block)),
        }
        pos = next;
    }

    main.rewrite_metadata_complete &= matches!(blocks.last(), Some(Block::End(_)));
    Ok((main, blocks))
}

/// Walks the records of a RAR 5 extra area, handing each one to `handle`.
///
/// A record that does not fit the area ends the walk instead of failing the
/// archive. RAR 7.12 and unrar 7.20 both extract normally from headers whose
/// extra area ends in a record claiming more bytes than are left, a size vint
/// cut off by the end of the area, or a record too small to hold its own type
/// vint. Rejecting the archive would throw away file data that is intact.
///
/// On a service header, a single byte left over after a `SUBDATA` record is
/// folded into that record. WinRAR 5.21 and earlier stored the `SUBDATA` size
/// one less than the payload they wrote, and `SUBDATA` is the last record in
/// those headers, so the shortfall surfaces as exactly one dangling byte.
/// Without this, `RR` loses its recovery percent and `STM` loses the last
/// character of the stream name. Note that the reference readers give no way
/// to see the recovered byte from the outside: they accept the short shape,
/// but neither prints the recovery percent, so the byte itself is unverified.
fn parse_extra_records<F>(
    input: &[u8],
    range: Range<usize>,
    is_service: bool,
    control: &crate::read_control::ReadControl,
    mut handle: F,
) -> Result<bool>
where
    F: FnMut(u64, Range<usize>) -> Result<()>,
{
    let mut pos = range.start;
    let mut poller = control.poller();
    while pos < range.end {
        poller.check(pos)?;
        let Ok((record_size, size_len)) = read_vint_at(input, pos, range.end) else {
            break;
        };
        let payload_start = pos + size_len;
        let Ok(record_payload_len) = usize::try_from(record_size) else {
            break;
        };
        let Some(mut record_end) = payload_start.checked_add(record_payload_len) else {
            break;
        };
        if record_end > range.end || record_end <= payload_start {
            break;
        }
        let Ok((record_type, type_len)) = read_vint_at(input, payload_start, record_end) else {
            break;
        };
        if is_service && record_type == FHEXTRA_SUBDATA && range.end - record_end == 1 {
            record_end = range.end;
        }
        handle(record_type, payload_start + type_len..record_end)?;
        pos = record_end;
    }
    Ok(pos == range.end)
}

struct ParsedBlockHeader {
    control: crate::read_control::ReadControl,
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
    budget: &mut crate::parse_budget::ParseBudget,
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
    budget.admit(header_total, offset)?;
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
        &budget.control,
    )
}

fn parse_encrypted_block_header_bytes(
    input: &[u8],
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
    budget: &mut crate::parse_budget::ParseBudget,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    budget.check_count(offset)?;
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
    budget.admit(header_total, offset)?;
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
        &budget.control,
    )
}

fn read_block_header_at(
    file: &mut (impl Read + std::io::Seek),
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    budget: &mut crate::parse_budget::ParseBudget,
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

    budget.admit(header_total, offset)?;
    let header = read_exact_at(file, sfx_offset + offset, header_total)?;
    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        header_total,
        &budget.control,
    )
}

fn read_encrypted_block_header_at(
    file: &mut (impl Read + std::io::Seek),
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
    budget: &mut crate::parse_budget::ParseBudget,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    budget.check_count(offset)?;
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
    budget.admit(header_total, offset)?;
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
        &budget.control,
    )
}

fn parse_block_header_image(
    header: Vec<u8>,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    header_crc: u32,
    disk_header_len: usize,
    control: &crate::read_control::ReadControl,
) -> Result<ParsedBlockHeader> {
    control.check()?;
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
        control: control.clone(),
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
    #[test]
    fn cancellation_interrupts_metadata_record_iteration() {
        let input = [2, 127, 0].repeat(10000);
        let token = crate::ReadCancellation::new();
        let control = crate::read_control::ReadControl::new(Some(&token));
        control.cancel_after_checks(1);
        let mut handled = 0;
        let err = super::parse_extra_records(&input, 0..input.len(), false, &control, |_, _| {
            handled += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Cancelled);
        assert!(handled > 0 && handled < 10000);
    }
    #[test]
    fn header_budget_refuses_full_reads_after_plain_and_encrypted_prefixes() {
        use crate::parse_budget::{ParseBudget, PrefixReader};
        let mut plain = vec![0u8; 16];
        plain[4] = 60; // 65 plaintext header bytes, larger than the prefix.
        let mut reader = PrefixReader::new(plain[..14].to_vec());
        let options = crate::ArchiveReadOptions::new().with_max_header_bytes(64);
        let e = super::read_block_header_at(&mut reader, 0, 128, 0, &mut ParseBudget::new(options))
            .map(|_| ())
            .expect_err("header budget must refuse");
        assert!(matches!(
            e.root_cause(),
            crate::Error::HeaderBytesLimitExceeded { required: 65, .. }
        ));
        assert_eq!(reader.reads, [14]);

        let keys = crate::crypto::rar50::Rar50Keys::derive(b"secret", [0; 16], 0).unwrap();
        crate::crypto::rar50::Rar50Cipher::new(keys.key, [0; 16])
            .encrypt_in_place(&mut plain)
            .unwrap();
        let mut prefix = vec![0; 16];
        prefix.extend_from_slice(&plain);
        let mut reader = PrefixReader::new(prefix);
        let e = super::read_encrypted_block_header_at(
            &mut reader,
            0,
            128,
            0,
            &keys,
            &mut ParseBudget::new(options),
        )
        .map(|_| ())
        .expect_err("header budget must refuse");
        assert!(matches!(
            e.root_cause(),
            crate::Error::HeaderBytesLimitExceeded { required: 65, .. }
        ));
        assert_eq!(reader.reads, [32]);
    }
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
    fn htime_precision_respects_record_bounds_and_time_layout() {
        let mut unix = vec![0x1f]; // mtime, ctime, atime, then their fractions
        for value in [123u32, 456, 789, 987_654_321, 111, 222] {
            unix.extend_from_slice(&value.to_le_bytes());
        }
        let (seconds, detail) = parse_htime_mtime(&unix, 0..unix.len()).unwrap();
        assert_eq!(seconds, 123);
        assert_eq!(detail.unwrap().nanoseconds, 987_654_321);
        assert_eq!(parse_htime_mtime(&unix, 0..2), None);
        assert_eq!(parse_htime_mtime(&unix, 0..14), Some((123, None)));
        unix[13..17].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        assert_eq!(parse_htime_mtime(&unix, 0..unix.len()), Some((123, None)));

        let mut filetime = vec![2];
        let ticks = (11_644_473_600u64 + 123) * 10_000_000 + 7_040_883;
        filetime.extend_from_slice(&ticks.to_le_bytes());
        let (seconds, detail) = parse_htime_mtime(&filetime, 0..filetime.len()).unwrap();
        assert_eq!(seconds, 123);
        assert_eq!(detail.unwrap().nanoseconds, 704_088_300);
        assert_eq!(parse_htime_mtime(&filetime, 0..8), None);
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
            rewrite_metadata_complete: true,
            unpacked_size: 0,
            attributes: 0,
            mtime: None,
            htime_mtime: None,
            htime_mtime_refinement: None,
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

    /// Builds a member from bytes the test already holds.
    fn rar50_entry(name: &[u8], data: &[u8]) -> crate::rar50::ArchiveEntry {
        crate::rar50::ArchiveEntry::new(
            name.to_vec(),
            crate::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
        )
    }

    fn build_archive_with_optional_comment(comment: Option<&[u8]>) -> Archive {
        use crate::FeatureSet;
        let features = FeatureSet::store_only();
        let entries = [rar50_entry(b"payload.txt", b"payload bytes")
            .with_attributes(0x20)
            .with_host_os(3)];
        let bytes = crate::rar50::Rar50Writer::new(
            crate::rar50::WriterOptions::new(crate::version::ArchiveVersion::Rar50, features)
                .with_compression_level(0),
        )
        .entries(entries.to_vec())
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
        let entry = rar50_entry(b"payload.txt", b"payload bytes")
            .with_attributes(0x20)
            .with_host_os(3)
            .with_service(crate::rar50::ServiceEntry::new(
                b"CMT".to_vec(),
                b"per-file comment".to_vec(),
            ));
        let features = FeatureSet::store_only();
        let bytes = crate::rar50::Rar50Writer::new(crate::rar50::WriterOptions::new(
            crate::version::ArchiveVersion::Rar50,
            features,
        ))
        .entry(entry)
        .finish()
        .unwrap();
        let archive = Archive::parse(&bytes).unwrap();

        assert!(archive.archive_comment().unwrap().is_none());
    }
}
