//! RAR 1.3/1.4 format parsing and sequential extraction.

#[cfg(feature = "write")]
pub(crate) mod write;
#[cfg(feature = "write")]
pub use write::{
    write_compressed_archive, write_compressed_archive_with_comment,
    write_compressed_archive_with_comment_and_progress, write_compressed_volumes,
    write_compressed_volumes_with_progress, write_stored_archive,
    write_stored_archive_with_comment, write_stored_volumes, write_streaming_archive_to,
    EntrySource, FileEntry, MemberCoding, StoredEntry, StreamingEntry, WriterOptions,
    WriterResources,
};
#[cfg(feature = "write")]
pub(crate) use write::{
    write_stored_archive_with_comment_and_progress, write_stored_volumes_with_progress,
};

use crate::codec::rar13::Reader15State;
use crate::codec::workspace::{Allowance, Budget, Buffer};
use crate::crypto::rar13::{Rar13Cipher, Rar13DecryptReader};
use crate::detect::{find_archive_start, ArchiveSignature, RAR13_SIGNATURE, SFX_SCAN_LIMIT};
use crate::error::{Error, Result};
use crate::io_util::{read_exact_at, read_u16, read_u32};
pub(crate) use crate::source::ArchiveSource;
use crate::version::ArchiveFamily;
use crate::volume_extract::ChainedReader;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

const MAIN_HEAD_SIZE: u16 = 7;
const FILE_HEAD_BASE_SIZE: usize = 21;
const MHD_VOLUME: u8 = 0x01;
const MHD_COMMENT: u8 = 0x02;
const MHD_SOLID: u8 = 0x08;
const MHD_PACK_COMMENT: u8 = 0x10;
const MHD_AV: u8 = 0x20;
#[cfg(feature = "write")]
const MHD_ALWAYS_SET: u8 = 0x80;
const RAR13_AV_PREFIX: &[u8; 6] = b"\x1ai\x6d\x02\xda\xae";
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const LHD_SPLIT_BEFORE: u8 = 0x01;
const LHD_SPLIT_AFTER: u8 = 0x02;
const LHD_PASSWORD: u8 = 0x04;
const LHD_COMMENT: u8 = 0x08;
#[cfg(feature = "write")]
const LHD_SOLID: u8 = 0x10;
const METHOD_STORE: u8 = 0;
#[cfg(feature = "write")]
const METHOD_BEST: u8 = 5;
#[cfg(feature = "write")]
const DEFAULT_UNP_VER: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub flags: u8,
    pub head_size: u16,
    pub extra: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub flags: u8,
    pub pack_size: u32,
    pub unp_size: u32,
    pub file_crc: u16,
    pub file_time: u32,
    pub file_attr: u8,
    pub unp_ver: u8,
    pub method: u8,
    pub head_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    pub header: FileHeader,
    pub name: Vec<u8>,
    pub extra: Vec<u8>,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Archive {
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub entries: Vec<Entry>,
    source: ArchiveSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticityVerification {
    pub size: u16,
    pub prefix: [u8; 6],
    pub cipher_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticityVerificationStatus {
    Absent,
    StructurallyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u8,
    pub is_directory: bool,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn has_archive_comment(&self) -> bool {
        self.flags & MHD_COMMENT != 0
    }

    pub fn has_packed_comment(&self) -> bool {
        self.flags & MHD_PACK_COMMENT != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn has_authenticity_verification(&self) -> bool {
        self.flags & MHD_AV != 0
    }

    fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < MAIN_HEAD_SIZE as usize {
            return Err(Error::TooShort);
        }
        if !input.starts_with(RAR13_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let head_size = read_u16(input, 4)?;
        let flags = input[6];
        if head_size < MAIN_HEAD_SIZE {
            return Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes",
            ));
        }
        if head_size as usize > input.len() {
            return Err(Error::TooShort);
        }

        let extra = input[MAIN_HEAD_SIZE as usize..head_size as usize].to_vec();

        Ok(Self {
            flags,
            head_size,
            extra,
        })
    }
}

// Inspect only the fixed prefix before any name/extra allocation or full read.
fn admit_header(
    prefix: &[u8],
    remaining: u64,
    main: bool,
    budget: &mut crate::parse_budget::ParseBudget,
    offset: usize,
) -> Result<()> {
    budget.control.check()?;
    if !budget.is_limited() {
        return Ok(());
    }
    let base = if main {
        MAIN_HEAD_SIZE as usize
    } else {
        FILE_HEAD_BASE_SIZE
    };
    if prefix.len() < base {
        return Err(Error::TooShort);
    }
    if main && !prefix.starts_with(RAR13_SIGNATURE) {
        return Err(Error::UnsupportedSignature);
    }
    let size = read_u16(prefix, if main { 4 } else { 10 })? as usize;
    let minimum = if main {
        base
    } else {
        base + prefix[19] as usize
    };
    if size < minimum {
        return Err(Error::InvalidHeader(if main {
            "RAR 1.3 main header is shorter than 7 bytes"
        } else {
            "RAR 1.3 file header is shorter than its name"
        }));
    }
    if size as u64 > remaining {
        return Err(Error::TooShort);
    }
    budget.admit(size, offset)
}

impl FileHeader {
    fn parse(input: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>, usize)> {
        if input.len() < FILE_HEAD_BASE_SIZE {
            return Err(Error::TooShort);
        }

        let pack_size = read_u32(input, 0)?;
        let unp_size = read_u32(input, 4)?;
        let file_crc = read_u16(input, 8)?;
        let head_size = read_u16(input, 10)?;
        let file_time = read_u32(input, 12)?;
        let file_attr = input[16];
        let flags = input[17];
        let unp_ver = input[18];
        let name_size = input[19] as usize;
        let method = input[20];
        let minimum_size = FILE_HEAD_BASE_SIZE + name_size;

        if (head_size as usize) < minimum_size {
            return Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name",
            ));
        }
        if input.len() < head_size as usize {
            return Err(Error::TooShort);
        }

        let name = input[FILE_HEAD_BASE_SIZE..FILE_HEAD_BASE_SIZE + name_size].to_vec();
        let extra = input[minimum_size..head_size as usize].to_vec();
        Ok((
            Self {
                flags,
                pack_size,
                unp_size,
                file_crc,
                file_time,
                file_attr,
                unp_ver,
                method,
                head_size,
            },
            name,
            extra,
            head_size as usize,
        ))
    }
}

/// Stored members need no dictionary. Delay model allocation until the first
/// compressed member, retaining the same allowance throughout a solid chain.
struct Decoder15<B: Budget = Allowance> {
    read_control: crate::read_control::ReadControl,
    allowance: B,
    state: Option<Reader15State<B>>,
}
impl<B: Budget> Decoder15<B> {
    fn with_allowance(allowance: &B) -> Self {
        Self {
            read_control: Default::default(),
            allowance: allowance.clone(),
            state: None,
        }
    }
    fn reset(&mut self) {
        self.state = None;
    }
    fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        solid: bool,
        out: &mut impl Write,
    ) -> crate::codec::Result<()> {
        self.read_control.check_codec()?;
        if self.state.is_none() {
            self.state = Some(Reader15State::with_allowance(&self.allowance)?);
        }
        let state = self.state.as_mut().expect("decoder initialized above");
        state.read_control = self.read_control.clone();
        state.decode_member_from_reader(input, output_size, solid, out)
    }
}
impl Decoder15<Allowance> {
    fn new() -> Self {
        Self::with_allowance(&Allowance::default())
    }
}

impl Archive {
    pub fn parse(input: &[u8]) -> Result<Self> {
        Self::parse_with_options(input, crate::ArchiveReadOptions::default())
    }

    pub fn parse_with_options(
        input: &[u8],
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data, options)
    }

    pub fn parse_owned(input: Vec<u8>) -> Result<Self> {
        Self::parse_owned_with_options(input, crate::ArchiveReadOptions::default())
    }

    pub fn parse_owned_with_options(
        input: Vec<u8>,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        Self::parse_shared(Arc::from(input.into_boxed_slice()), options)
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse_path_with_options(path, crate::ArchiveReadOptions::default())
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
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }
        Self::parse_seekable(file, len, sig.offset, ArchiveSource::File(path), options)
    }

    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
    ) -> Result<Self> {
        Self::parse_path_with_signature_and_options(
            path,
            signature,
            crate::ArchiveReadOptions::default(),
        )
    }

    pub fn parse_path_with_signature_and_options(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        if signature.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        Self::parse_seekable(
            file,
            len,
            signature.offset,
            ArchiveSource::File(path),
            options,
        )
    }

    fn parse_shared(input: Arc<[u8]>, options: crate::ArchiveReadOptions<'_>) -> Result<Self> {
        options.check_cancelled()?;
        let sig = find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }

        let archive = &input[sig.offset..];
        let mut budget = crate::parse_budget::ParseBudget::new(options);
        admit_header(archive, archive.len() as u64, true, &mut budget, 0)?;
        let main = MainHeader::parse(archive)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while pos < archive.len() {
            if archive.len() - pos < FILE_HEAD_BASE_SIZE {
                break;
            }

            admit_header(
                &archive[pos..],
                (archive.len() - pos) as u64,
                false,
                &mut budget,
                pos,
            )?;
            let (header, name, extra, consumed) = FileHeader::parse(&archive[pos..])?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if data_end > archive.len() {
                return Err(Error::TooShort);
            }

            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sig.offset + data_start..sig.offset + data_end,
            });
            pos = data_end;
        }

        options.check_cancelled()?;
        Ok(Self {
            sfx_offset: sig.offset,
            main,
            entries,
            source: ArchiveSource::Memory(input),
        })
    }

    pub(crate) fn parse_seekable(
        file: impl Read + std::io::Seek,
        file_len: u64,
        sfx_offset: usize,
        source: ArchiveSource,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        options.check_cancelled()?;
        let mut budget = crate::parse_budget::ParseBudget::new(options);
        let mut file = budget.control.reader(file);
        let main_prefix = read_exact_at(&mut file, sfx_offset, MAIN_HEAD_SIZE as usize)?;
        let head_size = read_u16(&main_prefix, 4)? as usize;
        admit_header(
            &main_prefix,
            file_len
                .checked_sub(sfx_offset as u64)
                .ok_or(Error::TooShort)?,
            true,
            &mut budget,
            0,
        )?;
        let main_bytes = read_exact_at(&mut file, sfx_offset, head_size)?;
        let main = MainHeader::parse(&main_bytes)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while (sfx_offset + pos) as u64 + FILE_HEAD_BASE_SIZE as u64 <= file_len {
            let header_prefix = read_exact_at(&mut file, sfx_offset + pos, FILE_HEAD_BASE_SIZE)?;
            let head_size = read_u16(&header_prefix, 10)? as usize;
            admit_header(
                &header_prefix,
                file_len
                    .checked_sub((sfx_offset + pos) as u64)
                    .ok_or(Error::TooShort)?,
                false,
                &mut budget,
                pos,
            )?;
            let header_bytes = read_exact_at(&mut file, sfx_offset + pos, head_size)?;
            let (header, name, extra, consumed) = FileHeader::parse(&header_bytes)?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if (sfx_offset + data_end) as u64 > file_len {
                return Err(Error::TooShort);
            }
            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sfx_offset + data_start..sfx_offset + data_end,
            });
            pos = data_end;
        }

        options.check_cancelled()?;
        Ok(Self {
            sfx_offset,
            main,
            entries,
            source,
        })
    }

    fn copy_range_to(&self, range: Range<usize>, out: &mut impl Write) -> Result<()> {
        self.source.copy_range_to(range, out)
    }

    fn range_reader(&self, range: Range<usize>) -> Result<crate::source::RangeReader<'_>> {
        self.source.range_reader(range)
    }

    fn copy_decrypted_range_to(
        &self,
        range: Range<usize>,
        mut cipher: Rar13Cipher,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut buffer = [0u8; COPY_BUFFER_SIZE];
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                for chunk in data.chunks(COPY_BUFFER_SIZE) {
                    buffer[..chunk.len()].copy_from_slice(chunk);
                    for byte in &mut buffer[..chunk.len()] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..chunk.len()])?;
                }
            }
            ArchiveSource::File(_) | ArchiveSource::Reader(_) => {
                let mut file = self.source.range_reader(range.clone())?;
                let mut remaining = range.len();
                while remaining > 0 {
                    let to_read = remaining.min(buffer.len());
                    file.read_exact(&mut buffer[..to_read])?;
                    for byte in &mut buffer[..to_read] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..to_read])?;
                    remaining -= to_read;
                }
            }
        }
        Ok(())
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_with_options(
            crate::ArchiveReadOptions::with_optional_password(password),
            open,
        )
    }

    /// Extracts members with explicit output policy; default wrappers retain their behavior.
    pub fn extract_to_with_options<F>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_impl(options, &mut open, None, None)
            .map(|_| ())
    }

    pub(crate) fn extract_controlled(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        selector: &mut crate::extraction_control::Selector<'_>,
        on_error: Option<&mut crate::extraction_control::ErrorHandler<'_>>,
    ) -> Result<crate::ExtractionOutcome> {
        self.extract_impl(
            options,
            &mut |_| unreachable!("controlled selection supplies writer"),
            Some(selector),
            on_error,
        )
    }

    fn extract_impl<F>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        open: &mut F,
        selector: Option<&mut crate::extraction_control::Selector<'_>>,
        on_error: Option<&mut crate::extraction_control::ErrorHandler<'_>>,
    ) -> Result<crate::ExtractionOutcome>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        if let Some(limit) = options.max_reader_workspace_bytes {
            return self.extract_with_allowance(
                options,
                open,
                selector,
                on_error,
                &crate::codec::workspace::Allowance::limited(limit),
            );
        }
        self.extract_with_allowance(options, open, selector, on_error, &Allowance::default())
    }

    fn extract_with_allowance<F, B: Budget>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        open: &mut F,
        mut selector: Option<&mut crate::extraction_control::Selector<'_>>,
        mut on_error: Option<&mut crate::extraction_control::ErrorHandler<'_>>,
        allowance: &B,
    ) -> Result<crate::ExtractionOutcome>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        options.check_cancelled()?;
        let password = options.password;
        let mut budget = crate::output_limit::OutputBudget::new(options);
        let mut unpack15 = Decoder15::with_allowance(allowance);
        unpack15.read_control = budget.control.clone();
        let mut extracted_count = 0usize;
        let solid = self.main.is_solid();
        for entry in &self.entries {
            let selected = crate::extraction_control::select(
                &mut selector,
                options,
                || crate::rar13_member(entry),
                solid,
            )?;
            let mut selected_writer = match selected {
                Some(crate::ExtractionDecision::Skip) => continue,
                Some(crate::ExtractionDecision::Stop) => {
                    return Ok(crate::ExtractionOutcome::Stopped)
                }
                Some(crate::ExtractionDecision::Extract(writer)) => Some(writer),
                None => None,
            };
            let result = (|| {
                options.check_cancelled()?;
                if entry.is_split_before() || entry.is_split_after() {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry requires multivolume extraction",
                    ));
                }
                let meta = entry.metadata();
                if meta.is_directory {
                    options.check_cancelled()?;
                    let _ = match selected_writer.take() {
                        Some(writer) => writer,
                        None => open(&meta)?,
                    };
                    options.check_cancelled()?;
                    extracted_count += 1;
                    return Ok(());
                }
                budget.check(u64::from(entry.header.unp_size), &meta.name)?;
                options.check_cancelled()?;
                let mut writer = match selected_writer.take() {
                    Some(writer) => writer,
                    None => open(&meta)?,
                };
                options.check_cancelled()?;
                budget.run(&meta.name, &mut writer, |mut writer| {
                    if entry.is_stored() && !entry.is_encrypted() {
                        entry
                            .write_stored_to(self, password, &mut writer)
                            .map_err(|error| entry.entry_error("extracting", error))?;
                    } else {
                        entry
                            .write_compressed_to(
                                self,
                                password,
                                &mut unpack15,
                                self.main.is_solid() && extracted_count != 0,
                                &mut writer,
                            )
                            .map_err(|error| entry.entry_error("extracting", error))?;
                    }
                    Ok(())
                })?;
                extracted_count += 1;
                Ok(())
            })();
            if crate::extraction_control::finish_member(
                &mut on_error,
                options,
                || crate::rar13_member(entry),
                solid,
                result,
            )? {
                unpack15.reset();
                unpack15.read_control = budget.control.clone();
            }
        }
        options.check_cancelled()?;
        Ok(crate::ExtractionOutcome::Complete)
    }

    #[cfg(feature = "write")]
    pub(crate) fn rewrite_preservation_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let exact_comment = |extra: &[u8], present: bool| {
            if present {
                read_u16(extra, 0).is_ok_and(|size| usize::from(size) + 2 == extra.len())
            } else {
                extra.is_empty()
            }
        };
        if self.main.flags & !(MHD_COMMENT | MHD_SOLID | MHD_PACK_COMMENT | MHD_ALWAYS_SET) != 0
            || (self.main.has_packed_comment() && !self.main.has_archive_comment())
            || !exact_comment(&self.main.extra, self.main.has_archive_comment())
        {
            issues.push(
                "RAR1.3/1.4 main metadata, volumes or authenticity records are unsupported".into(),
            );
        }
        if self.entries.is_empty() {
            issues.push("empty legacy archive (source format cannot be inferred)".into());
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.header.unp_ver != DEFAULT_UNP_VER
                || entry.header.method > METHOD_BEST
                || entry.header.flags & !(LHD_PASSWORD | LHD_COMMENT | LHD_SOLID) != 0
                || (!self.main.is_solid() && entry.header.flags & LHD_SOLID != 0)
                || !exact_comment(&entry.extra, entry.has_file_comment())
                || (entry.is_directory()
                    && (entry.header.pack_size != 0 || entry.header.unp_size != 0))
            {
                issues.push(format!("RAR1.3/1.4 member {index}: unsupported version, flags, comments or directory payload"));
            }
        }
        if self.entries.last().map(|entry| entry.packed_range.end) != self.source.len().ok() {
            issues.push("RAR1.3/1.4 trailing bytes or incomplete archive".into());
        }
        issues
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        self.archive_comment_with_options(crate::ArchiveReadOptions::new())
    }

    /// Decodes the archive comment under the same policy as [`crate::Archive::comment_with_options`].
    pub fn archive_comment_with_options(
        &self,
        options: crate::ArchiveReadOptions<'_>,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(limit) = options.max_reader_workspace_bytes {
            return self.archive_comment_with_allowance(options, &Allowance::limited(limit));
        }
        self.archive_comment_with_allowance(options, &Allowance::default())
    }

    fn archive_comment_with_allowance<B: Budget>(
        &self,
        options: crate::ArchiveReadOptions<'_>,
        allowance: &B,
    ) -> Result<Option<Vec<u8>>> {
        options.check_cancelled()?;
        let mut budget = crate::output_limit::OutputBudget::new(options);
        if !self.main.has_archive_comment() {
            return Ok(None);
        }

        let length = read_u16(&self.main.extra, 0)? as usize;
        if self.main.has_packed_comment() {
            if length < 2 {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 packed archive comment is shorter than size field",
                ));
            }
            let unpacked_len = read_u16(&self.main.extra, 2)? as usize;
            let packed_len = length - 2;
            let packed_start = 4usize;
            let packed_end = packed_start
                .checked_add(packed_len)
                .ok_or(Error::InvalidHeader(
                    "RAR 1.3 archive comment size overflows",
                ))?;
            if packed_end > self.main.extra.len() {
                return Err(Error::TooShort);
            }

            budget.check(unpacked_len as u64, b"CMT")?;
            let mut packed = Rar13DecryptReader::new(
                &self.main.extra[packed_start..packed_end],
                Rar13Cipher::new_comment(),
            );
            let mut decoder = Decoder15::with_allowance(allowance);
            decoder.read_control = budget.control.clone();
            let mut data = Vec::new();
            budget.run(b"CMT", &mut data, |writer| {
                decoder.decode_member_from_reader(&mut packed, unpacked_len, false, writer)?;
                Ok(())
            })?;
            return Ok(Some(data));
        }

        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader(
                "RAR 1.3 archive comment size overflows",
            ))?;
        if comment_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        budget.check(length as u64, b"CMT")?;
        let mut data = Vec::new();
        budget.run(b"CMT", &mut data, |writer| {
            writer.write_all(&self.main.extra[comment_start..comment_end])?;
            Ok(())
        })?;
        Ok(Some(data))
    }

    pub fn authenticity_verification(&self) -> Result<Option<AuthenticityVerification>> {
        if !self.main.has_authenticity_verification() {
            return Ok(None);
        }
        let size = read_u16(&self.main.extra, 0)?;
        if size < RAR13_AV_PREFIX.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"));
        }
        let payload_end = 2usize
            .checked_add(size as usize)
            .ok_or(Error::InvalidHeader("RAR 1.3 AV payload size overflows"))?;
        if payload_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        let prefix_bytes = self
            .main
            .extra
            .get(2..2 + RAR13_AV_PREFIX.len())
            .ok_or(Error::TooShort)?;
        let prefix: [u8; 6] = prefix_bytes
            .try_into()
            .expect("RAR 1.3 AV prefix slice has fixed length");
        if &prefix != RAR13_AV_PREFIX {
            return Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"));
        }
        Ok(Some(AuthenticityVerification {
            size,
            prefix,
            cipher_body: self.main.extra[2 + RAR13_AV_PREFIX.len()..payload_end].to_vec(),
        }))
    }

    pub fn authenticity_verification_status(&self) -> Result<AuthenticityVerificationStatus> {
        Ok(if self.authenticity_verification()?.is_some() {
            AuthenticityVerificationStatus::StructurallyPresent
        } else {
            AuthenticityVerificationStatus::Absent
        })
    }
}

impl Entry {
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the entry name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn is_encrypted(&self) -> bool {
        self.header.flags & LHD_PASSWORD != 0
    }

    pub fn is_split_before(&self) -> bool {
        self.header.flags & LHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.header.flags & LHD_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.header.file_attr & 0x10 != 0
    }

    pub fn has_file_comment(&self) -> bool {
        self.header.flags & LHD_COMMENT != 0
    }

    pub fn file_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_file_comment() {
            return Ok(None);
        }
        let length = read_u16(&self.extra, 0)? as usize;
        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader("RAR 1.3 file comment size overflows"))?;
        if comment_end > self.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.extra[comment_start..comment_end].to_vec()))
    }

    pub fn is_stored(&self) -> bool {
        self.header.method == METHOD_STORE
    }

    pub fn packed_data<'a>(&self, archive: &'a Archive) -> Result<&'a [u8]> {
        match &archive.source {
            ArchiveSource::Memory(data) => {
                data.get(self.packed_range.clone()).ok_or(Error::TooShort)
            }
            ArchiveSource::File(_) | ArchiveSource::Reader(_) => Err(Error::InvalidHeader(
                "RAR 1.3 file-backed packed data requires owned read",
            )),
        }
    }

    pub fn write_packed_data(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        archive.copy_range_to(self.packed_range.clone(), out)
    }

    pub fn verify_checksum(&self, data: &[u8]) -> Result<()> {
        let actual = file_checksum(data);
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: self.is_directory(),
        }
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_encrypted() {
            crate::crypto::require_encryption()?;
            let password = password.ok_or(Error::NeedPassword)?;
            let mut checksum = Rar13Checksum::new();
            let mut checksum_writer = Rar13ChecksumWriter {
                inner: out,
                checksum: &mut checksum,
            };
            archive.copy_decrypted_range_to(
                self.packed_range.clone(),
                Rar13Cipher::new(password),
                &mut checksum_writer,
            )?;
            let actual = checksum.finish();
            return if actual == self.header.file_crc {
                Ok(())
            } else {
                Err(Error::CrcMismatch {
                    expected: self.header.file_crc,
                    actual,
                })
            };
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        self.write_packed_data(archive, &mut checksum_writer)?;
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    fn write_compressed_to<B: Budget>(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        unpack15: &mut Decoder15<B>,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        if self.is_encrypted() {
            crate::crypto::require_encryption()?;
            let password = password.ok_or(Error::NeedPassword)?;
            let packed = archive.range_reader(self.packed_range.clone())?;
            let mut packed = Rar13DecryptReader::new(packed, Rar13Cipher::new(password));
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        } else {
            let mut packed = archive.range_reader(self.packed_range.clone())?;
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        }
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        self.write_compressed_to(archive, password, &mut Decoder15::new(), false, out)
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        if matches!(
            error,
            Error::NeedPassword | Error::WrongPasswordOrCorruptData
        ) {
            return error;
        }
        if self.is_encrypted()
            && !matches!(
                error.kind(),
                crate::ErrorKind::ResourceLimit
                    | crate::ErrorKind::Cancelled
                    | crate::ErrorKind::Io
            )
            && matches!(
                error,
                Error::InvalidHeader(_)
                    | Error::Codec(_)
                    | Error::CrcMismatch { .. }
                    | Error::Crc32Mismatch { .. }
                    | Error::HashMismatch { .. }
            )
        {
            return Error::WrongPasswordOrCorruptData;
        }
        error.at_entry(self.name.clone(), operation)
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(volumes: &[Archive], password: Option<&[u8]>, open: F) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_with_options(
        volumes,
        crate::ArchiveReadOptions::with_optional_password(password),
        open,
    )
}

/// Extracts logical volume members with explicit output policy.
pub fn extract_volumes_to_with_options<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    if let Some(limit) = options.max_reader_workspace_bytes {
        return extract_volumes_with_allowance(volumes, options, open, &Allowance::limited(limit));
    }
    extract_volumes_with_allowance(volumes, options, open, &Allowance::default())
}

fn extract_volumes_with_allowance<F, B: Budget>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    allowance: &B,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    options.check_cancelled()?;
    let password = options.password;
    let mut budget = crate::output_limit::OutputBudget::new(options);
    let mut pending: Option<PendingSplitRefs<B>> = None;
    let mut unpack15 = Decoder15::with_allowance(allowance);
    unpack15.read_control = budget.control.clone();
    let mut extracted_count = 0usize;

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (entry_index, entry) in archive.entries.iter().enumerate() {
            options.check_cancelled()?;
            if !entry.is_split_before() && !entry.is_split_after() {
                if pending.is_some() {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry is interrupted by a regular entry",
                    ));
                }
                let meta = entry.metadata();
                if meta.is_directory {
                    options.check_cancelled()?;
                    let _ = open(&meta)?;
                    options.check_cancelled()?;
                    extracted_count += 1;
                    continue;
                }
                budget.check(u64::from(entry.header.unp_size), &meta.name)?;
                options.check_cancelled()?;
                let mut writer = open(&meta)?;
                options.check_cancelled()?;
                budget.run(&meta.name, &mut writer, |mut writer| {
                    entry
                        .write_compressed_to(
                            archive,
                            password,
                            &mut unpack15,
                            archive.main.is_solid() && extracted_count != 0,
                            &mut writer,
                        )
                        .map_err(|error| entry.entry_error("extracting", error))?;
                    options.check_cancelled()?;
                    Ok(())
                })?;
                extracted_count += 1;
                continue;
            }

            match (
                &mut pending,
                entry.is_split_before(),
                entry.is_split_after(),
            ) {
                (None, false, true) => {
                    pending = Some(PendingSplitRefs::with_allowance(
                        entry,
                        volume_index,
                        entry_index,
                        allowance,
                    )?);
                }
                (Some(current), true, true) => {
                    current.append(entry, volume_index, entry_index)?;
                }
                (Some(current), true, false) => {
                    current.append(entry, volume_index, entry_index)?;
                    let completed = pending.take().expect("pending split");
                    let solid = archive.main.is_solid() && extracted_count != 0;
                    completed
                        .write_to(
                            volumes,
                            entry,
                            options,
                            &mut budget,
                            &mut unpack15,
                            solid,
                            &mut open,
                        )
                        .map_err(|error| entry.entry_error("extracting", error))?;
                    extracted_count += 1;
                }
                _ => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry flags are inconsistent",
                    ));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 1.3 split entry is incomplete"));
    }

    options.check_cancelled()?;
    Ok(())
}

struct Rar13ChecksumWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    checksum: &'a mut Rar13Checksum,
}

impl<W: Write + ?Sized> Write for Rar13ChecksumWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.checksum.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct Rar13Checksum {
    value: u16,
}

impl Rar13Checksum {
    fn new() -> Self {
        Self { value: 0 }
    }

    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.value = self.value.wrapping_add(byte as u16).rotate_left(1);
        }
    }

    fn finish(self) -> u16 {
        self.value
    }
}

struct PendingSplitRefs<B: Budget = Allowance> {
    name: Vec<u8>,
    fragments: Buffer<(usize, usize), B>,
    file_time: u32,
    file_attr: u8,
    method: u8,
    unp_ver: u8,
    was_encrypted: bool,
}

impl<B: Budget> PendingSplitRefs<B> {
    fn with_allowance(
        entry: &Entry,
        volume_index: usize,
        entry_index: usize,
        allowance: &B,
    ) -> Result<Self> {
        Ok(Self {
            name: entry.name.clone(),
            fragments: Buffer::copied(&[(volume_index, entry_index)], allowance)?,
            file_time: entry.header.file_time,
            file_attr: entry.header.file_attr,
            method: entry.header.method,
            unp_ver: entry.header.unp_ver,
            was_encrypted: entry.is_encrypted(),
        })
    }

    fn append(&mut self, entry: &Entry, volume_index: usize, entry_index: usize) -> Result<()> {
        if entry.name != self.name {
            return Err(Error::InvalidHeader("RAR 1.3 split entry name changed"));
        }
        if entry.header.method != self.method {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry compression method changed",
            ));
        }
        if entry.header.unp_ver != self.unp_ver {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry unpack version changed",
            ));
        }
        if entry.is_encrypted() != self.was_encrypted {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry encryption flag changed",
            ));
        }
        self.fragments.try_push((volume_index, entry_index))?;
        Ok(())
    }

    // Split decoding needs format state, policy accounting and the output callback.
    #[allow(clippy::too_many_arguments)]
    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_entry: &Entry,
        options: crate::ArchiveReadOptions<'_>,
        budget: &mut crate::output_limit::OutputBudget,
        unpack15: &mut Decoder15<B>,
        solid: bool,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        options.check_cancelled()?;
        let password = options.password;
        budget.check(u64::from(final_entry.header.unp_size), &self.name)?;
        let mut reader =
            self.fragment_reader_with_allowance(volumes, password, &unpack15.allowance)?;
        let meta = ExtractedEntryMeta {
            name: self.name,
            file_time: self.file_time,
            file_attr: self.file_attr,
            is_directory: false,
        };
        options.check_cancelled()?;
        let mut writer = open(&meta)?;
        options.check_cancelled()?;
        budget.run(&meta.name, &mut writer, |mut writer| {
            let mut checksum = Rar13Checksum::new();
            let mut checksum_writer = Rar13ChecksumWriter {
                inner: &mut writer,
                checksum: &mut checksum,
            };
            if self.method == METHOD_STORE {
                std::io::copy(&mut reader, &mut checksum_writer)?;
            } else {
                unpack15.decode_member_from_reader(
                    &mut reader,
                    final_entry.header.unp_size as usize,
                    solid,
                    &mut checksum_writer,
                )?;
            }
            let actual = checksum.finish();
            if actual == final_entry.header.file_crc {
                options.check_cancelled()?;
                Ok(())
            } else {
                Err(Error::CrcMismatch {
                    expected: final_entry.header.file_crc,
                    actual,
                })
            }
        })
    }

    fn fragment_reader_with_allowance<'a>(
        &self,
        volumes: &'a [Archive],
        password: Option<&'a [u8]>,
        allowance: &B,
    ) -> Result<PackedReader<ChainedReader<crate::source::RangeReader<'a>, B>>> {
        let mut readers = Buffer::with_capacity(self.fragments.len(), allowance)?;
        for &(volume_index, entry_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split volume is missing"))?;
            let entry = archive
                .entries
                .get(entry_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split entry is missing"))?;
            readers.push_admitted(archive.range_reader(entry.packed_range.clone())?);
        }
        let chained = ChainedReader::with_readers(readers);
        if self.was_encrypted {
            crate::crypto::require_encryption()?;
            let password = password.ok_or(Error::NeedPassword)?;
            // RAR 1.402 encrypts the logical packed stream continuously across
            // split volumes; restarting the cipher at each part corrupts it.
            Ok(PackedReader::Encrypted(Rar13DecryptReader::new(
                chained,
                Rar13Cipher::new(password),
            )))
        } else {
            Ok(PackedReader::Plain(chained))
        }
    }
}

enum PackedReader<R> {
    Plain(R),
    Encrypted(Rar13DecryptReader<R>),
}
impl<R: Read> Read for PackedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read(out),
            Self::Encrypted(reader) => reader.read(out),
        }
    }
}

pub fn file_checksum(input: &[u8]) -> u16 {
    let mut checksum = Rar13Checksum::new();
    checksum.update(input);
    checksum.finish()
}
