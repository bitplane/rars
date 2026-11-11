use super::*;
use crate::volume_sink::VolumeSink;
use std::io::{Read, Seek, SeekFrom};

/// A multiple of the cipher block, so only the last piece is ever padded.
const STREAM_CHUNK: usize = 64 * 1024;

/// Splits a stored member across volumes as it reads, so neither it nor the set is held.
pub fn write_stored_volumes_to(
    entry: &StreamingEntry,
    options: WriterOptions,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    split_stored(
        StoredSplit {
            name: &entry.name,
            bytes: MemberBytes::Source(&entry.source),
            file_time: entry.file_time,
            file_attr: entry.file_attr,
            host_os: entry.host_os,
            password: entry.password.as_deref(),
            file_comment: entry.file_comment.as_deref(),
        },
        options,
        volume_size,
        sink,
        resources,
        progress,
    )
}

pub(super) struct StoredSplit<'a> {
    pub(super) name: &'a [u8],
    pub(super) bytes: MemberBytes<'a>,
    pub(super) file_time: u32,
    pub(super) file_attr: u32,
    pub(super) host_os: u8,
    pub(super) password: Option<&'a [u8]>,
    pub(super) file_comment: Option<&'a [u8]>,
}

pub(super) fn split_stored(
    member: StoredSplit<'_>,
    options: WriterOptions,
    volume_size: usize,
    sink: &mut dyn VolumeSink,
    resources: &WriterResources,
    progress: Option<&dyn WriteProgress>,
) -> Result<()> {
    let control =
        crate::write_progress::ResourceProgress::new(resources, progress.map(ProgressReporter));
    let progress = ProgressReporter(&control);
    crate::write_progress::check_cancelled(Some(progress))?;
    validate_plan(options, PlanShape::new().volumes(true), false, false)?;
    let name = member.name;
    let source_len = member.bytes.len()?;
    let unpacked = usize::try_from(source_len)
        .map_err(|_| Error::InvalidArgument("RAR 1.5 writer does not support large files"))
        .and_then(|len| validate_member(name, len).map(|()| len))
        .map_err(|error| {
            crate::write_stream::member_error(error, name, "preparing volume member")
        })?;
    if member.file_comment.is_some() {
        return Err(Error::UnsupportedFeature {
            version: options.target,
            feature: "volume_file_comment",
        });
    }
    let header_password = if options.features.header_encryption {
        validate_header_encrypted_archive_options(options.target, member.password.is_some())?;
        Some(member.password.ok_or(Error::NeedPassword)?)
    } else {
        None
    };
    if unpacked == 0 {
        return Err(Error::InvalidArgument(
            "RAR 1.5 volume writer needs a non-empty packed payload",
        )
        .at_entry(name.to_vec(), "preparing volume member"));
    }
    let cipher = CipherPlan::new(options.target, member.password).map_err(|error| {
        crate::write_stream::member_error(error, name, "encrypting volume member")
    })?;
    let packed_len = cipher.packed_len(source_len)?;
    if volume_size == 0 {
        return Err(Error::InvalidArgument("volume size must be non-zero"));
    }

    let work = WorkTracker::new(Some(progress), WriteOperation::Emission, source_len);
    progress.report(WriteProgressEvent::OperationStarted {
        operation: WriteOperation::Emission,
        total_bytes: Some(source_len),
        total_entries: Some(1),
        pass: 1,
    });
    let mut packer = VolumePacker::new(
        sink,
        volume_size as u64,
        options.target,
        header_password,
        progress,
    )?;
    let member = VolumeMember {
        name,
        target: options.target,
        unpacked_size: source_len,
        file_time: member.file_time,
        file_attr: member.file_attr,
        host_os: member.host_os,
        method: 0x30,
        dictionary_flags: dictionary_flags_for_options(options)?,
        file_flags: writer_file_flags(member.password, None, false)
            | if cipher.salt.is_some() { FHD_SALT } else { 0 },
        salt: cipher.salt,
        packed_len,
        final_crc: None,
        payload: PackedStream::open(&member.bytes, source_len, &cipher, progress, Some(&work))?,
    };
    packer.expect_only(&member)?;
    packer.write_member(member)?;
    packer.finish()?;
    if !work.finish() {
        return Err(Error::Cancelled);
    }
    progress.report(WriteProgressEvent::OperationFinished {
        operation: WriteOperation::Emission,
        total_bytes: Some(source_len),
        total_entries: Some(1),
        pass: 1,
    });
    crate::write_progress::check_cancelled(Some(progress))
}

/// Header fields and two readers over one member's packed bytes.
struct VolumeMember<'a> {
    name: &'a [u8],
    target: ArchiveVersion,
    unpacked_size: u64,
    file_time: u32,
    file_attr: u32,
    host_os: u8,
    method: u8,
    dictionary_flags: u16,
    file_flags: u16,
    salt: Option<[u8; 8]>,
    packed_len: u64,
    /// Known when packing worked it out; otherwise found while copying the payload.
    final_crc: Option<u32>,
    payload: PackedStream<'a>,
}

impl VolumeMember<'_> {
    fn header(
        &self,
        split_before: bool,
        split_after: bool,
        packed_size: u64,
        file_crc: u32,
        header_password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut flags = self.file_flags;
        if split_before {
            flags |= FHD_SPLIT_BEFORE;
        }
        if split_after {
            flags |= FHD_SPLIT_AFTER;
        }
        let size = |value: u64| {
            usize::try_from(value)
                .map_err(|_| Error::InvalidArgument("RAR 1.5 writer does not support large files"))
        };
        let mut header = Vec::new();
        write_file_header(
            &mut header,
            &FileRecord {
                head_type: FILE_HEAD,
                name: self.name,
                unpacked_size: size(self.unpacked_size)?,
                file_crc,
                packed_size: size(packed_size)?,
                file_time: self.file_time,
                file_attr: self.file_attr,
                host_os: self.host_os,
                target: self.target,
                method: self.method,
                dictionary_flags: self.dictionary_flags,
                flags,
                salt: self.salt,
                extra: &[],
            },
        )?;
        match header_password {
            Some(password) => {
                let mut out = Vec::new();
                write_encrypted_header(&mut out, &header, password)?;
                Ok(out)
            }
            None => Ok(header),
        }
    }
}

/// Packs members into volumes; end blocks wait for the close, when it is known whether more follow.
struct VolumePacker<'a> {
    sink: &'a mut dyn VolumeSink,
    volume_size: u64,
    target: ArchiveVersion,
    header_password: Option<&'a [u8]>,
    progress: ProgressReporter<'a>,
    tail_len: u64,
    open: Option<OpenVolume>,
    index: u64,
    total_volumes: Option<usize>,
}

struct OpenVolume {
    out: Box<dyn crate::volume_sink::VolumeOutput>,
    used: u64,
    fragments: u64,
}

impl<'a> VolumePacker<'a> {
    fn new(
        sink: &'a mut dyn VolumeSink,
        volume_size: u64,
        target: ArchiveVersion,
        header_password: Option<&'a [u8]>,
        progress: ProgressReporter<'a>,
    ) -> Result<Self> {
        let mut packer = Self {
            sink,
            volume_size,
            target,
            header_password,
            progress,
            tail_len: 0,
            open: None,
            index: 0,
            total_volumes: None,
        };
        packer.tail_len = packer.tail(false)?.len() as u64;
        Ok(packer)
    }

    /// Works out the set's size up front when `member` is the only one.
    fn expect_only(&mut self, member: &VolumeMember<'_>) -> Result<()> {
        let header_len = self.header_len(member).map_err(|error| {
            crate::write_stream::member_error(error, member.name, "writing volume member")
        })?;
        let overhead = self.head(0)?.len() as u64 + header_len + self.tail_len;
        if let Some(payload) = self.volume_size.checked_sub(overhead).filter(|&p| p > 0) {
            let total = member.packed_len.div_ceil(payload);
            self.sink.expect_volumes(total)?;
            self.total_volumes = usize::try_from(total).ok();
        }
        Ok(())
    }

    /// Header length depends only on the member, not on the fragment.
    fn header_len(&self, member: &VolumeMember<'_>) -> Result<u64> {
        let probe = member.packed_len.min(self.volume_size);
        Ok(member
            .header(false, true, probe, 0, self.header_password)?
            .len() as u64)
    }

    fn write_member(&mut self, mut member: VolumeMember<'_>) -> Result<()> {
        let name = member.name;
        self.write_fragments(&mut member).map_err(|error| {
            crate::write_stream::member_error(error, name, "writing volume member")
        })
    }

    fn write_fragments(&mut self, member: &mut VolumeMember<'_>) -> Result<()> {
        let header_len = self.header_len(member)?;
        let mut start = 0;
        loop {
            crate::write_progress::check_cancelled(Some(self.progress))?;
            if self.open.is_none() {
                self.start_volume()?;
            }
            let volume = self.open.as_ref().expect("volume started");
            let room = self
                .volume_size
                .saturating_sub(volume.used)
                .saturating_sub(self.tail_len)
                .saturating_sub(header_len);
            let remaining = member.packed_len - start;
            if room == 0 && remaining > 0 {
                if volume.fragments == 0 {
                    return Err(Error::InvalidArgument(
                        "volume size is too small to hold the volume headers",
                    ));
                }
                self.close_volume(true)?;
                continue;
            }
            let len = remaining.min(room);
            let split_after = start + len < member.packed_len;
            // The header carries the CRC of what follows it, so it goes out as
            // a placeholder and is patched once the payload has been copied.
            let volume = self.open.as_mut().expect("volume started");
            volume.out.write_all(&vec![0; header_len as usize])?;
            let fragment_crc = member.payload.copy(len, &mut *volume.out)?;
            let file_crc = match (split_after, member.final_crc) {
                (true, _) => fragment_crc,
                (false, Some(crc)) => crc,
                (false, None) => member.payload.unpacked_crc(),
            };
            let header =
                member.header(start > 0, split_after, len, file_crc, self.header_password)?;
            if header.len() as u64 != header_len {
                return Err(Error::WriterFailure(
                    "legacy file header changed length when patched",
                ));
            }
            let volume = self.open.as_mut().expect("volume started");
            let back = i64::try_from(header_len + len)
                .map_err(|_| Error::InvalidArgument("legacy volume fragment is too long"))?;
            volume.out.seek(SeekFrom::Current(-back))?;
            volume.out.write_all(&header)?;
            volume
                .out
                .seek(SeekFrom::Current(back - header_len as i64))?;
            volume.used += header_len + len;
            volume.fragments += 1;
            start += len;
            if !split_after {
                return Ok(());
            }
            self.close_volume(true)?;
        }
    }

    fn finish(mut self) -> Result<()> {
        if self.open.is_some() {
            self.close_volume(false)?;
        }
        Ok(())
    }

    fn head(&self, index: u64) -> Result<Vec<u8>> {
        let mut main_flags = MHD_VOLUME;
        if self.header_password.is_some() {
            main_flags |= MHD_PASSWORD;
        }
        if index == 0 {
            main_flags |= MHD_FIRSTVOLUME;
        }
        let mut head = Vec::new();
        head.extend_from_slice(RAR15_SIGNATURE);
        write_main_header(&mut head, main_flags);
        write_producer(
            &mut head,
            self.target,
            self.header_password,
            Some(self.progress),
        )?;
        Ok(head)
    }

    fn start_volume(&mut self) -> Result<()> {
        let head = self.head(self.index)?;
        let mut out = self.sink.start_volume(self.index)?;
        out.write_all(&head)?;
        self.open = Some(OpenVolume {
            out,
            used: head.len() as u64,
            fragments: 0,
        });
        Ok(())
    }

    fn close_volume(&mut self, more: bool) -> Result<()> {
        let mut volume = self.open.take().expect("volume open");
        let tail = self.tail(more)?;
        let len = volume.used + tail.len() as u64;
        if len > self.volume_size {
            return Err(Error::WriterFailure(
                "legacy volume came out longer than the volume size",
            ));
        }
        volume.out.write_all(&tail)?;
        volume.out.flush()?;
        drop(volume.out);
        self.sink.finish_volume(self.index, len)?;
        self.progress.report(WriteProgressEvent::VolumeFinished {
            volume_number: self.index as usize + 1,
            total_volumes: if more {
                self.total_volumes
            } else {
                Some(self.index as usize + 1)
            },
            bytes: len,
        });
        self.index += 1;
        crate::write_progress::check_cancelled(Some(self.progress))
    }

    fn tail(&self, more: bool) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self.header_password {
            Some(password) => {
                write_encrypted_end_block(&mut out, volume_end_flags(more), password)?
            }
            None if writes_end_block(self.target) => {
                out.extend_from_slice(&end_block(volume_end_flags(more)))
            }
            None => {}
        }
        Ok(out)
    }
}

/// Fixed once so both reads of the source produce the same ciphertext.
struct CipherPlan<'a> {
    target: ArchiveVersion,
    password: Option<&'a [u8]>,
    salt: Option<[u8; 8]>,
}

impl<'a> CipherPlan<'a> {
    fn new(target: ArchiveVersion, password: Option<&'a [u8]>) -> Result<Self> {
        if password.is_none() {
            return Ok(Self {
                target,
                password,
                salt: None,
            });
        }
        #[cfg(not(feature = "encryption"))]
        {
            Err(Error::FeatureDisabled {
                feature: "encryption",
            })
        }
        #[cfg(feature = "encryption")]
        {
            let salt = match target {
                ArchiveVersion::Rar15 | ArchiveVersion::Rar20 => None,
                ArchiveVersion::Rar29 | ArchiveVersion::Rar30 | ArchiveVersion::Rar40 => {
                    Some(random_rar30_salt()?)
                }
                _ => return Err(Error::UnsupportedVersion(target)),
            };
            Ok(Self {
                target,
                password,
                salt,
            })
        }
    }

    /// RAR 2.0 onwards encrypts in 16-byte blocks and pads the last one.
    fn pads(&self) -> bool {
        self.password.is_some() && self.target != ArchiveVersion::Rar15
    }

    fn packed_len(&self, unpacked: u64) -> Result<u64> {
        if self.pads() {
            unpacked
                .checked_add(15)
                .map(|len| len & !15)
                .ok_or(Error::InvalidArgument("RAR 1.5 block size overflows"))
        } else {
            Ok(unpacked)
        }
    }

    fn start(&self) -> Result<Option<Cipher>> {
        let Some(password) = self.password else {
            return Ok(None);
        };
        #[cfg(not(feature = "encryption"))]
        {
            let _ = password;
            Err(Error::FeatureDisabled {
                feature: "encryption",
            })
        }
        #[cfg(feature = "encryption")]
        {
            Ok(Some(match self.target {
                ArchiveVersion::Rar15 => Cipher::Rar15(Rar15Cipher::new(password)),
                ArchiveVersion::Rar20 => Cipher::Rar20(Box::new(Rar20Cipher::new(password))),
                _ => Cipher::Rar30(Box::new(
                    Rar30Cipher::new(password, self.salt).map_err(super::map_rar30_crypto_error)?,
                )),
            }))
        }
    }
}

enum Cipher {
    #[cfg(feature = "encryption")]
    Rar15(Rar15Cipher),
    #[cfg(feature = "encryption")]
    Rar20(Box<Rar20Cipher>),
    #[cfg(feature = "encryption")]
    Rar30(Box<Rar30Cipher>),
}

impl Cipher {
    fn encrypt(&mut self, data: &mut [u8]) {
        match self {
            #[cfg(feature = "encryption")]
            Self::Rar15(cipher) => cipher.crypt_in_place(data),
            #[cfg(feature = "encryption")]
            Self::Rar20(cipher) => cipher
                .encrypt_in_place(data)
                .expect("stream chunks are block aligned"),
            #[cfg(feature = "encryption")]
            Self::Rar30(cipher) => cipher
                .encrypt_in_place(data)
                .expect("stream chunks are block aligned"),
            #[cfg(not(feature = "encryption"))]
            _ => {
                let _ = data;
                unreachable!("no cipher without the encryption feature")
            }
        }
    }
}

/// The member as stored: read in pieces, encrypted and padded if asked.
struct PackedStream<'a> {
    reader: Box<dyn Read + 'a>,
    expected: u64,
    left: u64,
    cipher: Option<Cipher>,
    pads: bool,
    buffer: Vec<u8>,
    position: usize,
    unpacked_crc: Crc32,
    progress: ProgressReporter<'a>,
    work: Option<&'a WorkTracker<'a>>,
}

impl<'a> PackedStream<'a> {
    fn open(
        bytes: &MemberBytes<'a>,
        expected: u64,
        cipher: &CipherPlan<'_>,
        progress: ProgressReporter<'a>,
        work: Option<&'a WorkTracker<'a>>,
    ) -> Result<Self> {
        Ok(Self {
            reader: bytes.open()?,
            expected,
            left: expected,
            cipher: cipher.start()?,
            pads: cipher.pads(),
            buffer: Vec::with_capacity(STREAM_CHUNK + 16),
            position: 0,
            unpacked_crc: Crc32::new(),
            progress,
            work,
        })
    }

    fn unpacked_crc(&self) -> u32 {
        self.unpacked_crc.finish()
    }

    /// Copies the next `len` packed bytes to `out`, returning their CRC.
    fn copy(&mut self, mut len: u64, out: &mut dyn Write) -> Result<u32> {
        let mut crc = Crc32::new();
        while len > 0 {
            if self.position == self.buffer.len() {
                self.fill()?;
            }
            let take = len.min((self.buffer.len() - self.position) as u64) as usize;
            let bytes = &self.buffer[self.position..self.position + take];
            crc.update(bytes);
            out.write_all(bytes)?;
            self.position += take;
            len -= take as u64;
        }
        Ok(crc.finish())
    }

    fn fill(&mut self) -> Result<()> {
        const CHANGED: &str = "entry source size changed while writing";
        crate::write_progress::check_cancelled(Some(self.progress))?;
        if self.left == 0 {
            return Err(Error::WriterFailure(
                "legacy volume payload ran past the member",
            ));
        }
        let want = self.left.min(STREAM_CHUNK as u64) as usize;
        self.buffer.clear();
        self.buffer.resize(want, 0);
        self.reader
            .read_exact(&mut self.buffer)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::UnexpectedEof => Error::SourceChanged(CHANGED),
                _ => error.into(),
            })?;
        self.left -= want as u64;
        self.unpacked_crc.update(&self.buffer);
        if let Some(work) = self.work {
            work.advance(want as u64);
        }
        if self.left == 0 {
            crate::write_stream::check_source_length(
                &mut self.reader,
                self.expected,
                self.expected,
                CHANGED,
            )?;
            if self.pads {
                self.buffer.resize(want.next_multiple_of(16), 0);
            }
        }
        if let Some(cipher) = &mut self.cipher {
            cipher.encrypt(&mut self.buffer);
        }
        self.position = 0;
        Ok(())
    }
}
