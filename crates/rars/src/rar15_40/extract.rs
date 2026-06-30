use super::*;
use crate::volume_extract::{ChainedReader, SplitVolumeState, SplitVolumeStep};
use std::io::{Read, Write};

enum CodecState {
    Unpack15(Box<Unpack15>),
    Unpack20(Box<Unpack20>),
    Unpack29(Box<Unpack29>),
}

impl CodecState {
    fn new_for(file: &FileHeader) -> Result<Self> {
        if file.unp_ver >= 29 {
            return Ok(Self::Unpack29(Box::default()));
        }
        if file.unp_ver == 20 || file.unp_ver == 26 {
            return Ok(Self::Unpack20(Box::default()));
        }
        if file.unp_ver == 15 {
            return Ok(Self::Unpack15(Box::default()));
        }
        Err(Error::UnsupportedCompression {
            family: "RAR 1.5-4.x",
            unpack_version: file.unp_ver,
            method: file.method,
        })
    }

    fn supports(&self, file: &FileHeader) -> bool {
        match self {
            Self::Unpack15(_) => file.unp_ver == 15,
            Self::Unpack20(_) => file.unp_ver == 20 || file.unp_ver == 26,
            Self::Unpack29(_) => file.unp_ver >= 29,
        }
    }

    fn decode_file_data(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Unpack15(decoder) => {
                if file.is_encrypted() {
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let mut out = Vec::new();
                    decoder
                        .decode_member_from_reader(
                            &mut packed,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                            })?,
                            solid,
                            &mut out,
                        )
                        .map(|_| out)
                        .map_err(Into::into)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))
                } else {
                    file.unpacked_data_with_unpack15(archive, decoder, solid)
                }
            }
            Self::Unpack20(decoder) => file.unpacked_data_with_unpack20(archive, decoder, password),
            Self::Unpack29(decoder) => {
                if file.is_encrypted() {
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let mut out = Vec::new();
                    decoder
                        .decode_member_from_reader(
                            &mut packed,
                            usize::try_from(file.unp_size).map_err(|_| {
                                Error::InvalidHeader("RAR 2.9 unpacked size overflows usize")
                            })?,
                            &mut out,
                        )
                        .map(|_| out)
                        .map_err(Into::into)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))
                } else {
                    file.unpacked_data_with_rar29(archive, decoder, solid)
                }
            }
        }
    }

    fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        match self {
            Self::Unpack15(decoder) => {
                file.write_unpack15_to(archive, decoder, solid, password, out)
            }
            Self::Unpack20(decoder) => file.write_unpack20_to(archive, decoder, password, out),
            Self::Unpack29(decoder) => {
                if file.is_encrypted() {
                    let mut crc = Crc32::new();
                    let mut crc_writer = CrcWriter {
                        inner: out,
                        crc: &mut crc,
                    };
                    let mut packed = file
                        .packed_reader_for_decode(archive, password)
                        .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let target = usize::try_from(file.unp_size).map_err(|_| {
                        Error::InvalidHeader("RAR 1.5 unpacked size overflows usize")
                    })?;
                    if solid {
                        decoder.decode_member_from_reader(&mut packed, target, &mut crc_writer)
                    } else {
                        decoder.decode_non_solid_member_from_reader(
                            &mut packed,
                            target,
                            &mut crc_writer,
                        )
                    }
                    .map_err(Error::from)
                    .map_err(|error| file.map_encrypted_payload_error(password, error))?;
                    let actual = crc.finish();
                    file.crc_result(actual, password)
                } else {
                    file.write_rar29_to(archive, decoder, out)
                }
            }
        }
    }

    fn write_split_to(
        &mut self,
        input: &mut impl Read,
        file: &FileHeader,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let target = usize::try_from(file.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize"))?;
        match self {
            Self::Unpack15(decoder) => decoder
                .decode_member_from_reader(input, target, solid, &mut crc_writer)
                .map_err(Error::from)
                .map_err(|error| file.map_encrypted_payload_error(password, error))?,
            Self::Unpack20(decoder) => decoder
                .decode_member_from_reader(input, target, &mut crc_writer)
                .map_err(Error::from)
                .map_err(|error| file.map_encrypted_payload_error(password, error))?,
            Self::Unpack29(decoder) => if solid {
                decoder.decode_member_from_reader(input, target, &mut crc_writer)
            } else {
                decoder.decode_non_solid_member_from_reader(input, target, &mut crc_writer)
            }
            .map_err(Error::from)
            .map_err(|error| file.map_encrypted_payload_error(password, error))?,
        }
        let actual = crc.finish();
        file.crc_result(actual, password)
    }
}

pub(super) struct DecoderSession<'a> {
    codec: Option<CodecState>,
    solid: bool,
    decoded_files: usize,
    password: Option<&'a [u8]>,
}

impl<'a> DecoderSession<'a> {
    pub(super) fn new(solid: bool) -> Self {
        Self::new_with_password(solid, None)
    }

    pub(super) fn new_with_password(solid: bool, password: Option<&'a [u8]>) -> Self {
        Self {
            codec: None,
            solid,
            decoded_files: 0,
            password,
        }
    }

    pub(super) fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        out: &mut impl Write,
    ) -> Result<()> {
        if file.is_empty_compressed_payload() {
            file.crc_result(0, self.password)?;
            return Ok(());
        }
        let solid = self.file_is_solid(file);
        let password = self.password;
        self.codec_for(file)?
            .write_file_to(archive, file, solid, password, out)?;
        self.decoded_files += 1;
        Ok(())
    }

    fn write_split_to(
        &mut self,
        input: &mut impl Read,
        final_file: &FileHeader,
        out: &mut impl Write,
    ) -> Result<()> {
        let solid = self.file_is_solid(final_file);
        let password = self.password;
        self.codec_for(final_file)?
            .write_split_to(input, final_file, solid, password, out)?;
        self.decoded_files += 1;
        Ok(())
    }

    pub(super) fn decode_file_data(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
    ) -> Result<Vec<u8>> {
        if file.is_empty_compressed_payload() {
            file.crc_result(0, self.password)?;
            return Ok(Vec::new());
        }
        let solid = self.file_is_solid(file);
        let password = self.password;
        self.codec_for(file)?
            .decode_file_data(archive, file, solid, password)
    }

    fn file_is_solid(&self, file: &FileHeader) -> bool {
        if !self.solid || self.decoded_files == 0 {
            return false;
        }
        // FHD_SOLID is not meaningful for unpack version < 20; rely on the
        // archive-level MHD_SOLID flag in that case.
        file.unp_ver < 20 || file.is_solid()
    }

    fn codec_for(&mut self, file: &FileHeader) -> Result<&mut CodecState> {
        let reset = !self.file_is_solid(file)
            || self
                .codec
                .as_ref()
                .is_none_or(|codec| !codec.supports(file));
        if reset {
            self.codec = Some(CodecState::new_for(file)?);
        }
        self.codec
            .as_mut()
            .ok_or(Error::InvalidHeader("RAR 1.5 codec state is missing"))
    }
}

impl FileHeader {
    fn is_empty_compressed_payload(&self) -> bool {
        !self.is_stored() && self.pack_size == 0 && self.unp_size == 0
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 1.5 volume set is empty"));
    }

    let password = options.password;
    let mut split = SplitVolumeState::new();
    let mut session = DecoderSession::new_with_password(
        volumes
            .first()
            .is_some_and(|archive| archive.main.is_solid()),
        password,
    );
    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    let meta = file.metadata();
                    if meta.is_directory {
                        let _ = open(&meta)?;
                    } else {
                        let mut writer = open(&meta)?;
                        if file.is_stored() {
                            file.write_stored_to(archive, password, &mut writer)
                                .map_err(|error| file.entry_error("extracting", error))?;
                        } else {
                            session
                                .write_file_to(archive, file, &mut writer)
                                .map_err(|error| file.entry_error("extracting", error))?;
                        }
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(file, volume_index, file_index);
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(file, volume_index, file_index);
                    completed.write_to(volumes, file, password, &mut session, &mut open)?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"));
    }

    Ok(())
}

fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split directory entry is invalid",
        ));
    }
    if file.is_encrypted() && password.is_none() {
        return Err(Error::NeedPassword);
    }
    Ok(())
}

fn validate_split_continuation_refs(
    pending: &PendingSplitRefs,
    file: &FileHeader,
    password: Option<&[u8]>,
) -> Result<()> {
    validate_split_fragment(file, password)?;
    if file.name != pending.name {
        return Err(Error::InvalidHeader("RAR 1.5 split entry name changed"));
    }
    if file.method != pending.method {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry compression method changed",
        ));
    }
    if file.unp_ver != pending.unp_ver {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry unpack version changed",
        ));
    }
    if file.is_encrypted() != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split entry encryption flag changed",
        ));
    }
    if pending.encrypted && pending.unp_ver >= 29 && file.salt != pending.salt {
        return Err(Error::InvalidHeader("RAR 3.x split entry salt changed"));
    }
    Ok(())
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    attr: u32,
    host_os: u8,
    method: u8,
    unp_ver: u8,
    encrypted: bool,
    salt: Option<[u8; 8]>,
}

impl PendingSplitRefs {
    fn new(file: &FileHeader, volume_index: usize, file_index: usize) -> Self {
        Self {
            name: file.name.clone(),
            fragments: vec![(volume_index, file_index)],
            file_time: file.file_time,
            attr: file.attr,
            host_os: file.host_os,
            method: file.method,
            unp_ver: file.unp_ver,
            encrypted: file.is_encrypted(),
            salt: file.salt,
        }
    }

    fn append(&mut self, _file: &FileHeader, volume_index: usize, file_index: usize) {
        self.fragments.push((volume_index, file_index));
    }

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_file: &FileHeader,
        password: Option<&[u8]>,
        session: &mut DecoderSession,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let meta = ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        let mut reader = self.fragment_reader(volumes, password)?;

        if final_file.is_stored() {
            let expected_len = usize::try_from(final_file.unp_size)
                .map_err(|_| Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize"))?;
            let actual_len = self.packed_size(volumes)?;
            let expected_packed_len =
                if self.encrypted && self.unp_ver >= 20 {
                    expected_len.checked_add(15).map(|len| len & !15).ok_or(
                        Error::InvalidHeader("RAR 2.x encrypted split stored size overflows"),
                    )?
                } else {
                    expected_len
                };
            if actual_len != expected_packed_len {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split stored file has wrong reassembled size",
                ));
            }

            let mut crc = Crc32::new();
            let mut crc_writer = CrcWriter {
                inner: &mut writer,
                crc: &mut crc,
            };
            let copied = std::io::copy(&mut reader.take(expected_len as u64), &mut crc_writer)?;
            if copied != expected_len as u64 {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split stored file ended before unpacked size",
                ));
            }
            let actual = crc.finish();
            final_file
                .crc_result(actual, password)
                .map_err(|error| final_file.entry_error("extracting", error))
        } else {
            session
                .write_split_to(&mut reader, final_file, &mut writer)
                .map_err(|error| final_file.entry_error("extracting", error))
        }
    }

    fn packed_size(&self, volumes: &[Archive]) -> Result<usize> {
        self.fragments
            .iter()
            .try_fold(0usize, |total, &(volume_index, file_index)| {
                let archive = volumes
                    .get(volume_index)
                    .ok_or(Error::InvalidHeader("RAR 1.5 split volume is missing"))?;
                let file = archive
                    .files()
                    .nth(file_index)
                    .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
                total
                    .checked_add(usize::try_from(file.pack_size).map_err(|_| {
                        Error::InvalidHeader("RAR 1.5 split packed size overflows usize")
                    })?)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.5 split packed size overflows usize",
                    ))
            })
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        password: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'a>> {
        let mut readers = Vec::with_capacity(self.fragments.len());
        for &(volume_index, file_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 1.5 split volume is missing"))?;
            let file = archive
                .files()
                .nth(file_index)
                .ok_or(Error::InvalidHeader("RAR 1.5 split entry is missing"))?;
            readers.push(archive.range_reader(file.packed_range.clone())?);
        }
        let reader = ChainedReader::new(readers);
        if !self.encrypted {
            return Ok(Box::new(reader));
        }

        let Some(password) = password else {
            return Err(Error::NeedPassword);
        };
        Ok(Box::new(DecryptingReader::new(
            reader,
            self.unp_ver,
            password,
            self.salt,
        )?))
    }
}

enum SplitCipher {
    Rar15(Rar15Cipher),
    Rar20(Box<Rar20Cipher>),
    Rar30(Box<Rar30Cipher>),
}

impl SplitCipher {
    fn new(unp_ver: u8, password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        if unp_ver == 15 {
            return Ok(Self::Rar15(Rar15Cipher::new(password)));
        }
        if unp_ver == 20 || unp_ver == 26 {
            return Ok(Self::Rar20(Box::new(Rar20Cipher::new(password))));
        }
        if unp_ver >= 29 {
            return Ok(Self::Rar30(Box::new(
                Rar30Cipher::new(password, salt).map_err(super::map_rar30_crypto_error)?,
            )));
        }
        Err(Error::UnsupportedEncryption {
            family: "RAR 1.5-4.x split volume",
            unpack_version: unp_ver,
        })
    }
}

pub(super) struct DecryptingReader<R> {
    inner: R,
    cipher: SplitCipher,
    encrypted_block: Vec<u8>,
    decrypted: Vec<u8>,
    read_buffer: Option<Vec<u8>>,
    decrypted_pos: usize,
    eof: bool,
}

impl<R: Read> DecryptingReader<R> {
    pub(super) fn new(
        inner: R,
        unp_ver: u8,
        password: &[u8],
        salt: Option<[u8; 8]>,
    ) -> Result<Self> {
        let cipher = SplitCipher::new(unp_ver, password, salt)?;
        let read_buffer = matches!(cipher, SplitCipher::Rar15(_)).then(|| vec![0; 64 * 1024]);
        Ok(Self {
            inner,
            cipher,
            encrypted_block: Vec::new(),
            decrypted: Vec::new(),
            read_buffer,
            decrypted_pos: 0,
            eof: false,
        })
    }

    fn fill_decrypted(&mut self) -> std::io::Result<()> {
        if self.decrypted_pos < self.decrypted.len() || self.eof {
            return Ok(());
        }
        self.decrypted.clear();
        self.decrypted_pos = 0;

        match &mut self.cipher {
            SplitCipher::Rar15(cipher) => {
                let read_buffer = self
                    .read_buffer
                    .as_mut()
                    .expect("RAR 1.5 decrypting reader has a reusable buffer");
                let count = self.inner.read(read_buffer)?;
                if count == 0 {
                    self.eof = true;
                    return Ok(());
                }
                self.decrypted.extend_from_slice(&read_buffer[..count]);
                cipher.crypt_in_place(&mut self.decrypted);
            }
            SplitCipher::Rar20(_) | SplitCipher::Rar30(_) => self.fill_block_decrypted()?,
        }
        Ok(())
    }

    fn fill_block_decrypted(&mut self) -> std::io::Result<()> {
        while self.encrypted_block.len() < 16 && !self.eof {
            let mut buf = [0u8; 64 * 1024];
            let count = self.inner.read(&mut buf)?;
            if count == 0 {
                self.eof = true;
                break;
            }
            self.encrypted_block.extend_from_slice(&buf[..count]);
        }

        let full_len = (self.encrypted_block.len() / 16) * 16;
        if full_len != 0 {
            let tail = self.encrypted_block.split_off(full_len);
            let mut data = std::mem::replace(&mut self.encrypted_block, tail);
            match &mut self.cipher {
                SplitCipher::Rar15(_) => unreachable!("RAR 1.5 is byte-stream decrypted"),
                SplitCipher::Rar20(cipher) => cipher
                    .decrypt_in_place(&mut data)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
                SplitCipher::Rar30(cipher) => cipher
                    .decrypt_in_place(&mut data)
                    .map_err(super::map_rar30_crypto_error)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?,
            }
            self.decrypted = data;
            self.decrypted_pos = 0;
        } else if self.eof && !self.encrypted_block.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR encrypted payload is not block aligned",
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        self.fill_decrypted()?;
        if self.decrypted_pos == self.decrypted.len() {
            return Ok(0);
        }
        let count = out.len().min(self.decrypted.len() - self.decrypted_pos);
        out[..count]
            .copy_from_slice(&self.decrypted[self.decrypted_pos..self.decrypted_pos + count]);
        self.decrypted_pos += count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ArchiveSource, Block, BlockHeader, MainHeader, FHD_DIRECTORY_MASK, FHD_PASSWORD,
        FHD_SPLIT_AFTER, FHD_SPLIT_BEFORE,
    };
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    fn block(flags: u16) -> BlockHeader {
        BlockHeader {
            head_crc: 0,
            head_type: 0x74,
            flags,
            head_size: 0,
            add_size: Some(0),
            offset: 0,
        }
    }

    fn file(name: &[u8], flags: u16) -> FileHeader {
        FileHeader {
            block: block(flags),
            pack_size: 0,
            unp_size: 0,
            host_os: 2,
            file_crc: 0,
            file_time: 0,
            unp_ver: 29,
            method: 0x30,
            name: name.to_vec(),
            attr: 0x20,
            salt: None,
            file_comment: Vec::new(),
            ext_time: Vec::new(),
            packed_range: 0..0,
        }
    }

    struct ChunkedReader<R> {
        inner: R,
        chunk: usize,
    }

    impl<R: Read> ChunkedReader<R> {
        fn new(inner: R, chunk: usize) -> Self {
            Self { inner, chunk }
        }
    }

    impl<R: Read> Read for ChunkedReader<R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let take = out.len().min(self.chunk);
            self.inner.read(&mut out[..take])
        }
    }

    fn read_in_small_chunks(mut reader: impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }
        out
    }

    #[test]
    fn decrypting_reader_streams_rar15_payload() {
        let plain = b"RAR 1.5 encrypted payload read in pieces";
        let mut encrypted = plain.to_vec();
        Rar15Cipher::new(b"pw").crypt_in_place(&mut encrypted);
        let mut reader = DecryptingReader::new(Cursor::new(encrypted), 15, b"pw", None).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 3];

        loop {
            let count = reader.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buf[..count]);
        }

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_streams_rar20_blocks_from_short_inner_reads() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let reader = DecryptingReader::new(
            ChunkedReader::new(Cursor::new(encrypted), 5),
            20,
            b"pw",
            None,
        )
        .unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_streams_rar30_blocks_from_short_inner_reads() {
        let salt = Some([7u8; 8]);
        let plain = *b"0123456789abcdefRAR3 block two!!";
        let mut encrypted = plain;
        Rar30Cipher::new(b"pw", salt)
            .unwrap()
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let reader = DecryptingReader::new(
            ChunkedReader::new(Cursor::new(encrypted), 5),
            29,
            b"pw",
            salt,
        )
        .unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    #[test]
    fn validate_split_fragment_rejects_directories_and_demands_password_for_encrypted() {
        let dir = file(b"d", FHD_DIRECTORY_MASK | FHD_SPLIT_AFTER);
        assert!(matches!(
            validate_split_fragment(&dir, None),
            Err(Error::InvalidHeader(_))
        ));

        let encrypted = file(b"a", FHD_PASSWORD | FHD_SPLIT_AFTER);
        assert!(matches!(
            validate_split_fragment(&encrypted, None),
            Err(Error::NeedPassword)
        ));
        validate_split_fragment(&encrypted, Some(b"pw")).unwrap();

        let plain = file(b"a", FHD_SPLIT_AFTER);
        validate_split_fragment(&plain, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_property_drift_between_fragments() {
        let first = file(b"a.txt", FHD_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let renamed = file(b"b.txt", FHD_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &renamed, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_method = file(b"a.txt", FHD_SPLIT_BEFORE);
        new_method.method = 0x35;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_method, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_version = file(b"a.txt", FHD_SPLIT_BEFORE);
        new_version.unp_ver = 20;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_version, None),
            Err(Error::InvalidHeader(_))
        ));

        let new_encryption = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_encryption, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let same = file(b"a.txt", FHD_SPLIT_BEFORE);
        validate_split_continuation_refs(&pending, &same, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_salt_drift_for_rar3_encrypted_entries() {
        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.salt = Some([1u8; 8]);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let mut other_salt = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        other_salt.salt = Some([2u8; 8]);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &other_salt, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let mut same_salt = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        same_salt.salt = Some([1u8; 8]);
        validate_split_continuation_refs(&pending, &same_salt, Some(b"pw")).unwrap();
    }

    fn empty_archive() -> Archive {
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: 0,
                head_size: 0,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks: Vec::new(),
            source: ArchiveSource::Memory(Arc::from(Vec::new().into_boxed_slice())),
        }
    }

    fn archive_with(blocks: Vec<Block>) -> Archive {
        let mut archive = empty_archive();
        archive.blocks = blocks;
        archive
    }

    fn archive_with_source(blocks: Vec<Block>, source: Vec<u8>) -> Archive {
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: 0,
                head_size: 0,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks,
            source: ArchiveSource::Memory(Arc::from(source.into_boxed_slice())),
        }
    }

    #[test]
    fn encrypted_split_fragment_reader_decrypts_after_chaining_fragments() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let split = 7;

        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.packed_range = 0..split;

        let mut second = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (encrypted.len() - split) as u64;
        second.packed_range = 0..(encrypted.len() - split);

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0);
        let volumes = vec![
            archive_with_source(vec![Block::File(first)], encrypted[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], encrypted[split..].to_vec()),
        ];

        let reader = pending.fragment_reader(&volumes, Some(b"pw")).unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    fn never_open(_meta: &ExtractedEntryMeta) -> Result<Box<dyn Write>> {
        panic!("open should not be invoked for this test");
    }

    #[test]
    fn extract_volumes_to_rejects_split_state_violations() {
        let empty: Vec<Archive> = Vec::new();
        assert!(matches!(
            extract_volumes_to(&empty, crate::ArchiveReadOptions::default(), never_open),
            Err(Error::InvalidHeader(_))
        ));

        let only_continuation = vec![archive_with(vec![Block::File(file(
            b"a.txt",
            FHD_SPLIT_BEFORE,
        ))])];
        assert!(matches!(
            extract_volumes_to(
                &only_continuation,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let interrupted = vec![archive_with(vec![
            Block::File(file(b"a.txt", FHD_SPLIT_AFTER)),
            Block::File(file(b"unrelated", 0)),
        ])];
        assert!(matches!(
            extract_volumes_to(
                &interrupted,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));

        let incomplete = vec![archive_with(vec![Block::File(file(
            b"a.txt",
            FHD_SPLIT_AFTER,
        ))])];
        assert!(matches!(
            extract_volumes_to(
                &incomplete,
                crate::ArchiveReadOptions::default(),
                never_open,
            ),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn codec_state_new_for_chooses_codec_by_unpack_version() {
        let mut f = file(b"a", 0);
        f.unp_ver = 15;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack15(_)
        ));
        f.unp_ver = 20;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack20(_)
        ));
        f.unp_ver = 26;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack20(_)
        ));
        f.unp_ver = 29;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack29(_)
        ));
        f.unp_ver = 36;
        assert!(matches!(
            CodecState::new_for(&f).unwrap(),
            CodecState::Unpack29(_)
        ));
        f.unp_ver = 14;
        f.method = 0x35;
        assert!(matches!(
            CodecState::new_for(&f),
            Err(Error::UnsupportedCompression {
                unpack_version: 14,
                method: 0x35,
                ..
            })
        ));
    }

    #[test]
    fn codec_state_supports_matches_codec_to_file_version() {
        let mut f = file(b"a", 0);

        f.unp_ver = 15;
        let unpack15 = CodecState::new_for(&f).unwrap();
        assert!(unpack15.supports(&f));
        f.unp_ver = 20;
        assert!(!unpack15.supports(&f));
        f.unp_ver = 29;
        assert!(!unpack15.supports(&f));

        f.unp_ver = 20;
        let unpack20 = CodecState::new_for(&f).unwrap();
        assert!(unpack20.supports(&f));
        f.unp_ver = 26;
        assert!(unpack20.supports(&f));
        f.unp_ver = 15;
        assert!(!unpack20.supports(&f));
        f.unp_ver = 29;
        assert!(!unpack20.supports(&f));

        f.unp_ver = 29;
        let unpack29 = CodecState::new_for(&f).unwrap();
        assert!(unpack29.supports(&f));
        f.unp_ver = 36;
        assert!(unpack29.supports(&f));
        f.unp_ver = 20;
        assert!(!unpack29.supports(&f));
    }

    #[test]
    fn decoder_session_empty_compressed_payload_does_not_reset_solid_codec() {
        let mut session = DecoderSession::new(true);
        let mut first = file(b"first.txt", 0);
        first.unp_ver = 29;
        first.method = 0x35;
        session.codec = Some(CodecState::new_for(&first).unwrap());
        session.decoded_files = 4;

        let mut empty = file(b"empty.txt", super::super::FHD_SOLID);
        empty.unp_ver = 20;
        empty.method = 0x33;
        empty.file_crc = 0;
        let archive = Archive {
            sfx_offset: 0,
            main: MainHeader {
                head_crc: 0,
                flags: super::super::MHD_SOLID,
                head_size: 13,
                reserved1: 0,
                reserved2: 0,
                encrypt_version: None,
            },
            blocks: vec![Block::File(empty.clone())],
            source: ArchiveSource::Memory(Arc::from([])),
        };

        let mut out = Vec::new();
        session.write_file_to(&archive, &empty, &mut out).unwrap();

        assert!(out.is_empty());
        assert_eq!(session.decoded_files, 4);
        assert!(matches!(session.codec, Some(CodecState::Unpack29(_))));
    }

    #[test]
    fn split_cipher_new_rejects_unsupported_unpack_version() {
        for ver in [14u8, 16, 19, 25, 27, 28] {
            assert!(
                matches!(
                    SplitCipher::new(ver, b"pw", None),
                    Err(Error::UnsupportedEncryption { unpack_version, .. }) if unpack_version == ver
                ),
                "unp_ver {ver} should be rejected"
            );
        }
    }

    #[test]
    fn decrypting_reader_new_rejects_unsupported_unpack_version() {
        let result = DecryptingReader::new(Cursor::new(Vec::<u8>::new()), 25, b"pw", None);
        assert!(matches!(
            result,
            Err(Error::UnsupportedEncryption {
                unpack_version: 25,
                ..
            })
        ));
    }

    #[test]
    fn decrypting_reader_rejects_non_block_aligned_rar20_payload() {
        let mut payload = vec![0u8; 23];
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut payload[..16])
            .unwrap();
        let mut reader = DecryptingReader::new(Cursor::new(payload), 20, b"pw", None).unwrap();
        let mut buf = [0u8; 64];
        let err = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("expected non-block-aligned data error"),
                Ok(_) => continue,
                Err(err) => break err,
            }
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decrypting_reader_reports_rar30_body_crypto_errors_without_header_context() {
        let error = super::map_rar30_crypto_error(Rar30Error::UnalignedInput);
        assert!(matches!(
            error,
            Error::Rar30Crypto(Rar30Error::UnalignedInput)
        ));
        assert_eq!(error.to_string(), "RAR 3.x AES input is not block aligned");

        let mapped =
            file(b"encrypted.bin", FHD_PASSWORD).map_encrypted_payload_error(Some(b"pw"), error);
        assert_eq!(mapped, Error::WrongPasswordOrCorruptData);
    }

    #[test]
    fn pending_split_refs_packed_size_rejects_missing_volume_or_file() {
        let f = file(b"a.txt", FHD_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&f, 9, 0);
        let no_volumes: Vec<Archive> = Vec::new();
        assert!(matches!(
            pending.packed_size(&no_volumes),
            Err(Error::InvalidHeader(_))
        ));

        let mut pending = PendingSplitRefs::new(&f, 0, 7);
        pending.fragments[0] = (0, 7);
        let one_volume = vec![archive_with(vec![Block::File(f)])];
        assert!(matches!(
            pending.packed_size(&one_volume),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn pending_split_refs_fragment_reader_rejects_missing_volume_or_file() {
        let f = file(b"a.txt", FHD_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&f, 9, 0);
        let no_volumes: Vec<Archive> = Vec::new();
        assert!(matches!(
            pending.fragment_reader(&no_volumes, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut pending = PendingSplitRefs::new(&f, 0, 7);
        pending.fragments[0] = (0, 7);
        let one_volume = vec![archive_with(vec![Block::File(f)])];
        assert!(matches!(
            pending.fragment_reader(&one_volume, None),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn pending_split_refs_fragment_reader_demands_password_for_encrypted() {
        let mut first = file(b"a.txt", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.packed_range = 0..0;
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_source(vec![Block::File(first)], Vec::new())];
        assert!(matches!(
            pending.fragment_reader(&volumes, None),
            Err(Error::NeedPassword)
        ));
    }

    #[test]
    fn pending_split_refs_fragment_reader_chains_unencrypted_volumes() {
        let plain: &[u8] = b"hello, this string is split across two volumes!";
        let split = 11usize;

        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.pack_size = split as u64;
        first.packed_range = 0..split;
        let mut second = file(b"a.txt", FHD_SPLIT_BEFORE);
        second.pack_size = (plain.len() - split) as u64;
        second.packed_range = 0..(plain.len() - split);

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0);
        let volumes = vec![
            archive_with_source(vec![Block::File(first)], plain[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], plain[split..].to_vec()),
        ];

        let reader = pending.fragment_reader(&volumes, None).unwrap();
        let out = read_in_small_chunks(reader);
        assert_eq!(out, plain);
    }

    #[test]
    fn pending_split_refs_packed_size_sums_fragment_pack_sizes() {
        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.pack_size = 7;
        let mut second = file(b"a.txt", FHD_SPLIT_BEFORE);
        second.pack_size = 5;

        let mut pending = PendingSplitRefs::new(&first, 0, 0);
        pending.append(&second, 1, 0);
        let volumes = vec![
            archive_with(vec![Block::File(first)]),
            archive_with(vec![Block::File(second)]),
        ];
        assert_eq!(pending.packed_size(&volumes).unwrap(), 12);
    }

    #[derive(Default, Clone)]
    struct Capture {
        bytes: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        opened: std::rc::Rc<std::cell::RefCell<Vec<ExtractedEntryMeta>>>,
    }

    struct CaptureWriter(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        fn opener(&self) -> impl FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>> + '_ {
            let bytes = self.bytes.clone();
            let opened = self.opened.clone();
            move |meta| {
                opened.borrow_mut().push(meta.clone());
                Ok(Box::new(CaptureWriter(bytes.clone())))
            }
        }
    }

    #[test]
    fn extract_volumes_to_invokes_open_for_directory_entries() {
        let dir = file(b"d", FHD_DIRECTORY_MASK);
        let volumes = vec![archive_with(vec![Block::File(dir)])];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap();

        let opened = capture.opened.borrow();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].name, b"d");
        assert!(opened[0].is_directory);
        assert!(capture.bytes.borrow().is_empty());
    }

    #[test]
    fn extract_volumes_to_writes_stored_file_payload_and_verifies_crc() {
        let payload = b"hello stored payload!".to_vec();
        let mut entry = file(b"hello.txt", 0);
        entry.unp_ver = 20;
        entry.pack_size = payload.len() as u64;
        entry.unp_size = payload.len() as u64;
        entry.packed_range = 0..payload.len();
        entry.file_crc = super::super::crc32(&payload);

        let volumes = vec![archive_with_source(
            vec![Block::File(entry)],
            payload.clone(),
        )];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap();

        assert_eq!(capture.bytes.borrow().as_slice(), payload.as_slice());
        let opened = capture.opened.borrow();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].name, b"hello.txt");
        assert!(!opened[0].is_directory);
    }

    #[test]
    fn extract_volumes_to_reports_stored_crc_mismatch_with_entry_context() {
        let payload = b"crc mismatch payload".to_vec();
        let mut entry = file(b"bad.txt", 0);
        entry.unp_ver = 20;
        entry.pack_size = payload.len() as u64;
        entry.unp_size = payload.len() as u64;
        entry.packed_range = 0..payload.len();
        entry.file_crc = super::super::crc32(&payload).wrapping_add(1);

        let volumes = vec![archive_with_source(
            vec![Block::File(entry)],
            payload.clone(),
        )];

        let capture = Capture::default();
        let err = extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::AtEntry { .. }),
            "expected Error::AtEntry, got {err:?}"
        );
    }

    #[test]
    fn extract_volumes_to_writes_split_stored_file_across_volumes() {
        let payload = b"this stored payload spans two volumes".to_vec();
        let split = 13usize;

        let mut first = file(b"split.txt", FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.unp_size = payload.len() as u64;
        first.packed_range = 0..split;
        first.file_crc = super::super::crc32(&payload);

        let mut second = file(b"split.txt", FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (payload.len() - split) as u64;
        second.unp_size = payload.len() as u64;
        second.packed_range = 0..(payload.len() - split);
        second.file_crc = super::super::crc32(&payload);

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], payload[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], payload[split..].to_vec()),
        ];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap();

        assert_eq!(capture.bytes.borrow().as_slice(), payload.as_slice());
        let opened = capture.opened.borrow();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].name, b"split.txt");
    }

    #[test]
    fn extract_volumes_to_rejects_split_stored_size_mismatch() {
        let payload = b"split stored mismatch".to_vec();
        let split = 10usize;
        let truncated = payload.len() - 3;

        let mut first = file(b"a.txt", FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.unp_size = payload.len() as u64;
        first.packed_range = 0..split;

        let mut second = file(b"a.txt", FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (truncated - split) as u64;
        second.unp_size = payload.len() as u64;
        second.packed_range = 0..(truncated - split);

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], payload[..split].to_vec()),
            archive_with_source(
                vec![Block::File(second)],
                payload[split..truncated].to_vec(),
            ),
        ];

        let capture = Capture::default();
        let err = extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::default(),
            capture.opener(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(_)),
            "expected Error::InvalidHeader, got {err:?}"
        );
    }

    #[test]
    fn decoder_session_codec_for_resets_when_unpack_version_changes() {
        let mut session = DecoderSession::new(true);
        let mut f = file(b"a", 0);
        f.unp_ver = 20;
        assert!(matches!(
            session.codec_for(&f).unwrap(),
            CodecState::Unpack20(_)
        ));
        let mut g = file(b"b", 0);
        g.unp_ver = 29;
        assert!(matches!(
            session.codec_for(&g).unwrap(),
            CodecState::Unpack29(_)
        ));
        let mut h = file(b"c", 0);
        h.unp_ver = 15;
        assert!(matches!(
            session.codec_for(&h).unwrap(),
            CodecState::Unpack15(_)
        ));
    }

    #[test]
    fn decoder_session_codec_for_propagates_unsupported_compression() {
        let mut session = DecoderSession::new(false);
        let mut f = file(b"a", 0);
        f.unp_ver = 14;
        assert!(matches!(
            session.codec_for(&f),
            Err(Error::UnsupportedCompression {
                unpack_version: 14,
                ..
            })
        ));
    }

    #[test]
    fn decoder_session_codec_for_reuses_codec_in_solid_mode() {
        let mut session = DecoderSession::new(true);
        let mut f = file(b"a", 0);
        f.unp_ver = 29;
        let first = session.codec_for(&f).unwrap() as *const CodecState;
        let second = session.codec_for(&f).unwrap() as *const CodecState;
        assert_eq!(first, second);
    }

    #[test]
    fn decoder_session_decode_file_data_dispatches_to_stored_path_for_each_codec_version() {
        let payload = b"decode_file_data stored dispatch".to_vec();
        let crc = super::super::crc32(&payload);
        for unp_ver in [15u8, 20, 26, 29] {
            let mut entry = file(b"a.txt", 0);
            entry.unp_ver = unp_ver;
            entry.pack_size = payload.len() as u64;
            entry.unp_size = payload.len() as u64;
            entry.packed_range = 0..payload.len();
            entry.file_crc = crc;

            let archive = archive_with_source(vec![Block::File(entry.clone())], payload.clone());
            let mut session = DecoderSession::new(false);
            let data = session
                .decode_file_data(&archive, &entry)
                .unwrap_or_else(|err| panic!("decode for unp_ver {unp_ver}: {err:?}"));
            assert_eq!(data, payload, "unp_ver {unp_ver} payload mismatch");
        }
    }

    #[test]
    fn decrypting_reader_works_through_boxed_inner_reader() {
        let plain = *b"0123456789abcdefRAR2 block two!!";
        let mut encrypted = plain;
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let inner: Box<dyn Read> = Box::new(Cursor::new(encrypted.to_vec()));
        let reader = DecryptingReader::new(inner, 20, b"pw", None).unwrap();
        let out = read_in_small_chunks(reader);

        assert_eq!(out, plain);
    }

    #[test]
    fn decrypting_reader_boxed_inner_rejects_non_block_aligned_eof() {
        let mut payload = vec![0u8; 32];
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut payload[..16])
            .unwrap();
        // 23 bytes of trailing data (not a multiple of 16) — should error at EOF.
        payload.truncate(23);
        let inner: Box<dyn Read> = Box::new(Cursor::new(payload));
        let mut reader = DecryptingReader::new(inner, 20, b"pw", None).unwrap();
        let mut buf = [0u8; 64];
        let err = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("expected non-block-aligned data error"),
                Ok(_) => continue,
                Err(err) => break err,
            }
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn extract_volumes_to_assembles_encrypted_stored_split_across_two_volumes() {
        let payload: &[u8] = b"twenty-byte payload!"; // exactly 20 bytes
        let unpacked_len = payload.len();
        assert_eq!(unpacked_len, 20);
        let padded_len = (unpacked_len + 15) & !15; // 32
        let mut encrypted = vec![0u8; padded_len];
        encrypted[..unpacked_len].copy_from_slice(payload);
        Rar20Cipher::new(b"pw")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        let split = 13usize;
        let crc = super::super::crc32(payload);

        let mut first = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = split as u64;
        first.unp_size = unpacked_len as u64;
        first.packed_range = 0..split;
        first.file_crc = crc;

        let mut second = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = (padded_len - split) as u64;
        second.unp_size = unpacked_len as u64;
        second.packed_range = 0..(padded_len - split);
        second.file_crc = crc;

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], encrypted[..split].to_vec()),
            archive_with_source(vec![Block::File(second)], encrypted[split..].to_vec()),
        ];

        let capture = Capture::default();
        extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::with_password(b"pw"),
            capture.opener(),
        )
        .unwrap();

        assert_eq!(capture.bytes.borrow().as_slice(), payload);
    }

    #[test]
    fn extract_volumes_to_rejects_encrypted_stored_split_when_padded_size_disagrees() {
        let unpacked_len = 20usize;
        // Two volumes total only 30 bytes, but expected_packed_len == 32.
        let payload = [0u8; 30];

        let mut first = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_AFTER);
        first.unp_ver = 20;
        first.pack_size = 13;
        first.unp_size = unpacked_len as u64;
        first.packed_range = 0..13;

        let mut second = file(b"split.bin", FHD_PASSWORD | FHD_SPLIT_BEFORE);
        second.unp_ver = 20;
        second.pack_size = 17;
        second.unp_size = unpacked_len as u64;
        second.packed_range = 0..17;

        let volumes = vec![
            archive_with_source(vec![Block::File(first)], payload[..13].to_vec()),
            archive_with_source(vec![Block::File(second)], payload[13..].to_vec()),
        ];

        let capture = Capture::default();
        let err = extract_volumes_to(
            &volumes,
            crate::ArchiveReadOptions::with_password(b"pw"),
            capture.opener(),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("wrong reassembled size")),
            "expected wrong reassembled size error, got {err:?}"
        );
    }
}
