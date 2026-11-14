use super::*;
use crate::output_limit::OutputBudget;
use crate::rar50::{Block, FHFL_UNP_SIZE_UNKNOWN};
use crate::source::{ArchiveSource, RangeReader};
use crate::volume_extract::{FragmentWalk, LazyChain, VolumeEnd, VolumeFeed};
use std::ops::Range;

pub(super) fn extract<F, R, B: Budget>(
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    open: &mut F,
    redirect: &mut R,
    emit_redirections: bool,
    allowance: &B,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    options.check_cancelled()?;
    let Some(mut volume) = feed.next()? else {
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    };

    let mut budget = OutputBudget::new(options);
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let mut session =
        DecoderSession::with_allowance(options.password, buffered_decode_limit, allowance);
    session.decoder.read_control = budget.control.clone();
    session.scratch = options.rar50_scratch;

    let mut skip = 0;
    loop {
        let mut resume = None;
        let count = volume.files().count();
        for (index, file) in volume.files().enumerate().skip(skip) {
            options.check_cancelled()?;
            // Admission precedes split decryption and checksum-error preference:
            // a resource refusal must not read payloads or become a checksum error.
            file.check_dictionary_limit(options.rar50_dictionary_size_limit)?;
            if file.is_split_before() {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry is missing its first part",
                ));
            }
            if file.is_split_after() {
                if index + 1 != count {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is interrupted by a regular entry",
                    ));
                }
                resume = Some(extract_split(
                    &volume,
                    file,
                    feed,
                    options,
                    &mut session,
                    &mut budget,
                    open,
                )?);
                break;
            }
            if let Some(redirection) = &file.redirection {
                if emit_redirections {
                    options.check_cancelled()?;
                    redirect(&file.metadata(), redirection)?;
                    options.check_cancelled()?;
                }
                continue;
            }
            file.check_output_limit(&budget)?;
            let meta = file.metadata();
            options.check_cancelled()?;
            let mut writer = open(&meta)?;
            options.check_cancelled()?;
            if !meta.is_directory {
                budget.run(&file.name, &mut writer, |writer| {
                    session.write_file_to(&volume, file, writer)
                })?;
            }
        }
        if let Some(last) = resume {
            // A continuation is always the first file of its volume.
            volume = last;
            skip = 1;
            continue;
        }
        match feed.after(volume_end(&volume))? {
            Some(next) => {
                volume = next;
                skip = 0;
            }
            None => break,
        }
    }

    options.check_cancelled()?;
    Ok(())
}

fn volume_end(archive: &Archive) -> VolumeEnd {
    if !archive.main.is_volume() {
        return VolumeEnd::Last;
    }
    match archive.blocks.iter().find_map(|block| match block {
        Block::End(end) => Some(end.has_next_volume()),
        _ => None,
    }) {
        Some(true) => VolumeEnd::More,
        Some(false) => VolumeEnd::Last,
        None => VolumeEnd::Unknown,
    }
}

/// Decodes a split member while its later volumes arrive; returns the volume holding its end.
fn extract_split<F, B: Budget>(
    volume: &Archive,
    first: &FileHeader,
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    session: &mut DecoderSession<'_, B>,
    budget: &mut OutputBudget,
    open: &mut F,
) -> Result<Archive>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    validate_split_fragment(first, options.password)?;
    let mut walk = SplitWalk::new(feed, volume, first, &session.allowance)?;
    // Parts written before the size was known record it only in the last header.
    let sized;
    let first = if first.known_unpacked_size().is_none() {
        let last = walk.prefetch()?;
        let mut header = first.clone();
        header.unpacked_size = last.unpacked_size;
        header.file_flags =
            (first.file_flags & !FHFL_UNP_SIZE_UNKNOWN) | (last.file_flags & FHFL_UNP_SIZE_UNKNOWN);
        sized = header;
        &sized
    } else {
        first
    };
    first.check_output_limit(budget)?;
    budget.control.check()?;
    let decryptor = split_decryptor(first, session)?;
    budget.control.check()?;
    let first_reader = volume
        .source
        .owned_range_reader(first.block.data_range.clone())?;
    let meta = ExtractedEntryMeta {
        name: first.name.clone(),
        file_time: first.modification_time(),
        mtime_refinement: first.modification_time_refinement(),
        attr: first.attributes,
        host_os: first.host_os,
        is_directory: false,
    };
    let mut writer = open(&meta)?;
    budget
        .run(&first.name, &mut writer, |mut writer| {
            if first.is_stored() {
                let allowance = session.allowance.clone();
                return write_stored(
                    first,
                    &mut walk,
                    first_reader,
                    decryptor.as_ref(),
                    &mut writer,
                    &allowance,
                )
                .map_err(|error| {
                    if error.kind() == crate::ErrorKind::Io {
                        error
                    } else {
                        walk.checksum_error().unwrap_or(error)
                    }
                })
                .map_err(|error| first.entry_error("extracting", error));
            }
            session.write_lazy_split_to(first, &mut walk, first_reader, decryptor.as_ref(), writer)
        })
        .map_err(|error| walk.failure.take().unwrap_or(error))?;
    walk.into_last_volume()
}

fn split_decryptor<B: Budget>(
    first: &FileHeader,
    session: &DecoderSession<'_, B>,
) -> Result<Option<SplitDecryptor>> {
    if !first.encrypted {
        return Ok(None);
    }
    let keys = first.encryption_keys_cached(
        session.password,
        session.shared_key_cache.unwrap_or(&session.key_cache),
    )?;
    Ok(Some(SplitDecryptor {
        keys,
        iv: first.encryption_iv()?,
    }))
}

pub(super) fn packed_reader<R: Read, B: Budget>(
    chain: R,
    decryptor: Option<&SplitDecryptor>,
    allowance: &B,
) -> Result<PackedReader<R, B>> {
    let Some(decryptor) = decryptor else {
        return Ok(PackedReader::Plain(chain));
    };
    Ok(PackedReader::Encrypted(Boxed::try_new(
        || Rar50DecryptingReader::with_keys(chain, decryptor.keys.key, decryptor.iv),
        allowance,
    )?))
}

/// Running checksums over a split member's output, checked once its last header is known.
struct SplitChecksums {
    crc: Crc32,
    hash: Option<blake2sp::Hasher>,
}

impl SplitChecksums {
    fn new(first: &FileHeader) -> Self {
        // Every fragment carries the hash record, so the first says whether to hash.
        Self {
            crc: Crc32::new(),
            hash: first.hash.is_some().then(blake2sp::Hasher::new),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        self.crc.update(chunk);
        if let Some(hasher) = &mut self.hash {
            hasher.update(chunk);
        }
    }

    fn verify(self, last: &FileHeader, decryptor: Option<&SplitDecryptor>) -> Result<()> {
        let hash = match (streaming_hash_verifier(last)?, self.hash) {
            (Some((expected, _)), Some(hasher)) => Some((expected, hasher)),
            (Some(_), None) => {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry hash record changed",
                ))
            }
            (None, _) => None,
        };
        last.verify_streaming_integrity(self.crc, hash, decryptor.map(|decryptor| &decryptor.keys))
    }
}

pub(super) fn write_stored<B: Budget>(
    first: &FileHeader,
    walk: &mut SplitWalk<'_, '_, '_, B>,
    first_reader: RangeReader<'static>,
    decryptor: Option<&SplitDecryptor>,
    writer: &mut dyn Write,
    allowance: &B,
) -> Result<()> {
    let mut sums = SplitChecksums::new(first);
    let mut reader = packed_reader(LazyChain::new(walk, first_reader), decryptor, allowance)?;
    // Padding after the unpacked size may hold any bytes.
    let written = crate::stored_copy::copy(
        &mut reader,
        first.unpacked_size,
        first.encrypted,
        &mut |chunk: &[u8]| sums.update(chunk),
        writer,
        allowance,
    )?;
    drop(reader);
    let last = walk.finish()?;
    if written != last.unpacked_size {
        return Err(Error::InvalidHeader(
            "RAR 5 stored split file has mismatched packed and unpacked sizes",
        ));
    }
    sums.verify(last, decryptor)
}

impl<B: Budget> DecoderSession<'_, B> {
    pub(super) fn write_lazy_split_to(
        &mut self,
        first: &FileHeader,
        walk: &mut SplitWalk<'_, '_, '_, B>,
        first_reader: RangeReader<'static>,
        decryptor: Option<&SplitDecryptor>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        self.guard_solid_chain(first, |session| {
            if first.should_stream_decode(session.buffered_decode_limit) {
                return session
                    .stream_lazy_split_to(first, walk, first_reader, decryptor, writer)
                    .map_err(|error| first.entry_error("decoding", error));
            }
            let data = session
                .decode_lazy_split(first, walk, first_reader, decryptor)
                .map_err(|error| first.entry_error("decoding", error))?;
            let last = walk
                .finish()
                .map_err(|error| first.entry_error("decoding", error))?;
            last.verify_integrity_with_keys(&data, decryptor.map(|decryptor| &decryptor.keys))
                .map_err(|error| walk.checksum_error().unwrap_or(error))
                .map_err(|error| first.entry_error("verifying", error))?;
            writer
                .write_all(&data)
                .map_err(Error::from)
                .map_err(|error| first.entry_error("writing", error))
        })
    }

    pub(super) fn stream_lazy_split_to(
        &mut self,
        first: &FileHeader,
        walk: &mut SplitWalk<'_, '_, '_, B>,
        first_reader: RangeReader<'static>,
        decryptor: Option<&SplitDecryptor>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        self.decoder.read_control.check()?;
        let mut decoder = self
            .decoder
            .take_for_stream(first.compression_info & 0x40 != 0);
        let control = decoder.read_control.clone();
        // The last fragment's header holds the checksums; check them once it is read.
        let mut unchecked = first.clone();
        unchecked.data_crc32 = None;
        unchecked.hash = None;
        let mut sums = SplitChecksums::new(first);
        let decoded = {
            let mut packed = packed_reader(
                LazyChain::new(&mut *walk, first_reader),
                decryptor,
                &self.allowance,
            )?;
            control.finish(unchecked.stream_packed_with_crc_policy::<true, _, _>(
                &mut packed,
                None,
                &mut decoder,
                self.buffered_decode_limit,
                self.scratch,
                Some(&mut |chunk: &[u8]| sums.update(chunk)),
                writer,
            ))
        };
        decoded
            .and_then(|()| walk.finish().and_then(|last| sums.verify(last, decryptor)))
            .map_err(|error| match error {
                // Sink/reader I/O and the intentional filter limit must retain their
                // own meaning. Fragment diagnostics are for decode/integrity failure.
                error
                    if matches!(
                        error.kind(),
                        crate::ErrorKind::Io
                            | crate::ErrorKind::ResourceLimit
                            | crate::ErrorKind::Cancelled
                            | crate::ErrorKind::UnsupportedFeature
                    ) =>
                {
                    error
                }
                error => walk.checksum_error().unwrap_or(error),
            })?;
        self.decoder = decoder;
        Ok(())
    }

    pub(super) fn decode_lazy_split(
        &mut self,
        first: &FileHeader,
        walk: &mut SplitWalk<'_, '_, '_, B>,
        first_reader: RangeReader<'static>,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Buffer<u8, B>> {
        let info = first.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = checked_unpacked_size(first.unpacked_size)?;
        let allowance = self.decoder.allowance();
        let decoded = {
            let mut reader = packed_reader(
                LazyChain::new(&mut *walk, first_reader),
                decryptor,
                &allowance,
            )?;
            self.decoder
                .decode_member_from_reader_with_dictionary(
                    &mut reader,
                    info.algorithm_version,
                    output_size,
                    dictionary_size,
                    info.solid,
                    DecodeMode::Lz,
                )
                .map_err(Error::from)
        };
        // A damaged volume usually derails the decoder before the fragment it
        // sits in is read to its end, so the reader's own check never fires and
        // the member fails as "truncated" instead. Checking the fragments here
        // turns that into the checksum mismatch it is.
        match decoded {
            Err(error)
                if matches!(
                    error.kind(),
                    crate::ErrorKind::ResourceLimit
                        | crate::ErrorKind::Cancelled
                        | crate::ErrorKind::Io
                        | crate::ErrorKind::UnsupportedFeature
                ) =>
            {
                Err(error)
            }
            Err(error) => Err(walk.checksum_error().unwrap_or(error)),
            decoded => decoded,
        }
    }
}

pub(super) struct Fragment {
    volume: usize,
    source: ArchiveSource,
    range: Range<usize>,
    check: Option<FragmentCheck>,
}

impl Fragment {
    fn feed(&self, update: impl FnMut(&[u8])) -> bool {
        self.source
            .copy_range_to(self.range.clone(), &mut UpdateSink(update))
            .is_ok()
    }
}

/// WinRAR's `-htb` volumes drop the CRC32 and keep only a hash record.
enum FragmentCheck {
    Crc32(u32),
    Blake2sp([u8; 32]),
}

impl FragmentCheck {
    fn of(file: &FileHeader) -> Option<Self> {
        if let Some(crc) = file.data_crc32 {
            return Some(Self::Crc32(crc));
        }
        // Unconfirmed for encrypted sets, and a keyed hash needs the password.
        let hash = file.hash.as_ref().filter(|_| !file.encrypted)?;
        (hash.hash_type == 0)
            .then(|| hash.data.as_slice().try_into().ok())
            .flatten()
            .map(Self::Blake2sp)
    }
}

/// Fetches a split member's later volumes as its reader reaches each fragment's end.
pub(super) struct SplitWalk<'f, 'p, 'o, B: Budget> {
    feed: &'f mut VolumeFeed<'p, 'o, Archive>,
    options: crate::ArchiveReadOptions<'o>,
    first: FileHeader,
    split_after: bool,
    last: Option<Archive>,
    fragments: Buffer<Fragment, B>,
    prefetched: std::collections::VecDeque<RangeReader<'static>>,
    /// A refused or missing volume, reported as itself rather than as a decode failure.
    failure: Option<Error>,
}

impl<'f, 'p, 'o, B: Budget> SplitWalk<'f, 'p, 'o, B> {
    pub(super) fn new(
        feed: &'f mut VolumeFeed<'p, 'o, Archive>,
        volume: &Archive,
        first: &FileHeader,
        allowance: &B,
    ) -> Result<Self> {
        let options = feed.options();
        let mut fragments = Buffer::new(allowance);
        fragments.try_push(Fragment {
            volume: feed.current_index(),
            source: volume.source.clone(),
            range: first.block.data_range.clone(),
            check: FragmentCheck::of(first),
        })?;
        Ok(Self {
            feed,
            options,
            first: first.clone(),
            split_after: true,
            last: None,
            fragments,
            prefetched: Default::default(),
            failure: None,
        })
    }

    /// Reads past any fragments the decoder did not need and returns the member's last header.
    pub(super) fn finish(&mut self) -> Result<&FileHeader> {
        while self.next_fragment()?.is_some() {}
        self.last_header()
    }

    fn last_header(&self) -> Result<&FileHeader> {
        self.last
            .as_ref()
            .and_then(|volume| volume.files().next())
            .ok_or(Error::InvalidHeader("RAR 5 split entry is incomplete"))
    }

    /// Fetches every remaining volume of the member before any of its data is read.
    fn prefetch(&mut self) -> Result<&FileHeader> {
        while let Some(reader) = self
            .advance()
            .inspect_err(|error| self.failure = Some(error.clone()))?
        {
            self.prefetched.push_back(reader);
        }
        self.last_header()
    }

    fn into_last_volume(mut self) -> Result<Archive> {
        self.finish()?;
        Ok(self.last.expect("finish found the last fragment"))
    }

    pub(super) fn validate_continuation(&self, file: &FileHeader) -> Result<()> {
        if !file.is_split_before() {
            return Err(Error::InvalidHeader(
                "RAR 5 split entry is interrupted by a regular entry",
            ));
        }
        file.check_dictionary_limit(self.options.rar50_dictionary_size_limit)?;
        validate_split_fragment(file, self.options.password)?;
        if file.name != self.first.name {
            return Err(Error::InvalidHeader("RAR 5 split entry name changed"));
        }
        if file.compression_info != self.first.compression_info {
            return Err(Error::InvalidHeader(
                "RAR 5 split entry compression info changed",
            ));
        }
        if file.encrypted != self.first.encrypted {
            return Err(Error::InvalidHeader(
                "RAR 5 split entry encryption flag changed",
            ));
        }
        Ok(())
    }

    /// Re-reads every fragment that carries a checksum over its own stored
    /// bytes and reports the first that disagrees.
    ///
    /// Only consulted once a member has already failed. Checking as the
    /// fragments are read would reject an archive whose fragment checksums say
    /// something other than what rars and WinRAR put there, and unrar and RAR
    /// 7.12 both extract those. Reading the set a second time to explain a
    /// failure is worth it; refusing a member that would have come out intact
    /// is not. A volume the caller has since removed is skipped.
    pub(super) fn checksum_error(&self) -> Option<Error> {
        let last = self.fragments.len().saturating_sub(1);
        for (index, fragment) in self.fragments.iter().enumerate() {
            if index == last && !self.split_after {
                break;
            }
            let Some(check) = &fragment.check else {
                continue;
            };
            let source = match check {
                FragmentCheck::Crc32(expected) => {
                    let mut crc = Crc32::new();
                    if !fragment.feed(|buf| crc.update(buf)) {
                        continue;
                    }
                    let actual = crc.finish();
                    if actual == *expected {
                        continue;
                    }
                    Error::Crc32Mismatch {
                        expected: *expected,
                        actual,
                    }
                }
                FragmentCheck::Blake2sp(expected) => {
                    let mut hash = blake2sp::Hasher::new();
                    if !fragment.feed(|buf| hash.update(buf)) || hash.finalize() == *expected {
                        continue;
                    }
                    Error::HashMismatch { hash_type: 0 }
                }
            };
            return Some(Error::InVolume {
                number: fragment.volume + 1,
                source: Box::new(source),
            });
        }
        None
    }
}

impl<B: Budget> FragmentWalk for SplitWalk<'_, '_, '_, B> {
    fn next_fragment(&mut self) -> Result<Option<RangeReader<'static>>> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if let Some(reader) = self.prefetched.pop_front() {
            return Ok(Some(reader));
        }
        self.advance()
            .inspect_err(|error| self.failure = Some(error.clone()))
    }
}

impl<B: Budget> SplitWalk<'_, '_, '_, B> {
    fn advance(&mut self) -> Result<Option<RangeReader<'static>>> {
        if !self.split_after {
            return Ok(None);
        }
        loop {
            let Some(volume) = self.feed.next_part()? else {
                return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
            };
            let Some(file) = volume.files().next() else {
                continue;
            };
            self.validate_continuation(file)?;
            if file.is_split_after() && volume.files().count() != 1 {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry is interrupted by a regular entry",
                ));
            }
            let reader = volume
                .source
                .owned_range_reader(file.block.data_range.clone())?;
            self.fragments.try_push(Fragment {
                volume: self.feed.current_index(),
                source: volume.source.clone(),
                range: file.block.data_range.clone(),
                check: FragmentCheck::of(file),
            })?;
            self.split_after = file.is_split_after();
            self.last = Some(volume);
            return Ok(Some(reader));
        }
    }
}

#[cfg(all(test, feature = "write"))]
pub(super) fn with_walk<B: Budget, T>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    allowance: &B,
    run: impl FnOnce(&Archive, &FileHeader, &mut SplitWalk<'_, '_, '_, B>) -> Result<T>,
) -> Result<T> {
    let mut volumes = volumes.iter().cloned().map(Ok);
    let mut feed = VolumeFeed::complete(&mut volumes, options);
    let volume = feed.next()?.expect("a first volume");
    let first = volume.files().next().expect("a first fragment");
    let mut walk = SplitWalk::new(&mut feed, &volume, first, allowance)?;
    run(&volume, first, &mut walk)
}
