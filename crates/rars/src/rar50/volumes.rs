use super::*;
use crate::extraction_control::{finish_independent, finish_member, finish_split_member, Resume};
use crate::output_limit::OutputBudget;
use crate::rar50::{Block, FHFL_UNP_SIZE_UNKNOWN};
use crate::source::{ArchiveSource, RangeReader};
use crate::volume_extract::{
    flush_split, LazyChain, SplitFailure, SplitFormat, VolumeEnd, VolumeFeed,
};
use std::ops::Range;

pub(super) fn extract(
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    open: &mut dyn FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    redirect: &mut dyn FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
    redirections: Redirections,
    allowance: &Allowance,
) -> Result<()> {
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

    let mut skip = feed.first_file();
    loop {
        let mut resume = None;
        let files: Vec<&FileHeader> = volume.files().collect();
        let count = files.len();
        for (index, &file) in files.iter().enumerate().skip(skip) {
            options.check_cancelled()?;
            if !feed.take_member() {
                return Ok(());
            }
            if file.is_split_before() || file.is_split_after() {
                // Split members are terminal, so keep admission ahead of their
                // structural, decryption and checksum errors.
                file.check_dictionary_limit(options.rar50_dictionary_size_limit)?;
            }
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
                let last = match extract_split(
                    &volume,
                    file,
                    feed,
                    options,
                    &mut session,
                    &mut budget,
                    open,
                ) {
                    Ok(last) => last,
                    Err(SplitFailure { error, last: None }) => return Err(error),
                    // The member's last volume is in hand, so a member error
                    // handler can carry on past it, as for any other member.
                    Err(SplitFailure {
                        error,
                        last: Some(last),
                    }) => {
                        let solid = volume.main.is_solid() || file.compression_info & 0x40 != 0;
                        match finish_split_member(
                            options,
                            || crate::rar50_member(file),
                            solid,
                            error,
                        )? {
                            Resume::Fresh => {
                                session = DecoderSession::with_allowance(
                                    options.password,
                                    buffered_decode_limit,
                                    allowance,
                                );
                                session.decoder.read_control = budget.control.clone();
                                session.scratch = options.rar50_scratch;
                            }
                            Resume::Solid => session.passed_over(),
                        }
                        *last
                    }
                };
                resume = Some(last);
                break;
            }
            if let Some(redirection) = file
                .redirection
                .as_ref()
                .filter(|_| redirections.redirects(file))
            {
                if redirections == Redirections::Emit {
                    options.check_cancelled()?;
                    let result = redirect(&file.metadata(), redirection);
                    // A link decodes nothing, so the session carries on as it was.
                    finish_independent(options, || crate::rar50_member(file), result)?;
                    options.check_cancelled()?;
                }
                continue;
            }
            let meta = file.metadata();
            options.check_cancelled()?;
            if meta.is_directory {
                open(&meta)?;
                options.check_cancelled()?;
                continue;
            }
            if !feed.selection_finished() {
                session.read_ahead(&volume, &files, index);
            }
            let result = (|| {
                file.check_dictionary_limit(options.rar50_dictionary_size_limit)?;
                file.check_output_limit(&budget)?;
                let writer = open(&meta)?;
                options.check_cancelled()?;
                budget.run_verified(&file.name, writer, |writer| {
                    session.write_file_to(&volume, file, writer)
                })
            })();
            let solid = volume.main.is_solid() || file.compression_info & 0x40 != 0;
            match finish_member(
                &mut None,
                options,
                || crate::rar50_member(file),
                solid,
                result,
            )? {
                Some(Resume::Fresh) => {
                    session = DecoderSession::with_allowance(
                        options.password,
                        buffered_decode_limit,
                        allowance,
                    );
                    session.decoder.read_control = budget.control.clone();
                    session.scratch = options.rar50_scratch;
                }
                Some(Resume::Solid) => session.passed_over(),
                None => {}
            }
        }
        session.end_volume();
        if let Some(last) = resume {
            feed.finished_split();
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
///
/// When it fails with a member error handler set, the rest of its volumes
/// are still read, so the walk can go on to the members after it.
fn extract_split(
    volume: &Archive,
    first: &FileHeader,
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    session: &mut DecoderSession<'_>,
    budget: &mut OutputBudget,
    open: &mut dyn FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
) -> std::result::Result<Archive, SplitFailure<Archive>> {
    validate_split_fragment(first, options.password)?;
    let mut walk = SplitWalk::new(feed, volume, first, &session.allowance)?;
    let salvage = options.salvage;
    match extract_split_walk(volume, first, &mut walk, salvage, session, budget, open) {
        Ok(writer) => flush_split(
            walk.into_last_volume()?,
            Some(writer),
            &budget.control,
            &first.name,
        ),
        Err(error)
            if options.member_errors.is_none()
                || matches!(
                    error.kind(),
                    crate::ErrorKind::Cancelled
                        | crate::ErrorKind::Io
                        | crate::ErrorKind::ResourceLimit
                ) =>
        {
            // Limits on a split member stay terminal, as before.
            Err(error.into())
        }
        Err(error) => Err(SplitFailure {
            error,
            last: walk.into_last_volume().ok().map(Box::new),
        }),
    }
}

fn extract_split_walk(
    volume: &Archive,
    first: &FileHeader,
    walk: &mut SplitWalk<'_, '_, '_>,
    salvage: bool,
    session: &mut DecoderSession<'_>,
    budget: &mut OutputBudget,
    open: &mut dyn FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
) -> Result<Box<dyn Write>> {
    // Parts written before the size was known record it only in the last header.
    let sized;
    let first = if first.known_unpacked_size().is_none() {
        let mut header = first.clone();
        if decodes_unsized(first, budget, session.scratch.is_some()) {
            // Its volumes are fetched as the decoder reaches them, and its
            // size checked against the last one's header at the end.
            header.unpacked_size = usize::MAX as u64;
        } else {
            match walk.prefetch() {
                Ok(last) => {
                    header.unpacked_size = last.unpacked_size;
                    header.file_flags = (first.file_flags & !FHFL_UNP_SIZE_UNKNOWN)
                        | (last.file_flags & FHFL_UNP_SIZE_UNKNOWN);
                }
                // Salvaging, the volumes there are are still decoded, size
                // unknown, until the walk's failure stops the decoder.
                Err(_) if salvage => header.unpacked_size = u64::MAX,
                Err(error) => return Err(error),
            }
        }
        sized = header;
        &sized
    } else {
        first
    };
    first.check_output_limit(budget)?;
    budget.control.check()?;
    let decryptor = split_decryptor(volume, first, session)?;
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
                    walk,
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
            session.write_lazy_split_to(first, walk, first_reader, decryptor.as_ref(), writer)
        })
        .map_err(|error| walk.failure.take().unwrap_or(error))?;
    Ok(writer)
}

/// Whether a split member whose first part doesn't record its size can be
/// decoded as its volumes arrive, so that a caller asked for each volume in
/// turn sees its output between them. The decoder stops at the stream's last
/// block. An output limit needs the size first, as do the scratch decoder and
/// an encrypted stored member, whose cipher padding only the size tells from
/// its data; their volumes are all fetched before decoding.
fn decodes_unsized(first: &FileHeader, budget: &OutputBudget, scratch: bool) -> bool {
    !budget.is_limited() && !scratch && !(first.is_stored() && first.encrypted)
}

/// Checks what an unsized split member decoded to, up to its stream's last
/// block, against the size its last header gives.
fn decoded_size_matches(last: &FileHeader, decoded: Option<usize>) -> Result<()> {
    let declared = last.unpacked_size;
    match decoded.map(|decoded| decoded as u64) {
        Some(decoded) if decoded == declared => Ok(()),
        Some(decoded) if decoded < declared => Err(Error::MemberEndedEarly { declared, decoded }),
        _ => Err(Error::MemberRanPastDeclaredSize { declared }),
    }
}

fn split_decryptor(
    volume: &Archive,
    first: &FileHeader,
    session: &DecoderSession<'_>,
) -> Result<Option<SplitDecryptor>> {
    if !first.encrypted {
        return Ok(None);
    }
    let keys = first.encryption_keys_cached(session.password, &volume.key_cache)?;
    Ok(Some(SplitDecryptor {
        keys,
        iv: first.encryption_iv()?,
    }))
}

pub(super) fn packed_reader<'a>(
    chain: LazyChain<'a>,
    decryptor: Option<&SplitDecryptor>,
    allowance: &Allowance,
    salvage: bool,
) -> Result<PackedReader<'a>> {
    let Some(decryptor) = decryptor else {
        return Ok(PackedReader::Plain(chain));
    };
    Ok(PackedReader::Encrypted(Boxed::try_new(
        || {
            Rar50DecryptingReader::with_keys(chain, decryptor.keys.key, decryptor.iv)
                .map(|reader| reader.dropping_cut_block(salvage))
        },
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

pub(super) fn write_stored(
    first: &FileHeader,
    walk: &mut SplitWalk<'_, '_, '_>,
    first_reader: RangeReader<'static>,
    decryptor: Option<&SplitDecryptor>,
    writer: &mut dyn Write,
    allowance: &Allowance,
) -> Result<()> {
    let mut sums = SplitChecksums::new(first);
    let salvage = walk.options.salvage;
    let mut reader = packed_reader(
        LazyChain::new(&mut *walk, first_reader),
        decryptor,
        allowance,
        salvage,
    )?;
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

impl DecoderSession<'_> {
    pub(super) fn write_lazy_split_to(
        &mut self,
        first: &FileHeader,
        walk: &mut SplitWalk<'_, '_, '_>,
        first_reader: RangeReader<'static>,
        decryptor: Option<&SplitDecryptor>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        self.guard_solid_chain(first, |session| {
            if first.known_unpacked_size().is_none()
                || first.should_stream_decode(session.buffered_decode_limit)
            {
                return session
                    .stream_lazy_split_to(first, walk, first_reader, decryptor, writer)
                    .map_err(|error| first.entry_error("decoding", error));
            }
            let write = |writer: &mut dyn Write, data: &[u8]| {
                writer
                    .write_all(data)
                    .map_err(Error::from)
                    .map_err(|error| first.entry_error("writing", error))
            };
            let data = match session.decode_lazy_split(first, walk, first_reader, decryptor) {
                Ok(data) => data,
                Err(error) => {
                    // Salvage delivers what decoded before the failure.
                    if let Some(partial) = session.decoder.take_salvaged() {
                        write(writer, &partial)?;
                    }
                    return Err(first.entry_error("decoding", error));
                }
            };
            let checked = walk.finish().map(|last| {
                last.verify_integrity_with_keys(&data, decryptor.map(|decryptor| &decryptor.keys))
            });
            let verified = match checked {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => {
                    Err(first.entry_error("verifying", walk.checksum_error().unwrap_or(error)))
                }
                Err(error) => Err(first.entry_error("decoding", error)),
            };
            // Salvage writes the member even when it fails, then its error.
            if verified.is_ok() || session.decoder.read_control.salvage() {
                write(writer, &data)?;
            }
            verified
        })
    }

    pub(super) fn stream_lazy_split_to(
        &mut self,
        first: &FileHeader,
        walk: &mut SplitWalk<'_, '_, '_>,
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
            let salvage = walk.options.salvage;
            let mut packed = packed_reader(
                LazyChain::new(&mut *walk, first_reader),
                decryptor,
                &self.allowance,
                salvage,
            )?;
            control.finish(unchecked.stream_packed_with_crc_policy::<true>(
                &mut packed,
                None,
                &mut decoder,
                self.buffered_decode_limit,
                self.scratch,
                Some(&mut |chunk: &[u8]| sums.update(chunk)),
                writer,
            ))
        };
        let size_unknown = first.known_unpacked_size().is_none();
        decoded
            .and_then(|()| walk.finish())
            .and_then(|last| {
                if size_unknown {
                    decoded_size_matches(last, decoder.ended_early())?;
                }
                sums.verify(last, decryptor)
            })
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
        walk: &mut SplitWalk<'_, '_, '_>,
        first_reader: RangeReader<'static>,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Buffer<u8>> {
        let info = first.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = checked_unpacked_size(first.unpacked_size)?;
        let allowance = self.decoder.allowance();
        let decoded = {
            let salvage = walk.options.salvage;
            let mut reader = packed_reader(
                LazyChain::new(&mut *walk, first_reader),
                decryptor,
                &allowance,
                salvage,
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
        // A MAC'd CRC32 or hash needs the password; RAR 7 and rars key only the final fragment.
        if file.uses_hash_mac() {
            return None;
        }
        if let Some(crc) = file.data_crc32 {
            return Some(Self::Crc32(crc));
        }
        let hash = file.hash.as_ref()?;
        (hash.hash_type == 0)
            .then(|| hash.data.as_slice().try_into().ok())
            .flatten()
            .map(Self::Blake2sp)
    }
}

/// RAR 5 split members, for the shared [`SplitWalk`](crate::volume_extract::SplitWalk).
pub(super) enum Rar50 {}

pub(super) type SplitWalk<'f, 'p, 'o> = crate::volume_extract::SplitWalk<'f, 'p, 'o, Rar50>;

impl SplitFormat for Rar50 {
    type Archive = Archive;
    type Header = FileHeader;
    type Fragment = Fragment;
    type State = ();
    const INCOMPLETE: &'static str = "RAR 5 split entry is incomplete";
    const INTERRUPTED: &'static str = "RAR 5 split entry is interrupted by a regular entry";

    fn first_header(volume: &Archive) -> Option<&FileHeader> {
        volume.files().next()
    }
    fn header_count(volume: &Archive) -> usize {
        volume.files().count()
    }
    fn known_size(file: &FileHeader) -> Option<u64> {
        file.known_unpacked_size()
    }
    fn is_split_after(file: &FileHeader) -> bool {
        file.is_split_after()
    }
    fn reader(volume: &Archive, file: &FileHeader) -> Result<RangeReader<'static>> {
        volume
            .source
            .owned_range_reader(file.block.data_range.clone())
    }
    fn fragment(index: usize, volume: &Archive, file: &FileHeader) -> Fragment {
        Fragment {
            volume: index,
            source: volume.source.clone(),
            range: file.block.data_range.clone(),
            check: FragmentCheck::of(file),
        }
    }

    fn validate_continuation(walk: &SplitWalk<'_, '_, '_>, file: &FileHeader) -> Result<()> {
        if !file.is_split_before() {
            return Err(Error::InvalidHeader(Self::INTERRUPTED));
        }
        file.check_dictionary_limit(walk.options.rar50_dictionary_size_limit)?;
        validate_split_fragment(file, walk.options.password)?;
        // The stored name may differ; size, compression info and checksums still tie it to its member.
        if let (Some(size), Some(known)) = (file.known_unpacked_size(), walk.size) {
            if size != known {
                return Err(Error::InvalidHeader(
                    "RAR 5 split entry unpacked size changed",
                ));
            }
        }
        if file.compression_info != walk.first.compression_info {
            return Err(Error::InvalidHeader(
                "RAR 5 split entry compression info changed",
            ));
        }
        if file.encrypted != walk.first.encrypted {
            return Err(Error::InvalidHeader(
                "RAR 5 split entry encryption flag changed",
            ));
        }
        Ok(())
    }
}

impl SplitWalk<'_, '_, '_> {
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
                index: fragment.volume,
                source: Box::new(source),
            });
        }
        None
    }
}

#[cfg(all(test, feature = "write"))]
pub(super) fn with_walk<T>(
    volumes: &[Archive],
    options: crate::ArchiveReadOptions<'_>,
    allowance: &Allowance,
    run: impl FnOnce(&Archive, &FileHeader, &mut SplitWalk<'_, '_, '_>) -> Result<T>,
) -> Result<T> {
    let mut volumes = volumes.iter().cloned().map(Ok);
    let mut feed = VolumeFeed::complete(&mut volumes, options);
    let volume = feed.next()?.expect("a first volume");
    let first = volume.files().next().expect("a first fragment");
    let mut walk = SplitWalk::new(&mut feed, &volume, first, allowance)?;
    run(&volume, first, &mut walk)
}
