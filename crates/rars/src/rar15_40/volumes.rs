use super::*;
use crate::extraction_control::{finish_member, finish_split_member, Resume};
use crate::extraction_links::{decode_legacy_output, legacy_meta_is_link};
use crate::output_limit::OutputBudget;
use crate::source::{ArchiveSource, RangeReader};
use crate::volume_extract::{
    flush_split, FragmentWalk, LazyChain, SplitFailure, VolumeEnd, VolumeFeed,
};
use std::ops::Range;

pub(super) fn extract<F, B: Budget>(
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    mut links: Option<&mut LegacyLink<'_>>,
    allowance: &B,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    options.check_cancelled()?;
    let Some(mut volume) = feed.next()? else {
        return Err(Error::InvalidHeader("RAR 1.5 volume set is empty"));
    };

    let password = options.password;
    let mut budget = OutputBudget::new(options);
    let mut session = DecoderSession::with_allowance(volume.main.is_solid(), password, allowance);
    session.read_control = budget.control.clone();
    let mut skip = feed.first_file();
    loop {
        let mut resume = None;
        let count = volume.files().count();
        for (index, file) in volume.files().enumerate().skip(skip) {
            options.check_cancelled()?;
            if !feed.take_member() {
                return Ok(());
            }
            if file.is_split_before() {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry is missing its first part",
                ));
            }
            if file.is_split_after() {
                if index + 1 != count {
                    return Err(Error::InvalidHeader(
                        "RAR 1.5 split entry is interrupted by a regular entry",
                    ));
                }
                let last = match extract_split(
                    &volume,
                    file,
                    feed,
                    options,
                    &mut session,
                    &mut budget,
                    &mut open,
                    &mut links,
                ) {
                    Ok(last) => last,
                    Err(SplitFailure { error, last: None }) => return Err(error),
                    // The member's last volume is in hand, so a member error
                    // handler can carry on past it, as for any other member.
                    Err(SplitFailure {
                        error,
                        last: Some(last),
                    }) => {
                        let solid = volume.main.is_solid() || file.is_solid();
                        match finish_split_member(
                            options,
                            || crate::rar15_40_member(file),
                            solid,
                            error,
                        )? {
                            Resume::Fresh => {
                                session = DecoderSession::with_allowance(
                                    volume.main.is_solid(),
                                    password,
                                    allowance,
                                );
                                session.read_control = budget.control.clone();
                            }
                            Resume::Solid => session.passed_over(),
                        }
                        *last
                    }
                };
                resume = Some(last);
                break;
            }
            let meta = file.metadata();
            if meta.is_directory {
                options.check_cancelled()?;
                let _ = open(&meta)?;
                options.check_cancelled()?;
                continue;
            }
            let result = (|| {
                budget.check(file.unp_size, &file.name)?;
                options.check_cancelled()?;
                check_legacy_size(&meta, file.unp_size, links.is_some())?;
                let control = budget.control.clone();
                legacy_output(
                    &meta,
                    allowance,
                    &control,
                    &mut links,
                    || open(&meta),
                    |writer| {
                        budget.run(&file.name, writer, |mut writer| {
                            if file.is_stored() {
                                file.write_stored_with_allowance(
                                    &volume,
                                    password,
                                    &mut writer,
                                    allowance,
                                )
                                .map_err(|error| file.entry_error("extracting", error))?;
                            } else {
                                session
                                    .write_file_to(&volume, file, &mut writer)
                                    .map_err(|error| file.entry_error("extracting", error))?;
                            }
                            options.check_cancelled()?;
                            Ok(())
                        })
                    },
                )
            })();
            let solid = volume.main.is_solid() || file.is_solid();
            match finish_member(
                &mut None,
                options,
                || crate::rar15_40_member(file),
                solid,
                result,
            )? {
                Some(Resume::Fresh) => {
                    session =
                        DecoderSession::with_allowance(volume.main.is_solid(), password, allowance);
                    session.read_control = budget.control.clone();
                }
                Some(Resume::Solid) => session.passed_over(),
                None => {}
            }
        }
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
#[allow(clippy::too_many_arguments)]
fn extract_split<F, B: Budget>(
    volume: &Archive,
    first: &FileHeader,
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    session: &mut DecoderSession<'_, B>,
    budget: &mut OutputBudget,
    open: &mut F,
    links: &mut Option<&mut LegacyLink<'_>>,
) -> std::result::Result<Archive, SplitFailure<Archive>>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    validate_split_fragment(first, session.password)?;
    let allowance = session.allowance.clone();
    let mut walk = SplitWalk::new(feed, volume, first, &allowance)?;
    let salvage = options.salvage;
    match extract_split_walk(
        volume, first, &mut walk, salvage, session, budget, open, links,
    ) {
        Ok(writer) => flush_split(
            walk.into_last_volume()?,
            writer,
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

#[allow(clippy::too_many_arguments)]
fn extract_split_walk<F, B: Budget>(
    volume: &Archive,
    first: &FileHeader,
    walk: &mut SplitWalk<'_, '_, '_, B>,
    salvage: bool,
    session: &mut DecoderSession<'_, B>,
    budget: &mut OutputBudget,
    open: &mut F,
    links: &mut Option<&mut LegacyLink<'_>>,
) -> Result<Option<Box<dyn Write>>>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let password = session.password;
    let allowance = session.allowance.clone();
    let meta = ExtractedEntryMeta {
        name_is_unicode: first.name_is_unicode(),
        name: first.name.clone(),
        file_time: first.file_time,
        mtime_refinement: first.mtime_refinement(),
        attr: first.attr,
        host_os: first.host_os,
        is_directory: false,
    };
    // Parts written before the size was known record it only in the last header.
    let lazy = first.known_unp_size().is_none()
        && decodes_unsized(first, budget, links.is_some() && legacy_meta_is_link(&meta));
    let sized;
    let first = if lazy {
        // Its volumes are fetched as the decoder reaches them, and its size
        // checked against the last one's header at the end.
        let mut header = first.clone();
        header.unp_size = UNSIZED;
        sized = header;
        &sized
    } else if first.known_unp_size().is_none() {
        let mut header = first.clone();
        match walk.prefetch() {
            Ok(last) => header.unp_size = last.unp_size,
            // Salvaging, the volumes there are are still decoded, size
            // unknown, until the walk's failure stops the decoder.
            Err(_) if salvage => header.unp_size = UNSIZED,
            Err(error) => return Err(error),
        }
        sized = header;
        &sized
    } else {
        first
    };
    budget.check(first.unp_size, &first.name)?;
    check_legacy_size(&meta, first.unp_size, links.is_some())?;
    let first_reader = volume
        .source
        .owned_range_reader(first.packed_range.clone())?;
    let control = budget.control.clone();
    decode_legacy_output(
        &meta,
        &allowance,
        &control,
        links,
        || open(&meta),
        |writer| {
            budget.run(&first.name, writer, |mut writer| {
                if first.is_stored() {
                    return write_stored(
                        first,
                        lazy,
                        first_reader,
                        walk,
                        password,
                        &volume.key_cache,
                        &mut writer,
                        &allowance,
                    )
                    .map_err(|error| match walk.explanation(&error) {
                        Some(explained) => first.entry_error("extracting", explained),
                        None => error,
                    });
                }
                let decoded = {
                    let salvage = walk.options.salvage;
                    let mut reader = packed_reader(
                        LazyChain::new(&mut *walk, first_reader),
                        first,
                        password,
                        &volume.key_cache,
                        &allowance,
                        salvage,
                    )?;
                    session.decode_split_to(&mut reader, first, &mut writer)
                };
                let decoded = decoded
                    .map_err(|error| first.entry_error("extracting", walk.explain(error)))?;
                let last = walk
                    .finish()
                    .map_err(|error| first.entry_error("extracting", error))?;
                if lazy {
                    // Decoded to its stream's end-of-file marker.
                    return size_matches(last, decoded.len)
                        .and_then(|()| last.crc_result(decoded.crc, password))
                        .map_err(|error| first.entry_error("extracting", walk.explain(error)));
                }
                // Split members pass a stream that ends early whatever the
                // strict-sizes option says.
                last.decoded_result(decoded.lenient(), password)
                    .map_err(|error| first.entry_error("extracting", walk.explain(error)))
            })
        },
    )
    .map_err(|error| walk.failure.take().unwrap_or(error))
}

/// The size an unsized split member is decoded to: its stream's end, or the
/// volumes' end for a stored one.
const UNSIZED: u64 = usize::MAX as u64;

/// Whether a split member whose first part doesn't record its size can be
/// decoded as its volumes arrive, so that a caller asked for each volume in
/// turn sees its output between them. RAR 2.9 and later streams end with an
/// end-of-file marker for the decoder to stop at; RAR 1.5 and 2.0 ones need
/// the size. So do an output limit, a symbolic link's target, which is read
/// whole, and an encrypted stored member, whose cipher padding only the size
/// tells from its data. Their volumes are all fetched before decoding.
fn decodes_unsized(first: &FileHeader, budget: &OutputBudget, link: bool) -> bool {
    !budget.is_limited()
        && !link
        && if first.is_stored() {
            !first.is_encrypted()
        } else {
            first.unp_ver >= 29
        }
}

/// Checks what an unsized split member decoded to against the size its last
/// header gives.
fn size_matches(last: &FileHeader, decoded: u64) -> Result<()> {
    let declared = last.unp_size;
    if decoded == declared {
        Ok(())
    } else if decoded < declared {
        Err(Error::MemberEndedEarly { declared, decoded })
    } else {
        Err(Error::MemberRanPastDeclaredSize { declared })
    }
}

#[allow(clippy::too_many_arguments)]
fn write_stored<B: Budget>(
    first: &FileHeader,
    lazy: bool,
    first_reader: RangeReader<'static>,
    walk: &mut SplitWalk<'_, '_, '_, B>,
    password: Option<&[u8]>,
    key_cache: &KeyCache,
    writer: &mut dyn Write,
    allowance: &B,
) -> Result<()> {
    if lazy {
        return write_unsized_stored(first, first_reader, walk, writer, allowance);
    }
    let expected_len = usize::try_from(first.unp_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize"))?;
    // Salvaged without its size, which only a missing volume held, the
    // member is copied to where its volumes end, short of the cipher
    // padding, and the walk's failure ends it before the size is checked.
    let unsized_salvage = walk.options.salvage && first.unp_size == UNSIZED;
    let padded = first.is_encrypted() && first.unp_ver >= 20 && !unsized_salvage;
    let expected_packed_len = if padded {
        expected_len
            .checked_add(15)
            .map(|len| len & !15)
            .ok_or(Error::InvalidHeader(
                "RAR 2.x encrypted split stored size overflows",
            ))?
    } else {
        expected_len
    };
    let mut crc = Crc32::new();
    let copied = {
        let salvage = walk.options.salvage;
        let reader = packed_reader(
            LazyChain::new(&mut *walk, first_reader),
            first,
            password,
            key_cache,
            allowance,
            salvage,
        )?;
        crate::stored_copy::copy(
            &mut reader.take(expected_len as u64),
            expected_len as u64,
            false,
            &mut |chunk: &[u8]| crc.update(chunk),
            writer,
            allowance,
        )
    };
    let last = walk.finish()?.clone();
    if walk.packed_len != expected_packed_len {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split stored file has wrong reassembled size",
        ));
    }
    if copied? != expected_len as u64 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split stored file ended before unpacked size",
        ));
    }
    last.crc_result(crc.finish(), password)
        .map_err(|error| last.entry_error("extracting", error))
}

/// Copies an unencrypted stored member of unknown size to the end of its
/// last fragment, then checks its length and CRC against the last header.
fn write_unsized_stored<B: Budget>(
    first: &FileHeader,
    first_reader: RangeReader<'static>,
    walk: &mut SplitWalk<'_, '_, '_, B>,
    writer: &mut dyn Write,
    allowance: &B,
) -> Result<()> {
    debug_assert!(!first.is_encrypted());
    let mut crc = Crc32::new();
    let copied = crate::stored_copy::copy(
        &mut LazyChain::new(&mut *walk, first_reader),
        UNSIZED,
        false,
        &mut |chunk: &[u8]| crc.update(chunk),
        writer,
        allowance,
    );
    let last = walk.finish()?.clone();
    let copied = copied?;
    size_matches(&last, copied)?;
    last.crc_result(crc.finish(), None)
        .map_err(|error| last.entry_error("extracting", error))
}

pub(super) fn packed_reader<R: Read, B: Budget>(
    chain: R,
    first: &FileHeader,
    password: Option<&[u8]>,
    key_cache: &KeyCache,
    allowance: &B,
    salvage: bool,
) -> Result<PackedReader<R, B>> {
    if !first.is_encrypted() {
        return Ok(PackedReader::Plain(chain));
    }
    let password = password.expect("encrypted split fragments were admitted with a password");
    Ok(PackedReader::Encrypted(Boxed::try_new(
        || {
            DecryptingReader::with_allowance(
                chain,
                first.unp_ver,
                password,
                first.salt,
                key_cache,
                allowance,
            )
            .map(|reader| reader.dropping_cut_block(salvage))
        },
        allowance,
    )?))
}

pub(super) fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 1.5 split directory entry is invalid",
        ));
    }
    if file.is_encrypted() {
        crate::crypto::require_encryption()?;
    }
    if file.is_encrypted() && password.is_none() {
        return Err(Error::NeedPassword);
    }
    Ok(())
}

/// Where a fragment's packed data is, and the CRC32 its header gives for it.
pub(super) struct Fragment {
    volume: usize,
    source: ArchiveSource,
    range: Range<usize>,
    /// Only a fragment the member goes on past has one: the last holds
    /// the CRC32 of the member's output instead. RAR 1.5 writes all ones.
    crc: Option<u32>,
}

impl Fragment {
    fn of(volume: usize, archive: &Archive, file: &FileHeader) -> Self {
        Self {
            volume,
            source: archive.source.clone(),
            range: file.packed_range.clone(),
            crc: file
                .is_split_after()
                .then_some(file.file_crc)
                .filter(|&crc| crc != u32::MAX),
        }
    }

    /// The CRC32 of its packed data, when its volume can still be read.
    fn actual_crc(&self) -> Option<u32> {
        let mut crc = Crc32::new();
        let mut sink = CrcWriter {
            inner: &mut std::io::sink(),
            crc: &mut crc,
        };
        self.source
            .copy_range_to(self.range.clone(), &mut sink)
            .ok()
            .map(|()| crc.finish())
    }
}

/// Fetches a split member's later volumes as its reader reaches each fragment's end.
pub(super) struct SplitWalk<'f, 'p, 'o, B: Budget> {
    feed: &'f mut VolumeFeed<'p, 'o, Archive>,
    options: crate::ArchiveReadOptions<'o>,
    first: FileHeader,
    /// The member's size, once a fragment states it.
    size: Option<u64>,
    split_after: bool,
    last: Option<Archive>,
    packed_len: usize,
    prefetched: std::collections::VecDeque<RangeReader<'static>>,
    /// Each fragment read so far, charged to the reader workspace.
    fragments: Buffer<Fragment, B>,
    /// A refused or missing volume, reported as itself rather than as a decode failure.
    failure: Option<Error>,
}

impl<'f, 'p, 'o, B: Budget> SplitWalk<'f, 'p, 'o, B> {
    fn new(
        feed: &'f mut VolumeFeed<'p, 'o, Archive>,
        volume: &Archive,
        first: &FileHeader,
        allowance: &B,
    ) -> Result<Self> {
        let mut fragments = Buffer::new(allowance);
        fragments.try_push(Fragment::of(feed.current_index(), volume, first))?;
        Ok(Self {
            fragments,
            options: feed.options(),
            feed,
            first: first.clone(),
            size: first.known_unp_size(),
            split_after: true,
            last: None,
            packed_len: packed_len(0, first)?,
            prefetched: Default::default(),
            failure: None,
        })
    }

    /// Reads past any fragments the decoder did not need and returns the member's last header.
    fn finish(&mut self) -> Result<&FileHeader> {
        while self.next_fragment()?.is_some() {}
        // Salvaging, a failure ends the fragments rather than failing.
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        self.last_header()
    }

    /// Turns a failed member's error into the checksum mismatch of the
    /// fragment whose packed data disagrees with its header, if one does.
    /// Sink and reader I/O, limits, cancellation and headers that contradict
    /// each other keep their own meaning.
    fn explain(&self, error: Error) -> Error {
        self.explanation(&error).unwrap_or(error)
    }

    /// The fragment checksum mismatch [`Self::explain`] gives for `error`.
    fn explanation(&self, error: &Error) -> Option<Error> {
        if matches!(
            error.kind(),
            crate::ErrorKind::Io
                | crate::ErrorKind::ResourceLimit
                | crate::ErrorKind::Cancelled
                | crate::ErrorKind::UnsupportedFeature
        ) || matches!(error.root_cause(), Error::InvalidHeader(_))
        {
            return None;
        }
        self.checksum_error()
    }

    /// Re-reads every fragment that carries a CRC32 of its own packed data
    /// and reports the first that disagrees.
    ///
    /// Only consulted once a member has already failed, as for RAR 5: a
    /// fragment CRC32 that says something other than what is there does not
    /// stop a member that decodes to its own checksum. A volume the caller
    /// has since removed is skipped.
    fn checksum_error(&self) -> Option<Error> {
        self.fragments.iter().find_map(|fragment| {
            let expected = fragment.crc?;
            let actual = fragment.actual_crc()?;
            (actual != expected).then(|| Error::InVolume {
                index: fragment.volume,
                source: Box::new(Error::Crc32Mismatch { expected, actual }),
            })
        })
    }

    fn last_header(&self) -> Result<&FileHeader> {
        self.last
            .as_ref()
            .and_then(|volume| volume.files().next())
            .ok_or(Error::InvalidHeader("RAR 1.5 split entry is incomplete"))
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
                "RAR 1.5 split entry is interrupted by a regular entry",
            ));
        }
        validate_split_fragment(file, self.options.password)?;
        let first = &self.first;
        // The stored name may differ; size, method and CRC still tie the fragment to its member.
        if let (Some(size), Some(known)) = (file.known_unp_size(), self.size) {
            if size != known {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry unpacked size changed",
                ));
            }
        }
        if file.method != first.method {
            return Err(Error::InvalidHeader(
                "RAR 1.5 split entry compression method changed",
            ));
        }
        if file.unp_ver != first.unp_ver {
            return Err(Error::InvalidHeader(
                "RAR 1.5 split entry unpack version changed",
            ));
        }
        if file.is_encrypted() != first.is_encrypted() {
            return Err(Error::InvalidHeader(
                "RAR 1.5 split entry encryption flag changed",
            ));
        }
        if first.is_encrypted() && first.unp_ver >= 29 && file.salt != first.salt {
            return Err(Error::InvalidHeader("RAR 3.x split entry salt changed"));
        }
        Ok(())
    }

    fn advance(&mut self) -> Result<Option<RangeReader<'static>>> {
        if !self.split_after {
            return Ok(None);
        }
        loop {
            let missing = self.feed.missing_next();
            let Some(volume) = self.feed.next_part()? else {
                // The volumes given ran out while the member continues.
                return Err(missing);
            };
            let Some(file) = volume.files().next() else {
                continue;
            };
            self.validate_continuation(file)?;
            if file.is_split_after() && volume.files().count() != 1 {
                return Err(Error::InvalidHeader(
                    "RAR 1.5 split entry is interrupted by a regular entry",
                ));
            }
            self.size = self.size.or(file.known_unp_size());
            self.fragments
                .try_push(Fragment::of(self.feed.current_index(), &volume, file))?;
            self.packed_len = packed_len(self.packed_len, file)?;
            let reader = volume
                .source
                .owned_range_reader(file.packed_range.clone())?;
            self.split_after = file.is_split_after();
            self.last = Some(volume);
            return Ok(Some(reader));
        }
    }
}

pub(super) fn packed_len(total: usize, file: &FileHeader) -> Result<usize> {
    total
        .checked_add(
            usize::try_from(file.pack_size)
                .map_err(|_| Error::InvalidHeader("RAR 1.5 split packed size overflows usize"))?,
        )
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 split packed size overflows usize",
        ))
}

impl<B: Budget> FragmentWalk for SplitWalk<'_, '_, '_, B> {
    fn next_fragment(&mut self) -> Result<Option<RangeReader<'static>>> {
        // Fragments fetched before a failure are still read, when salvaging.
        if let Some(reader) = self.prefetched.pop_front() {
            return Ok(Some(reader));
        }
        let error = match &self.failure {
            Some(error) => error.clone(),
            None => match self.advance() {
                Ok(reader) => return Ok(reader),
                Err(error) => {
                    self.failure = Some(error.clone());
                    error
                }
            },
        };
        // Salvaging, the member's data ends where its volumes give out, so
        // the decoder delivers what it decoded first. The failure is still
        // the member's, once it is decoded.
        if self.options.salvage {
            return Ok(None);
        }
        Err(error)
    }
}

#[cfg(all(test, feature = "write"))]
pub(super) fn with_walk<T>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    run: impl FnOnce(
        &Archive,
        &FileHeader,
        &mut SplitWalk<'_, '_, '_, crate::codec::workspace::Allowance>,
    ) -> Result<T>,
) -> Result<T> {
    let mut volumes = volumes.iter().cloned().map(Ok);
    let options = crate::ArchiveReadOptions::with_optional_password(password);
    let mut feed = VolumeFeed::complete(&mut volumes, options);
    let volume = feed.next()?.expect("a first volume");
    let first = volume.files().next().expect("a first fragment");
    let mut walk = SplitWalk::new(&mut feed, &volume, first, &Default::default())?;
    run(&volume, first, &mut walk)
}
