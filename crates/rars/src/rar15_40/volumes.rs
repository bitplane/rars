use super::*;
use crate::output_limit::OutputBudget;
use crate::source::RangeReader;
use crate::volume_extract::{FragmentWalk, LazyChain, VolumeEnd, VolumeFeed};

const EARC_NEXT_VOLUME: u16 = 0x0001;

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
    let mut skip = 0;
    loop {
        let mut resume = None;
        let count = volume.files().count();
        for (index, file) in volume.files().enumerate().skip(skip) {
            options.check_cancelled()?;
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
                resume = Some(extract_split(
                    &volume,
                    file,
                    feed,
                    &mut session,
                    &mut budget,
                    &mut open,
                    &mut links,
                )?);
                break;
            }
            let meta = file.metadata();
            if meta.is_directory {
                options.check_cancelled()?;
                let _ = open(&meta)?;
                options.check_cancelled()?;
                continue;
            }
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
            )?;
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
        Block::End(end) => Some(end.flags & EARC_NEXT_VOLUME != 0),
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
    session: &mut DecoderSession<'_, B>,
    budget: &mut OutputBudget,
    open: &mut F,
    links: &mut Option<&mut LegacyLink<'_>>,
) -> Result<Archive>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let password = session.password;
    validate_split_fragment(first, password)?;
    budget.check(first.unp_size, &first.name)?;
    let meta = ExtractedEntryMeta {
        name_is_unicode: first.unicode_name.is_some(),
        name: first.name.clone(),
        file_time: first.file_time,
        mtime_refinement: first.mtime_refinement(),
        attr: first.attr,
        host_os: first.host_os,
        is_directory: false,
    };
    check_legacy_size(&meta, first.unp_size, links.is_some())?;
    let allowance = session.allowance.clone();
    let mut walk = SplitWalk::new(feed, first, &allowance)?;
    let first_reader = volume
        .source
        .owned_range_reader(first.packed_range.clone())?;
    let control = budget.control.clone();
    legacy_output(
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
                        first_reader,
                        &mut walk,
                        password,
                        &mut writer,
                        &allowance,
                    );
                }
                let crc = {
                    let mut reader = packed_reader(
                        LazyChain::new(&mut walk, first_reader),
                        first,
                        password,
                        &allowance,
                    )?;
                    session
                        .decode_split_to(&mut reader, first, &mut writer)
                        .map_err(|error| first.entry_error("extracting", error))?
                };
                let last = walk
                    .finish()
                    .map_err(|error| first.entry_error("extracting", error))?;
                if last.unp_size != first.unp_size {
                    return Err(first.entry_error(
                        "extracting",
                        Error::InvalidHeader("RAR 1.5 split entry unpacked size changed"),
                    ));
                }
                last.crc_result(crc, password)
                    .map_err(|error| first.entry_error("extracting", error))
            })
        },
    )
    .map_err(|error| walk.failure.take().unwrap_or(error))?;
    walk.into_last_volume()
}

fn write_stored<B: Budget>(
    first: &FileHeader,
    first_reader: RangeReader<'static>,
    walk: &mut SplitWalk<'_, '_, '_, B>,
    password: Option<&[u8]>,
    writer: &mut dyn Write,
    allowance: &B,
) -> Result<()> {
    let expected_len = usize::try_from(first.unp_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 split unpacked size overflows usize"))?;
    let expected_packed_len = if first.is_encrypted() && first.unp_ver >= 20 {
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
        let reader = packed_reader(
            LazyChain::new(&mut *walk, first_reader),
            first,
            password,
            allowance,
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
    if walk.packed_len != expected_packed_len || last.unp_size != first.unp_size {
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

pub(super) fn packed_reader<R: Read, B: Budget>(
    chain: R,
    first: &FileHeader,
    password: Option<&[u8]>,
    allowance: &B,
) -> Result<PackedReader<R, B>> {
    if !first.is_encrypted() {
        return Ok(PackedReader::Plain(chain));
    }
    let password = password.expect("encrypted split fragments were admitted with a password");
    Ok(PackedReader::Encrypted(Boxed::try_new(
        || DecryptingReader::with_allowance(chain, first.unp_ver, password, first.salt, allowance),
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

/// Fetches a split member's later volumes as its reader reaches each fragment's end.
pub(super) struct SplitWalk<'f, 'p, 'o, B: Budget> {
    feed: &'f mut VolumeFeed<'p, 'o, Archive>,
    first: FileHeader,
    split_after: bool,
    last: Option<Archive>,
    packed_len: usize,
    /// The volume of each fragment, charged to the reader workspace.
    fragments: Buffer<usize, B>,
    /// A refused or missing volume, reported as itself rather than as a decode failure.
    failure: Option<Error>,
}

impl<'f, 'p, 'o, B: Budget> SplitWalk<'f, 'p, 'o, B> {
    fn new(
        feed: &'f mut VolumeFeed<'p, 'o, Archive>,
        first: &FileHeader,
        allowance: &B,
    ) -> Result<Self> {
        Ok(Self {
            fragments: Buffer::copied(&[feed.current_index()], allowance)?,
            feed,
            first: first.clone(),
            split_after: true,
            last: None,
            packed_len: packed_len(0, first)?,
            failure: None,
        })
    }

    /// Reads past any fragments the decoder did not need and returns the member's last header.
    fn finish(&mut self) -> Result<&FileHeader> {
        while self.next_fragment()?.is_some() {}
        self.last
            .as_ref()
            .and_then(|volume| volume.files().next())
            .ok_or(Error::InvalidHeader("RAR 1.5 split entry is incomplete"))
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
        validate_split_fragment(file, self.feed.options().password)?;
        let first = &self.first;
        if file.name != first.name {
            return Err(Error::InvalidHeader("RAR 1.5 split entry name changed"));
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
            let Some(volume) = self.feed.next_part()? else {
                return Err(Error::InvalidHeader("RAR 1.5 split entry is incomplete"));
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
            self.fragments.try_push(self.feed.current_index())?;
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
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        self.advance()
            .inspect_err(|error| self.failure = Some(error.clone()))
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
    let mut walk = SplitWalk::new(&mut feed, first, &Default::default())?;
    run(&volume, first, &mut walk)
}
