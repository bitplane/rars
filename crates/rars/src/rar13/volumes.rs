use super::*;
use crate::extraction_control::{finish_member, finish_split_member, Resume};
use crate::output_limit::OutputBudget;
use crate::source::RangeReader;
use crate::volume_extract::{
    flush_split, FragmentWalk, LazyChain, SplitFailure, VolumeEnd, VolumeFeed,
};

pub(super) fn extract<F>(
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    allowance: &Allowance,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    options.check_cancelled()?;
    let Some(mut volume) = feed.next()? else {
        return Err(Error::InvalidHeader("RAR 1.3 volume set is empty"));
    };
    let password = options.password;
    let mut budget = OutputBudget::new(options);
    let mut unpack15 = Decoder15::with_allowance(allowance);
    unpack15.read_control = budget.control.clone();
    let mut extracted_count = 0usize;
    let mut skip = feed.first_file();

    loop {
        let mut resume = None;
        let count = volume.entries.len();
        for (index, entry) in volume.entries.iter().enumerate().skip(skip) {
            options.check_cancelled()?;
            if !feed.take_member() {
                return Ok(());
            }
            let solid = volume.main.is_solid() && extracted_count != 0;
            if entry.is_split_before() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry flags are inconsistent",
                ));
            }
            if entry.is_split_after() {
                if index + 1 != count {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry is interrupted by a regular entry",
                    ));
                }
                let last = match extract_split(
                    &volume,
                    entry,
                    feed,
                    &mut budget,
                    &mut unpack15,
                    solid,
                    &mut open,
                ) {
                    Ok(last) => {
                        extracted_count += 1;
                        last
                    }
                    Err(SplitFailure { error, last: None }) => return Err(error),
                    // The member's last volume is in hand, so a member error
                    // handler can carry on past it, as for any other member.
                    Err(SplitFailure {
                        error,
                        last: Some(last),
                    }) => {
                        match finish_split_member(
                            options,
                            || crate::rar13_member(entry),
                            volume.main.is_solid(),
                            error,
                        )? {
                            Resume::Fresh => {
                                unpack15.reset();
                                unpack15.read_control = budget.control.clone();
                                extracted_count = 0;
                            }
                            Resume::Solid => extracted_count += 1,
                        }
                        *last
                    }
                };
                resume = Some(last);
                break;
            }
            let meta = entry.metadata();
            if meta.is_directory {
                options.check_cancelled()?;
                let _ = open(&meta)?;
                options.check_cancelled()?;
                extracted_count += 1;
                continue;
            }
            options.check_cancelled()?;
            let result = (|| {
                budget.check(u64::from(entry.header.unp_size), &meta.name)?;
                let writer = open(&meta)?;
                options.check_cancelled()?;
                budget.run_verified(&meta.name, writer, |mut writer| {
                    entry
                        .write_compressed_to(&volume, password, &mut unpack15, solid, &mut writer)
                        .map_err(|error| entry.entry_error("extracting", error))?;
                    options.check_cancelled()?;
                    Ok(())
                })
            })();
            let archive_solid = volume.main.is_solid();
            match finish_member(
                &mut None,
                options,
                || crate::rar13_member(entry),
                archive_solid,
                result,
            )? {
                Some(Resume::Fresh) => {
                    unpack15.reset();
                    unpack15.read_control = budget.control.clone();
                    extracted_count = 0;
                }
                Some(Resume::Solid) | None => extracted_count += 1,
            }
        }
        if let Some(last) = resume {
            feed.finished_split();
            // A continuation is always the first entry of its volume.
            volume = last;
            skip = 1;
            continue;
        }
        let end = if volume.main.is_volume() {
            VolumeEnd::Unknown
        } else {
            VolumeEnd::Last
        };
        match feed.after(end)? {
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

/// Decodes a split member while its later volumes arrive; returns the volume holding its end.
///
/// When it fails with a member error handler set, the rest of its volumes
/// are still read, so the walk can go on to the members after it. Unlike
/// RAR 1.5 and later, a fragment's header gives no checksum of its own
/// packed data (RAR 1.402 writes a running checksum of the input there), so
/// the damaged volume isn't named.
fn extract_split<F>(
    volume: &Archive,
    first: &Entry,
    feed: &mut VolumeFeed<'_, '_, Archive>,
    budget: &mut OutputBudget,
    unpack15: &mut Decoder15,
    solid: bool,
    open: &mut F,
) -> std::result::Result<Archive, SplitFailure<Archive>>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let options = feed.options();
    options.check_cancelled()?;
    budget.check(u64::from(first.header.unp_size), &first.name)?;
    if first.is_encrypted() {
        crate::crypto::require_encryption()?;
        options.password.ok_or(Error::NeedPassword)?;
    }
    let mut walk = SplitWalk::new(feed, first, &unpack15.allowance)?;
    match extract_split_walk(volume, first, &mut walk, budget, unpack15, solid, open) {
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
            Err(error.into())
        }
        Err(error) => Err(SplitFailure {
            error,
            last: walk.into_last_volume().ok().map(Box::new),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_split_walk<F>(
    volume: &Archive,
    first: &Entry,
    walk: &mut SplitWalk<'_, '_, '_>,
    budget: &mut OutputBudget,
    unpack15: &mut Decoder15,
    solid: bool,
    open: &mut F,
) -> Result<Box<dyn Write>>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let options = walk.options;
    let first_reader = volume
        .source
        .owned_range_reader(first.packed_range.clone())?;
    let meta = ExtractedEntryMeta {
        name: first.name.clone(),
        file_time: first.header.file_time,
        file_attr: first.header.file_attr,
        is_directory: false,
    };
    options.check_cancelled()?;
    let mut writer = open(&meta)?;
    options.check_cancelled()?;
    budget
        .run(&meta.name, &mut writer, |mut writer| {
            let mut checksum = Rar13Checksum::new();
            {
                let mut reader = packed_reader(
                    LazyChain::new(&mut *walk, first_reader),
                    first.is_encrypted(),
                    options.password,
                )?;
                if first.header.method == METHOD_STORE {
                    crate::stored_copy::copy(
                        &mut reader,
                        u64::from(first.header.unp_size),
                        false,
                        &mut |chunk: &[u8]| checksum.update(chunk),
                        &mut writer,
                        &unpack15.allowance,
                    )?;
                    checksum.verify_stored_length(first.header.unp_size)?;
                } else {
                    let mut checksum_writer = Rar13ChecksumWriter {
                        inner: &mut writer,
                        checksum: &mut checksum,
                    };
                    // Salvaging, a missing volume ends the input, so the
                    // last step may have run on past the bytes there are.
                    unpack15.decode_member_from_reader(
                        &mut reader,
                        first.header.unp_size as usize,
                        solid,
                        options.salvage,
                        &mut checksum_writer,
                    )?;
                }
            }
            let last = walk.finish()?;
            if last.header.unp_size != first.header.unp_size {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry unpacked size changed",
                ));
            }
            let actual = checksum.finish();
            if actual != last.header.file_crc {
                return Err(Error::CrcMismatch {
                    expected: last.header.file_crc,
                    actual,
                });
            }
            options.check_cancelled()
        })
        .map_err(|error| first.entry_error("extracting", error))
        .map_err(|error| walk.failure.take().unwrap_or(error))?;
    Ok(writer)
}

fn packed_reader<'a>(
    chain: LazyChain<'a>,
    encrypted: bool,
    password: Option<&[u8]>,
) -> Result<PackedReader<'a>> {
    if !encrypted {
        return Ok(PackedReader::Plain(chain));
    }
    crate::crypto::require_encryption()?;
    let password = password.ok_or(Error::NeedPassword)?;
    // RAR 1.402 encrypts the logical packed stream continuously across
    // split volumes; restarting the cipher at each part corrupts it.
    Ok(PackedReader::Encrypted(Rar13DecryptReader::new(
        chain,
        Rar13Cipher::for_password(password)?,
    )))
}

/// Fetches a split member's later volumes as its reader reaches each fragment's end.
struct SplitWalk<'f, 'p, 'o> {
    feed: &'f mut VolumeFeed<'p, 'o, Archive>,
    options: crate::ArchiveReadOptions<'o>,
    first: Entry,
    split_after: bool,
    last: Option<Archive>,
    /// The volume of each fragment, charged to the reader workspace.
    fragments: Buffer<usize>,
    /// A refused or missing volume, reported as itself rather than as a decode failure.
    failure: Option<Error>,
}

impl<'f, 'p, 'o> SplitWalk<'f, 'p, 'o> {
    fn new(
        feed: &'f mut VolumeFeed<'p, 'o, Archive>,
        first: &Entry,
        allowance: &Allowance,
    ) -> Result<Self> {
        Ok(Self {
            fragments: Buffer::copied(&[feed.current_index()], allowance)?,
            options: feed.options(),
            feed,
            first: first.clone(),
            split_after: true,
            last: None,
            failure: None,
        })
    }

    /// Reads past any fragments the decoder did not need and returns the member's last entry.
    fn finish(&mut self) -> Result<&Entry> {
        while self.next_fragment()?.is_some() {}
        // Salvaging, a failure ends the fragments rather than failing.
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        self.last
            .as_ref()
            .and_then(|volume| volume.entries.first())
            .ok_or(Error::InvalidHeader("RAR 1.3 split entry is incomplete"))
    }

    fn into_last_volume(mut self) -> Result<Archive> {
        self.finish()?;
        Ok(self.last.expect("finish found the last fragment"))
    }

    fn validate_continuation(&self, entry: &Entry) -> Result<()> {
        if !entry.is_split_before() {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry is interrupted by a regular entry",
            ));
        }
        if entry.name != self.first.name {
            return Err(Error::InvalidHeader("RAR 1.3 split entry name changed"));
        }
        if entry.header.method != self.first.header.method {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry compression method changed",
            ));
        }
        if entry.header.unp_ver != self.first.header.unp_ver {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry unpack version changed",
            ));
        }
        if entry.is_encrypted() != self.first.is_encrypted() {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry encryption flag changed",
            ));
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
            let Some(entry) = volume.entries.first() else {
                continue;
            };
            self.validate_continuation(entry)?;
            if entry.is_split_after() && volume.entries.len() != 1 {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry is interrupted by a regular entry",
                ));
            }
            self.fragments.try_push(self.feed.current_index())?;
            let reader = volume
                .source
                .owned_range_reader(entry.packed_range.clone())?;
            self.split_after = entry.is_split_after();
            self.last = Some(volume);
            return Ok(Some(reader));
        }
    }
}

impl FragmentWalk for SplitWalk<'_, '_, '_> {
    fn next_fragment(&mut self) -> Result<Option<RangeReader<'static>>> {
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
