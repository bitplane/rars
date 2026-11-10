use super::*;
use crate::output_limit::OutputBudget;
use crate::source::RangeReader;
use crate::volume_extract::{FragmentWalk, LazyChain, VolumeEnd, VolumeFeed};

pub(super) fn extract<F, B: Budget>(
    feed: &mut VolumeFeed<'_, '_, Archive>,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    allowance: &B,
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
    let mut skip = 0;

    loop {
        let mut resume = None;
        let count = volume.entries.len();
        for (index, entry) in volume.entries.iter().enumerate().skip(skip) {
            options.check_cancelled()?;
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
                resume = Some(extract_split(
                    &volume,
                    entry,
                    feed,
                    &mut budget,
                    &mut unpack15,
                    solid,
                    &mut open,
                )?);
                extracted_count += 1;
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
            budget.check(u64::from(entry.header.unp_size), &meta.name)?;
            options.check_cancelled()?;
            let mut writer = open(&meta)?;
            options.check_cancelled()?;
            budget.run(&meta.name, &mut writer, |mut writer| {
                entry
                    .write_compressed_to(&volume, password, &mut unpack15, solid, &mut writer)
                    .map_err(|error| entry.entry_error("extracting", error))?;
                options.check_cancelled()?;
                Ok(())
            })?;
            extracted_count += 1;
        }
        if let Some(last) = resume {
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
fn extract_split<F, B: Budget>(
    volume: &Archive,
    first: &Entry,
    feed: &mut VolumeFeed<'_, '_, Archive>,
    budget: &mut OutputBudget,
    unpack15: &mut Decoder15<B>,
    solid: bool,
    open: &mut F,
) -> Result<Archive>
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
                    LazyChain::new(&mut walk, first_reader),
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
                    unpack15.decode_member_from_reader(
                        &mut reader,
                        first.header.unp_size as usize,
                        solid,
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
    walk.into_last_volume()
}

fn packed_reader<R: Read>(
    chain: R,
    encrypted: bool,
    password: Option<&[u8]>,
) -> Result<PackedReader<R>> {
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
struct SplitWalk<'f, 'p, 'o, B: Budget> {
    feed: &'f mut VolumeFeed<'p, 'o, Archive>,
    first: Entry,
    split_after: bool,
    last: Option<Archive>,
    /// The volume of each fragment, charged to the reader workspace.
    fragments: Buffer<usize, B>,
    /// A refused or missing volume, reported as itself rather than as a decode failure.
    failure: Option<Error>,
}

impl<'f, 'p, 'o, B: Budget> SplitWalk<'f, 'p, 'o, B> {
    fn new(
        feed: &'f mut VolumeFeed<'p, 'o, Archive>,
        first: &Entry,
        allowance: &B,
    ) -> Result<Self> {
        Ok(Self {
            fragments: Buffer::copied(&[feed.current_index()], allowance)?,
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
            let Some(volume) = self.feed.next_part()? else {
                return Err(Error::InvalidHeader("RAR 1.3 split entry is incomplete"));
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

impl<B: Budget> FragmentWalk for SplitWalk<'_, '_, '_, B> {
    fn next_fragment(&mut self) -> Result<Option<RangeReader<'static>>> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        self.advance()
            .inspect_err(|error| self.failure = Some(error.clone()))
    }
}
