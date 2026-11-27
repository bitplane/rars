use crate::source::RangeReader;
use std::io::{Read, Result, Write};

/// Guesses one encoding for the legacy member names across all the volumes.
/// The same rules apply as for [`crate::Archive::detect_legacy_name_encoding`].
pub fn detect_volume_legacy_name_encoding(
    archives: &[crate::Archive],
) -> Option<crate::filename::LegacyNameEncoding> {
    crate::filename::detect_legacy_name_encoding(archives.iter())
}

pub(crate) type Volumes<'p, A> = dyn Iterator<Item = crate::Result<A>> + Send + 'p;
pub(crate) type VolumeCompletion<'p> = dyn FnMut(usize) + Send + 'p;

#[derive(Clone, Copy)]
pub(crate) struct VolumeSelection {
    pub(crate) volume: usize,
    pub(crate) first_file: usize,
    pub(crate) members: usize,
}

pub(crate) enum VolumeInput<'a> {
    Arriving(Option<Box<VolumeCompletion<'a>>>),
    Selected(VolumeSelection),
}

impl<'a> VolumeInput<'a> {
    pub(crate) fn feed<'p, 'o, A: PlacedVolume>(
        self,
        volumes: &'p mut Volumes<'p, A>,
        options: crate::ArchiveReadOptions<'o>,
    ) -> VolumeFeed<'p, 'o, A>
    where
        'a: 'p,
    {
        match self {
            Self::Arriving(completion) => {
                VolumeFeed::arriving(volumes, options).with_completion(completion)
            }
            Self::Selected(selection) => {
                VolumeFeed::complete(volumes, options).with_selection(selection)
            }
        }
    }
}

/// A failed split member and the volume holding its end, if available.
pub(crate) struct SplitFailure<A> {
    pub(crate) error: crate::Error,
    pub(crate) last: Option<Box<A>>,
}

impl<A> From<crate::Error> for SplitFailure<A> {
    fn from(error: crate::Error) -> Self {
        Self { error, last: None }
    }
}

/// A flush failure leaves the final volume available so extraction can resume.
pub(crate) fn flush_split<A>(
    last: A,
    writer: Option<Box<dyn Write>>,
    control: &crate::read_control::ReadControl,
    name: &[u8],
) -> std::result::Result<A, SplitFailure<A>> {
    let Some(mut writer) = writer else {
        return Ok(last);
    };
    if let Err(error) = crate::extraction_control::flush_verified(control, name, &mut *writer) {
        return Err(SplitFailure {
            error,
            last: Some(Box::new(last)),
        });
    }
    Ok(last)
}

/// A volume that may record its place in its set.
pub(crate) trait PlacedVolume {
    /// The number the volume records, if any. Each is one more than the one
    /// before, wrapping at 65,536 as the 16-bit RAR 3.x field does.
    fn volume_number(&self) -> Option<u16> {
        None
    }
}

impl PlacedVolume for crate::rar13::Archive {}

// RAR 5 checks its main header's number with `volume_order` instead.
impl PlacedVolume for crate::rar50::Archive {}

impl PlacedVolume for crate::rar15_40::Archive {
    fn volume_number(&self) -> Option<u16> {
        self.end_volume_number()
    }
}

/// Hands out a set's volumes front to back, each exactly once.
pub(crate) struct VolumeFeed<'p, 'o, A> {
    volumes: &'p mut Volumes<'p, A>,
    index: usize,
    /// The number the last volume handed out recorded.
    previous_number: Option<u16>,
    stop_at_last: bool,
    ended: bool,
    options: crate::ArchiveReadOptions<'o>,
    completion: Option<Box<VolumeCompletion<'p>>>,
    completed: usize,
    selection: Option<VolumeSelection>,
}

impl<'p, 'o, A: PlacedVolume> VolumeFeed<'p, 'o, A> {
    /// Volumes may still be arriving, so it is not advanced past one marked last.
    pub(crate) fn arriving(
        volumes: &'p mut Volumes<'p, A>,
        options: crate::ArchiveReadOptions<'o>,
    ) -> Self {
        let mut feed = Self::complete(volumes, options);
        feed.stop_at_last = true;
        feed
    }

    pub(crate) fn complete(
        volumes: &'p mut Volumes<'p, A>,
        options: crate::ArchiveReadOptions<'o>,
    ) -> Self {
        Self {
            volumes,
            index: 0,
            previous_number: None,
            stop_at_last: false,
            ended: false,
            options,
            completion: None,
            completed: 0,
            selection: None,
        }
    }

    pub(crate) fn with_completion(mut self, completion: Option<Box<VolumeCompletion<'p>>>) -> Self {
        self.completion = completion;
        self
    }

    pub(crate) fn with_selection(mut self, selection: VolumeSelection) -> Self {
        self.index = selection.volume;
        self.selection = Some(selection);
        self
    }

    pub(crate) fn first_file(&self) -> usize {
        self.selection.map_or(0, |selection| selection.first_file)
    }

    pub(crate) fn take_member(&mut self) -> bool {
        match &mut self.selection {
            Some(selection) if selection.members == 0 => false,
            Some(selection) => {
                selection.members -= 1;
                true
            }
            None => true,
        }
    }

    pub(crate) fn selection_finished(&self) -> bool {
        self.selection
            .is_some_and(|selection| selection.members == 0)
    }

    /// Split extraction may retain earlier sources until the member is checked.
    pub(crate) fn finished_split(&mut self) {
        self.finish_before(self.current_index());
    }

    fn finish_before(&mut self, index: usize) {
        if let Some(completion) = &mut self.completion {
            for finished in self.completed..index {
                completion(finished);
            }
            self.completed = index;
        }
    }

    pub(crate) fn options(&self) -> crate::ArchiveReadOptions<'o> {
        self.options
    }

    /// Zero-based index of the volume most recently handed out.
    pub(crate) fn current_index(&self) -> usize {
        self.index.saturating_sub(1)
    }

    /// Once the set has ended, the iterator is never advanced again.
    pub(crate) fn next(&mut self) -> crate::Result<Option<A>> {
        self.options.check_cancelled()?;
        if self.ended {
            return Ok(None);
        }
        let volume = self.volumes.next().transpose();
        self.ended = !matches!(volume, Ok(Some(_)));
        let volume = volume?;
        self.index += 1;
        // Relative to the volume before, so a run that starts later in a set,
        // or follows other archives, still reads; a swap or a gap breaks it.
        let number = volume.as_ref().and_then(PlacedVolume::volume_number);
        let previous = std::mem::replace(&mut self.previous_number, number);
        if matches!((previous, number), (Some(previous), Some(number))
            if number != previous.wrapping_add(1))
        {
            self.ended = true;
            return Err(crate::Error::InVolume {
                index: self.index - 1,
                source: Box::new(crate::Error::VolumeOutOfOrder),
            });
        }
        self.options.check_cancelled()?;
        Ok(volume)
    }

    /// The volume after one whose members are all done, unless it says it was the last.
    pub(crate) fn after(&mut self, end: VolumeEnd) -> crate::Result<Option<A>> {
        self.finish_before(self.index);
        if self.selection_finished() {
            return Ok(None);
        }
        if !self.stop_at_last {
            return self.next();
        }
        match end {
            VolumeEnd::Last => Ok(None),
            VolumeEnd::Unknown => self.next(),
            VolumeEnd::More => self.next_part(),
        }
    }

    /// The error for a member that continues past the volumes there are.
    pub(crate) fn missing_next(&self) -> crate::Error {
        crate::Error::InVolume {
            index: self.index,
            source: Box::new(crate::Error::MissingVolume),
        }
    }

    /// A volume the set still needs; running out fails the same way wherever it happens.
    pub(crate) fn next_part(&mut self) -> crate::Result<Option<A>> {
        let index = self.index;
        match self.next()? {
            None if self.stop_at_last => Err(crate::Error::InVolume {
                index,
                source: Box::new(crate::Error::MissingVolume),
            }),
            volume => Ok(volume),
        }
    }
}

/// What a volume's own headers say about the volumes after it.
pub(crate) enum VolumeEnd {
    Last,
    More,
    /// Volumes without an end record; the iterator ending ends the set.
    Unknown,
}

/// Yields a split member's packed fragments, fetching later volumes on demand.
pub(crate) trait FragmentWalk: Send {
    fn next_fragment(&mut self) -> crate::Result<Option<RangeReader<'static>>>;
}

/// Reads one packed range and follows continuation fragments when present.
pub(crate) struct LazyChain<'w> {
    walk: Option<&'w mut dyn FragmentWalk>,
    current: Option<RangeReader<'w>>,
}

impl<'w> LazyChain<'w> {
    pub(crate) fn single(reader: RangeReader<'w>) -> Self {
        Self {
            walk: None,
            current: Some(reader),
        }
    }

    pub(crate) fn bytes(bytes: &'w [u8]) -> Self {
        Self::single(RangeReader::Memory(std::io::Cursor::new(bytes)))
    }

    pub(crate) fn new(walk: &'w mut dyn FragmentWalk, first: RangeReader<'static>) -> Self {
        Self {
            walk: Some(walk),
            current: Some(first),
        }
    }
}

impl Read for LazyChain<'_> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while let Some(reader) = &mut self.current {
            let read = reader.read(out)?;
            if read != 0 {
                return Ok(read);
            }
            // Drop the spent fragment before pulling the next volume.
            self.current = None;
            if let Some(walk) = &mut self.walk {
                self.current = walk.next_fragment().map_err(std::io::Error::other)?;
            }
        }
        Ok(0)
    }
}

/// What a format supplies to [`SplitWalk`]: how its volumes' first headers
/// are read, what each fragment records, and what ties a continuation to the
/// member it continues.
pub(crate) trait SplitFormat: Sized {
    type Archive: PlacedVolume + Send;
    type Header: Clone + Send;
    /// What the walk keeps of each fragment, to explain a member that fails.
    type Fragment: Send;
    /// What the format keeps across a member's fragments beyond the walk's own.
    type State: Default + Send;
    const INCOMPLETE: &'static str;
    const INTERRUPTED: &'static str;
    fn first_header(volume: &Self::Archive) -> Option<&Self::Header>;
    fn header_count(volume: &Self::Archive) -> usize;
    fn known_size(file: &Self::Header) -> Option<u64>;
    fn is_split_after(file: &Self::Header) -> bool;
    fn reader(volume: &Self::Archive, file: &Self::Header) -> crate::Result<RangeReader<'static>>;
    fn fragment(index: usize, volume: &Self::Archive, file: &Self::Header) -> Self::Fragment;
    /// An error when `file` cannot be a later fragment of the member `walk` follows.
    fn validate_continuation(
        walk: &SplitWalk<'_, '_, '_, Self>,
        file: &Self::Header,
    ) -> crate::Result<()>;
    /// Takes note of a fragment the walk has accepted, the first included.
    fn record(_state: &mut Self::State, _file: &Self::Header) -> crate::Result<()> {
        Ok(())
    }
}

/// Fetches a split member's later volumes as its reader reaches each fragment's end.
pub(crate) struct SplitWalk<'f, 'p, 'o, F: SplitFormat> {
    feed: &'f mut VolumeFeed<'p, 'o, F::Archive>,
    pub(crate) options: crate::ArchiveReadOptions<'o>,
    pub(crate) first: F::Header,
    /// The member's size, once a fragment states it.
    pub(crate) size: Option<u64>,
    pub(crate) split_after: bool,
    last: Option<F::Archive>,
    prefetched: std::collections::VecDeque<RangeReader<'static>>,
    /// Each fragment read so far, charged to the reader workspace.
    pub(crate) fragments: crate::codec::workspace::Buffer<F::Fragment>,
    /// A refused or missing volume, reported as itself rather than as a decode failure.
    pub(crate) failure: Option<crate::Error>,
    pub(crate) state: F::State,
}

impl<'f, 'p, 'o, F: SplitFormat> SplitWalk<'f, 'p, 'o, F> {
    pub(crate) fn new(
        feed: &'f mut VolumeFeed<'p, 'o, F::Archive>,
        volume: &F::Archive,
        first: &F::Header,
        allowance: &crate::codec::workspace::Allowance,
    ) -> crate::Result<Self> {
        let mut fragments = crate::codec::workspace::Buffer::new(allowance);
        fragments.try_push(F::fragment(feed.current_index(), volume, first))?;
        let mut state = F::State::default();
        F::record(&mut state, first)?;
        Ok(Self {
            options: feed.options(),
            feed,
            first: first.clone(),
            size: F::known_size(first),
            split_after: true,
            last: None,
            prefetched: Default::default(),
            fragments,
            failure: None,
            state,
        })
    }

    /// Reads past any fragments the decoder did not need and returns the member's last header.
    pub(crate) fn finish(&mut self) -> crate::Result<&F::Header> {
        while self.next_fragment()?.is_some() {}
        // Salvaging, a failure ends the fragments rather than failing.
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        self.last_header()
    }

    pub(crate) fn last_header(&self) -> crate::Result<&F::Header> {
        self.last
            .as_ref()
            .and_then(F::first_header)
            .ok_or(crate::Error::InvalidHeader(F::INCOMPLETE))
    }

    /// Fetches every remaining volume of the member before any of its data is read.
    pub(crate) fn prefetch(&mut self) -> crate::Result<&F::Header> {
        while let Some(reader) = self
            .advance()
            .inspect_err(|error| self.failure = Some(error.clone()))?
        {
            self.prefetched.push_back(reader);
        }
        self.last_header()
    }

    pub(crate) fn into_last_volume(mut self) -> crate::Result<F::Archive> {
        self.finish()?;
        Ok(self.last.expect("finish found the last fragment"))
    }

    fn advance(&mut self) -> crate::Result<Option<RangeReader<'static>>> {
        if !self.split_after {
            return Ok(None);
        }
        loop {
            let missing = self.feed.missing_next();
            let Some(volume) = self.feed.next_part()? else {
                // The volumes given ran out while the member continues.
                return Err(missing);
            };
            let Some(file) = F::first_header(&volume) else {
                continue;
            };
            F::validate_continuation(self, file)?;
            if F::is_split_after(file) && F::header_count(&volume) != 1 {
                return Err(crate::Error::InvalidHeader(F::INTERRUPTED));
            }
            self.size = self.size.or(F::known_size(file));
            let reader = F::reader(&volume, file)?;
            self.fragments
                .try_push(F::fragment(self.feed.current_index(), &volume, file))?;
            F::record(&mut self.state, file)?;
            self.split_after = F::is_split_after(file);
            self.last = Some(volume);
            return Ok(Some(reader));
        }
    }
}

impl<F: SplitFormat> FragmentWalk for SplitWalk<'_, '_, '_, F> {
    fn next_fragment(&mut self) -> crate::Result<Option<RangeReader<'static>>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ArchiveSource;
    use std::collections::VecDeque;
    use std::sync::Arc;

    struct Fragments(VecDeque<crate::Result<RangeReader<'static>>>);

    impl FragmentWalk for Fragments {
        fn next_fragment(&mut self) -> crate::Result<Option<RangeReader<'static>>> {
            self.0.pop_front().transpose()
        }
    }

    fn fragment(bytes: &[u8]) -> RangeReader<'static> {
        ArchiveSource::Memory(Arc::from(bytes))
            .owned_range_reader(0..bytes.len())
            .unwrap()
    }

    #[test]
    fn lazy_chain_reads_every_fragment_in_order_and_skips_empty_ones() {
        let mut walk = Fragments(VecDeque::from([Ok(fragment(b"")), Ok(fragment(b"two"))]));
        let mut reader = LazyChain::new(&mut walk, fragment(b"one"));
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"onetwo");
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn lazy_chain_reports_the_walk_error_as_itself() {
        let mut walk = Fragments(VecDeque::from([Err(crate::Error::InvalidHeader(
            "refused",
        ))]));
        let mut reader = LazyChain::new(&mut walk, fragment(b"one"));
        let error = reader.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(
            crate::Error::from(error),
            crate::Error::InvalidHeader("refused")
        );
    }
}
