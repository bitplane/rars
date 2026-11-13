use crate::source::RangeReader;
use std::io::{Read, Result};

pub(crate) type Volumes<'p, A> = dyn Iterator<Item = crate::Result<A>> + Send + 'p;

/// A volume that can say it belongs somewhere else in its set.
pub(crate) trait PlacedVolume {
    /// True when the volume records a number other than `index`, counted from 0.
    fn placed_elsewhere(&self, _index: usize) -> bool {
        false
    }
}

impl PlacedVolume for crate::rar13::Archive {}

// RAR 5 checks its main header's number in `extract_with_volumes`.
impl PlacedVolume for crate::rar50::Archive {}

impl PlacedVolume for crate::rar15_40::Archive {
    fn placed_elsewhere(&self, index: usize) -> bool {
        // A 16-bit field, so a set past 65,536 volumes counts round again.
        self.end_volume_number()
            .is_some_and(|number| number != index as u16)
    }
}

/// Hands out a set's volumes front to back, each exactly once.
pub(crate) struct VolumeFeed<'p, 'o, A> {
    volumes: &'p mut Volumes<'p, A>,
    index: usize,
    stop_at_last: bool,
    ended: bool,
    options: crate::ArchiveReadOptions<'o>,
}

impl<'p, 'o, A: PlacedVolume> VolumeFeed<'p, 'o, A> {
    /// Volumes may still be arriving, so it is not advanced past one marked last.
    pub(crate) fn arriving(
        volumes: &'p mut Volumes<'p, A>,
        options: crate::ArchiveReadOptions<'o>,
    ) -> Self {
        Self {
            volumes,
            index: 0,
            stop_at_last: true,
            ended: false,
            options,
        }
    }

    pub(crate) fn complete(
        volumes: &'p mut Volumes<'p, A>,
        options: crate::ArchiveReadOptions<'o>,
    ) -> Self {
        Self {
            volumes,
            index: 0,
            stop_at_last: false,
            ended: false,
            options,
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
        if volume
            .as_ref()
            .is_some_and(|volume| volume.placed_elsewhere(self.index - 1))
        {
            self.ended = true;
            return Err(crate::Error::InVolume {
                number: self.index,
                source: Box::new(crate::Error::InvalidHeader("volume is out of order")),
            });
        }
        self.options.check_cancelled()?;
        Ok(volume)
    }

    /// The volume after one whose members are all done, unless it says it was the last.
    pub(crate) fn after(&mut self, end: VolumeEnd) -> crate::Result<Option<A>> {
        if !self.stop_at_last {
            return self.next();
        }
        match end {
            VolumeEnd::Last => Ok(None),
            VolumeEnd::Unknown => self.next(),
            VolumeEnd::More => self.next_part(),
        }
    }

    /// A volume the set still needs; running out fails the same way wherever it happens.
    pub(crate) fn next_part(&mut self) -> crate::Result<Option<A>> {
        let number = self.index + 1;
        match self.next()? {
            None if self.stop_at_last => Err(crate::Error::InVolume {
                number,
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
pub(crate) trait FragmentWalk {
    fn next_fragment(&mut self) -> crate::Result<Option<RangeReader<'static>>>;
}

/// Reads a split member's fragments as one stream, asking the walk for each next one.
pub(crate) struct LazyChain<'w, W> {
    walk: &'w mut W,
    current: Option<RangeReader<'static>>,
}

impl<'w, W: FragmentWalk> LazyChain<'w, W> {
    pub(crate) fn new(walk: &'w mut W, first: RangeReader<'static>) -> Self {
        Self {
            walk,
            current: Some(first),
        }
    }
}

impl<W: FragmentWalk> Read for LazyChain<'_, W> {
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
            self.current = self.walk.next_fragment().map_err(std::io::Error::other)?;
        }
        Ok(0)
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
