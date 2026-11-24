//! Deciding from a few samples that a member will not compress, before any of
//! it is coded.
//!
//! A writer that codes a member and only then compares sizes spends its whole
//! compression time on noise, video or archives it ends up storing anyway
//! (#481). This looks at sixteen spread-out samples first and stores the
//! member if together they show nothing worth keeping.
//!
//! The sampling and the rule are format-neutral. A writer supplies what one
//! sample packs to on its own, coded the cheapest way it has, and keeps the
//! decisions this cannot make for it: a member in a solid chain, say, which may
//! compress against the members before it even when it does not on its own.
//!
//! What a sample cannot see is redundancy at a longer range than the sample,
//! such as the same incompressible file twice in one tar. Those are stored, as
//! they would be by a writer whose dictionary did not reach back far enough.

use crate::{Error, Result};
use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;

/// How many samples a member is judged by.
const SAMPLES: u64 = 16;

/// The longest sample. Long enough that a block's tables are a small part of
/// what it packs to, short enough that sixteen of them cost about one
/// megabyte of the cheapest coding.
pub(crate) const SAMPLE_LEN: usize = 64 * 1024;

/// Members smaller than this are coded and compared afterwards, as before. A
/// probe of a smaller member would cost as much as coding it.
pub(crate) const MIN_MEMBER: u64 = 1024 * 1024;

/// The member is stored when its samples, coded alone, save less than this
/// share of their size, in parts per thousand.
///
/// One rule rather than a count of samples that missed, so a member with one
/// region that compresses well is still compressed: a sample at 92% is enough
/// to keep it, which is what a tar of text with one large video inside needs.
/// A sample that grows counts as saving nothing, so the overhead of coding
/// noise cannot hide what another sample saves.
const SAVING_PER_MILLE: u64 = 5;

/// Where a member of `len` bytes is sampled, or `None` when it is too small to
/// be worth sampling.
///
/// Each sample is centred in one of sixteen equal segments, which keeps them
/// off the header at the start of a container file and the index at its end:
/// the first 64 KiB of a video can pack to two thirds while its body does not
/// pack at all.
pub(crate) fn sample_ranges(len: u64) -> Option<impl Iterator<Item = Range<u64>>> {
    if len < MIN_MEMBER {
        return None;
    }
    // Samples cover at most half a member at the bottom of the range.
    let sample = (SAMPLE_LEN as u64).min(len / (2 * SAMPLES));
    let segment = len / SAMPLES;
    Some((0..SAMPLES).map(move |index| {
        let start = index * segment + (segment - sample) / 2;
        start..start + sample
    }))
}

/// Whether a member of `len` bytes looks too incompressible to be worth coding.
///
/// `measure` returns what one sample packs to on its own. Sampling stops at the
/// first sample that settles it the other way, so a compressible member costs
/// about one sample.
pub(crate) fn looks_incompressible(
    reader: &mut (impl Read + Seek + ?Sized),
    len: u64,
    mut measure: impl FnMut(&[u8]) -> Result<usize>,
) -> Result<bool> {
    let Some(ranges) = sample_ranges(len) else {
        return Ok(false);
    };
    let mut verdict = Verdict::default();
    let mut sample = Vec::new();
    for range in ranges {
        sample.resize((range.end - range.start) as usize, 0);
        reader.seek(SeekFrom::Start(range.start))?;
        reader
            .read_exact(&mut sample)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    Error::SourceChanged("entry source size changed while compressing")
                }
                _ => error.into(),
            })?;
        let packed = measure(&sample)?;
        if !verdict.add(sample.len(), packed, sample.len() as u64 * SAMPLES) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// What the samples so far have saved.
#[derive(Default)]
struct Verdict {
    saved: u64,
}

impl Verdict {
    /// Counts a sample, and returns whether the member could still be stored
    /// once all `sampled` bytes are in.
    fn add(&mut self, len: usize, packed: usize, sampled: u64) -> bool {
        self.saved += len.saturating_sub(packed) as u64;
        self.saved * 1000 < sampled * SAVING_PER_MILLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn small_members_are_not_sampled() {
        assert!(sample_ranges(MIN_MEMBER - 1).is_none());
        let mut reader = Cursor::new(vec![0u8; 1000]);
        assert!(!looks_incompressible(&mut reader, 1000, |_| unreachable!()).unwrap());
    }

    #[test]
    fn samples_are_centred_in_sixteen_segments_inside_the_member() {
        for len in [MIN_MEMBER, 3 * MIN_MEMBER + 7, 1 << 31] {
            let ranges: Vec<_> = sample_ranges(len).unwrap().collect();
            assert_eq!(ranges.len(), 16);
            let segment = len / 16;
            for (index, range) in ranges.iter().enumerate() {
                let index = index as u64;
                assert!(range.start >= index * segment && range.end <= (index + 1) * segment);
                let before = range.start - index * segment;
                let after = (index + 1) * segment - range.end;
                assert!(before.abs_diff(after) <= 1, "{len}: {range:?}");
                assert!(range.end - range.start <= SAMPLE_LEN as u64);
            }
            // Never more than half the member.
            let covered: u64 = ranges.iter().map(|range| range.end - range.start).sum();
            assert!(covered * 2 <= len);
        }
    }

    /// Sixteen samples that each grow a little are stored; one that saves a
    /// tenth keeps the member compressed, and stops the sampling there.
    #[test]
    fn one_region_that_compresses_keeps_the_member() {
        let len = 16 * SAMPLE_LEN as u64 * 4;
        let data: Vec<u8> = (0..len).map(|index| (index / 4) as u8).collect();
        let mut reader = Cursor::new(&data);
        let mut measured = 0;
        assert!(looks_incompressible(&mut reader, len, |sample| {
            measured += 1;
            Ok(sample.len() + 10)
        })
        .unwrap());
        assert_eq!(measured, 16);

        let mut measured = 0;
        assert!(!looks_incompressible(&mut reader, len, |sample| {
            measured += 1;
            Ok(if measured == 3 {
                sample.len() * 9 / 10
            } else {
                sample.len() + 10
            })
        })
        .unwrap());
        assert_eq!(measured, 3);
    }

    /// Small savings add up: half a percent spread over every sample is
    /// enough to compress.
    #[test]
    fn savings_are_summed_across_samples() {
        let len = 16 * SAMPLE_LEN as u64 * 4;
        let mut reader = Cursor::new(vec![0u8; len as usize]);
        assert!(
            looks_incompressible(&mut reader, len, |sample| Ok(sample.len() * 996 / 1000)).unwrap()
        );
        assert!(
            !looks_incompressible(&mut reader, len, |sample| Ok(sample.len() * 994 / 1000))
                .unwrap()
        );
    }

    #[test]
    fn a_source_shorter_than_its_length_is_reported() {
        let mut reader = Cursor::new(vec![0u8; MIN_MEMBER as usize / 2]);
        let error =
            looks_incompressible(&mut reader, MIN_MEMBER, |sample| Ok(sample.len())).unwrap_err();
        assert!(matches!(error, Error::SourceChanged(_)), "{error:?}");
    }
}
