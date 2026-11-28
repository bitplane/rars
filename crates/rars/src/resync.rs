//! Finding the next block header past damage, for a salvaging parse.
//!
//! The scan looks at every offset after the damage. A cheap test of the
//! bytes there (the probe) picks out the few offsets that could start a
//! header, and only those are read whole and checked, checksum included (the
//! confirmation). Compressed data can hold a false match for any one test, so
//! a candidate has to pass all of them.
//!
//! The work is bounded. Each offset costs the probe, a fixed handful of byte
//! tests. Confirmations cost the header bytes they read, and a parse may
//! spend no more on them than a few times the archive's length, see
//! [`ResyncBudget`]. Scans never go back over bytes an earlier scan passed,
//! because the walk only moves forward from where a scan found a header.

use crate::{Error, ErrorKind, Result};

/// The most bytes a probe needs at an offset.
pub(crate) const PROBE_LEN: usize = 64;
/// Bytes read per step of a scan.
const CHUNK: usize = 64 * 1024;

/// What one parse may spend confirming candidates, in header bytes read.
pub(crate) struct ResyncBudget {
    left: u64,
}

impl ResyncBudget {
    /// Four times the archive's length, plus room for two of the largest RAR 5
    /// headers, so a short archive can still confirm one.
    pub(crate) fn new(archive_len: usize) -> Self {
        Self {
            left: (archive_len as u64)
                .saturating_mul(4)
                .saturating_add(4 << 20),
        }
    }
}

/// Scans `from..end` for the first offset at which `probe` accepts the bytes
/// and `confirm` then accepts the header.
///
/// `read(offset, len)` returns the `len` bytes at `offset`, all inside
/// `from..end`. `probe` gets up to [`PROBE_LEN`] bytes at an offset and how
/// many bytes are left before `end`, and returns how many bytes from the
/// offset the header takes, if it may be one; at most what is left.
/// `confirm(offset, header)` checks those bytes: a header that turns out not
/// to parse is `Ok(false)`, or an error of the kind a damaged one gives.
///
/// `None` when no header is found, or when the budget runs out first.
pub(crate) fn scan(
    from: usize,
    end: usize,
    budget: &mut ResyncBudget,
    control: &crate::read_control::ReadControl,
    read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>>,
    probe: &dyn Fn(&[u8], usize) -> Option<usize>,
    confirm: &mut dyn FnMut(usize, Vec<u8>) -> Result<bool>,
) -> Result<Option<usize>> {
    let mut start = from;
    while start < end {
        control.check()?;
        let step = CHUNK.min(end - start);
        let bytes = read(start, (CHUNK + PROBE_LEN).min(end - start))?;
        for index in 0..step {
            let at = start + index;
            let Some(cost) = probe(&bytes[index..], end - at) else {
                continue;
            };
            let Some(left) = budget.left.checked_sub(cost as u64) else {
                return Ok(None);
            };
            budget.left = left;
            let header = if index + cost <= bytes.len() {
                bytes[index..index + cost].to_vec()
            } else {
                read(at, cost)?
            };
            match confirm(at, header) {
                Ok(true) => return Ok(Some(at)),
                Ok(false) => {}
                Err(error) if candidate_failed(&error) => {}
                Err(error) => return Err(error),
            }
        }
        start += step;
    }
    Ok(None)
}

/// Whether `error` from confirming a candidate only says it is no header:
/// anything but cancellation or a failing source, which end the parse.
fn candidate_failed(error: &Error) -> bool {
    !matches!(
        error.kind(),
        ErrorKind::Cancelled | ErrorKind::Io | ErrorKind::SourceChanged
    )
}

/// Why a salvaging walk resynced: a header whose sizes run past the file.
pub(crate) const SIZES_PAST_END: &str = "the header's sizes run past the end of the file";
/// Why a salvaging walk resynced: a header of no type a walk reads, which
/// fails its checksum, is taken for no header at all.
const UNKNOWN_DAMAGED: &str = "it fails its checksum and its type is unknown";
/// Why a salvaging walk resynced: the header fails its checksum, as do the
/// ones just before it.
const DAMAGED_RUN: &str = "it fails its checksum, as do the headers before it";
/// How many headers in a row a salvaging walk reads as stored when their
/// checksums fail.
const MAX_DAMAGED_RUN: usize = 3;

/// What a salvaging walk keeps to resync past a header that doesn't parse.
pub(crate) struct Resync {
    budget: ResyncBudget,
    /// The first of the blocks just read whose header failed its checksum,
    /// by offset from the archive's start. Its sizes may be wrong, and so may
    /// everything the walk read after it.
    pub(crate) suspect: Option<usize>,
    /// How many headers in a row failed their checksums.
    run: usize,
}

impl Resync {
    pub(crate) fn new(archive_len: usize) -> Self {
        Self {
            budget: ResyncBudget::new(archive_len),
            suspect: None,
            run: 0,
        }
    }

    /// Notes a block header just read at `pos`, and whether its checksum
    /// failed. Returns the reason to resync instead of reading it as stored:
    /// it is of no type the walk reads, or too many damaged headers came in
    /// a row. The walk got to those by the sizes of a damaged one, and
    /// following them on would let a crafted file send it through the same
    /// bytes again after every resync.
    pub(crate) fn read_header(
        &mut self,
        pos: usize,
        damaged: bool,
        known: bool,
    ) -> Option<&'static str> {
        if !damaged {
            self.suspect = None;
            self.run = 0;
            return None;
        }
        if self.suspect.is_none() {
            self.suspect = Some(pos);
        }
        self.run += 1;
        if !known {
            Some(UNKNOWN_DAMAGED)
        } else if self.run > MAX_DAMAGED_RUN {
            Some(DAMAGED_RUN)
        } else {
            None
        }
    }

    /// Where the walk carries on after the header at `pos` failed with
    /// `reason`: the next header after it that [`scan`] finds with `probe`
    /// and `confirm`, or after the first damaged header of the run that led
    /// here, if one did. Then `drop_since(start)` drops the blocks read after
    /// that header, and what they reported goes too, as the walk only got to
    /// them by its sizes. Returns the header found and where the damage
    /// began; `None` when no header is found, and then nothing is changed.
    ///
    /// `pos` and the result are relative to `archive_offset`, where the
    /// archive starts in the file, and `archive_len` is its length from there.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resume(
        &mut self,
        pos: usize,
        reason: &'static str,
        archive_len: usize,
        archive_offset: usize,
        control: &crate::read_control::ReadControl,
        read: &mut dyn FnMut(usize, usize) -> Result<Vec<u8>>,
        probe: &dyn Fn(&[u8], usize) -> Option<usize>,
        confirm: &mut dyn FnMut(usize, Vec<u8>) -> Result<bool>,
        drop_since: &mut dyn FnMut(usize),
    ) -> Result<Option<(usize, usize)>> {
        let start = self.suspect.unwrap_or(pos);
        let Some(next) = scan(
            start + 1,
            archive_len,
            &mut self.budget,
            control,
            read,
            probe,
            confirm,
        )?
        else {
            return Ok(None);
        };
        if self.suspect.is_some() {
            drop_since(start);
            control.retract_damage(archive_offset + start + 1..archive_offset + pos + 1);
        }
        control.report_damage(
            archive_offset + start,
            crate::HeaderDamageKind::Resynced {
                reason,
                next: (archive_offset + next) as u64,
            },
        );
        self.suspect = None;
        self.run = 0;
        Ok(Some((next, start)))
    }
}

/// Whether a salvaging parse passes over a header whose block was read
/// whole but whose own fields fail with `error`. Here even a field that runs
/// past the header is damage, not a cut.
pub(crate) fn salvage_skips(options: &crate::ArchiveReadOptions<'_>, error: &Error) -> bool {
    options.salvage && error.kind() == ErrorKind::InvalidArchive
}

/// Whether a salvaging parse goes past `error` in a header, rather than
/// failing: damage, not cancellation, a limit or a missing password.
pub(crate) fn salvage_stops(options: &crate::ArchiveReadOptions<'_>, error: &Error) -> bool {
    options.salvage
        && error.kind() == ErrorKind::InvalidArchive
        && !matches!(error.root_cause(), Error::TooShort)
}

/// Records a header that doesn't parse, which a salvaging parse passes over.
pub(crate) fn unreadable(control: &crate::read_control::ReadControl, offset: usize, error: &Error) {
    control.report_damage(
        offset,
        crate::HeaderDamageKind::Unreadable {
            reason: crate::header_damage::record_reason(error),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(
        bytes: &[u8],
        budget: &mut ResyncBudget,
        probe: &dyn Fn(&[u8], usize) -> Option<usize>,
    ) -> (Option<usize>, usize) {
        let mut confirmed = 0;
        let found = scan(
            0,
            bytes.len(),
            budget,
            &crate::read_control::ReadControl::default(),
            &mut |at, len| Ok(bytes[at..at + len].to_vec()),
            probe,
            &mut |_, header| {
                confirmed += 1;
                Ok(header == b"HEAD")
            },
        )
        .unwrap();
        (found, confirmed)
    }

    #[test]
    fn finds_a_header_past_a_chunk_boundary() {
        let mut bytes = vec![b'H'; CHUNK * 2 + 10];
        bytes[CHUNK + 3..CHUNK + 7].copy_from_slice(b"HEAD");
        let probe = |prefix: &[u8], _: usize| prefix.starts_with(b"HE").then_some(4);
        let (found, confirmed) = run(&bytes, &mut ResyncBudget::new(bytes.len()), &probe);
        assert_eq!(found, Some(CHUNK + 3));
        assert_eq!(confirmed, 1);
    }

    #[test]
    fn the_budget_bounds_confirmations() {
        let bytes = vec![0u8; 1 << 20];
        let mut budget = ResyncBudget { left: 1000 };
        let (found, confirmed) = run(&bytes, &mut budget, &|_, _| Some(100));
        assert_eq!(found, None);
        assert_eq!(confirmed, 10);
    }
}
