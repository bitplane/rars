use super::{Archive, DecoderSession, FileHeader};
use crate::codec::rar50::{MembersAhead, Offered};
use crate::codec::workspace::Budget;

#[cfg(all(test, feature = "write"))]
thread_local! {
    static CLAIMS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(all(test, feature = "write"))]
pub(super) fn claims() -> usize {
    CLAIMS.get()
}

pub(super) enum SolidAhead<B: Budget> {
    Undecided,
    Off,
    On {
        stage: MembersAhead<B>,
        // The first member not yet offered.
        next: usize,
    },
}

impl<B: Budget> DecoderSession<'_, B> {
    /// Offers the members from `index` on in `files`, the archive's in order, to be decoded ahead.
    pub(super) fn read_ahead(&mut self, archive: &Archive, files: &[&FileHeader], index: usize) {
        if let SolidAhead::Undecided = self.ahead {
            self.ahead = self.start_ahead(archive, files);
        }
        let SolidAhead::On { stage, next } = &mut self.ahead else {
            return;
        };
        if *next < index {
            *next = index;
            stage.break_run();
        }
        if let Some(file) = files.get(index) {
            stage.pass_before(ahead_key(file));
        }
        while let Some(file) = files.get(*next) {
            if stage.full() {
                return;
            }
            if file.is_directory() || (file.unpacked_size == 0 && file.packed_size() == 0) {
                *next += 1;
                continue;
            }
            if file.is_stored() && file.redirection.is_none() {
                *next += 1;
                continue;
            }
            let packed = ahead_candidate(file, self.buffered_decode_limit).and_then(|info| {
                let read = file.packed_data_with_allowance(
                    archive,
                    self.password,
                    &archive.key_cache,
                    &self.decoder.read_control,
                    &self.allowance,
                );
                Some((info, read.ok()?.0))
            });
            let offered = match packed {
                Some(((algorithm_version, solid), packed)) => stage.offer(
                    ahead_key(file),
                    &packed,
                    file.unpacked_size,
                    algorithm_version,
                    solid,
                ),
                None => {
                    stage.break_run();
                    Offered::Refused
                }
            };
            if offered == Offered::Full {
                return;
            }
            *next += 1;
        }
    }

    fn start_ahead(&self, archive: &Archive, files: &[&FileHeader]) -> SolidAhead<B> {
        let control = &self.decoder.read_control;
        let solid =
            archive.main.is_solid() || files.iter().any(|file| file.compression_info & 0x40 != 0);
        if self.decoder.is_limited()
            || !solid
            || self.scratch.is_some()
            || control.salvage()
            || !crate::parallel::may_spawn()
        {
            return SolidAhead::Off;
        }
        let workers = crate::parallel::block_decode_workers(control.decode_workers());
        match MembersAhead::new(workers, &self.allowance) {
            Some(stage) if workers != 0 => SolidAhead::On { stage, next: 0 },
            _ => SolidAhead::Off,
        }
    }

    /// Hands the decoder `file`'s blocks if they were decoded ahead.
    pub(super) fn claim_ahead(&mut self, file: &FileHeader) {
        if let SolidAhead::On { stage, .. } = &mut self.ahead {
            if let Some(claimed) = stage.claim(ahead_key(file)) {
                #[cfg(all(test, feature = "write"))]
                CLAIMS.set(CLAIMS.get() + 1);
                self.decoder.set_claimed(claimed);
            }
        }
    }

    pub(super) fn settle_ahead(&mut self, file: &FileHeader, decoded: bool) {
        let whole = self.decoder.settle_claim();
        if let SolidAhead::On { stage, .. } = &mut self.ahead {
            if !decoded {
                stage.clear();
            } else if whole {
                stage.replayed(ahead_key(file));
            }
        }
    }

    /// The next volume's members are offered from its first.
    pub(super) fn end_volume(&mut self) {
        if let SolidAhead::On { stage, next } = &mut self.ahead {
            stage.clear();
            *next = 0;
        }
    }
}

// Offsets rise through one volume, and a volume change clears the stage.
fn ahead_key(file: &FileHeader) -> u64 {
    file.block.data_range.start as u64
}

/// The algorithm version and solid flag of a member the buffered decoder would decode.
fn ahead_candidate(file: &FileHeader, buffered_decode_limit: u64) -> Option<(u8, bool)> {
    if file.is_stored()
        || file.redirection.is_some()
        || file.is_split_before()
        || file.is_split_after()
        || file.is_cut_short()
        || file.should_stream_decode(buffered_decode_limit)
    {
        return None;
    }
    let info = file.decoded_compression_info().ok()?;
    Some((info.algorithm_version, info.solid))
}
