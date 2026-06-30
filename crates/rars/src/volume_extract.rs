use std::io::{Read, Result};

pub(crate) struct SplitVolumeState<P> {
    pending: Option<P>,
}

impl<P> SplitVolumeState<P> {
    pub(crate) fn new() -> Self {
        Self { pending: None }
    }

    pub(crate) fn advance(
        &mut self,
        split_before: bool,
        split_after: bool,
    ) -> SplitVolumeStep<'_, P> {
        match (self.pending.is_some(), split_before, split_after) {
            (false, false, false) => SplitVolumeStep::Regular,
            (false, false, true) => SplitVolumeStep::Start,
            // The match arm's first field proves a pending split exists.
            (true, true, true) => {
                SplitVolumeStep::Continue(self.pending.as_mut().expect("pending split"))
            }
            // The match arm's first field proves a pending split exists.
            (true, true, false) => {
                SplitVolumeStep::Finish(self.pending.take().expect("pending split"))
            }
            // Error states leave pending untouched; callers currently return
            // the error immediately rather than attempting recovery.
            (false, true, _) => SplitVolumeStep::MissingFirst,
            (true, false, _) => SplitVolumeStep::Interrupted,
        }
    }

    pub(crate) fn begin(&mut self, pending: P) {
        debug_assert!(self.pending.is_none());
        self.pending = Some(pending);
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}

pub(crate) enum SplitVolumeStep<'a, P> {
    Regular,
    Start,
    Continue(&'a mut P),
    Finish(P),
    MissingFirst,
    Interrupted,
}

pub(crate) struct ChainedReader<'a> {
    readers: Vec<Box<dyn Read + 'a>>,
    index: usize,
}

impl<'a> ChainedReader<'a> {
    pub(crate) fn new(readers: Vec<Box<dyn Read + 'a>>) -> Self {
        Self { readers, index: 0 }
    }
}

impl Read for ChainedReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        while let Some(reader) = self.readers.get_mut(self.index) {
            let read = reader.read(out)?;
            if read != 0 {
                return Ok(read);
            }
            self.index += 1;
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn split_volume_state_reports_regular_member_without_pending_split() {
        let mut state = SplitVolumeState::<u8>::new();

        assert!(matches!(
            state.advance(false, false),
            SplitVolumeStep::Regular
        ));
        assert!(!state.is_pending());
    }

    #[test]
    fn split_volume_state_tracks_start_continue_and_finish() {
        let mut state = SplitVolumeState::new();

        assert!(matches!(state.advance(false, true), SplitVolumeStep::Start));
        state.begin(vec![1]);
        assert!(state.is_pending());

        match state.advance(true, true) {
            SplitVolumeStep::Continue(parts) => parts.push(2),
            _ => panic!("expected split continuation"),
        }
        assert!(state.is_pending());

        match state.advance(true, false) {
            SplitVolumeStep::Finish(parts) => assert_eq!(parts, vec![1, 2]),
            _ => panic!("expected split finish"),
        }
        assert!(!state.is_pending());
    }

    #[test]
    fn split_volume_state_reports_orphan_continuation() {
        let mut state = SplitVolumeState::<u8>::new();

        assert!(matches!(
            state.advance(true, false),
            SplitVolumeStep::MissingFirst
        ));
        assert!(matches!(
            state.advance(true, true),
            SplitVolumeStep::MissingFirst
        ));
        assert!(!state.is_pending());
    }

    #[test]
    fn split_volume_state_reports_regular_entry_interrupting_pending_split() {
        let mut state = SplitVolumeState::new();
        assert!(matches!(state.advance(false, true), SplitVolumeStep::Start));
        state.begin(7u8);

        assert!(matches!(
            state.advance(false, false),
            SplitVolumeStep::Interrupted
        ));
        assert!(state.is_pending());
    }

    #[test]
    fn chained_reader_reads_all_fragments_in_order() {
        let readers: Vec<Box<dyn Read>> = vec![
            Box::new(Cursor::new(b"one".to_vec())),
            Box::new(Cursor::new(Vec::new())),
            Box::new(Cursor::new(b"two".to_vec())),
        ];
        let mut reader = ChainedReader::new(readers);
        let mut out = Vec::new();

        reader.read_to_end(&mut out).unwrap();

        assert_eq!(out, b"onetwo");
    }
}
