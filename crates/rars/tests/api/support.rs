use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

pub(super) struct CollectWriter(pub(super) Rc<RefCell<Vec<u8>>>);

impl Write for CollectWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Builds a member from bytes the test already holds.
pub(super) fn rar50_entry(name: &[u8], data: &[u8]) -> rars::rar50::ArchiveEntry {
    rars::rar50::ArchiveEntry::new(
        name.to_vec(),
        rars::EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.to_vec())),
    )
}
