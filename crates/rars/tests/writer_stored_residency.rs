#![cfg(feature = "write")]

//! A stored member is copied through, never loaded: whatever the format, the
//! writer reads no further ahead of its output than one copy buffer. This pins
//! the "stored" column of `docs/writer-limits.md`.

use rars::{ArchiveVersion, Builder, EntrySource, WriterResources};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const MEMBER: u64 = 16 << 20;
/// Headers plus the largest copy buffer any writer uses, with room to spare.
const AHEAD: u64 = 1 << 20;

/// Bytes made up from their position, so the test holds none of them.
struct Pattern {
    pos: u64,
    read: Arc<AtomicUsize>,
}

impl Read for Pattern {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let n = buffer.len().min((MEMBER - self.pos) as usize);
        for (offset, byte) in buffer[..n].iter_mut().enumerate() {
            *byte = ((self.pos + offset as u64) * 31 % 251) as u8;
        }
        self.pos += n as u64;
        self.read.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
}

impl Seek for Pattern {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(delta) => MEMBER.saturating_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.saturating_add_signed(delta),
        };
        Ok(self.pos)
    }
}

/// Counts what is written and checks the source's current pass against it.
struct Output {
    written: u64,
    read: Arc<AtomicUsize>,
    furthest_ahead: u64,
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written += bytes.len() as u64;
        // Past the headers, the copying pass is the one under way.
        if self.written > AHEAD {
            let read = self.read.load(Ordering::Relaxed) as u64;
            let ahead = read.saturating_sub(self.written);
            self.furthest_ahead = self.furthest_ahead.max(ahead);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_stored_member_is_copied_through_not_loaded_in_every_format() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        let read = Arc::new(AtomicUsize::new(0));
        let source = {
            let read = read.clone();
            EntrySource::from_opener(MEMBER, move || {
                // Each pass counts from its own start.
                read.store(0, Ordering::Relaxed);
                Ok(Box::new(Pattern {
                    pos: 0,
                    read: read.clone(),
                }))
            })
        };
        let mut builder = Builder::new(format).store(true);
        builder
            .add_source(b"member.bin".to_vec(), source, None, None)
            .unwrap();
        let mut output = Output {
            written: 0,
            read,
            furthest_ahead: 0,
        };
        builder
            .write_to(&mut output, &WriterResources::default(), None)
            .unwrap();

        assert!(output.written > MEMBER, "{format}: {}", output.written);
        assert!(
            output.furthest_ahead <= AHEAD,
            "{format}: read {} bytes ahead of the output",
            output.furthest_ahead
        );
    }
}
