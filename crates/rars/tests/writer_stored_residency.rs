#![cfg(feature = "write")]

//! A stored member is copied through, never loaded: whatever the format, the
//! writer reads no further ahead of its output than its copy buffers. This pins
//! the "stored" column of `docs/writer-limits.md`.

use rars::{ArchiveVersion, Builder, EntrySource, WriterResources};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const MEMBER: u64 = 16 << 20;
/// Headers plus the largest buffer any writer copies through inline, with room
/// to spare.
const AHEAD: u64 = 1 << 20;
/// RAR 5 and 7 read, hash and write a stored member on separate threads when
/// there is more than one, through four 1 MiB buffers. However late the output
/// runs, the reader can fill every buffer but the one being written.
const PIPELINED_AHEAD: u64 = 3 << 20;

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

        let bound = match format {
            ArchiveVersion::Rar50 | ArchiveVersion::Rar70 => PIPELINED_AHEAD,
            _ => AHEAD,
        };
        assert!(output.written > MEMBER, "{format}: {}", output.written);
        assert!(
            output.furthest_ahead <= bound,
            "{format}: read {} bytes ahead of the output",
            output.furthest_ahead
        );
    }
}

/// What a whole volume set has written so far, and how far the source got ahead of it.
#[derive(Clone, Default)]
struct SetProgress {
    written: Arc<AtomicUsize>,
    read: Arc<AtomicUsize>,
    furthest_ahead: Arc<AtomicUsize>,
}

/// One volume, seekable so its writer can patch a header behind the data.
struct Volume {
    position: u64,
    len: u64,
    set: SetProgress,
}

impl Write for Volume {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.position += bytes.len() as u64;
        // A patched header rewrites bytes already counted.
        if self.position > self.len {
            let grew = (self.position - self.len) as usize;
            self.len = self.position;
            let written = (self.set.written.fetch_add(grew, Ordering::Relaxed) + grew) as u64;
            if written > AHEAD {
                let read = self.set.read.load(Ordering::Relaxed) as u64;
                let ahead = read.saturating_sub(written) as usize;
                self.set.furthest_ahead.fetch_max(ahead, Ordering::Relaxed);
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for Volume {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.position = match to {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(delta) => self.len.saturating_add_signed(delta),
            SeekFrom::Current(delta) => self.position.saturating_add_signed(delta),
        };
        Ok(self.position)
    }
}

struct Volumes {
    set: SetProgress,
    started: usize,
}

impl rars::rar50::VolumeSink for Volumes {
    fn start_volume(&mut self, _index: u64) -> rars::Result<Box<dyn rars::rar50::VolumeOutput>> {
        self.started += 1;
        Ok(Box::new(Volume {
            position: 0,
            len: 0,
            set: self.set.clone(),
        }))
    }
}

#[test]
fn a_stored_volume_set_is_copied_through_in_every_legacy_format() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar40,
    ] {
        let set = SetProgress::default();
        let source = {
            let read = set.read.clone();
            EntrySource::from_opener(MEMBER, move || {
                read.store(0, Ordering::Relaxed);
                Ok(Box::new(Pattern {
                    pos: 0,
                    read: read.clone(),
                }))
            })
        };
        let mut builder = Builder::new(format).store(true).volume_size(Some(5 << 20));
        builder
            .add_source(b"member.bin".to_vec(), source, None, None)
            .unwrap();
        let mut volumes = Volumes {
            set: set.clone(),
            started: 0,
        };
        builder
            .write_volumes_to(&mut volumes, &WriterResources::default(), None)
            .unwrap();

        assert_eq!(volumes.started, 4, "{format}");
        let written = set.written.load(Ordering::Relaxed) as u64;
        assert!(written > MEMBER, "{format}: {written}");
        let ahead = set.furthest_ahead.load(Ordering::Relaxed);
        assert!(
            ahead as u64 <= AHEAD,
            "{format}: read {ahead} bytes ahead of the output"
        );
    }
}
