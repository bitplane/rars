//! Where a native spool keeps its bytes: memory while it is small and the
//! writer's budget has room, a temporary file once it is not.
//!
//! The memory is charged to the writer's workspace budget as it grows, and
//! only from what is free right then: growth never waits, and it stops while
//! any acquirer is waiting. A spool that outgrows [`MEMORY_SPOOL_LIMIT`], or
//! whose growth the budget refuses, moves its bytes to a temporary file and
//! carries on there. An acquirer that finds the budget full moves held spools
//! to disk as well (see [`MemoryBudget::reclaim`]), so spool memory never
//! keeps a job from being admitted, and a write never waits on it.

use super::{MemoryBudget, MemoryPermit};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// The most one spool holds in memory before it moves to a temporary file.
///
/// Small enough that a spool costs little of any budget, and that the copy
/// when one moves to disk is quick; large enough to cover the packed members,
/// encrypted copies and volume bodies of most small files.
pub(super) const MEMORY_SPOOL_LIMIT: usize = 4 * 1024 * 1024;

/// The first allocation of a spool held in memory. Capacity doubles from here.
const FIRST_CAPACITY: usize = 4096;

/// A spool's bytes, shared by its writer, its readers and the budget, which can
/// move them to disk from another thread.
pub(super) struct Backing {
    /// The bytes and their charge, while the spool is in memory.
    held: Option<Held>,
    /// The temporary file, once the spool is on disk.
    path: Option<PathBuf>,
    temp_dir: Option<Arc<PathBuf>>,
    /// Set when the spool is dropped, so its bytes are never moved to a file
    /// nobody would remove.
    closed: bool,
}

struct Held {
    bytes: Vec<u8>,
    /// Covers `bytes.capacity()`, and the old allocation too while it grows.
    permit: MemoryPermit,
}

pub(super) type SharedBacking = Arc<Mutex<Backing>>;

pub(super) fn lock(backing: &SharedBacking) -> MutexGuard<'_, Backing> {
    backing.lock().expect("spool backing lock poisoned")
}

impl Backing {
    /// A spool already on disk at `path`.
    pub(super) fn on_disk(path: PathBuf) -> SharedBacking {
        Arc::new(Mutex::new(Self {
            held: None,
            path: Some(path),
            temp_dir: None,
            closed: false,
        }))
    }

    /// An empty spool held in memory against `budget`, which can move it to
    /// disk in `temp_dir` when an acquirer needs the room.
    pub(super) fn in_memory(
        budget: &Arc<MemoryBudget>,
        temp_dir: Option<Arc<PathBuf>>,
    ) -> SharedBacking {
        let backing = Arc::new(Mutex::new(Self {
            held: Some(Held {
                bytes: Vec::new(),
                permit: MemoryPermit {
                    budget: Arc::clone(budget),
                    bytes: 0,
                },
            }),
            path: None,
            temp_dir,
            closed: false,
        }));
        budget.register_spool(&backing);
        backing
    }

    #[cfg(test)]
    pub(super) fn path_capacity(&self) -> usize {
        self.path.as_ref().map_or(0, PathBuf::capacity)
    }

    /// The budget this spool holds in memory.
    pub(super) fn held_bytes(&self) -> u64 {
        self.held.as_ref().map_or(0, |held| held.permit.bytes)
    }

    #[cfg(test)]
    pub(super) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Moves held bytes to a new temporary file and releases their charge.
    /// Returns the file, positioned at its end, or `None` if the bytes were
    /// not held.
    pub(super) fn spill(&mut self) -> io::Result<Option<File>> {
        let Some(held) = &self.held else {
            return Ok(None);
        };
        if self.closed {
            return Ok(None);
        }
        let directory = self
            .temp_dir
            .as_deref()
            .map_or(Path::new("."), PathBuf::as_path);
        let (path, mut file, ()) = crate::temp_file::create_with_sequence(
            directory,
            |_| Ok(()),
            crate::temp_file::next_sequence,
        )
        .map_err(io::Error::other)?;
        if let Err(error) = file.write_all(&held.bytes) {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        self.path = Some(path);
        self.held = None;
        Ok(Some(file))
    }

    /// Drops held bytes and stops any later move to disk; returns the file to
    /// remove, if the spool is on disk.
    pub(super) fn close(&mut self) -> Option<PathBuf> {
        self.closed = true;
        self.held = None;
        self.path.take()
    }
}

impl Held {
    /// Makes room for `end` bytes, or says the budget refused it.
    fn reserve(&mut self, end: usize) -> bool {
        let capacity = self.bytes.capacity();
        if end <= capacity {
            return true;
        }
        let target = capacity
            .saturating_mul(2)
            .clamp(FIRST_CAPACITY, MEMORY_SPOOL_LIMIT)
            .max(end);
        // The old allocation lives until the new one has its bytes.
        let Some(transient) = capacity.checked_add(target) else {
            return false;
        };
        if !self.permit.try_grow_for_spool(transient as u64) {
            return false;
        }
        let reserved = self
            .bytes
            .try_reserve_exact(target - self.bytes.len())
            .is_ok();
        self.permit.shrink_to(self.bytes.capacity() as u64);
        reserved
    }

    fn write_at(&mut self, pos: usize, buffer: &[u8]) {
        if self.bytes.len() < pos {
            self.bytes.resize(pos, 0);
        }
        let overlap = (self.bytes.len() - pos).min(buffer.len());
        self.bytes[pos..pos + overlap].copy_from_slice(&buffer[..overlap]);
        self.bytes.extend_from_slice(&buffer[overlap..]);
    }
}

/// One handle on a spool's bytes, with its own cursor.
pub(super) struct SpoolStore {
    backing: SharedBacking,
    file: Option<File>,
    pos: u64,
    writable: bool,
}

impl SpoolStore {
    pub(super) fn writer(backing: SharedBacking, file: Option<File>) -> Self {
        Self {
            backing,
            file,
            pos: 0,
            writable: true,
        }
    }

    /// A read-only handle from the start of the same bytes.
    pub(super) fn reader(backing: SharedBacking) -> Self {
        Self {
            backing,
            file: None,
            pos: 0,
            writable: false,
        }
    }

    pub(super) fn backing(&self) -> &SharedBacking {
        &self.backing
    }

    #[cfg(test)]
    pub(super) fn is_parked(&self) -> bool {
        self.file.is_none()
    }

    /// Swaps in `file` as the open handle, keeping the cursor.
    #[cfg(test)]
    pub(super) fn replace_file(&mut self, file: File) {
        self.file = Some(file);
    }

    /// Closes the file handle, if any; the cursor is kept.
    pub(super) fn park(&mut self) {
        self.file = None;
    }
}

/// Opens the spool's file at `pos` if no handle is open.
fn open<'f>(
    file: &'f mut Option<File>,
    backing: &Backing,
    pos: u64,
    writable: bool,
) -> io::Result<&'f mut File> {
    if file.is_none() {
        let path = backing
            .path
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "spool has been released"))?;
        let mut opened = File::options().read(true).write(writable).open(path)?;
        opened.seek(SeekFrom::Start(pos))?;
        *file = Some(opened);
    }
    Ok(file.as_mut().expect("spool file is open"))
}

impl Write for SpoolStore {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut backing = lock(&self.backing);
        if let Some(held) = &mut backing.held {
            let fits = usize::try_from(self.pos)
                .ok()
                .and_then(|pos| Some((pos, pos.checked_add(buffer.len())?)))
                .filter(|&(_, end)| end <= MEMORY_SPOOL_LIMIT && held.reserve(end));
            if let Some((pos, end)) = fits {
                held.write_at(pos, buffer);
                self.pos = end as u64;
                return Ok(buffer.len());
            }
            let mut file = backing.spill()?.expect("held bytes move to a file");
            file.seek(SeekFrom::Start(self.pos))?;
            self.file = Some(file);
        }
        let file = open(&mut self.file, &backing, self.pos, self.writable)?;
        let written = file.write(buffer)?;
        self.pos += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl Read for SpoolStore {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let backing = lock(&self.backing);
        if let Some(held) = &backing.held {
            let start = usize::try_from(self.pos)
                .unwrap_or(usize::MAX)
                .min(held.bytes.len());
            let count = (held.bytes.len() - start).min(buffer.len());
            buffer[..count].copy_from_slice(&held.bytes[start..start + count]);
            self.pos += count as u64;
            return Ok(count);
        }
        let file = open(&mut self.file, &backing, self.pos, self.writable)?;
        let read = file.read(buffer)?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for SpoolStore {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let backing = lock(&self.backing);
        if let Some(held) = &backing.held {
            let (base, offset) = match from {
                SeekFrom::Start(pos) => {
                    self.pos = pos;
                    return Ok(pos);
                }
                SeekFrom::End(offset) => (held.bytes.len() as u64, offset),
                SeekFrom::Current(offset) => (self.pos, offset),
            };
            self.pos = base.checked_add_signed(offset).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                )
            })?;
            return Ok(self.pos);
        }
        let file = open(&mut self.file, &backing, self.pos, self.writable)?;
        self.pos = file.seek(from)?;
        Ok(self.pos)
    }
}
