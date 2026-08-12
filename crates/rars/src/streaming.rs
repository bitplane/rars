use crate::{Error, Result};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// Default aggregate compression workspace budget (256 MiB).
pub const DEFAULT_WRITER_MEMORY_LIMIT: u64 = 256 * 1024 * 1024;

/// A rewindable input reader used by streaming archive writers.
pub trait EntryReader: Read + Seek + Send {}
impl<T: Read + Seek + Send> EntryReader for T {}

trait SourceFactory: Send + Sync {
    fn len(&self) -> Result<u64>;
    fn open(&self) -> Result<Box<dyn EntryReader>>;
}

#[derive(Clone)]
/// A reopenable byte source for an archive member.
pub struct EntrySource(Arc<dyn SourceFactory>);

impl fmt::Debug for EntrySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntrySource")
            .field("len", &self.len().ok())
            .finish_non_exhaustive()
    }
}

impl EntrySource {
    pub fn from_bytes(data: impl Into<Arc<[u8]>>) -> Self {
        Self(Arc::new(MemorySource(data.into())))
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self(Arc::new(PathSource(path.into())))
    }

    pub fn from_opener<F>(len: u64, open: F) -> Self
    where
        F: Fn() -> Result<Box<dyn EntryReader>> + Send + Sync + 'static,
    {
        Self(Arc::new(OpenerSource {
            len,
            open: Arc::new(open),
        }))
    }

    pub fn len(&self) -> Result<u64> {
        self.0.len()
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|len| len == 0)
    }

    pub fn open(&self) -> Result<Box<dyn EntryReader>> {
        self.0.open()
    }
}

struct MemorySource(Arc<[u8]>);

impl SourceFactory for MemorySource {
    fn len(&self) -> Result<u64> {
        Ok(self.0.len() as u64)
    }

    fn open(&self) -> Result<Box<dyn EntryReader>> {
        Ok(Box::new(Cursor::new(Arc::clone(&self.0))))
    }
}

struct PathSource(PathBuf);

struct OpenerSource {
    len: u64,
    open: Arc<dyn Fn() -> Result<Box<dyn EntryReader>> + Send + Sync>,
}

impl SourceFactory for OpenerSource {
    fn len(&self) -> Result<u64> {
        Ok(self.len)
    }

    fn open(&self) -> Result<Box<dyn EntryReader>> {
        (self.open)()
    }
}

impl SourceFactory for PathSource {
    fn len(&self) -> Result<u64> {
        Ok(std::fs::metadata(&self.0)?.len())
    }

    fn open(&self) -> Result<Box<dyn EntryReader>> {
        Ok(Box::new(File::open(&self.0)?))
    }
}

#[derive(Clone, Debug)]
/// Shared memory and temporary-file policy for streaming writers.
pub struct WriterResources {
    memory_limit: u64,
    temp_dir: Option<PathBuf>,
    budget: Arc<MemoryBudget>,
}

impl Default for WriterResources {
    fn default() -> Self {
        Self::new(DEFAULT_WRITER_MEMORY_LIMIT)
    }
}

impl WriterResources {
    pub fn new(memory_limit: u64) -> Self {
        Self {
            memory_limit,
            temp_dir: None,
            budget: Arc::new(MemoryBudget::new(memory_limit)),
        }
    }

    pub fn with_temp_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.temp_dir = Some(path.into());
        self
    }

    pub fn memory_limit(&self) -> u64 {
        self.memory_limit
    }

    pub fn temp_dir(&self) -> Option<&Path> {
        self.temp_dir.as_deref()
    }

    pub(crate) fn acquire(&self, required: u64, dictionary_size: u64) -> Result<MemoryPermit> {
        if required > self.memory_limit {
            return Err(Error::MemoryLimitExceeded {
                limit: self.memory_limit,
                required,
                dictionary_size,
            });
        }
        Ok(self.budget.acquire(required))
    }
}

#[derive(Debug)]
struct MemoryBudget {
    limit: u64,
    used: Mutex<u64>,
    changed: Condvar,
}

impl MemoryBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            used: Mutex::new(0),
            changed: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>, bytes: u64) -> MemoryPermit {
        let mut used = self.used.lock().expect("memory budget lock poisoned");
        while self.limit.saturating_sub(*used) < bytes {
            used = self
                .changed
                .wait(used)
                .expect("memory budget lock poisoned while waiting");
        }
        *used += bytes;
        MemoryPermit {
            budget: Arc::clone(self),
            bytes,
        }
    }
}

pub(crate) struct MemoryPermit {
    budget: Arc<MemoryBudget>,
    bytes: u64,
}

static SPOOL_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Spool {
    path: PathBuf,
    file: File,
    len: u64,
}

impl Spool {
    pub(crate) fn create(resources: &WriterResources) -> Result<Self> {
        let directory = resources.temp_dir().unwrap_or_else(|| Path::new("."));
        for _ in 0..128 {
            let sequence = SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                ".rars-spool-{}-{sequence:016x}",
                std::process::id()
            ));
            match File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file, len: 0 }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique rars spool file",
        )
        .into())
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn rewind(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    pub(crate) fn copy_to(&mut self, output: &mut dyn Write) -> Result<u64> {
        self.rewind()?;
        Ok(std::io::copy(&mut self.file, output)?)
    }
}

impl Write for Spool {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.file.write(buffer)?;
        self.len = self.len.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Read for Spool {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        let mut used = self
            .budget
            .used
            .lock()
            .expect("memory budget lock poisoned");
        *used = used.saturating_sub(self.bytes);
        self.budget.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sources_are_rewindable_without_copying() {
        let source = EntrySource::from_bytes(Arc::<[u8]>::from(&b"hello"[..]));
        let mut first = source.open().unwrap();
        let mut second = source.open().unwrap();
        let mut a = Vec::new();
        let mut b = Vec::new();
        first.read_to_end(&mut a).unwrap();
        second.read_to_end(&mut b).unwrap();
        assert_eq!(a, b"hello");
        assert_eq!(b, b"hello");
    }

    #[test]
    fn oversized_workspace_is_rejected_before_waiting() {
        let resources = WriterResources::new(1024);
        assert!(matches!(
            resources.acquire(1025, 512),
            Err(Error::MemoryLimitExceeded { .. })
        ));
    }
}
