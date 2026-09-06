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
///
/// Reopening is not a snapshot: callers must keep the source stable for the
/// duration of a write. Writers check emitted stored data against the prepared
/// size and archive checksums. A mismatch fails the write, but a caller-provided
/// output stream can already contain partial data when the error is returned.
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

    /// Reserves what a member needs, or the whole budget if one member needs
    /// more than that.
    ///
    /// The RAR 1.3 to 4.x codecs compress a member as a unit, so there is no
    /// smaller piece to fall back to when one does not fit. Here the budget
    /// decides how many members are compressed at once rather than whether the
    /// job can run at all, and a member larger than the budget runs alone.
    pub(crate) fn acquire_serialising(&self, required: u64) -> MemoryPermit {
        self.budget.acquire(required.min(self.memory_limit))
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

/// Where a spool keeps its bytes.
///
/// A file on every real platform, which is the point: the RAR 5 writer spools
/// so that a member larger than the memory budget still gets written. Bare
/// WebAssembly has no filesystem, so there it is a buffer, and the budget stops
/// being a promise the writer can keep. Nothing else changes, because both
/// types are `Read + Write + Seek`.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
type SpoolStore = File;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
type SpoolStore = Cursor<Vec<u8>>;

pub(crate) struct Spool {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    path: PathBuf,
    file: Option<SpoolStore>,
    len: u64,
    pos: u64,
}

impl Spool {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
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
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                        len: 0,
                        pos: 0,
                    })
                }
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

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub(crate) fn create(_resources: &WriterResources) -> Result<Self> {
        SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            file: Some(Cursor::new(Vec::new())),
            len: 0,
            pos: 0,
        })
    }

    /// Allocate a spool whose handle is not retained while waiting for work.
    pub(crate) fn create_parked(resources: &WriterResources) -> Result<Self> {
        let mut spool = Self::create(resources)?;
        spool.park();
        Ok(spool)
    }

    /// Release the OS handle, retaining ownership of the file and its cursor.
    /// Bare WASM has no handle to release and must retain the in-memory bytes.
    pub(crate) fn park(&mut self) {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            self.file = None;
        }
    }

    fn file(&mut self) -> std::io::Result<&mut SpoolStore> {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        if self.file.is_none() {
            let mut file = File::options().read(true).write(true).open(&self.path)?;
            file.seek(SeekFrom::Start(self.pos))?;
            self.file = Some(file);
        }
        Ok(self.file.as_mut().expect("spool backing store is present"))
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn rewind(&mut self) -> Result<()> {
        self.seek_to(0)
    }

    /// Moves the read/write cursor to an absolute offset.
    pub(crate) fn seek_to(&mut self, pos: u64) -> Result<()> {
        self.seek(SeekFrom::Start(pos))?;
        Ok(())
    }

    pub(crate) fn copy_to(&mut self, output: &mut dyn Write) -> Result<u64> {
        let result = (|| {
            self.rewind()?;
            Ok(std::io::copy(self, output)?)
        })();
        self.park();
        result
    }

    /// Copies `len` bytes starting at `start` to `output`, which is how a
    /// volume set takes one fragment of a member at a time.
    pub(crate) fn copy_range_to(
        &mut self,
        start: u64,
        len: u64,
        output: &mut dyn Write,
    ) -> Result<u64> {
        let result = (|| {
            self.seek_to(start)?;
            let copied = std::io::copy(&mut self.take(len), output)?;
            if copied != len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "spooled range is shorter than expected",
                )
                .into());
            }
            Ok(copied)
        })();
        self.park();
        result
    }
}

impl Write for Spool {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.file()?.write(buffer)?;
        self.pos = self.pos.saturating_add(written as u64);
        self.len = self.len.max(self.pos);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file()?.flush()
    }
}

impl Read for Spool {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.file()?.read(buffer)?;
        self.pos = self.pos.saturating_add(read as u64);
        Ok(read)
    }
}

impl Seek for Spool {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.pos = self.file()?.seek(from)?;
        Ok(self.pos)
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
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
    fn spool_tracks_length_across_seeks_and_overwrites() {
        let scratch = crate::scratch::case("rars-spool");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let mut spool = Spool::create(&resources).unwrap();
        spool.write_all(b"0123456789").unwrap();
        assert_eq!(spool.len(), 10);

        // Rewriting earlier bytes must not extend the spool.
        spool.seek_to(4).unwrap();
        spool.write_all(b"ab").unwrap();
        assert_eq!(spool.len(), 10);

        // Writing past the end does extend it.
        spool.seek_to(9).unwrap();
        spool.write_all(b"xyz").unwrap();
        assert_eq!(spool.len(), 12);

        let mut copied = Vec::new();
        spool.copy_to(&mut copied).unwrap();
        assert_eq!(copied, b"0123ab678xyz");
    }

    #[test]
    fn spool_reads_from_the_seeked_position() {
        let scratch = crate::scratch::case("rars-spool");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let mut spool = Spool::create(&resources).unwrap();
        spool.write_all(b"abcdefgh").unwrap();
        spool.seek(SeekFrom::Start(3)).unwrap();

        let mut buffer = [0u8; 4];
        spool.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"defg");
        assert_eq!(spool.stream_position().unwrap(), 7);
    }

    #[test]
    fn parked_spools_preserve_cursor_and_release_handles_after_copy_errors() {
        let scratch = crate::scratch::case("parked-spool");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let mut spool = Spool::create_parked(&resources).unwrap();
        spool.write_all(b"abcdef").unwrap();
        spool.seek_to(2).unwrap();
        spool.park();
        spool.write_all(b"XY").unwrap();
        spool.park();
        spool.write_all(b"Z").unwrap();
        assert_eq!(spool.len(), 6);
        let mut bytes = Vec::new();
        spool.copy_range_to(1, 4, &mut bytes).unwrap();
        assert_eq!(bytes, b"bXYZ");
        struct FailingSink;
        impl Write for FailingSink {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(spool.copy_to(&mut FailingSink).is_err());
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        assert!(spool.file.is_none());
        assert!(spool.copy_range_to(0, 7, &mut Vec::new()).is_err());
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        assert!(spool.file.is_none());
        bytes.clear();
        spool.copy_to(&mut bytes).unwrap();
        assert_eq!(bytes, b"abXYZf");
        drop(spool);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
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
