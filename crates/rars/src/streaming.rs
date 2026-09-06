use crate::{Error, Result};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// A shared, one-way cancellation signal for RAR5/7 streaming writes.
///
/// Clone the token for another thread, or cancel it from an input/output callback.
/// Cancellation is cooperative: it is checked between chunks and during resource
/// waits; it cannot interrupt a caller's blocked I/O or an individual codec step.
#[derive(Clone, Debug, Default)]
pub struct WriteCancellation(Arc<AtomicBool>);

impl WriteCancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
/// Shared compression-workspace and temporary-file policy for streaming writers.
///
/// Native RAR5 writers retain packed payloads on disk and bound active input and
/// spool handles by compression concurrency, rather than the archive entry count.
/// The workspace limit is not a total process-RAM or temporary-disk quota. On bare
/// WebAssembly (`wasm32-unknown-unknown`), spools stay in memory and their retained
/// payloads are additional to this limit.
pub struct WriterResources {
    memory_limit: u64,
    temp_dir: Option<PathBuf>,
    budget: Arc<MemoryBudget>,
    cancellation: Option<WriteCancellation>,
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
            cancellation: None,
        }
    }

    /// Place temporary spools in this existing directory (default: the current
    /// directory). Use a directory whose contents untrusted users cannot replace:
    /// idle spools are closed and later reopened by path.
    ///
    /// Spools may contain unencrypted compressed data even for encrypted output.
    /// Files are created exclusively, with owner-only access on Unix (0600 before
    /// applying the umask); other platforms use inherited directory permissions.
    /// Dropping a spool closes its handle before attempting removal, including on
    /// errors and unwind. Removal is best-effort, not secure erasure, and process
    /// termination can leave files behind. Bare WASM ignores this setting.
    pub fn with_temp_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.temp_dir = Some(path.into());
        self
    }

    /// Attach a cancellation token to RAR5/7 streaming writes using this policy.
    /// The token works without a progress callback. Cancellation returns
    /// [`Error::Cancelled`]; a direct output sink may already contain partial data.
    /// Legacy buffered writers do not use this token.
    pub fn with_cancellation(mut self, cancellation: WriteCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub(crate) fn has_cancellation(&self) -> bool {
        self.cancellation.is_some()
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(WriteCancellation::is_cancelled)
    }

    pub fn memory_limit(&self) -> u64 {
        self.memory_limit
    }

    pub fn temp_dir(&self) -> Option<&Path> {
        self.temp_dir.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn acquire(&self, required: u64, dictionary_size: u64) -> Result<MemoryPermit> {
        self.acquire_cancellable(required, dictionary_size, &|| false)
    }

    pub(crate) fn acquire_cancellable(
        &self,
        required: u64,
        dictionary_size: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<MemoryPermit> {
        let cancelled = || self.is_cancelled() || cancelled();
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if required > self.memory_limit {
            return Err(Error::MemoryLimitExceeded {
                limit: self.memory_limit,
                required,
                dictionary_size,
            });
        }
        self.budget.acquire_cancellable(required, &cancelled)
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

    fn acquire_cancellable(
        self: &Arc<Self>,
        bytes: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<MemoryPermit> {
        // Call user cancellation code outside the budget mutex: a callback can
        // release a permit, and must not deadlock with its own admission wait.
        loop {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            let mut used = self.used.lock().expect("memory budget lock poisoned");
            if self.limit.saturating_sub(*used) >= bytes {
                *used += bytes;
                return Ok(MemoryPermit {
                    budget: Arc::clone(self),
                    bytes,
                });
            }
            // Tokens and progress callbacks need not notify this condition
            // variable, so wake periodically even while all permits are held.
            drop(
                self.changed
                    .wait_timeout(used, std::time::Duration::from_millis(25))
                    .expect("memory budget lock poisoned while waiting"),
            );
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

/// Owns a temporary payload until drop; parking releases only its handle.
/// Writes are unbuffered, so parking requires no flush and preserves the cursor.
/// The file must live until assembly finishes, even when no handle is open.
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
            let mut options = File::options();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // Encryption happens after compression; the temporary payload
                // must not inherit the usual world-readable creation mode.
                options.mode(0o600);
            }
            match options.open(&path) {
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
        self.file = None;
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

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn spool_cleanup_owns_both_active_and_parked_files() {
        let scratch = crate::scratch::case("spool-cleanup");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        for parked in [false, true] {
            let mut spool = Spool::create(&resources).unwrap();
            spool.write_all(b"private compressed payload").unwrap();
            let path = spool.path.clone();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                    0
                );
            }
            if parked {
                spool.park();
            }
            assert!(path.exists());
            drop(spool);
            assert!(!path.exists());
        }
        let unwind = std::panic::catch_unwind(|| {
            let mut spool = Spool::create(&resources).unwrap();
            spool.write_all(b"unfinished").unwrap();
            panic!("injected failure");
        });
        assert!(unwind.is_err());
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn admission_waits_can_be_cancelled_without_releasing_the_held_permit() {
        use std::sync::mpsc;
        use std::time::Duration;
        for via_callback in [false, true] {
            let cancel = WriteCancellation::new();
            let resources = WriterResources::new(100).with_cancellation(if via_callback {
                WriteCancellation::new()
            } else {
                cancel.clone()
            });
            let held = resources.acquire(100, 0).unwrap();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let callback_cancel = cancel.clone();
            let worker = std::thread::spawn(move || {
                let polls = AtomicU64::new(0);
                let result = resources.acquire_cancellable(1, 0, &|| {
                    // Admission checks once before entering the budget and
                    // again before locking. The third poll proves a timed
                    // wait occurred while the permit was still held.
                    if polls.fetch_add(1, Ordering::Relaxed) >= 2 {
                        let _ = entered_tx.send(());
                    }
                    via_callback && callback_cancel.is_cancelled()
                });
                done_tx.send(result.map(|_| ())).unwrap();
                resources
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            cancel.cancel();
            assert_eq!(
                done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                Err(Error::Cancelled)
            );
            let resources = worker.join().unwrap();
            assert_eq!(*resources.budget.used.lock().unwrap(), 100);
            drop(held);
            assert_eq!(*resources.budget.used.lock().unwrap(), 0);
        }
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
