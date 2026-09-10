use crate::{Error, Result};
#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
mod memory_spool;
pub(crate) mod output;
pub(crate) mod preparation;
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

pub(crate) trait SourceFactory: Send + Sync {
    fn release(&self) {}
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
    pub(crate) fn from_factory(factory: impl SourceFactory + 'static) -> Self {
        Self(Arc::new(factory))
    }

    /// Release a session-owned payload once this write will never reopen it.
    pub(crate) fn release(&self) {
        self.0.release();
    }

    pub fn from_bytes(data: impl Into<Arc<[u8]>>) -> Self {
        Self::from_factory(MemorySource(data.into()))
    }

    pub(crate) fn copy_for_writer(data: &[u8], resources: &WriterResources) -> Result<Self> {
        let Some(mut charge) = resources.execution_charge() else {
            return Ok(Self::from_bytes(Arc::<[u8]>::from(data)));
        };
        let bytes = data
            .len()
            .checked_add(std::mem::size_of::<WriterMemoryData>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<WriterMemorySource>()))
            .ok_or(Error::InvalidArgument("writer source capacity overflows"))?;
        charge.grow_to(bytes as u64)?;
        let data = Arc::new(WriterMemoryData {
            bytes: data.to_vec(),
            _charge: charge,
        });
        Ok(Self::from_factory(WriterMemorySource {
            data,
            resources: resources.clone(),
        }))
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self::from_factory(PathSource(path.into()))
    }

    pub fn from_opener<F>(len: u64, open: F) -> Self
    where
        F: Fn() -> Result<Box<dyn EntryReader>> + Send + Sync + 'static,
    {
        Self::from_factory(OpenerSource {
            len,
            open: Arc::new(open),
        })
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

// The shared owner keeps both its bytes and its charge alive if a reader
// outlives the converted entry. Reader boxes get separate capacity charges.
struct WriterMemoryData {
    bytes: Vec<u8>,
    _charge: CapacityCharge,
}
struct WriterMemorySource {
    data: Arc<WriterMemoryData>,
    resources: WriterResources,
}
struct WriterMemoryReader {
    data: Arc<WriterMemoryData>,
    position: u64,
    _charge: Option<CapacityCharge>,
}
impl SourceFactory for WriterMemorySource {
    fn len(&self) -> Result<u64> {
        Ok(self.data.bytes.len() as u64)
    }
    fn open(&self) -> Result<Box<dyn EntryReader>> {
        let mut charge = self.resources.execution_charge();
        if let Some(charge) = &mut charge {
            charge.grow_to(std::mem::size_of::<WriterMemoryReader>() as u64)?;
        }
        Ok(Box::new(WriterMemoryReader {
            data: self.data.clone(),
            position: 0,
            _charge: charge,
        }))
    }
}
impl Read for WriterMemoryReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut cursor = Cursor::new(&self.data.bytes);
        cursor.set_position(self.position);
        let count = cursor.read(out)?;
        self.position = cursor.position();
        Ok(count)
    }
}
impl Seek for WriterMemoryReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let mut cursor = Cursor::new(&self.data.bytes);
        cursor.set_position(self.position);
        self.position = cursor.seek(from)?;
        Ok(self.position)
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

/// A shared, one-way cancellation signal for archive writes.
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
/// payloads are additional to this limit. `with_max_spool_bytes` separately caps
/// logical spool contents on both backends. `with_max_spool_memory_bytes` caps
/// bare-WASM spool payload and index capacity, excluding other writer memory.
pub struct WriterResources {
    memory_limit: u64,
    temp_dir: Option<Arc<PathBuf>>,
    budget: Arc<MemoryBudget>,
    spool_budget: Option<Arc<StorageBudget>>,
    spool_memory_budget: Option<Arc<StorageBudget>>,
    prepared_header_budget: Option<Arc<StorageBudget>>,
    preparation_budget: Option<Arc<StorageBudget>>,
    cancellation: Option<WriteCancellation>,
    pub(crate) execution: Option<crate::codec::workspace::Limited>,
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
            spool_budget: None,
            spool_memory_budget: None,
            prepared_header_budget: None,
            preparation_budget: None,
            cancellation: None,
            execution: None,
        }
    }

    /// Set a hard ceiling on managed writer allocation capacity for RAR5/7.
    /// Includes active work, retained spools/headers, conversion and owned output.
    /// Caller-owned inputs and external sinks, allocator/runtime overhead, stacks
    /// and OS memory are excluded. This is not a process-RAM limit.
    /// Legacy writers refuse this policy. The estimated workspace policy remains
    /// independent. Configure before execution; clones share the new ledger.
    pub fn with_max_memory_bytes(mut self, limit: u64) -> Self {
        self.execution = Some(crate::codec::workspace::Allowance::limited(limit));
        self
    }

    pub fn max_memory_bytes(&self) -> Option<u64> {
        self.execution
            .as_ref()
            .map(crate::codec::workspace::Limited::limit)
    }

    /// Live managed capacity plus reservations for admitted workers.
    pub fn managed_memory_in_use(&self) -> u64 {
        self.execution
            .as_ref()
            .map_or(0, crate::codec::workspace::Limited::used)
    }

    pub(crate) fn execution_charge(&self) -> Option<CapacityCharge> {
        CapacityCharge::new(self, &None)
    }

    /// Cap the sum of live logical spool lengths, including reserved growth.
    /// Native spools use files; bare-WASM spools use memory. This does not cap
    /// filesystem allocation, Vec capacity, codec workspace or final output.
    /// Zero allows empty spools only. Growth fails immediately rather than waiting.
    ///
    /// Configuring this creates a fresh quota group; subsequent clones share it.
    /// Configure before dispatching work. Parking a spool or returning from a
    /// write does not release storage still owned by an EntrySource or reader.
    /// Failed native cleanup retains its charge conservatively in this group.
    pub fn with_max_spool_bytes(mut self, limit: u64) -> Self {
        self.spool_budget = Some(Arc::new(StorageBudget {
            resource: StorageResource::LogicalBytes,
            limit,
            used: Mutex::new(0),
        }));
        self
    }

    /// The optional logical spool quota, independent of `memory_limit()`.
    pub fn max_spool_bytes(&self) -> Option<u64> {
        self.spool_budget.as_ref().map(|budget| budget.limit)
    }

    /// Cap shared in-memory spool payload and index capacity on bare WASM.
    /// Bounded spools allocate zeroed 4096-byte blocks and a boxed index. Growth
    /// reserves both old and replacement indexes before allocation. Allocator
    /// overhead, codec workspace and output are not included.
    /// This is not an aggregate managed-memory or process-RAM ceiling.
    ///
    /// Native file spools have no in-memory payload charge. The default remains
    /// an unbounded Vec backend on WASM; zero permits only empty memory spools.
    /// Configuring creates a fresh group, shared by subsequent resource clones.
    /// Logical spool lengths remain independently limited by `max_spool_bytes`.
    pub fn with_max_spool_memory_bytes(mut self, limit: u64) -> Self {
        self.spool_memory_budget = Some(Arc::new(StorageBudget {
            resource: StorageResource::PayloadMemory,
            limit,
            used: Mutex::new(0),
        }));
        self
    }

    /// The optional memory-spool payload and index capacity quota.
    pub fn max_spool_memory_bytes(&self) -> Option<u64> {
        self.spool_memory_budget.as_ref().map(|budget| budget.limit)
    }

    /// Cap final RAR5/7 member and service header images retained by single-archive
    /// preparation. Counts encryption IVs and padding, with admission before
    /// allocation. Serializer scratch, main/end headers, volume fragment headers,
    /// legacy headers and coordinator records are outside this quota.
    /// Defaults to unlimited. Configuring creates a fresh group shared by clones.
    pub fn with_max_prepared_header_bytes(mut self, limit: u64) -> Self {
        self.prepared_header_budget = Some(Arc::new(StorageBudget {
            resource: StorageResource::PreparedHeaders,
            limit,
            used: Mutex::new(0),
        }));
        self
    }

    /// The optional quota for retained RAR5/7 prepared header images.
    pub fn max_prepared_header_bytes(&self) -> Option<u64> {
        self.prepared_header_budget
            .as_ref()
            .map(|budget| budget.limit)
    }

    pub(crate) fn reserve_prepared_header(&self, bytes: u64) -> Result<Option<StorageCharge>> {
        self.prepared_header_budget
            .as_ref()
            .map(|budget| {
                let mut charge = StorageCharge {
                    budget: budget.clone(),
                    bytes: 0,
                };
                charge.grow_to(bytes)?;
                Ok(charge)
            })
            .transpose()
    }

    /// Bound RAR5/7 engine header scratch, images, descriptor arrays and boxed
    /// preparation state, including volume and recovery headers. Capacity is
    /// reserved before allocation, including old/replacement overlap on growth.
    /// Configuring creates a new ledger shared by resource clones; default is
    /// unlimited. Legacy writers explicitly refuse this policy.
    ///
    /// Coordinator plan/job/result descriptor arrays also count; their pointed-to
    /// input/history and codec payload buffers do not. Codec/KDF/recovery workspace,
    /// input conversion, source/sink callbacks, collectors, diagnostics and allocator
    /// overhead are outside this quota. This is not a total writer-memory cap.
    pub fn with_max_preparation_bytes(mut self, limit: u64) -> Self {
        self.preparation_budget = Some(Arc::new(StorageBudget {
            resource: StorageResource::Preparation,
            limit,
            used: Mutex::new(0),
        }));
        self
    }

    /// The optional shared RAR5/7 engine preparation capacity limit.
    pub fn max_preparation_bytes(&self) -> Option<u64> {
        self.preparation_budget.as_ref().map(|budget| budget.limit)
    }

    pub(crate) fn preparation_charge(&self) -> Option<CapacityCharge> {
        CapacityCharge::new(self, &self.preparation_budget)
    }

    #[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
    fn spool_capacity_charge(&self) -> Option<CapacityCharge> {
        CapacityCharge::new(self, &self.spool_memory_budget)
    }

    // A coordinator supplies a child scope to its admitted workers.
    pub(crate) fn with_execution_allowance(
        mut self,
        allowance: crate::codec::workspace::Limited,
    ) -> Self {
        self.execution = Some(allowance);
        self
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
        self.temp_dir = Some(Arc::new(path.into()));
        self
    }

    /// Attach a cancellation token to archive writes using this policy.
    /// The token works without a progress callback. Cancellation returns
    /// [`Error::Cancelled`]; a direct output sink may already contain partial data.
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
        self.temp_dir.as_deref().map(PathBuf::as_path)
    }

    #[cfg(test)]
    pub(crate) fn workspace_in_use(&self) -> u64 {
        *self.budget.used.lock().unwrap()
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
    pub(crate) fn acquire_serialising_cancellable(
        &self,
        required: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<MemoryPermit> {
        self.budget
            .acquire_cancellable(required.min(self.memory_limit), &|| {
                self.is_cancelled() || cancelled()
            })
    }
}

/// Live storage and reservations share one ledger across resource clones.
/// No waiter can make progress by waiting for spools it must itself retain.
#[derive(Debug, Clone, Copy)]
enum StorageResource {
    LogicalBytes,
    PayloadMemory,
    PreparedHeaders,
    Preparation,
}

#[derive(Debug)]
struct StorageBudget {
    resource: StorageResource,
    limit: u64,
    used: Mutex<u64>,
}

#[derive(Debug)]
pub(crate) struct StorageCharge {
    budget: Arc<StorageBudget>,
    bytes: u64,
}

impl StorageCharge {
    fn new(resources: &WriterResources) -> Option<Self> {
        resources.spool_budget.as_ref().map(|budget| Self {
            budget: budget.clone(),
            bytes: 0,
        })
    }

    pub(crate) fn grow_to(&mut self, bytes: u64) -> Result<()> {
        let growth = bytes.saturating_sub(self.bytes);
        if growth == 0 {
            return Ok(());
        }
        let mut used = self.budget.used.lock().expect("spool budget lock poisoned");
        let required = used.checked_add(growth);
        if required.is_none_or(|required| required > self.budget.limit) {
            let required = required.unwrap_or(u64::MAX);
            return Err(match self.budget.resource {
                StorageResource::LogicalBytes => Error::WriterSpoolLimitExceeded {
                    limit: self.budget.limit,
                    required,
                    used: *used,
                },
                StorageResource::Preparation => Error::WriterPreparationLimitExceeded {
                    limit: self.budget.limit,
                    required,
                    used: *used,
                },
                StorageResource::PreparedHeaders => Error::WriterPreparedHeaderLimitExceeded {
                    limit: self.budget.limit,
                    required,
                    used: *used,
                },
                StorageResource::PayloadMemory => Error::WriterSpoolMemoryLimitExceeded {
                    limit: self.budget.limit,
                    required,
                    used: *used,
                },
            });
        }
        *used = required.unwrap();
        self.bytes = bytes;
        Ok(())
    }

    fn shrink_to(&mut self, bytes: u64) {
        let released = self.bytes - bytes;
        if released != 0 {
            let mut used = self.budget.used.lock().expect("spool budget lock poisoned");
            *used -= released;
            self.bytes = bytes;
        }
    }
}

impl Drop for StorageCharge {
    fn drop(&mut self) {
        self.shrink_to(0);
    }
}

/// A capacity owner can satisfy its existing class quota and an execution
/// reservation together. Failed admission rolls both ledgers back.
#[derive(Debug)]
pub(crate) enum CapacityCharge {
    Storage(StorageCharge),
    Execution {
        storage: Option<StorageCharge>,
        charge: crate::codec::workspace::Charge,
    },
}
impl CapacityCharge {
    fn new(_resources: &WriterResources, budget: &Option<Arc<StorageBudget>>) -> Option<Self> {
        let storage = budget.as_ref().map(|budget| StorageCharge {
            budget: budget.clone(),
            bytes: 0,
        });
        if let Some(allowance) = &_resources.execution {
            return Some(Self::Execution {
                storage,
                charge: crate::codec::workspace::Budget::charge(allowance),
            });
        }
        storage.map(Self::Storage)
    }
    fn bytes(&self) -> u64 {
        match self {
            Self::Storage(storage) => storage.bytes,
            Self::Execution { charge, .. } => charge.bytes(),
        }
    }
    pub(crate) fn grow_to(&mut self, bytes: u64) -> Result<()> {
        if bytes <= self.bytes() {
            return Ok(());
        }
        match self {
            Self::Storage(storage) => storage.grow_to(bytes),
            Self::Execution { storage, charge } => {
                use crate::codec::workspace::{Budget, Limited};
                let old = charge.bytes();
                Limited::resize(charge, bytes)?;
                if let Some(storage) = storage {
                    if let Err(error) = storage.grow_to(bytes) {
                        Limited::resize(charge, old).expect("rolling back capacity cannot fail");
                        return Err(error);
                    }
                }
                Ok(())
            }
        }
    }
    fn shrink_to(&mut self, bytes: u64) {
        match self {
            Self::Storage(storage) => storage.shrink_to(bytes),
            Self::Execution { storage, charge } => {
                use crate::codec::workspace::{Budget, Limited};
                if let Some(storage) = storage {
                    storage.shrink_to(bytes);
                }
                Limited::resize(charge, bytes).expect("releasing capacity cannot fail");
            }
        }
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
/// covering their retained storage. The optional logical spool quota applies
/// to both backends, independently of Vec capacity. Both are `Read + Write + Seek`.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
type SpoolStore = File;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
type SpoolStore = memory_spool::MemorySpool;

/// Owns a temporary payload until drop; parking releases only its handle.
/// Writes are unbuffered, so parking requires no flush and preserves the cursor.
/// The file must live until assembly finishes, even when no handle is open.
pub(crate) struct Spool {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    path: PathBuf,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    _path_charge: Option<CapacityCharge>,
    file: Option<SpoolStore>,
    len: u64,
    pos: u64,
    charge: Option<StorageCharge>,
}

impl Spool {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn create(resources: &WriterResources) -> Result<Self> {
        let directory = resources.temp_dir().unwrap_or_else(|| Path::new("."));
        for _ in 0..128 {
            let sequence = SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let mut name = [0u8; 64];
            let mut name_writer = std::io::Cursor::new(&mut name[..]);
            write!(
                name_writer,
                ".rars-spool-{}-{sequence:016x}",
                std::process::id()
            )?;
            let name_len = name_writer.position() as usize;
            let name = std::str::from_utf8(&name[..name_len]).expect("ASCII spool name");
            let capacity = directory
                .as_os_str()
                .len()
                .checked_add(1 + name_len)
                .ok_or(Error::InvalidArgument("spool path capacity overflows"))?;
            let mut path_charge = CapacityCharge::new(resources, &None);
            if let Some(charge) = &mut path_charge {
                charge.grow_to(capacity as u64)?;
            }
            let mut path = PathBuf::with_capacity(capacity);
            path.push(directory);
            path.push(name);
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
                        _path_charge: path_charge,
                        file: Some(file),
                        len: 0,
                        pos: 0,
                        charge: StorageCharge::new(resources),
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
    pub(crate) fn create(resources: &WriterResources) -> Result<Self> {
        SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            file: Some(memory_spool::MemorySpool::new(resources)),
            len: 0,
            pos: 0,
            charge: StorageCharge::new(resources),
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

impl Spool {
    // Keep reservation/reconciliation identical for native and memory stores.
    // The operation also permits deterministic short-write regression tests.
    fn write_with(
        &mut self,
        buffer: &[u8],
        write: impl FnOnce(&mut SpoolStore, &[u8]) -> std::io::Result<usize>,
    ) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let end = self.pos.checked_add(buffer.len() as u64).ok_or_else(|| {
            std::io::Error::other(Error::InvalidArgument("spool length overflows u64"))
        })?;
        if let Some(charge) = &mut self.charge {
            charge
                .grow_to(self.len.max(end))
                .map_err(std::io::Error::other)?;
        }
        // Keep the reservation while the backing store grows. Release only the
        // unwritten allowance on errors or short writes; overwrites cost nothing.
        let result = self.file().and_then(|file| write(file, buffer));
        match result {
            Ok(written) if written != 0 => {
                self.pos += written as u64;
                self.len = self.len.max(self.pos);
            }
            _ => {}
        }
        if let Some(charge) = &mut self.charge {
            charge.shrink_to(self.len);
        }
        result
    }
}

impl Write for Spool {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.write_with(buffer, |file, bytes| file.write(bytes))
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

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Spool {
    pub(crate) fn into_source(mut self) -> EntrySource {
        self.park();
        let owner = Arc::new(self);
        EntrySource::from_opener(owner.len(), move || {
            Ok(Box::new(SpoolReader {
                file: std::fs::File::open(&owner.path)?,
                _owner: owner.clone(),
            }))
        })
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
struct SpoolReader {
    file: std::fs::File,
    _owner: Arc<Spool>,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Read for SpoolReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Seek for SpoolReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(from)
    }
}

impl Seek for Spool {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.pos = self.file()?.seek(from)?;
        Ok(self.pos)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        self.file = None;
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                // The backing file may still occupy storage. Keep that debt in
                // the shared quota group instead of admitting replacement bytes.
                if let Some(charge) = &mut self.charge {
                    charge.bytes = 0;
                }
            }
        }
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
    #[test]
    fn writer_memory_reader_retains_payload_after_source_drop() {
        use super::*;
        let resources = WriterResources::default().with_max_memory_bytes(8192);
        let source = EntrySource::copy_for_writer(&[42; 4096], &resources).unwrap();
        let retained = resources.managed_memory_in_use();
        assert!(retained >= 4096);
        let mut reader = source.open().unwrap();
        drop(source);
        assert!(resources.managed_memory_in_use() > retained);
        let mut bytes = [0; 4096];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [42; 4096]);
        drop(reader);
        assert_eq!(resources.managed_memory_in_use(), 0);
    }

    use super::*;
    fn spool_used(resources: &WriterResources) -> u64 {
        *resources
            .spool_budget
            .as_ref()
            .unwrap()
            .used
            .lock()
            .unwrap()
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn spool_path_capacity_survives_parking_and_refuses_before_file_creation() {
        let root = crate::scratch::case("spool-path-capacity");
        let limited = crate::codec::workspace::Allowance::limited(1);
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_execution_allowance(limited.clone());
        assert_eq!(
            Spool::create(&resources).err().unwrap().kind(),
            crate::ErrorKind::ResourceLimit
        );
        assert_eq!(limited.used(), 0);
        assert_eq!(std::fs::read_dir(&*root).unwrap().count(), 0);
        let ledger = crate::codec::workspace::Allowance::limited(4096);
        let resources = resources.with_execution_allowance(ledger.clone());
        let mut spool = Spool::create(&resources).unwrap();
        let capacity = spool.path.capacity() as u64;
        assert_eq!(ledger.used(), capacity);
        spool.write_all(b"payload").unwrap();
        spool.park();
        assert_eq!(ledger.used(), capacity);
        let mut copied = Vec::new();
        spool.copy_to(&mut copied).unwrap();
        assert_eq!(copied, b"payload");
        assert_eq!(ledger.used(), capacity);
        drop(spool);
        assert_eq!(ledger.used(), 0);
        assert_eq!(std::fs::read_dir(&*root).unwrap().count(), 0);
    }

    #[test]
    fn spool_reservations_refuse_arithmetic_overflow() {
        let resources = WriterResources::default().with_max_spool_bytes(u64::MAX);
        let mut first = StorageCharge::new(&resources).unwrap();
        let mut second = StorageCharge::new(&resources).unwrap();
        first.grow_to(u64::MAX).unwrap();
        assert_eq!(
            second.grow_to(1).unwrap_err(),
            Error::WriterSpoolLimitExceeded {
                limit: u64::MAX,
                required: u64::MAX,
                used: u64::MAX,
            }
        );
        drop(first);
        second.grow_to(1).unwrap();
        assert_eq!(spool_used(&resources), 1);
    }

    #[test]
    fn spool_quota_counts_live_extents_across_parking_and_overwrites() {
        let root = crate::scratch::case("spool-quota-extents");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(10);
        let mut first = Spool::create(&resources).unwrap();
        first.write_all(b"abcdef").unwrap();
        first.park();
        let mut second = Spool::create(&resources.clone()).unwrap();
        second.write_all(b"1234").unwrap();
        assert_eq!(spool_used(&resources), 10);
        let error = Error::from(second.write(b"x").unwrap_err());
        assert_eq!(
            error,
            Error::WriterSpoolLimitExceeded {
                limit: 10,
                required: 11,
                used: 10
            }
        );
        assert_eq!(second.len(), 4);
        first.seek_to(1).unwrap();
        first.write_all(b"XY").unwrap();
        assert_eq!(spool_used(&resources), 10);
        drop(second);
        assert_eq!(spool_used(&resources), 6);
        first.seek_to(9).unwrap();
        assert_eq!(spool_used(&resources), 6);
        first.write_all(b"Z").unwrap(); // charge the hole as well
        assert_eq!(spool_used(&resources), 10);
        let mut bytes = Vec::new();
        first.copy_to(&mut bytes).unwrap();
        assert_eq!(bytes, b"aXYdef\0\0\0Z");
        drop(first);
        assert_eq!(spool_used(&resources), 0);
    }

    #[test]
    fn spool_short_writes_hold_then_reconcile_the_growth_reservation() {
        let root = crate::scratch::case("spool-quota-short-write");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(10);
        let mut spool = Spool::create(&resources).unwrap();
        let written = spool
            .write_with(b"0123456789", |file, bytes| {
                assert_eq!(spool_used(&resources), 10);
                file.write(&bytes[..3])
            })
            .unwrap();
        assert_eq!(written, 3);
        assert_eq!(spool.len(), 3);
        assert_eq!(spool_used(&resources), 3);
        spool.seek_to(9).unwrap();
        assert_eq!(
            spool
                .write_with(b"x", |_, _| {
                    assert_eq!(spool_used(&resources), 10);
                    Ok(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(spool.len(), 3);
        assert_eq!(spool_used(&resources), 3);
        assert!(spool
            .write_with(b"xx", |_, _| panic!("refusal must precede backing I/O"))
            .is_err());
        assert_eq!(spool_used(&resources), 3);
    }

    #[test]
    fn spool_zero_limit_allows_empty_writes_but_no_growth() {
        let root = crate::scratch::case("spool-quota-zero");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(0);
        let mut spool = Spool::create(&resources).unwrap();
        spool.seek_to(100).unwrap();
        assert_eq!(spool.write(b"").unwrap(), 0);
        assert_eq!(spool.len(), 0);
        assert_eq!(spool_used(&resources), 0);
        assert!(matches!(
            Error::from(spool.write(b"x").unwrap_err()),
            Error::WriterSpoolLimitExceeded {
                limit: 0,
                required: 101,
                used: 0
            }
        ));
        assert_eq!(spool.len(), 0);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn failed_backing_write_releases_only_its_reservation() {
        let root = crate::scratch::case("spool-quota-io");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(10);
        let mut spool = Spool::create(&resources).unwrap();
        spool.write_all(b"abc").unwrap();
        spool.park();
        let mut read_only = File::open(&spool.path).unwrap();
        read_only.seek(SeekFrom::Start(3)).unwrap();
        spool.file = Some(read_only);
        assert!(spool.write_all(b"1234567").is_err());
        assert_eq!(spool_used(&resources), 3);
        assert_eq!(spool.len(), 3);
        spool.park();
        spool.write_all(b"1234567").unwrap();
        assert_eq!(spool_used(&resources), 10);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn spool_sources_and_readers_retain_their_charge() {
        let root = crate::scratch::case("spool-quota-source");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(3);
        let mut spool = Spool::create(&resources).unwrap();
        spool.write_all(b"abc").unwrap();
        let source = spool.into_source();
        let mut reader = source.open().unwrap();
        drop(source);
        assert_eq!(spool_used(&resources), 3);
        let mut another = Spool::create(&resources).unwrap();
        assert!(another.write(b"x").is_err());
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abc");
        drop(reader);
        another.write_all(b"xyz").unwrap();
        assert_eq!(spool_used(&resources), 3);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn concurrent_spool_growth_cannot_overbook_shared_resources() {
        let root = crate::scratch::case("spool-quota-concurrent");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(10);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let tx = tx.clone();
                let resources = resources.clone();
                scope.spawn(move || {
                    let mut spool = Spool::create(&resources).unwrap();
                    let result = spool.write_all(b"1234567").map_err(Error::from);
                    tx.send((spool, result)).unwrap();
                });
            }
        });
        drop(tx);
        let outcomes: Vec<_> = rx.into_iter().collect();
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(spool_used(&resources), 7);
        for (_, result) in &outcomes {
            if let Err(error) = result {
                assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
            }
        }
        drop(outcomes);
        assert_eq!(spool_used(&resources), 0);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn spool_cleanup_failure_retains_debt_in_the_quota_group() {
        let root = crate::scratch::case("spool-quota-cleanup");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(3);
        let mut spool = Spool::create(&resources).unwrap();
        spool.write_all(b"abc").unwrap();
        spool.park();
        let original = spool.path.clone();
        // Force removal to fail without relying on root/Windows permissions.
        std::fs::rename(&original, root.join("orphan")).unwrap();
        std::fs::create_dir(&original).unwrap();
        drop(spool);
        assert_eq!(spool_used(&resources), 3);
        let mut another = Spool::create(&resources).unwrap();
        assert!(another.write_all(b"x").is_err());
    }

    #[test]
    fn spool_quota_is_released_on_unwind() {
        let root = crate::scratch::case("spool-quota-unwind");
        let resources = WriterResources::default()
            .with_temp_dir(&*root)
            .with_max_spool_bytes(3);
        let result = std::panic::catch_unwind(|| {
            let mut spool = Spool::create(&resources).unwrap();
            spool.write_all(b"abc").unwrap();
            panic!("injected unwind");
        });
        assert!(result.is_err());
        assert_eq!(spool_used(&resources), 0);
    }

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
