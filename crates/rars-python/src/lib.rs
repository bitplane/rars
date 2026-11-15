use pyo3::exceptions::{
    PyInterruptedError, PyKeyError, PyMemoryError, PyNotImplementedError, PyOSError, PyTypeError,
    PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyList, PyModule, PyString, PyTuple};
use pyo3::{create_exception, PyErr};
use rars_rs::filename::relative_path as output_relative_path;
use rars_rs::output_links::{create_link_output, link_source_path};
use rars_rs::output_staging::{
    failed_entry_name, publish_verified_output, refused_output, ExtractionStaging, OverwritePolicy,
};
use rars_rs::password_check::{PasswordProbe, PasswordVerdict};
use rars_rs::ExtractedLink;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(test)]
#[path = "../../rars/tests/support/scratch.rs"]
mod scratch;

create_exception!(rars, Error, pyo3::exceptions::PyException);
create_exception!(rars, BadRarFile, Error);
create_exception!(rars, BadPassword, BadRarFile);
create_exception!(rars, PasswordRequired, BadRarFile);
create_exception!(rars, MissingVolume, BadRarFile);
create_exception!(rars, ChecksumError, BadRarFile);
create_exception!(rars, UnsupportedRarFeature, Error);
create_exception!(rars, NotRarFile, Error);
create_exception!(rars, UnsafeArchivePath, Error);
create_exception!(rars, UnsafeLinkWarning, pyo3::exceptions::PyUserWarning);

#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone)]
struct ProgressEvent {
    #[pyo3(get)]
    phase: String,
    #[pyo3(get)]
    completed: u64,
    #[pyo3(get)]
    total: u64,
    #[pyo3(get)]
    pass_number: usize,
    #[pyo3(get)]
    entry_name: Option<Vec<u8>>,
    #[pyo3(get)]
    entry_index: Option<usize>,
    #[pyo3(get)]
    total_entries: Option<usize>,
    /// The volume being read, counting the first as 1; None outside a volume set.
    #[pyo3(get)]
    volume: Option<usize>,
    finished: bool,
    /// A set whose last volume hasn't been read yet has no total; `total` is 0 until it does.
    total_known: bool,
}

#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone)]
struct RepairReport {
    #[pyo3(get)]
    changed: bool,
    #[pyo3(get)]
    data_repaired: bool,
    #[pyo3(get)]
    recovery_record_rebuilt: bool,
    #[pyo3(get)]
    end_record_rebuilt: bool,
    #[pyo3(get)]
    available_recovery_shards: Option<u64>,
    #[pyo3(get)]
    expected_recovery_shards: Option<u64>,
}

impl From<rars_rs::RecoveryRepairReport> for RepairReport {
    fn from(value: rars_rs::RecoveryRepairReport) -> Self {
        Self {
            changed: value.changed,
            data_repaired: value.data_repaired,
            recovery_record_rebuilt: value.recovery_record_rebuilt,
            end_record_rebuilt: value.end_record_rebuilt,
            available_recovery_shards: value.available_recovery_shards,
            expected_recovery_shards: value.expected_recovery_shards,
        }
    }
}

#[pyclass(frozen, module = "rars")]
struct RepairResult {
    #[pyo3(get)]
    data: Vec<u8>,
    #[pyo3(get)]
    report: RepairReport,
}

#[pymethods]
impl ProgressEvent {
    #[getter]
    fn percentage(&self) -> Option<f64> {
        if !self.total_known || (self.phase == "writing" && self.total == 0 && !self.finished) {
            return None;
        }
        if self.total == 0 {
            Some(100.0)
        } else {
            Some(self.completed as f64 * 100.0 / self.total as f64)
        }
    }
}

/// A thread-safe, one-way cancellation signal for reading, writing and repair.
#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone, Default)]
struct CancellationToken {
    inner: rars_rs::ReadCancellation,
}

#[pymethods]
impl CancellationToken {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. A cancelled token cannot be reset.
    fn cancel(&self) {
        self.inner.cancel();
    }

    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

/// Per-call parsing, decoding and extraction policies.
#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone, Default)]
struct ReadOptions {
    #[pyo3(get)]
    legacy_name_encoding: Option<String>,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    cancellation: Option<rars_rs::ReadCancellation>,
    #[pyo3(get)]
    max_member_output_bytes: Option<u64>,
    #[pyo3(get)]
    max_total_output_bytes: Option<u64>,
    #[pyo3(get)]
    max_reader_workspace_bytes: Option<u64>,
    #[pyo3(get)]
    max_header_count: Option<u64>,
    #[pyo3(get)]
    max_header_bytes: Option<u64>,
    #[pyo3(get)]
    rar50_dictionary_size_limit: Option<u64>,
    #[pyo3(get)]
    rar50_buffered_decode_limit: Option<u64>,
    #[pyo3(get)]
    allow_rar3_vm_programs: bool,
    /// Caps members decoded side by side and a large RAR 5 member's block decoders; 0 or 1 keeps the call on the calling thread.
    #[pyo3(get)]
    threads: Option<usize>,
    /// Beside `cancellation` because a callback that raises cancels the read the same way.
    progress: Option<Arc<Py<PyAny>>>,
}

#[pymethods]
impl ReadOptions {
    #[new]
    #[allow(clippy::too_many_arguments)] // Python keyword-only policy fields.
    #[pyo3(signature = (*, cancellation=None, max_member_output_bytes=None, max_total_output_bytes=None, max_reader_workspace_bytes=None, rar50_dictionary_size_limit=None, rar50_buffered_decode_limit=None, max_header_count=None, max_header_bytes=None, legacy_name_encoding=None, allow_rar3_vm_programs=false, threads=None, progress=None))]
    fn new(
        cancellation: Option<&CancellationToken>,
        max_member_output_bytes: Option<u64>,
        max_total_output_bytes: Option<u64>,
        max_reader_workspace_bytes: Option<u64>,
        rar50_dictionary_size_limit: Option<u64>,
        rar50_buffered_decode_limit: Option<u64>,
        max_header_count: Option<u64>,
        max_header_bytes: Option<u64>,
        legacy_name_encoding: Option<String>,
        allow_rar3_vm_programs: bool,
        threads: Option<usize>,
        progress: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        if progress.is_some_and(|progress| !progress.is_callable()) {
            return Err(PyValueError::new_err("progress must be callable"));
        }
        let encoding = legacy_name_encoding
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(map_error)?;
        Ok(Self {
            legacy_name_encoding,
            encoding,
            cancellation: cancellation.map(|token| token.inner.clone()),
            max_member_output_bytes,
            max_total_output_bytes,
            max_reader_workspace_bytes,
            rar50_dictionary_size_limit,
            rar50_buffered_decode_limit,
            max_header_count,
            max_header_bytes,
            allow_rar3_vm_programs,
            threads,
            progress: progress.map(|progress| Arc::new(progress.clone().unbind())),
        })
    }

    /// Called with a `ProgressEvent` by `read`, `read_many`, `extract`, `extractall` and `testrar`, a few times a second at most; an exception it raises stops the call and is re-raised.
    #[getter]
    fn progress(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.progress
            .as_ref()
            .map(|progress| progress.clone_ref(py))
    }

    #[getter]
    fn cancellation(&self) -> Option<CancellationToken> {
        self.cancellation.as_ref().map(|inner| CancellationToken {
            inner: inner.clone(),
        })
    }
}

fn python_read_options<'a>(
    settings: Option<&'a ReadOptions>,
    password: Option<&'a [u8]>,
) -> rars_rs::ArchiveReadOptions<'a> {
    let mut options = rars_rs::ArchiveReadOptions::with_optional_password(password);
    if let Some(settings) = settings {
        options.cancellation = settings.cancellation.as_ref();
        options.legacy_name_encoding = settings.encoding;
        options.max_header_count = settings.max_header_count;
        options.max_header_bytes = settings.max_header_bytes;
        options.max_member_output_bytes = settings.max_member_output_bytes;
        options.max_total_output_bytes = settings.max_total_output_bytes;
        options.max_reader_workspace_bytes = settings.max_reader_workspace_bytes;
        options.rar50_dictionary_size_limit = settings.rar50_dictionary_size_limit;
        options.rar50_buffered_decode_limit = settings.rar50_buffered_decode_limit;
        options.allow_rar3_vm_programs = settings.allow_rar3_vm_programs;
        options.threads = settings.threads;
    }
    options
}

struct PythonProgress {
    callback: Option<Py<PyAny>>,
    state: Mutex<HashMap<&'static str, ProgressEvent>>,
    error: Mutex<Option<PyErr>>,
    cancelled: AtomicBool,
    read_cancellation: rars_rs::ReadCancellation,
}

impl PythonProgress {
    fn new(callback: Option<Py<PyAny>>, cancellation: Option<&CancellationToken>) -> Self {
        Self {
            callback,
            state: Mutex::new(HashMap::new()),
            error: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            read_cancellation: cancellation
                .map_or_else(rars_rs::ReadCancellation::new, |token| token.inner.child()),
        }
    }

    fn take_error(&self) -> Option<PyErr> {
        self.error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

impl rars_rs::WriteProgress for PythonProgress {
    fn report(&self, event: rars_rs::WriteProgressEvent<'_>) {
        if self.cancelled.load(Ordering::Relaxed) || self.read_cancellation.is_cancelled() {
            return;
        }
        let Some(callback) = &self.callback else {
            return;
        };
        let snapshot = {
            let operation = match event {
                rars_rs::WriteProgressEvent::OperationStarted { operation, .. }
                | rars_rs::WriteProgressEvent::EntryStarted { operation, .. }
                | rars_rs::WriteProgressEvent::EntryFinished { operation, .. }
                | rars_rs::WriteProgressEvent::Advanced { operation, .. }
                | rars_rs::WriteProgressEvent::OperationFinished { operation, .. } => operation,
                _ => rars_rs::WriteOperation::Emission,
            };
            let phase = progress_phase(operation);
            let mut states = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let state = states.entry(phase).or_insert_with(|| ProgressEvent {
                phase: phase.to_string(),
                completed: 0,
                total: 0,
                pass_number: 1,
                entry_name: None,
                entry_index: None,
                total_entries: None,
                volume: None,
                finished: false,
                total_known: true,
            });
            match event {
                rars_rs::WriteProgressEvent::OperationStarted {
                    operation,
                    total_bytes,
                    total_entries,
                    pass,
                } => {
                    state.phase = progress_phase(operation).to_string();
                    state.finished = false;
                    state.completed = 0;
                    state.total = total_bytes.unwrap_or(0);
                    state.pass_number = pass;
                    state.total_entries = total_entries;
                    state.entry_name = None;
                    state.entry_index = None;
                }
                rars_rs::WriteProgressEvent::EntryStarted {
                    index,
                    total_entries,
                    name,
                    ..
                }
                | rars_rs::WriteProgressEvent::EntryFinished {
                    index,
                    total_entries,
                    name,
                    ..
                } => {
                    state.entry_name = Some(name.to_vec());
                    state.entry_index = Some(index);
                    state.total_entries = Some(total_entries);
                }
                rars_rs::WriteProgressEvent::Advanced {
                    operation,
                    completed_bytes,
                    total_bytes,
                    pass,
                } => {
                    state.phase = progress_phase(operation).to_string();
                    state.completed = completed_bytes;
                    state.total = total_bytes;
                    state.pass_number = pass;
                }
                rars_rs::WriteProgressEvent::VolumeFinished { bytes, .. } => {
                    state.finished = true;
                    state.completed = bytes;
                    state.total = bytes;
                }
                rars_rs::WriteProgressEvent::BytesWritten { completed_bytes } => {
                    state.completed = completed_bytes;
                }
                rars_rs::WriteProgressEvent::OperationFinished {
                    operation,
                    total_bytes,
                    pass,
                    ..
                } => {
                    state.phase = progress_phase(operation).to_string();
                    state.finished = true;
                    state.total = total_bytes.unwrap_or(state.total);
                    state.completed = state.total;
                    state.pass_number = pass;
                }
                _ => {}
            }
            state.clone()
        };
        let result = Python::attach(|py| {
            let event = Py::new(py, snapshot)?;
            callback.call1(py, (event,)).map(|_| ())
        });
        if let Err(error) = result {
            self.cancelled.store(true, Ordering::Relaxed);
            self.read_cancellation.cancel();
            *self
                .error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed) || self.read_cancellation.is_cancelled()
    }
}

/// Callbacks need the GIL, so a read reports at most this often, plus once when it finishes.
const READ_PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// One read call's progress, counted at the writers the binding opens rather than in the decoder.
struct ReadProgress {
    callback: Arc<Py<PyAny>>,
    phase: &'static str,
    cancellation: rars_rs::ReadCancellation,
    error: Mutex<Option<PyErr>>,
    state: Mutex<ReadState>,
}

#[derive(Default)]
struct ReadState {
    completed: u64,
    seen_bytes: u64,
    seen_entries: usize,
    total_known: bool,
    /// The set's headers gave the total before reading, so volumes add nothing to it.
    listed: bool,
    started: usize,
    entry_name: Option<Vec<u8>>,
    volume: Option<usize>,
    next_index: usize,
    reported: Option<std::time::Instant>,
}

impl ReadProgress {
    fn new(settings: Option<&ReadOptions>, phase: &'static str) -> Option<Arc<Self>> {
        let settings = settings?;
        Some(Arc::new(Self {
            callback: Arc::clone(settings.progress.as_ref()?),
            phase,
            cancellation: settings
                .cancellation
                .as_ref()
                .map_or_else(rars_rs::ReadCancellation::new, |token| token.child()),
            error: Mutex::new(None),
            state: Mutex::new(ReadState::default()),
        }))
    }

    fn watch<'a>(
        &'a self,
        options: rars_rs::ArchiveReadOptions<'a>,
    ) -> rars_rs::ArchiveReadOptions<'a> {
        options.with_cancellation(&self.cancellation)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ReadState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `alone` when the call reads no later volume, so the first one holds the whole total.
    fn begin(&self, first: &rars_rs::Archive, chosen: &dyn Fn(usize) -> bool, alone: bool) {
        let mut state = self.lock();
        for (index, member) in first.members().enumerate() {
            state.next_index = index + 1;
            state.see(&member.meta, chosen(index));
        }
        state.volume = first.is_volume().then_some(1);
        state.total_known = state.listed || alone || volume_end(first) == VolumeEnd::Last;
        self.report(state, false);
    }

    fn list(&self, infos: &[RarInfo], chosen: &dyn Fn(usize) -> bool) {
        let mut state = self.lock();
        for info in infos {
            if chosen(info.member_index) && !info.is_directory && !info.is_redirection {
                state.seen_bytes += info.file_size;
                state.seen_entries += 1;
            }
        }
        state.listed = true;
    }

    /// A later volume's members count toward the total only once the set's last volume is known.
    fn arrived(&self, volume: &rars_rs::Archive, chosen: &dyn Fn(usize) -> bool) {
        let mut state = self.lock();
        for member in volume.members() {
            if !member.meta.is_split_before {
                state.next_index += 1;
            }
            let index = state.next_index - 1;
            state.see(&member.meta, chosen(index));
        }
        state.volume = state.volume.map(|volume| volume + 1);
        state.total_known = state.listed || volume_end(volume) == VolumeEnd::Last;
        self.report(state, false);
    }

    fn entry(&self, name: &[u8]) {
        let mut state = self.lock();
        state.entry_name = Some(name.to_vec());
        state.started += 1;
        self.report(state, false);
    }

    fn advance(&self, bytes: u64) {
        let mut state = self.lock();
        state.completed += bytes;
        self.report(state, false);
    }

    fn counted(self: &Arc<Self>, name: &[u8], writer: Box<dyn Write>) -> Box<dyn Write> {
        self.entry(name);
        Box::new(CountedWriter {
            writer,
            progress: Arc::clone(self),
            pending: 0,
        })
    }

    /// A raising callback's exception wins over the cancellation it caused; success reports once more, finished.
    fn finish<T>(&self, result: PyResult<T>) -> PyResult<T> {
        if let Some(error) = self.take_error() {
            return Err(error);
        }
        let value = result?;
        let mut state = self.lock();
        if state.total_known {
            state.completed = state.seen_bytes;
        } else {
            state.seen_bytes = state.completed;
            state.total_known = true;
        }
        self.report(state, true);
        match self.take_error() {
            Some(error) => Err(error),
            None => Ok(value),
        }
    }

    fn take_error(&self) -> Option<PyErr> {
        self.error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    fn report(&self, mut state: std::sync::MutexGuard<'_, ReadState>, finished: bool) {
        if self.cancellation.is_cancelled() {
            return;
        }
        let now = std::time::Instant::now();
        if !finished
            && state
                .reported
                .is_some_and(|reported| now.duration_since(reported) < READ_PROGRESS_INTERVAL)
        {
            return;
        }
        state.reported = Some(now);
        let total = if state.total_known {
            state.seen_bytes
        } else {
            0
        };
        let event = ProgressEvent {
            phase: self.phase.to_string(),
            completed: if state.total_known {
                state.completed.min(total)
            } else {
                state.completed
            },
            total,
            pass_number: 1,
            entry_name: state.entry_name.clone(),
            entry_index: state.started.checked_sub(1),
            total_entries: state.total_known.then_some(state.seen_entries),
            volume: state.volume,
            finished,
            total_known: state.total_known,
        };
        drop(state);
        let result = Python::attach(|py| {
            let event = Py::new(py, event)?;
            self.callback.call1(py, (event,)).map(|_| ())
        });
        if let Err(error) = result {
            self.cancellation.cancel();
            *self
                .error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
        }
    }
}

impl ReadState {
    /// A split member counts at its last part, the only one sure to record its whole size.
    fn see(&mut self, meta: &rars_rs::ArchiveMemberMeta, chosen: bool) {
        if !self.listed
            && chosen
            && !meta.is_split_after
            && !meta.is_directory
            && !meta.is_redirection
        {
            self.seen_bytes += meta.unpacked_size;
            self.seen_entries += 1;
        }
    }
}

type Volumes<'a> = dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send + 'a;

fn tracked<'a>(
    progress: Option<&'a ReadProgress>,
    volumes: &'a mut Volumes<'a>,
    chosen: &'a (dyn Fn(usize) -> bool + Sync),
) -> Box<Volumes<'a>> {
    match progress {
        Some(progress) => Box::new(volumes.inspect(move |volume| {
            if let Ok(volume) = volume {
                progress.arrived(volume, chosen);
            }
        })),
        None => Box::new(volumes),
    }
}

/// Hands counts over a mebibyte at a time, so a decoder's writes don't each take the progress lock.
const COUNTED_BATCH: u64 = 1 << 20;

struct CountedWriter {
    writer: Box<dyn Write>,
    progress: Arc<ReadProgress>,
    pending: u64,
}

impl Write for CountedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.writer.write(bytes)?;
        self.pending += written as u64;
        if self.pending >= COUNTED_BATCH {
            self.progress.advance(std::mem::take(&mut self.pending));
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl Drop for CountedWriter {
    fn drop(&mut self) {
        if self.pending > 0 {
            self.progress.advance(self.pending);
        }
    }
}

fn progress_phase(operation: rars_rs::WriteOperation) -> &'static str {
    match operation {
        rars_rs::WriteOperation::Staging => "staging",
        rars_rs::WriteOperation::Compression => "compression",
        rars_rs::WriteOperation::Recovery => "recovery",
        _ => "writing",
    }
}

#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone)]
struct RarInfo {
    #[pyo3(get)]
    member_index: usize,
    archive_identity: Option<Arc<()>>,
    #[pyo3(get)]
    filename: String,
    orig_filename_bytes: Arc<[u8]>,
    #[pyo3(get)]
    file_size: u64,
    #[pyo3(get)]
    compress_size: u64,
    #[pyo3(get)]
    /// Whole-second calendar tuple: UTC for RAR5, stored wall-clock fields for
    /// legacy DOS timestamps. None means no usable timestamp was recorded.
    date_time: Option<(u16, u8, u8, u8, u8, u8)>,
    #[pyo3(get)]
    crc: Option<u32>,
    #[pyo3(get)]
    host_os: Option<u64>,
    #[pyo3(get)]
    is_encrypted: bool,
    #[pyo3(get)]
    is_solid: bool,
    #[pyo3(get)]
    is_split_before: bool,
    #[pyo3(get)]
    is_split_after: bool,
    #[pyo3(get)]
    rar_version: String,
    #[pyo3(get)]
    file_attr: u64,
    #[pyo3(get)]
    detail: HashMap<String, String>,
    is_directory: bool,
    is_redirection: bool,
    /// Counted from 0.
    #[pyo3(get)]
    volume: usize,
}

#[pymethods]
impl RarInfo {
    #[getter]
    fn orig_filename_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.orig_filename_bytes)
    }

    #[getter(CRC)]
    fn crc_upper(&self) -> Option<u32> {
        self.crc
    }

    fn is_dir(&self) -> bool {
        self.is_directory
    }

    fn __repr__(&self) -> String {
        format!(
            "RarInfo(filename={:?}, file_size={}, compress_size={})",
            self.filename, self.file_size, self.compress_size
        )
    }
}

/// An archive opened from a bytes-like object (`bytes`, `bytearray`, `memoryview`,
/// `mmap`...), a path (`str` or `PathLike`) or a binary file object.
#[pyclass(module = "rars")]
struct RarFile {
    identity: Arc<()>,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    archive: rars_rs::Archive,
    /// Where it was opened from, to find a set's later volumes by name.
    path: Option<PathBuf>,
    password: Option<Vec<u8>>,
    /// The opening options, which listing later volumes reads with too.
    options: Option<ReadOptions>,
    /// Later volumes given at opening; a tuple, so listing and every read can walk them again.
    volumes: Option<Py<PyTuple>>,
    first_volume_only: bool,
    first: SetListing,
    /// The whole set, listed the first time a call needs a member past the first volume.
    whole: OnceLock<SetListing>,
}

struct SetListing {
    infos: Vec<RarInfo>,
    places: Vec<Place>,
    names: OnceLock<MemberNames>,
}

#[derive(Default)]
struct SelectionEnd {
    name: Option<Vec<u8>>,
    last_volume: Option<usize>,
}

#[derive(Clone, Copy)]
struct Place {
    /// Metadata calls reopen the member's own volume, which numbers its members from 0.
    index_in_volume: usize,
    /// Reads of the member stop pulling volumes here; None until its last part is listed.
    last_volume: Option<usize>,
}

impl SetListing {
    fn new(infos: Vec<RarInfo>) -> Self {
        let places = infos
            .iter()
            .enumerate()
            .map(|(index_in_volume, info)| Place {
                index_in_volume,
                last_volume: (!info.is_split_after).then_some(0),
            })
            .collect();
        Self {
            infos,
            places,
            names: OnceLock::new(),
        }
    }
}

#[derive(Default)]
struct MemberNames {
    raw: HashMap<Arc<[u8]>, usize>,
    decoded: HashMap<String, Option<usize>>,
}

impl MemberNames {
    fn new(infos: &[RarInfo], decoded: bool) -> Self {
        let mut names = Self::default();
        for (index, info) in infos.iter().enumerate() {
            names.raw.insert(info.orig_filename_bytes.clone(), index);
            if decoded {
                names
                    .decoded
                    .entry(info.filename.clone())
                    .and_modify(|previous| {
                        if previous.is_some_and(|previous| {
                            infos[previous].orig_filename_bytes == info.orig_filename_bytes
                        }) {
                            *previous = Some(index);
                        } else {
                            *previous = None;
                        }
                    })
                    .or_insert(Some(index));
            }
        }
        names
    }
}

#[pymethods]
impl RarFile {
    /// A path or seekable file object is read on demand from its start, so it must stay
    /// open and unchanged while the archive is, and its position is left wherever reading
    /// ended; a stream that can't seek is read whole from where it is.
    #[new]
    #[pyo3(signature = (source, mode = "r", password = None, *, options = None, first_volume_only = false, volumes = None))]
    fn new(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        mode: &str,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        first_volume_only: bool,
        volumes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        if mode != "r" {
            return Err(PyNotImplementedError::new_err(
                "RarFile currently opens archives for reading; use RarBuilder to create or rewrite archives",
            ));
        }
        let password = py_password(password)?;
        let volumes = stored_volumes(
            volumes,
            options.and_then(|options| options.cancellation.as_ref()),
        )?;
        let cancellation = options.and_then(|options| options.cancellation.as_ref());
        let file = match archive_input(source, cancellation)? {
            ArchiveInput::Bytes(bytes) => Self::from_bytes(py, bytes, password, options)?,
            ArchiveInput::Path(path) => Self::from_path(py, path, password, options)?,
            ArchiveInput::Reader(reader) => Self::parse(py, password, options, |options| {
                rars_rs::ArchiveReader::read_reader_with_options(reader, options)
            })?,
        };
        Ok(file.with_set(first_volume_only, volumes))
    }

    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    #[pyo3(signature = (data, password = None, *, options = None, first_volume_only = false, volumes = None))]
    fn from_bytes_py(
        py: Python<'_>,
        data: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        first_volume_only: bool,
        volumes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let volumes = stored_volumes(
            volumes,
            options.and_then(|options| options.cancellation.as_ref()),
        )?;
        let file = Self::from_bytes(
            py,
            py_required_bytes(data)?,
            py_password(password)?,
            options,
        )?;
        Ok(file.with_set(first_volume_only, volumes))
    }

    fn namelist(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        Ok(self
            .listing(py)?
            .infos
            .iter()
            .map(|info| info.filename.clone())
            .collect())
    }

    fn infolist(&self, py: Python<'_>) -> PyResult<Vec<RarInfo>> {
        Ok(self.listing(py)?.infos.clone())
    }

    fn getinfo(&self, py: Python<'_>, name: &Bound<'_, PyAny>) -> PyResult<RarInfo> {
        let index = self.resolve_index(py, name)?;
        // A first-volume member never waits for later volumes; its split sizes are whole once the set is listed.
        let listing = match self.whole.get() {
            Some(whole) => whole,
            None if index < self.first.infos.len() => &self.first,
            None => self.listing(py)?,
        };
        Ok(listing.infos[index].clone())
    }

    /// `volumes` works as in `extractall`, for a member that continues into later volumes.
    #[pyo3(signature = (name, password = None, *, options = None, volumes = None))]
    fn read(
        &self,
        py: Python<'_>,
        name: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<u8>> {
        check_read_options_cancellation(options)?;
        let index = self.resolve_index(py, name)?;
        let data = self.read_indices(py, &[index], password, options, volumes)?;
        data.into_iter()
            .next()
            .flatten()
            .ok_or_else(|| PyKeyError::new_err("member has no file payload"))
    }

    #[pyo3(signature = (name, password = None, *, options = None, volumes = None))]
    fn open(
        &self,
        py: Python<'_>,
        name: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let data = self.read(py, name, password, options, volumes)?;
        let io = py.import("io")?;
        let bytes = PyBytes::new(py, &data);
        Ok(io.getattr("BytesIO")?.call1((bytes,))?.unbind())
    }

    /// Read selected members in one session, preserving request order and duplicates.
    /// Output limits apply to the whole call, including required solid predecessors.
    #[pyo3(signature = (members, password = None, *, options = None, volumes = None))]
    fn read_many(
        &self,
        py: Python<'_>,
        members: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<Vec<u8>>> {
        check_read_options_cancellation(options)?;
        let indices = members
            .try_iter()?
            .map(|member| self.resolve_index(py, &member?))
            .collect::<PyResult<Vec<_>>>()?;
        self.read_indices(py, &indices, password, options, volumes)?
            .into_iter()
            .map(|bytes| bytes.ok_or_else(|| PyKeyError::new_err("member has no file payload")))
            .collect()
    }

    /// `overwrite`, `in_place`, `flatten` and `volumes` work as in `extractall`.
    #[pyo3(signature = (member, path = None, password = None, overwrite = Overwrite(OverwritePolicy::Never), *, options = None, volumes = None, restore_times = true, in_place = false, flatten = false))]
    #[allow(clippy::too_many_arguments)]
    fn extract(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        path: Option<PathBuf>,
        password: Option<&Bound<'_, PyAny>>,
        overwrite: Overwrite,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
        restore_times: bool,
        in_place: bool,
        flatten: bool,
    ) -> PyResult<PathBuf> {
        check_read_options_cancellation(options)?;
        let Overwrite(overwrite) = overwrite;
        let target = self.resolve_index(py, member)?;
        let out_dir = path.unwrap_or_else(|| PathBuf::from("."));
        let password = py_password(password)?.or_else(|| self.password.clone());
        let progress = ReadProgress::new(options, "extracting");
        let options = watched(
            &progress,
            self.extraction_options(options, password.as_deref()),
        );
        let mode = OutputMode {
            overwrite,
            in_place,
            restore_times,
            flatten,
        };
        let chosen = |index: usize| index == target;
        let extracted = if self.needs_later_volumes(target) {
            self.extract_from_set(
                py,
                volumes,
                options,
                Some(&HashSet::from([target])),
                &out_dir,
                mode,
                progress.as_ref(),
            )
        } else {
            if let Some(progress) = &progress {
                progress.begin(&self.archive, &chosen, true);
            }
            py.detach(|| {
                extract_archive(
                    &self.archive,
                    Some(&target),
                    &out_dir,
                    options,
                    mode,
                    progress.clone(),
                )
            })
            .map_err(map_error)
        };
        finished(&progress, extracted)?
            .warn(py)?
            .into_iter()
            .next()
            .ok_or_else(|| PyKeyError::new_err("member has no extractable payload"))
    }

    /// On a volume set, extracts the whole set, or with `members` reads only as far
    /// as they reach. Without `volumes`, a set opened from a path finds its later
    /// volumes by name beside it.
    ///
    /// `volumes` yields the volumes after this one, in order: bytes-like objects
    /// are archive data, `str` or `PathLike` are paths, and binary file objects are
    /// read as `RarFile` reads them. Each is pulled when needed, so a
    /// generator may wait for downloads. If the last volume isn't marked as last
    /// (all RAR 1.3 to 2.0 sets, some later ones), the iterator is advanced once
    /// more and must stop, not wait.
    ///
    /// Each file is written to a private directory inside `path` and moved into
    /// place once verified. `in_place=True` writes the destination itself
    /// instead: an existing file keeps its identity and metadata, and the
    /// directory needn't be writable, but a member that fails verification
    /// leaves a partly written file. An existing link or special file at a
    /// destination is still refused.
    ///
    /// `overwrite` is `False` to refuse an existing file, `True` to replace it,
    /// or `"rename"` to write beside it as `name(N).ext`. `flatten=True` writes
    /// every file straight into `path` under its base name and creates no
    /// directories; symlinks are kept only when they point at a bare name.
    #[pyo3(signature = (path = None, members = None, password = None, overwrite = Overwrite(OverwritePolicy::Never), *, options = None, volumes = None, restore_times = true, in_place = false, flatten = false))]
    #[allow(clippy::too_many_arguments)]
    fn extractall(
        &self,
        py: Python<'_>,
        path: Option<PathBuf>,
        members: Option<&Bound<'_, PyAny>>,
        password: Option<&Bound<'_, PyAny>>,
        overwrite: Overwrite,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
        restore_times: bool,
        in_place: bool,
        flatten: bool,
    ) -> PyResult<Vec<PathBuf>> {
        check_read_options_cancellation(options)?;
        let mode = OutputMode {
            overwrite: overwrite.0,
            in_place,
            restore_times,
            flatten,
        };
        let out_dir = path.unwrap_or_else(|| PathBuf::from("."));
        let password = py_password(password)?.or_else(|| self.password.clone());
        let selected = members
            .map(|members| {
                members
                    .try_iter()?
                    .map(|member| self.resolve_index(py, &member?))
                    .collect::<PyResult<HashSet<usize>>>()
            })
            .transpose()?;
        let progress = ReadProgress::new(options, "extracting");
        let options = watched(
            &progress,
            self.extraction_options(options, password.as_deref()),
        );
        let in_set = match &selected {
            None => volumes.is_some() || self.archive.is_volume(),
            Some(selected) => selected
                .iter()
                .any(|&index| self.needs_later_volumes(index)),
        };
        let extracted = if in_set {
            self.extract_from_set(
                py,
                volumes,
                options,
                selected.as_ref(),
                &out_dir,
                mode,
                progress.as_ref(),
            )
        } else {
            if let Some(progress) = &progress {
                let chosen = |index: usize| selected.as_ref().is_none_or(|s| s.contains(&index));
                progress.begin(&self.archive, &chosen, true);
            }
            py.detach(|| {
                extract_archive(
                    &self.archive,
                    selected.as_ref(),
                    &out_dir,
                    options,
                    mode,
                    progress.clone(),
                )
            })
            .map_err(map_error)
        };
        finished(&progress, extracted)?.warn(py)
    }

    /// `volumes` works as in `extractall`.
    #[pyo3(signature = (password = None, *, options = None, volumes = None))]
    fn testrar(
        &self,
        py: Python<'_>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let password = py_password(password)?.or_else(|| self.password.clone());
        let progress = ReadProgress::new(options, "testing");
        let options = watched(
            &progress,
            self.extraction_options(options, password.as_deref()),
        );
        let first = &self.archive;
        let alone = volumes.is_none() && !first.is_volume();
        if let Some(progress) = &progress {
            if alone {
                progress.begin(first, &|_| true, true);
            } else {
                self.begin_set(py, volumes, options, progress, &|_| true);
            }
        }
        let result = if alone {
            py.detach(|| match &progress {
                None => first.test_with_options(options),
                Some(progress) => test_counted(first, options, progress),
            })
            .map_err(map_error)
        } else {
            self.extract_set(py, volumes, options, |volumes| {
                let all = |_: usize| true;
                let volumes = tracked(progress.as_deref(), volumes, &all);
                first.extract_with_volumes(volumes, options, |meta| {
                    let sink = Box::new(io::sink()) as Box<dyn Write>;
                    Ok(match &progress {
                        Some(progress) if !meta.is_directory => progress.counted(&meta.name, sink),
                        _ => sink,
                    })
                })
            })
        };
        finished(&progress, result)
    }

    #[getter]
    fn comment(&self, py: Python<'_>) -> PyResult<Option<Vec<u8>>> {
        self.read_comment(py, None, None)
    }

    /// Returns the complete archive comment, or None if absent, under per-call read policies.
    #[pyo3(signature = (password = None, *, options = None))]
    fn read_comment(
        &self,
        py: Python<'_>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
    ) -> PyResult<Option<Vec<u8>>> {
        let password = py_password(password)?.or_else(|| self.password.clone());
        py.detach(|| {
            self.archive
                .comment_with_options(self.extraction_options(options, password.as_deref()))
        })
        .map_err(map_error)
    }

    #[getter]
    fn needs_password(&self) -> bool {
        self.first.infos.iter().any(|info| info.is_encrypted)
    }

    /// Returns the decoded comment attached to a member, or None if absent.
    #[pyo3(signature = (member, password = None, *, options = None))]
    fn getcomment(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
    ) -> PyResult<Option<Vec<u8>>> {
        check_read_options_cancellation(options)?;
        let index = self.resolve_index(py, member)?;
        let password = py_password(password)?.or_else(|| self.password.clone());
        let options = self.extraction_options(options, password.as_deref());
        let (archive, index) = self.member_volume(py, index, options)?;
        py.detach(|| archive.member_comment_at_with_options(index, options))
            .map_err(map_error)
    }

    /// Returns raw target bytes for a supported RAR5 or legacy Unix link.
    /// This reads archive metadata and never follows the link.
    #[pyo3(signature = (member, password = None, *, options = None))]
    fn readlink(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
    ) -> PyResult<Vec<u8>> {
        check_read_options_cancellation(options)?;
        let index = self.resolve_index(py, member)?;
        let password = py_password(password)?.or_else(|| self.password.clone());
        let options = self.extraction_options(options, password.as_deref());
        let (archive, index) = self.member_volume(py, index, options)?;
        let member = archive
            .members()
            .nth(index)
            .ok_or_else(|| PyKeyError::new_err("member not found"))?;
        if member.is_legacy_unix_symlink() {
            return Ok(py
                .detach(|| archive.legacy_symlink_target_at_with_options(index, options))
                .map_err(map_error)?
                .expect("legacy symlink predicate checked above"));
        }
        member
            .supported_redirection()
            .map(|link| link.target_name.clone())
            .ok_or_else(|| UnsupportedRarFeature::new_err("member is not a supported redirection"))
    }

    /// Exact Unix nanoseconds, absent kinds omitted; no `password` since headers were decrypted at open.
    #[pyo3(signature = (member, *, options = None))]
    fn gettimes(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        options: Option<&ReadOptions>,
    ) -> PyResult<HashMap<String, i128>> {
        check_read_options_cancellation(options)?;
        let index = self.resolve_index(py, member)?;
        let options = self.extraction_options(options, self.password.as_deref());
        let (archive, index) = self.member_volume(py, index, options)?;
        let member = archive
            .members()
            .nth(index)
            .ok_or_else(|| PyKeyError::new_err("member not found"))?;
        let mut times = member.file_times().map_err(map_error)?.unwrap_or_default();
        if times.modified.is_none() {
            times.modified = member
                .meta
                .modification_time()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|time| {
                    u32::try_from(time.as_secs())
                        .ok()
                        .map(|seconds| rars_rs::FileTimestamp::Unix {
                            seconds,
                            nanoseconds: time.subsec_nanos(),
                        })
                });
        }
        Ok([
            ("modified", times.modified),
            ("created", times.created),
            ("accessed", times.accessed),
        ]
        .into_iter()
        .filter_map(|(name, time)| time.map(|time| (name.to_string(), time.unix_nanoseconds())))
        .collect())
    }

    /// Metadata/settings the current rewrite implementation cannot preserve.
    /// This is a conservative metadata check, not a payload integrity test.
    fn rewrite_preservation_issues(&self) -> Vec<String> {
        self.archive.rewrite_preservation_issues()
    }

    /// Stops at the first volume missing or unreadable rather than raising, so clean-up gets what is there.
    fn volume_paths(&self, py: Python<'_>) -> PyResult<Vec<PathBuf>> {
        let Some(first_path) = &self.path else {
            return Err(PyValueError::new_err(
                "an archive opened from bytes or a file object has no volume paths",
            ));
        };
        if !self.archive.is_volume() {
            return Ok(vec![first_path.clone()]);
        }
        if !starts_set(&self.archive) {
            return Err(PyValueError::new_err(
                "volume_paths names a set's volumes from its first volume, and this is a later one",
            ));
        }
        let options = self.extraction_options(self.options.as_ref(), self.password.as_deref());
        let mut paths = vec![first_path.clone()];
        let mut index = 0;
        let readable = with_volume_sources(
            py,
            &self.archive,
            options,
            || {
                index += 1;
                let path = self
                    .archive
                    .volume_path(first_path, index)
                    .filter(|path| path.is_file());
                paths.extend(path.clone());
                Ok(path.map(ArchiveInput::Path))
            },
            |volumes| {
                Ok(1 + volumes_to_last(&self.archive, volumes)
                    .take_while(Result::is_ok)
                    .count())
            },
        )?
        .map_err(map_error)?;
        paths.truncate(readable);
        Ok(paths)
    }

    #[getter]
    fn sfx_offset(&self) -> usize {
        self.archive.sfx_offset()
    }

    #[getter]
    fn family(&self) -> String {
        family_name(self.archive.family()).to_string()
    }

    #[getter]
    fn is_volume(&self) -> bool {
        self.archive.is_volume()
    }

    #[getter]
    fn volume_number(&self) -> Option<u64> {
        self.archive.volume_number()
    }

    #[getter]
    fn is_first_volume(&self) -> Option<bool> {
        self.archive.is_first_volume()
    }

    #[getter]
    fn volume_naming(&self) -> &'static str {
        match self.archive.volume_naming() {
            rars_rs::volume_name::VolumeNaming::Part => "part",
            rars_rs::volume_name::VolumeNaming::Old => "old",
        }
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        false
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let list = PyList::new(py, self.listing(py)?.infos.clone())?;
        Ok(list.call_method0("__iter__")?.unbind())
    }
}

impl RarFile {
    fn with_set(mut self, first_volume_only: bool, volumes: Option<Py<PyTuple>>) -> Self {
        self.first_volume_only = first_volume_only;
        self.volumes = volumes;
        self
    }

    /// Runs `run` over the set, its later volumes from `volumes`, else found by name beside the first.
    fn extract_set<T: Send>(
        &self,
        py: Python<'_>,
        volumes: Option<&Bound<'_, PyAny>>,
        options: rars_rs::ArchiveReadOptions<'_>,
        run: impl FnOnce(
                &mut (dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send),
            ) -> rars_rs::Result<T>
            + Send,
    ) -> PyResult<T> {
        let stored = self
            .volumes
            .as_ref()
            .map(|volumes| volumes.bind(py).as_any());
        if let Some(volumes) = volumes.or(stored) {
            let iterator = volumes.try_iter()?.unbind();
            return with_volume_sources(
                py,
                &self.archive,
                options,
                || {
                    Python::attach(|py| {
                        let Some(volume) = iterator.bind(py).clone().next() else {
                            return Ok(None);
                        };
                        Ok(Some(archive_input(&volume?, options.cancellation)?))
                    })
                },
                run,
            )?
            .map_err(map_error);
        }
        let Some(first_path) = &self.path else {
            let mut asked = false;
            let result = with_volume_sources(
                py,
                &self.archive,
                options,
                || {
                    asked = true;
                    Ok(None)
                },
                run,
            )?;
            return result.map_err(|error| {
                if asked {
                    map_error_with(
                        error,
                        "; an archive opened from bytes or a file object cannot find its later volumes, so pass them as volumes=",
                    )
                } else {
                    map_error(error)
                }
            });
        };
        let mut index = 0;
        let mut missing = None;
        let result = with_volume_sources(
            py,
            &self.archive,
            options,
            || {
                index += 1;
                let path = self.archive.volume_path(first_path, index);
                if let Some(path) = path.as_ref().filter(|path| !path.is_file()) {
                    missing = Some(path.clone());
                    return Ok(None);
                }
                Ok(path.map(ArchiveInput::Path))
            },
            run,
        )?;
        result.map_err(|error| match &missing {
            Some(path) if set_fault(&error, is_missing_volume).is_some() => with_attribute(
                py,
                map_error_with(error, &format!(": {}", path.display())),
                "path",
                path,
            ),
            _ => map_error(error),
        })
    }

    /// Reads the set's headers first when every volume is already to hand, so progress has a total from its first event.
    fn begin_set(
        &self,
        py: Python<'_>,
        volumes: Option<&Bound<'_, PyAny>>,
        options: rars_rs::ArchiveReadOptions<'_>,
        progress: &ReadProgress,
        chosen: &dyn Fn(usize) -> bool,
    ) {
        // A volume not there yet leaves the total to arrive with the last volume.
        match volumes {
            None if self.lists_later_volumes() && !self.first_volume_only => {
                if let Ok(listing) = self.listing(py) {
                    progress.list(&listing.infos, chosen);
                }
            }
            Some(volumes) if starts_set(&self.archive) && rereadable(volumes) => {
                let listing = self.extract_set(py, Some(volumes), options, |later| {
                    list_later_volumes(
                        &self.archive,
                        &self.first,
                        later,
                        self.encoding,
                        &self.identity,
                    )
                });
                if let Ok(listing) = listing {
                    progress.list(&listing.infos, chosen);
                }
            }
            _ => {}
        }
        progress.begin(&self.archive, chosen, false);
    }

    /// A member that continues past, or starts after, the first volume needs the set to read.
    fn needs_later_volumes(&self, index: usize) -> bool {
        self.first
            .infos
            .get(index)
            .is_none_or(|info| info.is_split_after)
    }

    /// Lists the set only when asked, so opening never waits for volumes that may still be arriving.
    fn listing(&self, py: Python<'_>) -> PyResult<&SetListing> {
        if self.first_volume_only || !self.lists_later_volumes() {
            return Ok(&self.first);
        }
        if let Some(whole) = self.whole.get() {
            return Ok(whole);
        }
        let options = self.extraction_options(self.options.as_ref(), self.password.as_deref());
        let (first, archive, identity, encoding) =
            (&self.first, &self.archive, &self.identity, self.encoding);
        let whole = self.extract_set(py, None, options, |volumes| {
            list_later_volumes(archive, first, volumes, encoding, identity)
        })?;
        Ok(self.whole.get_or_init(|| whole))
    }

    /// A set's later volumes are read here, as their headers describe the set's members.
    fn rewrite_source(
        &self,
        py: Python<'_>,
        volumes: Option<&Bound<'_, PyAny>>,
        password: Option<&[u8]>,
    ) -> PyResult<(Vec<rars_rs::Archive>, Vec<SourceMember>)> {
        let options = self.extraction_options(self.options.as_ref(), password);
        let later = if !self.archive.is_volume() {
            Vec::new()
        } else if self.first_volume_only {
            return Err(PyValueError::new_err(
                "a RarFile opened with first_volume_only=True cannot rewrite its volume set; open it without first_volume_only",
            ));
        } else {
            self.extract_set(py, volumes, options, |volumes| {
                volumes_to_last(&self.archive, volumes).collect()
            })?
        };
        // Releases the GIL, which a file-object source takes from inside its lock.
        let members = py
            .detach(|| {
                let mut read = std::iter::once(&self.archive)
                    .chain(&later)
                    .map(|volume| {
                        Ok((
                            volume.member_comments_with_options(options)?,
                            volume.legacy_symlink_targets_with_options(options)?,
                            volume.member_comment_encryption(),
                        ))
                    })
                    .collect::<rars_rs::Result<Vec<_>>>()?;
                Ok::<_, rars_rs::Error>(
                    self.archive
                        .volume_set_members(&later)?
                        .into_iter()
                        .map(|set_member| {
                            let (comments, links, encrypted) = &mut read[set_member.volume];
                            let index = set_member.index_in_volume;
                            SourceMember {
                                member: set_member.member,
                                comment: comments[index].take(),
                                legacy_link: links[index].take(),
                                comment_encrypted: encrypted[index],
                            }
                        })
                        .collect(),
                )
            })
            .map_err(map_error)?;
        Ok((later, members))
    }

    /// Only a set's first volume knows where the set starts, and bytes alone can't find the rest.
    fn lists_later_volumes(&self) -> bool {
        self.archive.is_volume()
            && starts_set(&self.archive)
            && (self.path.is_some() || self.volumes.is_some())
    }

    /// Headers of later volumes aren't kept, so a later member's metadata reparses its volume.
    fn member_volume(
        &self,
        py: Python<'_>,
        index: usize,
        options: rars_rs::ArchiveReadOptions<'_>,
    ) -> PyResult<(Cow<'_, rars_rs::Archive>, usize)> {
        if index < self.first.infos.len() {
            return Ok((Cow::Borrowed(&self.archive), index));
        }
        let listing = self.listing(py)?;
        let volume = listing.infos[index].volume;
        let archive = self.extract_set(py, None, options, |volumes| {
            volumes.nth(volume - 1).unwrap_or_else(|| {
                Err(rars_rs::Error::InVolume {
                    number: volume + 1,
                    source: Box::new(rars_rs::Error::MissingVolume),
                })
            })
        })?;
        Ok((Cow::Owned(archive), listing.places[index].index_in_volume))
    }

    /// A later member's end comes from the listing; a first-volume member's is found while reading.
    fn selection_end(&self, selected: &HashSet<usize>) -> SelectionEnd {
        let Some(&last) = selected.iter().max() else {
            return SelectionEnd::default();
        };
        let listing = match self.first.infos.get(last) {
            Some(_) => &self.first,
            None => match self.whole.get() {
                Some(whole) => whole,
                None => return SelectionEnd::default(),
            },
        };
        SelectionEnd {
            name: Some(listing.infos[last].orig_filename_bytes.to_vec()),
            last_volume: listing.places[last]
                .last_volume
                .filter(|&volume| volume > 0),
        }
    }

    /// One pass over the set, so solid history and split members decode once.
    #[allow(clippy::too_many_arguments)]
    fn extract_from_set(
        &self,
        py: Python<'_>,
        volumes: Option<&Bound<'_, PyAny>>,
        options: rars_rs::ArchiveReadOptions<'_>,
        selected: Option<&HashSet<usize>>,
        out_dir: &Path,
        mode: OutputMode,
        progress: Option<&Arc<ReadProgress>>,
    ) -> PyResult<Extracted> {
        let first = &self.archive;
        let chosen = |index: usize| selected.is_none_or(|selected| selected.contains(&index));
        if let Some(progress) = progress {
            self.begin_set(py, volumes, options, progress, &chosen);
        }
        self.extract_set(py, volumes, options, |volumes| {
            let mut volumes = tracked(progress.map(Arc::as_ref), volumes, &chosen);
            let outputs = std::cell::RefCell::new(ExtractOutputs::new(
                out_dir,
                first.family(),
                options,
                mode,
                progress.cloned(),
            ));
            let open = |meta: &rars_rs::ExtractedEntryMeta| outputs.borrow_mut().open(meta);
            let link = |meta: &rars_rs::ExtractedEntryMeta, link: ExtractedLink<'_>| {
                outputs.borrow_mut().link(meta, link)
            };
            let result = match selected {
                Some(selected) => extract_arriving_selected(
                    first,
                    &mut *volumes,
                    options,
                    selected,
                    self.selection_end(selected),
                    |_, meta| open(meta),
                    link,
                ),
                None => rars_rs::output_links::extract_arriving_with_links(
                    first, volumes, options, open, link,
                ),
            };
            outputs.into_inner().finish(result)
        })
    }

    /// One pass over the set, so solid history and split members decode once.
    fn read_from_set(
        &self,
        py: Python<'_>,
        volumes: Option<&Bound<'_, PyAny>>,
        options: rars_rs::ArchiveReadOptions<'_>,
        indices: &[usize],
        progress: Option<&Arc<ReadProgress>>,
    ) -> PyResult<Vec<Option<Vec<u8>>>> {
        let selected: HashSet<usize> = indices.iter().copied().collect();
        let buffers = Mutex::new(HashMap::new());
        let first = &self.archive;
        let chosen = |index: usize| selected.contains(&index);
        if let Some(progress) = progress {
            self.begin_set(py, volumes, options, progress, &chosen);
        }
        self.extract_set(py, volumes, options, |volumes| {
            let mut volumes = tracked(progress.map(Arc::as_ref), volumes, &chosen);
            extract_arriving_selected(
                first,
                &mut *volumes,
                options,
                &selected,
                self.selection_end(&selected),
                |index, meta| {
                    if meta.is_directory {
                        return Ok(Box::new(io::sink()));
                    }
                    let buffer = Arc::new(Mutex::new(Vec::new()));
                    buffers
                        .lock()
                        .expect("read buffers lock poisoned")
                        .insert(index, Arc::clone(&buffer));
                    let buffer = Box::new(SharedBuffer(buffer));
                    Ok(match progress {
                        Some(progress) => progress.counted(&meta.name, buffer),
                        None => buffer,
                    })
                },
                |_, _| Ok(()),
            )
        })?;
        let buffers = buffers.into_inner().expect("read buffers lock poisoned");
        Ok(indices
            .iter()
            .map(|index| {
                buffers
                    .get(index)
                    .map(|buffer| buffer.lock().expect("read buffer lock poisoned").clone())
            })
            .collect())
    }

    fn read_indices(
        &self,
        py: Python<'_>,
        indices: &[usize],
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<Option<Vec<u8>>>> {
        let password = py_password(password)?.or_else(|| self.password.clone());
        let progress = ReadProgress::new(options, "reading");
        let options = watched(
            &progress,
            self.extraction_options(options, password.as_deref()),
        );
        let data = if indices.iter().any(|&index| self.needs_later_volumes(index)) {
            self.read_from_set(py, volumes, options, indices, progress.as_ref())
        } else {
            let selected: HashSet<usize> = indices.iter().copied().collect();
            if let Some(progress) = &progress {
                progress.begin(&self.archive, &|index| selected.contains(&index), true);
            }
            py.detach(|| match &progress {
                None => self.archive.read_members_at_with_options(indices, options),
                Some(progress) => {
                    read_counted(&self.archive, &selected, indices, options, progress)
                }
            })
            .map_err(map_error)
        };
        finished(&progress, data)
    }

    fn resolve_index(&self, py: Python<'_>, member: &Bound<'_, PyAny>) -> PyResult<usize> {
        if let Ok(info) = member.extract::<PyRef<'_, RarInfo>>() {
            if !info
                .archive_identity
                .as_ref()
                .is_some_and(|identity| Arc::ptr_eq(identity, &self.identity))
            {
                return Err(PyValueError::new_err(
                    "RarInfo belongs to a different archive",
                ));
            }
            return Ok(info.member_index);
        }
        // The first volume answers without looking for later volumes, which may not exist yet.
        if let Some(index) = self.find(&self.first, member)? {
            return Ok(index);
        }
        let listing = self.listing(py)?;
        if !std::ptr::eq(listing, &self.first) {
            if let Some(index) = self.find(listing, member)? {
                return Ok(index);
            }
        }
        let name = match member.extract::<String>() {
            Ok(text) => text,
            Err(_) => String::from_utf8_lossy(&member_name_bytes(member)?).into_owned(),
        };
        Err(self.not_found(name))
    }

    fn find(&self, listing: &SetListing, member: &Bound<'_, PyAny>) -> PyResult<Option<usize>> {
        if self.encoding.is_some() {
            if let Ok(text) = member.extract::<String>() {
                let names = listing
                    .names
                    .get_or_init(|| MemberNames::new(&listing.infos, true));
                return match names.decoded.get(&text) {
                    Some(Some(index)) => Ok(Some(*index)),
                    Some(None) => Err(PyValueError::new_err(
                        "ambiguous decoded name; select an entry by its RarInfo or original bytes",
                    )),
                    None => Ok(None),
                };
            }
        }
        let name = member_name_bytes(member)?;
        // Retain reverse lookup's constant-time last-entry case without
        // building an index for callers reading only that one entry.
        if listing
            .infos
            .last()
            .is_some_and(|info| info.orig_filename_bytes.as_ref() == name)
        {
            return Ok(Some(listing.infos.len() - 1));
        }
        let names = listing
            .names
            .get_or_init(|| MemberNames::new(&listing.infos, self.encoding.is_some()));
        Ok(names.raw.get(name.as_slice()).copied())
    }

    /// A set listed from its first volume alone can't find members that start later.
    fn not_found(&self, name: String) -> PyErr {
        if !self.archive.is_volume() || self.whole.get().is_some() {
            return PyKeyError::new_err(name);
        }
        if self.first_volume_only {
            return PyKeyError::new_err(format!(
                "{name} is not in the first volume; members that start in a later volume cannot be selected with first_volume_only=True"
            ));
        }
        if self.path.is_some() || self.volumes.is_some() {
            return PyKeyError::new_err(name);
        }
        PyKeyError::new_err(format!(
            "{name} is not in the first volume; an archive opened from bytes or a file object lists its later volumes only when given them as volumes="
        ))
    }

    fn extraction_options<'a>(
        &self,
        settings: Option<&'a ReadOptions>,
        password: Option<&'a [u8]>,
    ) -> rars_rs::ArchiveReadOptions<'a> {
        let mut options = python_read_options(settings, password);
        options.legacy_name_encoding = options.legacy_name_encoding.or(self.encoding);
        options
    }

    fn from_bytes(
        py: Python<'_>,
        bytes: Vec<u8>,
        password: Option<Vec<u8>>,
        options: Option<&ReadOptions>,
    ) -> PyResult<Self> {
        Self::parse(py, password, options, |options| {
            rars_rs::ArchiveReader::read_owned_with_options(bytes, options)
        })
    }

    fn from_path(
        py: Python<'_>,
        path: PathBuf,
        password: Option<Vec<u8>>,
        options: Option<&ReadOptions>,
    ) -> PyResult<Self> {
        // Payload reads reopen the path, so retain its meaning across chdir.
        let path = std::path::absolute(path)?;
        let mut file = Self::parse(py, password, options, |options| {
            rars_rs::ArchiveReader::read_path_with_options(&path, options)
        })?;
        file.path = Some(path);
        Ok(file)
    }

    fn parse(
        py: Python<'_>,
        password: Option<Vec<u8>>,
        options: Option<&ReadOptions>,
        read: impl Send + FnOnce(rars_rs::ArchiveReadOptions<'_>) -> rars_rs::Result<rars_rs::Archive>,
    ) -> PyResult<Self> {
        let archive = py
            .detach(|| read(python_read_options(options, password.as_deref())))
            .map_err(map_open_error)?;
        let encoding = options.and_then(|settings| settings.encoding);
        let identity = Arc::new(());
        let infos = archive
            .members()
            .enumerate()
            .map(|(index, member)| {
                let filename =
                    String::from_utf8_lossy(&member.decoded_name(encoding)?).into_owned();
                let mut info = info_from_member_named(member, filename);
                info.member_index = index;
                info.archive_identity = Some(identity.clone());
                Ok(info)
            })
            .collect::<rars_rs::Result<Vec<_>>>()
            .map_err(map_error)?;
        Ok(Self {
            identity,
            encoding,
            archive,
            path: None,
            password,
            options: options.cloned(),
            volumes: None,
            first_volume_only: false,
            first: SetListing::new(infos),
            whole: OnceLock::new(),
        })
    }
}

/// The Python face of [`rars_rs::Builder`]. Everything about choosing a writer,
/// mapping members onto entry types and splitting volumes lives in the core
/// crate; what is left here is argument conversion and the exception types
/// Python callers catch.
#[pyclass(module = "rars")]
#[derive(Debug, Clone)]
struct RarBuilder {
    inner: rars_rs::Builder,
    format: rars_rs::ArchiveVersion,
    rewrite: Option<RewriteInput>,
    resources: rars_rs::WriterResources,
}

enum PythonVolumes {
    Tracked(rars_rs::WriterVolumes),
    Untracked(Vec<Vec<u8>>),
}
impl PythonVolumes {
    fn len(&self) -> usize {
        match self {
            Self::Tracked(v) => v.volumes().len(),
            Self::Untracked(v) => v.len(),
        }
    }
    fn part(&self, index: usize) -> &[u8] {
        match self {
            Self::Tracked(v) => v.volumes()[index].as_bytes(),
            Self::Untracked(v) => &v[index],
        }
    }
}

/// A source member with the metadata read from its volume besides the payload.
struct SourceMember {
    member: rars_rs::ArchiveMember,
    comment: Option<Vec<u8>>,
    legacy_link: Option<Vec<u8>>,
    comment_encrypted: bool,
}

/// Original identity follows edits; verified payload sources belong to one write.
#[derive(Debug, Clone)]
struct RewriteInput {
    archive: rars_rs::Archive,
    later_volumes: Vec<rars_rs::Archive>,
    password: Option<Vec<u8>>,
    options: Option<ReadOptions>,
    members: HashMap<usize, RewriteMember>,
    directory: Option<PathBuf>,
    max_staged_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct RewriteMember {
    index: usize,
    size: u64,
}

impl RewriteInput {
    fn prepare<T>(
        &self,
        builder: &mut rars_rs::Builder,
        directory: &Path,
        progress: Option<Arc<PythonProgress>>,
        consume: impl FnOnce(&rars_rs::Builder) -> rars_rs::Result<T>,
    ) -> rars_rs::Result<T> {
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort_unstable_by_key(|(_, member)| member.index);
        let limit = match self.max_staged_bytes {
            Some(limit) => limit,
            None => members.iter().try_fold(0u64, |sum, (_, member)| {
                sum.checked_add(member.size)
                    .ok_or(rars_rs::Error::RewriteStagingLimitExceeded {
                        limit: u64::MAX,
                        required: u64::MAX,
                    })
            })?,
        };
        let indices: Vec<_> = members.iter().map(|(_, member)| member.index).collect();
        let mut options = python_read_options(self.options.as_ref(), self.password.as_deref());
        let joined = match (options.cancellation, &progress) {
            (Some(read), Some(progress)) => Some(read.joined(&progress.read_cancellation)),
            _ => None,
        };
        if let Some(cancellation) = joined.as_ref().or(progress
            .as_ref()
            .map(|progress| &progress.read_cancellation))
        {
            options = options.with_cancellation(cancellation);
        }
        self.archive.with_rewrite_sources_from_volumes(
            &self.later_volumes,
            &indices,
            options,
            &rars_rs::RewriteStaging {
                directory: self.directory.as_deref().unwrap_or(directory).to_path_buf(),
                max_staged_bytes: limit,
            },
            progress
                .clone()
                .map(|progress| progress as Arc<dyn rars_rs::WriteProgress>),
            |sources| {
                for ((id, _), source) in members.into_iter().zip(sources) {
                    builder.set_source_by_id(*id, source)?;
                }
                consume(builder)
            },
        )
    }
}

fn python_progress(
    callback: Option<&Bound<'_, PyAny>>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<Option<Arc<PythonProgress>>> {
    let callback = callback
        .map(|callback| {
            if !callback.is_callable() {
                return Err(PyValueError::new_err("progress must be callable"));
            }
            Ok(callback.clone().unbind())
        })
        .transpose()?;
    if callback.is_none() && cancellation.is_none() {
        return Ok(None);
    }
    Ok(Some(Arc::new(PythonProgress::new(callback, cancellation))))
}

/// Preserve the established Python argument exceptions for builder refusals.
#[derive(Debug, PartialEq, Eq)]
enum BuilderRefusal {
    NoSuchEntry,
    DuplicateName,
    Symlink,
    Other,
}

fn classify_builder_error(error: &rars_rs::Error) -> BuilderRefusal {
    match error.root_cause() {
        rars_rs::Error::EntryNotFound => BuilderRefusal::NoSuchEntry,
        rars_rs::Error::DuplicateEntry => BuilderRefusal::DuplicateName,
        rars_rs::Error::InputSymlink => BuilderRefusal::Symlink,
        _ => BuilderRefusal::Other,
    }
}

fn map_builder_error(error: rars_rs::Error) -> PyErr {
    match (classify_builder_error(&error), error.entry_context()) {
        (BuilderRefusal::NoSuchEntry, Some((name, _))) => {
            PyKeyError::new_err(String::from_utf8_lossy(name).into_owned())
        }
        (BuilderRefusal::DuplicateName, Some((name, _))) => PyValueError::new_err(format!(
            "duplicate archive entry name: {}",
            String::from_utf8_lossy(name)
        )),
        (BuilderRefusal::Symlink, Some((name, _))) => PyValueError::new_err(format!(
            "input '{}' is a symlink; refusing to follow it",
            String::from_utf8_lossy(name)
        )),
        _ => map_error(error),
    }
}

#[pymethods]
impl RarBuilder {
    #[new]
    #[pyo3(signature = (
        format = "rar50",
        compression = 3,
        store = false,
        solid = false,
        password = None,
        encrypt_headers = false,
        comment = None,
        recovery_percent = None,
        volume_size = None,
        filters = None,
        max_memory_bytes = None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        format: &str,
        compression: u8,
        store: bool,
        solid: bool,
        password: Option<&Bound<'_, PyAny>>,
        encrypt_headers: bool,
        comment: Option<&Bound<'_, PyAny>>,
        recovery_percent: Option<u64>,
        volume_size: Option<usize>,
        filters: Option<&Bound<'_, PyAny>>,
        max_memory_bytes: Option<u64>,
    ) -> PyResult<Self> {
        if filters.is_some() {
            return Err(PyNotImplementedError::new_err(
                "filter selection is not exposed yet; use the default writer filter policy",
            ));
        }
        let format = parse_version(format)?;
        Ok(Self {
            inner: rars_rs::Builder::new(format)
                .compression_level(Some(compression))
                .store(store)
                .solid(solid)
                .password(py_password(password)?)
                .header_encryption(encrypt_headers)
                .comment(py_optional_bytes(comment)?)
                .recovery_percent(recovery_percent)
                .volume_size(volume_size),
            format,
            rewrite: None,
            resources: max_memory_bytes.map_or_else(rars_rs::WriterResources::default, |limit| {
                rars_rs::WriterResources::default().with_max_memory_bytes(limit)
            }),
        })
    }

    /// Create a rewrite builder. Supported RAR1.3–4.x files retain
    /// native names, supported DOS timestamps, attributes, solid mode and
    /// supported data/header encryption.
    /// For RAR5/7, format,
    /// solid, data/header/comment encryption and archive metadata settings are
    /// retained; unknown or unsupported preservation fails before output.
    /// Explicit preserve=False converts to RAR5 level 3, non-solid and unencrypted.
    /// File contents, raw names, order, comments, directories, supported links
    /// and modification/creation/access times are copied in both modes.
    /// For an existing RarFile, its configured password is used. Preservation
    /// reuses it for encrypted output; conversion removes encryption.
    /// Input files, and a file object `source`, must remain open and unchanged until writing completes.
    #[staticmethod]
    /// Payload staging happens afresh during each write. staging_dir defaults
    /// to the output directory (current directory for to_bytes); max_staged_bytes
    /// defaults to the retained payloads' combined declared uncompressed size.
    ///
    /// `options` reads the source as `RarFile` does, replacing a `RarFile` source's own.
    /// A volume set rewrites into one archive with `preserve=False`, its later
    /// volumes taken from `volumes` as in `extractall`, else found by name. They are
    /// all read before this returns. Writing decodes every member up to the last one
    /// kept, removed ones included, so those must still be readable.
    #[pyo3(signature = (source, password = None, *, options = None, volumes = None, preserve = true, staging_dir = None, max_staged_bytes = None))]
    #[allow(clippy::too_many_arguments)]
    fn from_archive(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
        preserve: bool,
        staging_dir: Option<&Bound<'_, PyAny>>,
        max_staged_bytes: Option<u64>,
    ) -> PyResult<Self> {
        let archive = match source.extract::<PyRef<'_, RarFile>>() {
            Ok(archive) => RarFile {
                identity: archive.identity.clone(),
                encoding: options.map_or(archive.encoding, |options| options.encoding),
                archive: archive.archive.clone(),
                path: archive.path.clone(),
                password: archive.password.clone(),
                options: options.or(archive.options.as_ref()).cloned(),
                volumes: archive
                    .volumes
                    .as_ref()
                    .map(|volumes| volumes.clone_ref(py)),
                first_volume_only: archive.first_volume_only,
                first: SetListing::new(archive.first.infos.clone()),
                whole: OnceLock::new(),
            },
            Err(_) => RarFile::new(py, source, "r", password, options, false, None)?,
        };
        let password = archive.password.clone();
        if preserve {
            let issues = archive.archive.rewrite_preservation_issues();
            if !issues.is_empty() {
                let way_through = if archive.archive.is_volume() {
                    "use preserve=False to rewrite the volume set as one RAR5 archive"
                } else {
                    "use preserve=False for explicit RAR5 conversion"
                };
                return Err(UnsupportedRarFeature::new_err(format!(
                    "cannot preserve archive: {}; {way_through} (archive settings may be lost)",
                    issues.join("; ")
                )));
            }
        }
        let (later_volumes, members) = archive.rewrite_source(py, volumes, password.as_deref())?;
        let inner = if preserve {
            archive
                .archive
                .preserving_builder(password.as_deref())
                .map_err(map_error)?
        } else {
            rars_rs::Builder::new(rars_rs::ArchiveVersion::Rar50).compression_level(Some(3))
        };
        let format = inner.format();
        let legacy_preservation = preserve && format.family() != rars_rs::ArchiveFamily::Rar50Plus;
        let mut builder = Self {
            inner: inner
                .comment(archive.read_comment(py, None, archive.options.as_ref())?)
                .allow_duplicate_names(true),
            format,
            resources: rars_rs::WriterResources::default(),
            rewrite: Some(RewriteInput {
                archive: archive.archive.clone(),
                later_volumes: later_volumes.clone(),
                password: password.clone(),
                options: archive.options.clone(),
                members: HashMap::new(),
                directory: staging_dir.map(|path| py_path_buf(py, path)).transpose()?,
                max_staged_bytes,
            }),
        };
        for (
            member_index,
            SourceMember {
                member,
                comment,
                legacy_link,
                comment_encrypted,
            },
        ) in members.into_iter().enumerate()
        {
            let legacy_unicode_name = if legacy_preservation {
                match &member.detail {
                    rars_rs::ArchiveMemberDetail::Rar15To40 { unicode_name, .. } => {
                        unicode_name.clone()
                    }
                    _ => None,
                }
            } else {
                None
            };
            let legacy_extended_times = if legacy_preservation {
                match &member.detail {
                    rars_rs::ArchiveMemberDetail::Rar15To40 { extended_times, .. }
                        if !extended_times.is_empty() =>
                    {
                        Some(extended_times.clone())
                    }
                    _ => None,
                }
            } else {
                None
            };
            let file_times = if legacy_preservation {
                None
            } else {
                member.file_times().map_err(map_error)?
            };
            let converted_name = (!legacy_preservation
                && member.meta.family != rars_rs::ArchiveFamily::Rar50Plus)
                .then(|| member.decoded_name(archive.encoding).map(Cow::into_owned))
                .transpose()
                .map_err(map_error)?;
            let link = member.supported_redirection().cloned();
            let retained_link = link.as_ref().map(|_| member.clone());
            let info = member.meta;
            // A builder mode is Unix metadata, not generic archive attributes.
            // Reuse extraction's host rules: e.g. legacy host 1 is DOS, but
            // RAR5 host 1 is Unix. DOS 0x20 must not become Unix mode 0040.
            let attr_source = info.attr_source();
            let output_name = match converted_name {
                Some(name) if attr_source == rars_rs::AttrSource::Unix => {
                    rars_rs::builder::validate_entry_name(name.clone())
                        .map_err(map_builder_error)?;
                    rars_rs::filename::encode_rar50(&name).into_owned()
                }
                Some(name) => name,
                None => info.name.clone(),
            };
            let unix_type = info.file_attr & 0o170000;
            let unsupported_type = attr_source == rars_rs::AttrSource::Unix
                && !matches!(unix_type, 0 | 0o100000)
                && !(info.is_directory && unix_type == 0o040000);
            let reparse_point =
                attr_source == rars_rs::AttrSource::Dos && info.file_attr & 0x400 != 0;
            if link.is_none()
                && legacy_link.is_none()
                && (info.is_redirection
                    || unsupported_type
                    || reparse_point
                    || (info.is_directory && info.unpacked_size != 0))
            {
                return Err(UnsupportedRarFeature::new_err(format!(
                    "cannot rewrite special entry {:?}: its type or contents cannot be preserved",
                    String::from_utf8_lossy(&info.name)
                )));
            }
            let mode =
                (attr_source == rars_rs::AttrSource::Unix).then_some(if legacy_preservation {
                    info.file_attr as u32
                } else {
                    (info.file_attr & 0o7777) as u32
                });
            // Reuse CLI extraction's local-zone policy for legacy DOS times,
            // including the extended odd second, before writing RAR5 Unix time.
            let modified = (!legacy_preservation)
                .then(|| info.modification_time())
                .flatten()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
            let mtime = if legacy_preservation {
                info.file_time
            } else {
                modified
                    .map(|duration| u32::try_from(duration.as_secs()))
                    .transpose()
                    .map_err(|_| {
                        PyValueError::new_err("modification time exceeds the RAR5 timestamp range")
                    })?
            };
            if let Some(member) = retained_link {
                builder
                    .inner
                    .add_archive_redirection(&member)
                    .map_err(map_builder_error)?;
            } else if let Some(target) = legacy_link {
                builder
                    .inner
                    .add_unix_symlink(
                        output_name.clone(),
                        if legacy_preservation {
                            target
                        } else {
                            rars_rs::filename::encode_rar50(&target).into_owned()
                        },
                        false,
                        mtime,
                        mode,
                    )
                    .map_err(map_builder_error)?;
            } else if info.is_directory {
                builder
                    .inner
                    .add_directory(output_name.clone(), mtime, mode)
                    .map_err(map_builder_error)?;
            } else {
                // The per-write builder replaces this placeholder after a single
                // verified traversal. Never decode individual members on reopen.
                let source = rars_rs::EntrySource::from_opener(info.unpacked_size, || {
                    Err(rars_rs::Error::InvalidArgument(
                        "rewrite payload was not staged",
                    ))
                });
                builder
                    .inner
                    .add_source(output_name.clone(), source, mtime, mode)
                    .map_err(map_builder_error)?;
                builder.rewrite.as_mut().unwrap().members.insert(
                    builder.inner.member_ids().last().unwrap(),
                    RewriteMember {
                        index: member_index,
                        size: info.unpacked_size,
                    },
                );
            }
            let id = builder.inner.member_ids().last().unwrap();
            builder
                .inner
                .set_file_comment_by_id(id, comment)
                .map_err(map_builder_error)?;
            if let Some(time) = modified.filter(|time| time.subsec_nanos() != 0) {
                builder
                    .inner
                    .set_mtime_nanoseconds_by_id(id, time.subsec_nanos())
                    .map_err(map_builder_error)?;
            }
            if preserve {
                builder
                    .inner
                    .set_entry_encryption_by_id(
                        id,
                        if info.is_encrypted {
                            password.clone()
                        } else {
                            None
                        },
                        if comment_encrypted {
                            password.clone()
                        } else {
                            None
                        },
                    )
                    .map_err(map_builder_error)?;
            }
            if let Some(raw) = legacy_unicode_name {
                builder
                    .inner
                    .set_legacy_unicode_name_by_id(id, raw)
                    .map_err(map_builder_error)?;
            }
            if legacy_extended_times.is_some() {
                builder
                    .inner
                    .set_legacy_extended_times_by_id(id, legacy_extended_times)
                    .map_err(map_builder_error)?;
            }
            if file_times.is_some() {
                builder
                    .inner
                    .set_file_times_by_id(id, file_times)
                    .map_err(map_builder_error)?;
            }
            if attr_source == rars_rs::AttrSource::Dos {
                builder
                    .inner
                    .set_dos_attributes_by_id(id, info.file_attr)
                    .map_err(map_builder_error)?;
            }
        }
        builder.inner = builder.inner.allow_duplicate_names(false);
        Ok(builder)
    }

    #[pyo3(signature = (path, arcname = None))]
    fn add(
        &mut self,
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        arcname: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let path = py_path_buf(py, path)?;
        let base = match arcname {
            Some(name) => new_member_name(name)?,
            None => archive_base_name(&path)?,
        };
        self.inner.add_path(&path, &base).map_err(map_builder_error)
    }

    /// Add an explicit, possibly empty directory to RAR5/7 output.
    #[pyo3(signature = (arcname, mtime = None, mode = None))]
    fn add_directory(
        &mut self,
        arcname: &Bound<'_, PyAny>,
        mtime: Option<u32>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.inner
            .add_directory(new_member_name(arcname)?, mtime, mode)
            .map_err(map_builder_error)
    }

    #[pyo3(signature = (data, arcname, mtime = None, mode = None))]
    fn add_bytes(
        &mut self,
        data: &Bound<'_, PyAny>,
        arcname: &Bound<'_, PyAny>,
        mtime: Option<u32>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.inner
            .add_bytes(
                new_member_name(arcname)?,
                py_required_bytes(data)?,
                mtime,
                mode,
            )
            .map_err(map_builder_error)
    }

    /// Stable IDs in output order. Integer edit arguments select these IDs.
    fn member_ids(&self) -> Vec<usize> {
        self.inner.member_ids().collect()
    }

    fn remove(&mut self, name: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = self.edit_member_id(name)?;
        self.inner.remove_by_id(id).map_err(map_builder_error)?;
        if let Some(rewrite) = &mut self.rewrite {
            rewrite.members.remove(&id);
        }
        Ok(())
    }

    fn rename(&mut self, old: &Bound<'_, PyAny>, new: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = self.edit_member_id(old)?;
        self.inner
            .rename_by_id(id, new_member_name(new)?)
            .map_err(map_builder_error)
    }

    /// Queues a Unix symbolic link without reading or following the target.
    /// Target bytes use the RAR5 wire encoding and remain unchanged by renames.
    #[pyo3(signature = (arcname, target, *, target_is_directory=false, mtime=None, mode=None))]
    fn add_unix_symlink(
        &mut self,
        arcname: &Bound<'_, PyAny>,
        target: &Bound<'_, PyAny>,
        target_is_directory: bool,
        mtime: Option<u32>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.inner
            .add_unix_symlink(
                new_member_name(arcname)?,
                new_member_name(target)?,
                target_is_directory,
                mtime,
                mode,
            )
            .map_err(map_builder_error)
    }

    /// Sets complete timestamps from exact Unix nanoseconds.
    #[pyo3(signature = (member, *, modified_ns=None, created_ns=None, accessed_ns=None))]
    fn set_times(
        &mut self,
        member: &Bound<'_, PyAny>,
        modified_ns: Option<i128>,
        created_ns: Option<i128>,
        accessed_ns: Option<i128>,
    ) -> PyResult<()> {
        let times = rars_rs::FileTimes::from_unix_nanoseconds(modified_ns, created_ns, accessed_ns)
            .map_err(map_builder_error)?;
        let id = self.edit_member_id(member)?;
        self.inner
            .set_file_times_by_id(
                id,
                (times != rars_rs::FileTimes::default()).then_some(times),
            )
            .map_err(map_builder_error)
    }

    /// Sets or removes the comment attached to a queued member.
    #[pyo3(signature = (member, comment = None))]
    fn set_file_comment(
        &mut self,
        member: &Bound<'_, PyAny>,
        comment: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let id = self.edit_member_id(member)?;
        self.inner
            .set_file_comment_by_id(id, py_optional_bytes(comment)?)
            .map_err(map_builder_error)
    }

    #[pyo3(signature = (*, progress = None, cancellation = None))]
    fn to_bytes(
        &self,
        py: Python<'_>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Py<PyBytes>> {
        if self.resources.max_memory_bytes().is_none() {
            let bytes = self.detached(
                py,
                progress,
                cancellation,
                Path::new("."),
                |builder, progress| builder.to_bytes_with_progress(progress),
            )?;
            return Ok(PyBytes::new(py, &bytes).unbind());
        }
        let output = self.detached(
            py,
            progress,
            cancellation,
            Path::new("."),
            |builder, progress| builder.to_output(&self.resources, progress),
        )?;
        output
            .copy_with(|bytes| PyBytes::new(py, bytes).unbind())
            .map_err(map_error)
    }

    #[pyo3(signature = (path, *, progress = None, cancellation = None))]
    fn write(
        &self,
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<()> {
        let path = py_path_buf(py, path)?;
        let directory = output_directory(&path);
        self.detached(
            py,
            progress,
            cancellation,
            directory,
            |builder, progress| {
                builder.write_to_path_with_resources(
                    &path,
                    &self.resources.clone().with_temp_dir(directory),
                    progress,
                )
            },
        )
    }

    #[pyo3(signature = (first_path, *, progress = None, cancellation = None))]
    fn write_volumes(
        &self,
        py: Python<'_>,
        first_path: &Bound<'_, PyAny>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Vec<PathBuf>> {
        let first_path = py_path_buf(py, first_path)?;
        let parts = self.detached(
            py,
            progress,
            cancellation,
            output_directory(&first_path),
            |builder, progress| {
                if self.resources.max_memory_bytes().is_some() {
                    builder
                        .to_volume_output(
                            &self
                                .resources
                                .clone()
                                .with_temp_dir(output_directory(&first_path)),
                            progress,
                        )
                        .map(PythonVolumes::Tracked)
                } else {
                    builder
                        .build_volumes(progress)
                        .map(PythonVolumes::Untracked)
                }
            },
        )?;
        py.detach(|| {
            // A naming refusal must precede any replacement of existing parts.
            let paths = (0..parts.len())
                .map(|index| {
                    if matches!(
                        self.format,
                        rars_rs::ArchiveVersion::Rar50 | rars_rs::ArchiveVersion::Rar70
                    ) {
                        rar50_volume_part_path(&first_path, index, parts.len())
                    } else {
                        legacy_volume_part_path(&first_path, index)
                    }
                })
                .collect::<PyResult<Vec<_>>>()?;
            for (index, path) in paths.iter().enumerate() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return Err(map_error(rars_rs::Error::Cancelled));
                }
                fs::write(path, parts.part(index)).map_err(map_io_error)?;
            }
            Ok(paths)
        })
    }
}

impl RarBuilder {
    fn edit_member_id(&self, member: &Bound<'_, PyAny>) -> PyResult<usize> {
        if member.is_instance_of::<pyo3::types::PyInt>() {
            let id: usize = member
                .extract()
                .map_err(|_| PyKeyError::new_err("invalid member ID"))?;
            if !self.inner.member_ids().any(|candidate| candidate == id) {
                return Err(PyKeyError::new_err(id));
            }
            Ok(id)
        } else {
            self.inner
                .entry_id(&member_name_bytes(member)?)
                .map_err(map_builder_error)
        }
    }

    /// Run a core-builder call with the GIL released, wiring a Python callback
    /// to it as a progress sink. A callback that raises cancels the write, and
    /// its exception is re-raised here rather than the cancellation the core
    /// crate reports.
    fn detached<T, F>(
        &self,
        py: Python<'_>,
        callback: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        directory: &Path,
        run: F,
    ) -> PyResult<T>
    where
        T: Send,
        F: FnOnce(&rars_rs::Builder, Option<&dyn rars_rs::WriteProgress>) -> rars_rs::Result<T>
            + Send,
    {
        let progress = python_progress(callback, cancellation)?;
        let rewrite = self.rewrite.clone();
        let worker = progress.clone();
        let result = py.detach(move || {
            let consume = |builder: &rars_rs::Builder| {
                run(
                    builder,
                    worker
                        .as_deref()
                        .map(|progress| progress as &dyn rars_rs::WriteProgress),
                )
            };
            if let Some(rewrite) = rewrite {
                let mut builder = self.inner.clone();
                rewrite.prepare(&mut builder, directory, worker.clone(), consume)
            } else {
                consume(&self.inner)
            }
        });
        if let Some(error) = progress.as_ref().and_then(|progress| progress.take_error()) {
            return Err(error);
        }
        result.map_err(map_error)
    }
}

fn output_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn check_python_cancellation(cancellation: Option<&CancellationToken>) -> PyResult<()> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(PyInterruptedError::new_err("operation cancelled"));
    }
    Ok(())
}

fn py_input_bytes_with_cancellation(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<Vec<u8>> {
    check_python_cancellation(cancellation)?;
    let path = match archive_input(source, cancellation.map(|token| &token.inner))? {
        ArchiveInput::Bytes(bytes) => {
            check_python_cancellation(cancellation)?;
            return Ok(bytes);
        }
        ArchiveInput::Reader(PyFileReader(file)) => {
            let file = file.bind(py);
            file.call_method1("seek", (0,))?;
            return py_read_to_end(file, cancellation.map(|token| &token.inner));
        }
        ArchiveInput::Path(path) => path,
    };
    py.detach(|| {
        use std::io::Read;
        check_python_cancellation(cancellation)?;
        let mut file = fs::File::open(path).map_err(map_io_error)?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            check_python_cancellation(cancellation)?;
            let count = match file.read(&mut buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result.map_err(map_io_error)?,
            };
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        check_python_cancellation(cancellation)?;
        Ok(bytes)
    })
}

#[pyclass(frozen, module = "rars")]
struct PasswordCheck {
    #[pyo3(get)]
    correct: Option<Py<PyAny>>,
    undetermined: Vec<Py<PyAny>>,
    #[pyo3(get)]
    archive: Option<Py<RarFile>>,
    #[pyo3(get)]
    needs_password: bool,
}

#[pymethods]
impl PasswordCheck {
    #[getter]
    fn undetermined<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        PyList::new(
            py,
            self.undetermined.iter().map(|candidate| candidate.bind(py)),
        )
    }
}

/// Only the signature at offset 0; a file object is read from its position and put back.
#[pyfunction]
fn is_rarfile(py: Python<'_>, source: &Bound<'_, PyAny>) -> PyResult<bool> {
    with_probe_reader(py, source, |reader| {
        let mut prefix = Vec::with_capacity(8);
        io::Read::read_to_end(&mut io::Read::take(reader, 8), &mut prefix)?;
        Ok(rars_rs::detect_archive_family(&prefix).is_some())
    })
}

/// Finds an archive start the way `RarFile` does, so the two agree on what opens.
#[pyfunction]
fn is_rarfile_sfx(py: Python<'_>, source: &Bound<'_, PyAny>) -> PyResult<bool> {
    with_probe_reader(py, source, |reader| {
        let mut scan = Vec::new();
        let limit = rars_rs::SFX_SCAN_LIMIT + rars_rs::detect::RAR50_SIGNATURE.len();
        io::Read::read_to_end(&mut io::Read::take(reader, limit as u64), &mut scan)?;
        Ok(rars_rs::find_archive_start(&scan, rars_rs::SFX_SCAN_LIMIT).is_some())
    })
}

/// Any OSError, including a failed tell or seek, is not RAR: a file can vanish mid-job.
fn with_probe_reader(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    probe: impl FnOnce(&mut dyn io::Read) -> io::Result<bool> + Send,
) -> PyResult<bool> {
    match probe_source(py, source, probe) {
        Err(error) if error.is_instance_of::<PyOSError>(py) => Ok(false),
        result => result,
    }
}

/// Dispatches as `zipfile.is_zipfile` does, so a file object that can't tell or seek is not RAR.
fn probe_source(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    probe: impl FnOnce(&mut dyn io::Read) -> io::Result<bool> + Send,
) -> PyResult<bool> {
    if let Some(bytes) = py_bytes_like(source)? {
        refuse_bytes_path(source, &bytes)?;
        return Ok(probe(&mut &bytes[..])?);
    }
    if is_file_object(source)? {
        refuse_text_mode(source)?;
        let position = source.call_method0("tell")?;
        let found = probe(&mut PyFileReader(source.clone().unbind()));
        source.call_method1("seek", (position,))?;
        return Ok(found?);
    }
    if source.is_instance_of::<PyString>() || source.hasattr("__fspath__")? {
        let path = py_path_buf(py, source)?;
        // Python's open() refuses this before any I/O; File::open would report an OSError.
        if path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(PyValueError::new_err("embedded null byte"));
        }
        return py
            .detach(|| probe(&mut std::fs::File::open(path)?))
            .map_err(Into::into);
    }
    Err(PyTypeError::new_err(format!(
        "expected archive data (a bytes-like object), a path (str or os.PathLike) or a binary file object, not {}",
        type_name(source)
    )))
}

/// Candidates are taken one at a time, and none after the first proved correct.
#[pyfunction]
#[pyo3(signature = (source, candidates, *, options = None))]
fn check_password(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    candidates: &Bound<'_, PyAny>,
    options: Option<&ReadOptions>,
) -> PyResult<PasswordCheck> {
    check_read_options_cancellation(options)?;
    let read_options = python_read_options(options, None);
    let (probe, path) = match py_bytes_like(source)? {
        Some(bytes) => (
            py.detach(|| PasswordProbe::read_owned(bytes, read_options)),
            None,
        ),
        None => {
            let path = std::path::absolute(py_path_buf(py, source)?)?;
            (
                py.detach(|| PasswordProbe::read_path(&path, read_options)),
                Some(path),
            )
        }
    };
    let probe = probe.map_err(map_open_error)?;
    let needs_password = probe.needs_password();
    let mut winner = None;
    let mut undetermined = Vec::new();
    if needs_password {
        for candidate in candidates.try_iter()? {
            let candidate = candidate?;
            let password = py_password(Some(&candidate))?.unwrap_or_default();
            match py
                .detach(|| probe.check(&password, read_options))
                .map_err(map_error)?
            {
                PasswordVerdict::Correct => {
                    winner = Some((candidate.unbind(), password));
                    break;
                }
                PasswordVerdict::Undetermined => undetermined.push(candidate.unbind()),
                PasswordVerdict::Wrong => {}
            }
        }
    }
    let (archive, password) = match &winner {
        Some((_, password)) if probe.headers_encrypted() => {
            let archive = py
                .detach(|| probe.open(password, read_options))
                .map_err(map_error)?;
            (Some(archive), Some(password.clone()))
        }
        _ => (probe.into_archive(), None),
    };
    let archive = archive
        .map(|archive| -> PyResult<Py<RarFile>> {
            let mut file = RarFile::parse(py, password, options, |_| Ok(archive))?;
            file.path = path;
            Py::new(py, file.with_set(true, None))
        })
        .transpose()?;
    Ok(PasswordCheck {
        correct: winner.map(|(candidate, _)| candidate),
        undetermined,
        archive,
        needs_password,
    })
}

#[pyfunction]
#[pyo3(signature = (source, password = None, *, cancellation = None))]
fn repair(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<Vec<u8>> {
    check_python_cancellation(cancellation)?;
    let password = py_password(password)?;
    let bytes = py_input_bytes_with_cancellation(py, source, cancellation)?;
    py.detach(|| repair_core(&bytes, password.as_deref(), cancellation).map(|result| result.data))
        .map_err(map_error)
}

/// A parsing cancellation must not start the damaged-header fallback.
fn repair_core(
    bytes: &[u8],
    password: Option<&[u8]>,
    cancellation: Option<&CancellationToken>,
) -> rars_rs::Result<rars_rs::RecoveryRepairResult> {
    let mut options = rars_rs::ArchiveReadOptions::with_optional_password(password);
    options.cancellation = cancellation.map(|token| &token.inner);
    match rars_rs::ArchiveReader::read_with_options(bytes, options) {
        Ok(archive) => archive.repair_recovery_with_options(options),
        Err(error) if error.kind() == rars_rs::ErrorKind::Cancelled => Err(error),
        Err(_) => rars_rs::rar50::repair_inline_recovery_bytes_with_options(bytes, options),
    }
}

#[pyfunction]
#[pyo3(signature = (source, password = None, *, cancellation = None))]
fn repair_detailed(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<RepairResult> {
    check_python_cancellation(cancellation)?;
    let password = py_password(password)?;
    let bytes = py_input_bytes_with_cancellation(py, source, cancellation)?;
    py.detach(|| {
        let result = repair_core(&bytes, password.as_deref(), cancellation)?;
        Ok(RepairResult {
            data: result.data,
            report: result.report.into(),
        })
    })
    .map_err(map_error)
}

#[pyfunction]
#[pyo3(signature = (input, output, password = None, *, cancellation = None))]
fn repair_to_path(
    py: Python<'_>,
    input: &Bound<'_, PyAny>,
    output: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<()> {
    check_python_cancellation(cancellation)?;
    let output = py_path_buf(py, output)?;
    let password = py_password(password)?;
    let bytes = py_input_bytes_with_cancellation(py, input, cancellation)?;
    py.detach(|| {
        let result = repair_core(&bytes, password.as_deref(), cancellation)?;
        result.write_to_path(&output, cancellation.map(|token| &token.inner))
    })
    .map_err(map_error)
}

#[pymodule]
fn rars(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RarFile>()?;
    m.add_class::<RarInfo>()?;
    m.add_class::<RarBuilder>()?;
    m.add_class::<ProgressEvent>()?;
    m.add_class::<CancellationToken>()?;
    m.add_class::<ReadOptions>()?;
    m.add_class::<RepairReport>()?;
    m.add_class::<RepairResult>()?;
    m.add_class::<PasswordCheck>()?;
    m.add_function(wrap_pyfunction!(check_password, m)?)?;
    m.add_function(wrap_pyfunction!(is_rarfile, m)?)?;
    m.add_function(wrap_pyfunction!(is_rarfile_sfx, m)?)?;
    m.add_function(wrap_pyfunction!(repair, m)?)?;
    m.add_function(wrap_pyfunction!(repair_detailed, m)?)?;
    m.add_function(wrap_pyfunction!(repair_to_path, m)?)?;
    m.add("Error", py.get_type::<Error>())?;
    m.add("BadRarFile", py.get_type::<BadRarFile>())?;
    m.add("BadPassword", py.get_type::<BadPassword>())?;
    m.add("PasswordRequired", py.get_type::<PasswordRequired>())?;
    let missing_volume = py.get_type::<MissingVolume>();
    missing_volume.setattr("volume_number", py.None())?;
    missing_volume.setattr("path", py.None())?;
    m.add("MissingVolume", missing_volume)?;
    let checksum_error = py.get_type::<ChecksumError>();
    checksum_error.setattr("member", py.None())?;
    checksum_error.setattr("volume_number", py.None())?;
    m.add("ChecksumError", checksum_error)?;
    m.add(
        "UnsupportedRarFeature",
        py.get_type::<UnsupportedRarFeature>(),
    )?;
    m.add("NotRarFile", py.get_type::<NotRarFile>())?;
    m.add("UnsafeArchivePath", py.get_type::<UnsafeArchivePath>())?;
    m.add("UnsafeLinkWarning", py.get_type::<UnsafeLinkWarning>())?;
    for version in [
        "rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
    ] {
        m.add(version.to_ascii_uppercase(), version)?;
    }
    Ok(())
}

/// Archive data from a bytes-like object (anything `memoryview` accepts), or None for anything else.
fn py_bytes_like(value: &Bound<'_, PyAny>) -> PyResult<Option<Vec<u8>>> {
    if let Ok(bytes) = value.cast::<PyBytes>() {
        return Ok(Some(bytes.as_bytes().to_vec()));
    }
    if let Ok(bytes) = value.cast::<PyByteArray>() {
        return Ok(Some(bytes.to_vec()));
    }
    if value.is_instance_of::<PyString>() {
        return Ok(None);
    }
    let py = value.py();
    match py
        .import("builtins")?
        .getattr("memoryview")?
        .call1((value,))
    {
        Ok(view) => Ok(Some(
            view.call_method0("tobytes")?
                .cast::<PyBytes>()?
                .as_bytes()
                .to_vec(),
        )),
        Err(error) if error.is_instance_of::<PyTypeError>(py) => Ok(None),
        Err(error) => Err(error),
    }
}

fn py_required_bytes(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    py_bytes_like(value)?.ok_or_else(|| {
        PyTypeError::new_err(format!(
            "expected a bytes-like object, not {}",
            type_name(value)
        ))
    })
}

fn py_path_buf(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<PathBuf> {
    let os = py.import("os")?;
    let path = os.call_method1("fspath", (value,))?;
    path.extract::<PathBuf>()
}

/// An archive given as data, a path or a file object; a stream that can't seek arrives as data.
fn archive_input(
    value: &Bound<'_, PyAny>,
    cancellation: Option<&rars_rs::ReadCancellation>,
) -> PyResult<ArchiveInput> {
    let py = value.py();
    if let Some(bytes) = py_bytes_like(value)? {
        refuse_bytes_path(value, &bytes)?;
        return Ok(ArchiveInput::Bytes(bytes));
    }
    if let Some(input) = py_file_input(value, cancellation)? {
        return Ok(input);
    }
    if value.is_instance_of::<PyString>() || value.hasattr("__fspath__")? {
        return Ok(ArchiveInput::Path(std::path::absolute(py_path_buf(
            py, value,
        )?)?));
    }
    Err(PyTypeError::new_err(format!(
        "expected archive data (a bytes-like object), a path (str or os.PathLike) or a binary file object, not {}",
        type_name(value)
    )))
}

/// A binary file object, read on demand when it can seek and whole otherwise; None for anything else.
fn py_file_input(
    value: &Bound<'_, PyAny>,
    cancellation: Option<&rars_rs::ReadCancellation>,
) -> PyResult<Option<ArchiveInput>> {
    if !is_file_object(value)? {
        return Ok(None);
    }
    refuse_text_mode(value)?;
    if is_seekable(value)? {
        return Ok(Some(ArchiveInput::Reader(PyFileReader(
            value.clone().unbind(),
        ))));
    }
    Ok(Some(ArchiveInput::Bytes(py_read_to_end(
        value,
        cancellation,
    )?)))
}

fn refuse_text_mode(file: &Bound<'_, PyAny>) -> PyResult<()> {
    if file
        .call_method1("read", (0,))?
        .is_instance_of::<PyString>()
    {
        return Err(PyTypeError::new_err(
            "the file object is in text mode; open the archive with mode \"rb\"",
        ));
    }
    Ok(())
}

fn is_seekable(file: &Bound<'_, PyAny>) -> PyResult<bool> {
    match file.getattr("seekable") {
        Ok(seekable) => seekable.call0()?.is_truthy(),
        Err(_) => Ok(false),
    }
}

/// `mmap` has `read` too, but it is archive data.
fn is_file_object(value: &Bound<'_, PyAny>) -> PyResult<bool> {
    if value.is_instance_of::<PyString>()
        || value.hasattr("__fspath__")?
        || !value.hasattr("read")?
    {
        return Ok(false);
    }
    let py = value.py();
    match py
        .import("builtins")?
        .getattr("memoryview")?
        .call1((value,))
    {
        Ok(_) => Ok(false),
        Err(error) if error.is_instance_of::<PyTypeError>(py) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Bytes stay archive data, but a short value that names a file was meant as a path.
fn refuse_bytes_path(value: &Bound<'_, PyAny>, bytes: &[u8]) -> PyResult<()> {
    const SIGNATURES: [&[u8]; 2] = [b"Rar!", b"RE~^"];
    // Longer than any path a file system accepts.
    const LONGEST_PATH: usize = 4096;
    if bytes.len() > LONGEST_PATH
        || SIGNATURES
            .iter()
            .any(|signature| bytes.starts_with(signature))
    {
        return Ok(());
    }
    let py = value.py();
    let names_file = py
        .import("os.path")?
        .call_method1("isfile", (PyBytes::new(py, bytes),))
        .and_then(|found| found.is_truthy())
        .unwrap_or(false);
    if !names_file {
        return Ok(());
    }
    Err(PyTypeError::new_err(format!(
        "bytes are archive data, not a path; {} names a file, so pass it as str or os.PathLike",
        PyBytes::new(py, bytes).repr()?
    )))
}

const READ_CHUNK: usize = 64 * 1024;

fn py_read_to_end(
    file: &Bound<'_, PyAny>,
    cancellation: Option<&rars_rs::ReadCancellation>,
) -> PyResult<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        if cancellation.is_some_and(rars_rs::ReadCancellation::is_cancelled) {
            return Err(map_error(rars_rs::Error::Cancelled));
        }
        let chunk = file.call_method1("read", (READ_CHUNK,))?;
        let chunk = py_required_bytes(&chunk)?;
        if chunk.is_empty() {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk);
    }
}

/// Decoding threads read through this, so each call takes the GIL.
struct PyFileReader(Py<PyAny>);

impl io::Read for PyFileReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Python::attach(|py| {
            let chunk = self.0.bind(py).call_method1("read", (buffer.len(),))?;
            let chunk = py_required_bytes(&chunk)?;
            if chunk.len() > buffer.len() {
                return Err(PyValueError::new_err(format!(
                    "file object read returned {} bytes when asked for {}",
                    chunk.len(),
                    buffer.len()
                )));
            }
            buffer[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        })
        .map_err(io::Error::other)
    }
}

impl io::Seek for PyFileReader {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let (offset, whence) = match from {
            io::SeekFrom::Start(offset) => (offset as i128, 0),
            io::SeekFrom::Current(offset) => (offset as i128, 1),
            io::SeekFrom::End(offset) => (offset as i128, 2),
        };
        Python::attach(|py| {
            self.0
                .bind(py)
                .call_method1("seek", (offset, whence))?
                .extract::<u64>()
        })
        .map_err(io::Error::other)
    }
}

fn type_name(value: &Bound<'_, PyAny>) -> String {
    value
        .get_type()
        .name()
        .map_or_else(|_| "?".into(), |name| name.to_string())
}

fn py_password(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Vec<u8>>> {
    match value {
        None => Ok(None),
        Some(value) => {
            if let Ok(bytes) = value.extract::<Vec<u8>>() {
                Ok(Some(bytes))
            } else {
                Ok(Some(value.extract::<String>()?.into_bytes()))
            }
        }
    }
}

fn py_optional_bytes(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Vec<u8>>> {
    match value {
        None => Ok(None),
        Some(value) => {
            if let Ok(bytes) = value.extract::<Vec<u8>>() {
                Ok(Some(bytes))
            } else {
                Ok(Some(value.extract::<String>()?.into_bytes()))
            }
        }
    }
}

fn member_name_bytes(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(info) = value.extract::<PyRef<'_, RarInfo>>() {
        return Ok(info.orig_filename_bytes.to_vec());
    }
    if let Ok(bytes) = value.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    Ok(value.extract::<String>()?.into_bytes())
}

/// A `RarInfo` names a member that already exists, so it cannot name a new one.
fn new_member_name(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if value.is_instance_of::<RarInfo>() {
        return Err(PyTypeError::new_err(
            "a new member's name must be str or bytes, not RarInfo",
        ));
    }
    member_name_bytes(value)
}

fn check_read_options_cancellation(options: Option<&ReadOptions>) -> PyResult<()> {
    if options
        .and_then(|options| options.cancellation.as_ref())
        .is_some_and(rars_rs::ReadCancellation::is_cancelled)
    {
        return Err(map_error(rars_rs::Error::Cancelled));
    }
    Ok(())
}

trait Selection {
    fn contains_member(&self, index: usize, name: &[u8]) -> bool;
}

impl Selection for Vec<u8> {
    fn contains_member(&self, _index: usize, name: &[u8]) -> bool {
        self.as_slice() == name
    }
}

impl Selection for HashSet<Vec<u8>> {
    fn contains_member(&self, _index: usize, name: &[u8]) -> bool {
        self.contains(name)
    }
}

impl Selection for usize {
    fn contains_member(&self, index: usize, _name: &[u8]) -> bool {
        *self == index
    }
}

impl Selection for HashSet<usize> {
    fn contains_member(&self, index: usize, _name: &[u8]) -> bool {
        self.contains(&index)
    }
}

#[derive(Clone, Copy)]
struct OutputMode {
    overwrite: OverwritePolicy,
    in_place: bool,
    restore_times: bool,
    flatten: bool,
}

/// `True`, `False` or `"rename"`, as `extract` and `extractall` accept it.
struct Overwrite(OverwritePolicy);

impl<'a, 'py> FromPyObject<'a, 'py> for Overwrite {
    type Error = PyErr;

    fn extract(value: pyo3::Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(value) = value.cast::<pyo3::types::PyBool>() {
            return Ok(Self(if value.is_true() {
                OverwritePolicy::Always
            } else {
                OverwritePolicy::Never
            }));
        }
        match value.extract::<&str>() {
            Ok("rename") => Ok(Self(OverwritePolicy::Rename)),
            Ok(other) => Err(PyValueError::new_err(format!(
                "overwrite must be True, False or \"rename\", not {other:?}"
            ))),
            Err(_) => Err(pyo3::exceptions::PyTypeError::new_err(
                "overwrite must be True, False or \"rename\"",
            )),
        }
    }
}

/// Stages each file and publishes it once verified, so a hard link or FIFO at the destination is never written through, unless writing in place.
struct ExtractOutputs<'a> {
    out_dir: &'a Path,
    family: rars_rs::ArchiveFamily,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    overwrite: OverwritePolicy,
    in_place: bool,
    flatten: bool,
    flat_names: rars_rs::output_staging::FlatNames,
    renames: rars_rs::output_staging::RenameCounters,
    /// Destinations taken under `Rename`, so a repeated stored path fails as in the CLI.
    rename_claims: HashSet<PathBuf>,
    times: Option<rars_rs::output_times::OutputTimes>,
    staging: Option<ExtractionStaging>,
    staged: usize,
    pending: Option<PendingOutput>,
    published: Vec<PathBuf>,
    /// Where each output went, by its stored path, for hard links and copies.
    created: HashMap<PathBuf, PathBuf>,
    skipped_links: Vec<SkippedLink>,
    progress: Option<Arc<ReadProgress>>,
}

struct PendingOutput {
    /// None when the member is written in place.
    staged: Option<PathBuf>,
    stored: PathBuf,
    destination: PathBuf,
    meta: rars_rs::ExtractedEntryMeta,
    /// A legacy symlink's target, buffered until verified.
    link_target: Option<Arc<Mutex<Vec<u8>>>>,
}

struct SkippedLink {
    name: Vec<u8>,
    target: Vec<u8>,
}

struct Extracted {
    paths: Vec<PathBuf>,
    skipped_links: Vec<SkippedLink>,
}

impl Extracted {
    /// Raises nothing unless the warnings filter turns a skipped link into an error.
    fn warn(self, py: Python<'_>) -> PyResult<Vec<PathBuf>> {
        for link in &self.skipped_links {
            let message = format!(
                "skipped link '{}' -> '{}': it would point outside the output directory",
                String::from_utf8_lossy(&link.name),
                String::from_utf8_lossy(&link.target)
            );
            let message = std::ffi::CString::new(message.replace('\0', "\\0"))
                .expect("NUL bytes were escaped");
            PyErr::warn(py, py.get_type::<UnsafeLinkWarning>().as_any(), &message, 1)?;
        }
        Ok(self.paths)
    }
}

struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("link target lock poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> ExtractOutputs<'a> {
    fn new(
        out_dir: &'a Path,
        family: rars_rs::ArchiveFamily,
        options: rars_rs::ArchiveReadOptions<'_>,
        mode: OutputMode,
        progress: Option<Arc<ReadProgress>>,
    ) -> Self {
        Self {
            out_dir,
            family,
            encoding: options.legacy_name_encoding,
            overwrite: mode.overwrite,
            in_place: mode.in_place,
            flatten: mode.flatten,
            flat_names: Default::default(),
            renames: Default::default(),
            rename_claims: HashSet::new(),
            times: mode
                .restore_times
                .then(rars_rs::output_times::OutputTimes::new),
            staging: None,
            staged: 0,
            pending: None,
            published: Vec::new(),
            created: HashMap::new(),
            skipped_links: Vec::new(),
            progress,
        }
    }

    /// Stored path for link lookups, and destination, which flattening reduces to the base name.
    fn destination(
        &self,
        meta: &rars_rs::ExtractedEntryMeta,
    ) -> rars_rs::Result<(PathBuf, PathBuf)> {
        let (stored, path) =
            checked_output_path(self.out_dir, meta, self.family, self.encoding, self.flatten)
                .map_err(|error| refused_output(error, &meta.name))?;
        if let Some(staging) = &self.staging {
            staging
                .reject_alias(&path)
                .map_err(|error| refused_output(error, &meta.name))?;
        }
        Ok((stored, path))
    }

    fn claim(
        &mut self,
        destination: &Path,
        meta: &rars_rs::ExtractedEntryMeta,
    ) -> rars_rs::Result<()> {
        if self.flatten {
            let relative = destination
                .strip_prefix(self.out_dir)
                .expect("checked output path is under the output directory");
            return self
                .flat_names
                .claim(relative, &meta.name, self.overwrite)
                .map_err(|error| refused_output(error, &meta.name));
        }
        if self.overwrite == OverwritePolicy::Rename
            && !meta.is_directory
            && !self.rename_claims.insert(destination.to_path_buf())
        {
            return Err(rars_rs::Error::InvalidHeader(
                "multiple archive entries map to the same output path",
            ));
        }
        if self.encoding.is_some() && self.published.iter().any(|path| path == destination) {
            return Err(rars_rs::Error::InvalidArgument(
                "multiple entries map to the same decoded output path",
            ));
        }
        Ok(())
    }

    fn open(&mut self, meta: &rars_rs::ExtractedEntryMeta) -> rars_rs::Result<Box<dyn Write>> {
        let writer = self.open_file(meta)?;
        Ok(match &self.progress {
            Some(progress) if !meta.is_directory => progress.counted(&meta.name, writer),
            _ => writer,
        })
    }

    /// The library has verified the previous member by the time it asks for another output.
    fn open_file(&mut self, meta: &rars_rs::ExtractedEntryMeta) -> rars_rs::Result<Box<dyn Write>> {
        self.publish_pending()?;
        if self.flatten && meta.is_directory {
            return Ok(Box::new(io::sink()));
        }
        let (stored, destination) = self.destination(meta)?;
        self.claim(&destination, meta)?;
        if meta.is_directory {
            fs::create_dir_all(&destination)?;
            self.record_published(stored, destination, meta, true);
            return Ok(Box::new(io::sink()));
        }
        if self.overwrite == OverwritePolicy::Never && fs::symlink_metadata(&destination).is_ok() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "File exists").into());
        }
        if self.in_place {
            fs::create_dir_all(
                destination
                    .parent()
                    .expect("checked output path has a file name"),
            )?;
            // Creating the parents may have raced a symlink into place.
            let (_, destination) = self.destination(meta)?;
            let (destination, file) = rars_rs::output_staging::open_in_place(
                &destination,
                self.overwrite,
                &mut self.renames,
            )?;
            self.pending = Some(PendingOutput {
                staged: None,
                stored,
                destination,
                meta: meta.clone(),
                link_target: None,
            });
            return Ok(Box::new(file));
        }
        let staging = match &mut self.staging {
            Some(staging) => staging,
            None => self.staging.insert(ExtractionStaging::new(self.out_dir)?),
        };
        staging
            .reject_alias(&destination)
            .map_err(|error| refused_output(error, &meta.name))?;
        let staged = staging.root.join(self.staged.to_string());
        self.staged += 1;
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        self.pending = Some(PendingOutput {
            staged: Some(staged),
            stored,
            destination,
            meta: meta.clone(),
            link_target: None,
        });
        Ok(Box::new(file))
    }

    fn publish_pending(&mut self) -> rars_rs::Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        if let Some(target) = pending.link_target {
            let target = std::mem::take(&mut *target.lock().expect("link target lock poisoned"));
            rars_rs::output_links::check_legacy_symlink_target(
                &pending.meta.name,
                target.len() as u64,
                Some(&target),
            )?;
            return self.link(
                &pending.meta,
                ExtractedLink::Symlink {
                    target: &target,
                    directory: false,
                },
            );
        }
        let Some(staged) = &pending.staged else {
            self.record_published(pending.stored, pending.destination, &pending.meta, true);
            return Ok(());
        };
        fs::create_dir_all(
            pending
                .destination
                .parent()
                .expect("checked output path has a file name"),
        )?;
        // Creating the parents may have raced a symlink into place.
        let (_, destination) = self.destination(&pending.meta)?;
        let destination = publish_verified_output(
            staged,
            &destination,
            self.overwrite,
            None,
            &mut self.renames,
        )?;
        self.record_published(pending.stored, destination, &pending.meta, true);
        Ok(())
    }

    /// Buffers a legacy symlink's target; the link is made once the target is verified.
    fn open_legacy_link(
        &mut self,
        meta: &rars_rs::ExtractedEntryMeta,
    ) -> rars_rs::Result<Box<dyn Write>> {
        self.publish_pending()?;
        let target = Arc::new(Mutex::new(Vec::new()));
        self.pending = Some(PendingOutput {
            staged: None,
            stored: PathBuf::new(),
            destination: PathBuf::new(),
            meta: meta.clone(),
            link_target: Some(Arc::clone(&target)),
        });
        Ok(Box::new(SharedBuffer(target)))
    }

    fn link(
        &mut self,
        meta: &rars_rs::ExtractedEntryMeta,
        link: ExtractedLink<'_>,
    ) -> rars_rs::Result<()> {
        self.publish_pending()?;
        let (stored, destination) = self.destination(meta)?;
        let relative = destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory")
            .to_path_buf();
        let Some(target) = rars_rs::output_links::link_target(
            self.out_dir,
            &relative,
            meta,
            link,
            self.family,
            self.flatten,
        )?
        else {
            self.skipped_links.push(SkippedLink {
                name: meta.name.clone(),
                target: link.target().to_vec(),
            });
            return Ok(());
        };
        self.claim(&destination, meta)?;
        if self.in_place {
            let (path, file) = create_link_output(
                self.out_dir,
                &relative,
                &target,
                link,
                self.overwrite,
                &self.created,
                &mut self.renames,
            )?;
            self.record_published(stored, path, meta, file);
            return Ok(());
        }
        if self.overwrite == OverwritePolicy::Never && fs::symlink_metadata(&destination).is_ok() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "File exists").into());
        }
        let staging = match &mut self.staging {
            Some(staging) => staging,
            None => self.staging.insert(ExtractionStaging::new(self.out_dir)?),
        };
        let (staged, file) = create_link_output(
            &staging.root,
            Path::new(&self.staged.to_string()),
            &target,
            link,
            OverwritePolicy::Never,
            &self.created,
            &mut self.renames,
        )?;
        self.staged += 1;
        let source = match link {
            ExtractedLink::HardLink { .. } => {
                Some(link_source_path(&target, &self.created)?.to_path_buf())
            }
            _ => None,
        };
        fs::create_dir_all(
            destination
                .parent()
                .expect("checked output path has a file name"),
        )?;
        // Creating the parents may have raced a symlink into place.
        let (_, destination) = self.destination(meta)?;
        if self.overwrite == OverwritePolicy::Always
            && fs::symlink_metadata(&destination).is_ok_and(|metadata| metadata.is_dir())
        {
            fs::remove_dir(&destination)?;
        }
        let destination = publish_verified_output(
            &staged,
            &destination,
            self.overwrite,
            source.as_deref(),
            &mut self.renames,
        )?;
        self.record_published(stored, destination, meta, file);
        Ok(())
    }

    /// Symlinks keep their own times: setting them would follow the link.
    fn record_published(
        &mut self,
        stored: PathBuf,
        path: PathBuf,
        meta: &rars_rs::ExtractedEntryMeta,
        restore_times: bool,
    ) {
        if let (Some(times), true) = (&mut self.times, restore_times) {
            times.opened(path.clone(), self.family, meta);
            times.finish();
        }
        self.created.insert(stored, path.clone());
        self.published.push(path);
    }

    /// A member still in flight when extraction failed never reaches its destination.
    fn finish(mut self, result: rars_rs::Result<()>) -> rars_rs::Result<Extracted> {
        let published = match result {
            Ok(()) => self.publish_pending(),
            Err(error) => {
                let verified = matches!(
                    (failed_entry_name(&error), &self.pending),
                    (Some(failed), Some(pending)) if failed != pending.meta.name.as_slice()
                );
                if verified {
                    // The extraction's own error wins over a failure to publish.
                    let _ = self.publish_pending();
                }
                Err(error)
            }
        };
        let restored = match &self.times {
            Some(times) => times.restore(),
            None => Ok(()),
        };
        published?;
        restored?;
        let mut paths = std::mem::take(&mut self.published);
        if self.flatten && self.overwrite == OverwritePolicy::Always {
            // A member that replaced an earlier one is listed once, where it last landed.
            let mut seen = HashSet::new();
            paths.reverse();
            paths.retain(|path| seen.insert(path.clone()));
            paths.reverse();
        }
        Ok(Extracted {
            paths,
            skipped_links: std::mem::take(&mut self.skipped_links),
        })
    }
}

fn extract_archive<S: Selection>(
    archive: &rars_rs::Archive,
    selected: Option<&S>,
    out_dir: &Path,
    options: rars_rs::ArchiveReadOptions<'_>,
    mode: OutputMode,
    progress: Option<Arc<ReadProgress>>,
) -> rars_rs::Result<Extracted> {
    if options
        .cancellation
        .is_some_and(rars_rs::ReadCancellation::is_cancelled)
    {
        return Err(rars_rs::Error::Cancelled);
    }
    let outputs = std::cell::RefCell::new(ExtractOutputs::new(
        out_dir,
        archive.family(),
        options,
        mode,
        progress,
    ));
    let result = extract_selected(archive, selected, options, &outputs);
    outputs.into_inner().finish(result)
}

fn extract_selected<S: Selection>(
    archive: &rars_rs::Archive,
    selected: Option<&S>,
    options: rars_rs::ArchiveReadOptions<'_>,
    outputs: &std::cell::RefCell<ExtractOutputs<'_>>,
) -> rars_rs::Result<()> {
    let Some(selected) = selected else {
        // RAR 5 decodes members in parallel only where there are no links to create.
        if archive.family() == rars_rs::ArchiveFamily::Rar50Plus
            && !archive.member_refs().any(|member| member.is_redirection())
        {
            return archive.extract_to_parallel_buffered_with_options(options, |meta| {
                outputs.borrow_mut().open(meta)
            });
        }
        return archive.extract_with_links(
            options,
            |meta| outputs.borrow_mut().open(meta),
            |meta, link| outputs.borrow_mut().link(meta, link),
        );
    };
    let last = archive
        .member_refs()
        .enumerate()
        .filter(|(index, member)| selected.contains_member(*index, member.name_bytes()))
        .map(|(index, _)| index)
        .last();
    let Some(last) = last else {
        return Ok(());
    };
    let solid = archive.is_solid();
    let mut index = 0;
    archive.extract_with_control(options, |member| {
        // The previous payload has passed decoding and integrity checks.
        outputs.borrow_mut().publish_pending()?;
        let current = index;
        index += 1;
        if current > last {
            return Ok(rars_rs::ExtractionDecision::Stop);
        }
        let meta = &member.meta;
        let chosen = selected.contains_member(current, &meta.name);
        if meta.is_redirection {
            if chosen {
                if let rars_rs::ArchiveMemberDetail::Rar50Plus {
                    redirection: Some(redirection),
                    ..
                } = &member.detail
                {
                    let link = rars_rs::output_links::rar50_link(redirection)?;
                    outputs.borrow_mut().link(&extracted_meta(member), link)?;
                }
            }
            return Ok(rars_rs::ExtractionDecision::Skip);
        }
        if !chosen {
            return Ok(if solid && !meta.is_directory {
                rars_rs::ExtractionDecision::Extract(Box::new(io::sink()))
            } else {
                rars_rs::ExtractionDecision::Skip
            });
        }
        if rars_rs::output_links::is_legacy_symlink_member(meta) {
            rars_rs::output_links::check_legacy_symlink_target(
                &meta.name,
                meta.unpacked_size,
                None,
            )?;
            return Ok(rars_rs::ExtractionDecision::Extract(
                outputs
                    .borrow_mut()
                    .open_legacy_link(&extracted_meta(member))?,
            ));
        }
        Ok(rars_rs::ExtractionDecision::Extract(
            outputs.borrow_mut().open(&extracted_meta(member))?,
        ))
    })?;
    Ok(())
}

/// Stops once the last selected member is verified, so a generator isn't asked for volumes nobody needs.
fn extract_arriving_selected(
    first: &rars_rs::Archive,
    volumes: &mut (dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send),
    options: rars_rs::ArchiveReadOptions<'_>,
    selected: &HashSet<usize>,
    SelectionEnd {
        name: last_name,
        last_volume,
    }: SelectionEnd,
    mut open: impl FnMut(usize, &rars_rs::ExtractedEntryMeta) -> rars_rs::Result<Box<dyn Write>>,
    mut link: impl FnMut(&rars_rs::ExtractedEntryMeta, ExtractedLink<'_>) -> rars_rs::Result<()>,
) -> rars_rs::Result<()> {
    let last = selected.iter().copied().max().unwrap_or_default();
    let finished = AtomicBool::new(false);
    let mut last_volume_seen = false;
    let mut pulled = 0;
    let volumes = std::iter::from_fn(|| {
        // Asking past the volume where the last selected member ends means it has been verified.
        if last_volume_seen {
            finished.store(true, Ordering::Relaxed);
            return None;
        }
        let volume = volumes.next()?;
        pulled += 1;
        // Without a listing, a first-volume member ends where a volume's first member stops continuing.
        last_volume_seen = match last_volume {
            Some(last_volume) => pulled >= last_volume,
            None => volume.as_ref().is_ok_and(|volume| {
                volume
                    .members()
                    .next()
                    .is_some_and(|member| !member.meta.is_split_after)
            }),
        };
        Some(volume)
    });
    // The extractor calls `open` or `link` once per member, in archive order.
    let next = std::cell::Cell::new(0);
    let advance = || {
        let index = next.get();
        next.set(index + 1);
        if index > last {
            // The extractor asks for a later member only once the earlier ones are verified.
            finished.store(true, Ordering::Relaxed);
            return Err(rars_rs::Error::InvalidArgument("selection is complete"));
        }
        Ok(index)
    };
    let result = rars_rs::output_links::extract_arriving_with_links(
        first,
        volumes,
        options,
        |meta| {
            let index = advance()?;
            if selected.contains(&index) {
                open(index, meta)
            } else {
                Ok(Box::new(io::sink()))
            }
        },
        |meta, target| {
            if selected.contains(&advance()?) {
                link(meta, target)
            } else {
                Ok(())
            }
        },
    );
    match result {
        _ if finished.load(Ordering::Relaxed) => Ok(()),
        // A later member's admission checks run before it is opened, once the last selected one is verified.
        Err(error)
            if next.get() > last
                && failed_entry_name(&error)
                    .is_some_and(|name| Some(name) != last_name.as_deref()) =>
        {
            Ok(())
        }
        result => result,
    }
}

/// Listing walks `volumes` once more before the read, which an iterator or stream can't survive.
fn rereadable(volumes: &Bound<'_, PyAny>) -> bool {
    (volumes.is_instance_of::<PyList>() || volumes.is_instance_of::<PyTuple>())
        && volumes.try_iter().is_ok_and(|mut items| {
            items.all(|item| item.is_ok_and(|item| is_file_object(&item).is_ok_and(|file| !file)))
        })
}

fn watched<'a>(
    progress: &'a Option<Arc<ReadProgress>>,
    options: rars_rs::ArchiveReadOptions<'a>,
) -> rars_rs::ArchiveReadOptions<'a> {
    match progress {
        Some(progress) => progress.watch(options),
        None => options,
    }
}

fn finished<T>(progress: &Option<Arc<ReadProgress>>, result: PyResult<T>) -> PyResult<T> {
    match progress {
        Some(progress) => progress.finish(result),
        None => result,
    }
}

/// `read_members_at_with_options` keeps its buffers to itself, so a counted read chooses members the same way here.
fn read_counted(
    archive: &rars_rs::Archive,
    selected: &HashSet<usize>,
    indices: &[usize],
    options: rars_rs::ArchiveReadOptions<'_>,
    progress: &Arc<ReadProgress>,
) -> rars_rs::Result<Vec<Option<Vec<u8>>>> {
    let mut buffers = HashMap::new();
    let last = archive
        .member_refs()
        .enumerate()
        .filter(|(index, member)| {
            selected.contains(index) && !member.is_directory() && !member.is_redirection()
        })
        .map(|(index, _)| index)
        .last();
    if let Some(last) = last {
        let solid = archive.is_solid();
        let mut current = 0;
        archive.extract_with_control(options, |member| {
            let index = current;
            current += 1;
            let meta = &member.meta;
            if index > last {
                return Ok(rars_rs::ExtractionDecision::Stop);
            }
            if meta.is_directory || meta.is_redirection {
                return Ok(rars_rs::ExtractionDecision::Skip);
            }
            if selected.contains(&index) {
                let buffer = Arc::new(Mutex::new(Vec::new()));
                buffers.insert(index, Arc::clone(&buffer));
                return Ok(rars_rs::ExtractionDecision::Extract(
                    progress.counted(&meta.name, Box::new(SharedBuffer(buffer))),
                ));
            }
            Ok(if solid {
                rars_rs::ExtractionDecision::Extract(Box::new(io::sink()))
            } else {
                rars_rs::ExtractionDecision::Skip
            })
        })?;
    }
    Ok(indices
        .iter()
        .map(|index| {
            buffers
                .get(index)
                .map(|buffer| buffer.lock().expect("read buffer lock poisoned").clone())
        })
        .collect())
}

/// Testing a lone archive hands over no decoded bytes, so its progress moves a member at a time.
fn test_counted(
    archive: &rars_rs::Archive,
    options: rars_rs::ArchiveReadOptions<'_>,
    progress: &ReadProgress,
) -> rars_rs::Result<()> {
    // The callback names regular entries and directories in archive order, skipping redirections.
    let mut sizes = archive
        .members()
        .filter(|member| !member.meta.is_redirection)
        .map(|member| (!member.meta.is_directory).then_some(member.meta.unpacked_size));
    let mut previous = 0;
    archive.test_with_options_and_callback(options, |meta| {
        progress.advance(previous);
        previous = 0;
        if let Some(Some(size)) = sizes.next() {
            progress.entry(&meta.name);
            previous = size;
        }
        Ok(())
    })
}

fn extracted_meta(member: &rars_rs::ArchiveMember) -> rars_rs::ExtractedEntryMeta {
    let meta = &member.meta;
    let mut extracted = rars_rs::ExtractedEntryMeta::new(
        meta.name.clone(),
        meta.file_time,
        meta.file_attr,
        meta.is_directory,
    )
    .with_attr_source(meta.attr_source())
    .with_mtime_refinement(meta.mtime_refinement);
    extracted.name_is_unicode = member.name_is_unicode();
    extracted
}

/// Runs `run` without the GIL over the volumes `next` gives; an exception `next` raises wins over `run`'s error.
fn with_volume_sources<T: Send>(
    py: Python<'_>,
    first: &rars_rs::Archive,
    options: rars_rs::ArchiveReadOptions<'_>,
    mut next: impl FnMut() -> PyResult<Option<ArchiveInput>> + Send,
    run: impl FnOnce(
            &mut (dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send),
        ) -> rars_rs::Result<T>
        + Send,
) -> PyResult<rars_rs::Result<T>> {
    let raised: Mutex<Option<PyErr>> = Mutex::new(None);
    let result = py.detach(|| {
        // Reuses the keys `first` derived, so the set derives each RAR 5 key once.
        let mut session = rars_rs::read_session::ReadSession::continuing(first, options);
        let mut pulled = std::iter::from_fn(|| match next() {
            Ok(None) => None,
            Ok(Some(ArchiveInput::Bytes(bytes))) => Some(session.read_owned(bytes)),
            Ok(Some(ArchiveInput::Path(path))) => Some(session.read_path(path)),
            Ok(Some(ArchiveInput::Reader(reader))) => Some(session.read_reader(reader)),
            Err(error) => {
                *raised.lock().expect("raised lock poisoned") = Some(error);
                Some(Err(rars_rs::Error::InvalidArgument(
                    "volumes raised an exception",
                )))
            }
        });
        run(&mut pulled)
    });
    match raised.into_inner().expect("raised lock poisoned") {
        Some(error) => Err(error),
        None => Ok(result),
    }
}

/// Callers need the failing volume and member as values, and the core keeps them only in wrappers.
fn set_fault(
    error: &rars_rs::Error,
    is_cause: impl Fn(&rars_rs::Error) -> bool,
) -> Option<SetFault> {
    let mut fault = SetFault::default();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        current = error.source();
        // Wrapped errors expose their source as a `Box<Error>`.
        let Some(error) = error.downcast_ref::<rars_rs::Error>().or_else(|| {
            error
                .downcast_ref::<Box<rars_rs::Error>>()
                .map(|boxed| &**boxed)
        }) else {
            continue;
        };
        match error {
            rars_rs::Error::InVolume { number, .. } => fault.volume_number = Some(*number),
            rars_rs::Error::AtEntry { name, .. } if fault.member.is_none() => {
                fault.member = Some(String::from_utf8_lossy(name).into_owned());
            }
            error if is_cause(error) => return Some(fault),
            _ => {}
        }
    }
    None
}

#[derive(Default)]
struct SetFault {
    /// The innermost volume, where the fault is rather than where reading began.
    volume_number: Option<usize>,
    /// The outermost member, which is the one the caller asked for.
    member: Option<String>,
}

fn is_missing_volume(error: &rars_rs::Error) -> bool {
    matches!(error, rars_rs::Error::MissingVolume)
}

fn is_checksum_mismatch(error: &rars_rs::Error) -> bool {
    matches!(
        error,
        rars_rs::Error::CrcMismatch { .. }
            | rars_rs::Error::Crc32Mismatch { .. }
            | rars_rs::Error::HashMismatch { .. }
    )
}

/// `error` as Python would raise it, with `detail` appended to its message.
fn map_error_with(error: rars_rs::Error, detail: &str) -> PyErr {
    let message = format!("{error}{detail}");
    typed_error(error, message)
}

/// Sets `name` on `error`'s exception object, so callers read details instead of parsing text.
fn with_attribute<'py>(
    py: Python<'py>,
    error: PyErr,
    name: &str,
    value: impl IntoPyObject<'py>,
) -> PyErr {
    match error.value(py).setattr(name, value) {
        Ok(()) => error,
        Err(failed) => failed,
    }
}

enum ArchiveInput {
    Bytes(Vec<u8>),
    Path(PathBuf),
    Reader(PyFileReader),
}

/// Listing walks the volumes and every later read walks them again, so a one-shot iterator won't do.
fn stored_volumes(
    volumes: Option<&Bound<'_, PyAny>>,
    cancellation: Option<&rars_rs::ReadCancellation>,
) -> PyResult<Option<Py<PyTuple>>> {
    let Some(volumes) = volumes else {
        return Ok(None);
    };
    if !volumes.is_instance_of::<PyList>() && !volumes.is_instance_of::<PyTuple>() {
        return Err(PyTypeError::new_err(
            "volumes must be a list or tuple of paths, bytes-like or file objects; listing would use up a one-shot iterator",
        ));
    }
    let py = volumes.py();
    let volumes = volumes
        .try_iter()?
        .map(|volume| {
            let volume = volume?;
            // A stream reads once, and listing and every read walk the volumes again.
            match py_file_input(&volume, cancellation)? {
                Some(ArchiveInput::Bytes(bytes)) => Ok(PyBytes::new(py, &bytes).into_any()),
                _ => Ok(volume),
            }
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(Some(PyTuple::new(py, volumes)?.unbind()))
}

/// A later volume names the set's earlier ones as if it were the first, so listing from it would go astray.
fn starts_set(archive: &rars_rs::Archive) -> bool {
    let first_member_continues = archive
        .member_refs()
        .next()
        .is_some_and(|member| member.is_split_before());
    !first_member_continues
        && match archive {
            rars_rs::Archive::Rar15To40(archive) => {
                !archive.main.uses_new_numbering() || archive.main.is_first_volume()
            }
            rars_rs::Archive::Rar50Plus(archive) => {
                archive.main.volume_number.is_none_or(|number| number == 0)
            }
            _ => true,
        }
}

#[derive(PartialEq)]
enum VolumeEnd {
    Last,
    More,
    /// No end record says; the set ends where its volumes run out.
    Unknown,
}

/// Volumes marked with no end run until the caller's run out, so only a marked set can report one missing.
fn volumes_to_last<'a>(
    first: &rars_rs::Archive,
    volumes: &'a mut (dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send),
) -> impl Iterator<Item = rars_rs::Result<rars_rs::Archive>> + 'a {
    let mut end = volume_end(first);
    let mut number = 1;
    std::iter::from_fn(move || {
        if end == VolumeEnd::Last {
            return None;
        }
        number += 1;
        let volume = match volumes.next() {
            Some(volume) => volume,
            None if end == VolumeEnd::More => Err(rars_rs::Error::MissingVolume),
            None => return None,
        };
        end = volume.as_ref().map_or(VolumeEnd::Last, volume_end);
        Some(volume.map_err(|error| rars_rs::Error::InVolume {
            number,
            source: Box::new(error),
        }))
    })
}

fn volume_end(archive: &rars_rs::Archive) -> VolumeEnd {
    if !archive.is_volume() {
        return VolumeEnd::Last;
    }
    let next = match archive {
        rars_rs::Archive::Rar15To40(archive) => {
            archive.blocks.iter().find_map(|block| match block {
                rars_rs::rar15_40::Block::End(end) => Some(end.has_next_volume()),
                _ => None,
            })
        }
        rars_rs::Archive::Rar50Plus(archive) => {
            archive.blocks.iter().find_map(|block| match block {
                rars_rs::rar50::Block::End(end) => Some(end.has_next_volume()),
                _ => None,
            })
        }
        _ => None,
    };
    match next {
        Some(true) => VolumeEnd::More,
        Some(false) => VolumeEnd::Last,
        None => VolumeEnd::Unknown,
    }
}

/// Reads only headers, so a listing never waits on or decrypts member data.
fn list_later_volumes(
    first: &rars_rs::Archive,
    listing: &SetListing,
    volumes: &mut (dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send),
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    identity: &Arc<()>,
) -> rars_rs::Result<SetListing> {
    let in_volume = |index: usize, error: rars_rs::Error| rars_rs::Error::InVolume {
        number: index + 1,
        source: Box::new(error),
    };
    let broken = rars_rs::Error::InvalidHeader(
        "volume does not continue the member split from the volume before it",
    );
    let mut infos = listing.infos.clone();
    let mut places = listing.places.clone();
    let mut pending = infos.last().is_some_and(|info| info.is_split_after);
    let mut pulled = 0;
    for volume in volumes_to_last(first, volumes) {
        pulled += 1;
        let index = pulled;
        let volume = volume?;
        for (index_in_volume, member) in volume.members().enumerate() {
            let split_after = member.meta.is_split_after;
            if member.meta.is_split_before {
                let (Some(info), Some(place)) = (infos.last_mut(), places.last_mut()) else {
                    return Err(in_volume(index, broken));
                };
                if !pending
                    || index_in_volume != 0
                    || *info.orig_filename_bytes != *member.meta.name
                {
                    return Err(in_volume(index, broken));
                }
                info.compress_size += member.meta.packed_size;
                if !split_after {
                    // Only the last part records the whole member's CRC and hash.
                    let mut last = info_from_member_named(member, String::new());
                    info.file_size = last.file_size;
                    info.crc = last.crc;
                    if let Some(hash) = last.detail.remove("hash") {
                        info.detail.insert("hash".to_string(), hash);
                    }
                    place.last_volume = Some(index);
                }
            } else {
                if pending {
                    return Err(in_volume(index, broken));
                }
                let filename =
                    String::from_utf8_lossy(&member.decoded_name(encoding)?).into_owned();
                let mut info = info_from_member_named(member, filename);
                info.member_index = infos.len();
                info.archive_identity = Some(identity.clone());
                info.volume = index;
                infos.push(info);
                places.push(Place {
                    index_in_volume,
                    last_volume: (!split_after).then_some(index),
                });
            }
            pending = split_after;
        }
    }
    if pending {
        return Err(in_volume(pulled + 1, rars_rs::Error::MissingVolume));
    }
    Ok(SetListing {
        infos,
        places,
        names: OnceLock::new(),
    })
}

#[cfg(test)]
fn info_from_member(member: rars_rs::ArchiveMember) -> RarInfo {
    let filename = String::from_utf8_lossy(&member.meta.name).into_owned();
    info_from_member_named(member, filename)
}

fn info_from_member_named(member: rars_rs::ArchiveMember, filename: String) -> RarInfo {
    let mut detail = HashMap::new();
    let mut crc = None;
    let solid = member.is_solid();
    match member.detail {
        rars_rs::ArchiveMemberDetail::Rar13 {
            method,
            unpack_version,
            file_checksum,
            has_file_comment,
            ..
        } => {
            detail.insert("method".to_string(), method.to_string());
            detail.insert("unpack_version".to_string(), unpack_version.to_string());
            detail.insert("file_checksum".to_string(), file_checksum.to_string());
            detail.insert("has_file_comment".to_string(), has_file_comment.to_string());
        }
        rars_rs::ArchiveMemberDetail::Rar15To40 {
            method,
            unpack_version,
            crc32,
            salt,
            has_file_comment,
            ..
        } => {
            crc = Some(crc32);
            detail.insert("method".to_string(), method.to_string());
            detail.insert("unpack_version".to_string(), unpack_version.to_string());
            detail.insert("has_salt".to_string(), salt.is_some().to_string());
            detail.insert("has_file_comment".to_string(), has_file_comment.to_string());
        }
        rars_rs::ArchiveMemberDetail::Rar50Plus {
            compression_info,
            crc32,
            hash,
            ..
        } => {
            crc = crc32;
            detail.insert("compression_info".to_string(), compression_info.to_string());
            detail.insert("hash".to_string(), hash_label(hash));
        }
        _ => {
            detail.insert("kind".to_string(), "unknown".to_string());
        }
    }
    let date_time = member
        .meta
        .stored_modification_time()
        .and_then(rars_rs::StoredTimestamp::calendar_fields);
    RarInfo {
        member_index: 0,
        archive_identity: None,
        filename,
        orig_filename_bytes: member.meta.name.into(),
        file_size: member.meta.unpacked_size,
        compress_size: member.meta.packed_size,
        date_time,
        crc,
        host_os: member.meta.host_os,
        is_encrypted: member.meta.is_encrypted,
        is_solid: solid,
        is_split_before: member.meta.is_split_before,
        is_split_after: member.meta.is_split_after,
        rar_version: family_name(member.meta.family).to_string(),
        file_attr: member.meta.file_attr,
        detail,
        is_directory: member.meta.is_directory,
        is_redirection: member.meta.is_redirection,
        volume: 0,
    }
}

fn hash_label(hash: Option<rars_rs::ArchiveMemberHash>) -> String {
    match hash {
        Some(rars_rs::ArchiveMemberHash::Blake2sp(_)) => "blake2sp".to_string(),
        Some(rars_rs::ArchiveMemberHash::Other { hash_type, .. }) => format!("other:{hash_type}"),
        Some(_) => "unknown".to_string(),
        None => "none".to_string(),
    }
}

fn family_name(family: rars_rs::ArchiveFamily) -> &'static str {
    match family {
        rars_rs::ArchiveFamily::Rar13 => "rar13",
        rars_rs::ArchiveFamily::Rar15To40 => "rar15_40",
        rars_rs::ArchiveFamily::Rar50Plus => "rar50_plus",
        _ => "unknown",
    }
}

fn parse_version(value: &str) -> PyResult<rars_rs::ArchiveVersion> {
    rars_rs::ArchiveVersion::from_name(value)
        .ok_or_else(|| PyValueError::new_err(format!("unsupported RAR format: {value}")))
}

/// The member's stored relative path, and where it goes under `out_dir`.
fn checked_output_path(
    out_dir: &Path,
    meta: &rars_rs::ExtractedEntryMeta,
    family: rars_rs::ArchiveFamily,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    flatten: bool,
) -> rars_rs::Result<(PathBuf, PathBuf)> {
    // Retain the binding's conservative name preflight (including legacy
    // backslash traversal) before applying host-aware destination conversion.
    rars_rs::validate_entry_name(meta.name.clone())?;
    let rar50 = family == rars_rs::ArchiveFamily::Rar50Plus;
    let name = if rar50 {
        rars_rs::output_links::rar50_native_name(
            &meta.name,
            meta.attr_source == rars_rs::AttrSource::Unix,
        )
    } else {
        rars_rs::filename::decoded_name(&meta.name, meta.name_is_unicode, encoding)?.into_owned()
    };
    let stored = output_relative_path(&name, !rar50)?;
    let relative = if flatten {
        rars_rs::output_staging::flat_relative(&stored)
    } else {
        stored.clone()
    };
    let path = rars_rs::filename::checked_output_path(out_dir, &relative)?;
    Ok((stored, path))
}

fn archive_base_name(path: &Path) -> PyResult<Vec<u8>> {
    let file_name = path
        .file_name()
        .ok_or_else(|| PyValueError::new_err("input path has no file name"))?;
    rars_rs::filename::native_bytes(file_name)
        .map(<[u8]>::to_vec)
        .map_err(map_error)
}

fn legacy_volume_part_path(first_path: &Path, index: usize) -> PyResult<PathBuf> {
    rars_rs::volume_name::old_style(first_path, index)
        .ok_or_else(|| PyValueError::new_err("old-style volume names run out after .z99"))
}

fn rar50_volume_part_path(
    first_path: &Path,
    index: usize,
    total_parts: usize,
) -> PyResult<PathBuf> {
    let width = total_parts.to_string().len().max(2);
    rars_rs::volume_name::part_style(first_path, index, width)
        .ok_or_else(|| PyValueError::new_err("RAR 5 volume path needs a file name"))
}

fn map_io_error(error: io::Error) -> PyErr {
    PyOSError::new_err(error.to_string())
}

/// Only the file being opened can be "not a RAR"; a non-RAR later volume is a broken set.
/// A file object's own exception, which reached the core only as an `io::Error`.
fn raised_by_file(error: &rars_rs::Error) -> Option<PyErr> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        let raised = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<PyErr>());
        if let Some(raised) = raised {
            return Some(Python::attach(|py| raised.clone_ref(py)));
        }
        current = error.source();
    }
    None
}

fn map_open_error(error: rars_rs::Error) -> PyErr {
    if let Some(raised) = raised_by_file(&error) {
        return raised;
    }
    if matches!(error.root_cause(), rars_rs::Error::UnsupportedSignature) {
        return NotRarFile::new_err(error.to_string());
    }
    map_error(error)
}

fn map_error(error: rars_rs::Error) -> PyErr {
    let message = error.to_string();
    typed_error(error, message)
}

fn typed_error(error: rars_rs::Error, message: String) -> PyErr {
    if let Some(raised) = raised_by_file(&error) {
        return raised;
    }
    if error_is_need_password(&error) {
        return PasswordRequired::new_err(message);
    }
    if error_is_bad_password(&error) {
        return BadPassword::new_err(message);
    }
    if let Some(fault) = set_fault(&error, is_missing_volume) {
        return Python::attach(|py| {
            with_attribute(
                py,
                MissingVolume::new_err(message),
                "volume_number",
                fault.volume_number,
            )
        });
    }
    // Comment and recovery-record checksums name no member, so they stay plain BadRarFile.
    if let Some(fault) =
        set_fault(&error, is_checksum_mismatch).filter(|fault| fault.member.is_some())
    {
        return Python::attach(|py| {
            let error = with_attribute(py, ChecksumError::new_err(message), "member", fault.member);
            with_attribute(py, error, "volume_number", fault.volume_number)
        });
    }
    use rars_rs::ErrorKind;
    match error.kind() {
        ErrorKind::UnsupportedFormat | ErrorKind::UnsupportedFeature => {
            UnsupportedRarFeature::new_err(message)
        }
        ErrorKind::UnsafePath => UnsafeArchivePath::new_err(message),
        ErrorKind::Io | ErrorKind::SourceChanged => PyOSError::new_err(message),
        ErrorKind::InvalidArgument | ErrorKind::DuplicateEntry => PyValueError::new_err(message),
        ErrorKind::EntryNotFound => PyKeyError::new_err(message),
        ErrorKind::ResourceLimit => PyMemoryError::new_err(message),
        ErrorKind::Cancelled => PyInterruptedError::new_err(message),
        ErrorKind::WriterFailure => pyo3::exceptions::PyRuntimeError::new_err(message),
        _ => BadRarFile::new_err(message),
    }
}

fn error_is_need_password(error: &rars_rs::Error) -> bool {
    error.kind() == rars_rs::ErrorKind::PasswordRequired
}

fn error_is_bad_password(error: &rars_rs::Error) -> bool {
    error.kind() == rars_rs::ErrorKind::BadPassword
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_set() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rars/tests/fixtures/rar50/encrypted_multivol.part1.rar")
    }

    // Keeps every derivation on this thread, where the counter sees it.
    fn one_thread(py: Python<'_>) -> PyRef<'_, ReadOptions> {
        let kwargs = pyo3::types::PyDict::new(py);
        kwargs.set_item("threads", 1).unwrap();
        py.get_type::<ReadOptions>()
            .call((), Some(&kwargs))
            .unwrap()
            .extract::<PyRef<'_, ReadOptions>>()
            .unwrap()
    }

    #[test]
    fn a_rarfile_derives_each_key_once_however_many_calls_follow() {
        Python::initialize();
        let out = std::env::temp_dir().join(format!("rars-key-reuse-{}", std::process::id()));
        Python::attach(|py| {
            let options = one_thread(py);
            let before = rars_rs::crypto::rar50_key_derivations();
            let file = RarFile::from_path(
                py,
                encrypted_set(),
                Some(b"password".to_vec()),
                Some(&options),
            )
            .unwrap();
            file.testrar(py, None, Some(&options), None).unwrap();
            let first = PyString::new(py, &file.first.infos[0].filename);
            for _ in 0..2 {
                file.read(py, &first, None, Some(&options), None).unwrap();
                file.extract(
                    py,
                    &first,
                    Some(out.clone()),
                    None,
                    Overwrite(OverwritePolicy::Always),
                    Some(&options),
                    None,
                    true,
                    false,
                    false,
                )
                .unwrap();
                file.extractall(
                    py,
                    Some(out.clone()),
                    None,
                    None,
                    Overwrite(OverwritePolicy::Always),
                    Some(&options),
                    None,
                    true,
                    false,
                    false,
                )
                .unwrap();
            }
            assert_eq!(rars_rs::crypto::rar50_key_derivations() - before, 1);
        });
        fs::remove_dir_all(out).unwrap();
    }

    #[test]
    fn listing_a_header_encrypted_set_derives_its_key_once() {
        Python::initialize();
        Python::attach(|py| {
            let options = one_thread(py);
            let before = rars_rs::crypto::rar50_key_derivations();
            let file = RarFile::from_path(
                py,
                encrypted_set().with_file_name("header_encrypted_stored_multivol.part1.rar"),
                Some(b"password".to_vec()),
                Some(&options),
            )
            .unwrap();
            assert_eq!(file.namelist(py).unwrap(), ["stored_4k.bin"]);
            assert_eq!(rars_rs::crypto::rar50_key_derivations() - before, 1);
        });
    }

    #[test]
    fn a_volume_given_as_bytes_reuses_the_rarfiles_keys() {
        Python::initialize();
        Python::attach(|py| {
            let options = one_thread(py);
            let before = rars_rs::crypto::rar50_key_derivations();
            let file = RarFile::from_path(
                py,
                encrypted_set(),
                Some(b"password".to_vec()),
                Some(&options),
            )
            .unwrap();
            let later = PyList::new(
                py,
                (2..=3).map(|part| {
                    PyBytes::new(
                        py,
                        &fs::read(
                            encrypted_set()
                                .with_file_name(format!("encrypted_multivol.part{part}.rar")),
                        )
                        .unwrap(),
                    )
                }),
            )
            .unwrap();
            file.testrar(py, None, Some(&options), Some(&later))
                .unwrap();
            assert_eq!(rars_rs::crypto::rar50_key_derivations() - before, 1);
        });
    }

    fn rar300(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rars/tests/fixtures/rar15_40/rar300")
            .join(name)
    }

    #[test]
    fn listing_a_header_encrypted_rar3_set_derives_its_key_once() {
        Python::initialize();
        Python::attach(|py| {
            let options = one_thread(py);
            for first in [
                "header_encrypted_multivol_rar300.rar",
                "header_encrypted_newnaming_rar300.part01.rar",
            ] {
                let before = rars_rs::crypto::rar30_key_derivations();
                let file = RarFile::from_path(
                    py,
                    rar300(first),
                    Some(b"password".to_vec()),
                    Some(&options),
                )
                .unwrap();
                assert!(!file.namelist(py).unwrap().is_empty(), "{first}");
                assert_eq!(
                    rars_rs::crypto::rar30_key_derivations() - before,
                    1,
                    "{first}"
                );
            }
        });
    }

    #[test]
    fn extracting_a_header_encrypted_rar3_set_derives_each_key_once() {
        Python::initialize();
        let out = std::env::temp_dir().join(format!("rars-rar3-hp-{}", std::process::id()));
        Python::attach(|py| {
            let options = one_thread(py);
            let before = rars_rs::crypto::rar30_key_derivations();
            let file = RarFile::from_path(
                py,
                rar300("header_encrypted_multivol_rar300.rar"),
                Some(b"password".to_vec()),
                Some(&options),
            )
            .unwrap();
            for _ in 0..2 {
                file.extractall(
                    py,
                    Some(out.clone()),
                    None,
                    None,
                    Overwrite(OverwritePolicy::Always),
                    Some(&options),
                    None,
                    true,
                    false,
                    false,
                )
                .unwrap();
            }
            // The headers and the member carry different salts.
            assert_eq!(rars_rs::crypto::rar30_key_derivations() - before, 2);
        });
        fs::remove_dir_all(out).unwrap();
    }

    #[test]
    fn a_rarfile_derives_each_rar3_key_once_however_many_calls_follow() {
        Python::initialize();
        let out = std::env::temp_dir().join(format!("rars-rar3-key-reuse-{}", std::process::id()));
        Python::attach(|py| {
            let options = one_thread(py);
            let before = rars_rs::crypto::rar30_key_derivations();
            let file = RarFile::from_path(
                py,
                rar300("encrypted_multivol_rar300.rar"),
                Some(b"password".to_vec()),
                Some(&options),
            )
            .unwrap();
            let first = PyString::new(py, &file.first.infos[0].filename);
            for _ in 0..2 {
                file.testrar(py, None, Some(&options), None).unwrap();
                file.read(py, &first, None, Some(&options), None).unwrap();
                file.extract(
                    py,
                    &first,
                    Some(out.clone()),
                    None,
                    Overwrite(OverwritePolicy::Always),
                    Some(&options),
                    None,
                    true,
                    false,
                    false,
                )
                .unwrap();
            }
            assert_eq!(rars_rs::crypto::rar30_key_derivations() - before, 1);
        });
        fs::remove_dir_all(out).unwrap();
    }

    #[test]
    fn binding_preserves_rar5_member_solid_flags() {
        for version in [
            rars_rs::ArchiveVersion::Rar50,
            rars_rs::ArchiveVersion::Rar70,
        ] {
            let mut builder = rars_rs::Builder::new(version).solid(true);
            for name in [b"first".as_slice(), b"second".as_slice()] {
                builder
                    .add_bytes(name.to_vec(), b"repeated payload ".repeat(4), None, None)
                    .unwrap();
            }
            let archive = rars_rs::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let flags: Vec<_> = archive
                .members()
                .map(|member| info_from_member(member).is_solid)
                .collect();
            assert_eq!(flags, [false, true], "{version:?}");
        }
    }

    #[test]
    fn binding_boundary_values_and_error_mappings_preserve_their_contracts() {
        Python::initialize();
        Python::attach(|py| {
            let mut event = ProgressEvent {
                phase: "writing".into(),
                completed: 0,
                total: 0,
                pass_number: 1,
                entry_name: None,
                entry_index: None,
                total_entries: None,
                volume: None,
                finished: false,
                total_known: true,
            };
            assert_eq!(event.percentage(), None);
            event.finished = true;
            assert_eq!(event.percentage(), Some(100.0));
            event.completed = u64::MAX;
            event.total = u64::MAX;
            assert_eq!(event.percentage(), Some(100.0));
            let token = CancellationToken::new();
            assert!(!token.is_cancelled());
            token.cancel();
            assert!(token.is_cancelled());
            assert_eq!(
                hash_label(Some(rars_rs::ArchiveMemberHash::Other {
                    hash_type: 42,
                    data: vec![1, 2],
                })),
                "other:42"
            );
            for error in [
                rars_rs::Error::EntryNotFound,
                rars_rs::Error::DuplicateEntry,
                rars_rs::Error::InputSymlink,
            ] {
                let mapped = map_builder_error(error);
                assert!(!mapped.to_string().is_empty());
            }
            let symlink = map_builder_error(
                rars_rs::Error::InputSymlink.at_entry(b"link".to_vec(), "adding"),
            );
            assert!(symlink.is_instance_of::<PyValueError>(py));
            assert!(symlink.to_string().contains("link"));
            for (name, separator, expected) in [
                (&b"./nested/./file"[..], false, Some("nested/file")),
                (&b"nested\\file"[..], true, Some("nested/file")),
                (&b""[..], false, None),
                (&b"."[..], false, None),
                (&b"nul\0file"[..], false, None),
                (&b"C:file"[..], false, None),
                (&b"/absolute"[..], false, None),
                (&b"../parent"[..], false, None),
            ] {
                let result = output_relative_path(name, separator);
                match expected {
                    Some(expected) => assert_eq!(result.unwrap(), PathBuf::from(expected)),
                    None => assert!(result.is_err()),
                }
            }
        });
    }

    #[test]
    fn progress_suppresses_reports_after_either_cancellation_signal() {
        use rars_rs::WriteProgress;
        let event = rars_rs::WriteProgressEvent::Advanced {
            operation: rars_rs::WriteOperation::Emission,
            completed_bytes: 1,
            total_bytes: 2,
            pass: 1,
        };
        let progress = PythonProgress::new(None, None);
        progress.report(event);
        assert!(progress.state.lock().unwrap().is_empty());
        progress.cancelled.store(true, Ordering::Relaxed);
        progress.report(event);
        assert!(progress.is_cancelled());
        let token = CancellationToken::new();
        let progress = PythonProgress::new(None, Some(&token));
        token.cancel();
        progress.report(event);
        assert!(progress.is_cancelled());
        assert!(progress.state.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_recovers_poisoned_state_and_preserves_callback_exceptions() {
        use rars_rs::WriteProgress;
        Python::initialize();
        Python::attach(|py| {
            let callback = py.eval(c"lambda event: None", None, None).unwrap().unbind();
            let progress = PythonProgress::new(Some(callback), None);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = progress.state.lock().unwrap();
                panic!("poison progress state");
            }));
            progress.report(rars_rs::WriteProgressEvent::OperationStarted {
                operation: rars_rs::WriteOperation::Emission,
                total_bytes: None,
                total_entries: None,
                pass: 2,
            });
            assert!(!progress.is_cancelled());
            assert!(progress.take_error().is_none());
            let callback = py
                .eval(c"lambda event: 1 / 0", None, None)
                .unwrap()
                .unbind();
            let progress = PythonProgress::new(Some(callback), None);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = progress.error.lock().unwrap();
                panic!("poison progress error");
            }));
            progress.report(rars_rs::WriteProgressEvent::Advanced {
                operation: rars_rs::WriteOperation::Emission,
                completed_bytes: 1,
                total_bytes: 2,
                pass: 1,
            });
            assert!(progress.is_cancelled());
            assert!(progress
                .take_error()
                .unwrap()
                .is_instance_of::<pyo3::exceptions::PyZeroDivisionError>(py));
            assert!(progress.take_error().is_none());
        });
    }

    #[test]
    fn repair_parse_cancellation_does_not_enter_damaged_header_fallback() {
        let token = CancellationToken::new();
        token.cancel();
        let error = repair_core(b"not an archive", None, Some(&token)).unwrap_err();
        assert_eq!(error.kind(), rars_rs::ErrorKind::Cancelled);
    }

    #[test]
    fn reader_workspace_options_reach_the_decoder_and_raise_memory_error() {
        Python::initialize();
        Python::attach(|py| {
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("max_reader_workspace_bytes", 1u64).unwrap();
            let object = py
                .get_type::<ReadOptions>()
                .call((), Some(&kwargs))
                .unwrap();
            assert_eq!(
                object
                    .getattr("max_reader_workspace_bytes")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                1
            );
            let settings = object.extract::<PyRef<'_, ReadOptions>>().unwrap();
            let options = python_read_options(Some(&settings), None);
            assert_eq!(options.max_reader_workspace_bytes, Some(1));
            let mut builder = rars_rs::Builder::new(rars_rs::ArchiveVersion::Rar50);
            builder
                .add_bytes(
                    b"file".to_vec(),
                    b"compressed payload".repeat(32),
                    None,
                    None,
                )
                .unwrap();
            let archive = rars_rs::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let error = map_error(archive.test_with_options(options).unwrap_err());
            assert!(error.is_instance_of::<PyMemoryError>(py));
        });
    }

    #[test]
    fn python_thread_cancels_an_in_progress_read_without_a_callback() {
        use std::io::{Cursor, Read, Seek, SeekFrom};
        use std::sync::mpsc;
        use std::time::Duration;

        struct Paused {
            input: Cursor<Vec<u8>>,
            armed: Arc<AtomicBool>,
            started: mpsc::Sender<()>,
            resume: mpsc::Receiver<()>,
        }
        impl Read for Paused {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.armed.swap(false, Ordering::Relaxed) {
                    self.started.send(()).map_err(io::Error::other)?;
                    self.resume
                        .recv_timeout(Duration::from_secs(10))
                        .map_err(io::Error::other)?;
                }
                self.input.read(buffer)
            }
        }
        impl Seek for Paused {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                self.input.seek(from)
            }
        }
        Python::initialize();
        Python::attach(|py| {
            for format in [
                rars_rs::ArchiveVersion::Rar14,
                rars_rs::ArchiveVersion::Rar29,
                rars_rs::ArchiveVersion::Rar50,
            ] {
                let mut builder = rars_rs::Builder::new(format).store(true);
                builder
                    .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
                    .unwrap();
                let armed = Arc::new(AtomicBool::new(false));
                let (started, waiting) = mpsc::channel();
                let (resume, resumed) = mpsc::channel();
                let archive = rars_rs::ArchiveReader::read_reader(Paused {
                    input: Cursor::new(builder.to_bytes().unwrap()),
                    armed: armed.clone(),
                    started,
                    resume: resumed,
                })
                .unwrap();
                let file = RarFile {
                    identity: Arc::new(()),
                    encoding: None,
                    first: SetListing::new(archive.members().map(info_from_member).collect()),
                    options: None,
                    volumes: None,
                    first_volume_only: false,
                    whole: OnceLock::new(),
                    archive,
                    path: None,
                    password: None,
                };
                let token = CancellationToken::new();
                let options = ReadOptions::new(
                    Some(&token),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    false,
                    None,
                    None,
                )
                .unwrap();
                let cancel_object = Py::new(py, token).unwrap();
                armed.store(true, Ordering::Relaxed);
                let worker = std::thread::spawn(move || {
                    waiting.recv_timeout(Duration::from_secs(10)).unwrap();
                    Python::attach(|py| {
                        cancel_object.bind(py).call_method0("cancel").unwrap();
                    });
                    resume.send(()).unwrap();
                });
                let name = PyBytes::new(py, b"file");
                let error = file
                    .read(py, name.as_any(), None, Some(&options), None)
                    .unwrap_err();
                py.detach(|| worker.join().unwrap());
                assert!(
                    error.is_instance_of::<PyInterruptedError>(py),
                    "{format}: {error}"
                );
                assert_eq!(
                    file.read(py, name.as_any(), None, None, None).unwrap(),
                    b"payload"
                );
            }
        });
    }

    #[test]
    fn selected_extraction_preserves_solid_password_dependencies() {
        let root = scratch::case("selected-solid-extraction");
        for format in [
            rars_rs::ArchiveVersion::Rar29,
            rars_rs::ArchiveVersion::Rar50,
        ] {
            let mut builder = rars_rs::Builder::new(format).solid(true);
            for name in [b"first".as_slice(), b"secret", b"last"] {
                builder
                    .add_bytes(name.to_vec(), name.repeat(100), None, None)
                    .unwrap();
            }
            builder
                .set_entry_encryption(b"secret", Some(b"password".to_vec()), None)
                .unwrap();
            let archive = rars_rs::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            let directory = root.join(format.to_string());
            let first = b"first".to_vec();
            let last = b"last".to_vec();
            let paths = extract_archive(
                &archive,
                Some(&first),
                &directory,
                rars_rs::ArchiveReadOptions::new(),
                OutputMode {
                    overwrite: OverwritePolicy::Never,
                    in_place: false,
                    restore_times: true,
                    flatten: false,
                },
                None,
            )
            .unwrap()
            .paths;
            assert_eq!(paths, vec![directory.join("first")]);
            assert_eq!(fs::read(&paths[0]).unwrap(), first.repeat(100));
            let error = extract_archive(
                &archive,
                Some(&last),
                &directory,
                rars_rs::ArchiveReadOptions::new(),
                OutputMode {
                    overwrite: OverwritePolicy::Never,
                    in_place: false,
                    restore_times: true,
                    flatten: false,
                },
                None,
            )
            .map(|extracted| extracted.paths)
            .unwrap_err();
            assert_eq!(error.kind(), rars_rs::ErrorKind::PasswordRequired);
            assert!(!directory.join("last").exists());
            let paths = extract_archive(
                &archive,
                Some(&last),
                &directory,
                rars_rs::ArchiveReadOptions::with_password(b"password"),
                OutputMode {
                    overwrite: OverwritePolicy::Never,
                    in_place: false,
                    restore_times: true,
                    flatten: false,
                },
                None,
            )
            .unwrap()
            .paths;
            assert_eq!(paths, vec![directory.join("last")]);
            assert_eq!(fs::read(&paths[0]).unwrap(), last.repeat(100));
        }
    }

    #[test]
    fn python_rewrite_batches_link_metadata_and_stages_one_pass_per_write() {
        use rars_rs::atomic64::AtomicU64;
        use std::io::{Cursor, Read, Seek, SeekFrom};

        struct Counted {
            input: Cursor<Vec<u8>>,
            bytes: Arc<AtomicU64>,
        }
        impl Read for Counted {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let read = self.input.read(buffer)?;
                self.bytes.fetch_add(read as u64, Ordering::Relaxed);
                Ok(read)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                self.input.seek(from)
            }
        }

        let root = scratch::case("python-rewrite-once");
        Python::initialize();
        Python::attach(|py| {
            for with_links in [false, true] {
                for format in rars_rs::ArchiveVersion::ALL {
                    if with_links
                        && !matches!(
                            format,
                            rars_rs::ArchiveVersion::Rar20
                                | rars_rs::ArchiveVersion::Rar29
                                | rars_rs::ArchiveVersion::Rar30
                                | rars_rs::ArchiveVersion::Rar40
                        )
                    {
                        continue;
                    }
                    let mut input = rars_rs::Builder::new(format).solid(true);
                    for name in [b"first", b"other", b"final"] {
                        input
                            .add_bytes(name.to_vec(), name.repeat(100), None, None)
                            .unwrap();
                        if with_links && name != b"final" {
                            input
                                .add_unix_symlink(
                                    [name.as_slice(), b"-link"].concat(),
                                    b"../missing-\xff".to_vec(),
                                    false,
                                    None,
                                    None,
                                )
                                .unwrap();
                        }
                    }
                    let bytes = Arc::new(AtomicU64::new(0));
                    let archive = rars_rs::ArchiveReader::read_reader(Counted {
                        input: Cursor::new(input.to_bytes().unwrap()),
                        bytes: bytes.clone(),
                    })
                    .unwrap();
                    bytes.store(0, Ordering::Relaxed);
                    archive
                        .extract_with_control(rars_rs::ArchiveReadOptions::default(), |_| {
                            Ok(rars_rs::ExtractionDecision::Extract(Box::new(io::sink())))
                        })
                        .unwrap();
                    let one_pass = bytes.swap(0, Ordering::Relaxed);
                    let metadata_pass = if with_links {
                        archive
                            .extract_with_control(
                                rars_rs::ArchiveReadOptions::default(),
                                |member| {
                                    if member.meta.name == b"final" {
                                        Ok(rars_rs::ExtractionDecision::Stop)
                                    } else {
                                        Ok(rars_rs::ExtractionDecision::Extract(Box::new(
                                            io::sink(),
                                        )))
                                    }
                                },
                            )
                            .unwrap();
                        bytes.swap(0, Ordering::Relaxed)
                    } else {
                        0
                    };
                    // Both the diagnostic preflight and preserving_builder
                    // validate the small producer payload. Neither should read
                    // member data beyond the single link metadata pass.
                    let producer_checks = archive.as_rar50().map_or(0, |archive| {
                        2 * archive
                            .services()
                            .filter(|service| service.name == b"RARS")
                            .map(|service| service.packed_size())
                            .sum::<u64>()
                    }) + archive.as_rar15_40().map_or(0, |archive| {
                        2 * archive
                            .new_subs()
                            .filter(|sub| sub.file.name == b"RARS")
                            .map(|sub| sub.file.pack_size)
                            .sum::<u64>()
                    });
                    let source = Py::new(
                        py,
                        RarFile {
                            identity: Arc::new(()),
                            encoding: None,
                            archive,
                            path: None,
                            password: None,
                            options: None,
                            volumes: None,
                            first_volume_only: false,
                            first: SetListing::new(Vec::new()),
                            whole: OnceLock::new(),
                        },
                    )
                    .unwrap();
                    let directory = pyo3::types::PyString::new(py, root.to_str().unwrap());
                    let builder = RarBuilder::from_archive(
                        py,
                        source.bind(py).as_any(),
                        None,
                        None,
                        None,
                        true,
                        Some(directory.as_any()),
                        None,
                    )
                    .unwrap();
                    assert_eq!(
                        bytes.swap(0, Ordering::Relaxed),
                        metadata_pass + producer_checks,
                        "{format}: only one link metadata pass is allowed"
                    );
                    for _ in 0..2 {
                        let output = builder.to_bytes(py, None, None).unwrap();
                        assert_eq!(bytes.swap(0, Ordering::Relaxed), one_pass, "{format}");
                        let output =
                            rars_rs::ArchiveReader::read_owned(output.bind(py).as_bytes().to_vec())
                                .unwrap();
                        assert_eq!(
                            output.read_member(b"final", None).unwrap().unwrap(),
                            b"final".repeat(100)
                        );
                        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
                    }
                }
            }
        });
    }

    #[test]
    fn python_exception_types_and_messages_survive_nested_context() {
        use rars_rs::Error as CoreError;
        Python::initialize();
        Python::attach(|py| {
            let cases = [
                CoreError::from(io::Error::from(io::ErrorKind::PermissionDenied)),
                CoreError::UnsupportedCompression {
                    family: "RAR",
                    unpack_version: 99,
                    method: 1,
                },
                CoreError::MemoryLimitExceeded {
                    limit: 1,
                    required: 2,
                    dictionary_size: 1,
                },
                CoreError::Cancelled,
                CoreError::WriterFailure("layout failure"),
                CoreError::UnsafePath("refused path"),
                CoreError::InvalidArgument("bad option"),
                CoreError::InvalidHeader("unsafe; a password is required; I/O error"),
                CoreError::NeedPassword,
                CoreError::Rar50Crypto(rars_rs::crypto::rar50::Error::BadPassword),
            ];
            for cause in cases {
                let kind = cause.kind();
                let wrapped = CoreError::InVolume {
                    number: 2,
                    source: Box::new(
                        cause
                            .at_entry(b"member".to_vec(), "reading")
                            .at_archive_offset(7),
                    ),
                };
                let exception = map_error(wrapped);
                let matches = match kind {
                    rars_rs::ErrorKind::Io => exception.is_instance_of::<PyOSError>(py),
                    rars_rs::ErrorKind::UnsupportedFeature => {
                        exception.is_instance_of::<UnsupportedRarFeature>(py)
                    }
                    rars_rs::ErrorKind::ResourceLimit => {
                        exception.is_instance_of::<PyMemoryError>(py)
                    }
                    rars_rs::ErrorKind::Cancelled => {
                        exception.is_instance_of::<PyInterruptedError>(py)
                    }
                    rars_rs::ErrorKind::WriterFailure => {
                        exception.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py)
                    }
                    rars_rs::ErrorKind::UnsafePath => {
                        exception.is_instance_of::<UnsafeArchivePath>(py)
                    }
                    rars_rs::ErrorKind::InvalidArgument => {
                        exception.is_instance_of::<PyValueError>(py)
                    }
                    rars_rs::ErrorKind::PasswordRequired => {
                        exception.is_instance_of::<PasswordRequired>(py)
                    }
                    rars_rs::ErrorKind::BadPassword => exception.is_instance_of::<BadPassword>(py),
                    _ => exception.is_instance_of::<BadRarFile>(py),
                };
                assert!(matches, "{kind:?}: {exception}");
                assert!(exception.to_string().contains("in volume 2"));
                assert!(exception.to_string().contains("member"));
            }
            let missing = CoreError::InVolume {
                number: 2,
                source: Box::new(CoreError::EntryNotFound.at_entry(b"gone".to_vec(), "removing")),
            };
            assert!(map_builder_error(missing).is_instance_of::<PyKeyError>(py));
        });
    }

    #[test]
    fn password_classification_survives_volume_context() {
        use rars_rs::Error;
        for (cause, needs_password, bad_password) in [
            (Error::NeedPassword, true, false),
            (Error::WrongPasswordOrCorruptData, false, true),
            (Error::InvalidHeader("broken header"), false, false),
        ] {
            let volume = Error::InVolume {
                number: 2,
                source: Box::new(cause.clone()),
            };
            let nested = Error::AtEntry {
                name: b"file".to_vec(),
                operation: "extracting",
                source: Box::new(Error::AtArchiveOffset {
                    offset: 123,
                    source: Box::new(volume.clone()),
                }),
            };
            for error in [cause, volume, nested] {
                assert_eq!(error_is_need_password(&error), needs_password, "{error}");
                assert_eq!(error_is_bad_password(&error), bad_password, "{error}");
            }
        }
    }

    #[test]
    fn parses_python_version_names() {
        assert_eq!(
            parse_version("rar5").unwrap(),
            rars_rs::ArchiveVersion::Rar50
        );
        assert_eq!(
            parse_version("rar70").unwrap(),
            rars_rs::ArchiveVersion::Rar70
        );
        assert!(parse_version("zip").is_err());
    }

    #[test]
    fn rejects_unsafe_archive_names() {
        assert!(rars_rs::validate_entry_name(b"dir/file.txt".to_vec()).is_ok());
        assert!(rars_rs::validate_entry_name(b"../file.txt".to_vec()).is_err());
        assert!(rars_rs::validate_entry_name(b"/tmp/file.txt".to_vec()).is_err());
        assert!(rars_rs::validate_entry_name(b"C:/file.txt".to_vec()).is_err());
    }

    #[test]
    fn builder_creates_readable_rar50_bytes() {
        let mut builder = rars_rs::Builder::new(rars_rs::ArchiveVersion::Rar50)
            .compression_level(Some(0))
            .store(true)
            .comment(Some(b"comment".to_vec()));
        builder
            .add_bytes(b"hello.txt".to_vec(), b"hello".to_vec(), None, None)
            .unwrap();

        let bytes = builder.to_bytes().unwrap();
        let archive = rars_rs::ArchiveReader::read_owned(bytes).unwrap();
        let names: Vec<_> = archive.members().map(|member| member.meta.name).collect();
        assert_eq!(names, vec![b"hello.txt".to_vec()]);
    }

    #[test]
    fn classifies_the_builder_refusals_python_reports_as_argument_errors() {
        let mut builder = rars_rs::Builder::new(rars_rs::ArchiveVersion::Rar50);
        builder
            .add_bytes(b"a".to_vec(), vec![], None, None)
            .unwrap();
        assert_eq!(
            classify_builder_error(
                &builder
                    .add_bytes(b"a".to_vec(), vec![], None, None)
                    .unwrap_err()
            ),
            BuilderRefusal::DuplicateName
        );
        assert_eq!(
            classify_builder_error(&builder.remove(b"gone").unwrap_err()),
            BuilderRefusal::NoSuchEntry
        );
        assert_eq!(
            classify_builder_error(&builder.rename(b"gone", b"x".to_vec()).unwrap_err()),
            BuilderRefusal::NoSuchEntry
        );
        // An unsafe name is not one of the three; it keeps reaching
        // `UnsafeArchivePath` through the general mapping.
        assert_eq!(
            classify_builder_error(
                &builder
                    .add_bytes(b"../escape".to_vec(), vec![], None, None)
                    .unwrap_err()
            ),
            BuilderRefusal::Other
        );
    }
}
