use pyo3::exceptions::{PyIsADirectoryError, PyKeyError, PyOSError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyByteArray, PyBytes, PyList, PyModule, PyString, PyTuple, PyType};
use pyo3::{create_exception, PyErr};
use rars_rs::filename::relative_path as output_relative_path;
use rars_rs::output_links::{create_link_output, link_source_path};
use rars_rs::output_staging::{
    failed_entry_name, publish_verified_output, refused_output, ExtractionStaging, OverwritePolicy,
};
use rars_rs::output_tree::{FileDir, HeldFile, OutputTree, TreeEntry};
use rars_rs::password_check::{PasswordProbe, PasswordVerdict};
use rars_rs::ExtractedLink;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(test)]
#[path = "../../rars/tests/support/scratch.rs"]
mod scratch;

mod unrars;

create_exception!(rars, Error, pyo3::exceptions::PyException);
// `BadRarFile` is damage; a password or a volume still to come is not.
create_exception!(rars, BadRarFile, Error);
create_exception!(rars, BadPassword, Error);
create_exception!(rars, PasswordRequired, Error);
create_exception!(rars, MissingVolume, Error);
create_exception!(rars, VolumeOrderError, Error);
create_exception!(rars, ChecksumError, BadRarFile);
create_exception!(rars, MemberCutShort, BadRarFile);
create_exception!(rars, MemberRanPastDeclaredSize, BadRarFile);
create_exception!(rars, UnsupportedRarFeature, Error);
create_exception!(rars, NotRarFile, Error);
create_exception!(rars, UnsafeArchivePath, Error);
create_exception!(rars, LimitExceeded, Error);
create_exception!(rars, UnsafeLinkWarning, pyo3::exceptions::PyUserWarning);
// Outside `Error`, so a loop that skips bad archives doesn't swallow a cancel.
create_exception!(rars, Cancelled, pyo3::exceptions::PyException);

/// `str` subclasses, so each member still compares, hashes and formats as its
/// value did when these were plain strings. Python 3.10 has no `StrEnum`.
const ENUMS: &CStr = c"
import enum


class ArchiveVersion(str, enum.Enum):
    RAR13 = 'rar13'
    RAR14 = 'rar14'
    RAR15 = 'rar15'
    RAR20 = 'rar20'
    RAR29 = 'rar29'
    RAR30 = 'rar30'
    RAR40 = 'rar40'
    RAR50 = 'rar50'
    RAR70 = 'rar70'


class ArchiveFamily(str, enum.Enum):
    RAR13 = 'rar13'
    RAR15_40 = 'rar15_40'
    RAR50_PLUS = 'rar50_plus'
    UNKNOWN = 'unknown'


class VolumeNaming(str, enum.Enum):
    PART = 'part'
    OLD = 'old'


class AttributeKind(str, enum.Enum):
    DOS = 'dos'
    UNIX = 'unix'
    UNKNOWN = 'unknown'


class ProgressPhase(str, enum.Enum):
    READING = 'reading'
    EXTRACTING = 'extracting'
    TESTING = 'testing'
    STAGING = 'staging'
    COMPRESSING = 'compressing'
    PROTECTING = 'protecting'
    WRITING = 'writing'


class TruncatedBlock(str, enum.Enum):
    MEMBER = 'member'
    RECOVERY_RECORD = 'recovery_record'
    SERVICE = 'service'
    COMMENT = 'comment'
    END = 'end'
    UNKNOWN = 'unknown'


class MissingPart(str, enum.Enum):
    START = 'start'
    END = 'end'
    BOTH = 'both'


class HeaderDamageKind(str, enum.Enum):
    CHECKSUM = 'checksum'
    DROPPED_RECORD = 'dropped_record'
    UNREADABLE = 'unreadable'


ENUMS = (
    ArchiveVersion,
    ArchiveFamily,
    VolumeNaming,
    AttributeKind,
    ProgressPhase,
    TruncatedBlock,
    MissingPart,
    HeaderDamageKind,
)
for cls in ENUMS:
    cls.__str__ = str.__str__
    cls.__format__ = str.__format__
    cls.__module__ = 'rars'
";

static ARCHIVE_FAMILY: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static VOLUME_NAMING: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static PROGRESS_PHASE: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static ATTRIBUTE_KIND: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static TRUNCATED_BLOCK: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static MISSING_PART: PyOnceLock<Py<PyType>> = PyOnceLock::new();
static HEADER_DAMAGE_KIND: PyOnceLock<Py<PyType>> = PyOnceLock::new();

fn enum_member<'py>(
    py: Python<'py>,
    class: &PyOnceLock<Py<PyType>>,
    name: &str,
    value: &str,
) -> PyResult<Bound<'py, PyAny>> {
    class.import(py, "rars", name)?.call1((value,))
}

#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone)]
struct ProgressEvent {
    phase: String,
    #[pyo3(get)]
    completed: u64,
    total: u64,
    #[pyo3(get)]
    pass_number: usize,
    #[pyo3(get)]
    entry_name: Option<Vec<u8>>,
    #[pyo3(get)]
    entry_index: Option<usize>,
    #[pyo3(get)]
    total_entries: Option<usize>,
    /// The volume being read, counting the first as 0; None outside a volume set.
    #[pyo3(get)]
    volume_index: Option<usize>,
    finished: bool,
    /// A set whose last volume hasn't been read yet has no total until it is.
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
    /// None when `repair(output=)` wrote it to a file.
    #[pyo3(get)]
    data: Option<Vec<u8>>,
    #[pyo3(get)]
    report: RepairReport,
}

/// Where an archive's file ends early. Every member listed is whole.
#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone)]
struct Truncation {
    /// File offset of the block the file ends in, or where the next block was due.
    #[pyo3(get)]
    offset: u64,
    block: &'static str,
    name: Option<Vec<u8>>,
    /// Whether any of that block is in the file.
    #[pyo3(get)]
    started: bool,
    /// Whether the cut can have lost no member: see `rars::Truncation`.
    #[pyo3(get)]
    members_complete: bool,
    /// The volume cut short, counting the one opened as 0.
    #[pyo3(get)]
    volume_index: usize,
    text: String,
}

impl Truncation {
    fn new(truncation: &rars_rs::Truncation, volume_index: usize) -> Self {
        use rars_rs::TruncatedBlock as Block;
        let (block, name) = match &truncation.block {
            Block::Member(name) => ("member", Some(name.clone())),
            Block::RecoveryRecord => ("recovery_record", None),
            Block::Service(name) => ("service", Some(name.clone())),
            Block::Comment => ("comment", None),
            Block::End => ("end", None),
            _ => ("unknown", None),
        };
        Self {
            offset: truncation.offset,
            block,
            name,
            started: truncation.started,
            members_complete: truncation.members_complete,
            volume_index,
            text: truncation.to_string(),
        }
    }
}

#[pymethods]
impl Truncation {
    #[getter]
    fn block<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        enum_member(py, &TRUNCATED_BLOCK, "TruncatedBlock", self.block)
    }

    /// The stored name of a cut member or service block, or None for other blocks.
    #[getter]
    fn name<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.name.as_deref().map(|name| PyBytes::new(py, name))
    }

    fn __str__(&self) -> &str {
        &self.text
    }

    fn __repr__(&self) -> String {
        format!(
            "Truncation(block={:?}, offset={}, started={}, volume_index={})",
            self.block, self.offset, self.started, self.volume_index
        )
    }
}

/// A damaged header that `salvage=True` read past.
#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone)]
struct HeaderDamage {
    /// File offset of the header, in its volume.
    #[pyo3(get)]
    offset: u64,
    kind: &'static str,
    /// The volume it is in, counting the one opened as 0.
    #[pyo3(get)]
    volume_index: usize,
    text: String,
}

impl HeaderDamage {
    fn list<'a>(volumes: impl IntoIterator<Item = &'a rars_rs::Archive>) -> Vec<Self> {
        use rars_rs::HeaderDamageKind as Kind;
        volumes
            .into_iter()
            .enumerate()
            .flat_map(|(volume_index, volume)| {
                volume.header_damage().iter().map(move |damage| Self {
                    offset: damage.offset,
                    kind: match damage.kind {
                        Kind::Checksum { .. } => "checksum",
                        Kind::DroppedRecord { .. } => "dropped_record",
                        _ => "unreadable",
                    },
                    volume_index,
                    text: damage.to_string(),
                })
            })
            .collect()
    }
}

#[pymethods]
impl HeaderDamage {
    #[getter]
    fn kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        enum_member(py, &HEADER_DAMAGE_KIND, "HeaderDamageKind", self.kind)
    }

    fn __str__(&self) -> &str {
        &self.text
    }

    fn __repr__(&self) -> String {
        format!(
            "HeaderDamage(kind={:?}, offset={}, volume_index={})",
            self.kind, self.offset, self.volume_index
        )
    }
}

/// A split member a salvaged volume set leaves out, as part of it is in a volume not given.
#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone)]
struct IncompleteMember {
    #[pyo3(get)]
    filename: String,
    orig_filename_bytes: Vec<u8>,
    /// The first volume holding part of it, counting the one opened as 0.
    #[pyo3(get)]
    volume_index: usize,
    missing: &'static str,
}

#[pymethods]
impl IncompleteMember {
    #[getter]
    fn orig_filename_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.orig_filename_bytes)
    }

    #[getter]
    fn missing<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        enum_member(py, &MISSING_PART, "MissingPart", self.missing)
    }

    fn __repr__(&self) -> String {
        format!(
            "IncompleteMember(filename={:?}, volume_index={}, missing={:?})",
            self.filename, self.volume_index, self.missing
        )
    }
}

#[pymethods]
impl ProgressEvent {
    #[getter]
    fn phase<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        enum_member(py, &PROGRESS_PHASE, "ProgressPhase", &self.phase)
    }

    /// Bytes the phase will handle, or None while that isn't known yet.
    #[getter]
    fn total(&self) -> Option<u64> {
        let unknown =
            !self.total_known || (self.phase == "writing" && self.total == 0 && !self.finished);
        (!unknown).then_some(self.total)
    }

    #[getter]
    fn percentage(&self) -> Option<f64> {
        match self.total()? {
            0 => Some(100.0),
            total => Some(self.completed as f64 * 100.0 / total as f64),
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

/// Limits for `RarBuilder` writes. Raising a limit never changes the archive written.
#[pyclass(frozen, module = "rars")]
#[derive(Debug, Clone, Default)]
struct WriterResources {
    /// Hard ceiling on the RAR 5 writer's managed allocations; exceeding it
    /// raises `LimitExceeded`. `RarBuilder` refuses it for older versions.
    #[pyo3(get)]
    max_memory_bytes: Option<u64>,
    /// How much the members compressing at once may plan to use, for every
    /// version; the CLI's `--memory-limit`. The default is 256 MiB plus 160 MiB
    /// for each thread past the first, up to a quarter of memory on Linux.
    /// Lowering it runs fewer members at once; below 256 MiB it also plans
    /// smaller jobs, which can change the archive written.
    #[pyo3(get)]
    max_workspace_bytes: Option<u64>,
}

#[pymethods]
impl WriterResources {
    #[new]
    #[pyo3(signature = (*, max_memory_bytes = None, max_workspace_bytes = None))]
    fn new(max_memory_bytes: Option<u64>, max_workspace_bytes: Option<u64>) -> PyResult<Self> {
        if max_workspace_bytes == Some(0) {
            return Err(PyValueError::new_err(
                "max_workspace_bytes must be more than 0",
            ));
        }
        Ok(Self {
            max_memory_bytes,
            max_workspace_bytes,
        })
    }
}

impl WriterResources {
    fn core(&self) -> rars_rs::WriterResources {
        let mut resources = rars_rs::WriterResources::default();
        if let Some(limit) = self.max_workspace_bytes {
            resources = resources.with_memory_limit(limit);
        }
        match self.max_memory_bytes {
            Some(limit) => resources.with_max_memory_bytes(limit),
            None => resources,
        }
    }
}

/// Parsing, decoding and extraction policies, given to `RarFile` as defaults or to one call.
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
    max_rar50_dictionary_bytes: Option<u64>,
    /// The largest RAR 5 member decoded whole in memory; larger ones stream.
    #[pyo3(get)]
    max_rar50_buffered_member_bytes: Option<u64>,
    #[pyo3(get)]
    allow_rar3_vm_programs: bool,
    /// Caps members decoded side by side and a large RAR 5 member's block decoders; 0 or 1 keeps the call on the calling thread.
    #[pyo3(get)]
    threads: Option<usize>,
    /// Set per call from `progress=`, beside `cancellation` because a callback
    /// that raises cancels the read the same way.
    progress: Option<Arc<Py<PyAny>>>,
    /// Set by `RarFile(salvage=True)` for the parsing it does while opening, and never kept.
    salvage: bool,
}

#[pymethods]
impl ReadOptions {
    #[new]
    #[allow(clippy::too_many_arguments)] // Python keyword-only policy fields.
    #[pyo3(signature = (*, max_member_output_bytes=None, max_total_output_bytes=None, max_reader_workspace_bytes=None, max_rar50_dictionary_bytes=None, max_rar50_buffered_member_bytes=None, max_header_count=None, max_header_bytes=None, legacy_name_encoding=None, allow_rar3_vm_programs=false, threads=None))]
    fn new(
        max_member_output_bytes: Option<u64>,
        max_total_output_bytes: Option<u64>,
        max_reader_workspace_bytes: Option<u64>,
        max_rar50_dictionary_bytes: Option<u64>,
        max_rar50_buffered_member_bytes: Option<u64>,
        max_header_count: Option<u64>,
        max_header_bytes: Option<u64>,
        legacy_name_encoding: Option<String>,
        allow_rar3_vm_programs: bool,
        threads: Option<usize>,
    ) -> PyResult<Self> {
        let encoding = legacy_name_encoding
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(map_error)?;
        Ok(Self {
            legacy_name_encoding,
            encoding,
            cancellation: None,
            max_member_output_bytes,
            max_total_output_bytes,
            max_reader_workspace_bytes,
            max_rar50_dictionary_bytes,
            max_rar50_buffered_member_bytes,
            max_header_count,
            max_header_bytes,
            allow_rar3_vm_programs,
            threads,
            progress: None,
            salvage: false,
        })
    }
}

impl ReadOptions {
    /// One call's options: the caller's policies plus that call's `progress=`,
    /// called with a `ProgressEvent` a few times a second at most, and its
    /// `cancellation=`. An exception the callback raises stops the call and is re-raised.
    fn for_call(
        options: Option<&Self>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Option<Self>> {
        if progress.is_none() && cancellation.is_none() {
            return Ok(options.cloned());
        }
        if progress.is_some_and(|progress| !progress.is_callable()) {
            return Err(PyValueError::new_err("progress must be callable"));
        }
        let mut call = options.cloned().unwrap_or_default();
        if let Some(token) = cancellation {
            call.cancellation = Some(token.inner.clone());
        }
        if let Some(progress) = progress {
            call.progress = Some(Arc::new(progress.clone().unbind()));
        }
        Ok(Some(call))
    }

    /// The policies alone, without a call's progress or cancellation.
    fn policies(&self) -> Self {
        Self {
            cancellation: None,
            progress: None,
            salvage: false,
            ..self.clone()
        }
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
        options.rar50_dictionary_size_limit = settings.max_rar50_dictionary_bytes;
        options.rar50_buffered_decode_limit = settings.max_rar50_buffered_member_bytes;
        options.allow_rar3_vm_programs = settings.allow_rar3_vm_programs;
        options.threads = settings.threads;
        options.salvage = settings.salvage;
    }
    options
}

/// A call's `on_member_error`, which the library asks about each member it fails on.
struct MemberErrors {
    callback: Py<PyAny>,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    /// What the callback raised, which the call raises instead.
    raised: Mutex<Option<PyErr>>,
    /// Members gone past, whose output is not to be published.
    failed: Mutex<Vec<Vec<u8>>>,
    /// `keep_broken=True`: a failed member's output is published, unless it
    /// failed on its password, before any of it was decoded.
    keep_broken: bool,
}

impl MemberErrors {
    fn new(
        callback: Option<&Bound<'_, PyAny>>,
        encoding: Option<rars_rs::filename::LegacyNameEncoding>,
        keep_broken: bool,
    ) -> PyResult<Option<Self>> {
        let Some(callback) = callback else {
            return Ok(None);
        };
        if !callback.is_callable() {
            return Err(PyValueError::new_err("on_member_error must be callable"));
        }
        Ok(Some(Self {
            callback: callback.clone().unbind(),
            encoding,
            raised: Mutex::new(None),
            failed: Mutex::new(Vec::new()),
            keep_broken,
        }))
    }

    /// Gives the callback the error, naming the member, and carries on unless it raises.
    fn handle(
        &self,
        member: &rars_rs::ArchiveMember,
        error: &rars_rs::Error,
    ) -> rars_rs::Result<rars_rs::ExtractionErrorAction> {
        // A wrong password or an I/O error, our own output included, ends the call, as in the CLI.
        if matches!(
            error.kind(),
            rars_rs::ErrorKind::BadPassword | rars_rs::ErrorKind::Io
        ) {
            return Ok(rars_rs::ExtractionErrorAction::Abort);
        }
        let name = match member.decoded_name(self.encoding) {
            Ok(name) => String::from_utf8_lossy(&name).into_owned(),
            Err(_) => String::from_utf8_lossy(&member.meta.name).into_owned(),
        };
        let called = Python::attach(|py| {
            // The error is about this member even when the library's error doesn't name it.
            let exception = match set_fault(error, is_checksum_mismatch) {
                Some(fault) if fault.member.is_none() => with_attribute(
                    py,
                    ChecksumError::new_err(error.to_string()),
                    "volume_index",
                    fault.volume_index,
                ),
                _ => map_error(error.clone()),
            };
            let exception = with_attribute(py, exception, "member", name);
            self.callback.call1(py, (exception.value(py),)).map(drop)
        });
        match called {
            Ok(()) => {
                let kept = self.keep_broken
                    && !matches!(
                        error.kind(),
                        rars_rs::ErrorKind::PasswordRequired | rars_rs::ErrorKind::BadPassword
                    );
                if !kept {
                    lock(&self.failed).push(member.meta.name.clone());
                }
                Ok(rars_rs::ExtractionErrorAction::Continue)
            }
            Err(raised) => {
                *lock(&self.raised) = Some(raised);
                Ok(rars_rs::ExtractionErrorAction::Abort)
            }
        }
    }

    fn finish<T>(errors: &Option<Self>, result: PyResult<T>) -> PyResult<T> {
        match errors
            .as_ref()
            .and_then(|errors| lock(&errors.raised).take())
        {
            Some(raised) => Err(raised),
            None => result,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
                volume_index: None,
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
        state.volume = first.is_volume().then_some(0);
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
            volume_index: state.volume,
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
        rars_rs::WriteOperation::Compression => "compressing",
        rars_rs::WriteOperation::Recovery => "protecting",
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
    stored_time: Option<rars_rs::StoredTimestamp>,
    /// Unix nanoseconds, the names `os.stat_result` uses; a creation time is `birthtime_ns`.
    #[pyo3(get)]
    mtime_ns: Option<i128>,
    #[pyo3(get)]
    atime_ns: Option<i128>,
    #[pyo3(get)]
    birthtime_ns: Option<i128>,
    /// Python reads it as `CRC`, the name `zipfile` and `rarfile` use.
    crc: Option<u32>,
    /// The stored host number, which RAR 5 numbers differently from RAR 1.5 to 4.x.
    #[pyo3(get)]
    host_os: Option<u64>,
    attr_source: rars_rs::AttrSource,
    #[pyo3(get)]
    is_encrypted: bool,
    #[pyo3(get)]
    is_solid: bool,
    #[pyo3(get)]
    is_split_before: bool,
    #[pyo3(get)]
    is_split_after: bool,
    family: rars_rs::ArchiveFamily,
    #[pyo3(get)]
    file_attr: u64,
    is_directory: bool,
    is_redirection: bool,
    /// The volume the member starts in, counting the first as 0; Python counts from 1.
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

    /// Unix seconds, as `os.stat_result.st_mtime`.
    #[getter]
    fn mtime(&self) -> Option<f64> {
        self.mtime_ns.map(|nanoseconds| nanoseconds as f64 / 1e9)
    }

    /// Whole-second local wall-clock fields, as `zipfile.ZipInfo.date_time`. RAR 1.3 to
    /// 4.x store them so; a RAR 5 time is converted. None when no time was recorded.
    #[getter]
    fn date_time<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyTuple>>> {
        let fields = match self.stored_time {
            None => return Ok(None),
            Some(rars_rs::StoredTimestamp::UnixSeconds(seconds)) => {
                let local = py.import("time")?.call_method1("localtime", (seconds,))?;
                return Ok(Some(PyTuple::new(
                    py,
                    (0..6)
                        .map(|index| local.get_item(index))
                        .collect::<PyResult<Vec<_>>>()?,
                )?));
            }
            Some(stored) => stored.calendar_fields(),
        };
        fields.map(|fields| fields.into_pyobject(py)).transpose()
    }

    #[getter]
    fn family<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        family_member(py, self.family)
    }

    /// What `file_attr` holds: DOS attribute bits, a Unix mode, or nothing meaningful.
    #[getter]
    fn file_attr_kind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = match self.attr_source {
            rars_rs::AttrSource::Dos => "dos",
            rars_rs::AttrSource::Unix => "unix",
            _ => "unknown",
        };
        enum_member(py, &ATTRIBUTE_KIND, "AttributeKind", value)
    }

    fn is_dir(&self) -> bool {
        self.is_directory
    }

    /// The volume the member starts in, counting the first as 0, so it indexes `volume_paths()`.
    #[getter]
    fn volume_index(&self) -> usize {
        self.volume
    }

    /// The same member of the same opened archive, however many times it was looked up.
    fn __eq__(&self, other: &Self) -> bool {
        self.member_index == other.member_index
            && match (&self.archive_identity, &other.archive_identity) {
                (Some(this), Some(that)) => Arc::ptr_eq(this, that),
                _ => false,
            }
    }

    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.archive_identity
            .as_ref()
            .map(Arc::as_ptr)
            .hash(&mut hasher);
        self.member_index.hash(&mut hasher);
        hasher.finish()
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
///
/// `mode` may only be `"r"`, as `RarFile` only reads; `RarBuilder` writes.
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
    closed: AtomicBool,
    /// A set opened with `salvage=True`: its later volumes, read once at opening.
    salvaged: Option<Vec<rars_rs::Archive>>,
    incomplete: Vec<IncompleteMember>,
    truncation: Option<Truncation>,
    /// Opened with `salvage=True`, which every later call reads with too.
    salvage: bool,
    header_damage: Vec<HeaderDamage>,
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
    ///
    /// `options` cover opening and are the defaults for every later call; a call's own
    /// `options` replace them whole. `cancellation` covers opening alone.
    ///
    /// `salvage=True` reads what survives. Opening reads past damaged headers,
    /// listed in `header_damage`, and lists a member the file is cut short
    /// inside, as `truncation` says. A volume set may begin late or end early,
    /// its later volumes read now, from `volumes` or found by name until one is
    /// missing. Split members with a part outside them are left out and listed
    /// in `incomplete_members`. Every later call delivers a damaged member's
    /// bytes, then reports its error to `on_member_error` or raises it.
    #[new]
    #[pyo3(signature = (source, mode = "r", *, password = None, options = None, cancellation = None, first_volume_only = false, volumes = None, salvage = false))]
    #[allow(clippy::too_many_arguments)] // Python keyword arguments.
    fn new(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        mode: &str,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        cancellation: Option<&CancellationToken>,
        first_volume_only: bool,
        volumes: Option<&Bound<'_, PyAny>>,
        salvage: bool,
    ) -> PyResult<Self> {
        if mode != "r" {
            return Err(PyValueError::new_err(
                "RarFile only reads, so mode must be 'r'; write archives with RarBuilder",
            ));
        }
        let mut call_options = ReadOptions::for_call(options, None, cancellation)?;
        if salvage {
            call_options
                .get_or_insert_with(ReadOptions::default)
                .salvage = true;
        }
        let options = call_options.as_ref();
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
        let mut file = file.with_set(first_volume_only, volumes);
        if salvage {
            file.salvage_set(py, options)?;
        }
        Ok(file)
    }

    fn namelist(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        self.check_open()?;
        Ok(self
            .listing(py)?
            .infos
            .iter()
            .map(|info| info.filename.clone())
            .collect())
    }

    fn infolist(&self, py: Python<'_>) -> PyResult<Vec<RarInfo>> {
        self.check_open()?;
        Ok(self.listing(py)?.infos.clone())
    }

    fn getinfo(&self, py: Python<'_>, member: &Bound<'_, PyAny>) -> PyResult<RarInfo> {
        self.check_open()?;
        let index = self.resolve_index(py, member)?;
        Ok(self.info_at(py, index)?.clone())
    }

    /// `volumes` works as in `extractall`, for a member that continues into later volumes.
    ///
    /// `on_member_error` reports a member that fails instead of raising, as in
    /// `testrar`, and the call returns what was delivered for it: everything
    /// decoded before the failure under `salvage=True`, and `b""` otherwise.
    /// It can't be combined with a member in a later volume.
    #[pyo3(signature = (member, *, password = None, options = None, progress = None, cancellation = None, volumes = None, on_member_error = None))]
    #[allow(clippy::too_many_arguments)] // Python keyword arguments.
    fn read(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        volumes: Option<&Bound<'_, PyAny>>,
        on_member_error: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<u8>> {
        self.check_open()?;
        let call_options = self.call_options(options, progress, cancellation)?;
        let options = call_options.as_ref();
        check_read_options_cancellation(options)?;
        let index = self.resolve_index(py, member)?;
        let data = self.read_indices(py, &[index], password, options, volumes, on_member_error)?;
        match data.into_iter().next().flatten() {
            Some(data) => Ok(data),
            None => Err(no_payload(self.info_at(py, index)?)),
        }
    }

    /// `on_member_error` works as in `read`.
    #[pyo3(signature = (member, *, password = None, options = None, progress = None, cancellation = None, volumes = None, on_member_error = None))]
    #[allow(clippy::too_many_arguments)] // Python keyword arguments.
    fn open(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        volumes: Option<&Bound<'_, PyAny>>,
        on_member_error: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let call_options = self.call_options(options, progress, cancellation)?;
        let options = call_options.as_ref();
        let data = self.read(
            py,
            member,
            password,
            options,
            None,
            None,
            volumes,
            on_member_error,
        )?;
        let io = py.import("io")?;
        let bytes = PyBytes::new(py, &data);
        Ok(io.getattr("BytesIO")?.call1((bytes,))?.unbind())
    }

    /// Read selected members in one session, preserving request order and duplicates.
    /// Output limits apply to the whole call, including required solid predecessors.
    /// `on_member_error` works as in `read`, for each member that fails.
    #[pyo3(signature = (members, *, password = None, options = None, progress = None, cancellation = None, volumes = None, on_member_error = None))]
    #[allow(clippy::too_many_arguments)] // Python keyword arguments.
    fn read_many(
        &self,
        py: Python<'_>,
        members: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        volumes: Option<&Bound<'_, PyAny>>,
        on_member_error: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<Vec<u8>>> {
        self.check_open()?;
        let call_options = self.call_options(options, progress, cancellation)?;
        let options = call_options.as_ref();
        check_read_options_cancellation(options)?;
        let indices = members
            .try_iter()?
            .map(|member| self.resolve_index(py, &member?))
            .collect::<PyResult<Vec<_>>>()?;
        self.read_indices(py, &indices, password, options, volumes, on_member_error)?
            .into_iter()
            .zip(&indices)
            .map(|(bytes, &index)| match bytes {
                Some(bytes) => Ok(bytes),
                None => Err(no_payload(self.info_at(py, index)?)),
            })
            .collect()
    }

    /// `overwrite`, `in_place`, `flatten` and `volumes` work as in `extractall`.
    #[pyo3(signature = (member, path = None, *, password = None, overwrite = Overwrite(OverwritePolicy::Never), options = None, progress = None, cancellation = None, volumes = None, restore_times = true, in_place = false, flatten = false))]
    #[allow(clippy::too_many_arguments)]
    fn extract(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        path: Option<PathBuf>,
        password: Option<&Bound<'_, PyAny>>,
        overwrite: Overwrite,
        options: Option<&ReadOptions>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        volumes: Option<&Bound<'_, PyAny>>,
        restore_times: bool,
        in_place: bool,
        flatten: bool,
    ) -> PyResult<PathBuf> {
        self.check_open()?;
        let call_options = self.call_options(options, progress, cancellation)?;
        let options = call_options.as_ref();
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
                None,
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
                    None,
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
    /// more and must stop, not wait. A volume whose recorded number doesn't
    /// follow the one before raises `VolumeOrderError` with its `volume_index`;
    /// files written before it are complete, so call again in order with
    /// `overwrite=True`. RAR 1.3 to 2.0 volumes record no number, so a wrong
    /// order shows as damage instead.
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
    ///
    /// `on_member_error` carries on past members that fail, as `testrar` does,
    /// and none of their output is kept. It can't be combined with `members`.
    /// `keep_broken=True`, on a `RarFile` opened with `salvage=True`, keeps
    /// it: each member `on_member_error` is given keeps its file under its own
    /// name, holding what was delivered for it, unless it failed on its password.
    #[pyo3(signature = (path = None, members = None, *, password = None, overwrite = Overwrite(OverwritePolicy::Never), options = None, progress = None, cancellation = None, volumes = None, restore_times = true, in_place = false, flatten = false, on_member_error = None, keep_broken = false))]
    #[allow(clippy::too_many_arguments)]
    fn extractall(
        &self,
        py: Python<'_>,
        path: Option<PathBuf>,
        members: Option<&Bound<'_, PyAny>>,
        password: Option<&Bound<'_, PyAny>>,
        overwrite: Overwrite,
        options: Option<&ReadOptions>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        volumes: Option<&Bound<'_, PyAny>>,
        restore_times: bool,
        in_place: bool,
        flatten: bool,
        on_member_error: Option<&Bound<'_, PyAny>>,
        keep_broken: bool,
    ) -> PyResult<Vec<PathBuf>> {
        self.check_open()?;
        if keep_broken && !self.salvage {
            return Err(PyValueError::new_err(
                "keep_broken=True needs a RarFile opened with salvage=True",
            ));
        }
        if keep_broken && on_member_error.is_none() {
            return Err(PyValueError::new_err(
                "keep_broken=True needs on_member_error, which reports each member kept",
            ));
        }
        if members.is_some() && on_member_error.is_some() {
            // Selection counts the outputs opened, which a member failing before its output would upset.
            return Err(PyValueError::new_err(
                "on_member_error reads every member, so it can't be combined with members",
            ));
        }
        let call_options = self.call_options(options, progress, cancellation)?;
        let options = call_options.as_ref();
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
        let member_errors =
            MemberErrors::new(on_member_error, options.legacy_name_encoding, keep_broken)?;
        let handler = |member: &rars_rs::ArchiveMember, error: &rars_rs::Error| {
            member_errors
                .as_ref()
                .map_or(Ok(rars_rs::ExtractionErrorAction::Abort), |errors| {
                    errors.handle(member, error)
                })
        };
        let options = match &member_errors {
            Some(_) => options.with_member_error_handler(&handler),
            None => options,
        };
        let failed = member_errors.as_ref().map(|errors| &errors.failed);
        let in_set = match &selected {
            None => volumes.is_some() || self.archive.is_volume() && !self.salvaged_alone(),
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
                failed,
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
                    failed,
                )
            })
            .map_err(map_error)
        };
        finished(&progress, MemberErrors::finish(&member_errors, extracted))?.warn(py)
    }

    /// `volumes` works as in `extractall`.
    ///
    /// `on_member_error` carries on past members that fail, calling it with each
    /// error, its `member` set to the member's name. Raise from it to stop
    /// instead. A wrong password or an I/O error still stops the call, as do
    /// split members of a set with a volume missing; see `salvage`.
    #[pyo3(signature = (*, password = None, options = None, progress = None, cancellation = None, volumes = None, on_member_error = None))]
    #[allow(clippy::too_many_arguments)] // Python keyword arguments.
    fn testrar(
        &self,
        py: Python<'_>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        volumes: Option<&Bound<'_, PyAny>>,
        on_member_error: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.check_open()?;
        let call_options = self.call_options(options, progress, cancellation)?;
        let options = call_options.as_ref();
        let password = py_password(password)?.or_else(|| self.password.clone());
        let progress = ReadProgress::new(options, "testing");
        let options = watched(
            &progress,
            self.extraction_options(options, password.as_deref()),
        );
        let member_errors =
            MemberErrors::new(on_member_error, options.legacy_name_encoding, false)?;
        let handler = |member: &rars_rs::ArchiveMember, error: &rars_rs::Error| {
            member_errors
                .as_ref()
                .map_or(Ok(rars_rs::ExtractionErrorAction::Abort), |errors| {
                    errors.handle(member, error)
                })
        };
        let options = match &member_errors {
            Some(_) => options.with_member_error_handler(&handler),
            None => options,
        };
        let first = &self.archive;
        let alone = volumes.is_none() && (!first.is_volume() || self.salvaged_alone());
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
            let sink = |meta: &rars_rs::ExtractedEntryMeta| {
                let sink = Box::new(io::sink()) as Box<dyn Write>;
                Ok(match &progress {
                    Some(progress) if !meta.is_directory => progress.counted(&meta.name, sink),
                    _ => sink,
                })
            };
            // Given `volumes`, `extract_set` refuses them.
            match self.salvaged_run().filter(|_| volumes.is_none()) {
                Some(run) => py
                    .detach(|| rars_rs::extract_volumes_to_with_options(&run, options, sink))
                    .map_err(map_error),
                None => self.extract_set(py, volumes, options, |volumes| {
                    let all = |_: usize| true;
                    let volumes = tracked(progress.as_deref(), volumes, &all);
                    first.extract_with_volumes(volumes, options, sink)
                }),
            }
        };
        finished(&progress, MemberErrors::finish(&member_errors, result))
    }

    /// Where the file ends early, or None. In a set opened with `salvage=True`,
    /// the first volume that does.
    #[getter]
    fn truncation(&self) -> Option<Truncation> {
        self.truncation.clone()
    }

    /// The split members `salvage=True` left out of a volume set, in archive order.
    #[getter]
    fn incomplete_members(&self) -> Vec<IncompleteMember> {
        self.incomplete.clone()
    }

    /// The damaged headers `salvage=True` read past, in file order. Always
    /// empty without salvage, which refuses such an archive instead.
    #[getter]
    fn header_damage(&self) -> Vec<HeaderDamage> {
        self.header_damage.clone()
    }

    #[getter]
    fn comment(&self, py: Python<'_>) -> PyResult<Option<Vec<u8>>> {
        self.read_comment(py, None, None, None)
    }

    /// Returns the complete archive comment, or None if absent, under per-call read policies.
    #[pyo3(signature = (*, password = None, options = None, cancellation = None))]
    fn read_comment(
        &self,
        py: Python<'_>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Option<Vec<u8>>> {
        self.check_open()?;
        let call_options = self.call_options(options, None, cancellation)?;
        let options = call_options.as_ref();
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

    /// Returns the comment attached to a member, or None if absent.
    #[pyo3(signature = (member, *, password = None, options = None, cancellation = None))]
    fn member_comment(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Option<Vec<u8>>> {
        self.check_open()?;
        let call_options = self.call_options(options, None, cancellation)?;
        let options = call_options.as_ref();
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
    #[pyo3(signature = (member, *, password = None, options = None, cancellation = None))]
    fn readlink(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Vec<u8>> {
        self.check_open()?;
        let call_options = self.call_options(options, None, cancellation)?;
        let options = call_options.as_ref();
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
        if !member.meta.is_redirection {
            return Err(PyValueError::new_err(format!(
                "{} is not a link",
                String::from_utf8_lossy(&member.meta.name)
            )));
        }
        member
            .supported_redirection()
            .map(|link| link.target_name.clone())
            .ok_or_else(|| {
                UnsupportedRarFeature::new_err("member is a kind of link rars cannot read")
            })
    }

    /// Stops at the first volume missing or unreadable rather than raising, so clean-up gets what is there.
    fn volume_paths(&self, py: Python<'_>) -> PyResult<Vec<PathBuf>> {
        self.check_open()?;
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
                Ok(1 + volumes_to_last(&self.archive, volumes, false)
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
    fn family<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        family_member(py, self.archive.family())
    }

    #[getter]
    fn is_volume(&self) -> bool {
        self.archive.is_volume()
    }

    /// This volume's place in its set, counting the first as 0; None when the headers don't record it.
    #[getter]
    fn volume_index(&self) -> Option<u64> {
        self.archive.volume_index()
    }

    #[getter]
    fn is_first_volume(&self) -> Option<bool> {
        self.archive.is_first_volume()
    }

    #[getter]
    fn volume_naming<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = match self.archive.volume_naming() {
            rars_rs::volume_name::VolumeNaming::Part => "part",
            rars_rs::volume_name::VolumeNaming::Old => "old",
        };
        enum_member(py, &VOLUME_NAMING, "VolumeNaming", value)
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
        self.close();
        false
    }

    /// Later reads raise `ValueError`, as a closed file's do. Closing again does nothing.
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// Whether the archive was opened with `first_volume_only=True`.
    #[getter]
    fn first_volume_only(&self) -> bool {
        self.first_volume_only
    }

    #[getter]
    fn closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.check_open()?;
        let list = PyList::new(py, self.listing(py)?.infos.clone())?;
        Ok(list.call_method0("__iter__")?.unbind())
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        self.check_open()?;
        Ok(self.listing(py)?.infos.len())
    }

    /// Takes what `getinfo` takes; a `RarInfo` from another archive is not in this one.
    fn __contains__(&self, py: Python<'_>, member: &Bound<'_, PyAny>) -> PyResult<bool> {
        self.check_open()?;
        if let Ok(info) = member.extract::<PyRef<'_, RarInfo>>() {
            return Ok(info
                .archive_identity
                .as_ref()
                .is_some_and(|identity| Arc::ptr_eq(identity, &self.identity)));
        }
        match self.resolve_index(py, member) {
            Ok(_) => Ok(true),
            Err(error) if error.is_instance_of::<PyKeyError>(py) => Ok(false),
            // Two members decode to this name.
            Err(error) if error.is_instance_of::<PyValueError>(py) => Ok(true),
            Err(error) => Err(error),
        }
    }
}

impl RarFile {
    fn check_open(&self) -> PyResult<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(PyValueError::new_err("I/O operation on closed archive"));
        }
        Ok(())
    }

    /// A first-volume member never waits for later volumes; its split sizes are whole once the set is listed.
    fn info_at(&self, py: Python<'_>, index: usize) -> PyResult<&RarInfo> {
        let listing = match self.whole.get() {
            Some(whole) => whole,
            None if index < self.first.infos.len() => &self.first,
            None => self.listing(py)?,
        };
        Ok(&listing.infos[index])
    }

    /// A call's own `options` replace the ones the archive was opened with, whole.
    fn call_options(
        &self,
        options: Option<&ReadOptions>,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Option<ReadOptions>> {
        let defaults = self.options.as_ref().map(ReadOptions::policies);
        ReadOptions::for_call(options.or(defaults.as_ref()), progress, cancellation)
    }

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
        if let Some(salvaged) = &self.salvaged {
            if volumes.is_some() {
                return Err(PyValueError::new_err(
                    "a RarFile opened with salvage=True reads the volumes it read at opening; pass volumes= when opening it",
                ));
            }
            let mut later = salvaged.iter().cloned().map(Ok);
            return py.detach(|| run(&mut later)).map_err(map_error);
        }
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
                        false,
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
        let partial = self.salvaged.is_some();
        let whole = self.extract_set(py, None, options, |volumes| {
            list_later_volumes(archive, first, volumes, encoding, identity, partial)
        })?;
        Ok(self.whole.get_or_init(|| whole))
    }

    /// A set's later volumes are read here, as their headers describe the set's members.
    /// The rest of the set a rewrite reads, after this first volume.
    fn rewrite_volumes(
        &self,
        py: Python<'_>,
        volumes: Option<&Bound<'_, PyAny>>,
        password: Option<&[u8]>,
    ) -> PyResult<Vec<rars_rs::Archive>> {
        let options = self.extraction_options(self.options.as_ref(), password);
        if !self.archive.is_volume() {
            Ok(Vec::new())
        } else if self.first_volume_only {
            Err(PyValueError::new_err(
                "a RarFile opened with first_volume_only=True cannot rewrite its volume set; open it without first_volume_only",
            ))
        } else {
            self.extract_set(py, volumes, options, |volumes| {
                volumes_to_last(&self.archive, volumes, false).collect()
            })
        }
    }

    /// Only a set's first volume knows where the set starts, and bytes alone can't find the rest.
    /// A salvaged set lists the volumes it read at opening.
    fn lists_later_volumes(&self) -> bool {
        self.archive.is_volume()
            && (self.salvaged.is_some()
                || starts_set(&self.archive) && (self.path.is_some() || self.volumes.is_some()))
    }

    /// A salvaged volume on its own, which reads as a lone archive once its split members are gone.
    fn salvaged_alone(&self) -> bool {
        self.salvaged.as_ref().is_some_and(Vec::is_empty)
    }

    /// A salvaged set's volumes, read whole: one that ends early is not to wait for the rest.
    fn salvaged_run(&self) -> Option<Vec<rars_rs::Archive>> {
        let later = self.salvaged.as_ref().filter(|later| !later.is_empty())?;
        Some(
            std::iter::once(&self.archive)
                .chain(later)
                .cloned()
                .collect(),
        )
    }

    /// For `salvage=True`: reads the set's later volumes, those given or found by
    /// name, and leaves out the members they hold only part of.
    fn salvage_set(&mut self, py: Python<'_>, settings: Option<&ReadOptions>) -> PyResult<()> {
        if !self.archive.is_volume() {
            return Ok(());
        }
        let mut run = vec![self.archive.clone()];
        // A later volume would find the set's earlier ones by name as if it were the first.
        let finds_later =
            self.volumes.is_some() || self.path.is_some() && starts_set(&self.archive);
        if finds_later && !self.first_volume_only {
            let options = self.extraction_options(settings, self.password.as_deref());
            run.extend(self.extract_set(py, None, options, |volumes| {
                volumes.collect::<rars_rs::Result<Vec<_>>>()
            })?);
        }
        // Only a volume's first or last member can be incomplete; name it as `RarInfo` would.
        let mut names = HashMap::new();
        for (index, volume) in run.iter().enumerate() {
            for member in volume.members().take(1).chain(volume.members().last()) {
                let filename = String::from_utf8_lossy(
                    &member.decoded_name(self.encoding).map_err(map_error)?,
                )
                .into_owned();
                names.insert((index, member.meta.name.clone()), filename);
            }
        }
        self.incomplete = rars_rs::drop_incomplete_members(&mut run)
            .into_iter()
            .map(|member| IncompleteMember {
                filename: names
                    .remove(&(member.volume, member.name.clone()))
                    .unwrap_or_else(|| String::from_utf8_lossy(&member.name).into_owned()),
                orig_filename_bytes: member.name,
                volume_index: member.volume,
                missing: match member.missing {
                    rars_rs::MissingPart::Start => "start",
                    rars_rs::MissingPart::End => "end",
                    _ => "both",
                },
            })
            .collect();
        self.header_damage = HeaderDamage::list(&run);
        self.truncation = run.iter().enumerate().find_map(|(index, volume)| {
            volume
                .truncation()
                .map(|truncation| Truncation::new(truncation, index))
        });
        let mut run = run.into_iter();
        self.archive = run.next().expect("the opened volume leads the run");
        self.first = SetListing::new(
            member_infos(&self.archive, self.encoding, &self.identity).map_err(map_error)?,
        );
        self.salvaged = Some(run.collect());
        Ok(())
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
                    index: volume,
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
        failed: Option<&Mutex<Vec<Vec<u8>>>>,
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
                failed,
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
                None => match self.salvaged_run() {
                    Some(run) => rars_rs::extract_volumes_with_links(&run, options, open, link),
                    None => rars_rs::output_links::extract_arriving_with_links(
                        first, volumes, options, open, link,
                    ),
                },
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
        on_member_error: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<Option<Vec<u8>>>> {
        let in_set = indices.iter().any(|&index| self.needs_later_volumes(index));
        if in_set && on_member_error.is_some() {
            // A set's reads count the outputs opened, which a member failing before its output would upset.
            return Err(PyValueError::new_err(
                "on_member_error can't be combined with reading a member in a later volume; testrar and extractall can carry on past those",
            ));
        }
        let password = py_password(password)?.or_else(|| self.password.clone());
        let progress = ReadProgress::new(options, "reading");
        let options = watched(
            &progress,
            self.extraction_options(options, password.as_deref()),
        );
        let salvage = options.salvage;
        let member_errors =
            MemberErrors::new(on_member_error, options.legacy_name_encoding, false)?;
        let handler = |member: &rars_rs::ArchiveMember, error: &rars_rs::Error| {
            member_errors
                .as_ref()
                .map_or(Ok(rars_rs::ExtractionErrorAction::Abort), |errors| {
                    errors.handle(member, error)
                })
        };
        let options = match &member_errors {
            Some(_) => options.with_member_error_handler(&handler),
            None => options,
        };
        let data = if in_set {
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
        let mut data = finished(&progress, MemberErrors::finish(&member_errors, data))?;
        // Without salvage, what a failed member wrote before the failure was found isn't its own.
        if let Some(errors) = member_errors.as_ref().filter(|_| !salvage) {
            let failed = lock(&errors.failed);
            for (bytes, &index) in data.iter_mut().zip(indices) {
                let name = &self.info_at(py, index)?.orig_filename_bytes;
                if failed.iter().any(|failed| **failed == **name) {
                    if let Some(bytes) = bytes {
                        bytes.clear();
                    }
                }
            }
        }
        Ok(data)
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
        options.salvage |= self.salvage;
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
        let infos = member_infos(&archive, encoding, &identity).map_err(map_error)?;
        let truncation = archive
            .truncation()
            .map(|truncation| Truncation::new(truncation, 0));
        let header_damage = HeaderDamage::list([&archive]);
        Ok(Self {
            identity,
            encoding,
            archive,
            path: None,
            password,
            options: options.map(|options| ReadOptions {
                salvage: false,
                ..options.clone()
            }),
            volumes: None,
            first_volume_only: false,
            first: SetListing::new(infos),
            whole: OnceLock::new(),
            closed: AtomicBool::new(false),
            salvaged: None,
            incomplete: Vec::new(),
            truncation,
            salvage: options.is_some_and(|options| options.salvage),
            header_damage,
        })
    }
}

/// The members of one parsed volume, as `RarFile` lists them.
fn member_infos(
    archive: &rars_rs::Archive,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    identity: &Arc<()>,
) -> rars_rs::Result<Vec<RarInfo>> {
    archive
        .members()
        .enumerate()
        .map(|(index, member)| {
            let filename = String::from_utf8_lossy(&member.decoded_name(encoding)?).into_owned();
            let mut info = info_from_member_named(member, filename);
            info.member_index = index;
            info.archive_identity = Some(identity.clone());
            Ok(info)
        })
        .collect()
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

/// Writes each volume of a set to a file beside it as the volume fills, then
/// names the parts once the count is known, since that decides how they are
/// numbered. Only the volume being written is open; nothing is held.
struct PythonVolumeSink<'a> {
    first_path: &'a Path,
    rar50: bool,
    /// Staged volumes not yet published, in order.
    temporaries: Vec<PathBuf>,
    /// A part name that cannot exist, raised as Python sees it rather than as I/O.
    naming: Option<PyErr>,
}

impl<'a> PythonVolumeSink<'a> {
    fn new(first_path: &'a Path, rar50: bool) -> Self {
        Self {
            first_path,
            rar50,
            temporaries: Vec::new(),
            naming: None,
        }
    }

    fn part_path(&self, index: usize, total: usize) -> PyResult<PathBuf> {
        if self.rar50 {
            rar50_volume_part_path(self.first_path, index, total)
        } else {
            legacy_volume_part_path(self.first_path, index)
        }
    }

    fn check_name(&mut self, index: usize, total: usize) -> rars_rs::Result<()> {
        self.part_path(index, total).map(drop).map_err(|error| {
            let message = error.to_string();
            self.naming = Some(error);
            io::Error::other(message).into()
        })
    }

    /// Moves the staged volumes to their names. Every name is checked before
    /// any is used, so a refusal leaves existing files as they were.
    fn publish(
        mut self,
        overwrite: bool,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Vec<PathBuf>> {
        let total = self.temporaries.len();
        let paths = (0..total)
            .map(|index| self.part_path(index, total))
            .collect::<PyResult<Vec<_>>>()?;
        for path in &paths {
            refuse_existing(path, overwrite)?;
            if fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()) {
                return Err(PyIsADirectoryError::new_err(format!(
                    "{} is a directory",
                    path.display()
                )));
            }
        }
        let staged = std::mem::take(&mut self.temporaries);
        let mut remaining = staged.iter();
        for (temporary, path) in remaining.by_ref().zip(&paths) {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                self.temporaries = std::iter::once(temporary.clone())
                    .chain(remaining.cloned())
                    .collect();
                return Err(map_error(rars_rs::Error::Cancelled));
            }
            if let Err(error) = publish_volume(temporary, path, overwrite) {
                self.temporaries = std::iter::once(temporary.clone())
                    .chain(remaining.cloned())
                    .collect();
                return Err(match error.kind() {
                    io::ErrorKind::AlreadyExists => exists_error(path),
                    _ => map_io_error(error),
                });
            }
        }
        Ok(paths)
    }
}

/// Names a staged volume. Without `overwrite` a link cannot replace a file that
/// appeared since the names were checked; a file system without links renames.
fn publish_volume(temporary: &Path, path: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite {
        return fs::rename(temporary, path);
    }
    match fs::hard_link(temporary, path) {
        Ok(()) => fs::remove_file(temporary),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(_) => {
            if fs::symlink_metadata(path).is_ok() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            fs::rename(temporary, path)
        }
    }
}

impl Drop for PythonVolumeSink<'_> {
    fn drop(&mut self) {
        for temporary in &self.temporaries {
            let _ = fs::remove_file(temporary);
        }
    }
}

impl rars_rs::rar50::VolumeSink for PythonVolumeSink<'_> {
    fn expect_volumes(&mut self, total: u64) -> rars_rs::Result<()> {
        // Names only get harder to form as the index grows.
        let total = usize::try_from(total).unwrap_or(usize::MAX);
        for index in [0, total.saturating_sub(1)] {
            self.check_name(index, total)?;
        }
        Ok(())
    }

    fn start_volume(
        &mut self,
        index: u64,
    ) -> rars_rs::Result<Box<dyn rars_rs::rar50::VolumeOutput>> {
        // Refuse a name that cannot exist before writing a volume that would need it.
        let part = usize::try_from(index).unwrap_or(usize::MAX);
        self.check_name(part, part.saturating_add(1))?;
        let file_name = self
            .first_path
            .file_name()
            .ok_or_else(|| io::Error::other("volume path needs a file name"))?;
        for sequence in 0..128u8 {
            let mut name = std::ffi::OsString::from(".");
            name.push(file_name);
            name.push(format!(
                ".rars-volume-{}-{index:06}-{sequence:02x}",
                std::process::id()
            ));
            let temporary = self.first_path.with_file_name(name);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => {
                    self.temporaries.push(temporary);
                    return Ok(Box::new(file));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::other("could not allocate a unique temporary volume file").into())
    }
}

/// Original identity follows edits; verified payload sources belong to one write.
#[derive(Debug, Clone)]
struct RewriteInput {
    archive: rars_rs::Archive,
    later_volumes: Vec<rars_rs::Archive>,
    password: Option<Vec<u8>>,
    options: Option<ReadOptions>,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    /// Payloads still to stage, by builder id.
    members: HashMap<usize, rars_rs::RewritePayload>,
    directory: Option<PathBuf>,
    max_staged_bytes: Option<u64>,
}

impl RewriteInput {
    fn prepare<T>(
        &self,
        builder: &mut rars_rs::Builder,
        directory: &Path,
        progress: Option<Arc<PythonProgress>>,
        consume: impl FnOnce(&rars_rs::Builder) -> rars_rs::Result<T>,
    ) -> rars_rs::Result<T> {
        let payloads: Vec<_> = self.members.values().copied().collect();
        let limit = match self.max_staged_bytes {
            Some(limit) => limit,
            None => rars_rs::rewrite_payload_bytes(&payloads)?,
        };
        let mut options = python_read_options(self.options.as_ref(), self.password.as_deref());
        options.legacy_name_encoding = options.legacy_name_encoding.or(self.encoding);
        if let Some(progress) = &progress {
            options = options.with_cancellation(&progress.read_cancellation);
        }
        self.archive.with_rewrite_payloads(
            &self.later_volumes,
            &payloads,
            options,
            &rars_rs::RewriteStaging {
                directory: self.directory.as_deref().unwrap_or(directory).to_path_buf(),
                max_staged_bytes: limit,
            },
            progress
                .clone()
                .map(|progress| progress as Arc<dyn rars_rs::WriteProgress>),
            builder,
            consume,
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
    /// Everything after `version` is keyword-only, so later releases can add
    /// and regroup settings without breaking callers. `level=0` stores members uncompressed.
    #[new]
    #[pyo3(signature = (
        version = "rar50",
        *,
        level = 3,
        solid = false,
        password = None,
        encrypt_headers = false,
        blake2sp = false,
        comment = None,
        recovery_percent = None,
        volume_size = None,
        resources = None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        version: &str,
        level: i64,
        solid: bool,
        password: Option<&Bound<'_, PyAny>>,
        encrypt_headers: bool,
        blake2sp: bool,
        comment: Option<&Bound<'_, PyAny>>,
        recovery_percent: Option<u64>,
        volume_size: Option<usize>,
        resources: Option<&WriterResources>,
    ) -> PyResult<Self> {
        let format = parse_version(version)?;
        let password = py_password(password)?;
        let comment = py_optional_bytes(comment)?;
        let level = u8::try_from(level)
            .ok()
            .filter(|&level| level <= 5)
            .ok_or_else(|| PyValueError::new_err("level must be from 0 to 5"))?;
        // What the version alone decides is refused here, before any member is added.
        let shape = rars_rs::write_plan::PlanShape::new()
            .compressed(level > 0)
            .volumes(volume_size.is_some());
        let refuse_unless = |option: rars_rs::write_plan::WriterOption| {
            if rars_rs::write_plan::supports(format, option, shape) {
                return Ok(());
            }
            let set = if shape.volumes {
                " in a volume set"
            } else {
                ""
            };
            Err(PyValueError::new_err(format!(
                "{} cannot write {}{set}",
                format.as_str(),
                option.name()
            )))
        };
        if let Some(percent) = recovery_percent {
            refuse_unless(rars_rs::write_plan::WriterOption::RecoveryRecord)?;
            if !(1..=100).contains(&percent) {
                return Err(PyValueError::new_err(
                    "recovery_percent must be from 1 to 100",
                ));
            }
        }
        if encrypt_headers {
            if password.is_none() {
                return Err(PyValueError::new_err("encrypt_headers needs a password"));
            }
            refuse_unless(rars_rs::write_plan::WriterOption::Feature(
                rars_rs::Feature::HeaderEncryption,
            ))?;
        }
        if blake2sp {
            refuse_unless(rars_rs::write_plan::WriterOption::Feature(
                rars_rs::Feature::Blake2sp,
            ))?;
        }
        if comment.is_some() {
            refuse_unless(rars_rs::write_plan::WriterOption::ArchiveComment)?;
        }
        // Only the RAR 5 writer keeps its allocations to a quota.
        if resources.is_some_and(|resources| resources.max_memory_bytes.is_some())
            && format.family() != rars_rs::ArchiveFamily::Rar50Plus
        {
            return Err(PyValueError::new_err(format!(
                "{} cannot write to a memory limit; only rar50 and rar70 can",
                format.as_str()
            )));
        }
        if volume_size == Some(0) {
            return Err(PyValueError::new_err("volume_size must be more than 0"));
        }
        Ok(Self {
            inner: rars_rs::Builder::new(format)
                .compression_level(Some(level))
                .store(level == 0)
                .solid(solid)
                .password(password)
                .header_encryption(encrypt_headers)
                .blake2sp(blake2sp)
                .comment(comment)
                .recovery_percent(recovery_percent)
                .volume_size(volume_size),
            format,
            rewrite: None,
            resources: resources.map_or_else(rars_rs::WriterResources::default, |resources| {
                resources.core()
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
    /// `options` reads the source as `RarFile` does, replacing a `RarFile` source's own,
    /// both here and while staging. `cancellation` covers what this call reads;
    /// a write's own `cancellation` covers staging.
    /// A volume set rewrites into one archive with `preserve=False`, its later
    /// volumes taken from `volumes` as in `extractall`, else found by name. They are
    /// all read before this returns. Writing decodes every member up to the last one
    /// kept, removed ones included, so those must still be readable.
    #[pyo3(signature = (source, *, password = None, options = None, volumes = None, cancellation = None, preserve = true, staging_dir = None, max_staged_bytes = None))]
    #[allow(clippy::too_many_arguments)]
    fn from_archive(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        options: Option<&ReadOptions>,
        volumes: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
        preserve: bool,
        staging_dir: Option<&Bound<'_, PyAny>>,
        max_staged_bytes: Option<u64>,
    ) -> PyResult<Self> {
        let archive = match source.extract::<PyRef<'_, RarFile>>() {
            Ok(archive) if archive.closed() => return Err(archive.check_open().unwrap_err()),
            Ok(archive) => RarFile {
                identity: archive.identity.clone(),
                encoding: options.map_or(archive.encoding, |options| options.encoding),
                archive: archive.archive.clone(),
                path: archive.path.clone(),
                password: archive.password.clone(),
                options: ReadOptions::for_call(
                    options
                        .or(archive.options.as_ref())
                        .map(ReadOptions::policies)
                        .as_ref(),
                    None,
                    cancellation,
                )?,
                volumes: archive
                    .volumes
                    .as_ref()
                    .map(|volumes| volumes.clone_ref(py)),
                first_volume_only: archive.first_volume_only,
                first: SetListing::new(archive.first.infos.clone()),
                whole: OnceLock::new(),
                closed: AtomicBool::new(false),
                salvaged: archive.salvaged.clone(),
                incomplete: archive.incomplete.clone(),
                truncation: archive.truncation.clone(),
                salvage: archive.salvage,
                header_damage: archive.header_damage.clone(),
            },
            Err(_) => RarFile::new(
                py,
                source,
                "r",
                password,
                options,
                cancellation,
                false,
                None,
                false,
            )?,
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
        let later_volumes = archive.rewrite_volumes(py, volumes, password.as_deref())?;
        let options = archive.extraction_options(archive.options.as_ref(), password.as_deref());
        // Releases the GIL, which a file-object source takes from inside its lock.
        let (inner, payloads) = py
            .detach(|| {
                archive
                    .archive
                    .rewrite_builder(&later_volumes, options, preserve)
            })
            .map_err(map_builder_error)?;
        Ok(Self {
            format: inner.format(),
            inner,
            resources: rars_rs::WriterResources::default(),
            rewrite: Some(RewriteInput {
                archive: archive.archive.clone(),
                later_volumes,
                password,
                options: archive.options.as_ref().map(ReadOptions::policies),
                encoding: archive.encoding,
                members: payloads
                    .into_iter()
                    .map(|payload| (payload.id, payload))
                    .collect(),
                directory: staging_dir.map(|path| py_path_buf(py, path)).transpose()?,
                max_staged_bytes,
            }),
        })
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
    #[pyo3(signature = (arcname, *, mtime = None, mode = None))]
    fn add_directory(
        &mut self,
        arcname: &Bound<'_, PyAny>,
        mtime: Option<UnixSeconds>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.inner
            .add_directory(
                new_member_name(arcname)?,
                mtime.map(|UnixSeconds(time)| time),
                mode,
            )
            .map_err(map_builder_error)
    }

    /// `mtime` is Unix seconds, an int or a float such as `os.stat_result.st_mtime`, in every format.
    #[pyo3(signature = (data, arcname, *, mtime = None, mode = None))]
    fn add_bytes(
        &mut self,
        data: &Bound<'_, PyAny>,
        arcname: &Bound<'_, PyAny>,
        mtime: Option<UnixSeconds>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.inner
            .add_bytes(
                new_member_name(arcname)?,
                py_required_bytes(data)?,
                mtime.map(|UnixSeconds(time)| time),
                mode,
            )
            .map_err(map_builder_error)
    }

    /// Stable IDs in output order. Integer edit arguments select these IDs.
    fn member_ids(&self) -> Vec<usize> {
        self.inner.member_ids().collect()
    }

    fn remove(&mut self, member: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = self.edit_member_id(member)?;
        self.inner.remove_by_id(id).map_err(map_builder_error)?;
        if let Some(rewrite) = &mut self.rewrite {
            rewrite.members.remove(&id);
        }
        Ok(())
    }

    fn rename(&mut self, member: &Bound<'_, PyAny>, new: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = self.edit_member_id(member)?;
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
        mtime: Option<UnixSeconds>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.inner
            .add_unix_symlink(
                new_member_name(arcname)?,
                new_member_name(target)?,
                target_is_directory,
                mtime.map(|UnixSeconds(time)| time),
                mode,
            )
            .map_err(map_builder_error)
    }

    /// Sets times from exact Unix nanoseconds, named as on `RarInfo`; one left
    /// `None` keeps what the member has. RAR 1.3–4.x keep only `mtime_ns`, in 2-second steps.
    #[pyo3(signature = (member, *, mtime_ns=None, atime_ns=None, birthtime_ns=None))]
    fn set_times(
        &mut self,
        member: &Bound<'_, PyAny>,
        mtime_ns: Option<i128>,
        atime_ns: Option<i128>,
        birthtime_ns: Option<i128>,
    ) -> PyResult<()> {
        let time = |nanoseconds: Option<i128>| {
            nanoseconds
                .map(|nanoseconds| {
                    rars_rs::Timestamp::from_unix_nanoseconds(nanoseconds)
                        .ok_or_else(|| PyValueError::new_err("time is out of range"))
                })
                .transpose()
        };
        let times = rars_rs::FileTimes {
            modified: time(mtime_ns)?,
            created: time(birthtime_ns)?,
            accessed: time(atime_ns)?,
        };
        let id = self.edit_member_id(member)?;
        self.inner
            .set_times_by_id(id, times)
            .map_err(map_builder_error)
    }

    /// Sets or removes the comment attached to a queued member.
    #[pyo3(signature = (member, comment = None))]
    fn set_member_comment(
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
        if self.inner.splits_into_volumes() {
            return Err(PyValueError::new_err(
                "volume_size is set, so write the set to files with write()",
            ));
        }
        if self.resources.max_memory_bytes().is_none() {
            let bytes = self.detached(
                py,
                progress,
                cancellation,
                Path::new("."),
                |builder, progress| {
                    let mut output = Vec::new();
                    builder.write_to(&mut output, &self.resources, progress)?;
                    Ok(output)
                },
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

    /// Writes the archive to `path` and returns the files written: `path` alone, or with
    /// `volume_size` set, every part of the set, named from `path`.
    /// An existing file is refused unless `overwrite=True`. A set is written a volume at a
    /// time beside its first part and every part's name is checked before any is moved into
    /// place, so a refusal leaves existing files as they were.
    #[pyo3(signature = (path, *, overwrite = false, progress = None, cancellation = None))]
    fn write(
        &self,
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        overwrite: bool,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Vec<PathBuf>> {
        let path = py_path_buf(py, path)?;
        if self.inner.splits_into_volumes() {
            return self.write_volumes(py, path, overwrite, progress, cancellation);
        }
        refuse_existing(&path, overwrite)?;
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
        )?;
        Ok(vec![path])
    }
}

impl RarBuilder {
    fn write_volumes(
        &self,
        py: Python<'_>,
        first_path: PathBuf,
        overwrite: bool,
        progress: Option<&Bound<'_, PyAny>>,
        cancellation: Option<&CancellationToken>,
    ) -> PyResult<Vec<PathBuf>> {
        let rar50 = matches!(
            self.format,
            rars_rs::ArchiveVersion::Rar50 | rars_rs::ArchiveVersion::Rar70
        );
        // Volumes stream to files beside the set, so none is held in memory
        // and the budget only charges the coding, as for one archive.
        let (sink, result) = self.detached(
            py,
            progress,
            cancellation,
            output_directory(&first_path),
            |builder, progress| {
                // Spools go beside the set, as a single archive's do.
                let resources = self
                    .resources
                    .clone()
                    .with_temp_dir(output_directory(&first_path));
                let mut sink = PythonVolumeSink::new(&first_path, rar50);
                let result = builder.write_volumes_to(&mut sink, &resources, progress);
                Ok((sink, result))
            },
        )?;
        py.detach(|| {
            let mut sink = sink;
            if let Err(error) = result {
                return Err(sink.naming.take().unwrap_or_else(|| map_error(error)));
            }
            sink.publish(overwrite, cancellation)
        })
    }

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

/// What a writer raises for an existing file without `overwrite=True`, as extraction does.
fn exists_error(path: &Path) -> PyErr {
    PyOSError::new_err((
        libc::EEXIST,
        format!(
            "{} already exists; pass overwrite=True to replace it",
            path.display()
        ),
    ))
}

fn refuse_existing(path: &Path, overwrite: bool) -> PyResult<()> {
    if !overwrite && fs::symlink_metadata(path).is_ok() {
        return Err(exists_error(path));
    }
    Ok(())
}

fn output_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn check_python_cancellation(cancellation: Option<&CancellationToken>) -> PyResult<()> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(Cancelled::new_err(rars_rs::Error::Cancelled.to_string()));
    }
    Ok(())
}

/// Reads a whole file, polling for cancellation between chunks.
fn read_path_to_end(path: &Path, cancellation: Option<&CancellationToken>) -> PyResult<Vec<u8>> {
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
#[pyo3(signature = (source, candidates, *, options = None, cancellation = None))]
fn check_password(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    candidates: &Bound<'_, PyAny>,
    options: Option<&ReadOptions>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<PasswordCheck> {
    let call_options = ReadOptions::for_call(options, None, cancellation)?;
    let options = call_options.as_ref();
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
            Py::new(py, file)
        })
        .transpose()?;
    Ok(PasswordCheck {
        correct: winner.map(|(candidate, _)| candidate),
        undetermined,
        archive,
        needs_password,
    })
}

/// With `output=`, the repaired archive is written there once the repair
/// succeeds and `data` is None; otherwise `data` holds it. An existing
/// `output` is refused unless `overwrite=True`.
#[pyfunction]
#[pyo3(signature = (source, *, password = None, output = None, overwrite = false, options = None, cancellation = None))]
#[allow(clippy::too_many_arguments)] // Python keyword arguments.
fn repair(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
    output: Option<&Bound<'_, PyAny>>,
    overwrite: bool,
    options: Option<&ReadOptions>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<RepairResult> {
    check_python_cancellation(cancellation)?;
    let call_options = ReadOptions::for_call(options, None, cancellation)?;
    let options = call_options.as_ref();
    let output = output.map(|output| py_path_buf(py, output)).transpose()?;
    if let Some(output) = &output {
        refuse_existing(output, overwrite)?;
    }
    let password = py_password(password)?;
    let source = archive_input(source, cancellation.map(|token| &token.inner))?;
    check_python_cancellation(cancellation)?;
    py.detach(|| {
        let read_options = python_read_options(options, password.as_deref());
        let (data, report) = repair_core(source, read_options, output.as_deref(), cancellation)?;
        Ok(RepairResult {
            data,
            report: report.into(),
        })
    })
}

/// Opens the source as `RarFile` does, so a path or seekable file object is
/// read on demand. With `output`, the repair goes straight to the file and
/// `None` comes back, a source that will not parse included. Only that
/// damaged-header fallback without `output` reads the source whole, as it
/// returns the repaired archive whole. A parsing cancellation must not start
/// the fallback.
fn repair_core(
    source: ArchiveInput,
    options: rars_rs::ArchiveReadOptions<'_>,
    output: Option<&Path>,
    cancellation: Option<&CancellationToken>,
) -> PyResult<(Option<Vec<u8>>, rars_rs::RecoveryRepairReport)> {
    let opened = match &source {
        ArchiveInput::Bytes(bytes) => rars_rs::ArchiveReader::read_with_options(bytes, options),
        ArchiveInput::Path(path) => rars_rs::ArchiveReader::read_path_with_options(path, options),
        ArchiveInput::Reader(PyFileReader(file)) => {
            let reader = PyFileReader(Python::attach(|py| file.clone_ref(py)));
            rars_rs::ArchiveReader::read_reader_with_options(reader, options)
        }
    };
    let repaired = match opened {
        Ok(archive) => {
            return match output {
                Some(path) => archive
                    .repair_recovery_to_path_with_options(path, options)
                    .map(|report| (None, report)),
                None => archive
                    .repair_recovery_with_options(options)
                    .map(|repaired| (Some(repaired.data), repaired.report)),
            }
            .map_err(map_error);
        }
        Err(error) if error.kind() == rars_rs::ErrorKind::Cancelled => {
            return Err(map_error(error))
        }
        Err(_) if output.is_some() => {
            let output = output.expect("checked above");
            let report = match source {
                ArchiveInput::Bytes(bytes) => {
                    rars_rs::rar50::repair_inline_recovery_to_path_with_options(
                        io::Cursor::new(bytes),
                        output,
                        options,
                    )
                }
                ArchiveInput::Path(path) => {
                    rars_rs::rar50::repair_inline_recovery_to_path_with_options(
                        fs::File::open(path).map_err(map_io_error)?,
                        output,
                        options,
                    )
                }
                ArchiveInput::Reader(PyFileReader(file)) => {
                    rars_rs::rar50::repair_inline_recovery_to_path_with_options(
                        PyFileReader(file),
                        output,
                        options,
                    )
                }
            };
            return report.map(|report| (None, report)).map_err(map_error);
        }
        Err(_) => {
            let bytes = match source {
                ArchiveInput::Bytes(bytes) => bytes,
                ArchiveInput::Path(path) => read_path_to_end(&path, cancellation)?,
                ArchiveInput::Reader(PyFileReader(file)) => Python::attach(|py| {
                    let file = file.bind(py);
                    file.call_method1("seek", (0,))?;
                    py_read_to_end(file, cancellation.map(|token| &token.inner))
                })?,
            };
            rars_rs::rar50::repair_inline_recovery_bytes_with_options(&bytes, options)
                .map_err(map_error)?
        }
    };
    match output {
        Some(path) => {
            repaired
                .write_to_path(path, cancellation.map(|token| &token.inner))
                .map_err(map_error)?;
            Ok((None, repaired.report))
        }
        None => Ok((Some(repaired.data), repaired.report)),
    }
}

#[pymodule]
fn rars(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RarFile>()?;
    m.add_class::<RarInfo>()?;
    m.add_class::<RarBuilder>()?;
    m.add_class::<ProgressEvent>()?;
    m.add_class::<CancellationToken>()?;
    m.add_class::<ReadOptions>()?;
    m.add_class::<WriterResources>()?;
    m.add_class::<RepairReport>()?;
    m.add_class::<RepairResult>()?;
    m.add_class::<PasswordCheck>()?;
    m.add_class::<Truncation>()?;
    m.add_class::<IncompleteMember>()?;
    m.add_class::<HeaderDamage>()?;
    m.add_function(wrap_pyfunction!(check_password, m)?)?;
    m.add_function(wrap_pyfunction!(is_rarfile, m)?)?;
    m.add_function(wrap_pyfunction!(is_rarfile_sfx, m)?)?;
    m.add_function(wrap_pyfunction!(repair, m)?)?;
    // Set rather than added, so it stays out of `__all__` and the package.
    m.setattr("_unrars_main", wrap_pyfunction!(unrars::unrars_main, m)?)?;
    let error = py.get_type::<Error>();
    // Set on the errors `on_member_error` is given; None elsewhere unless a subclass says.
    error.setattr("member", py.None())?;
    m.add("Error", error)?;
    m.add("BadRarFile", py.get_type::<BadRarFile>())?;
    m.add("BadPassword", py.get_type::<BadPassword>())?;
    m.add("PasswordRequired", py.get_type::<PasswordRequired>())?;
    let missing_volume = py.get_type::<MissingVolume>();
    missing_volume.setattr("volume_index", py.None())?;
    missing_volume.setattr("path", py.None())?;
    m.add("MissingVolume", missing_volume)?;
    let volume_order = py.get_type::<VolumeOrderError>();
    volume_order.setattr("volume_index", py.None())?;
    m.add("VolumeOrderError", volume_order)?;
    let checksum_error = py.get_type::<ChecksumError>();
    checksum_error.setattr("member", py.None())?;
    checksum_error.setattr("volume_index", py.None())?;
    m.add("ChecksumError", checksum_error)?;
    let cut_short = py.get_type::<MemberCutShort>();
    cut_short.setattr("member", py.None())?;
    cut_short.setattr("packed", py.None())?;
    cut_short.setattr("present", py.None())?;
    m.add("MemberCutShort", cut_short)?;
    let ran_past = py.get_type::<MemberRanPastDeclaredSize>();
    ran_past.setattr("member", py.None())?;
    ran_past.setattr("declared", py.None())?;
    m.add("MemberRanPastDeclaredSize", ran_past)?;
    m.add(
        "UnsupportedRarFeature",
        py.get_type::<UnsupportedRarFeature>(),
    )?;
    m.add("NotRarFile", py.get_type::<NotRarFile>())?;
    m.add("UnsafeArchivePath", py.get_type::<UnsafeArchivePath>())?;
    m.add("LimitExceeded", py.get_type::<LimitExceeded>())?;
    m.add("UnsafeLinkWarning", py.get_type::<UnsafeLinkWarning>())?;
    m.add("Cancelled", py.get_type::<Cancelled>())?;
    let enums = PyModule::from_code(py, ENUMS, c"rars/_enums.py", c"rars._enums")?;
    for name in [
        "ArchiveVersion",
        "ArchiveFamily",
        "VolumeNaming",
        "AttributeKind",
        "ProgressPhase",
        "TruncatedBlock",
        "MissingPart",
        "HeaderDamageKind",
    ] {
        m.add(name, enums.getattr(name)?)?;
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

/// Unix seconds as an int or a float, as `time.time()` and `os.stat_result.st_mtime` give them.
struct UnixSeconds(rars_rs::Timestamp);

impl<'a, 'py> FromPyObject<'a, 'py> for UnixSeconds {
    type Error = PyErr;

    fn extract(value: pyo3::Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if value.is_instance_of::<pyo3::types::PyInt>() {
            return Ok(Self(rars_rs::Timestamp::from_unix_seconds(
                value.extract()?,
            )));
        }
        let seconds = value.extract::<f64>()?;
        if !seconds.is_finite() {
            return Err(PyValueError::new_err(
                "mtime must be a finite number of seconds",
            ));
        }
        let whole = seconds.floor();
        let nanoseconds = ((seconds - whole) * 1e9).round().min(999_999_999.0) as u32;
        Ok(Self(
            rars_rs::Timestamp::new(whole as i64, nanoseconds)
                .ok_or_else(|| PyValueError::new_err("time is out of range"))?,
        ))
    }
}

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
    /// Members `on_member_error` went past, whose pending output is dropped.
    failed: Option<&'a Mutex<Vec<Vec<u8>>>>,
    /// The output directory walked by descriptor, where the platform allows,
    /// once it exists. Each directory is opened once without following a
    /// symlink, and files are created and published relative to it.
    out_tree: Option<OutputTree>,
    /// Where files stage by descriptor in the staging storage, and its path.
    staged_files: Option<(FileDir, PathBuf)>,
}

/// Where staged files go in a staging storage walked by descriptor. Links
/// stage beside it under their numbers.
const STAGED_FILES: &str = "files";

struct PendingOutput {
    /// None when the member is written in place.
    staged: Option<PathBuf>,
    /// Staged by descriptor: the directory it is in and its name there.
    staged_at: Option<(FileDir, std::ffi::OsString)>,
    /// Written in place by descriptor: the file, once the library is done writing it.
    held: Option<Arc<OnceLock<fs::File>>>,
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
        failed: Option<&'a Mutex<Vec<Vec<u8>>>>,
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
            failed,
            out_tree: None,
            staged_files: None,
        }
    }

    /// The output directory walked by descriptor, opened once it exists, or
    /// made first if `create`. `None` where the platform has no such walk.
    fn tree(&mut self, create: bool) -> rars_rs::Result<Option<&mut OutputTree>> {
        if self.out_tree.is_none() && rars_rs::output_tree::AVAILABLE {
            if create {
                fs::create_dir_all(self.out_dir)?;
            }
            self.out_tree = OutputTree::open(self.out_dir)?;
        }
        Ok(self.out_tree.as_mut())
    }

    /// Drops the walks' open directories, after a change made by path.
    fn forget_walks(&mut self) {
        if let Some(tree) = &mut self.out_tree {
            tree.forget();
        }
    }

    /// Stored path for link lookups, and destination, which flattening
    /// reduces to the base name. Refuses a symlink on the way to it or at it.
    /// With the output directory walked by descriptor, also what is there now.
    fn destination(
        &mut self,
        meta: &rars_rs::ExtractedEntryMeta,
    ) -> rars_rs::Result<(PathBuf, PathBuf, Option<TreeEntry>)> {
        let refuse = |error| refused_output(error, &meta.name);
        let (stored, relative) =
            output_names(meta, self.family, self.encoding, self.flatten).map_err(refuse)?;
        let path = self.out_dir.join(&relative);
        if let Some(tree) = self.tree(false).map_err(refuse)? {
            return match tree.lstat(&relative).map_err(refuse)? {
                TreeEntry::Symlink => Err(refuse(rars_rs::Error::UnsafePath(
                    "unsafe archive path crosses symlink",
                ))),
                entry => Ok((stored, path, Some(entry))),
            };
        }
        rars_rs::filename::checked_output_path(self.out_dir, &relative).map_err(refuse)?;
        if let Some(staging) = &self.staging {
            staging.reject_alias(&path).map_err(refuse)?;
        }
        Ok((stored, path, None))
    }

    /// The time to give a published file, if any.
    fn modified_time(&self, meta: &rars_rs::ExtractedEntryMeta) -> Option<std::time::SystemTime> {
        self.times.as_ref()?;
        meta.modified
            .and_then(|time| std::time::SystemTime::try_from(time).ok())
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
        let (stored, destination, existing) = self.destination(meta)?;
        self.claim(&destination, meta)?;
        if meta.is_directory {
            self.create_directory(&destination, existing.as_ref(), &meta.name)?;
            self.record_published(stored, destination, meta, true);
            return Ok(Box::new(io::sink()));
        }
        let exists = match &existing {
            Some(entry) => *entry != TreeEntry::Missing,
            None => fs::symlink_metadata(&destination).is_ok(),
        };
        if self.overwrite == OverwritePolicy::Never && exists {
            return Err(already_exists(&destination).into());
        }
        if self.in_place {
            return self.open_in_place(stored, destination, meta);
        }
        self.open_staged(stored, destination, meta)
    }

    /// Makes a directory member, and any missing parents.
    fn create_directory(
        &mut self,
        destination: &Path,
        existing: Option<&TreeEntry>,
        name: &[u8],
    ) -> rars_rs::Result<()> {
        let relative = destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory");
        if matches!(existing, Some(TreeEntry::Other(_))) {
            // What `create_dir_all` says of a file in the way.
            return Err(io::Error::from_raw_os_error(libc::EEXIST).into());
        }
        match self.tree(true)? {
            Some(tree) => {
                tree.create_dirs(relative)
                    .map_err(|error| like_create_dir_all(refused_walk(error, name), destination))?;
            }
            None => fs::create_dir_all(destination)?,
        }
        Ok(())
    }

    /// Opens a member at its destination by the overwrite policy, never
    /// following a symlink and never writing through a hard link or
    /// anything but a regular file.
    fn open_in_place(
        &mut self,
        stored: PathBuf,
        destination: PathBuf,
        meta: &rars_rs::ExtractedEntryMeta,
    ) -> rars_rs::Result<Box<dyn Write>> {
        let parent = destination
            .parent()
            .expect("checked output path has a file name")
            .to_path_buf();
        self.tree(true)?;
        let (destination, writer, held): (_, Box<dyn Write>, _) = match &mut self.out_tree {
            Some(tree) => {
                let relative = destination
                    .strip_prefix(self.out_dir)
                    .expect("checked output path is under the output directory");
                let (dir, _) = tree.parent_dir(relative).map_err(|error| {
                    like_create_dir_all(refused_walk(error, &meta.name), &parent)
                })?;
                let name = relative.file_name().expect("output path has a name");
                let (destination, file) = match self.overwrite {
                    OverwritePolicy::Never => {
                        let file = dir.create_file(name, 0o666)?;
                        (destination, file)
                    }
                    OverwritePolicy::Rename => {
                        dir.create_numbered(&destination, 0o666, &mut self.renames)?
                    }
                    OverwritePolicy::Always => {
                        let opened = dir.open_in_place(name, 0o666)?;
                        if opened.len > 0 {
                            opened.file.set_len(0)?;
                        }
                        (destination, opened.file)
                    }
                };
                let (writer, held) = HeldFile::new(file);
                (destination, Box::new(writer), Some(held))
            }
            None => {
                fs::create_dir_all(&parent)?;
                // Creating the parents may have raced a symlink into place.
                let (_, destination, _) = self.destination(meta)?;
                let (destination, file) = rars_rs::output_staging::open_in_place(
                    &destination,
                    self.overwrite,
                    &mut self.renames,
                )?;
                (destination, Box::new(file), None)
            }
        };
        self.pending = Some(PendingOutput {
            staged: None,
            staged_at: None,
            held,
            stored,
            destination,
            meta: meta.clone(),
            link_target: None,
        });
        Ok(writer)
    }

    /// The staging storage, made on first use. Where the output directory is
    /// walked by descriptor, so is the storage, and the walks refuse it.
    fn staging(&mut self) -> rars_rs::Result<&ExtractionStaging> {
        if self.staging.is_none() {
            let staging = ExtractionStaging::new(self.out_dir)?;
            if let Some(tree) = self.tree(false)? {
                if let Some(mut storage) = OutputTree::open(&staging.root)? {
                    tree.forbid(storage.identity());
                    let files = storage.file_dir(Path::new(STAGED_FILES))?;
                    self.staged_files = Some((files, staging.root.join(STAGED_FILES)));
                }
            }
            self.staging = Some(staging);
        }
        Ok(self.staging.as_ref().expect("made above"))
    }

    /// Stages a member's file, to publish once it verifies.
    fn open_staged(
        &mut self,
        stored: PathBuf,
        destination: PathBuf,
        meta: &rars_rs::ExtractedEntryMeta,
    ) -> rars_rs::Result<Box<dyn Write>> {
        self.staging()?;
        let staging = self.staging.as_ref().expect("made above");
        if self.staged_files.is_none() {
            staging
                .reject_alias(&destination)
                .map_err(|error| refused_output(error, &meta.name))?;
        } else if destination.starts_with(&staging.root) {
            // Walked before the storage was there to refuse.
            return Err(refused_output(
                rars_rs::Error::InvalidHeader("archive path conflicts with extraction storage"),
                &meta.name,
            ));
        }
        let index = self.staged.to_string();
        let (staged, staged_at, file) = match &self.staged_files {
            Some((dir, root)) => {
                let name = std::ffi::OsString::from(index);
                let file = dir.create_file(&name, 0o666)?;
                (root.join(&name), Some((dir.clone(), name)), file)
            }
            None => {
                let staged = staging.root.join(index);
                let file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&staged)?;
                (staged, None, file)
            }
        };
        self.staged += 1;
        self.pending = Some(PendingOutput {
            staged: Some(staged),
            staged_at,
            held: None,
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
        // The library reports a failed member before it asks for the next output.
        let failed = self.failed.is_some_and(|failed| {
            let mut failed = lock(failed);
            let gone_past = failed.contains(&pending.meta.name);
            failed.clear();
            gone_past
        });
        if failed {
            if let Some(staged) = &pending.staged {
                let _ = fs::remove_file(staged);
            }
            return Ok(());
        }
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
            // Written in place: by descriptor, its time goes on through its own.
            let later = match (&pending.held, self.modified_time(&pending.meta)) {
                (Some(held), Some(modified)) => !held
                    .get()
                    .is_some_and(|file| file.set_modified(modified).is_ok()),
                _ => true,
            };
            self.record_published(pending.stored, pending.destination, &pending.meta, later);
            return Ok(());
        };
        if let Some((dir, name)) = &pending.staged_at {
            if let Some(published) = self.publish_by_descriptor(&pending, dir, name)? {
                self.record_published(pending.stored, published.0, &pending.meta, published.1);
                return Ok(());
            }
            // The filesystem can't rename it into place: publish it by path.
            self.forget_walks();
        }
        fs::create_dir_all(
            pending
                .destination
                .parent()
                .expect("checked output path has a file name"),
        )?;
        // Creating the parents may have raced a symlink into place.
        let (_, destination, _) = self.destination(&pending.meta)?;
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

    /// Publishes a file staged by descriptor, renaming it from the storage
    /// into the output directory's walked descriptors after giving it its
    /// time. Returns where it landed and whether its time still needs
    /// setting, or `None` when the filesystem can't rename it into place.
    fn publish_by_descriptor(
        &mut self,
        pending: &PendingOutput,
        dir: &FileDir,
        name: &std::ffi::OsStr,
    ) -> rars_rs::Result<Option<(PathBuf, bool)>> {
        let later = match self.modified_time(&pending.meta) {
            Some(modified) => dir.set_metadata(name, Some(modified), None).is_err(),
            None => true,
        };
        let relative = pending
            .destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory");
        let parent = pending
            .destination
            .parent()
            .expect("checked output path has a file name");
        let tree = self
            .out_tree
            .as_mut()
            .expect("files stage by descriptor only beside an output tree");
        let published = dir
            .publish(
                name,
                tree,
                relative,
                &pending.destination,
                self.overwrite,
                &mut self.renames,
            )
            .map_err(|error| {
                like_create_dir_all(refused_walk(error, &pending.meta.name), parent)
            })?;
        Ok(published.map(|published| (published, later)))
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
            staged_at: None,
            held: None,
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
        let (stored, destination, existing) = self.destination(meta)?;
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
            let created = create_link_output(
                self.out_dir,
                &relative,
                &target,
                link,
                self.overwrite,
                &self.created,
                &mut self.renames,
            );
            // Made by path, which can remove a directory the walks hold.
            self.forget_walks();
            let (path, file) = created?;
            self.record_published(stored, path, meta, file);
            return Ok(());
        }
        let exists = match &existing {
            Some(entry) => *entry != TreeEntry::Missing,
            None => fs::symlink_metadata(&destination).is_ok(),
        };
        if self.overwrite == OverwritePolicy::Never && exists {
            return Err(already_exists(&destination).into());
        }
        let root = self.staging()?.root.clone();
        let (staged, file) = create_link_output(
            &root,
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
        // Made by path: walk afresh.
        self.forget_walks();
        // Creating the parents may have raced a symlink into place.
        let (_, destination, _) = self.destination(meta)?;
        if self.overwrite == OverwritePolicy::Always
            && fs::symlink_metadata(&destination).is_ok_and(|metadata| metadata.is_dir())
        {
            fs::remove_dir(&destination)?;
        }
        let published = publish_verified_output(
            &staged,
            &destination,
            self.overwrite,
            source.as_deref(),
            &mut self.renames,
        );
        // Replacing a directory removes it, wherever the walks hold it.
        self.forget_walks();
        self.record_published(stored, published?, meta, file);
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
            times.opened(path.clone(), meta);
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
    failed: Option<&Mutex<Vec<Vec<u8>>>>,
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
        failed,
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
        meta.modification_time(),
        meta.file_attr,
        meta.is_directory,
    )
    .with_attr_source(meta.attr_source());
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
            rars_rs::Error::InVolume { index, .. } => fault.volume_index = Some(*index),
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
    volume_index: Option<usize>,
    /// The outermost member, which is the one the caller asked for.
    member: Option<String>,
}

fn is_missing_volume(error: &rars_rs::Error) -> bool {
    matches!(error, rars_rs::Error::MissingVolume)
}

fn is_volume_out_of_order(error: &rars_rs::Error) -> bool {
    matches!(error, rars_rs::Error::VolumeOutOfOrder)
}

fn is_checksum_mismatch(error: &rars_rs::Error) -> bool {
    matches!(
        error,
        rars_rs::Error::CrcMismatch { .. }
            | rars_rs::Error::Crc32Mismatch { .. }
            | rars_rs::Error::HashMismatch { .. }
    )
}

fn is_salvage_report(error: &rars_rs::Error) -> bool {
    matches!(
        error,
        rars_rs::Error::MemberCutShort { .. } | rars_rs::Error::MemberRanPastDeclaredSize { .. }
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
/// A `partial` set, salvaged, may end early.
fn volumes_to_last<'a>(
    first: &rars_rs::Archive,
    volumes: &'a mut (dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send),
    partial: bool,
) -> impl Iterator<Item = rars_rs::Result<rars_rs::Archive>> + 'a {
    let mut end = volume_end(first);
    let mut order = rars_rs::volume_order::VolumeOrder::after(first);
    let mut index = 0;
    std::iter::from_fn(move || {
        if end == VolumeEnd::Last {
            return None;
        }
        index += 1;
        let volume = match volumes.next() {
            Some(volume) => volume,
            None if end == VolumeEnd::More && !partial => Err(rars_rs::Error::MissingVolume),
            None => return None,
        };
        let volume = volume.and_then(|volume| order.next(&volume).map(|()| volume));
        end = volume.as_ref().map_or(VolumeEnd::Last, volume_end);
        Some(volume.map_err(|error| rars_rs::Error::InVolume {
            index,
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
    partial: bool,
) -> rars_rs::Result<SetListing> {
    let in_volume = |index: usize, error: rars_rs::Error| rars_rs::Error::InVolume {
        index,
        source: Box::new(error),
    };
    let broken = rars_rs::Error::InvalidHeader(
        "volume does not continue the member split from the volume before it",
    );
    let mut infos = listing.infos.clone();
    let mut places = listing.places.clone();
    let mut pending = infos.last().is_some_and(|info| info.is_split_after);
    let mut pulled = 0;
    for volume in volumes_to_last(first, volumes, partial) {
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
                    // Only the last part records the whole member's size and CRC.
                    let last = info_from_member_named(member, String::new());
                    info.file_size = last.file_size;
                    info.crc = last.crc;
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
    let solid = member.is_solid();
    let crc = match member.detail {
        rars_rs::ArchiveMemberDetail::Rar15To40 { crc32, .. } => Some(crc32),
        rars_rs::ArchiveMemberDetail::Rar50Plus { crc32, .. } => crc32,
        _ => None,
    };
    let stored_time = member.meta.stored_modification_time();
    // A malformed extended time record still leaves the main header's time.
    let times = member.times().unwrap_or_else(|_| rars_rs::FileTimes {
        modified: member.meta.modification_time(),
        ..Default::default()
    });
    let nanoseconds =
        |time: Option<rars_rs::Timestamp>| time.map(rars_rs::Timestamp::unix_nanoseconds);
    let attr_source = member.meta.attr_source();
    RarInfo {
        member_index: 0,
        archive_identity: None,
        filename,
        orig_filename_bytes: member.meta.name.into(),
        file_size: member.meta.unpacked_size,
        compress_size: member.meta.packed_size,
        stored_time,
        mtime_ns: nanoseconds(times.modified),
        atime_ns: nanoseconds(times.accessed),
        birthtime_ns: nanoseconds(times.created),
        crc,
        host_os: member.meta.host_os,
        attr_source,
        is_encrypted: member.meta.is_encrypted,
        is_solid: solid,
        is_split_before: member.meta.is_split_before,
        is_split_after: member.meta.is_split_after,
        family: member.meta.family,
        file_attr: member.meta.file_attr,
        is_directory: member.meta.is_directory,
        is_redirection: member.meta.is_redirection,
        volume: 0,
    }
}

/// Why `read` has nothing to return for a member that exists.
fn no_payload(info: &RarInfo) -> PyErr {
    if info.is_directory {
        PyIsADirectoryError::new_err(format!("{} is a directory", info.filename))
    } else if info.is_redirection {
        PyValueError::new_err(format!(
            "{} is a link; readlink() reads its target",
            info.filename
        ))
    } else {
        PyValueError::new_err(format!("{} has no data to read", info.filename))
    }
}

fn family_member(py: Python<'_>, family: rars_rs::ArchiveFamily) -> PyResult<Bound<'_, PyAny>> {
    let value = match family {
        rars_rs::ArchiveFamily::Rar13 => "rar13",
        rars_rs::ArchiveFamily::Rar15To40 => "rar15_40",
        rars_rs::ArchiveFamily::Rar50Plus => "rar50_plus",
        _ => "unknown",
    };
    enum_member(py, &ARCHIVE_FAMILY, "ArchiveFamily", value)
}

/// Exactly an `ArchiveVersion` value, so one version has one spelling.
fn parse_version(value: &str) -> PyResult<rars_rs::ArchiveVersion> {
    rars_rs::ArchiveVersion::from_name(value)
        .filter(|version| version.as_str() == value)
        .ok_or_else(|| {
            PyValueError::new_err(format!(
                "unknown RAR version {value:?}; expected an ArchiveVersion such as \"rar50\""
            ))
        })
}

/// The member's stored relative path, and where it goes relative to the output directory.
fn output_names(
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
    Ok((stored, relative))
}

/// Names the member a walk refused, as the checks by path did. Errors from
/// the filesystem itself pass through as they would from `create_dir_all`.
fn refused_walk(error: rars_rs::Error, name: &[u8]) -> rars_rs::Error {
    match error {
        rars_rs::Error::Io(_) => error,
        error => refused_output(error, name),
    }
}

/// `create_dir_all` reports a file where `directory` goes as `EEXIST`. A walk
/// by descriptor finds it can't open it as a directory, `ENOTDIR`, so it is
/// reported as `create_dir_all` would.
fn like_create_dir_all(error: rars_rs::Error, directory: &Path) -> rars_rs::Error {
    if io_errno(&error) == Some(libc::ENOTDIR)
        && fs::symlink_metadata(directory).is_ok_and(|metadata| !metadata.is_dir())
    {
        return io::Error::from_raw_os_error(libc::EEXIST).into();
    }
    error
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

/// What `overwrite=False` raises, naming the file and the ways past it.
fn already_exists(destination: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "{} already exists; pass overwrite=True to replace it or overwrite=\"rename\" to keep both",
            destination.display()
        ),
    )
}

/// The errno Python picks an `OSError` subclass by, such as `FileExistsError`.
fn io_errno(error: &rars_rs::Error) -> Option<i32> {
    let rars_rs::Error::Io(io_error) = error.root_cause() else {
        return None;
    };
    io_error
        .source()
        .downcast_ref::<io::Error>()
        .and_then(io::Error::raw_os_error)
        .or(match io_error.kind {
            io::ErrorKind::AlreadyExists => Some(libc::EEXIST),
            io::ErrorKind::NotFound => Some(libc::ENOENT),
            io::ErrorKind::PermissionDenied => Some(libc::EACCES),
            _ => None,
        })
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
                "volume_index",
                fault.volume_index,
            )
        });
    }
    if let Some(fault) = set_fault(&error, is_volume_out_of_order) {
        return Python::attach(|py| {
            with_attribute(
                py,
                VolumeOrderError::new_err(message),
                "volume_index",
                fault.volume_index,
            )
        });
    }
    // Comment and recovery-record checksums name no member, so they stay plain BadRarFile.
    if let Some(fault) =
        set_fault(&error, is_checksum_mismatch).filter(|fault| fault.member.is_some())
    {
        return Python::attach(|py| {
            let error = with_attribute(py, ChecksumError::new_err(message), "member", fault.member);
            with_attribute(py, error, "volume_index", fault.volume_index)
        });
    }
    // Only salvage reports these, after the member's bytes were delivered.
    match *error.root_cause() {
        rars_rs::Error::MemberCutShort { packed, present } => {
            let fault = set_fault(&error, is_salvage_report).unwrap_or_default();
            return Python::attach(|py| {
                let error = MemberCutShort::new_err(message);
                let error = with_attribute(py, error, "member", fault.member);
                let error = with_attribute(py, error, "packed", packed);
                with_attribute(py, error, "present", present)
            });
        }
        rars_rs::Error::MemberRanPastDeclaredSize { declared } => {
            let fault = set_fault(&error, is_salvage_report).unwrap_or_default();
            return Python::attach(|py| {
                let error = MemberRanPastDeclaredSize::new_err(message);
                let error = with_attribute(py, error, "member", fault.member);
                with_attribute(py, error, "declared", declared)
            });
        }
        _ => {}
    }
    use rars_rs::ErrorKind;
    match error.kind() {
        ErrorKind::UnsupportedFormat | ErrorKind::UnsupportedFeature => {
            UnsupportedRarFeature::new_err(message)
        }
        ErrorKind::UnsafePath => UnsafeArchivePath::new_err(message),
        ErrorKind::Io | ErrorKind::SourceChanged => match io_errno(&error) {
            Some(errno) => PyOSError::new_err((errno, message)),
            None => PyOSError::new_err(message),
        },
        ErrorKind::InvalidArgument | ErrorKind::DuplicateEntry => PyValueError::new_err(message),
        ErrorKind::EntryNotFound => PyKeyError::new_err(message),
        ErrorKind::ResourceLimit => LimitExceeded::new_err(message),
        ErrorKind::Cancelled => Cancelled::new_err(message),
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
            file.testrar(py, None, Some(&options), None, None, None, None)
                .unwrap();
            let first = PyString::new(py, &file.first.infos[0].filename);
            for _ in 0..2 {
                file.read(py, &first, None, Some(&options), None, None, None, None)
                    .unwrap();
                file.extract(
                    py,
                    &first,
                    Some(out.clone()),
                    None,
                    Overwrite(OverwritePolicy::Always),
                    Some(&options),
                    None,
                    None,
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
                    None,
                    None,
                    true,
                    false,
                    false,
                    None,
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
            file.testrar(py, None, Some(&options), None, None, Some(&later), None)
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
                    None,
                    None,
                    true,
                    false,
                    false,
                    None,
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
                file.testrar(py, None, Some(&options), None, None, None, None)
                    .unwrap();
                file.read(py, &first, None, Some(&options), None, None, None, None)
                    .unwrap();
                file.extract(
                    py,
                    &first,
                    Some(out.clone()),
                    None,
                    Overwrite(OverwritePolicy::Always),
                    Some(&options),
                    None,
                    None,
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
                volume_index: None,
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
        let options = rars_rs::ArchiveReadOptions::default().with_cancellation(&token.inner);
        Python::initialize();
        let source = ArchiveInput::Bytes(b"not an archive".to_vec());
        let error = repair_core(source, options, None, Some(&token)).unwrap_err();
        Python::attach(|py| assert!(error.is_instance_of::<Cancelled>(py)));
    }

    #[test]
    fn reader_workspace_options_reach_the_decoder_and_raise_limit_exceeded() {
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
            assert!(error.is_instance_of::<LimitExceeded>(py));
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
                    closed: AtomicBool::new(false),
                    archive,
                    path: None,
                    password: None,
                    salvaged: None,
                    incomplete: Vec::new(),
                    truncation: None,
                    salvage: false,
                    header_damage: Vec::new(),
                };
                let token = CancellationToken::new();
                let options =
                    ReadOptions::new(None, None, None, None, None, None, None, None, false, None)
                        .unwrap();
                let cancellation = token.clone();
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
                    .read(
                        py,
                        name.as_any(),
                        None,
                        Some(&options),
                        None,
                        Some(&cancellation),
                        None,
                        None,
                    )
                    .unwrap_err();
                py.detach(|| worker.join().unwrap());
                assert!(error.is_instance_of::<Cancelled>(py), "{format}: {error}");
                assert_eq!(
                    file.read(py, name.as_any(), None, None, None, None, None, None)
                        .unwrap(),
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
                            closed: AtomicBool::new(false),
                            salvaged: None,
                            incomplete: Vec::new(),
                            truncation: None,
                            salvage: false,
                            header_damage: Vec::new(),
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
                    index: 1,
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
                        exception.is_instance_of::<LimitExceeded>(py)
                    }
                    rars_rs::ErrorKind::Cancelled => exception.is_instance_of::<Cancelled>(py),
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
                index: 1,
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
                index: 1,
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
            parse_version("rar50").unwrap(),
            rars_rs::ArchiveVersion::Rar50
        );
        assert!(parse_version("rar5").is_err());
        assert!(parse_version("RAR50").is_err());
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
