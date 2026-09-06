use pyo3::exceptions::{
    PyInterruptedError, PyKeyError, PyMemoryError, PyNotImplementedError, PyOSError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyModule};
use pyo3::{create_exception, PyErr};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

create_exception!(rars, Error, pyo3::exceptions::PyException);
create_exception!(rars, BadRarFile, Error);
create_exception!(rars, BadPassword, BadRarFile);
create_exception!(rars, PasswordRequired, BadRarFile);
create_exception!(rars, UnsupportedRarFeature, Error);
create_exception!(rars, UnsafeArchivePath, Error);

#[pyclass(frozen, module = "rars", skip_from_py_object)]
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
}

#[pyclass(frozen, module = "rars", skip_from_py_object)]
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

#[pyclass(frozen, module = "rars", skip_from_py_object)]
struct RepairResult {
    #[pyo3(get)]
    data: Vec<u8>,
    #[pyo3(get)]
    report: RepairReport,
}

#[pymethods]
impl ProgressEvent {
    #[getter]
    fn percentage(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            self.completed as f64 * 100.0 / self.total as f64
        }
    }
}

struct PythonProgress {
    callback: Py<PyAny>,
    state: Mutex<ProgressEvent>,
    error: Mutex<Option<PyErr>>,
    cancelled: AtomicBool,
}

impl PythonProgress {
    fn new(callback: Py<PyAny>) -> Self {
        Self {
            callback,
            state: Mutex::new(ProgressEvent {
                phase: "compression".to_string(),
                completed: 0,
                total: 0,
                pass_number: 1,
                entry_name: None,
                entry_index: None,
                total_entries: None,
            }),
            error: Mutex::new(None),
            cancelled: AtomicBool::new(false),
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
        if self.cancelled.load(Ordering::Relaxed) {
            return;
        }
        let snapshot = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match event {
                rars_rs::WriteProgressEvent::OperationStarted {
                    operation,
                    total_bytes,
                    total_entries,
                    pass,
                } => {
                    state.phase = progress_phase(operation).to_string();
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
                } => {
                    state.entry_name = Some(name.to_vec());
                    state.entry_index = Some(index);
                    state.total_entries = Some(total_entries);
                }
                rars_rs::WriteProgressEvent::EntryFinished { .. } => {}
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
                rars_rs::WriteProgressEvent::OperationFinished {
                    operation,
                    total_bytes,
                    pass,
                    ..
                } => {
                    state.phase = progress_phase(operation).to_string();
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
            self.callback.call1(py, (event,)).map(|_| ())
        });
        if let Err(error) = result {
            self.cancelled.store(true, Ordering::Relaxed);
            *self
                .error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

fn progress_phase(operation: rars_rs::WriteOperation) -> &'static str {
    match operation {
        rars_rs::WriteOperation::Compression => "compression",
        rars_rs::WriteOperation::Recovery => "recovery",
        _ => "writing",
    }
}

#[pyclass(frozen, module = "rars", skip_from_py_object)]
#[derive(Debug, Clone)]
struct RarInfo {
    #[pyo3(get)]
    filename: String,
    #[pyo3(get)]
    orig_filename_bytes: Vec<u8>,
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
}

#[pymethods]
impl RarInfo {
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

#[pyclass(module = "rars", skip_from_py_object)]
struct RarFile {
    archive: rars_rs::Archive,
    password: Option<Vec<u8>>,
    infos: Vec<RarInfo>,
}

#[pymethods]
impl RarFile {
    #[new]
    #[pyo3(signature = (source, mode = "r", password = None))]
    fn new(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        mode: &str,
        password: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        if mode != "r" {
            return Err(PyNotImplementedError::new_err(
                "RarFile currently opens archives for reading; use RarBuilder to create or rewrite archives",
            ));
        }
        let password = py_password(password)?;
        let bytes = py_input_bytes(py, source)?;
        Self::from_bytes(py, bytes, password)
    }

    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    #[pyo3(signature = (data, password = None))]
    fn from_bytes_py(
        py: Python<'_>,
        data: Vec<u8>,
        password: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Self::from_bytes(py, data, py_password(password)?)
    }

    fn namelist(&self) -> Vec<String> {
        self.infos
            .iter()
            .map(|info| info.filename.clone())
            .collect()
    }

    fn infolist(&self) -> Vec<RarInfo> {
        self.infos.clone()
    }

    fn getinfo(&self, name: &Bound<'_, PyAny>) -> PyResult<RarInfo> {
        let target = member_name_bytes(name)?;
        self.infos
            .iter()
            .find(|info| info.orig_filename_bytes == target)
            .cloned()
            .ok_or_else(|| PyKeyError::new_err(String::from_utf8_lossy(&target).into_owned()))
    }

    #[pyo3(signature = (name, pwd = None))]
    fn read(
        &self,
        py: Python<'_>,
        name: &Bound<'_, PyAny>,
        pwd: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<u8>> {
        let target = member_name_bytes(name)?;
        let password = py_password(pwd)?.or_else(|| self.password.clone());
        py.detach(|| self.archive.read_member(&target, password.as_deref()))
            .map_err(map_error)?
            .ok_or_else(|| PyKeyError::new_err(String::from_utf8_lossy(&target).into_owned()))
    }

    #[pyo3(signature = (name, pwd = None))]
    fn open(
        &self,
        py: Python<'_>,
        name: &Bound<'_, PyAny>,
        pwd: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let data = self.read(py, name, pwd)?;
        let io = py.import("io")?;
        let bytes = PyBytes::new(py, &data);
        Ok(io.getattr("BytesIO")?.call1((bytes,))?.unbind())
    }

    #[pyo3(signature = (member, path = None, pwd = None, overwrite = false))]
    fn extract(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        path: Option<PathBuf>,
        pwd: Option<&Bound<'_, PyAny>>,
        overwrite: bool,
    ) -> PyResult<PathBuf> {
        let target = member_name_bytes(member)?;
        let out_dir = path.unwrap_or_else(|| PathBuf::from("."));
        let password = py_password(pwd)?.or_else(|| self.password.clone());
        let written = py
            .detach(|| {
                extract_archive(
                    &self.archive,
                    Some(&target),
                    &out_dir,
                    password.as_deref(),
                    overwrite,
                )
            })
            .map_err(map_error)?;
        written
            .into_iter()
            .next()
            .ok_or_else(|| PyKeyError::new_err(String::from_utf8_lossy(&target).into_owned()))
    }

    #[pyo3(signature = (path = None, members = None, pwd = None, overwrite = false))]
    fn extractall(
        &self,
        py: Python<'_>,
        path: Option<PathBuf>,
        members: Option<&Bound<'_, PyAny>>,
        pwd: Option<&Bound<'_, PyAny>>,
        overwrite: bool,
    ) -> PyResult<Vec<PathBuf>> {
        let out_dir = path.unwrap_or_else(|| PathBuf::from("."));
        let selected = match members {
            Some(members) => Some(member_name_set(members)?),
            None => None,
        };
        let password = py_password(pwd)?.or_else(|| self.password.clone());
        py.detach(|| {
            extract_archive(
                &self.archive,
                selected.as_ref(),
                &out_dir,
                password.as_deref(),
                overwrite,
            )
        })
        .map_err(map_error)
    }

    #[pyo3(signature = (pwd = None))]
    fn testrar(&self, py: Python<'_>, pwd: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        let password = py_password(pwd)?.or_else(|| self.password.clone());
        py.detach(|| self.archive.test(password.as_deref()))
            .map_err(map_error)
    }

    #[getter]
    fn comment(&self, py: Python<'_>) -> PyResult<Option<Vec<u8>>> {
        let password = self.password.clone();
        py.detach(|| self.archive.comment(password.as_deref()))
            .map_err(map_error)
    }

    #[getter]
    fn needs_password(&self) -> bool {
        self.infos.iter().any(|info| info.is_encrypted)
    }

    /// Returns the decoded comment attached to a member, or None if absent.
    #[pyo3(signature = (member, pwd = None))]
    fn getcomment(
        &self,
        py: Python<'_>,
        member: &Bound<'_, PyAny>,
        pwd: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Option<Vec<u8>>> {
        let name = member_name_bytes(member)?;
        let index = self
            .archive
            .members()
            .position(|member| member.meta.name == name)
            .ok_or_else(|| PyKeyError::new_err("member not found"))?;
        let password = py_password(pwd)?.or_else(|| self.password.clone());
        py.detach(|| self.archive.member_comment_at(index, password.as_deref()))
            .map_err(map_error)
    }

    /// Returns the raw RAR5 target of a supported redirection.
    /// This reads archive metadata and never follows the link.
    fn readlink(&self, member: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
        let name = member_name_bytes(member)?;
        let member = self
            .archive
            .members()
            .find(|member| member.meta.name == name)
            .ok_or_else(|| PyKeyError::new_err("member not found"))?;
        member
            .supported_redirection()
            .map(|link| link.target_name.clone())
            .ok_or_else(|| UnsupportedRarFeature::new_err("member is not a supported redirection"))
    }

    /// Metadata/settings the current rewrite implementation cannot preserve.
    /// This is a conservative metadata check, not a payload integrity test.
    fn rewrite_preservation_issues(&self) -> Vec<String> {
        self.archive.rewrite_preservation_issues()
    }

    #[getter]
    fn sfx_offset(&self) -> usize {
        self.archive.sfx_offset()
    }

    #[getter]
    fn family(&self) -> String {
        family_name(self.archive.family()).to_string()
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
        let list = PyList::new(py, self.infos.clone())?;
        Ok(list.call_method0("__iter__")?.unbind())
    }
}

impl RarFile {
    fn from_bytes(py: Python<'_>, bytes: Vec<u8>, password: Option<Vec<u8>>) -> PyResult<Self> {
        let parse_password = password.clone();
        let archive = py
            .detach(|| {
                let options = match parse_password.as_deref() {
                    Some(password) => rars_rs::ArchiveReadOptions::with_password(password),
                    None => rars_rs::ArchiveReadOptions::new(),
                };
                rars_rs::ArchiveReader::read_owned_with_options(bytes, options)
            })
            .map_err(map_error)?;
        let infos = archive.members().map(info_from_member).collect();
        Ok(Self {
            archive,
            password,
            infos,
        })
    }
}

/// The Python face of [`rars_rs::Builder`]. Everything about choosing a writer,
/// mapping members onto entry types and splitting volumes lives in the core
/// crate; what is left here is argument conversion and the exception types
/// Python callers catch.
#[pyclass(module = "rars", skip_from_py_object)]
#[derive(Debug, Clone)]
struct RarBuilder {
    inner: rars_rs::Builder,
    format: rars_rs::ArchiveVersion,
}

fn python_progress(callback: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Arc<PythonProgress>>> {
    callback
        .map(|callback| {
            if !callback.is_callable() {
                return Err(PyValueError::new_err("progress must be callable"));
            }
            Ok(Arc::new(PythonProgress::new(callback.clone().unbind())))
        })
        .transpose()
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
    let refusal = classify_builder_error(&error);
    if refusal == BuilderRefusal::Other {
        return map_error(error);
    }
    let Some((name, _)) = error.entry_context() else {
        return map_error(error);
    };
    let name = String::from_utf8_lossy(name).into_owned();
    match refusal {
        BuilderRefusal::NoSuchEntry => PyKeyError::new_err(name),
        BuilderRefusal::DuplicateName => {
            PyValueError::new_err(format!("duplicate archive entry name: {name}"))
        }
        BuilderRefusal::Symlink => PyValueError::new_err(format!(
            "input '{name}' is a symlink; refusing to follow it"
        )),
        BuilderRefusal::Other => map_error(error),
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
        filters = None
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
        })
    }

    /// Create a RAR5 level-3 conversion builder from an archive.
    ///
    /// This currently copies file contents, names, order, archive and file comments,
    /// and modification times including supported subsecond precision.
    /// Explicit directories and supported Unix symbolic links are retained; other special entries are
    /// rejected before writing. It does not preserve encryption, solid settings
    /// or volume layout. Unix permission bits and DOS file flags are retained;
    /// unknown hosts use the builder's DOS defaults. The password
    /// unlocks the input; output is unencrypted. For an existing RarFile, its
    /// configured password is used.
    /// Set preserve=True to reject unsupported metadata or setting changes
    /// before writing. RarFile.rewrite_preservation_issues() lists those gaps.
    ///
    /// This is not yet a metadata-preserving archive editor. See
    /// python/REWRITING.md for current limitations and the planned contract.
    #[staticmethod]
    #[pyo3(signature = (source, password = None, *, preserve = false))]
    fn from_archive(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
        preserve: bool,
    ) -> PyResult<Self> {
        let archive = match source.extract::<PyRef<'_, RarFile>>() {
            Ok(archive) => RarFile {
                archive: archive.archive.clone(),
                password: archive.password.clone(),
                infos: archive.infos.clone(),
            },
            Err(_) => RarFile::new(py, source, "r", password)?,
        };
        let password = archive.password.clone();
        if preserve {
            let issues = archive.archive.rewrite_preservation_issues();
            if !issues.is_empty() {
                return Err(UnsupportedRarFeature::new_err(format!(
                    "cannot preserve archive: {}",
                    issues.join("; ")
                )));
            }
        }
        let mut names = HashSet::new();
        for member in archive.archive.members() {
            if !names.insert(member.meta.name.clone()) {
                return Err(PyValueError::new_err(format!(
                    "cannot rewrite duplicate member name {:?}: the editing API requires unique names",
                    String::from_utf8_lossy(&member.meta.name)
                )));
            }
        }
        let comments = archive
            .archive
            .member_comments(password.as_deref())
            .map_err(map_error)?;
        let format = rars_rs::ArchiveVersion::Rar50;
        let mut builder = Self {
            inner: rars_rs::Builder::new(format)
                .compression_level(Some(3))
                .comment(archive.comment(py)?),
            format,
        };
        for ((member_index, member), comment) in archive.archive.members().enumerate().zip(comments)
        {
            let link = member.supported_redirection().cloned();
            let retained_link = link.as_ref().map(|_| member.clone());
            let info = member.meta;
            // A builder mode is Unix metadata, not generic archive attributes.
            // Reuse extraction's host rules: e.g. legacy host 1 is DOS, but
            // RAR5 host 1 is Unix. DOS 0x20 must not become Unix mode 0040.
            let attr_source = info.attr_source();
            let unix_type = info.file_attr & 0o170000;
            let unsupported_type = attr_source == rars_rs::AttrSource::Unix
                && !matches!(unix_type, 0 | 0o100000)
                && !(info.is_directory && unix_type == 0o040000);
            let reparse_point =
                attr_source == rars_rs::AttrSource::Dos && info.file_attr & 0x400 != 0;
            if link.is_none()
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
            let mode = (attr_source == rars_rs::AttrSource::Unix)
                .then_some((info.file_attr & 0o7777) as u32);
            // Reuse CLI extraction's local-zone policy for legacy DOS times,
            // including the extended odd second, before writing RAR5 Unix time.
            let modified = info
                .modification_time()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
            let mtime = modified
                .map(|duration| u32::try_from(duration.as_secs()))
                .transpose()
                .map_err(|_| {
                    PyValueError::new_err("modification time exceeds the RAR5 timestamp range")
                })?;
            if let Some(member) = retained_link {
                builder
                    .inner
                    .add_archive_redirection(&member)
                    .map_err(map_builder_error)?;
            } else if info.is_directory {
                builder
                    .inner
                    .add_directory(info.name.clone(), mtime, mode)
                    .map_err(map_builder_error)?;
            } else {
                let member_archive = archive.archive.clone();
                let member_password = password.clone();
                let source = rars_rs::EntrySource::from_opener(info.unpacked_size, move || {
                    let data = member_archive
                        // Source identity stays in original archive order, including
                        // directories, regardless of later removes/adds/renames.
                        .read_member_at(member_index, member_password.as_deref())?
                        .ok_or(rars_rs::Error::InvalidHeader(
                            "archive member disappeared while rewriting",
                        ))?;
                    Ok(Box::new(Cursor::new(data)))
                });
                builder
                    .inner
                    .add_source(info.name.clone(), source, mtime, mode)
                    .map_err(map_builder_error)?;
            }
            builder
                .inner
                .set_file_comment(&info.name, comment)
                .map_err(map_builder_error)?;
            if let Some(time) = modified.filter(|time| time.subsec_nanos() != 0) {
                builder
                    .inner
                    .set_mtime_nanoseconds(&info.name, time.subsec_nanos())
                    .map_err(map_builder_error)?;
            }
            if attr_source == rars_rs::AttrSource::Dos {
                builder
                    .inner
                    .set_dos_attributes(&info.name, info.file_attr)
                    .map_err(map_builder_error)?;
            }
        }
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
            Some(name) => member_name_bytes(name)?,
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
            .add_directory(member_name_bytes(arcname)?, mtime, mode)
            .map_err(map_builder_error)
    }

    #[pyo3(signature = (data, arcname, mtime = None, mode = None))]
    fn add_bytes(
        &mut self,
        data: Vec<u8>,
        arcname: &Bound<'_, PyAny>,
        mtime: Option<u32>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.inner
            .add_bytes(member_name_bytes(arcname)?, data, mtime, mode)
            .map_err(map_builder_error)
    }

    fn remove(&mut self, name: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner
            .remove(&member_name_bytes(name)?)
            .map_err(map_builder_error)
    }

    fn rename(&mut self, old: &Bound<'_, PyAny>, new: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner
            .rename(&member_name_bytes(old)?, member_name_bytes(new)?)
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
                member_name_bytes(arcname)?,
                member_name_bytes(target)?,
                target_is_directory,
                mtime,
                mode,
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
        self.inner
            .set_file_comment(&member_name_bytes(member)?, py_optional_bytes(comment)?)
            .map_err(map_builder_error)
    }

    #[pyo3(signature = (*, progress = None))]
    fn to_bytes(&self, py: Python<'_>, progress: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<u8>> {
        self.detached(py, progress, |builder, progress| {
            builder.to_bytes_with_progress(progress)
        })
    }

    #[pyo3(signature = (path, *, progress = None))]
    fn write(
        &self,
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        progress: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let path = py_path_buf(py, path)?;
        self.detached(py, progress, move |builder, progress| {
            builder.write_to_path(&path, progress)
        })
    }

    #[pyo3(signature = (first_path, *, progress = None))]
    fn write_volumes(
        &self,
        py: Python<'_>,
        first_path: &Bound<'_, PyAny>,
        progress: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<PathBuf>> {
        let first_path = py_path_buf(py, first_path)?;
        let parts = self.detached(py, progress, |builder, progress| {
            builder.build_volumes(progress)
        })?;
        let mut paths = Vec::with_capacity(parts.len());
        for (index, part) in parts.iter().enumerate() {
            let path = if matches!(
                self.format,
                rars_rs::ArchiveVersion::Rar50 | rars_rs::ArchiveVersion::Rar70
            ) {
                rar50_volume_part_path(&first_path, index, parts.len())?
            } else {
                legacy_volume_part_path(&first_path, index)?
            };
            fs::write(&path, part).map_err(map_io_error)?;
            paths.push(path);
        }
        Ok(paths)
    }
}

impl RarBuilder {
    /// Run a core-builder call with the GIL released, wiring a Python callback
    /// to it as a progress sink. A callback that raises cancels the write, and
    /// its exception is re-raised here rather than the cancellation the core
    /// crate reports.
    fn detached<T, F>(
        &self,
        py: Python<'_>,
        callback: Option<&Bound<'_, PyAny>>,
        run: F,
    ) -> PyResult<T>
    where
        T: Send,
        F: FnOnce(&rars_rs::Builder, Option<&dyn rars_rs::WriteProgress>) -> rars_rs::Result<T>
            + Send,
    {
        let progress = python_progress(callback)?;
        let builder = self.inner.clone();
        let worker = progress.clone();
        let result = py.detach(move || {
            run(
                &builder,
                worker
                    .as_deref()
                    .map(|progress| progress as &dyn rars_rs::WriteProgress),
            )
        });
        if let Some(error) = progress.as_ref().and_then(|progress| progress.take_error()) {
            return Err(error);
        }
        result.map_err(map_error)
    }
}

#[pyfunction]
#[pyo3(signature = (source, password = None))]
fn repair(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
) -> PyResult<Vec<u8>> {
    let password = py_password(password)?;
    let bytes = py_input_bytes(py, source)?;
    py.detach(|| repair_core(&bytes, password.as_deref()).map(|result| result.data))
        .map_err(map_error)
}

/// Repairs from the archive's own recovery record, falling back to a raw
/// inline-recovery pass when the headers are too damaged to parse.
fn repair_core(
    bytes: &[u8],
    password: Option<&[u8]>,
) -> rars_rs::Result<rars_rs::RecoveryRepairResult> {
    let options = || match password {
        Some(password) => rars_rs::ArchiveReadOptions::with_password(password),
        None => rars_rs::ArchiveReadOptions::new(),
    };
    match rars_rs::ArchiveReader::read_with_options(bytes, options()) {
        Ok(archive) => archive.repair_recovery_with_report(password),
        Err(_) => rars_rs::rar50::repair_inline_recovery_bytes_with_options(bytes, options()),
    }
}

#[pyfunction]
#[pyo3(signature = (source, password = None))]
fn repair_detailed(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
) -> PyResult<RepairResult> {
    let password = py_password(password)?;
    let bytes = py_input_bytes(py, source)?;
    py.detach(|| {
        let result = repair_core(&bytes, password.as_deref())?;
        Ok(RepairResult {
            data: result.data,
            report: result.report.into(),
        })
    })
    .map_err(map_error)
}

#[pyfunction]
#[pyo3(signature = (input, output, password = None))]
fn repair_to_path(
    py: Python<'_>,
    input: &Bound<'_, PyAny>,
    output: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
) -> PyResult<()> {
    let output = py_path_buf(py, output)?;
    let data = repair(py, input, password)?;
    py.detach(|| fs::write(output, data)).map_err(map_io_error)
}

#[pyfunction]
#[pyo3(signature = (paths, path = None, password = None, overwrite = false))]
fn extract_volumes(
    py: Python<'_>,
    paths: &Bound<'_, PyAny>,
    path: Option<PathBuf>,
    password: Option<&Bound<'_, PyAny>>,
    overwrite: bool,
) -> PyResult<Vec<PathBuf>> {
    let archive_paths = py_paths(paths)?;
    let out_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let password = py_password(password)?;
    py.detach(|| {
        let archives = read_archives_from_paths(&archive_paths, password.as_deref())?;
        extract_volumes_archive(&archives, &out_dir, password.as_deref(), overwrite)
    })
    .map_err(map_error)
}

#[pyfunction]
#[pyo3(signature = (paths, password = None))]
fn test_volumes(
    py: Python<'_>,
    paths: &Bound<'_, PyAny>,
    password: Option<&Bound<'_, PyAny>>,
) -> PyResult<()> {
    let archive_paths = py_paths(paths)?;
    let password = py_password(password)?;
    py.detach(|| {
        let archives = read_archives_from_paths(&archive_paths, password.as_deref())?;
        rars_rs::extract_volumes_to(&archives, password.as_deref(), |_| {
            Ok(Box::new(io::sink()) as Box<dyn Write>)
        })
    })
    .map_err(map_error)
}

#[pymodule]
fn rars(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RarFile>()?;
    m.add_class::<RarInfo>()?;
    m.add_class::<RarBuilder>()?;
    m.add_class::<ProgressEvent>()?;
    m.add_class::<RepairReport>()?;
    m.add_class::<RepairResult>()?;
    m.add_function(wrap_pyfunction!(repair, m)?)?;
    m.add_function(wrap_pyfunction!(repair_detailed, m)?)?;
    m.add_function(wrap_pyfunction!(repair_to_path, m)?)?;
    m.add_function(wrap_pyfunction!(extract_volumes, m)?)?;
    m.add_function(wrap_pyfunction!(test_volumes, m)?)?;
    m.add("Error", py.get_type::<Error>())?;
    m.add("BadRarFile", py.get_type::<BadRarFile>())?;
    m.add("BadPassword", py.get_type::<BadPassword>())?;
    m.add("PasswordRequired", py.get_type::<PasswordRequired>())?;
    m.add(
        "UnsupportedRarFeature",
        py.get_type::<UnsupportedRarFeature>(),
    )?;
    m.add("UnsafeArchivePath", py.get_type::<UnsafeArchivePath>())?;
    for version in [
        "rar13", "rar14", "rar15", "rar20", "rar29", "rar30", "rar40", "rar50", "rar70",
    ] {
        m.add(version.to_ascii_uppercase(), version)?;
    }
    Ok(())
}

fn py_input_bytes(py: Python<'_>, source: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = source.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    let path = py_path_buf(py, source)?;
    py.detach(|| fs::read(path)).map_err(map_io_error)
}

fn py_path_buf(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<PathBuf> {
    let os = py.import("os")?;
    let path = os.call_method1("fspath", (value,))?;
    path.extract::<PathBuf>()
}

fn py_paths(value: &Bound<'_, PyAny>) -> PyResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    for item in value.try_iter()? {
        out.push(item?.extract::<PathBuf>()?);
    }
    if out.is_empty() {
        return Err(PyValueError::new_err("volume path list is empty"));
    }
    Ok(out)
}

fn py_password(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Vec<u8>>> {
    match value {
        None => Ok(None),
        Some(value) if value.is_none() => Ok(None),
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
        Some(value) if value.is_none() => Ok(None),
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
        return Ok(info.orig_filename_bytes.clone());
    }
    if let Ok(bytes) = value.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    Ok(value.extract::<String>()?.into_bytes())
}

fn member_name_set(value: &Bound<'_, PyAny>) -> PyResult<HashSet<Vec<u8>>> {
    let mut out = HashSet::new();
    for item in value.try_iter()? {
        out.insert(member_name_bytes(&item?)?);
    }
    Ok(out)
}

trait Selection {
    fn contains_member(&self, name: &[u8]) -> bool;
}

impl Selection for Vec<u8> {
    fn contains_member(&self, name: &[u8]) -> bool {
        self.as_slice() == name
    }
}

impl Selection for HashSet<Vec<u8>> {
    fn contains_member(&self, name: &[u8]) -> bool {
        self.contains(name)
    }
}

fn extract_archive<S: Selection>(
    archive: &rars_rs::Archive,
    selected: Option<&S>,
    out_dir: &Path,
    password: Option<&[u8]>,
    overwrite: bool,
) -> rars_rs::Result<Vec<PathBuf>> {
    let written = Arc::new(Mutex::new(Vec::new()));
    extract_to_best(archive, password, {
        let written = Arc::clone(&written);
        move |meta| {
            if selected.is_some_and(|set| !set.contains_member(&meta.name)) {
                return Ok(Box::new(io::sink()) as Box<dyn Write>);
            }
            let path = checked_output_path(out_dir, meta, archive.family())?;
            if meta.is_directory {
                fs::create_dir_all(&path)?;
                written.lock().expect("written lock poisoned").push(path);
                return Ok(Box::new(io::sink()) as Box<dyn Write>);
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut options = fs::OpenOptions::new();
            options.write(true);
            if overwrite {
                options.create(true).truncate(true);
            } else {
                options.create_new(true);
            }
            set_no_follow(&mut options);
            let file = options.open(&path)?;
            written.lock().expect("written lock poisoned").push(path);
            Ok(Box::new(file) as Box<dyn Write>)
        }
    })?;
    let out = written.lock().expect("written lock poisoned").clone();
    Ok(out)
}

fn extract_volumes_archive(
    archives: &[rars_rs::Archive],
    out_dir: &Path,
    password: Option<&[u8]>,
    overwrite: bool,
) -> rars_rs::Result<Vec<PathBuf>> {
    let written = Arc::new(Mutex::new(Vec::new()));
    rars_rs::extract_volumes_to(archives, password, {
        let written = Arc::clone(&written);
        move |meta| {
            let path = checked_output_path(out_dir, meta, archives[0].family())?;
            if meta.is_directory {
                fs::create_dir_all(&path)?;
                written.lock().expect("written lock poisoned").push(path);
                return Ok(Box::new(io::sink()) as Box<dyn Write>);
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut options = fs::OpenOptions::new();
            options.write(true);
            if overwrite {
                options.create(true).truncate(true);
            } else {
                options.create_new(true);
            }
            set_no_follow(&mut options);
            let file = options.open(&path)?;
            written.lock().expect("written lock poisoned").push(path);
            Ok(Box::new(file) as Box<dyn Write>)
        }
    })?;
    let out = written.lock().expect("written lock poisoned").clone();
    Ok(out)
}

fn read_archives_from_paths(
    paths: &[PathBuf],
    password: Option<&[u8]>,
) -> rars_rs::Result<Vec<rars_rs::Archive>> {
    paths
        .iter()
        .map(|path| {
            let options = match password {
                Some(password) => rars_rs::ArchiveReadOptions::with_password(password),
                None => rars_rs::ArchiveReadOptions::new(),
            };
            rars_rs::ArchiveReader::read_path_with_options(path, options)
        })
        .collect()
}

fn extract_to_best<F>(
    archive: &rars_rs::Archive,
    password: Option<&[u8]>,
    open: F,
) -> rars_rs::Result<()>
where
    F: FnMut(&rars_rs::ExtractedEntryMeta) -> rars_rs::Result<Box<dyn Write>>,
{
    archive.extract_to_parallel_buffered(password, open)
}

fn info_from_member(member: rars_rs::ArchiveMember) -> RarInfo {
    let mut detail = HashMap::new();
    let mut crc = None;
    let mut solid = false;
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
            solid: member_solid,
            salt,
            has_file_comment,
            ..
        } => {
            crc = Some(crc32);
            solid = member_solid;
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
    let filename = String::from_utf8_lossy(&member.meta.name).into_owned();
    RarInfo {
        filename,
        orig_filename_bytes: member.meta.name,
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

fn checked_output_path(
    out_dir: &Path,
    meta: &rars_rs::ExtractedEntryMeta,
    family: rars_rs::ArchiveFamily,
) -> rars_rs::Result<PathBuf> {
    // Retain the binding's conservative name preflight (including legacy
    // backslash traversal) before applying host-aware destination conversion.
    rars_rs::validate_entry_name(meta.name.clone())?;
    let rar50 = family == rars_rs::ArchiveFamily::Rar50Plus;
    let name = if rar50 && cfg!(unix) && meta.attr_source == rars_rs::AttrSource::Unix {
        rars_rs::filename::decode_rar50(&meta.name).into_owned()
    } else if rar50 {
        meta.name
            .iter()
            .map(|&b| if b == b'\\' { b'_' } else { b })
            .collect()
    } else {
        meta.name.clone()
    };
    let rel = output_relative_path(&name, !rar50)?;
    let mut out_path = out_dir.to_path_buf();
    for component in rel.components() {
        let Component::Normal(part) = component else {
            return Err(rars_rs::Error::UnsafePath("unsafe archive path"));
        };
        out_path.push(part);
        if fs::symlink_metadata(&out_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(rars_rs::Error::UnsafePath(
                "unsafe archive path crosses symlink",
            ));
        }
    }
    Ok(out_path)
}

fn output_relative_path(name: &[u8], backslash_separator: bool) -> rars_rs::Result<PathBuf> {
    if name.contains(&0) {
        return Err(rars_rs::Error::UnsafePath(
            "unsafe archive path contains NUL byte",
        ));
    }
    let bytes: Vec<_> = name
        .iter()
        .map(|&b| {
            if backslash_separator && b == b'\\' {
                b'/'
            } else {
                b
            }
        })
        .collect();
    let text = rars_rs::filename::native_string(&bytes)?;
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(rars_rs::Error::UnsafePath("unsafe archive path"));
    }
    let path = Path::new(&text);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(rars_rs::Error::UnsafePath("unsafe archive path")),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(rars_rs::Error::InvalidHeader("empty archive path"));
    }
    Ok(out)
}

fn archive_base_name(path: &Path) -> PyResult<Vec<u8>> {
    let file_name = path
        .file_name()
        .ok_or_else(|| PyValueError::new_err("input path has no file name"))?;
    rars_rs::filename::native_bytes(file_name)
        .map(<[u8]>::to_vec)
        .map_err(map_error)
}

#[cfg(unix)]
fn set_no_follow(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_no_follow(_options: &mut fs::OpenOptions) {}

fn legacy_volume_part_path(first_path: &Path, index: usize) -> PyResult<PathBuf> {
    if index == 0 {
        return Ok(first_path.to_path_buf());
    }
    if index > 100 {
        return Err(PyValueError::new_err(
            "legacy RAR volume names only support .r00 through .r99",
        ));
    }
    Ok(first_path.with_extension(format!("r{:02}", index - 1)))
}

fn rar50_volume_part_path(
    first_path: &Path,
    index: usize,
    total_parts: usize,
) -> PyResult<PathBuf> {
    let parent = first_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = first_path
        .file_name()
        .ok_or_else(|| PyValueError::new_err("RAR 5 volume path needs a file name"))?
        .to_string_lossy();
    let stem = rar50_volume_stem(&file_name);
    let width = total_parts.to_string().len().max(2);
    Ok(parent.join(format!(
        "{stem}.part{:0width$}.rar",
        index + 1,
        width = width
    )))
}

fn rar50_volume_stem(file_name: &str) -> &str {
    let without_rar = file_name
        .strip_suffix(".rar")
        .or_else(|| file_name.strip_suffix(".RAR"))
        .unwrap_or(file_name);
    if let Some((base, digits)) = without_rar.rsplit_once(".part") {
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return base;
        }
    }
    without_rar
}

fn map_io_error(error: io::Error) -> PyErr {
    PyOSError::new_err(error.to_string())
}

fn map_error(error: rars_rs::Error) -> PyErr {
    let message = error.to_string();
    if error_is_need_password(&error) {
        return PasswordRequired::new_err(message);
    }
    if error_is_bad_password(&error) {
        return BadPassword::new_err(message);
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
