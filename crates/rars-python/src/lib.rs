use pyo3::exceptions::{PyKeyError, PyNotImplementedError, PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyModule};
use pyo3::{create_exception, PyErr};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

create_exception!(rars, Error, pyo3::exceptions::PyException);
create_exception!(rars, BadRarFile, Error);
create_exception!(rars, BadPassword, BadRarFile);
create_exception!(rars, PasswordRequired, BadRarFile);
create_exception!(rars, UnsupportedRarFeature, Error);
create_exception!(rars, UnsafeArchivePath, Error);

const DOS_ARCHIVE_ATTR: u8 = 0x20;
const DEFAULT_HOST_OS_UNIX: u64 = 3;

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
        py.detach(|| read_member(&self.archive, &target, password.as_deref()))
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
        py.detach(|| test_archive(&self.archive, password.as_deref()))
            .map_err(map_error)
    }

    #[getter]
    fn comment(&self, py: Python<'_>) -> PyResult<Option<Vec<u8>>> {
        let password = self.password.clone();
        py.detach(|| archive_comment(&self.archive, password.as_deref()))
            .map_err(map_error)
    }

    #[getter]
    fn needs_password(&self) -> bool {
        self.infos.iter().any(|info| info.is_encrypted)
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

#[pyclass(module = "rars", skip_from_py_object)]
#[derive(Debug, Clone)]
struct RarBuilder {
    format: rars_rs::ArchiveVersion,
    compression: Option<u8>,
    store: bool,
    solid: bool,
    password: Option<Vec<u8>>,
    encrypt_headers: bool,
    comment: Option<Vec<u8>>,
    recovery_percent: Option<u64>,
    volume_size: Option<usize>,
    entries: Vec<BuilderEntry>,
}

#[derive(Debug, Clone)]
struct BuilderEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    mtime: Option<u32>,
    mode: Option<u32>,
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
        Ok(Self {
            format: parse_version(format)?,
            compression: Some(compression),
            store,
            solid,
            password: py_password(password)?,
            encrypt_headers,
            comment: py_optional_bytes(comment)?,
            recovery_percent,
            volume_size,
            entries: Vec::new(),
        })
    }

    #[staticmethod]
    #[pyo3(signature = (source, password = None))]
    fn from_archive(
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        password: Option<&Bound<'_, PyAny>>,
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
        let mut builder = Self {
            format: rars_rs::ArchiveVersion::Rar50,
            compression: Some(3),
            store: false,
            solid: false,
            password: None,
            encrypt_headers: false,
            comment: archive.comment(py)?,
            recovery_percent: None,
            volume_size: None,
            entries: Vec::new(),
        };
        for info in &archive.infos {
            if info.is_directory {
                continue;
            }
            if let Some(data) = read_member(
                &archive.archive,
                &info.orig_filename_bytes,
                password.as_deref(),
            )
            .map_err(map_error)?
            {
                builder.entries.push(BuilderEntry {
                    name: info.orig_filename_bytes.clone(),
                    data,
                    mtime: None,
                    mode: Some((info.file_attr & 0o777) as u32),
                });
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
            Some(name) => safe_input_name(member_name_bytes(name)?)?,
            None => archive_base_name(&path)?,
        };
        collect_builder_input(&path, &base, &mut self.entries)?;
        reject_duplicate_names(&self.entries)?;
        Ok(())
    }

    #[pyo3(signature = (data, arcname, mtime = None, mode = None))]
    fn add_bytes(
        &mut self,
        data: Vec<u8>,
        arcname: &Bound<'_, PyAny>,
        mtime: Option<u32>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        self.entries.push(BuilderEntry {
            name: safe_input_name(member_name_bytes(arcname)?)?,
            data,
            mtime,
            mode,
        });
        reject_duplicate_names(&self.entries)?;
        Ok(())
    }

    fn remove(&mut self, name: &Bound<'_, PyAny>) -> PyResult<()> {
        let name = member_name_bytes(name)?;
        let old_len = self.entries.len();
        self.entries.retain(|entry| entry.name != name);
        if self.entries.len() == old_len {
            return Err(PyKeyError::new_err(
                String::from_utf8_lossy(&name).into_owned(),
            ));
        }
        Ok(())
    }

    fn rename(&mut self, old: &Bound<'_, PyAny>, new: &Bound<'_, PyAny>) -> PyResult<()> {
        let old = member_name_bytes(old)?;
        let new = safe_input_name(member_name_bytes(new)?)?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.name == old)
            .ok_or_else(|| PyKeyError::new_err(String::from_utf8_lossy(&old).into_owned()))?;
        entry.name = new;
        reject_duplicate_names(&self.entries)?;
        Ok(())
    }

    fn to_bytes(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        let this = self.clone();
        py.detach(move || this.build_single_archive())
            .map_err(map_error)
    }

    fn write(&self, py: Python<'_>, path: &Bound<'_, PyAny>) -> PyResult<()> {
        let path = py_path_buf(py, path)?;
        let data = self.to_bytes(py)?;
        py.detach(|| fs::write(&path, data)).map_err(map_io_error)
    }

    fn write_volumes(
        &self,
        py: Python<'_>,
        first_path: &Bound<'_, PyAny>,
    ) -> PyResult<Vec<PathBuf>> {
        let first_path = py_path_buf(py, first_path)?;
        let this = self.clone();
        let parts = py.detach(move || this.build_volumes()).map_err(map_error)?;
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
    fn features(&self) -> rars_rs::FeatureSet {
        let mut features = rars_rs::FeatureSet::store_only();
        features.solid = self.solid;
        features.file_encryption = self.password.is_some();
        features.header_encryption = self.encrypt_headers;
        features.archive_comment = self.comment.is_some();
        features.recovery_record = self.recovery_percent.is_some();
        features
    }

    fn build_single_archive(&self) -> rars_rs::Result<Vec<u8>> {
        if self.entries.is_empty() {
            return Err(rars_rs::Error::InvalidHeader(
                "archive builder has no entries",
            ));
        }
        if self.volume_size.is_some() {
            return Err(rars_rs::Error::InvalidHeader(
                "use write_volumes for multivolume archives",
            ));
        }
        match self.format.family() {
            rars_rs::ArchiveFamily::Rar50Plus => self.build_rar50_single(),
            rars_rs::ArchiveFamily::Rar15To40 => self.build_rar15_single(),
            rars_rs::ArchiveFamily::Rar13 => self.build_rar13_single(),
            _ => Err(rars_rs::Error::UnsupportedSignature),
        }
    }

    fn build_volumes(&self) -> rars_rs::Result<Vec<Vec<u8>>> {
        let volume_size = self
            .volume_size
            .ok_or(rars_rs::Error::InvalidHeader("volume_size is required"))?;
        if self.entries.is_empty() {
            return Err(rars_rs::Error::InvalidHeader(
                "archive builder has no entries",
            ));
        }
        match self.format.family() {
            rars_rs::ArchiveFamily::Rar50Plus => self.build_rar50_volumes(volume_size),
            rars_rs::ArchiveFamily::Rar15To40 => self.build_rar15_volumes(volume_size),
            rars_rs::ArchiveFamily::Rar13 => self.build_rar13_volumes(volume_size),
            _ => Err(rars_rs::Error::UnsupportedSignature),
        }
    }

    fn build_rar50_single(&self) -> rars_rs::Result<Vec<u8>> {
        let mut options = rars_rs::rar50::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        if let Some(password) = self.password.as_deref() {
            if self.store {
                let entries: Vec<_> = self
                    .entries
                    .iter()
                    .map(|entry| rars_rs::rar50::EncryptedStoredEntry {
                        name: &entry.name,
                        data: &entry.data,
                        mtime: entry.mtime,
                        attributes: rar50_attr(entry),
                        host_os: DEFAULT_HOST_OS_UNIX,
                        password,
                    })
                    .collect();
                rars_rs::rar50::Rar50Writer::new(options)
                    .encrypted_stored_entries(&entries)
                    .encrypted_archive_comment(self.comment.as_deref().map(|data| {
                        rars_rs::rar50::EncryptedArchiveCommentEntry { data, password }
                    }))
                    .recovery_percent(self.recovery_percent)
                    .recovery_password(self.recovery_percent.map(|_| password))
                    .finish()
            } else {
                let entries: Vec<_> = self
                    .entries
                    .iter()
                    .map(|entry| rars_rs::rar50::EncryptedCompressedEntry {
                        name: &entry.name,
                        data: &entry.data,
                        mtime: entry.mtime,
                        attributes: rar50_attr(entry),
                        host_os: DEFAULT_HOST_OS_UNIX,
                        password,
                    })
                    .collect();
                rars_rs::rar50::Rar50Writer::new(options)
                    .encrypted_compressed_entries(&entries)
                    .encrypted_archive_comment(self.comment.as_deref().map(|data| {
                        rars_rs::rar50::EncryptedArchiveCommentEntry { data, password }
                    }))
                    .recovery_percent(self.recovery_percent)
                    .finish()
            }
        } else if self.store {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rars_rs::rar50::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    mtime: entry.mtime,
                    attributes: rar50_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX,
                })
                .collect();
            rars_rs::rar50::Rar50Writer::new(options)
                .stored_entries(&entries)
                .archive_comment(self.comment.as_deref())
                .recovery_percent(self.recovery_percent)
                .finish()
        } else {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rars_rs::rar50::CompressedEntry {
                    name: &entry.name,
                    data: &entry.data,
                    mtime: entry.mtime,
                    attributes: rar50_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX,
                })
                .collect();
            rars_rs::rar50::Rar50Writer::new(options)
                .compressed_entries(&entries)
                .archive_comment(self.comment.as_deref())
                .recovery_percent(self.recovery_percent)
                .finish()
        }
    }

    fn build_rar15_single(&self) -> rars_rs::Result<Vec<u8>> {
        let mut options = rars_rs::rar15_40::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        if self.store {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rars_rs::rar15_40::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: rar15_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX as u8,
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rars_rs::rar15_40::write_stored_archive_with_comment(
                &entries,
                options,
                self.comment.as_deref(),
            )
        } else {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rars_rs::rar15_40::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: rar15_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX as u8,
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rars_rs::rar15_40::write_compressed_archive_with_comment(
                &entries,
                options,
                self.comment.as_deref(),
            )
        }
    }

    fn build_rar13_single(&self) -> rars_rs::Result<Vec<u8>> {
        let mut options = rars_rs::rar13::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        if self.store {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rars_rs::rar13::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: DOS_ARCHIVE_ATTR,
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rars_rs::rar13::write_stored_archive_with_comment(
                &entries,
                options,
                self.comment.as_deref(),
            )
        } else {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rars_rs::rar13::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: DOS_ARCHIVE_ATTR,
                    password: self.password.as_deref(),
                    file_comment: None,
                })
                .collect();
            rars_rs::rar13::write_compressed_archive_with_comment(
                &entries,
                options,
                self.comment.as_deref(),
            )
        }
    }

    fn build_rar50_volumes(&self, volume_size: usize) -> rars_rs::Result<Vec<Vec<u8>>> {
        if self.comment.is_some() {
            return Err(rars_rs::Error::InvalidHeader(
                "RAR 5 volume comments are not supported",
            ));
        }
        let mut options = rars_rs::rar50::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        if let Some(password) = self.password.as_deref() {
            if self.store {
                if self.entries.len() != 1 {
                    return Err(rars_rs::Error::InvalidHeader(
                        "stored RAR 5 volumes support one input",
                    ));
                }
                let entry = &self.entries[0];
                rars_rs::rar50::Rar50VolumeWriter::new(options)
                    .encrypted_stored_entry(rars_rs::rar50::EncryptedStoredEntry {
                        name: &entry.name,
                        data: &entry.data,
                        mtime: entry.mtime,
                        attributes: rar50_attr(entry),
                        host_os: DEFAULT_HOST_OS_UNIX,
                        password,
                    })
                    .max_payload_per_volume(volume_size)
                    .recovery_percent(self.recovery_percent)
                    .finish()
            } else {
                let entries: Vec<_> = self
                    .entries
                    .iter()
                    .map(|entry| rars_rs::rar50::EncryptedCompressedEntry {
                        name: &entry.name,
                        data: &entry.data,
                        mtime: entry.mtime,
                        attributes: rar50_attr(entry),
                        host_os: DEFAULT_HOST_OS_UNIX,
                        password,
                    })
                    .collect();
                rars_rs::rar50::Rar50VolumeWriter::new(options)
                    .encrypted_compressed_entries(&entries)
                    .max_payload_per_volume(volume_size)
                    .recovery_percent(self.recovery_percent)
                    .finish()
            }
        } else if self.store {
            if self.entries.len() != 1 {
                return Err(rars_rs::Error::InvalidHeader(
                    "stored RAR 5 volumes support one input",
                ));
            }
            let entry = &self.entries[0];
            rars_rs::rar50::Rar50VolumeWriter::new(options)
                .stored_entry(rars_rs::rar50::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    mtime: entry.mtime,
                    attributes: rar50_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX,
                })
                .max_payload_per_volume(volume_size)
                .recovery_percent(self.recovery_percent)
                .finish()
        } else {
            let entries: Vec<_> = self
                .entries
                .iter()
                .map(|entry| rars_rs::rar50::CompressedEntry {
                    name: &entry.name,
                    data: &entry.data,
                    mtime: entry.mtime,
                    attributes: rar50_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX,
                })
                .collect();
            rars_rs::rar50::Rar50VolumeWriter::new(options)
                .compressed_entries(&entries)
                .max_payload_per_volume(volume_size)
                .recovery_percent(self.recovery_percent)
                .finish()
        }
    }

    fn build_rar15_volumes(&self, volume_size: usize) -> rars_rs::Result<Vec<Vec<u8>>> {
        if self.entries.len() != 1 {
            return Err(rars_rs::Error::InvalidHeader(
                "legacy volumes support one input",
            ));
        }
        let entry = &self.entries[0];
        let mut options = rars_rs::rar15_40::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        if self.store {
            rars_rs::rar15_40::write_stored_volumes(
                rars_rs::rar15_40::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: rar15_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX as u8,
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
            )
        } else {
            rars_rs::rar15_40::write_compressed_volumes(
                rars_rs::rar15_40::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: rar15_attr(entry),
                    host_os: DEFAULT_HOST_OS_UNIX as u8,
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
            )
        }
    }

    fn build_rar13_volumes(&self, volume_size: usize) -> rars_rs::Result<Vec<Vec<u8>>> {
        if self.entries.len() != 1 {
            return Err(rars_rs::Error::InvalidHeader(
                "legacy volumes support one input",
            ));
        }
        let entry = &self.entries[0];
        let mut options = rars_rs::rar13::WriterOptions::new(self.format, self.features());
        if let Some(level) = self.compression {
            options = options.with_compression_level(level);
        }
        if self.store {
            rars_rs::rar13::write_stored_volumes(
                rars_rs::rar13::StoredEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: DOS_ARCHIVE_ATTR,
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
            )
        } else {
            rars_rs::rar13::write_compressed_volumes(
                rars_rs::rar13::FileEntry {
                    name: &entry.name,
                    data: &entry.data,
                    file_time: entry.mtime.unwrap_or(0),
                    file_attr: DOS_ARCHIVE_ATTR,
                    password: self.password.as_deref(),
                    file_comment: None,
                },
                options,
                volume_size,
            )
        }
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
    py.detach(|| {
        let options = match password.as_deref() {
            Some(password) => rars_rs::ArchiveReadOptions::with_password(password),
            None => rars_rs::ArchiveReadOptions::new(),
        };
        let archive = rars_rs::ArchiveReader::read_owned_with_options(bytes, options)?;
        archive.repair_recovery()
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
    m.add_function(wrap_pyfunction!(repair, m)?)?;
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

fn read_member(
    archive: &rars_rs::Archive,
    target: &[u8],
    password: Option<&[u8]>,
) -> rars_rs::Result<Option<Vec<u8>>> {
    let output = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(Mutex::new(false));
    extract_to_best(archive, password, {
        let output = Arc::clone(&output);
        let seen = Arc::clone(&seen);
        move |meta| {
            if meta.name == target && !meta.is_directory {
                *seen.lock().expect("seen lock poisoned") = true;
                Ok(Box::new(SharedVecWriter(Arc::clone(&output))) as Box<dyn Write>)
            } else {
                Ok(Box::new(io::sink()) as Box<dyn Write>)
            }
        }
    })?;
    if *seen.lock().expect("seen lock poisoned") {
        Ok(Some(output.lock().expect("output lock poisoned").clone()))
    } else {
        Ok(None)
    }
}

fn test_archive(archive: &rars_rs::Archive, password: Option<&[u8]>) -> rars_rs::Result<()> {
    extract_to_best(archive, password, |_| {
        Ok(Box::new(io::sink()) as Box<dyn Write>)
    })
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
            let path = checked_output_path(out_dir, &meta.name)?;
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
            let path = checked_output_path(out_dir, &meta.name)?;
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
    #[cfg(feature = "parallel")]
    {
        archive.extract_to_parallel_buffered(password, open)
    }
    #[cfg(not(feature = "parallel"))]
    {
        archive.extract_to(password, open)
    }
}

struct SharedVecWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedVecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("output lock poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn archive_comment(
    archive: &rars_rs::Archive,
    password: Option<&[u8]>,
) -> rars_rs::Result<Option<Vec<u8>>> {
    match archive {
        rars_rs::Archive::Rar13(archive) => archive.archive_comment(),
        rars_rs::Archive::Rar15To40(archive) => archive.archive_comment(),
        rars_rs::Archive::Rar50Plus(archive) => archive.archive_comment_with_password(password),
        _ => Err(rars_rs::Error::UnsupportedSignature),
    }
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
    let filename = String::from_utf8_lossy(&member.meta.name).into_owned();
    RarInfo {
        filename,
        orig_filename_bytes: member.meta.name,
        file_size: member.meta.unpacked_size,
        compress_size: member.meta.packed_size,
        date_time: member.meta.file_time.and_then(dos_datetime),
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

fn dos_datetime(raw: u32) -> Option<(u16, u8, u8, u8, u8, u8)> {
    let date = (raw >> 16) as u16;
    let time = raw as u16;
    let year = 1980 + ((date >> 9) & 0x7f);
    let month = ((date >> 5) & 0x0f) as u8;
    let day = (date & 0x1f) as u8;
    let hour = ((time >> 11) & 0x1f) as u8;
    let minute = ((time >> 5) & 0x3f) as u8;
    let second = ((time & 0x1f) * 2) as u8;
    (month != 0 && day != 0).then_some((year, month, day, hour, minute, second))
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
    match value
        .to_ascii_lowercase()
        .replace(['_', '-', '.'], "")
        .as_str()
    {
        "rar13" => Ok(rars_rs::ArchiveVersion::Rar13),
        "rar14" => Ok(rars_rs::ArchiveVersion::Rar14),
        "rar15" => Ok(rars_rs::ArchiveVersion::Rar15),
        "rar20" => Ok(rars_rs::ArchiveVersion::Rar20),
        "rar29" => Ok(rars_rs::ArchiveVersion::Rar29),
        "rar30" => Ok(rars_rs::ArchiveVersion::Rar30),
        "rar40" | "rar4" => Ok(rars_rs::ArchiveVersion::Rar40),
        "rar50" | "rar5" => Ok(rars_rs::ArchiveVersion::Rar50),
        "rar70" | "rar7" => Ok(rars_rs::ArchiveVersion::Rar70),
        _ => Err(PyValueError::new_err(format!(
            "unsupported RAR format: {value}"
        ))),
    }
}

fn checked_output_path(out_dir: &Path, name: &[u8]) -> rars_rs::Result<PathBuf> {
    let rel = output_relative_path(name)?;
    let mut out_path = out_dir.to_path_buf();
    for component in rel.components() {
        let Component::Normal(part) = component else {
            return Err(rars_rs::Error::InvalidHeader("unsafe archive path"));
        };
        out_path.push(part);
        if fs::symlink_metadata(&out_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(rars_rs::Error::InvalidHeader(
                "unsafe archive path crosses symlink",
            ));
        }
    }
    Ok(out_path)
}

fn output_relative_path(name: &[u8]) -> rars_rs::Result<PathBuf> {
    if name.contains(&0) {
        return Err(rars_rs::Error::InvalidHeader(
            "unsafe archive path contains NUL byte",
        ));
    }
    let text = String::from_utf8(name.to_vec())
        .map_err(|_| rars_rs::Error::InvalidHeader("archive entry name is not UTF-8"))?
        .replace('\\', "/");
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(rars_rs::Error::InvalidHeader("unsafe archive path"));
    }
    let path = Path::new(&text);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(rars_rs::Error::InvalidHeader("unsafe archive path")),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(rars_rs::Error::InvalidHeader("empty archive path"));
    }
    Ok(out)
}

fn safe_input_name(name: Vec<u8>) -> PyResult<Vec<u8>> {
    output_relative_path(&name).map_err(map_error)?;
    Ok(name)
}

fn archive_base_name(path: &Path) -> PyResult<Vec<u8>> {
    let file_name = path
        .file_name()
        .ok_or_else(|| PyValueError::new_err("input path has no file name"))?;
    Ok(file_name.to_string_lossy().into_owned().into_bytes())
}

fn collect_builder_input(
    path: &Path,
    archive_name: &[u8],
    out: &mut Vec<BuilderEntry>,
) -> PyResult<()> {
    let link_meta = fs::symlink_metadata(path).map_err(map_io_error)?;
    if link_meta.file_type().is_symlink() {
        return Err(PyValueError::new_err(format!(
            "input '{}' is a symlink; refusing to follow it",
            path.display()
        )));
    }
    let meta = fs::metadata(path).map_err(map_io_error)?;
    if meta.is_dir() {
        let mut children = fs::read_dir(path)
            .map_err(map_io_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_io_error)?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let mut child_name = archive_name.to_vec();
            child_name.push(b'/');
            child_name.extend_from_slice(child.file_name().to_string_lossy().as_bytes());
            collect_builder_input(&child.path(), &child_name, out)?;
        }
    } else if meta.is_file() {
        out.push(BuilderEntry {
            name: safe_input_name(archive_name.to_vec())?,
            data: fs::read(path).map_err(map_io_error)?,
            mtime: None,
            mode: source_unix_mode(&meta),
        });
    }
    Ok(())
}

fn reject_duplicate_names(entries: &[BuilderEntry]) -> PyResult<()> {
    let mut seen = HashSet::new();
    for entry in entries {
        if !seen.insert(entry.name.clone()) {
            return Err(PyValueError::new_err(format!(
                "duplicate archive entry name: {}",
                String::from_utf8_lossy(&entry.name)
            )));
        }
    }
    Ok(())
}

fn rar50_attr(entry: &BuilderEntry) -> u64 {
    u64::from(entry.mode.unwrap_or(u32::from(DOS_ARCHIVE_ATTR)))
}

fn rar15_attr(entry: &BuilderEntry) -> u32 {
    entry.mode.unwrap_or(u32::from(DOS_ARCHIVE_ATTR))
}

#[cfg(unix)]
fn source_unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn source_unix_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
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
    match error {
        rars_rs::Error::UnsupportedSignature
        | rars_rs::Error::UnsupportedVersion(_)
        | rars_rs::Error::UnsupportedFeature { .. }
        | rars_rs::Error::UnsupportedFamilyFeature { .. }
        | rars_rs::Error::UnsupportedCompression { .. }
        | rars_rs::Error::UnsupportedEncryption { .. } => UnsupportedRarFeature::new_err(message),
        rars_rs::Error::InvalidHeader(message) if message.contains("unsafe") => {
            UnsafeArchivePath::new_err(error.to_string())
        }
        rars_rs::Error::Io(io_error) => PyOSError::new_err(io_error.message),
        rars_rs::Error::CrcMismatch { .. }
        | rars_rs::Error::Crc32Mismatch { .. }
        | rars_rs::Error::HashMismatch { .. } => BadRarFile::new_err(message),
        _ => BadRarFile::new_err(error.to_string()),
    }
}

fn error_is_need_password(error: &rars_rs::Error) -> bool {
    match error {
        rars_rs::Error::NeedPassword => true,
        rars_rs::Error::AtArchiveOffset { source, .. } | rars_rs::Error::AtEntry { source, .. } => {
            error_is_need_password(source)
        }
        _ => false,
    }
}

fn error_is_bad_password(error: &rars_rs::Error) -> bool {
    match error {
        rars_rs::Error::WrongPasswordOrCorruptData => true,
        rars_rs::Error::AtArchiveOffset { source, .. } | rars_rs::Error::AtEntry { source, .. } => {
            error_is_bad_password(source)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(safe_input_name(b"dir/file.txt".to_vec()).is_ok());
        assert!(safe_input_name(b"../file.txt".to_vec()).is_err());
        assert!(safe_input_name(b"/tmp/file.txt".to_vec()).is_err());
        assert!(safe_input_name(b"C:/file.txt".to_vec()).is_err());
    }

    #[test]
    fn builder_creates_readable_rar50_bytes() {
        let mut builder = RarBuilder {
            format: rars_rs::ArchiveVersion::Rar50,
            compression: Some(0),
            store: true,
            solid: false,
            password: None,
            encrypt_headers: false,
            comment: Some(b"comment".to_vec()),
            recovery_percent: None,
            volume_size: None,
            entries: Vec::new(),
        };
        builder.entries.push(BuilderEntry {
            name: b"hello.txt".to_vec(),
            data: b"hello".to_vec(),
            mtime: None,
            mode: None,
        });

        let bytes = builder.build_single_archive().unwrap();
        let archive = rars_rs::ArchiveReader::read_owned(bytes).unwrap();
        let names: Vec<_> = archive.members().map(|member| member.meta.name).collect();
        assert_eq!(names, vec![b"hello.txt".to_vec()]);
    }
}
