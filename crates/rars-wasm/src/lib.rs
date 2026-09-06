//! Internal WebAssembly engine for the `@bitplane/rars` worker API.
//!
//! These exports are deliberately low level and live inside package-managed
//! workers. The supported JavaScript surface is the asynchronous TypeScript
//! facade assembled by `scripts/build-npm.sh`; wasm-bindgen classes are not
//! exposed from the npm package.

use rars_rs::{ArchiveVersion, Builder};
use wasm_bindgen::prelude::*;

/// The `rars` version this module was built from, so a page can report which
/// encoder wrote an archive.
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The format names `RarBuilder` accepts, newest last.
#[wasm_bindgen(js_name = formats)]
pub fn formats() -> Vec<String> {
    ArchiveVersion::ALL
        .iter()
        .map(|version| version.as_str().to_string())
        .collect()
}

fn set_error_field(object: &JsValue, name: &str, value: &JsValue) {
    js_sys::Reflect::set(object, &JsValue::from_str(name), value)
        .expect("new error records are extensible");
}

fn binding_error(code: &str, message: &str) -> JsValue {
    let error: JsValue = js_sys::Error::new(message).into();
    set_error_field(&error, "code", &JsValue::from_str(code));
    error
}

fn js_error(error: rars_rs::Error) -> JsValue {
    let record = binding_error(error.kind().code(), &error.to_string());
    let details = js_sys::Object::new();
    let contexts = js_sys::Array::new();
    let mut cause = &error;
    loop {
        let context = js_sys::Object::new();
        match cause {
            rars_rs::Error::AtEntry {
                name,
                operation,
                source,
            } => {
                set_error_field(&context, "kind", &"entry".into());
                // Ordinary arrays survive worker messaging without transferring
                // or detaching any WASM-owned memory. Keep the raw name bytes.
                let bytes = js_sys::Array::new();
                for &byte in name {
                    bytes.push(&JsValue::from(byte));
                }
                set_error_field(&context, "nameBytes", &bytes);
                set_error_field(&context, "operation", &(*operation).into());
                cause = source;
            }
            rars_rs::Error::AtArchiveOffset { offset, source } => {
                set_error_field(&context, "kind", &"archiveOffset".into());
                set_error_field(&context, "offset", &offset.to_string().into());
                cause = source;
            }
            rars_rs::Error::InVolume { number, source } => {
                set_error_field(&context, "kind", &"volume".into());
                set_error_field(&context, "number", &(*number as f64).into());
                cause = source;
            }
            _ => break,
        }
        contexts.push(&context);
    }
    if contexts.length() != 0 {
        set_error_field(&details, "contexts", &contexts);
    }
    match cause {
        rars_rs::Error::MemoryLimitExceeded {
            limit,
            required,
            dictionary_size,
        } => {
            set_error_field(&details, "limitBytes", &limit.to_string().into());
            set_error_field(&details, "requiredBytes", &required.to_string().into());
            set_error_field(
                &details,
                "dictionaryBytes",
                &dictionary_size.to_string().into(),
            );
        }
        rars_rs::Error::MemberOutputLimitExceeded { limit, required }
        | rars_rs::Error::Rar50DictionaryLimitExceeded { limit, required }
        | rars_rs::Error::Rar50BufferedDecodeLimitExceeded { limit, required } => {
            set_error_field(&details, "limitBytes", &limit.to_string().into());
            set_error_field(&details, "requiredBytes", &required.to_string().into());
        }
        rars_rs::Error::Io(error) => {
            set_error_field(&details, "ioKind", &format!("{:?}", error.kind).into())
        }
        rars_rs::Error::Rar5Recovery(rars_rs::recovery::rar5::Error::Io(kind)) => {
            set_error_field(&details, "ioKind", &format!("{kind:?}").into())
        }
        _ => {}
    }
    set_error_field(&record, "details", &details);
    record
}

fn parse_format(name: &str) -> Result<ArchiveVersion, JsValue> {
    ArchiveVersion::from_name(name).ok_or_else(|| {
        binding_error(
            "UNSUPPORTED_FORMAT",
            &format!("unsupported RAR format: {name}"),
        )
    })
}

fn family_name(family: rars_rs::ArchiveFamily) -> &'static str {
    match family {
        rars_rs::ArchiveFamily::Rar13 => "rar13",
        rars_rs::ArchiveFamily::Rar15To40 => "rar15_40",
        rars_rs::ArchiveFamily::Rar50Plus => "rar50_plus",
        _ => "unknown",
    }
}

/// What is known about one member without decoding it.
#[wasm_bindgen]
#[derive(Clone)]
pub struct RarInfo {
    name: Vec<u8>,
    size: f64,
    packed_size: f64,
    crc: Option<u32>,
    host_os: Option<f64>,
    file_attr: f64,
    file_time: Option<u32>,
    encrypted: bool,
    stored: bool,
    solid: bool,
    directory: bool,
    split_before: bool,
    split_after: bool,
}

#[wasm_bindgen]
impl RarInfo {
    /// The member name, decoded leniently. RAR names are bytes, and an archive
    /// written on a DOS codepage has no encoding recorded; use `nameBytes`
    /// when the exact bytes matter.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    /// The member name exactly as the header spells it.
    #[wasm_bindgen(getter, js_name = nameBytes)]
    pub fn name_bytes(&self) -> Vec<u8> {
        self.name.clone()
    }

    /// Decoded size in bytes.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        self.size
    }

    /// Stored size in bytes, before decoding.
    #[wasm_bindgen(getter, js_name = packedSize)]
    pub fn packed_size(&self) -> f64 {
        self.packed_size
    }

    /// CRC-32 of the decoded bytes, where the header carries one.
    #[wasm_bindgen(getter)]
    pub fn crc(&self) -> Option<u32> {
        self.crc
    }

    /// The host OS code from the header, where the format has the field.
    #[wasm_bindgen(getter, js_name = hostOs)]
    pub fn host_os(&self) -> Option<f64> {
        self.host_os
    }

    /// File attributes, whose meaning follows `hostOs`.
    #[wasm_bindgen(getter, js_name = fileAttr)]
    pub fn file_attr(&self) -> f64 {
        self.file_attr
    }

    /// Modification time as a raw DOS timestamp.
    #[wasm_bindgen(getter, js_name = fileTime)]
    pub fn file_time(&self) -> Option<u32> {
        self.file_time
    }

    /// Whether the member's data is encrypted.
    #[wasm_bindgen(getter, js_name = isEncrypted)]
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Whether the member is stored rather than compressed.
    #[wasm_bindgen(getter, js_name = isStored)]
    pub fn is_stored(&self) -> bool {
        self.stored
    }

    /// Whether the member is part of a solid stream, so decoding it means
    /// decoding everything before it.
    #[wasm_bindgen(getter, js_name = isSolid)]
    pub fn is_solid(&self) -> bool {
        self.solid
    }

    /// Whether the entry is a directory rather than a file.
    #[wasm_bindgen(getter, js_name = isDirectory)]
    pub fn is_directory(&self) -> bool {
        self.directory
    }

    /// Whether the member continues from the previous volume.
    #[wasm_bindgen(getter, js_name = isSplitBefore)]
    pub fn is_split_before(&self) -> bool {
        self.split_before
    }

    /// Whether the member continues into the next volume.
    #[wasm_bindgen(getter, js_name = isSplitAfter)]
    pub fn is_split_after(&self) -> bool {
        self.split_after
    }
}

/// An archive opened for reading.
#[wasm_bindgen]
pub struct RarFile {
    archives: Vec<rars_rs::Archive>,
    password: Option<Vec<u8>>,
    infos: Vec<RarInfo>,
}

#[wasm_bindgen]
impl RarFile {
    /// Parse `data` as an archive. The headers are read now and the member
    /// data is decoded on demand, so opening a large archive is cheap.
    ///
    /// A password is needed here only when the archive's headers are
    /// encrypted; for encrypted data in plain headers, pass it to `read`
    /// instead.
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>, password: Option<Password>) -> Result<RarFile, JsValue> {
        let password = password_bytes(password)?;
        let options = match password.as_deref() {
            Some(password) => rars_rs::ArchiveReadOptions::with_password(password),
            None => rars_rs::ArchiveReadOptions::new(),
        };
        let archive =
            rars_rs::ArchiveReader::read_owned_with_options(data, options).map_err(js_error)?;
        let infos = archive.members().map(info_from_member).collect();
        Ok(Self {
            archives: vec![archive],
            password,
            infos,
        })
    }

    /// Parse an ordered set of archive volumes.
    #[wasm_bindgen(js_name = openVolumes)]
    pub fn open_volumes(
        volumes: js_sys::Array,
        password: Option<Password>,
    ) -> Result<RarFile, JsValue> {
        let password = password_bytes(password)?;
        let mut archives = Vec::with_capacity(volumes.length() as usize);
        for value in volumes.iter() {
            if !value.is_instance_of::<js_sys::Uint8Array>() {
                return Err(binding_error(
                    "INVALID_OPTION",
                    "each volume must be a Uint8Array",
                ));
            }
            let data = js_sys::Uint8Array::unchecked_from_js(value).to_vec();
            let options = match password.as_deref() {
                Some(password) => rars_rs::ArchiveReadOptions::with_password(password),
                None => rars_rs::ArchiveReadOptions::new(),
            };
            archives.push(
                rars_rs::ArchiveReader::read_owned_with_options(data, options).map_err(js_error)?,
            );
        }
        let infos = rars_rs::volume_members(&archives)
            .map_err(js_error)?
            .into_iter()
            .map(info_from_member)
            .collect();
        Ok(Self {
            archives,
            password,
            infos,
        })
    }

    /// Every member name, in archive order.
    #[wasm_bindgen(js_name = names)]
    pub fn names(&self) -> Vec<String> {
        self.infos.iter().map(RarInfo::name).collect()
    }

    /// Every member's metadata, in archive order.
    #[wasm_bindgen(js_name = entries)]
    pub fn entries(&self) -> Vec<RarInfo> {
        self.infos.clone()
    }

    /// One member's metadata, or `undefined` when no member has that name.
    #[wasm_bindgen(js_name = getInfo)]
    pub fn get_info(&self, name: &str) -> Option<RarInfo> {
        self.infos
            .iter()
            .find(|info| info.name == name.as_bytes())
            .cloned()
    }

    /// Decode one member.
    ///
    /// Solid archives decode from the start every time, so pulling several
    /// members out of one costs a pass each. Reading a whole solid archive is
    /// better served by asking for each member in archive order.
    pub fn read(&self, name: &str, password: Option<Password>) -> Result<Vec<u8>, JsValue> {
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        self.archives[0]
            .read_member(name.as_bytes(), password.as_deref())
            .map_err(js_error)?
            .ok_or_else(|| {
                js_error(
                    rars_rs::Error::EntryNotFound.at_entry(name.as_bytes().to_vec(), "reading"),
                )
            })
    }

    /// Decode one member by archive-order index.
    #[wasm_bindgen(js_name = readAt)]
    pub fn read_at(&self, index: usize, password: Option<Password>) -> Result<Vec<u8>, JsValue> {
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        let found = if self.archives.len() == 1 {
            self.archives[0].read_member_at(index, password.as_deref())
        } else {
            rars_rs::read_volume_member_at(&self.archives, index, password.as_deref())
        };
        found.map_err(js_error)?.ok_or_else(|| {
            binding_error(
                "ENTRY_NOT_FOUND",
                &format!("no such archive entry index: {index}"),
            )
        })
    }

    /// Decode every member and discard the bytes, throwing on the first
    /// checksum failure or wrong password.
    pub fn test(&self, password: Option<Password>) -> Result<(), JsValue> {
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        if self.archives.len() == 1 {
            return self.archives[0].test(password.as_deref()).map_err(js_error);
        }
        rars_rs::extract_volumes_to(&self.archives, password.as_deref(), |_| {
            Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>)
        })
        .map_err(js_error)
    }

    /// The archive comment, or `undefined` when there is none.
    #[wasm_bindgen(getter)]
    pub fn comment(&self) -> Result<Option<Vec<u8>>, JsValue> {
        self.archives[0]
            .comment(self.password.as_deref())
            .map_err(js_error)
    }

    /// Whether any member is encrypted.
    #[wasm_bindgen(getter, js_name = needsPassword)]
    pub fn needs_password(&self) -> bool {
        self.infos.iter().any(|info| info.encrypted)
    }

    /// Where the RAR data starts, which is past the stub in a self-extracting
    /// archive and zero otherwise.
    #[wasm_bindgen(getter, js_name = sfxOffset)]
    pub fn sfx_offset(&self) -> f64 {
        self.archives[0].sfx_offset() as f64
    }

    /// Which family of the format this archive belongs to: `rar13`,
    /// `rar15_40` or `rar50_plus`.
    #[wasm_bindgen(getter)]
    pub fn family(&self) -> String {
        family_name(self.archives[0].family()).to_string()
    }
}

fn info_from_member(member: rars_rs::ArchiveMember) -> RarInfo {
    // RAR 1.3 checksums are 16 bit and RAR 5 may carry a BLAKE2sp hash instead
    // of a CRC, so the one field JavaScript sees is the CRC-32 where the format
    // has one and null everywhere else.
    let (crc, solid) = match member.detail {
        rars_rs::ArchiveMemberDetail::Rar13 { .. } => (None, false),
        rars_rs::ArchiveMemberDetail::Rar15To40 { crc32, solid, .. } => (Some(crc32), solid),
        rars_rs::ArchiveMemberDetail::Rar50Plus { crc32, .. } => (crc32, false),
        _ => (None, false),
    };
    RarInfo {
        name: member.meta.name,
        size: member.meta.unpacked_size as f64,
        packed_size: member.meta.packed_size as f64,
        crc,
        host_os: member.meta.host_os.map(|os| os as f64),
        file_attr: member.meta.file_attr as f64,
        file_time: member.meta.file_time,
        encrypted: member.meta.is_encrypted,
        stored: member.meta.is_stored,
        solid,
        directory: member.meta.is_directory,
        split_before: member.meta.is_split_before,
        split_after: member.meta.is_split_after,
    }
}

/// Options for a new [`RarBuilder`], passed as a plain object.
#[wasm_bindgen(typescript_custom_section)]
const BUILDER_OPTIONS: &'static str = r#"
export interface RarBuilderOptions {
  /** Archive format to write. Defaults to "rar50". */
  format?: "rar13" | "rar14" | "rar15" | "rar20" | "rar29" | "rar30" | "rar40" | "rar50" | "rar70";
  /** Compression level from 0 to 5. Defaults to 3. */
  compression?: number;
  /** Store members without compressing them. Overrides `compression`. */
  store?: boolean;
  /** Compress members against each other rather than independently. */
  solid?: boolean;
  /** Encrypt member data. */
  password?: Uint8Array | string;
  /** Encrypt the headers too, hiding member names. Requires `password`. */
  encryptHeaders?: boolean;
  /** Archive comment. */
  comment?: Uint8Array | string;
  /** Add a recovery record covering this percentage of the archive. */
  recoveryPercent?: number;
  /** Split into volumes of at most this many bytes; use `toVolumes()`. */
  volumeSize?: number;
}

export interface RarEntryOptions {
  /** Modification time as a raw DOS timestamp. */
  mtime?: number;
  /** File mode, as `st_mode` from `stat`. */
  mode?: number;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "RarBuilderOptions")]
    pub type RarBuilderOptions;

    #[wasm_bindgen(typescript_type = "RarEntryOptions")]
    pub type RarEntryOptions;

    #[wasm_bindgen(typescript_type = "Uint8Array | string")]
    pub type Password;
}

/// Assembles an archive from members added one at a time.
#[wasm_bindgen]
pub struct RarBuilder {
    inner: Builder,
}

#[wasm_bindgen]
impl RarBuilder {
    /// A builder for the format named in `options`, defaulting to RAR 5 at
    /// compression level 3.
    #[wasm_bindgen(constructor)]
    pub fn new(options: Option<RarBuilderOptions>) -> Result<RarBuilder, JsValue> {
        let options: JsValue = match options {
            Some(options) => options.into(),
            None => JsValue::UNDEFINED,
        };
        let format = match opt_string(&options, "format")? {
            Some(name) => parse_format(&name)?,
            None => ArchiveVersion::Rar50,
        };
        let compression = opt_number(&options, "compression")?
            .map(|level| level as u8)
            .unwrap_or(3);
        Ok(Self {
            inner: Builder::new(format)
                .compression_level(Some(compression))
                .store(opt_bool(&options, "store")?)
                .solid(opt_bool(&options, "solid")?)
                .password(opt_bytes(&options, "password")?)
                .header_encryption(opt_bool(&options, "encryptHeaders")?)
                .comment(opt_bytes(&options, "comment")?)
                .recovery_percent(opt_number(&options, "recoveryPercent")?.map(|n| n as u64))
                .volume_size(opt_number(&options, "volumeSize")?.map(|n| n as usize)),
        })
    }

    /// Queue `data` under `name`.
    ///
    /// Names that would escape an extraction directory are refused here rather
    /// than written and refused later: absolute paths, `..`, drive letters.
    #[wasm_bindgen(js_name = addBytes)]
    pub fn add_bytes(
        &mut self,
        name: &str,
        data: Vec<u8>,
        options: Option<RarEntryOptions>,
    ) -> Result<(), JsValue> {
        let options: JsValue = match options {
            Some(options) => options.into(),
            None => JsValue::UNDEFINED,
        };
        self.inner
            .add_bytes(
                name.as_bytes().to_vec(),
                data,
                opt_number(&options, "mtime")?.map(|n| n as u32),
                opt_number(&options, "mode")?.map(|n| n as u32),
            )
            .map_err(js_error)
    }

    /// Queue `data` under an exact byte name. Internal worker-facing variant.
    #[wasm_bindgen(js_name = addBytesRaw)]
    pub fn add_bytes_raw(
        &mut self,
        name: Vec<u8>,
        data: Vec<u8>,
        options: Option<RarEntryOptions>,
    ) -> Result<(), JsValue> {
        let options: JsValue = match options {
            Some(options) => options.into(),
            None => JsValue::UNDEFINED,
        };
        self.inner
            .add_bytes(
                name,
                data,
                opt_number(&options, "mtime")?.map(|n| n as u32),
                opt_number(&options, "mode")?.map(|n| n as u32),
            )
            .map_err(js_error)
    }

    /// Drop the member called `name`.
    pub fn remove(&mut self, name: &str) -> Result<(), JsValue> {
        self.inner.remove(name.as_bytes()).map_err(js_error)
    }

    /// Rename a queued member.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), JsValue> {
        self.inner
            .rename(from.as_bytes(), to.as_bytes().to_vec())
            .map_err(js_error)
    }

    /// The queued member names, in the order they will be written.
    #[wasm_bindgen(js_name = names)]
    pub fn names(&self) -> Vec<String> {
        self.inner
            .names()
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect()
    }

    /// How many members are queued.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> usize {
        self.inner.len()
    }

    /// Encode the archive.
    ///
    /// This runs the compressor, which for a large input at a high level is
    /// seconds of work with no yielding. Call it from a worker if the page has
    /// to stay responsive.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.to_bytes().map_err(js_error)
    }

    /// Encode the archive as a volume set, one `Uint8Array` per volume.
    /// Requires `volumeSize`.
    #[wasm_bindgen(js_name = toVolumes, unchecked_return_type = "Uint8Array[]")]
    pub fn to_volumes(&self) -> Result<js_sys::Array, JsValue> {
        let volumes = self.inner.build_volumes(None).map_err(js_error)?;
        Ok(volumes
            .iter()
            .map(|volume| js_sys::Uint8Array::from(volume.as_slice()))
            .collect())
    }
}

/// Rebuild a damaged archive from its recovery record, returning the repaired
/// bytes. Throws when the archive has no recovery record, or when the damage is
/// past what the record covers.
#[wasm_bindgen(js_name = repair)]
pub fn repair(data: Vec<u8>, password: Option<Password>) -> Result<Vec<u8>, JsValue> {
    let password = password_bytes(password)?;
    repair_core(&data, password.as_deref())
        .map(|result| result.data)
        .map_err(js_error)
}

fn repair_core(
    data: &[u8],
    password: Option<&[u8]>,
) -> rars_rs::Result<rars_rs::RecoveryRepairResult> {
    let options = || match password {
        Some(password) => rars_rs::ArchiveReadOptions::with_password(password),
        None => rars_rs::ArchiveReadOptions::new(),
    };
    match rars_rs::ArchiveReader::read_with_options(data, options()) {
        Ok(archive) => archive.repair_recovery_with_report(password),
        Err(_) => rars_rs::rar50::repair_inline_recovery_bytes_with_options(data, options()),
    }
}

#[wasm_bindgen]
pub struct RepairReport {
    inner: rars_rs::RecoveryRepairReport,
}

#[wasm_bindgen]
impl RepairReport {
    #[wasm_bindgen(getter)]
    pub fn changed(&self) -> bool {
        self.inner.changed
    }
    #[wasm_bindgen(getter, js_name = dataRepaired)]
    pub fn data_repaired(&self) -> bool {
        self.inner.data_repaired
    }
    #[wasm_bindgen(getter, js_name = recoveryRecordRebuilt)]
    pub fn recovery_record_rebuilt(&self) -> bool {
        self.inner.recovery_record_rebuilt
    }
    #[wasm_bindgen(getter, js_name = endRecordRebuilt)]
    pub fn end_record_rebuilt(&self) -> bool {
        self.inner.end_record_rebuilt
    }
    #[wasm_bindgen(getter, js_name = availableRecoveryShards)]
    pub fn available_recovery_shards(&self) -> Option<f64> {
        self.inner.available_recovery_shards.map(|v| v as f64)
    }
    #[wasm_bindgen(getter, js_name = expectedRecoveryShards)]
    pub fn expected_recovery_shards(&self) -> Option<f64> {
        self.inner.expected_recovery_shards.map(|v| v as f64)
    }
}

#[wasm_bindgen]
pub struct RepairResult {
    data: Vec<u8>,
    report: RepairReport,
}

#[wasm_bindgen]
impl RepairResult {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn report(&self) -> RepairReport {
        RepairReport {
            inner: self.report.inner,
        }
    }
}

#[wasm_bindgen(js_name = repairDetailed)]
pub fn repair_detailed(data: Vec<u8>, password: Option<Password>) -> Result<RepairResult, JsValue> {
    let password = password_bytes(password)?;
    let result = repair_core(&data, password.as_deref()).map_err(js_error)?;
    Ok(RepairResult {
        data: result.data,
        report: RepairReport {
            inner: result.report,
        },
    })
}

/// A password is either a string, encoded as UTF-8, or the raw bytes. RAR 5
/// stores UTF-8, so a string is the normal case; the byte form is for the older
/// formats, where the password is whatever bytes the original writer used and
/// no encoding is recorded.
fn password_bytes(password: Option<Password>) -> Result<Option<Vec<u8>>, JsValue> {
    let Some(password) = password else {
        return Ok(None);
    };
    let value: JsValue = password.into();
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    if let Some(text) = value.as_string() {
        return Ok(Some(text.into_bytes()));
    }
    if value.is_instance_of::<js_sys::Uint8Array>() {
        return Ok(Some(js_sys::Uint8Array::unchecked_from_js(value).to_vec()));
    }
    Err(binding_error(
        "INVALID_OPTION",
        "password must be a string or Uint8Array",
    ))
}

/// Read `key` off a plain JS object, treating a missing object and a missing
/// key alike. Everything the options types accept is optional, so this is the
/// only shape of lookup the bindings need.
fn opt_value(options: &JsValue, key: &str) -> Result<JsValue, JsValue> {
    if options.is_undefined() || options.is_null() {
        return Ok(JsValue::UNDEFINED);
    }
    js_sys::Reflect::get(options, &JsValue::from_str(key))
}

fn opt_bool(options: &JsValue, key: &str) -> Result<bool, JsValue> {
    Ok(opt_value(options, key)?.is_truthy())
}

fn opt_number(options: &JsValue, key: &str) -> Result<Option<f64>, JsValue> {
    let value = opt_value(options, key)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    value
        .as_f64()
        .map(Some)
        .ok_or_else(|| binding_error("INVALID_OPTION", &format!("{key} must be a number")))
}

fn opt_string(options: &JsValue, key: &str) -> Result<Option<String>, JsValue> {
    let value = opt_value(options, key)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    value
        .as_string()
        .map(Some)
        .ok_or_else(|| binding_error("INVALID_OPTION", &format!("{key} must be a string")))
}

/// Passwords and comments take either a string or raw bytes. A string is
/// encoded as UTF-8, which is what a RAR 5 archive stores; the byte form is
/// there for the older formats, where the password is whatever bytes the
/// original writer used.
fn opt_bytes(options: &JsValue, key: &str) -> Result<Option<Vec<u8>>, JsValue> {
    let value = opt_value(options, key)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    if let Some(text) = value.as_string() {
        return Ok(Some(text.into_bytes()));
    }
    if value.is_instance_of::<js_sys::Uint8Array>() {
        let array = js_sys::Uint8Array::unchecked_from_js(value);
        return Ok(Some(array.to_vec()));
    }
    Err(binding_error(
        "INVALID_OPTION",
        &format!("{key} must be a string or Uint8Array"),
    ))
}
