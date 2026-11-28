//! Internal WebAssembly engine for the `@bitplane/rars` worker API.
//!
//! These exports are deliberately low level and live inside package-managed
//! workers. The supported JavaScript surface is the asynchronous TypeScript
//! facade assembled by `scripts/build-npm.sh`; wasm-bindgen classes are not
//! exposed from the npm package.

use rars_rs::filename::LegacyNameEncoding;
use rars_rs::{ArchiveVersion, Builder};
use wasm_bindgen::prelude::*;

mod member_errors;
mod progress;

/// The `rars` version this module was built from, so a page can report which
/// encoder wrote an archive.
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The format names `RarBuilder` accepts, newest last.
/// Tries `candidates` in order against one volume, stopping at the first proved correct.
/// Returns `{ correct, undetermined, needsPassword, headersEncrypted }`, with candidates
/// given by their index in `candidates`.
#[wasm_bindgen(js_name = checkPassword)]
pub fn check_password(
    data: Vec<u8>,
    candidates: js_sys::Array,
    settings: JsValue,
) -> Result<JsValue, JsValue> {
    use rars_rs::password_check::{PasswordProbe, PasswordVerdict};
    let options = read_options(None, &settings)?;
    let probe = PasswordProbe::read_owned(data, options).map_err(js_error)?;
    let result = js_sys::Object::new();
    let undetermined = js_sys::Array::new();
    if probe.needs_password() {
        for (index, candidate) in candidates.iter().enumerate() {
            let password = password_bytes(Some(candidate.unchecked_into()))?.unwrap_or_default();
            match probe.check(&password, options).map_err(js_error)? {
                PasswordVerdict::Correct => {
                    set_error_field(&result, "correct", &(index as f64).into());
                    break;
                }
                PasswordVerdict::Undetermined => {
                    undetermined.push(&(index as f64).into());
                }
                PasswordVerdict::Wrong => {}
            }
        }
    }
    set_error_field(&result, "undetermined", &undetermined);
    set_error_field(&result, "needsPassword", &probe.needs_password().into());
    set_error_field(
        &result,
        "headersEncrypted",
        &probe.headers_encrypted().into(),
    );
    Ok(result.into())
}

/// The file names of a `total`-volume set written as `version`, derived from the first
/// volume's name as RAR derives them.
#[wasm_bindgen(js_name = volumeNames)]
pub fn volume_names(first_name: &str, total: usize, version: &str) -> Result<Vec<String>, JsValue> {
    let version = parse_format(version)?;
    let first = std::path::Path::new(first_name);
    let part = matches!(version, ArchiveVersion::Rar50 | ArchiveVersion::Rar70);
    let width = total.to_string().len().max(2);
    (0..total)
        .map(|index| {
            let name = if part {
                rars_rs::volume_name::part_style(first, index, width)
            } else {
                rars_rs::volume_name::old_style(first, index)
            };
            name.map(|name| name.to_string_lossy().into_owned())
                .ok_or_else(|| {
                    binding_error(
                        "INVALID_OPTION",
                        if part {
                            "volume output needs a file name"
                        } else {
                            "old-style volume names run out after .z99"
                        },
                    )
                })
        })
        .collect()
}

/// Whether `prefix` starts with a RAR signature.
#[wasm_bindgen(js_name = isRarFile)]
pub fn is_rar_file(prefix: &[u8]) -> bool {
    rars_rs::detect_archive_family(prefix).is_some()
}

/// Whether a RAR archive starts in `prefix`, at its start or behind a self-extractor stub,
/// found the way opening finds it.
#[wasm_bindgen(js_name = isRarFileSfx)]
pub fn is_rar_file_sfx(prefix: &[u8]) -> bool {
    rars_rs::find_archive_start(prefix, rars_rs::SFX_SCAN_LIMIT).is_some()
}

/// How many leading bytes `isRarFileSfx` needs.
#[wasm_bindgen(js_name = sfxProbeBytes)]
pub fn sfx_probe_bytes() -> f64 {
    (rars_rs::SFX_SCAN_LIMIT + rars_rs::detect::RAR50_SIGNATURE.len()) as f64
}

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

// Keep the wire names and exact byte counts testable without a JavaScript host.
fn total_output_error_details(limit: u64, required: u64, used: u64) -> [(&'static str, String); 3] {
    [
        ("limitBytes", limit.to_string()),
        ("requiredBytes", required.to_string()),
        ("usedBytes", used.to_string()),
    ]
}

fn header_count_error_details(limit: u64, required: u64) -> [(&'static str, String); 2] {
    [
        ("limitHeaders", limit.to_string()),
        ("requiredHeaders", required.to_string()),
    ]
}

#[cfg(test)]
mod error_detail_tests {
    #[test]
    fn header_count_details_keep_header_units_and_exact_integer_counts() {
        assert_eq!(
            super::header_count_error_details(9_007_199_254_740_993, u64::MAX),
            [
                ("limitHeaders", "9007199254740993".to_owned()),
                ("requiredHeaders", "18446744073709551615".to_owned()),
            ]
        );
    }
    #[test]
    fn total_output_details_preserve_counts_above_javascript_integer_precision() {
        assert_eq!(
            super::total_output_error_details(u64::MAX - 1, u64::MAX, 9_007_199_254_740_993),
            [
                ("limitBytes", "18446744073709551614".to_owned()),
                ("requiredBytes", "18446744073709551615".to_owned()),
                ("usedBytes", "9007199254740993".to_owned()),
            ]
        );
    }
}

fn js_error(error: rars_rs::Error) -> JsValue {
    // Volume faults the caller fixes are not damage, so they get their own codes, as in Python.
    let code = match error.root_cause() {
        rars_rs::Error::MissingVolume => "MISSING_VOLUME",
        rars_rs::Error::VolumeOutOfOrder => "VOLUME_ORDER",
        // Only salvage reports these, after the member's bytes were delivered.
        rars_rs::Error::MemberCutShort { .. } => "MEMBER_CUT_SHORT",
        rars_rs::Error::MemberRanPastDeclaredSize { .. } => "MEMBER_RAN_PAST_DECLARED_SIZE",
        _ => error.kind().code(),
    };
    let record = binding_error(code, &error.to_string());
    let details = js_sys::Object::new();
    let contexts = js_sys::Array::new();
    let mut cause = &error;
    // The innermost volume, where the fault is rather than where reading began.
    let mut volume_index = None;
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
            rars_rs::Error::InVolume { index, source } => {
                set_error_field(&context, "kind", &"volume".into());
                set_error_field(&context, "index", &(*index as f64).into());
                volume_index = Some(*index);
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
        // Python's MissingVolume and VolumeOrderError carry it as `volume_index`.
        rars_rs::Error::MissingVolume | rars_rs::Error::VolumeOutOfOrder => {
            if let Some(index) = volume_index {
                set_error_field(&details, "volumeIndex", &(index as f64).into());
            }
        }
        rars_rs::Error::Codec(rars_rs::codec::Error::WorkspaceLimitExceeded(detail)) => {
            for (name, value) in
                total_output_error_details(detail.limit, detail.required, detail.used)
            {
                set_error_field(&details, name, &value.into());
            }
        }
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
        rars_rs::Error::WriterPreparationLimitExceeded {
            limit,
            required,
            used,
        }
        | rars_rs::Error::WriterPreparedHeaderLimitExceeded {
            limit,
            required,
            used,
        }
        | rars_rs::Error::WriterSpoolMemoryLimitExceeded {
            limit,
            required,
            used,
        }
        | rars_rs::Error::WriterSpoolLimitExceeded {
            limit,
            required,
            used,
        }
        | rars_rs::Error::TotalOutputLimitExceeded {
            limit,
            required,
            used,
        } => {
            for (name, value) in total_output_error_details(*limit, *required, *used) {
                set_error_field(&details, name, &value.into());
            }
        }
        rars_rs::Error::MemberOutputLimitExceeded { limit, required }
        | rars_rs::Error::HeaderBytesLimitExceeded { limit, required }
        | rars_rs::Error::Rar50DictionaryLimitExceeded { limit, required }
        | rars_rs::Error::Rar50BufferedDecodeLimitExceeded { limit, required } => {
            set_error_field(&details, "limitBytes", &limit.to_string().into());
            set_error_field(&details, "requiredBytes", &required.to_string().into());
        }
        rars_rs::Error::HeaderCountLimitExceeded { limit, required } => {
            for (name, value) in header_count_error_details(*limit, *required) {
                set_error_field(&details, name, &value.into());
            }
        }
        rars_rs::Error::MemberCutShort { packed, present } => {
            set_error_field(&details, "packedBytes", &packed.to_string().into());
            set_error_field(&details, "presentBytes", &present.to_string().into());
        }
        rars_rs::Error::MemberRanPastDeclaredSize { declared } => {
            set_error_field(&details, "declaredBytes", &declared.to_string().into());
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
    display_name: String,
    name: Vec<u8>,
    size: f64,
    packed_size: f64,
    crc: Option<u32>,
    host_os: Option<f64>,
    file_attr: f64,
    mtime: Option<f64>,
    atime: Option<f64>,
    birthtime: Option<f64>,
    encrypted: bool,
    stored: bool,
    solid: bool,
    directory: bool,
    split_before: bool,
    split_after: bool,
    volume_index: usize,
    link: bool,
}

#[wasm_bindgen]
impl RarInfo {
    /// The member name, decoded leniently. RAR names are bytes, and an archive
    /// written on a DOS codepage has no encoding recorded; use `nameBytes`
    /// when the exact bytes matter.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.display_name.clone()
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

    /// Modification time in Unix seconds, with any fraction the archive keeps.
    #[wasm_bindgen(getter)]
    pub fn mtime(&self) -> Option<f64> {
        self.mtime
    }

    /// Access time in Unix seconds, where the archive records one.
    #[wasm_bindgen(getter)]
    pub fn atime(&self) -> Option<f64> {
        self.atime
    }

    /// Creation time in Unix seconds, where the archive records one.
    #[wasm_bindgen(getter)]
    pub fn birthtime(&self) -> Option<f64> {
        self.birthtime
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

    /// The volume the member starts in, counting the first as 0.
    #[wasm_bindgen(getter, js_name = volumeIndex)]
    pub fn volume_index(&self) -> usize {
        self.volume_index
    }

    /// Whether the member is a link, whose target `readLink` reads.
    #[wasm_bindgen(getter, js_name = isLink)]
    pub fn is_link(&self) -> bool {
        self.link
    }
}

/// An archive opened for reading.
#[wasm_bindgen]
pub struct RarFile {
    archives: Vec<rars_rs::Archive>,
    password: Option<Vec<u8>>,
    infos: Vec<RarInfo>,
    encoding: Option<LegacyNameEncoding>,
    detect_encoding: bool,
    /// Each member's first part: its volume, and its index within that volume.
    places: Vec<(usize, usize)>,
    /// The split members `salvage` left out, as part of each is in a volume not given.
    incomplete: Vec<Incomplete>,
}

/// A split member a salvaged volume set leaves out.
#[derive(Clone)]
struct Incomplete {
    name: String,
    name_bytes: Vec<u8>,
    volume_index: usize,
    missing: &'static str,
}

/// Under salvage, leaves out the members `volumes` hold only part of, so the rest read
/// as a whole set, and returns them in archive order.
fn drop_incomplete(
    volumes: &mut [rars_rs::Archive],
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
) -> rars_rs::Result<Vec<Incomplete>> {
    // Only a volume's first or last member can be incomplete; name it as `entries` would.
    let mut names = std::collections::HashMap::new();
    for (index, volume) in volumes.iter().enumerate() {
        for member in volume.members().take(1).chain(volume.members().last()) {
            let name = String::from_utf8_lossy(&member.decoded_name(encoding)?).into_owned();
            names.insert((index, member.meta.name.clone()), name);
        }
    }
    Ok(rars_rs::drop_incomplete_members(volumes)
        .into_iter()
        .map(|member| Incomplete {
            name: names
                .remove(&(member.volume, member.name.clone()))
                .unwrap_or_else(|| String::from_utf8_lossy(&member.name).into_owned()),
            name_bytes: member.name,
            volume_index: member.volume,
            missing: match member.missing {
                rars_rs::MissingPart::Start => "start",
                rars_rs::MissingPart::End => "end",
                _ => "both",
            },
        })
        .collect())
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
    pub fn new(
        data: Vec<u8>,
        password: Option<Password>,
        settings: JsValue,
    ) -> Result<RarFile, JsValue> {
        let password = password_bytes(password)?;
        let options = read_options(password.as_deref(), &settings)?;
        let mut archives =
            vec![rars_rs::ArchiveReader::read_owned_with_options(data, options).map_err(js_error)?];
        let detect_encoding = options.legacy_name_encoding == Some(LegacyNameEncoding::Detect);
        let encoding = if detect_encoding {
            rars_rs::detect_volume_legacy_name_encoding(&archives)
        } else {
            options.legacy_name_encoding
        };
        // A volume on its own reads as a lone archive once its split members are gone.
        let incomplete = if options.salvage {
            drop_incomplete(&mut archives, encoding).map_err(js_error)?
        } else {
            Vec::new()
        };
        let infos = archives[0]
            .members()
            .map(|member| info_with_encoding(member, encoding))
            .collect::<rars_rs::Result<Vec<_>>>()
            .map_err(js_error)?;
        let places = (0..infos.len()).map(|index| (0, index)).collect();
        Ok(Self {
            archives,
            password,
            infos,
            encoding,
            detect_encoding,
            places,
            incomplete,
        })
    }

    /// Parse an ordered set of archive volumes.
    #[wasm_bindgen(js_name = openVolumes)]
    pub fn open_volumes(
        volumes: js_sys::Array,
        password: Option<Password>,
        settings: JsValue,
    ) -> Result<RarFile, JsValue> {
        let password = password_bytes(password)?;
        let options = read_options(password.as_deref(), &settings)?;
        let mut archives = Vec::with_capacity(volumes.length() as usize);
        for value in volumes.iter() {
            if !value.is_instance_of::<js_sys::Uint8Array>() {
                return Err(binding_error(
                    "INVALID_OPTION",
                    "each volume must be a Uint8Array",
                ));
            }
            let data = js_sys::Uint8Array::unchecked_from_js(value).to_vec();
            archives.push(
                rars_rs::ArchiveReader::read_owned_with_options(data, options).map_err(js_error)?,
            );
        }
        let detect_encoding = options.legacy_name_encoding == Some(LegacyNameEncoding::Detect);
        let encoding = if detect_encoding {
            rars_rs::detect_volume_legacy_name_encoding(&archives)
        } else {
            options.legacy_name_encoding
        };
        // A salvaged set may begin late or end early: what it holds only part of is left out.
        let incomplete = if options.salvage {
            drop_incomplete(&mut archives, encoding).map_err(js_error)?
        } else {
            Vec::new()
        };
        // A member starts in the volume holding its first part.
        let places: Vec<(usize, usize)> = archives
            .iter()
            .enumerate()
            .flat_map(|(volume, archive)| {
                archive
                    .members()
                    .enumerate()
                    .filter(|(_, member)| !member.meta.is_split_before)
                    .map(move |(index, _)| (volume, index))
            })
            .collect();
        let infos = rars_rs::volume_members(&archives)
            .map_err(js_error)?
            .into_iter()
            .zip(places.iter().map(|&(volume, _)| volume))
            .map(|(member, volume_index)| {
                info_with_encoding(member, encoding).map(|info| RarInfo {
                    volume_index,
                    ..info
                })
            })
            .collect::<rars_rs::Result<Vec<_>>>()
            .map_err(js_error)?;
        Ok(Self {
            archives,
            password,
            infos,
            encoding,
            detect_encoding,
            places,
            incomplete,
        })
    }

    /// The resolved source encoding for legacy filenames.
    #[wasm_bindgen(getter, js_name = legacyNameEncoding)]
    pub fn legacy_name_encoding(&self) -> Option<String> {
        self.encoding.map(|encoding| encoding.as_str().to_owned())
    }

    /// Where the file ends early, or undefined: `{ block, name, offset, started,
    /// membersComplete, volumeIndex, message }`, from the first volume that does.
    /// `block` is `member`, `recoveryRecord`, `service`, `comment`, `end` or `unknown`,
    /// and `name` the stored name of a cut member or service block.
    pub fn truncation(&self) -> JsValue {
        use rars_rs::TruncatedBlock as Block;
        let Some((volume_index, truncation)) = self
            .archives
            .iter()
            .enumerate()
            .find_map(|(index, volume)| volume.truncation().map(|cut| (index, cut)))
        else {
            return JsValue::UNDEFINED;
        };
        let (block, name) = match &truncation.block {
            Block::Member(name) => ("member", Some(name)),
            Block::RecoveryRecord => ("recoveryRecord", None),
            Block::Service(name) => ("service", Some(name)),
            Block::Comment => ("comment", None),
            Block::End => ("end", None),
            _ => ("unknown", None),
        };
        let record = js_sys::Object::new();
        set_error_field(&record, "block", &block.into());
        if let Some(name) = name {
            set_error_field(&record, "name", &js_sys::Uint8Array::from(name.as_slice()));
        }
        set_error_field(&record, "offset", &(truncation.offset as f64).into());
        set_error_field(&record, "started", &truncation.started.into());
        set_error_field(
            &record,
            "membersComplete",
            &truncation.members_complete.into(),
        );
        set_error_field(&record, "volumeIndex", &(volume_index as f64).into());
        set_error_field(&record, "message", &truncation.to_string().into());
        record.into()
    }

    /// The damaged headers salvage read past, in file order: `{ kind, offset,
    /// volumeIndex, message }`, `kind` one of `checksum`, `droppedRecord`,
    /// `unreadable`, `resynced` or `quickOpenCopy`.
    #[wasm_bindgen(js_name = headerDamage)]
    pub fn header_damage(&self) -> js_sys::Array {
        use rars_rs::HeaderDamageKind as Kind;
        let list = js_sys::Array::new();
        for (volume_index, volume) in self.archives.iter().enumerate() {
            for damage in volume.header_damage() {
                let kind = match damage.kind {
                    Kind::Checksum { .. } => "checksum",
                    Kind::DroppedRecord { .. } => "droppedRecord",
                    Kind::Resynced { .. } => "resynced",
                    Kind::QuickOpenCopy { .. } => "quickOpenCopy",
                    _ => "unreadable",
                };
                let record = js_sys::Object::new();
                set_error_field(&record, "kind", &kind.into());
                set_error_field(&record, "offset", &(damage.offset as f64).into());
                set_error_field(&record, "volumeIndex", &(volume_index as f64).into());
                set_error_field(&record, "message", &damage.to_string().into());
                list.push(&record);
            }
        }
        list
    }

    /// The split members salvage left out of a volume set, in archive order:
    /// `{ name, nameBytes, volumeIndex, missing }`, `missing` one of `start`, `end`
    /// or `both`.
    #[wasm_bindgen(js_name = incompleteMembers)]
    pub fn incomplete_members(&self) -> js_sys::Array {
        let list = js_sys::Array::new();
        for member in &self.incomplete {
            let record = js_sys::Object::new();
            set_error_field(&record, "name", &member.name.as_str().into());
            set_error_field(
                &record,
                "nameBytes",
                &js_sys::Uint8Array::from(member.name_bytes.as_slice()),
            );
            set_error_field(&record, "volumeIndex", &(member.volume_index as f64).into());
            set_error_field(&record, "missing", &member.missing.into());
            list.push(&record);
        }
        list
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
            .rev()
            .find(|info| info.name == name.as_bytes())
            .cloned()
    }

    /// Decode one member.
    ///
    /// Each call starts a new decoder session. Use `readMany` for several
    /// members so required solid predecessors are decoded once.
    pub fn read(
        &self,
        name: &str,
        password: Option<Password>,
        settings: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        let options = read_options(password.as_deref(), &settings)?;
        let found = if let Some(index) = self
            .infos
            .iter()
            .rposition(|info| info.name == name.as_bytes())
        {
            if self.archives.len() == 1 {
                self.archives[0].read_member_at_with_options(index, options)
            } else {
                rars_rs::read_volume_member_at_with_options(&self.archives, index, options)
            }
        } else {
            Ok(None)
        };
        found.map_err(js_error)?.ok_or_else(|| {
            js_error(rars_rs::Error::EntryNotFound.at_entry(name.as_bytes().to_vec(), "reading"))
        })
    }

    /// Decode one member by archive-order index.
    ///
    /// Given `memberError`, a member that fails is reported to it instead of failing
    /// the call, and the call returns what was delivered for it: everything decoded
    /// before the failure under salvage, and nothing otherwise.
    #[wasm_bindgen(js_name = readAt)]
    pub fn read_at(
        &self,
        index: usize,
        password: Option<Password>,
        settings: JsValue,
        progress: Option<js_sys::Function>,
        member_error: Option<js_sys::Function>,
    ) -> Result<Vec<u8>, JsValue> {
        self.refuse_continued(&[index])?;
        let missing = || {
            binding_error(
                "ENTRY_NOT_FOUND",
                &format!("no such archive entry index: {index}"),
            )
        };
        if member_error.is_some() {
            let data =
                self.read_reporting(&[index], password, &settings, progress, member_error)?;
            return data.into_iter().next().flatten().ok_or_else(missing);
        }
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        if progress.is_some() && self.archives.len() == 1 {
            let options = read_options(password.as_deref(), &settings)?;
            let data = progress::watching(progress, || {
                read_counted(&self.archives[0], &[index], options)
            })
            .map_err(js_error)?;
            return data.into_iter().next().flatten().ok_or_else(missing);
        }
        let found = if self.archives.len() == 1 {
            self.archives[0]
                .read_member_at_with_options(index, read_options(password.as_deref(), &settings)?)
        } else {
            rars_rs::read_volume_member_at_with_options(
                &self.archives,
                index,
                read_options(password.as_deref(), &settings)?,
            )
        };
        found.map_err(js_error)?.ok_or_else(missing)
    }

    /// Decode selected indices in one session, preserving order and duplicates.
    /// `memberError` works as in `readAt`, for each member that fails.
    #[wasm_bindgen(js_name = readMany)]
    pub fn read_many(
        &self,
        indices: Vec<u32>,
        password: Option<Password>,
        settings: JsValue,
        progress: Option<js_sys::Function>,
        member_error: Option<js_sys::Function>,
    ) -> Result<js_sys::Array, JsValue> {
        let indices: Vec<usize> = indices.into_iter().map(|index| index as usize).collect();
        self.refuse_continued(&indices)?;
        let data = if member_error.is_some() {
            self.read_reporting(&indices, password, &settings, progress, member_error)?
        } else {
            let password = password_bytes(password)?.or_else(|| self.password.clone());
            let options = read_options(password.as_deref(), &settings)?;
            if progress.is_some() && self.archives.len() == 1 {
                progress::watching(progress, || {
                    read_counted(&self.archives[0], &indices, options)
                })
            } else if self.archives.len() == 1 {
                self.archives[0].read_members_at_with_options(&indices, options)
            } else {
                rars_rs::read_volume_members_at_with_options(&self.archives, &indices, options)
            }
            .map_err(js_error)?
        };
        let results = js_sys::Array::new();
        for (index, bytes) in indices.into_iter().zip(data) {
            let bytes = bytes.ok_or_else(|| {
                binding_error(
                    "ENTRY_NOT_FOUND",
                    &format!("no file payload at archive entry index: {index}"),
                )
            })?;
            results.push(&js_sys::Uint8Array::from(bytes.as_slice()));
        }
        Ok(results)
    }

    /// Decode every member and discard the bytes, throwing on the first
    /// checksum failure or wrong password. Given `nextVolume`, the set's later
    /// volumes are each pulled from it as needed, until it returns undefined.
    /// Given `memberError`, each member that fails is reported to it instead,
    /// and the call carries on.
    pub fn test(
        &self,
        password: Option<Password>,
        settings: JsValue,
        progress: Option<js_sys::Function>,
        next_volume: Option<js_sys::Function>,
        member_error: Option<js_sys::Function>,
    ) -> Result<(), JsValue> {
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        let mut options = read_options(password.as_deref(), &settings)?;
        let mut next_volume = next_volume;
        let volumes = self.resolve_call_encoding(&mut options, &mut next_volume)?;
        let report =
            member_errors::Reporting::start(member_error, options.legacy_name_encoding, false);
        let options = report
            .as_ref()
            .map_or(options, |report| report.handling(options));
        let result = Self::test_with(
            volumes.as_deref().unwrap_or(&self.archives),
            options,
            progress,
            next_volume,
        );
        if let Some(report) = report {
            report.finish()?;
        }
        result
    }
    /// The archive comment, or `undefined` when there is none.
    #[wasm_bindgen(getter)]
    pub fn comment(&self) -> Result<Option<Vec<u8>>, JsValue> {
        self.read_comment(None, JsValue::UNDEFINED)
    }

    /// Decode the archive comment under the supplied read policies.
    #[wasm_bindgen(js_name = readComment)]
    pub fn read_comment(
        &self,
        password: Option<Password>,
        settings: JsValue,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        self.archives[0]
            .comment_with_options(read_options(password.as_deref(), &settings)?)
            .map_err(js_error)
    }

    /// The comment attached to the member at `index`, or `undefined` when it has none.
    #[wasm_bindgen(js_name = readMemberComment)]
    pub fn read_member_comment(
        &self,
        index: usize,
        password: Option<Password>,
        settings: JsValue,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        let &(volume, index_in_volume) = self.places.get(index).ok_or_else(|| {
            binding_error(
                "ENTRY_NOT_FOUND",
                &format!("no such archive entry index: {index}"),
            )
        })?;
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        self.archives[volume]
            .member_comment_at_with_options(
                index_in_volume,
                read_options(password.as_deref(), &settings)?,
            )
            .map_err(js_error)
    }

    /// The raw target of the link at `index`; it is read from the headers and never followed.
    #[wasm_bindgen(js_name = readLink)]
    pub fn read_link(
        &self,
        index: usize,
        password: Option<Password>,
        settings: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let &(volume, index_in_volume) = self.places.get(index).ok_or_else(|| {
            binding_error(
                "ENTRY_NOT_FOUND",
                &format!("no such archive entry index: {index}"),
            )
        })?;
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        let options = read_options(password.as_deref(), &settings)?;
        let archive = &self.archives[volume];
        let member = archive
            .members()
            .nth(index_in_volume)
            .ok_or_else(|| binding_error("ENTRY_NOT_FOUND", "no such archive entry"))?;
        if member.is_legacy_unix_symlink() {
            return archive
                .legacy_symlink_target_at_with_options(index_in_volume, options)
                .map_err(js_error)?
                .ok_or_else(|| binding_error("INVALID_ARCHIVE", "link has no target"));
        }
        if !member.meta.is_redirection {
            return Err(binding_error(
                "INVALID_OPTION",
                &format!(
                    "{} is not a link",
                    String::from_utf8_lossy(&member.meta.name)
                ),
            ));
        }
        member
            .supported_redirection()
            .map(|link| link.target_name.clone())
            .ok_or_else(|| {
                binding_error(
                    "UNSUPPORTED_FEATURE",
                    "member is a kind of link rars cannot read",
                )
            })
    }

    /// Whether any member is encrypted.
    #[wasm_bindgen(getter, js_name = needsPassword)]
    pub fn needs_password(&self) -> bool {
        self.infos.iter().any(|info| info.encrypted)
    }

    /// Decodes the entries at `indices` (every entry when undefined) in one pass and hands
    /// each to `deliver(entry, bytes)` once the core has verified it. `entry` is
    /// `{ path, stored, isDirectory, mtime, mode, modeEarly }` for a file or directory, where
    /// `path` is the safe relative output path, `/`-separated, and `stored` the same before
    /// flattening. `mode` is the permission bits to give it, if any, and `modeEarly` whether
    /// a file can take them before it is published; otherwise they wait for the end, so
    /// later members can still read it.
    /// A link comes as `{ path, stored, link: { kind, target, directory } }` with no bytes,
    /// `kind` one of `symlink`, `junction`, `hardlink` or `copy`, or with `skipped: true`
    /// and its raw target when following it could leave the output directory.
    /// `skipSymlinks` leaves symlinks and junctions out undelivered; a hard link or copy
    /// to one fails as its own member.
    /// `readLink(path)` answers for that check: the target of the symbolic link already at
    /// `path` under the output directory, or undefined.
    ///
    /// Given `memberError`, each member that fails is reported to it and the call carries
    /// on; a reported member is not delivered, unless `keepBroken`, when it is delivered
    /// with what it was given and `broken: true`. One that failed on its password is not.
    #[wasm_bindgen(js_name = extractEach)]
    #[allow(clippy::too_many_arguments)] // JavaScript arguments.
    pub fn extract_each(
        &self,
        indices: Option<Vec<u32>>,
        password: Option<Password>,
        settings: JsValue,
        flatten: bool,
        posix: bool,
        skip_symlinks: bool,
        deliver: js_sys::Function,
        read_link: js_sys::Function,
        next_volume: Option<js_sys::Function>,
        progress: Option<js_sys::Function>,
        member_error: Option<js_sys::Function>,
        keep_broken: bool,
    ) -> Result<(), JsValue> {
        use rars_rs::ExtractedLink;
        use std::cell::RefCell;
        use std::collections::HashSet;
        use std::rc::Rc;
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        let mut options = read_options(password.as_deref(), &settings)?;
        let mut next_volume = next_volume;
        let volumes = self.resolve_call_encoding(&mut options, &mut next_volume)?;
        let report = member_errors::Reporting::start(
            member_error,
            options.legacy_name_encoding,
            keep_broken,
        );
        let options = report
            .as_ref()
            .map_or(options, |report| report.handling(options));
        // Selection by stored name: the core calls back once per member, for a file,
        // directory or link alike, and gives each its stored name.
        let selected: Option<HashSet<Vec<u8>>> = indices.map(|indices| {
            indices
                .into_iter()
                .filter_map(|index| self.infos.get(index as usize).map(|info| info.name.clone()))
                .collect()
        });
        let chosen = |name: &[u8]| selected.as_ref().is_none_or(|set| set.contains(name));
        // Later volumes still to arrive have members not listed yet.
        let total = (next_volume.is_none() && volumes.is_none()).then(|| {
            self.infos
                .iter()
                .filter(|info| chosen(&info.name) && !info.link && !info.directory)
                .map(|info| info.size as u64)
                .sum()
        });
        let archives = volumes.as_deref().unwrap_or(&self.archives);
        let family = archives[0].family();
        let encoding = options.legacy_name_encoding;
        let tree = JsTree(read_link);
        let raised: RefCell<Option<JsValue>> = RefCell::new(None);
        let skipped_symlinks: RefCell<HashSet<String>> = RefCell::default();
        // The entry, its bytes, and its stored name, which a failure report names.
        type Pending = (JsValue, Rc<RefCell<Vec<u8>>>, Vec<u8>);
        let pending: RefCell<Option<Pending>> = RefCell::new(None);
        let hand_over = |entry: &JsValue, bytes: &JsValue| -> rars_rs::Result<()> {
            if let Err(error) = deliver.call2(&JsValue::NULL, entry, bytes) {
                *raised.borrow_mut() = Some(error);
                return Err(rars_rs::Error::InvalidArgument("extraction output failed"));
            }
            Ok(())
        };
        // Hands over the entry before; the core has verified it, or reported it as failed,
        // by the time it opens the next.
        let flush = || -> rars_rs::Result<()> {
            // The members reported since the last entry was handed over.
            let failed = report
                .as_ref()
                .map(member_errors::Reporting::take_failed)
                .unwrap_or_default();
            let Some((entry, buffer, stored)) = pending.borrow_mut().take() else {
                return Ok(());
            };
            match failed.iter().rev().find(|(name, _)| *name == stored) {
                Some((_, false)) => return Ok(()),
                Some((_, true)) => set_error_field(&entry, "broken", &true.into()),
                None => {}
            }
            let bytes = js_sys::Uint8Array::from(buffer.borrow().as_slice());
            hand_over(&entry, &bytes)
        };
        let describe =
            |meta: &rars_rs::ExtractedEntryMeta| -> rars_rs::Result<(js_sys::Object, String, String)> {
                let (stored, path) = output_paths(meta, family, encoding, flatten, posix)?;
                let entry = js_sys::Object::new();
                set_error_field(&entry, "path", &path.as_str().into());
                set_error_field(&entry, "stored", &stored.as_str().into());
                set_error_field(&entry, "isDirectory", &meta.is_directory.into());
                if let Some(time) = meta.modified {
                    let seconds = time.unix_seconds() as f64 + f64::from(time.nanoseconds()) / 1e9;
                    set_error_field(&entry, "mtime", &seconds.into());
                }
                if let Some(mode) = rars_rs::output_modes::restored_mode(meta) {
                    set_error_field(&entry, "mode", &mode.into());
                    let early = !rars_rs::output_modes::waits_for_end(mode);
                    set_error_field(&entry, "modeEarly", &early.into());
                }
                Ok((entry, stored, path))
            };
        let result = progress::watching(progress, || {
            let count = progress::ReadCount::with_total("extracting", total);
            let open =
                |meta: &rars_rs::ExtractedEntryMeta| -> rars_rs::Result<Box<dyn std::io::Write>> {
                    flush()?;
                    if !chosen(&meta.name) {
                        return Ok(Box::new(std::io::sink()));
                    }
                    let (entry, _, _) = describe(meta)?;
                    let buffer = Rc::new(RefCell::new(Vec::new()));
                    *pending.borrow_mut() =
                        Some((entry.into(), Rc::clone(&buffer), meta.name.clone()));
                    Ok(count.counted(Box::new(SharedBytes(buffer))))
                };
            let link = |meta: &rars_rs::ExtractedEntryMeta, link: ExtractedLink<'_>| {
                flush()?;
                if !chosen(&meta.name) {
                    return Ok(());
                }
                let (entry, stored, path) = describe(meta)?;
                if skip_symlinks
                    && matches!(
                        link,
                        ExtractedLink::Symlink { .. } | ExtractedLink::Junction { .. }
                    )
                {
                    skipped_symlinks.borrow_mut().insert(stored);
                    return Ok(());
                }
                let target = rars_rs::output_links::link_target_in(
                    &tree,
                    std::path::Path::new(""),
                    std::path::Path::new(&path),
                    meta,
                    link,
                    family,
                    flatten,
                )?;
                // A kind this build doesn't know is skipped like an unsafe one.
                let kind = match link {
                    ExtractedLink::Symlink { directory, .. } => Some(("symlink", directory)),
                    ExtractedLink::Junction { .. } => Some(("junction", true)),
                    ExtractedLink::HardLink { .. } => Some(("hardlink", false)),
                    ExtractedLink::FileCopy { .. } => Some(("copy", false)),
                    _ => None,
                };
                let links_to_skipped = matches!(
                    link,
                    ExtractedLink::HardLink { .. } | ExtractedLink::FileCopy { .. }
                ) && target
                    .as_ref()
                    .is_some_and(|target| skipped_symlinks.borrow().contains(&slash_path(target)));
                if links_to_skipped {
                    return Err(rars_rs::Error::InvalidArgument(
                        "hard link or file copy target is a symbolic link left out",
                    ));
                }
                match target.zip(kind) {
                    Some((target, (kind, directory))) => {
                        let detail = js_sys::Object::new();
                        set_error_field(&detail, "kind", &kind.into());
                        set_error_field(&detail, "target", &slash_path(&target).into());
                        set_error_field(&detail, "directory", &directory.into());
                        set_error_field(&entry, "link", &detail);
                    }
                    None => {
                        set_error_field(&entry, "skipped", &true.into());
                        let raw = String::from_utf8_lossy(link.target()).into_owned();
                        set_error_field(&entry, "target", &raw.into());
                    }
                }
                hand_over(&entry, &JsValue::UNDEFINED)
            };
            let result = if options.salvage && next_volume.is_none() {
                // A salvaged set may end early: it is the volumes it was opened with, and
                // waits for no more. A volume on its own reads as a lone archive once its
                // split members are gone.
                Ok(if archives.len() == 1 {
                    archives[0].extract_with_links(options, open, link)
                } else {
                    rars_rs::extract_volumes_with_links(archives, options, open, link)
                }
                .and_then(|()| flush()))
            } else {
                with_later_volumes(archives, options, next_volume, |later| {
                    rars_rs::output_links::extract_arriving_with_links(
                        &archives[0],
                        later,
                        options,
                        open,
                        link,
                    )
                    .and_then(|()| flush())
                })
            };
            if matches!(result, Ok(Ok(()))) {
                count.finish();
            }
            result
        });
        if let Some(error) = raised.into_inner() {
            return Err(error);
        }
        if let Some(report) = report {
            report.finish()?;
        }
        result?.map_err(js_error)
    }

    /// Volume `index` of the set this first volume begins, named as RAR names it from
    /// `first_name`; undefined when the name can't take one.
    #[wasm_bindgen(js_name = volumeName)]
    pub fn volume_name(&self, first_name: &str, index: usize) -> Option<String> {
        self.archives[0]
            .volume_path(std::path::Path::new(first_name), index)
            .map(|name| name.to_string_lossy().into_owned())
    }

    /// Whether the (first) archive opened is one volume of a set.
    #[wasm_bindgen(getter, js_name = isVolume)]
    pub fn is_volume(&self) -> bool {
        self.archives[0].is_volume()
    }

    /// The (first) archive's place in its set, counting the first as 0; undefined when
    /// its headers don't record it.
    #[wasm_bindgen(getter, js_name = volumeIndex)]
    pub fn volume_index(&self) -> Option<f64> {
        self.archives[0].volume_index().map(|index| index as f64)
    }

    /// Whether the (first) archive starts its set; undefined when its headers can't tell.
    #[wasm_bindgen(getter, js_name = isFirstVolume)]
    pub fn is_first_volume(&self) -> Option<bool> {
        self.archives[0].is_first_volume()
    }

    /// How the set names its volume files: "part" or "old".
    #[wasm_bindgen(getter, js_name = volumeNaming)]
    pub fn volume_naming(&self) -> String {
        match self.archives[0].volume_naming() {
            rars_rs::volume_name::VolumeNaming::Part => "part",
            rars_rs::volume_name::VolumeNaming::Old => "old",
        }
        .to_string()
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

impl RarFile {
    /// Refuses a read of a member that a volume on its own holds only the start of:
    /// the rest is in the next volume, which wasn't given, so it is missing, as
    /// reading the set would report. Salvage has left such members out already.
    fn refuse_continued(&self, indices: &[usize]) -> Result<(), JsValue> {
        let [archive] = self.archives.as_slice() else {
            return Ok(());
        };
        let continued = archive.members().enumerate().any(|(index, member)| {
            member.meta.is_split_after && !member.meta.is_split_before && indices.contains(&index)
        });
        if continued {
            return Err(js_error(rars_rs::Error::InVolume {
                index: 1,
                source: Box::new(rars_rs::Error::MissingVolume),
            }));
        }
        Ok(())
    }

    fn resolve_call_encoding(
        &self,
        options: &mut rars_rs::ArchiveReadOptions<'_>,
        next_volume: &mut Option<js_sys::Function>,
    ) -> Result<Option<Vec<rars_rs::Archive>>, JsValue> {
        match options.legacy_name_encoding {
            Some(LegacyNameEncoding::Detect) if next_volume.is_some() => {
                let volumes = with_later_volumes(
                    &self.archives,
                    *options,
                    next_volume.take(),
                    |mut later| {
                        let mut volumes = vec![self.archives[0].clone()];
                        while !ends_volume_set(volumes.last().expect("the first volume is present"))
                        {
                            let Some(volume) = later.next() else { break };
                            volumes.push(volume?);
                        }
                        Ok(volumes)
                    },
                )?
                .map_err(js_error)?;
                options.legacy_name_encoding =
                    rars_rs::detect_volume_legacy_name_encoding(&volumes);
                Ok(Some(volumes))
            }
            Some(LegacyNameEncoding::Detect) => {
                options.legacy_name_encoding = if self.detect_encoding {
                    self.encoding
                } else {
                    rars_rs::detect_volume_legacy_name_encoding(&self.archives)
                };
                Ok(None)
            }
            None => {
                options.legacy_name_encoding = self.encoding;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// `test` once its options are settled.
    fn test_with(
        archives: &[rars_rs::Archive],
        options: rars_rs::ArchiveReadOptions<'_>,
        progress: Option<js_sys::Function>,
        next_volume: Option<js_sys::Function>,
    ) -> Result<(), JsValue> {
        // A volume on its own is the start of its set, so running out of it is a
        // missing volume, as extraction and Python have it. Salvage stops there.
        let lone_volume = !options.salvage && archives.len() == 1 && archives[0].is_volume();
        if next_volume.is_some() || lone_volume {
            return progress::watching(progress, || {
                let count = progress::ReadCount::with_total("testing", None);
                let result = with_later_volumes(archives, options, next_volume, |later| {
                    archives[0].extract_with_volumes(later, options, |_| {
                        Ok(count.counted(Box::new(std::io::sink())))
                    })
                });
                if matches!(result, Ok(Ok(()))) {
                    count.finish();
                }
                result
            })?
            .map_err(js_error);
        }
        if progress.is_some() {
            return progress::watching(progress, || test_counted(archives, options))
                .map_err(js_error);
        }
        if archives.len() == 1 {
            return archives[0].test_with_options(options).map_err(js_error);
        }
        rars_rs::extract_volumes_to_with_options(archives, options, |_| {
            Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>)
        })
        .map_err(js_error)
    }

    /// Reads `indices` with each member that fails reported to `member_error`, as
    /// Python's `on_member_error`. A reported member gets what was delivered for it
    /// under salvage, and nothing otherwise: what a decoder wrote before it found
    /// the failure isn't the member's own.
    fn read_reporting(
        &self,
        indices: &[usize],
        password: Option<Password>,
        settings: &JsValue,
        progress: Option<js_sys::Function>,
        member_error: Option<js_sys::Function>,
    ) -> Result<Vec<Option<Vec<u8>>>, JsValue> {
        // A set's reads count the outputs opened, which a member failing before its
        // output would upset.
        let later = |index: usize| match self.places.get(index) {
            Some(&(0, at)) => self.archives[0]
                .members()
                .nth(at)
                .is_none_or(|member| member.meta.is_split_after),
            _ => true,
        };
        if self.archives.len() > 1 && indices.iter().any(|&index| later(index)) {
            return Err(binding_error(
                "INVALID_OPTION",
                "onMemberError can't be combined with reading a member in a later volume; test() and extractAll() can carry on past those",
            ));
        }
        let password = password_bytes(password)?.or_else(|| self.password.clone());
        let mut options = read_options(password.as_deref(), settings)?;
        self.resolve_call_encoding(&mut options, &mut None)?;
        let salvage = options.salvage;
        let report =
            member_errors::Reporting::start(member_error, options.legacy_name_encoding, false);
        let options = report
            .as_ref()
            .map_or(options, |report| report.handling(options));
        let data = if progress.is_some() && self.archives.len() == 1 {
            progress::watching(progress, || {
                read_counted(&self.archives[0], indices, options)
            })
        } else if self.archives.len() == 1 {
            self.archives[0].read_members_at_with_options(indices, options)
        } else {
            rars_rs::read_volume_members_at_with_options(&self.archives, indices, options)
        };
        let failed = report
            .as_ref()
            .map(member_errors::Reporting::take_failed)
            .unwrap_or_default();
        if let Some(report) = report {
            report.finish()?;
        }
        let mut data = data.map_err(js_error)?;
        for (bytes, &index) in data.iter_mut().zip(indices) {
            let Some(info) = self.infos.get(index) else {
                continue;
            };
            if failed.iter().any(|(name, _)| *name == info.name) {
                let bytes = bytes.get_or_insert_with(Vec::new);
                if !salvage {
                    bytes.clear();
                }
            }
        }
        Ok(data)
    }
}

/// Tests the archive or set a member at a time, counting each as it is verified.
fn test_counted(
    archives: &[rars_rs::Archive],
    options: rars_rs::ArchiveReadOptions<'_>,
) -> rars_rs::Result<()> {
    // The callback names regular entries and directories in archive order, skipping
    // redirections, a member at a time; each counts as it is verified.
    let members: Vec<rars_rs::ArchiveMember> = if archives.len() == 1 {
        archives[0].members().collect()
    } else {
        rars_rs::volume_members(archives)?
    };
    let mut sizes = members
        .iter()
        .filter(|member| !member.meta.is_redirection)
        .map(|member| (!member.meta.is_directory).then_some(member.meta.unpacked_size))
        .collect::<Vec<_>>()
        .into_iter();
    let total = members
        .iter()
        .filter(|member| !member.meta.is_redirection && !member.meta.is_directory)
        .map(|member| member.meta.unpacked_size)
        .sum();
    let count = progress::ReadCount::new("testing", total);
    let mut previous = 0;
    let mut tested = |_: &rars_rs::ExtractedEntryMeta| {
        count.add(std::mem::take(&mut previous));
        previous = sizes.next().flatten().unwrap_or(0);
        Ok(())
    };
    if archives.len() == 1 {
        archives[0].test_with_options_and_callback(options, &mut tested)?;
    } else {
        rars_rs::test_volumes_with_options_and_callback(archives, options, &mut tested)?;
    }
    count.finish();
    Ok(())
}

/// Collects one member's bytes for `extractEach`.
struct SharedBytes(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

impl std::io::Write for SharedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

thread_local! {
    /// The caller's next-volume function for the call in progress, and what it threw.
    /// It is kept here, not in the volume iterator, because the core reads later volumes
    /// through an iterator that must be `Send`, which a JavaScript function isn't; bare
    /// WebAssembly has one thread, so the call that set it is the one that reads it.
    static NEXT_VOLUME: std::cell::RefCell<Option<js_sys::Function>> =
        const { std::cell::RefCell::new(None) };
    static VOLUME_RAISED: std::cell::RefCell<Option<JsValue>> =
        const { std::cell::RefCell::new(None) };
}

/// A set's later volumes, pulled from the caller's function as the core reaches them.
struct Arriving<'a> {
    session: rars_rs::read_session::ReadSession<'a>,
}

impl Iterator for Arriving<'_> {
    type Item = rars_rs::Result<rars_rs::Archive>;

    fn next(&mut self) -> Option<Self::Item> {
        let answer = NEXT_VOLUME.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|next| next.call0(&JsValue::NULL))
        })?;
        match answer {
            Ok(volume) if volume.is_undefined() || volume.is_null() => None,
            Ok(volume) => match volume.dyn_into::<js_sys::Uint8Array>() {
                Ok(bytes) => Some(self.session.read_owned(bytes.to_vec())),
                Err(_) => Some(Err(rars_rs::Error::InvalidArgument(
                    "a volume must be a Uint8Array",
                ))),
            },
            Err(error) => {
                VOLUME_RAISED.with(|slot| *slot.borrow_mut() = Some(error));
                Some(Err(rars_rs::Error::InvalidArgument(
                    "volumes raised an exception",
                )))
            }
        }
    }
}

fn ends_volume_set(archive: &rars_rs::Archive) -> bool {
    if !archive.is_volume() {
        return true;
    }
    match archive {
        rars_rs::Archive::Rar15To40(archive) => archive.blocks.iter().any(
            |block| matches!(block, rars_rs::rar15_40::Block::End(end) if !end.has_next_volume()),
        ),
        rars_rs::Archive::Rar50Plus(archive) => archive.blocks.iter().any(
            |block| matches!(block, rars_rs::rar50::Block::End(end) if !end.has_next_volume()),
        ),
        _ => false,
    }
}

/// Runs `run` with the set's later volumes: those opened with `archives`, or, given
/// `next`, each pulled from it as needed until it returns undefined. What `next` threw
/// is raised in place of the error it caused.
fn with_later_volumes<T>(
    archives: &[rars_rs::Archive],
    options: rars_rs::ArchiveReadOptions<'_>,
    next: Option<js_sys::Function>,
    run: impl FnOnce(
        Box<dyn Iterator<Item = rars_rs::Result<rars_rs::Archive>> + Send + '_>,
    ) -> rars_rs::Result<T>,
) -> Result<rars_rs::Result<T>, JsValue> {
    let Some(next) = next else {
        return Ok(run(Box::new(archives[1..].iter().cloned().map(Ok))));
    };
    let session = rars_rs::read_session::ReadSession::continuing(&archives[0], options);
    NEXT_VOLUME.with(|slot| *slot.borrow_mut() = Some(next));
    let result = run(Box::new(Arriving { session }));
    NEXT_VOLUME.with(|slot| *slot.borrow_mut() = None);
    match VOLUME_RAISED.with(|slot| slot.borrow_mut().take()) {
        Some(error) => Err(error),
        None => Ok(result),
    }
}

/// The output directory as the Node worker sees it, for the link containment check.
struct JsTree(js_sys::Function);

impl rars_rs::output_links::OutputTree for JsTree {
    fn read_link(&self, path: &std::path::Path) -> std::io::Result<Option<std::path::PathBuf>> {
        let answer = self
            .0
            .call1(&JsValue::NULL, &slash_path(path).into())
            .map_err(|_| std::io::Error::other("reading a link in the output directory failed"))?;
        Ok(answer.as_string().map(std::path::PathBuf::from))
    }
}

/// A relative path as `/`-separated text, the form the worker joins onto its directory.
fn slash_path(path: &std::path::Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// The member's stored and output paths, `/`-separated, by the rules Python's extraction
/// uses: the name is validated, RAR 5 names are made native, older ones decoded, and the
/// path must stay inside the output directory. They differ only when flattening.
fn output_paths(
    meta: &rars_rs::ExtractedEntryMeta,
    family: rars_rs::ArchiveFamily,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    flatten: bool,
    posix: bool,
) -> rars_rs::Result<(String, String)> {
    rars_rs::validate_entry_name(meta.name.clone())?;
    let rar50 = family == rars_rs::ArchiveFamily::Rar50Plus;
    let name = if !rar50 {
        rars_rs::filename::decoded_name(&meta.name, meta.name_is_unicode, encoding)?.into_owned()
    } else if posix && meta.attr_source == rars_rs::AttrSource::Unix {
        rars_rs::filename::decode_rar50(&meta.name).into_owned()
    } else {
        rars_rs::output_links::rar50_native_name(&meta.name, false)
    };
    let stored = rars_rs::filename::relative_path(&name, !rar50)?;
    if stored.components().next().is_none() {
        return Err(rars_rs::Error::UnsafePath("empty output path"));
    }
    let relative = if flatten {
        rars_rs::output_staging::flat_relative(&stored)
    } else {
        stored.clone()
    };
    Ok((slash_path(&stored), slash_path(&relative)))
}

/// Selected members decoded in one pass, counted as they decode. Unselected solid
/// predecessors decode into a sink and aren't counted.
fn read_counted(
    archive: &rars_rs::Archive,
    indices: &[usize],
    options: rars_rs::ArchiveReadOptions<'_>,
) -> rars_rs::Result<Vec<Option<Vec<u8>>>> {
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;
    struct Shared(Rc<RefCell<Vec<u8>>>);
    impl std::io::Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let selected: HashSet<usize> = indices.iter().copied().collect();
    let readable =
        |member: &rars_rs::ArchiveMember| !member.meta.is_directory && !member.meta.is_redirection;
    let members: Vec<_> = archive.members().collect();
    let total = members
        .iter()
        .enumerate()
        .filter(|(index, member)| selected.contains(index) && readable(member))
        .map(|(_, member)| member.meta.unpacked_size)
        .sum();
    let last = members
        .iter()
        .enumerate()
        .filter(|(index, member)| selected.contains(index) && readable(member))
        .map(|(index, _)| index)
        .next_back();
    let count = progress::ReadCount::new("reading", total);
    let mut buffers: HashMap<usize, Rc<RefCell<Vec<u8>>>> = HashMap::new();
    if let Some(last) = last {
        let solid = archive.is_solid();
        let mut current = 0;
        archive.extract_with_control(options, |member| {
            let index = current;
            current += 1;
            if index > last {
                return Ok(rars_rs::ExtractionDecision::Stop);
            }
            if !readable(member) {
                return Ok(rars_rs::ExtractionDecision::Skip);
            }
            if selected.contains(&index) {
                let buffer = Rc::new(RefCell::new(Vec::new()));
                buffers.insert(index, Rc::clone(&buffer));
                return Ok(rars_rs::ExtractionDecision::Extract(
                    count.counted(Box::new(Shared(buffer))),
                ));
            }
            Ok(if solid {
                rars_rs::ExtractionDecision::Extract(Box::new(std::io::sink()))
            } else {
                rars_rs::ExtractionDecision::Skip
            })
        })?;
    }
    count.finish();
    Ok(indices
        .iter()
        .map(|index| buffers.get(index).map(|buffer| buffer.borrow().clone()))
        .collect())
}

fn info_with_encoding(
    member: rars_rs::ArchiveMember,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
) -> rars_rs::Result<RarInfo> {
    let display_name = String::from_utf8_lossy(&member.decoded_name(encoding)?).into_owned();
    let mut info = info_from_member(member);
    info.display_name = display_name;
    Ok(info)
}

fn info_from_member(member: rars_rs::ArchiveMember) -> RarInfo {
    let solid = member.is_solid();
    // RAR 1.3 checksums are 16 bit and RAR 5 may carry a BLAKE2sp hash instead
    // of a CRC, so the one field JavaScript sees is the CRC-32 where the format
    // has one and null everywhere else.
    let crc = match member.detail {
        rars_rs::ArchiveMemberDetail::Rar13 { .. } => None,
        rars_rs::ArchiveMemberDetail::Rar15To40 { crc32, .. } => Some(crc32),
        rars_rs::ArchiveMemberDetail::Rar50Plus { crc32, .. } => crc32,
        _ => None,
    };
    // A malformed extended time record still leaves the main header's time.
    let times = member.times().unwrap_or_else(|_| rars_rs::FileTimes {
        modified: member.meta.modification_time(),
        ..Default::default()
    });
    let link = member.meta.is_redirection || member.is_legacy_unix_symlink();
    let seconds = |time: Option<rars_rs::Timestamp>| {
        time.map(|time| time.unix_seconds() as f64 + f64::from(time.nanoseconds()) / 1e9)
    };
    RarInfo {
        mtime: seconds(times.modified),
        atime: seconds(times.accessed),
        birthtime: seconds(times.created),
        display_name: String::from_utf8_lossy(&member.meta.name).into_owned(),
        name: member.meta.name,
        size: member.meta.unpacked_size as f64,
        packed_size: member.meta.packed_size as f64,
        crc,
        host_os: member.meta.host_os.map(|os| os as f64),
        file_attr: member.meta.file_attr as f64,
        encrypted: member.meta.is_encrypted,
        stored: member.meta.is_stored,
        solid,
        directory: member.meta.is_directory,
        split_before: member.meta.is_split_before,
        split_after: member.meta.is_split_after,
        volume_index: 0,
        link,
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
  /** Store a BLAKE2sp hash of each member beside its CRC32. RAR 5 and later. */
  blake2sp?: boolean;
  /** Archive comment. */
  comment?: Uint8Array | string;
  /** Add a recovery record covering this percentage of the archive. */
  recoveryPercent?: number;
  /** Split into volumes of at most this many bytes; use `toVolumes()`. */
  volumeSize?: number;
  /** Hard managed writer capacity, excluding inputs and runtime/allocator overhead. */
  maxMemoryBytes?: number | bigint;
}

export interface RarEntryOptions {
  /** Modification time in Unix seconds; a fraction is kept where the format can. */
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

impl RarBuilder {
    /// Queues one member with its `mtime`, `mode`, `atime`, `birthtime` and `comment` options.
    fn add_entry(
        &mut self,
        name: Vec<u8>,
        data: Vec<u8>,
        options: &JsValue,
    ) -> Result<(), JsValue> {
        self.inner
            .add_bytes(
                name,
                data,
                opt_timestamp(options, "mtime")?,
                opt_number(options, "mode")?.map(|n| n as u32),
            )
            .map_err(js_error)?;
        self.finish_entry(options)
    }

    /// The options every kind of member takes once it is queued: its comment, and access and
    /// creation times, which only RAR 5 keeps.
    fn finish_entry(&mut self, options: &JsValue) -> Result<(), JsValue> {
        let id = self.inner.member_ids().last().expect("member just added");
        let comment = opt_bytes(options, "comment")?;
        if comment.is_some() {
            self.inner
                .set_file_comment_by_id(id, comment)
                .map_err(js_error)?;
        }
        let accessed = opt_timestamp(options, "atime")?;
        let created = opt_timestamp(options, "birthtime")?;
        if accessed.is_some() || created.is_some() {
            self.inner
                .set_times_by_id(
                    id,
                    rars_rs::FileTimes {
                        modified: None,
                        created,
                        accessed,
                    },
                )
                .map_err(js_error)?;
        }
        Ok(())
    }
}

/// Assembles an archive from members added one at a time.
#[wasm_bindgen]
pub struct RarBuilder {
    inner: Builder,
    resources: rars_rs::WriterResources,
    rewrite: Option<Rewrite>,
}

/// An archive being written again: where its members' payloads come from.
struct Rewrite {
    archives: Vec<rars_rs::Archive>,
    password: Option<Vec<u8>>,
    settings: JsValue,
    /// Payloads still to stage, by builder member id.
    payloads: std::collections::HashMap<usize, rars_rs::RewritePayload>,
    max_staged_bytes: Option<u64>,
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
        let mut resources = rars_rs::WriterResources::default();
        if let Some(limit) = read_limit(&options, "maxMemoryBytes")? {
            resources = resources.with_max_memory_bytes(limit);
        }
        Ok(Self {
            resources,
            rewrite: None,
            inner: Builder::new(format)
                .compression_level(Some(compression))
                .store(opt_bool(&options, "store")?)
                .solid(opt_bool(&options, "solid")?)
                .password(opt_bytes(&options, "password")?)
                .header_encryption(opt_bool(&options, "encryptHeaders")?)
                .blake2sp(opt_bool(&options, "blake2sp")?)
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
        self.add_entry(name.as_bytes().to_vec(), data, &options)
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
        self.add_entry(name, data, &options)
    }

    /// Queue an explicit, possibly empty directory.
    #[wasm_bindgen(js_name = addDirectory)]
    pub fn add_directory(
        &mut self,
        name: Vec<u8>,
        options: Option<RarEntryOptions>,
    ) -> Result<(), JsValue> {
        let options: JsValue = options.map_or(JsValue::UNDEFINED, Into::into);
        self.inner
            .add_directory(
                name,
                opt_timestamp(&options, "mtime")?,
                opt_number(&options, "mode")?.map(|n| n as u32),
            )
            .map_err(js_error)?;
        self.finish_entry(&options)
    }

    /// Queue a Unix symbolic link to `target`, which is stored as given and never followed.
    #[wasm_bindgen(js_name = addSymlink)]
    pub fn add_symlink(
        &mut self,
        name: Vec<u8>,
        target: Vec<u8>,
        options: Option<RarEntryOptions>,
    ) -> Result<(), JsValue> {
        let options: JsValue = options.map_or(JsValue::UNDEFINED, Into::into);
        self.inner
            .add_unix_symlink(
                name,
                target,
                opt_bool(&options, "targetIsDirectory")?,
                opt_timestamp(&options, "mtime")?,
                opt_number(&options, "mode")?.map(|n| n as u32),
            )
            .map_err(js_error)?;
        self.finish_entry(&options)
    }

    /// A builder holding every member of `archive`, which may be a volume set,
    /// ready to edit and write again. `preserve` keeps the source's format,
    /// settings and encryption, and refuses an archive whose settings can't be
    /// kept; otherwise it writes RAR 5 at level 3. Payloads are decoded and
    /// verified when the archive is written, held in memory, up to
    /// `maxStagedBytes` when given.
    #[wasm_bindgen(js_name = fromArchive)]
    pub fn from_archive(
        archive: &RarFile,
        preserve: bool,
        password: Option<Password>,
        settings: JsValue,
        max_staged_bytes: Option<f64>,
    ) -> Result<RarBuilder, JsValue> {
        let password = password_bytes(password)?.or_else(|| archive.password.clone());
        let mut options = read_options(password.as_deref(), &settings)?;
        archive.resolve_call_encoding(&mut options, &mut None)?;
        let (first, later) = archive
            .archives
            .split_first()
            .expect("a file has a first volume");
        if preserve {
            let issues = first.rewrite_preservation_issues();
            if !issues.is_empty() {
                let way_through = if first.is_volume() {
                    "use preserve: false to rewrite the volume set as one RAR5 archive"
                } else {
                    "use preserve: false for explicit RAR5 conversion"
                };
                return Err(binding_error(
                    "UNSUPPORTED_FEATURE",
                    &format!(
                        "cannot preserve archive: {}; {way_through} (archive settings may be lost)",
                        issues.join("; ")
                    ),
                ));
            }
        }
        let (inner, payloads) = first
            .rewrite_builder(later, options, preserve)
            .map_err(js_error)?;
        Ok(Self {
            inner,
            resources: rars_rs::WriterResources::default(),
            rewrite: Some(Rewrite {
                archives: archive.archives.clone(),
                password,
                settings,
                payloads: payloads
                    .into_iter()
                    .map(|payload| (payload.id, payload))
                    .collect(),
                max_staged_bytes: max_staged_bytes.map(|limit| limit as u64),
            }),
        })
    }

    /// Each queued member's id, in the order they will be written. Ids stay
    /// with a member through renames.
    #[wasm_bindgen(js_name = memberIds)]
    pub fn member_ids(&self) -> Vec<u32> {
        self.inner.member_ids().map(|id| id as u32).collect()
    }

    /// The queued member names as stored, in the order they will be written.
    #[wasm_bindgen(js_name = rawNames, unchecked_return_type = "Uint8Array[]")]
    pub fn raw_names(&self) -> js_sys::Array {
        self.inner.names().map(js_sys::Uint8Array::from).collect()
    }

    /// Drop the member with id `id`.
    #[wasm_bindgen(js_name = removeId)]
    pub fn remove_id(&mut self, id: u32) -> Result<(), JsValue> {
        self.inner.remove_by_id(id as usize).map_err(js_error)?;
        if let Some(rewrite) = &mut self.rewrite {
            rewrite.payloads.remove(&(id as usize));
        }
        Ok(())
    }

    /// Rename the member with id `id` to the exact bytes `name`.
    #[wasm_bindgen(js_name = renameId)]
    pub fn rename_id(&mut self, id: u32, name: Vec<u8>) -> Result<(), JsValue> {
        self.inner.rename_by_id(id as usize, name).map_err(js_error)
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
    pub fn to_bytes(
        &self,
        progress: Option<js_sys::Function>,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        progress::watching(progress, || {
            self.with_payloads(|builder| self.to_bytes_reporting(builder))
        })
    }

    /// Encode the archive as a volume set, one `Uint8Array` per volume.
    /// Requires `volumeSize`.
    #[wasm_bindgen(js_name = toVolumes, unchecked_return_type = "Uint8Array[]")]
    pub fn to_volumes(&self, progress: Option<js_sys::Function>) -> Result<js_sys::Array, JsValue> {
        progress::watching(progress, || {
            self.with_payloads(|builder| self.to_volumes_reporting(builder))
        })
    }
}

impl RarBuilder {
    fn reporter() -> Option<&'static dyn rars_rs::WriteProgress> {
        progress::active().then_some(&progress::WriteReporter as &dyn rars_rs::WriteProgress)
    }

    /// Runs `write` on the builder, with a rewrite's payloads staged into a copy of it.
    fn with_payloads<T>(
        &self,
        write: impl FnOnce(&Builder) -> Result<T, JsValue>,
    ) -> Result<T, JsValue> {
        let Some(rewrite) = &self.rewrite else {
            return write(&self.inner);
        };
        let payloads: Vec<_> = rewrite.payloads.values().copied().collect();
        let limit = match rewrite.max_staged_bytes {
            Some(limit) => limit,
            None => rars_rs::rewrite_payload_bytes(&payloads).map_err(js_error)?,
        };
        let options = read_options(rewrite.password.as_deref(), &rewrite.settings)?;
        let mut builder = self.inner.clone();
        let raised = std::cell::RefCell::new(None);
        let (first, later) = rewrite
            .archives
            .split_first()
            .expect("a set has a first volume");
        let staged = first.with_rewrite_payloads(
            later,
            &payloads,
            options,
            &rars_rs::RewriteStaging {
                directory: std::path::PathBuf::new(),
                max_staged_bytes: limit,
            },
            progress::active().then(|| {
                std::sync::Arc::new(progress::WriteReporter)
                    as std::sync::Arc<dyn rars_rs::WriteProgress>
            }),
            &mut builder,
            |builder| {
                write(builder).map_err(|error| {
                    *raised.borrow_mut() = Some(error);
                    rars_rs::Error::WriterFailure("rewrite output failed")
                })
            },
        );
        if let Some(error) = raised.into_inner() {
            return Err(error);
        }
        staged.map_err(js_error)
    }

    fn to_bytes_reporting(&self, builder: &Builder) -> Result<js_sys::Uint8Array, JsValue> {
        if self.resources.max_memory_bytes().is_none()
            && builder.format().family() != rars_rs::ArchiveFamily::Rar50Plus
        {
            let bytes = builder
                .to_bytes_with_progress(Self::reporter())
                .map_err(js_error)?;
            return Ok(js_sys::Uint8Array::from(bytes.as_slice()));
        }
        let output = builder
            .to_output(&self.resources, Self::reporter())
            .map_err(js_error)?;
        output
            .copy_with(|bytes| js_sys::Uint8Array::from(bytes))
            .map_err(js_error)
    }

    fn to_volumes_reporting(&self, builder: &Builder) -> Result<js_sys::Array, JsValue> {
        if self.resources.max_memory_bytes().is_none()
            && builder.format().family() != rars_rs::ArchiveFamily::Rar50Plus
        {
            return Ok(builder
                .build_volumes(Self::reporter())
                .map_err(js_error)?
                .iter()
                .map(|volume| js_sys::Uint8Array::from(volume.as_slice()))
                .collect());
        }
        let volumes = builder
            .to_volume_output(&self.resources, Self::reporter())
            .map_err(js_error)?;
        volumes
            .copy_with(|volumes| {
                volumes
                    .iter()
                    .map(|volume| js_sys::Uint8Array::from(volume.as_bytes()))
                    .collect()
            })
            .map_err(js_error)
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

/// Unix seconds, possibly fractional, as a timestamp; refuses what isn't one.
fn opt_timestamp(options: &JsValue, key: &str) -> Result<Option<rars_rs::Timestamp>, JsValue> {
    let Some(seconds) = opt_number(options, key)? else {
        return Ok(None);
    };
    let nanoseconds = (seconds * 1e9).round();
    if !nanoseconds.is_finite() || nanoseconds.abs() >= 1e36 {
        return Err(binding_error(
            "INVALID_OPTION",
            &format!("{key} must be Unix seconds"),
        ));
    }
    rars_rs::Timestamp::from_unix_nanoseconds(nanoseconds as i128)
        .map(Some)
        .ok_or_else(|| binding_error("INVALID_OPTION", &format!("{key} is out of range")))
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

fn read_limit(settings: &JsValue, key: &str) -> Result<Option<u64>, JsValue> {
    let value = opt_value(settings, key)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let invalid = || {
        binding_error(
            "INVALID_OPTION",
            &format!("{key} must be a nonnegative safe integer or a bigint through 2**64 - 1"),
        )
    };
    if let Some(number) = value.as_f64() {
        if number.is_finite()
            && number.fract() == 0.0
            && (0.0..=9_007_199_254_740_991.0).contains(&number)
        {
            return Ok(Some(number as u64));
        }
        return Err(invalid());
    }
    let bigint = value.dyn_into::<js_sys::BigInt>().map_err(|_| invalid())?;
    u64::try_from(bigint).map(Some).map_err(|_| invalid())
}

fn read_options<'a>(
    password: Option<&'a [u8]>,
    settings: &JsValue,
) -> Result<rars_rs::ArchiveReadOptions<'a>, JsValue> {
    let mut options = rars_rs::ArchiveReadOptions::with_optional_password(password);
    let encoding = opt_value(settings, "legacyNameEncoding")?;
    if !encoding.is_null() && !encoding.is_undefined() {
        options.legacy_name_encoding = Some(
            encoding
                .as_string()
                .ok_or_else(|| {
                    binding_error("INVALID_OPTION", "legacyNameEncoding must be a string")
                })?
                .parse()
                .map_err(js_error)?,
        );
    }
    options.max_header_count = read_limit(settings, "maxHeaderCount")?;
    options.max_header_bytes = read_limit(settings, "maxHeaderBytes")?;
    options.max_member_output_bytes = read_limit(settings, "maxMemberOutputBytes")?;
    options.max_total_output_bytes = read_limit(settings, "maxTotalOutputBytes")?;
    options.max_reader_workspace_bytes = read_limit(settings, "maxReaderWorkspaceBytes")?;
    options.rar50_dictionary_size_limit = read_limit(settings, "maxRar50DictionaryBytes")?;
    options.rar50_buffered_decode_limit = read_limit(settings, "maxRar50BufferedMemberBytes")?;
    options.allow_rar3_vm_programs = opt_bool(settings, "allowRar3VmPrograms")?;
    options.salvage = opt_bool(settings, "salvage")?;
    Ok(options)
}

// This export exists only in the test engine built by coverage-wasm.py.
// It exercises private error conversion in a real JavaScript host without
// requiring browser-only types to work in native Rust unit tests.
#[cfg(test)]
mod host_tests {
    #[test]
    fn duplicate_name_metadata_selects_the_last_entry() {
        let mut builder = rars_rs::Builder::new(rars_rs::ArchiveVersion::Rar50)
            .store(true)
            .allow_duplicate_names(true);
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            builder
                .add_bytes(b"same".to_vec(), payload.to_vec(), None, None)
                .unwrap();
        }
        let archive = rars_rs::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let infos: Vec<_> = archive.members().map(super::info_from_member).collect();
        let file = super::RarFile {
            places: (0..infos.len()).map(|index| (0, index)).collect(),
            infos,
            encoding: None,
            detect_encoding: false,
            archives: vec![archive],
            password: None,
            incomplete: Vec::new(),
        };
        assert_eq!(file.get_info("same").unwrap().size, 6.0);
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
                .map(|member| super::info_from_member(member).solid)
                .collect();
            assert_eq!(flags, [false, true], "{version:?}");
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen::prelude::wasm_bindgen(js_name = __testErrorRecords)]
    pub fn error_records() -> js_sys::Array {
        use rars_rs::Error;
        let limit = 9_007_199_254_740_993;
        let required = u64::MAX;
        let used = 17;
        let errors = [
            Error::Codec(rars_rs::codec::Error::WorkspaceLimitExceeded(Box::new(
                rars_rs::codec::WorkspaceLimitError {
                    limit,
                    required,
                    used,
                },
            ))),
            Error::MemoryLimitExceeded {
                limit,
                required,
                dictionary_size: used,
            },
            Error::WriterPreparationLimitExceeded {
                limit,
                required,
                used,
            },
            Error::WriterPreparedHeaderLimitExceeded {
                limit,
                required,
                used,
            },
            Error::WriterSpoolMemoryLimitExceeded {
                limit,
                required,
                used,
            },
            Error::WriterSpoolLimitExceeded {
                limit,
                required,
                used,
            },
            Error::TotalOutputLimitExceeded {
                limit,
                required,
                used,
            },
            Error::MemberOutputLimitExceeded { limit, required },
            Error::HeaderBytesLimitExceeded { limit, required },
            Error::Rar50DictionaryLimitExceeded { limit, required },
            Error::Rar50BufferedDecodeLimitExceeded { limit, required },
            Error::HeaderCountLimitExceeded { limit, required },
            Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            Error::Rar5Recovery(rars_rs::recovery::rar5::Error::Io(
                std::io::ErrorKind::BrokenPipe,
            )),
        ];
        errors
            .into_iter()
            .map(|error| {
                let wrapped = Error::InVolume {
                    index: 2,
                    source: Box::new(
                        error
                            .at_entry(vec![0xff, 0, 1], "reading")
                            .at_archive_offset(usize::MAX),
                    ),
                };
                super::js_error(wrapped)
            })
            .collect()
    }
}
