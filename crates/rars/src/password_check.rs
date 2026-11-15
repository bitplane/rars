use crate::detect::{find_archive_start, SFX_SCAN_LIMIT};
use crate::error::{Error, Result};
use crate::key_cache::KeyCache;
use crate::version::ArchiveFamily;
use crate::{rar15_40, rar50, Archive, ArchiveReadOptions, ArchiveReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Room for RAR 1.5-4's marker, largest main header and largest first encrypted header.
const HEADER_PREFIX_LEN: usize = 7 + 65535 + 8 + 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerdict {
    Correct,
    Wrong,
    Undetermined,
}

/// Read once, so candidates are checked in memory and the winner's open reuses their RAR 5 keys.
pub struct PasswordProbe {
    source: Source,
    evidence: Evidence,
    archive: Option<Archive>,
    key_cache: Arc<KeyCache>,
}

enum Source {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

enum Evidence {
    Unencrypted,
    Undetermined,
    Rar50Files(Vec<rar50::PasswordCheckValue>),
    Rar50Headers {
        prefix: Vec<u8>,
        at_volume_end: bool,
        sfx_offset: usize,
        encryption: rar50::HeaderEncryption,
    },
    Rar15To40Headers {
        prefix: Vec<u8>,
        offset: usize,
    },
}

impl PasswordProbe {
    pub fn read_path(path: impl AsRef<Path>, options: ArchiveReadOptions<'_>) -> Result<Self> {
        options.check_cancelled()?;
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        let signature =
            crate::read_archive_signature(&mut file, len.min(SFX_SCAN_LIMIT as u64) as usize)?
                .ok_or(Error::UnsupportedSignature)?;
        let available = (len - signature.offset as u64).min(HEADER_PREFIX_LEN as u64) as usize;
        let prefix = crate::io_util::read_exact_at(&mut file, signature.offset, available)?;
        let at_volume_end = signature.offset as u64 + available as u64 == len;
        Self::read(
            Source::Path(path.to_path_buf()),
            signature.family,
            (prefix, at_volume_end),
            signature.offset,
            options,
        )
    }

    pub fn read_owned(input: Vec<u8>, options: ArchiveReadOptions<'_>) -> Result<Self> {
        options.check_cancelled()?;
        let signature =
            find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        let end = input.len().min(signature.offset + HEADER_PREFIX_LEN);
        let prefix = (input[signature.offset..end].to_vec(), end == input.len());
        Self::read(
            Source::Bytes(input),
            signature.family,
            prefix,
            signature.offset,
            options,
        )
    }

    fn read(
        source: Source,
        family: ArchiveFamily,
        (prefix, at_volume_end): (Vec<u8>, bool),
        sfx_offset: usize,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        let header_evidence = match family {
            ArchiveFamily::Rar50Plus => rar50::header_encryption(&prefix, sfx_offset, options)?
                .map(|encryption| Evidence::Rar50Headers {
                    prefix,
                    at_volume_end,
                    sfx_offset,
                    encryption,
                }),
            ArchiveFamily::Rar15To40 => rar15_40::first_encrypted_header_offset(&prefix)?
                .map(|offset| Evidence::Rar15To40Headers { prefix, offset }),
            ArchiveFamily::Rar13 => None,
        };
        let mut probe = Self {
            source,
            evidence: Evidence::Unencrypted,
            archive: None,
            key_cache: Arc::default(),
        };
        match header_evidence {
            Some(evidence) => probe.evidence = evidence,
            None => {
                let archive = probe.parse(options)?;
                probe.evidence = file_evidence(&archive);
                probe.archive = Some(archive);
            }
        }
        Ok(probe)
    }

    pub fn needs_password(&self) -> bool {
        !matches!(self.evidence, Evidence::Unencrypted)
    }

    /// Its member list needs the password too.
    pub fn headers_encrypted(&self) -> bool {
        matches!(
            self.evidence,
            Evidence::Rar50Headers { .. } | Evidence::Rar15To40Headers { .. }
        )
    }

    pub fn check(
        &self,
        password: &[u8],
        options: ArchiveReadOptions<'_>,
    ) -> Result<PasswordVerdict> {
        options.check_cancelled()?;
        let correct = match &self.evidence {
            Evidence::Unencrypted | Evidence::Undetermined => {
                return Ok(PasswordVerdict::Undetermined)
            }
            Evidence::Rar50Files(check_values) => {
                for check_value in check_values {
                    if !check_value.matches(password, &self.key_cache)? {
                        return Ok(PasswordVerdict::Wrong);
                    }
                }
                true
            }
            Evidence::Rar50Headers {
                prefix,
                at_volume_end,
                sfx_offset,
                encryption,
            } => rar50::header_password_matches(
                prefix,
                *at_volume_end,
                *sfx_offset,
                encryption,
                password,
                &self.key_cache,
                options,
            )?,
            Evidence::Rar15To40Headers { prefix, offset } => rar15_40::header_password_matches(
                prefix,
                *offset,
                password,
                &self.key_cache,
                options,
            )?,
        };
        Ok(if correct {
            PasswordVerdict::Correct
        } else {
            PasswordVerdict::Wrong
        })
    }

    /// Opens the volume with `password`, reusing the keys checking derived.
    pub fn open(&self, password: &[u8], options: ArchiveReadOptions<'_>) -> Result<Archive> {
        self.parse(ArchiveReadOptions {
            password: Some(password),
            ..options
        })
    }

    /// None when the headers are encrypted, since it was read without a password.
    pub fn into_archive(self) -> Option<Archive> {
        self.archive
    }

    fn parse(&self, options: ArchiveReadOptions<'_>) -> Result<Archive> {
        let key_cache = Arc::clone(&self.key_cache);
        match &self.source {
            Source::Path(path) => ArchiveReader::read_path_cached(path, options, key_cache),
            Source::Bytes(bytes) => {
                ArchiveReader::read_owned_cached(bytes.clone(), options, key_cache)
            }
        }
    }
}

fn file_evidence(archive: &Archive) -> Evidence {
    if !archive.members().any(|member| member.meta.is_encrypted) {
        return Evidence::Unencrypted;
    }
    let Archive::Rar50Plus(archive) = archive else {
        return Evidence::Undetermined;
    };
    let mut check_values = Vec::new();
    for encryption in archive.files().filter_map(|file| file.encryption.as_ref()) {
        if let Some(check_value) = rar50::PasswordCheckValue::of_file(encryption) {
            if !check_values.contains(&check_value) {
                check_values.push(check_value);
            }
        }
    }
    if check_values.is_empty() {
        Evidence::Undetermined
    } else {
        Evidence::Rar50Files(check_values)
    }
}
