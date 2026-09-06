//! Conservative preflight for the currently supported rewrite model.

use crate::{Archive, ArchiveMemberMeta, AttrSource};
use std::collections::HashSet;

impl Archive {
    /// Decodes comments in member order with one metadata traversal. Like
    /// `member_comment_at`, this does not retain resource limits from parsing.
    pub fn member_comments(&self, password: Option<&[u8]>) -> crate::Result<Vec<Option<Vec<u8>>>> {
        match self {
            Archive::Rar13(a) => a.entries.iter().map(|entry| entry.file_comment()).collect(),
            Archive::Rar15To40(a) => a.files().map(|file| file.file_comment()).collect(),
            Archive::Rar50Plus(a) => {
                let mut comments: Vec<Option<&crate::rar50::FileHeader>> = Vec::new();
                for block in &a.blocks {
                    match block {
                        crate::rar50::Block::File(_) => comments.push(None),
                        crate::rar50::Block::Service(service) if service.name == b"CMT" => {
                            if let Some(comment) = comments.last_mut() {
                                if comment.replace(service).is_some() {
                                    return Err(crate::Error::InvalidHeader(
                                        "duplicate member comment records",
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                comments
                    .into_iter()
                    .map(|comment| {
                        comment
                            .map(|service| {
                                let mut data = Vec::new();
                                service.write_to(a, password, &mut data)?;
                                Ok(data)
                            })
                            .transpose()
                    })
                    .collect()
            }
        }
    }

    /// Decodes a member comment by original archive index, including directories.
    /// Missing comments return `None`; an invalid index returns `EntryNotFound`.
    /// Duplicate RAR5 CMT records are refused rather than silently dropping one.
    /// This helper does not retain parsing/extraction resource policies.
    pub fn member_comment_at(
        &self,
        index: usize,
        password: Option<&[u8]>,
    ) -> crate::Result<Option<Vec<u8>>> {
        match self {
            Archive::Rar13(a) => a
                .entries
                .get(index)
                .ok_or(crate::Error::EntryNotFound)?
                .file_comment(),
            Archive::Rar15To40(a) => a
                .files()
                .nth(index)
                .ok_or(crate::Error::EntryNotFound)?
                .file_comment(),
            Archive::Rar50Plus(a) => {
                let mut current = None;
                let mut next = 0;
                let mut found = false;
                let mut comment = None;
                for block in &a.blocks {
                    match block {
                        crate::rar50::Block::File(_) => {
                            if found {
                                break;
                            }
                            current = Some(next);
                            next += 1;
                            found = current == Some(index);
                        }
                        crate::rar50::Block::Service(service)
                            if current == Some(index) && service.name == b"CMT" =>
                        {
                            if comment.is_some() {
                                return Err(crate::Error::InvalidHeader(
                                    "duplicate member comment records",
                                ));
                            }
                            comment = Some(service);
                        }
                        _ => {}
                    }
                }
                if !found {
                    return Err(crate::Error::EntryNotFound);
                }
                comment
                    .map(|service| {
                        let mut data = Vec::new();
                        service.write_to(a, password, &mut data)?;
                        Ok(data)
                    })
                    .transpose()
            }
        }
    }

    /// Configure a builder with supported source format, solid and encryption settings.
    /// Member data/comment passwords are retained separately when entries are copied.
    pub fn preserving_builder(&self, password: Option<&[u8]>) -> crate::Result<crate::Builder> {
        let issues = self.rewrite_preservation_issues();
        if !issues.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "archive has unsupported preservation settings",
            ));
        }
        let Archive::Rar50Plus(archive) = self else {
            return Err(crate::Error::InvalidArgument(
                "legacy preservation is unsupported",
            ));
        };
        let version = if archive
            .files()
            .any(|file| file.compression_info & 0x3f == 1)
        {
            crate::ArchiveVersion::Rar70
        } else {
            crate::ArchiveVersion::Rar50
        };
        let encrypted = archive.main.encrypted_headers
            || archive.blocks.iter().any(|block| match block {
                crate::rar50::Block::File(file) | crate::rar50::Block::Service(file) => {
                    file.encrypted
                }
                _ => false,
            });
        let password = if encrypted {
            Some(
                password
                    .filter(|password| !password.is_empty())
                    .ok_or(crate::Error::NeedPassword)?
                    .to_vec(),
            )
        } else {
            None
        };
        let archive_comment_encrypted = archive.blocks.iter().take_while(|block| !matches!(block, crate::rar50::Block::File(_)))
            .any(|block| matches!(block, crate::rar50::Block::Service(service) if service.name == b"CMT" && service.encrypted));
        let mut quick_open = false;
        let mut recovery_percent = None;
        for block in &archive.blocks {
            if let crate::rar50::Block::Service(service) = block {
                if service.name == b"QO" || service.name == b"RR" {
                    service.write_to(archive, password.as_deref(), &mut std::io::sink())?;
                    quick_open |= service.name == b"QO";
                    if service.name == b"RR" {
                        recovery_percent = service.recovery_record()?.map(|record| record.percent);
                    }
                }
            }
        }
        let metadata = archive.main.extras.iter().find_map(|extra| match extra {
            crate::rar50::MainExtraRecord::ArchiveMetadata(metadata) => Some(metadata.clone()),
            _ => None,
        });
        crate::Builder::new(version)
            .compression_level(Some(3))
            .solid(archive.main.is_solid())
            .password(password.clone())
            .header_encryption(archive.main.encrypted_headers)
            .archive_comment_password(if archive_comment_encrypted {
                password
            } else {
                None
            })
            .recovery_percent(recovery_percent)
            .archive_metadata(metadata, archive.main.is_locked(), quick_open)
    }

    /// Whether each member's comment payload is encrypted, in archive member order.
    pub fn member_comment_encryption(&self) -> Vec<bool> {
        let Archive::Rar50Plus(archive) = self else {
            return self.members().map(|_| false).collect();
        };
        let mut encrypted = Vec::new();
        for block in &archive.blocks {
            match block {
                crate::rar50::Block::File(_) => encrypted.push(false),
                crate::rar50::Block::Service(service) if service.name == b"CMT" => {
                    if let Some(last) = encrypted.last_mut() {
                        *last = service.encrypted;
                    }
                }
                _ => {}
            }
        }
        encrypted
    }

    /// Properties the current rewrite adapters cannot promise to preserve.
    ///
    /// An empty list certifies only the supported metadata subset, not payload
    /// integrity or byte-identical output. Legacy formats are conservatively
    /// rejected until their settings and metadata have preservation adapters.
    /// Parsed unknown/incomplete RAR5 extras remain visible to this check even
    /// though ordinary extraction tolerates them. Source files must stay stable.
    pub fn rewrite_preservation_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.sfx_offset() != 0 {
            issues.push("SFX executable prefix".into());
        }
        let mut names = HashSet::new();
        let mut link_targets = std::collections::HashMap::new();
        for (index, member) in self.members().enumerate() {
            let meta = &member.meta;
            let label = format!("member {index} ({:?})", String::from_utf8_lossy(&meta.name));
            let link = member.supported_redirection();
            if let Some(link) = link.filter(|link| link.redirection_type >= 4) {
                if link_targets.get(&link.target_name) != Some(&meta.unpacked_size) {
                    issues.push(format!(
                        "{label}: missing, forward or inconsistent redirection target"
                    ));
                }
            }
            if !meta.is_directory
                && (!meta.is_redirection || link.is_some_and(|link| link.redirection_type >= 4))
            {
                link_targets.insert(meta.name.clone(), meta.unpacked_size);
            }
            if !names.insert(meta.name.clone()) {
                issues.push(format!("{label}: duplicate name"));
            }
            if crate::builder::validate_entry_name(meta.name.clone()).is_err() {
                issues.push(format!("{label}: unsupported output name"));
            }

            if meta.is_split_before || meta.is_split_after {
                issues.push(format!("{label}: split-volume layout"));
            }
            if meta.attr_source() == AttrSource::Unknown {
                issues.push(format!("{label}: unknown host attributes"));
            }
            if special_entry(meta) && member.supported_redirection().is_none() {
                issues.push(format!("{label}: special entry type or directory contents"));
            }
            if (meta.attr_source() == AttrSource::Unix
                && (meta.file_attr & !0o177777 != 0
                    || (meta.is_directory && meta.file_attr & 0o170000 == 0o100000)))
                || (meta.attr_source() == AttrSource::Dos
                    && (meta.file_attr & 0x10 != 0) != meta.is_directory)
            {
                issues.push(format!("{label}: unsupported or inconsistent attributes"));
            }
        }
        match self {
            Archive::Rar13(archive) => {
                issues
                    .push("legacy source format and metadata require preservation adapters".into());
                if archive.main.is_solid() {
                    issues.push("solid archive".into());
                }
                if archive.main.is_volume() {
                    issues.push("volume layout".into());
                }
            }
            Archive::Rar15To40(archive) => {
                issues
                    .push("legacy source format and metadata require preservation adapters".into());
                if archive.main.is_solid() {
                    issues.push("solid archive".into());
                }
                if archive.main.is_volume() {
                    issues.push("volume layout".into());
                }
                if archive.main.has_encrypted_headers() {
                    issues.push("header encryption".into());
                }
                if archive.main.has_recovery_record() {
                    issues.push("recovery records".into());
                }
            }
            Archive::Rar50Plus(archive) => {
                use crate::rar50::Block;
                let main = &archive.main;

                if main.is_volume() || main.volume_number.is_some() {
                    issues.push("volume layout".into());
                }

                if !main.rewrite_metadata_complete
                    || main.archive_flags & !0x1f != 0
                    || main.block.flags & !1 != 0
                    || main.block.data_size.unwrap_or(0) != 0
                {
                    issues.push("main header metadata, extra records or unknown flags".into());
                }
                if main.encrypted_headers && !archive.files().any(|file| file.encrypted) {
                    issues.push("header encryption without encrypted members".into());
                }
                let mut derived_services = HashSet::new();
                for extra in &main.extras {
                    if let crate::rar50::MainExtraRecord::ArchiveMetadata(metadata) = extra {
                        if crate::rar50::write::headers::retained_archive_metadata(metadata)
                            .is_err()
                        {
                            issues.push("unsupported archive metadata".into());
                        }
                    }
                }
                let mut index = 0;
                let mut comment_seen = false;
                for block in &archive.blocks {
                    match block {
                        Block::File(file) => {
                            comment_seen = false;
                            if !file.rewrite_metadata_complete
                                || file.file_flags & !7 != 0
                                || file.block.flags & !0x1b != 0
                                || file.compression_info
                                    & if file.compression_info & 0x3f == 0 {
                                        !0x7fff
                                    } else {
                                        !0x1fffff
                                    }
                                    != 0
                            {
                                issues.push(format!(
                                    "member {index}: unsupported, duplicate or incomplete metadata"
                                ));
                            }
                            if file.compression_info & 0x3f > 1 {
                                issues.push(format!(
                                    "member {index}: source format requires an unsupported compression algorithm"
                                ));
                            }
                            if file.compression_info & 0x40 != 0 && !main.is_solid() {
                                issues.push(format!(
                                    "member {index}: solid dependency without a solid archive"
                                ));
                            }
                            index += 1;
                        }
                        Block::Service(service) => {
                            if service.name == b"QO" || service.name == b"RR" {
                                if !derived_services.insert(service.name.clone())
                                    || !service.rewrite_metadata_complete
                                    || service.encrypted
                                    || service.modification_time().is_some()
                                    || service.file_times.is_some()
                                    || service.file_flags & !4 != 0
                                    || service.block.flags & !3 != 0
                                    || service.attributes != 0
                                    || service.host_os != 0
                                    || service.compression_info != 0
                                    || (service.name == b"RR"
                                        && !service.recovery_record().ok().flatten().is_some_and(
                                            |record| (1..=100).contains(&record.percent),
                                        ))
                                {
                                    issues.push(format!(
                                        "unsupported derived service {:?}",
                                        String::from_utf8_lossy(&service.name)
                                    ));
                                }
                                continue;
                            }
                            // One CMT per owner (archive or preceding member).
                            // Other services and ambiguous duplicates remain rejected.
                            if comment_seen
                                || service.name != b"CMT"
                                || !service.rewrite_metadata_complete
                                || service.modification_time().is_some()
                                || service.file_times.is_some()
                                || service.file_flags & !4 != 0
                                || service.block.flags & !3 != 0
                                || service.attributes != 0
                                || service.host_os != 0
                                || service.compression_info & !0x7fff != 0
                                || service.compression_info & 0x7f != 0
                            {
                                issues.push(format!(
                                    "service record {:?}",
                                    String::from_utf8_lossy(&service.name)
                                ));
                            }
                            comment_seen = true;
                        }
                        Block::End(end) => {
                            // Canonical end headers contain only type, block flags
                            // and end flags. Reject extra fields instead of silently
                            // certifying metadata this reader does not expose.
                            if end.flags != 0 || end.block.flags != 0 || end.block.header_size != 3
                            {
                                issues.push(
                                    "end header flags, volume continuation or extra metadata"
                                        .into(),
                                );
                            }
                        }
                        Block::Unknown(_) => issues.push("unknown archive block".into()),
                    }
                }
                if main.has_recovery_record() != derived_services.contains(b"RR".as_slice()) {
                    issues.push("recovery flag and service disagree".into());
                }
                if main.encrypted_headers && derived_services.contains(b"QO".as_slice()) {
                    issues.push("quick-open index with encrypted headers".into());
                }
                for extra in &main.extras {
                    if let crate::rar50::MainExtraRecord::Locator(locator) = extra {
                        if locator.quick_open_offset.is_some_and(|offset| offset != 0)
                            && !derived_services.contains(b"QO".as_slice())
                            || locator
                                .recovery_record_offset
                                .is_some_and(|offset| offset != 0)
                                && !derived_services.contains(b"RR".as_slice())
                        {
                            issues.push("locator refers to a missing service".into());
                        }
                    }
                }
            }
        }
        issues
    }
}

pub(crate) fn special_entry(meta: &ArchiveMemberMeta) -> bool {
    let kind = meta.file_attr & 0o170000;
    meta.is_redirection
        || (meta.is_directory && meta.unpacked_size != 0)
        || (meta.attr_source() == AttrSource::Unix
            && !matches!(kind, 0 | 0o100000)
            && !(meta.is_directory && kind == 0o040000))
        || (meta.attr_source() == AttrSource::Dos && meta.file_attr & 0x400 != 0)
}

impl crate::ArchiveMember {
    /// Complete supported file times. Legacy DOS fields use the established local-zone policy.
    pub fn file_times(&self) -> crate::Result<Option<crate::FileTimes>> {
        match &self.detail {
            crate::ArchiveMemberDetail::Rar50Plus { file_times, .. } => Ok(*file_times),
            crate::ArchiveMemberDetail::Rar15To40 { extended_times, .. } => {
                crate::FileTimes::legacy(extended_times, self.meta.file_time)
            }
            _ => Ok(None),
        }
    }

    /// A redirection whose known kind and header metadata can be retained.
    pub fn supported_redirection(&self) -> Option<&crate::rar50::FileRedirection> {
        let crate::ArchiveMemberDetail::Rar50Plus {
            redirection: Some(link),
            ..
        } = &self.detail
        else {
            return None;
        };
        (link.supports_header(
            self.meta.host_os?,
            self.meta.file_attr,
            self.meta.is_directory,
        ) && (link.redirection_type != 1 || self.unix_symlink().is_some())
            && self.meta.packed_size == 0)
            .then_some(link)
    }

    /// Supported RAR5 Unix symbolic link metadata. No filesystem lookup occurs.
    pub fn unix_symlink(&self) -> Option<&crate::rar50::FileRedirection> {
        let crate::ArchiveMemberDetail::Rar50Plus {
            redirection: Some(link),
            ..
        } = &self.detail
        else {
            return None;
        };
        (link.is_supported_unix_symlink()
            && self.meta.host_os == Some(1)
            && self.meta.file_attr & !0o7777 == 0o120000
            && !self.meta.is_directory
            && (self.meta.unpacked_size == 0
                || self.meta.unpacked_size
                    == crate::filename::decode_rar50(&link.target_name).len() as u64)
            && self.meta.packed_size == 0)
            .then_some(link)
    }
}
