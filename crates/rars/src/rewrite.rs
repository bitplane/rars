//! Conservative preflight for the currently supported rewrite model.

use crate::{Archive, ArchiveMemberMeta, AttrSource};
use std::collections::HashSet;

impl Archive {
    /// Properties the current RAR5 conversion builder cannot promise to preserve.
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
        for (index, member) in self.members().enumerate() {
            let meta = member.meta;
            let label = format!("member {index} ({:?})", String::from_utf8_lossy(&meta.name));
            if !names.insert(meta.name.clone()) {
                issues.push(format!("{label}: duplicate name"));
            }
            if crate::builder::validate_entry_name(meta.name.clone()).is_err() {
                issues.push(format!("{label}: unsupported output name"));
            }
            if meta.is_encrypted {
                issues.push(format!("{label}: data encryption"));
            }
            if meta.is_split_before || meta.is_split_after {
                issues.push(format!("{label}: split-volume layout"));
            }
            if meta.attr_source() == AttrSource::Unknown {
                issues.push(format!("{label}: unknown host attributes"));
            }
            if special_entry(&meta) {
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
                if main.encrypted_headers {
                    issues.push("header encryption".into());
                }
                if main.is_solid() {
                    issues.push("solid archive".into());
                }
                if main.is_volume() || main.volume_number.is_some() {
                    issues.push("volume layout".into());
                }
                if main.has_recovery_record() {
                    issues.push("recovery records".into());
                }
                if main.is_locked() {
                    issues.push("archive lock flag".into());
                }
                if !main.rewrite_metadata_complete
                    || main.archive_flags & !0x1f != 0
                    || main.block.flags & !1 != 0
                    || main.block.data_size.unwrap_or(0) != 0
                {
                    issues.push("main header metadata, extra records or unknown flags".into());
                }
                let mut index = 0;
                let mut comment_seen = false;
                for block in &archive.blocks {
                    match block {
                        Block::File(file) => {
                            if !file.rewrite_metadata_complete
                                || file.file_flags & !7 != 0
                                || file.block.flags & !0x1b != 0
                                || file.compression_info & !0x7fff != 0
                            {
                                issues.push(format!(
                                    "member {index}: unsupported, duplicate or incomplete metadata"
                                ));
                            }
                            if file.compression_info & 0x3f != 0 {
                                issues.push(format!(
                                    "member {index}: source format requires conversion to RAR5"
                                ));
                            }
                            if file.compression_info & 0x40 != 0 {
                                issues.push(format!("member {index}: solid dependency"));
                            }
                            index += 1;
                        }
                        Block::Service(service) => {
                            // Only the single archive comment's content is carried
                            // forward. Attached comments, streams, ACLs and recovery
                            // services need their own preservation adapters.
                            if index != 0
                                || comment_seen
                                || service.name != b"CMT"
                                || service.encrypted
                                || !service.rewrite_metadata_complete
                                || service.modification_time().is_some()
                                || service.file_flags & !4 != 0
                                || service.block.flags & !3 != 0
                                || service.attributes != 0
                                || service.host_os != 0
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
