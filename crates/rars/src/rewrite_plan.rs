//! A builder that writes an existing archive again, for bindings to edit before writing.

use crate::{
    filename, Archive, ArchiveFamily, ArchiveMemberDetail, ArchiveReadOptions, ArchiveVersion,
    AttrSource, Builder, EntrySource, Error, Result, RewriteStaging,
};
use std::sync::Arc;

/// A member of a rewrite builder whose payload is still to be read from the
/// source: its builder id, its place among the source set's members, and its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RewritePayload {
    pub id: usize,
    pub index: usize,
    pub size: u64,
}

impl Archive {
    /// A builder holding every member of this archive, or of the volume set it
    /// begins with `later_volumes`, with names, times, attributes, comments and
    /// links carried over, and the payloads it still needs.
    ///
    /// `preserve` keeps the source's format and settings, as
    /// [`Archive::preserving_builder`] reads them, and each member's encryption;
    /// callers check [`Archive::rewrite_preservation_issues`] first. Otherwise
    /// the builder writes RAR 5 at level 3 and older names are decoded with
    /// `options.legacy_name_encoding`. Payloads are placeholders until
    /// [`Archive::with_rewrite_payloads`] stages them; removing a member from
    /// the builder means dropping its payload from the list too.
    pub fn rewrite_builder(
        &self,
        later_volumes: &[Archive],
        options: ArchiveReadOptions<'_>,
        preserve: bool,
    ) -> Result<(Builder, Vec<RewritePayload>)> {
        let password = options.password;
        let mut read = std::iter::once(self)
            .chain(later_volumes)
            .map(|volume| {
                Ok((
                    volume.member_comments_with_options(options)?,
                    volume.legacy_symlink_targets_with_options(options)?,
                    volume.member_comment_encryption(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let members = self.volume_set_members(later_volumes)?;
        let inner = if preserve {
            self.preserving_builder(password)?
        } else {
            Builder::new(ArchiveVersion::Rar50).compression_level(Some(3))
        };
        let format = inner.format();
        let legacy_preservation = preserve && format.family() != ArchiveFamily::Rar50Plus;
        let mut builder = inner
            .comment(self.comment_with_options(options)?)
            .allow_duplicate_names(true);
        let mut payloads = Vec::new();
        for (member_index, set_member) in members.into_iter().enumerate() {
            let (comments, links, encrypted) = &mut read[set_member.volume_index];
            let at = set_member.index_in_volume;
            let comment = comments[at].take();
            let legacy_link = links[at].take();
            let comment_encrypted = encrypted[at];
            let member = set_member.member;
            let legacy_unicode_name = match &member.detail {
                ArchiveMemberDetail::Rar15To40 { unicode_name, .. } if legacy_preservation => {
                    unicode_name.clone()
                }
                _ => None,
            };
            // Within one family the stored times copy exactly; across families
            // they go through Unix time.
            let (copied_times, converted_times) = if member.meta.family == format.family() {
                (Some(member.clone()), None)
            } else {
                (None, Some(member.times()?))
            };
            let converted_name = (!legacy_preservation
                && member.meta.family != ArchiveFamily::Rar50Plus)
                .then(|| {
                    member
                        .decoded_name(options.legacy_name_encoding)
                        .map(std::borrow::Cow::into_owned)
                })
                .transpose()?;
            let link = member.supported_redirection().cloned();
            let retained_link = link.as_ref().map(|_| member.clone());
            let info = member.meta;
            // A builder mode is Unix metadata, not generic archive attributes.
            // Reuse extraction's host rules: e.g. legacy host 1 is DOS, but
            // RAR5 host 1 is Unix. DOS 0x20 must not become Unix mode 0040.
            let attr_source = info.attr_source();
            let output_name = match converted_name {
                Some(name) if attr_source == AttrSource::Unix => {
                    crate::builder::validate_entry_name(name.clone())?;
                    filename::encode_rar50(&name).into_owned()
                }
                Some(name) => name,
                None => info.name.clone(),
            };
            let unix_type = info.file_attr & 0o170000;
            let unsupported_type = attr_source == AttrSource::Unix
                && !matches!(unix_type, 0 | 0o100000)
                && !(info.is_directory && unix_type == 0o040000);
            let reparse_point = attr_source == AttrSource::Dos && info.file_attr & 0x400 != 0;
            if link.is_none()
                && legacy_link.is_none()
                && (info.is_redirection
                    || unsupported_type
                    || reparse_point
                    || (info.is_directory && info.unpacked_size != 0))
            {
                return Err(Error::UnrewritableEntry { name: info.name });
            }
            let mode = (attr_source == AttrSource::Unix).then_some(if legacy_preservation {
                info.file_attr as u32
            } else {
                (info.file_attr & 0o7777) as u32
            });
            if let Some(member) = retained_link {
                builder.add_archive_redirection(&member)?;
            } else if let Some(target) = legacy_link {
                let target = if legacy_preservation {
                    target
                } else {
                    filename::encode_rar50(&target).into_owned()
                };
                builder.add_unix_symlink(output_name, target, false, None, mode)?;
            } else if info.is_directory {
                builder.add_directory(output_name, None, mode)?;
            } else {
                // Replaced once the payloads are staged in one verified traversal;
                // members are never decoded one by one.
                let source = EntrySource::from_opener(info.unpacked_size, || {
                    Err(Error::InvalidArgument("rewrite payload was not staged"))
                });
                builder.add_source(output_name, source, None, mode)?;
                payloads.push(RewritePayload {
                    id: builder
                        .member_ids()
                        .last()
                        .expect("a member was just added"),
                    index: member_index,
                    size: info.unpacked_size,
                });
            }
            let id = builder
                .member_ids()
                .last()
                .expect("a member was just added");
            builder.set_file_comment_by_id(id, comment)?;
            if let Some(source) = &copied_times {
                builder.copy_times_by_id(id, source)?;
            }
            if let Some(times) = converted_times {
                builder.set_times_by_id(id, times)?;
            }
            if preserve {
                let password = password.map(<[u8]>::to_vec);
                builder.set_entry_encryption_by_id(
                    id,
                    password.clone().filter(|_| info.is_encrypted),
                    password.filter(|_| comment_encrypted),
                )?;
            }
            if let Some(raw) = legacy_unicode_name {
                builder.set_legacy_unicode_name_by_id(id, raw)?;
            }
            if attr_source == AttrSource::Dos {
                builder.set_dos_attributes_by_id(id, info.file_attr)?;
            }
        }
        Ok((builder.allow_duplicate_names(false), payloads))
    }

    /// Stages `payloads` in one verified pass over the source, puts each into
    /// `builder` as its member's source, and hands the builder to `consume`
    /// for one write. The staged sources go when this returns.
    #[allow(clippy::too_many_arguments)] // The staging call's own, plus the builder.
    pub fn with_rewrite_payloads<T>(
        &self,
        later_volumes: &[Archive],
        payloads: &[RewritePayload],
        options: ArchiveReadOptions<'_>,
        staging: &RewriteStaging,
        progress: Option<Arc<dyn crate::WriteProgress>>,
        builder: &mut Builder,
        consume: impl FnOnce(&Builder) -> Result<T>,
    ) -> Result<T> {
        let mut payloads = payloads.to_vec();
        payloads.sort_unstable_by_key(|payload| payload.index);
        let indices: Vec<_> = payloads.iter().map(|payload| payload.index).collect();
        self.with_rewrite_sources_from_volumes(
            later_volumes,
            &indices,
            options,
            staging,
            progress,
            |sources| {
                for (payload, source) in payloads.iter().zip(sources) {
                    builder.set_source_by_id(payload.id, source)?;
                }
                consume(builder)
            },
        )
    }
}

/// The sum of `payloads`' sizes, the staging limit that holds all of them at once.
pub fn rewrite_payload_bytes(payloads: &[RewritePayload]) -> Result<u64> {
    payloads.iter().try_fold(0u64, |sum, payload| {
        sum.checked_add(payload.size)
            .ok_or(Error::RewriteStagingLimitExceeded {
                limit: u64::MAX,
                required: u64::MAX,
            })
    })
}
