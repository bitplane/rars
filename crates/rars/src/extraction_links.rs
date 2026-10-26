//! Common link extraction without changing the byte-oriented extraction APIs.
use crate::codec::workspace::{Budget, Buffer};
use crate::{Archive, ArchiveReadOptions, Error, ExtractedEntryMeta, Result};
use std::io::Write;

/// A link to recreate. Targets are borrowed only for the callback.
///
/// Legacy symbolic-link targets are native Unix bytes, not legacy-encoded
/// member names. RAR5 targets retain their wire encoding. No filesystem path
/// resolution or link creation is performed by the library. Legacy records do
/// not carry a target-directory hint, so their `Symlink::directory` is false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractedLink<'a> {
    Symlink { target: &'a [u8], directory: bool },
    Junction { target: &'a [u8] },
    HardLink { target: &'a [u8] },
    FileCopy { target: &'a [u8] },
}

impl<'a> ExtractedLink<'a> {
    pub fn target(self) -> &'a [u8] {
        match self {
            Self::Symlink { target, .. }
            | Self::Junction { target }
            | Self::HardLink { target }
            | Self::FileCopy { target } => target,
        }
    }

    fn rar50(link: &'a crate::rar50::FileRedirection) -> Result<Self> {
        let target = link.target_name.as_slice();
        Ok(match link.redirection_type {
            1 | 2 => Self::Symlink {
                target,
                directory: link.flags & 1 != 0,
            },
            3 => Self::Junction { target },
            4 => Self::HardLink { target },
            5 => Self::FileCopy { target },
            _ => {
                return Err(Error::UnsupportedFeature {
                    version: crate::ArchiveVersion::Rar50,
                    feature: "RAR 5 unsupported file redirection type",
                })
            }
        })
    }
}

impl Archive {
    /// Extract files and directories to writers, and report links separately.
    ///
    /// Legacy link payloads are decoded and integrity-checked before `link` is
    /// called, with the operation's output and workspace limits. Targets larger
    /// than 64 KiB are refused before decoding. Only Unix-host legacy records
    /// become links; BeOS mode bits retain their ordinary-data interpretation.
    /// Link targets are not path-checked:
    /// the caller chooses its filesystem confinement and overwrite policies.
    ///
    /// Independent legacy members may be decoded in parallel; callbacks arrive
    /// in archive order. Solid archives and total-output-limited operations use
    /// sequential decoding. RAR5 uses its streaming extraction path. Earlier
    /// callback side effects are retained on failure; ordinary file writers have
    /// the staging requirements of [`Archive::extract_to`]. Metadata retains raw
    /// archive names, including in errors. Existing byte-oriented APIs continue
    /// to expose legacy link payloads as data and skip RAR5 redirections.
    pub fn extract_with_links<F, L>(
        &self,
        options: ArchiveReadOptions<'_>,
        mut open: F,
        mut link: L,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
        L: FnMut(&ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
    {
        options.check_cancelled()?;
        match self {
            Self::Rar13(archive) => {
                archive.extract_to_with_options(options, |meta| open(&crate::rar13_meta(meta)))
            }
            Self::Rar15To40(archive) => archive.extract_parallel_with_links(
                options,
                |meta| open(&crate::rar15_40_meta(meta)),
                Some(&mut |meta, target| {
                    link(
                        &crate::rar15_40_meta(meta),
                        ExtractedLink::Symlink {
                            target,
                            directory: false,
                        },
                    )
                }),
            ),
            Self::Rar50Plus(archive) => archive.extract_to_with_redirections(
                options,
                |meta| open(&crate::rar50_meta(meta)),
                |meta, redirection| {
                    ExtractedLink::rar50(redirection)
                        .and_then(|kind| link(&crate::rar50_meta(meta), kind))
                        .map_err(|error| link_error(error, &meta.name))
                },
            ),
        }
    }
}

/// Extract a volume set with the link and staging semantics of
/// [`Archive::extract_with_links`]. Split legacy targets are verified after
/// reassembly, and reported once at the final fragment.
pub fn extract_volumes_with_links<F, L>(
    archives: &[Archive],
    options: ArchiveReadOptions<'_>,
    mut open: F,
    mut link: L,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    L: FnMut(&ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
{
    options.check_cancelled()?;
    let first = archives
        .first()
        .ok_or(Error::InvalidHeader("volume set is empty"))?;
    match first.family() {
        crate::ArchiveFamily::Rar13 => {
            crate::extract_volumes_to_with_options(archives, options, open)
        }
        crate::ArchiveFamily::Rar15To40 => crate::rar15_40::extract_volumes_with_links(
            &crate::rar15_40_volumes(archives)?,
            options,
            |meta| open(&crate::rar15_40_meta(meta)),
            Some(&mut |meta, target| {
                link(
                    &crate::rar15_40_meta(meta),
                    ExtractedLink::Symlink {
                        target,
                        directory: false,
                    },
                )
            }),
        ),
        crate::ArchiveFamily::Rar50Plus => crate::rar50::extract_volumes_to_with_redirections(
            &crate::rar50_volumes(archives)?,
            options,
            |meta| open(&crate::rar50_meta(meta)),
            |meta, redirection| {
                ExtractedLink::rar50(redirection)
                    .and_then(|kind| link(&crate::rar50_meta(meta), kind))
                    .map_err(|error| link_error(error, &meta.name))
            },
        ),
    }
}

pub(crate) type LegacyLink<'a> =
    dyn FnMut(&crate::rar15_40::ExtractedEntryMeta, &[u8]) -> Result<()> + 'a;

// Only HOST_UNIX records have the legacy symbolic-link interpretation. BeOS
// uses Unix mode bits for permissions but UnRAR treats its payloads as files.
pub(crate) fn is_legacy_symlink(host: u64, attr: u64, directory: bool) -> bool {
    host == 3 && attr & !0o7777 == 0o120000 && !directory
}

pub(crate) fn validate_legacy_target(target: &[u8], name: &[u8]) -> Result<()> {
    if target.is_empty() || target.contains(&0) {
        return Err(
            Error::InvalidArgument("legacy symbolic link target is empty or contains NUL")
                .at_entry(name.to_vec(), "reading link target"),
        );
    }
    Ok(())
}

pub(crate) fn check_legacy_size(
    meta: &crate::rar15_40::ExtractedEntryMeta,
    size: u64,
    links: bool,
) -> Result<()> {
    if links && legacy_meta_is_link(meta) && size > 64 * 1024 {
        return Err(
            Error::InvalidHeader("legacy symbolic link target exceeds 64 KiB")
                .at_entry(meta.name.clone(), "reading link target"),
        );
    }
    Ok(())
}

fn legacy_meta_is_link(meta: &crate::rar15_40::ExtractedEntryMeta) -> bool {
    is_legacy_symlink(
        u64::from(meta.host_os),
        u64::from(meta.attr),
        meta.is_directory,
    )
}

pub(crate) fn emit_legacy_link(
    meta: &crate::rar15_40::ExtractedEntryMeta,
    target: &[u8],
    links: &mut Option<&mut LegacyLink<'_>>,
    control: &crate::read_control::ReadControl,
) -> Result<bool> {
    if !legacy_meta_is_link(meta) {
        return Ok(false);
    }
    let Some(link) = links.as_mut() else {
        return Ok(false);
    };
    (|| {
        control.check()?;
        validate_legacy_target(target, &meta.name)?;
        link(meta, target)?;
        control.check()
    })()
    .map_err(|error| link_error(error, &meta.name))?;
    Ok(true)
}

fn link_error(error: Error, name: &[u8]) -> Error {
    if error.entry_context().is_none() {
        error.at_entry(name.to_vec(), "extracting link")
    } else {
        error
    }
}

// Decode through the same budget/session exactly once. Target storage remains
// charged to the decoder's allowance until after the verified link callback.
pub(crate) fn legacy_output<B: Budget>(
    meta: &crate::rar15_40::ExtractedEntryMeta,
    allowance: &B,
    control: &crate::read_control::ReadControl,
    links: &mut Option<&mut LegacyLink<'_>>,
    open: impl FnOnce() -> Result<Box<dyn Write>>,
    decode: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    if links.is_some() && legacy_meta_is_link(meta) {
        let mut target = Buffer::new(allowance);
        decode(&mut target)?;
        emit_legacy_link(meta, &target, links, control)?;
    } else {
        decode(&mut *open()?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::RefusingBudget;
    use std::cell::Cell;

    fn meta() -> crate::rar15_40::ExtractedEntryMeta {
        crate::rar15_40::ExtractedEntryMeta {
            name_is_unicode: false,
            name: b"link".to_vec(),
            file_time: 0,
            mtime_refinement: None,
            attr: 0o120777,
            host_os: 3,
            is_directory: false,
        }
    }

    #[test]
    fn target_storage_refusals_and_late_cancellation_do_not_emit_links() {
        for cancel_after_decode in [false, true] {
            let allowance = RefusingBudget::new(if cancel_after_decode { usize::MAX } else { 0 });
            let token = crate::ReadCancellation::new();
            let control = crate::read_control::ReadControl::new(Some(&token));
            let calls = Cell::new(0);
            let mut callback = |_: &crate::rar15_40::ExtractedEntryMeta, _: &[u8]| {
                calls.set(calls.get() + 1);
                Ok(())
            };
            let result = legacy_output(
                &meta(),
                &allowance,
                &control,
                &mut Some(&mut callback),
                || panic!("link must not open file output"),
                |writer| {
                    writer.write_all(b"target")?;
                    if cancel_after_decode {
                        token.cancel();
                    }
                    Ok(())
                },
            );
            assert_eq!(result.unwrap_err().kind(), crate::ErrorKind::Cancelled);
            assert_eq!(calls.get(), 0);
            assert_eq!(allowance.used(), 0);
        }
    }

    #[test]
    fn target_charge_is_live_during_callback_and_released_on_callback_error() {
        let allowance = RefusingBudget::new(usize::MAX);
        let control = crate::read_control::ReadControl::default();
        let mut callback = |_: &crate::rar15_40::ExtractedEntryMeta, target: &[u8]| {
            assert_eq!(target, b"target");
            assert!(allowance.used() >= target.len() as u64);
            Err(Error::InvalidArgument("callback refused"))
        };
        let error = legacy_output(
            &meta(),
            &allowance,
            &control,
            &mut Some(&mut callback),
            || panic!(),
            |writer| {
                writer.write_all(b"target")?;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error.root_cause(),
            Error::InvalidArgument("callback refused")
        ));
        assert!(error.entry_context().is_some());
        assert_eq!(allowance.used(), 0);
    }
}
