use crate::{ArchiveMember, ArchiveReadOptions, Error, Result};
use std::io::Write;

/// Decision made before a member's payload is admitted or decoded.
pub enum ExtractionDecision {
    /// Decode and verify the member, writing its contents to this destination.
    Extract(Box<dyn Write>),
    /// Do not read, decrypt, decode or verify this member's payload.
    Skip,
    /// Finish successfully without processing this member or any later member.
    Stop,
}

/// Whether a controlled extraction visited every member or stopped by request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionOutcome {
    /// Reached the end; skipped members and explicitly continued failures were not verified.
    Complete,
    /// The callback requested an early stop.
    Stopped,
}

/// Response to a failed independent member's extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionErrorAction {
    /// Return the original extraction error.
    Abort,
    /// Keep any partial output and attempt the next independent member.
    Continue,
}

pub(crate) type ErrorHandler<'a> =
    dyn FnMut(&ArchiveMember, &Error) -> Result<ExtractionErrorAction> + 'a;

/// Completes a writer after all its data has been written and verified.
pub(crate) fn flush_verified(
    control: &crate::read_control::ReadControl,
    name: &[u8],
    writer: &mut dyn Write,
) -> Result<()> {
    control
        .check()
        .and_then(|()| writer.flush().map_err(Error::from))
        .map_err(|error| error.at_entry(name.to_vec(), "extracting"))
}

/// The handler [`ArchiveReadOptions::with_member_error_handler`] sets.
#[derive(Clone, Copy)]
pub(crate) struct MemberErrorHandler<'a>(
    pub(crate) &'a (dyn Fn(&ArchiveMember, &Error) -> Result<ExtractionErrorAction> + Sync),
);

impl std::fmt::Debug for MemberErrorHandler<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemberErrorHandler(..)")
    }
}

/// Whether a resource limit belongs only to the member which raised it.
///
/// Continuing is safe only when the next member starts from fresh decoder
/// state. Operation-wide budgets and unknown future limit variants remain
/// terminal by default.
fn is_member_local_limit(error: &Error) -> bool {
    matches!(
        error.root_cause(),
        Error::MemberOutputLimitExceeded { .. }
            | Error::Rar50DictionaryLimitExceeded { .. }
            | Error::Rar50BufferedDecodeLimitExceeded { .. }
            | Error::Rar50ScratchLimitExceeded { .. }
            | Error::Rar50FilterMemoryLimitExceeded { .. }
            | Error::Codec(crate::codec::Error::WorkspaceLimitExceeded(_))
    )
}

/// How the next member starts after a failed one the caller chose to pass over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resume {
    /// From fresh decoder state.
    Fresh,
    /// From the decoder state the failed member left, as unrar does, so a
    /// solid successor keeps what history there is.
    Solid,
}

/// `None` when the member succeeded. Otherwise asks a handler whether to carry
/// on past it: the one passed to [`crate::Archive::extract_with_control_and_errors`],
/// which refuses solid members, or else the one in the read options. With
/// neither, or when the handler aborts, returns the error.
pub(crate) fn finish_member(
    handler: &mut Option<&mut ErrorHandler<'_>>,
    options: ArchiveReadOptions<'_>,
    member: impl FnOnce() -> ArchiveMember,
    solid: bool,
    result: Result<()>,
) -> Result<Option<Resume>> {
    finish(handler, options, member, solid, result, false)
}

/// [`finish_member`] for a member split across volumes, once the volume
/// holding its end has been read, so that the walk can carry on past it.
/// Only the handler in the read options is asked, and never about a limit.
pub(crate) fn finish_split_member(
    options: ArchiveReadOptions<'_>,
    member: impl FnOnce() -> ArchiveMember,
    solid: bool,
    error: Error,
) -> Result<Resume> {
    if error.kind() == crate::ErrorKind::ResourceLimit {
        return Err(error);
    }
    finish(&mut None, options, member, solid, Err(error), true)
        .map(|resume| resume.expect("a failed member resumes or fails"))
}

fn finish(
    handler: &mut Option<&mut ErrorHandler<'_>>,
    options: ArchiveReadOptions<'_>,
    member: impl FnOnce() -> ArchiveMember,
    solid: bool,
    result: Result<()>,
    split: bool,
) -> Result<Option<Resume>> {
    let Err(error) = result else {
        return Ok(None);
    };
    let explicit = handler.is_some();
    if error.kind() == crate::ErrorKind::Cancelled
        || (error.kind() == crate::ErrorKind::ResourceLimit
            && (explicit || solid || !is_member_local_limit(&error)))
    {
        return Err(error);
    }
    if explicit && solid {
        return Err(error);
    }
    if !explicit && options.member_errors.is_none() {
        return Err(error);
    }
    options.check_cancelled()?;
    let member = member();
    if !split && (member.meta.is_split_before || member.meta.is_split_after) {
        return Err(error);
    }
    let action = match (handler.as_mut(), options.member_errors) {
        (Some(handler), _) => handler(&member, &error)?,
        (None, Some(MemberErrorHandler(handler))) => handler(&member, &error)?,
        (None, None) => unreachable!("checked above"),
    };
    options.check_cancelled()?;
    match action {
        ExtractionErrorAction::Abort => Err(error),
        ExtractionErrorAction::Continue if solid => Ok(Some(Resume::Solid)),
        ExtractionErrorAction::Continue => Ok(Some(Resume::Fresh)),
    }
}

/// [`finish_member`] for an independent member, decoded with state of its
/// own, so nothing carries over to the next one.
pub(crate) fn finish_independent(
    options: ArchiveReadOptions<'_>,
    member: impl FnOnce() -> ArchiveMember,
    result: Result<()>,
) -> Result<()> {
    finish_member(&mut None, options, member, false, result).map(|_| ())
}

/// Whether a worker's error is held for the member error handler, to be
/// raised in archive order, instead of stopping the batch. Cancellation and
/// operation-wide resource limits always stop it. So does a workspace refusal:
/// a worker holds only a share of the workspace, so the batch ends there and
/// the member streams inline with all of it, as sequential extraction would.
pub(crate) fn holds_for_handler(options: &ArchiveReadOptions<'_>, error: &Error) -> bool {
    options.member_errors.is_some()
        && error.kind() != crate::ErrorKind::Cancelled
        && (error.kind() != crate::ErrorKind::ResourceLimit || is_member_local_limit(error))
        && !crate::codec::workspace::is_refusal(error)
}

pub(crate) type Selector<'a> = dyn FnMut(&ArchiveMember) -> Result<ExtractionDecision> + 'a;

/// Asks the selector about the next member. A solid member it skips is
/// refused, or, with a solid skip budget, decoded into a sink that charges
/// that budget so the solid history still reaches the members after it.
pub(crate) fn select(
    selector: &mut Option<&mut Selector<'_>>,
    options: ArchiveReadOptions<'_>,
    budget: &mut crate::output_limit::OutputBudget,
    member: impl FnOnce() -> ArchiveMember,
    solid: bool,
) -> Result<Option<ExtractionDecision>> {
    budget.set_discarding(false);
    let Some(selector) = selector.as_mut() else {
        return Ok(None);
    };
    options.check_cancelled()?;
    let member = member();
    let decision = selector(&member).map_err(|error| {
        if error.entry_context().is_none() {
            error.at_entry(member.meta.name.clone(), "selecting")
        } else {
            error
        }
    })?;
    options.check_cancelled()?;
    if matches!(decision, ExtractionDecision::Skip)
        && solid
        && !member.meta.is_directory
        && !member.meta.is_redirection
    {
        if !budget.can_discard() {
            return Err(Error::CannotSkipSolidMember.at_entry(member.meta.name, "selecting"));
        }
        budget.set_discarding(true);
        return Ok(Some(ExtractionDecision::Extract(Box::new(std::io::sink()))));
    }
    Ok(Some(decision))
}

#[cfg(test)]
mod tests {
    use super::is_member_local_limit;
    use crate::Error;

    #[test]
    fn only_member_local_resource_limits_are_recoverable() {
        for error in [
            Error::MemberOutputLimitExceeded {
                limit: 8,
                required: 9,
            },
            Error::Rar50DictionaryLimitExceeded {
                limit: 8,
                required: 16,
            },
            Error::Rar50BufferedDecodeLimitExceeded {
                limit: 8,
                required: 16,
            },
            Error::Rar50ScratchLimitExceeded {
                limit: 8,
                required: 16,
            },
            Error::Rar50FilterMemoryLimitExceeded {
                limit: 8,
                required: 16,
            },
            Error::Codec(crate::codec::Error::WorkspaceLimitExceeded(Box::new(
                crate::codec::WorkspaceLimitError {
                    limit: 8,
                    required: 16,
                    used: 0,
                },
            ))),
        ] {
            assert!(is_member_local_limit(&error), "{error}");
        }

        for error in [
            Error::TotalOutputLimitExceeded {
                limit: 8,
                required: 9,
                used: 8,
            },
            Error::SolidSkipBudgetExceeded {
                limit: 8,
                required: 9,
            },
            Error::HeaderCountLimitExceeded {
                limit: 8,
                required: 9,
            },
            Error::HeaderBytesLimitExceeded {
                limit: 8,
                required: 9,
            },
            Error::MemoryLimitExceeded {
                limit: 8,
                required: 9,
                dictionary_size: 0,
            },
        ] {
            assert!(!is_member_local_limit(&error), "{error}");
        }
    }
}
