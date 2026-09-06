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

/// Returns true only when an independent member failure was explicitly accepted.
pub(crate) fn finish_member(
    handler: &mut Option<&mut ErrorHandler<'_>>,
    options: ArchiveReadOptions<'_>,
    member: impl FnOnce() -> ArchiveMember,
    solid: bool,
    result: Result<()>,
) -> Result<bool> {
    let Err(error) = result else {
        return Ok(false);
    };
    if solid
        || matches!(
            error.kind(),
            crate::ErrorKind::Cancelled | crate::ErrorKind::ResourceLimit
        )
    {
        return Err(error);
    }
    let Some(handler) = handler.as_mut() else {
        return Err(error);
    };
    options.check_cancelled()?;
    let member = member();
    if member.meta.is_split_before || member.meta.is_split_after {
        return Err(error);
    }
    let action = handler(&member, &error)?;
    options.check_cancelled()?;
    match action {
        ExtractionErrorAction::Abort => Err(error),
        ExtractionErrorAction::Continue => Ok(true),
    }
}

pub(crate) type Selector<'a> = dyn FnMut(&ArchiveMember) -> Result<ExtractionDecision> + 'a;

pub(crate) fn select(
    selector: &mut Option<&mut Selector<'_>>,
    options: ArchiveReadOptions<'_>,
    member: impl FnOnce() -> ArchiveMember,
    solid: bool,
) -> Result<Option<ExtractionDecision>> {
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
        return Err(Error::CannotSkipSolidMember.at_entry(member.meta.name, "selecting"));
    }
    Ok(Some(decision))
}
