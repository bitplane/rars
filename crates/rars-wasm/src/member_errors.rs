//! Members that fail, reported to a JavaScript callback while one engine call
//! carries on past them.
//!
//! The core's member error handler must be `Sync`, which a JavaScript function
//! isn't. The engine runs on one thread, so the callback lives in a
//! thread-local for the length of the call, as the progress callback does, and
//! what the core holds is a plain function.

use std::cell::RefCell;
use wasm_bindgen::prelude::*;

struct Report {
    callback: js_sys::Function,
    encoding: Option<rars_rs::filename::LegacyNameEncoding>,
    keep_broken: bool,
    /// Stored names of the members reported, and whether each keeps its output.
    failed: Vec<(Vec<u8>, bool)>,
    /// What the callback threw, which the call throws instead.
    raised: Option<JsValue>,
}

thread_local! {
    static REPORT: RefCell<Option<Report>> = const { RefCell::new(None) };
}

/// One call's report, in force until it is finished or dropped.
pub(crate) struct Reporting(());

impl Reporting {
    /// Starts reporting to `callback`, or returns `None` without one, when a
    /// failed member ends the call as before.
    pub(crate) fn start(
        callback: Option<js_sys::Function>,
        encoding: Option<rars_rs::filename::LegacyNameEncoding>,
        keep_broken: bool,
    ) -> Option<Self> {
        let callback = callback?;
        REPORT.with(|slot| {
            *slot.borrow_mut() = Some(Report {
                callback,
                encoding,
                keep_broken,
                failed: Vec::new(),
                raised: None,
            })
        });
        Some(Self(()))
    }

    /// The options with the handler set.
    pub(crate) fn handling<'a>(
        &self,
        options: rars_rs::ArchiveReadOptions<'a>,
    ) -> rars_rs::ArchiveReadOptions<'a> {
        options.with_member_error_handler(&handle)
    }

    /// Takes the members reported so far, each with whether its output is kept.
    pub(crate) fn take_failed(&self) -> Vec<(Vec<u8>, bool)> {
        REPORT.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .map(|report| std::mem::take(&mut report.failed))
                .unwrap_or_default()
        })
    }

    /// Ends the call's report. What the callback threw, if anything, is the
    /// call's error.
    pub(crate) fn finish(self) -> Result<(), JsValue> {
        let raised = REPORT.with(|slot| slot.borrow_mut().as_mut().and_then(|r| r.raised.take()));
        drop(self);
        raised.map_or(Ok(()), Err)
    }
}

impl Drop for Reporting {
    fn drop(&mut self) {
        REPORT.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Gives the callback the error, naming the member, and carries on unless it
/// throws. A wrong password or an I/O error ends the call, as in Python and the CLI.
fn handle(
    member: &rars_rs::ArchiveMember,
    error: &rars_rs::Error,
) -> rars_rs::Result<rars_rs::ExtractionErrorAction> {
    use rars_rs::{ErrorKind, ExtractionErrorAction as Action};
    if matches!(error.kind(), ErrorKind::BadPassword | ErrorKind::Io) {
        return Ok(Action::Abort);
    }
    // Taken out of the slot so the callback runs with nothing borrowed.
    let Some((callback, encoding)) = REPORT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|report| (report.callback.clone(), report.encoding))
    }) else {
        return Ok(Action::Abort);
    };
    let name = match member.decoded_name(encoding) {
        Ok(name) => String::from_utf8_lossy(&name).into_owned(),
        Err(_) => String::from_utf8_lossy(&member.meta.name).into_owned(),
    };
    let record = crate::js_error(error.clone());
    crate::set_error_field(&record, "member", &name.into());
    let called = callback.call1(&JsValue::NULL, &record);
    REPORT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(report) = slot.as_mut() else {
            return Ok(Action::Abort);
        };
        match called {
            Ok(_) => {
                // A member that failed on its password has nothing of its own to keep.
                let kept = report.keep_broken
                    && !matches!(
                        error.kind(),
                        ErrorKind::PasswordRequired | ErrorKind::BadPassword
                    );
                report.failed.push((member.meta.name.clone(), kept));
                Ok(Action::Continue)
            }
            Err(raised) => {
                report.raised = Some(raised);
                Ok(Action::Abort)
            }
        }
    })
}
