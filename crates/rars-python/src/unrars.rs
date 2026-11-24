//! The `unrars` command that `pip install rars` puts on PATH.
//!
//! The wheel's console script calls [`unrars_main`], which runs the same code
//! as the standalone `unrars` binary from `rars-cli`, so the package stays one
//! extension module.

use pyo3::prelude::*;
use std::ffi::OsString;
use std::panic::{self, AssertUnwindSafe};

/// The exit code of a Rust program whose main thread panics.
const PANIC_EXIT: i32 = 101;

/// Runs `unrars` with `sys.argv[1:]` and returns its exit code for `sys.exit`.
///
/// Ctrl-C goes back to the default action first, so it stops the command as
/// it stops the binary, without a `KeyboardInterrupt` traceback.
#[pyfunction]
#[pyo3(name = "_unrars_main")]
pub(crate) fn unrars_main(py: Python<'_>) -> PyResult<i32> {
    let argv: Vec<OsString> = py.import("sys")?.getattr("argv")?.extract()?;
    let signal = py.import("signal")?;
    signal.call_method1(
        "signal",
        (signal.getattr("SIGINT")?, signal.getattr("SIG_DFL")?),
    )?;
    let code = py.detach(|| {
        // The panic hook has already printed the message, as it does for the
        // binary; exit as the binary would rather than raise into Python.
        panic::catch_unwind(AssertUnwindSafe(|| {
            rars_cli::unrars_run(argv.into_iter().skip(1))
        }))
        .unwrap_or(PANIC_EXIT)
    });
    Ok(code)
}
