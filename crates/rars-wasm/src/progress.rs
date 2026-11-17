//! Progress reported to a JavaScript callback while one engine call runs.
//!
//! The core's progress trait must be `Send + Sync`, which a JavaScript function
//! isn't. The engine runs on one thread, so the callback lives in a thread-local
//! for the length of the call, and what the core holds is a unit struct.

use std::cell::{Cell, RefCell};
use std::io::{self, Write};
use std::rc::Rc;
use wasm_bindgen::prelude::*;

thread_local! {
    static CALLBACK: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

/// Runs `run` with `callback` receiving `(phase, completed, total)`, `total` undefined while unknown.
pub(crate) fn watching<T>(callback: Option<js_sys::Function>, run: impl FnOnce() -> T) -> T {
    CALLBACK.with(|slot| *slot.borrow_mut() = callback);
    let result = run();
    CALLBACK.with(|slot| *slot.borrow_mut() = None);
    result
}

pub(crate) fn active() -> bool {
    CALLBACK.with(|slot| slot.borrow().is_some())
}

/// A callback that throws can't stop the engine from here, so its exception is dropped;
/// the worker owns cancellation.
pub(crate) fn report(phase: &str, completed: u64, total: Option<u64>) {
    CALLBACK.with(|slot| {
        if let Some(callback) = slot.borrow().as_ref() {
            let total = total.map_or(JsValue::UNDEFINED, |total| (total as f64).into());
            let _ = callback.call3(
                &JsValue::NULL,
                &phase.into(),
                &(completed as f64).into(),
                &total,
            );
        }
    })
}

/// The core's write progress, named with Python's phases.
pub(crate) struct WriteReporter;

fn phase(operation: rars_rs::WriteOperation) -> &'static str {
    match operation {
        rars_rs::WriteOperation::Staging => "staging",
        rars_rs::WriteOperation::Compression => "compressing",
        rars_rs::WriteOperation::Recovery => "protecting",
        _ => "writing",
    }
}

impl rars_rs::WriteProgress for WriteReporter {
    fn report(&self, event: rars_rs::WriteProgressEvent<'_>) {
        use rars_rs::WriteProgressEvent as Event;
        match event {
            Event::OperationStarted {
                operation,
                total_bytes,
                ..
            } => report(phase(operation), 0, total_bytes),
            Event::Advanced {
                operation,
                completed_bytes,
                total_bytes,
                ..
            } => report(phase(operation), completed_bytes, Some(total_bytes)),
            Event::BytesWritten { completed_bytes } => report("writing", completed_bytes, None),
            Event::OperationFinished {
                operation,
                total_bytes: Some(total),
                ..
            } => report(phase(operation), total, Some(total)),
            _ => {}
        }
    }
}

/// Reports a mebibyte at a time, so a decoder's writes don't each call into JavaScript.
const BATCH: u64 = 1 << 20;

/// Decoded bytes counted toward one call's total, which is unknown while a
/// set's later volumes are still arriving.
#[derive(Clone)]
pub(crate) struct ReadCount {
    phase: &'static str,
    total: Option<u64>,
    completed: Rc<Cell<u64>>,
    reported: Rc<Cell<u64>>,
}

impl ReadCount {
    pub(crate) fn new(phase: &'static str, total: u64) -> Self {
        Self::with_total(phase, Some(total))
    }

    pub(crate) fn with_total(phase: &'static str, total: Option<u64>) -> Self {
        report(phase, 0, total);
        Self {
            phase,
            total,
            completed: Rc::default(),
            reported: Rc::default(),
        }
    }

    pub(crate) fn counted(&self, writer: Box<dyn Write>) -> Box<dyn Write> {
        Box::new(Counted {
            writer,
            count: self.clone(),
        })
    }

    pub(crate) fn add(&self, bytes: u64) {
        let completed = self.completed.get() + bytes;
        let completed = self.total.map_or(completed, |total| completed.min(total));
        self.completed.set(completed);
        if completed - self.reported.get() >= BATCH {
            self.reported.set(completed);
            report(self.phase, completed, self.total);
        }
    }

    pub(crate) fn finish(&self) {
        let completed = self.total.unwrap_or(self.completed.get());
        report(self.phase, completed, Some(completed));
    }
}

struct Counted {
    writer: Box<dyn Write>,
    count: ReadCount,
}

impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.writer.write(bytes)?;
        self.count.add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
