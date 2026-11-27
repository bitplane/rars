//! `Write` sinks that keep what an extraction writes where the test can read it.

#![allow(dead_code)]

use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

/// Appends to a buffer the test holds another handle to.
pub struct Capture(pub Rc<RefCell<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// [`Capture`] for writers that must be `Send`.
pub struct SyncCapture(pub Arc<Mutex<Vec<u8>>>);

impl Write for SyncCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
