use std::io::{self, Cursor, Read};

/// Short reads with one source error at an exact byte offset.
pub(crate) struct ErrorOnceReader {
    inner: Cursor<Vec<u8>>,
    fail_at: u64,
    kind: io::ErrorKind,
    failed: bool,
}

impl ErrorOnceReader {
    pub(crate) fn new(data: Vec<u8>, fail_at: u64, kind: io::ErrorKind) -> Self {
        Self {
            inner: Cursor::new(data),
            fail_at,
            kind,
            failed: false,
        }
    }
}

impl Read for ErrorOnceReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if !self.failed && self.inner.position() == self.fail_at {
            self.failed = true;
            return Err(io::Error::new(self.kind, "source read failed"));
        }
        let mut count = out.len().min(5);
        if !self.failed {
            count = count.min((self.fail_at - self.inner.position()) as usize);
        }
        self.inner.read(&mut out[..count])
    }
}
