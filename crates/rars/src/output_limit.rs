//! Member-output admission and a writer guard whose error survives I/O adapters.
use crate::{Error, Result};
use std::io::{self, Write};

pub(crate) fn check(limit: Option<u64>, required: u64, name: &[u8]) -> Result<()> {
    if let Some(limit) = limit.filter(|limit| required > *limit) {
        return Err(error(limit, required, name));
    }
    Ok(())
}

fn error(limit: u64, required: u64, name: &[u8]) -> Error {
    Error::MemberOutputLimitExceeded { limit, required }.at_entry(name.to_vec(), "limiting output")
}

pub(crate) fn run<W: Write, T>(
    limit: Option<u64>,
    name: &[u8],
    writer: W,
    work: impl FnOnce(&mut LimitedWriter<W>) -> Result<T>,
) -> Result<T> {
    let mut guarded = LimitedWriter {
        writer,
        limit,
        written: 0,
        exceeded: None,
    };
    let result = work(&mut guarded);
    // Older decoders/error adapters may wrap or replace the sentinel. Keep the
    // refusal out of band, so it cannot turn into bad-password/checksum/I/O.
    match guarded.exceeded {
        Some(required) => Err(error(limit.expect("guard has a limit"), required, name)),
        None => result,
    }
}

pub(crate) struct LimitedWriter<W> {
    writer: W,
    limit: Option<u64>,
    written: u64,
    exceeded: Option<u64>,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(limit) = self.limit else {
            return self.writer.write(bytes);
        };
        if self.exceeded.is_some() || bytes.len() as u64 > limit - self.written {
            self.exceeded
                .get_or_insert(self.written.saturating_add(bytes.len() as u64));
            return Err(io::Error::other("member output limit exceeded"));
        }
        let n = self.writer.write(bytes)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refusal_is_latched_and_restored_after_error_remapping() {
        let mut out = Vec::new();
        let err = run(Some(3), b"member", &mut out, |w| {
            w.write_all(b"ab")?;
            assert!(w.write_all(b"cd").is_err());
            assert!(w.write_all(b"x").is_err());
            Err::<(), _>(Error::WrongPasswordOrCorruptData)
        })
        .unwrap_err();
        assert_eq!(out, b"ab");
        assert!(matches!(
            err.root_cause(),
            Error::MemberOutputLimitExceeded {
                limit: 3,
                required: 4
            }
        ));
        assert_eq!(err.kind(), crate::ErrorKind::ResourceLimit);
    }
    #[test]
    fn partial_writes_count_only_accepted_bytes_and_keep_sink_errors() {
        struct Short(Vec<u8>);
        impl Write for Short {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if self.0.len() == 3 {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let n = b.len().min(1);
                self.0.extend_from_slice(&b[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut out = Short(Vec::new());
        let err = run(Some(4), b"member", &mut out, |w| {
            w.write_all(b"abcd")?;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(out.0, b"abc");
        assert!(matches!(err, Error::Io(e) if e.kind == io::ErrorKind::PermissionDenied));
        let mut out = Vec::new();
        run(Some(3), b"member", &mut out, |w| {
            w.write_all(b"abc")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(out, b"abc");
        check(Some(u64::MAX), u64::MAX, b"member").unwrap();
    }
}
