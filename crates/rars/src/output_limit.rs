//! Output admission and a writer guard whose error survives I/O adapters.
#[cfg(test)]
use crate::ArchiveReadOptions;
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

/// Owned by one sequential extraction operation, including all its volumes.
/// Declarations admit work; only bytes accepted by the logical output sink charge it.
pub(crate) struct OutputBudget {
    pub(crate) control: crate::read_control::ReadControl,
    member_limit: Option<u64>,
    total_limit: Option<u64>,
    used: u64,
}

impl OutputBudget {
    pub(crate) fn new(options: crate::ArchiveReadOptions<'_>) -> Self {
        Self {
            control: crate::read_control::ReadControl::new(options.cancellation),
            member_limit: options.max_member_output_bytes,
            total_limit: options.max_total_output_bytes,
            used: 0,
        }
    }

    pub(crate) fn is_limited(&self) -> bool {
        self.member_limit.is_some() || self.total_limit.is_some()
    }

    pub(crate) fn check(&self, required: u64, name: &[u8]) -> Result<()> {
        self.control.check()?;
        check(self.member_limit, required, name)?;
        if let Some(limit) = self.total_limit {
            if required > limit - self.used {
                return Err(self
                    .total_error(limit, required)
                    .at_entry(name.to_vec(), "limiting output"));
            }
        }
        Ok(())
    }

    fn total_error(&self, limit: u64, additional: u64) -> Error {
        Error::TotalOutputLimitExceeded {
            limit,
            required: self.used.saturating_add(additional),
            used: self.used,
        }
    }

    pub(crate) fn run<W: Write, T>(
        &mut self,
        name: &[u8],
        writer: W,
        work: impl FnOnce(&mut LimitedWriter<'_, W>) -> Result<T>,
    ) -> Result<T> {
        self.control.check()?;
        let mut guarded = LimitedWriter {
            writer,
            budget: self,
            written: 0,
            exceeded: None,
        };
        let result = work(&mut guarded);
        // Older decoders/error adapters may wrap or replace the sentinel. Keep
        // the refusal out of band so it cannot become bad-password/checksum/I/O.
        match guarded.exceeded {
            Some(error) => Err(error.at_entry(name.to_vec(), "limiting output")),
            None => guarded
                .budget
                .control
                .finish(result)
                .and_then(|value| guarded.budget.control.check().map(|()| value))
                .map_err(|error| {
                    if error.kind() == crate::ErrorKind::Cancelled
                        && error.entry_context().is_none()
                    {
                        error.at_entry(name.to_vec(), "extracting")
                    } else {
                        error
                    }
                }),
        }
    }
}

#[cfg(test)]
pub(crate) fn run<W: Write, T>(
    limit: Option<u64>,
    name: &[u8],
    writer: W,
    work: impl FnOnce(&mut LimitedWriter<'_, W>) -> Result<T>,
) -> Result<T> {
    let mut options = ArchiveReadOptions::new();
    options.max_member_output_bytes = limit;
    OutputBudget::new(options).run(name, writer, work)
}

pub(crate) struct LimitedWriter<'a, W> {
    writer: W,
    budget: &'a mut OutputBudget,
    written: u64,
    exceeded: Option<Error>,
}

impl<W: Write> Write for LimitedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.budget.control.check().map_err(io::Error::other)?;
        if !self.budget.is_limited() {
            let len = if self.budget.control.is_enabled() {
                bytes.len().min(64 * 1024)
            } else {
                bytes.len()
            };
            return self.writer.write(&bytes[..len]);
        }
        if self.exceeded.is_none() {
            let count = bytes.len() as u64;
            if let Some(limit) = self.budget.member_limit {
                if count > limit - self.written {
                    self.exceeded = Some(Error::MemberOutputLimitExceeded {
                        limit,
                        required: self.written.saturating_add(count),
                    });
                }
            }
            if self.exceeded.is_none() {
                if let Some(limit) = self.budget.total_limit {
                    if count > limit - self.budget.used {
                        self.exceeded = Some(self.budget.total_error(limit, count));
                    }
                }
            }
        }
        if self.exceeded.is_some() {
            return Err(io::Error::other("output limit exceeded"));
        }
        let len = if self.budget.control.is_enabled() {
            bytes.len().min(64 * 1024)
        } else {
            bytes.len()
        };
        let n = self.writer.write(&bytes[..len])?;
        if self.budget.member_limit.is_some() {
            self.written += n as u64;
        }
        if self.budget.total_limit.is_some() {
            self.budget.used += n as u64;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.budget.control.check().map_err(io::Error::other)?;
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_survives_adapters_without_refunding_or_hiding_quota_refusal() {
        let token = crate::ReadCancellation::new();
        let mut budget = OutputBudget::new(
            ArchiveReadOptions::new()
                .with_cancellation(&token)
                .with_max_total_output_bytes(4),
        );
        let err = budget
            .run(b"member", io::sink(), |w| {
                w.write_all(b"ab")?;
                token.cancel();
                assert!(w.write_all(b"c").is_err());
                Err::<(), _>(Error::WrongPasswordOrCorruptData)
            })
            .unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Cancelled);
        assert_eq!(err.entry_context().unwrap().0, b"member");
        assert_eq!(budget.used, 2);

        let token = crate::ReadCancellation::new();
        let mut budget = OutputBudget::new(
            ArchiveReadOptions::new()
                .with_cancellation(&token)
                .with_max_total_output_bytes(0),
        );
        let err = budget
            .run(b"member", io::sink(), |w| {
                assert!(w.write_all(b"a").is_err());
                token.cancel();
                assert!(w.write_all(b"b").is_err());
                Err::<(), _>(Error::WrongPasswordOrCorruptData)
            })
            .unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(budget.used, 0);
    }
    #[test]
    fn total_accounting_survives_short_writes_and_later_errors() {
        struct Short;
        impl Write for Short {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                Ok(b.len().min(1))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut budget =
            OutputBudget::new(ArchiveReadOptions::new().with_max_total_output_bytes(6));
        budget.check(6, b"first").unwrap();
        // Admission is not a charge, and short writes do not count offered bytes twice.
        assert_eq!(budget.used, 0);
        let err = budget
            .run(b"first", Short, |w| {
                w.write_all(b"abc")?;
                Err::<(), _>(Error::Crc32Mismatch {
                    expected: 1,
                    actual: 2,
                })
            })
            .unwrap_err();
        assert!(matches!(err, Error::Crc32Mismatch { .. }));
        assert_eq!(budget.used, 3);
        budget.check(3, b"second").unwrap();
        let err = budget
            .run(b"second", io::sink(), |w| {
                w.write_all(b"d")?;
                assert!(w.write_all(b"efg").is_err());
                assert!(w.write_all(b"x").is_err());
                Err::<(), _>(Error::WrongPasswordOrCorruptData)
            })
            .unwrap_err();
        let err = Error::InVolume {
            number: 2,
            source: Box::new(err),
        };
        assert_eq!(budget.used, 4);
        assert_eq!(err.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(err.entry_context().unwrap().0, b"second");
        assert!(matches!(
            err.root_cause(),
            Error::TotalOutputLimitExceeded {
                limit: 6,
                used: 4,
                required: 7
            }
        ));
    }

    #[test]
    fn total_admission_and_runtime_use_overflow_safe_arithmetic() {
        let mut budget =
            OutputBudget::new(ArchiveReadOptions::new().with_max_total_output_bytes(u64::MAX));
        budget.used = u64::MAX - 1;
        budget.check(1, b"member").unwrap();
        let err = budget.check(2, b"member").unwrap_err();
        assert!(
            matches!(err.root_cause(), Error::TotalOutputLimitExceeded { limit:u64::MAX, required:u64::MAX, used } if *used == u64::MAX - 1)
        );
        budget
            .run(b"member", io::sink(), |w| {
                w.write_all(b"x")?;
                Ok(())
            })
            .unwrap();
        budget.check(0, b"empty").unwrap();
        let err = budget
            .run(b"member", io::sink(), |w| {
                w.write_all(b"x")?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(
            err.root_cause(),
            Error::TotalOutputLimitExceeded { used: u64::MAX, .. }
        ));
    }

    #[test]
    fn member_precedence_and_total_only_refusal() {
        for (member, expected_member) in [(2, true), (3, false)] {
            let mut budget = OutputBudget::new(
                ArchiveReadOptions::new()
                    .with_max_member_output_bytes(member)
                    .with_max_total_output_bytes(2),
            );
            for err in [
                budget.check(3, b"member").unwrap_err(),
                budget
                    .run(b"member", io::sink(), |w| {
                        w.write_all(b"abc")?;
                        Ok(())
                    })
                    .unwrap_err(),
            ] {
                assert_eq!(
                    matches!(err.root_cause(), Error::MemberOutputLimitExceeded { .. }),
                    expected_member
                );
                assert_eq!(err.kind(), crate::ErrorKind::ResourceLimit);
            }
            assert_eq!(budget.used, 0);
        }
    }

    #[test]
    fn total_guard_keeps_real_sink_errors_and_empty_output() {
        let mut budget =
            OutputBudget::new(ArchiveReadOptions::new().with_max_total_output_bytes(3));
        let mut empty = [].as_mut_slice();
        let err = budget
            .run(b"member", &mut empty, |w| {
                w.write_all(b"a")?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(err.root_cause(), Error::Io(e) if e.kind == io::ErrorKind::WriteZero));
        assert_eq!(budget.used, 0);
        let mut zero = OutputBudget::new(ArchiveReadOptions::new().with_max_total_output_bytes(0));
        zero.run(b"empty", io::sink(), |w| {
            assert_eq!(w.write(b"")?, 0);
            Ok(())
        })
        .unwrap();
        assert_eq!(zero.used, 0);
    }
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
