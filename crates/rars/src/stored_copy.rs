use std::io::{ErrorKind, Read, Write};

use crate::codec::workspace::Budget;
use crate::output_pipeline::{self, PipeError};

#[derive(Debug)]
pub(crate) enum CopyError {
    Read(std::io::Error),
    Write(std::io::Error),
}

impl From<CopyError> for crate::Error {
    fn from(error: CopyError) -> Self {
        match error {
            CopyError::Read(error) | CopyError::Write(error) => error.into(),
        }
    }
}

/// Returns bytes written; a `padded` member's bytes past `size` are cipher padding, read but dropped.
pub(crate) fn copy<R, C, B>(
    reader: &mut R,
    size: u64,
    padded: bool,
    check: &mut C,
    writer: &mut dyn Write,
    allowance: &B,
) -> Result<u64, CopyError>
where
    R: Read + Send,
    C: FnMut(&[u8]) + Send,
    B: Budget,
{
    let limit = if padded { size } else { u64::MAX };
    if let Some(_charge) = output_pipeline::admit(size, allowance) {
        return output_pipeline::run(|chunks| produce(reader, limit, chunks), check, writer)
            .map_err(|error| match error {
                PipeError::Produce(error) => CopyError::Read(error),
                PipeError::Write(error) => CopyError::Write(error),
            });
    }
    inline(reader, limit, check, writer)
}

fn produce<R: Read>(
    reader: &mut R,
    limit: u64,
    chunks: &mut output_pipeline::Chunks<'_>,
) -> std::io::Result<u64> {
    let mut read = 0u64;
    let mut written = 0u64;
    loop {
        let count = match reader.read(chunks.space()?) {
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            count => count?,
        };
        if count == 0 {
            return Ok(written);
        }
        let kept = kept_len(read, count, limit);
        read = read.saturating_add(count as u64);
        written += kept as u64;
        chunks.commit(kept)?;
    }
}

fn inline<R: Read, C: FnMut(&[u8])>(
    reader: &mut R,
    limit: u64,
    check: &mut C,
    writer: &mut dyn Write,
) -> Result<u64, CopyError> {
    let mut buf = [0u8; 64 * 1024];
    let mut read = 0u64;
    let mut written = 0u64;
    loop {
        let count = match reader.read(&mut buf) {
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            count => count.map_err(CopyError::Read)?,
        };
        if count == 0 {
            return Ok(written);
        }
        let chunk = &buf[..kept_len(read, count, limit)];
        read = read.saturating_add(count as u64);
        written += chunk.len() as u64;
        if !chunk.is_empty() {
            check(chunk);
            writer.write_all(chunk).map_err(CopyError::Write)?;
        }
    }
}

fn kept_len(read: u64, count: usize, limit: u64) -> usize {
    usize::try_from(limit.saturating_sub(read)).map_or(count, |left| count.min(left))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::Allowance;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn copies_every_byte_in_order_and_checks_what_it_emits() {
        for len in [0, 1000, 3 << 20] {
            let data = pattern(len);
            let mut checked = Vec::new();
            let mut out = Vec::new();
            let written = copy(
                &mut data.as_slice(),
                len as u64,
                false,
                &mut |chunk: &[u8]| checked.extend_from_slice(chunk),
                &mut out,
                &Allowance::default(),
            )
            .unwrap();
            assert_eq!(written, len as u64);
            assert_eq!(out, data);
            assert_eq!(checked, data);
        }
    }

    #[test]
    fn only_padded_members_drop_bytes_past_their_size() {
        for (len, size) in [(1000, 900), ((3 << 20) + 16, 3 << 20)] {
            let data = pattern(len);
            for padded in [true, false] {
                let mut checked = Vec::new();
                let mut out = Vec::new();
                let written = copy(
                    &mut data.as_slice(),
                    size as u64,
                    padded,
                    &mut |chunk: &[u8]| checked.extend_from_slice(chunk),
                    &mut out,
                    &Allowance::default(),
                )
                .unwrap();
                let kept = if padded { size } else { len };
                assert_eq!(written, kept as u64);
                assert_eq!(out, data[..kept]);
                assert_eq!(checked, data[..kept]);
            }
        }
    }

    struct Tracing<'a> {
        data: &'a [u8],
        threads: Vec<std::thread::ThreadId>,
    }

    impl Read for Tracing<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.threads.push(std::thread::current().id());
            self.data.read(buf)
        }
    }

    fn read_on_caller<B: Budget>(len: usize, allowance: &B) -> bool {
        let data = pattern(len);
        let mut reader = Tracing {
            data: &data,
            threads: Vec::new(),
        };
        let mut out = Vec::new();
        copy(
            &mut reader,
            len as u64,
            false,
            &mut |_: &[u8]| {},
            &mut out,
            allowance,
        )
        .unwrap();
        assert_eq!(out, data);
        let caller = std::thread::current().id();
        reader.threads.iter().all(|thread| *thread == caller)
    }

    #[test]
    fn small_members_and_refused_budgets_stay_on_the_caller() {
        assert!(read_on_caller(256 << 10, &Allowance::default()));
        assert!(read_on_caller(4 << 20, &Allowance::limited(1 << 20)));
    }

    #[test]
    fn large_members_are_read_off_the_caller() {
        if crate::parallel::may_spawn() {
            assert!(!read_on_caller(4 << 20, &Allowance::default()));
            assert!(!read_on_caller(4 << 20, &Allowance::limited(64 << 20)));
        }
    }

    struct Endless<'a>(&'a std::sync::atomic::AtomicUsize);

    impl Read for Endless<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0
                .fetch_add(buf.len(), std::sync::atomic::Ordering::Relaxed);
            Ok(buf.len())
        }
    }

    struct FailsAfter(usize);

    impl Write for FailsAfter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.0 < buf.len() {
                return Err(std::io::Error::other("disk full"));
            }
            self.0 -= buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_write_failure_stops_reading_the_member() {
        for (size, room) in [(64 << 10, 1000), (1 << 40, 5 << 20)] {
            let pulled = std::sync::atomic::AtomicUsize::new(0);
            let error = copy(
                &mut Endless(&pulled),
                size,
                false,
                &mut |_: &[u8]| {},
                &mut FailsAfter(room),
                &Allowance::default(),
            )
            .unwrap_err();
            assert!(matches!(error, CopyError::Write(error) if error.to_string() == "disk full"));
            assert!(pulled.into_inner() < 16 << 20);
        }
    }

    struct PanicsAfter(usize);

    impl Write for PanicsAfter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.0 < buf.len() {
                // Lets the producer use up every buffer first.
                std::thread::sleep(std::time::Duration::from_millis(100));
                panic!("writer panicked");
            }
            self.0 -= buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_panicking_writer_unwinds_instead_of_hanging() {
        let pulled = std::sync::atomic::AtomicUsize::new(0);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            copy(
                &mut Endless(&pulled),
                1 << 40,
                false,
                &mut |_: &[u8]| {},
                &mut PanicsAfter(5 << 20),
                &Allowance::default(),
            )
        }));
        assert!(unwound.is_err());
        assert!(pulled.into_inner() < 16 << 20);
    }

    #[test]
    fn a_read_failure_follows_the_bytes_read_before_it() {
        for len in [1000, 3 << 20] {
            let data = pattern(len);
            let mut reader = data.as_slice().chain(Failing);
            let mut out = Vec::new();
            let error = copy(
                &mut reader,
                (len * 2) as u64,
                true,
                &mut |_: &[u8]| {},
                &mut out,
                &Allowance::default(),
            )
            .unwrap_err();
            assert!(matches!(error, CopyError::Read(error) if error.to_string() == "truncated"));
            assert_eq!(out, data);
        }
    }

    /// Interrupts every other read, as a signal arriving mid-read does.
    struct Interrupting<'a> {
        data: &'a [u8],
        interrupt: bool,
    }

    impl Read for Interrupting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(ErrorKind::Interrupted.into());
            }
            self.data.read(buf)
        }
    }

    #[test]
    fn interrupted_reads_are_retried() {
        for len in [1000, 3 << 20] {
            let data = pattern(len);
            let mut out = Vec::new();
            let written = copy(
                &mut Interrupting {
                    data: &data,
                    interrupt: false,
                },
                len as u64,
                false,
                &mut |_: &[u8]| {},
                &mut out,
                &Allowance::default(),
            )
            .unwrap();
            assert_eq!(written, len as u64);
            assert_eq!(out, data);
        }
    }

    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("truncated"))
        }
    }
}
