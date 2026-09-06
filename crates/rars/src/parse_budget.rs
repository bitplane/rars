//! Header admission for one physical archive parse, before full-body allocation.
use crate::{ArchiveReadOptions, Error, Result};

pub(crate) struct ParseBudget {
    pub(crate) control: crate::read_control::ReadControl,
    count_limit: Option<u64>,
    byte_limit: Option<u64>,
    count: u64,
    bytes: u64,
}

impl ParseBudget {
    pub(crate) fn new(options: ArchiveReadOptions<'_>) -> Self {
        Self {
            control: crate::read_control::ReadControl::new(options.cancellation),
            count_limit: options.max_header_count,
            byte_limit: options.max_header_bytes,
            count: 0,
            bytes: 0,
        }
    }

    pub(crate) fn is_limited(&self) -> bool {
        self.count_limit.is_some() || self.byte_limit.is_some()
    }

    // Encrypted readers can check count before deriving keys/decrypting a prefix.
    pub(crate) fn check_count(&self, offset: usize) -> Result<()> {
        self.control.check()?;
        if let Some(limit) = self.count_limit {
            if self.count == limit {
                return Err(Error::HeaderCountLimitExceeded {
                    limit,
                    required: self.count.saturating_add(1),
                }
                .at_archive_offset(offset));
            }
        }
        Ok(())
    }

    pub(crate) fn admit(&mut self, size: usize, offset: usize) -> Result<()> {
        self.check_count(offset)?;
        if let Some(limit) = self.byte_limit {
            if size as u64 > limit - self.bytes {
                return Err(Error::HeaderBytesLimitExceeded {
                    limit,
                    required: self.bytes.saturating_add(size as u64),
                }
                .at_archive_offset(offset));
            }
            self.bytes += size as u64;
        }
        if self.count_limit.is_some() {
            self.count += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) struct PrefixReader {
    inner: std::io::Cursor<Vec<u8>>,
    pub reads: Vec<usize>,
}

#[cfg(test)]
impl PrefixReader {
    pub(crate) fn new(prefix: Vec<u8>) -> Self {
        Self {
            inner: std::io::Cursor::new(prefix),
            reads: Vec::new(),
        }
    }
}

#[cfg(test)]
impl std::io::Read for PrefixReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads.push(buf.len());
        if self.inner.position() as usize + buf.len() > self.inner.get_ref().len() {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        std::io::Read::read(&mut self.inner, buf)
    }
}

#[cfg(test)]
impl std::io::Seek for PrefixReader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        std::io::Seek::seek(&mut self.inner, pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_admission_is_inclusive_and_refusal_does_not_charge() {
        let mut b = ParseBudget::new(
            ArchiveReadOptions::new()
                .with_max_header_count(2)
                .with_max_header_bytes(10),
        );
        b.admit(4, 0).unwrap();
        let e = b.admit(7, 4).unwrap_err();
        assert!(matches!(
            e.root_cause(),
            Error::HeaderBytesLimitExceeded {
                limit: 10,
                required: 11
            }
        ));
        assert!(matches!(e, Error::AtArchiveOffset { offset: 4, .. }));
        b.admit(6, 4).unwrap();
        let e = b.admit(1, 10).unwrap_err();
        assert!(matches!(
            e.root_cause(),
            Error::HeaderCountLimitExceeded {
                limit: 2,
                required: 3
            }
        ));
        assert_eq!(e.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!((b.count, b.bytes), (2, 10));
    }

    #[test]
    fn overflow_cannot_bypass_limits() {
        let mut b = ParseBudget::new(
            ArchiveReadOptions::new()
                .with_max_header_count(u64::MAX)
                .with_max_header_bytes(u64::MAX),
        );
        b.bytes = u64::MAX - 1;
        b.count = u64::MAX - 1;
        assert!(matches!(
            b.admit(2, 0).unwrap_err().root_cause(),
            Error::HeaderBytesLimitExceeded {
                required: u64::MAX,
                ..
            }
        ));
        b.admit(1, 0).unwrap();
        assert!(matches!(
            b.admit(0, 0).unwrap_err().root_cause(),
            Error::HeaderCountLimitExceeded {
                required: u64::MAX,
                ..
            }
        ));
    }
}
