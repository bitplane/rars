//! Reading and writing archive members one at a time.
//!
//! The RAR 1.3 to 4.x codecs compress a member as a unit, so those writers
//! cannot avoid having a member resident. What they can avoid is having *every*
//! member resident, which is what they used to do: the caller read all the
//! inputs, the writer built the whole archive in a `Vec`, and peak memory was a
//! multiple of the total input rather than of the largest member.

use crate::error::{Error, Result};
use crate::streaming::EntrySource;
use std::borrow::Cow;
use std::io::{Read, Write};

/// How much of a member is read at a time when it is walked rather than held.
const WALK_CHUNK: usize = 256 * 1024;

/// Where one member's bytes come from.
///
/// A caller who already holds the whole input hands over a slice; one writing
/// from disk hands over a source that is opened when the member is coded and
/// closed again straight after. Everything downstream is the same either way.
pub(crate) enum MemberBytes<'a> {
    Borrowed(&'a [u8]),
    Source(&'a EntrySource),
}

impl<'a> MemberBytes<'a> {
    pub(crate) fn len(&self) -> Result<u64> {
        match self {
            Self::Borrowed(data) => Ok(data.len() as u64),
            Self::Source(source) => source.len(),
        }
    }

    /// The whole member, borrowed when the caller already had it.
    pub(crate) fn load(&self) -> Result<Cow<'_, [u8]>> {
        match self {
            Self::Borrowed(data) => Ok(Cow::Borrowed(data)),
            Self::Source(source) => {
                let expected = source.len()?;
                let capacity = usize::try_from(expected).map_err(|_| {
                    Error::InvalidHeader("member is larger than this host can hold")
                })?;
                let mut data = Vec::with_capacity(capacity);
                let mut reader = source.open()?;
                reader.by_ref().take(expected).read_to_end(&mut data)?;
                check_source_length(
                    &mut *reader,
                    data.len() as u64,
                    expected,
                    "entry source size changed while compressing",
                )?;
                Ok(Cow::Owned(data))
            }
        }
    }

    /// Walks the member in chunks without holding it, which is how a stored
    /// one is checksummed on its way through.
    pub(crate) fn walk(&self, mut visit: impl FnMut(&[u8])) -> Result<()> {
        match self {
            Self::Borrowed(data) => visit(data),
            Self::Source(source) => {
                let expected = source.len()?;
                let mut reader = source.open()?;
                let mut limited = reader.by_ref().take(expected);
                let mut observed = 0;
                let mut buffer = vec![0u8; WALK_CHUNK];
                loop {
                    let read = limited.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    observed += read as u64;
                    visit(&buffer[..read]);
                }
                check_source_length(
                    &mut *reader,
                    observed,
                    expected,
                    "entry source size changed while reading",
                )?;
            }
        }
        Ok(())
    }

    /// The source behind this member, when there is one to copy from.
    pub(crate) fn source(&self) -> Option<&'a EntrySource> {
        match self {
            Self::Borrowed(_) => None,
            Self::Source(source) => Some(source),
        }
    }
}

/// A member's bytes as they will appear in the archive.
pub(crate) enum MemberPayload<'a> {
    /// Already in memory: everything compressed, and anything encrypted.
    Packed(Vec<u8>),
    /// Copied from the source as the archive is written, which keeps a stored
    /// member off the heap however large it is.
    Copied(&'a EntrySource),
}

impl MemberPayload<'_> {
    /// How many bytes this payload puts in the archive. A copied member is
    /// stored verbatim, so its packed size is the size it came in at.
    pub(crate) fn size(&self, unpacked_size: u64) -> u64 {
        match self {
            Self::Packed(packed) => packed.len() as u64,
            Self::Copied(_) => unpacked_size,
        }
    }

    pub(crate) fn write_to(&self, output: &mut dyn Write, expected: u64) -> Result<()> {
        match self {
            Self::Packed(packed) => output.write_all(packed)?,
            Self::Copied(source) => {
                let mut reader = source.open()?;
                let copied = std::io::copy(&mut reader.by_ref().take(expected), output)?;
                check_source_length(
                    &mut *reader,
                    copied,
                    expected,
                    "entry source size changed while writing",
                )?;
            }
        }
        Ok(())
    }
}

// Consume at most the advertised length plus one probe byte, including for a
// source that keeps growing. The extra byte is never passed to a codec or sink.
pub(crate) fn check_source_length(
    reader: &mut dyn Read,
    observed: u64,
    expected: u64,
    message: &'static str,
) -> Result<()> {
    if observed != expected {
        return Err(Error::InvalidHeader(message));
    }
    let mut probe = [0];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(Error::InvalidHeader(message)),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_sources_are_bounded_and_rejected() {
        use std::io::{Cursor, Seek, SeekFrom};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct Counted {
            data: Cursor<Vec<u8>>,
            read: Arc<AtomicUsize>,
        }
        impl Read for Counted {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = self.data.read(buffer)?;
                self.read.fetch_add(count, Ordering::Relaxed);
                Ok(count)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                self.data.seek(position)
            }
        }

        for expected in [0, 8] {
            for actual in [0, 3, 8, 1024 * 1024] {
                let read = Arc::new(AtomicUsize::new(0));
                let source = EntrySource::from_opener(expected, {
                    let read = Arc::clone(&read);
                    move || {
                        Ok(Box::new(Counted {
                            data: Cursor::new(vec![42; actual]),
                            read: Arc::clone(&read),
                        }))
                    }
                });
                let bytes = MemberBytes::Source(&source);
                let valid = actual as u64 == expected;
                assert_eq!(bytes.load().is_ok(), valid);
                assert!(read.swap(0, Ordering::Relaxed) as u64 <= expected + 1);
                let mut visited = 0;
                assert_eq!(bytes.walk(|chunk| visited += chunk.len()).is_ok(), valid);
                assert!(visited as u64 <= expected);
                assert!(read.swap(0, Ordering::Relaxed) as u64 <= expected + 1);
                let mut output = Vec::new();
                assert_eq!(
                    MemberPayload::Copied(&source)
                        .write_to(&mut output, expected)
                        .is_ok(),
                    valid
                );
                assert!(output.len() as u64 <= expected);
                assert!(read.load(Ordering::Relaxed) as u64 <= expected + 1);
            }
        }
    }

    #[test]
    fn a_source_walks_in_chunks_and_loads_whole() {
        let data: Vec<u8> = (0..WALK_CHUNK * 2 + 7).map(|index| index as u8).collect();
        let source = EntrySource::from_bytes(data.clone());
        let bytes = MemberBytes::Source(&source);

        assert_eq!(bytes.len().unwrap(), data.len() as u64);
        assert_eq!(bytes.load().unwrap().as_ref(), data.as_slice());

        let mut chunks = Vec::new();
        let mut seen = Vec::new();
        bytes
            .walk(|chunk| {
                chunks.push(chunk.len());
                seen.extend_from_slice(chunk);
            })
            .unwrap();
        assert_eq!(seen, data);
        assert!(chunks.len() > 1, "a large source should arrive in pieces");
    }

    #[test]
    fn borrowed_bytes_are_never_copied() {
        let data = b"already in memory".to_vec();
        let bytes = MemberBytes::Borrowed(&data);
        assert!(matches!(bytes.load().unwrap(), Cow::Borrowed(_)));
        assert!(bytes.source().is_none());
    }
}
