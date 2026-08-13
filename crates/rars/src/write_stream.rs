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
                source.open()?.read_to_end(&mut data)?;
                if data.len() as u64 != expected {
                    return Err(Error::InvalidHeader(
                        "entry source size changed while compressing",
                    ));
                }
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
                let mut reader = source.open()?;
                let mut buffer = vec![0u8; WALK_CHUNK];
                loop {
                    let read = reader.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    visit(&buffer[..read]);
                }
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
                let copied = std::io::copy(&mut source.open()?, output)?;
                if copied != expected {
                    return Err(Error::InvalidHeader(
                        "entry source size changed while writing",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
