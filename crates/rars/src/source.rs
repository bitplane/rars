use crate::error::{Error, Result};
use crate::io_util::read_exact_at;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

pub(crate) struct ReaderSource {
    reader: Mutex<Box<dyn ReadSeek>>,
    len: usize,
}

impl std::fmt::Debug for ReaderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderSource")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl ReaderSource {
    pub(crate) fn new(mut reader: impl Read + Seek + Send + 'static) -> Result<Arc<Self>> {
        let len = usize::try_from(reader.seek(SeekFrom::End(0))?)
            .map_err(|_| Error::InvalidHeader("archive size overflows host address size"))?;
        Ok(Arc::new(Self {
            reader: Mutex::new(Box::new(reader)),
            len,
        }))
    }

    pub(crate) fn cursor(self: &Arc<Self>) -> SourceCursor {
        SourceCursor {
            source: self.clone(),
            position: 0,
        }
    }
}

pub(crate) struct SourceCursor {
    source: Arc<ReaderSource>,
    position: u64,
}

impl Read for SourceCursor {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = (self.source.len as u64).saturating_sub(self.position);
        let count = bytes.len().min(remaining as usize);
        if count == 0 {
            return Ok(0);
        }
        let mut reader = self
            .source
            .reader
            .lock()
            .map_err(|_| std::io::Error::other("archive reader lock poisoned"))?;
        // The seek and read share one lock; sibling cursors never share a position.
        reader.seek(SeekFrom::Start(self.position))?;
        let count = reader.read(&mut bytes[..count])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for SourceCursor {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let position = match from {
            SeekFrom::Start(position) => position as i128,
            SeekFrom::Current(offset) => self.position as i128 + offset as i128,
            SeekFrom::End(offset) => self.source.len as i128 + offset as i128,
        };
        self.position = u64::try_from(position)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        Ok(self.position)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<PathBuf>),
    Reader(Arc<ReaderSource>),
}

impl ArchiveSource {
    pub(crate) fn read_range(&self, range: Range<usize>) -> Result<Vec<u8>> {
        match self {
            Self::Memory(data) => data
                .get(range)
                .map(|data| data.to_vec())
                .ok_or(Error::TooShort),
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                read_exact_at(&mut file, range.start, range.len())
            }
            Self::Reader(source) => read_exact_at(&mut source.cursor(), range.start, range.len()),
        }
    }

    pub(crate) fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        match self {
            Self::Reader(_) => {
                let mut reader = self.range_reader(range)?;
                std::io::copy(&mut reader, writer)?;
            }
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                writer.write_all(data)?;
            }
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                let mut limited = file.take(range.len() as u64);
                std::io::copy(&mut limited, writer)?;
            }
        }
        Ok(())
    }

    pub(crate) fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + '_>> {
        match self {
            Self::Reader(source) => {
                if range.start > range.end || range.end > source.len {
                    return Err(Error::TooShort);
                }
                let mut reader = source.cursor();
                reader.seek(SeekFrom::Start(range.start as u64))?;
                Ok(Box::new(reader.take(range.len() as u64)))
            }
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                Ok(Box::new(Cursor::new(data)))
            }
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                Ok(Box::new(file.take(range.len() as u64)))
            }
        }
    }

    pub(crate) fn len(&self) -> Result<usize> {
        match self {
            Self::Reader(source) => Ok(source.len),
            Self::Memory(data) => Ok(data.len()),
            Self::File(path) => usize::try_from(std::fs::metadata(path.as_ref())?.len())
                .map_err(|_| Error::InvalidHeader("archive size overflows host address size")),
        }
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Reader(source) => self.read_range(0..source.len),
            Self::Memory(data) => Ok(data.to_vec()),
            Self::File(path) => Ok(std::fs::read(path.as_ref())?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_cursors_keep_independent_positions_and_range_boundaries() {
        let source = ReaderSource::new(Cursor::new(b"0123456789".to_vec())).unwrap();
        let mut first = source.cursor();
        let mut second = source.cursor();
        second.seek(SeekFrom::End(-3)).unwrap();
        let mut bytes = [0; 2];
        first.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"01");
        second.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"78");
        first.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"23");
        assert!(first.seek(SeekFrom::Current(-5)).is_err());
        assert_eq!(first.stream_position().unwrap(), 4);
        let source = ArchiveSource::Reader(source);
        let mut range = source.range_reader(4..6).unwrap();
        let mut result = Vec::new();
        range.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"45");
        assert!(source.range_reader(9..11).is_err());
    }
}
