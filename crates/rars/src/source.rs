use crate::error::{Error, Result};
use crate::io_util::read_exact_at;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<PathBuf>),
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
        }
    }

    pub(crate) fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        match self {
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
            Self::Memory(data) => Ok(data.len()),
            Self::File(path) => usize::try_from(std::fs::metadata(path.as_ref())?.len())
                .map_err(|_| Error::InvalidHeader("archive size overflows host address size")),
        }
    }

    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Memory(data) => Ok(data.to_vec()),
            Self::File(path) => Ok(std::fs::read(path.as_ref())?),
        }
    }
}
