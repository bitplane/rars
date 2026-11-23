use crate::{Error, Result};
use std::io::{Read, Seek, SeekFrom};

pub(crate) fn read_exact_at(
    file: &mut (impl Read + Seek),
    offset: usize,
    len: usize,
) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut data = vec![0; len];
    file.read_exact(&mut data)?;
    Ok(data)
}

pub(crate) fn read_u16(input: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or(Error::TooShort)?;
    let bytes = input.get(offset..end).ok_or(Error::TooShort)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::TooShort)?;
    let bytes = input.get(offset..end).ok_or(Error::TooShort)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(feature = "encryption")]
pub(crate) fn align16(value: usize, overflow_message: &'static str) -> Result<usize> {
    value
        .checked_add(15)
        .map(|value| value & !15)
        .ok_or(Error::InvalidHeader(overflow_message))
}

/// Bytes read at once by [`ReadAhead`].
const READ_AHEAD: usize = 16 << 10;

/// Serves small reads from a window read ahead of the first of them, so
/// walking the headers of an archive of small members costs one seek and
/// one read per window rather than per header.
pub(crate) struct ReadAhead<R> {
    inner: R,
    position: u64,
    window_start: u64,
    window: Vec<u8>,
}

impl<R> ReadAhead<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            position: 0,
            window_start: 0,
            window: Vec::new(),
        }
    }
}

impl<R: Read + Seek> Read for ReadAhead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let offset = self.position.checked_sub(self.window_start);
        let held = offset.filter(|&offset| offset < self.window.len() as u64);
        let offset = match held {
            Some(offset) => offset as usize,
            None => {
                self.inner.seek(SeekFrom::Start(self.position))?;
                if bytes.len() >= READ_AHEAD {
                    let count = self.inner.read(bytes)?;
                    self.position += count as u64;
                    return Ok(count);
                }
                self.window.resize(READ_AHEAD, 0);
                let count = match self.inner.read(&mut self.window) {
                    Ok(count) => count,
                    Err(error) => {
                        self.window.clear();
                        return Err(error);
                    }
                };
                self.window.truncate(count);
                self.window_start = self.position;
                if count == 0 {
                    return Ok(0);
                }
                0
            }
        };
        let count = bytes.len().min(self.window.len() - offset);
        bytes[..count].copy_from_slice(&self.window[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: Seek> Seek for ReadAhead<R> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.position = match from {
            SeekFrom::Start(position) => position,
            SeekFrom::Current(delta) => self
                .position
                .checked_add_signed(delta)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?,
            SeekFrom::End(_) => self.inner.seek(from)?,
        };
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_ahead_reads_what_the_source_holds_wherever_it_is_sought() {
        let data: Vec<u8> = (0..3 * READ_AHEAD as u32).map(|n| n as u8).collect();
        let mut reader = ReadAhead::new(Cursor::new(data.clone()));
        for (offset, len) in [
            (0, 14),
            (3, 40),
            (READ_AHEAD - 5, 20),
            (100, 7),
            (2 * READ_AHEAD - 9, READ_AHEAD + 9),
            (3 * READ_AHEAD - 4, 4),
        ] {
            assert_eq!(
                read_exact_at(&mut reader, offset, len).unwrap(),
                data[offset..offset + len]
            );
        }
        assert!(read_exact_at(&mut reader, 3 * READ_AHEAD - 4, 5).is_err());
        assert_eq!(
            reader.seek(SeekFrom::End(-2)).unwrap(),
            data.len() as u64 - 2
        );
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, data[data.len() - 2..]);
    }
}
