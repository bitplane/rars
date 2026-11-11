use crate::error::{Error, Result};
use std::io::{Seek, SeekFrom, Write};

/// One volume's output, seekable so a header can be finished after its data.
pub trait VolumeOutput: Write + Seek + Send {}

impl<T: Write + Seek + Send> VolumeOutput for T {}

/// Receives each volume of a multi-volume archive as it is finished.
pub trait VolumeSink {
    /// Told the set's size before the first volume, when the writer knows it up front.
    fn expect_volumes(&mut self, total: u64) -> Result<()> {
        let _ = total;
        Ok(())
    }

    /// Opens the output for volume `index`, numbered from zero.
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn VolumeOutput>>;

    /// Called once volume `index` has been written and flushed.
    fn finish_volume(&mut self, index: u64, len: u64) -> Result<()> {
        let _ = (index, len);
        Ok(())
    }
}

/// A [`VolumeSink`] that keeps the whole set in memory.
///
/// The point of the sink is that a caller need not, so this is for the callers
/// that want the bytes back anyway: the Python bindings hand Python a list, and
/// tests inspect what was written. Four hand-rolled copies of it had grown up,
/// and only two of them checked that volumes arrived in order.
#[derive(Debug, Default)]
pub struct CollectedVolumes {
    volumes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

struct CollectedVolume {
    volumes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    index: usize,
    position: usize,
}

impl CollectedVolumes {
    pub fn new() -> Self {
        Self::default()
    }

    /// The finished set, in order. Takes the volumes rather than copying them,
    /// so a set that only just fitted in memory does not need twice the room.
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(
            &mut *self
                .volumes
                .lock()
                .expect("volume collector is not poisoned"),
        )
    }
}

impl Write for CollectedVolume {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut volumes = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned");
        let volume = &mut volumes[self.index];
        let overlap = buf.len().min(volume.len() - self.position);
        volume[self.position..self.position + overlap].copy_from_slice(&buf[..overlap]);
        volume.extend_from_slice(&buf[overlap..]);
        self.position += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for CollectedVolume {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let len = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned")[self.index]
            .len();
        self.position = seek_within(self.position, len, from)?;
        Ok(self.position as u64)
    }
}

/// Resolves a seek inside a buffer; past the end would leave a gap, which no writer needs.
pub(crate) fn seek_within(position: usize, len: usize, from: SeekFrom) -> std::io::Result<usize> {
    let target = match from {
        SeekFrom::Start(offset) => i128::from(offset),
        SeekFrom::Current(delta) => position as i128 + i128::from(delta),
        SeekFrom::End(delta) => len as i128 + i128::from(delta),
    };
    if !(0..=len as i128).contains(&target) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "volume seek outside what was written",
        ));
    }
    Ok(target as usize)
}

impl VolumeSink for CollectedVolumes {
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn VolumeOutput>> {
        let mut volumes = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned");
        if volumes.len() as u64 != index {
            return Err(Error::WriterFailure("volumes arrived out of order"));
        }
        volumes.push(Vec::new());
        drop(volumes);
        Ok(Box::new(CollectedVolume {
            volumes: std::sync::Arc::clone(&self.volumes),
            index: index as usize,
            position: 0,
        }))
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> Result<()> {
        let volumes = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned");
        if volumes[index as usize].len() as u64 != len {
            return Err(Error::WriterFailure(
                "volume length does not match what was written",
            ));
        }
        Ok(())
    }
}
