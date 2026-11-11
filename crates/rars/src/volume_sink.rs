use crate::error::{Error, Result};
use std::io::Write;

/// Receives each volume of a multi-volume archive as it is finished.
pub trait VolumeSink {
    /// Opens the output for volume `index`, numbered from zero.
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn Write + Send>>;

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
        self.volumes
            .lock()
            .expect("volume collector is not poisoned")[self.index]
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl VolumeSink for CollectedVolumes {
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn Write + Send>> {
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
