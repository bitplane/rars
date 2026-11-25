use crate::error::{Error, Result};
use std::io::{Read, Seek, SeekFrom, Write};

/// One volume's output, seekable so a header can be finished after its data.
pub trait VolumeOutput: Write + Seek + Send {}

impl<T: Write + Seek + Send> VolumeOutput for T {}

/// One volume's output that can also be read back.
pub trait ReadableVolumeOutput: Read + Write + Seek + Send {}

impl<T: Read + Write + Seek + Send> ReadableVolumeOutput for T {}

/// Receives each volume of a multi-volume archive as it is finished.
pub trait VolumeSink {
    /// Told the set's size before the first volume, when the writer knows it up front.
    fn expect_volumes(&mut self, total: u64) -> Result<()> {
        let _ = total;
        Ok(())
    }

    /// Opens the output for volume `index`, numbered from zero.
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn VolumeOutput>>;

    /// Opens the output for volume `index` so that what is written to it can
    /// be read back, or returns `None` when the sink cannot, and
    /// [`start_volume`](Self::start_volume) is called for it instead.
    ///
    /// A RAR 5 set reads a volume back to build its recovery record, and to
    /// write a large compressed member into it as the member is packed.
    /// Without that, the volume's body or the packed member goes through
    /// scratch storage first.
    fn start_readable_volume(
        &mut self,
        index: u64,
    ) -> Result<Option<Box<dyn ReadableVolumeOutput>>> {
        let _ = index;
        Ok(None)
    }

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

impl Read for CollectedVolume {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let volumes = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned");
        let volume = &volumes[self.index];
        let available = &volume[self.position.min(volume.len())..];
        let read = available.len().min(buf.len());
        buf[..read].copy_from_slice(&available[..read]);
        self.position += read;
        Ok(read)
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

impl CollectedVolumes {
    fn open(&mut self, index: u64) -> Result<CollectedVolume> {
        let mut volumes = self
            .volumes
            .lock()
            .expect("volume collector is not poisoned");
        if volumes.len() as u64 != index {
            return Err(Error::WriterFailure("volumes arrived out of order"));
        }
        volumes.push(Vec::new());
        drop(volumes);
        Ok(CollectedVolume {
            volumes: std::sync::Arc::clone(&self.volumes),
            index: index as usize,
            position: 0,
        })
    }
}

impl VolumeSink for CollectedVolumes {
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn VolumeOutput>> {
        Ok(Box::new(self.open(index)?))
    }

    fn start_readable_volume(
        &mut self,
        index: u64,
    ) -> Result<Option<Box<dyn ReadableVolumeOutput>>> {
        Ok(Some(Box::new(self.open(index)?)))
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

/// Collects a set while checking that every payload write is covered by the
/// budget, which is what a member's charge holding until it is written
/// promises. Headers are written outside any charge; payloads are not.
#[cfg(test)]
pub(crate) struct ChargedVolumes {
    pub(crate) collected: CollectedVolumes,
    resources: crate::WriterResources,
    payload_writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl ChargedVolumes {
    pub(crate) fn new(resources: &crate::WriterResources) -> Self {
        Self {
            collected: CollectedVolumes::new(),
            resources: resources.clone(),
            payload_writes: Default::default(),
        }
    }

    pub(crate) fn payload_writes(&self) -> usize {
        self.payload_writes
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
struct ChargedVolume {
    inner: Box<dyn VolumeOutput>,
    resources: crate::WriterResources,
    payload_writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl Write for ChargedVolume {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > 512 {
            self.payload_writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let charged = self.resources.workspace_in_use();
            assert!(
                charged >= bytes.len() as u64,
                "{} bytes written with {charged} charged",
                bytes.len()
            );
        }
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
impl Seek for ChargedVolume {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(from)
    }
}

#[cfg(test)]
impl VolumeSink for ChargedVolumes {
    fn expect_volumes(&mut self, total: u64) -> Result<()> {
        self.collected.expect_volumes(total)
    }

    fn start_volume(&mut self, index: u64) -> Result<Box<dyn VolumeOutput>> {
        Ok(Box::new(ChargedVolume {
            inner: self.collected.start_volume(index)?,
            resources: self.resources.clone(),
            payload_writes: std::sync::Arc::clone(&self.payload_writes),
        }))
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> Result<()> {
        self.collected.finish_volume(index, len)
    }
}
