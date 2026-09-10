//! Final collectors retain capacity until transfer, including adapter copies.
use super::{
    preparation::{Bytes, Records},
    CapacityCharge, WriterResources,
};
use crate::{Error, Result};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

/// Encoded bytes whose managed capacity remains charged until dropped or handed
/// to the caller with `into_vec`. Bindings use `copy_with` for a counted copy.
#[derive(Debug)]
pub struct WriterOutput {
    bytes: Bytes,
    resources: WriterResources,
}
impl WriterOutput {
    pub(crate) fn new(resources: &WriterResources) -> Self {
        Self {
            bytes: Bytes::output(resources),
            resources: resources.clone(),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_vec(mut self) -> Vec<u8> {
        self.bytes.take_vec()
    }
    /// Reserve the destination payload while this source remains live. The
    /// callback must make one copy of the bytes; its result belongs to the caller.
    pub fn copy_with<T>(&self, copy: impl FnOnce(&[u8]) -> T) -> Result<T> {
        let mut charge = self.resources.execution_charge();
        if let Some(charge) = &mut charge {
            charge.grow_to(self.bytes.len() as u64)?;
        }
        Ok(copy(&self.bytes))
    }
}
impl Write for WriterOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes
            .extend_from_slice(bytes)
            .map_err(io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A collected volume set retaining its aggregate charge through adapter copies.
pub struct WriterVolumes {
    outputs: Records<WriterOutput>,
    resources: WriterResources,
}
impl WriterVolumes {
    pub fn volumes(&self) -> &[WriterOutput] {
        &self.outputs
    }
    pub fn into_vec(mut self) -> Result<Vec<Vec<u8>>> {
        let mut charge = self.resources.execution_charge();
        let bytes = self
            .outputs
            .len()
            .checked_mul(std::mem::size_of::<Vec<u8>>())
            .ok_or(Error::InvalidArgument("volume output capacity overflows"))?;
        if let Some(charge) = &mut charge {
            charge.grow_to(bytes as u64)?;
        }
        let mut out = Vec::with_capacity(self.outputs.len());
        // Keep all source charges in the old array until the handoff, although
        // the buffers have moved to the destination array without copying.
        for output in self.outputs.iter_mut() {
            out.push(output.bytes.take_vec());
        }
        Ok(out)
    }
    /// Count all destination payloads while the full source set stays retained.
    pub fn copy_with<T>(&self, copy: impl FnOnce(&[WriterOutput]) -> T) -> Result<T> {
        let bytes = self
            .outputs
            .iter()
            .try_fold(0u64, |total, out| total.checked_add(out.bytes.len() as u64))
            .ok_or(Error::InvalidArgument("volume copy capacity overflows"))?;
        let mut charge = self.resources.execution_charge();
        if let Some(charge) = &mut charge {
            charge.grow_to(bytes)?;
        }
        Ok(copy(&self.outputs))
    }
}

struct Shared {
    outputs: Mutex<Records<WriterOutput>>,
    _charge: Option<CapacityCharge>,
}
pub(crate) struct VolumeCollector {
    shared: Arc<Shared>,
    resources: WriterResources,
}
struct VolumeOutput {
    shared: Arc<Shared>,
    index: usize,
    _charge: Option<CapacityCharge>,
}
impl VolumeCollector {
    pub(crate) fn new(resources: &WriterResources) -> Result<Self> {
        let mut charge = resources.execution_charge();
        if let Some(charge) = &mut charge {
            charge.grow_to(std::mem::size_of::<Shared>() as u64)?;
        }
        Ok(Self {
            shared: Arc::new(Shared {
                outputs: Mutex::new(Records::with_charge(0, resources.execution_charge())?),
                _charge: charge,
            }),
            resources: resources.clone(),
        })
    }
    pub(crate) fn finish(self) -> Result<WriterVolumes> {
        let shared = Arc::try_unwrap(self.shared)
            .map_err(|_| Error::WriterFailure("volume output still open"))?;
        Ok(WriterVolumes {
            outputs: shared.outputs.into_inner().unwrap(),
            resources: self.resources,
        })
    }
}
impl crate::rar50::VolumeSink for VolumeCollector {
    fn start_volume(&mut self, index: u64) -> Result<Box<dyn Write + Send>> {
        let index =
            usize::try_from(index).map_err(|_| Error::InvalidArgument("volume index overflows"))?;
        let mut outputs = self.shared.outputs.lock().unwrap();
        if index != outputs.len() {
            return Err(Error::WriterFailure("nonsequential volume output"));
        }
        let mut charge = self.resources.execution_charge();
        if let Some(charge) = &mut charge {
            charge.grow_to(std::mem::size_of::<VolumeOutput>() as u64)?;
        }
        outputs.push_growing(WriterOutput::new(&self.resources))?;
        Ok(Box::new(VolumeOutput {
            shared: self.shared.clone(),
            index,
            _charge: charge,
        }))
    }
}
impl Write for VolumeOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.shared.outputs.lock().unwrap()[self.index].write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_adapter_copy_keeps_source_charged_and_never_calls_adapter() {
        let resources = WriterResources::default().with_max_memory_bytes(4096);
        let mut output = WriterOutput::new(&resources);
        output.write_all(&[42; 4096]).unwrap();
        assert_eq!(resources.managed_memory_in_use(), 4096);
        let error = output
            .copy_with(|_| panic!("copy must be refused before allocation"))
            .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(output.as_bytes(), &[42; 4096]);
        assert_eq!(resources.managed_memory_in_use(), 4096);
        drop(output);
        assert_eq!(resources.managed_memory_in_use(), 0);
    }

    #[test]
    fn adapter_copy_charges_source_and_destination_until_handoff() {
        let resources = WriterResources::default().with_max_memory_bytes(8192);
        let mut output = WriterOutput::new(&resources);
        output.write_all(&[42; 4096]).unwrap();
        let copied = output
            .copy_with(|bytes| {
                assert_eq!(resources.managed_memory_in_use(), 8192);
                bytes.to_vec()
            })
            .unwrap();
        assert_eq!(resources.managed_memory_in_use(), 4096);
        assert_eq!(output.into_vec(), copied);
        assert_eq!(resources.managed_memory_in_use(), 0);
    }
}
