use super::*;
use crate::codec::rar50::{apply_filter_data, FilterType, PendingFilter};
use crate::streaming::Spool;
use std::cell::RefCell;
use std::io::{Seek, SeekFrom};
use std::rc::Rc;

struct DiskBudget {
    used: u64,
    limit: u64,
}
struct ScratchFile {
    spool: Spool,
    budget: Rc<RefCell<DiskBudget>>,
    pos: u64,
    len: u64,
}

impl ScratchFile {
    fn create(policy: &crate::Rar50Scratch, budget: &Rc<RefCell<DiskBudget>>) -> Result<Self> {
        let resources = crate::WriterResources::new(0).with_temp_dir(&policy.directory);
        Ok(Self {
            spool: Spool::create(&resources)?,
            budget: budget.clone(),
            pos: 0,
            len: 0,
        })
    }
    fn rewind(&mut self) -> Result<()> {
        self.seek(SeekFrom::Start(0))?;
        Ok(())
    }
}
impl Read for ScratchFile {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = self.spool.read(bytes)?;
        self.pos += count as u64;
        Ok(count)
    }
}
impl Write for ScratchFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .pos
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("scratch offset overflow"))?;
        let mut budget = self.budget.borrow_mut();
        let required = budget
            .used
            .checked_add(end.saturating_sub(self.len))
            .ok_or_else(|| {
                std::io::Error::other(Error::Rar50ScratchLimitExceeded {
                    limit: budget.limit,
                    required: u64::MAX,
                })
            })?;
        if required > budget.limit {
            return Err(std::io::Error::other(Error::Rar50ScratchLimitExceeded {
                limit: budget.limit,
                required,
            }));
        }
        let count = self.spool.write(bytes)?;
        self.pos += count as u64;
        budget.used += self.pos.saturating_sub(self.len);
        self.len = self.len.max(self.pos);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.spool.flush()
    }
}
impl Seek for ScratchFile {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.pos = self.spool.seek(from)?;
        Ok(self.pos)
    }
}

fn copy(
    source: &mut ScratchFile,
    mut destination: &mut dyn Write,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    source.rewind()?;
    let mut buffer = [0; 64 * 1024];
    loop {
        control.check()?;
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        control.write_all(&mut destination, &buffer[..count])?;
    }
    control.check()
}

fn verify(
    file: &FileHeader,
    data: &mut ScratchFile,
    keys: Option<&Rar50Keys>,
    control: &crate::read_control::ReadControl,
) -> Result<()> {
    data.rewind()?;
    let mut crc = Crc32::new();
    let mut hash = streaming_hash_verifier(file)?;
    let mut buffer = [0; 64 * 1024];
    loop {
        control.check()?;
        let count = data.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        crc.update(&buffer[..count]);
        if let Some((_, hasher)) = &mut hash {
            hasher.update(&buffer[..count]);
        }
    }
    file.verify_streaming_integrity(crc, hash, keys)
}

fn encode_filter(filter: PendingFilter) -> [u8; 24] {
    let mut bytes = [0; 24];
    bytes[..8].copy_from_slice(&(filter.start as u64).to_le_bytes());
    bytes[8..16].copy_from_slice(&(filter.length as u64).to_le_bytes());
    bytes[16] = match filter.filter_type {
        FilterType::Delta => 0,
        FilterType::E8 => 1,
        FilterType::E8E9 => 2,
        FilterType::Arm => 3,
    };
    bytes[17] = filter.channels as u8;
    bytes
}

fn decode_filter(bytes: [u8; 24]) -> Result<PendingFilter> {
    let start = usize::try_from(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        .map_err(|_| Error::InvalidHeader("scratch filter offset overflows"))?;
    let length = usize::try_from(u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
        .map_err(|_| Error::InvalidHeader("scratch filter length overflows"))?;
    let filter_type = match bytes[16] {
        0 => FilterType::Delta,
        1 => FilterType::E8,
        2 => FilterType::E8E9,
        3 => FilterType::Arm,
        _ => return Err(Error::InvalidHeader("scratch filter type changed")),
    };
    Ok(PendingFilter {
        start,
        length,
        filter_type,
        channels: bytes[17] as usize,
    })
}

pub(super) fn decode<R: Read>(
    file: &FileHeader,
    packed: &mut R,
    keys: Option<&Rar50Keys>,
    decoder: &mut Unpack50Decoder,
    policy: &crate::Rar50Scratch,
    writer: &mut dyn Write,
) -> Result<()> {
    if cfg!(all(target_arch = "wasm32", target_os = "unknown")) {
        return Err(Error::UnsupportedFamilyFeature {
            family: crate::ArchiveFamily::Rar50Plus,
            feature: "disk-backed reader scratch on bare WebAssembly",
        });
    }
    let control = decoder.read_control.clone();
    control.check()?;
    // Reserve the known payload storage before creating any temporary files.
    let required = file
        .unpacked_size
        .checked_mul(2)
        .ok_or(Error::Rar50ScratchLimitExceeded {
            limit: policy.max_bytes,
            required: u64::MAX,
        })?;
    if required > policy.max_bytes {
        return Err(Error::Rar50ScratchLimitExceeded {
            limit: policy.max_bytes,
            required,
        });
    }
    let payload_reservation = required;
    let budget = Rc::new(RefCell::new(DiskBudget {
        used: 0,
        limit: policy.max_bytes,
    }));
    let mut raw = ScratchFile::create(policy, &budget)?;
    let mut records = ScratchFile::create(policy, &budget)?;
    let info = file.decoded_compression_info()?;
    let output_size = checked_unpacked_size(file.unpacked_size)?;
    let dictionary_size = usize::try_from(info.dictionary_size)
        .map_err(|_| Error::InvalidHeader("RAR 5 dictionary size overflows host address size"))?;
    decoder
        .decode_to_sink_with_filters(
            packed,
            info.algorithm_version,
            output_size,
            dictionary_size,
            info.solid,
            |chunk| -> Result<()> {
                control.check()?;
                match chunk {
                    DecodedChunk::Bytes(bytes) => raw.write_all(bytes)?,
                    DecodedChunk::Repeated { byte, len } => {
                        let buffer = [byte; 64 * 1024];
                        let mut remaining = len;
                        while remaining != 0 {
                            control.check()?;
                            let count = remaining.min(buffer.len());
                            raw.write_all(&buffer[..count])?;
                            remaining -= count;
                        }
                    }
                }
                Ok(())
            },
            Some(&mut |filter: PendingFilter| -> Result<()> {
                control.check()?;
                let required = (filter.length as u64).saturating_mul(2);
                if required > policy.filter_memory_limit {
                    return Err(Error::Rar50FilterMemoryLimitExceeded {
                        limit: policy.filter_memory_limit,
                        required,
                    });
                }
                // Records may arrive before payload bytes: retain the payload
                // reservation rather than letting records spend that space.
                let disk_required = payload_reservation
                    .checked_add(records.len)
                    .and_then(|bytes| bytes.checked_add(24))
                    .ok_or(Error::Rar50ScratchLimitExceeded {
                        limit: policy.max_bytes,
                        required: u64::MAX,
                    })?;
                if disk_required > policy.max_bytes {
                    return Err(Error::Rar50ScratchLimitExceeded {
                        limit: policy.max_bytes,
                        required: disk_required,
                    });
                }
                records.write_all(&encode_filter(filter))?;
                Ok(())
            }),
        )
        .map_err(|error| match error {
            StreamDecodeError::Decode(error) => Error::from(error),
            StreamDecodeError::Sink(error) => error,
            StreamDecodeError::FilteredMember => unreachable!("scratch supplies a filter handler"),
        })?;
    if records.len == 0 {
        verify(file, &mut raw, keys, &control)?;
        return copy(&mut raw, writer, &control);
    }
    let mut transformed = ScratchFile::create(policy, &budget)?;
    copy(&mut raw, &mut transformed, &control)?;
    records.rewind()?;
    while records.pos < records.len {
        control.check()?;
        let mut bytes = [0; 24];
        records.read_exact(&mut bytes)?;
        let filter = decode_filter(bytes)?;
        let required = (filter.length as u64).saturating_mul(2);
        if required > policy.filter_memory_limit {
            return Err(Error::Rar50FilterMemoryLimitExceeded {
                limit: policy.filter_memory_limit,
                required,
            });
        }
        if filter
            .start
            .checked_add(filter.length)
            .is_none_or(|end| end > output_size)
        {
            return Err(Error::InvalidHeader("scratch filter range exceeds output"));
        }
        transformed.seek(SeekFrom::Start(filter.start as u64))?;
        let mut data = vec![0; filter.length];
        control.reader(&mut transformed).read_exact(&mut data)?;
        apply_filter_data(&mut data, &filter, &control)?;
        transformed.seek(SeekFrom::Start(filter.start as u64))?;
        control.write_all(&mut transformed, &data)?;
    }
    match verify(file, &mut transformed, keys, &control) {
        Ok(()) => copy(&mut transformed, writer, &control),
        Err(error) if error.kind() == crate::ErrorKind::ChecksumMismatch => {
            // Preserve the existing compatibility retry for streams whose
            // integrity records describe raw LZ output despite filter records.
            verify(file, &mut raw, keys, &control).map_err(|raw_error| {
                if raw_error.kind() == crate::ErrorKind::ChecksumMismatch {
                    error
                } else {
                    raw_error
                }
            })?;
            copy(&mut raw, writer, &control)
        }
        Err(error) => Err(error),
    }
}
