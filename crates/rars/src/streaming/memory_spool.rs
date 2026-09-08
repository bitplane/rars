//! Optional bounded storage for bare-WASM spools.
//! Payload blocks and index replacements have known sizes before allocation.
use super::{SpoolCharge, WriterResources};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

const BLOCK_BYTES: usize = 4096;
type Block = Box<[u8; BLOCK_BYTES]>;
const INDEX_ENTRY_BYTES: usize = std::mem::size_of::<Option<Block>>();

pub(super) struct MemorySpool {
    store: Store,
}

enum Store {
    Unbounded(Cursor<Vec<u8>>),
    Bounded(BoundedSpool),
}

struct BoundedSpool {
    // Only index slots move during growth; payload allocations stay in place.
    blocks: Box<[Option<Block>]>,
    block_count: usize,
    len: usize,
    pos: u64,
    // Drop payload and index allocations before releasing their shared charge.
    charge: SpoolCharge,
}

impl MemorySpool {
    pub(super) fn new(resources: &WriterResources) -> Self {
        let store = match &resources.spool_memory_budget {
            Some(budget) => Store::Bounded(BoundedSpool {
                blocks: Box::default(),
                block_count: 0,
                len: 0,
                pos: 0,
                charge: SpoolCharge {
                    budget: budget.clone(),
                    bytes: 0,
                },
            }),
            None => Store::Unbounded(Cursor::new(Vec::new())),
        };
        Self { store }
    }
}

impl BoundedSpool {
    fn grow(&mut self, end: usize) -> io::Result<()> {
        let count = end.div_ceil(BLOCK_BYTES);
        if count <= self.block_count {
            return Ok(());
        }
        let overflow = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory spool capacity overflow",
            )
        };
        let slots = if count > self.blocks.len() {
            count.checked_next_power_of_two().ok_or_else(overflow)?
        } else {
            self.blocks.len()
        };
        let payload_bytes = count.checked_mul(BLOCK_BYTES).ok_or_else(overflow)?;
        let index_bytes = slots.checked_mul(INDEX_ENTRY_BYTES).ok_or_else(overflow)?;
        let retained = payload_bytes
            .checked_add(index_bytes)
            .ok_or_else(overflow)?;
        let old_index_bytes = if slots != self.blocks.len() {
            self.blocks.len() * INDEX_ENTRY_BYTES
        } else {
            0
        };
        let peak = retained.checked_add(old_index_bytes).ok_or_else(overflow)?;
        self.charge.grow_to(peak as u64).map_err(io::Error::other)?;
        if slots != self.blocks.len() {
            // vec![value; n] requests exactly n elements. The boxed slice keeps
            // that layout; no unspecified Vec growth capacity enters the quota.
            let mut replacement = vec![None; slots].into_boxed_slice();
            for (target, source) in replacement.iter_mut().zip(self.blocks.iter_mut()) {
                *target = source.take();
            }
            self.blocks = replacement;
            // Assignment freed the old index before its allowance is released.
            self.charge.shrink_to(retained as u64);
        }
        while self.block_count < count {
            self.blocks[self.block_count] = Some(Box::new([0; BLOCK_BYTES]));
            self.block_count += 1;
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let pos = usize::try_from(self.pos).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory spool position overflow",
            )
        })?;
        let end = pos.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "memory spool length overflow")
        })?;
        self.grow(end)?;
        let mut copied = 0;
        while copied < bytes.len() {
            let offset = pos + copied;
            let within = offset % BLOCK_BYTES;
            let count = (BLOCK_BYTES - within).min(bytes.len() - copied);
            self.blocks[offset / BLOCK_BYTES].as_mut().unwrap()[within..within + count]
                .copy_from_slice(&bytes[copied..copied + count]);
            copied += count;
        }
        self.pos = end as u64;
        self.len = self.len.max(end);
        Ok(bytes.len())
    }

    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len as u64 {
            return Ok(0);
        }
        let pos = self.pos as usize;
        let size = bytes.len().min(self.len - pos);
        let mut copied = 0;
        while copied < size {
            let offset = pos + copied;
            let within = offset % BLOCK_BYTES;
            let count = (BLOCK_BYTES - within).min(size - copied);
            bytes[copied..copied + count].copy_from_slice(
                &self.blocks[offset / BLOCK_BYTES].as_ref().unwrap()[within..within + count],
            );
            copied += count;
        }
        self.pos += size as u64;
        Ok(size)
    }

    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let pos = match from {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::End(offset) => (self.len as u64).checked_add_signed(offset),
            SeekFrom::Current(offset) => self.pos.checked_add_signed(offset),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid memory spool seek"))?;
        self.pos = pos;
        Ok(pos)
    }
}

impl Write for MemorySpool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.store {
            Store::Unbounded(cursor) => cursor.write(bytes),
            Store::Bounded(spool) => spool.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for MemorySpool {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match &mut self.store {
            Store::Unbounded(cursor) => cursor.read(bytes),
            Store::Bounded(spool) => spool.read(bytes),
        }
    }
}
impl Seek for MemorySpool {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        match &mut self.store {
            Store::Unbounded(cursor) => cursor.seek(from),
            Store::Bounded(spool) => spool.seek(from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, ErrorKind};

    fn capacity(blocks: usize) -> u64 {
        (blocks * BLOCK_BYTES + blocks.next_power_of_two() * INDEX_ENTRY_BYTES) as u64
    }

    fn used(resources: &WriterResources) -> u64 {
        *resources
            .spool_memory_budget
            .as_ref()
            .unwrap()
            .used
            .lock()
            .unwrap()
    }

    #[test]
    fn quota_admits_payload_capacity_before_allocating_any_blocks() {
        for limit in [0, BLOCK_BYTES as u64, capacity(1) - 1] {
            let resources = WriterResources::default().with_max_spool_memory_bytes(limit);
            let mut spool = MemorySpool::new(&resources);
            let error = Error::from(spool.write(b"x").unwrap_err());
            assert_eq!(
                error,
                Error::WriterSpoolMemoryLimitExceeded {
                    limit,
                    required: capacity(1),
                    used: 0,
                }
            );
            assert_eq!(error.kind(), ErrorKind::ResourceLimit);
            assert_eq!(used(&resources), 0);
            let Store::Bounded(bounded) = &spool.store else {
                panic!("bounded storage required")
            };
            assert!(bounded.blocks.is_empty());
            assert_eq!(bounded.len, 0);
            assert_eq!(bounded.pos, 0);
        }
    }

    #[test]
    fn spare_payload_capacity_is_shared_and_stays_charged_until_drop() {
        let resources = WriterResources::default().with_max_spool_memory_bytes(capacity(1));
        let mut first = MemorySpool::new(&resources);
        first.write_all(b"x").unwrap();
        assert_eq!(used(&resources), capacity(1));
        let mut second = MemorySpool::new(&resources.clone());
        assert!(second.write(b"y").is_err());
        first.rewind().unwrap();
        first.write_all(b"replacement").unwrap();
        assert_eq!(used(&resources), capacity(1));
        first.seek(SeekFrom::Start(BLOCK_BYTES as u64 - 1)).unwrap();
        assert!(first.write_all(b"ab").is_err());
        assert_eq!(used(&resources), capacity(1));
        let mut bytes = Vec::new();
        first.rewind().unwrap();
        first.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"replacement");
        drop(first);
        second.write_all(b"y").unwrap();
        assert_eq!(used(&resources), capacity(1));
        drop(second);
        assert_eq!(used(&resources), 0);
    }

    #[test]
    fn index_replacement_requires_both_indexes_before_growth() {
        let peak = capacity(2) + INDEX_ENTRY_BYTES as u64;
        for limit in [peak - 1, peak] {
            let resources = WriterResources::default().with_max_spool_memory_bytes(limit);
            let mut spool = MemorySpool::new(&resources);
            spool.write_all(b"original").unwrap();
            spool.seek(SeekFrom::Start(BLOCK_BYTES as u64)).unwrap();
            let result = spool.write(b"next");
            if limit < peak {
                assert_eq!(
                    Error::from(result.unwrap_err()),
                    Error::WriterSpoolMemoryLimitExceeded {
                        limit,
                        required: peak,
                        used: capacity(1),
                    }
                );
                assert_eq!(used(&resources), capacity(1));
                assert_eq!(spool.stream_position().unwrap(), BLOCK_BYTES as u64);
                assert_eq!(spool.seek(SeekFrom::End(0)).unwrap(), 8);
            } else {
                assert_eq!(result.unwrap(), 4);
                // The replaced index is no longer charged after growth.
                assert_eq!(used(&resources), capacity(2));
            }
            spool.rewind().unwrap();
            let mut original = [0; 8];
            spool.read_exact(&mut original).unwrap();
            assert_eq!(&original, b"original");
            drop(spool);
            assert_eq!(used(&resources), 0);
        }
    }

    #[test]
    fn unused_index_slots_remain_charged_and_reused() {
        let resources = WriterResources::default().with_max_spool_memory_bytes(capacity(4));
        let mut spool = MemorySpool::new(&resources);
        // Three payload blocks allocate four index slots.
        spool.write_all(&vec![7; BLOCK_BYTES * 3]).unwrap();
        assert_eq!(used(&resources), capacity(3));
        spool.write_all(b"fourth").unwrap();
        assert_eq!(used(&resources), capacity(4));
        // A second spool cannot use the retained capacity.
        assert!(MemorySpool::new(&resources).write(b"x").is_err());
        assert_eq!(used(&resources), capacity(4));
        drop(spool);
        assert_eq!(used(&resources), 0);
    }

    #[test]
    fn block_boundaries_overwrites_and_holes_match_cursor_contents() {
        let resources =
            WriterResources::default().with_max_spool_memory_bytes((BLOCK_BYTES * 8) as u64);
        let mut actual = MemorySpool::new(&resources);
        let mut expected = Cursor::new(Vec::new());
        for (position, data) in [
            (0, b"start".as_slice()),
            (BLOCK_BYTES as u64 - 3, b"cross a block boundary".as_slice()),
            (
                (BLOCK_BYTES * 3) as u64 + 1,
                b"after a zero-filled hole".as_slice(),
            ),
            (2, b"overwrite".as_slice()),
        ] {
            actual.seek(SeekFrom::Start(position)).unwrap();
            expected.seek(SeekFrom::Start(position)).unwrap();
            actual.write_all(data).unwrap();
            expected.write_all(data).unwrap();
        }
        assert_eq!(used(&resources), capacity(4));
        assert_eq!(
            actual.seek(SeekFrom::End(-5)).unwrap(),
            expected.seek(SeekFrom::End(-5)).unwrap()
        );
        actual.write_all(b"tail!").unwrap();
        expected.write_all(b"tail!").unwrap();
        actual.rewind().unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 73];
        loop {
            let count = actual.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(bytes, expected.into_inner());
    }

    #[test]
    fn seek_and_empty_io_do_not_allocate_or_change_length() {
        let resources = WriterResources::default().with_max_spool_memory_bytes(0);
        let mut spool = MemorySpool::new(&resources);
        spool.seek(SeekFrom::Start(u64::MAX)).unwrap();
        assert_eq!(spool.write(b"").unwrap(), 0);
        assert_eq!(spool.read(&mut [0; 1]).unwrap(), 0);
        assert!(spool.write(b"x").is_err());
        assert_eq!(used(&resources), 0);
        assert!(spool.seek(SeekFrom::Current(1)).is_err());
        assert_eq!(spool.stream_position().unwrap(), u64::MAX);
        assert!(spool.seek(SeekFrom::End(-1)).is_err());
        assert_eq!(spool.seek(SeekFrom::End(0)).unwrap(), 0);
    }

    #[test]
    fn unwinding_releases_payload_blocks_and_their_charge() {
        let resources = WriterResources::default().with_max_spool_memory_bytes(capacity(1));
        let failure = std::panic::catch_unwind(|| {
            let mut spool = MemorySpool::new(&resources);
            spool.write_all(b"payload").unwrap();
            panic!("injected failure");
        });
        assert!(failure.is_err());
        assert_eq!(used(&resources), 0);
        MemorySpool::new(&resources)
            .write_all(b"replacement")
            .unwrap();
        assert_eq!(used(&resources), 0);
    }

    #[test]
    fn default_storage_remains_the_unbounded_cursor() {
        let resources = WriterResources::default();
        let mut spool = MemorySpool::new(&resources);
        assert!(matches!(spool.store, Store::Unbounded(_)));
        spool.write_all(b"payload").unwrap();
        spool.rewind().unwrap();
        let mut bytes = Vec::new();
        spool.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"payload");
    }
}
