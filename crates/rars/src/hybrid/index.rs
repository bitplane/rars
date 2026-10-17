use super::DictionaryStats;
use crate::{EntrySource, Error, Result};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const NONE: u64 = u64::MAX;
const PAGE: usize = 4096;
const RECORD_BYTES: usize = 88;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexLimits {
    /// Heap capacity of the fixed node/member/byte caches, excluding returned queries.
    pub cache_bytes: u64,
    /// Aggregate logical bytes of the captured input, nodes and member records.
    pub max_disk_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Occurrence {
    pub member_id: u64,
    pub offset: u64,
}

#[derive(Debug)]
struct Storage {
    directory: PathBuf,
}

impl Drop for Storage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

trait Record: Copy + Default {
    const WIDTH: usize;
    fn encode(self, bytes: &mut [u8]);
    fn decode(bytes: &[u8]) -> Self;
}

#[derive(Clone, Copy, Default)]
struct Node {
    start: u64,
    end: u64,
    owner: u64,
    suffix_link: u64,
    first_child: u64,
    first_terminator: u64,
    next_sibling: u64,
    parent: u64,
    suffix_start: u64,
    depth: u64,
    first_symbol: u64,
}

impl Node {
    fn empty() -> Self {
        Self {
            end: NONE,
            owner: NONE,
            suffix_link: 0,
            first_child: NONE,
            first_terminator: NONE,
            next_sibling: NONE,
            parent: NONE,
            suffix_start: NONE,
            ..Self::default()
        }
    }
}

impl Record for Node {
    const WIDTH: usize = RECORD_BYTES;
    fn encode(self, bytes: &mut [u8]) {
        let fields = [
            self.start,
            self.end,
            self.owner,
            self.suffix_link,
            self.first_child,
            self.first_terminator,
            self.next_sibling,
            self.parent,
            self.suffix_start,
            self.depth,
            self.first_symbol,
        ];
        for (dst, value) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(fields) {
            dst.copy_from_slice(&value.to_le_bytes());
        }
    }
    fn decode(bytes: &[u8]) -> Self {
        let mut f = [0u64; 11];
        for (dst, src) in f.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
            *dst = u64::from_le_bytes(*src);
        }
        Self {
            start: f[0],
            end: f[1],
            owner: f[2],
            suffix_link: f[3],
            first_child: f[4],
            first_terminator: f[5],
            next_sibling: f[6],
            parent: f[7],
            suffix_start: f[8],
            depth: f[9],
            first_symbol: f[10],
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Member {
    id: u64,
    raw_start: u64,
    length: u64,
    text_start: u64,
    finished: u64,
}

impl Record for Member {
    const WIDTH: usize = 40;
    fn encode(self, bytes: &mut [u8]) {
        for (dst, value) in bytes.as_chunks_mut::<8>().0.iter_mut().zip([
            self.id,
            self.raw_start,
            self.length,
            self.text_start,
            self.finished,
        ]) {
            dst.copy_from_slice(&value.to_le_bytes());
        }
    }
    fn decode(bytes: &[u8]) -> Self {
        let mut f = [0u64; 5];
        for (dst, src) in f.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
            *dst = u64::from_le_bytes(*src);
        }
        Self {
            id: f[0],
            raw_start: f[1],
            length: f[2],
            text_start: f[3],
            finished: f[4],
        }
    }
}

#[derive(Clone, Copy)]
struct Slot<T: Record> {
    id: u64,
    value: T,
}

struct Records<T: Record> {
    file: File,
    length: u64,
    // Direct mapped and write-through: no unbounded hash/LRU auxiliary storage.
    cache: Vec<Slot<T>>,
}

fn memory_error(limit: u64, required: u64) -> Error {
    Error::MemoryLimitExceeded {
        limit,
        required,
        dictionary_size: 0,
    }
}

impl<T: Record> Records<T> {
    fn create(path: &Path, cache_bytes: u64) -> Result<Self> {
        let count = usize::try_from(cache_bytes / std::mem::size_of::<Slot<T>>() as u64)
            .map_err(|_| memory_error(cache_bytes, u64::MAX))?;
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(count)
            .map_err(|_| memory_error(cache_bytes, cache_bytes))?;
        cache.resize(
            count,
            Slot {
                id: NONE,
                value: T::default(),
            },
        );
        Ok(Self {
            file: private_file(path)?,
            length: 0,
            cache,
        })
    }
    fn allocated(&self) -> u64 {
        (self.cache.capacity() * std::mem::size_of::<Slot<T>>()) as u64
    }
    fn get(&mut self, id: u64) -> Result<T> {
        if id >= self.length {
            return Err(Error::WriterFailure("hybrid index record is missing"));
        }
        if !self.cache.is_empty() {
            let slot = &self.cache[id as usize % self.cache.len()];
            if slot.id == id {
                return Ok(slot.value);
            }
        }
        let mut bytes = [0u8; RECORD_BYTES];
        self.file
            .seek(SeekFrom::Start(id.checked_mul(T::WIDTH as u64).ok_or(
                Error::WriterFailure("hybrid index record offset overflows"),
            )?))?;
        self.file.read_exact(&mut bytes[..T::WIDTH])?;
        let value = T::decode(&bytes[..T::WIDTH]);
        self.cache_value(id, value);
        Ok(value)
    }
    fn cache_value(&mut self, id: u64, value: T) {
        if !self.cache.is_empty() {
            let at = id as usize % self.cache.len();
            self.cache[at] = Slot { id, value };
        }
    }
    fn put(&mut self, id: u64, value: T) -> Result<()> {
        let mut bytes = [0u8; RECORD_BYTES];
        value.encode(&mut bytes[..T::WIDTH]);
        self.file
            .seek(SeekFrom::Start(id.checked_mul(T::WIDTH as u64).ok_or(
                Error::WriterFailure("hybrid index record offset overflows"),
            )?))?;
        self.file.write_all(&bytes[..T::WIDTH])?;
        self.cache_value(id, value);
        Ok(())
    }
    fn append(&mut self, value: T) -> Result<u64> {
        let id = self.length;
        self.put(id, value)?;
        self.length = self
            .length
            .checked_add(1)
            .ok_or(Error::WriterFailure("hybrid index record count overflows"))?;
        Ok(id)
    }
}

struct BytePage {
    id: u64,
    valid: usize,
    bytes: [u8; PAGE],
}
struct Bytes {
    file: File,
    length: u64,
    cache: Vec<BytePage>,
}

impl Bytes {
    fn create(path: &Path, budget: u64) -> Result<Self> {
        let count = usize::try_from(budget / std::mem::size_of::<BytePage>() as u64)
            .map_err(|_| memory_error(budget, u64::MAX))?;
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(count)
            .map_err(|_| memory_error(budget, budget))?;
        cache.resize_with(count, || BytePage {
            id: NONE,
            valid: 0,
            bytes: [0; PAGE],
        });
        Ok(Self {
            file: private_file(path)?,
            length: 0,
            cache,
        })
    }
    fn allocated(&self) -> u64 {
        (self.cache.capacity() * std::mem::size_of::<BytePage>()) as u64
    }
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(self.length))?;
        self.file.write_all(bytes)?;
        self.length = self
            .length
            .checked_add(bytes.len() as u64)
            .ok_or(Error::WriterFailure(
                "hybrid captured input offset overflows",
            ))?;
        // Existing full pages remain immutable; only an old partial tail can change.
        if !bytes.is_empty() && !self.cache.is_empty() {
            let old = self.length - bytes.len() as u64;
            let page = old / PAGE as u64;
            let at = page as usize % self.cache.len();
            if self.cache[at].id == page {
                self.cache[at].id = NONE;
            }
        }
        Ok(())
    }
    fn get(&mut self, offset: u64) -> Result<u8> {
        if offset >= self.length {
            return Err(Error::WriterFailure("hybrid captured byte is missing"));
        }
        if self.cache.is_empty() {
            let mut byte = [0u8; 1];
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.read_exact(&mut byte)?;
            return Ok(byte[0]);
        }
        let id = offset / PAGE as u64;
        let at = id as usize % self.cache.len();
        let page = &mut self.cache[at];
        if page.id != id {
            let start = id * PAGE as u64;
            page.valid = (self.length - start).min(PAGE as u64) as usize;
            self.file.seek(SeekFrom::Start(start))?;
            self.file.read_exact(&mut page.bytes[..page.valid])?;
            page.id = id;
        }
        let within = offset as usize % PAGE;
        if within >= page.valid {
            return Err(Error::WriterFailure("hybrid byte cache is stale"));
        }
        Ok(page.bytes[within])
    }
}

/// Online generalized Ukkonen suffix tree with fixed-record external storage.
///
/// Edge labels are ranges in captured input plus unique virtual file terminators.
/// Finished member leaf ends are shared through their member record, avoiding a
/// leaf rewrite pass. Byte children have at most 256 entries; unique terminator
/// children have a separate list and are never scanned during byte lookup.
/// All mutations are write-through. An I/O/quota failure poisons construction,
/// so an incomplete tree can never be returned as a complete query result.
pub struct RepeatIndex {
    nodes: Records<Node>,
    members: Records<Member>,
    bytes: Bytes,
    limits: IndexLimits,
    disk_used: u64,
    active_member: Option<u64>,
    text_length: u64,
    phase_end: u64,
    active_node: u64,
    active_edge: u64,
    active_length: u64,
    remainder: u64,
    failed: bool,
    sequential_ids: bool,
    stats: DictionaryStats,
    // Last: files close before the final directory owner removes their paths.
    storage: Arc<Storage>,
}

impl RepeatIndex {
    pub fn create(directory: impl AsRef<Path>, limits: IndexLimits) -> Result<Self> {
        let directory = directory.as_ref();
        let storage = loop {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!("rars-hybrid-{}-{id}", std::process::id()));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => break Arc::new(Storage { directory: path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        };
        let nodes = Records::create(&storage.directory.join("nodes"), limits.cache_bytes / 2)?;
        let members = Records::create(&storage.directory.join("members"), limits.cache_bytes / 8)?;
        let bytes = Bytes::create(
            &storage.directory.join("captured"),
            limits.cache_bytes - limits.cache_bytes / 2 - limits.cache_bytes / 8,
        )?;
        let mut index = Self {
            nodes,
            members,
            bytes,
            limits,
            disk_used: 0,
            active_member: None,
            text_length: 0,
            phase_end: 0,
            active_node: 0,
            active_edge: 0,
            active_length: 0,
            remainder: 0,
            failed: false,
            sequential_ids: true,
            stats: DictionaryStats::default(),
            storage,
        };
        let allocated = index.cache_allocated_bytes();
        if allocated > limits.cache_bytes {
            return Err(memory_error(limits.cache_bytes, allocated));
        }
        let root = Node {
            end: 0,
            ..Node::empty()
        };
        index.new_node(root)?;
        Ok(index)
    }

    pub fn disk_bytes(&self) -> u64 {
        self.disk_used
    }
    pub fn cache_allocated_bytes(&self) -> u64 {
        self.nodes.allocated() + self.members.allocated() + self.bytes.allocated()
    }
    pub fn member_count(&self) -> u64 {
        self.members.length
    }
    pub fn node_count(&self) -> u64 {
        self.nodes.length
    }
    pub fn stats(&self) -> &DictionaryStats {
        &self.stats
    }

    #[cfg(test)]
    pub(super) fn test_directory(&self) -> &Path {
        &self.storage.directory
    }

    fn healthy(&self) -> Result<()> {
        if self.failed {
            Err(Error::WriterFailure(
                "hybrid index construction previously failed",
            ))
        } else {
            Ok(())
        }
    }
    fn reserve_disk(&mut self, amount: u64) -> Result<()> {
        let required = self.disk_used.checked_add(amount);
        if required.is_none_or(|n| n > self.limits.max_disk_bytes) {
            return Err(Error::WriterSpoolLimitExceeded {
                limit: self.limits.max_disk_bytes,
                required: required.unwrap_or(u64::MAX),
                used: self.disk_used,
            });
        }
        self.disk_used = required.expect("checked disk reservation");
        Ok(())
    }
    fn new_node(&mut self, node: Node) -> Result<u64> {
        self.reserve_disk(Node::WIDTH as u64)?;
        self.nodes.append(node)
    }

    pub fn begin_member(&mut self, member_id: u64) -> Result<()> {
        self.healthy()?;
        if self.active_member.is_some() {
            return Err(Error::InvalidArgument(
                "hybrid index member is already open",
            ));
        }
        // IDs are caller identities; uniqueness is checked without retaining an unbounded map.
        if !(self.sequential_ids && member_id == self.members.length)
            && self.find_member(member_id)?.is_some()
        {
            return Err(Error::DuplicateEntry);
        }
        if self.members.length > u64::MAX - 256 {
            return Err(Error::InvalidArgument(
                "hybrid index has too many virtual terminators",
            ));
        }
        self.failed = true;
        self.reserve_disk(Member::WIDTH as u64)?;
        let ordinal = self.members.append(Member {
            id: member_id,
            raw_start: self.bytes.length,
            length: 0,
            text_start: self.text_length,
            finished: 0,
        })?;
        self.active_member = Some(ordinal);
        self.sequential_ids &= member_id == ordinal;
        self.failed = false;
        Ok(())
    }

    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        self.append_with_cancellation(data, &|| false)
    }

    /// Cancellation aborts construction; already captured sources stay owned,
    /// but no query can mistake the unfinished tree for a complete index.
    pub fn append_with_cancellation(
        &mut self,
        data: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        self.healthy()?;
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let ordinal = self
            .active_member
            .ok_or(Error::InvalidArgument("hybrid index has no open member"))?;
        self.failed = true;
        let mut member = self.members.get(ordinal)?;
        member.length = member
            .length
            .checked_add(data.len() as u64)
            .ok_or(Error::InvalidArgument("hybrid member size overflows"))?;
        self.reserve_disk(data.len() as u64)?;
        self.bytes.append(data)?;
        self.members.put(ordinal, member)?;
        for &byte in data {
            self.extend(u64::from(byte), cancelled)?;
        }
        self.failed = false;
        Ok(())
    }

    pub fn finish_member(&mut self) -> Result<()> {
        self.finish_member_with_cancellation(&|| false)
    }

    pub fn finish_member_with_cancellation(&mut self, cancelled: &dyn Fn() -> bool) -> Result<()> {
        self.healthy()?;
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let ordinal = self
            .active_member
            .ok_or(Error::InvalidArgument("hybrid index has no open member"))?;
        self.failed = true;
        let mut member = self.members.get(ordinal)?;
        member.finished = 1;
        self.members.put(ordinal, member)?;
        self.extend(256 + ordinal, cancelled)?;
        if self.remainder != 0 {
            return Err(Error::WriterFailure(
                "hybrid terminator left implicit suffixes",
            ));
        }
        self.active_member = None;
        self.active_node = 0;
        self.active_length = 0;
        self.active_edge = 0;
        self.failed = false;
        Ok(())
    }

    fn member_at_text(&mut self, pos: u64) -> Result<(u64, Member)> {
        let mut low = 0;
        let mut high = self.members.length;
        while low < high {
            let mid = low + (high - low) / 2;
            let member = self.members.get(mid)?;
            if member.text_start <= pos {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            return Err(Error::WriterFailure("hybrid text position precedes input"));
        }
        let ordinal = low - 1;
        let member = self.members.get(ordinal)?;
        if pos - member.text_start > member.length {
            return Err(Error::WriterFailure("hybrid text position exceeds member"));
        }
        Ok((ordinal, member))
    }
    fn symbol(&mut self, pos: u64) -> Result<u64> {
        let (ordinal, member) = self.member_at_text(pos)?;
        let offset = pos - member.text_start;
        if offset == member.length {
            Ok(256 + ordinal)
        } else {
            Ok(u64::from(self.bytes.get(member.raw_start + offset)?))
        }
    }
    fn edge_end(&mut self, node: Node) -> Result<u64> {
        if node.end != NONE {
            return Ok(node.end);
        }
        if Some(node.owner) == self.active_member {
            return Ok(self.phase_end);
        }
        let member = self.members.get(node.owner)?;
        member
            .text_start
            .checked_add(member.length)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::WriterFailure("hybrid leaf end overflows"))
    }
    fn child(&mut self, parent: u64, symbol: u64) -> Result<Option<u64>> {
        // Each virtual terminator appears once in the entire text, so no old
        // edge can match the terminator used in the current extension.
        if symbol >= 256 {
            return Ok(None);
        }
        let mut child = self.nodes.get(parent)?.first_child;
        while child != NONE {
            let node = self.nodes.get(child)?;
            if node.first_symbol == symbol {
                return Ok(Some(child));
            }
            child = node.next_sibling;
        }
        Ok(None)
    }
    fn insert_child(&mut self, parent: u64, id: u64) -> Result<()> {
        let mut p = self.nodes.get(parent)?;
        let mut child = self.nodes.get(id)?;
        let head = if child.first_symbol < 256 {
            &mut p.first_child
        } else {
            &mut p.first_terminator
        };
        child.next_sibling = *head;
        child.parent = parent;
        *head = id;
        self.nodes.put(id, child)?;
        self.nodes.put(parent, p)
    }
    fn replace_child(&mut self, parent: u64, old: u64, new: u64) -> Result<()> {
        let old_node = self.nodes.get(old)?;
        let mut p = self.nodes.get(parent)?;
        let head = if old_node.first_symbol < 256 {
            &mut p.first_child
        } else {
            &mut p.first_terminator
        };
        if *head == old {
            *head = new;
            self.nodes.put(parent, p)?;
        } else {
            let mut before = *head;
            loop {
                if before == NONE {
                    return Err(Error::WriterFailure("hybrid split edge is detached"));
                }
                let mut node = self.nodes.get(before)?;
                if node.next_sibling == old {
                    node.next_sibling = new;
                    self.nodes.put(before, node)?;
                    break;
                }
                before = node.next_sibling;
            }
        }
        let mut replacement = self.nodes.get(new)?;
        replacement.next_sibling = old_node.next_sibling;
        self.nodes.put(new, replacement)
    }
    fn link(&mut self, from: u64, to: u64) -> Result<()> {
        let mut node = self.nodes.get(from)?;
        node.suffix_link = to;
        self.nodes.put(from, node)
    }
    fn leaf(&mut self, start: u64, suffix_start: u64) -> Result<u64> {
        let first_symbol = self.symbol(start)?;
        self.new_node(Node {
            start,
            suffix_start,
            first_symbol,
            owner: self.active_member.expect("extension has a member"),
            ..Node::empty()
        })
    }
    fn witness(&mut self, representative: u64, current: u64, length: u64) -> Result<()> {
        let (_, old) = self.member_at_text(representative)?;
        let (_, new) = self.member_at_text(current)?;
        let old_raw = old.raw_start + (representative - old.text_start);
        let new_raw = new.raw_start + (current - new.text_start);
        if old_raw < new_raw {
            self.stats.observe(new_raw - old_raw, length);
        }
        Ok(())
    }

    fn extend(&mut self, symbol: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
        let pos = self.text_length;
        self.phase_end = pos
            .checked_add(1)
            .ok_or(Error::InvalidArgument("hybrid text size overflows"))?;
        self.remainder = self
            .remainder
            .checked_add(1)
            .ok_or(Error::InvalidArgument("hybrid suffix count overflows"))?;
        let mut last_split = NONE;
        while self.remainder != 0 {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            if self.active_length == 0 {
                self.active_edge = pos;
            }
            let edge_symbol = self.symbol(self.active_edge)?;
            if let Some(next_id) = self.child(self.active_node, edge_symbol)? {
                let mut next = self.nodes.get(next_id)?;
                let edge_length = self.edge_end(next)? - next.start;
                if self.active_length >= edge_length {
                    self.active_edge += edge_length;
                    self.active_length -= edge_length;
                    self.active_node = next_id;
                    continue;
                }
                if self.symbol(next.start + self.active_length)? == symbol {
                    if last_split != NONE && self.active_node != 0 {
                        self.link(last_split, self.active_node)?;
                    }
                    let depth = self.nodes.get(self.active_node)?.depth;
                    self.witness(
                        next.suffix_start,
                        self.phase_end - self.remainder,
                        depth + self.active_length + 1,
                    )?;
                    self.active_length += 1;
                    break;
                }
                let parent_depth = self.nodes.get(self.active_node)?.depth;
                let split = self.new_node(Node {
                    start: next.start,
                    end: next.start + self.active_length,
                    parent: self.active_node,
                    suffix_start: next.suffix_start,
                    depth: parent_depth + self.active_length,
                    first_symbol: next.first_symbol,
                    ..Node::empty()
                })?;
                self.replace_child(self.active_node, next_id, split)?;
                next.start += self.active_length;
                next.first_symbol = self.symbol(next.start)?;
                next.next_sibling = NONE;
                self.nodes.put(next_id, next)?;
                self.insert_child(split, next_id)?;
                let leaf = self.leaf(pos, self.phase_end - self.remainder)?;
                self.insert_child(split, leaf)?;
                if last_split != NONE {
                    self.link(last_split, split)?;
                }
                last_split = split;
            } else {
                let leaf = self.leaf(pos, self.phase_end - self.remainder)?;
                self.insert_child(self.active_node, leaf)?;
                if last_split != NONE {
                    self.link(last_split, self.active_node)?;
                    last_split = NONE;
                }
            }
            self.remainder -= 1;
            if self.active_node == 0 && self.active_length != 0 {
                self.active_length -= 1;
                self.active_edge = self.phase_end - self.remainder;
            } else if self.active_node != 0 {
                self.active_node = self.nodes.get(self.active_node)?.suffix_link;
            }
        }
        self.text_length = self.phase_end;
        Ok(())
    }

    fn query_ready(&self, pattern: &[u8]) -> Result<()> {
        self.healthy()?;
        if self.active_member.is_some() {
            return Err(Error::InvalidArgument(
                "finish the hybrid member before querying occurrences",
            ));
        }
        if pattern.is_empty() {
            return Err(Error::InvalidArgument("hybrid occurrence pattern is empty"));
        }
        Ok(())
    }

    fn matching_subtree(&mut self, pattern: &[u8]) -> Result<Option<u64>> {
        let mut node = 0;
        let mut at = 0;
        while at < pattern.len() {
            let Some(child) = self.child(node, u64::from(pattern[at]))? else {
                return Ok(None);
            };
            let edge = self.nodes.get(child)?;
            let end = self.edge_end(edge)?;
            for pos in edge.start..end {
                if self.symbol(pos)? != u64::from(pattern[at]) {
                    return Ok(None);
                }
                at += 1;
                if at == pattern.len() {
                    return Ok(Some(child));
                }
            }
            node = child;
        }
        Ok(Some(node))
    }

    /// Visit every exact occurrence, including overlaps, with constant traversal
    /// memory. Order is deterministic tree order, not member order. Callback
    /// failure stops immediately; the complete underlying index stays reusable.
    pub fn for_each_occurrence(
        &mut self,
        pattern: &[u8],
        mut visit: impl FnMut(Occurrence) -> Result<()>,
    ) -> Result<u64> {
        self.query_ready(pattern)?;
        let Some(root) = self.matching_subtree(pattern)? else {
            return Ok(0);
        };
        self.visit_subtree(root, pattern.len() as u64, &mut |occurrence| {
            visit(occurrence)?;
            Ok(true)
        })
    }

    fn visit_subtree(
        &mut self,
        root: u64,
        length: u64,
        visit: &mut impl FnMut(Occurrence) -> Result<bool>,
    ) -> Result<u64> {
        let mut current = root;
        let mut count = 0u64;
        loop {
            let node = self.nodes.get(current)?;
            let first = if node.first_child != NONE {
                node.first_child
            } else {
                node.first_terminator
            };
            if first != NONE {
                current = first;
                continue;
            }
            let (_, member) = self.member_at_text(node.suffix_start)?;
            let offset = node.suffix_start - member.text_start;
            if length <= member.length.saturating_sub(offset) {
                if !visit(Occurrence {
                    member_id: member.id,
                    offset,
                })? {
                    return Ok(count);
                }
                count = count
                    .checked_add(1)
                    .ok_or(Error::WriterFailure("hybrid occurrence count overflows"))?;
            }
            loop {
                if current == root {
                    return Ok(count);
                }
                let node = self.nodes.get(current)?;
                if node.next_sibling != NONE {
                    current = node.next_sibling;
                    break;
                }
                let parent = self.nodes.get(node.parent)?;
                if node.first_symbol < 256 && parent.first_terminator != NONE {
                    current = parent.first_terminator;
                    break;
                }
                current = node.parent;
            }
        }
    }

    /// Collect all occurrences. Returned storage is caller-owned and is not
    /// part of the cache budget; use the visitor or explicit limited collector
    /// when the number of results is not already bounded by the caller.
    pub fn occurrences(&mut self, pattern: &[u8]) -> Result<Vec<Occurrence>> {
        let mut out = Vec::new();
        self.for_each_occurrence(pattern, |occurrence| {
            out.push(occurrence);
            Ok(())
        })?;
        out.sort_unstable();
        Ok(out)
    }

    pub fn occurrences_limited(
        &mut self,
        pattern: &[u8],
        limit: usize,
    ) -> Result<(Vec<Occurrence>, bool)> {
        self.query_ready(pattern)?;
        let mut out = Vec::new();
        let Some(root) = self.matching_subtree(pattern)? else {
            return Ok((out, false));
        };
        let mut truncated = false;
        self.visit_subtree(root, pattern.len() as u64, &mut |occurrence| {
            if out.len() == limit {
                truncated = true;
                return Ok(false);
            }
            out.push(occurrence);
            Ok(true)
        })?;
        out.sort_unstable();
        Ok((out, truncated))
    }

    fn find_member(&mut self, id: u64) -> Result<Option<Member>> {
        if self.sequential_ids {
            return if id < self.members.length {
                Ok(Some(self.members.get(id)?))
            } else {
                Ok(None)
            };
        }
        for ordinal in 0..self.members.length {
            let member = self.members.get(ordinal)?;
            if member.id == id {
                return Ok(Some(member));
            }
        }
        Ok(None)
    }

    pub fn member_source(&mut self, member_id: u64) -> Result<EntrySource> {
        self.healthy()?;
        let member = self.find_member(member_id)?.ok_or(Error::EntryNotFound)?;
        if member.finished == 0 {
            return Err(Error::InvalidArgument(
                "hybrid captured member is unfinished",
            ));
        }
        let owner = self.storage.clone();
        Ok(EntrySource::from_opener(member.length, move || {
            let mut file = File::open(owner.directory.join("captured"))?;
            file.seek(SeekFrom::Start(member.raw_start))?;
            Ok(Box::new(CapturedReader {
                file,
                start: member.raw_start,
                length: member.length,
                position: 0,
                _owner: owner.clone(),
            }))
        }))
    }

    pub fn read_member_range(
        &mut self,
        member_id: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        let source = self.member_source(member_id)?;
        let end = offset
            .checked_add(length as u64)
            .ok_or(Error::InvalidArgument("hybrid captured range overflows"))?;
        if end > source.len()? {
            return Err(Error::InvalidArgument(
                "hybrid captured range exceeds member",
            ));
        }
        let mut reader = source.open()?;
        reader.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0u8; length];
        reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

struct CapturedReader {
    file: File,
    start: u64,
    length: u64,
    position: u64,
    _owner: Arc<Storage>,
}

impl Read for CapturedReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let take = self
            .length
            .saturating_sub(self.position)
            .min(bytes.len() as u64) as usize;
        let read = self.file.read(&mut bytes[..take])?;
        self.position += read as u64;
        Ok(read)
    }
}
impl Seek for CapturedReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let position = match from {
            SeekFrom::Start(pos) => i128::from(pos),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        let position = u64::try_from(position)
            .ok()
            .and_then(|pos| self.start.checked_add(pos).map(|_| pos))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "hybrid captured seek overflows",
                )
            })?;
        self.file.seek(SeekFrom::Start(self.start + position))?;
        self.position = position;
        Ok(position)
    }
}
