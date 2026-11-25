use super::block_ops::{BlockOps, Flat, Replay};
use super::blocks_ahead::{decode_pool, enter, held_bytes, Batch, Tables, BATCH_BYTES};
use super::{read_compressed_block_salvaging, Budget, DecodeMode, ReaderState, Result};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// Packed input and decoded operations held for members not yet replayed; one
// larger member is still taken when less is held.
const HELD_MAX: usize = 12 << 20;
// Replay is slower than decode, so a few members past one per worker keep it
// fed; more only holds memory. The member being claimed counts, so at least
// one other must fit.
const DEPTH_PAST_WORKERS: usize = 3;
const DEPTH_MIN: usize = 4;
const DEPTH_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offered {
    Taken,
    /// Offer it again once a member has been claimed.
    Full,
    /// Stepped over: the next member offered must carry its own tables.
    Refused,
}

/// A member's blocks, decoding on the pool, for the buffered decoder to replay.
pub(crate) struct Claimed<B: Budget> {
    batches: Vec<Arc<Batch<B>>>,
    spare: Arc<Mutex<Vec<BlockOps>>>,
}

impl<B: Budget> std::fmt::Debug for Claimed<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claimed")
            .field("batches", &self.batches.len())
            .finish()
    }
}

struct Queued<B: Budget> {
    key: u64,
    batches: Vec<Arc<Batch<B>>>,
    // The member that must replay to its final block first, unless this one carries tables.
    after: Option<u64>,
    charge: usize,
    // Set when the member is dropped unclaimed, so workers skip what they have not begun.
    abandoned: Arc<AtomicBool>,
}

impl<B: Budget> Drop for Queued<B> {
    fn drop(&mut self) {
        self.abandoned.store(true, Ordering::Relaxed);
    }
}

enum Carry<B: Budget> {
    Parsed(Tables<B>),
    // Parsed only once a member that reuses them is offered.
    In(Arc<Batch<B>>, usize),
}

/// Lets a solid chain's later members decode on the pool while this thread replays one.
pub(crate) struct MembersAhead<B: Budget> {
    pool: Arc<rayon::ThreadPool>,
    allowance: B,
    depth: usize,
    queue: VecDeque<Queued<B>>,
    held: usize,
    // The tables in force after the last member offered, and that member.
    carry: Option<Carry<B>>,
    last: Option<u64>,
    replayed: Option<u64>,
    spare: Arc<Mutex<Vec<BlockOps>>>,
}

impl<B: Budget> MembersAhead<B> {
    pub(crate) fn new(workers: usize, allowance: &B) -> Option<Self> {
        Some(Self {
            pool: decode_pool(workers)?,
            allowance: allowance.clone(),
            depth: (workers + DEPTH_PAST_WORKERS).clamp(DEPTH_MIN, DEPTH_MAX),
            queue: VecDeque::new(),
            held: 0,
            carry: None,
            last: None,
            replayed: None,
            spare: Arc::default(),
        })
    }

    pub(crate) fn full(&self) -> bool {
        self.queue.len() >= self.depth || self.held >= HELD_MAX
    }

    /// `key` names the member to [`Self::claim`]; `solid` is the member's own flag.
    pub(crate) fn offer(
        &mut self,
        key: u64,
        packed: &[u8],
        unpacked: u64,
        algorithm_version: u8,
        solid: bool,
    ) -> Offered {
        if self.full() {
            return Offered::Full;
        }
        if unpacked == 0 {
            return self.refuse();
        }
        let mut input = packed;
        let mut blocks = Vec::new();
        loop {
            match read_compressed_block_salvaging(&mut input, &self.allowance, false) {
                Ok(block) => {
                    let last = block.header.is_last;
                    blocks.push(block);
                    if last {
                        break;
                    }
                }
                Err(_) => return self.refuse(),
            }
        }
        if !blocks[0].header.has_tables && !solid {
            return self.refuse();
        }
        let after = (!blocks[0].header.has_tables)
            .then_some(self.last)
            .flatten();
        let mut batches = Vec::new();
        let mut blocks = blocks.into_iter().peekable();
        while blocks.peek().is_some() {
            let mut batch = Vec::new();
            let mut bytes = 0;
            while let Some(block) = blocks.next_if(|_| bytes < BATCH_BYTES) {
                bytes += held_bytes(&block);
                batch.push(block);
            }
            let inherited = if batch[0].header.has_tables {
                None
            } else {
                match self.carried() {
                    Some(tables) => Some(tables),
                    None => return self.refuse(),
                }
            };
            let newest_tables = batch.iter().rposition(|block| block.header.has_tables);
            let batch = Arc::new(Batch::new(batch, algorithm_version, inherited));
            if let Some(index) = newest_tables {
                self.carry = Some(Carry::In(Arc::clone(&batch), index));
            }
            batches.push(batch);
        }
        self.last = Some(key);
        let abandoned = Arc::new(AtomicBool::new(false));
        for batch in &batches {
            let (task, spare, abandoned) = (
                Arc::clone(batch),
                Arc::clone(&self.spare),
                Arc::clone(&abandoned),
            );
            self.pool.spawn(move || task.run(&spare, &abandoned));
        }
        let charge = packed.len() + 2 * unpacked as usize;
        self.held += charge;
        self.queue.push_back(Queued {
            key,
            batches,
            after,
            charge,
            abandoned,
        });
        Offered::Taken
    }

    fn carried(&mut self) -> Option<Tables<B>> {
        let tables = match self.carry.as_ref()? {
            Carry::Parsed(tables) => return Some(Arc::clone(tables)),
            Carry::In(batch, index) => {
                enter(&batch.blocks[*index], batch.algorithm_version, None)
                    .ok()?
                    .0
            }
        };
        self.carry = Some(Carry::Parsed(Arc::clone(&tables)));
        Some(tables)
    }

    fn refuse(&mut self) -> Offered {
        self.break_run();
        Offered::Refused
    }

    /// Something that may change the tables in force was not offered.
    pub(crate) fn break_run(&mut self) {
        self.carry = None;
        self.last = None;
    }

    /// Drops members offered before `key`, which keys rise through, that were never claimed.
    pub(crate) fn pass_before(&mut self, key: u64) {
        while self.queue.front().is_some_and(|queued| queued.key < key) {
            let passed = self.queue.pop_front().expect("checked above");
            self.held -= passed.charge;
        }
    }

    /// Called for every compressed member decoded; `None` decodes it serially.
    pub(crate) fn claim(&mut self, key: u64) -> Option<Claimed<B>> {
        let replayed = self.replayed.take();
        let position = self.queue.iter().position(|queued| queued.key == key)?;
        // Members offered but passed over are never reached.
        for passed in self.queue.drain(..position) {
            self.held -= passed.charge;
        }
        let mut queued = self.queue.pop_front().expect("found above");
        self.held -= queued.charge;
        if queued.after.is_some() && queued.after != replayed {
            return None;
        }
        // Claimed, so the workers carry on; only the replaced flag is set on drop.
        queued.abandoned = Arc::default();
        Some(Claimed {
            batches: std::mem::take(&mut queued.batches),
            spare: Arc::clone(&self.spare),
        })
    }

    /// The claimed member `key` replayed to its final block, leaving its last tables in force.
    pub(crate) fn replayed(&mut self, key: u64) {
        self.replayed = Some(key);
    }

    /// A failed member leaves the tables in force unknown.
    pub(crate) fn clear(&mut self) {
        self.queue.clear();
        self.held = 0;
        self.replayed = None;
        self.break_run();
    }
}

impl<B: Budget> ReaderState<B> {
    /// The member's blocks from the pool, unless they must be decoded here.
    pub(super) fn take_claimed(&mut self, mode: DecodeMode) -> Option<Claimed<B>> {
        self.claimed
            .take()
            .filter(|_| mode == DecodeMode::Lz && !B::LIMITED)
    }

    /// Drops a claim a failure left unused; true when the claim replayed to its final block.
    pub(crate) fn settle_claim(&mut self) -> bool {
        self.claimed = None;
        std::mem::take(&mut self.replayed_whole)
    }

    pub(crate) fn set_claimed(&mut self, claimed: Claimed<B>) {
        self.claimed = Some(claimed);
    }

    /// The buffered decoder's block loop, from operations decoded on the pool.
    pub(super) fn replay_claimed(
        &mut self,
        claimed: Claimed<B>,
        flat: &mut Flat<'_, B>,
    ) -> Result<()> {
        let mut out = Replay::begin(flat)?;
        let mut tables = self.tables.take();
        let mut replayed = Ok(());
        let mut whole = false;
        for (index, batch) in claimed.batches.iter().enumerate() {
            let (batch_replayed, batch_whole) =
                self.replay_batch(batch, &claimed.spare, &mut out, &mut tables);
            replayed = batch_replayed;
            whole = batch_whole && index + 1 == claimed.batches.len();
            if replayed.is_err() || out.full() {
                break;
            }
        }
        out.finish();
        self.tables = tables;
        self.replayed_whole = replayed.is_ok() && whole;
        replayed
    }
}

#[cfg(all(test, feature = "write"))]
#[path = "members_ahead_tests.rs"]
mod tests;
