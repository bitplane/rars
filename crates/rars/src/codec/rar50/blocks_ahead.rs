//! Pool threads decode batches of blocks to operations; the calling thread
//! reads ahead and replays them, so output and errors match the serial decoder.
use super::block_ops::{BlockOps, Repeats, Stop};
use super::{
    read_compressed_block_with_allowance, read_table_lengths_with_allowance, Budget, DecodedChunk,
    Error, OwnedCompressedBlock, PendingFilter, ReaderState, ReaderTables, Result,
    StreamDecodeError, StreamingOutput,
};
use std::collections::VecDeque;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

// Packed bytes read ahead of the output, whatever the worker count.
const MAX_AHEAD_BYTES: usize = 32 * 1024 * 1024;
// Packed bytes that make a batch worth a task of its own.
#[cfg(not(any(test, fuzzing)))]
const BATCH_BYTES: usize = 256 * 1024;
#[cfg(any(test, fuzzing))]
const BATCH_BYTES: usize = 256;

type Tables<B> = Arc<ReaderTables<B>>;

/// A block's own tables, or the ones before it, and where its symbols start.
fn enter<B: Budget>(
    block: &OwnedCompressedBlock<B>,
    algorithm_version: u8,
    previous: Option<&Tables<B>>,
) -> Result<(Tables<B>, usize)> {
    if !block.header.has_tables {
        return previous
            .map(|tables| (Arc::clone(tables), 0))
            .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"));
    }
    let allowance = block.payload.allowance();
    let (lengths, table_bits) =
        read_table_lengths_with_allowance(&block.payload, algorithm_version, &allowance)?;
    let tables = ReaderTables::from_lengths(&lengths, &allowance)?;
    Ok((Arc::new(tables), table_bits))
}

/// Operations for a batch's blocks up to `stop`, which ended block `index`.
struct Decoded<B: Budget> {
    ops: BlockOps,
    index: usize,
    stop: Stop,
    // The tables of each block begun, in order.
    tables: Vec<Tables<B>>,
}

enum Turn<B: Budget> {
    Queued,
    Running,
    Done(Decoded<B>),
}

/// Consecutive blocks decoded as one task.
struct Batch<B: Budget> {
    blocks: Vec<OwnedCompressedBlock<B>>,
    algorithm_version: u8,
    // The tables in effect before the first block, if it needs them.
    inherited: Option<Tables<B>>,
    turn: Mutex<Turn<B>>,
    ready: Condvar,
}

impl<B: Budget> Batch<B> {
    /// Decodes blocks from `index` on until one does not end cleanly.
    fn decode_from(
        &self,
        index: usize,
        ops: &mut BlockOps,
        tables: &mut Vec<Tables<B>>,
    ) -> (usize, Stop) {
        for index in index..self.blocks.len() {
            let block = &self.blocks[index];
            let previous = tables.last().or(self.inherited.as_ref());
            let (entered, bit_pos) = match enter(block, self.algorithm_version, previous) {
                Ok(entered) => entered,
                Err(error) => return (index, Stop::Failed(error)),
            };
            ops.begin_block();
            let stop = ops.decode(&entered, &block.payload, bit_pos, block.header.payload_bits);
            tables.push(entered);
            if !matches!(stop, Stop::BlockEnd) {
                return (index, stop);
            }
        }
        (self.blocks.len() - 1, Stop::BlockEnd)
    }

    fn decode(&self, spare: &Mutex<Vec<BlockOps>>) -> Decoded<B> {
        let mut ops = spare.lock().unwrap().pop().unwrap_or_default();
        ops.clear();
        let mut tables = Vec::with_capacity(self.blocks.len());
        let (index, stop) = self.decode_from(0, &mut ops, &mut tables);
        Decoded {
            ops,
            index,
            stop,
            tables,
        }
    }

    /// A worker's turn: skipped if the batch was claimed or the decode ended.
    fn run(&self, spare: &Mutex<Vec<BlockOps>>, abandoned: &AtomicBool) {
        {
            let mut turn = self.turn.lock().unwrap();
            if abandoned.load(Ordering::Relaxed) || !matches!(*turn, Turn::Queued) {
                return;
            }
            *turn = Turn::Running;
        }
        // If decoding unwinds, hand the batch back rather than strand the replay.
        let mut finished = Finish(self, Turn::Queued);
        finished.1 = Turn::Done(self.decode(spare));
    }

    /// Decodes here if no worker has started, so this never waits on idle work.
    fn take(&self, spare: &Mutex<Vec<BlockOps>>) -> Decoded<B> {
        let mut turn = self.turn.lock().unwrap();
        loop {
            match std::mem::replace(&mut *turn, Turn::Running) {
                Turn::Queued => {
                    drop(turn);
                    return self.decode(spare);
                }
                Turn::Running => turn = self.ready.wait(turn).unwrap(),
                Turn::Done(decoded) => return decoded,
            }
        }
    }
}

struct Finish<'a, B: Budget>(&'a Batch<B>, Turn<B>);

impl<B: Budget> Drop for Finish<'_, B> {
    fn drop(&mut self) {
        let turn = std::mem::replace(&mut self.1, Turn::Queued);
        if let Ok(mut slot) = self.0.turn.lock() {
            *slot = turn;
        }
        self.0.ready.notify_all();
    }
}

/// Reads blocks into batches, leaving their tables to whoever decodes them.
struct Scan<'a, R, B: Budget> {
    input: &'a mut R,
    algorithm_version: u8,
    allowance: B,
    // The tables before the next batch, unless `unparsed` supersedes them.
    inherited: Option<Tables<B>>,
    // The newest block with tables, which only its batch's decoder has parsed.
    unparsed: Option<(Arc<Batch<B>>, usize)>,
    done: bool,
}

impl<R: Read, B: Budget> Scan<'_, R, B> {
    /// The next batch, then the failure that ended the scan, if any.
    fn next(&mut self) -> (Option<Arc<Batch<B>>>, Option<Error>) {
        let mut blocks = Vec::new();
        let mut bytes = 0;
        let mut failure = None;
        while !self.done && bytes < BATCH_BYTES {
            match read_compressed_block_with_allowance(self.input, &self.allowance) {
                Ok(block) => {
                    bytes += held_bytes(&block);
                    self.done = block.header.is_last;
                    blocks.push(block);
                }
                Err(error) => {
                    self.done = true;
                    failure = Some(error);
                }
            }
        }
        let Some(first) = blocks.first() else {
            return (None, failure);
        };
        if !first.header.has_tables {
            if let Some((batch, index)) = self.unparsed.take() {
                // Parsed again here rather than wait; a failure surfaces at that block first.
                self.inherited = enter(&batch.blocks[index], self.algorithm_version, None)
                    .ok()
                    .map(|(tables, _)| tables);
            }
        }
        let newest_tables = blocks.iter().rposition(|block| block.header.has_tables);
        let batch = Arc::new(Batch {
            blocks,
            algorithm_version: self.algorithm_version,
            inherited: self.inherited.clone(),
            turn: Mutex::new(Turn::Queued),
            ready: Condvar::new(),
        });
        if let Some(index) = newest_tables {
            self.unparsed = Some((Arc::clone(&batch), index));
        }
        (Some(batch), failure)
    }
}

/// Just the workers, since idle threads of a larger pool spin-yield on every spawn; shared so concurrent members stay within them.
fn decode_pool(workers: usize) -> Option<Arc<rayon::ThreadPool>> {
    static POOL: Mutex<Option<(usize, Arc<rayon::ThreadPool>)>> = Mutex::new(None);
    let mut cached = POOL.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, pool)) = cached.as_ref().filter(|(size, _)| *size == workers) {
        return Some(Arc::clone(pool));
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|index| format!("rars-block-decode-{index}"))
        .build()
        .ok()
        .map(Arc::new)?;
    *cached = Some((workers, Arc::clone(&pool)));
    Some(pool)
}

fn in_place_scope<'scope, R>(
    pool: Option<&rayon::ThreadPool>,
    op: impl FnOnce(&rayon::Scope<'scope>) -> R,
) -> R {
    match pool {
        Some(pool) => pool.in_place_scope(op),
        None => rayon::in_place_scope(op),
    }
}

// Counting the block itself bounds a run of empty blocks too.
fn held_bytes<B: Budget>(block: &OwnedCompressedBlock<B>) -> usize {
    block.payload.len() + std::mem::size_of::<OwnedCompressedBlock<B>>()
}

fn batch_bytes<B: Budget>(batch: &Batch<B>) -> usize {
    batch.blocks.iter().map(held_bytes).sum()
}

impl<B: Budget> ReaderState<B> {
    pub(super) fn decode_blocks_ahead<E>(
        &mut self,
        workers: usize,
        input: &mut impl Read,
        algorithm_version: u8,
        output: &mut StreamingOutput<B>,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
        filters: &mut Option<&mut dyn FnMut(PendingFilter) -> std::result::Result<(), E>>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let output_size = output.output_limit;
        let control = self.read_control.clone();
        let mut repeats = Repeats {
            distances: &mut self.reps,
            last_length: &mut self.last_length,
        };
        let mut reached_tables = self.tables.take().map(Arc::new);
        let mut scan = Scan {
            input,
            algorithm_version,
            allowance: output.ring.allowance(),
            inherited: reached_tables.clone(),
            unparsed: None,
            done: false,
        };
        let spare = Mutex::new(Vec::new());
        let abandoned = AtomicBool::new(false);

        let pool = decode_pool(workers);
        let result = in_place_scope(pool.as_deref(), |scope| {
            // A read failure waits in line behind the blocks before it.
            let mut queue: VecDeque<Result<Arc<Batch<B>>>> = VecDeque::new();
            let mut ahead_bytes = 0;
            let mut replay = || loop {
                while !scan.done && queue.len() <= workers && ahead_bytes < MAX_AHEAD_BYTES {
                    let (batch, failure) = scan.next();
                    if let Some(batch) = batch {
                        ahead_bytes += batch_bytes(&batch);
                        // The batch at the head is decoded here unless more follow.
                        if !queue.is_empty() {
                            let batch = Arc::clone(&batch);
                            let (spare, abandoned) = (&spare, &abandoned);
                            scope.spawn(move |_| batch.run(spare, abandoned));
                        }
                        queue.push_back(Ok(batch));
                    }
                    queue.extend(failure.map(Err));
                }
                let batch = queue.pop_front().expect("a batch or the scan's error")?;
                ahead_bytes -= batch_bytes(&batch);
                let mut poller = control.poller();
                let Decoded {
                    mut ops,
                    mut index,
                    mut stop,
                    mut tables,
                } = batch.take(&spare);
                let mut begun = 0;
                let mut in_symbols = false;
                let replayed = loop {
                    let applied =
                        ops.apply(&mut repeats, output, &mut poller, sink, filters, &mut begun);
                    // As in the serial decoder, a failure among symbols leaves no tables.
                    if applied.is_err() {
                        in_symbols = true;
                        break applied;
                    }
                    if output.written() >= output_size {
                        break applied;
                    }
                    // Whatever the worker left is decoded here, a list at a time.
                    ops.clear();
                    (index, stop) = match stop {
                        Stop::Failed(error) => {
                            in_symbols = tables.len() > index;
                            break Err(error.into());
                        }
                        Stop::Full(bit_pos) => {
                            let block = &batch.blocks[index];
                            let stop = ops.decode(
                                &tables[tables.len() - 1],
                                &block.payload,
                                bit_pos,
                                block.header.payload_bits,
                            );
                            (index, stop)
                        }
                        Stop::BlockEnd if index + 1 == batch.blocks.len() => break Ok(()),
                        Stop::BlockEnd => batch.decode_from(index + 1, &mut ops, &mut tables),
                    };
                };
                if let Some(reached) = begun.checked_sub(1) {
                    reached_tables = Some(Arc::clone(&tables[reached]));
                }
                if in_symbols {
                    reached_tables = None;
                }
                replayed?;
                spare.lock().unwrap().push(ops);
                if scan.done && queue.is_empty() || output.written() >= output_size {
                    return Ok(());
                }
            };
            let result = replay();
            abandoned.store(true, Ordering::Relaxed);
            result
        });

        // A solid successor continues from the last block replayed, not the last scanned.
        drop(scan);
        self.tables = match reached_tables.map(Arc::try_unwrap) {
            Some(Ok(tables)) => Some(tables),
            Some(Err(shared)) => Some(shared.try_clone()?),
            None => None,
        };
        result
    }
}

#[cfg(all(test, feature = "write"))]
#[path = "blocks_ahead_tests.rs"]
mod tests;
