//! Turning member sources into packed payloads with workspace admission.
//!
//! RAR 5 compresses in independent blocks: a block depends only on its own
//! bytes and on up to a dictionary's worth of the raw input that precedes it.
//! Since that preceding input is just the file being read, the history a block
//! needs is known before any compression happens, and blocks can be compressed
//! in parallel while their packed output is written back in order.
//!
//! Non-solid members each carry their own history and are interleaved so that
//! several small members keep every core busy. Solid members share one history
//! chain that runs across member boundaries, so their blocks are produced by a
//! single walk through the members in order — the walk is just reading, which
//! is cheap, so waves of blocks still compress in parallel.

use super::filter_policy::{
    compression_info, encode_member_with_filter_policy_candidates_and_progress,
    should_store_compressed_payload,
};
use super::FilterPolicy;
#[cfg(test)]
use crate::codec::rar50::EncodeOptions;
use crate::codec::rar50::{encode_lz_streaming_blocks, BlockSplitter};
use crate::crc32::Crc32;
use crate::rar50::blake2sp;
use crate::streaming::preparation::Records;
use crate::streaming::Spool;
use crate::{EntrySource, Error, Result, WriterResources};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// Compression work and member lifecycle, independent of presentation.
pub(super) trait CompressionProgress: Sync {
    fn advance(&self, bytes: u64) -> bool;
    fn is_cancelled(&self) -> bool {
        false
    }
    fn started(&self, _member: usize, _size: u64) {}
    fn finished(&self, _member: usize, _size: u64) {}
}
impl<F: Fn(u64) -> bool + Sync> CompressionProgress for F {
    fn advance(&self, bytes: u64) -> bool {
        self(bytes)
    }
}

/// Batch-local cancellation joins already admitted workers and prevents queued
/// work from opening a source after a sibling has failed. The caller's token is
/// never changed, so the same resources can be reused after an ordinary error.
struct BatchProgress<'a> {
    progress: &'a dyn CompressionProgress,
    resources: &'a WriterResources,
    stopped: AtomicBool,
}
impl CompressionProgress for BatchProgress<'_> {
    fn advance(&self, bytes: u64) -> bool {
        if self.is_cancelled() {
            return false;
        }
        if !self.progress.advance(bytes) {
            self.stopped.store(true, Ordering::Release);
            return false;
        }
        !self.is_cancelled()
    }
    fn is_cancelled(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
            || self.resources.is_cancelled()
            || self.progress.is_cancelled()
    }
    fn started(&self, member: usize, size: u64) {
        self.progress.started(member, size);
    }
    fn finished(&self, member: usize, size: u64) {
        self.progress.finished(member, size);
    }
}

/// Slots are admitted before dispatch. Both input and result descriptor storage
/// stay owned until all callbacks join, even if one callback fails. The caller
/// retains its workspace reservation through consumption of returned results.
fn run_jobs<T: Send, O: Send>(
    jobs: Records<T>,
    resources: &WriterResources,
    progress: &dyn CompressionProgress,
    map: impl Fn(T, &dyn CompressionProgress) -> Result<O> + Sync + Send,
) -> Result<Records<O>> {
    let mut output = Records::new(jobs.len(), resources)?;
    let mut slots = Records::collect(jobs.into_iter().map(|job| Ok((Some(job), None))), resources)?;
    let batch = BatchProgress {
        progress,
        resources,
        stopped: AtomicBool::new(false),
    };
    crate::parallel::for_each_mut(&mut slots, |_, (job, result)| {
        if batch.is_cancelled() {
            return;
        }
        let mapped = map(job.take().expect("one callback per slot"), &batch);
        if mapped.is_err() {
            batch.stopped.store(true, Ordering::Release);
        }
        *result = Some(mapped);
    });
    // Prefer the source/codec failure over cancellation caused by that failure.
    // Scan in job order, so scheduling does not choose which error we report.
    let mut failure = None;
    for (_, result) in slots.iter_mut() {
        if result.as_ref().is_some_and(Result::is_err) {
            let error = result.take().unwrap().err().unwrap();
            if failure
                .as_ref()
                .is_none_or(|error: &Error| error.kind() == crate::ErrorKind::Cancelled)
            {
                failure = Some(error);
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if batch.is_cancelled() {
        return Err(Error::Cancelled);
    }
    for (_, result) in slots {
        output.push(result.expect("all jobs completed")?)?;
    }
    Ok(output)
}

/// A member that has been compressed and is waiting to be framed.
pub(super) struct CompressedMember {
    pub(super) input_size: u64,
    pub(super) crc32: u32,
    pub(super) hash: [u8; 32],
    pub(super) packed: Spool,
    /// True when the payload should be written as-is from the source because
    /// compressing it did not pay.
    pub(super) store: bool,
    /// True when this member continues the previous member's dictionary.
    pub(super) solid_continuation: bool,
}

#[cfg(test)]
use super::plan::whole_member_workspace;
pub(super) use super::plan::CompressPlan;
use super::plan::{Execution, ExecutionPlan, MemberPlan};

/// A bounded run of adjacent blocks, sharing one copy of the preceding input.
struct BlockJob {
    data: Vec<u8>,
    history: Vec<u8>,
    /// Member index, end within `data`, and final-block flag.
    blocks: Records<(usize, usize, bool)>,
}

fn run_size(plan: &CompressPlan) -> usize {
    plan.encode_options
        .max_match_distance
        .max(crate::codec::rar50::MAX_LZ_BLOCK_SIZE)
}

/// A member being read, and the packed bytes it has produced so far.
struct MemberStream {
    member: usize,
    input_size: u64,
    started: bool,
    source: EntrySource,
    reader: Option<Box<dyn crate::EntryReader>>,
    remaining: u64,
    packed: Spool,
    /// A chunk read to decide a block boundary and not used by that block.
    pushback: Vec<u8>,
    crc: Crc32,
    hash: blake2sp::Hasher,
}

impl MemberStream {
    fn new(
        member: usize,
        source: &EntrySource,
        size: u64,
        resources: &WriterResources,
        progress: &dyn CompressionProgress,
    ) -> Result<Self> {
        if size == 0 {
            progress.started(member, size);
            if progress.is_cancelled() {
                return Err(Error::Cancelled);
            }
            check_source_end(&mut *source.open()?)?;
            progress.finished(member, size);
        }
        Ok(Self {
            member,
            input_size: size,
            started: size == 0,
            source: source.clone(),
            reader: None,
            remaining: size,
            packed: Spool::create_parked(resources)?,
            pushback: Vec::new(),
            crc: Crc32::new(),
            hash: blake2sp::Hasher::new(),
        })
    }

    /// Whether this member has anything left, read or unread.
    fn has_more(&self) -> bool {
        self.remaining != 0 || !self.pushback.is_empty()
    }
}

/// `advance` is called with each newly completed chunk of work and returns
/// false when the caller wants to stop.
pub(super) fn compress_members_with_context(
    sources: &[EntrySource],
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<CompressedMember>> {
    if advance.is_cancelled() || resources.is_cancelled() {
        return Err(Error::Cancelled);
    }
    let mut integrity = Records::new(sources.len(), resources)?;
    for (index, source) in sources.iter().enumerate() {
        let input_size = source.len().map_err(|error| error_context(index, error))?;
        // Compression fills these checksums while consuming the source.
        integrity.push((input_size, 0, [0; 32]))?;
    }

    let execution =
        ExecutionPlan::with_resources(plan, integrity.iter().map(|entry| entry.0), resources)?;
    if let ExecutionPlan::IndependentMembers(ref members) = execution {
        return compress_members_whole(
            sources,
            &integrity,
            plan,
            members,
            resources,
            advance,
            error_context,
        );
    }

    // Storing is not "compress and hope it does not help": the header records
    // method zero, so the payload must be the source bytes.
    let packed = if plan.method == 0 {
        for (index, (source, (input_size, crc, hash))) in
            sources.iter().zip(&mut integrity).enumerate()
        {
            advance.started(index, *input_size);
            (*crc, *hash) = super::source_integrity(source, *input_size, plan.block_size, advance)
                .map_err(|error| error_context(index, error))?;
            if !advance.advance(*input_size) {
                return Err(Error::Cancelled);
            }
            advance.finished(index, *input_size);
        }
        Records::collect(
            integrity.iter().map(|_| Spool::create_parked(resources)),
            resources,
        )?
    } else {
        compress_streaming_members(
            sources,
            &mut integrity,
            plan,
            match execution {
                ExecutionPlan::Blocks { workspace } => workspace,
                _ => unreachable!("streaming execution planned"),
            },
            resources,
            advance,
            error_context,
        )?
    };

    Records::collect(
        packed.into_iter().zip(&integrity).enumerate().map(
            |(member, (packed, &(input_size, crc32, hash)))| {
                Ok(CompressedMember {
                    input_size,
                    crc32,
                    hash,
                    // One rule, shared with the whole-member path and the legacy
                    // writers, plus the two cases that are not really fallbacks:
                    // storing was asked for, and an empty member has nothing to
                    // pack. `StoreFallback` refuses to store a solid member, whose
                    // successors decode against the dictionary it fills.
                    store: plan.method == 0
                        || input_size == 0
                        || should_store_compressed_payload(
                            input_size,
                            packed.len(),
                            plan.solid,
                            &plan.filter_policy,
                        ),
                    packed,
                    solid_continuation: plan.solid && member > 0,
                })
            },
        ),
        resources,
    )
}

#[allow(clippy::too_many_arguments)]
fn compress_streaming_members(
    sources: &[EntrySource],
    integrity: &mut [(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<Spool>> {
    let max_jobs_by_memory = resources.memory_limit() / required;
    if max_jobs_by_memory == 0 {
        resources
            .acquire_cancellable(required, plan.dictionary_size, &|| advance.is_cancelled())?;
        unreachable!("oversized workspace acquisition must fail");
    }
    let batch_capacity = usize::try_from(max_jobs_by_memory)
        .unwrap_or(usize::MAX)
        .min(crate::parallel::threads())
        .max(1);

    if plan.solid {
        compress_solid_chain(
            sources,
            integrity,
            plan,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
        )
    } else {
        compress_independent_members(
            sources,
            integrity,
            plan,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
        )
    }
}

/// Compresses independent whole members concurrently, with each workspace
/// admitted against the shared budget before its input is loaded.
///
/// The resolved plan schedules automatic-filter fallback outside whole-member
/// batches. Explicit filters retain their whole-member requirement and fail
/// admission when their workspace exceeds the budget.
#[allow(clippy::too_many_arguments)]
fn compress_members_whole(
    sources: &[EntrySource],
    integrity: &[(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    members: &[MemberPlan],
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<CompressedMember>> {
    let mut results = Records::new(sources.len(), resources)?;
    let mut start = 0;
    while start < sources.len() {
        if advance.is_cancelled() || resources.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if members[start].execution != Execution::WholeMember {
            results.push(
                compress_fallback_member(
                    start,
                    &sources[start],
                    integrity[start],
                    plan,
                    members[start].workspace,
                    resources,
                    advance,
                    error_context,
                )
                .map_err(|error| error_context(start, error))?,
            )?;
            start += 1;
            continue;
        }
        let (end, reserved) = whole_member_wave(
            members,
            start,
            crate::parallel::threads(),
            resources.memory_limit(),
        );
        // Acquire the entire wave on the coordinator. No dispatched worker
        // waits for workspace held by another worker in the same pool.
        let _permit = resources
            .acquire_cancellable(reserved, plan.dictionary_size, &|| advance.is_cancelled())
            .map_err(|error| error_context(start, error))?;
        let jobs = Records::collect((start..end).map(Ok), resources)?;
        let completed = run_jobs(jobs, resources, advance, |index, progress| {
            compress_whole_member(
                index,
                &sources[index],
                integrity[index],
                plan,
                resources,
                progress,
            )
            .map_err(|error| error_context(index, error))
        })?;
        for member in completed {
            results.push(member)?;
        }
        start = end;
    }
    Ok(results)
}

/// A contiguous wave fitting both the configured estimate and the worker count.
/// Include an oversized first job so admission reports its real requirement.
fn whole_member_wave(
    members: &[MemberPlan],
    start: usize,
    threads: usize,
    limit: u64,
) -> (usize, u64) {
    let mut reserved = members[start].workspace;
    let mut end = start + 1;
    while end < members.len() && end - start < threads.max(1) {
        if members[end].execution != Execution::WholeMember {
            break;
        }
        let Some(total) = reserved.checked_add(members[end].workspace) else {
            break;
        };
        if total > limit {
            break;
        }
        reserved = total;
        end += 1;
    }
    (end, reserved)
}

fn compress_whole_member(
    index: usize,
    source: &EntrySource,
    integrity: (u64, u32, [u8; 32]),
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
) -> Result<CompressedMember> {
    let (input_size, _, _) = integrity;
    let mut crc = Crc32::new();
    let mut hasher = blake2sp::Hasher::new();

    let mut packed_spool = Spool::create(resources)?;
    let mut stored = input_size == 0;
    if !stored {
        advance.started(index, input_size);
        if advance.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let size = usize::try_from(input_size)
            .map_err(|_| Error::InvalidArgument("entry size overflows usize"))?;
        let mut data = vec![0; size];
        let mut reader = source.open()?;
        for chunk in data.chunks_mut(plan.block_size.max(1)) {
            if advance.is_cancelled() {
                return Err(Error::Cancelled);
            }
            reader.read_exact(chunk)?;
            crc.update(chunk);
            hasher.update(chunk);
        }
        check_source_end(&mut *reader)?;
        // The filter search walks the member many times over, so
        // encoder positions are scaled down to the member's share
        // of that total: many passes, one member's worth of
        // progress.
        let walk = super::filter_policy_walk_bytes(
            &data,
            &plan.filter_policy,
            plan.algorithm_version,
            plan.candidates.len(),
        )
        .max(input_size)
        .max(1);
        let share =
            |bytes: u64| (u128::from(bytes) * u128::from(input_size) / u128::from(walk)) as u64;
        let mut reported = 0u64;
        let mut charged = 0u64;
        let mut report = |event| {
            let position = match event {
                crate::filter_search::EncodeProgress::PassStarted => {
                    reported = 0;
                    return !advance.is_cancelled();
                }
                crate::filter_search::EncodeProgress::Advanced(position) => position as u64,
            };
            let delta = position.saturating_sub(reported);
            reported = position;
            let target = (charged + delta).min(walk);
            let scaled = share(target) - share(charged);
            charged = target;
            advance.advance(scaled)
        };
        let packed = encode_member_with_filter_policy_candidates_and_progress(
            &data,
            plan.algorithm_version,
            &plan.filter_policy,
            &plan.candidates,
            Some(&mut report),
        )?;
        // An explicitly requested filter is not discarded just
        // because the result did not shrink.
        stored = should_store_compressed_payload(
            data.len() as u64,
            packed.len() as u64,
            plan.solid,
            &plan.filter_policy,
        );
        if !stored {
            packed_spool.write_all(&packed)?;
        }
    }

    if input_size == 0 {
        advance.started(index, input_size);
        if advance.is_cancelled() {
            return Err(Error::Cancelled);
        }
        check_source_end(&mut *source.open()?)?;
    }
    packed_spool.park();
    if !stored {
        source.release();
    }
    advance.finished(index, input_size);
    Ok(CompressedMember {
        input_size,
        crc32: crc.finish(),
        hash: hasher.finalize(),
        store: stored,
        packed: packed_spool,
        solid_continuation: false,
    })
}

/// Execute the planned automatic-filter fallback without re-entering planning.
/// Block execution uses only `encode_options`; filter search and the candidate
/// list belong to whole-member execution. Store fallback follows that unfiltered
/// base encoding, while the shared codec settings remain intact.
#[allow(clippy::too_many_arguments)]
fn compress_fallback_member(
    index: usize,
    source: &EntrySource,
    integrity: (u64, u32, [u8; 32]),
    plan: &CompressPlan,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<CompressedMember> {
    struct Remapped<'a> {
        index: usize,
        progress: &'a dyn CompressionProgress,
    }
    impl CompressionProgress for Remapped<'_> {
        fn is_cancelled(&self) -> bool {
            self.progress.is_cancelled()
        }
        fn advance(&self, bytes: u64) -> bool {
            self.progress.advance(bytes)
        }
        fn started(&self, _: usize, size: u64) {
            self.progress.started(self.index, size);
        }
        fn finished(&self, _: usize, size: u64) {
            self.progress.finished(self.index, size);
        }
    }
    if advance.is_cancelled() || resources.is_cancelled() {
        return Err(Error::Cancelled);
    }
    let mut integrity = [integrity];
    let mut packed = compress_streaming_members(
        std::slice::from_ref(source),
        &mut integrity,
        plan,
        required,
        resources,
        &Remapped {
            index,
            progress: advance,
        },
        &|_, error| error_context(index, error),
    )?;
    let packed = packed.pop().expect("one fallback member");
    let (input_size, crc32, hash) = integrity[0];
    Ok(CompressedMember {
        input_size,
        crc32,
        hash,
        store: input_size == 0
            || should_store_compressed_payload(
                input_size,
                packed.len(),
                false,
                &FilterPolicy::None,
            ),
        packed,
        solid_continuation: false,
    })
}

/// Members with independent dictionaries, interleaved so a batch of small
/// members can still saturate the machine.
#[allow(clippy::too_many_arguments)]
fn compress_independent_members(
    sources: &[EntrySource],
    integrity: &mut [(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<Spool>> {
    let mut packed = Records::new(sources.len(), resources)?;
    for (group_index, group) in sources.chunks(batch_capacity).enumerate() {
        let group_start = group_index * batch_capacity;
        let mut streams = Records::collect(
            group.iter().enumerate().map(|(offset, source)| {
                MemberStream::new(
                    group_start + offset,
                    source,
                    integrity[group_start + offset].0,
                    resources,
                    advance,
                )
                .map_err(|error| error_context(group_start + offset, error))
            }),
            resources,
        )?;

        let mut histories =
            Records::collect((0..streams.len()).map(|_| Ok(Vec::new())), resources)?;
        let mut cursor = 0usize;
        while streams.iter().any(MemberStream::has_more) {
            let reserved = required.saturating_mul(batch_capacity as u64);
            let _permit = resources
                .acquire_cancellable(reserved, plan.dictionary_size, &|| advance.is_cancelled())?;

            let mut jobs = Records::new(batch_capacity, resources)?;
            let mut misses = 0usize;
            while jobs.len() < batch_capacity && misses < streams.len() {
                let stream_count = streams.len();
                let member = cursor;
                let stream = &mut streams[member];
                cursor = (cursor + 1) % stream_count;
                if !stream.has_more() {
                    misses += 1;
                    continue;
                }
                misses = 0;

                let mut job = BlockJob {
                    data: Vec::new(),
                    history: histories[member].clone(),
                    blocks: Records::new(0, resources)?,
                };
                while stream.has_more() && job.data.len() < run_size(plan) {
                    job.data.extend(
                        read_block(stream, plan.block_size, advance)
                            .map_err(|error| error_context(stream.member, error))?,
                    );
                    job.blocks
                        .push_growing((member, job.data.len(), !stream.has_more()))?;
                }
                advance_history(
                    &mut histories[member],
                    &job.data,
                    plan.encode_options.max_match_distance,
                );
                jobs.push(job)?;
            }

            compress_wave(jobs, plan, &mut streams, resources, advance, error_context)?;
        }

        for stream in streams {
            let slot = &mut integrity[stream.member];
            slot.1 = stream.crc.finish();
            slot.2 = stream.hash.finalize();
            packed.push(stream.packed)?;
        }
    }
    Ok(packed)
}

/// One dictionary running through every member in order.
#[allow(clippy::too_many_arguments)]
fn compress_solid_chain(
    sources: &[EntrySource],
    integrity: &mut [(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<Spool>> {
    let mut streams = Records::collect(
        sources.iter().enumerate().map(|(member, source)| {
            MemberStream::new(member, source, integrity[member].0, resources, advance)
                .map_err(|error| error_context(member, error))
        }),
        resources,
    )?;

    let mut history: Vec<u8> = Vec::new();
    let mut next = 0usize;
    loop {
        let reserved = required.saturating_mul(batch_capacity as u64);
        let _permit = resources
            .acquire_cancellable(reserved, plan.dictionary_size, &|| advance.is_cancelled())?;

        // Run boundaries depend on input and dictionary size, never on the
        // worker count. Adjacent blocks amortize history copies and seeding.
        let mut jobs = Records::new(batch_capacity, resources)?;
        while jobs.len() < batch_capacity {
            let mut job = BlockJob {
                data: Vec::new(),
                history: history.clone(),
                blocks: Records::new(0, resources)?,
            };
            while job.data.len() < run_size(plan) {
                while next < streams.len() && !streams[next].has_more() {
                    next += 1;
                }
                let Some(stream) = streams.get_mut(next) else {
                    break;
                };
                job.data.extend(
                    read_block(stream, plan.block_size, advance)
                        .map_err(|error| error_context(stream.member, error))?,
                );
                job.blocks
                    .push_growing((stream.member, job.data.len(), !stream.has_more()))?;
            }
            if job.blocks.is_empty() {
                break;
            }
            advance_history(
                &mut history,
                &job.data,
                plan.encode_options.max_match_distance,
            );
            jobs.push(job)?;
        }

        if jobs.is_empty() {
            break;
        }
        compress_wave(jobs, plan, &mut streams, resources, advance, error_context)?;
    }

    Records::collect(
        streams.into_iter().map(|stream| {
            let slot = &mut integrity[stream.member];
            slot.1 = stream.crc.finish();
            slot.2 = stream.hash.finalize();
            Ok(stream.packed)
        }),
        resources,
    )
}

/// Reads the next block from `stream`, checking the source has not grown.
///
/// One chunk, then further chunks while the data is not moving, which is the
/// same question [`BlockSplitter`] answers for the buffered writer. Both have
/// to reach the same answer or the same input packs to two different archives.
fn read_block(
    stream: &mut MemberStream,
    block_size: usize,
    progress: &dyn CompressionProgress,
) -> Result<Vec<u8>> {
    if !stream.started {
        progress.started(stream.member, stream.input_size);
        stream.started = true;
    }
    let mut data = read_chunk(stream, block_size, progress)?;
    let mut splitter = BlockSplitter::new();
    splitter.accept(&data);
    while stream.has_more() {
        let next = read_chunk(stream, block_size, progress)?;
        if !splitter.extends(&next) {
            // Deciding needs the chunk in hand, so this reads one further than
            // it keeps. Hand it back for the next block rather than seeking
            // backwards, which an `EntryReader` cannot always do.
            stream.pushback = next;
            break;
        }
        splitter.accept(&next);
        data.extend_from_slice(&next);
    }
    Ok(data)
}

/// Reads one chunk, preferring anything a previous read put back.
fn read_chunk(
    stream: &mut MemberStream,
    block_size: usize,
    progress: &dyn CompressionProgress,
) -> Result<Vec<u8>> {
    if progress.is_cancelled() {
        return Err(Error::Cancelled);
    }
    if !stream.pushback.is_empty() {
        return Ok(std::mem::take(&mut stream.pushback));
    }
    let wanted = usize::try_from(stream.remaining.min(block_size as u64))
        .map_err(|_| Error::InvalidArgument("RAR 5 block size overflows usize"))?;
    let mut data = vec![0u8; wanted];
    // Solid planning can retain every member, but only the current input
    // needs a reader. Release it at EOF, even when a block has pushback.
    if stream.reader.is_none() {
        stream.reader = Some(stream.source.open()?);
    }
    let reader = stream.reader.as_mut().expect("opened above");
    reader.read_exact(&mut data)?;
    stream.crc.update(&data);
    stream.hash.update(&data);
    stream.remaining -= wanted as u64;
    if stream.remaining == 0 {
        check_source_end(&mut **reader)?;
        stream.reader = None;
    }
    Ok(data)
}

fn check_source_end(reader: &mut dyn Read) -> Result<()> {
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(Error::SourceChanged(
            "entry source size changed while compressing",
        ));
    }
    Ok(())
}

/// Extends the rolling window with `data`, dropping what has fallen out of
/// dictionary range.
fn advance_history(history: &mut Vec<u8>, data: &[u8], max_match_distance: usize) {
    if data.len() >= max_match_distance {
        history.clear();
        history.extend_from_slice(&data[data.len() - max_match_distance..]);
        return;
    }
    history.extend_from_slice(data);
    let keep_from = history.len().saturating_sub(max_match_distance);
    if keep_from != 0 {
        history.drain(..keep_from);
    }
}

/// Compresses a wave of blocks in parallel, then appends the results to their
/// members in job order so output does not depend on scheduling.
fn compress_wave(
    jobs: Records<BlockJob>,
    plan: &CompressPlan,
    streams: &mut [MemberStream],
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<()> {
    // All coordinator-owned boundary and result arrays are reserved before
    // dispatch, rather than letting workers compete for preparation capacity.
    let jobs = Records::collect(
        jobs.into_iter().map(|job| {
            let boundaries = Records::collect(
                job.blocks.iter().map(|&(_, end, last)| Ok((end, last))),
                resources,
            )?;
            let output = Records::new(job.blocks.len(), resources)?;
            Ok((job, boundaries, output))
        }),
        resources,
    )?;
    let packed_runs = run_jobs(
        jobs,
        resources,
        advance,
        |(job, boundaries, mut output), progress| {
            // Report each block from the worker that finished it. A run holds a
            // dictionary's worth of blocks and a wave holds one run per thread, so
            // reporting once the wave is appended is a single jump across the whole
            // member whenever the member fits one wave.
            let mut block_done = |bytes: usize| progress.advance(bytes as u64);
            let packed = encode_lz_streaming_blocks(
                &job.data,
                &job.history,
                &boundaries,
                plan.algorithm_version,
                plan.encode_options,
                Some(&mut block_done),
            )?;
            for ((member, _, last), packed) in job.blocks.into_iter().zip(packed) {
                output.push((member, packed, last))?;
            }
            Ok(output)
        },
    )?;
    // A solid wave can cover thousands of tiny members. Keep only the spool
    // currently being appended open, rather than one descriptor per member.
    let mut previous: Option<usize> = None;
    for (member, packed, last) in packed_runs.into_iter().flatten() {
        if previous != Some(member) {
            if let Some(previous) = previous {
                streams[previous].packed.park();
            }
            previous = Some(member);
        }
        streams[member]
            .packed
            .write_all(&packed)
            .map_err(|error| error_context(streams[member].member, error.into()))?;
        if last {
            let stream = &streams[member];
            if stream.input_size != 0
                && !should_store_compressed_payload(
                    stream.input_size,
                    stream.packed.len(),
                    plan.solid,
                    &plan.filter_policy,
                )
            {
                stream.source.release();
            }
            advance.finished(stream.member, stream.input_size);
        }
    }
    if let Some(previous) = previous {
        streams[previous].packed.park();
    }
    Ok(())
}

/// The compression-info vint for a member, including its solid flag.
pub(super) fn member_compression_info(
    plan: &CompressPlan,
    member: &CompressedMember,
) -> Result<u64> {
    compression_info(
        plan.algorithm_version,
        if member.store { 0 } else { plan.method },
        plan.dictionary_size,
        member.solid_continuation,
    )
}

#[cfg(test)]
pub(super) fn compress_members_reporting(
    sources: &[EntrySource],
    plan: CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
) -> Result<Vec<CompressedMember>> {
    compress_members_with_context(sources, &plan, resources, advance, &|_, error| error)
        .map(|members| members.into_iter().collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn whole_waves_admit_the_sum_without_crossing_fallbacks_or_overflowing() {
        let whole = |workspace| MemberPlan {
            execution: Execution::WholeMember,
            workspace,
        };
        let members = [whole(60), whole(40), whole(1), whole(u64::MAX)];
        assert_eq!(whole_member_wave(&members, 0, 4, 100), (2, 100));
        assert_eq!(whole_member_wave(&members, 0, 1, 100), (1, 60));
        assert_eq!(whole_member_wave(&members, 0, 4, 59), (1, 60));
        assert_eq!(whole_member_wave(&members, 2, 4, u64::MAX), (3, 1));
        let fallback = MemberPlan {
            execution: Execution::Blocks {
                fallback: super::super::plan::FallbackReason::AutomaticFilterWorkspace {
                    required: 100,
                    limit: 99,
                },
            },
            workspace: 10,
        };
        assert_eq!(
            whole_member_wave(&[whole(0), fallback, whole(0)], 0, 4, 0),
            (1, 0)
        );
    }

    #[test]
    fn coordinator_slots_are_admitted_before_callbacks_and_results_stay_charged() {
        use std::sync::atomic::AtomicUsize;
        let calls = AtomicUsize::new(0);
        let limited = WriterResources::default().with_max_preparation_bytes(16);
        let jobs = Records::collect([Ok(1u64), Ok(2)].into_iter(), &limited).unwrap();
        assert!(matches!(
            run_jobs(jobs, &limited, &|_| true, |job, _| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(job)
            }),
            Err(Error::WriterPreparationLimitExceeded { .. })
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        drop(Records::<u8>::new(16, &limited).unwrap());

        let resources = WriterResources::default().with_max_preparation_bytes(65536);
        for _ in 0..8 {
            let jobs = Records::collect([Ok(1u64), Ok(2)].into_iter(), &resources).unwrap();
            let output = run_jobs(jobs, &resources, &|_| true, |job, _| Ok(job * 2)).unwrap();
            assert_eq!(&*output, &[2, 4]);
            assert!(matches!(
                Records::<u8>::new(65536, &resources),
                Err(Error::WriterPreparationLimitExceeded { used: 16, .. })
            ));
            drop(output);
            drop(Records::<u8>::new(65536, &resources).unwrap());
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn failed_wave_skips_queued_sources_and_releases_successful_siblings() {
        use std::sync::atomic::AtomicUsize;
        struct Retained<'a>(&'a AtomicUsize);
        impl Drop for Retained<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let scratch = crate::scratch::case("coordinator-failure");
        let resources = WriterResources::new(100)
            .with_temp_dir(&*scratch)
            .with_max_preparation_bytes(65536);
        let calls = AtomicUsize::new(0);
        let drops = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let permit = resources.acquire(100, 0).unwrap();
        let jobs = Records::collect((0..3).map(Ok), &resources).unwrap();
        let result = pool.install(|| {
            run_jobs(jobs, &resources, &|_| true, |job, _| {
                calls.fetch_add(1, Ordering::Relaxed);
                assert_eq!(resources.workspace_in_use(), 100);
                if job == 1 {
                    return Err(Error::SourceChanged("test sibling failure"));
                }
                Ok((Retained(&drops), Spool::create(&resources)?))
            })
        });
        assert!(matches!(
            result,
            Err(Error::SourceChanged("test sibling failure"))
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(resources.workspace_in_use(), 100);
        drop(permit);
        assert_eq!(resources.workspace_in_use(), 0);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        drop(Records::<u8>::new(65536, &resources).unwrap());
        let jobs = Records::collect((0..3).map(Ok), &resources).unwrap();
        assert_eq!(
            pool.install(|| run_jobs(jobs, &resources, &|_| true, |job, _| Ok(job)))
                .unwrap()
                .len(),
            3
        );
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn sibling_failure_joins_running_work_and_keeps_the_original_error() {
        use std::sync::{atomic::AtomicUsize, Barrier};
        let resources = WriterResources::default().with_max_preparation_bytes(65536);
        let barrier = Barrier::new(2);
        let joined = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let jobs = Records::collect((0..2).map(Ok), &resources).unwrap();
        let result: Result<Records<()>> = pool.install(|| {
            run_jobs(jobs, &resources, &|_| true, |job, progress| {
                barrier.wait();
                if job == 1 {
                    return Err(Error::SourceChanged("original failure"));
                }
                while !progress.is_cancelled() {
                    std::thread::yield_now();
                }
                joined.fetch_add(1, Ordering::Relaxed);
                Err(Error::Cancelled)
            })
        });
        assert!(matches!(
            result,
            Err(Error::SourceChanged("original failure"))
        ));
        assert_eq!(joined.load(Ordering::Relaxed), 1);
        drop(Records::<u8>::new(65536, &resources).unwrap());
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn whole_member_sources_open_only_after_combined_admission() {
        use std::sync::{atomic::AtomicUsize, Arc};
        let encode_options = EncodeOptions::new(8).with_max_match_distance(65536);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options,
            dictionary_size: 65536,
            block_size: 65536,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![encode_options],
        };
        let required = whole_member_workspace(32, &plan);
        let scratch = crate::scratch::case("coordinator-admission");
        let resources = WriterResources::new(required * 2).with_temp_dir(&*scratch);
        let calls = Arc::new(AtomicUsize::new(0));
        let sources: Vec<_> = (0..4)
            .map(|_| {
                let resources = resources.clone();
                let calls = calls.clone();
                EntrySource::from_opener(32, move || {
                    assert_eq!(resources.workspace_in_use(), required * 2);
                    calls.fetch_add(1, Ordering::Relaxed);
                    Ok(Box::new(std::io::Cursor::new([42u8; 32])))
                })
            })
            .collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        drop(
            pool.install(|| compress_members_reporting(&sources, plan, &resources, &|_| true))
                .unwrap(),
        );
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        assert_eq!(resources.workspace_in_use(), 0);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }

    #[test]
    fn mixed_whole_and_fallback_members_keep_order_progress_and_cleanup() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        };
        struct Progress {
            events: Mutex<Vec<(bool, usize)>>,
            cancel: bool,
            stopped: AtomicBool,
        }
        impl CompressionProgress for Progress {
            fn advance(&self, _: u64) -> bool {
                !self.is_cancelled()
            }
            fn is_cancelled(&self) -> bool {
                self.stopped.load(Ordering::Relaxed)
            }
            fn started(&self, index: usize, _: u64) {
                self.events.lock().unwrap().push((true, index));
                if self.cancel && index == 1 {
                    self.stopped.store(true, Ordering::Relaxed);
                }
            }
            fn finished(&self, index: usize, _: u64) {
                self.events.lock().unwrap().push((false, index));
            }
        }
        let scratch = crate::scratch::case("planned-fallback");
        let data = b"planned automatic filter fallback\n".repeat(65536);
        let sources = [
            EntrySource::from_bytes(b"first".to_vec()),
            EntrySource::from_bytes(data.clone()),
            EntrySource::from_bytes(b"last".to_vec()),
        ];
        let encode_options = EncodeOptions::new(8).with_max_match_distance(128 * 1024);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options,
            dictionary_size: 128 * 1024,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![encode_options],
        };
        let resources = WriterResources::new(70 * 1024 * 1024).with_temp_dir(&*scratch);
        for cancel in [false, true] {
            let progress = Progress {
                events: Mutex::new(Vec::new()),
                cancel,
                stopped: AtomicBool::new(false),
            };
            let result = compress_members_reporting(&sources, plan.clone(), &resources, &progress);
            if cancel {
                assert!(matches!(result, Err(Error::Cancelled)));
                assert!(!progress.events.lock().unwrap().contains(&(true, 2)));
            } else {
                let mut members = result.unwrap();
                assert_eq!(members.len(), 3);
                for index in 0..3 {
                    let events = progress.events.lock().unwrap();
                    assert_eq!(
                        events
                            .iter()
                            .filter(|event| **event == (true, index))
                            .count(),
                        1
                    );
                    assert_eq!(
                        events
                            .iter()
                            .filter(|event| **event == (false, index))
                            .count(),
                        1
                    );
                }
                assert_eq!(members[1].hash, blake2sp::hash(&data));
                let mut fallback_bytes = Vec::new();
                members[1].packed.copy_to(&mut fallback_bytes).unwrap();
                let mut plain = compress_members_reporting(
                    &sources[1..2],
                    CompressPlan {
                        filter_policy: FilterPolicy::None,
                        ..plan.clone()
                    },
                    &resources,
                    &|_| true,
                )
                .unwrap();
                let mut plain_bytes = Vec::new();
                plain[0].packed.copy_to(&mut plain_bytes).unwrap();
                assert_eq!(fallback_bytes, plain_bytes);
            }
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn explicit_filter_pass_events_do_not_change_packed_bytes() {
        use crate::filter_search::EncodeProgress;
        let data: Vec<_> = (0..8192u32).flat_map(u32::to_le_bytes).collect();
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let plain = encode_member_with_filter_policy_candidates_and_progress(
            &data,
            0,
            &FilterPolicy::Auto,
            &[options, options],
            None,
        )
        .unwrap();
        let mut events = Vec::new();
        let reported = encode_member_with_filter_policy_candidates_and_progress(
            &data,
            0,
            &FilterPolicy::Auto,
            &[options, options],
            Some(&mut |event| {
                events.push(event);
                true
            }),
        )
        .unwrap();
        assert_eq!(plain, reported);
        assert!(
            events
                .iter()
                .filter(|&&event| event == EncodeProgress::PassStarted)
                .count()
                > 2
        );
        assert_eq!(events.first(), Some(&EncodeProgress::PassStarted));
    }

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn many_members_fit_a_small_descriptor_limit() {
        const CHILD: &str = "RARS_TEST_LOW_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new("sh")
                .args(["-c", "ulimit -n 64 && exec \"$@\"", "sh"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "rar50::write::compress::tests::many_members_fit_a_small_descriptor_limit",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("RAYON_NUM_THREADS", "2")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let scratch = crate::scratch::case("low-fd-members");
        let input = scratch.join("input");
        let data = b"many tiny archive members\n".repeat(8);
        std::fs::write(&input, &data).unwrap();
        let sources = vec![EntrySource::from_path(&input); 128];
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        for (method, solid, filter_policy) in [
            (0, false, FilterPolicy::None),
            (1, false, FilterPolicy::None),
            (1, true, FilterPolicy::None),
            (1, false, FilterPolicy::Auto),
        ] {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 65536,
                block_size: 65536,
                solid,
                method,
                filter_policy,
                candidates: vec![options],
            };
            let mut members =
                compress_members_reporting(&sources, plan, &resources, &|_| true).unwrap();
            assert_eq!(members.len(), sources.len());
            for member in &mut members {
                assert_eq!(member.input_size, data.len() as u64);
                assert_eq!(member.hash, blake2sp::hash(&data));
                let mut bytes = Vec::new();
                assert_eq!(
                    member.packed.copy_to(&mut bytes).unwrap(),
                    member.packed.len()
                );
                if method != 0 {
                    assert!(!bytes.is_empty());
                }
            }
            drop(members);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 1);
        }
    }

    #[test]
    fn solid_inputs_open_one_at_a_time_and_close_on_failure() {
        use std::io::{Cursor, Seek, SeekFrom};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        struct Tracked {
            data: Cursor<Vec<u8>>,
            live: Arc<AtomicUsize>,
        }
        impl Read for Tracked {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.data.read(bytes)
            }
        }
        impl Seek for Tracked {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.data.seek(pos)
            }
        }
        impl Drop for Tracked {
            fn drop(&mut self) {
                self.live.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let live = Arc::new(AtomicUsize::new(0));
        let sources: Vec<_> = (0..128)
            .map(|n| {
                let live = live.clone();
                EntrySource::from_opener(32, move || {
                    assert_eq!(live.fetch_add(1, Ordering::SeqCst), 0);
                    Ok(Box::new(Tracked {
                        data: Cursor::new(vec![n; 32]),
                        live: live.clone(),
                    }))
                })
            })
            .collect();
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 65536,
            solid: true,
            method: 1,
            filter_policy: FilterPolicy::None,
            candidates: vec![options],
        };
        let scratch = crate::scratch::case("lazy-solid-inputs");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let result =
            compress_members_reporting(&sources, plan.clone(), &resources, &|_| true).unwrap();
        assert_eq!(result.len(), sources.len());
        assert_eq!(live.load(Ordering::SeqCst), 0);
        drop(result);
        assert!(compress_members_reporting(&sources, plan, &resources, &|_| false).is_err());
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }

    #[test]
    fn whole_member_budget_includes_tree_and_parse_workspace() {
        let size = 16 * 1024 * 1024;
        let options = EncodeOptions::new(32)
            .with_max_match_distance(size)
            .with_optimal_parse(true);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: size as u64,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 3,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options],
        };
        let required = whole_member_workspace(size as u64, &plan);
        assert!(required >= (size * 12) as u64);
        assert!(matches!(
            WriterResources::new((size * 4 + 2 * 1024 * 1024) as u64)
                .acquire(required, size as u64),
            Err(Error::MemoryLimitExceeded { .. })
        ));
        // A large configured dictionary must not charge unreachable links.
        let mut larger = plan.clone();
        larger.encode_options.max_match_distance *= 2;
        assert_eq!(whole_member_workspace(size as u64, &larger), required);
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn whole_members_use_multiple_workers_without_changing_bytes() {
        use std::collections::HashSet;
        use std::sync::Mutex;
        let sources: Vec<_> = (0..8)
            .map(|n| {
                EntrySource::from_bytes(
                    format!("member {n}: independent text compression\n")
                        .repeat(1024)
                        .into_bytes(),
                )
            })
            .collect();
        let options = EncodeOptions::new(8);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 65536,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options],
        };
        let run = |threads, budget| {
            let workers = Mutex::new(HashSet::new());
            let result = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    compress_members_reporting(
                        &sources,
                        plan.clone(),
                        &WriterResources::new(budget),
                        &|_| {
                            workers.lock().unwrap().insert(std::thread::current().id());
                            true
                        },
                    )
                    .unwrap()
                    .into_iter()
                    .map(|mut member| {
                        let mut bytes = Vec::new();
                        member.packed.copy_to(&mut bytes).unwrap();
                        bytes
                    })
                    .collect::<Vec<_>>()
                });
            (result, workers.into_inner().unwrap().len())
        };
        let (serial, _) = run(1, 256 * 1024 * 1024);
        let (parallel, workers) = run(4, 256 * 1024 * 1024);
        assert_eq!(serial, parallel);
        assert!(workers > 1);
        let (limited, _) = run(
            4,
            whole_member_workspace(sources[0].len().unwrap(), &plan) * 2,
        );
        assert_eq!(serial, limited);
    }
    #[test]
    fn checksums_follow_the_compression_read_including_pushback_and_empty_members() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let mut data = vec![0; 65536];
        data.extend(std::iter::repeat_n(1, 65536));
        data.extend(std::iter::repeat_n(2, 65536));
        for policy in [FilterPolicy::None, FilterPolicy::Auto] {
            for solid in [false, true] {
                let opens = Arc::new(AtomicUsize::new(0));
                let sources: Vec<_> = [data.clone(), Vec::new()]
                    .into_iter()
                    .map(|data| {
                        let opens = Arc::clone(&opens);
                        EntrySource::from_opener(data.len() as u64, move || {
                            opens.fetch_add(1, Ordering::SeqCst);
                            Ok(Box::new(std::io::Cursor::new(data.clone())))
                        })
                    })
                    .collect();
                let options = EncodeOptions::new(8).with_max_match_distance(131072);
                let plan = CompressPlan {
                    algorithm_version: 0,
                    encode_options: options,
                    dictionary_size: 131072,
                    block_size: 65536,
                    solid,
                    method: 1,
                    filter_policy: policy.clone(),
                    candidates: vec![options],
                };
                let members = compress_members_reporting(
                    &sources,
                    plan,
                    &WriterResources::default(),
                    &|_| true,
                )
                .unwrap();
                assert_eq!(
                    opens.load(Ordering::SeqCst),
                    2,
                    "policy={policy:?}, solid={solid}"
                );
                for (member, input) in members.iter().zip([data.as_slice(), &[]]) {
                    let mut crc = Crc32::new();
                    crc.update(input);
                    assert_eq!(member.crc32, crc.finish());
                    assert_eq!(member.hash, blake2sp::hash(input));
                }
            }
        }
    }
}
