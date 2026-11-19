//! Turning member sources into packed payloads with workspace admission.
//!
//! RAR 5 compresses in independent blocks: a block depends only on its own
//! bytes and on up to a dictionary's worth of the raw input that precedes it.
//! Since that preceding input is just the file being read, the history a block
//! needs is known before any compression happens, and blocks can be compressed
//! in parallel while their packed output is written back in order.
//!
//! A member too large to filter whole chooses filters run by run. The window
//! then holds filtered bytes, so its runs pick filters in one parallel pass and
//! take their histories from the filtered runs before them in a second.
//!
//! Non-solid members each carry their own history. A wave takes a member's
//! runs in order until it runs out and then moves to the next, so several
//! small members keep every core busy, and a large member's runs in a wave
//! share one window between them. Solid members share one history
//! chain that runs across member boundaries, so their blocks are produced by a
//! single walk through the members in order — the walk is just reading, which
//! is cheap, so waves of blocks still compress in parallel.

#[cfg(test)]
use super::filter_policy::encode_member_with_filter_policy_candidates_and_progress;
use super::filter_policy::{
    candidates_with_allowance, compression_info, should_store_compressed_payload,
    within_filter_reach,
};
use super::FilterPolicy;
use crate::codec::packed_chain::{PackedMatchFinder, SharedPackedIndex};
use crate::codec::rar50::EncodeOptions;
use crate::codec::rar50::{
    filter_streaming_blocks_in_place, streaming_blocks_in_window, streaming_blocks_with_finder,
    BlockSplitter, EncodeFilter,
};
use crate::codec::workspace::{Allowance, Budget, Buffer};
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
    let output = Records::new(jobs.len(), resources)?;
    let slots = Records::collect(jobs.into_iter().map(|job| Ok((Some(job), None))), resources)?;
    complete_jobs(slots, output, resources, progress, |_, job, progress| {
        map(job, progress)
    })
}

type JobSlot<T, O> = (Option<T>, Option<Result<O>>);

fn complete_jobs<T: Send, O: Send>(
    mut slots: Records<JobSlot<T, O>>,
    mut output: Records<O>,
    resources: &WriterResources,
    progress: &dyn CompressionProgress,
    map: impl Fn(usize, T, &dyn CompressionProgress) -> Result<O> + Sync + Send,
) -> Result<Records<O>> {
    let batch = BatchProgress {
        progress,
        resources,
        stopped: AtomicBool::new(false),
    };
    crate::parallel::for_each_mut(&mut slots, |index, (job, result)| {
        if batch.is_cancelled() {
            return;
        }
        let mapped = map(index, job.take().expect("one callback per slot"), &batch);
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

/// Admit fixed worker scopes only after coordinator slots have capacity. Keep
/// every reservation until all callbacks join, then retire unused capacity;
/// output owners remain charged after return. No worker can extend its scope.
fn run_jobs_admitted<T: Send, O: Send>(
    jobs: Records<T>,
    resources: &WriterResources,
    progress: &dyn CompressionProgress,
    required: impl Fn(&T) -> u64,
    map: impl Fn(
            T,
            &WriterResources,
            &dyn CompressionProgress,
            &crate::codec::workspace::Limited,
        ) -> Result<O>
        + Sync
        + Send,
) -> Result<Records<O>> {
    let ledger = resources
        .execution
        .as_ref()
        .expect("admitted execution ledger");
    let output = Records::new(jobs.len(), resources)?;
    let slots = Records::collect(jobs.into_iter().map(|job| Ok((Some(job), None))), resources)?;
    let mut reservations = Records::new(slots.len(), resources)?;
    for (job, _) in slots.iter() {
        if progress.is_cancelled() || resources.is_cancelled() {
            return Err(Error::Cancelled);
        }
        reservations.push(ledger.reserve(required(job.as_ref().unwrap()))?)?;
    }
    for reservation in reservations.iter_mut() {
        reservation.start();
    }
    let result = complete_jobs(
        slots,
        output,
        resources,
        progress,
        |index, job, progress| {
            let allowance = reservations[index].allowance();
            let worker = resources
                .clone()
                .with_execution_allowance(allowance.clone());
            map(job, &worker, progress, &allowance)
        },
    );
    for reservation in reservations {
        reservation.retire();
    }
    result
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
use super::plan::{filter_search_bytes, Execution, ExecutionPlan, MemberPlan};

/// A bounded run of adjacent blocks, sharing one copy of the preceding input.
struct BlockJob<B: Budget> {
    data: Buffer<u8, B>,
    history: Buffer<u8, B>,
    /// Member index, end within `data`, and final-block flag.
    blocks: Records<(usize, usize, bool)>,
    /// Where `data` starts in its member. Only filtered runs read it.
    offset: usize,
    /// Filters ranged over `data`. A run with any is coded as one filtered
    /// stream, cut where its filter records fit rather than at `blocks`.
    filters: Records<crate::FilterSpec>,
    /// In a solid run, where each member's bytes lie in `data` and how far
    /// into the member they start. A solid run can hold several members, and
    /// a filter converts by position in its own.
    segments: Records<(std::ops::Range<usize>, usize)>,
    /// In a solid run that was filtered, each block's filter records. `data`
    /// already holds the filtered bytes, and the blocks stay as they were.
    records: Option<Buffer<Buffer<EncodeFilter, B>, B>>,
    /// The run's part of a window and index it shares with other runs of its
    /// member in the wave. `data` and `history` are empty when this is set.
    shared: Option<SharedRun<B>>,
}

/// A run's part of its group's window, and for a run that walks chains, a
/// finder over the group's index standing where the run's own would.
struct SharedRun<B: Budget> {
    window: std::sync::Arc<Buffer<u8, B>>,
    /// Where the run starts and ends in `window`.
    start: usize,
    end: usize,
    /// None for a run that searches a tree, which it builds for itself.
    finder: Option<PackedMatchFinder<B>>,
    /// For a filtered run, the blocks it is coded in and their records. Its
    /// part of `window` already holds the filtered bytes.
    filtered: Option<crate::codec::rar50::FilteredRunBlocks<B>>,
}

/// The most a shared window holds. A packed index keeps positions in 32 bits
/// with room for its records, as a job's own does (`packed_index_fits`), and
/// a shared one refuses a window past 1 GiB.
const SHARED_WINDOW_LIMIT: usize = u32::MAX as usize / 6;

/// Gives each member's consecutive runs in a wave one window between them,
/// and the runs that walk chains one packed index over it, where they each
/// held a window and built an index over it (#276). Neighbouring runs'
/// windows overlap, so a group of sixteen holds seventeen runs' bytes rather
/// than thirty-two, and indexes them once.
///
/// The output does not change. A run joins only when its own window would
/// have used a packed index or a tree; its window is the group's cut off where
/// the run ends, so positions past it stay out of reach. A run that searches a
/// tree trims the window to a dictionary before its start and seeds its tree
/// from there, as it would its own. A run that walks chains gets a finder
/// standing where the run's own would. The chains then hold extra positions
/// only from before the run's own window, which its distance floor stops at,
/// and its distance limit works out the same: a run whose own window starts
/// at the member's start is in a group whose window does too, and any other
/// carries a whole dictionary of history.
///
/// A filtered run's part of the window holds its filtered bytes, which is
/// what its own window held and what later runs' histories hold. It joins
/// only when it has history, as it always has.
///
/// In a solid `chain`, the wave's runs are consecutive runs of one stream
/// that crosses members, so they group as one. A filtered run there already
/// holds its filtered bytes and carries its blocks' records, and joins on the
/// same terms.
fn share_member_windows<B: Budget + Send + Sync>(
    jobs: &mut [BlockJob<B>],
    plan: &CompressPlan,
    chain: bool,
    allowance: &B,
) -> Result<()>
where
    B::Charge: Send,
{
    let options = plan.encode_options;
    if !options.optimal_parse {
        return Ok(());
    }
    let dictionary = options.max_match_distance;
    let own_window = |job: &BlockJob<B>| job.history.len().min(dictionary) + job.data.len();
    let shareable = |job: &BlockJob<B>| {
        let plain = job.filters.is_empty() && job.records.is_none();
        let (window, start) = (own_window(job), job.history.len().min(dictionary));
        (plain || start != 0)
            && (crate::codec::rar50::searches_tree(window, start, options)
                || crate::codec::rar50::packed_index_fits(window, start, options))
    };
    let next_to = |before: &BlockJob<B>, after: &BlockJob<B>| {
        chain || before.offset + before.data.len() == after.offset
    };
    let mut members: Vec<usize> = jobs.iter().map(|job| job.blocks[0].0).collect();
    members.sort_unstable();
    members.dedup();
    if chain {
        members.truncate(1);
    }
    let mut groups: Vec<(Vec<usize>, usize)> = Vec::new();
    for member in members {
        // Jobs are taken from a member in order, so its runs here are
        // consecutive in the list's order; a chain's are all one stream.
        let runs: Vec<usize> = (0..jobs.len())
            .filter(|&index| chain || jobs[index].blocks[0].0 == member)
            .collect();
        let mut group: Vec<usize> = Vec::new();
        let mut window_len = 0usize;
        for index in runs.into_iter().chain(std::iter::once(usize::MAX)) {
            let joins = index != usize::MAX && shareable(&jobs[index]) && {
                match group.last() {
                    None => own_window(&jobs[index]) <= SHARED_WINDOW_LIMIT,
                    Some(&last) => {
                        next_to(&jobs[last], &jobs[index])
                            && window_len + jobs[index].data.len() <= SHARED_WINDOW_LIMIT
                    }
                }
            };
            if joins {
                window_len += if group.is_empty() {
                    own_window(&jobs[index])
                } else {
                    jobs[index].data.len()
                };
                group.push(index);
                continue;
            }
            if group.len() > 1 {
                groups.push((std::mem::take(&mut group), window_len));
            }
            group.clear();
            window_len = 0;
            if index != usize::MAX && shareable(&jobs[index]) {
                window_len = own_window(&jobs[index]);
                group.push(index);
            }
        }
    }

    // A wave of small members holds many groups. Each is built on its own
    // part of the pool, as their jobs built their own indexes before, rather
    // than one after another.
    let mut slots: Vec<Option<&mut BlockJob<B>>> = jobs.iter_mut().map(Some).collect();
    let mut builds: Vec<_> = groups
        .into_iter()
        .map(|(indices, window_len)| {
            let group: Vec<&mut BlockJob<B>> = indices
                .into_iter()
                .map(|index| slots[index].take().expect("a run joins one group"))
                .collect();
            (group, window_len, Ok(()))
        })
        .collect();
    crate::parallel::for_each_mut(&mut builds, |_, (group, window_len, result)| {
        *result = share_group(group, *window_len, options, allowance);
    });
    builds.into_iter().try_for_each(|(_, _, result)| result)
}

fn share_group<B: Budget + Send + Sync>(
    group: &mut [&mut BlockJob<B>],
    window_len: usize,
    options: EncodeOptions,
    allowance: &B,
) -> Result<()>
where
    B::Charge: Send,
{
    let dictionary = options.max_match_distance;
    let first = &group[0];
    let history = &first.history[first.history.len().saturating_sub(dictionary)..];
    let mut window = Buffer::with_capacity(window_len, allowance)?;
    window
        .extend_from_slice(history)
        .map_err(Into::<crate::codec::Error>::into)?;
    let mut bounds = Vec::with_capacity(group.len());
    let mut at = Vec::with_capacity(group.len());
    for job in group.iter_mut() {
        let start = window.len();
        window
            .extend_from_slice(&job.data)
            .map_err(Into::<crate::codec::Error>::into)?;
        let end = window.len();
        // Where the run's own collector would start: at the run, never past
        // where the run's window can insert.
        at.push(start.min(end.saturating_sub(3)));
        bounds.push((start, end));
        job.data = Buffer::new(allowance);
    }

    // Filtered runs are filtered where they lie, each on its own thread, as
    // each job filtered its own copy before.
    struct Piece<'a, B: Budget> {
        bytes: &'a mut [u8],
        job: &'a BlockJob<B>,
        filtered: Option<crate::codec::Result<crate::codec::rar50::FilteredRunBlocks<B>>>,
    }
    let mut pieces = Vec::with_capacity(group.len());
    let mut rest: &mut [u8] = &mut window[bounds[0].0..];
    for (job, &(start, end)) in group.iter().zip(&bounds) {
        let (bytes, after) = rest.split_at_mut(end - start);
        rest = after;
        pieces.push(Piece {
            bytes,
            job,
            filtered: None,
        });
    }
    crate::parallel::for_each_mut(&mut pieces, |_, piece| {
        let job = piece.job;
        if !job.filters.is_empty() {
            let last = job.blocks.last().is_some_and(|&(_, _, last)| last);
            piece.filtered = Some(crate::codec::rar50::filter_run_in_place(
                piece.bytes,
                &job.filters,
                job.offset,
                last,
                allowance,
            ));
        }
    });
    let filtered = pieces
        .into_iter()
        .map(|piece| piece.filtered.transpose())
        .collect::<crate::codec::Result<Vec<_>>>()?;

    for (job, &(start, _)) in group.iter_mut().zip(&bounds) {
        debug_assert!(
            job.history[job.history.len().saturating_sub(dictionary)..]
                == window[start.saturating_sub(dictionary.min(job.history.len()))..start],
            "a grouped run's history is the window before it"
        );
        job.history = Buffer::new(allowance);
    }
    // Only the runs that walk chains want the index; a run that searches a
    // tree seeds its own from the window.
    let chains: Vec<bool> = bounds
        .iter()
        .map(|&(start, end)| {
            let skip = start.saturating_sub(dictionary);
            !crate::codec::rar50::searches_tree(end - skip, start - skip, options)
        })
        .collect();
    let chain_at: Vec<usize> = at
        .iter()
        .zip(&chains)
        .filter_map(|(&at, &chain)| chain.then_some(at))
        .collect();
    let mut finders = if chain_at.is_empty() {
        Buffer::new(allowance)
    } else {
        SharedPackedIndex::finders_over(&window, &chain_at, allowance)?
    }
    .into_iter();
    let window = std::sync::Arc::new(window);
    let runs = group.iter_mut().zip(bounds).zip(chains).zip(filtered);
    for (((job, (start, end)), chain), filtered) in runs {
        let finder = if chain { finders.next() } else { None };
        job.shared = Some(SharedRun {
            window: std::sync::Arc::clone(&window),
            start,
            end,
            finder,
            filtered,
        });
    }
    Ok(())
}

impl<B: Budget> BlockJob<B> {
    fn append(&mut self, data: Buffer<u8, B>) -> Result<()> {
        if self.data.is_empty() {
            self.data = data;
        } else {
            self.data
                .extend_from_slice(&data)
                .map_err(Into::<crate::codec::Error>::into)?;
        }
        Ok(())
    }
}

pub(super) fn run_size(plan: &CompressPlan) -> usize {
    plan.encode_options
        .max_match_distance
        .max(crate::codec::rar50::MAX_LZ_BLOCK_SIZE)
}

/// A member being read, and the packed bytes it has produced so far.
struct MemberStream<B: Budget> {
    member: usize,
    input_size: u64,
    started: bool,
    source: EntrySource,
    reader: Option<Box<dyn crate::EntryReader>>,
    remaining: u64,
    packed: Spool,
    /// A chunk read to decide a block boundary and not used by that block.
    pushback: Buffer<u8, B>,
    /// How much of the member has gone into jobs so far.
    placed: usize,
    crc: Crc32,
    hash: blake2sp::Hasher,
}

impl<B: Budget> MemberStream<B> {
    fn new(
        member: usize,
        source: &EntrySource,
        size: u64,
        resources: &WriterResources,
        progress: &dyn CompressionProgress,
        allowance: &B,
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
            pushback: Buffer::new(allowance),
            placed: 0,
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
    let packed = match execution {
        ExecutionPlan::IndependentMembers(members) => {
            return compress_members_whole(
                sources,
                &integrity,
                plan,
                &members,
                resources,
                advance,
                error_context,
            );
        }
        // Storing is not "compress and hope it does not help": the header
        // records method zero, so the payload must be the source bytes.
        ExecutionPlan::Stored => {
            for (index, (source, (input_size, crc, hash))) in
                sources.iter().zip(&mut integrity).enumerate()
            {
                advance.started(index, *input_size);
                (*crc, *hash) = super::source_integrity(
                    source,
                    *input_size,
                    plan.block_size,
                    advance,
                    resources,
                )
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
        }
        ExecutionPlan::Blocks {
            workspace,
            run_filters,
        } => compress_streaming_members(
            sources,
            &mut integrity,
            plan,
            run_filters,
            workspace,
            resources,
            advance,
            error_context,
        )?,
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
    run_filters: bool,
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

    if let Some(allowance) = &resources.execution {
        let encode = if plan.solid {
            compress_solid_chain::<crate::codec::workspace::Limited>
        } else {
            compress_independent_members::<crate::codec::workspace::Limited>
        };
        return encode(
            sources,
            integrity,
            plan,
            run_filters,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
            allowance,
        );
    }

    if plan.solid {
        compress_solid_chain(
            sources,
            integrity,
            plan,
            run_filters,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
            &Allowance::default(),
        )
    } else {
        compress_independent_members(
            sources,
            integrity,
            plan,
            run_filters,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
            &Allowance::default(),
        )
    }
}

/// Keep estimated codec admission separate from actual coordinator capacity.
/// Assembly runs on the coordinator; workers receive only their fixed scopes.
/// Retained history and spool capacity reduce the next wave's available space.
fn streaming_wave_capacity(
    maximum: usize,
    _required: u64,
    _plan: &CompressPlan,
    _resources: &WriterResources,
) -> usize {
    if let Some(ledger) = &_resources.execution {
        // Run growth/replacement, block assembly and history copies coexist.
        // Descriptor capacity is still checked by its owners before dispatch.
        let assembly = (run_size(_plan) as u64)
            .saturating_mul(8)
            .saturating_add((_plan.block_size as u64).saturating_mul(4));
        let per_job = _required
            .saturating_add(assembly)
            .saturating_add(crate::codec::workspace::RESERVATION_BYTES);
        return maximum
            .min(usize::try_from(ledger.available() / per_job.max(1)).unwrap_or(usize::MAX))
            .max(1);
    }
    maximum
}

/// Compresses independent whole members concurrently, with each workspace
/// admitted against the shared budget before its input is loaded.
///
/// The resolved plan schedules filter fallback outside whole-member batches.
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
        if let Execution::Blocks { run_filters, .. } = members[start].execution {
            // Consecutive fallback members share waves, so a set of mid-size
            // members fills the machine instead of running one member's two
            // or three runs at a time. Each member keeps its own runs,
            // history and filters, so the bytes do not depend on the grouping.
            let end = start
                + members[start..]
                    .iter()
                    .take_while(|member| {
                        matches!(
                            member.execution,
                            Execution::Blocks { run_filters: same, .. } if same == run_filters
                        )
                    })
                    .count();
            let required = members[start..end]
                .iter()
                .map(|member| member.workspace)
                .max()
                .unwrap_or(0);
            for member in compress_fallback_members(
                start,
                &sources[start..end],
                &integrity[start..end],
                plan,
                run_filters,
                required,
                resources,
                advance,
                error_context,
            )? {
                results
                    .push(member)
                    .expect("one compression result per source was admitted");
            }
            start = end;
            continue;
        }
        let (end, reserved) = whole_member_wave(
            members,
            start,
            crate::parallel::threads(),
            resources.memory_limit(),
        );
        let (end, reserved) = if let Some(ledger) = &resources.execution {
            let slot_bytes = std::mem::size_of::<usize>()
                + std::mem::size_of::<CompressedMember>()
                + std::mem::size_of::<JobSlot<usize, CompressedMember>>()
                + std::mem::size_of::<crate::codec::workspace::Reservation>();
            whole_member_wave_with_slots(
                members,
                start,
                crate::parallel::threads(),
                resources.memory_limit(),
                slot_bytes as u64 + crate::codec::workspace::RESERVATION_BYTES,
                ledger.available(),
            )
        } else {
            (end, reserved)
        };
        // Acquire the entire wave on the coordinator. No dispatched worker
        // waits for workspace held by another worker in the same pool.
        let _permit = resources
            .acquire_cancellable(reserved, plan.dictionary_size, &|| advance.is_cancelled())
            .map_err(|error| error_context(start, error))?;
        let jobs = Records::collect((start..end).map(Ok), resources)?;
        let unlimited = |jobs| {
            run_jobs(jobs, resources, advance, |index, progress| {
                compress_whole_member(
                    index,
                    &sources[index],
                    integrity[index],
                    plan,
                    resources,
                    progress,
                    &Allowance::default(),
                )
                .map_err(|error| error_context(index, error))
            })
        };
        let completed = if resources.execution.is_some() {
            run_jobs_admitted(
                jobs,
                resources,
                advance,
                |index| members[*index].workspace,
                |index, worker, progress, allowance| {
                    compress_whole_member(
                        index,
                        &sources[index],
                        integrity[index],
                        plan,
                        worker,
                        progress,
                        allowance,
                    )
                    .map_err(|error| error_context(index, error))
                },
            )?
        } else {
            unlimited(jobs)?
        };
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
    whole_member_wave_with_slots(members, start, threads, limit, 0, u64::MAX)
}

fn whole_member_wave_with_slots(
    members: &[MemberPlan],
    start: usize,
    max_jobs: usize,
    limit: u64,
    slot_bytes: u64,
    capacity: u64,
) -> (usize, u64) {
    let mut reserved = members[start].workspace;
    let mut end = start + 1;
    while end < members.len() && end - start < max_jobs.max(1) {
        if members[end].execution != Execution::WholeMember {
            break;
        }
        let Some(total) = reserved.checked_add(members[end].workspace) else {
            break;
        };
        if total > limit
            || total.saturating_add(slot_bytes.saturating_mul((end - start + 1) as u64)) > capacity
        {
            break;
        }
        reserved = total;
        end += 1;
    }
    (end, reserved)
}

fn compress_whole_member<B: Budget>(
    index: usize,
    source: &EntrySource,
    integrity: (u64, u32, [u8; 32]),
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    allowance: &B,
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
        let mut data = Buffer::filled(size, 0, allowance)?;
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
        let packed = candidates_with_allowance(
            &data,
            plan.algorithm_version,
            &plan.filter_policy,
            &plan.candidates,
            Some(&mut report),
            allowance,
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

/// Execute the planned filter fallback without re-entering planning. Block
/// execution uses only `encode_options` and filters each run; the candidate
/// list belongs to whole-member execution.
#[allow(clippy::too_many_arguments)]
fn compress_fallback_members(
    first: usize,
    sources: &[EntrySource],
    integrity: &[(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    run_filters: bool,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<CompressedMember>> {
    struct Remapped<'a> {
        first: usize,
        progress: &'a dyn CompressionProgress,
    }
    impl CompressionProgress for Remapped<'_> {
        fn is_cancelled(&self) -> bool {
            self.progress.is_cancelled()
        }
        fn advance(&self, bytes: u64) -> bool {
            self.progress.advance(bytes)
        }
        fn started(&self, member: usize, size: u64) {
            self.progress.started(self.first + member, size);
        }
        fn finished(&self, member: usize, size: u64) {
            self.progress.finished(self.first + member, size);
        }
    }
    if advance.is_cancelled() || resources.is_cancelled() {
        return Err(Error::Cancelled);
    }
    let mut integrity = Records::collect(integrity.iter().copied().map(Ok), resources)?;
    let packed = compress_streaming_members(
        sources,
        &mut integrity,
        plan,
        run_filters,
        required,
        resources,
        &Remapped {
            first,
            progress: advance,
        },
        &|member, error| error_context(first + member, error),
    )
    .map_err(|error| error_context(first, error))?;
    Records::collect(
        packed
            .into_iter()
            .zip(integrity.iter())
            .map(|(packed, &(input_size, crc32, hash))| {
                Ok(CompressedMember {
                    input_size,
                    crc32,
                    hash,
                    store: should_store_compressed_payload(
                        input_size,
                        packed.len(),
                        false,
                        &plan.filter_policy,
                    ),
                    packed,
                    solid_continuation: false,
                })
            }),
        resources,
    )
}

/// Members with independent dictionaries. A wave takes each member's runs in
/// order until it runs out, then the next member's, so a batch of small
/// members still saturates the machine and a large member's runs in a wave
/// are consecutive, which is what lets them share a window and an index.
/// Taking one run from each member in turn left every run of a member in a
/// wave of its own whenever there were as many members as threads.
///
/// A run is coded from its own bytes and its member's history, so which
/// runs share a wave never changes the archive. With `filter_runs`, each run
/// chooses its own filters.
#[allow(clippy::too_many_arguments)]
fn compress_independent_members<B: Budget + Send + Sync>(
    sources: &[EntrySource],
    integrity: &mut [(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    filter_runs: bool,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    allowance: &B,
) -> Result<Records<Spool>>
where
    B::Charge: Send,
{
    let mut packed = Records::new(sources.len(), resources)?;
    let mut group_start = 0;
    while group_start < sources.len() {
        let group_capacity = streaming_wave_capacity(batch_capacity, required, plan, resources);
        let group_end = group_start
            .saturating_add(group_capacity)
            .min(sources.len());
        let group = &sources[group_start..group_end];
        let mut streams = Records::collect(
            group.iter().enumerate().map(|(offset, source)| {
                MemberStream::new(
                    group_start + offset,
                    source,
                    integrity[group_start + offset].0,
                    resources,
                    advance,
                    allowance,
                )
                .map_err(|error| error_context(group_start + offset, error))
            }),
            resources,
        )?;

        let mut histories = Records::collect(
            (0..streams.len()).map(|_| Ok(Buffer::new(allowance))),
            resources,
        )?;
        let mut offsets = Records::collect((0..streams.len()).map(|_| Ok(0usize)), resources)?;
        let mut cursor = 0usize;
        while streams.iter().any(MemberStream::has_more) {
            let wave_capacity = streaming_wave_capacity(batch_capacity, required, plan, resources);
            let reserved = required.saturating_mul(wave_capacity as u64);
            let _permit = resources
                .acquire_cancellable(reserved, plan.dictionary_size, &|| advance.is_cancelled())?;

            let mut jobs = Records::new(wave_capacity, resources)?;
            let mut misses = 0usize;
            while jobs.len() < wave_capacity && misses < streams.len() {
                let member = cursor;
                let stream = &mut streams[member];
                if !stream.has_more() {
                    cursor = (cursor + 1) % streams.len();
                    misses += 1;
                    continue;
                }
                misses = 0;

                let mut job = BlockJob {
                    data: Buffer::new(allowance),
                    // A filtered run's history is the window the decoder will
                    // hold, which is not known until the runs before it have
                    // chosen their filters.
                    history: if filter_runs {
                        Buffer::new(allowance)
                    } else {
                        Buffer::copied(&histories[member], allowance)?
                    },
                    blocks: Records::new(0, resources)?,
                    offset: offsets[member],
                    filters: Records::new(0, resources)?,
                    segments: Records::new(0, resources)?,
                    records: None,
                    shared: None,
                };
                while stream.has_more() && job.data.len() < run_size(plan) {
                    job.append(
                        read_block(stream, plan.block_size, advance)
                            .map_err(|error| error_context(stream.member, error))?,
                    )?;
                    job.blocks
                        .push_growing((member, job.data.len(), !stream.has_more()))?;
                }
                offsets[member] += job.data.len();
                if filter_runs {
                    // Histories are kept below, once the filters are known.
                } else if stream.has_more() {
                    histories[member]
                        .remember(&job.data, plan.encode_options.max_match_distance)?;
                } else {
                    // The final job already owns its input and preceding
                    // history. No later job can read this member's retained
                    // buffer, so release it instead of copying terminal bytes.
                    histories[member] = Buffer::new(allowance);
                }
                jobs.push(job)?;
            }

            if filter_runs {
                if let FilterPolicy::Explicit(spec) = &plan.filter_policy {
                    for job in jobs.iter_mut() {
                        explicit_run_filter(job, spec)?;
                    }
                } else {
                    let concurrent = jobs.len();
                    choose_run_filters(&mut jobs, concurrent, plan, required, resources, advance)?;
                }
                for job in jobs.iter_mut() {
                    let (member, _, _) = job.blocks[0];
                    let last = job.blocks.last().is_some_and(|&(_, _, last)| last);
                    job.history = Buffer::copied(&histories[member], allowance)?;
                    if last {
                        histories[member] = Buffer::new(allowance);
                    } else if job.filters.is_empty() {
                        histories[member]
                            .remember(&job.data, plan.encode_options.max_match_distance)?;
                    } else {
                        let window = crate::codec::rar50::filtered_run_bytes(
                            &job.data,
                            &job.filters,
                            job.offset,
                            allowance,
                        )?;
                        histories[member]
                            .remember(&window, plan.encode_options.max_match_distance)?;
                    }
                }
            }

            if resources.execution.is_none() {
                share_member_windows(&mut jobs, plan, false, allowance)?;
            }
            compress_wave(
                jobs,
                plan,
                required,
                &mut streams,
                resources,
                advance,
                error_context,
            )?;
        }

        for stream in streams {
            let slot = &mut integrity[stream.member];
            slot.1 = stream.crc.finish();
            slot.2 = stream.hash.finalize();
            packed.push(stream.packed)?;
        }
        group_start = group_end;
    }
    Ok(packed)
}

/// One dictionary running through every member in order.
#[allow(clippy::too_many_arguments)]
fn compress_solid_chain<B: Budget + Send + Sync>(
    sources: &[EntrySource],
    integrity: &mut [(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    filter_runs: bool,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    allowance: &B,
) -> Result<Records<Spool>>
where
    B::Charge: Send,
{
    let mut streams = Records::collect(
        sources.iter().enumerate().map(|(member, source)| {
            MemberStream::new(
                member,
                source,
                integrity[member].0,
                resources,
                advance,
                allowance,
            )
            .map_err(|error| error_context(member, error))
        }),
        resources,
    )?;

    let mut history = Buffer::new(allowance);
    let mut next = 0usize;
    loop {
        let wave_capacity = streaming_wave_capacity(batch_capacity, required, plan, resources);
        let reserved = required.saturating_mul(wave_capacity as u64);
        let _permit = resources
            .acquire_cancellable(reserved, plan.dictionary_size, &|| advance.is_cancelled())?;

        // Run boundaries depend on input and dictionary size, never on the
        // worker count. Adjacent blocks amortize history copies and seeding.
        let mut jobs = Records::new(wave_capacity, resources)?;
        while jobs.len() < wave_capacity {
            while next < streams.len() && !streams[next].has_more() {
                next += 1;
            }
            if next == streams.len() {
                break;
            }
            let mut job = BlockJob {
                data: Buffer::new(allowance),
                // A filtered run's history is the window the decoder will
                // hold, which is not known until the runs before it have
                // chosen their filters.
                history: if filter_runs {
                    Buffer::new(allowance)
                } else {
                    Buffer::copied(&history, allowance)?
                },
                blocks: Records::new(0, resources)?,
                offset: 0,
                filters: Records::new(0, resources)?,
                segments: Records::new(0, resources)?,
                records: None,
                shared: None,
            };
            while job.data.len() < run_size(plan) {
                while next < streams.len() && !streams[next].has_more() {
                    next += 1;
                }
                let Some(stream) = streams.get_mut(next) else {
                    break;
                };
                let start = job.data.len();
                job.append(
                    read_block(stream, plan.block_size, advance)
                        .map_err(|error| error_context(stream.member, error))?,
                )?;
                job.blocks
                    .push_growing((stream.member, job.data.len(), !stream.has_more()))?;
                if filter_runs {
                    let block = job.data.len() - start;
                    match job.segments.last_mut() {
                        Some((segment, _)) if stream.placed != 0 && segment.end == start => {
                            segment.end += block;
                        }
                        _ => job
                            .segments
                            .push_growing((start..start + block, stream.placed))?,
                    }
                    stream.placed += block;
                }
            }
            // The outer loop found a stream with data, so this job contains
            // at least that stream's next block.
            if !filter_runs {
                history.remember(&job.data, plan.encode_options.max_match_distance)?;
            }
            jobs.push(job)?;
        }

        if filter_runs && !jobs.is_empty() {
            // A solid run can hold many members, each searched on its own.
            // The wave reserved workspace for `wave_capacity` jobs whether or
            // not it filled that many, so that many searches fit at once.
            choose_run_filters(&mut jobs, wave_capacity, plan, required, resources, advance)?;
            for job in jobs.iter_mut() {
                job.history = Buffer::copied(&history, allowance)?;
                if !job.filters.is_empty() {
                    let boundaries = Records::collect(
                        job.blocks.iter().map(|&(_, end, last)| Ok((end, last))),
                        resources,
                    )?;
                    job.records = Some(filter_streaming_blocks_in_place(
                        &mut job.data,
                        &boundaries,
                        &job.filters,
                        &job.segments,
                        allowance,
                    )?);
                    // The filters are in the bytes now. Left here they would
                    // send the run down the one-member filtered path.
                    job.filters = Records::new(0, resources)?;
                }
                history.remember(&job.data, plan.encode_options.max_match_distance)?;
            }
        }

        if jobs.is_empty() {
            break;
        }
        if resources.execution.is_none() {
            share_member_windows(&mut jobs, plan, true, allowance)?;
        }
        compress_wave(
            jobs,
            plan,
            required,
            &mut streams,
            resources,
            advance,
            error_context,
        )?;
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
fn read_block<B: Budget>(
    stream: &mut MemberStream<B>,
    block_size: usize,
    progress: &dyn CompressionProgress,
) -> Result<Buffer<u8, B>> {
    if !stream.started {
        progress.started(stream.member, stream.input_size);
        stream.started = true;
    }
    let mut data = read_chunk(stream, block_size, progress)?;
    let mut splitter = BlockSplitter::new();
    splitter.accept(&data);
    while stream.has_more() {
        let next = read_chunk(stream, block_size, progress)?;
        if !splitter.try_extend(&next) {
            // Deciding needs the chunk in hand, so this reads one further than
            // it keeps. Hand it back for the next block rather than seeking
            // backwards, which an `EntryReader` cannot always do.
            stream.pushback = next;
            break;
        }
        data.extend_from_slice(&next)
            .map_err(Into::<crate::codec::Error>::into)?;
    }
    Ok(data)
}

/// Reads one chunk, preferring anything a previous read put back.
fn read_chunk<B: Budget>(
    stream: &mut MemberStream<B>,
    block_size: usize,
    progress: &dyn CompressionProgress,
) -> Result<Buffer<u8, B>> {
    if progress.is_cancelled() {
        return Err(Error::Cancelled);
    }
    if !stream.pushback.is_empty() {
        return Ok({
            let empty = Buffer::new(&stream.pushback.allowance());
            std::mem::replace(&mut stream.pushback, empty)
        });
    }
    let wanted = usize::try_from(stream.remaining.min(block_size as u64))
        .map_err(|_| Error::InvalidArgument("RAR 5 block size overflows usize"))?;
    let mut data = Buffer::filled(wanted, 0u8, &stream.pushback.allowance())?;
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

/// The part of an explicit filter that falls in a job's run, ranged over it.
fn explicit_run_filter<B: Budget>(job: &mut BlockJob<B>, spec: &crate::FilterSpec) -> Result<()> {
    if let Some(range) = explicit_run_range(spec, job.offset..job.offset + job.data.len()) {
        job.filters
            .push_growing(crate::FilterSpec::range(spec.kind, range))?;
    }
    Ok(())
}

/// The part of `spec` that falls in `run`, a range of its member, ranged over
/// the run. Nothing past [`FILTER_REACH`](super::filter_policy::FILTER_REACH)
/// is filtered, so a run there is coded as it is, and no later run fails
/// after the earlier ones were written.
fn explicit_run_range(
    spec: &crate::FilterSpec,
    run: std::ops::Range<usize>,
) -> Option<std::ops::Range<usize>> {
    let range = within_filter_reach(spec.range.clone().unwrap_or(run.clone()));
    let (start, end) = (range.start.max(run.start), range.end.min(run.end));
    (start < end).then(|| start - run.start..end - run.start)
}

/// Chooses each run's filters, in parallel and against the same admission as
/// the wave that will code them: at most `concurrent` searches at a time,
/// which is as many as the wave has workspace reserved for.
///
/// A run is searched in pieces of
/// [`FILTER_SEARCH_BYTES`](super::plan::FILTER_SEARCH_BYTES), so one search
/// fits the budget whatever the dictionary, and the pieces' ranges are offset
/// into the run.
fn choose_run_filters<B: Budget + Send + Sync>(
    jobs: &mut Records<BlockJob<B>>,
    concurrent: usize,
    plan: &CompressPlan,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
) -> Result<()>
where
    B::Charge: Send,
{
    // A piece is a stretch of one member: the bytes to search and how far
    // into the member they start. A solid run holds a segment per member; any
    // other run is all one member's.
    let piece = filter_search_bytes();
    let mut pieces = Records::new(0, resources)?;
    for (index, job) in jobs.iter().enumerate() {
        let whole = [(0..job.data.len(), job.offset)];
        let segments = if job.segments.is_empty() {
            &whole[..]
        } else {
            &job.segments[..]
        };
        for (segment, file_offset) in segments {
            let mut start = segment.start;
            while start < segment.end {
                let end = (start + piece).min(segment.end);
                pieces.push_growing((index, start..end, file_offset + (start - segment.start)))?;
                start = end;
            }
        }
    }
    let mut chosen = Records::new(pieces.len(), resources)?;
    for batch in pieces.chunks(concurrent.max(1)) {
        let searches = Records::collect(
            batch.iter().map(|(index, range, file_offset)| {
                Ok((&jobs[*index].data[range.clone()], *file_offset))
            }),
            resources,
        )?;
        let found = if resources.execution.is_some() {
            run_jobs_admitted(
                searches,
                resources,
                advance,
                |_| required,
                |(data, offset), worker, progress, allowance| {
                    let specs = super::filter_policy::run_filters_with_allowance(
                        data,
                        offset,
                        plan.algorithm_version,
                        plan.encode_options,
                        &|| progress.is_cancelled(),
                        allowance,
                    )?;
                    Records::collect(specs.iter().cloned().map(Ok), worker)
                },
            )?
        } else {
            run_jobs(searches, resources, advance, |(data, offset), progress| {
                let specs = super::filter_policy::run_filters_with_allowance(
                    data,
                    offset,
                    plan.algorithm_version,
                    plan.encode_options,
                    &|| progress.is_cancelled(),
                    &Allowance::default(),
                )?;
                Records::collect(specs.iter().cloned().map(Ok), resources)
            })?
        };
        for specs in found {
            chosen.push(specs)?;
        }
    }
    for ((index, range, _), specs) in pieces.iter().zip(chosen) {
        let filters = &mut jobs[*index].filters;
        for spec in specs {
            let span = spec.range.map_or(range.clone(), |r| {
                range.start + r.start..range.start + r.end
            });
            filters.push_growing(crate::FilterSpec::range(spec.kind, span))?;
        }
    }
    Ok(())
}

/// Compresses a wave of blocks in parallel, then appends the results to their
/// members in job order so output does not depend on scheduling.
fn compress_wave<B: Budget + Send + Sync>(
    jobs: Records<BlockJob<B>>,
    plan: &CompressPlan,
    _required: u64,
    streams: &mut [MemberStream<B>],
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<()>
where
    B::Charge: Send,
{
    if resources.execution.is_some() {
        let jobs = prepare_block_jobs::<B, crate::codec::workspace::Limited>(jobs, resources)?;
        let packed_runs = run_jobs_admitted(
            jobs,
            resources,
            advance,
            |_| _required,
            |job, _, progress, allowance| encode_block_job(job, plan, progress, allowance),
        )?;
        return append_packed_runs(packed_runs, plan, streams, advance, error_context);
    }
    let jobs = prepare_block_jobs::<B, B>(jobs, resources)?;
    let packed_runs = run_jobs(jobs, resources, advance, |job, progress| {
        let allowance = job.0.data.allowance();
        if job.0.shared.is_some() {
            return encode_shared_block_job(job, plan, progress, &allowance);
        }
        encode_block_job(job, plan, progress, &allowance)
    })?;
    append_packed_runs(packed_runs, plan, streams, advance, error_context)
}

type PackedBlocks<B> = Records<(usize, Buffer<u8, B>, bool)>;
type PreparedBlockJob<B, C> = (BlockJob<B>, Records<(usize, bool)>, PackedBlocks<C>);

fn prepare_block_jobs<B: Budget, C: Budget>(
    jobs: Records<BlockJob<B>>,
    resources: &WriterResources,
) -> Result<Records<PreparedBlockJob<B, C>>> {
    // Allocate boundary and result descriptors before dispatch. Worker outputs
    // carry their scoped codec charge; descriptor arrays keep the root charge.
    Records::collect(
        jobs.into_iter().map(|job| {
            let boundaries = Records::collect(
                job.blocks.iter().map(|&(_, end, last)| Ok((end, last))),
                resources,
            )?;
            let output = Records::new(job.blocks.len(), resources)?;
            Ok((job, boundaries, output))
        }),
        resources,
    )
}

fn encode_block_job<B: Budget, C: Budget>(
    (job, boundaries, mut output): PreparedBlockJob<B, C>,
    plan: &CompressPlan,
    progress: &dyn CompressionProgress,
    allowance: &C,
) -> Result<PackedBlocks<C>> {
    if !job.filters.is_empty() {
        let (member, _, last) = *job.blocks.last().expect("a job holds a block");
        let mut reported = 0usize;
        let mut run_progress = |position: usize| {
            let delta = position.saturating_sub(reported);
            reported = reported.max(position);
            progress.advance(delta as u64)
        };
        let packed = crate::codec::rar50::encode_filtered_run(
            &job.data,
            &job.filters,
            &job.history,
            job.offset,
            last,
            plan.algorithm_version,
            plan.encode_options,
            Some(&mut run_progress),
            allowance,
        )?;
        if reported < job.data.len() && !progress.advance((job.data.len() - reported) as u64) {
            return Err(Error::Cancelled);
        }
        output.push((member, packed, last))?;
        return Ok(output);
    }
    let mut block_done = |bytes: usize| progress.advance(bytes as u64);
    // The records were made under the job's own budget and the encoder charges
    // this worker's, so they cross over as a copy.
    let records = match &job.records {
        Some(records) => Some(Buffer::try_collect(
            records.iter().map(|block| Buffer::copied(block, allowance)),
            allowance,
        )?),
        None => None,
    };
    let BlockJob {
        data,
        history,
        blocks,
        ..
    } = job;
    // The encoder parses history and run as one window. Grow the history into
    // it and let the run go, rather than have the encoder copy both into a
    // third buffer for the whole encode.
    let start = history.len();
    let window = if start == 0 {
        data
    } else {
        let mut window = history;
        window
            .extend_from_slice(&data)
            .map_err(Into::<crate::codec::Error>::into)?;
        drop(data);
        window
    };
    let packed = streaming_blocks_in_window(
        &window,
        start,
        &boundaries,
        records.as_deref(),
        plan.algorithm_version,
        plan.encode_options,
        Some(&mut block_done),
        allowance,
    )?;
    drop(window);
    for ((member, _, last), packed) in blocks.into_iter().zip(packed) {
        output.push((member, packed, last))?;
    }
    Ok(output)
}

/// A run that shares its member's window and index with the other runs of
/// the wave, coded by the same block walk as one with its own.
fn encode_shared_block_job<B: Budget>(
    (job, boundaries, mut output): PreparedBlockJob<B, B>,
    plan: &CompressPlan,
    progress: &dyn CompressionProgress,
    allowance: &B,
) -> Result<PackedBlocks<B>> {
    let BlockJob {
        blocks,
        shared,
        records: solid_records,
        ..
    } = job;
    let SharedRun {
        window,
        start,
        end,
        finder,
        filtered,
    } = shared.expect("dispatched as a shared run");
    let mut block_done = |bytes: usize| progress.advance(bytes as u64);
    let (cuts, records) = match &filtered {
        Some((cuts, records)) => (&cuts[..], Some(&records[..])),
        None => (&boundaries[..], solid_records.as_deref()),
    };
    let packed = match finder {
        Some(finder) => streaming_blocks_with_finder(
            &window[..end],
            start,
            finder,
            cuts,
            records,
            plan.algorithm_version,
            plan.encode_options,
            Some(&mut block_done),
            allowance,
        )?,
        None => streaming_blocks_in_window(
            &window[..end],
            start,
            cuts,
            records,
            plan.algorithm_version,
            plan.encode_options,
            Some(&mut block_done),
            allowance,
        )?,
    };
    drop(window);
    if filtered.is_some() {
        // A filtered run is coded as one stream, as `encode_block_job` codes
        // it, cut where its records fit rather than at `blocks`.
        let (member, _, last) = *blocks.last().expect("a job holds a block");
        let mut run = Buffer::new(allowance);
        for block in packed {
            run.extend_from_slice(&block)
                .map_err(Into::<crate::codec::Error>::into)?;
        }
        output.push((member, run, last))?;
        return Ok(output);
    }
    for ((member, _, last), packed) in blocks.into_iter().zip(packed) {
        output.push((member, packed, last))?;
    }
    Ok(output)
}

fn append_packed_runs<B: Budget, C: Budget>(
    packed_runs: Records<PackedBlocks<C>>,
    plan: &CompressPlan,
    streams: &mut [MemberStream<B>],
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<()> {
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
            // A completed block run always came from `has_more`, so an empty
            // member cannot reach this branch.
            if !should_store_compressed_payload(
                stream.input_size,
                stream.packed.len(),
                plan.solid,
                &plan.filter_policy,
            ) {
                stream.source.release();
            }
            advance.finished(stream.member, stream.input_size);
        }
    }
    // Both wave builders dispatch only non-empty jobs, and every job emits
    // one packed block for each recorded boundary.
    let previous = previous.expect("compression wave contains a packed block");
    streams[previous].packed.park();
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
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn explicit_filter_runs_past_4_gib_are_coded_unfiltered() {
        use super::super::filter_policy::FILTER_REACH;
        let e8 = crate::FilterKind::E8;
        let run = 1 << 20;
        let whole = crate::FilterSpec::whole(e8);
        let at = |start: usize| start..start + run;
        // Runs before 4 GiB keep the whole filter.
        assert_eq!(
            super::explicit_run_range(&whole, at(FILTER_REACH - 2 * run)),
            Some(0..run)
        );
        // The run 4 GiB falls in is filtered up to it.
        assert_eq!(
            super::explicit_run_range(&whole, at(FILTER_REACH - 10)),
            Some(0..10)
        );
        // Runs past it carry no filter, so the encoder never sees an offset
        // it refuses.
        for start in [FILTER_REACH, FILTER_REACH + 1, 3 * FILTER_REACH] {
            assert_eq!(super::explicit_run_range(&whole, at(start)), None);
            let ranged = crate::FilterSpec::range(e8, 0..start + run);
            assert_eq!(super::explicit_run_range(&ranged, at(start)), None);
        }
        // A range is still cut to the run it falls in.
        let ranged = crate::FilterSpec::range(e8, 100..FILTER_REACH + 100);
        assert_eq!(super::explicit_run_range(&ranged, at(0)), Some(100..run));
        assert_eq!(super::explicit_run_range(&ranged, at(run)), Some(0..run));
        assert_eq!(
            super::explicit_run_range(&ranged, at(2 * run)),
            Some(0..run)
        );
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn stream_creation_failure_keeps_member_context_before_opening_source() {
        let scratch = crate::scratch::case("stream-creation-context");
        for solid in [false, true] {
            let resources = WriterResources::new(128 * 1024 * 1024)
                .with_max_memory_bytes(128 * 1024 * 1024)
                .with_temp_dir(scratch.join("missing-directory"));
            let options = EncodeOptions::new(8).with_max_match_distance(65536);
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 65536,
                block_size: 65536,
                solid,
                method: 1,
                filter_policy: FilterPolicy::None,
                candidates: vec![options].into(),
            };
            let source = EntrySource::from_opener(1, || {
                panic!("spool creation must fail before opening the source")
            });
            let error = compress_members_with_context(
                &[source],
                &plan,
                &resources,
                &|_| true,
                &|index, error| {
                    assert_eq!(index, 0);
                    error.at_entry(b"unopened.bin".to_vec(), "compressing")
                },
            )
            .err()
            .unwrap();
            assert_eq!(error.kind(), crate::ErrorKind::Io);
            assert_eq!(
                error.entry_context(),
                Some((b"unopened.bin".as_slice(), "compressing"))
            );
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(resources.managed_memory_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn cancellation_after_wave_check_keeps_admission_error_context() {
        struct CancelAfterObservation(crate::WriteCancellation);
        impl CompressionProgress for CancelAfterObservation {
            fn advance(&self, _: u64) -> bool {
                !self.0.is_cancelled()
            }
            fn is_cancelled(&self) -> bool {
                // Model cancellation arriving just after the observation.
                let observed = self.0.is_cancelled();
                self.0.cancel();
                observed
            }
        }
        let scratch = crate::scratch::case("wave-admission-context");
        let resources = WriterResources::new(128 * 1024 * 1024).with_temp_dir(&*scratch);
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 65536,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options].into(),
        };
        let execution = ExecutionPlan::with_resources(&plan, [32].into_iter(), &resources).unwrap();
        let ExecutionPlan::IndependentMembers(members) = execution else {
            panic!("expected whole-member plan");
        };
        assert_eq!(members[0].execution, Execution::WholeMember);
        let source = EntrySource::from_opener(32, || {
            panic!("cancelled admission must precede source opening")
        });
        let progress = CancelAfterObservation(crate::WriteCancellation::new());
        let error = compress_members_whole(
            &[source],
            &[(32, 0, [0; 32])],
            &plan,
            &members,
            &resources,
            &progress,
            &|index, error| {
                assert_eq!(index, 0);
                error.at_entry(b"waiting.bin".to_vec(), "compressing")
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
        assert_eq!(
            error.entry_context(),
            Some((b"waiting.bin".as_slice(), "compressing"))
        );
        assert_eq!(resources.workspace_in_use(), 0);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }

    #[test]
    fn streaming_compression_releases_each_refused_preparation_allocation() {
        use std::sync::atomic::Ordering;

        let scratch = crate::scratch::case("streaming-preparation-refusals");
        let sources = [EntrySource::from_bytes(vec![b'A'; 2048])];
        let options = EncodeOptions::new(8);
        for solid in [false, true] {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 65536,
                block_size: 1024,
                solid,
                method: 1,
                filter_policy: FilterPolicy::None,
                candidates: vec![options].into(),
            };
            let run = |resources: &WriterResources| -> Result<()> {
                let packed =
                    compress_members_reporting(&sources, plan.clone(), resources, &|_| true)?;
                assert_eq!(packed.len(), 1);
                Ok(())
            };
            let (resources, attempts) = WriterResources::default()
                .with_temp_dir(&*scratch)
                .refuse_preparation_growth_at(usize::MAX);
            run(&resources).unwrap();
            let count = attempts.load(Ordering::Relaxed);
            assert!(count > 5);
            assert!(count < 100);
            assert_eq!(resources.preparation_in_use(), 0);

            for index in 0..count {
                let (resources, _) = WriterResources::default()
                    .with_temp_dir(&*scratch)
                    .refuse_preparation_growth_at(index);
                let error = run(&resources).unwrap_err();
                assert_eq!(
                    error.root_cause(),
                    &Error::WriterFailure("injected preparation admission failure"),
                    "solid mode {solid}, admission {index}"
                );
                assert_eq!(resources.preparation_in_use(), 0, "admission {index}");
                assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
            }
        }
    }

    #[test]
    fn admitted_whole_member_worker_propagates_source_failure() {
        let options = EncodeOptions::new(8);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 1024,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::None,
            candidates: vec![options, options].into(),
        };
        let source = EntrySource::from_opener(1024, || {
            Err(std::io::Error::other("injected worker source failure").into())
        });
        let resources =
            WriterResources::new(70 * 1024 * 1024).with_max_memory_bytes(70 * 1024 * 1024);
        let error = compress_members_reporting(&[source], plan, &resources, &|_| true)
            .err()
            .expect("the admitted worker must report its source failure");
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(resources.workspace_in_use(), 0);
        assert_eq!(resources.execution.as_ref().unwrap().used(), 0);
    }

    #[test]
    fn stored_member_descriptor_refusal_releases_preparation_charge() {
        let options = EncodeOptions::new(8);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 128 * 1024,
            block_size: 4096,
            solid: false,
            method: 0,
            filter_policy: FilterPolicy::None,
            candidates: vec![options].into(),
        };
        let source = EntrySource::from_bytes(b"payload".to_vec());
        let limit = std::mem::size_of::<(u64, u32, [u8; 32])>() as u64;
        let resources = WriterResources::default().with_max_preparation_bytes(limit);
        let error = compress_members_reporting(&[source], plan, &resources, &|_| true)
            .err()
            .expect("the stored spool descriptors must exceed the integrity record");
        assert!(matches!(
            error,
            Error::WriterPreparationLimitExceeded {
                limit: actual_limit,
                used,
                ..
            } if actual_limit == limit && used == limit
        ));
        drop(Records::<u8>::new(limit as usize, &resources).unwrap());
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn whole_member_cancellation_after_start_does_not_open_source() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct StopAfterStart(AtomicBool);
        impl CompressionProgress for StopAfterStart {
            fn advance(&self, _: u64) -> bool {
                !self.is_cancelled()
            }
            fn is_cancelled(&self) -> bool {
                self.0.load(Ordering::SeqCst)
            }
            fn started(&self, _: usize, _: u64) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let scratch = crate::scratch::case("whole-member-cancel-after-start");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let options = EncodeOptions::new(8);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 128 * 1024,
            block_size: 4096,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::None,
            candidates: vec![options].into(),
        };
        for size in [0, 16] {
            let source = EntrySource::from_opener(size, || {
                panic!("cancelled compression must not open the source")
            });
            let progress = StopAfterStart(AtomicBool::new(false));
            assert!(matches!(
                compress_whole_member(
                    0,
                    &source,
                    (size, 0, [0; 32]),
                    &plan,
                    &resources,
                    &progress,
                    &Allowance::default(),
                ),
                Err(Error::Cancelled)
            ));
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn whole_member_cancellation_between_waves_does_not_open_next_source() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct StopAfterFirst {
            finished: AtomicBool,
            checks_after_finish: AtomicUsize,
            resource_cancellation: Option<crate::WriteCancellation>,
        }
        impl CompressionProgress for StopAfterFirst {
            fn advance(&self, _: u64) -> bool {
                !self.is_cancelled()
            }
            fn is_cancelled(&self) -> bool {
                // Let the completed wave return its result, then cancel at
                // the coordinator's check before admitting the next wave.
                if !self.finished.load(Ordering::SeqCst) {
                    return false;
                }
                if self.checks_after_finish.fetch_add(1, Ordering::SeqCst) == 0 {
                    return false;
                }
                if let Some(token) = &self.resource_cancellation {
                    token.cancel();
                    false
                } else {
                    true
                }
            }
            fn finished(&self, index: usize, _: u64) {
                if index == 0 {
                    self.finished.store(true, Ordering::SeqCst);
                }
            }
        }

        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 65536,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options].into(),
        };
        let scratch = crate::scratch::case("whole-member-cancel-between-waves");
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        for resource_cancellation in [false, true] {
            let first = EntrySource::from_bytes(b"first".to_vec());
            let second = EntrySource::from_opener(6, || {
                panic!("cancellation between waves must not open the next source")
            });
            let token = resource_cancellation.then(crate::WriteCancellation::new);
            let mut resources = WriterResources::new(80 * 1024 * 1024).with_temp_dir(&*scratch);
            if let Some(token) = &token {
                resources = resources.with_cancellation(token.clone());
            }
            let progress = StopAfterFirst {
                finished: AtomicBool::new(false),
                checks_after_finish: AtomicUsize::new(0),
                resource_cancellation: token.clone(),
            };
            let result = pool.install(|| {
                compress_members_reporting(&[first, second], plan.clone(), &resources, &progress)
            });
            assert!(
                matches!(result, Err(Error::Cancelled)),
                "{:?}",
                result.err()
            );
            if let Some(token) = &token {
                assert!(token.is_cancelled());
            } else {
                assert!(progress.is_cancelled());
            }
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    struct Cancelled;

    impl CompressionProgress for Cancelled {
        fn advance(&self, _: u64) -> bool {
            false
        }

        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_prevents_worker_dispatch_and_empty_source_open() {
        let resources = WriterResources::default();
        let jobs = Records::collect([1u8].into_iter().map(Ok), &resources).unwrap();
        assert_eq!(
            run_jobs(jobs, &resources, &Cancelled, |_, _| -> Result<u8> {
                panic!("cancelled job was dispatched")
            })
            .err()
            .unwrap(),
            Error::Cancelled
        );

        let ledger = crate::codec::workspace::Allowance::limited(1024 * 1024);
        let admitted = resources.with_execution_allowance(ledger.clone());
        let jobs = Records::collect([1u8].into_iter().map(Ok), &admitted).unwrap();
        assert_eq!(
            run_jobs_admitted(
                jobs,
                &admitted,
                &Cancelled,
                |_| 1,
                |_, _, _, _| -> Result<u8> { panic!("cancelled job was admitted") },
            )
            .err()
            .unwrap(),
            Error::Cancelled
        );
        assert_eq!(ledger.used(), 0);

        let cancellation = crate::WriteCancellation::new();
        let admitted = WriterResources::default()
            .with_cancellation(cancellation.clone())
            .with_execution_allowance(ledger.clone());
        let jobs = Records::collect([1u8].into_iter().map(Ok), &admitted).unwrap();
        cancellation.cancel();
        assert_eq!(
            run_jobs_admitted(
                jobs,
                &admitted,
                &|_| true,
                |_| 1,
                |_, _, _, _| -> Result<u8> { panic!("cancelled resource dispatched a job") },
            )
            .err()
            .unwrap(),
            Error::Cancelled
        );
        assert_eq!(ledger.used(), 0);

        let source = EntrySource::from_opener(0, || panic!("empty source was opened"));
        assert_eq!(
            MemberStream::new(
                0,
                &source,
                0,
                &WriterResources::default(),
                &Cancelled,
                &crate::codec::workspace::Allowance::default(),
            )
            .err()
            .unwrap(),
            Error::Cancelled
        );
    }

    #[test]
    fn a_codec_failure_takes_precedence_over_sibling_cancellation() {
        let resources = WriterResources::default();
        let jobs = Records::collect(
            [
                (None::<u8>, Some(Err::<u8, _>(Error::Cancelled))),
                (None, Some(Err(Error::InvalidArgument("codec failure")))),
            ]
            .into_iter()
            .map(Ok),
            &resources,
        )
        .unwrap();
        let output = Records::new(2, &resources).unwrap();
        assert_eq!(
            complete_jobs(
                jobs,
                output,
                &resources,
                &Cancelled,
                |_, _, _| -> Result<u8> {
                    panic!("cancelled worker overwrote its recorded result")
                }
            )
            .err()
            .unwrap(),
            Error::InvalidArgument("codec failure")
        );

        let jobs = Records::collect(
            [
                (
                    None::<u8>,
                    Some(Err::<u8, _>(Error::InvalidArgument("first"))),
                ),
                (None, Some(Err(Error::InvalidArgument("second")))),
            ]
            .into_iter()
            .map(Ok),
            &resources,
        )
        .unwrap();
        let output = Records::new(2, &resources).unwrap();
        assert_eq!(
            complete_jobs(
                jobs,
                output,
                &resources,
                &Cancelled,
                |_, _, _| -> Result<u8> {
                    panic!("cancelled worker overwrote its recorded result")
                }
            )
            .err()
            .unwrap(),
            Error::InvalidArgument("first")
        );
    }

    #[test]
    fn compression_guards_sources_before_start_and_fallback() {
        struct Untouched;
        impl crate::streaming::SourceFactory for Untouched {
            fn len(&self) -> Result<u64> {
                panic!("cancelled compression measured a source")
            }
            fn open(&self) -> Result<Box<dyn crate::EntryReader>> {
                panic!("cancelled compression opened a source")
            }
        }
        let options = EncodeOptions::new(8);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 128 * 1024,
            block_size: 4096,
            solid: false,
            method: 0,
            filter_policy: FilterPolicy::None,
            candidates: vec![options].into(),
        };
        let resources = WriterResources::default();
        let source = EntrySource::from_factory(Untouched);
        assert_eq!(
            compress_members_with_context(&[source], &plan, &resources, &Cancelled, &|_, error| {
                error
            })
            .err()
            .unwrap(),
            Error::Cancelled
        );
        assert_eq!(
            compress_members_with_context(
                &[EntrySource::from_bytes(b"payload".to_vec())],
                &plan,
                &resources,
                &|_| false,
                &|_, error| error,
            )
            .err()
            .unwrap(),
            Error::Cancelled
        );
        let token = crate::WriteCancellation::new();
        token.cancel();
        let resources = WriterResources::default().with_cancellation(token);
        assert_eq!(
            compress_members_with_context(
                &[EntrySource::from_factory(Untouched)],
                &plan,
                &resources,
                &|_| true,
                &|_, error| error,
            )
            .err()
            .unwrap(),
            Error::Cancelled
        );
        let running = |_: u64| true;
        for (resources, progress) in [
            (
                WriterResources::default(),
                &Cancelled as &dyn CompressionProgress,
            ),
            (resources, &running as &dyn CompressionProgress),
        ] {
            assert_eq!(
                compress_fallback_members(
                    0,
                    &[EntrySource::from_factory(Untouched)],
                    &[(7, 0, [0; 32])],
                    &plan,
                    false,
                    0,
                    &resources,
                    progress,
                    &|_, error| error,
                )
                .err()
                .unwrap(),
                Error::Cancelled
            );
        }
    }

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
                run_filters: false,
            },
            workspace: 10,
        };
        assert_eq!(
            whole_member_wave(&[whole(0), fallback, whole(0)], 0, 4, 0),
            (1, 0)
        );
    }

    #[test]
    fn stream_read_admission_precedes_open_and_pushback_keeps_its_charge() {
        use std::sync::{atomic::AtomicUsize, Arc};
        let scratch = crate::scratch::case("stream-read-allowance");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let opens = Arc::new(AtomicUsize::new(0));
        let source = EntrySource::from_opener(8, {
            let opens = opens.clone();
            move || {
                opens.fetch_add(1, Ordering::Relaxed);
                Ok(Box::new(std::io::Cursor::new(*b"abcdefgh")))
            }
        });
        let allowance = Allowance::limited(3);
        let mut stream =
            MemberStream::new(0, &source, 8, &resources, &|_| true, &allowance).unwrap();
        assert_eq!(
            read_chunk(&mut stream, 4, &|_| true).unwrap_err().kind(),
            crate::ErrorKind::ResourceLimit
        );
        assert_eq!(opens.load(Ordering::Relaxed), 0);
        assert_eq!(stream.remaining, 8);
        assert_eq!(allowance.used(), 0);
        drop(stream);

        let allowance = Allowance::limited(8);
        let mut stream =
            MemberStream::new(0, &source, 8, &resources, &|_| true, &allowance).unwrap();
        stream.pushback = read_chunk(&mut stream, 4, &|_| true).unwrap();
        assert_eq!(allowance.used(), 4);
        let first = read_chunk(&mut stream, 4, &|_| true).unwrap();
        assert_eq!(&*first, b"abcd");
        assert_eq!(allowance.used(), 4);
        assert_eq!(stream.remaining, 4);
        let last = read_chunk(&mut stream, 4, &|_| true).unwrap();
        assert_eq!(&*last, b"efgh");
        assert_eq!(allowance.used(), 8);
        assert!(stream.reader.is_none());
        drop(stream);
        assert_eq!(allowance.used(), 8);
        drop((first, last));
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn streaming_writer_allowance_covers_assembly_encoding_and_failure_cleanup() {
        let scratch = crate::scratch::case("stream-writer-allowance");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let data: Vec<u8> = (0..8192).map(|i| ((i * 71) % 251) as u8).collect();
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        for solid in [false, true] {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 65536,
                block_size: 1024,
                solid,
                method: 1,
                filter_policy: FilterPolicy::None,
                candidates: vec![options].into(),
            };
            let sources = [
                EntrySource::from_bytes(data.clone()),
                EntrySource::from_bytes(data[..2048].to_vec()),
                EntrySource::from_bytes(Vec::new()),
            ];
            let initial = [(8192, 0, [0; 32]), (2048, 0, [0; 32]), (0, 0, [0; 32])];
            let mut expected_integrity = initial;
            let encode = if solid {
                compress_solid_chain::<Allowance>
            } else {
                compress_independent_members::<Allowance>
            };
            let expected = encode(
                &sources,
                &mut expected_integrity,
                &plan,
                false,
                2,
                1,
                &resources,
                &|_| true,
                &|_, error| error,
                &Allowance::default(),
            )
            .unwrap();
            let payloads = |spools: Records<Spool>| -> Vec<Vec<u8>> {
                spools
                    .into_iter()
                    .map(|mut spool| {
                        let mut bytes = Vec::new();
                        spool.copy_to(&mut bytes).unwrap();
                        bytes
                    })
                    .collect()
            };
            let expected = payloads(expected);
            let mut refusals = 0;
            let mut successes = 0;
            for limit in [0, 1023, 2048, 8192, 32768, 131072, 524288, 4 * 1024 * 1024] {
                let allowance = Allowance::limited(limit);
                let mut integrity = initial;
                let encode = if solid {
                    compress_solid_chain::<crate::codec::workspace::Limited>
                } else {
                    compress_independent_members::<crate::codec::workspace::Limited>
                };
                let result = encode(
                    &sources,
                    &mut integrity,
                    &plan,
                    false,
                    2,
                    1,
                    &resources,
                    &|_| {
                        assert!(allowance.used() > 0);
                        true
                    },
                    &|_, error| error,
                    &allowance,
                );
                match result {
                    Ok(spools) => {
                        successes += 1;
                        assert_eq!(payloads(spools), expected);
                        assert_eq!(integrity, expected_integrity);
                    }
                    Err(error) => {
                        refusals += 1;
                        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit, "{error}");
                    }
                }
                assert_eq!(allowance.used(), 0, "solid={solid}, limit={limit}");
                assert_eq!(resources.workspace_in_use(), 0);
                assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
            }
            assert!(refusals >= 3 && successes > 0);

            let allowance = Allowance::limited(4 * 1024 * 1024);
            let encode = if solid {
                compress_solid_chain::<crate::codec::workspace::Limited>
            } else {
                compress_independent_members::<crate::codec::workspace::Limited>
            };
            let mut integrity = initial;
            let result = encode(
                &sources,
                &mut integrity,
                &plan,
                false,
                2,
                1,
                &resources,
                &|_| false,
                &|_, error| error,
                &allowance,
            );
            assert!(matches!(result, Err(Error::Cancelled)));
            assert_eq!(allowance.used(), 0);
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn bounded_streaming_history_survives_multiple_waves_and_member_boundaries() {
        let scratch = crate::scratch::case("stream-history-allowance");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let size = crate::codec::rar50::MAX_LZ_BLOCK_SIZE + 4096;
        let data: Vec<u8> = (0..size).map(|i| ((i * 71) % 251) as u8).collect();
        let sources = [
            EntrySource::from_bytes(data.clone()),
            EntrySource::from_bytes(data),
        ];
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        for solid in [false, true] {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 65536,
                block_size: 65536,
                solid,
                method: 1,
                filter_policy: FilterPolicy::None,
                candidates: vec![options].into(),
            };
            let mut expected_integrity = [(size as u64, 0, [0; 32]); 2];
            let mut actual_integrity = expected_integrity;
            let encode = if solid {
                compress_solid_chain::<Allowance>
            } else {
                compress_independent_members::<Allowance>
            };
            let expected = encode(
                &sources,
                &mut expected_integrity,
                &plan,
                false,
                1,
                1,
                &resources,
                &|_| true,
                &|_, error| error,
                &Allowance::default(),
            )
            .unwrap();
            let allowance = Allowance::limited(64 * 1024 * 1024);
            let encode = if solid {
                compress_solid_chain::<crate::codec::workspace::Limited>
            } else {
                compress_independent_members::<crate::codec::workspace::Limited>
            };
            let actual = encode(
                &sources,
                &mut actual_integrity,
                &plan,
                false,
                2,
                1,
                &resources,
                &|_| true,
                &|_, error| error,
                &allowance,
            )
            .unwrap();
            assert_eq!(actual_integrity, expected_integrity);
            assert_eq!(allowance.used(), 0);
            for (mut expected, mut actual) in expected.into_iter().zip(actual) {
                let mut expected_bytes = Vec::new();
                let mut actual_bytes = Vec::new();
                expected.copy_to(&mut expected_bytes).unwrap();
                actual.copy_to(&mut actual_bytes).unwrap();
                assert_eq!(actual_bytes, expected_bytes);
            }
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn streaming_ledger_covers_repeated_waves_and_retained_history() {
        use crate::atomic64::AtomicU64;
        let scratch = crate::scratch::case("stream-ledger-waves");
        let size = crate::codec::rar50::MAX_LZ_BLOCK_SIZE * 2 + 4096;
        let data: Vec<u8> = (0..size).map(|i| ((i * 71) % 251) as u8).collect();
        let sources = [
            EntrySource::from_bytes(data.clone()),
            EntrySource::from_bytes(data),
        ];
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        for (solid, filter_policy) in [
            (false, FilterPolicy::None),
            (true, FilterPolicy::None),
            (false, FilterPolicy::Auto),
        ] {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 65536,
                block_size: 65536,
                solid,
                method: 1,
                filter_policy,
                candidates: vec![options].into(),
            };
            let required = super::super::streaming_lz_workspace(
                plan.dictionary_size,
                crate::codec::rar50::MAX_LZ_BLOCK_SIZE,
                false,
            );
            // Automatic mode is forced through its existing streaming fallback.
            let max_workers = if plan.filter_policy == FilterPolicy::Auto {
                1
            } else {
                2
            };
            let resources = WriterResources::new(required * max_workers).with_temp_dir(&*scratch);
            let collect = |members: Records<CompressedMember>| -> Vec<_> {
                members
                    .into_iter()
                    .map(|mut member| {
                        let mut bytes = Vec::new();
                        member.packed.copy_to(&mut bytes).unwrap();
                        (
                            bytes,
                            member.crc32,
                            member.hash,
                            member.store,
                            member.solid_continuation,
                        )
                    })
                    .collect()
            };
            let expected = collect(
                pool.install(|| {
                    compress_members_with_context(&sources, &plan, &resources, &|_| true, &|_, e| e)
                })
                .unwrap(),
            );
            for workers in 1..=max_workers {
                let limit = required * workers + 32 * 1024 * 1024;
                let ledger = Allowance::limited(limit);
                let bounded = resources.clone().with_execution_allowance(ledger.clone());
                let peak = AtomicU64::new(0);
                let progress = |_| {
                    let used = ledger.used();
                    assert!(used <= limit);
                    peak.fetch_max(used, Ordering::Relaxed);
                    true
                };
                let actual = pool
                    .install(|| {
                        compress_members_with_context(
                            &sources,
                            &plan,
                            &bounded,
                            &progress,
                            &|_, e| e,
                        )
                    })
                    .unwrap();
                assert!(peak.load(Ordering::Relaxed) >= required * workers);
                // Native spools retain their path storage alongside result descriptors.
                assert!(
                    ledger.used()
                        > (sources.len() * std::mem::size_of::<CompressedMember>()) as u64
                );
                assert_eq!(collect(actual), expected);
                assert_eq!(ledger.used(), 0);
                assert_eq!(bounded.workspace_in_use(), 0);
                assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
            }
        }
    }

    #[test]
    fn streaming_ledger_releases_assembly_workers_and_spools_on_failure() {
        use std::sync::{atomic::AtomicUsize, Arc};
        let scratch = crate::scratch::case("stream-ledger-failure");
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        for solid in [false, true] {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 65536,
                block_size: 4096,
                solid,
                method: 1,
                filter_policy: FilterPolicy::None,
                candidates: vec![options].into(),
            };
            let ledger = Allowance::limited(256 * 1024 * 1024);
            let resources = WriterResources::default()
                .with_temp_dir(&*scratch)
                .with_execution_allowance(ledger.clone());
            let opens = Arc::new(AtomicUsize::new(0));
            let failed_source = EntrySource::from_opener(4096, {
                let opens = opens.clone();
                let ledger = ledger.clone();
                move || {
                    assert!(ledger.used() >= 4096);
                    opens.fetch_add(1, Ordering::Relaxed);
                    Err(std::io::Error::other("injected source failure").into())
                }
            });
            let result = compress_members_with_context(
                &[failed_source],
                &plan,
                &resources,
                &|_| true,
                &|_, e| e,
            );
            assert!(result.is_err());
            assert_eq!(opens.load(Ordering::Relaxed), 1);
            assert_eq!(ledger.used(), 0);
            let sources = [EntrySource::from_bytes(vec![7; 8192])];
            // Below the fixed 3 MiB every streaming job is charged, whatever its input.
            let too_small = Allowance::limited(1024 * 1024);
            let constrained = resources
                .clone()
                .with_execution_allowance(too_small.clone());
            assert_eq!(
                compress_members_with_context(&sources, &plan, &constrained, &|_| true, &|_, e| e,)
                    .err()
                    .unwrap()
                    .kind(),
                crate::ErrorKind::ResourceLimit
            );
            assert_eq!(too_small.used(), 0);
            let result =
                compress_members_with_context(&sources, &plan, &resources, &|_| false, &|_, e| e);
            assert!(matches!(result, Err(Error::Cancelled)));
            assert_eq!(ledger.used(), 0);
            let constrained = resources.clone().with_max_spool_bytes(1);
            assert!(compress_members_with_context(
                &sources,
                &plan,
                &constrained,
                &|_| true,
                &|_, e| e
            )
            .is_err());
            assert_eq!(ledger.used(), 0);
            drop(
                compress_members_with_context(&sources, &plan, &resources, &|_| true, &|_, e| e)
                    .unwrap(),
            );
            assert_eq!(ledger.used(), 0);
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn stored_ledger_admits_read_buffer_before_opening_and_releases_it() {
        use std::sync::{atomic::AtomicUsize, Arc};
        let scratch = crate::scratch::case("stored-ledger");
        let options = EncodeOptions::new(8);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 65536,
            solid: false,
            method: 0,
            filter_policy: FilterPolicy::None,
            candidates: vec![options].into(),
        };
        let opens = Arc::new(AtomicUsize::new(0));
        for limit in [32768, 131072] {
            let ledger = Allowance::limited(limit);
            let resources = WriterResources::default()
                .with_temp_dir(&*scratch)
                .with_execution_allowance(ledger.clone());
            let source = EntrySource::from_opener(8, {
                let opens = opens.clone();
                let ledger = ledger.clone();
                move || {
                    assert!(ledger.used() >= 65536);
                    opens.fetch_add(1, Ordering::Relaxed);
                    Ok(Box::new(std::io::Cursor::new([7u8; 8])))
                }
            });
            let result =
                compress_members_with_context(&[source], &plan, &resources, &|_| true, &|_, e| e);
            if limit < 65536 {
                assert_eq!(
                    result.err().unwrap().kind(),
                    crate::ErrorKind::ResourceLimit
                );
                assert_eq!(opens.load(Ordering::Relaxed), 0);
            } else {
                let result = result.unwrap();
                assert!(result[0].store);
                assert_eq!(result[0].crc32, crate::crc32::crc32(&[7u8; 8]));
                drop(result);
                assert_eq!(opens.load(Ordering::Relaxed), 1);
            }
            assert_eq!(ledger.used(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
    }

    #[test]
    fn streaming_source_failure_releases_admitted_buffers() {
        let scratch = crate::scratch::case("stream-source-failure-allowance");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        for bytes in [b"short".as_slice(), b"too long for declared size"] {
            let source =
                EntrySource::from_opener(8, move || Ok(Box::new(std::io::Cursor::new(bytes))));
            let allowance = Allowance::limited(128);
            let mut stream =
                MemberStream::new(0, &source, 8, &resources, &|_| true, &allowance).unwrap();
            let error = read_block(&mut stream, 4, &|_| true).unwrap_err();
            assert!(matches!(error, Error::Io(_) | Error::SourceChanged(_)));
            drop(stream);
            assert_eq!(allowance.used(), 0);
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn admitted_workers_share_one_ledger_without_racing_for_spare_capacity() {
        use crate::atomic64::AtomicU64;
        use crate::streaming::preparation::Bytes;
        use std::sync::Barrier;
        let ledger = Allowance::limited(65536);
        let resources = WriterResources::default().with_execution_allowance(ledger.clone());
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        for fail in [false, true] {
            let barrier = Barrier::new(2);
            let admitted = AtomicU64::new(0);
            let jobs = Records::collect((0..2).map(Ok), &resources).unwrap();
            let result = pool.install(|| {
                run_jobs_admitted(
                    jobs,
                    &resources,
                    &|_| true,
                    |_| 128,
                    |index, worker, _, allowance| {
                        if index == 0 {
                            admitted.store(ledger.used(), Ordering::Relaxed);
                        }
                        barrier.wait();
                        let prepared = Bytes::zeroed(32, worker)?;
                        let bytes = Buffer::filled(64, index as u8, allowance)?;
                        assert_eq!(ledger.used(), admitted.load(Ordering::Relaxed));
                        barrier.wait();
                        if fail && index == 0 {
                            Buffer::filled(33, 0u8, allowance)?;
                        }
                        Ok((prepared, bytes))
                    },
                )
            });
            if fail {
                assert_eq!(
                    result.err().unwrap().kind(),
                    crate::ErrorKind::ResourceLimit
                );
                assert_eq!(ledger.used(), 0);
            } else {
                let mut output = result.unwrap();
                let first = output.pop().unwrap();
                let second = output.pop().unwrap();
                drop(output);
                assert_eq!(
                    ledger.used(),
                    192 + 2 * crate::codec::workspace::RESERVATION_BYTES
                );
                drop(first);
                assert_eq!(
                    ledger.used(),
                    96 + crate::codec::workspace::RESERVATION_BYTES
                );
                drop(second);
                assert_eq!(ledger.used(), 0);
            }
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn whole_member_ledger_selects_fitting_waves_before_opening_sources() {
        use std::sync::{atomic::AtomicUsize, Arc, Barrier};
        let scratch = crate::scratch::case("whole-member-ledger");
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 1024,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options].into(),
        };
        let data: Arc<[u8]> = (0..1024u32)
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>()
            .into();
        let required = whole_member_workspace(data.len() as u64, &plan);
        let expected = candidates_with_allowance(
            &data,
            0,
            &plan.filter_policy,
            &plan.candidates,
            None,
            &Allowance::default(),
        )
        .unwrap();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        for workers in [1, 2] {
            let ledger = Allowance::limited(required * workers + 65536);
            let resources = WriterResources::new(required * 2)
                .with_temp_dir(&*scratch)
                .with_execution_allowance(ledger.clone());
            let opens = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(workers as usize));
            let sources: Vec<_> = (0..4)
                .map(|_| {
                    let data = data.clone();
                    let ledger = ledger.clone();
                    let opens = opens.clone();
                    let barrier = barrier.clone();
                    EntrySource::from_opener(data.len() as u64, move || {
                        assert!(ledger.used() >= required * workers);
                        opens.fetch_add(1, Ordering::Relaxed);
                        barrier.wait();
                        Ok(Box::new(std::io::Cursor::new(data.clone())))
                    })
                })
                .collect();
            let result = pool
                .install(|| {
                    compress_members_with_context(
                        &sources,
                        &plan,
                        &resources,
                        &|_| true,
                        &|_, error| error,
                    )
                })
                .unwrap();
            assert_eq!(opens.load(Ordering::Relaxed), 4);
            assert!(ledger.used() > (4 * std::mem::size_of::<CompressedMember>()) as u64);
            for mut member in result {
                let mut bytes = Vec::new();
                member.packed.copy_to(&mut bytes).unwrap();
                assert_eq!(&*expected, bytes);
            }
            assert_eq!(ledger.used(), 0);
            assert_eq!(resources.workspace_in_use(), 0);
            assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
        }
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

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
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

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
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

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn whole_member_allowance_precedes_source_open_and_survives_until_spooling() {
        use std::sync::{atomic::AtomicUsize, Arc};
        let scratch = crate::scratch::case("whole-member-allowance");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 1024,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options, options.with_optimal_parse(true)].into(),
        };
        let data: Vec<u8> = (0..1024u32).flat_map(|n| n.to_le_bytes()).collect();
        let opens = Arc::new(AtomicUsize::new(0));
        let source = EntrySource::from_opener(data.len() as u64, {
            let data = data.clone();
            let opens = opens.clone();
            move || {
                opens.fetch_add(1, Ordering::Relaxed);
                Ok(Box::new(std::io::Cursor::new(data.clone())))
            }
        });
        let integrity = (data.len() as u64, 0, [0; 32]);
        let allowance = Allowance::limited(data.len() as u64 - 1);
        let error = compress_whole_member(
            0,
            &source,
            integrity,
            &plan,
            &resources,
            &|_| true,
            &allowance,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(opens.load(Ordering::Relaxed), 0);
        assert_eq!(allowance.used(), 0);

        let allowance = Allowance::limited(16 * 1048576);
        let mut packed = compress_whole_member(
            0,
            &source,
            integrity,
            &plan,
            &resources,
            &|_| {
                assert!(allowance.used() >= data.len() as u64);
                true
            },
            &allowance,
        )
        .unwrap();
        assert!(!packed.store);
        assert_eq!(packed.crc32, crate::crc32::crc32(&data));
        assert_eq!(packed.hash, blake2sp::hash(&data));
        assert_eq!(allowance.used(), 0);
        let expected = candidates_with_allowance(
            &data,
            0,
            &plan.filter_policy,
            &plan.candidates,
            None,
            &Allowance::default(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        packed.packed.copy_to(&mut bytes).unwrap();
        assert_eq!(&*expected, bytes);
        drop(packed);

        let refused_spool = resources.clone().with_max_spool_bytes(0);
        let error = compress_whole_member(
            0,
            &source,
            integrity,
            &plan,
            &refused_spool,
            &|_| true,
            &allowance,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        assert_eq!(allowance.used(), 0);
        let cancelled = compress_whole_member(
            0,
            &source,
            integrity,
            &plan,
            &resources,
            &|_| false,
            &allowance,
        );
        assert!(matches!(cancelled, Err(Error::Cancelled)));
        assert_eq!(allowance.used(), 0);
        for actual in [b"short".as_slice(), b"longer than declared"] {
            let changed =
                EntrySource::from_opener(8, move || Ok(Box::new(std::io::Cursor::new(actual))));
            let result = compress_whole_member(
                0,
                &changed,
                (8, 0, [0; 32]),
                &plan,
                &resources,
                &|_| true,
                &allowance,
            );
            assert!(matches!(
                result,
                Err(Error::Io(_) | Error::SourceChanged(_))
            ));
            assert_eq!(allowance.used(), 0);
        }
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
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
            candidates: vec![encode_options].into(),
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
    fn automatic_filter_fallback_source_failure_keeps_member_context() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let scratch = crate::scratch::case("fallback-source-error");
        let resources = WriterResources::new(70 * 1024 * 1024).with_temp_dir(&*scratch);
        let length = 2 * 1024 * 1024;
        let options = EncodeOptions::new(8).with_max_match_distance(128 * 1024);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 128 * 1024,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options].into(),
        };
        let execution =
            ExecutionPlan::with_resources(&plan, std::iter::once(length), &resources).unwrap();
        let ExecutionPlan::IndependentMembers(ref members) = execution else {
            panic!("automatic filtering should plan independent members");
        };
        assert!(matches!(members[0].execution, Execution::Blocks { .. }));
        drop(execution);
        let opens = Arc::new(AtomicUsize::new(0));
        let source = EntrySource::from_opener(length, {
            let opens = Arc::clone(&opens);
            move || {
                opens.fetch_add(1, Ordering::Relaxed);
                Err(std::io::Error::other("fallback source refused").into())
            }
        });
        let error = compress_members_with_context(
            &[source],
            &plan,
            &resources,
            &|_| true,
            &|index, error| {
                assert_eq!(index, 0);
                error.at_entry(b"fallback.bin".to_vec(), "compressing")
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(
            error.entry_context(),
            Some((b"fallback.bin".as_slice(), "compressing"))
        );
        assert!(error.to_string().contains("fallback source refused"));
        assert_eq!(opens.load(Ordering::Relaxed), 1);
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
            candidates: vec![encode_options].into(),
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
    fn fallback_members_packed_together_match_each_packed_alone() {
        let scratch = crate::scratch::case("grouped-fallback");
        let first = b"grouped automatic filter fallback\n".repeat(65536);
        let second: Vec<u8> = (0..600_000u32)
            .flat_map(|n| (n.wrapping_mul(2_654_435_761) >> 7).to_le_bytes())
            .collect();
        let sources = [
            EntrySource::from_bytes(first.clone()),
            EntrySource::from_bytes(second.clone()),
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
            candidates: vec![encode_options].into(),
        };
        let resources = WriterResources::new(70 * 1024 * 1024).with_temp_dir(&*scratch);
        let members = ExecutionPlan::with_resources(
            &plan,
            [first.len() as u64, second.len() as u64].into_iter(),
            &resources,
        )
        .unwrap();
        let ExecutionPlan::IndependentMembers(members) = members else {
            panic!("automatic filters plan independent members");
        };
        assert!(members
            .iter()
            .all(|member| matches!(member.execution, Execution::Blocks { .. })));

        let bytes = |member: &mut CompressedMember| {
            let mut bytes = Vec::new();
            member.packed.copy_to(&mut bytes).unwrap();
            bytes
        };
        let mut together =
            compress_members_reporting(&sources, plan.clone(), &resources, &|_| true).unwrap();
        assert_eq!(together[0].hash, blake2sp::hash(&first));
        assert_eq!(together[1].hash, blake2sp::hash(&second));
        for index in 0..2 {
            let mut alone = compress_members_reporting(
                &sources[index..index + 1],
                plan.clone(),
                &resources,
                &|_| true,
            )
            .unwrap();
            assert_eq!(bytes(&mut together[index]), bytes(&mut alone[0]));
        }
        drop(together);
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
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
                candidates: vec![options].into(),
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
            candidates: vec![options].into(),
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
            candidates: vec![options].into(),
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
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
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
            candidates: vec![options].into(),
        };
        let run = |threads: usize, budget| {
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
                            // Optimised, one thread can finish every member before another starts,
                            // so each waits up to 5 s for a second thread to join.
                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(5);
                            while threads > 1
                                && workers.lock().unwrap().len() < 2
                                && std::time::Instant::now() < deadline
                            {
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
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
                    candidates: vec![options].into(),
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
