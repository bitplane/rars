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
use crate::codec::packed_chain::SharedPackedIndex;
use crate::codec::rar50::EncodeOptions;
use crate::codec::rar50::{
    filter_streaming_blocks_in_place, filtered_run_cuts, run_trees_workspace, seed_chain,
    seed_chains, seed_run_tree, streaming_blocks_in_window, streaming_blocks_with_finder,
    streaming_blocks_with_tree, BlockSplitter, EncodeFilter, RunFinder,
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
    slots: Records<JobSlot<T, O>>,
    output: Records<O>,
    resources: &WriterResources,
    progress: &dyn CompressionProgress,
    map: impl Fn(usize, T, &dyn CompressionProgress) -> Result<O> + Sync + Send,
) -> Result<Records<O>> {
    complete_jobs_dispatched(slots, output, resources, progress, map, |slots, run| {
        crate::parallel::for_each_mut(slots, |index, slot| run(index, slot, None));
    })
}

/// A job's slot, its index, and what failed before it could run, if anything.
type RunSlot<'a, T, O> = dyn Fn(usize, &mut JobSlot<T, O>, Option<Error>) + Sync + 'a;

/// [`complete_jobs`], with `dispatch` deciding when each slot runs. It must
/// run every slot once and return only when all have run.
fn complete_jobs_dispatched<T: Send, O: Send>(
    mut slots: Records<JobSlot<T, O>>,
    mut output: Records<O>,
    resources: &WriterResources,
    progress: &dyn CompressionProgress,
    map: impl Fn(usize, T, &dyn CompressionProgress) -> Result<O> + Sync + Send,
    dispatch: impl FnOnce(&mut [JobSlot<T, O>], &RunSlot<'_, T, O>),
) -> Result<Records<O>> {
    let batch = BatchProgress {
        progress,
        resources,
        stopped: AtomicBool::new(false),
    };
    dispatch(&mut slots, &|index, (job, result), failed| {
        if batch.is_cancelled() {
            return;
        }
        let mapped = match failed {
            Some(error) => Err(error),
            None => map(index, job.take().expect("one callback per slot"), &batch),
        };
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

/// A member's size, CRC32 and, when the archive asks for one, BLAKE2sp hash.
pub(super) type Integrity = (u64, u32, Option<[u8; 32]>);

/// A member that has been compressed and is waiting to be framed.
pub(super) struct CompressedMember {
    pub(super) input_size: u64,
    pub(super) crc32: u32,
    /// Only computed when the archive stores BLAKE2sp hashes.
    pub(super) hash: Option<[u8; 32]>,
    pub(super) packed: Spool,
    /// True when the payload should be written as-is from the source because
    /// compressing it did not pay.
    pub(super) store: bool,
    /// True when this member continues the previous member's dictionary.
    pub(super) solid_continuation: bool,
    /// Stored without being read, so its checksums wait for its copy.
    pub(super) checksums_pending: bool,
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
    /// Where one run ends and the next starts in `data`, when the job codes
    /// several runs of its member back to back: see [`runs_per_job`]. Each
    /// run keeps its own filter search, filters and blocks, so only the tree
    /// it would have seeded is saved.
    seams: Records<usize>,
    /// Filters ranged over `data`, each inside one run. A run with any is
    /// coded as one filtered stream, cut where its filter records fit rather
    /// than at `blocks`.
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
    /// Where in `data` the member's short tail starts, when it was joined to
    /// the last run and is to be coded as a job of its own once the filters
    /// are chosen ([`split_tail`]).
    tail: Option<usize>,
    /// Searches a tree whatever its length: a tail cut from the run before it,
    /// which would have parsed it on that run's tree.
    tree: bool,
}

/// A run's part of its group's window, and a finder standing where the run's
/// own would: over the group's index for a run that walks chains, or the tree
/// a run that searches one would have seeded.
struct SharedRun<B: Budget> {
    window: std::sync::Arc<Buffer<u8, B>>,
    /// Where the run starts and ends in `window`.
    start: usize,
    end: usize,
    /// None for a run that seeds its own tree.
    finder: Option<RunFinder<B>>,
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
/// only when it has history.
///
/// In a solid `chain`, the wave's runs are consecutive runs of one stream
/// that crosses members, so they group as one. A filtered run there already
/// holds its filtered bytes and carries its blocks' records, and joins on the
/// same terms.
///
/// Returns, for each group outside a `chain`, the trees the wave seeds for
/// its runs before they code.
fn share_member_windows<B: Budget + Send + Sync>(
    jobs: &mut [BlockJob<B>],
    plan: &CompressPlan,
    chain: bool,
    allowance: &B,
) -> Result<Vec<TreeRuns<B>>>
where
    B::Charge: Send,
{
    let options = plan.encode_options;
    if !options.optimal_parse {
        return Ok(Vec::new());
    }
    let dictionary = options.max_match_distance;
    let own_window = |job: &BlockJob<B>| job.history.len().min(dictionary) + job.data.len();
    let shareable = |job: &BlockJob<B>| {
        let plain = job.filters.is_empty() && job.records.is_none();
        let (window, start) = (own_window(job), job.history.len().min(dictionary));
        (plain || start != 0)
            && (job.tree
                || crate::codec::rar50::searches_tree(window, start, options)
                || crate::codec::rar50::packed_index_fits(window, start, options))
    };
    // A run alone in its group shares nothing, but one that seeds a tree from
    // history is still worth a group of its own: the wave seeds it on threads
    // its own job would leave idle.
    let seeds_alone = |job: &BlockJob<B>| {
        let (window, start) = (own_window(job), job.history.len().min(dictionary));
        !chain
            && start != 0
            && crate::parallel::threads() > 1
            && (job.tree || crate::codec::rar50::searches_tree(window, start, options))
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
            if group.len() > 1 || group.first().is_some_and(|&only| seeds_alone(&jobs[only])) {
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
                .iter()
                .map(|&index| slots[index].take().expect("a run joins one group"))
                .collect();
            (group, indices, window_len, Ok(()))
        })
        .collect();
    crate::parallel::for_each_mut(&mut builds, |_, (group, _, window_len, result)| {
        *result = share_group(group, *window_len, options, allowance);
    });
    for (_, _, _, result) in builds.iter_mut() {
        std::mem::replace(result, Ok(()))?;
    }
    if chain {
        return Ok(Vec::new());
    }
    Ok(builds
        .into_iter()
        .filter_map(|(group, indices, _, _)| TreeRuns::of(&group, &indices, options))
        .collect())
}

/// The runs of a group that search a tree and have none yet, and how the wave
/// seeds them ([`code_seeded_wave`]).
struct TreeRuns<B: Budget> {
    window: std::sync::Arc<Buffer<u8, B>>,
    /// Their jobs' indexes in the wave.
    trees: Vec<usize>,
    /// Where each starts and ends in `window`.
    runs: Vec<std::ops::Range<usize>>,
    /// [`seed_chains`] over `runs`.
    chains: Vec<std::ops::Range<usize>>,
}

impl<B: Budget + Sync> TreeRuns<B>
where
    B::Charge: Send,
{
    /// `None` where no run of `group`, the wave's jobs at `indices`, is seeded
    /// before its job starts.
    fn of(group: &[&mut BlockJob<B>], indices: &[usize], options: EncodeOptions) -> Option<Self> {
        let trees: Vec<usize> = (0..group.len())
            .filter(|&index| {
                group[index]
                    .shared
                    .as_ref()
                    .is_some_and(|shared| shared.finder.is_none())
            })
            .collect();
        let window = std::sync::Arc::clone(&group[*trees.first()?].shared.as_ref()?.window);
        let runs: Vec<_> = trees
            .iter()
            .map(|&index| {
                let shared = group[index].shared.as_ref().expect("a shared run");
                debug_assert!(std::sync::Arc::ptr_eq(&shared.window, &window));
                shared.start..shared.end
            })
            .collect();
        let chains = seed_chains(&window, &runs, options);
        (!chains.is_empty()).then(|| Self {
            window,
            trees: trees.into_iter().map(|index| indices[index]).collect(),
            runs,
            chains,
        })
    }

    /// Whether a chain of several runs is seeded from a shared tree.
    fn shares_a_tree(&self) -> bool {
        self.chains.iter().any(|chain| chain.len() > 1)
    }
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
            piece.filtered = Some(job.filter_in_place(piece.bytes, allowance));
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
        .zip(group.iter())
        .map(|(&(start, end), job)| {
            let skip = start.saturating_sub(dictionary);
            !job.tree && !crate::codec::rar50::searches_tree(end - skip, start - skip, options)
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
    .into_iter()
    .map(RunFinder::Packed);
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

    /// The runs this job codes, over `len` bytes of them: its `data`, or its
    /// part of a shared window once `data` has gone there.
    fn runs(&self, len: usize) -> impl Iterator<Item = std::ops::Range<usize>> + '_ {
        let mut start = 0;
        self.seams
            .iter()
            .copied()
            .chain(std::iter::once(len))
            .map(move |end| {
                let run = start..end;
                start = end;
                run
            })
    }

    /// Transforms `bytes`, the job's data, into what its encode codes, and
    /// returns the blocks it is coded in with their records. Each run is
    /// filtered as [`filter_run_in_place`](crate::codec::rar50::filter_run_in_place)
    /// filters a run that is a job of its own, and a run without filters
    /// keeps its blocks, as it does when it is a job of its own.
    fn filter_in_place<C: Budget>(
        &self,
        bytes: &mut [u8],
        allowance: &C,
    ) -> crate::codec::Result<crate::codec::rar50::FilteredRunBlocks<C>> {
        let last = self.blocks.last().is_some_and(|&(_, _, last)| last);
        if self.seams.is_empty() {
            return crate::codec::rar50::filter_run_in_place(
                bytes,
                &self.filters,
                self.offset,
                last,
                allowance,
            );
        }
        let len = bytes.len();
        let mut ends = Buffer::new(allowance);
        let mut records = Buffer::new(allowance);
        for run in self.runs(len) {
            let mut filters = Buffer::new(allowance);
            for spec in self.filters.iter() {
                let range = spec.range.clone().unwrap_or(0..len);
                let (start, end) = (range.start.max(run.start), range.end.min(run.end));
                if start < end {
                    filters.try_push(crate::FilterSpec::range(
                        spec.kind,
                        start - run.start..end - run.start,
                    ))?;
                }
            }
            if filters.is_empty() {
                for &(_, end, last) in self.blocks.iter() {
                    if run.start < end && end <= run.end {
                        ends.try_push((end, last))?;
                        records.try_push(Buffer::new(allowance))?;
                    }
                }
                continue;
            }
            let (run_ends, run_records) = crate::codec::rar50::filter_run_in_place(
                &mut bytes[run.clone()],
                &filters,
                self.offset + run.start,
                last && run.end == len,
                allowance,
            )?;
            for (&(end, last), block_records) in run_ends.iter().zip(run_records) {
                ends.try_push((run.start + end, last))?;
                records.try_push(block_records)?;
            }
        }
        Ok((ends, records))
    }
}

pub(super) fn run_size(plan: &CompressPlan) -> usize {
    run_size_for_distance(plan.encode_options.max_match_distance)
}

pub(super) fn run_size_for_distance(distance: usize) -> usize {
    distance.max(crate::codec::rar50::MAX_LZ_BLOCK_SIZE)
}

/// The longest run an independent member is cut into: 4 MiB.
///
/// A run is a dictionary long up to this, as at levels 1 to 3. A larger
/// dictionary is cut into runs of this length instead, so a 32 MiB member at
/// level 5's 16 MiB dictionary is eight runs rather than two, and eight
/// threads code it (#546). A run that starts a job seeds a tree from the
/// dictionary before it, a descent per byte, so a job of one short run costs
/// more CPU than one of a whole dictionary. [`runs_per_job`] joins the runs
/// back up a dictionary at a time where threads or memory are short, and a
/// job that joins runs parses straight on, so the archive does not depend on
/// it. It is the length of one filter search, which the runs are already
/// searched in pieces of, and a test that lowers one lowers the other.
fn longest_member_run() -> usize {
    super::plan::filter_search_bytes()
}

/// How long the runs of an independent member are: [`run_size`], or
/// [`longest_member_run`] where the dictionary is longer and the parse is
/// the shortest-path one. The lazy parse keeps a dictionary a run, so its
/// runs cut a member where the whole-member path does
/// (`super::plan::codes_alike_in_runs`).
pub(super) fn member_run_size(plan: &CompressPlan) -> usize {
    if !plan.encode_options.optimal_parse {
        return run_size(plan);
    }
    run_size(plan).min(longest_member_run().max(crate::codec::rar50::MAX_LZ_BLOCK_SIZE))
}

/// Whether the rest of a member, `unread` bytes, goes into the run being read
/// rather than a run of its own: where runs are shorter than the dictionary
/// and that run would walk chains (see [`next_run_searches_tree`]). Joined to
/// the run before it, the tail is parsed on the tree that run has built, at
/// no cost in seeding.
fn absorbs_tail(plan: &CompressPlan, unread: u64) -> bool {
    member_run_size(plan) < run_size(plan) && !next_run_searches_tree(plan, unread)
}

/// How many of a member's runs one block job codes back to back.
///
/// A run that follows another in its member seeds a tree from the dictionary
/// before it. A job of several runs parses straight on instead, and a tree that
/// has parsed up to a run holds what one seeded there would, so the archive is
/// the same whatever this returns. Only how many jobs can run at once changes.
///
/// So runs are joined up only as far as every thread still has a job: the
/// largest member is cut into a whole number of jobs per thread, where those
/// jobs' windows fit the budget side by side. One thread codes a member in as
/// few jobs as the budget allows, and a machine with more threads than runs
/// codes every run on its own. A run that walks chains, which only a member's
/// short last run does, still starts a job of its own.
///
/// Where runs are shorter than the dictionary ([`member_run_size`]), threads
/// count only as far as the budget holds a job for each, and a job of more
/// than a dictionary holds whole dictionaries of runs: every job seeds a
/// dictionary of history, so one thread codes the member a dictionary a job.
fn runs_per_job(
    plan: &CompressPlan,
    largest: u64,
    admission: u64,
    memory_limit: u64,
    threads: usize,
) -> usize {
    if !plan.encode_options.optimal_parse {
        return 1;
    }
    let run = member_run_size(plan) as u64;
    let dictionary = (run_size(plan) as u64 / run).max(1);
    // A short tail joins the run before it, so it is not a run of its own.
    let runs = if dictionary > 1 {
        largest / run
    } else {
        largest.div_ceil(run)
    }
    .max(1);
    let mut threads = threads.max(1) as u64;
    if dictionary > 1 {
        threads = threads
            .min(memory_limit / joined_admission(plan, admission, 1, memory_limit))
            .max(1);
    }
    // A window this long is what the finders are known to hold.
    let longest = (SHARED_WINDOW_LIMIT as u64 / run).max(1);
    for waves in 1u64.. {
        let jobs = threads.saturating_mul(waves);
        let mut joined = runs.div_ceil(jobs);
        if joined > dictionary {
            joined -= joined % dictionary;
        }
        if joined <= 1 {
            return 1;
        }
        if joined > longest {
            continue;
        }
        let concurrent = threads.min(runs.div_ceil(joined));
        let admitted = joined_admission(plan, admission, joined as usize, memory_limit);
        if memory_limit / admitted >= concurrent {
            return usize::try_from(joined).unwrap_or(1);
        }
    }
    1
}

/// What a job of `joined` runs is admitted for, beside `admission` for one:
/// each further run is held by the coordinator while it is read and its
/// filters are searched, and then by the job's window.
///
/// A job no longer than a dictionary is admitted as one run of a dictionary,
/// which is what it holds: each further run once, and the whole budget when it
/// needs more, one job at a time.
fn joined_admission(plan: &CompressPlan, admission: u64, joined: usize, memory_limit: u64) -> u64 {
    let run = member_run_size(plan) as u64;
    let further = (joined.saturating_sub(1) as u64).saturating_mul(run);
    if (joined as u64).saturating_mul(run) <= run_size(plan) as u64 {
        return admission.saturating_add(further).min(memory_limit).max(1);
    }
    admission.saturating_add(further.saturating_mul(2)).max(1)
}

/// Whether the run a member starts next, `unread` bytes from its end, would
/// search a tree when coded as a job of its own: one that follows a whole run
/// carries a dictionary of history, and a run never ends short of its size
/// before the member does.
fn next_run_searches_tree(plan: &CompressPlan, unread: u64) -> bool {
    let options = plan.encode_options;
    let dictionary = options.max_match_distance;
    let run = usize::try_from(unread).map_or(member_run_size(plan), |unread| {
        unread.min(member_run_size(plan))
    });
    options.optimal_parse
        && crate::codec::rar50::searches_tree(dictionary.saturating_add(run), dictionary, options)
}

/// A member being read, and the packed bytes it has produced so far.
struct MemberStream<B: Budget> {
    member: usize,
    input_size: u64,
    started: bool,
    source: EntrySource,
    reader: Option<Box<dyn crate::EntryReader>>,
    remaining: u64,
    /// Taken when handed on; a member going straight out never fills it.
    packed: Option<Spool>,
    straight: bool,
    packed_len: u64,
    /// Members go out in order, so one waits for its last block to be packed.
    done: bool,
    /// A chunk read to decide a block boundary and not used by that block.
    pushback: Buffer<u8, B>,
    /// How much of the member has gone into jobs so far.
    placed: usize,
    crc: Crc32,
    hash: Option<blake2sp::Hasher>,
}

impl<B: Budget> MemberStream<B> {
    fn new(
        member: usize,
        source: &EntrySource,
        size: u64,
        blake2sp: bool,
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
            packed: Some(Spool::create_parked(resources)?),
            straight: false,
            packed_len: 0,
            done: size == 0,
            pushback: Buffer::new(allowance),
            placed: 0,
            crc: Crc32::new(),
            hash: blake2sp.then(blake2sp::Hasher::new),
        })
    }

    /// Whether this member has anything left, read or unread.
    fn has_more(&self) -> bool {
        self.remaining != 0 || !self.pushback.is_empty()
    }

    /// Bytes not yet in a job.
    fn unread(&self) -> u64 {
        self.remaining + self.pushback.len() as u64
    }

    fn packed(&mut self) -> &mut Spool {
        self.packed
            .as_mut()
            .expect("a member is packed before it is handed on")
    }

    fn hand_on(&mut self, consume: &mut ConsumePacked<'_>) -> Result<()> {
        let hash = self.hash.take().map(blake2sp::Hasher::finalize);
        let crc32 = self.crc.finish();
        let packing = if self.straight {
            Packing::Closed {
                crc32,
                hash,
                packed_len: self.packed_len,
            }
        } else {
            let packed = self.packed.take().expect("a member is handed on once");
            Packing::Done(packed, crc32, hash)
        };
        consume(self.member, packing)
    }
}

/// Writing a member can take workspace, so no wave may hold any when this runs.
fn hand_on_done<B: Budget>(
    streams: &mut [MemberStream<B>],
    handed: &mut usize,
    consume: &mut ConsumePacked<'_>,
) -> Result<()> {
    while *handed < streams.len() && streams[*handed].done {
        streams[*handed].hand_on(consume)?;
        *handed += 1;
    }
    Ok(())
}

/// `advance` is called with each newly completed chunk of work and returns
/// false when the caller wants to stop. Stored members are hashed before they
/// are handed on; the writers hash them on their copy instead.
#[cfg(test)]
pub(super) fn compress_members_with_context(
    sources: &[EntrySource],
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<CompressedMember>> {
    let mut members = Records::new(sources.len(), resources)?;
    compress_members_in_order(
        sources,
        plan,
        resources,
        advance,
        error_context,
        false,
        &|_, _| false,
        &mut |_, handed| match handed {
            Handed::Member(member) => members.push(member),
            _ => unreachable!("no member goes out straight"),
        },
    )?;
    Ok(members)
}

/// Members are handed on as their windows finish, so a writer need not hold them all.
#[allow(clippy::too_many_arguments)]
pub(super) fn compress_members_in_order(
    sources: &[EntrySource],
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    stored_hashed_later: bool,
    straight: &Straight<'_>,
    consume: &mut Consume<'_>,
) -> Result<()> {
    if advance.is_cancelled() || resources.is_cancelled() {
        return Err(Error::Cancelled);
    }
    let Some(stored_early) = probe_members(sources, plan, resources, advance, error_context)?
    else {
        return compress_members_as_planned(
            sources,
            plan,
            resources,
            advance,
            error_context,
            stored_hashed_later,
            straight,
            consume,
        );
    };

    // The rest are planned and coded as if the stored members were not there:
    // nothing about one independent member depends on another.
    let split = |store: bool| -> Result<(Records<usize>, Records<EntrySource>)> {
        let count = stored_early.iter().filter(|&&early| early == store).count();
        let mut indexes = Records::new(count, resources)?;
        let mut picked = Records::new(count, resources)?;
        for index in (0..sources.len()).filter(|&index| stored_early[index] == store) {
            indexes.push(index)?;
            picked.push(sources[index].clone())?;
        }
        Ok((indexes, picked))
    };
    let (stored, stored_sources) = split(true)?;
    let (coded, coded_sources) = split(false)?;

    let mut stored_integrity = Records::new(stored.len(), resources)?;
    for (member, source) in stored_sources.iter().enumerate() {
        let size = source
            .len()
            .map_err(|error| error_context(stored[member], error))?;
        // A placeholder hash sizes the header until the copy's is patched in.
        let hash = (stored_hashed_later && plan.blake2sp).then_some([0; 32]);
        stored_integrity.push((size, 0, hash))?;
    }
    let mut checksums = Records::new(stored.len(), resources)?;
    if stored_hashed_later {
        // Progress reports them where hashing them would have.
        for (member, &integrity) in stored_integrity.iter().enumerate() {
            advance.started(stored[member], integrity.0);
            if !advance.advance(integrity.0) {
                return Err(Error::Cancelled);
            }
            advance.finished(stored[member], integrity.0);
            checksums.push(integrity)?;
        }
    } else {
        hash_stored_members(
            &stored_sources,
            &stored_integrity,
            plan.blake2sp,
            resources,
            &Remapped::new(&stored, advance),
            &|member, error| error_context(stored[member], error),
            &mut |_, size, crc, hash| checksums.push((size, crc, hash)),
        )?;
    }

    // Members go out in order, so each coded one waits for the stored ones before it.
    let mut next_stored = 0;
    if !coded.is_empty() {
        compress_members_as_planned(
            &coded_sources,
            plan,
            resources,
            &Remapped::new(&coded, advance),
            &|member, error| error_context(coded[member], error),
            stored_hashed_later,
            &|member, size| straight(coded[member], size),
            &mut |member, handed| {
                let index = coded[member];
                hand_on_stored(
                    &stored,
                    &checksums,
                    stored_hashed_later,
                    &mut next_stored,
                    index,
                    resources,
                    consume,
                )?;
                consume(index, handed)
            },
        )?;
    }
    hand_on_stored(
        &stored,
        &checksums,
        stored_hashed_later,
        &mut next_stored,
        usize::MAX,
        resources,
        consume,
    )
}

fn hand_on_stored(
    stored: &[usize],
    checksums: &[Integrity],
    pending: bool,
    next: &mut usize,
    before: usize,
    resources: &WriterResources,
    consume: &mut Consume<'_>,
) -> Result<()> {
    while *next < stored.len() && stored[*next] < before {
        let (input_size, crc32, hash) = checksums[*next];
        let member = CompressedMember {
            input_size,
            crc32,
            hash,
            packed: Spool::create_parked(resources)?,
            store: true,
            solid_continuation: false,
            checksums_pending: pending,
        };
        consume(stored[*next], Handed::Member(member))?;
        *next += 1;
    }
    Ok(())
}

/// Progress for a subset of the members, reported under their own indexes.
struct Remapped<'a> {
    members: &'a [usize],
    progress: &'a dyn CompressionProgress,
}

impl<'a> Remapped<'a> {
    fn new(members: &'a [usize], progress: &'a dyn CompressionProgress) -> Self {
        Self { members, progress }
    }
}

impl CompressionProgress for Remapped<'_> {
    fn is_cancelled(&self) -> bool {
        self.progress.is_cancelled()
    }
    fn advance(&self, bytes: u64) -> bool {
        self.progress.advance(bytes)
    }
    fn started(&self, member: usize, size: u64) {
        self.progress.started(self.members[member], size);
    }
    fn finished(&self, member: usize, size: u64) {
        self.progress.finished(self.members[member], size);
    }
}

/// Which members to store without coding them, judged from samples of each
/// (#481), or `None` when there are none.
///
/// Only independent members are sampled. A member in a solid chain is coded
/// against the ones before it, so a sample coded alone says nothing about what
/// it packs to there, and a stored member would leave a gap in the dictionary
/// the next one is decoded against. A filter the caller named is applied
/// whatever it does to the size, as it is when the comparison comes after.
fn probe_members(
    sources: &[EntrySource],
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Option<Records<bool>>> {
    if plan.method == 0 || plan.solid || matches!(plan.filter_policy, FilterPolicy::Explicit(_)) {
        return Ok(None);
    }
    let mut candidates = Records::new(sources.len(), resources)?;
    for (index, source) in sources.iter().enumerate() {
        // A rewrite's sources are staged one window at a time, in order, and
        // held until written, so opening one ahead to sample it can need
        // staging that the members before it still hold.
        if source.max_preparation_window() != usize::MAX {
            continue;
        }
        let size = source.len().map_err(|error| error_context(index, error))?;
        if crate::incompressible::sample_ranges(size).is_some() {
            candidates.push((index, size))?;
        }
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut stored = Records::collect(sources.iter().map(|_| Ok(false)), resources)?;
    let mut any = false;
    let sample = crate::incompressible::SAMPLE_LEN;
    let charge = super::streaming_lz_workspace(sample as u64, sample, false) + sample as u64;
    crate::parallel::map_slice_windowed(
        &candidates,
        crate::parallel::default_window(),
        |_, opens| {
            if opens {
                resources
                    .acquire_serialising_cancellable(charge, &|| advance.is_cancelled())
                    .map(Some)
            } else {
                resources.try_acquire_serialising(charge)
            }
        },
        |&(index, size), _permit| {
            let cancelled = || advance.is_cancelled() || resources.is_cancelled();
            let probe = || -> Result<bool> {
                let mut reader = sources[index].open()?;
                crate::incompressible::looks_incompressible(&mut *reader, size, |sample| {
                    if cancelled() {
                        return Err(Error::Cancelled);
                    }
                    match &resources.execution {
                        Some(allowance) => probe_packed_len(sample, plan, &cancelled, allowance),
                        None => probe_packed_len(sample, plan, &cancelled, &Allowance::default()),
                    }
                })
            };
            probe().map_err(|error| error_context(index, error))
        },
        |&(index, _), store| {
            stored[index] = store;
            any |= store;
            Ok(())
        },
    )?;
    Ok(any.then_some(stored))
}

/// What a probe sample packs to coded on its own at level 1, unfiltered: the
/// cheapest coding there is, and about the least any level saves.
fn probe_packed_len<B: Budget>(
    sample: &[u8],
    plan: &CompressPlan,
    cancelled: &dyn Fn() -> bool,
    allowance: &B,
) -> Result<usize> {
    let options = super::filter_policy::encode_options_for_level(Some(1), sample.len() as u64)?;
    let packed = crate::codec::rar50::encode_owned_member(
        sample,
        plan.algorithm_version,
        options,
        None,
        Some(&mut |_| !cancelled()),
        allowance,
    )?;
    Ok(packed.len())
}

#[allow(clippy::too_many_arguments)]
fn compress_members_as_planned(
    sources: &[EntrySource],
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    stored_hashed_later: bool,
    straight: &Straight<'_>,
    consume: &mut Consume<'_>,
) -> Result<()> {
    let mut integrity = Records::new(sources.len(), resources)?;
    for (index, source) in sources.iter().enumerate() {
        let input_size = source.len().map_err(|error| error_context(index, error))?;
        // Compression fills these checksums while consuming the source. A
        // member hashed on its copy keeps the placeholder, which sizes its
        // header until the real hash is patched in.
        integrity.push((input_size, 0, plan.blake2sp.then_some([0; 32])))?;
    }

    let mut execution =
        ExecutionPlan::with_resources(plan, integrity.iter().map(|entry| entry.0), resources)?;
    for (index, &(input_size, ..)) in integrity.iter().enumerate() {
        if straight(index, input_size) {
            execution.in_place(plan, index, input_size, resources);
        }
    }
    // One rule, shared with the whole-member path and the legacy writers, plus
    // the two cases that are not really fallbacks: storing was asked for, and
    // an empty member has nothing to pack. `StoreFallback` refuses to store a
    // solid member, whose successors decode against the dictionary it fills.
    let store = |input_size: u64, packed_len: u64| {
        plan.method == 0
            || input_size == 0
            || should_store_compressed_payload(
                input_size,
                packed_len,
                plan.solid,
                &plan.filter_policy,
            )
    };
    let stored = |index: usize, (input_size, crc32, hash): Integrity, pending: bool| {
        Ok::<_, Error>(Handed::Member(CompressedMember {
            input_size,
            crc32,
            hash,
            store: true,
            packed: Spool::create_parked(resources)?,
            solid_continuation: plan.solid && index > 0,
            checksums_pending: pending,
        }))
    };
    match execution {
        ExecutionPlan::IndependentMembers(members) => compress_members_whole(
            sources,
            &integrity,
            plan,
            &members,
            resources,
            advance,
            error_context,
            straight,
            consume,
        ),
        // Storing is not "compress and hope it does not help": the header
        // records method zero, so the payload must be the source bytes.
        ExecutionPlan::Stored if stored_hashed_later => integrity
            .iter()
            .enumerate()
            .try_for_each(|(index, &member)| consume(index, stored(index, member, true)?)),
        ExecutionPlan::Stored => hash_stored_members(
            sources,
            &integrity,
            plan.blake2sp,
            resources,
            advance,
            error_context,
            &mut |index, size, crc, hash| consume(index, stored(index, (size, crc, hash), false)?),
        ),
        ExecutionPlan::Blocks {
            workspace,
            admission,
            run_filters,
        } => compress_streaming_members(
            sources,
            &integrity,
            plan,
            run_filters,
            workspace,
            admission,
            resources,
            advance,
            error_context,
            straight,
            &mut |index, packing| {
                let input_size = integrity[index].0;
                let handed = settle(packing, input_size, plan.solid && index > 0, &store);
                consume(index, handed)
            },
        ),
    }
}

fn settle<'b>(
    packing: Packing<'b>,
    input_size: u64,
    solid_continuation: bool,
    store: &dyn Fn(u64, u64) -> bool,
) -> Handed<'b> {
    match packing {
        Packing::Done(packed, crc32, hash) => Handed::Member(CompressedMember {
            input_size,
            crc32,
            hash,
            store: store(input_size, packed.len()),
            packed,
            solid_continuation,
            checksums_pending: false,
        }),
        Packing::Opening(input_size) => Handed::Opening { input_size },
        Packing::Packed(bytes) => Handed::Packed(bytes),
        Packing::Closed {
            crc32,
            hash,
            packed_len,
        } => Handed::Closed(ClosedMember {
            input_size,
            crc32,
            hash,
            packed_len,
            store: store(input_size, packed_len),
        }),
    }
}

/// A large member goes out as it is packed, so it is handed on in pieces.
pub(super) enum Handed<'b> {
    Member(CompressedMember),
    /// Every member before it has been handed on.
    Opening {
        input_size: u64,
    },
    Packed(&'b [u8]),
    Closed(ClosedMember),
}

pub(super) struct ClosedMember {
    pub(super) input_size: u64,
    pub(super) crc32: u32,
    pub(super) hash: Option<[u8; 32]>,
    pub(super) packed_len: u64,
    /// Its packed bytes are already out, so the writer stores it over them.
    pub(super) store: bool,
}

impl ClosedMember {
    pub(super) fn stored(&self, resources: &WriterResources) -> Result<CompressedMember> {
        Ok(CompressedMember {
            input_size: self.input_size,
            crc32: self.crc32,
            hash: self.hash,
            packed: Spool::create_parked(resources)?,
            store: true,
            solid_continuation: false,
            checksums_pending: false,
        })
    }
}

pub(super) type Consume<'a> = dyn FnMut(usize, Handed<'_>) -> Result<()> + 'a;
pub(super) type Straight<'a> = dyn Fn(usize, u64) -> bool + Sync + 'a;

/// The store rule differs by path, so packing hands on before applying it.
enum Packing<'b> {
    Done(Spool, u32, Option<[u8; 32]>),
    Opening(u64),
    Packed(&'b [u8]),
    Closed {
        crc32: u32,
        hash: Option<[u8; 32]>,
        packed_len: u64,
    },
}
type ConsumePacked<'a> = dyn FnMut(usize, Packing<'_>) -> Result<()> + 'a;

/// Scoped sources can retain their payloads through member emission.
fn source_preparation_window(sources: &[EntrySource]) -> usize {
    sources
        .iter()
        .map(EntrySource::max_preparation_window)
        .min()
        .unwrap_or(usize::MAX)
        .max(1)
}

/// Members' checksums are independent, so a window of them is hashed across the pool.
fn hash_stored_members(
    sources: &[EntrySource],
    integrity: &[Integrity],
    blake2sp: bool,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    consume: &mut dyn FnMut(usize, u64, u32, Option<[u8; 32]>) -> Result<()>,
) -> Result<()> {
    let jobs = Records::collect(
        integrity
            .iter()
            .enumerate()
            .map(|(index, &(size, ..))| Ok((index, size))),
        resources,
    )?;
    crate::parallel::map_slice_windowed(
        &jobs,
        crate::parallel::default_window().min(source_preparation_window(sources)),
        |&(index, size), opens| {
            let block = super::stored_block_len(size) as u64;
            let permit = if opens {
                resources.acquire_serialising_cancellable(block, &|| advance.is_cancelled())?
            } else {
                match resources.try_acquire_serialising(block)? {
                    Some(permit) => permit,
                    None => return Ok(None),
                }
            };
            advance.started(index, size);
            Ok(Some(permit))
        },
        // Failures wait for `consume`, so the first member in order is reported
        // rather than the first to fail.
        |&(index, size), _permit| {
            Ok(super::source_integrity(
                &sources[index],
                size,
                blake2sp,
                advance,
                resources,
            ))
        },
        |&(index, size), checksums| {
            let (crc, hash) = checksums.map_err(|error| error_context(index, error))?;
            // Hashing reported its progress as it read.
            advance.finished(index, size);
            consume(index, size, crc, hash)
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn compress_streaming_members(
    sources: &[EntrySource],
    integrity: &[Integrity],
    plan: &CompressPlan,
    run_filters: bool,
    required: u64,
    admission: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    straight: &Straight<'_>,
    consume: &mut ConsumePacked<'_>,
) -> Result<()> {
    if resources.memory_limit() < required {
        resources
            .acquire_cancellable(required, plan.dictionary_size, &|| advance.is_cancelled())?;
        unreachable!("oversized workspace acquisition must fail");
    }
    let batch_capacity = crate::parallel::threads();
    let runs_per_job = if plan.solid {
        1
    } else {
        runs_per_job(
            plan,
            integrity.iter().map(|&(size, ..)| size).max().unwrap_or(0),
            admission,
            resources
                .execution
                .as_ref()
                .map_or(resources.memory_limit(), |ledger| {
                    resources.memory_limit().min(ledger.available())
                }),
            batch_capacity,
        )
    };

    // One dictionary runs through solid members, so none can be stored
    // instead once its packed bytes have gone out.
    match (&resources.execution, plan.solid) {
        (Some(allowance), true) => compress_solid_chain(
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
            straight,
            consume,
        ),
        (Some(allowance), false) => compress_independent_members(
            sources,
            integrity,
            plan,
            run_filters,
            runs_per_job,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
            allowance,
            straight,
            consume,
        ),
        (None, true) => compress_solid_chain(
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
            straight,
            consume,
        ),
        (None, false) => compress_independent_members(
            sources,
            integrity,
            plan,
            run_filters,
            runs_per_job,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
            &Allowance::default(),
            straight,
            consume,
        ),
    }
}

/// What one encode of a filter search over up to `len` bytes holds.
fn filter_search_workspace(options: EncodeOptions, len: u64) -> u64 {
    use crate::codec::rar50::{lazy_parse_workspace, MAX_LZ_BLOCK_SIZE};
    let piece = len.min(filter_search_bytes() as u64);
    let reach = piece.min(options.max_match_distance as u64);
    let block = piece.min(MAX_LZ_BLOCK_SIZE as u64) as usize;
    let scratch = if options.optimal_parse {
        super::streaming_lz_workspace(reach, block, true)
    } else {
        lazy_parse_workspace(options, usize::try_from(reach).unwrap_or(usize::MAX), block)
    };
    scratch.saturating_add(piece.saturating_mul(2))
}

/// Assembly, filter selection and coding hold different sets of buffers.
#[derive(Default, Clone, Copy)]
struct WaveWorkspace {
    assembly: u64,
    filter_inputs: u64,
    /// One filter search's scratch for each job, which searches its pieces
    /// one at a time under an execution ledger.
    filter_search: u64,
    /// One for each piece, and the most one holds, for the searches of every
    /// piece in the wave side by side ([`choose_run_filters`]).
    piece_searches: u64,
    piece_search: u64,
    coding: u64,
}

impl WaveWorkspace {
    #[allow(clippy::too_many_arguments)]
    fn add_job(
        self,
        options: EncodeOptions,
        len: u64,
        history: u64,
        block: usize,
        filter_piece: u64,
        filter_pieces: u64,
        tree_chunk_size: Option<usize>,
    ) -> Self {
        use crate::codec::rar50::{lazy_parse_workspace, MAX_LZ_BLOCK_SIZE};
        let cap = if tree_chunk_size.is_some() {
            // A run can start with a non-power-of-two block and grow from it.
            len.saturating_mul(2)
        } else {
            len.checked_next_power_of_two().unwrap_or(len)
        };
        let block = block
            .min(MAX_LZ_BLOCK_SIZE)
            .min(usize::try_from(len).unwrap_or(usize::MAX));
        let window = len.saturating_add(history);
        let reach = window.min(options.max_match_distance as u64);
        let scratch = |reach: u64, block: usize| {
            if options.optimal_parse {
                super::streaming_lz_workspace(reach, block, true)
            } else {
                lazy_parse_workspace(options, usize::try_from(reach).unwrap_or(usize::MAX), block)
            }
        };
        // While the coordinator builds windows, the assembled jobs can still
        // own their original histories and their run buffers.
        let assembly = cap
            .saturating_mul(2)
            .saturating_add(window)
            .saturating_add(history);
        let search = if filter_piece > 0 {
            filter_search_workspace(options, filter_piece)
        } else {
            0
        };
        // Optimal coding's window term includes room beside the finder links.
        // Lazy coding explicitly adds the window, which it owns per job.
        let coding = if let Some(chunk) = tree_chunk_size {
            let scratch = crate::codec::rar50::single_pass_tree_workspace(
                options,
                usize::try_from(window).unwrap_or(usize::MAX),
                usize::try_from(len).unwrap_or(usize::MAX),
                chunk,
            );
            // A worker growing its own window releases the separate run
            // before parsing. Idle workers can still own both source buffers.
            if history == 0 {
                cap.saturating_add(scratch)
            } else {
                let grown = window.max(history.saturating_mul(2));
                grown
                    .saturating_add(scratch.max(cap))
                    .max(cap.saturating_add(history))
            }
        } else {
            scratch(reach, block).saturating_add(if options.optimal_parse {
                len.saturating_add(cap)
            } else {
                window.saturating_add(cap.saturating_mul(2))
            })
        };
        Self {
            assembly: self.assembly.saturating_add(assembly),
            filter_inputs: self.filter_inputs.saturating_add(cap),
            filter_search: self.filter_search.saturating_add(search),
            piece_searches: self
                .piece_searches
                .saturating_add(search.saturating_mul(filter_pieces)),
            piece_search: self.piece_search.max(search),
            coding: self.coding.saturating_add(coding),
        }
    }

    /// `seed` is held beside the coded jobs' trees while their windows are
    /// shared out, before any of them codes. `piece_threads` is how many
    /// filter searches run at once when the wave's pieces are searched side by
    /// side, or `None` when each job searches its own in turn.
    fn peak(self, retained: u64, seed: u64, piece_threads: Option<u64>) -> u64 {
        let search = piece_threads.map_or(self.filter_search, |threads| {
            self.piece_searches
                .min(self.piece_search.saturating_mul(threads))
                .max(self.filter_search)
        });
        let filters = self.filter_inputs.saturating_add(search);
        self.assembly
            .max(filters)
            .max(self.coding.saturating_add(seed))
            .saturating_add(retained)
    }
}

#[derive(Default)]
struct BlockWave {
    workspace: WaveWorkspace,
    permit: Option<crate::streaming::MemoryPermit>,
    // The hard ledger also holds the scopes' control blocks and any existing
    // coordinator allocations, such as retained histories and spool storage.
    scopes: u64,
    /// The member of the last job that seeds a tree from history, and how
    /// many of its jobs in a row do.
    seeding: Option<(usize, usize)>,
    /// Whether a member has two jobs that seed trees, which may then share a
    /// seed tree ([`seed_group_trees`]).
    shared_seed: bool,
}

impl BlockWave {
    #[allow(clippy::too_many_arguments)]
    fn admit(
        &mut self,
        plan: &CompressPlan,
        filter_runs: bool,
        len: u64,
        min_len: u64,
        history: u64,
        retained: u64,
        required: u64,
        resources: &WriterResources,
        advance: &dyn CompressionProgress,
        seeding: Option<usize>,
    ) -> Result<bool> {
        let seeding = match seeding {
            Some(member) => Some(match self.seeding {
                Some((last, count)) if last == member => (member, count + 1),
                _ => (member, 1),
            }),
            None => self.seeding,
        };
        let shared_seed = self.shared_seed || seeding.is_some_and(|(_, count)| count >= 2);
        let seed = if shared_seed {
            run_trees_workspace(plan.encode_options)
        } else {
            0
        };
        let filter_piece = if filter_runs && plan.filter_policy == FilterPolicy::Auto {
            len
        } else {
            0
        };
        let workspace = self.workspace.add_job(
            plan.encode_options,
            len,
            history,
            crate::codec::rar50::MAX_LZ_BLOCK_SIZE,
            filter_piece,
            filter_piece.div_ceil(filter_search_bytes() as u64),
            single_pass_tree_chunk(plan, filter_runs, min_len, history)
                .filter(|_| resources.execution.is_none()),
        );
        let piece_threads = resources
            .execution
            .is_none()
            .then(|| crate::parallel::threads() as u64);
        let charge = workspace.peak(retained, seed, piece_threads);
        let scopes = self
            .scopes
            .saturating_add(required.saturating_add(crate::codec::workspace::RESERVATION_BYTES));
        if let Some(permit) = &mut self.permit {
            if resources.execution.as_ref().is_some_and(|ledger| {
                let incoming = len
                    .saturating_mul(4)
                    .saturating_add(history.saturating_mul(2));
                scopes.saturating_add(incoming) > ledger.available()
            }) || !permit.try_grow_to(charge)
            {
                return Ok(false);
            }
        } else {
            self.permit = Some(resources.acquire_cancellable(
                charge.min(resources.memory_limit()),
                plan.dictionary_size,
                &|| advance.is_cancelled(),
            )?);
        }
        self.scopes = scopes;
        self.seeding = seeding;
        self.shared_seed = shared_seed;
        Ok(true)
    }

    /// Grows the charge for the tail of the job just recorded, `len` bytes
    /// behind `history`, to be coded as a job of its own ([`split_tail`]):
    /// its coding beside the job's, which stays charged for the whole. Only a
    /// wave without an execution ledger cuts tails off.
    fn admit_tail(
        &mut self,
        plan: &CompressPlan,
        filter_runs: bool,
        member: usize,
        len: u64,
        history: u64,
        retained: u64,
    ) -> bool {
        let Some(permit) = &mut self.permit else {
            return false;
        };
        let seeding = match self.seeding {
            Some((last, count)) if last == member => (member, count + 1),
            _ => (member, 1),
        };
        let shared_seed = self.shared_seed || seeding.1 >= 2;
        let seed = if shared_seed {
            run_trees_workspace(plan.encode_options)
        } else {
            0
        };
        let tail = WaveWorkspace::default().add_job(
            plan.encode_options,
            len,
            history,
            crate::codec::rar50::MAX_LZ_BLOCK_SIZE,
            0,
            0,
            single_pass_tree_chunk(plan, filter_runs, len, history),
        );
        let workspace = WaveWorkspace {
            coding: self.workspace.coding.saturating_add(tail.coding),
            ..self.workspace
        };
        let charge = workspace.peak(retained, seed, Some(crate::parallel::threads() as u64));
        if !permit.try_grow_to(charge) {
            return false;
        }
        self.workspace = workspace;
        self.seeding = Some(seeding);
        self.shared_seed = shared_seed;
        true
    }

    fn record<B: Budget>(
        &mut self,
        job: &BlockJob<B>,
        plan: &CompressPlan,
        filter_runs: bool,
        history: u64,
    ) {
        let mut block = crate::codec::rar50::MAX_LZ_BLOCK_SIZE;
        if !plan.encode_options.optimal_parse && (plan.solid || !filter_runs) {
            let mut start = 0;
            block = job
                .blocks
                .iter()
                .map(|&(_, end, _)| {
                    let len = end - start;
                    start = end;
                    len
                })
                .max()
                .unwrap_or(0);
        }
        let (filter_piece, filter_pieces) =
            if !filter_runs || plan.filter_policy != FilterPolicy::Auto {
                (0, 0)
            } else {
                filter_pieces(job).fold((0, 0), |(most, count), (piece, _)| {
                    (most.max(piece.len()), count + 1)
                })
            };
        self.workspace = self.workspace.add_job(
            plan.encode_options,
            job.data.len() as u64,
            history,
            block,
            filter_piece as u64,
            filter_pieces,
            single_pass_tree_chunk(plan, filter_runs, job.data.len() as u64, history)
                .filter(|_| !B::LIMITED),
        );
    }
}

// A short run behind a long history can use chains, whose frontier has a
// different limit. Before reading, use the smallest run the job could hold.
fn single_pass_tree_chunk(
    plan: &CompressPlan,
    filter_runs: bool,
    len: u64,
    history: u64,
) -> Option<usize> {
    let options = plan.encode_options;
    (options.optimal_parse
        && options.parse_passes == 1
        && !filter_runs
        && !plan.solid
        && history <= len.saturating_mul(4))
    .then_some(plan.block_size)
}

/// The last block of a run can cross its nominal boundary, and a short
/// independent tail can be absorbed by the preceding run.
fn job_size_bound(plan: &CompressPlan, joined: usize, unread: u64) -> u64 {
    let run = if plan.solid {
        run_size(plan)
    } else {
        member_run_size(plan)
    };
    let end_slack = crate::codec::rar50::MAX_LZ_BLOCK_SIZE.saturating_sub(plan.block_size);
    let tail = if !plan.solid && run < run_size(plan) {
        plan.encode_options.max_match_distance / 4
    } else {
        0
    };
    let nominal = (run as u64).saturating_mul(joined as u64);
    let bound = nominal
        .saturating_add((end_slack as u64).saturating_mul(joined as u64))
        .saturating_add(tail as u64);
    unread.min(bound)
}

/// Compresses independent whole members concurrently, with each workspace
/// admitted against the shared budget before its input is loaded.
///
/// The resolved plan schedules filter fallback outside whole-member batches.
#[allow(clippy::too_many_arguments)]
fn compress_members_whole(
    sources: &[EntrySource],
    integrity: &[Integrity],
    plan: &CompressPlan,
    members: &[MemberPlan],
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    straight: &Straight<'_>,
    consume: &mut Consume<'_>,
) -> Result<()> {
    let source_window = source_preparation_window(sources);
    let mut start = 0;
    while start < sources.len() {
        if advance.is_cancelled() || resources.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let end_of_window = start.saturating_add(source_window).min(members.len());
        let members = &members[..end_of_window];
        if let Execution::Blocks { run_filters, .. } = members[start].execution {
            let end = runs_lookahead(members, integrity, start, straight);
            if members[start..end]
                .iter()
                .any(|member| runs_kind(member) != Some(run_filters))
            {
                compress_lookahead(
                    start..end,
                    sources,
                    integrity,
                    plan,
                    members,
                    resources,
                    advance,
                    error_context,
                    straight,
                    consume,
                )?;
                start = end;
                continue;
            }
            // Consecutive fallback members share waves, so a set of mid-size
            // members fills the machine instead of running one member's two
            // or three runs at a time. Each member keeps its own runs,
            // history and filters, so the bytes do not depend on the grouping.
            let end = start
                + members[start..]
                    .iter()
                    .take_while(|member| runs_kind(member) == Some(run_filters))
                    .count();
            let required = members[start..end]
                .iter()
                .map(|member| member.workspace)
                .max()
                .unwrap_or(0);
            let admission = members[start..end]
                .iter()
                .map(|member| member.admission)
                .max()
                .unwrap_or(0);
            compress_fallback_members(
                start,
                &sources[start..end],
                &integrity[start..end],
                plan,
                run_filters,
                required,
                admission,
                resources,
                advance,
                error_context,
                straight,
                consume,
            )?;
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
        let permit = resources
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
        // The writer may need workspace of its own for what it is handed.
        drop(permit);
        for (index, member) in (start..end).zip(completed) {
            consume(index, Handed::Member(member))?;
        }
        start = end;
    }
    Ok(())
}

/// Past 32 MiB the lookahead stopped gaining and only held more packed members.
const RUNS_LOOKAHEAD_BYTES: u64 = 64 * 1024 * 1024;
const RUNS_LOOKAHEAD_MEMBERS: usize = 1024;

/// So a few members coded in runs share waves across the whole members between them.
fn runs_lookahead(
    members: &[MemberPlan],
    integrity: &[Integrity],
    start: usize,
    straight: &Straight<'_>,
) -> usize {
    let mut last = start;
    let mut bytes = 0u64;
    let mut end = start;
    while end < members.len() && end - start < RUNS_LOOKAHEAD_MEMBERS {
        let size = integrity[end].0;
        bytes = bytes.saturating_add(size);
        if straight(end, size) || (end > start && bytes > RUNS_LOOKAHEAD_BYTES) {
            break;
        }
        if matches!(members[end].execution, Execution::Blocks { .. }) {
            last = end;
        }
        end += 1;
    }
    last + 1
}

/// No member's bytes depend on its neighbours, so each kind is coded as if the others were not there.
#[allow(clippy::too_many_arguments)]
fn compress_lookahead(
    window: std::ops::Range<usize>,
    sources: &[EntrySource],
    integrity: &[Integrity],
    plan: &CompressPlan,
    members: &[MemberPlan],
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    straight: &Straight<'_>,
    consume: &mut Consume<'_>,
) -> Result<()> {
    let first = window.start;
    let mut packed = Records::collect(window.clone().map(|_| Ok(None)), resources)?;
    for wanted in [Some(true), Some(false), None] {
        let count = members[window.clone()]
            .iter()
            .filter(|member| runs_kind(member) == wanted)
            .count();
        if count == 0 {
            continue;
        }
        let mut indexes = Records::new(count, resources)?;
        let mut picked_sources = Records::new(count, resources)?;
        let mut picked_integrity = Records::new(count, resources)?;
        let mut picked_members = Records::new(count, resources)?;
        for index in window
            .clone()
            .filter(|&index| runs_kind(&members[index]) == wanted)
        {
            indexes.push(index)?;
            picked_sources.push(sources[index].clone())?;
            picked_integrity.push(integrity[index])?;
            picked_members.push(members[index])?;
        }
        compress_members_whole(
            &picked_sources,
            &picked_integrity,
            plan,
            &picked_members,
            resources,
            &Remapped::new(&indexes, advance),
            &|member, error| error_context(indexes[member], error),
            &|member, size| straight(indexes[member], size),
            &mut |member, handed| match handed {
                Handed::Member(member_packed) => {
                    packed[indexes[member] - first] = Some(member_packed);
                    Ok(())
                }
                _ => unreachable!("no member in a lookahead goes out straight"),
            },
        )?;
    }
    for (offset, member) in packed.into_iter().enumerate() {
        let member = member.expect("every member in a lookahead is coded");
        consume(first + offset, Handed::Member(member))?;
    }
    Ok(())
}

/// Whether a member is coded in runs that search filters, in runs that do not, or whole.
fn runs_kind(member: &MemberPlan) -> Option<bool> {
    match member.execution {
        Execution::Blocks { run_filters, .. } => Some(run_filters),
        Execution::WholeMember => None,
    }
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
    integrity: Integrity,
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    allowance: &B,
) -> Result<CompressedMember> {
    let (input_size, _, _) = integrity;
    let mut crc = Crc32::new();
    let mut hasher = plan.blake2sp.then(blake2sp::Hasher::new);

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
            if let Some(hasher) = &mut hasher {
                hasher.update(chunk);
            }
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
        hash: hasher.map(blake2sp::Hasher::finalize),
        store: stored,
        packed: packed_spool,
        solid_continuation: false,
        checksums_pending: false,
    })
}

/// Execute the planned filter fallback without re-entering planning. Block
/// execution uses only `encode_options` and filters each run; the candidate
/// list belongs to whole-member execution.
#[allow(clippy::too_many_arguments)]
fn compress_fallback_members(
    first: usize,
    sources: &[EntrySource],
    integrity: &[Integrity],
    plan: &CompressPlan,
    run_filters: bool,
    required: u64,
    admission: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    straight: &Straight<'_>,
    consume: &mut Consume<'_>,
) -> Result<()> {
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
    compress_streaming_members(
        sources,
        integrity,
        plan,
        run_filters,
        required,
        admission,
        resources,
        &Remapped {
            first,
            progress: advance,
        },
        &|member, error| error_context(first + member, error),
        &|member, size| straight(first + member, size),
        &mut |member, packing| {
            let store = |input_size, packed_len| {
                should_store_compressed_payload(input_size, packed_len, false, &plan.filter_policy)
            };
            let handed = settle(packing, integrity[member].0, false, &store);
            consume(first + member, handed)
        },
    )
    // What a member was handed back with already names its member.
    .map_err(|error| match error.entry_context() {
        Some(_) => error,
        None => error_context(first, error),
    })
}

/// Members with independent dictionaries. A wave takes each member's runs in
/// order until it runs out, then the next member's, so a batch of small
/// members still saturates the machine and a large member's runs in a wave
/// are consecutive, which is what lets them share a window and an index.
///
/// A run is coded from its own bytes and its member's history, so which
/// runs share a wave never changes the archive. With `filter_runs`, each run
/// chooses its own filters.
#[allow(clippy::too_many_arguments)]
fn compress_independent_members<B: Budget + Send + Sync>(
    sources: &[EntrySource],
    integrity: &[Integrity],
    plan: &CompressPlan,
    filter_runs: bool,
    runs_per_job: usize,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    allowance: &B,
    straight: &Straight<'_>,
    consume: &mut ConsumePacked<'_>,
) -> Result<()>
where
    B::Charge: Send,
{
    let group_capacity = batch_capacity.min(source_preparation_window(sources));
    let mut group_start = 0;
    while group_start < sources.len() {
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
                    plan.blake2sp,
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
        let mut handed = 0usize;
        let goes_straight = |stream: &MemberStream<B>| straight(stream.member, stream.input_size);
        while streams.iter().any(MemberStream::has_more) {
            // Between waves, so writing a whole member holds no workspace.
            hand_on_done(&mut streams, &mut handed, consume)?;
            // A member that goes straight out opens a wave of its own, once
            // every member before it is out.
            if let Some(member) = (cursor..streams.len()).find(|&m| streams[m].has_more()) {
                let stream = &mut streams[member];
                if offsets[member] == 0 && goes_straight(stream) {
                    debug_assert_eq!(handed, member, "members before it are out");
                    stream.straight = true;
                    stream.packed = None;
                    consume(stream.member, Packing::Opening(stream.input_size))?;
                }
            }
            let mut wave = BlockWave::default();
            let mut jobs = Records::new(batch_capacity, resources)?;
            let mut misses = 0usize;
            // Tails to be cut off into jobs of their own once filters are chosen.
            let mut tails = 0usize;
            while jobs.len() + tails < batch_capacity && misses < streams.len() {
                let member = cursor;
                let stream = &mut streams[member];
                if !stream.has_more() {
                    cursor = (cursor + 1) % streams.len();
                    misses += 1;
                    continue;
                }
                misses = 0;
                if offsets[member] == 0 && !stream.straight && goes_straight(stream) {
                    break;
                }

                let history = offsets[member].min(plan.encode_options.max_match_distance) as u64;
                let len = job_size_bound(plan, runs_per_job, stream.unread());
                if !wave.admit(
                    plan,
                    filter_runs,
                    len,
                    stream.unread().min(member_run_size(plan) as u64),
                    history,
                    plan.encode_options.max_match_distance as u64,
                    required,
                    resources,
                    advance,
                    // Only a run with history seeds a tree, and only a wave
                    // whose windows are shared seeds them together.
                    (history > 0 && resources.execution.is_none()).then_some(member),
                )? {
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
                        Buffer::copied(&histories[member], allowance)?
                    },
                    blocks: Records::new(0, resources)?,
                    offset: offsets[member],
                    seams: Records::new(0, resources)?,
                    filters: Records::new(0, resources)?,
                    segments: Records::new(0, resources)?,
                    records: None,
                    shared: None,
                    tail: None,
                    tree: false,
                };
                let mut run_start = 0;
                // Where the last run would have ended had it not taken the tail.
                let mut tail = None;
                loop {
                    while stream.has_more()
                        && (job.data.len() - run_start < member_run_size(plan)
                            || absorbs_tail(plan, stream.unread()))
                    {
                        if job.data.len() - run_start >= member_run_size(plan) {
                            tail.get_or_insert(job.data.len());
                        }
                        job.append(
                            read_block(stream, plan.block_size, advance)
                                .map_err(|error| error_context(stream.member, error))?,
                        )?;
                        job.blocks
                            .push_growing((member, job.data.len(), !stream.has_more()))?;
                    }
                    if job.seams.len() + 1 >= runs_per_job
                        || !stream.has_more()
                        || !next_run_searches_tree(plan, stream.unread())
                    {
                        break;
                    }
                    run_start = job.data.len();
                    job.seams.push_growing(run_start)?;
                }
                wave.record(&job, plan, filter_runs, history);
                // A tail worth a thread of its own, where there is one, is coded
                // on a tree seeded from its own history rather than after the
                // run it joined ([`split_tail`]).
                let tail = tail.filter(|&at| {
                    resources.execution.is_none()
                        && crate::parallel::threads() > 1
                        && jobs.len() + tails + 2 <= batch_capacity
                        && job.data.len() - at >= member_run_size(plan) / 4
                });
                if let Some(at) = tail {
                    let dictionary = plan.encode_options.max_match_distance;
                    if wave.admit_tail(
                        plan,
                        filter_runs,
                        member,
                        (job.data.len() - at) as u64,
                        (history as usize).saturating_add(at).min(dictionary) as u64,
                        dictionary as u64,
                    ) {
                        job.tail = Some(at);
                        tails += 1;
                    }
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
                    choose_run_filters(&mut jobs, plan, required, resources, advance)?;
                }
            }
            if tails > 0 {
                jobs = split_tails(jobs, filter_runs, plan, resources, allowance)?;
            }
            if filter_runs {
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
                        let mut window = Buffer::copied(&job.data, allowance)?;
                        job.filter_in_place(&mut window, allowance)?;
                        histories[member]
                            .remember(&window, plan.encode_options.max_match_distance)?;
                    }
                }
            }

            let seeding = if resources.execution.is_none() {
                share_member_windows(&mut jobs, plan, false, allowance)?
            } else {
                Vec::new()
            };
            compress_wave(
                jobs,
                seeding,
                plan,
                required,
                &mut streams,
                resources,
                advance,
                error_context,
                consume,
            )?;
        }

        hand_on_done(&mut streams, &mut handed, consume)?;
        debug_assert_eq!(handed, streams.len(), "every member is handed on");
        group_start = group_end;
    }
    Ok(())
}

/// One dictionary running through every member in order.
#[allow(clippy::too_many_arguments)]
fn compress_solid_chain<B: Budget + Send + Sync>(
    sources: &[EntrySource],
    integrity: &[Integrity],
    plan: &CompressPlan,
    filter_runs: bool,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    allowance: &B,
    straight: &Straight<'_>,
    consume: &mut ConsumePacked<'_>,
) -> Result<()>
where
    B::Charge: Send,
{
    let source_window = source_preparation_window(sources);
    let mut streams = Records::new(sources.len(), resources)?;

    let mut history = Buffer::new(allowance);
    let mut next = 0usize;
    // Members before this have been handed to `consume`.
    let mut handed = 0usize;
    // Runs cross into it as into any member, so both outputs pack alike; the
    // wave its first run is in ends with that run, and it opens after.
    let goes_straight = |stream: &MemberStream<B>| {
        !stream.started && !stream.straight && straight(stream.member, stream.input_size)
    };
    let mut remaining = 0u64;
    let mut placed = 0u64;
    while handed < sources.len() {
        if handed == streams.len() {
            // Empty members can open during preparation. Admit their sources
            // in the same window as the ones read while assembling runs.
            let end = handed.saturating_add(source_window).min(sources.len());
            for member in handed..end {
                let size = integrity[member].0;
                let stream = MemberStream::new(
                    member,
                    &sources[member],
                    size,
                    plan.blake2sp,
                    resources,
                    advance,
                    allowance,
                )
                .map_err(|error| error_context(member, error))?;
                streams.push(stream)?;
                remaining = remaining.saturating_add(size);
            }
        }
        let mut wave = BlockWave::default();
        let mut jobs = Records::new(batch_capacity, resources)?;
        let mut opens = false;
        while jobs.len() < batch_capacity && !opens {
            while next < streams.len() && !streams[next].has_more() {
                next += 1;
            }
            if next == streams.len() {
                break;
            }
            let dictionary = plan.encode_options.max_match_distance as u64;
            if !wave.admit(
                plan,
                filter_runs,
                job_size_bound(plan, 1, remaining),
                0,
                placed.min(dictionary),
                dictionary,
                required,
                resources,
                advance,
                None,
            )? {
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
                seams: Records::new(0, resources)?,
                filters: Records::new(0, resources)?,
                segments: Records::new(0, resources)?,
                records: None,
                shared: None,
                tail: None,
                tree: false,
            };
            while job.data.len() < run_size(plan) {
                while next < streams.len() && !streams[next].has_more() {
                    next += 1;
                }
                let Some(stream) = streams.get_mut(next) else {
                    break;
                };
                opens |= goes_straight(stream);
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
            wave.record(&job, plan, filter_runs, placed.min(dictionary));
            remaining = remaining.saturating_sub(job.data.len() as u64);
            placed = placed.saturating_add(job.data.len() as u64);
            jobs.push(job)?;
        }

        if filter_runs && !jobs.is_empty() {
            // A solid run can hold many members, each searched on its own.
            choose_run_filters(&mut jobs, plan, required, resources, advance)?;
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

        if !jobs.is_empty() {
            if resources.execution.is_none() {
                share_member_windows(&mut jobs, plan, true, allowance)?;
            }
            compress_wave(
                jobs,
                Vec::new(),
                plan,
                required,
                &mut streams,
                resources,
                advance,
                error_context,
                consume,
            )?;
        }
        // The writer may need workspace of its own for what it is handed.
        drop(wave);
        hand_on_opening(&mut streams, &mut handed, straight, consume)?;
    }
    debug_assert_eq!(handed, streams.len(), "every member is handed on");
    Ok(())
}

/// A large member whose first run went into the spool opens once every
/// member before it is out, and what it packed to so far follows its header.
fn hand_on_opening<B: Budget>(
    streams: &mut [MemberStream<B>],
    handed: &mut usize,
    straight: &Straight<'_>,
    consume: &mut ConsumePacked<'_>,
) -> Result<()> {
    loop {
        hand_on_done(streams, handed, consume)?;
        let Some(stream) = streams.get_mut(*handed) else {
            return Ok(());
        };
        if stream.straight || !stream.started || !straight(stream.member, stream.input_size) {
            return Ok(());
        }
        consume(stream.member, Packing::Opening(stream.input_size))?;
        let mut head = stream
            .packed
            .take()
            .expect("a member is packed before it opens");
        head.rewind()?;
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let read = head.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            consume(stream.member, Packing::Packed(&chunk[..read]))?;
        }
        stream.straight = true;
    }
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
    if let Some(hash) = &mut stream.hash {
        hash.update(&data);
    }
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

/// How many tails [`split_tail`] has cut off, for tests to see that it did.
#[cfg(test)]
static TAILS_CUT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Cuts each job's tail ([`BlockJob::tail`]) off into a job of its own,
/// after it, where [`split_tail`] can.
fn split_tails<B: Budget>(
    jobs: Records<BlockJob<B>>,
    filter_runs: bool,
    plan: &CompressPlan,
    resources: &WriterResources,
    allowance: &B,
) -> Result<Records<BlockJob<B>>> {
    let tails = jobs.iter().filter(|job| job.tail.is_some()).count();
    let mut split = Records::new(jobs.len() + tails, resources)?;
    for mut job in jobs {
        let tail = match job.tail.take() {
            Some(at) => split_tail(&mut job, at, filter_runs, plan, resources, allowance)?,
            None => None,
        };
        split.push(job)?;
        if let Some(tail) = tail {
            split.push(tail)?;
        }
    }
    Ok(split)
}

/// Cuts `job`'s data at `at`, the end of a block in its last run, and returns
/// the bytes after as a job of its own, or `None` where that would change
/// what is coded.
///
/// The tail is coded as it is when its run parses straight on into it: on a
/// tree, here one seeded from its own history ([`BlockJob::tree`]), which
/// holds what the run's tree would have by then, in blocks cut where the
/// run's were, with the filters the run's search found in it. A run with
/// filters is cut where its filter records fit ([`filtered_run_cuts`]), and
/// each part, filtered or not, must then be cut where the whole run was,
/// which it is when those cuts fall on its blocks.
///
/// With `filter_runs`, the tail's history is left for the caller to fill
/// once the job's filtered bytes are known.
fn split_tail<B: Budget>(
    job: &mut BlockJob<B>,
    at: usize,
    filter_runs: bool,
    plan: &CompressPlan,
    resources: &WriterResources,
    allowance: &B,
) -> Result<Option<BlockJob<B>>> {
    let len = job.data.len();
    let run = job.seams.last().copied().unwrap_or(0);
    debug_assert!(run < at && at < len);
    let filtered = job
        .filters
        .iter()
        .any(|spec| spec.range.as_ref().is_none_or(|range| range.end > run));
    if filtered {
        let ends = job
            .blocks
            .iter()
            .filter(|&&(_, end, _)| end > run)
            .map(|&(_, end, _)| end - run);
        if !filtered_run_cuts(&job.data[run..]).eq(ends) {
            return Ok(None);
        }
    }
    let (member, _, _) = job.blocks[0];
    let mut blocks = Records::new(0, resources)?;
    let mut head = Records::new(0, resources)?;
    for &(member, end, last) in job.blocks.iter() {
        if end <= at {
            head.push_growing((member, end, false))?;
        } else {
            blocks.push_growing((member, end - at, last))?;
        }
    }
    let mut filters = Records::new(0, resources)?;
    let mut kept = Records::new(0, resources)?;
    for spec in job.filters.iter() {
        let range = spec.range.clone().unwrap_or(0..len);
        if range.start < at {
            kept.push_growing(crate::FilterSpec::range(
                spec.kind,
                range.start..range.end.min(at),
            ))?;
        }
        if range.end > at {
            filters.push_growing(crate::FilterSpec::range(
                spec.kind,
                range.start.max(at) - at..range.end - at,
            ))?;
        }
    }
    let data = Buffer::copied(&job.data[at..], allowance)?;
    job.data.truncate(at);
    job.blocks = head;
    job.filters = kept;
    let history = if filter_runs {
        Buffer::new(allowance)
    } else {
        let mut history = Buffer::copied(&job.history, allowance)?;
        history.remember(&job.data, plan.encode_options.max_match_distance)?;
        history
    };
    debug_assert_eq!(member, blocks[0].0);
    #[cfg(test)]
    TAILS_CUT.fetch_add(1, Ordering::Relaxed);
    Ok(Some(BlockJob {
        data,
        history,
        blocks,
        offset: job.offset + at,
        seams: Records::new(0, resources)?,
        filters,
        segments: Records::new(0, resources)?,
        records: None,
        shared: None,
        tail: None,
        tree: true,
    }))
}

/// The part of an explicit filter that falls in a job's run, ranged over it.
fn explicit_run_filter<B: Budget>(job: &mut BlockJob<B>, spec: &crate::FilterSpec) -> Result<()> {
    let mut found = Vec::new();
    for run in job.runs(job.data.len()) {
        let offset = job.offset + run.start;
        if let Some(range) = explicit_run_range(spec, offset..job.offset + run.end) {
            found.push(run.start + range.start..run.start + range.end);
        }
    }
    for range in found {
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

/// Each admitted job searches its own pieces in order, so at most one search
/// holds scratch for that job at a time. Without an execution ledger every
/// piece of the wave is searched side by side instead, as many at once as
/// there are threads ([`WaveWorkspace::peak`]).
fn choose_run_filters<B: Budget>(
    jobs: &mut [BlockJob<B>],
    plan: &CompressPlan,
    required: u64,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
) -> Result<()> {
    if resources.execution.is_some() {
        let searches = Records::collect(jobs.iter().map(Ok), resources)?;
        let found = run_jobs_admitted(
            searches,
            resources,
            advance,
            |_| required,
            |job, worker, progress, allowance| {
                let mut filters = Records::new(0, worker)?;
                for (range, offset) in filter_pieces(job) {
                    let found =
                        search_filter_piece(job, range, offset, plan, progress, worker, allowance)?;
                    for spec in found {
                        filters.push_growing(spec)?;
                    }
                }
                Ok(filters)
            },
        )?;
        for (job, filters) in jobs.iter_mut().zip(found) {
            job.filters = filters;
        }
        return Ok(());
    }
    let mut pieces = Records::new(0, resources)?;
    for (index, job) in jobs.iter().enumerate() {
        for (range, offset) in filter_pieces(job) {
            pieces.push_growing((index, range, offset))?;
        }
    }
    let owners = Records::collect(pieces.iter().map(|&(index, _, _)| Ok(index)), resources)?;
    let found = run_jobs(
        pieces,
        resources,
        advance,
        |(index, range, offset), progress| {
            search_filter_piece(
                &jobs[index],
                range,
                offset,
                plan,
                progress,
                resources,
                &Allowance::default(),
            )
        },
    )?;
    for job in jobs.iter_mut() {
        job.filters = Records::new(0, resources)?;
    }
    for (index, found) in owners.into_iter().zip(found) {
        for spec in found {
            jobs[index].filters.push_growing(spec)?;
        }
    }
    Ok(())
}

/// The pieces a job's filters are searched in, each with where it starts in
/// its file. A joined job searches on the same grid as its runs would alone.
fn filter_pieces<B: Budget>(
    job: &BlockJob<B>,
) -> impl Iterator<Item = (std::ops::Range<usize>, usize)> + '_ {
    let segments: Vec<(std::ops::Range<usize>, usize)> = if job.segments.is_empty() {
        job.runs(job.data.len())
            .map(|run| {
                let offset = job.offset + run.start;
                (run, offset)
            })
            .collect()
    } else {
        job.segments.iter().cloned().collect()
    };
    let piece = filter_search_bytes();
    segments
        .into_iter()
        .flat_map(move |(segment, file_offset)| {
            (segment.start..segment.end)
                .step_by(piece)
                .map(move |start| {
                    let end = (start + piece).min(segment.end);
                    (start..end, file_offset + (start - segment.start))
                })
        })
}

/// The filters found in one piece of `job`'s data, ranged over the data.
fn search_filter_piece<B: Budget, C: Budget>(
    job: &BlockJob<B>,
    range: std::ops::Range<usize>,
    offset: usize,
    plan: &CompressPlan,
    progress: &dyn CompressionProgress,
    resources: &WriterResources,
    allowance: &C,
) -> Result<Records<crate::FilterSpec>> {
    let specs = super::filter_policy::run_filters_with_allowance(
        &job.data[range.clone()],
        offset,
        plan.algorithm_version,
        plan.encode_options,
        &|| progress.is_cancelled(),
        allowance,
    )?;
    let mut filters = Records::new(0, resources)?;
    for spec in specs {
        let span = spec.range.map_or(range.clone(), |r| {
            range.start + r.start..range.start + r.end
        });
        filters.push_growing(crate::FilterSpec::range(spec.kind, span))?;
    }
    Ok(filters)
}

/// Compresses a wave of blocks in parallel, then appends the results to their
/// members in job order so output does not depend on scheduling.
#[allow(clippy::too_many_arguments)]
fn compress_wave<B: Budget + Send + Sync>(
    jobs: Records<BlockJob<B>>,
    seeding: Vec<TreeRuns<B>>,
    plan: &CompressPlan,
    _required: u64,
    streams: &mut [MemberStream<B>],
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
    consume: &mut ConsumePacked<'_>,
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
        return append_packed_runs(packed_runs, plan, streams, advance, error_context, consume);
    }
    let jobs = prepare_block_jobs::<B, B>(jobs, resources)?;
    let output = Records::new(jobs.len(), resources)?;
    let slots = Records::collect(jobs.into_iter().map(|job| Ok((Some(job), None))), resources)?;
    let packed_runs = complete_jobs_dispatched(
        slots,
        output,
        resources,
        advance,
        |_, job, progress| {
            let allowance = job.0.data.allowance();
            if job.0.shared.is_some() {
                return encode_shared_block_job(job, plan, progress, &allowance);
            }
            encode_block_job(job, plan, progress, &allowance)
        },
        |slots, run| code_seeded_wave(slots, &seeding, plan.encode_options, run),
    )?;
    append_packed_runs(packed_runs, plan, streams, advance, error_context, consume)
}

type WaveSlot<B> = JobSlot<PreparedBlockJob<B, B>, PackedBlocks<B>>;

/// A wave job's index and slot.
type WaveJob<'s, B> = (usize, &'s mut WaveSlot<B>);

/// What one of a wave's threads takes on in [`code_seeded_wave`].
enum WaveUnit<'s, B: Budget> {
    /// A job that needs no tree seeded for it.
    Job(WaveJob<'s, B>),
    /// A run seeded alone, under a cap on how many threads it splits between,
    /// and then coded.
    Alone {
        window: &'s [u8],
        run: std::ops::Range<usize>,
        job: WaveJob<'s, B>,
        cap: Option<usize>,
    },
    /// Chains of runs seeded from shared trees.
    Chains(Vec<WaveChain<'s, B>>),
}

/// A chain of runs seeded from a shared tree: their window, the runs, and
/// their jobs.
type WaveChain<'s, B> = (&'s [u8], &'s [std::ops::Range<usize>], Vec<WaveJob<'s, B>>);

/// Runs a wave's jobs through `run`, each as soon as it can: one with no tree
/// to seed at once, and one whose run `seeding` seeds alone as soon as its
/// tree is in, on the thread that seeded it. Each tree is the one its job
/// would have seeded, so when a job starts changes nothing it codes.
///
/// A job starts only where it will run to the end without another job's tree
/// waiting on it. A thread waiting in a seeding's fan-out can take any job a
/// thread has left to be picked up, and holds that seeding until the job is
/// done; so the jobs of a seed tree's chains start once all those chains are
/// seeded. Those chains go one after another, since each holds a seed tree
/// while it seeds, which the wave is charged for once. Groups with none split
/// the threads between them while they seed.
fn code_seeded_wave<B: Budget + Send + Sync>(
    slots: &mut [WaveSlot<B>],
    seeding: &[TreeRuns<B>],
    options: EncodeOptions,
    run: &RunSlot<'_, PreparedBlockJob<B, B>, PackedBlocks<B>>,
) where
    B::Charge: Send,
{
    let mut slots: Vec<Option<&mut WaveSlot<B>>> = slots.iter_mut().map(Some).collect();
    let mut take = |index: usize| (index, slots[index].take().expect("a job is seeded once"));
    let lone = seeding.iter().filter(|runs| !runs.shares_a_tree()).count();
    let lone_cap = (crate::parallel::threads() / lone.max(1)).max(1);
    let mut chains = Vec::new();
    let mut units = Vec::new();
    for runs in seeding {
        let cap = (!runs.shares_a_tree()).then_some(lone_cap);
        for chain in &runs.chains {
            if chain.len() > 1 {
                chains.push((
                    &runs.window[..],
                    &runs.runs[chain.clone()],
                    chain.clone().map(|tree| take(runs.trees[tree])).collect(),
                ));
            } else {
                units.push(WaveUnit::Alone {
                    window: &runs.window[..],
                    run: runs.runs[chain.start].clone(),
                    job: take(runs.trees[chain.start]),
                    cap,
                });
            }
        }
    }
    let allowance = seeding.first().map(|runs| runs.window.allowance());
    if !chains.is_empty() {
        units.insert(0, WaveUnit::Chains(chains));
    }
    units.extend(
        slots
            .into_iter()
            .enumerate()
            .filter_map(|(index, slot)| Some(WaveUnit::Job((index, slot?)))),
    );
    // Hands a job its tree, or the error seeding it, and says whether it is
    // still to run.
    let seeded = |(index, slot): &mut WaveJob<'_, B>, tree: crate::codec::Result<_>| match tree {
        Ok(tree) => {
            let (job, _, _) = slot.0.as_mut().expect("a seeded job has not run");
            job.shared.as_mut().expect("a seeded run is shared").finder =
                Some(RunFinder::Tree(tree));
            true
        }
        Err(error) => {
            run(*index, slot, Some(Error::from(error)));
            false
        }
    };
    crate::parallel::for_each_mut(&mut units, |_, unit| match unit {
        WaveUnit::Job((index, slot)) => run(*index, slot, None),
        WaveUnit::Alone {
            window,
            run: range,
            job,
            cap,
        } => {
            let allowance = allowance.as_ref().expect("a seeded wave has a window");
            let tree = {
                let _cap = crate::parallel::ThreadCap::set(*cap);
                seed_run_tree(window, range.clone(), options, allowance)
            };
            if seeded(job, tree) {
                run(job.0, job.1, None);
            }
        }
        WaveUnit::Chains(chains) => {
            let allowance = allowance.as_ref().expect("a seeded wave has a window");
            let mut ready = Vec::new();
            for (window, runs, jobs) in chains.iter_mut() {
                match seed_chain(window, runs, options, allowance) {
                    Ok(trees) => {
                        for (job, tree) in jobs.iter_mut().zip(trees) {
                            if seeded(job, Ok(tree)) {
                                ready.push(job);
                            }
                        }
                    }
                    Err(error) => {
                        for job in jobs.iter_mut() {
                            seeded(job, Err(error.clone()));
                        }
                    }
                }
            }
            crate::parallel::for_each_mut(&mut ready, |_, (index, slot)| {
                run(*index, slot, None);
            });
        }
    });
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
    if !job.filters.is_empty() && job.seams.is_empty() && !job.tree {
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
    let mut job = job;
    let empty = Buffer::new(&job.data.allowance());
    let data = std::mem::replace(&mut job.data, empty);
    // The encoder parses history and run as one window. Grow the history into
    // it and let the run go, rather than have the encoder copy both into a
    // third buffer for the whole encode.
    let start = job.history.len();
    let mut window = if start == 0 {
        data
    } else {
        let empty = Buffer::new(&data.allowance());
        let mut window = std::mem::replace(&mut job.history, empty);
        window
            .extend_from_slice(&data)
            .map_err(Into::<crate::codec::Error>::into)?;
        drop(data);
        window
    };
    // A job of several runs with filters among them is coded as each run would
    // be on its own, filtered runs as one stream cut where their records fit.
    let filtered = if job.filters.is_empty() {
        None
    } else {
        Some(job.filter_in_place(&mut window[start..], allowance)?)
    };
    let (cuts, records) = match &filtered {
        Some((cuts, records)) => (&cuts[..], Some(&records[..])),
        None => (&boundaries[..], records.as_deref()),
    };
    let packed = if job.tree {
        let tree = seed_run_tree(&window, start..window.len(), plan.encode_options, allowance)?;
        streaming_blocks_with_tree(
            &window,
            start,
            tree,
            cuts,
            records,
            plan.algorithm_version,
            plan.encode_options,
            Some(&mut block_done),
            allowance,
        )?
    } else {
        streaming_blocks_in_window(
            &window,
            start,
            cuts,
            records,
            plan.algorithm_version,
            plan.encode_options,
            Some(&mut block_done),
            allowance,
        )?
    };
    drop(window);
    if filtered.is_some() {
        let (member, _, last) = *job.blocks.last().expect("a job holds a block");
        let mut run = Buffer::new(allowance);
        for block in packed {
            run.extend_from_slice(&block)
                .map_err(Into::<crate::codec::Error>::into)?;
        }
        output.push((member, run, last))?;
        return Ok(output);
    }
    for ((member, _, last), packed) in job.blocks.into_iter().zip(packed) {
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
        tree,
        ..
    } = job;
    let SharedRun {
        window,
        start,
        end,
        finder,
        filtered,
    } = shared.expect("dispatched as a shared run");
    let finder = match finder {
        None if tree => Some(RunFinder::Tree(seed_run_tree(
            &window,
            start..end,
            plan.encode_options,
            allowance,
        )?)),
        finder => finder,
    };
    let mut block_done = |bytes: usize| progress.advance(bytes as u64);
    let (cuts, records) = match &filtered {
        Some((cuts, records)) => (&cuts[..], Some(&records[..])),
        None => (&boundaries[..], solid_records.as_deref()),
    };
    let packed = match finder {
        Some(RunFinder::Packed(finder)) => streaming_blocks_with_finder(
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
        Some(RunFinder::Tree(tree)) => streaming_blocks_with_tree(
            &window[..end],
            start,
            tree,
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
    consume: &mut ConsumePacked<'_>,
) -> Result<()> {
    // A solid wave can cover thousands of tiny members. Keep only the spool
    // currently being appended open, rather than one descriptor per member.
    let mut previous: Option<usize> = None;
    for (member, packed, last) in packed_runs.into_iter().flatten() {
        if previous != Some(member) {
            if let Some(previous) = previous {
                if let Some(spool) = streams[previous].packed.as_mut() {
                    spool.park();
                }
            }
            previous = Some(member);
        }
        let stream = &mut streams[member];
        stream.packed_len += packed.len() as u64;
        if stream.straight {
            consume(stream.member, Packing::Packed(&packed))?;
        } else {
            stream
                .packed()
                .write_all(&packed)
                .map_err(|error| error_context(stream.member, error.into()))?;
        }
        if last {
            // A completed block run always came from `has_more`, so an empty
            // member cannot reach this branch.
            if !should_store_compressed_payload(
                stream.input_size,
                stream.packed_len,
                plan.solid,
                &plan.filter_policy,
            ) {
                stream.source.release();
            }
            stream.done = true;
            advance.finished(stream.member, stream.input_size);
        }
    }
    // Both wave builders dispatch only non-empty jobs, and every job emits
    // one packed block for each recorded boundary.
    let previous = previous.expect("compression wave contains a packed block");
    if let Some(spool) = streams[previous].packed.as_mut() {
        spool.park();
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
fn compress_members_hashing_stored_later(
    sources: &[EntrySource],
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &dyn CompressionProgress,
    error_context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<CompressedMember>> {
    let mut members = Records::new(sources.len(), resources)?;
    compress_members_in_order(
        sources,
        plan,
        resources,
        advance,
        error_context,
        true,
        &|_, _| false,
        &mut |_, handed| match handed {
            Handed::Member(member) => members.push(member),
            _ => unreachable!("no member goes out straight"),
        },
    )?;
    Ok(members)
}

#[cfg(test)]
mod tests {
    fn packed_by(
        integrity: &mut [Integrity],
        run: impl FnOnce(&[Integrity], &mut ConsumePacked<'_>) -> Result<()>,
    ) -> Result<Vec<Spool>> {
        let sizes = integrity.to_vec();
        let mut spools = Vec::new();
        run(&sizes, &mut |member, packing| {
            let Packing::Done(packed, crc, hash) = packing else {
                unreachable!("no member goes out straight");
            };
            (integrity[member].1, integrity[member].2) = (crc, hash);
            spools.push(packed);
            Ok(())
        })?;
        Ok(spools)
    }

    #[allow(clippy::too_many_arguments)]
    fn independent<B: Budget + Send + Sync>(
        sources: &[EntrySource],
        integrity: &[Integrity],
        plan: &CompressPlan,
        filter_runs: bool,
        batch_capacity: usize,
        required: u64,
        resources: &WriterResources,
        advance: &dyn CompressionProgress,
        error_context: &(dyn Fn(usize, Error) -> Error + Sync),
        allowance: &B,
        consume: &mut ConsumePacked<'_>,
    ) -> Result<()>
    where
        B::Charge: Send,
    {
        compress_independent_members(
            sources,
            integrity,
            plan,
            filter_runs,
            1,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
            allowance,
            &|_, _| false,
            consume,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn solid_chain<B: Budget + Send + Sync>(
        sources: &[EntrySource],
        integrity: &[Integrity],
        plan: &CompressPlan,
        filter_runs: bool,
        batch_capacity: usize,
        required: u64,
        resources: &WriterResources,
        advance: &dyn CompressionProgress,
        error_context: &(dyn Fn(usize, Error) -> Error + Sync),
        allowance: &B,
        consume: &mut ConsumePacked<'_>,
    ) -> Result<()>
    where
        B::Charge: Send,
    {
        compress_solid_chain(
            sources,
            integrity,
            plan,
            filter_runs,
            batch_capacity,
            required,
            resources,
            advance,
            error_context,
            allowance,
            &|_, _| false,
            consume,
        )
    }

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
                blake2sp: true,
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
            blake2sp: true,
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
            &[(32, 0, None)],
            &plan,
            &members,
            &resources,
            &progress,
            &|index, error| {
                assert_eq!(index, 0);
                error.at_entry(b"waiting.bin".to_vec(), "compressing")
            },
            &|_, _| false,
            &mut |_, _| Ok(()),
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
                blake2sp: true,
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
            blake2sp: true,
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
            blake2sp: true,
        };
        let source = EntrySource::from_bytes(b"payload".to_vec());
        let limit = std::mem::size_of::<Integrity>() as u64;
        let resources = WriterResources::default().with_max_preparation_bytes(limit);
        let error = compress_members_reporting(&[source], plan, &resources, &|_| true)
            .err()
            .expect("the stored spool descriptors must exceed the integrity record");
        assert!(matches!(
            error,
            Error::WriterPreparationLimitExceeded {
                limit: actual_limit,
                ..
            } if actual_limit == limit
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
            blake2sp: true,
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
                    (size, 0, None),
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
            blake2sp: true,
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
                true,
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
            blake2sp: true,
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
                    &[(7, 0, None)],
                    &plan,
                    false,
                    0,
                    0,
                    &resources,
                    progress,
                    &|_, error| error,
                    &|_, _| false,
                    &mut |_, _| Ok(()),
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
            admission: workspace,
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
            admission: 10,
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
            MemberStream::new(0, &source, 8, true, &resources, &|_| true, &allowance).unwrap();
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
            MemberStream::new(0, &source, 8, true, &resources, &|_| true, &allowance).unwrap();
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
                blake2sp: true,
            };
            let sources = [
                EntrySource::from_bytes(data.clone()),
                EntrySource::from_bytes(data[..2048].to_vec()),
                EntrySource::from_bytes(Vec::new()),
            ];
            let initial = [(8192, 0, None), (2048, 0, None), (0, 0, None)];
            let mut expected_integrity = initial;
            let encode = if solid {
                solid_chain::<Allowance>
            } else {
                independent::<Allowance>
            };
            let expected = packed_by(&mut expected_integrity, |integrity, consume| {
                encode(
                    &sources,
                    integrity,
                    &plan,
                    false,
                    2,
                    1,
                    &resources,
                    &|_| true,
                    &|_, error| error,
                    &Allowance::default(),
                    consume,
                )
            })
            .unwrap();
            let payloads = |spools: Vec<Spool>| -> Vec<Vec<u8>> {
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
                    solid_chain::<crate::codec::workspace::Limited>
                } else {
                    independent::<crate::codec::workspace::Limited>
                };
                let result = packed_by(&mut integrity, |integrity, consume| {
                    encode(
                        &sources,
                        integrity,
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
                        consume,
                    )
                });
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
                solid_chain::<crate::codec::workspace::Limited>
            } else {
                independent::<crate::codec::workspace::Limited>
            };
            let mut integrity = initial;
            let result = packed_by(&mut integrity, |integrity, consume| {
                encode(
                    &sources,
                    integrity,
                    &plan,
                    false,
                    2,
                    1,
                    &resources,
                    &|_| false,
                    &|_, error| error,
                    &allowance,
                    consume,
                )
            });
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
                blake2sp: true,
            };
            let mut expected_integrity = [(size as u64, 0, None); 2];
            let mut actual_integrity = expected_integrity;
            let encode = if solid {
                solid_chain::<Allowance>
            } else {
                independent::<Allowance>
            };
            let expected = packed_by(&mut expected_integrity, |integrity, consume| {
                encode(
                    &sources,
                    integrity,
                    &plan,
                    false,
                    1,
                    1,
                    &resources,
                    &|_| true,
                    &|_, error| error,
                    &Allowance::default(),
                    consume,
                )
            })
            .unwrap();
            let allowance = Allowance::limited(64 * 1024 * 1024);
            let encode = if solid {
                solid_chain::<crate::codec::workspace::Limited>
            } else {
                independent::<crate::codec::workspace::Limited>
            };
            let actual = packed_by(&mut actual_integrity, |integrity, consume| {
                encode(
                    &sources,
                    integrity,
                    &plan,
                    false,
                    2,
                    1,
                    &resources,
                    &|_| true,
                    &|_, error| error,
                    &allowance,
                    consume,
                )
            })
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
                blake2sp: true,
            };
            let required = super::super::plan::lazy_streaming_workspace(options, size as u64);
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
                blake2sp: true,
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
            // Even a short run needs the finder's hash heads.
            let too_small = Allowance::limited(64 * 1024);
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
            blake2sp: true,
        };
        let opens = Arc::new(AtomicUsize::new(0));
        for limit in [32768, 131072] {
            let ledger = Allowance::limited(limit);
            let resources = WriterResources::default()
                .with_temp_dir(&*scratch)
                .with_execution_allowance(ledger.clone());
            // The read buffer fits the member, up to a block.
            let source = EntrySource::from_opener(65536, {
                let opens = opens.clone();
                let ledger = ledger.clone();
                move || {
                    assert!(ledger.used() >= 65536);
                    opens.fetch_add(1, Ordering::Relaxed);
                    Ok(Box::new(std::io::Cursor::new(vec![7u8; 65536])))
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
                assert_eq!(result[0].crc32, crate::crc32::crc32(&[7u8; 65536]));
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
                MemberStream::new(0, &source, 8, true, &resources, &|_| true, &allowance).unwrap();
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
        let options = EncodeOptions::new(8)
            .with_max_match_distance(65536)
            .with_optimal_parse(true);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: 1024,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options].into(),
            blake2sp: true,
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
            blake2sp: true,
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
        let integrity = (data.len() as u64, 0, None);
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
        assert_eq!(packed.hash, Some(blake2sp::hash(&data)));
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
                (8, 0, None),
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
        let encode_options = EncodeOptions::new(8)
            .with_max_match_distance(65536)
            .with_optimal_parse(true);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options,
            dictionary_size: 65536,
            block_size: 65536,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![encode_options].into(),
            blake2sp: true,
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
            blake2sp: true,
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
            blake2sp: true,
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
                assert_eq!(members[1].hash, Some(blake2sp::hash(&data)));
                let mut fallback_bytes = Vec::new();
                members[1].packed.copy_to(&mut fallback_bytes).unwrap();
                let mut plain = compress_members_reporting(
                    &sources[1..2],
                    CompressPlan {
                        filter_policy: FilterPolicy::None,
                        blake2sp: true,
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
            blake2sp: true,
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
        assert_eq!(together[0].hash, Some(blake2sp::hash(&first)));
        assert_eq!(together[1].hash, Some(blake2sp::hash(&second)));
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
    fn members_coded_in_runs_share_waves_across_the_whole_members_between_them() {
        use std::sync::Mutex;
        struct Starts(Mutex<Vec<usize>>);
        impl CompressionProgress for Starts {
            fn advance(&self, _: u64) -> bool {
                true
            }
            fn started(&self, index: usize, _: u64) {
                self.0.lock().unwrap().push(index);
            }
        }
        let scratch = crate::scratch::case("medium-lookahead");
        let first = b"runs either side of a whole member\n".repeat(65536);
        let second: Vec<u8> = (0..600_000u32)
            .flat_map(|n| (n.wrapping_mul(2_654_435_761) >> 7).to_le_bytes())
            .collect();
        let sources = [
            EntrySource::from_bytes(first.clone()),
            EntrySource::from_bytes(b"small enough to code whole".to_vec()),
            EntrySource::from_bytes(second.clone()),
            EntrySource::from_bytes(b"and another".to_vec()),
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
            blake2sp: true,
        };
        let resources = WriterResources::new(70 * 1024 * 1024).with_temp_dir(&*scratch);

        let starts = Starts(Mutex::new(Vec::new()));
        let mut handed = Vec::new();
        compress_members_in_order(
            &sources,
            &plan,
            &resources,
            &starts,
            &|_, error| error,
            false,
            &|_, _| false,
            &mut |index, member| match member {
                Handed::Member(member) => {
                    handed.push((index, member));
                    Ok(())
                }
                _ => unreachable!("no member goes out straight"),
            },
        )
        .unwrap();
        assert_eq!(
            handed.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        let starts = starts.0.into_inner().unwrap();
        let at = |member| starts.iter().position(|&index| index == member).unwrap();
        assert!(at(2) < at(1), "{starts:?}");

        // Captured from the writer before members in runs looked ahead.
        let fingerprints = [
            (156, 0x4d9e_9ba6, false),
            (0, 0, true),
            (2_126_960, 0x8f44_4877, false),
            (0, 0, true),
        ];
        for ((_, member), expected) in handed.iter_mut().zip(fingerprints) {
            let mut bytes = Vec::new();
            member.packed.copy_to(&mut bytes).unwrap();
            assert_eq!(
                (bytes.len(), crate::crc32::crc32(&bytes), member.store),
                expected
            );
        }
        drop(handed);
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
                blake2sp: true,
            };
            let mut members =
                compress_members_reporting(&sources, plan, &resources, &|_| true).unwrap();
            assert_eq!(members.len(), sources.len());
            for member in &mut members {
                assert_eq!(member.input_size, data.len() as u64);
                assert_eq!(member.hash, Some(blake2sp::hash(&data)));
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
            blake2sp: true,
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
            blake2sp: true,
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
            blake2sp: true,
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
                    blake2sp: true,
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
                    assert_eq!(member.hash, Some(blake2sp::hash(input)));
                }
            }
        }
    }

    /// A filtered run's filter search was charged as if it coded a member
    /// whole, which took a wave of them below the jobs the budget had room
    /// for (#315). Here a run is 1 MiB and its search 168 MiB as planned,
    /// while a job is admitted for 119 MiB: a 360 MiB budget runs three at
    /// once rather than two. The first wave has read its jobs' runs before
    /// any of them reports coding progress, so its size shows in the reads.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn filtered_runs_are_admitted_for_what_they_hold_not_their_planning_charge() {
        use std::sync::{atomic::AtomicUsize, Arc};
        struct Counted(std::io::Cursor<Arc<[u8]>>, Arc<AtomicUsize>);
        impl Read for Counted {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let read = self.0.read(buf)?;
                self.1.fetch_add(read, Ordering::SeqCst);
                Ok(read)
            }
        }
        impl std::io::Seek for Counted {
            fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0.seek(to)
            }
        }
        const MIB: u64 = 1024 * 1024;
        let scratch = crate::scratch::case("filtered-run-admission");
        let options = EncodeOptions::new(8)
            .with_max_match_distance(65536)
            .with_optimal_parse(true);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options].into(),
            blake2sp: true,
        };
        let run = run_size(&plan);
        assert_eq!(run as u64, MIB);
        // Not text, so every run is searched.
        let data: Arc<[u8]> = (0..3 * run).map(|i| (i * 71 % 251) as u8).collect();
        let read = Arc::new(AtomicUsize::new(0));
        let sources: Vec<_> = (0..2)
            .map(|_| {
                let (data, read) = (data.clone(), read.clone());
                EntrySource::from_opener(data.len() as u64, move || {
                    Ok(Box::new(Counted(
                        std::io::Cursor::new(data.clone()),
                        read.clone(),
                    )))
                })
            })
            .collect();
        // Too large to code whole, small enough to search each run.
        let resources = WriterResources::new(170 * MIB)
            .with_memory_limit(360 * MIB)
            .with_temp_dir(&*scratch);
        let ExecutionPlan::IndependentMembers(members) =
            ExecutionPlan::with_resources(&plan, [data.len() as u64].into_iter(), &resources)
                .unwrap()
        else {
            panic!("independent members are planned one by one");
        };
        assert!(matches!(
            members[0].execution,
            Execution::Blocks {
                run_filters: true,
                ..
            }
        ));
        assert_eq!(360 * MIB / members[0].workspace, 2);
        let first_wave = AtomicUsize::new(0);
        let progress = |bytes: u64| {
            if bytes > 0 && first_wave.load(Ordering::SeqCst) == 0 {
                first_wave.store(read.load(Ordering::SeqCst), Ordering::SeqCst);
            }
            true
        };
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        pool.install(|| {
            compress_members_with_context(&sources, &plan, &resources, &progress, &|_, e| e)
        })
        .unwrap();
        assert_eq!(first_wave.load(Ordering::SeqCst) / run, 3);
        assert_eq!(resources.workspace_in_use(), 0);
    }

    fn joined_runs_plan(filter_policy: FilterPolicy) -> CompressPlan {
        let options = EncodeOptions::new(8)
            .with_max_match_distance(65536)
            .with_optimal_parse(true);
        CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 65536,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 1,
            filter_policy,
            candidates: vec![options].into(),
            blake2sp: true,
        }
    }

    /// Five runs that alternate between x86-like calls, which the search
    /// filters, and numbered lines, which it leaves alone, with a stretch of zeros
    /// that grows a block past a run's end, then `tail` bytes of lines, short
    /// enough to walk chains.
    fn joined_runs_input(run: usize, tail: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(5 * run + tail);
        // Numbered lines: long matches, which an unoptimised build parses
        // quickly, and every one of them distinct.
        let mut line = 0u32;
        let mut word = |data: &mut Vec<u8>| {
            line += 1;
            let text = format!(
                "{line:07} a tree that parsed up to a run holds what one seeded there would\n"
            );
            data.extend_from_slice(text.as_bytes());
        };
        for index in 0..5 {
            let end = (index + 1) * run - if index == 2 { 20_000 } else { 0 };
            while data.len() < end {
                if index % 2 == 0 {
                    data.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0xe8]);
                    let target = 0x1000 + (data.len() as u32 / 5 % 13) * 0x40;
                    let relative = target.wrapping_sub(data.len() as u32 + 4);
                    data.extend_from_slice(&relative.to_le_bytes());
                    data.extend_from_slice(&[0x5d, 0xc3]);
                } else {
                    word(&mut data);
                }
            }
            data.truncate(end);
            if index == 2 {
                data.resize(data.len() + 40_000, 0);
            }
        }
        while data.len() < 5 * run + tail {
            word(&mut data);
        }
        data.truncate(5 * run + tail);
        data
    }

    /// Runs shorter than the dictionary, as level 5's are, are joined a
    /// dictionary at a time when one thread or the budget allows one job,
    /// and coded each on its own when there are threads for all of them.
    #[test]
    fn short_runs_are_joined_a_dictionary_at_a_time() {
        const MIB: u64 = 1024 * 1024;
        let options = EncodeOptions::new(512)
            .with_max_match_distance(16 * MIB as usize)
            .with_optimal_parse(true);
        let plan = CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 16 * MIB,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 1,
            filter_policy: FilterPolicy::Auto,
            candidates: vec![options].into(),
            blake2sp: true,
        };
        assert_eq!(member_run_size(&plan), 4 * MIB as usize);
        let budget = |threads: u64| 256 * MIB + 160 * MIB * (threads - 1);
        let joined = |threads: usize| {
            runs_per_job(&plan, 33 * MIB, 283 * MIB, budget(threads as u64), threads)
        };
        // One job of a dictionary fits one thread's budget as one run of it
        // did. Two threads' budget holds no second job, but holds one job of
        // the whole member, which seeds nothing.
        assert_eq!(joined(1), 4);
        assert_eq!(joined(2), 8);
        assert_eq!(joined(4), 4);
        assert_eq!(joined(8), 2);
        assert_eq!(joined(22), 1);
        assert_eq!(
            joined_admission(&plan, 283 * MIB, 4, budget(1)),
            256 * MIB,
            "a dictionary a job takes the whole budget"
        );
        // The lazy parse keeps a dictionary a run.
        let lazy = plan.encode_options.with_optimal_parse(false);
        let lazy = CompressPlan {
            encode_options: lazy,
            candidates: vec![lazy].into(),
            ..plan
        };
        assert_eq!(member_run_size(&lazy), 16 * MIB as usize);
    }

    /// Runs shorter than the dictionary code the same member at 1, 2, 4 and 8
    /// threads, which join them four, two and one to a job, and the short
    /// tail joins the run before it (#546). With their filters searched, the
    /// pieces are searched side by side, and a run whose job follows an
    /// unshared one has its tree seeded before the jobs start.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn runs_shorter_than_the_dictionary_code_alike_on_any_thread_count() {
        const MIB: usize = 1024 * 1024;
        let options = EncodeOptions::new(8)
            .with_max_match_distance(2 * MIB)
            .with_optimal_parse(true);
        let data = joined_runs_input(MIB, 10_000);
        let sources = [EntrySource::from_bytes(data.clone())];
        let scratch = crate::scratch::case("short-runs-threads");
        for filter_policy in [FilterPolicy::None, FilterPolicy::Auto] {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 2 * MIB as u64,
                block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
                solid: false,
                method: 1,
                filter_policy: filter_policy.clone(),
                candidates: vec![options].into(),
                blake2sp: true,
            };
            let code = |threads: usize| -> Vec<u8> {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap()
                    .install(|| {
                        super::super::plan::with_filter_search_bytes(MIB, || {
                            assert_eq!(member_run_size(&plan), MIB);
                            let resources = WriterResources::default().with_temp_dir(&*scratch);
                            let mut members = compress_members_reporting(
                                &sources,
                                plan.clone(),
                                &resources,
                                &|_| true,
                            )
                            .unwrap();
                            let mut packed = Vec::new();
                            members[0].packed.copy_to(&mut packed).unwrap();
                            drop(members);
                            assert_eq!(resources.workspace_in_use(), 0);
                            packed
                        })
                    })
            };
            let one = code(1);
            for threads in [2, 4, 8] {
                assert!(
                    code(threads) == one,
                    "{threads} threads changed the member, {filter_policy:?}"
                );
            }
            if filter_policy == FilterPolicy::None {
                let decoded = crate::codec::rar50::decode_lz(&one, 0, data.len()).unwrap();
                assert!(decoded == data, "the member does not round-trip");
            }
        }
    }

    /// A tail long enough for a thread of its own is cut off the run it joined
    /// and coded as a job of its own, on a tree seeded from its history, at 2
    /// and 8 threads, and codes what it codes joined to the run at 1 (#546):
    /// after a filtered run, with the runs' filters searched or not.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn a_tail_cut_from_its_run_codes_what_the_run_coded_it_as() {
        const MIB: usize = 1024 * 1024;
        let options = EncodeOptions::new(8)
            .with_max_match_distance(2 * MIB)
            .with_optimal_parse(true);
        // Short enough to join the run before it, long enough to be cut off.
        let tail = 300 * 1024;
        let data = joined_runs_input(MIB, tail);
        let sources = [EntrySource::from_bytes(data.clone())];
        let scratch = crate::scratch::case("tail-cut-threads");
        for (filter_policy, filter_runs) in
            [(FilterPolicy::None, false), (FilterPolicy::Auto, true)]
        {
            let plan = CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 2 * MIB as u64,
                block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
                solid: false,
                method: 1,
                filter_policy: filter_policy.clone(),
                candidates: vec![options].into(),
                blake2sp: true,
            };
            let code = |threads: usize| -> (Vec<u8>, usize) {
                crate::parallel::private_pool(threads).install(|| {
                    super::super::plan::with_filter_search_bytes(MIB, || {
                        assert_eq!(member_run_size(&plan), MIB);
                        assert!(absorbs_tail(&plan, tail as u64));
                        let resources = WriterResources::default().with_temp_dir(&*scratch);
                        let mut integrity = [(data.len() as u64, 0, None)];
                        let cut = TAILS_CUT.load(Ordering::Relaxed);
                        let mut spools = packed_by(&mut integrity, |integrity, consume| {
                            compress_independent_members::<Allowance>(
                                &sources,
                                integrity,
                                &plan,
                                filter_runs,
                                1,
                                threads,
                                1,
                                &resources,
                                &|_| true,
                                &|_, error| error,
                                &Allowance::default(),
                                &|_, _| false,
                                consume,
                            )
                        })
                        .unwrap();
                        let cut = TAILS_CUT.load(Ordering::Relaxed) - cut;
                        let mut packed = Vec::new();
                        spools[0].copy_to(&mut packed).unwrap();
                        drop(spools);
                        assert_eq!(resources.workspace_in_use(), 0);
                        (packed, cut)
                    })
                })
            };
            let (one, _) = code(1);
            for threads in [2, 8] {
                let (packed, cut) = code(threads);
                // Tests running beside this one may cut tails too, but none
                // take one away.
                assert!(cut > 0, "{threads} threads coded the tail with its run");
                assert!(
                    packed == one,
                    "{threads} threads changed the member, {filter_policy:?}"
                );
            }
            let decoded = crate::codec::rar50::decode_lz(&one, 0, data.len()).unwrap();
            assert!(decoded == data, "{filter_policy:?} does not round-trip");
        }
    }

    /// A job of several runs parses straight through where each run of its
    /// own seeds a tree from the history before it. The bytes are the same
    /// either way, with the runs' filters searched, given, or not looked
    /// for, and with jobs coded on their own or sharing a wave's window.
    #[test]
    fn joined_runs_code_the_bytes_their_runs_code_alone() {
        let scratch = crate::scratch::case("joined-runs");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let run = run_size(&joined_runs_plan(FilterPolicy::None));
        let data = joined_runs_input(run, 10_000);
        let sources = [EntrySource::from_bytes(data.clone())];
        let e8 = crate::FilterSpec::range(crate::FilterKind::E8, run / 2..3 * run + 7);
        let mut sizes = Vec::new();
        // Each coding takes seconds in an unoptimised build, so each policy
        // is checked where it matters: a job of every run, jobs sharing a
        // wave's window, and an explicit filter that spans joined runs.
        for (policy, filter_runs, joined) in [
            (FilterPolicy::None, false, &[(6, 1), (2, 2)][..]),
            (FilterPolicy::Auto, true, &[(2, 3)][..]),
            (FilterPolicy::Explicit(e8), true, &[(2, 1)][..]),
        ] {
            let plan = joined_runs_plan(policy.clone());
            let code = |runs_per_job: usize, batch_capacity: usize| -> Vec<u8> {
                let mut integrity = [(data.len() as u64, 0, None)];
                let mut spools = super::super::plan::with_filter_search_bytes(256 * 1024, || {
                    packed_by(&mut integrity, |integrity, consume| {
                        compress_independent_members::<Allowance>(
                            &sources,
                            integrity,
                            &plan,
                            filter_runs,
                            runs_per_job,
                            batch_capacity,
                            1,
                            &resources,
                            &|_| true,
                            &|_, error| error,
                            &Allowance::default(),
                            &|_, _| false,
                            consume,
                        )
                    })
                })
                .unwrap();
                let mut packed = Vec::new();
                spools[0].copy_to(&mut packed).unwrap();
                packed
            };
            let alone = code(1, 1);
            for &(runs_per_job, batch_capacity) in joined {
                assert!(
                    code(runs_per_job, batch_capacity) == alone,
                    "{policy:?}, {runs_per_job} runs a job, {batch_capacity} jobs a wave"
                );
            }
            let decoded = crate::codec::rar50::decode_lz(&alone, 0, data.len()).unwrap();
            assert!(decoded == data, "{policy:?} does not round-trip");
            sizes.push(alone.len());
        }
        // Both filtered codings filtered something.
        assert!(sizes[1] < sizes[0] && sizes[2] < sizes[0], "{sizes:?}");
        assert_eq!(resources.workspace_in_use(), 0);
    }

    #[test]
    fn runs_are_joined_only_while_every_thread_keeps_a_job() {
        const MIB: u64 = 1024 * 1024;
        let level3 = |optimal_parse: bool| {
            let options = EncodeOptions::new(128)
                .with_max_match_distance(4 * MIB as usize)
                .with_optimal_parse(optimal_parse);
            CompressPlan {
                algorithm_version: 0,
                encode_options: options,
                dictionary_size: 4 * MIB,
                block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
                solid: false,
                method: 1,
                filter_policy: FilterPolicy::Auto,
                candidates: vec![options].into(),
                blake2sp: true,
            }
        };
        let plan = level3(true);
        let budget = |threads: u64| 256 * MIB + 160 * MIB * (threads - 1);
        let joined = |size: u64, threads: usize| {
            runs_per_job(&plan, size, 159 * MIB, budget(threads as u64), threads)
        };
        // Sixteen runs: one job a thread, or two a thread where a job of
        // eight would not fit the budget twice over.
        assert_eq!(joined(64 * MIB, 1), 8);
        assert_eq!(joined(64 * MIB, 2), 4);
        assert_eq!(joined(64 * MIB, 4), 4);
        assert_eq!(joined(64 * MIB, 8), 2);
        assert_eq!(joined(64 * MIB, 16), 1);
        assert_eq!(joined(64 * MIB, 32), 1);
        assert_eq!(joined(12 * MIB, 1), 3);
        assert_eq!(joined(12 * MIB, 2), 2);
        assert_eq!(joined(12 * MIB, 3), 1);
        assert_eq!(joined(4 * MIB, 1), 1);
        // Chains are seeded with one store a byte, so a lazy parse keeps its runs.
        assert_eq!(
            runs_per_job(&level3(false), 64 * MIB, 159 * MIB, budget(1), 1),
            1
        );
        // A run that takes the whole budget is coded on its own.
        assert_eq!(runs_per_job(&plan, 64 * MIB, 256 * MIB, budget(1), 1), 1);
        // However many jobs run at once, the budget holds them all.
        for threads in 1..=32 {
            for size in [4, 8, 12, 20, 64, 1024] {
                let runs = joined(size * MIB, threads);
                let jobs = (size / 4).div_ceil(runs as u64).min(threads as u64);
                let budget = budget(threads as u64);
                let admitted = budget / joined_admission(&plan, 159 * MIB, runs, budget);
                assert!(admitted >= jobs, "{size} MiB at {threads} threads");
            }
        }
    }
}

#[cfg(test)]
mod stored_hashing_tests {
    use super::*;
    use crate::rar50::FilterPolicy;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    fn stored_plan() -> CompressPlan {
        let options = EncodeOptions::new(8);
        CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size: 128 * 1024,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid: false,
            method: 0,
            filter_policy: FilterPolicy::None,
            candidates: vec![options].into(),
            blake2sp: true,
        }
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn stored_members_are_hashed_side_by_side() {
        use std::time::{Duration, Instant};
        let opened = Arc::new(AtomicUsize::new(0));
        let met = Arc::new(AtomicUsize::new(0));
        let sources: Vec<EntrySource> = (0..2)
            .map(|_| {
                let (opened, met) = (opened.clone(), met.clone());
                EntrySource::from_opener(4, move || {
                    opened.fetch_add(1, Ordering::SeqCst);
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while opened.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    if opened.load(Ordering::SeqCst) >= 2 {
                        met.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(Box::new(std::io::Cursor::new(b"data".to_vec())))
                })
            })
            .collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let members = pool
            .install(|| {
                compress_members_with_context(
                    &sources,
                    &stored_plan(),
                    &WriterResources::default(),
                    &|_| true,
                    &|_, error| error,
                )
            })
            .unwrap();
        assert_eq!(
            met.load(Ordering::SeqCst),
            2,
            "one member waited for the other"
        );
        let expected = crate::rar50::blake2sp::hash(b"data");
        assert!(members.iter().all(|member| member.hash == Some(expected)));
    }

    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn the_first_failing_member_is_reported_whichever_fails_first() {
        let sources: Vec<EntrySource> = [50, 0]
            .into_iter()
            .map(|delay| {
                EntrySource::from_opener(4, move || {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                    Ok(Box::new(std::io::Cursor::new(b"x".to_vec())))
                })
            })
            .collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let error = pool
            .install(|| {
                compress_members_with_context(
                    &sources,
                    &stored_plan(),
                    &WriterResources::default(),
                    &|_| true,
                    &|index, _| Error::WriterFailure(["first", "second"][index]),
                )
            })
            .err()
            .unwrap();
        assert_eq!(error, Error::WriterFailure("first"));
    }

    #[test]
    fn cancelling_stops_hashing_members_not_yet_opened() {
        struct Stop(Arc<AtomicBool>);
        impl CompressionProgress for Stop {
            fn advance(&self, _: u64) -> bool {
                !self.is_cancelled()
            }
            fn is_cancelled(&self) -> bool {
                self.0.load(Ordering::SeqCst)
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let opened = Arc::new(AtomicUsize::new(0));
        let window = crate::parallel::default_window();
        let sources: Vec<EntrySource> = (0..window * 2 + 1)
            .map(|_| {
                let (stop, opened) = (stop.clone(), opened.clone());
                EntrySource::from_opener(4, move || {
                    opened.fetch_add(1, Ordering::SeqCst);
                    stop.store(true, Ordering::SeqCst);
                    Ok(Box::new(std::io::Cursor::new(b"data".to_vec())))
                })
            })
            .collect();
        let result = compress_members_with_context(
            &sources,
            &stored_plan(),
            &WriterResources::default(),
            &Stop(stop),
            &|_, error| error,
        );
        assert_eq!(result.err().unwrap(), Error::Cancelled);
        let opened = opened.load(Ordering::SeqCst);
        assert!(
            (1..=window).contains(&opened),
            "{opened} of {} opened",
            sources.len()
        );
    }
}

#[cfg(test)]
mod incompressible_probe_tests {
    use super::*;
    use crate::rar50::FilterPolicy;

    fn noise(len: usize, mut state: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    fn text(len: usize) -> Vec<u8> {
        let mut text = Vec::with_capacity(len + 64);
        let mut line = 0u32;
        while text.len() < len {
            text.extend_from_slice(format!("line {line}: a member worth compressing\n").as_bytes());
            line = (line * 7 + 13) % 1000;
        }
        text.truncate(len);
        text
    }

    fn level_one_plan(solid: bool) -> CompressPlan {
        let dictionary_size = 128 * 1024;
        let options =
            super::super::filter_policy::encode_options_for_level(Some(1), dictionary_size)
                .unwrap();
        CompressPlan {
            algorithm_version: 0,
            encode_options: options,
            dictionary_size,
            block_size: crate::codec::rar50::LZ_BLOCK_SIZE,
            solid,
            method: 1,
            filter_policy: FilterPolicy::None,
            candidates: vec![options].into(),
            blake2sp: true,
        }
    }

    /// Too little memory to code a block, enough to sample and hash.
    fn too_small_to_code() -> WriterResources {
        WriterResources::new(8 * 1024 * 1024)
    }

    fn checksums(data: &[u8]) -> (u32, Option<[u8; 32]>) {
        let mut crc = Crc32::new();
        crc.update(data);
        let mut hash = blake2sp::Hasher::new();
        hash.update(data);
        (crc.finish(), Some(hash.finalize()))
    }

    /// An archive that keeps no BLAKE2sp hashes does not compute them, on any
    /// of the paths a member can take: stored, coded, solid, or stored from
    /// its samples.
    #[test]
    fn members_are_not_hashed_unless_the_archive_keeps_hashes() {
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(2000);
        let random = noise(2 * 1024 * 1024, 0x9e37_79b9_7f4a_7c15);
        let stored_plan = CompressPlan {
            method: 0,
            ..level_one_plan(false)
        };
        let cases = [
            (stored_plan, WriterResources::default()),
            (level_one_plan(false), WriterResources::default()),
            (level_one_plan(true), WriterResources::default()),
            (level_one_plan(false), too_small_to_code()),
        ];
        for (mut plan, resources) in cases {
            plan.blake2sp = false;
            for stored_later in [false, true] {
                let compress = if stored_later {
                    compress_members_hashing_stored_later
                } else {
                    compress_members_with_context
                };
                let members = compress(
                    &[
                        EntrySource::from_bytes(text.clone()),
                        EntrySource::from_bytes(random.clone()),
                    ],
                    &plan,
                    &resources,
                    &|_| true,
                    &|_, error| error,
                )
                .unwrap();
                for (member, data) in members.iter().zip([&text, &random]) {
                    assert_eq!(member.hash, None);
                    // A stored member hashed on its copy has no checksums yet.
                    assert_eq!(member.checksums_pending, stored_later && member.store);
                    if !member.checksums_pending {
                        assert_eq!(member.crc32, checksums(data).0);
                    }
                }
            }
        }
    }

    /// A noise member is stored from its samples, so it never needs the memory
    /// to code it, and its checksums are those of the whole member.
    #[test]
    fn noise_is_stored_without_coding_it() {
        let data = noise(2 * 1024 * 1024, 0x9e37_79b9_7f4a_7c15);
        let members = compress_members_with_context(
            &[EntrySource::from_bytes(data.clone())],
            &level_one_plan(false),
            &too_small_to_code(),
            &|_| true,
            &|_, error| error,
        )
        .unwrap();
        let member = &members[0];
        assert!(member.store);
        assert_eq!(member.input_size, data.len() as u64);
        assert_eq!((member.crc32, member.hash), checksums(&data));
    }

    /// A solid chain is never sampled: a member that does not compress alone
    /// may against the members before it, and storing it would leave a gap in
    /// the dictionary the next member is decoded against.
    #[test]
    fn a_solid_member_is_not_sampled() {
        let data = noise(2 * 1024 * 1024, 0x2545_f491_4f6c_dd1d);
        let result = compress_members_with_context(
            &[EntrySource::from_bytes(data)],
            &level_one_plan(true),
            &too_small_to_code(),
            &|_| true,
            &|_, error| error,
        );
        assert!(
            matches!(result, Err(Error::MemoryLimitExceeded { .. })),
            "{:?}",
            result.map(|members| members.len())
        );
    }

    /// Stored and coded members come back in order, each with its own result,
    /// and a member with only part of it noise is still coded.
    #[test]
    fn members_beside_a_stored_one_keep_their_place_and_their_coding() {
        let quiet = text(1536 * 1024);
        let mut halves = text(1024 * 1024);
        halves.extend(noise(1024 * 1024, 7));
        let loud = noise(3 * 1024 * 1024, 11);
        let inputs = [quiet, loud.clone(), halves, Vec::new(), loud];
        let sources: Vec<_> = inputs
            .iter()
            .map(|data| EntrySource::from_bytes(data.clone()))
            .collect();
        let started = std::sync::Mutex::new(Vec::new());
        struct Started<'a>(&'a std::sync::Mutex<Vec<usize>>);
        impl CompressionProgress for Started<'_> {
            fn advance(&self, _: u64) -> bool {
                true
            }
            fn started(&self, member: usize, _: u64) {
                self.0.lock().unwrap().push(member);
            }
        }
        let members = compress_members_with_context(
            &sources,
            &level_one_plan(false),
            &WriterResources::default(),
            &Started(&started),
            &|_, error| error,
        )
        .unwrap();
        let stored: Vec<_> = members.iter().map(|member| member.store).collect();
        assert_eq!(stored, [false, true, false, true, true]);
        for (member, data) in members.iter().zip(&inputs) {
            assert_eq!(member.input_size, data.len() as u64);
            assert_eq!((member.crc32, member.hash), checksums(data));
            if !member.store {
                assert!(member.packed.len() < data.len() as u64 * 3 / 4);
            }
        }
        let mut started = started.into_inner().unwrap();
        started.sort_unstable();
        assert_eq!(started, [0, 1, 2, 3, 4]);
    }
}
