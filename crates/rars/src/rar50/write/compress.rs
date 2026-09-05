//! Turning member sources into packed payloads, in bounded memory.
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
use crate::codec::rar50::{encode_lz_streaming_block, BlockSplitter, EncodeOptions};
use crate::streaming::Spool;
use crate::{EntrySource, Error, Result, WriterResources};
use std::io::{Read, Write};

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

#[derive(Debug, Clone)]
pub(super) struct CompressPlan {
    pub(super) algorithm_version: u8,
    pub(super) encode_options: EncodeOptions,
    pub(super) dictionary_size: u64,
    pub(super) block_size: usize,
    pub(super) solid: bool,
    /// The RAR 5 compression method. Method zero means the members are stored
    /// verbatim, so nothing is compressed at all.
    pub(super) method: u8,
    /// Filters and multi-candidate encoding both need the whole member at
    /// once, so they only run for members that fit the memory budget.
    pub(super) filter_policy: FilterPolicy,
    pub(super) candidates: Vec<EncodeOptions>,
}

/// One block of input waiting to be compressed.
struct BlockJob {
    member: usize,
    data: Vec<u8>,
    history: Vec<u8>,
    /// Marks the final block of a member's compressed stream.
    is_last: bool,
}

/// A member being read, and the packed bytes it has produced so far.
struct MemberStream {
    member: usize,
    reader: Box<dyn crate::EntryReader>,
    remaining: u64,
    packed: Spool,
    /// A chunk read to decide a block boundary and not used by that block.
    pushback: Vec<u8>,
}

impl MemberStream {
    /// Whether this member has anything left, read or unread.
    fn has_more(&self) -> bool {
        self.remaining != 0 || !self.pushback.is_empty()
    }
}

/// `advance` is called with each newly completed chunk of work and returns
/// false when the caller wants to stop.
pub(super) fn compress_members_reporting(
    sources: &[EntrySource],
    plan: CompressPlan,
    resources: &WriterResources,
    advance: &(dyn Fn(u64) -> bool + Sync),
) -> Result<Vec<CompressedMember>> {
    let mut integrity = Vec::with_capacity(sources.len());
    for source in sources {
        let input_size = source.len()?;
        let (crc32, hash) = super::source_integrity(source, input_size, plan.block_size)?;
        integrity.push((input_size, crc32, hash));
    }

    // Filters and multi-candidate encoding both need the whole member at once.
    // Members that fit the budget take that path; the rest stream, losing the
    // filter but staying within memory.
    let wants_whole_member =
        plan.method != 0 && (plan.filter_policy != FilterPolicy::None || plan.candidates.len() > 1);
    if wants_whole_member && !plan.solid {
        return compress_members_whole(sources, &integrity, &plan, resources, advance);
    }

    // Any candidate that parses optimally searches a tree, so the charge has to
    // cover the widest finder the member could build, not the one the level
    // finally writes with.
    let optimal_parse = plan.encode_options.optimal_parse
        || plan.candidates.iter().any(|options| options.optimal_parse);
    // A block grows past the read size when the data it covers is not moving,
    // so the charge covers the largest one the parse could end up holding.
    let required = super::streaming_lz_workspace(
        plan.dictionary_size,
        crate::codec::rar50::MAX_LZ_BLOCK_SIZE,
        optimal_parse,
    );
    let max_jobs_by_memory = resources.memory_limit() / required;
    if max_jobs_by_memory == 0 {
        resources.acquire(required, plan.dictionary_size)?;
        unreachable!("oversized workspace acquisition must fail");
    }
    let batch_capacity = usize::try_from(max_jobs_by_memory)
        .unwrap_or(usize::MAX)
        .min(crate::parallel::threads())
        .max(1);

    // Storing is not "compress and hope it does not help": the header records
    // method zero, so the payload must be the source bytes.
    let packed = if plan.method == 0 {
        for (input_size, _, _) in &integrity {
            if !advance(*input_size) {
                return Err(Error::Cancelled);
            }
        }
        integrity
            .iter()
            .map(|_| Spool::create(resources))
            .collect::<Result<Vec<_>>>()?
    } else if plan.solid {
        compress_solid_chain(
            sources,
            &integrity,
            &plan,
            batch_capacity,
            required,
            resources,
            advance,
        )?
    } else {
        compress_independent_members(
            sources,
            &integrity,
            &plan,
            batch_capacity,
            required,
            resources,
            advance,
        )?
    };

    Ok(packed
        .into_iter()
        .zip(&integrity)
        .enumerate()
        .map(
            |(member, (packed, &(input_size, crc32, hash)))| CompressedMember {
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
            },
        )
        .collect())
}

/// Working memory a member needs to be filtered as a whole: the member, the
/// filtered copy, and the candidate packed outputs being compared.
fn whole_member_workspace(input_size: u64, plan: &CompressPlan) -> u64 {
    let optimal = plan.encode_options.optimal_parse
        || plan.candidates.iter().any(|options| options.optimal_parse);
    let reach = plan
        .candidates
        .iter()
        .map(|options| options.max_match_distance as u64)
        .chain(std::iter::once(
            plan.encode_options.max_match_distance as u64,
        ))
        .max()
        .unwrap_or(0)
        .min(input_size)
        .max(crate::codec::rar50::LZ_BLOCK_SIZE as u64);
    let block = input_size.min(crate::codec::rar50::MAX_LZ_BLOCK_SIZE as u64) as usize;
    // Input, transformed input and competing packed outputs stay live alongside
    // the finder and the per-block token/parse workspace, not instead of them.
    input_size
        .saturating_mul(4)
        .saturating_add(super::streaming_lz_workspace(reach, block, optimal))
}

/// Compresses independent whole members concurrently, with each workspace
/// admitted against the shared budget before its input is loaded.
///
/// A member too large for the budget falls back to streaming: an automatic
/// filter is a best-effort size win, so dropping it beats refusing the job.
/// An explicitly requested filter is not best-effort, so that one errors.
fn compress_members_whole(
    sources: &[EntrySource],
    integrity: &[(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &(dyn Fn(u64) -> bool + Sync),
) -> Result<Vec<CompressedMember>> {
    // Each worker acquires its complete workspace before loading the source.
    // Results are disk spools, so retaining them in source order is cheap.
    let mut members = Vec::with_capacity(sources.len());
    let mut start = 0;
    while start < sources.len() {
        let end = (start..sources.len())
            .take(crate::parallel::threads())
            .take_while(|&index| {
                whole_member_workspace(integrity[index].0, plan) <= resources.memory_limit()
            })
            .last()
            .map_or(start, |index| index + 1);
        if end == start {
            // A streaming fallback can itself use rayon. Run it outside the
            // worker batch so a nested job cannot wait behind budget waiters.
            members.push(compress_whole_member(
                &sources[start],
                integrity[start],
                plan,
                resources,
                advance,
            )?);
            start += 1;
        } else {
            members.extend(crate::parallel::map_collect(
                (start..end).collect(),
                |index| {
                    compress_whole_member(
                        &sources[index],
                        integrity[index],
                        plan,
                        resources,
                        advance,
                    )
                },
            )?);
            start = end;
        }
    }
    Ok(members)
}

fn compress_whole_member(
    source: &EntrySource,
    integrity: (u64, u32, [u8; 32]),
    plan: &CompressPlan,
    resources: &WriterResources,
    advance: &(dyn Fn(u64) -> bool + Sync),
) -> Result<CompressedMember> {
    let (input_size, crc32, hash) = integrity;
    let required = whole_member_workspace(input_size, plan);

    let mut packed_spool = Spool::create(resources)?;
    let mut stored = input_size == 0;
    if !stored {
        match resources.acquire(required, plan.dictionary_size) {
            Ok(_permit) => {
                let mut data = Vec::with_capacity(input_size as usize);
                source.open()?.read_to_end(&mut data)?;
                if data.len() as u64 != input_size {
                    return Err(Error::InvalidHeader(
                        "entry source size changed while compressing",
                    ));
                }
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
                let share = |bytes: u64| {
                    (u128::from(bytes) * u128::from(input_size) / u128::from(walk)) as u64
                };
                let mut reported = 0u64;
                let mut charged = 0u64;
                let mut report = |position: usize| {
                    let position = position as u64;
                    if position < reported {
                        // A new pass restarted at the beginning.
                        reported = 0;
                    }
                    let delta = position - reported;
                    reported = position;
                    let target = (charged + delta).min(walk);
                    let scaled = share(target) - share(charged);
                    charged = target;
                    advance(scaled)
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
            Err(error) => {
                if plan.filter_policy != FilterPolicy::Auto {
                    return Err(error);
                }
                // Too big to filter; compress it as a stream instead.
                let mut streamed = compress_members_reporting(
                    std::slice::from_ref(source),
                    CompressPlan {
                        filter_policy: FilterPolicy::None,
                        candidates: vec![plan.encode_options],
                        ..plan.clone()
                    },
                    resources,
                    advance,
                )?;
                return Ok(streamed.remove(0));
            }
        }
    }

    Ok(CompressedMember {
        input_size,
        crc32,
        hash,
        store: stored,
        packed: packed_spool,
        solid_continuation: false,
    })
}

/// Members with independent dictionaries, interleaved so a batch of small
/// members can still saturate the machine.
#[allow(clippy::too_many_arguments)]
fn compress_independent_members(
    sources: &[EntrySource],
    integrity: &[(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &(dyn Fn(u64) -> bool + Sync),
) -> Result<Vec<Spool>> {
    let mut packed = Vec::with_capacity(sources.len());
    for (group_index, group) in sources.chunks(batch_capacity).enumerate() {
        let group_start = group_index * batch_capacity;
        let mut streams = group
            .iter()
            .enumerate()
            .map(|(offset, source)| {
                Ok(MemberStream {
                    member: offset,
                    reader: source.open()?,
                    remaining: integrity[group_start + offset].0,
                    packed: Spool::create(resources)?,
                    pushback: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut histories = vec![Vec::new(); streams.len()];
        let mut cursor = 0usize;
        while streams.iter().any(MemberStream::has_more) {
            let reserved = required.saturating_mul(batch_capacity as u64);
            let _permit = resources.acquire(reserved, plan.dictionary_size)?;

            let mut jobs = Vec::with_capacity(batch_capacity);
            let mut misses = 0usize;
            while jobs.len() < batch_capacity && misses < streams.len() {
                let stream_count = streams.len();
                let stream = &mut streams[cursor];
                cursor = (cursor + 1) % stream_count;
                if !stream.has_more() {
                    misses += 1;
                    continue;
                }
                misses = 0;

                let member = stream.member;
                let data = read_block(stream, plan.block_size)?;
                let is_last = !stream.has_more();
                jobs.push(BlockJob {
                    member,
                    history: histories[member].clone(),
                    is_last,
                    data,
                });
                advance_history(
                    &mut histories[member],
                    &jobs.last().expect("just pushed").data,
                    plan.encode_options.max_match_distance,
                );
            }

            compress_wave(jobs, plan, &mut streams, advance)?;
        }

        packed.extend(streams.into_iter().map(|stream| stream.packed));
    }
    Ok(packed)
}

/// One dictionary running through every member in order.
#[allow(clippy::too_many_arguments)]
fn compress_solid_chain(
    sources: &[EntrySource],
    integrity: &[(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
    advance: &(dyn Fn(u64) -> bool + Sync),
) -> Result<Vec<Spool>> {
    let mut streams = sources
        .iter()
        .enumerate()
        .map(|(member, source)| {
            Ok(MemberStream {
                member,
                reader: source.open()?,
                remaining: integrity[member].0,
                packed: Spool::create(resources)?,
                pushback: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut history: Vec<u8> = Vec::new();
    let mut next = 0usize;
    loop {
        let reserved = required.saturating_mul(batch_capacity as u64);
        let _permit = resources.acquire(reserved, plan.dictionary_size)?;

        // Read ahead far enough to fill a wave. Reading is sequential because
        // each block's history is the raw input before it, but it is only
        // reading; the compression it feeds runs in parallel.
        let mut jobs = Vec::with_capacity(batch_capacity);
        while jobs.len() < batch_capacity {
            while next < streams.len() && !streams[next].has_more() {
                next += 1;
            }
            let Some(stream) = streams.get_mut(next) else {
                break;
            };

            let member = stream.member;
            let data = read_block(stream, plan.block_size)?;
            let is_last = !stream.has_more();
            jobs.push(BlockJob {
                member,
                history: history.clone(),
                is_last,
                data,
            });
            advance_history(
                &mut history,
                &jobs.last().expect("just pushed").data,
                plan.encode_options.max_match_distance,
            );
        }

        if jobs.is_empty() {
            break;
        }
        compress_wave(jobs, plan, &mut streams, advance)?;
    }

    Ok(streams.into_iter().map(|stream| stream.packed).collect())
}

/// Reads the next block from `stream`, checking the source has not grown.
///
/// One chunk, then further chunks while the data is not moving, which is the
/// same question [`BlockSplitter`] answers for the buffered writer. Both have
/// to reach the same answer or the same input packs to two different archives.
fn read_block(stream: &mut MemberStream, block_size: usize) -> Result<Vec<u8>> {
    let mut data = read_chunk(stream, block_size)?;
    let mut splitter = BlockSplitter::new();
    splitter.accept(&data);
    while stream.has_more() {
        let next = read_chunk(stream, block_size)?;
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
fn read_chunk(stream: &mut MemberStream, block_size: usize) -> Result<Vec<u8>> {
    if !stream.pushback.is_empty() {
        return Ok(std::mem::take(&mut stream.pushback));
    }
    let wanted = usize::try_from(stream.remaining.min(block_size as u64))
        .map_err(|_| Error::InvalidHeader("RAR 5 block size overflows usize"))?;
    let mut data = vec![0u8; wanted];
    stream.reader.read_exact(&mut data)?;
    stream.remaining -= wanted as u64;
    if stream.remaining == 0 {
        let mut trailing = [0u8; 1];
        if stream.reader.read(&mut trailing)? != 0 {
            return Err(Error::InvalidHeader(
                "entry source size changed while compressing",
            ));
        }
    }
    Ok(data)
}

/// Extends the rolling window with `data`, dropping what has fallen out of
/// dictionary range.
fn advance_history(history: &mut Vec<u8>, data: &[u8], max_match_distance: usize) {
    history.extend_from_slice(data);
    let keep_from = history.len().saturating_sub(max_match_distance);
    if keep_from != 0 {
        history.drain(..keep_from);
    }
}

/// Compresses a wave of blocks in parallel, then appends the results to their
/// members in job order so output does not depend on scheduling.
fn compress_wave(
    jobs: Vec<BlockJob>,
    plan: &CompressPlan,
    streams: &mut [MemberStream],
    advance: &(dyn Fn(u64) -> bool + Sync),
) -> Result<()> {
    let wave_bytes: u64 = jobs.iter().map(|job| job.data.len() as u64).sum();
    let packed_blocks = crate::parallel::map_collect(jobs, |job| {
        let packed = encode_lz_streaming_block(
            &job.data,
            &job.history,
            plan.algorithm_version,
            plan.encode_options,
            job.is_last,
        )?;
        Ok::<_, crate::codec::Error>((job.member, packed))
    })?;
    for (member, packed) in packed_blocks {
        streams[member].packed.write_all(&packed)?;
    }
    if !advance(wave_bytes) {
        return Err(Error::Cancelled);
    }
    Ok(())
}

/// The compression-info vint for a member, including its solid flag.
pub(super) fn member_compression_info(
    plan: &CompressPlan,
    member: &CompressedMember,
    method: u8,
) -> Result<u64> {
    compression_info(
        plan.algorithm_version,
        if member.store { 0 } else { method },
        plan.dictionary_size,
        member.solid_continuation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
