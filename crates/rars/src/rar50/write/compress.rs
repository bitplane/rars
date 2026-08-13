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

use super::filter_policy::compression_info;
use crate::codec::rar50::{encode_lz_streaming_block, EncodeOptions};
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

#[derive(Debug, Clone, Copy)]
pub(super) struct CompressPlan {
    pub(super) algorithm_version: u8,
    pub(super) encode_options: EncodeOptions,
    pub(super) dictionary_size: u64,
    pub(super) block_size: usize,
    pub(super) solid: bool,
    /// The RAR 5 compression method. Method zero means the members are stored
    /// verbatim, so nothing is compressed at all.
    pub(super) method: u8,
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
}

pub(super) fn compress_members(
    sources: &[EntrySource],
    plan: CompressPlan,
    resources: &WriterResources,
) -> Result<Vec<CompressedMember>> {
    let mut integrity = Vec::with_capacity(sources.len());
    for source in sources {
        let input_size = source.len()?;
        let (crc32, hash) = super::source_integrity(source, input_size, plan.block_size)?;
        integrity.push((input_size, crc32, hash));
    }

    let required = super::streaming_lz_workspace(plan.dictionary_size, plan.block_size);
    let max_jobs_by_memory = resources.memory_limit() / required;
    if max_jobs_by_memory == 0 {
        resources.acquire(required, plan.dictionary_size)?;
        unreachable!("oversized workspace acquisition must fail");
    }
    let batch_capacity = usize::try_from(max_jobs_by_memory)
        .unwrap_or(usize::MAX)
        .min(rayon::current_num_threads())
        .max(1);

    // Storing is not "compress and hope it does not help": the header records
    // method zero, so the payload must be the source bytes.
    let packed = if plan.method == 0 {
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
        )?
    } else {
        compress_independent_members(
            sources,
            &integrity,
            &plan,
            batch_capacity,
            required,
            resources,
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
                // A solid member must never fall back to stored: the members
                // after it decode against the dictionary it contributes to.
                store: plan.method == 0
                    || input_size == 0
                    || (!plan.solid && packed.len() >= input_size),
                packed,
                solid_continuation: plan.solid && member > 0,
            },
        )
        .collect())
}

/// Members with independent dictionaries, interleaved so a batch of small
/// members can still saturate the machine.
fn compress_independent_members(
    sources: &[EntrySource],
    integrity: &[(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
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
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mut histories = vec![Vec::new(); streams.len()];
        let mut cursor = 0usize;
        while streams.iter().any(|stream| stream.remaining != 0) {
            let reserved = required.saturating_mul(batch_capacity as u64);
            let _permit = resources.acquire(reserved, plan.dictionary_size)?;

            let mut jobs = Vec::with_capacity(batch_capacity);
            let mut misses = 0usize;
            while jobs.len() < batch_capacity && misses < streams.len() {
                let stream_count = streams.len();
                let stream = &mut streams[cursor];
                cursor = (cursor + 1) % stream_count;
                if stream.remaining == 0 {
                    misses += 1;
                    continue;
                }
                misses = 0;

                let member = stream.member;
                let data = read_block(stream, plan.block_size)?;
                let is_last = stream.remaining == 0;
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

            compress_wave(jobs, plan, &mut streams)?;
        }

        packed.extend(streams.into_iter().map(|stream| stream.packed));
    }
    Ok(packed)
}

/// One dictionary running through every member in order.
fn compress_solid_chain(
    sources: &[EntrySource],
    integrity: &[(u64, u32, [u8; 32])],
    plan: &CompressPlan,
    batch_capacity: usize,
    required: u64,
    resources: &WriterResources,
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
            while next < streams.len() && streams[next].remaining == 0 {
                next += 1;
            }
            let Some(stream) = streams.get_mut(next) else {
                break;
            };

            let member = stream.member;
            let data = read_block(stream, plan.block_size)?;
            let is_last = stream.remaining == 0;
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
        compress_wave(jobs, plan, &mut streams)?;
    }

    Ok(streams.into_iter().map(|stream| stream.packed).collect())
}

/// Reads the next block from `stream`, checking the source has not grown.
fn read_block(stream: &mut MemberStream, block_size: usize) -> Result<Vec<u8>> {
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
) -> Result<()> {
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
