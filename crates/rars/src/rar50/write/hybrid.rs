//! Capture and plan once; only captured bytes enter speculative compression.
use super::{ArchiveEntry, WriterOptions};
use crate::hybrid::{
    choose_minimax, DictionaryMeasurement, DictionaryStats, IndexLimits, RepeatIndex,
};
use crate::streaming::preparation::Records;
use crate::streaming::CapacityCharge;
use crate::{Error, HybridOptions, Result, WriterResources};
use std::collections::BTreeSet;
use std::io::{Read, Write};

pub(super) struct Captured {
    pub entries: Records<ArchiveEntry>,
    pub stats: DictionaryStats,
    _metadata: Option<CapacityCharge>,
}

pub(super) fn validate(
    entries: &[ArchiveEntry],
    options: HybridOptions,
    policy: &super::FilterPolicy,
) -> Result<()> {
    if options.member_order_optimization && (!options.archive_analysis || options.variant & 16 == 0)
    {
        return Err(Error::InvalidArgument(
            "member ordering requires archive analysis and an ordering-enabled hybrid variant",
        ));
    }
    if options.architecture == crate::HybridArchitecture::Streams
        && (options.archive_analysis
            || options.member_order_optimization
            || options.variant & 32 != 0)
    {
        return Err(Error::InvalidArgument(
            "stream-only control requires fixed dictionary selection and preserved member order",
        ));
    }
    if *policy == super::FilterPolicy::Auto && options.variant & 8 == 0 {
        return Err(Error::InvalidArgument(
            "automatic filtering conflicts with the selected hybrid variant",
        ));
    }
    if let super::FilterPolicy::Explicit(spec) = policy {
        for entry in entries {
            if let Some(range) = &spec.range {
                if range.start >= range.end || range.end as u64 > entry.source.len()? {
                    return Err(Error::InvalidArgument("RAR 5 filter range is invalid"));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn resources(resources: &WriterResources, hybrid: HybridOptions) -> WriterResources {
    let mut resources = resources.clone();
    resources.hybrid = Some(hybrid);
    if resources.max_memory_bytes().is_none() {
        let limit = resources.memory_limit().min(hybrid.memory_bytes());
        resources = resources.with_max_memory_bytes(limit);
    }
    if resources.max_spool_bytes().is_none() {
        resources = resources.with_max_spool_bytes(hybrid.index_disk_bytes());
    }
    resources
}

pub(super) fn capture(
    entries: &[ArchiveEntry],
    hybrid: HybridOptions,
    resources: &WriterResources,
    progress: Option<crate::write_progress::ProgressReporter<'_>>,
) -> Result<Captured> {
    if hybrid.member_order_optimization && !hybrid.archive_analysis {
        return Err(Error::InvalidArgument(
            "member ordering requires archive relationship analysis",
        ));
    }
    if hybrid.variant > 63 {
        return Err(Error::InvalidArgument("hybrid variant must be in 0..=63"));
    }
    let limit = resources
        .spool_remaining()
        .unwrap_or(hybrid.index_disk_bytes());
    let cache = hybrid.index_cache_bytes().min(resources.memory_limit() / 4);
    let mut metadata = resources.execution_charge();
    let metadata_size = entries.iter().try_fold(0u64, |sum, entry| {
        let owned = (entry.name.len() as u64)
            .saturating_mul(3)
            .saturating_add(256)
            + entry
                .redirection
                .as_ref()
                .map_or(0, |redirect| redirect.target_name.len()) as u64
            + entry.password.as_ref().map_or(0, |p| p.len()) as u64
            + entry
                .services
                .iter()
                .map(|s| {
                    std::mem::size_of::<super::ServiceEntry>() as u64
                        + s.name.len() as u64
                        + s.data.len() as u64
                        + s.password.as_ref().map_or(0, |p| p.len()) as u64
                })
                .sum::<u64>();
        sum.checked_add(owned)
            .ok_or(Error::InvalidArgument("hybrid metadata capacity overflows"))
    })?;
    if let Some(charge) = &mut metadata {
        charge.grow_to(metadata_size.saturating_add(16 * 1024))?;
    }
    let mut cache_charge = resources.execution_charge();
    if let Some(charge) = &mut cache_charge {
        charge.grow_to(cache.saturating_add(128 * 1024))?;
    }
    let create = |remaining| {
        RepeatIndex::create_with_resources(
            resources
                .temp_dir()
                .unwrap_or_else(|| std::path::Path::new(".")),
            IndexLimits {
                cache_bytes: cache,
                max_disk_bytes: remaining,
            },
            resources,
        )
    };
    let mut global = if hybrid.archive_analysis {
        Some(create(limit)?)
    } else {
        None
    };
    let mut captured = Records::new(entries.len(), resources)?;
    let mut stats = DictionaryStats::default();
    let mut used_disk = 0u64;
    let mut input = [0u8; 64 * 1024];
    let total = entries.iter().try_fold(0u64, |total, entry| {
        Ok::<_, Error>(total.saturating_add(entry.source.len()?))
    })?;
    let tracker =
        crate::write_progress::WorkTracker::new(progress, crate::WriteOperation::Staging, total);
    if let Some(progress) = progress {
        progress.report(crate::WriteProgressEvent::OperationStarted {
            operation: crate::WriteOperation::Staging,
            total_bytes: Some(total),
            total_entries: Some(entries.len()),
            pass: 1,
        });
    }
    for (id, entry) in entries.iter().enumerate() {
        tracker.check()?;
        if resources.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let token = entry.source.consistency_token()?;
        let expected = entry.source.len()?;
        let mut local = if global.is_none() {
            Some(create(limit.saturating_sub(used_disk))?)
        } else {
            None
        };
        let local_only = global.is_none();
        let index = global.as_mut().or(local.as_mut()).expect("one index");
        index.begin_member(id as u64)?;
        let mut reader = entry.source.open()?;
        let mut read = 0u64;
        loop {
            tracker.check()?;
            if resources.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let count = reader.read(&mut input)?;
            if count == 0 {
                break;
            }
            read = read
                .checked_add(count as u64)
                .ok_or(Error::InvalidArgument("hybrid input size overflows"))?;
            if read > expected {
                return Err(Error::SourceChanged("hybrid source grew during capture"));
            }
            index.append_with_cancellation(&input[..count], &|| {
                resources.is_cancelled() || tracker.is_cancelled()
            })?;
            if !tracker.advance(count as u64) {
                return Err(Error::Cancelled);
            }
        }
        if read != expected
            || entry.source.len()? != expected
            || entry.source.consistency_token()? != token
        {
            return Err(Error::SourceChanged("hybrid source changed during capture"));
        }
        index.finish_member_with_cancellation(&|| {
            resources.is_cancelled() || tracker.is_cancelled()
        })?;
        let mut replacement = entry.clone();
        replacement.source = index.member_source(id as u64)?;
        entry.source.release();
        captured.push(replacement)?;
        if local_only {
            merge_stats(&mut stats, index.stats());
            used_disk = used_disk.saturating_add(index.disk_bytes());
        }
    }
    tracker.check()?;
    if let Some(mut index) = global {
        stats = index.stats().clone();
        if hybrid.member_order_optimization && hybrid.variant & 16 != 0 {
            reorder(
                &mut captured,
                &mut index,
                hybrid.dictionary_ceiling,
                resources,
            )?;
        }
    }
    if let Some(progress) = progress {
        progress.report(crate::WriteProgressEvent::OperationFinished {
            operation: crate::WriteOperation::Staging,
            total_bytes: Some(total),
            total_entries: Some(entries.len()),
            pass: 1,
        });
    }
    Ok(Captured {
        entries: captured,
        stats,
        _metadata: metadata,
    })
}

fn merge_stats(into: &mut DictionaryStats, from: &DictionaryStats) {
    into.witnesses = into.witnesses.saturating_add(from.witnesses);
    into.matched_bytes = into.matched_bytes.saturating_add(from.matched_bytes);
    into.max_distance = into.max_distance.max(from.max_distance);
    for (a, b) in into.distance_bytes.iter_mut().zip(from.distance_bytes) {
        *a = a.saturating_add(b);
    }
}

// Reordering never crosses special entries, duplicate names or password domains.
// The complete index remains exact; ordering uses explicitly bounded hints.
fn reorder(
    entries: &mut [ArchiveEntry],
    index: &mut RepeatIndex,
    dictionary: u64,
    resources: &WriterResources,
) -> Result<()> {
    let mut names = BTreeSet::new();
    if entries
        .iter()
        .any(|entry| !names.insert(entry.name.clone()))
    {
        return Ok(());
    }
    let original_names: Vec<_> = entries.iter().map(|entry| entry.name.clone()).collect();
    let mut begin = 0;
    while begin < entries.len() {
        if entries[begin].is_directory || entries[begin].redirection.is_some() {
            begin += 1;
            continue;
        }
        let mut end = begin + 1;
        while end < entries.len()
            && !entries[end].is_directory
            && entries[end].redirection.is_none()
            && entries[end].password == entries[begin].password
        {
            end += 1;
        }
        let mut position = begin;
        while position + 1 < end {
            if resources.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let current_id = original_names
                .iter()
                .position(|name| *name == entries[position].name)
                .unwrap() as u64;
            let size = entries[position].source.len()?;
            let length = size.min(64) as usize;
            if length == 0 {
                position += 1;
                continue;
            }
            // A tail witness can remain reachable when a related member follows.
            let offset = size
                .saturating_sub(dictionary)
                .min(size.saturating_sub(length as u64));
            let pattern = index.read_member_range(current_id, offset, length)?;
            let (hits, _) = index.occurrences_limited(&pattern, 128)?;
            let best = (position + 1..end)
                .filter_map(|candidate| {
                    let id = original_names
                        .iter()
                        .position(|name| *name == entries[candidate].name)
                        .unwrap() as u64;
                    let score = hits
                        .iter()
                        .filter(|hit| {
                            hit.member_id == id
                                && size.saturating_sub(offset).saturating_add(hit.offset)
                                    <= dictionary
                        })
                        .count();
                    (score > 0).then_some((candidate, score))
                })
                .max_by(|(ai, a), (bi, b)| a.cmp(b).then_with(|| bi.cmp(ai)));
            if let Some((best, _)) = best {
                entries[position + 1..=best].rotate_right(1);
            }
            position += 1;
        }
        begin = end;
    }
    Ok(())
}

pub(super) fn shortlist(
    captured: &Captured,
    options: WriterOptions,
    resources: &WriterResources,
) -> Result<Vec<u64>> {
    let hybrid = options.hybrid.expect("hybrid options");
    if let Some(explicit) = options.dictionary_size {
        super::filter_policy::validate_dictionary_size(options.target, explicit)?;
        return Ok(vec![explicit]);
    }
    let ceiling = hybrid.dictionary_ceiling;
    super::filter_policy::validate_dictionary_size(options.target, ceiling)?;
    let baseline = super::filter_policy::dictionary_size_for_options(
        options,
        super::dictionary_reach(&captured.entries, options.features.solid),
        resources.memory_limit(),
    )?
    .min(ceiling);
    if hybrid.variant & 32 == 0 {
        return Ok(vec![baseline]);
    }
    let count = if hybrid.profile == crate::HybridProfile::Server {
        3
    } else {
        2
    };
    crate::hybrid::dictionary_shortlist(&captured.stats, baseline, ceiling, count)
}

fn codec_options(
    options: HybridOptions,
    policy: &super::FilterPolicy,
) -> crate::codec::rar50::HybridCodecOptions {
    let server = options.profile == crate::HybridProfile::Server;
    crate::codec::rar50::HybridCodecOptions {
        beam_width: if options.variant & 2 == 0 {
            1
        } else {
            options.candidate_states()
        },
        finalists: if server { 4 } else { 2 },
        full_partitions: options.variant & 4 != 0,
        deeper_search: options.variant & 1 != 0,
        auto_filters: *policy == super::FilterPolicy::Auto && options.variant & 8 != 0,
        max_match_candidates: if server { 64 } else { 16 },
        max_endpoints_per_run: if server { 16 } else { 8 },
        pricing_passes: options.passes(),
    }
}

fn workspace(dictionary: u64, options: HybridOptions) -> u64 {
    let visits = if options.profile == crate::HybridProfile::Server {
        64
    } else {
        16
    };
    let states = if options.variant & 2 == 0 {
        1
    } else {
        options.candidate_states() as u64
    };
    dictionary
        .saturating_mul(8)
        .saturating_add((256 * 1024u64).saturating_mul(visits * 8 + states * 40 + 192))
}

pub(super) fn select_dictionary(
    captured: &Captured,
    options: WriterOptions,
    policy: &super::FilterPolicy,
    resources: &WriterResources,
) -> Result<u64> {
    let hybrid = options.hybrid.expect("hybrid options");
    let dictionaries = shortlist(captured, options, resources)?;
    if dictionaries.len() == 1 {
        return Ok(dictionaries[0]);
    }
    let allowance = resources.execution.as_ref().expect("hybrid memory ledger");
    let control = crate::read_control::ReadControl::default();
    let config = codec_options(hybrid, policy);
    let mandatory = match policy {
        super::FilterPolicy::Explicit(spec) => std::slice::from_ref(spec),
        _ => &[],
    };
    let target_bytes = if hybrid.profile == crate::HybridProfile::Server {
        16 * 1024 * 1024
    } else {
        4 * 1024 * 1024
    };
    let mut measurements = Vec::with_capacity(dictionaries.len());
    for dictionary in dictionaries {
        if resources.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let required = workspace(dictionary, hybrid);
        if required > resources.memory_limit() {
            continue;
        }
        let version = super::filter_policy::rar50_algorithm_version(options, dictionary)?;
        let mut cost = 0u64;
        let mut work = 0u64;
        let mut sampled = 0usize;
        // Each pilot follows the proposed stream from its real starting state.
        // This includes joins, resets, filter-domain history and recent distances.
        let mut state = crate::codec::rar50::HybridCodecState::new(
            &[],
            dictionary as usize,
            version,
            allowance,
        )?;
        for entry in captured.entries.iter() {
            let size = entry.source.len()?;
            if sampled >= target_bytes {
                break;
            }
            if !options.features.solid {
                state = crate::codec::rar50::HybridCodecState::new(
                    &[],
                    dictionary as usize,
                    version,
                    allowance,
                )?;
            }
            state.begin_member();
            let mut reader = entry.source.open()?;
            let mut remaining = size.min((target_bytes - sampled) as u64);
            let mut read_window = || -> Result<crate::codec::workspace::Buffer<u8, crate::codec::workspace::Limited>> {
                if resources.is_cancelled() { return Err(Error::Cancelled); }
                let length = remaining.min(256 * 1024) as usize;
                let mut bytes = crate::codec::workspace::Buffer::filled(length, 0u8, allowance)?;
                reader.read_exact(&mut bytes)?;
                remaining -= length as u64;
                Ok(bytes)
            };
            let mut current = read_window()?;
            let mut next = read_window()?;
            while !current.is_empty() {
                let result = crate::codec::rar50::encode_partition(
                    &current,
                    &next,
                    &state,
                    config,
                    mandatory,
                    next.is_empty(),
                    allowance,
                    &control,
                    &|| resources.is_cancelled(),
                    None,
                )?;
                debug_assert_eq!(result.history_append.len(), current.len());
                debug_assert!(!next.is_empty() || result.next_cost == 0);
                cost = cost.saturating_add(result.bytes.len() as u64);
                work = work
                    .saturating_add(result.work.endpoint_prices)
                    .saturating_add(result.work.lookahead_bytes)
                    .saturating_add(result.work.collector_searches)
                    .saturating_add(result.work.chain_candidates)
                    .saturating_add(result.work.greedy_searches)
                    .saturating_add(result.work.seeded_positions)
                    .saturating_add(current.len() as u64);
                sampled += current.len();
                state = result.end_state;
                current = next;
                next = read_window()?;
            }
        }
        measurements.push(DictionaryMeasurement {
            dictionary_size: dictionary,
            packed_bytes: cost,
            work_units: work,
            memory_bytes: required,
        });
    }
    if measurements.is_empty() {
        return Err(Error::MemoryLimitExceeded {
            limit: resources.memory_limit(),
            required: workspace(hybrid.dictionary_ceiling, hybrid),
            dictionary_size: hybrid.dictionary_ceiling,
        });
    }
    Ok(choose_minimax(&measurements)?.dictionary_size)
}

pub(super) fn compress_members(
    sources: &[crate::EntrySource],
    plan: &super::compress::CompressPlan,
    resources: &WriterResources,
    progress: &dyn super::compress::CompressionProgress,
    context: &(dyn Fn(usize, Error) -> Error + Sync),
) -> Result<Records<super::compress::CompressedMember>> {
    let hybrid = resources.hybrid.expect("hybrid execution settings");
    let required = workspace(plan.dictionary_size, hybrid);
    if !plan.solid && sources.len() > 1 {
        let ledger = resources.execution.as_ref().expect("hybrid memory ledger");
        let headroom = ledger.available().saturating_sub(64 * 1024);
        let window = (headroom / required.saturating_add(256))
            .max(1)
            .min(crate::parallel::threads() as u64)
            .min(sources.len() as u64) as usize;
        let mut results = Records::new(sources.len(), resources)?;
        for (wave, sources) in sources.chunks(window).enumerate() {
            let start = wave * window;
            let jobs = Records::collect(
                sources
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(index, source)| Ok((start + index, source))),
                resources,
            )?;
            let outputs = super::compress::run_jobs_admitted(
                jobs,
                resources,
                progress,
                |_| required,
                |(index, source), worker, progress, _| {
                    let mapped = MemberProgress {
                        inner: progress,
                        member: index,
                    };
                    let mut result = compress_members(
                        std::slice::from_ref(&source),
                        plan,
                        worker,
                        &mapped,
                        &|_, error| context(index, error),
                    )?;
                    result
                        .pop()
                        .ok_or(Error::WriterFailure("hybrid member result is missing"))
                },
            )?;
            for output in outputs {
                results.push(output)?;
            }
        }
        return Ok(results);
    }
    let _permit = resources
        .acquire_cancellable(required, plan.dictionary_size, &|| progress.is_cancelled())?;
    let allowance = resources.execution.as_ref().expect("hybrid memory ledger");
    let mut state = crate::codec::rar50::HybridCodecState::new(
        &[],
        plan.dictionary_size as usize,
        plan.algorithm_version,
        allowance,
    )?;
    let mut results = Records::new(sources.len(), resources)?;
    for (member, source) in sources.iter().enumerate() {
        if resources.is_cancelled() || progress.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if !plan.solid {
            state = crate::codec::rar50::HybridCodecState::new(
                &[],
                plan.dictionary_size as usize,
                plan.algorithm_version,
                allowance,
            )?;
        }
        state.begin_member();
        let result = (|| {
            let token = source.consistency_token()?;
            let size = source.len()?;
            progress.started(member, size);
            let mut reader = source.open()?;
            let mut remaining = size;
            let mut read_window = || -> Result<crate::codec::workspace::Buffer<u8, crate::codec::workspace::Limited>> {
                let len = remaining.min(256 * 1024) as usize;
                let mut bytes = crate::codec::workspace::Buffer::filled(len, 0u8, allowance)?;
                reader.read_exact(&mut bytes).map_err(|_| Error::SourceChanged("hybrid captured source is truncated"))?;
                remaining -= len as u64;
                Ok(bytes)
            };
            let mut current = read_window()?;
            let mut next = read_window()?;
            let mut packed = crate::streaming::Spool::create(resources)?;
            let mut crc = crate::crc32::Crc32::new();
            let mut hash = super::blake2sp::Hasher::new();
            let mandatory: &[crate::FilterSpec] = match &plan.filter_policy {
                super::FilterPolicy::Explicit(spec) => std::slice::from_ref(spec),
                _ => &[],
            };
            let config = codec_options(hybrid, &plan.filter_policy);
            while !current.is_empty() {
                let result = crate::codec::rar50::encode_partition(&current, &next, &state, config, mandatory, next.is_empty(), allowance, &crate::read_control::ReadControl::default(), &|| resources.is_cancelled() || progress.is_cancelled(), None)?;
                debug_assert_eq!(result.history_append.len(), current.len());
                debug_assert!(!next.is_empty() || result.next_cost == 0);
                debug_assert!(result.partition_id < 4 && result.representation_id < 6);
                debug_assert!(result.cache_quality.iter().all(|quality| quality.dictionary_size == plan.dictionary_size as usize && quality.block_start <= quality.block_end));
                packed.write_all(&result.bytes)?;
                crc.update(&current);
                hash.update(&current);
                state = result.end_state;
                if !progress.advance(current.len() as u64) { return Err(Error::Cancelled); }
                current = next;
                next = read_window()?;
            }
            let mut extra = [0u8; 1];
            if reader.read(&mut extra)? != 0 { return Err(Error::SourceChanged("hybrid captured source grew")); }
            if source.len()? != size || source.consistency_token()? != token {
                return Err(Error::SourceChanged("hybrid source changed during compression"));
            }
            packed.park();
            progress.finished(member, size);
            Ok(super::compress::CompressedMember {
                input_size: size, crc32: crc.finish(), hash: hash.finalize(),
                store: size == 0 || super::filter_policy::should_store_compressed_payload(size, packed.len(), plan.solid, &plan.filter_policy),
                packed, solid_continuation: plan.solid && member > 0,
            })
        })().map_err(|error| context(member, error))?;
        results.push(result)?;
    }
    Ok(results)
}

struct MemberProgress<'a> {
    inner: &'a dyn super::compress::CompressionProgress,
    member: usize,
}
impl super::compress::CompressionProgress for MemberProgress<'_> {
    fn advance(&self, bytes: u64) -> bool {
        self.inner.advance(bytes)
    }
    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
    fn started(&self, _: usize, size: u64) {
        self.inner.started(self.member, size);
    }
    fn finished(&self, _: usize, size: u64) {
        self.inner.finished(self.member, size);
    }
}

#[cfg(test)]
mod dictionary_tests {
    use super::*;

    #[test]
    fn automatic_dictionary_respects_profile_ceiling_and_explicit_dictionary_wins() {
        let hybrid = HybridOptions::default()
            .with_variant(0)
            .unwrap()
            .with_dictionary_ceiling(256 * 1024);
        let resources = resources(&WriterResources::default(), hybrid);
        let captured = Captured {
            entries: Records::collect(
                [Ok(ArchiveEntry::new(
                    b"large".to_vec(),
                    crate::EntrySource::from_opener(16 * 1024 * 1024, || {
                        panic!("dictionary planning opened the source")
                    }),
                ))]
                .into_iter(),
                &resources,
            )
            .unwrap(),
            stats: DictionaryStats::default(),
            _metadata: None,
        };
        let options = WriterOptions::new(
            crate::ArchiveVersion::Rar50,
            crate::FeatureSet::store_only(),
        )
        .with_compression_level(3)
        .with_hybrid(hybrid);
        assert_eq!(
            shortlist(&captured, options, &resources).unwrap(),
            [256 * 1024]
        );
        assert_eq!(
            shortlist(
                &captured,
                options.with_dictionary_size(8 * 1024 * 1024),
                &resources
            )
            .unwrap(),
            [8 * 1024 * 1024]
        );
    }
}
