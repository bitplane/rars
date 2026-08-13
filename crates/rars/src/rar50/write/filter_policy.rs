use super::*;
use crate::codec::rar50::{
    encode_lz_member_with_options, encode_lz_member_with_options_and_progress, EncodeOptions,
    Unpack50Encoder,
};
use crate::x86_filter_scan::auto_x86_filter_ranges;

fn borrow_progress<'a>(
    progress: &'a mut Option<&mut dyn FnMut(usize) -> bool>,
) -> Option<&'a mut dyn FnMut(usize) -> bool> {
    match progress {
        Some(report) => Some(&mut **report),
        None => None,
    }
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_policy(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_filter_policy_and_progress(data, algorithm_version, policy, options, None)
}

fn encode_member_with_filter_policy_and_progress(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    match policy {
        FilterPolicy::None => match progress {
            Some(progress) => {
                encode_safe_lz_member_with_progress(data, algorithm_version, options, progress)
            }
            None => encode_safe_lz_member(data, algorithm_version, options),
        },
        FilterPolicy::Explicit(filter) => encode_member_with_filter_specs_progress(
            data,
            algorithm_version,
            std::slice::from_ref(filter),
            options,
            progress,
        )
        .map_err(Error::from),
        FilterPolicy::Auto => {
            encode_member_with_auto_size_filter_progress(data, algorithm_version, options, progress)
        }
    }
}

pub(super) fn encode_member_with_filter_policy_candidates_and_progress(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    candidates: &[EncodeOptions],
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let mut remaining = candidates.iter().copied();
    let first = remaining.next().ok_or(Error::InvalidHeader(
        "RAR 5 compression level has no encoder options",
    ))?;

    // Searching for a filter once and then trying the encoder settings against
    // it is the difference between a handful of passes over the member and one
    // whole search per setting.
    if *policy == FilterPolicy::Auto && auto_size_filter_search_applies(data) {
        let (specs, mut best) = choose_auto_size_filter(
            data,
            algorithm_version,
            first,
            borrow_progress(&mut progress),
        )?;
        // The search already encoded the winner at the first setting, so only
        // the remaining settings are left to try.
        for options in remaining {
            let packed = encode_member_with_filter_specs_progress(
                data,
                algorithm_version,
                &specs,
                options,
                borrow_progress(&mut progress),
            )
            .map_err(Error::from)?;
            if packed.len() < best.len() {
                best = packed;
            }
        }
        return Ok(best);
    }

    let mut best = encode_member_with_filter_policy_and_progress(
        data,
        algorithm_version,
        policy,
        first,
        borrow_progress(&mut progress),
    )?;
    for options in remaining {
        let packed = encode_member_with_filter_policy_and_progress(
            data,
            algorithm_version,
            policy,
            options,
            borrow_progress(&mut progress),
        )?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

fn auto_size_filter_search_applies(data: &[u8]) -> bool {
    !data.is_empty() && !is_text_like_filter_skip_candidate(data)
}

/// How many bytes the encoder will walk while packing this member.
///
/// Progress is reported by encoder position, and the filter search walks the
/// member several times over, so the reporter needs the total to scale by. The
/// screens this repeats are byte counting, cheap next to the encodes they are
/// predicting.
pub(super) fn filter_policy_walk_bytes(
    data: &[u8],
    policy: &FilterPolicy,
    encoder_candidates: usize,
) -> u64 {
    let member = data.len() as u64;
    let encoder_candidates = encoder_candidates.max(1) as u64;
    if *policy != FilterPolicy::Auto || !auto_size_filter_search_applies(data) {
        return member * encoder_candidates;
    }
    // The screens encode a sample once unfiltered and once per filter they are
    // deciding on. What survives them is not knowable without doing the work,
    // so this assumes one detectorless filter does: a progress bar that
    // finishes a little early or a little late is not worth a second search to
    // predict exactly.
    let sample = filter_screen_sample(data).len() as u64;
    let regions = x86_code_regions(data);
    let screen = sample * (SCREENED_FILTER_KINDS.len() as u64 + 1)
        + if regions.is_empty() { 0 } else { sample * 2 };
    let finalists = 1 + x86_filter_finalists(data, &regions).len() as u64 + 1;
    // Every finalist gets a whole-member encode, then the extra encoder
    // settings re-encode the winner.
    screen + member * (finalists + encoder_candidates - 1)
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_policy_candidates(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    candidates: &[EncodeOptions],
) -> Result<Vec<u8>> {
    let mut candidates = candidates.iter().copied();
    let first = candidates.next().ok_or(Error::InvalidHeader(
        "RAR 5 compression level has no encoder options",
    ))?;
    let mut best = encode_member_with_filter_policy(data, algorithm_version, policy, first)?;
    for options in candidates {
        let packed = encode_member_with_filter_policy(data, algorithm_version, policy, options)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

pub(super) fn should_store_compressed_payload(
    data: &[u8],
    packed: &[u8],
    solid: bool,
    policy: &FilterPolicy,
) -> bool {
    !solid && !matches!(policy, FilterPolicy::Explicit(_)) && packed.len() >= data.len()
}

#[cfg(test)]
pub(super) fn encode_with_solid_reset_policy(
    encoder: &mut Unpack50Encoder,
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    index: usize,
) -> Result<(Vec<u8>, bool)> {
    encode_with_solid_reset_policy_and_progress(
        encoder,
        data,
        algorithm_version,
        options,
        index,
        None,
    )
}

pub(super) fn encode_with_solid_reset_policy_and_progress(
    encoder: &mut Unpack50Encoder,
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    index: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<(Vec<u8>, bool)> {
    if index == 0 {
        let packed = if let Some(progress) = progress.as_deref_mut() {
            encoder
                .encode_member_with_progress(data, algorithm_version, progress)
                .map_err(Error::from)?
        } else {
            encoder
                .encode_member(data, algorithm_version)
                .map_err(Error::from)?
        };
        return Ok((packed, false));
    }

    let mut continued = encoder.clone();
    let continued_packed = if let Some(progress) = progress.as_deref_mut() {
        continued
            .encode_member_with_progress(data, algorithm_version, progress)
            .map_err(Error::from)?
    } else {
        continued
            .encode_member(data, algorithm_version)
            .map_err(Error::from)?
    };
    let mut fresh = Unpack50Encoder::with_options(options);
    let fresh_packed = if let Some(progress) = progress {
        fresh
            .encode_member_with_progress(data, algorithm_version, progress)
            .map_err(Error::from)?
    } else {
        fresh
            .encode_member(data, algorithm_version)
            .map_err(Error::from)?
    };
    if fresh_packed.len() < continued_packed.len() {
        *encoder = fresh;
        Ok((fresh_packed, false))
    } else {
        *encoder = continued;
        Ok((continued_packed, true))
    }
}

pub(super) fn encode_options_for_level(
    level: Option<u8>,
    dictionary_size: u64,
) -> Result<EncodeOptions> {
    let candidates = match level {
        None => MAX_MATCH_CANDIDATES_DEFAULT,
        Some(0) => 0,
        Some(1) => 8,
        Some(2) => 32,
        Some(3) => 64,
        Some(4) => 48,
        Some(5) => 64,
        Some(_) => {
            return Err(Error::InvalidHeader(
                "RAR 5 compression level must be in the range 0..5",
            ))
        }
    };
    let max_match_distance = usize::try_from(dictionary_size).map_err(|_| {
        Error::InvalidHeader("RAR 5 dictionary size exceeds this platform's address space")
    })?;
    Ok(EncodeOptions::new(candidates)
        .with_lazy_matching(matches!(level, None | Some(4..=5)))
        .with_lazy_lookahead(1)
        .with_max_match_distance(max_match_distance))
}

pub(super) fn encode_option_candidates_for_level(
    level: Option<u8>,
    dictionary_size: u64,
) -> Result<Vec<EncodeOptions>> {
    let mut candidates = vec![encode_options_for_level(level, dictionary_size)?];
    if matches!(level, Some(5)) {
        for fallback_level in (1..5).rev() {
            candidates.push(encode_options_for_level(
                Some(fallback_level),
                dictionary_size,
            )?);
        }
    }
    Ok(candidates)
}

pub(super) fn validate_compression_level(options: WriterOptions) -> Result<()> {
    compression_method_for_level(options.compression_level)?;
    let dictionary_size = dictionary_size_for_options(options)?;
    encode_options_for_level(options.compression_level, dictionary_size).map(|_| ())
}

pub(super) fn rar50_algorithm_version(options: WriterOptions) -> Result<u8> {
    match options.target {
        crate::ArchiveVersion::Rar50 => Ok(0),
        crate::ArchiveVersion::Rar70 => {
            let dictionary_size = dictionary_size_for_options(options)?;
            if dictionary_size_fields(0, dictionary_size).is_ok() {
                Ok(0)
            } else {
                Ok(1)
            }
        }
        _ => Err(Error::UnsupportedVersion(options.target)),
    }
}

pub(super) fn compression_method_for_level(level: Option<u8>) -> Result<u8> {
    match level {
        None => Ok(1),
        Some(level @ 0..=5) => Ok(level),
        Some(_) => Err(Error::InvalidHeader(
            "RAR 5 compression level must be in the range 0..5",
        )),
    }
}

pub(super) fn dictionary_size_for_options(options: WriterOptions) -> Result<u64> {
    let size = options
        .dictionary_size
        .unwrap_or(DEFAULT_RAR50_DICTIONARY_SIZE);
    validate_dictionary_size(options.target, size)?;
    Ok(size)
}

pub(super) fn validate_dictionary_size(target: crate::ArchiveVersion, size: u64) -> Result<()> {
    match target {
        crate::ArchiveVersion::Rar50 => dictionary_size_fields(0, size).map(|_| ()),
        crate::ArchiveVersion::Rar70 => dictionary_size_fields(0, size)
            .or_else(|_| dictionary_size_fields(1, size))
            .map(|_| ()),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

pub(super) fn dictionary_size_fields(algorithm_version: u8, size: u64) -> Result<(u8, u8)> {
    if size == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 dictionary size must be non-zero",
        ));
    }
    match algorithm_version {
        0 => {
            if size < DEFAULT_RAR50_DICTIONARY_SIZE {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size must be at least 128 KiB",
                ));
            }
            if !size.is_multiple_of(DEFAULT_RAR50_DICTIONARY_SIZE) {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
                ));
            }
            let multiple = size / DEFAULT_RAR50_DICTIONARY_SIZE;
            if !multiple.is_power_of_two() {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
                ));
            }
            let power = multiple.trailing_zeros();
            if power > 15 {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size exceeds 4 GiB",
                ));
            }
            Ok((power as u8, 0))
        }
        1 => {
            if !size.is_multiple_of(4096) {
                return Err(Error::InvalidHeader(
                    "RAR 7 dictionary size must be a multiple of 4 KiB",
                ));
            }
            let mut units = size / 4096;
            let mut power = 0u8;
            while units > 63 {
                if !units.is_multiple_of(2) || power == 31 {
                    return Err(Error::InvalidHeader(
                        "RAR 7 dictionary size is not encodable",
                    ));
                }
                units /= 2;
                power += 1;
            }
            if units < 32 {
                return Err(Error::InvalidHeader(
                    "RAR 7 dictionary size must be at least 128 KiB",
                ));
            }
            Ok((power, (units - 32) as u8))
        }
        _ => Err(Error::InvalidHeader(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}

pub(super) fn compression_info(
    algorithm_version: u8,
    method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
) -> Result<u64> {
    let (dictionary_power, dictionary_fraction) =
        dictionary_size_fields(algorithm_version, dictionary_size)?;
    Ok(u64::from(algorithm_version)
        | (u64::from(method) << 7)
        | (u64::from(dictionary_power) << 10)
        | (u64::from(dictionary_fraction) << 15)
        | solid_compression_flag(solid_continuation))
}

pub(super) fn encode_safe_lz_member(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_with_options(data, algorithm_version, options).map_err(Error::from)
}

pub(super) fn encode_safe_lz_member_with_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_lz_member_with_options_and_progress(data, algorithm_version, options, progress)
        .map_err(Error::from)
}

#[cfg(test)]
pub(super) fn encode_member_with_auto_size_filter(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_auto_size_filter_progress(data, algorithm_version, options, None)
}

/// How much of the member the screens encode when deciding whether a filter is
/// worth a whole-member encode.
const FILTER_SCREEN_SAMPLE_LEN: usize = 128 * 1024;

/// Keeps the screen sample's delta planes aligned the way they fall in the
/// whole member: the lowest common multiple of the delta widths tried.
const FILTER_SCREEN_SAMPLE_ALIGNMENT: usize = 12;

/// How much smaller a filter has to make the sample before it earns a
/// whole-member encode, as a percentage.
///
/// A filter that pays off does so by a mile: delta on 16-bit audio takes 43% off
/// and on interleaved counters 96%. A sample that comes out a fraction of a
/// percent smaller is measurement noise from the shorter history, and chasing it
/// costs a whole-member encode per filter to find out.
const FILTER_SCREEN_MARGIN_PERCENT: usize = 1;

fn filter_screen_wins(filtered: usize, baseline: usize) -> bool {
    filtered * 100 < baseline * (100 - FILTER_SCREEN_MARGIN_PERCENT)
}

/// The filters with no detector of their own, so they have to be measured.
const SCREENED_FILTER_KINDS: [FilterKind; 5] = [
    FilterKind::Arm,
    FilterKind::Delta { channels: 1 },
    FilterKind::Delta { channels: 2 },
    FilterKind::Delta { channels: 3 },
    FilterKind::Delta { channels: 4 },
];

/// How much of the member x86 detection has to cover before filtering the whole
/// thing is as good as filtering only the detected regions, as a fraction.
const X86_CODE_COVERAGE_RATIO: (usize, usize) = (9, 10);

/// A window from the middle of the member, used to screen the filters that have
/// nothing but a trial encode to go on.
fn filter_screen_sample(data: &[u8]) -> &[u8] {
    if data.len() <= FILTER_SCREEN_SAMPLE_LEN {
        return data;
    }
    let middle = (data.len() - FILTER_SCREEN_SAMPLE_LEN) / 2;
    let start = middle / FILTER_SCREEN_SAMPLE_ALIGNMENT * FILTER_SCREEN_SAMPLE_ALIGNMENT;
    &data[start..start + FILTER_SCREEN_SAMPLE_LEN]
}

/// Which of the detectorless filters shrink a sample of the member.
///
/// Delta and ARM used to cost a whole-member encode each to prove they made the
/// member bigger, which on a binary is most of the search. Whether they help is
/// a local property of the byte layout, so a slice of the member answers it for
/// a few per cent of the price. This measures the real filter rather than a
/// statistic standing in for it, because the wins do not all show up as
/// entropy: RAR's delta reorders into planes first, and what that buys is
/// repetition the encoder can match, not a flatter byte histogram.
fn screened_filter_kinds(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<ScreenOutcome> {
    let sample = filter_screen_sample(data);
    let mut outcome = ScreenOutcome::default();
    if sample.len() < FILTER_SCREEN_SAMPLE_ALIGNMENT {
        return Ok(outcome);
    }
    // A member no bigger than the sample is the sample, so the screen's encodes
    // are whole-member measurements and the search should keep them rather than
    // repeat them.
    let whole_member = sample.len() == data.len();
    let baseline =
        encode_member_with_filter_specs_progress(sample, algorithm_version, &[], options, None)
            .map_err(Error::from)?;
    for kind in SCREENED_FILTER_KINDS {
        let packed = encode_member_with_filter_specs_progress(
            sample,
            algorithm_version,
            &[FilterSpec::whole(kind)],
            options,
            None,
        )
        .map_err(Error::from)?;
        if filter_screen_wins(packed.len(), baseline.len()) {
            outcome.kinds.push((kind, whole_member.then_some(packed)));
        }
    }
    if whole_member {
        outcome.plain = Some(baseline);
    }
    Ok(outcome)
}

/// What the screen learned, along with any encodes the search can reuse.
#[derive(Default)]
struct ScreenOutcome {
    kinds: Vec<(FilterKind, Option<Vec<u8>>)>,
    plain: Option<Vec<u8>>,
}

/// Where the scanner thinks x86 code lives, merged into disjoint regions.
fn x86_code_regions(data: &[u8]) -> Vec<std::ops::Range<usize>> {
    disjoint_filter_ranges(auto_x86_filter_ranges(data, true))
}

/// Whether the x86 filter earns its keep on a slice of what the scanner called
/// code.
///
/// Byte patterns that look like call opcodes turn up in compressed data by
/// chance, and the scanner cannot tell those from a real code section. Trying
/// the filter inside the largest region it found separates the two for the price
/// of a sample encode instead of two whole-member ones.
fn x86_filter_helps_sample(
    data: &[u8],
    regions: &[std::ops::Range<usize>],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<bool> {
    let Some(largest) = regions.iter().max_by_key(|range| range.len()) else {
        return Ok(false);
    };
    let sample = filter_screen_sample(&data[largest.clone()]);
    if sample.len() < FILTER_SCREEN_SAMPLE_ALIGNMENT {
        return Ok(false);
    }
    let baseline =
        encode_member_with_filter_specs_progress(sample, algorithm_version, &[], options, None)
            .map_err(Error::from)?;
    let filtered = encode_member_with_filter_specs_progress(
        sample,
        algorithm_version,
        &[FilterSpec::whole(FilterKind::E8E9)],
        options,
        None,
    )
    .map_err(Error::from)?;
    // No margin here, unlike the detectorless filters: the scanner has already
    // ruled on where code is, so a small win on this sample is evidence rather
    // than noise.
    Ok(filtered.len() < baseline.len())
}

/// The x86 filter specs worth measuring against the whole member.
///
/// The scanner proposes overlapping regions at several clustering distances,
/// and the old search priced every one of them with its own whole-member
/// encode. Measured at full effort the whole spread is worth about a third of a
/// percent, so this keeps the two that are structurally different: filter
/// everything, or filter only where the scanner saw code. The second is only
/// worth an encode when there is enough non-code to protect.
fn x86_filter_finalists(data: &[u8], regions: &[std::ops::Range<usize>]) -> Vec<Vec<FilterSpec>> {
    let covered: usize = regions.iter().map(|range| range.len()).sum();
    let (numerator, denominator) = X86_CODE_COVERAGE_RATIO;
    let sparse = covered * denominator < data.len() * numerator;

    let mut finalists = Vec::new();
    for kind in [FilterKind::E8E9, FilterKind::E8] {
        finalists.push(vec![FilterSpec::whole(kind)]);
        if sparse {
            finalists.push(
                regions
                    .iter()
                    .map(|range| FilterSpec::range(kind, range.clone()))
                    .collect(),
            );
        }
    }
    finalists
}

/// The filter specs worth measuring against the whole member, paired with the
/// bytes for any the screen already measured.
///
/// Everything expensive happens downstream of this, one whole-member encode per
/// unmeasured finalist, so the job here is to hand back a handful rather than
/// the several dozen the scanner and the delta widths can between them suggest.
#[allow(clippy::type_complexity)]
fn auto_size_filter_finalists(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<(Vec<FilterSpec>, Option<Vec<u8>>)>> {
    let screen = screened_filter_kinds(data, algorithm_version, options)?;
    let mut finalists = vec![(Vec::new(), screen.plain)];

    let regions = x86_code_regions(data);
    if x86_filter_helps_sample(data, &regions, algorithm_version, options)? {
        finalists.extend(
            x86_filter_finalists(data, &regions)
                .into_iter()
                .map(|specs| (specs, None)),
        );
    }

    for (kind, packed) in screen.kinds {
        finalists.push((vec![FilterSpec::whole(kind)], packed));
        if let FilterKind::Delta { channels } = kind {
            if let Some(range) = auto_delta_filter_range(data, channels) {
                finalists.push((vec![FilterSpec::range(kind, range)], None));
            }
        }
    }

    Ok(finalists)
}

/// Picks the filter for a member, returning the winning specs together with the
/// bytes they produced so the caller does not have to encode the winner again.
///
/// Which filter suits a member is a property of the data, not of how hard the
/// encoder is trying, so this is worth doing once even when several encoder
/// settings are going to be compared afterwards.
///
/// Every finalist is measured at the caller's own encoder settings and the
/// unfiltered member is always one of them, so the result can never be larger
/// than leaving the data alone.
fn choose_auto_size_filter(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<(Vec<FilterSpec>, Vec<u8>)> {
    let mut best: Option<(Vec<FilterSpec>, Vec<u8>)> = None;
    for (specs, measured) in auto_size_filter_finalists(data, algorithm_version, options)? {
        let packed = match measured {
            Some(packed) => packed,
            None => encode_member_with_filter_specs_progress(
                data,
                algorithm_version,
                &specs,
                options,
                borrow_progress(&mut progress),
            )
            .map_err(Error::from)?,
        };
        if best
            .as_ref()
            .is_none_or(|(_, best): &(_, Vec<u8>)| packed.len() < best.len())
        {
            best = Some((specs, packed));
        }
    }
    Ok(best.expect("the unfiltered member is always a finalist"))
}

fn encode_member_with_auto_size_filter_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    if !auto_size_filter_search_applies(data) {
        return encode_member_with_filter_policy_and_progress(
            data,
            algorithm_version,
            &FilterPolicy::None,
            options,
            progress,
        );
    }
    let (_, packed) = choose_auto_size_filter(data, algorithm_version, options, progress)?;
    Ok(packed)
}

fn is_text_like_filter_skip_candidate(data: &[u8]) -> bool {
    let sample_len = data.len().min(8192);
    if sample_len == 0 {
        return false;
    }
    let sample = &data[..sample_len];
    let text_bytes = sample
        .iter()
        .filter(|&&byte| matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    text_bytes * 100 / sample_len >= 95
}

pub(super) fn auto_delta_filter_range(
    data: &[u8],
    channels: usize,
) -> Option<std::ops::Range<usize>> {
    if channels == 0 || data.len() <= AUTO_DELTA_EDGE_SKIP * 2 + channels * 8 {
        return None;
    }
    let start = AUTO_DELTA_EDGE_SKIP;
    let end = data.len() - AUTO_DELTA_EDGE_SKIP;
    let aligned_start = start + ((channels - start % channels) % channels);
    let aligned_end = end - (end - aligned_start) % channels;
    (aligned_start + channels * 8 <= aligned_end).then_some(aligned_start..aligned_end)
}

pub(super) fn disjoint_filter_ranges(
    mut ranges: Vec<std::ops::Range<usize>>,
) -> Vec<std::ops::Range<usize>> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut disjoint: Vec<std::ops::Range<usize>> = Vec::new();
    for range in ranges {
        if let Some(last) = disjoint.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        disjoint.push(range);
    }
    disjoint
}

fn encode_member_with_filter_specs_progress(
    data: &[u8],
    algorithm_version: u8,
    filters: &[FilterSpec],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> crate::codec::Result<Vec<u8>> {
    // Carrying filters forces shorter blocks, so encoding no filters through
    // the filter path would not produce what asking for no filter produces.
    // The search compares candidates against leaving the data alone, and that
    // has to mean the bytes it would really emit.
    if filters.is_empty() {
        return match progress {
            Some(progress) => encode_lz_member_with_options_and_progress(
                data,
                algorithm_version,
                options,
                progress,
            ),
            None => encode_lz_member_with_options(data, algorithm_version, options),
        };
    }
    let mut encoder = Unpack50Encoder::with_options(options);
    match progress {
        Some(progress) => encoder.encode_member_with_filters_and_progress(
            data,
            algorithm_version,
            filters,
            progress,
        ),
        None => encoder.encode_member_with_filters(data, algorithm_version, filters),
    }
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_spec(
    data: &[u8],
    algorithm_version: u8,
    filter: FilterSpec,
    options: EncodeOptions,
) -> crate::codec::Result<Vec<u8>> {
    Unpack50Encoder::with_options(options).encode_member_with_filter(
        data,
        algorithm_version,
        filter,
    )
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_specs(
    data: &[u8],
    algorithm_version: u8,
    filters: &[FilterSpec],
    options: EncodeOptions,
) -> crate::codec::Result<Vec<u8>> {
    Unpack50Encoder::with_options(options).encode_member_with_filters(
        data,
        algorithm_version,
        filters,
    )
}

pub(super) fn solid_compression_flag(solid_continuation: bool) -> u64 {
    if solid_continuation {
        0x40
    } else {
        0
    }
}

#[cfg(test)]
mod screen_tests {
    use super::*;

    fn options() -> EncodeOptions {
        encode_options_for_level(None, 128 * 1024).unwrap()
    }

    /// Interleaved counters: RAR's delta reorders them into planes of near
    /// constants, which is a huge win the byte histogram cannot see.
    fn interleaved_counters() -> Vec<u8> {
        let mut data = Vec::new();
        for index in 0..20_000u32 {
            data.push(0xe8);
            data.extend_from_slice(&index.to_le_bytes());
            data.extend_from_slice(b"\x55\x89\xe5");
        }
        data
    }

    #[test]
    fn screen_keeps_a_delta_width_that_pays_off() {
        let data = interleaved_counters();
        let kinds: Vec<_> = screened_filter_kinds(&data, 0, options())
            .unwrap()
            .kinds
            .into_iter()
            .map(|(kind, _)| kind)
            .collect();
        assert!(
            kinds.contains(&FilterKind::Delta { channels: 4 }),
            "delta 4 turns this into planes of constants, so it has to survive: {kinds:?}"
        );
    }

    #[test]
    fn screen_rejects_filters_on_incompressible_data() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let data: Vec<u8> = std::iter::repeat_with(|| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .take(400_000)
        .collect();
        assert!(
            screened_filter_kinds(&data, 0, options())
                .unwrap()
                .kinds
                .is_empty(),
            "nothing helps random bytes, and finding that out must not cost whole-member encodes"
        );
    }

    #[test]
    fn a_short_member_reuses_the_screens_encodes() {
        let data = interleaved_counters()[..100_000].to_vec();
        assert!(data.len() <= FILTER_SCREEN_SAMPLE_LEN);
        let screen = screened_filter_kinds(&data, 0, options()).unwrap();
        assert!(screen.plain.is_some(), "the unfiltered encode is reusable");
        assert!(
            screen.kinds.iter().all(|(_, packed)| packed.is_some()),
            "so is every survivor's"
        );
    }

    #[test]
    fn the_search_never_loses_to_no_filter() {
        for data in [
            interleaved_counters(),
            b"the quick brown fox ".repeat(20_000),
            (0..300_000u32).map(|index| (index / 3) as u8).collect(),
        ] {
            let plain = encode_safe_lz_member(&data, 0, options()).unwrap();
            let (specs, packed) = choose_auto_size_filter(&data, 0, options(), None).unwrap();
            assert!(
                packed.len() <= plain.len(),
                "{specs:?} came out at {} against {} unfiltered",
                packed.len(),
                plain.len()
            );
        }
    }

    #[test]
    fn the_screen_sample_sits_in_the_middle_and_keeps_delta_planes_aligned() {
        let data = vec![0u8; 5 * FILTER_SCREEN_SAMPLE_LEN + 7];
        let sample = filter_screen_sample(&data);
        assert_eq!(sample.len(), FILTER_SCREEN_SAMPLE_LEN);
        let start = sample.as_ptr() as usize - data.as_ptr() as usize;
        assert_eq!(start % FILTER_SCREEN_SAMPLE_ALIGNMENT, 0);
        assert!(start > 0 && start + sample.len() < data.len());
    }
}
