use super::*;
use crate::codec::rar50::{
    encode_lz_member_with_options, encode_lz_member_with_options_and_progress, EncodeOptions,
    Unpack50Encoder,
};

fn borrow_progress<'a>(
    progress: &'a mut Option<&mut dyn FnMut(usize) -> bool>,
) -> Option<&'a mut dyn FnMut(usize) -> bool> {
    match progress {
        Some(report) => Some(&mut **report),
        None => None,
    }
}

pub(super) fn encode_member_with_filter_policy_and_progress(
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

use crate::filter_search::search_applies as auto_size_filter_search_applies;

/// How many bytes the encoder will walk while packing this member, for progress
/// to scale by.
pub(super) fn filter_policy_walk_bytes(
    data: &[u8],
    policy: &FilterPolicy,
    algorithm_version: u8,
    encoder_candidates: usize,
) -> u64 {
    let member = data.len() as u64;
    if *policy != FilterPolicy::Auto || !auto_size_filter_search_applies(data) {
        return member * encoder_candidates.max(1) as u64;
    }
    crate::filter_search::walk_bytes(&Rar50Search { algorithm_version }, data, encoder_candidates)
}

/// Whether a member compression did not help is better off stored.
///
/// Takes lengths rather than the bytes, because the streaming path decides this
/// for a payload it has already spilled to disk.
pub(super) fn should_store_compressed_payload(
    unpacked: u64,
    packed: u64,
    solid: bool,
    policy: &FilterPolicy,
) -> bool {
    // A solid member is decoded against the dictionary the members before it
    // filled, so this writer can never go back and store one.
    crate::write_plan::StoreFallback::new()
        .filter_requested(matches!(policy, FilterPolicy::Explicit(_)))
        .applies(solid, unpacked as usize, packed as usize)
}

/// How hard each level looks for a match, and where the default sits.
///
/// The ladder used to run 8, 32, 64, 48, 64 with the absent level on 256, so
/// asking for the most compression got you less of it than asking for nothing:
/// `--level 5` searched 64 positions where the default searched 256, and level
/// 4 searched fewer than level 3. On 4 MiB of man pages the default packed
/// 679,368 bytes and `--level 5` packed 691,274.
///
/// Measured on that member, packed bytes against seconds, at lookahead 2:
///
/// ```text
/// candidates     64     128     256     512    1024
/// packed     686,891 680,315 675,746 672,645 670,061
/// seconds       1.67    2.35    3.53    4.71    6.65
/// ```
///
/// It flattens out: the last doubling buys 0.4% for another two seconds. So
/// the top of the ladder sits at 512 rather than chasing it, and level 3 stays
/// near what the default already cost.
fn match_candidates_for_level(level: u8) -> Result<usize> {
    match level {
        0 => Ok(0),
        1 => Ok(8),
        2 => Ok(32),
        3 => Ok(128),
        4 => Ok(256),
        5 => Ok(512),
        _ => Err(Error::InvalidHeader(
            "RAR 5 compression level must be in the range 0..5",
        )),
    }
}

/// The level an absent `--level` means. Resolved once, so the effort spent, the
/// method byte written and the fallback ladder cannot disagree about it.
pub(super) const RAR50_DEFAULT_LEVEL: u8 = 3;

pub(super) fn resolved_level(level: Option<u8>) -> u8 {
    level.unwrap_or(RAR50_DEFAULT_LEVEL)
}

pub(super) fn encode_options_for_level(
    level: Option<u8>,
    dictionary_size: u64,
) -> Result<EncodeOptions> {
    let level = resolved_level(level);
    let candidates = match_candidates_for_level(level)?;
    let max_match_distance = usize::try_from(dictionary_size).map_err(|_| {
        Error::InvalidHeader("RAR 5 dictionary size exceeds this platform's address space")
    })?;
    Ok(EncodeOptions::new(candidates)
        // Looking one byte further ahead before settling for the match at hand
        // is both smaller and quicker than not: at 64 candidates it took 4,383
        // bytes off that member and half a second off the encode, because a
        // longer match covers ground the finder then does not have to search.
        // Four is worse than one, which is its own question (#83).
        .with_lazy_matching(level >= 3)
        .with_lazy_lookahead(2)
        // Pricing the whole block and keeping the cheapest path takes 2.4% off
        // a stripped ELF and 4.3% off manpage text against lazy matching at the
        // same search depth, and costs six times the time. That trade belongs
        // at the top of the ladder and nowhere else: level 3 is the default.
        .with_optimal_parse(level >= 5)
        .with_max_match_distance(max_match_distance))
}

pub(super) fn encode_option_candidates_for_level(
    level: Option<u8>,
    dictionary_size: u64,
) -> Result<Vec<EncodeOptions>> {
    let mut candidates = vec![encode_options_for_level(level, dictionary_size)?];
    if resolved_level(level) == 5 {
        for fallback_level in (1..5).rev() {
            candidates.push(encode_options_for_level(
                Some(fallback_level),
                dictionary_size,
            )?);
        }
    }
    Ok(candidates)
}

pub(super) fn rar50_algorithm_version(options: WriterOptions, dictionary_size: u64) -> Result<u8> {
    match options.target {
        crate::ArchiveVersion::Rar50 => Ok(0),
        crate::ArchiveVersion::Rar70 => {
            if dictionary_size_fields(0, dictionary_size).is_ok() {
                Ok(0)
            } else {
                Ok(1)
            }
        }
        _ => Err(Error::UnsupportedVersion(options.target)),
    }
}

/// The level written into the member header.
///
/// It is the resolved level, so an archive says what it was compressed at. An
/// absent level used to write 1 while spending more search than `--level 5`
/// did, which described neither what was asked for nor what was done.
pub(super) fn compression_method_for_level(level: Option<u8>) -> Result<u8> {
    let level = resolved_level(level);
    match_candidates_for_level(level)?;
    Ok(level)
}

/// The largest dictionary the writer picks on its own at each level.
///
/// The format goes far higher and `--dict-size` still does. What stops the
/// writer reaching for it is that the hash chains lengthen with the window, so
/// a wider one costs time that is not always repaid. How often it is repaid
/// depends entirely on the data. Over 16 MiB of manpage text and 16 MiB of
/// shared libraries at level 3:
///
///     dictionary       text     seconds        binary     seconds
///          1 MiB  3,480,749         6.6     4,646,481        14.1
///          2 MiB  2,223,009         8.1     4,590,488        25.3
///          4 MiB  2,061,307        14.8     4,514,109        53.0
///          8 MiB  2,043,138        21.7     4,505,410        83.2
///         16 MiB  2,040,730        27.6     4,507,232       105.0
///
/// A 1 MiB cap costs text 41% and buys binaries most of their speed. One
/// number cannot serve both, so the level picks, which is what a level is for.
/// Text keeps paying up to about 8 MiB; binaries stop at 4 and are slightly
/// worse by 16.
fn fitted_dictionary_cap(level: u8) -> u64 {
    let megabytes = match level {
        0..=2 => 1,
        3 => 4,
        4 => 8,
        _ => 16,
    };
    megabytes * 1024 * 1024
}

/// The smallest dictionary that still reaches past `content`.
///
/// A window larger than the data cannot match anything extra, so a small member
/// keeps a small window and stays as quick as it was. Sizes are the format's
/// own: 128 KiB doubled.
pub(super) fn fitted_dictionary_size(content: u64, level: u8) -> u64 {
    let cap = fitted_dictionary_cap(level);
    let mut size = DEFAULT_RAR50_DICTIONARY_SIZE;
    while size < cap && size <= content {
        size *= 2;
    }
    size
}

/// The dictionary to write with, either the caller's or one fitted to the data.
///
/// `content` is what one window has to reach across: the whole archive when the
/// members share a dictionary, otherwise the largest member. `memory_limit` is
/// the workspace budget the write has to stay inside.
///
/// A dictionary the caller named is validated and used as given: if it does not
/// fit the budget the write fails saying so, which is the answer to a request
/// that cannot be met. A fitted one is shrunk to fit instead, because it has no
/// business failing a write that the smaller default would have finished.
pub(super) fn dictionary_size_for_options(
    options: WriterOptions,
    content: u64,
    memory_limit: u64,
) -> Result<u64> {
    let size = match options.dictionary_size {
        Some(size) => size,
        None => {
            let mut fitted =
                fitted_dictionary_size(content, resolved_level(options.compression_level));
            while fitted > DEFAULT_RAR50_DICTIONARY_SIZE
                && super::streaming_lz_workspace(fitted, crate::codec::rar50::LZ_BLOCK_SIZE)
                    > memory_limit
            {
                fitted /= 2;
            }
            fitted
        }
    };
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

/// How RAR 5 measures a filter candidate, for the shared search.
#[derive(Clone, Copy)]
pub(crate) struct Rar50Search {
    pub(crate) algorithm_version: u8,
}

impl crate::filter_search::FilterSearch for Rar50Search {
    type Options = EncodeOptions;

    fn screened_kinds(&self, _data: &[u8]) -> Vec<FilterKind> {
        vec![
            FilterKind::Arm,
            FilterKind::Delta { channels: 1 },
            FilterKind::Delta { channels: 2 },
            FilterKind::Delta { channels: 3 },
            FilterKind::Delta { channels: 4 },
        ]
    }

    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Vec<u8>> {
        crate::codec::rar50::filtered_lz_member(data, filters)
            .map(|(filtered, _)| filtered)
            .map_err(Error::from)
    }

    /// Screens rank filters against each other, and the optimal parse costs six
    /// encodes' worth of time to sharpen a ranking that the same parse on both
    /// sides already gets right. Everything else about the settings stays, so a
    /// screen still measures what the writer will do.
    fn screen_options(&self, options: EncodeOptions) -> EncodeOptions {
        options.with_optimal_parse(false)
    }

    fn encode_plain(
        &self,
        data: &[u8],
        options: EncodeOptions,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        match progress {
            Some(progress) => encode_lz_member_with_options_and_progress(
                data,
                self.algorithm_version,
                options,
                progress,
            ),
            None => encode_lz_member_with_options(data, self.algorithm_version, options),
        }
        .map_err(Error::from)
    }

    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: EncodeOptions,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        let mut encoder = Unpack50Encoder::with_options(options);
        match progress {
            Some(progress) => encoder.encode_member_with_filters_and_progress(
                data,
                self.algorithm_version,
                filters,
                progress,
            ),
            None => encoder.encode_member_with_filters(data, self.algorithm_version, filters),
        }
        .map_err(Error::from)
    }
}

fn choose_auto_size_filter(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<(Vec<FilterSpec>, Vec<u8>)> {
    crate::filter_search::choose_filter(&Rar50Search { algorithm_version }, data, options, progress)
}

pub(super) fn encode_member_with_auto_size_filter_progress(
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

pub(super) fn solid_compression_flag(solid_continuation: bool) -> u64 {
    if solid_continuation {
        0x40
    } else {
        0
    }
}
