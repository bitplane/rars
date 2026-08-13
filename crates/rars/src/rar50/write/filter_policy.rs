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

/// How RAR 5 measures a filter candidate, for the shared search.
#[derive(Clone, Copy)]
struct Rar50Search {
    algorithm_version: u8,
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
