use super::plan::filter_search_bytes;
use super::*;
use crate::codec::rar50::EncodeOptions;
#[cfg(test)]
use crate::codec::rar50::{
    encode_lz_member_with_options, encode_lz_member_with_options_and_progress, Unpack50Encoder,
};
#[cfg(test)]
use crate::codec::workspace::Allowance;
use crate::codec::workspace::{Budget, Buffer};
use crate::filter_search::{encode_pass, EncodeProgress, OwnedSearch};

fn borrow_progress<'a>(
    progress: &'a mut Option<&mut dyn FnMut(EncodeProgress) -> bool>,
) -> Option<&'a mut dyn FnMut(EncodeProgress) -> bool> {
    match progress {
        Some(report) => Some(&mut **report),
        None => None,
    }
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_policy_and_progress(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
) -> Result<Vec<u8>> {
    policy_with_allowance(
        data,
        algorithm_version,
        policy,
        options,
        progress,
        &Allowance::default(),
    )
    .map(Buffer::into_vec)
}
#[cfg(test)]
pub(super) fn encode_member_with_filter_policy_candidates_and_progress(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    candidates: &[EncodeOptions],
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
) -> Result<Vec<u8>> {
    candidates_with_allowance(
        data,
        algorithm_version,
        policy,
        candidates,
        progress,
        &Allowance::default(),
    )
    .map(Buffer::into_vec)
}
pub(super) fn candidates_with_allowance<B: Budget>(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    candidates: &[EncodeOptions],
    mut progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let mut remaining = candidates.iter().copied();
    let first = remaining.next().ok_or(Error::WriterFailure(
        "RAR 5 compression level has no encoder options",
    ))?;

    // Searching for a filter once and then trying the encoder settings against
    // it is the difference between a handful of passes over the member and one
    // whole search per setting.
    if *policy == FilterPolicy::Auto && auto_size_filter_search_applies(data) {
        let (specs, mut best) = choose_owned_filter(
            data,
            algorithm_version,
            first,
            borrow_progress(&mut progress),
            allowance,
        )?;
        // The search already encoded the winner at the first setting, so only
        // the remaining settings are left to try.
        for options in remaining {
            let packed = specs_with_allowance(
                data,
                algorithm_version,
                &specs,
                options,
                borrow_progress(&mut progress),
                allowance,
            )?;
            if packed.len() < best.len() {
                best = packed;
            }
        }
        return Ok(best);
    }

    let mut best = policy_with_allowance(
        data,
        algorithm_version,
        policy,
        first,
        borrow_progress(&mut progress),
        allowance,
    )?;
    for options in remaining {
        let packed = policy_with_allowance(
            data,
            algorithm_version,
            policy,
            options,
            borrow_progress(&mut progress),
            allowance,
        )?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

use crate::filter_search::search_applies_throughout as auto_size_filter_search_applies;

/// How many bytes the encoder will walk while packing this member, for progress
/// to scale by.
///
/// A search that judges by statistics (see [`estimated_search`]) encodes next
/// to nothing on the way, so only the member's own encodes count.
pub(super) fn filter_policy_walk_bytes(
    data: &[u8],
    policy: &FilterPolicy,
    _algorithm_version: u8,
    candidates: &[EncodeOptions],
) -> u64 {
    let member = data.len() as u64;
    let encoder_candidates = candidates.len();
    if *policy != FilterPolicy::Auto
        || !auto_size_filter_search_applies(data)
        || candidates.first().is_some_and(|&options| estimated_search(options))
    {
        return member * encoder_candidates.max(1) as u64;
    }
    crate::filter_search::walk_bytes_for_kinds(
        data,
        SCREENED_KINDS.len() as u64,
        encoder_candidates,
    )
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
        .applies(solid, unpacked, packed)
}

/// How hard each level looks for a match, and where the default sits.
///
/// Each rung packs smaller than the one below. Level 3 is the default because
/// it is the knee. Level 5 searches filters exhaustively, which is most of what
/// it costs over level 4, and its 16 MiB window is most of what it buys.
fn match_candidates_for_level(level: u8) -> Result<usize> {
    match level {
        0 => Ok(0),
        1 => Ok(8),
        2 => Ok(16),
        3 => Ok(32),
        4 => Ok(128),
        5 => Ok(512),
        _ => Err(Error::InvalidArgument(
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
        Error::InvalidArgument("RAR 5 dictionary size exceeds this platform's address space")
    })?;
    Ok(EncodeOptions::new(candidates)
        // Looking a byte or two further ahead before settling for the match at
        // hand is what level 1 parses with; the levels above it parse by
        // shortest path and never ask. A lookahead of four is worse than one.
        //
        // A deeper lazy rung between levels 1 and 2 loses to the shortest-path
        // parse at a shallow search: chains over a 4 MiB window cost the lazy
        // parse more than the tree costs the shortest-path one.
        .with_lazy_matching(level >= 1)
        .with_lazy_lookahead(2)
        // Everything above level 1 parses by shortest path. Search depth is
        // worth far less than the parse, so there is no setting of the other
        // knobs that makes a greedy rung competitive. What the depth still buys
        // is the ordering: at 32, 128, 256 and 512 candidates the parse packs
        // steadily smaller for steadily more time, which is what a level is.
        //
        // Level 1 keeps the lazy parse. It is the rung that exists to be quick,
        // and it is the only place left to go when the shortest-path parse is
        // too slow for the job.
        .with_optimal_parse(level >= 2)
        .with_nice_match_length(parse_effort_for_level(level).0)
        .with_parse_passes(parse_effort_for_level(level).1)
        .with_max_match_distance(max_match_distance))
}

/// The nice match length and parse passes for a level.
///
/// Search depth alone barely separates the parsing levels on a member that
/// fits one window. These two are what does. A single pass at level 2 parses
/// each block once, on guessed prices, rather than again on the prices the
/// pass before produced.
fn parse_effort_for_level(level: u8) -> (usize, usize) {
    match level {
        2 => (32, 1),
        3 => (64, 2),
        4 => (256, 3),
        5.. => (1024, 6),
        _ => (512, 3),
    }
}

/// The encoder settings to try for a level, smallest output kept.
///
/// Just one. The list stays for a setting that competes on something other than
/// search depth.
pub(super) fn encode_option_candidates_for_level(
    level: Option<u8>,
    dictionary_size: u64,
) -> Result<[EncodeOptions; 1]> {
    Ok([encode_options_for_level(level, dictionary_size)?])
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
/// It is the resolved level, so an archive says what it was compressed at.
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
/// depends entirely on the data.
///
/// A 1 MiB cap costs text and buys binaries most of their speed. One number
/// cannot serve both, so the level picks, which is what a level is for. Text
/// keeps paying up to about 8 MiB; binaries stop at 4 and are slightly worse by
/// 16.
///
/// Level 2 sits between.
fn fitted_dictionary_cap(level: u8) -> u64 {
    let megabytes = match level {
        0..=1 => 1,
        2 => 2,
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
            let level = resolved_level(options.compression_level);
            let mut fitted = fitted_dictionary_size(content, level);
            while fitted > DEFAULT_RAR50_DICTIONARY_SIZE
                && fitted_dictionary_workspace(level, fitted)? > memory_limit
            {
                fitted /= 2;
            }
            fitted
        }
    };
    validate_dictionary_size(options.target, size)?;
    Ok(size)
}

/// Reserve for a full block job, including room for per-run filters.
pub(super) fn fitted_dictionary_workspace(level: u8, dictionary: u64) -> Result<u64> {
    let options = encode_options_for_level(Some(level), dictionary)?;
    let code = if options.optimal_parse {
        super::streaming_lz_workspace(dictionary, crate::codec::rar50::MAX_LZ_BLOCK_SIZE, true)
    } else {
        super::plan::lazy_streaming_workspace(options, u64::MAX)
    };
    Ok(super::plan::block_admission(code, options, u64::MAX, true))
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
        return Err(Error::InvalidArgument(
            "RAR 5 dictionary size must be non-zero",
        ));
    }
    match algorithm_version {
        0 => {
            if size < DEFAULT_RAR50_DICTIONARY_SIZE {
                return Err(Error::InvalidArgument(
                    "RAR 5 v0 dictionary size must be at least 128 KiB",
                ));
            }
            if !size.is_multiple_of(DEFAULT_RAR50_DICTIONARY_SIZE) {
                return Err(Error::InvalidArgument(
                    "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
                ));
            }
            let multiple = size / DEFAULT_RAR50_DICTIONARY_SIZE;
            if !multiple.is_power_of_two() {
                return Err(Error::InvalidArgument(
                    "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
                ));
            }
            let power = multiple.trailing_zeros();
            if power > 15 {
                return Err(Error::InvalidArgument(
                    "RAR 5 v0 dictionary size exceeds 4 GiB",
                ));
            }
            Ok((power as u8, 0))
        }
        1 => {
            if !size.is_multiple_of(4096) {
                return Err(Error::InvalidArgument(
                    "RAR 7 dictionary size must be a multiple of 4 KiB",
                ));
            }
            let mut units = size / 4096;
            let mut power = 0u8;
            while units > 63 {
                if !units.is_multiple_of(2) || power == 31 {
                    return Err(Error::InvalidArgument(
                        "RAR 7 dictionary size is not encodable",
                    ));
                }
                units /= 2;
                power += 1;
            }
            if units < 32 {
                return Err(Error::InvalidArgument(
                    "RAR 7 dictionary size must be at least 128 KiB",
                ));
            }
            Ok((power, (units - 32) as u8))
        }
        _ => Err(Error::InvalidArgument(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}

#[cfg(test)]
mod dictionary_encoding_tests {
    use super::*;

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn encode_options_refuse_a_valid_dictionary_above_the_host_limit() {
        let size = 1u64 << 32;
        assert_eq!(dictionary_size_fields(0, size).unwrap(), (15, 0));
        assert_eq!(
            encode_options_for_level(Some(3), size).unwrap_err(),
            Error::InvalidArgument("RAR 5 dictionary size exceeds this platform's address space")
        );
    }

    #[test]
    fn rar5_dictionary_boundaries_and_rejections() {
        let unit = DEFAULT_RAR50_DICTIONARY_SIZE;
        assert_eq!(dictionary_size_fields(0, unit).unwrap(), (0, 0));
        assert_eq!(dictionary_size_fields(0, 1u64 << 32).unwrap(), (15, 0));
        for (size, reason) in [
            (
                unit - 1,
                "RAR 5 v0 dictionary size must be at least 128 KiB",
            ),
            (
                unit + 4096,
                "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
            ),
            (
                unit * 3,
                "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
            ),
            (1u64 << 33, "RAR 5 v0 dictionary size exceeds 4 GiB"),
        ] {
            assert_eq!(
                dictionary_size_fields(0, size).unwrap_err(),
                Error::InvalidArgument(reason),
                "size {size}"
            );
        }
    }

    #[test]
    fn rar7_dictionary_boundaries_and_rejections() {
        assert_eq!(dictionary_size_fields(1, 128 * 1024).unwrap(), (0, 0));
        assert_eq!(dictionary_size_fields(1, 63 * 4096).unwrap(), (0, 31));
        assert_eq!(dictionary_size_fields(1, 64 * 4096).unwrap(), (1, 0));
        for (size, reason) in [
            (4096, "RAR 7 dictionary size must be at least 128 KiB"),
            (65 * 4096, "RAR 7 dictionary size is not encodable"),
            (
                64u64 * (1u64 << 31) * 4096,
                "RAR 7 dictionary size is not encodable",
            ),
        ] {
            assert_eq!(
                dictionary_size_fields(1, size).unwrap_err(),
                Error::InvalidArgument(reason),
                "size {size}"
            );
        }
    }

    #[test]
    fn dictionary_and_compression_options_reject_unsupported_encodings() {
        for level in [6, u8::MAX] {
            assert_eq!(
                encode_options_for_level(Some(level), 128 * 1024).unwrap_err(),
                Error::InvalidArgument("RAR 5 compression level must be in the range 0..5")
            );
        }
        let rar5 = WriterOptions::default();
        let rar7 = WriterOptions::new(
            crate::ArchiveVersion::Rar70,
            crate::FeatureSet::store_only(),
        );
        let fractional = 160 * 1024;
        assert!(validate_dictionary_size(rar5.target, fractional).is_err());
        validate_dictionary_size(rar7.target, fractional).unwrap();
        assert_eq!(rar50_algorithm_version(rar7, 128 * 1024).unwrap(), 0);
        assert_eq!(rar50_algorithm_version(rar7, fractional).unwrap(), 1);
        assert_eq!(
            rar50_algorithm_version(
                WriterOptions::new(
                    crate::ArchiveVersion::Rar40,
                    crate::FeatureSet::store_only(),
                ),
                128 * 1024,
            )
            .unwrap_err(),
            Error::UnsupportedVersion(crate::ArchiveVersion::Rar40)
        );
        assert_eq!(
            validate_dictionary_size(crate::ArchiveVersion::Rar40, 128 * 1024).unwrap_err(),
            Error::UnsupportedVersion(crate::ArchiveVersion::Rar40)
        );
        assert_eq!(
            dictionary_size_fields(2, 128 * 1024).unwrap_err(),
            Error::InvalidArgument("RAR 5 unknown compression algorithm version")
        );
    }

    #[test]
    fn filter_trials_propagate_codec_allocation_refusals() {
        use crate::codec::workspace::Allowance;
        use crate::filter_search::OwnedSearch;

        let search = Rar50OwnedSearch {
            algorithm_version: 0,
            file_offset: 0,
            piece: false,
            exhaustive: false,
            estimates: false,
            allowance: Allowance::limited(0),
        };
        let filter = FilterSpec::whole(FilterKind::Delta { channels: 1 });
        let data = vec![42; 4096];
        assert_eq!(
            search
                .filtered_bytes(&data, std::slice::from_ref(&filter))
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ResourceLimit
        );
        assert_eq!(
            search
                .encode_filtered(&data, &[filter], EncodeOptions::new(8), None)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::ResourceLimit
        );
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

const SCREENED_KINDS: [FilterKind; 5] = [
    FilterKind::Arm,
    FilterKind::Delta { channels: 1 },
    FilterKind::Delta { channels: 2 },
    FilterKind::Delta { channels: 3 },
    FilterKind::Delta { channels: 4 },
];

/// How finely RAR 5 looks for tables of fixed-size records to delta filter.
///
/// A binary's tables are mostly small: the relocations, symbols, dynamic
/// section and unwind index of one executable come to a few kilobytes each,
/// and a tar of executables has one set per file. At the shared search's
/// 16 KiB windows, with two in a row needed, the scanner sees none of them.
///
/// The scan costs the same per byte at any window size. Below 256 bytes a
/// window holds too few records to tell a table from chance, and text starts to
/// lose.
const RAR50_TABLE_SCAN_WINDOW: usize = 256;

struct Rar50OwnedSearch<B: Budget> {
    algorithm_version: u8,
    /// Where the data searched starts in its member. The x86 filters convert
    /// by file position, so a run has to be measured at its own.
    file_offset: usize,
    /// Whether this is one piece of a larger member, which measures E8 alone
    /// alongside E8E9 (see `prices_calls_alone`).
    piece: bool,
    /// Whether every finalist is encoded in full (see [`exhaustive_search`]).
    exhaustive: bool,
    /// Whether the samples are priced rather than encoded (see
    /// [`estimated_search`]).
    estimates: bool,
    allowance: B,
}
impl<B: Budget> OwnedSearch for Rar50OwnedSearch<B> {
    type Options = EncodeOptions;
    type Memory = B;
    fn allowance(&self) -> &B {
        &self.allowance
    }
    fn screened_kinds(&self, _: &[u8]) -> Result<Buffer<FilterKind, B>> {
        Ok(Buffer::collect(SCREENED_KINDS, &self.allowance)?)
    }
    fn detects_x86(&self) -> bool {
        true
    }
    fn prices_calls_alone(&self) -> bool {
        self.piece
    }
    fn max_delta_channels(&self) -> usize {
        crate::codec::rar50::MAX_DELTA_CHANNELS
    }
    fn table_scan_window(&self) -> usize {
        RAR50_TABLE_SCAN_WINDOW
    }
    /// One step down from the caller's parse: the lazy parse that seeds the
    /// shortest path, and below level 2, where that lazy parse is the real
    /// one, a greedy parse unless the search is exhaustive.
    ///
    /// The screens and the trial encode about twice the member in samples.
    fn screen_options(&self, options: EncodeOptions) -> EncodeOptions {
        if options.optimal_parse || self.exhaustive {
            options.with_optimal_parse(false)
        } else {
            options.with_lazy_matching(false)
        }
    }
    fn exhaustive(&self) -> bool {
        self.exhaustive
    }
    fn estimates(&self) -> bool {
        self.estimates
    }
    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Buffer<u8, B>> {
        if self.file_offset != 0 {
            return Ok(crate::codec::rar50::filtered_run_bytes(
                data,
                filters,
                self.file_offset,
                &self.allowance,
            )?);
        }
        Ok(crate::codec::rar50::filtered_owned_member(
            data,
            filters,
            &self.allowance,
        )?)
    }
    fn filtered_window(
        &self,
        data: &[u8],
        offset: usize,
        filters: &[FilterSpec],
    ) -> Result<Buffer<u8, B>> {
        Ok(crate::codec::rar50::filtered_run_bytes(
            data,
            filters,
            self.file_offset + offset,
            &self.allowance,
        )?)
    }
    fn encode_plain(
        &self,
        data: &[u8],
        options: EncodeOptions,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, B>> {
        Ok(crate::codec::rar50::encode_owned_member(
            data,
            self.algorithm_version,
            options,
            None,
            progress,
            &self.allowance,
        )?)
    }
    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: EncodeOptions,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, B>> {
        if self.file_offset != 0 {
            return Ok(crate::codec::rar50::encode_filtered_run(
                data,
                filters,
                &[],
                self.file_offset,
                true,
                self.algorithm_version,
                options,
                progress,
                &self.allowance,
            )?);
        }
        Ok(crate::codec::rar50::encode_owned_member(
            data,
            self.algorithm_version,
            options,
            Some(filters),
            progress,
            &self.allowance,
        )?)
    }
}
/// Chooses a whole member's filters, and returns them with the member packed
/// under them.
///
/// A member longer than one
/// [`FILTER_SEARCH_BYTES`](super::plan::FILTER_SEARCH_BYTES) piece is searched
/// a piece at a time, on the grid the block path cuts it into runs and pieces,
/// with the same search each of those gets, so both paths pick the same filters
/// for a member.
fn choose_owned_filter<B: Budget>(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
    allowance: &B,
) -> Result<crate::filter_search::FilterChoice<B>> {
    let piece = filter_search_bytes();
    if data.len() <= piece {
        return crate::filter_search::choose_owned(
            &Rar50OwnedSearch {
                algorithm_version,
                file_offset: 0,
                piece: false,
                exhaustive: exhaustive_search(options),
                estimates: estimated_search(options),
                allowance: allowance.clone(),
            },
            data,
            options,
            progress,
        );
    }
    let run = options
        .max_match_distance
        .max(crate::codec::rar50::MAX_LZ_BLOCK_SIZE);
    let mut specs = Buffer::new(allowance);
    for run_start in (0..data.len()).step_by(run) {
        let run_end = (run_start + run).min(data.len());
        for start in (run_start..run_end).step_by(piece) {
            let end = (start + piece).min(run_end);
            let found = piece_filters(
                &data[start..end],
                start,
                algorithm_version,
                options,
                borrow_progress(&mut progress),
                allowance,
            )?;
            for spec in found.iter() {
                let range = spec
                    .range
                    .clone()
                    .map_or(start..end, |range| start + range.start..start + range.end);
                specs.try_push(FilterSpec::range(spec.kind, range))?;
            }
        }
    }
    let packed = specs_with_allowance(
        data,
        algorithm_version,
        &specs,
        options,
        progress,
        allowance,
    )?;
    Ok((specs, packed))
}

/// Whether the search at these settings encodes every finalist in full
/// rather than ranking them by a trial: level 5's, which is the level that
/// spends whatever it takes.
fn exhaustive_search(options: EncodeOptions) -> bool {
    options.max_match_candidates >= match_candidates_for_level(5).expect("level 5 is a level")
}
/// Whether the search at these settings judges filters by byte statistics
/// rather than sample encodes (see [`OwnedSearch::estimates`]): levels 1 and
/// 2's. There the sample encodes cost about as much as packing the member, and
/// on the bench classes the statistics pick filters that pack as small.
fn estimated_search(options: EncodeOptions) -> bool {
    options.max_match_candidates <= match_candidates_for_level(2).expect("level 2 is a level")
}

/// The filters for one run of a member too large to search whole, ranged over
/// the run. The run is searched on its own, without the history it is later
/// coded against, so the choice never waits on the runs before it. It is
/// filtered where it lies in the member all the same: an x86 filter measured
/// as if the run began the file leaves alone every call that reaches back
/// past the run's start.
///
/// The decoder converts x86 and ARM addresses from a 32-bit file offset, and
/// the encoder refuses one past that, so a run reaching beyond
/// [`FILTER_REACH`] stays unfiltered.
pub(super) fn run_filters_with_allowance<B: Budget>(
    data: &[u8],
    file_offset: usize,
    algorithm_version: u8,
    options: EncodeOptions,
    cancelled: &dyn Fn() -> bool,
    allowance: &B,
) -> Result<Buffer<FilterSpec, B>> {
    let mut progress = |_| !cancelled();
    piece_filters(
        data,
        file_offset,
        algorithm_version,
        options,
        Some(&mut progress),
        allowance,
    )
}

/// The search [`run_filters_with_allowance`] makes, reporting to `progress`.
fn piece_filters<B: Budget>(
    data: &[u8],
    file_offset: usize,
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
    allowance: &B,
) -> Result<Buffer<FilterSpec, B>> {
    let past_offsets = file_offset
        .checked_add(data.len())
        .is_none_or(|end| end > FILTER_REACH);
    if past_offsets || !auto_size_filter_search_applies(data) {
        return Ok(Buffer::new(allowance));
    }
    crate::filter_search::choose_owned_specs(
        &Rar50OwnedSearch {
            algorithm_version,
            file_offset,
            piece: true,
            exhaustive: exhaustive_search(options),
            estimates: estimated_search(options),
            allowance: allowance.clone(),
        },
        data,
        run_search_options(options),
        progress,
    )
}

/// The parse a run's filter search measures with: the member's own, but no
/// more than level 3's.
///
/// The search only ranks filters. Its encodes are thrown away, and the run is
/// coded again later against its history.
fn run_search_options(options: EncodeOptions) -> EncodeOptions {
    if !options.optimal_parse {
        return options;
    }
    let (nice, passes) = parse_effort_for_level(3);
    let mut search = options
        .with_nice_match_length(options.nice_match_length.min(nice))
        .with_parse_passes(options.parse_passes.min(passes));
    search.max_match_candidates = options
        .max_match_candidates
        .min(match_candidates_for_level(3).expect("level 3 is a level"));
    search
}

fn specs_with_allowance<B: Budget>(
    data: &[u8],
    algorithm_version: u8,
    filters: &[FilterSpec],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    encode_pass(progress, |progress| {
        Ok(crate::codec::rar50::encode_owned_member(
            data,
            algorithm_version,
            options,
            (!filters.is_empty()).then_some(filters),
            progress,
            allowance,
        )?)
    })
}

/// How far into a member a RAR 5 filter reaches.
///
/// x86 and ARM filters convert addresses from a 32-bit file offset, and the
/// encoder refuses a filter that starts past one. Automatic filters stop here
/// (see [`run_filters_with_allowance`]), and an explicit filter is cut here
/// too, rather than refused partway through writing a member that runs past
/// it. A member's first 4 GiB is still filtered as asked.
pub(super) const FILTER_REACH: usize = u32::MAX as usize;

/// `range`, in bytes of its member, cut to [`FILTER_REACH`].
pub(super) fn within_filter_reach(range: std::ops::Range<usize>) -> std::ops::Range<usize> {
    range.start.min(FILTER_REACH)..range.end.min(FILTER_REACH)
}

/// An explicit filter over a whole member of `len` bytes, cut to
/// [`FILTER_REACH`], or `None` when nothing of it is left. A range the member
/// cannot hold is passed on unchanged, for the encoder to refuse.
pub(super) fn explicit_member_filter(spec: &FilterSpec, len: usize) -> Option<FilterSpec> {
    let range = spec.range.clone().unwrap_or(0..len);
    if range.end <= FILTER_REACH || range.start >= range.end || range.end > len {
        return Some(spec.clone());
    }
    let range = within_filter_reach(range);
    (range.start < range.end).then(|| FilterSpec::range(spec.kind, range))
}

fn policy_with_allowance<B: Budget>(
    data: &[u8],
    algorithm_version: u8,
    policy: &FilterPolicy,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    match policy {
        FilterPolicy::Auto if auto_size_filter_search_applies(data) => {
            choose_owned_filter(data, algorithm_version, options, progress, allowance)
                .map(|(_, bytes)| bytes)
        }
        FilterPolicy::Explicit(filter) => specs_with_allowance(
            data,
            algorithm_version,
            explicit_member_filter(filter, data.len()).as_slice(),
            options,
            progress,
            allowance,
        ),
        _ => specs_with_allowance(data, algorithm_version, &[], options, progress, allowance),
    }
}

/// How RAR 5 measures a filter candidate, for the shared search.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct Rar50Search {
    pub(crate) algorithm_version: u8,
}

#[cfg(test)]
impl crate::filter_search::FilterSearch for Rar50Search {
    type Options = EncodeOptions;

    fn screened_kinds(&self, _data: &[u8]) -> Vec<FilterKind> {
        SCREENED_KINDS.to_vec()
    }

    fn max_delta_channels(&self) -> usize {
        crate::codec::rar50::MAX_DELTA_CHANNELS
    }
    fn table_scan_window(&self) -> usize {
        RAR50_TABLE_SCAN_WINDOW
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

#[cfg(test)]
pub(super) fn encode_member_with_auto_size_filter_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
) -> Result<Vec<u8>> {
    policy_with_allowance(
        data,
        algorithm_version,
        &FilterPolicy::Auto,
        options,
        progress,
        &Allowance::default(),
    )
    .map(Buffer::into_vec)
}

pub(super) fn solid_compression_flag(solid_continuation: bool) -> u64 {
    if solid_continuation {
        0x40
    } else {
        0
    }
}

#[cfg(test)]
mod allowance_tests {
    use super::*;

    #[test]
    fn candidate_search_keeps_the_winner_charged_and_releases_refused_trials() {
        let data: Vec<u8> = (0..1024u32)
            .flat_map(|n| ((n * 71) % 32749).to_le_bytes())
            .collect();
        let candidates = [
            EncodeOptions::new(8).with_max_match_distance(65536),
            EncodeOptions::new(16).with_max_match_distance(65536),
        ];
        for version in [0, 1] {
            for policy in [
                FilterPolicy::None,
                FilterPolicy::Auto,
                FilterPolicy::Explicit(FilterSpec::whole(FilterKind::Delta { channels: 4 })),
            ] {
                let expected = candidates_with_allowance(
                    &data,
                    version,
                    &policy,
                    &candidates,
                    None,
                    &Allowance::default(),
                )
                .unwrap();
                let mut successes = 0;
                let mut refusals = 0;
                for limit in [0, 4096, 16384, 65536, 262144, 1048576, 8 * 1048576] {
                    let allowance = Allowance::limited(limit);
                    match candidates_with_allowance(
                        &data,
                        version,
                        &policy,
                        &candidates,
                        None,
                        &allowance,
                    ) {
                        Ok(packed) => {
                            successes += 1;
                            assert_eq!(&*packed, &*expected);
                            assert!(allowance.used() >= packed.len() as u64);
                            assert!(allowance.used() > 0);
                            drop(packed);
                        }
                        Err(error) => {
                            refusals += 1;
                            assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit, "{error}");
                        }
                    }
                    assert_eq!(allowance.used(), 0);
                }
                assert!(successes > 0 && refusals >= 3);
            }
        }
    }

    #[test]
    fn bounded_sampled_search_preserves_code_and_table_candidates() {
        let mut data = vec![0x90u8; 65536];
        for pos in (0..65000).step_by(32) {
            data[pos] = 0xe8;
            data[pos + 1..pos + 5].copy_from_slice(&(1024i32 - pos as i32).to_le_bytes());
        }
        for index in 0..8192u64 {
            data.extend_from_slice(&(0x7f80_1234_0000 + index * 24).to_le_bytes());
            data.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
            data.extend_from_slice(&(0x4455_6677_0000 | ((index * 7) & 0xffff)).to_le_bytes());
        }
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let expected = choose_owned_filter(&data, 0, options, None, &Allowance::default()).unwrap();
        assert!(!expected.0.is_empty());
        assert!(expected
            .0
            .iter()
            .any(|spec| matches!(spec.kind, FilterKind::Delta { channels: 24 })));
        let allowance = Allowance::limited(32 * 1048576);
        let (specs, packed) = choose_owned_filter(&data, 0, options, None, &allowance).unwrap();
        assert_eq!(&*specs, &*expected.0);
        assert_eq!(&*packed, &*expected.1);
        let retained = allowance.used();
        assert!(retained > packed.len() as u64);
        drop(specs);
        assert!(allowance.used() < retained);
        assert!(allowance.used() >= packed.len() as u64);
        drop(packed);
        assert_eq!(allowance.used(), 0);
    }

    /// A run deep in a member, whose calls all reach back before the run
    /// began. Searched as if it started the file none of them converts, and
    /// the x86 filter measures as no filter at all.
    #[test]
    fn a_run_is_searched_at_its_own_file_offset() {
        const FILE_OFFSET: usize = 8 * 1048576;
        let mut state = 0x2545_f491u32;
        let mut data = Vec::new();
        while data.len() < 512 * 1024 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.extend_from_slice(&[0x48, 0x89, (state >> 16) as u8, (state >> 8) as u8]);
            data.extend_from_slice(&[0x8b, 0x45, (state >> 20) as u8 & 0xfc]);
            let target = 0x0010_0000u32 + ((state >> 24) & 7) * 0x400;
            let call_end = (FILE_OFFSET + data.len() + 5) as u32;
            data.push(0xe8);
            data.extend_from_slice(&target.wrapping_sub(call_end).to_le_bytes());
        }
        let options = EncodeOptions::new(32).with_max_match_distance(1048576);
        let filters = |file_offset| {
            run_filters_with_allowance(
                &data,
                file_offset,
                0,
                options,
                &|| false,
                &Allowance::default(),
            )
            .unwrap()
        };
        let placed = filters(FILE_OFFSET);
        assert!(
            placed
                .iter()
                .any(|spec| matches!(spec.kind, FilterKind::E8 | FilterKind::E8E9)),
            "the run's calls went unfiltered: {:?}",
            &placed[..]
        );
        // The same bytes at the start of a file hold calls to before it.
        assert!(
            !filters(0)
                .iter()
                .any(|spec| matches!(spec.kind, FilterKind::E8 | FilterKind::E8E9)),
            "calls to before the file began were converted"
        );
    }

    #[test]
    fn cancellation_drops_retained_screens_and_previous_encoder_candidates() {
        let data: Vec<u8> = (0..1024u32).flat_map(|n| n.to_le_bytes()).collect();
        let options = EncodeOptions::new(8).with_max_match_distance(65536);
        let candidates = [options, options.with_optimal_parse(true)];
        for policy in [FilterPolicy::None, FilterPolicy::Auto] {
            let mut passes = 0;
            let expected = candidates_with_allowance(
                &data,
                0,
                &policy,
                &candidates,
                Some(&mut |event| {
                    passes += usize::from(event == EncodeProgress::PassStarted);
                    true
                }),
                &Allowance::default(),
            )
            .unwrap();
            assert!(passes >= 2);
            for stop in 1..=passes {
                let allowance = Allowance::limited(16 * 1048576);
                let mut pass = 0;
                let result = candidates_with_allowance(
                    &data,
                    0,
                    &policy,
                    &candidates,
                    Some(&mut |event| {
                        pass += usize::from(event == EncodeProgress::PassStarted);
                        pass < stop
                    }),
                    &allowance,
                );
                assert!(matches!(result, Err(Error::Cancelled)));
                assert_eq!(allowance.used(), 0, "pass {stop}");
                let retried =
                    candidates_with_allowance(&data, 0, &policy, &candidates, None, &allowance)
                        .unwrap();
                assert_eq!(&*retried, &*expected);
                drop(retried);
                assert_eq!(allowance.used(), 0);
            }
        }
    }
}

#[cfg(test)]
mod run_search_tests {
    use super::*;

    /// x86 code that opens with a script: calls to a few targets, which E8
    /// turns into repeats.
    fn scripted_code(len: usize) -> Vec<u8> {
        let mut data = b"#!/bin/sh\n# a script at the front of the member\n".repeat(400);
        let mut state = 0x2545_f491u32;
        while data.len() + 16 <= len {
            data.extend_from_slice(&[
                0x48, 0x89, 0x8b, 0xc3, 0x83, 0x0f, 0x85, 0x31, 0xff, 0x74, 0x41,
            ]);
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let target = [0x1000u32, 0x2340, 0x8800, 0x10000][(state >> 30) as usize];
            let at = data.len() as u32;
            data.push(0xe8);
            data.extend_from_slice(&target.wrapping_sub(at + 5).to_le_bytes());
        }
        data.resize(len, 0x90);
        data
    }

    /// One search covers a run, so a member a little over one run is longer
    /// than one search, as a member over 4 MiB is.
    const SEARCH: usize = crate::codec::rar50::MAX_LZ_BLOCK_SIZE;

    #[test]
    fn a_large_member_is_searched_on_the_block_paths_grid() {
        let dictionary = 128 * 1024;
        let options = encode_options_for_level(Some(2), dictionary).unwrap();
        let run = crate::codec::rar50::MAX_LZ_BLOCK_SIZE;
        let data = scripted_code(SEARCH + 64 * 1024);
        let allowance = Allowance::default();
        let (specs, _) = super::super::plan::with_filter_search_bytes(SEARCH, || {
            choose_owned_filter(&data, 0, options, None, &allowance).unwrap()
        });
        // What the block path chooses, run by run.
        let mut runs = Vec::new();
        for start in (0..data.len()).step_by(run) {
            let end = (start + run).min(data.len());
            let found = run_filters_with_allowance(
                &data[start..end],
                start,
                0,
                options,
                &|| false,
                &allowance,
            )
            .unwrap();
            for spec in found.iter() {
                let range = spec
                    .range
                    .clone()
                    .map_or(start..end, |range| start + range.start..start + range.end);
                runs.push(FilterSpec::range(spec.kind, range));
            }
        }
        assert_eq!(specs.into_vec(), runs);
        // The script in front does not keep the first run unsearched.
        assert!(runs
            .first()
            .is_some_and(|spec| spec.range.as_ref().is_some_and(|range| range.start < run)));
    }

    /// A member longer than one filter search is filtered as well whole as run
    /// by run, to the byte. The member opens with text, as a tar of `/usr` can
    /// open with a script. The two paths choose the same filters
    /// (`a_large_member_is_searched_on_the_block_paths_grid`), and code them
    /// alike: the member's last run is shorter than the history behind it but
    /// over a quarter of it, so it searches a tree as the whole member does
    /// (#383).
    #[test]
    fn a_member_too_long_for_one_search_is_filtered_on_both_paths() {
        use crate::rar50::{ArchiveEntry, ArchiveExtras, WriterOptions};
        use crate::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};
        const MIB: u64 = 1024 * 1024;
        let root = crate::scratch::case("rar50-large-member-filter-paths");
        let tail = 120 * 1024;
        let data = scripted_code(SEARCH + tail);
        let options = encode_options_for_level(Some(2), 128 * 1024).unwrap();
        let (window, history) = (
            options.max_match_distance + tail,
            options.max_match_distance,
        );
        assert!(tail < history && crate::codec::rar50::searches_tree(window, history, options));
        // Above one run's filter search (169.1 MiB at a 128 KiB dictionary)
        // and below this 1.12 MiB member's whole-member charge (169.6 MiB),
        // so the member is coded run by run and each run still searches.
        let blocks = WriterResources::new(169 * MIB + MIB / 2).with_temp_dir(&*root);
        let whole = WriterResources::new(1024 * MIB).with_temp_dir(&*root);
        let write = |policy: FilterPolicy, resources: &WriterResources| {
            let entries = [ArchiveEntry::new(
                "code",
                EntrySource::from_bytes(data.clone()),
            )];
            let mut bytes = Vec::new();
            super::super::plan::with_filter_search_bytes(SEARCH, || {
                crate::rar50::write_streaming_archive_with_progress(
                    &entries,
                    WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                        .with_compression_level(2)
                        .with_dictionary_size(128 * 1024),
                    ArchiveExtras::default().with_filter_policy(policy),
                    resources,
                    None,
                    &mut bytes,
                )
            })
            .unwrap();
            bytes
        };
        let plain = write(FilterPolicy::None, &blocks);
        let by_runs = write(FilterPolicy::Auto, &blocks);
        let at_once = write(FilterPolicy::Auto, &whole);
        assert!(
            by_runs == at_once,
            "runs packed to {} and the whole member to {}",
            by_runs.len(),
            at_once.len()
        );
        for filtered in [by_runs, at_once] {
            let archive = ArchiveReader::read(&filtered).unwrap();
            archive.test(None).unwrap();
            assert_eq!(archive.read_member(b"code", None).unwrap().unwrap(), data);
            assert!(
                filtered.len() * 4 < plain.len() * 3,
                "filters took {} down only to {}",
                plain.len(),
                filtered.len()
            );
        }
    }

    /// Level 1 codes a member longer than one filter search in runs, which
    /// run on every thread, rather than whole on one (#545). The archive is
    /// the same at any thread count, and its packed member is the one the
    /// whole-member path makes.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn a_lazy_member_codes_in_runs_alike_on_any_thread_count() {
        use crate::rar50::{ArchiveEntry, ArchiveExtras, WriterOptions};
        use crate::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};
        let root = crate::scratch::case("rar50-lazy-member-runs");
        let data = scripted_code(2 * SEARCH + 100 * 1024);
        let options = encode_options_for_level(Some(1), 128 * 1024).unwrap();
        assert!(!options.optimal_parse);
        let whole = super::super::plan::with_filter_search_bytes(SEARCH, || {
            encode_member_with_filter_policy_candidates_and_progress(
                &data,
                0,
                &FilterPolicy::Auto,
                &[options],
                None,
            )
            .unwrap()
        });
        let write = |threads: usize| {
            let entries = [ArchiveEntry::new(
                "code",
                EntrySource::from_bytes(data.clone()),
            )];
            let resources = WriterResources::new(1024 * 1024 * 1024).with_temp_dir(&*root);
            let mut bytes = Vec::new();
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    super::super::plan::with_filter_search_bytes(SEARCH, || {
                        crate::rar50::write_streaming_archive_with_progress(
                            &entries,
                            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                                .with_compression_level(1)
                                .with_dictionary_size(128 * 1024),
                            ArchiveExtras::default().with_filter_policy(FilterPolicy::Auto),
                            &resources,
                            None,
                            &mut bytes,
                        )
                    })
                })
                .unwrap();
            bytes
        };
        let one = write(1);
        assert!(
            memchr::memmem::find(&one, &whole).is_some(),
            "the {}-byte archive does not hold the {}-byte whole-member packing",
            one.len(),
            whole.len()
        );
        for threads in [2, 8] {
            assert!(
                one == write(threads),
                "{threads} threads changed the archive"
            );
        }
        let archive = ArchiveReader::read(&one).unwrap();
        archive.test(None).unwrap();
        assert_eq!(archive.read_member(b"code", None).unwrap().unwrap(), data);
    }

    /// A filtered member is cut into the blocks an unfiltered one would be,
    /// so on data that never moves a block runs to a mebibyte, filter and
    /// all, and a member coded in runs has blocks that end where its runs
    /// do. The archive is the same at any thread count, and its packed member
    /// is the one the whole-member path makes.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn a_filtered_member_in_long_blocks_codes_alike_on_any_thread_count() {
        use crate::rar50::{ArchiveEntry, ArchiveExtras, WriterOptions};
        use crate::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};
        let root = crate::scratch::case("rar50-filtered-long-blocks");
        // A run of zeros and then one phrase, 8,191 bytes a period.
        let phrase = b"the quick brown fox jumps over the lazy dog. ";
        let mut period = vec![0u8; 4096];
        while period.len() + phrase.len() <= 8191 {
            period.extend_from_slice(phrase);
        }
        let data: Vec<u8> = period
            .iter()
            .copied()
            .cycle()
            .take(2 * SEARCH + 100 * 1024)
            .collect();
        let policy = FilterPolicy::Explicit(crate::FilterSpec::whole(crate::FilterKind::Delta {
            channels: 1,
        }));
        let options = encode_options_for_level(Some(3), 128 * 1024).unwrap();
        let whole = super::super::plan::with_filter_search_bytes(SEARCH, || {
            encode_member_with_filter_policy_candidates_and_progress(
                &data,
                0,
                &policy,
                &[options],
                None,
            )
            .unwrap()
        });
        // Three blocks with a set of tables each. With a block every 64 KiB,
        // the tables alone come to more than this.
        assert!(whole.len() < 700, "{} bytes", whole.len());
        let write = |threads: usize| {
            let entries = [ArchiveEntry::new(
                "period",
                EntrySource::from_bytes(data.clone()),
            )];
            let resources = WriterResources::new(1024 * 1024 * 1024).with_temp_dir(&*root);
            let mut bytes = Vec::new();
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    super::super::plan::with_filter_search_bytes(SEARCH, || {
                        crate::rar50::write_streaming_archive_with_progress(
                            &entries,
                            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                                .with_compression_level(3)
                                .with_dictionary_size(128 * 1024),
                            ArchiveExtras::default().with_filter_policy(policy.clone()),
                            &resources,
                            None,
                            &mut bytes,
                        )
                    })
                })
                .unwrap();
            bytes
        };
        let one = write(1);
        assert!(
            memchr::memmem::find(&one, &whole).is_some(),
            "the {}-byte archive does not hold the {}-byte whole-member packing",
            one.len(),
            whole.len()
        );
        for threads in [2, 8] {
            assert!(
                one == write(threads),
                "{threads} threads changed the archive"
            );
        }
        let archive = ArchiveReader::read(&one).unwrap();
        archive.test(None).unwrap();
        assert_eq!(archive.read_member(b"period", None).unwrap().unwrap(), data);
    }

    /// A table of 16-byte records, delta filtered, whose last field repeats
    /// every 512 KiB. The shortest-path parse reaches most of it through a
    /// remembered distance, which can carry it past where the search
    /// committed to the far copy, and the rest of that copy then has to be
    /// found where the parse lands. The archive is the same at any thread
    /// count, and level 2 packs it no larger than level 1.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    #[test]
    fn a_record_table_packs_no_larger_at_level_two_on_any_thread_count() {
        use crate::rar50::{ArchiveEntry, ArchiveExtras, WriterOptions};
        use crate::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};
        let root = crate::scratch::case("rar50-record-table-ladder");
        let data: Vec<u8> = (0..65536u32)
            .flat_map(|i| {
                [0x40_0000 + i * 24, i * 3, 7, i.wrapping_mul(i) & 0xffff]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
            })
            .collect();
        let write = |level: u8, threads: usize| {
            let entries = [ArchiveEntry::new(
                "table",
                EntrySource::from_bytes(data.clone()),
            )];
            let resources = WriterResources::new(1024 * 1024 * 1024).with_temp_dir(&*root);
            let mut bytes = Vec::new();
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    crate::rar50::write_streaming_archive_with_progress(
                        &entries,
                        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                            .with_compression_level(level),
                        ArchiveExtras::default().with_filter_policy(FilterPolicy::Auto),
                        &resources,
                        None,
                        &mut bytes,
                    )
                })
                .unwrap();
            bytes
        };
        let one = write(1, 1);
        let two = write(2, 1);
        assert!(
            two.len() <= one.len(),
            "level 2 packed {} bytes against level 1's {}",
            two.len(),
            one.len()
        );
        for threads in [2, 8] {
            assert!(
                two == write(2, threads),
                "{threads} threads changed the archive"
            );
        }
        let archive = ArchiveReader::read(&two).unwrap();
        archive.test(None).unwrap();
        assert_eq!(archive.read_member(b"table", None).unwrap().unwrap(), data);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn an_explicit_filter_over_a_member_stops_at_4_gib() {
        let e8 = FilterKind::E8;
        let reach = FILTER_REACH;
        let large = reach + 4096;
        // Within reach, the filter is passed on as asked.
        let whole = FilterSpec::whole(e8);
        assert_eq!(explicit_member_filter(&whole, reach), Some(whole));
        let ranged = FilterSpec::range(e8, 10..reach);
        assert_eq!(explicit_member_filter(&ranged, large), Some(ranged));
        // Past it, the filter is cut at 4 GiB.
        for spec in [
            FilterSpec::whole(e8),
            FilterSpec::range(e8, 0..large),
            FilterSpec::range(e8, 0..reach + 1),
        ] {
            assert_eq!(
                explicit_member_filter(&spec, large),
                Some(FilterSpec::range(e8, 0..reach))
            );
        }
        assert_eq!(
            explicit_member_filter(&FilterSpec::range(e8, 100..large), large),
            Some(FilterSpec::range(e8, 100..reach))
        );
        // A range wholly past it leaves nothing to filter.
        assert_eq!(
            explicit_member_filter(&FilterSpec::range(e8, reach..large), large),
            None
        );
        // A range the member cannot hold is the encoder's to refuse.
        for spec in [
            FilterSpec::range(e8, 0..large + 1),
            FilterSpec::range(e8, large..large),
        ] {
            assert_eq!(explicit_member_filter(&spec, large), Some(spec.clone()));
        }
    }

    #[test]
    fn run_searches_parse_no_harder_than_level_three() {
        let dictionary = 4 << 20;
        let three = encode_options_for_level(Some(3), dictionary).unwrap();
        for level in 3..=5 {
            let options = encode_options_for_level(Some(level), dictionary).unwrap();
            assert_eq!(run_search_options(options), three);
        }
        for level in 1..=2 {
            let options = encode_options_for_level(Some(level), dictionary).unwrap();
            assert_eq!(run_search_options(options), options);
        }
    }
}

#[cfg(test)]
mod store_decision_tests {
    use super::*;

    const FOUR_GIB: u64 = 1 << 32;

    #[test]
    fn a_member_over_four_gib_keeps_the_64_bit_store_decision() {
        let auto = FilterPolicy::Auto;
        // Cut to 32 bits, the unpacked size would fall below the packed one.
        assert!(!should_store_compressed_payload(
            FOUR_GIB + 10,
            3 << 30,
            false,
            &auto
        ));
        // Cut to 32 bits, the packed size would fall below the unpacked one.
        assert!(should_store_compressed_payload(
            3 << 30,
            FOUR_GIB + 10,
            false,
            &auto
        ));
    }
}
