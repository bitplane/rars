//! Choosing a filter for a member, for any format that has filters.
//!
//! The expensive part of picking a filter is that judging one means compressing
//! the member with it. Doing that for every filter a format offers, times every
//! region a scanner proposes, is most of the cost of writing an archive and
//! nearly all of it is spent proving that filters which were never going to help
//! do not help.
//!
//! So the candidates are cut down before any whole-member encode happens.
//! Filters with a structural detector behind them, which today means the x86
//! pair, get their regions from the detector and a sample encode per region to
//! confirm the detector was not fooled by chance byte patterns and to drop the
//! regions where the filter would cost more than it saves. Filters with no
//! detector are measured on a sample of the member and have to win by a clear
//! margin to earn a whole-member encode. What survives is a handful of
//! finalists, each encoded once at the caller's real settings, smallest wins.
//!
//! The unfiltered member is always one of the finalists, so the result can never
//! be larger than leaving the data alone.

use crate::x86_filter_scan::auto_x86_filter_ranges;
use crate::{FilterKind, FilterSpec, Result};
use std::ops::Range;

/// How much of the member the screens encode when deciding whether a filter is
/// worth a whole-member encode.
const SCREEN_SAMPLE_LEN: usize = 128 * 1024;

/// Keeps the screen sample's delta planes aligned the way they fall in the whole
/// member: the lowest common multiple of the delta widths worth trying.
const SCREEN_SAMPLE_ALIGNMENT: usize = 12;

/// How much smaller a filter has to make the sample before it earns a
/// whole-member encode, as a percentage.
///
/// A filter that pays off does so by a mile: delta on 16-bit audio takes 43% off
/// and on interleaved counters 96%. A sample that comes out a fraction of a
/// percent smaller is measurement noise from the shorter history, and chasing it
/// costs a whole-member encode per filter to find out.
const SCREEN_MARGIN_PERCENT: usize = 1;

/// How much of the member x86 detection has to cover before filtering the whole
/// thing is as good as filtering only the detected regions, as a fraction.
const X86_CODE_COVERAGE_RATIO: (usize, usize) = (9, 10);

/// How many x86 regions the progress estimate assumes the scanner will find.
///
/// Only used to scale a progress bar, and deliberately not measured: finding out
/// means scanning the member, which is a whole extra pass to sharpen a
/// percentage. Two to five is what the binaries measured came to, with an
/// unstripped 25 MB outlier at eleven.
const X86_ASSUMED_REGIONS: u64 = 4;

/// Bytes at each end of a member that a ranged delta filter skips, because
/// container headers and trailers are not part of the sampled signal.
pub(crate) const AUTO_DELTA_EDGE_SKIP: usize = 64;

/// What a writer has to tell the search about its format.
///
/// Implementors describe a format at fixed encoder settings and hold no state,
/// so a search can run inside a parallel per-member encode.
pub(crate) trait FilterSearch {
    /// The encoder settings a candidate is measured at. Compared, so the search
    /// can tell when a screen's encode is also a real measurement.
    type Options: Copy + PartialEq;

    /// Every filter this format can encode that has no detector of its own, so
    /// the only way to know whether it helps is to try it. Given the member, so
    /// a format can drop widths that do not fit or that its own cheap
    /// statistics have already ruled out.
    fn screened_kinds(&self, data: &[u8]) -> Vec<FilterKind>;

    /// Whether this format can encode the x86 filters, which come with a
    /// structural detector instead of a screen.
    fn detects_x86(&self) -> bool {
        true
    }

    /// Cheaper settings for the screens, when ranking candidates at less than
    /// full effort ranks them the same way.
    ///
    /// Defaults to the caller's own settings, because on RAR 5 the
    /// reduced-effort parse measured *slower* than the full one: weaker matches
    /// mean more for the entropy coder to do. On RAR 2.9 it really is cheaper,
    /// so that format overrides this.
    fn screen_options(&self, options: Self::Options) -> Self::Options {
        options
    }

    /// Apply the filters to a copy of `data`, without encoding it.
    ///
    /// The screens measure a transform by compressing its output against the
    /// unfiltered bytes. Comparing a filtered *encode* with an unfiltered one
    /// measured something else: on a 396 KB binary the 128 KiB sample said the
    /// E8E9 filter cost 10% (74322 plain against 81744 filtered) while the same
    /// filter was worth 7.4% of the finished archive, so every x86 member was
    /// screened out before anything measured it. Compressing the transformed
    /// bytes put the sample back in agreement with the member: 73579.
    ///
    /// Why the two encode paths disagree by that much on real data is not
    /// settled; on synthetic x86 they differ by a few bytes.
    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Vec<u8>>;

    /// Encode without filters.
    ///
    /// Separate from [`FilterSearch::encode_filtered`] because carrying filters
    /// can force shorter blocks, so encoding an empty filter list would not
    /// produce what asking for no filter produces. The search compares every
    /// candidate against leaving the data alone, and that has to mean the bytes
    /// the writer would really emit.
    fn encode_plain(
        &self,
        data: &[u8],
        options: Self::Options,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>>;

    /// Encode with these filters applied. Never called with an empty list.
    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: Self::Options,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>>;
}

fn borrow_progress<'a>(
    progress: &'a mut Option<&mut dyn FnMut(usize) -> bool>,
) -> Option<&'a mut dyn FnMut(usize) -> bool> {
    match progress {
        Some(report) => Some(&mut **report),
        None => None,
    }
}

/// Whether looking for a filter is worth starting at all.
///
/// An empty member has nothing to filter, and text does not benefit from any of
/// them, so neither should cost a single encode to find that out.
pub(crate) fn search_applies(data: &[u8]) -> bool {
    !data.is_empty() && !is_text_like(data)
}

fn is_text_like(data: &[u8]) -> bool {
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

fn screen_wins(filtered: usize, baseline: usize) -> bool {
    filtered * 100 < baseline * (100 - SCREEN_MARGIN_PERCENT)
}

/// A window from the middle of the member, used to screen the filters that have
/// nothing but a trial encode to go on.
fn screen_sample(data: &[u8]) -> &[u8] {
    if data.len() <= SCREEN_SAMPLE_LEN {
        return data;
    }
    let middle = (data.len() - SCREEN_SAMPLE_LEN) / 2;
    let start = middle / SCREEN_SAMPLE_ALIGNMENT * SCREEN_SAMPLE_ALIGNMENT;
    &data[start..start + SCREEN_SAMPLE_LEN]
}

/// What the screen learned, along with any encodes the search can reuse.
#[derive(Default)]
struct ScreenOutcome {
    kinds: Vec<(FilterKind, Option<Vec<u8>>)>,
    plain: Option<Vec<u8>>,
}

/// Which of the detectorless filters shrink a sample of the member.
///
/// These used to cost a whole-member encode each to prove they made the member
/// bigger, which on a binary is most of the search. Whether they help is a local
/// property of the byte layout, so a slice of the member answers it for a few
/// per cent of the price. This measures the real filter rather than a statistic
/// standing in for it, because the wins do not all show up as entropy: RAR's
/// delta reorders into planes first, and what that buys is repetition the
/// encoder can match, not a flatter byte histogram.
fn screen_kinds<S: FilterSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<ScreenOutcome> {
    let sample = screen_sample(data);
    let mut outcome = ScreenOutcome::default();
    if sample.len() < SCREEN_SAMPLE_ALIGNMENT {
        return Ok(outcome);
    }
    let screen_options = search.screen_options(options);
    // A member no bigger than the sample is the sample, so as long as the screen
    // measured it at the settings the finalists will use, those encodes are
    // whole-member measurements and the search should keep them rather than
    // repeat them.
    let reusable = sample.len() == data.len() && screen_options == options;
    let baseline = search.encode_plain(sample, screen_options, None)?;
    for kind in search.screened_kinds(data) {
        let transformed = search.filtered_bytes(sample, &[FilterSpec::whole(kind)])?;
        let packed = search.encode_plain(&transformed, screen_options, None)?;
        if screen_wins(packed.len(), baseline.len()) {
            // The screen measured the transform, not the encode the writer
            // would emit, so this is evidence for a finalist rather than a
            // measurement the search can reuse.
            outcome.kinds.push((kind, None));
        }
    }
    if reusable {
        outcome.plain = Some(baseline);
    }
    Ok(outcome)
}

/// Where the scanner thinks x86 code lives, merged into disjoint regions.
fn x86_code_regions(data: &[u8]) -> Vec<Range<usize>> {
    disjoint_filter_ranges(auto_x86_filter_ranges(data, true))
}

/// Which of the scanner's regions the x86 filter should cover, empty when none
/// of them is worth filtering.
///
/// Byte patterns that look like call opcodes turn up in compressed data by
/// chance, and the scanner cannot tell those from a real code section. A sample
/// encode inside a region separates the two for a fraction of what a
/// whole-member encode costs.
///
/// Every region gets its own sample, because on an unstripped binary the biggest
/// region is the debug data rather than the code. Screening only the largest, as
/// this did, declined the filter on every unstripped binary measured: it read
/// DWARF, saw no win, and stopped before anything measured the member. Regions
/// are disjoint, so the samples together never come to more than the member.
///
/// A region the filter makes bigger is dropped rather than counted against the
/// rest, which is what keeps the debug data out of the ranged candidate. On a
/// 20 MB unstripped binary that turns a filter worth 0.2% into one worth
/// 0.4%; leaving it in was worse than not filtering at all. Ties are kept: a
/// sample with no convertible opcodes in it is not evidence against the region
/// it came from.
fn x86_screened_regions<S: FilterSearch>(
    search: &S,
    data: &[u8],
    regions: &[Range<usize>],
    options: S::Options,
) -> Result<X86Screen> {
    let mut kept = Vec::new();
    let mut helped = false;
    for region in regions {
        let sample = screen_sample(&data[region.clone()]);
        if sample.len() < SCREEN_SAMPLE_ALIGNMENT {
            kept.push(region.clone());
            continue;
        }
        // Measured at the caller's real settings, not the cheaper screen ones.
        // The detectorless screens rank many candidates against each other,
        // where a reduced parse ranks them the same way; this is a yes or no
        // with no margin under it, and a sample encode is cheap enough to get
        // right.
        let baseline = search.encode_plain(sample, options, None)?;
        let transformed = search.filtered_bytes(sample, &[FilterSpec::whole(FilterKind::E8E9)])?;
        let filtered = search.encode_plain(&transformed, options, None)?;
        if filtered.len() > baseline.len() {
            continue;
        }
        // No margin here, unlike the detectorless filters: the scanner has
        // already ruled on where code is, so a small win on this sample is
        // evidence rather than noise.
        helped |= filtered.len() < baseline.len();
        kept.push(region.clone());
    }
    Ok(X86Screen {
        rejected_a_region: kept.len() < regions.len(),
        kept: if helped { kept } else { Vec::new() },
    })
}

/// What the x86 screen made of the regions the scanner proposed.
struct X86Screen {
    /// The regions worth filtering, empty when none of them is.
    kept: Vec<Range<usize>>,
    /// Whether any region came out bigger under the filter, which rules out
    /// filtering the member end to end.
    rejected_a_region: bool,
}

/// The x86 filter specs worth measuring against the whole member, given what the
/// screen made of the regions the scanner proposed.
///
/// The scanner proposes overlapping regions at several clustering distances, and
/// the search this replaced priced every one of them with its own whole-member
/// encode. Measured at full effort the whole spread is worth about a third of a
/// percent, so this keeps the two that are structurally different: filter
/// everything, or filter only where the screen saw code.
///
/// Which of the two is worth an encode is mostly already known. Filtering
/// everything covers the regions the screen rejected as well, so once it has
/// rejected one, that candidate is asking to be told again that those bytes come
/// out bigger; on all seven binaries measured the kept regions beat it. Filtering
/// only the regions is the same thing as filtering everything when they cover
/// nearly the whole member. So each case is worth one candidate per kind, not
/// two, which is what keeps an unstripped binary to three whole-member encodes
/// rather than five.
fn x86_finalists(
    data: &[u8],
    regions: &[Range<usize>],
    rejected_a_region: bool,
) -> Vec<Vec<FilterSpec>> {
    let covered: usize = regions.iter().map(|range| range.len()).sum();
    let (numerator, denominator) = X86_CODE_COVERAGE_RATIO;
    let sparse = covered * denominator < data.len() * numerator;

    let mut finalists = Vec::new();
    for kind in [FilterKind::E8E9, FilterKind::E8] {
        if rejected_a_region || sparse {
            finalists.push(
                regions
                    .iter()
                    .map(|range| FilterSpec::range(kind, range.clone()))
                    .collect(),
            );
        }
        if !rejected_a_region {
            finalists.push(vec![FilterSpec::whole(kind)]);
        }
    }
    finalists
}

/// The filter specs worth measuring against the whole member, paired with the
/// bytes for any the screen already measured.
///
/// Everything expensive happens downstream of this, one whole-member encode per
/// unmeasured finalist, so the job here is to hand back a handful rather than the
/// several dozen the scanner and the delta widths can between them suggest.
#[allow(clippy::type_complexity)]
fn finalists<S: FilterSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<Vec<(Vec<FilterSpec>, Option<Vec<u8>>)>> {
    let screen = screen_kinds(search, data, options)?;
    let mut finalists = vec![(Vec::new(), screen.plain)];

    if search.detects_x86() {
        let screen = x86_screened_regions(search, data, &x86_code_regions(data), options)?;
        if !screen.kept.is_empty() {
            finalists.extend(
                x86_finalists(data, &screen.kept, screen.rejected_a_region)
                    .into_iter()
                    .map(|specs| (specs, None)),
            );
        }
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
pub(crate) fn choose_filter<S: FilterSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<(Vec<FilterSpec>, Vec<u8>)> {
    let mut best: Option<(Vec<FilterSpec>, Vec<u8>)> = None;
    for (specs, measured) in finalists(search, data, options)? {
        let packed = match measured {
            Some(packed) => packed,
            None if specs.is_empty() => {
                search.encode_plain(data, options, borrow_progress(&mut progress))?
            }
            None => {
                search.encode_filtered(data, &specs, options, borrow_progress(&mut progress))?
            }
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

/// How many bytes the encoder will walk while this search runs.
///
/// Progress is reported by encoder position, and the search walks the member
/// several times over, so the reporter needs the total to scale by. What
/// survives the screens is not knowable without doing the work, so this assumes
/// one detectorless filter does, and that the x86 detector finds code and
/// proposes its usual pair of specs.
///
/// Deliberately does not run the detector to find out. This is called for every
/// member before anything is compressed, and scanning here only to scan again
/// inside the search cost a second pass over the member to sharpen a percentage.
/// A progress bar that finishes a little early or a little late is not worth
/// that.
pub(crate) fn walk_bytes<S: FilterSearch>(
    search: &S,
    data: &[u8],
    encoder_candidates: usize,
) -> u64 {
    let member = data.len() as u64;
    let encoder_candidates = encoder_candidates.max(1) as u64;
    let sample = screen_sample(data).len() as u64;
    let screened = search.screened_kinds(data).len() as u64;
    // Two sample encodes per region for the x86 screen, and the two specs it
    // proposes when the detector does find code. How many regions there are is
    // not knowable without scanning, so this assumes [`X86_ASSUMED_REGIONS`],
    // bounded by the member: the regions are disjoint, so however many the
    // scanner finds, their samples together cannot come to more than that.
    let (x86_screen, x86_finalists) = if search.detects_x86() {
        ((sample * X86_ASSUMED_REGIONS).min(member) * 2, 2)
    } else {
        (0, 0)
    };
    let screen = sample * (screened + 1) + x86_screen;
    // The unfiltered member, the x86 finalists, and one assumed screen survivor.
    let finalists = 2 + x86_finalists;
    screen + member * (finalists + encoder_candidates - 1)
}

/// The bytes a ranged delta filter covers: the member minus its edges, trimmed
/// so the planes stay aligned.
pub(crate) fn auto_delta_filter_range(data: &[u8], channels: usize) -> Option<Range<usize>> {
    if channels == 0 || data.len() <= AUTO_DELTA_EDGE_SKIP * 2 + channels * 8 {
        return None;
    }
    let start = AUTO_DELTA_EDGE_SKIP;
    let end = data.len() - AUTO_DELTA_EDGE_SKIP;
    let aligned_start = start + ((channels - start % channels) % channels);
    let aligned_end = end - (end - aligned_start) % channels;
    (aligned_start + channels * 8 <= aligned_end).then_some(aligned_start..aligned_end)
}

/// Merges overlapping and touching ranges.
///
/// Merging rather than dropping: two ranges that overlap describe one region,
/// and keeping only the first loses coverage of the rest of it.
pub(crate) fn disjoint_filter_ranges(mut ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut disjoint: Vec<Range<usize>> = Vec::new();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::rar50::{
        encode_lz_member_with_options, encode_lz_member_with_options_and_progress, EncodeOptions,
        Unpack50Encoder,
    };

    /// A stand-in format that measures candidates the way RAR 5 does. The
    /// driver is generic, but it still has to be exercised against a real
    /// encoder for the screens to mean anything.
    #[derive(Clone, Copy)]
    struct TestSearch {
        cheap_screens: bool,
    }

    impl FilterSearch for TestSearch {
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
                .map_err(crate::Error::from)
        }

        fn screen_options(&self, options: EncodeOptions) -> EncodeOptions {
            if self.cheap_screens {
                EncodeOptions::new(4).with_max_match_distance(options.max_match_distance)
            } else {
                options
            }
        }

        fn encode_plain(
            &self,
            data: &[u8],
            options: EncodeOptions,
            progress: Option<&mut dyn FnMut(usize) -> bool>,
        ) -> Result<Vec<u8>> {
            match progress {
                Some(progress) => {
                    encode_lz_member_with_options_and_progress(data, 0, options, progress)
                }
                None => encode_lz_member_with_options(data, 0, options),
            }
            .map_err(crate::Error::from)
        }

        fn encode_filtered(
            &self,
            data: &[u8],
            filters: &[FilterSpec],
            options: EncodeOptions,
            _progress: Option<&mut dyn FnMut(usize) -> bool>,
        ) -> Result<Vec<u8>> {
            Unpack50Encoder::with_options(options)
                .encode_member_with_filters(data, 0, filters)
                .map_err(crate::Error::from)
        }
    }

    const FULL: TestSearch = TestSearch {
        cheap_screens: false,
    };

    fn options() -> EncodeOptions {
        EncodeOptions::new(64).with_max_match_distance(128 * 1024)
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

    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        std::iter::repeat_with(|| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .take(len)
        .collect()
    }

    #[test]
    fn the_screen_keeps_a_delta_width_that_pays_off() {
        let kinds: Vec<_> = screen_kinds(&FULL, &interleaved_counters(), options())
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
    fn the_screen_rejects_filters_on_incompressible_data() {
        assert!(
            screen_kinds(&FULL, &incompressible(400_000), options())
                .unwrap()
                .kinds
                .is_empty(),
            "nothing helps random bytes, and finding that out must not cost whole-member encodes"
        );
    }

    #[test]
    fn a_short_member_reuses_only_the_unfiltered_encode() {
        let data = interleaved_counters()[..100_000].to_vec();
        assert!(data.len() <= SCREEN_SAMPLE_LEN);
        let screen = screen_kinds(&FULL, &data, options()).unwrap();
        assert!(screen.plain.is_some(), "the unfiltered encode is reusable");
        // A survivor's number came from compressing the transformed bytes, not
        // from the encode the writer would emit, so it cannot stand in for a
        // measurement however long the member is.
        assert!(screen.kinds.iter().all(|(_, packed)| packed.is_none()));
    }

    /// A screen run at cheaper settings measured something the finalists will
    /// not be measured at, so it cannot stand in for a real measurement even
    /// when the sample happens to be the whole member.
    #[test]
    fn cheaper_screens_are_not_reused_as_measurements() {
        let data = interleaved_counters()[..100_000].to_vec();
        let cheap = TestSearch {
            cheap_screens: true,
        };
        let screen = screen_kinds(&cheap, &data, options()).unwrap();
        assert!(screen.plain.is_none());
        assert!(screen.kinds.iter().all(|(_, packed)| packed.is_none()));
    }

    /// A member big enough that the screens have to sample it, with a filter in
    /// it worth finding. The call targets here are absolute rather than
    /// relative, so it is the delta filter that pays off on it, not the x86
    /// one; see [`calls_to_fixed_addresses`] for code shaped the way the x86
    /// filter wants.
    fn x86_like(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491u32;
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if state.is_multiple_of(11) {
                // A call to one of a few fixed addresses, which the filter turns
                // into a handful of repeated relative offsets.
                let target = 0x4000u32 + (state >> 28) * 0x400;
                data.push(0xe8);
                data.extend_from_slice(&target.to_le_bytes());
            } else {
                data.extend_from_slice(&[0x48, 0x89, (state >> 16) as u8, 0xe5]);
            }
        }
        data.truncate(len);
        data
    }

    /// The search has to end up with the filter when one plainly helps.
    #[test]
    fn the_screen_finds_a_filter_worth_having_on_a_sampled_member() {
        let data = x86_like(SCREEN_SAMPLE_LEN * 4);
        let (specs, packed) = choose_filter(&FULL, &data, options(), None).unwrap();
        let plain = FULL.encode_plain(&data, options(), None).unwrap();

        assert!(
            !specs.is_empty(),
            "the search left the filter on the table: {} against {} unfiltered",
            packed.len(),
            plain.len()
        );
        assert!(packed.len() < plain.len());
    }

    /// Calls to a handful of fixed addresses, in bodies that repeat. Unfiltered
    /// the call breaks every repeat, because the displacement counts from wherever
    /// the call sits; converted to an absolute address the bodies match each
    /// other again. That is what the x86 filter is for, and it is why a stretch
    /// of real code screens as a win.
    fn calls_to_fixed_addresses(len: usize) -> Vec<u8> {
        const BODIES: [[u8; 11]; 4] = [
            [
                0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x89, 0x7d, 0xfc,
            ],
            [
                0x48, 0x8b, 0x45, 0xf8, 0x48, 0x8b, 0x00, 0x48, 0x89, 0xc7, 0x90,
            ],
            [
                0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x01, 0x89, 0x45, 0xfc, 0x66, 0x90,
            ],
            [
                0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00, 0x31, 0xc0, 0x0f, 0x1f,
            ],
        ];
        let mut state = 0x2545_f491u32;
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.extend_from_slice(&BODIES[(state >> 28) as usize % BODIES.len()]);
            // Far enough ahead that the address stays in the range the filter
            // converts however the member is sliced.
            let target = 0x0010_0000u32 + ((state >> 24) & 7) * 0x400;
            let call_end = (data.len() + 5) as u32;
            data.push(0xe8);
            data.extend_from_slice(&target.wrapping_sub(call_end).to_le_bytes());
        }
        data.truncate(len);
        data
    }

    /// Debug data: strings and symbol names, with enough stray call opcodes in
    /// the numbers between them for the scanner to call it code.
    ///
    /// The numbers behind those opcodes repeat, so converting them by position
    /// is the wrong way round: it turns a handful of repeated values into a
    /// different one every time and costs the encoder the matches. That is why
    /// filtering a whole unstripped binary makes it bigger.
    fn debug_like(len: usize) -> Vec<u8> {
        const WORDS: [&[u8]; 6] = [
            b"_ZN4llvm12FunctionPassE",
            b"/usr/include/c++/14/bits/",
            b"DW_AT_decl_file",
            b"unsigned long long int",
            b"__gnu_cxx::__normal_iterator",
            b"DW_TAG_subprogram",
        ];
        let mut state = 0x9e37_79b9u32;
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if state.is_multiple_of(37) {
                data.push(0xe8);
                data.extend_from_slice(
                    &(0x0004_0000u32 + ((state >> 20) & 3) * 0x40).to_le_bytes(),
                );
            } else {
                data.extend_from_slice(WORDS[(state >> 28) as usize % WORDS.len()]);
                data.push(0);
                data.extend_from_slice(&state.rotate_left(7).to_le_bytes());
            }
        }
        data.truncate(len);
        data
    }

    /// An unstripped binary in miniature: a code section, then a debug section
    /// several times its size that carries enough stray call opcodes to look
    /// like code to the scanner. Returns the member and where the code ends.
    fn code_then_debug() -> (Vec<u8>, usize) {
        let code_len = 132 * 1024;
        // Wider than the scanner's clustering gap, so the two stay separate
        // regions rather than merging into one.
        let gap = 48 * 1024;
        let mut data = calls_to_fixed_addresses(code_len);
        data.resize(code_len + gap, 0x5a);
        data.extend_from_slice(&debug_like(220 * 1024));
        (data, code_len)
    }

    /// The screen has to look past the biggest region. On an unstripped binary
    /// the biggest thing the scanner calls code is the debug data, and sampling
    /// only that declined the filter on every unstripped binary measured.
    #[test]
    fn the_x86_screen_looks_past_the_largest_region_to_the_code() {
        let (data, code_len) = code_then_debug();
        let regions = x86_code_regions(&data);
        let largest = regions
            .iter()
            .max_by_key(|range| range.len())
            .expect("the scanner has to find something");
        assert!(
            largest.start >= code_len,
            "this proves nothing unless the debug section is the largest region: {regions:?}"
        );

        let screen = x86_screened_regions(&FULL, &data, &regions, options()).unwrap();
        assert_eq!(
            screen.kept.len(),
            1,
            "the code region is the only one worth filtering: {:?}",
            screen.kept
        );
        assert!(
            screen.kept[0].end <= code_len + 1024,
            "kept {:?}",
            screen.kept
        );
        assert!(screen.rejected_a_region);
    }

    /// And the member as a whole has to come out smaller for it.
    #[test]
    fn the_search_filters_the_code_in_an_unstripped_binary() {
        let (data, _) = code_then_debug();
        let plain = FULL.encode_plain(&data, options(), None).unwrap();
        let (specs, packed) = choose_filter(&FULL, &data, options(), None).unwrap();

        assert!(
            matches!(
                specs.as_slice(),
                [FilterSpec {
                    kind: FilterKind::E8E9 | FilterKind::E8,
                    range: Some(_)
                }]
            ),
            "expected a ranged x86 filter, got {specs:?} at {} against {} unfiltered",
            packed.len(),
            plain.len()
        );
        assert!(packed.len() * 100 < plain.len() * 97);
    }

    #[test]
    fn the_search_never_loses_to_no_filter() {
        for data in [
            interleaved_counters(),
            b"the quick brown fox ".repeat(20_000),
            (0..300_000u32).map(|index| (index / 3) as u8).collect(),
            incompressible(200_000),
        ] {
            let plain = FULL.encode_plain(&data, options(), None).unwrap();
            let (specs, packed) = choose_filter(&FULL, &data, options(), None).unwrap();
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
        let data = vec![0u8; 5 * SCREEN_SAMPLE_LEN + 7];
        let sample = screen_sample(&data);
        assert_eq!(sample.len(), SCREEN_SAMPLE_LEN);
        let start = sample.as_ptr() as usize - data.as_ptr() as usize;
        assert_eq!(start % SCREEN_SAMPLE_ALIGNMENT, 0);
        assert!(start > 0 && start + sample.len() < data.len());
    }

    #[test]
    fn a_ranged_delta_filter_skips_container_edges_and_aligns_planes() {
        let data = vec![0u8; 512];
        let range = auto_delta_filter_range(&data, 3).unwrap();

        assert!(range.start >= AUTO_DELTA_EDGE_SKIP);
        assert!(range.end <= data.len() - AUTO_DELTA_EDGE_SKIP);
        assert_eq!(range.start % 3, 0);
        assert_eq!((range.end - range.start) % 3, 0);
        assert!(auto_delta_filter_range(&data[..80], 3).is_none());
    }

    /// Two ranges describing one region must come out as one range. Dropping
    /// the second instead, which one copy of this used to do, loses coverage of
    /// everything past the overlap.
    #[test]
    fn overlapping_ranges_merge_rather_than_drop() {
        assert_eq!(
            disjoint_filter_ranges(vec![0..100, 50..200, 400..500]),
            vec![0..200, 400..500]
        );
        assert_eq!(disjoint_filter_ranges(vec![0..100, 100..200]), vec![0..200]);
    }
}
