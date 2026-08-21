//! Choosing a filter for a member, for any format that has filters.
//!
//! The expensive part of picking a filter is that judging one means compressing
//! the member with it. Doing that for every filter a format offers, times every
//! region a scanner proposes, is most of the cost of writing an archive and
//! nearly all of it is spent proving that filters which were never going to help
//! do not help.
//!
//! So the candidates are cut down before any whole-member encode happens.
//! Filters with a structural detector behind them get their regions from the
//! detector and a sample encode per region to confirm the detector was not
//! fooled by chance byte patterns and to drop the regions where the filter
//! would cost more than it saves. The x86 pair detect code by its opcodes; the
//! table scanner detects arrays of fixed-size records by the stride they
//! repeat at, and its regions become ranged delta filters at the record size.
//! Filters with no detector are measured on a sample of the member and have to
//! win by a clear margin to earn a whole-member encode. What survives is a
//! handful of finalists, each encoded once at the caller's real settings,
//! smallest wins.
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

/// How much of the member the table scanner judges at a time.
///
/// A window is the resolution of the region boundaries: a table loses at most
/// one window at each end. Smaller windows find smaller tables and cost more
/// scanning per member.
const TABLE_SCAN_WINDOW: usize = 16 * 1024;

/// The widest record stride the table scanner looks for.
///
/// This is the scanner's own ceiling, traded against what it costs: every extra
/// stride is another comparison per byte of the member. What the *format* can
/// encode is a separate question, answered by
/// [`FilterSearch::max_delta_channels`], and the scan uses whichever is lower.
const MAX_TABLE_STRIDE: usize = 32;

/// How close a byte has to be to the one a stride back to count as part of the
/// record structure. Not just equal: a field that creeps, like an address
/// column, is exactly what delta flattens.
const TABLE_STRIDE_NEAR: u8 = 2;

/// How much of a window has to repeat at the winning stride before the window
/// counts as table-like, as a percentage. Code and text sit well under half
/// this at every stride; an array of structs sits well over it at the record
/// size, because most fields barely change from one record to the next.
const TABLE_STRIDE_HIT_PERCENT: usize = 40;

/// How close to the best stride's score a shorter stride has to come to be
/// preferred, as a percentage. An 8-byte record repeats at 16, 24 and 32 too,
/// and the shortest period is the record size; the tolerance keeps noise from
/// picking a harmonic.
const TABLE_STRIDE_TIE_PERCENT: usize = 95;

/// The smallest run of table-like windows worth a filter of its own.
const MIN_TABLE_REGION: usize = 2 * TABLE_SCAN_WINDOW;

/// How many table regions the progress estimate assumes the scanner will find.
///
/// Same reasoning as [`X86_ASSUMED_REGIONS`], and the same refusal to go and
/// measure: the binaries this was built for have one or two, being a
/// relocation table and sometimes a symbol table beside it.
const TABLE_ASSUMED_REGIONS: u64 = 2;

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

    /// The most channels this format's delta filter can carry.
    ///
    /// The table scanner picks a stride from the data rather than from
    /// [`FilterSearch::screened_kinds`], so this is how a format keeps it
    /// inside what the writer can encode. Deliberately has no default: a
    /// format that gets this wrong proposes a filter its own writer must then
    /// refuse, and there is no safe guess to make on its behalf.
    fn max_delta_channels(&self) -> usize;

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
    /// This is how a screen prices a filter it can only afford to try on a slice
    /// of the member: compress the transformed bytes and compare against the
    /// unfiltered ones. Comparing a filtered *encode* with an unfiltered one used
    /// to measure something else entirely. On a 396 KB binary the 128 KiB sample
    /// said the E8E9 filter cost 10% (74322 plain against 81744 filtered) while
    /// the same filter was worth 7.4% of the finished archive, so every x86
    /// member was screened out before anything measured it.
    ///
    /// That gap was the two paths cutting blocks at different sizes, fixed in
    /// 6ce759c: they now agree to within a filter token per block. So a screen
    /// that can encode the whole member goes straight to
    /// [`FilterSearch::encode_filtered`] and keeps the result, and this stays for
    /// the case it was written for, where the sample is a slice and there is
    /// nothing to keep.
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

/// What the screen made of one filter kind.
struct ScreenedKind {
    kind: FilterKind,
    /// The bytes, when the screen encoded the whole member the way the writer
    /// would write it, so the search can take this as its measurement.
    measured: Option<Vec<u8>>,
    /// Whether it beat leaving the data alone by enough to be worth spending
    /// another encode on a narrower range of the same filter.
    worth_a_range: bool,
}

/// What the screen learned, along with any encodes the search can reuse.
#[derive(Default)]
struct ScreenOutcome {
    kinds: Vec<ScreenedKind>,
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
///
/// A member no bigger than one sample is a special case worth taking. There is
/// no slice to approximate with, so the screen encodes it the way the writer
/// would and every number it produces is the measurement the search was going to
/// spend an encode on anyway. That skips a second encode per surviving kind, and
/// it lets kinds that win by too little to be worth chasing stay in the running,
/// because keeping a candidate the screen has already paid for costs nothing.
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
    // Only when the screen measures at the settings the finalists will use. A
    // format that screens at reduced effort, which RAR 2.9 does, is measuring
    // something else and keeps the two-encode path.
    let measures_the_member = sample.len() == data.len() && screen_options == options;
    let baseline = search.encode_plain(sample, screen_options, None)?;
    for kind in search.screened_kinds(data) {
        let filters = [FilterSpec::whole(kind)];
        let packed = if measures_the_member {
            search.encode_filtered(data, &filters, options, None)?
        } else {
            let transformed = search.filtered_bytes(sample, &filters)?;
            search.encode_plain(&transformed, screen_options, None)?
        };
        let worth_a_range = screen_wins(packed.len(), baseline.len());
        if measures_the_member {
            outcome.kinds.push(ScreenedKind {
                kind,
                measured: Some(packed),
                worth_a_range,
            });
        } else if worth_a_range {
            // The screen measured the transform, not the encode the writer
            // would emit, so this is evidence for a finalist rather than a
            // measurement the search can reuse.
            outcome.kinds.push(ScreenedKind {
                kind,
                measured: None,
                worth_a_range,
            });
        }
    }
    if measures_the_member {
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
///
/// A kept region is then asked the second question: does leaving the jump
/// opcodes alone beat converting them as well. That decides whether the E8-only
/// filter is worth a whole-member encode of its own, and the answer is usually
/// no. Over twenty-four members it won seven times and never by more than
/// 0.21%, while carrying the pair cost a third of the search; screening it here
/// keeps the wins and spends the encode only where a sample gives a reason to.
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
            kept.push((region.clone(), None));
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
        kept.push((region.clone(), Some(filtered.len())));
    }
    let rejected_a_region = kept.len() < regions.len();
    if !helped {
        return Ok(X86Screen::default());
    }

    // Held back until the regions are known to be worth filtering at all. Asking
    // per region inside the loop above priced the jump opcodes on members that
    // then declined every filter, which is a sample encode each for an answer
    // nothing reads.
    let mut jumps_cost_more = false;
    for (region, e8e9) in &kept {
        let Some(e8e9) = *e8e9 else { continue };
        let sample = screen_sample(&data[region.clone()]);
        let e8_only = search.filtered_bytes(sample, &[FilterSpec::whole(FilterKind::E8)])?;
        let e8_only = search.encode_plain(&e8_only, options, None)?;
        jumps_cost_more |= e8_only.len() < e8e9;
    }

    Ok(X86Screen {
        rejected_a_region,
        kept: kept.into_iter().map(|(region, _)| region).collect(),
        jumps_cost_more,
    })
}

/// What the x86 screen made of the regions the scanner proposed.
#[derive(Default)]
struct X86Screen {
    /// The regions worth filtering, empty when none of them is.
    kept: Vec<Range<usize>>,
    /// Whether any region came out bigger under the filter, which rules out
    /// filtering the member end to end.
    rejected_a_region: bool,
    /// Whether any kept region did better with the jump opcodes left alone,
    /// which is the only reason to price the E8-only filter separately. A tie
    /// does not count: it usually means the sample held no jump opcodes at all,
    /// so it is an absence of evidence, and acting on it costs a whole-member
    /// encode.
    jumps_cost_more: bool,
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
/// two.
///
/// And usually one kind rather than two, because the screen has already asked
/// whether the jump opcodes are worth converting. That takes an unstripped
/// binary from five whole-member encodes to two.
fn x86_finalists(data: &[u8], screen: &X86Screen) -> Vec<Vec<FilterSpec>> {
    let regions = &screen.kept;
    let covered: usize = regions.iter().map(|range| range.len()).sum();
    let (numerator, denominator) = X86_CODE_COVERAGE_RATIO;
    let sparse = covered * denominator < data.len() * numerator;
    let rejected_a_region = screen.rejected_a_region;

    let mut kinds = vec![FilterKind::E8E9];
    if screen.jumps_cost_more {
        kinds.push(FilterKind::E8);
    }

    let mut finalists = Vec::new();
    for kind in kinds {
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

/// The record stride this window repeats at, when it looks like an array of
/// fixed-size records at all.
///
/// An array of structs repeats at its record size: most fields hold the same or
/// a slowly moving value from one record to the next, so the byte one stride
/// back predicts this one. Code and text have no such period. The score is how
/// many bytes land within [`TABLE_STRIDE_NEAR`] of the byte a stride back,
/// and the shortest stride within [`TABLE_STRIDE_TIE_PERCENT`] of the best
/// wins, because a period repeats at its own multiples.
fn table_stride(window: &[u8], max_stride: usize) -> Option<usize> {
    if max_stride == 0 || window.len() < max_stride * 8 {
        return None;
    }
    let mut hits = [0usize; MAX_TABLE_STRIDE + 1];
    for index in max_stride..window.len() {
        let byte = window[index];
        for stride in 1..=max_stride {
            let diff = (byte.wrapping_sub(window[index - stride]) as i8).unsigned_abs();
            hits[stride] += usize::from(diff <= TABLE_STRIDE_NEAR);
        }
    }
    let total = window.len() - max_stride;
    let best = *hits[1..=max_stride]
        .iter()
        .max()
        .expect("there is at least one stride");
    if best * 100 < total * TABLE_STRIDE_HIT_PERCENT {
        return None;
    }
    (1..=max_stride).find(|&stride| hits[stride] * 100 >= best * TABLE_STRIDE_TIE_PERCENT)
}

/// Where the member holds arrays of fixed-size records, each with the stride
/// it repeats at.
///
/// This is what the whole-member delta screens cannot see: a relocation table
/// is a few hundred kilobytes of 24-byte records inside a binary that delta
/// with stride 24 nearly halves, while the same filter over the whole member
/// is a disaster. On a 3.6 MB shared object the table packed to 32,767 bytes
/// against 59,512 unfiltered; delta 24 over the whole member came out 85%
/// *bigger* than no filter at all. The filter has to cover the table and stop.
fn delta_table_regions(data: &[u8], max_stride: usize) -> Vec<(Range<usize>, usize)> {
    let max_stride = max_stride.min(MAX_TABLE_STRIDE);
    let mut regions: Vec<(Range<usize>, usize)> = Vec::new();
    for start in (0..).map(|window| window * TABLE_SCAN_WINDOW) {
        let Some(window) = data.get(start..start + TABLE_SCAN_WINDOW) else {
            break;
        };
        let Some(stride) = table_stride(window, max_stride) else {
            continue;
        };
        match regions.last_mut() {
            Some((last, last_stride)) if *last_stride == stride && last.end == start => {
                last.end = start + TABLE_SCAN_WINDOW;
            }
            _ => regions.push((start..start + TABLE_SCAN_WINDOW, stride)),
        }
    }
    regions.retain(|(range, _)| range.len() >= MIN_TABLE_REGION);
    regions
}

/// Which of the scanner's table regions the delta filter actually shrinks.
///
/// The scanner reads byte statistics, and repetition at a stride is also
/// something the match finder can sometimes reach on its own; a run of
/// constant bytes scores as a table at every stride and needs no filter at
/// all. A sample encode inside the region separates the tables delta helps
/// from the ones LZ was already handling, the same way the x86 screen checks
/// its scanner.
fn table_screened_regions<S: FilterSearch>(
    search: &S,
    data: &[u8],
    regions: &[(Range<usize>, usize)],
    options: S::Options,
) -> Result<Vec<(Range<usize>, usize)>> {
    let screen_options = search.screen_options(options);
    let mut kept = Vec::new();
    for (region, stride) in regions {
        let sample = screen_sample(&data[region.clone()]);
        if sample.len() < SCREEN_SAMPLE_ALIGNMENT {
            continue;
        }
        let baseline = search.encode_plain(sample, screen_options, None)?;
        let filters = [FilterSpec::whole(FilterKind::Delta { channels: *stride })];
        let transformed = search.filtered_bytes(sample, &filters)?;
        let filtered = search.encode_plain(&transformed, screen_options, None)?;
        if screen_wins(filtered.len(), baseline.len()) {
            kept.push((region.clone(), *stride));
        }
    }
    Ok(kept)
}

/// `range` with the `removed` ranges cut out of it. `removed` must be sorted
/// and disjoint.
fn subtract_ranges(range: Range<usize>, removed: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut kept = Vec::new();
    let mut start = range.start;
    for cut in removed {
        if cut.end <= start {
            continue;
        }
        if cut.start >= range.end {
            break;
        }
        if cut.start > start {
            kept.push(start..cut.start);
        }
        start = start.max(cut.end);
    }
    if start < range.end {
        kept.push(start..range.end);
    }
    kept
}

/// A finalist with the screened tables riding along: the table ranges are cut
/// out of whatever the specs covered, and delta at the record stride takes
/// their place. Empty specs come out as a tables-only candidate.
///
/// The tables win where the two overlap. A verified table stride is worth
/// tens of percent of its region where the x86 filter is worth a few. This
/// used to build one bundled candidate that competed with the x86 finalists
/// instead, and on an unstripped binary the x86-only finalist won, taking the
/// tables down with the debug data they were bundled against. Grafting the
/// tables into every finalist lets them ride with whichever x86 variant wins.
fn graft_tables(
    specs: Vec<FilterSpec>,
    tables: &[(Range<usize>, usize)],
    member: usize,
) -> Vec<FilterSpec> {
    if tables.is_empty() {
        return specs;
    }
    let table_ranges: Vec<Range<usize>> = tables.iter().map(|(range, _)| range.clone()).collect();
    let mut grafted: Vec<FilterSpec> = specs
        .into_iter()
        .flat_map(|spec| {
            let covered = spec.range.clone().unwrap_or(0..member);
            subtract_ranges(covered, &table_ranges)
                .into_iter()
                .map(move |range| FilterSpec::range(spec.kind, range))
        })
        .collect();
    grafted.extend(tables.iter().map(|(range, stride)| {
        FilterSpec::range(FilterKind::Delta { channels: *stride }, range.clone())
    }));
    grafted.sort_by_key(|spec| spec.range.as_ref().map_or(0, |range| range.start));
    grafted
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

    let table_regions = delta_table_regions(data, search.max_delta_channels());
    let tables = table_screened_regions(search, data, &table_regions, options)?;

    // The tables graft into every x86 finalist rather than competing against
    // them, so when the x86 screen kept anything they cost no encode of their
    // own. Only a member with tables and no code pays for a tables-only
    // candidate.
    let mut tables_carried = false;
    if search.detects_x86() {
        let screen = x86_screened_regions(search, data, &x86_code_regions(data), options)?;
        if !screen.kept.is_empty() {
            tables_carried = !tables.is_empty();
            finalists.extend(
                x86_finalists(data, &screen)
                    .into_iter()
                    .map(|specs| (graft_tables(specs, &tables, data.len()), None)),
            );
        }
    }
    if !tables.is_empty() && !tables_carried {
        finalists.push((graft_tables(Vec::new(), &tables, data.len()), None));
    }

    for screened in screen.kinds {
        finalists.push((vec![FilterSpec::whole(screened.kind)], screened.measured));
        if let (true, FilterKind::Delta { channels }) = (screened.worth_a_range, screened.kind) {
            if let Some(range) = auto_delta_filter_range(data, channels) {
                finalists.push((vec![FilterSpec::range(screened.kind, range)], None));
            }
        }
    }

    Ok(finalists)
}

/// The candidate filter lists, screened but not ranked.
///
/// The screens still run: whether a filter has any chance on this member is a
/// property of the member's own bytes, and a sample answers it the same way
/// whoever is going to measure the survivors. What this hands back is the
/// ranking, for a caller whose real encoder is not the one
/// [`FilterSearch::encode_filtered`] describes.
///
/// A solid chain is that caller. Its members code against everything before
/// them, so a candidate encoded on its own has not been measured at all, and
/// the bytes [`choose_filter`] returns are bytes the chain would never write.
pub(crate) fn filter_candidates<S: FilterSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<Vec<Vec<FilterSpec>>> {
    Ok(finalists(search, data, options)?
        .into_iter()
        .map(|(specs, _measured)| specs)
        .collect())
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
    // And two more per table region, on the same assumption and with the same
    // bound. Tables graft into the x86 finalists rather than earning an encode
    // of their own, and this already assumes the detector finds code, so they
    // add nothing beyond their screens here.
    let table_screen = (sample * TABLE_ASSUMED_REGIONS).min(member) * 2;
    let screen = sample * (screened + 1) + x86_screen + table_screen;
    // The unfiltered member, the x86 finalists, and one assumed screen
    // survivor. When the sample is the whole member the screen encodes it the
    // way the writer would, so the unfiltered member and the survivor are
    // already counted in `screen`. That reads the sample rather than asking
    // whether this format screens at full effort, which needs the caller's
    // settings; RAR 5 is the only format that reports progress through here
    // and it always does.
    let finalists = if sample == member {
        x86_finalists
    } else {
        2 + x86_finalists
    };
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

        fn max_delta_channels(&self) -> usize {
            crate::codec::rar50::MAX_DELTA_CHANNELS
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
            .map(|screened| screened.kind)
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

    /// A member that fits in one sample has no slice to approximate with, so
    /// the screen encodes it the way the writer would and the search keeps every
    /// number rather than paying for the winners twice.
    #[test]
    fn a_short_member_is_measured_by_the_screen_rather_than_encoded_twice() {
        let data = interleaved_counters()[..100_000].to_vec();
        assert!(data.len() <= SCREEN_SAMPLE_LEN);
        let screen = screen_kinds(&FULL, &data, options()).unwrap();

        assert!(screen.plain.is_some(), "the unfiltered encode is reusable");
        assert_eq!(
            screen.kinds.len(),
            FULL.screened_kinds(&data).len(),
            "a kind the screen has already encoded is worth keeping whether or \
             not it won by the margin"
        );
        for screened in &screen.kinds {
            let measured = screened
                .measured
                .as_ref()
                .unwrap_or_else(|| panic!("{:?} came back without its bytes", screened.kind));
            // Not just present: the same bytes the writer would emit for it.
            // Anything else is a number the search cannot stand on.
            let written = FULL
                .encode_filtered(&data, &[FilterSpec::whole(screened.kind)], options(), None)
                .unwrap();
            assert_eq!(*measured, written, "{:?}", screened.kind);
        }
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
        assert!(screen
            .kinds
            .iter()
            .all(|screened| screened.measured.is_none()));
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

    /// The E8-only filter costs a whole-member encode to ask whether leaving
    /// the jump opcodes alone packs better. Over twenty-four members it won
    /// seven times and never by more than 0.21%, so it only earns that encode
    /// when a sample says it might.
    #[test]
    fn the_jump_opcodes_are_priced_on_a_sample_before_they_earn_an_encode() {
        let (data, _) = code_then_debug();
        let regions = x86_code_regions(&data);
        let screen = x86_screened_regions(&FULL, &data, &regions, options()).unwrap();
        let kinds: Vec<_> = x86_finalists(&data, &screen)
            .iter()
            .map(|specs| specs[0].kind)
            .collect();

        // Every call here goes to a fixed address, which is what the jump
        // conversion is for, so this member is one where converting both pays.
        assert!(!screen.jumps_cost_more, "{kinds:?}");
        assert_eq!(
            kinds,
            [FilterKind::E8E9],
            "the E8-only candidate cost an encode nothing asked for"
        );
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

    /// A relocation table in miniature: 24-byte records of three 8-byte fields
    /// that creep or repeat from one record to the next. What makes it a filter
    /// case is that the creeping fields never repeat exactly, so the match
    /// finder gets nothing, while their stride-24 differences are constants.
    fn reloc_table(records: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(records * 24);
        for index in 0..records as u64 {
            data.extend_from_slice(&(0x7f80_1234_0000 + index * 24).to_le_bytes());
            data.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
            data.extend_from_slice(&(0x4455_6677_0000 | ((index * 7) & 0xffff)).to_le_bytes());
        }
        data
    }

    #[test]
    fn a_struct_table_scans_as_its_record_stride() {
        let data = reloc_table(20_000);
        let regions = delta_table_regions(&data, MAX_TABLE_STRIDE);
        assert_eq!(regions.len(), 1, "{regions:?}");
        let (region, stride) = &regions[0];
        assert_eq!(*stride, 24, "the record size is the shortest true period");
        assert!(
            region.len() * 10 >= data.len() * 9,
            "the region has to cover the table: {region:?} of {}",
            data.len()
        );
    }

    #[test]
    fn text_and_random_bytes_do_not_scan_as_tables() {
        for data in [
            b"the quick brown fox jumps over the lazy dog ".repeat(6_000),
            incompressible(256 * 1024),
        ] {
            assert_eq!(
                delta_table_regions(&data, MAX_TABLE_STRIDE),
                vec![],
                "{} bytes",
                data.len()
            );
        }
    }

    /// x86 instructions are variable length, so code has no byte period for the
    /// scanner to lock onto. [`calls_to_fixed_addresses`] is no use for proving
    /// that: it emits a fixed 16-byte unit, which really is a record array as
    /// far as any stride test can tell. This mixes instruction lengths the way
    /// a compiler does, so a false table here would be a false table on a real
    /// `.text`.
    fn variable_length_code(len: usize) -> Vec<u8> {
        const INSTRUCTIONS: [&[u8]; 7] = [
            &[0x55],                                     // push rbp
            &[0x48, 0x89, 0xe5],                         // mov rbp, rsp
            &[0x8b, 0x45, 0xfc],                         // mov eax, [rbp-4]
            &[0x48, 0x83, 0xec, 0x20],                   // sub rsp, 32
            &[0x0f, 0xb6, 0x54, 0x18, 0x01],             // movzx edx, [rax+rbx+1]
            &[0x48, 0x8d, 0x35, 0x12, 0x00, 0x00, 0x00], // lea rsi, [rip+18]
            &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0, 0, 0, 0], // nop word [rax+rax]
        ];
        let mut state = 0x2545_f491u32;
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.extend_from_slice(INSTRUCTIONS[(state >> 27) as usize % INSTRUCTIONS.len()]);
        }
        data.truncate(len);
        data
    }

    #[test]
    fn real_shaped_code_does_not_scan_as_a_table() {
        let data = variable_length_code(256 * 1024);
        assert_eq!(
            delta_table_regions(&data, MAX_TABLE_STRIDE),
            vec![],
            "variable-length instructions have no record stride to find"
        );
    }

    /// And the property that actually matters: even where the scanner does fire
    /// on code, nothing reaches the encoder unless a sample encode agrees.
    #[test]
    fn code_never_reaches_the_encoder_as_a_delta_candidate() {
        for data in [
            variable_length_code(256 * 1024),
            calls_to_fixed_addresses(256 * 1024),
        ] {
            let regions = delta_table_regions(&data, MAX_TABLE_STRIDE);
            assert_eq!(
                table_screened_regions(&FULL, &data, &regions, options()).unwrap(),
                vec![],
                "the screen let a delta filter onto code: {regions:?}"
            );
        }
    }

    /// A format that cannot encode a wide delta must never be handed one. The
    /// scan is bounded by what the writer can say, not only by the data.
    #[test]
    fn the_scan_stays_inside_what_the_format_can_encode() {
        let data = reloc_table(20_000);
        assert_eq!(delta_table_regions(&data, MAX_TABLE_STRIDE)[0].1, 24);
        for (region, stride) in delta_table_regions(&data, 8) {
            assert!(stride <= 8, "{region:?} asked for {stride} channels");
        }
        assert_eq!(delta_table_regions(&data, 0), vec![]);
    }

    /// Constant bytes repeat at every stride, so the scanner calls them a
    /// table, but the encoder handles a run perfectly well on its own. The
    /// sample encode is what stops a useless filter there.
    #[test]
    fn a_run_of_constant_bytes_screens_out_of_the_table_regions() {
        let data = vec![0u8; 200 * 1024];
        let regions = delta_table_regions(&data, MAX_TABLE_STRIDE);
        assert!(!regions.is_empty(), "the scanner sees repetition in a run");
        assert_eq!(
            table_screened_regions(&FULL, &data, &regions, options()).unwrap(),
            vec![]
        );
    }

    #[test]
    fn subtracting_ranges_cuts_the_tables_out_of_the_code() {
        assert_eq!(
            subtract_ranges(0..1000, &[200..300, 600..700]),
            vec![0..200, 300..600, 700..1000]
        );
        assert_eq!(
            subtract_ranges(100..200, &[0..250, 300..400]),
            Vec::<Range<usize>>::new()
        );
        assert_eq!(
            subtract_ranges(100..200, &[0..50, 300..400]),
            vec![100..200]
        );
        assert_eq!(
            subtract_ranges(100..200, &[150..400, 500..600]),
            vec![100..150]
        );
    }

    /// The point of the whole scanner: a binary with a table in it comes out
    /// with delta at the record stride over the table, and only there.
    #[test]
    fn the_search_deltas_the_table_inside_a_binary() {
        let code_len = 132 * 1024;
        let mut data = calls_to_fixed_addresses(code_len);
        let table_start = data.len();
        data.extend_from_slice(&reloc_table(20_000));

        let plain = FULL.encode_plain(&data, options(), None).unwrap();
        let (specs, packed) = choose_filter(&FULL, &data, options(), None).unwrap();

        let delta = specs
            .iter()
            .find(|spec| matches!(spec.kind, FilterKind::Delta { channels: 24 }))
            .unwrap_or_else(|| panic!("no stride-24 delta among {specs:?}"));
        let range = delta.range.clone().expect("the table filter is ranged");
        assert!(
            range.start >= table_start.saturating_sub(TABLE_SCAN_WINDOW)
                && range.start < table_start + TABLE_SCAN_WINDOW,
            "the filter starts at the table, not the code: {range:?} against {table_start}"
        );
        for spec in &specs {
            let other = spec.range.clone().expect("every spec here is ranged");
            assert!(
                spec == delta || other.end <= range.start || other.start >= range.end,
                "{specs:?} overlap"
            );
        }
        assert!(
            packed.len() * 100 < plain.len() * 90,
            "the table filter is worth a lot more than this: {} against {}",
            packed.len(),
            plain.len()
        );
    }

    #[test]
    fn grafting_cuts_the_tables_out_of_whatever_the_specs_covered() {
        let tables = [(200..300, 24), (600..700, 8)];
        assert_eq!(
            graft_tables(vec![FilterSpec::whole(FilterKind::E8E9)], &tables, 1000),
            vec![
                FilterSpec::range(FilterKind::E8E9, 0..200),
                FilterSpec::range(FilterKind::Delta { channels: 24 }, 200..300),
                FilterSpec::range(FilterKind::E8E9, 300..600),
                FilterSpec::range(FilterKind::Delta { channels: 8 }, 600..700),
                FilterSpec::range(FilterKind::E8E9, 700..1000),
            ]
        );
        assert_eq!(
            graft_tables(Vec::new(), &tables[..1], 1000),
            vec![FilterSpec::range(
                FilterKind::Delta { channels: 24 },
                200..300
            )]
        );
        let code_only = vec![FilterSpec::range(FilterKind::E8, 0..100)];
        assert_eq!(graft_tables(code_only.clone(), &[], 1000), code_only);
    }

    /// The member this change exists for: an unstripped binary with a
    /// relocation table in it. The bundled candidate this replaces lost to the
    /// x86-only finalist here, because it carried the tables and the trimmed
    /// code coverage as one bet, and the table went unfiltered with it.
    #[test]
    fn the_winner_filters_the_code_and_deltas_the_table_in_one_member() {
        let (mut data, code_len) = code_then_debug();
        let table_start = data.len();
        data.extend_from_slice(&reloc_table(20_000));

        let (specs, _) = choose_filter(&FULL, &data, options(), None).unwrap();
        let filters_the_code = specs.iter().any(|spec| {
            matches!(spec.kind, FilterKind::E8 | FilterKind::E8E9)
                && spec
                    .range
                    .as_ref()
                    .is_some_and(|range| range.start < code_len)
        });
        let deltas_the_table = specs.iter().any(|spec| {
            matches!(spec.kind, FilterKind::Delta { channels: 24 })
                && spec
                    .range
                    .as_ref()
                    .is_some_and(|range| range.start >= table_start - TABLE_SCAN_WINDOW)
        });
        assert!(
            filters_the_code && deltas_the_table,
            "one of the two regions went unfiltered: {specs:?}"
        );
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
