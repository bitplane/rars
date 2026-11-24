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
//! handful of finalists. A trial on windows of the member ranks them and only
//! the winner is encoded at the caller's real settings; a small member, or a
//! search that asks for it, has every finalist encoded in full and the smallest
//! wins. Only that full comparison is sure never to come out larger than
//! leaving the data alone.

use crate::codec::workspace::{Allowance, Budget, Buffer};
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

/// How much of the member the table scanner judges at a time, unless the
/// format asks for another size (see [`OwnedSearch::table_scan_window`]).
///
/// A window is the resolution of the region boundaries: a table loses at most
/// one window at each end, and the smallest table found is two windows long.
/// Smaller windows find smaller tables, and every table found is another
/// sample to screen and another filter record to write.
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

/// How many table-like windows in a row are worth a filter of their own.
const MIN_TABLE_WINDOWS: usize = 2;

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

    /// How much of the member the table scanner judges at a time: the
    /// resolution its regions are found at. See [`TABLE_SCAN_WINDOW`].
    fn table_scan_window(&self) -> usize {
        TABLE_SCAN_WINDOW
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

    /// Whether every finalist is encoded in full at the caller's settings,
    /// rather than ranked by a trial on windows of the member. See
    /// [`OwnedSearch::exhaustive`].
    fn exhaustive(&self) -> bool {
        false
    }

    /// Apply the filters to a copy of `data`, without encoding it.
    ///
    /// This is how a screen prices a filter it can only afford to try on a slice
    /// of the member: compress the transformed bytes and compare against the
    /// unfiltered ones. A screen that can encode the whole member uses
    /// [`FilterSearch::encode_filtered`] instead and keeps the result; this is
    /// for a sample slice, where there is nothing to keep.
    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Vec<u8>>;

    /// [`FilterSearch::filtered_bytes`] for `data` lying `offset` bytes into
    /// the data searched, which the x86 filters convert by position. The
    /// filters' ranges are in `data`.
    ///
    /// Defaults to filtering `data` behind `offset` bytes of padding, which a
    /// format whose filters can start at an offset should not pay for.
    fn filtered_window(
        &self,
        data: &[u8],
        offset: usize,
        filters: &[FilterSpec],
    ) -> Result<Vec<u8>> {
        let mut padded = vec![0; offset];
        padded.extend_from_slice(data);
        let filters: Vec<FilterSpec> = filters
            .iter()
            .map(|spec| {
                let range = spec.range.clone().unwrap_or(0..data.len());
                FilterSpec::range(spec.kind, offset + range.start..offset + range.end)
            })
            .collect();
        let mut filtered = self.filtered_bytes(&padded, &filters)?;
        filtered.drain(..offset);
        Ok(filtered)
    }

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

pub(crate) type FilterChoice<B> = (Buffer<FilterSpec, B>, Buffer<u8, B>);
type Finalist<B> = (Buffer<FilterSpec, B>, Option<Buffer<u8, B>>);
type TableRegions<B> = Buffer<(Range<usize>, usize), B>;

/// Search owners cannot detach bounded byte storage while candidates compete.
pub(crate) trait OwnedSearch {
    type Options: Copy + PartialEq;
    type Memory: Budget;
    fn allowance(&self) -> &Self::Memory;
    fn screened_kinds(&self, data: &[u8]) -> Result<Buffer<FilterKind, Self::Memory>>;
    fn detects_x86(&self) -> bool;
    /// Whether to measure the E8-only filter wherever the x86 screen keeps
    /// code, rather than only where a sample says the jumps cost more. See
    /// [`x86_screened_regions`].
    fn prices_calls_alone(&self) -> bool {
        false
    }
    fn max_delta_channels(&self) -> usize;
    /// See [`FilterSearch::table_scan_window`].
    fn table_scan_window(&self) -> usize {
        TABLE_SCAN_WINDOW
    }
    fn screen_options(&self, options: Self::Options) -> Self::Options;
    /// Whether every finalist is encoded in full at the caller's settings and
    /// the smallest kept, rather than the finalists ranked by a trial and only
    /// the winner encoded. See [`trial_winner`].
    fn exhaustive(&self) -> bool {
        false
    }
    fn filtered_bytes(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
    ) -> Result<Buffer<u8, Self::Memory>>;
    /// See [`FilterSearch::filtered_window`], and the same default.
    fn filtered_window(
        &self,
        data: &[u8],
        offset: usize,
        filters: &[FilterSpec],
    ) -> Result<Buffer<u8, Self::Memory>> {
        let mut padded = Buffer::filled(offset + data.len(), 0, self.allowance())?;
        padded[offset..].copy_from_slice(data);
        let filters = Buffer::collect(
            filters.iter().map(|spec| {
                let range = spec.range.clone().unwrap_or(0..data.len());
                FilterSpec::range(spec.kind, offset + range.start..offset + range.end)
            }),
            self.allowance(),
        )?;
        let mut filtered = self.filtered_bytes(&padded, &filters)?;
        filtered.discard_prefix(offset);
        Ok(filtered)
    }
    fn encode_plain(
        &self,
        data: &[u8],
        options: Self::Options,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, Self::Memory>>;
    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: Self::Options,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, Self::Memory>>;
}
struct UnlimitedSearch<'a, S>(&'a S, Allowance);
impl<S: FilterSearch> OwnedSearch for UnlimitedSearch<'_, S> {
    type Options = S::Options;
    type Memory = Allowance;
    fn allowance(&self) -> &Allowance {
        &self.1
    }
    fn screened_kinds(&self, data: &[u8]) -> Result<Buffer<FilterKind>> {
        Ok(Buffer::from_vec(self.0.screened_kinds(data)))
    }
    fn detects_x86(&self) -> bool {
        self.0.detects_x86()
    }
    fn max_delta_channels(&self) -> usize {
        self.0.max_delta_channels()
    }
    fn table_scan_window(&self) -> usize {
        self.0.table_scan_window()
    }
    fn screen_options(&self, options: Self::Options) -> Self::Options {
        self.0.screen_options(options)
    }
    fn exhaustive(&self) -> bool {
        self.0.exhaustive()
    }
    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Buffer<u8>> {
        self.0.filtered_bytes(data, filters).map(Buffer::from_vec)
    }
    fn filtered_window(
        &self,
        data: &[u8],
        offset: usize,
        filters: &[FilterSpec],
    ) -> Result<Buffer<u8>> {
        self.0
            .filtered_window(data, offset, filters)
            .map(Buffer::from_vec)
    }
    fn encode_plain(
        &self,
        data: &[u8],
        options: Self::Options,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8>> {
        self.0
            .encode_plain(data, options, progress)
            .map(Buffer::from_vec)
    }
    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: Self::Options,
        progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8>> {
        self.0
            .encode_filtered(data, filters, options, progress)
            .map(Buffer::from_vec)
    }
}

/// Internal events: codec positions are absolute only within one encode pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodeProgress {
    PassStarted,
    Advanced(usize),
}

/// Adapt a single codec pass without inferring restarts from byte positions.
pub(crate) fn encode_pass<T>(
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
    encode: impl FnOnce(Option<&mut dyn FnMut(usize) -> bool>) -> Result<T>,
) -> Result<T> {
    match progress {
        Some(progress) => {
            if !progress(EncodeProgress::PassStarted) {
                return Err(crate::Error::Cancelled);
            }
            encode(Some(&mut |position| {
                progress(EncodeProgress::Advanced(position))
            }))
        }
        None => encode(None),
    }
}

/// Observe every encode in a search, including sample screens which previously
/// discarded the caller's progress/cancellation callback. The codec adapter and
/// search decisions remain unchanged.
struct ReportingSearch<'a, S> {
    search: &'a S,
    progress: std::cell::RefCell<&'a mut dyn FnMut(EncodeProgress) -> bool>,
}
impl<S: OwnedSearch> OwnedSearch for ReportingSearch<'_, S> {
    type Options = S::Options;
    type Memory = S::Memory;
    fn allowance(&self) -> &Self::Memory {
        self.search.allowance()
    }
    fn screened_kinds(&self, data: &[u8]) -> Result<Buffer<FilterKind, S::Memory>> {
        self.search.screened_kinds(data)
    }
    fn detects_x86(&self) -> bool {
        self.search.detects_x86()
    }
    fn prices_calls_alone(&self) -> bool {
        self.search.prices_calls_alone()
    }
    fn max_delta_channels(&self) -> usize {
        self.search.max_delta_channels()
    }
    fn table_scan_window(&self) -> usize {
        self.search.table_scan_window()
    }
    fn screen_options(&self, options: Self::Options) -> Self::Options {
        self.search.screen_options(options)
    }
    fn exhaustive(&self) -> bool {
        self.search.exhaustive()
    }
    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Buffer<u8, S::Memory>> {
        self.search.filtered_bytes(data, filters)
    }
    fn filtered_window(
        &self,
        data: &[u8],
        offset: usize,
        filters: &[FilterSpec],
    ) -> Result<Buffer<u8, S::Memory>> {
        self.search.filtered_window(data, offset, filters)
    }
    fn encode_plain(
        &self,
        data: &[u8],
        options: Self::Options,
        _: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, S::Memory>> {
        encode_pass(Some(&mut **self.progress.borrow_mut()), |progress| {
            self.search.encode_plain(data, options, progress)
        })
    }
    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: Self::Options,
        _: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, S::Memory>> {
        encode_pass(Some(&mut **self.progress.borrow_mut()), |progress| {
            self.search
                .encode_filtered(data, filters, options, progress)
        })
    }
}

/// Whether looking for a filter is worth starting at all.
///
/// An empty member has nothing to filter, and text does not benefit from any of
/// them, so neither should cost a single encode to find that out.
fn search_applies(data: &[u8]) -> bool {
    !data.is_empty() && !is_text_like(data)
}

fn is_text_like(data: &[u8]) -> bool {
    let sample_len = data.len().min(TEXT_SAMPLE_LEN);
    // `search_applies` screens empty members before calling this helper.
    text_byte_count(&data[..sample_len]) * 100 / sample_len >= 95
}

/// How much of a member [`search_applies_throughout`] reads at each place.
const TEXT_SAMPLE_LEN: usize = 8192;

/// How many places across a member [`search_applies_throughout`] reads.
const TEXT_SAMPLES: usize = 16;

/// [`search_applies`], judged from samples spread across the whole of `data`
/// rather than from its start.
///
/// A member's first bytes need not say what the rest is. A tar of `/usr`
/// can open with a script and go on to megabytes of ELF code, and judged by
/// its first 8 KiB the whole member was taken for text and never searched.
/// Cut into runs, the same bytes were searched wherever a run did not open
/// with text, so the two paths came out 7% apart. Sixteen samples cost
/// nothing next to one encode, and the whole member and each of its runs are
/// then judged by what they hold.
///
/// The RAR 1.5 to 4 writer asks the same question of a whole member, of each
/// segment of a streamed one and of each member of a solid chain, and gets the
/// same answer. A shell script carrying an ELF payload had gone unsearched
/// there too, and came out 4% to 5% larger at every level.
pub(crate) fn search_applies_throughout(data: &[u8]) -> bool {
    if data.len() <= TEXT_SAMPLE_LEN * 2 {
        return search_applies(data);
    }
    let samples = TEXT_SAMPLES.min(data.len() / TEXT_SAMPLE_LEN);
    let stride = data.len() / samples;
    let text_bytes: usize = (0..samples)
        .map(|sample| text_byte_count(&data[sample * stride..][..TEXT_SAMPLE_LEN]))
        .sum();
    text_bytes * 100 / (samples * TEXT_SAMPLE_LEN) < 95
}

fn text_byte_count(sample: &[u8]) -> usize {
    sample
        .iter()
        .filter(|&&byte| matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count()
}

fn screen_wins(filtered: usize, baseline: usize) -> bool {
    filtered * 100 < baseline * (100 - SCREEN_MARGIN_PERCENT)
}

/// A window from the middle of the member, used to screen the filters that have
/// nothing but a trial encode to go on.
fn screen_sample(data: &[u8]) -> &[u8] {
    &data[screen_sample_range(data.len())]
}

/// Where [`screen_sample`] takes its window from, in a member this long.
fn screen_sample_range(len: usize) -> Range<usize> {
    if len <= SCREEN_SAMPLE_LEN {
        return 0..len;
    }
    let middle = (len - SCREEN_SAMPLE_LEN) / 2;
    let start = middle / SCREEN_SAMPLE_ALIGNMENT * SCREEN_SAMPLE_ALIGNMENT;
    start..start + SCREEN_SAMPLE_LEN
}

/// A sample of the member as `kind` would leave it, filtered where it lies.
///
/// The x86 filters turn a call's displacement into the address it reaches, and
/// leave alone a call that reaches outside the file. Filtered on its own, a
/// sample starts at address zero, so every call back past its first byte looks
/// like one of those and stays as it was: half the calls in ordinary code. The
/// screen then prices a filter doing half its work, and that is the price it
/// turned regions down at. So the member is filtered up to the end of the
/// sample, over the sample's range only, and the sample is read back out.
fn filtered_sample<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    sample: Range<usize>,
    kind: FilterKind,
) -> Result<Buffer<u8, S::Memory>> {
    let filters = [FilterSpec::range(kind, sample.clone())];
    let mut filtered = search.filtered_bytes(&data[..sample.end], &filters)?;
    filtered.discard_prefix(sample.start);
    Ok(filtered)
}

/// What the screen made of one filter kind.
struct ScreenedKind<B: Budget> {
    kind: FilterKind,
    /// The bytes, when the screen encoded the whole member the way the writer
    /// would write it, so the search can take this as its measurement.
    measured: Option<Buffer<u8, B>>,
    /// Whether it beat leaving the data alone by enough to be worth spending
    /// another encode on a narrower range of the same filter.
    worth_a_range: bool,
}

/// What the screen learned, along with any encodes the search can reuse.
struct ScreenOutcome<B: Budget> {
    kinds: Buffer<ScreenedKind<B>, B>,
    plain: Option<Buffer<u8, B>>,
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
fn screen_kinds<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<ScreenOutcome<S::Memory>> {
    let sample = screen_sample(data);
    let mut outcome = ScreenOutcome {
        kinds: Buffer::new(search.allowance()),
        plain: None,
    };
    if sample.len() < SCREEN_SAMPLE_ALIGNMENT {
        return Ok(outcome);
    }
    let screen_options = search.screen_options(options);
    // Only when the screen measures at the settings the finalists will use. A
    // format that screens at reduced effort, which RAR 2.9 does, is measuring
    // something else and keeps the two-encode path.
    let measures_the_member = sample.len() == data.len() && screen_options == options;
    let baseline = search.encode_plain(sample, screen_options, None)?;
    let mut sampled = Buffer::new(search.allowance());
    for kind in search.screened_kinds(data)? {
        let filters = [FilterSpec::whole(kind)];
        let packed = if measures_the_member {
            search.encode_filtered(data, &filters, options, None)?
        } else {
            let transformed = search.filtered_bytes(sample, &filters)?;
            search.encode_plain(&transformed, screen_options, None)?
        };
        let worth_a_range = screen_wins(packed.len(), baseline.len());
        if measures_the_member {
            outcome.kinds.try_push(ScreenedKind {
                kind,
                measured: Some(packed),
                worth_a_range,
            })?;
        } else if worth_a_range {
            // The screen measured the transform, not the encode the writer
            // would emit, so this is evidence for a finalist rather than a
            // measurement the search can reuse.
            sampled.try_push((
                ScreenedKind {
                    kind,
                    measured: None,
                    worth_a_range,
                },
                packed.len(),
            ))?;
        }
    }
    // A kind the sample shows losing to another by the same margin it has to
    // beat the plain member by is not worth a whole-member encode either. On
    // 16-bit stereo audio delta 2 and delta 4 both clear the screen, and delta
    // 2 then cost two whole encodes, its own and its ranged one, to come out
    // 6% behind delta 4 as the sample already said it would.
    //
    // Only when the screen ran at the finalists' own settings. A screen at
    // reduced effort, as RAR 2.9 runs above its lowest level, is fit to say
    // whether a kind helps at all but not which of two helps more: on a few
    // hundred bytes of stereo samples it ranked another kind 1% ahead of the
    // delta that won the real encode.
    let ranks = screen_options == options;
    let best = sampled.iter().map(|&(_, packed)| packed).min();
    for (kind, packed) in sampled {
        if !ranks || best.is_none_or(|best| !screen_wins(best, packed)) {
            outcome.kinds.try_push(kind)?;
        }
    }
    if measures_the_member {
        outcome.plain = Some(baseline);
    }
    Ok(outcome)
}

/// Where the scanner thinks x86 code lives, merged into disjoint regions.
fn x86_code_regions<B: Budget>(data: &[u8], allowance: &B) -> Result<Buffer<Range<usize>, B>> {
    disjoint_ranges(crate::x86_filter_scan::ranges_with_allowance(
        data, true, allowance,
    )?)
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
/// region is the debug data rather than the code; screening only that one reads
/// DWARF, sees no win, and declines the filter. Regions are disjoint, so the
/// samples together never come to more than the member.
///
/// A long region gets one sample per [`X86_REGION_SAMPLE_SPAN`] of it, and is
/// judged on their sum (see [`x86_region_samples`]).
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
///
/// A search that [`OwnedSearch::prices_calls_alone`] skips that question and
/// measures both. RAR 5 searches a large member in 4 MiB pieces, where one
/// sample per region often has to stand for a whole piece, and there it
/// guessed wrong: on a 32 MiB slice of ELF binaries E8 alone came out 0.9%
/// smaller over the member, and the samples priced it in four pieces of
/// eight.
fn x86_screened_regions<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    regions: &[Range<usize>],
    options: S::Options,
) -> Result<X86Screen<S::Memory>> {
    // At the screens' settings, unless the search is exhaustive. This used to
    // run at the caller's own, on the grounds that it is a yes or no with no
    // margin under it. But a tar of `/usr` has a region for nearly every
    // file, and these samples came to 60% as many bytes as the member; at
    // level 3 every one of them went through the shortest-path parse. At the
    // screens' settings, 64 MiB of `/usr` at level 3 packed to within 75
    // bytes of what it did, as files and as a tar.
    let options = if search.exhaustive() {
        options
    } else {
        search.screen_options(options)
    };
    // The packed size of a region's samples under `kind`, or left alone.
    let priced = |region: &Range<usize>, kind: Option<FilterKind>| -> Result<usize> {
        let mut packed = 0;
        for within in x86_region_samples(region) {
            packed += match kind {
                None => search.encode_plain(&data[within], options, None)?.len(),
                Some(kind) => {
                    let filtered = filtered_sample(search, data, within, kind)?;
                    search.encode_plain(&filtered, options, None)?.len()
                }
            };
        }
        Ok(packed)
    };
    let mut kept = Buffer::new(search.allowance());
    let mut helped = false;
    for region in regions {
        if screen_sample_range(region.len()).len() < SCREEN_SAMPLE_ALIGNMENT {
            // Scanner padding makes this possible only when the entire
            // member is too short to provide a useful x86 sample.
            continue;
        }
        let baseline = priced(region, None)?;
        let pair = priced(region, Some(FilterKind::E8E9))?;
        // No margin here, unlike the detectorless filters: the scanner has
        // already ruled on where code is, so a small win on this sample is
        // evidence rather than noise.
        if pair <= baseline {
            helped |= pair < baseline;
            kept.try_push((region.clone(), Some(pair)))?;
            continue;
        }
        // The pair losing is not the calls losing. Where jumps are dense and
        // short, as in unoptimised code, converting them costs more than the
        // calls give back, and the region was turned down with the calls
        // never priced: on one 4 MiB run of a debug build the pair came out
        // 1.3% bigger than no filter and the calls alone 7.6% smaller. Only a
        // region the pair fails pays for this second question.
        if priced(region, Some(FilterKind::E8))? < baseline {
            helped = true;
            kept.try_push((region.clone(), None))?;
        }
    }
    let rejected_a_region = kept.len() < regions.len();
    if !helped {
        return Ok(X86Screen {
            kept: Buffer::new(search.allowance()),
            rejected_a_region: false,
            jumps_pay: false,
            jumps_cost_more: false,
        });
    }

    // Held back until the regions are known to be worth filtering at all. Asking
    // per region inside the loop above priced the jump opcodes on members that
    // then declined every filter, which is a sample encode each for an answer
    // nothing reads.
    let mut jumps_pay = false;
    let mut jumps_cost_more = false;
    for (region, pair) in kept.iter() {
        let Some(pair) = pair else {
            jumps_cost_more = true;
            continue;
        };
        jumps_pay = true;
        if search.prices_calls_alone() {
            jumps_cost_more = true;
            continue;
        }
        jumps_cost_more |= priced(region, Some(FilterKind::E8))? < *pair;
    }

    Ok(X86Screen {
        rejected_a_region,
        kept: Buffer::collect(
            kept.into_iter().map(|(region, _)| region),
            search.allowance(),
        )?,
        jumps_pay,
        jumps_cost_more,
    })
}

/// How much of an x86 region each of its screen samples stands for.
///
/// The same span RAR 5 searches a large member in, so a region no longer than
/// one of its pieces is sampled once, in the middle, as it always was.
const X86_REGION_SAMPLE_SPAN: usize = 4 * 1024 * 1024;

/// Where the x86 screen samples `region`: the middle of each of as many equal
/// parts as it takes to keep each part within [`X86_REGION_SAMPLE_SPAN`].
///
/// One sample used to stand for a region however long. On a 32 MiB slice of a
/// tar of `/usr/bin` the scanner proposed one region for the last 26 MiB of ELF
/// executables, and its one 128 KiB sample came out 20 bytes bigger under the
/// filter at one setting and 500 bytes smaller at another. Turning the region
/// down also took the whole-member candidate away, so 19 MiB of code went
/// unfiltered and the member came out 5% larger, at some levels and not
/// others. Summed over a sample for each 4 MiB, the code in the region
/// outweighs whatever one window happens to land on.
fn x86_region_samples(region: &Range<usize>) -> impl Iterator<Item = Range<usize>> + '_ {
    let parts = region.len().div_ceil(X86_REGION_SAMPLE_SPAN).max(1);
    (0..parts).map(move |part| {
        let start = region.start + region.len() * part / parts;
        let end = region.start + region.len() * (part + 1) / parts;
        let within = screen_sample_range(end - start);
        start + within.start..start + within.end
    })
}

/// What the x86 screen made of the regions the scanner proposed.
struct X86Screen<B: Budget> {
    /// The regions worth filtering, empty when none of them is.
    kept: Buffer<Range<usize>, B>,
    /// Whether any region came out bigger under the filter, which rules out
    /// filtering the member end to end.
    rejected_a_region: bool,
    /// Whether any kept region did no worse with the jump opcodes converted
    /// than with no filter. Where none did, the pair is not worth an encode.
    jumps_pay: bool,
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
/// The scanner proposes overlapping regions at several clustering distances.
/// Pricing each with a whole-member encode is worth about a third of a percent
/// at full effort, so this keeps the two that are structurally different: filter
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
fn x86_finalists<B: Budget>(
    data: &[u8],
    screen: &X86Screen<B>,
) -> Result<Buffer<Buffer<FilterSpec, B>, B>> {
    let allowance = screen.kept.allowance();
    let regions = &screen.kept;
    let covered: usize = regions.iter().map(|range| range.len()).sum();
    let (numerator, denominator) = X86_CODE_COVERAGE_RATIO;
    let sparse = covered * denominator < data.len() * numerator;
    let mut finalists = Buffer::new(&allowance);
    for kind in [
        screen.jumps_pay.then_some(FilterKind::E8E9),
        screen.jumps_cost_more.then_some(FilterKind::E8),
    ]
    .into_iter()
    .flatten()
    {
        if screen.rejected_a_region || sparse {
            finalists.try_push(Buffer::collect(
                regions
                    .iter()
                    .map(|range| FilterSpec::range(kind, range.clone())),
                &allowance,
            )?)?;
        }
        if !screen.rejected_a_region {
            finalists.try_push(Buffer::collect([FilterSpec::whole(kind)], &allowance)?)?;
        }
    }
    Ok(finalists)
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
    // table_regions supplies a full scan window and caps the stride, so the
    // only caller-side case without a candidate is a format with no delta.
    if max_stride == 0 {
        return None;
    }
    let hits = stride_hits(window, max_stride);
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

/// For each stride up to `max_stride`, how many bytes of `window` past the
/// first `max_stride` land within [`TABLE_STRIDE_NEAR`] of the byte that far
/// back.
///
/// One stride at a time over two slices the same length, counted a short run
/// at a time in a byte that no run can overflow: a loop the compiler runs
/// sixteen bytes to an instruction. Taking every stride at each byte in turn,
/// as this did, was a quarter of the time spent writing a member with no
/// table anywhere in it, and every member pays for the scan.
fn stride_hits(window: &[u8], max_stride: usize) -> [usize; MAX_TABLE_STRIDE + 1] {
    let mut hits = [0usize; MAX_TABLE_STRIDE + 1];
    let Some(current) = window.get(max_stride..) else {
        return hits;
    };
    for stride in 1..=max_stride {
        let behind = &window[max_stride - stride..window.len() - stride];
        hits[stride] = current
            .chunks(128)
            .zip(behind.chunks(128))
            .map(|(current, behind)| {
                let mut near = 0u8;
                for (byte, behind) in current.iter().zip(behind) {
                    // Within TABLE_STRIDE_NEAR either way, as one unsigned test.
                    let apart = byte.wrapping_sub(*behind).wrapping_add(TABLE_STRIDE_NEAR);
                    near += u8::from(apart <= 2 * TABLE_STRIDE_NEAR);
                }
                usize::from(near)
            })
            .sum();
    }
    hits
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
fn table_regions<B: Budget>(
    data: &[u8],
    max_stride: usize,
    scan_window: usize,
    allowance: &B,
) -> Result<Buffer<(Range<usize>, usize), B>> {
    let max_stride = max_stride.min(MAX_TABLE_STRIDE);
    // A window has to hold more than a stride's worth of bytes to be scored.
    let scan_window = scan_window.max(2 * MAX_TABLE_STRIDE);
    let mut regions: Buffer<(Range<usize>, usize), B> = Buffer::new(allowance);
    for start in (0..).map(|window| window * scan_window) {
        let Some(window) = data.get(start..start + scan_window) else {
            break;
        };
        let Some(stride) = table_stride(window, max_stride) else {
            continue;
        };
        match regions.last_mut() {
            Some((last, last_stride)) if *last_stride == stride && last.end == start => {
                last.end = start + scan_window;
            }
            _ => regions.try_push((start..start + scan_window, stride))?,
        }
    }
    // The scan steps in whole windows, so a file that is one table loses its
    // last partial window. Keep that tail when it has the same stride. A
    // different tail stays out, which is what keeps a table from swallowing
    // the bytes after it. The last region has to reach the last whole window,
    // or the tail would also cover the windows the scan rejected.
    let whole_windows = data.len() - data.len() % scan_window;
    if let Some((last, last_stride)) = regions.last_mut() {
        if last.end == whole_windows && last.end < data.len() {
            let tail = &data[last.end..];
            if tail.len() > max_stride && table_stride(tail, max_stride) == Some(*last_stride) {
                last.end = data.len();
            }
        }
    }
    regions.retain(|(range, _)| range.len() >= MIN_TABLE_WINDOWS * scan_window);
    Ok(regions)
}

/// Which of the scanner's table regions the delta filter actually shrinks.
///
/// The scanner reads byte statistics, and repetition at a stride is also
/// something the match finder can sometimes reach on its own; a run of
/// constant bytes scores as a table at every stride and needs no filter at
/// all. A sample encode inside the region separates the tables delta helps
/// from the ones LZ was already handling, the same way the x86 screen checks
/// its scanner.
fn table_screened_regions<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    regions: &[(Range<usize>, usize)],
    options: S::Options,
) -> Result<TableRegions<S::Memory>> {
    let screen_options = search.screen_options(options);
    let mut kept = Buffer::new(search.allowance());
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
            kept.try_push((region.clone(), *stride))?;
        }
    }
    Ok(kept)
}

/// `range` with the `removed` ranges cut out of it. `removed` must be sorted
/// and disjoint.
fn subtract_owned<B: Budget>(
    range: Range<usize>,
    removed: &[Range<usize>],
    allowance: &B,
) -> Result<Buffer<Range<usize>, B>> {
    let mut kept = Buffer::new(allowance);
    let mut start = range.start;
    for cut in removed {
        if cut.end <= start {
            continue;
        }
        if cut.start >= range.end {
            break;
        }
        if cut.start > start {
            kept.try_push(start..cut.start)?;
        }
        start = start.max(cut.end);
    }
    if start < range.end {
        kept.try_push(start..range.end)?;
    }
    Ok(kept)
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
fn graft_owned<B: Budget>(
    specs: Buffer<FilterSpec, B>,
    tables: &[(Range<usize>, usize)],
    member: usize,
) -> Result<Buffer<FilterSpec, B>> {
    if tables.is_empty() {
        return Ok(specs);
    }
    let allowance = specs.allowance();
    let table_ranges = Buffer::collect(tables.iter().map(|(range, _)| range.clone()), &allowance)?;
    let mut grafted = Buffer::new(&allowance);
    for spec in specs {
        let covered = spec.range.clone().unwrap_or(0..member);
        for range in subtract_owned(covered, &table_ranges, &allowance)? {
            grafted.try_push((grafted.len(), FilterSpec::range(spec.kind, range)))?;
        }
    }
    for (range, stride) in tables {
        grafted.try_push((
            grafted.len(),
            FilterSpec::range(FilterKind::Delta { channels: *stride }, range.clone()),
        ))?;
    }
    // Explicit original order preserves stable ties without an unaccounted sort allocation.
    grafted.sort_unstable_by_key(|(order, spec)| {
        (spec.range.as_ref().map_or(0, |range| range.start), *order)
    });
    Ok(Buffer::collect(
        grafted.into_iter().map(|(_, spec)| spec),
        &allowance,
    )?)
}

/// The tables left once the code has had its say on the ones inside it.
///
/// The table scanner reads repetition at a stride, and code built from one
/// instruction pattern repeats at the pattern's length. A run of calls sixteen
/// bytes apart scans as a table of sixteen-byte records from end to end, and
/// the delta filter does shrink it, so the table screen keeps it. Grafting then
/// cut the whole run out of every x86 finalist, and the x86 filter, worth far
/// more there, was never measured.
///
/// So a table that lies in code the x86 screen kept is priced both ways on
/// its own sample, and goes to whichever filter leaves that smaller. A real
/// table inside a code region, a jump table or the relocations the scanner
/// swept up with the code around them, still wins: the x86 filter finds
/// little in it to convert.
fn tables_outside_code<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    tables: TableRegions<S::Memory>,
    code: &X86Screen<S::Memory>,
    options: S::Options,
) -> Result<TableRegions<S::Memory>> {
    let screen_options = search.screen_options(options);
    let kind = if code.jumps_pay {
        FilterKind::E8E9
    } else {
        FilterKind::E8
    };
    let mut kept = Buffer::new(search.allowance());
    for (region, stride) in tables {
        let within = screen_sample_range(region.len());
        let within = region.start + within.start..region.start + within.end;
        let in_code = code
            .kept
            .iter()
            .any(|code| code.start < within.end && within.start < code.end);
        if in_code {
            let filters = [FilterSpec::whole(FilterKind::Delta { channels: stride })];
            let as_table = search.filtered_bytes(&data[within.clone()], &filters)?;
            let as_table = search.encode_plain(&as_table, screen_options, None)?;
            let as_code = filtered_sample(search, data, within, kind)?;
            let as_code = search.encode_plain(&as_code, screen_options, None)?;
            if as_code.len() < as_table.len() {
                continue;
            }
        }
        kept.try_push((region, stride))?;
    }
    Ok(kept)
}

/// The filter specs worth measuring against the whole member, paired with the
/// bytes for any the screen already measured.
///
/// Everything expensive happens downstream of this, one whole-member encode per
/// unmeasured finalist, so the job here is to hand back a handful rather than the
/// several dozen the scanner and the delta widths can between them suggest.
fn finalists<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<Buffer<Finalist<S::Memory>, S::Memory>> {
    let screen = screen_kinds(search, data, options)?;
    let allowance = search.allowance();
    let mut finalists = Buffer::collect([(Buffer::new(allowance), screen.plain)], allowance)?;

    let table_regions = table_regions(
        data,
        search.max_delta_channels(),
        search.table_scan_window(),
        allowance,
    )?;
    let mut tables = table_screened_regions(search, data, &table_regions, options)?;

    // The tables graft into every x86 finalist rather than competing against
    // them, so when the x86 screen kept anything they cost no encode of their
    // own. Only a member with tables and no code pays for a tables-only
    // candidate.
    let mut tables_carried = false;
    if search.detects_x86() {
        let screen =
            x86_screened_regions(search, data, &x86_code_regions(data, allowance)?, options)?;
        if !screen.kept.is_empty() {
            tables = tables_outside_code(search, data, tables, &screen, options)?;
            tables_carried = !tables.is_empty();
            for specs in x86_finalists(data, &screen)? {
                finalists.try_push((graft_owned(specs, &tables, data.len())?, None))?;
            }
        }
    }
    if !tables.is_empty() && !tables_carried {
        finalists.try_push((
            graft_owned(Buffer::new(allowance), &tables, data.len())?,
            None,
        ))?;
    }

    for screened in screen.kinds {
        finalists.try_push((
            Buffer::collect([FilterSpec::whole(screened.kind)], allowance)?,
            screened.measured,
        ))?;
        if let (true, FilterKind::Delta { channels }) = (screened.worth_a_range, screened.kind) {
            if let Some(range) = auto_delta_filter_range(data, channels) {
                finalists.try_push((
                    Buffer::collect([FilterSpec::range(screened.kind, range)], allowance)?,
                    None,
                ))?;
            }
        }
    }

    // The table scanner can find a table the length of the member, and then
    // offers the same filter over the same bytes as a screened kind does,
    // ranged where the other is whole. That is one transform encoded twice.
    // Keep the first of each: a later equal one could only tie, and a tie
    // never displaces the first.
    let member = 0..data.len();
    let same = |left: &[FilterSpec], right: &[FilterSpec]| {
        left.len() == right.len()
            && left.iter().zip(right).all(|(left, right)| {
                left.kind == right.kind
                    && left.range.as_ref().unwrap_or(&member)
                        == right.range.as_ref().unwrap_or(&member)
            })
    };
    let mut kept: Buffer<Finalist<S::Memory>, S::Memory> = Buffer::new(allowance);
    for (specs, measured) in finalists {
        if kept.iter().any(|(earlier, _)| same(earlier, &specs)) {
            continue;
        }
        kept.try_push((specs, measured))?;
    }
    let finalists = kept;
    Ok(finalists)
}

/// How much of the member each trial window stands for. The trial encodes one
/// [`TRIAL_WINDOW_LEN`] window from the middle of each part this long.
const TRIAL_SPAN: usize = 256 * 1024;

/// How long each trial window is.
///
/// A quarter of the member. On 1 MiB pieces of a tar of `/usr` at level 1, the
/// filter this picked came to 0.07% more than the best finalist encoded in
/// full; an eighth of the member, as 64 KiB in each 512 KiB or 32 KiB in each
/// 256 KiB, came to 0.11%.
const TRIAL_WINDOW_LEN: usize = 64 * 1024;

/// Where the trial encodes a member this long: the middle of each
/// [`TRIAL_SPAN`] of it.
fn trial_windows(len: usize) -> impl Iterator<Item = Range<usize>> {
    let parts = len.div_ceil(TRIAL_SPAN).max(1);
    (0..parts).map(move |part| {
        let start = len * part / parts;
        let end = len * (part + 1) / parts;
        let middle = start + (end - start).saturating_sub(TRIAL_WINDOW_LEN) / 2;
        middle..(middle + TRIAL_WINDOW_LEN).min(end)
    })
}

/// What the finalist with these specs packs to over the trial windows, at
/// `trial_options`.
///
/// Each window is filtered on its own, where it lies in the member, with the
/// finalist's ranges cut to it, as the screens filter their samples. Cutting a
/// window out of the member filtered whole would cut it out of delta's planes,
/// and a window of one plane is no measure of the whole: on a binary that was
/// mostly a relocation table, delta 4 over the member won such a trial against
/// delta 24 over the table that it lost to in full.
///
/// `seen` holds every window already encoded, as its index, a hash of its
/// bytes and what it packed to. A window that comes out the same bytes under
/// two finalists, as a ranged filter leaves the bytes outside its ranges, is
/// encoded once.
fn trial_size<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    specs: &[FilterSpec],
    trial_options: S::Options,
    seen: &mut Buffer<(usize, u64, usize), S::Memory>,
) -> Result<usize> {
    let mut total = 0;
    for (index, window) in trial_windows(data.len()).enumerate() {
        let mut cut = Buffer::new(search.allowance());
        for spec in specs {
            let range = spec.range.clone().unwrap_or(0..data.len());
            let start = range.start.max(window.start);
            let end = range.end.min(window.end);
            if start < end {
                cut.try_push(FilterSpec::range(
                    spec.kind,
                    start - window.start..end - window.start,
                ))?;
            }
        }
        let filtered;
        let window_bytes = &data[window.clone()];
        let bytes = if cut.is_empty() {
            window_bytes
        } else {
            filtered = search.filtered_window(window_bytes, window.start, &cut)?;
            &filtered[..]
        };
        let hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut hasher);
            hasher.finish()
        };
        let known = seen
            .iter()
            .find(|&&(seen_index, seen_hash, _)| seen_index == index && seen_hash == hash)
            .map(|&(_, _, packed)| packed);
        total += match known {
            Some(packed) => packed,
            None => {
                let packed = search.encode_plain(bytes, trial_options, None)?.len();
                seen.try_push((index, hash, packed))?;
                packed
            }
        };
    }
    Ok(total)
}

/// The one finalist worth encoding at the caller's settings, or `None` when
/// they should all be encoded in full and the smallest kept.
///
/// Encoding every finalist in full was most of the time spent writing a
/// binary: up to six encodes of the member to keep one. On 64 MiB of a tar of
/// `/usr` the search was 70% of level 1 and half of level 3, for filters
/// worth 7% to 8%. So the finalists are ranked by a trial, and only the winner
/// is encoded.
///
/// The trial encodes a window from each [`TRIAL_SPAN`] of the member under
/// each finalist, at the screens' settings (see [`trial_size`]). The smallest
/// total wins and the earliest takes a tie.
///
/// Leaving the member alone is not one of the candidates the windows rank.
/// Every finalist but the plain member is there because a screen saw its
/// filter win, and a window without the member's history behind it undersells
/// the filters: x86 code converted to absolute addresses gains from calls to
/// the same place far apart. Ranked with the others, the plain member won the
/// trial on 1 MiB pieces of a tar of `/usr` that it lost by 7% in full, and
/// the choice came to 0.35% more than the best finalist; left out, 0.07%. So
/// when the screens pass only one filter, it is taken without a trial.
///
/// A member no longer than one span has no history to lose. It is encoded
/// whole under each finalist, the plain member included, and at the caller's
/// own settings that is the full comparison, so that is what it gets. So does
/// a search that is [`OwnedSearch::exhaustive`].
fn trial_winner<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
    finalists: &mut Buffer<Finalist<S::Memory>, S::Memory>,
) -> Result<Option<Finalist<S::Memory>>> {
    if finalists.len() <= 1 {
        return Ok(finalists.pop());
    }
    let trial_options = search.screen_options(options);
    let whole = data.len() <= TRIAL_SPAN;
    if search.exhaustive()
        || (whole && trial_options == options)
        || finalists.iter().any(|(_, measured)| measured.is_some())
    {
        return Ok(None);
    }
    let mut seen = Buffer::new(search.allowance());
    let mut best: Option<(usize, usize)> = None;
    for (index, (specs, _)) in finalists.iter().enumerate() {
        let packed = match (whole, specs.is_empty()) {
            (true, true) => search.encode_plain(data, trial_options, None)?.len(),
            (true, false) => search
                .encode_filtered(data, specs, trial_options, None)?
                .len(),
            (false, true) => continue,
            // The only filter a screen passed.
            (false, false) if finalists.len() == 2 => {
                best = Some((index, 0));
                break;
            }
            (false, false) => trial_size(search, data, specs, trial_options, &mut seen)?,
        };
        if best.is_none_or(|(_, best)| packed < best) {
            best = Some((index, packed));
        }
    }
    let (best, _) = best.expect("a trial has a candidate");
    Ok(
        std::mem::replace(finalists, Buffer::new(search.allowance()))
            .into_iter()
            .nth(best),
    )
}

/// The finalists worth encoding at the caller's settings: the trial's winner
/// alone, or all of them when the search compares them in full.
fn ranked_finalists<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<Buffer<Finalist<S::Memory>, S::Memory>> {
    let mut finalists = finalists(search, data, options)?;
    Ok(match trial_winner(search, data, options, &mut finalists)? {
        Some(winner) => Buffer::collect([winner], search.allowance())?,
        None => finalists,
    })
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
    Ok(finalists(
        &UnlimitedSearch(search, Allowance::default()),
        data,
        options,
    )?
    .into_iter()
    .map(|(specs, _measured)| specs.into_vec())
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
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
) -> Result<(Vec<FilterSpec>, Vec<u8>)> {
    choose_owned(
        &UnlimitedSearch(search, Allowance::default()),
        data,
        options,
        progress,
    )
    .map(|(specs, bytes)| (specs.into_vec(), bytes.into_vec()))
}

/// [`choose_filter`], with the whole-member encodes run side by side where
/// there is room for them.
///
/// Each finalist's encode fans out inside, but it still fills its match finder
/// ahead and screens its filters serially, so encoding the finalists one after
/// another leaves most threads idle for most of the search. Run beside each
/// other, those serial stretches overlap. The plain member is a finalist the
/// screen cannot measure on anything but a member one sample long, so beyond
/// that it is encoded while the screens run.
///
/// The choice is [`choose_filter`]'s: the finalists are the same, the trial
/// that ranks them is the same, each is encoded the same way whatever runs
/// beside it, and they are compared in order, the smallest winning and a tie
/// going to the earlier. A failure is the one the earliest failing finalist
/// met, as when they ran in turn. When the trial picks the winner, there is
/// only that one to encode.
///
/// `admit` is asked for room before each encode beyond the first that would
/// run at once, and the room it hands back is held until that encode's bytes
/// have been compared and the losers dropped. When it has none, the search
/// waits for the encodes in flight instead, so it runs within what `admit`
/// grants and never waits on it.
///
/// `progress` is told how many bytes an encode walked since it last reported,
/// zero as each encode starts, from whichever thread runs it. False stops the
/// search with [`crate::Error::Cancelled`].
pub(crate) fn choose_filter_side_by_side<S, R>(
    search: &S,
    data: &[u8],
    options: S::Options,
    progress: Option<&(dyn Fn(usize) -> bool + Sync)>,
    admit: &(dyn Fn() -> Option<R> + Sync),
) -> Result<(Vec<FilterSpec>, Vec<u8>)>
where
    S: FilterSearch + Sync,
    S::Options: Send + Sync,
    R: Send,
{
    let search = UnlimitedSearch(search, Allowance::default());
    match progress {
        Some(progress) => side_by_side(
            &SharedReporting {
                search: &search,
                progress,
            },
            data,
            options,
            admit,
        ),
        None => side_by_side(&search, data, options, admit),
    }
    .map(|(specs, bytes)| (specs.into_vec(), bytes.into_vec()))
}

/// Reports every encode of a search to one sink, from whichever thread runs it.
///
/// Each encode keeps its own place, so encodes running side by side report
/// what each of them walked rather than one another's positions.
struct SharedReporting<'a, S> {
    search: &'a S,
    progress: &'a (dyn Fn(usize) -> bool + Sync),
}

impl<S: OwnedSearch> SharedReporting<'_, S> {
    fn pass<T>(
        &self,
        encode: impl FnOnce(Option<&mut dyn FnMut(usize) -> bool>) -> Result<T>,
    ) -> Result<T> {
        if !(self.progress)(0) {
            return Err(crate::Error::Cancelled);
        }
        let mut last = 0usize;
        encode(Some(&mut |position| {
            let walked = position.saturating_sub(last);
            last = position;
            (self.progress)(walked)
        }))
    }
}

impl<S: OwnedSearch> OwnedSearch for SharedReporting<'_, S> {
    type Options = S::Options;
    type Memory = S::Memory;
    fn allowance(&self) -> &Self::Memory {
        self.search.allowance()
    }
    fn screened_kinds(&self, data: &[u8]) -> Result<Buffer<FilterKind, S::Memory>> {
        self.search.screened_kinds(data)
    }
    fn detects_x86(&self) -> bool {
        self.search.detects_x86()
    }
    fn max_delta_channels(&self) -> usize {
        self.search.max_delta_channels()
    }
    fn table_scan_window(&self) -> usize {
        self.search.table_scan_window()
    }
    fn screen_options(&self, options: Self::Options) -> Self::Options {
        self.search.screen_options(options)
    }
    fn exhaustive(&self) -> bool {
        self.search.exhaustive()
    }
    fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Buffer<u8, S::Memory>> {
        self.search.filtered_bytes(data, filters)
    }
    fn filtered_window(
        &self,
        data: &[u8],
        offset: usize,
        filters: &[FilterSpec],
    ) -> Result<Buffer<u8, S::Memory>> {
        self.search.filtered_window(data, offset, filters)
    }
    fn encode_plain(
        &self,
        data: &[u8],
        options: Self::Options,
        _: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, S::Memory>> {
        self.pass(|progress| self.search.encode_plain(data, options, progress))
    }
    fn encode_filtered(
        &self,
        data: &[u8],
        filters: &[FilterSpec],
        options: Self::Options,
        _: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Buffer<u8, S::Memory>> {
        self.pass(|progress| {
            self.search
                .encode_filtered(data, filters, options, progress)
        })
    }
}

fn side_by_side<S, R>(
    search: &S,
    data: &[u8],
    options: S::Options,
    admit: &(dyn Fn() -> Option<R> + Sync),
) -> Result<FilterChoice<S::Memory>>
where
    S: OwnedSearch + Sync,
    S::Options: Send + Sync,
    R: Send,
{
    let at_once = if crate::parallel::may_nest() {
        crate::parallel::threads()
    } else {
        1
    };
    // The screen measures the plain member itself only when the member is no
    // longer than its sample. Past that the plain encode is always the first
    // finalist, and nothing the screen decides changes it, so it can start at
    // once. The room taken for the screens beside it then goes to the
    // finalists after it, one at a time, for as long as it runs.
    // Only a search that encodes every finalist in full is sure to encode the
    // plain member at these settings.
    let early = if at_once > 1 && data.len() > SCREEN_SAMPLE_LEN && search.exhaustive() {
        admit()
    } else {
        None
    };
    let Some(room) = early else {
        let finalists = ranked_finalists(search, data, options)?.into_iter();
        return Ok(smallest(search, data, options, finalists, at_once, admit)?
            .expect("the unfiltered member is always a finalist"));
    };
    let (plain, rest) = crate::parallel::join(
        || search.encode_plain(data, options, None),
        || -> Result<Result<_>> {
            let mut finalists = finalists(search, data, options)?.into_iter();
            let plain = finalists.next().expect("the plain member is first");
            debug_assert!(plain.0.is_empty() && plain.1.is_none());
            let rest = smallest(search, data, options, finalists, at_once - 1, admit);
            drop(room);
            Ok(rest)
        },
    );
    // In the order they would have failed in turn: the screens, the plain
    // member, then the finalists after it.
    let rest = rest?;
    let plain = plain?;
    Ok(match rest? {
        Some(rest) if rest.1.len() < plain.len() => rest,
        _ => (Buffer::new(search.allowance()), plain),
    })
}

/// The smallest of `finalists`, the earliest on a tie, with up to `at_once` of
/// them encoded side by side.
///
/// One encode at a time, and the smallest so far, are the caller's to cover;
/// every encode beside that one runs in room `admit` grants, held until its
/// bytes have been compared and the larger dropped. A failure is the earliest
/// failing finalist's, and nothing after it is compared.
fn smallest<S, R>(
    search: &S,
    data: &[u8],
    options: S::Options,
    finalists: impl Iterator<Item = Finalist<S::Memory>>,
    at_once: usize,
    admit: &(dyn Fn() -> Option<R> + Sync),
) -> Result<Option<FilterChoice<S::Memory>>>
where
    S: OwnedSearch + Sync,
    S::Options: Send + Sync,
{
    let encode = |(specs, measured): Finalist<S::Memory>| -> Result<FilterChoice<S::Memory>> {
        let packed = match measured {
            Some(packed) => packed,
            None if specs.is_empty() => search.encode_plain(data, options, None)?,
            None => search.encode_filtered(data, &specs, options, None)?,
        };
        Ok((specs, packed))
    };
    let mut finalists = finalists.peekable();
    let mut best: Option<FilterChoice<S::Memory>> = None;
    while let Some(first) = finalists.next() {
        // A finalist the screen measured costs no encode, and so no room.
        let mut encodes = usize::from(first.1.is_none());
        let mut window = vec![first];
        let mut rooms = Vec::new();
        while let Some((_, measured)) = finalists.peek() {
            if measured.is_none() {
                if encodes >= at_once.max(1) {
                    break;
                }
                if encodes > 0 {
                    match admit() {
                        Some(room) => rooms.push(room),
                        None => break,
                    }
                }
                encodes += 1;
            }
            window.push(finalists.next().expect("peeked"));
        }
        let (packed, failure) = if encodes > 1 {
            crate::parallel::map_prefix(window, encode)
        } else {
            let mut packed = Vec::with_capacity(window.len());
            let mut failure = None;
            for finalist in window {
                match encode(finalist) {
                    Ok(choice) => packed.push(choice),
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            (packed, failure)
        };
        for (specs, packed) in packed {
            if best
                .as_ref()
                .is_none_or(|(_, best)| packed.len() < best.len())
            {
                best = Some((specs, packed));
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        drop(rooms);
    }
    Ok(best)
}

/// The filters [`choose_owned`] would pick, for a caller that throws the
/// bytes away. A winner picked by the trial is not encoded at all.
pub(crate) fn choose_owned_specs<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
) -> Result<Buffer<FilterSpec, S::Memory>> {
    match progress {
        Some(progress) => specs_only(
            &ReportingSearch {
                search,
                progress: std::cell::RefCell::new(progress),
            },
            data,
            options,
        ),
        None => specs_only(search, data, options),
    }
}

fn specs_only<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<Buffer<FilterSpec, S::Memory>> {
    let mut finalists = ranked_finalists(search, data, options)?;
    if finalists.len() == 1 {
        let (specs, _) = finalists.pop().expect("one finalist");
        return Ok(specs);
    }
    choose_filter_inner_from(search, data, options, finalists).map(|(specs, _)| specs)
}

pub(crate) fn choose_owned<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
    progress: Option<&mut dyn FnMut(EncodeProgress) -> bool>,
) -> Result<FilterChoice<S::Memory>> {
    match progress {
        Some(progress) => choose_filter_inner(
            &ReportingSearch {
                search,
                progress: std::cell::RefCell::new(progress),
            },
            data,
            options,
        ),
        None => choose_filter_inner(search, data, options),
    }
}

fn choose_filter_inner<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
) -> Result<FilterChoice<S::Memory>> {
    let finalists = ranked_finalists(search, data, options)?;
    choose_filter_inner_from(search, data, options, finalists)
}

/// The smallest of `finalists`, each encoded in full at `options`, the
/// earliest on a tie.
fn choose_filter_inner_from<S: OwnedSearch>(
    search: &S,
    data: &[u8],
    options: S::Options,
    finalists: Buffer<Finalist<S::Memory>, S::Memory>,
) -> Result<FilterChoice<S::Memory>> {
    let mut best: Option<FilterChoice<S::Memory>> = None;
    for (specs, measured) in finalists {
        let packed = match measured {
            Some(packed) => packed,
            None if specs.is_empty() => search.encode_plain(data, options, None)?,
            None => search.encode_filtered(data, &specs, options, None)?,
        };
        if best
            .as_ref()
            .is_none_or(|(_, best)| packed.len() < best.len())
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
pub(crate) fn walk_bytes_for_kinds(data: &[u8], screened: u64, encoder_candidates: usize) -> u64 {
    let member = data.len() as u64;
    let encoder_candidates = encoder_candidates.max(1) as u64;
    let sample = screen_sample(data).len() as u64;
    // Two sample encodes per region for the x86 screen, and the two specs it
    // proposes when the detector does find code. How many regions there are is
    // not knowable without scanning, so this assumes [`X86_ASSUMED_REGIONS`],
    // bounded by the member: the regions are disjoint, so however many the
    // scanner finds, their samples together cannot come to more than that.
    let x86_screen = (sample * X86_ASSUMED_REGIONS).min(member) * 2;
    let x86_finalists = 2;
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
    if member > TRIAL_SPAN as u64 {
        // Past one span the trial ranks the filters on a window from each,
        // leaving out the unfiltered member, and only the winner is encoded.
        let windows = trial_windows(data.len())
            .map(|window| window.len() as u64)
            .sum::<u64>();
        return screen + windows * (1 + x86_finalists) + member * encoder_candidates;
    }
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
#[cfg(test)]
pub(crate) fn disjoint_filter_ranges(ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    disjoint_ranges(Buffer::from_vec(ranges))
        .expect("unlimited ranges")
        .into_vec()
}
fn disjoint_ranges<B: Budget>(
    mut ranges: Buffer<Range<usize>, B>,
) -> Result<Buffer<Range<usize>, B>> {
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut disjoint: Buffer<Range<usize>, B> = Buffer::new(&ranges.allowance());
    for range in ranges {
        if let Some(last) = disjoint.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        disjoint.try_push(range)?;
    }
    Ok(disjoint)
}

#[cfg(test)]
mod tests {
    fn screen_kinds<S: FilterSearch>(
        search: &S,
        data: &[u8],
        options: S::Options,
    ) -> Result<ScreenOutcome<Allowance>> {
        super::screen_kinds(
            &UnlimitedSearch(search, Allowance::default()),
            data,
            options,
        )
    }
    fn x86_code_regions(data: &[u8]) -> Vec<Range<usize>> {
        super::x86_code_regions(data, &Allowance::default())
            .unwrap()
            .into_vec()
    }
    fn x86_screened_regions<S: FilterSearch>(
        search: &S,
        data: &[u8],
        regions: &[Range<usize>],
        options: S::Options,
    ) -> Result<X86Screen<Allowance>> {
        super::x86_screened_regions(
            &UnlimitedSearch(search, Allowance::default()),
            data,
            regions,
            options,
        )
    }
    fn x86_finalists(data: &[u8], screen: &X86Screen<Allowance>) -> Vec<Vec<FilterSpec>> {
        super::x86_finalists(data, screen)
            .unwrap()
            .into_iter()
            .map(Buffer::into_vec)
            .collect()
    }
    fn delta_table_regions(data: &[u8], max_stride: usize) -> Vec<(Range<usize>, usize)> {
        table_regions(data, max_stride, TABLE_SCAN_WINDOW, &Allowance::default())
            .unwrap()
            .into_vec()
    }
    fn table_screened_regions<S: FilterSearch>(
        search: &S,
        data: &[u8],
        regions: &[(Range<usize>, usize)],
        options: S::Options,
    ) -> Result<Buffer<(Range<usize>, usize)>> {
        super::table_screened_regions(
            &UnlimitedSearch(search, Allowance::default()),
            data,
            regions,
            options,
        )
    }
    fn subtract_ranges(range: Range<usize>, removed: &[Range<usize>]) -> Vec<Range<usize>> {
        subtract_owned(range, removed, &Allowance::default())
            .unwrap()
            .into_vec()
    }
    fn graft_tables(
        specs: Vec<FilterSpec>,
        tables: &[(Range<usize>, usize)],
        member: usize,
    ) -> Vec<FilterSpec> {
        graft_owned(Buffer::from_vec(specs), tables, member)
            .unwrap()
            .into_vec()
    }

    #[test]
    fn a_member_is_judged_text_by_what_it_holds_not_how_it_opens() {
        let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n".repeat(1200);
        let mut state = 0x9e37_79b9u32;
        let noise: Vec<u8> = (0..1 << 20)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        // Text in front of a megabyte of binary.
        let opens_with_text = [&text[..], &noise[..]].concat();
        assert!(!search_applies(&opens_with_text));
        assert!(search_applies_throughout(&opens_with_text));
        // A binary header in front of a megabyte of text.
        let text_body = text.repeat(16);
        let opens_with_binary = [&noise[..2048], &text_body[..]].concat();
        assert!(search_applies(&opens_with_binary));
        assert!(!search_applies_throughout(&opens_with_binary));
        // A member of up to two samples is judged as it always was.
        for len in [0, 1, TEXT_SAMPLE_LEN, 2 * TEXT_SAMPLE_LEN] {
            for data in [&opens_with_text[..len], &opens_with_binary[..len]] {
                assert_eq!(search_applies_throughout(data), search_applies(data));
            }
        }
    }

    #[test]
    fn search_reports_each_sample_pass_and_can_cancel_during_screening() {
        use std::cell::RefCell;
        struct CountingSearch(RefCell<Vec<usize>>);
        impl FilterSearch for CountingSearch {
            type Options = ();
            fn screened_kinds(&self, _: &[u8]) -> Vec<FilterKind> {
                vec![FilterKind::Delta { channels: 1 }]
            }
            fn detects_x86(&self) -> bool {
                false
            }
            fn max_delta_channels(&self) -> usize {
                1
            }
            fn filtered_bytes(&self, data: &[u8], _: &[FilterSpec]) -> Result<Vec<u8>> {
                Ok(data.to_vec())
            }
            fn encode_plain(
                &self,
                data: &[u8],
                _: (),
                progress: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Vec<u8>> {
                self.0.borrow_mut().push(data.len());
                // Short codec passes may report only their final position.
                if progress.is_some_and(|report| !report(data.len())) {
                    return Err(crate::Error::Cancelled);
                }
                Ok(vec![0; 10])
            }
            fn encode_filtered(
                &self,
                data: &[u8],
                _: &[FilterSpec],
                options: (),
                progress: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Vec<u8>> {
                self.encode_plain(data, options, progress)
            }
        }
        let data = vec![0; SCREEN_SAMPLE_LEN * 2];
        let search = CountingSearch(RefCell::new(Vec::new()));
        let mut events = Vec::new();
        let observed = choose_filter(
            &search,
            &data,
            (),
            Some(&mut |event| {
                events.push(event);
                true
            }),
        )
        .unwrap();
        let calls = search.0.borrow().clone();
        assert!(calls.len() >= 3);
        assert!(calls[..calls.len() - 1]
            .iter()
            .all(|&len| len == SCREEN_SAMPLE_LEN));
        assert_eq!(calls.last(), Some(&data.len()));
        assert_eq!(
            events,
            calls
                .iter()
                .flat_map(|&len| [EncodeProgress::PassStarted, EncodeProgress::Advanced(len)])
                .collect::<Vec<_>>()
        );
        assert_eq!(observed, choose_filter(&search, &data, (), None).unwrap());
        search.0.borrow_mut().clear();
        assert_eq!(
            choose_filter(
                &search,
                &data,
                (),
                Some(&mut |event| matches!(event, EncodeProgress::PassStarted))
            ),
            Err(crate::Error::Cancelled)
        );
        assert_eq!(*search.0.borrow(), [SCREEN_SAMPLE_LEN]);
    }

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

    #[test]
    fn tiny_scanner_regions_do_not_trigger_sample_encodes() {
        let data = b"abcdefgh";
        let region = 0..data.len();
        let x86 =
            x86_screened_regions(&FULL, data, std::slice::from_ref(&region), options()).unwrap();
        assert!(x86.kept.is_empty());
        assert!(!x86.rejected_a_region);
        let tables = table_screened_regions(&FULL, data, &[(0..data.len(), 1)], options()).unwrap();
        assert!(tables.is_empty());
        assert!(auto_delta_filter_range(data, 0).is_none());
        assert!(!search_applies(b""));
    }

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

    /// Two channels of 16-bit samples, a slow wave each with a little noise.
    /// Delta at width 4 takes each channel's sample from the last; width 2
    /// helps too, but less.
    fn stereo_samples(len: usize) -> Vec<u8> {
        let mut noise = 0x2545_f491u32;
        let mut data = Vec::with_capacity(len + 4);
        let mut phase = 0f64;
        while data.len() < len {
            phase += 0.013;
            for (scale, rate) in [(12_000.0, 1.0), (9_000.0, 1.5)] {
                noise = noise.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let jitter = f64::from((noise >> 24) as u8) - 128.0;
                let sample = (scale * (phase * rate).sin() + jitter) as i16;
                data.extend_from_slice(&sample.to_le_bytes());
            }
        }
        data.truncate(len);
        data
    }

    fn finalist_specs(search: &TestSearch, data: &[u8]) -> Vec<Vec<FilterSpec>> {
        super::finalists(
            &UnlimitedSearch(search, Allowance::default()),
            data,
            options(),
        )
        .unwrap()
        .into_iter()
        .map(|(specs, _)| specs.into_vec())
        .collect()
    }

    /// A screen at the finalists' own settings ranks the kinds as they will
    /// be measured, so one that loses by the margin is not encoded whole.
    /// Nor is the same filter twice, once whole from the screen and once over
    /// the whole member from the table scanner.
    #[test]
    fn only_kinds_the_screen_cannot_rank_apart_are_encoded_whole() {
        let data = stereo_samples(SCREEN_SAMPLE_LEN * 2);
        let finalists = finalist_specs(&FULL, &data);
        let member = 0..data.len();
        let widths: Vec<usize> = finalists
            .iter()
            .flatten()
            .filter_map(|spec| match spec.kind {
                FilterKind::Delta { channels } => Some(channels),
                _ => None,
            })
            .collect();
        assert!(widths.contains(&4), "{finalists:?}");
        assert!(
            !widths.contains(&2),
            "delta 2 lost on the sample: {finalists:?}"
        );
        for (index, specs) in finalists.iter().enumerate() {
            for later in &finalists[index + 1..] {
                let effective = |specs: &[FilterSpec]| {
                    specs
                        .iter()
                        .map(|spec| (spec.kind, spec.range.clone().unwrap_or(member.clone())))
                        .collect::<Vec<_>>()
                };
                assert_ne!(effective(specs), effective(later), "{finalists:?}");
            }
        }
        let (specs, _) = choose_filter(&FULL, &data, options(), None).unwrap();
        assert!(
            specs
                .iter()
                .all(|spec| spec.kind == FilterKind::Delta { channels: 4 }),
            "{specs:?}"
        );

        // A screen at reduced effort can tell a kind helps, not which of two
        // helps more, so both stay.
        let cheap = TestSearch {
            cheap_screens: true,
        };
        let widths: Vec<usize> = finalist_specs(&cheap, &data)
            .iter()
            .flatten()
            .filter_map(|spec| match spec.kind {
                FilterKind::Delta { channels } => Some(channels),
                _ => None,
            })
            .collect();
        assert!(widths.contains(&2) && widths.contains(&4), "{widths:?}");
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
        for screened in screen.kinds.iter() {
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

    #[test]
    fn x86_region_scan_releases_all_storage_on_each_admission_failure() {
        use crate::codec::workspace::RefusingBudget;

        let data = calls_to_fixed_addresses(256 * 1024);
        let baseline = RefusingBudget::new(usize::MAX);
        let regions = super::x86_code_regions(&data, &baseline).unwrap();
        assert!(!regions.is_empty());
        drop(regions);
        assert_eq!(baseline.used(), 0);
        assert!(baseline.attempts() > 0);

        for index in 0..baseline.attempts() {
            let budget = RefusingBudget::new(index);
            assert_eq!(
                super::x86_code_regions(&data, &budget).unwrap_err(),
                crate::Error::Cancelled,
                "admission {index}"
            );
            assert_eq!(budget.used(), 0, "admission {index}");
        }
    }

    #[test]
    fn x86_candidate_construction_releases_storage_on_each_admission_failure() {
        use crate::codec::workspace::RefusingBudget;

        let run = |budget: &RefusingBudget| -> Result<()> {
            let screen = X86Screen {
                rejected_a_region: true,
                kept: Buffer::collect(std::iter::once(0..3), budget)?,
                jumps_pay: true,
                jumps_cost_more: true,
            };
            let finalists = super::x86_finalists(&[0; 100], &screen)?;
            assert_eq!(finalists.len(), 2);
            assert!(finalists.iter().all(|specs| specs.len() == 1));
            Ok(())
        };
        let baseline = RefusingBudget::new(usize::MAX);
        run(&baseline).unwrap();
        assert_eq!(baseline.used(), 0);
        for index in 0..baseline.attempts() {
            let budget = RefusingBudget::new(index);
            assert_eq!(
                run(&budget),
                Err(crate::Error::Cancelled),
                "admission {index}"
            );
            assert_eq!(budget.used(), 0, "admission {index}");
        }
    }

    #[test]
    fn table_grafting_releases_storage_on_each_admission_failure() {
        use crate::codec::workspace::RefusingBudget;

        let run = |budget: &RefusingBudget| -> Result<()> {
            let specs = Buffer::collect([FilterSpec::whole(FilterKind::E8E9)], budget)?;
            let grafted = super::graft_owned(specs, &[(20..40, 2)], 100)?;
            assert_eq!(grafted.len(), 3);
            assert_eq!(grafted[0].range, Some(0..20));
            assert_eq!(grafted[1].range, Some(20..40));
            assert_eq!(grafted[2].range, Some(40..100));
            Ok(())
        };
        let baseline = RefusingBudget::new(usize::MAX);
        run(&baseline).unwrap();
        assert_eq!(baseline.used(), 0);
        for index in 0..baseline.attempts() {
            let budget = RefusingBudget::new(index);
            assert_eq!(
                run(&budget),
                Err(crate::Error::Cancelled),
                "admission {index}"
            );
            assert_eq!(budget.used(), 0, "admission {index}");
        }
    }

    #[test]
    fn candidate_search_preserves_codec_cancellation() {
        struct CancelledCodec;

        impl FilterSearch for CancelledCodec {
            type Options = ();

            fn screened_kinds(&self, _: &[u8]) -> Vec<FilterKind> {
                Vec::new()
            }

            fn detects_x86(&self) -> bool {
                false
            }

            fn max_delta_channels(&self) -> usize {
                0
            }

            fn filtered_bytes(&self, _: &[u8], _: &[FilterSpec]) -> Result<Vec<u8>> {
                unreachable!("no filters are proposed")
            }

            fn encode_plain(
                &self,
                _: &[u8],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Vec<u8>> {
                Err(crate::Error::Cancelled)
            }

            fn encode_filtered(
                &self,
                _: &[u8],
                _: &[FilterSpec],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Vec<u8>> {
                unreachable!("no filters are proposed")
            }
        }

        assert_eq!(
            filter_candidates(&CancelledCodec, b"binary\0member", ()),
            Err(crate::Error::Cancelled)
        );
    }

    #[test]
    fn bounded_delta_finalists_release_storage_on_each_admission_failure() {
        use crate::codec::workspace::RefusingBudget;

        struct DeltaSearch(RefusingBudget);
        impl OwnedSearch for DeltaSearch {
            type Options = ();
            type Memory = RefusingBudget;

            fn allowance(&self) -> &Self::Memory {
                &self.0
            }
            fn screened_kinds(&self, _: &[u8]) -> Result<Buffer<FilterKind, Self::Memory>> {
                Ok(Buffer::collect(
                    [1, 2, 3].map(|channels| FilterKind::Delta { channels }),
                    &self.0,
                )?)
            }
            fn detects_x86(&self) -> bool {
                false
            }
            fn max_delta_channels(&self) -> usize {
                0
            }
            fn screen_options(&self, options: ()) {
                options
            }
            fn filtered_bytes(
                &self,
                _: &[u8],
                _: &[FilterSpec],
            ) -> Result<Buffer<u8, Self::Memory>> {
                unreachable!("the whole member is measured directly")
            }
            fn encode_plain(
                &self,
                _: &[u8],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Buffer<u8, Self::Memory>> {
                Ok(Buffer::collect([0; 10], &self.0)?)
            }
            fn encode_filtered(
                &self,
                _: &[u8],
                _: &[FilterSpec],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Buffer<u8, Self::Memory>> {
                Ok(Buffer::collect([0], &self.0)?)
            }
        }

        let run = |budget: &RefusingBudget| -> Result<()> {
            let finalists = super::finalists(&DeltaSearch(budget.clone()), &[0; 512], ())?;
            assert_eq!(finalists.len(), 7);
            assert!(finalists[1].0[0].range.is_none());
            assert!(finalists[2].0[0].range.is_some());
            Ok(())
        };
        let baseline = RefusingBudget::new(usize::MAX);
        run(&baseline).unwrap();
        assert_eq!(baseline.used(), 0);
        for index in 0..baseline.attempts() {
            let budget = RefusingBudget::new(index);
            assert_eq!(
                run(&budget),
                Err(crate::Error::Cancelled),
                "admission {index}"
            );
            assert_eq!(budget.used(), 0, "admission {index}");
        }
    }

    #[test]
    fn x86_screen_releases_storage_on_each_admission_failure() {
        use crate::codec::workspace::RefusingBudget;
        use std::cell::Cell;

        struct ScreenSearch {
            budget: RefusingBudget,
            encodes: Cell<usize>,
        }
        impl OwnedSearch for ScreenSearch {
            type Options = ();
            type Memory = RefusingBudget;

            fn allowance(&self) -> &Self::Memory {
                &self.budget
            }
            fn screened_kinds(&self, _: &[u8]) -> Result<Buffer<FilterKind, Self::Memory>> {
                Ok(Buffer::new(&self.budget))
            }
            fn detects_x86(&self) -> bool {
                true
            }
            fn max_delta_channels(&self) -> usize {
                0
            }
            fn screen_options(&self, options: ()) {
                options
            }
            fn filtered_bytes(
                &self,
                data: &[u8],
                _: &[FilterSpec],
            ) -> Result<Buffer<u8, Self::Memory>> {
                Ok(Buffer::collect(data.iter().copied(), &self.budget)?)
            }
            fn encode_plain(
                &self,
                _: &[u8],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Buffer<u8, Self::Memory>> {
                let pass = self.encodes.get();
                self.encodes.set(pass + 1);
                let size = [10, 5, 6][pass];
                Ok(Buffer::collect(std::iter::repeat_n(0, size), &self.budget)?)
            }
            fn encode_filtered(
                &self,
                _: &[u8],
                _: &[FilterSpec],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Buffer<u8, Self::Memory>> {
                unreachable!("the x86 screen encodes filtered bytes as plain data")
            }
        }

        let run = |budget: &RefusingBudget| -> Result<()> {
            let search = ScreenSearch {
                budget: budget.clone(),
                encodes: Cell::new(0),
            };
            let region = 0..64;
            let result =
                super::x86_screened_regions(&search, &[0; 64], std::slice::from_ref(&region), ())?;
            assert_eq!(result.kept.len(), 1);
            assert!(!result.jumps_cost_more);
            Ok(())
        };
        let baseline = RefusingBudget::new(usize::MAX);
        run(&baseline).unwrap();
        assert_eq!(baseline.used(), 0);
        for index in 0..baseline.attempts() {
            let budget = RefusingBudget::new(index);
            assert_eq!(
                run(&budget),
                Err(crate::Error::Cancelled),
                "admission {index}"
            );
            assert_eq!(budget.used(), 0, "admission {index}");
        }
    }

    #[test]
    fn table_only_candidate_releases_storage_on_each_admission_failure() {
        use crate::codec::workspace::RefusingBudget;

        struct TableSearch(RefusingBudget);
        impl OwnedSearch for TableSearch {
            type Options = ();
            type Memory = RefusingBudget;

            fn allowance(&self) -> &Self::Memory {
                &self.0
            }
            fn screened_kinds(&self, _: &[u8]) -> Result<Buffer<FilterKind, Self::Memory>> {
                Ok(Buffer::new(&self.0))
            }
            fn detects_x86(&self) -> bool {
                false
            }
            fn max_delta_channels(&self) -> usize {
                MAX_TABLE_STRIDE
            }
            fn screen_options(&self, options: ()) {
                options
            }
            fn filtered_bytes(
                &self,
                _: &[u8],
                _: &[FilterSpec],
            ) -> Result<Buffer<u8, Self::Memory>> {
                Ok(Buffer::collect([0], &self.0)?)
            }
            fn encode_plain(
                &self,
                data: &[u8],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Buffer<u8, Self::Memory>> {
                let size = if data.len() == 1 { 1 } else { 10 };
                Ok(Buffer::collect(std::iter::repeat_n(0, size), &self.0)?)
            }
            fn encode_filtered(
                &self,
                _: &[u8],
                _: &[FilterSpec],
                _: (),
                _: Option<&mut dyn FnMut(usize) -> bool>,
            ) -> Result<Buffer<u8, Self::Memory>> {
                unreachable!("the candidate search only screens the table")
            }
        }

        let data = reloc_table(2048);
        let run = |budget: &RefusingBudget| -> Result<()> {
            let finalists = super::finalists(&TableSearch(budget.clone()), &data, ())?;
            assert_eq!(finalists.len(), 2);
            assert!(matches!(
                &finalists[1].0[..],
                [FilterSpec {
                    kind: FilterKind::Delta { channels: 24 },
                    range: Some(_),
                }]
            ));
            Ok(())
        };
        let baseline = RefusingBudget::new(usize::MAX);
        run(&baseline).unwrap();
        assert_eq!(baseline.used(), 0);
        for index in 0..baseline.attempts() {
            let budget = RefusingBudget::new(index);
            assert_eq!(
                run(&budget),
                Err(crate::Error::Cancelled),
                "admission {index}"
            );
            assert_eq!(budget.used(), 0, "admission {index}");
        }
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

    #[test]
    fn dense_x86_code_uses_a_whole_member_finalist() {
        let data = calls_to_fixed_addresses(256 * 1024);
        let regions = x86_code_regions(&data);
        let screen = x86_screened_regions(&FULL, &data, &regions, options()).unwrap();
        assert!(!screen.rejected_a_region, "{regions:?}");
        let finalists = x86_finalists(&data, &screen);
        assert!(!finalists.is_empty());
        assert!(finalists
            .iter()
            .all(|specs| specs.iter().all(|spec| spec.range.is_none())));
    }

    #[test]
    fn sparse_x86_code_prices_region_and_whole_member_finalists() {
        let code = calls_to_fixed_addresses(32 * 1024);
        let mut data = code.clone();
        data.resize(512 * 1024, 0);
        let regions = x86_code_regions(&data);
        let screen = x86_screened_regions(&FULL, &data, &regions, options()).unwrap();
        assert_eq!(screen.kept.len(), 1, "{regions:?}");
        assert!(!screen.rejected_a_region);
        let finalists = x86_finalists(&data, &screen);
        assert!(finalists
            .iter()
            .any(|specs| specs.iter().all(|spec| spec.range.is_some())));
        assert!(finalists
            .iter()
            .any(|specs| specs.iter().all(|spec| spec.range.is_none())));
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

    /// The scan counts a stride at a time, in runs. This is the count it
    /// replaced, a byte at a time and every stride at each.
    #[test]
    fn the_stride_scan_counts_what_a_byte_at_a_time_count_does() {
        fn byte_at_a_time(window: &[u8], max_stride: usize) -> [usize; MAX_TABLE_STRIDE + 1] {
            let mut hits = [0usize; MAX_TABLE_STRIDE + 1];
            for index in max_stride..window.len() {
                for stride in 1..=max_stride {
                    let diff =
                        (window[index].wrapping_sub(window[index - stride]) as i8).unsigned_abs();
                    hits[stride] += usize::from(diff <= TABLE_STRIDE_NEAR);
                }
            }
            hits
        }
        let noise = incompressible(TABLE_SCAN_WINDOW);
        let table = reloc_table(TABLE_SCAN_WINDOW / 24 + 1);
        // Every difference there is, at stride one and across the wrap, so
        // the edges of "near" are each counted on the right side.
        let steps: Vec<u8> = (0..=255u8)
            .flat_map(|step| [100, 100u8.wrapping_add(step), 250, 250u8.wrapping_add(step)])
            .collect();
        let flat = vec![7u8; 1000];
        for window in [&noise[..], &table[..], &steps[..], &flat[..]] {
            // Lengths either side of a run of 128, and windows shorter than
            // the strides they are asked about.
            for len in [
                0,
                1,
                31,
                32,
                33,
                127,
                128,
                129,
                160,
                161,
                1000,
                window.len(),
            ] {
                let window = &window[..len.min(window.len())];
                for max_stride in [1, 2, 24, MAX_TABLE_STRIDE] {
                    assert_eq!(
                        stride_hits(window, max_stride),
                        if window.len() >= max_stride {
                            byte_at_a_time(window, max_stride)
                        } else {
                            [0; MAX_TABLE_STRIDE + 1]
                        },
                        "{} bytes at up to stride {max_stride}",
                        window.len()
                    );
                }
            }
        }
        assert_eq!(stride_hits(&flat, 3)[1..=3], [997; 3]);
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

    /// One executable's relocations are a few kilobytes: too short for two
    /// default windows, and found by a format that scans finer.
    #[test]
    fn a_small_table_needs_a_fine_scan_window() {
        let table = reloc_table(200);
        let mut data = incompressible(64 * 1024);
        let table_start = data.len();
        data.extend_from_slice(&table);
        data.extend(incompressible(64 * 1024));

        assert_eq!(delta_table_regions(&data, MAX_TABLE_STRIDE), vec![]);
        let regions = table_regions(&data, MAX_TABLE_STRIDE, 256, &Allowance::default())
            .unwrap()
            .into_vec();
        assert_eq!(regions.len(), 1, "{regions:?}");
        let (region, stride) = &regions[0];
        assert_eq!(*stride, 24);
        // A window is the resolution either way: one that is mostly table
        // joins it, one that is mostly noise does not.
        let table_end = table_start + table.len();
        assert!(
            region.start + 256 > table_start && region.end < table_end + 256,
            "{region:?} strays a window past the table at {table_start}..{table_end}"
        );
        assert!(
            region.len() + 2 * 256 >= table.len(),
            "{region:?} loses more than a window at each end of {} bytes",
            table.len()
        );
    }

    #[test]
    fn a_table_keeps_the_partial_window_at_the_end_of_the_file() {
        // 2,000 records is 48,000 bytes, two scan windows plus a tail. The
        // scanner only steps in whole windows, so without the tail check the
        // delta would stop 15,232 bytes early and those records would be
        // stored as they are.
        let data = reloc_table(2_000);
        assert!(data.len() > MIN_TABLE_WINDOWS * TABLE_SCAN_WINDOW);
        assert!(!data.len().is_multiple_of(TABLE_SCAN_WINDOW));
        let regions = delta_table_regions(&data, MAX_TABLE_STRIDE);
        assert_eq!(regions, vec![(0..data.len(), 24)]);

        let cut = (data.len() / TABLE_SCAN_WINDOW * TABLE_SCAN_WINDOW) / 24 * 24;
        assert!(cut < data.len());
        let truncated = FULL
            .encode_filtered(
                &data,
                &[FilterSpec::range(
                    FilterKind::Delta { channels: 24 },
                    0..cut,
                )],
                options(),
                None,
            )
            .unwrap();
        let covered = FULL
            .encode_filtered(
                &data,
                &[FilterSpec::range(
                    FilterKind::Delta { channels: 24 },
                    0..data.len(),
                )],
                options(),
                None,
            )
            .unwrap();
        assert!(
            covered.len() < truncated.len(),
            "covering the tail packed {} against {} for the cut at {cut}",
            covered.len(),
            truncated.len()
        );
    }

    #[test]
    fn the_table_tail_does_not_reach_back_over_a_rejected_window() {
        // A table window, a noise window, then a partial window of table.
        let table = reloc_table(4_000);
        let mut data = table[..TABLE_SCAN_WINDOW].to_vec();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..TABLE_SCAN_WINDOW {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.push(x as u8);
        }
        data.extend_from_slice(&table[TABLE_SCAN_WINDOW..TABLE_SCAN_WINDOW + 16_000]);
        let regions = delta_table_regions(&data, MAX_TABLE_STRIDE);
        assert!(
            regions
                .iter()
                .all(|(range, _)| range.end <= TABLE_SCAN_WINDOW
                    || range.start >= 2 * TABLE_SCAN_WINDOW),
            "{regions:?}"
        );
    }

    #[test]
    fn a_table_without_code_gets_its_own_filter_candidate() {
        let mut data = reloc_table(2048);
        for byte in &mut data {
            if matches!(*byte, 0xe8 | 0xe9) {
                *byte = 0xe7;
            }
        }
        assert!(x86_code_regions(&data).is_empty());
        let candidates = filter_candidates(&FULL, &data, options()).unwrap();
        assert!(candidates.iter().any(|specs| matches!(
            specs.as_slice(),
            [FilterSpec {
                kind: FilterKind::Delta { channels: 24 },
                range: Some(_),
            }]
        )));
    }

    #[test]
    fn adjacent_struct_tables_with_different_record_sizes_stay_separate() {
        let mut data = reloc_table(4096);
        let boundary = data.len();
        for index in 0..8192u64 {
            data.extend_from_slice(&(0x7f80_1234_0000 + index * 8).to_le_bytes());
        }
        let regions = delta_table_regions(&data, MAX_TABLE_STRIDE);
        assert_eq!(regions.len(), 2, "{regions:?}");
        assert_eq!(regions[0].1, 24);
        assert_eq!(regions[1].1, 8);
        assert_eq!(regions[0].0.end, boundary);
        assert_eq!(regions[1].0.start, boundary);
    }

    #[test]
    fn matching_table_strides_do_not_merge_across_a_non_table_gap() {
        let mut data = reloc_table(4096);
        let first_end = data.len();
        data.extend(incompressible(2 * TABLE_SCAN_WINDOW));
        let second_start = data.len();
        data.extend(reloc_table(4096));
        let regions = delta_table_regions(&data, MAX_TABLE_STRIDE);
        assert_eq!(regions.len(), 2, "{regions:?}");
        assert_eq!(regions[0], (0..first_end, 24));
        assert_eq!(regions[1], (second_start..data.len(), 24));
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

    /// Code whose calls all reach back to a few functions at the start of the
    /// member, the way the calls in the later part of a binary reach the
    /// earlier part.
    fn calls_back_to_the_start(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491u32;
        let mut data = Vec::with_capacity(len + 16);
        while data.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            // Bodies of several lengths, so the calls fall at no fixed stride
            // and nothing here scans as a table.
            const BODY: [u8; 13] = [
                0x48, 0x89, 0x45, 0xf8, 0x8b, 0x45, 0xfc, 0x48, 0x83, 0xc0, 0x01, 0x66, 0x90,
            ];
            data.extend_from_slice(&BODY[..7 + 2 * ((state >> 20) as usize % 4)]);
            let target = 0x40u32 + ((state >> 24) & 7) * 0x400;
            let call_end = (data.len() + 5) as u32;
            data.push(0xe8);
            data.extend_from_slice(&target.wrapping_sub(call_end).to_le_bytes());
        }
        data.truncate(len);
        data
    }

    /// A sample filtered as if it began the file converts no call that reaches
    /// back past its first byte, which here is every call there is. The screen
    /// used to price that, see no difference, and decline the filter.
    #[test]
    fn the_x86_screen_filters_a_sample_where_it_lies_in_the_member() {
        let data = calls_back_to_the_start(SCREEN_SAMPLE_LEN * 4);
        let within = screen_sample_range(data.len());
        assert!(
            within.start > 0x2000,
            "the sample has to lie past the targets"
        );
        let whole = [FilterSpec::whole(FilterKind::E8E9)];
        let alone = FULL.filtered_bytes(&data[within.clone()], &whole).unwrap();
        assert_eq!(alone, &data[within.clone()], "nothing converts on its own");

        let search = UnlimitedSearch(&FULL, Allowance::default());
        let placed = filtered_sample(&search, &data, within.clone(), FilterKind::E8E9).unwrap();
        assert_eq!(placed.len(), within.len());
        let in_member = FULL.filtered_bytes(&data, &whole).unwrap();
        assert_eq!(&placed[..], &in_member[within.clone()]);
        assert_ne!(&placed[..], &data[within]);

        let plain = FULL.encode_plain(&data, options(), None).unwrap();
        let (specs, packed) = choose_filter(&FULL, &data, options(), None).unwrap();
        assert!(
            specs
                .iter()
                .any(|spec| matches!(spec.kind, FilterKind::E8 | FilterKind::E8E9)),
            "the calls went unfiltered: {specs:?}"
        );
        assert!(
            packed.len() * 10 < plain.len() * 9,
            "the x86 filter is worth more than this: {} against {}",
            packed.len(),
            plain.len()
        );
    }

    /// One instruction sequence over and over, sixteen bytes long: load an
    /// argument, call one of a few dozen functions, test what came back. Only
    /// the argument and the call's displacement change from one to the next.
    fn calls_in_one_pattern(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491u32;
        let mut step = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state >> 16
        };
        let mut data = Vec::with_capacity(len + 16);
        while data.len() < len {
            data.push(0xbf);
            data.extend_from_slice(&(step() % 4096).to_le_bytes());
            let target = 0x0010_0000u32 + (step() % 64) * 0x1230;
            let call_end = (data.len() + 5) as u32;
            data.push(0xe8);
            data.extend_from_slice(&target.wrapping_sub(call_end).to_le_bytes());
            data.extend_from_slice(&[0x85, 0xc0, 0x75, 0x04, 0x0f, 0x1f]);
        }
        data.truncate(len);
        data
    }

    /// Calls a fixed sixteen bytes apart are code and scan as a table. The
    /// delta filter the scanner offers does shrink them, which is how it gets
    /// past its screen, and the x86 filter shrinks them further.
    #[test]
    fn code_that_scans_as_a_table_is_still_measured_as_code() {
        let data = calls_in_one_pattern(SCREEN_SAMPLE_LEN * 4);
        let tables = delta_table_regions(&data, FULL.max_delta_channels());
        let tables = table_screened_regions(&FULL, &data, &tables, options()).unwrap();
        assert!(
            tables
                .iter()
                .any(|(range, stride)| *stride == 16 && range.len() * 2 > data.len()),
            "the fixture no longer scans as a table: {:?}",
            &tables[..]
        );

        let delta = [FilterSpec::whole(FilterKind::Delta { channels: 16 })];
        let delta = FULL
            .encode_filtered(&data, &delta, options(), None)
            .unwrap();
        let (specs, packed) = choose_filter(&FULL, &data, options(), None).unwrap();
        assert!(
            specs
                .iter()
                .all(|spec| matches!(spec.kind, FilterKind::E8 | FilterKind::E8E9))
                && !specs.is_empty(),
            "the code went to the table filter: {specs:?}"
        );
        assert!(
            packed.len() * 10 < delta.len() * 9,
            "the x86 filter is worth more than this: {} against {} under delta",
            packed.len(),
            delta.len()
        );
    }

    /// A relocation table in the middle of code stays a table: the x86 filter
    /// finds nothing in it, and the code around it is no reason to give it up.
    #[test]
    fn a_table_inside_code_is_still_a_table() {
        let mut data = calls_to_fixed_addresses(SCREEN_SAMPLE_LEN * 2);
        let table_start = data.len();
        data.extend_from_slice(&reloc_table(20_000));
        let table_end = data.len();
        data.extend_from_slice(&calls_to_fixed_addresses(SCREEN_SAMPLE_LEN * 2));

        let search = UnlimitedSearch(&FULL, Allowance::default());
        let tables = delta_table_regions(&data, FULL.max_delta_channels());
        let tables = table_screened_regions(&FULL, &data, &tables, options()).unwrap();
        assert!(!tables.is_empty());
        // The scanner's own regions may stop at the table. Code that covers
        // the member is the case where the table has to defend itself.
        let code = X86Screen {
            kept: Buffer::collect(std::iter::once(0..data.len()), &Allowance::default()).unwrap(),
            rejected_a_region: false,
            jumps_pay: true,
            jumps_cost_more: false,
        };
        let expected = tables.to_vec();
        let kept = tables_outside_code(&search, &data, tables, &code, options()).unwrap();
        assert_eq!(&kept[..], &expected[..]);

        let (specs, _) = choose_filter(&FULL, &data, options(), None).unwrap();
        assert!(
            specs.iter().any(|spec| {
                matches!(spec.kind, FilterKind::Delta { channels: 24 })
                    && spec
                        .range
                        .as_ref()
                        .is_some_and(|range| range.start < table_end && table_start < range.end)
            }),
            "the table lost its filter: {specs:?}"
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

    /// An unstripped binary with a relocation table in it. A candidate that
    /// bundles the table delta with the trimmed code coverage as one bet loses
    /// to the x86-only finalist here, and the table goes unfiltered.
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

    /// A search whose whole-member encodes come out the sizes it is given, and
    /// take longer the earlier the finalist, so encodes run side by side finish
    /// out of order.
    #[cfg(feature = "parallel")]
    struct Scripted {
        /// The plain member, then each delta width's whole and ranged encode.
        sizes: [usize; 7],
        /// The finalist that fails, by the same index, and how; 7 is the screen.
        failures: Vec<(usize, &'static str)>,
        in_flight: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        /// Room granted and not yet handed back.
        rooms: std::sync::atomic::AtomicUsize,
        /// Set when more encodes ran at once than the room granted covers.
        overran: std::sync::atomic::AtomicBool,
        encodes: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "parallel")]
    impl Scripted {
        const SAMPLE: usize = 8;
        const SCREEN: usize = 7;

        fn new(sizes: [usize; 7]) -> Self {
            Self {
                sizes,
                failures: Vec::new(),
                in_flight: 0.into(),
                peak: 0.into(),
                rooms: 0.into(),
                overran: false.into(),
                encodes: 0.into(),
            }
        }

        fn encode(
            &self,
            finalist: usize,
            len: usize,
            progress: Option<&mut dyn FnMut(usize) -> bool>,
        ) -> Result<Vec<u8>> {
            use std::sync::atomic::Ordering::SeqCst;
            let running = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.encodes.fetch_add(1, SeqCst);
            self.peak.fetch_max(running, SeqCst);
            if running > 1 + self.rooms.load(SeqCst) {
                self.overran.store(true, SeqCst);
            }
            let whole = finalist < Self::SCREEN;
            if whole {
                std::thread::sleep(std::time::Duration::from_millis(5 * (7 - finalist as u64)));
            }
            self.in_flight.fetch_sub(1, SeqCst);
            if let Some(&(_, error)) = self.failures.iter().find(|&&(at, _)| at == finalist) {
                return Err(crate::Error::InvalidArgument(error));
            }
            if progress.is_some_and(|report| !report(len)) {
                return Err(crate::Error::Cancelled);
            }
            Ok(vec![0; if whole { self.sizes[finalist] } else { 1000 }])
        }
    }

    #[cfg(feature = "parallel")]
    impl FilterSearch for Scripted {
        type Options = ();
        fn screened_kinds(&self, _: &[u8]) -> Vec<FilterKind> {
            (1..=3)
                .map(|channels| FilterKind::Delta { channels })
                .collect()
        }
        fn detects_x86(&self) -> bool {
            false
        }
        fn max_delta_channels(&self) -> usize {
            0
        }
        // A sample is tagged with the width it was filtered at, and each width
        // wins its screen by the same margin, so none ranks another out.
        fn filtered_bytes(&self, data: &[u8], filters: &[FilterSpec]) -> Result<Vec<u8>> {
            let mut data = data.to_vec();
            if let [FilterSpec {
                kind: FilterKind::Delta { channels },
                ..
            }] = filters
            {
                data[0] = *channels as u8;
            }
            Ok(data)
        }
        fn encode_plain(
            &self,
            data: &[u8],
            _: (),
            progress: Option<&mut dyn FnMut(usize) -> bool>,
        ) -> Result<Vec<u8>> {
            if data.len() != SCREEN_SAMPLE_LEN {
                return self.encode(0, data.len(), progress);
            }
            let screen = if self.failures.iter().any(|&(at, _)| at == Self::SCREEN) {
                Self::SCREEN
            } else {
                Self::SAMPLE
            };
            let packed = self.encode(screen, data.len(), progress)?;
            Ok(if data[0] == 0 {
                packed
            } else {
                vec![0; packed.len() / 10 * 9]
            })
        }
        fn encode_filtered(
            &self,
            data: &[u8],
            filters: &[FilterSpec],
            _: (),
            progress: Option<&mut dyn FnMut(usize) -> bool>,
        ) -> Result<Vec<u8>> {
            let [filter] = filters else {
                unreachable!("one filter per finalist")
            };
            let FilterKind::Delta { channels } = filter.kind else {
                unreachable!("only delta is screened")
            };
            let ranged = filter
                .range
                .as_ref()
                .is_some_and(|range| range.len() < data.len());
            self.encode(2 * channels - 1 + usize::from(ranged), data.len(), progress)
        }
    }

    /// Room for one more encode, while `granted` is not all held.
    #[cfg(feature = "parallel")]
    struct Room<'a>(&'a std::sync::atomic::AtomicUsize);
    #[cfg(feature = "parallel")]
    impl Drop for Room<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    #[cfg(feature = "parallel")]
    fn room(search: &Scripted, granted: usize) -> Option<Room<'_>> {
        use std::sync::atomic::Ordering::SeqCst;
        // Granted first and handed back if it was one too many, so an encode
        // can see more room than there is but never less.
        let room = Room(&search.rooms);
        (search.rooms.fetch_add(1, SeqCst) < granted).then_some(room)
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn finalists_side_by_side_choose_what_they_choose_in_turn() {
        use std::sync::atomic::Ordering::SeqCst;
        let data = vec![0u8; 2 * SCREEN_SAMPLE_LEN];
        let delta = |channels, ranged: bool| {
            let kind = FilterKind::Delta { channels };
            if ranged {
                FilterSpec::range(kind, auto_delta_filter_range(&data, channels).unwrap())
            } else {
                FilterSpec::whole(kind)
            }
        };
        let cases: [([usize; 7], Vec<FilterSpec>); 4] = [
            // A tie goes to the earlier finalist.
            ([500, 400, 400, 300, 300, 300, 301], vec![delta(2, false)]),
            ([500, 400, 399, 300, 301, 300, 299], vec![delta(3, true)]),
            // The plain member keeps a tie with the best of the rest.
            ([500, 600, 500, 700, 500, 501, 900], Vec::new()),
            ([500, 501, 502, 503, 504, 505, 499], vec![delta(3, true)]),
        ];
        let pool = crate::parallel::private_pool(4);
        for (sizes, winner) in cases {
            let search = Scripted::new(sizes);
            let (specs, packed) = choose_filter(&search, &data, (), None).unwrap();
            assert_eq!(
                (&specs, packed.len()),
                (&winner, *sizes.iter().min().unwrap())
            );
            for granted in [0, 1, 2, 8] {
                let search = Scripted::new(sizes);
                let chosen = pool.install(|| {
                    choose_filter_side_by_side(&search, &data, (), None, &|| room(&search, granted))
                });
                assert_eq!(
                    chosen.unwrap(),
                    (specs.clone(), packed.clone()),
                    "{sizes:?} {granted}"
                );
                assert!(!search.overran.load(SeqCst), "{sizes:?} {granted}");
                assert_eq!(search.rooms.load(SeqCst), 0, "room handed back");
                // Room for one more puts the plain member beside the screens,
                // and room for more puts the finalists after it side by side.
                assert_eq!(
                    search.peak.load(SeqCst).min(3),
                    granted.min(2) + 1,
                    "{granted}"
                );
            }
            // Capped to one thread there is nothing to run beside, so no room is asked for.
            let search = Scripted::new(sizes);
            let chosen = pool.install(|| {
                let _cap = crate::parallel::ThreadCap::set(Some(1));
                choose_filter_side_by_side(&search, &data, (), None, &|| -> Option<()> {
                    panic!("room asked for at one thread")
                })
            });
            assert_eq!(chosen.unwrap(), (specs.clone(), packed.clone()));
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn finalists_side_by_side_fail_and_cancel_as_they_do_in_turn() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let data = vec![0u8; 2 * SCREEN_SAMPLE_LEN];
        let pool = crate::parallel::private_pool(4);
        let sizes = [500, 400, 400, 300, 300, 300, 301];
        for failures in [
            vec![(3, "delta 2"), (5, "delta 3")],
            vec![(6, "last")],
            // The plain member is encoded beside the screens, but in turn the
            // screens ran first, so theirs is the failure reported.
            vec![(0, "plain"), (Scripted::SCREEN, "screen")],
            vec![(0, "plain"), (4, "ranged")],
        ] {
            let mut search = Scripted::new(sizes);
            search.failures = failures.clone();
            let serial = choose_filter(&search, &data, (), None).unwrap_err();
            for granted in [0, 1, 8] {
                let chosen = pool.install(|| {
                    choose_filter_side_by_side(&search, &data, (), None, &|| room(&search, granted))
                });
                assert_eq!(chosen.unwrap_err(), serial, "{failures:?} {granted}");
                assert_eq!(search.rooms.load(SeqCst), 0);
            }
        }

        // Each encode reports its own walk, so the total is the one reported in turn.
        let search = Scripted::new(sizes);
        let mut serial = 0;
        let mut last = 0;
        choose_filter(
            &search,
            &data,
            (),
            Some(&mut |event| {
                match event {
                    EncodeProgress::PassStarted => last = 0,
                    EncodeProgress::Advanced(position) => {
                        serial += position - last;
                        last = position;
                    }
                }
                true
            }),
        )
        .unwrap();
        let search = Scripted::new(sizes);
        let walked = AtomicUsize::new(0);
        let starts = AtomicUsize::new(0);
        pool.install(|| {
            choose_filter_side_by_side(
                &search,
                &data,
                (),
                Some(&|bytes| {
                    walked.fetch_add(bytes, SeqCst);
                    starts.fetch_add(usize::from(bytes == 0), SeqCst);
                    true
                }),
                &|| room(&search, 8),
            )
        })
        .unwrap();
        assert_eq!(walked.into_inner(), serial);
        assert_eq!(starts.into_inner(), search.encodes.load(SeqCst));

        // A cancelled search encodes nothing, beside the screens or after them.
        for granted in [0, 8] {
            let search = Scripted::new(sizes);
            let chosen = pool.install(|| {
                choose_filter_side_by_side(&search, &data, (), Some(&|_| false), &|| {
                    room(&search, granted)
                })
            });
            assert_eq!(chosen, Err(crate::Error::Cancelled));
            assert_eq!(search.encodes.load(SeqCst), 0);
        }
    }
}
