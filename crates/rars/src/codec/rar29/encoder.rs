//! RAR29 LZ and PPMd encoding, filter preparation and table emission.
use super::super::ppmd::{PpmdEncoder, PpmdModel};
use super::super::{
    filters::{self, FilterOp},
    huffman, match_finder,
};
use super::standard_filters::rgb_predict;
use super::*;
use std::io::Read;
use std::ops::ControlFlow;

const MAX_VM_FILTER_BLOCK_SIZE: usize = 128 * 1024;
// The standard AUDIO bytecode uses separate input/output regions inside RARVM
// memory. Keep generated blocks below the overlap boundary accepted by period
// decoders.
pub(crate) const MAX_VM_DELTA_FILTER_BLOCK_SIZE: usize = 120_000;
const MAX_VM_AUDIO_FILTER_BLOCK_SIZE: usize = 120_000;
const MAX_ENCODER_MATCH_OFFSET: usize = 1024 * 1024;
const MAX_ENCODER_MATCH_LENGTH: usize = 258;
const MAX_MATCH_CANDIDATES: usize = 256;
const MAX_PPMD_MATCH_LENGTH: usize = 255;
const MIN_PPMD_MATCH_LENGTH: usize = 32;
const MAX_PPMD_REPEAT_LENGTH: usize = 259;
// The parameters rar 3.00 itself declares at -m5, read out of its streams.
const PPMD_ORDER: usize = 8;
const PPMD_DICTIONARY_MB: u8 = 25;
pub(crate) const PPMD_MODEL_BYTES: u64 = PPMD_DICTIONARY_MB as u64 * 1024 * 1024;

/// The order and memory a PPMd block declares when it starts a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PpmdModelSize {
    pub(crate) order: usize,
    pub(crate) memory_mb: u8,
}

impl PpmdModelSize {
    pub(crate) const DEFAULT: Self = Self {
        order: PPMD_ORDER,
        memory_mb: PPMD_DICTIONARY_MB,
    };

    pub(crate) const fn bytes(self) -> u64 {
        self.memory_mb as u64 * 1024 * 1024
    }

    /// The header's five order bits. Past 16 they count in threes, so only
    /// 19, 22 and so on are expressible there.
    const fn order_bits(self) -> u8 {
        if self.order <= 16 {
            self.order as u8 - 1
        } else {
            ((self.order - 16) / 3 + 15) as u8
        }
    }
}
const PPMD_ESC: u8 = 2;
// Seeds and weights for the escape-token cost model in `encode_ppmd_hybrid`.
// The seeds only steer the first few decisions; measured costs take over as
// the member is coded. All five are tuning knobs, not format constants.
const PPMD_LITERAL_BITS_SEED: f64 = 4.0;
const PPMD_MATCH_BITS_SEED: f64 = 60.0;
const PPMD_REPEAT_BITS_SEED: f64 = 24.0;
const PPMD_LITERAL_EMA_WEIGHT: f64 = 1.0 / 32.0;
const PPMD_TOKEN_EMA_WEIGHT: f64 = 1.0 / 8.0;
// An escape token's copied bytes never reach the model, so the literals right
// after it are predicted from the token's own bytes and pay for the broken
// context. That cost lands on the literals' ledger, not the token's, so the
// token is charged a flat estimate of it here. 16 took matches that cost more
// than the literals: 64 packs 4 MiB of Rust source 4% smaller.
const PPMD_CONTEXT_BREAK_BITS: f64 = 64.0;
// After a match is priced out, nearby positions almost always price out the
// same way, so the search sleeps a few bytes rather than re-walking the hash
// chain at every literal.
const PPMD_REJECT_SEARCH_COOLDOWN: usize = 8;

type Rar29MatchFinder = match_finder::MatchFinder<4>;
/// Chains keyed on six bytes, for a parse that walks only a few candidates.
type Rar29LongMatchFinder = match_finder::MatchFinder<6>;

/// The most candidates a parse walks for its chains to key on six bytes.
///
/// A chain holds every earlier position that shares its key, newest first, and
/// a parse that walks a handful of them never gets past the newest. On text
/// the newest positions sharing four bytes are spaces, indentation and common
/// words, which match a few bytes, and the copy that runs on is further down.
/// Keyed on six bytes a chain holds far fewer of those, so the same walk
/// reaches back to it. The four- and five-byte matches it can no longer offer
/// come from [`NearMatches`] instead.
///
/// A greedy parse walks half its candidates on six-byte chains. It is the
/// fastest level, and a chain of positions sharing six bytes holds the copy
/// that runs on near its head, where four-byte chains bury it.
///
/// A lazy parse walking 64 candidates, as level 3 does, already reaches most of
/// what a long key would find, and executables come out larger keyed on six
/// there. A short member keeps four-byte chains (see [`LONG_KEY_MIN_SPAN`]).
const LONG_KEY_MAX_CANDIDATES: usize = 16;

/// How many bytes a member and the history before it must span for its
/// chains to key on six bytes.
///
/// A member of a few tens of kilobytes keeps its chains short enough to walk
/// in full. Keyed on six it loses the four- and five-byte matches further back
/// than the near matches reach, and gains nothing.
const LONG_KEY_MIN_SPAN: usize = 1024 * 1024;

/// Whether a parse searching `options` walks few enough candidates to key its
/// chains on six bytes over a long span, and so keeps near matches at any
/// span. One refined by shortest path keeps four-byte chains, which it prices
/// from.
fn walks_few(options: EncodeOptions) -> bool {
    (1..=LONG_KEY_MAX_CANDIDATES).contains(&options.max_match_candidates)
        && options.optimal_parse_passes == 0
}

/// Whether a member spanning `span` bytes with the history it reaches keys its
/// chains on six bytes. Judged from lengths alone, so a member parses the same
/// read whole or in segments.
fn keys_long(options: EncodeOptions, span: usize) -> bool {
    walks_few(options) && span >= LONG_KEY_MIN_SPAN
}

/// The chains a parse walks, keyed as [`keys_long`] says.
enum ChainFinder {
    Short(Rar29MatchFinder),
    Long(Rar29LongMatchFinder),
}

impl ChainFinder {
    fn for_reach(window: usize, reach: usize, long: bool) -> Self {
        match long {
            true => Self::Long(Rar29LongMatchFinder::for_reach(window, reach)),
            false => Self::Short(Rar29MatchFinder::for_reach(window, reach)),
        }
    }

    fn insert(&mut self, input: &[u8], pos: usize) {
        match self {
            Self::Short(finder) => finder.insert(input, pos),
            Self::Long(finder) => finder.insert(input, pos),
        }
    }

    #[cfg(test)]
    fn window(&self) -> usize {
        match self {
            Self::Short(finder) => finder.window(),
            Self::Long(finder) => finder.window(),
        }
    }
}
/// PPMd takes only 32-byte matches; a 4-byte key fills text chains with words that never get there.
type PpmdMatchFinder = match_finder::MatchFinder<MIN_PPMD_MATCH_LENGTH>;

/// A finder filled as the parse goes, or ahead of it and skipping what the parse has not reached.
trait Candidates {
    fn first(&self, input: &[u8], pos: usize, limit: usize) -> usize;
    fn previous(&self, candidate: usize) -> usize;
    fn insert(&mut self, input: &[u8], pos: usize);
    /// The newest candidate before `pos`, once `pos` itself has been inserted.
    fn before(&self, pos: usize) -> usize;
    /// How many bytes a position's chain is keyed on. A position with fewer
    /// left before its block ends is not looked up: whether it was inserted
    /// depends on where the bytes in hand end, which is not where the block does.
    fn key(&self) -> usize;
}

impl<const MIN_MATCH: usize> Candidates for match_finder::MatchFinder<MIN_MATCH> {
    fn first(&self, input: &[u8], pos: usize, _limit: usize) -> usize {
        match_finder::MatchFinder::first(self, input, pos)
    }

    fn key(&self) -> usize {
        MIN_MATCH
    }

    fn before(&self, pos: usize) -> usize {
        self.first_before(pos, pos)
    }

    fn previous(&self, candidate: usize) -> usize {
        match_finder::MatchFinder::previous(self, candidate)
    }

    fn insert(&mut self, input: &[u8], pos: usize) {
        match_finder::MatchFinder::insert(self, input, pos);
    }
}

struct FilledAhead<'a, const MIN_MATCH: usize = 4>(&'a match_finder::MatchFinder<MIN_MATCH>);

impl<const MIN_MATCH: usize> Candidates for FilledAhead<'_, MIN_MATCH> {
    fn first(&self, _input: &[u8], pos: usize, limit: usize) -> usize {
        self.0.first_before(pos, limit)
    }

    fn key(&self) -> usize {
        MIN_MATCH
    }

    fn previous(&self, candidate: usize) -> usize {
        self.0.previous(candidate)
    }

    fn insert(&mut self, _input: &[u8], _pos: usize) {}

    fn before(&self, pos: usize) -> usize {
        self.0.first_before(pos, pos)
    }
}

// RAR 3.x standard filters are stored as RARVM bytecode in the compressed
// stream. RAR15_40_FORMAT_SPECIFICATION.md §20 and FILTER_TRANSFORMS.md §9
// define these blobs by byte length plus CRC32 fingerprint; keep the bytes
// verbatim so writer output and reader recognition use the same wire identity.
const RAR3_E8_FILTER_BYTECODE: &[u8] = &[
    0x97, 0x1b, 0x01, 0x28, 0x07, 0x06, 0x98, 0x08, 0x00, 0x00, 0x00, 0xd1, 0x3a, 0x10, 0x15, 0x92,
    0xec, 0x50, 0xcb, 0x99, 0x20, 0xb9, 0x25, 0xf0, 0x29, 0x19, 0x15, 0x53, 0x03, 0x12, 0xae, 0x51,
    0x10, 0x35, 0x59, 0x2b, 0x60, 0x04, 0x15, 0x6d, 0x40, 0x66, 0xab, 0x02, 0x34, 0x49, 0x04, 0x36,
    0x02, 0x52, 0x3e, 0x97, 0x00,
];
const RAR3_E8E9_FILTER_BYTECODE: &[u8] = &[
    0x84, 0x1b, 0x01, 0x28, 0x11, 0x10, 0x69, 0x80, 0x80, 0x00, 0x00, 0x0d, 0x13, 0xa1, 0x01, 0xc6,
    0x89, 0xd2, 0x80, 0xac, 0x97, 0x62, 0x85, 0x5c, 0xc9, 0x05, 0xc9, 0x2f, 0x81, 0x48, 0xc8, 0xaa,
    0x98, 0x18, 0x95, 0x72, 0x88, 0x81, 0xaa, 0xc9, 0x5b, 0x00, 0x20, 0xab, 0x6a, 0x03, 0x35, 0x58,
    0x11, 0xa2, 0x48, 0x21, 0xb0, 0x12, 0x91, 0xf4, 0xb8,
];
const RAR3_DELTA_FILTER_BYTECODE: &[u8] = &[
    0x2f, 0x01, 0x9a, 0x41, 0x80, 0xec, 0x27, 0x48, 0x2f, 0x09, 0x76, 0x6d, 0xd3, 0xea, 0x41, 0x5b,
    0x59, 0x44, 0xe8, 0x17, 0x5c, 0xe1, 0x6c, 0x91, 0x4c, 0x4e, 0x3f, 0x77, 0x00,
];
const RAR3_ITANIUM_FILTER_BYTECODE: &[u8] = &[
    0x46, 0x9e, 0x08, 0x08, 0x0c, 0x0c, 0x00, 0x00, 0x0e, 0x0e, 0x08, 0x08, 0x00, 0x00, 0x08, 0x08,
    0x00, 0x00, 0x6c, 0x11, 0x5a, 0x04, 0xac, 0x0c, 0xc4, 0xcc, 0x5c, 0x08, 0x18, 0x46, 0x24, 0x08,
    0xf9, 0xa0, 0x44, 0x25, 0x12, 0x12, 0x45, 0x85, 0x99, 0x0c, 0x14, 0x00, 0x26, 0x25, 0x58, 0x99,
    0x90, 0x03, 0x38, 0x1a, 0x08, 0xdc, 0x02, 0x30, 0x0c, 0x4e, 0xd1, 0x1d, 0x89, 0xa1, 0xe2, 0xd0,
    0x55, 0x11, 0x33, 0x60, 0x8c, 0x5a, 0x23, 0x06, 0xde, 0x06, 0x18, 0x00, 0x7f, 0xff, 0xfc, 0x4d,
    0xcc, 0x19, 0x17, 0xb3, 0x06, 0xc4, 0x44, 0xb2, 0x32, 0x5a, 0x44, 0xc4, 0xa6, 0x01, 0xf4, 0x24,
    0x88, 0x83, 0x38, 0xcc, 0xc4, 0x11, 0x09, 0x87, 0xa6, 0xe0, 0x46, 0x02, 0xb2, 0x24, 0x03, 0xe2,
    0xa0, 0x32, 0x54, 0x83, 0x52, 0xc5, 0xb1, 0x70,
];
const RAR3_RGB_FILTER_BYTECODE: &[u8] = &[
    0xc5, 0x01, 0x9a, 0x41, 0x95, 0xc9, 0xa6, 0x4d, 0xba, 0x4b, 0x14, 0x0a, 0xf4, 0x9b, 0x80, 0x4c,
    0x00, 0x15, 0xa6, 0xa8, 0x07, 0x26, 0x2a, 0xc9, 0xc4, 0x8b, 0x86, 0x62, 0x32, 0x0f, 0x86, 0x64,
    0x24, 0x06, 0x66, 0x71, 0x19, 0x98, 0xcc, 0x43, 0x33, 0x31, 0x99, 0x00, 0x66, 0x88, 0x33, 0x30,
    0xcc, 0xd1, 0x0e, 0x98, 0x0b, 0x33, 0x34, 0x40, 0x0c, 0xd1, 0x46, 0x66, 0x19, 0x9a, 0x28, 0xcc,
    0x49, 0x80, 0xb3, 0x33, 0x45, 0x00, 0xcd, 0x18, 0x66, 0x61, 0x99, 0xa3, 0x0c, 0xc8, 0x98, 0x0b,
    0x33, 0x34, 0x60, 0x4c, 0xd1, 0x06, 0x68, 0xa5, 0x20, 0x62, 0x66, 0x88, 0x33, 0x46, 0x28, 0x05,
    0x0f, 0x32, 0x0c, 0x4c, 0xd1, 0x46, 0x68, 0xc5, 0x00, 0x41, 0xe4, 0x8f, 0xc8, 0x85, 0x5e, 0x02,
    0x7c, 0xc9, 0x26, 0x81, 0x83, 0xb0, 0x9d, 0xc2, 0xde, 0x9c, 0x78, 0xac, 0xd6, 0x68, 0xb4, 0x0e,
    0x71, 0xdb, 0xb2, 0x49, 0x38, 0x6e, 0x02, 0x2a, 0x2c, 0x41, 0x2b, 0x10, 0x98, 0x82, 0x49, 0x03,
    0x14, 0xf4, 0xe1, 0x97, 0x00,
];
const RAR3_AUDIO_FILTER_BYTECODE: &[u8] = &[
    0x47, 0x01, 0x9a, 0x41, 0x95, 0xe5, 0x72, 0x0d, 0xc2, 0x64, 0x82, 0x74, 0x93, 0x24, 0xb1, 0x40,
    0x06, 0xd8, 0x38, 0x44, 0x00, 0xa8, 0x01, 0x34, 0x11, 0xdc, 0xa1, 0xba, 0x01, 0x99, 0x0c, 0xc4,
    0x03, 0x31, 0x19, 0xa4, 0x06, 0x66, 0x22, 0x60, 0x4d, 0x9a, 0x40, 0x0d, 0x66, 0x8e, 0x60, 0xd0,
    0x30, 0x40, 0x18, 0x26, 0xc1, 0xc8, 0xf6, 0xe6, 0x26, 0x13, 0x78, 0x92, 0x08, 0xe8, 0x50, 0xbc,
    0x5a, 0x07, 0xc6, 0xe9, 0xf5, 0x20, 0xa9, 0xa0, 0xed, 0x37, 0x33, 0x47, 0x39, 0x66, 0x90, 0x70,
    0x19, 0xa3, 0x9b, 0xcf, 0x25, 0x83, 0x80, 0xc1, 0xbd, 0x30, 0x16, 0x6e, 0x23, 0x34, 0x93, 0x81,
    0x16, 0x09, 0xb0, 0x50, 0x18, 0x3b, 0x4d, 0xc8, 0x4c, 0x05, 0x9b, 0x88, 0xc5, 0x28, 0xe0, 0x76,
    0x93, 0x90, 0x98, 0x0b, 0x37, 0x11, 0x8a, 0x59, 0xc4, 0x80, 0x42, 0x48, 0x43, 0xa9, 0x47, 0xee,
    0x43, 0x34, 0x60, 0x47, 0xd4, 0x4a, 0x0d, 0xbb, 0xd3, 0x59, 0xa4, 0x86, 0xee, 0x05, 0x09, 0x40,
    0x26, 0xc9, 0x34, 0x24, 0x76, 0xa0, 0x30, 0x6a, 0x20, 0xea, 0x02, 0x20, 0x04, 0xa0, 0x41, 0x50,
    0x9e, 0x50, 0x3f, 0xe6, 0xe1, 0x28, 0x94, 0x46, 0x01, 0xbd, 0x8b, 0x40, 0xf0, 0x68, 0x11, 0x36,
    0xc9, 0xa1, 0x92, 0x38, 0x11, 0x41, 0x9c, 0xa8, 0x95, 0x10, 0xee, 0x50, 0x66, 0x2b, 0x00, 0x20,
    0x95, 0x11, 0x04, 0x02, 0x62, 0xac, 0x66, 0x8c, 0x6a, 0xca, 0x26, 0x40, 0xb2, 0x67, 0x1b, 0x4b,
    0x26, 0xcc, 0x64, 0x8a, 0x62, 0x71, 0xa2, 0xb8,
];

pub fn unpack29_encode_literals(input: &[u8]) -> Result<Vec<u8>> {
    encode_member(input, &[])
}

pub fn unpack29_encode_literals_with_options(
    input: &[u8],
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_options(input, &[], options)
}

pub(crate) fn unpack29_encode_literals_with_options_and_progress(
    input: &[u8],
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_member_with_options_and_progress(input, &[], options, &mut [0; TABLE_COUNT], progress)
}

pub fn unpack29_encode_ppmd_literals(input: &[u8]) -> Result<Vec<u8>> {
    encode_ppmd_member(input, false, None, 0)
}

/// One member as PPMd, filtered first when `filter` is given, starting a
/// model of the given size.
pub(crate) fn unpack29_encode_ppmd_with_progress(
    input: &[u8],
    lz_escapes: bool,
    filter: Option<crate::FilterSpec>,
    max_match_distance: usize,
    size: PpmdModelSize,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    if !progress(0) {
        return Err(Error::Cancelled);
    }
    let (filtered, mut declared) = match filter {
        Some(filter) => {
            let filters = split_large_filter(input.len(), filter)?;
            let filtered =
                filtered_members_with_progress(input, 0, &filters, Some(&mut *progress))?;
            (
                Some(filtered.data),
                Some(PpmdFilters::applied(filtered.records)),
            )
        }
        None => (None, None),
    };
    encode_ppmd_block_with_model(
        filtered.as_deref().unwrap_or(input),
        lz_escapes,
        declared.as_mut(),
        max_match_distance,
        None,
        size,
        Some(progress),
    )
    .map(|(packed, _)| packed)
}

/// `max_match_distance` is the dictionary the file header declares. PPMd's
/// escape-4 matches copy out of the same window the LZ decoder uses, so a match
/// that reaches further back than the header promises lands on whatever the
/// decoder still happens to hold, and unrar fails the member on its checksum.
pub fn unpack29_encode_ppmd(input: &[u8], max_match_distance: usize) -> Result<Vec<u8>> {
    encode_ppmd_member(input, true, None, max_match_distance)
}

pub fn unpack29_encode_ppmd_with_filter(
    input: &[u8],
    filter: crate::FilterSpec,
    max_match_distance: usize,
) -> Result<Vec<u8>> {
    encode_ppmd_filtered_member(input, filter, true, max_match_distance)
}

fn encode_ppmd_filtered_member(
    input: &[u8],
    filter: crate::FilterSpec,
    lz_escapes: bool,
    max_match_distance: usize,
) -> Result<Vec<u8>> {
    let filters = split_large_filter(input.len(), filter)?;
    let filtered = filtered_members(input, 0, &filters)?;
    let mut declared = PpmdFilters::applied(filtered.records);
    encode_ppmd_member(
        &filtered.data,
        lz_escapes,
        Some(&mut declared),
        max_match_distance,
    )
}

/// A filtered copy of `input`, which lies `offset` bytes into its member.
///
/// `filters` are ranged over `input`, and so are the records that come back.
/// The offset is where the x86 filters convert calls from, so a search over one
/// streamed segment measures them as the segment will be written.
pub(crate) fn filtered_members(
    input: &[u8],
    offset: usize,
    filters: &[crate::FilterSpec],
) -> Result<FilteredMembers> {
    filtered_members_with_progress(input, offset, filters, None)
}

fn filtered_members_with_progress(
    input: &[u8],
    offset: usize,
    filters: &[crate::FilterSpec],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<FilteredMembers> {
    let moved = filters
        .iter()
        .map(|filter| {
            let range = checked_filter_range(input.len(), filter)?;
            Ok(crate::FilterSpec::range(
                filter.kind,
                offset + range.start..offset + range.end,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut data = input.to_vec();
    let mut records = filter_window(&mut data, offset, &moved, progress)?;
    for record in &mut records {
        record.block_start -= offset;
    }
    Ok(FilteredMembers { data, records })
}

/// `data` is the member from `offset` on, so a streamed segment filters where it lies.
fn filter_window(
    data: &mut [u8],
    offset: usize,
    filters: &[crate::FilterSpec],
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<OwnedVmFilterRecord>> {
    let member_len = offset + data.len();
    let mut ordered = filters.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|filter| filter.range.as_ref().map_or(0, |range| range.start));
    let mut records = Vec::with_capacity(filters.len());
    let mut index = 0;
    let mut previous_end = 0;
    while index < ordered.len() {
        let range = checked_filter_range(member_len, ordered[index])?;
        if range.start < previous_end {
            return Err(Error::InvalidData("RAR 2.9 VM filters partially overlap"));
        }

        let mut group_end = index + 1;
        while group_end < ordered.len()
            && ordered[group_end].range.clone().unwrap_or(0..member_len) == range
        {
            group_end += 1;
        }
        let mut group_records = Vec::with_capacity(group_end - index);
        // Decoding runs records in wire order. Apply their inverses in reverse
        // so each decoder invocation receives the prior one's output.
        for filter in ordered[index..group_end].iter().rev() {
            // Large ranges have already been split into bounded records. Poll
            // between them without advancing encoded-byte progress, so filter
            // preprocessing cannot hide cancellation for an entire member.
            if progress.as_mut().is_some_and(|report| !report(0)) {
                return Err(Error::Cancelled);
            }
            if !x86_offsets_invert(filter.kind, &range) {
                continue;
            }
            let filtered = filter_in_place(data, offset, filter)?;
            group_records.push(OwnedVmFilterRecord {
                block_start: filtered.block_start,
                block_size: filtered.block_size,
                init_regs: filtered.init_regs,
                code: filtered.code,
                global_data: Vec::new(),
            });
        }
        group_records.reverse();
        records.extend(group_records);
        previous_end = range.end;
        index = group_end;
    }
    Ok(records)
}

pub(crate) struct FilteredMembers {
    pub(crate) data: Vec<u8>,
    records: Vec<OwnedVmFilterRecord>,
}

fn split_large_filter(
    input_len: usize,
    filter: crate::FilterSpec,
) -> Result<Vec<crate::FilterSpec>> {
    let range = checked_filter_range(input_len, &filter)?;
    let (_, chunk_size) = filter_chunking(filter.kind)?;
    if range.len() <= chunk_size {
        return Ok(vec![filter]);
    }
    Ok(FilterPieces::new(input_len, &filter)?
        .map(|piece| crate::FilterSpec::range(filter.kind, piece))
        .collect())
}

/// The ranges [`split_large_filter`] cuts a filter into, worked out one at a time.
#[derive(Clone)]
struct FilterPieces {
    next: usize,
    end: usize,
    chunk_size: usize,
    unit: usize,
}

impl FilterPieces {
    fn new(input_len: usize, filter: &crate::FilterSpec) -> Result<Self> {
        let range = checked_filter_range(input_len, filter)?;
        let (unit, chunk_size) = filter_chunking(filter.kind)?;
        Ok(Self {
            next: range.start,
            end: range.end,
            chunk_size,
            // A range one record covers is kept whole, however short.
            unit: if range.len() <= chunk_size { 0 } else { unit },
        })
    }
}

impl Iterator for FilterPieces {
    type Item = std::ops::Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.next.saturating_add(self.chunk_size).min(self.end);
        // Chunking can leave a remainder the filter has no way to transform.
        // Those bytes stay as they are; a filter covering part of a member is
        // exactly what a range is for.
        if self.next >= self.end || end - self.next < self.unit {
            return None;
        }
        let piece = self.next..end;
        self.next = end;
        Some(piece)
    }
}

/// The fewest bytes a filter of `kind` transforms, and the most one record covers.
fn filter_chunking(kind: crate::FilterKind) -> Result<(usize, usize)> {
    // The smallest run of bytes each filter can still transform. A trailing
    // chunk shorter than this is left unfiltered rather than handed to a filter
    // that cannot process it.
    let unit = match rar29_filter(kind)? {
        Rar29Filter::Delta { channels } | Rar29Filter::Audio { channels } => channels,
        Rar29Filter::Rgb { width, .. } => width.max(3),
        Rar29Filter::E8 | Rar29Filter::E8E9 | Rar29Filter::Itanium => 4,
    };
    let chunk_size = match rar29_filter(kind)? {
        Rar29Filter::Delta { channels } => {
            if channels == 0 || channels > MAX_VM_DELTA_FILTER_BLOCK_SIZE {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM filter channel count is invalid",
                ));
            }
            MAX_VM_DELTA_FILTER_BLOCK_SIZE - (MAX_VM_DELTA_FILTER_BLOCK_SIZE % channels)
        }
        Rar29Filter::Audio { channels } => {
            if channels == 0 || channels > MAX_AUDIO_CHANNELS {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM filter channel count is invalid",
                ));
            }
            MAX_VM_AUDIO_FILTER_BLOCK_SIZE - (MAX_VM_AUDIO_FILTER_BLOCK_SIZE % channels)
        }
        Rar29Filter::Rgb { width, .. } => {
            if width == 0 || width > MAX_VM_FILTER_BLOCK_SIZE {
                return Err(Error::InvalidData(
                    "RAR 2.9 RGB filter scanline width is invalid",
                ));
            }
            MAX_VM_FILTER_BLOCK_SIZE - (MAX_VM_FILTER_BLOCK_SIZE % width)
        }
        Rar29Filter::E8 | Rar29Filter::E8E9 | Rar29Filter::Itanium => MAX_VM_FILTER_BLOCK_SIZE,
    };
    Ok((unit, chunk_size))
}

/// A named filter's share of each streamed segment in turn, for [`Unpack29Encoder::encode_lz_streamed`].
///
/// Records are cut where [`split_large_filter`] cuts the whole member, so a
/// member streams the records it would code in memory. A record a segment
/// boundary falls inside is cut there too, since a segment is filtered before
/// the next one is read, and a piece too short to transform stays as it is.
pub(crate) fn named_filter_segments(
    len: usize,
    filter: crate::FilterSpec,
) -> Result<impl FnMut(&[u8], usize) -> Result<Vec<crate::FilterSpec>>> {
    let range = checked_filter_range(len, &filter)?;
    let (unit, chunk_size) = filter_chunking(filter.kind)?;
    let (step, end) = match range.len() <= chunk_size {
        true => (range.len(), range.end),
        false => match range.len() % chunk_size {
            tail if tail < unit => (chunk_size, range.end - tail),
            _ => (chunk_size, range.end),
        },
    };
    Ok(move |segment: &[u8], start: usize| {
        let stop = start + segment.len();
        let mut pieces = Vec::new();
        let mut from = range.start + start.saturating_sub(range.start) / step * step;
        while from < end.min(stop) {
            let to = (from + step).min(end);
            let (lo, hi) = (from.max(start), to.min(stop));
            if (lo, hi) == (from, to) || hi - lo >= unit {
                pieces.push(crate::FilterSpec::range(
                    filter.kind,
                    lo - start..hi - start,
                ));
            }
            from = to;
        }
        Ok(pieces)
    })
}

/// Whether a decoder can undo the x86 filter on every operand in `range`.
///
/// It finds an operand from its position in the member, as a `u32`. Where that
/// position is past 2^31 (mod 2^32), no encoding decodes back to some operands,
/// small forward calls among them, so those stretches stay unfiltered. The
/// decoder looks for opcodes up to five bytes from the range's end.
fn x86_offsets_invert(kind: crate::FilterKind, range: &std::ops::Range<usize>) -> bool {
    if !matches!(kind, crate::FilterKind::E8 | crate::FilterKind::E8E9) || range.len() <= 4 {
        return true;
    }
    let (first, last) = (range.start as u64, (range.end - 5) as u64);
    first >> 32 == last >> 32 && last & 0xffff_ffff < 1 << 31
}

fn checked_filter_range(
    input_len: usize,
    filter: &crate::FilterSpec,
) -> Result<std::ops::Range<usize>> {
    let range = filter.range.clone().unwrap_or(0..input_len);
    if range.start >= range.end || range.end > input_len {
        return Err(Error::InvalidData("RAR 2.9 VM filter range is invalid"));
    }
    Ok(range)
}

#[derive(Clone)]
struct OwnedVmFilterRecord {
    block_start: usize,
    block_size: usize,
    init_regs: Vec<(usize, u32)>,
    code: &'static [u8],
    global_data: Vec<u8>,
}

fn encode_ppmd_member(
    input: &[u8],
    lz_escapes: bool,
    filters: Option<&mut PpmdFilters>,
    max_match_distance: usize,
) -> Result<Vec<u8>> {
    encode_ppmd_block(input, lz_escapes, filters, max_match_distance)
}

fn encode_ppmd_block(
    input: &[u8],
    lz_escapes: bool,
    filters: Option<&mut PpmdFilters>,
    max_match_distance: usize,
) -> Result<Vec<u8>> {
    encode_ppmd_block_with_model(
        input,
        lz_escapes,
        filters,
        max_match_distance,
        None,
        PpmdModelSize::DEFAULT,
        None,
    )
    .map(|(packed, _)| packed)
}

/// Codes one PPMd block, either starting a model or carrying one on.
///
/// The header byte's 0x20 bit tells the reader to throw its model away and
/// build a new one from the order and dictionary size that follow. Clearing it
/// leaves the reader's model where it is, which is how a solid chain gets a
/// model that has already read every member before this one. WinRAR does this
/// on 67 of the 68 PPMd blocks in a solid archive of 70 small files, and the
/// difference is most of why that archive is 18% smaller than ours was.
///
/// The model comes back out so the next block can continue it in turn.
fn encode_ppmd_block_with_model(
    input: &[u8],
    lz_escapes: bool,
    mut filters: Option<&mut PpmdFilters>,
    max_match_distance: usize,
    model: Option<PpmdModel>,
    size: PpmdModelSize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<(Vec<u8>, PpmdModel)> {
    if progress.as_mut().is_some_and(|report| !report(0)) {
        return Err(Error::Cancelled);
    }
    let mut out = Vec::new();
    // A continued model keeps the order it started with, and the reader
    // ignores the bits here unless the model is reset.
    let mut encoder = match model {
        Some(model) => {
            out.push(0x80 | size.order_bits());
            PpmdEncoder::continuing(model, PPMD_ESC)
        }
        None => {
            out.push(0x80 | 0x20 | size.order_bits());
            out.push(size.memory_mb - 1);
            PpmdEncoder::new(size.order, PPMD_ESC, usize::from(size.memory_mb))?
        }
    };
    let mut declare = |encoder: &mut PpmdEncoder, pos: usize, len: usize| match filters.as_mut() {
        Some(filters) => filters.declare(encoder, pos, len),
        None => Ok(()),
    };
    if lz_escapes {
        let mut report = |position| progress.as_mut().is_none_or(|report| report(position));
        let reach = input.len().min(max_match_distance).min(MAX_HISTORY);
        encode_ppmd_hybrid_span(
            &mut PpmdMatchSearch::new(input, max_match_distance, reach),
            0,
            input.len(),
            &mut encoder,
            &mut PpmdHybrid::new(),
            &mut declare,
            |_| (),
            Some(&mut report),
        )?;
    } else {
        for (position, &byte) in input.iter().enumerate() {
            if position.is_multiple_of(4096)
                && progress.as_mut().is_some_and(|report| !report(position))
            {
                return Err(Error::Cancelled);
            }
            declare(&mut encoder, position, 1)?;
            encoder.encode_literal(byte)?;
        }
    }
    let (packed, model) = encoder.finish_keeping_model()?;
    out.extend_from_slice(&packed);
    if progress.as_mut().is_some_and(|report| !report(input.len())) {
        return Err(Error::Cancelled);
    }
    Ok((out, model))
}

/// How much of a member [`encode_ppmd_either_way`] codes both ways to choose.
const PPMD_EITHER_WAY_SAMPLE: usize = 1 << 20;

/// Codes a PPMd block with LZ escapes or as plain literals, from the same
/// model, whichever codes the member's start smaller, escapes on a tie.
///
/// An escape prices itself against costs measured off the stream it shapes,
/// so on text that rarely repeats it can lose to literals: a 4.3 MB source
/// tar at order 25 packs 1.8% smaller without them. Coding the whole member
/// twice to find out costs half as much again on text where escapes win, so
/// past twice the sample only the sample is coded both ways, from copies of
/// the model, and the member is coded once the way it chose. The model comes
/// back from that coding, since that is what its reader holds.
fn encode_ppmd_either_way(
    input: &[u8],
    max_match_distance: usize,
    model: Option<&PpmdModel>,
    size: PpmdModelSize,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<(Vec<u8>, PpmdModel)> {
    encode_ppmd_either_way_sampled(
        input,
        max_match_distance,
        model,
        size,
        PPMD_EITHER_WAY_SAMPLE,
        progress,
    )
}

/// [`encode_ppmd_either_way`] choosing from the first `sample` bytes.
fn encode_ppmd_either_way_sampled(
    input: &[u8],
    max_match_distance: usize,
    model: Option<&PpmdModel>,
    size: PpmdModelSize,
    sample: usize,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<(Vec<u8>, PpmdModel)> {
    let code = |input: &[u8], escapes: bool, progress: &mut dyn FnMut(usize) -> bool| {
        encode_ppmd_block_with_model(
            input,
            escapes,
            None,
            max_match_distance,
            model.cloned(),
            size,
            Some(progress),
        )
    };
    if input.len() <= sample.saturating_mul(2) {
        let escaped = code(input, true, &mut *progress)?;
        let literals = code(input, false, &mut |_| progress(input.len()))?;
        return Ok(if literals.0.len() < escaped.0.len() {
            literals
        } else {
            escaped
        });
    }
    let sample = &input[..sample];
    let mut poll = |_| progress(0);
    let escaped = code(sample, true, &mut poll)?.0.len();
    let literals = code(sample, false, &mut poll)?.0.len();
    code(input, literals >= escaped, progress)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PpmdEncodeToken {
    Literal(u8),
    RepeatOffsetOne { length: usize },
    Match { offset: usize, length: usize },
}

/// The writer rejects these before compressing anything, so reaching this is
/// either a direct `codec` caller or a bug. Either way the codec stays total.
fn rar29_filter(kind: crate::FilterKind) -> Result<Rar29Filter> {
    Rar29Filter::try_from(kind)
        .map_err(|_| Error::InvalidData("the RAR 2.9 family has no program for this filter"))
}

struct FilteredMember {
    block_start: usize,
    block_size: usize,
    init_regs: Vec<(usize, u32)>,
    code: &'static [u8],
}

/// In place, from `offset` on: copying the member per record made many-record members quadratic.
fn filter_in_place(
    filtered: &mut [u8],
    offset: usize,
    filter: &crate::FilterSpec,
) -> Result<FilteredMember> {
    let range = checked_filter_range(offset + filtered.len(), filter)?;
    if range.start < offset {
        return Err(Error::InvalidData("RAR 2.9 VM filter range is invalid"));
    }
    let local = range.start - offset..range.end - offset;
    let (init_regs, code): (Vec<(usize, u32)>, &'static [u8]) = match rar29_filter(filter.kind)? {
        Rar29Filter::E8 => {
            filters::e8e9_encode(&mut filtered[local.clone()], range.start as u32, false);
            (Vec::new(), RAR3_E8_FILTER_BYTECODE)
        }
        Rar29Filter::E8E9 => {
            filters::e8e9_encode(&mut filtered[local.clone()], range.start as u32, true);
            (Vec::new(), RAR3_E8E9_FILTER_BYTECODE)
        }
        Rar29Filter::Delta { channels } => {
            filters::encode_in_place(
                FilterOp::Delta { channels },
                &mut filtered[local.clone()],
                0,
                rar29_delta_messages(),
            )?;
            (vec![(0, channels as u32)], RAR3_DELTA_FILTER_BYTECODE)
        }
        Rar29Filter::Itanium => {
            itanium_encode(&mut filtered[local.clone()], range.start as u32);
            (Vec::new(), RAR3_ITANIUM_FILTER_BYTECODE)
        }
        Rar29Filter::Rgb { width, pos_r } => {
            let encoded = rgb_encode(&filtered[local.clone()], width, pos_r)?;
            filtered[local.clone()].copy_from_slice(&encoded);
            let init_regs = if pos_r == 0 {
                vec![(0, width as u32 + 3)]
            } else {
                vec![(0, width as u32 + 3), (1, pos_r as u32)]
            };
            (init_regs, RAR3_RGB_FILTER_BYTECODE)
        }
        Rar29Filter::Audio { channels } => {
            let encoded = audio_encode(&filtered[local.clone()], channels)?;
            filtered[local.clone()].copy_from_slice(&encoded);
            (vec![(0, channels as u32)], RAR3_AUDIO_FILTER_BYTECODE)
        }
    };
    Ok(FilteredMember {
        block_start: range.start,
        block_size: range.end - range.start,
        init_regs,
        code,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeOptions {
    pub max_match_candidates: usize,
    pub lazy_matching: bool,
    pub lazy_lookahead: usize,
    pub max_match_distance: usize,
    pub block_size: Option<usize>,
    /// How many times to re-parse each block by shortest path, each priced by
    /// the tables the parse before it produced. The block keeps whichever
    /// parse codes smallest, the lazy one included. Zero leaves the lazy parse.
    pub optimal_parse_passes: usize,
    /// Whether a block's tokens may be cut into several blocks, each with
    /// tables of its own, where the cuts price smaller than one table.
    pub split_blocks: bool,
    /// Whether the lazy parse also takes three-byte matches under 8 KiB and
    /// repeats of two or three bytes at a remembered offset, which its
    /// four-byte chains cannot offer. A greedy parse ignores it.
    ///
    /// A parse whose chains key on six bytes (at most
    /// [`LONG_KEY_MAX_CANDIDATES`] candidates) keeps near matches whatever
    /// this says, since they are where its short matches come from.
    pub near_matches: bool,
    /// In a block that looks random, how many positions in a row may offer no
    /// match before the parse looks only at every other one, then every third
    /// after as many again, and so on. `None` looks at every position.
    ///
    /// Already-compressed data offers a match now and then and nothing in
    /// between, so a parse that looks everywhere walks a chain of collisions
    /// at every byte for nothing. A long repeat is still found a few bytes in.
    /// See [`SKIP_RANDOM_ABOVE_BITS`] for which blocks look random.
    pub skip_literal_runs: Option<usize>,
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            lazy_matching: false,
            lazy_lookahead: 1,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            block_size: None,
            optimal_parse_passes: 0,
            split_blocks: false,
            near_matches: false,
            skip_literal_runs: None,
        }
    }

    pub const fn with_lazy_matching(mut self, enabled: bool) -> Self {
        self.lazy_matching = enabled;
        self
    }

    pub const fn with_lazy_lookahead(mut self, bytes: usize) -> Self {
        self.lazy_lookahead = bytes;
        self
    }

    pub const fn with_max_match_distance(mut self, distance: usize) -> Self {
        self.max_match_distance = if distance > MAX_HISTORY {
            MAX_HISTORY
        } else {
            distance
        };
        self
    }

    pub const fn with_block_size(mut self, bytes: usize) -> Self {
        self.block_size = Some(bytes);
        self
    }

    pub const fn with_optimal_parse_passes(mut self, passes: usize) -> Self {
        self.optimal_parse_passes = passes;
        self
    }

    pub const fn with_split_blocks(mut self, enabled: bool) -> Self {
        self.split_blocks = enabled;
        self
    }

    pub const fn with_near_matches(mut self, enabled: bool) -> Self {
        self.near_matches = enabled;
        self
    }

    pub const fn with_skip_literal_runs(mut self, misses: Option<usize>) -> Self {
        self.skip_literal_runs = misses;
        self
    }

    const fn constrained(mut self) -> Self {
        if self.max_match_distance > MAX_HISTORY {
            self.max_match_distance = MAX_HISTORY;
        }
        self
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new(MAX_MATCH_CANDIDATES)
    }
}

/// Which engine a member of a solid chain is coded with.
///
/// A chain used to be LZ and nothing else. Both engines keep state that carries
/// from member to member, so this is a per-member choice inside one chain
/// rather than a property of the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainEngine {
    Lz,
    Ppmd,
    /// Code it both ways and keep whichever is smaller. Worth asking for when
    /// the content might go either way, and not otherwise: it doubles the work
    /// and copying the model to try costs more the longer the chain has run.
    Smaller,
}

/// One way of coding a member into the chain, and the state it would leave.
///
/// The state is carried rather than committed because a candidate that loses
/// must not move the chain: the reader rebuilds its code-length table from the
/// bytes it actually reads, so committing a table the winner never wrote leaves
/// every later member coded against a table no decoder holds.
struct LzCandidate {
    packed: Vec<u8>,
    /// The bytes the LZ layer coded, when a filter rewrote them. `None` when
    /// the candidate took no filter and coded the input as it came.
    coded: Option<Vec<u8>>,
    levels: [u8; TABLE_COUNT],
}

#[derive(Debug, Clone)]
pub struct Unpack29Encoder {
    history: Vec<u8>,
    options: EncodeOptions,
    /// The code-length table a reader holds once everything coded so far has
    /// been read. A solid chain carries it from one member to the next, which
    /// is what lets a member say "same table as before" instead of spelling one
    /// out. A reader clears it on a member that does not continue a chain, and
    /// so does a fresh encoder.
    levels: [u8; TABLE_COUNT],
    /// The PPMd model a reader holds, once some member in the chain has built
    /// one. A reader keeps it across every block that does not ask for a reset,
    /// LZ blocks included, so a member can go PPMd against everything the chain
    /// has read even when the member before it went LZ. The size is the one
    /// it started with, which every later block keeps.
    ppmd: Option<(PpmdModel, PpmdModelSize)>,
    /// The sizes a member that starts the chain's model tries, in order; the
    /// one that codes it smallest is the one the rest of the chain continues.
    ppmd_sizes: &'static [PpmdModelSize],
}

impl Default for Unpack29Encoder {
    fn default() -> Self {
        Self::with_options(EncodeOptions::default())
    }
}

impl Unpack29Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            history: Vec::new(),
            options: options.constrained(),
            levels: [0; TABLE_COUNT],
            ppmd: None,
            ppmd_sizes: &[PpmdModelSize::DEFAULT],
        }
    }

    /// The PPMd model sizes to try when a member starts the chain's model.
    ///
    /// A chain keeps the model its first PPMd member starts, so the size is
    /// chosen there and nowhere else. An empty list keeps the default.
    pub(crate) fn with_ppmd_sizes(mut self, sizes: &'static [PpmdModelSize]) -> Self {
        if !sizes.is_empty() {
            self.ppmd_sizes = sizes;
        }
        self
    }

    pub fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let packed = encode_member_with_options_impl(
            input,
            &self.history,
            self.options,
            &mut self.levels,
            None,
        )?;
        self.remember(input);
        Ok(packed)
    }

    /// Codes one member of a solid chain with the engine the caller asked for.
    ///
    /// Both engines carry state across the chain and only one of them can be
    /// right for a given member, so the loser's state is thrown away: an LZ
    /// member must not advance the reader's PPMd model, and a PPMd member must
    /// not advance its code-length table. What both advance is the window,
    /// since the reader's window is fed by whichever engine wrote the bytes.
    ///
    /// `candidates` is the filter lists to choose between, each measured
    /// against the chain as it stands. An empty slice means code it plainly,
    /// which is what a caller with no search to offer passes.
    pub(crate) fn encode_member_with_engine(
        &mut self,
        input: &[u8],
        engine: ChainEngine,
        candidates: &[Vec<crate::FilterSpec>],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        if engine == ChainEngine::Ppmd {
            let (packed, model) = self.encode_ppmd_member(input, false, progress)?;
            self.ppmd = Some(model);
            self.remember(input);
            return Ok(packed);
        }

        let lz = self.best_lz_candidate(input, candidates, progress)?;

        let ppmd = match engine {
            ChainEngine::Smaller => {
                Some(self.encode_ppmd_member(input, true, &mut |_| progress(input.len()))?)
            }
            _ => None,
        };

        match ppmd.filter(|(packed, _)| packed.len() < lz.packed.len()) {
            Some((packed, model)) => {
                self.ppmd = Some(model);
                self.remember(input);
                Ok(packed)
            }
            None => {
                self.levels = lz.levels;
                // The LZ layer coded the filtered bytes, so those are what a
                // decoder's window holds and what the next member can match
                // against. A member that took no filter coded its input.
                self.remember(lz.coded.as_deref().unwrap_or(input));
                Ok(lz.packed)
            }
        }
    }

    /// Codes the member under every candidate filter list and keeps the
    /// smallest, along with the chain state that candidate would leave behind.
    ///
    /// This is the whole reason a chain can search for a filter at all. Which
    /// filter suits a member is decided elsewhere, on the member's own bytes;
    /// what cannot be decided there is whether the winner still pays once the
    /// history behind it is doing some of the same work, and that is what the
    /// encodes here measure. They are the real thing, against the real history,
    /// at the caller's real settings.
    ///
    /// Only the first candidate advances progress; later candidates poll at
    /// the completed byte count for cancellation. Every candidate walks the
    /// whole member, and the bar counts bytes coded rather than work done, so
    /// reporting each one over again would run it past the end of the member
    /// and back. The plain candidate comes first, so what the bar shows is one
    /// member's worth of the pass that always happens.
    fn best_lz_candidate(
        &self,
        input: &[u8],
        candidates: &[Vec<crate::FilterSpec>],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<LzCandidate> {
        let plain_only = [Vec::new()];
        let candidates = if candidates.is_empty() {
            &plain_only[..]
        } else {
            candidates
        };
        let mut best: Option<LzCandidate> = None;
        for (index, filters) in candidates.iter().enumerate() {
            let mut report =
                |position: usize| progress(if index == 0 { position } else { input.len() });
            let mut levels = self.levels;
            let candidate = if filters.is_empty() {
                LzCandidate {
                    packed: encode_member_with_options_and_progress(
                        input,
                        &self.history,
                        self.options,
                        &mut levels,
                        &mut report,
                    )?,
                    coded: None,
                    levels,
                }
            } else {
                let mut split = Vec::new();
                for filter in filters {
                    split.extend(split_large_filter(input.len(), filter.clone())?);
                }
                let filtered = filtered_members_with_progress(input, 0, &split, Some(&mut report))?;
                let packed = encode_filtered_member_blocks(
                    &filtered.data,
                    &self.history,
                    &filtered.records,
                    self.options,
                    &mut levels,
                    Some(&mut report),
                )?;
                LzCandidate {
                    packed,
                    coded: Some(filtered.data),
                    levels,
                }
            };
            if best
                .as_ref()
                .is_none_or(|best| candidate.packed.len() < best.packed.len())
            {
                best = Some(candidate);
            }
            // Check again after committing the candidate, without moving the
            // byte count backwards for repeated work on the same member.
            if index > 0 && !progress(input.len()) {
                return Err(Error::Cancelled);
            }
        }
        Ok(best.expect("a chain always has at least the plain candidate"))
    }

    /// Codes the member against a copy of the chain's model, so a trial that
    /// loses leaves the reader's model where the winning member expects it.
    ///
    /// A member that starts the model codes under each of the chain's sizes
    /// and keeps the smallest, earlier on a tie. With `either_way`, each size,
    /// or the model the chain continues, codes with LZ escapes or as plain
    /// literals, whichever [`encode_ppmd_either_way`] chooses: the model
    /// carries on from the coding written, as the reader's does. Forced PPMd codes with
    /// escapes only, which is what a streamed member can match. Only the first
    /// coding reports progress; the others poll at the end.
    fn encode_ppmd_member(
        &self,
        input: &[u8],
        either_way: bool,
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<(Vec<u8>, (PpmdModel, PpmdModelSize))> {
        let distance = self.options.max_match_distance;
        let code = |model: Option<&PpmdModel>,
                    size: PpmdModelSize,
                    progress: &mut dyn FnMut(usize) -> bool| {
            if either_way {
                encode_ppmd_either_way(input, distance, model, size, progress)
            } else {
                encode_ppmd_block_with_model(
                    input,
                    true,
                    None,
                    distance,
                    model.cloned(),
                    size,
                    Some(progress),
                )
            }
        };
        if let Some((model, size)) = &self.ppmd {
            let (packed, model) = code(Some(model), *size, progress)?;
            return Ok((packed, (model, *size)));
        }
        let mut best: Option<(Vec<u8>, (PpmdModel, PpmdModelSize))> = None;
        for (index, &size) in self.ppmd_sizes.iter().enumerate() {
            let mut report =
                |position: usize| progress(if index == 0 { position } else { input.len() });
            let (packed, model) = code(None, size, &mut report)?;
            if best
                .as_ref()
                .is_none_or(|(best, _)| packed.len() < best.len())
            {
                best = Some((packed, (model, size)));
            }
        }
        Ok(best.expect("a chain always has a PPMd size to try"))
    }

    /// Whether the chain holds a PPMd model a member would continue.
    pub(crate) fn has_ppmd_model(&self) -> bool {
        self.ppmd.is_some()
    }

    pub fn encode_member_with_filter(
        &mut self,
        input: &[u8],
        filter: crate::FilterSpec,
    ) -> Result<Vec<u8>> {
        let filters = split_large_filter(input.len(), filter)?;
        let filtered = filtered_members(input, 0, &filters)?;
        let mut levels = self.levels;
        let packed = encode_filtered_member_blocks(
            &filtered.data,
            &self.history,
            &filtered.records,
            self.options,
            &mut levels,
            None,
        )?;
        // The LZ layer coded the filtered bytes, so that is what a decoder's
        // window holds and what the next member in a solid chain can match
        // against. Remembering the caller's input instead leaves every member
        // after this one referring to bytes no decoder ever had.
        self.levels = levels;
        self.remember(&filtered.data);
        Ok(packed)
    }

    pub fn encode_member_with_filters(
        &mut self,
        input: &[u8],
        filters: &[crate::FilterSpec],
    ) -> Result<Vec<u8>> {
        self.encode_member_with_filters_and_progress(input, 0, filters, None)
    }

    /// `input` lies `offset` bytes into its member, as for [`filtered_members`];
    /// a member coded whole starts at 0.
    pub(crate) fn encode_member_with_filters_and_progress(
        &mut self,
        input: &[u8],
        offset: usize,
        filters: &[crate::FilterSpec],
        mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    ) -> Result<Vec<u8>> {
        if progress.as_mut().is_some_and(|report| !report(0)) {
            return Err(Error::Cancelled);
        }
        let mut split_filters = Vec::new();
        for filter in filters {
            split_filters.extend(split_large_filter(input.len(), filter.clone())?);
        }
        let filtered = match progress.as_mut() {
            Some(report) => {
                filtered_members_with_progress(input, offset, &split_filters, Some(&mut **report))?
            }
            None => filtered_members(input, offset, &split_filters)?,
        };
        let mut levels = self.levels;
        let packed = encode_filtered_member_blocks(
            &filtered.data,
            &self.history,
            &filtered.records,
            self.options,
            &mut levels,
            progress,
        )?;
        // The LZ layer coded the filtered bytes, so that is what a decoder's
        // window holds and what the next member in a solid chain can match
        // against. Remembering the caller's input instead leaves every member
        // after this one referring to bytes no decoder ever had.
        self.levels = levels;
        self.remember(&filtered.data);
        Ok(packed)
    }

    fn remember(&mut self, input: &[u8]) {
        self.history.extend_from_slice(input);
        let keep_from = self.history.len().saturating_sub(MAX_HISTORY);
        if keep_from != 0 {
            self.history.drain(..keep_from);
        }
    }
}

fn encode_member(input: &[u8], history: &[u8]) -> Result<Vec<u8>> {
    encode_member_with_options(input, history, EncodeOptions::default())
}

fn encode_member_with_options(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_options_impl(input, history, options, &mut [0; TABLE_COUNT], None)
}

fn encode_member_with_options_and_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    levels: &mut [u8; TABLE_COUNT],
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_member_with_options_impl(input, history, options, levels, Some(progress))
}

fn encode_member_with_options_impl(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    levels: &mut [u8; TABLE_COUNT],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let options = options.constrained();
    if let Some(block_size) = options.block_size.filter(|&size| size != 0) {
        if input.len() > block_size {
            return encode_member_blocks(input, history, options, block_size, levels, progress);
        }
    }
    encode_member_inner(input, history, &[], options, false, levels, progress)
}

fn encode_member_blocks(
    input: &[u8],
    history: &[u8],
    mut options: EncodeOptions,
    block_size: usize,
    levels: &mut [u8; TABLE_COUNT],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    options.block_size = None;
    let mut out = Vec::new();
    for_each_block(
        &mut InMemory::new(input, history, &[], options),
        options,
        block_size,
        levels,
        progress,
        |_, _, _| Ok(Vec::new()),
        |packed, _| {
            out.extend_from_slice(packed);
            Ok(ControlFlow::Continue(()))
        },
    )?
    .continue_value()
    .expect("an in-memory member codes every block");
    Ok(out)
}

/// Takes packed bytes as they are coded, with how far into the member they code through.
pub(crate) type PackedOut<'a> = &'a mut dyn FnMut(&[u8], usize) -> Result<ControlFlow<()>>;

/// Takes a segment and where it starts in the member. Ranges are the segment's
/// own, so a chooser needs no member to measure against, but the x86 filters
/// convert from the segment's place in the member, so a chooser measures there.
pub(crate) type SegmentFilters<'a> =
    &'a mut dyn FnMut(&[u8], usize) -> Result<Vec<crate::FilterSpec>>;

/// The bytes of [`unpack29_encode_literals_with_options`], or with `filters` of [`Unpack29Encoder::encode_member_with_filters`], without holding the member.
#[cfg(test)]
pub(crate) fn unpack29_encode_literals_streamed(
    input: &mut dyn Read,
    len: usize,
    options: EncodeOptions,
    filters: Option<SegmentFilters<'_>>,
    progress: &mut dyn FnMut(usize) -> bool,
    out: PackedOut<'_>,
) -> Result<ControlFlow<()>> {
    Unpack29Encoder::with_options(options).encode_lz_streamed(input, len, filters, progress, out)
}

/// The least a streamed PPMd member codes between reads; it codes four reaches when that is more.
const PPMD_STREAM_SEGMENT: usize = 256 * 1024;
/// A batch filled ahead and the longest token, so a search by a segment's end sees what the in-memory one does.
const PPMD_STREAM_LOOKAHEAD: usize = PpmdMatchSearch::MAX_BATCH + MAX_PPMD_REPEAT_LENGTH;

/// The bytes of [`unpack29_encode_ppmd_with_progress`] without holding the member; `out` breaks to abandon it.
///
/// `escapes` is the distance LZ escapes reach back, or `None` for literals only.
#[cfg(test)]
pub(crate) fn unpack29_encode_ppmd_streamed(
    input: &mut dyn Read,
    len: usize,
    escapes: Option<usize>,
    filter: Option<crate::FilterSpec>,
    progress: &mut dyn FnMut(usize) -> bool,
    out: PackedOut<'_>,
) -> Result<ControlFlow<()>> {
    encode_ppmd_streamed(
        input,
        len,
        escapes,
        filter,
        None,
        PpmdModelSize::DEFAULT,
        None,
        progress,
        out,
    )
    .map(|(flow, _)| flow)
}

impl Unpack29Encoder {
    /// [`Self::encode_member_with_engine`]'s LZ side read as it is coded; a break leaves the chain as it was.
    pub(crate) fn encode_lz_streamed(
        &mut self,
        input: &mut dyn Read,
        len: usize,
        filters: Option<SegmentFilters<'_>>,
        progress: &mut dyn FnMut(usize) -> bool,
        out: PackedOut<'_>,
    ) -> Result<ControlFlow<()>> {
        let mut options = self.options;
        let mut levels = self.levels;
        let filtering = filters.is_some();
        let block_size = if filtering {
            filtered_block_size(options, len)
        } else if let Some(size) = options.block_size.filter(|&size| size != 0 && len > size) {
            size
        } else {
            // A single block parses against a smaller finder, so it is read whole to match.
            let mut data = Vec::with_capacity(len);
            input.take(len as u64).read_to_end(&mut data)?;
            if data.len() != len {
                return Err(Error::NeedMoreInput);
            }
            let packed = encode_member_with_options_impl(
                &data,
                &self.history,
                options,
                &mut levels,
                Some(progress),
            )?;
            let flow = out(&packed, len)?;
            if flow.is_continue() {
                self.levels = levels;
                self.remember(&data);
            }
            return Ok(flow);
        };
        options.block_size = None;
        let window = options.max_match_distance.max(1);
        let reach = options.max_match_distance.min(MAX_HISTORY);
        let mut segments = ReadSegments {
            input,
            len,
            window: self.history[self.history.len().saturating_sub(reach)..].to_vec(),
            filters,
        };
        let mut programs = Vec::new();
        let flow = for_each_block(
            &mut segments,
            options,
            block_size,
            &mut levels,
            Some(progress),
            |base, end, records| match filtering {
                true => block_filter_records(records, base, end, window, &mut programs),
                false => Ok(Vec::new()),
            },
            out,
        )?;
        if flow.is_continue() {
            // Every parse reads one reach of history, which the window still holds.
            let mut history = segments.window;
            history.drain(..history.len().saturating_sub(reach));
            self.history = history;
            self.levels = levels;
        }
        Ok(flow)
    }

    /// [`Self::encode_member_with_engine`]'s PPMd side read as it is coded; a break leaves a chain to discard.
    ///
    /// With `filter`, a fresh encoder codes what [`unpack29_encode_ppmd_with_progress`] does with it.
    ///
    /// `size` is the model to start when the chain holds none; a model the
    /// chain holds is continued at the size it started with.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encode_ppmd_streamed(
        &mut self,
        input: &mut dyn Read,
        len: usize,
        escapes: Option<usize>,
        filter: Option<crate::FilterSpec>,
        size: PpmdModelSize,
        progress: &mut dyn FnMut(usize) -> bool,
        out: PackedOut<'_>,
    ) -> Result<ControlFlow<()>> {
        // Taken rather than copied: after a break the caller starts a new chain.
        let mut history = std::mem::take(&mut self.history);
        let (model, size) = match &self.ppmd {
            Some((model, size)) => (Some(model.clone()), *size),
            None => (None, size),
        };
        let (flow, model) = encode_ppmd_streamed(
            input,
            len,
            escapes,
            filter,
            model,
            size,
            Some(&mut history),
            progress,
            out,
        )?;
        self.history = history;
        if let Some(model) = model {
            self.ppmd = Some((model, size));
        }
        Ok(flow)
    }
}

/// `history`, when given, is left holding the last [`MAX_HISTORY`] bytes read after it.
///
/// `filter` is applied a record at a time as the bytes each covers are read,
/// and each record is declared as the coder reaches it.
#[allow(clippy::too_many_arguments)]
fn encode_ppmd_streamed(
    input: &mut dyn Read,
    len: usize,
    escapes: Option<usize>,
    filter: Option<crate::FilterSpec>,
    model: Option<PpmdModel>,
    size: PpmdModelSize,
    mut history: Option<&mut Vec<u8>>,
    progress: &mut dyn FnMut(usize) -> bool,
    out: PackedOut<'_>,
) -> Result<(ControlFlow<()>, Option<PpmdModel>)> {
    if !progress(0) {
        return Err(Error::Cancelled);
    }
    let mut filters = filter
        .map(|filter| PpmdFilters::new(len, filter))
        .transpose()?;
    // Headed as [`encode_ppmd_block_with_model`] heads a block.
    let (mut encoder, head) = match model {
        Some(model) => (
            PpmdEncoder::continuing(model, PPMD_ESC),
            vec![0x80 | size.order_bits()],
        ),
        None => (
            PpmdEncoder::new(size.order, PPMD_ESC, usize::from(size.memory_mb))?,
            vec![0x80 | 0x20 | size.order_bits(), size.memory_mb - 1],
        ),
    };
    if out(&head, 0)?.is_break() {
        return Ok((ControlFlow::Break(()), None));
    }
    let reach = escapes.map_or(0, |distance| len.min(distance).min(MAX_HISTORY));
    let mut state = PpmdHybrid::new();
    let mut window = Vec::new();
    // The member position of `window[0]`.
    let mut origin = 0usize;
    let mut pos = 0usize;
    while pos < len {
        let keep_from = pos.saturating_sub(reach);
        window.drain(..keep_from - origin);
        state.rebase(keep_from - origin);
        origin = keep_from;
        let end = pos
            .saturating_add(reach.saturating_mul(4).max(PPMD_STREAM_SEGMENT))
            .min(len);
        let lookahead = escapes.map_or(0, |_| PPMD_STREAM_LOOKAHEAD);
        let mut want = end.saturating_add(lookahead).min(len);
        if let Some(filters) = &filters {
            want = filters.read_end(want);
        }
        let have = window.len();
        window.resize((want - origin).max(have), 0);
        input.read_exact(&mut window[have..])?;
        if let Some(filters) = &mut filters {
            filters.apply(&mut window, origin)?;
        }
        if let Some(history) = history.as_deref_mut() {
            history.extend_from_slice(&window[have..]);
            history.drain(..history.len().saturating_sub(MAX_HISTORY));
        }
        let mut declare = |encoder: &mut PpmdEncoder, at: usize, len: usize| match &mut filters {
            Some(filters) => filters.declare(encoder, origin + at, len),
            None => Ok(()),
        };
        if let Some(distance) = escapes {
            let mut report = |local: usize| progress(origin + local);
            pos = origin
                + encode_ppmd_hybrid_span(
                    &mut PpmdMatchSearch::new(&window, distance, reach),
                    pos - origin,
                    end - origin,
                    &mut encoder,
                    &mut state,
                    &mut declare,
                    |_| (),
                    Some(&mut report),
                )?;
        } else {
            let start = pos - origin;
            for (at, &byte) in window[start..end - origin].iter().enumerate() {
                let at = start + at;
                if (origin + at).is_multiple_of(4096) && !progress(origin + at) {
                    return Err(Error::Cancelled);
                }
                declare(&mut encoder, at, 1)?;
                encoder.encode_literal(byte)?;
            }
            pos = end;
        }
        if out(&encoder.take_output(), pos)?.is_break() {
            return Ok((ControlFlow::Break(()), None));
        }
    }
    let (packed, model) = encoder.finish_keeping_model()?;
    let flow = out(&packed, len)?;
    if !progress(len) {
        return Err(Error::Cancelled);
    }
    Ok((flow, flow.is_continue().then_some(model)))
}

/// Where a block parse reads its member from, one segment at a time.
trait Segments {
    fn len(&self) -> usize;

    /// `start - behind..end`, after history when `behind` falls short of the reach.
    fn segment(
        &mut self,
        start: usize,
        behind: usize,
        end: usize,
        reach: usize,
    ) -> Result<Segment<'_>>;
}

struct Segment<'a> {
    bytes: std::borrow::Cow<'a, [u8]>,
    /// Those whose blocks start in the segment, which its blocks declare.
    records: std::borrow::Cow<'a, [OwnedVmFilterRecord]>,
}

struct InMemory<'a> {
    input: &'a [u8],
    history: &'a [u8],
    /// In the order their blocks start.
    records: &'a [OwnedVmFilterRecord],
}

impl<'a> InMemory<'a> {
    fn new(
        input: &'a [u8],
        history: &'a [u8],
        records: &'a [OwnedVmFilterRecord],
        options: EncodeOptions,
    ) -> Self {
        let reach = options.max_match_distance.min(MAX_HISTORY);
        Self {
            input,
            history: &history[history.len().saturating_sub(reach)..],
            records,
        }
    }
}

impl Segments for InMemory<'_> {
    fn len(&self) -> usize {
        self.input.len()
    }

    fn segment(
        &mut self,
        start: usize,
        behind: usize,
        end: usize,
        reach: usize,
    ) -> Result<Segment<'_>> {
        let (input, history) = (self.input, self.history);
        let first = self
            .records
            .partition_point(|record| record.block_start < start);
        let last = self
            .records
            .partition_point(|record| record.block_start < end);
        let records = std::borrow::Cow::Borrowed(&self.records[first..last]);
        let bytes = if behind == reach || history.is_empty() {
            std::borrow::Cow::Borrowed(&input[start - behind..end])
        } else {
            let carried = &history[history.len().saturating_sub(reach - behind)..];
            let mut joined = Vec::with_capacity(carried.len() + end - start + behind);
            joined.extend_from_slice(carried);
            joined.extend_from_slice(&input[start - behind..end]);
            std::borrow::Cow::Owned(joined)
        };
        Ok(Segment { bytes, records })
    }
}

/// Keeps the last reach of what it has read, filtered as a decoder's window holds it, after any history it starts with.
struct ReadSegments<'a, 'f> {
    input: &'a mut dyn Read,
    len: usize,
    window: Vec<u8>,
    filters: Option<SegmentFilters<'f>>,
}

impl Segments for ReadSegments<'_, '_> {
    fn len(&self) -> usize {
        self.len
    }

    fn segment(
        &mut self,
        start: usize,
        _behind: usize,
        end: usize,
        reach: usize,
    ) -> Result<Segment<'_>> {
        // A chain member starts with the reach before it already in the window.
        self.window.drain(..self.window.len().saturating_sub(reach));
        let kept = self.window.len();
        self.window.resize(kept + end - start, 0);
        self.input.read_exact(&mut self.window[kept..])?;
        let mut records = Vec::new();
        if let Some(choose) = self.filters.as_mut() {
            let fresh = &mut self.window[kept..];
            let mut split = Vec::new();
            for filter in choose(fresh, start)? {
                let range = checked_filter_range(fresh.len(), &filter)?;
                let moved =
                    crate::FilterSpec::range(filter.kind, start + range.start..start + range.end);
                split.extend(split_large_filter(end, moved)?);
            }
            records = filter_window(fresh, start, &split, None)?;
        }
        Ok(Segment {
            bytes: std::borrow::Cow::Borrowed(&self.window),
            records: std::borrow::Cow::Owned(records),
        })
    }
}

/// Parses and codes `input` a block at a time, handing each coded piece to `out` in order.
///
/// `filters_for` gives the coded filter records a piece declares, from its
/// start and end and the segment's records. It is called once per piece, in
/// order, so it may carry state from one piece to the next. `levels` is the
/// table the reader holds before the first piece, as for [`code_block`], and
/// is left holding the last coded piece's.
fn for_each_block(
    input: &mut dyn Segments,
    options: EncodeOptions,
    block_size: usize,
    levels: &mut [u8; TABLE_COUNT],
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    mut filters_for: impl FnMut(usize, usize, &[OwnedVmFilterRecord]) -> Result<Vec<Vec<u8>>>,
    mut out: impl FnMut(&[u8], usize) -> Result<ControlFlow<()>>,
) -> Result<ControlFlow<()>> {
    let block_size = block_size.max(1);
    let reach = options.max_match_distance.min(MAX_HISTORY);
    let len = input.len();
    let mut ends: Vec<usize> = (block_size..len).step_by(block_size).collect();
    ends.push(len);
    let per_batch = (LzParser::batch_bytes(block_size) / block_size).max(1);
    // Segments bound what a parser holds, for one re-hashed reach each.
    let per_segment = per_batch
        * reach
            .saturating_mul(4)
            .div_ceil(per_batch * block_size)
            .max(1);
    let mut block_start = 0;
    let mut long = None;
    for segment in ends.chunks(per_segment) {
        let segment_end = *segment.last().expect("chunks are never empty");
        let behind = reach.min(block_start);
        let Segment {
            bytes: combined,
            records,
        } = input.segment(block_start, behind, segment_end, reach)?;
        let base = combined.len() - (segment_end - block_start);
        // The first segment starts with all the history the member reaches.
        let long = *long.get_or_insert_with(|| keys_long(options, len + base));
        let mut parser = LzParser::new(&combined, base, options, block_size, long);
        let origin = block_start;
        let local = |end: usize| base + end - origin;
        let batches: Vec<&[usize]> = segment.chunks(per_batch).collect();
        parser.fill_to(local(*batches[0].last().expect("chunks are never empty")));
        for (index, &batch) in batches.iter().enumerate() {
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(block_start))
            {
                return Err(Error::Cancelled);
            }
            let ends: Vec<usize> = batch.iter().map(|&end| local(end)).collect();
            // Each piece in order, with the end of its block if it is the last.
            let mut pieces = Vec::new();
            let mut filter_failure = None;
            let mut start = block_start;
            'blocks: for (block, &end) in parser.parse_filled(&ends)?.into_iter().zip(batch) {
                let count = block.len();
                for (at, piece) in block.into_iter().enumerate() {
                    let piece_end = origin + piece.end - base;
                    match filters_for(start, piece_end, &records) {
                        Ok(filters) => pieces.push((
                            BlockToCode {
                                tokens: piece.tokens,
                                state: piece.state,
                                filters,
                                more_blocks_follow: piece_end < len,
                            },
                            piece_end,
                            (at + 1 == count).then_some(end),
                        )),
                        Err(error) => {
                            filter_failure = Some(error);
                            break 'blocks;
                        }
                    }
                    start = piece_end;
                }
            }
            let (blocks, places): (Vec<_>, Vec<_>) = pieces
                .into_iter()
                .map(|(block, piece_end, block_end)| (block, (piece_end, block_end)))
                .unzip();
            // Filling ahead is serial, so the next batch fills while this one
            // codes. Nothing in this batch reads the finder any more.
            let next = batches
                .get(index + 1)
                .map(|next| local(next[next.len() - 1]));
            let ((), (packed, coding_failure)) = crate::parallel::join(
                || {
                    if let Some(last) = next {
                        parser.fill_to(last);
                    }
                },
                || code_blocks(blocks, &mut *levels),
            );
            // What coded before a failure is still handed on, as it was when
            // each piece was coded as soon as it parsed.
            for (packed, &(piece_end, block_end)) in packed.iter().zip(&places) {
                if out(packed, piece_end)?.is_break() {
                    return Ok(ControlFlow::Break(()));
                }
                block_start = piece_end;
                if let Some(end) = block_end {
                    debug_assert_eq!(block_start, end);
                    if progress.as_deref_mut().is_some_and(|report| !report(end)) {
                        return Err(Error::Cancelled);
                    }
                }
            }
            if let Some(error) = coding_failure.or(filter_failure) {
                return Err(error);
            }
        }
    }
    Ok(ControlFlow::Continue(()))
}

/// One parsed piece and what [`code_block`] needs besides the reader's table.
struct BlockToCode {
    tokens: Vec<EncodeToken>,
    state: EncoderMatchState,
    filters: Vec<Vec<u8>>,
    more_blocks_follow: bool,
}

/// Codes consecutive pieces side by side, to the bytes [`code_block`] gives coding them in turn.
///
/// A piece's table is counted from its own tokens alone. The previous piece
/// only decides how that table is written, outright or as a delta against the
/// one before, so every table is counted first and then each piece is coded
/// against its predecessor's, with `levels` standing in before the first.
///
/// Returns the packed pieces before the first failure and that failure.
/// `levels` is left holding the last table counted.
fn code_blocks(
    blocks: Vec<BlockToCode>,
    levels: &mut [u8; TABLE_COUNT],
) -> (Vec<Vec<u8>>, Option<Error>) {
    let (tables, table_failure) = map_blocks(blocks.iter().collect(), |block: &BlockToCode| {
        table_lengths_for_tokens(&block.tokens, block.state, block.filters.len())
    });
    let mut previous = *levels;
    let jobs: Vec<_> = blocks
        .into_iter()
        .zip(&tables)
        .map(|(block, table)| (block, std::mem::replace(&mut previous, *table), table))
        .collect();
    *levels = previous;
    let (packed, coding_failure) = map_blocks(jobs, |(block, previous, table)| {
        code_block_with_table(
            &block.tokens,
            block.state,
            &block.filters,
            block.more_blocks_follow,
            &previous,
            table,
        )
    });
    // A piece that coded did so after every table before it counted.
    (packed, coding_failure.or(table_failure))
}

/// Maps items in order, side by side when this thread may fan out; the outputs before the first failure, and that failure.
fn map_blocks<T: Send, O: Send>(
    items: Vec<T>,
    map: impl Fn(T) -> Result<O> + Sync + Send,
) -> (Vec<O>, Option<Error>) {
    if crate::parallel::may_nest() {
        return crate::parallel::map_prefix(items, map);
    }
    let mut outputs = Vec::with_capacity(items.len());
    for item in items {
        match map(item) {
            Ok(output) => outputs.push(output),
            Err(error) => return (outputs, Some(error)),
        }
    }
    (outputs, None)
}

/// `more_blocks_follow` is what the block's terminator says.
///
/// The end-of-block symbol is followed by a bit meaning "another table comes
/// next". A member split across blocks needs that bit set on every block but
/// the last, and clear on the last so the member ends. Getting either one
/// wrong leaves a reader parsing whatever comes after as the wrong thing.
///
/// `previous_levels` is the code-length table the reader holds when this block
/// starts, and is left holding this block's. A reader clears it between members
/// unless the archive is solid, so a caller that is not chaining members hands
/// over a table of zeroes and gets one block's worth of state back it can throw
/// away.
fn encode_member_inner(
    input: &[u8],
    history: &[u8],
    initial_filters: &[Vec<u8>],
    options: EncodeOptions,
    more_blocks_follow: bool,
    previous_levels: &mut [u8; TABLE_COUNT],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let pieces = parse_member(input, history, options, progress)?;
    let mut out = Vec::new();
    let mut filters = initial_filters;
    for (index, piece) in pieces.iter().enumerate() {
        let more = more_blocks_follow || index + 1 < pieces.len();
        out.extend_from_slice(&code_block(
            &piece.tokens,
            piece.state,
            filters,
            more,
            previous_levels,
        )?);
        filters = &[];
    }
    Ok(out)
}

/// The code-length table a block of these tokens is coded with.
fn table_lengths_for_tokens(
    tokens: &[EncodeToken],
    mut match_state: EncoderMatchState,
    filter_records: usize,
) -> Result<[u8; TABLE_COUNT]> {
    let mut frequencies = [0usize; TABLE_COUNT];
    frequencies[257] += filter_records;
    for token in tokens {
        match *token {
            EncodeToken::Literal(byte) => {
                frequencies[byte as usize] += 1;
            }
            EncodeToken::Match { length, offset } => {
                let (length, offset) = (length as usize, offset as usize);
                count_match(match_state.encode_match(length, offset)?, &mut frequencies);
                match_state.remember(length, offset);
            }
        }
    }
    frequencies[256] += 1;
    Ok(table_lengths_for_frequencies(frequencies))
}

/// Where each alphabet starts in a table, and in counts laid out like one.
const OFFSET_TABLE: usize = MAIN_COUNT;
const LOW_OFFSET_TABLE: usize = OFFSET_TABLE + OFFSET_COUNT;
const LENGTH_TABLE: usize = LOW_OFFSET_TABLE + LOW_OFFSET_COUNT;

/// Counts the symbols one match codes as, in counts laid out like a table.
fn count_match(encoded: EncodedMatch, frequencies: &mut [usize; TABLE_COUNT]) {
    match encoded {
        EncodedMatch::LastLengthRepeat => frequencies[258] += 1,
        EncodedMatch::RepeatOffset {
            index, length_slot, ..
        } => {
            frequencies[259 + index] += 1;
            frequencies[LENGTH_TABLE + length_slot] += 1;
        }
        EncodedMatch::Short { slot, .. } => frequencies[263 + slot] += 1,
        EncodedMatch::Fresh {
            length_slot,
            offset_slot,
            offset_extra,
            ..
        } => {
            frequencies[271 + length_slot] += 1;
            frequencies[OFFSET_TABLE + offset_slot] += 1;
            if offset_slot > 9 {
                frequencies[LOW_OFFSET_TABLE + (offset_extra & 0x0f)] += 1;
            }
        }
    }
}

/// The code-length table for a block's symbol counts, end of block included.
fn table_lengths_for_frequencies(mut frequencies: [usize; TABLE_COUNT]) -> [u8; TABLE_COUNT] {
    let low_offsets = &mut frequencies[LOW_OFFSET_TABLE..LENGTH_TABLE];
    if low_offsets.iter().all(|&frequency| frequency == 0) {
        low_offsets[0] = 1;
    }
    let mut table_lengths = [0u8; TABLE_COUNT];
    for alphabet in [
        0..OFFSET_TABLE,
        OFFSET_TABLE..LOW_OFFSET_TABLE,
        LOW_OFFSET_TABLE..LENGTH_TABLE,
        LENGTH_TABLE..TABLE_COUNT,
    ] {
        table_lengths[alphabet.clone()].copy_from_slice(&huffman::lengths_for_frequencies(
            &frequencies[alphabet],
            15,
        ));
    }
    table_lengths
}

fn code_block(
    tokens: &[EncodeToken],
    state: EncoderMatchState,
    initial_filters: &[Vec<u8>],
    more_blocks_follow: bool,
    previous_levels: &mut [u8; TABLE_COUNT],
) -> Result<Vec<u8>> {
    let table_lengths = table_lengths_for_tokens(tokens, state, initial_filters.len())?;
    let packed = code_block_with_table(
        tokens,
        state,
        initial_filters,
        more_blocks_follow,
        previous_levels,
        &table_lengths,
    )?;
    *previous_levels = table_lengths;
    Ok(packed)
}

/// [`code_block`] with the block's table already counted by [`table_lengths_for_tokens`].
fn code_block_with_table(
    tokens: &[EncodeToken],
    state: EncoderMatchState,
    initial_filters: &[Vec<u8>],
    more_blocks_follow: bool,
    previous_levels: &[u8; TABLE_COUNT],
    table_lengths: &[u8; TABLE_COUNT],
) -> Result<Vec<u8>> {
    let table_lengths = *table_lengths;

    // Two ways to say the same table: outright, or as a delta against the one
    // the reader already holds. Neither wins everywhere, so code both and take
    // the shorter. Coding a table costs nothing next to parsing the block it
    // describes, and picking by size means the keep-tables bit can only help.
    let outright = encode_table_level_tokens(&table_lengths);
    let against_previous = encode_level_tokens_against(&table_lengths, previous_levels);
    let keep_previous_tables =
        level_tokens_bit_cost(&against_previous) < level_tokens_bit_cost(&outright);
    let level_tokens = match keep_previous_tables {
        true => against_previous,
        false => outright,
    };

    let level_lengths = level_code_lengths(&level_tokens);
    let level_codes = canonical_codes(&level_lengths);
    let main_codes = canonical_codes(&table_lengths[..MAIN_COUNT]);

    let mut bits = BitWriter::default();
    bits.write_bit(false); // LZ block.
    bits.write_bit(keep_previous_tables);
    for &len in &level_lengths {
        bits.write_bits(len as u32, 4);
    }
    // Both passes replay the same tokens from the same initial match state.
    // Every emitted symbol was counted, and positive frequencies receive codes.
    for token in level_tokens {
        let code = level_codes[token.symbol].expect("counted level Huffman code");
        bits.write_bits(code.code as u32, code.len);
        if token.extra_bits != 0 {
            bits.write_bits(token.extra_value as u32, token.extra_bits);
        }
    }
    let offset_codes = canonical_codes(&table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT]);
    let low_offset_codes = canonical_codes(
        &table_lengths[MAIN_COUNT + OFFSET_COUNT..MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT],
    );
    let length_codes =
        canonical_codes(&table_lengths[MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT..]);
    for filter in initial_filters {
        let code = main_codes[257].expect("counted VM filter Huffman code");
        bits.write_bits(code.code as u32, code.len);
        for &byte in filter {
            bits.write_bits(u32::from(byte), 8);
        }
    }
    let mut match_state = state;
    for &token in tokens {
        match token {
            EncodeToken::Literal(byte) => {
                let code = main_codes[byte as usize].expect("counted literal Huffman code");
                bits.write_bits(code.code as u32, code.len);
            }
            EncodeToken::Match { length, offset } => {
                let (length, offset) = (length as usize, offset as usize);
                match match_state.encode_match(length, offset)? {
                    EncodedMatch::LastLengthRepeat => {
                        let code =
                            main_codes[258].expect("counted last-length repeat Huffman code");
                        bits.write_bits(code.code as u32, code.len);
                    }
                    EncodedMatch::RepeatOffset {
                        index,
                        length_slot,
                        length_extra,
                    } => {
                        let code =
                            main_codes[259 + index].expect("counted repeat-offset Huffman code");
                        bits.write_bits(code.code as u32, code.len);
                        let length_code =
                            length_codes[length_slot].expect("counted repeat length Huffman code");
                        bits.write_bits(length_code.code as u32, length_code.len);
                        if LENGTH_BITS[length_slot] != 0 {
                            bits.write_bits(length_extra as u32, LENGTH_BITS[length_slot]);
                        }
                    }
                    EncodedMatch::Short { slot, extra } => {
                        let code =
                            main_codes[263 + slot].expect("counted short match Huffman code");
                        bits.write_bits(code.code as u32, code.len);
                        bits.write_bits(extra as u32, SHORT_BITS[slot]);
                    }
                    EncodedMatch::Fresh {
                        length_slot,
                        length_extra,
                        offset_slot,
                        offset_extra,
                    } => {
                        let code =
                            main_codes[271 + length_slot].expect("counted match Huffman code");
                        bits.write_bits(code.code as u32, code.len);
                        if LENGTH_BITS[length_slot] != 0 {
                            bits.write_bits(length_extra as u32, LENGTH_BITS[length_slot]);
                        }
                        let offset =
                            offset_codes[offset_slot].expect("counted offset Huffman code");
                        bits.write_bits(offset.code as u32, offset.len);
                        if offset_slot > 9 {
                            let offset_bits = OFFSET_BITS[offset_slot];
                            if offset_bits > 4 {
                                bits.write_bits((offset_extra >> 4) as u32, offset_bits - 4);
                            }
                            let low_offset = low_offset_codes[offset_extra & 0x0f]
                                .expect("counted low-offset Huffman code");
                            bits.write_bits(low_offset.code as u32, low_offset.len);
                        } else if OFFSET_BITS[offset_slot] != 0 {
                            bits.write_bits(offset_extra as u32, OFFSET_BITS[offset_slot]);
                        }
                    }
                }
                match_state.remember(length, offset);
            }
        }
    }
    let end = main_codes[256].expect("counted end-of-block Huffman code");
    bits.write_bits(end.code as u32, end.len);
    // The end-of-block symbol on its own does not end the member: the next bit
    // says whether another table follows. A block in the middle of a member
    // sets it, because one does. The last block clears it and then writes a
    // second bit, which is what the reader carries into a solid follower: a one
    // tells it to read its own tables.
    if more_blocks_follow {
        bits.write_bit(true);
    } else {
        bits.write_bit(false);
        bits.write_bit(true);
    }
    Ok(bits.finish())
}

/// Encodes the filter records for one LZ block.
///
/// `base` is where the block starts in the member, because a record's block
/// start is read relative to the decoder's current output position, and that
/// position is the head of the block the record is declared in. Writing the
/// member-absolute offset instead makes the decoder mask it against the window
/// and apply the filter in the wrong place.
///
/// `programs` carries across blocks so a program declared once is referenced by
/// index afterwards, which is what the decoder expects.
fn encoded_filter_records_at(
    filters: &[&OwnedVmFilterRecord],
    base: usize,
    window: usize,
    programs: &mut Vec<&'static [u8]>,
) -> Result<Vec<Vec<u8>>> {
    let mut records = Vec::with_capacity(filters.len());
    for filter in filters {
        let existing = (filter.code != RAR3_AUDIO_FILTER_BYTECODE)
            .then(|| programs.iter().position(|&code| code == filter.code))
            .flatten();
        let (program_selector, include_code) = match existing {
            Some(index) => (
                u32::try_from(index + 1)
                    .map_err(|_| Error::InvalidData("RAR 2.9 VM program index overflows"))?,
                false,
            ),
            None => {
                let selector = if programs.is_empty() {
                    0
                } else {
                    u32::try_from(programs.len() + 1)
                        .map_err(|_| Error::InvalidData("RAR 2.9 VM program index overflows"))?
                };
                programs.push(filter.code);
                (selector, true)
            }
        };
        let block_start = filter
            .block_start
            .checked_sub(base)
            .ok_or(Error::InvalidData(
                "RAR 2.9 VM filter starts before its block",
            ))?;
        // The decoder masks this against its window, so a record reaching past
        // one lands somewhere else entirely and the member decodes to the wrong
        // bytes. Our own decoder reads it back the way it was written and so
        // agrees, which is why this is checked here rather than left to a round
        // trip to notice.
        if block_start >= window {
            return Err(Error::InvalidData(
                "RAR 2.9 VM filter starts further past its block than the window can express",
            ));
        }
        records.push(encode_vm_filter_record_inner(
            VmFilterRecord {
                block_start,
                block_size: filter.block_size,
                init_regs: &filter.init_regs,
                code: filter.code,
                global_data: &filter.global_data,
            },
            program_selector,
            include_code,
        )?);
    }
    Ok(records)
}

/// Codes filtered bytes a block at a time, so that no filter is declared
/// further ahead of its block than the decoder's window can express, and so a
/// large member does not need a whole LZ pass in memory at once.
fn encode_filtered_member_blocks(
    data: &[u8],
    history: &[u8],
    filters: &[OwnedVmFilterRecord],
    options: EncodeOptions,
    levels: &mut [u8; TABLE_COUNT],
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let block_size = filtered_block_size(options, data.len());
    let window = options.max_match_distance.max(1);
    let mut inner = options;
    inner.block_size = None;
    let mut programs: Vec<&'static [u8]> = Vec::new();
    let mut out = Vec::new();
    for_each_block(
        &mut InMemory::new(data, history, filters, inner),
        inner,
        block_size,
        levels,
        progress,
        |base, end, records| block_filter_records(records, base, end, window, &mut programs),
        |packed, _| {
            out.extend_from_slice(packed);
            Ok(ControlFlow::Continue(()))
        },
    )?
    .continue_value()
    .expect("an in-memory member codes every block");
    Ok(out)
}

/// A record's offset is relative to the head of its own block, so a block no
/// larger than the window keeps every offset inside it.
fn filtered_block_size(options: EncodeOptions, len: usize) -> usize {
    options
        .block_size
        .filter(|&size| size != 0)
        .unwrap_or(len.max(1))
        .min(options.max_match_distance.max(1))
        .max(1)
}

/// A block declares the filters that start in it, relative to its head.
fn block_filter_records(
    records: &[OwnedVmFilterRecord],
    base: usize,
    end: usize,
    window: usize,
    programs: &mut Vec<&'static [u8]>,
) -> Result<Vec<Vec<u8>>> {
    let in_block: Vec<&OwnedVmFilterRecord> = records
        .iter()
        .filter(|record| record.block_start >= base && record.block_start < end.max(base + 1))
        .collect();
    encoded_filter_records_at(&in_block, base, window, programs)
}

#[derive(Debug, Clone, Copy)]
struct VmFilterRecord<'a> {
    block_start: usize,
    block_size: usize,
    init_regs: &'a [(usize, u32)],
    code: &'a [u8],
    global_data: &'a [u8],
}

fn encode_vm_filter_record_inner(
    record: VmFilterRecord<'_>,
    program_selector: u32,
    include_code: bool,
) -> Result<Vec<u8>> {
    if record.block_size == 0 {
        return Err(Error::InvalidData("RAR 2.9 VM filter block is empty"));
    }
    if include_code && record.code.is_empty() {
        return Err(Error::InvalidData("RAR 2.9 VM filter bytecode is empty"));
    }

    let mut body = BitWriter::default();
    body.write_encoded_u32(program_selector);
    body.write_encoded_u32(
        u32::try_from(record.block_start)
            .map_err(|_| Error::InvalidData("RAR 2.9 VM block start overflows"))?,
    );
    body.write_encoded_u32(
        u32::try_from(record.block_size)
            .map_err(|_| Error::InvalidData("RAR 2.9 VM block size overflows"))?,
    );
    if !record.init_regs.is_empty() {
        let mut mask = 0u32;
        for &(index, _) in record.init_regs {
            if index >= 7 {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM init register index is invalid",
                ));
            }
            mask |= 1 << index;
        }
        body.write_bits(mask, 7);
        for index in 0..7 {
            if let Some((_, value)) = record.init_regs.iter().find(|(reg, _)| *reg == index) {
                body.write_encoded_u32(*value);
            }
        }
    }
    if include_code {
        body.write_encoded_u32(
            u32::try_from(record.code.len())
                .map_err(|_| Error::InvalidData("RAR 2.9 VM code size overflows"))?,
        );
        for &byte in record.code {
            body.write_bits(u32::from(byte), 8);
        }
    }
    if !record.global_data.is_empty() {
        body.write_encoded_u32(
            u32::try_from(record.global_data.len())
                .map_err(|_| Error::InvalidData("RAR 2.9 VM global data size overflows"))?,
        );
        for &byte in record.global_data {
            body.write_bits(u32::from(byte), 8);
        }
    }
    let body = body.finish();

    let mut out = Vec::new();
    let mut first = 0x80 | 0x20;
    if !record.init_regs.is_empty() {
        first |= 0x10;
    }
    if !record.global_data.is_empty() {
        first |= 0x08;
    }
    match body.len() {
        1..=6 => first |= (body.len() as u8) - 1,
        7..=262 => {
            first |= 6;
            out.push((body.len() - 7) as u8);
        }
        263..=65535 => {
            first |= 7;
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        _ => return Err(Error::InvalidData("RAR 2.9 VM filter record is too large")),
    }
    out.insert(0, first);
    out.extend_from_slice(&body);
    Ok(out)
}

fn rgb_encode(data: &[u8], width: usize, pos_r: usize) -> Result<Vec<u8>> {
    if data.len() < 3 || width == 0 || !width.is_multiple_of(3) || width > data.len() || pos_r > 2 {
        return Err(Error::InvalidData(
            "RAR 2.9 RGB filter parameters are invalid",
        ));
    }
    let mut work = data.to_vec();
    for i in (pos_r..work.len().saturating_sub(2)).step_by(3) {
        let green = work[i + 1];
        work[i] = work[i].wrapping_sub(green);
        work[i + 2] = work[i + 2].wrapping_sub(green);
    }

    let mut out = Vec::with_capacity(data.len());
    for channel in 0..3 {
        let mut prev = 0u8;
        let mut i = channel;
        while i < work.len() {
            let predicted = if i >= width + 3 {
                rgb_predict(prev, work[i - width], work[i - width - 3])
            } else {
                prev
            };
            let byte = work[i];
            out.push(predicted.wrapping_sub(byte));
            prev = byte;
            i += 3;
        }
    }
    Ok(out)
}

fn audio_encode(data: &[u8], channels: usize) -> Result<Vec<u8>> {
    if channels == 0 || channels > MAX_AUDIO_CHANNELS {
        return Err(Error::InvalidData(
            "RAR 2.9 AUDIO filter channel count is invalid",
        ));
    }
    let mut out = Vec::with_capacity(data.len());
    for channel in 0..channels {
        let mut prev_byte = 0u32;
        let mut prev_delta = 0i32;
        let mut d1 = 0i32;
        let mut d2 = 0i32;
        let mut k1 = 0i32;
        let mut k2 = 0i32;
        let mut k3 = 0i32;
        let mut dif = [0u32; 7];
        let mut byte_count = 0usize;
        let mut i = channel;
        while i < data.len() {
            let d3 = d2;
            d2 = prev_delta - d1;
            d1 = prev_delta;
            let predicted = ((8 * prev_byte as i32 + k1 * d1 + k2 * d2 + k3 * d3) >> 3) & 0xff;
            let decoded = data[i];
            let encoded = (predicted as u8).wrapping_sub(decoded);
            out.push(encoded);
            prev_delta = decoded.wrapping_sub(prev_byte as u8) as i8 as i32;
            prev_byte = decoded as u32;
            let d = (encoded as i8 as i32) << 3;
            dif[0] += d.unsigned_abs();
            dif[1] += (d - d1).unsigned_abs();
            dif[2] += (d + d1).unsigned_abs();
            dif[3] += (d - d2).unsigned_abs();
            dif[4] += (d + d2).unsigned_abs();
            dif[5] += (d - d3).unsigned_abs();
            dif[6] += (d + d3).unsigned_abs();
            if byte_count & 0x1f == 0 {
                let mut min = dif[0];
                let mut min_index = 0usize;
                dif[0] = 0;
                for (index, value) in dif.iter_mut().enumerate().skip(1) {
                    if *value < min {
                        min = *value;
                        min_index = index;
                    }
                    *value = 0;
                }
                match min_index {
                    1 if k1 >= -16 => k1 -= 1,
                    2 if k1 < 16 => k1 += 1,
                    3 if k2 >= -16 => k2 -= 1,
                    4 if k2 < 16 => k2 += 1,
                    5 if k3 >= -16 => k3 -= 1,
                    6 if k3 < 16 => k3 += 1,
                    _ => {}
                }
            }
            byte_count += 1;
            i += channels;
        }
    }
    Ok(out)
}

fn itanium_encode(data: &mut [u8], file_offset: u32) {
    if data.len() <= 21 {
        return;
    }
    let base_offset = file_offset >> 4;
    let block_count = (data.len() - 21).div_ceil(16);
    for block in 0..block_count {
        let pos = block * 16;
        let file_offset = base_offset.wrapping_add(block as u32);
        let mut mask = (0x334b_0000u32 >> (data[pos] & 0x1e)) & 3;
        if mask != 0 {
            mask += 1;
            while mask <= 4 {
                let p = pos + (mask as usize * 5 - 8);
                if ((data[p + 3] >> mask) & 15) == 5 {
                    let raw = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    let mut value = raw >> mask;
                    value = value.wrapping_add(file_offset) & 0x000f_ffff;
                    let raw = (raw & !(0x000f_ffff << mask)) | (value << mask);
                    data[p..p + 4].copy_from_slice(&raw.to_le_bytes());
                }
                mask += 1;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EncodeToken {
    Literal(u8),
    // u32 halves a token, and a parse batch holds one per byte at worst.
    Match { length: u32, offset: u32 },
}

#[derive(Debug, Clone, Copy, Default)]
struct EncoderMatchState {
    old_offsets: [usize; 4],
    last_offset: usize,
    last_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedMatch {
    LastLengthRepeat,
    RepeatOffset {
        index: usize,
        length_slot: usize,
        length_extra: usize,
    },
    /// A two-byte match up to 256 back, which only the shortest-path parse emits.
    Short {
        slot: usize,
        extra: usize,
    },
    Fresh {
        length_slot: usize,
        length_extra: usize,
        offset_slot: usize,
        offset_extra: usize,
    },
}

impl EncoderMatchState {
    fn encode_match(&self, length: usize, offset: usize) -> Result<EncodedMatch> {
        if self.last_length != 0 && offset == self.last_offset && length == self.last_length {
            return Ok(EncodedMatch::LastLengthRepeat);
        }
        if let Some(index) = self
            .old_offsets
            .iter()
            .position(|&old_offset| old_offset == offset && old_offset != 0)
        {
            // The repeat-distance table stops at 257 bytes, one byte before
            // the fresh-match table. A 258-byte match at a remembered
            // distance is still representable, just not with the shorter
            // repeat token.
            if let Ok((length_slot, length_extra)) = length_slot_for_repeat_match(length) {
                return Ok(EncodedMatch::RepeatOffset {
                    index,
                    length_slot,
                    length_extra,
                });
            }
        }
        if length == 2 {
            let (slot, extra) = short_slot_for_match(offset)?;
            return Ok(EncodedMatch::Short { slot, extra });
        }
        let encoded_length =
            length
                .checked_sub(match_length_adjustment(offset))
                .ok_or(Error::InvalidData(
                    "RAR 2.9 adjusted match length underflows",
                ))?;
        let (length_slot, length_extra) = length_slot_for_match(encoded_length)?;
        let (offset_slot, offset_extra) = offset_slot_for_match(offset)?;
        Ok(EncodedMatch::Fresh {
            length_slot,
            length_extra,
            offset_slot,
            offset_extra,
        })
    }

    fn remember(&mut self, length: usize, offset: usize) {
        if self.last_length != 0 && offset == self.last_offset && length == self.last_length {
            return;
        }
        if let Some(index) = self
            .old_offsets
            .iter()
            .position(|&old_offset| old_offset == offset)
            .filter(|_| length_slot_for_repeat_match(length).is_ok())
        {
            self.old_offsets[..=index].rotate_right(1);
        } else {
            // This is a fresh token even when its distance already occurs in
            // the repeat ring. The decoder shifts it in and keeps the older
            // occurrence, so the encoder must retain the duplicate too.
            self.old_offsets.rotate_right(1);
            self.old_offsets[0] = offset;
        }
        self.last_offset = offset;
        self.last_length = length;
    }
}

/// Every block's tokens in order, coded from one state as a single block would be.
#[cfg(test)]
fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    Ok(parse_member(input, history, options, progress)?
        .into_iter()
        .flat_map(|piece| piece.tokens)
        .collect())
}

/// A member parsed as one block, or cut into several where that codes smaller.
fn parse_member(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<Piece>> {
    let combined = with_history(history, input, options);
    let start = combined.len() - input.len();
    let reach = options.max_match_distance.min(MAX_HISTORY);
    let long = keys_long(options, input.len() + start.min(reach));
    let mut finder = ChainFinder::for_reach(reach, reach, long);
    for history_pos in 0..start {
        finder.insert(&combined, history_pos);
    }
    let end = combined.len();
    match &mut finder {
        ChainFinder::Short(finder) => parse_block(&combined, start, end, finder, options, progress),
        ChainFinder::Long(finder) => parse_block(&combined, start, end, finder, options, progress),
    }
}

fn with_history<'a>(
    history: &[u8],
    input: &'a [u8],
    options: EncodeOptions,
) -> std::borrow::Cow<'a, [u8]> {
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    if history.is_empty() {
        return std::borrow::Cow::Borrowed(input);
    }
    let mut combined = Vec::with_capacity(history.len() + input.len());
    combined.extend_from_slice(history);
    combined.extend_from_slice(input);
    std::borrow::Cow::Owned(combined)
}

/// Blocks start with no repeat offsets, so a batch parses in parallel against a finder filled ahead.
struct LzParser<'a> {
    data: &'a [u8],
    /// Where the next block parsed starts.
    parsed: usize,
    filled: usize,
    batch_bytes: usize,
    finder: ChainFinder,
    options: EncodeOptions,
}

impl<'a> LzParser<'a> {
    /// Two blocks per thread, up to 16 threads, so the window stays bounded.
    fn batch_bytes(block_size: usize) -> usize {
        block_size
            .saturating_mul(crate::parallel::threads().min(16) * 2)
            .max(block_size)
    }

    /// `long` is [`keys_long`] for the whole member, which a segment of it cannot judge.
    fn new(
        data: &'a [u8],
        start: usize,
        options: EncodeOptions,
        block_size: usize,
        long: bool,
    ) -> Self {
        let reach = options.max_match_distance.min(MAX_HISTORY);
        let batch_bytes = Self::batch_bytes(block_size);
        // Reach plus a batch, so filling a batch only overwrites links nothing
        // in it can reach, and no more than the data, which then overwrites
        // none. A batch is megabytes at any thread count: clearing links for
        // one was most of the time spent on a member of a few kilobytes.
        let window = reach.saturating_add(batch_bytes).min(data.len());
        let mut finder = ChainFinder::for_reach(window, reach, long);
        for history_pos in 0..start {
            finder.insert(data, history_pos);
        }
        Self {
            data,
            parsed: start,
            filled: start,
            batch_bytes,
            finder,
            options,
        }
    }

    /// `ends` must stay within one batch of where the last call ended.
    #[cfg(test)]
    fn parse_blocks(&mut self, ends: &[usize]) -> Result<Vec<Vec<Piece>>> {
        if let Some(&last) = ends.last() {
            self.fill_to(last);
        }
        self.parse_filled(ends)
    }

    /// Inserts every position before `last`, for the batch that ends there.
    ///
    /// Only once every block before has parsed: filling overwrites links a
    /// batch further back than the reach, which those blocks may still read.
    fn fill_to(&mut self, last: usize) {
        debug_assert!(self.filled == self.parsed);
        debug_assert!(last - self.filled <= self.batch_bytes);
        match &mut self.finder {
            ChainFinder::Short(finder) => {
                for pos in self.filled..last {
                    finder.insert(self.data, pos);
                }
            }
            ChainFinder::Long(finder) => {
                for pos in self.filled..last {
                    finder.insert(self.data, pos);
                }
            }
        }
        self.filled = last;
    }

    /// Parses the blocks ending at `ends`, from where the last call ended, which must already be filled.
    fn parse_filled(&mut self, ends: &[usize]) -> Result<Vec<Vec<Piece>>> {
        let Some(&last) = ends.last() else {
            return Ok(Vec::new());
        };
        debug_assert!(last <= self.filled);
        let first = std::mem::replace(&mut self.parsed, last);
        let ranges: Vec<(usize, usize)> = std::iter::once(first)
            .chain(ends[..ends.len() - 1].iter().copied())
            .zip(ends.iter().copied())
            .collect();
        let (data, options) = (self.data, self.options);
        match &self.finder {
            ChainFinder::Short(finder) => parse_ranges(ranges, |(start, end)| {
                parse_block(data, start, end, &mut FilledAhead(finder), options, None)
            }),
            ChainFinder::Long(finder) => parse_ranges(ranges, |(start, end)| {
                parse_block(data, start, end, &mut FilledAhead(finder), options, None)
            }),
        }
    }
}

/// Parses each block, side by side when this thread may fan out.
fn parse_ranges(
    ranges: Vec<(usize, usize)>,
    parse: impl Fn((usize, usize)) -> Result<Vec<Piece>> + Sync + Send,
) -> Result<Vec<Vec<Piece>>> {
    if !crate::parallel::may_nest() {
        return ranges.into_iter().map(parse).collect();
    }
    // A failure must not leave the blocks after it out of the member.
    match crate::parallel::map_prefix(ranges, parse) {
        (_, Some(error)) => Err(error),
        (pieces, None) => Ok(pieces),
    }
}

/// The most one in-memory LZ encode of a `len` byte member holds beside the
/// member itself, filtered or not: a filtered copy of it, its packed bytes, the
/// match finder, and one parse batch's tokens, pieces and packed blocks. Plus the
/// packed bytes of an earlier encode, for a caller comparing encodes to keep
/// the best so far while the next one runs.
///
/// The shortest-path parse's own workspace is not included; a caller that
/// asks for it charges [`OPTIMAL_PARSE_WORKSPACE`] per block parsing at once.
pub(crate) fn member_encode_workspace(len: usize, options: EncodeOptions) -> u64 {
    let options = options.constrained();
    let reach = options.max_match_distance.min(MAX_HISTORY);
    // A filtered member's blocks are never longer than a plain one's.
    let block = options
        .block_size
        .filter(|&size| size != 0)
        .unwrap_or(len)
        .max(1);
    let batch = LzParser::batch_bytes(block).min(len.max(1));
    let finder = Rar29MatchFinder::bytes_for_reach(reach.saturating_add(batch).min(len), reach);
    // A token per byte at worst, and a packed byte. Cutting a block splits
    // the tail of its tokens off into fresh pieces while the head keeps its
    // capacity, beside a running count per cut it weighs.
    let token = std::mem::size_of::<EncodeToken>() as u64;
    let per_byte = match options.split_blocks {
        true => 2 * token + 2,
        false => token + 1,
    };
    let tokens = (batch as u64).saturating_mul(per_byte);
    let len = len as u64;
    // The packed member can come out a little larger than the member.
    let packed = len.saturating_add(len / 8);
    finder
        .saturating_add(tokens)
        .saturating_add(len)
        .saturating_add(packed.saturating_mul(2))
}

/// One block's tokens, and where in the parsed bytes the block ends.
#[derive(Debug)]
struct Piece {
    end: usize,
    /// The repeat offsets the parse carried into the block. The reader keeps
    /// its own across blocks, and agrees on every one of these it remembers.
    state: EncoderMatchState,
    tokens: Vec<EncodeToken>,
}

/// The lazy parse, at the levels that ask for it parsed again by shortest
/// path, then cut into blocks where that codes smaller. At those levels each
/// block is parsed again once cut, priced by the tables it now has.
fn parse_block<C: Candidates>(
    data: &[u8],
    start: usize,
    end: usize,
    finder: &mut C,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<Piece>> {
    let mut tokens = parse_range(data, start, end, finder, options, progress)?;
    let fresh = EncoderMatchState::default();
    let refiner = match options.optimal_parse_passes {
        0 => None,
        _ => optimal_parse::Refiner::new(data, start, end, &*finder, options),
    };
    if let Some(refiner) = &refiner {
        tokens = refiner
            .refine(data, (start, end), options, tokens, (fresh, fresh))?
            .0;
    }
    if !options.split_blocks {
        return Ok(vec![Piece {
            end,
            state: fresh,
            tokens,
        }]);
    }
    let pieces = block_split::split(start, end, tokens)?;
    let Some(refiner) = refiner.filter(|_| pieces.len() > 1) else {
        return Ok(pieces);
    };
    // Coming in with the offsets the pieces before it now leave, which the
    // tokens it was cut with may no longer code from. That can cost a piece
    // more than its own parse saved, so the cut parse stays if it was smaller.
    //
    // One pass a piece. Level 5's three took its time on 4 MiB of a binary
    // from 1.13 to 1.33 times what it was before cutting, for 0.03-0.06%.
    let mut cut_bits = 0usize;
    let mut parsed_bits = 0usize;
    let mut parsed = Vec::with_capacity(pieces.len());
    let mut state = fresh;
    let mut from = start;
    for piece in &pieces {
        cut_bits += optimal_parse::priced_bits(&piece.tokens, piece.state)?;
        let (tokens, bits) = refiner.refine(
            data,
            (from, piece.end),
            options.with_optimal_parse_passes(1),
            piece.tokens.clone(),
            (piece.state, state),
        )?;
        parsed_bits = parsed_bits.saturating_add(bits);
        let piece = Piece {
            end: piece.end,
            state,
            tokens,
        };
        for token in &piece.tokens {
            if let EncodeToken::Match { length, offset } = *token {
                state.remember(length as usize, offset as usize);
            }
        }
        from = piece.end;
        parsed.push(piece);
    }
    Ok(match parsed_bits < cut_bits {
        true => parsed,
        false => pieces,
    })
}

/// No match crosses `end`, so a block covers exactly the bytes it was given.
fn parse_range<C: Candidates>(
    data: &[u8],
    start: usize,
    end: usize,
    finder: &mut C,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    let mut tokens = Vec::new();
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    let mut pending_match: Option<MatchCandidate> = None;
    let mut pos = start;
    // Judged from the block's own bytes, so a block parses the same wherever
    // the member is cut.
    let random = std::cell::OnceCell::new();
    let looks_random = || *random.get_or_init(|| NearMatches::looks_random(&data[start..end]));
    // A parse that walks few candidates keeps near matches for the four- and
    // five-byte matches a six-byte key cannot offer. A lazy one keeps them on
    // four-byte chains too, where they pay; a greedy one there has its chains'
    // four-byte matches already, and goes without. Not in a block that looks
    // random, at any level: there they cost more time than they find.
    let walks_few_on = match options.lazy_matching {
        true => walks_few(options),
        false => finder.key() > MIN_CHAIN_MATCH,
    };
    let near_pays =
        (walks_few_on || (options.lazy_matching && options.near_matches)) && !looks_random();
    // Filled from the history a near match can reach, so a block parses the
    // same whether the bytes before it were parsed in this call or another.
    let mut near = near_pays.then(|| {
        let mut near = NearMatches::new();
        for history_pos in start.saturating_sub(MAX_THREE_BYTE_OFFSET)..start {
            near.insert(data, history_pos);
        }
        near
    });
    let skip_after = options
        .skip_literal_runs
        .filter(|_| looks_random())
        .map(|misses| misses.max(1));
    let mut misses = 0usize;
    // A greedy parse keyed on six bytes is the fastest level, and keeps the
    // near table to the positions it searches: the start of each match, not
    // every byte inside it. The newest copy of a three-byte run inside a long
    // match is one the six-byte chains usually find anyway.
    let sparse_near = !options.lazy_matching && finder.key() > MIN_CHAIN_MATCH;
    let insert = |finder: &mut C, near: &mut Option<NearMatches>, pos: usize| {
        finder.insert(data, pos);
        if let Some(near) = near {
            near.insert(data, pos);
        }
    };
    while pos < end {
        let candidate = pending_match.take().or_else(|| {
            best_match_before(data, pos, end, pos, finder, options, &state, near.as_ref())
        });
        if let Some(candidate) = candidate {
            misses = 0;
            let (emit_literal, cached_next) = lazy_match_decision(
                data,
                pos,
                end,
                finder,
                options,
                &state,
                candidate,
                near.as_ref(),
            );
            if emit_literal {
                tokens.push(EncodeToken::Literal(data[pos]));
                insert(finder, &mut near, pos);
                pos += 1;
                pending_match = cached_next;
                continue;
            }
            let MatchCandidate { length, offset, .. } = candidate;
            tokens.push(EncodeToken::Match {
                length: length as u32,
                offset: offset as u32,
            });
            state.remember(length, offset);
            if sparse_near {
                insert(finder, &mut near, pos);
                for history_pos in pos + 1..pos + length {
                    finder.insert(data, history_pos);
                }
            } else {
                for history_pos in pos..pos + length {
                    insert(finder, &mut near, history_pos);
                }
            }
            pos += length;
        } else if let Some(skip_after) = skip_after {
            misses += 1;
            let run = (1 + misses / skip_after).min(end - pos);
            for (literal_pos, &byte) in (pos..).zip(&data[pos..pos + run]) {
                tokens.push(EncodeToken::Literal(byte));
                insert(finder, &mut near, literal_pos);
            }
            pos += run;
        } else {
            tokens.push(EncodeToken::Literal(data[pos]));
            insert(finder, &mut near, pos);
            pos += 1;
        }
        let consumed = pos - start;
        if consumed >= next_report {
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(consumed))
            {
                return Err(Error::Cancelled);
            }
            next_report = consumed.saturating_add(1024 * 1024);
        }
    }
    if progress.is_some_and(|report| !report(end - start)) {
        return Err(Error::Cancelled);
    }
    Ok(tokens)
}

/// Decides whether a literal should be emitted instead of `current` because a
/// better match starts within the lazy lookahead window. Also returns the
/// match found one byte ahead (when computed) so the caller can reuse it for
/// the next position instead of searching again.
#[allow(clippy::too_many_arguments)]
fn lazy_match_decision<C: Candidates>(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &C,
    options: EncodeOptions,
    state: &EncoderMatchState,
    current: MatchCandidate,
    near: Option<&NearMatches>,
) -> (bool, Option<MatchCandidate>) {
    if !options.lazy_matching {
        return (false, None);
    }
    let lookahead = options.lazy_lookahead.max(1);
    let mut cached_next = None;
    for offset in 1..=lookahead {
        if pos + offset >= end {
            break;
        }
        let next = best_match_before(input, pos + offset, end, pos, finder, options, state, near);
        if offset == 1 {
            cached_next = next;
        }
        let skipped_literal_score = offset as isize * 8;
        if next.is_some_and(|next| next.score > current.score + skipped_literal_score) {
            return (true, cached_next);
        }
    }
    (false, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchCandidate {
    length: usize,
    offset: usize,
    score: isize,
}

/// The running price of each token kind, measured off the range coder as the
/// member is encoded. An escape token is far from free: a match is six model
/// symbols (escape, 4, three offset bytes, a length) and a repeat is three,
/// coded through contexts where the escape byte is rare, and the copied bytes
/// never enter the model. On text the model predicts a repeated span for a
/// fraction of a bit per byte, so a minimum-length match can cost several
/// times the literals it replaces. Emitting every legal match is what left
/// PPMd members 30-45% behind rar 3.00 on log-shaped text.
///
/// The literal average answers "what does a byte cost as a literal right
/// now", which is the opportunity cost of a match, so it moves slowly. The
/// token averages track a near-fixed overhead, so they move fast. All three
/// are only ever compared against each other, so the model self-corrects: a
/// token kind that keeps losing keeps its measured price and stays rejected.
struct PpmdTokenCosts {
    literal_bits: f64,
    match_bits: f64,
    repeat_bits: f64,
}

impl PpmdTokenCosts {
    fn new() -> Self {
        Self {
            literal_bits: PPMD_LITERAL_BITS_SEED,
            match_bits: PPMD_MATCH_BITS_SEED,
            repeat_bits: PPMD_REPEAT_BITS_SEED,
        }
    }

    fn match_pays(&self, length: usize) -> bool {
        length as f64 * self.literal_bits > self.match_bits + PPMD_CONTEXT_BREAK_BITS
    }

    fn repeat_pays(&self, length: usize) -> bool {
        length as f64 * self.literal_bits > self.repeat_bits + PPMD_CONTEXT_BREAK_BITS
    }

    fn record_literal(&mut self, bits: f64) {
        ema(&mut self.literal_bits, bits, PPMD_LITERAL_EMA_WEIGHT);
    }

    fn record_match(&mut self, bits: f64) {
        ema(&mut self.match_bits, bits, PPMD_TOKEN_EMA_WEIGHT);
    }

    fn record_repeat(&mut self, bits: f64) {
        ema(&mut self.repeat_bits, bits, PPMD_TOKEN_EMA_WEIGHT);
    }
}

fn ema(slot: &mut f64, sample: f64, weight: f64) {
    *slot += weight * (sample - *slot);
}

/// Feed the member through PPMd, escaping to an LZ token only where the token
/// prices in cheaper than letting the model code the same bytes as literals.
/// Tokenising and encoding are one loop so each decision can read the cost of
/// the last one straight off the range coder; a separate tokenising pass has
/// no way to know what the model would have charged.
///
/// `on_token` sees every emitted token, in order. Production passes a no-op;
/// the tests collect them.
#[cfg(all(test, feature = "write"))]
fn encode_ppmd_hybrid(
    input: &[u8],
    max_match_distance: usize,
    encoder: &mut PpmdEncoder,
    on_token: impl FnMut(PpmdEncodeToken),
) -> Result<()> {
    let reach = input.len().min(max_match_distance).min(MAX_HISTORY);
    encode_ppmd_hybrid_span(
        &mut PpmdMatchSearch::new(input, max_match_distance, reach),
        0,
        input.len(),
        encoder,
        &mut PpmdHybrid::new(),
        &mut |_, _, _| Ok(()),
        on_token,
        None,
    )
    .map(|_| ())
}

/// Called with each token's position and length before it is coded.
type Declare<'a> = &'a mut dyn FnMut(&mut PpmdEncoder, usize, usize) -> Result<()>;

/// A named filter's records in a PPMd member, each declared just ahead of its bytes.
///
/// A record is coded behind the escape symbol, as an LZ match is, so it can be
/// declared anywhere in the stream, and gives its start relative to where it
/// is declared. Declaring every record before the first byte, as this coder
/// once did, needs the whole member filtered first, and works only while the
/// reader can hold every record pending at once: our decoder takes 8192, which
/// a named filter's 120,000-byte records pass before a member is 1 GB. Declared
/// as the coder reaches it, each record is applied and dropped long before the
/// next arrives, and a member read whole codes to the bytes a streamed one does.
struct PpmdFilters {
    /// The filter's records not yet applied, in member order.
    pieces: Option<(crate::FilterKind, FilterPieces)>,
    /// Applied and waiting for the coder to reach them, in member order.
    records: std::collections::VecDeque<OwnedVmFilterRecord>,
    programs: Vec<&'static [u8]>,
}

impl PpmdFilters {
    /// `filter` cut into the records [`split_large_filter`] gives, none applied yet.
    fn new(len: usize, filter: crate::FilterSpec) -> Result<Self> {
        Ok(Self {
            pieces: Some((filter.kind, FilterPieces::new(len, &filter)?)),
            records: std::collections::VecDeque::new(),
            programs: Vec::new(),
        })
    }

    /// Records already applied to the bytes they cover, in member order.
    fn applied(records: Vec<OwnedVmFilterRecord>) -> Self {
        Self {
            pieces: None,
            records: records.into(),
            programs: Vec::new(),
        }
    }

    /// Where a read meant to stop at `end` stops instead, so no record is left half read.
    fn read_end(&self, end: usize) -> usize {
        self.pieces
            .iter()
            .flat_map(|(_, pieces)| pieces.clone())
            .find(|piece| piece.end > end)
            .filter(|piece| piece.start < end)
            .map_or(end, |piece| piece.end)
    }

    /// Applies each record whose bytes `window`, the member from `origin` on, now holds.
    fn apply(&mut self, window: &mut [u8], origin: usize) -> Result<()> {
        let held = origin + window.len();
        let Some((kind, pieces)) = &mut self.pieces else {
            return Ok(());
        };
        while let Some(piece) = pieces.clone().next().filter(|piece| piece.end <= held) {
            pieces.next();
            let piece = crate::FilterSpec::range(*kind, piece);
            // A record the decoder could not undo comes back empty, as in memory.
            let applied = filter_window(window, origin, std::slice::from_ref(&piece), None)?;
            self.records.extend(applied);
        }
        Ok(())
    }

    /// Declares each record starting in `pos..pos + len`, before the token that codes those bytes.
    fn declare(&mut self, encoder: &mut PpmdEncoder, pos: usize, len: usize) -> Result<()> {
        while let Some(record) = self.records.front() {
            if record.block_start >= pos + len {
                break;
            }
            for bytes in encoded_filter_records_at(&[record], pos, usize::MAX, &mut self.programs)?
            {
                encoder.encode_vm_filter_record(&bytes)?;
            }
            self.records.pop_front();
        }
        Ok(())
    }
}

/// Carried across spans so a streamed member decides as one coded whole would.
struct PpmdHybrid {
    costs: PpmdTokenCosts,
    search_from: usize,
    next_check: usize,
}

impl PpmdHybrid {
    fn new() -> Self {
        Self {
            costs: PpmdTokenCosts::new(),
            search_from: 0,
            next_check: 0,
        }
    }

    /// Follows a window whose start moved `by` bytes on.
    fn rebase(&mut self, by: usize) {
        self.search_from = self.search_from.saturating_sub(by);
        self.next_check = self.next_check.saturating_sub(by);
    }
}

/// Returns where it stopped, since a token that starts before `end` may finish past it.
///
/// `declare` is handed each token's position and length before the token is
/// coded, so a filter record that starts under it is declared ahead of its bytes.
#[allow(clippy::too_many_arguments)]
fn encode_ppmd_hybrid_span(
    search: &mut PpmdMatchSearch<'_>,
    mut pos: usize,
    end: usize,
    encoder: &mut PpmdEncoder,
    state: &mut PpmdHybrid,
    declare: Declare<'_>,
    mut on_token: impl FnMut(PpmdEncodeToken),
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<usize> {
    let input = search.input;
    while pos < end {
        #[cfg(all(
            feature = "parallel",
            not(all(target_arch = "wasm32", target_os = "unknown"))
        ))]
        if crate::parallel::may_nest() {
            pos = search.alongside(pos, |found, searched| {
                encode_ppmd_hybrid_run(
                    input,
                    found,
                    pos,
                    end.min(searched),
                    encoder,
                    state,
                    declare,
                    &mut on_token,
                    &mut progress,
                )
            })?;
            continue;
        }
        let stop = end.min(pos.saturating_add(search.batch));
        pos = encode_ppmd_hybrid_run(
            input,
            &mut |at| search.best(at),
            pos,
            stop,
            encoder,
            state,
            declare,
            &mut on_token,
            &mut progress,
        )?;
    }
    Ok(pos)
}

/// [`encode_ppmd_hybrid_span`] from `pos` to `end`, with `best` the escape search at a position.
#[allow(clippy::too_many_arguments)]
fn encode_ppmd_hybrid_run(
    input: &[u8],
    best: &mut dyn FnMut(usize) -> Option<(usize, usize)>,
    mut pos: usize,
    end: usize,
    encoder: &mut PpmdEncoder,
    state: &mut PpmdHybrid,
    declare: Declare<'_>,
    on_token: &mut impl FnMut(PpmdEncodeToken),
    progress: &mut Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<usize> {
    while pos < end {
        if pos >= state.next_check {
            if progress.as_mut().is_some_and(|report| !report(pos)) {
                return Err(Error::Cancelled);
            }
            state.next_check = pos.saturating_add(4096);
        }
        if let Some(length) = ppmd_offset_one_repeat(input, pos) {
            if state.costs.repeat_pays(length) {
                declare(encoder, pos, length)?;
                let before = encoder.spent_bits();
                encoder.encode_repeat_offset_one(length)?;
                state.costs.record_repeat(encoder.spent_bits() - before);
                on_token(PpmdEncodeToken::RepeatOffsetOne { length });
                pos += length;
                continue;
            }
        }

        if pos >= state.search_from {
            if let Some((length, offset)) = best(pos) {
                if state.costs.match_pays(length) {
                    declare(encoder, pos, length)?;
                    let before = encoder.spent_bits();
                    encoder.encode_match(offset, length)?;
                    state.costs.record_match(encoder.spent_bits() - before);
                    on_token(PpmdEncodeToken::Match { offset, length });
                    pos += length;
                    continue;
                }
                state.search_from = pos + PPMD_REJECT_SEARCH_COOLDOWN;
            }
        }

        declare(encoder, pos, 1)?;
        let before = encoder.spent_bits();
        encoder.encode_literal(input[pos])?;
        state.costs.record_literal(encoder.spent_bits() - before);
        on_token(PpmdEncodeToken::Literal(input[pos]));
        pos += 1;
    }
    Ok(pos)
}

fn ppmd_offset_one_repeat(input: &[u8], pos: usize) -> Option<usize> {
    if pos == 0 || input[pos] != input[pos - 1] {
        return None;
    }
    let mut length = 0usize;
    while pos + length < input.len()
        && input[pos + length] == input[pos - 1]
        && length < MAX_PPMD_REPEAT_LENGTH
    {
        length += 1;
    }
    (length >= 4).then_some(length)
}

/// Every position enters the finder whatever the model codes, so searches can run a batch ahead.
struct PpmdMatchSearch<'a> {
    input: &'a [u8],
    max_match_distance: usize,
    batch: usize,
    finder: PpmdMatchFinder,
    filled: usize,
    found_from: usize,
    found: Vec<Option<(u8, u32)>>,
    /// The half batch after `found`, searched on the pool while `found`'s is coded.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    ahead: Vec<Option<(u8, u32)>>,
}

impl<'a> PpmdMatchSearch<'a> {
    const CHUNK: usize = 16 * 1024;
    const MAX_BATCH: usize = Self::CHUNK * 16 * 2;

    /// `reach` is the member's, which a window of it can be shorter than.
    fn new(input: &'a [u8], max_match_distance: usize, reach: usize) -> Self {
        let batch = (Self::CHUNK * crate::parallel::threads() * 2).min(Self::MAX_BATCH);
        Self {
            input,
            max_match_distance,
            batch,
            // Reach plus a batch, so filling a batch only overwrites links nothing in it can reach.
            finder: PpmdMatchFinder::for_reach(reach.saturating_add(batch), reach),
            filled: 0,
            found_from: 0,
            found: Vec::new(),
            #[cfg(all(
                feature = "parallel",
                not(all(target_arch = "wasm32", target_os = "unknown"))
            ))]
            ahead: Vec::new(),
        }
    }

    /// How many positions a search alone looks ahead, so their chain walks
    /// overlap in memory. Searches the parse skips, inside a match or a
    /// rejection's cooldown, are the price; the result at each position is the
    /// one a search there alone would find.
    const LOOKAHEAD: usize = 64;

    /// `pos` must not go back.
    fn best(&mut self, pos: usize) -> Option<(usize, usize)> {
        debug_assert!(pos >= self.found_from);
        if pos >= self.filled {
            self.fill_from(pos);
        }
        if pos - self.found_from >= self.found.len() {
            self.look_ahead(pos);
        }
        self.found[pos - self.found_from]
            .map(|(length, offset)| (usize::from(length), offset as usize))
    }

    /// Searches from `pos` up to [`Self::LOOKAHEAD`] positions, within what the finder holds.
    fn look_ahead(&mut self, pos: usize) {
        let end = pos.saturating_add(Self::LOOKAHEAD).min(self.filled);
        self.found_from = pos;
        self.found.clear();
        self.found.resize(end - pos, None);
        let searched = best_ppmd_matches(
            self.input,
            pos,
            &FilledAhead(&self.finder),
            self.max_match_distance,
            &mut self.found,
            true,
        );
        self.found.truncate(searched);
    }

    /// Fills the finder a batch ahead of `pos`, so searches can run ahead of the parse.
    fn fill_from(&mut self, pos: usize) {
        let end = pos.saturating_add(self.batch).min(self.input.len());
        for history_pos in self.filled..end {
            self.finder.insert(self.input, history_pos);
        }
        self.filled = end;
        self.found_from = pos;
        self.found.clear();
    }

    /// Runs `code` from `pos` through the positions searched, handing it the
    /// search at each and where the searched positions end, while the pool
    /// searches the half batch after them. Two halves hold what one batch did.
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    fn alongside<R>(
        &mut self,
        pos: usize,
        code: impl FnOnce(&mut dyn FnMut(usize) -> Option<(usize, usize)>, usize) -> R,
    ) -> R {
        let half = self.batch / 2;
        let Self {
            input,
            max_match_distance: distance,
            finder,
            filled,
            found_from,
            found,
            ahead,
            ..
        } = self;
        let (input, distance) = (*input, *distance);
        if pos < *found_from || pos - *found_from >= found.len() {
            let end = pos.saturating_add(half).min(input.len());
            search_half(input, finder, filled, distance, pos, end, found);
            *found_from = pos;
        }
        let searched = *found_from + found.len();
        let next = searched.saturating_add(half).min(input.len());
        let (behind, behind_from) = (&*found, *found_from);
        let (finder, filled, next_found) = (&mut *finder, &mut *filled, &mut *ahead);
        let coded = rayon::in_place_scope(|scope| {
            if searched < next {
                scope.spawn(move |_| {
                    search_half(input, finder, filled, distance, searched, next, next_found);
                });
            }
            code(
                &mut |at| {
                    behind[at - behind_from]
                        .map(|(length, offset)| (usize::from(length), offset as usize))
                },
                searched,
            )
        });
        if searched < next {
            std::mem::swap(found, ahead);
            *found_from = searched;
        }
        coded
    }
}

/// Fills `finder` through `end` and searches `start..end` into `out`, a chunk per thread.
#[cfg(all(
    feature = "parallel",
    not(all(target_arch = "wasm32", target_os = "unknown"))
))]
fn search_half(
    input: &[u8],
    finder: &mut PpmdMatchFinder,
    filled: &mut usize,
    distance: usize,
    start: usize,
    end: usize,
    out: &mut Vec<Option<(u8, u32)>>,
) {
    for history_pos in *filled..end {
        finder.insert(input, history_pos);
    }
    *filled = (*filled).max(end);
    out.clear();
    out.resize(end - start, None);
    let finder = &*finder;
    let mut chunks: Vec<_> = out.chunks_mut(PpmdMatchSearch::CHUNK).collect();
    crate::parallel::for_each_mut(&mut chunks, |index, chunk| {
        let from = start + index * PpmdMatchSearch::CHUNK;
        best_ppmd_matches(input, from, &FilledAhead(finder), distance, chunk, false);
    });
}

/// The most an escape search holds: links over the reach and a batch, the heads, and a batch found.
pub(crate) fn ppmd_search_workspace(max_match_distance: usize) -> u64 {
    let batch = PpmdMatchSearch::MAX_BATCH;
    let links = max_match_distance
        .min(MAX_HISTORY)
        .saturating_add(batch)
        .next_power_of_two();
    let found = batch * std::mem::size_of::<Option<(u8, u32)>>();
    (links as u64 + (1 << 20)) * 4 + found as u64
}

/// The longest escape match at `pos`, nearest first on a tie: up to
/// [`MAX_MATCH_CANDIDATES`] of its chain's candidates, probed and measured.
#[cfg(test)]
fn best_ppmd_match(
    input: &[u8],
    pos: usize,
    finder: &impl Candidates,
    max_match_distance: usize,
) -> Option<(usize, usize)> {
    let mut walk = PpmdWalk::start(input, pos, finder, max_match_distance)?;
    while walk.step(input, finder) {}
    walk.best
}

/// [`best_ppmd_match`] at each position from `start`, one per slot of `out`.
/// Returns how many slots, from the first, hold their position's result.
///
/// A chain walk is a run of dependent loads into links and input too large
/// for the cache, so one walk at a time leaves the memory system idle. Several
/// walks stepped in turn keep that many loads in flight. Each walk takes the
/// steps it would take alone, so the results are the same.
///
/// With `until_found`, the search ends at the first position with a match:
/// the parse codes that match or cools down after it, so it searches none of
/// the next few positions, and those walked past it are dropped.
fn best_ppmd_matches(
    input: &[u8],
    start: usize,
    finder: &impl Candidates,
    max_match_distance: usize,
    out: &mut [Option<(u8, u32)>],
    until_found: bool,
) -> usize {
    const LANES: usize = 16;
    let mut lanes: [Option<PpmdWalk>; LANES] = [None; LANES];
    let (mut next, mut end) = (0, out.len());
    loop {
        let mut busy = false;
        for lane in &mut lanes {
            if let Some(walk) = lane {
                let at = walk.pos - start;
                if at >= end {
                    *lane = None;
                } else if walk.step(input, finder) {
                    busy = true;
                    continue;
                } else {
                    // An escape match is at most 255 bytes long and 4 MiB back.
                    out[at] = walk
                        .best
                        .map(|(length, offset)| (length as u8, offset as u32));
                    if until_found && walk.best.is_some() {
                        end = end.min(at + 1);
                    }
                    *lane = None;
                }
            }
            while next < end {
                let pos = start + next;
                next += 1;
                match PpmdWalk::start(input, pos, finder, max_match_distance) {
                    Some(walk) => {
                        *lane = Some(walk);
                        busy = true;
                        break;
                    }
                    None => out[pos - start] = None,
                }
            }
        }
        if !busy {
            return end;
        }
    }
}

/// One escape search part way along its chain.
#[derive(Clone, Copy)]
struct PpmdWalk {
    pos: usize,
    max_offset: usize,
    max_length: usize,
    /// The next candidate, or [`match_finder::NO_POSITION`] once the search is over.
    candidate: usize,
    checked: usize,
    best: Option<(usize, usize)>,
}

impl PpmdWalk {
    /// None where no escape match can start.
    fn start(
        input: &[u8],
        pos: usize,
        finder: &impl Candidates,
        max_match_distance: usize,
    ) -> Option<Self> {
        let max_offset = pos.min(0x1000001).min(MAX_HISTORY).min(max_match_distance);
        let max_length = (input.len() - pos).min(MAX_PPMD_MATCH_LENGTH);
        if max_offset < 2 || max_length < MIN_PPMD_MATCH_LENGTH {
            return None;
        }
        Some(Self {
            pos,
            max_offset,
            max_length,
            candidate: finder.first(input, pos, pos),
            checked: 0,
            best: None,
        })
    }

    fn stop(&mut self) -> bool {
        self.candidate = match_finder::NO_POSITION;
        false
    }

    /// Looks at one candidate; false once the search is over.
    fn step(&mut self, input: &[u8], finder: &impl Candidates) -> bool {
        let (pos, candidate) = (self.pos, self.candidate);
        if candidate == match_finder::NO_POSITION {
            return false;
        }
        // MatchFinder chains contain only previously inserted positions and
        // each link moves strictly backwards.
        let offset = pos - candidate;
        if offset > self.max_offset {
            return self.stop();
        }
        self.candidate = finder.previous(candidate);
        if offset < 2 {
            return true;
        }
        self.checked += 1;
        // Only a candidate reaching past the current best (or the minimum) can
        // win, so probe that one byte before measuring the whole match.
        let probe = self
            .best
            .map_or(MIN_PPMD_MATCH_LENGTH - 1, |(best_length, _)| best_length);
        if input[candidate + probe] == input[pos + probe] {
            let length = match_length(input, pos, offset, self.max_length);
            if length >= MIN_PPMD_MATCH_LENGTH
                && self.best.is_none_or(|(best_length, best_offset)| {
                    length > best_length || (length == best_length && offset < best_offset)
                })
            {
                self.best = Some((length, offset));
                if length == self.max_length {
                    return self.stop();
                }
            }
        }
        if self.checked >= MAX_MATCH_CANDIDATES {
            return self.stop();
        }
        true
    }
}

#[cfg(test)]
fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    finder: &Rar29MatchFinder,
    options: EncodeOptions,
    state: &EncoderMatchState,
) -> Option<MatchCandidate> {
    best_match_before(input, pos, end, pos, finder, options, state, None)
}

/// The newest position of each three-byte hash, for the matches the
/// four-byte chains cannot offer: three bytes under 8 KiB.
///
/// Only the lazy parse keeps it. The shortest-path parse finds these matches
/// its own way, and the levels that ask for it beat a lazy parse without them
/// by 4% to 7% on binaries, much of which this takes back: on a 4 MiB shared
/// object, with repeats of two and three bytes as well, the lazy parse at
/// level 3 comes out 1.45 MB against 1.51 MB, and rar 3.93 `-m3` packs
/// 1.45 MB. A greedy parse has no second look to undo a short match that costs
/// it a longer one next, so it goes without.
///
/// The exceptions are parses that walk few candidates (see
/// [`LONG_KEY_MAX_CANDIDATES`]): a lazy one keeps it at any span, and a greedy
/// one on six-byte chains, for the four- and five-byte matches those chains
/// cannot offer. A greedy one takes nothing shorter from it than its chains
/// would have.
///
/// Two-byte matches at short offsets were offered too, and dropped. The lazy
/// parse prices a literal at eight bits, so every one of them looked cheaper
/// than the two literals it replaced, and random data offers one every few
/// hundred bytes: a member of noise coded larger than stored. Over the bench
/// corpus they were worth 0.3% on the unstripped ELF and cost up to 1.3% on
/// text, and the totals came out within 0.03% of each other.
struct NearMatches {
    triples: Vec<u32>,
}

impl NearMatches {
    const EMPTY: u32 = u32::MAX;
    /// Hashed, and small, because a block parses with a table of its own and
    /// it is cleared for every one: the newest position is all it keeps, and
    /// a three-byte match reaches back only 8 KiB.
    const TRIPLE_BITS: u32 = 14;

    fn new() -> Self {
        Self {
            triples: vec![Self::EMPTY; 1 << Self::TRIPLE_BITS],
        }
    }

    fn triple(data: &[u8], pos: usize) -> usize {
        let bytes =
            u32::from(data[pos]) << 16 | u32::from(data[pos + 1]) << 8 | u32::from(data[pos + 2]);
        (bytes.wrapping_mul(2_654_435_761) >> (32 - Self::TRIPLE_BITS)) as usize
    }

    fn insert(&mut self, data: &[u8], pos: usize) {
        if pos + 3 <= data.len() {
            self.triples[Self::triple(data, pos)] = pos as u32;
        }
    }

    /// Whether a block's bytes are spread so evenly that short matches are
    /// not worth looking for: more than 7.5 bits a byte of order-0 entropy.
    ///
    /// Already-compressed data offers a three-byte match now and then and
    /// nothing longer, so every position looked one up for nothing. On a 32 MiB
    /// tar of compressed files at level 3 that cost 15% more time for 0.11%,
    /// where executables gain 2.3% for 6%.
    fn looks_random(block: &[u8]) -> bool {
        block.is_empty() || order0_entropy(block) > SKIP_RANDOM_ABOVE_BITS
    }

    /// The newest earlier position sharing `pos`'s three-byte hash.
    fn candidate(&self, data: &[u8], pos: usize) -> Option<usize> {
        if pos + 3 > data.len() {
            return None;
        }
        let slot = self.triples[Self::triple(data, pos)];
        (slot != Self::EMPTY && (slot as usize) < pos).then_some(slot as usize)
    }
}

/// Above this much order-0 entropy, in bits a byte, a block looks random
/// enough for [`EncodeOptions::skip_literal_runs`] to apply.
///
/// The threshold the near matches use. On a 32 MiB tar of already-compressed
/// files, skipping from 7.8 bits rather than 7.5 kept 0.06% more at level 2
/// for a fifth more time; waiting longer before skipping was the better knob.
const SKIP_RANDOM_ABOVE_BITS: f64 = 7.5;

/// The order-0 entropy of `block` in bits a byte, 8 for an empty one.
pub(crate) fn order0_entropy(block: &[u8]) -> f64 {
    if block.is_empty() {
        return 8.0;
    }
    let mut counts = [0u32; 256];
    for &byte in block {
        counts[usize::from(byte)] += 1;
    }
    let len = block.len() as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let p = f64::from(count) / len;
            -p * p.log2()
        })
        .sum()
}

/// The shortest match the four-byte chains offer.
const MIN_CHAIN_MATCH: usize = 4;

/// How far a three-byte fresh match reaches: past it the format adds a byte
/// to every fresh length.
const MAX_THREE_BYTE_OFFSET: usize = 0x2000 - 1;

/// From this length on, a match is not worth looking for a near one beside.
const NEAR_MATCH_LIMIT: usize = 8;

#[allow(clippy::too_many_arguments)]
fn best_match_before<C: Candidates>(
    input: &[u8],
    pos: usize,
    end: usize,
    limit: usize,
    finder: &C,
    options: EncodeOptions,
    state: &EncoderMatchState,
    near: Option<&NearMatches>,
) -> Option<MatchCandidate> {
    let max_offset = pos.min(options.max_match_distance).min(MAX_HISTORY);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0 || max_offset == 0 || max_length < 4 {
        return None;
    }
    // See `LONG_KEY_MAX_CANDIDATES` for why a greedy parse walks half.
    let walk = match !options.lazy_matching && finder.key() > MIN_CHAIN_MATCH {
        true => (options.max_match_candidates / 2).max(1),
        false => options.max_match_candidates,
    };
    let mut best = None;
    let mut checked = 0usize;
    // A match shorter than four bytes is never taken, so a candidate that
    // differs anywhere in the first four is not measured at all. On data with
    // nothing to find that is nearly every candidate: the old offsets at every
    // position, and the collisions every chain is made of.
    let prefix = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
    let shares_prefix = |candidate: usize| {
        u32::from_le_bytes(input[candidate..candidate + 4].try_into().unwrap()) == prefix
    };
    // A remembered offset codes a repeat as short as two bytes, which a lazy
    // parse keeping near matches takes where it prices in. A greedy one takes
    // near matches only as long as its chains would have offered.
    let near_min = match options.lazy_matching {
        true => 3,
        false => MIN_CHAIN_MATCH,
    };
    let min_repeat = match near {
        Some(_) if options.lazy_matching => 2,
        _ => MIN_CHAIN_MATCH,
    };
    for offset in state.old_offsets {
        if offset == 0 || offset > max_offset {
            continue;
        }
        let from = pos - offset;
        let shares = match near {
            Some(_) => input[from..from + 2] == input[pos..pos + 2],
            None => shares_prefix(from),
        };
        if !shares {
            continue;
        }
        let length = match_length(input, pos, offset, max_length);
        consider_match_candidate(&mut best, state, length, offset, min_repeat);
    }
    if let Some(best) = best {
        if best.length == max_length {
            return Some(best);
        }
    }
    let mut candidate = match max_length >= finder.key() {
        true => finder.first(input, pos, limit),
        false => match_finder::NO_POSITION,
    };
    while candidate != match_finder::NO_POSITION {
        // MatchFinder chains contain only previously inserted positions and
        // each link moves strictly backwards.
        let offset = pos - candidate;
        if offset > max_offset {
            break;
        }
        checked += 1;
        // A candidate can only improve on the current best when it matches at
        // least one byte past the best length, so probe that byte first.
        let best_length = best.map_or(0, |best: MatchCandidate| best.length);
        if input[candidate + best_length] == input[pos + best_length] && shares_prefix(candidate) {
            let length = match_length(input, pos, offset, max_length);
            consider_match_candidate(&mut best, state, length, offset, MIN_CHAIN_MATCH);
        }
        if best.is_some_and(|candidate| candidate.length == max_length) {
            break;
        }
        if checked >= walk {
            break;
        }
        candidate = finder.previous(candidate);
    }
    if let Some(near) = near.filter(|_| best.is_none_or(|best| best.length < NEAR_MATCH_LIMIT)) {
        if let Some(from) = near.candidate(input, pos) {
            let offset = pos - from;
            if offset <= max_offset
                && offset <= MAX_THREE_BYTE_OFFSET
                && input[from..from + 3] == input[pos..pos + 3]
            {
                let length = match_length(input, pos, offset, max_length);
                consider_match_candidate(&mut best, state, length, offset, near_min);
            }
        }
    }
    best
}

fn match_length(input: &[u8], pos: usize, offset: usize, max_length: usize) -> usize {
    super::super::fast::match_length(input, pos, offset, max_length)
}

fn consider_match_candidate(
    best: &mut Option<MatchCandidate>,
    state: &EncoderMatchState,
    length: usize,
    offset: usize,
    min_length: usize,
) {
    if length < min_length {
        return;
    }
    let Ok(cost) = estimated_match_cost(state, length, offset) else {
        return;
    };
    let score = (length as isize * 8) - cost as isize;
    let candidate = MatchCandidate {
        length,
        offset,
        score,
    };
    if best.is_none_or(|best| {
        candidate.score > best.score
            || (candidate.score == best.score
                && (candidate.length > best.length
                    || (candidate.length == best.length && candidate.offset < best.offset)))
    }) {
        *best = Some(candidate);
    }
}

fn estimated_match_cost(state: &EncoderMatchState, length: usize, offset: usize) -> Result<usize> {
    match state.encode_match(length, offset)? {
        EncodedMatch::LastLengthRepeat => Ok(2),
        EncodedMatch::RepeatOffset { length_slot, .. } => {
            Ok(5 + usize::from(LENGTH_BITS[length_slot]))
        }
        EncodedMatch::Short { slot, .. } => Ok(5 + usize::from(SHORT_BITS[slot])),
        EncodedMatch::Fresh {
            length_slot,
            offset_slot,
            ..
        } => {
            let low_offset_cost = usize::from(offset_slot > 9) * 4;
            Ok(8 + usize::from(LENGTH_BITS[length_slot])
                + usize::from(OFFSET_BITS[offset_slot])
                + low_offset_cost)
        }
    }
}

fn match_length_adjustment(offset: usize) -> usize {
    usize::from(offset >= 0x2000) + usize::from(offset >= 0x40000)
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 3 {
        return Err(Error::InvalidData("RAR 2.9 match length is too short"));
    }
    let adjusted = length - 3;
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData("RAR 2.9 match length is too long"))
}

fn length_slot_for_repeat_match(length: usize) -> Result<(usize, usize)> {
    if length < 2 {
        return Err(Error::InvalidData(
            "RAR 2.9 repeat match length is too short",
        ));
    }
    let adjusted = length - 2;
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData(
        "RAR 2.9 repeat match length is too long",
    ))
}

fn short_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    let adjusted = offset
        .checked_sub(1)
        .ok_or(Error::InvalidData("RAR 2.9 match offset is zero"))?;
    for (slot, &base) in SHORT_BASES.iter().enumerate() {
        if adjusted < base + (1usize << SHORT_BITS[slot]) {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData(
        "RAR 2.9 two-byte match offset is too large",
    ))
}

fn offset_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 {
        return Err(Error::InvalidData("RAR 2.9 match offset is zero"));
    }
    // Worked out rather than searched for, since the shortest-path parse asks
    // for every match it prices. Below 256 KiB two slots share each power of
    // two, split by the bit below the top one. Past that the slots are 64 KiB
    // wide up to 1 MiB, then 256 KiB wide.
    let adjusted = offset - 1;
    let slot = match adjusted {
        0..4 => adjusted,
        4..0x40000 => {
            let top = adjusted.ilog2() as usize;
            2 * top + ((adjusted >> (top - 1)) & 1)
        }
        0x40000..0x100000 => 32 + (adjusted >> 16),
        0x100000..0x400000 => 44 + (adjusted >> 18),
        _ => return Err(Error::InvalidData("RAR 2.9 match offset is too large")),
    };
    Ok((slot, adjusted - OFFSET_BASES[slot]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LevelToken {
    symbol: usize,
    extra_bits: u8,
    extra_value: u8,
}

impl LevelToken {
    const fn plain(symbol: usize) -> Self {
        Self {
            symbol,
            extra_bits: 0,
            extra_value: 0,
        }
    }

    const fn repeat_previous_short(count: usize) -> Self {
        Self {
            symbol: 16,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn repeat_previous_long(count: usize) -> Self {
        Self {
            symbol: 17,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }

    const fn zero_run_short(count: usize) -> Self {
        Self {
            symbol: 18,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_long(count: usize) -> Self {
        Self {
            symbol: 19,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }
}

fn encode_table_level_tokens(lengths: &[u8; TABLE_COUNT]) -> Vec<LevelToken> {
    encode_level_tokens_against(lengths, &[0; TABLE_COUNT])
}

/// Codes one code-length table as level tokens, against the table the reader
/// already holds.
///
/// Symbols 0 to 15 are read as a delta: the reader adds one to what it has at
/// that position, modulo 16. So a table close to the previous one spends the
/// cheap end of the alphabet, which is what the block header's keep-tables bit
/// buys. Pass a table of zeroes to code the lengths outright, which is the same
/// arithmetic with nothing to add to.
///
/// The run symbols do not take part. 16 and 17 repeat the length just decoded
/// and 18 and 19 write zeroes, both regardless of `base`, so runs are found in
/// the lengths themselves either way.
fn encode_level_tokens_against(lengths: &[u8], base: &[u8]) -> Vec<LevelToken> {
    let mut tokens = Vec::new();
    level_tokens_against(lengths, base, &mut tokens);
    tokens
}

/// What [`level_tokens_bit_cost`] says the outright coding of `lengths`
/// costs, without keeping the tokens.
fn table_level_bit_cost(lengths: &[u8; TABLE_COUNT]) -> usize {
    struct Tally {
        frequencies: [usize; LEVEL_COUNT],
        extra_bits: usize,
    }
    impl LevelTokens for Tally {
        fn push(&mut self, token: LevelToken) {
            self.frequencies[token.symbol] += 1;
            self.extra_bits += usize::from(token.extra_bits);
        }
    }
    let mut tally = Tally {
        frequencies: [0; LEVEL_COUNT],
        extra_bits: 0,
    };
    level_tokens_against(lengths, &[0; TABLE_COUNT], &mut tally);
    let lengths = level_code_lengths_for(tally.frequencies);
    tally
        .frequencies
        .iter()
        .zip(lengths)
        .map(|(&count, length)| count * usize::from(length))
        .sum::<usize>()
        + tally.extra_bits
}

/// Where level tokens go as they are found.
trait LevelTokens {
    fn push(&mut self, token: LevelToken);
}

impl LevelTokens for Vec<LevelToken> {
    fn push(&mut self, token: LevelToken) {
        Vec::push(self, token);
    }
}

fn level_tokens_against(lengths: &[u8], base: &[u8], tokens: &mut impl LevelTokens) {
    let delta = |pos: usize, value: u8| (value.wrapping_sub(base[pos]) & 0x0f) as usize;
    let mut pos = 0usize;
    let mut previous = None;
    while pos < lengths.len() {
        let value = lengths[pos];
        let mut run = 1usize;
        while pos + run < lengths.len() && lengths[pos + run] == value {
            run += 1;
        }

        if value == 0 {
            emit_zero_level_run(tokens, pos, run, &delta);
            previous = Some(0);
            pos += run;
            continue;
        }

        if previous == Some(value) && run >= 3 {
            emit_repeat_level_run(tokens, run);
            pos += run;
            continue;
        }

        tokens.push(LevelToken::plain(delta(pos, value)));
        previous = Some(value);
        pos += 1;
    }
}

/// What the level tokens cost, so two codings of a table can be compared.
///
/// The 20 four-bit code lengths at the head of the table are the same either
/// way and are left out.
fn level_tokens_bit_cost(tokens: &[LevelToken]) -> usize {
    let lengths = level_code_lengths(tokens);
    tokens
        .iter()
        .map(|token| usize::from(lengths[token.symbol]) + usize::from(token.extra_bits))
        .sum()
}

fn emit_repeat_level_run(tokens: &mut impl LevelTokens, mut run: usize) {
    while run >= 11 {
        let mut chunk = run.min(138);
        if matches!(run - chunk, 1 | 2) {
            chunk -= 3;
        }
        tokens.push(LevelToken::repeat_previous_long(chunk));
        run -= chunk;
    }
    if run >= 3 {
        tokens.push(LevelToken::repeat_previous_short(run));
    }
}

fn emit_zero_level_run(
    tokens: &mut impl LevelTokens,
    start: usize,
    mut run: usize,
    delta: &dyn Fn(usize, u8) -> usize,
) {
    let mut pos = start;
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) {
                chunk -= 3;
            }
            tokens.push(LevelToken::zero_run_long(chunk));
            run -= chunk;
            pos += chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens.push(LevelToken::zero_run_short(chunk));
            run -= chunk;
            pos += chunk;
        } else {
            // A run too short for its own symbol is written out position by
            // position, and each of those is a delta like any other.
            for pos in pos..pos + run {
                tokens.push(LevelToken::plain(delta(pos, 0)));
            }
            break;
        }
    }
}

/// Codes the level alphabet by how often each symbol is used, not by how many
/// of them appear.
///
/// A flat code charges the same for every symbol in play, so a table whose
/// tokens are mostly one symbol pays as if they were spread evenly. That is
/// what the keep-tables bit produces, and against a flat code it saved almost
/// nothing. Weighting by frequency is what makes it pay.
///
/// The 20 lengths are written four bits each, hence the cap of 15.
fn level_code_lengths(tokens: &[LevelToken]) -> [u8; LEVEL_COUNT] {
    let mut frequencies = [0usize; LEVEL_COUNT];
    for token in tokens {
        frequencies[token.symbol] += 1;
    }
    level_code_lengths_for(frequencies)
}

/// [`level_code_lengths`] from how often each level symbol is used.
fn level_code_lengths_for(frequencies: [usize; LEVEL_COUNT]) -> [u8; LEVEL_COUNT] {
    // One symbol in play gives a code with one branch and an empty slot beside
    // it, which a strict reader rejects. Only the flat assignment pads it.
    if frequencies.iter().filter(|&&count| count != 0).count() <= 1 {
        let mut lengths = [0u8; LEVEL_COUNT];
        for (symbol, &count) in frequencies.iter().enumerate() {
            lengths[symbol] = u8::from(count != 0);
        }
        huffman::assign_flat_complete_code(&mut lengths);
        return lengths;
    }
    huffman::lengths_for_frequency_array(&frequencies, 15)
}

#[derive(Debug, Clone, Copy)]
struct HuffmanCode {
    code: u16,
    len: u8,
}

// Only encoder-generated tables reach this helper; archive tables use Huffman.
fn canonical_codes(lengths: &[u8]) -> Vec<Option<HuffmanCode>> {
    debug_assert!(lengths.iter().all(|&len| len <= 15));
    let mut count = [0u16; 16];
    for &len in lengths {
        if len != 0 {
            count[len as usize] += 1;
        }
    }
    debug_assert!(validate_huffman_counts(&count).is_ok());

    let mut next_code = [0u16; 16];
    let mut code = 0u16;
    for len in 1..=15 {
        code = (code + count[len - 1]) << 1;
        next_code[len] = code;
    }

    let mut codes = vec![None; lengths.len()];
    for (symbol, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let code = next_code[len as usize];
        next_code[len as usize] += 1;
        codes[symbol] = Some(HuffmanCode { code, len });
    }
    codes
}

/// Bits written most significant first, gathered in a word and moved to the
/// bytes a word at a time.
///
/// Pushing each symbol into the bytes as it came was a quarter of the time
/// level 1 spent on a binary.
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    /// The bits not yet in `bytes`, in the low `pending` bits.
    word: u64,
    pending: u32,
}

impl BitWriter {
    fn write_bits(&mut self, value: u32, count: u8) {
        let count = u32::from(count);
        debug_assert!(count <= 32);
        if count == 0 {
            return;
        }
        let value = u64::from(value) & ((1u64 << count) - 1);
        if self.pending + count > 64 {
            self.flush_bytes();
        }
        self.word = (self.word << count) | value;
        self.pending += count;
    }

    /// Moves the whole bytes the word holds into `bytes`.
    fn flush_bytes(&mut self) {
        let whole = self.pending / 8;
        if whole == 0 {
            return;
        }
        let rest = self.pending % 8;
        let out = (self.word >> rest) << (64 - 8 * whole);
        self.bytes
            .extend_from_slice(&out.to_be_bytes()[..whole as usize]);
        self.word &= (1u64 << rest) - 1;
        self.pending = rest;
    }

    fn write_encoded_u32(&mut self, value: u32) {
        if value < 16 {
            self.write_bits(0, 2);
            self.write_bits(value, 4);
        } else if value < 256 {
            self.write_bits(1, 2);
            self.write_bits(value, 8);
        } else if value <= 0xffff {
            self.write_bits(2, 2);
            self.write_bits(value, 16);
        } else {
            self.write_bits(3, 2);
            self.write_bits(value >> 16, 16);
            self.write_bits(value & 0xffff, 16);
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.write_bits(u32::from(bit), 1);
    }

    fn finish(mut self) -> Vec<u8> {
        self.flush_bytes();
        if self.pending != 0 {
            self.bytes.push((self.word << (8 - self.pending)) as u8);
        }
        self.bytes
    }
}

/// `dec r0; jnz 0`, then the implicit `ret`: a custom program that counts the
/// register a filter record sets down to zero, two instructions a step,
/// leaving its block as it found it. Left at zero, it wraps and runs until
/// an instruction limit stops it.
#[cfg(test)]
pub(crate) const COUNTDOWN_VM_PROGRAM: &[u8] = &[0x12, 0x3a, 0x14, 0x3c];

/// Codes `data` with a filter record for `code` over each range, with the
/// registers given, so tests can build members with custom programs, which
/// the writer never emits. Ranges must be in order.
#[cfg(test)]
pub(crate) fn encode_member_with_custom_filters(
    data: &[u8],
    code: &'static [u8],
    filters: &[(std::ops::Range<usize>, u32)],
) -> Result<Vec<u8>> {
    let records: Vec<_> = filters
        .iter()
        .map(|(range, r0)| OwnedVmFilterRecord {
            block_start: range.start,
            block_size: range.len(),
            init_regs: vec![(0, *r0)],
            code,
            global_data: Vec::new(),
        })
        .collect();
    let mut levels = [0; TABLE_COUNT];
    encode_filtered_member_blocks(
        data,
        &[],
        &records,
        EncodeOptions::default(),
        &mut levels,
        None,
    )
}

#[path = "block_split.rs"]
mod block_split;
#[path = "optimal_parse.rs"]
mod optimal_parse;
pub(crate) use optimal_parse::OPTIMAL_PARSE_WORKSPACE;

// Round-trip and malformed-input tests use private encoder helpers and ancestor
// decoder state, without exposing those internals to sibling production code.
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[cfg(test)]
#[path = "vm_work_tests.rs"]
mod vm_work_tests;
