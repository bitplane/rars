//! Opt-in, bounded decision windows. Speculation never mutates committed state.
use super::*;
use crate::read_control::ReadControl;

pub(crate) const HYBRID_WINDOW: usize = 256 * 1024;
const FILTER_UNIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct HybridCodecOptions {
    pub beam_width: usize,
    pub finalists: usize,
    pub full_partitions: bool,
    pub deeper_search: bool,
    pub auto_filters: bool,
    pub max_match_candidates: usize,
    pub max_endpoints_per_run: usize,
    pub pricing_passes: usize,
}
impl Default for HybridCodecOptions {
    fn default() -> Self {
        Self {
            beam_width: 2,
            finalists: 2,
            full_partitions: true,
            deeper_search: true,
            auto_filters: false,
            max_match_candidates: 64,
            max_endpoints_per_run: 16,
            pricing_passes: 2,
        }
    }
}

/// The byte domain is owned, not authorized by a collision-prone fingerprint.
#[derive(Debug)]
pub(crate) struct HybridCodecState<B: Budget = Allowance> {
    history: Buffer<u8, B>,
    pub dictionary_size: usize,
    pub algorithm_version: u8,
    pub stream_offset: u64,
    pub member_offset: u64,
    pub reps: [usize; 4],
    pub last_length: usize,
}
impl<B: Budget> HybridCodecState<B> {
    pub(crate) fn new(
        history: &[u8],
        dictionary_size: usize,
        algorithm_version: u8,
        allowance: &B,
    ) -> Result<Self> {
        distance_size(algorithm_version)?;
        if dictionary_size == 0 || dictionary_size > u32::MAX as usize {
            return Err(Error::InvalidData("hybrid dictionary is zero"));
        }
        Ok(Self {
            history: Buffer::copied(
                &history[history.len().saturating_sub(dictionary_size)..],
                allowance,
            )?,
            dictionary_size,
            algorithm_version,
            stream_offset: history.len() as u64,
            member_offset: 0,
            reps: [0; 4],
            last_length: 0,
        })
    }
    pub(crate) fn history(&self) -> &[u8] {
        &self.history
    }
    pub(crate) fn begin_member(&mut self) {
        self.member_offset = 0;
    }
    fn matches(&self) -> EncoderMatchState {
        EncoderMatchState {
            reps: self.reps,
            last_length: self.last_length,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HybridWork {
    pub screened: u64,
    pub finalists: u64,
    pub cache_builds: u64,
    pub price_passes: u64,
    pub endpoint_prices: u64,
    pub lookahead_bytes: u64,
    pub blocks: u64,
    pub collector_searches: u64,
    pub greedy_searches: u64,
    pub chain_candidates: u64,
    pub seeded_positions: u64,
    pub truncated_caches: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatchCacheQuality {
    pub block_start: usize,
    pub block_end: usize,
    pub dictionary_size: usize,
    pub max_visits: usize,
    pub nice_threshold: usize,
    pub seeded_chain: bool,
    /// NICE-covered origins are absent, not certified match-free.
    pub every_position: bool,
    pub run_cap: usize,
    pub truncated: bool,
    pub nearest_prefix_then_longest: bool,
}
#[derive(Debug)]
pub(crate) struct HybridPartition<B: Budget = Allowance> {
    pub bytes: Buffer<u8, B>,
    pub end_state: HybridCodecState<B>,
    pub history_append: Buffer<u8, B>,
    pub work: HybridWork,
    pub partition_id: usize,
    pub representation_id: usize,
    pub next_cost: usize,
    pub cache_quality: Buffer<MatchCacheQuality, B>,
}

fn check(control: &ReadControl, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err(Error::Cancelled);
    }
    control.check_codec()
}
fn collector_with_control<B: Budget>(
    combined: &[u8],
    start: usize,
    options: EncodeOptions,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<OptimalCollector<B>> {
    check(control, cancelled)?;
    let finder = if start == 0 {
        CollectorFinder::Tree(match_finder::TreeMatchFinder::with_allowance(
            finder_window(options, combined.len()),
            allowance,
        )?)
    } else {
        let mut finder =
            Rar50MatchFinder::with_allowance(finder_window(options, combined.len()), allowance)?;
        for pos in 0..start {
            if pos % 4096 == 0 {
                check(control, cancelled)?;
            }
            finder.insert(combined, pos);
        }
        work.seeded_positions += start as u64;
        CollectorFinder::Chains(finder)
    };
    Ok(OptimalCollector { finder })
}
impl<B: Budget> OptimalCollector<B> {
    #[allow(clippy::too_many_arguments)]
    fn collect_hybrid(
        &mut self,
        combined: &[u8],
        block: std::ops::Range<usize>,
        options: EncodeOptions,
        control: &ReadControl,
        cancelled: &dyn Fn() -> bool,
        cap: usize,
        work: &mut HybridWork,
    ) -> Result<(BlockMatches<B>, bool)> {
        let allowance = match &self.finder {
            CollectorFinder::Tree(finder) => finder.allowance(),
            CollectorFinder::Chains(finder) => finder.allowance(),
        };
        let span = block.end - block.start;
        let mut truncated = false;
        let mut matches = BlockMatches {
            // One run per position to start with, which is where data that
            // matches at all lands, so the common case grows this once.
            runs: Buffer::with_capacity(span, &allowance)?,
            starts: Buffer::with_capacity(span + 1, &allowance)?,
        };
        // The first position past a match the parse will commit to. The parse
        // reaches the same decision from the same lengths, so the two agree on
        // which positions matter without having to be told.
        let mut committed_through = block.start;
        for pos in block.clone() {
            if pos % 64 == 0 {
                check(control, cancelled)?;
            }
            matches.starts.push_admitted(matches.runs.len() as u32);
            let searching = pos >= committed_through && options.max_match_candidates != 0;
            work.collector_searches += u64::from(searching);
            let max_distance = pos.min(options.max_match_distance);
            let before = matches.runs.len();
            match &mut self.finder {
                CollectorFinder::Tree(tree) => {
                    // Inserting into a tree is the same descent as searching
                    // it, so a position the parse steps over is stepped over
                    // here too rather than inserted for nothing. Its bytes are
                    // a copy of what the match already points at, so the tree
                    // loses little by not holding them.
                    let avail = combined.len() - pos;
                    if !searching || avail < 4 {
                        continue;
                    }
                    // Compares stop where the parse stops caring about better
                    // alternatives. A match that reaches that far is measured
                    // out to its real end, which is the length the parse
                    // commits to and steps over.
                    let len_limit = avail.min(NICE_MATCH_LENGTH);
                    tree.matches(
                        combined,
                        pos,
                        len_limit,
                        max_distance,
                        options.max_match_candidates,
                        &mut matches.runs,
                    )
                    .map_err(Into::into)?;
                    if let Some(last) = matches.runs[before..].last_mut() {
                        let limit = avail.min(MAX_ENCODER_MATCH_LENGTH);
                        if last.0 as usize == len_limit && len_limit < limit {
                            last.0 = match_length(combined, pos, last.1 as usize, limit) as u32;
                        }
                    }
                }
                CollectorFinder::Chains(finder) => {
                    // Inserting into a chain is one store, so every position
                    // goes in whether or not it is searched from. That keeps a
                    // solid member's candidates exactly what they were.
                    finder.insert(combined, pos);
                    let max_length = (block.end - pos).min(MAX_ENCODER_MATCH_LENGTH);
                    if !searching || max_distance == 0 || max_length < 4 {
                        continue;
                    }
                    // The chain walks nearest first, so the first distance to
                    // reach a length is the cheapest one that can.
                    let mut longest = 0usize;
                    let mut checked = 0usize;
                    let mut candidate = finder.first(combined, pos);
                    while candidate != match_finder::NO_POSITION
                        && longest < max_length
                        && longest < NICE_MATCH_LENGTH
                    {
                        if candidate >= pos {
                            candidate = finder.previous(candidate);
                            continue;
                        }
                        let distance = pos - candidate;
                        if distance > max_distance {
                            break;
                        }
                        checked += 1;
                        work.chain_candidates += 1;
                        if combined[candidate + longest] == combined[pos + longest] {
                            let length = match_length(combined, pos, distance, max_length);
                            if length > longest {
                                matches
                                    .runs
                                    .push((length as u32, distance as u32))
                                    .map_err(Into::into)?;
                                longest = length;
                            }
                        }
                        if checked >= options.max_match_candidates {
                            break;
                        }
                        candidate = finder.previous(candidate);
                    }
                }
            }
            if matches.runs.len() - before > cap {
                let last = *matches.runs.last().unwrap();
                matches.runs.truncate(before + cap - 1);
                matches.runs.push(last).map_err(Into::into)?;
                truncated = true;
            }
            // The parse can only take a match the block still has room for, so
            // the reach it will commit to is measured the way it measures it.
            if let Some(&(length, _)) = matches.runs[before..].last() {
                let reach = (length as usize)
                    .min(block.end - pos)
                    .min(MAX_ENCODER_MATCH_LENGTH);
                if reach >= NICE_MATCH_LENGTH {
                    committed_through = pos + reach;
                }
            }
        }
        matches.starts.push_admitted(matches.runs.len() as u32);
        Ok((matches, truncated))
    }
}

fn distance_size(version: u8) -> Result<usize> {
    match version {
        0 => Ok(DISTANCE_TABLE_SIZE_50),
        1 => Ok(DISTANCE_TABLE_SIZE_70),
        _ => Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}
fn validate(config: HybridCodecOptions) -> Result<()> {
    if !matches!(config.beam_width, 1 | 2 | 8)
        || !matches!(config.finalists, 1 | 2 | 4)
        || !(1..=16).contains(&config.max_endpoints_per_run)
        || !(1..=3).contains(&config.pricing_passes)
        || config.max_match_candidates > 1024
    {
        return Err(Error::InvalidData("invalid hybrid codec options"));
    }
    Ok(())
}

/// Partition IDs are stable: 256;128+128;64x4;192+64 (server only).
fn boundaries(length: usize, id: usize) -> ([usize; 4], usize) {
    let nominal: &[usize] = match id {
        0 => &[HYBRID_WINDOW],
        1 => &[128 * 1024, HYBRID_WINDOW],
        2 => &[64 * 1024, 128 * 1024, 192 * 1024, HYBRID_WINDOW],
        _ => &[192 * 1024, HYBRID_WINDOW],
    };
    let mut out = [0; 4];
    let mut count = 0;
    for &end in nominal {
        let end = end.min(length);
        if count == 0 || out[count - 1] != end {
            out[count] = end;
            count += 1;
        }
        if end == length {
            break;
        }
    }
    (out, count)
}
fn representation(id: usize) -> Option<crate::FilterKind> {
    match id {
        0 => None,
        1 => Some(crate::FilterKind::E8E9),
        2 => Some(crate::FilterKind::Arm),
        3 => Some(crate::FilterKind::Delta { channels: 1 }),
        4 => Some(crate::FilterKind::Delta { channels: 2 }),
        _ => Some(crate::FilterKind::Delta { channels: 4 }),
    }
}

struct Domain<B: Budget> {
    bytes: Buffer<u8, B>,
    records: Buffer<EncodeFilter, B>,
}
fn make_domain<B: Budget>(
    input: &[u8],
    member_offset: u64,
    mandatory: &[crate::FilterSpec],
    auto: Option<crate::FilterKind>,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
) -> Result<Domain<B>> {
    check(control, cancelled)?;
    let mut bytes = Buffer::copied(input, allowance)?;
    let mut records = Buffer::new(allowance);
    if member_offset > usize::MAX as u64 {
        return Err(Error::InvalidData("hybrid member offset overflows"));
    }
    let base = member_offset as usize;
    let limit = base
        .checked_add(input.len())
        .ok_or(Error::InvalidData("hybrid member range overflows"))?;
    let apply = |spec: &crate::FilterSpec,
                 bytes: &mut Buffer<u8, B>,
                 records: &mut Buffer<EncodeFilter, B>|
     -> Result<()> {
        let kind = rar50_filter(spec.kind)?;
        let absolute = spec.range.clone().unwrap_or(base..limit);
        if absolute.start >= absolute.end {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        for unit in (0..input.len()).step_by(FILTER_UNIT) {
            check(control, cancelled)?;
            let lo = absolute.start.max(base + unit);
            let hi = absolute
                .end
                .min(base + (unit + FILTER_UNIT).min(input.len()));
            if lo >= hi {
                continue;
            }
            let (filter_type, channels) =
                encode_filter_data(kind, &mut bytes[lo - base..hi - base], lo, allowance)?;
            records
                .push(EncodeFilter {
                    offset: lo - base,
                    length: hi - lo,
                    filter_type,
                    channels,
                })
                .map_err(Into::into)?;
        }
        Ok(())
    };
    if let Some(kind) = auto {
        apply(&crate::FilterSpec::whole(kind), &mut bytes, &mut records)?;
    }
    // The decoder executes announced filters in order. Compose their inverse
    // transforms in reverse order while preserving the original commands.
    for spec in mandatory.iter().rev() {
        let mut current_records = Buffer::new(allowance);
        apply(spec, &mut bytes, &mut current_records)?;
        records.prepend(current_records.iter().copied())?;
    }
    Ok(Domain { bytes, records })
}

fn history_after<B: Budget>(
    history: &[u8],
    append: &[u8],
    dictionary: usize,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let incoming = &append[append.len().saturating_sub(dictionary)..];
    let keep = history.len().min(dictionary - incoming.len());
    Buffer::from_slices(&[&history[history.len() - keep..], incoming], allowance)
}

#[derive(Clone, Copy, Debug)]
struct Node {
    price: u32,
    previous: u32,
    length: u32,
    distance: u32,
    reps: [u32; 4],
    last: u32,
}
impl Node {
    const EMPTY: Self = Self {
        price: u32::MAX,
        previous: 0,
        length: 0,
        distance: 0,
        reps: [0; 4],
        last: 0,
    };
    fn state(self) -> EncoderMatchState {
        EncoderMatchState {
            reps: self.reps.map(|x| x as usize),
            last_length: self.last as usize,
        }
    }
}
fn offer(nodes: &mut [Node], width: usize, target: usize, candidate: Node) {
    let slots = &mut nodes[target * width..(target + 1) * width];
    if let Some(at) = slots.iter().position(|old| {
        old.price != u32::MAX && old.reps == candidate.reps && old.last == candidate.last
    }) {
        if candidate.price >= slots[at].price {
            return;
        }
        slots[at] = candidate;
    } else {
        if candidate.price >= slots[width - 1].price {
            return;
        }
        slots[width - 1] = candidate;
    }
    // Stable insertion order is the deterministic tie rule.
    for at in (1..width).rev() {
        if slots[at].price < slots[at - 1].price {
            slots.swap(at, at - 1);
        }
    }
}
fn endpoints(start: usize, end: usize, last: usize, limit: usize) -> ([usize; 16], usize) {
    let mut out = [0; 16];
    let mut count = 0;
    // The full reach and an exact last-length token always get a chance.
    for length in [
        end, last, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,
    ] {
        if length >= start && length <= end && !out[..count].contains(&length) && count < limit {
            out[count] = length;
            count += 1;
        }
    }
    out[..count].sort_unstable();
    (out, count)
}

#[allow(clippy::too_many_arguments)]
fn beam_tokens<B: Budget>(
    combined: &[u8],
    block: Range<usize>,
    matches: &BlockMatches<B>,
    initial: EncoderMatchState,
    config: HybridCodecOptions,
    size: usize,
    prices: Option<&TokenPrices<'_>>,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Buffer<EncodeToken, B>> {
    let span = block.len();
    let width = config.beam_width;
    let count = (span + 1)
        .checked_mul(width)
        .ok_or(Error::InvalidData("hybrid beam size overflows"))?;
    let mut nodes = Buffer::filled(count, Node::EMPTY, allowance)?;
    nodes[0] = Node {
        price: 0,
        reps: initial.reps.map(|x| x as u32),
        last: initial.last_length as u32,
        ..Node::EMPTY
    };
    for pos in 0..span {
        if pos % 1024 == 0 {
            check(control, cancelled)?;
        }
        for lane in 0..width {
            let index = pos * width + lane;
            let origin = nodes[index];
            if origin.price == u32::MAX {
                continue;
            }
            let state = origin.state();
            let literal = prices.map_or(ESTIMATED_LITERAL_COST, |p| {
                p.literal(combined[block.start + pos]) as u32
            });
            offer(
                &mut nodes,
                width,
                pos + 1,
                Node {
                    price: origin.price.saturating_add(literal),
                    previous: index as u32,
                    length: 0,
                    distance: 0,
                    ..origin
                },
            );
            if config.max_match_candidates == 0 {
                continue;
            }
            let at = block.start + pos;
            let max = (span - pos).min(MAX_ENCODER_MATCH_LENGTH);
            let mut price_run =
                |run_start: usize, run_end: usize, distance: usize, nodes: &mut [Node]| {
                    let (lengths, n) = endpoints(
                        run_start.max(4),
                        run_end,
                        state.last_length,
                        config.max_endpoints_per_run,
                    );
                    for &length in &lengths[..n] {
                        work.endpoint_prices += 1;
                        let cost = match prices {
                            Some(p) => p.match_cost(&state, length, distance, size),
                            None => estimated_match_cost(&state, length, distance, size),
                        };
                        if let Ok(cost) = cost {
                            let mut next = state;
                            next.remember(length, distance);
                            offer(
                                nodes,
                                width,
                                pos + length,
                                Node {
                                    price: origin.price.saturating_add(cost as u32),
                                    previous: index as u32,
                                    length: length as u32,
                                    distance: distance as u32,
                                    reps: next.reps.map(|x| x as u32),
                                    last: next.last_length as u32,
                                },
                            );
                        }
                    }
                };
            for distance in state.reps {
                if distance > 0 && distance <= at && distance <= combined.len() {
                    let len = match_length(combined, at, distance, max);
                    if len >= 4 {
                        price_run(4, len, distance, &mut nodes);
                    }
                }
            }
            let mut longest = 0;
            for &(length, distance) in
                &matches.runs[matches.starts[pos] as usize..matches.starts[pos + 1] as usize]
            {
                let length = (length as usize).min(max);
                if length > longest {
                    price_run(longest + 1, length, distance as usize, &mut nodes);
                    longest = length;
                }
            }
        }
    }
    let mut out = Buffer::new(allowance);
    let mut at = span * width;
    if nodes[at].price == u32::MAX {
        return Err(Error::InvalidData("hybrid beam has no complete path"));
    }
    while at != 0 {
        let node = nodes[at];
        let target = at / width;
        let token = if node.length == 0 {
            EncodeToken::Literal(combined[block.start + target - 1])
        } else {
            EncodeToken::Match {
                length: node.length as usize,
                distance: node.distance as usize,
            }
        };
        out.push(token).map_err(Into::into)?;
        at = node.previous as usize;
    }
    out.reverse();
    Ok(out)
}
#[allow(clippy::too_many_arguments)]
fn greedy_tokens<B: Budget>(
    combined: &[u8],
    block: Range<usize>,
    initial: EncoderMatchState,
    options: EncodeOptions,
    size: usize,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Buffer<EncodeToken, B>> {
    let behind = block.start.min(options.max_match_distance);
    let mut finder =
        Rar50MatchFinder::with_allowance(finder_window(options, combined.len()), allowance)?;
    for pos in block.start - behind..block.start {
        if pos % 4096 == 0 {
            check(control, cancelled)?;
        }
        finder.insert(combined, pos);
    }
    work.seeded_positions += behind as u64;
    let mut tokens = Buffer::new(allowance);
    let mut state = initial;
    let mut pos = block.start;
    while pos < block.end {
        check(control, cancelled)?;
        work.greedy_searches += 1;
        if let Some(candidate) =
            best_match(combined, pos, block.end, &finder, options, &state, size)
        {
            tokens
                .push(EncodeToken::Match {
                    length: candidate.length,
                    distance: candidate.distance,
                })
                .map_err(Into::into)?;
            state.remember(candidate.length, candidate.distance);
            for index in pos..pos + candidate.length {
                finder.insert(combined, index);
            }
            pos += candidate.length;
        } else {
            tokens
                .push(EncodeToken::Literal(combined[pos]))
                .map_err(Into::into)?;
            finder.insert(combined, pos);
            pos += 1;
        }
    }
    Ok(tokens)
}

struct Encoded<B: Budget> {
    bytes: Buffer<u8, B>,
    state: EncoderMatchState,
    history: Buffer<u8, B>,
    quality: Buffer<MatchCacheQuality, B>,
}
#[allow(clippy::too_many_arguments)]
fn encode_domain<B: Budget>(
    domain: &Domain<B>,
    history: &[u8],
    initial: EncoderMatchState,
    version: u8,
    dictionary: usize,
    partition: usize,
    config: HybridCodecOptions,
    cheap: bool,
    is_last: bool,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Encoded<B>> {
    let combined = Buffer::from_slices(&[history, &domain.bytes], allowance)?;
    let start = history.len();
    let size = distance_size(version)?;
    let visits = if cheap {
        config.max_match_candidates.min(16)
    } else if config.deeper_search {
        config.max_match_candidates
    } else {
        config.max_match_candidates.min(16)
    };
    let options = EncodeOptions::new(visits).with_max_match_distance(dictionary);
    let (ends, count) = boundaries(domain.bytes.len(), partition);
    let mut begin = 0;
    let mut state = initial;
    let mut bytes = Buffer::new(allowance);
    let mut quality = Buffer::new(allowance);
    for (number, &end) in ends[..count].iter().enumerate() {
        check(control, cancelled)?;
        let block = start + begin..start + end;
        let mut tokens = if cheap {
            greedy_tokens(
                &combined,
                block.clone(),
                state,
                options,
                size,
                allowance,
                control,
                cancelled,
                work,
            )?
        } else {
            let mut collector = collector_with_control(
                &combined,
                block.start,
                options,
                allowance,
                control,
                cancelled,
                work,
            )?;
            let cap = if config.finalists == 4 { 64 } else { 16 };
            let (matches, truncated) = collector.collect_hybrid(
                &combined,
                block.clone(),
                options,
                control,
                cancelled,
                cap,
                work,
            )?;
            work.cache_builds += 1;
            work.truncated_caches += u64::from(truncated);
            quality
                .push(MatchCacheQuality {
                    block_start: block.start,
                    block_end: block.end,
                    dictionary_size: dictionary,
                    max_visits: visits,
                    nice_threshold: NICE_MATCH_LENGTH,
                    seeded_chain: block.start != 0,
                    every_position: false,
                    run_cap: cap,
                    truncated,
                    nearest_prefix_then_longest: true,
                })
                .map_err(Into::into)?;
            let mut best = beam_tokens(
                &combined,
                block.clone(),
                &matches,
                state,
                config,
                size,
                None,
                allowance,
                control,
                cancelled,
                work,
            )?;
            work.price_passes += 1;
            let mut best_bytes =
                encode_token_block_with_state(&best, version, size, false, allowance, state)?
                    .0
                    .len();
            for _ in 1..config.pricing_passes {
                let lengths = table_lengths_with_state(&best, &[], size, allowance, state)?;
                let prices = TokenPrices {
                    lengths: lengths.slices(),
                };
                let next = beam_tokens(
                    &combined,
                    block.clone(),
                    &matches,
                    state,
                    config,
                    size,
                    Some(&prices),
                    allowance,
                    control,
                    cancelled,
                    work,
                )?;
                work.price_passes += 1;
                let next_bytes =
                    encode_token_block_with_state(&next, version, size, false, allowance, state)?
                        .0
                        .len();
                if next_bytes < best_bytes {
                    best = next;
                    best_bytes = next_bytes;
                } else {
                    break;
                }
            }
            best
        };
        let mut records = Buffer::new(allowance);
        for record in domain.records.iter() {
            if record.offset >= begin && record.offset < end {
                if record.offset + record.length > end {
                    return Err(Error::InvalidData(
                        "hybrid partition splits a mandatory filter unit",
                    ));
                }
                records
                    .push(EncodeFilter {
                        offset: record.offset - begin,
                        ..*record
                    })
                    .map_err(Into::into)?;
            }
        }
        tokens.prepend(records.iter().copied().map(EncodeToken::Filter))?;
        let (packed, next) = encode_token_block_with_state(
            &tokens,
            version,
            size,
            is_last && number + 1 == count,
            allowance,
            state,
        )?;
        bytes.extend_from_slice(&packed).map_err(Into::into)?;
        state = next;
        work.blocks += 1;
        begin = end;
    }
    Ok(Encoded {
        bytes,
        state,
        history: history_after(history, &domain.bytes, dictionary, allowance)?,
        quality,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct Candidate {
    score: usize,
    representation: usize,
    partition: usize,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_partition<B: Budget>(
    input: &[u8],
    lookahead: &[u8],
    start: &HybridCodecState<B>,
    config: HybridCodecOptions,
    mandatory_filters: &[crate::FilterSpec],
    is_last: bool,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<HybridPartition<B>> {
    check(control, cancelled)?;
    validate(config)?;
    if input.len() > HYBRID_WINDOW
        || lookahead.len() > HYBRID_WINDOW
        || (!is_last && input.len() != HYBRID_WINDOW)
        || (is_last && !lookahead.is_empty())
    {
        return Err(Error::InvalidData("hybrid decision window is incomplete"));
    }
    if start.history.len() > start.dictionary_size
        || start.dictionary_size == 0
        || start.reps.iter().any(|&d| d > start.dictionary_size)
        || start.last_length > MAX_ENCODER_MATCH_LENGTH
    {
        return Err(Error::InvalidData(
            "hybrid start state is outside its dictionary domain",
        ));
    }
    distance_size(start.algorithm_version)?;
    let next_offset = start
        .member_offset
        .checked_add(input.len() as u64)
        .ok_or(Error::InvalidData("hybrid member offset overflows"))?;
    let end_offset = start
        .stream_offset
        .checked_add(input.len() as u64)
        .ok_or(Error::InvalidData("hybrid stream offset overflows"))?;
    let mut work = HybridWork::default();
    let mut selected = [Candidate::default(); 4];
    let mut selected_len = 0;
    let representations = if config.auto_filters && mandatory_filters.is_empty() {
        config.finalists.min(4)
    } else {
        1
    };
    let partitions = if config.full_partitions {
        if config.finalists == 4 {
            4
        } else {
            3
        }
    } else {
        1
    };
    for representation_id in 0..representations {
        let domain = make_domain(
            input,
            start.member_offset,
            mandatory_filters,
            representation(representation_id),
            allowance,
            control,
            cancelled,
        )?;
        let mut seen_partitions = [([0usize; 4], 0usize); 4];
        let mut seen_count = 0;
        for partition_id in 0..partitions {
            let current = boundaries(input.len(), partition_id);
            if seen_partitions[..seen_count].contains(&current) {
                continue;
            }
            seen_partitions[seen_count] = current;
            seen_count += 1;
            let trial = encode_domain(
                &domain,
                start.history(),
                start.matches(),
                start.algorithm_version,
                start.dictionary_size,
                partition_id,
                config,
                true,
                is_last,
                allowance,
                control,
                cancelled,
                &mut work,
            )?;
            work.screened += 1;
            let candidate = Candidate {
                score: trial.bytes.len(),
                representation: representation_id,
                partition: partition_id,
            };
            let at = selected[..selected_len]
                .iter()
                .position(|old| {
                    (
                        candidate.score,
                        candidate.representation,
                        candidate.partition,
                    ) < (old.score, old.representation, old.partition)
                })
                .unwrap_or(selected_len);
            if at < config.finalists {
                let upper = selected_len.min(config.finalists - 1);
                for index in (at..upper).rev() {
                    selected[index + 1] = selected[index];
                }
                selected[at] = candidate;
                selected_len = (selected_len + 1).min(config.finalists);
            }
        }
    }
    let mut best: Option<(usize, usize, HybridPartition<B>)> = None;
    for (rank, candidate) in selected[..selected_len].iter().enumerate() {
        check(control, cancelled)?;
        let domain = make_domain(
            input,
            start.member_offset,
            mandatory_filters,
            representation(candidate.representation),
            allowance,
            control,
            cancelled,
        )?;
        let current = encode_domain(
            &domain,
            start.history(),
            start.matches(),
            start.algorithm_version,
            start.dictionary_size,
            candidate.partition,
            config,
            false,
            is_last,
            allowance,
            control,
            cancelled,
            &mut work,
        )?;
        let next_cost = if lookahead.is_empty() {
            0
        } else {
            // Every finalist sees the same next bytes, mandatory filters and
            // cheap policy. Only its real end dictionary/repeat state varies.
            let next_domain = make_domain(
                lookahead,
                next_offset,
                mandatory_filters,
                None,
                allowance,
                control,
                cancelled,
            )?;
            work.lookahead_bytes += lookahead.len() as u64;
            encode_domain(
                &next_domain,
                &current.history,
                current.state,
                start.algorithm_version,
                start.dictionary_size,
                0,
                config,
                true,
                true,
                allowance,
                control,
                cancelled,
                &mut work,
            )?
            .bytes
            .len()
        };
        work.finalists += 1;
        let score = current
            .bytes
            .len()
            .checked_add(next_cost)
            .ok_or(Error::InvalidData("hybrid candidate size overflows"))?;
        if best
            .as_ref()
            .is_none_or(|(old, old_rank, _)| (score, rank) < (*old, *old_rank))
        {
            let end_state = HybridCodecState {
                history: current.history,
                dictionary_size: start.dictionary_size,
                algorithm_version: start.algorithm_version,
                stream_offset: end_offset,
                member_offset: next_offset,
                reps: current.state.reps,
                last_length: current.state.last_length,
            };
            best = Some((
                score,
                rank,
                HybridPartition {
                    bytes: current.bytes,
                    end_state,
                    history_append: domain.bytes,
                    work: HybridWork::default(),
                    partition_id: candidate.partition,
                    representation_id: candidate.representation,
                    next_cost,
                    cache_quality: current.quality,
                },
            ));
        }
    }
    check(control, cancelled)?;
    if progress.is_some_and(|report| !report(input.len())) {
        return Err(Error::Cancelled);
    }
    let mut result = best
        .ok_or(Error::InvalidData("hybrid has no complete finalist"))?
        .2;
    result.work = work;
    Ok(result)
}

#[cfg(test)]
#[path = "hybrid_encoder_tests.rs"]
mod tests;
