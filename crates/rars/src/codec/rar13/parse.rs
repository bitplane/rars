//! A priced parse for the RAR 1.3 encoder: the cheapest path of literals and
//! matches through the next [`PLAN_SPAN`] bytes, with every token priced from
//! the adaptive tables as they stand where the span starts.
//!
//! The tables move as tokens are coded, so the prices drift over a span. The
//! remembered distances do not: each step of the search carries the distances
//! its own path leaves behind, so a planned repeat or old-distance match is
//! one the decoder will have when it gets there.
use super::*;
use std::collections::VecDeque;

/// Prices are in sixteenths of a bit.
const BIT: u32 = 16;

/// Bytes one plan looks at. Only its steps that start more than a longest
/// match before its end are kept; the next plan starts where they stop.
///
/// A plan made anywhere in a flags group of a window that does not reach the
/// end of the member stays inside the window: the group starts more than
/// [`LOOKAHEAD`] from its end and covers at most nine tokens of 258 bytes, so
/// a plan of this size still ends short of it.
const PLAN_SPAN: usize = 1024;
const _: () = assert!(9 * 258 + PLAN_SPAN <= LOOKAHEAD);

/// A flag bit costs itself and about another bit of the adaptively coded
/// flags byte it goes in.
const FLAG_BIT: u32 = 2 * BIT;

/// Matches are tried at every length up to this. Longer ones are tried only at
/// their full length.
const ALL_LENGTHS_UP_TO: usize = 48;

/// A match at least this long is taken whole: no path starts inside it.
const TAKEN_WHOLE: usize = 64;

const UNPRICED: u32 = u32::MAX;

/// The steps of the parse not yet coded, starting at member position `at`.
/// `None` is a literal.
#[derive(Debug)]
pub(super) struct Plan {
    at: usize,
    /// Each step, with its price.
    steps: VecDeque<(Option<MatchToken>, u32)>,
    /// What each literal and the stmode escape cost when the plan was made.
    literal: [u32; 256],
    escape: u32,
    /// The search's working space, kept for the next plan.
    nodes: Vec<Node>,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            at: 0,
            steps: VecDeque::new(),
            literal: [0; 256],
            escape: 0,
            nodes: Vec::new(),
        }
    }
}

impl Plan {
    /// Moves past the step at the front, once it has been coded.
    pub(super) fn consume(&mut self) {
        if let Some((step, _)) = self.steps.pop_front() {
            self.at += step.map_or(1, |token| token.length() as usize);
        }
    }
}

/// What each token costs, from the encoder's tables where a plan starts.
struct Prices {
    literal: [u32; 256],
    literal_flag: u32,
    long_flag: u32,
    /// By distance minus one.
    short_distance: [u32; 256],
    /// By distance bits 7 to 14, the part the adaptive table codes.
    long_distance: [u32; 256],
    long_length: [u32; 256],
    old_length: [u32; 256],
    prefix: [u32; 14],
    max_dist3: u32,
    escape: u32,
}

impl Prices {
    fn new(encoder: &Unpack15Encoder) -> Self {
        let mut literal = [UNPRICED; 256];
        let (start, dec, pos) = literal_codebook(encoder.avr_plc);
        for (place, &value) in encoder.ch_set.iter().enumerate() {
            literal[usize::from(value >> 8)] =
                price(decode_num_bit_cost(place as u32, start, dec, pos));
        }
        let mut short_distance = [UNPRICED; 256];
        for (place, &value) in encoder.ch_set_a.iter().enumerate() {
            short_distance[usize::from(value)] =
                price(decode_num_bit_cost(place as u32, 5, DEC_HF2, POS_HF2));
        }
        let mut long_distance = [UNPRICED; 256];
        for (place, &value) in encoder.ch_set_b.iter().enumerate() {
            long_distance[usize::from(value >> 8)] =
                (encoder.long_lz_distance_bit_cost(place) as u32 + 7) * BIT;
        }
        let long_length =
            std::array::from_fn(|code| encoder.long_lz_length_bit_cost(code as u32) as u32 * BIT);
        let old_length =
            std::array::from_fn(|code| price(decode_num_bit_cost(code as u32, 2, DEC_L1, POS_L1)));
        let prefix =
            std::array::from_fn(|code| encoder.short_lz_prefix_bit_cost(code as u32) as u32 * BIT);
        let huff_on_one = encoder.nlzb <= encoder.nhfb;
        Self {
            literal,
            literal_flag: huff_flag_bits(huff_on_one).len() as u32 * FLAG_BIT,
            long_flag: long_lz_flag_bits(encoder.nlzb > encoder.nhfb).len() as u32 * FLAG_BIT,
            short_distance,
            long_distance,
            long_length,
            old_length,
            prefix,
            max_dist3: encoder.max_dist3,
            escape: price(decode_num_bit_cost(0, start, dec, pos)),
        }
    }
}

fn price(bits: Option<usize>) -> u32 {
    bits.map_or(UNPRICED, |bits| bits as u32 * BIT)
}

/// The literal codebook the decoder picks for `avr_plc`.
pub(super) fn literal_codebook(avr_plc: u32) -> (u32, &'static [u16], &'static [u16]) {
    if avr_plc > 0x75ff {
        (8, DEC_HF4, POS_HF4)
    } else if avr_plc > 0x5dff {
        (6, DEC_HF3, POS_HF3)
    } else if avr_plc > 0x35ff {
        (5, DEC_HF2, POS_HF2)
    } else if avr_plc > 0x0dff {
        (5, DEC_HF1, POS_HF1)
    } else {
        (4, DEC_HF0, POS_HF0)
    }
}

/// The cheapest way found to a position, and the distances it remembers.
#[derive(Clone, Copy, Debug)]
struct Node {
    cost: u32,
    /// The step that ends here, and how many bytes it covers.
    step: Option<MatchToken>,
    len: u16,
    old_dist: [u32; 4],
    old_dist_ptr: u8,
    last_dist: u32,
    last_length: u32,
}

const UNREACHED: Node = Node {
    cost: u32::MAX,
    step: None,
    len: 0,
    old_dist: [0; 4],
    old_dist_ptr: 0,
    last_dist: 0,
    last_length: 0,
};

impl Node {
    /// Offers the position `len` bytes on the way there through `self`.
    fn relax(&self, target: &mut Node, cost: u32, len: usize, step: Option<MatchToken>) {
        let cost = self.cost.saturating_add(cost);
        if cost >= target.cost {
            return;
        }
        *target = Node {
            cost,
            step,
            len: len as u16,
            ..*self
        };
        match step {
            None | Some(MatchToken::RepeatLast(_)) => {}
            Some(token) => {
                let distance = match token {
                    MatchToken::ShortLz(t) => t.distance,
                    MatchToken::OldDist(t) => t.distance,
                    MatchToken::LongLz(t) => t.distance,
                    MatchToken::RepeatLast(_) => unreachable!(),
                };
                target.old_dist[usize::from(target.old_dist_ptr)] = distance;
                target.old_dist_ptr = (target.old_dist_ptr + 1) & 3;
                target.last_dist = distance;
                target.last_length = len as u32;
            }
        }
    }
}

/// `low..=high`, but past [`ALL_LENGTHS_UP_TO`] only `high`.
fn lengths(low: usize, high: usize) -> impl Iterator<Item = usize> {
    (low..=high.min(ALL_LENGTHS_UP_TO))
        .chain((high > ALL_LENGTHS_UP_TO && high >= low).then_some(high))
}

/// Stmode matches reach back this far.
const STMODE_MATCH_DISTANCES: u32 = 0x2000;

impl Unpack15Encoder {
    /// Codes the next stmode step of the plan, or says stmode should end
    /// because the plan has a match there worth leaving it for.
    ///
    /// A planned match is worth leaving for when the exit code and the match
    /// cost less than coding its bytes without leaving: as a stmode match,
    /// three or four bytes no more than 8 KiB back, and literals for the rest,
    /// or as literals only. Otherwise it is coded that way, and the plan goes
    /// on from where the match would have ended.
    pub(super) fn planned_stmode_step(
        &mut self,
        plan: &mut Plan,
        input: &[u8],
        pos: &mut usize,
        base: usize,
        finder: &mut Rar13MatchFinder,
    ) -> bool {
        let at = base + *pos;
        if plan.at <= at || plan.steps.is_empty() {
            match self.planned_step(plan, input, *pos, at, finder) {
                Some(token) => {
                    let length = token.length() as usize;
                    let distance = token.distance();
                    let literals = |bytes: &[u8]| -> u32 {
                        bytes
                            .iter()
                            .map(|&byte| plan.literal[usize::from(byte)])
                            .sum()
                    };
                    let as_literals = literals(&input[*pos..*pos + length]);
                    let short = length.min(4);
                    let as_match = if length >= 3
                        && (1..STMODE_MATCH_DISTANCES).contains(&distance)
                        && distance as usize <= *pos
                    {
                        price(decode_num_bit_cost(distance >> 5, 5, DEC_HF2, POS_HF2))
                            .saturating_add(
                                plan.escape
                                    + 7 * BIT
                                    + literals(&input[*pos + short..*pos + length]),
                            )
                    } else {
                        UNPRICED
                    };
                    let leaving = plan.escape + BIT + plan.steps[0].1;
                    if leaving < as_literals.min(as_match) {
                        return true;
                    }
                    plan.consume();
                    if as_match < as_literals {
                        self.emit_stmode_match(distance, short as u32);
                        *pos += short;
                        return false;
                    }
                }
                None => plan.consume(),
            }
        }
        // A literal, or a byte of a planned match passed over.
        self.emit_stmode_literal(input[*pos]);
        *pos += 1;
        false
    }

    /// The stmode escape, then the match: three or four bytes, `distance`
    /// back.
    fn emit_stmode_match(&mut self, distance: u32, length: u32) {
        debug_assert!((3..=4).contains(&length));
        let (start, dec, pos) = literal_codebook(self.avr_plc);
        emit_decode_num(&mut self.bits, 0, start, dec, pos);
        self.bits.write_bits(u32::from(length == 4), 2);
        emit_decode_num(&mut self.bits, distance >> 5, 5, DEC_HF2, POS_HF2);
        self.bits.write_bits(distance & 0x1f, 5);
    }

    /// The planned step at window position `pos` (member position `at`),
    /// planning afresh if the plan does not start there. A planned match the
    /// coder's state can no longer code (its length rule moved with
    /// `max_dist3`) drops the plan and gives a literal instead.
    pub(super) fn planned_step(
        &self,
        plan: &mut Plan,
        input: &[u8],
        pos: usize,
        at: usize,
        finder: &mut Rar13MatchFinder,
    ) -> Option<MatchToken> {
        if plan.at != at || plan.steps.is_empty() {
            plan.at = at;
            plan.steps.clear();
            self.plan_parse(input, pos, finder, plan);
        }
        match plan.steps[0].0 {
            Some(token) if self.can_code(token) => Some(token),
            Some(_) => {
                plan.steps.clear();
                None
            }
            None => None,
        }
    }

    fn can_code(&self, token: MatchToken) -> bool {
        match token {
            MatchToken::RepeatLast(t) => {
                self.last_dist == t.distance && self.last_length == t.length
            }
            MatchToken::OldDist(t) => {
                self.old_dist[self.old_dist_ptr.wrapping_sub((t.short_code - 9) as usize) & 3]
                    == t.distance
                    && old_dist_lz_length_code(t.length, t.distance, self.max_dist3, t.short_code)
                        .is_some()
            }
            MatchToken::ShortLz(_) => true,
            MatchToken::LongLz(t) => long_lz_length_code_for_distance(t, self.max_dist3).is_some(),
        }
    }

    /// Fills `plan` with the cheapest parse of the span from window position
    /// `pos`, and the prices it was made with.
    fn plan_parse(&self, input: &[u8], pos: usize, finder: &mut Rar13MatchFinder, plan: &mut Plan) {
        let end = (pos + PLAN_SPAN).min(input.len());
        let span = end - pos;
        let prices = Prices::new(self);
        plan.literal = prices.literal;
        plan.escape = prices.escape;
        let max_distance = MAX_LONG_LZ_DISTANCE.min(self.options.max_long_match_distance);
        let mut nodes = std::mem::take(&mut plan.nodes);
        nodes.clear();
        nodes.resize(span + 1, UNREACHED);
        nodes[0] = Node {
            cost: 0,
            step: None,
            len: 0,
            old_dist: self.old_dist,
            old_dist_ptr: self.old_dist_ptr as u8,
            last_dist: self.last_dist,
            last_length: self.last_length,
        };
        let mut long = Vec::with_capacity(16);
        let two_flags = 2 * FLAG_BIT;
        let mut skip_until = 0;
        for i in 0..span {
            if i < skip_until {
                continue;
            }
            let node = nodes[i];
            let p = pos + i;
            let room = span - i;
            let literal = prices
                .literal_flag
                .saturating_add(prices.literal[usize::from(input[p])]);
            node.relax(&mut nodes[i + 1], literal, 1, None);
            if room < 2 {
                continue;
            }
            let max_len = room.min(258);
            let mut longest = 0;
            let (before, after) = nodes.split_at_mut(i + 1);
            let node = &before[i];
            let mut offer = |len: usize, cost: u32, token: MatchToken| {
                node.relax(&mut after[len - 1], cost, len, Some(token));
            };

            if node.last_dist != u32::MAX {
                let distance = node.last_dist as usize;
                let length = node.last_length as usize;
                if distance <= p
                    && length <= room
                    && super::super::super::fast::match_length(input, p, distance, length) == length
                {
                    offer(
                        length,
                        two_flags + prices.prefix[9],
                        MatchToken::RepeatLast(RepeatLastLz {
                            distance: node.last_dist,
                            length: node.last_length,
                        }),
                    );
                }
            }

            for short_code in 10..=13u32 {
                let distance = node.old_dist
                    [usize::from(node.old_dist_ptr).wrapping_sub((short_code - 9) as usize) & 3];
                if distance == u32::MAX || distance as usize > p {
                    continue;
                }
                let found =
                    super::super::super::fast::match_length(input, p, distance as usize, max_len);
                if found < 3 {
                    continue;
                }
                longest = longest.max(found);
                for length in lengths(3, found) {
                    let length = length as u32;
                    if !old_dist_lz_is_encodable(length, distance, short_code) {
                        continue;
                    }
                    let Some(code) =
                        old_dist_lz_length_code(length, distance, prices.max_dist3, short_code)
                    else {
                        continue;
                    };
                    let cost = prices
                        .old_length
                        .get(code as usize)
                        .copied()
                        .unwrap_or(UNPRICED);
                    if cost == UNPRICED {
                        continue;
                    }
                    offer(
                        length as usize,
                        two_flags + prices.prefix[short_code as usize] + cost,
                        MatchToken::OldDist(OldDistLz {
                            distance,
                            length,
                            short_code,
                        }),
                    );
                }
            }

            if p > 0 {
                // The cheapest distance for each short length.
                let mut best = [(UNPRICED, 0usize); 11];
                let cap = room.min(10);
                pair_recurrences(input, p, p.min(256), |distance| {
                    let mut found = 2;
                    while found < cap && input[p + found] == input[p + found - distance] {
                        found += 1;
                    }
                    let cost = prices.short_distance[distance - 1];
                    for entry in &mut best[2..=found] {
                        // Farthest first, so a tie goes to the nearer.
                        if cost <= entry.0 {
                            *entry = (cost, distance);
                        }
                    }
                });
                for (length, &(cost, distance)) in best.iter().enumerate().skip(2) {
                    if cost != UNPRICED {
                        offer(
                            length,
                            two_flags + prices.prefix[length - 2] + cost,
                            MatchToken::ShortLz(ShortLz {
                                distance: distance as u32,
                                length: length as u32,
                            }),
                        );
                    }
                }
            }

            long_candidates(input, p, max_len, max_distance, finder, &mut long);
            let mut from = 3;
            for &(found, distance) in &long {
                let token_at = |length: usize| LongLz {
                    distance: distance as u32,
                    length: length as u32,
                };
                let distance_cost = prices.long_distance[(distance >> 7) & 0xff];
                for length in lengths(from, found) {
                    let token = token_at(length);
                    if let Some(code) = long_lz_length_code_for_distance(token, prices.max_dist3) {
                        offer(
                            length,
                            prices.long_flag + prices.long_length[code as usize] + distance_cost,
                            MatchToken::LongLz(token),
                        );
                    }
                }
                from = found + 1;
                longest = longest.max(found);
            }
            if longest >= TAKEN_WHOLE {
                let mut reached = i + longest;
                while nodes[reached].cost == u32::MAX {
                    reached -= 1;
                }
                skip_until = reached;
            }
        }

        let steps = &mut plan.steps;
        let mut at = span;
        while at > 0 {
            let node = &nodes[at];
            let from = at - usize::from(node.len);
            steps.push_back((node.step, node.cost - nodes[from].cost));
            at = from;
        }
        steps.make_contiguous().reverse();
        // A step starting within a longest match of the end of the span was
        // chosen with the span's end cutting its options short: leave it to
        // the next plan, unless the member ends there too.
        if end < input.len() {
            let mut covered = 0;
            let keep = steps
                .iter()
                .take_while(|(step, _)| {
                    let starts = covered;
                    covered += step.map_or(1, |token| token.length() as usize);
                    starts == 0 || starts + 258 < span
                })
                .count();
            steps.truncate(keep);
        }
        plan.nodes = nodes;
    }
}

/// Calls `each` with every distance up to `reach`, farthest first, at which
/// the two bytes at `pos` occur before it.
fn pair_recurrences(input: &[u8], pos: usize, reach: usize, mut each: impl FnMut(usize)) {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    let (first, second) = (input[pos], input[pos + 1]);
    let (firsts, seconds) = (ONES * u64::from(first), ONES * u64::from(second));
    let word = |at: usize| u64::from_le_bytes(input[at..at + 8].try_into().unwrap());
    let mut at = pos - reach;
    // Eight starts at a time: a byte of `differ` is zero where both bytes
    // match. The zero-byte test can also flag the byte above a zero one, so
    // each flagged start is checked.
    while at + 8 <= pos {
        let differ = (word(at) ^ firsts) | (word(at + 1) ^ seconds);
        let mut zeros = differ.wrapping_sub(ONES) & !differ & HIGHS;
        while zeros != 0 {
            let start = at + zeros.trailing_zeros() as usize / 8;
            if input[start] == first && input[start + 1] == second {
                each(pos - start);
            }
            zeros &= zeros - 1;
        }
        at += 8;
    }
    for start in at..pos {
        if input[start] == first && input[start + 1] == second {
            each(pos - start);
        }
    }
}

/// Long-match candidates at `pos` whose lengths increase, nearest first for
/// each length.
fn long_candidates(
    input: &[u8],
    pos: usize,
    max_len: usize,
    max_distance: usize,
    finder: &mut Rar13MatchFinder,
    out: &mut Vec<(usize, usize)>,
) {
    out.clear();
    if pos == 0 || pos + 2 >= input.len() {
        return;
    }
    let max_distance = pos.min(max_distance);
    let mut best = 0usize;
    let mut checked = 0usize;
    for candidate in finder.candidates_before(input, pos) {
        let distance = pos - candidate;
        if distance > max_distance {
            break;
        }
        if distance > 256 {
            if checked >= MAX_LONG_MATCH_CANDIDATES {
                break;
            }
            checked += 1;
        }
        if best == 0 || input[candidate + best] == input[pos + best] {
            let found = super::super::super::fast::match_length(input, pos, distance, max_len);
            let shortest = if distance <= 256 { 11 } else { 3 };
            if found >= shortest && found > best {
                out.push((found, distance));
                best = found;
                if found == max_len {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::Unpack15;
    use super::*;

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn words(len: usize, seed: u64) -> Vec<u8> {
        const WORDS: [&[u8]; 8] = [
            b"the ",
            b"cheapest ",
            b"path ",
            b"through ",
            b"a ",
            b"span, ",
            b"priced\n",
            b"0x7f ",
        ];
        let mut state = seed;
        let mut out = Vec::with_capacity(len + 16);
        while out.len() < len {
            out.extend_from_slice(WORDS[xorshift(&mut state) as usize % WORDS.len()]);
        }
        out.truncate(len);
        out
    }

    /// Noise in which a few three- and four-byte strings recur close
    /// together: what stmode matches are for.
    fn speckled(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut out: Vec<u8> = Vec::with_capacity(len + 4);
        while out.len() < len {
            let roll = xorshift(&mut state);
            if out.len() > 64 && roll.is_multiple_of(23) {
                let length = 3 + (roll >> 8) as usize % 2;
                let from = out.len() - 1 - (roll >> 16) as usize % 60;
                for k in 0..length {
                    out.push(out[from + k]);
                }
            } else {
                out.push(roll as u8);
            }
        }
        out.truncate(len);
        out
    }

    fn priced() -> EncodeOptions {
        EncodeOptions::new().with_priced_parse(true)
    }

    fn round_trip(data: &[u8]) -> (Vec<u8>, Unpack15) {
        let packed = Unpack15Encoder::with_options(priced())
            .encode_member(data)
            .unwrap();
        let mut decoder = Unpack15::new();
        assert_eq!(
            decoder.decode_member(&packed, data.len(), false).unwrap(),
            data
        );
        (packed, decoder)
    }

    #[test]
    fn priced_members_round_trip() {
        let mut runs = vec![0u8; 3000];
        runs.extend(words(5000, 9));
        runs.extend(vec![b'x'; 700]);
        let inputs = [
            vec![7],
            vec![1, 2],
            b"abcabcabc".to_vec(),
            words(40_000, 1),
            speckled(40_000, 2),
            runs,
            (0..20_000u32).map(|i| ((i * i) >> 7) as u8).collect(),
        ];
        for data in &inputs {
            round_trip(data);
        }
    }

    #[test]
    fn priced_parse_codes_stmode_matches_in_noise() {
        let data = speckled(60_000, 3);
        let (_, decoder) = round_trip(&data);
        assert!(decoder.state.token_stats.st_matches > 0);
    }

    #[test]
    fn priced_parse_packs_smaller_than_the_greedy_one() {
        for data in [words(60_000, 4), speckled(60_000, 5)] {
            let greedy = Unpack15Encoder::new().encode_member(&data).unwrap();
            let (packed, _) = round_trip(&data);
            assert!(packed.len() < greedy.len());
        }
    }

    #[test]
    fn a_priced_solid_chain_decodes() {
        let members = [words(30_000, 6), speckled(30_000, 7), words(20_000, 8)];
        let mut encoder = Unpack15Encoder::with_options(priced());
        let mut decoder = Unpack15::new();
        for (index, member) in members.iter().enumerate() {
            let packed = encoder.encode_member(member).unwrap();
            assert_eq!(
                decoder
                    .decode_member(&packed, member.len(), index > 0)
                    .unwrap(),
                *member
            );
        }
    }

    #[test]
    fn pair_recurrences_lists_every_earlier_pair_farthest_first() {
        let mut state = 11;
        let data: Vec<u8> = (0..2000)
            .map(|_| b"abc"[xorshift(&mut state) as usize % 3])
            .collect();
        for pos in [0, 1, 7, 8, 9, 100, 255, 256, 257, 1000, 1998] {
            let reach = pos.min(256);
            let expected: Vec<_> = (1..=reach)
                .rev()
                .filter(|&d| data[pos - d] == data[pos] && data[pos + 1 - d] == data[pos + 1])
                .collect();
            let mut listed = Vec::new();
            pair_recurrences(&data, pos, reach, |d| listed.push(d));
            assert_eq!(listed, expected, "at {pos}");
        }
    }
}
