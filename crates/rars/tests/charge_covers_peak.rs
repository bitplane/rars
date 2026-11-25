#![cfg(feature = "write")]
// A counting global allocator has to implement `GlobalAlloc`, an unsafe
// trait. Every method forwards to `System` unchanged.
#![allow(unsafe_code)]

//! Every writer's memory charge against what it allocates.
//!
//! A writer charges its `WriterResources` budget an estimate of what each job
//! holds. This measures both sides of one write:
//!
//! - **allocated**: the high-water mark of live heap bytes during the write,
//!   above the level when it began, counted by the global allocator below. The
//!   members' bytes and the thread pool exist before that point, and the
//!   archive goes to `io::sink()`, so neither counts.
//! - **charged**: the most the write held against its budget at once,
//!   [`WriterResources::workspace_peak`].
//!
//! and asserts, for each case:
//!
//! 1. **covered**: allocated ≤ charged, with a budget far above the charge.
//!    The legacy writers clamp a member's charge to the budget, so a small
//!    budget would say nothing about the formula.
//! 2. **not wildly loose**: charged ≤ [`LOOSE_FACTOR`] × the largest
//!    allocated peak over every input for the same writer, path, level and
//!    thread count, plus [`LOOSE_SLACK`]. A charge has to hold for the worst
//!    input, so it is judged against the worst.
//! 3. **inside the budget**: allocated ≤ the default budget's
//!    `memory_limit()` for the thread count. A case whose charge fits that
//!    budget is admitted there exactly as it was under the large one, so the
//!    first run already answers this; a case whose charge does not fit is
//!    written again at the default budget and measured.
//!
//! Cases that fail an assertion are listed in [`KNOWN_GAPS`] against the issue
//! that tracks them, and the test asserts each listed gap is still there, so a
//! fix has to remove its entry.
//!
//! A case is about a second in a test build, so the default run takes a
//! sample of the 1 MiB matrix. The whole matrix, and the matrix again at each
//! level's fitted dictionary, are `#[ignore]`d and run by hand.
//!
//! Resident memory (what the allocator keeps after a free, glibc's arenas)
//! is not counted here, and nor is the PPMd model's pool, which is an
//! anonymous mapping of its own on Unix and Windows rather than a heap
//! allocation.

use rars::rar15_40::{MemberCoding, Rar29Method};
use rars::rar50::{ArchiveEntry, ArchiveExtras};
use rars::{ArchiveVersion, EntrySource, FeatureSet, FilterPolicy, WriterResources};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Far above every charge, so no charge is clamped to the budget. It keeps
/// the default planning limit, so the archive is the default one.
const LARGE_BUDGET: u64 = 8 * 1024 * MIB;

/// Assertion 2's bound: charged ≤ `LOOSE_FACTOR` × worst allocated + `LOOSE_SLACK`.
const LOOSE_FACTOR: f64 = 2.0;
const LOOSE_SLACK: u64 = 16 * MIB;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn shrank(bytes: usize) {
    LIVE.fetch_sub(bytes, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grew(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grew(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One measurement at a time, whichever harness runs the tests.
static MEASURING: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    /// An explicit 1 MiB dictionary and 2.5 MiB members.
    Small,
    /// Each level's fitted dictionary, members two and a half of it long.
    Fitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Writer {
    Rar13,
    Rar15,
    Rar20,
    /// RAR 4, the 2.9 codec.
    Rar4,
    Rar5,
    Rar7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    /// One member coded whole: RAR 4 without a filter search, and the only
    /// path RAR 1.3 to 2.0 have.
    Whole,
    /// One member, filters searched. RAR 5 codes a member this short whole.
    FiltersAuto,
    /// RAR 5 and 7: one member without filters, coded in block jobs.
    Blocks,
    /// RAR 4 with PPMd forced.
    Ppmd,
    /// Three members in a solid chain.
    Solid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    /// Words from a small vocabulary.
    Text,
    /// Repeating records with counters, absolute addresses and calls.
    Binary,
    Random,
    TwoSymbol,
    ThreeSymbol,
    Zeros,
}

const WRITERS: [Writer; 6] = [
    Writer::Rar13,
    Writer::Rar15,
    Writer::Rar20,
    Writer::Rar4,
    Writer::Rar5,
    Writer::Rar7,
];

const INPUTS: [Input; 6] = [
    Input::Text,
    Input::Binary,
    Input::Random,
    Input::TwoSymbol,
    Input::ThreeSymbol,
    Input::Zeros,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Assertion {
    Covered,
    Loose,
    InsideBudget,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    writer: Writer,
    path: Path,
    level: u8,
    threads: usize,
    input: Input,
}

/// Cases that fail an assertion today. `None` matches any.
struct Gap {
    tier: Tier,
    writer: Writer,
    paths: &'static [Path],
    levels: &'static [u8],
    threads: Option<usize>,
    input: Option<Input>,
    assertion: Assertion,
    /// The issue tracking it.
    issue: u32,
}

impl Gap {
    fn covers(&self, tier: Tier, case: &Case) -> bool {
        self.tier == tier
            && self.writer == case.writer
            && self.paths.contains(&case.path)
            && self.levels.contains(&case.level)
            && self.threads.is_none_or(|threads| threads == case.threads)
            && self.input.is_none_or(|input| input == case.input)
    }

    fn matches(&self, tier: Tier, case: &Case, assertion: Assertion) -> bool {
        self.covers(tier, case) && self.assertion == assertion
    }
}

/// Every case that fails an assertion today, against the issue tracking it.
/// #393 is the accounting work these belong to; an entry naming it has no
/// issue of its own yet.
const KNOWN_GAPS: &[Gap] = &[
    // At a 1 MiB dictionary.
    //
    // RAR 2.0 charges a block's workspace for each block coded at once, and
    // level 1's lazy parse holds well under half of that.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar20,
        paths: &[Path::Whole],
        levels: &[1],
        threads: Some(4),
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    // RAR 2.0's optimal parse on two-symbol noise holds more than its charge.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar20,
        paths: &[Path::Whole],
        levels: &[5],
        threads: Some(1),
        input: Some(Input::TwoSymbol),
        assertion: Assertion::Covered,
        issue: 393,
    },
    // A RAR 2.0 chain holds far less than a member coded on its own, and is
    // charged the same.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar20,
        paths: &[Path::Solid],
        levels: &[3, 5],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    // From level 3, RAR 4 tries PPMd on text, and is charged the trial's
    // models in full. Their pools are anonymous mappings, not heap
    // allocations, so the allocator here does not see them.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar4,
        paths: &[Path::Whole, Path::FiltersAuto, Path::Solid],
        levels: &[3, 4, 5],
        threads: None,
        input: Some(Input::Text),
        assertion: Assertion::Loose,
        issue: 393,
    },
    // Level 5's filter search codes its finalists side by side, each in room
    // charged as it runs, and at four threads that room is more than binary
    // records hold.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar4,
        paths: &[Path::FiltersAuto],
        levels: &[5],
        threads: Some(4),
        input: Some(Input::Binary),
        assertion: Assertion::Loose,
        issue: 393,
    },
    // Forced PPMd is charged its models in full. The model's pool is an
    // anonymous mapping, not a heap allocation, so the allocator here does
    // not see it either: part of this gap is what the test cannot count.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar4,
        paths: &[Path::Ppmd],
        levels: &[1, 2, 3, 4, 5],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    // A RAR 4 chain is charged as one member at a time, and holds more than
    // that while it codes.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar4,
        paths: &[Path::Solid],
        levels: &[1, 2, 3, 4, 5],
        threads: None,
        input: None,
        assertion: Assertion::Covered,
        issue: 393,
    },
    // The lazy parse's charge is the same at every level, and level 1's
    // short chains hold a fraction of it.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar5,
        paths: &[Path::FiltersAuto, Path::Blocks, Path::Solid],
        levels: &[1],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    // A wave of block jobs reserves admission for every job it could hold,
    // which at four threads is more than a member of three runs uses.
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar5,
        paths: &[Path::Blocks],
        levels: &[2, 3, 4, 5],
        threads: Some(4),
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Small,
        writer: Writer::Rar7,
        paths: &[Path::Blocks],
        levels: &[3, 5],
        threads: Some(4),
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    // At each level's fitted dictionary, for the causes above where an entry
    // gives none of its own.
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar20,
        paths: &[Path::Whole],
        levels: &[1],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar20,
        paths: &[Path::Solid],
        levels: &[3, 5],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar4,
        paths: &[Path::Whole],
        levels: &[3, 4, 5],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar4,
        paths: &[Path::FiltersAuto],
        levels: &[4, 5],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar4,
        paths: &[Path::FiltersAuto],
        levels: &[3],
        threads: Some(1),
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar4,
        paths: &[Path::Solid],
        levels: &[4, 5],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar4,
        paths: &[Path::Ppmd],
        levels: &[1, 2, 3, 4, 5],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar4,
        paths: &[Path::Solid],
        levels: &[1, 2, 3, 4, 5],
        threads: None,
        input: None,
        assertion: Assertion::Covered,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar5,
        paths: &[Path::FiltersAuto, Path::Blocks, Path::Solid],
        levels: &[1],
        threads: None,
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    // A member two and a half dictionaries long is past one filter search, so
    // with filters searched it is coded in runs too.
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar5,
        paths: &[Path::FiltersAuto],
        levels: &[3],
        threads: Some(4),
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
    Gap {
        tier: Tier::Fitted,
        writer: Writer::Rar5,
        paths: &[Path::Blocks],
        levels: &[2],
        threads: Some(4),
        input: None,
        assertion: Assertion::Loose,
        issue: 393,
    },
];

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

impl Input {
    fn bytes(self, size: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x2545_f491_4f6c_dd1d;
        let mut data = Vec::with_capacity(size);
        match self {
            Self::Text => {
                const WORDS: [&str; 48] = [
                    "the",
                    "of",
                    "and",
                    "archive",
                    "member",
                    "window",
                    "match",
                    "length",
                    "distance",
                    "block",
                    "header",
                    "volume",
                    "budget",
                    "charge",
                    "memory",
                    "writer",
                    "reader",
                    "filter",
                    "delta",
                    "audio",
                    "image",
                    "text",
                    "binary",
                    "solid",
                    "chain",
                    "thread",
                    "pool",
                    "level",
                    "dictionary",
                    "search",
                    "parse",
                    "tree",
                    "hash",
                    "token",
                    "symbol",
                    "table",
                    "model",
                    "order",
                    "escape",
                    "context",
                    "range",
                    "coder",
                    "bit",
                    "byte",
                    "word",
                    "line",
                    "page",
                    "file",
                ];
                let mut words = 0;
                while data.len() < size {
                    let word = WORDS[(lcg(&mut state) >> 33) as usize % WORDS.len()];
                    data.extend_from_slice(word.as_bytes());
                    words += 1;
                    data.push(if words % 12 == 0 { b'\n' } else { b' ' });
                }
            }
            Self::Binary => {
                let mut record = 0u32;
                while data.len() < size {
                    let at = data.len() as u32;
                    data.extend_from_slice(&record.to_le_bytes());
                    data.extend_from_slice(&(0x0040_1000 + at).to_le_bytes());
                    // A call to a fixed routine, relative as x86 codes it.
                    data.push(0xe8);
                    let call = 0x0001_0000u32.wrapping_sub(at + 13);
                    data.extend_from_slice(&call.to_le_bytes());
                    data.extend_from_slice(&[0x8b, 0x45, 0xfc, 0x89, 0xc1, 0x00, 0x00]);
                    data.extend_from_slice(&((record % 7) as u16).to_le_bytes());
                    data.extend_from_slice(&[0x90; 8]);
                    record += 1;
                }
            }
            Self::Random => {
                while data.len() < size {
                    data.push((lcg(&mut state) >> 33) as u8);
                }
            }
            Self::TwoSymbol => {
                while data.len() < size {
                    data.push((lcg(&mut state) >> 63) as u8);
                }
            }
            Self::ThreeSymbol => {
                while data.len() < size {
                    data.push(((lcg(&mut state) >> 33) % 3) as u8);
                }
            }
            Self::Zeros => data.resize(size, 0),
        }
        data.truncate(size);
        data
    }
}

impl Writer {
    fn version(self) -> ArchiveVersion {
        match self {
            Self::Rar13 => ArchiveVersion::Rar13,
            Self::Rar15 => ArchiveVersion::Rar15,
            Self::Rar20 => ArchiveVersion::Rar20,
            Self::Rar4 => ArchiveVersion::Rar40,
            Self::Rar5 => ArchiveVersion::Rar50,
            Self::Rar7 => ArchiveVersion::Rar70,
        }
    }

    fn levels(self) -> &'static [u8] {
        match self {
            Self::Rar13 | Self::Rar15 | Self::Rar20 => &[1, 3, 5],
            Self::Rar4 | Self::Rar5 => &[1, 2, 3, 4, 5],
            Self::Rar7 => &[3, 5],
        }
    }

    fn paths(self) -> &'static [Path] {
        match self {
            Self::Rar13 | Self::Rar15 => &[Path::Whole],
            Self::Rar20 => &[Path::Whole, Path::Solid],
            Self::Rar4 => &[Path::Whole, Path::FiltersAuto, Path::Ppmd, Path::Solid],
            Self::Rar5 => &[Path::FiltersAuto, Path::Blocks, Path::Solid],
            Self::Rar7 => &[Path::Blocks],
        }
    }

    /// The dictionary a tier writes with, `None` for RAR 1.3 and 1.5's fixed
    /// 64 KiB window.
    fn dictionary(self, tier: Tier, level: u8) -> Option<u64> {
        match (self, tier) {
            (Self::Rar13 | Self::Rar15, _) => None,
            (_, Tier::Small) => Some(MIB),
            // The legacy writers fit up to 4 MiB, RAR 5 and 7 up to a
            // dictionary that grows with the level.
            (Self::Rar20 | Self::Rar4, Tier::Fitted) => Some(4 * MIB),
            (Self::Rar5 | Self::Rar7, Tier::Fitted) => Some(
                match level {
                    1 => 1,
                    2 => 2,
                    3 => 4,
                    4 => 8,
                    _ => 16,
                } * MIB,
            ),
        }
    }

    fn tiers(self) -> &'static [Tier] {
        match self {
            // A 64 KiB window is the same in both tiers.
            Self::Rar13 | Self::Rar15 => &[Tier::Small],
            _ => &[Tier::Small, Tier::Fitted],
        }
    }
}

fn member_size(writer: Writer, tier: Tier, level: u8) -> usize {
    match tier {
        Tier::Small => (5 * MIB / 2) as usize,
        Tier::Fitted => (writer.dictionary(tier, level).unwrap_or(MIB) * 5 / 2) as usize,
    }
}

fn thread_counts() -> &'static [usize] {
    if cfg!(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    )) {
        &[1, 4]
    } else {
        &[1]
    }
}

/// Runs `run` on a pool of `threads` built beforehand, and returns what it
/// returns with the most live heap it added at once.
fn measure<T: Send>(threads: usize, run: impl FnOnce() -> T + Send) -> (T, u64) {
    let counted = move || {
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        let result = run();
        let peak = PEAK.load(Ordering::Relaxed);
        (result, peak.saturating_sub(before) as u64)
    };
    #[cfg(all(
        feature = "parallel",
        not(all(target_arch = "wasm32", target_os = "unknown"))
    ))]
    {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(counted)
    }
    #[cfg(any(
        not(feature = "parallel"),
        all(target_arch = "wasm32", target_os = "unknown")
    ))]
    {
        assert_eq!(threads, 1);
        counted()
    }
}

/// The members of one case, made before anything is counted.
fn members(case: &Case, tier: Tier) -> Vec<(String, EntrySource)> {
    let count = if case.path == Path::Solid { 3 } else { 1 };
    let size = member_size(case.writer, tier, case.level);
    (0..count)
        .map(|member| {
            let data = case.input.bytes(size, member + 1);
            (format!("member{member}.bin"), EntrySource::from_bytes(data))
        })
        .collect()
}

/// Writes one case's archive to a sink under `resources`.
fn write(case: &Case, tier: Tier, members: &[(String, EntrySource)], resources: &WriterResources) {
    let mut features = FeatureSet::store_only();
    features.solid = case.path == Path::Solid;
    let version = case.writer.version();
    let dictionary = case.writer.dictionary(tier, case.level);
    let sink = &mut std::io::sink();
    match case.writer {
        Writer::Rar13 => {
            let entries: Vec<_> = members
                .iter()
                .map(|(name, source)| {
                    rars::rar13::StreamingEntry::new(name.as_str(), source.clone())
                })
                .collect();
            rars::rar13::write_streaming_archive_to(
                &entries,
                rars::rar13::WriterOptions::new(version, features)
                    .with_compression_level(case.level),
                MemberCoding::Compressed,
                None,
                resources,
                None,
                sink,
            )
            .unwrap();
        }
        Writer::Rar15 | Writer::Rar20 | Writer::Rar4 => {
            let entries: Vec<_> = members
                .iter()
                .map(|(name, source)| {
                    rars::rar15_40::StreamingEntry::new(name.as_str(), source.clone())
                })
                .collect();
            let mut options = rars::rar15_40::WriterOptions::new(version, features)
                .with_compression_level(case.level);
            if let Some(dictionary) = dictionary {
                options = options.with_dictionary_size(dictionary as usize);
            }
            let coding = match case.path {
                Path::Whole if case.writer == Writer::Rar4 => {
                    MemberCoding::Filtered(FilterPolicy::None)
                }
                Path::Ppmd => {
                    options = options.with_method(Rar29Method::Ppmd);
                    MemberCoding::Compressed
                }
                _ => MemberCoding::Compressed,
            };
            rars::rar15_40::write_streaming_archive_to(
                &entries, options, coding, None, resources, None, sink,
            )
            .unwrap();
        }
        Writer::Rar5 | Writer::Rar7 => {
            let entries: Vec<_> = members
                .iter()
                .map(|(name, source)| ArchiveEntry::new(name.as_str(), source.clone()))
                .collect();
            let policy = match case.path {
                Path::Blocks => FilterPolicy::None,
                _ => FilterPolicy::Auto,
            };
            rars::rar50::write_streaming_archive_with_progress(
                &entries,
                rars::rar50::WriterOptions::new(version, features)
                    .with_compression_level(case.level)
                    .with_dictionary_size(dictionary.expect("RAR 5 always names one")),
                ArchiveExtras::default().with_filter_policy(policy),
                resources,
                None,
                sink,
            )
            .unwrap();
        }
    }
}

struct Measured {
    case: Case,
    allocated: u64,
    charged: u64,
    /// The default budget for the thread count, and what the case allocated
    /// written under it when its charge does not fit.
    default_limit: u64,
    allocated_at_default: Option<u64>,
}

fn run_case(case: Case, tier: Tier) -> Measured {
    let members = members(&case, tier);
    let _one = MEASURING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let ((charged, default_limit), allocated) = measure(case.threads, || {
        let resources = WriterResources::default().with_memory_limit(LARGE_BUDGET);
        write(&case, tier, &members, &resources);
        (
            resources.workspace_peak(),
            WriterResources::default().memory_limit(),
        )
    });
    let allocated_at_default = (charged > default_limit).then(|| {
        measure(case.threads, || {
            write(&case, tier, &members, &WriterResources::default());
        })
        .1
    });
    Measured {
        case,
        allocated,
        charged,
        default_limit,
        allocated_at_default,
    }
}

fn mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / MIB as f64)
}

fn all_cases(tier: Tier) -> Vec<Case> {
    let mut cases = Vec::new();
    for writer in WRITERS {
        if !writer.tiers().contains(&tier) {
            continue;
        }
        for &path in writer.paths() {
            for &level in writer.levels() {
                for &threads in thread_counts() {
                    for input in INPUTS {
                        cases.push(Case {
                            writer,
                            path,
                            level,
                            threads,
                            input,
                        });
                    }
                }
            }
        }
    }
    cases
}

/// A sample of the 1 MiB matrix that runs in seconds: every writer and path
/// once, on two-symbol noise, the input that holds the most on most of them.
fn quick_cases() -> Vec<Case> {
    let both = thread_counts();
    let four: &[usize] = if both.contains(&4) { &[4] } else { &[1] };
    let one: &[usize] = &[1];
    let sample: [(Writer, Path, u8, &[usize]); 12] = [
        (Writer::Rar13, Path::Whole, 1, both),
        (Writer::Rar15, Path::Whole, 1, both),
        (Writer::Rar20, Path::Whole, 1, both),
        (Writer::Rar20, Path::Solid, 1, both),
        (Writer::Rar4, Path::Whole, 3, both),
        (Writer::Rar4, Path::FiltersAuto, 3, both),
        (Writer::Rar4, Path::Ppmd, 1, both),
        (Writer::Rar4, Path::Solid, 1, both),
        // A member this short is coded whole, on one thread at any count.
        (Writer::Rar5, Path::FiltersAuto, 3, one),
        (Writer::Rar5, Path::Blocks, 3, both),
        (Writer::Rar5, Path::Solid, 2, four),
        // The RAR 5 encoder behind RAR 7's headers.
        (Writer::Rar7, Path::Blocks, 3, four),
    ];
    let mut cases = Vec::new();
    for (writer, path, level, threads) in sample {
        for &threads in threads {
            cases.push(Case {
                writer,
                path,
                level,
                threads,
                input: Input::TwoSymbol,
            });
        }
    }
    cases
}

fn check(tier: Tier, cases: Vec<Case>) {
    let started = std::time::Instant::now();
    let mut results = Vec::new();
    for case in cases {
        let case_started = std::time::Instant::now();
        let measured = run_case(case, tier);
        eprintln!(
            "{:?} {:?} L{} t{} {:?}: allocated {} charged {} MiB{} ({:.2} s)",
            case.writer,
            case.path,
            case.level,
            case.threads,
            case.input,
            mib(measured.allocated),
            mib(measured.charged),
            measured
                .allocated_at_default
                .map(|bytes| format!(
                    "; allocated {} MiB at the default {} MiB budget",
                    mib(bytes),
                    mib(measured.default_limit)
                ))
                .unwrap_or_default(),
            case_started.elapsed().as_secs_f64()
        );
        results.push(measured);
    }

    let mut failures = Vec::new();
    for measured in &results {
        let case = &measured.case;
        let worst = results
            .iter()
            .filter(|other| {
                other.case.writer == case.writer
                    && other.case.path == case.path
                    && other.case.level == case.level
                    && other.case.threads == case.threads
            })
            .map(|other| other.allocated)
            .max()
            .unwrap();
        if measured.allocated > measured.charged {
            failures.push((
                *case,
                Assertion::Covered,
                format!(
                    "allocated {} MiB > charged {} MiB",
                    mib(measured.allocated),
                    mib(measured.charged)
                ),
            ));
        }
        let bound = (worst as f64 * LOOSE_FACTOR) as u64 + LOOSE_SLACK;
        if measured.charged > bound {
            failures.push((
                *case,
                Assertion::Loose,
                format!(
                    "charged {} MiB > {LOOSE_FACTOR} × worst allocated {} MiB + {} MiB",
                    mib(measured.charged),
                    mib(worst),
                    mib(LOOSE_SLACK)
                ),
            ));
        }
        let at_default = measured.allocated_at_default.unwrap_or(measured.allocated);
        if at_default > measured.default_limit {
            failures.push((
                *case,
                Assertion::InsideBudget,
                format!(
                    "allocated {} MiB > default budget {} MiB",
                    mib(at_default),
                    mib(measured.default_limit)
                ),
            ));
        }
    }

    let mut problems = Vec::new();
    for (case, assertion, detail) in &failures {
        match KNOWN_GAPS
            .iter()
            .find(|gap| gap.matches(tier, case, *assertion))
        {
            Some(gap) => eprintln!(
                "known gap (#{}): {case:?} {assertion:?}: {detail}",
                gap.issue
            ),
            None => problems.push(format!("{case:?} {assertion:?}: {detail}")),
        }
    }
    // A gap is checked wherever its cases ran; the sample runs only some.
    for gap in KNOWN_GAPS.iter().filter(|gap| {
        results
            .iter()
            .any(|measured| gap.covers(tier, &measured.case))
    }) {
        if !failures
            .iter()
            .any(|(case, assertion, _)| gap.matches(tier, case, *assertion))
        {
            problems.push(format!(
                "the gap tracked by #{} ({:?} {:?} levels {:?} threads {:?} {:?} {:?}) no \
                 longer fails: remove it from KNOWN_GAPS",
                gap.issue, gap.writer, gap.paths, gap.levels, gap.threads, gap.input, gap.assertion
            ));
        }
    }
    eprintln!(
        "{tier:?} tier: {} cases in {:.1} s",
        results.len(),
        started.elapsed().as_secs_f64()
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn charges_cover_what_writers_allocate_on_a_sample() {
    check(Tier::Small, quick_cases());
}

/// Every writer, path, level, thread count and input at a 1 MiB dictionary.
/// Run by hand with `--ignored`.
#[test]
#[ignore = "tens of minutes in a test build; run by hand"]
fn charges_cover_what_writers_allocate_at_a_one_mib_dictionary() {
    check(Tier::Small, all_cases(Tier::Small));
}

/// Each level's fitted dictionary. Level 5 makes this hours long even in a
/// release build; run it by hand with `--ignored`.
#[test]
#[ignore = "hours in a release build; run by hand"]
fn charges_cover_what_writers_allocate_at_fitted_dictionaries() {
    check(Tier::Fitted, all_cases(Tier::Fitted));
}
