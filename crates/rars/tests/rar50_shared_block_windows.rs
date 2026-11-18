#![cfg(all(feature = "write", feature = "parallel"))]

//! Consecutive runs of a member in one wave share a window and a match index
//! (#276). At one thread a wave holds one run, so nothing is shared; at
//! several, runs of the same member share. The archive must not change.

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{
    ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, FilterKind, FilterSpec, WriterResources,
};

const KIB: usize = 1024;
const MIB: u64 = 1024 * 1024;
/// The budget each job is planned in: below a 3 MiB member's whole-member
/// charge with filters (192 MiB at a 1 MiB dictionary), so a member with
/// filters is coded run by run. The budget for the wave is wider, so several
/// runs can be coded at once.
const LIMIT: u64 = 190 * MIB;

/// Text built from a small vocabulary, so matches reach back across run
/// boundaries and the parse has long ones to commit to.
fn text(size: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&[u8]; 12] = [
        b"volume ",
        b"header ",
        b"the ",
        b"of ",
        b"match ",
        b"block ",
        b"\n",
        b"window ",
        b"dictionary ",
        b"a shared index ",
        b"run ",
        b"member ",
    ];
    let mut state = seed;
    let mut data = Vec::with_capacity(size + 16);
    while data.len() < size {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        data.extend_from_slice(WORDS[(state >> 33) as usize % WORDS.len()]);
    }
    data.truncate(size);
    data
}

/// With a 1 MiB dictionary a run is 1 MiB and its window up to 2 MiB, which
/// the optimal parse searches through a packed index. Two members two runs
/// long, the second of one cut short. A wave of four takes the first
/// member's runs and then the second's, and each member's two share.
fn members() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("first.txt", text(2048 * KIB, 1)),
        ("second.txt", text(1024 * KIB + 3, 2)),
    ]
}

/// The same few instructions before each call to one of eight targets, which
/// the E8 filter turns into eight absolute addresses.
fn code(size: usize) -> Vec<u8> {
    const FILLER: [u8; 11] = [
        0x48, 0x89, 0x8b, 0xc3, 0x83, 0x0f, 0x85, 0x31, 0xff, 0x74, 0x41,
    ];
    const TARGETS: [u32; 8] = [
        0x1000, 0x2340, 0x8800, 0x10000, 0x23456, 0x40000, 0x7f000, 0x12_3456,
    ];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut data = Vec::with_capacity(size);
    while data.len() + 16 <= size {
        data.extend_from_slice(&FILLER);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let target = TARGETS[(state >> 33) as usize % TARGETS.len()];
        let at = data.len();
        data.push(0xe8);
        data.extend_from_slice(&target.wrapping_sub(at as u32 + 5).to_le_bytes());
    }
    data.resize(size, 0x90);
    data
}

fn write(
    members: Vec<(&'static str, Vec<u8>)>,
    policy: FilterPolicy,
    solid: bool,
    threads: usize,
) -> Vec<u8> {
    let entries: Vec<_> = members
        .into_iter()
        .map(|(name, data)| ArchiveEntry::new(name, EntrySource::from_bytes(data)))
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let mut bytes = Vec::new();
    pool.install(|| {
        rar50::write_streaming_archive_with_progress(
            &entries,
            WriterOptions::new(ArchiveVersion::Rar50, features)
                .with_compression_level(2)
                .with_dictionary_size(1024 * 1024),
            ArchiveExtras::default().with_filter_policy(policy),
            &WriterResources::new(LIMIT).with_memory_limit(4096 * MIB),
            None,
            &mut bytes,
        )
    })
    .unwrap();
    bytes
}

#[test]
fn runs_sharing_a_window_write_the_archive_one_run_at_a_time_would() {
    same_archive_shared_or_alone(members, FilterPolicy::None, false, 4);
}

#[test]
fn solid_runs_sharing_a_window_write_the_archive_one_run_at_a_time_would() {
    // A solid chain is one stream through every member, so a wave of four
    // holds four consecutive runs of it, the second crossing from the first
    // member into the second.
    let chain = || {
        vec![
            ("first.txt", text(1536 * KIB, 1)),
            ("second.txt", text(1536 * KIB + 3, 2)),
        ]
    };
    same_archive_shared_or_alone(chain, FilterPolicy::None, true, 4);
}

#[test]
fn filtered_solid_runs_sharing_a_window_write_the_archive_one_run_at_a_time_would() {
    // Automatic filters give a solid run its blocks' records, with its bytes
    // already filtered. The first run, filtered at the chain's start, keeps
    // its own window; the second, filtered, and the third, plain text, share.
    let mixed = || {
        vec![
            ("code.bin", code(2048 * KIB)),
            ("notes.txt", text(64 * KIB + 3, 3)),
        ]
    };
    same_archive_shared_or_alone(mixed, FilterPolicy::Auto, true, 3);
}

#[test]
fn filtered_runs_sharing_a_window_write_the_archive_one_run_at_a_time_would() {
    // A wave of three holds the member's three runs. With the filter over the
    // whole member, the first run searches a tree and keeps its own window,
    // and the other two share theirs, filtered. With it from partway into the
    // second run, one group holds a plain, a part-filtered and a filtered run.
    // Automatic filters choose a run's filters before this, so a run they
    // filter is coded the same way.
    let member = || vec![("code.bin", code(3072 * KIB))];
    let whole = same_archive_shared_or_alone(
        member,
        FilterPolicy::Explicit(FilterSpec::whole(FilterKind::E8)),
        false,
        3,
    );
    let part = same_archive_shared_or_alone(
        member,
        FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8, 1536 * KIB..3072 * KIB)),
        false,
        3,
    );
    assert!(whole.len() < part.len(), "the filters were not applied");
}

/// Writes `members` at one thread and at `threads`, checks the archives are
/// the same and extract, and returns the archive.
fn same_archive_shared_or_alone(
    members: impl Fn() -> Vec<(&'static str, Vec<u8>)>,
    policy: FilterPolicy,
    solid: bool,
    threads: usize,
) -> Vec<u8> {
    let alone = write(members(), policy.clone(), solid, 1);
    let shared = write(members(), policy.clone(), solid, threads);
    assert!(alone == shared, "{policy:?}: sharing changed the archive");

    let archive = ArchiveReader::read(&shared).unwrap();
    archive.test(None).unwrap();
    for (name, data) in members() {
        assert!(archive.read_member(name.as_bytes(), None).unwrap().unwrap() == data);
    }
    shared
}
