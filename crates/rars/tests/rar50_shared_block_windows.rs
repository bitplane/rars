#![cfg(all(feature = "write", feature = "parallel"))]

//! Consecutive runs of a member in one wave share a window and a match index
//! (#276). At one thread a wave holds one run, so nothing is shared; at four,
//! runs of the same member share. The archive must not change.

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};

const KIB: usize = 1024;

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
/// the optimal parse searches through a packed index. Two members several
/// runs long, the last of each cut short, so each wave holds runs of both.
fn members() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("first.txt", text(3584 * KIB, 1)),
        ("second.txt", text(2560 * KIB + 3, 2)),
    ]
}

fn write(policy: FilterPolicy, threads: usize) -> Vec<u8> {
    let entries: Vec<_> = members()
        .into_iter()
        .map(|(name, data)| ArchiveEntry::new(name, EntrySource::from_bytes(data)))
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap();
    let mut bytes = Vec::new();
    pool.install(|| {
        rar50::write_streaming_archive_with_progress(
            &entries,
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                .with_compression_level(2)
                .with_dictionary_size(1024 * 1024),
            ArchiveExtras::default().with_filter_policy(policy),
            &WriterResources::default(),
            None,
            &mut bytes,
        )
    })
    .unwrap();
    bytes
}

#[test]
fn runs_sharing_a_window_write_the_archive_one_run_at_a_time_would() {
    // Without filters every run takes the block path; with automatic filters
    // the runs are searched first, find nothing in text, and share after.
    for policy in [FilterPolicy::None, FilterPolicy::Auto] {
        let alone = write(policy.clone(), 1);
        let shared = write(policy.clone(), 4);
        assert!(alone == shared, "{policy:?}: sharing changed the archive");

        let archive = ArchiveReader::read(&shared).unwrap();
        archive.test(None).unwrap();
        for (name, data) in members() {
            assert!(archive.read_member(name.as_bytes(), None).unwrap().unwrap() == data);
        }
    }
}
