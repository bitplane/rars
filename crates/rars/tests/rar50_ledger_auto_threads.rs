#![cfg(all(feature = "write", feature = "parallel"))]

//! Under a hard memory ledger, a wave of filtered runs admits only as many
//! jobs as the ledger can hold once each has its history and its worker has
//! grown that history into a window, so many threads run fewer jobs at once
//! rather than fail, and write what fewer threads do.

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};

const MIB: usize = 1024 * 1024;

/// 64 printable symbols, which an LZ parse codes nearly a literal at a time.
fn literals(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x2545_f491_4f6c_dd1d;
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            b'0' + ((state >> 33) % 64) as u8
        })
        .collect()
}

/// Two independent 10 MiB members at level 3 with a 4 MiB dictionary, coded
/// in runs that each search for filters, under a 1 GiB ledger.
fn write(entries: &[ArchiveEntry], threads: usize) -> Vec<u8> {
    let resources = WriterResources::default().with_max_memory_bytes(1 << 30);
    let mut bytes = Vec::new();
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
        .install(|| {
            rar50::write_streaming_archive_with_progress(
                entries,
                WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                    .with_compression_level(3)
                    .with_dictionary_size(4 * MIB as u64),
                ArchiveExtras::default().with_filter_policy(FilterPolicy::Auto),
                &resources,
                None,
                &mut bytes,
            )
        })
        .unwrap_or_else(|error| panic!("{threads} threads: {error}"));
    assert_eq!(resources.managed_memory_in_use(), 0);
    bytes
}

#[test]
fn filtered_runs_under_a_ledger_write_alike_at_any_thread_count() {
    let entries: Vec<_> = (0..2)
        .map(|member| {
            ArchiveEntry::new(
                format!("member{member}.bin"),
                EntrySource::from_bytes(literals(10 * MIB, member + 1)),
            )
        })
        .collect();
    let expected = write(&entries, 1);
    ArchiveReader::read(&expected).unwrap().test(None).unwrap();
    for threads in [2, 8] {
        assert!(
            write(&entries, threads) == expected,
            "{threads} threads write differently from one"
        );
    }
}
