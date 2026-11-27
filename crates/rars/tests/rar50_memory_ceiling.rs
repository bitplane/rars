#![cfg(all(feature = "write", feature = "parallel"))]

//! A hard memory ceiling bounds what a RAR 5 writer holds at once. It decides
//! how many jobs run side by side, never what they write, so an archive
//! written under one is the archive written without one, at any thread count.

#[path = "support/data.rs"]
mod data;

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};

const KIB: usize = 1024;

/// A directory, members that pack differently (text, noise, half of each)
/// and one long enough to be coded in more than one run.
fn entries() -> Vec<ArchiveEntry> {
    let text: Vec<u8> = b"the ceiling decides how many jobs run, not what they write\n"
        .iter()
        .copied()
        .cycle()
        .take(160 * KIB)
        .collect();
    let mut entries =
        vec![ArchiveEntry::new("dir", EntrySource::from_bytes(Vec::new())).with_directory(true)];
    for (index, data) in [
        text.clone(),
        data::noise(7, 96 * KIB),
        data::half_noise(200 * KIB, 11, &text),
        data::half_noise(3 * 1024 * KIB, 13, &text),
    ]
    .into_iter()
    .enumerate()
    {
        entries.push(ArchiveEntry::new(
            format!("dir/member{index}"),
            EntrySource::from_bytes(data),
        ));
    }
    entries
}

fn write(
    entries: &[ArchiveEntry],
    level: u8,
    solid: bool,
    threads: usize,
    ceiling: Option<u64>,
) -> Vec<u8> {
    let mut resources = WriterResources::default();
    if let Some(ceiling) = ceiling {
        resources = resources.with_max_memory_bytes(ceiling);
    }
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let mut bytes = Vec::new();
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
        .install(|| {
            rar50::write_streaming_archive_with_progress(
                entries,
                WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(level),
                ArchiveExtras::default().with_filter_policy(FilterPolicy::Auto),
                &resources,
                None,
                &mut bytes,
            )
        })
        .unwrap_or_else(|error| {
            panic!("level {level}, solid {solid}, {threads} threads, ceiling {ceiling:?}: {error}")
        });
    assert_eq!(resources.managed_memory_in_use(), 0);
    bytes
}

#[test]
fn a_ceiling_changes_how_many_jobs_run_and_not_the_archive() {
    let entries = entries();
    for level in [1, 3, 5] {
        for solid in [false, true] {
            let expected = write(&entries, level, solid, 1, None);
            ArchiveReader::read(&expected).unwrap().test(None).unwrap();
            for threads in [1, 4] {
                assert!(
                    write(&entries, level, solid, threads, Some(1 << 30)) == expected,
                    "level {level}, solid {solid}, {threads} threads: \
                     a 1 GiB ceiling changes the archive"
                );
            }
        }
    }
}
