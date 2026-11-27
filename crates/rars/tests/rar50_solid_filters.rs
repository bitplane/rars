#![cfg(feature = "write")]

//! A solid archive chooses filters too: for each run of each member, with x86
//! addresses converted from the member's own offset and not the stream's.

#[path = "support/scratch.rs"]
mod scratch;

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, WriterResources};

const KIB: usize = 1024;

/// A few instructions before each call to one of eight targets, at no fixed
/// stride. The calls only repeat once the E8 filter makes them absolute, and
/// they only become the same absolute addresses in every member if each
/// member is converted from its own start.
fn code(size: usize, seed: u64) -> Vec<u8> {
    const FILLER: [u8; 13] = [
        0x48, 0x89, 0x8b, 0xc3, 0x83, 0x0f, 0x85, 0x31, 0xff, 0x74, 0x41, 0x66, 0x90,
    ];
    const TARGETS: [u32; 8] = [
        0x1000, 0x2340, 0x8800, 0x10000, 0x23456, 0x40000, 0x7f000, 0x12_3456,
    ];
    let mut state = seed;
    let mut data = Vec::with_capacity(size);
    while data.len() + 18 <= size {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        data.extend_from_slice(&FILLER[..7 + 2 * ((state >> 40) as usize % 4)]);
        let target = TARGETS[(state >> 33) as usize % TARGETS.len()];
        let at = data.len();
        data.push(0xe8);
        data.extend_from_slice(&target.wrapping_sub(at as u32 + 5).to_le_bytes());
    }
    data.resize(size, 0x90);
    data
}

fn text(size: usize) -> Vec<u8> {
    b"A solid archive shares one dictionary between its members. "
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
}

/// Code before and after text, members smaller than a block and larger than a
/// run, and one that is empty. With a 128 KiB dictionary a run is 1 MiB, so
/// the 1.25 MiB member is cut and its second run starts mid-member.
fn members() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("first.bin", code(200 * KIB, 1)),
        ("notes.txt", text(40 * KIB)),
        ("tiny.bin", code(3 * KIB, 2)),
        ("empty", Vec::new()),
        ("large.bin", code(1280 * KIB, 3)),
        ("last.bin", code(200 * KIB, 4)),
    ]
}

fn write(policy: FilterPolicy, resources: &WriterResources) -> Vec<u8> {
    let entries: Vec<_> = members()
        .into_iter()
        .map(|(name, data)| ArchiveEntry::new(name, EntrySource::from_bytes(data)))
        .collect();
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let mut bytes = Vec::new();
    // Runs follow the dictionary, not the level, and level 2 still searches
    // filters for each run. Its lazy parse still packs the filtered archive
    // to under half the plain one, at a fraction of level 3's cost, and the
    // filtered archive is written twice: once per thread count.
    rar50::write_streaming_archive_with_progress(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar50, features)
            .with_compression_level(2)
            .with_dictionary_size(128 * 1024),
        ArchiveExtras::default().with_filter_policy(policy),
        resources,
        None,
        &mut bytes,
    )
    .unwrap();
    bytes
}

#[test]
fn a_solid_archive_filters_each_member_from_its_own_offset() {
    let root = scratch::case("rar50-solid-filters");
    let resources = WriterResources::default().with_temp_dir(&root);
    let filtered = write(FilterPolicy::Auto, &resources);
    let plain = write(FilterPolicy::None, &resources);

    let archive = ArchiveReader::read(&filtered).unwrap();
    archive.test(None).unwrap();
    for (name, data) in members() {
        assert_eq!(
            archive.read_member(name.as_bytes(), None).unwrap().unwrap(),
            data,
            "{name}"
        );
    }
    assert!(
        filtered.len() * 2 < plain.len(),
        "filters took {} down only to {}",
        plain.len(),
        filtered.len()
    );

    // The filters are chosen run by run, so the worker count has no say.
    #[cfg(feature = "parallel")]
    {
        let one = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(|| write(FilterPolicy::Auto, &resources));
        assert!(one == filtered, "one thread packed differently");
    }
}
