#![cfg(feature = "write")]

//! A member too large to filter whole still gets filters, chosen run by run or
//! asked for, and runs that start mid-member convert x86 addresses from their
//! own offset.

#[path = "support/scratch.rs"]
mod scratch;

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{
    ArchiveReader, ArchiveVersion, EntrySource, FeatureSet, FilterKind, FilterSpec, WriterResources,
};

const MIB: u64 = 1024 * 1024;
const MEMBER: usize = 2 << 20;
/// Below the 2 MiB member's whole-member charge (173.1 MiB at a 128 KiB
/// dictionary) and above one 1 MiB run's filter search (169.1 MiB), so the
/// member is coded run by run and each run still searches.
const LIMIT: u64 = 171 * MIB;

/// The same few instructions before each call to one of eight targets. Once
/// the E8 filter makes the addresses absolute, the member is eight records.
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

fn write(data: &[u8], policy: FilterPolicy, resources: &WriterResources) -> Vec<u8> {
    let entries = [ArchiveEntry::new(
        "code",
        EntrySource::from_bytes(data.to_vec()),
    )];
    let mut bytes = Vec::new();
    rar50::write_streaming_archive_with_progress(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
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
fn runs_of_a_large_member_choose_their_own_filters() {
    let root = scratch::case("rar50-large-member-filters");
    let data = code(MEMBER);
    // The plain archive is only the yardstick, and it packs to the same bytes
    // with or without the ledger, so one serves both.
    let plain = write(
        &data,
        FilterPolicy::None,
        &WriterResources::new(LIMIT).with_temp_dir(&root),
    );
    for ledger in [None, Some(4 * 1024 * MIB)] {
        let resources = WriterResources::new(LIMIT).with_temp_dir(&root);
        let resources = match ledger {
            Some(limit) => resources.with_max_memory_bytes(limit),
            None => resources,
        };
        let filtered = write(&data, FilterPolicy::Auto, &resources);

        let archive = ArchiveReader::read(&filtered).unwrap();
        archive.test(None).unwrap();
        assert_eq!(archive.read_member(b"code", None).unwrap().unwrap(), data);
        assert!(
            filtered.len() * 4 < plain.len() * 3,
            "filters took {} down only to {}",
            plain.len(),
            filtered.len()
        );
    }
}

#[test]
fn an_explicit_filter_too_large_to_apply_whole_is_applied_run_by_run() {
    let root = scratch::case("rar50-large-member-explicit-filter");
    let data = code(MEMBER);
    let resources = WriterResources::new(LIMIT).with_temp_dir(&root);
    let plain = write(&data, FilterPolicy::None, &resources);
    // The range starts and ends mid-run.
    for range in [None, Some(MEMBER / 3..MEMBER * 2 / 3)] {
        let spec = match range.clone() {
            Some(range) => FilterSpec::range(FilterKind::E8, range),
            None => FilterSpec::whole(FilterKind::E8),
        };
        let filtered = write(&data, FilterPolicy::Explicit(spec), &resources);

        let archive = ArchiveReader::read(&filtered).unwrap();
        archive.test(None).unwrap();
        assert_eq!(archive.read_member(b"code", None).unwrap().unwrap(), data);
        let covered = range.as_ref().map_or(MEMBER, |range| range.len());
        let saved = plain.len() - filtered.len();
        assert!(
            saved * 4 > plain.len() * covered / MEMBER,
            "{range:?} took {} down only to {}",
            plain.len(),
            filtered.len()
        );
    }
}
