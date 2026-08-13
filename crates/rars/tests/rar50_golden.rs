//! Byte-for-byte golden fixtures for structural RAR 5/7 writer output.
//!
//! These cover *stored* archives only. Their bytes exercise header layout,
//! locator records, quick-open, recovery records, comments, metadata and
//! volume splitting without involving the LZ encoder, so they must stay
//! identical across writer refactors. Compressed output is deliberately
//! excluded: block granularity is an implementation detail that the streaming
//! writer is expected to change, and it is covered by round-trip and external
//! `unrar` tests instead.
//!
//! Regenerate after an intentional format change with:
//! `RARS_BLESS_GOLDEN=1 cargo test -p rars --test rar50_golden`

use rars::rar50::{
    ArchiveMetadataEntry, Rar50VolumeWriter, Rar50Writer, StoredEntry, WriterOptions,
};
use rars::{ArchiveVersion, Error, FeatureSet};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden")
}

fn blessing() -> bool {
    std::env::var_os("RARS_BLESS_GOLDEN").is_some()
}

/// Deterministic, mildly compressible bytes so recovery parity has real work
/// to do while fixtures stay reviewable.
fn deterministic_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|index| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if index % 7 == 0 {
                b'A' + (index % 23) as u8
            } else {
                (state >> 24) as u8
            }
        })
        .collect()
}

fn entry<'a>(name: &'a [u8], data: &'a [u8]) -> StoredEntry<'a> {
    StoredEntry {
        name,
        data,
        mtime: Some(0x5000_0000),
        attributes: 0x20,
        host_os: 0,
    }
}

fn assert_golden(name: &str, produced: &[u8]) {
    let path = golden_dir().join(name);
    if blessing() {
        std::fs::create_dir_all(golden_dir()).expect("create golden fixture directory");
        std::fs::write(&path, produced).expect("write golden fixture");
        return;
    }

    let expected = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden fixture {}: {error}\n\
             regenerate with RARS_BLESS_GOLDEN=1 cargo test -p rars --test rar50_golden",
            path.display()
        )
    });

    if expected == produced {
        return;
    }

    let first_difference = expected
        .iter()
        .zip(produced)
        .position(|(left, right)| left != right);
    panic!(
        "{} changed: golden is {} bytes, produced {} bytes, first difference at {:?}\n\
         if this change is intentional, regenerate with \
         RARS_BLESS_GOLDEN=1 cargo test -p rars --test rar50_golden",
        name,
        expected.len(),
        produced.len(),
        first_difference
    );
}

/// Large fixtures are pinned by digest rather than stored whole, so the repo
/// does not carry hundreds of kilobytes of binary per case.
fn assert_golden_digest(name: &str, produced: &[u8]) {
    let hash = Sha256::digest(produced)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let digest = format!("{hash}  {} bytes\n", produced.len());
    let path = golden_dir().join(name);
    if blessing() {
        std::fs::create_dir_all(golden_dir()).expect("create golden fixture directory");
        std::fs::write(&path, digest).expect("write golden digest");
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden digest {}: {error}\n\
             regenerate with RARS_BLESS_GOLDEN=1 cargo test -p rars --test rar50_golden",
            path.display()
        )
    });
    assert_eq!(
        expected, digest,
        "{name} digest changed; if intentional, regenerate with \
         RARS_BLESS_GOLDEN=1 cargo test -p rars --test rar50_golden"
    );
}

fn stored_options(target: ArchiveVersion) -> WriterOptions {
    WriterOptions::new(target, FeatureSet::store_only())
}

fn write_stored(entries: &[StoredEntry<'_>], options: WriterOptions) -> Result<Vec<u8>, Error> {
    Rar50Writer::new(options).stored_entries(entries).finish()
}

#[test]
fn golden_stored_archive_layout_is_stable() {
    let first = deterministic_bytes(4096, 1);
    let second = deterministic_bytes(37, 2);
    let entries = [entry(b"first.bin", &first), entry(b"second.bin", &second)];

    assert_golden(
        "stored_rar50.rar",
        &write_stored(&entries, stored_options(ArchiveVersion::Rar50)).unwrap(),
    );
    assert_golden(
        "stored_rar70.rar",
        &write_stored(&entries, stored_options(ArchiveVersion::Rar70)).unwrap(),
    );
}

#[test]
fn golden_comment_and_metadata_layout_is_stable() {
    let data = deterministic_bytes(1024, 3);
    let entries = [entry(b"payload.bin", &data)];

    let mut features = FeatureSet::store_only();
    features.archive_comment = true;
    let options = WriterOptions::new(ArchiveVersion::Rar50, features);

    let commented = Rar50Writer::new(options)
        .stored_entries(&entries)
        .archive_comment(Some(b"golden archive comment"))
        .finish()
        .unwrap();
    assert_golden("stored_comment.rar", &commented);

    let with_metadata = Rar50Writer::new(options)
        .stored_entries(&entries)
        .archive_comment(Some(b"golden archive comment"))
        .archive_metadata(Some(ArchiveMetadataEntry {
            name: Some(b"golden.rar"),
            creation_time: Some(0x01D9_0000_0000_0000),
        }))
        .finish()
        .unwrap();
    assert_golden("stored_comment_metadata.rar", &with_metadata);
}

#[test]
fn golden_quick_open_layout_is_stable() {
    let data = deterministic_bytes(2048, 4);
    let entries = [
        entry(b"alpha.bin", &data),
        entry(b"beta.bin", &data[..512]),
        entry(b"gamma.bin", &data[..7]),
    ];

    let mut features = FeatureSet::store_only();
    features.quick_open = true;
    let options = WriterOptions::new(ArchiveVersion::Rar50, features);

    assert_golden(
        "stored_quick_open.rar",
        &write_stored(&entries, options).unwrap(),
    );
}

#[test]
fn golden_recovery_record_layout_is_stable() {
    let data = deterministic_bytes(8192, 5);
    let entries = [entry(b"protected.bin", &data)];

    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
    let options = WriterOptions::new(ArchiveVersion::Rar50, features);

    for percent in [1u64, 5, 10, 50] {
        let archive = Rar50Writer::new(options)
            .stored_entries(&entries)
            .recovery_percent(Some(percent))
            .finish()
            .unwrap();
        assert_golden(&format!("stored_recovery_{percent}.rar"), &archive);
    }
}

#[test]
fn golden_recovery_record_over_200kib_is_stable() {
    // Above 200 KiB the recovery planner switches to the fixed 200-data-shard
    // layout, which is the case real archives hit.
    let data = deterministic_bytes(300 * 1024, 6);
    let entries = [entry(b"large.bin", &data)];

    let mut features = FeatureSet::store_only();
    features.recovery_record = true;
    let options = WriterOptions::new(ArchiveVersion::Rar50, features);

    let archive = Rar50Writer::new(options)
        .stored_entries(&entries)
        .recovery_percent(Some(10))
        .finish()
        .unwrap();
    assert_golden_digest("stored_recovery_large.sha256", &archive);
}

#[test]
fn golden_volume_set_layout_is_stable() {
    let data = deterministic_bytes(5000, 7);
    let options = stored_options(ArchiveVersion::Rar50);

    let volumes = Rar50VolumeWriter::new(options)
        .stored_entry(entry(b"split.bin", &data))
        .max_payload_per_volume(1500)
        .finish()
        .unwrap();

    assert!(volumes.len() > 1, "expected a multi-volume set");
    for (index, volume) in volumes.iter().enumerate() {
        assert_golden(&format!("stored_volume_{index}.rar"), volume);
    }
}
