#![cfg(all(feature = "write", feature = "parallel", target_os = "linux"))]

//! Testing an archive of small RAR 3 PPMd members must not hold the whole
//! declared model resident on every worker (#553). Each member's model is
//! 25 MB, RAR 3's default, of which a few kilobytes of text reach a few
//! pages. With glibc, once the first model is freed each later one comes back
//! from the heap cleared in full, so four workers can hold 100 MiB.
//!
//! Real use is resident memory, read from `/proc`. The test is the only one
//! in its binary, so nothing else runs in the process.

use rars::rar15_40::{self, FileEntry, FilterPolicy, Rar29Method, WriterOptions};
use rars::{ArchiveReader, ArchiveVersion, FeatureSet};

const MIB: u64 = 1024 * 1024;

/// One field of `/proc/self/status`, in bytes.
fn status(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .unwrap_or_else(|| panic!("no {field} in /proc/self/status"));
    let kib: u64 = line[field.len()..]
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .unwrap();
    kib * 1024
}

fn text(member: usize) -> Vec<u8> {
    format!("member {member}: a short source file, coded as PPMd text\n")
        .into_bytes()
        .repeat(64 + member)
}

#[test]
fn small_ppmd_members_hold_only_what_their_models_reach() {
    let names: Vec<_> = (0..32).map(|member| format!("{member}.txt")).collect();
    let texts: Vec<_> = (0..names.len()).map(text).collect();
    let entries: Vec<_> = names
        .iter()
        .zip(&texts)
        .map(|(name, data)| FileEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        })
        .collect();
    let bytes = rar15_40::write_rar29_compressed_archive_with_filter_policy(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
            .with_method(Rar29Method::Ppmd),
        FilterPolicy::None,
    )
    .unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    // Start counting from here: reset the high-water mark where the kernel
    // allows it, and otherwise count it from the resident set, which can
    // only overstate what the test used.
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let before = status("VmRSS:");
    pool.install(|| archive.test(None)).unwrap();
    let used = status("VmHWM:").saturating_sub(before);
    // Four workers each holding a whole model would be 100 MiB.
    assert!(
        used <= 16 * MIB,
        "{} MiB resident testing 32 small PPMd members on four workers",
        used / MIB
    );
}
