#![cfg(all(feature = "write", feature = "parallel", target_os = "linux"))]

//! Block jobs are admitted for what they hold rather than their planning
//! charge (#315), so a wave runs more of them in the same budget. This checks
//! that what they really hold still fits that budget, on the input that holds
//! the most: two-symbol noise, whose every position reports a long list of
//! matches, and which is not text, so every run is searched for filters too.
//!
//! Real use is resident memory, read from `/proc`, so allocator overhead and
//! what glibc keeps after a free count against the budget as well. The test
//! is the only one in its binary, so nothing else runs in the process.

#[path = "support/scratch.rs"]
mod scratch;

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{ArchiveVersion, EntrySource, FeatureSet, WriterResources};

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

fn noise(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut data = Vec::with_capacity(size);
    for _ in 0..size {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        data.push((state >> 63) as u8);
    }
    data
}

#[test]
fn admitted_block_jobs_stay_inside_the_budget_on_noise() {
    // A 1 MiB dictionary makes 1 MiB runs. Planned at 190 MiB, a 3 MiB
    // member is too large to code whole (192 MiB) and each run's search
    // fits (184 MiB). A job is admitted for 120 MiB, so this budget runs
    // three at once, where planning charges admitted two. Three peaked at
    // 271 MiB allocated and 355 MiB resident: glibc keeps what worker
    // threads free in their own arenas (#276), and that counts here too.
    const BUDGET: u64 = 400 * MIB;
    let scratch = scratch::case("rar50-admission-memory");
    let entries: Vec<_> = (0..4)
        .map(|member| {
            ArchiveEntry::new(
                format!("noise{member}.bin"),
                EntrySource::from_bytes(noise(3 * MIB as usize, member + 1)),
            )
        })
        .collect();
    let resources = WriterResources::new(190 * MIB)
        .with_memory_limit(BUDGET)
        .with_temp_dir(&*scratch);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    // Start counting from here: reset the high-water mark where the kernel
    // allows it, and otherwise count it from the resident set, which can
    // only overstate what the write used.
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let before = status("VmRSS:");
    pool.install(|| {
        rar50::write_streaming_archive_with_progress(
            &entries,
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                .with_compression_level(3)
                .with_dictionary_size(MIB),
            ArchiveExtras::default().with_filter_policy(FilterPolicy::Auto),
            &resources,
            None,
            &mut std::io::sink(),
        )
    })
    .unwrap();
    let used = status("VmHWM:").saturating_sub(before);
    assert!(
        used <= BUDGET,
        "{} MiB resident beyond the {} MiB budget",
        used / MIB,
        BUDGET / MIB
    );
}
