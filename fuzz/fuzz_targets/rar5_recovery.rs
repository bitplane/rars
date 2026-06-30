#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::rar50::{repair_inline_recovery_bytes, Rev5Volume, Rev5VolumeMeta};
use rars::recovery::rar5::{
    build_structural_inline_recovery_data, repair_inline_recovery_archive,
    repair_inline_recovery_prefix,
};

const MAX_PREFIX_SIZE: usize = 256 * 1024;
const MAX_RAW_SIZE: usize = 512 * 1024;

fuzz_target!(|data: &[u8]| {
    let raw = &data[..data.len().min(MAX_RAW_SIZE)];
    let _ = Rev5VolumeMeta::parse(raw);
    let _ = Rev5Volume::parse(raw);
    let _ = repair_inline_recovery_archive(raw);
    let _ = repair_inline_recovery_bytes(raw);

    if raw.len() < 3 {
        return;
    }
    let percent = 1 + u64::from(raw[0] % 100);
    let split = 1 + (usize::from(raw[1]) % (raw.len() - 1));
    let prefix = &raw[2..][..(split - 1).min(raw.len() - 2).min(MAX_PREFIX_SIZE)];
    let Ok(recovery_data) = build_structural_inline_recovery_data(prefix, percent) else {
        return;
    };
    let _ = repair_inline_recovery_prefix(prefix, &recovery_data);
});
