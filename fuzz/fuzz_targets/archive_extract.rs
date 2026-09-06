#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::{ArchiveReadOptions, ArchiveReader};

const MAX_INPUT_SIZE: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }
    // Bound metadata and logical output before discarding it. A sink alone
    // cannot bound decoding. Dictionary admission is RAR5-specific, so the
    // runner must also impose process timeout and RSS limits (see README).
    let options = ArchiveReadOptions::new()
        .with_max_header_count(256)
        .with_max_header_bytes(256 * 1024)
        .with_max_member_output_bytes(1024 * 1024)
        .with_max_total_output_bytes(4 * 1024 * 1024)
        .with_rar50_dictionary_size_limit(8 * 1024 * 1024)
        .with_rar50_buffered_decode_limit(1024 * 1024);
    // No password: encrypted-input refusals are expected. Crypto primitives
    // have dedicated targets; volume-set extraction is separate future work.
    if let Ok(archive) = ArchiveReader::read_with_options(data, options) {
        let _ = archive.extract_to_with_options(options, |_| Ok(Box::new(std::io::sink())));
    }
});
