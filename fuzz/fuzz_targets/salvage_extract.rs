#![no_main]

//! Salvage reading: parse, test and extract with a member error handler that
//! always carries on, as `rars test` and `rars x` do. Parsing then reads a
//! file cut through a member up to the cut, and in a solid archive each member
//! after a failed one decodes from whatever state the failed one left.
//!
//! Each input is read twice: once as above, and once with
//! `ArchiveReadOptions::with_salvage` as well, which reads past header
//! damage and delivers what a failed member decoded.

use libfuzzer_sys::fuzz_target;
use rars::{ArchiveMember, ArchiveReadOptions, ArchiveReader, Error, ExtractionErrorAction};

const MAX_INPUT_SIZE: usize = 1024 * 1024;

fn carry_on(_: &ArchiveMember, _: &Error) -> rars::Result<ExtractionErrorAction> {
    Ok(ExtractionErrorAction::Continue)
}

fn options(salvage: bool) -> ArchiveReadOptions<'static> {
    ArchiveReadOptions::new()
        .with_max_header_count(64)
        .with_max_header_bytes(256 * 1024)
        .with_max_member_output_bytes(1024 * 1024)
        .with_rar50_dictionary_size_limit(8 * 1024 * 1024)
        .with_rar50_buffered_decode_limit(1024 * 1024)
        .with_rar3_vm_programs(true)
        .with_member_error_handler(&carry_on)
        .with_salvage(salvage)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }
    for salvage in [false, true] {
        read(data, salvage);
    }
});

fn read(data: &[u8], salvage: bool) {
    let Ok(archive) = ArchiveReader::read_with_options(data, options(salvage)) else {
        return;
    };
    let _ = archive.truncation();
    let _ = archive.header_damage();
    // Testing on two threads takes the batch path, where a worker's error
    // waits for its place in archive order. Salvage tests on one.
    let _ = archive.test_with_options_and_callback(options(salvage).with_threads(2), |_| Ok(()));
    // Extraction as the CLI does it, sequentially under a total output cap.
    let _ = archive.extract_with_links(
        options(salvage)
            .with_threads(1)
            .with_max_total_output_bytes(4 * 1024 * 1024),
        |_| Ok(Box::new(std::io::sink())),
        |_, _| Ok(()),
    );
}
