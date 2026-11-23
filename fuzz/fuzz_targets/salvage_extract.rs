#![no_main]

//! Salvage reading: parse, test and extract with a member error handler that
//! always carries on, as `rars test` and `rars x` do. Parsing then reads a
//! file cut through a member up to the cut, and in a solid archive each member
//! after a failed one decodes from whatever state the failed one left.
//!
//! Each input is read twice: once as above, and once with
//! `ArchiveReadOptions::with_salvage` as well, which reads past header
//! damage and delivers what a failed member decoded. The salvaging read also
//! extracts a second time with a small buffered limit, so RAR 5 members
//! stream, or for half the inputs decode through scratch files.

use libfuzzer_sys::fuzz_target;
use rars::{
    ArchiveMember, ArchiveReadOptions, ArchiveReader, Error, ExtractionErrorAction, Rar50Scratch,
};
use std::sync::OnceLock;

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

/// A directory of this process's own for scratch files, which are removed
/// as each member finishes. `RARS_FUZZ_SCRATCH` picks where it goes.
fn scratch() -> &'static Rar50Scratch {
    static SCRATCH: OnceLock<Rar50Scratch> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let root = std::env::var_os("RARS_FUZZ_SCRATCH")
            .map(Into::into)
            .unwrap_or_else(std::env::temp_dir);
        let dir = root.join(format!("rars-fuzz-scratch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Rar50Scratch::new(dir, 4 * 1024 * 1024).with_filter_memory_limit(1024 * 1024)
    })
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
    if salvage {
        // Half the inputs stream their larger RAR 5 members, half decode
        // them through scratch files.
        let mut streamed = options(salvage)
            .with_threads(1)
            .with_max_total_output_bytes(4 * 1024 * 1024)
            .with_rar50_buffered_decode_limit(4096);
        if data.len() % 2 == 0 {
            streamed = streamed.with_rar50_scratch(scratch());
        }
        let _ =
            archive.extract_with_links(streamed, |_| Ok(Box::new(std::io::sink())), |_, _| Ok(()));
    }
}
