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
//!
//! The salvaging read is done twice more: parsing only from a seekable
//! reader, which takes the parsers' other path, and on a copy with a stretch
//! a quarter of the way in overwritten, so that most inputs have a block
//! header that doesn't parse with the fuzzer's bytes after it. That drives
//! the resync scan and, in RAR 5, the quick-open fallback.

use libfuzzer_sys::fuzz_target;
use rars::{
    ArchiveMember, ArchiveReadOptions, ArchiveReader, Error, ExtractionErrorAction, Rar50Scratch,
};
use std::io::Cursor;
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
    read_damaged(data);
});

fn read(data: &[u8], salvage: bool) {
    let Ok(archive) = ArchiveReader::read_with_options(data, options(salvage)) else {
        return;
    };
    extract(&archive, data.len(), salvage);
    if salvage {
        // Only the parse differs from a seekable reader.
        if let Ok(archive) =
            ArchiveReader::read_reader_with_options(Cursor::new(data.to_vec()), options(true))
        {
            let _ = archive.header_damage();
        }
    }
}

/// Salvages a copy with 12 bytes a quarter of the way in set to 0xff: a
/// RAR 1.5-4 header size under its fixed fields, or a RAR 5 one that never
/// ends, wherever a header starts there. RAR 3 VM programs stay refused
/// here: one that runs to the instruction limit is slow enough already in
/// the passes above.
fn read_damaged(data: &[u8]) {
    let at = data.len() / 4;
    if at < 16 {
        return;
    }
    let mut damaged = data.to_vec();
    let end = (at + 12).min(damaged.len());
    damaged[at..end].fill(0xff);
    let options = || options(true).with_rar3_vm_programs(false);
    if let Ok(archive) = ArchiveReader::read_with_options(&damaged, options()) {
        let _ = archive.header_damage();
        let _ = archive.extract_with_links(
            options()
                .with_threads(1)
                .with_max_total_output_bytes(4 * 1024 * 1024),
            |_| Ok(Box::new(std::io::sink())),
            |_, _| Ok(()),
        );
    }
}

fn extract(archive: &rars::Archive, len: usize, salvage: bool) {
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
        if len % 2 == 0 {
            streamed = streamed.with_rar50_scratch(scratch());
        }
        let _ =
            archive.extract_with_links(streamed, |_| Ok(Box::new(std::io::sink())), |_, _| Ok(()));
    }
}
