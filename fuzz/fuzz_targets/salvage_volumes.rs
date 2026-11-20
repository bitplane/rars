#![no_main]

//! Salvage reading of a partial volume set, as `rars test` and `rars x` read
//! one: parse each volume with a member error handler that always carries on,
//! drop the split members whose start or end is missing, then test and
//! extract what is left to a sink.
//!
//! The input is one to three volumes. The first byte gives the count (its
//! value mod 3, plus one), and each volume but the last is preceded by its
//! length as a little-endian `u16`; the last takes the rest. A length past the
//! end is cut short. `salvage_seeds.py` writes seeds in this layout.

use libfuzzer_sys::fuzz_target;
use rars::{
    drop_incomplete_members, extract_volumes_with_links, test_volumes_with_options_and_callback,
    ArchiveMember, ArchiveReadOptions, ArchiveReader, Error, ExtractionErrorAction,
};

const MAX_INPUT_SIZE: usize = 1024 * 1024;

fn carry_on(_: &ArchiveMember, _: &Error) -> rars::Result<ExtractionErrorAction> {
    Ok(ExtractionErrorAction::Continue)
}

fn options() -> ArchiveReadOptions<'static> {
    ArchiveReadOptions::new()
        .with_max_header_count(64)
        .with_max_header_bytes(256 * 1024)
        .with_max_member_output_bytes(1024 * 1024)
        .with_rar50_dictionary_size_limit(8 * 1024 * 1024)
        .with_rar50_buffered_decode_limit(1024 * 1024)
        .with_rar3_vm_programs(true)
        .with_member_error_handler(&carry_on)
}

fn split(data: &[u8]) -> Vec<&[u8]> {
    let Some((&count, mut rest)) = data.split_first() else {
        return Vec::new();
    };
    let count = usize::from(count % 3) + 1;
    let mut volumes = Vec::with_capacity(count);
    for _ in 1..count {
        let Some((length, tail)) = rest.split_first_chunk::<2>() else {
            break;
        };
        let length = usize::from(u16::from_le_bytes(*length)).min(tail.len());
        let (volume, tail) = tail.split_at(length);
        volumes.push(volume);
        rest = tail;
    }
    volumes.push(rest);
    volumes
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }
    // A volume that fails to parse is left out, as if its file were missing,
    // so the ones either side of it need not belong together.
    let mut archives: Vec<_> = split(data)
        .into_iter()
        .filter_map(|volume| ArchiveReader::read_with_options(volume, options()).ok())
        .collect();
    if archives.is_empty() {
        return;
    }
    let _ = drop_incomplete_members(&mut archives);
    let extract = options()
        .with_threads(1)
        .with_max_total_output_bytes(4 * 1024 * 1024);
    if let [archive] = archives.as_slice() {
        let _ = archive.test_with_options_and_callback(options().with_threads(2), |_| Ok(()));
        let _ =
            archive.extract_with_links(extract, |_| Ok(Box::new(std::io::sink())), |_, _| Ok(()));
        return;
    }
    let _ =
        test_volumes_with_options_and_callback(&archives, options().with_threads(2), |_| Ok(()));
    let _ = extract_volumes_with_links(
        &archives,
        extract,
        |_| Ok(Box::new(std::io::sink())),
        |_, _| Ok(()),
    );
});
