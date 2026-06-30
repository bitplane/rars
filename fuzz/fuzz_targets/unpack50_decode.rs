#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::codec::rar50::{DecodeMode, Unpack50Decoder};

const MAX_INPUT_SIZE: usize = 128 * 1024;
const MAX_OUTPUT_SIZE: usize = 128 * 1024;
const MAX_DICTIONARY_SIZE: usize = 512 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let algorithm_version = data[0] & 1;
    let mode = match data[1] % 3 {
        0 => DecodeMode::LiteralOnly,
        1 => DecodeMode::Lz,
        _ => DecodeMode::LzNoFilters,
    };
    let solid = data[2] & 1 != 0;
    let output_size = u16::from_le_bytes([data[3], data[4]]) as usize % (MAX_OUTPUT_SIZE + 1);
    let dictionary_size =
        1 + (u16::from_le_bytes([data[1], data[2]]) as usize % MAX_DICTIONARY_SIZE);
    let packed = &data[5..data.len().min(5 + MAX_INPUT_SIZE)];

    let mut decoder = Unpack50Decoder::new();
    let _ = decoder.decode_member_with_dictionary(
        packed,
        algorithm_version,
        output_size,
        dictionary_size,
        solid,
        mode,
    );
});
