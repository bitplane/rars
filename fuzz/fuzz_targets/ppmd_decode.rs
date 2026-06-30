#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::codec::rar29::Unpack29;

const MAX_OUTPUT_SIZE: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let output_size = u16::from_le_bytes([data[0], data[1]]) as usize % (MAX_OUTPUT_SIZE + 1);
    let mut packed = Vec::with_capacity(data.len() + 3);
    packed.push(0x80 | 0x40 | 0x20 | 3);
    packed.push(15);
    packed.push(2);
    packed.extend_from_slice(&data[2..]);
    let mut decoder = Unpack29::new();
    let _ = decoder.decode_non_solid_member(&packed, output_size);
});
