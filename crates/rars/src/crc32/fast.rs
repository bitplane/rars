#[cfg(feature = "fast")]
use std::simd::{num::SimdUint, Simd};

#[cfg(feature = "fast")]
const LANES: usize = 8;

#[cfg(feature = "fast")]
pub(crate) fn update_raw(mut crc: u32, mut input: &[u8]) -> u32 {
    while input.len() >= 8 {
        let word = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        crc ^= word;

        let indices = Simd::<usize, LANES>::from_array([
            7 * 256 + (crc & 0xff) as usize,
            6 * 256 + ((crc >> 8) & 0xff) as usize,
            5 * 256 + ((crc >> 16) & 0xff) as usize,
            4 * 256 + ((crc >> 24) & 0xff) as usize,
            3 * 256 + input[4] as usize,
            2 * 256 + input[5] as usize,
            256 + input[6] as usize,
            input[7] as usize,
        ]);
        crc = Simd::<u32, LANES>::gather_or_default(&super::TABLES_FLAT, indices).reduce_xor();
        input = &input[8..];
    }

    for &byte in input {
        crc = super::update_raw_byte(crc, byte);
    }
    crc
}
