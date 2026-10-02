//! Checksum utilities independent of recovery generation and repair.

const CRC64_XZ_POLY: u64 = 0xc96c_5795_d787_0f42;
pub(super) const CRC64_XZ_INIT: u64 = 0xffff_ffff_ffff_ffff;

pub fn crc64_xz(data: &[u8]) -> u64 {
    crc64_update(data, CRC64_XZ_INIT) ^ CRC64_XZ_INIT
}

pub(super) fn crc64_update(data: &[u8], initial: u64) -> u64 {
    let mut crc = initial;
    for &byte in data {
        crc ^= byte as u64;
        for _ in 0..8 {
            let mask = 0u64.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC64_XZ_POLY & mask);
        }
    }
    crc
}

pub fn crc64_rar_state(data: &[u8]) -> u64 {
    crc64_update(data, 0)
}
