//! RAR 5 variable-length integers, for tests that read or patch headers by hand.

#![allow(dead_code)]

/// Reads the vint at `*at` and moves `*at` past it.
pub fn read_vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
    }
    panic!("vint longer than ten bytes");
}

/// `value` in the fewest vint bytes.
pub fn vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}
