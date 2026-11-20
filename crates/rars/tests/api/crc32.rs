use rars::crc32::*;

use rars::crc32::{crc32, Crc32};

#[test]
fn combining_two_crcs_matches_the_crc_of_both_runs() {
    let data: Vec<u8> = (0..5000u32).map(|n| (n * 31 % 251) as u8).collect();
    for split in [0, 1, 7, 64, 4999, 5000] {
        let (first, second) = data.split_at(split);
        assert_eq!(
            crc32_combine(crc32(first), crc32(second), second.len() as u64),
            crc32(&data),
            "split at {split}"
        );
    }
}

#[test]
fn crc32_matches_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn default_accumulator_uses_the_standard_seed_and_finalization() {
    assert_eq!(Crc32::default().finish(), 0);
    let mut crc = Crc32::default();
    crc.update(b"1234");
    crc.update(b"");
    crc.update(b"56789");
    assert_eq!(crc.finish(), 0xcbf4_3926);
}

#[test]
fn raw_crc_matches_unfinalized_seeded_rar15_value() {
    assert_eq!(crc32_raw(b"password"), 0xca3d_b92a);
}

#[test]
fn update_zeroes_matches_byte_update() {
    let mut skipped = Crc32::new();
    skipped.update(b"prefix");
    skipped.update_zeroes(1024);
    skipped.update(b"suffix");

    let mut bytewise = Crc32::new();
    bytewise.update(b"prefix");
    bytewise.update(&[0; 1024]);
    bytewise.update(b"suffix");

    assert_eq!(skipped.finish(), bytewise.finish());
}

fn reference_crc32(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in input {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    out
}

#[test]
fn crc32_matches_bitwise_reference_across_chunk_boundaries() {
    for len in 0..=257 {
        let input = deterministic_bytes(len);
        assert_eq!(crc32(&input), reference_crc32(&input), "len {len}");
    }

    for len in [1024, 4095, 4096, 4097, 65_536] {
        let input = deterministic_bytes(len);
        assert_eq!(crc32(&input), reference_crc32(&input), "len {len}");
    }
}

#[test]
fn table_entry_matches_bitwise_generation() {
    assert_eq!(table_entry(0), 0);
    assert_eq!(table_entry(1), 0x7707_3096);
    assert_eq!(table_entry(0xff), 0x2d02_ef8d);
}
