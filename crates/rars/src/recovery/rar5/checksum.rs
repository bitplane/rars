//! Checksum utilities independent of recovery generation and repair.

const CRC64_XZ_POLY: u64 = 0xc96c_5795_d787_0f42;
pub(super) const CRC64_XZ_INIT: u64 = 0xffff_ffff_ffff_ffff;

/// Sixteen bytes per step: the record CRCs cover the whole protected body.
static CRC64_XZ_TABLES: [[u64; 256]; 16] = crc64_xz_tables();

const fn crc64_xz_tables() -> [[u64; 256]; 16] {
    let mut tables = [[0u64; 256]; 16];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u64;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (CRC64_XZ_POLY & 0u64.wrapping_sub(crc & 1));
            bit += 1;
        }
        tables[0][byte] = crc;
        byte += 1;
    }
    let mut table = 1;
    while table < 16 {
        let mut byte = 0;
        while byte < 256 {
            let previous = tables[table - 1][byte];
            tables[table][byte] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            byte += 1;
        }
        table += 1;
    }
    tables
}

pub fn crc64_xz(data: &[u8]) -> u64 {
    crc64_update(data, CRC64_XZ_INIT) ^ CRC64_XZ_INIT
}

pub(super) fn crc64_update(data: &[u8], initial: u64) -> u64 {
    let t = &CRC64_XZ_TABLES;
    let mut crc = initial;
    let (blocks, tail) = data.as_chunks::<16>();
    for block in blocks {
        let (low, high) = block.split_at(8);
        let low = crc ^ u64::from_le_bytes(low.try_into().expect("eight bytes"));
        let low = low.to_le_bytes();
        crc = t[15][low[0] as usize]
            ^ t[14][low[1] as usize]
            ^ t[13][low[2] as usize]
            ^ t[12][low[3] as usize]
            ^ t[11][low[4] as usize]
            ^ t[10][low[5] as usize]
            ^ t[9][low[6] as usize]
            ^ t[8][low[7] as usize]
            ^ t[7][high[0] as usize]
            ^ t[6][high[1] as usize]
            ^ t[5][high[2] as usize]
            ^ t[4][high[3] as usize]
            ^ t[3][high[4] as usize]
            ^ t[2][high[5] as usize]
            ^ t[1][high[6] as usize]
            ^ t[0][high[7] as usize];
    }
    for &byte in tail {
        crc = t[0][((crc ^ byte as u64) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

pub fn crc64_rar_state(data: &[u8]) -> u64 {
    crc64_update(data, 0)
}

#[cfg(test)]
mod tests {
    use super::{crc64_update, CRC64_XZ_INIT, CRC64_XZ_POLY};

    fn bitwise(data: &[u8], initial: u64) -> u64 {
        let mut crc = initial;
        for &byte in data {
            crc ^= byte as u64;
            for _ in 0..8 {
                crc = (crc >> 1) ^ (CRC64_XZ_POLY & 0u64.wrapping_sub(crc & 1));
            }
        }
        crc
    }

    fn generated(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn sixteen_byte_steps_match_the_bitwise_crc_from_any_start_and_split() {
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4099] {
            let data = generated(len);
            for initial in [0, CRC64_XZ_INIT, 0x0123_4567_89ab_cdef] {
                let expected = bitwise(&data, initial);
                assert_eq!(crc64_update(&data, initial), expected, "{len} bytes");
                for split in [1, 3, 15, 16, 17, len / 2] {
                    let split = split.min(len);
                    let carried = crc64_update(&data[..split], initial);
                    assert_eq!(
                        crc64_update(&data[split..], carried),
                        expected,
                        "{len} bytes split at {split}"
                    );
                }
            }
        }
    }
}
