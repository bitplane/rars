use rars::recovery::rar5::{
    build_structural_inline_recovery_data, crc64_rar_state, crc64_xz,
    encode_inline_recovery_parity, encode_parity_shards, make_encoder_matrix, plan_inline_recovery,
    reconstruct_data_shards, repair_inline_recovery_archive, repair_inline_recovery_prefix,
    repair_inline_recovery_prefix_shards, split_prefix_shard_ranges, split_prefix_shards, Gf16,
};

fn recovery_test_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|index| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if index % 5 == 0 {
                (index % 251) as u8
            } else {
                (state >> 24) as u8
            }
        })
        .collect()
}

#[test]
fn gf16_matches_rar5_polynomial_wrap() {
    let gf = Gf16::new();

    assert_eq!(gf.mul(0x8000, 2), 0x100b);
    assert_eq!(gf.mul(0, 0x1234), 0);
    assert_eq!(gf.mul(0x1234, 0), 0);
    assert_eq!(gf.mul(0, 0), 0);
    assert_eq!(gf.mul(1, 0x1234), 0x1234);
}

#[test]
fn crc64_xz_matches_reference_vectors() {
    assert_eq!(crc64_xz(b""), 0);
    assert_eq!(crc64_xz(b"123456789"), 0x995d_c9bb_df19_39fa);
    assert_eq!(crc64_xz(b"testtesttest"), 0x7b1c_2d23_0ede_b436);
}

#[test]
fn raw_crc64_state_matches_reference_vector() {
    assert_eq!(crc64_rar_state(b""), 0);
    assert_eq!(crc64_rar_state(b"te\x80st"), 0xb5db_f958_3a6e_ed4a);
}

#[test]
fn rar5_cauchy_encoder_matrix_uses_inverse_xor_denominators() {
    let gf = Gf16::new();
    let matrix = make_encoder_matrix(3, 2).unwrap();

    assert_eq!(matrix.len(), 2);
    assert_eq!(matrix[0].len(), 3);
    for (i, row) in matrix.iter().enumerate() {
        for (j, &cell) in row.iter().enumerate() {
            let denominator = ((i + 3) ^ j) as u16;
            assert_eq!(gf.mul(cell, denominator), 1);
        }
    }
}

#[test]
fn rar5_parity_encoder_generates_systematic_recovery_shards() {
    let first = [1, 0, 2, 0, 3, 0, 4, 0];
    let parity = encode_parity_shards(&[&first], 1).unwrap();

    assert_eq!(parity, [first.to_vec()]);
}

#[test]
fn rar5_parity_encoder_applies_cauchy_matrix_coefficients() {
    let gf = Gf16::new();
    let first = [1, 0, 2, 0];
    let second = [3, 0, 4, 0];
    let matrix = make_encoder_matrix(2, 2).unwrap();
    let parity = encode_parity_shards(&[&first, &second], 2).unwrap();

    for recovery_index in 0..2 {
        for word_index in 0..2 {
            let offset = word_index * 2;
            let left = u16::from_le_bytes([first[offset], first[offset + 1]]);
            let right = u16::from_le_bytes([second[offset], second[offset + 1]]);
            let expected =
                gf.mul(matrix[recovery_index][0], left) ^ gf.mul(matrix[recovery_index][1], right);
            assert_eq!(
                u16::from_le_bytes([
                    parity[recovery_index][offset],
                    parity[recovery_index][offset + 1],
                ]),
                expected
            );
        }
    }
}

#[test]
fn rar5_inline_recovery_parity_splits_and_encodes_prefix() {
    let prefix = b"RAR5 inline recovery parity payload input";
    let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();

    assert_eq!(plan, plan_inline_recovery(prefix.len() as u64, 10).unwrap());
    assert_eq!(parity.len(), plan.recovery_shards as usize);
    assert!(parity
        .iter()
        .all(|shard| shard.len() == plan.group_count as usize));

    let data_shards = split_prefix_shards(prefix, plan).unwrap();
    let shard_refs: Vec<&[u8]> = data_shards.iter().map(Vec::as_slice).collect();
    assert_eq!(
        parity,
        encode_parity_shards(&shard_refs, plan.recovery_shards as usize).unwrap()
    );
}

#[test]
fn rar5_structural_inline_recovery_data_writes_chunks_and_crc64() {
    let prefix = b"RAR5 structural inline recovery data";
    let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();
    let data = build_structural_inline_recovery_data(prefix, 10).unwrap();

    assert_eq!(data.len(), plan.payload_size().unwrap() as usize);
    for (shard_index, payload) in parity.iter().enumerate() {
        let chunk_start = shard_index * plan.shard_size as usize;
        let chunk = &data[chunk_start..chunk_start + plan.shard_size as usize];
        assert_eq!(&chunk[..4], b"{RB}");
        assert_eq!(
            u64::from_le_bytes(chunk[4..12].try_into().unwrap()),
            crc64_xz(&chunk[0x0c..])
        );
        assert_eq!(
            u32::from_le_bytes(chunk[0x0c..0x10].try_into().unwrap()) as u64,
            plan.shard_size
        );
        assert_eq!(
            u32::from_le_bytes(chunk[0x10..0x14].try_into().unwrap()) as u64,
            plan.header_size
        );
        assert_eq!(chunk[0x14], 1);
        assert_eq!(chunk[0x15], 1);
        assert_eq!(
            u64::from_le_bytes(chunk[0x22..0x2a].try_into().unwrap()),
            prefix.len() as u64
        );
        assert_eq!(
            u16::from_le_bytes(chunk[0x3e..0x40].try_into().unwrap()) as usize,
            shard_index
        );
        let shard_ranges = split_prefix_shard_ranges(prefix.len(), plan).unwrap();
        assert_eq!(
            u32::from_le_bytes(chunk[0x1e..0x22].try_into().unwrap()) as usize,
            shard_ranges.last().unwrap().len()
        );
        for (data_index, range) in shard_ranges.iter().enumerate() {
            let state_offset = 0x40 + data_index * 8;
            assert_eq!(
                u64::from_le_bytes(chunk[state_offset..state_offset + 8].try_into().unwrap()),
                crc64_rar_state(&prefix[range.clone()])
            );
        }
        assert_eq!(&chunk[plan.header_size as usize..], payload);
    }
}

#[test]
fn rar5_structural_inline_recovery_uses_shared_final_state() {
    let prefix: Vec<u8> = (0..(256 * 1024)).map(|index| index as u8).collect();
    let (plan, parity) = encode_inline_recovery_parity(&prefix, 20).unwrap();
    assert!(plan.recovery_shards > 1);
    let data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    let expected = crc64_rar_state(&parity[0]);

    for shard_index in 0..plan.recovery_shards as usize {
        let chunk_start = shard_index * plan.shard_size as usize;
        let final_state_offset = chunk_start + 0x40 + plan.data_shards as usize * 8;
        assert_eq!(
            u64::from_le_bytes(
                data[final_state_offset..final_state_offset + 8]
                    .try_into()
                    .unwrap()
            ),
            expected
        );
    }
}

#[test]
fn rar5_range_repair_restores_short_final_shard() {
    let prefix = recovery_test_bytes(10_001, 79);
    let plan = plan_inline_recovery(prefix.len() as u64, 20).unwrap();
    let final_start = (plan.data_shards as usize - 1) * plan.group_count as usize;
    assert!(final_start < prefix.len());
    assert!((prefix.len() - final_start) % 2 == 1);
    let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    let mut damaged = prefix.clone();
    damaged[final_start] ^= 1;
    let repaired = repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
        Ok(damaged[range].to_vec())
    })
    .unwrap();
    assert_eq!(
        repaired,
        vec![(final_start..prefix.len(), prefix[final_start..].to_vec())]
    );
}

#[test]
fn rar5_inline_recovery_repairs_single_damaged_data_shard() {
    let prefix: Vec<u8> = (0..32_000).map(|index| (index * 17) as u8).collect();
    let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    let mut damaged = prefix.clone();
    damaged[1500..1537].fill(0xa5);

    let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

    assert_eq!(repaired, prefix);
}

#[test]
fn rar5_inline_recovery_skips_damaged_recovery_chunks_if_enough_survive() {
    let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
    let mut recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    recovery_data[0x48] ^= 0xff;
    let mut damaged = prefix.clone();
    damaged[1024..1300].fill(0xa5);

    let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

    assert_eq!(repaired, prefix);
}

#[test]
fn rar5_inline_recovery_repairs_multiple_damaged_data_shards() {
    let prefix: Vec<u8> = (0..128_000).map(|index| (index * 31) as u8).collect();
    let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    let mut damaged = prefix.clone();
    damaged[100..500].fill(0x11);
    damaged[4_000..4_400].fill(0x22);
    damaged[9_000..9_400].fill(0x33);

    let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

    assert_eq!(repaired, prefix);
}

#[test]
fn rar5_inline_recovery_returns_only_repaired_shard_ranges() {
    let prefix: Vec<u8> = (0..128_000).map(|index| (index * 29) as u8).collect();
    let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    let mut damaged = prefix.clone();
    damaged[100..500].fill(0x11);
    damaged[9_000..9_400].fill(0x33);

    let repaired_shards =
        repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
            Ok(damaged[range].to_vec())
        })
        .unwrap();
    assert!(!repaired_shards.is_empty());

    let mut repaired = damaged;
    for (range, data) in repaired_shards {
        assert_eq!(range.len(), data.len());
        repaired[range].copy_from_slice(&data);
    }

    assert_eq!(repaired, prefix);
}

#[test]
fn rar5_inline_recovery_archive_scans_chunks_and_repairs_prefix() {
    let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
    let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    let mut archive = prefix.clone();
    archive.extend_from_slice(b"service header bytes before chunks");
    archive.extend_from_slice(&recovery_data);
    archive.extend_from_slice(b"end bytes");
    let mut damaged = archive.clone();
    damaged[256..320].fill(0x5a);

    let repaired = repair_inline_recovery_archive(&damaged).unwrap();

    assert_eq!(repaired, archive);
}

#[test]
fn rar5_inline_recovery_picks_the_outermost_record() {
    // A stored archive nested inside this one has its own {RB} chunks, and
    // they sit earlier in the file than ours.
    let inner_prefix: Vec<u8> = (0..16_000).map(|index| (index * 7) as u8).collect();
    let mut inner = inner_prefix.clone();
    inner.extend_from_slice(&build_structural_inline_recovery_data(&inner_prefix, 20).unwrap());

    let mut prefix = b"outer archive header bytes".to_vec();
    prefix.extend_from_slice(&inner);
    prefix.extend_from_slice(&recovery_test_bytes(9_000, 5));
    let mut archive = prefix.clone();
    archive.extend_from_slice(b"service header bytes before chunks");
    let record_start = archive.len();
    archive.extend_from_slice(&build_structural_inline_recovery_data(&prefix, 20).unwrap());
    archive.extend_from_slice(b"end bytes");

    let mut damaged = archive.clone();
    damaged[record_start + 0x48] ^= 0xff;

    let repaired = repair_inline_recovery_archive(&damaged).unwrap();

    assert_eq!(repaired, archive);
}

#[test]
fn rar5_inline_recovery_archive_accepts_healthy_archive() {
    let prefix: Vec<u8> = (0..32_000).map(|index| (index * 17) as u8).collect();
    let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
    let mut archive = prefix.clone();
    archive.extend_from_slice(b"service header bytes before chunks");
    archive.extend_from_slice(&recovery_data);
    archive.extend_from_slice(b"end bytes");

    let repaired = repair_inline_recovery_archive(&archive).unwrap();

    assert_eq!(repaired, archive);
}

#[test]
fn rar5_reconstruct_data_shards_repairs_missing_shards_from_parity() {
    let first = b"abcdefgh".to_vec();
    let second = b"ijklmnop".to_vec();
    let third = b"qrstuvwx".to_vec();
    let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
    let parity = encode_parity_shards(&refs, 2).unwrap();

    let reconstructed = reconstruct_data_shards(
        &[Some(&first), None, Some(&third)],
        &[(0, parity[0].as_slice())],
    )
    .unwrap();

    assert_eq!(reconstructed[0], first);
    assert_eq!(reconstructed[1], second);
    assert_eq!(reconstructed[2], third);
}
