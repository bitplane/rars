use super::*;

fn counts(lengths: &[u8]) -> [u16; 16] {
    let mut counts = [0; 16];
    for &len in lengths {
        if len != 0 {
            counts[len as usize] += 1;
        }
    }
    validate_counts(&counts, "oversubscribed").unwrap();
    counts
}

#[test]
fn lookup_matches_bitwise_decoding_for_every_prefix_and_input_boundary() {
    let tables = [
        (1..=15).chain([15]).collect::<Vec<_>>(),
        vec![0, 2, 2, 10, 11, 15],
        vec![10; 1024],
        vec![15; 32768],
    ];
    for lengths in tables {
        for wide in [false, true] {
            let mut table =
                Huffman::from_counts_with_lookup(&lengths, counts(&lengths), &Allowance::default())
                    .unwrap();
            if wide {
                table.symbols[1] = (1usize << 28) + 1;
                table.build_lookup().unwrap();
            }
            for prefix in 0..1u32 << 15 {
                for available in 0..=15 {
                    let mut consumed = 0;
                    let expected = table
                        .decode(
                            || {
                                if consumed == available {
                                    return Err(Error::NeedMoreInput);
                                }
                                let bit = ((prefix >> (14 - consumed)) & 1) as u16;
                                consumed += 1;
                                Ok(bit)
                            },
                            "empty",
                            "invalid",
                        )
                        .map(|symbol| (symbol, consumed));
                    let padded = prefix & (0x7fff << (15 - available));
                    assert_eq!(
                        table.decode_peeked_checked(padded, available, "empty", "invalid"),
                        expected,
                        "prefix={prefix:#x}, available={available}, lengths={}",
                        lengths.len()
                    );
                }
            }
        }
    }
}

#[test]
fn lookup_preserves_alphabet_indices_larger_than_the_packed_entry() {
    let mut table = Huffman::from_counts(&[1], counts(&[1]), &Allowance::default()).unwrap();
    // A synthetic sparse alphabet avoids allocating 256 MiB of zero lengths.
    table.symbols[0] = (1usize << 28) + 1;
    table.build_lookup().unwrap();
    assert_eq!(
        table.decode_peeked_checked(0, 1, "empty", "invalid"),
        Ok(((1 << 28) + 1, 1))
    );
    assert_eq!(
        table.try_clone().unwrap().decode_peeked(0),
        Some(((1 << 28) + 1, 1))
    );
}

#[test]
fn bitwise_only_and_empty_tables_do_not_allocate_a_lookup() {
    let bytes = 2 * std::mem::size_of::<usize>() as u64;
    let budget = Allowance::limited(bytes * 2);
    let table = Huffman::from_counts(&[1, 1], counts(&[1, 1]), &budget).unwrap();
    assert_eq!(budget.used(), bytes);
    assert!(table.quick.is_empty());
    let copy = table.try_clone().unwrap();
    assert_eq!(budget.used(), bytes * 2);
    assert_eq!(copy.decode(|| Ok(1), "empty", "invalid"), Ok(1));
    drop((table, copy));
    assert_eq!(budget.used(), 0);
    let budget = Allowance::limited(0);
    for table in [
        Huffman::with_allowance(&budget),
        Huffman::from_counts_with_lookup(&[0; 16], [0; 16], &budget).unwrap(),
    ] {
        assert!(table.quick.is_empty());
        for available in 0..=15 {
            assert_eq!(
                table.decode_peeked_checked(0, available, "empty", "invalid"),
                Err(Error::InvalidData("empty"))
            );
        }
    }
    assert_eq!(budget.used(), 0);
}

#[test]
fn failed_lookup_allocation_releases_the_previously_admitted_symbols() {
    let budget = Allowance::limited(2 * std::mem::size_of::<usize>() as u64);
    assert!(matches!(
        Huffman::from_counts_with_lookup(&[1, 1], counts(&[1, 1]), &budget),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    assert_eq!(budget.used(), 0);
}
