use super::*;

#[test]
fn public_huffman_constructor_rejects_active_alphabet_count_overflow() {
    for length in [1, 15] {
        for active in [65_535, 65_536, 65_537] {
            assert!(matches!(
                HuffmanTable::from_lengths(&vec![length; active]),
                Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
            ));
        }
    }
}

#[test]
fn public_huffman_constructor_keeps_wide_sparse_symbol_indices() {
    let mut lengths = vec![0; 65_538];
    lengths[65_537] = 1;
    let table = HuffmanTable::from_lengths(&lengths).unwrap();
    let mut bits = BitReader::new(&[0]);
    assert_eq!(table.state.decode(&mut bits), Ok(65_537));
    assert_eq!(bits.position(), 1);
}
