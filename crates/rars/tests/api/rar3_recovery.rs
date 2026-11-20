use rars::recovery::rar3::reconstruct_data_volumes;

#[test]
fn rev3_returns_healthy_padded_data_without_decoding() {
    let actual = b"a";
    let recovery = b"rs";
    assert_eq!(
        reconstruct_data_volumes(&[Some(actual)], 1, &[(0, recovery)]),
        Ok(vec![b"a\0".to_vec()])
    );
}
