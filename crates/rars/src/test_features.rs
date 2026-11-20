//! Unit-test fixtures track independently selected Cargo capabilities.

#[cfg(feature = "write")]
pub(crate) fn encryption_cases() -> impl Iterator<Item = bool> {
    std::iter::once(false).chain(cfg!(feature = "encryption").then_some(true))
}

#[test]
fn crypto_key_equality_and_debug_do_not_require_derivation() {
    use crate::crypto::rar50::Rar50Keys;
    let keys = Rar50Keys {
        key: [1; 32],
        hash_key: [2; 32],
        password_check: [3; 8],
    };
    assert_eq!(keys, keys.clone());
    for field in 0..3 {
        let mut different = keys.clone();
        match field {
            0 => different.key[31] ^= 1,
            1 => different.hash_key[31] ^= 1,
            _ => different.password_check[7] ^= 1,
        }
        assert_ne!(keys, different);
    }
    assert_eq!(format!("{keys:?}"), "Rar50Keys { .. }");
}
