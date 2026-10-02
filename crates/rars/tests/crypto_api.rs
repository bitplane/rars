#![cfg(feature = "encryption")]

use rars::crypto::{rar30, rar50};

#[test]
fn key_equality_checks_every_byte_and_debug_keeps_material_private() {
    let keys = rar50::Rar50Keys::derive(b"secret", [7; 16], 0).unwrap();
    assert_eq!(keys, keys.clone());
    assert_eq!(format!("{keys:?}"), "Rar50Keys { .. }");
    for index in 0..72 {
        let mut changed = keys.clone();
        match index {
            0..32 => changed.key[index] ^= 1,
            32..64 => changed.hash_key[index - 32] ^= 1,
            _ => changed.password_check[index - 64] ^= 1,
        }
        assert_ne!(keys, changed, "changed byte {index}");
        assert_ne!(changed, keys, "changed byte {index}");
    }
}

#[test]
fn password_check_rejects_each_corrupted_byte_and_retains_old_zero_record_policy() {
    let keys = rar50::Rar50Keys::derive(b"secret", [7; 16], 0).unwrap();
    let record = keys.password_check_record();
    assert_eq!(keys.check_password(&record), Ok(()));
    assert_ne!(record[..8], [0; 8]);
    for index in 0..12 {
        let mut changed = record;
        changed[index] ^= 1;
        let error = keys.check_password(&changed).unwrap_err();
        assert_eq!(error, rar50::Error::BadPassword);
        assert_eq!(
            error.to_string(),
            "wrong password or corrupt encrypted data"
        );
    }
    let mut absent = [0; 12];
    absent[8..].fill(0xa5);
    assert_eq!(keys.check_password(&absent), Ok(()));
}

#[test]
fn excessive_kdf_exponents_are_refused_before_derivation() {
    for exponent in [25, u8::MAX] {
        let error = rar50::Rar50Keys::derive(b"secret", [0; 16], exponent)
            .err()
            .unwrap();
        assert_eq!(error, rar50::Error::KdfCountTooLarge);
        assert_eq!(error.to_string(), "RAR 5 KDF count is too large");
    }
}

#[test]
fn legacy_non_utf8_password_error_has_a_useful_diagnostic() {
    let error = rar30::Rar30Cipher::new(b"\xffpassword", None)
        .err()
        .unwrap();
    assert_eq!(error, rar30::Error::NonUtf8Password);
    assert_eq!(error.to_string(), "RAR 3.x password is not UTF-8");
}

#[test]
fn partial_aes_blocks_are_refused_without_mutating_the_input() {
    let mut data = [0x55; 15];
    let error = rar30::Rar30Cipher::new(b"secret", None)
        .unwrap()
        .decrypt_in_place(&mut data)
        .unwrap_err();
    assert_eq!(error, rar30::Error::UnalignedInput);
    assert_eq!(error.to_string(), "RAR 3.x AES input is not block aligned");
    assert_eq!(data, [0x55; 15]);
    let error = rar50::Rar50Cipher::new([7; 32], [3; 16])
        .decrypt_in_place(&mut data)
        .unwrap_err();
    assert_eq!(error, rar50::Error::UnalignedInput);
    assert_eq!(error.to_string(), "RAR 5 AES input is not block aligned");
    assert_eq!(data, [0x55; 15]);
}
