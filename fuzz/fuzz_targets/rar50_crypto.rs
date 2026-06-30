#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::crypto::rar50::{Rar50Cipher, Rar50Keys};

const MAX_DATA_SIZE: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 50 {
        return;
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[..16]);
    let kdf_count_log = data[16] % 26;
    let password_len = usize::from(data[17]) % 32;
    if data.len() < 50 + password_len {
        return;
    }
    let password = &data[18..18 + password_len];
    let key_material = &data[18 + password_len..];

    let _ = Rar50Keys::derive(password, salt, kdf_count_log);

    if key_material.len() < 48 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_material[..32]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&key_material[32..48]);
    let mut payload = key_material[48..key_material.len().min(48 + MAX_DATA_SIZE)].to_vec();

    let _ = Rar50Cipher::new(key, iv).decrypt_in_place(&mut payload);
    let _ = Rar50Cipher::new(key, iv).encrypt_in_place(&mut payload);
});
