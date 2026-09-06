#![no_main]

use libfuzzer_sys::fuzz_target;
use rars::crypto::rar30::Rar30Cipher;

const MAX_PASSWORD_SIZE: usize = 96;
const MAX_DATA_SIZE: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < 11 {
        return;
    }

    let password_len = usize::from(data[0]) % MAX_PASSWORD_SIZE;
    if data.len() < 10 + password_len {
        return;
    }
    let salt = if data[1] & 1 == 0 {
        None
    } else {
        let mut salt = [0; 8];
        salt.copy_from_slice(&data[2..10]);
        Some(salt)
    };
    let password = &data[10..10 + password_len];
    let payload = &data[10 + password_len..];

    let _ = Rar30Cipher::new(password, salt);

    let block_len = payload.len().min(MAX_DATA_SIZE) & !15;
    if block_len == 0 {
        return;
    }
    let mut encrypted = payload[..block_len].to_vec();
    let Ok(mut encrypt_cipher) = Rar30Cipher::new(password, salt) else {
        return;
    };
    if encrypt_cipher.encrypt_in_place(&mut encrypted).is_err() {
        return;
    }

    let mut decrypted = encrypted.clone();
    let Ok(mut decrypt_cipher) = Rar30Cipher::new(password, salt) else {
        return;
    };
    let _ = decrypt_cipher.decrypt_in_place(&mut decrypted);

    let mut maybe_unaligned = payload[..payload.len().min(MAX_DATA_SIZE)].to_vec();
    if !maybe_unaligned.len().is_multiple_of(16) {
        let _ = encrypt_cipher.encrypt_in_place(&mut maybe_unaligned);
    }
});
