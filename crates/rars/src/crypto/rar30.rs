use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use sha1::{Digest, Sha1 as FastSha1};
use std::str;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const HASH_ROUNDS: u32 = 0x40000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    NonUtf8Password,
    UnalignedInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonUtf8Password => f.write_str("RAR 3.x password is not UTF-8"),
            Self::UnalignedInput => f.write_str("RAR 3.x AES input is not block aligned"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, ZeroizeOnDrop)]
pub struct Rar30Cipher {
    cipher: Aes128,
    iv: [u8; 16],
}

impl Rar30Cipher {
    pub fn new(password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        let (mut key, iv) = derive_key_iv(password, salt)?;
        let cipher = Aes128::new(&key.into());
        key.zeroize();
        Ok(Self { cipher, iv })
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        for block in data.chunks_exact_mut(16) {
            self.decrypt_block(block);
        }
        Ok(())
    }

    pub fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        for block in data.chunks_exact_mut(16) {
            self.encrypt_block(block);
        }
        Ok(())
    }

    fn encrypt_block(&mut self, block: &mut [u8]) {
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        let block: &mut [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.encrypt_block(block.into());
        self.iv.copy_from_slice(block);
    }

    fn decrypt_block(&mut self, block: &mut [u8]) {
        let ciphertext: [u8; 16] = block.try_into().expect("AES block size");
        let block: &mut [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.decrypt_block(block.into());
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        self.iv = ciphertext;
    }
}

fn derive_key_iv(password: &[u8], salt: Option<[u8; 8]>) -> Result<([u8; 16], [u8; 16])> {
    let mut raw = Zeroizing::new(Vec::with_capacity(password.len() * 2 + 8));
    let password = str::from_utf8(password).map_err(|_| Error::NonUtf8Password)?;
    for code_unit in password.encode_utf16() {
        raw.extend_from_slice(&code_unit.to_le_bytes());
    }
    if let Some(salt) = salt {
        raw.extend_from_slice(&salt);
    }

    // RAR 3.x mutates password/salt bytes only when the repeated KDF input
    // crosses complete SHA-1 blocks. The stock SHA-1 path is equivalent while
    // the password+salt material never fills a 64-byte block.
    if raw.len() < 64 {
        return Ok(derive_key_iv_fast(&raw));
    }

    Ok(derive_key_iv_slow(&mut raw))
}

fn derive_key_iv_slow(raw: &mut [u8]) -> ([u8; 16], [u8; 16]) {
    let raw_size = raw.len();
    let mut raw = Zeroizing::new(raw.to_vec());
    raw.resize(raw_size + 64, 0);
    let mut sha1 = FastSha1::new();
    let mut iv = [0; 16];
    let mut pos = 0u32;
    for i in 0..HASH_ROUNDS {
        sha1.update(&raw[..raw_size]);
        let end_pos = (pos + raw_size as u32) & !(64 - 1);
        if end_pos > pos + 64 {
            let mut cur_pos = (pos & !(64 - 1)) + 64;
            while cur_pos != end_pos {
                let offset = (cur_pos - pos) as usize;
                update_password_data_sha1(&mut raw[offset..offset + 64]);
                cur_pos += 64;
            }
        }
        pos = pos.wrapping_add(raw_size as u32);

        sha1.update([
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        pos = pos.wrapping_add(3);
        if i.is_multiple_of(HASH_ROUNDS / 16) {
            let digest = sha1.clone().finalize();
            iv[(i / (HASH_ROUNDS / 16)) as usize] = digest[19];
        }
    }

    let digest = sha1.finalize();
    let mut key = [0; 16];
    for (word_index, chunk) in digest[..16].chunks_exact(4).enumerate() {
        key[word_index * 4..word_index * 4 + 4]
            .copy_from_slice(&[chunk[3], chunk[2], chunk[1], chunk[0]]);
    }
    (key, iv)
}

fn update_password_data_sha1(data: &mut [u8]) {
    let mut w = [0u32; 80];
    for (i, chunk) in data.chunks_exact(4).take(16).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().expect("SHA-1 word size"));
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    for (i, word) in w[64..80].iter().enumerate() {
        data[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

fn derive_key_iv_fast(raw: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut sha1 = FastSha1::new();
    let mut iv = [0; 16];
    for i in 0..HASH_ROUNDS {
        sha1.update(raw);
        sha1.update([
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        if i.is_multiple_of(HASH_ROUNDS / 16) {
            let digest = sha1.clone().finalize();
            iv[(i / (HASH_ROUNDS / 16)) as usize] = digest[19];
        }
    }

    let digest = sha1.finalize();
    let mut key = [0; 16];
    for (word_index, chunk) in digest[..16].chunks_exact(4).enumerate() {
        key[word_index * 4..word_index * 4 + 4]
            .copy_from_slice(&[chunk[3], chunk[2], chunk[1], chunk[0]]);
    }
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_kdf_material(password: &[u8], salt: Option<[u8; 8]>) -> Vec<u8> {
        let mut raw = Vec::with_capacity(password.len() * 2 + 8);
        let password = str::from_utf8(password).unwrap();
        for code_unit in password.encode_utf16() {
            raw.extend_from_slice(&code_unit.to_le_bytes());
        }
        if let Some(salt) = salt {
            raw.extend_from_slice(&salt);
        }
        raw
    }

    #[test]
    fn rar30_aes_encrypt_decrypt_round_trips_blocks() {
        let salt = Some([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        let plain = data;

        Rar30Cipher::new(b"password", salt)
            .unwrap()
            .encrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(
            data,
            [
                0x5e, 0x59, 0xce, 0xa1, 0x16, 0xca, 0xa2, 0x1d, 0x4d, 0xc5, 0x05, 0xeb, 0xa9, 0x3f,
                0x7b, 0xcd, 0x0d, 0x04, 0xff, 0xea, 0x60, 0x67, 0x3d, 0xaf, 0x6a, 0x8f, 0x02, 0xb2,
                0x03, 0xc8, 0x7d, 0xde,
            ]
        );

        Rar30Cipher::new(b"password", salt)
            .unwrap()
            .decrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn rar30_aes_round_trips_with_long_password_slow_path() {
        // Password long enough that utf-16(password) + 8-byte salt >= 64,
        // forcing derive_key_iv to use the RAR3 password-buffer mutation path
        // instead of derive_key_iv_fast.
        let password = b"this-password-is-deliberately-long-enough-to-exceed-64-bytes-utf16";
        let salt = Some(*b"longsalt");
        let mut data = *b"0123456789abcdefRAR AES CBC data";
        let plain = data;

        Rar30Cipher::new(password, salt)
            .unwrap()
            .encrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(
            data,
            [
                0xb9, 0xa7, 0xac, 0x4b, 0x81, 0x0a, 0x5c, 0xf1, 0x6e, 0xd4, 0x5a, 0x4c, 0xbc, 0x1e,
                0x2e, 0xef, 0x53, 0x7b, 0x89, 0x63, 0x7a, 0xc5, 0x7a, 0x1e, 0xfc, 0x43, 0x3c, 0x18,
                0xea, 0xfd, 0x54, 0xed,
            ]
        );

        Rar30Cipher::new(password, salt)
            .unwrap()
            .decrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn rar30_aes_rejects_partial_tail() {
        let mut data = *b"partial block!!";

        assert_eq!(
            Rar30Cipher::new(b"password", None)
                .unwrap()
                .encrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
        assert_eq!(
            Rar30Cipher::new(b"password", None)
                .unwrap()
                .decrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
    }

    #[test]
    fn rejects_non_utf8_passwords() {
        assert!(matches!(
            Rar30Cipher::new(b"\xffpassword", None),
            Err(Error::NonUtf8Password)
        ));
    }

    #[test]
    fn rar30_fast_kdf_matches_reference_path_for_short_material() {
        for (password, salt) in [
            (b"".as_slice(), None),
            (b"password".as_slice(), Some(*b"rarsalt!")),
            ("páss".as_bytes(), Some([1, 2, 3, 4, 5, 6, 7, 8])),
        ] {
            let raw = raw_kdf_material(password, salt);
            assert!(
                raw.len() < 64,
                "case should exercise the fast-path precondition"
            );

            let fast = derive_key_iv_fast(&raw);
            let mut reference_raw = raw.clone();
            let reference = derive_key_iv_slow(&mut reference_raw);

            assert_eq!(fast, reference);
        }
    }
}
