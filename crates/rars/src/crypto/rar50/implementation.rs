use super::{constant_time_eq, Error, Rar50Keys, Result};

#[cfg(any(test, feature = "write", feature = "recovery"))]
use aes::cipher::BlockCipherEncrypt;
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use sha2::block_api::compress256;
use sha2::{Digest, Sha256};
use std::slice;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_KDF_COUNT_LOG: u8 = 24;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
thread_local! {
    pub(crate) static DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Rar50Keys {
    pub fn derive(password: &[u8], salt: [u8; 16], kdf_count_log: u8) -> Result<Self> {
        if kdf_count_log > MAX_KDF_COUNT_LOG {
            return Err(Error::KdfCountTooLarge);
        }
        #[cfg(test)]
        DERIVATIONS.with(|count| count.set(count.get() + 1));
        let password = crate::crypto::clamp_password(password);

        let mut rounds = Pbkdf2Rounds::new(password, salt);
        let mut accumulator = rounds.u;
        let mut taps = [[0u32; 8]; 3];
        let mut iterations = (1u32 << kdf_count_log) - 1;

        for tap in &mut taps {
            for _ in 0..iterations {
                rounds.next();
                for (acc, word) in accumulator.iter_mut().zip(rounds.u) {
                    *acc ^= word;
                }
            }
            *tap = accumulator;
            iterations = 16;
        }

        let mut result = Self {
            key: [0; 32],
            hash_key: [0; 32],
            password_check: [0; 8],
        };
        write_be_words(&mut result.key, &taps[0]);
        write_be_words(&mut result.hash_key, &taps[1]);
        for (i, byte) in result.password_check.iter_mut().enumerate() {
            let word =
                taps[2][i / 4] ^ taps[2][i / 4 + 2] ^ taps[2][i / 4 + 4] ^ taps[2][i / 4 + 6];
            *byte = word.to_be_bytes()[i % 4];
        }
        accumulator.zeroize();
        taps.zeroize();
        Ok(result)
    }

    /// Verifies the password against a stored check record, unless the record
    /// is the all-zero one WinRAR 5.21 and earlier wrote.
    ///
    /// Those versions set the check-present flag and then left the eight bytes
    /// zero, so verifying rejects the correct password and the archive cannot
    /// be opened at all. Treat all-zero as "no check available" and let the
    /// data checksum decide instead.
    ///
    /// The reference readers do the same. Zeroing the field in a WinRAR 7.12
    /// archive leaves the right password working, and changes what a wrong one
    /// reports from "Incorrect password" to a checksum error, which is the
    /// explicit check dropping out and detection falling through. Zeroing the
    /// record's own trailing checksum or leaving it stale makes no difference
    /// to that, so the all-zero test comes first here too.
    pub fn check_password(&self, stored: &[u8; 12]) -> Result<()> {
        if stored[..8] == [0u8; 8] {
            return Ok(());
        }
        let checksum = sha256(&stored[..8]);
        let checksum_matches = constant_time_eq(
            checksum.first_chunk::<4>().unwrap(),
            stored.last_chunk::<4>().unwrap(),
        );
        let password_matches =
            constant_time_eq(&self.password_check, stored.first_chunk::<8>().unwrap());
        if !(checksum_matches & password_matches) {
            return Err(Error::BadPassword);
        }
        Ok(())
    }

    pub fn password_check_record(&self) -> [u8; 12] {
        let mut record = [0u8; 12];
        record[..8].copy_from_slice(&self.password_check);
        record[8..].copy_from_slice(&sha256(&self.password_check)[..4]);
        record
    }

    pub fn mac_crc32(&self, crc: u32) -> u32 {
        let digest = hmac_sha256(&self.hash_key, &crc.to_le_bytes());
        digest
            .as_chunks::<4>()
            .0
            .iter()
            .fold(0, |acc, chunk| acc ^ u32::from_le_bytes(*chunk))
    }

    pub fn mac_hash32(&self, hash: [u8; 32]) -> [u8; 32] {
        hmac_sha256(&self.hash_key, &hash)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Rar50Cipher {
    cipher: Aes256,
    iv: [u8; 16],
}

impl Rar50Cipher {
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self {
            cipher: Aes256::new(&key.into()),
            iv,
        }
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        for block in data.as_chunks_mut::<16>().0.iter_mut() {
            self.decrypt_block(block);
        }
        Ok(())
    }

    #[cfg(any(test, feature = "write", feature = "recovery"))]
    pub fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        for block in data.as_chunks_mut::<16>().0.iter_mut() {
            self.encrypt_block(block);
        }
        Ok(())
    }

    #[cfg(any(test, feature = "write", feature = "recovery"))]
    fn encrypt_block(&mut self, block: &mut [u8]) {
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        let block: &mut [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.encrypt_block(block.into());
        self.iv.copy_from_slice(block);
    }

    pub(crate) fn decrypt_block(&mut self, block: &mut [u8; 16]) {
        let ciphertext = *block;
        self.cipher.decrypt_block(block.into());
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        self.iv = ciphertext;
    }
}

const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// PBKDF2-HMAC-SHA256 as one SHA-256 block per hash, so no HMAC setup runs per round.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Pbkdf2Rounds {
    inner: [u32; 8],
    outer: [u32; 8],
    block: [u8; 64],
    u: [u32; 8],
}

impl Pbkdf2Rounds {
    fn new(password: &[u8], salt: [u8; 16]) -> Self {
        let mut rounds = Self {
            inner: SHA256_IV,
            outer: SHA256_IV,
            block: [0; 64],
            u: [0; 8],
        };
        if password.len() > rounds.block.len() {
            let mut digest = sha256(password);
            rounds.block[..32].copy_from_slice(&digest);
            digest.zeroize();
        } else {
            rounds.block[..password.len()].copy_from_slice(password);
        }
        rounds.block.iter_mut().for_each(|byte| *byte ^= 0x36);
        compress256(&mut rounds.inner, slice::from_ref(&rounds.block));
        rounds
            .block
            .iter_mut()
            .for_each(|byte| *byte ^= 0x36 ^ 0x5c);
        compress256(&mut rounds.outer, slice::from_ref(&rounds.block));

        rounds.block = [0; 64];
        rounds.block[..16].copy_from_slice(&salt);
        rounds.block[16..20].copy_from_slice(&1u32.to_be_bytes());
        rounds.block[20] = 0x80;
        rounds.block[56..].copy_from_slice(&((64 + 20) * 8u64).to_be_bytes());
        rounds.hash_block(Pad::Inner);

        rounds.block[32..].fill(0);
        rounds.block[32] = 0x80;
        rounds.block[56..].copy_from_slice(&((64 + 32) * 8u64).to_be_bytes());
        rounds.hash_block(Pad::Outer);
        rounds
    }

    fn next(&mut self) {
        self.hash_block(Pad::Inner);
        self.hash_block(Pad::Outer);
    }

    /// Leaves U in the block too, as the next hash's message.
    fn hash_block(&mut self, pad: Pad) {
        self.u = match pad {
            Pad::Inner => self.inner,
            Pad::Outer => self.outer,
        };
        compress256(&mut self.u, slice::from_ref(&self.block));
        write_be_words(&mut self.block[..32], &self.u);
    }
}

// Selects a keyed state by name so it is never copied out to a stack argument.
enum Pad {
    Inner,
    Outer,
}

fn write_be_words(out: &mut [u8], words: &[u32; 8]) {
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *chunk = word.to_be_bytes();
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hmac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any size");
    hmac.update(data);
    hmac.finalize().into_bytes().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_matches_standard_vector() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn password_check_uses_the_check_value_and_its_checksum() {
        let keys = Rar50Keys::derive(b"secret", [7; 16], 4).unwrap();
        let mut record = keys.password_check_record();

        assert_eq!(keys.check_password(&record), Ok(()));

        record[0] ^= 0x01;
        assert_eq!(keys.check_password(&record), Err(Error::BadPassword));

        let mut record = keys.password_check_record();
        record[11] ^= 0x01;
        assert_eq!(keys.check_password(&record), Err(Error::BadPassword));
    }

    #[test]
    fn rar50_aes_encrypt_decrypt_round_trips_blocks() {
        let key = [9u8; 32];
        let iv = [5u8; 16];
        let mut data = *b"0123456789abcdefRAR5 block two!!";
        let plain = data;

        Rar50Cipher::new(key, iv)
            .encrypt_in_place(&mut data)
            .unwrap();
        assert_ne!(data, plain);

        Rar50Cipher::new(key, iv)
            .decrypt_in_place(&mut data)
            .unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn rar50_aes_rejects_partial_tail() {
        let key = [9u8; 32];
        let iv = [5u8; 16];
        let mut data = *b"partial block!!";

        assert_eq!(
            Rar50Cipher::new(key, iv).encrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
        assert_eq!(
            Rar50Cipher::new(key, iv).decrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
    }

    #[test]
    fn rar50_kdf_matches_pinned_vector() {
        let keys = Rar50Keys::derive(
            b"password",
            [
                0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31,
                0x32, 0x33,
            ],
            4,
        )
        .unwrap();

        assert_eq!(
            hex(&keys.key),
            "cae43ebc57fcbdfc97ddc6f4a2d09687fd06010b51f651bec8f911f20caf008f"
        );
        assert_eq!(
            hex(&keys.hash_key),
            "e65c566ff17139eaabdf60986e64058aac7e8dd82d6c5b027dd2e6d761a44d3c"
        );
        assert_eq!(hex(&keys.password_check), "118929fdcad8a74f");
        assert_eq!(
            hex(&keys.password_check_record()),
            "118929fdcad8a74f5379ff2d"
        );
        assert_eq!(keys.mac_crc32(0x1234_5678), 0xd742_398d);
    }

    #[test]
    fn rar50_kdf_matches_mac_reference() {
        let passwords: [&[u8]; 5] = [b"", b"password", &[b'p'; 64], &[b'q'; 65], &[0xe9; 127]];
        for password in passwords {
            for kdf_count_log in [0, 1, 4, 11] {
                let salt = [kdf_count_log; 16];
                let keys = Rar50Keys::derive(password, salt, kdf_count_log).unwrap();
                let reference = reference_derive(password, salt, kdf_count_log);
                let case = (password.len(), kdf_count_log);
                assert_eq!(keys.key, reference.key, "{case:?}");
                assert_eq!(keys.hash_key, reference.hash_key, "{case:?}");
                assert_eq!(keys.password_check, reference.password_check, "{case:?}");
            }
        }
    }

    fn reference_derive(password: &[u8], salt: [u8; 16], kdf_count_log: u8) -> Rar50Keys {
        let password = crate::crypto::clamp_password(password);
        let mut first_input = [0u8; 20];
        first_input[..16].copy_from_slice(&salt);
        first_input[16..].copy_from_slice(&1u32.to_be_bytes());

        let mut u = hmac_sha256(password, &first_input);
        let mut accumulator = u;
        let mut taps = [[0u8; 32]; 3];
        let mut iterations = (1u32 << kdf_count_log) - 1;
        for tap in &mut taps {
            for _ in 0..iterations {
                u = hmac_sha256(password, &u);
                for (acc, byte) in accumulator.iter_mut().zip(u) {
                    *acc ^= byte;
                }
            }
            *tap = accumulator;
            iterations = 16;
        }

        let mut password_check = [0u8; 8];
        for (i, byte) in password_check.iter_mut().enumerate() {
            *byte = taps[2][i] ^ taps[2][i + 8] ^ taps[2][i + 16] ^ taps[2][i + 24];
        }
        Rar50Keys {
            key: taps[0],
            hash_key: taps[1],
            password_check,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
