//! RAR legacy and modern archive encryption primitives used by `rars`.

pub mod rar13;
#[cfg(feature = "encryption")]
pub mod rar15;
pub mod rar20;
pub mod rar30;
pub mod rar50;

#[cfg(not(feature = "encryption"))]
pub(crate) mod unavailable;

/// The longest password any RAR key derivation sees.
///
/// Reference builds copy the password into a 128-element `wchar_t` buffer and
/// keep 127 entries plus a terminator, so nothing past character 127 reaches
/// the KDF. Measured against RAR 7.12: a 133-character password and its first
/// 127 characters open the same archive, and the first 126 do not.
pub const MAX_PASSWORD_CHARS: usize = 127;

/// Cuts a password down to the [`MAX_PASSWORD_CHARS`] the reference tools keep.
///
/// Without this rars derives a key no official tool can reproduce, in both
/// directions: it cannot open a WinRAR archive when handed the same long
/// password, and the archives it writes from character 128 on cannot be opened
/// by WinRAR with that password or with any prefix of it. The boundary is
/// sharp, so a password of exactly 127 characters is untouched.
///
/// A character here is a Unicode scalar, which matches the Linux reference
/// where `wchar_t` is 4 bytes wide. The Windows build has a 2-byte `wchar_t`
/// and so keeps 127 UTF-16 code units instead. The two disagree only for a
/// password carrying astral characters past position 127, where they derive
/// different keys from each other, so no single rule matches both. Scalars win
/// here because truncating UTF-16 can split a surrogate pair, and a Rust `str`
/// cannot hold the lone surrogate that would produce.
pub fn clamp_password(password: &[u8]) -> &[u8] {
    match std::str::from_utf8(password) {
        Ok(text) => match text.char_indices().nth(MAX_PASSWORD_CHARS) {
            Some((byte_offset, _)) => &password[..byte_offset],
            None => password,
        },
        // RAR 1.3 through 2.0 take single-byte OEM/ANSI passwords, so one byte
        // is one character.
        Err(_) => &password[..password.len().min(MAX_PASSWORD_CHARS)],
    }
}

/// RAR 5 keys derived on this thread, so bindings can test that calls reuse them.
#[cfg(feature = "encryption")]
pub fn rar50_key_derivations() -> usize {
    rar50::DERIVATIONS.with(std::cell::Cell::get)
}

/// RAR 1.5–4 AES keys derived on this thread, so bindings can test that calls reuse them.
#[cfg(feature = "encryption")]
pub fn rar30_key_derivations() -> usize {
    rar30::DERIVATIONS.with(std::cell::Cell::get)
}

/// Blocks handed to the cipher per call, enough to fill every `aes` backend's parallel width.
#[cfg(feature = "encryption")]
const CBC_BATCH_BLOCKS: usize = 64;

/// CBC-decrypts whole blocks, many per cipher call so its backend can pipeline them.
#[cfg(feature = "encryption")]
pub(crate) fn cbc_decrypt<C>(cipher: &C, iv: &mut [u8; 16], blocks: &mut [[u8; 16]])
where
    C: aes::cipher::BlockCipherDecrypt<BlockSize = aes::cipher::consts::U16>,
{
    let mut chain = [[0u8; 16]; CBC_BATCH_BLOCKS];
    for chunk in blocks.chunks_mut(CBC_BATCH_BLOCKS) {
        let (last, earlier) = chunk.split_last().expect("chunks are never empty");
        chain[0] = *iv;
        chain[1..chunk.len()].copy_from_slice(earlier);
        *iv = *last;
        cipher.decrypt_blocks(aes::cipher::Array::cast_slice_from_core_mut(chunk));
        for (block, mask) in chunk.iter_mut().zip(&chain) {
            for (byte, mask_byte) in block.iter_mut().zip(mask) {
                *byte ^= mask_byte;
            }
        }
    }
}

/// CBC-encrypts whole blocks inside the cipher's backend, so the chain loop inlines around the AES instructions.
#[cfg(all(
    feature = "encryption",
    any(test, feature = "write", feature = "recovery")
))]
pub(crate) fn cbc_encrypt<C>(cipher: &C, iv: &mut [u8; 16], blocks: &mut [[u8; 16]])
where
    C: aes::cipher::BlockCipherEncrypt<BlockSize = aes::cipher::consts::U16>,
{
    use aes::cipher::{
        consts::U16, Array, BlockCipherEncBackend, BlockCipherEncClosure, BlockSizeUser,
    };

    struct CbcEncryption<'a> {
        iv: &'a mut [u8; 16],
        blocks: &'a mut [[u8; 16]],
    }

    impl BlockSizeUser for CbcEncryption<'_> {
        type BlockSize = U16;
    }

    impl BlockCipherEncClosure for CbcEncryption<'_> {
        #[inline(always)]
        fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
            let mut previous = *self.iv;
            for block in self.blocks.iter_mut() {
                for (byte, previous_byte) in block.iter_mut().zip(previous) {
                    *byte ^= previous_byte;
                }
                let array: &mut Array<u8, U16> = block.into();
                backend.encrypt_block(array.into());
                previous = *block;
            }
            *self.iv = previous;
        }
    }

    cipher.encrypt_with_backend(CbcEncryption { iv, blocks });
}

/// Refuses encrypted operations when the implementation is omitted.
pub(crate) fn require_encryption() -> crate::Result<()> {
    if cfg!(feature = "encryption") {
        Ok(())
    } else {
        Err(crate::Error::FeatureDisabled {
            feature: "encryption",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{clamp_password, MAX_PASSWORD_CHARS};

    #[test]
    fn clamp_password_keeps_127_characters() {
        let short = b"hunter2";
        assert_eq!(clamp_password(short), short);

        let exact = "A".repeat(MAX_PASSWORD_CHARS);
        assert_eq!(clamp_password(exact.as_bytes()), exact.as_bytes());

        let long = "A".repeat(130) + "ZZZ";
        assert_eq!(clamp_password(long.as_bytes()), exact.as_bytes());
    }

    #[test]
    fn clamp_password_counts_characters_not_bytes() {
        // 140 astral scalars: 560 UTF-8 bytes, 280 UTF-16 code units.
        let emoji = "\u{1F600}".repeat(140);
        let clamped = clamp_password(emoji.as_bytes());
        let text = std::str::from_utf8(clamped).unwrap();
        assert_eq!(text.chars().count(), MAX_PASSWORD_CHARS);
        assert_eq!(clamped.len(), MAX_PASSWORD_CHARS * 4);
    }

    #[test]
    fn clamp_password_falls_back_to_bytes_when_not_utf8() {
        let latin1 = vec![0xe9u8; 200];
        assert_eq!(clamp_password(&latin1).len(), MAX_PASSWORD_CHARS);
    }

    #[cfg(feature = "encryption")]
    fn hex_blocks(hex: &str) -> Vec<[u8; 16]> {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        bytes.as_chunks::<16>().0.to_vec()
    }

    // NIST SP 800-38A F.2.1 and F.2.5, so the expected ciphertext does not come from our code.
    #[test]
    #[cfg(feature = "encryption")]
    fn cbc_encrypt_matches_the_published_vectors_however_the_blocks_are_split() {
        use aes::cipher::KeyInit;

        let iv = hex_blocks("000102030405060708090a0b0c0d0e0f")[0];
        let plain = hex_blocks(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let aes128 = aes::Aes128::new(&hex_blocks("2b7e151628aed2a6abf7158809cf4f3c")[0].into());
        let aes256_key: [u8; 32] =
            hex_blocks("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .concat()
                .try_into()
                .unwrap();
        let aes256 = aes::Aes256::new(&aes256_key.into());
        let expected128 = hex_blocks(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        );
        let expected256 = hex_blocks(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
             39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        );

        assert_encrypts_in_two_calls(&aes128, iv, &plain, &expected128);
        assert_encrypts_in_two_calls(&aes256, iv, &plain, &expected256);
    }

    #[cfg(feature = "encryption")]
    fn assert_encrypts_in_two_calls<C>(
        cipher: &C,
        iv: [u8; 16],
        plain: &[[u8; 16]],
        expected: &[[u8; 16]],
    ) where
        C: aes::cipher::BlockCipherEncrypt<BlockSize = aes::cipher::consts::U16>,
    {
        for split in 0..=plain.len() {
            let mut chain = iv;
            let mut blocks = plain.to_vec();
            let (first, second) = blocks.split_at_mut(split);
            super::cbc_encrypt(cipher, &mut chain, first);
            super::cbc_encrypt(cipher, &mut chain, second);
            assert_eq!(blocks, expected, "split at {split}");
            assert_eq!(&chain, expected.last().unwrap());
        }
    }
}
