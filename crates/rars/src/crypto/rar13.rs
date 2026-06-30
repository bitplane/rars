use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct Rar13Cipher {
    key: [u8; 3],
}

pub struct Rar13DecryptReader<R> {
    inner: R,
    cipher: Rar13Cipher,
}

impl Rar13Cipher {
    pub fn new(password: &[u8]) -> Self {
        let mut key = [0u8; 3];
        for &byte in password {
            key[0] = key[0].wrapping_add(byte);
            key[1] ^= byte;
            key[2] = key[2].wrapping_add(byte).rotate_left(1);
        }
        Self { key }
    }

    pub fn new_comment() -> Self {
        Self { key: [0, 7, 77] }
    }

    pub fn encrypt_in_place(mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.encrypt_byte(*byte);
        }
    }

    pub fn decrypt_in_place(mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.decrypt_byte(*byte);
        }
    }

    pub fn encrypt_byte(&mut self, byte: u8) -> u8 {
        self.advance();
        byte.wrapping_add(self.key[0])
    }

    pub fn decrypt_byte(&mut self, byte: u8) -> u8 {
        self.advance();
        byte.wrapping_sub(self.key[0])
    }

    fn advance(&mut self) {
        self.key[1] = self.key[1].wrapping_add(self.key[2]);
        self.key[0] = self.key[0].wrapping_add(self.key[1]);
    }
}

impl<R> Rar13DecryptReader<R> {
    pub fn new(inner: R, cipher: Rar13Cipher) -> Self {
        Self { inner, cipher }
    }
}

impl<R: std::io::Read> std::io::Read for Rar13DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(out)?;
        for byte in &mut out[..read] {
            *byte = self.cipher.decrypt_byte(*byte);
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::Rar13Cipher;

    #[test]
    fn rar13_cipher_matches_pinned_stream_vector() {
        let mut data = *b"hello world";
        Rar13Cipher::new(b"password").encrypt_in_place(&mut data);
        assert_eq!(
            data,
            [0x37, 0xcd, 0xaa, 0xbd, 0x10, 0x4e, 0x6f, 0x6e, 0xb5, 0x30, 0xe6]
        );

        Rar13Cipher::new(b"password").decrypt_in_place(&mut data);
        assert_eq!(&data, b"hello world");
    }
}
