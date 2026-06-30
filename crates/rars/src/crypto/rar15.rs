use crate::crc32::{crc32_raw, table_entry as crc32_table_entry};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct Rar15Cipher {
    key: [u16; 4],
}

impl Rar15Cipher {
    pub fn new(password: &[u8]) -> Self {
        let password = password.split(|&byte| byte == 0).next().unwrap_or(password);
        let password_crc = crc32_raw(password);
        let mut key = [
            (password_crc & 0xffff) as u16,
            (password_crc >> 16) as u16,
            0,
            0,
        ];

        for &byte in password {
            let crc = crc32_table_entry(byte);
            key[2] ^= u16::from(byte) ^ crc as u16;
            key[3] = key[3].wrapping_add(u16::from(byte).wrapping_add((crc >> 16) as u16));
        }

        Self { key }
    }

    pub fn crypt_in_place(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte ^= self.next_mask();
        }
    }

    fn next_mask(&mut self) -> u8 {
        self.key[0] = self.key[0].wrapping_add(0x1234);
        let crc = crc32_table_entry(((self.key[0] & 0x01fe) >> 1) as u8);
        self.key[1] ^= crc as u16;
        self.key[2] = self.key[2].wrapping_sub((crc >> 16) as u16);
        self.key[0] ^= self.key[2];
        self.key[3] = self.key[3].rotate_right(1) ^ self.key[1];
        self.key[3] = self.key[3].rotate_right(1);
        self.key[0] ^= self.key[3];
        (self.key[0] >> 8) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::Rar15Cipher;

    #[test]
    fn crypts_known_rar15_stream_vector() {
        let mut data = *b"hello world";
        Rar15Cipher::new(b"password").crypt_in_place(&mut data);
        assert_eq!(
            data,
            [0x2b, 0xb9, 0xf3, 0x9c, 0x41, 0xa6, 0xaa, 0xe7, 0x1a, 0x7a, 0x7b]
        );

        Rar15Cipher::new(b"password").crypt_in_place(&mut data);
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn password_is_legacy_c_string() {
        let mut truncated = *b"hello world";
        let mut plain = *b"hello world";

        Rar15Cipher::new(b"password\0ignored").crypt_in_place(&mut truncated);
        Rar15Cipher::new(b"password").crypt_in_place(&mut plain);

        assert_eq!(truncated, plain);
    }
}
