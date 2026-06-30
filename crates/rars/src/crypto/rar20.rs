use crate::crc32::table_entry as crc32_table_entry;
use zeroize::{ZeroizeOnDrop, Zeroizing};

const INIT_SUBST_TABLE: [u8; 256] = [
    215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42, 232, 1, 177, 233, 14,
    88, 219, 25, 223, 195, 244, 90, 87, 239, 153, 137, 255, 199, 147, 70, 92, 66, 246, 13, 216, 40,
    62, 29, 217, 230, 86, 6, 71, 24, 171, 196, 101, 113, 218, 123, 93, 91, 163, 178, 202, 67, 44,
    235, 107, 250, 75, 234, 49, 167, 125, 211, 83, 114, 157, 144, 32, 193, 143, 36, 158, 124, 247,
    187, 89, 214, 141, 47, 121, 228, 61, 130, 213, 194, 174, 251, 97, 110, 54, 229, 115, 57, 152,
    94, 105, 243, 212, 55, 209, 245, 63, 11, 164, 200, 31, 156, 81, 176, 227, 21, 76, 99, 139, 188,
    127, 17, 248, 51, 207, 120, 189, 210, 8, 226, 41, 72, 183, 203, 135, 165, 166, 60, 98, 7, 122,
    38, 155, 170, 69, 172, 252, 238, 39, 134, 59, 128, 236, 27, 240, 80, 131, 3, 85, 206, 145, 79,
    154, 142, 159, 220, 201, 133, 74, 64, 20, 129, 224, 185, 138, 103, 173, 182, 43, 34, 254, 82,
    198, 151, 231, 180, 58, 10, 118, 26, 102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4, 148,
    108, 161, 56, 78, 126, 242, 222, 15, 175, 146, 23, 33, 241, 181, 190, 77, 225, 0, 46, 169, 186,
    68, 95, 237, 65, 53, 208, 253, 168, 9, 18, 100, 52, 116, 184, 160, 96, 109, 37, 30, 106, 140,
    104, 150, 5, 204, 117, 112, 84,
];

const INIT_KEY: [u32; 4] = [0xd3a3_b879, 0x3f6d_12f7, 0x7515_a235, 0xa4e7_f123];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    UnalignedInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnalignedInput => f.write_str("RAR 2.0 cipher input is not block aligned"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ZeroizeOnDrop)]
pub struct Rar20Cipher {
    key: [u32; 4],
    subst: [u8; 256],
}

impl Rar20Cipher {
    pub fn new(password: &[u8]) -> Self {
        let mut cipher = Self {
            key: INIT_KEY,
            subst: INIT_SUBST_TABLE,
        };
        cipher.set_key(password);
        cipher
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

    fn set_key(&mut self, password: &[u8]) {
        for j in 0..=255u32 {
            for i in (0..password.len()).step_by(2) {
                let n1_index = password[i].wrapping_sub(j as u8);
                let next = password.get(i + 1).copied().unwrap_or(0);
                let n2_index = next.wrapping_add(j as u8);
                let mut n1 = crc32_table_entry(n1_index) as u8;
                let n2 = crc32_table_entry(n2_index) as u8;
                let mut k = 1usize;
                while n1 != n2 {
                    self.subst.swap(n1 as usize, (n1 as usize + i + k) & 0xff);
                    n1 = n1.wrapping_add(1);
                    k += 1;
                }
            }
        }

        let mut padded = Zeroizing::new(password.to_vec());
        let padding = (16 - padded.len() % 16) % 16;
        let new_len = padded.len() + padding;
        padded.resize(new_len, 0);
        for block in padded.chunks_exact_mut(16) {
            self.encrypt_block(block);
        }
    }

    fn encrypt_block(&mut self, block: &mut [u8]) {
        let (mut a, mut b, mut c, mut d) = self.load_block(block);
        for i in 0..32 {
            (a, b, c, d) = self.round(i, a, b, c, d);
        }
        write_block(
            block,
            c ^ self.key[0],
            d ^ self.key[1],
            a ^ self.key[2],
            b ^ self.key[3],
        );
        self.update_keys(block);
    }

    fn decrypt_block(&mut self, block: &mut [u8]) {
        let saved: [u8; 16] = block.try_into().expect("RAR 2 block size");
        let (mut a, mut b, mut c, mut d) = self.load_block(block);
        for i in (0..32).rev() {
            (a, b, c, d) = self.round(i, a, b, c, d);
        }
        write_block(
            block,
            c ^ self.key[0],
            d ^ self.key[1],
            a ^ self.key[2],
            b ^ self.key[3],
        );
        self.update_keys(&saved);
    }

    fn load_block(&self, block: &[u8]) -> (u32, u32, u32, u32) {
        (
            read_u32_le(&block[0..4]) ^ self.key[0],
            read_u32_le(&block[4..8]) ^ self.key[1],
            read_u32_le(&block[8..12]) ^ self.key[2],
            read_u32_le(&block[12..16]) ^ self.key[3],
        )
    }

    fn round(&self, i: usize, a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        let t = c.wrapping_add(d.rotate_left(11)) ^ self.key[i & 3];
        let ta = a ^ self.subst_long(t);
        let t = (d ^ c.rotate_left(17)).wrapping_add(self.key[i & 3]);
        let tb = b ^ self.subst_long(t);
        (c, d, ta, tb)
    }

    fn subst_long(&self, value: u32) -> u32 {
        u32::from(self.subst[(value & 0xff) as usize])
            | (u32::from(self.subst[((value >> 8) & 0xff) as usize]) << 8)
            | (u32::from(self.subst[((value >> 16) & 0xff) as usize]) << 16)
            | (u32::from(self.subst[((value >> 24) & 0xff) as usize]) << 24)
    }

    fn update_keys(&mut self, block: &[u8]) {
        for chunk in block.chunks_exact(4) {
            self.key[0] ^= crc32_table_entry(chunk[0]);
            self.key[1] ^= crc32_table_entry(chunk[1]);
            self.key[2] ^= crc32_table_entry(chunk[2]);
            self.key[3] ^= crc32_table_entry(chunk[3]);
        }
    }
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("u32 input size"))
}

fn write_block(block: &mut [u8], a: u32, b: u32, c: u32, d: u32) {
    block[0..4].copy_from_slice(&a.to_le_bytes());
    block[4..8].copy_from_slice(&b.to_le_bytes());
    block[8..12].copy_from_slice(&c.to_le_bytes());
    block[12..16].copy_from_slice(&d.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::{Error, Rar20Cipher};

    #[test]
    fn rar20_encrypt_decrypt_round_trips_blocks() {
        let mut encrypted = *b"0123456789abcdefRAR2.0 block pad";
        let original = encrypted;

        Rar20Cipher::new(b"password")
            .encrypt_in_place(&mut encrypted)
            .unwrap();
        assert_eq!(
            encrypted,
            [
                0xb7, 0x14, 0x54, 0x5a, 0x55, 0x8b, 0xca, 0xf7, 0xbc, 0x18, 0x38, 0x17, 0x1d, 0x9e,
                0x31, 0xab, 0x81, 0x40, 0x72, 0xfe, 0x02, 0x76, 0x76, 0x65, 0x4a, 0xa5, 0x3f, 0x4b,
                0xb3, 0x0c, 0xad, 0x07,
            ]
        );

        Rar20Cipher::new(b"password")
            .decrypt_in_place(&mut encrypted)
            .unwrap();
        assert_eq!(encrypted, original);
    }

    #[test]
    fn rar20_cipher_rejects_partial_tail() {
        let mut data = *b"0123456789abcdef!";
        let original = data;

        assert_eq!(
            Rar20Cipher::new(b"password").encrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
        assert_eq!(data, original);
        assert_eq!(
            Rar20Cipher::new(b"password").decrypt_in_place(&mut data),
            Err(Error::UnalignedInput)
        );
        assert_eq!(data, original);
    }
}
