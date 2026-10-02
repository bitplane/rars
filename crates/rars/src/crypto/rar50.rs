#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    KdfCountTooLarge,
    BadPassword,
    UnalignedInput,
    FeatureDisabled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KdfCountTooLarge => f.write_str("RAR 5 KDF count is too large"),
            Self::BadPassword => f.write_str("wrong password or corrupt encrypted data"),
            Self::FeatureDisabled => f.write_str("Cargo feature encryption is disabled"),
            Self::UnalignedInput => f.write_str("RAR 5 AES input is not block aligned"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// The PBKDF2 iteration exponent this writer stores in new archives, giving
/// `2^15` = 32768 iterations.
///
/// WinRAR writes 15 and a reader honours whatever the archive declares, so the
/// only thing a smaller exponent buys is a faster offline password guess
/// against the archives we produce. It costs about 15 ms per encrypted member
/// on the write side, which is what WinRAR pays too.
pub const WRITE_KDF_COUNT_LOG: u8 = 15;

#[derive(Clone)]
#[cfg_attr(feature = "encryption", derive(zeroize::ZeroizeOnDrop))]
#[non_exhaustive]
pub struct Rar50Keys {
    pub key: [u8; 32],
    pub hash_key: [u8; 32],
    pub password_check: [u8; 8],
}

impl std::fmt::Debug for Rar50Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rar50Keys").finish_non_exhaustive()
    }
}

impl PartialEq for Rar50Keys {
    fn eq(&self, other: &Self) -> bool {
        let key_eq = constant_time_eq(&self.key, &other.key);
        let hash_eq = constant_time_eq(&self.hash_key, &other.hash_key);
        let check_eq = constant_time_eq(&self.password_check, &other.password_check);
        key_eq & hash_eq & check_eq
    }
}

impl Eq for Rar50Keys {}

fn constant_time_eq<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(feature = "encryption")]
mod implementation;
#[cfg(feature = "encryption")]
pub use implementation::*;

impl Rar50Keys {
    pub(crate) fn checked_crc_mac(&self, value: u32) -> crate::Result<u32> {
        #[cfg(feature = "encryption")]
        {
            Ok(self.mac_crc32(value))
        }
        #[cfg(not(feature = "encryption"))]
        {
            let _ = value;
            Err(crate::Error::FeatureDisabled {
                feature: "encryption",
            })
        }
    }
    pub(crate) fn checked_hash_mac(&self, value: [u8; 32]) -> crate::Result<[u8; 32]> {
        #[cfg(feature = "encryption")]
        {
            Ok(self.mac_hash32(value))
        }
        #[cfg(not(feature = "encryption"))]
        {
            let _ = value;
            Err(crate::Error::FeatureDisabled {
                feature: "encryption",
            })
        }
    }
}

#[cfg(not(feature = "encryption"))]
impl Rar50Keys {
    pub fn derive(_password: &[u8], _salt: [u8; 16], _kdf_count_log: u8) -> Result<Self> {
        Err(Error::FeatureDisabled)
    }
}
#[cfg(feature = "write")]
impl Rar50Keys {
    pub(crate) fn checked_password_record(&self) -> crate::Result<[u8; 12]> {
        #[cfg(feature = "encryption")]
        {
            Ok(self.password_check_record())
        }
        #[cfg(not(feature = "encryption"))]
        {
            Err(crate::Error::FeatureDisabled {
                feature: "encryption",
            })
        }
    }
}
