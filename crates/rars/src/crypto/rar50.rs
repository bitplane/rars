#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    KdfCountTooLarge,
    BadPassword,
    UnalignedInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KdfCountTooLarge => f.write_str("RAR 5 KDF count is too large"),
            Self::BadPassword => f.write_str("wrong password or corrupt encrypted data"),
            Self::UnalignedInput => f.write_str("RAR 5 AES input is not block aligned"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

mod implementation;
pub use implementation::*;
