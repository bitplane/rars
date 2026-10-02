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

mod implementation;
pub use implementation::*;
