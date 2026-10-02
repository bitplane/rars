#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidParitySize,
    InvalidCodewordSize,
    TooManyErasures,
    DecodeFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParitySize => f.write_str("RAR 3 recovery parity size is invalid"),
            Self::InvalidCodewordSize => f.write_str("RAR 3 recovery codeword size is invalid"),
            Self::TooManyErasures => {
                f.write_str("RAR 3 recovery data cannot repair this many erasures")
            }
            Self::DecodeFailed => f.write_str("RAR 3 recovery decode failed"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
