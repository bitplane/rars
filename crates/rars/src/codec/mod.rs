//! RAR compression codecs, filters, PPMd, and RARVM components used by `rars`.

mod fast;
pub(crate) mod filters;
mod huffman;
mod match_finder;
mod ppmd;
pub mod rar13;
pub mod rar20;
pub mod rar29;
pub mod rar50;
pub mod rarvm;
pub(crate) mod workspace;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidData(&'static str),
    NeedMoreInput,
    Cancelled,
    WorkspaceLimitExceeded(Box<WorkspaceLimitError>),
}

/// A refused codec allocation. Boxed by `Error` so successful codec operations
/// keep the existing compact Result layout. Diagnostic storage is not workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLimitError {
    pub limit: u64,
    /// Capacity required by this owner, including a simultaneous replacement.
    pub required: u64,
    pub used: u64,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(msg) => write!(f, "{msg}"),
            Self::NeedMoreInput => write!(f, "codec input is truncated"),
            Self::Cancelled => f.write_str("codec operation was cancelled"),
            Self::WorkspaceLimitExceeded(details) => {
                write!(f,
                "codec workspace limit {} exceeded: owner requires {} bytes with {} bytes in use",
                details.limit, details.required, details.used)
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::convert::Infallible> for Error {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}
