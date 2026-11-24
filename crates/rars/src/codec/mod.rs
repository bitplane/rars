//! RAR compression codecs, filters, PPMd, and RARVM components used by `rars`.

mod canonical;
pub(crate) mod fast;
pub mod filters;
#[cfg(any(test, feature = "write"))]
mod huffman;
#[cfg(any(test, feature = "write"))]
mod match_finder;
#[cfg(feature = "write")]
pub(crate) mod packed_chain;
pub(crate) mod packed_window;
mod ppmd;
pub mod rar13;
pub mod rar20;
pub mod rar29;
pub mod rar50;
// Public only to the fuzz targets, which drive the interpreter directly.
#[cfg(fuzzing)]
pub mod rarvm;
#[cfg(not(fuzzing))]
pub(crate) mod rarvm;
pub(crate) mod workspace;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidData(&'static str),
    NeedMoreInput,
    Cancelled,
    /// A RAR 2.9-4.x stream defines a filter program other than the six
    /// standard ones, and running such programs was not enabled.
    Rar3VmProgramRefused,
    /// Custom RAR 2.9-4.x filter programs ran more instructions than the
    /// bytes they filter allow; see `rarvm::VmWork`. Like a single run that
    /// reaches its own limit, this is invalid data: no archive WinRAR wrote
    /// comes near it.
    Rar3VmWorkLimitExceeded,
    WorkspaceLimitExceeded(Box<WorkspaceLimitError>),
    /// An error carried by a reader or writer, including typed library errors
    /// transported through `io::Error`. Successful decoding allocates no
    /// diagnostic storage.
    Io(Box<crate::Error>),
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
            Self::Rar3VmProgramRefused => {
                f.write_str("RAR 3 VM filter program refused: only standard filters are enabled")
            }
            Self::Rar3VmWorkLimitExceeded => write!(
                f,
                "RAR 3 VM filter programs ran past their instruction budget of {} per filtered byte",
                rarvm::VM_WORK_PER_BYTE
            ),
            Self::WorkspaceLimitExceeded(details) => {
                write!(f,
                "codec workspace limit {} exceeded: owner requires {} bytes with {} bytes in use",
                details.limit, details.required, details.used)
            }
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        match crate::Error::from(error) {
            crate::Error::Cancelled => Self::Cancelled,
            crate::Error::Codec(error) => error,
            error => Self::Io(Box::new(error)),
        }
    }
}

/// A RAR 1.5 stream that runs out of packed data before its declared size.
pub(crate) const RAR15_ENDED_EARLY: Error =
    Error::InvalidData("RAR 1.5 member ended before its declared size");
/// A RAR 2.0 stream that runs out of packed data before its declared size.
pub(crate) const RAR20_ENDED_EARLY: Error = Error::InvalidData("RAR 2.0 bitstream is truncated");
/// A RAR 2.9 stream that reaches its end-of-file marker before its declared
/// size.
pub(crate) const RAR29_ENDED_EARLY: Error =
    Error::InvalidData("RAR 2.9 member ended before its declared size");

impl Error {
    /// Whether a member's stream ended before its declared size. What it
    /// produced is all there is, and its checksum says whether that is the
    /// whole file and the declared size is what is wrong.
    pub(crate) fn ended_early(&self) -> bool {
        [RAR15_ENDED_EARLY, RAR20_ENDED_EARLY, RAR29_ENDED_EARLY].contains(self)
    }

    fn from_read_error(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::NeedMoreInput
        } else {
            Self::from(error)
        }
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn codec_io_errors_expose_the_library_cause_and_leaf_errors_have_no_source() {
        let cause = crate::Error::InvalidHeader("bad block").at_archive_offset(42);
        let error = Error::Io(Box::new(cause.clone()));
        assert_eq!(
            error.to_string(),
            "at archive offset 0x2a: invalid header: bad block"
        );
        let source = error.source().unwrap();
        assert_eq!(source.downcast_ref::<crate::Error>(), Some(&cause));
        assert_eq!(
            source.source().unwrap().to_string(),
            "invalid header: bad block"
        );
        for error in [
            Error::InvalidData("bad symbol"),
            Error::NeedMoreInput,
            Error::Cancelled,
            Error::WorkspaceLimitExceeded(Box::new(WorkspaceLimitError {
                limit: 1,
                required: 2,
                used: 1,
            })),
        ] {
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn codec_diagnostics_propagate_formatter_failure() {
        struct RefuseFormatting;
        impl std::fmt::Write for RefuseFormatting {
            fn write_str(&mut self, _: &str) -> std::fmt::Result {
                Err(std::fmt::Error)
            }
        }
        let error = Error::WorkspaceLimitExceeded(Box::new(WorkspaceLimitError {
            limit: 1,
            required: 2,
            used: 1,
        }));
        assert_eq!(
            std::fmt::write(&mut RefuseFormatting, format_args!("{error}")),
            Err(std::fmt::Error),
        );
    }
}
