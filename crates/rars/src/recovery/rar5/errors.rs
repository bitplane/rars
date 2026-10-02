#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Cancelled,
    BadRecoveryChunk,
    OddShardSize,
    PlanOverflow,
    PrefixExceedsPlan,
    TooManyDamagedShards,
    ShardSizeMismatch,
    TooManyShards,
    SingularElement,
    RebuildTooLarge,
    Io(std::io::ErrorKind),
    /// Preserve a structured archive error from workspace admission, a reader or a sink.
    TypedIo(Box<crate::Error>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("RAR 5 recovery cancelled"),
            Self::BadRecoveryChunk => f.write_str("RAR 5 recovery chunk is invalid"),
            Self::OddShardSize => f.write_str("RAR 5 recovery shard size is odd"),
            Self::PlanOverflow => f.write_str("RAR 5 recovery plan overflows"),
            Self::PrefixExceedsPlan => {
                f.write_str("RAR 5 recovery prefix exceeds planned shard capacity")
            }
            Self::TooManyDamagedShards => {
                f.write_str("RAR 5 recovery data cannot repair this many damaged shards")
            }
            Self::ShardSizeMismatch => f.write_str("RAR 5 recovery shard sizes differ"),
            Self::TooManyShards => f.write_str("RAR 5 recovery shard count is invalid"),
            Self::SingularElement => f.write_str("RAR 5 recovery matrix is singular"),
            Self::RebuildTooLarge => {
                f.write_str("RAR 5 recovery record is too large to rebuild in memory")
            }
            Self::Io(kind) => write!(f, "RAR 5 recovery I/O failed: {kind}"),
            Self::TypedIo(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TypedIo(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        match error.downcast::<crate::Error>() {
            Ok(error) => Self::TypedIo(Box::new(error)),
            Err(error) => Self::Io(error.kind()),
        }
    }
}

impl From<crate::codec::Error> for Error {
    fn from(error: crate::codec::Error) -> Self {
        Self::TypedIo(Box::new(error.into()))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
