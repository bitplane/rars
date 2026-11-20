use crate::version::{ArchiveFamily, ArchiveVersion};
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, Error>;

/// Stable error categories for callers and language bindings. Context wrappers
/// do not change the category; display text remains a diagnostic, not a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    InvalidArchive,
    InvalidArgument,
    UnsupportedFormat,
    UnsupportedFeature,
    PasswordRequired,
    BadPassword,
    ChecksumMismatch,
    EntryNotFound,
    DuplicateEntry,
    UnsafePath,
    Io,
    ResourceLimit,
    Cancelled,
    SourceChanged,
    /// Archive construction failed because the writer reached an invalid state.
    WriterFailure,
}

impl ErrorKind {
    /// Stable machine-readable code, independent of diagnostic wording.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidArchive => "INVALID_ARCHIVE",
            Self::InvalidArgument => "INVALID_OPTION",
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::UnsupportedFeature => "UNSUPPORTED_FEATURE",
            Self::PasswordRequired => "PASSWORD_REQUIRED",
            Self::BadPassword => "BAD_PASSWORD",
            Self::ChecksumMismatch => "CHECKSUM_MISMATCH",
            Self::EntryNotFound => "ENTRY_NOT_FOUND",
            Self::DuplicateEntry => "DUPLICATE_ENTRY",
            Self::UnsafePath => "UNSAFE_ENTRY_NAME",
            Self::Io => "IO",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::Cancelled => "CANCELLED",
            Self::SourceChanged => "SOURCE_CHANGED",
            Self::WriterFailure => "WRITE_FAILED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IoError {
    pub kind: std::io::ErrorKind,
    pub message: String,
    source: Arc<std::io::Error>,
}

impl IoError {
    pub fn source(&self) -> &(dyn std::error::Error + 'static) {
        self.source.as_ref()
    }
}

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl Eq for IoError {}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    TooShort,
    UnsupportedSignature,
    InvalidHeader(&'static str),
    InvalidArgument(&'static str),
    EntryNotFound,
    DuplicateEntry,
    InputSymlink,
    UnsafePath(&'static str),
    SourceChanged(&'static str),
    WriterFailure(&'static str),
    AtArchiveOffset {
        offset: usize,
        source: Box<Error>,
    },
    AtEntry {
        name: Vec<u8>,
        operation: &'static str,
        source: Box<Error>,
    },
    /// A fault traced to one volume of a set, counting the first as 0. The
    /// message counts from 1, as volume file names do.
    InVolume {
        index: usize,
        source: Box<Error>,
    },
    /// The set needs a volume that never arrived; [`Error::InVolume`] around it numbers it.
    MissingVolume,
    /// A volume's recorded number doesn't follow the one before; [`Error::InVolume`] around it numbers it.
    VolumeOutOfOrder,
    UnsupportedVersion(ArchiveVersion),
    /// The requested implementation was omitted at compile time.
    FeatureDisabled {
        feature: &'static str,
    },
    /// Skipping payload decoding would leave solid history unavailable.
    CannotSkipSolidMember,
    /// An earlier member of this solid chain failed, so its history is gone.
    BrokenSolidChain,
    /// A RAR 2.9-4.x member defines a filter program other than the six
    /// standard ones, and `ArchiveReadOptions::allow_rar3_vm_programs` is off.
    Rar3VmProgramRefused,
    UnsupportedFeature {
        version: ArchiveVersion,
        feature: &'static str,
    },
    /// A writer option that would change the output, for a format that cannot
    /// honour it.
    UnsupportedWriterOption {
        target: ArchiveVersion,
        option: crate::WriterOption,
        /// Why, when the format alone is not the reason: "in a compressed
        /// archive", "levels run from 0 to 5". Rendered after the format.
        because: Option<&'static str>,
    },
    /// `required` is the declared size or the minimum attempted output size.
    MemberOutputLimitExceeded {
        limit: u64,
        required: u64,
    },
    /// Skipped solid members, decoded only to be discarded, would need
    /// `required` bytes in all, above `ArchiveReadOptions::solid_skip_budget`.
    SolidSkipBudgetExceeded {
        limit: u64,
        required: u64,
    },
    /// Cumulative top-level headers required; diagnostic sums saturate at u64::MAX.
    HeaderCountLimitExceeded {
        limit: u64,
        required: u64,
    },
    /// Cumulative plaintext header bytes required, saturated at u64::MAX.
    HeaderBytesLimitExceeded {
        limit: u64,
        required: u64,
    },
    /// Total logical output refusal. `used` is accepted output before refusal;
    /// `required` is used plus the declared size or offered chunk, saturated at
    /// u64::MAX (a lower bound if the attempted sum cannot be represented).
    TotalOutputLimitExceeded {
        limit: u64,
        required: u64,
        used: u64,
    },
    Rar50DictionaryLimitExceeded {
        limit: u64,
        required: u64,
    },
    Rar50BufferedDecodeLimitExceeded {
        limit: u64,
        required: u64,
    },
    Rar50ScratchLimitExceeded {
        limit: u64,
        required: u64,
    },
    /// Retained rewrite payload bytes, excluding decoder and writer workspace.
    /// A member a rewrite cannot carry over: a special file, or a link or
    /// directory whose type or contents the writer cannot reproduce.
    UnrewritableEntry {
        name: Vec<u8>,
    },
    RewriteStagingLimitExceeded {
        limit: u64,
        required: u64,
    },
    Rar50FilterMemoryLimitExceeded {
        limit: u64,
        required: u64,
    },
    /// Aggregate logical spool storage, including in-flight growth reservations.
    /// Diagnostic `required` saturates at u64::MAX on accounting overflow.
    WriterSpoolLimitExceeded {
        limit: u64,
        required: u64,
        used: u64,
    },
    /// Shared capacity of in-memory spool payloads and indexes, including reservations.
    WriterSpoolMemoryLimitExceeded {
        limit: u64,
        required: u64,
        used: u64,
    },
    /// Retained RAR5/7 prepared header image capacity, including reservations.
    WriterPreparedHeaderLimitExceeded {
        limit: u64,
        required: u64,
        used: u64,
    },
    WriterPreparationLimitExceeded {
        limit: u64,
        required: u64,
        used: u64,
    },
    MemoryLimitExceeded {
        limit: u64,
        required: u64,
        dictionary_size: u64,
    },
    UnsupportedFamilyFeature {
        family: ArchiveFamily,
        feature: &'static str,
    },
    UnsupportedCompression {
        family: &'static str,
        unpack_version: u8,
        method: u8,
    },
    UnsupportedEncryption {
        family: &'static str,
        unpack_version: u8,
    },
    Io(IoError),
    NeedPassword,
    WrongPasswordOrCorruptData,
    /// The operation was cancelled by a token or progress callback.
    Cancelled,
    CrcMismatch {
        expected: u16,
        actual: u16,
    },
    Crc32Mismatch {
        expected: u32,
        actual: u32,
    },
    HashMismatch {
        hash_type: u64,
    },
    Codec(crate::codec::Error),
    Rar3Recovery(crate::recovery::rar3::Error),
    Rar5Recovery(crate::recovery::rar5::Error),
    Rar20Crypto(crate::crypto::rar20::Error),
    Rar30Crypto(crate::crypto::rar30::Error),
    Rar50Crypto(crate::crypto::rar50::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "input is too short"),
            Self::UnsupportedSignature => write!(f, "unsupported archive signature"),
            Self::InvalidHeader(msg) => write!(f, "invalid header: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::EntryNotFound => f.write_str("no such archive entry"),
            Self::DuplicateEntry => f.write_str("duplicate archive entry name"),
            Self::InputSymlink => f.write_str("input is a symlink; refusing to follow it"),
            Self::UnsafePath(msg) | Self::SourceChanged(msg) | Self::WriterFailure(msg) => f.write_str(msg),
            Self::AtArchiveOffset { offset, source } => {
                write!(f, "at archive offset {offset:#x}: {source}")
            }
            Self::InVolume { index, source } => write!(f, "in volume {}: {source}", index + 1),
            Self::MissingVolume => f.write_str("volume is missing"),
            Self::VolumeOutOfOrder => f.write_str("volume is out of order"),
            Self::AtEntry {
                name,
                operation,
                source,
            } => {
                write!(
                    f,
                    "while {operation} entry '{}': {source}",
                    String::from_utf8_lossy(name)
                )
            }
            Self::UnsupportedVersion(version) => write!(f, "unsupported version: {version}"),
            Self::FeatureDisabled { feature } => write!(f, "Cargo feature {feature} is disabled"),
            Self::CannotSkipSolidMember => write!(f, "cannot skip file data in a solid archive"),
            Self::Rar3VmProgramRefused => write!(
                f,
                "archive uses a custom RAR 3 VM filter program; enable allow_rar3_vm_programs to run it"
            ),
            Self::BrokenSolidChain => {
                write!(f, "an earlier member of this solid archive failed to extract")
            }
            Self::UnsupportedFeature { version, feature } => {
                write!(f, "feature {feature} is not supported by {version}")
            }
            Self::UnsupportedWriterOption {
                target,
                option,
                because,
            } => match because {
                Some(reason) => {
                    write!(f, "{} is not supported by {target} ({reason})", option.name())
                }
                None => write!(f, "{} is not supported by {target}", option.name()),
            },
            Self::MemberOutputLimitExceeded { limit, required } => write!(f,
                "member requires {required} output bytes, above the configured limit of {limit} bytes"),
            Self::SolidSkipBudgetExceeded { limit, required } => write!(f,
                "skipping solid members requires decoding {required} bytes, above the solid skip budget of {limit} bytes"),
            Self::HeaderCountLimitExceeded { limit, required } => write!(f,
                "parsing requires at least {required} headers, above the configured limit of {limit} headers"),
            Self::HeaderBytesLimitExceeded { limit, required } => write!(f,
                "parsing requires at least {required} header bytes, above the configured limit of {limit} bytes"),
            Self::TotalOutputLimitExceeded { limit, required, used } => write!(f,
                "extraction requires at least {required} total output bytes, above the configured limit of {limit} bytes ({used} bytes already accepted)"),
            Self::Rar50DictionaryLimitExceeded { limit, required } => write!(
                f,
                "RAR 5 member declares a {required}-byte dictionary, above the configured limit of {limit} bytes"
            ),
            Self::Rar50BufferedDecodeLimitExceeded { limit, required } => write!(
                f,
                "RAR 5 filtered member requires buffered decoding of {required} bytes, above the configured limit of {limit} bytes"
            ),
            Self::Rar50ScratchLimitExceeded { limit, required } => write!(f, "RAR 5 scratch limit {limit} bytes exceeded (requires {required})"),
            Self::UnrewritableEntry { name } => write!(
                f,
                "cannot rewrite special entry {:?}: its type or contents cannot be preserved",
                String::from_utf8_lossy(name)
            ),
            Self::RewriteStagingLimitExceeded { limit, required } => write!(f, "rewrite staging limit {limit} bytes exceeded (requires {required})"),
            Self::Rar50FilterMemoryLimitExceeded { limit, required } => write!(f, "RAR 5 filter workspace limit {limit} bytes exceeded (requires {required})"),
            Self::WriterSpoolLimitExceeded { limit, required, used } => write!(f,
                "writer spool limit {limit} bytes exceeded (requires {required}; {used} bytes already retained or reserved)"),
            Self::WriterPreparationLimitExceeded { limit, required, used } => write!(f,
                "writer preparation limit {limit} bytes exceeded (requires {required}; {used} bytes already retained or reserved)"),
            Self::WriterPreparedHeaderLimitExceeded { limit, required, used } => write!(f,
                "writer prepared header limit {limit} bytes exceeded (requires {required}; {used} bytes already retained or reserved)"),
            Self::WriterSpoolMemoryLimitExceeded { limit, required, used } => write!(f,
                "writer spool memory limit {limit} bytes exceeded (requires {required}; {used} bytes already retained or reserved)"),
            Self::MemoryLimitExceeded {
                limit,
                required,
                dictionary_size,
            } => write!(
                f,
                "compression needs at least {required} bytes of working memory for a {dictionary_size}-byte dictionary, above the configured limit of {limit} bytes"
            ),
            Self::UnsupportedFamilyFeature { family, feature } => {
                write!(f, "feature {feature} is not supported by {family:?}")
            }
            Self::UnsupportedCompression {
                family,
                unpack_version,
                method,
            } => write!(
                f,
                "{family} compression is not supported: unpack version {unpack_version}, method {method:#04x}"
            ),
            Self::UnsupportedEncryption {
                family,
                unpack_version,
            } => write!(
                f,
                "{family} encryption is not supported: unpack version {unpack_version}"
            ),
            Self::Io(error) => write!(f, "I/O error: {}", error.message),
            Self::NeedPassword => write!(f, "a password is required"),
            Self::WrongPasswordOrCorruptData => {
                write!(f, "wrong password or corrupt encrypted data")
            }
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#06x}, got {actual:#06x}"
                )
            }
            Self::Crc32Mismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                )
            }
            Self::HashMismatch { hash_type } => {
                write!(f, "hash mismatch for hash type {hash_type}")
            }
            Self::Codec(error) => write!(f, "{error}"),
            Self::Rar3Recovery(error) => write!(f, "{error}"),
            Self::Rar5Recovery(error) => write!(f, "{error}"),
            Self::Rar20Crypto(error) => write!(f, "{error}"),
            Self::Rar30Crypto(error) => write!(f, "{error}"),
            Self::Rar50Crypto(error) => write!(f, "{error}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        // A reader buried inside a decoder has only `io::Error` to report
        // through, so it wraps the real error. Unwrap it again here, otherwise
        // a checksum mismatch surfaces as an I/O failure.
        let error = match error.downcast::<Self>() {
            Ok(inner) => return inner,
            Err(error) => error,
        };
        Self::Io(IoError {
            kind: error.kind(),
            message: error.to_string(),
            source: Arc::new(error),
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AtArchiveOffset { source, .. }
            | Self::AtEntry { source, .. }
            | Self::InVolume { source, .. } => Some(source),
            Self::Codec(source) => Some(source),
            Self::Rar3Recovery(source) => Some(source),
            Self::Rar5Recovery(source) => Some(source),
            Self::Rar20Crypto(source) => Some(source),
            Self::Rar30Crypto(source) => Some(source),
            Self::Rar50Crypto(source) => Some(source),
            Self::Io(source) => Some(source.source()),
            _ => None,
        }
    }
}

impl Error {
    /// The underlying library error, with archive/entry/volume context removed.
    /// The original error still owns and displays every context wrapper.
    pub fn root_cause(&self) -> &Self {
        let mut error = self;
        while let Self::AtArchiveOffset { source, .. }
        | Self::AtEntry { source, .. }
        | Self::InVolume { source, .. } = error
        {
            error = source;
        }
        error
    }

    /// Names the volume a member failed in, counting the first as 0, unless
    /// the error names a volume already or no member.
    pub(crate) fn in_member_volume(self, index: usize) -> Self {
        let mut error = &self;
        loop {
            match error {
                Self::InVolume { .. } => return self,
                Self::AtArchiveOffset { source, .. } | Self::AtEntry { source, .. } => {
                    error = source
                }
                _ => break,
            }
        }
        if self.entry_context().is_none() {
            return self;
        }
        Self::InVolume {
            index,
            source: Box::new(self),
        }
    }

    /// The outermost member context, if this error identifies a member.
    pub fn entry_context(&self) -> Option<(&[u8], &'static str)> {
        let mut error = self;
        loop {
            match error {
                Self::AtEntry {
                    name, operation, ..
                } => return Some((name, operation)),
                Self::AtArchiveOffset { source, .. } | Self::InVolume { source, .. } => {
                    error = source
                }
                _ => return None,
            }
        }
    }

    /// Classify the cause without discarding its diagnostic context.
    pub fn kind(&self) -> ErrorKind {
        match self.root_cause() {
            Self::AtArchiveOffset { .. } | Self::AtEntry { .. } | Self::InVolume { .. } => {
                unreachable!("root cause has no context wrapper")
            }
            Self::UnsupportedSignature | Self::UnsupportedVersion(_) => {
                ErrorKind::UnsupportedFormat
            }
            Self::FeatureDisabled { .. }
            | Self::Rar50Crypto(crate::crypto::rar50::Error::FeatureDisabled)
            | Self::CannotSkipSolidMember
            | Self::BrokenSolidChain
            | Self::Rar3VmProgramRefused
            | Self::UnsupportedFeature { .. }
            | Self::UnsupportedFamilyFeature { .. }
            | Self::UnsupportedCompression { .. }
            | Self::UnsupportedEncryption { .. }
            | Self::UnsupportedWriterOption { .. }
            | Self::UnrewritableEntry { .. } => ErrorKind::UnsupportedFeature,
            Self::NeedPassword => ErrorKind::PasswordRequired,
            Self::WrongPasswordOrCorruptData
            | Self::Rar50Crypto(crate::crypto::rar50::Error::BadPassword) => ErrorKind::BadPassword,
            Self::CrcMismatch { .. } | Self::Crc32Mismatch { .. } | Self::HashMismatch { .. } => {
                ErrorKind::ChecksumMismatch
            }
            Self::Rar5Recovery(crate::recovery::rar5::Error::Cancelled) => ErrorKind::Cancelled,
            Self::Io(_) | Self::Rar5Recovery(crate::recovery::rar5::Error::Io(_)) => ErrorKind::Io,
            Self::Rar50ScratchLimitExceeded { .. }
            | Self::RewriteStagingLimitExceeded { .. }
            | Self::Rar50FilterMemoryLimitExceeded { .. }
            | Self::MemoryLimitExceeded { .. }
            | Self::WriterSpoolLimitExceeded { .. }
            | Self::WriterSpoolMemoryLimitExceeded { .. }
            | Self::WriterPreparedHeaderLimitExceeded { .. }
            | Self::WriterPreparationLimitExceeded { .. }
            | Self::MemberOutputLimitExceeded { .. }
            | Self::SolidSkipBudgetExceeded { .. }
            | Self::HeaderCountLimitExceeded { .. }
            | Self::HeaderBytesLimitExceeded { .. }
            | Self::TotalOutputLimitExceeded { .. }
            | Self::Rar50DictionaryLimitExceeded { .. }
            | Self::Rar50BufferedDecodeLimitExceeded { .. }
            | Self::Rar5Recovery(crate::recovery::rar5::Error::RebuildTooLarge)
            | Self::Rar5Recovery(crate::recovery::rar5::Error::RepairWorkspaceLimitExceeded {
                ..
            }) => ErrorKind::ResourceLimit,
            Self::Codec(crate::codec::Error::Io(error)) => error.kind(),
            Self::Codec(crate::codec::Error::WorkspaceLimitExceeded(_)) => ErrorKind::ResourceLimit,
            Self::Cancelled | Self::Codec(crate::codec::Error::Cancelled) => ErrorKind::Cancelled,
            Self::EntryNotFound => ErrorKind::EntryNotFound,
            Self::DuplicateEntry => ErrorKind::DuplicateEntry,
            Self::InputSymlink | Self::InvalidArgument(_) => ErrorKind::InvalidArgument,
            Self::UnsafePath(_) => ErrorKind::UnsafePath,
            Self::SourceChanged(_) => ErrorKind::SourceChanged,
            Self::WriterFailure(_) => ErrorKind::WriterFailure,
            Self::TooShort
            | Self::InvalidHeader(_)
            | Self::MissingVolume
            | Self::VolumeOutOfOrder
            | Self::Codec(_)
            | Self::Rar3Recovery(_)
            | Self::Rar5Recovery(_)
            | Self::Rar20Crypto(_)
            | Self::Rar30Crypto(_)
            | Self::Rar50Crypto(_) => ErrorKind::InvalidArchive,
        }
    }

    pub fn at_archive_offset(self, offset: usize) -> Self {
        Self::AtArchiveOffset {
            offset,
            source: Box::new(self),
        }
    }

    pub fn at_entry(self, name: Vec<u8>, operation: &'static str) -> Self {
        Self::AtEntry {
            name,
            operation,
            source: Box::new(self),
        }
    }
}

impl From<crate::codec::Error> for Error {
    fn from(error: crate::codec::Error) -> Self {
        match error {
            crate::codec::Error::Cancelled => Self::Cancelled,
            crate::codec::Error::Rar3VmProgramRefused => Self::Rar3VmProgramRefused,
            crate::codec::Error::Io(error) => *error,
            error => Self::Codec(error),
        }
    }
}

impl From<crate::recovery::rar5::Error> for Error {
    fn from(error: crate::recovery::rar5::Error) -> Self {
        match error {
            crate::recovery::rar5::Error::Cancelled => Self::Cancelled,
            crate::recovery::rar5::Error::TypedIo(error) => *error,
            error => Self::Rar5Recovery(error),
        }
    }
}

impl From<crate::recovery::rar3::Error> for Error {
    fn from(error: crate::recovery::rar3::Error) -> Self {
        Self::Rar3Recovery(error)
    }
}

impl From<crate::crypto::rar20::Error> for Error {
    fn from(error: crate::crypto::rar20::Error) -> Self {
        Self::Rar20Crypto(error)
    }
}

impl From<crate::crypto::rar30::Error> for Error {
    fn from(error: crate::crypto::rar30::Error) -> Self {
        Self::Rar30Crypto(error)
    }
}

impl From<crate::crypto::rar50::Error> for Error {
    fn from(error: crate::crypto::rar50::Error) -> Self {
        if error == crate::crypto::rar50::Error::FeatureDisabled {
            return Self::FeatureDisabled {
                feature: "encryption",
            };
        }
        Self::Rar50Crypto(error)
    }
}
