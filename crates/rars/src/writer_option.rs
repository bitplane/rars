//! Writer option names retained for structured error diagnostics.

use crate::features::Feature;

/// Something a caller can ask a writer for, that a format may not be able to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriterOption {
    Feature(Feature),
    CompressionLevel,
    /// An engine other than the format's default, which today means PPMd.
    CompressionMethod,
    DictionarySize,
    Filter,
    RecoveryRecord,
    VolumeSize,
    ArchiveComment,
    FileComment,
    ArchiveMetadata,
    Password,
    MemoryLimit,
    TempDir,
}

impl WriterOption {
    pub const ALL: [Self; 15] = [
        Self::Feature(Feature::Solid),
        Self::Feature(Feature::HeaderEncryption),
        Self::Feature(Feature::QuickOpen),
        Self::CompressionLevel,
        Self::CompressionMethod,
        Self::DictionarySize,
        Self::Filter,
        Self::RecoveryRecord,
        Self::VolumeSize,
        Self::ArchiveComment,
        Self::FileComment,
        Self::ArchiveMetadata,
        Self::Password,
        Self::MemoryLimit,
        Self::TempDir,
    ];

    /// How this option is named in a library message. The command line
    /// substitutes the flag the user actually typed.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Feature(feature) => feature.name(),
            Self::CompressionLevel => "a compression level",
            Self::CompressionMethod => "an alternative compression method",
            Self::DictionarySize => "a dictionary size",
            Self::Filter => "a data filter",
            Self::RecoveryRecord => "a recovery record",
            Self::VolumeSize => "splitting into volumes",
            Self::ArchiveComment => "an archive comment",
            Self::FileComment => "a per-file comment",
            Self::ArchiveMetadata => "archive metadata",
            Self::Password => "encryption",
            Self::MemoryLimit => "a memory limit",
            Self::TempDir => "a temporary directory",
        }
    }
}
