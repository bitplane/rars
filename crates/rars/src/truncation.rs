//! Archives whose file ends before their last block does.

use std::fmt;

/// Where an archive's file was cut short, found while reading its blocks.
///
/// Every member listed before the cut is whole and can be tested and
/// extracted. A cut through a file header or member data is an error instead,
/// unless the archive was read with a member error handler (see
/// [`crate::ArchiveReadOptions::with_member_error_handler`]); then it ends the
/// archive here as [`TruncatedBlock::Member`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Truncation {
    /// File offset of the block the file ends in, or where the next block was due.
    pub offset: u64,
    /// The block the file ends in, or the one that was due.
    pub block: TruncatedBlock,
    /// Whether any of that block is in the file.
    pub started: bool,
}

/// The kind of block an archive's file ends in.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TruncatedBlock {
    /// A member whose file header or data the cut goes through, by stored
    /// name. Empty when the cut leaves no name.
    Member(Vec<u8>),
    /// The recovery record.
    RecoveryRecord,
    /// A service block other than the recovery record, by stored name, such
    /// as `QO`, `CMT` or `AV`. Empty when the cut leaves no name.
    Service(Vec<u8>),
    /// An old-style archive comment block.
    Comment,
    /// The end of archive block.
    End,
    /// A block too little of which is left to tell, or of a type the reader
    /// doesn't know.
    Unknown,
}

impl Truncation {
    pub(crate) fn new(offset: usize, block: TruncatedBlock, started: bool) -> Self {
        Self {
            offset: offset as u64,
            block,
            started,
        }
    }
}

impl TruncatedBlock {
    /// A service block by its stored name.
    pub(crate) fn service(name: &[u8]) -> Self {
        if name == b"RR" {
            Self::RecoveryRecord
        } else {
            Self::Service(name.to_vec())
        }
    }
}

impl fmt::Display for TruncatedBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Member(name) if name.is_empty() => f.write_str("a file header"),
            Self::Member(name) => {
                write!(
                    f,
                    "member '{}'",
                    String::from_utf8_lossy(name).escape_debug()
                )
            }
            Self::RecoveryRecord => f.write_str("the recovery record"),
            Self::Service(name) if name.is_empty() => f.write_str("a service block"),
            Self::Service(name) => {
                write!(
                    f,
                    "service block '{}'",
                    String::from_utf8_lossy(name).escape_debug()
                )
            }
            Self::Comment => f.write_str("the archive comment"),
            Self::End => f.write_str("the end of archive block"),
            Self::Unknown => f.write_str("a block header"),
        }
    }
}

impl fmt::Display for Truncation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.started {
            write!(
                f,
                "truncated inside {}, which starts at offset {}",
                self.block, self.offset
            )
        } else {
            write!(
                f,
                "truncated at offset {}, before {}",
                self.offset, self.block
            )
        }
    }
}
