//! Header damage a salvaging read went past.

use std::fmt;
use std::sync::{Arc, Mutex};

/// A damaged header that parsing with
/// [`crate::ArchiveReadOptions::with_salvage`] read past instead of refusing.
/// Listed by [`crate::Archive::header_damage`] in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HeaderDamage {
    /// File offset of the header.
    pub offset: u64,
    /// What is wrong with it.
    pub kind: HeaderDamageKind,
}

/// What is wrong with a header listed in [`HeaderDamage`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderDamageKind {
    /// The header's checksum doesn't match. It was read as it is stored,
    /// so any of its fields may be wrong. RAR 1.5 to 4.x store the low 16
    /// bits of a CRC32, RAR 5 the whole CRC32.
    Checksum { expected: u32, actual: u32 },
    /// An optional record in the header is malformed. It was dropped and
    /// the rest of the header kept. `record` is the RAR 5 extra record type.
    DroppedRecord { record: u64, reason: &'static str },
    /// The header doesn't parse. If its block's size could be read, the
    /// walk went on past it and its member is lost; otherwise the walk
    /// stopped here and any members after it are lost.
    Unreadable { reason: &'static str },
    /// The header doesn't parse, or a damaged header before it sent the walk
    /// astray, so the walk scanned forward for the next block header that
    /// checks out and carried on there, at file offset `next`. Anything
    /// between is lost, unless a quick-open copy fills it in.
    ///
    /// A header is taken only if its checksum matches and its type, sizes and
    /// fields make sense, with its data inside the file. A false match in
    /// compressed data is still possible, so a member found this way is
    /// verified by its own checksum like any other. A solid member after the
    /// gap has lost the history it needs and fails with
    /// [`crate::Error::SolidHistoryLost`] once its bytes are delivered.
    Resynced { reason: &'static str, next: u64 },
    /// The member's own header was lost to damage, and it was read from the
    /// copy in the RAR 5 quick-open block instead. The format says not to
    /// trust those copies, so salvage only uses one for a member the main
    /// headers no longer give. Its data is still checked against the checksum
    /// that copy records. `name` is the member's stored name.
    QuickOpenCopy { name: Vec<u8> },
}

impl fmt::Display for HeaderDamage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            HeaderDamageKind::Checksum { expected, actual } => write!(
                f,
                "header at offset {} fails its checksum (expected {expected:#x}, got {actual:#x}) and was read as stored",
                self.offset
            ),
            HeaderDamageKind::DroppedRecord { record, reason } => write!(
                f,
                "header at offset {} has a malformed record of type {record}, which was dropped: {reason}",
                self.offset
            ),
            HeaderDamageKind::Unreadable { reason } => write!(
                f,
                "header at offset {} doesn't parse: {reason}",
                self.offset
            ),
            HeaderDamageKind::Resynced { reason, next } => write!(
                f,
                "header at offset {} doesn't parse ({reason}); reading resumed at the next header found, at offset {next}",
                self.offset
            ),
            HeaderDamageKind::QuickOpenCopy { name } => write!(
                f,
                "member '{}' at offset {} was read from its quick-open copy, as its own header is lost",
                String::from_utf8_lossy(name).escape_debug(),
                self.offset
            ),
        }
    }
}

/// Where a salvaging parse collects the damage it reads past. Shared by the
/// clones of one parse's read control.
#[derive(Debug, Default)]
pub(crate) struct DamageLog(Mutex<Vec<HeaderDamage>>);

impl DamageLog {
    pub(crate) fn new() -> Arc<Self> {
        Arc::default()
    }

    pub(crate) fn push(&self, damage: HeaderDamage) {
        let mut list = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A header can be parsed twice, as when a cut is named; list it once.
        // Its entries are the last ones pushed.
        let repeated = list
            .iter()
            .rev()
            .take_while(|listed| listed.offset == damage.offset)
            .any(|listed| *listed == damage);
        if !repeated {
            list.push(damage);
        }
    }

    /// Drops what was listed for offsets in `range`: headers a damaged size
    /// led the walk to, which a resync found were no headers at all.
    pub(crate) fn retract(&self, range: std::ops::Range<u64>) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|damage| !range.contains(&damage.offset));
    }

    pub(crate) fn take(&self) -> Vec<HeaderDamage> {
        let mut list = std::mem::take(
            &mut *self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        list.sort_by_key(|damage| damage.offset);
        list
    }
}

/// The reason to give for a header or record that failed to parse.
pub(crate) fn record_reason(error: &crate::Error) -> &'static str {
    match error.root_cause() {
        crate::Error::InvalidHeader(reason) => reason,
        crate::Error::TooShort => "it runs past the end of its data",
        _ => "it doesn't parse",
    }
}

/// Whether `error` is what decoding a member's bytes can end in: invalid
/// data or a checksum that fails. A member whose history was lost reports
/// that instead, as the cause.
pub(crate) fn decoding_failure(error: &crate::Error) -> bool {
    matches!(
        error.kind(),
        crate::ErrorKind::InvalidArchive | crate::ErrorKind::ChecksumMismatch
    )
}
