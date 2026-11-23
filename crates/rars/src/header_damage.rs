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
