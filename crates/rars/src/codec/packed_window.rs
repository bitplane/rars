//! Packed input read through a fixed window rather than whole, so a decoder's
//! memory does not grow with the member. Shared by the reader-based legacy
//! decoders.

use super::workspace::{Budget, Buffer};
use super::{Error, Result};
use std::io::Read;

/// The most packed input held at once.
pub(crate) const PACKED_WINDOW: usize = 1024 * 1024;
/// Refill once fewer bytes than this remain: more than one decode step of any
/// legacy format reads (an RAR 2.9 VM code is at most 64 KiB).
const PACKED_LOW_WATER: usize = 128 * 1024;
const PACKED_READ_CHUNK: usize = 32 * 1024;

/// A bit position no reader reaches: the window never refills again.
pub(crate) const DRAINED: usize = usize::MAX;

/// Drops the bytes before `bit_pos` and refills `input` from `src` up to the
/// window. Returns the bit position to refill at next, or [`DRAINED`] once
/// `src` is exhausted.
#[cold]
pub(crate) fn refill<B: Budget>(
    input: &mut Buffer<u8, B>,
    bit_pos: &mut usize,
    src: &mut dyn Read,
) -> Result<usize> {
    let consumed = *bit_pos / 8;
    input.discard_prefix(consumed);
    *bit_pos -= consumed * 8;
    let mut chunk = [0u8; PACKED_READ_CHUNK];
    while input.len() < PACKED_WINDOW {
        let want = (PACKED_WINDOW - input.len()).min(chunk.len());
        let len = match src.read(&mut chunk[..want]) {
            Ok(0) => return Ok(DRAINED),
            Ok(len) => len,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::from(error)),
        };
        input.extend_from_slice(&chunk[..len]).map_err(Into::into)?;
    }
    Ok((PACKED_WINDOW - PACKED_LOW_WATER) * 8)
}
