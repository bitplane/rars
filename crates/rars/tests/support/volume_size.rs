//! A volume size counts every header in the volume, so a test that wants each
//! volume to carry a few bytes of member data cannot name that size directly.
//! These find it by asking the writer. Shared with the unit tests by path.

#![allow(dead_code)]

/// Calls `write` with the volume size that leaves `payload` bytes of member
/// data in each volume. The smallest size `write` accepts leaves room for one.
pub fn sized_for_payload<T, E: std::fmt::Display>(
    payload: usize,
    mut write: impl FnMut(usize) -> Result<T, E>,
) -> Result<T, E> {
    let size = smallest_volume_size(&mut write) + payload - 1;
    write(size)
}

/// The smallest volume size `write` does not refuse as too small for its
/// headers. Any other outcome, success or a different error, counts as
/// accepted, so a writer that refuses for another reason still reports it.
pub fn smallest_volume_size<T, E: std::fmt::Display>(
    mut write: impl FnMut(usize) -> Result<T, E>,
) -> usize {
    let (mut refused, mut accepted) = (0usize, 1usize << 16);
    while accepted - refused > 1 {
        let middle = refused + (accepted - refused) / 2;
        match write(middle) {
            Err(error) if error.to_string().contains("too small") => refused = middle,
            _ => accepted = middle,
        }
    }
    accepted
}
