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

/// `sized_for_payload` for a legacy member too long to search with.
///
/// The search ends by writing the member at the smallest size it accepts, cut
/// into one-byte volumes, and with encrypted headers every volume pays for its
/// own key derivations: in the slowest tests that one write was most of the
/// run. Legacy volumes repeat the same headers around every slice and no
/// header field grows with the member, so `probe`, writing the same member
/// with one byte of data, has the same smallest size and far less to cut up.
/// The full member is still asked about the size just below, which it refuses
/// at its first volume, so its volumes cannot carry more than `payload`.
pub fn sized_for_payload_probed<P, T, F: std::fmt::Display, E: std::fmt::Display>(
    payload: usize,
    probe: impl FnMut(usize) -> Result<P, F>,
    mut write: impl FnMut(usize) -> Result<T, E>,
) -> Result<T, E> {
    let smallest = smallest_volume_size(probe);
    assert!(
        matches!(write(smallest - 1), Err(error) if error.to_string().contains("too small")),
        "the full member fits a volume smaller than its one-byte probe needs"
    );
    write(smallest + payload - 1)
}

/// The smallest volume size `write` does not refuse as too small for its
/// headers. Any other outcome, success or a different error, counts as
/// accepted, so a writer that refuses for another reason still reports it.
/// Sizes just above the smallest split the data into one-byte volumes, so only the final scan probes there.
pub fn smallest_volume_size<T, E: std::fmt::Display>(
    mut write: impl FnMut(usize) -> Result<T, E>,
) -> usize {
    let mut refuses =
        |size| matches!(write(size), Err(error) if error.to_string().contains("too small"));
    let (mut refused, mut accepted) = (0usize, 64usize);
    while refuses(accepted) {
        assert!(
            accepted < 1 << 16,
            "every volume size up to {accepted} was refused"
        );
        refused = accepted;
        accepted *= 2;
    }
    while accepted - refused > 16 {
        let middle = refused + (accepted - refused) / 2;
        match refuses(middle) {
            true => refused = middle,
            false => accepted = middle,
        }
    }
    (refused + 1..accepted)
        .find(|&size| !refuses(size))
        .unwrap_or(accepted)
}
