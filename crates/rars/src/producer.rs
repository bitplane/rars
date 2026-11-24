//! Shared advisory producer payload; each container supplies its own framing.

pub(crate) const NAME: &[u8] = b"RARS";
#[cfg(not(test))]
pub(crate) const DATA: &[u8] =
    concat!("rars/", env!("CARGO_PKG_VERSION"), "\nmarker-schema=1\n").as_bytes();
/// Unit tests pin fingerprints of whole archives, so their marker carries a
/// fixed version rather than the crate's. Integration tests build the library
/// without `cfg(test)` and check the real version.
#[cfg(test)]
pub(crate) const DATA: &[u8] = b"rars/0.0.0-test\nmarker-schema=1\n";
pub(crate) const MAX_DATA_LEN: u64 = 128;

pub(crate) fn recognized(data: &[u8]) -> bool {
    data.strip_prefix(b"rars/")
        .and_then(|data| data.strip_suffix(b"\nmarker-schema=1\n"))
        .is_some_and(|version| {
            !version.is_empty()
                && version
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(byte))
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_unit_test_marker_is_recognized() {
        assert!(super::recognized(super::DATA));
    }
}
