//! Fresh salts and IVs for writing archives or framing repaired headers.

use crate::{Error, Result};

fn entropy_error(error: getrandom::Error, context: &'static str) -> Error {
    std::io::Error::other(format!("{context}: {error}")).into()
}

/// Fill salt or IV bytes using the operating system's entropy source.
pub(crate) fn fill_entropy(bytes: &mut [u8], context: &'static str) -> Result<()> {
    fill_entropy_with(bytes, context, getrandom::fill)
}

fn fill_entropy_with(
    bytes: &mut [u8],
    context: &'static str,
    fill: fn(&mut [u8]) -> std::result::Result<(), getrandom::Error>,
) -> Result<()> {
    fill(bytes).map_err(|error| entropy_error(error, context))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_failure_is_io_and_keeps_the_backend_diagnostic() {
        let error = super::entropy_error(getrandom::Error::UNSUPPORTED, "encryption salt");
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert!(error.to_string().contains("encryption salt"));
        assert!(error
            .to_string()
            .contains(&getrandom::Error::UNSUPPORTED.to_string()));
    }

    #[test]
    fn entropy_fill_delegates_the_whole_buffer_and_refuses_backend_failure() {
        fn success(bytes: &mut [u8]) -> std::result::Result<(), getrandom::Error> {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = index as u8;
            }
            Ok(())
        }
        fn failure(bytes: &mut [u8]) -> std::result::Result<(), getrandom::Error> {
            bytes[0] = 42;
            Err(getrandom::Error::UNSUPPORTED)
        }
        for context in [
            "RAR 3.x writer could not generate encryption salt",
            "RAR 5 writer could not generate encryption salt",
            "RAR 5 writer could not generate encryption IV",
        ] {
            let mut bytes = [0xff; 16];
            fill_entropy_with(&mut bytes, context, success).unwrap();
            assert_eq!(bytes, std::array::from_fn(|index| index as u8));
            let error = fill_entropy_with(&mut bytes, context, failure).unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::Io);
            assert_eq!(
                error.to_string(),
                format!("I/O error: {context}: {}", getrandom::Error::UNSUPPORTED)
            );
            assert_eq!(bytes[0], 42);
            assert_eq!(&bytes[1..], &(1u8..16).collect::<Vec<_>>());
        }
    }
}
