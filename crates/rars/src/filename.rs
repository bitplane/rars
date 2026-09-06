//! Conversion at the boundary between archive member names and native paths.
//!
//! Legacy byte names have no reliably inferable code page. On Unix they remain
//! bytes; Unicode legacy names have already been decoded by the format reader.
//! RAR5 archive names remain in their wire encoding in member metadata and lookup
//! APIs. Its Unix byte mapping is applied only when importing/exporting paths.

use crate::{Error, Result};
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};

/// Native filename bytes on Unix, UTF-8 elsewhere. Never substitutes characters.
pub fn native_bytes(name: &OsStr) -> Result<&[u8]> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(name.as_bytes())
    }
    #[cfg(not(unix))]
    {
        name.to_str()
            .map(str::as_bytes)
            .ok_or(Error::InvalidArgument(
                "native filename cannot be represented as Unicode",
            ))
    }
}

/// Convert decoded filename bytes to a native name without replacement.
/// Non-Unix platforms require Unicode; an unspecified legacy code page is not
/// guessed. This function does not validate paths or decode RAR5 wire names.
pub fn native_string(name: &[u8]) -> Result<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(OsString::from_vec(name.to_vec()))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(name).map(OsString::from).map_err(|_| {
            Error::InvalidArgument(
                "archive name requires an explicit legacy code page on this platform",
            )
        })
    }
}

/// Encode native Unix filename bytes as a RAR5 UTF-8 name.
///
/// Valid UTF-8 is unchanged unless it contains the reserved U+FFFE marker.
/// Otherwise high bytes are mapped to U+E080..U+E0FF with a U+FFFE marker.
/// Mapping all high bytes in this case also protects literal private-use
/// characters and literal markers from being confused with encoded bytes.
/// See <https://www.rarlab.com/technote.htm>.
pub fn encode_rar50(name: &[u8]) -> Cow<'_, [u8]> {
    if std::str::from_utf8(name).is_ok_and(|s| !s.contains('\u{fffe}')) {
        return Cow::Borrowed(name);
    }
    let mut out = String::from("\u{fffe}");
    for &byte in name {
        out.push(if byte < 0x80 {
            char::from(byte)
        } else {
            char::from_u32(0xe000 + u32::from(byte)).expect("mapped high byte")
        });
    }
    Cow::Owned(out.into_bytes())
}

/// Restore a RAR5 Unix mapped name to filename bytes. Call only for Unix-host
/// names when writing to a Unix filesystem. Unmarked names, including malformed
/// UTF-8 from tolerant archive readers, retain their exact bytes.
pub fn decode_rar50(name: &[u8]) -> Cow<'_, [u8]> {
    let Ok(text) = std::str::from_utf8(name) else {
        return Cow::Borrowed(name);
    };
    if !text.contains('\u{fffe}') {
        return Cow::Borrowed(name);
    }
    let mut out = Vec::with_capacity(name.len());
    for ch in text.chars() {
        match ch {
            '\u{fffe}' => {}
            '\u{e080}'..='\u{e0ff}' => out.push((ch as u32 - 0xe000) as u8),
            _ => out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    Cow::Owned(out)
}

/// Validate relative member identity using ASCII path syntax, independently of
/// filename encoding and of the destination filesystem.
pub(crate) fn validate_relative(name: &[u8]) -> Result<()> {
    if name.contains(&0) {
        return Err(Error::UnsafePath("unsafe archive path contains NUL byte"));
    }
    if name.first().is_some_and(|b| matches!(b, b'/' | b'\\'))
        || (name.len() >= 2 && name[0].is_ascii_alphabetic() && name[1] == b':')
        || name
            .split(|b| matches!(b, b'/' | b'\\'))
            .any(|p| p == b"..")
    {
        return Err(Error::UnsafePath("unsafe archive path"));
    }
    if name
        .split(|b| matches!(b, b'/' | b'\\'))
        .all(|p| p.is_empty() || p == b".")
    {
        return Err(Error::InvalidArgument("empty archive path"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar50_mapping_is_reversible_and_does_not_alias_unicode() {
        let mut bytes: Vec<u8> = (0x80..=0xff).collect();
        bytes.extend_from_slice("/日本語/\u{fffe}\u{e080}".as_bytes());
        for name in [
            bytes.as_slice(),
            "literal-\u{fffe}".as_bytes(),
            b"bad-\xff",
            "\u{e0ff}".as_bytes(),
        ] {
            let encoded = encode_rar50(name);
            assert!(std::str::from_utf8(&encoded).is_ok());
            assert_eq!(decode_rar50(&encoded).as_ref(), name);
        }
        assert_ne!(
            encode_rar50(b"bad-\xff"),
            encode_rar50("bad-\u{fffd}".as_bytes())
        );
        assert!(matches!(
            encode_rar50("cafe\u{301}/日本語".as_bytes()),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn rar50_mapping_accepts_reference_mixed_names_and_marker_positions() {
        for encoded in ["a\u{fffe}\u{e0ff}日本語", "a\u{e0ff}日本語\u{fffe}"] {
            assert_eq!(
                decode_rar50(encoded.as_bytes()).as_ref(),
                b"a\xff\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e"
            );
        }
        // Only high bytes are mapped; lower private-use characters stay Unicode.
        assert_eq!(
            decode_rar50("\u{fffe}\u{e02f}".as_bytes()).as_ref(),
            "\u{e02f}".as_bytes()
        );
    }
}
