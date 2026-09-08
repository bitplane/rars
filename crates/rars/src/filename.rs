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

/// Encode a renamed legacy Unicode entry without relying on a code page.
/// Full UTF-16 units make the Unicode stream independent of the ASCII fallback.
pub(crate) fn encode_legacy_unicode(name: &[u8]) -> Result<Vec<u8>> {
    validate_relative(name)?;
    let text = std::str::from_utf8(name)
        .map_err(|_| Error::InvalidArgument("renaming a Unicode entry requires a UTF-8 name"))?;
    let mut raw: Vec<u8> = text
        .chars()
        .map(|ch| if ch.is_ascii() { ch as u8 } else { b'_' })
        .collect();
    raw.extend_from_slice(&[0, 0]);
    let units: Vec<u16> = text.encode_utf16().collect();
    for group in units.chunks(4) {
        raw.push(0xaa); // Four full UTF-16 commands; unused low bits are ignored.
        for unit in group {
            raw.extend_from_slice(&unit.to_le_bytes());
        }
    }
    if raw.len() > usize::from(u16::MAX) - 32 {
        return Err(Error::InvalidArgument(
            "legacy Unicode filename is too long",
        ));
    }
    Ok(raw)
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

/// Explicit source encoding for legacy names without a Unicode representation.
/// These mappings are locale independent and shared by every binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LegacyNameEncoding {
    Cp437,
    Cp850,
    Cp852,
    Cp866,
    Windows1251,
    Windows1252,
    Utf8,
}

impl std::str::FromStr for LegacyNameEncoding {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "cp437" => Ok(Self::Cp437),
            "cp850" => Ok(Self::Cp850),
            "cp852" => Ok(Self::Cp852),
            "cp866" => Ok(Self::Cp866),
            "cp1251" | "windows-1251" => Ok(Self::Windows1251),
            "cp1252" | "windows-1252" => Ok(Self::Windows1252),
            "utf8" | "utf-8" => Ok(Self::Utf8),
            _ => Err(Error::InvalidArgument("unsupported legacy name encoding (use cp437, cp850, cp852, cp866, windows-1251, windows-1252 or utf-8)")),
        }
    }
}

impl LegacyNameEncoding {
    /// Strict decoding: undefined bytes never become replacement characters.
    pub fn decode(self, name: &[u8]) -> Result<String> {
        if self == Self::Utf8 {
            return std::str::from_utf8(name)
                .map(str::to_owned)
                .map_err(|_| Error::InvalidArgument("legacy name is not valid UTF-8"));
        }
        let table = match self {
            Self::Cp437 => &CP437,
            Self::Cp850 => &CP850,
            Self::Cp852 => &CP852,
            Self::Cp866 => &CP866,
            Self::Windows1251 => &CP1251,
            Self::Windows1252 => &CP1252,
            Self::Utf8 => unreachable!(),
        };
        name.iter()
            .map(|&byte| {
                if byte < 128 {
                    Ok(char::from(byte))
                } else {
                    char::from_u32(u32::from(table[usize::from(byte - 128)])).ok_or(
                        Error::InvalidArgument("undefined byte in selected legacy name encoding"),
                    )
                }
            })
            .collect()
    }
}

/// Interpret a legacy name without changing its stored identity. `unicode` means
/// the format already supplied Unicode, which always takes precedence. Without
/// an explicit encoding the existing bytes are returned unchanged.
pub fn decoded_name(
    name: &[u8],
    unicode: bool,
    encoding: Option<LegacyNameEncoding>,
) -> Result<Cow<'_, [u8]>> {
    match encoding {
        Some(encoding) if !unicode => encoding
            .decode(name)
            .map(|text| Cow::Owned(text.into_bytes()))
            .map_err(|error| error.at_entry(name.to_vec(), "decoding legacy filename")),
        _ => Ok(Cow::Borrowed(name)),
    }
}

// High-byte mappings from Python's standard-library IBM/Microsoft codec tables.
// ASCII 0..127 is unchanged. 0xD800 marks an undefined code-page byte.
const CP437: [u16; 128] = [
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb, 0x00e8, 0x00ef,
    0x00ee, 0x00ec, 0x00c4, 0x00c5, 0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
    0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192, 0x00e1, 0x00ed, 0x00f3, 0x00fa,
    0x00f1, 0x00d1, 0x00aa, 0x00ba, 0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255d, 0x255c, 0x255b, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
    0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4, 0x03a6, 0x0398, 0x03a9, 0x03b4,
    0x221e, 0x03c6, 0x03b5, 0x2229, 0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
    0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0,
];
const CP850: [u16; 128] = [
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb, 0x00e8, 0x00ef,
    0x00ee, 0x00ec, 0x00c4, 0x00c5, 0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
    0x00ff, 0x00d6, 0x00dc, 0x00f8, 0x00a3, 0x00d8, 0x00d7, 0x0192, 0x00e1, 0x00ed, 0x00f3, 0x00fa,
    0x00f1, 0x00d1, 0x00aa, 0x00ba, 0x00bf, 0x00ae, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00c1, 0x00c2, 0x00c0, 0x00a9, 0x2563, 0x2551, 0x2557,
    0x255d, 0x00a2, 0x00a5, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x00e3, 0x00c3,
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x00a4, 0x00f0, 0x00d0, 0x00ca, 0x00cb,
    0x00c8, 0x0131, 0x00cd, 0x00ce, 0x00cf, 0x2518, 0x250c, 0x2588, 0x2584, 0x00a6, 0x00cc, 0x2580,
    0x00d3, 0x00df, 0x00d4, 0x00d2, 0x00f5, 0x00d5, 0x00b5, 0x00fe, 0x00de, 0x00da, 0x00db, 0x00d9,
    0x00fd, 0x00dd, 0x00af, 0x00b4, 0x00ad, 0x00b1, 0x2017, 0x00be, 0x00b6, 0x00a7, 0x00f7, 0x00b8,
    0x00b0, 0x00a8, 0x00b7, 0x00b9, 0x00b3, 0x00b2, 0x25a0, 0x00a0,
];
const CP852: [u16; 128] = [
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x016f, 0x0107, 0x00e7, 0x0142, 0x00eb, 0x0150, 0x0151,
    0x00ee, 0x0179, 0x00c4, 0x0106, 0x00c9, 0x0139, 0x013a, 0x00f4, 0x00f6, 0x013d, 0x013e, 0x015a,
    0x015b, 0x00d6, 0x00dc, 0x0164, 0x0165, 0x0141, 0x00d7, 0x010d, 0x00e1, 0x00ed, 0x00f3, 0x00fa,
    0x0104, 0x0105, 0x017d, 0x017e, 0x0118, 0x0119, 0x00ac, 0x017a, 0x010c, 0x015f, 0x00ab, 0x00bb,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00c1, 0x00c2, 0x011a, 0x015e, 0x2563, 0x2551, 0x2557,
    0x255d, 0x017b, 0x017c, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x0102, 0x0103,
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x00a4, 0x0111, 0x0110, 0x010e, 0x00cb,
    0x010f, 0x0147, 0x00cd, 0x00ce, 0x011b, 0x2518, 0x250c, 0x2588, 0x2584, 0x0162, 0x016e, 0x2580,
    0x00d3, 0x00df, 0x00d4, 0x0143, 0x0144, 0x0148, 0x0160, 0x0161, 0x0154, 0x00da, 0x0155, 0x0170,
    0x00fd, 0x00dd, 0x0163, 0x00b4, 0x00ad, 0x02dd, 0x02db, 0x02c7, 0x02d8, 0x00a7, 0x00f7, 0x00b8,
    0x00b0, 0x00a8, 0x02d9, 0x0171, 0x0158, 0x0159, 0x25a0, 0x00a0,
];
const CP866: [u16; 128] = [
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, 0x0418, 0x0419, 0x041a, 0x041b,
    0x041c, 0x041d, 0x041e, 0x041f, 0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,
    0x0428, 0x0429, 0x042a, 0x042b, 0x042c, 0x042d, 0x042e, 0x042f, 0x0430, 0x0431, 0x0432, 0x0433,
    0x0434, 0x0435, 0x0436, 0x0437, 0x0438, 0x0439, 0x043a, 0x043b, 0x043c, 0x043d, 0x043e, 0x043f,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255d, 0x255c, 0x255b, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, 0x0448, 0x0449, 0x044a, 0x044b,
    0x044c, 0x044d, 0x044e, 0x044f, 0x0401, 0x0451, 0x0404, 0x0454, 0x0407, 0x0457, 0x040e, 0x045e,
    0x00b0, 0x2219, 0x00b7, 0x221a, 0x2116, 0x00a4, 0x25a0, 0x00a0,
];
const CP1251: [u16; 128] = [
    0x0402, 0x0403, 0x201a, 0x0453, 0x201e, 0x2026, 0x2020, 0x2021, 0x20ac, 0x2030, 0x0409, 0x2039,
    0x040a, 0x040c, 0x040b, 0x040f, 0x0452, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0xd800, 0x2122, 0x0459, 0x203a, 0x045a, 0x045c, 0x045b, 0x045f, 0x00a0, 0x040e, 0x045e, 0x0408,
    0x00a4, 0x0490, 0x00a6, 0x00a7, 0x0401, 0x00a9, 0x0404, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x0407,
    0x00b0, 0x00b1, 0x0406, 0x0456, 0x0491, 0x00b5, 0x00b6, 0x00b7, 0x0451, 0x2116, 0x0454, 0x00bb,
    0x0458, 0x0405, 0x0455, 0x0457, 0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
    0x0418, 0x0419, 0x041a, 0x041b, 0x041c, 0x041d, 0x041e, 0x041f, 0x0420, 0x0421, 0x0422, 0x0423,
    0x0424, 0x0425, 0x0426, 0x0427, 0x0428, 0x0429, 0x042a, 0x042b, 0x042c, 0x042d, 0x042e, 0x042f,
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, 0x0438, 0x0439, 0x043a, 0x043b,
    0x043c, 0x043d, 0x043e, 0x043f, 0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
    0x0448, 0x0449, 0x044a, 0x044b, 0x044c, 0x044d, 0x044e, 0x044f,
];
const CP1252: [u16; 128] = [
    0x20ac, 0xd800, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039,
    0x0152, 0xd800, 0x017d, 0xd800, 0xd800, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0xd800, 0x017e, 0x0178, 0x00a0, 0x00a1, 0x00a2, 0x00a3,
    0x00a4, 0x00a5, 0x00a6, 0x00a7, 0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb,
    0x00bc, 0x00bd, 0x00be, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf, 0x00d0, 0x00d1, 0x00d2, 0x00d3,
    0x00d4, 0x00d5, 0x00d6, 0x00d7, 0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb,
    0x00ec, 0x00ed, 0x00ee, 0x00ef, 0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff,
];
