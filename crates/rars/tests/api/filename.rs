use rars::filename::*;

use rars::Error;
use std::path::PathBuf;

#[test]
fn utf8_legacy_decoding_is_strict_for_both_valid_and_invalid_input() {
    for name in ["", "é", "🦀", "a/b"] {
        assert_eq!(
            LegacyNameEncoding::Utf8.decode(name.as_bytes()).unwrap(),
            name
        );
    }
    assert_eq!(
        LegacyNameEncoding::Utf8.decode(&[0xff]),
        Err(Error::InvalidArgument("legacy name is not valid UTF-8")),
    );
}

#[test]
fn native_names_preserve_utf8_and_unix_legacy_bytes_without_replacement() {
    let bytes = "café.txt".as_bytes();
    let borrowed = native_str(bytes).unwrap();
    assert!(std::ptr::eq(
        native_bytes(borrowed).unwrap().as_ptr(),
        bytes.as_ptr()
    ));
    let name = native_string(bytes).unwrap();
    assert_eq!(native_bytes(&name).unwrap(), bytes);
    #[cfg(unix)]
    {
        let bytes = b"caf\xff.txt";
        let name = native_string(bytes).unwrap();
        assert_eq!(native_bytes(&name).unwrap(), bytes);
    }
    #[cfg(not(unix))]
    assert!(native_string(b"caf\xff.txt").is_err());
}

#[test]
fn destination_paths_preserve_selected_separator_policy_and_error_categories() {
    for separator in [false, true] {
        for name in [b"a\0b".as_slice(), b"/root", b"a/../b", b"C:root"] {
            assert!(matches!(
                relative_path(name, separator),
                Err(Error::UnsafePath(_))
            ));
        }
        for name in [b"".as_slice(), b".", b"././"] {
            assert_eq!(
                relative_path(name, separator),
                Err(Error::InvalidHeader("empty archive path"))
            );
        }
        assert_eq!(
            relative_path(b"./a//./b", separator).unwrap(),
            PathBuf::from("a").join("b")
        );
    }
    assert_eq!(
        relative_path(b"a\\b", true).unwrap(),
        PathBuf::from("a").join("b")
    );
    assert!(relative_path(b"a\\..\\b", true).is_err());
    #[cfg(unix)]
    {
        assert_eq!(
            relative_path(b"..\\literal", false).unwrap(),
            PathBuf::from("..\\literal")
        );
        assert_eq!(
            native_bytes(relative_path(b"caf\xff", false).unwrap().as_os_str()).unwrap(),
            b"caf\xff"
        );
    }
    #[cfg(not(unix))]
    assert!(relative_path(b"caf\xff", false).is_err());
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
