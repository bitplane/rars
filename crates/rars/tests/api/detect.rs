use rars::detect::*;

use rars::detect::{find_archive_start, RAR15_SIGNATURE, SFX_SCAN_LIMIT};
use rars::ArchiveFamily;

#[test]
fn detects_all_known_signatures() {
    assert_eq!(
        detect_archive_family(b"RE~^").unwrap().family,
        ArchiveFamily::Rar13
    );
    assert_eq!(
        detect_archive_family(b"Rar!\x1a\x07\x00").unwrap().family,
        ArchiveFamily::Rar15To40
    );
    assert_eq!(
        detect_archive_family(b"Rar!\x1a\x07\x01\x00")
            .unwrap()
            .family,
        ArchiveFamily::Rar50Plus
    );
}

#[test]
fn finds_sfx_prefixed_archive() {
    let sig = find_archive_start(b"stub bytes RE~^payload", 128).unwrap();
    assert_eq!(sig.family, ArchiveFamily::Rar13);
    assert_eq!(sig.offset, 11);
}

#[test]
fn sfx_scan_prefers_stronger_rar15_signature_over_earlier_rar13_bytes() {
    let sig = find_archive_start(b"stub RE~^ bytes Rar!\x1a\x07\x00payload", 128).unwrap();
    assert_eq!(sig.family, ArchiveFamily::Rar15To40);
    assert_eq!(sig.offset, 16);
}

#[test]
fn rejects_unknown_and_truncated_signatures() {
    assert_eq!(detect_archive_family(b""), None);
    assert_eq!(detect_archive_family(b"RAR!"), None);
    assert_eq!(detect_archive_family(b"Rar!\x1a\x07"), None);
    assert_eq!(find_archive_start(b"not an archive", 128), None);
}

#[test]
fn scan_limit_bounds_sfx_detection() {
    let input = b"stub bytes RE~^payload";

    assert_eq!(find_archive_start(input, 10), None);

    let sig = find_archive_start(input, 11).unwrap();
    assert_eq!(sig.family, ArchiveFamily::Rar13);
    assert_eq!(sig.offset, 11);
    assert_eq!(sig.length, RAR13_SIGNATURE.len());
}

#[test]
fn shorter_signatures_in_scan_lookahead_do_not_escape_the_offset_limit() {
    for signature in [RAR15_SIGNATURE.as_slice(), RAR13_SIGNATURE.as_slice()] {
        let mut input = vec![0];
        input.extend_from_slice(signature);
        assert_eq!(find_archive_start(&input, 0), None);
        let found = find_archive_start(&input, 1).unwrap();
        assert_eq!(found.offset, 1);
        assert_eq!(found.length, signature.len());
    }
}

#[test]
fn sfx_scan_limit_finds_signature_past_128kib_stub() {
    // Real SFX installers routinely place the RAR payload past 128 KiB
    // (modern WinRAR-built SFXes, Nero, anti-virus installers, etc.).
    let mut stub = vec![0u8; 300 * 1024];
    stub.extend_from_slice(RAR15_SIGNATURE);
    let sig = find_archive_start(&stub, SFX_SCAN_LIMIT).unwrap();
    assert_eq!(sig.family, ArchiveFamily::Rar15To40);
    assert_eq!(sig.offset, 300 * 1024);
}
