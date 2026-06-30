use crate::version::ArchiveFamily;
use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

pub const RAR13_SIGNATURE: &[u8; 4] = b"RE~^";
pub const RAR15_SIGNATURE: &[u8; 7] = b"Rar!\x1a\x07\x00";
pub const RAR50_SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";

/// Default upper bound for scanning past an SFX stub when looking for the RAR
/// signature. Most installers in the wild place the archive within a few
/// hundred KiB, but large SFX modules (notably WinRAR's own installer plus a
/// bundled runtime) can push the offset past 1 MiB.
pub const SFX_SCAN_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveSignature {
    pub family: ArchiveFamily,
    pub offset: usize,
    pub length: usize,
}

pub fn detect_archive_family(input: &[u8]) -> Option<ArchiveSignature> {
    detect_at(input, 0)
}

const SIGNATURES: &[&[u8]] = &[RAR50_SIGNATURE, RAR15_SIGNATURE, RAR13_SIGNATURE];
const MAX_SIGNATURE_LEN: usize = {
    let mut max_len = 0;
    let mut i = 0;
    while i < SIGNATURES.len() {
        if SIGNATURES[i].len() > max_len {
            max_len = SIGNATURES[i].len();
        }
        i += 1;
    }
    max_len
};

fn signatures_searcher() -> &'static AhoCorasick {
    static INSTANCE: OnceLock<AhoCorasick> = OnceLock::new();
    INSTANCE.get_or_init(|| AhoCorasick::new(SIGNATURES).unwrap())
}

fn signatures_searcher_only_15_plus() -> &'static AhoCorasick {
    static INSTANCE: OnceLock<AhoCorasick> = OnceLock::new();
    INSTANCE.get_or_init(|| AhoCorasick::new(&SIGNATURES[..2]).unwrap())
}

pub fn find_archive_start(input: &[u8], max_scan: usize) -> Option<ArchiveSignature> {
    // The limit is the maximum offset to find the signature, so we need to look
    // up to the longest signature after that point.
    let limit = input.len().min(max_scan.saturating_add(MAX_SIGNATURE_LEN));
    let input = &input[..limit];
    let mut first_rar13 = None;
    let mut it = signatures_searcher().find_iter(input);
    while let Some(m) = it.next() {
        let family = match m.pattern().as_u32() {
            0 => ArchiveFamily::Rar50Plus,
            1 => ArchiveFamily::Rar15To40,
            2 => {
                // Only find the first rar13 signature
                debug_assert!(first_rar13.is_none());
                first_rar13 = Some(ArchiveSignature {
                    family: ArchiveFamily::Rar13,
                    offset: m.start(),
                    length: m.len(),
                });
                // Switch to a searcher that doesn't have the rar13 signature anymore
                it = signatures_searcher_only_15_plus()
                    .find_iter(aho_corasick::Input::new(input).range(m.end()..));
                continue;
            }
            _ => unreachable!(),
        };
        if m.start() > max_scan {
            break;
        }
        return Some(ArchiveSignature {
            family,
            offset: m.start(),
            length: m.len(),
        });
    }
    first_rar13.filter(|sig| sig.offset <= max_scan)
}

fn detect_at(input: &[u8], offset: usize) -> Option<ArchiveSignature> {
    let tail = input.get(offset..)?;

    if tail.starts_with(RAR50_SIGNATURE) {
        Some(ArchiveSignature {
            family: ArchiveFamily::Rar50Plus,
            offset,
            length: RAR50_SIGNATURE.len(),
        })
    } else if tail.starts_with(RAR15_SIGNATURE) {
        Some(ArchiveSignature {
            family: ArchiveFamily::Rar15To40,
            offset,
            length: RAR15_SIGNATURE.len(),
        })
    } else if tail.starts_with(RAR13_SIGNATURE) {
        Some(ArchiveSignature {
            family: ArchiveFamily::Rar13,
            offset,
            length: RAR13_SIGNATURE.len(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn sfx_scan_limit_finds_signature_past_128kib_stub() {
        // Real SFX installers routinely place the RAR payload past 128 KiB
        // (modern WinRAR-built SFXes, Nero, anti-virus installers, etc.).
        let mut stub = vec![0u8; 300 * 1024];
        stub.extend_from_slice(RAR15_SIGNATURE);
        let sig = find_archive_start(&stub, SFX_SCAN_LIMIT).unwrap();
        assert_eq!(sig.family, ArchiveFamily::Rar15To40);
        assert_eq!(sig.offset, 300 * 1024);
    }
}
