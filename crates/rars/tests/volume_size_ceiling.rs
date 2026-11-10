#![cfg(all(feature = "write", feature = "encryption", feature = "recovery"))]

//! `volume_size` is the size of each volume file, headers included, the way
//! RAR's own `-v` switch counts it. The writers used to treat it as the payload
//! each volume carried and put the headers on top, so every part came out tens
//! or hundreds of bytes over the size it was asked for.

use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error};

const LEGACY: [ArchiveVersion; 6] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
];
const MODERN: [ArchiveVersion; 2] = [ArchiveVersion::Rar50, ArchiveVersion::Rar70];
const PASSWORD: &[u8] = b"secret";

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2654435761) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct Case {
    version: ArchiveVersion,
    stored: bool,
    encrypted_headers: bool,
    recovery: bool,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for version in LEGACY.into_iter().chain(MODERN) {
        let modern = MODERN.contains(&version);
        let header_encryption =
            modern || matches!(version, ArchiveVersion::Rar30 | ArchiveVersion::Rar40);
        for stored in [true, false] {
            for encrypted_headers in [false, true] {
                if encrypted_headers && !header_encryption {
                    continue;
                }
                for recovery in [false, true] {
                    if recovery && !modern {
                        continue;
                    }
                    cases.push(Case {
                        version,
                        stored,
                        encrypted_headers,
                        recovery,
                    });
                }
            }
        }
    }
    cases
}

/// Legacy volume sets hold one member; RAR 5 sets mix sizes, including an
/// empty member that still needs a header of its own.
fn members(version: ArchiveVersion) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sizes: &[usize] = if MODERN.contains(&version) {
        &[7_000, 37, 0, 3_000]
    } else {
        &[9_000]
    };
    sizes
        .iter()
        .enumerate()
        .map(|(index, &len)| {
            (
                format!("m{index}").into_bytes(),
                noise(index as u32 + 1, len),
            )
        })
        .collect()
}

fn build(case: Case, volume_size: usize) -> rars::Result<Vec<Vec<u8>>> {
    let mut builder = Builder::new(case.version)
        .store(case.stored)
        .volume_size(Some(volume_size));
    if case.encrypted_headers {
        builder = builder
            .password(Some(PASSWORD.to_vec()))
            .header_encryption(true);
    }
    if case.recovery {
        builder = builder.recovery_percent(Some(5));
    }
    for (name, data) in members(case.version) {
        builder.add_bytes(name, data, None, None)?;
    }
    builder.build_volumes(None)
}

fn read_back(case: Case, volumes: &[Vec<u8>]) -> usize {
    let options = if case.encrypted_headers {
        ArchiveReadOptions::with_password(PASSWORD)
    } else {
        ArchiveReadOptions::default()
    };
    let archives: Vec<Archive> = volumes
        .iter()
        .map(|volume| ArchiveReader::read_owned_with_options(volume.clone(), options).unwrap())
        .collect();
    let password = case.encrypted_headers.then_some(PASSWORD);
    let mut extracted = 0;
    // Extraction checks each member's CRC, so a bad split fails here.
    rars::extract_volumes_to(&archives, password, |_| {
        extracted += 1;
        Ok(Box::new(std::io::sink()))
    })
    .unwrap_or_else(|error| panic!("{case:?}: {error}"));
    extracted
}

#[test]
fn no_volume_is_longer_than_the_volume_size() {
    for case in cases() {
        for volume_size in [2_731, 4_096] {
            let volumes = build(case, volume_size)
                .unwrap_or_else(|error| panic!("{case:?} size {volume_size}: {error}"));
            assert!(volumes.len() > 1, "{case:?} size {volume_size}: one volume");
            for (index, volume) in volumes.iter().enumerate() {
                assert!(
                    volume.len() <= volume_size,
                    "{case:?} size {volume_size}: volume {index} is {} bytes",
                    volume.len()
                );
            }
            assert_eq!(
                read_back(case, &volumes),
                members(case.version).len(),
                "{case:?} size {volume_size}"
            );
        }
    }
}

/// A legacy volume carries the same headers around each slice, so every part
/// but the last fills the size exactly, as RAR's own volumes do.
#[test]
fn legacy_volumes_fill_the_volume_size_exactly() {
    for case in cases() {
        if MODERN.contains(&case.version) {
            continue;
        }
        let volumes = build(case, 2_731).unwrap();
        let (last, full) = volumes.split_last().unwrap();
        for (index, volume) in full.iter().enumerate() {
            assert_eq!(volume.len(), 2_731, "{case:?}: volume {index}");
        }
        assert!(last.len() <= 2_731, "{case:?}");
    }
}

#[test]
fn a_volume_size_too_small_for_the_headers_is_refused() {
    for case in cases() {
        let error = build(case, 64).unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::InvalidArgument(message) if message.contains("too small")),
            "{case:?}: {error:?}"
        );
    }
}
