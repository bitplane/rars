#![cfg(all(feature = "write", feature = "encryption"))]
//! RAR 5 members carry a CRC32, as rar writes them, and a BLAKE2sp hash record
//! beside it only when asked for, the hash rar's `-htb` writes.

#[path = "support/data.rs"]
mod data;
#[path = "support/scratch.rs"]
mod scratch;
use data::xorshift;

use rars::rar50::{Archive, Block};
use rars::{ArchiveReader, ArchiveVersion, Builder, Error};
use std::io::Write;
use std::sync::{Arc, Mutex};

const PASSWORD: &[u8] = b"pw";

fn members() -> Vec<(&'static [u8], Vec<u8>)> {
    let text = b"the quick brown fox jumps over the lazy dog\n".repeat(900);
    vec![
        (b"text.txt", text),
        (b"noise.bin", xorshift(100_000, 0x2545_f491)),
        (b"empty", Vec::new()),
    ]
}

#[derive(Clone, Copy, Debug)]
struct Case {
    blake2sp: bool,
    password: bool,
    solid: bool,
    store: bool,
    volumes: bool,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for blake2sp in [false, true] {
        for password in [false, true] {
            for volumes in [false, true] {
                for (store, solid) in [(true, false), (false, false), (false, true)] {
                    cases.push(Case {
                        blake2sp,
                        password,
                        solid,
                        store,
                        volumes,
                    });
                }
            }
        }
    }
    cases
}

fn builder(case: Case) -> Builder {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(case.store)
        .solid(case.solid)
        .blake2sp(case.blake2sp)
        .password(case.password.then(|| PASSWORD.to_vec()))
        .volume_size(case.volumes.then_some(24 * 1024));
    for (name, data) in members() {
        builder.add_bytes(name.to_vec(), data, None, None).unwrap();
    }
    builder
}

fn build(case: Case) -> Vec<Vec<u8>> {
    let builder = builder(case);
    if case.volumes {
        let volumes = builder.build_volumes(None).unwrap();
        assert!(volumes.len() > 2, "{case:?}: {} volumes", volumes.len());
        volumes
    } else {
        vec![builder.to_bytes().unwrap()]
    }
}

fn password(case: Case) -> Option<&'static [u8]> {
    case.password.then_some(PASSWORD)
}

/// Each extracted member's name and contents, in order.
type Members = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Clone)]
struct Capture(Arc<Mutex<Members>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .last_mut()
            .unwrap()
            .1
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn extract(volumes: &[Vec<u8>], password: Option<&[u8]>) -> rars::Result<Members> {
    let archives = volumes
        .iter()
        .map(|volume| ArchiveReader::read_owned(volume.clone()))
        .collect::<rars::Result<Vec<_>>>()?;
    let output = Arc::new(Mutex::new(Vec::new()));
    let capture = Capture(output.clone());
    let open = |meta: &rars::ExtractedEntryMeta| -> rars::Result<Box<dyn Write>> {
        output.lock().unwrap().push((meta.name.clone(), Vec::new()));
        Ok(Box::new(capture.clone()))
    };
    if archives.len() == 1 {
        archives[0].extract_to(password, open)?;
    } else {
        rars::extract_volumes_to(&archives, password, open)?;
    }
    let extracted = output.lock().unwrap().clone();
    Ok(extracted)
}

fn expected() -> Members {
    members()
        .into_iter()
        .map(|(name, data)| (name.to_vec(), data))
        .collect()
}

/// Every member header, in every volume, carries the checksums asked for.
fn assert_checksums(volumes: &[Vec<u8>], case: Case) {
    let mut files = 0;
    for volume in volumes {
        let archive = Archive::parse_with_password(volume, password(case)).unwrap();
        for block in &archive.blocks {
            let Block::File(file) = block else { continue };
            files += 1;
            assert_eq!(file.hash.is_some(), case.blake2sp, "{case:?}");
            assert!(file.data_crc32.is_some(), "{case:?}");
        }
    }
    assert!(files >= 3, "{case:?}");
}

#[test]
fn members_carry_the_checksums_asked_for_and_round_trip() {
    for case in cases() {
        let volumes = build(case);
        assert_checksums(&volumes, case);
        assert_eq!(
            extract(&volumes, password(case)).unwrap(),
            expected(),
            "{case:?}"
        );
    }
}

#[test]
fn a_default_member_has_no_hash_record_and_the_plain_crc32() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"a.txt".to_vec(), b"hello\n".to_vec(), None, None)
        .unwrap();
    let archive = Archive::parse(&builder.to_bytes().unwrap()).unwrap();
    let file = archive.files().next().unwrap();
    assert_eq!(file.hash, None);
    assert_eq!(file.data_crc32, Some(rars::crc32::crc32(b"hello\n")));
    assert_eq!(file.data_crc32, Some(0x363a_3020));
    // With the time in the base header there is nothing left for an extra area.
    assert_eq!(file.block.flags & 0x0001, 0);
}

#[test]
fn blake2sp_is_refused_below_rar5() {
    let mut builder = Builder::new(ArchiveVersion::Rar40).blake2sp(true);
    builder
        .add_bytes(b"a.txt".to_vec(), b"hello\n".to_vec(), None, None)
        .unwrap();
    assert!(matches!(
        builder.to_bytes().unwrap_err(),
        Error::UnsupportedWriterOption {
            option: rars::WriterOption::Feature(rars::Feature::Blake2sp),
            ..
        }
    ));
}

/// Flips one byte in the middle of the largest stretch of member data in the
/// set, which is where a flip is a change to the payload and nothing else.
fn corrupt(volumes: &mut [Vec<u8>], case: Case) {
    let mut largest = (0, 0..0);
    for (index, volume) in volumes.iter().enumerate() {
        let archive = Archive::parse_with_password(volume, password(case)).unwrap();
        for file in archive.files() {
            let range = file.block.data_range.clone();
            if range.len() > largest.1.len() {
                largest = (index, range);
            }
        }
    }
    let (index, range) = largest;
    assert!(range.len() > 64, "{case:?}");
    volumes[index][range.start + range.len() / 2] ^= 0x20;
}

#[test]
fn a_flipped_data_byte_fails_the_member_whichever_checksum_it_has() {
    for case in cases().into_iter().filter(|case| case.store) {
        let mut volumes = build(case);
        corrupt(&mut volumes, case);
        let error = extract(&volumes, password(case)).unwrap_err();
        assert_eq!(
            error.kind(),
            rars::ErrorKind::ChecksumMismatch,
            "{case:?}: {error:?}"
        );
    }
}

#[test]
fn a_flipped_compressed_byte_fails_the_member_whichever_checksum_it_has() {
    for case in cases().into_iter().filter(|case| !case.store) {
        let mut volumes = build(case);
        corrupt(&mut volumes, case);
        assert!(extract(&volumes, password(case)).is_err(), "{case:?}");
    }
}

#[test]
fn a_wrong_password_is_refused_whichever_checksum_the_member_has() {
    for case in cases().into_iter().filter(|case| case.password) {
        let volumes = build(case);
        assert!(extract(&volumes, Some(b"wrong")).is_err(), "{case:?}");
    }
}

#[test]
fn a_seekable_output_hashes_stored_members_on_the_copy() {
    // A stored archive written to a path is read once, and its headers patched
    // with the checksums of the copy, so the header has to be sized for them.
    let dir = scratch::case("rar50-checksum-choice");
    for blake2sp in [false, true] {
        for password in [false, true] {
            let case = Case {
                blake2sp,
                password,
                solid: false,
                store: true,
                volumes: false,
            };
            let path = dir.join(format!("{blake2sp}-{password}.rar"));
            builder(case).write_to_path(&path, None).unwrap();
            let volumes = vec![std::fs::read(&path).unwrap()];
            assert_checksums(&volumes, case);
            assert_eq!(
                extract(&volumes, self::password(case)).unwrap(),
                expected(),
                "{case:?}"
            );
            let mut corrupted = volumes.clone();
            corrupt(&mut corrupted, case);
            assert!(
                extract(&corrupted, self::password(case)).is_err(),
                "{case:?}"
            );
        }
    }
}
