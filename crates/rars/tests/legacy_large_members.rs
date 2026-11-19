#![cfg(feature = "write")]

use rars::rar15_40::{
    write_seekable_archive_to, write_streaming_archive_to, EntrySource, StreamingEntry,
    WriterOptions,
};
use rars::{ArchiveReader, ArchiveVersion, FeatureSet, MemberCoding, WriterResources};
use std::io::{self, BufWriter, Read, Seek, SeekFrom};
use std::process::Command;

#[path = "support/scratch.rs"]
mod scratch;

const SIZE: u64 = (4 << 30) + 4099;

struct Pattern {
    size: u64,
    position: u64,
    /// Bytes that don't compress, so a compressed member falls back to storing.
    noise: bool,
}

impl Pattern {
    fn source(size: u64, noise: bool) -> EntrySource {
        EntrySource::from_opener(size, move || {
            Ok(Box::new(Pattern {
                size,
                position: 0,
                noise,
            }))
        })
    }
}

impl Read for Pattern {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = (self.size - self.position).min(buffer.len() as u64) as usize;
        for (offset, byte) in buffer[..count].iter_mut().enumerate() {
            let at = self.position + offset as u64;
            *byte = if self.noise {
                let mut mixed = at.wrapping_add(0x9e37_79b9_7f4a_7c15);
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                (mixed ^ (mixed >> 31)) as u8
            } else {
                (at ^ (at >> 13)) as u8
            };
        }
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Pattern {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = match position {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => self.size.saturating_add_signed(delta),
            SeekFrom::Current(delta) => self.position.saturating_add_signed(delta),
        }
        .min(self.size);
        Ok(self.position)
    }
}

fn round_trip(target: ArchiveVersion, coding: MemberCoding, password: Option<&[u8]>) {
    sized_round_trip(target, coding, password, SIZE, false, false);
}

/// `seekable` patches a streamed member's header in place rather than spooling it.
fn sized_round_trip(
    target: ArchiveVersion,
    coding: MemberCoding,
    password: Option<&[u8]>,
    size: u64,
    noise: bool,
    seekable: bool,
) {
    let dir = scratch::case("legacy-large-member");
    let path = dir.join("big.rar");
    let mut entry = StreamingEntry::new(b"big.bin".to_vec(), Pattern::source(size, noise));
    entry.password = password.map(<[u8]>::to_vec);
    let features = if coding == MemberCoding::Stored {
        FeatureSet::store_only()
    } else {
        FeatureSet::default()
    };
    let mut options = WriterOptions::new(target, features);
    if noise {
        // Noise packs to nothing at any level, and the fastest gets there soonest.
        options = options.with_compression_level(1);
    }
    let resources = WriterResources::default();
    let mut output = BufWriter::new(std::fs::File::create(&path).unwrap());
    if seekable {
        write_seekable_archive_to(
            &[entry],
            options,
            coding.clone(),
            None,
            &resources,
            None,
            &mut output,
        )
    } else {
        write_streaming_archive_to(
            &[entry],
            options,
            coding.clone(),
            None,
            &resources,
            None,
            &mut output,
        )
    }
    .unwrap_or_else(|error| panic!("{target} {coding:?} of {size} bytes: {error}"));
    drop(output);

    let archive = ArchiveReader::read_path(&path).unwrap();
    let sizes: Vec<_> = archive
        .members()
        .map(|member| member.meta.unpacked_size)
        .collect();
    assert_eq!(sizes, [size], "{target}");
    archive.test(password).unwrap();

    let mut unrar = Command::new("unrar");
    unrar.arg("t");
    unrar.arg(match password {
        Some(password) => format!("-p{}", String::from_utf8_lossy(password)),
        None => "-p-".to_owned(),
    });
    match unrar.arg(&path).output() {
        Ok(result) => assert!(
            result.status.success(),
            "{target}: {}",
            String::from_utf8_lossy(&result.stdout)
        ),
        Err(error) => eprintln!("skipping unrar check: {error}"),
    }
}

#[test]
#[ignore = "writes and reads back four archives of over 4 GiB each"]
fn stored_members_over_4_gib_round_trip() {
    for target in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        round_trip(target, MemberCoding::Stored, None);
    }
}

#[test]
#[ignore = "compresses and encrypts members of over 4 GiB, spooling each to disk"]
fn compressed_and_encrypted_members_over_4_gib_round_trip() {
    round_trip(ArchiveVersion::Rar20, MemberCoding::Compressed, None);
    round_trip(ArchiveVersion::Rar40, MemberCoding::Compressed, None);
    #[cfg(feature = "encryption")]
    {
        round_trip(ArchiveVersion::Rar20, MemberCoding::Stored, Some(b"secret"));
        round_trip(ArchiveVersion::Rar30, MemberCoding::Stored, Some(b"secret"));
        round_trip(
            ArchiveVersion::Rar40,
            MemberCoding::Compressed,
            Some(b"secret"),
        );
    }
}

/// Cipher padding takes a stored copy of the first three past `u32::MAX`.
/// The last pads to itself, so it stays short either way.
#[cfg(feature = "encryption")]
const NEAR_4_GIB: [u64; 4] = [
    u32::MAX as u64 - 14,
    u32::MAX as u64 - 8,
    u32::MAX as u64 - 1,
    u32::MAX as u64 - 15,
];

#[cfg(feature = "encryption")]
#[test]
#[ignore = "compresses four encrypted members of just under 4 GiB at once, then stores each"]
fn encrypted_rar20_members_just_under_4_gib_patch_in_place() {
    // Noise codes slowly and each member stands alone, so they run side by side.
    std::thread::scope(|scope| {
        for size in NEAR_4_GIB {
            scope.spawn(move || {
                sized_round_trip(
                    ArchiveVersion::Rar20,
                    MemberCoding::Compressed,
                    Some(b"secret"),
                    size,
                    true,
                    true,
                )
            });
        }
    });
}

#[cfg(feature = "encryption")]
#[test]
#[ignore = "compresses an encrypted member of just under 4 GiB into a spool, then stores it"]
fn an_encrypted_rar20_member_just_under_4_gib_spools() {
    sized_round_trip(
        ArchiveVersion::Rar20,
        MemberCoding::Compressed,
        Some(b"secret"),
        u32::MAX as u64 - 8,
        true,
        false,
    );
}

#[cfg(feature = "encryption")]
#[test]
#[ignore = "stores an encrypted member of just under 4 GiB"]
fn an_encrypted_rar20_member_just_under_4_gib_stores() {
    sized_round_trip(
        ArchiveVersion::Rar20,
        MemberCoding::Stored,
        Some(b"secret"),
        u32::MAX as u64 - 8,
        true,
        true,
    );
}

#[test]
#[ignore = "writes and reads back two RAR 5 archives of over 4 GiB each"]
fn rar5_members_over_4_gib_round_trip() {
    for store in [true, false] {
        let dir = scratch::case("rar5-large-member");
        let path = dir.join("big.rar");
        let mut builder = rars::Builder::new(ArchiveVersion::Rar50).store(store);
        builder
            .add_source(
                b"big.bin".to_vec(),
                Pattern::source(SIZE, false),
                None,
                None,
            )
            .unwrap();
        builder.write_to_path(&path, None).unwrap();

        let archive = ArchiveReader::read_path(&path).unwrap();
        let sizes: Vec<_> = archive
            .members()
            .map(|member| member.meta.unpacked_size)
            .collect();
        assert_eq!(sizes, [SIZE], "store {store}");
        archive.test(None).unwrap();
    }
}
