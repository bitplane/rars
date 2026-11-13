#![cfg(feature = "write")]

use rars::rar15_40::{write_streaming_archive_to, EntrySource, StreamingEntry, WriterOptions};
use rars::{ArchiveReader, ArchiveVersion, FeatureSet, MemberCoding, WriterResources};
use std::io::{self, BufWriter, Read, Seek, SeekFrom};
use std::process::Command;

#[path = "support/scratch.rs"]
mod scratch;

const SIZE: u64 = (4 << 30) + 4099;

struct Pattern {
    position: u64,
}

impl Read for Pattern {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = (SIZE - self.position).min(buffer.len() as u64) as usize;
        for (offset, byte) in buffer[..count].iter_mut().enumerate() {
            let at = self.position + offset as u64;
            *byte = (at ^ (at >> 13)) as u8;
        }
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Pattern {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = match position {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => SIZE.saturating_add_signed(delta),
            SeekFrom::Current(delta) => self.position.saturating_add_signed(delta),
        }
        .min(SIZE);
        Ok(self.position)
    }
}

fn round_trip(target: ArchiveVersion, coding: MemberCoding, password: Option<&[u8]>) {
    let dir = scratch::case("legacy-large-member");
    let path = dir.join("big.rar");
    let source = EntrySource::from_opener(SIZE, || Ok(Box::new(Pattern { position: 0 })));
    let mut entry = StreamingEntry::new(b"big.bin".to_vec(), source);
    entry.password = password.map(<[u8]>::to_vec);
    let features = if coding == MemberCoding::Stored {
        FeatureSet::store_only()
    } else {
        FeatureSet::default()
    };
    let mut output = BufWriter::new(std::fs::File::create(&path).unwrap());
    write_streaming_archive_to(
        &[entry],
        WriterOptions::new(target, features),
        coding,
        None,
        &WriterResources::default(),
        None,
        &mut output,
    )
    .unwrap();
    drop(output);

    let archive = ArchiveReader::read_path(&path).unwrap();
    let sizes: Vec<_> = archive
        .members()
        .map(|member| member.meta.unpacked_size)
        .collect();
    assert_eq!(sizes, [SIZE], "{target}");
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
#[ignore = "compresses and encrypts members of over 4 GiB, holding each in memory"]
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
