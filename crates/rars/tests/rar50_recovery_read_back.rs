#![cfg(all(feature = "write", feature = "recovery"))]

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, WriterOptions};
use rars::{ArchiveVersion, Builder, EntrySource, Error, FeatureSet, WriterResources};
use std::io::{Cursor, Seek, SeekFrom, Write};

#[path = "support/data.rs"]
mod data;
#[path = "support/scratch.rs"]
mod scratch;
use data::xorshift;

struct WriteOnly(Cursor<Vec<u8>>);

impl Write for WriteOnly {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for WriteOnly {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(to)
    }
}

fn text(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|offset| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if offset % 3 == 0 {
                (state >> 24) as u8
            } else {
                b'a' + (offset % 7) as u8
            }
        })
        .collect()
}

fn entries(members: &[Vec<u8>], password: Option<&[u8]>) -> Vec<ArchiveEntry> {
    members
        .iter()
        .enumerate()
        .map(|(index, data)| {
            let entry = ArchiveEntry::new(
                format!("member{index:02}.bin").into_bytes(),
                EntrySource::from_bytes(data.clone()),
            )
            .with_mtime(Some(0x5000_0000));
            match password {
                Some(password) => entry.with_password(password.to_vec()),
                None => entry,
            }
        })
        .collect()
}

fn options(quick_open: bool, header_encryption: bool) -> WriterOptions {
    let mut features = FeatureSet::store_only();
    features.quick_open = quick_open;
    features.header_encryption = header_encryption;
    WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(1)
}

fn extras(password: Option<&'static [u8]>) -> ArchiveExtras<'static> {
    let mut extras = ArchiveExtras::default().with_recovery_percent(Some(5));
    extras.header_password = password;
    extras
}

#[derive(Clone, Copy, Debug)]
enum To {
    Readable,
    WriteOnly,
    Stream,
}

fn write(
    to: To,
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
    resources: &WriterResources,
) -> rars::Result<Vec<u8>> {
    match to {
        To::Readable => {
            let mut output = Cursor::new(Vec::new());
            rar50::write_readable_archive_to(entries, options, extras, resources, &mut output)?;
            Ok(output.into_inner())
        }
        To::WriteOnly => {
            let mut output = WriteOnly(Cursor::new(Vec::new()));
            rar50::write_seekable_archive_to(entries, options, extras, resources, &mut output)?;
            Ok(output.0.into_inner())
        }
        To::Stream => {
            let mut output = Vec::new();
            rar50::write_streaming_archive_to(entries, options, extras, resources, &mut output)?;
            Ok(output)
        }
    }
}

fn on_two_threads<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    #[cfg(feature = "parallel")]
    return rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap()
        .install(work);
    #[cfg(not(feature = "parallel"))]
    work()
}

#[test]
fn a_readable_output_needs_no_mirror_of_the_archive() {
    // Too large to mirror under the cap, but the members in flight and the
    // record fit.
    let members: Vec<_> = (0..48)
        .map(|index| xorshift(64 * 1024, index | 1))
        .collect();
    let entries = entries(&members, None);
    // Stored members hashed on their copy are held as sources, so at level 0
    // only a mirror can exceed the cap.
    for compression_level in [1, 0] {
        let options = options(false, false).with_compression_level(compression_level);
        let resources = || WriterResources::default().with_max_spool_bytes(1024 * 1024);
        let archive =
            on_two_threads(|| write(To::Readable, &entries, options, extras(None), &resources()))
                .unwrap();
        assert!(archive.len() > 3 * 1024 * 1024);
        rars::ArchiveReader::read(&archive)
            .unwrap()
            .test(None)
            .unwrap();

        let error =
            on_two_threads(|| write(To::WriteOnly, &entries, options, extras(None), &resources()))
                .unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::WriterSpoolLimitExceeded { .. }),
            "level {compression_level}: {error}"
        );
    }
}

#[test]
fn a_record_read_back_matches_one_built_from_a_mirror() {
    let members: Vec<_> = [0, 1, 200_000, 40_000, 400_000]
        .iter()
        .enumerate()
        .map(|(index, &len)| text(len, index as u32))
        .collect();
    let entries = entries(&members, None);
    for solid in [false, true] {
        for quick_open in [false, true] {
            for compression_level in [1, 0] {
                let mut options =
                    options(quick_open, false).with_compression_level(compression_level);
                options.features.solid = solid;
                let case =
                    format!("solid {solid}, quick open {quick_open}, level {compression_level}");
                let resources = WriterResources::default();
                let mirrored =
                    write(To::WriteOnly, &entries, options, extras(None), &resources).unwrap();
                let streamed =
                    write(To::Stream, &entries, options, extras(None), &resources).unwrap();
                let read_back =
                    write(To::Readable, &entries, options, extras(None), &resources).unwrap();
                assert!(mirrored == streamed, "{case}: stream differs");
                assert!(read_back == mirrored, "{case}: read back differs");

                let mut prefixed = Cursor::new(b"not an archive".to_vec());
                prefixed.seek(SeekFrom::End(0)).unwrap();
                rar50::write_readable_archive_to(
                    &entries,
                    options,
                    extras(None),
                    &resources,
                    &mut prefixed,
                )
                .unwrap();
                let prefixed = prefixed.into_inner();
                assert!(prefixed.starts_with(b"not an archive"), "{case}");
                assert!(prefixed[14..] == read_back[..], "{case}: prefixed differs");
            }
        }
    }
}

#[test]
fn a_damaged_copy_written_to_a_readable_output_repairs_from_its_record() {
    let members: Vec<_> = (0..6).map(|index| text(60_000, index)).collect();
    let header_encryption = if cfg!(feature = "encryption") {
        vec![false, true]
    } else {
        vec![false]
    };
    for quick_open in [false, true] {
        for &header_encryption in &header_encryption {
            // Quick open is refused with encrypted headers.
            if quick_open && header_encryption {
                continue;
            }
            let password = header_encryption.then_some(b"secret".as_slice());
            let case = format!("quick open {quick_open}, header encryption {header_encryption}");
            let archive = write(
                To::Readable,
                &entries(&members, password),
                options(quick_open, header_encryption),
                extras(password),
                &WriterResources::default(),
            )
            .unwrap();
            let mut damaged = archive.clone();
            let at = archive.len() / 3;
            damaged[at..at + 64]
                .iter_mut()
                .for_each(|byte| *byte ^= 0xff);
            let read_options = match password {
                Some(password) => rars::ArchiveReadOptions::with_password(password),
                None => rars::ArchiveReadOptions::new(),
            };
            let repaired =
                rar50::repair_inline_recovery_bytes_with_options(&damaged, read_options).unwrap();
            assert!(repaired.report.data_repaired, "{case}");
            assert!(repaired.data == archive, "{case}: not repaired");
        }
    }
}

#[test]
fn a_builder_writing_to_a_path_reads_its_record_back() {
    let root = scratch::case("recovery-read-back");
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .compression_level(Some(1))
        .recovery_percent(Some(5));
    for index in 0..48 {
        builder
            .add_bytes(
                format!("member{index:02}.bin").into_bytes(),
                xorshift(64 * 1024, index | 1),
                None,
                None,
            )
            .unwrap();
    }
    let resources = || WriterResources::default().with_max_spool_bytes(1024 * 1024);
    let destination = root.join("protected.rar");
    on_two_threads(|| builder.write_to_path_with_resources(&destination, &resources(), None))
        .unwrap();
    rars::ArchiveReader::read(&std::fs::read(&destination).unwrap())
        .unwrap()
        .test(None)
        .unwrap();

    let error =
        on_two_threads(|| builder.write_to(&mut Vec::new(), &resources(), None)).unwrap_err();
    assert!(
        matches!(error.root_cause(), Error::WriterSpoolLimitExceeded { .. }),
        "{error}"
    );
}
